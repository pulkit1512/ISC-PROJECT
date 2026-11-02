"""Local patient portal. Run through start.ps1; one backend worker is supported."""
import hashlib
import hmac
import io
import json
import os
import secrets
import sys
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from alembic import command
from alembic.config import Config
from fastapi import FastAPI, Depends, HTTPException, Request, Response, UploadFile, File, Form
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from starlette.formparsers import MultiPartParser
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import create_engine, event, select, insert, update, delete, func
from sqlalchemy.exc import IntegrityError
from argon2.exceptions import VerificationError
from cryptography.exceptions import InvalidTag

from database import users, profiles, sessions, images, predictions, audit, settings, attempts
from keys import backend_key
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
import research_support as shared
# Keep accepted uploads in RAM instead of spooling plaintext image files to disk.
MultiPartParser.spool_max_size = shared.MAX_UPLOAD + 1024*1024

def utc(): return datetime.now(timezone.utc).isoformat()
def digest(value): return hashlib.sha256(value.encode()).hexdigest()
def identifier(): return uuid.uuid4().hex

class Credentials(BaseModel):
    model_config = ConfigDict(extra='forbid')
    username: str = Field(min_length=3, max_length=40, pattern=r'^[A-Za-z0-9_-]+$')
    password: str = Field(min_length=12, max_length=256)

class Profile(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str = Field(min_length=1, max_length=100)
    age: int = Field(ge=0, le=120)
    sex: str = Field(pattern=r'^(Female|Male|Other|Prefer not to say)$')
    reference: str = Field(max_length=60, default='')
    symptoms: str = Field(max_length=300, default='')
    symptom_duration: str = Field(max_length=80, default='')
    medical_history: str = Field(max_length=500, default='')
    version: int = Field(ge=0, default=0)

class AccountState(BaseModel):
    model_config = ConfigDict(extra='forbid')
    active: bool

class SavePrediction(BaseModel):
    model_config = ConfigDict(extra='forbid')
    draft_id: str = Field(min_length=32, max_length=64)

def bootstrap_admin(engine):
    """Host-controlled setup only; never accept these credentials from HTTP."""
    username = os.environ.get('SECUREMED_ADMIN_USERNAME')
    password = os.environ.get('SECUREMED_ADMIN_PASSWORD')
    if username is None and password is None:
        return
    with engine.begin() as c:
        c.exec_driver_sql('BEGIN IMMEDIATE')
        # Restarts must not replace credentials or grant a second admin account.
        if c.scalar(select(func.count()).select_from(users).where(users.c.role == 'ADMIN')):
            return
        try:
            credentials = Credentials(username=username, password=password)
        except ValidationError:
            raise RuntimeError('Set both admin environment variables: username must be 3-40 letters/numbers/_/-, password 12-256 characters.') from None
        if c.scalar(select(users.c.id).where(users.c.username == credentials.username.lower())):
            raise RuntimeError('Admin setup username is already taken. Choose a different username; existing accounts are never promoted.')
        uid = identifier()
        c.execute(insert(users).values(id=uid, username=credentials.username.lower(),
            password_hash=shared.PH.hash(credentials.password), role='ADMIN', created_at=utc()))
        c.execute(insert(audit).values(actor_id=uid, action='ADMIN_PROVISIONED_FROM_ENV',
            status='OK', created_at=utc()))


def create_app(db_path=None, key=None, testing=False):
    db_path = Path(db_path or os.environ.get('SECUREMED_DB_PATH') or ROOT / 'securemed_web.db').resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f'sqlite:///{db_path.as_posix()}', connect_args={'check_same_thread':False, 'timeout':15})
    @event.listens_for(engine, 'connect')
    def configure(connection, record):
        connection.execute('PRAGMA foreign_keys=ON')
        connection.execute('PRAGMA secure_delete=ON')
    with engine.begin() as connection:
        config = Config()
        config.set_main_option('script_location', str(ROOT / 'alembic'))
        config.attributes['connection'] = connection
        command.upgrade(config, 'head')
    vault_key = key or backend_key(ROOT / 'vault_key.dpapi')
    with engine.begin() as c:
        # Fail closed if the OS key changes while encrypted data remains.
        verifier = c.execute(select(settings).where(settings.c.name=='key_verifier')).mappings().first()
        if verifier:
            check = json.loads(verifier['value'])
            shared.decrypt_bytes(vault_key, bytes.fromhex(check['cipher']), bytes.fromhex(check['nonce']), 'website', 'key-check')
        else:
            cipher, nonce = shared.encrypt_bytes(vault_key, b'SecureMed website', 'website', 'key-check')
            c.execute(insert(settings).values(name='key_verifier', value=json.dumps(dict(cipher=cipher.hex(),nonce=nonce.hex()))))
    draft_lock = threading.Lock()
    inference_lock = threading.Lock()
    drafts = {}
    cookie_secure = os.environ.get('SECUREMED_HTTPS') == '1'
    cookie_name = 'securemed_session'
    allowed_origins = {'http://127.0.0.1:8000','http://localhost:8000','http://127.0.0.1:5173','http://localhost:5173'}
    public_origin = os.environ.get('SECUREMED_ORIGIN') or os.environ.get('RENDER_EXTERNAL_URL')
    allowed_hosts = ['127.0.0.1', 'localhost']
    if public_origin:
        parsed = urlsplit(public_origin)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.path not in ('', '/') or parsed.query or parsed.fragment or parsed.username:
            raise RuntimeError('Public origin must be an HTTPS origin without a path or credentials.')
        allowed_origins = {public_origin.rstrip('/')}
        allowed_hosts.append(parsed.hostname)
        if not cookie_secure:
            raise RuntimeError('Set SECUREMED_HTTPS=1 for public hosting.')
    if testing: allowed_hosts.append('testserver')
    if not testing:
        bootstrap_admin(engine)

    @asynccontextmanager
    async def lifespan(app):
        yield
        with draft_lock: drafts.clear()
        engine.dispose()

    app = FastAPI(title='SecureMed patient portal', lifespan=lifespan, docs_url='/api/docs' if testing else None, redoc_url=None)
    app.add_middleware(TrustedHostMiddleware,allowed_hosts=allowed_hosts)
    app.state.engine = engine

    @app.exception_handler(RequestValidationError)
    async def invalid_input(request, exc):
        # Pydantic's default error includes submitted values, including passwords.
        return JSONResponse({'detail':'; '.join(f"{'.'.join(str(v) for v in e['loc'][1:])}: {e['msg']}" for e in exc.errors())},422)

    def log(actor, action, status='OK', reference=None, connection=None):
        stmt = insert(audit).values(actor_id=actor,action=action,status=status,reference=reference,created_at=utc())
        if connection is not None: connection.execute(stmt)
        else:
            with engine.begin() as c: c.execute(stmt)

    def denied(actor, action):
        log(actor,action,'DENIED')
        raise HTTPException(403,'You do not have permission for this action.')

    @app.middleware('http')
    async def boundaries(request, call_next):
        if request.method in {'POST','PUT','PATCH','DELETE'}:
            origin = request.headers.get('origin')
            if (origin and origin not in allowed_origins) or request.headers.get('sec-fetch-site')=='cross-site':
                return JSONResponse({'detail':'Cross-site request rejected.'},403)
            try:
                if int(request.headers.get('content-length','0')) > shared.MAX_UPLOAD + 1024*1024:
                    return JSONResponse({'detail':'Upload exceeds the configured size limit.'},413)
            except ValueError: return JSONResponse({'detail':'Invalid content length.'},400)
        response = await call_next(request)
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['Referrer-Policy']='same-origin'
        response.headers['X-Frame-Options']='DENY'
        response.headers['Content-Security-Policy']="default-src 'self'; img-src 'self' blob: data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        if request.url.path.startswith('/api'): response.headers['Cache-Control']='no-store'
        return response

    @app.exception_handler(InvalidTag)
    async def integrity_error(request, exc):
        return JSONResponse({'detail':'Encrypted data could not be authenticated. Nothing was changed.'},409)

    def actor(request: Request):
        token = request.cookies.get(cookie_name,'')
        with engine.connect() as c:
            row = c.execute(select(users, sessions.c.csrf, sessions.c.expires).join(sessions,users.c.id==sessions.c.user_id).where(sessions.c.token_hash==digest(token))).mappings().first()
        if not row or not row['active'] or row['expires'] < time.time():
            raise HTTPException(401,'Please sign in again.')
        if request.method not in {'GET','HEAD','OPTIONS'} and not secrets.compare_digest(request.headers.get('x-csrf-token',''),row['csrf']):
            denied(row['id'],'CSRF_CHECK')
        return dict(row)

    def patient(user=Depends(actor)):
        if user['role']!='PATIENT': denied(user['id'],'PATIENT_ACCESS')
        return user

    def admin(user=Depends(actor)):
        if user['role']!='ADMIN': denied(user['id'],'ADMIN_ACCESS')
        return user

    def recheck(c,user,role):
        current=c.execute(select(users.c.active,users.c.role).where(users.c.id==user['id'])).first()
        if not current or not current.active or current.role!=role:
            raise HTTPException(403,'Account access changed. Please sign in again.')

    def throttle(request,action):
        bucket=digest(f"{action}:{request.client.host if request.client else 'local'}")
        limited=False
        with engine.begin() as c:
            c.exec_driver_sql('BEGIN IMMEDIATE')
            row=c.execute(select(attempts).where(attempts.c.bucket==bucket)).mappings().first()
            if not row or row['reset_at']<time.time():
                c.execute(delete(attempts).where(attempts.c.reset_at<time.time()))
                c.execute(insert(attempts).values(bucket=bucket,count=1,reset_at=time.time()+60))
            elif row['count']>=20: limited=True
            else: c.execute(update(attempts).where(attempts.c.bucket==bucket).values(count=row['count']+1))
        if limited: raise HTTPException(429,'Too many attempts. Please wait one minute.')

    @app.get('/api/status')
    def status():
        return dict(max_upload_mb=shared.MAX_UPLOAD//1048576)

    @app.post('/api/signup',status_code=201)
    def signup(data: Credentials, request: Request):
        throttle(request,'signup')
        try:
            with engine.begin() as c:
                uid=identifier()
                c.execute(insert(users).values(id=uid,username=data.username.lower(),password_hash=shared.PH.hash(data.password),role='PATIENT',created_at=utc()))
                log(uid,'SIGNUP',connection=c)
        except IntegrityError: raise HTTPException(409,'That username is already in use.')
        return {'message':'Account created. You can now sign in.'}

    @app.post('/api/login')
    def login(data: Credentials, request: Request, response: Response):
        throttle(request,'login')
        valid=False; uid=None
        with engine.begin() as c:
            c.exec_driver_sql('BEGIN IMMEDIATE')
            row=c.execute(select(users).where(users.c.username==data.username.lower())).mappings().first()
            if row:
                uid=row['id']
                if row['active'] and row['locked_until']<=time.time():
                    try: valid=shared.PH.verify(row['password_hash'],data.password)
                    except VerificationError: pass
                    if not valid:
                        failures=(0 if row['locked_until']>0 else row['failures'])+1
                        c.execute(update(users).where(users.c.id==uid).values(failures=failures,locked_until=time.time()+60 if failures>=5 else 0))
            if valid:
                c.execute(update(users).where(users.c.id==uid).values(failures=0,locked_until=0))
                token=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(32)
                c.execute(delete(sessions).where(sessions.c.expires<time.time()))
                c.execute(insert(sessions).values(token_hash=digest(token),user_id=uid,csrf=csrf,expires=time.time()+3600))
            log(uid,'LOGIN','OK' if valid else 'DENIED',connection=c)
        if not valid: raise HTTPException(401,'Incorrect credentials, inactive account, or temporary lock. Wait 60 seconds after five failed attempts.')
        response.set_cookie(cookie_name,token,httponly=True,secure=cookie_secure,samesite='strict',max_age=3600,path='/')
        return dict(user=dict(id=uid,username=row['username'],role=row['role']),csrf=csrf)

    @app.get('/api/me')
    def me(user=Depends(actor)):
        return dict(user={k:user[k] for k in ('id','username','role')},csrf=user['csrf'])

    @app.post('/api/logout')
    def logout(request: Request,response: Response,user=Depends(actor)):
        with engine.begin() as c:
            c.execute(delete(sessions).where(sessions.c.token_hash==digest(request.cookies.get(cookie_name,''))))
            log(user['id'],'LOGOUT',connection=c)
        with draft_lock:
            for k in [k for k,v in drafts.items() if v['user_id']==user['id']]: drafts.pop(k)
        response.delete_cookie(cookie_name,path='/')
        return {'message':'Signed out.'}

    @app.get('/api/profile')
    def profile(user=Depends(patient)):
        with engine.connect() as c: row=c.execute(select(profiles).where(profiles.c.user_id==user['id'])).mappings().first()
        if not row: return {'profile':None}
        data=json.loads(shared.decrypt_bytes(vault_key,row['ciphertext'],row['nonce'],user['id'],'profile'))
        log(user['id'],'VIEW_PROFILE')
        return {'profile':dict(data,version=row['version'])}

    @app.put('/api/profile')
    def save_profile(data: Profile,user=Depends(patient)):
        if not data.name.strip(): raise HTTPException(422,'Enter a fictional patient name.')
        plain=data.model_dump(exclude={'version'})
        cipher,nonce=shared.encrypt_bytes(vault_key,json.dumps(plain).encode(),user['id'],'profile')
        conflict=False
        with engine.begin() as c:
            c.exec_driver_sql('BEGIN IMMEDIATE'); recheck(c,user,'PATIENT')
            old=c.execute(select(profiles.c.version).where(profiles.c.user_id==user['id'])).scalar()
            if (old or 0)!=data.version:
                conflict=True; log(user['id'],'UPDATE_PROFILE','CONFLICT',connection=c)
            elif old is None:
                c.execute(insert(profiles).values(user_id=user['id'],ciphertext=cipher,nonce=nonce,version=1,updated_at=utc()))
                log(user['id'],'CREATE_PROFILE',connection=c)
            else:
                c.execute(update(profiles).where(profiles.c.user_id==user['id']).values(ciphertext=cipher,nonce=nonce,version=old+1,updated_at=utc()))
                log(user['id'],'UPDATE_PROFILE',connection=c)
        if conflict: raise HTTPException(409,'Your details changed in another tab. Reload before saving.')
        return {'profile':dict(plain,version=data.version+1)}

    @app.get('/api/models')
    def models(user=Depends(actor)):
        return {'models':[dict(id=name,available=(shared.BASE/file).exists()) for name,file in shared.MODEL_FILES.items()]}

    @lru_cache(maxsize=2)
    def model_for(name,modified): return shared.load_model(shared.BASE/shared.MODEL_FILES[name])

    @app.post('/api/predict')
    def predict(model: str=Form(...), file: UploadFile=File(...),user=Depends(patient)):
        with engine.connect() as c: profile_row=c.execute(select(profiles).where(profiles.c.user_id==user['id'])).mappings().first()
        if not profile_row: raise HTTPException(409,'Complete your patient details before prediction.')
        if model not in shared.MODEL_FILES: raise HTTPException(422,'Select an available model.')
        raw=file.file.read(shared.MAX_UPLOAD+1)
        try: shared.validate_image(raw)
        except ValueError as exc:
            log(user['id'],'UPLOAD','REJECTED'); raise HTTPException(422,str(exc))
        path=shared.BASE/shared.MODEL_FILES[model]
        if not path.is_file(): raise HTTPException(503,'This model checkpoint is unavailable.')
        if not inference_lock.acquire(blocking=False): raise HTTPException(429,'Another prediction is running. Try again shortly.')
        try:
            network,metadata=model_for(model,path.stat().st_mtime_ns)
            result=shared.predict(raw,network,metadata)
        finally: inference_lock.release()
        draft_id=identifier()
        # Unsaved uploads live only in RAM, encrypted, and expire after ten minutes.
        payload=json.dumps(dict(image=raw.hex(),result=result,profile_snapshot=json.loads(shared.decrypt_bytes(vault_key,profile_row['ciphertext'],profile_row['nonce'],user['id'],'profile')))).encode()
        cipher,nonce=shared.encrypt_bytes(vault_key,payload,draft_id,'draft')
        with draft_lock:
            for k in [k for k,v in drafts.items() if v['expires']<time.time() or v['user_id']==user['id']]: drafts.pop(k)
            if len(drafts)>=20: raise HTTPException(503,'Temporary prediction capacity reached. Try again later.')
            drafts[draft_id]=dict(user_id=user['id'],expires=time.time()+600,cipher=cipher,nonce=nonce)
        log(user['id'],'PREDICT')
        return dict(draft_id=draft_id,**result)

    @app.post('/api/records',status_code=201)
    def save_record(data: SavePrediction,user=Depends(patient)):
        with draft_lock:
            draft=drafts.get(data.draft_id)
            if not draft or draft['user_id']!=user['id'] or draft['expires']<time.time():
                denied(user['id'],'SAVE_RECORD')
            if draft.get('saved_id'): return {'id':draft['saved_id']}
            payload=json.loads(shared.decrypt_bytes(vault_key,draft['cipher'],draft['nonce'],data.draft_id,'draft'))
            raw=bytes.fromhex(payload['image']); fingerprint=hashlib.sha256(raw).hexdigest()
            lookup=hmac.new(vault_key,f"{user['id']}:{fingerprint}".encode(),hashlib.sha256).hexdigest()
            rid=identifier()
            with engine.begin() as c:
                c.exec_driver_sql('BEGIN IMMEDIATE'); recheck(c,user,'PATIENT')
                old=c.execute(select(images).where(images.c.user_id==user['id'],images.c.lookup==lookup)).mappings().first()
                if old:
                    image_id=old['id']
                    if shared.decrypt_bytes(vault_key,old['ciphertext'],old['nonce'],f"{user['id']}:{image_id}",'image')!=raw:
                        raise HTTPException(409,'Stored image integrity mismatch.')
                else:
                    image_id=identifier()
                    cipher,nonce=shared.encrypt_bytes(vault_key,raw,f"{user['id']}:{image_id}",'image')
                    c.execute(insert(images).values(id=image_id,user_id=user['id'],lookup=lookup,ciphertext=cipher,nonce=nonce,created_at=utc()))
                result=dict(payload['result'],sha256=fingerprint,image_id=image_id,user_id=user['id'],profile_snapshot=payload['profile_snapshot'])
                cipher,nonce=shared.encrypt_bytes(vault_key,json.dumps(result).encode(),rid,'prediction')
                c.execute(insert(predictions).values(id=rid,user_id=user['id'],image_id=image_id,ciphertext=cipher,nonce=nonce,model_version=result['model_version'],created_at=utc()))
                log(user['id'],'SAVE_RECORD',reference=rid,connection=c)
            draft['saved_id']=rid
        return {'id':rid}

    def read_record(rid,user):
        with engine.connect() as c:
            row=c.execute(select(predictions).where(predictions.c.id==rid,predictions.c.user_id==user['id'])).mappings().first()
            if not row: denied(user['id'],'READ_RECORD')
            image=c.execute(select(images).where(images.c.id==row['image_id'],images.c.user_id==user['id'])).mappings().first()
        result=json.loads(shared.decrypt_bytes(vault_key,row['ciphertext'],row['nonce'],rid,'prediction'))
        if not image or result['user_id']!=user['id'] or result['image_id']!=image['id']:
            raise HTTPException(409,'Record binding failed.')
        raw=shared.decrypt_bytes(vault_key,image['ciphertext'],image['nonce'],f"{user['id']}:{image['id']}",'image')
        if not shared.verify_integrity(raw,result['sha256']): raise HTTPException(409,'Image integrity check failed.')
        log(user['id'],'READ_RECORD',reference=rid)
        return row,result,raw

    @app.get('/api/records')
    def records(user=Depends(patient)):
        with engine.connect() as c:
            rows=c.execute(select(predictions.c.id,predictions.c.model_version,predictions.c.created_at).where(predictions.c.user_id==user['id']).order_by(predictions.c.created_at.desc()).limit(100)).mappings().all()
        log(user['id'],'LIST_RECORDS')
        return {'records':[dict(r) for r in rows]}

    @app.get('/api/records/{rid}')
    def record(rid: str,user=Depends(patient)):
        row,result,raw=read_record(rid,user)
        return dict(id=rid,created_at=row['created_at'],result=result,integrity_verified=True)

    @app.get('/api/records/{rid}/image')
    def image(rid: str,user=Depends(patient)):
        _,_,raw=read_record(rid,user)
        return Response(raw,media_type='image/png' if raw.startswith(b'\x89PNG') else 'image/jpeg')

    @app.get('/api/admin')
    def admin_dashboard(user=Depends(admin)):
        with engine.connect() as c:
            account_rows=c.execute(select(users.c.id,users.c.username,users.c.role,users.c.active,users.c.created_at)).mappings().all()
            image_bytes=c.scalar(select(func.coalesce(func.sum(func.length(images.c.ciphertext)+func.length(images.c.nonce)),0)))
            count=c.scalar(select(func.count()).select_from(predictions))
            logs=c.execute(select(audit).order_by(audit.c.id.desc()).limit(100)).mappings().all()
        return dict(users=[dict(r) for r in account_rows],audit=[dict(r) for r in logs],database_bytes=db_path.stat().st_size,encrypted_image_bytes=image_bytes,predictions=count)

    @app.patch('/api/admin/users/{uid}')
    def account(uid: str,data: AccountState,user=Depends(admin)):
        with engine.begin() as c:
            c.exec_driver_sql('BEGIN IMMEDIATE'); recheck(c,user,'ADMIN')
            target=c.execute(select(users.c.role).where(users.c.id==uid)).scalar()
            if target!='PATIENT': raise HTTPException(403,'Only patient accounts can be changed here.')
            c.execute(update(users).where(users.c.id==uid).values(active=int(data.active)))
            c.execute(delete(sessions).where(sessions.c.user_id==uid))
            log(user['id'],'ACTIVATE_ACCOUNT' if data.active else 'DEACTIVATE_ACCOUNT',reference=uid,connection=c)
        with draft_lock:
            for k in [k for k,v in drafts.items() if v['user_id']==uid]: drafts.pop(k)
        return {'message':'Account updated.'}

    dist=ROOT/'dist'
    if dist.exists():
        app.mount('/assets',StaticFiles(directory=dist/'assets'),name='assets')
        @app.get('/')
        def index(): return FileResponse(dist/'index.html')
    return app
