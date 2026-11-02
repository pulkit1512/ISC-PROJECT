"""Run with .venv/Scripts/python.exe -B SecureMed_AI/website/test_api.py."""
import io
import secrets
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy import select, func, update
from api import create_app, shared
from manage_admin import provision_admin
from database import users, images, predictions, audit
from PIL import Image

def run():
    checks=[]
    def check(name,condition):
        assert condition,name
        checks.append(name)
        print('PASS',name,flush=True)
    with tempfile.TemporaryDirectory(prefix='securemed_web_tests_') as temp:
        application=create_app(Path(temp)/'test.db',key=secrets.token_bytes(32),testing=True)
        password=secrets.token_urlsafe(24)
        with TestClient(application) as admin, TestClient(application) as alice, TestClient(application) as bob:
            check('Public setup endpoint removed',admin.post('/api/setup',json=dict(username='admin',password=password)).status_code==404)
            check('Patient signup without public setup',alice.post('/api/signup',json=dict(username='early_patient',password=password)).status_code==201)
            provision_admin(application.state.engine,'admin',password)
            try:
                provision_admin(application.state.engine,'other_admin',password)
                duplicate_denied=False
            except ValueError:
                duplicate_denied=True
            check('Second admin provisioning denied',duplicate_denied)
            check('Injected admin role rejected',alice.post('/api/signup',json=dict(username='alice',password=password,role='ADMIN')).status_code==422)
            for client,name in [(alice,'alice'),(bob,'bob')]:
                check(name+' signup',client.post('/api/signup',json=dict(username=name,password=password)).status_code==201)
            for client,name in [(admin,'admin'),(alice,'alice'),(bob,'bob')]:
                response=client.post('/api/login',json=dict(username=name,password=password))
                check(name+' login',response.status_code==200)
                client.headers['x-csrf-token']=response.json()['csrf']
                check('HttpOnly session '+name,'httponly' in response.headers['set-cookie'].lower())
            check('SQL injection login denied',bob.post('/api/login',json=dict(username="' OR 1=1 --",password=password)).status_code==422)
            check('Patient cannot access admin',alice.get('/api/admin').status_code==403)
            check('Admin cannot access patient profile',admin.get('/api/profile').status_code==403)
            profile=dict(name='Fictional Alice Example',age=24,sex='Prefer not to say',reference='DEMO',symptoms='Fictional cough',symptom_duration='3 days',medical_history='Fictional history',version=0)
            csrf=alice.headers.pop('x-csrf-token')
            check('Missing CSRF denied',alice.put('/api/profile',json=profile).status_code==403)
            alice.headers['x-csrf-token']=csrf
            check('Cross-origin write denied',alice.put('/api/profile',json=profile,headers={'origin':'https://evil.invalid'}).status_code==403)
            check('Profile saved',alice.put('/api/profile',json=profile).status_code==200)
            restored=alice.get('/api/profile').json()['profile']
            check('Additional encrypted profile fields round trip',all(restored[k]==profile[k] for k in ['symptoms','symptom_duration','medical_history']))
            check('Oversized medical history rejected',alice.put('/api/profile',json=dict(profile,medical_history='x'*501)).status_code==422)
            check('Profile optimistic version conflict',alice.put('/api/profile',json=profile).status_code==409)
            check('Other patient profile private',bob.get('/api/profile').json()['profile'] is None)
            check('Bad upload rejected',alice.post('/api/predict',data={'model':'Custom CNN'},files={'file':('bad.jpg',b'bad','image/jpeg')}).status_code==422)
            check('Oversized upload rejected',alice.post('/api/predict',data={'model':'Custom CNN'},files={'file':('big.jpg',b'x'*(shared.MAX_UPLOAD+1),'image/jpeg')}).status_code==422)
            check('Invalid model rejected',alice.post('/api/predict',data={'model':'../../model'},files={'file':('bad.jpg',b'bad','image/jpeg')}).status_code==422)
            raw=next((shared.BASE.parent/'archive/chest_xray/test/NORMAL').glob('*.jpeg')).read_bytes()
            check('Profile required for prediction',bob.post('/api/predict',data={'model':'Custom CNN'},files={'file':('x.jpg',raw,'image/jpeg')}).status_code==409)
            saved=[]
            for name in shared.MODEL_FILES:
                r=alice.post('/api/predict',data={'model':name},files={'file':('x.jpg',raw,'image/jpeg')})
                check(name+' actual prediction',r.status_code==200)
                draft=r.json()['draft_id']
                check('Foreign draft save denied',bob.post('/api/records',json={'draft_id':draft}).status_code==403)
                with application.state.engine.connect() as c:
                    check('Prediction not auto-saved',c.scalar(select(func.count()).select_from(predictions))==len(saved))
                response=alice.post('/api/records',json={'draft_id':draft})
                check('Explicit encrypted save '+name,response.status_code==201)
                rid=response.json()['id']; saved.append(rid)
                check('Save retry idempotent',alice.post('/api/records',json={'draft_id':draft}).json()['id']==rid)
                check('Own record integrity verified',alice.get('/api/records/'+rid).json()['integrity_verified'])
                check('Image bytes exact',alice.get('/api/records/'+rid+'/image').content==raw)
                check('Foreign record denied',bob.get('/api/records/'+rid).status_code==403)
                check('Foreign image denied',bob.get('/api/records/'+rid+'/image').status_code==403)
                check('Admin decryption denied',admin.get('/api/records/'+rid).status_code==403)
            with application.state.engine.connect() as c:
                check('One deduplicated encrypted image',c.scalar(select(func.count()).select_from(images))==1)
                check('Two immutable prediction records',c.scalar(select(func.count()).select_from(predictions))==2)
                check('Passwords are Argon2id hashes',all(r.startswith('$argon2id$') for r in c.scalars(select(users.c.password_hash))))
                check('Denied access audit exists',c.scalar(select(func.count()).select_from(audit).where(audit.c.status=='DENIED'))>0)
            check('No plaintext details in SQLite',b'Fictional Alice Example' not in (Path(temp)/'test.db').read_bytes())
            check('Admin statistics',admin.get('/api/admin').json()['predictions']==2)
            dashboard=admin.get('/api/admin').json()
            check('Admin model totals',sum(r['count'] for r in dashboard['predictions_by_model'])==2)
            check('Admin activity totals',dashboard['activity_24h']['predictions']==2 and dashboard['activity_24h']['denied']>0)
            check('Admin unique image count',dashboard['unique_images']==1)
            check('Admin checkpoint availability',len(dashboard['models'])==2 and all(m['checkpoint_present'] for m in dashboard['models']))
            check('Admin metadata excludes private fields','Fictional Alice Example' not in str(dashboard) and 'password_hash' not in str(dashboard) and 'ciphertext' not in str(dashboard))

            uid=alice.get('/api/me').json()['user']['id']
            check('Patient cannot deactivate user',bob.patch('/api/admin/users/'+uid,json={'active':False}).status_code==403)
            check('Admin can deactivate patient',admin.patch('/api/admin/users/'+uid,json={'active':False}).status_code==200)
            check('Deactivated session invalidated',alice.get('/api/records').status_code==401)
            admin.patch('/api/admin/users/'+uid,json={'active':True})
            response=alice.post('/api/login',json=dict(username='alice',password=password)); alice.headers['x-csrf-token']=response.json()['csrf']
            with application.state.engine.begin() as c: c.execute(update(images).values(ciphertext=b'tampered'))
            check('Ciphertext tampering rejected',alice.get('/api/records/'+saved[0]+'/image').status_code==409)
            check('Logout succeeds',alice.post('/api/logout').status_code==200)
            check('Logout blocks further access',alice.get('/api/records').status_code==401)
    print(f'ALL {len(checks)} API CHECKS PASSED')

if __name__=='__main__': run()
