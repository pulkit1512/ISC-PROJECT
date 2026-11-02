"""Shared model inference and isolated notebook security experiments; no web UI."""
from pathlib import Path
import contextlib
import hashlib
import hmac
import os
import io
import json
import secrets
import sqlite3
import time
import uuid
import warnings
import tempfile
from datetime import datetime, timezone

import torch
from torch import nn
from torchvision import transforms
from torchvision.models import resnet18
from PIL import Image, UnidentifiedImageError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerificationError, InvalidHashError

BASE = Path(__file__).resolve().parent
CLASS_MAP = {"NORMAL": 0, "PNEUMONIA": 1}
MEAN, STD = [0.5] * 3, [0.5] * 3
RESNET_MEAN, RESNET_STD = [0.485, 0.456, 0.406], [0.229, 0.224, 0.225]
MODEL_FILES = {'Custom CNN': 'securemed_model.pth', 'ResNet18': 'securemed_resnet18.pth'}
MAX_UPLOAD = int(os.environ.get("SECUREMED_MAX_UPLOAD_MB", "10")) * 1024 * 1024
if not 1 <= MAX_UPLOAD <= 100 * 1024 * 1024:
    raise ValueError("SECUREMED_MAX_UPLOAD_MB must be between 1 and 100.")
PH = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, type=Type.ID)


class SecureMedCNN(nn.Module):
    def __init__(self):
        super().__init__()
        layers = []
        for a, b in zip([3, 32, 64, 128], [32, 64, 128, 256]):
            layers += [nn.Conv2d(a, b, 3, padding=1), nn.BatchNorm2d(b),
                       nn.ReLU(), nn.MaxPool2d(2)]
        self.features = nn.Sequential(*layers)
        self.classifier = nn.Sequential(nn.AdaptiveAvgPool2d(1), nn.Flatten(),
                                        nn.Linear(256, 128), nn.ReLU(),
                                        nn.Dropout(0.4), nn.Linear(128, 1))

    def forward(self, x):
        return self.classifier(self.features(x)).squeeze(1)


def preprocessing(mean=MEAN, std=STD):
    return transforms.Compose([transforms.Resize((224, 224)), transforms.ToTensor(),
                               transforms.Normalize(mean, std)])


def validate_image(raw):
    if not raw or len(raw) > MAX_UPLOAD:
        raise ValueError(f"Image must be nonempty and at most {MAX_UPLOAD // (1024 * 1024)} MB.")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(raw)) as im:
                if im.format not in {"PNG", "JPEG"} or im.width * im.height > 20_000_000:
                    raise ValueError("Use a PNG/JPEG with at most 20 million pixels.")
                im.verify()
            with Image.open(io.BytesIO(raw)) as im:
                return im.convert("RGB")
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError,
            Image.DecompressionBombWarning) as exc:
        raise ValueError("Invalid or unsafe image.") from exc


def load_model(path=BASE / "securemed_model.pth"):
    if not Path(path).is_file():
        raise FileNotFoundError("Train the notebook first to create securemed_model.pth.")
    ck = torch.load(path, map_location="cpu", weights_only=True)
    architecture = ck.get('architecture')
    expected = {'SecureMedCNN-v1': (MEAN, STD), 'ResNet18-v1': (RESNET_MEAN, RESNET_STD)}
    if (architecture not in expected or ck.get("class_mapping") != CLASS_MAP
            or ck.get("image_size") != 224 or (ck.get("mean"), ck.get("std")) != expected.get(architecture)
            or not 0 < ck.get("threshold", 0) < 1 or not ck.get("trained")):
        raise ValueError("Incompatible or untrained checkpoint.")
    if architecture == 'ResNet18-v1':
        model = resnet18(weights=None)
        model.fc = nn.Linear(model.fc.in_features, 1)
    else:
        model = SecureMedCNN()
    model.load_state_dict(ck["state_dict"], strict=True)
    return model.eval(), ck


def predict(raw, model, metadata):
    image = validate_image(raw)
    start = time.perf_counter()
    with torch.inference_mode():
        score = model(preprocessing(metadata['mean'], metadata['std'])(image).unsqueeze(0)).sigmoid().item()
    return {"label": "PNEUMONIA" if score >= metadata["threshold"] else "NORMAL",
            "score": score, "threshold": metadata["threshold"],
            "model_version": metadata["model_version"],
            "inference_seconds": time.perf_counter() - start}


def generate_key():
    return AESGCM.generate_key(bit_length=256)


def encrypt_bytes(key, raw, reference, field):
    nonce = secrets.token_bytes(12)
    return AESGCM(key).encrypt(nonce, raw, f"securemed:v1:{reference}:{field}".encode()), nonce


def decrypt_bytes(key, ciphertext, nonce, reference, field):
    return AESGCM(key).decrypt(nonce, ciphertext, f"securemed:v1:{reference}:{field}".encode())


def verify_integrity(raw, expected):
    return secrets.compare_digest(hashlib.sha256(raw).hexdigest(), expected)


def now():
    return datetime.now(timezone.utc).isoformat()


class Store:
    """Authorization is enforced here, independently of Streamlit navigation.

    Opaque sessions are minted only after password verification. Local Python code
    and the filesystem remain trusted; this is not a sandbox against its operator.
    """
    def __init__(self, path):
        self.path = str(path)
        self.sessions = {}
        with self.db() as c:
            c.executescript('''
            CREATE TABLE IF NOT EXISTS users(user_id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
              password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('ADMIN','DOCTOR','VIEWER')),
              created_at TEXT NOT NULL, failures INTEGER NOT NULL DEFAULT 0, locked_until REAL NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS patients(patient_id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(user_id),
              encrypted_details BLOB NOT NULL, nonce BLOB NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS medical_records(record_id TEXT PRIMARY KEY,
              patient_id TEXT NOT NULL REFERENCES patients(patient_id), encrypted_image BLOB NOT NULL,
              image_nonce BLOB NOT NULL, encrypted_prediction BLOB NOT NULL, prediction_nonce BLOB NOT NULL,
              model_version TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS grants(record_id TEXT REFERENCES medical_records(record_id),
              user_id TEXT REFERENCES users(user_id), PRIMARY KEY(record_id,user_id));
            CREATE TABLE IF NOT EXISTS audit_logs(log_id INTEGER PRIMARY KEY, actor_id TEXT,
              action TEXT NOT NULL, record_reference TEXT, timestamp TEXT NOT NULL, status TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS key_metadata(id INTEGER PRIMARY KEY CHECK(id=1), salt BLOB NOT NULL,
              verifier BLOB NOT NULL, nonce BLOB NOT NULL);
            CREATE INDEX IF NOT EXISTS records_patient ON medical_records(patient_id);
            CREATE INDEX IF NOT EXISTS patients_owner ON patients(owner_id);
            CREATE TABLE IF NOT EXISTS patient_access(
              patient_id TEXT NOT NULL REFERENCES patients(patient_id),
              user_id TEXT NOT NULL REFERENCES users(user_id),
              permission TEXT NOT NULL CHECK(permission IN ('READ','WRITE')),
              granted_by TEXT NOT NULL REFERENCES users(user_id),
              granted_at TEXT NOT NULL, PRIMARY KEY(patient_id,user_id));
            CREATE TABLE IF NOT EXISTS patient_history(
              patient_id TEXT NOT NULL REFERENCES patients(patient_id), version INTEGER NOT NULL,
              encrypted_details BLOB NOT NULL, nonce BLOB NOT NULL,
              changed_by TEXT NOT NULL REFERENCES users(user_id), changed_at TEXT NOT NULL,
              PRIMARY KEY(patient_id,version));
            CREATE TABLE IF NOT EXISTS encrypted_images(
              image_id TEXT PRIMARY KEY, patient_id TEXT NOT NULL REFERENCES patients(patient_id),
              dedup_token TEXT NOT NULL, ciphertext BLOB NOT NULL, nonce BLOB NOT NULL,
              created_at TEXT NOT NULL, UNIQUE(patient_id,dedup_token));
            ''')
            # Additive migration preserves existing records; no implicit access grants.
            for table, column, definition in [
                ('users', 'active', 'INTEGER NOT NULL DEFAULT 1'),
                ('patients', 'version', 'INTEGER NOT NULL DEFAULT 1'),
                ('patients', 'updated_at', "TEXT NOT NULL DEFAULT ''"),
                ('medical_records', 'patient_version', 'INTEGER NOT NULL DEFAULT 1'),
                ('medical_records', 'created_by', 'TEXT REFERENCES users(user_id)'),
                ('medical_records', 'image_id', 'TEXT REFERENCES encrypted_images(image_id)'),
            ]:
                if column not in {r[1] for r in c.execute(f'PRAGMA table_info({table})')}:
                    c.execute(f'ALTER TABLE {table} ADD COLUMN {column} {definition}')

    @contextlib.contextmanager
    def db(self):
        c = sqlite3.connect(self.path, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        try:
            with c:
                yield c
        finally:
            c.close()

    def audit(self, actor, action, reference=None, status="OK"):
        with self.db() as c:
            c.execute("INSERT INTO audit_logs(actor_id,action,record_reference,timestamp,status) VALUES(?,?,?,?,?)",
                      (actor, action, reference, now(), status))

    def initialized(self):
        with self.db() as c:
            return c.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0

    @staticmethod
    def credentials(username, password):
        if not 3 <= len(username) <= 40 or not all(x.isalnum() or x in '_-' for x in username):
            raise ValueError("Username: 3–40 letters, numbers, underscores or hyphens.")
        if not 12 <= len(password) <= 256:
            raise ValueError("Use a password of 12–256 characters.")

    def bootstrap(self, username, password, passphrase):
        self.credentials(username, password)
        if not 16 <= len(passphrase) <= 256:
            raise ValueError("Use a separate master passphrase of 16–256 characters.")
        if secrets.compare_digest(password, passphrase):
            raise ValueError("Admin password and master passphrase must differ.")
        salt = secrets.token_bytes(16)
        key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode())
        cipher, nonce = encrypt_bytes(key, b"SecureMed key check", "master", "verifier")
        with self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            if c.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
                raise PermissionError("Setup is already complete.")
            c.execute("INSERT INTO users(user_id,username,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                      (uuid.uuid4().hex, username, PH.hash(password), "ADMIN", now()))
            c.execute("INSERT INTO key_metadata VALUES(1,?,?,?)", (salt, cipher, nonce))
        self.audit(None, "INITIAL_SETUP")

    def login(self, username, password):
        if len(username) > 40 or len(password) > 256:
            raise PermissionError("Login failed.")
        with self.db() as c:
            row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            valid = False
            if row and row["active"] and row["locked_until"] <= time.time():
                try:
                    valid = PH.verify(row["password_hash"], password)
                except (VerificationError, InvalidHashError):
                    pass
            if row and not valid and row["locked_until"] <= time.time():
                # Attempts during a lock must not extend it. Start a fresh failure
                # window after a previous lock has expired.
                failures = (0 if row["locked_until"] > 0 else row["failures"]) + 1
                c.execute("UPDATE users SET failures=?,locked_until=? WHERE user_id=?",
                          (failures, time.time() + 60 if failures >= 5 else 0, row["user_id"]))
            if valid:
                c.execute("UPDATE users SET failures=0,locked_until=0 WHERE user_id=?", (row["user_id"],))
        self.audit(row["user_id"] if row else None, "LOGIN", status="OK" if valid else "DENIED")
        if not valid:
            raise PermissionError("Login failed or temporarily locked. Try again later.")
        token = secrets.token_urlsafe(32)
        self.sessions[token] = (row["user_id"], time.time() + 1800)
        return token

    def actor(self, token, roles=("ADMIN", "DOCTOR", "VIEWER")):
        session = self.sessions.get(token)
        if not session or session[1] < time.time():
            self.sessions.pop(token, None)
            raise PermissionError("Please sign in again.")
        with self.db() as c:
            row = c.execute("SELECT user_id,username,role,active FROM users WHERE user_id=?", (session[0],)).fetchone()
        if not row or not row["active"] or row["role"] not in roles:
            self.audit(session[0], "AUTHORIZATION", status="DENIED")
            raise PermissionError("Access denied.")
        return dict(row)

    @contextlib.contextmanager
    def authorized(self, token, action, roles, pid=None, permission=None, rid=None):
        """Recheck identity, active flag, role and DB permissions inside one transaction.

        BEGIN IMMEDIATE serializes permission changes with clinical writes. Successful
        writes and their audit entry commit together. Denials are logged after rollback.
        No caller-supplied identity or role is used to authorize an operation.
        """
        uid = None
        try:
            with self.db() as c:
                c.execute('BEGIN IMMEDIATE')
                session = self.sessions.get(token)
                if not session or session[1] < time.time():
                    raise PermissionError('Please sign in again.')
                uid = session[0]
                actor = c.execute('SELECT user_id,username,role,active FROM users WHERE user_id=?', (uid,)).fetchone()
                if not actor or not actor['active'] or actor['role'] not in roles:
                    raise PermissionError('Access denied.')
                if rid is not None:
                    record = c.execute('SELECT patient_id FROM medical_records WHERE record_id=?', (rid,)).fetchone()
                    if not record:
                        raise PermissionError('Access denied.')
                    pid = record[0]
                if pid is not None and permission:
                    access = c.execute('SELECT permission FROM patient_access WHERE patient_id=? AND user_id=?', (pid, uid)).fetchone()
                    if not access or (permission == 'WRITE' and access[0] != 'WRITE'):
                        raise PermissionError('Patient permission denied.')
                    if actor['role'] == 'VIEWER':
                        if permission != 'READ' or rid is None or not c.execute(
                            'SELECT 1 FROM grants WHERE record_id=? AND user_id=?', (rid, uid)).fetchone():
                            raise PermissionError('Explicit record permission required.')
                yield c, dict(actor)
                c.execute('INSERT INTO audit_logs(actor_id,action,record_reference,timestamp,status) VALUES(?,?,?,?,?)',
                          (uid, action, rid or pid, now(), 'OK'))
        except (PermissionError, ValueError, sqlite3.Error, InvalidTag) as exc:
            # Never record untrusted references, plaintext, secrets or exception text.
            self.audit(uid, action, status='DENIED' if isinstance(exc, PermissionError) else 'REJECTED')
            raise

    def logout(self, token):
        session = self.sessions.pop(token, None)
        if session:
            self.audit(session[0], "LOGOUT")

    def unlock(self, token, passphrase):
        self.actor(token, ("DOCTOR", "VIEWER"))
        if not 16 <= len(passphrase) <= 256:
            raise ValueError("Invalid master passphrase length.")
        with self.db() as c:
            row = c.execute("SELECT * FROM key_metadata WHERE id=1").fetchone()
        key = Scrypt(salt=row["salt"], length=32, n=2**15, r=8, p=1).derive(passphrase.encode())
        decrypt_bytes(key, row["verifier"], row["nonce"], "master", "verifier")
        return key

    def create_user(self, token, username, password, role):
        self.credentials(username, password)
        if role not in ('ADMIN', 'DOCTOR', 'VIEWER'):
            raise ValueError('Invalid role.')
        uid = uuid.uuid4().hex
        with self.authorized(token, 'CREATE_USER', ('ADMIN',)) as (c, actor):
            c.execute('INSERT INTO users(user_id,username,password_hash,role,created_at) VALUES(?,?,?,?,?)',
                      (uid, username, PH.hash(password), role, now()))
        return uid

    def manage_user(self, token, username, role, active):
        if role not in ('ADMIN', 'DOCTOR', 'VIEWER') or type(active) is not bool:
            raise ValueError('Invalid account settings.')
        with self.authorized(token, 'MANAGE_USER', ('ADMIN',)) as (c, actor):
            target = c.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
            if not target:
                raise ValueError('Account not found.')
            if target['user_id'] == actor['user_id']:
                raise ValueError('Use another administrator to change your own account.')
            c.execute('UPDATE users SET role=?,active=? WHERE user_id=?', (role, int(active), target['user_id']))
            # Revocation/demotion removes stale permissions; reactivation never restores them.
            if not active or role != target['role']:
                c.execute('DELETE FROM patient_access WHERE user_id=?', (target['user_id'],))
                c.execute('DELETE FROM grants WHERE user_id=?', (target['user_id'],))
            c.execute('INSERT INTO audit_logs(actor_id,action,record_reference,timestamp,status) VALUES(?,?,?,?,?)',
                      (actor['user_id'], 'ACCOUNT_CHANGED', target['user_id'], now(), 'OK'))

    def admin_metadata(self, token):
        with self.authorized(token, 'ADMIN_METADATA', ('ADMIN',)) as (c, actor):
            return dict(users=[dict(r) for r in c.execute('SELECT user_id,username,role,active FROM users')],
                        patients=[dict(r) for r in c.execute('SELECT patient_id,version,created_at FROM patients')],
                        records=[dict(r) for r in c.execute('SELECT record_id,patient_id,created_at FROM medical_records')],
                        access=[dict(r) for r in c.execute('SELECT * FROM patient_access')])

    def assign_patient(self, token, pid, username, permission):
        if permission not in ('READ', 'WRITE', 'REVOKE'):
            raise ValueError('Invalid permission.')
        with self.authorized(token, 'ASSIGN_PATIENT', ('ADMIN',), pid=pid) as (c, actor):
            target = c.execute('SELECT user_id,role,active FROM users WHERE username=?', (username,)).fetchone()
            if not target or not c.execute('SELECT 1 FROM patients WHERE patient_id=?', (pid,)).fetchone():
                raise ValueError('Account or patient reference not found.')
            if permission == 'REVOKE':
                c.execute('DELETE FROM patient_access WHERE patient_id=? AND user_id=?', (pid, target['user_id']))
                c.execute('DELETE FROM grants WHERE user_id=? AND record_id IN (SELECT record_id FROM medical_records WHERE patient_id=?)', (target['user_id'], pid))
            else:
                if not target['active'] or target['role'] not in ('DOCTOR', 'VIEWER') or (target['role'] == 'VIEWER' and permission != 'READ'):
                    raise PermissionError('Incompatible active role and permission.')
                c.execute('INSERT INTO patient_access VALUES(?,?,?,?,?) ON CONFLICT(patient_id,user_id) DO UPDATE SET permission=excluded.permission,granted_by=excluded.granted_by,granted_at=excluded.granted_at',
                          (pid, target['user_id'], permission, actor['user_id'], now()))

    @staticmethod
    def validate_details(details):
        if not isinstance(details, dict) or not isinstance(details.get('fictional_name'), str) or not 1 <= len(details['fictional_name']) <= 100:
            raise ValueError('Provide a fictional name of 1–100 characters.')
        if type(details.get('age')) is not int or not 0 <= details['age'] <= 120 or len(json.dumps(details)) > 4000:
            raise ValueError('Invalid fictional patient details.')

    def register_patient(self, token, key, details):
        self.validate_details(details)
        pid = uuid.uuid4().hex
        cipher, nonce = encrypt_bytes(key, json.dumps(details).encode(), pid, 'details')
        with self.authorized(token, 'REGISTER_PATIENT', ('DOCTOR',)) as (c, actor):
            c.execute('INSERT INTO patients(patient_id,owner_id,encrypted_details,nonce,created_at,version,updated_at) VALUES(?,?,?,?,?,?,?)',
                      (pid, actor['user_id'], cipher, nonce, now(), 1, now()))
            c.execute('INSERT INTO patient_history VALUES(?,?,?,?,?,?)', (pid, 1, cipher, nonce, actor['user_id'], now()))
            c.execute('INSERT INTO audit_logs(actor_id,action,record_reference,timestamp,status) VALUES(?,?,?,?,?)',
                      (actor['user_id'], 'PATIENT_AWAITING_ASSIGNMENT', pid, now(), 'OK'))
        # Creating a patient does not self-grant clinical access. Admin assigns it.
        return pid

    def patients(self, token):
        with self.authorized(token, 'LIST_ASSIGNED_PATIENTS', ('DOCTOR',)) as (c, actor):
            return [r[0] for r in c.execute('SELECT patient_id FROM patient_access WHERE user_id=?', (actor['user_id'],))]

    def patient_version(self, token, pid, write=False):
        with self.authorized(token, 'CHECK_PATIENT_ACCESS', ('DOCTOR',), pid, 'WRITE' if write else 'READ') as (c, actor):
            return c.execute('SELECT version FROM patients WHERE patient_id=?', (pid,)).fetchone()[0]

    def view_patient(self, token, key, pid):
        with self.authorized(token, 'VIEW_PATIENT', ('DOCTOR',), pid, 'READ') as (c, actor):
            row = c.execute('SELECT * FROM patients WHERE patient_id=?', (pid,)).fetchone()
            details = json.loads(decrypt_bytes(key, row['encrypted_details'], row['nonce'], pid, 'details'))
            return details, row['version']

    def edit_patient(self, token, key, pid, details, expected_version):
        with self.authorized(token, 'EDIT_PATIENT', ('DOCTOR',), pid, 'WRITE') as (c, actor):
            if type(expected_version) is not int:
                raise ValueError('A previously read patient version is required.')
            self.validate_details(details)
            cipher, nonce = encrypt_bytes(key, json.dumps(details).encode(), pid, 'details')
            changed = c.execute('UPDATE patients SET encrypted_details=?,nonce=?,version=version+1,updated_at=? WHERE patient_id=? AND version=?',
                                (cipher, nonce, now(), pid, expected_version)).rowcount
            if changed != 1:
                raise ValueError('Concurrent change detected. Reload before editing.')
            c.execute('INSERT INTO patient_history VALUES(?,?,?,?,?,?)',
                      (pid, expected_version + 1, cipher, nonce, actor['user_id'], now()))
        return expected_version + 1

    def patient_history(self, token, key, pid):
        with self.authorized(token, 'VIEW_PATIENT_HISTORY', ('DOCTOR',), pid, 'READ') as (c, actor):
            return [dict(version=r['version'], changed_at=r['changed_at'],
                         details=json.loads(decrypt_bytes(key, r['encrypted_details'], r['nonce'], pid, 'details')))
                    for r in c.execute('SELECT * FROM patient_history WHERE patient_id=? ORDER BY version', (pid,))]

    def predict_for_patient(self, token, pid, raw, model, metadata):
        with self.authorized(token, 'UPLOAD_AND_PREDICT', ('DOCTOR',), pid, 'WRITE') as (c, actor):
            # Validation and inference happen only after active-account and assignment checks.
            result = predict(raw, model, metadata)
            version = c.execute('SELECT version FROM patients WHERE patient_id=?', (pid,)).fetchone()[0]
            return result, version

    def save_record(self, token, key, pid, raw, prediction, expected_version):
        with self.authorized(token, 'SAVE_RECORD', ('DOCTOR',), pid, 'WRITE') as (c, actor):
            validate_image(raw)
            if type(expected_version) is not int:
                raise ValueError('A previously read patient version is required.')
            changed = c.execute('UPDATE patients SET version=version+1,updated_at=? WHERE patient_id=? AND version=?',
                                (now(), pid, expected_version)).rowcount
            if changed != 1:
                raise ValueError('Concurrent change detected. Reload and rerun prediction.')
            rid = uuid.uuid4().hex
            fingerprint = hashlib.sha256(raw).hexdigest()
            # Patient-scoped keyed lookup avoids exposing public-image fingerprints.
            lookup = hmac.new(key, f'dedup:v1:{pid}:{fingerprint}'.encode(), hashlib.sha256).hexdigest()
            image = c.execute('SELECT * FROM encrypted_images WHERE patient_id=? AND dedup_token=?', (pid, lookup)).fetchone()
            if image:
                image_id = image['image_id']
                recovered = decrypt_bytes(key, image['ciphertext'], image['nonce'], f'{pid}:{image_id}', 'image')
                if recovered != raw:
                    raise ValueError('Stored duplicate failed integrity verification.')
            else:
                image_id = uuid.uuid4().hex
                enc, nonce = encrypt_bytes(key, raw, f'{pid}:{image_id}', 'image')
                c.execute('INSERT INTO encrypted_images VALUES(?,?,?,?,?,?)', (image_id, pid, lookup, enc, nonce, now()))
            result = dict(prediction, sha256=fingerprint, patient_id=pid, patient_version=expected_version + 1, image_id=image_id)
            ep, pn = encrypt_bytes(key, json.dumps(result).encode(), rid, 'prediction')
            # Append only: every prediction gets a fresh record ID; previous predictions stay intact.
            c.execute('INSERT INTO medical_records(record_id,patient_id,encrypted_image,image_nonce,encrypted_prediction,prediction_nonce,model_version,created_at,patient_version,created_by,image_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                      (rid, pid, b'', b'', ep, pn, result['model_version'], now(), expected_version + 1, actor['user_id'], image_id))
            c.execute('INSERT INTO audit_logs(actor_id,action,record_reference,timestamp,status) VALUES(?,?,?,?,?)',
                      (actor['user_id'], 'PREDICTION_APPENDED', rid, now(), 'OK'))
        return rid

    def records(self, token):
        with self.authorized(token, 'LIST_RECORDS', ('DOCTOR', 'VIEWER')) as (c, actor):
            return [r[0] for r in c.execute("""SELECT m.record_id FROM medical_records m
                JOIN patient_access a ON a.patient_id=m.patient_id AND a.user_id=?
                WHERE ?='DOCTOR' OR EXISTS(SELECT 1 FROM grants g WHERE g.record_id=m.record_id AND g.user_id=?)
                ORDER BY m.created_at DESC""", (actor['user_id'], actor['role'], actor['user_id']))]

    def retrieve(self, token, key, rid):
        with self.authorized(token, 'READ_RECORD', ('DOCTOR', 'VIEWER'), permission='READ', rid=rid) as (c, actor):
            r = c.execute('SELECT * FROM medical_records WHERE record_id=?', (rid,)).fetchone()
            p = c.execute('SELECT * FROM patients WHERE patient_id=?', (r['patient_id'],)).fetchone()
            result = json.loads(decrypt_bytes(key, r['encrypted_prediction'], r['prediction_nonce'], rid, 'prediction'))
            if result.get('patient_id') != r['patient_id']:
                raise ValueError('Record-to-patient integrity check failed.')
            if r['image_id']:
                if result.get('image_id') != r['image_id']:
                    raise ValueError('Image reference authentication failed.')
                image = c.execute('SELECT * FROM encrypted_images WHERE image_id=? AND patient_id=?', (r['image_id'], r['patient_id'])).fetchone()
                if image is None:
                    raise ValueError('Encrypted image reference missing.')
                raw = decrypt_bytes(key, image['ciphertext'], image['nonce'], f"{r['patient_id']}:{r['image_id']}", 'image')
            else:
                raw = decrypt_bytes(key, r['encrypted_image'], r['image_nonce'], rid, 'image')
            details = json.loads(decrypt_bytes(key, p['encrypted_details'], p['nonce'], p['patient_id'], 'details'))
            if not verify_integrity(raw, result['sha256']):
                raise ValueError('Image integrity check failed.')
            return details, raw, result

    def grant(self, token, rid, username, revoke=False):
        with self.authorized(token, 'REVOKE_RECORD' if revoke else 'GRANT_RECORD', ('ADMIN',), rid=rid) as (c, actor):
            viewer = c.execute("SELECT user_id FROM users WHERE username=? AND role='VIEWER' AND active=1", (username,)).fetchone()
            if not viewer:
                raise ValueError('Active viewer not found.')
            if revoke:
                c.execute('DELETE FROM grants WHERE record_id=? AND user_id=?', (rid, viewer[0]))
            else:
                pid = c.execute('SELECT patient_id FROM medical_records WHERE record_id=?', (rid,)).fetchone()[0]
                c.execute("INSERT INTO patient_access VALUES(?,?,'READ',?,?) ON CONFLICT(patient_id,user_id) DO UPDATE SET permission='READ',granted_by=excluded.granted_by,granted_at=excluded.granted_at",
                          (pid, viewer[0], actor['user_id'], now()))
                c.execute('INSERT OR IGNORE INTO grants VALUES(?,?)', (rid, viewer[0]))

    def audit_rows(self, token):
        with self.authorized(token, 'VIEW_AUDIT', ('ADMIN',)) as (c, actor):
            return [dict(r) for r in c.execute('SELECT * FROM audit_logs ORDER BY log_id DESC LIMIT 200')]

    def counts(self, token):
        actor = self.actor(token)
        if actor['role'] == 'ADMIN':
            with self.authorized(token, 'AGGREGATE_COUNTS', ('ADMIN',)) as (c, actor):
                return c.execute('SELECT COUNT(*) FROM patients').fetchone()[0], c.execute('SELECT COUNT(*) FROM medical_records').fetchone()[0]
        return (len(self.patients(token)) if actor['role'] == 'DOCTOR' else 0), len(self.records(token))

    def storage_stats(self, token):
        with self.authorized(token, 'STORAGE_STATISTICS', ('ADMIN',)) as (c, actor):
            image_bytes = c.execute('SELECT COALESCE(SUM(length(ciphertext)+length(nonce)),0) FROM encrypted_images').fetchone()[0]
            legacy_bytes = c.execute('SELECT COALESCE(SUM(length(encrypted_image)+length(image_nonce)),0) FROM medical_records').fetchone()[0]
            return dict(database_bytes=Path(self.path).stat().st_size,
                        encrypted_image_bytes=image_bytes + legacy_bytes,
                        unique_images=c.execute('SELECT COUNT(*) FROM encrypted_images').fetchone()[0])


