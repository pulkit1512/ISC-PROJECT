"""SQLAlchemy schema; Alembic upgrades this database before serving requests."""
from sqlalchemy import MetaData, Table, Column, String, Integer, Float, LargeBinary, ForeignKey, UniqueConstraint, CheckConstraint

metadata = MetaData()
users = Table('users', metadata,
    Column('id', String, primary_key=True), Column('username', String, unique=True, nullable=False),
    Column('password_hash', String, nullable=False), Column('role', String, nullable=False),
    Column('active', Integer, nullable=False, default=1), Column('failures', Integer, nullable=False, default=0),
    Column('locked_until', Float, nullable=False, default=0), Column('created_at', String, nullable=False),
    CheckConstraint("role IN ('PATIENT','ADMIN')"))
profiles = Table('patient_profiles', metadata,
    Column('user_id', String, ForeignKey('users.id'), primary_key=True),
    Column('ciphertext', LargeBinary, nullable=False), Column('nonce', LargeBinary, nullable=False),
    Column('version', Integer, nullable=False), Column('updated_at', String, nullable=False))
sessions = Table('sessions', metadata,
    Column('token_hash', String, primary_key=True), Column('user_id', String, ForeignKey('users.id'), nullable=False),
    Column('csrf', String, nullable=False), Column('expires', Float, nullable=False))
images = Table('medical_images', metadata,
    Column('id', String, primary_key=True), Column('user_id', String, ForeignKey('users.id'), nullable=False),
    Column('lookup', String, nullable=False), Column('ciphertext', LargeBinary, nullable=False),
    Column('nonce', LargeBinary, nullable=False), Column('created_at', String, nullable=False),
    UniqueConstraint('user_id','lookup'))
predictions = Table('predictions', metadata,
    Column('id', String, primary_key=True), Column('user_id', String, ForeignKey('users.id'), nullable=False),
    Column('image_id', String, ForeignKey('medical_images.id'), nullable=False),
    Column('ciphertext', LargeBinary, nullable=False), Column('nonce', LargeBinary, nullable=False),
    Column('model_version', String, nullable=False), Column('created_at', String, nullable=False))
audit = Table('audit_logs', metadata,
    Column('id', Integer, primary_key=True), Column('actor_id', String), Column('action', String, nullable=False),
    Column('reference', String), Column('status', String, nullable=False), Column('created_at', String, nullable=False))
settings = Table('settings', metadata, Column('name', String, primary_key=True), Column('value', String, nullable=False))
attempts = Table('auth_attempts', metadata,
    Column('bucket', String, primary_key=True), Column('count', Integer, nullable=False), Column('reset_at', Float, nullable=False))
