"""Privately provision the sole administrator from the host terminal."""
from getpass import getpass

from sqlalchemy import select, insert, func
from sqlalchemy.exc import IntegrityError
from pydantic import ValidationError

from api import Credentials, create_app, identifier, shared, utc
from database import users, audit


def provision_admin(engine, username, password):
    data = Credentials(username=username, password=password)
    with engine.begin() as connection:
        connection.exec_driver_sql('BEGIN IMMEDIATE')
        if connection.scalar(select(func.count()).select_from(users).where(users.c.role == 'ADMIN')):
            raise ValueError('An administrator already exists. Sign in with that account.')
        uid = identifier()
        connection.execute(insert(users).values(
            id=uid, username=data.username.lower(), password_hash=shared.PH.hash(data.password),
            role='ADMIN', created_at=utc()))
        connection.execute(insert(audit).values(
            actor_id=uid, action='ADMIN_PROVISIONED_LOCALLY', status='OK', created_at=utc()))
    return uid


def main():
    application = create_app()
    engine = application.state.engine
    try:
        with engine.connect() as connection:
            if connection.scalar(select(func.count()).select_from(users).where(users.c.role == 'ADMIN')):
                print('An administrator already exists. Use the normal website sign-in page.')
                return
        username = input('Choose admin username: ').strip()
        password = getpass('Choose password (at least 12 characters; hidden): ')
        if password != getpass('Confirm password (hidden): '):
            print('Passwords did not match. Nothing was created.')
            return
        provision_admin(engine, username, password)
        print('Account created. Sign in through the normal website login.')
    except ValidationError:
        print('Use a username of 3-40 letters, numbers, underscores or hyphens and a password of 12-256 characters.')
    except IntegrityError:
        print('That username is already taken. No account was changed.')
    except ValueError as exc:
        print(str(exc))
    finally:
        engine.dispose()


if __name__ == '__main__':
    main()
