"""Operator commands. Never ships a default privileged password."""
import argparse
import base64
import getpass
import secrets
from sqlalchemy import select
from .db import Session, User
from .security import uid, password_hash

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['create-admin'])
    parser.add_argument('--email', required=True)
    args = parser.parse_args()
    password = getpass.getpass('Admin password (10+ characters): ')
    if len(password) < 10:
        raise SystemExit('Password must contain at least 10 characters')
    with Session() as db:
        if db.scalar(select(User).where(User.email == args.email.lower())):
            raise SystemExit('Account already exists; use the role management API')
        secret = base64.b32encode(secrets.token_bytes(20)).decode()
        db.add(User(id=uid(), email=args.email.lower(), password=password_hash(password), role='admin', verified=1, mfa_secret=secret))
        db.commit()
        print('Add this TOTP secret to an authenticator and store it securely:', secret)

if __name__ == '__main__':
    main()
