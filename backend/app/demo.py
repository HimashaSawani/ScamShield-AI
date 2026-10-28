"""Explicitly provision the optional local demo account; never run on deployment."""
import os
import secrets
from sqlalchemy import select
from .db import Session, User
from .security import uid, password_hash, password_ok

EMAIL = os.getenv('SCAMSHIELD_DEMO_EMAIL', 'demo@scamshield.test')

def main():
    raw_password = os.getenv('SCAMSHIELD_DEMO_PASSWORD')
    generated = False
    if not raw_password:
        raw_password = secrets.token_urlsafe(16)
        generated = True

    with Session() as db:
        existing = db.scalar(select(User).where(User.email == EMAIL))
        if existing:
            if existing.role != 'user' or not existing.verified:
                raise SystemExit('Demo email is already in use with different account settings; no changes made.')
            if os.getenv('SCAMSHIELD_DEMO_PASSWORD') and not password_ok(raw_password, existing.password):
                existing.password = password_hash(raw_password)
                db.commit()
                print(f'Updated local demo account password for {EMAIL} from SCAMSHIELD_DEMO_PASSWORD.')
                return
            print(f'Local demo account is already available: {EMAIL}')
            return

        db.add(User(id=uid(), email=EMAIL, password=password_hash(raw_password), role='user', verified=1))
        db.commit()
        if generated:
            print(f'Local demo account created: {EMAIL}')
            print(f'Generated demo password: {raw_password}')
            print('Note: Set SCAMSHIELD_DEMO_PASSWORD in your environment to specify a custom password.')
        else:
            print(f'Local demo account created: {EMAIL} (configured via SCAMSHIELD_DEMO_PASSWORD)')

if __name__ == '__main__':
    main()
