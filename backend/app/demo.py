"""Explicitly provision the optional local demo account; never run on deployment."""
from sqlalchemy import select
from .db import Session, User
from .security import uid, password_hash, password_ok

EMAIL = 'demo@scamshield.test'
PASSWORD = 'ScamShieldDemo123!'

def main():
    with Session() as db:
        existing = db.scalar(select(User).where(User.email == EMAIL))
        if existing:
            if existing.role != 'user' or not password_ok(PASSWORD, existing.password) or not existing.verified:
                raise SystemExit('Demo email is already in use with different account settings; no changes made.')
            print('Local demo account is already available.')
            return
        db.add(User(id=uid(), email=EMAIL, password=password_hash(PASSWORD), role='user', verified=1))
        db.commit()
        print('Local demo account created: '+EMAIL)

if __name__ == '__main__':
    main()
