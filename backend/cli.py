"""Offline provisioning and password rotation; secrets are prompted, never argv."""
import argparse
import getpass
from .config import Settings, prepare
from .db import connect, migrate
from .security import audit, now, passwords, uid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['init', 'create-admin', 'reset-password'])
    parser.add_argument('--username')
    args = parser.parse_args()
    settings = Settings.environment()
    prepare(settings)
    migrate(settings)
    if args.command == 'init':
        return
    import re
    name = (args.username or input('Username: ')).lower()
    if not re.fullmatch(r'[a-z0-9_.-]{3,64}', name):
        parser.error('Invalid username')
    password = getpass.getpass('Password (12-128 characters): ')
    if not 12 <= len(password) <= 128 or password != getpass.getpass('Confirm password: '):
        parser.error('Password length or confirmation invalid')
    with connect(settings) as db:
        user = db.execute('SELECT id FROM users WHERE username=?', (name,)).fetchone()
        if args.command == 'create-admin':
            if user:
                parser.error('Username already exists')
            identifier = uid()
            db.execute("INSERT INTO users(id,username,password_hash,role,console_only,created_at) VALUES(?,?,?,'admin',1,?)",
                       (identifier, name, passwords.hash(password), now()))
        else:
            if not user:
                parser.error('Unknown username')
            identifier = user['id']
            db.execute('UPDATE users SET password_hash=?,password_until=NULL WHERE id=?',
                       (passwords.hash(password), identifier))
            db.execute('UPDATE sessions SET revoked=1 WHERE user_id=?', (identifier,))
        audit(db, 'offline.' + args.command, 'allowed', target=identifier)


if __name__ == '__main__':
    main()
