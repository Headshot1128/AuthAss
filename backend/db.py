import sqlite3
from fastapi import HTTPException
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def connect(settings):
    db = sqlite3.connect(settings.database, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    try:
        # Serialize writes and authorization decisions across worker processes.
        db.execute('BEGIN IMMEDIATE')
        yield db
        db.commit()
    except HTTPException:
        # Expected denials may contain audit events, throttle counters, or replay revocations.
        db.commit()
        raise
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


def migrate(settings):
    with sqlite3.connect(settings.database) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY)')
        if not db.execute('SELECT 1 FROM schema_migrations WHERE version=1').fetchone():
            sql = (Path(__file__).parent / 'migrations/001_initial.sql').read_text()
            db.executescript('BEGIN IMMEDIATE;\n' + sql + '\nCOMMIT;')
        if not db.execute('SELECT 1 FROM schema_migrations WHERE version=2').fetchone():
            sql = (Path(__file__).parent / 'migrations/002_console_accounts.sql').read_text()
            db.executescript('BEGIN IMMEDIATE;\n' + sql + '\nCOMMIT;')
        if not db.execute('SELECT 1 FROM schema_migrations WHERE version=3').fetchone():
            sql = (Path(__file__).parent / 'migrations/003_visible_license_keys.sql').read_text()
            db.executescript('BEGIN IMMEDIATE;\n' + sql + '\nCOMMIT;')
        if not db.execute('SELECT 1 FROM schema_migrations WHERE version=4').fetchone():
            sql = (Path(__file__).parent / 'migrations/004_website_approval.sql').read_text()
            db.executescript('BEGIN IMMEDIATE;\n' + sql + '\nCOMMIT;')
        if not db.execute('SELECT 1 FROM schema_migrations WHERE version=5').fetchone():
            sql = (Path(__file__).parent / 'migrations/005_license_freeze.sql').read_text()
            db.executescript('BEGIN IMMEDIATE;\n' + sql + '\nCOMMIT;')
