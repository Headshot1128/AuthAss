import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    database: str = 'data/auth.db'
    storage: str = 'data/private'
    access_seconds: int = 300
    session_seconds: int = 86400
    require_https: bool = True
    registration: bool = False
    rate_limit: int = 30
    license_key_file: str | None = None
    owner_username: str = 'gerry2.0'

    @classmethod
    def environment(cls):
        return cls(database=os.getenv('AUTH_DATABASE', 'data/auth.db'),
                   storage=os.getenv('AUTH_STORAGE', 'data/private'),
                   registration=os.getenv('AUTH_REGISTRATION', 'false') == 'true',
                   license_key_file=os.getenv('AUTH_LICENSE_KEY_FILE'),
                   owner_username=os.getenv('AUTH_OWNER_USERNAME', 'gerry2.0').lower())


def prepare(settings):
    Path(settings.database).parent.mkdir(parents=True, exist_ok=True)
    Path(settings.storage).mkdir(parents=True, exist_ok=True)
