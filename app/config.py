from contextvars import ContextVar
from enums import Lang


# DB
DB_HOST = 'db'
DB_USER = 'admin'
DB_PASS = '123456'
DB_NAME = 'attack_modeling'
# DB URLS
SYNC_DATABASE_URL = f'postgresql+psycopg2://{DB_USER}:{DB_PASS}@{DB_HOST}:5432/{DB_NAME}'
ASYNC_DATABASE_URL = f'postgresql+asyncpg://{DB_USER}:{DB_PASS}@{DB_HOST}:5432/{DB_NAME}'

cur_lang: ContextVar[Lang] = ContextVar("cur_lang", default=Lang.RU)
