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
# API
SECRET_KEY = "45a0a5d595c54f5bc76f1e408b80fe503922af19d2"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 сутки

cur_lang: ContextVar[Lang] = ContextVar("cur_lang", default=Lang.RU)
