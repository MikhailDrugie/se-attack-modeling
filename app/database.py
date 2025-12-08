from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from config import ASYNC_DATABASE_URL


ENGINE = create_async_engine(
    ASYNC_DATABASE_URL,
    echo=True,  # True => debug
)
async_session = sessionmaker(
    ENGINE, 
    class_=AsyncSession, 
    expire_on_commit=False  # чтобы объекты не "протухали" после коммита
)


async def get_db():
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()
