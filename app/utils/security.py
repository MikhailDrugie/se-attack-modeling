import bcrypt
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
import secrets
from typing import Optional
from config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES


# ============ ПАРОЛИ ============
def hash_password(password: str) -> str:
    """Хэширует пароль"""
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверяет пароль"""
    pwd_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(pwd_bytes, hashed_bytes)


# ============ JWT ТОКЕНЫ ============
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta is not None else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


# ============ API КЛЮЧИ ============
def generate_api_key() -> str:
    random_part = secrets.token_urlsafe(32)
    return f"picsec_live_{random_part}"


def verify_api_key(api_key: str, stored_hash: str) -> bool:
    """Проверка апи ключа с хранимым по нему хэшем"""
    return verify_password(api_key, stored_hash)
