"""
Сервис аутентификации: регистрация, вход, выдача и проверка JWT-токенов.
Остальные микросервисы могут получать валидные токены и проверять их через /validate.
"""
import os
import sqlite3
import logging
from contextlib import closing
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import jwt
import bcrypt

DB_PATH = "auth.db"
JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60

# Логирование: все запросы и попытки доступа
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "auth_service.log"), encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("auth_service")

security = HTTPBearer(auto_error=False)


def _hash_password(password: str) -> str:
    """Хеш пароля через bcrypt (не более 72 байт)."""
    raw = password.encode("utf-8")[:72]
    return bcrypt.hashpw(raw, bcrypt.gensalt()).decode("utf-8")


def _verify_password(password: str, password_hash: str) -> bool:
    """Проверка пароля."""
    raw = password.encode("utf-8")[:72]
    return bcrypt.checkpw(raw, password_hash.encode("utf-8"))


def init_db() -> None:
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS access_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                at TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                username TEXT,
                success INTEGER NOT NULL,
                detail TEXT
            )
            """
        )
        conn.commit()


def log_access(method: str, path: str, username: Optional[str], success: bool, detail: str = ""):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            "INSERT INTO access_log (at, method, path, username, success, detail) VALUES (?, ?, ?, ?, ?, ?)",
            (datetime.utcnow().isoformat(), method, path, username, 1 if success else 0, detail),
        )
        conn.commit()
    msg = f"method={method} path={path} username={username} success={success}"
    if detail:
        msg += f" detail={detail}"
    logger.info(msg)


class UserRegister(BaseModel):
    username: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


app = FastAPI(title="Auth Service", version="1.0.0")


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    logger.info("Auth service started")


@app.middleware("http")
async def log_requests(request, call_next):
    response = await call_next(request)
    # Детали успеха/неудачи логируются в эндпоинтах
    logger.info("request method=%s path=%s status_code=%s", request.method, request.url.path, response.status_code)
    return response


@app.post("/register", status_code=201)
def register(data: UserRegister) -> dict:
    if not data.username.strip():
        log_access("POST", "/register", None, False, "empty username")
        raise HTTPException(status_code=400, detail="Username required")
    if not data.password:
        log_access("POST", "/register", data.username, False, "empty password")
        raise HTTPException(status_code=400, detail="Password required")

    password_hash = _hash_password(data.password)
    with closing(sqlite3.connect(DB_PATH)) as conn:
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (data.username, password_hash, datetime.utcnow().isoformat()),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            log_access("POST", "/register", data.username, False, "username exists")
            raise HTTPException(status_code=400, detail="Username already exists")

    log_access("POST", "/register", data.username, True)
    return {"message": "User registered"}


@app.post("/login", response_model=TokenResponse)
def login(data: UserLogin) -> TokenResponse:
    with closing(sqlite3.connect(DB_PATH)) as conn:
        row = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (data.username,),
        ).fetchone()

    if row is None:
        log_access("POST", "/login", data.username, False, "user not found")
        raise HTTPException(status_code=401, detail="Invalid username or password")

    user_id, username, password_hash = row
    if not _verify_password(data.password, password_hash):
        log_access("POST", "/login", data.username, False, "bad password")
        raise HTTPException(status_code=401, detail="Invalid username or password")

    payload = {
        "sub": str(user_id),
        "username": username,
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXPIRE_MINUTES),
        "iat": datetime.utcnow(),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    log_access("POST", "/login", data.username, True, "token issued")
    return TokenResponse(access_token=token)


@app.get("/validate")
def validate_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> dict:
    if not credentials or not credentials.credentials:
        log_access("GET", "/validate", None, False, "no token")
        raise HTTPException(status_code=401, detail="Missing token")

    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("username")
        sub = payload.get("sub")
        log_access("GET", "/validate", username, True)
        return {"valid": True, "user_id": sub, "username": username}
    except jwt.ExpiredSignatureError:
        log_access("GET", "/validate", None, False, "token expired")
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        log_access("GET", "/validate", None, False, "invalid token")
        raise HTTPException(status_code=401, detail="Invalid token")
