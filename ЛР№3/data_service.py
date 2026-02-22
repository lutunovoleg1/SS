"""
Сервис данных: отдаёт данные только авторизованным пользователям/сервисам.
Проверка JWT через общий секрет (без вызова auth_service на каждый запрос).
Логирование всех запросов и попыток доступа.
"""
import os
import sqlite3
import logging
from contextlib import closing
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import jwt

DB_PATH = "data.db"
JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-in-production")
JWT_ALGORITHM = "HS256"

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "data_service.log"), encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("data_service")

security = HTTPBearer(auto_error=False)


def init_db() -> None:
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                owner_id INTEGER NOT NULL,
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
                user_id TEXT,
                username TEXT,
                success INTEGER NOT NULL,
                status_code INTEGER,
                detail TEXT
            )
            """
        )
        conn.commit()


def log_access(
    method: str,
    path: str,
    user_id: Optional[str],
    username: Optional[str],
    success: bool,
    status_code: int,
    detail: str = "",
):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            """INSERT INTO access_log (at, method, path, user_id, username, success, status_code, detail)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.utcnow().isoformat(),
                method,
                path,
                user_id,
                username,
                1 if success else 0,
                status_code,
                detail,
            ),
        )
        conn.commit()
    logger.info(
        "method=%s path=%s user_id=%s username=%s success=%s status=%s detail=%s",
        method, path, user_id, username, success, status_code, detail or "-",
    )


def verify_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> dict:
    if not credentials or not credentials.credentials:
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return {"user_id": payload.get("sub"), "username": payload.get("username")}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


class DocumentCreate(BaseModel):
    title: str
    content: str


class Document(BaseModel):
    id: int
    title: str
    content: str
    owner_id: int
    created_at: str


app = FastAPI(title="Data Service", version="1.0.0")


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    logger.info("Data service started")


@app.middleware("http")
async def log_requests(request, call_next):
    response = await call_next(request)
    logger.info("request method=%s path=%s status_code=%s", request.method, request.url.path, response.status_code)
    return response


@app.post("/documents", response_model=Document, status_code=201)
def create_document(
    data: DocumentCreate,
    token_data: dict = Depends(verify_token),
) -> Document:
    user_id = token_data["user_id"]
    username = token_data["username"]
    try:
        owner_id = int(user_id)
    except (TypeError, ValueError):
        owner_id = 0

    with closing(sqlite3.connect(DB_PATH)) as conn:
        cur = conn.execute(
            "INSERT INTO documents (title, content, owner_id, created_at) VALUES (?, ?, ?, ?)",
            (data.title, data.content, owner_id, datetime.utcnow().isoformat()),
        )
        conn.commit()
        doc_id = cur.lastrowid
        row = conn.execute(
            "SELECT id, title, content, owner_id, created_at FROM documents WHERE id = ?",
            (doc_id,),
        ).fetchone()

    log_access("POST", "/documents", user_id, username, True, 201)
    return Document(id=row[0], title=row[1], content=row[2], owner_id=row[3], created_at=row[4])


@app.get("/documents", response_model=List[Document])
def list_documents(token_data: dict = Depends(verify_token)) -> List[Document]:
    user_id = token_data["user_id"]
    username = token_data["username"]

    with closing(sqlite3.connect(DB_PATH)) as conn:
        rows = conn.execute(
            "SELECT id, title, content, owner_id, created_at FROM documents ORDER BY id"
        ).fetchall()

    log_access("GET", "/documents", user_id, username, True, 200)
    return [
        Document(id=r[0], title=r[1], content=r[2], owner_id=r[3], created_at=r[4])
        for r in rows
    ]


@app.get("/documents/{document_id}", response_model=Document)
def get_document(
    document_id: int,
    token_data: dict = Depends(verify_token),
) -> Document:
    user_id = token_data["user_id"]
    username = token_data["username"]

    with closing(sqlite3.connect(DB_PATH)) as conn:
        row = conn.execute(
            "SELECT id, title, content, owner_id, created_at FROM documents WHERE id = ?",
            (document_id,),
        ).fetchone()

    if row is None:
        log_access("GET", f"/documents/{document_id}", user_id, username, False, 404, "not found")
        raise HTTPException(status_code=404, detail="Document not found")

    log_access("GET", f"/documents/{document_id}", user_id, username, True, 200)
    return Document(id=row[0], title=row[1], content=row[2], owner_id=row[3], created_at=row[4])


@app.get("/me")
def me(token_data: dict = Depends(verify_token)) -> dict:
    log_access("GET", "/me", token_data["user_id"], token_data["username"], True, 200)
    return {"user_id": token_data["user_id"], "username": token_data["username"]}


@app.exception_handler(HTTPException)
async def log_http_exception(request, exc: HTTPException):
    if exc.status_code == 401:
        log_access(request.method, request.url.path, None, None, False, 401, exc.detail or "unauthorized")
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
