import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time

try:
    import psycopg
    from psycopg.rows import dict_row
    from psycopg.errors import UniqueViolation
except ImportError:
    psycopg = None
    dict_row = None
    UniqueViolation = None
import uuid
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import parse_qsl

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

APP_DIR = Path(__file__).resolve().parent
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
DB_PATH = Path(os.getenv("DATABASE_PATH", str(APP_DIR / "memorycraft.sqlite3")))
DB_INTEGRITY_ERRORS = (sqlite3.IntegrityError,) + ((UniqueViolation,) if UniqueViolation else ())
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
TOKEN_SECRET = os.getenv("TOKEN_SECRET", "").strip() or (BOT_TOKEN or secrets.token_urlsafe(48))
WEB_ORIGINS = [
    x.strip() for x in os.getenv(
        "WEB_ORIGINS",
        "https://prime-kronos.github.io,http://localhost:8000,http://127.0.0.1:8000"
    ).split(",") if x.strip()
]
TOKEN_TTL = 60 * 60 * 24 * 14
ROOM_LIMIT = 12
TASHKENT_TZ = timezone(timedelta(hours=5))


class PostgresCompat:
    """Small adapter so the existing parameterized SQL can run on SQLite or PostgreSQL."""
    def __init__(self, connection):
        self.connection = connection

    def execute(self, sql, params=()):
        return self.connection.execute(sql.replace("?", "%s"), params)

    def executescript(self, script):
        for statement in script.split(";"):
            if statement.strip():
                self.execute(statement)


@contextmanager
def db():
    if DATABASE_URL:
        if psycopg is None:
            raise RuntimeError("DATABASE_URL задан, но psycopg не установлен.")
        with psycopg.connect(DATABASE_URL, row_factory=dict_row) as con:
            yield PostgresCompat(con)
    else:
        con = sqlite3.connect(DB_PATH, timeout=20)
        try:
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA foreign_keys=ON")
            con.execute("PRAGMA journal_mode=WAL")
            yield con
            con.commit()
        finally:
            con.close()


def current_week_window():
    """A rolling 7-day leaderboard period anchored once in the database."""
    now = int(time.time())
    with db() as con:
        row = con.execute(
            "SELECT period_start FROM leaderboard_periods WHERE id=1"
        ).fetchone()
        if not row:
            con.execute(
                "INSERT INTO leaderboard_periods(id, period_start) VALUES(1, ?) ON CONFLICT(id) DO NOTHING",
                (now,)
            )
            row = con.execute(
                "SELECT period_start FROM leaderboard_periods WHERE id=1"
            ).fetchone()
        start_ts = int(row["period_start"])
        week_seconds = 7 * 24 * 60 * 60
        if now >= start_ts + week_seconds:
            periods_elapsed = (now - start_ts) // week_seconds
            start_ts += periods_elapsed * week_seconds
            con.execute(
                "UPDATE leaderboard_periods SET period_start=? WHERE id=1",
                (start_ts,)
            )
        return start_ts, start_ts + week_seconds

app = FastAPI(title="ELVARQ MemoryCraft API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=WEB_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

def init_db():
    if not DATABASE_URL:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db() as con:
        score_id = "BIGSERIAL PRIMARY KEY" if DATABASE_URL else "INTEGER PRIMARY KEY AUTOINCREMENT"
        con.executescript(f"""
        CREATE TABLE IF NOT EXISTS users (
            uid TEXT PRIMARY KEY,
            telegram_id TEXT UNIQUE,
            name TEXT NOT NULL,
            username TEXT NOT NULL DEFAULT '',
            created_at BIGINT NOT NULL,
            last_seen BIGINT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scores (
            id {score_id},
            uid TEXT NOT NULL REFERENCES users(uid),
            score INTEGER NOT NULL,
            round_reached INTEGER NOT NULL,
            mode TEXT NOT NULL,
            difficulty TEXT NOT NULL,
            room_code TEXT,
            created_at BIGINT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_scores_global
            ON scores(mode, score DESC, created_at ASC);
        CREATE TABLE IF NOT EXISTS rooms (
            code TEXT PRIMARY KEY,
            owner_uid TEXT NOT NULL REFERENCES users(uid),
            difficulty TEXT NOT NULL DEFAULT 'normal',
            status TEXT NOT NULL DEFAULT 'lobby',
            created_at BIGINT NOT NULL,
            started_at BIGINT
        );
        CREATE TABLE IF NOT EXISTS room_members (
            room_code TEXT NOT NULL REFERENCES rooms(code) ON DELETE CASCADE,
            uid TEXT NOT NULL REFERENCES users(uid),
            joined_at BIGINT NOT NULL,
            PRIMARY KEY(room_code, uid)
        );
        CREATE TABLE IF NOT EXISTS leaderboard_periods (
            id SMALLINT PRIMARY KEY,
            period_start BIGINT NOT NULL
        );
        """)
        con.execute(
            "INSERT INTO leaderboard_periods(id, period_start) VALUES(1, ?) ON CONFLICT(id) DO NOTHING",
            (int(time.time()),)
        )

@app.on_event("startup")
def startup():
    init_db()

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def sign_token(payload: dict) -> str:
    body = b64u(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode())
    signature = hmac.new(TOKEN_SECRET.encode(), body.encode(), hashlib.sha256).digest()
    return body + "." + b64u(signature)

def verify_token(token: str) -> dict:
    try:
        body, signature = token.split(".", 1)
        expected = hmac.new(TOKEN_SECRET.encode(), body.encode(), hashlib.sha256).digest()
        supplied = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        if not hmac.compare_digest(expected, supplied):
            raise ValueError("bad signature")
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if int(payload.get("exp", 0)) < int(time.time()):
            raise ValueError("expired")
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Сессия истекла. Перезапусти Mini App.")

def issue_user(uid: str, name: str, username: str = "", telegram_id: str | None = None):
    stamp = int(time.time())
    with db() as con:
        con.execute("""
            INSERT INTO users(uid,telegram_id,name,username,created_at,last_seen)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(uid) DO UPDATE SET
                name=excluded.name, username=excluded.username, last_seen=excluded.last_seen
        """, (uid, telegram_id, name[:80], username[:64], stamp, stamp))
    payload = {"uid": uid, "name": name[:80], "exp": stamp + TOKEN_TTL, "tg": bool(telegram_id)}
    return {"token": sign_token(payload), "user": {"id": uid, "name": name[:80], "username": username}}

def telegram_user_from_init_data(init_data: str):
    if not BOT_TOKEN:
        raise HTTPException(status_code=503, detail="На сервере не задан BOT_TOKEN.")
    if not init_data or len(init_data) > 10000:
        raise HTTPException(status_code=400, detail="Telegram initData отсутствует.")
    values = dict(parse_qsl(init_data, keep_blank_values=True))
    received_hash = values.pop("hash", "")
    if not received_hash:
        raise HTTPException(status_code=401, detail="Некорректные данные Telegram.")
    auth_date = int(values.get("auth_date", "0") or 0)
    if auth_date < int(time.time()) - 86400 or auth_date > int(time.time()) + 60:
        raise HTTPException(status_code=401, detail="Данные Telegram устарели. Перезапусти игру.")
    check_string = "\n".join(f"{k}={v}" for k, v in sorted(values.items()))
    secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
    calculated = hmac.new(secret_key, check_string.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calculated, received_hash):
        raise HTTPException(status_code=401, detail="Не удалось подтвердить Telegram-пользователя.")
    try:
        user = json.loads(values["user"])
        telegram_id = str(user["id"])
    except Exception:
        raise HTTPException(status_code=400, detail="В initData нет данных пользователя.")
    name = " ".join(x for x in [user.get("first_name", ""), user.get("last_name", "")] if x).strip()
    return telegram_id, name or "Игрок", user.get("username", "")

def current_user(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Открой игру через Telegram.")
    return verify_token(authorization[7:])

def get_room(code: str):
    with db() as con:
        row = con.execute("SELECT * FROM rooms WHERE code=?", (code.upper(),)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Комната не найдена.")
        members = con.execute("""
            SELECT u.uid,u.name,COALESCE(MAX(s.score),0) AS score,
                   CASE WHEN MAX(s.id) IS NULL THEN 0 ELSE 1 END AS finished
            FROM room_members m JOIN users u ON u.uid=m.uid
            LEFT JOIN scores s ON s.uid=m.uid AND s.room_code=m.room_code
            WHERE m.room_code=? GROUP BY u.uid,u.name ORDER BY score DESC, u.name
        """, (code.upper(),)).fetchall()
        return dict(row), [dict(x) for x in members]

def public_players(rows):
    return [{"name": r["name"], "score": int(r["score"] or 0), "finished": bool(r["finished"])} for r in rows]

class AuthBody(BaseModel):
    init_data: str = Field(min_length=1, max_length=10000)

class RoomCreate(BaseModel):
    difficulty: str = "normal"

class RoomStart(BaseModel):
    difficulty: str = "normal"

class ScoreBody(BaseModel):
    score: int = Field(ge=0, le=100000)
    round: int = Field(ge=1, le=35)
    mode: str = Field(pattern="^(global|friends)$")
    difficulty: str = Field(pattern="^(normal|medium|hardcore|extreme)$")
    room_code: str | None = Field(default=None, max_length=6)

class ConnectionManager:
    def __init__(self):
        self.connections: dict[str, set[WebSocket]] = {}

    async def connect(self, code: str, websocket: WebSocket):
        await websocket.accept()
        self.connections.setdefault(code, set()).add(websocket)

    def disconnect(self, code: str, websocket: WebSocket):
        self.connections.get(code, set()).discard(websocket)
        if code in self.connections and not self.connections[code]:
            self.connections.pop(code, None)

    async def broadcast(self, code: str, payload: dict):
        dead = []
        for ws in list(self.connections.get(code, set())):
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(code, ws)

manager = ConnectionManager()

async def broadcast_room(code: str, kind: str = "room_scoreboard"):
    try:
        room, players = get_room(code)
        await manager.broadcast(code, {
            "type": kind, "code": code, "status": room["status"],
            "difficulty": room["difficulty"], "players": public_players(players)
        })
    except HTTPException:
        pass

@app.get("/")
def root():
    return {"name": "ELVARQ MemoryCraft API", "status": "online", "docs": "/docs"}

@app.get("/health")
def health():
    return {"ok": True, "service": "memorycraft-api"}

@app.post("/api/auth/telegram")
def auth_telegram(body: AuthBody):
    telegram_id, name, username = telegram_user_from_init_data(body.init_data)
    return issue_user("tg:" + telegram_id, name, username, telegram_id)

@app.post("/api/auth/guest")
def auth_guest():
    # Browser-only preview identity. Telegram Mini App should use /api/auth/telegram.
    uid = "guest:" + str(uuid.uuid4())
    return issue_user(uid, "Guest-" + uid[-5:])

@app.get("/api/leaderboard")
def leaderboard(limit: int = 100, difficulty: str | None = None):
    limit = max(1, min(limit, 100))
    allowed = {"normal", "medium", "hardcore", "extreme"}
    if difficulty is not None and difficulty not in allowed:
        raise HTTPException(status_code=400, detail="Неизвестный уровень сложности.")
    week_start, reset_at = current_week_window()
    with db() as con:
        rows = con.execute("""
            SELECT u.name, s.difficulty, MAX(s.score) AS score,
                   MAX(s.round_reached) AS round_reached
            FROM scores s JOIN users u ON u.uid=s.uid
            WHERE s.mode='global' AND s.created_at>=?
              AND (? IS NULL OR s.difficulty=?)
            GROUP BY s.uid,u.name,s.difficulty
            ORDER BY score DESC, round_reached DESC, u.name ASC
            LIMIT ?
        """, (week_start, difficulty, difficulty, limit)).fetchall()
    return {
        "items": [dict(r) for r in rows],
        "period": "weekly",
        "reset_at": datetime.fromtimestamp(reset_at, TASHKENT_TZ).isoformat()
    }

@app.post("/api/rooms")
async def create_room(body: RoomCreate, user=Depends(current_user)):
    difficulty = body.difficulty if body.difficulty in {"normal", "medium", "hardcore", "extreme"} else "normal"
    for _ in range(10):
        code = "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(6))
        try:
            with db() as con:
                con.execute(
                    "INSERT INTO rooms(code,owner_uid,difficulty,status,created_at) VALUES(?,?,?,'lobby',?)",
                    (code, user["uid"], difficulty, int(time.time()))
                )
                con.execute("INSERT INTO room_members(room_code,uid,joined_at) VALUES(?,?,?)",
                            (code, user["uid"], int(time.time())))
            room, players = get_room(code)
            await broadcast_room(code, "room_state")
            return {"code": code, "members": len(players), "difficulty": difficulty, "status": "lobby", "is_owner": True}
        except DB_INTEGRITY_ERRORS:
            continue
    raise HTTPException(status_code=503, detail="Не удалось создать код комнаты. Попробуй снова.")

@app.post("/api/rooms/{code}/join")
async def join_room(code: str, user=Depends(current_user)):
    code = code.upper()
    with db() as con:
        room = con.execute("SELECT * FROM rooms WHERE code=?", (code,)).fetchone()
        if not room:
            raise HTTPException(status_code=404, detail="Комната не найдена.")
        if room["status"] != "lobby":
            raise HTTPException(status_code=409, detail="Игра в этой комнате уже началась.")
        count_row = con.execute("SELECT COUNT(*) AS member_count FROM room_members WHERE room_code=?", (code,)).fetchone()
        count = int(count_row["member_count"])
        exists = con.execute("SELECT 1 FROM room_members WHERE room_code=? AND uid=?", (code, user["uid"])).fetchone()
        if not exists and count >= ROOM_LIMIT:
            raise HTTPException(status_code=409, detail=f"В комнате максимум {ROOM_LIMIT} игроков.")
        con.execute("INSERT INTO room_members(room_code,uid,joined_at) VALUES(?,?,?) ON CONFLICT(room_code,uid) DO NOTHING",
                    (code, user["uid"], int(time.time())))
    room, players = get_room(code)
    await broadcast_room(code, "room_state")
    return {"code": code, "members": len(players), "difficulty": room["difficulty"], "status": room["status"], "is_owner": room["owner_uid"] == user["uid"]}

@app.post("/api/rooms/{code}/start")
async def start_room(code: str, body: RoomStart, user=Depends(current_user)):
    code = code.upper()
    difficulty = body.difficulty if body.difficulty in {"normal", "medium", "hardcore", "extreme"} else "normal"
    with db() as con:
        room = con.execute("SELECT * FROM rooms WHERE code=?", (code,)).fetchone()
        if not room:
            raise HTTPException(status_code=404, detail="Комната не найдена.")
        if room["owner_uid"] != user["uid"]:
            raise HTTPException(status_code=403, detail="Начать игру может только создатель комнаты.")
        if room["status"] != "lobby":
            raise HTTPException(status_code=409, detail="Комната уже запущена.")
        con.execute("UPDATE rooms SET status='playing',difficulty=?,started_at=? WHERE code=?",
                    (difficulty, int(time.time()), code))
    await broadcast_room(code, "room_started")
    return {"ok": True, "code": code, "difficulty": difficulty}

@app.post("/api/scores")
async def submit_score(body: ScoreBody, user=Depends(current_user)):
    room_code = None
    if body.mode == "friends":
        if not body.room_code:
            raise HTTPException(status_code=400, detail="Для FRIENDS нужен код комнаты.")
        room_code = body.room_code.upper()
        with db() as con:
            room = con.execute("SELECT status FROM rooms WHERE code=?", (room_code,)).fetchone()
            member = con.execute("SELECT 1 FROM room_members WHERE room_code=? AND uid=?",
                                 (room_code, user["uid"])).fetchone()
            if not room or not member:
                raise HTTPException(status_code=403, detail="Ты не состоишь в этой комнате.")
    with db() as con:
        con.execute("""
            INSERT INTO scores(uid,score,round_reached,mode,difficulty,room_code,created_at)
            VALUES(?,?,?,?,?,?,?)
        """, (user["uid"], body.score, body.round, body.mode, body.difficulty,
              room_code, int(time.time())))
    if room_code:
        await broadcast_room(room_code)
    return {"ok": True, "saved": True}

@app.websocket("/ws/rooms/{code}")
async def room_socket(websocket: WebSocket, code: str, token: str):
    code = code.upper()
    try:
        user = verify_token(token)
        room, players = get_room(code)
        with db() as con:
            member = con.execute("SELECT 1 FROM room_members WHERE room_code=? AND uid=?",
                                 (code, user["uid"])).fetchone()
        if not member:
            await websocket.close(code=4403)
            return
    except Exception:
        await websocket.close(code=4401)
        return
    await manager.connect(code, websocket)
    await websocket.send_json({
        "type": "room_state", "code": code, "status": room["status"],
        "difficulty": room["difficulty"], "players": public_players(players)
    })
    try:
        while True:
            # Client does not need to send gameplay state; keep connection alive.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(code, websocket)
    except Exception:
        manager.disconnect(code, websocket)

@app.get("/api/me")
def me(user=Depends(current_user)):
    return {"id": user["uid"], "name": user["name"], "telegram": user.get("tg", False)}
