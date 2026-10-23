"""Persistence. Uses DATABASE_URL from Streamlit secrets (Postgres on Supabase or Neon in production);
falls back to a local SQLite file, which Streamlit Community Cloud wipes on every restart."""
import json
import secrets as pysecrets
import time
import uuid

import pandas as pd
import streamlit as st
from sqlalchemy import create_engine, text

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS sessions (
        code VARCHAR(32) PRIMARY KEY, name VARCHAR(200) NOT NULL, mode VARCHAR(8) NOT NULL DEFAULT 'self',
        current_inject VARCHAR(8) NOT NULL DEFAULT '1.1', revealed TEXT NOT NULL DEFAULT '[]',
        is_open INTEGER NOT NULL DEFAULT 1, created_at DOUBLE PRECISION NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS participants (
        pid VARCHAR(40) PRIMARY KEY, code VARCHAR(32) NOT NULL, name VARCHAR(120), role VARCHAR(120),
        org VARCHAR(160), created_at DOUBLE PRECISION NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS answers (
        pid VARCHAR(40) NOT NULL, code VARCHAR(32) NOT NULL, inject VARCHAR(8) NOT NULL, act TEXT,
        d VARCHAR(16) NOT NULL, f VARCHAR(16) NOT NULL, o VARCHAR(16) NOT NULL, at DOUBLE PRECISION NOT NULL,
        PRIMARY KEY (pid, inject))""",
    """CREATE TABLE IF NOT EXISTS hotwash (
        code VARCHAR(32) NOT NULL, n INTEGER NOT NULL, note TEXT,
        at DOUBLE PRECISION NOT NULL, PRIMARY KEY (code, n))""",
]

# Added after first release, so existing databases need the column rather than the table.
# "ADD COLUMN IF NOT EXISTS" is Postgres-only, so each is attempted and the duplicate-column
# error swallowed; that keeps one code path for SQLite and Postgres.
MIGRATIONS = [
    "ALTER TABLE sessions ADD COLUMN track VARCHAR(16) NOT NULL DEFAULT 'technical'",
]


def _db_url():
    try:
        return st.secrets.get("DATABASE_URL")
    except Exception:
        return None


@st.cache_resource
def engine():
    url = _db_url()
    if url:
        if url.startswith("postgres://"):
            url = "postgresql://" + url[len("postgres://"):]
        # Name the driver explicitly: SQLAlchemy 2.1 changed the default for a bare
        # "postgresql://" URL from psycopg2 to psycopg 3, which this app does not install,
        # so a bare URL fails on the first connect with ModuleNotFoundError.
        if url.startswith("postgresql://"):
            url = "postgresql+psycopg2://" + url[len("postgresql://"):]
        eng = create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=5)
    else:
        eng = create_engine("sqlite:///ttx.db", connect_args={"check_same_thread": False})
    with eng.begin() as c:
        for s in SCHEMA:
            c.execute(text(s))
    for m in MIGRATIONS:
        try:
            with eng.begin() as c:
                c.execute(text(m))
        except Exception:
            pass  # column already present
    with eng.begin() as c:
        if not c.execute(text("SELECT 1 FROM sessions LIMIT 1")).first():
            c.execute(text("INSERT INTO sessions (code, name, created_at) VALUES ('main', 'Main session', :t)"), {"t": time.time()})
    return eng


def persistent():
    return bool(_db_url())


# ---------- sessions ----------
def get_session(code):
    with engine().connect() as c:
        r = c.execute(text("SELECT * FROM sessions WHERE code=:c"), {"c": code}).mappings().first()
    if not r:
        return None
    r = dict(r)
    try:
        r["revealed"] = json.loads(r["revealed"] or "[]")
    except ValueError:
        r["revealed"] = []
    r["is_open"] = bool(r["is_open"])
    r.setdefault("track", "technical")
    r["track"] = r["track"] or "technical"
    return r


def list_sessions():
    with engine().connect() as c:
        return [dict(r) for r in c.execute(text("SELECT code, name, track, created_at FROM sessions ORDER BY created_at DESC")).mappings()]


def create_session(name, track="technical"):
    code = pysecrets.token_urlsafe(5).replace("-", "x").replace("_", "y")[:6].lower()
    with engine().begin() as c:
        c.execute(text("INSERT INTO sessions (code, name, track, created_at) VALUES (:c, :n, :k, :t)"),
                  {"c": code, "n": name.strip()[:200] or "Untitled session", "k": track, "t": time.time()})
    return code


def save_hotwash(code, n, note):
    with engine().begin() as c:
        c.execute(text("""INSERT INTO hotwash (code, n, note, at) VALUES (:c,:n,:x,:t)
                          ON CONFLICT (code, n) DO UPDATE SET note=excluded.note, at=excluded.at"""),
                  {"c": code, "n": n, "x": (note or "").strip()[:4000], "t": time.time()})


def get_hotwash(code):
    with engine().connect() as c:
        rows = c.execute(text("SELECT n, note FROM hotwash WHERE code=:c"), {"c": code}).mappings()
        return {r["n"]: r["note"] for r in rows}


def update_session(code, **fields):
    allowed = {"mode", "current_inject", "revealed", "is_open", "name", "track"}
    sets, params = [], {"c": code}
    for k, v in fields.items():
        if k not in allowed:
            continue
        if k == "revealed":
            v = json.dumps(sorted(set(v)))
        if k == "is_open":
            v = int(bool(v))
        sets.append(f"{k}=:{k}")
        params[k] = v
    if sets:
        with engine().begin() as c:
            c.execute(text(f"UPDATE sessions SET {', '.join(sets)} WHERE code=:c"), params)


def reset_session(code):
    with engine().begin() as c:
        c.execute(text("DELETE FROM answers WHERE code=:c"), {"c": code})
        c.execute(text("DELETE FROM participants WHERE code=:c"), {"c": code})
        c.execute(text("DELETE FROM hotwash WHERE code=:c"), {"c": code})


def delete_session(code):
    reset_session(code)
    with engine().begin() as c:
        c.execute(text("DELETE FROM sessions WHERE code=:c"), {"c": code})


# ---------- participants and answers ----------
def add_participant(code, name, role, org):
    pid = uuid.uuid4().hex
    with engine().begin() as c:
        c.execute(text("INSERT INTO participants (pid, code, name, role, org, created_at) VALUES (:p,:c,:n,:r,:o,:t)"),
                  {"p": pid, "c": code, "n": (name or "").strip()[:120], "r": role[:120], "o": (org or "").strip()[:160], "t": time.time()})
    return pid


def get_participant(pid, code):
    with engine().connect() as c:
        r = c.execute(text("SELECT * FROM participants WHERE pid=:p AND code=:c"), {"p": pid, "c": code}).mappings().first()
    return dict(r) if r else None


def delete_participant(pid):
    with engine().begin() as c:
        c.execute(text("DELETE FROM answers WHERE pid=:p"), {"p": pid})
        c.execute(text("DELETE FROM participants WHERE pid=:p"), {"p": pid})


def my_answers(pid):
    with engine().connect() as c:
        rows = c.execute(text("SELECT inject, act, d, f, o FROM answers WHERE pid=:p"), {"p": pid}).mappings()
        return {r["inject"]: dict(r) for r in rows}


def save_answer(pid, code, inject, act, d, f, o):
    with engine().begin() as c:
        c.execute(text("""INSERT INTO answers (pid, code, inject, act, d, f, o, at) VALUES (:p,:c,:i,:a,:d,:f,:o,:t)
                          ON CONFLICT (pid, inject) DO UPDATE SET act=excluded.act, d=excluded.d, f=excluded.f,
                          o=excluded.o, at=excluded.at"""),
                  {"p": pid, "c": code, "i": inject, "a": (act or "").strip()[:600], "d": d, "f": f, "o": o, "t": time.time()})


def session_frames(code):
    eng = engine()
    with eng.connect() as c:
        parts = pd.read_sql(text("SELECT * FROM participants WHERE code=:c ORDER BY created_at"), c, params={"c": code})
        ans = pd.read_sql(text("SELECT * FROM answers WHERE code=:c"), c, params={"c": code})
    return parts, ans
