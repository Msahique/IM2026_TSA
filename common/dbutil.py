"""MySQL helpers shared by every server.

Each independent server owns its own MySQL database (ca_db, tsa_db,
global_registry_db, secserver_consumer_db, secserver_provider_db,
application_db). Connection: localhost:3306 root/root (overridable via env).
"""
from __future__ import annotations

import os

import pymysql
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DB_HOST = os.getenv("IM_DB_HOST", "localhost")
DB_PORT = int(os.getenv("IM_DB_PORT", "3306"))
DB_USER = os.getenv("IM_DB_USER", "root")
DB_PASS = os.getenv("IM_DB_PASS", "root")


def ensure_database(db_name: str) -> None:
    """Create the database if it does not yet exist."""
    conn = pymysql.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASS)
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"CREATE DATABASE IF NOT EXISTS `{db_name}` "
                f"CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        conn.commit()
    finally:
        conn.close()


def make_engine(db_name: str):
    url = (f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{db_name}"
           "?charset=utf8mb4")
    return create_engine(url, pool_pre_ping=True, pool_recycle=280, future=True)


def make_session_factory(engine):
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


class SessionProxy:
    """Callable placeholder so `from x.database import SessionLocal` keeps a
    stable reference that starts working once `init()` configures it."""

    def __init__(self):
        self._factory = None

    def configure(self, factory):
        self._factory = factory

    def __call__(self):
        if self._factory is None:
            raise RuntimeError("Database not initialised - call database.init() first")
        return self._factory()


def init_db(db_name: str, base):
    """Ensure database exists and create all tables for the given Base."""
    ensure_database(db_name)
    engine = make_engine(db_name)
    base.metadata.create_all(engine)
    return engine
