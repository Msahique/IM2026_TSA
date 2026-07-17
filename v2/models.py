import datetime as dt

from sqlalchemy import Column, DateTime, Integer, String, Text

from tsa_server.database import Base


class TsaKey(Base):
    __tablename__ = "tsa_key"
    id = Column(Integer, primary_key=True)
    cert_pem = Column(Text, nullable=False)
    key_pem = Column(Text, nullable=False)
    serial = Column(String(64))
    created_at = Column(DateTime, default=dt.datetime.utcnow)


class TimestampLog(Base):
    __tablename__ = "timestamp_log"
    id = Column(Integer, primary_key=True)
    serial = Column(String(64))
    hash_alg = Column(String(16))
    hashed_message = Column(String(128))
    gen_time = Column(DateTime)
    requester = Column(String(255))
    token_json = Column(Text)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
