"""Time-Stamping Authority logic.

Issues RFC-3161-style signed timestamp tokens. A token binds a message
imprint (SHA-256 hash) to a trusted UTC time, a serial number and the TSA
identity, sealed with a real RSA-SHA256 signature made by the TSA's
CA-issued time-stamping certificate.
"""
import datetime as dt
import secrets

import httpx

from common import crypto
from common.topology import CA_URL
from common.util import canonical_json
from tsa_server import models
from tsa_server.database import SessionLocal

TSA_NAME = "GovStack IM TSA"
POLICY = "1.3.6.1.4.1.99999.1"


def get_or_create_key():
    db = SessionLocal()
    try:
        rec = db.query(models.TsaKey).first()
        if rec:
            return rec
        # Generate key, request a TSA cert from the CA
        key = crypto.generate_rsa_key()
        csr = crypto.create_csr(key, TSA_NAME, org="GovStack IM", org_unit="TSA")
        resp = httpx.post(f"{CA_URL}/api/sign",
                          json={"csr_pem": csr, "profile": crypto.PROFILE_TSA,
                                "requested_by": "tsa_server"}, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        rec = models.TsaKey(cert_pem=data["cert_pem"], key_pem=crypto.key_to_pem(key),
                            serial=data["serial"])
        db.add(rec)
        db.commit()
        db.refresh(rec)
        return rec
    finally:
        db.close()


def timestamp(hashed_message_b64: str, hash_alg: str = "SHA-256",
              requester: str = "") -> dict:
    rec = get_or_create_key()
    key = crypto.load_key(rec.key_pem)
    gen_time = dt.datetime.utcnow()
    serial = format(secrets.randbits(64), "x")

    tst_info = {
        "version": 1,
        "policy": POLICY,
        "message_imprint": {"hash_alg": hash_alg, "hashed_message": hashed_message_b64},
        "serial_number": serial,
        "gen_time": gen_time.isoformat() + "Z",
        "tsa": TSA_NAME,
    }
    signature = crypto.sign_bytes(canonical_json(tst_info), key)
    token = {"tst_info": tst_info, "signature": signature, "tsa_cert_pem": rec.cert_pem}

    db = SessionLocal()
    try:
        db.add(models.TimestampLog(
            serial=serial, hash_alg=hash_alg, hashed_message=hashed_message_b64,
            gen_time=gen_time, requester=requester,
            token_json=canonical_json(token).decode()))
        db.commit()
    finally:
        db.close()
    return token


def verify_token(token: dict, ca_cert_pem: str) -> bool:
    """Used by anyone holding the CA cert to verify a TSA token."""
    try:
        tsa_cert = crypto.load_cert(token["tsa_cert_pem"])
        ca_cert = crypto.load_cert(ca_cert_pem)
        if not crypto.verify_cert_chain(tsa_cert, ca_cert):
            return False
        return crypto.verify_bytes(canonical_json(token["tst_info"]),
                                   token["signature"], tsa_cert)
    except Exception:
        return False


def delete_timestamp(serial: str) -> bool:
    db = SessionLocal()
    try:
        rec = db.query(models.TimestampLog).filter_by(serial=serial).first()
        if not rec:
            return False
        db.delete(rec)
        db.commit()
        return True
    finally:
        db.close()


def clear_timestamps() -> int:
    db = SessionLocal()
    try:
        n = db.query(models.TimestampLog).delete()
        db.commit()
        return n
    finally:
        db.close()


def list_timestamps(limit: int = 100) -> list:
    db = SessionLocal()
    try:
        rows = (db.query(models.TimestampLog)
                .order_by(models.TimestampLog.id.desc()).limit(limit).all())
        return [{"serial": r.serial, "hash_alg": r.hash_alg,
                 "hashed_message": r.hashed_message,
                 "gen_time": r.gen_time.isoformat() if r.gen_time else None,
                 "requester": r.requester,
                 "created_at": r.created_at.isoformat() if r.created_at else None}
                for r in rows]
    finally:
        db.close()
