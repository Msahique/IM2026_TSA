"""Time-Stamp Authority server. Port 9002. DB: tsa_db.

Gets its own time-stamping certificate from the CA, then issues signed
RFC-3161-style timestamp tokens used by security servers to prove the
existence of a logged message at a point in time (non-repudiation).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from tsa_server import database, tsa_core

app = FastAPI(title="IM Time-Stamp Authority", version="1.0")


class StampReq(BaseModel):
    hashed_message: str            # base64 SHA-256 digest of the data
    hash_alg: str = "SHA-256"
    requester: str = ""


@app.on_event("startup")
def _startup():
    database.init()
    try:
        tsa_core.get_or_create_key()  # provision cert from CA if reachable
    except Exception as e:
        print(f"[tsa] cert provisioning deferred: {e}")


@app.get("/api/tsa-cert", response_class=PlainTextResponse)
def tsa_cert():
    return tsa_core.get_or_create_key().cert_pem


@app.post("/api/timestamp")
def timestamp(req: StampReq):
    return tsa_core.timestamp(req.hashed_message, req.hash_alg, req.requester)


@app.get("/api/timestamps")
def timestamps():
    return tsa_core.list_timestamps()


@app.delete("/api/timestamps/{serial}")
def delete_timestamp(serial: str):
    if not tsa_core.delete_timestamp(serial):
        raise HTTPException(404, "serial not found")
    return {"deleted": serial}


@app.delete("/api/timestamps")
def clear_timestamps():
    return {"deleted": tsa_core.clear_timestamps()}


app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static"),
                           html=True), name="static")
