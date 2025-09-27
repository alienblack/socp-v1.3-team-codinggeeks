
from pydantic import BaseModel, Field
from typing import Any, Literal, Dict

class Envelope(BaseModel):
    type: str
    from_: str = Field(alias="from")
    to: str
    ts: int
    payload: Dict[str, Any]
    sig: str = ""

ERROR_CODES = {"USER_NOT_FOUND","INVALID_SIG","BAD_KEY","TIMEOUT","UNKNOWN_TYPE","NAME_IN_USE"}

def build_frame(type: str, from_: str, to: str, payload: dict) -> dict:
    from time import time
    return {"type": type, "from": from_, "to": to, "ts": int(time()*1000), "payload": payload, "sig": ""}
