"""Authentication: bcrypt passwords + JWT for the dashboard, shared token for agents."""
from __future__ import annotations

import hmac
from datetime import timedelta

import bcrypt
import jwt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from . import config, db

bearer = HTTPBearer(auto_error=False)


def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def verify_password(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    except ValueError:
        return False


def create_token(username: str, role: str) -> str:
    payload = {"sub": username, "role": role, "exp": db.now() + timedelta(minutes=config.JWT_TTL_MINUTES)}
    return jwt.encode(payload, config.JWT_SECRET, algorithm="HS256")


async def require_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    try:
        claims = jwt.decode(creds.credentials, config.JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired token")
    return {"username": claims["sub"], "role": claims.get("role", "analyst")}


async def require_agent(x_agent_token: str = Header(default="")) -> None:
    if not config.AGENT_TOKEN or not hmac.compare_digest(x_agent_token, config.AGENT_TOKEN):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid agent token")
