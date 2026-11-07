"""FastAPI backend: REST APIs for events, alerts and analytics (MongoDB storage)."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo.errors import DuplicateKeyError

from . import config, db
from .routers import api, ingest
from .security import create_token, hash_password, require_user, verify_password

log = logging.getLogger("ids.backend")


async def seed_admin():
    if not config.ADMIN_PASSWORD:
        log.warning("ADMIN_PASSWORD not set - no admin user seeded")
        return
    users = db.db().users
    existing = await users.find_one({"username": config.ADMIN_USERNAME})
    if existing is None:
        try:
            await users.insert_one({"username": config.ADMIN_USERNAME, "role": "admin",
                                    "password_hash": hash_password(config.ADMIN_PASSWORD), "created_at": db.now()})
        except DuplicateKeyError:
            pass  # another replica seeded it
    elif not verify_password(config.ADMIN_PASSWORD, existing["password_hash"]):
        # the Secret was rotated
        await users.update_one({"_id": existing["_id"]}, {"$set": {"password_hash": hash_password(config.ADMIN_PASSWORD)}})


@asynccontextmanager
async def lifespan(_: FastAPI):
    await db.connect()
    await seed_admin()
    yield
    await db.close()


app = FastAPI(title="eBPF IDS for Kubernetes", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=config.CORS_ORIGINS, allow_methods=["*"], allow_headers=["*"])
app.include_router(ingest.router)
app.include_router(api.router)


class Login(BaseModel):
    username: str
    password: str


@app.post("/api/auth/login", tags=["auth"])
async def login(body: Login):
    user = await db.db().users.find_one({"username": body.username})
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(401, "invalid username or password")
    return {"access_token": create_token(user["username"], user.get("role", "analyst")),
            "token_type": "bearer", "username": user["username"], "role": user.get("role", "analyst")}


@app.get("/api/auth/me", tags=["auth"])
async def me(user: dict = Depends(require_user)):
    return user


@app.get("/healthz", tags=["health"])
async def healthz():
    await db.db().command("ping")
    return {"status": "ok"}
