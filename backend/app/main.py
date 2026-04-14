from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import urlparse

from app.bootstrap import ensure_admin_user, ensure_security_rules
from app.config import settings
from app.database import Base, SessionLocal, engine
from app.middleware.waf import WAFMiddleware
from app.redis_client import close_redis_client
from app.routes import auth, dashboard, security

Base.metadata.create_all(bind=engine)


@asynccontextmanager
async def lifespan(_: FastAPI):
    db = SessionLocal()
    try:
        ensure_admin_user(db)
        ensure_security_rules(db)
    finally:
        db.close()

    yield
    await close_redis_client()


app = FastAPI(title=settings.app_name, lifespan=lifespan)

def _build_cors_origins() -> list[str]:
    origins = {settings.frontend_origin}
    parsed = urlparse(settings.frontend_origin)
    if parsed.hostname in {"localhost", "127.0.0.1"}:
        port = f":{parsed.port}" if parsed.port else ""
        origins.add(f"http://localhost{port}")
        origins.add(f"http://127.0.0.1{port}")
    return sorted(origins)

app.add_middleware(WAFMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_build_cors_origins(),
    allow_origin_regex=r"^http://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(dashboard.router, prefix="/api")
app.include_router(auth.router, prefix="/api")
app.include_router(security.router)


@app.get("/")
def root():
    return {
        "message": "CAFW API is running",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health_check():
    return {"status": "ok", "env": settings.app_env}
