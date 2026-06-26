from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import auth, cases, data, hunt_packages, notifications, rag, threat_reports
from app.core.config import get_settings

settings = get_settings()

app = FastAPI(title=settings.app_name, version=settings.app_version)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(threat_reports.router)
app.include_router(hunt_packages.router)
app.include_router(data.router)
app.include_router(rag.router)
app.include_router(auth.router)
app.include_router(notifications.router)
app.include_router(cases.router)


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "app": settings.app_name,
        "version": settings.app_version,
        "ai_provider": settings.ai_provider,
        "analyzer_mode": settings.analyzer_mode,
        "firestore_enabled": settings.firestore_enabled,
        "firebase_project_id": settings.firebase_project_id,
    }
