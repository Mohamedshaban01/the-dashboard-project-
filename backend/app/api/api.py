from fastapi import APIRouter, Depends
from .v1.endpoints import scans, reports, network, targets, vulnerabilities, dashboard, openvas, siem, config
from .v1.endpoints import auth
from .deps import get_current_user

api_router = APIRouter()

# ── Public routes (no authentication required) ────────────────────────────────
# Phase 1.4: feature flag map
api_router.include_router(config.router, prefix="/config", tags=["config"])
# Phase 3.1: authentication
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])

# ── Authenticated routes ───────────────────────────────────────────────────────
_auth = [Depends(get_current_user)]

# Core PentesterFlow endpoints
api_router.include_router(targets.router, prefix="/targets", tags=["targets"], dependencies=_auth)
api_router.include_router(scans.router, prefix="/scans", tags=["scans"], dependencies=_auth)
api_router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["vulnerabilities"], dependencies=_auth)

# Legacy endpoints
api_router.include_router(reports.router, prefix="/reports", tags=["reports"], dependencies=_auth)
api_router.include_router(network.router, prefix="/network", tags=["network"], dependencies=_auth)
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"], dependencies=_auth)
api_router.include_router(openvas.router, prefix="/openvas", tags=["openvas"], dependencies=_auth)
api_router.include_router(siem.router, prefix="/siem", tags=["siem"], dependencies=_auth)


@api_router.get("/")
def root():
    return {"message": "PentesterFlow API is running", "version": "2.0"}
