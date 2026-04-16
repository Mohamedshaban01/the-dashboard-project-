from fastapi import APIRouter, HTTPException
from app.core.config import settings

router = APIRouter()


def _check_siem_enabled():
    """Raise HTTP 503 with an explicit message when SIEM_ENABLED is False.

    This gives the frontend (and any API consumer) an honest signal instead
    of a cryptic 500 or silent empty response.  Do NOT delete these routes —
    a visible, documented disabled state is better than a missing route.
    """
    if not settings.SIEM_ENABLED:
        raise HTTPException(
            status_code=503,
            detail=(
                "SIEM integration is disabled. "
                "Set SIEM_ENABLED=true in the backend .env file to activate."
            ),
        )


@router.get("/status")
async def get_siem_status():
    """
    Return the current SIEM integration status without requiring connectivity.
    Always returns 200 so the frontend can show enabled/disabled state.
    """
    return {
        "enabled": getattr(settings, "SIEM_ENABLED", False),
        "message": (
            "SIEM integration is active."
            if getattr(settings, "SIEM_ENABLED", False)
            else "SIEM integration is disabled. Set SIEM_ENABLED=true in .env to activate."
        ),
    }


@router.get("/alerts")
async def get_siem_alerts(index: str = "wazuh-alerts-*", size: int = 100):
    """
    Fetch recent security alerts from Elasticsearch.

    Returns HTTP 503 when SIEM_ENABLED=false (default).
    """
    _check_siem_enabled()
    try:
        from app.services.elastic_integration import elastic_service
        alerts = await elastic_service.fetch_recent_alerts(index=index, size=size)
        return alerts
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch alerts: {str(e)}")


@router.get("/health")
async def get_siem_health():
    """
    Check connectivity to the SIEM (Elasticsearch).

    Returns HTTP 503 when SIEM_ENABLED=false (default).
    """
    _check_siem_enabled()
    try:
        from app.services.elastic_integration import elastic_service
        is_alive = await elastic_service.check_health()
        if is_alive:
            return {"status": "connected", "engine": "Elasticsearch"}
        return {"status": "disconnected", "engine": "Elasticsearch"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SIEM health check failed: {str(e)}")
