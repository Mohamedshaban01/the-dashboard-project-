"""
PentesterFlow API Endpoints - OpenVAS
Legacy scan endpoints for OpenVAS interaction
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from typing import List, Optional, Any
import logging

from app.schemas.scan import OpenVASScanCreate, OpenVASScanResponse
from app.services.openvas import openvas_service

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/status")
def get_openvas_status():
    """
    Return the current OpenVAS integration status.
    Always returns 200 so the frontend can show enabled/disabled state.
    """
    try:
        connected = openvas_service.is_connected() if hasattr(openvas_service, "is_connected") else False
    except Exception:
        connected = False
    return {
        "enabled": connected,
        "message": "OpenVAS connected." if connected else "OpenVAS not reachable — check OPENVAS_HOST in .env.",
    }


@router.post("/scan/quick", response_model=OpenVASScanResponse)
def start_quick_scan(scan_in: OpenVASScanCreate):
    """
    Start a quick scan on a target using OpenVAS.
    This is a multi-step process: Create Target -> Create Task -> Start Task.
    """
    try:
        # 1. Create Target
        target_id = openvas_service.create_target(
            name=f"Quick Scan: {scan_in.target_name}",
            hosts=[scan_in.target_ip]
        )
        
        if not target_id:
            raise HTTPException(status_code=500, detail="Failed to create OpenVAS target")
            
        # 2. Create Task
        task_id = openvas_service.create_task(
            name=f"Task: {scan_in.target_name}",
            target_id=target_id
        )
        
        if not task_id:
            raise HTTPException(status_code=500, detail="Failed to create OpenVAS task")
            
        # 3. Start Scan
        report_id = openvas_service.start_scan(task_id)
        
        return {
            "task_id": task_id,
            "report_id": report_id,
            "status": "success"
        }
    except ConnectionError as e:
        logger.error(f"OpenVAS connection error: {e}")
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logger.error(f"Error starting OpenVAS scan: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")

@router.get("/status/{task_id}")
def get_scan_status(task_id: str):
    """
    Get the status of an OpenVAS scan task.
    """
    try:
        status = openvas_service.get_task_status(task_id)
        return status
    except Exception as e:
        logger.error(f"Error getting OpenVAS status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/results/{report_id}")
def get_scan_results(report_id: str):
    """
    Get the results of an OpenVAS scan.
    """
    try:
        results = openvas_service.get_results(report_id)
        return results
    except Exception as e:
        logger.error(f"Error getting OpenVAS results: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/schedule")
def schedule_scan(data: Any):
    """
    Placeholder for scheduling scans.
    """
    return {"message": "Scheduling not fully implemented in this endpoint yet", "data": data}
