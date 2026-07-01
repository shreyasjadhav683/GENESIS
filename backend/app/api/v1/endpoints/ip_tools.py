from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import StreamingResponse
import socket
import requests
import json
import asyncio
from sqlmodel import Session
from app.core.db import get_session
from app.core.ip_scanner_service import ip_scanner
from app.core.export_service import export_service
from app.api import deps
from app.models.user import User
from app.models.scan_history import ScanHistory

router = APIRouter()

@router.get("/url")
async def check_url(
    url: str, 
    current_user: User = Depends(deps.get_current_user),
    session: Session = Depends(get_session)
):
    from app.core.url_scanner_service import url_scanner
    
    # Use the new aggressive scanner
    result = await url_scanner.scan_url(url)

    # Save to history
    scan = ScanHistory(
        user_id=current_user.id,
        scan_type="URL_AGGRESSIVE_SCAN",
        target=url,
        result=json.dumps(result, default=str)
    )
    session.add(scan)
    session.commit()

    return result


@router.post("/scan")
async def comprehensive_ip_scan(
    ip_address: str,
    current_user: User = Depends(deps.get_current_user),
    session: Session = Depends(get_session)
):
    """
    Comprehensive IP scan with threat intelligence, port scanning, and risk assessment.
    
    Returns:
    - Geolocation data
    - Threat intelligence (VPN/Proxy/Tor detection, blacklist status)
    - Open ports and services
    - DNS information
    - Risk score and assessment
    """
    # Run the comprehensive scan
    result = await ip_scanner.scan_ip(ip_address)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    # Save to history
    scan = ScanHistory(
        user_id=current_user.id,
        scan_type="IP_COMPREHENSIVE_SCAN",
        target=ip_address,
        result=json.dumps(result, default=str)
    )
    session.add(scan)
    session.commit()
    
    return result


@router.post("/scan/export/excel")
async def export_scan_to_excel(
    ip_address: str,
    current_user: User = Depends(deps.get_current_user)
):
    """
    Export IP scan results to Excel format
    """
    # Run the scan
    result = await ip_scanner.scan_ip(ip_address)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    # Generate Excel file
    excel_file = export_service.export_to_excel(result)
    
    # Return as downloadable file
    filename = f"ip_scan_{ip_address}_{result.get('scan_timestamp', 'report')[:10]}.xlsx"
    
    return StreamingResponse(
        excel_file,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.post("/scan/export/pdf")
async def export_scan_to_pdf(
    ip_address: str,
    current_user: User = Depends(deps.get_current_user)
):
    """
    Export IP scan results to PDF format
    """
    # Run the scan
    result = await ip_scanner.scan_ip(ip_address)
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    # Generate PDF file
    pdf_file = export_service.export_to_pdf(result)
    
    # Return as downloadable file
    filename = f"ip_scan_{ip_address}_{result.get('scan_timestamp', 'report')[:10]}.pdf"
    
    return StreamingResponse(
        pdf_file,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@router.get("/{ip_address}")
def check_ip(
    ip_address: str, 
    current_user: User = Depends(deps.get_current_user),
    session: Session = Depends(get_session)
):
    """Basic IP geolocation check (legacy endpoint)"""
    # Real Geolocation using ip-api.com
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query")
        data = response.json()
        
        if data.get("status") == "fail":
            geo_info = {"error": data.get("message", "Unknown error")}
        else:
            geo_info = data
    except Exception as e:
        geo_info = {"error": str(e)}

    # Determine reputation (Mock logic for now, enhanced with real Geo data)
    reputation_score = "Neutral"
    if geo_info.get("countryCode") in ["KP", "IR", "RU", "CN"]:
        reputation_score = "Caution (High Risk Region)"
    
    result = {
        "ip": ip_address,
        "geolocation": geo_info,
        "reputation": reputation_score,
        "city": geo_info.get("city", "Unknown"),
        "country": geo_info.get("country", "Unknown"),
        "org": geo_info.get("org", "Unknown"),
        "isp": geo_info.get("isp", "Unknown"),
        "region": geo_info.get("regionName", "Unknown")
    }
    
    # Save to history (serialize fully)
    scan = ScanHistory(
        user_id=current_user.id,
        scan_type="IP_CHECK",
        target=ip_address,
        result=json.dumps(result, default=str)
    )
    session.add(scan)
    session.commit()
    
    return result

