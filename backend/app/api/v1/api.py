from fastapi import APIRouter
from app.api.v1.endpoints import auth, ip_tools, files, scan, ai, reports, history, file_integrity, users, whois_dns, admin

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(ip_tools.router, prefix="/ip", tags=["ip"])
api_router.include_router(files.router, prefix="/files", tags=["files"])
api_router.include_router(file_integrity.router, prefix="/fim", tags=["fim"])
api_router.include_router(scan.router, prefix="/scan", tags=["scan"])
api_router.include_router(whois_dns.router, prefix="/whois-dns", tags=["whois-dns"])
api_router.include_router(ai.router, prefix="/ai", tags=["ai"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(history.router, prefix="/history", tags=["history"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(admin.router, prefix="/admin", tags=["admin"])

