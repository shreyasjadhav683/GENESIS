from pathlib import Path
from pydantic_settings import BaseSettings

# Resolve .env path relative to the backend directory (2 levels up from this file)
_BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
_ENV_FILE = _BACKEND_DIR / ".env"

class Settings(BaseSettings):
    PROJECT_NAME: str = "Cybersecurity Dashboard API"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = "CHANGE_THIS_TO_A_SECURE_SECRET_KEY_IN_PRODUCTION"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Database
    DATABASE_URL: str = "sqlite:///./genesis.db"
    
    # API Keys for IP Scanner
    ABUSEIPDB_API_KEY: str | None = None
    IPQUALITYSCORE_API_KEY: str | None = None
    GEMINI_API_KEY: str | None = None
    GOOGLE_SAFE_BROWSING_KEY: str | None = None

    # SMTP Settings
    SMTP_SERVER: str | None = None
    SMTP_PORT: int = 587
    SMTP_USER: str | None = None
    SMTP_PASSWORD: str | None = None
    EMAILS_FROM_EMAIL: str | None = None  # Defaults to SMTP_USER if not set
    EMAILS_FROM_NAME: str | None = "Genesis Security"

    @property
    def from_email(self) -> str:
        """Return sender email, defaulting to SMTP_USER (required for Gmail)"""
        return self.EMAILS_FROM_EMAIL or self.SMTP_USER or "noreply@genesis.local"
    
    class Config:
        env_file = str(_ENV_FILE)

settings = Settings()

# Startup diagnostics - log which API keys are configured
def _log_key_status():
    keys = {
        "ABUSEIPDB_API_KEY": settings.ABUSEIPDB_API_KEY,
        "IPQUALITYSCORE_API_KEY": settings.IPQUALITYSCORE_API_KEY,
        "GEMINI_API_KEY": settings.GEMINI_API_KEY,
        "GOOGLE_SAFE_BROWSING_KEY": settings.GOOGLE_SAFE_BROWSING_KEY,
        "SMTP_SERVER": settings.SMTP_SERVER,
        "SMTP_USER": settings.SMTP_USER,
        "SMTP_PASSWORD": "SET" if settings.SMTP_PASSWORD else None,
    }
    print(f"\n[Config] Loading .env from: {_ENV_FILE} (exists: {_ENV_FILE.exists()})")
    for name, val in keys.items():
        status = "✓ SET" if val else "✗ NOT SET"
        print(f"[Config] {name}: {status}")
    print(f"[Config] From Email will be: {settings.from_email}")
    print()

_log_key_status()
