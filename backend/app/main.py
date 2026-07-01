from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.v1.api import api_router
from app.core.db import create_db_and_tables

app = FastAPI(title=settings.PROJECT_NAME, openapi_url=f"{settings.API_V1_STR}/openapi.json")

# Build the list of allowed origins from settings (comma-separated string).
# This includes localhost for dev and the GitHub Pages URL for production.
origins = [o.strip() for o in settings.ALLOWED_ORIGINS.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,        # explicit list — required when allow_credentials=True
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

app.include_router(api_router, prefix=settings.API_V1_STR)

@app.get("/")
def read_root():
    return {"message": "Welcome to Cybersecurity Dashboard API"}
