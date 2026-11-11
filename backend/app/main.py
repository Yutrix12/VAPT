"""HTTP API for the Trivy report prototype. How to run it: see README.md."""

from fastapi import FastAPI

from app.api import analyze, fix, health, llm
from app.middleware import register as register_middleware

app = FastAPI(title="Trivy report prototype")
register_middleware(app)
app.include_router(health.router)
app.include_router(analyze.router)
app.include_router(llm.router)
app.include_router(fix.router)
