"""HTTP API for the Trivy report prototype. How to run it: see README.md."""

from fastapi import FastAPI

app = FastAPI(title="Trivy report prototype")


@app.get("/api/health")
async def health() -> dict[str, str]:
    """Tell the frontend that the backend is running."""
    return {"status": "ok"}
