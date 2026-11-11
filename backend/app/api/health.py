"""GET /api/health."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/api/health")
async def health() -> dict[str, str]:
    """Tell the frontend that the backend is running."""
    return {"status": "ok"}
