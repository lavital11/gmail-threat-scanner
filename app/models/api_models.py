"""API request/response models."""

from pydantic import BaseModel, Field


class AnalysisResponse(BaseModel):
    """Public response contract for the `/analyze` endpoint."""

    score: int = Field(..., ge=0, le=100)
    verdict: str = Field(..., min_length=1, max_length=8_000)
