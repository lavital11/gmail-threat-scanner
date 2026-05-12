"""Shared engine result types."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AnalysisModuleResult(BaseModel):
    """Single analyzer output with bounded contribution to final score."""

    module: str = Field(..., min_length=1, max_length=128)
    score: int = Field(..., ge=0, le=100)
    reasoning: str = Field(..., min_length=1, max_length=2000)
