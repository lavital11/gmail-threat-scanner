"""Pydantic schemas for untrusted email analysis inputs.

Security note:
Incoming payloads are treated as untrusted data from external clients.
We enforce length boundaries and normalization at the schema layer to reduce
resource abuse and keep the rest of the application logic predictable.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


MAX_BODY_LENGTH = 50_000


class EmailPayload(BaseModel):
    """Validated and normalized request body for email threat analysis."""

    model_config = ConfigDict(
        extra="forbid",  # Reject unknown fields to prevent silent misuse.
        str_strip_whitespace=True,
    )

    sender_name: str = Field(..., min_length=1, max_length=256)
    sender_email: str = Field(..., min_length=3, max_length=320)
    subject: str = Field(default="", max_length=998)
    body_text: str = Field(default="")
    body_html: str = Field(default="")
    authentication_results: Optional[str] = Field(default=None, max_length=8192)

    @field_validator("body_text", "body_html", mode="before")
    @classmethod
    def truncate_body(cls, value: str | None) -> str:
        """Truncate potentially oversized body content to limit DoS impact."""
        if value is None:
            return ""
        normalized = str(value)
        return normalized[:MAX_BODY_LENGTH]
