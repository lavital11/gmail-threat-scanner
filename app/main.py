"""FastAPI application entrypoint for Gmail add-on email analysis backend."""

from fastapi import FastAPI

from app.engine.service import EmailThreatScoringService
from app.models.api_models import AnalysisResponse
from app.models.email_payload import EmailPayload

app = FastAPI(
    title="Gmail Add-on Email Threat Analyzer",
    version="0.1.0",
    description=(
        "Analyzes opened Gmail messages for phishing/maliciousness indicators. "
        "Input is treated as untrusted and sanitized at schema boundaries."
    ),
)

scoring_service = EmailThreatScoringService()


@app.post("/analyze", response_model=AnalysisResponse)
def analyze_email(payload: EmailPayload) -> AnalysisResponse:
    """Run modular threat analysis and return a unified score + verdict."""
    score, verdict = scoring_service.analyze(payload)
    return AnalysisResponse(score=score, verdict=verdict)
