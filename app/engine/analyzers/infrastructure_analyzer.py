"""Header/authentication signal analysis."""

from __future__ import annotations

from app.engine.types import AnalysisModuleResult
from app.models.email_payload import EmailPayload


class InfrastructureAnalyzer:
    """Parse SPF/DKIM/DMARC-like auth result snippets with conservative scoring."""

    MAX_SCORE = 20

    def analyze(self, payload: EmailPayload) -> AnalysisModuleResult:
        raw = (payload.authentication_results or "").strip().lower()

        if not raw:
            return AnalysisModuleResult(
                module="InfrastructureAnalyzer",
                score=5,
                reasoning="Authentication-Results header missing; verification confidence reduced.",
            )

        if "fail" in raw:
            return AnalysisModuleResult(
                module="InfrastructureAnalyzer",
                score=20,
                reasoning="Authentication checks indicate failure in SPF/DKIM/DMARC signals.",
            )

        if "pass" in raw:
            return AnalysisModuleResult(
                module="InfrastructureAnalyzer",
                score=0,
                reasoning="Authentication checks indicate pass results.",
            )

        return AnalysisModuleResult(
            module="InfrastructureAnalyzer",
            score=5,
            reasoning="Authentication results present but inconclusive.",
        )
