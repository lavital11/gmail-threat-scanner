"""Threat scoring orchestration service."""

from __future__ import annotations

from app.engine.analyzers.content_analyzer import ContentAnalyzer
from app.engine.analyzers.identity_analyzer import IdentityAnalyzer
from app.engine.analyzers.infrastructure_analyzer import InfrastructureAnalyzer
from app.engine.analyzers.link_analyzer import LinkAnalyzer
from app.engine.types import AnalysisModuleResult
from app.models.email_payload import EmailPayload


class EmailThreatScoringService:
    """Aggregate modular analyzer outputs into one score and user verdict."""

    MAX_TOTAL_SCORE = 100

    def __init__(self) -> None:
        self._analyzers = (
            IdentityAnalyzer(),
            ContentAnalyzer(),
            LinkAnalyzer(),
            InfrastructureAnalyzer(),
        )

    def analyze(self, payload: EmailPayload) -> tuple[int, str]:
        module_results = [analyzer.analyze(payload) for analyzer in self._analyzers]
        total = min(sum(result.score for result in module_results), self.MAX_TOTAL_SCORE)
        verdict = self._build_verdict(total, module_results)
        return total, verdict

    @staticmethod
    def _build_verdict(total: int, module_results: list[AnalysisModuleResult]) -> str:
        if total >= 70:
            severity = "High risk: this email shows strong phishing indicators."
        elif total >= 40:
            severity = "Medium risk: suspicious signs detected; verify before acting."
        else:
            severity = "Low risk: limited phishing indicators were detected."

        details = " ".join(
            f"[{result.module}: {result.score}] {result.reasoning}" for result in module_results
        )
        return f"{severity} Total score: {total}/100. {details}"
