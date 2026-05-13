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

    SYNERGY_THRESHOLD = 3
    SYNERGY_MULTIPLIER = 1.5

    def analyze(self, payload: EmailPayload) -> tuple[int, str]:
        module_results = [analyzer.analyze(payload) for analyzer in self._analyzers]

        base_score = sum(result.score for result in module_results)

        # Multi-Vector Synergy: when 3 or more independent analyzers all detect
        # anomalies, the combined threat is statistically more likely to be a real
        # attack than any single signal alone, so a 20% boost is applied.
        triggered = sum(1 for result in module_results if result.score > 0)
        synergy_applied = triggered >= self.SYNERGY_THRESHOLD

        boosted_score = int(base_score * self.SYNERGY_MULTIPLIER) if synergy_applied else base_score
        total = min(boosted_score, self.MAX_TOTAL_SCORE)
        added_points = total - base_score

        verdict = self._build_verdict(total, module_results, added_points)
        return total, verdict

    @staticmethod
    def _build_verdict(
        total: int,
        module_results: list[AnalysisModuleResult],
        added_points: int,
    ) -> str:
        if total >= 70:
            severity = "High risk: this email shows strong phishing indicators."
        elif total >= 40:
            severity = "Medium risk: suspicious signs detected; verify before acting."
        else:
            severity = "Low risk: limited phishing indicators were detected."

        details = " ".join(
            f"[{result.module}: {result.score}] {result.reasoning}" for result in module_results
        )
        # Appended in the same [Module: score] format so the Gmail add-on's
        # regex parser picks it up as a regular analyzer block and renders it
        # as a clean line in the verdict card.
        synergy_note = (
            f" [SynergyAnalyzer: {added_points}]"
            " Multi-Vector Boost - 3 or more independent analyzers detected anomalies,"
            " significantly increasing the threat level."
            if added_points > 0
            else ""
        )
        return f"{severity} Total score: {total}/100. {details}{synergy_note}"
