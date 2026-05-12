"""Text-content based phishing heuristics."""

from __future__ import annotations

from app.engine.types import AnalysisModuleResult
from app.models.email_payload import EmailPayload


class ContentAnalyzer:
    """Score threatening, urgent, and money-requesting language in body text."""

    MAX_SCORE = 25

    def analyze(self, payload: EmailPayload) -> AnalysisModuleResult:
        text = payload.body_text.lower()

        urgency_keywords = ("urgent", "immediately", "asap", "act now", "time sensitive")
        threat_keywords = ("account suspended", "legal action", "security alert", "locked", "violation")
        financial_keywords = ("wire transfer", "bank account", "gift card", "payment", "invoice due")

        score = 0
        reasons: list[str] = []

        urgency_hits = sum(1 for keyword in urgency_keywords if keyword in text)
        threat_hits = sum(1 for keyword in threat_keywords if keyword in text)
        financial_hits = sum(1 for keyword in financial_keywords if keyword in text)

        if urgency_hits:
            score += min(10, urgency_hits * 4)
            reasons.append("Contains urgency language intended to pressure quick action.")
        if threat_hits:
            score += min(10, threat_hits * 5)
            reasons.append("Contains threatening or punitive language.")
        if financial_hits:
            score += min(10, financial_hits * 5)
            reasons.append("Contains direct financial transfer/payment requests.")

        if score == 0:
            reasons.append("No high-risk urgency/threat/financial wording detected.")

        return AnalysisModuleResult(
            module="ContentAnalyzer",
            score=min(score, self.MAX_SCORE),
            reasoning=" ".join(reasons),
        )
