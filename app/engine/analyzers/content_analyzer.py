"""Text-content based phishing heuristics."""

from __future__ import annotations

from app.engine.types import AnalysisModuleResult
from app.models.email_payload import EmailPayload


class ContentAnalyzer:
    """Score threatening, urgent, and money-requesting language in body text."""

    MAX_SCORE = 25

    def analyze(self, payload: EmailPayload) -> AnalysisModuleResult:
        # Hebrew characters are already case-insensitive, but .lower() is safe to call.
        text = payload.body_text.lower()

        urgency_keywords = (
            "urgent", "immediately", "asap", "act now", "time sensitive",
            "renew", "update payment", "update payment information",
            # Hebrew urgency signals
            "דחוף", "מיידי", "פעולה נדרשת",
            # Hebrew call-to-action phrases commonly used on phishing buttons/links
            "לצפייה במסמך", "התחברות לחשבון", "לחץ כאן", "לעדכון פרטים", "כניסה לחשבון",
        )
        threat_keywords = (
            "account suspended", "legal action", "security alert", "locked", "violation",
            "expired", "payment failure", "disruption", "disruption to your service",
            "חשבונך ננעל", "הושעה", "מסמך חדש",
        )
        financial_keywords = (
            "wire transfer", "bank account", "gift card", "payment", "invoice due",
            "חשבונית", "תשלום", "קבלה",
        )
        # Words that indicate a routine transactional email (receipt, booking confirmation).
        # Used together with the Safe Transaction rule below to reduce false positives.
        safe_transaction_keywords = ("order", "booking", "receipt", "confirmation", "thank you for")

        score = 0
        reasons: list[str] = []

        urgency_hits  = sum(1 for keyword in urgency_keywords  if keyword in text)
        threat_hits   = sum(1 for keyword in threat_keywords   if keyword in text)
        financial_hits = sum(1 for keyword in financial_keywords if keyword in text)
        safe_hits     = sum(1 for keyword in safe_transaction_keywords if keyword in text)

        if urgency_hits:
            score += min(10, urgency_hits * 5)
            reasons.append("Contains urgency language intended to pressure quick action.")
        if threat_hits:
            score += min(12, threat_hits * 6)
            reasons.append("Contains threatening or punitive language.")
        if financial_hits:
            score += min(12, financial_hits * 6)
            reasons.append("Contains direct financial transfer/payment requests.")

        # Safe Transaction rule: a financial keyword appearing in an email that
        # shows no urgency and no threats is consistent with a legitimate receipt
        # or booking confirmation. Reset the content score to avoid false positives.
        if financial_hits and urgency_hits == 0 and threat_hits == 0 and safe_hits > 0:
            score = 0
            reasons = ["Financial keywords detected but context indicates a safe transactional email."]

        if score == 0 and not reasons:
            reasons.append("No high-risk urgency/threat/financial wording detected.")

        return AnalysisModuleResult(
            module="ContentAnalyzer",
            score=min(score, self.MAX_SCORE),
            reasoning=" ".join(reasons),
        )
