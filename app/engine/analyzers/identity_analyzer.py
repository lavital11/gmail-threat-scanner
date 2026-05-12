"""Identity-based phishing heuristics."""

from __future__ import annotations

import re
from difflib import SequenceMatcher

from app.engine.types import AnalysisModuleResult
from app.models.email_payload import EmailPayload


class IdentityAnalyzer:
    """Detect sender identity anomalies and simple typosquatting patterns."""

    MAX_SCORE = 30

    def analyze(self, payload: EmailPayload) -> AnalysisModuleResult:
        sender_name = payload.sender_name.lower()
        sender_email = payload.sender_email.lower()

        score = 0
        reasons: list[str] = []

        name_tokens = [token for token in re.split(r"\W+", sender_name) if token]
        local_part = sender_email.split("@")[0]
        domain = sender_email.split("@")[-1]

        # If no name token appears in local part, it can indicate impersonation.
        if name_tokens and not any(token in local_part for token in name_tokens):
            score += 10
            reasons.append("Sender name does not align with email local-part.")

        suspicious_brands = ("paypal", "microsoft", "google", "apple", "amazon", "bank")
        if any(brand in sender_name for brand in suspicious_brands):
            legit_domains = ("paypal.com", "microsoft.com", "google.com", "apple.com", "amazon.com")
            if not any(domain.endswith(valid) for valid in legit_domains):
                score += 12
                reasons.append("Brand-like sender name uses unrelated email domain.")

        # Basic typosquatting hint: known domains with one-character variation.
        known_domains = ("paypal.com", "microsoft.com", "google.com", "apple.com", "amazon.com")
        if all(not domain.endswith(kd) for kd in known_domains):
            similarity = max(SequenceMatcher(None, domain, kd).ratio() for kd in known_domains)
            if 0.80 <= similarity < 0.98:
                score += 12
                reasons.append("Domain resembles a trusted brand (possible typosquatting).")

        if score == 0:
            reasons.append("No obvious sender identity inconsistencies detected.")

        return AnalysisModuleResult(
            module="IdentityAnalyzer",
            score=min(score, self.MAX_SCORE),
            reasoning=" ".join(reasons),
        )
