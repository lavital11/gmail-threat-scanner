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

        suspicious_brands = (
            "paypal", "microsoft", "google", "apple", "amazon", "bank",
            "spotify", "netflix", "facebook",
        )
        if any(brand in sender_name for brand in suspicious_brands):
            legit_domains = (
                "paypal.com", "microsoft.com", "google.com", "apple.com", "amazon.com",
                "spotify.com", "netflix.com", "facebook.com",
            )
            if not any(domain.endswith(valid) for valid in legit_domains):
                score += 12
                reasons.append("Brand-like sender name uses unrelated email domain.")

        # Basic typosquatting hint: known domains with one-character variation.
        known_domains = (
            "paypal.com", "microsoft.com", "google.com", "apple.com", "amazon.com",
            "spotify.com", "netflix.com", "facebook.com",
        )
        if all(not domain.endswith(kd) for kd in known_domains):
            similarity = max(SequenceMatcher(None, domain, kd).ratio() for kd in known_domains)
            if 0.80 <= similarity < 0.98:
                score += 12
                reasons.append("Domain resembles a trusted brand (possible typosquatting).")

        # Manipulative authority/trust words in the display name (e.g. "Billing Support",
        # "Trusted Admin") are a common social-engineering tactic to bypass suspicion.
        trust_bait_words = ("trusted", "verified", "billing", "admin", "system", "support")
        trusted_domains = ("gmail.com", "yahoo.com", "outlook.com", "hotmail.com")
        if any(word in sender_name for word in trust_bait_words):
            if not any(domain.endswith(td) for td in trusted_domains):
                score += 10
                reasons.append("Sender name uses manipulative trust/authority words.")

        # Cheap or high-abuse TLDs are disproportionately used in phishing campaigns.
        high_risk_tlds = (".biz", ".xyz", ".top", ".id", ".club", ".online", ".site", ".info")
        if any(domain.endswith(tld) for tld in high_risk_tlds):
            score += 15
            reasons.append("Email originates from a high-risk or cheap Top-Level Domain (TLD).")

        # Bot-generated addresses commonly have high-entropy local parts with long
        # runs of consonants that no real name or word would produce.
        if re.search(r"[bcdfghjklmnpqrstvwxz]{5,}", local_part):
            score += 10
            reasons.append("Local-part of the email contains a high-entropy/gibberish consonant string.")

        if score == 0:
            reasons.append("No obvious sender identity inconsistencies detected.")

        return AnalysisModuleResult(
            module="IdentityAnalyzer",
            score=min(score, self.MAX_SCORE),
            reasoning=" ".join(reasons),
        )
