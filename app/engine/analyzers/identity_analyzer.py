"""Identity-based phishing heuristics."""

from __future__ import annotations

import re
from difflib import SequenceMatcher

from app.engine.types import AnalysisModuleResult
from app.models.email_payload import EmailPayload


class IdentityAnalyzer:
    """Detect sender identity anomalies and simple typosquatting patterns."""

    MAX_SCORE = 30

    # Role-based / automated local-parts: name vs local-part mismatch is usually not impersonation.
    _GENERIC_LOCAL_PREFIXES: frozenset[str] = frozenset(
        {
            "automated",
            "noreply",
            "no-reply",
            "support",
            "info",
            "marketing",
            "sales",
            "billing",
            "admin",
            "notifications",
            "updates",
        }
    )

    @staticmethod
    def _normalize_alnum_lower(s: str) -> str:
        """Lowercase and keep only a-z0-9 for fuzzy substring checks."""
        return re.sub(r"[^a-z0-9]+", "", (s or "").lower())

    @staticmethod
    def _domain_stem_without_tld(domain: str) -> str:
        """Hostname labels excluding the final TLD label (e.g. airbnb.com -> airbnb)."""
        parts = (domain or "").lower().strip().strip(".").split(".")
        if len(parts) < 2:
            return parts[0] if parts else ""
        return ".".join(parts[:-1])

    @classmethod
    def _sender_name_aligns_with_domain(
        cls, sender_name: str, name_tokens: list[str], domain: str
    ) -> bool:
        """True if the display name matches the registrable host stem (substring, alnum-normalized)."""
        stem_raw = cls._domain_stem_without_tld(domain)
        stem_norm = cls._normalize_alnum_lower(stem_raw)
        name_norm = cls._normalize_alnum_lower(sender_name)
        if not stem_norm:
            return False
        if name_norm and (name_norm in stem_norm or stem_norm in name_norm):
            return True
        return any(
            len(t) >= 3 and cls._normalize_alnum_lower(t) in stem_norm for t in name_tokens
        )

    @classmethod
    def _generic_local_part(cls, local_part: str) -> bool:
        base = local_part.split("+", 1)[0].strip().lower()
        return base in cls._GENERIC_LOCAL_PREFIXES

    @staticmethod
    def _sender_name_aligns_with_local_part(name_tokens: list[str], local_part: str) -> bool:
        """True if any name token appears in the local-part (alnum-normalized, case-insensitive)."""
        lp_norm = IdentityAnalyzer._normalize_alnum_lower(local_part)
        for t in name_tokens:
            tn = IdentityAnalyzer._normalize_alnum_lower(t)
            if tn and tn in lp_norm:
                return True
        return False

    def analyze(self, payload: EmailPayload) -> AnalysisModuleResult:
        sender_name = payload.sender_name.lower()
        sender_email = payload.sender_email.lower()

        score = 0
        reasons: list[str] = []

        name_tokens = [token for token in re.split(r"\W+", sender_name) if token]
        local_part = sender_email.split("@")[0]
        domain = sender_email.split("@")[-1]

        # Name vs local-part: penalize only if domain, generic-local, and local-part checks all fail.
        if name_tokens:
            domain_ok = self._sender_name_aligns_with_domain(sender_name, name_tokens, domain)
            generic_ok = self._generic_local_part(local_part)
            local_ok = self._sender_name_aligns_with_local_part(name_tokens, local_part)
            if not domain_ok and not generic_ok and not local_ok:
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
