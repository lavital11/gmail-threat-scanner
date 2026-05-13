"""HTML link analysis for phishing indicators."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from app.engine.types import AnalysisModuleResult
from app.models.email_payload import EmailPayload


class LinkAnalyzer:
    """Inspect HTML anchor tags for raw IP URLs, mismatched link text, and suspicious routing."""

    MAX_SCORE = 25
    HREF_RE = re.compile(
        r"<a\s+[^>]*href=[\"'](?P<href>[^\"']+)[\"'][^>]*>(?P<label>.*?)</a>",
        flags=re.IGNORECASE | re.DOTALL,
    )
    URL_RE = re.compile(r"https?://[^\s<>'\"]+", flags=re.IGNORECASE)

    _SUSPICIOUS_KEYWORDS: tuple[str, ...] = ("login", "secure", "update", "inv", "verify", "auth")
    _URL_SHORTENERS: tuple[str, ...] = ("bit.ly", "tinyurl.com", "t.co")

    def analyze(self, payload: EmailPayload) -> AnalysisModuleResult:
        html = payload.body_html or ""
        score = 0
        reasons: list[str] = []
        suspicious_routing_flagged = False

        for match in self.HREF_RE.finditer(html):
            href = match.group("href").strip()
            label = re.sub(r"<[^>]+>", "", match.group("label")).strip()

            if self._href_uses_raw_ip(href):
                score += 12
                reasons.append("Link uses a raw IP address instead of a domain.")

            label_urls = self.URL_RE.findall(label)
            if label_urls and not any(self._same_host(href, label_url) for label_url in label_urls):
                score += 10
                reasons.append("Displayed link text does not match target URL domain.")

            # Check for suspicious routing keywords in the URL path or a known URL shortener.
            if not suspicious_routing_flagged:
                href_lower = href.lower()
                parsed_host = urlparse(href).hostname or ""
                is_suspicious_keyword = any(kw in href_lower for kw in self._SUSPICIOUS_KEYWORDS)
                is_url_shortener = any(parsed_host == shortener for shortener in self._URL_SHORTENERS)
                if is_suspicious_keyword or is_url_shortener:
                    score += 10
                    reasons.append("Link contains suspicious routing keywords or uses a URL shortener.")
                    suspicious_routing_flagged = True  # Report once per email, not per link.

        if score == 0:
            reasons.append("No suspicious link patterns detected in HTML body.")

        return AnalysisModuleResult(
            module="LinkAnalyzer",
            score=min(score, self.MAX_SCORE),
            reasoning=" ".join(reasons),
        )

    @staticmethod
    def _href_uses_raw_ip(href: str) -> bool:
        parsed = urlparse(href)
        host = parsed.hostname
        if not host:
            return False
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    @staticmethod
    def _same_host(url_a: str, url_b: str) -> bool:
        try:
            host_a = urlparse(url_a).hostname or ""
            host_b = urlparse(url_b).hostname or ""
            return host_a.lower() == host_b.lower() and host_a != ""
        except Exception:
            # Fail closed: if parsing fails, treat as not matching.
            return False
