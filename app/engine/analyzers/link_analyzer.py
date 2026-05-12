"""HTML link analysis for phishing indicators."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from app.engine.types import AnalysisModuleResult
from app.models.email_payload import EmailPayload


class LinkAnalyzer:
    """Inspect HTML anchor tags for raw IP URLs and mismatched link text."""

    MAX_SCORE = 25
    HREF_RE = re.compile(
        r"<a\s+[^>]*href=[\"'](?P<href>[^\"']+)[\"'][^>]*>(?P<label>.*?)</a>",
        flags=re.IGNORECASE | re.DOTALL,
    )
    URL_RE = re.compile(r"https?://[^\s<>'\"]+", flags=re.IGNORECASE)

    def analyze(self, payload: EmailPayload) -> AnalysisModuleResult:
        html = payload.body_html or ""
        score = 0
        reasons: list[str] = []

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
