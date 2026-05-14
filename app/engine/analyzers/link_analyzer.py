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

            # Compare href host to URL(s) shown in link text: allow same org across
            # www / apex / tracking subdomains; unrelated domains still mismatch.
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
    def _normalize_hostname(host: str | None) -> str:
        if not host:
            return ""
        return host.lower().rstrip(".")

    @staticmethod
    def _same_host(url_a: str, url_b: str) -> bool:
        """True when href and link-text URL are the same site (exact host, or subdomain of the other).

        Tolerates www vs apex and tracking subdomains (e.g. click.* vs bare domain).
        Unrelated domains never match; sibling hosts under a multi-tenant parent do not match each
        other (e.g. a.github.io vs b.github.io) because neither hostname is a DNS subdomain of the other.
        """
        try:
            host_a = LinkAnalyzer._normalize_hostname(urlparse(url_a).hostname)
            host_b = LinkAnalyzer._normalize_hostname(urlparse(url_b).hostname)
            if not host_a or not host_b:
                return False
            if host_a == host_b:
                return True
            return host_a.endswith("." + host_b) or host_b.endswith("." + host_a)
        except Exception:
            # Fail closed: if parsing fails, treat as not matching.
            return False
