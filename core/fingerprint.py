"""Basit, header/cookie/gövde tabanlı teknoloji tespiti.

httpx -td (Wappalyzer) sonuçlarını tamamlar; httpx yoksa tek kaynak budur.
Çıktı isimleri httpx/Wappalyzer adlarıyla uyumludur (ör. 'PHP', 'Microsoft ASP.NET', 'Java'),
böylece settings.yaml'daki tech_wordlists eşlemesi iki kaynakta da çalışır.
"""
from __future__ import annotations

import re

RULES: list[tuple[str, str, re.Pattern]] = [
    # (kaynak, teknoloji, regex)  kaynak: header | cookie | body
    ("header", "PHP", re.compile(r"x-powered-by:[^\n]*php", re.I)),
    ("cookie", "PHP", re.compile(r"PHPSESSID", re.I)),
    ("header", "Microsoft ASP.NET", re.compile(r"x-aspnet-version|x-aspnetmvc-version|x-powered-by:[^\n]*asp\.net", re.I)),
    ("cookie", "Microsoft ASP.NET", re.compile(r"ASP\.NET_SessionId|\.ASPXAUTH", re.I)),
    ("header", "IIS", re.compile(r"server:[^\n]*microsoft-iis", re.I)),
    ("cookie", "Java", re.compile(r"JSESSIONID", re.I)),
    ("header", "Apache Tomcat", re.compile(r"server:[^\n]*(tomcat|coyote)", re.I)),
    ("header", "Java", re.compile(r"x-powered-by:[^\n]*(servlet|jsp|jboss)", re.I)),
    ("header", "Express", re.compile(r"x-powered-by:[^\n]*express", re.I)),
    ("header", "Next.js", re.compile(r"x-powered-by:[^\n]*next\.js", re.I)),
    ("cookie", "Express", re.compile(r"connect\.sid", re.I)),
    ("header", "Nginx", re.compile(r"server:[^\n]*nginx", re.I)),
    ("header", "Apache HTTP Server", re.compile(r"server:[^\n]*apache(?!-coyote)", re.I)),
    ("cookie", "Laravel", re.compile(r"laravel_session|XSRF-TOKEN", re.I)),
    ("body", "WordPress", re.compile(r"/wp-content/|/wp-includes/", re.I)),
    ("body", "Next.js", re.compile(r"/_next/static/", re.I)),
    ("body", "Java", re.compile(r"\.jsp[\"'?#]|\.do[\"'?#]", re.I)),
    ("body", "PHP", re.compile(r"\.php[\"'?#]", re.I)),
    ("body", "Microsoft ASP.NET", re.compile(r"__VIEWSTATE|\.aspx[\"'?#]", re.I)),
]


def detect(headers: dict[str, str] | None, body: str = "") -> list[str]:
    headers = headers or {}
    header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items())
    cookie_blob = "\n".join(v for k, v in headers.items() if k.lower() == "set-cookie")
    body = body[:200_000]
    found: list[str] = []
    for source, tech, rx in RULES:
        blob = {"header": header_blob, "cookie": cookie_blob, "body": body}[source]
        if tech not in found and rx.search(blob):
            found.append(tech)
    return found


def extract_title(body: str) -> str | None:
    m = re.search(r"<title[^>]*>(.*?)</title>", body[:100_000], re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else None


# --- Sürüm ifşası (banner leakage) tespiti --------------------------------
# Bu başlıklar sunucu/altyapı sürümünü dışarı sızdırabilir. Sürüm numarası
# içerenler (ör. "nginx/1.18.0", "PHP/8.1.2") uyumluluk açısından bulgu sayılır.
VERSION_LEAK_HEADERS = {
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-runtime", "x-drupal-dynamic-cache", "x-nginx-version",
    "via", "x-varnish", "x-litespeed-cache", "liferay-portal", "x-jenkins",
    "x-confluence-request-time", "x-oracle-dms-ecid",
}
# Mere presence = leak (sürüm olmasa bile teknolojiyi ifşa eder)
ALWAYS_SENSITIVE = {"x-aspnet-version", "x-aspnetmvc-version", "x-powered-by", "x-generator", "x-jenkins"}
_VERSION_NUM = re.compile(r"\d+\.\d[\w.\-]*")


def detect_version_disclosure(headers: dict[str, str] | None) -> list[dict]:
    """Sürüm/banner ifşası yapan yanıt başlıklarını döndürür: [{header, value, version}]."""
    out: list[dict] = []
    for k, v in (headers or {}).items():
        kl = str(k).lower()
        if kl not in VERSION_LEAK_HEADERS:
            continue
        val = ", ".join(v) if isinstance(v, list) else str(v)
        if not val.strip():
            continue
        m = _VERSION_NUM.search(val)
        if m or kl in ALWAYS_SENSITIVE:
            out.append({"header": k, "value": val[:200], "version": m.group(0) if m else ""})
    return out
