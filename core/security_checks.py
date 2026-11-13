"""Maruziyet analizi: canlı hostları güvenlik bulgularına çevirir.

Bu modül, keşifte toplanan verileri (yanıt başlıkları, TLS, gövde) bir pentester'ın
baktığı sinyallere dönüştürür ve HEPSİNİ tek bir 'bulgu' modeline normalize eder.
Yalnızca standart kütüphane kullanır (ssl, socket) — ek bağımlılık yoktur.

Üretilen bulgu (dict):
    severity   CRITICAL | HIGH | MEDIUM | LOW | INFO
    category   hardening | cors | tls | takeover | version-disclosure | port | exposure | js-secret | cve | nuclei
    target     ilgili URL / host
    title      kısa başlık
    detail     ne tespit edildi
    evidence   kanıt (başlık değeri, hata mesajı, imza...)
    remediation  önerilen düzeltme
"""
from __future__ import annotations

import socket
import ssl
import time
import warnings

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


def finding(severity: str, category: str, target: str, title: str,
            detail: str = "", evidence: str = "", remediation: str = "",
            cvss: float | None = None, cve: str = "") -> dict:
    d = {
        "severity": severity, "category": category, "target": target,
        "title": title, "detail": detail, "evidence": evidence[:300], "remediation": remediation,
    }
    # CVSS/CVE yalnızca varsa eklenir (ör. Nuclei bulguları); sezgisel skor ÜRETİLMEZ.
    if cvss is not None:
        d["cvss"] = cvss
    if cve:
        d["cve"] = cve
    return d


def severity_from_cvss(score: float | None) -> str | None:
    """CVSS taban puanını önem seviyesine çevirir (yalnızca gerçek puan varsa)."""
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def _headers_lower(headers: dict | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in (headers or {}).items():
        out[str(k).lower()] = ", ".join(v) if isinstance(v, list) else str(v)
    return out


# --------------------------------------------------------------- güvenlik başlıkları
def analyze_security_headers(url: str, headers: dict | None, status_code: int | None = None) -> list[dict]:
    """Yanıt başlıklarından sıkılaştırma (hardening) eksiklerini ve CORS hatalarını çıkarır.

    Eksik güvenlik başlıkları, zayıf CSP, çerez bayrakları ve '*' CORS birer zafiyet DEĞİL,
    sıkılaştırma önerisidir (bug bounty programlarının çoğu bunları kapsam dışı sayar). Bu yüzden
    host başına TEK bir INFO satırında toplanırlar; tabloyu host başına 3-4 MEDIUM/LOW satırla
    doldurup gerçek bulguları gömmezler. Yalnızca gerçekten istismar edilebilir olan
    '*' + credentials CORS yapılandırması HIGH kalır.

    Yönlendirme yanıtlarında (3xx) başlık denetimi yapılmaz: asıl sayfanın başlıkları orada değildir."""
    if status_code is not None and 300 <= status_code < 400:
        return []
    h = _headers_lower(headers)
    is_https = url.lower().startswith("https")
    out: list[dict] = []
    notes: list[str] = []        # sıkılaştırma eksikleri (tek satırda birleştirilir)

    if is_https and "strict-transport-security" not in h:
        notes.append("HSTS")
    csp = h.get("content-security-policy", "")
    if not csp:
        notes.append("CSP")
    elif "unsafe-inline" in csp or "unsafe-eval" in csp:
        notes.append("CSP allows unsafe-inline/eval")
    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        notes.append("X-Frame-Options / frame-ancestors")
    if h.get("x-content-type-options", "").lower() != "nosniff":
        notes.append("X-Content-Type-Options: nosniff")

    # CORS misconfiguration
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        out.append(finding("HIGH", "cors", url, "Dangerous CORS: '*' + credentials",
                            "Access-Control-Allow-Origin: * together with credentials=true; authenticated data can be stolen.",
                            evidence=f"ACAO: {acao} | ACAC: {acac}",
                            remediation="Restrict origin to an allow-list; do not use credentials with '*'."))
    elif acao == "*":
        notes.append("CORS allows any origin (*)")

    # Cookie flags
    cookie = h.get("set-cookie", "")
    if cookie and is_https:
        cl = cookie.lower()
        miss = [flag for flag, present in
                (("Secure", "secure" in cl), ("HttpOnly", "httponly" in cl)) if not present]
        if miss:
            notes.append("cookie without " + "/".join(miss))

    if notes:
        out.append(finding("INFO", "hardening", url, f"Missing hardening headers ({len(notes)})",
                           "Hardening recommendations, not vulnerabilities; usually out of scope for bug bounty programs.",
                           evidence="; ".join(notes),
                           remediation="Add the missing response headers / flags where applicable."))
    return out


# --------------------------------------------------------------- TLS / sertifika
def analyze_tls(host: str, port: int = 443, timeout: float = 6.0) -> list[dict]:
    """TLS sertifikasını doğrular (süresi dolmuş / kendinden imzalı / yakında dolacak) ve sunucunun
    eski protokolleri (TLS 1.0/1.1) hâlâ kabul edip etmediğini ayrı bir el sıkışmayla sınar.

    Ağ erişilemezse ya da TLS yoksa sessizce boş döner (bulgu üretmez)."""
    target = f"https://{host}"
    out = _analyze_cert(host, port, timeout, target)
    if out is None:
        return []  # no TLS / unreachable — not a finding
    legacy = _accepts_legacy_tls(host, port, timeout)
    if legacy:
        out.append(finding("LOW", "tls", target, f"Legacy TLS protocol accepted: {legacy}",
                           "The server still completes a handshake with a deprecated protocol version.",
                           evidence=legacy, remediation="Enforce TLS 1.2+, disable older versions."))
    return out


def _accepts_legacy_tls(host: str, port: int, timeout: float) -> str | None:
    """Yalnızca TLS 1.0/1.1 teklif eden bir el sıkışma dener; başarılıysa anlaşılan sürümü döner.

    Varsayılan bağlam TLS 1.2 altını hiç teklif etmediği için bu kontrol ayrı yapılmalıdır. Yerel
    OpenSSL eski protokolleri desteklemiyorsa sessizce None döner (yanlış pozitif üretmez)."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.version()
    except (OSError, ValueError):   # ssl.SSLError bir OSError'dır
        return None


def _analyze_cert(host: str, port: int, timeout: float, target: str) -> list[dict] | None:
    """Sertifika bulguları; hedefe ulaşılamıyorsa / TLS yoksa None."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        msg = str(exc).lower()
        if "expired" in msg:
            return [finding("HIGH", "tls", target, "TLS certificate expired",
                            "The certificate's validity period has passed.", evidence=str(exc)[:160],
                            remediation="Renew the certificate.")]
        if "self signed" in msg or "self-signed" in msg:
            return [finding("MEDIUM", "tls", target, "Self-signed certificate",
                            "Not signed by a trusted CA.", evidence=str(exc)[:160],
                            remediation="Use a certificate from a trusted CA.")]
        if "hostname mismatch" in msg or "doesn't match" in msg or "does not match" in msg:
            return [finding("LOW", "tls", target, "Certificate does not match hostname",
                            "The name in the certificate does not match the requested host.", evidence=str(exc)[:160],
                            remediation="Use a certificate that covers the correct hostname.")]
        return [finding("MEDIUM", "tls", target, "TLS certificate could not be verified",
                        "Chain validation failed.", evidence=str(exc)[:160])]
    except (socket.timeout, ConnectionError, OSError, ssl.SSLError):
        return None

    out: list[dict] = []
    not_after = (cert or {}).get("notAfter")
    if not_after:
        try:
            days = (ssl.cert_time_to_seconds(not_after) - time.time()) / 86400
        except ValueError:
            days = None
        if days is not None:
            if days < 0:
                out.append(finding("HIGH", "tls", target, "TLS certificate expired",
                                   f"Expired {abs(int(days))} days ago.", evidence=not_after,
                                   remediation="Renew the certificate."))
            elif days < 15:
                out.append(finding("MEDIUM", "tls", target, "Certificate expiring soon",
                                   f"Expires in {int(days)} days.", evidence=not_after,
                                   remediation="Renew the certificate / check auto-renewal."))
    return out


# --------------------------------------------------------------- subdomain takeover
# (sağlayıcı, gövdede aranan imza, sağlayıcıya ait CNAME hedef sonekleri)
# Gövde imzası tek başına zayıf kanıttır ("repository not found" her sitede çıkabilir); bulgu ancak
# hostun CNAME zinciri gerçekten o sağlayıcıya gidiyorsa CRITICAL sayılır.
TAKEOVER_FINGERPRINTS: list[tuple[str, str, tuple[str, ...]]] = [
    ("GitHub Pages", "there isn't a github pages site here", ("github.io", "githubusercontent.com")),
    ("AWS/S3", "nosuchbucket", ("amazonaws.com",)),
    ("AWS/S3", "the specified bucket does not exist", ("amazonaws.com",)),
    ("Heroku", "no such app", ("herokuapp.com", "herokudns.com", "herokussl.com")),
    ("Shopify", "sorry, this shop is currently unavailable", ("myshopify.com",)),
    ("Fastly", "fastly error: unknown domain", ("fastly.net", "fastlylb.net")),
    ("Bitbucket", "repository not found", ("bitbucket.io",)),
    ("Ghost", "the thing you were looking for is no longer here", ("ghost.io",)),
    ("Surge.sh", "project not found", ("surge.sh",)),
    ("Tumblr", "whatever you were looking for doesn't currently exist at this address", ("tumblr.com",)),
    ("Pantheon", "the gods are wise, but do not know of the site which you seek", ("pantheonsite.io",)),
    ("Help Scout", "no settings were found for this company", ("helpscoutdocs.com",)),
    ("Readme.io", "project doesnt exist... yet!", ("readme.io", "readmessl.com")),
    ("Agile CRM", "sorry, this page is no longer available", ("agilecrm.com",)),
    ("Wufoo", "profile not found", ("wufoo.com",)),
    ("Azure", "404 web site not found", ("azurewebsites.net", "cloudapp.net", "cloudapp.azure.com",
                                         "trafficmanager.net", "azureedge.net", "azure-api.net",
                                         "blob.core.windows.net")),
]


def resolve_cname_chain(host: str, max_hops: int = 8, lifetime: float = 4.0) -> list[str] | None:
    """Hostun CNAME zincirini döndürür (ör. ['shop.example.com' -> 'x.myshopify.com'] için ['x.myshopify.com']).

    Dönüş: zincirdeki hedef adlar (CNAME yoksa boş liste); belirlenemediyse None.
    dnspython kuruluysa onu kullanır (zincirin sonu NXDOMAIN olsa da — asıl 'dangling' durum — çalışır);
    değilse standart kütüphanenin verdiği takma adlara düşer (Windows'ta çoğu zaman boş → None)."""
    host = host.rstrip(".").lower()
    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        try:
            canonical, aliases, _ = socket.gethostbyname_ex(host)
        except (OSError, UnicodeError):
            return None
        names = [n.rstrip(".").lower() for n in [*aliases, canonical]]
        chain = list(dict.fromkeys(n for n in names if n and n != host))
        return chain or None      # boş = "CNAME yok" mu "platform vermedi" mi ayırt edilemez
    resolver = dns.resolver.Resolver()
    resolver.lifetime = lifetime
    chain: list[str] = []
    name = host
    for _ in range(max_hops):
        try:
            answer = resolver.resolve(name, "CNAME")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            break                 # zincirin sonu (A kaydı ya da artık var olmayan hedef)
        except dns.exception.DNSException:
            return chain or None  # zaman aşımı / sunucu hatası: bilinmiyor
        name = str(answer[0].target).rstrip(".").lower()
        if name in chain:
            break
        chain.append(name)
    return chain


def detect_takeover(url: str, body: str, resolve=resolve_cname_chain) -> list[dict]:
    """Yanıt gövdesinde bilinen 'sahipsiz kaynak' imzasını arar ve DNS ile doğrular.

    - İmza + CNAME zinciri sağlayıcıya gidiyor  -> CRITICAL (doğrulandı)
    - İmza var ama CNAME sağlayıcıya gitmiyor / belirlenemedi -> MEDIUM (doğrulanmadı, elle bakın)
    DNS sorgusu yalnızca imza eşleşirse yapılır. `resolve` test için değiştirilebilir."""
    if not body:
        return []
    low = body.lower()
    for provider, sig, suffixes in TAKEOVER_FINGERPRINTS:
        if sig not in low:
            continue
        host = url.split("://")[-1].split("/")[0].split(":")[0].lower()
        try:
            chain = resolve(host)
        except Exception:
            chain = None
        hit = next((c for c in chain or [] if any(c == s or c.endswith("." + s) for s in suffixes)), None)
        if hit:
            return [finding("CRITICAL", "takeover", url, f"Subdomain takeover ({provider}) — CNAME confirmed",
                            f"Body contains the {provider} 'unclaimed resource' fingerprint and the host's CNAME "
                            f"points to {provider}; the record can be taken over.",
                            evidence=f"{sig} | CNAME -> {hit}",
                            remediation="Remove the dangling DNS record or reclaim the resource.")]
        if chain is None:
            why, dns_ev = "the CNAME chain could not be determined", "CNAME: unknown"
        elif chain:
            why, dns_ev = f"the CNAME does not point to {provider}", "CNAME -> " + " -> ".join(chain)
        else:
            why, dns_ev = "the host has no CNAME record (A record only)", "CNAME: none"
        return [finding("MEDIUM", "takeover", url, f"Possible subdomain takeover ({provider}) — unconfirmed",
                        f"Body contains the {provider} 'unclaimed resource' fingerprint, but {why}. "
                        "Likely a false positive unless DNS shows the host is served by that provider.",
                        evidence=f"{sig} | {dns_ev}",
                        remediation="Check the DNS records manually; remove any dangling record.")]
    return []


# Well-known public files that are safe by design — never a HIGH "sensitive" exposure.
BENIGN_PUBLIC = {
    "robots.txt", "sitemap.xml", "sitemap_index.xml", "sitemap-index.xml", "crossdomain.xml",
    "humans.txt", "favicon.ico", "security.txt", "ads.txt", "app-ads.txt", "browserconfig.xml",
    "manifest.json", "site.webmanifest", ".well-known",
}


def exposure_finding(hit: dict) -> dict | None:
    """Turns one directory/file hit into an identifiable, provable exposure finding.

    - Names the actual file/path (so you can tell WHERE and WHAT at a glance).
    - Evidence carries HTTP status + size, and the content proof for verified files.
    - Benign public files (robots.txt, sitemap.xml …) are INFO, not HIGH.
    - Only content-verified files are HIGH; otherwise MEDIUM/LOW, and 403 = exists-but-restricted.
    Returns None when the hit is not worth reporting.
    """
    url = hit.get("url", "")
    cat = hit.get("category") or ""
    status = hit.get("status")
    length = hit.get("length")
    verified = hit.get("verified")
    proof = hit.get("evidence") or ""
    # Display the full relative path (e.g. ".git/HEAD"), but classify benign files by basename.
    name = ((hit.get("path") or "").lstrip("/") or url.rstrip("/").rsplit("/", 1)[-1] or url)
    basename = name.rstrip("/").rsplit("/", 1)[-1].lower()
    size = f", {length} B" if isinstance(length, int) and length >= 0 else ""
    ev = f"HTTP {status}{size}"

    if basename in BENIGN_PUBLIC and not verified:
        return finding("INFO", "exposure", url, f"Public metadata file: {name}",
                       "Standard public file — intended to be reachable; not sensitive.",
                       evidence=ev)
    if verified:
        return finding("HIGH", "exposure", url, f"Sensitive file exposed: {name}",
                       "Response content confirms a backup/config/secret file is reachable from outside.",
                       evidence=f"{ev} · content-verified" + (f" · {proof}" if proof else ""),
                       remediation="Restrict access to the file or remove it from the server.")
    if status == 403:
        # Exists but access-restricted — worth noting, but NOT an exposure.
        if cat in ("sensitive", "backup"):
            return finding("LOW", "exposure", url, f"Restricted sensitive path: {name}",
                           "A sensitive/backup path exists but returns 403 (access restricted).",
                           evidence=ev, remediation="Confirm the restriction is intentional and sufficient.")
        return None
    if cat in ("sensitive", "backup") and status == 200:
        return finding("MEDIUM", "exposure", url, f"Possibly sensitive file: {name} ({cat})",
                       "A path matching a sensitive/backup pattern is reachable; confirm its content.",
                       evidence=ev,
                       remediation="If it holds sensitive data, restrict access or remove it; otherwise ignore.")
    if status == 200:
        return finding("LOW", "exposure", url, f"Accessible path (200): {name}",
                       "A discovered directory/file returned 200.", evidence=ev)
    return None


def version_finding(leak: dict) -> dict:
    """Converts a version-disclosure record into the unified finding model."""
    return finding("INFO", "version-disclosure", leak.get("url", ""),
                   f"Version/banner disclosure: {leak.get('header')}",
                   "The response header leaks the server/infrastructure version.",
                   evidence=f"{leak.get('header')}: {leak.get('value')}",
                   remediation="Hide the server banner/version headers.")


# --------------------------------------------------------------- sayım / sıralama
def severity_counts(findings: list[dict]) -> dict[str, int]:
    out = {s: 0 for s in SEVERITIES}
    for f in findings:
        sev = f.get("severity")
        if sev in out:
            out[sev] += 1
    return out


def sort_key(f: dict) -> tuple:
    return (SEVERITY_ORDER.get(f.get("severity"), 9), f.get("category", ""), f.get("target", ""))


# --------------------------------------------------------------- birleşik bulgu listesi / rapor
def js_secret_finding(f: dict) -> dict | None:
    """JS analizindeki HIGH/MEDIUM sır bulgusunu birleşik modele çevirir (LOW anahtar kelimeler hariç)."""
    sev = f.get("severity")
    if sev not in ("HIGH", "MEDIUM"):
        return None
    return finding(sev, "js-secret", f.get("url", ""),
                   f"JS secret leak: {f.get('rule')}", "Sensitive data/key embedded in JavaScript.",
                   evidence=f.get("match", ""),
                   remediation="Remove the secret from the code and revoke the related key.")


def merge_findings(base: list[dict], js: list[dict] | None = None, dirs: list[dict] | None = None) -> list[dict]:
    """Tüm kaynakları önem sırasına göre TEK listede birleştirir:
    güvenlik (başlık/TLS/takeover/sürüm/port/nuclei) + JS sırları + dizin/dosya ifşaları.
    CLI raporu ve web arayüzü aynı fonksiyonu kullanır; ikisinin notu/sayıları birbirini tutar."""
    out: list[dict] = list(base)
    for f in js or []:
        item = js_secret_finding(f)
        if item is not None:
            out.append(item)
    for d in dirs or []:
        item = exposure_finding(d)
        if item is not None:
            out.append(item)
    out.sort(key=sort_key)
    return out


def findings_to_markdown(unified: list[dict], target: str) -> str:
    counts = severity_counts(unified)
    lines = [f"# Security findings report: {target}", "",
             f"- Total: {len(unified)}",
             "- " + " · ".join(f"{s}: {counts.get(s, 0)}" for s in SEVERITIES), ""]
    by_sev: dict[str, list[dict]] = {}
    for f in unified:
        by_sev.setdefault(f.get("severity", "INFO"), []).append(f)
    for s in SEVERITIES:
        items = by_sev.get(s, [])
        if not items:
            continue
        lines += [f"## {s} ({len(items)})", ""]
        for f in items:
            cvss = f" · CVSS {f['cvss']}" if f.get("cvss") is not None else ""
            cve = f" · {f['cve']}" if f.get("cve") else ""
            lines.append(f"- **{f.get('title')}**{cvss}{cve} — {f.get('target')}")
            if f.get("detail"):
                lines.append(f"  - {f['detail']}")
            if f.get("evidence"):
                lines.append(f"  - Evidence: `{f['evidence']}`")
            if f.get("remediation"):
                lines.append(f"  - Remediation: {f['remediation']}")
        lines.append("")
    return "\n".join(lines)
