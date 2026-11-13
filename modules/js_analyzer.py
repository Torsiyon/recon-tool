"""Modül B (2/2): JS dosyalarında kritik veri (anahtar, token, parola...) tespiti.

Her JS dosyası rate limit'e uyularak indirilir ve satır satır taranır:
  1) Kesin formatlı regex kuralları (AWS anahtarı, Google API anahtarı, JWT, özel anahtar...) -> HIGH
  2) Değer atamalı genel kurallar (apiKey = "...", password: "...")                         -> MEDIUM
  3) Kelime listesi, yalnızca atama + sır-benzeri değer (api_key/secret/token/password…=VALUE) -> LOW

Çıktılar (outputs/<hedef>/js_analysis/):
  js_files.txt     taranan JS URL'leri (crawler yazar)
  critical.txt     [SEVİYE][kural] url:satır -> kesit   (önem sırasına göre)
  critical.json    aynı bulgular makine-okunur biçimde
  endpoints.txt    JS içinden çıkarılan yol/URL'ler (LinkFinder benzeri, ham hâlleriyle)
  endpoint_urls.txt  bu yolların tam URL'ye çözülmüş, kapsam içi hâlleri (URL envanterine de eklenir)
  skipped.txt      kütüphane olduğu için atlanan dosyalar
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from urllib.parse import urldefrag, urlsplit

from core.progress import ProgressCounter
from modules.base import BaseModule, ScanContext
from modules.crawler import is_js, save_url_inventory

# Keyword (LOW) pass: only secret-ish words, and only when they look like an assignment
# (word followed by : or =). "config"/"admin" were removed — too generic, pure noise in
# minified libraries (e.g. "Config" inside TableTools.min.js).
KEYWORDS = ["api_key", "apikey", "api-key", "secret", "token", "password", "passwd", "aws_", "firebase"]

# (kural adı, seviye, regex)
REGEX_RULES: list[tuple[str, str, str]] = [
    ("aws_access_key", "HIGH", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("aws_secret_key", "HIGH", r"(?i)aws.{0,20}(?:secret|private).{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("google_api_key", "HIGH", r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ("google_oauth_client", "MEDIUM", r"\b[0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com\b"),
    ("firebase_db_url", "MEDIUM", r"\b[a-z0-9.-]+\.firebaseio\.com\b"),
    ("firebase_app", "LOW", r"\b[a-z0-9-]+\.firebaseapp\.com\b"),
    ("private_key", "HIGH", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"),
    ("github_token", "HIGH", r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{60,}\b"),
    ("slack_token", "HIGH", r"\bxox[abposr]-[0-9A-Za-z-]{10,}\b"),
    ("slack_webhook", "HIGH", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
    ("stripe_secret", "HIGH", r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b"),
    ("stripe_public", "LOW", r"\bpk_live_[0-9a-zA-Z]{20,}\b"),
    ("twilio_key", "HIGH", r"\bSK[0-9a-fA-F]{32}\b"),
    ("sendgrid_key", "HIGH", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
    ("mailgun_key", "HIGH", r"\bkey-[0-9a-zA-Z]{32}\b"),
    ("jwt", "MEDIUM", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ("basic_auth_url", "HIGH", r"\b[a-z][a-z0-9+.-]*://[^/\s:@'\"]{1,64}:[^/\s:@'\"]{1,64}@[^\s'\"]+"),
    ("s3_bucket", "LOW", r"\b[a-z0-9.-]{3,63}\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\b|\bs3://[a-z0-9.-]{3,63}"),
    ("bearer_token", "MEDIUM", r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{20,}=*"),
    ("generic_secret_assignment", "MEDIUM",
     r"(?i)\b[\w-]*(?:api[_-]?key|apikey|secret|token|passw(?:or)?d|pwd|client[_-]?secret|access[_-]?key)[\w-]*"
     r"['\"]?\s*[:=]\s*['\"`]([^'\"`\s]{6,})['\"`]"),
]

# Değeri sahte/yer tutucu olan atamaları ele (gürültü azaltma)
PLACEHOLDER_RE = re.compile(r"(?i)^(?:x{4,}|\*{4,}|your[_-]|<|\$\{|\{\{|process\.env|null|undefined|true|false|example|changeme|test)")

# Common non-secret values that look like `key: "value"` but are config/validation vocabulary,
# e.g. `password: 'required'` on a form field. These are NOT leaked secrets.
SECRET_STOPWORDS = {
    "required", "optional", "nullable", "none", "null", "undefined", "default", "auto",
    "true", "false", "yes", "no", "on", "off", "string", "number", "integer", "boolean",
    "object", "array", "function", "hidden", "submit", "button", "checkbox", "radio",
    "text", "email", "value", "label", "title", "name", "type", "input", "readonly",
    "checked", "selected", "enabled", "disabled", "primary", "secondary", "error", "success",
}


def _looks_like_secret(value: str) -> bool:
    """A captured assignment value is treated as a real secret only if it is long enough and
    not an ordinary word. Cuts false positives like `password: 'required'` (a validation rule)
    while keeping credential-like values (`hunter2`, mixed-case/base64/hex tokens)."""
    v = value.strip()
    if len(v) < 6 or v.lower() in SECRET_STOPWORDS:
        return False
    classes = sum(bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    # Real secrets mix character classes, or are long enough to be high-entropy.
    return classes >= 2 or len(v) >= 16

ENDPOINT_RE = re.compile(
    r"""["'`]((?:https?://[^"'`\s]{4,}|/[a-zA-Z0-9_\-./]{2,}(?:\?[^"'`\s]*)?|[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-./]+\.(?:php|aspx?|jsp|json|action|do|html?)(?:\?[^"'`\s]*)?))["'`]"""
)
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
SNIPPET_RADIUS = 80
MAX_HITS_PER_RULE_PER_LINE = 25   # minified (tek satırlık) dosyalarda kural başına üst sınır


@dataclass
class JSFinding:
    url: str
    line_no: int
    rule: str
    severity: str
    match: str
    snippet: str

    def to_line(self) -> str:
        return f"[{self.severity}][{self.rule}] {self.url}:{self.line_no} -> {self.snippet}"


class JSAnalyzer(BaseModule):
    name = "js"
    description = "JS dosyalarında hassas veri/anahtar kelime taraması"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._rules = [(n, sev, re.compile(rx)) for n, sev, rx in REGEX_RULES]
        # Keyword (LOW) only when it looks like an assignment: word followed by : or = and a value.
        # group(1)=keyword, group(2)=value. This stops minified-library noise (bare word, no value)
        # and config/validation values (password: 'required') are dropped by the value check below.
        self._keyword_re = re.compile(
            r"(?i)\b(" + "|".join(re.escape(k) for k in KEYWORDS) +
            r")\b['\"]?\s*[:=]\s*['\"]?([^'\"\s,;{}()]{1,60})?")
        cfg = getattr(self.config, "js_analysis", None) or {}
        self._skip = [re.compile(p, re.I) for p in cfg.get("skip_patterns", [])]
        self._max_files = int(cfg.get("max_files", 500))
        self._feed_endpoints = bool(cfg.get("feed_endpoints", True))

    # ------------------------------------------------------------------ akış
    def run(self, ctx: ScanContext) -> None:
        self._emit = ctx.emit
        if not ctx.js_files:
            self.log.warning("Analiz edilecek JS dosyası yok.")
            self._save([], set(), [], ctx)
            return
        targets, skipped = self._split(sorted(ctx.js_files))
        if len(targets) > self._max_files:
            self.log.warning(f"{len(targets)} JS dosyası var, ilk {self._max_files} taranacak (js_analysis.max_files)")
            targets = targets[: self._max_files]
        self.log.info(f"{len(targets)} JS dosyası taranacak, {len(skipped)} kütüphane atlandı")

        findings: list[JSFinding] = []
        endpoints: set[str] = set()
        resolved: set[str] = set()       # endpoint'lerin tam URL'ye çözülmüş, kapsam içi hâlleri
        self._scan_batch(targets, "JS analizi", ctx, findings, endpoints, resolved)

        if self._feed_endpoints and resolved:
            # JS içinden çıkan yollar artık yalnızca dosyaya yazılmıyor: URL envanterine eklenir ve
            # crawler'ın hiç görmediği JS dosyaları (lazy-load chunk'lar) bir tur daha taranır.
            new_js, more_skipped = self._split(sorted(u for u in resolved if is_js(u) and u not in ctx.js_files))
            skipped += more_skipped
            budget = max(0, self._max_files - len(targets))
            if new_js[:budget]:
                self.log.info(f"JS içinden {len(new_js[:budget])} yeni JS dosyası bulundu; onlar da taranıyor")
                self._scan_batch(new_js[:budget], "JS analizi (2. tur)", ctx, findings, endpoints, resolved)
            added = resolved - ctx.urls
            ctx.urls |= resolved
            ctx.js_files |= {u for u in resolved if is_js(u)}
            ctx.stats["js_endpoint_urls"] = len(added)
            if added:
                self.log.info(f"JS endpoint'lerinden {len(added)} yeni URL envantere eklendi")
                save_url_inventory(self.output, ctx)

        findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.url, f.line_no, f.rule))
        ctx.findings[self.name] = [asdict(f) for f in findings]
        counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
        ctx.stats["js_findings"] = counts
        self.log.info(f"JS bulguları: {counts}")
        self._save(findings, endpoints, skipped, ctx, resolved)

    def _split(self, urls: list[str]) -> tuple[list[str], list[str]]:
        """(taranacaklar, bilinen kütüphane olduğu için atlananlar)"""
        targets: list[str] = []
        skipped: list[str] = []
        for url in urls:
            (skipped if any(rx.search(url) for rx in self._skip) else targets).append(url)
        return targets, skipped

    def _scan_batch(self, targets: list[str], label: str, ctx: ScanContext, findings: list[JSFinding],
                    endpoints: set[str], resolved: set[str]) -> None:
        with ProgressCounter(label, len(targets)) as progress:
            for url, result, exc in self.parallel(self._process, targets):
                if exc:
                    self.log.error(f"{url} analiz edilemedi: {exc}")
                    progress.advance(error=True)
                    continue
                f, e = result
                findings.extend(f)
                endpoints |= e
                for ep in e:
                    full = self.resolve_endpoint(url, ep)
                    if full and ctx.in_scope(full):
                        resolved.add(full)
                for finding in f:
                    self._emit("js_finding", asdict(finding))
                progress.advance(found=len(f))

    @staticmethod
    def resolve_endpoint(js_url: str, endpoint: str) -> str:
        """JS içindeki bir yolu tam URL'ye çevirir. Mutlak URL olduğu gibi kalır; '/api/x' ve 'api/x.php'
        gibi yollar JS dosyasının geldiği sitenin köküne göre çözülür (uygulama yolları genelde köke
        göredir, JS dosyasının bulunduğu /static/ klasörüne göre değil)."""
        endpoint = urldefrag(endpoint.strip())[0]
        if endpoint.lower().startswith(("http://", "https://")):
            return endpoint
        parts = urlsplit(js_url)
        if not parts.scheme or not parts.netloc or not endpoint:
            return ""
        return f"{parts.scheme}://{parts.netloc}/{endpoint.lstrip('/')}"

    def _process(self, url: str) -> tuple[list[JSFinding], set[str]]:
        resp = self.http.get(url, allow_redirects=True)
        if resp is None or resp.status_code != 200 or not resp.text:
            self.log.debug(f"İndirilemedi: {url} ({resp.status_code if resp else 'bağlantı hatası'})")
            return [], set()
        return self.scan_content(url, resp.text), self.extract_endpoints(resp.text)

    # ------------------------------------------------------------------ tarama
    @staticmethod
    def _snippet(line: str, start: int, end: int) -> str:
        a, b = max(0, start - SNIPPET_RADIUS), min(len(line), end + SNIPPET_RADIUS)
        text = line[a:b].strip()
        return ("…" if a > 0 else "") + text + ("…" if b < len(line) else "")

    @staticmethod
    def _overlaps(span: tuple[int, int], spans: list[tuple[int, int]]) -> bool:
        return any(span[0] < e and s < span[1] for s, e in spans)

    def scan_content(self, url: str, content: str) -> list[JSFinding]:
        """Satır satır tarar. Bir satırda aynı kural, FARKLI her değer için bir kez raporlanır
        (minified/tek satırlık paketlerde birden çok anahtar kaçmasın diye; aynı değer tekrar etmez).

        Genel atama kuralı ve anahtar kelime geçişi, yalnızca daha kesin bir kuralın eşleştiği
        AYNI metin parçasıyla çakışıyorsa bastırılır — satırın geri kalanı taranmaya devam eder."""
        results: list[JSFinding] = []
        for no, line in enumerate(content.splitlines(), start=1):
            if not line.strip():
                continue
            spans: list[tuple[int, int]] = []
            for name, sev, rx in self._rules:
                generic = name == "generic_secret_assignment"
                seen_values: set[str] = set()
                for m in rx.finditer(line):
                    value = m.group(m.lastindex) if m.lastindex else m.group(0)
                    if value in seen_values:
                        continue
                    if generic and (self._overlaps(m.span(), spans) or PLACEHOLDER_RE.match(value)
                                    or not _looks_like_secret(value)):
                        continue  # daha kesin bir kural aynı yeri yakaladı ya da değer yer tutucu/sıradan kelime
                    seen_values.add(value)
                    spans.append(m.span())
                    results.append(JSFinding(url, no, name, sev, m.group(0)[:200], self._snippet(line, m.start(), m.end())))
                    if len(seen_values) >= MAX_HITS_PER_RULE_PER_LINE:
                        break
            seen_keywords: set[str] = set()
            for kw in self._keyword_re.finditer(line):
                word = kw.group(1).lower()
                val = kw.group(2) or ""
                # Atama + değer şart; sıradan config/doğrulama değerleri (password: 'required') ve
                # yer tutucular elenir. Her anahtar kelime satırda bir kez raporlanır.
                if (not val or word in seen_keywords or self._overlaps(kw.span(), spans)
                        or val.lower() in SECRET_STOPWORDS or PLACEHOLDER_RE.match(val)):
                    continue
                seen_keywords.add(word)
                results.append(JSFinding(url, no, f"keyword:{word}", "LOW",
                                         kw.group(1), self._snippet(line, kw.start(), kw.end())))
        return results

    @staticmethod
    def extract_endpoints(content: str) -> set[str]:
        out = set()
        for m in ENDPOINT_RE.finditer(content):
            ep = m.group(1)
            if len(ep) > 300 or ep.startswith("//") or re.search(r"\.(png|jpe?g|gif|svg|css|woff2?)(\?|$)", ep, re.I):
                continue
            out.add(ep)
        return out

    # ------------------------------------------------------------------ kayıt
    def _save(self, findings: list[JSFinding], endpoints: set[str], skipped: list[str], ctx: ScanContext,
              resolved: set[str] | None = None) -> None:
        header = [
            f"# JS sensitive-data report - {ctx.target}",
            f"# Total: {len(findings)} | " + " | ".join(
                f"{s}: {sum(1 for f in findings if f.severity == s)}" for s in SEVERITY_ORDER),
            "# Format: [SEVERITY][rule] url:line -> snippet",
            "",
        ]
        self.output.write_text("js_analysis", "critical.txt", "\n".join(header + [f.to_line() for f in findings]) + "\n")
        self.output.write_json("js_analysis", "critical.json", [asdict(f) for f in findings])
        self.output.write_lines("js_analysis", "endpoints.txt", endpoints)
        self.output.write_lines("js_analysis", "endpoint_urls.txt", resolved or ())
        self.output.write_lines("js_analysis", "skipped.txt", skipped)
