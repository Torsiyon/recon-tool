"""Modül A: subfinder ile pasif subdomain keşfi + httpx ile canlılık/teknoloji tespiti.

Çıktılar (outputs/<hedef>/subdomains/):
  all.txt      bulunan tüm subdomainler
  live.txt     canlı URL'ler
  live.json    canlı hostların durum kodu, başlık, sunucu, teknolojiler, header'ları
  dead.txt     yanıt vermeyen subdomainler
  by_tech.txt  teknoloji -> URL özet listesi
"""
from __future__ import annotations

import json
import threading

from core import fingerprint
from core import security_checks as sec
from core.config import TOOL_DEFAULT_FLAGS
from core.fingerprint import detect_version_disclosure
from core.exceptions import ToolExecutionError
from core.targets import HOST_RE
from modules.base import BaseModule, LiveHost, ScanContext

MAX_EXPOSURE_BODY_FETCH = 120   # takeover imzası için gövde indirilen azami host sayısı
TAKEOVER_BODY_BYTES = 200_000   # takeover imzası hata sayfasının başındadır; fazlasını indirme


class SubdomainRecon(BaseModule):
    name = "subdomains"
    description = "subfinder + httpx: subdomain keşfi ve canlılık kontrolü"
    optional_tools = ("subfinder", "httpx")

    def run(self, ctx: ScanContext) -> None:
        self._emit = ctx.emit
        cfg = self.config.subdomains
        subs = self._enumerate(ctx) | self._load_user_list()
        if cfg.get("include_root", True):
            subs.add(ctx.target)
        ctx.subdomains = {s for s in subs if ctx.in_scope(s)}
        self.log.info(f"Toplam {len(ctx.subdomains)} benzersiz subdomain")

        self.probe_and_record(ctx, ctx.subdomains)

    def probe_and_record(self, ctx: ScanContext, hosts_set: set[str]) -> None:
        """Verilen host kümesini canlılık/teknoloji için yoklar, sonuçları + sürüm ifşasını kaydeder.
        Hem normal keşifte hem de 'keşfi atla' (elle hedef girme) modunda kullanılır."""
        self._emit = ctx.emit
        self._bodies: dict[str, str] = {}   # dahili yoklamada inen gövdeler (takeover için yeniden indirme)
        engine = self.choose_engine(self.config.subdomains.get("probe_engine"), "httpx")
        self.log.info(f"Canlılık kontrolü motoru: {engine}")
        # Her canlı host bulunduğu ANDA arayüze düşer (önceden yoklamanın tamamı bitene kadar tablo boştu).
        # Aynı URL birden çok kez gelebilir (ör. yönlendirme); burada tekilleştirilir.
        uniq: dict[str, LiveHost] = {}
        lock = threading.Lock()

        def on_host(h: LiveHost) -> None:
            if not ctx.in_scope(h.url):
                return
            key = h.url.rstrip("/")
            with lock:
                if key in uniq:
                    return
                uniq[key] = h
            self._emit("live_host", h.to_dict())

        if engine == "httpx":
            self._probe_httpx(hosts_set, on_host)
        else:
            self._probe_internal(hosts_set, on_host)
        ctx.live_hosts = sorted(uniq.values(), key=lambda h: h.url)
        self.log.info(f"{len(ctx.live_hosts)} canlı host")
        ctx.stats["probe_engine"] = engine
        self._record_version_disclosure(ctx)
        self._analyze_exposure(ctx)
        self._save(ctx)

    # --------------------------------------------------------------- maruziyet
    def _analyze_one_host(self, h: LiveHost) -> list[dict]:
        """Tek host için güvenlik başlığı + TLS + takeover bulgularını toplar."""
        out: list[dict] = []
        out += sec.analyze_security_headers(h.url, h.headers, h.status_code)
        if h.url.lower().startswith("https") and h.host:
            out += sec.analyze_tls(h.host)
        return out

    def _analyze_exposure(self, ctx: ScanContext) -> None:
        """Canlı hostları birleşik güvenlik bulgularına çevirir (başlık/TLS/takeover/sürüm).

        Sonuç ctx.findings['security'] içinde toplanır ve her bulgu 'finding' olayı olarak yayınlanır,
        böylece web arayüzü anlık gösterebilir."""
        findings: list[dict] = []
        # 1) Sürüm ifşasını birleşik modele taşı
        for leak in ctx.findings.get("version_disclosure", []):
            findings.append(sec.version_finding(leak))
        # 2) Başlık + TLS (paralel)
        for h, res, exc in self.parallel(self._analyze_one_host, ctx.live_hosts):
            if exc:
                self.log.debug(f"maruziyet analizi hatası: {exc}")
            elif res:
                findings.extend(res)
        # 3) Takeover: sınırlı sayıda host için gövdede imza ara. Dahili yoklama gövdeyi zaten
        #    indirdiyse o kullanılır (host başına ikinci bir istek atılmaz); yalnızca eksikler indirilir.
        candidates = ctx.live_hosts[:MAX_EXPOSURE_BODY_FETCH]
        bodies = getattr(self, "_bodies", {})
        for h in candidates:
            if h.url in bodies:
                findings.extend(sec.detect_takeover(h.url, bodies[h.url]))
        missing = [h for h in candidates if h.url not in bodies]
        for h, body, exc in self.parallel(self._fetch_body, missing):
            if not exc and body:
                findings.extend(sec.detect_takeover(h.url, body))
        self._bodies = {}
        findings.sort(key=sec.sort_key)
        ctx.findings["security"] = findings
        for f in findings:
            self._emit("finding", f)
        counts = sec.severity_counts(findings)
        ctx.stats["security_findings"] = len(findings)
        ctx.stats["security_counts"] = counts
        if findings:
            self.log.warning(f"Güvenlik bulguları: {len(findings)} {counts}")
        lines = [f"[{f['severity']}][{f['category']}] {f['target']} — {f['title']}"
                 + (f"  ({f['evidence']})" if f['evidence'] else "") for f in findings]
        self.output.write_lines("root", "compliance/findings.txt", lines, sort=False)
        self.output.write_json("root", "compliance/findings.json", findings)

    def _fetch_body(self, h: LiveHost) -> str:
        resp = self.http.get(h.url, allow_redirects=True, max_bytes=TAKEOVER_BODY_BYTES)
        return resp.text if resp else ""

    def _record_version_disclosure(self, ctx: ScanContext) -> None:
        """Her canlı hostun yanıt başlıklarında sürüm/banner ifşası arar."""
        leaks: list[dict] = []
        for h in ctx.live_hosts:
            for item in detect_version_disclosure(h.headers):
                rec = {"url": h.url, **item}
                leaks.append(rec)
                self._emit("version_leak", rec)
        ctx.findings["version_disclosure"] = leaks
        ctx.stats["version_leaks"] = len(leaks)
        if leaks:
            self.log.warning(f"Sürüm/banner ifşası: {len(leaks)} başlık ({len({l['url'] for l in leaks})} host)")
        lines = [f"{l['url']}  {l['header']}: {l['value']}" for l in leaks]
        self.output.write_lines("root", "compliance/version_disclosure.txt", lines, sort=True)

    # ------------------------------------------------------------------ keşif
    def _enumerate(self, ctx: ScanContext) -> set[str]:
        if not self.runner.is_available("subfinder"):
            self.log.warning("subfinder bulunamadı; yalnızca kök domain taranacak.")
            return set()
        # -d <hedef> zorunlu (kaldırılamaz); geri kalan bayraklar düzenlenebilir (varsayılan: -silent -nc -all)
        args = ["-d", ctx.target] + self.config.flags("subfinder", TOOL_DEFAULT_FLAGS["subfinder"])
        if self.config.proxy and self.config.proxy.startswith("http"):
            args += ["-proxy", self.config.proxy]
        try:
            res = self.runner.run("subfinder", args)
        except ToolExecutionError as exc:
            self.log.error(f"subfinder başarısız: {exc}")
            return set()
        found = set()
        for line in res.stdout.splitlines():
            host = line.strip().lower().lstrip("*.").rstrip(".")
            if HOST_RE.match(host):
                found.add(host)
        self.log.info(f"subfinder: {len(found)} subdomain")
        return found

    def _load_user_list(self) -> set[str]:
        path = self.config.extra_subdomains
        if not path:
            return set()
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            self.log.error(f"Subdomain listesi okunamadı ({path}): {exc}")
            return set()
        subs = {l.strip().lower().lstrip("*.").rstrip(".") for l in lines}
        subs = {s for s in subs if HOST_RE.match(s)}
        self.log.info(f"--subs: {len(subs)} subdomain eklendi")
        return subs

    # ------------------------------------------------------------------ httpx
    def _probe_httpx(self, subdomains: set[str], on_host) -> None:
        rl = self.config.rate_limit
        # -json zorunlu (çıktı ayrıştırma için, kaldırılamaz); davranış bayrakları düzenlenebilir.
        args = ["-json"] + self.config.flags("httpx", TOOL_DEFAULT_FLAGS["httpx"]) + [
            "-rl", self.limiter.as_tool_flag(),
            "-t", rl.threads,
            "-timeout", rl.timeout,
            "-H", f"User-Agent: {rl.user_agent}",
            *self.config.header_flags("-H"),
        ]
        ports = self.config.subdomains.get("ports") or []
        if ports:
            args += ["-p", ",".join(str(p) for p in ports)]
        if self.config.proxy:
            args += ["-http-proxy", self.config.proxy]

        def on_line(line: str) -> None:
            h = self._parse_httpx_line(line)
            if h is not None:
                on_host(h)

        try:
            self.runner.run("httpx", args, stdin="\n".join(sorted(subdomains)) + "\n", on_stdout=on_line)
        except ToolExecutionError as exc:
            self.log.error(f"httpx başarısız, dahili motora geçiliyor: {exc}")
            self._probe_internal(subdomains, on_host)

    @staticmethod
    def _parse_httpx_line(line: str) -> LiveHost | None:
        """Tek bir httpx JSON satırını LiveHost'a çevirir (yanıt vermeyen / bozuk satır için None)."""
        line = line.strip()
        if not line.startswith("{"):
            return None
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(d, dict) or d.get("failed") or not d.get("url"):
            return None
        headers = d.get("header") or d.get("headers") or {}
        techs = list(d.get("tech") or d.get("technologies") or [])
        # httpx teknolojilerini header tabanlı imzalarla zenginleştir (cookie vb.)
        norm_headers = {str(k).replace("_", "-"): (", ".join(v) if isinstance(v, list) else str(v))
                        for k, v in headers.items()}
        for t in fingerprint.detect(norm_headers):
            if not any(t.lower() in x.lower() for x in techs):
                techs.append(t)
        return LiveHost(
            url=d["url"].rstrip("/"),
            host=d.get("input") or d.get("host") or "",
            status_code=d.get("status_code"),
            title=d.get("title"),
            webserver=d.get("webserver"),
            content_length=d.get("content_length"),
            technologies=techs,
            headers=headers,
            source="httpx",
        )

    # ------------------------------------------------------------------ dahili
    def _probe_one(self, host: str) -> LiveHost | None:
        if not hasattr(self, "_bodies"):
            self._bodies = {}
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            # httpx ile aynı anlam: yönlendirme takip edilmeden ilk yanıtın kodu
            resp = self.http.get(url, allow_redirects=False)
            if resp is None:
                continue
            body = resp.text
            if not 300 <= resp.status_code < 400:      # yönlendirmede asıl sayfa ayrıca indirilir
                self._bodies[url] = body[:TAKEOVER_BODY_BYTES]
            return LiveHost(
                url=url,
                host=host,
                status_code=resp.status_code,
                title=fingerprint.extract_title(body),
                webserver=resp.headers.get("Server"),
                content_length=resp.length,
                technologies=fingerprint.detect(resp.headers, body),
                headers=resp.headers,
                source="internal",
            )
        return None

    def _probe_internal(self, subdomains: set[str], on_host) -> None:
        for sub, h, exc in self.parallel(self._probe_one, sorted(subdomains)):
            if exc:
                self.log.debug(f"{sub} yoklanamadı: {exc}")
            elif h:
                on_host(h)

    # ------------------------------------------------------------------ kayıt
    def _save(self, ctx: ScanContext) -> None:
        live_hostnames = {h.host for h in ctx.live_hosts}
        self.output.write_lines("subdomains", "all.txt", ctx.subdomains)
        self.output.write_lines("subdomains", "live.txt", (h.url for h in ctx.live_hosts))
        self.output.write_lines("subdomains", "dead.txt", ctx.subdomains - live_hostnames)
        self.output.write_json("subdomains", "live.json", [h.to_dict() for h in ctx.live_hosts])
        by_tech: dict[str, list[str]] = {}
        for h in ctx.live_hosts:
            for t in h.technologies or ["(tespit edilemedi)"]:
                by_tech.setdefault(t, []).append(h.url)
        lines = [f"{t}: {', '.join(sorted(urls))}" for t, urls in sorted(by_tech.items())]
        self.output.write_lines("subdomains", "by_tech.txt", lines, sort=False)
