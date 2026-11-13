"""Modül C: Teknolojiye duyarlı dizin/dosya keşfi (dahili motor veya ffuf).

Akış (her canlı host için):
  1) httpx/fingerprint teknolojilerine göre wordlist seçimi (settings.yaml -> tech_wordlists)
     + altyapıdan bağımsız genel listeler (hassas dosyalar, yedekler, yaygın dizinler)
     + opsiyonel kullanıcı listesi (--wordlist)
  2) {domain} / {host} / {sub} yer tutucuları hedefe göre doldurulur (ör. example.com.zip)
  3) Soft-404 kalibrasyonu: rastgele yollara verilen yanıt "taban çizgisi" olur, ona benzeyenler elenir
  4) Bilinen hassas dosyalar içerik imzasıyla doğrulanır (ör. .git/HEAD içinde "ref:")

Çıktılar (outputs/<hedef>/directory_brute/):
  found.txt       tüm bulgular: DURUM UZUNLUK KATEGORİ URL
  sensitive.txt   hassas dosya/dizin bulguları
  backups.txt     yedek dosya bulguları
  verified.txt    içeriği doğrulanmış ifşaatlar
  findings.json   tüm ayrıntılar
"""
from __future__ import annotations

import difflib
import json
import re
import secrets
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit

from core.config import PROJECT_ROOT
from core.exceptions import ScanCancelled, ToolExecutionError
from core.progress import ProgressCounter
from modules.base import BaseModule, LiveHost, ScanContext

# İçerik doğrulama imzaları: yol deseni -> gövdede aranacak regex
VERIFY_SIGNATURES: list[tuple[re.Pattern, re.Pattern]] = [
    (re.compile(r"\.git/HEAD$"), re.compile(r"^ref: refs/", re.M)),
    (re.compile(r"\.git/config$"), re.compile(r"\[core\]")),
    (re.compile(r"\.svn/entries$"), re.compile(r"^\d+\s*$|dir", re.M)),
    (re.compile(r"\.env(\.[a-z]+)?$"), re.compile(r"^[A-Z0-9_]{2,}\s*=", re.M)),
    (re.compile(r"\.DS_Store$"), re.compile(r"Bud1")),
    (re.compile(r"wp-config\.php(\.bak|\.old|~|\.save|\.txt)$"), re.compile(r"DB_PASSWORD")),
    (re.compile(r"web\.config(\.bak|\.old)?$"), re.compile(r"<configuration", re.I)),
    (re.compile(r"phpinfo\.php$|info\.php$"), re.compile(r"PHP Version", re.I)),
    (re.compile(r"actuator/env$"), re.compile(r"propertySources|activeProfiles")),
    (re.compile(r"\.(sql|sql\.gz)$"), re.compile(r"(CREATE TABLE|INSERT INTO|mysqldump)", re.I)),
    (re.compile(r"server-status$"), re.compile(r"Apache Server Status", re.I)),
    (re.compile(r"\.htpasswd$"), re.compile(r"^[^:\s]+:\S+", re.M)),
    (re.compile(r"package\.json$|composer\.json$"), re.compile(r"\"(dependencies|require)\"")),
    (re.compile(r"swagger\.json$|openapi\.json$|api-docs$"), re.compile(r"\"(swagger|openapi)\"")),
]
FFUF_PROGRESS_RE = re.compile(r"Progress: \[(\d+)/(\d+)\].*?Errors: (\d+)")
ARCHIVE_MAGIC = (b"PK\x03\x04", b"\x1f\x8b", b"Rar!", b"7z\xbc\xaf")
# Yoklamada gövdenin yalnızca başı gerekir (soft-404 karşılaştırması ilk 3000 karaktere bakar).
# Sınır olmadan, bulunan her büyük yedek/arşiv dosyası 5 MB'a kadar indiriliyordu.
PROBE_MAX_BYTES = 64 * 1024
VERIFY_MAX_BYTES = 256 * 1024


@dataclass
class DirFinding:
    url: str
    path: str
    status: int
    length: int
    category: str            # sensitive | backup | tech:<ad> | common | custom
    redirect: str = ""
    verified: bool = False
    engine: str = ""
    evidence: str = ""       # content proof snippet for verified sensitive files

    def to_line(self) -> str:
        flag = " [VERIFIED]" if self.verified else ""
        redir = f" -> {self.redirect}" if self.redirect else ""
        return f"{self.status} {self.length:>8} {self.category:<14} {self.url}{redir}{flag}"


class DirBruteforcer(BaseModule):
    name = "dirs"
    description = "Altyapıya göre wordlist seçen dizin ve yedek dosya taraması"
    optional_tools = ("ffuf",)

    # ------------------------------------------------------------------ akış
    def run(self, ctx: ScanContext) -> None:
        self._emit = ctx.emit
        if not ctx.live_hosts:
            self.log.warning("Canlı host yok, dizin taraması atlandı.")
            return
        cfg = self.config.dir_bruteforce
        engine = self.choose_engine(cfg.get("engine"), "ffuf")
        hosts = ctx.live_hosts[: int(cfg.get("max_hosts", 50))]
        if len(hosts) < len(ctx.live_hosts):
            self.log.warning(f"{len(ctx.live_hosts)} canlı hosttan ilk {len(hosts)} taranacak (dir_bruteforce.max_hosts)")
        self.log.info(f"Dizin tarama motoru: {engine}")
        ctx.stats["dir_engine"] = engine

        all_hits: list[DirFinding] = []
        # Hostlar SIRAYLA taranır: toplam istek hızı --rate-limit değerini aşmaz.
        for idx, host in enumerate(hosts, start=1):
            try:
                # Wordlist haritası host başına BİR kez kurulur ve motorlara aktarılır
                # (önceden her host için dosyalar diskten iki kez okunup yeniden işleniyordu).
                categories = self.build_wordlist_map(host, ctx.target)
                words = list(categories)
                self.log.info(f"[{idx}/{len(hosts)}] {host.url}: {len(words)} yol | "
                              f"teknolojiler: {', '.join(host.technologies) or '-'}")
                label = f"[{idx}/{len(hosts)}] {host.url}"
                hits = (self._scan_ffuf(host, words, label, categories) if engine == "ffuf"
                        else self._scan_internal(host, words, label, categories))
                # Verify BEFORE emitting so the UI/live table sees the final verified flag
                # and the content-proof evidence (otherwise findings arrive as unverified).
                self._verify(hits)
                for h in hits:
                    self._emit("dir_hit", asdict(h))
                all_hits.extend(hits)
                self.log.info(f"{host.url}: {len(hits)} bulgu")
            except ScanCancelled:
                raise
            except Exception as exc:  # bir hostun hatası diğerlerini durdurmasın
                self.log.error(f"{host.url} taranamadı: {exc}")

        ctx.findings[self.name] = [asdict(h) for h in all_hits]
        ctx.stats["dir_findings"] = len(all_hits)
        self._save(all_hits)

    # ------------------------------------------------------------------ wordlist
    def select_wordlists(self, host: LiveHost) -> list[tuple[str, Path]]:
        """(kategori, dosya) listesi: önce genel listeler, sonra teknolojiye özel olanlar."""
        cfg = self.config.dir_bruteforce
        backup_wl = cfg.get("backup_wordlist", "wordlists/common/backups.txt")
        cmap = cfg.get("_category_map") or {}   # arayüzden gelen kesin kategori eşlemesi
        chosen: list[tuple[str, Path]] = []
        for wl in cfg.get("common_wordlists", []):
            path = PROJECT_ROOT / wl               # mutlak yol verilirse olduğu gibi kalır
            cat = cmap.get(str(path.resolve()))
            if cat is None:
                cat = "backup" if wl == backup_wl else ("sensitive" if "sensitive" in str(wl) else "common")
            chosen.append((cat, path))
        techs = [t.lower() for t in host.technologies]
        seen = {p for _, p in chosen}
        for key, wl in (cfg.get("tech_wordlists") or {}).items():
            path = PROJECT_ROOT / wl
            if path not in seen and any(key.lower() in t for t in techs):
                chosen.append((f"tech:{Path(wl).stem}", path))
                seen.add(path)
        if self.config.extra_wordlist:
            chosen.append(("custom", Path(self.config.extra_wordlist)))
        return chosen

    @staticmethod
    def _expand(word: str, domain: str, host: str) -> list[str]:
        sub = host.split(".")[0] if host != domain else domain.split(".")[0]
        values = {"{domain}": domain, "{host}": host, "{sub}": sub}
        out = word
        for k, v in values.items():
            out = out.replace(k, v)
        return [out]

    def build_wordlist(self, host: LiveHost, domain: str) -> list[str]:
        return list(self.build_wordlist_map(host, domain))

    def build_wordlist_map(self, host: LiveHost, domain: str) -> dict[str, str]:
        """yol -> kategori (ilk gelen kategori kalır; genel listeler önceliklidir)."""
        mapping: dict[str, str] = {}
        for category, path in self.select_wordlists(host):
            for raw in self._wordlist_lines(path):
                for w in self._expand(raw, domain, host.host or domain):
                    w = w.lstrip("/")
                    if w and " " not in w:
                        mapping.setdefault(w, category)
        return mapping

    def _wordlist_lines(self, path: Path) -> list[str]:
        """Bir wordlist dosyasının temizlenmiş satırları. Dosya tarama boyunca bir kez okunur;
        50 host x büyük bir SecLists dosyası her host için yeniden okunmaz."""
        cache = self.__dict__.setdefault("_wl_cache", {})
        if path not in cache:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                self.log.error(f"Wordlist okunamadı ({path}): {exc}")
                text = ""
            cache[path] = [l for l in (raw.strip() for raw in text.splitlines()) if l and not l.startswith("#")]
        return cache[path]

    # ------------------------------------------------------------------ dahili motor
    def _baseline(self, base: str) -> list[tuple[int, int, str]]:
        """Var olmayan yollara verilen yanıtlar (soft-404 / wildcard tespiti)."""
        probes = [secrets.token_hex(8), secrets.token_hex(8) + ".php", secrets.token_hex(8) + "/",
                  "." + secrets.token_hex(6), secrets.token_hex(8) + ".zip"]
        base_lines = []
        for p in probes:
            r = self.http.get(f"{base}/{p}", allow_redirects=False, max_bytes=PROBE_MAX_BYTES)
            if r is not None:
                base_lines.append((r.status_code, r.length, self._norm_body(r.text, p)))
        return base_lines

    @staticmethod
    def _norm_body(text: str, path: str) -> str:
        """İstenen yolun sayfaya yansımasını çıkar ki karşılaştırma adil olsun."""
        return text[:3000].replace(path, "").replace(path.rstrip("/"), "")

    @classmethod
    def _is_soft404(cls, status: int, length: int, body: str, baselines: list[tuple[int, int, str]]) -> bool:
        for b_status, b_len, b_body in baselines:
            if status != b_status:
                continue
            if abs(length - b_len) > max(50, int(b_len * 0.10)):
                continue
            # Uzunluk yakın: içerik benzerliğine bak (küçük ama farklı dosyaları kaçırmamak için)
            if body == b_body:          # en sık durum (wildcard sayfa): pahalı difflib'e hiç girme
                return True
            # Tek eşleyici; ucuzdan pahalıya üst sınırlar (real_quick -> quick -> ratio)
            sm = difflib.SequenceMatcher(None, body, b_body)
            if sm.real_quick_ratio() >= 0.85 and sm.quick_ratio() >= 0.85 and sm.ratio() >= 0.85:
                return True
        return False

    def _scan_internal(self, host: LiveHost, words: list[str], label: str = "",
                       categories: dict[str, str] | None = None) -> list[DirFinding]:
        base = host.url.rstrip("/")
        if categories is None:
            categories = self.build_wordlist_map(host, self.config.target)
        match_codes = set(self.config.dir_bruteforce.get("match_codes") or [200, 204, 301, 302, 307, 401, 403])
        baselines = self._baseline(base)
        if any(b[0] == 200 for b in baselines):
            self.log.warning(f"{base}: rastgele yollara 200 dönüyor (wildcard); uzunluk filtresi uygulanacak")

        def probe(word: str) -> DirFinding | None:
            r = self.http.get(f"{base}/{word}", allow_redirects=False, max_bytes=PROBE_MAX_BYTES)
            if r is None or r.status_code not in match_codes:
                return None
            if self._is_soft404(r.status_code, r.length, self._norm_body(r.text, word), baselines):
                return None
            redirect = r.headers.get("Location") or r.headers.get("location") or ""
            return DirFinding(f"{base}/{word}", word, r.status_code, r.length,
                              categories.get(word, "common"), redirect, engine="internal")

        hits: list[DirFinding] = []
        with ProgressCounter(label or base, len(words), self._log_interval()) as progress:
            for word, hit, exc in self.parallel(probe, words):
                if exc:
                    self.log.debug(f"{word}: istek hatası: {exc}")
                elif hit:
                    hits.append(hit)
                progress.advance(found=1 if hit else 0, error=exc is not None)
        return self._drop_redirect_noise(hits)

    @staticmethod
    def _drop_redirect_noise(hits: list[DirFinding]) -> list[DirFinding]:
        """Çok sayıda yolun AYNI hedefe yönlendirmesi (ör. /login) genelde gürültüdür."""
        counts: dict[str, int] = {}
        for h in hits:
            if h.redirect:
                counts[h.redirect] = counts.get(h.redirect, 0) + 1
        noisy = {loc for loc, n in counts.items() if n >= 10}
        return [h for h in hits if h.redirect not in noisy]

    # ------------------------------------------------------------------ ffuf
    def _log_interval(self) -> float:
        return float(self.config.dir_bruteforce.get("progress_interval", 15))

    def _scan_ffuf(self, host: LiveHost, words: list[str], label: str = "",
                   categories: dict[str, str] | None = None) -> list[DirFinding]:
        base = host.url.rstrip("/")
        if categories is None:
            categories = self.build_wordlist_map(host, self.config.target)
        rl = self.config.rate_limit
        safe = self.output._safe_name(urlsplit(base).netloc)
        wl_file = self.output.write_lines("directory_brute", f"_wordlists/{safe}.txt", words, sort=False)
        out_file = self.output.path("directory_brute", f"_ffuf/{safe}.json")
        codes = ",".join(str(c) for c in self.config.dir_bruteforce.get("match_codes") or [200, 301, 302, 403])
        args = [
            "-u", f"{base}/FUZZ",
            "-w", wl_file,
            "-rate", self.limiter.as_tool_flag(),
            "-t", rl.threads,
            "-timeout", rl.timeout,
            "-mc", codes,
            "-ac",                                   # otomatik kalibrasyon (soft-404 filtresi)
            "-noninteractive",                      # -s yok: ilerleme satırları stderr'den okunur
            "-of", "json", "-o", out_file,
            "-H", f"User-Agent: {rl.user_agent}",
            *self.config.header_flags("-H"),
        ]
        if self.config.proxy:
            args += ["-x", self.config.proxy]
        args += self.config.extra_args("ffuf")
        progress = ProgressCounter(label or base, len(words), self._log_interval())

        def on_stderr(chunk: str) -> None:
            # ffuf: ":: Progress: [1200/4700] :: Job [1/1] :: 98 req/sec :: Duration: [...] :: Errors: 0 ::"
            for done, total, errors in FFUF_PROGRESS_RE.findall(chunk):
                progress.set(int(done), int(total), int(errors))

        try:
            self.runner.run("ffuf", args, on_stderr=on_stderr)
        except ToolExecutionError as exc:
            progress.close()
            self.log.error(f"ffuf başarısız, dahili motora geçiliyor: {exc}")
            return self._scan_internal(host, words, label, categories)
        try:
            data = json.loads(out_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            progress.close()
            self.log.error(f"ffuf çıktısı okunamadı ({out_file}): {exc}")
            return []
        hits = []
        progress.found = len(data.get("results", []))
        progress.set(progress.total)
        progress.close()
        for r in data.get("results", []):
            word = (r.get("input") or {}).get("FUZZ", "")
            finding = DirFinding(
                url=r.get("url", f"{base}/{word}"), path=word, status=int(r.get("status", 0)),
                length=int(r.get("length", 0)), category=categories.get(word, "common"),
                redirect=r.get("redirectlocation", "") or "", engine="ffuf",
            )
            hits.append(finding)
        return self._drop_redirect_noise(hits)

    # ------------------------------------------------------------------ doğrulama
    def _verify(self, hits: list[DirFinding]) -> None:
        """200 dönen bilinen hassas dosyaları içerikle doğrular (az sayıda ek istek)."""
        for h in hits:
            if h.status != 200:
                continue
            sig = next((body_rx for path_rx, body_rx in VERIFY_SIGNATURES if path_rx.search(h.path)), None)
            is_archive = h.category == "backup" and re.search(r"\.(zip|tar\.gz|tgz|gz|rar|7z)$", h.path)
            if not sig and not is_archive:
                continue
            r = self.http.get(h.url, allow_redirects=False, max_bytes=VERIFY_MAX_BYTES)
            if r is None or r.status_code != 200:
                continue
            m = sig.search(r.text) if sig else None
            if m:
                h.verified = True
                # Short content proof: the matched signature in context (single line, trimmed)
                h.evidence = " ".join(m.group(0).split())[:160]
            elif is_archive and r.head.startswith(ARCHIVE_MAGIC):
                h.verified = True
                h.evidence = "Binary archive signature (ZIP/gzip/RAR/7z) in response body"

    # ------------------------------------------------------------------ kayıt
    def _save(self, hits: list[DirFinding]) -> None:
        hits.sort(key=lambda h: (not h.verified, h.url))
        self.output.write_lines("directory_brute", "found.txt", (h.to_line() for h in hits), sort=False)
        self.output.write_lines("directory_brute", "sensitive.txt",
                                (h.to_line() for h in hits if h.category in ("sensitive",) or h.category.startswith("tech:")),
                                sort=False)
        self.output.write_lines("directory_brute", "backups.txt",
                                (h.to_line() for h in hits if h.category == "backup"), sort=False)
        self.output.write_lines("directory_brute", "verified.txt",
                                (h.to_line() for h in hits if h.verified), sort=False)
        self.output.write_json("directory_brute", "findings.json", [asdict(h) for h in hits])
