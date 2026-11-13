"""Modül B (1/2): katana ile endpoint ve JS dosyası toplama (katana yoksa dahili crawler).

Çıktılar (outputs/<hedef>/urls/):
  all_urls.txt             kapsam içindeki tüm URL'ler
  parameterized.txt        parametre içeren tüm URL'ler
  parameterized_unique.txt aynı path + aynı parametre adları için tek temsilci (fuzzing için)
  params.txt               görülen parametre adları
  by_host/<host>.txt       host bazında URL listesi
  (+ js_analysis/js_files.txt)
"""
from __future__ import annotations

import re
from collections import deque
from urllib.parse import parse_qsl, urldefrag, urljoin, urlsplit

from core.exceptions import ToolExecutionError
from modules.base import BaseModule, ScanContext

LINK_RE = re.compile(r"""(?:href|src|action|data-src)\s*=\s*["']([^"'<>\s]+)["']""", re.I)
ABS_URL_RE = re.compile(r"""https?://[^\s"'<>\\)]+""", re.I)
SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
ROBOTS_RE = re.compile(r"^(?:dis)?allow:\s*(\S+)", re.I | re.M)


def is_js(url: str) -> bool:
    return urlsplit(url).path.lower().endswith((".js", ".mjs", ".jsx"))


def save_url_inventory(output, ctx: ScanContext) -> None:
    """ctx.urls / ctx.js_files içeriğini urls/ ve js_analysis/js_files.txt dosyalarına yazar.
    Crawler'dan sonra JS analizi yeni URL eklediğinde de çağrılır (dosyalar güncel kalsın)."""
    params_urls = {u for u in ctx.urls if urlsplit(u).query}
    unique: dict[tuple, str] = {}
    param_names: set[str] = set()
    for u in sorted(params_urls):
        parts = urlsplit(u)
        names = tuple(sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)}))
        param_names |= set(names)
        unique.setdefault((parts.scheme, parts.netloc, parts.path, names), u)

    output.write_lines("urls", "all_urls.txt", ctx.urls)
    output.write_lines("urls", "parameterized.txt", params_urls)
    output.write_lines("urls", "parameterized_unique.txt", unique.values())
    output.write_lines("urls", "params.txt", param_names)
    by_host: dict[str, list[str]] = {}
    for u in ctx.urls:
        by_host.setdefault(urlsplit(u).hostname or "unknown", []).append(u)
    for host, urls in by_host.items():
        output.write_lines("urls", f"by_host/{output._safe_name(host)}.txt", urls)
    output.write_lines("js_analysis", "js_files.txt", ctx.js_files)


class Crawler(BaseModule):
    name = "crawl"
    description = "katana: endpoint, parametreli URL ve JS dosyası toplama"
    optional_tools = ("katana",)

    def run(self, ctx: ScanContext) -> None:
        if not ctx.live_hosts:
            self.log.warning("Canlı host yok, crawling atlandı.")
            return
        seeds = [h.url for h in ctx.live_hosts]
        engine = self.choose_engine(self.config.crawler.get("engine"), "katana")
        self.log.info(f"Crawling motoru: {engine} ({len(seeds)} host)")
        urls = self._crawl_katana(seeds, ctx) if engine == "katana" else self._crawl_internal(seeds, ctx)
        urls = {self._normalize(u) for u in urls}
        urls = {u for u in urls if u and ctx.in_scope(u) and not self._excluded(u)}
        ctx.urls |= urls | set(seeds)
        ctx.js_files |= {u for u in ctx.urls if is_js(u)}
        ctx.stats["crawl_engine"] = engine
        self.log.info(f"{len(ctx.urls)} URL, {len(ctx.js_files)} JS dosyası")
        self._save(ctx)

    # ------------------------------------------------------------------ yardımcılar
    @staticmethod
    def _normalize(url: str) -> str:
        url = urldefrag(url.strip())[0]
        return url if url.lower().startswith(("http://", "https://")) else ""

    def _excluded(self, url: str) -> bool:
        suffixes = getattr(self, "_excl_suffixes", None)
        if suffixes is None:    # bir kez hesapla: her link için listeyi yeniden kurma
            exts = self.config.crawler.get("exclude_extensions") or []
            suffixes = self._excl_suffixes = tuple("." + str(e).lower().lstrip(".") for e in exts)
        return bool(suffixes) and urlsplit(url).path.lower().endswith(suffixes)

    # ------------------------------------------------------------------ katana
    def _crawl_katana(self, seeds: list[str], ctx: ScanContext | None = None) -> set[str]:
        cfg, rl = self.config.crawler, self.config.rate_limit
        seed_file = self.output.write_lines("urls", "_katana_input.txt", seeds)
        args = [
            "-list", seed_file,
            "-d", int(cfg.get("depth", 3)),
            "-silent", "-nc",
            "-rl", self.limiter.as_tool_flag(),
            "-c", rl.threads,
            "-p", 1,                                   # hostlar sırayla: toplam RPS sınırı korunur
            "-timeout", rl.timeout,
            "-fs", "rdn",                              # kapsam: kök domain
            "-H", f"User-Agent: {rl.user_agent}",
            *self.config.header_flags("-H"),
        ]
        if cfg.get("js_crawl", True):
            args.append("-jc")
        if cfg.get("known_files", True):
            args += ["-kf", "all"]
        exts = cfg.get("exclude_extensions") or []
        if exts:
            args += ["-ef", ",".join(exts)]
        if self.config.proxy:
            args += ["-proxy", self.config.proxy]
        args += self.config.extra_args("katana")
        try:
            res = self.runner.run("katana", args)
        except ToolExecutionError as exc:
            self.log.error(f"katana başarısız, dahili crawler'a geçiliyor: {exc}")
            return self._crawl_internal(seeds, ctx)   # ctx: Direct moddaki kapsam (scope_hosts) korunur
        return {l.strip() for l in res.stdout.splitlines() if l.strip().startswith("http")}

    # ------------------------------------------------------------------ dahili
    def _crawl_internal(self, seeds: list[str], ctx: ScanContext | None) -> set[str]:
        scope = ctx or ScanContext(target=self.config.target)
        found: set[str] = set()
        for seed, urls, exc in self.parallel(lambda s: self._crawl_host(s, scope), seeds):
            if exc:
                self.log.error(f"{seed} taranırken hata: {exc}")
            else:
                found |= urls
        return found

    def _crawl_host(self, seed: str, scope: ScanContext) -> set[str]:
        cfg = self.config.crawler
        max_depth = int(cfg.get("depth", 3))
        budget = int(cfg.get("max_pages_per_host", 300))
        seen: set[str] = set()
        found: set[str] = {seed}
        seed_netloc = urlsplit(seed).netloc
        queue: deque[tuple[str, int]] = deque([(seed, 0)])
        if cfg.get("known_files", True):
            for extra in ("/robots.txt", "/sitemap.xml"):
                queue.append((urljoin(seed + "/", extra), max_depth))

        while queue and len(seen) < budget:
            url, depth = queue.popleft()
            if url in seen:
                continue
            seen.add(url)
            resp = self.http.get(url, allow_redirects=False)
            if resp is None:
                continue
            links: set[str] = set()
            loc = resp.headers.get("Location") or resp.headers.get("location")
            if loc:
                links.add(urljoin(url, loc))
            ctype = resp.headers.get("Content-Type", "").lower()
            path = urlsplit(url).path.lower()
            if path.endswith("robots.txt") and resp.status_code == 200:
                links |= {urljoin(url, p.replace("*", "")) for p in ROBOTS_RE.findall(resp.text)}
            elif path.endswith(".xml") and resp.status_code == 200:
                links |= set(SITEMAP_LOC_RE.findall(resp.text))
            elif "html" in ctype or "javascript" in ctype:
                links |= {urljoin(url, l) for l in LINK_RE.findall(resp.text)}
                links |= set(ABS_URL_RE.findall(resp.text))

            for link in links:
                link = self._normalize(link)
                if not link or not scope.in_scope(link) or self._excluded(link):
                    continue
                found.add(link)
                # Yalnızca aynı host içinde derinleş; JS dosyaları JS modülünde indirilir
                if (depth + 1 <= max_depth and link not in seen and not is_js(link)
                        and urlsplit(link).netloc == seed_netloc):
                    queue.append((link, depth + 1))
        return found

    # ------------------------------------------------------------------ kayıt
    def _save(self, ctx: ScanContext) -> None:
        save_url_inventory(self.output, ctx)
