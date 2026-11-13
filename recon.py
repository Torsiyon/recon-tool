#!/usr/bin/env python3
"""
Recon - Modüler keşif otomasyon aracı (YALNIZCA yazılı izniniz olan hedeflerde kullanın).

Örnekler:
    python recon.py -d example.com
    python recon.py -d example.com --rate-limit 5 --threads 5 -H "X-Bug-Bounty: kullanici"
    python recon.py -d example.com -m js dirs          # önceki çalışmanın çıktılarından devam eder
    python recon.py --targets hosts.txt                # keşfi atla; -d olmadan IP/host listesi (Direct mod)
    python recon.py --check-tools
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from core import security_checks as sec
from core.config import Config
from core.exceptions import ConfigError, ModuleError, ReconError, ToolExecutionError, ToolNotFoundError
from core.http_client import HttpClient
from core.logger import get_logger, setup_logging
from core.output_manager import OutputManager
from core.rate_limiter import RateLimiter
from core.targets import direct_label, parse_targets
from core.tool_runner import ToolRunner
from modules import MODULE_REGISTRY
from modules.base import LiveHost, ScanContext

log = get_logger("main")

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$", re.IGNORECASE)
EXTERNAL_TOOLS = ("subfinder", "httpx", "katana", "ffuf", "nmap", "nuclei")

BANNER = r"""
  ____
 |  _ \ ___  ___ ___  _ __
 | |_) / _ \/ __/ _ \| '_ \
 |  _ <  __/ (_| (_) | | | |
 |_| \_\___|\___\___/|_| |_|   v1.0  - yalnızca yetkili hedefler
"""


class ReconOrchestrator:
    """Modülleri sırayla çalıştırır; bir modülün hatası diğerlerini durdurmaz."""

    def __init__(self, config: Config) -> None:
        self.config = config
        rl = config.rate_limit
        self.output = OutputManager(config.output_dir, config.target)
        self.runner = ToolRunner(config.tools, default_timeout=config.tool_timeout)
        self.limiter = RateLimiter(rl.requests_per_second, rl.random_delay)
        self.http = HttpClient(
            self.limiter,
            timeout=rl.timeout,
            user_agent=rl.user_agent,
            headers=config.headers,
            proxy=config.proxy,
            verify_tls=rl.verify_tls,
        )
        self.ctx = ScanContext(target=config.target)
        self.results: dict[str, dict] = {}
        self._finalized = False
        self.started_at = datetime.now(timezone.utc)

    def selected_modules(self) -> list[str]:
        chosen = self.config.enabled_modules or list(MODULE_REGISTRY)
        return [m for m in MODULE_REGISTRY if m in chosen]     # her zaman pipeline sırasıyla

    # ------------------------------------------------------------------ devam etme
    def _read_json(self, rel: str):
        f = self.output.root / rel
        return json.loads(f.read_text(encoding="utf-8")) if f.is_file() else None

    def _load_previous(self, selected: list[str]) -> None:
        """Bir modül çalıştırılmayacaksa, verisini ve BULGULARINI önceki çıktılardan yükle.

        Bulgular da yüklenir; aksi halde `-m js dirs` gibi kısmi bir çalıştırma summary.json /
        report.md dosyalarını önceki port/nuclei/güvenlik bulguları olmadan (sıfırlanmış) yeniden yazardı."""
        c = self.ctx
        try:
            if "subdomains" not in selected:
                data = self._read_json("subdomains/live.json")
                if data:
                    c.live_hosts = [LiveHost(**{k: v for k, v in d.items() if k in LiveHost.__dataclass_fields__})
                                    for d in data]
                    log.info(f"Önceki çalışmadan {len(c.live_hosts)} canlı host yüklendi")
                all_txt = self.output.dirs["subdomains"] / "all.txt"
                if all_txt.is_file():
                    c.subdomains = set(all_txt.read_text(encoding="utf-8").split())
                from core.fingerprint import detect_version_disclosure
                c.findings["version_disclosure"] = [
                    {"url": h.url, **item} for h in c.live_hosts for item in detect_version_disclosure(h.headers)]
                security = self._read_json("compliance/findings.json")
                if security:
                    c.findings["security"] = security
                    c.stats["security_counts"] = sec.severity_counts(security)
            if "crawl" not in selected:
                for name, attr in (("urls/all_urls.txt", "urls"), ("js_analysis/js_files.txt", "js_files")):
                    f = self.output.root / name
                    if f.is_file():
                        setattr(c, attr, set(f.read_text(encoding="utf-8").split()))
                if c.urls or c.js_files:
                    log.info(f"Önceki çalışmadan {len(c.urls)} URL / {len(c.js_files)} JS yüklendi")
            if "ports" not in selected:
                inventory = self._read_json("ports/ports.json")
                if inventory:
                    from modules.port_scan import PortScanner
                    c.findings["ports"] = inventory
                    c.findings["port_findings"] = PortScanner.risk_findings(inventory)
            if "js" not in selected:
                js = self._read_json("js_analysis/critical.json")
                if js:
                    c.findings["js"] = js
                    c.stats["js_findings"] = {s: sum(1 for f in js if f.get("severity") == s)
                                              for s in ("HIGH", "MEDIUM", "LOW")}
            if "dirs" not in selected:
                dirs = self._read_json("directory_brute/findings.json")
                if dirs:
                    c.findings["dirs"] = dirs
                    c.stats["dir_findings"] = len(dirs)
            if "nuclei" not in selected:
                nuclei = self._read_json("nuclei/findings.json")
                if nuclei:
                    c.findings["nuclei"] = nuclei
                    c.stats["nuclei_available"] = True
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
            log.warning(f"Önceki çıktılar okunamadı, eksik kısımlar sıfırdan devam ediyor: {exc}")
        # Hiç canlı host yoksa ve keşif modülü seçilmediyse kök domaini yokla
        if not c.live_hosts and "subdomains" not in selected and {"ports", "crawl", "dirs", "nuclei"} & set(selected):
            log.warning("Canlı host verisi yok; 'subdomains' modülü de çalıştırılıyor.")
            selected.insert(0, "subdomains")

    # ------------------------------------------------------------------ çalıştırma
    def _seed_targets(self, targets: list[str], selected: list[str]) -> None:
        """--targets: keşfi atla, verilen hostları doğrudan canlı host olarak yokla.

        -d verilmişse hedefler o domainin kapsamıyla süzülür. -d verilmemişse (Direct mod) kapsam
        tam olarak dosyadaki host/IP'lerdir — web arayüzündeki Direct modla aynı davranış."""
        from modules.subdomain_recon import SubdomainRecon
        hosts = set(parse_targets("\n".join(targets)))
        if self.config.direct:
            self.ctx.scope_hosts = set(hosts)
        in_scope = {h for h in hosts if self.ctx.in_scope(h)}
        dropped = hosts - in_scope
        if dropped:
            log.warning(f"Kapsam dışı {len(dropped)} hedef elendi: {', '.join(sorted(dropped))}")
        if not in_scope:
            raise ConfigError("--targets dosyasında kapsam içi geçerli hedef (host/IP) yok")
        if "subdomains" in selected:
            selected.remove("subdomains")   # keşif atlanıyor; yoklama aşağıda yapılır
        log.info(f"--targets: {len(in_scope)} hedef yoklanıyor (keşif atlandı)")
        self.ctx.subdomains = set(in_scope)
        module = SubdomainRecon(self.config, self.output, self.runner, self.limiter, self.http)
        try:
            module.probe_and_record(self.ctx, in_scope)
        except ReconError:
            raise
        except Exception:
            log.exception("Hedef yoklama hatası")

    def run(self) -> bool:
        self.output.prepare()
        selected = self.selected_modules()
        if getattr(self.config, "seed_targets", None):
            self._seed_targets(self.config.seed_targets, selected)
        else:
            self._load_previous(selected)
        rl = self.config.rate_limit
        log.info(f"Hedef: {self.config.target} | modüller: {', '.join(selected)} | "
                 f"rate: {self.limiter.rps:g}/s | threads: {rl.threads} | timeout: {rl.timeout}s")
        tools = {t: self.runner.is_available(t) for t in EXTERNAL_TOOLS}
        log.info("Harici araçlar: " + ", ".join(f"{t}={'var' if ok else 'yok'}" for t, ok in tools.items()))

        for name in selected:
            module = MODULE_REGISTRY[name](self.config, self.output, self.runner, self.limiter, self.http)
            missing = module.check_requirements()
            if missing:
                log.warning(f"[{name}] atlandı, eksik araç(lar): {', '.join(missing)}")
                self.results[name] = {"status": "skipped", "reason": f"eksik: {', '.join(missing)}"}
                continue

            started = time.monotonic()
            log.info(f"[{name}] başlıyor: {module.description}")
            status, reason = "ok", ""
            try:
                module.run(self.ctx)
            except (ToolNotFoundError, ToolExecutionError) as exc:
                status, reason = "failed", f"harici araç hatası: {exc}"
            except (ModuleError, ReconError) as exc:
                status, reason = "failed", f"modül hatası: {exc}"
            except KeyboardInterrupt:
                self.results[name] = {"status": "interrupted", "seconds": round(time.monotonic() - started, 1)}
                self._finalize()
                raise
            except Exception as exc:  # beklenmeyen hata: tüm taramayı düşürme, logla ve devam et
                log.exception(f"[{name}] beklenmeyen hata")
                status, reason = "failed", f"beklenmeyen hata: {exc!r}"
            if reason:
                log.error(f"[{name}] {reason}")
            elapsed = round(time.monotonic() - started, 1)
            self.results[name] = {"status": status, "seconds": elapsed, **({"reason": reason} if reason else {})}
            log.info(f"[{name}] bitti: {status} ({elapsed}s)")

        self._finalize()
        return all(r["status"] != "failed" for r in self.results.values())

    # ------------------------------------------------------------------ Modül E: özet
    def unified_findings(self) -> list[dict]:
        """Tüm modüllerin bulguları tek, önem sırasına göre dizilmiş listede (arayüzdeki tabloyla aynı)."""
        c = self.ctx
        base = (c.findings.get("security", []) + c.findings.get("port_findings", [])
                + c.findings.get("nuclei", []))
        return sec.merge_findings(base, c.findings.get("js", []), c.findings.get("dirs", []))

    def _finalize(self) -> None:
        if self._finalized:
            return
        self._finalized = True
        try:
            unified = self.unified_findings()
            summary = self._build_summary(unified)
            self.output.write_json("root", "summary.json", summary)
            self.output.write_text("root", "report.md", self._build_report(summary, unified))
            self.output.write_json("root", "findings.json", unified)
            self.output.write_text("root", "findings.md", sec.findings_to_markdown(unified, self.config.target))
        except ReconError as exc:
            log.error(f"Özet yazılamadı: {exc}")
        self._print_summary()

    @staticmethod
    def _redact_proxy(proxy: str | None) -> str | None:
        """Proxy URL'sindeki kullanıcı:parola kısmını özet dosyasına (ve indirilen .zip'e) yazma."""
        return re.sub(r"(?<=://)[^/@]+@", "***@", proxy) if proxy else proxy

    def _build_summary(self, unified: list[dict] | None = None) -> dict:
        c = self.ctx
        unified = self.unified_findings() if unified is None else unified
        return {
            "target": self.config.target,
            "started_at": self.started_at.isoformat(timespec="seconds"),
            "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "settings": {
                "rate_limit_rps": self.config.rate_limit.requests_per_second,
                "final_rps": self.limiter.rps,
                "threads": self.config.rate_limit.threads,
                "timeout": self.config.rate_limit.timeout,
                "proxy": self._redact_proxy(self.config.proxy),
                "custom_headers": list(self.config.headers),
            },
            "modules": self.results,
            "engines": {k: v for k, v in c.stats.items() if k.endswith("_engine")},
            "counts": {
                "subdomains": len(c.subdomains),
                "live_hosts": len(c.live_hosts),
                "urls": len(c.urls),
                "js_files": len(c.js_files),
                "js_findings": c.stats.get("js_findings", {}),
                "js_endpoint_urls": c.stats.get("js_endpoint_urls", 0),
                "dir_findings": c.stats.get("dir_findings", 0),
                "dir_verified": sum(1 for f in c.findings.get("dirs", []) if f.get("verified")),
                "version_disclosure": len(c.findings.get("version_disclosure", [])),
                "security_findings": len(c.findings.get("security", [])),
                "security_counts": c.stats.get("security_counts", {}),
                "overall_findings": len(unified),
                "overall_counts": sec.severity_counts(unified),
                "open_ports": len(c.findings.get("ports", [])),
                "nuclei_findings": len(c.findings.get("nuclei", [])),
                "nuclei_available": c.stats.get("nuclei_available", False),
            },
        }

    def _build_report(self, s: dict, unified: list[dict] | None = None) -> str:
        c = self.ctx
        unified = self.unified_findings() if unified is None else unified
        lines = [f"# Recon report: {s['target']}", "",
                 f"- Start: {s['started_at']}  End: {s['finished_at']}",
                 f"- Rate limit: {s['settings']['rate_limit_rps']} req/s (final: {s['settings']['final_rps']:g})", "",
                 "## Modules", "", "| Module | Status | Time (s) | Note |", "|---|---|---|---|"]
        for name, r in s["modules"].items():
            lines.append(f"| {name} | {r['status']} | {r.get('seconds', '-')} | {r.get('reason', '')} |")
        n = s["counts"]
        lines += ["", "## Counts", "",
                  f"- Findings: {n.get('overall_findings', 0)}",
                  f"- Subdomains: {n['subdomains']}, live hosts: {n['live_hosts']}",
                  f"- URLs: {n['urls']}, JS files: {n['js_files']}",
                  f"- JS findings: {n['js_findings'] or 0}",
                  f"- Directory findings: {n['dir_findings']} (verified: {n['dir_verified']})",
                  f"- Version/banner disclosure: {n['version_disclosure']}", ""]
        _sec = sec
        # Unified findings: header/TLS/takeover/version + port + nuclei + JS secrets + file exposures
        allf = unified
        if allf:
            counts = _sec.severity_counts(allf)
            lines += ["## Security and vulnerability findings", "",
                      "- " + " · ".join(f"{k}: {counts.get(k, 0)}" for k in _sec.SEVERITIES), "",
                      "| Severity | CVSS | Category | Target | Finding |", "|---|---|---|---|---|"]
            for f in allf[:150]:
                title = str(f.get("title", "")).replace("|", "/")
                cvss = f.get("cvss", "")
                lines.append(f"| {f['severity']} | {cvss} | {f.get('category')} | {f.get('target')} | {title} |")
            if len(allf) > 150:
                lines.append(f"\n_{len(allf) - 150} more — see `findings.md` / `findings.json` for the full list._")
            lines.append("")
        ports = c.findings.get("ports", [])
        if ports:
            lines += ["## Open ports", "", "| Host | Port | Service |", "|---|---|---|"]
            for p in ports[:150]:
                lines.append(f"| {p.get('host')} | {p.get('port')} | {p.get('service')} |")
            lines.append("")
        if c.live_hosts:
            lines += ["## Live hosts", "", "| URL | Code | Title | Technologies |", "|---|---|---|---|"]
            for h in c.live_hosts[:200]:
                title = (h.title or "").replace("|", "/")[:60]
                lines.append(f"| {h.url} | {h.status_code} | {title} | {', '.join(h.technologies)} |")
            lines.append("")
        high = [f for f in c.findings.get("js", []) if f["severity"] == "HIGH"]
        if high:
            lines += ["## JS: high-severity findings", ""]
            lines += [f"- `{f['rule']}` {f['url']}:{f['line_no']}" for f in high[:50]]
            lines.append("")
        vleaks = c.findings.get("version_disclosure", [])
        if vleaks:
            lines += ["## Version / banner disclosure", ""]
            lines += [f"- {v['url']} — `{v['header']}: {v['value']}`" for v in vleaks[:50]]
            lines.append("")
        verified = [f for f in c.findings.get("dirs", []) if f.get("verified")]
        if verified:
            lines += ["## Verified file exposures", ""]
            lines += [f"- {f['status']} {f['url']}" + (f" — proof: `{f.get('evidence')}`" if f.get('evidence') else "")
                      for f in verified[:50]]
            lines.append("")
        lines += ["## Files", "", "- `findings.md`, `findings.json` unified, severity-ranked findings",
                  "- `subdomains/` live.txt, dead.txt, live.json, by_tech.txt",
                  "- `urls/` all_urls.txt, parameterized.txt, parameterized_unique.txt, params.txt",
                  "- `js_analysis/` critical.txt, critical.json, js_files.txt, endpoints.txt",
                  "- `directory_brute/` found.txt, sensitive.txt, backups.txt, verified.txt, findings.json",
                  "- `compliance/` version_disclosure.txt, findings.txt, findings.json",
                  "- `ports/` open_ports.txt, ports.json",
                  "- `nuclei/` findings.txt, findings.json", ""]
        return "\n".join(lines)

    def _print_summary(self) -> None:
        c = self.ctx
        log.info("=" * 60)
        for name, r in self.results.items():
            log.info(f"  {name:<12} {r['status']:<10} {r.get('seconds', '')}")
        log.info(f"  subdomain: {len(c.subdomains)} | canlı: {len(c.live_hosts)} | "
                 f"url: {len(c.urls)} | js: {len(c.js_files)}")
        log.info(f"  JS bulguları: {c.stats.get('js_findings', {})} | dizin bulguları: {c.stats.get('dir_findings', 0)}")
        log.info(f"  Çıktılar: {self.output.root}  (özet: report.md)")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="recon.py",
        description="Modular recon automation tool (subfinder, httpx, katana, ffuf, nmap, nuclei orchestration).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-d", "--domain", help="Target root domain (e.g. example.com). Optional with --targets "
                                          "(direct mode: scope = exactly the listed hosts/IPs)")
    p.add_argument("-m", "--modules", nargs="+", choices=list(MODULE_REGISTRY),
                   help="Modules to run (default: all)")
    g = p.add_argument_group("rate and safety (Module D)")
    g.add_argument("--rate-limit", type=float, help="Maximum requests per second (RPS), for all modules")
    g.add_argument("--threads", type=int, help="Number of concurrent workers")
    g.add_argument("--timeout", type=int, help="Request timeout (seconds)")
    g.add_argument("--jitter", type=float, nargs=2, metavar=("MIN", "MAX"),
                   help="Extra random delay between requests (seconds)")
    g.add_argument("-H", "--header", action="append", dest="headers", metavar="'Name: Value'",
                   help="Header added to all requests (repeatable)")
    g.add_argument("--proxy", help="HTTP/SOCKS5 proxy (e.g. http://127.0.0.1:8080)")
    t = p.add_argument_group("scan")
    t.add_argument("--subs", help="Existing subdomain list (merged with subfinder results)")
    t.add_argument("--targets", help="SKIP discovery: scan the hosts/IPs in this file directly (one per line). "
                                     "Without -d the scope is exactly these targets (IPs allowed).")
    t.add_argument("--depth", type=int, dest="crawl_depth", help="Crawling depth")
    t.add_argument("-w", "--wordlist", help="Extra wordlist added to the directory scan (e.g. SecLists)")
    t.add_argument("--dir-engine", choices=["auto", "internal", "ffuf"], help="Directory scan engine")
    o = p.add_argument_group("output")
    o.add_argument("-o", "--output-dir", help="Output root directory (default: outputs)")
    o.add_argument("-c", "--config", type=Path, help="Alternative settings.yaml path")
    o.add_argument("-v", "--verbose", action="store_true", help="Log at DEBUG level")
    p.add_argument("--check-tools", action="store_true", help="Show whether external tools are installed and exit")
    args = p.parse_args(argv)
    if not args.domain and not args.check_tools and not args.targets:
        p.error("-d/--domain gerekli (ya da --targets ile Direct mod)")
    return args


def normalize_domain(raw: str) -> str:
    domain = raw.strip().lower()
    domain = re.sub(r"^[a-z]+://", "", domain).split("/")[0].split(":")[0].strip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    if not DOMAIN_RE.match(domain):
        raise ConfigError(f"Geçersiz domain: {raw!r}")
    return domain


def check_tools(config_path: Path | None) -> int:
    try:
        cfg = Config.load("example.com", config_path=config_path)
        runner = ToolRunner(cfg.tools)
    except ConfigError as exc:
        log.error(str(exc))
        return 2
    for t in EXTERNAL_TOOLS:
        try:
            log.info(f"  {t:<10} OK  {runner.resolve(t)}")
        except ToolNotFoundError:
            note = {"subfinder": "yalnızca kök domain taranır",
                    "nuclei": "zafiyet taraması aşaması atlanır"}.get(t, "dahili motor kullanılacak")
            log.warning(f"  {t:<10} YOK ({note})")
    return 0


def _install_signal_handlers() -> None:
    """docker stop SIGTERM gönderir; Ctrl+C ile aynı yoldan geçsin ki kısmi çıktı ve özet yazılsın."""
    def _handler(signum, _frame):
        raise KeyboardInterrupt(f"sinyal {signum}")
    try:
        signal.signal(signal.SIGTERM, _handler)
    except (ValueError, OSError):  # ana thread dışı / desteklenmeyen platform
        pass


def main(argv: list[str] | None = None) -> int:
    # Windows konsolu / dosyaya yönlendirme UTF-8 değilse (ör. cp1254) yazdırılamayan bir karakter
    # taramayı UnicodeEncodeError ile düşürmesin.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
    args = parse_args(argv)
    _install_signal_handlers()
    setup_logging("DEBUG" if args.verbose else "INFO")
    print(BANNER)
    if args.check_tools:
        return check_tools(args.config)
    try:
        seed_targets = None
        if args.targets:
            tp = Path(args.targets)
            if not tp.is_file():
                raise ConfigError(f"--targets dosyası bulunamadı: {tp}")
            seed_targets = parse_targets(tp.read_text(encoding="utf-8", errors="replace"))
            if not seed_targets:
                raise ConfigError(f"--targets dosyasında geçerli hedef (host/IP) yok: {tp}")
            if not args.modules:
                args.modules = ["crawl", "js", "dirs"]   # keşfi atla, kalan aşamalar
        direct = bool(seed_targets) and not args.domain
        # Direct mod: domain yok; çıktı klasörü ilk hedefin adını alır
        target = direct_label(seed_targets[0]) if direct else normalize_domain(args.domain)
        config = Config.load(
            target,
            config_path=args.config,
            overrides={
                "rate_limit": args.rate_limit,
                "threads": args.threads,
                "timeout": args.timeout,
                "jitter": args.jitter,
                "headers": args.headers,
                "proxy": args.proxy,
                "wordlist": args.wordlist,
                "dir_engine": args.dir_engine,
                "subs": args.subs,
                "crawl_depth": args.crawl_depth,
                "output_dir": args.output_dir,
                "log_level": "DEBUG" if args.verbose else None,
                "modules": args.modules,
            },
        )
        if seed_targets is not None:
            config.seed_targets = seed_targets
            config.direct = direct
        if not args.verbose:   # settings.yaml > general.log_level (önceden hiç uygulanmıyordu)
            logging.getLogger().setLevel(str(config.log_level).upper())
        ok = ReconOrchestrator(config).run()
        return 0 if ok else 1
    except ConfigError as exc:
        log.error(f"Konfigürasyon hatası: {exc}")
        return 2
    except KeyboardInterrupt:
        log.warning("Kullanıcı tarafından durduruldu (Ctrl+C). O ana kadarki çıktılar ve özet kaydedildi.")
        return 130
    except ReconError as exc:
        log.error(f"Kritik hata: {exc}")
        return 1
    except Exception:
        log.exception("Beklenmeyen kritik hata")
        return 1


if __name__ == "__main__":
    sys.exit(main())
