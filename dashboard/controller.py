"""ScanController: recon modüllerini web arayüzü için ADIM ADIM yürütür.

Streamlit'ten bağımsızdır (import etmez), böylece ayrıca birim test edilebilir.
Her modül ayrı bir arka plan iş parçacığında çalışır; bulgular thread-safe bir kuyruğa
'olay' olarak düşer. Arayüz kuyruğu boşaltıp canlı tablo/grafik çizer.

Adım akışı:
    subdomains  -> (kullanıcı canlı hostları seçer: dinamik kapsam)
    crawl       -> yalnızca seçili hostlarda
    js          -> toplanan JS dosyalarında
    dirs        -> yalnızca seçili hostlarda
"""
from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core import targets
from core.config import Config
from core.exceptions import ScanCancelled
from core.http_client import HttpClient
from core.output_manager import OutputManager
from core.rate_limiter import RateLimiter
from core.targets import HOST_RE, IPV4_RE   # noqa: F401  (geriye uyumlu dışa aktarım)
from core.tool_runner import ToolRunner
from modules import MODULE_REGISTRY
from modules.base import LiveHost, ScanContext   # noqa: F401
from modules.subdomain_recon import SubdomainRecon

# Arayüzde gösterilecek modül sırası ve etiketleri
STEP_ORDER = ["subdomains", "ports", "crawl", "js", "dirs", "nuclei"]
STEP_LABELS = {
    "subdomains": "Discovery · subdomain & liveness",
    "ports": "Ports · port & service scan",
    "crawl": "Crawl · URL & JS collection",
    "js": "Secrets · JS secret analysis",
    "dirs": "Content · directory & file discovery",
    "nuclei": "Vuln · Nuclei CVE scan",
}


@dataclass
class ModuleRun:
    """Tek bir modül çalıştırmasının durumu."""
    name: str
    thread: threading.Thread
    started_at: float
    status: str = "running"            # running | ok | failed | cancelled
    error: str = ""
    log_lines: list[str] = field(default_factory=list)
    finished_at: float | None = None

    @property
    def seconds(self) -> float:
        """Modülün gerçek çalışma süresi (bitmediyse şu ana kadar geçen süre)."""
        return round((self.finished_at or time.monotonic()) - self.started_at, 1)


class ScanController:
    """Bir hedef için tüm tarama oturumunu yönetir."""

    def __init__(self, config: Config) -> None:
        self.config = config
        rl = config.rate_limit
        self.output = OutputManager(config.output_dir, config.target)
        self.output.prepare()
        self.runner = ToolRunner(config.tools, default_timeout=config.tool_timeout)
        self.limiter = RateLimiter(rl.requests_per_second, rl.random_delay)
        self.http = HttpClient(self.limiter, timeout=rl.timeout, user_agent=rl.user_agent,
                               headers=config.headers, proxy=config.proxy, verify_tls=rl.verify_tls)
        self.events: "queue.Queue[tuple[str, dict]]" = queue.Queue()
        self.ctx = ScanContext(target=config.target, event_hook=self._on_event)
        self.runs: dict[str, ModuleRun] = {}
        self._completed: list[str] = []
        self.started_at = datetime.now(timezone.utc)
        self.cancelled = False

    # ------------------------------------------------------------------ durdurma
    def cancel(self) -> None:
        """Taramayı durdurur: bekleyen tüm HTTP istekleri iptal edilir, çalışan harici araç
        (nmap/nuclei/ffuf...) öldürülür. Arka plandaki modül iş parçacığı kısa sürede 'cancelled'
        durumuyla biter. Oturum bundan sonra yeni modül başlatamaz (yalnızca rapor yazılabilir)."""
        self.cancelled = True
        self.limiter.cancel()
        self.runner.cancel()

    def _execute(self, run: ModuleRun, fn) -> None:
        """Modül iş parçacığının ortak gövdesi: durum, hata, süre ve 'module_done' olayı."""
        try:
            fn()
            run.status = "cancelled" if self.cancelled else "ok"
        except ScanCancelled:
            run.status = "cancelled"
        except Exception as exc:  # modül hatası oturumu düşürmesin
            run.status = "cancelled" if self.cancelled else "failed"
            run.error = "" if self.cancelled else f"{type(exc).__name__}: {exc}"
        finally:
            run.finished_at = time.monotonic()
            self.events.put(("module_done", {"name": run.name, "status": run.status, "error": run.error}))

    # ------------------------------------------------------------------ olaylar
    def _on_event(self, kind: str, payload: dict) -> None:
        """Modül iş parçacığından çağrılır (Streamlit API'si ASLA burada kullanılmaz)."""
        self.events.put((kind, payload))

    def drain_events(self, limit: int = 2000) -> list[tuple[str, dict]]:
        """Kuyruktaki olayları toplar (arayüz her yenilemede çağırır)."""
        out: list[tuple[str, dict]] = []
        for _ in range(limit):
            try:
                out.append(self.events.get_nowait())
            except queue.Empty:
                break
        return out

    # ------------------------------------------------------------------ araç durumu
    def tool_status(self) -> dict[str, bool]:
        return {t: self.runner.is_available(t)
                for t in ("subfinder", "httpx", "katana", "ffuf", "nmap", "nuclei")}

    # ------------------------------------------------------------------ dinamik kapsam
    def set_scope(self, selected_urls: list[str]) -> int:
        """Kullanıcının seçtiği canlı hostlar dışındakileri kapsamdan çıkarır.
        Sonraki crawl/dirs modülleri yalnızca bunları görür."""
        keep = {u.rstrip("/") for u in selected_urls}
        self.ctx.live_hosts = [h for h in self.ctx.live_hosts if h.url.rstrip("/") in keep]
        return len(self.ctx.live_hosts)

    # ------------------------------------------------------------------ modül çalıştırma
    def is_running(self) -> bool:
        return any(r.status == "running" for r in self.runs.values())

    @staticmethod
    def parse_targets(raw: str) -> list[str]:
        """Metin kutusundan host listesi: URL/scheme/port ayıklanır, geçerli host/IP'ler döner.
        Hem domain/subdomain hem de IPv4 adresleri kabul edilir (Direct mod IP listesi desteği)."""
        return targets.parse_targets(raw)

    def start_seed(self, raw_targets: str) -> tuple[ModuleRun, list[str]]:
        """Keşfi atla (Direct mod): kullanıcının girdiği hedefleri yoklayıp canlı host olarak ekler.
        Ana domain zorunlu değildir; kapsam = tam olarak girilen hedefler (her biri tek tek).
        Girilenler host/IP olarak geçerli değilse (dropped) elenir."""
        if self.is_running():
            raise RuntimeError("Zaten çalışan bir modül var")
        hosts = self.parse_targets(raw_targets)
        # Direct modda kapsamı girilen hedeflerle sınırla: hiçbiri "domain dışı" diye elenmez.
        self.ctx.scope_hosts = set(hosts)
        dropped: list[str] = []   # yalnızca geçersiz (parse edilemeyen) satırlar parse_targets'ta düşer
        self.ctx.subdomains = set(hosts)
        module = SubdomainRecon(self.config, self.output, self.runner, self.limiter, self.http)
        run = ModuleRun(name="subdomains", thread=None, started_at=time.monotonic())  # type: ignore[arg-type]

        def job() -> None:
            if not hosts:
                raise ValueError("No valid target (enter at least one host or IP).")
            module.probe_and_record(self.ctx, set(hosts))

        run.thread = threading.Thread(target=self._execute, args=(run, job), name="recon-seed", daemon=True)
        self.runs["subdomains"] = run
        run.thread.start()
        return run, dropped

    def start_module(self, name: str) -> ModuleRun:
        if name not in MODULE_REGISTRY:
            raise ValueError(f"Bilinmeyen modül: {name}")
        if self.is_running():
            raise RuntimeError("Zaten çalışan bir modül var")
        if self.cancelled:
            raise RuntimeError("Tarama durduruldu; yeni bir tarama başlatın")

        module = MODULE_REGISTRY[name](self.config, self.output, self.runner, self.limiter, self.http)
        run = ModuleRun(name=name, thread=None, started_at=time.monotonic())  # type: ignore[arg-type]

        def job() -> None:
            missing = module.check_requirements()
            if missing:
                run.log_lines.append(f"Uyarı: eksik araç(lar): {', '.join(missing)} — atlanıyor")
                return
            module.run(self.ctx)

        run.thread = threading.Thread(target=self._execute, args=(run, job), name=f"recon-{name}", daemon=True)
        self.runs[name] = run
        run.thread.start()
        return run

    def mark_completed(self, name: str) -> None:
        if name not in self._completed:
            self._completed.append(name)

    def completed_steps(self) -> list[str]:
        return list(self._completed)

    # ------------------------------------------------------------------ summary stats
    def module_summary(self, name: str) -> dict[str, Any]:
        """Summary statistics shown in the UI when a module finishes."""
        c = self.ctx
        if name == "subdomains":
            found = len(c.subdomains)
            live = len(c.live_hosts)
            return {"subdomains found": found, "live": live,
                    "unresponsive": max(0, found - live),
                    "security findings": len(c.findings.get("security", []))}
        if name == "ports":
            inv = c.findings.get("ports", [])
            return {"open ports": len(inv),
                    "hosts": len({r["host"] for r in inv}),
                    "risky services": len(c.findings.get("port_findings", []))}
        if name == "crawl":
            params = sum(1 for u in c.urls if "?" in u and "=" in u)
            return {"URLs": len(c.urls), "URLs with params": params, "JS files": len(c.js_files)}
        if name == "nuclei":
            f = c.findings.get("nuclei", [])
            if not c.stats.get("nuclei_available", True):
                return {"nuclei": "absent (skipped)"}
            counts = {s: sum(1 for x in f if x.get("severity") == s) for s in ("CRITICAL", "HIGH", "MEDIUM")}
            return {"vulns": len(f), **counts}
        if name == "js":
            f = c.findings.get("js", [])
            sev = {s: sum(1 for x in f if x.get("severity") == s) for s in ("HIGH", "MEDIUM", "LOW")}
            return {"JS findings": len(f), **sev, "new URLs from JS": c.stats.get("js_endpoint_urls", 0)}
        if name == "dirs":
            d = c.findings.get("dirs", [])
            return {"directory findings": len(d),
                    "403": sum(1 for x in d if x.get("status") == 403),
                    "verified": sum(1 for x in d if x.get("verified"))}
        return {}

    def write_reports(self) -> Path:
        """Oturum bitince CLI ile aynı summary.json / report.md / findings.* dosyalarını yazar."""
        from recon import ReconOrchestrator
        orch = ReconOrchestrator.__new__(ReconOrchestrator)
        orch.config = self.config
        orch.output = self.output
        orch.limiter = self.limiter
        orch.ctx = self.ctx
        orch.results = {n: {"status": r.status, "seconds": r.seconds, **({"reason": r.error} if r.error else {})}
                        for n, r in self.runs.items()}
        orch.started_at = self.started_at     # gerçek başlangıç (önceden rapor anı yazılıyordu)
        orch._finalized = False
        orch._finalize()
        return self.output.root
