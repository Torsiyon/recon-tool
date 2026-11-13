"""Motor davranışı testleri: yerel (127.0.0.1, rastgele port) bir HTTP sunucusuna karşı uçtan uca
modül çalıştırmaları + hız sınırlayıcı, iptal, araç çalıştırıcı ve devam etme (resume) senaryoları.
Dış ağa hiçbir istek atılmaz; /etc/hosts ya da root gerekmez."""
import http.server
import json
import socketserver
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from core.config import Config
from core.exceptions import ConfigError, ScanCancelled, ToolExecutionError
from core.http_client import HttpClient
from core.output_manager import OutputManager
from core.rate_limiter import RateLimiter
from core.tool_runner import ToolRunner
from modules.base import LiveHost, ScanContext
from modules.crawler import Crawler
from modules.dir_bruteforce import DirBruteforcer
from modules.js_analyzer import JSAnalyzer

BIG_ZIP = b"PK\x03\x04" + b"\0" * (600 * 1024)        # 600 KB "yedek": tamamı indirilmemeli
FILES = {
    "/": ("text/html", b"<html><title>Lab</title><script src='/static/app.js'></script>"
                       b"<a href='/index.php?id=1&cat=2'>a</a><a href='/about/'>b</a></html>"),
    "/about/": ("text/html", b"<html><a href='/contact.php?ref=about'>c</a></html>"),
    "/static/app.js": ("application/javascript",
                       b'var cfg={apiKey:"AIzaSyA1234567890abcdefghijklmnopqrstuv"};fetch("/api/v2/users");'
                       b'load("/static/chunk.lazy.js");go("shop/search.php?q=1");x("https://other.example.org/y");'),
    # Hiçbir HTML sayfasından bağlanmayan (crawler'ın göremeyeceği) lazy-load chunk
    "/static/chunk.lazy.js": ("application/javascript", b'const k="AKIAABCDEFGHIJKLMNOP";'),
    "/.git/HEAD": ("text/plain", b"ref: refs/heads/main\n"),
    "/.env": ("text/plain", b"APP_KEY=base64:xxx\nDB_PASSWORD=hunter2\n"),
    "/backup.zip": ("application/zip", BIG_ZIP),
    "/robots.txt": ("text/plain", b"User-agent: *\nDisallow: /secret-area/\n"),
}


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    state = {"hits": 0, "throttle": False}

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.state["hits"] += 1
        path = self.path.split("?")[0]
        if self.state["throttle"]:
            code, ctype, body = 429, "text/plain", b"slow down"
        elif path in FILES:
            code, (ctype, body) = 200, FILES[path]
        else:
            code, ctype, body = 404, "text/html", b"<html>404 Not Found</html>"
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:      # istemci gövdeyi yarıda kesti (max_bytes) — beklenen durum
            pass


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass   # istemci bağlantıyı yarıda kesti (max_bytes) — beklenen, gürültü basma


@pytest.fixture()
def lab():
    _Handler.state.update(hits=0, throttle=False)
    srv = _Server(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def make(module_cls, tmp_path, target="lab.test", rps=2000, **overrides):
    cfg = Config.load(target, overrides=overrides or None)
    limiter = RateLimiter(rps)
    out = OutputManager(tmp_path, target)
    out.prepare()
    return module_cls(cfg, out, ToolRunner({}), limiter, HttpClient(limiter, timeout=5))


def lab_ctx(url):
    ctx = ScanContext(target="lab.test")
    ctx.scope_hosts = {"127.0.0.1"}
    ctx.live_hosts = [LiveHost(url=url)]
    return ctx


# ------------------------------------------------------------------ HTTP istemcisi
def test_http_max_bytes_truncates_but_reports_real_length(lab):
    http = HttpClient(RateLimiter(1000), timeout=5)
    r = http.get(f"{lab}/backup.zip", max_bytes=4096)
    assert r.truncated and len(r.text) == 4096
    assert r.length == len(BIG_ZIP)                  # uzunluk Content-Length'ten
    assert r.head.startswith(b"PK\x03\x04")
    small = http.get(f"{lab}/.env", max_bytes=4096)
    assert not small.truncated and small.length == len(FILES["/.env"][1])


def test_http_get_returns_none_on_network_error():
    assert HttpClient(RateLimiter(1000), timeout=1).get("http://127.0.0.1:9/") is None


# ------------------------------------------------------------------ hız sınırlayıcı
def test_backoff_burst_halves_only_once_and_recovers():
    rl = RateLimiter(16)
    for _ in range(10):                              # aynı anda uçuşta olan 10 istek 429 aldı
        rl.backoff("429", pause=5)
    assert rl.rps == 8                               # 16 -> 0.5'e çakılmaz, tek sefer yarılanır
    rl._pause_until = 0.0
    rl._last_change -= rl.RECOVERY_INTERVAL + 1      # yeterince sorunsuz süre geçti
    rl.wait()
    assert rl.rps == 12                              # kademeli toparlanma (x1.5)
    rl._last_change -= rl.RECOVERY_INTERVAL + 1
    rl.wait()
    assert rl.rps == 16                              # başlangıç değerini aşmaz


def test_limiter_cancel_wakes_waiters():
    rl = RateLimiter(0.5)                            # istek arası 2 sn
    rl.wait()
    threading.Timer(0.1, rl.cancel).start()
    start = time.monotonic()
    with pytest.raises(ScanCancelled):
        rl.wait()
    assert time.monotonic() - start < 1.5            # 2 sn'lik beklemeden erken uyandı
    with pytest.raises(ScanCancelled):
        rl.wait()


def test_http_429_triggers_backoff(lab):
    _Handler.state["throttle"] = True
    rl = RateLimiter(100)
    r = HttpClient(rl, timeout=5).get(f"{lab}/")
    assert r.status_code == 429 and rl.rps == 50


# ------------------------------------------------------------------ paralel yürütücü
def test_parallel_bounded_queue_and_error_isolation(tmp_path):
    mod = make(JSAnalyzer, tmp_path, threads=4)
    running, peak, lock = [0], [0], threading.Lock()

    def work(i):
        with lock:
            running[0] += 1
            peak[0] = max(peak[0], running[0])
        time.sleep(0.002)
        with lock:
            running[0] -= 1
        if i == 7:
            raise ValueError("boom")
        return i * 2

    results = list(mod.parallel(work, range(200)))
    assert len(results) == 200 and peak[0] <= 4
    assert sorted(r for _, r, e in results if e is None) == sorted(i * 2 for i in range(200) if i != 7)
    assert [i for i, _, e in results if e is not None] == [7]


def test_parallel_stops_on_cancel(tmp_path):
    mod = make(JSAnalyzer, tmp_path, threads=4)
    calls = []

    def work(i):
        calls.append(i)
        if i == 3:
            mod.limiter.cancel()
        mod.limiter.wait()
        return i

    with pytest.raises(ScanCancelled):
        list(mod.parallel(work, range(1000)))
    assert len(calls) < 100                          # kalan ~1000 iş hiç başlatılmadı


# ------------------------------------------------------------------ araç çalıştırıcı
def test_tool_runner_timeout_fires_for_silent_tool():
    """Araç hiç çıktı üretmeden takılırsa da zaman aşımı çalışmalı (canlı/stderr modunda da)."""
    runner = ToolRunner({"py": sys.executable})
    start = time.monotonic()
    with pytest.raises(ToolExecutionError):
        runner.run("py", ["-c", "import time; time.sleep(30)"], timeout=1, on_stderr=lambda s: None)
    assert time.monotonic() - start < 10


def test_tool_runner_streams_stderr_and_stdin():
    runner = ToolRunner({"py": sys.executable})
    seen = []
    res = runner.run("py", ["-c", "import sys; sys.stderr.write('Progress: 1\\n'); print(sys.stdin.read().upper())"],
                     stdin="merhaba", on_stderr=seen.append, timeout=30)
    assert "MERHABA" in res.stdout and "Progress: 1" in "".join(seen)
    with pytest.raises(ToolExecutionError):
        runner.run("py", ["-c", "import sys; sys.exit(3)"], timeout=30)


def test_tool_runner_cancel_kills_running_process():
    runner = ToolRunner({"py": sys.executable})
    threading.Timer(0.5, runner.cancel).start()
    start = time.monotonic()
    with pytest.raises(ScanCancelled):
        runner.run("py", ["-c", "import time; time.sleep(30)"], timeout=60)
    assert time.monotonic() - start < 10
    with pytest.raises(ScanCancelled):               # iptalden sonra yeni araç başlatılmaz
        runner.run("py", ["-c", "print(1)"], timeout=10)


# ------------------------------------------------------------------ modüller (uçtan uca, yerel)
def test_dir_bruteforce_internal_end_to_end(lab, tmp_path):
    mod = make(DirBruteforcer, tmp_path, dir_engine="internal")
    ctx = lab_ctx(lab)
    mod.run(ctx)
    hits = {h["path"]: h for h in ctx.findings["dirs"]}
    assert hits[".git/HEAD"]["verified"] and hits[".env"]["verified"]
    assert "DB_PASSWORD" in hits[".env"]["evidence"] or "APP_KEY" in hits[".env"]["evidence"]
    assert hits["backup.zip"]["verified"]                       # arşiv imzası
    assert hits["backup.zip"]["length"] == len(BIG_ZIP)         # kesilse de gerçek boyut
    assert not any(h["status"] == 404 for h in hits.values())
    found = (tmp_path / "lab.test" / "directory_brute" / "verified.txt").read_text(encoding="utf-8")
    assert ".git/HEAD" in found


def test_dir_bruteforce_reads_each_wordlist_once(tmp_path, monkeypatch):
    mod = make(DirBruteforcer, tmp_path)
    reads = []
    real = Path.read_text

    def counting(self, *a, **k):
        reads.append(self.name)
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", counting)
    for i in range(5):
        mod.build_wordlist_map(LiveHost(url=f"https://h{i}.lab.test"), "lab.test")
    assert reads.count("sensitive.txt") == 1


def test_crawler_internal_and_scope(lab, tmp_path):
    mod = make(Crawler, tmp_path)
    ctx = lab_ctx(lab)
    mod.config.crawler["engine"] = "internal"
    mod.run(ctx)
    assert f"{lab}/static/app.js" in ctx.js_files
    assert any(u.startswith(f"{lab}/index.php?") for u in ctx.urls)
    assert f"{lab}/secret-area/" in ctx.urls                    # robots.txt
    assert f"{lab}/contact.php?ref=about" in ctx.urls           # 2. derinlik


def test_js_analyzer_end_to_end(lab, tmp_path):
    mod = make(JSAnalyzer, tmp_path)
    ctx = lab_ctx(lab)
    ctx.js_files = {f"{lab}/static/app.js"}
    mod.run(ctx)
    assert any(f["rule"] == "google_api_key" and f["severity"] == "HIGH" for f in ctx.findings["js"])
    endpoints = (tmp_path / "lab.test" / "js_analysis" / "endpoints.txt").read_text(encoding="utf-8")
    assert "/api/v2/users" in endpoints


def test_js_minified_line_reports_every_distinct_secret(tmp_path):
    """Tek satırlık (minified) pakette aynı kuralın birden çok FARKLI eşleşmesi kaçmamalı ve
    kesin bir eşleşme, satırın başka yerindeki genel atama bulgusunu bastırmamalı."""
    a = make(JSAnalyzer, tmp_path)
    line = ('var a="AKIAABCDEFGHIJKLMNOP",b="AKIAZZZZZZZZZZZZZZZZ",c="AKIAABCDEFGHIJKLMNOP";'
            'x={dbPassword:"Tr0ub4dor&3xyz"};')
    hits = a.scan_content("x.min.js", line)
    aws = [h for h in hits if h.rule == "aws_access_key"]
    assert len(aws) == 2                                        # iki farklı anahtar, tekrar yok
    assert any(h.rule == "generic_secret_assignment" for h in hits)
    # Aynı metni hem kesin kural hem genel kural/anahtar kelime ayrı ayrı raporlamaz
    one = a.scan_content("x.js", 'const apiKey = "AIzaSyA1234567890abcdefghijklmnopqrstuv";')
    assert [h.rule for h in one] == ["google_api_key"]


# ------------------------------------------------------------------ CLI / orkestratör
def test_cli_direct_targets_without_domain(lab, tmp_path, monkeypatch):
    """--targets -d olmadan: kapsam = dosyadaki hedefler (IP dahil), keşif atlanır."""
    import recon
    tf = tmp_path / "targets.txt"
    tf.write_text("127.0.0.1\n# yorum\nnot a host\n", encoding="utf-8")
    captured = {}
    real_run = recon.ReconOrchestrator.run

    def fake_run(self):
        captured["cfg"] = self.config
        return True

    monkeypatch.setattr(recon.ReconOrchestrator, "run", fake_run)
    assert recon.main(["--targets", str(tf), "-o", str(tmp_path / "out")]) == 0
    cfg = captured["cfg"]
    assert cfg.direct and cfg.target == "127.0.0.1" and cfg.seed_targets == ["127.0.0.1"]
    assert cfg.enabled_modules == ["crawl", "js", "dirs"]
    monkeypatch.setattr(recon.ReconOrchestrator, "run", real_run)
    empty = tmp_path / "empty.txt"
    empty.write_text("???\n", encoding="utf-8")
    assert recon.main(["--targets", str(empty), "-o", str(tmp_path / "out")]) == 2


def test_resume_keeps_previous_findings_in_report(tmp_path):
    """`-m js` gibi kısmi çalıştırma, önceki port/dizin/güvenlik bulgularını rapordan silmemeli."""
    from recon import ReconOrchestrator
    cfg = Config.load("example.com", overrides={"output_dir": str(tmp_path), "modules": ["js"]})
    root = tmp_path / "example.com"
    for rel, data in {
        "subdomains/live.json": [{"url": "https://example.com", "status_code": 200,
                                  "headers": {"Server": "nginx/1.18.0"}}],
        "ports/ports.json": [{"host": "example.com", "port": 6379, "service": "redis"}],
        "directory_brute/findings.json": [{"url": "https://example.com/.env", "path": ".env", "status": 200,
                                           "length": 40, "category": "sensitive", "verified": True}],
        "compliance/findings.json": [{"severity": "MEDIUM", "category": "security-header",
                                      "target": "https://example.com", "title": "No HSTS header"}],
    }.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(json.dumps(data), encoding="utf-8")
    orch = ReconOrchestrator(cfg)
    orch.output.prepare()
    orch._load_previous(["js"])
    orch._finalize()
    summary = json.loads((root / "summary.json").read_text(encoding="utf-8"))
    assert summary["counts"]["open_ports"] == 1 and summary["counts"]["dir_verified"] == 1
    assert summary["counts"]["version_disclosure"] == 1
    assert summary["counts"]["overall_counts"]["HIGH"] == 2     # Redis + .env
    assert "overall_grade" not in summary["counts"] and "grade" not in (root / "report.md").read_text(encoding="utf-8").lower()
    unified = json.loads((root / "findings.json").read_text(encoding="utf-8"))
    cats = {f["category"] for f in unified}
    assert {"port", "exposure", "security-header"} <= cats
    assert "Sensitive file exposed: .env" in (root / "report.md").read_text(encoding="utf-8")


def test_summary_redacts_proxy_credentials(tmp_path):
    from recon import ReconOrchestrator
    assert ReconOrchestrator._redact_proxy("http://user:s3cret@10.0.0.1:8080") == "http://***@10.0.0.1:8080"
    assert ReconOrchestrator._redact_proxy("http://127.0.0.1:8080") == "http://127.0.0.1:8080"
    assert ReconOrchestrator._redact_proxy(None) is None


def test_config_validates_engines_and_proxy():
    with pytest.raises(ConfigError):
        Config.load("example.com", overrides={"dir_engine": "nmap"})
    assert Config.load("example.com", overrides={"proxy": "socks5h://127.0.0.1:9050"}).proxy


def test_output_path_rejects_sibling_prefix_escape(tmp_path):
    """outputs/a.com ile outputs/a.com.evil aynı önekle başlar; içerme kontrolü öneke bakmamalı."""
    from core.exceptions import ReconError
    out = OutputManager(tmp_path, "a.com")
    out.prepare()
    with pytest.raises(ReconError):
        out.path("root", "../a.com.evil/x.txt")
    assert out.path("root", "ok/x.txt").name == "x.txt"


# ------------------------------------------------------------------ dashboard denetleyicisi
def test_controller_cancel_stops_running_module(lab, tmp_path):
    from dashboard.config_builder import build_config
    from dashboard.controller import ScanController
    cfg = build_config("127.0.0.1", rate_limit=1, threads=2, timeout=5, output_dir=str(tmp_path),
                       dir_engine="internal", direct=True)
    c = ScanController(cfg)
    c.ctx.scope_hosts = {"127.0.0.1"}
    c.ctx.live_hosts = [LiveHost(url=lab)]
    run = c.start_module("dirs")                     # 1 istek/sn ile ~200 yol: dakikalar sürer
    time.sleep(0.5)
    assert run.status == "running"
    c.cancel()
    run.thread.join(timeout=10)
    assert run.status == "cancelled" and run.finished_at is not None
    hits_after = _Handler.state["hits"]
    time.sleep(1.5)
    assert _Handler.state["hits"] == hits_after      # durdurulduktan sonra hedefe istek gitmiyor
    with pytest.raises(RuntimeError):
        c.start_module("js")
    assert (c.write_reports() / "report.md").is_file()   # o ana kadarki sonuçlarla rapor yazılabilir


# ------------------------------------------------------------------ eklentiler
def test_takeover_requires_cname_confirmation():
    """Gövde imzası tek başına CRITICAL değildir; CNAME sağlayıcıya gidiyorsa doğrulanır."""
    from core.security_checks import detect_takeover
    body = "<html>There isn't a GitHub Pages site here.</html>"
    url = "https://docs.example.com"
    asked = []

    def to_github(host):
        asked.append(host)
        return ["example.github.io"]

    ok = detect_takeover(url, body, resolve=to_github)[0]
    assert ok["severity"] == "CRITICAL" and "confirmed" in ok["title"] and "example.github.io" in ok["evidence"]
    assert asked == ["docs.example.com"]
    elsewhere = detect_takeover(url, body, resolve=lambda h: ["cdn.cloudflare.net"])[0]
    assert elsewhere["severity"] == "MEDIUM" and "unconfirmed" in elsewhere["title"]
    assert "cdn.cloudflare.net" in elsewhere["evidence"]
    assert detect_takeover(url, body, resolve=lambda h: [])[0]["severity"] == "MEDIUM"       # yalnızca A kaydı
    assert detect_takeover(url, body, resolve=lambda h: None)[0]["severity"] == "MEDIUM"     # DNS belirsiz
    # Sonek sınırı: "evilgithub.io" github.io sayılmaz
    assert detect_takeover(url, body, resolve=lambda h: ["x.evilgithub.io"])[0]["severity"] == "MEDIUM"

    def boom(host):
        raise AssertionError("imza yokken DNS sorgusu yapılmamalı")

    assert detect_takeover(url, "<html>welcome</html>", resolve=boom) == []


def test_resolve_cname_chain_handles_unresolvable_host():
    from core.security_checks import resolve_cname_chain
    # İstisna fırlatmaz; liste ya da None döner. (dnspython yokken Windows, 'localhost' için kanonik ad
    # olarak makine adını verir; bu yüzden içerik değil yalnızca tür doğrulanır.)
    chain = resolve_cname_chain("localhost")
    assert chain is None or isinstance(chain, list)
    assert resolve_cname_chain("no-such-host.invalid") in ([], None)


def test_tool_runner_streams_stdout_lines_live():
    """on_stdout satırları araç daha çalışırken alır (çıktının tamamı beklenmez)."""
    runner = ToolRunner({"py": sys.executable})
    stamps = []
    code = ("import sys,time\n"
            "print('one', flush=True); time.sleep(1.2); print('two', flush=True); sys.stdout.write('tail')")
    res = runner.run("py", ["-c", code], on_stdout=lambda l: stamps.append((l.strip(), time.monotonic())), timeout=30)
    assert [s[0] for s in stamps] == ["one", "two", "tail"]
    assert stamps[1][1] - stamps[0][1] > 0.8                    # 'one' beklemeden, anında geldi
    assert "one" in res.stdout and res.stdout.rstrip().endswith("tail")


def test_nuclei_findings_are_emitted_while_running(tmp_path):
    """Nuclei bulguları satır geldikçe olaya dönüşür; araç hata ile bitse de o ana kadarkiler kalır."""
    from modules.nuclei_scan import NucleiScanner
    mod = make(NucleiScanner, tmp_path)
    ctx = ScanContext(target="lab.test")
    ctx.live_hosts = [LiveHost(url="https://lab.test")]
    events, seen_during_run = [], []
    ctx.event_hook = lambda kind, payload: events.append((kind, payload))
    lines = [
        json.dumps({"template-id": "CVE-2021-44228", "matched-at": "https://lab.test/a",
                    "info": {"name": "Log4Shell", "severity": "critical",
                             "classification": {"cvss-score": 10.0, "cve-id": ["cve-2021-44228"]}}}),
        "[INF] not json",
        json.dumps({"template-id": "tech-detect", "host": "https://lab.test", "info": {"name": "nginx", "severity": "info"}}),
    ]

    def fake_run(tool, args, stdin=None, on_stdout=None, **kw):
        assert tool == "nuclei" and "-jsonl" in args and "-exclude-tags" in args
        for line in lines:
            on_stdout(line)
            seen_during_run.append(len(events))
        raise ToolExecutionError("nuclei zaman aşımına uğradı")

    mod.runner.is_available = lambda tool: True
    mod.runner.run = fake_run
    mod.run(ctx)
    assert seen_during_run == [1, 1, 2]                         # her bulgu satırı anında yayınlandı
    assert [f["severity"] for f in ctx.findings["nuclei"]] == ["CRITICAL", "INFO"]
    assert ctx.findings["nuclei"][0]["cve"] == "CVE-2021-44228" and ctx.findings["nuclei"][0]["cvss"] == 10.0
    assert len(events) == 2                                     # bitişte ikinci kez yayınlanmaz
    saved = json.loads((tmp_path / "lab.test" / "nuclei" / "findings.json").read_text(encoding="utf-8"))
    assert len(saved) == 2


def test_js_endpoints_feed_back_into_scan(lab, tmp_path):
    """JS'ten çıkan yollar URL envanterine eklenir; crawler'ın görmediği JS dosyası da taranır."""
    mod = make(JSAnalyzer, tmp_path)
    ctx = lab_ctx(lab)
    ctx.urls = {lab}
    ctx.js_files = {f"{lab}/static/app.js"}
    mod.run(ctx)
    assert f"{lab}/api/v2/users" in ctx.urls                    # kök-göreli yol
    assert f"{lab}/shop/search.php?q=1" in ctx.urls                  # göreli yol site köküne göre çözülür
    assert not any("other.example.org" in u for u in ctx.urls)  # kapsam dışı eklenmez
    assert f"{lab}/static/chunk.lazy.js" in ctx.js_files
    rules = {(f["url"].rsplit("/", 1)[-1], f["rule"]) for f in ctx.findings["js"]}
    assert ("chunk.lazy.js", "aws_access_key") in rules         # 2. turda bulundu
    assert ctx.stats["js_endpoint_urls"] >= 3
    root = tmp_path / "lab.test"
    assert "/api/v2/users" in (root / "js_analysis" / "endpoint_urls.txt").read_text(encoding="utf-8")
    assert "shop/search.php?q=1" in (root / "urls" / "parameterized.txt").read_text(encoding="utf-8")


def test_js_endpoint_feedback_can_be_disabled(lab, tmp_path):
    mod = make(JSAnalyzer, tmp_path)
    mod._feed_endpoints = False
    ctx = lab_ctx(lab)
    ctx.js_files = {f"{lab}/static/app.js"}
    mod.run(ctx)
    assert ctx.urls == set() and ctx.js_files == {f"{lab}/static/app.js"}


def test_resolve_endpoint():
    r = JSAnalyzer.resolve_endpoint
    assert r("https://a.test/static/app.js", "/api/x") == "https://a.test/api/x"
    assert r("https://a.test/static/app.js", "api/x.php?id=1#frag") == "https://a.test/api/x.php?id=1"
    assert r("https://a.test/static/app.js", "https://b.test/y") == "https://b.test/y"
    assert r("x.js", "/api/x") == ""


def test_live_hosts_are_emitted_as_they_are_found(tmp_path):
    """Canlı hostlar yoklama bitmeden, bulundukça olay olarak yayınlanır; aynı URL iki kez yayınlanmaz."""
    from modules.subdomain_recon import SubdomainRecon
    mod = make(SubdomainRecon, tmp_path, target="example.com")
    mod.config.subdomains["probe_engine"] = "internal"
    ctx = ScanContext(target="example.com")
    events, emitted_before_done = [], []
    ctx.event_hook = lambda kind, payload: events.append(kind) if kind == "live_host" else None

    def fake_probe(host):
        if host == "dead.example.com":
            return None
        emitted_before_done.append(len(events))          # önceki hostlar çoktan yayınlanmış olmalı
        return LiveHost(url=f"http://{host}", status_code=200, headers={})

    mod._probe_one = fake_probe
    mod.config.rate_limit.threads = 1                    # sıralı çalışsın ki sıra doğrulanabilsin
    mod.probe_and_record(ctx, {"a.example.com", "b.example.com", "dead.example.com"})
    assert events == ["live_host", "live_host"] and emitted_before_done == [0, 1]
    assert [h.url for h in ctx.live_hosts] == ["http://a.example.com", "http://b.example.com"]

    line = json.dumps({"url": "https://a.example.com/", "input": "a.example.com", "status_code": 403,
                       "tech": ["Nginx"], "header": {"set_cookie": "PHPSESSID=1"}})
    h = SubdomainRecon._parse_httpx_line(line)
    assert h.url == "https://a.example.com" and h.status_code == 403 and "PHP" in h.technologies
    assert SubdomainRecon._parse_httpx_line('{"failed": true, "url": "x"}') is None
    assert SubdomainRecon._parse_httpx_line("not json") is None


def test_missing_headers_are_one_info_row_not_many_medium_rows():
    """Eksik güvenlik başlıkları zafiyet değil sıkılaştırma notudur: host başına TEK INFO satırı."""
    from core.security_checks import analyze_security_headers, version_finding
    f = analyze_security_headers("https://x.test", {"Set-Cookie": "sid=1", "Access-Control-Allow-Origin": "*"}, 200)
    assert len(f) == 1 and f[0]["severity"] == "INFO" and f[0]["category"] == "hardening"
    for part in ("HSTS", "CSP", "X-Frame-Options", "nosniff", "cookie without Secure/HttpOnly", "CORS allows any origin"):
        assert part in f[0]["evidence"]
    assert analyze_security_headers("http://x.test", {"Location": "https://x.test/"}, 301) == []   # yönlendirme
    hardened = {"Strict-Transport-Security": "max-age=1", "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                "X-Content-Type-Options": "nosniff"}
    assert analyze_security_headers("https://x.test", hardened, 200) == []
    # Gerçekten istismar edilebilir CORS hatası HIGH kalır
    bad = analyze_security_headers("https://x.test", {**hardened, "Access-Control-Allow-Origin": "*",
                                                      "Access-Control-Allow-Credentials": "true"}, 200)
    assert [x["severity"] for x in bad] == ["HIGH"]
    assert version_finding({"url": "https://x.test", "header": "Server", "value": "nginx/1.18.0",
                            "version": "1.18.0"})["severity"] == "INFO"
