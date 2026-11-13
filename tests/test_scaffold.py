import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from core.config import Config
from core.exceptions import ConfigError
from core.fingerprint import detect
from core.http_client import HttpClient
from core.output_manager import OutputManager
from core.rate_limiter import RateLimiter
from core.tool_runner import ToolRunner
from modules.base import LiveHost, ScanContext
from modules.dir_bruteforce import DirBruteforcer
from modules.js_analyzer import JSAnalyzer
from recon import normalize_domain


def make(module_cls, tmp_path, target="example.com"):
    cfg = Config.load(target)
    limiter = RateLimiter(1000)
    out = OutputManager(tmp_path, target)
    out.prepare()
    return module_cls(cfg, out, ToolRunner({}), limiter, HttpClient(limiter))


def test_normalize_domain():
    assert normalize_domain("https://Example.com/path") == "example.com"
    assert normalize_domain("*.example.com") == "example.com"
    with pytest.raises(ConfigError):
        normalize_domain("not a domain")


def test_config_validation():
    with pytest.raises(ConfigError):
        Config.load("example.com", overrides={"rate_limit": 0})
    with pytest.raises(ConfigError):
        Config.load("example.com", overrides={"headers": ["bozuk-header"]})
    cfg = Config.load("example.com", overrides={"headers": ["X-Bug-Bounty: kullanici"], "rate_limit": 3})
    assert cfg.headers["X-Bug-Bounty"] == "kullanici"
    assert cfg.rate_limit.requests_per_second == 3


def test_rate_limiter_respects_rps():
    rl = RateLimiter(20)
    start = time.monotonic()
    for _ in range(21):
        rl.wait()
    assert time.monotonic() - start >= 0.95  # 21 istek / 20 rps ~= 1 sn


def test_rate_limiter_backoff_halves():
    rl = RateLimiter(10)
    rl.backoff("429", pause=0)
    assert rl.rps == 5


def test_scope():
    ctx = ScanContext(target="example.com")
    assert ctx.in_scope("https://api.example.com/x")
    assert not ctx.in_scope("https://example.com.evil.net/")
    assert not ctx.in_scope("notexample.com")


def test_js_scan_content(tmp_path):
    analyzer = make(JSAnalyzer, tmp_path)
    js = ('var a = 1;\n'
          'const apiKey = "abcdef123456";\n'       # generic_secret_assignment (quoted, secret-like)
          'var k="AKIAABCDEFGHIJKLMNOP";\n'         # aws_access_key HIGH
          'var p = "your_password";\n'              # placeholder value -> NO finding (noise removed)
          'var admin = 1;\n'                        # "admin" no longer a keyword -> NO finding
          'var secret = realSecretRef;')            # keyword:secret LOW (assignment, non-noise value)
    hits = analyzer.scan_content("x.js", js)
    rules = {(h.line_no, h.rule) for h in hits}
    assert (2, "generic_secret_assignment") in rules
    assert (3, "aws_access_key") in rules
    assert (6, "keyword:secret") in rules
    # False-positive noise is suppressed: placeholder password value and bare "admin"
    assert (4, "keyword:password") not in rules
    assert not any(r.startswith("keyword:admin") for _, r in rules)


def test_fingerprint():
    techs = detect({"X-Powered-By": "PHP/8.1", "Set-Cookie": "JSESSIONID=1"})
    assert "PHP" in techs and "Java" in techs


def test_tech_aware_wordlist(tmp_path):
    mod = make(DirBruteforcer, tmp_path)
    php = mod.build_wordlist_map(LiveHost(url="https://shop.example.com", technologies=["PHP:8.1"]), "example.com")
    plain = mod.build_wordlist_map(LiveHost(url="https://shop.example.com"), "example.com")
    assert "composer.json" in php and "composer.json" not in plain
    assert php["example.com.zip"] == "backup" and "shop.zip" in php
    assert ".git/HEAD" in plain                   # genel liste her zaman var


def test_soft404_similarity():
    base = [(200, 60, "<html><title>App</title>Sayfa bulunamadi ama 200</html>")]
    assert DirBruteforcer._is_soft404(200, 58, "<html><title>App</title>Sayfa bulunamadi ama 200</html>", base)
    assert not DirBruteforcer._is_soft404(200, 46, '{"name":"app","dependencies":{"express":"4"}}', base)


def test_progress_counter_and_ffuf_parse():
    from core.progress import ProgressCounter
    from modules.dir_bruteforce import FFUF_PROGRESS_RE
    chunk = "\r\x1b[2K:: Progress: [1200/4700] :: Job [1/1] :: 98 req/sec :: Duration: [0:00:12] :: Errors: 3 ::"
    assert FFUF_PROGRESS_RE.findall(chunk) == [("1200", "4700", "3")]
    p = ProgressCounter("test", 4700, live=False)
    p.set(1200, 4700, 3)
    p.advance(found=2)
    assert p.done == 1201 and p.found == 2 and "1201/4700 (%25)" in p.line() and "hata: 3" in p.line()
    p.close()
