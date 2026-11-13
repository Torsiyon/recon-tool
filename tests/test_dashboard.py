"""Web arayüzü sürücü katmanı (Streamlit'siz) testleri."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from core.exceptions import ConfigError
from dashboard.config_builder import build_config, prepare_custom_wordlist
from dashboard.controller import STEP_ORDER, ScanController
from modules.base import LiveHost


def test_build_config_rejects_bad_domain():
    with pytest.raises(ConfigError):
        build_config("not a domain", 10, 10, 10, "outputs")


def test_build_config_rate_and_wordlist(tmp_path):
    cfg = build_config("example.com", rate_limit=5, threads=4, timeout=8,
                       output_dir=str(tmp_path), custom_words="admin\nbackup.zip\n# yorum\n")
    assert cfg.rate_limit.requests_per_second == 5
    assert cfg.extra_wordlist and cfg.extra_wordlist.is_file()
    assert "admin" in cfg.extra_wordlist.read_text()


def test_only_custom_wordlist_clears_builtins(tmp_path):
    cfg = build_config("example.com", 10, 10, 10, str(tmp_path),
                       custom_words="x\n", only_custom_wordlist=True)
    assert cfg.dir_bruteforce["common_wordlists"] == []
    assert cfg.dir_bruteforce["tech_wordlists"] == {}


def test_prepare_custom_wordlist_empty():
    assert prepare_custom_wordlist("\n  \n# sadece yorum\n") is None


def test_controller_scope_filters_hosts(tmp_path):
    cfg = build_config("example.com", 10, 10, 10, str(tmp_path))
    c = ScanController(cfg)
    c.ctx.live_hosts = [LiveHost(url="https://a.example.com"), LiveHost(url="https://b.example.com"),
                        LiveHost(url="https://c.example.com")]
    kept = c.set_scope(["https://b.example.com"])
    assert kept == 1 and c.ctx.live_hosts[0].url == "https://b.example.com"


def test_controller_event_queue(tmp_path):
    cfg = build_config("example.com", 10, 10, 10, str(tmp_path))
    c = ScanController(cfg)
    c.ctx.emit("dir_hit", {"status": 403, "url": "https://example.com/admin"})
    events = c.drain_events()
    assert events == [("dir_hit", {"status": 403, "url": "https://example.com/admin"})]


def test_step_order():
    assert STEP_ORDER == ["subdomains", "ports", "crawl", "js", "dirs", "nuclei"]


def test_nuclei_safe_by_default_and_cvss():
    """Güvenli varsayılan: tehlikeli etiketler dışlanır; CVSS gerçek puandan türetilir."""
    from modules.nuclei_scan import DANGEROUS_TAGS, NucleiScanner
    for tag in ("dos", "intrusive", "fuzz", "brute"):
        assert tag in DANGEROUS_TAGS
    # Nuclei classification'dan CVSS/CVE çıkarımı
    cvss, cve = NucleiScanner._cvss_cve(
        {"classification": {"cvss-score": "10.0", "cve-id": "CVE-2021-44228"}})
    assert cvss == 10.0 and cve == "CVE-2021-44228"
    from core.security_checks import severity_from_cvss
    assert severity_from_cvss(10.0) == "CRITICAL"
    assert severity_from_cvss(7.5) == "HIGH"
    assert severity_from_cvss(None) is None


def test_port_risky_service_is_high_or_critical():
    from modules.port_scan import RISKY_SERVICES
    assert RISKY_SERVICES[6379][1] == "HIGH"       # Redis
    assert RISKY_SERVICES[2375][1] == "CRITICAL"   # Docker API
    assert 80 not in RISKY_SERVICES                 # düz HTTP riskli değil


def test_nmap_xml_parse_extracts_service_and_version():
    """nmap -sV çıktısından açık port + ürün/sürüm çıkarımı; kapalı portlar atlanır."""
    from modules.port_scan import PortScanner, _svc_label
    xml = ('<nmaprun><host><hostnames><hostname name="api.x.test"/></hostnames>'
           '<address addr="127.0.0.1"/><ports>'
           '<port protocol="tcp" portid="6379"><state state="open"/>'
           '<service name="redis" product="Redis key-value store" version="6.0.9"/></port>'
           '<port protocol="tcp" portid="443"><state state="closed"/></port>'
           '</ports></host></nmaprun>')
    recs = PortScanner._parse_nmap_xml(xml)
    assert len(recs) == 1                                  # kapalı 443 atlandı
    assert recs[0]["host"] == "api.x.test" and recs[0]["port"] == 6379
    assert recs[0]["version"] == "6.0.9"
    assert _svc_label(recs[0]) == "Redis key-value store 6.0.9"


def test_nmap_ssl_tunnel_relabeled_and_port80_kept():
    """443'te tunnel=ssl → 'https'; 80'de ürün (Wing FTP) korunur."""
    from modules.port_scan import PortScanner
    xml = ('<nmaprun><host><hostnames><hostname name="h.test"/></hostnames><address addr="1.1.1.1"/><ports>'
           '<port protocol="tcp" portid="443"><state state="open"/>'
           '<service name="http" tunnel="ssl" product="nginx" version="1.18.0"/></port>'
           '<port protocol="tcp" portid="80"><state state="open"/>'
           '<service name="http" product="Wing FTP Server"/></port>'
           '</ports></host></nmaprun>')
    recs = {r["port"]: r for r in PortScanner._parse_nmap_xml(xml)}
    assert recs[443]["service"] == "https" and recs[443]["product"] == "nginx"
    assert recs[80]["product"] == "Wing FTP Server"


def test_security_header_cors_credentials_is_high():
    from core.security_checks import analyze_security_headers
    f = analyze_security_headers("https://x.test", {
        "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
    assert any(x["severity"] == "HIGH" and x["category"] == "cors" for x in f)


def test_version_disclosure_detection():
    from core.fingerprint import detect_version_disclosure as d
    assert d({"Server": "nginx/1.18.0"})[0]["version"] == "1.18.0"
    assert d({"X-Powered-By": "PHP/8.1.2"})[0]["header"] == "X-Powered-By"
    assert d({"Server": "nginx"}) == []            # sürüm yok -> ifşa sayılmaz
    assert d({"X-AspNet-Version": "4.0.30319"})    # her zaman hassas
    assert d({"Content-Type": "text/html"}) == []  # alakasız başlık


def test_parse_targets_filters(tmp_path):
    from dashboard.controller import ScanController
    hosts = ScanController.parse_targets("app.example.com\nhttps://api.example.com:8443/x\n# yorum\nbadhost\n")
    assert hosts == ["app.example.com", "api.example.com"]


def test_parse_targets_accepts_ipv4():
    """Direct modda IP hedefleri de kabul edilir; geçersiz oktet elenir."""
    from dashboard.controller import ScanController
    hosts = ScanController.parse_targets("93.184.216.34\nhttps://10.0.0.1:8080/a\n999.1.1.1\nhost.example.com")
    assert "93.184.216.34" in hosts and "10.0.0.1" in hosts
    assert "999.1.1.1" not in hosts                      # geçersiz IP elendi
    assert "host.example.com" in hosts


def test_direct_scope_accepts_entered_hosts_only():
    """scope_hosts ayarlıyken kapsam = girilen hedefler (domain zorunluluğu yok)."""
    from modules.base import ScanContext
    ctx = ScanContext(target="direct-scan")
    ctx.scope_hosts = {"a.example.com", "93.184.216.34"}
    assert ctx.in_scope("a.example.com")
    assert ctx.in_scope("https://93.184.216.34:443/x")
    assert ctx.in_scope("sub.a.example.com")             # alt alan da kapsamda
    assert not ctx.in_scope("other.net")


def test_build_config_direct_allows_ip_and_no_domain(tmp_path):
    """direct=True: IP ya da boş target ConfigError vermez; etiket dosya-güvenlidir."""
    cfg = build_config("93.184.216.34", 10, 10, 10, str(tmp_path), direct=True)
    assert cfg.target == "93.184.216.34"
    cfg2 = build_config("", 10, 10, 10, str(tmp_path), direct=True)
    assert cfg2.target == "direct-scan"


def test_tool_flags_default_and_editable_override(tmp_path):
    """Düzenlenebilir bayraklar: varsayılanda -sV/-all var; kullanıcı çıkarabilir (override)."""
    from core.config import TOOL_DEFAULT_FLAGS
    cfg = build_config("example.com", 10, 10, 10, str(tmp_path))
    # Varsayılan davranış bayrakları
    assert "-all" in cfg.flags("subfinder", TOOL_DEFAULT_FLAGS["subfinder"])
    assert "-sV" in cfg.flags("nmap", TOOL_DEFAULT_FLAGS["nmap"])
    # Kullanıcı nmap'ten -sV'yi ÇIKARIR (override = tam liste)
    cfg2 = build_config("example.com", 10, 10, 10, str(tmp_path),
                        tool_args={"nmap": "-sT -Pn -n --open", "subfinder": "-silent -nc"})
    assert "-sV" not in cfg2.flags("nmap", TOOL_DEFAULT_FLAGS["nmap"])
    assert "-all" not in cfg2.flags("subfinder", TOOL_DEFAULT_FLAGS["subfinder"])
    # Boş = varsayılana dön
    cfg3 = build_config("example.com", 10, 10, 10, str(tmp_path), tool_args={"nmap": ""})
    assert "-sV" in cfg3.flags("nmap", TOOL_DEFAULT_FLAGS["nmap"])


def test_wordlist_selection_only_backup(tmp_path):
    """Yalnızca seçilen wordlist'ler kullanılır (ör. sadece yedek)."""
    from dashboard.config_builder import builtin_wordlists
    backup = [(p, c) for _, p, c in builtin_wordlists() if c == "backup"]
    cfg = build_config("example.com", 10, 10, 10, str(tmp_path),
                       wordlist_files=backup, auto_tech=False)
    assert all("backups.txt" in w for w in cfg.dir_bruteforce["common_wordlists"])
    assert cfg.dir_bruteforce["tech_wordlists"] == {}
    # kategori eşlemesi select_wordlists tarafından okunabilir olmalı
    assert cfg.dir_bruteforce["_category_map"]


def test_js_generic_secret_skips_ordinary_words_keeps_real():
    """`password: 'required'` bir doğrulama kuralıdır, sır değil → elenir; gerçek sır kalır."""
    import re as _re
    from modules.js_analyzer import JSAnalyzer, KEYWORDS, REGEX_RULES, _looks_like_secret
    assert not _looks_like_secret("required")        # düz kelime
    assert not _looks_like_secret("optional")
    assert _looks_like_secret("hunter2")             # harf+rakam
    assert _looks_like_secret("S3cr3t_Key!value")

    a = JSAnalyzer.__new__(JSAnalyzer)
    a._rules = [(n, sev, _re.compile(rx)) for n, sev, rx in REGEX_RULES]
    a._keyword_re = _re.compile(r"(?i)\b(" + "|".join(_re.escape(k) for k in KEYWORDS) + r")\b['\"]?\s*[:=]\s*['\"]?([^'\"\s,;{}()]{1,60})?")
    fp = a.scan_content("http://x/app.js", "var rule = {password: 'required'};")
    assert fp == []                                   # yanlış pozitif üretilmez
    tp = a.scan_content("http://x/app.js", "const apiKey = 'AbC123xyZ789secret';")
    assert any(f.rule == "generic_secret_assignment" for f in tp)


def test_js_keyword_pass_requires_assignment_context():
    """keyword:config gibi kuru kelime eşleşmesi (ör. minified lib) artık üretilmez."""
    import re as _re
    from modules.js_analyzer import JSAnalyzer, KEYWORDS, REGEX_RULES
    a = JSAnalyzer.__new__(JSAnalyzer)
    a._rules = [(n, sev, _re.compile(rx)) for n, sev, rx in REGEX_RULES]
    a._keyword_re = _re.compile(r"(?i)\b(" + "|".join(_re.escape(k) for k in KEYWORDS) + r")\b['\"]?\s*[:=]\s*['\"]?([^'\"\s,;{}()]{1,60})?")
    assert a.scan_content("http://x/lib.min.js", "new TableTools.Config(this);") == []
    assert "config" not in KEYWORDS and "admin" not in KEYWORDS
    hit = a.scan_content("http://x/app.js", "var token = userToken;")  # token = ... → keyword LOW
    assert any(f.rule.startswith("keyword:") for f in hit)


def test_exposure_finding_names_file_and_proves_verified():
    """Bulgu dosyayı adıyla gösterir; doğrulanmış dosya HIGH + içerik kanıtı taşır."""
    from core.security_checks import exposure_finding
    f = exposure_finding({"url": "https://x.test/.env", "path": ".env", "status": 200,
                          "length": 240, "category": "sensitive", "verified": True,
                          "evidence": "DB_PASSWORD=hunter2"})
    assert f["severity"] == "HIGH"
    assert ".env" in f["title"]                     # nerede/ne olduğu başlıkta
    assert "content-verified" in f["evidence"] and "DB_PASSWORD=hunter2" in f["evidence"]
    assert "240 B" in f["evidence"]                 # boyut kanıtı


def test_exposure_finding_benign_public_is_info_not_high():
    """robots.txt / sitemap.xml gibi standart dosyalar HIGH değil INFO sayılır."""
    from core.security_checks import exposure_finding
    for name in ("robots.txt", "sitemap.xml", "crossdomain.xml"):
        f = exposure_finding({"url": f"https://x.test/{name}", "path": name, "status": 200,
                              "length": 50, "category": "sensitive", "verified": False})
        assert f["severity"] == "INFO" and name in f["title"]


def test_exposure_finding_unverified_sensitive_is_medium_and_403_restricted():
    """Doğrulanmamış hassas yol 200 → MEDIUM (içeriği teyit et); 403 → LOW (var ama kısıtlı)."""
    from core.security_checks import exposure_finding
    m = exposure_finding({"url": "https://x.test/backup.zip", "path": "backup.zip", "status": 200,
                          "length": 1024, "category": "backup", "verified": False})
    assert m["severity"] == "MEDIUM" and "backup.zip" in m["title"]
    r = exposure_finding({"url": "https://x.test/logs/", "path": "logs/", "status": 403,
                          "length": 0, "category": "sensitive", "verified": False})
    assert r["severity"] == "LOW" and "logs" in r["title"]
    # Alakasız 403 (ör. common) bulgu üretmez
    assert exposure_finding({"url": "https://x.test/admin", "path": "admin", "status": 403,
                             "length": 0, "category": "common", "verified": False}) is None


def test_uploaded_wordlist_category_and_save(tmp_path):
    from dashboard.config_builder import guess_category, save_uploaded_wordlist
    assert guess_category("my-backup-list.txt") == "backup"
    assert guess_category("secrets.txt") == "sensitive"
    assert guess_category("rastgele.txt") == "custom"
    p = save_uploaded_wordlist("a b/..evil.txt", b"admin\nbackup.zip\n", tmp_path)
    assert p.is_file() and p.parent == tmp_path and "/" not in p.name
