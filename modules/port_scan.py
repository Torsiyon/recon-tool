"""Port taraması: canlı hostlarda açık portları ve SERVİSLERİ (ürün + sürüm) tespit eder.

nmap varsa onu kullanır (servis/sürüm tespitinde en olgun araç: `-sV`); yoksa dahili
(socket tabanlı) tarayıcıya düşer. nmap bağlan (connect / `-sT`) taraması yapar; bu mod
root yetkisi gerektirmez, imaj root olmayan kullanıcıyla çalıştığı için uygundur.

Açık portlar envantere yazılır; riskli/veri-deposu servisleri (Redis, Elasticsearch,
MongoDB, Docker API...) internete açıksa birleşik güvenlik bulgusu olarak işaretlenir.
nmap'in tespit ettiği gerçek ürün/sürüm bilgisi bulgunun kanıtına eklenir.

Çıktılar (outputs/<hedef>/ports/):
  open_ports.txt   host:port servis (ürün sürüm)
  ports.json       makine-okunur envanter
"""
from __future__ import annotations

import socket
import xml.etree.ElementTree as ET

from core import security_checks as sec
from core.config import TOOL_DEFAULT_FLAGS
from core.exceptions import ScanCancelled, ToolExecutionError
from core.rate_limiter import RateLimiter
from modules.base import BaseModule, ScanContext

# Varsayılan taranan portlar (web + yaygın servis/yönetim portları)
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 1521, 2375, 2379,
    3000, 3306, 3389, 5000, 5432, 5601, 5672, 5900, 6379, 7001, 8000, 8080, 8081,
    8443, 8888, 9000, 9092, 9200, 9300, 11211, 15672, 27017,
]

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 1433: "MSSQL",
    1521: "Oracle", 2375: "Docker API", 2379: "etcd", 3000: "HTTP-alt", 3306: "MySQL",
    3389: "RDP", 5000: "HTTP-alt", 5432: "PostgreSQL", 5601: "Kibana", 5672: "AMQP",
    5900: "VNC", 6379: "Redis", 7001: "WebLogic", 8000: "HTTP-alt", 8080: "HTTP-alt",
    8081: "HTTP-alt", 8443: "HTTPS-alt", 8888: "HTTP-alt", 9000: "HTTP-alt", 9092: "Kafka",
    9200: "Elasticsearch", 9300: "Elasticsearch", 11211: "Memcached", 15672: "RabbitMQ UI",
    27017: "MongoDB",
}

# İnternete açık olmaması gereken servisler: (servis, önem)
RISKY_SERVICES = {
    23: ("Telnet", "HIGH"), 2375: ("Docker API", "CRITICAL"), 2379: ("etcd", "HIGH"),
    1433: ("MSSQL", "MEDIUM"), 1521: ("Oracle", "MEDIUM"), 3306: ("MySQL", "MEDIUM"),
    3389: ("RDP", "MEDIUM"), 5432: ("PostgreSQL", "MEDIUM"), 5601: ("Kibana", "MEDIUM"),
    5900: ("VNC", "HIGH"), 6379: ("Redis", "HIGH"), 7001: ("WebLogic", "MEDIUM"),
    9200: ("Elasticsearch", "HIGH"), 9300: ("Elasticsearch", "MEDIUM"),
    11211: ("Memcached", "HIGH"), 15672: ("RabbitMQ UI", "MEDIUM"), 27017: ("MongoDB", "HIGH"),
    445: ("SMB", "MEDIUM"),
}


def _svc_label(rec: dict) -> str:
    """İnsan-okunur servis etiketi: 'Redis 6.0.9' gibi, varsa ürün+sürüm."""
    parts = [p for p in (rec.get("product"), rec.get("version")) if p]
    if parts:
        return " ".join(parts)
    return rec.get("service") or "unknown"


class PortScanner(BaseModule):
    name = "ports"
    description = "Port taraması (nmap / dahili) ve servis-sürüm tespiti"
    optional_tools = ("nmap",)

    def run(self, ctx: ScanContext) -> None:
        self._emit = ctx.emit
        cfg = self.config.ports if hasattr(self.config, "ports") else {}
        hosts = sorted({h.host for h in ctx.live_hosts if h.host} or
                       {s for s in ctx.subdomains if ctx.in_scope(s)})
        if not hosts:
            self.log.warning("Taranacak host yok, port taraması atlandı.")
            ctx.findings["ports"] = []
            return
        max_hosts = int(cfg.get("max_hosts", 50))
        if len(hosts) > max_hosts:
            self.log.warning(f"{len(hosts)} hosttan ilk {max_hosts} taranacak (ports.max_hosts)")
            hosts = hosts[:max_hosts]
        ports = [int(p) for p in (cfg.get("ports") or DEFAULT_PORTS)]
        engine = self.choose_engine(cfg.get("engine"), "nmap")
        self.log.info(f"Port tarama motoru: {engine} | {len(hosts)} host x {len(ports)} port")
        ctx.stats["port_engine"] = engine

        inventory = (self._scan_nmap(hosts, ports) if engine == "nmap"
                     else self._scan_internal(hosts, ports))
        inventory.sort(key=lambda r: (r["host"], r["port"]))
        ctx.findings["ports"] = inventory

        for rec in inventory:
            self._emit("port", rec)
        findings = self.risk_findings(inventory)
        for f in findings:
            self._emit("finding", f)
        ctx.findings["port_findings"] = findings
        ctx.stats["open_ports"] = len(inventory)
        self.log.info(f"Açık port: {len(inventory)} | riskli servis bulgusu: {len(findings)}")
        self._save(inventory)

    @staticmethod
    def risk_findings(inventory: list[dict]) -> list[dict]:
        """Envanterdeki riskli (internete açık olmaması gereken) servisleri bulguya çevirir."""
        findings: list[dict] = []
        for rec in inventory:
            if rec.get("port") not in RISKY_SERVICES:
                continue
            svc, severity = RISKY_SERVICES[rec["port"]]
            detected = _svc_label(rec)
            detail = f"The {svc} port ({rec['port']}) appears exposed to the internet."
            if rec.get("product") or rec.get("version"):
                detail += f" Detected service: {detected}."
            findings.append(sec.finding(
                severity, "port", f"{rec['host']}:{rec['port']}",
                f"Open/accessible service: {svc}", detail,
                evidence=f"{rec['host']}:{rec['port']} ({detected})",
                remediation="Close the service off from the internet, restrict it with a security group/firewall."))
        return findings

    @staticmethod
    def _max_rate(rps: float) -> int:
        """Port taraması paket hızı tavanı (nmap --max-rate ve dahili tarayıcı aynı değeri kullanır)."""
        return max(50, int(rps * 20))

    # ------------------------------------------------------------------ nmap
    def _scan_nmap(self, hosts: list[str], ports: list[int]) -> list[dict]:
        rl = self.config.rate_limit
        cfg = self.config.ports if hasattr(self.config, "ports") else {}
        # Düzenlenebilir davranış bayrakları (varsayılan: -sT -sV -Pn -n --open).
        # Kullanıcı -sV'yi çıkarabilir (o zaman sürüm tespiti yapılmaz).
        # -p <portlar>, --max-rate, --host-timeout ve -oX zorunludur (ayrıştırma/limit için).
        flags = self.config.flags("nmap", TOOL_DEFAULT_FLAGS["nmap"])
        args = list(flags) + ["-p", ",".join(str(p) for p in ports)]
        # Servis/sürüm yoğunluğu yalnızca -sV varken anlamlı. VARSAYILAN: standart (yoğunluk 7).
        if "-sV" in flags:
            if cfg.get("version_all"):
                args.append("--version-all")                   # yoğunluk 9 (en kapsamlı, yavaş)
            elif cfg.get("version_intensity") is not None:
                args += ["--version-intensity", str(int(cfg["version_intensity"]))]
        # --max-retries 2: filtrelenmiş (yanıtsız) portlarda yeniden deneme sayısını sınırlar →
        #   port taraması çok hızlanır, host zaman aşımına takılıp sonuçların kesilmesini önler.
        # --host-timeout yüksek tutulur: -sV bazı serviste (ör. Wing FTP) yavaş olabilir; düşük
        #   zaman aşımı hostu komple düşürüp açık portların (80 gibi) kaybolmasına yol açıyordu.
        args += ["--max-retries", "2",
                 "--max-rate", str(self._max_rate(self.limiter.rps)),
                 "--host-timeout", f"{max(240, int(rl.timeout) * 30)}s",
                 "-oX", "-"]
        args += list(hosts)
        try:
            res = self.runner.run("nmap", args)
        except ToolExecutionError as exc:
            self.log.error(f"nmap başarısız, dahili motora geçiliyor: {exc}")
            return self._scan_internal(hosts, ports)
        try:
            return self._parse_nmap_xml(res.stdout)
        except ET.ParseError as exc:
            self.log.error(f"nmap XML ayrıştırılamadı, dahili motora geçiliyor: {exc}")
            return self._scan_internal(hosts, ports)

    @staticmethod
    def _parse_nmap_xml(xml_text: str) -> list[dict]:
        out: list[dict] = []
        root = ET.fromstring(xml_text)
        for host in root.findall("host"):
            # Hedef adı: önce taranan hostname, yoksa IP adresi
            name = ""
            hn = host.find("hostnames/hostname")
            if hn is not None and hn.get("name"):
                name = hn.get("name")
            if not name:
                addr = host.find("address")
                name = addr.get("addr") if addr is not None else ""
            for port in host.findall("ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid = int(port.get("portid"))
                svc = port.find("service")
                service = SERVICE_NAMES.get(portid, "unknown")
                product = version = ""
                if svc is not None:
                    service = svc.get("name") or service
                    # SSL/TLS tüneli: nmap "http" + tunnel=ssl der → "https" olarak göster
                    if svc.get("tunnel") == "ssl" and not service.startswith(("ssl", "https")):
                        service = f"ssl/{service}" if service != "http" else "https"
                    product = svc.get("product") or ""
                    version = svc.get("version") or ""
                rec = {"host": name, "port": portid, "service": service}
                if product:
                    rec["product"] = product
                if version:
                    rec["version"] = version
                out.append(rec)
        return out

    # ------------------------------------------------------------------ dahili
    @staticmethod
    def _resolve(host: str) -> str | None:
        """Hostu bir kez çöz (IPv4/IPv6). Çözülemeyen host için onlarca bağlantı denemesi yapılmaz."""
        try:
            return socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)[0][4][0]
        except (OSError, IndexError, UnicodeError):
            return None

    def _probe_port(self, item: tuple[str, str, int]) -> dict | None:
        host, addr, port = item
        if self.limiter.cancelled:
            raise ScanCancelled("tarama durduruldu")
        self._port_limiter.wait()
        timeout = min(4.0, float(self.config.rate_limit.timeout))
        try:
            with socket.create_connection((addr, port), timeout=timeout):
                return {"host": host, "port": port, "service": SERVICE_NAMES.get(port, "unknown")}
        except (socket.timeout, ConnectionError, OSError):
            return None

    def _scan_internal(self, hosts: list[str], ports: list[int]) -> list[dict]:
        # Dahili tarayıcı da nmap ile aynı hız tavanına uyar (önceden hiç sınırlanmıyordu).
        self._port_limiter = RateLimiter(self._max_rate(self.limiter.rps))
        resolved: dict[str, str] = {}
        for host, addr, exc in self.parallel(self._resolve, hosts):
            if addr and not exc:
                resolved[host] = addr
        skipped = len(hosts) - len(resolved)
        if skipped:
            self.log.warning(f"{skipped} host DNS'te çözülemedi; port taraması dışında bırakıldı")
        pairs = [(h, resolved[h], p) for h in hosts if h in resolved for p in ports]
        out: list[dict] = []
        workers = min(100, max(self.config.rate_limit.threads, 20))
        for item, res, exc in self.parallel(self._probe_port, pairs, workers=workers):
            if not exc and res:
                out.append(res)
        return out

    # ------------------------------------------------------------------ kayıt
    def _save(self, inventory: list[dict]) -> None:
        lines = []
        for r in inventory:
            label = _svc_label(r)
            lines.append(f"{r['host']}:{r['port']} {r['service']}"
                         + (f" ({label})" if label and label != r['service'] else ""))
        self.output.write_lines("root", "ports/open_ports.txt", lines, sort=True)
        self.output.write_json("root", "ports/ports.json", inventory)
