"""settings.yaml + CLI argümanlarını tek bir Config nesnesinde birleştirir."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.exceptions import ConfigError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "settings.yaml"

# Arayüzde düzenlenebilen "davranış" bayrakları (kullanıcı ekleyip ÇIKARABİLİR).
# Çıktı biçimi/hedef gibi zorunlu bayraklar (ör. httpx -json, nmap -oX, subfinder -d)
# modül içinde ayrıca eklenir ve buraya DAHİL DEĞİLDİR; kullanıcı onları kaldıramaz.
TOOL_DEFAULT_FLAGS: dict[str, list[str]] = {
    "subfinder": ["-silent", "-nc", "-all"],
    "httpx":     ["-silent", "-nc", "-sc", "-title", "-td", "-server", "-cl", "-irh"],
    "nmap":      ["-sT", "-sV", "-Pn", "-n", "--open"],
    "nuclei":    ["-silent", "-nc", "-duc"],
}


@dataclass
class RateLimitConfig:
    requests_per_second: float = 10
    threads: int = 10
    timeout: int = 10
    random_delay: tuple[float, float] = (0.0, 0.0)
    user_agent: str = "ReconTool/0.1"
    verify_tls: bool = False


@dataclass
class Config:
    target: str
    output_dir: Path = Path("outputs")
    log_level: str = "INFO"
    tool_timeout: int = 3600
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    headers: dict[str, str] = field(default_factory=dict)
    proxy: str | None = None
    tools: dict[str, str] = field(default_factory=dict)
    tool_args: dict[str, list[str]] = field(default_factory=dict)   # araç -> ek CLI bayrakları
    subdomains: dict[str, Any] = field(default_factory=dict)
    ports: dict[str, Any] = field(default_factory=dict)
    crawler: dict[str, Any] = field(default_factory=dict)
    js_analysis: dict[str, Any] = field(default_factory=dict)
    dir_bruteforce: dict[str, Any] = field(default_factory=dict)
    nuclei: dict[str, Any] = field(default_factory=dict)
    enabled_modules: list[str] = field(default_factory=list)
    extra_wordlist: Path | None = None
    extra_subdomains: Path | None = None     # --subs: elde bulunan subdomain listesi
    seed_targets: list | None = None         # --targets: keşfi atla, bu hostları doğrudan tara
    direct: bool = False                     # Direct mod: kapsam = tam olarak verilen hedefler (domain yok)

    @classmethod
    def load(cls, target: str, config_path: Path | None = None, overrides: dict[str, Any] | None = None) -> "Config":
        path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
        try:
            import yaml
        except ImportError as exc:
            raise ConfigError("PyYAML kurulu değil: pip install -r requirements.txt") from exc
        try:
            with path.open(encoding="utf-8") as fh:
                raw: dict[str, Any] = yaml.safe_load(fh) or {}
        except FileNotFoundError as exc:
            raise ConfigError(f"Konfigürasyon dosyası bulunamadı: {path}") from exc
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigError(f"Konfigürasyon okunamadı ({path}): {exc}") from exc
        if not isinstance(raw, dict):
            raise ConfigError(f"Konfigürasyon kök öğesi bir sözlük olmalı: {path}")

        try:
            general = raw.get("general") or {}
            rl_raw = raw.get("rate_limit") or {}
            http = raw.get("http") or {}
            rl = RateLimitConfig(
                requests_per_second=float(rl_raw.get("requests_per_second", 10)),
                threads=int(rl_raw.get("threads", 10)),
                timeout=int(rl_raw.get("timeout", 10)),
                random_delay=tuple(rl_raw.get("random_delay") or (0.0, 0.0)),
                user_agent=str(rl_raw.get("user_agent", "ReconTool/0.1")),
                verify_tls=bool(rl_raw.get("verify_tls", False)),
            )
            cfg = cls(
                target=target,
                output_dir=Path(general.get("output_dir", "outputs")),
                log_level=str(general.get("log_level", "INFO")),
                tool_timeout=int(general.get("tool_timeout", 3600)),
                rate_limit=rl,
                headers=dict(http.get("headers") or {}),
                proxy=http.get("proxy"),
                tools=dict(raw.get("tools") or {}),
                tool_args=cls._normalize_tool_args(raw.get("tool_args")),
                subdomains=dict(raw.get("subdomains") or {}),
                ports=dict(raw.get("ports") or {}),
                crawler=dict(raw.get("crawler") or {}),
                js_analysis=dict(raw.get("js_analysis") or {}),
                dir_bruteforce=dict(raw.get("dir_bruteforce") or {}),
                nuclei=dict(raw.get("nuclei") or {}),
            )
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"Konfigürasyonda geçersiz değer: {exc}") from exc

        cfg._apply_overrides(overrides or {})
        cfg.validate()
        return cfg

    @staticmethod
    def _normalize_tool_args(raw: Any) -> dict[str, list[str]]:
        """tool_args'ı {araç: [bayraklar]} biçimine getirir. Değer string ise shlex ile parçalanır."""
        import shlex
        out: dict[str, list[str]] = {}
        if not isinstance(raw, dict):
            return out
        for tool, val in raw.items():
            if val is None:
                continue
            if isinstance(val, str):
                parts = shlex.split(val)
            elif isinstance(val, (list, tuple)):
                parts = [str(x) for x in val]
            else:
                continue
            if parts:
                out[str(tool)] = parts
        return out

    def extra_args(self, tool: str) -> list[str]:
        """Bir aracın invocation'ına EKLENECEK ek bayraklar (katana/ffuf gibi; append semantiği)."""
        return list(self.tool_args.get(tool) or [])

    def flags(self, tool: str, default: list[str]) -> list[str]:
        """Düzenlenebilir 'davranış' bayrakları: kullanıcı override ettiyse onu, etmediyse
        varsayılanı döner. Override = tam liste (kullanıcı bayrak çıkarabilir, ör. -sV'yi silmek)."""
        v = self.tool_args.get(tool)
        return list(v) if v is not None else list(default)

    def _apply_overrides(self, ov: dict[str, Any]) -> None:
        try:
            if ov.get("rate_limit") is not None:
                self.rate_limit.requests_per_second = float(ov["rate_limit"])
            if ov.get("threads") is not None:
                self.rate_limit.threads = int(ov["threads"])
            if ov.get("timeout") is not None:
                self.rate_limit.timeout = int(ov["timeout"])
            if ov.get("jitter") is not None:
                lo, hi = ov["jitter"]
                self.rate_limit.random_delay = (float(lo), float(hi))
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"Geçersiz CLI değeri: {exc}") from exc
        if ov.get("output_dir"):
            self.output_dir = Path(ov["output_dir"])
        if ov.get("log_level"):
            self.log_level = ov["log_level"]
        if ov.get("modules"):
            self.enabled_modules = list(dict.fromkeys(ov["modules"]))
        for raw_header in ov.get("headers") or []:
            if ":" not in raw_header:
                raise ConfigError(f"Header 'Ad: Değer' biçiminde olmalı: {raw_header!r}")
            name, value = raw_header.split(":", 1)
            self.headers[name.strip()] = value.strip()
        if ov.get("proxy"):
            self.proxy = ov["proxy"]
        if ov.get("tool_args"):
            # Arayüzden gelen ek bayraklar settings.yaml'dakilerin yerini alır (araç bazında).
            for tool, args in self._normalize_tool_args(ov["tool_args"]).items():
                self.tool_args[tool] = args
        if ov.get("wordlist"):
            self.extra_wordlist = Path(ov["wordlist"])
        if ov.get("subs"):
            self.extra_subdomains = Path(ov["subs"])
        if ov.get("dir_engine"):
            self.dir_bruteforce["engine"] = ov["dir_engine"]
        if ov.get("crawl_depth") is not None:
            self.crawler["depth"] = int(ov["crawl_depth"])

    def validate(self) -> None:
        rl = self.rate_limit
        if rl.requests_per_second <= 0:
            raise ConfigError("--rate-limit 0'dan büyük olmalı")
        if rl.threads <= 0:
            raise ConfigError("--threads 0'dan büyük olmalı")
        if rl.timeout <= 0:
            raise ConfigError("--timeout 0'dan büyük olmalı")
        if len(rl.random_delay) != 2 or rl.random_delay[0] < 0 or rl.random_delay[1] < rl.random_delay[0]:
            raise ConfigError("--jitter MIN MAX biçiminde ve 0 <= MIN <= MAX olmalı")
        if self.extra_wordlist and not self.extra_wordlist.is_file():
            raise ConfigError(f"Wordlist bulunamadı: {self.extra_wordlist}")
        if self.extra_subdomains and not self.extra_subdomains.is_file():
            raise ConfigError(f"Subdomain listesi bulunamadı: {self.extra_subdomains}")
        if self.proxy and not self.proxy.startswith(("http://", "https://", "socks5://", "socks5h://")):
            raise ConfigError("--proxy http://, https://, socks5:// veya socks5h:// ile başlamalı")
        allowed = {"subdomains": "httpx", "crawler": "katana", "dir_bruteforce": "ffuf", "ports": "nmap"}
        for key, tool in allowed.items():
            engine = getattr(self, key).get("engine") or getattr(self, key).get("probe_engine")
            if engine and str(engine).lower() not in ("auto", "internal", tool):
                raise ConfigError(f"{key}: bilinmeyen motor {engine!r} (auto | internal | {tool})")

    def header_flags(self, flag: str = "-H") -> list[str]:
        """Harici araçlara aktarılacak header bayrakları."""
        out: list[str] = []
        for k, v in self.headers.items():
            out += [flag, f"{k}: {v}"]
        return out
