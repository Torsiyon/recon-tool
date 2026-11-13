"""Tüm modüllerin ortak sözleşmesi ve modüller arası paylaşılan veri."""
from __future__ import annotations

from abc import ABC, abstractmethod
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Iterable, Iterator
import logging
from urllib.parse import urlsplit

from core.config import Config
from core.exceptions import ScanCancelled
from core.http_client import HttpClient
from core.logger import get_logger
from core.output_manager import OutputManager
from core.rate_limiter import RateLimiter
from core.tool_runner import ToolRunner


@dataclass
class LiveHost:
    url: str                      # ör. https://api.example.com
    host: str = ""
    status_code: int | None = None
    title: str | None = None
    webserver: str | None = None
    content_length: int | None = None
    technologies: list[str] = field(default_factory=list)
    headers: dict[str, Any] = field(default_factory=dict)
    source: str = ""              # httpx | internal

    def __post_init__(self) -> None:
        if not self.host:
            self.host = (urlsplit(self.url).hostname or "").lower()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanContext:
    """Modüller arasında taşınan sonuçlar (pipeline durumu)."""
    target: str
    subdomains: set[str] = field(default_factory=set)
    live_hosts: list[LiveHost] = field(default_factory=list)
    urls: set[str] = field(default_factory=set)
    js_files: set[str] = field(default_factory=set)
    findings: dict[str, list[Any]] = field(default_factory=dict)   # modül adı -> bulgular
    stats: dict[str, Any] = field(default_factory=dict)
    # Opsiyonel canlı olay kancası (ör. web arayüzü). CLI'da None kalır, davranış değişmez.
    event_hook: Callable[[str, dict], None] | None = None
    # Direct (keşfi atla) modu: kapsam = tam olarak girilen hostlar (domain zorunluluğu yok).
    # None kaldığında klasik davranış: kapsam = hedef domain ve alt alan adları.
    scope_hosts: set[str] | None = None

    def emit(self, kind: str, payload: dict) -> None:
        """Bir bulgu/olay üretildiğinde dinleyiciye haber verir. Hook yoksa hiçbir şey yapmaz,
        hook hata verirse tarama bundan etkilenmez."""
        hook = self.event_hook
        if hook is None:
            return
        try:
            hook(kind, payload)
        except Exception:  # arayüz kancası taramayı asla düşürmesin
            logging.getLogger("recon.event").debug("event_hook hatası", exc_info=True)

    def in_scope(self, url_or_host: str) -> bool:
        """Kapsam kontrolü.
        Direct modda (scope_hosts ayarlı): yalnızca girilen hostların kendisi veya alt alan adları.
        Normal modda: hedef domain ve alt alan adları."""
        host = urlsplit(url_or_host).hostname if "://" in url_or_host else url_or_host.split(":")[0]
        host = (host or "").lower().rstrip(".")
        if self.scope_hosts is not None:
            return any(host == s or host.endswith("." + s) for s in self.scope_hosts)
        return host == self.target or host.endswith("." + self.target)


class BaseModule(ABC):
    name: str = "base"
    description: str = ""
    required_tools: tuple[str, ...] = ()   # Zorunlu araçlar (yoksa modül atlanır)
    optional_tools: tuple[str, ...] = ()   # Varsa kullanılır, yoksa dahili motora düşülür

    def __init__(
        self,
        config: Config,
        output: OutputManager,
        runner: ToolRunner,
        limiter: RateLimiter,
        http: HttpClient,
    ) -> None:
        self.config = config
        self.output = output
        self.runner = runner
        self.limiter = limiter
        self.http = http
        self.log = get_logger(self.name)
        # run() başında ctx.emit'e bağlanır; öncesinde no-op (yardımcı metotlar güvenle çağırabilir)
        self._emit = lambda kind, payload: None

    def check_requirements(self) -> list[str]:
        """Eksik zorunlu araçların listesini döner (boş liste = hazır)."""
        return [t for t in self.required_tools if not self.runner.is_available(t)]

    def choose_engine(self, setting: str | None, tool: str) -> str:
        """auto | <tool> | internal  -> gerçekte kullanılacak motor."""
        setting = (setting or "auto").lower()
        if setting == "internal":
            return "internal"
        if self.runner.is_available(tool):
            return tool
        if setting == tool:
            self.log.warning(f"{tool} istendi ama bulunamadı; dahili motor kullanılacak.")
        return "internal"

    def parallel(self, fn: Callable[[Any], Any], items: Iterable[Any], workers: int | None = None
                 ) -> Iterator[tuple[Any, Any, BaseException | None]]:
        """fn'i items üzerinde thread havuzunda çalıştırır; (öğe, sonuç, hata) üretir.

        Ctrl+C / docker stop geldiğinde kuyruktaki işler iptal edilir ve havuz BEKLEMEDEN kapanır;
        aksi halde binlerce istek bitene kadar program kapanmazdı.
        """
        items = list(items)
        if not items:
            return
        n = max(1, min(workers or self.config.rate_limit.threads, len(items)))
        pool = ThreadPoolExecutor(max_workers=n)
        # Kuyruk sınırlı tutulur: yüz binlerce kelimelik listede hepsi için önceden Future
        # oluşturmak yerine yalnızca işçi sayısının birkaç katı kadar iş bekletilir.
        window = n * 4
        it = iter(items)
        pending: dict[Future, Any] = {}

        def fill() -> None:
            while len(pending) < window:
                try:
                    item = next(it)
                except StopIteration:
                    return
                pending[pool.submit(fn, item)] = item

        try:
            fill()
            while pending:
                done, _ = wait(pending, return_when=FIRST_COMPLETED)
                for fut in done:
                    item = pending.pop(fut)
                    try:
                        result = fut.result()
                    except ScanCancelled:
                        raise                   # kullanıcı durdurdu: kalan işleri de bırak
                    except Exception as exc:    # tek bir öğenin hatası diğerlerini durdurmaz
                        yield item, None, exc
                    else:
                        yield item, result, None
                fill()
        except BaseException:
            pool.shutdown(wait=False, cancel_futures=True)
            raise
        else:
            pool.shutdown(wait=True)

    @abstractmethod
    def run(self, ctx: ScanContext) -> None:
        """Modülün ana işi. ctx'i günceller, çıktıları self.output ile yazar."""
