"""Tüm dahili HTTP trafiği için ortak istemci.

Her istek RateLimiter'dan geçer; özel header, proxy, timeout ve gövde boyutu sınırı tek yerden yönetilir.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field

import requests
import urllib3

from core.rate_limiter import RateLimiter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SLOWDOWN_CODES = {429, 503}


@dataclass
class HttpResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    text: str
    length: int
    final_url: str = ""
    history: list[str] = field(default_factory=list)
    head: bytes = b""          # gövdenin ilk baytları (dosya imzası kontrolü için)
    truncated: bool = False    # gövde max_bytes sınırında kesildi mi


class HttpClient:
    def __init__(
        self,
        limiter: RateLimiter,
        timeout: int = 10,
        user_agent: str = "ReconTool/0.1",
        headers: dict[str, str] | None = None,
        proxy: str | None = None,
        verify_tls: bool = False,
        max_body_bytes: int = 5 * 1024 * 1024,
    ) -> None:
        self.limiter = limiter
        self.timeout = timeout
        self.headers = {"User-Agent": user_agent, **(headers or {})}
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.verify = verify_tls
        self.max_body_bytes = max_body_bytes
        self._local = threading.local()

    def _session(self) -> requests.Session:
        sess = getattr(self._local, "session", None)
        if sess is None:
            sess = requests.Session()
            sess.headers.update(self.headers)
            if self.proxies:
                sess.proxies.update(self.proxies)
            sess.verify = self.verify
            # Oturum iş parçacığına özeldir: aynı anda tek bağlantı kullanır, küçük havuz yeterli.
            adapter = requests.adapters.HTTPAdapter(pool_connections=4, pool_maxsize=4, max_retries=0)
            sess.mount("http://", adapter)
            sess.mount("https://", adapter)
            self._local.session = sess
        return sess

    def get(self, url: str, allow_redirects: bool = False, read_body: bool = True,
            max_bytes: int | None = None) -> HttpResponse | None:
        """Rate limit'e uyarak GET atar. Ağ hatasında None döner (ağ kaynaklı exception fırlatmaz).

        max_bytes: gövdenin en fazla bu kadarı indirilir (ör. dizin taramasında tüm yedek dosyasını
        çekmemek için). Kesilen yanıtlarda `length` Content-Length başlığından alınır.
        Tarama iptal edildiyse limiter ScanCancelled fırlatır (bilerek yakalanmaz)."""
        self.limiter.wait()
        limit = min(max_bytes, self.max_body_bytes) if max_bytes else self.max_body_bytes
        try:
            with self._session().get(url, timeout=self.timeout, allow_redirects=allow_redirects, stream=True) as r:
                body = bytearray()
                truncated = False
                if read_body:
                    for chunk in r.iter_content(chunk_size=65536):
                        body += chunk
                        if len(body) >= limit:
                            truncated = len(body) > limit or not self._at_end(r)
                            del body[limit:]
                            break
                if r.status_code in SLOWDOWN_CODES:
                    self.limiter.backoff(f"HTTP {r.status_code} @ {url}")
                length = len(body)
                if truncated or not read_body:
                    declared = r.headers.get("Content-Length", "")
                    if declared.isdigit():
                        length = max(length, int(declared))
                text = bytes(body).decode(r.encoding or "utf-8", errors="replace") if body else ""
                return HttpResponse(
                    url=url,
                    status_code=r.status_code,
                    headers=dict(r.headers),
                    text=text,
                    length=length,
                    final_url=r.url,
                    history=[h.url for h in r.history],
                    head=bytes(body[:16]),
                    truncated=truncated,
                )
        except (requests.RequestException, UnicodeError, LookupError, ValueError, OSError):
            return None

    @staticmethod
    def _at_end(r: requests.Response) -> bool:
        """Sınır tam gövde sonuna denk geldiyse 'kesildi' sayma (Content-Length biliniyorsa)."""
        declared = r.headers.get("Content-Length", "")
        if not declared.isdigit() or r.headers.get("Content-Encoding"):
            return False
        try:
            return r.raw.tell() >= int(declared)
        except (AttributeError, OSError, ValueError):
            return False
