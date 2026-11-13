"""Modül D: Rate limiting.

- Token-bucket benzeri aralık kontrolü: tüm iş parçacıkları toplamda saniyede en fazla N istek atar.
- Opsiyonel rastgele gecikme (jitter): istek desenini düzensizleştirip WAF imzalarına takılmayı azaltır.
- Uyarlanabilir yavaşlama: 429/503 gibi "yavaşla" yanıtlarında hız otomatik yarıya iner. Aynı anda
  uçuşta olan isteklerin hepsi 429 alsa bile hız yalnızca BİR kez yarılanır (duraklama penceresi başına).
- Kademeli toparlanma: bir süre "yavaşla" yanıtı gelmezse hız adım adım başlangıç değerine geri çıkar.
- İptal: cancel() çağrılınca bekleyen/sonraki tüm wait() çağrıları ScanCancelled fırlatır.
- Harici araçlar (httpx, katana, ffuf) aynı RPS değerini kendi bayraklarıyla alır ve sırayla çalıştırılır,
  böylece toplam yük kullanıcının belirlediği sınırı aşmaz.
"""
from __future__ import annotations

import random
import threading
import time

from core.exceptions import ScanCancelled
from core.logger import get_logger

log = get_logger("ratelimit")


class RateLimiter:
    MIN_RPS = 0.5
    RECOVERY_INTERVAL = 30.0     # bu kadar sn sorunsuz geçerse hız bir adım artar
    RECOVERY_FACTOR = 1.5

    def __init__(self, requests_per_second: float, random_delay: tuple[float, float] = (0.0, 0.0)) -> None:
        if requests_per_second <= 0:
            raise ValueError("requests_per_second > 0 olmalı")
        self.initial_rps = float(requests_per_second)
        self.rps = float(requests_per_second)
        lo, hi = (list(random_delay) + [0.0, 0.0])[:2]
        self.random_delay = (max(0.0, float(lo)), max(0.0, float(hi)))
        self._lock = threading.Lock()
        self._next_allowed = time.monotonic()
        self._pause_until = 0.0
        self._last_change = 0.0          # son yavaşlama/toparlanma anı
        self._cancel = threading.Event()

    @property
    def interval(self) -> float:
        return 1.0 / self.rps

    # ------------------------------------------------------------------ iptal
    def cancel(self) -> None:
        self._cancel.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    # ------------------------------------------------------------------ bekleme
    def _reserve_slot(self) -> float:
        with self._lock:
            now = time.monotonic()
            if self.rps < self.initial_rps and now - self._last_change >= self.RECOVERY_INTERVAL:
                old = self.rps
                self.rps = min(self.initial_rps, self.rps * self.RECOVERY_FACTOR)
                self._last_change = now
                log.info(f"Hedef sorunsuz yanıt veriyor; hız {old:g} -> {self.rps:g} istek/sn")
            start = max(now, self._next_allowed, self._pause_until)
            self._next_allowed = start + self.interval
            wait = start - now
        lo, hi = self.random_delay
        if hi > 0:
            wait += random.uniform(lo, max(lo, hi))
        return wait

    def wait(self) -> None:
        """Bir sonraki istek hakkı gelene kadar bloklar (thread-safe). İptal edildiyse ScanCancelled."""
        if self._cancel.is_set():
            raise ScanCancelled("tarama durduruldu")
        delay = self._reserve_slot()
        if delay > 0 and self._cancel.wait(delay):
            raise ScanCancelled("tarama durduruldu")

    def backoff(self, reason: str = "", pause: float = 5.0) -> None:
        """Hedef 'yavaşla' dediğinde: hızı yarıya indir ve kısa süre tüm istekleri durdur.

        Duraklama penceresi içindeyken gelen ek çağrılar yok sayılır: aynı patlamadaki (eşzamanlı
        uçuşta olan) isteklerin her biri hızı ayrı ayrı yarılayıp tek seferde tabana çakmasın."""
        with self._lock:
            now = time.monotonic()
            if now < self._pause_until:
                return
            old = self.rps
            self.rps = max(self.MIN_RPS, self.rps / 2)
            self._pause_until = now + pause
            self._last_change = now
        if old != self.rps:
            log.warning(f"Hedef yavaşlama istedi ({reason}); hız {old:g} -> {self.rps:g} istek/sn")

    def as_tool_flag(self) -> int:
        """Harici araçlara geçirilecek tamsayı RPS değeri (en az 1)."""
        return max(1, int(self.rps))
