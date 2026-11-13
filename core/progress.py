"""İlerleme sayacı: "kaç kelimeden kaçı denendi".

- Gerçek terminalde: canlı ilerleme çubuğu (yüzde, x/y, hız, kalan süre, bulgu sayısı).
- Terminal yoksa (docker run -t olmadan, CI, dosyaya yönlendirme): her `log_interval` saniyede
  bir ve bitişte tek satırlık log:  "[2/5] http://x: 1200/4700 (%25) | 9.8 istek/sn | bulgu: 3 | kalan ~6dk"
"""
from __future__ import annotations

import threading
import time

from core.logger import CONSOLE, get_logger, is_interactive

log = get_logger("progress")


def fmt_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    if seconds < 60:
        return f"{seconds}sn"
    if seconds < 3600:
        return f"{seconds // 60}dk {seconds % 60:02d}sn"
    return f"{seconds // 3600}sa {(seconds % 3600) // 60:02d}dk"


class ProgressCounter:
    def __init__(self, label: str, total: int, log_interval: float = 15.0, live: bool | None = None) -> None:
        self.label = label
        self.total = max(0, int(total))
        self.done = 0
        self.found = 0
        self.errors = 0
        self.log_interval = log_interval
        self._lock = threading.Lock()
        self._start = time.monotonic()
        self._last_log = self._start
        self._bar = None
        self._task = None
        if (is_interactive() if live is None else live) and CONSOLE is not None:
            from rich.progress import (BarColumn, MofNCompleteColumn, Progress, TaskProgressColumn,
                                       TextColumn, TimeRemainingColumn)
            self._bar = Progress(
                TextColumn("{task.description}"), BarColumn(), MofNCompleteColumn(), TaskProgressColumn(),
                TextColumn("{task.fields[rate]:.1f} istek/sn"), TextColumn("bulgu: {task.fields[found]}"),
                TimeRemainingColumn(), console=CONSOLE, transient=True,
            )
            self._task = self._bar.add_task(label, total=self.total or None, rate=0.0, found=0)
            self._bar.start()

    # ------------------------------------------------------------------ güncelleme
    def advance(self, n: int = 1, found: int = 0, error: bool = False) -> None:
        with self._lock:
            self.done += n
            self.found += found
            self.errors += int(error)
            self._refresh()

    def set(self, done: int, total: int | None = None, errors: int | None = None) -> None:
        """Dış araçtan (ffuf) gelen mutlak değerlerle güncelle."""
        with self._lock:
            self.done = max(self.done, int(done))
            if total:
                self.total = int(total)
            if errors is not None:
                self.errors = int(errors)
            self._refresh()

    @property
    def rate(self) -> float:
        elapsed = time.monotonic() - self._start
        return self.done / elapsed if elapsed > 0 else 0.0

    def eta(self) -> float | None:
        r = self.rate
        return (self.total - self.done) / r if r > 0 and self.total else None

    def line(self) -> str:
        pct = f" (%{self.done * 100 // self.total})" if self.total else ""
        eta = self.eta()
        parts = [f"{self.label}: {self.done}/{self.total}{pct}", f"{self.rate:.1f} istek/sn", f"bulgu: {self.found}"]
        if self.errors:
            parts.append(f"hata: {self.errors}")
        if eta is not None and self.done < self.total:
            parts.append(f"kalan ~{fmt_duration(eta)}")
        return " | ".join(parts)

    def _refresh(self) -> None:
        if self._bar is not None:
            self._bar.update(self._task, completed=self.done, total=self.total or None,
                             rate=self.rate, found=self.found)
            return
        now = time.monotonic()
        if now - self._last_log >= self.log_interval:
            self._last_log = now
            log.info(self.line())

    # ------------------------------------------------------------------ bitiş
    def close(self) -> None:
        if self._bar is not None:
            self._bar.stop()
            self._bar = None
        took = fmt_duration(time.monotonic() - self._start)
        log.info(f"{self.label}: {self.done}/{self.total} denendi, {self.found} bulgu"
                 + (f", {self.errors} hata" if self.errors else "") + f" ({took})")

    def __enter__(self) -> "ProgressCounter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
