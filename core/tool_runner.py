"""Harici CLI araçlarını (subfinder, httpx, katana, ffuf, nmap, nuclei) güvenli şekilde çalıştıran sarmalayıcı."""
from __future__ import annotations

import os
import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from core.exceptions import ScanCancelled, ToolExecutionError, ToolNotFoundError
from core.logger import get_logger

log = get_logger("runner")


def _extra_search_dirs() -> list[str]:
    """Go araçlarının sık kurulduğu ama PATH'te olmayabilen dizinler (GOBIN, GOPATH/bin, ~/go/bin)."""
    cands: list[Path] = []
    if os.environ.get("GOBIN"):
        cands.append(Path(os.environ["GOBIN"]))
    for gopath in (os.environ.get("GOPATH") or "").split(os.pathsep):
        if gopath:
            cands.append(Path(gopath) / "bin")
    cands.append(Path.home() / "go" / "bin")
    return [str(d) for d in dict.fromkeys(cands) if d.is_dir()]


@dataclass
class ToolResult:
    returncode: int
    stdout: str
    stderr: str


class ToolRunner:
    def __init__(self, tool_paths: dict[str, str], default_timeout: int | None = None) -> None:
        self.tool_paths = tool_paths
        self.default_timeout = default_timeout
        self._cache: dict[str, str | None] = {}
        self._procs: set[subprocess.Popen] = set()
        self._lock = threading.Lock()
        self._cancelled = False

    def _find(self, binary: str) -> str | None:
        found = shutil.which(binary)
        if found:
            return found
        # shutil.which platform uzantılarını da dener (Windows'ta subfinder.exe gibi)
        dirs = _extra_search_dirs()
        return shutil.which(binary, path=os.pathsep.join(dirs)) if dirs else None

    def _verify(self, tool: str, path: str) -> bool:
        """Aynı isimli yanlış aracı ayıkla (ör. Python 'httpx' CLI'si ProjectDiscovery httpx değildir)."""
        if tool != "httpx":
            return True
        try:
            proc = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=20, check=False)
        except (OSError, subprocess.SubprocessError):
            return False
        text = (proc.stdout + proc.stderr).lower()
        if "projectdiscovery" in text or "current version" in text:
            return True
        log.warning(f"'{path}' ProjectDiscovery httpx değil gibi görünüyor (Python httpx olabilir); yok sayılıyor.")
        return False

    def resolve(self, tool: str) -> str:
        with self._lock:
            if tool not in self._cache:
                binary = self.tool_paths.get(tool, tool)
                path = self._find(binary)
                self._cache[tool] = path if path and self._verify(tool, path) else None
            path = self._cache[tool]
        if not path:
            raise ToolNotFoundError(f"'{tool}' bulunamadı veya doğrulanamadı. Kurulum için README'ye bakın.")
        return path

    def is_available(self, tool: str) -> bool:
        try:
            self.resolve(tool)
            return True
        except ToolNotFoundError:
            return False

    # ------------------------------------------------------------------ iptal
    def cancel(self) -> None:
        """Çalışan tüm alt süreçleri sonlandırır; sonraki run() çağrıları ScanCancelled fırlatır."""
        with self._lock:
            self._cancelled = True
            procs = list(self._procs)
        for p in procs:
            try:
                p.kill()
            except OSError:
                pass

    # ------------------------------------------------------------------ çalıştırma
    def run(
        self,
        tool: str,
        args: list[str],
        stdin: str | None = None,
        timeout: int | None = None,
        ok_codes: tuple[int, ...] = (0,),
        on_stderr: Callable[[str], None] | None = None,
        on_stdout: Callable[[str], None] | None = None,
    ) -> ToolResult:
        """Komutu shell=False ile çalıştırır (komut enjeksiyonuna karşı).

        on_stderr verilirse araç çalışırken stderr parça parça bu fonksiyona iletilir (ilerleme okumak için).
        on_stdout verilirse stdout SATIR SATIR, üretildiği anda iletilir (ör. nuclei JSONL bulguları);
        tam çıktı yine de ToolResult.stdout içinde döner.
        Zaman aşımı araç hiç çıktı üretmese de işler; Ctrl+C / iptal durumunda alt süreç öldürülür.
        """
        cmd = [self.resolve(tool), *[str(a) for a in args]]
        timeout = timeout or self.default_timeout
        if self._cancelled:
            raise ScanCancelled("tarama durduruldu")
        log.debug("Çalıştırılıyor: %s", " ".join(cmd))
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as exc:
            raise ToolExecutionError(f"{tool} başlatılamadı: {exc}") from exc
        with self._lock:
            self._procs.add(proc)
        data = stdin.encode("utf-8") if stdin is not None else None
        try:
            if on_stderr is None and on_stdout is None:
                out, err = proc.communicate(data, timeout=timeout)
            else:
                out, err = self._pump(proc, data, timeout, on_stderr, on_stdout)
        except subprocess.TimeoutExpired as exc:
            self._kill(proc)
            raise ToolExecutionError(f"{tool} zaman aşımına uğradı ({timeout}s)") from exc
        except BaseException:
            self._kill(proc)   # Ctrl+C / docker stop: alt süreç de dursun
            raise
        finally:
            with self._lock:
                self._procs.discard(proc)
        if self._cancelled:
            raise ScanCancelled("tarama durduruldu")
        stdout = out.decode("utf-8", errors="replace")
        stderr = err.decode("utf-8", errors="replace")
        if proc.returncode not in ok_codes:
            raise ToolExecutionError(f"{tool} hata kodu {proc.returncode}: {stderr.strip()[-500:]}")
        return ToolResult(proc.returncode, stdout, stderr)

    @staticmethod
    def _kill(proc: subprocess.Popen) -> None:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass

    @staticmethod
    def _pump(proc: subprocess.Popen, data: bytes | None, timeout: int | None,
              on_stderr: Callable[[str], None] | None,
              on_stdout: Callable[[str], None] | None = None) -> tuple[bytes, bytes]:
        """stdout'u biriktirir (istenirse satır satır on_stdout'a da verir), stderr'i canlı olarak
        on_stderr'e iletir. Okuma ayrı iş parçacıklarında yapılır; böylece araç sessizce takılsa bile
        ana iş parçacığındaki zaman aşımı çalışır."""
        out_chunks: list[bytes] = []
        err_tail = bytearray()

        def call(cb: Callable[[str], None], raw: bytes) -> None:
            try:
                cb(raw.decode("utf-8", errors="replace"))
            except Exception as exc:  # geri çağrı hatası aracı durdurmasın
                log.debug(f"çıktı geri çağrısı hatası: {exc}")

        def read_stdout() -> None:
            pending = b""
            for chunk in iter(lambda: proc.stdout.read1(65536), b""):
                out_chunks.append(chunk)
                if on_stdout is not None:
                    *lines, pending = (pending + chunk).split(b"\n")
                    for line in lines:
                        call(on_stdout, line)
            if on_stdout is not None and pending:
                call(on_stdout, pending)

        def read_stderr() -> None:
            for chunk in iter(lambda: proc.stderr.read1(8192), b""):
                err_tail.extend(chunk)
                del err_tail[:-4000]
                if on_stderr is not None:
                    call(on_stderr, chunk)

        readers = [threading.Thread(target=read_stdout, daemon=True),
                   threading.Thread(target=read_stderr, daemon=True)]
        for t in readers:
            t.start()
        if data is not None:
            try:
                proc.stdin.write(data)
                proc.stdin.close()
            except OSError:
                pass
        proc.wait(timeout=timeout)
        for t in readers:
            t.join(timeout=5)
        return b"".join(out_chunks), bytes(err_tail)
