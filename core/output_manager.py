"""Modül E: Hedef başına klasör yapısı ve güvenli dosya yazımı.

outputs/<hedef>/
├── subdomains/       canlı ve cansız subdomain listeleri
├── urls/             katana çıktıları ve parametreli linkler
├── js_analysis/      kritik ifşaatlar ve parse edilmiş js listeleri
├── directory_brute/  bulunan hassas dizinler ve yedek dosyaları
└── summary.json / report.md
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from core.exceptions import ReconError
from core.logger import get_logger

log = get_logger("output")

SUBDIRS = ("subdomains", "urls", "js_analysis", "directory_brute")


class OutputManager:
    def __init__(self, base_dir: Path, target: str) -> None:
        self.root = Path(base_dir) / self._safe_name(target)
        self.dirs: dict[str, Path] = {name: self.root / name for name in SUBDIRS}

    @staticmethod
    def _safe_name(target: str) -> str:
        """Domain'i dosya sistemi için güvenli hale getirir (path traversal'a karşı)."""
        name = re.sub(r"[^A-Za-z0-9._-]", "_", target.strip().lower()).strip(".")
        return name or "unknown_target"

    def prepare(self) -> None:
        try:
            for path in self.dirs.values():
                path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ReconError(f"Çıktı klasörleri oluşturulamadı ({self.root}): {exc}") from exc
        log.info(f"Çıktı dizini: {self.root}")

    def path(self, section: str, filename: str) -> Path:
        base = self.root if section == "root" else self.dirs.get(section)
        if base is None:
            raise ReconError(f"Bilinmeyen çıktı bölümü: {section}")
        target = (base / filename).resolve()
        if not target.is_relative_to(base.resolve()):
            raise ReconError(f"Geçersiz dosya adı: {filename}")
        target.parent.mkdir(parents=True, exist_ok=True)
        return target

    def write_lines(self, section: str, filename: str, lines: Iterable[str], sort: bool = True) -> Path:
        target = self.path(section, filename)
        cleaned = [l.strip() for l in lines if l and l.strip()]
        items = sorted(set(cleaned)) if sort else list(dict.fromkeys(cleaned))
        try:
            target.write_text("\n".join(items) + ("\n" if items else ""), encoding="utf-8")
        except OSError as exc:
            raise ReconError(f"Dosya yazılamadı ({target}): {exc}") from exc
        log.debug(f"{len(items)} satır -> {target}")
        return target

    def write_text(self, section: str, filename: str, text: str) -> Path:
        target = self.path(section, filename)
        try:
            target.write_text(text, encoding="utf-8")
        except OSError as exc:
            raise ReconError(f"Dosya yazılamadı ({target}): {exc}") from exc
        return target

    def write_json(self, section: str, filename: str, data: Any) -> Path:
        target = self.path(section, filename)
        try:
            target.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        except (OSError, TypeError, ValueError) as exc:
            raise ReconError(f"JSON yazılamadı ({target}): {exc}") from exc
        return target
