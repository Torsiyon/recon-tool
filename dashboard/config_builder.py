"""Arayüz girdilerini (hedef, hız, wordlist vb.) bir Config nesnesine çevirir."""
from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

from core.config import PROJECT_ROOT, Config
from core.targets import direct_label as _direct_label
from recon import normalize_domain


def prepare_custom_wordlist(words_text: str) -> Path | None:
    """Arayüzdeki text-area içeriğini geçici bir dosyaya yazar (harici wordlist'lere dokunmadan).
    Boşsa None döner."""
    lines = [w.strip() for w in words_text.splitlines() if w.strip() and not w.strip().startswith("#")]
    if not lines:
        return None
    tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", prefix="recon_ui_wl_", delete=False, encoding="utf-8")
    tmp.write("\n".join(dict.fromkeys(lines)) + "\n")
    tmp.close()
    return Path(tmp.name)


def build_config(
    target: str,
    rate_limit: float,
    threads: int,
    timeout: int,
    output_dir: str,
    dir_engine: str = "auto",
    custom_words: str = "",
    only_custom_wordlist: bool = False,
    proxy: str | None = None,
    headers: list[str] | None = None,
    wordlist_files: list[tuple[str, str]] | None = None,
    auto_tech: bool = True,
    nuclei_intrusive: bool = False,
    nuclei_templates: list[str] | None = None,
    nuclei_exclude_tags: list[str] | None = None,
    nuclei_severity: list[str] | None = None,
    tool_args: dict[str, object] | None = None,
    direct: bool = False,
) -> Config:
    """Arayüz formundan Config üretir.
    direct=False: normalize_domain geçersiz domaini ConfigError ile reddeder (Full recon).
    direct=True : ana domain zorunlu değil; target yalnızca çıktı klasörü etiketidir (IP de olabilir)."""
    norm = _direct_label(target) if direct else normalize_domain(target)
    overrides = {
        "rate_limit": rate_limit,
        "threads": threads,
        "timeout": timeout,
        "output_dir": output_dir,
        "dir_engine": dir_engine,
        "proxy": proxy or None,
        "headers": headers or [],
    }
    wl = prepare_custom_wordlist(custom_words)
    if wl:
        overrides["wordlist"] = str(wl)
    cfg = Config.load(norm, overrides=overrides)
    cfg.direct = bool(direct)
    # Arayüzden gelen açık wordlist seçimi (yüklenen .txt'ler + tikli yerleşikler)
    if wordlist_files is not None:
        cfg.dir_bruteforce["common_wordlists"] = [p for p, _ in wordlist_files]
        cfg.dir_bruteforce["_category_map"] = {
            str(Path(p).resolve()): c for p, c in wordlist_files
        }
    if not auto_tech:
        cfg.dir_bruteforce["tech_wordlists"] = {}
    # Nuclei güvenlik ayarları (arayüzden). Varsayılan GÜVENLİ: intrusive kapalı.
    if tool_args:
        for tool, val in tool_args.items():
            if val:
                cfg.tool_args[str(tool)] = (val if isinstance(val, list)
                                            else __import__("shlex").split(str(val)))
            else:
                cfg.tool_args.pop(str(tool), None)   # boş = varsayılanı (ör. -all) kaldır
    cfg.nuclei["intrusive"] = bool(nuclei_intrusive)
    if nuclei_templates:
        cfg.nuclei["templates"] = list(nuclei_templates)
    if nuclei_exclude_tags:
        cfg.nuclei["exclude_tags"] = list(nuclei_exclude_tags)
    if nuclei_severity:
        cfg.nuclei["severity"] = list(nuclei_severity)
    seed = os.environ.get("RECON_EXTRA_SUBS")   # ops.: elde subdomain listesi (subfinder sonuçlarına eklenir)
    if seed and Path(seed).is_file():
        cfg.extra_subdomains = Path(seed)
    if only_custom_wordlist and wl:
        # Yerleşik listeleri devre dışı bırak, yalnızca kullanıcının listesini kullan
        cfg.dir_bruteforce["common_wordlists"] = []
        cfg.dir_bruteforce["tech_wordlists"] = {}
    return cfg


def default_wordlist_text(config: Config) -> str:
    """Text-area'yı dolduracak varsayılan içerik: yerleşik genel listelerin birleşimi."""
    from core.config import PROJECT_ROOT
    seen: dict[str, None] = {}
    for rel in config.dir_bruteforce.get("common_wordlists", []):
        p = PROJECT_ROOT / rel
        try:
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    seen.setdefault(line, None)
        except OSError:
            continue
    return "\n".join(seen)


# Arayüzdeki tik listesi için yerleşik wordlist kataloğu: (etiket, path, kategori)
BUILTIN_WORDLISTS = [
    ("Hassas dosyalar (.git, .env, config...)", "wordlists/common/sensitive.txt", "sensitive"),
    ("Yedek dosyaları (.zip, .bak, .sql...)", "wordlists/common/backups.txt", "backup"),
    ("Yaygın dizinler (admin, api, backup...)", "wordlists/common/dirs.txt", "common"),
]


def builtin_wordlists() -> list[tuple[str, str, str]]:
    """(etiket, mutlak_path, kategori) listesi; yalnızca var olan dosyalar."""
    out = []
    for label, rel, cat in BUILTIN_WORDLISTS:
        p = PROJECT_ROOT / rel
        if p.is_file():
            n = sum(1 for _ in p.open(encoding="utf-8", errors="replace"))
            out.append((f"{label} · {n} satır", str(p), cat))
    return out


def save_uploaded_wordlist(name: str, data: bytes, dest_dir: Path) -> Path:
    """Yüklenen .txt wordlist'i kalıcı (oturum) bir klasöre yazar, path döner."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name) or "wordlist.txt"
    path = dest_dir / safe
    path.write_bytes(data)
    return path


def guess_category(filename: str) -> str:
    """Yüklenen dosya adından kategori tahmini (çıktı dosyası sınıflandırması için)."""
    n = filename.lower()
    if "backup" in n or "yedek" in n:
        return "backup"
    if "sensitive" in n or "secret" in n or "hassas" in n:
        return "sensitive"
    return "custom"
