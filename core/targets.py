"""Hedef (host / IP) ayrıştırma yardımcıları. CLI (--targets) ve web arayüzü (Direct mod) ortak kullanır."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_*-]{1,63}\.)+[a-z]{2,63}$")
# Basit IPv4 doğrulaması (0-255 oktetler). Direct modda IP hedefleri için.
IPV4_RE = re.compile(r"^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$")


def parse_targets(raw: str) -> list[str]:
    """Serbest metinden host listesi: URL/scheme/port ayıklanır, geçerli host/IPv4'ler (sıra korunarak,
    tekilleştirilmiş) döner. Satır sonu ya da virgül ayırıcıdır; '#' ile başlayan satırlar yorumdur."""
    hosts: list[str] = []
    for line in raw.replace(",", "\n").splitlines():
        t = line.strip().lower()
        if not t or t.startswith("#"):
            continue
        if "://" in t:
            t = urlsplit(t).hostname or ""
        else:
            t = t.split("/")[0].split(":")[0]
        t = t.strip(".").lstrip("*.")
        if t and (HOST_RE.match(t) or IPV4_RE.match(t)):
            hosts.append(t)
    return list(dict.fromkeys(hosts))


def direct_label(target: str) -> str:
    """Direct modda çıktı klasörü için güvenli bir etiket üretir (domain doğrulaması yok).
    target boşsa 'direct-scan' kullanılır; IP/host ise dosya-güvenli biçime getirilir."""
    raw = (target or "").strip().lower()
    raw = re.sub(r"^[a-z]+://", "", raw).split("/")[0].split(":")[0].strip(".")
    safe = re.sub(r"[^a-z0-9._-]", "_", raw)
    return safe or "direct-scan"
