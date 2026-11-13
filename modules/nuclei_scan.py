"""Nuclei entegrasyonu: CVE ve yanlış yapılandırma şablonlarıyla zafiyet taraması.

GÜVENLİK İLKELERİ:
  * Varsayılan GÜVENLİ: zarar verebilecek şablonlar (dos, intrusive, fuzz, brute...)
    varsayılan olarak DIŞLANIR. Yetkisiz/hassas hedefte tehlikeli şablon çalışmaz.
  * "intrusive" mod yalnızca kullanıcı AÇIKÇA açarsa devreye girer (opt-in + uyarı).
  * Kullanıcı istediğinde ek etiket/şablonları dışlayabilir.
  * Teknoloji/sürüme özel kendi şablon dizinini/dosyasını ekleyebilir (-t).
  * Yalnızca kapsam içi canlı hostlarda, mevcut rate limit'e uyarak çalışır.

CVSS: sezgisel üretilmez. Yalnızca Nuclei şablonunun taşıdığı resmî CVSS puanı/vektörü kullanılır.

Nuclei yoksa modül sessizce atlanır (uydurma CVE üretmez).

Çıktılar (outputs/<hedef>/nuclei/):
  findings.txt / findings.json
"""
from __future__ import annotations

import json

from core import security_checks as sec
from core.config import TOOL_DEFAULT_FLAGS
from core.exceptions import ToolExecutionError
from modules.base import BaseModule, ScanContext

# Zarar verebilecek / gürültülü şablon etiketleri — güvenli modda daima dışlanır.
DANGEROUS_TAGS = ["dos", "intrusive", "fuzz", "fuzzing", "brute", "bruteforce"]

SEVERITY_MAP = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
    "low": "LOW", "info": "INFO", "unknown": "INFO", "": "INFO",
}


class NucleiScanner(BaseModule):
    name = "nuclei"
    description = "Nuclei: CVE/yanlış yapılandırma taraması (güvenli varsayılan)"
    optional_tools = ("nuclei",)

    def run(self, ctx: ScanContext) -> None:
        self._emit = ctx.emit
        ctx.findings.setdefault("nuclei", [])
        if not self.runner.is_available("nuclei"):
            self.log.warning("nuclei bulunamadı — zafiyet taraması atlandı (sezgisel CVE ÜRETİLMEZ).")
            ctx.stats["nuclei_available"] = False
            return
        ctx.stats["nuclei_available"] = True
        if not ctx.live_hosts:
            self.log.warning("Canlı host yok, nuclei taraması atlandı.")
            return

        cfg = self.config.nuclei if hasattr(self.config, "nuclei") else {}
        targets = [h.url for h in ctx.live_hosts]
        intrusive = bool(cfg.get("intrusive", False))

        # -jsonl zorunlu (çıktı ayrıştırma için, kaldırılamaz); davranış bayrakları düzenlenebilir
        # (varsayılan: -silent -nc -duc). -rate-limit/-timeout hız ayarından gelir.
        args = ["-jsonl"] + self.config.flags("nuclei", TOOL_DEFAULT_FLAGS["nuclei"]) + [
                "-rate-limit", str(self.limiter.as_tool_flag()),   # 429 sonrası düşen hız da yansır
                "-timeout", str(self.config.rate_limit.timeout),
                "-retries", "1"]

        # Şablon dizini: nuclei NUCLEI_TEMPLATES_DIR ortam değişkenini kendiliğinden okur
        # (Docker imajında gömülü şablonlar buraya ayarlıdır). İstenirse config ile -ud geçilebilir.
        tpl_dir = cfg.get("templates_dir")
        if tpl_dir:
            args += ["-update-template-dir", str(tpl_dir)]

        # --- GÜVENLİK: tehlikeli etiketleri dışla (intrusive opt-in değilse) ---
        exclude_tags = list(DANGEROUS_TAGS) if not intrusive else []
        exclude_tags += [t.strip() for t in (cfg.get("exclude_tags") or []) if t.strip()]
        if exclude_tags:
            args += ["-exclude-tags", ",".join(dict.fromkeys(exclude_tags))]
        if intrusive:
            self.log.warning("INTRUSIVE MOD AÇIK: tehlikeli şablonlar DIŞLANMIYOR. Yalnızca yetkili hedefte kullanın.")

        # Severity filtresi (ops.)
        if cfg.get("severity"):
            args += ["-severity", ",".join(cfg["severity"])]
        # Belirli etiketlerle sınırla (ops.)
        if cfg.get("tags"):
            args += ["-tags", ",".join(cfg["tags"])]
        # Kullanıcının eklediği özel şablonlar (teknoloji/sürüme özel): dizin ya da dosya
        for tpl in cfg.get("templates") or []:
            args += ["-t", str(tpl)]
        # Dışlanacak şablonlar
        for tpl in cfg.get("exclude_templates") or []:
            args += ["-exclude-templates", str(tpl)]
        # Header / proxy
        for k, v in self.config.headers.items():
            args += ["-H", f"{k}: {v}"]
        if self.config.proxy:
            args += ["-proxy", self.config.proxy]
        if cfg.get("concurrency"):
            args += ["-c", str(cfg["concurrency"])]

        self.log.info(f"nuclei başlıyor: {len(targets)} hedef | "
                      f"mod: {'INTRUSIVE' if intrusive else 'güvenli'} | "
                      f"dışlanan etiketler: {','.join(exclude_tags) or '(yok)'}")
        # Bulgular nuclei yazdığı ANDA işlenir ve arayüze düşer (önceden tarama bitene kadar hiçbir
        # şey görünmüyordu). Liste baştan ctx'e bağlanır: tarama durdurulsa / zaman aşımına uğrasa da
        # o ana kadarki bulgular rapora girer.
        findings: list[dict] = []
        ctx.findings["nuclei"] = findings

        def on_line(line: str) -> None:
            f = self._parse_line(line)
            if f is not None:
                findings.append(f)
                self._emit("finding", f)
                self.log.info(f"nuclei [{f['severity']}] {f['target']} — {f['title']}")

        try:
            self.runner.run("nuclei", args, stdin="\n".join(targets) + "\n", on_stdout=on_line)
        except ToolExecutionError as exc:
            self.log.error(f"nuclei hatası (o ana kadarki {len(findings)} bulgu korunuyor): {exc}")

        findings.sort(key=sec.sort_key)
        counts = sec.severity_counts(findings)
        ctx.stats["nuclei_findings"] = len(findings)
        ctx.stats["nuclei_counts"] = counts
        self.log.info(f"nuclei bulguları: {len(findings)} {counts}")
        self._save(findings)

    # ------------------------------------------------------------------ parse
    def _parse(self, stdout: str) -> list[dict]:
        return [f for f in map(self._parse_line, stdout.splitlines()) if f is not None]

    def _parse_line(self, line: str) -> dict | None:
        """Tek bir nuclei JSONL satırını birleşik bulgu modeline çevirir (bulgu değilse None)."""
        line = line.strip()
        if not line.startswith("{"):
            return None
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(d, dict):
            return None
        info = d.get("info") or {}
        sev = SEVERITY_MAP.get(str(info.get("severity", "")).lower(), "INFO")
        cvss, cve = self._cvss_cve(info)
        # Gerçek CVSS varsa ve Nuclei severity'si eksik/belirsizse CVSS'ten türet
        if cvss is not None and str(info.get("severity", "")).lower() in ("", "unknown"):
            sev = sec.severity_from_cvss(cvss) or sev
        target = d.get("matched-at") or d.get("host") or d.get("matched_at") or ""
        title = info.get("name") or d.get("template-id") or "nuclei bulgusu"
        tags = info.get("tags")
        tag_str = ",".join(tags) if isinstance(tags, list) else str(tags or "")
        ev = d.get("template-id", "")
        if cve:
            ev = f"{cve} · {ev}" if ev else cve
        return sec.finding(
            sev, "cve" if cve else "nuclei", target, title,
            detail=(info.get("description") or "").strip()[:300],
            evidence=(ev + (f" [{tag_str}]" if tag_str else ""))[:300],
            remediation=(info.get("remediation") or "").strip()[:300],
            cvss=cvss, cve=cve)

    @staticmethod
    def _cvss_cve(info: dict) -> tuple[float | None, str]:
        cls = info.get("classification") or {}
        cvss = None
        score = cls.get("cvss-score")
        try:
            if score is not None:
                cvss = float(score)
        except (TypeError, ValueError):
            cvss = None
        cve = cls.get("cve-id") or info.get("cve-id") or ""
        if isinstance(cve, list):
            cve = ", ".join(str(c) for c in cve)
        return cvss, str(cve).upper()

    # ------------------------------------------------------------------ kayıt
    def _save(self, findings: list[dict]) -> None:
        lines = []
        for f in findings:
            cvss = f" CVSS {f['cvss']}" if f.get("cvss") is not None else ""
            lines.append(f"[{f['severity']}]{cvss} {f['target']} — {f['title']}"
                         + (f"  ({f['evidence']})" if f.get("evidence") else ""))
        self.output.write_lines("root", "nuclei/findings.txt", lines, sort=False)
        self.output.write_json("root", "nuclei/findings.json", findings)
