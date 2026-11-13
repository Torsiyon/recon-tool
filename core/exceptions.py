"""Projeye özel hata hiyerarşisi. Modüller yalnızca bunları fırlatır; orkestratör bunları yakalar."""


class ReconError(Exception):
    """Tüm proje hatalarının temel sınıfı."""


class ConfigError(ReconError):
    """Geçersiz veya eksik konfigürasyon."""


class ToolNotFoundError(ReconError):
    """Harici araç (subfinder, httpx, katana, ffuf) PATH'te bulunamadı."""


class ToolExecutionError(ReconError):
    """Harici araç hata koduyla çıktı veya zaman aşımına uğradı."""


class ModuleError(ReconError):
    """Bir keşif modülü çalışırken kurtarılamaz hata oluştu."""


class ScanCancelled(ReconError):
    """Tarama kullanıcı tarafından durduruldu (arayüzdeki Stop / New scan)."""
