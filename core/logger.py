"""Merkezi loglama (rich destekli, yoksa standart logging)."""
import logging
import sys

try:
    from rich.console import Console
    from rich.logging import RichHandler
    # Log satırları ve ilerleme çubukları AYNI konsolu kullanır ki birbirine karışmasın
    CONSOLE = Console(stderr=True)
    _HANDLER = RichHandler(console=CONSOLE, rich_tracebacks=True, show_path=False)
except ImportError:  # rich kurulu değilse düz loglama
    CONSOLE = None
    _HANDLER = logging.StreamHandler()

_CONFIGURED = False


def setup_logging(level: str = "INFO") -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    logging.basicConfig(level=level.upper(), format="%(message)s", datefmt="[%X]", handlers=[_HANDLER])
    _CONFIGURED = True


def is_interactive() -> bool:
    """Gerçek bir terminal mi? (Docker -t olmadan, CI veya dosyaya yönlendirmede False)"""
    return CONSOLE is not None and CONSOLE.is_terminal and sys.stderr.isatty()


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"recon.{name}")
