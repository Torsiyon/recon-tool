"""Keşif modülleri. Yeni bir modül eklemek için BaseModule'den türetip MODULE_REGISTRY'ye ekleyin."""
from modules.subdomain_recon import SubdomainRecon
from modules.port_scan import PortScanner
from modules.crawler import Crawler
from modules.js_analyzer import JSAnalyzer
from modules.dir_bruteforce import DirBruteforcer
from modules.nuclei_scan import NucleiScanner

# Sıra önemli: her modül bir öncekinin ScanContext'e yazdığı veriyi kullanır.
# Nuclei en sonda çalışır (canlı hostlar + toplanan veriler hazır olduğunda).
MODULE_REGISTRY = {
    SubdomainRecon.name: SubdomainRecon,
    PortScanner.name: PortScanner,
    Crawler.name: Crawler,
    JSAnalyzer.name: JSAnalyzer,
    DirBruteforcer.name: DirBruteforcer,
    NucleiScanner.name: NucleiScanner,
}

__all__ = ["MODULE_REGISTRY", "SubdomainRecon", "PortScanner", "Crawler",
           "JSAnalyzer", "DirBruteforcer", "NucleiScanner"]
