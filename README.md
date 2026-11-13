# Recon

> **English summary.** Recon is a modular reconnaissance tool for **authorized** bug bounty and pentest
> targets. It chains subfinder, httpx, nmap, katana, ffuf and nuclei into one pipeline — subdomain
> discovery, liveness and technology detection, TLS/security-header/CORS checks, port and service
> scanning, crawling, secret detection in JavaScript files, technology-aware directory brute-forcing and
> vulnerability scanning — and merges everything into a single severity-ranked report. It runs from the
> command line or a Streamlit web dashboard, respects one shared rate limit across all stages, and falls
> back to built-in Python engines when an external tool is not installed.
>
> Quick start: `pip install -r requirements.txt`, then `python recon.py -d example.com` or
> `streamlit run app.py`. With Docker: `docker compose up dashboard` and open http://localhost:8501.
> The rest of this document is in Turkish. **Only scan systems you own or have written permission to test.**

<!-- Ekran görüntüsü eklemek için: görseli docs/dashboard.png olarak kaydedin ve aşağıdaki satırın
     başındaki ve sonundaki yorum işaretlerini kaldırın.
![Recon Dashboard](docs/dashboard.png)
-->

Yetkili bug bounty / pentest hedefleri için modüler keşif aracı. subfinder, httpx, nmap, katana, ffuf ve
nuclei'yi orkestre eder; bulguları hedef başına düzenli bir klasör yapısında saklar.

> ## Yalnızca izinli hedeflerde kullanın
>
> Bu araç **yalnızca sahibi olduğunuz ya da yazılı test izniniz (bug bounty kapsamı, pentest
> sözleşmesi, staj/iş yetkisi vb.) bulunan hedeflerde** kullanılır. İzniniz olmayan sistemleri
> taramak çoğu ülkede **suçtur**. Kapsamı ve izni açıkça tanımlanmış hedefler dışında
> çalıştırmayın; kapsam dışı hiçbir host/IP girmeyin. Sorumluluk tümüyle kullanıcıya aittir.
>
> Ayrıntılı kurallar için aşağıdaki [Yasal Uyarı / Etik Kullanım](#yasal-uyarı--etik-kullanım)
> bölümüne bakın.

## Yasal Uyarı / Etik Kullanım
**Bu araç yalnızca izinli ve kapsamı tanımlı hedeflerde kullanılmak üzere yapılmıştır.** Çalıştırmadan önce:

- **İzin:** Taradığınız her host/IP için sahiplik ya da açık yazılı test izniniz olduğundan emin olun
  (bug bounty programının kapsamı, pentest/staj sözleşmesi, kendi laboratuvarınız). Yetkisiz tarama
  birçok hukukta cezai sorumluluk doğurur.
- **Kapsam:** "Direct mod" ile elle host/IP girerken kapsam dışı hiçbir adres girmeyin. Program kuralları
  bir alt alan adını ya da yolu kapsam dışı bırakıyorsa onu taramayın.
- **Hız & yük:** Varsayılan hız 10 istek/sn'dir; programın/sözleşmenin kurallarına göre `--rate-limit` ile
  düşürün. Araç tek paylaşımlı limiter kullanır ve 429/503 görünce hızı otomatik yarıya indirir
  (aynı patlamada yalnızca bir kez); hedef 30 sn sorunsuz yanıt verirse hız kademeli olarak geri çıkar.
- **Zararsız varsayılan:** Nuclei **güvenli modda** çalışır — `dos, intrusive, fuzz, brute` etiketli zararlı
  şablonlar dışlanır. "Intrusive" modu yalnızca açık izinli hedefte, bilerek açın. CVSS sezgisel üretilmez;
  yalnızca şablonun resmî puanı kullanılır.
- **Sorumluluk:** Bu aracın kullanımından doğan tüm sorumluluk kullanıcıya aittir. Yazarlar yetkisiz ya da
  kötü niyetli kullanımdan sorumlu değildir.

## Kurulum
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Go araçları (Go 1.26+; güncel ProjectDiscovery sürümleri bunu istiyor). Kurulu değilse araç dahili Python motorlarına düşer.
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/ffuf/ffuf/v2@latest

python recon.py --check-tools      # hangi araçların bulunduğunu gösterir (~/go/bin de aranır)
```

## Web Dashboard (Streamlit)
`app.py`, backend motorunun üzerinde interaktif bir arayüzdür. Varsayılan **Quick scan** tüm aşamaları baştan sona
otomatik çalıştırır; **Expert mode** açıkken tarama adım adım ilerler ve her aşamada kontrol sizdedir.
Canlı hostlar, bulgular ve nuclei sonuçları tarama sürerken tabloya düşer.

```bash
pip install -r requirements.txt
streamlit run app.py              # http://localhost:8501
# ya da Docker:
docker compose up dashboard       # http://localhost:8501
```

Özellikler:
- **Hedef & hız:** Arayüzden domain ve bir slider ile `--rate-limit` (RPS), ayrıca thread/timeout/proxy.
- **Adım adım mod:** Her modül (A→B→JS→C) bitince durur, özet istatistik verir, "Sonraki Aşama" butonu beklenir.
- **Dinamik kapsam:** Modül A bitince canlı hostlar checkbox'lı tabloda listelenir; işaretlediğiniz hostlar
  dışındakiler kapsamdan çıkar ve sonraki Crawl/JS/Dizin modülleri YALNIZCA seçili hostlarda çalışır.
- **Canlı 403 & JS alarmı:** 403 durum kodları ve kritik JS sızıntıları kırmızı alarm kutusu + durum koduna
  göre filtrelenebilir tablo ve grafik olarak anlık ekrana düşer; durum kodu/metin ile canlı arama yapılır.
- **Wordlist yönetimi:** Dizin taramasında kullanılacak listeler tik kutularıyla seçilir. Kendi `.txt`
  listenizi **yükleyip** yerleşiklerin (hassas / yedek / yaygın dizin) üzerine ekleyebilir; ya da örneğin
  yalnızca "Yedek" listesini tikleyip sadece onunla tarayabilirsiniz. "Teknolojiye göre otomatik" seçeneği
  ve elle kelime kutusu da ayrı tiklerle açılıp kapanır.
- **Sürüm ifşası uyarısı:** Yanıt başlıklarında (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator` vb.)
  sürüm/banner sızıntısı tespit edilir; dashboard'da turuncu alarm + ayrı sekme, dosyada `compliance/version_disclosure.txt`.
- **Keşfi atlama (Direct mod):** Hedefleri elle girip subdomain keşfini atlayarak doğrudan tararsınız.
  Ana domain **zorunlu değildir**; girilen host ya da **IP** adreslerinin her biri tek tek ele alınır,
  kapsam = tam olarak girdikleriniz (IP listesi senaryosu için uygundur). "Çalışacak aşamalar" ile
  hangi modüllerin koşacağı seçilir.
- **Tool commands (araç komutları):** "Tool commands" bölümünde subfinder/httpx/nmap/nuclei bayraklarını
  doğrudan düzenlersiniz: hazır gelir, bayrak **ekleyebilir ya da çıkarabilirsiniz** (ör. nmap'ten `-sV`'yi
  silip sürüm tespitini kapatmak, ya da subfinder'dan `-all`'ı çıkarmak). Çıktı biçimi/hedef gibi zorunlu
  bölüm (httpx `-json`, nmap `-oX`/`-p`, subfinder `-d`, nuclei `-jsonl`) her zaman eklenir, kaldırılamaz.
  Varsayılanlar `core/config.py > TOOL_DEFAULT_FLAGS`; `settings.yaml > tool_args` ile kalıcı override edilebilir.
- **Taramayı durdurma:** Tarama sürerken kenar çubuğundaki **Stop scan** bekleyen istekleri iptal eder ve
  çalışan harici aracı (nmap/nuclei/ffuf…) sonlandırır; o ana kadarki sonuçlarla rapor yazılabilir.
  **New scan** de çalışan taramayı önce durdurur (arka planda hedefe istek atmaya devam etmez).
- **Tüm çıktıyı indirme:** Tarama bitince **Download all output (.zip)** ile subdomains (all/live/dead),
  ports, nuclei, compliance bulguları ve raporun tamamını tek bir `.zip` olarak indirebilirsiniz
  (named-volume kullansanız bile tarayıcıdan iner).

Mimari: `app.py` yalnızca arayüzdür; tüm tarama mantığı `dashboard/controller.py` (Streamlit'ten bağımsız,
birim test edilebilir) + mevcut `core/` ve `modules/` motorudur. Backend'e yalnızca geriye uyumlu bir
canlı olay kancası (`ScanContext.event_hook`) eklenmiştir; CLI davranışı değişmez.

### Sorun giderme
- **`exec streamlit failed: No such file or directory` / `exited with code 127`:** İmaj eksik ya da eski
  (muhtemelen build yarım kalmış). Önce imajı **yeniden** derleyin: `docker compose build --no-cache dashboard`,
  sonra `docker compose up dashboard`. Compose girişi `python -m streamlit` kullanır; doğru derlenmiş imajda streamlit `/usr/local/bin` altındadır.
- **`error getting credentials - err: exit status 1` (build sırasında):** Docker Desktop'ın kimlik yardımcısı
  (credential helper) bozuk; bu yüzden temel imajlar (golang/python) çekilemiyor ve build başarısız oluyor.
  Düzeltme (Windows): `C:\Users\<kullanıcı>\.docker\config.json` dosyasını açıp **`"credsStore": "desktop"`
  satırını silin** (öncesindeki virgülü de) ve kaydedin. En garantisi: dosyanın tüm içeriğini `{ "auths": {} }`
  ile değiştirin (önce yedek alın). Ardından Docker Desktop'ı yeniden başlatıp
  `docker compose build --no-cache dashboard` çalıştırın. Public imajlar için oturum gerekmez; bozuk helper
  çağrısı kalktığında anonim indirme çalışır. (Dockerfile'daki `# syntax=` satırı kaldırıldı; böylece ayrıca
  bir frontend imajı indirmeye gerek kalmaz.)

## Docker
**Hızlı başlangıç** (Docker Desktop açıkken, bu klasörün içinde):
```bash
docker compose build dashboard    # ilk derleme 10-20 dk sürebilir (Go araçları + nuclei şablonları)
docker compose up dashboard       # ardından tarayıcıda http://localhost:8501
```
Durdurmak için `Ctrl+C`, konteyneri kaldırmak için `docker compose down`. Kodu ya da `requirements.txt`
dosyasını güncellediyseniz yeniden derleyin: `docker compose build --no-cache dashboard`.

Çok aşamalı imaj: Go 1.26 aşamasında subfinder, httpx, katana ve ffuf statik derlenir (sürümler sabit,
`--build-arg` ile değiştirilebilir); ince `python:3.12-slim` imajına yalnızca ikililer ve uygulama kopyalanır.
Konteyner root olmayan `recon` (uid 10001) kullanıcısıyla, `tini` altında çalışır (Ctrl+C / `docker stop`
düzgün iletilir, kısmi çıktı ve özet yazılır).

```bash
docker build -t recon:latest .
# Sürüm değiştirmek: --build-arg SUBFINDER_VERSION=... HTTPX_VERSION=... KATANA_VERSION=... FFUF_VERSION=...
# katana headless modu için: --build-arg INSTALL_CHROMIUM=true

docker run --rm -v "$PWD/outputs:/app/outputs" recon:latest -d example.com --rate-limit 5
docker run --rm recon:latest --check-tools

# Kendi ayarlarınız ve subfinder API anahtarlarınızla:
docker run --rm \
  -v "$PWD/outputs:/app/outputs" \
  -v "$PWD/settings.yaml:/app/config/settings.yaml:ro" \
  -v "$PWD/provider-config.yaml:/home/recon/.config/subfinder/provider-config.yaml:ro" \
  recon:latest -d example.com

# Sertleştirilmiş çalıştırma (salt-okunur kök FS, tüm yetkiler kapalı) docker-compose.yml içinde hazır:
docker compose run --rm recon -d example.com --rate-limit 5   # CLI
docker compose up dashboard                                 # Web arayüzü :8501
```
Linux'ta host'taki `outputs/` dizini uid 10001 tarafından yazılabilir olmalı
(`mkdir -p outputs && sudo chown 10001:10001 outputs`) ya da `--user "$(id -u):$(id -g)"` verin.
Salt-okunur modda `~/.config` ve `~/.cache` tmpfs olarak bağlanmalıdır, çünkü araçlar buraya yazar (compose dosyası bunu yapar).

## Kullanım
```bash
python recon.py -d example.com
python recon.py -d example.com --rate-limit 3 --threads 5 --jitter 0.1 0.5 -H "X-Bug-Bounty: kullanici"
python recon.py -d example.com --subs bilinen_subdomainler.txt -w /opt/SecLists/Discovery/Web-Content/common.txt
python recon.py -d example.com --proxy http://127.0.0.1:8080          # Burp üzerinden
python recon.py -d example.com -m js dirs                              # önceki çıktılardan devam
python recon.py -d example.com --targets hosts.txt                     # keşfi atla, verilen hostları tara
python recon.py --targets hosts.txt -m ports dirs                      # Direct mod: -d yok, IP/host listesi
```

| Seçenek | Açıklama |
|---|---|
| `-m subdomains ports crawl js dirs nuclei` | Çalışacak modüller (varsayılan hepsi, her zaman bu sırayla) |
| `--rate-limit N` | Tüm modüllerde saniyedeki azami istek (harici araçlara da aktarılır) |
| `--threads N`, `--timeout N` | Eşzamanlılık ve istek zaman aşımı |
| `--jitter MIN MAX` | İstekler arasına rastgele bekleme |
| `-H "Ad: Değer"` | Tüm isteklere header (tekrarlanabilir) |
| `--proxy URL` | HTTP/SOCKS5 proxy (`http://`, `https://`, `socks5://`, `socks5h://`) |
| `--subs DOSYA` | Elde bulunan subdomainleri ekle |
| `--targets DOSYA` | Keşfi atla: dosyadaki hostları doğrudan tara (ör. `-m dirs js` ile). `-d` verilmezse **Direct mod**: kapsam tam olarak dosyadaki host/IP'lerdir (IPv4 dahil), çıktı klasörü ilk hedefin adını alır |
| `-w DOSYA` | Dizin taramasına ek wordlist |
| `--dir-engine auto/internal/ffuf` | Dizin tarama motoru |
| `--depth N` | Crawling derinliği |

**İlerleme sayacı:** Dizin taraması (ve JS analizi) sırasında host bazlı `denenen/toplam`, yüzde, hız, bulgu ve
kalan süre gösterilir. Gerçek terminalde canlı çubuk; terminal yoksa (`docker run` `-t` olmadan, CI, dosyaya
yönlendirme) her 15 sn'de bir log satırı yazılır (`dir_bruteforce.progress_interval`). Docker'da çubuk için `docker run -it` kullanın.

**Devam etme:** `-m js dirs` gibi kısmi bir çalıştırma, çalıştırılmayan modüllerin verisini **ve bulgularını**
(güvenlik, port, nuclei, JS, dizin) önceki çıktılardan yükler; `summary.json` / `report.md` eksilmeden yeniden yazılır.

Diğer tüm ayarlar `config/settings.yaml` içindedir (teknoloji -> wordlist eşlemesi, JS kütüphane atlama listesi vb.).

## Modüller
- **subdomains**: subfinder (pasif) + `--subs` → httpx (`-sc -title -td -server -irh`) ile canlılık, durum kodu,
  header ve teknoloji. httpx yoksa dahili prober + header/cookie/gövde imzalı teknoloji tespiti. Python'daki aynı
  isimli `httpx` CLI'si otomatik ayıklanır. Ardından **maruziyet analizi** (saf Python): eksik sıkılaştırma
  başlıkları (HSTS/CSP/X-Frame/X-Content-Type; zafiyet sayılmaz, host başına tek **INFO** satırında toplanır ve
  dashboard'da varsayılan olarak gizlidir), CORS yanlış yapılandırması, TLS/sertifika (süre + ayrı bir el sıkışmayla
  TLS 1.0/1.1 kabulü),
  subdomain takeover imzaları (gövde imzası **CNAME zinciriyle doğrulanır**: sağlayıcıya gidiyorsa CRITICAL,
  gitmiyorsa/belirlenemiyorsa "unconfirmed" MEDIUM) ve çerez bayrakları → tümü birleşik **bulgu** modeline (severity + öneri) yazılır.
- **ports**: nmap varsa onunla (`-sT -sV` connect taraması + servis/sürüm tespiti; root gerekmez), yoksa dahili
  socket tarayıcıyla açık port tespiti. Veri-deposu/yönetim servisleri (Redis, Elasticsearch, MongoDB, Docker API,
  MySQL, RDP...) internete açıksa riskli servis bulgusu üretir; nmap'in tespit ettiği ürün/sürüm bulguya eklenir.
- **nuclei**: CVE ve yanlış yapılandırma taraması. **Güvenli varsayılan**: `dos, intrusive, fuzz, brute` etiketli
  zararlı şablonlar dışlanır; "intrusive" mod yalnızca açık `intrusive: true` ile ve uyarıyla devreye girer. Kullanıcı
  teknoloji/sürüme özel kendi şablonlarını (`-t`) ekleyebilir, ek etiket dışlayabilir. **CVSS sezgisel üretilmez** —
  yalnızca Nuclei şablonunun taşıdığı resmî CVSS puanı/vektörü kullanılır. Nuclei kurulu değilse aşama atlanır.
  Bulgular nuclei ürettiği **anda** loglanır ve dashboard'a düşer; tarama durdurulsa da o ana kadarkiler rapora girer.
- **B – crawl**: katana (`-jc -kf all -fs rdn`) ile URL ve JS toplama; yoksa dahili crawler (robots.txt, sitemap.xml dahil).
  Parametreli URL'ler path + parametre adlarına göre tekilleştirilir.
- **B – js**: JS dosyaları rate limit'e uyarak indirilir ve satır satır taranır. Kesin regex'ler (AWS, Google, GitHub,
  Slack, Stripe, JWT, özel anahtar...) HIGH; değer atamalı `apiKey = "..."` MEDIUM; kelime listesi (`API_KEY, secret,
  token, password, aws_, firebase`) LOW. Değer "sır gibi" görünmüyorsa (kısa/placeholder/sözlük kelimesi) elenir.
  Minified (tek satırlık) paketlerde aynı kuralın her **farklı** eşleşmesi ayrı raporlanır.
  Bilinen kütüphaneler atlanır. JS içinden endpointler çıkarılır; kapsam içi olanlar tam URL'ye çözülüp URL
  envanterine (`urls/`) eklenir ve crawler'ın görmediği JS dosyaları bir tur daha taranır
  (`js_analysis.feed_endpoints: false` ile kapatılır).
- **C – dirs**: Hosta göre wordlist seçimi (PHP, WordPress, ASP.NET/IIS, Java/Tomcat/Spring, Node/Express/Next,
  Nginx, Apache) + her hosta genel listeler (hassas dosyalar, yedekler, yaygın dizinler). `{domain}`, `{host}`, `{sub}`
  yer tutucuları (ör. `example.com.zip`). ffuf `-ac` veya dahili motor; dahili motor soft-404'ü uzunluk + içerik
  benzerliğiyle eler. `.git/HEAD`, `.env`, `actuator/env`, zip/tar.gz vb. içerik imzasıyla **doğrulanır**.
  Yoklamada gövdenin yalnızca ilk 64 KB'ı indirilir (büyük yedek dosyaları baştan sona çekilmez).
- **D – hız**: Tüm dahili istekler tek bir paylaşılan limiter'dan geçer; 429/503 gelince hız otomatik yarıya iner.
  Harici araçlar aynı RPS ile ve **sırayla** çalışır, böylece toplam yük sınırı aşmaz.
- **E – çıktı**: aşağıdaki yapı + `summary.json`, `report.md` ve tüm modüllerin önem sırasına dizilmiş
  birleşik bulguları `findings.md` / `findings.json` (CLI ve dashboard aynı listeyi ve notu üretir).

## Çıktı yapısı
```
outputs/<hedef>/
├── summary.json, report.md, findings.md, findings.json
├── subdomains/       all.txt, live.txt, dead.txt, live.json, by_tech.txt
├── urls/             all_urls.txt, parameterized.txt, parameterized_unique.txt, params.txt, by_host/
├── js_analysis/      critical.txt, critical.json, js_files.txt, endpoints.txt, endpoint_urls.txt, skipped.txt
├── directory_brute/  found.txt, sensitive.txt, backups.txt, verified.txt, findings.json
├── compliance/       version_disclosure.txt, findings.txt, findings.json  (birleşik güvenlik bulguları)
├── ports/            open_ports.txt, ports.json
└── nuclei/           findings.txt, findings.json  (CVE/CVSS)
```
`critical.txt` biçimi: `[SEVİYE][kural] url:satır -> kesit`

## Kod yapısı
```
recon.py                 CLI + ReconOrchestrator (modül sırası, hata izolasyonu, devam etme, rapor)
core/  config.py         YAML + CLI birleştirme ve doğrulama
       rate_limiter.py   paylaşılan RPS limiter, jitter, otomatik yavaşlama/toparlanma, iptal
       http_client.py    rate limit'li, proxy/header destekli requests istemcisi (gövde boyutu sınırı)
       tool_runner.py    harici araç çalıştırma (shell=False, zaman aşımı, araç doğrulama, iptal)
       targets.py        host/IP hedef ayrıştırma (CLI --targets ve dashboard Direct mod ortak)
       security_checks.py başlık/CORS/TLS/takeover kontrolleri, birleşik bulgu modeli ve notlama
       fingerprint.py    teknoloji imzaları
       output_manager.py klasör yapısı ve güvenli yazım
modules/ base.py         BaseModule, ScanContext, LiveHost
         subdomain_recon.py, port_scan.py, crawler.py, js_analyzer.py, dir_bruteforce.py, nuclei_scan.py
dashboard/               controller.py (adım adım yürütme, durdurma), config_builder.py
wordlists/tech/*.txt, wordlists/common/*.txt
tests/                   pytest testleri (test_engine.py yerel sunucuyla uçtan uca) + lab_server.py
```
Yeni modül: `BaseModule`'den türet, `name` ve `run(ctx)` yaz, `modules/__init__.py` içindeki `MODULE_REGISTRY`'ye ekle.

## Test
```bash
python -m pytest -q tests      # test_engine.py 127.0.0.1 üzerinde geçici bir sunucu açar; root/hosts gerekmez
# Uçtan uca, yerel ve güvenli: (root gerekir, 80 portu)
echo "127.0.0.1 recon-lab.test app.recon-lab.test api.recon-lab.test" | sudo tee -a /etc/hosts
sudo python3 tests/lab_server.py &
printf 'app.recon-lab.test\napi.recon-lab.test\n' > /tmp/subs.txt
NO_PROXY=.recon-lab.test python recon.py -d recon-lab.test --subs /tmp/subs.txt --rate-limit 50
```

## Lisans
[MIT](LICENSE). Araç yalnızca izinli hedeflerde kullanılmak üzere, hiçbir garanti verilmeden sunulur.

