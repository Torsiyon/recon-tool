# ---------------------------------------------------------------------------
# Recon - kurumsal varlık envanteri / keşif aracı
#   Aşama 1 (go-builder): subfinder, httpx, katana, ffuf, nuclei derlenir (nmap apt'tan gelir)
#   Aşama 2 (runtime)   : ince Python imajı + derlenmiş ikililer + uygulama
# Derleme:  docker build -t recon:latest .
# Çalıştırma: docker run --rm -v "$PWD/outputs:/app/outputs" recon:latest -d example.com
#
# Not: nuclei şablonları derleme sırasında indirilip imaja gömülür (çalışma zamanında
#      internet gerekmez; imaj ~200 MB büyür — kullanılabilir olması için bilerek).
# ---------------------------------------------------------------------------
# Güncel ProjectDiscovery sürümleri go >= 1.26 istiyor
ARG GO_VERSION=1.26
ARG PYTHON_VERSION=3.12
ARG DEBIAN_RELEASE=bookworm

############################
# Aşama 1: Go araçları
############################
FROM golang:${GO_VERSION}-${DEBIAN_RELEASE} AS go-builder

# Sürümler sabitlenir: tekrar üretilebilir derleme. Güncellemek için --build-arg ile ezin.
ARG SUBFINDER_VERSION=v2.17.0
ARG HTTPX_VERSION=v1.12.0
ARG KATANA_VERSION=v1.8.0
ARG FFUF_VERSION=v2.3.0
ARG NUCLEI_VERSION=v3.11.1
# Port/servis taraması nmap ile yapılır (apt'tan kurulur, aşağıda). nmap servis+sürüm
# tespitinde (-sV) en olgun araçtır; connect taraması (-sT) root gerektirmez.

ENV CGO_ENABLED=0 \
    GOBIN=/out \
    GOFLAGS=-trimpath

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -eux; \
    go install -ldflags="-s -w" github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}; \
    go install -ldflags="-s -w" github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}; \
    go install -ldflags="-s -w" github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION}; \
    go install -ldflags="-s -w" github.com/ffuf/ffuf/v2@${FFUF_VERSION}; \
    go install -ldflags="-s -w" github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}; \
    /out/subfinder -version; /out/httpx -version; /out/katana -version; /out/ffuf -V; \
    /out/nuclei -version

# Nuclei şablonları imaja gömülür: derlemede bir kez indirilir, çalışma zamanında hazır gelir.
# (Ağ gerektirir. İmaj ~200 MB büyür; kullanıcı talebi doğrultusunda bilerek gömülüyor.)
RUN set -eux; \
    /out/nuclei -update-templates -update-template-dir /out/nuclei-templates; \
    test -d /out/nuclei-templates; \
    ls -A /out/nuclei-templates | head -1 >/dev/null

############################
# Aşama 2: Çalışma imajı
############################
FROM python:${PYTHON_VERSION}-slim-${DEBIAN_RELEASE} AS runtime

ARG APP_UID=10001
ARG APP_GID=10001
# katana -headless gerekirse: --build-arg INSTALL_CHROMIUM=true (imajı ~400 MB büyütür)
ARG INSTALL_CHROMIUM=false

LABEL org.opencontainers.image.title="recon" \
      org.opencontainers.image.description="Modüler keşif/envanter aracı: subfinder, httpx, katana, ffuf, nmap, nuclei orkestrasyonu" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/home/recon \
    PATH=/usr/local/bin:$PATH \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    STREAMLIT_SERVER_FILE_WATCHER_TYPE=none

# Sistem bağımlılıkları: TLS sertifikaları, sinyal yönetimi (tini) ve nmap (port/servis taraması)
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates tini nmap; \
    if [ "$INSTALL_CHROMIUM" = "true" ]; then apt-get install -y --no-install-recommends chromium; fi; \
    rm -rf /var/lib/apt/lists/*

# Yetkisiz kullanıcı
RUN groupadd --gid ${APP_GID} recon \
 && useradd --uid ${APP_UID} --gid ${APP_GID} --create-home --shell /usr/sbin/nologin recon

WORKDIR /app

# Önce bağımlılıklar (katman önbelleği için kod kopyalanmadan önce); test bağımlılıkları imaja girmez
COPY requirements.txt .
RUN grep -viE '^\s*pytest' requirements.txt > /tmp/req.txt \
 && pip install --no-cache-dir -r /tmp/req.txt \
 && rm /tmp/req.txt

# Derlenmiş Go ikilileri
COPY --from=go-builder /out/subfinder /out/httpx /out/katana /out/ffuf /out/nuclei /usr/local/bin/

# Nuclei şablonları: imaja gömülü geliyor (derlemede indirildi). Çalışma zamanında
# internetten indirmeye gerek yok. nuclei bu ortam değişkenini kendiliğinden okur.
COPY --from=go-builder --chown=recon:recon /out/nuclei-templates /home/recon/nuclei-templates
ENV NUCLEI_TEMPLATES_DIR=/home/recon/nuclei-templates

# Uygulama kodu
COPY --chown=recon:recon recon.py ./
COPY --chown=recon:recon core/ ./core/
COPY --chown=recon:recon modules/ ./modules/
COPY --chown=recon:recon config/ ./config/
COPY --chown=recon:recon wordlists/ ./wordlists/
COPY --chown=recon:recon app.py ./
COPY --chown=recon:recon dashboard/ ./dashboard/
COPY --chown=recon:recon .streamlit/ ./.streamlit/

RUN mkdir -p /app/outputs /home/recon/.config/subfinder \
 && chown -R recon:recon /app/outputs /home/recon \
 && python -m compileall -q /app

USER recon

# Web arayüzü (app.py) bu porttan yayınlanır; CLI kullanımı için port gerekmez
EXPOSE 8501

# Çıktılar host'a bağlanmalı; subfinder API anahtarları için:
#   -v ./provider-config.yaml:/home/recon/.config/subfinder/provider-config.yaml:ro
VOLUME ["/app/outputs"]

# Araçların ve Python ortamının hazır olduğunu doğrular
HEALTHCHECK --interval=5m --timeout=20s --start-period=5s --retries=1 \
    CMD python recon.py --check-tools >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "python", "/app/recon.py"]
CMD ["--help"]
