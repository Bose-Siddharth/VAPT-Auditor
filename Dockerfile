FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1

# --- OS packages: nmap, nikto, ruby (for wpscan), weasyprint's native deps ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    ruby-full \
    build-essential \
    libcurl4-openssl-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
    fonts-liberation \
    git curl wget ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

# --- wpscan (Ruby gem) ---
RUN gem install wpscan --no-document

# --- testssl.sh ---
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
    && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh \
    && chmod +x /usr/local/bin/testssl.sh

# --- nuclei (prebuilt Go binary) ---
ARG NUCLEI_VERSION=3.3.9
RUN ARCH=$(dpkg --print-architecture) \
    && case "$ARCH" in \
         amd64) NARCH=amd64 ;; \
         arm64) NARCH=arm64 ;; \
         *) echo "unsupported arch $ARCH" && exit 1 ;; \
       esac \
    && wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NARCH}.zip" -O /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /usr/local/bin nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

# Bake in the nuclei template set so the first real scan isn't slow.
RUN nuclei -update-templates -silent || true

WORKDIR /srv/app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app
COPY scripts ./scripts

RUN mkdir -p /srv/app/data /srv/app/uploads

ENV VAPT_DATA_DIR=/srv/app/data \
    VAPT_UPLOAD_DIR=/srv/app/uploads \
    PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
