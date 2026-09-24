# syntax=docker/dockerfile:1.7
# Worker image with the external tools from the catalog (Tool - *). Runs `osint-board worker --queue tools`.
FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DEBIAN_FRONTEND=noninteractive
ARG NUCLEI_VERSION=3.3.7
ARG TRUFFLEHOG_VERSION=3.88.0

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git unzip whois \
      nmap nbtscan onesixtyone whatweb \
      nodejs npm \
      bsdmainutils procps openssl \
    && rm -rf /var/lib/apt/lists/*

# Go-binary tools from GitHub releases
RUN curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /usr/local/bin nuclei && rm /tmp/nuclei.zip \
    && curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" \
       | tar -xz -C /usr/local/bin trufflehog

# Shell / Python / Node tools
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh /opt/testssl.sh && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh \
    && git clone --depth 1 https://github.com/Tuhinshubhra/CMSeeK /opt/cmseek \
    && pip install --no-cache-dir wafw00f dnstwist[full] snallygaster -r /opt/cmseek/requirements.txt \
    && npm install -g retire

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
COPY backend /app/backend
COPY catalog /app/catalog
RUN cd /app/backend && uv sync --frozen --no-dev
ENV PATH="/app/backend/.venv/bin:$PATH" OSINT_TOOLS_DIR=/opt
WORKDIR /app/backend
CMD ["osint-board", "worker", "--queue", "tools"]
