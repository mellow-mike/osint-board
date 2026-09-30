# syntax=docker/dockerfile:1.7
# Worker image with the external tools from the catalog (Tool - *). Runs `osint-board worker --queue tools`.
FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DEBIAN_FRONTEND=noninteractive
ARG NUCLEI_VERSION=3.3.7
ARG TRUFFLEHOG_VERSION=3.88.0
ARG WAPPALYZER_REVISION=20436693e89619e5e7eb5237576ec970ce688127
ARG RETIREJS_VERSION=5.7.0

COPY --from=node:22-bookworm-slim /usr/local/ /usr/local/

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git unzip whois \
      nmap nbtscan onesixtyone whatweb \
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
    && pip install --no-cache-dir wafw00f dnstwist dnspython snallygaster -r /opt/cmseek/requirements.txt \
    && npm install -g "retire@$RETIREJS_VERSION"

# Only the maintained engine/data are needed. Our static HTTP runner has no npm
# dependencies and never launches Chromium or executes page JavaScript.
RUN git init /opt/wappalyzer \
    && git -C /opt/wappalyzer remote add origin https://github.com/HTTPArchive/wappalyzer.git \
    && git -C /opt/wappalyzer fetch --depth 1 origin "$WAPPALYZER_REVISION" \
    && git -C /opt/wappalyzer checkout --detach FETCH_HEAD

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
COPY backend /app/backend
COPY catalog /app/catalog
# Sync the worker venv, then add CMSeeK's own dependencies into it: tool_cmseek runs `cmseek.py` with the
# worker interpreter (sys.executable), so its imports must resolve inside this venv, not just system Python.
RUN cd /app/backend && uv sync --frozen --no-dev \
    && uv pip install --no-cache-dir -r /opt/cmseek/requirements.txt
ENV PATH="/app/backend/.venv/bin:$PATH" OSINT_TOOLS_DIR=/opt
WORKDIR /app/backend
CMD ["osint-board", "worker", "--queue", "tools"]
