FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei vulnerability scanner
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/') \
    && NUCLEI_VER=$(wget -qO- "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest" \
    | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_${ARCH}.zip" \
    -O /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /tmp \
    && mv /tmp/nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip \
    && nuclei -update-templates -silent || true

COPY requirements.txt .

# Use high timeout and skip pip upgrade for stability
RUN pip install --no-cache-dir --default-timeout=1000 -r requirements.txt

COPY . .

# Create non-root user for runtime security
RUN addgroup --system celery && adduser --system --ingroup celery celery \
    && chown -R celery:celery /app

USER celery

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
