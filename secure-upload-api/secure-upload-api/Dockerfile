FROM python:3.12-slim

# Install system dependencies: ClamAV, libmagic
RUN apt-get update && apt-get install -y --no-install-recommends \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    libmagic1 \
    libmagic-dev \
    && rm -rf /var/lib/apt/lists/*

# Update virus definitions at build time
RUN freshclam || true

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app/ ./app/

# Create storage directory
RUN mkdir -p /app/storage

# Configure ClamAV daemon for TCP
RUN sed -i 's/^#TCPSocket.*/TCPSocket 3310/' /etc/clamav/clamd.conf && \
    sed -i 's/^#TCPAddr.*/TCPAddr 0.0.0.0/' /etc/clamav/clamd.conf && \
    echo "Foreground yes" >> /etc/clamav/clamd.conf

# Entrypoint: start clamd then uvicorn
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 8000

ENV PYTHONUNBUFFERED=1
ENV STORAGE_PATH=/app/storage

ENTRYPOINT ["/docker-entrypoint.sh"]
