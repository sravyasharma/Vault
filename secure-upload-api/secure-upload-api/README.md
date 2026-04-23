# 🔐 Secure File Upload API

A production-grade file upload service with multi-layer security built on **FastAPI**.

## Security Architecture

```
Upload Request
     │
     ▼
┌─────────────────────────┐
│   1. File Validation    │  ← Size, extension block list, MIME type,
│                         │    MIME/extension mismatch (polyglot detection)
└──────────┬──────────────┘
           │ PASS
           ▼
┌─────────────────────────┐
│   2. ClamAV Scan        │  ← Stream scan via clamd TCP socket
│                         │    Graceful degradation if unavailable
└──────────┬──────────────┘
           │ CLEAN
           ▼
┌─────────────────────────┐
│   3. Fernet Encryption  │  ← AES-128-CBC + HMAC-SHA256
│                         │    SHA-256 checksum recorded
└──────────┬──────────────┘
           │
           ▼
┌─────────────────────────┐
│   4. Encrypted Storage  │  ← .enc files on disk (S3-ready)
└─────────────────────────┘
```

## Security Layers

| Layer | What it catches |
|---|---|
| Extension block list | `.exe`, `.bat`, `.sh`, `.ps1`, `.dll`, `.vbs` … |
| MIME allow list | Only whitelisted content types accepted |
| MIME/extension mismatch | Polyglot files (e.g. ZIP disguised as `.jpg`) |
| ClamAV virus scan | Known malware, trojans, EICAR test virus |
| Fernet encryption (AES) | Data-at-rest protection |
| SHA-256 checksum | Tampering/corruption detection on download |

## Quick Start

### Without Docker (dev mode)

```bash
# Install system dependencies
# macOS
brew install libmagic clamav

# Ubuntu/Debian
sudo apt-get install libmagic1 clamav clamav-daemon

# Install Python packages
pip install -r requirements.txt

# Copy env file and configure
cp .env.example .env
# Edit .env with your settings

# Run
uvicorn app.main:app --reload
```

### With Docker (recommended)

```bash
# Start ClamAV + API together
docker compose up --build

# API available at http://localhost:8000
# Swagger UI at  http://localhost:8000/docs
```

## API Reference

### Upload a file
```http
POST /upload/
Content-Type: multipart/form-data

file: <binary>
```

**Response (201)**
```json
{
  "success": true,
  "file_id": "550e8400-e29b-41d4-a716-446655440000",
  "filename": "document.pdf",
  "mime_type": "application/pdf",
  "size_bytes": 45231,
  "checksum_sha256": "abc123...",
  "scan": {
    "status": "CLEAN",
    "message": "No threats detected"
  },
  "uploaded_at": "2025-04-01T12:00:00+00:00"
}
```

### Download a file
```http
GET /upload/{file_id}/download
```
Decrypts and streams the original file. Verifies checksum before delivery.

### Get metadata
```http
GET /upload/{file_id}/metadata
```

### List all files
```http
GET /upload/
```

### Delete a file
```http
DELETE /upload/{file_id}
```

### Health check
```http
GET /health
```

## Example cURL Commands

```bash
# Upload
curl -X POST http://localhost:8000/upload/ \
  -F "file=@/path/to/your/file.pdf"

# Download
curl -OJ http://localhost:8000/upload/{file_id}/download

# Health
curl http://localhost:8000/health | jq
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `ENCRYPTION_KEY` | auto-generated | Fernet key or passphrase |
| `STORAGE_PATH` | `storage` | Directory for encrypted files |
| `MAX_FILE_SIZE_MB` | `50` | Max upload size |
| `CLAMAV_HOST` | `localhost` | clamd hostname |
| `CLAMAV_PORT` | `3310` | clamd TCP port |
| `DEBUG` | `false` | Verbose logging |

### Generate a proper Fernet key

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## Running Tests

```bash
pip install pytest pytest-asyncio
pytest tests/ -v
```

## Allowed File Types

| MIME Type | Extensions |
|---|---|
| `image/jpeg` | `.jpg`, `.jpeg` |
| `image/png` | `.png` |
| `image/gif` | `.gif` |
| `image/webp` | `.webp` |
| `application/pdf` | `.pdf` |
| `text/plain` | `.txt` |
| `text/csv` | `.csv` |
| `application/json` | `.json` |
| `application/zip` | `.zip` |
| `application/vnd.openxmlformats-officedocument.wordprocessingml.document` | `.docx` |
| `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` | `.xlsx` |

## Production Checklist

- [ ] Set a strong `ENCRYPTION_KEY` (Fernet key, not a passphrase)
- [ ] Run ClamAV daemon and ensure `CLAMAV_HOST`/`CLAMAV_PORT` are correct
- [ ] Run `freshclam` regularly to update virus definitions
- [ ] Replace in-memory file registry with a database (PostgreSQL recommended)
- [ ] Add authentication/authorization (OAuth2, API keys)
- [ ] Mount `storage/` on a persistent volume or migrate to S3
- [ ] Set `DEBUG=false` in production
- [ ] Restrict CORS origins
- [ ] Set up rate limiting (e.g. `slowapi`)
- [ ] Enable HTTPS via reverse proxy (nginx, Caddy)
