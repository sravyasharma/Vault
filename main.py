import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from app.routes.upload import router as upload_router
from app.services.scanner import scanner
from app.services.encryption import encryption_service
from app.utils.config import settings

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown hooks."""
    # Ensure storage directory exists
    Path(settings.STORAGE_PATH).mkdir(parents=True, exist_ok=True)

    # Warm up encryption (derives key, creates salt if needed)
    logger.info("Encryption service initialised")

    # Check ClamAV
    clamav_ok = scanner.ping()
    if clamav_ok:
        version = scanner.get_version()
        logger.info(f"ClamAV ready — {version}")
    else:
        logger.warning(
            "ClamAV daemon not reachable. Running in degraded mode "
            "(files will NOT be virus-scanned). Start clamd for full security."
        )

    logger.info(f"🚀 {settings.APP_NAME} v{settings.APP_VERSION} started")
    yield
    logger.info("Shutting down...")


# ── App ──────────────────────────────────────────────────────────────────────
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="""
## Secure File Upload API

A production-grade file upload service with:

- ✅ **File validation** — size, extension, MIME type, polyglot detection
- 🦠 **Antivirus scanning** — ClamAV integration with graceful degradation
- 🔐 **Encrypted storage** — Fernet (AES-128-CBC + HMAC-SHA256)
- ✅ **Integrity verification** — SHA-256 checksum on every download
- 🗑️ **File lifecycle** — upload, list, download, delete

### Security layers

| Layer | What it catches |
|---|---|
| Extension block list | `.exe`, `.bat`, `.sh`, `.ps1`, etc. |
| MIME type allow list | Only whitelisted content types |
| MIME/extension mismatch | Polyglot / spoofed files |
| ClamAV scan | Known malware, trojans, EICAR test |
| Fernet encryption | Data at rest protection |
| SHA-256 checksum | Tampering / corruption detection |
    """,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── Middleware ────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # Restrict in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Global exception handler ──────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred"},
    )

# ── Routes ────────────────────────────────────────────────────────────────────
app.include_router(upload_router)


@app.get("/", tags=["Health"])
async def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "ok",
        "docs": "/docs",
    }


@app.get("/health", tags=["Health"])
async def health():
    """Full health check including ClamAV status."""
    clamav_ok = scanner.ping()
    clamav_version = scanner.get_version() if clamav_ok else None

    return {
        "status": "ok",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "storage_path": settings.STORAGE_PATH,
        "max_upload_mb": settings.MAX_FILE_SIZE_MB,
        "clamav": {
            "available": clamav_ok,
            "version": clamav_version,
            "host": settings.CLAMAV_HOST,
            "port": settings.CLAMAV_PORT,
        },
        "encryption": "Fernet (AES-128-CBC + HMAC-SHA256)",
    }
