import uuid
import logging
import aiofiles
from pathlib import Path
from datetime import datetime, UTC

from fastapi import APIRouter, UploadFile, File, HTTPException, status
from fastapi.responses import JSONResponse, Response

from app.services.validator import validator
from app.services.scanner import scanner, ScanStatus
from app.services.encryption import encryption_service
from app.utils.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/upload", tags=["File Upload"])

STORAGE_PATH = Path(settings.STORAGE_PATH)
STORAGE_PATH.mkdir(parents=True, exist_ok=True)

# In-memory file registry (replace with DB in production)
_file_registry: dict[str, dict] = {}


@router.post(
    "/",
    summary="Upload a file securely",
    response_description="Upload result with file ID and scan details",
)
async def upload_file(file: UploadFile = File(...)):
    """
    Secure file upload pipeline:

    1. **Read** file into memory
    2. **Validate** size, extension, MIME type, and MIME/extension consistency
    3. **Scan** for malware via ClamAV
    4. **Encrypt** using Fernet (AES-128-CBC + HMAC)
    5. **Store** encrypted file to disk
    6. Return file ID and metadata
    """

    # ── 1. Read content ──────────────────────────────────────────────────────
    try:
        content = await file.read()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded file: {e}",
        )

    filename = file.filename or "unknown"
    file_size = len(content)
    logger.info(f"Upload received: '{filename}' ({file_size} bytes)")

    # ── 2. Validate ──────────────────────────────────────────────────────────
    validation = await validator.validate(file, content)
    if not validation.valid:
        logger.warning(f"Validation failed for '{filename}': {validation.message}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "stage": "validation",
                "error": validation.message,
                "filename": filename,
            },
        )

    # ── 3. Virus scan ────────────────────────────────────────────────────────
    scan_result = scanner.scan(content, filename=filename)

    if scan_result.should_reject:
        logger.error(
            f"INFECTED FILE REJECTED: '{filename}' — {scan_result.threat_name}"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "stage": "antivirus",
                "error": "Malware detected — file rejected",
                "threat": scan_result.threat_name,
                "filename": filename,
            },
        )

    if scan_result.status == ScanStatus.ERROR:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"stage": "antivirus", "error": scan_result.message},
        )

    # ── 4. Encrypt ───────────────────────────────────────────────────────────
    try:
        checksum = encryption_service.compute_checksum(content)
        encrypted = encryption_service.encrypt(content)
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"stage": "encryption", "error": "Failed to encrypt file"},
        )

    # ── 5. Store ─────────────────────────────────────────────────────────────
    file_id = str(uuid.uuid4())
    stored_filename = f"{file_id}.enc"
    dest_path = STORAGE_PATH / stored_filename

    try:
        async with aiofiles.open(dest_path, "wb") as f:
            await f.write(encrypted)
    except Exception as e:
        logger.error(f"Storage failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"stage": "storage", "error": "Failed to store file"},
        )

    # ── 6. Register & respond ─────────────────────────────────────────────────
    metadata = {
        "file_id": file_id,
        "original_name": filename,
        "mime_type": validation.mime_type,
        "size_bytes": file_size,
        "checksum_sha256": checksum,
        "stored_as": stored_filename,
        "scan_status": scan_result.status.value,
        "scan_message": scan_result.message,
        "uploaded_at": datetime.now(UTC).isoformat(),
    }
    _file_registry[file_id] = metadata

    logger.info(f"File stored: {file_id} ('{filename}', {file_size} bytes)")

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "success": True,
            "file_id": file_id,
            "filename": filename,
            "mime_type": validation.mime_type,
            "size_bytes": file_size,
            "checksum_sha256": checksum,
            "scan": {
                "status": scan_result.status.value,
                "message": scan_result.message,
            },
            "uploaded_at": metadata["uploaded_at"],
        },
    )


@router.get(
    "/{file_id}/metadata",
    summary="Get file metadata",
)
async def get_file_metadata(file_id: str):
    """Retrieve stored metadata for an uploaded file."""
    meta = _file_registry.get(file_id)
    if not meta:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File '{file_id}' not found",
        )
    return meta


@router.get(
    "/{file_id}/download",
    summary="Download and decrypt a file",
)
async def download_file(file_id: str):
    """Decrypt and stream a previously uploaded file."""
    meta = _file_registry.get(file_id)
    if not meta:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File '{file_id}' not found",
        )

    dest_path = STORAGE_PATH / meta["stored_as"]
    if not dest_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Stored file not found on disk",
        )

    try:
        async with aiofiles.open(dest_path, "rb") as f:
            encrypted = await f.read()
        decrypted = encryption_service.decrypt(encrypted)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Decryption failed: {e}",
        )

    # Verify integrity
    checksum = encryption_service.compute_checksum(decrypted)
    if checksum != meta["checksum_sha256"]:
        logger.error(f"Checksum mismatch for file {file_id}!")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="File integrity check failed — data may be corrupted",
        )

    return Response(
        content=decrypted,
        media_type=meta["mime_type"],
        headers={
            "Content-Disposition": f'attachment; filename="{meta["original_name"]}"',
            "X-Checksum-SHA256": checksum,
        },
    )


@router.delete(
    "/{file_id}",
    summary="Delete a stored file",
)
async def delete_file(file_id: str):
    """Permanently delete an uploaded file and its metadata."""
    meta = _file_registry.get(file_id)
    if not meta:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File '{file_id}' not found",
        )

    dest_path = STORAGE_PATH / meta["stored_as"]
    try:
        if dest_path.exists():
            dest_path.unlink()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete file: {e}",
        )

    del _file_registry[file_id]
    logger.info(f"File deleted: {file_id}")
    return {"success": True, "file_id": file_id, "message": "File deleted"}


@router.get(
    "/",
    summary="List all uploaded files",
)
async def list_files():
    """List metadata for all stored files."""
    return {
        "count": len(_file_registry),
        "files": list(_file_registry.values()),
    }
