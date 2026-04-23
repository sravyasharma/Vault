import os
import magic
import logging
from pathlib import Path
from fastapi import UploadFile, HTTPException, status

from app.utils.config import settings

logger = logging.getLogger(__name__)


class ValidationResult:
    def __init__(self, valid: bool, mime_type: str = "", message: str = ""):
        self.valid = valid
        self.mime_type = mime_type
        self.message = message

    def __repr__(self):
        return f"ValidationResult(valid={self.valid}, mime_type={self.mime_type}, message={self.message})"


class FileValidator:
    """
    Validates uploaded files for:
    - File size limits
    - Blocked extensions
    - MIME type (content-based, not just extension)
    - MIME vs extension mismatch (polyglot detection)
    """

    def __init__(self):
        self.allowed_mimes = set(settings.ALLOWED_MIME_TYPES)
        self.blocked_exts = {ext.lower() for ext in settings.BLOCKED_EXTENSIONS}

    async def validate(self, file: UploadFile, content: bytes) -> ValidationResult:
        """Run all validation checks and return a ValidationResult."""

        # 1. File size check
        size_check = self._check_size(content)
        if not size_check.valid:
            return size_check

        # 2. Extension check
        ext_check = self._check_extension(file.filename)
        if not ext_check.valid:
            return ext_check

        # 3. MIME type check (magic bytes)
        mime_check = self._check_mime(content)
        if not mime_check.valid:
            return mime_check

        # 4. MIME vs extension mismatch check
        mismatch_check = self._check_mime_extension_mismatch(
            file.filename, mime_check.mime_type
        )
        if not mismatch_check.valid:
            return mismatch_check

        logger.info(
            f"File '{file.filename}' passed all validation checks "
            f"(MIME: {mime_check.mime_type}, size: {len(content)} bytes)"
        )
        return ValidationResult(valid=True, mime_type=mime_check.mime_type, message="OK")

    def _check_size(self, content: bytes) -> ValidationResult:
        size = len(content)
        max_size = settings.max_file_size_bytes
        if size > max_size:
            msg = (
                f"File too large: {size / (1024**2):.2f} MB "
                f"(limit: {settings.MAX_FILE_SIZE_MB} MB)"
            )
            logger.warning(msg)
            return ValidationResult(valid=False, message=msg)
        if size == 0:
            return ValidationResult(valid=False, message="Empty file not allowed")
        return ValidationResult(valid=True)

    def _check_extension(self, filename: str) -> ValidationResult:
        if not filename:
            return ValidationResult(valid=False, message="Filename is required")

        ext = Path(filename).suffix.lower()
        if ext in self.blocked_exts:
            msg = f"File extension '{ext}' is not allowed"
            logger.warning(f"Blocked extension detected: {filename}")
            return ValidationResult(valid=False, message=msg)

        return ValidationResult(valid=True)

    def _check_mime(self, content: bytes) -> ValidationResult:
        try:
            mime = magic.from_buffer(content, mime=True)
        except Exception as e:
            logger.error(f"MIME detection failed: {e}")
            return ValidationResult(valid=False, message="Could not determine file type")

        if mime not in self.allowed_mimes:
            msg = f"File type '{mime}' is not permitted"
            logger.warning(f"Blocked MIME type: {mime}")
            return ValidationResult(valid=False, mime_type=mime, message=msg)

        return ValidationResult(valid=True, mime_type=mime)

    def _check_mime_extension_mismatch(
        self, filename: str, detected_mime: str
    ) -> ValidationResult:
        """
        Detect polyglot files: e.g., a .jpg that is actually a ZIP.
        Maps common extensions to expected MIME types.
        """
        ext = Path(filename).suffix.lower() if filename else ""
        ext_to_mime: dict[str, list[str]] = {
            ".jpg": ["image/jpeg"],
            ".jpeg": ["image/jpeg"],
            ".png": ["image/png"],
            ".gif": ["image/gif"],
            ".webp": ["image/webp"],
            ".pdf": ["application/pdf"],
            ".txt": ["text/plain"],
            ".csv": ["text/plain", "text/csv"],
            ".json": ["application/json", "text/plain"],
            ".zip": ["application/zip", "application/x-zip-compressed"],
            ".docx": [
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "application/zip",  # .docx is a ZIP internally
            ],
            ".xlsx": [
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "application/zip",
            ],
        }

        expected_mimes = ext_to_mime.get(ext)
        if expected_mimes and detected_mime not in expected_mimes:
            msg = (
                f"File extension '{ext}' does not match detected type '{detected_mime}'. "
                f"Possible file spoofing attempt."
            )
            logger.warning(
                f"MIME/extension mismatch for '{filename}': "
                f"expected {expected_mimes}, got {detected_mime}"
            )
            return ValidationResult(valid=False, message=msg)

        return ValidationResult(valid=True, mime_type=detected_mime)


# Singleton
validator = FileValidator()
