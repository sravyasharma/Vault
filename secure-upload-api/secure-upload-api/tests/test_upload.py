"""
Tests for the Secure File Upload API.
Run with: pytest tests/ -v
"""
import io
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.services.scanner import ScanResult, ScanStatus
from app.services.encryption import encryption_service

client = TestClient(app)


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_upload(content: bytes, filename: str, content_type: str = "image/jpeg"):
    return ("file", (filename, io.BytesIO(content), content_type))


# Minimal valid JPEG header (SOI marker + tiny data)
JPEG_MAGIC = b"\xff\xd8\xff\xe0" + b"\x00" * 100
PNG_MAGIC = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
PDF_MAGIC = b"%PDF-1.4\n" + b"\x00" * 100


# ── Encryption service tests ──────────────────────────────────────────────────

class TestEncryptionService:
    def test_encrypt_decrypt_roundtrip(self):
        data = b"Hello, secure world!"
        encrypted = encryption_service.encrypt(data)
        assert encrypted != data
        decrypted = encryption_service.decrypt(encrypted)
        assert decrypted == data

    def test_checksum_consistency(self):
        data = b"checksum test"
        cs1 = encryption_service.compute_checksum(data)
        cs2 = encryption_service.compute_checksum(data)
        assert cs1 == cs2
        assert len(cs1) == 64  # SHA-256 hex

    def test_different_data_different_checksum(self):
        assert encryption_service.compute_checksum(b"a") != encryption_service.compute_checksum(b"b")

    def test_tampered_ciphertext_raises(self):
        encrypted = encryption_service.encrypt(b"secret")
        tampered = encrypted[:-5] + b"XXXXX"
        with pytest.raises((ValueError, Exception)):
            encryption_service.decrypt(tampered)


# ── Validator tests ───────────────────────────────────────────────────────────

class TestFileValidator:
    """Test via the upload endpoint with mocked ClamAV."""

    @patch("app.routes.upload.scanner")
    def test_valid_jpeg_accepted(self, mock_scanner):
        mock_scanner.scan.return_value = ScanResult(status=ScanStatus.CLEAN, message="OK")
        files = [make_upload(JPEG_MAGIC, "photo.jpg", "image/jpeg")]
        resp = client.post("/upload/", files=files)
        assert resp.status_code == 201
        data = resp.json()
        assert data["success"] is True
        assert data["mime_type"] == "image/jpeg"

    @patch("app.routes.upload.scanner")
    def test_blocked_extension_rejected(self, mock_scanner):
        mock_scanner.scan.return_value = ScanResult(status=ScanStatus.CLEAN)
        files = [make_upload(b"malicious", "virus.exe", "application/octet-stream")]
        resp = client.post("/upload/", files=files)
        assert resp.status_code == 422
        assert "extension" in resp.json()["detail"]["error"].lower()

    @patch("app.routes.upload.scanner")
    def test_empty_file_rejected(self, mock_scanner):
        mock_scanner.scan.return_value = ScanResult(status=ScanStatus.CLEAN)
        files = [make_upload(b"", "empty.txt", "text/plain")]
        resp = client.post("/upload/", files=files)
        assert resp.status_code == 422

    @patch("app.routes.upload.scanner")
    def test_mime_mismatch_rejected(self, mock_scanner):
        """A .jpg file whose content is actually a ZIP should be rejected."""
        mock_scanner.scan.return_value = ScanResult(status=ScanStatus.CLEAN)
        # ZIP magic bytes in a .jpg file
        zip_content = b"PK\x03\x04" + b"\x00" * 100
        files = [make_upload(zip_content, "photo.jpg", "application/zip")]
        resp = client.post("/upload/", files=files)
        assert resp.status_code == 422

    @patch("app.routes.upload.scanner")
    def test_infected_file_rejected(self, mock_scanner):
        mock_scanner.scan.return_value = ScanResult(
            status=ScanStatus.INFECTED,
            threat_name="Eicar-Signature",
            message="Malware detected: Eicar-Signature",
        )
        files = [make_upload(JPEG_MAGIC, "infected.jpg", "image/jpeg")]
        resp = client.post("/upload/", files=files)
        assert resp.status_code == 400
        detail = resp.json()["detail"]
        assert detail["stage"] == "antivirus"
        assert "Eicar" in detail["threat"]

    @patch("app.routes.upload.scanner")
    def test_pdf_accepted(self, mock_scanner):
        mock_scanner.scan.return_value = ScanResult(status=ScanStatus.CLEAN, message="OK")
        files = [make_upload(PDF_MAGIC, "document.pdf", "application/pdf")]
        resp = client.post("/upload/", files=files)
        assert resp.status_code == 201


# ── Upload lifecycle tests ────────────────────────────────────────────────────

class TestUploadLifecycle:
    @patch("app.routes.upload.scanner")
    def test_upload_metadata_download_delete(self, mock_scanner):
        mock_scanner.scan.return_value = ScanResult(status=ScanStatus.CLEAN, message="OK")

        # Upload
        files = [make_upload(JPEG_MAGIC, "lifecycle.jpg", "image/jpeg")]
        resp = client.post("/upload/", files=files)
        assert resp.status_code == 201
        file_id = resp.json()["file_id"]

        # Metadata
        resp = client.get(f"/upload/{file_id}/metadata")
        assert resp.status_code == 200
        meta = resp.json()
        assert meta["file_id"] == file_id
        assert meta["original_name"] == "lifecycle.jpg"

        # Download
        resp = client.get(f"/upload/{file_id}/download")
        assert resp.status_code == 200
        assert resp.content == JPEG_MAGIC
        assert "X-Checksum-SHA256" in resp.headers

        # Delete
        resp = client.delete(f"/upload/{file_id}")
        assert resp.status_code == 200
        assert resp.json()["success"] is True

        # Confirm deleted
        resp = client.get(f"/upload/{file_id}/metadata")
        assert resp.status_code == 404

    def test_not_found_returns_404(self):
        resp = client.get("/upload/nonexistent-id/metadata")
        assert resp.status_code == 404

    @patch("app.routes.upload.scanner")
    def test_list_files(self, mock_scanner):
        mock_scanner.scan.return_value = ScanResult(status=ScanStatus.CLEAN, message="OK")
        files = [make_upload(JPEG_MAGIC, "list_test.jpg", "image/jpeg")]
        client.post("/upload/", files=files)
        resp = client.get("/upload/")
        assert resp.status_code == 200
        assert "count" in resp.json()
        assert "files" in resp.json()


# ── Health check ──────────────────────────────────────────────────────────────

class TestHealth:
    def test_root(self):
        resp = client.get("/")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_health(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "clamav" in data
        assert "encryption" in data
