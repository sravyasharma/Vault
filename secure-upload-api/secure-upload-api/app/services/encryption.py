import os
import base64
import logging
import hashlib
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.utils.config import settings

logger = logging.getLogger(__name__)


class EncryptionService:
    """
    Handles symmetric encryption/decryption of files using Fernet (AES-128-CBC + HMAC-SHA256).

    Key derivation:
    - If ENCRYPTION_KEY is a valid 32-byte URL-safe base64 string → use as-is.
    - Otherwise → derive a proper Fernet key via PBKDF2HMAC.
    """

    SALT_FILE = ".encryption_salt"

    def __init__(self):
        self._fernet = self._init_fernet()

    def _init_fernet(self) -> Fernet:
        raw_key = settings.ENCRYPTION_KEY
        try:
            # Try to use the key directly (must be URL-safe base64, 32 bytes decoded)
            decoded = base64.urlsafe_b64decode(raw_key + "==")
            if len(decoded) == 32:
                fernet_key = base64.urlsafe_b64encode(decoded)
                logger.info("Encryption initialised with provided key")
                return Fernet(fernet_key)
        except Exception:
            pass

        # Derive key from passphrase via PBKDF2
        salt = self._get_or_create_salt()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,
        )
        fernet_key = base64.urlsafe_b64encode(kdf.derive(raw_key.encode()))
        logger.info("Encryption key derived via PBKDF2HMAC")
        return Fernet(fernet_key)

    def _get_or_create_salt(self) -> bytes:
        salt_path = Path(settings.STORAGE_PATH) / self.SALT_FILE
        salt_path.parent.mkdir(parents=True, exist_ok=True)

        if salt_path.exists():
            return salt_path.read_bytes()

        salt = os.urandom(16)
        salt_path.write_bytes(salt)
        logger.info("Generated new encryption salt")
        return salt

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt raw bytes and return ciphertext."""
        try:
            encrypted = self._fernet.encrypt(data)
            logger.debug(f"Encrypted {len(data)} bytes → {len(encrypted)} bytes")
            return encrypted
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise RuntimeError("Encryption failed") from e

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext and return plaintext bytes."""
        try:
            data = self._fernet.decrypt(ciphertext)
            logger.debug(f"Decrypted {len(ciphertext)} bytes → {len(data)} bytes")
            return data
        except InvalidToken as e:
            logger.error("Decryption failed: invalid token or corrupted data")
            raise ValueError("Decryption failed: invalid or corrupted file") from e
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise RuntimeError("Decryption failed") from e

    def compute_checksum(self, data: bytes) -> str:
        """Return SHA-256 hex digest of data."""
        return hashlib.sha256(data).hexdigest()

    def rotate_key(self, ciphertext: bytes, new_key: str) -> bytes:
        """
        Re-encrypt data with a new key (key rotation).
        Returns new ciphertext encrypted under new_key.
        """
        plaintext = self.decrypt(ciphertext)

        try:
            decoded = base64.urlsafe_b64decode(new_key + "==")
            if len(decoded) == 32:
                new_fernet_key = base64.urlsafe_b64encode(decoded)
            else:
                raise ValueError("Invalid key length")
        except Exception:
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=600_000,
            )
            new_fernet_key = base64.urlsafe_b64encode(kdf.derive(new_key.encode()))

        new_fernet = Fernet(new_fernet_key)
        return new_fernet.encrypt(plaintext)


# Singleton
encryption_service = EncryptionService()
