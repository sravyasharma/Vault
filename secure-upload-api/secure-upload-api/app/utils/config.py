import os
import secrets
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # App
    APP_NAME: str = "Secure File Upload API"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Storage
    STORAGE_PATH: str = Field(default="storage", description="Local storage directory")
    MAX_FILE_SIZE_MB: int = Field(default=50, description="Max upload size in MB")

    # Encryption
    ENCRYPTION_KEY: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32),
        description="Fernet encryption key (base64-encoded 32-byte key)",
    )

    # ClamAV
    CLAMAV_HOST: str = Field(default="localhost", description="ClamAV daemon host")
    CLAMAV_PORT: int = Field(default=3310, description="ClamAV daemon port")
    CLAMAV_TIMEOUT: int = Field(default=60, description="ClamAV scan timeout seconds")

    # Allowed MIME types
    ALLOWED_MIME_TYPES: list[str] = [
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/webp",
        "application/pdf",
        "text/plain",
        "text/csv",
        "application/json",
        "application/zip",
        "application/x-zip-compressed",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ]

    # Blocked extensions (always reject regardless of MIME)
    BLOCKED_EXTENSIONS: list[str] = [
        ".exe", ".bat", ".cmd", ".sh", ".ps1", ".vbs",
        ".js", ".msi", ".com", ".scr", ".pif", ".reg",
        ".dll", ".sys", ".drv", ".lnk",
    ]

    @property
    def max_file_size_bytes(self) -> int:
        return self.MAX_FILE_SIZE_MB * 1024 * 1024

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
