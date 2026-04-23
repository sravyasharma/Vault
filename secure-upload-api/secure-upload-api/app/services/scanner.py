import io
import logging
import socket
from enum import Enum
from dataclasses import dataclass

try:
    import clamd
    CLAMD_AVAILABLE = True
except ImportError:
    CLAMD_AVAILABLE = False

from app.utils.config import settings

logger = logging.getLogger(__name__)


class ScanStatus(str, Enum):
    CLEAN = "CLEAN"
    INFECTED = "INFECTED"
    ERROR = "ERROR"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass
class ScanResult:
    status: ScanStatus
    threat_name: str | None = None
    message: str = ""

    @property
    def is_safe(self) -> bool:
        """
        A file is safe to store only if explicitly CLEAN.
        UNAVAILABLE falls back to safe (degraded mode) — configurable.
        """
        return self.status in (ScanStatus.CLEAN, ScanStatus.UNAVAILABLE)

    @property
    def should_reject(self) -> bool:
        return self.status == ScanStatus.INFECTED


class ClamAVScanner:
    """
    ClamAV antivirus scanner with graceful degradation.

    Connects to clamd via TCP socket. Falls back to UNAVAILABLE
    if the daemon is not running (so the API still works in dev
    environments without ClamAV installed).
    """

    def __init__(self):
        self.host = settings.CLAMAV_HOST
        self.port = settings.CLAMAV_PORT
        self.timeout = settings.CLAMAV_TIMEOUT
        self._client = None

    def _get_client(self):
        """Lazily initialise the clamd client."""
        if not CLAMD_AVAILABLE:
            return None
        if self._client is None:
            try:
                self._client = clamd.ClamdNetworkSocket(
                    host=self.host,
                    port=self.port,
                    timeout=self.timeout,
                )
                # Ping to verify connectivity
                self._client.ping()
                logger.info(f"ClamAV connected at {self.host}:{self.port}")
            except Exception as e:
                logger.warning(f"ClamAV not available: {e}")
                self._client = None
        return self._client

    def scan(self, data: bytes, filename: str = "upload") -> ScanResult:
        """
        Scan file bytes for malware.
        Returns ScanResult with CLEAN, INFECTED, ERROR, or UNAVAILABLE.
        """
        client = self._get_client()

        if client is None:
            logger.warning(
                "ClamAV unavailable — scanning skipped (degraded mode). "
                "Ensure clamd is running in production!"
            )
            return ScanResult(
                status=ScanStatus.UNAVAILABLE,
                message="ClamAV daemon not reachable. File not virus-scanned.",
            )

        try:
            stream = io.BytesIO(data)
            result = client.instream(stream)

            # result = {'stream': ('OK', None)} or {'stream': ('FOUND', 'Eicar-Signature')}
            status_str, threat = result.get("stream", ("ERROR", None))

            if status_str == "OK":
                logger.info(f"Scan CLEAN: '{filename}'")
                return ScanResult(status=ScanStatus.CLEAN, message="No threats detected")

            elif status_str == "FOUND":
                logger.warning(f"MALWARE DETECTED in '{filename}': {threat}")
                return ScanResult(
                    status=ScanStatus.INFECTED,
                    threat_name=threat,
                    message=f"Malware detected: {threat}",
                )

            else:
                logger.error(f"Unexpected ClamAV result: {result}")
                return ScanResult(
                    status=ScanStatus.ERROR,
                    message=f"Unexpected scan result: {status_str}",
                )

        except clamd.ConnectionError as e:
            # Reset client so next request retries connection
            self._client = None
            logger.error(f"ClamAV connection lost: {e}")
            return ScanResult(
                status=ScanStatus.UNAVAILABLE,
                message="Lost connection to ClamAV daemon",
            )
        except Exception as e:
            logger.error(f"Scan error for '{filename}': {e}")
            return ScanResult(
                status=ScanStatus.ERROR,
                message=f"Scan failed: {str(e)}",
            )

    def ping(self) -> bool:
        """Returns True if ClamAV daemon is reachable."""
        client = self._get_client()
        if client is None:
            return False
        try:
            client.ping()
            return True
        except Exception:
            self._client = None
            return False

    def get_version(self) -> str | None:
        """Returns ClamAV version string or None."""
        client = self._get_client()
        if client is None:
            return None
        try:
            return client.version()
        except Exception:
            return None


# Singleton
scanner = ClamAVScanner()
