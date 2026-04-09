import ssl
import socket
from datetime import datetime
from typing import Dict, Any, List
from urllib.parse import urlparse
import logging

from core.models import Finding, Severity
from core.session import HTTPSession

logger = logging.getLogger(__name__)


class SSLAnalyzer:
    name = "ssl_analyzer"
    description = "Analyzes SSL/TLS certificates and cipher suites"
    owasp_categories = ["A02", "A04"]

    WEAK_CIPHERS = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon', '3DES']

    def __init__(self, session: HTTPSession, target_url: str):
        self.session = session
        self.target_url = target_url
        self.findings: List[Finding] = []
        self.cert_info: Dict[str, Any] = {}
        self.cipher_info: Dict[str, Any] = {}

    async def run(self) -> Dict[str, Any]:
        logger.info(f"Starting SSL analysis for {self.target_url}")

        parsed = urlparse(self.target_url)

        # Only analyze HTTPS
        if parsed.scheme != "https":
            return {
                "skipped": True,
                "reason": "Not HTTPS",
                "findings": [],
                "summary": {"checked": False}
            }

        hostname = parsed.netloc.split(":")[0]
        port = parsed.port or 443

        try:
            self._analyze_certificate(hostname, port)
            self._analyze_cipher(hostname, port)
        except Exception as e:
            logger.error(f"SSL analysis error: {e}")

        return {
            "certificate": self.cert_info,
            "cipher": self.cipher_info,
            "findings": self.findings,
            "summary": self._generate_summary()
        }

    def _analyze_certificate(self, hostname: str, port: int):
        context = ssl.create_default_context()

        try:
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    self._parse_certificate(cert, hostname)

        except ssl.SSLCertVerificationError as e:
            self.cert_info = {"valid": False, "error": str(e)}
            self.findings.append(Finding(
                module=self.name,
                title="SSL Certificate Verification Failed",
                description=f"Certificate verification failed: {e}",
                severity=Severity.HIGH,
                owasp_categories=self.owasp_categories,
                url=self.target_url,
                recommendation="Use a valid SSL certificate from a trusted CA"
            ))

        except socket.timeout:
            self.cert_info = {"valid": False, "error": "Connection timeout"}

        except Exception as e:
            self.cert_info = {"valid": False, "error": str(e)}

    def _parse_certificate(self, cert: Dict, hostname: str):
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_until_expiry = (not_after - datetime.utcnow()).days

        self.cert_info = {
            "valid": True,
            "subject": subject.get("commonName", ""),
            "issuer": issuer.get("commonName", ""),
            "expires": not_after.isoformat(),
            "days_until_expiry": days_until_expiry
        }

        # Check expiry
        if days_until_expiry < 0:
            self.findings.append(Finding(
                module=self.name,
                title="SSL Certificate Expired",
                description=f"Certificate expired {abs(days_until_expiry)} days ago",
                severity=Severity.CRITICAL,
                owasp_categories=self.owasp_categories,
                url=self.target_url,
                recommendation="Renew the SSL certificate immediately"
            ))
        elif days_until_expiry < 30:
            self.findings.append(Finding(
                module=self.name,
                title="SSL Certificate Expiring Soon",
                description=f"Certificate expires in {days_until_expiry} days",
                severity=Severity.MEDIUM,
                owasp_categories=self.owasp_categories,
                url=self.target_url,
                recommendation="Plan to renew the SSL certificate"
            ))

        # Check self-signed
        if subject.get("commonName") == issuer.get("commonName"):
            self.findings.append(Finding(
                module=self.name,
                title="Self-Signed Certificate",
                description="Certificate appears to be self-signed",
                severity=Severity.MEDIUM,
                owasp_categories=self.owasp_categories,
                url=self.target_url,
                recommendation="Use a certificate from a trusted CA"
            ))

    def _analyze_cipher(self, hostname: str, port: int):
        try:
            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    protocol = ssock.version()

                    if cipher:
                        cipher_name, _, bits = cipher

                        self.cipher_info = {
                            "name": cipher_name,
                            "bits": bits,
                            "protocol": protocol
                        }

                        # Check weak cipher
                        if any(weak in cipher_name.upper() for weak in self.WEAK_CIPHERS):
                            self.findings.append(Finding(
                                module=self.name,
                                title="Weak Cipher Suite",
                                description=f"Server uses weak cipher: {cipher_name}",
                                severity=Severity.MEDIUM,
                                owasp_categories=self.owasp_categories,
                                url=self.target_url,
                                recommendation="Disable weak cipher suites"
                            ))

                        # Check low bits
                        if bits and bits < 128:
                            self.findings.append(Finding(
                                module=self.name,
                                title="Low Encryption Strength",
                                description=f"Cipher uses only {bits}-bit encryption",
                                severity=Severity.HIGH,
                                owasp_categories=self.owasp_categories,
                                url=self.target_url,
                                recommendation="Use at least 128-bit encryption"
                            ))

                    # Check outdated protocol
                    if protocol in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"]:
                        self.findings.append(Finding(
                            module=self.name,
                            title="Outdated TLS Protocol",
                            description=f"Server uses deprecated protocol: {protocol}",
                            severity=Severity.HIGH,
                            owasp_categories=self.owasp_categories,
                            url=self.target_url,
                            recommendation="Upgrade to TLS 1.2 or TLS 1.3"
                        ))

        except Exception as e:
            logger.warning(f"Cipher analysis error: {e}")

    def _generate_summary(self) -> Dict[str, Any]:
        return {
            "certificate_valid": self.cert_info.get("valid", False),
            "days_until_expiry": self.cert_info.get("days_until_expiry", 0),
            "protocol": self.cipher_info.get("protocol", "unknown"),
            "findings_count": len(self.findings)
        }