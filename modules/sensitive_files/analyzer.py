import re
from typing import Dict, Any, List
from urllib.parse import urljoin
import logging

from core.models import Finding, Severity
from core.session import HTTPSession, get_base_url

logger = logging.getLogger(__name__)


class SensitiveFileAnalyzer:
    name = "sensitive_files"
    description = "Checks for exposed sensitive files and credentials"
    owasp_categories = ["A02", "A05"]

    SENSITIVE_FILES = [
        ".env", ".env.local", ".env.production", ".env.backup",
        ".git/config", ".git/HEAD",
        "config.json", "config.yaml", "config.yml",
        "package.json", "composer.json", "requirements.txt",
        "backup.sql", "database.sql", "dump.sql",
        ".htpasswd", ".htaccess",
        "phpinfo.php", "info.php",
        "wp-config.php", "web.config"
    ]

    SECRET_PATTERNS = [
        (r'api[_-]?key["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})', "API Key"),
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
        (r'password["\s:=]+["\']?([^\s"\']{4,})', "Password"),
        (r'secret["\s:=]+["\']?([^\s"\']{8,})', "Secret"),
        (r'token["\s:=]+["\']?([a-zA-Z0-9_\-\.]{20,})', "Token"),
        (r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----', "Private Key"),
        (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', "JWT"),
        (r'ghp_[a-zA-Z0-9]{36}', "GitHub Token"),
        (r'sk_live_[0-9a-zA-Z]{24}', "Stripe Key"),
    ]

    def __init__(self, session: HTTPSession, target_url: str):
        self.session = session
        self.target_url = target_url
        self.base_url = get_base_url(target_url)
        self.findings: List[Finding] = []
        self.found_files: List[Dict[str, Any]] = []
        self.found_secrets: List[Dict[str, Any]] = []

    async def run(self) -> Dict[str, Any]:
        logger.info(f"Starting sensitive file analysis for {self.base_url}")

        for file_path in self.SENSITIVE_FILES:
            await self._check_file(file_path)

        return {
            "files": self.found_files,
            "secrets": self.found_secrets,
            "findings": self.findings,
            "summary": self._generate_summary()
        }

    async def _check_file(self, file_path: str):
        url = urljoin(self.base_url + "/", file_path)
        response = await self.session.get(url)

        if not response or response.status_code == 404:
            return

        content = response.text or ""

        # Skip soft 404s
        if self._is_soft_404(content):
            return

        # File found!
        file_info = {
            "path": file_path,
            "url": url,
            "status": response.status_code,
            "size": len(content)
        }
        self.found_files.append(file_info)

        if response.status_code == 200:
            self._analyze_content(file_path, url, content)
        elif response.status_code == 403:
            self.findings.append(Finding(
                module=self.name,
                title=f"Sensitive File Exists: {file_path}",
                description=f"File exists but access is forbidden",
                severity=Severity.LOW,
                owasp_categories=self.owasp_categories,
                url=url,
                recommendation="Remove this file from the web server"
            ))

    def _is_soft_404(self, content: str) -> bool:
        indicators = ["not found", "404", "page not found", "does not exist"]
        lower = content.lower()
        return any(ind in lower for ind in indicators)

    def _analyze_content(self, file_path: str, url: str, content: str):
        severity = self._get_severity(file_path)

        # Add finding for exposed file
        self.findings.append(Finding(
            module=self.name,
            title=f"Sensitive File Exposed: {file_path}",
            description=f"Sensitive file is publicly accessible",
            severity=severity,
            owasp_categories=self.owasp_categories,
            url=url,
            evidence={"size": len(content)},
            recommendation=f"Remove {file_path} from web root"
        ))

        # Search for secrets
        self._find_secrets(file_path, url, content)

    def _get_severity(self, file_path: str) -> Severity:
        if any(x in file_path for x in [".env", ".git/config", ".htpasswd", "backup.sql"]):
            return Severity.CRITICAL
        if any(x in file_path for x in ["config.json", "config.yaml", "wp-config"]):
            return Severity.HIGH
        return Severity.MEDIUM

    def _find_secrets(self, file_path: str, url: str, content: str):
        for pattern, secret_type in self.SECRET_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                value = match.group(1) if match.groups() else match.group(0)
                masked = value[:2] + "*" * (len(value) - 4) + value[-2:] if len(value) > 8 else "****"

                self.found_secrets.append({
                    "file": file_path,
                    "type": secret_type,
                    "masked": masked
                })

                self.findings.append(Finding(
                    module=self.name,
                    title=f"{secret_type} Found in {file_path}",
                    description=f"Potential {secret_type} exposed",
                    severity=Severity.CRITICAL,
                    owasp_categories=self.owasp_categories,
                    url=url,
                    evidence={"type": secret_type, "masked": masked},
                    recommendation=f"Rotate this {secret_type} immediately"
                ))

    def _generate_summary(self) -> Dict[str, Any]:
        return {
            "files_checked": len(self.SENSITIVE_FILES),
            "files_found": len(self.found_files),
            "secrets_found": len(self.found_secrets),
            "findings_count": len(self.findings)
        }