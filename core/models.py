from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime
import uuid


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OWASPCategory(str, Enum):
    A01 = "A01:2025 - Broken Access Control"
    A02 = "A02:2025 - Security Misconfiguration"
    A03 = "A03:2025 - Software Supply Chain Failures"
    A04 = "A04:2025 - Cryptographic Failures"
    A05 = "A05:2025 - Injection"
    A06 = "A06:2025 - Insecure Design"
    A07 = "A07:2025 - Authentication Failures"
    A08 = "A08:2025 - Software or Data Integrity Failures"
    A09 = "A09:2025 - Security Logging & Alerting Failures"
    A10 = "A10:2025 - Mishandling of Exceptional Conditions"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    module: str
    title: str
    description: str
    severity: Severity
    confidence: str = "high"
    owasp_categories: List[str] = Field(default_factory=list)
    url: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    recommendation: str = ""
    references: List[str] = Field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "module": self.module,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "owasp_categories": self.owasp_categories,
            "url": self.url,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "references": self.references
        }


class EndpointInfo(BaseModel):
    url: str
    path: str
    method: str = "GET"
    source: str
    found_on: Optional[str] = None
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    priority: str = "medium"
    auth_required: Optional[bool] = None
    redirect_url: Optional[str] = None
    parameters: List[str] = Field(default_factory=list)
    owasp_categories: List[str] = Field(default_factory=list)
    notes: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "path": self.path,
            "method": self.method,
            "source": self.source,
            "found_on": self.found_on,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "priority": self.priority,
            "auth_required": self.auth_required,
            "redirect_url": self.redirect_url,
            "parameters": self.parameters,
            "owasp_categories": self.owasp_categories,
            "notes": self.notes
        }


class HeaderAnalysis(BaseModel):
    name: str
    present: bool
    value: Optional[str] = None
    score: int = 0
    severity: Optional[Severity] = None
    issues: List[str] = Field(default_factory=list)
    recommendation: Optional[str] = None
    owasp_categories: List[str] = Field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "present": self.present,
            "value": self.value,
            "score": self.score,
            "severity": self.severity.value if self.severity else None,
            "issues": self.issues,
            "recommendation": self.recommendation,
            "owasp_categories": self.owasp_categories
        }


class CookieAnalysis(BaseModel):
    name: str
    value_preview: str = ""
    secure: bool = False
    httponly: bool = False
    samesite: Optional[str] = None
    path: Optional[str] = None
    domain: Optional[str] = None
    expires: Optional[str] = None
    is_session_cookie: bool = False
    score: int = 0
    issues: List[str] = Field(default_factory=list)
    owasp_categories: List[str] = Field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "value_preview": self.value_preview,
            "flags": {
                "secure": self.secure,
                "httponly": self.httponly,
                "samesite": self.samesite
            },
            "path": self.path,
            "domain": self.domain,
            "expires": self.expires,
            "is_session_cookie": self.is_session_cookie,
            "score": self.score,
            "issues": self.issues,
            "owasp_categories": self.owasp_categories
        }


class CORSAnalysis(BaseModel):
    enabled: bool = False
    allow_origin: Optional[str] = None
    allow_credentials: bool = False
    allow_methods: List[str] = Field(default_factory=list)
    allow_headers: List[str] = Field(default_factory=list)
    expose_headers: List[str] = Field(default_factory=list)
    max_age: Optional[int] = None
    issues: List[str] = Field(default_factory=list)
    score: int = 100
    owasp_categories: List[str] = Field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "allow_origin": self.allow_origin,
            "allow_credentials": self.allow_credentials,
            "allow_methods": self.allow_methods,
            "allow_headers": self.allow_headers,
            "expose_headers": self.expose_headers,
            "max_age": self.max_age,
            "issues": self.issues,
            "score": self.score,
            "owasp_categories": self.owasp_categories
        }


class ScanConfig(BaseModel):
    target_url: str
    modules: List[str] = ["endpoint_discovery", "header_analyzer"]

    # Endpoint Discovery settings
    crawl_depth: int = 3
    crawl_max_pages: int = 100
    bruteforce_enabled: bool = True
    wordlists: List[str] = ["common_paths.txt", "api_endpoints.txt"]

    # General settings
    timeout: int = 10
    rate_limit: float = 2.0
    user_agent: str = "OWASP-Scanner/1.0"
    verify_ssl: bool = True

    # Proxy (optional)
    proxy: Optional[str] = None

    # Auth (optional)
    auth_header: Optional[str] = None
    cookies: Optional[Dict[str, str]] = None


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_url: str
    start_time: datetime = Field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    status: str = "running"

    # Statistics
    total_requests: int = 0
    endpoints_discovered: int = 0

    # Results
    endpoints: List[EndpointInfo] = Field(default_factory=list)
    headers: List[HeaderAnalysis] = Field(default_factory=list)
    cookies: List[CookieAnalysis] = Field(default_factory=list)
    cors: Optional[CORSAnalysis] = None
    injection_results: Optional[Dict[str, Any]] = None
    auth_results: Optional[Dict[str, Any]] = None
    findings: List[Finding] = Field(default_factory=list)
    info_disclosures: List[Dict[str, Any]] = Field(default_factory=list)

    # Summary
    score: int = 100
    grade: str = "A"

    def calculate_grade(self):
        # Max points each severity bucket can deduct in total
        severity_config = {
            Severity.CRITICAL: {"per_finding": 20, "cap": 60},
            Severity.HIGH: {"per_finding": 10, "cap": 30},
            Severity.MEDIUM: {"per_finding": 5, "cap": 20},
            Severity.LOW: {"per_finding": 2, "cap": 8},
            Severity.INFO: {"per_finding": 0, "cap": 0},
        }

        # Group findings by severity
        from collections import defaultdict
        counts = defaultdict(int)
        for finding in self.findings:
            counts[finding.severity] += 1

        total_deduction = 0
        for severity, cfg in severity_config.items():
            n = counts.get(severity, 0)
            if n == 0:
                continue
            # First finding hits full cost; extras use log scaling
            import math
            raw = cfg["per_finding"] * (1 + math.log(n))
            total_deduction += min(raw, cfg["cap"])

        self.score = max(0, round(100 - total_deduction))

        if self.score >= 90:
            self.grade = "A"
        elif self.score >= 75:
            self.grade = "B"
        elif self.score >= 60:
            self.grade = "C"
        elif self.score >= 45:
            self.grade = "D"
        else:
            self.grade = "F"

    def to_dict(self) -> dict:
        self.calculate_grade()
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "status": self.status,
            "statistics": {
                "total_requests": self.total_requests,
                "endpoints_discovered": len(self.endpoints),
                "findings_count": len(self.findings),
                "findings_by_severity": self._count_by_severity()
            },
            "endpoints": [e.to_dict() for e in self.endpoints],
            "headers": [h.to_dict() for h in self.headers],
            "cookies": [c.to_dict() for c in self.cookies],
            "cors": self.cors.to_dict() if self.cors else None,
            "info_disclosures": self.info_disclosures,
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                "score": self.score,
                "grade": self.grade
            }
        }

    def _count_by_severity(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts