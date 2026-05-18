import re
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import logging

from core.models import Finding, Severity, EndpointInfo
from core.session import HTTPSession, get_base_url

logger = logging.getLogger(__name__)


class InjectionTester:
    name = "injection_tester"
    description = "Tests for SQL injection and XSS vulnerabilities"
    owasp_categories = ["A03"]

    # SQL Injection payloads
    SQLI_PAYLOADS = [
        # Error-based
        "'",
        "''",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "1' ORDER BY 1--",
        "1' ORDER BY 10--",
        "' UNION SELECT NULL--",
        "1; DROP TABLE users--",

        # Time-based (careful!)
        "' AND SLEEP(2)--",
        "'; WAITFOR DELAY '0:0:2'--",

        # Boolean-based
        "' AND '1'='1",
        "' AND '1'='2",
    ]

    # SQL error patterns
    SQLI_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySqlException",
        r"valid MySQL result",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_",
        r"valid PostgreSQL result",
        r"ORA-\d{5}",
        r"Oracle error",
        r"SQLite.*error",
        r"sqlite3\.OperationalError",
        r"Microsoft.*ODBC.*SQL Server",
        r"SQLServer JDBC Driver",
        r"Unclosed quotation mark",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
        r"unexpected end of SQL command",
        r"SQLSTATE\[",
        r"syntax error at or near",
    ]

    # XSS payloads
    XSS_PAYLOADS = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        'javascript:alert(1)',
        '<body onload=alert(1)>',
        '"><img src=x onerror=alert(1)>',
        "{{constructor.constructor('alert(1)')()}}",  # Template injection
    ]

    # XSS reflection patterns
    XSS_REFLECTION_PATTERNS = [
        r'<script>alert\(1\)</script>',
        r'onerror\s*=\s*alert',
        r'onload\s*=\s*alert',
        r'javascript:alert',
    ]

    def __init__(
            self,
            session: HTTPSession,
            target_url: str,
            endpoints: Optional[List[EndpointInfo]] = None,
            test_sqli: bool = True,
            test_xss: bool = True,
            max_tests_per_endpoint: int = 10,
            custom_test_cases: Optional[List[Dict[str, Any]]] = None
    ):
        self.session = session
        self.target_url = target_url
        self.base_url = get_base_url(target_url)
        self.endpoints = endpoints or []
        self.test_sqli = test_sqli
        self.test_xss = test_xss
        self.max_tests = max_tests_per_endpoint
        self.findings: List[Finding] = []
        self.tested_params: List[Dict[str, Any]] = []
        self.custom_test_cases = custom_test_cases or []

    async def run(self) -> Dict[str, Any]:
        logger.info(f"Starting injection testing for {self.base_url}")

        # Get testable endpoints
        testable = self._get_testable_endpoints()

        if not testable:
            logger.info("No testable endpoints found")
            return {
                "tested_endpoints": [],
                "findings": [],
                "summary": {
                    "endpoints_tested": 0,
                    "sqli_found": 0,
                    "xss_found": 0,
                    "findings_count": 0
                }
            }

        # Test each endpoint
        for endpoint in testable[:20]:  # Limit to 20 endpoints
            await self._test_endpoint(endpoint)

        # Summarize
        sqli_count = len([f for f in self.findings if "SQL" in f.title])
        xss_count = len([f for f in self.findings if "XSS" in f.title])

        return {
            "tested_endpoints": self.tested_params,
            "findings": self.findings,
            "summary": {
                "endpoints_tested": len(testable[:20]),
                "sqli_found": sqli_count,
                "xss_found": xss_count,
                "findings_count": len(self.findings)
            }
        }

    def _build_url_with_params(self, url: str, params: Dict[str, str]) -> str:
        if not params:
            return url

        separator = "&" if "?" in url else "?"
        return f"{url}{separator}{urlencode(params)}"

    def _get_testable_endpoints(self) -> List[Dict[str, Any]]:
        testable = []

        # From provided endpoints
        for ep in self.endpoints:
            url = ep.url if hasattr(ep, 'url') else f"{self.base_url}{ep.path}"
            parsed = urlparse(url)

            if parsed.query:
                params = parse_qs(parsed.query)
                testable.append({
                    "url": url.split("?")[0],
                    "params": {k: v[0] for k, v in params.items()},
                    "method": "GET",
                    "source": ep.source if hasattr(ep, 'source') else "discovery"
                })

        # Also test the main URL with common param names
        common_params = ["id", "page", "search", "q", "query", "user", "name", "file", "path"]
        for param in common_params:
            testable.append({
                "url": self.base_url,
                "params": {param: "1"},
                "method": "GET",
                "source": "common_params"
            })

        for case in self.custom_test_cases:
            path = case.get("path") or case.get("url")
            if not path:
                continue

            full_url = path if path.startswith(("http://", "https://")) else f"{self.base_url}{path}"

            testable.append({
                "url": full_url,
                "params": case.get("params", {}),
                "method": case.get("method", "GET").upper(),
                "source": "custom_test_cases"
            })

        return testable

    async def _test_endpoint(self, endpoint: Dict[str, Any]):
        url = endpoint["url"]
        params = endpoint["params"]

        for param_name, original_value in params.items():
            # Test SQLi
            if self.test_sqli:
                await self._test_sqli(url, param_name, original_value, params)

            # Test XSS
            if self.test_xss:
                await self._test_xss(url, param_name, original_value, params)

    async def _test_sqli(
            self,
            url: str,
            param_name: str,
            original_value: str,
            all_params: Dict[str, str]
    ):
        # Get baseline response
        baseline_url = self._build_url_with_params(url, all_params)
        baseline = await self.session.get(baseline_url)
        if not baseline:
            return

        baseline_length = len(baseline.text)

        for payload in self.SQLI_PAYLOADS[:self.max_tests]:
            test_params = all_params.copy()
            test_params[param_name] = payload

            test_url = self._build_url_with_params(url, test_params)
            response = await self.session.get(test_url)
            if not response:
                continue

            # Check for SQL errors in response
            is_vulnerable = False
            evidence = []

            for pattern in self.SQLI_ERROR_PATTERNS:
                if re.search(pattern, response.text, re.IGNORECASE):
                    is_vulnerable = True
                    evidence.append(f"SQL error pattern: {pattern}")
                    break

            # Check for significant response difference (boolean-based)
            if not is_vulnerable:
                length_diff = abs(len(response.text) - baseline_length)
                if length_diff > 500 and "1'='1" in payload:
                    # Could be boolean-based SQLi
                    is_vulnerable = True
                    evidence.append(f"Response length changed by {length_diff} bytes")

            if is_vulnerable:
                self.findings.append(Finding(
                    module=self.name,
                    title=f"Potential SQL Injection in '{param_name}'",
                    description=f"Parameter '{param_name}' at {url} may be vulnerable to SQL injection",
                    severity=Severity.CRITICAL,
                    owasp_categories=self.owasp_categories,
                    url=url,
                    evidence={
                        "parameter": param_name,
                        "payload": payload,
                        "indicators": evidence
                    },
                    recommendation="Use parameterized queries/prepared statements. Never concatenate user input into SQL queries."
                ))

                self.tested_params.append({
                    "url": url,
                    "parameter": param_name,
                    "type": "sqli",
                    "vulnerable": True,
                    "payload": payload
                })

                # Found SQLi, don't test more payloads for this param
                return

        self.tested_params.append({
            "url": url,
            "parameter": param_name,
            "type": "sqli",
            "vulnerable": False
        })

    async def _test_xss(
            self,
            url: str,
            param_name: str,
            original_value: str,
            all_params: Dict[str, str]
    ):
        for payload in self.XSS_PAYLOADS[:self.max_tests]:
            test_params = all_params.copy()
            test_params[param_name] = payload

            test_url = self._build_url_with_params(url, test_params)
            response = await self.session.get(test_url)
            if not response:
                continue

            # Check if payload is reflected
            is_reflected = False
            evidence = []

            # Direct reflection
            if payload in response.text:
                is_reflected = True
                evidence.append("Payload directly reflected in response")

            # Check for dangerous patterns
            for pattern in self.XSS_REFLECTION_PATTERNS:
                if re.search(pattern, response.text, re.IGNORECASE):
                    is_reflected = True
                    evidence.append(f"XSS pattern found: {pattern}")
                    break

            if is_reflected:
                # Check Content-Type - XSS mainly affects HTML
                content_type = response.headers.get("Content-Type", "")
                if "html" in content_type.lower():
                    severity = Severity.HIGH
                else:
                    severity = Severity.MEDIUM

                self.findings.append(Finding(
                    module=self.name,
                    title=f"Potential XSS in '{param_name}'",
                    description=f"Parameter '{param_name}' at {url} reflects user input without proper encoding",
                    severity=severity,
                    owasp_categories=self.owasp_categories,
                    url=url,
                    evidence={
                        "parameter": param_name,
                        "payload": payload,
                        "content_type": content_type,
                        "indicators": evidence
                    },
                    recommendation="Encode all user input before reflecting in HTML. Use Content-Security-Policy headers."
                ))

                self.tested_params.append({
                    "url": url,
                    "parameter": param_name,
                    "type": "xss",
                    "vulnerable": True,
                    "payload": payload
                })

                return

        self.tested_params.append({
            "url": url,
            "parameter": param_name,
            "type": "xss",
            "vulnerable": False
        })