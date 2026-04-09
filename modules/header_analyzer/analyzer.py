import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import logging

from core.models import (
    HeaderAnalysis, CookieAnalysis, CORSAnalysis,
    Finding, Severity
)
from core.session import HTTPSession, get_base_url

logger = logging.getLogger(__name__)


class HeaderAnalyzer:
    """Analyzes HTTP security headers and cookies."""

    def __init__(self, session: HTTPSession, target_url: str):
        self.session = session
        self.target_url = target_url
        self.base_url = get_base_url(target_url)

        self.headers: List[HeaderAnalysis] = []
        self.cookies: List[CookieAnalysis] = []
        self.cors: Optional[CORSAnalysis] = None
        self.findings: List[Finding] = []
        self.info_disclosures: List[Dict[str, Any]] = []

        # Session cookie patterns
        self.session_cookie_patterns = [
            "session", "sess", "sid", "ssid", "token",
            "auth", "jwt", "phpsessid", "jsessionid",
            "asp.net_sessionid", "aspsessionid", "cfid", "cftoken",
            "logged_in", "user", "userid", "remember"
        ]

    async def run(self) -> Dict[str, Any]:
        """Run all header analysis checks."""
        logger.info(f"Starting header analysis for {self.target_url}")

        # Fetch the main page
        response = await self.session.get(self.target_url)

        if not response:
            logger.error("Failed to fetch target URL")
            return {"error": "Failed to fetch target URL"}

        # 1. Analyze security headers
        self._analyze_security_headers(response.headers)

        # 2. Analyze cookies
        self._analyze_cookies(response.headers)

        # 3. Analyze CORS
        await self._analyze_cors()

        # 4. Check for information disclosure
        self._check_info_disclosure(response.headers, response.text)

        return {
            "headers": self.headers,
            "cookies": self.cookies,
            "cors": self.cors,
            "findings": self.findings,
            "info_disclosures": self.info_disclosures,
            "summary": self._generate_summary()
        }

    def _analyze_security_headers(self, headers: Dict[str, str]):
        """Analyze security-related HTTP headers."""

        # 1. Strict-Transport-Security (HSTS)
        self._check_hsts(headers)

        # 2. Content-Security-Policy
        self._check_csp(headers)

        # 3. X-Frame-Options
        self._check_x_frame_options(headers)

        # 4. X-Content-Type-Options
        self._check_x_content_type_options(headers)

        # 5. X-XSS-Protection
        self._check_x_xss_protection(headers)

        # 6. Referrer-Policy
        self._check_referrer_policy(headers)

        # 7. Permissions-Policy
        self._check_permissions_policy(headers)

        # 8. Cache-Control
        self._check_cache_control(headers)

    def _check_hsts(self, headers: Dict[str, str]):
        """Check Strict-Transport-Security header."""
        header_name = "Strict-Transport-Security"
        value = self._get_header(headers, header_name)

        analysis = HeaderAnalysis(
            name=header_name,
            present=value is not None,
            value=value,
            owasp_categories=["A02", "A04"]
        )

        if not value:
            analysis.score = 0
            analysis.severity = Severity.HIGH
            analysis.issues = ["HSTS header missing - SSL stripping attacks possible"]
            analysis.recommendation = "Add Strict-Transport-Security header with max-age of at least 1 year"

            self.findings.append(Finding(
                module="header_analyzer",
                title="Missing HSTS Header",
                description="Strict-Transport-Security header is not set",
                severity=Severity.HIGH,
                owasp_categories=["A02", "A04"],
                url=self.target_url,
                recommendation="Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
            ))
        else:
            # Parse max-age
            max_age_match = re.search(r'max-age=(\d+)', value, re.IGNORECASE)
            max_age = int(max_age_match.group(1)) if max_age_match else 0

            if max_age < 15768000:  # 6 months
                analysis.score = 30
                analysis.severity = Severity.MEDIUM
                analysis.issues = [f"HSTS max-age too short ({max_age} seconds)"]
                analysis.recommendation = "Increase max-age to at least 31536000 (1 year)"
            elif max_age < 31536000:  # 1 year
                analysis.score = 60
                analysis.severity = Severity.LOW
                analysis.issues = ["Consider increasing max-age to 1 year"]
            else:
                analysis.score = 80

            # Check for includeSubDomains
            if "includesubdomains" not in value.lower():
                analysis.score = min(analysis.score, 70)
                analysis.issues.append("Missing 'includeSubDomains' directive")
            else:
                analysis.score = min(analysis.score + 10, 100)

            # Check for preload
            if "preload" in value.lower():
                analysis.score = 100

        self.headers.append(analysis)

    def _check_csp(self, headers: Dict[str, str]):
        """Check Content-Security-Policy header."""
        header_name = "Content-Security-Policy"
        value = self._get_header(headers, header_name)

        # Also check for report-only variant
        report_only = self._get_header(headers, "Content-Security-Policy-Report-Only")

        analysis = HeaderAnalysis(
            name=header_name,
            present=value is not None,
            value=value[:200] + "..." if value and len(value) > 200 else value,
            owasp_categories=["A02", "A05"]
        )

        if not value:
            analysis.score = 0
            analysis.severity = Severity.HIGH
            analysis.issues = ["CSP header missing - no XSS protection from CSP"]
            analysis.recommendation = "Implement Content-Security-Policy header"

            if report_only:
                analysis.issues.append("CSP-Report-Only is set (not enforced)")
                analysis.score = 20

            self.findings.append(Finding(
                module="header_analyzer",
                title="Missing Content-Security-Policy",
                description="CSP header is not set, reducing XSS protection",
                severity=Severity.HIGH,
                owasp_categories=["A02", "A05"],
                url=self.target_url,
                recommendation="Implement a strict CSP. Start with: default-src 'self'; script-src 'self'"
            ))
        else:
            analysis.score = 50  # Base score for having CSP

            # Parse and analyze directives
            directives = self._parse_csp(value)

            # Check for dangerous values
            script_src = directives.get("script-src", directives.get("default-src", []))

            if "'unsafe-inline'" in script_src:
                analysis.issues.append("'unsafe-inline' in script-src allows inline scripts")
                analysis.score -= 20

                self.findings.append(Finding(
                    module="header_analyzer",
                    title="CSP allows unsafe-inline scripts",
                    description="Content-Security-Policy allows inline scripts via 'unsafe-inline'",
                    severity=Severity.MEDIUM,
                    owasp_categories=["A02", "A05"],
                    url=self.target_url,
                    evidence={"directive": "script-src", "value": "'unsafe-inline'"},
                    recommendation="Remove 'unsafe-inline' and use nonces or hashes instead"
                ))

            if "'unsafe-eval'" in script_src:
                analysis.issues.append("'unsafe-eval' in script-src allows eval()")
                analysis.score -= 20

                self.findings.append(Finding(
                    module="header_analyzer",
                    title="CSP allows unsafe-eval",
                    description="Content-Security-Policy allows eval() via 'unsafe-eval'",
                    severity=Severity.MEDIUM,
                    owasp_categories=["A02", "A05"],
                    url=self.target_url,
                    evidence={"directive": "script-src", "value": "'unsafe-eval'"},
                    recommendation="Remove 'unsafe-eval' from CSP"
                ))

            if "*" in script_src or "data:" in script_src:
                analysis.issues.append("Overly permissive script-src")
                analysis.score -= 30

            # Check for frame-ancestors (clickjacking)
            if "frame-ancestors" not in directives:
                analysis.issues.append("Missing frame-ancestors directive")
                analysis.score -= 10
            elif "*" in directives.get("frame-ancestors", []):
                analysis.issues.append("frame-ancestors allows any origin")
                analysis.score -= 15

            # Cap score
            analysis.score = max(0, min(100, analysis.score))

            if analysis.issues:
                analysis.severity = Severity.MEDIUM if analysis.score > 30 else Severity.HIGH

        self.headers.append(analysis)

    def _parse_csp(self, csp_value: str) -> Dict[str, List[str]]:
        """Parse CSP header into directives."""
        directives = {}

        for directive in csp_value.split(";"):
            directive = directive.strip()
            if not directive:
                continue

            parts = directive.split()
            if parts:
                directive_name = parts[0].lower()
                values = parts[1:] if len(parts) > 1 else []
                directives[directive_name] = values

        return directives

    def _check_x_frame_options(self, headers: Dict[str, str]):
        """Check X-Frame-Options header."""
        header_name = "X-Frame-Options"
        value = self._get_header(headers, header_name)

        analysis = HeaderAnalysis(
            name=header_name,
            present=value is not None,
            value=value,
            owasp_categories=["A02"]
        )

        if not value:
            analysis.score = 0
            analysis.severity = Severity.HIGH
            analysis.issues = ["X-Frame-Options missing - clickjacking possible"]
            analysis.recommendation = "Add X-Frame-Options: DENY or SAMEORIGIN"

            self.findings.append(Finding(
                module="header_analyzer",
                title="Missing X-Frame-Options",
                description="X-Frame-Options header not set - page may be vulnerable to clickjacking",
                severity=Severity.HIGH,
                owasp_categories=["A02"],
                url=self.target_url,
                recommendation="Add header: X-Frame-Options: DENY"
            ))
        else:
            value_upper = value.upper()

            if value_upper == "DENY":
                analysis.score = 100
            elif value_upper == "SAMEORIGIN":
                analysis.score = 90
            elif value_upper.startswith("ALLOW-FROM"):
                analysis.score = 60
                analysis.severity = Severity.LOW
                analysis.issues = ["ALLOW-FROM is deprecated and not supported by modern browsers"]
            else:
                analysis.score = 30
                analysis.severity = Severity.MEDIUM
                analysis.issues = [f"Invalid X-Frame-Options value: {value}"]

        self.headers.append(analysis)

    def _check_x_content_type_options(self, headers: Dict[str, str]):
        """Check X-Content-Type-Options header."""
        header_name = "X-Content-Type-Options"
        value = self._get_header(headers, header_name)

        analysis = HeaderAnalysis(
            name=header_name,
            present=value is not None,
            value=value,
            owasp_categories=["A02"]
        )

        if not value:
            analysis.score = 0
            analysis.severity = Severity.MEDIUM
            analysis.issues = ["X-Content-Type-Options missing - MIME sniffing possible"]
            analysis.recommendation = "Add X-Content-Type-Options: nosniff"

            self.findings.append(Finding(
                module="header_analyzer",
                title="Missing X-Content-Type-Options",
                description="X-Content-Type-Options header not set - browser may MIME-sniff responses",
                severity=Severity.MEDIUM,
                owasp_categories=["A02"],
                url=self.target_url,
                recommendation="Add header: X-Content-Type-Options: nosniff"
            ))
        elif value.lower() == "nosniff":
            analysis.score = 100
        else:
            analysis.score = 30
            analysis.severity = Severity.MEDIUM
            analysis.issues = [f"Invalid value: {value} (should be 'nosniff')"]

        self.headers.append(analysis)

    def _check_x_xss_protection(self, headers: Dict[str, str]):
        """Check X-XSS-Protection header."""
        header_name = "X-XSS-Protection"
        value = self._get_header(headers, header_name)

        analysis = HeaderAnalysis(
            name=header_name,
            present=value is not None,
            value=value,
            owasp_categories=["A02"]
        )

        # Note: This header is deprecated in modern browsers
        # But still useful for older browsers

        if not value:
            analysis.score = 50  # Not critical since deprecated
            analysis.severity = Severity.LOW
            analysis.issues = ["X-XSS-Protection not set (deprecated but useful for old browsers)"]
            analysis.recommendation = "Consider adding X-XSS-Protection: 1; mode=block"
        elif value == "0":
            analysis.score = 70  # Explicitly disabled is OK
            analysis.issues = ["XSS filter disabled (acceptable if CSP is configured)"]
        elif "1" in value:
            if "mode=block" in value.lower():
                analysis.score = 100
            else:
                analysis.score = 80
                analysis.issues = ["Consider adding mode=block"]

        self.headers.append(analysis)

    def _check_referrer_policy(self, headers: Dict[str, str]):
        """Check Referrer-Policy header."""
        header_name = "Referrer-Policy"
        value = self._get_header(headers, header_name)

        analysis = HeaderAnalysis(
            name=header_name,
            present=value is not None,
            value=value,
            owasp_categories=["A02"]
        )

        safe_values = [
            "no-referrer",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin"
        ]

        if not value:
            analysis.score = 30
            analysis.severity = Severity.LOW
            analysis.issues = ["Referrer-Policy not set - URL may leak to external sites"]
            analysis.recommendation = "Add Referrer-Policy: strict-origin-when-cross-origin"
        elif value.lower() == "unsafe-url":
            analysis.score = 0
            analysis.severity = Severity.HIGH
            analysis.issues = ["'unsafe-url' sends full URL to all destinations"]
            analysis.recommendation = "Change to strict-origin-when-cross-origin"

            self.findings.append(Finding(
                module="header_analyzer",
                title="Unsafe Referrer-Policy",
                description="Referrer-Policy is set to 'unsafe-url' which sends full URL to all destinations",
                severity=Severity.MEDIUM,
                owasp_categories=["A02"],
                url=self.target_url,
                recommendation="Change to: Referrer-Policy: strict-origin-when-cross-origin"
            ))
        elif value.lower() in safe_values:
            analysis.score = 100
        else:
            analysis.score = 60
            analysis.issues = [f"Consider using stricter policy: {value}"]

        self.headers.append(analysis)

    def _check_permissions_policy(self, headers: Dict[str, str]):
        """Check Permissions-Policy header."""
        header_name = "Permissions-Policy"
        value = self._get_header(headers, header_name)

        # Also check legacy Feature-Policy
        if not value:
            value = self._get_header(headers, "Feature-Policy")
            if value:
                header_name = "Feature-Policy (legacy)"

        analysis = HeaderAnalysis(
            name="Permissions-Policy",
            present=value is not None,
            value=value[:100] + "..." if value and len(value) > 100 else value,
            owasp_categories=["A02"]
        )

        if not value:
            analysis.score = 30
            analysis.severity = Severity.LOW
            analysis.issues = ["Permissions-Policy not set - browser features not restricted"]
            analysis.recommendation = "Add Permissions-Policy to restrict sensitive features"
        else:
            analysis.score = 70

            # Check if sensitive features are restricted
            sensitive_features = ["camera", "microphone", "geolocation", "payment"]
            restricted_count = 0

            for feature in sensitive_features:
                if f"{feature}=()" in value.lower():
                    restricted_count += 1

            if restricted_count == len(sensitive_features):
                analysis.score = 100
            elif restricted_count > 0:
                analysis.score = 80
                analysis.issues = ["Some sensitive features not restricted"]

        self.headers.append(analysis)

    def _check_cache_control(self, headers: Dict[str, str]):
        """Check Cache-Control header for sensitive pages."""
        header_name = "Cache-Control"
        value = self._get_header(headers, header_name)

        analysis = HeaderAnalysis(
            name=header_name,
            present=value is not None,
            value=value,
            owasp_categories=["A02"]
        )

        if not value:
            analysis.score = 50
            analysis.severity = Severity.LOW
            analysis.issues = ["Cache-Control not set"]
            analysis.recommendation = "Set appropriate Cache-Control for sensitive pages"
        else:
            value_lower = value.lower()

            if "no-store" in value_lower:
                analysis.score = 100
            elif "no-cache" in value_lower and "private" in value_lower:
                analysis.score = 90
            elif "private" in value_lower:
                analysis.score = 70
            elif "public" in value_lower:
                analysis.score = 40
                analysis.severity = Severity.LOW
                analysis.issues = ["Cache-Control set to public - may cache sensitive data"]
            else:
                analysis.score = 60

        self.headers.append(analysis)

    def _analyze_cookies(self, headers: Dict[str, str]):
        """Analyze Set-Cookie headers."""
        # Get all Set-Cookie headers
        set_cookie_headers = []

        # httpx stores multiple headers differently
        for key, value in headers.multi_items():
            if key.lower() == "set-cookie":
                set_cookie_headers.append(value)

        for cookie_header in set_cookie_headers:
            cookie = self._parse_cookie(cookie_header)
            self.cookies.append(cookie)

            # Add findings for insecure cookies
            if cookie.is_session_cookie:
                if not cookie.secure:
                    self.findings.append(Finding(
                        module="header_analyzer",
                        title="Session Cookie Missing Secure Flag",
                        description=f"Session cookie '{cookie.name}' is not marked as Secure",
                        severity=Severity.HIGH,
                        owasp_categories=["A02", "A04"],
                        url=self.target_url,
                        evidence={"cookie_name": cookie.name},
                        recommendation="Add Secure flag to session cookies"
                    ))

                if not cookie.httponly:
                    self.findings.append(Finding(
                        module="header_analyzer",
                        title="Session Cookie Missing HttpOnly Flag",
                        description=f"Session cookie '{cookie.name}' is accessible to JavaScript",
                        severity=Severity.HIGH,
                        owasp_categories=["A02", "A05"],
                        url=self.target_url,
                        evidence={"cookie_name": cookie.name},
                        recommendation="Add HttpOnly flag to session cookies"
                    ))

                if not cookie.samesite:
                    self.findings.append(Finding(
                        module="header_analyzer",
                        title="Session Cookie Missing SameSite Attribute",
                        description=f"Session cookie '{cookie.name}' does not have SameSite attribute",
                        severity=Severity.MEDIUM,
                        owasp_categories=["A02"],
                        url=self.target_url,
                        evidence={"cookie_name": cookie.name},
                        recommendation="Add SameSite=Strict or SameSite=Lax attribute"
                    ))

    def _parse_cookie(self, cookie_header: str) -> CookieAnalysis:
        """Parse a Set-Cookie header."""
        parts = cookie_header.split(";")

        # First part is name=value
        name_value = parts[0].strip()
        name = name_value.split("=")[0].strip()
        value = name_value.split("=", 1)[1].strip() if "=" in name_value else ""

        # Parse attributes
        secure = False
        httponly = False
        samesite = None
        path = None
        domain = None
        expires = None

        for part in parts[1:]:
            part = part.strip().lower()

            if part == "secure":
                secure = True
            elif part == "httponly":
                httponly = True
            elif part.startswith("samesite="):
                samesite = part.split("=")[1].strip().capitalize()
            elif part.startswith("path="):
                path = part.split("=")[1].strip()
            elif part.startswith("domain="):
                domain = part.split("=")[1].strip()
            elif part.startswith("expires="):
                expires = part.split("=", 1)[1].strip()
            elif part.startswith("max-age="):
                expires = f"max-age={part.split('=')[1].strip()}"

        # Check if this looks like a session cookie
        is_session = any(
            pattern in name.lower()
            for pattern in self.session_cookie_patterns
        )

        # Calculate score
        score = 100
        issues = []
        owasp_categories = []

        if not secure:
            score -= 30
            issues.append("Missing Secure flag")
            owasp_categories.extend(["A02", "A04"])

        if not httponly:
            score -= 25 if is_session else 10
            issues.append("Missing HttpOnly flag")
            if is_session:
                owasp_categories.extend(["A02", "A05"])

        if not samesite:
            score -= 20
            issues.append("Missing SameSite attribute")
            owasp_categories.append("A02")
        elif samesite.lower() == "none" and not secure:
            score -= 25
            issues.append("SameSite=None requires Secure flag")
            owasp_categories.append("A02")

        return CookieAnalysis(
            name=name,
            value_preview=value[:20] + "..." if len(value) > 20 else value,
            secure=secure,
            httponly=httponly,
            samesite=samesite,
            path=path,
            domain=domain,
            expires=expires,
            is_session_cookie=is_session,
            score=max(0, score),
            issues=issues,
            owasp_categories=list(set(owasp_categories))
        )

    async def _analyze_cors(self):
        """Analyze CORS configuration."""
        logger.info("Analyzing CORS configuration")

        cors = CORSAnalysis()

        # Test with different origins
        test_origins = [
            "https://evil.com",
            "null"
        ]

        for test_origin in test_origins:
            response = await self.session.get(
                self.target_url,
                headers={"Origin": test_origin}
            )

            if not response:
                continue

            acao = response.headers.get("Access-Control-Allow-Origin")
            acac = response.headers.get("Access-Control-Allow-Credentials")
            acam = response.headers.get("Access-Control-Allow-Methods")
            acah = response.headers.get("Access-Control-Allow-Headers")

            if acao:
                cors.enabled = True
                cors.allow_origin = acao
                cors.allow_credentials = acac and acac.lower() == "true"
                cors.allow_methods = acam.split(",") if acam else []
                cors.allow_headers = acah.split(",") if acah else []

                # Check for dangerous configurations
                if acao == "*":
                    cors.issues.append("Wildcard origin (*) allows any site to read responses")
                    cors.score -= 30
                    cors.owasp_categories = ["A02"]

                    if cors.allow_credentials:
                        cors.issues.append("CRITICAL: Wildcard with credentials (browsers block this)")
                        cors.score -= 40
                        cors.owasp_categories.append("A01")

                        self.findings.append(Finding(
                            module="header_analyzer",
                            title="CORS Misconfiguration: Wildcard with Credentials",
                            description="CORS configured with wildcard origin and credentials (invalid but indicates misconfiguration)",
                            severity=Severity.HIGH,
                            owasp_categories=["A01", "A02"],
                            url=self.target_url,
                            recommendation="Specify explicit allowed origins instead of wildcard"
                        ))

                elif acao == test_origin:
                    cors.issues.append(f"Origin '{test_origin}' is reflected/accepted")
                    cors.score -= 20

                    if test_origin == "null":
                        cors.issues.append("'null' origin accepted - exploitable via sandboxed iframe")
                        cors.score -= 30
                        cors.owasp_categories = ["A01"]

                        self.findings.append(Finding(
                            module="header_analyzer",
                            title="CORS Accepts 'null' Origin",
                            description="CORS configuration accepts 'null' origin which can be exploited",
                            severity=Severity.HIGH,
                            owasp_categories=["A01"],
                            url=self.target_url,
                            evidence={"test_origin": "null", "acao": acao},
                            recommendation="Do not accept 'null' as a valid origin"
                        ))
                    elif cors.allow_credentials:
                        self.findings.append(Finding(
                            module="header_analyzer",
                            title="CORS Origin Reflection with Credentials",
                            description=f"CORS reflects arbitrary origin '{test_origin}' with credentials enabled",
                            severity=Severity.HIGH,
                            owasp_categories=["A01", "A02"],
                            url=self.target_url,
                            evidence={"test_origin": test_origin, "acao": acao, "credentials": True},
                            recommendation="Implement strict origin whitelist validation"
                        ))

                break  # Found CORS, no need to test more origins

        cors.score = max(0, cors.score)
        self.cors = cors

    def _check_info_disclosure(self, headers: Dict[str, str], body: str):
        """Check for information disclosure in headers and body."""

        # Check headers for version information
        info_headers = {
            "Server": r"(Apache|nginx|IIS|LiteSpeed|Tomcat|Jetty)/?[\d.]*",
            "X-Powered-By": r".*",
            "X-AspNet-Version": r".*",
            "X-AspNetMvc-Version": r".*",
            "X-Generator": r".*",
            "X-Drupal-Cache": r".*",
            "X-Varnish": r".*"
        }

        for header_name, pattern in info_headers.items():
            value = self._get_header(headers, header_name)
            if value:
                match = re.search(pattern, value, re.IGNORECASE)
                if match:
                    self.info_disclosures.append({
                        "type": "header",
                        "header": header_name,
                        "value": value,
                        "severity": "low",
                        "recommendation": f"Remove or obfuscate {header_name} header"
                    })

        # Check body for sensitive information
        if body:
            # Stack traces
            stack_patterns = [
                (r"Traceback \(most recent call last\)", "Python stack trace"),
                (r"at \w+\.\w+\([^)]+:\d+\)", "Java/C# stack trace"),
                (r"Fatal error:.*in .* on line \d+", "PHP fatal error"),
                (r"Exception in thread", "Java exception"),
                (r"Stack trace:", "Generic stack trace")
            ]

            for pattern, description in stack_patterns:
                if re.search(pattern, body):
                    self.info_disclosures.append({
                        "type": "body",
                        "issue": description,
                        "severity": "high",
                        "owasp_categories": ["A02", "A10"],
                        "recommendation": "Implement proper error handling, display generic error messages"
                    })

                    self.findings.append(Finding(
                        module="header_analyzer",
                        title="Stack Trace Exposed",
                        description=f"{description} found in response",
                        severity=Severity.HIGH,
                        owasp_categories=["A02", "A10"],
                        url=self.target_url,
                        recommendation="Implement proper error handling in production"
                    ))
                    break

            # SQL errors
            sql_patterns = [
                r"SQL syntax.*MySQL",
                r"ORA-\d{5}",
                r"PostgreSQL.*ERROR",
                r"SQLite.*error",
                r"ODBC.*Driver",
                r"Microsoft.*SQL.*Server"
            ]

            for pattern in sql_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    self.info_disclosures.append({
                        "type": "body",
                        "issue": "SQL error message",
                        "severity": "high",
                        "owasp_categories": ["A02", "A05", "A10"],
                        "recommendation": "Hide database errors from end users"
                    })

                    self.findings.append(Finding(
                        module="header_analyzer",
                        title="SQL Error Message Exposed",
                        description="Database error message found in response",
                        severity=Severity.HIGH,
                        owasp_categories=["A02", "A05", "A10"],
                        url=self.target_url,
                        recommendation="Implement proper error handling, never expose database errors"
                    ))
                    break

            # Path disclosure
            path_patterns = [
                r"/var/www/[^\s<>\"']+",
                r"/home/\w+/[^\s<>\"']+",
                r"C:\\[^\s<>\"']+",
                r"/usr/local/[^\s<>\"']+"
            ]

            for pattern in path_patterns:
                match = re.search(pattern, body)
                if match:
                    self.info_disclosures.append({
                        "type": "body",
                        "issue": "Internal path disclosure",
                        "value": match.group(0),
                        "severity": "medium",
                        "owasp_categories": ["A02"],
                        "recommendation": "Remove internal paths from error messages"
                    })
                    break

    def _get_header(self, headers: Dict[str, str], name: str) -> Optional[str]:
        """Get header value (case-insensitive)."""
        for key, value in headers.items():
            if key.lower() == name.lower():
                return value
        return None

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate analysis summary."""
        # Calculate overall header score
        header_scores = [h.score for h in self.headers]
        avg_header_score = sum(header_scores) / len(header_scores) if header_scores else 0

        # Calculate cookie score
        cookie_scores = [c.score for c in self.cookies]
        avg_cookie_score = sum(cookie_scores) / len(cookie_scores) if cookie_scores else 100

        # Calculate overall score
        overall_score = (avg_header_score * 0.6 + avg_cookie_score * 0.3 +
                         (self.cors.score if self.cors else 100) * 0.1)

        # Determine grade
        if overall_score >= 90:
            grade = "A"
        elif overall_score >= 80:
            grade = "B"
        elif overall_score >= 70:
            grade = "C"
        elif overall_score >= 60:
            grade = "D"
        else:
            grade = "F"

        return {
            "overall_score": round(overall_score),
            "grade": grade,
            "header_score": round(avg_header_score),
            "cookie_score": round(avg_cookie_score),
            "cors_score": self.cors.score if self.cors else 100,
            "findings_count": len(self.findings),
            "findings_by_severity": self._count_findings_by_severity(),
            "info_disclosures_count": len(self.info_disclosures)
        }

    def _count_findings_by_severity(self) -> Dict[str, int]:
        """Count findings by severity level."""
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts