import re
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urljoin
import logging

from core.models import Finding, Severity
from core.session import HTTPSession, get_base_url

logger = logging.getLogger(__name__)


class AuthTester:
    name = "auth_tester"
    description = "Tests authentication mechanisms and session security"
    owasp_categories = ["A07"]

    # Common login paths
    LOGIN_PATHS = [
        "/login", "/signin", "/sign-in", "/auth/login",
        "/admin/login", "/user/login", "/account/login",
        "/api/login", "/api/auth/login", "/api/v1/login",
        "/wp-login.php", "/administrator",
        "/auth", "/authenticate", "/session/new"
    ]

    # Common username field names
    USERNAME_FIELDS = [
        "username", "user", "email", "login", "user_login",
        "user_name", "uname", "userid", "user_id", "mail"
    ]

    # Common password field names
    PASSWORD_FIELDS = [
        "password", "pass", "passwd", "pwd", "user_pass",
        "user_password", "secret", "credential"
    ]

    # Default/weak credentials to test
    WEAK_CREDENTIALS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("admin", "admin123"),
        ("root", "root"),
        ("root", "password"),
        ("test", "test"),
        ("user", "user"),
        ("guest", "guest"),
        ("demo", "demo"),
        ("admin", ""),
        ("administrator", "administrator"),
    ]

    # Patterns indicating successful login
    LOGIN_SUCCESS_PATTERNS = [
        r"welcome",
        r"dashboard",
        r"logout",
        r"sign.?out",
        r"my.?account",
        r"profile",
        r"successfully.*logged",
        r"login.*successful",
    ]

    # Patterns indicating failed login
    LOGIN_FAILURE_PATTERNS = [
        r"invalid.*password",
        r"invalid.*credentials",
        r"incorrect.*password",
        r"login.*failed",
        r"authentication.*failed",
        r"wrong.*password",
        r"bad.*credentials",
        r"user.*not.*found",
        r"invalid.*user",
    ]

    def __init__(
            self,
            session: HTTPSession,
            target_url: str,
            test_weak_creds: bool = True,
            test_session: bool = True,
            max_login_attempts: int = 5,
            custom_login_endpoints: Optional[List[Dict[str, Any]]] = None
    ):
        self.session = session
        self.target_url = target_url
        self.base_url = get_base_url(target_url)
        self.test_weak_creds = test_weak_creds
        self.test_session = test_session
        self.max_attempts = max_login_attempts
        self.findings: List[Finding] = []
        self.login_forms: List[Dict[str, Any]] = []
        self.session_issues: List[Dict[str, Any]] = []
        self.custom_login_endpoints = custom_login_endpoints or []

    async def run(self) -> Dict[str, Any]:
        logger.info(f"Starting auth testing for {self.base_url}")

        # Find login pages
        await self._find_login_pages()
        self._load_custom_login_endpoints()

        if not self.login_forms:
            logger.info("No login forms found")
            return {
                "login_forms": [],
                "session_issues": [],
                "findings": [],
                "summary": {
                    "login_forms_found": 0,
                    "weak_creds_found": 0,
                    "session_issues": 0,
                    "findings_count": 0
                }
            }

        # Test weak credentials
        if self.test_weak_creds:
            await self._test_weak_credentials()

        # Test session security
        if self.test_session:
            await self._test_session_security()

        # Check for username enumeration
        await self._test_username_enumeration()

        # Check for brute force protection
        await self._test_brute_force_protection()

        return {
            "login_forms": self.login_forms,
            "session_issues": self.session_issues,
            "findings": self.findings,
            "summary": {
                "login_forms_found": len(self.login_forms),
                "weak_creds_found": len([f for f in self.findings if "Weak" in f.title or "Default" in f.title]),
                "session_issues": len(self.session_issues),
                "findings_count": len(self.findings)
            }
        }

    async def _find_login_pages(self):
        for path in self.LOGIN_PATHS:
            url = urljoin(self.base_url, path)
            response = await self.session.get(url)

            if not response or response.status_code == 404:
                continue

            # Check if it looks like a login page
            if response.status_code in [200, 401, 403]:
                form_info = self._parse_login_form(response.text, url)

                if form_info:
                    self.login_forms.append(form_info)
                    logger.info(f"Found login form at {url}")

    def _load_custom_login_endpoints(self):
        for case in self.custom_login_endpoints:
            path = case.get("path") or case.get("url")
            if not path:
                continue

            action = path if path.startswith(("http://", "https://")) else urljoin(self.base_url, path)

            self.login_forms.append({
                "url": action,
                "action": action,
                "method": case.get("method", "POST").upper(),
                "username_field": case.get("username_field", "username"),
                "password_field": case.get("password_field", "password"),
                "content_type": case.get("content_type", "form"),
                "csrf_field": None,
                "csrf_token": None,
                "has_csrf": case.get("has_csrf", False),
                "weak_credentials": case.get("weak_credentials")
            })

            logger.info(f"Loaded custom login endpoint: {action}")

    def _parse_login_form(self, html: str, url: str) -> Optional[Dict[str, Any]]:
        # Simple form detection
        has_password_field = any(
            f'type="password"' in html.lower() or
            f"type='password'" in html.lower()
            for _ in [1]
        )

        if not has_password_field:
            return None

        # Find form action
        action_match = re.search(r'<form[^>]*action=["\']([^"\']*)["\']', html, re.IGNORECASE)
        action = action_match.group(1) if action_match else url

        if not action.startswith("http"):
            action = urljoin(url, action)

        # Find method
        method_match = re.search(r'<form[^>]*method=["\']([^"\']*)["\']', html, re.IGNORECASE)
        method = method_match.group(1).upper() if method_match else "POST"

        # Find username field
        username_field = None
        for field in self.USERNAME_FIELDS:
            if f'name="{field}"' in html.lower() or f"name='{field}'" in html.lower():
                username_field = field
                break

        if not username_field:
            # Try to find any text input before password
            input_match = re.search(r'<input[^>]*type=["\'](?:text|email)["\'][^>]*name=["\']([^"\']+)["\']', html,
                                    re.IGNORECASE)
            if input_match:
                username_field = input_match.group(1)

        # Find password field
        password_field = None
        for field in self.PASSWORD_FIELDS:
            if f'name="{field}"' in html.lower() or f"name='{field}'" in html.lower():
                password_field = field
                break

        if not password_field:
            pass_match = re.search(r'<input[^>]*type=["\']password["\'][^>]*name=["\']([^"\']+)["\']', html,
                                   re.IGNORECASE)
            if pass_match:
                password_field = pass_match.group(1)

        # Find CSRF token if present
        csrf_token = None
        csrf_field = None
        csrf_patterns = [
            r'name=["\']csrf[_-]?token["\'][^>]*value=["\']([^"\']+)["\']',
            r'name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']',
            r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)["\']',
        ]

        for pattern in csrf_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                csrf_token = match.group(1)
                csrf_field = re.search(r'name=["\']([^"\']+)["\']', match.group(0)).group(1)
                break

        return {
            "url": url,
            "action": action,
            "method": method,
            "username_field": username_field or "username",
            "password_field": password_field or "password",
            "csrf_field": csrf_field,
            "csrf_token": csrf_token,
            "has_csrf": csrf_token is not None
        }

    async def _test_weak_credentials(self):
        for form in self.login_forms:
            attempts = 0

            credentials = form.get("weak_credentials") or [
                {"username": u, "password": p} for u, p in self.WEAK_CREDENTIALS
            ]

            for cred in credentials:
                username = cred["username"]
                password = cred["password"]

                success, response = await self._attempt_login(form, username, password)
                attempts += 1

                if success:
                    self.findings.append(Finding(
                        module=self.name,
                        title=f"Weak Credentials: {username}",
                        description=f"Login successful with weak credentials at {form['url']}",
                        severity=Severity.CRITICAL,
                        owasp_categories=self.owasp_categories,
                        url=form["url"],
                        evidence={
                            "username": username,
                            "password": "***" + password[-2:] if len(password) > 2 else "***"
                        },
                        recommendation="Change default credentials. Implement strong password policy."
                    ))
                    break  # Stop testing this form

    async def _attempt_login(
            self,
            form: Dict[str, Any],
            username: str,
            password: str
    ) -> Tuple[bool, Any]:
        # Build form data
        data = {
            form["username_field"]: username,
            form["password_field"]: password
        }

        # Add CSRF token if present
        if form.get("csrf_token"):
            data[form["csrf_field"]] = form["csrf_token"]

        # Make request
        if form["method"] == "POST":
            if form.get("content_type") == "json":
                response = await self.session.post(form["action"], json=data)
            else:
                response = await self.session.post(form["action"], data=data)
        else:
            response = await self.session.get(form["action"], params=data)

        if not response:
            return False, None

        # Analyze response
        is_success = self._analyze_login_response(response)

        return is_success, response

    def _analyze_login_response(self, response) -> bool:
        text = response.text.lower()

        # Check for redirect to dashboard/home
        if response.status_code in [301, 302, 303]:
            location = response.headers.get("Location", "").lower()
            if any(p in location for p in ["dashboard", "home", "account", "profile"]):
                return True

        # Check for success patterns
        for pattern in self.LOGIN_SUCCESS_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                # But make sure no failure pattern
                has_failure = any(
                    re.search(p, text, re.IGNORECASE)
                    for p in self.LOGIN_FAILURE_PATTERNS
                )
                if not has_failure:
                    return True

        # Check for session cookie being set
        cookies = response.headers.get_list("Set-Cookie") if hasattr(response.headers, 'get_list') else []
        for cookie in cookies:
            if any(s in cookie.lower() for s in ["session", "auth", "token", "logged"]):
                return True

        return False

    async def _test_session_security(self):
        for form in self.login_forms:
            # Check if login is over HTTPS
            if form["action"].startswith("http://"):
                self.findings.append(Finding(
                    module=self.name,
                    title="Login Form Over HTTP",
                    description=f"Login form submits credentials over unencrypted HTTP",
                    severity=Severity.HIGH,
                    owasp_categories=self.owasp_categories,
                    url=form["url"],
                    recommendation="Use HTTPS for all authentication forms"
                ))
                self.session_issues.append({
                    "issue": "http_login",
                    "url": form["url"]
                })

            # Check for CSRF protection
            if not form.get("has_csrf"):
                self.findings.append(Finding(
                    module=self.name,
                    title="Missing CSRF Protection on Login",
                    description=f"Login form lacks CSRF token protection",
                    severity=Severity.MEDIUM,
                    owasp_categories=self.owasp_categories,
                    url=form["url"],
                    recommendation="Implement CSRF tokens on all forms"
                ))
                self.session_issues.append({
                    "issue": "missing_csrf",
                    "url": form["url"]
                })

    async def _test_username_enumeration(self):
        for form in self.login_forms:
            # Try invalid username
            _, invalid_user_resp = await self._attempt_login(form, "invalid_user_xyz123", "wrongpass")

            # Try valid-looking username
            _, valid_user_resp = await self._attempt_login(form, "admin", "wrongpass")

            if invalid_user_resp and valid_user_resp:
                # Compare responses
                invalid_text = invalid_user_resp.text.lower()
                valid_text = valid_user_resp.text.lower()

                # Check for different error messages
                user_not_found = any(
                    p in invalid_text for p in ["user not found", "no user", "invalid user", "unknown user"])
                wrong_password = any(
                    p in valid_text for p in ["wrong password", "invalid password", "incorrect password"])

                if user_not_found and wrong_password:
                    self.findings.append(Finding(
                        module=self.name,
                        title="Username Enumeration Possible",
                        description="Different error messages reveal valid/invalid usernames",
                        severity=Severity.MEDIUM,
                        owasp_categories=self.owasp_categories,
                        url=form["url"],
                        evidence={
                            "invalid_user_hint": "Error indicates user not found",
                            "valid_user_hint": "Error only mentions password"
                        },
                        recommendation="Use generic error messages like 'Invalid credentials'"
                    ))

    async def _test_brute_force_protection(self):
        for form in self.login_forms:
            # Make several rapid login attempts
            blocked = False

            for i in range(6):
                _, response = await self._attempt_login(form, "testuser", f"wrongpass{i}")

                if response:
                    text = response.text.lower()

                    # Check for lockout/rate limit
                    if any(p in text for p in
                           ["locked", "too many", "rate limit", "try again later", "blocked", "captcha"]):
                        blocked = True
                        break

                    if response.status_code == 429:
                        blocked = True
                        break

            if not blocked:
                self.findings.append(Finding(
                    module=self.name,
                    title="No Brute Force Protection",
                    description="Login form allows unlimited login attempts",
                    severity=Severity.MEDIUM,
                    owasp_categories=self.owasp_categories,
                    url=form["url"],
                    recommendation="Implement account lockout, rate limiting, or CAPTCHA after failed attempts"
                ))