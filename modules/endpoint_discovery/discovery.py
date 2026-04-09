import asyncio
import re
import os
from typing import List, Set, Optional, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs
from pathlib import Path
from bs4 import BeautifulSoup
import logging

from core.models import EndpointInfo, Finding, Severity
from core.session import HTTPSession, get_base_url, normalize_url, is_same_origin

logger = logging.getLogger(__name__)


class EndpointDiscovery:
    def __init__(
            self,
            session: HTTPSession,
            base_url: str,
            crawl_depth: int = 3,
            crawl_max_pages: int = 100,
            bruteforce_enabled: bool = True,
            wordlists: List[str] = None
    ):
        self.session = session
        self.base_url = get_base_url(base_url)
        self.target_url = base_url
        self.crawl_depth = crawl_depth
        self.crawl_max_pages = crawl_max_pages
        self.bruteforce_enabled = bruteforce_enabled
        self.wordlists = wordlists or ["common_paths.txt", "api_endpoints.txt"]

        self.discovered_endpoints: List[EndpointInfo] = []
        self.visited_urls: Set[str] = set()
        self.findings: List[Finding] = []

        # Get wordlists directory
        self.wordlists_dir = Path(__file__).parent / "wordlists"

    async def run(self) -> Dict[str, Any]:
        logger.info(f"Starting endpoint discovery for {self.base_url}")

        # 1. Parse robots.txt and sitemap.xml
        await self._parse_robots()
        await self._parse_sitemap()

        # 2. Crawl the website
        await self._crawl()

        # 3. Bruteforce common paths
        if self.bruteforce_enabled:
            await self._bruteforce()

        # 4. Analyze discovered API endpoints
        await self._analyze_api_endpoints()

        # Sort by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        self.discovered_endpoints.sort(
            key=lambda x: priority_order.get(x.priority, 4)
        )

        return {
            "endpoints": self.discovered_endpoints,
            "findings": self.findings,
            "statistics": {
                "total_discovered": len(self.discovered_endpoints),
                "by_source": self._count_by_source(),
                "by_priority": self._count_by_priority()
            }
        }

    async def _parse_robots(self):
        robots_url = f"{self.base_url}/robots.txt"
        logger.info(f"Fetching robots.txt: {robots_url}")

        response = await self.session.get(robots_url)

        if not response or response.status_code != 200:
            logger.info("robots.txt not found or inaccessible")
            return

        content = response.text
        sitemaps = []

        for line in content.split("\n"):
            line = line.strip()

            # Extract Disallow paths
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    await self._add_endpoint(
                        path=path,
                        source="robots.txt",
                        priority=self._calculate_path_priority(path),
                        notes="Found in robots.txt Disallow"
                    )

            # Extract Allow paths
            elif line.lower().startswith("allow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    await self._add_endpoint(
                        path=path,
                        source="robots.txt",
                        priority="low",
                        notes="Found in robots.txt Allow"
                    )

            # Extract Sitemap references
            elif line.lower().startswith("sitemap:"):
                sitemap_url = line.split(":", 1)[1].strip()
                # Handle sitemap: URL format
                if sitemap_url.startswith("//"):
                    sitemap_url = "https:" + sitemap_url
                elif sitemap_url.startswith("/"):
                    sitemap_url = self.base_url + sitemap_url
                sitemaps.append(sitemap_url)

        # Store sitemaps for later processing
        self._sitemaps = sitemaps

        logger.info(f"Found {len(sitemaps)} sitemap references in robots.txt")

    async def _parse_sitemap(self):
        # Start with common sitemap locations
        sitemap_urls = getattr(self, "_sitemaps", [])
        sitemap_urls.extend([
            f"{self.base_url}/sitemap.xml",
            f"{self.base_url}/sitemap_index.xml",
            f"{self.base_url}/sitemaps.xml"
        ])

        processed = set()
        to_process = list(set(sitemap_urls))
        max_sitemaps = 10
        processed_count = 0

        while to_process and processed_count < max_sitemaps:
            sitemap_url = to_process.pop(0)

            if sitemap_url in processed:
                continue
            processed.add(sitemap_url)
            processed_count += 1

            logger.info(f"Processing sitemap: {sitemap_url}")
            response = await self.session.get(sitemap_url)

            if not response or response.status_code != 200:
                continue

            try:
                soup = BeautifulSoup(response.text, "lxml-xml")

                # Check for sitemap index
                sitemap_tags = soup.find_all("sitemap")
                for sitemap_tag in sitemap_tags:
                    loc = sitemap_tag.find("loc")
                    if loc and loc.text:
                        to_process.append(loc.text.strip())

                # Extract URLs
                url_tags = soup.find_all("url")
                for url_tag in url_tags:
                    loc = url_tag.find("loc")
                    if loc and loc.text:
                        url = loc.text.strip()
                        parsed = urlparse(url)
                        path = parsed.path

                        if path:
                            await self._add_endpoint(
                                path=path,
                                source="sitemap",
                                priority="low",
                                notes="Found in sitemap.xml"
                            )

            except Exception as e:
                logger.warning(f"Error parsing sitemap {sitemap_url}: {e}")

    async def _crawl(self):
        logger.info(f"Starting crawl from {self.target_url}")

        queue = [(self.target_url, 0)]  # (url, depth)
        crawled_count = 0

        while queue and crawled_count < self.crawl_max_pages:
            url, depth = queue.pop(0)

            # Normalize URL
            url = normalize_url(url, self.base_url)

            # Skip if already visited or too deep
            if url in self.visited_urls or depth > self.crawl_depth:
                continue

            # Skip if not same origin
            if not is_same_origin(url, self.base_url):
                continue

            self.visited_urls.add(url)
            crawled_count += 1

            logger.debug(f"Crawling: {url} (depth={depth})")

            response = await self.session.get(url)

            if not response:
                continue

            # Add this URL as an endpoint
            parsed = urlparse(url)
            await self._add_endpoint(
                path=parsed.path or "/",
                source="crawler",
                status_code=response.status_code,
                content_type=response.headers.get("Content-Type", ""),
                found_on=url if depth > 0 else None,
                priority="low"
            )

            # Extract links from HTML
            content_type = response.headers.get("Content-Type", "")

            if "text/html" in content_type:
                links = self._extract_html_links(response.text, url)
                for link in links:
                    if link not in self.visited_urls:
                        queue.append((link, depth + 1))

            # Extract URLs from JavaScript
            elif "javascript" in content_type or url.endswith(".js"):
                js_urls = self._extract_js_urls(response.text)
                for js_url in js_urls:
                    full_url = normalize_url(js_url, self.base_url)
                    await self._add_endpoint(
                        path=urlparse(full_url).path,
                        source="crawler",
                        found_on=url,
                        priority="medium",
                        notes="Extracted from JavaScript"
                    )

        logger.info(f"Crawl complete. Visited {crawled_count} pages.")

    def _extract_html_links(self, html: str, current_url: str) -> List[str]:
        links = []

        try:
            soup = BeautifulSoup(html, "lxml")

            # Extract from <a> tags
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                    full_url = normalize_url(href, current_url)
                    if is_same_origin(full_url, self.base_url):
                        links.append(full_url)

            # Extract from <form> tags
            for form in soup.find_all("form", action=True):
                action = form["action"]
                if action:
                    full_url = normalize_url(action, current_url)
                    if is_same_origin(full_url, self.base_url):
                        links.append(full_url)

            # Extract from <script> tags (src)
            for script in soup.find_all("script", src=True):
                src = script["src"]
                full_url = normalize_url(src, current_url)
                if is_same_origin(full_url, self.base_url):
                    links.append(full_url)

            # Extract URLs from inline scripts
            for script in soup.find_all("script"):
                if script.string:
                    js_urls = self._extract_js_urls(script.string)
                    for js_url in js_urls:
                        full_url = normalize_url(js_url, current_url)
                        if is_same_origin(full_url, self.base_url):
                            links.append(full_url)

        except Exception as e:
            logger.warning(f"Error extracting links: {e}")

        return list(set(links))

    def _extract_js_urls(self, js_content: str) -> List[str]:
        urls = []

        patterns = [
            # fetch('/api/...')
            r'fetch\s*\(\s*[\'"]([^\'"]+)[\'"]',
            # axios.get('/api/...')
            r'axios\.[a-z]+\s*\(\s*[\'"]([^\'"]+)[\'"]',
            # $.ajax({url: '/api/...'})
            r'url\s*:\s*[\'"]([^\'"]+)[\'"]',
            # href="/path"
            r'href\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
            # src="/path"
            r'src\s*[=:]\s*[\'"]([^\'"]+)[\'"]',
            # "/api/something"
            r'[\'"](\/?api\/[^\'"]+)[\'"]',
            # "/v1/something" or "/v2/something"
            r'[\'"](\/?v[1-3]\/[^\'"]+)[\'"]',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                # Clean up the URL
                url = match.strip()
                if url and url.startswith("/"):
                    urls.append(url)
                elif url and not url.startswith(("http://", "https://", "#", "javascript:")):
                    urls.append("/" + url)

        return list(set(urls))

    async def _bruteforce(self):
        logger.info("Starting path bruteforce")

        # Load wordlists
        paths_to_test = set()

        for wordlist in self.wordlists:
            wordlist_path = self.wordlists_dir / wordlist
            if wordlist_path.exists():
                with open(wordlist_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            # Ensure path starts with /
                            path = line if line.startswith("/") else "/" + line
                            paths_to_test.add(path)
                logger.info(f"Loaded {wordlist}: {len(paths_to_test)} paths")
            else:
                logger.warning(f"Wordlist not found: {wordlist_path}")

        # Get baseline 404 response for soft-404 detection
        baseline_404 = await self._get_baseline_404()

        # Test paths in batches
        paths_list = list(paths_to_test)
        batch_size = 10
        tested = 0
        found = 0

        for i in range(0, len(paths_list), batch_size):
            batch = paths_list[i:i + batch_size]
            urls = [f"{self.base_url}{path}" for path in batch]

            results = await self.session.get_multiple(urls, concurrency=5)

            for url, response in results:
                tested += 1

                if not response:
                    continue

                path = urlparse(url).path
                status = response.status_code

                # Skip soft 404s
                if status == 200 and self._is_soft_404(response, baseline_404):
                    continue

                # Check for interesting status codes
                if status in [200, 201, 301, 302, 307, 308, 401, 403, 405, 500]:
                    found += 1

                    priority = self._calculate_path_priority(path)

                    # Adjust priority based on status code
                    if status in [401, 403]:
                        priority = "high"  # Exists but restricted
                    elif status == 500:
                        priority = "critical"  # Server error

                    redirect_url = None
                    if status in [301, 302, 307, 308]:
                        redirect_url = response.headers.get("Location")

                    await self._add_endpoint(
                        path=path,
                        source="bruteforce",
                        status_code=status,
                        content_type=response.headers.get("Content-Type", ""),
                        priority=priority,
                        redirect_url=redirect_url,
                        notes=self._get_status_note(status)
                    )

                    # Add finding for critical discoveries
                    if status in [403, 500] or priority == "critical":
                        self._add_finding_for_path(path, status)

        logger.info(f"Bruteforce complete. Tested {tested}, found {found}")

    async def _get_baseline_404(self) -> Optional[Dict[str, Any]]:
        random_path = "/asdfjkl1234567890notexist"
        response = await self.session.get(f"{self.base_url}{random_path}")

        if response:
            return {
                "status_code": response.status_code,
                "content_length": len(response.content),
                "content_hash": hash(response.text[:1000]) if response.text else 0
            }
        return None

    def _is_soft_404(self, response, baseline: Optional[Dict]) -> bool:
        if not baseline:
            return False

        # If same content hash, it's likely a soft 404
        content_hash = hash(response.text[:1000]) if response.text else 0
        if content_hash == baseline["content_hash"]:
            return True

        # Check for 404 keywords in content
        content_lower = response.text.lower() if response.text else ""
        not_found_keywords = ["not found", "404", "does not exist", "page not found", "nincs"]

        for keyword in not_found_keywords:
            if keyword in content_lower:
                return True

        return False

    async def _analyze_api_endpoints(self):
        api_endpoints = [
            ep for ep in self.discovered_endpoints
            if "/api" in ep.path.lower() or "/graphql" in ep.path.lower()
        ]

        if not api_endpoints:
            return

        logger.info(f"Analyzing {len(api_endpoints)} API endpoints")

        for endpoint in api_endpoints[:20]:  # Limit to prevent too many requests
            url = f"{self.base_url}{endpoint.path}"

            # Try OPTIONS request for CORS and allowed methods
            response = await self.session.options(url)

            if response and response.status_code == 200:
                allowed = response.headers.get("Allow", "")
                if allowed:
                    endpoint.notes = f"Allowed methods: {allowed}"

    def _calculate_path_priority(self, path: str) -> str:
        path_lower = path.lower()

        # Critical patterns
        critical_patterns = [
            r"\.git", r"\.env", r"\.htpasswd", r"\.htaccess",
            r"backup", r"\.sql", r"\.bak", r"phpinfo",
            r"server-status", r"debug", r"console", r"shell"
        ]

        for pattern in critical_patterns:
            if re.search(pattern, path_lower):
                return "critical"

        # High priority patterns
        high_patterns = [
            r"admin", r"api/internal", r"swagger", r"graphql",
            r"config", r"settings", r"actuator", r"manage",
            r"\.config", r"\.json$", r"\.yaml$", r"\.yml$"
        ]

        for pattern in high_patterns:
            if re.search(pattern, path_lower):
                return "high"

        # Medium priority patterns
        medium_patterns = [
            r"api", r"login", r"auth", r"dashboard", r"status",
            r"health", r"user", r"account", r"profile"
        ]

        for pattern in medium_patterns:
            if re.search(pattern, path_lower):
                return "medium"

        return "low"

    def _get_status_note(self, status_code: int) -> str:
        notes = {
            200: "Accessible",
            201: "Created (likely POST endpoint)",
            301: "Permanent redirect",
            302: "Temporary redirect",
            401: "Authentication required",
            403: "Access forbidden (path exists)",
            405: "Method not allowed",
            500: "Server error (potential vulnerability)"
        }
        return notes.get(status_code, f"Status: {status_code}")

    def _add_finding_for_path(self, path: str, status_code: int):
        path_lower = path.lower()

        if ".git" in path_lower:
            self.findings.append(Finding(
                module="endpoint_discovery",
                title="Git Repository Exposed",
                description=f"Git repository files found at {path}",
                severity=Severity.CRITICAL,
                owasp_categories=["A02", "A03"],
                url=f"{self.base_url}{path}",
                evidence={"path": path, "status_code": status_code},
                recommendation="Block access to .git directory in web server configuration"
            ))

        elif ".env" in path_lower:
            self.findings.append(Finding(
                module="endpoint_discovery",
                title="Environment File Exposed",
                description=f"Environment configuration file found at {path}",
                severity=Severity.CRITICAL,
                owasp_categories=["A02", "A05"],
                url=f"{self.base_url}{path}",
                evidence={"path": path, "status_code": status_code},
                recommendation="Remove .env file from web root or block access"
            ))

        elif status_code == 403 and "admin" in path_lower:
            self.findings.append(Finding(
                module="endpoint_discovery",
                title="Admin Interface Found",
                description=f"Admin interface discovered at {path} (access restricted)",
                severity=Severity.MEDIUM,
                owasp_categories=["A01"],
                url=f"{self.base_url}{path}",
                evidence={"path": path, "status_code": status_code},
                recommendation="Ensure strong authentication and consider IP restrictions"
            ))

        elif status_code == 500:
            self.findings.append(Finding(
                module="endpoint_discovery",
                title="Server Error Detected",
                description=f"Server error (500) at {path}",
                severity=Severity.MEDIUM,
                owasp_categories=["A10"],
                url=f"{self.base_url}{path}",
                evidence={"path": path, "status_code": status_code},
                recommendation="Investigate and fix the server error, implement proper error handling"
            ))

    async def _add_endpoint(
            self,
            path: str,
            source: str,
            status_code: Optional[int] = None,
            content_type: Optional[str] = None,
            found_on: Optional[str] = None,
            priority: str = "medium",
            redirect_url: Optional[str] = None,
            notes: Optional[str] = None
    ):
        # Normalize path
        if not path.startswith("/"):
            path = "/" + path

        full_url = f"{self.base_url}{path}"

        # Check for duplicates
        for ep in self.discovered_endpoints:
            if ep.path == path:
                # Update with new info if available
                if status_code and not ep.status_code:
                    ep.status_code = status_code
                if content_type and not ep.content_type:
                    ep.content_type = content_type
                return

        # Create new endpoint
        endpoint = EndpointInfo(
            url=full_url,
            path=path,
            source=source,
            status_code=status_code,
            content_type=content_type,
            found_on=found_on,
            priority=priority,
            redirect_url=redirect_url,
            notes=notes,
            owasp_categories=self._get_owasp_categories(path)
        )

        self.discovered_endpoints.append(endpoint)

    def _get_owasp_categories(self, path: str) -> List[str]:
        categories = []
        path_lower = path.lower()

        if any(x in path_lower for x in ["admin", "user", "account", "profile"]):
            categories.append("A01")  # Broken Access Control

        if any(x in path_lower for x in [".git", ".env", "config", "backup", "debug"]):
            categories.append("A02")  # Security Misconfiguration

        if any(x in path_lower for x in ["package.json", "requirements.txt", "composer.json", "go.mod"]):
            categories.append("A03")  # Supply Chain

        if any(x in path_lower for x in ["api", "graphql", "rest"]):
            categories.append("A01")  # APIs often relate to access control

        return categories

    def _count_by_source(self) -> Dict[str, int]:
        counts = {}
        for ep in self.discovered_endpoints:
            counts[ep.source] = counts.get(ep.source, 0) + 1
        return counts

    def _count_by_priority(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for ep in self.discovered_endpoints:
            counts[ep.priority] = counts.get(ep.priority, 0) + 1
        return counts