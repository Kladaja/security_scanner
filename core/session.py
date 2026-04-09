import httpx
import asyncio
import time
from typing import Optional, Dict, Any, List
from urllib.parse import urljoin, urlparse
import logging

logger = logging.getLogger(__name__)


class RateLimiter:
    def __init__(self, requests_per_second: float = 2.0):
        self.requests_per_second = requests_per_second
        self.min_interval = 1.0 / requests_per_second
        self.last_request_time = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = time.time()
            elapsed = now - self.last_request_time

            if elapsed < self.min_interval:
                await asyncio.sleep(self.min_interval - elapsed)

            self.last_request_time = time.time()


class HTTPSession:
    def __init__(
            self,
            timeout: int = 10,
            rate_limit: float = 2.0,
            user_agent: str = "OWASP-Scanner/1.0",
            verify_ssl: bool = True,
            proxy: Optional[str] = None,
            auth_header: Optional[str] = None,
            cookies: Optional[Dict[str, str]] = None
    ):
        self.timeout = timeout
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.auth_header = auth_header
        self.cookies = cookies or {}

        self.rate_limiter = RateLimiter(rate_limit)
        self.request_count = 0

        # Default headers
        self.default_headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive"
        }

        if auth_header:
            self.default_headers["Authorization"] = auth_header

        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def start(self):
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            verify=self.verify_ssl,
            follow_redirects=False,
            proxy=self.proxy,
            cookies=self.cookies
        )

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None

    async def request(
            self,
            method: str,
            url: str,
            headers: Optional[Dict[str, str]] = None,
            data: Optional[Any] = None,
            json: Optional[Any] = None,
            follow_redirects: bool = True,
            max_redirects: int = 5
    ) -> Optional[httpx.Response]:
        if not self._client:
            await self.start()

        # Merge headers
        request_headers = {**self.default_headers}
        if headers:
            request_headers.update(headers)

        # Rate limiting
        await self.rate_limiter.acquire()

        try:
            response = await self._client.request(
                method=method,
                url=url,
                headers=request_headers,
                data=data,
                json=json
            )

            self.request_count += 1

            # Handle redirects manually if needed
            redirect_count = 0
            while follow_redirects and response.is_redirect and redirect_count < max_redirects:
                redirect_url = response.headers.get("Location")
                if redirect_url:
                    # Handle relative redirects
                    if not redirect_url.startswith(("http://", "https://")):
                        redirect_url = urljoin(url, redirect_url)

                    await self.rate_limiter.acquire()
                    response = await self._client.request(
                        method="GET",
                        url=redirect_url,
                        headers=request_headers
                    )
                    self.request_count += 1
                    redirect_count += 1
                else:
                    break

            return response

        except httpx.TimeoutException:
            logger.warning(f"Timeout for {url}")
            return None
        except httpx.ConnectError as e:
            logger.warning(f"Connection error for {url}: {e}")
            return None
        except httpx.RequestError as e:
            logger.warning(f"Request error for {url}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error for {url}: {e}")
            return None

    async def get(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self.request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self.request("OPTIONS", url, **kwargs)

    async def get_multiple(
            self,
            urls: List[str],
            concurrency: int = 5
    ) -> List[tuple]:
        semaphore = asyncio.Semaphore(concurrency)

        async def fetch_one(url: str) -> tuple:
            async with semaphore:
                response = await self.get(url)
                return (url, response)

        tasks = [fetch_one(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions
        valid_results = []
        for result in results:
            if isinstance(result, tuple):
                valid_results.append(result)

        return valid_results


def get_base_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def normalize_url(url: str, base_url: str) -> str:
    # Handle relative URLs
    if url.startswith("/"):
        url = urljoin(base_url, url)
    elif not url.startswith(("http://", "https://")):
        url = urljoin(base_url, url)

    # Remove fragment
    if "#" in url:
        url = url.split("#")[0]

    # Remove trailing slash for consistency (except for root)
    parsed = urlparse(url)
    if parsed.path and parsed.path != "/" and url.endswith("/"):
        url = url.rstrip("/")

    return url


def is_same_origin(url: str, base_url: str) -> bool:
    try:
        url_parsed = urlparse(url)
        base_parsed = urlparse(base_url)

        return (
                url_parsed.scheme == base_parsed.scheme and
                url_parsed.netloc == base_parsed.netloc
        )
    except Exception:
        return False