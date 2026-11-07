"""
WebSentry HTTP Client
High-reliability HTTP engine supporting both `requests` and Python standard library `urllib` fallback.
Features: timeouts, retries, rate-limiting, custom User-Agent, safe connection recovery.
Developer: Isha Sonaria
"""

import time
import ssl
import threading
from typing import Dict, Optional, Tuple, Any
from urllib.parse import urljoin, urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    import urllib.request
    import urllib.error
    import http.client

class CaseInsensitiveDict(dict):
    """Case-insensitive dictionary for HTTP headers."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._lower_map = {k.lower(): k for k in self}

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self._lower_map[key.lower()] = key

    def __getitem__(self, key):
        return super().__getitem__(self._lower_map.get(key.lower(), key))

    def __contains__(self, key):
        return key.lower() in self._lower_map

    def get(self, key, default=None):
        lower = key.lower()
        if lower in self._lower_map:
            return super().get(self._lower_map[lower], default)
        return default

class WebResponse:
    def __init__(
        self,
        status_code: int,
        headers: Dict[str, str],
        text: str,
        content: bytes,
        url: str,
        elapsed: float = 0.0,
        error: Optional[str] = None
    ):
        self.status_code = status_code
        self.headers = CaseInsensitiveDict(headers)
        self.text = text
        self.content = content
        self.url = url
        self.elapsed = elapsed
        self.error = error

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

class HttpClient:
    def __init__(
        self,
        user_agent: str,
        timeout: float = 8.0,
        retries: int = 2,
        delay: float = 0.05,
        verify_ssl: bool = True,
        custom_headers: Optional[Dict[str, str]] = None
    ):
        self.user_agent = user_agent
        self.timeout = timeout
        self.retries = retries
        self.delay = delay
        self.verify_ssl = verify_ssl
        self.custom_headers = custom_headers or {}
        
        self._lock = threading.Lock()
        self._last_request_time = 0.0
        self.total_requests = 0

        # Initialize requests session if available
        if HAS_REQUESTS:
            self._session = requests.Session()
            retry_strategy = Retry(
                total=self.retries,
                backoff_factor=0.3,
                status_forcelist=[500, 502, 503, 504],
                raise_on_status=False
            )
            adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=20, pool_maxsize=20)
            self._session.mount("http://", adapter)
            self._session.mount("https://", adapter)
            if not self.verify_ssl:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        else:
            self._session = None

    def _apply_rate_limit(self) -> None:
        """Applies configured delay between consecutive requests."""
        if self.delay <= 0:
            return
        with self._lock:
            now = time.time()
            elapsed = now - self._last_request_time
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)
            self._last_request_time = time.time()
            self.total_requests += 1

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Any = None,
        allow_redirects: bool = True
    ) -> WebResponse:
        """Executes an HTTP request with timeout, retries, and rate limiting."""
        self._apply_rate_limit()

        req_headers = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        }
        req_headers.update(self.custom_headers)
        if headers:
            req_headers.update(headers)

        start_time = time.time()

        if HAS_REQUESTS:
            return self._request_via_requests(method, url, req_headers, data, allow_redirects, start_time)
        else:
            return self._request_via_urllib(method, url, req_headers, data, allow_redirects, start_time)

    def _request_via_requests(
        self, method: str, url: str, headers: Dict[str, str], data: Any, allow_redirects: bool, start_time: float
    ) -> WebResponse:
        attempts = 0
        last_error = None
        while attempts <= self.retries:
            try:
                res = self._session.request(
                    method=method.upper(),
                    url=url,
                    headers=headers,
                    data=data,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=allow_redirects,
                )
                elapsed = time.time() - start_time
                return WebResponse(
                    status_code=res.status_code,
                    headers=dict(res.headers),
                    text=res.text or "",
                    content=res.content or b"",
                    url=res.url,
                    elapsed=elapsed
                )
            except Exception as e:
                last_error = str(e)
                attempts += 1
                if attempts <= self.retries:
                    time.sleep(0.3 * attempts)

        elapsed = time.time() - start_time
        return WebResponse(
            status_code=0,
            headers={},
            text="",
            content=b"",
            url=url,
            elapsed=elapsed,
            error=last_error or "Request failed"
        )

    def _request_via_urllib(
        self, method: str, url: str, headers: Dict[str, str], data: Any, allow_redirects: bool, start_time: float
    ) -> WebResponse:
        attempts = 0
        last_error = None

        ssl_ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def http_error_302(self, req, fp, code, msg, headers):
                return fp
            http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302

        handlers = []
        if not allow_redirects:
            handlers.append(NoRedirectHandler())
        handlers.append(urllib.request.HTTPSHandler(context=ssl_ctx))
        opener = urllib.request.build_opener(*handlers)

        while attempts <= self.retries:
            try:
                req_data = data.encode("utf-8") if isinstance(data, str) else data
                req = urllib.request.Request(url, data=req_data, headers=headers, method=method.upper())
                with opener.open(req, timeout=self.timeout) as resp:
                    raw_content = resp.read()
                    charset = resp.headers.get_content_charset() or "utf-8"
                    try:
                        text = raw_content.decode(charset, errors="replace")
                    except Exception:
                        text = raw_content.decode("utf-8", errors="replace")
                    elapsed = time.time() - start_time
                    resp_headers = {k: v for k, v in resp.headers.items()}
                    return WebResponse(
                        status_code=resp.status,
                        headers=resp_headers,
                        text=text,
                        content=raw_content,
                        url=resp.geturl() or url,
                        elapsed=elapsed
                    )
            except urllib.error.HTTPError as e:
                elapsed = time.time() - start_time
                try:
                    err_content = e.read()
                    err_text = err_content.decode("utf-8", errors="replace")
                except Exception:
                    err_content = b""
                    err_text = ""
                err_headers = {k: v for k, v in e.headers.items()} if e.headers else {}
                return WebResponse(
                    status_code=e.code,
                    headers=err_headers,
                    text=err_text,
                    content=err_content,
                    url=url,
                    elapsed=elapsed
                )
            except Exception as e:
                last_error = str(e)
                attempts += 1
                if attempts <= self.retries:
                    time.sleep(0.3 * attempts)

        elapsed = time.time() - start_time
        return WebResponse(
            status_code=0,
            headers={},
            text="",
            content=b"",
            url=url,
            elapsed=elapsed,
            error=last_error or "Connection error"
        )

    def get(self, url: str, **kwargs) -> WebResponse:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs) -> WebResponse:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> WebResponse:
        return self.request("OPTIONS", url, **kwargs)

    def post(self, url: str, **kwargs) -> WebResponse:
        return self.request("POST", url, **kwargs)
