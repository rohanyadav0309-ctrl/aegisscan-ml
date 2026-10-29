"""
core/requester.py - Resilient HTTP Client with Telemetry
"""
import time
import requests
from urllib.parse import urlparse
from typing import Optional, Dict, Any

class Requester:
    def __init__(self, timeout: int = 8, delay: float = 0.05, user_agent: Optional[str] = None):
        self.session = requests.Session()
        self.timeout = timeout
        self.delay = delay
        self.headers = {
            "User-Agent": user_agent or "AegisScan-Engine/1.0 (+Security Audit Framework)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "keep-alive"
        }
        self.session.headers.update(self.headers)
        
    def send(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Executes an HTTP request with delay pacing, timeout protection, and latency metrics.
        """
        if self.delay > 0:
            time.sleep(self.delay)
            
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        
        try:
            start_time = time.perf_counter()
            response = self.session.request(method.upper(), url, **kwargs)
            elapsed = time.perf_counter() - start_time
            # Attach custom timing metadata to response
            response.elapsed_seconds = elapsed  # type: ignore
            return response
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.RequestException as exc:
            return None
