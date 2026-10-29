"""
core/crawler.py - BFS Web Crawler and Attack Vector Extractor
"""
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from typing import Set, List, Dict, Any
from core.requester import Requester

class Crawler:
    def __init__(self, target_base_url: str, requester: Requester, max_depth: int = 2):
        self.base_url = target_base_url.rstrip("/")
        self.domain = urlparse(self.base_url).netloc
        self.requester = requester
        self.max_depth = max_depth
        self.visited_urls: Set[str] = set()
        self.discovered_vectors: List[Dict[str, Any]] = []

    def is_in_scope(self, url: str) -> bool:
        """Ensures the crawler strictly stays within the authorized target domain."""
        parsed = urlparse(url)
        return parsed.netloc == self.domain or not parsed.netloc

    def crawl(self) -> List[Dict[str, Any]]:
        """Executes a Breadth-First Search (BFS) crawl to discover URLs and form inputs."""
        queue: List[tuple[str, int]] = [(self.base_url, 0)]
        
        while queue:
            current_url, depth = queue.pop(0)
            if current_url in self.visited_urls or depth > self.max_depth:
                continue
                
            self.visited_urls.add(current_url)
            resp = self.requester.send("GET", current_url)
            if not resp or not resp.text or "text/html" not in resp.headers.get("Content-Type", ""):
                continue

            soup = BeautifulSoup(resp.text, "html.parser")
            
            # 1. Parse URL query parameters
            parsed_url = urlparse(current_url)
            if parsed_url.query:
                params = list(parse_qs(parsed_url.query).keys())
                self.discovered_vectors.append({
                    "type": "URL_QUERY",
                    "url": current_url.split("?")[0],
                    "method": "GET",
                    "params": {k: "1" for k in params}
                })

            # 2. Parse HTML <form> inputs
            for form in soup.find_all("form"):
                action = form.get("action") or current_url
                form_url = urljoin(current_url, action)
                method = form.get("method", "GET").upper()
                inputs = {}
                for inp in form.find_all(["input", "textarea"]):
                    name = inp.get("name")
                    if name:
                        inputs[name] = inp.get("value", "test_val")
                        
                if inputs:
                    self.discovered_vectors.append({
                        "type": "FORM",
                        "url": form_url,
                        "method": method,
                        "params": inputs
                    })

            # 3. Queue downstream links
            if depth < self.max_depth:
                for a_tag in soup.find_all("a", href=True):
                    next_url = urljoin(current_url, a_tag["href"]).split("#")[0]
                    if self.is_in_scope(next_url) and next_url not in self.visited_urls:
                        queue.append((next_url, depth + 1))
                        
        return self.discovered_vectors
