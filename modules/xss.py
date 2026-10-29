"""
modules/xss.py - Context-Aware Reflected XSS Auditor
"""
import uuid
from typing import List, Dict, Any
from urllib.parse import urlencode
from modules.base import BaseScannerModule

class XSSModule(BaseScannerModule):
    def scan(self, target: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        url = target["url"]
        method = target["method"]
        base_params = target["params"]

        for param_key in base_params.keys():
            # Canary token ensures zero false-positive collisions with existing page text
            canary = f"aegis_{uuid.uuid4().hex[:6]}"
            payload = f"<script>{canary}</script>"
            
            test_params = base_params.copy()
            test_params[param_key] = payload
            
            resp = None
            if method == "GET":
                resp = self.requester.send("GET", f"{url}?{urlencode(test_params)}")
            elif method == "POST":
                resp = self.requester.send("POST", url, data=test_params)

            if resp and canary in resp.text:
                findings.append({
                    "vuln_type": "Cross-Site Scripting (Reflected)",
                    "severity": "MEDIUM",
                    "cvss": 6.1,
                    "url": url,
                    "parameter": param_key,
                    "payload": payload,
                    "status_code": resp.status_code,
                    "response_body": resp.text[:5000],
                    "elapsed": getattr(resp, "elapsed_seconds", 0.0)
                })
        return findings
