"""
ml/features.py - Feature Vectorizer for HTTP Payloads and Responses
"""
import math
import re
import numpy as np
from typing import List, Dict, Any

class HTTPFeatureExtractor:
    # Common signature fragments for SQL errors
    SQL_ERRORS = [
        "sql syntax", "mysql", "syntax error", "ora-", 
        "postgresql", "sqlite", "unclosed quotation mark"
    ]

    @staticmethod
    def shannon_entropy(data: str) -> float:
        """Calculates Shannon entropy to detect obfuscated payloads."""
        if not data:
            return 0.0
        entropy = 0.0
        for x in set(data):
            p_x = float(data.count(x)) / len(data)
            entropy += - p_x * math.log(p_x, 2)
        return entropy

    def extract(self, payload: str, status_code: int, response_body: str) -> np.ndarray:
        """
        Extracts a 7-dimensional numeric feature vector from the HTTP transaction.
        """
        # 1. Payload length
        p_len = len(payload)
        
        # 2. Syntax/escape characters count (', ", <, >, ;, %, --)
        special_chars = len(re.findall(r"['\"<>;%=\-]", payload))
        
        # 3. Shannon entropy of the payload
        entropy = self.shannon_entropy(payload)
        
        # 4. HTTP response status code
        status = float(status_code)
        
        # 5. Length of the response body
        body_len = float(len(response_body))
        
        # 6. Database error signature presence (binary)
        has_sql_error = 1.0 if any(err in response_body.lower() for err in self.SQL_ERRORS) else 0.0
        
        # 7. Unescaped reflection of payload in response (binary)
        has_reflection = 1.0 if payload in response_body else 0.0

        return np.array([p_len, special_chars, entropy, status, body_len, has_sql_error, has_reflection], dtype=np.float32)
