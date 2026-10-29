"""
modules/base.py - Abstract Base Class for Scanner Probers
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from core.requester import Requester

class BaseScannerModule(ABC):
    def __init__(self, requester: Requester):
        self.requester = requester

    @abstractmethod
    def scan(self, target: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Audits an endpoint and returns verified findings."""
        pass
