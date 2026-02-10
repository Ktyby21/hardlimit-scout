from __future__ import annotations
from typing import Dict, Protocol

class StateStore(Protocol):
    def load_last_sent(self, account_id: str) -> Dict[str,float]:
        ...
    
    def save_last_sent(self, account_id: str, last_sent: Dict[str,float]) -> None:
        ...