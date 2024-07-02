from dataclasses import dataclass

@dataclass
class Threshold:
    account_type: str
    warn: int
    violation: int
    alert: bool
    user: str = ""
