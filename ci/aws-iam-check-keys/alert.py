from dataclasses import dataclass
from datetime import datetime


@dataclass
class Alert:
    alert_type: str
    warn_date: datetime
    violation_date: datetime
    last_rotated: datetime = None
    username: str = ""
    key_num: str = ""
