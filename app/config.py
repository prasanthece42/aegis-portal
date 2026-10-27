import os
from pathlib import Path
from typing import Literal

from aegis_platform.portal_config import LiveConfig
from aegis_platform.portal_config import Profile as Profile

from app.security import strict_json


class Settings:
    def __init__(self):
        self.mode: Literal["unconfigured", "demo", "live"] = os.getenv("AEGIS_MODE", "unconfigured")
        if self.mode not in {"unconfigured", "demo", "live"}:
            raise ValueError("AEGIS_MODE must be unconfigured, demo or live")
        self.live = None
        if self.mode == "live":
            self.live = LiveConfig.model_validate(
                strict_json(Path(os.environ["AEGIS_CONFIG"]).read_bytes())
            )
        self.demo_path = Path(os.getenv("AEGIS_DEMO_DATA", ".local/demo-registrations.json"))
        self.origin = self.live.public_origin if self.live else "http://127.0.0.1:8010"
        self.cookie_name = "__Host-aegis_session" if self.mode == "live" else "aegis_demo_session"
