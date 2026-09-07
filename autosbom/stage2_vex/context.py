"""Device context: the automotive configuration facts VEX rules reason over.

A device context file (JSON always; YAML if PyYAML is installed) describes
how the *actual device* is configured — which features are disabled, what
network exposure exists, whether local access is realistically achievable.
Example: examples/device-context.json.

The context is declarative input written by a human who knows the device.
The rules engine only ever *proposes* suppressions from it; nothing here is
an authority on its own (see review.py).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..common.io_utils import load_yaml_or_json


@dataclass
class DeviceContext:
    device_name: str = "unknown-device"
    # Feature/profile switches, e.g. {"bluetooth.avrcp": False, "bluetooth": True}
    features: dict[str, bool] = field(default_factory=dict)
    # Components with no path to a reachable network interface.
    network_isolated_components: list[str] = field(default_factory=list)
    # True if untrusted local access (shell/USB debug) is realistically possible.
    local_access_possible: bool = True
    # Components present on disk but never loaded/executed in this configuration.
    not_in_execute_path: list[str] = field(default_factory=list)
    # Free-text notes carried into VEX impact statements.
    notes: str = ""

    @classmethod
    def load(cls, path: str | Path) -> "DeviceContext":
        data = load_yaml_or_json(path)
        if data is not None and not isinstance(data, dict):
            raise ValueError(f"{path}: device context must be a JSON/YAML "
                             f"object, got {type(data).__name__}")
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in (data or {}).items() if k in known})

    def feature_enabled(self, feature: str) -> bool | None:
        """Tri-state: True/False if declared, None if not covered by context."""
        if feature in self.features:
            return self.features[feature]
        # A disabled parent implies disabled children: bluetooth=False
        # implies bluetooth.avrcp is off even if not listed explicitly.
        parts = feature.split(".")
        for i in range(len(parts) - 1, 0, -1):
            parent = ".".join(parts[:i])
            if self.features.get(parent) is False:
                return False
        return None
