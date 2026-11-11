from __future__ import annotations

import os
import threading
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from .exceptions import ModelNotLoadedError

ARTIFACTS_ROOT = Path(
    os.environ.get(
        "KITSUNE_ARTIFACTS_DIR",
        Path(__file__).resolve().parent.parent / "ml_artifacts",
    )
)

RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_CRITICAL = "low", "medium", "high", "critical"
RISK_ORDER = {RISK_LOW: 0, RISK_MEDIUM: 1, RISK_HIGH: 2, RISK_CRITICAL: 3}


def risk_from_score(score: float, thresholds=(0.30, 0.60, 0.85)) -> str:
    """Map a 0-1 malicious-probability to a risk level."""
    if score < thresholds[0]:
        return RISK_LOW
    if score < thresholds[1]:
        return RISK_MEDIUM
    if score < thresholds[2]:
        return RISK_HIGH
    return RISK_CRITICAL


@dataclass(frozen=True)
class DetectionResult:
    prediction: str
    risk_level: str
    score: Optional[float] = None
    explanation: dict = field(default_factory=dict)
    model_version: str = ""
    input_summary: str = ""

    def __post_init__(self):
        if self.risk_level not in RISK_ORDER:
            raise ValueError(f"invalid risk_level: {self.risk_level!r}")

    def to_dict(self) -> dict:
        return asdict(self)


class BaseDetector(ABC):
    """Contract every detection module implements."""

    key: str = ""
    display_name: str = ""
    version: str = "0.0.0"
    artifact_files: tuple = ()

    def __init__(self, artifacts_dir=None):
        self.artifacts_dir = Path(artifacts_dir) if artifacts_dir else ARTIFACTS_ROOT / self.key
        self._loaded = False
        self._lock = threading.Lock()

    def is_ready(self) -> bool:
        return all((self.artifacts_dir / f).is_file() for f in self.artifact_files)

    def ensure_loaded(self) -> None:
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            if not self.is_ready():
                raise ModelNotLoadedError(f"{self.key}: trained model artifacts not found")
            self.load()
            self._loaded = True

    @abstractmethod
    def load(self) -> None:
        """Load model files from self.artifacts_dir (called once, lazily)."""

    @abstractmethod
    def validate_input(self, payload: dict) -> dict:
        """Validate and normalise the payload. Raise InvalidInputError on bad input."""

    @abstractmethod
    def _predict(self, data: dict) -> DetectionResult:
        """Run the model on validated data."""

    def analyze(self, payload: dict[str, Any]) -> DetectionResult:
        data = self.validate_input(payload)
        self.ensure_loaded()
        return self._predict(data)