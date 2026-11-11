from importlib import import_module

from .base import BaseDetector
from .exceptions import DetectorNotFoundError

MODULE_KEYS = (
    "phishing_url",
    "network_intrusion",
    "phishing_email",
    "malware_risk",
    "suspicious_login",
    "ransomware_behavior",
)

_REGISTRY: dict = {}
_INSTANCES: dict = {}


def register(cls):
    """Class decorator: @register on a BaseDetector subclass."""
    _REGISTRY[cls.key] = cls
    _INSTANCES.pop(cls.key, None)
    return cls


def unregister(key: str) -> None:
    _REGISTRY.pop(key, None)
    _INSTANCES.pop(key, None)


def autodiscover(key: str = None) -> None:
    """Import detectors.<key>.predictor so its @register runs. Missing modules are skipped."""
    for k in ([key] if key else MODULE_KEYS):
        target = f"detectors.{k}.predictor"
        try:
            import_module(target)
        except ModuleNotFoundError as exc:
            if exc.name not in (target, f"detectors.{k}"):
                raise


def get_detector(key: str) -> BaseDetector:
    if key not in _REGISTRY:
        autodiscover(key) if key in MODULE_KEYS else None
    if key not in _REGISTRY:
        raise DetectorNotFoundError(f"no detector registered for {key!r}")
    if key not in _INSTANCES:
        _INSTANCES[key] = _REGISTRY[key]()
    return _INSTANCES[key]


def status() -> list:
    autodiscover()
    out = []
    for k in MODULE_KEYS:
        cls = _REGISTRY.get(k)
        out.append(
            {
                "module": k,
                "registered": cls is not None,
                "ready": bool(cls and get_detector(k).is_ready()),
                "version": cls.version if cls else None,
            }
        )
    return out