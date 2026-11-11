class DetectorError(Exception):
    """Base class for all detector errors."""


class DetectorNotFoundError(DetectorError):
    """No detector is registered for the requested module."""


class ModelNotLoadedError(DetectorError):
    """The module exists but its trained artifacts are missing."""


class InvalidInputError(DetectorError):
    """The payload failed validation. Safe to show to the caller."""