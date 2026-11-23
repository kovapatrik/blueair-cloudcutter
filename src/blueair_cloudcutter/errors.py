class CutterError(Exception):
    """An expected, user-facing failure."""


class DeviceError(CutterError):
    """The device rejected a request or did not answer as expected."""


class TransportError(CutterError):
    """Serial / network transport failed."""


class SafetyError(CutterError):
    """A destructive action was refused because a precondition was not met."""
