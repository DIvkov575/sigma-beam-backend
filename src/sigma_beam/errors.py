"""Custom exception types for sigma_beam evaluation paths."""


class SigmaBeamError(Exception):
    """Base class for runtime errors raised inside the pipeline."""


class EvaluationError(SigmaBeamError):
    """Raised (and caught) when a rule's predicate explodes on an event."""
