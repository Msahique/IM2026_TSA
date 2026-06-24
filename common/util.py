import json


def canonical_json(obj) -> bytes:
    """Deterministic JSON bytes used for signing/verifying structured data."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
