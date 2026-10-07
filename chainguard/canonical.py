"""Restricted canonical JSON bytes for M3 typed records; no cryptography."""

import json


MAX_INTEGER = 2**53 - 1


def _validate(value):
    if value is None or type(value) is bool:
        return
    if type(value) is int and abs(value) <= MAX_INTEGER:
        return
    if type(value) is str:
        value.encode("utf-8", errors="strict")
        return
    if type(value) is list:
        for item in value:
            _validate(item)
        return
    if type(value) is dict and all(type(key) is str for key in value):
        for key, item in value.items():
            _validate(key)
            _validate(item)
        return
    raise ValueError("Value outside the restricted canonical JSON types/range")


def encode(value) -> bytes:
    """Unicode is preserved, keys sorted, integers bounded, floats rejected."""
    _validate(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key")
        result[key] = value
    return result


def _noninteger(value):
    raise ValueError("Floating point and non-finite numbers are unsupported")


def decode(data: bytes):
    """Read only exact canonical bytes, rejecting duplicate keys and aliases."""
    if type(data) is not bytes:
        raise ValueError("Canonical storage must contain bytes")
    value = json.loads(data.decode("utf-8", errors="strict"),
                       object_pairs_hook=_object, parse_float=_noninteger,
                       parse_constant=_noninteger)
    if encode(value) != data:
        raise ValueError("Noncanonical JSON representation")
    return value
