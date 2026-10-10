import pytest

from evidenceshield_crypto.canonicalization import (
    canonicalize_json,
    canonicalize_json_str,
)


def test_rfc8785_key_sorting():
    # RFC 8785 requires sorting by UTF-16 code units
    data = {"b": 2, "a": 1, "c": 3}
    assert canonicalize_json_str(data) == '{"a":1,"b":2,"c":3}'

    # Check key ordering consistency
    data2 = {"z": 10, "aa": 20, "a": 30}
    assert canonicalize_json_str(data2) == '{"a":30,"aa":20,"z":10}'


def test_rfc8785_whitespace_removal():
    data = {"case_id": "CAS-001", "items": [1, 2, {"key": "val"}]}
    assert canonicalize_json_str(data) == '{"case_id":"CAS-001","items":[1,2,{"key":"val"}]}'


def test_rfc8785_number_formatting():
    assert canonicalize_json_str(0) == "0"
    assert canonicalize_json_str(-42) == "-42"
    assert canonicalize_json_str(100.0) == "100"


def test_rfc8785_rejects_nan_and_inf():
    with pytest.raises(ValueError, match="NaN or Infinity"):
        canonicalize_json_str(float("nan"))

    with pytest.raises(ValueError, match="NaN or Infinity"):
        canonicalize_json_str(float("inf"))


def test_rfc8785_utf8_bytes():
    data = {"name": "Justice & Forensic"}
    raw = canonicalize_json(data)
    assert isinstance(raw, bytes)
    assert raw == b'{"name":"Justice & Forensic"}'
