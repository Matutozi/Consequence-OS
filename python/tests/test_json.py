import json

import pytest

from consequence_verify import AmbiguousJSON, loads_strict


@pytest.mark.parametrize(
    "body",
    [
        '{"amount": 10, "amount": 5000}',
        '{"amount": 10, "Amount": 5000}',
        '{"params": {"arguments": {"a": 1, "A": 2}}}',
        '{"x": [{"k": 1, "k": 2}]}',
        '{"amount": NaN}',
        '{"amount": Infinity}',
        '{"amount": -Infinity}',
    ],
)
def test_ambiguous_bodies_are_refused(body):
    with pytest.raises(AmbiguousJSON):
        loads_strict(body)


def test_plain_json_parses():
    assert loads_strict('{"amount": 5000, "note": "caf\\u00e9", "items": [1, 2.5]}') == {
        "amount": 5000,
        "note": "café",
        "items": [1, 2.5],
    }


def test_not_json_is_a_decode_error_not_ambiguity():
    with pytest.raises(json.JSONDecodeError):
        loads_strict("{not json")
