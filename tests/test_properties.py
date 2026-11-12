from hypothesis import given
from hypothesis import strategies as st

from heron.features import levenshtein


@given(a=st.text(), b=st.text())
def test_levenshtein_properties(a: str, b: str) -> None:
    distance = levenshtein(a, b)

    assert distance == levenshtein(b, a)
    assert abs(len(a) - len(b)) <= distance <= max(len(a), len(b))
    assert (distance == 0) == (a == b)
