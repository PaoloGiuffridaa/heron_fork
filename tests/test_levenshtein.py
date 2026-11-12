import pytest

from heron.features import levenshtein


def test_distance_zero_with_identical_strings() -> None:
    assert levenshtein("paypal", "paypal") == 0


def test_distance_1_with_one_character_difference() -> None:
    assert levenshtein("paypal", "paypa") == 1
    assert levenshtein("paypal", "paypall") == 1
    assert levenshtein("paypal", "paypol") == 1


@pytest.mark.parametrize(
    ("a", "b", "distance"),
    [
        ("", "abc", 3),
        ("amazon", "", 6),
        ("paypal", "paypa1", 1),
        ("amazon", "amaz0n", 1),
        ("microsoft", "microsft", 1),
        ("ab", "ba", 2),
    ],
)
def test_multiple_distances(a: str, b: str, distance: int) -> None:
    assert levenshtein(a, b) == distance
