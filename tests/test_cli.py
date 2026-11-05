from pathlib import Path

import pytest

from heron.cli import main

SAMPLES = Path(__file__).parent.parent / "data" / "samples"


def test_cli_triages_the_six_samples(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main([str(SAMPLES)])

    out = (
        capsys.readouterr().out
    )  # when executing the command, the output is captured by capsys.readouterr().out
    assert exit_code == 0
    assert out.splitlines()[-1] == "6 emails: 2 phishing, 1 suspicious, 3 benign"
