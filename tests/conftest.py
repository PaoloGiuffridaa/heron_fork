import pytest

from heron.models import ParsedEmail
from tests.helpers import make_email


@pytest.fixture
def benign_email() -> ParsedEmail:
    return make_email()


@pytest.fixture
def phishing_email() -> ParsedEmail:
    return make_email(
        sender="PayPal Support <security@paypa1-secure.net>",
        from_domain="paypa1-secure.net",
        reply_to_domain="mail-verify.net",
        auth_results="spf=fail; dmarc=fail",
        text="urgent: your account is suspended.",
        links=("http://192.0.2.44/login",),
    )
