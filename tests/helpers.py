"""Build test messages without writing .eml files."""

from heron.models import ParsedEmail


def make_email(
    *,  # the argumets before the * can be passed without keywords,
    # the ones after must be passed with keywords
    sender: str = "Alice <alice@example.com>",
    from_domain: str | None = "example.com",
    reply_to_domain: str | None = None,
    auth_results: str = "spf=pass; dkim=pass; dmarc=pass",
    text: str = "hello, see you at the meeting.",
    links: tuple[str, ...] = (),
) -> ParsedEmail:
    """A harmless message; each keyword argument changes one field."""
    return ParsedEmail(
        email_id="test.eml",
        sender=sender,
        from_domain=from_domain,
        reply_to_domain=reply_to_domain,
        auth_results=auth_results,
        text=text,
        links=links,
    )
