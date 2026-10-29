"""Read and parse relevant parts from an email message"""

from email import message_from_string, policy
from email.utils import parseaddr
import re
from heron.models import ParsedEmail

_URL_RE = re.compile(r"https?://[^\\s\"'<>]+")

def parse_eml(raw: str, email_id: str) -> ParsedEmail:
    """Parse a raw email file and and return a data structure with the useful fields"""
    msg = message_from_string(raw, policy=policy.default)
    sender = str(msg.get("From", ""))
    reply_to=_domain(str(msg.get("Reply-To", "")))
    from_domain = _domain(sender)
    reply_domain = _domain(reply_to) 
    auhth_result = str(msg.get("Authentication-Results", "")).lower()

    parsed_email = ParsedEmail(
        email_id=email_id,
        sender=sender,
        from_domain=from_domain,
        reply_to_domain=reply_domain,
        auth_result=auhth_result,
        text=raw.lower(),
        links=tuple(re.findall(_URL_RE, raw))
    )
    return parsed_email

def _domain(header_value: str) -> str | None:
    """return the email address domain if exists, otherwise None

    Args:
        address (_type_): _description_
    """
    _, address = parseaddr(header_value)
    if "@" not in address:
        return None
    return address.split("@")[1].lower()