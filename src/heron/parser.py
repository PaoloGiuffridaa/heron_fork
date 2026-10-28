"""Read and parse relevant parts from an email message"""

from email.utils import parseaddr

def sender_domain(header_value):
    """return the email address domain if exists, otherwise None

    Args:
        address (_type_): _description_
    """
    _, address = parseaddr(header_value)
    if "@" not in address:
        return None
    return address.split("@")[1].lower()