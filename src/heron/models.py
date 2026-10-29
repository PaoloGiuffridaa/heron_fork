from dataclasses import dataclass
from enum import StrEnum

@dataclass(frozen=True) #frozen is for readonly classes
class ParsedEmail(): 
    """Dataclass that contains all the field from an parsed email"""
    email_id: str
    sender: str
    from_domain: str | None
    reply_to_domain: str | None
    auth_result: str
    text: str
    links: tuple[str]

email = ParsedEmail(
    email_id="1",
    sender="fede.lecca@gmail.com",
    from_domain="@gmail.com",
    reply_to_domain=None,
    auth_result="OK",
    text="poba",
    links=("amazon.it", "paypal.com")
)

@dataclass(frozen=True)
class TriageResult():
    """The verdict of an phishind detection system, given an email"""
    email_id: str
    score: int
    verdict: Verdict

class Verdict(StrEnum):
    """The possible verdicts of the phishing detection system"""
    PHISHING = "PHISHING"
    SUSPICIOUS = "SUSPICIOUS"
    OK = "OK"