"""Email text cleaning. Pure string processing: never fetches links or opens attachments."""
from __future__ import annotations

import html
import re

MAX_CHARS = 20000

_A_TAG = re.compile(r"<a\b[^>]{0,2000}?href\s*=[^>]{0,2000}>", re.I)
_TAGS = re.compile(r"<[^>]{0,2000}>")
_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]{1,500}", re.I)
_EMAIL = re.compile(r"[\w.+-]{1,64}@[\w-]{1,255}(?:\.[\w-]{1,63}){1,5}")
_NUM = re.compile(r"\d{3,}")
_HEADER = re.compile(
    r"^(?:message-id|from|to|cc|bcc|date|x-[\w-]+|mime-version|content-[\w-]+|return-path|received|"
    r"reply-to|sender|delivered-to|in-reply-to|references|status|lines|xref|path|newsgroups)\s*:.*$",
    re.I | re.M,
)
_SUBJECT = re.compile(r"^subject\s*:\s*", re.I | re.M)
_WS = re.compile(r"\s+")

PLACEHOLDERS = {"urltoken": "[link]", "emailtoken": "[email address]", "numtoken": "[number]"}


def count_links(text) -> int:
    t = str(text)[:MAX_CHARS]
    return len(_A_TAG.findall(t)) + len(_URL.findall(_A_TAG.sub(" ", t)))


def build_email_text(subject, body) -> str:
    return f"{subject or ''}\n{body or ''}"


def clean_text(text, max_chars: int = MAX_CHARS) -> str:
    """Lowercase, strip HTML and mail headers, mask links/addresses/numbers."""
    t = html.unescape(str(text)[:max_chars])
    t = _A_TAG.sub(" urltoken ", t)
    t = _TAGS.sub(" ", t)
    t = _HEADER.sub(" ", t)
    t = _SUBJECT.sub(" ", t)
    t = _URL.sub(" urltoken ", t)
    t = _EMAIL.sub(" emailtoken ", t)
    t = _NUM.sub(" numtoken ", t)
    return _WS.sub(" ", t.lower()).strip()