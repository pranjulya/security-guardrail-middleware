"""Bounded injection-risk rules with stable rule IDs.

Detection runs over several *views* of the input, never over the raw text alone:

* ``lite``     NFKC, format/invisible characters stripped, diacritics removed,
               casefolded, confusable/homoglyph letters folded to ASCII,
               whitespace collapsed (punctuation kept).
* ``words``    ``lite`` with markdown emphasis removed, every non-alphanumeric run
               turned into one space and spaced-out single letters rejoined.
* ``leet``     ``words`` with common digit substitutions folded (0->o, 1->i ...).
* ``squashed`` letters only; scanned with a small set of long, strong patterns.

In addition, a bounded, single level of decoding (base64/base64url, hex, percent
and HTML entities) is applied and decoded payloads are scanned with the same
views. Decoding is never recursive.

Limits are measured *after* normalisation. If a normalised view exceeds
``MAX_NORMALIZED_CHARS`` the scan fails closed with :class:`InjectionScanLimit`
instead of truncating (truncation after NFKC expansion was a bypass).
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass

# Inputs are capped at 16 KiB UTF-8 upstream; NFKC can expand a code point up to
# 18x. Anything above this after normalisation is refused, not truncated.
MAX_NORMALIZED_CHARS = 64 * 1024
MAX_DECODE_CANDIDATES = 32
MAX_DECODED_CHARS = 16 * 1024
_MIN_ENCODED_LEN = 16

RULE_ORDER = ("block-direct-override", "block-exfiltration")


class InjectionScanLimit(Exception):
    """Normalised input exceeded the scan bound; callers must fail closed."""

    def __init__(self) -> None:
        super().__init__("injection scan limit exceeded")


@dataclass(frozen=True)
class InjectionFinding:
    rule_id: str


# --------------------------------------------------------------------------- #
# Normalisation
# --------------------------------------------------------------------------- #

_CONFUSABLES = {
    # Cyrillic
    "а": "a",
    "в": "b",
    "е": "e",
    "ё": "e",
    "һ": "h",
    "і": "i",
    "ї": "i",
    "ј": "j",
    "к": "k",
    "м": "m",
    "н": "h",
    "о": "o",
    "р": "p",
    "с": "c",
    "т": "t",
    "у": "y",
    "ү": "y",
    "х": "x",
    "ѕ": "s",
    "ԁ": "d",
    "ԛ": "q",
    "ԝ": "w",
    "ӏ": "l",
    "ҽ": "e",
    "ɡ": "g",
    "ѵ": "v",
    "ԍ": "g",
    "ᴦ": "r",
    # Greek
    "α": "a",
    "β": "b",
    "γ": "y",
    "ε": "e",
    "η": "n",
    "ι": "i",
    "κ": "k",
    "μ": "u",
    "ν": "v",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "υ": "u",
    "χ": "x",
    "ω": "w",
    "ϲ": "c",
    "ϳ": "j",
    "ς": "s",
    "σ": "o",
    # Armenian
    "օ": "o",
    "ս": "u",
    "ռ": "n",
    "հ": "h",
    "ց": "g",
    "զ": "q",
    # Latin look-alikes and small capitals
    "ı": "i",
    "ȷ": "j",
    "ɑ": "a",
    "ɩ": "i",
    "ʀ": "r",
    "ʏ": "y",
    "ᴀ": "a",
    "ʙ": "b",
    "ᴄ": "c",
    "ᴅ": "d",
    "ᴇ": "e",
    "ɢ": "g",
    "ʜ": "h",
    "ɪ": "i",
    "ᴊ": "j",
    "ᴋ": "k",
    "ʟ": "l",
    "ᴍ": "m",
    "ɴ": "n",
    "ᴏ": "o",
    "ᴘ": "p",
    "ꜱ": "s",
    "ᴛ": "t",
    "ᴜ": "u",
    "ᴠ": "v",
    "ᴡ": "w",
    "ᴢ": "z",
    "ǀ": "l",
    "ɵ": "o",
    "ø": "o",
    "đ": "d",
    "ł": "l",
}
# Regional indicator symbols render as letters in many UIs.
_CONFUSABLES.update({chr(0x1F1E6 + i): chr(ord("a") + i) for i in range(26)})
_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLES)

_LEET_TABLE = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"}
)

# Variation selectors / combining grapheme joiner are category Mn and are
# removed with the other combining marks below.
_WS_RE = re.compile(r"\s+")
_MARKDOWN_RE = re.compile(r"[*~`]+")
_NON_ALNUM_RE = re.compile(r"[\W_]+")
_SPACED_LETTERS_RE = re.compile(r"(?<!\w)(?:\w )+\w(?!\w)")
_NON_LETTER_RE = re.compile(r"[^a-z]+")


def _strip_invisible(text: str) -> str:
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def _fold(text: str) -> str:
    """NFKC + invisible stripping, keeping case (used for decoding candidates)."""
    return unicodedata.normalize("NFKC", _strip_invisible(text))


def _lite(folded: str) -> str:
    decomposed = unicodedata.normalize("NFKD", folded)
    no_marks = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    recomposed = unicodedata.normalize("NFKC", no_marks).casefold()
    return _WS_RE.sub(" ", recomposed.translate(_CONFUSABLE_TABLE)).strip()


def _words(lite: str) -> str:
    text = _MARKDOWN_RE.sub("", lite)
    text = _NON_ALNUM_RE.sub(" ", text).strip()
    return _SPACED_LETTERS_RE.sub(lambda m: m.group(0).replace(" ", ""), text)


def _views(text: str) -> list[tuple[str, str]]:
    folded = _fold(text)
    lite = _lite(folded)
    if len(lite) > MAX_NORMALIZED_CHARS:
        raise InjectionScanLimit()
    words = _words(lite)
    views = [("lite", lite), ("words", words)]
    if any(ch.isdigit() for ch in words):
        views.append(
            (
                "words",
                _SPACED_LETTERS_RE.sub(
                    lambda m: m.group(0).replace(" ", ""), words.translate(_LEET_TABLE)
                ),
            )
        )
    views.append(("squashed", _NON_LETTER_RE.sub("", views[-1][1])))
    return views


def normalized_view(text: str) -> str:
    """Primary word-level detection view (no truncation; raises on oversize)."""
    lite = _lite(_fold(text))
    if len(lite) > MAX_NORMALIZED_CHARS:
        raise InjectionScanLimit()
    return _words(lite)


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #

_V_OVERRIDE = r"(?:ignore|disregard|forget|override|overrule|bypass|discard|abandon)"
_Q = (
    r"(?:previous|prior|above|earlier|preceding|original|initial|foregoing|system|"
    r"all|any|every|your|these|those|existing|current|developer|safety)"
)
_T = (
    r"(?:instructions?|directives?|rules|guidelines|guardrails?|prompts?|policies|"
    r"constraints|restrictions|programming|orders|commands)"
)
_V_REVEAL = (
    r"(?:reveal|print|show|display|output|repeat|dump|leak|disclose|expose|"
    r"recite|echo|tell me|give me)"
)
_O_HIDDEN_ADJ = (
    r"(?:system|hidden|secret|initial|original|internal|confidential|admin|"
    r"developer)"
)
_N_HIDDEN_NOUN = (
    r"(?:prompts?|instructions?|message|notes?|passwords?|keys?|credentials?|"
    r"config(?:uration)?|rules|tokens?|secrets?)"
)
_SENSITIVE_OBJ = (
    r"(?:list|data|records?|database|db|files?|credentials?|passwords?|"
    r"keys?|secrets?|tokens?|history|conversation|chat|logs?|contacts?|"
    r"emails|prompt|notes)"
)
_V_SEND = r"(?:send|email|e-mail|mail|forward|upload|post|transmit|copy|leak|share)"
_V_DESTROY = r"(?:delete|drop|destroy|wipe|erase|purge|truncate|remove)"
_DATA_OBJ = (
    r"(?:records?|tables?|databases?|db|rows|users|accounts|files|backups|"
    r"logs|data)"
)

# (rule_id, views it applies to, pattern)
_RULES: tuple[tuple[str, tuple[str, ...], str], ...] = (
    # --- direct override / role hijack -----------------------------------
    (
        "block-direct-override",
        ("lite", "words"),
        rf"\b{_V_OVERRIDE}\s+(?:\w+\s+){{0,3}}?{_Q}\s+(?:\w+\s+){{0,2}}?{_T}\b",
    ),
    (
        "block-direct-override",
        ("lite", "words"),
        (
            rf"\b{_V_OVERRIDE}\s+(?:the\s+|all\s+|any\s+|your\s+)?{_T}\s+(?:above|before|"
            r"earlier|so far|you were given|you have been given|from before)\b"
        ),
    ),
    (
        "block-direct-override",
        ("lite", "words"),
        (
            r"\byou\s+are\s+(?:now\s+)?(?:no\s+longer\s+(?:bound|restricted|limited|an?\s+ai)|"
            r"free\s+(?:from|of)\s+(?:all\s+|any\s+|your\s+)?(?:rules|restrictions|guidelines|"
            r"filters|limits)|(?:now\s+)(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|"
            r"jailbroken|dan|evil|rogue)\b)"
        ),
    ),
    (
        "block-direct-override",
        ("lite", "words"),
        (
            r"\b(?:act|behave|pretend|roleplay)\s+(?:as|like|to\s+be)\s+(?:if\s+you\s+(?:are|"
            r"were)\s+)?(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|jailbroken|dan|evil|"
            r"rogue)\b"
        ),
    ),
    (
        "block-direct-override",
        ("lite", "words"),
        (
            r"\b(?:enter|enable|activate|switch\s+to)\s+(?:the\s+)?(?:developer|dan|god|"
            r"jailbreak|unrestricted)\s+mode\b"
        ),
    ),
    (
        "block-direct-override",
        ("lite", "words"),
        r"\bnew\s+system\s+(?:instructions?|prompts?|messages?|rules|directives?)\b",
    ),
    (
        "block-direct-override",
        ("lite", "words"),
        (
            r"\bfrom\s+now\s+on,?\s+you\s+(?:will|must|shall|are\s+to)\s+(?:ignore|disregard|"
            r"obey\s+only|no\s+longer)\b"
        ),
    ),
    (
        "block-direct-override",
        ("lite", "words"),
        (
            r"\b(?:ignore|disregard|forget)\s+(?:everything|anything|all)\s+(?:(?:that\s+)?you\s+"
            r"(?:were|have\s+been|had\s+been)\s+(?:told|given|instructed|taught)|above|before|"
            r"so\s+far|prior|earlier)\b"
        ),
    ),
    ("block-direct-override", ("lite",), r"<\|?\s*(?:im_start|system)\s*\|?>"),
    (
        "block-direct-override",
        ("squashed",),
        (
            r"(?:ignore|disregard|forget|override|bypass)(?:all|any|the|your|of){0,3}"
            r"(?:previous|prior|above|earlier|preceding|original|initial|system)"
            r"(?:instructions?|directives?|rules|guidelines|prompts?)"
        ),
    ),
    # --- exfiltration / destructive -----------------------------------------
    (
        "block-exfiltration",
        ("lite", "words"),
        (
            rf"\b{_V_REVEAL}\s+(?:me\s+)?(?:the\s+|your\s+|all\s+|any\s+)?(?:\w+\s+)?"
            rf"{_O_HIDDEN_ADJ}\s+(?:\w+\s+)?{_N_HIDDEN_NOUN}\b"
        ),
    ),
    (
        "block-exfiltration",
        ("lite", "words"),
        (
            r"\bwhat\s+(?:is|are|was|were)\s+your\s+(?:system|initial|original|hidden|secret)\s+"
            r"(?:prompts?|instructions?|rules)\b"
        ),
    ),
    (
        "block-exfiltration",
        ("lite", "words"),
        (
            r"\bexfiltrat\w*\s+(?:\w+\s+){0,2}?(?:data|records?|files?|secrets?|credentials?|"
            r"keys?|tokens?|database|db|information|info|emails?|contacts?|logs?|prompts?|"
            r"messages?|it|this|them|everything)\b"
        ),
    ),
    (
        "block-exfiltration",
        ("words",),
        (
            rf"\b{_V_SEND}\s+(?:\w+\s+){{0,5}}?to\s+(?:an?\s+|the\s+|my\s+|this\s+|some\s+)?"
            r"(?:external|outside|third\s?party|remote|attackers?|attacker\w*|unknown|public)\b"
        ),
    ),
    (
        "block-exfiltration",
        ("lite",),
        (
            rf"\b{_V_SEND}\s+(?:[\w.-]+\s+){{0,4}}?{_SENSITIVE_OBJ}\s+to\s+"
            r"(?:[\w.+-]+@[\w-]+(?:\.[\w-]+)+|https?://\S+)"
        ),
    ),
    (
        "block-exfiltration",
        ("lite", "words"),
        (
            rf"\b{_V_DESTROY}\s+(?:all|every|each|the\s+entire|the\s+whole)\s+(?:of\s+)?"
            rf"(?:the\s+)?(?:\w+\s+){{0,2}}?{_DATA_OBJ}\b"
        ),
    ),
    (
        "block-exfiltration",
        ("lite", "words"),
        (
            r"\b(?:delete|drop|destroy|wipe|erase|purge|truncate)\s+(?:the\s+)?(?:\w+\s+)?"
            r"(?:records|tables?|databases?|db)\b"
        ),
    ),
    (
        "block-exfiltration",
        ("squashed",),
        (
            r"(?:reveal|print|show|display|output|repeat|dump|leak|disclose)(?:me)?(?:the|your)?"
            r"(?:system|hidden|secret|initial|original|internal)(?:prompt|instructions?)"
        ),
    ),
    (
        "block-exfiltration",
        ("squashed",),
        r"exfiltrat(?:e|ing)(?:the|all)?(?:data|records|files|secrets|credentials)",
    ),
)

_COMPILED = tuple((rid, views, re.compile(p)) for rid, views, p in _RULES)


# --------------------------------------------------------------------------- #
# Single-level decoding of encoded payloads
# --------------------------------------------------------------------------- #

_B64_RE = re.compile(r"[A-Za-z0-9+/]{" + str(_MIN_ENCODED_LEN) + r",}={0,2}")
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]{" + str(_MIN_ENCODED_LEN) + r",}={0,2}")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")
_PCT_RE = re.compile(r"%[0-9A-Fa-f]{2}")


def _printable_text(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch.isspace())
    letters = sum(1 for ch in text if ch.isalpha())
    if printable / len(text) < 0.9 or letters < 4:
        return None
    return text


def _decode_b64(token: str, urlsafe: bool) -> str | None:
    stripped = token.rstrip("=")
    padded = stripped + "=" * (-len(stripped) % 4)
    try:
        if urlsafe:
            raw = base64.urlsafe_b64decode(padded)
        else:
            raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    return _printable_text(raw)


def _decoded_payloads(folded: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    budget = MAX_DECODED_CHARS

    def add(candidate: str | None) -> bool:
        nonlocal budget
        if candidate is None or candidate in seen or candidate == folded:
            return True
        if len(candidate) > budget or len(out) >= MAX_DECODE_CANDIDATES:
            return False
        seen.add(candidate)
        out.append(candidate)
        budget -= len(candidate)
        return True

    tokens = 0
    for regex, urlsafe in ((_B64_RE, False), (_B64URL_RE, True)):
        for match in regex.finditer(folded):
            tokens += 1
            if tokens > MAX_DECODE_CANDIDATES * 2:
                break
            if not add(_decode_b64(match.group(0), urlsafe)):
                return out
    for match in _HEX_RE.finditer(folded):
        try:
            raw = bytes.fromhex(match.group(0))
        except ValueError:
            continue
        if not add(_printable_text(raw)):
            return out
    if _PCT_RE.search(folded):
        add(urllib.parse.unquote(folded, errors="replace"))
    if "&" in folded:
        add(html.unescape(folded))
    return out


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def _scan(
    views: list[tuple[str, str]], wanted: set[str] | None, found: dict[str, InjectionFinding]
) -> None:
    for rule_id, applies_to, pattern in _COMPILED:
        if rule_id in found or (wanted is not None and rule_id not in wanted):
            continue
        for view_name, view in views:
            if view_name in applies_to and pattern.search(view):
                found[rule_id] = InjectionFinding(rule_id=rule_id)
                break


def detect(text: str, rule_ids: Iterable[str] | None = None) -> tuple[InjectionFinding, ...]:
    """Return findings (canonical rule order). Raises InjectionScanLimit on oversize."""
    wanted = set(rule_ids) if rule_ids is not None else None
    found: dict[str, InjectionFinding] = {}
    _scan(_views(text), wanted, found)
    if wanted is None or any(r not in found for r in wanted):
        for payload in _decoded_payloads(_fold(text)):
            _scan(_views(payload), wanted, found)
    return tuple(found[r] for r in RULE_ORDER if r in found) + tuple(
        f for r, f in found.items() if r not in RULE_ORDER
    )


def is_blocked(text: str, rule_ids: Iterable[str] | None = None) -> bool:
    try:
        return bool(detect(text, rule_ids))
    except InjectionScanLimit:
        return True
