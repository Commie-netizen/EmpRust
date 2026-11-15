"""Personal-data detection and scrubbing.

Contract (used by seeds, extractor and the final filter):
    find_pii(text) -> sorted list of category names found, [] when clean
    scrub(text)    -> text with each hit replaced by a placeholder such as [EMAIL]

Categories and placeholders:
    email   [EMAIL]    plain and lightly obfuscated addresses (name [at] host [dot] com)
    url     [URL]      http(s)://, www. and bare domains on common TLDs
    ip      [IP]       IPv4 and full IPv6 addresses
    handle  [HANDLE]   @user, u/user, and WeChat / QQ / Telegram / Snapchat id mentions
    phone   [PHONE]    international, North American, French, UK, Chinese mobile and landline
    id      [ID]       long digit runs: national ids, card numbers, SSN-like patterns
    address [ADDRESS]  street addresses (English, French, Chinese) with a house number

The patterns are regex based and tuned for precision on ordinary counseling text:
ages, years, durations, clock times, small amounts of money and scores are not flagged.
Personal names cannot be detected reliably with regexes and are out of scope here;
the Extractor enforces name abstraction separately.

Guarantee: find_pii(scrub(t)) == [] for any string t.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

_CJK = r"㐀-䶿一-鿿豈-﫿"
_TLDS = r"com|net|org|edu|gov|io|info|biz|fr|cn|uk|de|ru|jp|xyz"


@dataclass(frozen=True)
class _Rule:
    name: str
    pattern: re.Pattern[str]
    groups: tuple[str, ...] = ()  # when set, replace only the first group that matched
    accept: Callable[[re.Match[str]], bool] | None = None  # extra validation of a match


def _not_year_list(m: re.Match[str]) -> bool:
    """Reject runs like '1998 2004 2010' that are lists of years, not a card number."""
    groups = re.findall(r"\d+", m.group(0))
    return not all(len(g) == 4 and g[:2] in ("19", "20") for g in groups)


def _enough_digits(lo: int, hi: int) -> Callable[[re.Match[str]], bool]:
    def check(m: re.Match[str]) -> bool:
        return lo <= sum(c.isdigit() for c in m.group(0)) <= hi

    return check


_IM_KEYWORDS = r"微信号?|威信|薇信|vx|v信|wechat|weixin|qq号?|扣扣|telegram|snapchat|discord|kakao"
_IM_VALUE = r"[A-Za-z0-9][A-Za-z0-9_.-]{2,28}[A-Za-z0-9_]"
# Words that cannot be part of a street name after a number ("3 years on that street").
_ADDRESS_FILLERS = (
    r"(?:years?|months?|weeks?|days?|hours?|minutes?|times?|blocks?|streets?|roads?|miles?|kms?"
    r"|doors?|houses?|floors?|stops?|kids?|people|friends?|of|on|in|at|to|the|that|this|these|those"
    r"|a|an|and|or|but|down|up|across|along|from|away|over|near|by|for|with|my|our|his|her|their"
    r"|your|its|same|other|another|different|whole|entire|busy|quiet|more|less|few|many"
    r"|separate|lives?|living|walked|moved|ago|later)\b"
)

_RULES: tuple[_Rule, ...] = (
    _Rule(
        "email",
        re.compile(
            r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
        ),
    ),
    _Rule(
        "email",
        re.compile(
            r"\b[A-Za-z0-9._-]+\s*(?:\[at\]|\(at\)|\{at\})\s*[A-Za-z0-9-]+\s*"
            r"(?:\[dot\]|\(dot\)|\{dot\}|\sdot\s|\.)\s*(?:" + _TLDS + r")\b",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        "email",
        re.compile(
            r"\b[A-Za-z0-9._-]+\s+at\s+[A-Za-z0-9-]+\s+dot\s+(?:" + _TLDS + r")\b",
            re.IGNORECASE,
        ),
    ),
    _Rule("url", re.compile(r"(?:https?://|www\.)[^\s<>\"'\]\)）】」]+", re.IGNORECASE)),
    _Rule(
        "url",
        re.compile(
            r"(?<![\w@.-])(?:[a-z0-9-]{2,63}\.)+(?:" + _TLDS + r")\b(?:/[^\s<>\"'\]\)）]*)?",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        "ip",
        re.compile(
            r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])"
        ),
    ),
    _Rule(
        "ip",
        re.compile(r"(?<![0-9a-f:])(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}(?![0-9a-f:])", re.IGNORECASE),
    ),
    # IM ids: "微信号: lilyrose", "QQ 12345678", "my wechat is lily2001". Only the value is
    # replaced. The value needs real handle evidence: either an explicit id keyword
    # (id, username, 号, 账号...) before it, or a digit, an underscore or an inner dot in
    # it. So "Discord: talking to friends", "wechat group" or "my wechat is blocked"
    # stay clean.
    _Rule(
        "handle",
        re.compile(
            r"(?<![A-Za-z])(?:" + _IM_KEYWORDS + r")(?![A-Za-z])"
            r"(?:\s*(?:id|username|user\s?name|handle|pseudo|identifiant|号|账号|帐号)(?![A-Za-z])"
            r"\s*(?:[:：=]|是|为|is|est)?\s*(?P<v>" + _IM_VALUE + r")"
            r"|\s*(?:[:：=]|是|为|is|est)?\s*(?P<w>(?=[A-Za-z-]*(?:\d|_|\.[A-Za-z0-9]))" + _IM_VALUE + r"))",
            re.IGNORECASE,
        ),
        groups=("v", "w"),
    ),
    _Rule("handle", re.compile(r"(?<![\w@./])@[A-Za-z_](?:[A-Za-z0-9_.]{0,28}[A-Za-z0-9_])?")),
    _Rule("handle", re.compile(r"(?<![\w/])/?u/[A-Za-z0-9_-]{3,20}\b")),
    # Phones. Each alternative is anchored so that it cannot start or end inside a number.
    _Rule("phone", re.compile(r"(?<![\d+])(?:\+?86[\s-]?)?1[3-9]\d[\s-]?\d{4}[\s-]?\d{4}(?!\d)")),
    _Rule(
        "phone",
        re.compile(r"(?<![\w+])\+\d{1,3}[\s.-]?(?:\(\d{1,4}\)[\s.-]?)?\d{1,4}(?:[\s.-]?\d{2,4}){1,4}(?!\d)"),
        accept=_enough_digits(8, 15),
    ),
    _Rule("phone", re.compile(r"(?<![\d(])\(\d{3}\)[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)")),
    _Rule("phone", re.compile(r"(?<![\d.-])\d{3}[.-]\d{3}[.-]\d{4}(?![\d.-]?\d)")),
    _Rule("phone", re.compile(r"(?<![\d.,])\d{3}\s\d{3}\s\d{4}(?![\d.,]?\d)")),
    _Rule("phone", re.compile(r"(?<![\d.])0[1-9](?:[\s.-]?\d{2}){4}(?!\d)")),
    _Rule("phone", re.compile(r"(?<![\d-])0\d{2,3}-\d{7,8}(?!\d)")),
    _Rule("phone", re.compile(r"(?<!\d)0\d{3,4}\s\d{6,7}(?!\d)")),
    # Ids and card numbers.
    _Rule("id", re.compile(r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])")),
    _Rule("id", re.compile(r"(?<!\d)\d{4}(?:[ -]\d{4}){2,4}(?!\d)"), accept=_not_year_list),
    _Rule("id", re.compile(r"(?<!\d)\d{17}[Xx](?![A-Za-z0-9])")),
    _Rule("id", re.compile(r"(?<![\d.,])\d{9,}(?![\d.,]?\d)")),
    _Rule("id", re.compile(r"(?<!\d)[12]\s\d{2}\s\d{2}\s\d{2}\s\d{3}\s\d{3}(?:\s\d{2})?(?!\d)")),
    # Street addresses: a house number, then capitalised words, then a street type.
    _Rule(
        "address",
        re.compile(
            r"(?<![\w.])\d{1,5}[A-Za-z]?\s+(?:[A-Z][a-z]+\.?\s+){1,3}"
            r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Terrace"
            r"|Place|Pl|Crescent|Close|Square|Sq|Parkway|Pkwy|Highway|Hwy)\b\.?"
            r"(?:,?\s*(?:Apt|Apartment|Unit|Suite|Flat)\.?\s*#?\w{1,5})?"
        ),
    ),
    # Lower-case variant ("42 maple street"): one or two name words that are not
    # ordinary function words or units, then a full street type, singular.
    _Rule(
        "address",
        re.compile(
            r"(?<![\w.])\d{1,5}[a-z]?\s+(?:(?!" + _ADDRESS_FILLERS + r")[a-z]{2,}\s+){1,2}"
            r"(?:street|avenue|road|boulevard|lane|drive|court|terrace|crescent|parkway|highway)\b"
            r"(?!-)",
            re.IGNORECASE,
        ),
    ),
    _Rule(
        "address",
        re.compile(
            r"(?<![\w.])\d{1,4}(?:\s?(?:bis|ter))?,?\s+"
            r"(?i:rue|avenue|av\.|boulevard|bd|chemin|all[ée]e|impasse|place|quai|route)\s+"
            r"(?:(?i:de\s+la|de\s+l'|du|des|de|d')\s*)?[A-ZÀ-Ý][\w'’-]*(?:\s+[A-ZÀ-Ý][\w'’-]*){0,3}"
        ),
    ),
    _Rule(
        "address",
        re.compile(
            r"(?:(?![在住于到的是我家])[" + _CJK + r"]){2,5}(?:路|街|大道|巷|弄|胡同)\d{1,5}(?:号|號)"
            r"(?:院?\d{1,4}(?:号楼|栋|幢|座))?(?:\d{1,3}单元)?(?:\d{1,5}(?:室|房))?"
        ),
    ),
    _Rule("address", re.compile(r"\d{1,4}(?:号楼|栋|幢)\d{1,3}单元(?:\d{1,5}(?:室|号|房))?")),
)


# Cheap gates: a category is only searched when its gate matches somewhere in the text.
# Every pattern of the category requires what its gate looks for, so results are unchanged.
_GATES: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"@|\bat\b|\[at\]|\(at\)|\{at\}", re.IGNORECASE),
    "url": re.compile(r"\."),
    "ip": re.compile(r"\d"),
    "handle": re.compile(r"@|u/|" + _IM_KEYWORDS, re.IGNORECASE),
    "phone": re.compile(r"\d"),
    "id": re.compile(r"\d"),
    "address": re.compile(r"\d"),
}


def _active(text: str) -> list[_Rule]:
    open_ = {name for name, gate in _GATES.items() if gate.search(text)}
    return [rule for rule in _RULES if rule.name in open_]


def _hits(text: str) -> list[tuple[_Rule, re.Match[str]]]:
    out = []
    for rule in _active(text):
        for m in rule.pattern.finditer(text):
            if rule.accept is None or rule.accept(m):
                out.append((rule, m))
    return out


def find_pii(text: str) -> list[str]:
    """Return the sorted, de-duplicated category names found in `text`."""
    return sorted({rule.name for rule, _ in _hits(text)})


def _replacement(rule: _Rule, m: re.Match[str]) -> str:
    placeholder = f"[{rule.name.upper()}]"
    for g in rule.groups:
        if m.group(g) is not None:
            whole, base = m.group(0), m.start()
            start, end = m.span(g)
            return whole[: start - base] + placeholder + whole[end - base:]
    return placeholder


def _scrub_once(text: str) -> str:
    for rule in _active(text):

        def repl(m: re.Match[str], rule: _Rule = rule) -> str:
            if rule.accept is not None and not rule.accept(m):
                return m.group(0)
            return _replacement(rule, m)

        text = rule.pattern.sub(repl, text)
    return text


def scrub(text: str) -> str:
    """Replace every hit by its placeholder. Idempotent: find_pii(scrub(t)) == []."""
    for _ in range(4):
        new = _scrub_once(text)
        if new == text:
            # A pass that changes nothing found no accepted match: text is clean.
            return text
        text = new
    # Safety net for pathological overlaps: blank remaining hits one at a time.
    for _ in range(50):
        hits = _hits(text)
        if not hits:
            break
        rule, m = max(hits, key=lambda h: h[1].start())
        text = text[: m.start()] + f"[{rule.name.upper()}]" + text[m.end():]
    return text
