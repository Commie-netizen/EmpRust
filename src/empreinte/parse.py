"""Small, forgiving Obsidian Markdown parser."""
from __future__ import annotations

import re
import csv
from pathlib import PurePosixPath
from urllib.parse import unquote, urlsplit

from .model import ParsedDoc

_CJK = r"\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\U00020000-\U0003134f"
_WORDS = re.compile(rf"[{_CJK}]|[^\W_{_CJK}]+(?:['’][^\W_{_CJK}]+)*", re.UNICODE)
_LINK = re.compile(r"(!?)\[\[([^\[\]\n]+)\]\]|!?\[[^\[\]\n]*\]\((<[^>\[\n]*>|[^)\[\n]*)\)")


def count_words(text: str) -> int:
    """Count word runs, treating each Han character as one word."""
    return sum(1 for _ in _WORDS.finditer(text))


def is_text(media_type: str) -> bool:
    """Recognize textual MIME types, including structured text."""
    media = media_type.lower().split(";", 1)[0].strip()
    return media.startswith("text/") or media.endswith(("+json", "+xml")) or media in {
        "application/json", "application/xml", "application/javascript",
        "application/x-python", "application/sql", "application/x-sh",
        "application/toml", "application/yaml", "application/x-yaml", "image/svg+xml",
    }


def _scalar(value: str) -> str:
    return value.strip().strip("\"'")


def _items(value: str) -> list[str]:
    return [_scalar(s).lstrip("#") for s in re.split(r"[,\s]+", value.strip().strip("[]")) if _scalar(s)]


def _aliases(value: str) -> list[str]:
    return [s for item in next(csv.reader([value.strip().strip("[]")], skipinitialspace=True))
            if (s := _scalar(item))]


def _body(text: str) -> tuple[dict[str, str | list[str]], str]:
    lines = text.lstrip("\ufeff").splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        return {}, "".join(lines)
    end = next((i for i in range(1, len(lines)) if lines[i].strip() in {"---", "..."}), None)
    if end is None:
        return {}, "".join(lines)
    meta: dict[str, str | list[str]] = {}
    key = ""
    for line in lines[1:end]:
        candidate, separator, value = line.partition(":")
        if separator and candidate in {"title", "tags", "aliases"}:
            key = candidate
            meta[key] = _scalar(value) if key == "title" else (_aliases(value) if key == "aliases" else _items(value))
        elif key in {"tags", "aliases"} and line.lstrip().startswith("- "):
            values = meta[key]
            if isinstance(values, list):
                values.extend([_scalar(line.lstrip()[2:])] if key == "aliases" else _items(line.lstrip()[2:]))
        else:
            key = ""
    return meta, "".join(lines[end + 1:])


def _without_fences(body: str) -> str:
    output: list[str] = []
    fence = ""
    length = 0
    for line in body.splitlines(keepends=True):
        match = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line.rstrip("\r\n"))
        if fence:
            if match and match[1][0] == fence and len(match[1]) >= length and not match[2].strip():
                fence = ""
            output.append("\n")
        elif match:
            fence, length = match[1][0], len(match[1])
            output.append("\n")
        else:
            output.append(line)
    return "".join(output)


def _without_inline_code(text: str) -> str:
    # Index delimiter runs first so unmatched backticks cannot cause rescans.
    runs = list(re.finditer(r"`+", text))
    following: dict[int, int] = {}
    last: dict[int, int] = {}
    for i in range(len(runs) - 1, -1, -1):
        size = len(runs[i][0])
        if size in last:
            following[i] = last[size]
        last[size] = i
    output: list[str] = []
    cursor = i = 0
    while i < len(runs):
        if i in following:
            end = following[i]
            output.extend((text[cursor:runs[i].start()], " "))
            cursor = runs[end].end()
            i = end + 1
        else:
            i += 1
    output.append(text[cursor:])
    return "".join(output)


def parse_document(text: str, *, path: str, media_type: str = "text/markdown") -> ParsedDoc:
    """Extract navigation metadata without evaluating YAML or Markdown."""
    fallback = PurePosixPath(path.replace("\\", "/")).stem
    if media_type.split(";", 1)[0].lower() not in {"text/markdown", "text/x-markdown"}:
        return ParsedDoc(title=fallback, words=count_words(text))
    meta, body = _body(text)
    body = _without_fences(body)
    clean = _without_inline_code(body)
    headings: list[str] = []
    first_title = ""
    for line in clean.splitlines():
        heading = re.match(r"^ {0,3}(#{1,6})[ \t]+(.*)$", line)
        if heading:
            label = heading[2].strip()
            without_hashes = label.rstrip("#")
            if without_hashes and without_hashes[-1].isspace():
                label = without_hashes.rstrip()
            headings.append(label)
            if len(heading[1]) == 1 and not first_title:
                first_title = label
    links: list[str] = []
    embeds: list[str] = []

    def link(match: re.Match[str]) -> str:
        if match[2] is not None:
            target = match[2].split("|", 1)[0].split("#", 1)[0].strip()
            if target:
                (embeds if match[1] else links).append(target)
        else:
            raw = match[3].strip()
            raw = raw[1:-1] if raw.startswith("<") and raw.endswith(">") else raw.split(' "', 1)[0]
            try:
                parts = urlsplit(raw)
                if not parts.scheme and not parts.netloc and parts.path:
                    links.append(unquote(parts.path))
            except ValueError:
                pass
        return " "

    clean = _LINK.sub(link, clean)
    tags = list(meta.get("tags", []))
    for match in re.finditer(r"(?<![\w#])#([\w/-]+)", clean):
        tag = match[1]
        if not tag.isnumeric():
            tags.append(tag)
    return ParsedDoc(title=str(meta.get("title") or first_title or fallback),
                     tags=list(dict.fromkeys(tags)), links=links, embeds=embeds,
                     aliases=list(dict.fromkeys(meta.get("aliases", []))),
                     headings=headings, words=count_words(body))


def plain_body(text: str, media_type: str = "text/markdown") -> str:
    """Body text for search snippets, without front matter or Markdown decoration."""
    if media_type.split(";", 1)[0].lower() not in {"text/markdown", "text/x-markdown"}:
        return text
    _, text = _body(text)
    text = re.sub(r"!?\[\[([^\[\]\n]+)\]\]", lambda m: m[1].split("|", 1)[-1], text)
    text = re.sub(r"!?\[([^\[\]\n]*)\]\([^\n)]*\)", r"\1", text)
    text = re.sub(r"(?m)^\s*(?:#{1,6}\s+|>\s*|[-+*]\s+|\d+\.\s+|`{3,}.*$|~{3,}.*$)", "", text)
    return re.sub(r"[*_`~]", "", text)
