"""Deterministic, bounded model context; no tokenizer, model call or disk cache."""
from dataclasses import dataclass
import hashlib
import re

from .parse import plain_body

CONTEXT_BYTES = 12_000
CONTEXT_POLICY = "teaser-extract-v1-12000"


def preview_cache_policy(base_url: str) -> str:
    """Bind the context policy to the local endpoint without changing Preview."""
    return CONTEXT_POLICY + ":endpoint-sha256:" + hashlib.sha256(base_url.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Context:
    text: str
    source_bytes: int
    sent_bytes: int
    partial: bool


def compact_context(document: str, media_type: str, *, max_bytes: int = CONTEXT_BYTES) -> Context:
    """Remove metadata/duplicate paragraphs, then sample beginning, middle and end.

    UTF-8 bytes are a deterministic size budget, NOT an exact model token count.
    Sampling is intentionally disclosed: omitted passages may contain other topics.
    """
    if max_bytes < 128:
        raise ValueError("context budget must be at least 128 bytes")
    source_bytes = len(document.encode("utf-8"))
    seen, paragraphs = set(), []
    for paragraph in re.split(r"\n\s*\n", plain_body(document, media_type)):
        paragraph = re.sub(r"[ \t]+", " ", paragraph).strip()
        if paragraph and paragraph not in seen:
            seen.add(paragraph)
            paragraphs.append(paragraph)
    raw = "\n\n".join(paragraphs).encode("utf-8")
    partial = len(raw) > max_bytes
    if partial:
        marker = "\n[... passage omis ...]\n"
        size = (max_bytes - 2 * len(marker.encode("utf-8"))) // 3
        starts = (0, (len(raw) - size) // 2, len(raw) - size)
        text = marker.join(raw[start:start + size].decode("utf-8", errors="ignore") for start in starts)
    else:
        text = raw.decode("utf-8")
    return Context(text, source_bytes, len(text.encode("utf-8")), partial)
