"""Synchronous chat completions restricted to loopback model servers."""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import time
from collections.abc import Callable
from typing import Any, TypeVar
from urllib.parse import urlsplit, urlunsplit

import httpx
from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)
Message = dict[str, str]


class LLMError(RuntimeError):
    """Local inference or response validation failed."""


def strip_reasoning(text: str) -> str:
    """Discard complete and unterminated reasoning blocks."""
    return re.sub(r"<think\b[^>]*>.*?(?:</think\s*>|$)", "", text, flags=re.I | re.S).strip()


def iter_json_objects(text: str) -> list[Any]:
    """Extract successive JSON objects from prose or fenced model replies."""
    text = strip_reasoning(text)
    decoder = json.JSONDecoder()
    result = []
    position = 0
    while (start := text.find("{", position)) != -1:
        try:
            obj, end = decoder.raw_decode(text, start)
        except ValueError:
            position = start + 1
        else:
            result.append(obj)
            position = end
    return result


def complete_json(client: LocalLLMClient, messages: list[Message], schema: type[T], *, retries: int = 2,
                  max_tokens: int = 1024) -> T:
    """Try every object against the schema, then request a corrected response."""
    conversation = list(messages)
    error = "no JSON object in output"
    for _ in range(retries + 1):
        raw = client.complete(conversation, json_mode=True, max_tokens=max_tokens)
        for obj in iter_json_objects(raw):
            try:
                return schema.model_validate(obj)
            except ValidationError as exc:
                error = str(exc)
        conversation = messages + [{"role": "assistant", "content": raw[:2000]},
            {"role": "user", "content": f"Return one valid JSON object. Validation error: {error[:800]}"}]
    raise LLMError("invalid model JSON: " + error[:300])


def _local_url(base_url: str) -> str:
    parts = urlsplit(base_url)
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("model URL must be an http(s) loopback URL without credentials, query or fragment")
    host = parts.hostname
    if "%" in host:
        raise ValueError("model host must be loopback without a zone identifier")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        if host.lower() != "localhost":
            raise ValueError("model host must be localhost or a loopback IP address") from None
    else:
        if not literal.is_loopback:
            raise ValueError("model host must be a loopback address")
    try:
        addresses = socket.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError("cannot resolve local model host") from exc
    if not addresses or any(not ipaddress.ip_address(item[4][0]).is_loopback for item in addresses):
        raise ValueError("model host resolved to a non-loopback address")
    # Pin the validated address: a later DNS resolution cannot redirect plaintext.
    address = addresses[0][4][0]
    authority = f"[{address}]" if ":" in address else address
    if parts.port is not None:
        authority += f":{parts.port}"
    return urlunsplit((parts.scheme, authority, parts.path.rstrip("/"), "", ""))


class LocalLLMClient:
    """Loopback-only client with bounded retries and injectable HTTP transport."""

    def __init__(self, base_url: str = "http://127.0.0.1:11434/v1", model: str = "local", *,
                 transport: httpx.BaseTransport | None = None, timeout: float = 120,
                 max_retries: int = 2, sleep: Callable[[float], None] = time.sleep) -> None:
        if max_retries < 0 or timeout <= 0:
            raise ValueError("max_retries must be nonnegative and timeout positive")
        self.base_url = _local_url(base_url)
        self.model, self.timeout, self.max_retries = model, timeout, max_retries
        self._sleep = sleep
        self._http = httpx.Client(transport=transport, trust_env=False, follow_redirects=False)

    def complete(self, messages: list[Message], *, temperature: float = 0.2,
                 max_tokens: int = 1024, json_mode: bool = False) -> str:
        """Call the pinned local server, never following redirects or proxies."""
        payload: dict[str, Any] = {"model": self.model, "messages": messages,
            "temperature": temperature, "max_tokens": max_tokens}
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        error = "no completion"
        for attempt in range(self.max_retries + 1):
            try:
                response = self._http.post(self.base_url + "/chat/completions", json=payload, timeout=self.timeout)
            except httpx.HTTPError as exc:
                error = type(exc).__name__
            else:
                if response.status_code == 200:
                    try:
                        raw = response.json()["choices"][0]["message"]["content"]
                        result = strip_reasoning(raw) if isinstance(raw, str) else ""
                    except (ValueError, KeyError, IndexError, TypeError):
                        result = ""
                    if result:
                        return result
                    error = "empty or malformed completion"
                elif response.status_code in {408, 409, 425, 429, 500, 502, 503, 504}:
                    error = f"HTTP {response.status_code}"
                else:
                    raise LLMError(f"local server HTTP {response.status_code}")
            if attempt < self.max_retries:
                self._sleep(min(8.0, 0.5 * 2 ** attempt))
        raise LLMError(f"local model failed after {self.max_retries + 1} attempts: {error}")

    def complete_json(self, messages: list[Message], schema: type[T], *, retries: int = 2,
                      max_tokens: int = 1024) -> T:
        """Validate a structured local completion."""
        return complete_json(self, messages, schema, retries=retries, max_tokens=max_tokens)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> LocalLLMClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


OpenAICompatClient = LocalLLMClient
