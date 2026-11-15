"""Local HTTP server of Empreinte: the JSON API and the web interface.

Standard library only. The server gives access to a decrypted archive, so the browser
is treated as hostile territory:

* it binds to loopback only (127.0.0.1, ::1, localhost) unless `allow_remote=True`;
* every request must carry a Host header naming a loopback name and the bound port
  (defeats DNS rebinding), otherwise 403 `bad_host`;
* every state-changing request (POST, PUT, DELETE) must carry an Origin header equal to
  the server's own origin and a JSON content type, otherwise 403 `bad_origin` or 415;
  a `Sec-Fetch-Site` header other than same-origin or none is refused on /api;
* no CORS header is ever sent, OPTIONS gets 405;
* a random page token is created at start and written into index.html as a meta tag.
  Every /api call must send it in the `X-Empreinte-Token` header (a custom header, so
  another site cannot send it without a preflight that is never granted, and cannot
  read the page that holds it). Unlocking returns a second random token, kept in the
  page's memory only and sent as `X-Empreinte-Unlock`; it dies with the lock;
* the open vault, its workspace, the unlock token and a generation number form one
  session object, replaced or dropped atomically under the operation lock. Every
  authorised request re-checks the token against the current session while holding
  that lock, so a request authorised before a lock can never run against the next
  session. Locking calls workspace.close() (drops every plaintext it holds) and
  vault.lock(), then drops every reference. An unlock that finishes after a lock
  happened while it was running does not install its session;
* locking an open session needs its unlock token (another local process that only has
  the page token cannot lock the user out); locking when already locked is a no-op;
* the passphrase is rate limited: a few free attempts, then an exponential delay
  (429 with Retry-After); only one attempt runs at a time;
* an idle lock: after `idle_timeout` seconds without an API request (status polls do
  not count), the session is locked as above;
* denial of service: the request line plus headers and the body each have a total
  deadline enforced on every recv (a trickling client cannot extend it), concurrent
  connections are capped (503 beyond), a rejected request is answered and closed without
  reading its body, "Expect: 100-continue" is refused (417), and preview generation runs
  outside the operation lock;
* every response the process emits, including http.server's own error pages, carries a
  strict Content-Security-Policy (no inline script, no remote origin), `Cache-Control:
  no-store`, nosniff, frame denial and no referrer. The server writes nothing to disk
  itself (only the vault's export_bundle writes, into the configured export directory,
  on an explicit action), and logs only method, path without query, and status.
  Passphrases and tokens travel in bodies or headers, never in URLs;
* bodies are limited in size (413), every input is validated before the vault is
  called, static files come from an in-memory table built at start (no path is ever
  resolved against the file system from a request).

Routes (all JSON; X = needs the page token; U = also needs the unlock token; S = state
changing, needs a same-origin Origin). Errors are `{"error": code, "message": text}`.

    GET    /                                  the interface (index.html with the page token)
    GET    /<file>                            static files of web/ (css, js, svg)
    GET    /api/status                    X   {exists, unlocked, demo, features{import, previews,
                                              export, anchor_methods}, idle_timeout, retry_after}
    POST   /api/unlock                    XS  {passphrase} -> {unlock_token, idle_timeout}
    POST   /api/create                    XS  {passphrase} -> {unlock_token, idle_timeout, recovery_key}
    POST   /api/lock                      XS  {} -> {locked: true}; needs U when a session is open
    GET    /api/entries                   XU  [EntryMeta]
    GET    /api/entries/<id>              XU  {meta, parsed, outlinks, backlinks, link_targets}
    GET    /api/entries/<id>/text         XU  ?version=n -> {entry_id, version, media_type, text}
    GET    /api/entries/<id>/versions     XU  [Version]
    GET    /api/entries/<id>/proof        XU  ?version=n -> ProvenanceProof
    POST   /api/entries/<id>/remove       XUS {confirm: true} -> {removed: id}
    GET    /api/graph                     XU  ?until=ISO-datetime&tags=0|1 -> Graph
    POST   /api/search                    XUS {q, limit?} -> [SearchHit]
    POST   /api/mentions                  XUS {term, limit?} -> [Mention]
    GET    /api/activity                  XU  ?basis=claimed|ledger -> Activity
    GET    /api/ledger                    XU  ?offset=&limit=&order=asc|desc -> {total, offset, limit, order, records}
    POST   /api/verify                    XUS {} -> VerifyReport
    GET    /api/anchors                   XU  [Anchor]
    POST   /api/anchor                    XUS {method (one of anchor_methods), confirm: true} -> Anchor
    GET    /api/licenses                  XU  [LicenseGrant]
    POST   /api/licenses                  XUS {licensee, items:[{entry_id, version|null}], usage, terms?,
                                              royalty?:{model, amount, currency, note}, valid_until?} -> LicenseGrant
    POST   /api/licenses/<id>/export      XUS {} -> {license_id, path, bundle_hash}   (only when an export dir is set)
    GET    /api/royalties                 XU  ?license_id= -> [RoyaltyEvent]
    POST   /api/royalties                 XUS {license_id, amount, currency?, received_on?, period?, note?} -> RoyaltyEvent
    POST   /api/previews                  XUS {entry_ids:[...]} -> [Preview + {current, digest}] drafts
                                              (only when make_previews is set; runs outside the lock)
    GET    /api/previews/<id>             XU  Preview + {current, digest} (404 when none is stored)
    POST   /api/previews/<id>/approve     XUS {digest} -> Preview + {current, digest}, approved true
                                              (409 changed when digest differs, 409 stale)
    POST   /api/import                    XUS {path} -> dict                   (only when import_folder is set)
    GET    /api/prefs                     XU  interface preferences, stored encrypted with aux_put
    PUT    /api/prefs                     XUS any JSON object up to 64 KiB -> {saved: true}

Search terms go in POST bodies so that they never appear in a URL or a log line.

Status codes: 400 invalid input, 401 bad_token / locked / wrong_passphrase, 403 bad_host /
bad_origin / cross_site, 404 not_found / no_route / feature_off, 405, 408 timeout, 409
vault_error / exists / stale, 411, 413 too_large, 415, 429 rate_limited, 500 corrupted /
internal, 503 busy.

Run the demo: python -m empreinte.server --demo [--fresh] [--port N] [--open] [--idle S]
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import re
import secrets
import socket
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, unquote, urlsplit

from pydantic import BaseModel, ValidationError

from .api import Corrupted, NotFound, VaultAPI, VaultError, WorkspaceAPI, WrongPassphrase
from .model import Preview, RoyaltyTerms

WEB_DIR = Path(__file__).with_name("web")
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
TOKEN_PLACEHOLDER = "__EMPREINTE_PAGE_TOKEN__"
PREFS_KEY = "ui.prefs.v1"
PREVIEW_KEY = "preview/"  # same key as previews.make_preview
ENTRY_ID = re.compile(r"^[0-9a-f]{32}$")
LICENSE_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
CURRENCY = re.compile(r"^[A-Z]{3}$")
STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
}
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'none'; object-src 'none'"
)
SECURITY_HEADERS = (
    ("Cache-Control", "no-store"),
    ("Pragma", "no-cache"),
    ("Content-Security-Policy", CSP),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()"),
)


# --------------------------------------------------------------------------- session


@dataclass
class Session:
    """What the integrator supplies: how to open or create the vault, and optional actions.

    The callables keep no reference to the vault: import_folder and make_previews receive
    the vault and workspace of the current session as arguments. None hides the action in
    the interface. export_dir is where export_bundle writes disclosure bundles; None hides
    the export action.
    """

    open_vault: Callable[[str], tuple[VaultAPI, WorkspaceAPI]]
    create_vault: Callable[[str], tuple[VaultAPI, WorkspaceAPI, str]]
    exists: Callable[[], bool]
    import_folder: Callable[[VaultAPI, WorkspaceAPI, Path], dict] | None = None
    make_previews: Callable[[VaultAPI, WorkspaceAPI, list[str]], list[Preview]] | None = None
    export_dir: Path | None = None
    demo: bool = False


@dataclass
class ServerOptions:
    """Tunable limits (tests shorten them)."""

    idle_timeout: float = 900.0  # seconds without an API request before the vault locks
    free_attempts: int = 3  # wrong passphrases allowed before delays start
    base_delay: float = 2.0  # first delay in seconds, doubled at each further failure
    max_delay: float = 300.0
    max_body: int = 1_000_000  # bytes
    socket_timeout: float = 10.0  # any single read
    header_deadline: float = 15.0  # request line and headers, in total
    body_deadline: float = 30.0  # body, in total
    max_connections: int = 32
    log: bool = True


class ApiError(Exception):
    """An error answered as JSON with a given status."""

    def __init__(self, status: int, code: str, message: str, *, retry_after: float | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.retry_after = retry_after


@dataclass(eq=False)
class Active:
    """The open session: replaced or dropped as one piece, under App.lock."""

    vault: VaultAPI
    workspace: WorkspaceAPI
    token: str
    generation: int


# ---------------------------------------------------------------------- rate limiting


class RateLimiter:
    """Free attempts, then an exponential delay measured from the latest failure."""

    def __init__(self, free: int, base: float, maximum: float, clock: Callable[[], float] = time.monotonic):
        self.free, self.base, self.maximum, self.clock = free, base, maximum, clock
        self.failures = 0
        self.last_failure = 0.0
        self._lock = threading.Lock()

    def wait(self) -> float:
        """Seconds to wait before the next attempt is allowed (0 when allowed now)."""
        with self._lock:
            if self.failures < self.free:
                return 0.0
            delay = min(self.maximum, self.base * 2 ** (self.failures - self.free))
            return max(0.0, self.last_failure + delay - self.clock())

    def failure(self) -> None:
        with self._lock:
            self.failures += 1
            self.last_failure = self.clock()

    def success(self) -> None:
        with self._lock:
            self.failures = 0


# -------------------------------------------------------------------------- helpers


def to_json(value: Any) -> Any:
    """Turn models, dates and containers into JSON-ready values."""
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(k): to_json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_json(v) for v in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    return value


def bad(message: str) -> ApiError:
    return ApiError(400, "invalid", message)


def req_str(body: dict, key: str, *, min_len: int = 0, max_len: int = 1000, required: bool = True,
            default: str = "") -> str:
    value = body.get(key, None)
    if value is None:
        if required:
            raise bad(f"champ manquant : {key}")
        return default
    if not isinstance(value, str):
        raise bad(f"{key} doit être une chaîne")
    if "\x00" in value:
        raise bad(f"{key} contient un caractère nul")
    if not (min_len <= len(value) <= max_len):
        raise bad(f"{key} doit faire entre {min_len} et {max_len} caractères")
    return value


def req_bool(body: dict, key: str) -> bool:
    value = body.get(key, False)
    if not isinstance(value, bool):
        raise bad(f"{key} doit être un booléen")
    return value


def parse_int(raw: Any, key: str, *, lo: int, hi: int, default: int | None = None) -> int | None:
    if raw is None or raw == "":
        return default
    if isinstance(raw, bool):
        raise bad(f"{key} doit être un entier")
    if isinstance(raw, str):
        if not re.fullmatch(r"-?\d{1,12}", raw):
            raise bad(f"{key} doit être un entier")
        raw = int(raw)
    if not isinstance(raw, int) or not (lo <= raw <= hi):
        raise bad(f"{key} doit être un entier entre {lo} et {hi}")
    return raw


def parse_amount(raw: Any, key: str, *, lo: float, hi: float) -> float:
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise bad(f"{key} doit être un nombre")
    value = float(raw)
    if not math.isfinite(value) or not (lo <= value <= hi):
        raise bad(f"{key} doit être un nombre entre {lo} et {hi}")
    return value


def parse_date(raw: Any, key: str) -> date | None:
    if raw is None or raw == "":
        return None
    if not isinstance(raw, str) or len(raw) > 10:
        raise bad(f"{key} doit être une date AAAA-MM-JJ")
    try:
        return date.fromisoformat(raw)
    except ValueError:
        raise bad(f"{key} doit être une date AAAA-MM-JJ") from None


def parse_datetime(raw: str | None, key: str) -> datetime | None:
    if raw is None or raw == "":
        return None
    if len(raw) > 40:
        raise bad(f"{key} trop long")
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        raise bad(f"{key} doit être une date ISO 8601") from None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def entry_id_of(raw: str) -> str:
    if not ENTRY_ID.fullmatch(raw):
        raise ApiError(404, "not_found", "identifiant de note inconnu")
    return raw


def license_id_of(raw: Any) -> str:
    if not isinstance(raw, str) or not LICENSE_ID.fullmatch(raw):
        raise ApiError(404, "not_found", "identifiant de licence inconnu")
    return raw


def preview_digest(raw: bytes) -> str:
    """Names one stored preview exactly (hex SHA-256 of its stored JSON)."""
    return hashlib.sha256(raw).hexdigest()


def anchor_methods_of(vault: VaultAPI) -> list[str]:
    """The anchoring methods the vault really implements (none if it cannot say)."""
    method = getattr(vault, "anchor_methods", None)
    if method is None:
        return []
    try:
        return [m for m in method() if m in ("rfc3161", "opentimestamps")]
    except VaultError:
        return []


def load_static() -> dict[str, tuple[bytes, str]]:
    """Every file of web/, read once, keyed by its relative posix path."""
    files: dict[str, tuple[bytes, str]] = {}
    if not WEB_DIR.is_dir():
        return files
    for path in WEB_DIR.rglob("*"):
        if path.is_file() and path.suffix.lower() in STATIC_TYPES and not path.name.endswith(".test.mjs"):
            files[path.relative_to(WEB_DIR).as_posix()] = (path.read_bytes(), STATIC_TYPES[path.suffix.lower()])
    return files


def close_session(active: Active | None, *, lock_vault: bool = True) -> None:
    """Drop the workspace's plaintext, then the vault's keys, then release the vault
    (Vault.close() frees its writer lock, when the vault has one). Never raises."""
    if active is None:
        return
    close = getattr(active.workspace, "close", None)
    if close is not None:
        try:
            close()
        except Exception:  # noqa: BLE001 - locking must never fail the caller
            pass
    if not lock_vault:
        return
    for name in ("lock", "close"):
        method = getattr(active.vault, name, None)
        if method is None:
            continue
        try:
            method()
        except Exception:  # noqa: BLE001
            pass


# ------------------------------------------------------------------------ app state


class App:
    """Server-wide state: tokens, the open session, the rate limiter and the idle lock."""

    def __init__(self, session: Session, options: ServerOptions):
        self.session = session
        self.options = options
        self.page_token = secrets.token_urlsafe(32)
        self.active: Active | None = None
        self.generation = 0  # bumped every time a session is installed or locked
        self.last_activity = time.monotonic()
        self.lock = threading.RLock()  # serialises every call into the vault and workspace
        self.auth_lock = threading.Lock()  # one passphrase attempt at a time
        self.limiter = RateLimiter(options.free_attempts, options.base_delay, options.max_delay)
        self.static = load_static()
        self.host = "127.0.0.1"
        self.port = 0
        self.allowed_hosts: set[str] = set()
        self.allowed_origins: set[str] = set()
        self._stop = threading.Event()
        self.stopped = False

    # ---------------------------------------------------------------- binding
    def bind(self, host: str, port: int) -> None:
        self.host, self.port = host, port
        names = set(LOOPBACK_HOSTS) | {host.lower()}
        hosts = set()
        for name in names:
            bracketed = f"[{name}]" if ":" in name and not name.startswith("[") else name
            hosts.add(f"{bracketed}:{port}")
        self.allowed_hosts = hosts
        self.allowed_origins = {f"http://{h}" for h in hosts}

    # ------------------------------------------------------------- sessions
    def install(self, vault: VaultAPI, workspace: WorkspaceAPI, seen_generation: int) -> str | None:
        """Make (vault, workspace) the open session, unless a lock or a stop happened
        since `seen_generation` was read; then the new session is disposed of (workspace
        closed, vault locked and released) and None returned."""
        with self.lock:
            if self.stopped or self.generation != seen_generation:
                close_session(Active(vault, workspace, "", -1))
                return None
            previous = self.active
            self.generation += 1
            self.active = Active(vault, workspace, secrets.token_urlsafe(32), self.generation)
            self.last_activity = time.monotonic()
            if previous is not None:
                # The previous workspace always goes; its vault too, unless the new
                # session reopened that same vault object.
                close_session(previous, lock_vault=previous.vault is not vault)
            return self.active.token

    def do_lock(self) -> bool:
        """Lock the open session, if any, and invalidate every pending unlock or
        creation (they read the generation before opening). Returns whether a session
        was locked."""
        with self.lock:
            self.generation += 1
            active = self.active
            if active is None:
                return False
            self.active = None
            close_session(active)
            return True

    def current(self, token: str) -> Active | None:
        """The open session if `token` is its unlock token (caller holds self.lock)."""
        active = self.active
        if active is None or not token or not hmac.compare_digest(token.encode(), active.token.encode()):
            return None
        return active

    def idle_expired(self) -> bool:
        return self.active is not None and time.monotonic() - self.last_activity > self.options.idle_timeout

    def idle_loop(self) -> None:
        period = max(0.05, min(1.0, self.options.idle_timeout / 4))
        while not self._stop.wait(period):
            with self.lock:
                if self.idle_expired():
                    self.do_lock()

    def stop(self) -> None:
        with self.lock:
            self.stopped = True
        self._stop.set()
        self.do_lock()

    def index_html(self) -> bytes | None:
        item = self.static.get("index.html")
        if item is None:
            return None
        return item[0].replace(TOKEN_PLACEHOLDER.encode(), self.page_token.encode())

    def features(self, active: Active | None) -> dict[str, Any]:
        return {
            "import": self.session.import_folder is not None,
            "previews": self.session.make_previews is not None,
            "export": self.session.export_dir is not None,
            "anchor_methods": anchor_methods_of(active.vault) if active is not None else [],
        }


# ------------------------------------------------------------------------ handlers


Route = tuple[str, re.Pattern[str], str, bool]  # method, pattern, handler name, needs unlock


def _r(method: str, pattern: str, name: str, unlock: bool = True) -> Route:
    return method, re.compile(f"^{pattern}$"), name, unlock


ROUTES: list[Route] = [
    _r("GET", r"/api/status", "status", False),
    _r("POST", r"/api/unlock", "unlock", False),
    _r("POST", r"/api/create", "create", False),
    _r("POST", r"/api/lock", "lock_now", False),
    _r("GET", r"/api/entries", "entries"),
    _r("GET", r"/api/entries/([^/]+)", "entry"),
    _r("GET", r"/api/entries/([^/]+)/text", "entry_text"),
    _r("GET", r"/api/entries/([^/]+)/versions", "entry_versions"),
    _r("GET", r"/api/entries/([^/]+)/proof", "entry_proof"),
    _r("POST", r"/api/entries/([^/]+)/remove", "entry_remove"),
    _r("GET", r"/api/graph", "graph"),
    _r("POST", r"/api/search", "search"),
    _r("POST", r"/api/mentions", "mentions"),
    _r("GET", r"/api/activity", "activity"),
    _r("GET", r"/api/ledger", "ledger"),
    _r("POST", r"/api/verify", "verify"),
    _r("GET", r"/api/anchors", "anchors"),
    _r("POST", r"/api/anchor", "anchor"),
    _r("GET", r"/api/licenses", "licenses"),
    _r("POST", r"/api/licenses", "grant"),
    _r("POST", r"/api/licenses/([^/]+)/export", "export"),
    _r("GET", r"/api/royalties", "royalties"),
    _r("POST", r"/api/royalties", "record_royalty"),
    _r("POST", r"/api/previews", "previews"),
    _r("GET", r"/api/previews/([^/]+)", "preview_get"),
    _r("POST", r"/api/previews/([^/]+)/approve", "preview_approve"),
    _r("POST", r"/api/import", "import_folder"),
    _r("GET", r"/api/prefs", "prefs_get"),
    _r("PUT", r"/api/prefs", "prefs_put"),
]
STATE_CHANGING = {"POST", "PUT", "DELETE"}
OUTSIDE_LOCK = {"previews"}  # long work: runs without the operation lock, see _Guarded


class _Guarded:
    """Stands in for the session's vault or workspace while work runs outside App.lock.

    Each call takes the lock and first checks that the session is still the one the work
    started in (else VaultError). aux_put is not applied: it is recorded, and the caller
    commits the records only if the session is still the same when the work ends."""

    def __init__(self, app: "App", active: Active, target: Any, writes: list[tuple[str, bytes]] | None):
        self._app, self._active, self._target, self._writes = app, active, target, writes

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._target, name)
        if not callable(attr):
            return attr
        if name == "aux_put" and self._writes is not None:
            def record(key: str, value: bytes) -> None:
                self._writes.append((key, bytes(value)))
            return record
        if name == "aux_get" and self._writes is not None:
            def read(key: str) -> bytes | None:
                for k, v in reversed(self._writes):
                    if k == key:
                        return v
                return self._call(attr, key)
            return read

        def call(*args: Any, **kwargs: Any) -> Any:
            return self._call(attr, *args, **kwargs)
        return call

    def _call(self, attr: Callable, *args: Any, **kwargs: Any) -> Any:
        with self._app.lock:
            if self._app.active is not self._active:
                raise VaultError("archive verrouillée pendant la génération")
            return attr(*args, **kwargs)


class _DeadlineReader:
    """Reads the request straight from the socket with a total deadline.

    Before every recv the socket timeout is set to what is left of the deadline (capped
    by the per-read timeout), so a client trickling one byte at a time cannot extend the
    request line, the headers or the body beyond their deadline."""

    def __init__(self, sock: socket.socket, socket_timeout: float):
        self.sock = sock
        self.socket_timeout = socket_timeout
        self.deadline = math.inf
        self.buf = bytearray()

    def _recv(self) -> bytes:
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("request deadline exceeded")
        self.sock.settimeout(max(0.01, min(self.socket_timeout, left)))
        try:
            return self.sock.recv(65536)
        except socket.timeout:
            raise TimeoutError("request deadline exceeded") from None

    def readline(self, limit: int = -1) -> bytes:
        while True:
            nl = self.buf.find(b"\n")
            if nl >= 0 and (limit < 0 or nl < limit):
                line = bytes(self.buf[:nl + 1])
                del self.buf[:nl + 1]
                return line
            if 0 <= limit <= len(self.buf):
                line = bytes(self.buf[:limit])
                del self.buf[:limit]
                return line
            chunk = self._recv()
            if not chunk:
                line = bytes(self.buf)
                self.buf.clear()
                return line
            self.buf += chunk

    def read(self, n: int = -1) -> bytes:
        while n > len(self.buf):
            chunk = self._recv()
            if not chunk:
                break
            self.buf += chunk
        data = bytes(self.buf[:n])
        del self.buf[:n]
        return data

    def close(self) -> None:
        self.buf.clear()


class Handler(BaseHTTPRequestHandler):
    server_version = "Empreinte"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    error_content_type = "application/json; charset=utf-8"
    _active: Active | None = None
    _body_read = False

    @property
    def app(self) -> App:
        return self.server.app  # type: ignore[attr-defined]

    # ------------------------------------------------------------ plumbing
    def setup(self) -> None:
        self.timeout = self.app.options.socket_timeout
        super().setup()
        self.rfile = _DeadlineReader(self.connection, self.app.options.socket_timeout)  # type: ignore[assignment]

    def handle_expect_100(self) -> bool:
        """Refuse "Expect: 100-continue" (no browser sends it) through send_error, so the
        refusal carries the security headers like every other response."""
        self.send_error(417)
        return False

    def handle_one_request(self) -> None:
        self.rfile.deadline = time.monotonic() + self.app.options.header_deadline  # type: ignore[attr-defined]
        try:
            super().handle_one_request()
        except (ConnectionError, TimeoutError):
            self.close_connection = True  # the client went away or was too slow: just close

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        if self.app.options.log:
            path = urlsplit(self.path).path if isinstance(getattr(self, "path", None), str) else "?"
            sys.stderr.write(f"{self.command} {path[:120]} {code}\n")

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - signature of the base class
        """Silence the default logger, which would print query strings."""

    def _headers(self, status: int, ctype: str, length: int, extra: dict[str, str] | None = None) -> None:
        try:
            self.connection.settimeout(self.app.options.socket_timeout)  # reads may have shortened it
        except OSError:
            pass
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        for key, value in SECURITY_HEADERS:
            self.send_header(key, value)
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        """http.server's own errors (bad request line, unsupported method...) with our headers."""
        self.close_connection = True
        body = json.dumps({"error": "http", "message": f"erreur HTTP {code}"}).encode()
        try:
            self._headers(code, "application/json; charset=utf-8", len(body))
            if getattr(self, "command", None) != "HEAD" and code >= 200 and code not in (204, 304):
                self.wfile.write(body)
        except OSError:
            pass

    def send_json(self, status: int, payload: Any, extra: dict[str, str] | None = None) -> None:
        data = json.dumps(to_json(payload), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(data), extra)
        if self.command != "HEAD":
            self.wfile.write(data)

    def send_error_json(self, err: ApiError) -> None:
        extra = {}
        body: dict[str, Any] = {"error": err.code, "message": err.message}
        if err.retry_after is not None:
            extra["Retry-After"] = str(max(1, math.ceil(err.retry_after)))
            body["retry_after"] = round(err.retry_after, 2)
        self.send_json(err.status, body, extra)

    def _drain_small_body(self) -> bool:
        length = self.headers.get("Content-Length")
        if self.headers.get("Transfer-Encoding") or length is None or not length.strip().isdigit():
            return False
        if int(length) > self.app.options.max_body:
            return False
        self.rfile.deadline = time.monotonic() + self.app.options.body_deadline  # type: ignore[attr-defined]
        try:
            return len(self.rfile.read(int(length))) == int(length)
        except (TimeoutError, OSError):
            return False

    def _has_body(self) -> bool:
        length = self.headers.get("Content-Length")
        return bool(self.headers.get("Transfer-Encoding")) or (length is not None and length.strip() not in ("", "0"))

    # ------------------------------------------------------------ dispatch
    def do_GET(self) -> None:
        self.handle_any()

    def do_HEAD(self) -> None:
        self.handle_any()

    def do_POST(self) -> None:
        self.handle_any()

    def do_PUT(self) -> None:
        self.handle_any()

    def do_DELETE(self) -> None:
        self.handle_any()

    def do_OPTIONS(self) -> None:
        self.handle_any()

    def do_PATCH(self) -> None:
        self.handle_any()

    def handle_any(self) -> None:
        self._body_read = False
        self._token_ok = False
        try:
            self._check_host()
            parts = urlsplit(self.path)
            if parts.path.startswith("/api/") or parts.path == "/api":
                self.handle_api(parts.path, parts.query)
            else:
                if self._has_body():
                    self.close_connection = True  # never read an unexpected body
                self.handle_static(parts.path)
        except ApiError as err:
            if not self._body_read and self._has_body():
                # Without a valid page token: answer and close, never read an untrusted
                # body. With one, a small declared body is read (bounded in size and time)
                # so the page gets the answer rather than a connection reset.
                if not (self._token_ok and self._drain_small_body()):
                    self.close_connection = True
            try:
                self.send_error_json(err)
            except OSError:
                self.close_connection = True
        except (ConnectionError, TimeoutError, OSError):
            self.close_connection = True

    def _check_host(self) -> None:
        host = (self.headers.get("Host") or "").strip().lower()
        if host not in self.app.allowed_hosts:
            raise ApiError(403, "bad_host", "en-tête Host refusé")

    # ------------------------------------------------------------ static
    def handle_static(self, path: str) -> None:
        if self.command not in ("GET", "HEAD"):
            raise ApiError(405, "method", "méthode non autorisée")
        name = unquote(path).lstrip("/") or "index.html"
        if name == "index.html":
            data = self.app.index_html()
            ctype = STATIC_TYPES[".html"]
        else:
            item = self.app.static.get(name)
            data, ctype = (item[0], item[1]) if item else (None, "")
        if data is None:
            raise ApiError(404, "not_found", "fichier inconnu")
        self._headers(200, ctype, len(data))
        if self.command != "HEAD":
            self.wfile.write(data)

    # --------------------------------------------------------------- api
    def handle_api(self, path: str, query: str) -> None:
        app = self.app
        token = self.headers.get("X-Empreinte-Token") or ""
        if not hmac.compare_digest(token.encode(), app.page_token.encode()):
            raise ApiError(401, "bad_token", "jeton de page absent ou invalide")
        self._token_ok = True
        site = self.headers.get("Sec-Fetch-Site")
        if site is not None and site not in ("same-origin", "none"):
            raise ApiError(403, "cross_site", "requête d'un autre site refusée")
        method = self.command
        if method in STATE_CHANGING:
            origin = self.headers.get("Origin") or ""
            if origin.lower() not in app.allowed_origins:
                raise ApiError(403, "bad_origin", "origine refusée")
        route = None
        args: tuple[str, ...] = ()
        path_known = False
        for r_method, pattern, name, unlock in ROUTES:
            match = pattern.match(path)
            if match:
                path_known = True
                if r_method == method:
                    route = (name, unlock)
                    args = match.groups()
                    break
        if route is None:
            if path_known:
                raise ApiError(405, "method", "méthode non autorisée")
            raise ApiError(404, "no_route", "route inconnue")
        if len(query) > 2000:
            raise bad("paramètres trop longs")
        name, unlock = route
        given = self.headers.get("X-Empreinte-Unlock") or ""
        # The page token is valid here, so the body is read (bounded in size and time):
        # the page then always gets a readable answer, even "locked".
        body = self._read_body() if method in STATE_CHANGING else {}
        params = {k: v[-1] for k, v in parse_qs(query, keep_blank_values=True).items()}
        handler = getattr(self, f"api_{name}")
        try:
            if unlock and name in OUTSIDE_LOCK:
                with app.lock:
                    if app.idle_expired():
                        app.do_lock()
                    active = app.current(given)
                    if active is None:
                        raise ApiError(401, "locked", "archive verrouillée")
                    app.last_activity = time.monotonic()
                self._active = active
                result = handler(*args, params=params, body=body)
            elif unlock:
                with app.lock:
                    # Re-checked while holding the lock: the session cannot change until
                    # the handler returns.
                    if app.idle_expired():
                        app.do_lock()
                    active = app.current(given)
                    if active is None:
                        raise ApiError(401, "locked", "archive verrouillée")
                    app.last_activity = time.monotonic()
                    self._active = active
                    result = handler(*args, params=params, body=body)
            else:
                result = handler(*args, params=params, body=body)
        except ApiError:
            raise
        except WrongPassphrase:
            raise ApiError(401, "wrong_passphrase", "phrase de passe incorrecte") from None
        except NotFound:
            raise ApiError(404, "not_found", "élément introuvable") from None
        except Corrupted as exc:
            raise ApiError(500, "corrupted", f"contrôle d'intégrité en échec : {exc}") from None
        except VaultError as exc:
            raise ApiError(409, "vault_error", str(exc)[:500]) from None
        except ValidationError:
            raise bad("données refusées par le modèle") from None
        except Exception as exc:  # noqa: BLE001 - never leak details of unexpected errors
            if app.options.log:
                sys.stderr.write(f"erreur interne : {type(exc).__name__}\n")
            raise ApiError(500, "internal", "erreur interne du serveur") from None
        finally:
            self._active = None
        self.send_json(200, result)

    def _read_body(self) -> dict:
        if self.headers.get("Transfer-Encoding"):
            raise ApiError(411, "length_required", "Content-Length requis")
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise ApiError(411, "length_required", "Content-Length requis")
        if not raw_length.isdigit():
            raise bad("Content-Length invalide")
        length = int(raw_length)
        if length > self.app.options.max_body:
            raise ApiError(413, "too_large", "corps de requête trop grand")
        self.rfile.deadline = time.monotonic() + self.app.options.body_deadline  # type: ignore[attr-defined]
        try:
            data = self.rfile.read(length) if length else b""
        except TimeoutError:
            self.close_connection = True
            raise ApiError(408, "timeout", "corps de requête trop lent") from None
        self._body_read = True
        if len(data) < length:
            self.close_connection = True
            raise bad("corps de requête incomplet")
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            raise ApiError(415, "media_type", "Content-Type application/json requis")
        if not data:
            return {}
        try:
            body = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise bad("JSON invalide") from None
        if not isinstance(body, dict):
            raise bad("le corps doit être un objet JSON")
        return body

    def _vault(self) -> VaultAPI:
        assert self._active is not None
        return self._active.vault

    def _ws(self) -> WorkspaceAPI:
        assert self._active is not None
        return self._active.workspace

    # ------------------------------------------------------------ session
    def api_status(self, *, params: dict, body: dict) -> dict:
        app = self.app
        given = self.headers.get("X-Empreinte-Unlock") or ""
        with app.lock:
            if app.idle_expired():
                app.do_lock()
            active = app.current(given)
            features = app.features(active)
        try:
            exists = bool(app.session.exists())
        except Exception:  # noqa: BLE001
            exists = False
        return {
            "exists": exists,
            "unlocked": active is not None,
            "demo": app.session.demo,
            "features": features,
            "idle_timeout": app.options.idle_timeout,
            "retry_after": round(app.limiter.wait(), 2),
        }

    def _installed(self, vault: VaultAPI, workspace: WorkspaceAPI, seen: int) -> str:
        token = self.app.install(vault, workspace, seen)
        if token is None:
            raise ApiError(409, "locked_meanwhile", "l'archive a été verrouillée pendant l'ouverture")
        return token

    def api_unlock(self, *, params: dict, body: dict) -> dict:
        passphrase = req_str(body, "passphrase", min_len=1, max_len=1024)
        app = self.app
        with app.auth_lock:
            wait = app.limiter.wait()
            if wait > 0:
                raise ApiError(429, "rate_limited", "trop d'essais, patientez", retry_after=wait)
            # Close the current session before opening the vault again: a second
            # instance would find the first one's writer lock and stay read-only.
            app.do_lock()
            seen = app.generation
            try:
                vault, workspace = app.session.open_vault(passphrase)
            except WrongPassphrase:
                app.limiter.failure()
                raise ApiError(401, "wrong_passphrase", "phrase de passe incorrecte",
                               retry_after=app.limiter.wait() or None) from None
            app.limiter.success()
            token = self._installed(vault, workspace, seen)
        return {"unlock_token": token, "idle_timeout": app.options.idle_timeout}

    def api_create(self, *, params: dict, body: dict) -> dict:
        passphrase = req_str(body, "passphrase", min_len=10, max_len=1024)
        app = self.app
        with app.auth_lock:
            if app.session.exists():
                raise ApiError(409, "exists", "une archive existe déjà")
            seen = app.generation
            vault, workspace, recovery = app.session.create_vault(passphrase)
            token = self._installed(vault, workspace, seen)
        return {"unlock_token": token, "idle_timeout": app.options.idle_timeout, "recovery_key": recovery}

    def api_lock_now(self, *, params: dict, body: dict) -> dict:
        app = self.app
        given = self.headers.get("X-Empreinte-Unlock") or ""
        with app.lock:
            if app.active is None:
                app.do_lock()  # nothing open, but a pending unlock must not install afterwards
                return {"locked": True}
            if app.current(given) is None:
                raise ApiError(401, "locked", "jeton de déverrouillage requis pour verrouiller")
            app.do_lock()
        return {"locked": True}

    # ------------------------------------------------------------ entries
    def api_entries(self, *, params: dict, body: dict) -> list:
        return self._vault().entries()

    def api_entry(self, raw_id: str, *, params: dict, body: dict) -> dict:
        entry_id = entry_id_of(raw_id)
        meta = self._vault().entry(entry_id)
        ws = self._ws()
        return {"meta": meta, "parsed": ws.parsed(entry_id), "outlinks": ws.outlinks(entry_id),
                "backlinks": ws.backlinks(entry_id), "link_targets": ws.link_targets(entry_id)}

    def api_entry_text(self, raw_id: str, *, params: dict, body: dict) -> dict:
        entry_id = entry_id_of(raw_id)
        version = parse_int(params.get("version"), "version", lo=1, hi=10**9)
        meta = self._vault().entry(entry_id)
        if version is not None and version > meta.n_versions:
            raise ApiError(404, "not_found", "version inconnue")
        text = self._ws().text(entry_id, version)
        return {"entry_id": entry_id, "version": version or meta.n_versions, "media_type": meta.media_type,
                "text": text}

    def api_entry_versions(self, raw_id: str, *, params: dict, body: dict) -> list:
        return self._vault().versions(entry_id_of(raw_id))

    def api_entry_proof(self, raw_id: str, *, params: dict, body: dict) -> Any:
        version = parse_int(params.get("version"), "version", lo=1, hi=10**9)
        return self._vault().proof(entry_id_of(raw_id), version)

    def api_entry_remove(self, raw_id: str, *, params: dict, body: dict) -> dict:
        entry_id = entry_id_of(raw_id)
        if not req_bool(body, "confirm"):
            raise bad("confirmation requise")
        self._vault().remove(entry_id)
        self._ws().refresh()
        return {"removed": entry_id}

    # -------------------------------------------------------------- derived
    def api_graph(self, *, params: dict, body: dict) -> Any:
        until = parse_datetime(params.get("until"), "until")
        tags = params.get("tags", "0")
        if tags not in ("0", "1", "true", "false", ""):
            raise bad("tags doit valoir 0 ou 1")
        return self._ws().graph(until=until, tags_as_nodes=tags in ("1", "true"))

    def api_search(self, *, params: dict, body: dict) -> list:
        q = req_str(body, "q", min_len=1, max_len=300)
        limit = parse_int(body.get("limit"), "limit", lo=1, hi=200, default=30)
        if not q.strip():
            return []
        return self._ws().search(q, limit=limit)

    def api_mentions(self, *, params: dict, body: dict) -> list:
        term = req_str(body, "term", min_len=1, max_len=200)
        limit = parse_int(body.get("limit"), "limit", lo=1, hi=500, default=50)
        if not term.strip():
            return []
        return self._ws().mentions(term, limit=limit)

    def api_activity(self, *, params: dict, body: dict) -> Any:
        basis = params.get("basis") or "claimed"
        if basis not in ("claimed", "ledger"):
            raise bad("basis doit valoir claimed ou ledger")
        return self._ws().activity(basis)  # type: ignore[arg-type]

    # ---------------------------------------------------------------- ledger
    def api_ledger(self, *, params: dict, body: dict) -> dict:
        offset = parse_int(params.get("offset"), "offset", lo=0, hi=10**9, default=0)
        limit = parse_int(params.get("limit"), "limit", lo=1, hi=500, default=100)
        order = params.get("order") or "desc"
        if order not in ("asc", "desc"):
            raise bad("order doit valoir asc ou desc")
        records = self._vault().ledger()
        total = len(records)
        if order == "desc":
            records = records[::-1]
        assert offset is not None and limit is not None
        return {"total": total, "offset": offset, "limit": limit, "order": order,
                "records": records[offset:offset + limit]}

    def api_verify(self, *, params: dict, body: dict) -> Any:
        return self._vault().verify()

    def api_anchors(self, *, params: dict, body: dict) -> list:
        return self._vault().anchors()

    def api_anchor(self, *, params: dict, body: dict) -> Any:
        method = body.get("method", "rfc3161")
        available = anchor_methods_of(self._vault())
        if not isinstance(method, str) or method not in available:
            raise bad("méthode d'ancrage non disponible pour cette archive")
        if not req_bool(body, "confirm"):
            raise bad("confirmation requise : seule l'empreinte de 32 octets de la tête de chaîne est envoyée")
        return self._vault().anchor(method)  # type: ignore[arg-type]

    # ------------------------------------------------------------- licensing
    def api_licenses(self, *, params: dict, body: dict) -> list:
        return self._vault().licenses()

    def api_grant(self, *, params: dict, body: dict) -> Any:
        licensee = req_str(body, "licensee", min_len=1, max_len=200).strip()
        usage = req_str(body, "usage", min_len=1, max_len=1000).strip()
        terms = req_str(body, "terms", max_len=20000, required=False)
        if not licensee or not usage:
            raise bad("bénéficiaire et usage sont requis")
        raw_items = body.get("items")
        if not isinstance(raw_items, list) or not (1 <= len(raw_items) <= 1000):
            raise bad("items doit être une liste de 1 à 1000 éléments")
        items: list[tuple[str, int | None]] = []
        seen = set()
        for raw in raw_items:
            if not isinstance(raw, dict):
                raise bad("chaque item doit être un objet")
            entry_id = raw.get("entry_id")
            if not isinstance(entry_id, str) or not ENTRY_ID.fullmatch(entry_id):
                raise bad("entry_id invalide")
            version = parse_int(raw.get("version"), "version", lo=1, hi=10**9)
            if (entry_id, version) in seen:
                continue
            seen.add((entry_id, version))
            items.append((entry_id, version))
        royalty = None
        raw_royalty = body.get("royalty")
        if raw_royalty is not None:
            if not isinstance(raw_royalty, dict):
                raise bad("royalty doit être un objet")
            model = raw_royalty.get("model", "none")
            if model not in ("flat", "per_use", "revenue_share", "none"):
                raise bad("modèle de redevance inconnu")
            amount = parse_amount(raw_royalty.get("amount", 0), "amount", lo=0, hi=1e12)
            if model == "revenue_share" and amount > 100:
                raise bad("un partage de revenus est un pourcentage entre 0 et 100")
            currency = req_str(raw_royalty, "currency", required=False, default="EUR", max_len=3)
            if not CURRENCY.fullmatch(currency):
                raise bad("devise : trois lettres majuscules (EUR, USD...)")
            note = req_str(raw_royalty, "note", required=False, max_len=500)
            royalty = RoyaltyTerms(model=model, amount=amount, currency=currency, note=note)
        valid_until = parse_date(body.get("valid_until"), "valid_until")
        return self._vault().grant(licensee, items, usage=usage, terms=terms, royalty=royalty,
                                   valid_until=valid_until)

    def api_export(self, raw_id: str, *, params: dict, body: dict) -> dict:
        license_id = license_id_of(raw_id)
        out_dir = self.app.session.export_dir
        if out_dir is None:
            raise ApiError(404, "feature_off", "export non configuré")
        path = self._vault().export_bundle(license_id, Path(out_dir))
        grant = next((g for g in self._vault().licenses() if g.license_id == license_id), None)
        return {"license_id": license_id, "path": str(path), "bundle_hash": grant.bundle_hash if grant else ""}

    def api_royalties(self, *, params: dict, body: dict) -> list:
        raw = params.get("license_id")
        license_id = license_id_of(raw) if raw else None
        return self._vault().royalties(license_id)

    def api_record_royalty(self, *, params: dict, body: dict) -> Any:
        license_id = license_id_of(body.get("license_id"))
        amount = parse_amount(body.get("amount"), "amount", lo=-1e12, hi=1e12)
        if amount == 0:
            raise bad("le montant ne peut pas être nul")
        currency = req_str(body, "currency", required=False, default="EUR", max_len=3)
        if not CURRENCY.fullmatch(currency):
            raise bad("devise : trois lettres majuscules (EUR, USD...)")
        received_on = parse_date(body.get("received_on"), "received_on")
        period = req_str(body, "period", required=False, max_len=40)
        note = req_str(body, "note", required=False, max_len=500)
        return self._vault().record_royalty(license_id, amount, currency=currency, received_on=received_on,
                                            period=period, note=note)

    # ------------------------------------------------------- optional actions
    def api_previews(self, *, params: dict, body: dict) -> list:
        make = self.app.session.make_previews
        if make is None:
            raise ApiError(404, "feature_off", "aperçus non disponibles")
        raw = body.get("entry_ids")
        if not isinstance(raw, list) or not (1 <= len(raw) <= 50):
            raise bad("entry_ids doit être une liste de 1 à 50 identifiants")
        ids = []
        for value in raw:
            if not isinstance(value, str) or not ENTRY_ID.fullmatch(value):
                raise bad("entry_id invalide")
            ids.append(value)
        app, active = self.app, self._active
        assert active is not None
        with app.lock:
            if app.active is not active:
                raise ApiError(401, "locked", "archive verrouillée")
            for value in ids:
                active.vault.entry(value)  # NotFound before the model runs
        # The model runs without the operation lock: locking, idle lock and other
        # requests are not held up. Vault and workspace calls are checked one by one,
        # and the stored results are committed only if the session did not change.
        writes: list[tuple[str, bytes]] = []
        previews = list(make(_Guarded(app, active, active.vault, writes), _Guarded(app, active, active.workspace, None), ids))
        with app.lock:
            if app.active is not active:
                raise ApiError(409, "locked_meanwhile", "l'archive a été verrouillée pendant la génération")
            for key, value in writes:
                active.vault.aux_put(key, value)
        stored = {key[len(PREVIEW_KEY):]: value for key, value in writes if key.startswith(PREVIEW_KEY)}
        out = []
        for preview in previews:
            raw_bytes = stored.get(preview.entry_id, preview.model_dump_json().encode("utf-8"))
            out.append({**preview.model_dump(mode="json"), "current": True, "digest": preview_digest(raw_bytes)})
        return out

    def _stored_preview(self, entry_id: str) -> tuple[Preview, bool, str]:
        vault = self._vault()
        vault.entry(entry_id)
        raw = vault.aux_get(PREVIEW_KEY + entry_id)
        if raw is None:
            raise ApiError(404, "not_found", "aucun aperçu pour cette note")
        try:
            preview = Preview.model_validate_json(raw)
        except ValidationError:
            raise ApiError(404, "not_found", "aperçu illisible") from None
        latest = vault.versions(entry_id)[-1]
        current = (preview.entry_id == entry_id and preview.version == latest.version
                   and preview.commitment == latest.commitment)
        return preview, current, preview_digest(raw)

    def api_preview_get(self, raw_id: str, *, params: dict, body: dict) -> dict:
        preview, current, digest = self._stored_preview(entry_id_of(raw_id))
        return {**preview.model_dump(mode="json"), "current": current, "digest": digest}

    def api_preview_approve(self, raw_id: str, *, params: dict, body: dict) -> Any:
        """Approve exactly the preview that was displayed: the request names it by the
        digest GET or generation returned; any other stored preview is refused."""
        entry_id = entry_id_of(raw_id)
        digest = req_str(body, "digest", min_len=64, max_len=64)
        preview, current, stored_digest = self._stored_preview(entry_id)
        if not hmac.compare_digest(digest, stored_digest):
            raise ApiError(409, "changed", "l'aperçu a changé depuis son affichage : relisez-le avant de l'approuver")
        if not current:
            raise ApiError(409, "stale", "cet aperçu porte sur une ancienne version : régénérez-le")
        approved = preview.model_copy(update={"approved": True})
        raw = approved.model_dump_json().encode("utf-8")
        self._vault().aux_put(PREVIEW_KEY + entry_id, raw)
        return {**approved.model_dump(mode="json"), "current": True, "digest": preview_digest(raw)}

    def api_import_folder(self, *, params: dict, body: dict) -> dict:
        run = self.app.session.import_folder
        if run is None:
            raise ApiError(404, "feature_off", "import non disponible")
        raw = req_str(body, "path", min_len=1, max_len=1000).strip()
        path = Path(raw)
        if not path.is_absolute():
            raise bad("le chemin doit être absolu")
        if not path.is_dir():
            raise bad("ce dossier n'existe pas")
        result = run(self._vault(), self._ws(), path)
        self._ws().refresh()
        return result if isinstance(result, dict) else {"result": result}

    def api_prefs_get(self, *, params: dict, body: dict) -> dict:
        raw = self._vault().aux_get(PREFS_KEY)
        if not raw:
            return {}
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}
        return value if isinstance(value, dict) else {}

    def api_prefs_put(self, *, params: dict, body: dict) -> dict:
        data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(data) > 65536:
            raise ApiError(413, "too_large", "préférences trop grandes")
        self._vault().aux_put(PREFS_KEY, data)
        return {"saved": True}


# --------------------------------------------------------------------------- serving

def _busy_bytes() -> bytes:
    body = json.dumps({"error": "busy", "message": "trop de connexions"}).encode()
    head = ("HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json; charset=utf-8\r\n"
            + "".join(f"{k}: {v}\r\n" for k, v in SECURITY_HEADERS)
            + f"Connection: close\r\nContent-Length: {len(body)}\r\n\r\n")
    return head.encode() + body


class _HTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    app: App
    slots: threading.BoundedSemaphore

    def process_request(self, request, client_address) -> None:
        if not self.slots.acquire(blocking=False):
            try:
                request.settimeout(1.0)
                request.sendall(_busy_bytes())
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


@dataclass
class RunningServer:
    """A started server. `url` holds no secret; `shutdown()` locks the vault and stops."""

    url: str
    host: str
    port: int
    app: App
    _httpd: _HTTPServer = field(repr=False)
    _threads: list[threading.Thread] = field(default_factory=list, repr=False)

    def shutdown(self) -> None:
        self.app.stop()
        self._httpd.shutdown()
        self._httpd.server_close()
        for thread in self._threads:
            thread.join(timeout=2)


def serve(session: Session, *, host: str = "127.0.0.1", port: int = 0, open_browser: bool = False,
          allow_remote: bool = False, options: ServerOptions | None = None,
          idle_timeout: float | None = None) -> RunningServer:
    """Start the server in background threads and return it."""
    if host.lower() not in LOOPBACK_HOSTS and not allow_remote:
        raise ValueError("Empreinte n'écoute que sur la boucle locale ; passez allow_remote=True pour forcer")
    options = options or ServerOptions()
    if idle_timeout is not None:
        options.idle_timeout = idle_timeout
    app = App(session, options)
    bind_host = host.strip("[]")
    server_class = _HTTPServer
    if ":" in bind_host:

        class _V6(_HTTPServer):
            address_family = socket.AF_INET6

        server_class = _V6
    httpd = server_class((bind_host, port), Handler)
    httpd.app = app
    httpd.slots = threading.BoundedSemaphore(max(1, options.max_connections))
    real_port = httpd.server_address[1]
    app.bind(bind_host, real_port)
    url_host = f"[{bind_host}]" if ":" in bind_host else bind_host
    url = f"http://{url_host}:{real_port}/"
    t_http = threading.Thread(target=httpd.serve_forever, name="empreinte-http", daemon=True)
    t_idle = threading.Thread(target=app.idle_loop, name="empreinte-idle", daemon=True)
    t_http.start()
    t_idle.start()
    running = RunningServer(url=url, host=bind_host, port=real_port, app=app, _httpd=httpd,
                            _threads=[t_http, t_idle])
    if open_browser:
        webbrowser.open(url)
    return running


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m empreinte.server", description="Serveur local d'Empreinte")
    parser.add_argument("--demo", action="store_true", help="servir des données de démonstration en mémoire")
    parser.add_argument("--fresh", action="store_true", help="démo sans archive : montre l'écran de création")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--allow-remote", action="store_true", help="autoriser une adresse hors boucle locale")
    parser.add_argument("--open", action="store_true", help="ouvrir le navigateur")
    parser.add_argument("--idle", type=float, default=900.0, help="verrouillage après N secondes d'inactivité")
    args = parser.parse_args(argv)
    if not args.demo:
        parser.error("sans --demo, le serveur est lancé par la commande empreinte avec une vraie archive")
    from .demo import demo_session

    session = demo_session(fresh=args.fresh)
    running = serve(session, host=args.host, port=args.port, open_browser=args.open,
                    allow_remote=args.allow_remote, idle_timeout=args.idle)
    print(f"Empreinte (démo) sur {running.url}  phrase de passe : demo", flush=True)
    if session.export_dir:
        print(f"Les bundles exportés de la démo vont dans {session.export_dir}", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        running.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
