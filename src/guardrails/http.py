"""Optional authenticated HTTP adapter (loopback, private use, stdlib only).

Hardening (review 02):

* Authorization is compared as bytes, so non-ASCII headers get 401, not a crash.
* Every request gets a response: malformed JSON / unencodable strings -> 400,
  unexpected errors -> 500 with a stable code, never a dropped connection.
* A total read deadline (headers + body) is enforced by a watchdog that shuts
  the socket down, independent of the per-``recv`` socket timeout, so
  slow-header / slow-body clients cannot hold a connection indefinitely.
* The request body is read *before* taking a processing (admission) slot, so
  slow clients cannot starve the detector pool.
* The number of open connections (and therefore handler threads) is capped
  before authentication; excess connections receive 503 and are closed.
"""

from __future__ import annotations

import hmac
import json
import logging
import socket
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from .contracts import ReasonCode
from .pipeline import Pipeline

MAX_WIRE_BYTES = 17 * 1024
ADMISSION_WAIT_SECONDS = 0.05
SOCKET_TIMEOUT_SECONDS = 5
READ_DEADLINE_SECONDS = 10.0
MAX_CONNECTIONS = 32

PipelineFactory = Callable[[], Pipeline]

_LOG = logging.getLogger("guardrails.http")
_REJECT_RESPONSE = (
    b"HTTP/1.1 503 Service Unavailable\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: 24\r\n"
    b"Connection: close\r\n\r\n"
    b'{"code": "OVERLOADED"}\r\n'
)


@dataclass(frozen=True)
class ServerConfig:
    auth_token: str
    pipeline_factory: PipelineFactory
    host: str = "127.0.0.1"
    port: int = 0
    max_concurrent: int = 8
    warm_up: bool = True
    max_connections: int = MAX_CONNECTIONS
    read_deadline_seconds: float = READ_DEADLINE_SECONDS

    def __post_init__(self) -> None:
        if not self.auth_token:
            raise ValueError("auth token required")
        if self.host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError("loopback host only; public hosting needs separate approval")
        if self.max_concurrent <= 0 or self.max_connections <= 0:
            raise ValueError("max_concurrent and max_connections must be positive")
        if self.max_connections < self.max_concurrent:
            raise ValueError("max_connections must be >= max_concurrent")
        if not self.read_deadline_seconds > 0:
            raise ValueError("read_deadline_seconds must be positive")


class _Watchdog:
    """Shuts down sockets whose total read deadline has passed."""

    def __init__(self) -> None:
        self._entries: dict[int, tuple[float, socket.socket, Any]] = {}
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stopped = False
        self._next = 0
        self._thread = threading.Thread(target=self._run, name="guardrail-watchdog", daemon=True)
        self._thread.start()

    def register(self, sock: socket.socket, deadline: float, owner: Any) -> int:
        with self._lock:
            self._next += 1
            token = self._next
            self._entries[token] = (deadline, sock, owner)
        self._wake.set()
        return token

    def cancel(self, token: int | None) -> None:
        if token is None:
            return
        with self._lock:
            self._entries.pop(token, None)

    def stop(self) -> None:
        self._stopped = True
        self._wake.set()

    def _run(self) -> None:
        while not self._stopped:
            now = time.monotonic()
            expired = []
            with self._lock:
                for token, (deadline, sock, owner) in list(self._entries.items()):
                    if deadline <= now:
                        expired.append((sock, owner))
                        del self._entries[token]
                upcoming = min((d for d, _, _ in self._entries.values()), default=now + 0.5)
            for sock, owner in expired:
                owner.deadline_expired = True
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            self._wake.wait(timeout=max(0.01, min(0.5, upcoming - time.monotonic())))
            self._wake.clear()


class GuardrailHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a connection cap, read watchdog and readiness."""

    daemon_threads = True
    ready: bool = False
    warm_up_ms: int | None = None

    def __init__(
        self,
        server_address: Any,
        handler: type[BaseHTTPRequestHandler],
        *,
        max_connections: int = MAX_CONNECTIONS,
        read_deadline_seconds: float = READ_DEADLINE_SECONDS,
    ) -> None:
        self.read_deadline_seconds = read_deadline_seconds
        self.rejected_connections = 0
        self._connection_slots = threading.BoundedSemaphore(max_connections)
        self.watchdog = _Watchdog()
        super().__init__(server_address, handler)

    def process_request(self, request: Any, client_address: Any) -> None:
        # Cap connections (== handler threads) before any bytes are parsed or
        # the client is authenticated.
        if not self._connection_slots.acquire(blocking=False):
            self.rejected_connections += 1
            try:
                request.settimeout(0.2)
                request.sendall(_REJECT_RESPONSE)
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._connection_slots.release()
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()

    def handle_error(self, request: Any, client_address: Any) -> None:
        # Content-free: never print tracebacks (which may quote request data).
        exc = sys.exc_info()[1]
        _LOG.error("guardrail-http: unhandled %s", type(exc).__name__ if exc else "error")

    def server_close(self) -> None:
        self.watchdog.stop()
        super().server_close()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = SOCKET_TIMEOUT_SECONDS
    server_version = "guardrail-inspect"
    sys_version = ""
    error_content_type = "application/json"
    error_message_format = '{"code": "HTTP_%(code)d"}'

    config: ServerConfig
    admission: threading.BoundedSemaphore
    policy_version: str
    server: GuardrailHTTPServer

    deadline_expired = False
    _watch_token: int | None = None

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass

    # -- connection lifecycle -------------------------------------------------
    def setup(self) -> None:
        super().setup()
        self.deadline_expired = False
        self._watch_token = self.server.watchdog.register(
            self.connection, time.monotonic() + self.server.read_deadline_seconds, self
        )

    def _end_read_phase(self) -> None:
        self.server.watchdog.cancel(self._watch_token)
        self._watch_token = None

    def handle(self) -> None:
        try:
            super().handle()
        except OSError:
            if not self.deadline_expired:
                raise

    def finish(self) -> None:
        self._end_read_phase()
        try:
            super().finish()
        except OSError:
            pass

    # -- helpers --------------------------------------------------------------
    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _send_safely(self, status: int, payload: dict[str, Any]) -> None:
        try:
            self._send(status, payload)
        except OSError:
            self.close_connection = True

    def _authorized(self) -> bool:
        # Header values are decoded as latin-1 by http.client; compare bytes so
        # non-ASCII input can never raise (hmac.compare_digest rejects non-ASCII str).
        header = self.headers.get("Authorization", "").encode("latin-1", "replace")
        expected = b"Bearer " + self.config.auth_token.encode("utf-8")
        return hmac.compare_digest(header, expected)

    def _ready(self) -> bool:
        return bool(getattr(self.server, "ready", False))

    # -- routes -----------------------------------------------------------------
    def do_GET(self) -> None:
        self._end_read_phase()
        if self.path == "/healthz":
            if self._ready():
                self._send_safely(200, {"status": "ready", "policy_version": self.policy_version})
            else:
                self._send_safely(
                    503, {"status": "starting", "policy_version": self.policy_version}
                )
        else:
            self._send_safely(404, {"code": "NOT_FOUND"})

    def do_POST(self) -> None:
        try:
            self._do_post()
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            self.close_connection = True
        except Exception:
            if self.deadline_expired:
                self.close_connection = True
            else:
                _LOG.error("guardrail-http: internal error %s", type(sys.exc_info()[1]).__name__)
                self._send_safely(500, {"code": "INTERNAL_ERROR"})

    def _do_post(self) -> None:
        if self.path != "/v1/inspect":
            self._end_read_phase()
            self._send_safely(404, {"code": "NOT_FOUND"})
            return
        if not self._authorized():
            self._end_read_phase()
            self._send_safely(401, {"code": "UNAUTHORIZED"})
            return
        if not self._ready():
            self._end_read_phase()
            self._send_safely(503, {"code": "NOT_READY"})
            return
        length_header = self.headers.get("Content-Length")
        try:
            length = int(length_header) if length_header is not None else -1
        except ValueError:
            length = -1
        if length < 0:
            self._end_read_phase()
            self._send_safely(400, {"code": "BAD_REQUEST"})
            return
        if length > MAX_WIRE_BYTES:
            self._end_read_phase()
            self._send_safely(413, {"code": "BODY_TOO_LARGE"})
            return
        # Read the whole body under the total read deadline *before* taking an
        # admission slot, so slow clients cannot occupy detector capacity.
        raw = self.rfile.read(length)
        if self.deadline_expired or len(raw) < length:
            self.close_connection = True
            return
        self._end_read_phase()
        if not self.admission.acquire(timeout=ADMISSION_WAIT_SECONDS):
            self._send_safely(429, {"code": "SATURATED"})
            return
        try:
            self._inspect(raw)
        finally:
            self.admission.release()

    def _inspect(self, raw: bytes) -> None:
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeDecodeError, RecursionError):
            self._send_safely(400, {"code": "BAD_JSON"})
            return
        if not isinstance(data, dict) or set(data) != {"boundary", "language", "text"}:
            self._send_safely(400, {"code": "BAD_REQUEST"})
            return
        for value in data.values():
            if isinstance(value, str):
                try:
                    value.encode("utf-8")
                except UnicodeEncodeError:  # e.g. escaped lone surrogate "\ud800"
                    self._send_safely(400, {"code": "BAD_JSON"})
                    return
        pipeline = self.config.pipeline_factory()
        request_id = uuid.uuid4().hex
        try:
            decision = pipeline.inspect(
                {
                    "boundary": data["boundary"],
                    "language": data["language"],
                    "text": data["text"],
                    "request_id": request_id,
                    "policy_id": pipeline.policy.version,
                }
            )
        finally:
            pipeline.end_request(request_id)
        if decision.action.value == "BLOCK":
            if ReasonCode.DETECTOR_ERROR in decision.reason_codes:
                self._send_safely(503, {"code": "DETECTOR_UNAVAILABLE"})
                return
            if ReasonCode.AUDIT_ERROR in decision.reason_codes:
                self._send_safely(503, {"code": "AUDIT_UNAVAILABLE"})
                return
        payload = decision.to_public_dict()
        if decision.safe_text is not None:
            payload["safe_text"] = decision.safe_text
        self._send_safely(200, payload)


def create_server(config: ServerConfig) -> GuardrailHTTPServer:
    """Build the server; warm the detector *before* reporting ready.

    With ``config.warm_up`` (default) the model is loaded and exercised once
    here, so the first request is not blocked by cold-start latency. If warm-up
    fails the server still binds but ``/healthz`` and ``/v1/inspect`` answer 503
    until the process is restarted (fail closed, visible to supervisors).
    """
    startup = config.pipeline_factory()
    ready = True
    warm_up_ms: int | None = None
    if config.warm_up:
        try:
            warm_up_ms = startup.warm_up()
        except Exception:
            ready = False

    class Handler(_Handler):
        pass

    Handler.config = config
    Handler.admission = threading.BoundedSemaphore(config.max_concurrent)
    Handler.policy_version = startup.policy.version
    server = GuardrailHTTPServer(
        (config.host, config.port),
        Handler,
        max_connections=config.max_connections,
        read_deadline_seconds=config.read_deadline_seconds,
    )
    server.warm_up_ms = warm_up_ms
    server.ready = ready
    return server
