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
* Every response carries ``Cache-Control: no-store``,
  ``X-Content-Type-Options: nosniff`` and ``X-Request-Id``; 401 carries
  ``WWW-Authenticate: Bearer`` (L3).
* The token must be >= 32 characters with no whitespace/control characters;
  ``python -m guardrails.http`` reads it from ``GUARDRAIL_TOKEN_FILE`` or
  ``GUARDRAIL_TOKEN``, never from code or argv (L3).
* Non-string envelope fields -> 400; any ``Transfer-Encoding`` -> 400 (no
  CL/TE ambiguity behind proxies) (L3).
* Optional content-free ``event_sink`` receives inspection audit events and one
  ``http_access`` event per request; ``shutdown_gracefully()`` drains
  in-flight requests (L3).
"""

from __future__ import annotations

import argparse
import hmac
import json
import logging
import os
import signal
import socket
import sys
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .contracts import ReasonCode
from .pipeline import EventSink, Pipeline

MAX_WIRE_BYTES = 17 * 1024
ADMISSION_WAIT_SECONDS = 0.05
SOCKET_TIMEOUT_SECONDS = 5
READ_DEADLINE_SECONDS = 10.0
MAX_CONNECTIONS = 32
MIN_TOKEN_CHARS = 32
AUTH_ENV_VAR = "GUARDRAIL_TOKEN"
AUTH_FILE_ENV_VAR = "GUARDRAIL_TOKEN_FILE"
_ROUTES = ("/v1/inspect", "/healthz")

PipelineFactory = Callable[[], Pipeline]

_LOG = logging.getLogger("guardrails.http")
_REJECT_RESPONSE = (
    b"HTTP/1.1 503 Service Unavailable\r\n"
    b"Content-Type: application/json\r\n"
    b"Cache-Control: no-store\r\n"
    b"X-Content-Type-Options: nosniff\r\n"
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
    #: Content-free audit sink: receives the pipeline's inspection events and
    #: one ``http_access`` event per request. A failing sink turns inspection
    #: into 503 AUDIT_UNAVAILABLE (fail closed).
    event_sink: EventSink | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.auth_token, str) or not self.auth_token:
            raise ValueError("auth token required")
        if len(self.auth_token) < MIN_TOKEN_CHARS:
            raise ValueError(f"auth token must be at least {MIN_TOKEN_CHARS} characters")
        if any(c.isspace() or not c.isprintable() for c in self.auth_token):
            raise ValueError("auth token must not contain whitespace or control characters")
        if type(self.max_concurrent) is not int or type(self.max_connections) is not int:
            raise ValueError("max_concurrent and max_connections must be ints")
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
        self.draining = False
        self._active = 0
        self._active_cond = threading.Condition()
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
        with self._active_cond:
            self._active += 1
        try:
            super().process_request(request, client_address)
        except Exception:
            self._connection_slots.release()
            self._done()
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()
            self._done()

    def _done(self) -> None:
        with self._active_cond:
            self._active -= 1
            self._active_cond.notify_all()

    @property
    def active_connections(self) -> int:
        with self._active_cond:
            return self._active

    def shutdown_gracefully(self, timeout: float = 10.0) -> bool:
        """Stop accepting, let in-flight requests finish, then close.

        Must be called from a thread other than the one running
        ``serve_forever``. New requests on already-accepted connections get 503
        while draining. Returns True if every in-flight request finished within
        ``timeout`` seconds (remaining daemon threads are abandoned otherwise).
        """
        self.draining = True
        self.ready = False
        self.shutdown()
        deadline = time.monotonic() + max(0.0, timeout)
        with self._active_cond:
            while self._active > 0:
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                self._active_cond.wait(left)
            drained = self._active == 0
        self.server_close()
        return drained

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
    _request_id: str = ""
    _started: float = 0.0
    _status: int = 0

    def log_message(self, format: str, *args: Any) -> None:
        pass

    # -- connection lifecycle -------------------------------------------------
    def setup(self) -> None:
        super().setup()
        self.deadline_expired = False
        self._request_id = uuid.uuid4().hex
        self._started = time.monotonic()
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
        self._access_event()

    def _access_event(self) -> None:
        sink = self.config.event_sink
        if sink is None or not self._status:
            return
        method = self.command if self.command in ("GET", "POST") else "other"
        path = (self.path or "").split("?", 1)[0]
        try:
            sink(
                {
                    "event": "http_access",
                    "request_id": self._request_id,
                    "method": method,
                    "route": path if path in _ROUTES else "other",
                    "status": int(self._status),
                    "elapsed_ms": int((time.monotonic() - self._started) * 1000),
                }
            )
        except Exception:  # noqa: BLE001 - access log is best effort; audit is not
            _LOG.error("guardrail-http: access event sink failed")

    def send_response(self, code: int, message: str | None = None) -> None:
        self._status = code
        super().send_response(code, message)

    def end_headers(self) -> None:
        # Applied to every response, including BaseHTTPRequestHandler errors.
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if self._request_id:
            self.send_header("X-Request-Id", self._request_id)
        super().end_headers()

    # -- helpers --------------------------------------------------------------
    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        if status == 401:
            self.send_header("WWW-Authenticate", 'Bearer realm="guardrail"')
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
        except Exception:  # noqa: BLE001 - fail closed: always answer
            if self.deadline_expired:
                self.close_connection = True
            else:
                _LOG.error("guardrail-http: internal error %s", type(sys.exc_info()[1]).__name__)
                self._send_safely(500, {"code": "INTERNAL_ERROR"})

    def _do_post(self) -> None:
        if getattr(self.server, "draining", False):
            self._end_read_phase()
            self._send_safely(503, {"code": "SHUTTING_DOWN"})
            return
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
        # Any Transfer-Encoding (alone or with Content-Length) is refused: only
        # a single, unambiguous Content-Length framing is accepted.
        if self.headers.get("Transfer-Encoding") is not None or (
            len(self.headers.get_all("Content-Length") or []) > 1
        ):
            self._end_read_phase()
            self._send_safely(400, {"code": "BAD_REQUEST"})
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
            if not isinstance(value, str):  # LLD: wrong field type is a 400
                self._send_safely(400, {"code": "BAD_REQUEST"})
                return
            try:
                value.encode("utf-8")
            except UnicodeEncodeError:  # e.g. escaped lone surrogate "\ud800"
                self._send_safely(400, {"code": "BAD_JSON"})
                return
        pipeline = self.config.pipeline_factory()
        if self.config.event_sink is not None and pipeline.event_sink is None:
            pipeline.event_sink = self.config.event_sink
        request_id = self._request_id
        try:
            decision = pipeline.inspect(
                {
                    "boundary": data["boundary"],
                    "language": data["language"],
                    "text": data["text"],
                    "request_id": request_id,
                    "policy_id": pipeline.policy.policy_id,
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
        payload["request_id"] = request_id
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
        except Exception:  # noqa: BLE001 - fail closed: always answer
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


def load_token(environ: Any = None) -> str:
    """Read the bearer token from GUARDRAIL_TOKEN_FILE (preferred) or GUARDRAIL_TOKEN."""
    env = os.environ if environ is None else environ
    path = env.get(AUTH_FILE_ENV_VAR)
    if path:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    token = env.get(AUTH_ENV_VAR, "")
    if not token:
        raise ValueError(f"set {AUTH_FILE_ENV_VAR} or {AUTH_ENV_VAR}")
    return str(token)


def _stderr_audit_sink(event: dict[str, Any]) -> None:
    logging.getLogger("guardrails.audit").info(json.dumps(event, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    """``python -m guardrails.http``: loopback server, token from the environment."""
    parser = argparse.ArgumentParser(prog="python -m guardrails.http")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--max-concurrent", type=int, default=8)
    parser.add_argument("--drain-seconds", type=float, default=10.0)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stderr)
    try:
        token = load_token()
    except (OSError, ValueError) as exc:
        print(f"guardrails.http: {type(exc).__name__}: token not configured", file=sys.stderr)
        return 2
    from .policy import DEFAULT_POLICY, load_policy

    policy = load_policy(DEFAULT_POLICY)

    def factory() -> Pipeline:
        return Pipeline.from_policy(policy)

    try:
        config = ServerConfig(
            auth_token=token,
            pipeline_factory=factory,
            host=args.host,
            port=args.port,
            max_concurrent=args.max_concurrent,
            max_connections=max(MAX_CONNECTIONS, args.max_concurrent),
            event_sink=_stderr_audit_sink,
        )
    except ValueError as exc:
        print(f"guardrails.http: invalid configuration: {exc}", file=sys.stderr)
        return 2
    server = create_server(config)
    stop = threading.Event()

    def _on_signal(signum: int, frame: Any) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)
    thread = threading.Thread(target=server.serve_forever, name="guardrail-http", daemon=True)
    thread.start()
    print(
        f"guardrails.http listening on {args.host}:{server.server_address[1]} ready={server.ready}",
        file=sys.stderr,
        flush=True,
    )
    stop.wait()
    drained = server.shutdown_gracefully(args.drain_seconds)
    return 0 if drained else 1


if __name__ == "__main__":
    raise SystemExit(main())
