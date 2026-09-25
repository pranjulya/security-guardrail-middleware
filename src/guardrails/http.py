"""Optional authenticated HTTP adapter (loopback, private use, stdlib only)."""

from __future__ import annotations

import hmac
import json
import threading
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from .contracts import ReasonCode
from .pipeline import Pipeline

MAX_WIRE_BYTES = 17 * 1024
ADMISSION_WAIT_SECONDS = 0.05
SOCKET_TIMEOUT_SECONDS = 5

PipelineFactory = Callable[[], Pipeline]


@dataclass(frozen=True)
class ServerConfig:
    auth_token: str
    pipeline_factory: PipelineFactory
    host: str = "127.0.0.1"
    port: int = 0
    max_concurrent: int = 8

    def __post_init__(self) -> None:
        if not self.auth_token:
            raise ValueError("auth token required")
        if self.host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError("loopback host only; public hosting needs separate approval")


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = SOCKET_TIMEOUT_SECONDS
    server_version = "guardrail-inspect"
    sys_version = ""

    config: ServerConfig
    admission: threading.BoundedSemaphore
    policy_version: str

    def log_message(self, format: str, *args) -> None:
        pass

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        expected = f"Bearer {self.config.auth_token}"
        return hmac.compare_digest(header, expected)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send(200, {"status": "ready", "policy_version": self.policy_version})
        else:
            self._send(404, {"code": "NOT_FOUND"})

    def do_POST(self) -> None:
        if self.path != "/v1/inspect":
            self._send(404, {"code": "NOT_FOUND"})
            return
        if not self._authorized():
            self._send(401, {"code": "UNAUTHORIZED"})
            return
        length_header = self.headers.get("Content-Length")
        try:
            length = int(length_header) if length_header is not None else -1
        except ValueError:
            length = -1
        if length < 0:
            self._send(400, {"code": "BAD_REQUEST"})
            return
        if length > MAX_WIRE_BYTES:
            self._send(413, {"code": "BODY_TOO_LARGE"})
            return
        if not self.admission.acquire(timeout=ADMISSION_WAIT_SECONDS):
            self._send(429, {"code": "SATURATED"})
            return
        try:
            raw = self.rfile.read(length)
            try:
                data = json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                self._send(400, {"code": "BAD_JSON"})
                return
            if not isinstance(data, dict) or set(data) != {
                "boundary",
                "language",
                "text",
            }:
                self._send(400, {"code": "BAD_REQUEST"})
                return
            pipeline = self.config.pipeline_factory()
            decision = pipeline.inspect(
                {
                    "boundary": data["boundary"],
                    "language": data["language"],
                    "text": data["text"],
                    "request_id": uuid.uuid4().hex,
                    "policy_id": pipeline.policy.version,
                }
            )
            if (
                decision.action.value == "BLOCK"
                and ReasonCode.DETECTOR_ERROR in decision.reason_codes
            ):
                self._send(503, {"code": "DETECTOR_UNAVAILABLE"})
                return
            payload = decision.to_public_dict()
            if decision.safe_text is not None:
                payload["safe_text"] = decision.safe_text
            self._send(200, payload)
        except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
            pass
        finally:
            self.admission.release()


def create_server(config: ServerConfig) -> ThreadingHTTPServer:
    startup = config.pipeline_factory()

    class Handler(_Handler):
        pass

    Handler.config = config
    Handler.admission = threading.BoundedSemaphore(config.max_concurrent)
    Handler.policy_version = startup.policy.version
    server = ThreadingHTTPServer((config.host, config.port), Handler)
    server.daemon_threads = True
    return server
