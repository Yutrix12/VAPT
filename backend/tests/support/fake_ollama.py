"""A tiny fake Ollama server for the tests (standard library only).

It listens on a random local port, records every request, and answers
according to `behaviour`: "ok", "http-500", "http-404", "invalid-json",
"slow", "drip", "redirect", "chat-not-json" or "chat-no-content".
"""

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

TAGS = {"models": [{"name": "llama3.2:latest", "model": "llama3.2:latest"},
                   {"name": "qwen3:8b", "model": "qwen3:8b"}]}
CHAT_ANSWER = {"summary": "Update openssl.", "solutions": ["Upgrade"], "mitigations": [],
               "target_version": "3.5.4-1~deb13u2", "commands": [],
               "risk_notes": "none"}


class _Handler(BaseHTTPRequestHandler):
    server: "FakeOllama"

    def log_message(self, format: str, *args: Any) -> None:
        """Keep the test output quiet."""

    def _record(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        self.server.requests.append(
            {"method": self.command, "path": self.path,
             "headers": dict(self.headers), "body": body})
        return body

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _answer(self, ok_body: dict[str, Any]) -> None:
        behaviour = self.server.behaviour
        if behaviour == "slow":
            time.sleep(1)  # longer than the 0.5 s timeout the test uses
        if behaviour == "drip":
            # Headers at once, then one byte every 0.2 s: no single read
            # waits long, but the whole answer takes far too long.
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            for _ in range(100):
                self.wfile.write(b" ")
                self.wfile.flush()
                time.sleep(0.2)
        elif behaviour == "http-500":
            self._send(500, b'{"error": "model runner crashed"}')
        elif behaviour == "http-404":
            self._send(404, b'{"error": "model \'x\' not found\\u001b[31m"}')
        elif behaviour == "invalid-json":
            self._send(200, b"this is not json")
        elif behaviour == "deep-json":
            self._send(200, b"[" * 100_000)
        elif behaviour == "redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.2:9/elsewhere")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._send(200, json.dumps(ok_body).encode("utf-8"))

    def do_GET(self) -> None:
        self._record()
        self._answer(TAGS)

    def do_POST(self) -> None:
        self._record()
        content: Any = json.dumps(self.server.chat_answer)
        if self.server.behaviour == "chat-not-json":
            content = "Sure! Here is my advice: upgrade."
        elif self.server.behaviour == "chat-no-content":
            content = None
        self._answer({"model": "llama3.2:latest", "done": True,
                      "message": {"role": "assistant", "content": content}})


class FakeOllama(ThreadingHTTPServer):
    """Start with `with FakeOllama("ok") as fake:`; use `fake.base_url`."""

    # Do not wait for a deliberately slow handler when the test is done.
    daemon_threads = True
    block_on_close = False

    def __init__(self, behaviour: str = "ok",
                 chat_answer: dict[str, Any] | None = None) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.behaviour = behaviour
        self.chat_answer = CHAT_ANSWER if chat_answer is None else chat_answer
        self.requests: list[dict[str, Any]] = []
        self.base_url = f"http://127.0.0.1:{self.server_address[1]}"
        # serve_forever checks for shutdown every poll_interval (default
        # 0.5 s); a short one keeps each test fast.
        self._thread = threading.Thread(target=self.serve_forever,
                                        kwargs={"poll_interval": 0.01},
                                        daemon=True)

    def handle_error(self, request: Any, client_address: Any) -> None:
        """Stay quiet when a test client hangs up on purpose (timeouts)."""
        if not isinstance(sys.exc_info()[1], ConnectionError):
            super().handle_error(request, client_address)

    def __enter__(self) -> "FakeOllama":
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.shutdown()
        self.server_close()
