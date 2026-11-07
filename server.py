"""Small local web server for the upload page.

POST the bytes of one Trivy JSON report to /api/parse?name=<file name> and
get back the same data as `trivy_parser.py --json` gives for that report.
Standard library only. It listens on 127.0.0.1, so only this computer can
reach it.
"""

import json
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import PurePath
from typing import Any
from urllib.parse import parse_qs, urlsplit

from trivy_parser import (
    ReportError,
    for_display,
    group_by_package,
    parse_report_bytes,
    summarize,
    to_json_entry,
)

HOST = "127.0.0.1"
PORT = 8000
MAX_UPLOAD_BYTES = 50 * 1024 * 1024


class LocalServer(ThreadingHTTPServer):
    """A ThreadingHTTPServer that refuses a port that is already in use.

    HTTPServer turns on SO_REUSEADDR. On Linux and macOS that only allows a
    quick restart; on Windows it lets a second server bind the same port,
    so uploads could reach either one.
    """

    allow_reuse_address = sys.platform != "win32"


class ParseHandler(BaseHTTPRequestHandler):
    """Answer POST /api/parse; every other address gets 404."""

    def do_POST(self) -> None:
        """Parse the uploaded report and send it back as JSON."""
        url = urlsplit(self.path)
        if url.path != "/api/parse":
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "unknown address"})
            return
        # Keep only the last part, in case a path was sent as the name.
        file_name = PurePath(parse_qs(url.query).get("name", [""])[0]).name
        try:
            size = int(self.headers.get("Content-Length", ""))
        except ValueError:
            size = -1
        if size < 0:
            self.send_json(
                HTTPStatus.LENGTH_REQUIRED,
                {"error": "the upload has no size (Content-Length)"},
            )
            return
        if size > MAX_UPLOAD_BYTES:
            self.send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                           {"error": "the file is larger than 50 MB"})
            return
        raw = self.rfile.read(size)
        try:
            report = parse_report_bytes(file_name, raw)
        except ReportError as error:
            self.send_json(HTTPStatus.UNPROCESSABLE_ENTITY,
                           {"error": str(error)})
            return
        analysed = (report, summarize(report), group_by_package(report))
        self.send_json(HTTPStatus.OK, to_json_entry(analysed))

    def send_json(self, status: HTTPStatus, body: dict[str, Any]) -> None:
        """Send one JSON response."""
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: Any) -> None:
        """Log each request with terminal control characters escaped.

        The logged address holds the uploaded file name, which anyone can
        choose. The parameter is named `format` to match the base class.
        """
        # Same layout as the standard BaseHTTPRequestHandler.log_message.
        line = (f"{self.address_string()} - - "
                f"[{self.log_date_time_string()}] {format % args}")
        sys.stderr.write(for_display(line) + "\n")


def main() -> int:
    """Start the server; return 1 if it cannot start."""
    try:
        server = LocalServer((HOST, PORT), ParseHandler)
    except OSError as error:
        reason = error.strerror or type(error).__name__
        print(f"Cannot start on {HOST}:{PORT}: {reason}", file=sys.stderr)
        return 1
    print(f"Parser API on http://{HOST}:{PORT}/api/parse (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
