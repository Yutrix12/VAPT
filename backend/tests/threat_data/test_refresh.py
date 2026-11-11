"""The hand-run refresh command, against a small local web server (no real network)."""

import contextlib
import io
import os
import threading
import unittest
from pathlib import Path
from unittest import mock
from http.server import BaseHTTPRequestHandler, HTTPServer

from app.threat_data import __main__ as command
from app.threat_data.files import EPSS_FILE, KEV_FILE, load_threat_data
from app.threat_data.refresh import SOURCES, refresh
from tests.support.threat_files import ThreatDataDirCase, epss_gz, kev_json


class FakeFeeds:
    """Serves {path: (status, bytes)} on a free local port."""

    def __init__(self, routes: dict[str, tuple[int, bytes]]) -> None:
        self.routes = routes
        self.hits: list[str] = []
        self.promise: dict[str, int] = {}
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                outer.hits.append(self.path)
                status, body = outer.routes.get(self.path, (404, b"not found"))
                self.send_response(status)
                if status in (301, 302):  # the body is the new address
                    self.send_header("Location", body.decode())
                    body = b""
                # A route can promise more bytes than it sends (a download cut short).
                promised = outer.promise.get(self.path, len(body))
                self.send_header("Content-Length", str(promised))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class RefreshTest(ThreatDataDirCase):
    def serve(self, routes: dict[str, tuple[int, bytes]]) -> FakeFeeds:
        feeds = FakeFeeds(routes)
        self.addCleanup(feeds.close)
        return feeds

    def good_routes(self) -> dict[str, tuple[int, bytes]]:
        return {"/kev.json": (200, kev_json(["CVE-2021-44228"])),
                "/epss.csv.gz": (200, epss_gz({"CVE-2021-44228": "0.9"}))}

    def run_refresh(self, feeds: FakeFeeds) -> list:
        return refresh(self.data_dir, kev_url=feeds.base + "/kev.json", epss_url=feeds.base + "/epss.csv.gz")

    def test_the_official_addresses_are_the_ones_checked_on_2026_11_11(self) -> None:
        self.assertEqual(SOURCES["kev"], "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        self.assertEqual(SOURCES["epss"], "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz")

    def test_it_downloads_both_files_into_the_data_folder_and_the_app_can_read_them(self) -> None:
        results = self.run_refresh(self.serve(self.good_routes()))
        self.assertTrue(all(result.ok for result in results), results)
        self.assertEqual(sorted(p.name for p in self.data_dir.iterdir()), sorted([EPSS_FILE, KEV_FILE]))
        data = load_threat_data({"CVE-2021-44228"})
        self.assertEqual(data.lookup("CVE-2021-44228").kev, "listed")
        self.assertEqual(data.lookup("CVE-2021-44228").epss, 0.9)

    def test_it_creates_the_data_folder_when_it_is_missing(self) -> None:
        self.data_dir.rmdir()
        self.assertTrue(all(r.ok for r in self.run_refresh(self.serve(self.good_routes()))))
        self.assertTrue((self.data_dir / KEV_FILE).is_file())

    def test_a_download_that_is_not_the_feed_is_refused_and_the_old_file_is_kept(self) -> None:
        self.write_kev(kev_json(["CVE-2020-0001"]))
        routes = self.good_routes()
        routes["/kev.json"] = (200, b"<html>maintenance</html>")
        kev, epss = self.run_refresh(self.serve(routes))
        self.assertFalse(kev.ok)
        self.assertIn("not valid JSON", kev.message)
        self.assertTrue(epss.ok)  # the other source is still refreshed
        self.assertEqual(load_threat_data(set()).kev_ids, {"CVE-2020-0001"})
        self.assertEqual([p.name for p in self.data_dir.iterdir() if p.name.endswith(".part")], [])

    def test_a_server_error_or_a_missing_page_is_a_clear_message(self) -> None:
        routes = self.good_routes()
        routes["/epss.csv.gz"] = (500, b"oops")
        kev, epss = self.run_refresh(self.serve(routes))
        self.assertTrue(kev.ok)
        self.assertFalse(epss.ok)
        self.assertIn("HTTP 500", epss.message)
        self.assertFalse((self.data_dir / EPSS_FILE).exists())

    def test_an_unreachable_server_is_a_clear_message_not_a_crash(self) -> None:
        feeds = self.serve({})
        base = feeds.base
        feeds.close()
        results = refresh(self.data_dir, kev_url=base + "/kev.json", epss_url=base + "/epss.csv.gz", timeout=2)
        self.assertEqual([r.ok for r in results], [False, False])
        self.assertIn("cannot be reached", results[0].message)

    def test_a_download_over_the_size_limit_is_refused(self) -> None:
        routes = self.good_routes()
        routes["/kev.json"] = (200, b"x" * 2000)
        feeds = self.serve(routes)
        kev, _ = refresh(self.data_dir, kev_url=feeds.base + "/kev.json", epss_url=feeds.base + "/epss.csv.gz",
                         limits={"kev": 1000, "epss": 10_000_000})
        self.assertFalse(kev.ok)
        self.assertIn("larger than", kev.message)

    def test_a_failure_while_saving_is_a_message_and_the_other_source_is_still_refreshed(self) -> None:
        real_replace = os.replace

        def busy_for_kev(source: object, target: object) -> None:
            if Path(target).name == KEV_FILE:
                raise PermissionError("the file is in use")
            real_replace(source, target)

        with mock.patch.object(os, "replace", side_effect=busy_for_kev):
            kev, epss = self.run_refresh(self.serve(self.good_routes()))
        self.assertFalse(kev.ok)
        self.assertIn("cannot be saved", kev.message)
        self.assertTrue(epss.ok)
        self.assertEqual([p.name for p in self.data_dir.iterdir() if p.name.endswith(".part")], [])

    def test_a_disk_error_is_not_called_a_network_error(self) -> None:
        real_open = Path.open

        def full_disk(path: Path, *args: object, **kwargs: object):
            if path.name.endswith(".part"):
                raise OSError("no space left on device")
            return real_open(path, *args, **kwargs)

        with mock.patch.object(Path, "open", full_disk):
            kev, _ = self.run_refresh(self.serve(self.good_routes()))
        self.assertFalse(kev.ok)
        self.assertIn("cannot be saved", kev.message)
        self.assertNotIn("reached", kev.message)

    def test_a_download_cut_short_is_a_message_not_a_crash(self) -> None:
        feeds = self.serve(self.good_routes())
        feeds.promise["/kev.json"] = 100_000
        kev, epss = self.run_refresh(feeds)
        self.assertFalse(kev.ok)
        self.assertIn("cut short", kev.message)
        self.assertTrue(epss.ok)

    def test_a_download_that_takes_too_long_is_stopped(self) -> None:
        feeds = self.serve(self.good_routes())
        kev, _ = refresh(self.data_dir, kev_url=feeds.base + "/kev.json", epss_url=feeds.base + "/epss.csv.gz", max_seconds=-1)
        self.assertFalse(kev.ok)
        self.assertIn("longer than", kev.message)

    def test_a_redirect_to_another_kind_of_address_is_refused(self) -> None:
        routes = self.good_routes()
        routes["/kev.json"] = (302, b"ftp://127.0.0.1/kev.json")
        kev, _ = self.run_refresh(self.serve(routes))
        self.assertFalse(kev.ok)
        self.assertIn("http", kev.message)

    def test_a_redirect_to_another_https_address_is_followed(self) -> None:
        routes = self.good_routes()
        routes["/moved"] = (302, b"/kev.json")
        feeds = self.serve(routes)
        kev, _ = refresh(self.data_dir, kev_url=feeds.base + "/moved", epss_url=feeds.base + "/epss.csv.gz")
        self.assertTrue(kev.ok, kev.message)

    def test_only_http_and_https_addresses_are_followed(self) -> None:
        kev, _ = refresh(self.data_dir, kev_url="file:///etc/passwd", epss_url="ftp://example.com/x")
        self.assertFalse(kev.ok)
        self.assertIn("http", kev.message)


class CommandTest(ThreatDataDirCase):
    def run_command(self, *args: str) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            return command.main(list(args)), out.getvalue()

    def test_no_arguments_prints_the_usage_and_fails(self) -> None:
        code, text = self.run_command()
        self.assertEqual(code, 2)
        self.assertIn("refresh", text)

    def test_refresh_prints_one_line_per_source_and_exits_0(self) -> None:
        feeds = FakeFeeds({"/k": (200, kev_json(["CVE-2021-44228"])), "/e": (200, epss_gz({"CVE-2021-44228": "0.9"}))})
        self.addCleanup(feeds.close)
        code, text = self.run_command("refresh", "--kev-url", feeds.base + "/k", "--epss-url", feeds.base + "/e")
        self.assertEqual(code, 0)
        self.assertIn("KEV: saved", text)
        self.assertIn("EPSS: saved", text)

    def test_refresh_exits_1_when_a_source_fails(self) -> None:
        feeds = FakeFeeds({"/k": (200, kev_json(["CVE-2021-44228"]))})
        self.addCleanup(feeds.close)
        code, text = self.run_command("refresh", "--kev-url", feeds.base + "/k", "--epss-url", feeds.base + "/e")
        self.assertEqual(code, 1)
        self.assertIn("EPSS: FAILED", text)


if __name__ == "__main__":
    unittest.main()
