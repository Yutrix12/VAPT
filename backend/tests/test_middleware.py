"""Tests for the checks every request passes: Host and Origin.

They stop other websites from using this local backend (DNS rebinding,
cross-site form posts). The Vite dev page at localhost:5173 is allowed.
"""

import unittest

from fastapi.testclient import TestClient

from app.main import app


class HostAndOriginTest(unittest.TestCase):

    def setUp(self) -> None:
        self.client = TestClient(app, base_url="http://localhost")

    def test_local_host_names_are_allowed(self) -> None:
        for host in ["localhost:8000", "127.0.0.1:8000", "localhost:5173"]:
            with self.subTest(host=host):
                response = self.client.get("/api/health",
                                           headers={"Host": host})
                self.assertEqual(response.status_code, 200)

    def test_other_host_name_is_refused(self) -> None:
        response = self.client.get("/api/health",
                                   headers={"Host": "attacker.example"})
        self.assertEqual(response.status_code, 400)

    def test_vite_page_origin_is_allowed(self) -> None:
        response = self.client.get(
            "/api/health", headers={"Origin": "http://localhost:5173"})
        self.assertEqual(response.status_code, 200)

    def test_other_origin_is_refused(self) -> None:
        response = self.client.post(
            "/api/analyze", headers={"Origin": "https://attacker.example"},
            files={"file": ("r.json", b"{}", "application/json")})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), {
            "detail": "Requests are only accepted from the local page."})


if __name__ == "__main__":
    unittest.main()
