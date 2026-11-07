"""Tests for GET /api/health."""

import unittest

from fastapi.testclient import TestClient

from main import app


class HealthTest(unittest.TestCase):
    """The frontend uses /api/health to show that the backend is running."""

    def setUp(self) -> None:
        self.client = TestClient(app, base_url="http://localhost")

    def test_health_returns_ok(self) -> None:
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})


if __name__ == "__main__":
    unittest.main()
