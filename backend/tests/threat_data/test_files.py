"""Reading the local KEV and EPSS files: found, not listed, missing, broken."""

import gzip
import unittest
from datetime import date

from app.threat_data.files import load_threat_data
from tests.support.threat_files import ThreatDataDirCase, epss_gz, kev_json

TODAY = date(2026, 11, 12)


class FoundAndNotListedTest(ThreatDataDirCase):
    def setUp(self) -> None:
        super().setUp()
        self.write_kev(kev_json(["CVE-2021-44228", "CVE-2024-0001"]))
        self.write_epss(epss_gz({"CVE-2021-44228": "0.99999", "CVE-2023-5555": "0.01234"}))
        self.data = load_threat_data({"CVE-2021-44228", "CVE-2023-5555", "CVE-2020-1111"}, today=TODAY)

    def test_a_cve_in_the_kev_list_is_listed(self) -> None:
        threat = self.data.lookup("CVE-2021-44228")
        self.assertEqual((threat.kev, threat.epss_state, threat.epss), ("listed", "listed", 0.99999))

    def test_a_cve_with_a_score_that_is_not_in_the_kev_list_is_not_listed_there(self) -> None:
        threat = self.data.lookup("CVE-2023-5555")
        self.assertEqual((threat.kev, threat.epss_state, threat.epss), ("not_listed", "listed", 0.01234))

    def test_a_cve_in_neither_file_is_not_listed_in_both(self) -> None:
        threat = self.data.lookup("CVE-2020-1111")
        self.assertEqual((threat.kev, threat.epss_state, threat.epss), ("not_listed", "not_listed", None))

    def test_an_id_that_is_not_a_cve_is_named_so_and_is_not_called_not_listed(self) -> None:
        for vuln_id in ("GHSA-xxxx-yyyy-zzzz", "TEMP-0000000-ABCDEF", "DSA-5000-1"):
            threat = self.data.lookup(vuln_id)
            self.assertEqual((threat.kev, threat.epss_state, threat.epss), ("not_cve", "not_cve", None))

    def test_the_status_has_the_date_inside_the_data_and_its_age(self) -> None:
        self.assertEqual((self.data.kev.status, self.data.kev.as_of, self.data.kev.age_days, self.data.kev.old),
                         ("loaded", "2026-11-10", 2, False))
        self.assertEqual((self.data.epss.status, self.data.epss.as_of, self.data.epss.age_days),
                         ("loaded", "2026-11-11", 1))

    def test_data_older_than_a_week_is_marked_old(self) -> None:
        data = load_threat_data({"CVE-2021-44228"}, today=date(2026, 11, 18))
        self.assertEqual((data.kev.age_days, data.kev.old), (8, True))
        self.assertEqual((data.epss.age_days, data.epss.old), (7, False))


class MissingFilesTest(ThreatDataDirCase):
    def test_no_files_means_not_loaded_and_no_value_at_all(self) -> None:
        data = load_threat_data({"CVE-2021-44228"}, today=TODAY)
        self.assertEqual((data.kev.status, data.epss.status), ("not_loaded", "not_loaded"))
        self.assertIsNone(data.lookup("CVE-2021-44228"))  # nothing is guessed, not even "not listed"

    def test_a_missing_folder_is_the_same_as_no_files(self) -> None:
        self.data_dir.rmdir()
        data = load_threat_data({"CVE-2021-44228"}, today=TODAY)
        self.assertEqual((data.kev.status, data.epss.status), ("not_loaded", "not_loaded"))

    def test_with_only_the_kev_file_the_epss_answer_is_no_data(self) -> None:
        self.write_kev(kev_json(["CVE-2021-44228"]))
        data = load_threat_data({"CVE-2021-44228", "CVE-2020-1111"}, today=TODAY)
        self.assertEqual((data.kev.status, data.epss.status), ("loaded", "not_loaded"))
        threat = data.lookup("CVE-2020-1111")
        self.assertEqual((threat.kev, threat.epss_state, threat.epss), ("not_listed", "no_data", None))

    def test_with_only_the_epss_file_the_kev_answer_is_no_data(self) -> None:
        self.write_epss(epss_gz({"CVE-2021-44228": "0.5"}))
        threat = load_threat_data({"CVE-2021-44228"}, today=TODAY).lookup("CVE-2021-44228")
        self.assertEqual((threat.kev, threat.epss_state, threat.epss), ("no_data", "listed", 0.5))


class BrokenFilesTest(ThreatDataDirCase):
    """A broken file is a clear error on that source, never a crash and never a value."""

    def assert_error(self, source, *words: str) -> None:
        self.assertEqual(source.status, "error")
        for word in words:
            self.assertIn(word, source.error)

    def test_a_kev_file_that_is_not_json(self) -> None:
        self.write_kev(b"<html>Access denied</html>")
        data = load_threat_data({"CVE-2021-44228"}, today=TODAY)
        self.assert_error(data.kev, "KEV", "not valid JSON")
        self.assertEqual(data.epss.status, "not_loaded")
        self.assertIsNone(data.lookup("CVE-2021-44228"))

    def test_a_kev_file_with_the_wrong_shape(self) -> None:
        for raw in (b"[]", b'{"vulnerabilities": 3, "dateReleased": "2026-11-10"}',
                    b'{"vulnerabilities": [{"cveID": 5}], "dateReleased": "2026-11-10"}',
                    b'{"vulnerabilities": [], "dateReleased": "2026-11-10"}',
                    b'{"vulnerabilities": [{"cveID": "CVE-2021-44228"}], "dateReleased": "yesterday"}'):
            with self.subTest(raw=raw):
                self.write_kev(raw)
                self.assert_error(load_threat_data({"CVE-2021-44228"}, today=TODAY).kev, "KEV")

    def test_an_epss_file_that_is_not_gzip(self) -> None:
        self.write_epss(b"cve,epss,percentile\nCVE-2021-44228,0.5,0.5\n")
        self.assert_error(load_threat_data({"CVE-2021-44228"}, today=TODAY).epss, "EPSS")

    def test_an_epss_file_cut_in_the_middle(self) -> None:
        good = epss_gz({f"CVE-2021-{n:05d}": "0.5" for n in range(20000)})
        self.write_epss(good[: len(good) // 2])
        self.assert_error(load_threat_data({"CVE-2021-00001"}, today=TODAY).epss, "EPSS")

    def test_an_epss_file_with_other_columns_or_no_date_line(self) -> None:
        self.write_epss(epss_gz({"CVE-2021-44228": "0.5"}, header="cve,score,percentile"))
        self.assert_error(load_threat_data({"CVE-2021-44228"}, today=TODAY).epss, "EPSS", "columns")
        self.write_epss(gzip.compress(b"cve,epss,percentile\nCVE-2021-44228,0.5,0.5\n"))
        self.assert_error(load_threat_data({"CVE-2021-44228"}, today=TODAY).epss, "EPSS", "score_date")

    def test_an_epss_row_with_a_score_outside_0_to_1_or_not_a_number(self) -> None:
        for bad in ("1.5", "-0.1", "high", "nan", ""):
            with self.subTest(score=bad):
                self.write_epss(epss_gz({"CVE-2021-44228": "0.5", "CVE-2022-1": bad}))
                self.assert_error(load_threat_data({"CVE-2021-44228"}, today=TODAY).epss, "EPSS")

    def test_an_epss_file_with_no_rows(self) -> None:
        self.write_epss(epss_gz({}))
        self.assert_error(load_threat_data({"CVE-2021-44228"}, today=TODAY).epss, "EPSS")

    def test_a_broken_epss_file_does_not_spoil_a_good_kev_file(self) -> None:
        self.write_kev(kev_json(["CVE-2021-44228"]))
        self.write_epss(b"broken")
        data = load_threat_data({"CVE-2021-44228"}, today=TODAY)
        self.assertEqual((data.kev.status, data.epss.status), ("loaded", "error"))
        threat = data.lookup("CVE-2021-44228")
        self.assertEqual((threat.kev, threat.epss_state, threat.epss), ("listed", "no_data", None))

    def test_an_error_message_never_holds_the_file_path(self) -> None:
        self.write_kev(b"nope")
        self.assertNotIn(str(self.data_dir), load_threat_data(set(), today=TODAY).kev.error)


if __name__ == "__main__":
    unittest.main()
