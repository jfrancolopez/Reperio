from __future__ import annotations

import unittest

from shared.browser_normalization import normalize_browser_record, normalize_url


class BrowserNormalizationTests(unittest.TestCase):
    def test_preserves_original_url_and_derives_safe_domain_fields(self) -> None:
        normalized = normalize_url("HTTPS://Sub.Example.CO.UK/a%20b?q=1#frag")

        self.assertEqual(
            "HTTPS://Sub.Example.CO.UK/a%20b?q=1#frag", normalized["original_url_preserved"]
        )
        self.assertEqual("sub.example.co.uk", normalized["host"])
        self.assertEqual("example.co.uk", normalized["registrable_domain"])
        self.assertEqual("https://sub.example.co.uk/a%20b?q=1", normalized["canonical_url"])
        self.assertTrue(normalized["fragment_present"])
        self.assertIn("fragment_omitted_from_canonical_url", normalized["warnings"])

    def test_idn_host_uses_punycode_without_merging_origins(self) -> None:
        normalized = normalize_url("https://exämple.test/path")

        self.assertEqual("xn--exmple-cua.test", normalized["host"])
        self.assertEqual("xn--exmple-cua.test", normalized["registrable_domain"])
        self.assertIn("idn_host_punycode_display", normalized["warnings"])

    def test_malformed_and_file_urls_are_labeled_but_preserved(self) -> None:
        malformed = normalize_url("http://[bad")
        file_url = normalize_url("file:///C:/Users/Alice/report.txt")
        ipv6 = normalize_url("http://[2001:db8::1]/")
        invalid_port = normalize_url("https://example.test:bad/path")

        self.assertEqual("http://[bad", malformed["canonical_url"])
        self.assertIn("malformed_url", malformed["warnings"])
        self.assertEqual("file", file_url["scheme"])
        self.assertEqual("", file_url["host"])
        self.assertEqual("http://[2001:db8::1]", ipv6["origin"])
        self.assertEqual("2001:db8::1", ipv6["registrable_domain"])
        self.assertIn("invalid_port", invalid_port["warnings"])

    def test_default_and_non_default_ports_do_not_merge_origins(self) -> None:
        default_port = normalize_url("https://Example.test:443/path")
        non_default_port = normalize_url("https://Example.test:8443/path")

        self.assertEqual("https://example.test/path", default_port["canonical_url"])
        self.assertEqual("https://example.test:8443/path", non_default_port["canonical_url"])

    def test_visit_collapse_key_uses_canonical_url_without_merging_origins(self) -> None:
        first = normalize_browser_record(visit_record("https://Example.test:443/path#one"))
        same_origin = normalize_browser_record(visit_record("https://example.test/path#two"))
        different_origin = normalize_browser_record(visit_record("https://example.test:8443/path"))

        self.assertEqual(first["visit_collapse_key"], same_origin["visit_collapse_key"])
        self.assertNotEqual(first["visit_collapse_key"], different_origin["visit_collapse_key"])

    def test_record_timestamps_gain_local_display_without_losing_raw_epoch(self) -> None:
        record = normalize_browser_record(
            {
                "artifact_kind": "visit",
                "url": "https://example.test/?a=1&b=2",
                "visit_time": {
                    "raw_epoch": 13368163200000000,
                    "normalized_utc": "2024-09-01T05:30:00Z",
                    "display_timezone": "UTC",
                },
            }
        )

        self.assertEqual(13368163200000000, record["visit_time"]["raw_epoch"])
        self.assertEqual("2024-09-01T05:30:00Z", record["visit_time"]["local_display"])
        self.assertEqual(("a", "b"), record["url_normalization"]["query_keys"])


def visit_record(url: str) -> dict[str, object]:
    return {
        "artifact_kind": "visit",
        "profile_id": "profile-1",
        "url": url,
        "visit_time": {
            "raw_epoch": 13368163200000000,
            "normalized_utc": "2024-09-01T05:30:00Z",
            "display_timezone": "UTC",
        },
    }


if __name__ == "__main__":
    unittest.main()
