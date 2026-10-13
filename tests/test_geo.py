"""Geo blocklist loading."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import botgate_proxy as botgate


class GeoFileTests(unittest.TestCase):
    def test_ipv6_ranges_are_skipped_not_fatal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mixed.txt"
            path.write_text("deny from 203.0.113.0/24\n"
                            "deny from 2001:db8::/32\n"
                            "deny from 198.51.100.0/24\n")
            with self.assertLogs(botgate.log, level="WARNING") as logs:
                starts, ends = botgate.load_geo_file(str(path))
        self.assertEqual(len(starts), 2)
        for ip in ["203.0.113.7", "198.51.100.200"]:
            self.assertTrue(botgate.geo_range_contains(int(botgate.ipaddress.ip_address(ip)), starts, ends), ip)
        self.assertFalse(botgate.geo_range_contains(int(botgate.ipaddress.ip_address("192.0.2.1")), starts, ends))
        self.assertTrue(any("1 IPv6 range" in line for line in logs.output), logs.output)


if __name__ == "__main__":
    unittest.main()
