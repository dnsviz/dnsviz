import unittest

import dns.name
import dns.rdatatype

from dnsviz.analysis.offline import OfflineDomainNameAnalysis


class _Query:
    """Just enough of a query for the code under test: one NODATA response, no NXDOMAIN."""
    def __init__(self):
        self.nodata_info = [object()]
        self.nxdomain_info = []


class InconsistentNegativeResponsesTestCase(unittest.TestCase):
    def test_zone_negative_status_not_yet_populated(self):
        # A CNAME target that lives inside its own zone is populated while that zone is
        # still being populated, so the zone's negative status has not been computed yet.
        zone = OfflineDomainNameAnalysis(dns.name.from_text('example.com.'))
        zone.has_ns = True
        zone.queries = {(dns.name.from_text('example.com.'), dns.rdatatype.A): _Query()}
        self.assertIsNone(zone.nodata_status)
        self.assertIsNone(zone.nxdomain_status)

        name = OfflineDomainNameAnalysis(dns.name.from_text('www.example.com.'))
        name.parent = zone
        self.assertFalse(name.is_zone())
        self.assertIs(name.zone, zone)

        # Used to raise TypeError: 'NoneType' object is not subscriptable
        name._populate_inconsistent_negative_dnssec_responses_all(False)


if __name__ == '__main__':
    unittest.main()
