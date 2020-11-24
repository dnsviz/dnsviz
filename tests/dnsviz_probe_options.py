# -*- coding: utf-8 -*-

import argparse
import binascii
import gzip
import logging
import os
import subprocess
import tempfile
import unittest

import dns.name, dns.rdatatype, dns.rrset, dns.zone

from dnsviz.commands.probe import ZoneFileToServe, ArgHelper, DomainListArgHelper, StandardRecursiveQueryCD, WILDCARD_EXPLICIT_DELEGATION, AnalysisInputError, CustomQueryMixin
from dnsviz import transport
from dnsviz.resolver import Resolver
from dnsviz.ipaddr import IPAddr

DATA_DIR = os.path.dirname(__file__)
EXAMPLE_COM_ZONE = os.path.join(DATA_DIR, 'zone', 'example.com.zone')
EXAMPLE_COM_DELEGATION = os.path.join(DATA_DIR, 'zone', 'example.com.zone-delegation')
EXAMPLE_AUTHORITATIVE = os.path.join(DATA_DIR, 'data', 'example-authoritative.json.gz')

class DNSVizProbeOptionsTestCase(unittest.TestCase):
    def setUp(self):
        self.tm = transport.DNSQueryTransportManager()
        self.resolver = Resolver.from_file('/etc/resolv.conf', StandardRecursiveQueryCD, transport_manager=self.tm)
        self.helper = DomainListArgHelper(self.resolver)
        self.logger = logging.getLogger()
        for handler in self.logger.handlers:
            self.logger.removeHandler(handler)
        self.logger.addHandler(logging.NullHandler())
        try:
            ArgHelper.bindable_ip('::1')
        except argparse.ArgumentTypeError:
            self.use_ipv6 = False
        else:
            self.use_ipv6 = True
        self.first_port = ZoneFileToServe._next_free_port
        self.custom_query_mixin_edns_options_orig = CustomQueryMixin.edns_options[:]

    def tearDown(self):
        CustomQueryMixin.edns_options = self.custom_query_mixin_edns_options_orig[:]
        if self.tm is not None:
            self.tm.close()

    def test_authoritative_option(self):
        arg1 = 'example.com+:ns1.example.com=192.0.2.1:1234,ns1.example.com=[2001:db8::1],' + \
                'ns1.example.com=192.0.2.2,ns2.example.com=[2001:db8::2],a.root-servers.net,192.0.2.3'

        arg1_with_spaces = ' example.com+ : ns1.example.com = [192.0.2.1]:1234 , ns1.example.com = [2001:db8::1], ' + \
                'ns1.example.com = [192.0.2.2] , ns2.example.com = [2001:db8::2] , a.root-servers.net , 192.0.2.3 '

        arg2 = 'example.com:ns1.example.com=192.0.2.1'

        arg3 = 'example.com:%s' % EXAMPLE_COM_ZONE

        arg4 = 'example.com+:%s' % EXAMPLE_COM_ZONE

        delegation_mapping1 = {
                (dns.name.from_text('example.com'), dns.rdatatype.NS):
                        dns.rrset.from_text_list(dns.name.from_text('example.com'), 0, dns.rdataclass.IN, dns.rdatatype.NS,
                            ['ns1.example.com', 'ns2.example.com', 'a.root-servers.net', 'ns1._dnsviz.example.com']),
                (dns.name.from_text('ns1.example.com'), dns.rdatatype.A):
                        dns.rrset.from_text_list(dns.name.from_text('ns1.example.com'), 0, dns.rdataclass.IN, dns.rdatatype.A,
                            ['192.0.2.1', '192.0.2.2']),
                (dns.name.from_text('ns1.example.com'), dns.rdatatype.AAAA):
                        dns.rrset.from_text_list(dns.name.from_text('ns1.example.com'), 0, dns.rdataclass.IN, dns.rdatatype.AAAA,
                            ['2001:db8::1']),
                (dns.name.from_text('ns1._dnsviz.example.com'), dns.rdatatype.A):
                        dns.rrset.from_text_list(dns.name.from_text('ns1._dnsviz.example.com'), 0, dns.rdataclass.IN, dns.rdatatype.A,
                            ['192.0.2.3']),
                (dns.name.from_text('ns2.example.com'), dns.rdatatype.AAAA):
                        dns.rrset.from_text_list(dns.name.from_text('ns2.example.com'), 0, dns.rdataclass.IN, dns.rdatatype.AAAA,
                            ['2001:db8::2']),
                (dns.name.from_text('a.root-servers.net'), dns.rdatatype.A):
                        dns.rrset.from_text_list(dns.name.from_text('a.root-servers.net'), 0, dns.rdataclass.IN, dns.rdatatype.A,
                            ['198.41.0.4']),
                (dns.name.from_text('a.root-servers.net'), dns.rdatatype.AAAA):
                        dns.rrset.from_text_list(dns.name.from_text('a.root-servers.net'), 0, dns.rdataclass.IN, dns.rdatatype.AAAA,
                            ['2001:503:ba3e::2:30'])
                }
        stop_at1 = True
        odd_ports1 = { (dns.name.from_text('example.com'), IPAddr('192.0.2.1')): 1234 }
        zone_filename1 = None

        delegation_mapping2 = {
                (dns.name.from_text('example.com'), dns.rdatatype.NS):
                        dns.rrset.from_text_list(dns.name.from_text('example.com'), 0, dns.rdataclass.IN, dns.rdatatype.NS,
                            ['ns1.example.com']),
                (dns.name.from_text('ns1.example.com'), dns.rdatatype.A):
                        dns.rrset.from_text_list(dns.name.from_text('ns1.example.com'), 0, dns.rdataclass.IN, dns.rdatatype.A,
                            ['192.0.2.1'])
                }
        stop_at2 = False
        odd_ports2 = {}
        zone_filename2 = None

        delegation_mapping3 = {
                (dns.name.from_text('example.com'), dns.rdatatype.NS):
                        dns.rrset.from_text_list(dns.name.from_text('example.com'), 0, dns.rdataclass.IN, dns.rdatatype.NS,
                            []),
                }
        stop_at3 = False
        odd_ports3 = {}
        zone_filename3 = EXAMPLE_COM_ZONE

        delegation_mapping4 = {
                (dns.name.from_text('example.com'), dns.rdatatype.NS):
                        dns.rrset.from_text_list(dns.name.from_text('example.com'), 0, dns.rdataclass.IN, dns.rdatatype.NS,
                            []),
                }
        stop_at4 = True
        odd_ports4 = {}
        zone_filename4 = EXAMPLE_COM_ZONE

        obj = self.helper.authoritative_name_server_mappings(arg1)
        self.assertEqual(obj.domain, dns.name.from_text('example.com'))
        self.assertEqual(obj.delegation_mapping, delegation_mapping1)
        self.assertEqual(obj.stop_at, stop_at1)
        self.assertEqual(obj.odd_ports, odd_ports1)
        self.assertEqual(obj.filename, zone_filename1)

        obj = self.helper.authoritative_name_server_mappings(arg1_with_spaces)
        self.assertEqual(obj.domain, dns.name.from_text('example.com'))
        self.assertEqual(obj.delegation_mapping, delegation_mapping1)
        self.assertEqual(obj.stop_at, stop_at1)
        self.assertEqual(obj.odd_ports, odd_ports1)
        self.assertEqual(obj.filename, zone_filename1)

        obj = self.helper.authoritative_name_server_mappings(arg2)
        self.assertEqual(obj.domain, dns.name.from_text('example.com'))
        self.assertEqual(obj.delegation_mapping, delegation_mapping2)
        self.assertEqual(obj.stop_at, stop_at2)
        self.assertEqual(obj.odd_ports, odd_ports2)
        self.assertEqual(obj.filename, zone_filename2)

        obj = self.helper.authoritative_name_server_mappings(arg3)
        self.assertEqual(obj.domain, dns.name.from_text('example.com'))
        self.assertEqual(obj.delegation_mapping, delegation_mapping3)
        self.assertEqual(obj.stop_at, stop_at3)
        self.assertEqual(obj.odd_ports, odd_ports3)
        self.assertEqual(obj.filename, zone_filename3)

        obj = self.helper.authoritative_name_server_mappings(arg4)
        self.assertEqual(obj.domain, dns.name.from_text('example.com'))
        self.assertEqual(obj.delegation_mapping, delegation_mapping4)
        self.assertEqual(obj.stop_at, stop_at4)
        self.assertEqual(obj.odd_ports, odd_ports4)
        self.assertEqual(obj.filename, zone_filename4)

    def test_authoritative_errors(self):
        # no mapping
        arg = 'example.com'
        with self.assertRaises(argparse.ArgumentTypeError):
            self.helper.authoritative_name_server_mappings(arg)

        # bad domain name
        arg = 'example.com:ns1..foo.com'
        with self.assertRaises(argparse.ArgumentTypeError):
            self.helper.authoritative_name_server_mappings(arg)

        # bad IPv4 address
        arg = 'example.com:ns1.foo.com=192'
        with self.assertRaises(argparse.ArgumentTypeError):
            self.helper.authoritative_name_server_mappings(arg)

        # Bad IPv6 address
        arg = 'example.com:ns1.foo.com=2001:db8'
        with self.assertRaises(argparse.ArgumentTypeError):
            self.helper.authoritative_name_server_mappings(arg)

        # IPv6 address needs brackets (IP valid even with port stripped)
        arg = 'example.com:ns1.foo.com=2001:db8::1:3'
        with self.assertRaises(argparse.ArgumentTypeError):
            self.helper.authoritative_name_server_mappings(arg)

        # IPv6 address needs brackets (IP invalid with port stripped)
        arg = 'example.com:ns1.foo.com=2001:db8::3'
        with self.assertRaises(argparse.ArgumentTypeError):
            self.helper.authoritative_name_server_mappings(arg)

        # Name does not resolve properly
        arg = 'example.com:ns1.does-not-exist-foo-bar-baz-123-abc-dnsviz.net'
        with self.assertRaises(argparse.ArgumentTypeError):
            self.helper.authoritative_name_server_mappings(arg)

    def test_delegation_option(self):
        arg1 = 'example.com:ns1.example.com=192.0.2.1:1234,ns1.example.com=[2001:db8::1],' + \
                'ns1.example.com=192.0.2.2,ns2.example.com=[2001:db8::2]'

        arg1_with_spaces = ' example.com : ns1.example.com = [192.0.2.1]:1234 , ns1.example.com = [2001:db8::1], ' + \
                'ns1.example.com = [192.0.2.2] , ns2.example.com = [2001:db8::2] '

        arg2 = 'example.com:%s' % EXAMPLE_COM_DELEGATION

        delegation_mapping1 = {
                (dns.name.from_text('example.com'), dns.rdatatype.NS):
                        dns.rrset.from_text_list(dns.name.from_text('example.com'), 0, dns.rdataclass.IN, dns.rdatatype.NS,
                            ['ns1.example.com', 'ns2.example.com']),
                (dns.name.from_text('ns1.example.com'), dns.rdatatype.A):
                        dns.rrset.from_text_list(dns.name.from_text('ns1.example.com'), 0, dns.rdataclass.IN, dns.rdatatype.A,
                            ['192.0.2.1', '192.0.2.2']),
                (dns.name.from_text('ns1.example.com'), dns.rdatatype.AAAA):
                        dns.rrset.from_text_list(dns.name.from_text('ns1.example.com'), 0, dns.rdataclass.IN, dns.rdatatype.AAAA,
                            ['2001:db8::1']),
                (dns.name.from_text('ns2.example.com'), dns.rdatatype.AAAA):
                        dns.rrset.from_text_list(dns.name.from_text('ns2.example.com'), 0, dns.rdataclass.IN, dns.rdatatype.AAAA,
                            ['2001:db8::2']),
                }
        stop_at1 = False
        odd_ports1 = { (dns.name.from_text('example.com'), IPAddr('192.0.2.1')): 1234 }

        delegation_mapping2 = {
                (dns.name.from_text('example.com'), dns.rdatatype.NS):
                        dns.rrset.from_text_list(dns.name.from_text('example.com'), 0, dns.rdataclass.IN, dns.rdatatype.NS,
                            ['ns1.example.com']),
                (dns.name.from_text('ns1.example.com'), dns.rdatatype.A):
                        dns.rrset.from_text_list(dns.name.from_text('ns1.example.com'), 0, dns.rdataclass.IN, dns.rdatatype.A,
                            ['127.0.0.1'])
                }
        stop_at2 = False
        odd_ports2 = {}

        obj = self.helper.delegation_name_server_mappings(arg1)
        self.assertEqual(obj.domain, dns.name.from_text('example.com'))
        self.assertEqual(obj.delegation_mapping, delegation_mapping1)
        self.assertEqual(obj.stop_at, stop_at1)
        self.assertEqual(obj.odd_ports, odd_ports1)

        obj = self.helper.delegation_name_server_mappings(arg1_with_spaces)
        self.assertEqual(obj.domain, dns.name.from_text('example.com'))
        self.assertEqual(obj.delegation_mapping, delegation_mapping1)
        self.assertEqual(obj.stop_at, stop_at1)
        self.assertEqual(obj.odd_ports, odd_ports1)

        obj = self.helper.delegation_name_server_mappings(arg2)
        self.assertEqual(obj.domain, dns.name.from_text('example.com'))
        self.assertEqual(obj.delegation_mapping, delegation_mapping2)
        self.assertEqual(obj.stop_at, stop_at2)
        self.assertEqual(obj.odd_ports, odd_ports2)

    def test_delegation_errors(self):
        # all the authoritative error tests as well

        # requires name=addr mapping
        arg = 'example.com:ns1.example.com'
        with self.assertRaises(argparse.ArgumentTypeError):
            self.helper.delegation_name_server_mappings(arg)

        # requires name=addr mapping
        arg = 'example.com:192.0.2.1'
        with self.assertRaises(argparse.ArgumentTypeError):
            self.helper.delegation_name_server_mappings(arg)

        # doesn't allow +
        arg = 'example.com+:ns1.example.com=192.0.2.1'
        with self.assertRaises(argparse.ArgumentTypeError):
            self.helper.delegation_name_server_mappings(arg)

        # can't do this for root domain
        arg = '.:ns1.example.com=192.0.2.1'
        with self.assertRaises(argparse.ArgumentTypeError):
            self.helper.delegation_name_server_mappings(arg)

    def test_recursive_option(self):
        arg1 = 'ns1.example.com=192.0.2.1:1234,ns1.example.com=[2001:db8::1],' + \
                'ns1.example.com=192.0.2.2,ns2.example.com=[2001:db8::2],a.root-servers.net'

        arg1_with_spaces = ' ns1.example.com = [192.0.2.1]:1234 , ns1.example.com = [2001:db8::1], ' + \
                'ns1.example.com = [192.0.2.2] , ns2.example.com = [2001:db8::2] , a.root-servers.net '

        delegation_mapping1 = {
                (WILDCARD_EXPLICIT_DELEGATION, dns.rdatatype.NS):
                        dns.rrset.from_text_list(WILDCARD_EXPLICIT_DELEGATION, 0, dns.rdataclass.IN, dns.rdatatype.NS,
                            ['ns1.example.com', 'ns2.example.com', 'a.root-servers.net']),
                (dns.name.from_text('ns1.example.com'), dns.rdatatype.A):
                        dns.rrset.from_text_list(dns.name.from_text('ns1.example.com'), 0, dns.rdataclass.IN, dns.rdatatype.A,
                            ['192.0.2.1', '192.0.2.2']),
                (dns.name.from_text('ns1.example.com'), dns.rdatatype.AAAA):
                        dns.rrset.from_text_list(dns.name.from_text('ns1.example.com'), 0, dns.rdataclass.IN, dns.rdatatype.AAAA,
                            ['2001:db8::1']),
                (dns.name.from_text('ns2.example.com'), dns.rdatatype.AAAA):
                        dns.rrset.from_text_list(dns.name.from_text('ns2.example.com'), 0, dns.rdataclass.IN, dns.rdatatype.AAAA,
                            ['2001:db8::2']),
                (dns.name.from_text('a.root-servers.net'), dns.rdatatype.A):
                        dns.rrset.from_text_list(dns.name.from_text('a.root-servers.net'), 0, dns.rdataclass.IN, dns.rdatatype.A,
                            ['198.41.0.4']),
                (dns.name.from_text('a.root-servers.net'), dns.rdatatype.AAAA):
                        dns.rrset.from_text_list(dns.name.from_text('a.root-servers.net'), 0, dns.rdataclass.IN, dns.rdatatype.AAAA,
                            ['2001:503:ba3e::2:30'])
                }
        stop_at1 = False
        odd_ports1 = { (WILDCARD_EXPLICIT_DELEGATION, IPAddr('192.0.2.1')): 1234 }

        obj = self.helper.recursive_servers_for_domain(arg1)
        self.assertEqual(obj.domain, WILDCARD_EXPLICIT_DELEGATION)
        self.assertEqual(obj.delegation_mapping, delegation_mapping1)
        self.assertEqual(obj.stop_at, stop_at1)
        self.assertEqual(obj.odd_ports, odd_ports1)

        obj = self.helper.recursive_servers_for_domain(arg1_with_spaces)
        self.assertEqual(obj.domain, WILDCARD_EXPLICIT_DELEGATION)
        self.assertEqual(obj.delegation_mapping, delegation_mapping1)
        self.assertEqual(obj.stop_at, stop_at1)
        self.assertEqual(obj.odd_ports, odd_ports1)

    def test_recursive_errors(self):
        # all the authoritative error tests as well

        # doesn't accept file
        arg = EXAMPLE_COM_DELEGATION
        with self.assertRaises(argparse.ArgumentTypeError):
            self.helper.recursive_servers_for_domain(arg)

    def test_ds_option(self):
        arg1 = 'example.com:34983 10 1 EC358CFAAEC12266EF5ACFC1FEAF2CAFF083C418,' + \
            '34983 10 2 608D3B089D79D554A1947BD10BEC0A5B1BDBE67B4E60E34B1432ED00 33F24B49'

        delegation_mapping1 = {
                (dns.name.from_text('example.com'), dns.rdatatype.DS):
                        dns.rrset.from_text_list(dns.name.from_text('example.com'), 0, dns.rdataclass.IN, dns.rdatatype.DS,
                            ['34983 10 1 EC358CFAAEC12266EF5ACFC1FEAF2CAFF083C418',
                                '34983 10 2 608D3B089D79D554A1947BD10BEC0A5B1BDBE67B4E60E34B1432ED00 33F24B49'])
                }

        arg1_with_spaces = ' example.com : 34983 10 1 EC358CFAAEC12266EF5ACFC1FEAF2CAFF083C418, ' + \
            ' 34983 10 2 608D3B089D79D554A1947BD10BEC0A5B1BDBE67B4E60E34B1432ED00 33F24B49 '

        arg2 = 'example.com:%s' % EXAMPLE_COM_DELEGATION

        delegation_mapping2 = {
                (dns.name.from_text('example.com'), dns.rdatatype.DS):
                        dns.rrset.from_text_list(dns.name.from_text('example.com'), 0, dns.rdataclass.IN, dns.rdatatype.DS,
                            ['34983 10 1 EC358CFAAEC12266EF5ACFC1FEAF2CAFF083C418',
                                '34983 10 2 608D3B089D79D554A1947BD10BEC0A5B1BDBE67B4E60E34B1432ED00 33F24B49'])
                }


        obj = self.helper.ds_for_domain(arg1)
        self.assertEqual(obj.domain, dns.name.from_text('example.com'))
        self.assertEqual(obj.delegation_mapping, delegation_mapping1)

        obj = self.helper.ds_for_domain(arg1_with_spaces)
        self.assertEqual(obj.domain, dns.name.from_text('example.com'))
        self.assertEqual(obj.delegation_mapping, delegation_mapping1)

        obj = self.helper.ds_for_domain(arg2)
        self.assertEqual(obj.domain, dns.name.from_text('example.com'))
        self.assertEqual(obj.delegation_mapping, delegation_mapping2)

    def test_ds_error(self):
        # bad DS record
        arg = 'example.com:blah'
        with self.assertRaises(argparse.ArgumentTypeError):
            obj = self.helper.ds_for_domain(arg)

    def test_positive_int(self):
        self.assertEqual(ArgHelper.positive_int('1'), 1)
        self.assertEqual(ArgHelper.positive_int('2'), 2)

        # zero
        with self.assertRaises(argparse.ArgumentTypeError):
            ArgHelper.positive_int('0')

        # negative
        with self.assertRaises(argparse.ArgumentTypeError):
            ArgHelper.positive_int('-1')

    def test_bindable_ip(self):
        self.assertEqual(ArgHelper.bindable_ip('127.0.0.1'), IPAddr('127.0.0.1'))
        if self.use_ipv6:
            self.assertEqual(ArgHelper.bindable_ip('::1'), IPAddr('::1'))

        # invalid IPv4 address
        with self.assertRaises(argparse.ArgumentTypeError):
            ArgHelper.bindable_ip('192.')

        # invalid IPv6 address
        with self.assertRaises(argparse.ArgumentTypeError):
            ArgHelper.bindable_ip('2001:')

        # invalid IPv4 to bind to
        with self.assertRaises(argparse.ArgumentTypeError):
            ArgHelper.bindable_ip('192.0.2.1')

        # invalid IPv6 to bind to
        with self.assertRaises(argparse.ArgumentTypeError):
            ArgHelper.bindable_ip('2001:db8::1')

    def test_valid_url(self):
        url1 = 'http://www.example.com/foo'
        url2 = 'https://www.example.com/foo'
        url3 = 'ws:///path/to/file'
        url4 = 'ssh://user@example.com/foo'

        self.assertEqual(ArgHelper.valid_url(url1), url1)
        self.assertEqual(ArgHelper.valid_url(url2), url2)
        self.assertEqual(ArgHelper.valid_url(url3), url3)
        self.assertEqual(ArgHelper.valid_url(url4), url4)

        # invalid schema
        with self.assertRaises(argparse.ArgumentTypeError):
            ArgHelper.valid_url('ftp://www.example.com/foo')

        # ws with hostname
        with self.assertRaises(argparse.ArgumentTypeError):
            ArgHelper.valid_url('ws://www.example.com/foo')

    def test_rrtype_list(self):
        arg1 = 'A,AAAA,MX,CNAME'
        arg1_with_spaces = ' A , AAAA , MX , CNAME '
        arg2 = 'A'
        arg3 = 'A,BLAH'
        arg4_empty = ''
        arg4_empty_spaces = ' '

        type_list1 = [dns.rdatatype.A, dns.rdatatype.AAAA, dns.rdatatype.MX, dns.rdatatype.CNAME]
        type_list2 = [dns.rdatatype.A]
        empty_list = []

        self.assertEqual(ArgHelper.comma_separated_dns_types(arg1), type_list1)
        self.assertEqual(ArgHelper.comma_separated_dns_types(arg1_with_spaces), type_list1)
        self.assertEqual(ArgHelper.comma_separated_dns_types(arg4_empty), empty_list)
        self.assertEqual(ArgHelper.comma_separated_dns_types(arg4_empty_spaces), empty_list)

        # invalid schema
        with self.assertRaises(argparse.ArgumentTypeError):
            ArgHelper.comma_separated_dns_types(arg3)

    def test_valid_domain_name(self):
        arg1 = '.'
        arg2 = 'www.example.com'
        arg3 = 'www..example.com'

        self.assertEqual(ArgHelper.valid_domain_name(arg1), dns.name.from_text(arg1))
        self.assertEqual(ArgHelper.valid_domain_name(arg2), dns.name.from_text(arg2))

        # invalid domain name
        with self.assertRaises(argparse.ArgumentTypeError):
            ArgHelper.valid_domain_name(arg3)

    def test_nsid_option(self):
        self.assertEqual(ArgHelper.nsid_option(), dns.edns.GenericOption(3, b''))

    def test_ecs_option(self):
        arg1 = '192.0.2.0'
        arg2 = '192.0.2.0/25'
        arg3 = '192.0.2.255/25'
        arg4 = '192.0.2.0/24'
        arg5 = '2001:db8::'
        arg6 = '2001:db8::/121'
        arg7 = '2001:db8::ff/121'
        arg8 = '2001:db8::/120'


        ecs_option1 = dns.edns.GenericOption(8, binascii.unhexlify('00012000c0000200'))
        ecs_option2 = dns.edns.GenericOption(8, binascii.unhexlify('00011900c0000200'))
        ecs_option3 = dns.edns.GenericOption(8, binascii.unhexlify('00011900c0000280'))
        ecs_option4 = dns.edns.GenericOption(8, binascii.unhexlify('00011800c00002'))
        ecs_option5 = dns.edns.GenericOption(8, binascii.unhexlify('0002800020010db8000000000000000000000000'))
        ecs_option6 = dns.edns.GenericOption(8, binascii.unhexlify('0002790020010db8000000000000000000000000'))
        ecs_option7 = dns.edns.GenericOption(8, binascii.unhexlify('0002790020010db8000000000000000000000080'))
        ecs_option8 = dns.edns.GenericOption(8, binascii.unhexlify('0002780020010db80000000000000000000000'))

        self.assertEqual(ArgHelper.ecs_option(arg1), ecs_option1)
        self.assertEqual(ArgHelper.ecs_option(arg2), ecs_option2)
        self.assertEqual(ArgHelper.ecs_option(arg3), ecs_option3)
        self.assertEqual(ArgHelper.ecs_option(arg4), ecs_option4)
        self.assertEqual(ArgHelper.ecs_option(arg5), ecs_option5)
        self.assertEqual(ArgHelper.ecs_option(arg6), ecs_option6)
        self.assertEqual(ArgHelper.ecs_option(arg7), ecs_option7)
        self.assertEqual(ArgHelper.ecs_option(arg8), ecs_option8)

        # invalid IP address
        with self.assertRaises(argparse.ArgumentTypeError):
            ArgHelper.ecs_option('192')

        # invalid length
        with self.assertRaises(argparse.ArgumentTypeError):
            ArgHelper.ecs_option('192.0.2.0/foo')

        # invalid length
        with self.assertRaises(argparse.ArgumentTypeError):
            ArgHelper.ecs_option('192.0.2.0/33')

        # invalid length
        with self.assertRaises(argparse.ArgumentTypeError):
            ArgHelper.ecs_option('2001:db8::/129')

    def test_cookie_option(self):
        arg1 = '0102030405060708'
        arg2 = ''

        cookie_option1 = dns.edns.GenericOption(10, binascii.unhexlify('0102030405060708'))
        cookie_option2 = None

        self.assertEqual(ArgHelper.dns_cookie_option(arg1), cookie_option1)
        self.assertEqual(ArgHelper.dns_cookie_option(arg2), None)

        self.assertIsInstance(ArgHelper.dns_cookie_rand(), dns.edns.GenericOption)

        # too short
        with self.assertRaises(argparse.ArgumentTypeError):
            ArgHelper.dns_cookie_option('01')

        # too long
        with self.assertRaises(argparse.ArgumentTypeError):
            ArgHelper.dns_cookie_option('010203040506070809')

        # non-hexadecimal
        with self.assertRaises(argparse.ArgumentTypeError):
            ArgHelper.dns_cookie_option('010203040506070h')

    def test_delegation_aggregation(self):
        args1 = ['-A', '-N', 'example.com:ns1.example.com=192.0.2.1,ns1.example.com=[2001:db8::1]',
                        '-N', 'example.com:ns1.example.com=192.0.2.4',
                        '-N', 'example.com:ns2.example.com=192.0.2.2',
                        '-N', 'example.com:ns3.example.com=192.0.2.3']
        args2 = ['-A', '-N', 'example.com:ns1.example.com=192.0.2.1',
                        '-D', 'example.com:34983 10 1 EC358CFAAEC12266EF5ACFC1FEAF2CAFF083C418',
                        '-D', 'example.com:34983 10 2 608D3B089D79D554A1947BD10BEC0A5B1BDBE67B4E60E34B1432ED00 33F24B49']
        args3 = ['-A', '-N', 'example.com:ns1.example.com=192.0.2.1',
                        '-N', 'example1.com:ns1.example1.com=192.0.2.2']
        args4 = ['-A', '-N', 'example.com:ns1.example.com=192.0.2.1',
                        '-N', 'example.net:ns1.example.net=192.0.2.2']

        explicit_delegations1 = {
                (dns.name.from_text('com'), dns.rdatatype.NS):
                        dns.rrset.from_text_list(dns.name.from_text('com'), 0, dns.rdataclass.IN, dns.rdatatype.NS,
                            ['localhost']),
                }
        explicit_delegations2 = {
                (dns.name.from_text('com'), dns.rdatatype.NS):
                        dns.rrset.from_text_list(dns.name.from_text('com'), 0, dns.rdataclass.IN, dns.rdatatype.NS,
                            ['localhost']),
                }
        explicit_delegations3 = {
                (dns.name.from_text('com'), dns.rdatatype.NS):
                        dns.rrset.from_text_list(dns.name.from_text('com'), 0, dns.rdataclass.IN, dns.rdatatype.NS,
                            ['localhost']),
                }
        explicit_delegations4 = {
                (dns.name.from_text('com'), dns.rdatatype.NS):
                        dns.rrset.from_text_list(dns.name.from_text('com'), 0, dns.rdataclass.IN, dns.rdatatype.NS,
                            ['localhost']),
                (dns.name.from_text('net'), dns.rdatatype.NS):
                        dns.rrset.from_text_list(dns.name.from_text('net'), 0, dns.rdataclass.IN, dns.rdatatype.NS,
                            ['localhost']),
                }

        for ex in (explicit_delegations1, explicit_delegations2, explicit_delegations3, explicit_delegations4):
            if self.use_ipv6:
                    ex[(dns.name.from_text('localhost'), dns.rdatatype.AAAA)] = \
                            dns.rrset.from_text_list(dns.name.from_text('localhost'), 0, dns.rdataclass.IN, dns.rdatatype.AAAA,
                                ['::1'])
                    loopback_ip = IPAddr('::1')
            else:
                    ex[(dns.name.from_text('localhost'), dns.rdatatype.A)] = \
                            dns.rrset.from_text_list(dns.name.from_text('localhost'), 0, dns.rdataclass.IN, dns.rdatatype.A,
                                ['127.0.0.1'])
                    loopback_ip = IPAddr('127.0.0.1')

        odd_ports1 = { (dns.name.from_text('com'), loopback_ip): self.first_port }
        odd_ports2 = { (dns.name.from_text('com'), loopback_ip): self.first_port }
        odd_ports3 = { (dns.name.from_text('com'), loopback_ip): self.first_port }
        odd_ports4 = {
                (dns.name.from_text('com'), loopback_ip): self.first_port,
                (dns.name.from_text('net'), loopback_ip): self.first_port + 1,
                }

        if self.use_ipv6:
            rdata = b'AAAA ::1'
        else:
            rdata = b'A 127.0.0.1'

        zone_contents1 = b'''@ 600 IN SOA localhost. root.localhost. 1 1800 900 86400 600
@ 600 IN NS @
@ 600 IN ''' + rdata + \
b'''
example 0 IN NS ns1.example
example 0 IN NS ns2.example
example 0 IN NS ns3.example
ns1.example 0 IN A 192.0.2.1
ns1.example 0 IN A 192.0.2.4
ns1.example 0 IN AAAA 2001:db8::1
ns2.example 0 IN A 192.0.2.2
ns3.example 0 IN A 192.0.2.3
'''
        zone_contents2 = b'''@ 600 IN SOA localhost. root.localhost. 1 1800 900 86400 600
@ 600 IN NS @
@ 600 IN ''' + rdata + \
b'''
example 0 IN DS 34983 10 1 ec358cfaaec12266ef5acfc1feaf2caff083c418
example 0 IN DS 34983 10 2 608d3b089d79d554a1947bd10bec0a5b1bdbe67b4e60e34b1432ed0033f24b49
example 0 IN NS ns1.example
ns1.example 0 IN A 192.0.2.1
'''

        ZoneFileToServe._next_free_port = self.first_port

        arghelper1 = ArgHelper(self.resolver, self.logger)
        arghelper1.build_parser('probe')
        arghelper1.parse_args(args1)
        arghelper1.aggregate_delegation_info()
        zone_to_serve = arghelper1._zones_to_serve[0]
        zone_obj = dns.zone.from_file(zone_to_serve.filename, dns.name.from_text('com'))
        zone_obj_other = dns.zone.from_text(zone_contents1, dns.name.from_text('com'))
        self.assertEqual(zone_obj, zone_obj_other)
        self.assertEqual(arghelper1.explicit_delegations, explicit_delegations1)
        self.assertEqual(arghelper1.odd_ports, odd_ports1)
        
        ZoneFileToServe._next_free_port = self.first_port

        arghelper2 = ArgHelper(self.resolver, self.logger)
        arghelper2.build_parser('probe')
        arghelper2.parse_args(args2)
        arghelper2.aggregate_delegation_info()
        zone_to_serve = arghelper2._zones_to_serve[0]
        zone_obj = dns.zone.from_file(zone_to_serve.filename, dns.name.from_text('com'))
        zone_obj_other = dns.zone.from_text(zone_contents2, dns.name.from_text('com'))
        self.assertEqual(zone_obj, zone_obj_other)
        self.assertEqual(arghelper2.explicit_delegations, explicit_delegations2)
        self.assertEqual(arghelper2.odd_ports, odd_ports2)
        
        ZoneFileToServe._next_free_port = self.first_port

        arghelper3 = ArgHelper(self.resolver, self.logger)
        arghelper3.build_parser('probe')
        arghelper3.parse_args(args3)
        arghelper3.aggregate_delegation_info()
        self.assertEqual(arghelper3.explicit_delegations, explicit_delegations3)
        self.assertEqual(arghelper3.odd_ports, odd_ports3)
        
        ZoneFileToServe._next_free_port = self.first_port

        arghelper4 = ArgHelper(self.resolver, self.logger)
        arghelper4.build_parser('probe')
        arghelper4.parse_args(args4)
        arghelper4.aggregate_delegation_info()
        self.assertEqual(arghelper4.explicit_delegations, explicit_delegations4)
        self.assertEqual(arghelper4.odd_ports, odd_ports4)
        
    def test_delegation_authoritative_aggregation(self):
        args1 = ['-A', '-N', 'example.com:ns1.example.com=192.0.2.1,ns1.example.com=[2001:db8::1]',
                '-x', 'foo.com:ns1.foo.com=192.0.2.3:50503']

        explicit_delegations1 = {
                (dns.name.from_text('com'), dns.rdatatype.NS):
                        dns.rrset.from_text_list(dns.name.from_text('com'), 0, dns.rdataclass.IN, dns.rdatatype.NS,
                            ['localhost']),
                (dns.name.from_text('foo.com'), dns.rdatatype.NS):
                        dns.rrset.from_text_list(dns.name.from_text('foo.com'), 0, dns.rdataclass.IN, dns.rdatatype.NS,
                            ['ns1.foo.com']),
                (dns.name.from_text('ns1.foo.com'), dns.rdatatype.A):
                        dns.rrset.from_text_list(dns.name.from_text('ns1.foo.com'), 0, dns.rdataclass.IN, dns.rdatatype.A,
                            ['192.0.2.3']),
                }

        for ex in (explicit_delegations1,):
            if self.use_ipv6:
                    ex[(dns.name.from_text('localhost'), dns.rdatatype.AAAA)] = \
                            dns.rrset.from_text_list(dns.name.from_text('localhost'), 0, dns.rdataclass.IN, dns.rdatatype.AAAA,
                                ['::1'])
                    loopback_ip = IPAddr('::1')
            else:
                    ex[(dns.name.from_text('localhost'), dns.rdatatype.A)] = \
                            dns.rrset.from_text_list(dns.name.from_text('localhost'), 0, dns.rdataclass.IN, dns.rdatatype.A,
                                ['127.0.0.1'])
                    loopback_ip = IPAddr('127.0.0.1')

        odd_ports1 = { (dns.name.from_text('com'), loopback_ip): self.first_port,
                            (dns.name.from_text('foo.com'), IPAddr('192.0.2.3')): 50503,
                    }

        ZoneFileToServe._next_free_port = self.first_port

        arghelper1 = ArgHelper(self.resolver, self.logger)
        arghelper1.build_parser('probe')
        arghelper1.parse_args(args1)
        arghelper1.aggregate_delegation_info()
        self.assertEqual(arghelper1.explicit_delegations, explicit_delegations1)
        self.assertEqual(arghelper1.odd_ports, odd_ports1)
        
    def test_delegation_authoritative_aggregation_errors(self):
        args1 = ['-A', '-N', 'example.com:ns1.example.com=192.0.2.1,ns1.example.com=[2001:db8::1]',
                '-x', 'com:ns1.foo.com=192.0.2.3']

        arghelper1 = ArgHelper(self.resolver, self.logger)
        arghelper1.build_parser('probe')
        arghelper1.parse_args(args1)

        # com is specified with -x but example.com is specified with -N
        with self.assertRaises(argparse.ArgumentTypeError):
            arghelper1.aggregate_delegation_info()
        
    def test_recursive_aggregation(self):
        args1 = ['-s', 'ns1.example.com=192.0.2.1,ns1.example.com=[2001:db8::1]',
                        '-s', 'ns1.example.com=192.0.2.4,a.root-servers.net']

        explicit_delegations1 = {
                (WILDCARD_EXPLICIT_DELEGATION, dns.rdatatype.NS):
                        dns.rrset.from_text_list(WILDCARD_EXPLICIT_DELEGATION, 0, dns.rdataclass.IN, dns.rdatatype.NS,
                            ['ns1.example.com', 'a.root-servers.net']),
                (dns.name.from_text('ns1.example.com'), dns.rdatatype.A):
                        dns.rrset.from_text_list(dns.name.from_text('ns1.example.com'), 0, dns.rdataclass.IN, dns.rdatatype.A,
                            ['192.0.2.1', '192.0.2.4']),
                (dns.name.from_text('ns1.example.com'), dns.rdatatype.AAAA):
                        dns.rrset.from_text_list(dns.name.from_text('ns1.example.com'), 0, dns.rdataclass.IN, dns.rdatatype.AAAA,
                            ['2001:db8::1']),
                (dns.name.from_text('a.root-servers.net'), dns.rdatatype.A):
                        dns.rrset.from_text_list(dns.name.from_text('a.root-servers.net'), 0, dns.rdataclass.IN, dns.rdatatype.A,
                            ['198.41.0.4']),
                (dns.name.from_text('a.root-servers.net'), dns.rdatatype.AAAA):
                        dns.rrset.from_text_list(dns.name.from_text('a.root-servers.net'), 0, dns.rdataclass.IN, dns.rdatatype.AAAA,
                            ['2001:503:ba3e::2:30'])
                }

        odd_ports1 = {}

        arghelper1 = ArgHelper(self.resolver, self.logger)
        arghelper1.build_parser('probe')
        arghelper1.parse_args(args1)
        arghelper1.aggregate_delegation_info()
        self.assertEqual(arghelper1.explicit_delegations, explicit_delegations1)
        self.assertEqual(arghelper1.odd_ports, odd_ports1)
        
    def test_option_combination_errors(self):

        # Names, input file, or names file required
        args = []
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        with self.assertRaises(argparse.ArgumentTypeError):
            arghelper.check_args()

        # Names file and command-line domain names are mutually exclusive
        args = ['-f', '/dev/null', 'example.com']
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        with self.assertRaises(argparse.ArgumentTypeError):
            arghelper.check_args()
        arghelper.args.names_file.close()

        # Authoritative analysis and recursive servers
        args = ['-A', '-s', '192.0.2.1', 'example.com']
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        with self.assertRaises(argparse.ArgumentTypeError):
            arghelper.check_args()

        # Authoritative servers with recursive analysis
        args = ['-x', 'example.com:ns1.example.com=192.0.2.1', 'example.com']
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        with self.assertRaises(argparse.ArgumentTypeError):
            arghelper.check_args()

        # Delegation information with recursive analysis
        args = ['-N', 'example.com:ns1.example.com=192.0.2.1', 'example.com']
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        with self.assertRaises(argparse.ArgumentTypeError):
            arghelper.check_args()

        # Delegation information with recursive analysis
        args = [ '-D', 'example.com:34983 10 1 EC358CFAAEC12266EF5ACFC1FEAF2CAFF083C418', 'example.com']
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        with self.assertRaises(argparse.ArgumentTypeError):
            arghelper.check_args()

    def test_ceiling(self):
        args = ['-a', 'com', 'example.com']
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        arghelper.set_kwargs()
        self.assertEqual(arghelper.ceiling, dns.name.from_text('com'))

        args = ['example.com']
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        arghelper.set_kwargs()
        self.assertEqual(arghelper.ceiling, dns.name.root)

        args = ['-A', 'example.com']
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        arghelper.set_kwargs()
        self.assertIsNone(arghelper.ceiling)

    def test_ip4_ipv6(self):
        args = []
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        arghelper.set_kwargs()
        self.assertEqual(arghelper.try_ipv4, True)
        self.assertEqual(arghelper.try_ipv6, True)

        args = ['-4', '-6']
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        arghelper.set_kwargs()
        self.assertEqual(arghelper.try_ipv4, True)
        self.assertEqual(arghelper.try_ipv6, True)

        args = ['-4']
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        arghelper.set_kwargs()
        self.assertEqual(arghelper.try_ipv4, True)
        self.assertEqual(arghelper.try_ipv6, False)

        args = ['-6']
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        arghelper.set_kwargs()
        self.assertEqual(arghelper.try_ipv4, False)
        self.assertEqual(arghelper.try_ipv6, True)

    def test_client_ip(self):
        args = []
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        arghelper.set_kwargs()
        self.assertIsNone(arghelper.client_ipv4)
        self.assertIsNone(arghelper.client_ipv6)

        args = ['-b', '127.0.0.1']
        if self.use_ipv6:
            args.extend(['-b', '::1'])
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        arghelper.set_kwargs()
        self.assertEqual(arghelper.client_ipv4, IPAddr('127.0.0.1'))
        if self.use_ipv6:
            self.assertEqual(arghelper.client_ipv6, IPAddr('::1'))

    def test_th_factories(self):
        args = ['example.com']
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        arghelper.set_kwargs()
        self.assertIsNone(arghelper.th_factories)

        args = ['-u', 'http://example.com/', 'example.com']
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        arghelper.set_kwargs()
        self.assertIsInstance(arghelper.th_factories[0], transport.DNSQueryTransportHandlerHTTPFactory)

        args = ['-u', 'ws:///dev/null', 'example.com']
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        arghelper.set_kwargs()
        self.assertIsInstance(arghelper.th_factories[0], transport.DNSQueryTransportHandlerWebSocketServerFactory)

        args = ['-u', 'ssh://example.com/', 'example.com']
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        arghelper.set_kwargs()
        self.assertIsInstance(arghelper.th_factories[0], transport.DNSQueryTransportHandlerRemoteCmdFactory)

    def test_edns_options(self):
        CustomQueryMixin.edns_options = self.custom_query_mixin_edns_options_orig[:]

        # None
        args = ['-c', '', 'example.com']
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        arghelper.set_kwargs()
        self.assertEqual(len(CustomQueryMixin.edns_options), 0)

        CustomQueryMixin.edns_options = self.custom_query_mixin_edns_options_orig[:]

        # Only DNS cookie 
        args = ['example.com']
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        arghelper.set_kwargs()
        self.assertEqual(set([o.otype for o in CustomQueryMixin.edns_options]), set([10]))

        CustomQueryMixin.edns_options = self.custom_query_mixin_edns_options_orig[:]

        # All EDNS options
        args = ['-n', '-e', '192.0.2.0/24', 'example.com']
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        arghelper.set_kwargs()
        self.assertEqual(set([o.otype for o in CustomQueryMixin.edns_options]), set([3, 8, 10]))

        CustomQueryMixin.edns_options = self.custom_query_mixin_edns_options_orig[:]

    def test_ingest_input(self):
        with tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False) as example_bad_json:
            example_bad_json.write(b'{')

        with tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False) as example_no_version:
            example_no_version.write(b'{}')

        with tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False) as example_invalid_version_1:
            example_invalid_version_1.write(b'{ "_meta._dnsviz.": { "version": 1.11 } }')

        with tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False) as example_invalid_version_2:
            example_invalid_version_2.write(b'{ "_meta._dnsviz.": { "version": 5.0 } }')

        with gzip.open(EXAMPLE_AUTHORITATIVE, 'rb') as example_auth_in:
            with tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False) as example_auth_out:
                example_auth_out.write(example_auth_in.read())

        try:
            args = ['-r', example_auth_out.name]
            arghelper = ArgHelper(self.resolver, self.logger)
            arghelper.build_parser('probe')
            arghelper.parse_args(args)
            arghelper.ingest_input()

            # Bad json
            args = ['-r', example_bad_json.name]
            arghelper = ArgHelper(self.resolver, self.logger)
            arghelper.build_parser('probe')
            arghelper.parse_args(args)
            with self.assertRaises(AnalysisInputError):
                arghelper.ingest_input()

            # No version
            args = ['-r', example_no_version.name]
            arghelper = ArgHelper(self.resolver, self.logger)
            arghelper.build_parser('probe')
            arghelper.parse_args(args)
            with self.assertRaises(AnalysisInputError):
                arghelper.ingest_input()

            # Invalid version
            args = ['-r', example_invalid_version_1.name]
            arghelper = ArgHelper(self.resolver, self.logger)
            arghelper.build_parser('probe')
            arghelper.parse_args(args)
            with self.assertRaises(AnalysisInputError):
                arghelper.ingest_input()

            # Invalid version
            args = ['-r', example_invalid_version_2.name]
            arghelper = ArgHelper(self.resolver, self.logger)
            arghelper.build_parser('probe')
            arghelper.parse_args(args)
            with self.assertRaises(AnalysisInputError):
                arghelper.ingest_input()

        finally:
            for tmpfile in (example_auth_out, example_bad_json, example_no_version, \
                    example_invalid_version_1, example_invalid_version_2):
                os.remove(tmpfile.name)

    def test_ingest_names(self):
        args = ['example.com', 'example.net']
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        arghelper.ingest_names()
        self.assertEqual(list(arghelper.names), [dns.name.from_text('example.com'), dns.name.from_text('example.net')])

        unicode_name = 'テスト'

        args = [unicode_name]
        arghelper = ArgHelper(self.resolver, self.logger)
        arghelper.build_parser('probe')
        arghelper.parse_args(args)
        arghelper.ingest_names()
        self.assertEqual(list(arghelper.names), [dns.name.from_text('xn--zckzah.')])

        with tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False) as names_file:
            names_file.write('example.com\nexample.net\n'.encode('utf-8'))

        with tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False) as names_file_unicode:
            try:
                names_file_unicode.write(('%s\n' % (unicode_name)).encode('utf-8'))
            # python3/python2 dual compatibility
            except UnicodeDecodeError:
                names_file_unicode.write(('%s\n' % (unicode_name)))

        with tempfile.NamedTemporaryFile('wb', prefix='dnsviz', delete=False) as example_names_only:
            example_names_only.write(b'{ "_meta._dnsviz.": { "version": 1.2, "names": [ "example.com.", "example.net.", "example.org." ] } }') 

        try:
            args = ['-f', names_file.name]
            arghelper = ArgHelper(self.resolver, self.logger)
            arghelper.build_parser('probe')
            arghelper.parse_args(args)
            arghelper.ingest_names()
            self.assertEqual(list(arghelper.names), [dns.name.from_text('example.com'), dns.name.from_text('example.net')])

            args = ['-f', names_file_unicode.name]
            arghelper = ArgHelper(self.resolver, self.logger)
            arghelper.build_parser('probe')
            arghelper.parse_args(args)
            arghelper.ingest_names()
            self.assertEqual(list(arghelper.names), [dns.name.from_text('xn--zckzah.')])

            args = ['-r', example_names_only.name]
            arghelper = ArgHelper(self.resolver, self.logger)
            arghelper.build_parser('probe')
            arghelper.parse_args(args)
            arghelper.ingest_input()
            arghelper.ingest_names()
            self.assertEqual(list(arghelper.names), [dns.name.from_text('example.com'), dns.name.from_text('example.net'), dns.name.from_text('example.org')])

            args = ['-r', example_names_only.name, 'example.com']
            arghelper = ArgHelper(self.resolver, self.logger)
            arghelper.build_parser('probe')
            arghelper.parse_args(args)
            arghelper.ingest_input()
            arghelper.ingest_names()
            self.assertEqual(list(arghelper.names), [dns.name.from_text('example.com')])
        finally:
            for tmpfile in (names_file, names_file_unicode, example_names_only):
                os.remove(tmpfile.name)

if __name__ == '__main__':
    unittest.main()
