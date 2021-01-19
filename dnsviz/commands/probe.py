#!/usr/bin/env python
#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Created by Casey Deccio (casey@deccio.net)
#
# Copyright 2014-2016 VeriSign, Inc.
#
# Copyright 2016-2021 Casey Deccio
#
# DNSViz is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# DNSViz is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with DNSViz.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import unicode_literals

import argparse
import atexit
import binascii
import codecs
import errno
import getopt
import io
import json
import logging
import multiprocessing
import multiprocessing.managers
import os
import random
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

# minimal support for python2.6
try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict

# python3/python2 dual compatibility
try:
    import urllib.parse
except ImportError:
    import urlparse
else:
    urlparse = urllib.parse

import dns.edns, dns.exception, dns.message, dns.name, dns.rdata, dns.rdataclass, dns.rdatatype, dns.rdtypes.ANY.NS, dns.rdtypes.IN.A, dns.rdtypes.IN.AAAA, dns.resolver, dns.rrset

from dnsviz.analysis import COOKIE_STANDIN, WILDCARD_EXPLICIT_DELEGATION, PrivateAnalyst, PrivateRecursiveAnalyst, OnlineDomainNameAnalysis, NetworkConnectivityException, DNS_RAW_VERSION
from dnsviz.config import RESOLV_CONF
import dnsviz.format as fmt
from dnsviz.ipaddr import IPAddr
from dnsviz.query import DiagnosticQuery, QuickDNSSECQuery, StandardRecursiveQueryCD
from dnsviz.resolver import DNSAnswer, Resolver, ResolvConfError, PrivateFullResolver
from dnsviz import transport
from dnsviz.util import get_client_address, get_root_hints
lb2s = fmt.latin1_binary_to_string

logging.basicConfig(level=logging.WARNING, format='%(message)s')
logger = logging.getLogger()

# this needs to be global because of multiprocessing
tm = None
th_factories = None
resolver = None
explicit_delegations = None
odd_ports = None

A_ROOT_IPV4 = IPAddr('198.41.0.4')
A_ROOT_IPV6 = IPAddr('2001:503:ba3e::2:30')

class MissingExecutablesError(Exception):
    pass

class ZoneFileServiceError(Exception):
    pass

class AnalysisInputError(Exception):
    pass

class CustomQueryMixin(object):
    edns_options = []

#XXX this is a hack required for inter-process sharing of dns.name.Name
# instances using multiprocess
def _setattr_dummy(self, name, value):
    return super(dns.name.Name, self).__setattr__(name, value)
dns.name.Name.__setattr__ = _setattr_dummy

def _raise_eof(signum, frame):
    # EOFError is raised instead of KeyboardInterrupt
    # because the multiprocessing worker doesn't handle
    # KeyboardInterrupt
    raise EOFError

def _init_tm():
    global tm
    tm = transport.DNSQueryTransportManager()

def _cleanup_tm():
    global tm
    if tm is not None:
        tm.close()

def _init_stub_resolver():
    global resolver

    servers = set()
    for rdata in explicit_delegations[(WILDCARD_EXPLICIT_DELEGATION, dns.rdatatype.NS)]:
        for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            if (rdata.target, rdtype) in explicit_delegations:
                servers.update([IPAddr(r.address) for r in explicit_delegations[(rdata.target, rdtype)]])
    resolver = Resolver(list(servers), StandardRecursiveQueryCD, transport_manager=tm)

def _init_full_resolver():
    global resolver

    quick_query = QuickDNSSECQuery.add_mixin(CustomQueryMixin).add_server_cookie(COOKIE_STANDIN)
    diagnostic_query = DiagnosticQuery.add_mixin(CustomQueryMixin).add_server_cookie(COOKIE_STANDIN)

    # now that we have the hints, make resolver a full resolver instead of a stub
    hints = get_root_hints()
    for key in explicit_delegations:
        hints[key] = explicit_delegations[key]
    resolver = PrivateFullResolver(hints, query_cls=(quick_query, diagnostic_query), odd_ports=odd_ports, cookie_standin=COOKIE_STANDIN, transport_manager=tm)

def _init_interrupt_handler():
    signal.signal(signal.SIGINT, _raise_eof)

def _init_subprocess(use_full):
    _init_tm()
    if use_full:
        _init_full_resolver()
    else:
        _init_stub_resolver()
    _init_interrupt_handler()
    multiprocessing.util.Finalize(None, _cleanup_tm, exitpriority=0)

def _analyze(args):
    (cls, name, rdclass, dlv_domain, try_ipv4, try_ipv6, client_ipv4, client_ipv6, query_class_mixin, ceiling, edns_diagnostics, \
            stop_at_explicit, extra_rdtypes, explicit_only, cache, cache_level, cache_lock) = args
    if ceiling is not None and name.is_subdomain(ceiling):
        c = ceiling
    else:
        c = name
    try:
        a = cls(name, rdclass=rdclass, dlv_domain=dlv_domain, try_ipv4=try_ipv4, try_ipv6=try_ipv6, client_ipv4=client_ipv4, client_ipv6=client_ipv6, query_class_mixin=query_class_mixin, ceiling=c, edns_diagnostics=edns_diagnostics, explicit_delegations=explicit_delegations, stop_at_explicit=stop_at_explicit, odd_ports=odd_ports, extra_rdtypes=extra_rdtypes, explicit_only=explicit_only, analysis_cache=cache, cache_level=cache_level, analysis_cache_lock=cache_lock, transport_manager=tm, th_factories=th_factories, resolver=resolver)
        return a.analyze()
    # re-raise a KeyboardInterrupt, as this means we've been interrupted
    except KeyboardInterrupt:
        raise
    # report exceptions related to network connectivity
    except (NetworkConnectivityException, transport.RemoteQueryTransportError) as e:
        logger.error('Error analyzing %s: %s' % (fmt.humanize_name(name), e))
    # don't report EOFError, as that is what is raised if there is a
    # KeyboardInterrupt in ParallelAnalyst
    except EOFError:
        pass
    except:
        logger.exception('Error analyzing %s' % fmt.humanize_name(name))
        return None

class BulkAnalyst(object):
    analyst_cls = PrivateAnalyst
    use_full_resolver = True

    def __init__(self, rdclass, try_ipv4, try_ipv6, client_ipv4, client_ipv6, query_class_mixin, ceiling, edns_diagnostics, stop_at_explicit, cache_level, extra_rdtypes, explicit_only, dlv_domain):
        self.rdclass = rdclass
        self.try_ipv4 = try_ipv4
        self.try_ipv6 = try_ipv6
        self.client_ipv4 = client_ipv4
        self.client_ipv6 = client_ipv6
        self.query_class_mixin = query_class_mixin
        self.ceiling = ceiling
        self.edns_diagnostics = edns_diagnostics
        self.stop_at_explicit = stop_at_explicit
        self.cache_level = cache_level
        self.extra_rdtypes = extra_rdtypes
        self.explicit_only = explicit_only
        self.dlv_domain = dlv_domain

        self.cache = {}
        self.cache_lock = threading.Lock()

    def _name_to_args_iter(self, names):
        for name in names:
            yield (self.analyst_cls, name, self.rdclass, self.dlv_domain, self.try_ipv4, self.try_ipv6, self.client_ipv4, self.client_ipv6, self.query_class_mixin, self.ceiling, self.edns_diagnostics, self.stop_at_explicit, self.extra_rdtypes, self.explicit_only, self.cache, self.cache_level, self.cache_lock)

    def analyze(self, names, flush_func=None):
        name_objs = []
        for args in self._name_to_args_iter(names):
            name_obj = _analyze(args)
            if flush_func is not None:
                flush_func(name_obj)
            else:
                name_objs.append(name_obj)
        return name_objs

class RecursiveBulkAnalyst(BulkAnalyst):
    analyst_cls = PrivateRecursiveAnalyst
    use_full_resolver = False

class MultiProcessAnalystMixin(object):
    analysis_model = OnlineDomainNameAnalysis

    def _finalize_analysis_proper(self, name_obj):
        self.analysis_cache[name_obj.name] = name_obj
        super(MultiProcessAnalystMixin, self)._finalize_analysis_proper(name_obj)

    def _finalize_analysis_all(self, name_obj):
        self.analysis_cache[name_obj.name] = name_obj
        super(MultiProcessAnalystMixin, self)._finalize_analysis_all(name_obj)

    def refresh_dependency_references(self, name_obj, trace=None):
        if trace is None:
            trace = []

        if name_obj.name in trace:
            return

        if name_obj.parent is not None:
            self.refresh_dependency_references(name_obj.parent, trace+[name_obj.name])
        if name_obj.nxdomain_ancestor is not None:
            self.refresh_dependency_references(name_obj.nxdomain_ancestor, trace+[name_obj.name])
        if name_obj.dlv_parent is not None:
            self.refresh_dependency_references(name_obj.dlv_parent, trace+[name_obj.name])

        # loop until all deps have been added
        for cname in name_obj.cname_targets:
            for target in name_obj.cname_targets[cname]:
                while name_obj.cname_targets[cname][target] is None:
                    try:
                        name_obj.cname_targets[cname][target] = self.analysis_cache[target]
                    except KeyError:
                        time.sleep(1)
                self.refresh_dependency_references(name_obj.cname_targets[cname][target], trace+[name_obj.name])
        for signer in name_obj.external_signers:
            while name_obj.external_signers[signer] is None:
                try:
                    name_obj.external_signers[signer] = self.analysis_cache[signer]
                except KeyError:
                    time.sleep(1)
            self.refresh_dependency_references(name_obj.external_signers[signer], trace+[name_obj.name])
        if self.follow_ns:
            for ns in name_obj.ns_dependencies:
                while name_obj.ns_dependencies[ns] is None:
                    try:
                        name_obj.ns_dependencies[ns] = self.analysis_cache[ns]
                    except KeyError:
                        time.sleep(1)
                self.refresh_dependency_references(name_obj.ns_dependencies[ns], trace+[name_obj.name])
        if self.follow_mx:
            for target in name_obj.mx_targets:
                while name_obj.mx_targets[target] is None:
                    try:
                        name_obj.mx_targets[target] = self.analysis_cache[target]
                    except KeyError:
                        time.sleep(1)
                self.refresh_dependency_references(name_obj.mx_targets[target], trace+[name_obj.name])

    def analyze(self):
        name_obj = super(MultiProcessAnalystMixin, self).analyze()
        if not self.trace:
            self.refresh_dependency_references(name_obj)
        return name_obj

class MultiProcessAnalyst(MultiProcessAnalystMixin, PrivateAnalyst):
    pass

class RecursiveMultiProcessAnalyst(MultiProcessAnalystMixin, PrivateRecursiveAnalyst):
    pass

class ParallelAnalystMixin(object):
    analyst_cls = MultiProcessAnalyst
    use_full_resolver = None

    def __init__(self, rdclass, try_ipv4, try_ipv6, client_ipv4, client_ipv6, query_class_mixin, ceiling, edns_diagnostics, stop_at_explicit, cache_level, extra_rdtypes, explicit_only, dlv_domain, processes):
        super(ParallelAnalystMixin, self).__init__(rdclass, try_ipv4, try_ipv6, client_ipv4, client_ipv6, query_class_mixin, ceiling, edns_diagnostics, stop_at_explicit, cache_level, extra_rdtypes, explicit_only, dlv_domain)
        self.manager = multiprocessing.managers.SyncManager()
        self.manager.start()

        self.processes = processes

        self.cache = self.manager.dict()
        self.cache_lock = self.manager.Lock()

    def analyze(self, names, flush_func=None):
        results = []
        name_objs = []
        pool = multiprocessing.Pool(self.processes, _init_subprocess, (self.use_full_resolver,))
        try:
            for args in self._name_to_args_iter(names):
                results.append(pool.apply_async(_analyze, (args,)))
            # loop instead of just joining, so we can check for interrupt at
            # main process
            for result in results:
                name_objs.append(result.get())
        except KeyboardInterrupt:
            pool.terminate()
            raise

        pool.close()
        pool.join()
        return name_objs

class ParallelAnalyst(ParallelAnalystMixin, BulkAnalyst):
    analyst_cls = MultiProcessAnalyst
    use_full_resolver = True

class RecursiveParallelAnalyst(ParallelAnalystMixin, RecursiveBulkAnalyst):
    analyst_cls = RecursiveMultiProcessAnalyst
    use_full_resolver = False

class ZoneFileToServe:
    _next_free_port = 50053

    NAMED = 'named'
    NAMED_CHECKCONF = 'named-checkconf'
    NAMED_CONF = '%(dir)s/named.conf'
    NAMED_PID = '%(dir)s/named.pid'
    NAMED_LOG = '%(dir)s/named.log'
    NAMED_CONF_TEMPLATE = '''
options {
    directory "%(dir)s";
    pid-file "%(named_pid)s";
    listen-on port %(port)d { localhost; };
    listen-on-v6 port %(port)d { localhost; };
    recursion no;
    notify no;
};
controls {};
zone "%(zone_name)s" {
    type master;
    file "%(zone_file)s";
};
logging {
	channel info_file { file "%(named_log)s"; severity info; };
	category default { info_file; };
	category unmatched { null; };
};
'''
    ZONEFILE_TEMPLATE_PRE = '''
$ORIGIN %(zone_name)s
$TTL 600
@ IN SOA localhost. root.localhost. 1 1800 900 86400 600
@ IN NS @
'''
    ZONEFILE_TEMPLATE_A = '@ IN A 127.0.0.1\n'
    ZONEFILE_TEMPLATE_AAAA = '@ IN AAAA ::1\n'
    USAGE_RE = re.compile(r'usage:', re.IGNORECASE)

    def __init__(self, domain, filename):
        self.domain = domain
        self.filename = filename

        self.port = self._next_free_port
        self.__class__._next_free_port += 1

        self.working_dir = None
        self.pid = None

    @classmethod
    def from_mappings(cls, domain, mappings, use_ipv6_loopback):
        zonefile = tempfile.NamedTemporaryFile('w', prefix='dnsviz', delete=False)
        atexit.register(os.remove, zonefile.name)

        args = { 'zone_name': lb2s(domain.to_text()) }
        if use_ipv6_loopback:
            zonefile_template = cls.ZONEFILE_TEMPLATE_PRE + cls.ZONEFILE_TEMPLATE_AAAA
        else:
            zonefile_template = cls.ZONEFILE_TEMPLATE_PRE + cls.ZONEFILE_TEMPLATE_A
        zonefile_contents = zonefile_template % args
        zonefile.write(zonefile_contents)

        for name, rdtype in mappings:
            if not name.is_subdomain(domain):
                continue
            zonefile.write(mappings[(name, rdtype)].to_text() + '\n')
        zonefile.close()
        return cls(domain, zonefile.name)

    def _cleanup_process(self):
        if self.pid is not None:
            try:
                os.kill(self.pid, signal.SIGTERM)
            except OSError:
                pass
            else:
                time.sleep(1.0)
                try:
                    os.kill(self.pid, signal.SIGKILL)
                except OSError:
                    pass

        if self.working_dir is not None:
            shutil.rmtree(self.working_dir)

    def serve(self):
        self.working_dir = tempfile.mkdtemp(prefix='dnsviz')
        env = { 'PATH': '%s:/sbin:/usr/sbin:/usr/local/sbin' % (os.environ.get('PATH', '')) }

        args = { 'dir': self.working_dir, 'port': self.port,
                'zone_name': lb2s(self.domain.to_text()),
                'zone_file': os.path.abspath(self.filename) }
        args['named_conf'] = self.NAMED_CONF % args
        args['named_pid'] = self.NAMED_PID % args
        args['named_log'] = self.NAMED_LOG % args

        named_conf_contents = self.NAMED_CONF_TEMPLATE % args
        io.open(args['named_conf'], 'w', encoding='utf-8').write(named_conf_contents)
        try:
            p = subprocess.Popen([self.NAMED_CHECKCONF, '-z', args['named_conf']],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
        except OSError as e:
            self._cleanup_process()
            raise MissingExecutablesError('The options used require %s.  Please ensure that it is installed and in PATH (%s).' % (self.NAMED_CHECKCONF, e))

        (stdout, stderr) = p.communicate()
        if p.returncode != 0:
            stdout = stdout.decode('utf-8')
            self._cleanup_process()
            raise ZoneFileServiceError('There was an problem with the zone file for "%s":\n%s' % (args['zone_name'], stdout))

        named_cmd_without_log = [self.NAMED, '-c', args['named_conf']]
        named_cmd_with_log = named_cmd_without_log + ['-L', args['named_log']]
        checked_usage = False
        for named_cmd in (named_cmd_with_log, named_cmd_without_log):
            try:
                p = subprocess.Popen(named_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
            except OSError as e:
                self._cleanup_process()
                raise MissingExecutablesError('The options used require %s.  Please ensure that it is installed and in PATH (%s).' % (self.NAMED, e))

            (stdout, stderr) = p.communicate()
            if p.returncode == 0:
                break

            stdout = stdout.decode('utf-8')
            if not checked_usage and self.USAGE_RE.search(stdout):
                # Versions of BIND pre 9.11 don't support -L, so fall back to without -L
                checked_usage = True
                continue

            try:
                with io.open(args['named_log'], 'r', encoding='utf-8') as fh:
                    log = fh.read()
            except IOError as e:
                log = ''
            if not log:
                log = stdout
            self._cleanup_process()
            raise ZoneFileServiceError('There was an problem executing %s to serve the "%s" zone:\n%s' % (self.NAMED, args['zone_name'], log))

        try:
            with io.open(args['named_pid'], 'r', encoding='utf-8') as fh:
                self.pid = int(fh.read())
        except (IOError, ValueError) as e:
            self._cleanup_process()
            raise ZoneFileServiceError('There was an problem detecting the process ID for %s: %s' % (self.NAMED, e))

        atexit.register(self._cleanup_process)

class NameServerMappingsForDomain(object):
    PORT_RE = re.compile(r'^(.*):(\d+)$')
    BRACKETS_RE = re.compile(r'^\[(.*)\]$')

    DEFAULT_PORT = 53
    DYN_LABEL = '_dnsviz'

    _allow_file = None
    _allow_name_only = None
    _allow_addr_only = None
    _allow_stop_at = None
    _handle_file_arg = None

    def __init__(self, domain, stop_at, resolver):
        if not (self._allow_file is not None and \
                self._allow_name_only is not None and \
                self._allow_addr_only is not None and \
                self._allow_stop_at is not None and \
                (not self._allow_file or self._handle_file_arg is not None)):
            raise NotImplemented

        if stop_at and not self._allow_stop_at:
            raise argparse.ArgumentTypeError('The "+" may not be specified with this option')

        self.domain = domain
        self._resolver = resolver
        self._nsi = 1

        self.delegation_mapping = {}
        self.stop_at = stop_at
        self.odd_ports = {}
        self.filename = None

        self.delegation_mapping[(self.domain, dns.rdatatype.NS)] = dns.rrset.RRset(self.domain, dns.rdataclass.IN, dns.rdatatype.NS)

    @classmethod
    def _strip_port(cls, s):
        # Determine whether there is a port attached to the end
        match = cls.PORT_RE.search(s)
        if match is not None:
            s = match.group(1)
            port = int(match.group(2))
        else:
            port = None
        return s, port

    def handle_list_arg(self, name_addr_arg):
        name_addr_arg = name_addr_arg.strip()

        # if the value is actually a path, then check it as a zone file
        if os.path.isfile(name_addr_arg):
            if not self._allow_file:
                raise argparse.ArgumentTypeError('A filename may not be specified with this option')
            self._handle_file_arg(name_addr_arg)
        else:
            self._handle_name_addr_list(name_addr_arg)

    def _handle_name_addr_list(self, name_addr_list):
        for name_addr in name_addr_list.split(','):
            self._handle_name_addr_mapping(name_addr)

    def _handle_name_no_addr(self, name, port):
        query_tuples = ((name, dns.rdatatype.A, dns.rdataclass.IN), (name, dns.rdatatype.AAAA, dns.rdataclass.IN))
        answer_map = self._resolver.query_multiple_for_answer(*query_tuples)
        found_answer = False
        for (n, rdtype, rdclass) in answer_map:
            a = answer_map[(n, rdtype, rdclass)]
            if isinstance(a, DNSAnswer):
                found_answer = True
                if (name, rdtype) not in self.delegation_mapping:
                    self.delegation_mapping[(name, rdtype)] = dns.rrset.RRset(name, dns.rdataclass.IN, rdtype)
                if rdtype == dns.rdatatype.A:
                    rdtype_cls = dns.rdtypes.IN.A.A
                else:
                    rdtype_cls = dns.rdtypes.IN.AAAA.AAAA
                for rdata in a.rrset:
                    self.delegation_mapping[(name, rdtype)].add(rdtype_cls(dns.rdataclass.IN, rdtype, rdata.address))

                    if port is not None and port != self.DEFAULT_PORT:
                        self.odd_ports[(self.domain, IPAddr(rdata.address))] = port

            # negative responses
            elif isinstance(a, (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)):
                pass
            # error responses
            elif isinstance(a, (dns.exception.Timeout, dns.resolver.NoNameservers)):
                pass

        if not found_answer:
            raise argparse.ArgumentTypeError('"%s" could not be resolved to an address.  Please specify an address or use a name that resolves properly.' % fmt.humanize_name(name))

    def _handle_name_with_addr(self, name, addr, port):
        if addr.version == 6:
            rdtype = dns.rdatatype.AAAA
            rdtype_cls = dns.rdtypes.IN.AAAA.AAAA
        else:
            rdtype = dns.rdatatype.A
            rdtype_cls = dns.rdtypes.IN.A.A
        if (name, rdtype) not in self.delegation_mapping:
            self.delegation_mapping[(name, rdtype)] = dns.rrset.RRset(name, dns.rdataclass.IN, rdtype)
        self.delegation_mapping[(name, rdtype)].add(rdtype_cls(dns.rdataclass.IN, rdtype, addr))

        if port is not None and port != self.DEFAULT_PORT:
            self.odd_ports[(self.domain, addr)] = port

    def _handle_name_addr_mapping(self, name_addr):
        name_addr = name_addr.strip()
        name, addr, port = self._parse_name_addr(name_addr)

        if not name and not self._allow_addr_only:
            raise argparse.ArgumentTypeError('A domain name must accompany the address')
        if not addr and not self._allow_name_only:
            raise argparse.ArgumentTypeError('An address must accompany the domain name name')

        name = self._format_name(name)
        addr = self._format_addr(addr)

        # Add the name to the NS RRset
        self.delegation_mapping[(self.domain, dns.rdatatype.NS)].add(dns.rdtypes.ANY.NS.NS(dns.rdataclass.IN, dns.rdatatype.NS, name))

        if not addr:
            self._handle_name_no_addr(name, port)
        else:
            self._handle_name_with_addr(name, addr, port)

    def _create_name(self):
        # value is an address
        name = 'ns%d.%s.%s' % (self._nsi, self.DYN_LABEL, lb2s(self.domain.canonicalize().to_text()))
        self._nsi += 1
        return name

    def _format_name(self, name):
        if name is None:
            name = self._create_name()
        try:
            name = dns.name.from_text(name)
        except dns.exception.DNSException:
            raise argparse.ArgumentTypeError('The domain name was invalid: "%s"' % name)
        return name

    def _format_addr(self, addr):
        if addr is not None:
            addr, num_sub = self.BRACKETS_RE.subn(r'\1', addr)
            try:
                addr = IPAddr(addr)
            except ValueError:
                raise argparse.ArgumentTypeError('The IP address was invalid: "%s"' % addr)

            if addr.version == 6 and num_sub < 1:
                raise argparse.ArgumentTypeError('Brackets are required around IPv6 addresses.')
        return addr

    def _parse_name_addr(self, name_addr):
        # 1. Strip an optional port off the end
        name_addr_orig = name_addr
        name_addr, port = self._strip_port(name_addr)

        # 2. Now determine whether the argument is a) a single value--either
        #    name or addr--or b) a name-addr mapping
        try:
            name, addr = name_addr.split('=', 1)
        except ValueError:
            # a) Argument is either a name or an address, not a mapping;
            # Now, determine which it is.
            try:
                IPAddr(self.BRACKETS_RE.sub(r'\1', name_addr))
            except ValueError:
                # a1. It is not a valid address.  Maybe.  See if the address
                #     was valid with the port re-appended.
                try:
                    IPAddr(self.BRACKETS_RE.sub(r'\1', name_addr_orig))
                except ValueError:
                    # a2. Even with the port, the address is not valid, so the
                    #     must be a name instead of an address.  Validity of
                    #     the name will be checked later.
                    name = name_addr
                    addr = None
                else:
                    # a3. When considering the address with the port, the
                    #     address is valid, so it is in fact an address.
                    #     Re-append the port to make the address valid, and 
                    #     cancel the port.
                    name = None
                    addr = name_addr_orig
                    port = None
            else:
                # a4. Value was a valid address.
                name = None
                addr = name_addr

        else:
            # b) Argument is a name-addr mapping.  Now, determine whether
            #    removing the port was the right thing.
            name = name.strip()
            addr = addr.strip()

            if port is None:
                addr_orig = addr
            else:
                addr_orig = '%s:%d' % (addr, port)

            try:
                IPAddr(self.BRACKETS_RE.sub(r'\1', addr))
            except ValueError:
                # b1. Without the port, addr is not a valid address.  See if
                #     things change when we re-append the port.
                try:
                    IPAddr(self.BRACKETS_RE.sub(r'\1', addr_orig))
                except ValueError:
                    # b2. Even with the port, the address is not valid, so it
                    #     doesn't matter if we leave the port on or off;
                    #     address invalidity will be reported later.
                    pass
                else:
                    # b3. When considering the address with the port, the
                    #     address is valid, so re-append the port to make the
                    #     address valid, and cancel the port.
                    addr = addr_orig
                    port = None
            else:
                # b4. Value was a valid address, so no need to do anything
                pass

        return name, addr, port

    def _set_filename(self, filename):
        self.filename = filename

    def _extract_delegation_info_from_file(self, filename):
        # if this is a file containing delegation records, then read the
        # file, create a name=value string, and call name_addrs_from_string()
        try:
            with io.open(filename, 'r', encoding='utf-8') as fh:
                file_contents = fh.read()
        except IOError as e:
            raise argparse.ArgumentTypeError('%s: "%s"' % (e.strerror, filename))

        try:
            m = dns.message.from_text(str(';ANSWER\n' + file_contents))
        except dns.exception.DNSException as e:
            raise argparse.ArgumentTypeError('Error reading delegation records from %s: "%s"' % (filename, e))

        try:
            ns_rrset = m.find_rrset(m.answer, self.domain, dns.rdataclass.IN, dns.rdatatype.NS)
        except KeyError:
            raise argparse.ArgumentTypeError('No NS records for %s found in %s' % (lb2s(self.domain.canonicalize().to_text()), filename))

        for rdata in ns_rrset:
            a_rrsets = [r for r in m.answer if r.name == rdata.target and r.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA)]
            if not a_rrsets or not rdata.target.is_subdomain(self.domain.parent()):
                name_addr = lb2s(rdata.target.canonicalize().to_text())
            else:
                for a_rrset in a_rrsets:
                    for a_rdata in a_rrset:
                        name_addr = '%s=[%s]' % (lb2s(rdata.target.canonicalize().to_text()), a_rdata.address)
            self._handle_name_addr_mapping(name_addr)

class DelegationNameServerMappingsForDomain(NameServerMappingsForDomain):
    _allow_file = True
    _allow_name_only = False
    _allow_addr_only = False
    _allow_stop_at = False
    _handle_file_arg = NameServerMappingsForDomain._extract_delegation_info_from_file

    def __init__(self, *args, **kwargs):
        super(DelegationNameServerMappingsForDomain, self).__init__(*args, **kwargs)
        if self.domain == dns.name.root:
            raise argparse.ArgumentTypeError('The root domain may not specified with this option.')

class AuthoritativeNameServerMappingsForDomain(NameServerMappingsForDomain):
    _allow_file = True
    _allow_name_only = True
    _allow_addr_only = True
    _allow_stop_at = True
    _handle_file_arg = NameServerMappingsForDomain._set_filename

class RecursiveServersForDomain(NameServerMappingsForDomain):
    _allow_file = False
    _allow_name_only = True
    _allow_addr_only = True
    _allow_stop_at = False
    _handle_file_arg = None

class DSForDomain:
    def __init__(self, domain, stop_at, resolver):
        self.domain = domain

        if stop_at and not self._allow_stop_at:
            raise argparse.ArgumentTypeError('The "+" may not be specified with this option')

        self.delegation_mapping = {}
        self.delegation_mapping[(self.domain, dns.rdatatype.DS)] = dns.rrset.RRset(self.domain, dns.rdataclass.IN, dns.rdatatype.DS)

    def _extract_ds_info_from_file(self, filename):
        # if this is a file containing delegation records, then read the
        # file, create a name=value string, and call name_addrs_from_string()
        try:
            with io.open(filename, 'r', encoding='utf-8') as fh:
                file_contents = fh.read()
        except IOError as e:
            raise argparse.ArgumentTypeError('%s: "%s"' % (e.strerror, filename))

        try:
            m = dns.message.from_text(str(';ANSWER\n' + file_contents))
        except dns.exception.DNSException as e:
            raise argparse.ArgumentTypeError('Error reading DS records from %s: "%s"' % (filename, e))

        try:
            ds_rrset = m.find_rrset(m.answer, self.domain, dns.rdataclass.IN, dns.rdatatype.DS)
        except KeyError:
            raise argparse.ArgumentTypeError('No DS records for %s found in %s' % (lb2s(self.domain.canonicalize().to_text()), filename))

        for rdata in ds_rrset:
            self.delegation_mapping[(self.domain, dns.rdatatype.DS)].add(rdata)

    def _handle_ds(self, ds):
        ds = ds.strip()

        try:
            self.delegation_mapping[(self.domain, dns.rdatatype.DS)].add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, ds))
        except dns.exception.DNSException as e:
            raise argparse.ArgumentTypeError('Error parsing DS records: %s\n%s' % (e, ds))

    def _handle_ds_list(self, ds_list):
        for ds in ds_list.split(','):
            self._handle_ds(ds)

    def handle_list_arg(self, ds_arg):
        ds_arg = ds_arg.strip()

        # if the value is actually a path, then check it as a zone file
        if os.path.isfile(ds_arg):
            self._extract_ds_info_from_file(ds_arg)
        else:
            self._handle_ds_list(ds_arg)

class DomainListArgHelper:
    STOP_RE = re.compile(r'^(.*)\+$')

    def __init__(self, resolver):
        self._resolver = resolver
    
    @classmethod
    def _strip_stop_marker(cls, s):
        match = cls.STOP_RE.search(s)
        if match is not None:
            s = match.group(1)
            stop_at = True
        else:
            stop_at = False

        return s, stop_at

    def _parse_domain_list(self, domain_item_list):
        try:
            domain, item_list = domain_item_list.split(':', 1)
        except ValueError:
            raise argparse.ArgumentTypeError('Option expects both a domain and servers for that domain')

        domain = domain.strip()
        domain, stop_at = self._strip_stop_marker(domain)

        return domain, item_list, stop_at

    def _handle_domain_list_arg(self, cls, domain_list_arg):
        domain, list_arg, stop_at = self._parse_domain_list(domain_list_arg)

        if domain is not None:
            domain = domain.strip()
            try:
                domain = dns.name.from_text(domain)
            except dns.exception.DNSException:
                raise argparse.ArgumentTypeError('The domain name was invalid: "%s"' % domain)

        if list_arg is not None:
            list_arg = list_arg.strip()

        obj = cls(domain, stop_at, self._resolver)

        if list_arg:
            obj.handle_list_arg(list_arg)
        return obj

    def _handle_list_arg(self, cls, list_arg):
        obj = cls(WILDCARD_EXPLICIT_DELEGATION, False, self._resolver)
        obj.handle_list_arg(list_arg)
        return obj

    def delegation_name_server_mappings(self, arg):
        return self._handle_domain_list_arg(DelegationNameServerMappingsForDomain, arg)

    def authoritative_name_server_mappings(self, arg):
        return self._handle_domain_list_arg(AuthoritativeNameServerMappingsForDomain, arg)

    def recursive_servers_for_domain(self, arg):
        return self._handle_list_arg(RecursiveServersForDomain, arg)

    def ds_for_domain(self, arg):
        return self._handle_domain_list_arg(DSForDomain, arg)

class ArgHelper:
    BRACKETS_RE = re.compile(r'^\[(.*)\]$')

    def __init__(self, resolver, logger):
        self._resolver = resolver
        self.parser = None

        self.odd_ports = {}
        self.stop_at = {}
        self.explicit_delegations = {}
        self.ceiling = None
        self.explicit_only = None
        self.try_ipv4 = None
        self.try_ipv6 = None
        self.client_ipv4 = None
        self.client_ipv6 = None
        self.edns_diagnostics = None
        self.th_factories = None
        self.processes = None
        self.dlv_domain = None
        self.meta_only = None
        self.cache_level = None
        self.names = None
        self.analysis_structured = None

        self.args = None
        self._arg_mapping = None

        self._resolver = resolver
        self._logger = logger
        self._zones_to_serve = []

    def build_parser(self, prog):
        self.parser = argparse.ArgumentParser(description='Issue diagnostic DNS queries', prog=prog)
        helper = DomainListArgHelper(self._resolver)

        # python3/python2 dual compatibility
        stdout_buffer = io.open(sys.stdout.fileno(), 'wb', closefd=False)

        try:
            self.parser.add_argument('-f', '--names-file',
                    type=argparse.FileType('r', encoding='utf-8'),
                    action='store', metavar='<filename>',
                    help='Read names from a file')
        except TypeError:
            # this try/except is for
            # python3/python2 dual compatibility
            self.parser.add_argument('-f', '--names-file',
                    type=argparse.FileType('r'),
                    action='store', metavar='<filename>',
                    help='Read names from a file')
        self.parser.add_argument('-d', '--debug',
                type=int, choices=range(4), default=2,
                action='store', metavar='<level>',
                help='Set debug level')
        try:
            self.parser.add_argument('-r', '--input-file',
                    type=argparse.FileType('r', encoding='utf-8'),
                    action='store', metavar='<filename>',
                    help='Read diagnostic queries from a file')
        except TypeError:
            # this try/except is for
            # python3/python2 dual compatibility
            self.parser.add_argument('-r', '--input-file',
                    type=argparse.FileType('r'),
                    action='store', metavar='<filename>',
                    help='Read diagnostic queries from a file')
        self.parser.add_argument('-t', '--threads',
                type=self.positive_int, default=1,
                action='store', metavar='<threads>',
                help='Use the specified number of threads for parallel queries')
        self.parser.add_argument('-4', '--ipv4',
                const=True, default=False,
                action='store_const',
                help='Use IPv4 only')
        self.parser.add_argument('-6', '--ipv6',
                const=True, default=False,
                action='store_const',
                help='Use IPv6 only')
        self.parser.add_argument('-b', '--source-ip',
                type=self.bindable_ip, default=[],
                action='append', metavar='<address>',
                help='Use the specified source IPv4 or IPv6 address for queries')
        self.parser.add_argument('-u', '--looking-glass-url',
                type=self.valid_url,
                action='append', metavar='<url>',
                help='Issue queries through the DNS looking glass at the specified URL')
        self.parser.add_argument('-k', '--insecure',
                const=True, default=False,
                action='store_const',
                help='Do not verify the TLS certificate for a DNS looking glass using HTTPS')
        self.parser.add_argument('-a', '--ancestor',
                type=self.valid_domain_name, default=None,
                action='store', metavar='<ancestor>',
                help='Query the ancestry of each domain name through the specified ancestor')
        self.parser.add_argument('-R', '--rr-types',
                type=self.comma_separated_dns_types,
                action='store', metavar='<type>,[<type>...]',
                help='Issue queries for only the specified type(s) during analysis')
        self.parser.add_argument('-s', '--recursive-servers',
                type=helper.recursive_servers_for_domain, default=[],
                action='append', metavar='<server>[,<server>...]',
                help='Query the specified recursive server(s)')
        self.parser.add_argument('-A', '--authoritative-analysis',
                const=True, default=False,
                action='store_const',
                help='Query authoritative servers, instead of recursive servers')
        self.parser.add_argument('-x', '--authoritative-servers',
                type=helper.authoritative_name_server_mappings, default=[],
                action='append', metavar='<domain>[+]:<server>[,<server>...]',
                help='Query the specified authoritative servers for a domain')
        self.parser.add_argument('-N', '--delegation-information',
                type=helper.delegation_name_server_mappings, default=[],
                action='append', metavar='<domain>:<server>[,<server>...]',
                help='Use the specified delegation information for a domain')
        self.parser.add_argument('-D', '--ds',
                type=helper.ds_for_domain, default=[],
                action='append', metavar='<domain>:"<ds>"[,"<ds>"...]',
                help='Use the specified DS records for a domain')
        self.parser.add_argument('-n', '--nsid',
                const=self.nsid_option(),
                action='store_const',
                help='Use the NSID EDNS option in queries')
        self.parser.add_argument('-e', '--client-subnet',
                type=self.ecs_option,
                action='store', metavar='<subnet>[:<prefix_len>]',
                help='Use the DNS client subnet option with the specified subnet and prefix length in queries')
        self.parser.add_argument('-c', '--cookie',
                type=self.dns_cookie_option, default=self.dns_cookie_rand(),
                action='store', metavar='<cookie>',
                help='Use the specified DNS cookie value in queries')
        self.parser.add_argument('-E', '--edns',
                const=True, default=False,
                action='store_const',
                help='Issue queries to check EDNS compatibility')
        self.parser.add_argument('-o', '--output-file',
                type=argparse.FileType('wb'), default=stdout_buffer,
                action='store', metavar='<filename>',
                help='Save the output to the specified file')
        self.parser.add_argument('-p', '--pretty-output',
                const=True, default=False,
                action='store_const',
                help='Format JSON output with indentation and newlines')
        self.parser.add_argument('domain_name',
                type=self.valid_domain_name,
                action='store', nargs='*', metavar='<domain_name>',
                help='Domain names')

        self._arg_mapping = dict([(a.dest, '/'.join(a.option_strings)) for a in self.parser._actions])

    def parse_args(self, args):
        self.args = self.parser.parse_args(args)

    @classmethod
    def positive_int(cls, arg):
        try:
            val = int(arg)
        except ValueError:
            msg = "The argument must be a positive integer: %s" % val
            raise argparse.ArgumentTypeError(msg)
        else:
            if val < 1:
                msg = "The argument must be a positive integer: %d" % val
                raise argparse.ArgumentTypeError(msg)
        return val

    @classmethod
    def bindable_ip(cls, arg):
        try:
            addr = IPAddr(cls.BRACKETS_RE.sub(r'\1', arg))
        except ValueError:
            raise argparse.ArgumentTypeError('The IP address was invalid: "%s"' % arg)
        if addr.version == 4:
            fam = socket.AF_INET
        else:
            fam = socket.AF_INET6
        try:
            s = socket.socket(fam)
            s.bind((addr, 0))
        except socket.error as e:
            if e.errno == errno.EADDRNOTAVAIL:
                raise argparse.ArgumentTypeError('Cannot bind to specified IP address: "%s"' % addr)
        finally:
            s.close()
        return addr

    @classmethod
    def valid_url(cls, arg):
        url = urlparse.urlparse(arg)
        if url.scheme not in ('http', 'https', 'ws', 'ssh'):
            raise argparse.ArgumentTypeError('Unsupported URL scheme: "%s"' % url.scheme)

        # check that version is >= 2.7.9 if HTTPS is requested
        if url.scheme == 'https':
            vers0, vers1, vers2 = sys.version_info[:3]
            if (2, 7, 9) > (vers0, vers1, vers2):
                raise argparse.ArgumentTypeError('Python version >= 2.7.9 is required to use a DNS looking glass with HTTPS.')

        elif url.scheme == 'ws':
            if url.hostname is not None:
                raise argparse.ArgumentTypeError('WebSocket URL must designate a local UNIX domain socket.')

        return arg

    @classmethod
    def comma_separated_dns_types(cls, arg):
        rdtypes = []
        arg = arg.strip()
        if not arg:
            return rdtypes
        for r in arg.split(','):
            try:
                rdtypes.append(dns.rdatatype.from_text(r.strip()))
            except dns.rdatatype.UnknownRdatatype:
                raise argparse.ArgumentTypeError('Invalid resource record type: %s' % (r))
        return rdtypes

    @classmethod
    def valid_domain_name(cls, arg):
        # python3/python2 dual compatibility
        if isinstance(arg, bytes):
            arg = codecs.decode(arg, sys.getfilesystemencoding())
        try:
            return dns.name.from_text(arg)
        except dns.exception.DNSException:
            raise argparse.ArgumentTypeError('Invalid domain name: "%s"' % arg)

    @classmethod
    def nsid_option(cls):
        return dns.edns.GenericOption(dns.edns.NSID, b'')

    @classmethod
    def ecs_option(cls, arg):
        try:
            addr, prefix_len = arg.split('/', 1)
        except ValueError:
            addr = arg
            prefix_len = None

        try:
            addr = IPAddr(addr)
        except ValueError:
            raise argparse.ArgumentTypeError('The IP address was invalid: "%s"' % addr)

        if addr.version == 4:
            addrlen = 4
            family = 1
        else:
            addrlen = 16
            family = 2

        if prefix_len is None:
            prefix_len = addrlen << 3
        else:
            try:
                prefix_len = int(prefix_len)
            except ValueError:
                raise argparse.ArgumentTypeError('The prefix length was invalid: "%s"' % prefix_len)

            if prefix_len < 0 or prefix_len > (addrlen << 3):
                raise argparse.ArgumentTypeError('The prefix length was invalid: "%d"' % prefix_len)

        bytes_masked, remainder = divmod(prefix_len, 8)

        wire = struct.pack(b'!H', family)
        wire += struct.pack(b'!B', prefix_len)
        wire += struct.pack(b'!B', 0)
        wire += addr._ipaddr_bytes[:bytes_masked]
        if remainder:
            # python3/python2 dual compatibility
            byte = addr._ipaddr_bytes[bytes_masked]
            if isinstance(addr._ipaddr_bytes, str):
                byte = ord(byte)

            mask = ~(2**(8 - remainder)-1)
            wire += struct.pack('B', mask & byte)

        return dns.edns.GenericOption(8, wire)

    @classmethod
    def dns_cookie_option(cls, arg):
        if not arg:
            return None

        try:
            cookie = binascii.unhexlify(arg)
        except (binascii.Error, TypeError):
            raise argparse.ArgumentTypeError('The DNS cookie provided was not valid hexadecimal: "%s"' % arg)

        if len(cookie) != 8:
            raise argparse.ArgumentTypeError('The DNS client cookie provided had a length of %d, but only a length of %d is valid .' % (len(cookie), 8))

        return dns.edns.GenericOption(10, cookie)

    @classmethod
    def dns_cookie_rand(cls):
        r = random.getrandbits(64)
        cookie = struct.pack(b'Q', r)
        return cls.dns_cookie_option(binascii.hexlify(cookie))

    def aggregate_delegation_info(self):
        localhost = dns.name.from_text('localhost')
        try:
            self.bindable_ip('::1')
        except argparse.ArgumentTypeError:
            use_ipv6_loopback = False
            loopback = IPAddr('127.0.0.1')
            loopback_rdtype = dns.rdatatype.A
            loopback_rdtype_cls = dns.rdtypes.IN.A.A
        else:
            use_ipv6_loopback = True
            loopback = IPAddr('::1')
            loopback_rdtype = dns.rdatatype.AAAA
            loopback_rdtype_cls = dns.rdtypes.IN.AAAA.AAAA

        self.rdclass = dns.rdataclass.IN

        for arg in self.args.recursive_servers + self.args.authoritative_servers:
            zone_name = arg.domain
            for name, rdtype in arg.delegation_mapping:
                if (name, rdtype) not in self.explicit_delegations:
                    self.explicit_delegations[(name, rdtype)] = arg.delegation_mapping[(name, rdtype)]
                else:
                    self.explicit_delegations[(name, rdtype)].update(arg.delegation_mapping[(name, rdtype)])
            self.odd_ports.update(arg.odd_ports)
            self.stop_at[arg.domain] = arg.stop_at
            if arg.filename is not None:
                zone = ZoneFileToServe(arg.domain, arg.filename)
                self._zones_to_serve.append(zone)
                self.explicit_delegations[(zone_name, dns.rdatatype.NS)].add(dns.rdtypes.ANY.NS.NS(dns.rdataclass.IN, dns.rdatatype.NS, localhost))
                self.explicit_delegations[(localhost, loopback_rdtype)] = dns.rrset.RRset(localhost, dns.rdataclass.IN, loopback_rdtype)
                self.explicit_delegations[(localhost, loopback_rdtype)].add(loopback_rdtype_cls(dns.rdataclass.IN, loopback_rdtype, loopback))
                self.odd_ports[(zone_name, loopback)] = zone.port

        delegation_info_by_zone = OrderedDict()
        for arg in self.args.ds + self.args.delegation_information:
            zone_name = arg.domain.parent()
            if (zone_name, dns.rdatatype.NS) in self.explicit_delegations:
                raise argparse.ArgumentTypeError('Cannot use "' + lb2s(zone_name.to_text()) + '" with %(authoritative_servers)s if a child zone is specified with %(delegation_information)s' % self._arg_mapping)
            if zone_name not in delegation_info_by_zone:
                delegation_info_by_zone[zone_name] = {}
            for name, rdtype in arg.delegation_mapping:
                if (name, rdtype) not in delegation_info_by_zone[zone_name]:
                    delegation_info_by_zone[zone_name][(name, rdtype)] = arg.delegation_mapping[(name, rdtype)]
                else:
                    delegation_info_by_zone[zone_name][(name, rdtype)].update(arg.delegation_mapping[(name, rdtype)])

        for zone_name in delegation_info_by_zone:
            zone = ZoneFileToServe.from_mappings(zone_name, delegation_info_by_zone[zone_name], use_ipv6_loopback)
            self._zones_to_serve.append(zone)
            self.explicit_delegations[(zone_name, dns.rdatatype.NS)] = dns.rrset.RRset(zone_name, dns.rdataclass.IN, dns.rdatatype.NS)
            self.explicit_delegations[(zone_name, dns.rdatatype.NS)].add(dns.rdtypes.ANY.NS.NS(dns.rdataclass.IN, dns.rdatatype.NS, localhost))
            self.explicit_delegations[(localhost, loopback_rdtype)] = dns.rrset.RRset(localhost, dns.rdataclass.IN, loopback_rdtype)
            self.explicit_delegations[(localhost, loopback_rdtype)].add(loopback_rdtype_cls(dns.rdataclass.IN, loopback_rdtype, loopback))
            self.odd_ports[(zone_name, loopback)] = zone.port
            self.stop_at[zone_name] = True

    def populate_recursive_servers(self):
        if not self.args.authoritative_analysis and not self.args.recursive_servers:
            if (WILDCARD_EXPLICIT_DELEGATION, dns.rdatatype.NS) not in self.explicit_delegations:
                self.explicit_delegations[(WILDCARD_EXPLICIT_DELEGATION, dns.rdatatype.NS)] = dns.rrset.RRset(WILDCARD_EXPLICIT_DELEGATION, dns.rdataclass.IN, dns.rdatatype.NS)
            for i, server in enumerate(self._resolver._servers):
                if IPAddr(server).version == 6:
                    rdtype = dns.rdatatype.AAAA
                else:
                    rdtype = dns.rdatatype.A
                name = dns.name.from_text('ns%d' % i)
                self.explicit_delegations[(WILDCARD_EXPLICIT_DELEGATION, dns.rdatatype.NS)].add(dns.rdtypes.ANY.NS.NS(dns.rdataclass.IN, dns.rdatatype.NS, name))
                if (name, rdtype) not in self.explicit_delegations:
                    self.explicit_delegations[(name, rdtype)] = dns.rrset.RRset(name, dns.rdataclass.IN, rdtype)
                self.explicit_delegations[(name, rdtype)].add(dns.rdata.from_text(dns.rdataclass.IN, rdtype, server))

    def check_args(self):
        if not self.args.names_file and not self.args.domain_name and not self.args.input_file:
            raise argparse.ArgumentTypeError('If no domain names are supplied as command-line arguments, then either %(input_file)s or %(names_file)s must be used.' % \
                    self._arg_mapping)
        if self.args.names_file and self.args.domain_name:
            raise argparse.ArgumentTypeError('If %(names_file)s is used, then domain names may not supplied as command line arguments.' % \
                    self._arg_mapping)
        if self.args.authoritative_analysis and self.args.recursive_servers:
            raise argparse.ArgumentTypeError('If %(authoritative_analysis)s is used, then %(recursive_servers)s cannot be used.' % \
                    self._arg_mapping)
        if self.args.authoritative_servers and not self.args.authoritative_analysis:
            raise argparse.ArgumentTypeError('%(authoritative_servers)s may only be used in conjunction with %(authoritative_analysis)s.' % \
                    self._arg_mapping)
        if self.args.delegation_information and not self.args.authoritative_analysis:
            raise argparse.ArgumentTypeError('%(delegation_information)s may only be used in conjunction with %(authoritative_analysis)s.' % \
                    self._arg_mapping)
        if self.args.ds and not self.args.delegation_information:
            raise argparse.ArgumentTypeError('%(ds)s may only be used in conjunction with %(delegation_information)s.' % \
                    self._arg_mapping)

    def set_kwargs(self):
        if self.args.ancestor is not None:
            self.ceiling = self.args.ancestor
        elif self.args.authoritative_analysis:
            self.ceiling = None
        else:
            self.ceiling = dns.name.root

        if self.args.rr_types is not None:
            self.explicit_only = True
        else:
            self.explicit_only = False

        # if both are specified or neither is specified, then they're both tried
        if (self.args.ipv4 and self.args.ipv6) or \
                (not self.args.ipv4 and not self.args.ipv6):
            self.try_ipv4 = True
            self.try_ipv6 = True
        # if one or the other is specified, then only the one specified is
        # tried
        else:
            if self.args.ipv4:
                self.try_ipv4 = True
                self.try_ipv6 = False
            else: # self.args.ipv6
                self.try_ipv4 = False
                self.try_ipv6 = True

        for ip in self.args.source_ip:
            if ip.version == 4:
                self.client_ipv4 = ip
            else:
                self.client_ipv6 = ip

        if self.args.looking_glass_url:
            self.th_factories = []
            for looking_glass_url in self.args.looking_glass_url:
                url = urlparse.urlparse(looking_glass_url)
                if url.scheme in ('http', 'https'):
                    self.th_factories.append(transport.DNSQueryTransportHandlerHTTPFactory(looking_glass_url, insecure=self.args.insecure))
                elif url.scheme == 'ws':
                    self.th_factories.append(transport.DNSQueryTransportHandlerWebSocketServerFactory(url.path))
                elif url.scheme == 'ssh':
                    self.th_factories.append(transport.DNSQueryTransportHandlerRemoteCmdFactory(looking_glass_url))
        else:
            self.th_factories = None

        # the following options are not documented in usage, because they don't
        # apply to most users
        #if args.dlv is not None:
        #    dlv_domain = args.dlv
        #else:
        #    dlv_domain = None
        #try:
        #    cache_level = int(opts['-C'])
        #except (KeyError, ValueError):
        #    cache_level = None
        self.dlv_domain = None
        self.cache_level = None
        self.meta_only = None

        if self.args.client_subnet:
            CustomQueryMixin.edns_options.append(self.args.client_subnet)
        if self.args.nsid:
            CustomQueryMixin.edns_options.append(self.args.nsid)
        if self.args.cookie:
            CustomQueryMixin.edns_options.append(self.args.cookie)

    def set_buffers(self):
        # This entire method is for
        # python3/python2 dual compatibility
        if self.args.input_file is not None:
            if self.args.input_file.fileno() == sys.stdin.fileno():
                filename = self.args.input_file.fileno()
            else:
                filename = self.args.input_file.name
                self.args.input_file.close()
            self.args.input_file = io.open(filename, 'r', encoding='utf-8')
        if self.args.names_file is not None:
            if self.args.names_file.fileno() == sys.stdin.fileno():
                filename = self.args.names_file.fileno()
            else:
                filename = self.args.names_file.name
                self.args.names_file.close()
            self.args.names_file = io.open(filename, 'r', encoding='utf-8')
        if self.args.output_file is not None:
            if self.args.output_file.fileno() == sys.stdout.fileno():
                filename = self.args.output_file.fileno()
            else:
                filename = self.args.output_file.name
                self.args.output_file.close()
            self.args.output_file = io.open(filename, 'wb')

    def check_network_connectivity(self):
        if self.args.authoritative_analysis:
            if self.try_ipv4 and get_client_address(A_ROOT_IPV4) is None:
                self._logger.warning('No global IPv4 connectivity detected')
            if self.try_ipv6 and get_client_address(A_ROOT_IPV6) is None:
                self._logger.warning('No global IPv6 connectivity detected')

    def get_log_level(self):
        if self.args.debug > 2:
            return logging.DEBUG
        elif self.args.debug > 1:
            return logging.INFO
        elif self.args.debug > 0:
            return logging.WARNING
        else:
            return logging.ERROR

    def ingest_input(self):
        if not self.args.input_file:
            return

        analysis_str = self.args.input_file.read()
        if not analysis_str:
            if self.args.input_file.fileno() != sys.stdin.fileno():
                raise AnalysisInputError('No input')
            else:
                raise AnalysisInputError()
        try:
            self.analysis_structured = json.loads(analysis_str)
        except ValueError:
            raise AnalysisInputError('There was an error parsing the JSON input: "%s"' % self.args.input_file.name)

        # check version
        if '_meta._dnsviz.' not in self.analysis_structured or 'version' not in self.analysis_structured['_meta._dnsviz.']:
            raise AnalysisInputError('No version information in JSON input: "%s"' % self.args.input_file.name)
        try:
            major_vers, minor_vers = [int(x) for x in str(self.analysis_structured['_meta._dnsviz.']['version']).split('.', 1)]
        except ValueError:
            raise AnalysisInputError('Version of JSON input is invalid: %s' % self.analysis_structured['_meta._dnsviz.']['version'])
        # ensure major version is a match and minor version is no greater
        # than the current minor version
        curr_major_vers, curr_minor_vers = [int(x) for x in str(DNS_RAW_VERSION).split('.', 1)]
        if major_vers != curr_major_vers or minor_vers > curr_minor_vers:
            raise AnalysisInputError('Version %d.%d of JSON input is incompatible with this software.' % (major_vers, minor_vers))

    def ingest_names(self):
        self.names = OrderedDict()

        if self.args.domain_name:
            for name in self.args.domain_name:
                if name not in self.names:
                    self.names[name] = None
            return

        if self.args.names_file:
            args = self.args.names_file
        else:
            try:
                args = self.analysis_structured['_meta._dnsviz.']['names']
            except KeyError:
                raise AnalysisInputError('No names found in JSON input!')

        for arg in args:
            name = arg.strip()

            # python3/python2 dual compatibility
            if hasattr(name, 'decode'):
                name = name.decode('utf-8')

            try:
                name = dns.name.from_text(name)
            except UnicodeDecodeError as e:
                self._logger.error('%s: "%s"' % (e, name))
            except dns.exception.DNSException:
                self._logger.error('The domain name was invalid: "%s"' % name)
            else:
                if name not in self.names:
                    self.names[name] = None

    def serve_zones(self):
        for zone in self._zones_to_serve:
            zone.serve()

def build_helper(logger, cmd, subcmd):
    try:
        resolver = Resolver.from_file(RESOLV_CONF, StandardRecursiveQueryCD, transport_manager=tm)
    except ResolvConfError:
        sys.stderr.write('File %s not found or contains no nameserver entries.\n' % RESOLV_CONF)
        sys.exit(1)

    arghelper = ArgHelper(resolver, logger)
    arghelper.build_parser('%s %s' % (cmd, subcmd))
    return arghelper

def main(argv):
    global tm
    global th_factories
    global explicit_delegations
    global odd_ports

    try:
        _init_tm()
        arghelper = build_helper(logger, sys.argv[0], argv[0])
        arghelper.parse_args(argv[1:])
        logger.setLevel(arghelper.get_log_level())

        try:
            arghelper.check_args()
            arghelper.set_kwargs()
            arghelper.set_buffers()
            arghelper.check_network_connectivity()
            arghelper.aggregate_delegation_info()
            arghelper.populate_recursive_servers()
            arghelper.ingest_input()
            arghelper.ingest_names()
            arghelper.serve_zones()
        except argparse.ArgumentTypeError as e:
            arghelper.parser.error(str(e))
        except (ZoneFileServiceError, MissingExecutablesError) as e:
            s = str(e)
            if s:
                logger.error(s)
            sys.exit(1)
        except AnalysisInputError as e:
            s = str(e)
            if s:
                logger.error(s)
            sys.exit(3)

        th_factories = arghelper.th_factories
        explicit_delegations = arghelper.explicit_delegations
        odd_ports = arghelper.odd_ports

        if arghelper.args.authoritative_analysis:
            if arghelper.args.threads > 1:
                cls = ParallelAnalyst
            else:
                cls = BulkAnalyst
        else:
            if arghelper.args.threads > 1:
                cls = RecursiveParallelAnalyst
            else:
                cls = RecursiveBulkAnalyst

        if arghelper.args.pretty_output:
            kwargs = { 'indent': 4, 'separators': (',', ': ') }
        else:
            kwargs = {}
        dnsviz_meta = { 'version': DNS_RAW_VERSION, 'names': [lb2s(n.to_text()) for n in arghelper.names] }

        name_objs = []
        if arghelper.args.input_file:
            cache = {}
            for name in arghelper.names:
                if name.canonicalize().to_text() not in arghelper.analysis_structured:
                    logger.error('The domain name was not found in the analysis input: "%s"' % name.to_text())
                    continue
                name_objs.append(OnlineDomainNameAnalysis.deserialize(name, arghelper.analysis_structured, cache))
        else:
            if arghelper.args.threads > 1:
                a = cls(arghelper.rdclass, arghelper.try_ipv4, arghelper.try_ipv6, arghelper.client_ipv4, arghelper.client_ipv6, CustomQueryMixin, arghelper.ceiling, arghelper.args.edns, arghelper.stop_at, arghelper.cache_level, arghelper.args.rr_types, arghelper.explicit_only, arghelper.dlv_domain, arghelper.args.threads)
            else:
                if cls.use_full_resolver:
                    _init_full_resolver()
                else:
                    _init_stub_resolver()
                a = cls(arghelper.rdclass, arghelper.try_ipv4, arghelper.try_ipv6, arghelper.client_ipv4, arghelper.client_ipv6, CustomQueryMixin, arghelper.ceiling, arghelper.args.edns, arghelper.stop_at, arghelper.cache_level, arghelper.args.rr_types, arghelper.explicit_only, arghelper.dlv_domain)

            name_objs = a.analyze(arghelper.names)

        name_objs = [x for x in name_objs if x is not None]

        if not name_objs:
            sys.exit(4)

        d = OrderedDict()
        for name_obj in name_objs:
            name_obj.serialize(d, arghelper.meta_only)
        d['_meta._dnsviz.'] = dnsviz_meta

        try:
            arghelper.args.output_file.write(json.dumps(d, ensure_ascii=False, **kwargs).encode('utf-8'))
        except IOError as e:
            logger.error('Error writing analysis: %s' % e)
            sys.exit(3)

    except KeyboardInterrupt:
        logger.error('Interrupted.')
        sys.exit(4)

    # tm is global (because of possible multiprocessing), so we need to
    # explicitly close it here
    finally:
        _cleanup_tm()

if __name__ == "__main__":
    main(sys.argv)
