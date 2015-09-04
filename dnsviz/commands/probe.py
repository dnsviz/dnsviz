#!/usr/bin/env python
#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Created by Casey Deccio (casey@deccio.net)
#
# Copyright 2014-2015 VeriSign, Inc.
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
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

import codecs
import collections
import errno
import getopt
import json
import logging
import signal
import socket
import sys
import multiprocessing
import multiprocessing.managers
import threading
import time

import dns.exception, dns.name, dns.rdataclass, dns.rdatatype

from dnsviz.analysis import WILDCARD_EXPLICIT_DELEGATION, PrivateAnalyst, PrivateRecursiveAnalyst, OnlineDomainNameAnalysis, get_client_addresses, NetworkConnectivityException, resolver, DNS_RAW_VERSION
import dnsviz.format as fmt
from dnsviz.ipaddr import IPAddr
from dnsviz.resolver import DNSAnswer, get_standard_resolver
from dnsviz.transport import close_default_dns_transport_handler

logger = logging.getLogger('dnsviz.analysis.online')

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

def _init_interrupt_handler():
    signal.signal(signal.SIGINT, _raise_eof)

def _analyze((cls, name, dlv_domain, client_ipv4, client_ipv6, ceiling, edns_diagnostics, explicit_delegations, extra_rdtypes, explicit_only, cache, cache_level, cache_lock)):
    if ceiling is not None and name.is_subdomain(ceiling):
        c = ceiling
    else:
        c = name
    try:
        a = cls(name, dlv_domain=dlv_domain, client_ipv4=client_ipv4, client_ipv6=client_ipv6, ceiling=c, edns_diagnostics=edns_diagnostics, explicit_delegations=explicit_delegations, extra_rdtypes=extra_rdtypes, explicit_only=explicit_only, analysis_cache=cache, cache_level=cache_level, analysis_cache_lock=cache_lock)
        return a.analyze()
    # re-raise a KeyboardInterrupt, as this means we've been interrupted
    except KeyboardInterrupt:
        raise
    # don't report EOFError, as that is what is raised if there is a
    # KeyboardInterrupt in ParallelAnalyst
    except EOFError:
        pass
    except:
        logger.exception('Error analyzing %s' % fmt.humanize_name(name))
        return None

class BulkAnalyst(object):
    analyst_cls = PrivateAnalyst

    def __init__(self, client_ipv4, client_ipv6, ceiling, edns_diagnostics, cache_level, explicit_delegations, extra_rdtypes, explicit_only, dlv_domain):
        self.client_ipv4 = client_ipv4
        self.client_ipv6 = client_ipv6
        self.ceiling = ceiling
        self.edns_diagnostics = edns_diagnostics
        self.cache_level = cache_level
        self.explicit_delegations = explicit_delegations
        self.extra_rdtypes = extra_rdtypes
        self.explicit_only = explicit_only
        self.dlv_domain = dlv_domain

        self.cache = {}
        self.cache_lock = threading.Lock()

    def _name_to_args_iter(self, names):
        for name in names:
            yield (self.analyst_cls, name, self.dlv_domain, self.client_ipv4, self.client_ipv6, self.ceiling, self.edns_diagnostics, self.explicit_delegations, self.extra_rdtypes, self.explicit_only, self.cache, self.cache_level, self.cache_lock)

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

    def __init__(self, client_ipv4, client_ipv6, ceiling, edns_diagnostics, cache_level, explicit_delegations, extra_rdtypes, explicit_only, dlv_domain, processes):
        super(ParallelAnalystMixin, self).__init__(client_ipv4, client_ipv6, ceiling, edns_diagnostics, cache_level, explicit_delegations, extra_rdtypes, explicit_only, dlv_domain)
        self.manager = multiprocessing.managers.SyncManager()
        self.manager.start()

        self.processes = processes

        self.cache = self.manager.dict()
        self.cache_lock = self.manager.Lock()

    def analyze(self, names, flush_func=None):
        results = []
        name_objs = []
        pool = multiprocessing.Pool(self.processes, _init_interrupt_handler)
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

class RecursiveParallelAnalyst(ParallelAnalystMixin, RecursiveBulkAnalyst):
    analyst_cls = RecursiveMultiProcessAnalyst

def name_addr_mappings_from_string(mappings):
    mappings_set = set()
    mappings = mappings.split(',')
    i = 1
    for mapping in mappings:
        try:
            name, addr = mapping.rsplit('=', 1)
        except ValueError:
            # first see if it's a plain IP address
            try:
                addr = IPAddr(mapping.strip())
            except ValueError:
                # if not, then assign name to mapping
                name = mapping
                addr = None
            else:
                # if it's an IP with no name specified, then create
                # a name
                name = 'ns%d' % i
                i += 1
        else:
            addr = addr.strip()
        name = name.strip()
        try:
            name = dns.name.from_text(name)
        except dns.exception.DNSException:
            usage('The domain name was invalid: "%s"' % name)
            sys.exit(1)

        # no address is provided, so query A/AAAA records for the name
        if addr is None:
            query_tuples = ((name, dns.rdatatype.A, dns.rdataclass.IN), (name, dns.rdatatype.AAAA, dns.rdataclass.IN))
            answer_map = resolver.query_multiple_for_answer(*query_tuples)
            found_answer = False
            for a in answer_map.values():
                if isinstance(a, DNSAnswer):
                    found_answer = True
                    for a_rr in a.rrset:
                        mappings_set.add((name, IPAddr(a_rr.to_text())))
                # negative responses
                elif isinstance(a, (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)):
                    pass
                # error responses
                elif isinstance(a, (dns.exception.Timeout, dns.resolver.NoNameservers)):
                    usage('There was an error resolving "%s".  Please specify an address or use a name that resolves properly.' % fmt.humanize_name(name))
                    sys.exit(1)

            if not found_answer:
                usage('"%s" did not resolve to an address.  Please specify an address or use a name that resolves properly.' % fmt.humanize_name(name))
                sys.exit(1)

        # otherwise, add the address
        elif not addr:
            usage('No IP address was supplied.')
            sys.exit(1)
        else:
            if addr and addr[0] == '[' and addr[-1] == ']':
                addr = addr[1:-1]
            try:
                addr = IPAddr(addr)
            except ValueError:
                usage('The IP address was invalid: "%s"' % addr)
                sys.exit(1)
            mappings_set.add((name, addr))
    return mappings_set

def usage(err=None):
    if err is not None:
        err += '\n\n'
    else:
        err = ''
    sys.stderr.write('''%sUsage: dnsviz probe [options] [domain_name...]
Options:
    -f <filename>  - read names from a file
    -d <level>     - set debug level
    -r <filename>  - read diagnostic queries from a file
    -t <threads>   - specify number of threads to use for parallel queries
    -4             - use IPv4 only
    -6             - use IPv6 only
    -b             - specify a source IPv4 or IPv6 address for queries
    -a <ancestor>  - query the ancestry of each domain name through ancestor
    -R <type>[,<type>...]
                   - perform analysis using only the specified type(s)
    -s <server>[,<server>...]
                   - designate servers for recursive analysis
    -A             - query analysis against authoritative servers
    -x <domain>:<server>[,<server>...]
                   - set explicit delegation for the specified domain
    -E             - include EDNS compatibility diagnostics
    -p             - make json output pretty instead of minimal
    -o <filename>    - write the analysis to the specified file
    -h             - display the usage and exit
''' % (err))

def main(argv):
    try:
        try:
            opts, args = getopt.getopt(argv[1:], 'f:d:l:c:r:t:64b:mpo:a:R:x:EAs:Fh')
        except getopt.GetoptError, e:
            usage(str(e))
            sys.exit(1)

        # get all the -x options
        explicit_delegations = {}
        client_ipv4 = None
        client_ipv6 = None
        for opt, arg in opts:
            if opt == '-x':
                try:
                    domain, mappings = arg.split(':', 1)
                except ValueError:
                    usage('Incorrect usage of -x option: "%s"' % arg)
                    sys.exit(1)
                domain = domain.strip()
                mappings = mappings.strip()
                try:
                    domain = dns.name.from_text(domain)
                except dns.exception.DNSException:
                    usage('The domain name was invalid: "%s"' % domain)
                    sys.exit(1)
                if not mappings:
                    usage('Incorrect usage of -x option: "%s"' % arg)
                    sys.exit(1)
                if domain not in explicit_delegations:
                    explicit_delegations[domain] = set()
                explicit_delegations[domain].update(name_addr_mappings_from_string(mappings))

            elif opt == '-b':
                try:
                    addr = IPAddr(arg)
                except ValueError:
                    usage('The IP address was invalid: "%s"' % arg)
                    sys.exit(1)

                if addr.version == 4:
                    client_ipv4 = addr
                    fam = socket.AF_INET
                else:
                    client_ipv6 = addr
                    fam = socket.AF_INET6
                try:
                    s = socket.socket(fam)
                    s.bind((addr, 0))
                    del s
                except socket.error, e:
                    if e.errno == errno.EADDRNOTAVAIL:
                        usage('Cannot bind to specified IP address: "%s"' % addr)
                        sys.exit(1)

        opts = dict(opts)
        if '-h' in opts:
            usage()
            sys.exit(0)

        if not ('-f' in opts or args) and '-r' not in opts:
            usage('When -r is not used, either -f must be used or domain names must be supplied as command line arguments.')
            sys.exit(1)
        if '-f' in opts and args:
            usage('If -f is used, then domain names may not supplied as command line arguments.')
            sys.exit(1)

        if '-A' in opts and '-s' in opts:
            usage('If -A is used, then -s cannot be used.')
            sys.exit(1)

        if '-x' in opts and '-A' not in opts:
            usage('-x may only be used in conjunction with -A.')
            sys.exit(1)

        if '-a' in opts:
            try:
                ceiling = dns.name.from_text(opts['-a'])
            except dns.exception.DNSException:
                usage('The domain name was invalid: "%s"' % opts['-a'])
                sys.exit(1)
        elif '-A' in opts:
            ceiling = None
        else:
            ceiling = dns.name.root

        if '-R' in opts:
            explicit_only = True
            try:
                rdtypes = opts['-R'].split(',')
            except ValueError:
                usage('The list of types was invalid: "%s"' % opts['-R'])
                sys.exit(1)
            try:
                rdtypes = map(dns.rdatatype.from_text, rdtypes)
            except dns.rdatatype.UnknownRdatatype:
                usage('The list of types was invalid: "%s"' % opts['-R'])
                sys.exit(1)
        else:
            rdtypes = None
            explicit_only = False

        use_ipv4 = None
        use_ipv6 = None
        require_ipv4 = False
        require_ipv6 = False
        # if neither is specified, then they're both used
        if '-4' not in opts and '-6' not in opts:
            use_ipv4 = True
            use_ipv6 = True
        else:
            # use IPv4 only if specified
            if '-4' in opts:
                use_ipv4 = True
                require_ipv4 = True
            else:
                use_ipv4 = False
            # use IPv6 only if specified
            if '-6' in opts:
                use_ipv6 = True
                require_ipv6 = True
            else:
                use_ipv6 = False
        if '-A' not in opts:
            if '-t' in opts:
                cls = RecursiveParallelAnalyst
            else:
                cls = RecursiveBulkAnalyst
            if '-s' in opts:
                explicit_delegations[WILDCARD_EXPLICIT_DELEGATION] = name_addr_mappings_from_string(opts['-s'])

                ipv4_resolvers = filter(lambda x: x[1].version == 4, explicit_delegations[WILDCARD_EXPLICIT_DELEGATION])
                ipv6_resolvers = filter(lambda x: x[1].version == 6, explicit_delegations[WILDCARD_EXPLICIT_DELEGATION])
                if not ipv4_resolvers and not require_ipv4:
                    use_ipv4 = False
                if not ipv6_resolvers and not require_ipv6:
                    use_ipv6 = False
            else:
                servers = get_standard_resolver()._servers
                explicit_delegations[WILDCARD_EXPLICIT_DELEGATION] = set([(dns.name.from_text('ns%d' % i), s) for i, s in enumerate(servers)])
        else:
            if '-t' in opts:
                cls = ParallelAnalyst
            else:
                cls = BulkAnalyst

        edns_diagnostics = '-E' in opts

        if '-l' in opts:
            try:
                dlv_domain = dns.name.from_text(opts['-l'])
            except dns.exception.DNSException:
                usage('The domain name was invalid: "%s"' % opts['-l'])
        else:
            dlv_domain = None

        # the following option is not documented in usage, as it doesn't
        # apply to most users
        try:
            cache_level = int(opts['-c'])
        except (KeyError, ValueError):
            cache_level = None

        try:
            processes = int(opts.get('-t', 1))
        except ValueError:
            usage('The number of threads used must be greater than 0.')
            sys.exit(1)
        if processes < 1:
            usage('The number of threads used must be greater than 0.')
            sys.exit(1)

        try:
            val = int(opts.get('-d', 2))
        except ValueError:
            usage('The debug value must be an integer between 0 and 3.')
            sys.exit(1)
        if val < 0 or val > 3:
            usage('The debug value must be an integer between 0 and 3.')
            sys.exit(1)

        if val > 2:
            debug_level = logging.DEBUG
        elif val > 1:
            debug_level = logging.INFO
        elif val > 0:
            debug_level = logging.WARNING
        else:
            debug_level = logging.ERROR
        handler = logging.StreamHandler()
        handler.setLevel(debug_level)
        logger.addHandler(handler)
        logger.setLevel(debug_level)

        if '-r' in opts:
            if opts['-r'] == '-':
                analysis_str = codecs.getreader('utf-8')(sys.stdin).read()
            else:
                try:
                    analysis_str = codecs.open(opts['-r'], 'r', 'utf-8').read()
                except IOError, e:
                    logger.error('%s: "%s"' % (e.strerror, opts['-r']))
                    sys.exit(3)
            try:
                analysis_structured = json.loads(analysis_str)
            except ValueError:
                logger.error('There was an error parsing the json input: "%s"' % opts['-r'])
                sys.exit(3)

            # check version
            if '_meta._dnsviz.' in analysis_structured and 'version' in analysis_structured['_meta._dnsviz.'] and analysis_structured['_meta._dnsviz.']['version'] > DNS_RAW_VERSION:
                logger.error('Unsupported version: "%s"' % analysis_structured['_meta._dnsviz.']['version'])
                sys.exit(3)

        else:
            # get client addresses where they are needed
            if (client_ipv4 is None and use_ipv4) or \
                    (client_ipv6 is None and use_ipv6):
                c4, c6 = get_client_addresses(warn_ipv4=use_ipv4 and client_ipv4 is None, \
                        warn_ipv6=use_ipv6 and client_ipv6 is None)
                if use_ipv4 and client_ipv4 is None:
                    client_ipv4 = c4
                if use_ipv6 and client_ipv6 is None:
                    client_ipv6 = c6
                if require_ipv4 and client_ipv4 is None:
                    sys.exit(2)
                if require_ipv6 and client_ipv6 is None:
                    sys.exit(2)
            # when explicitly assigned, check that they should be used
            else:
                if client_ipv4 is not None and not use_ipv4:
                    client_ipv4 = None
                if client_ipv6 is not None and not use_ipv6:
                    client_ipv6 = None

            if client_ipv4 is None and client_ipv6 is None:
                logger.error('No network interfaces available for analysis!')
                sys.exit(2)

        names = []
        if '-f' in opts:
            try:
                f = codecs.open(opts['-f'], 'r', 'utf-8')
            except IOError, e:
                logger.error('%s: "%s"' % (e.strerror, opts['-f']))
                sys.exit(3)
            for line in f:
                name = line.strip()
                try:
                    name = dns.name.from_text(name)
                except UnicodeDecodeError, e:
                    logger.error('%s: "%s"' % (e, name))
                except dns.exception.DNSException:
                    logger.error('The domain name was invalid: "%s"' % name)
                else:
                    names.append(name)
            f.close()
        else:
            if args:
                args = map(lambda x: x.decode(sys.getfilesystemencoding()), args)
            else:
                try:
                    args = analysis_structured['_meta._dnsviz.']['names']
                except KeyError:
                    logger.error('No names found in json input!')
                    sys.exit(3)
            for name in args:
                try:
                    name = dns.name.from_text(name)
                except UnicodeDecodeError, e:
                    logger.error('%s: "%s"' % (e, name))
                except dns.exception.DNSException:
                    logger.error('The domain name was invalid: "%s"' % name)
                else:
                    names.append(name)

        if '-p' in opts:
            kwargs = { 'indent': 4, 'separators': (',', ': ') }
        else:
            kwargs = {}

        meta_only = '-m' in opts

        if '-o' not in opts or opts['-o'] == '-':
            fh = sys.stdout
        else:
            try:
                fh = open(opts['-o'], 'w')
            except IOError, e:
                logger.error('%s: "%s"' % (e.strerror, opts['-o']))
                sys.exit(3)

        def _flush(name_obj):
            d = collections.OrderedDict()
            name_obj.serialize(d)
            s = json.dumps(d, **kwargs)
            lindex = s.index('{')
            rindex = s.rindex('}')
            fh.write(s[lindex+1:rindex]+',')

        dnsviz_meta = { 'version': DNS_RAW_VERSION, 'names': [n.to_text() for n in names] }

        flush = '-F' in opts

        name_objs = []
        if '-r' in opts:
            cache = {}
            for name in names:
                if name.canonicalize().to_text() not in analysis_structured:
                    logger.error('The domain name was not found in the analysis input: "%s"' % name.to_text())
                    continue
                name_objs.append(OnlineDomainNameAnalysis.deserialize(name, analysis_structured, cache))
        else:
            if '-t' in opts:
                a = cls(client_ipv4, client_ipv6, ceiling, edns_diagnostics, cache_level, explicit_delegations, rdtypes, explicit_only, dlv_domain, processes)
            else:
                a = cls(client_ipv4, client_ipv6, ceiling, edns_diagnostics, cache_level, explicit_delegations, rdtypes, explicit_only, dlv_domain)
                if flush:
                    fh.write('{')
                    a.analyze(names, _flush)
                    fh.write('"_meta._dnsviz.":%s}' % json.dumps(dnsviz_meta, **kwargs))
                    sys.exit(0)

            name_objs = a.analyze(names)

        name_objs = filter(lambda x: x is not None, name_objs)

        if not name_objs:
            sys.exit(4)

        d = collections.OrderedDict()
        for name_obj in name_objs:
            name_obj.serialize(d, meta_only)
        d['_meta._dnsviz.'] = dnsviz_meta

        fh.write(json.dumps(d, **kwargs))

    except KeyboardInterrupt:
        logger.error('Interrupted.')
        sys.exit(4)
    finally:
        close_default_dns_transport_handler()

if __name__ == "__main__":
    main(sys.argv)
