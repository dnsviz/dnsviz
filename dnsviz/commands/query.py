#!/usr/bin/env python
#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Created by Casey Deccio (casey@deccio.net)
#
# Copyright 2015-2016 VeriSign, Inc.
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

import getopt
import socket
import subprocess
import sys

import dns.name, dns.rdataclass, dns.rdatatype

from dnsviz.ipaddr import IPAddr
from dnsviz import resolver as Resolver

def _get_nameservers_for_name(addr):
    nameservers = []
    try:
        addrinfo = socket.getaddrinfo(addr, 53, 0, 0, socket.IPPROTO_TCP)
    except socket.gaierror:
        sys.stderr.write('Unable to resolve "%s"\n' % addr)
    else:
        for item in addrinfo:
            nameservers.append(IPAddr(item[4][0]))
    return nameservers

def usage(err=None):
    if err is not None:
        err += '\n\n'
    else:
        err = ''
    sys.stderr.write('''%sUsage: %s %s [@global-server] [domain] [q-type] [q-class] {q-opt}
           {global-d-opt} host [@local-server] {local-d-opt}
           [ host [@local-server] {local-d-opt} [...]]
Where:  domain    is in the Domain Name System
        q-class  is one of (in...) [default: in]
        q-type   is one of (a,mx,ns,soa,txt,...) [default:a]
        q-opt    is one of:
                 -x dot-notation     (shortcut for reverse lookups)
                 -b address          (bind to source address)
                 -q name             (specify query name)
                 -t type             (specify query type)
                 -c class            (specify query class)
                 -4                  (use IPv4 query transport only)
                 -6                  (use IPv6 query transport only)
        d-opt    is of the form +keyword[=value], where keyword is:
                 +[no]trace          (Trace delegation down from root [+dnssec])
                 +trusted-key=####   (filename containing Trusted Key when chasing DNSSEC sigs)
        global d-opts and servers (before host name) affect all queries.
        local d-opts and servers (after host name) affect only that lookup.
        -h                           (print help and exit)
''' % (err, sys.argv[0], __name__.split('.')[-1]))

class DVCommandLineQuery:
    def __init__(self, qname, rdtype, rdclass):
        self.qname = qname
        self.rdtype = rdtype
        self.rdclass = rdclass

        self.nameservers = []
        self.query_options = []

        self.trace = False
        self.trusted_keys_file = None

    def process_query_options(self, global_options):
        for arg in global_options + self.query_options:
            if arg == '+trace':
                self.trace = True
            elif arg == '+notrace':
                self.trace = False
            elif arg.startswith('+trusted-key') and \
                    (len(arg) <= 12 or arg[12] == '='):
                try:
                    opt, arg = arg.split('=')
                    if not arg:
                        raise ValueError()
                except ValueError:
                    sys.stderr.write('+trusted-key requires a filename argument.\n')
                    sys.exit(1)
                else:
                    self.trusted_keys_file = arg
            else:
                sys.stderr.write('Option "%s" not recognized.\n' % arg)
                sys.exit(1)

    def process_nameservers(self, nameservers, use_ipv4, use_ipv6):
        processed_nameservers = []
        for addr in self.nameservers:
            processed_nameservers.extend(_get_nameservers_for_name(addr))

        if not use_ipv4:
            processed_nameservers = [x for x in processed_nameservers if x.version != 4]
        if not use_ipv6:
            processed_nameservers = [x for x in processed_nameservers if x.version != 6]

        self.nameservers = nameservers + processed_nameservers

    def _get_rdtype(self, options):
        if self.rdtype is None:
            return options['rdtype']
        else:
            return self.rdtype

    def _get_rdclass(self, options):
        if self.rdclass is None:
            return options['rdclass']
        else:
            return self.rdclass

    def query_and_display(self, options):
        dnsget_args = ['dnsviz', 'probe']
        dnsviz_args = ['dnsviz', 'print']
        dnsget_args.extend(['-d', '1', '-a', '.'])
        if options['use_ipv4'] and not options['use_ipv6']:
            dnsget_args.append('-4')
        if options['use_ipv6'] and not options['use_ipv4']:
            dnsget_args.append('-6')
        if options['client_ipv4'] is not None:
            dnsget_args.extend(['-b', options['client_ipv4']])
        if options['client_ipv6'] is not None:
            dnsget_args.extend(['-b', options['client_ipv6']])
        dnsget_args.extend(['-R', dns.rdatatype.to_text(self._get_rdtype(options))])
        if self.trace:
            dnsget_args.append('-A')
        else:
            if self.nameservers[0].version == 6:
                dnsget_args.extend(['-s', '[%s]' % (self.nameservers[0])])
            else:
                dnsget_args.extend(['-s', self.nameservers[0]])
        dnsget_args.append(self.qname)

        if self.trusted_keys_file is not None:
            dnsviz_args.extend(['-t', self.trusted_keys_file])
        dnsviz_args.extend(['-R', dns.rdatatype.to_text(self._get_rdtype(options))])

        try:
            dnsget_p = subprocess.Popen(dnsget_args, stdout=subprocess.PIPE)
            dnsviz_p = subprocess.Popen(dnsviz_args, stdin=dnsget_p.stdout)
        except OSError as e:
            sys.stderr.write('error: %s\n' % e)
            return False
        else:
            dnsget_p.stdout.close()
            dnsviz_p.communicate()
            return dnsget_p.returncode == 0 and dnsviz_p.returncode == 0

class DVCommandLine:
    def __init__(self, args):
        self.args = args
        self.arg_index = 0

        self.options = {
            'rdtype': None,
            'rdclass': None,
            'use_ipv4': None,
            'use_ipv6': None,
            'client_ipv4': None,
            'client_ipv6': None,
        }

        self.nameservers = []
        self.global_query_options = []

        self.queries = []

        self._process_args()
        self._process_network()
        self._process_nameservers()

        if not self.queries:
            self.queries.append(DVCommandLineQuery('.', dns.rdatatype.NS, dns.rdataclass.IN))

        for q in self.queries:
            q.process_nameservers(self.nameservers, self.options['use_ipv4'], self.options['use_ipv6'])
            q.process_query_options(self.global_query_options)

            if not q.nameservers and not q.trace:
                sys.stderr.write('No nameservers to query\n')
                sys.exit(1)

        if self.options['rdtype'] is None:
            self.options['rdtype'] = dns.rdatatype.A
        if self.options['rdclass'] is None:
            self.options['rdclass'] = dns.rdataclass.IN

    def query_and_display(self):
        ret = True
        for q in self.queries:
            if not q.query_and_display(self.options):
                ret = False
        return ret

    def _get_arg(self, has_arg):
        try:
            if len(self.args[self.arg_index]) > 2:
                if not has_arg:
                    sys.stderr.write('"%s" option does not take arguments\n' % self.args[self.arg_index][:2])
                    sys.exit(1)
                return self.args[self.arg_index][2:]
            else:
                if not has_arg:
                    return None
                else:
                    self.arg_index += 1
                    if self.arg_index >= len(self.args):
                        sys.stderr.write('"%s" option requires an argument\n' % self.args[self.arg_index - 1])
                        sys.exit(1)
                    return self.args[self.arg_index]
        finally:
            self.arg_index += 1

    def _add_server_to_options(self, query):
        addr = self.args[self.arg_index][1:]
        self.arg_index += 1
        if query is None:
            self.nameservers.append(addr)
        else:
            query.nameservers.append(addr)

    def _add_reverse_query(self):
        arg = self._get_arg(True)
        try:
            addr = IPAddr(arg)
        except ValueError:
            sys.stderr.write('Invalid IP address: "%s"\n' % arg)
            sys.exit(1)
        else:
            qname = addr.arpa_name()

        return DVCommandLineQuery(qname, dns.rdatatype.PTR, dns.rdataclass.IN)

    def _add_qname_from_opt(self):
        qname = self._get_arg(True)
        return DVCommandLineQuery(qname, None, None)

    def _add_default_option(self):
        if self.options['rdclass'] is None:
            try:
                self.options['rdclass'] = dns.rdataclass.from_text(self.args[self.arg_index])
            except dns.rdataclass.UnknownRdataclass:
                pass
            else:
                self.arg_index += 1
                return True

        if self.options['rdtype'] is None:
            try:
                self.options['rdtype'] = dns.rdatatype.from_text(self.args[self.arg_index])
            except dns.rdatatype.UnknownRdatatype:
                pass
            else:
                self.arg_index += 1
                return True

        return False

    def _add_qname(self):
        qname = self.args[self.arg_index]
        self.arg_index += 1

        # check for optional type
        try:
            rdtype = dns.rdatatype.from_text(self.args[self.arg_index])
        except (IndexError, dns.rdatatype.UnknownRdatatype):
            # no type detected; use default rdtype/rdclass
            rdtype = None
            rdclass = None
        else:
            self.arg_index += 1

        # now check for optional class
        try:
            rdclass = dns.rdataclass.from_text(self.args[self.arg_index])
        except (IndexError, dns.rdataclass.UnknownRdataclass):
            # no class detected; use default rdclass
            rdclass = None
        else:
            self.arg_index += 1

        return DVCommandLineQuery(qname, rdtype, rdclass)

    def _add_option(self):
        if self.args[self.arg_index].startswith('-h'):
            usage()
            sys.exit(0)
        elif self.args[self.arg_index].startswith('-b'):
            arg = self._get_arg(True)
            try:
                addr = IPAddr(arg)
            except ValueError:
                sys.stderr.write('Invalid IP address: "%s"\n' % arg)
                sys.exit(1)

            if addr.version == 6:
                family = socket.AF_INET6
            else:
                family = socket.AF_INET

            try:
                s = socket.socket(family)
                s.bind((addr, 0))
            except socket.error as e:
                if e.errno == errno.EADDRNOTAVAIL:
                    sys.stderr.write('Cannot bind to specified IP address: "%s"\n' % addr)
                    sys.exit(1)
            else:
                del s
                if addr.version == 6:
                    self.options['client_ipv6'] = addr
                else:
                    self.options['client_ipv4'] = addr
        elif self.args[self.arg_index].startswith('-c'):
            arg = self._get_arg(True)
            try:
                self.options['rdclass'] = dns.rdataclass.from_text(arg)
            except dns.rdataclass.UnknownRdataclass:
                sys.stderr.write('Unknown class: "%s".\n' % arg)
                sys.exit(1)
        elif self.args[self.arg_index].startswith('-t'):
            arg = self._get_arg(True)
            try:
                self.options['rdtype'] = dns.rdatatype.from_text(arg)
            except dns.rdatatype.UnknownRdatatype:
                sys.stderr.write('Unknown type: "%s".\n' % arg)
                sys.exit(1)
        elif self.args[self.arg_index].startswith('-6'):
            self._get_arg(False)
            self.options['use_ipv6'] = True
        elif self.args[self.arg_index].startswith('-4'):
            self._get_arg(False)
            self.options['use_ipv4'] = True
        else:
            sys.stderr.write('Option "%s" not recognized.\n' % self.args[self.arg_index][:2])
            sys.exit(1)

    def _add_query_option(self, query):
        if query is None:
            self.global_query_options.append(self.args[self.arg_index])
        else:
            query.query_options.append(self.args[self.arg_index])
        self.arg_index += 1

    def _process_args(self):
        query = None
        while self.arg_index < len(self.args):
            # server address
            if self.args[self.arg_index][0] == '@':
                self._add_server_to_options(query)

            # reverse lookup
            elif self.args[self.arg_index].startswith('-x'):
                query = self._add_reverse_query()
                self.queries.append(query)

            # forward lookup (with -q)
            elif self.args[self.arg_index].startswith('-q'):
                query = self._add_qname_from_opt()
                self.queries.append(query)

            # options
            elif self.args[self.arg_index][0] == '-':
                self._add_option()

            # query options
            elif self.args[self.arg_index][0] == '+':
                self._add_query_option(query)

            # global query class/type
            elif query is None and self._add_default_option():
                pass

            # name to be queried
            else:
                query = self._add_qname()
                self.queries.append(query)

    def _process_network(self):
        if self.options['use_ipv4'] is None and self.options['use_ipv6'] is None:
            self.options['use_ipv4'] = True
            self.options['use_ipv6'] = True
        if not self.options['use_ipv4']:
            self.options['use_ipv4'] = False
        if not self.options['use_ipv6']:
            self.options['use_ipv6'] = False

    def _process_nameservers(self):
        if not self.nameservers:
            processed_nameservers = Resolver.get_standard_resolver()._servers
        else:
            processed_nameservers = []
            for addr in self.nameservers:
                processed_nameservers.extend(_get_nameservers_for_name(addr))

        if not self.options['use_ipv4']:
            processed_nameservers = [x for x in processed_nameservers if x.version != 4]
        if not self.options['use_ipv6']:
            processed_nameservers = [x for x in processed_nameservers if x.version != 6]

        self.nameservers = processed_nameservers

def main(argv):
    try:
        q = DVCommandLine(argv[1:])
        if q.query_and_display():
            sys.exit(0)
        else:
            sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(1)

if __name__ == "__main__":
    main(sys.argv)
