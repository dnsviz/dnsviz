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
import codecs
import io
import json
import logging
import os
import re
import sys

# minimal support for python2.6
try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict

import dns.exception, dns.name

from dnsviz.analysis import OfflineDomainNameAnalysis, DNS_RAW_VERSION
from dnsviz.format import latin1_binary_to_string as lb2s
from dnsviz.util import get_trusted_keys

# If the import of DNSAuthGraph fails because of the lack of pygraphviz, it
# will be reported later
try:
    from dnsviz.viz.dnssec import DNSAuthGraph
except ImportError:
    try:
        import pygraphviz
    except ImportError:
        pass
    else:
        raise

logging.basicConfig(level=logging.WARNING, format='%(message)s')
logger = logging.getLogger()

class AnalysisInputError(Exception):
    pass

TERM_COLOR_MAP = {
    'BOLD': '\033[1m',
    'RESET': '\033[0m',
    'SECURE': '\033[36m',
    'BOGUS': '\033[31m',
    'INSECURE': '\033[37m',
    'NOERROR': '\033[37m',
    'NXDOMAIN': '\033[37m',
    'INDETERMINATE': '\033[31m',
    'NON_EXISTENT': '\033[37m',
    'VALID': '\033[36m',
    'INDETERMINATE': '\033[37m',
    'INDETERMINATE_NO_DNSKEY': '\033[37m',
    'INDETERMINATE_MATCH_PRE_REVOKE': '\033[37m',
    'INDETERMINATE_UNKNOWN_ALGORITHM': '\033[33m',
    'ALGORITHM_IGNORED': '\033[37m',
    'EXPIRED': '\033[35m',
    'PREMATURE': '\033[35m',
    'INVALID_SIG': '\033[31m',
    'INVALID': '\033[31m',
    'INVALID_DIGEST': '\033[31m',
    'INCOMPLETE': '\033[33m',
    'LAME': '\033[33m',
    'INVALID_TARGET': '\033[31m',
    'ERROR': '\033[31m',
    'WARNING': '\033[33m',
}

KEY_RE = re.compile(r'^((?P<indent>\s+)")(.+)(": )')
ERRORS_RE = re.compile(r'^((?P<indent>\s+)")((?P<level>warning|error)s?)(": \[)$')
ERRORS_CLOSE_RE = re.compile(r'^(?P<indent>\s+)],?$')
DESCRIPTION_CODE_RE = re.compile(r'^((?P<indent>\s+)")(?P<name>description|code)(": ")(.+)(",?)$')
STATUS_RE = re.compile(r'^(?P<indent>\s+)("status": ")(?P<status>.+)(",?)')


def color_json(s):
    error = None
    s1 = ''

    for line in s.split('\n'):
        if error is None:
            # not in an error object; look for a start
            error = ERRORS_RE.search(line)
            if error is not None:
                # found an error start
                line = ERRORS_RE.sub(r'\1%s%s\3%s\5' % (TERM_COLOR_MAP['BOLD'], TERM_COLOR_MAP[error.group('level').upper()], TERM_COLOR_MAP['RESET']), line)
                s1 += line + '\n'
                continue

        if error is None:
            # not in an error object
            m = STATUS_RE.search(line)
            if m is not None:
                line = STATUS_RE.sub(r'\1\2%s\3%s\4' % (TERM_COLOR_MAP[m.group('status').upper()], TERM_COLOR_MAP['RESET']), line)
            line = KEY_RE.sub(r'\1%s\3%s\4' % (TERM_COLOR_MAP['BOLD'], TERM_COLOR_MAP['RESET']), line)
            s1 += line + '\n'
            continue

        # in an error object
        m = ERRORS_CLOSE_RE.search(line)
        if m is not None and len(m.group('indent')) == len(error.group('indent')):
            error = None
            s1 += line + '\n'
            continue

        line = DESCRIPTION_CODE_RE.sub(r'\1\3\4%s\5%s\6' % (TERM_COLOR_MAP[error.group('level').upper()], TERM_COLOR_MAP['RESET']), line)
        line = KEY_RE.sub(r'\1%s\3%s\4' % (TERM_COLOR_MAP['BOLD'], TERM_COLOR_MAP['RESET']), line)
        s1 += line + '\n'

    return s1.rstrip()

def test_pygraphviz():
    try:
        from pygraphviz import release
        try:
            major, minor = release.version.split('.')[:2]
            major = int(major)
            minor = int(re.sub(r'(\d+)[^\d].*', r'\1', minor))
            if (major, minor) < (1,3):
                logger.error('''pygraphviz version >= 1.3 is required, but version %s is installed.''' % release.version)
                sys.exit(2)
        except ValueError:
            logger.error('''pygraphviz version >= 1.3 is required, but version %s is installed.''' % release.version)
            sys.exit(2)
    except ImportError:
        logger.error('''pygraphviz is required, but not installed.''')
        sys.exit(2)

class GrokArgHelper:

    def __init__(self, logger):
        self.parser = None

        self.trusted_keys = None
        self.names = None
        self.analysis_structured = None
        self.log_level = None

        self.args = None
        self._arg_mapping = None

        self._logger = logger

    def build_parser(self, prog):
        self.parser = argparse.ArgumentParser(description='Assess diagnostic DNS queries', prog=prog)

        # python3/python2 dual compatibility
        stdin_buffer = io.open(sys.stdin.fileno(), 'rb', closefd=False)
        stdout_buffer = io.open(sys.stdout.fileno(), 'wb', closefd=False)

        try:
            self.parser.add_argument('-f', '--names-file',
                    type=argparse.FileType('r', encoding='UTF-8'),
                    action='store', metavar='<filename>',
                    help='Read names from a file')
        except TypeError:
            # this try/except is for
            # python3/python2 dual compatibility
            self.parser.add_argument('-f', '--names-file',
                    type=argparse.FileType('r'),
                    action='store', metavar='<filename>',
                    help='Read names from a file')
        #self.parser.add_argument('-s', '--silent',
        #        const=True, default=False,
        #        action='store_const',
        #        help='Suppress error messages')
        try:
            self.parser.add_argument('-r', '--input-file',
                    type=argparse.FileType('r', encoding='UTF-8'), default=stdin_buffer,
                    action='store', metavar='<filename>',
                    help='Read diagnostic queries from a file')
        except TypeError:
            # this try/except is for
            # python3/python2 dual compatibility
            self.parser.add_argument('-r', '--input-file',
                    type=argparse.FileType('r'), default=stdin_buffer,
                    action='store', metavar='<filename>',
                    help='Read diagnostic queries from a file')
        try:
            self.parser.add_argument('-t', '--trusted-keys-file',
                    type=argparse.FileType('r', encoding='UTF-8'),
                    action='append', metavar='<filename>',
                    help='Use trusted keys from the designated file')
        except TypeError:
            # this try/except is for
            # python3/python2 dual compatibility
            self.parser.add_argument('-t', '--trusted-keys-file',
                    type=argparse.FileType('r'),
                    action='append', metavar='<filename>',
                    help='Use trusted keys from the designated file')
        self.parser.add_argument('-a', '--algorithms',
                type=self.comma_separated_ints_set,
                action='store', metavar='<alg>,[<alg>...]',
                help='Support only the specified DNSSEC algorithm(s)')
        self.parser.add_argument('-d', '--digest-algorithms',
                type=self.comma_separated_ints_set,
                action='store', metavar='<digest_alg>,[<digest_alg>...]',
                help='Support only the specified DNSSEC digest algorithm(s)')
        self.parser.add_argument('-b', '--validate-prohibited-algs',
                const=True, default=False,
                action='store_const',
                help='Validate algorithms for which validation is otherwise prohibited')
        self.parser.add_argument('-C', '--enforce-cookies',
                const=True, default=False,
                action='store_const',
                help='Enforce DNS cookies strictly')
        self.parser.add_argument('-P', '--allow-private',
                const=True, default=False,
                action='store_const',
                help='Allow private IP addresses for authoritative DNS servers')
        self.parser.add_argument('-o', '--output-file',
                type=argparse.FileType('wb'), default=stdout_buffer,
                action='store', metavar='<filename>',
                help='Save the output to the specified file')
        self.parser.add_argument('-c', '--minimize-output',
                const=True, default=False,
                action='store_const',
                help='Format JSON output minimally, instead of "pretty"')
        self.parser.add_argument('-l', '--log-level',
                type=str, choices=('error', 'warning', 'info', 'debug'), default='debug',
                action='store', metavar='<loglevel>',
                help='Save the output to the specified file')
        self.parser.add_argument('domain_name',
                type=self.valid_domain_name,
                action='store', nargs='*', metavar='<domain_name>',
                help='Domain names')

        self._arg_mapping = dict([(a.dest, '/'.join(a.option_strings)) for a in self.parser._actions])

    def parse_args(self, args):
        self.args = self.parser.parse_args(args)

    @classmethod
    def comma_separated_ints_set(cls, arg):
        return set(cls.comma_separated_ints(arg))

    @classmethod
    def comma_separated_ints(cls, arg):
        ints = []
        arg = arg.strip()
        if not arg:
            return ints
        for i in arg.split(','):
            try:
                ints.append(int(i.strip()))
            except ValueError:
                raise argparse.ArgumentTypeError('Invalid integer: %s' % (i))
        return ints

    @classmethod
    def valid_domain_name(cls, arg):
        try:
            return dns.name.from_text(arg)
        except dns.exception.DNSException:
            raise argparse.ArgumentTypeError('Invalid domain name: "%s"' % arg)

    def check_args(self):
        if self.args.names_file and self.args.domain_name:
            raise argparse.ArgumentTypeError('If %(names_file)s is used, then domain names may not supplied as command line arguments.' % \
                    self._arg_mapping)

    def set_kwargs(self):
        if self.args.log_level == 'error':
            self.log_level = logging.ERROR
        elif self.args.log_level == 'warning':
            self.log_level = logging.WARNING
        elif self.args.log_level == 'info':
            self.log_level = logging.INFO
        else: # self.args.log_level == 'debug':
            self.log_level = logging.DEBUG

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
        if self.args.trusted_keys_file is not None:
            trusted_keys_files = []
            for tk_file in self.args.trusted_keys_file:
                if tk_file.fileno() == sys.stdin.fileno():
                    filename = tk_file.fileno()
                else:
                    filename = tk_file.name
                    tk_file.close()
                trusted_keys_files.append(io.open(filename, 'r', encoding='utf-8'))
            self.args.trusted_keys_file = trusted_keys_files
        if self.args.output_file is not None:
            if self.args.output_file.fileno() == sys.stdout.fileno():
                filename = self.args.output_file.fileno()
            else:
                filename = self.args.output_file.name
                self.args.output_file.close()
            self.args.output_file = io.open(filename, 'wb')

    def aggregate_trusted_key_info(self):
        if not self.args.trusted_keys_file:
            return

        self.trusted_keys = []
        for fh in self.args.trusted_keys_file:
            tk_str = fh.read()
            try:
                self.trusted_keys.extend(get_trusted_keys(tk_str))
            except dns.exception.DNSException:
                raise argparse.ArgumentTypeError('There was an error parsing the trusted keys file: "%s"' % \
                        self._arg_mapping)

    def update_trusted_key_info(self):
        if self.args.trusted_keys_file is None:
            self.trusted_keys = []

    def ingest_input(self):
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

def build_helper(logger, cmd, subcmd):
    arghelper = GrokArgHelper(logger)
    arghelper.build_parser('%s %s' % (cmd, subcmd))
    return arghelper

def main(argv):
    try:

        arghelper = build_helper(logger, sys.argv[0], argv[0])
        arghelper.parse_args(argv[1:])
        logger.setLevel(logging.WARNING)

        try:
            arghelper.check_args()
            arghelper.set_kwargs()
            arghelper.set_buffers()
            arghelper.aggregate_trusted_key_info()
            arghelper.ingest_input()
            arghelper.ingest_names()
        except argparse.ArgumentTypeError as e:
            arghelper.parser.error(str(e))
        except AnalysisInputError as e:
            s = str(e)
            if s:
                logger.error(s)
            sys.exit(3)

        if arghelper.args.minimize_output:
            kwargs = {}
        else:
            kwargs = { 'indent': 4, 'separators': (',', ': ') }

        # if trusted keys were supplied, check that pygraphviz is installed
        if arghelper.trusted_keys:
            test_pygraphviz()

        name_objs = []
        cache = {}
        for name in arghelper.names:
            name_str = lb2s(name.canonicalize().to_text())
            if name_str not in arghelper.analysis_structured or arghelper.analysis_structured[name_str].get('stub', True):
                logger.error('The analysis of "%s" was not found in the input.' % lb2s(name.to_text()))
                continue
            name_obj = OfflineDomainNameAnalysis.deserialize(name, arghelper.analysis_structured, cache, strict_cookies=arghelper.args.enforce_cookies, allow_private=arghelper.args.allow_private)
            name_objs.append(name_obj)

        if not name_objs:
            sys.exit(4)

        arghelper.update_trusted_key_info()

        d = OrderedDict()
        for name_obj in name_objs:
            name_obj.populate_status(arghelper.trusted_keys, supported_algs=arghelper.args.algorithms, supported_digest_algs=arghelper.args.digest_algorithms, validate_prohibited_algs=arghelper.args.validate_prohibited_algs)

            if arghelper.trusted_keys:
                G = DNSAuthGraph()
                for qname, rdtype in name_obj.queries:
                    if name_obj.is_zone() and rdtype in (dns.rdatatype.DNSKEY, dns.rdatatype.DS, dns.rdatatype.DLV):
                        continue
                    G.graph_rrset_auth(name_obj, qname, rdtype)
                for target, mx_obj in name_obj.mx_targets.items():
                    if mx_obj is not None:
                        G.graph_rrset_auth(mx_obj, target, dns.rdatatype.A)
                        G.graph_rrset_auth(mx_obj, target, dns.rdatatype.AAAA)
                for target, ns_obj in name_obj.ns_dependencies.items():
                    if ns_obj is not None:
                        G.graph_rrset_auth(ns_obj, target, dns.rdatatype.A)
                        G.graph_rrset_auth(ns_obj, target, dns.rdatatype.AAAA)
                G.add_trust(arghelper.trusted_keys, supported_algs=arghelper.args.algorithms)
                name_obj.populate_response_component_status(G)

            name_obj.serialize_status(d, loglevel=arghelper.log_level)

        if d:
            s = json.dumps(d, ensure_ascii=False, **kwargs)
            if not arghelper.args.minimize_output and arghelper.args.output_file.isatty() and os.environ.get('TERM', 'dumb') != 'dumb':
                s = color_json(s)
            arghelper.args.output_file.write(s.encode('utf-8'))

    except KeyboardInterrupt:
        logger.error('Interrupted.')
        sys.exit(4)

if __name__ == "__main__":
    main(sys.argv)
