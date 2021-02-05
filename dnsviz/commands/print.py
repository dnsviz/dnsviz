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

from dnsviz.analysis import TTLAgnosticOfflineDomainNameAnalysis, DNS_RAW_VERSION
from dnsviz.format import latin1_binary_to_string as lb2s
from dnsviz.util import get_trusted_keys, get_default_trusted_keys

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

def finish_graph(G, name_objs, rdtypes, trusted_keys, supported_algs, filename):
    G.add_trust(trusted_keys, supported_algs=supported_algs)

    try:
        fh = io.open(filename, 'w', encoding='utf-8')
    except IOError as e:
        logger.error('%s: "%s"' % (e.strerror, filename))
        sys.exit(3)

    show_colors = fh.isatty() and os.environ.get('TERM', 'dumb') != 'dumb'

    tuples = []
    processed = set()
    for name_obj in name_objs:
        name_obj.populate_response_component_status(G)
        tuples.extend(name_obj.serialize_status_simple(rdtypes, processed))

    fh.write(textualize_status_output(tuples, show_colors))

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

STATUS_MAP = {
    'SECURE': '.',
    'BOGUS': '!',
    'INSECURE': '-',
    'NON_EXISTENT': '-',
    'VALID': '.',
    'INDETERMINATE': '-',
    'INDETERMINATE_NO_DNSKEY': '-',
    'INDETERMINATE_MATCH_PRE_REVOKE': '-',
    'INDETERMINATE_UNKNOWN_ALGORITHM': '?',
    'ALGORITHM_IGNORED': '-',
    'EXPIRED': '!',
    'PREMATURE': '!',
    'INVALID_SIG': '!',
    'INVALID': '!',
    'INVALID_DIGEST': '!',
    'INCOMPLETE': '?',
    'LAME': '?',
    'INVALID_TARGET': '!',
    'ERROR': '!',
    'WARNING': '?',
}

def _errors_warnings_full(warnings, errors, indent, show_color):
    # display status, errors, and warnings
    s = ''
    for error in errors:
        if show_color:
            s += '%s%sE:%s%s\n' % (indent, TERM_COLOR_MAP['ERROR'], error, TERM_COLOR_MAP['RESET'])
        else:
            s += '%sE:%s\n' % (indent, error)

    for warning in warnings:
        if show_color:
            s += '%s%sW:%s%s\n' % (indent, TERM_COLOR_MAP['WARNING'], warning, TERM_COLOR_MAP['RESET'])
        else:
            s += '%sW:%s\n' % (indent, warning)

    return s

def _errors_warnings_str(status, warnings, errors, show_color):
    # display status, errors, and warnings
    error_str = ''
    if errors:
        if show_color:
            error_str = '%s%s%s' % (TERM_COLOR_MAP['ERROR'], STATUS_MAP['ERROR'], TERM_COLOR_MAP[status])
        else:
            error_str = STATUS_MAP['ERROR']
    elif warnings:
        if show_color:
            error_str = '%s%s%s' % (TERM_COLOR_MAP['WARNING'], STATUS_MAP['WARNING'], TERM_COLOR_MAP[status])
        else:
            error_str = STATUS_MAP['WARNING']
    return '[%s%s]' % (STATUS_MAP[status], error_str)

def _textualize_status_output_response(rdtype_str, status, warnings, errors, rdata, children, depth, show_color):
    s = ''

    response_prefix = '  %(status_color)s%(status)s%(preindent)s %(indent)s%(rdtype)s: '
    response_rdata = '%(rdata)s%(color_reset)s%(status_color_rdata)s%(status_rdata)s%(color_reset)s'
    join_str_template = '%(status_color)s, '

    params = {}
    params['status_color'] = ''
    params['status_color_rdata'] = ''

    if show_color:
        params['color_reset'] = TERM_COLOR_MAP['RESET']
    else:
        params['color_reset'] = ''

    # display status, errors, and warnings
    params['status'] = _errors_warnings_str(status, warnings, errors, show_color)

    # indent based on the presence of errors and warnings
    if errors or warnings:
        params['preindent'] = ''
    else:
        params['preindent'] = ' '

    params['rdtype'] = rdtype_str
    params['indent'] = '  '*depth
    if show_color:
        params['status_color'] = TERM_COLOR_MAP[status]
    s += response_prefix % params

    rdata_set = []
    subwarnings_all = warnings[:]
    suberrors_all = errors[:]
    for i, (substatus, subwarnings, suberrors, rdata_item) in enumerate(rdata):
        params['rdata'] = rdata_item
        # display status, errors, and warnings
        if substatus is not None:
            if show_color:
                params['status_color_rdata'] = TERM_COLOR_MAP[substatus]
            params['status_rdata'] = ' ' + _errors_warnings_str(substatus, subwarnings, suberrors, show_color)
        else:
            params['status_color_rdata'] = ''
            params['status_rdata'] = ''
        rdata_set.append(response_rdata % params)

        subwarnings_all.extend(subwarnings)
        suberrors_all.extend(suberrors)

    join_str = join_str_template % params
    s += join_str.join(rdata_set) + '\n'

    s += _errors_warnings_full(subwarnings_all, suberrors_all, '        ' + params['preindent'] + params['indent'], show_color)

    for rdtype_str_child, status_child, warnings_child, errors_child, rdata_child, children_child in children:
        s += _textualize_status_output_response(rdtype_str_child, status_child, warnings_child, errors_child, rdata_child, children_child, depth + 1, show_color)

    return s

def _textualize_status_output_name(name, zone_status, zone_warnings, zone_errors, delegation_status, delegation_warnings, delegation_errors, responses, show_color):
    s = ''

    name_template = '%(status_color)s%(name)s%(color_reset)s%(status_color_rdata)s%(status_rdata)s%(color_reset)s\n'

    params = {}
    params['status_color'] = ''
    params['status_color_rdata'] = ''

    if show_color:
        params['color_reset'] = TERM_COLOR_MAP['RESET']
    else:
        params['color_reset'] = ''

    warnings_all = zone_warnings + delegation_warnings
    errors_all = zone_errors + delegation_errors

    params['name'] = name
    params['status_rdata'] = ''
    if show_color:
        params['status_color'] = TERM_COLOR_MAP['BOLD']
        params['color_reset'] = TERM_COLOR_MAP['RESET']
    if zone_status is not None:
        params['status_rdata'] += ' ' + _errors_warnings_str(zone_status, zone_warnings, zone_errors, show_color)
        if show_color:
            params['status_color_rdata'] = TERM_COLOR_MAP[zone_status]
    if delegation_status is not None:
        params['status_rdata'] += ' ' + _errors_warnings_str(delegation_status, delegation_warnings, delegation_errors, show_color)
        if show_color:
            params['status_color_rdata'] = TERM_COLOR_MAP[delegation_status]
    s += name_template % params

    s += _errors_warnings_full(warnings_all, errors_all, '  ', show_color)

    for rdtype_str, status, warnings, errors, rdata, children in responses:
        s += _textualize_status_output_response(rdtype_str, status, warnings, errors, rdata, children, 0, show_color)

    return s

def textualize_status_output(names, show_color):
    s = ''
    for name, zone_status, zone_warnings, zone_errors, delegation_status, delegation_warnings, delegation_errors, responses in names:
        s += _textualize_status_output_name(name, zone_status, zone_warnings, zone_errors, delegation_status, delegation_warnings, delegation_errors, responses, show_color)

    return s

def test_pygraphviz():
    try:
        try:
            # pygraphviz < 1.7 used pygraphviz.release.version
            from pygraphviz import release
            version = release.version
        except ImportError:
            # pygraphviz 1.7 changed to pygraphviz.__version__
            from pygraphviz import __version__
            version = __version__
        try:
            major, minor = version.split('.')[:2]
            major = int(major)
            minor = int(re.sub(r'(\d+)[^\d].*', r'\1', minor))
            if (major, minor) < (1,3):
                logger.error('''pygraphviz version >= 1.3 is required, but version %s is installed.''' % version)
                sys.exit(2)
        except ValueError:
            logger.error('''pygraphviz version >= 1.3 is required, but version %s is installed.''' % version)
            sys.exit(2)
    except ImportError:
        logger.error('''pygraphviz is required, but not installed.''')
        sys.exit(2)

class PrintArgHelper:

    def __init__(self, logger):
        self.parser = None

        self.trusted_keys = None
        self.names = None
        self.analysis_structured = None

        self.args = None
        self._arg_mapping = None

        self._logger = logger

    def build_parser(self, prog):
        self.parser = argparse.ArgumentParser(description='Print the assessment of diagnostic DNS queries', prog=prog)

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
        self.parser.add_argument('-R', '--rr-types',
                type=self.comma_separated_dns_types,
                action='store', metavar='<type>,[<type>...]',
                help='Process queries of only the specified type(s)')
        self.parser.add_argument('-O', '--derive-filename',
                const=True, default=False,
                action='store_const',
                help='Derive the filename(s) from domain name(s)')
        self.parser.add_argument('-o', '--output-file',
                type=argparse.FileType('wb'), default=stdout_buffer,
                action='store', metavar='<filename>',
                help='Save the output to the specified file')
        self.parser.add_argument('domain_name',
                type=self.valid_domain_name,
                action='store', nargs='*', metavar='<domain_name>',
                help='Domain names')

        self._arg_mapping = dict([(a.dest, '/'.join(a.option_strings)) for a in self.parser._actions])

    def parse_args(self, args):
        self.args = self.parser.parse_args(args)

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
        if self.args.derive_filename and self.args.output_file.fileno() != sys.stdout.fileno():
            raise argparse.ArgumentTypeError('The %(derive_filename)s and %(output_file)s options may not be used together.' % \
                    self._arg_mapping)

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

    def update_trusted_key_info(self, latest_analysis_date):
        if self.args.trusted_keys_file is None:
            self.trusted_keys = get_default_trusted_keys(latest_analysis_date)

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
    arghelper = PrintArgHelper(logger)
    arghelper.build_parser('%s %s' % (cmd, subcmd))
    return arghelper

def main(argv):
    try:
        test_pygraphviz()

        arghelper = build_helper(logger, sys.argv[0], argv[0])
        arghelper.parse_args(argv[1:])
        logger.setLevel(logging.WARNING)

        try:
            arghelper.check_args()
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

        latest_analysis_date = None
        name_objs = []
        cache = {}
        for name in arghelper.names:
            name_str = lb2s(name.canonicalize().to_text())
            if name_str not in arghelper.analysis_structured or arghelper.analysis_structured[name_str].get('stub', True):
                logger.error('The analysis of "%s" was not found in the input.' % lb2s(name.to_text()))
                continue
            name_obj = TTLAgnosticOfflineDomainNameAnalysis.deserialize(name, arghelper.analysis_structured, cache, strict_cookies=arghelper.args.enforce_cookies, allow_private=arghelper.args.allow_private)
            name_objs.append(name_obj)

            if latest_analysis_date is None or latest_analysis_date > name_obj.analysis_end:
                latest_analysis_date = name_obj.analysis_end

        if not name_objs:
            sys.exit(4)

        arghelper.update_trusted_key_info(latest_analysis_date)

        G = DNSAuthGraph()
        for name_obj in name_objs:
            name_obj.populate_status(arghelper.trusted_keys, supported_algs=arghelper.args.algorithms, supported_digest_algs=arghelper.args.digest_algorithms, validate_prohibited_algs=arghelper.args.validate_prohibited_algs)
            for qname, rdtype in name_obj.queries:
                if arghelper.args.rr_types is None:
                    # if rdtypes was not specified, then graph all, with some
                    # exceptions
                    if name_obj.is_zone() and rdtype in (dns.rdatatype.DNSKEY, dns.rdatatype.DS, dns.rdatatype.DLV):
                        continue
                else:
                    # if rdtypes was specified, then only graph rdtypes that
                    # were specified
                    if qname != name_obj.name or rdtype not in arghelper.args.rr_types:
                        continue
                G.graph_rrset_auth(name_obj, qname, rdtype)

            if arghelper.args.rr_types is not None:
                for rdtype in arghelper.args.rr_types:
                    if (name_obj.name, rdtype) not in name_obj.queries:
                        logger.error('No query for "%s/%s" was included in the analysis.' % (lb2s(name_obj.name.to_text()), dns.rdatatype.to_text(rdtype)))

            if arghelper.args.derive_filename:
                if name_obj.name == dns.name.root:
                    name = 'root'
                else:
                    name = lb2s(name_obj.name.canonicalize().to_text()).rstrip('.')
                    name = name.replace(os.sep, '--')
                finish_graph(G, [name_obj], arghelper.args.rr_types, arghelper.trusted_keys, arghelper.args.algorithms, '%s.txt' % name)
                G = DNSAuthGraph()

        if not arghelper.args.derive_filename:
            finish_graph(G, name_objs, arghelper.args.rr_types, arghelper.trusted_keys, arghelper.args.algorithms, arghelper.args.output_file.fileno())

    except KeyboardInterrupt:
        logger.error('Interrupted.')
        sys.exit(4)

if __name__ == "__main__":
    main(sys.argv)
