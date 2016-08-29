#!/usr/bin/env python
#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Created by Casey Deccio (casey@deccio.net)
#
# Copyright 2014-2016 VeriSign, Inc.
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

import codecs
import getopt
import io
import json
import logging
import os
import re
import sys

import dns.exception, dns.name

from dnsviz.analysis import TTLAgnosticOfflineDomainNameAnalysis, DNS_RAW_VERSION
from dnsviz.format import latin1_binary_to_string as lb2s
from dnsviz.util import TRUSTED_KEYS_ROOT, get_trusted_keys

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

logger = logging.getLogger('dnsviz.analysis.offline')

def usage(err=None):
    if err is not None:
        err += '\n\n'
    else:
        err = ''
    sys.stderr.write('''%sUsage: dnsviz print [options] [domain name...]
Options:
    -f <filename>  - read names from a file
    -r <filename>  - read diagnostic queries from a file
    -t <filename>  - specify file containing trusted keys
    -R <type>[,<type>...]
                   - Process queries of only the specified type(s)
    -O             - derive the filename(s) from domain name(s)
    -o <filename>  - save the output to the specified file
    -h             - display the usage and exit
''' % (err))

def finish_graph(G, name_objs, rdtypes, trusted_keys, filename):
    G.add_trust(trusted_keys)

    if filename is None:
        filename = sys.stdout.fileno()
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

def test_m2crypto():
    try:
        import M2Crypto
    except ImportError:
        sys.stderr.write('''Warning: M2Crypto is not installed; cryptographic validation of signatures and digests will not be available.\n''')

def test_pygraphviz():
    try:
        from pygraphviz import release
        try:
            major, minor = release.version.split('.')[:2]
            major = int(major)
            minor = int(re.sub(r'(\d+)[^\d].*', r'\1', minor))
            if (major, minor) < (1,1):
                sys.stderr.write('''pygraphviz version >= 1.1 is required, but version %s is installed.\n''' % release.version)
                sys.exit(2)
        except ValueError:
            sys.stderr.write('''pygraphviz version >= 1.1 is required, but version %s is installed.\n''' % release.version)
            sys.exit(2)
    except ImportError:
        sys.stderr.write('''pygraphviz is required, but not installed.\n''')
        sys.exit(2)

def main(argv):
    try:
        test_m2crypto()
        test_pygraphviz()

        try:
            opts, args = getopt.getopt(argv[1:], 'f:r:R:t:Oo:h')
        except getopt.GetoptError as e:
            usage(str(e))
            sys.exit(1)

        # collect trusted keys
        trusted_keys = []
        for opt, arg in opts:
            if opt == '-t':
                try:
                    tk_str = io.open(arg, 'r', encoding='utf-8').read()
                except IOError as e:
                    sys.stderr.write('%s: "%s"\n' % (e.strerror, arg))
                    sys.exit(3)
                try:
                    trusted_keys.extend(get_trusted_keys(tk_str))
                except dns.exception.DNSException:
                    sys.stderr.write('There was an error parsing the trusted keys file: "%s"\n' % arg)
                    sys.exit(3)

        opts = dict(opts)
        if '-h' in opts:
            usage()
            sys.exit(0)

        if '-f' in opts and args:
            usage('If -f is used, then domain names may not supplied as command line arguments.')
            sys.exit(1)

        if '-R' in opts:
            try:
                rdtypes = opts['-R'].split(',')
            except ValueError:
                usage('The list of types was invalid: "%s"' % opts['-R'])
                sys.exit(1)
            try:
                rdtypes = [dns.rdatatype.from_text(x) for x in rdtypes]
            except dns.rdatatype.UnknownRdatatype:
                usage('The list of types was invalid: "%s"' % opts['-R'])
                sys.exit(1)
        else:
            rdtypes = None

        if '-o' in opts and '-O' in opts:
            usage('The -o and -O options may not be used together.')
            sys.exit(1)

        handler = logging.StreamHandler()
        handler.setLevel(logging.WARNING)
        logger.addHandler(handler)
        logger.setLevel(logging.WARNING)

        if '-r' not in opts or opts['-r'] == '-':
            opt_r = sys.stdin.fileno()
        else:
            opt_r = opts['-r']
        try:
            analysis_str = io.open(opt_r, 'r', encoding='utf-8').read()
        except IOError as e:
            logger.error('%s: "%s"' % (e.strerror, opts.get('-r', '-')))
            sys.exit(3)
        try:
            analysis_structured = json.loads(analysis_str)
        except ValueError:
            logger.error('There was an error parsing the json input: "%s"' % opts.get('-r', '-'))
            sys.exit(3)

        # check version
        if '_meta._dnsviz.' not in analysis_structured or 'version' not in analysis_structured['_meta._dnsviz.']:
            logger.error('No version information in JSON input.')
            sys.exit(3)
        try:
            major_vers, minor_vers = [int(x) for x in str(analysis_structured['_meta._dnsviz.']['version']).split('.', 1)]
        except ValueError:
            logger.error('Version of JSON input is invalid: %s' % analysis_structured['_meta._dnsviz.']['version'])
            sys.exit(3)
        # ensure major version is a match and minor version is no greater
        # than the current minor version
        curr_major_vers, curr_minor_vers = [int(x) for x in str(DNS_RAW_VERSION).split('.', 1)]
        if major_vers != curr_major_vers or minor_vers > curr_minor_vers:
            logger.error('Version %d.%d of JSON input is incompatible with this software.' % (major_vers, minor_vers))
            sys.exit(3)

        names = []
        if '-f' in opts:
            if opts['-f'] == '-':
                opts['-f'] = sys.stdin.fileno()
            try:
                f = io.open(opts['-f'], 'r', encoding='utf-8')
            except IOError as e:
                logger.error('%s: "%s"' % (e.strerror, opts['-f']))
                sys.exit(3)
            for line in f:
                name = line.strip()
                try:
                    name = dns.name.from_text(name)
                except UnicodeDecodeError as e:
                    logger.error('%s: "%s"' % (e, name))
                except dns.exception.DNSException:
                    logger.error('The domain name was invalid: "%s"' % name)
                else:
                    names.append(name)
            f.close()
        else:
            if args:
                # python3/python2 dual compatibility
                if isinstance(args[0], bytes):
                    args = [codecs.decode(x, sys.getfilesystemencoding()) for x in args]
            else:
                try:
                    args = analysis_structured['_meta._dnsviz.']['names']
                except KeyError:
                    logger.error('No names found in json input!')
                    sys.exit(3)
            for name in args:
                try:
                    name = dns.name.from_text(name)
                except UnicodeDecodeError as e:
                    logger.error('%s: "%s"' % (e, name))
                except dns.exception.DNSException:
                    logger.error('The domain name was invalid: "%s"' % name)
                else:
                    names.append(name)

        if '-t' not in opts:
            try:
                tk_str = io.open(TRUSTED_KEYS_ROOT, 'r', encoding='utf-8').read()
            except IOError as e:
                logger.error('Error reading trusted keys file "%s": %s' % (TRUSTED_KEYS_ROOT, e.strerror))
                sys.exit(3)
            try:
                trusted_keys.extend(get_trusted_keys(tk_str))
            except dns.exception.DNSException:
                logger.error('There was an error parsing the trusted keys file: "%s"' % arg)
                sys.exit(3)

        name_objs = []
        cache = {}
        for name in names:
            name_str = lb2s(name.canonicalize().to_text())
            if name_str not in analysis_structured or analysis_structured[name_str].get('stub', True):
                logger.error('The analysis of "%s" was not found in the input.' % lb2s(name.to_text()))
                continue
            name_objs.append(TTLAgnosticOfflineDomainNameAnalysis.deserialize(name, analysis_structured, cache))

        if not name_objs:
            sys.exit(4)

        G = DNSAuthGraph()
        for name_obj in name_objs:
            name_obj.populate_status(trusted_keys)
            for qname, rdtype in name_obj.queries:
                if rdtypes is None:
                    # if rdtypes was not specified, then graph all, with some
                    # exceptions
                    if name_obj.is_zone() and rdtype in (dns.rdatatype.DNSKEY, dns.rdatatype.DS, dns.rdatatype.DLV):
                        continue
                else:
                    # if rdtypes was specified, then only graph rdtypes that
                    # were specified
                    if qname != name_obj.name or rdtype not in rdtypes:
                        continue
                G.graph_rrset_auth(name_obj, qname, rdtype)

            if rdtypes is not None:
                for rdtype in rdtypes:
                    if (name_obj.name, rdtype) not in name_obj.queries:
                        logger.error('No query for "%s/%s" was included in the analysis.' % (lb2s(name_obj.name.to_text()), dns.rdatatype.to_text(rdtype)))

            if '-O' in opts:
                if name_obj.name == dns.name.root:
                    name = 'root'
                else:
                    name = lb2s(name_obj.name.canonicalize().to_text()).rstrip('.')
                finish_graph(G, [name_obj], rdtypes, trusted_keys, '%s.txt' % name)
                G = DNSAuthGraph()

        if '-O' not in opts:
            if '-o' not in opts or opts['-o'] == '-':
                finish_graph(G, name_objs, rdtypes, trusted_keys, None)
            else:
                finish_graph(G, name_objs, rdtypes, trusted_keys, opts['-o'])

    except KeyboardInterrupt:
        logger.error('Interrupted.')
        sys.exit(4)

if __name__ == "__main__":
    main(sys.argv)
