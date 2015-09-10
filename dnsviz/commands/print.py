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
# with DNSViz.  If not, see <http://www.gnu.org/licenses/>.
#

import codecs
import getopt
import json
import logging
import os
import re
import sys

import dns.exception, dns.name

from dnsviz.analysis import OfflineDomainNameAnalysis, DNS_RAW_VERSION
from dnsviz.viz.dnssec import DNSAuthGraph
from dnsviz.util import get_trusted_keys

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

def finish_graph(G, name_objs, rdtypes, trusted_keys, filename, fh=None):
    assert filename is not None or fh is not None, 'Either filename or fh must be passed'

    G.add_trust(trusted_keys)

    if filename is None:
        show_colors = fh.isatty() and os.environ.get('TERM', 'dumb') != 'dumb'
    else:
        show_colors = False
        try:
            fh = codecs.open(filename, 'w', 'utf-8')
        except IOError, e:
            logger.error('%s: "%s"' % (e.strerror, filename))

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
    join_str = join_str_template % params
    s += join_str.join(rdata_set) + '\n'

    for rdtype_str_child, status_child, warnings_child, errors_child, rdata_child, children_child in children:
        s += _textualize_status_output_response(rdtype_str_child, status_child, warnings_child, errors_child, rdata_child, children_child, depth + 1, show_color)

    return s

def _textualize_status_output_name(name, status, warnings, errors, responses, show_color):
    s = ''

    name_template = '%(status_color)s%(name)s%(color_reset)s%(status_color_rdata)s%(status_rdata)s%(color_reset)s\n'

    params = {}
    params['status_color'] = ''
    params['status_color_rdata'] = ''

    if show_color:
        params['color_reset'] = TERM_COLOR_MAP['RESET']
    else:
        params['color_reset'] = ''

    params['name'] = name
    params['status_rdata'] = ''
    if show_color:
        params['status_color'] = TERM_COLOR_MAP['BOLD']
        params['color_reset'] = TERM_COLOR_MAP['RESET']
    if status is not None:
        params['status_rdata'] = ' ' + _errors_warnings_str(status, warnings, errors, show_color)
        if show_color:
            params['status_color_rdata'] = TERM_COLOR_MAP[status]
    s += name_template % params

    for rdtype_str, status, warnings, errors, rdata, children in responses:
        s += _textualize_status_output_response(rdtype_str, status, warnings, errors, rdata, children, 0, show_color)

    return s

def textualize_status_output(names, show_color):
    s = ''
    for name, status, warnings, errors, responses in names:
        s += _textualize_status_output_name(name, status, warnings, errors, responses, show_color)

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
        except getopt.GetoptError, e:
            usage(str(e))
            sys.exit(1)

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
                rdtypes = map(dns.rdatatype.from_text, rdtypes)
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
            logger.error('There was an error parsing the json input: "%s"' % opts.get('-r', '-'))
            sys.exit(3)

        # check version
        if '_meta._dnsviz.' in analysis_structured and 'version' in analysis_structured['_meta._dnsviz.'] and analysis_structured['_meta._dnsviz.']['version'] > DNS_RAW_VERSION:
            logger.error('Unsupported version: "%s"' % analysis_structured['_meta._dnsviz.']['version'])
            sys.exit(3)

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

        if '-t' in opts:
            try:
                tk_str = open(opts['-t']).read()
            except IOError, e:
                logger.error('%s: "%s"' % (e.strerror, opts['-t']))
                sys.exit(3)
            try:
                trusted_keys = get_trusted_keys(tk_str)
            except dns.exception.DNSException:
                logger.error('There was an error parsing the trusted keys file: "%s"' % opts['-t'])
                sys.exit(3)
        else:
            trusted_keys = ()

        name_objs = []
        cache = {}
        for name in names:
            name_str = name.canonicalize().to_text()
            if name_str not in analysis_structured or analysis_structured[name_str].get('stub', True):
                logger.error('The analysis of "%s" was not found in the input.' % name.to_text())
                continue
            name_objs.append(OfflineDomainNameAnalysis.deserialize(name, analysis_structured, cache))

        if not name_objs:
            sys.exit(4)

        G = DNSAuthGraph()
        for name_obj in name_objs:
            name_obj.populate_status(trusted_keys)
            for qname, rdtype in name_obj.queries:
                if rdtypes is None:
                    # if rdtypes was not specified, then graph all, with some
                    # exceptions
                    if name_obj.is_zone() and rdtype in (dns.rdatatype.NS, dns.rdatatype.DNSKEY, dns.rdatatype.DS, dns.rdatatype.DLV):
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
                        logger.error('No query for "%s/%s" was included in the analysis.' % (name_obj.name.to_text(), dns.rdatatype.to_text(rdtype)))

            if '-O' in opts:
                if name_obj.name == dns.name.root:
                    name = 'root'
                else:
                    name = name_obj.name.canonicalize().to_text().rstrip('.')
                finish_graph(G, [name_obj], rdtypes, trusted_keys, '%s.txt' % name)
                G = DNSAuthGraph()

        if '-O' not in opts:
            if '-o' not in opts or opts['-o'] == '-':
                finish_graph(G, name_objs, rdtypes, trusted_keys, None, sys.stdout)
            else:
                finish_graph(G, name_objs, rdtypes, trusted_keys, opts['-o'])

    except KeyboardInterrupt:
        logger.error('Interrupted.')
        sys.exit(4)

if __name__ == "__main__":
    main(sys.argv)
