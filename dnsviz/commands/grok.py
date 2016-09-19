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

# minimal support for python2.6
try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict

import dns.exception, dns.name

from dnsviz.analysis import OfflineDomainNameAnalysis, DNS_RAW_VERSION
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

def usage(err=None):
    if err is not None:
        err += '\n\n'
    else:
        err = ''
    sys.stderr.write('''%sUsage: dnsviz grok [options] [domain name...]
Options:
    -f <filename>  - read names from a file
    -r <filename>  - read diagnostic queries from a file
    -t <filename>  - specify file containing trusted keys
    -o <filename>  - save the output to the specified file
    -c             - make json output minimal instead of pretty
    -l <loglevel>  - set log level to one of: error, warning, info, debug
    -h             - display the usage and exit
''' % (err))

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

        #TODO remove -p option (it is now the default, and -c is used to change it)
        try:
            opts, args = getopt.getopt(argv[1:], 'f:r:t:o:cpl:h')
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

        if '-l' in opts:
            if opts['-l'] == 'error':
                loglevel = logging.ERROR
            elif opts['-l'] == 'warning':
                loglevel = logging.WARNING
            elif opts['-l'] == 'info':
                loglevel = logging.INFO
            elif opts['-l'] == 'debug':
                loglevel = logging.DEBUG
            else:
                usage('Invalid log level: "%s"' % opts['-l'])
                sys.exit(1)
        else:
            loglevel = logging.DEBUG
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

        if '-o' not in opts or opts['-o'] == '-':
            opts['-o'] = sys.stdout.fileno()
        try:
            fh = io.open(opts['-o'], 'wb')
        except IOError as e:
            logger.error('%s: "%s"' % (e.strerror, opts['-o']))
            sys.exit(3)

        if '-c' not in opts:
            kwargs = { 'indent': 4, 'separators': (',', ': ') }
        else:
            kwargs = {}

        # if trusted keys were supplied, check that pygraphviz is installed
        if trusted_keys:
            test_pygraphviz()

        name_objs = []
        cache = {}
        for name in names:
            name_str = lb2s(name.canonicalize().to_text())
            if name_str not in analysis_structured or analysis_structured[name_str].get('stub', True):
                logger.error('The analysis of "%s" was not found in the input.' % lb2s(name.to_text()))
                continue
            name_objs.append(OfflineDomainNameAnalysis.deserialize(name, analysis_structured, cache))

        if not name_objs:
            sys.exit(4)

        d = OrderedDict()
        for name_obj in name_objs:
            name_obj.populate_status(trusted_keys)

            if trusted_keys:
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
                G.add_trust(trusted_keys)
                name_obj.populate_response_component_status(G)

            name_obj.serialize_status(d, loglevel=loglevel)

        if d:
            s = json.dumps(d, ensure_ascii=False, **kwargs)
            if '-c' not in opts and fh.isatty() and os.environ.get('TERM', 'dumb') != 'dumb':
                s = color_json(s)
            fh.write(s.encode('utf-8'))

    except KeyboardInterrupt:
        logger.error('Interrupted.')
        sys.exit(4)

if __name__ == "__main__":
    main(sys.argv)
