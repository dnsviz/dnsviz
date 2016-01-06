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

import codecs
import collections
import getopt
import json
import logging
import re
import sys

import dns.exception, dns.name

from dnsviz.analysis import OfflineDomainNameAnalysis, DNS_RAW_VERSION
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
    sys.stderr.write('''%sUsage: dnsviz grok [options] [domain name...]
Options:
    -f <filename>  - read names from a file
    -r <filename>  - read diagnostic queries from a file
    -t <filename>  - specify file containing trusted keys
    -o <filename>  - save the output to the specified file
    -p             - make json output pretty instead of minimal
    -l <loglevel>  - set log level to one of: error, warning, info, debug
    -h             - display the usage and exit
''' % (err))

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

        try:
            opts, args = getopt.getopt(argv[1:], 'f:r:t:o:pl:h')
        except getopt.GetoptError, e:
            usage(str(e))
            sys.exit(1)

        # collect trusted keys
        trusted_keys = []
        for opt, arg in opts:
            if opt == '-t':
                try:
                    tk_str = open(arg).read()
                except IOError, e:
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
        if '_meta._dnsviz.' not in analysis_structured or 'version' not in analysis_structured['_meta._dnsviz.']:
            logger.error('No version information in JSON input.')
            sys.exit(3)
        try:
            major_vers, minor_vers = map(int, str(analysis_structured['_meta._dnsviz.']['version']).split('.', 1))
        except ValueError:
            logger.error('Version of JSON input is invalid: %s' % analysis_structured['_meta._dnsviz.']['version'])
            sys.exit(3)
        # ensure major version is a match and minor version is no greater
        # than the current minor version
        curr_major_vers, curr_minor_vers = map(int, str(DNS_RAW_VERSION).split('.', 1))
        if major_vers != curr_major_vers or minor_vers > curr_minor_vers:
            logger.error('Version %d.%d of JSON input is incompatible with this software.' % (major_vers, minor_vers))
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

        if '-p' in opts:
            kwargs = { 'indent': 4, 'separators': (',', ': ') }
        else:
            kwargs = {}

        if '-o' not in opts or opts['-o'] == '-':
            fh = sys.stdout
        else:
            try:
                fh = open(opts['-o'], 'w')
            except IOError, e:
                logger.error('%s: "%s"' % (e.strerror, opts['-o']))
                sys.exit(3)

        # if trusted keys were supplied, check that pygraphviz is installed
        if trusted_keys:
            test_pygraphviz()

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

        d = collections.OrderedDict()
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
            fh.write(json.dumps(d, **kwargs))

    except KeyboardInterrupt:
        logger.error('Interrupted.')
        sys.exit(4)

if __name__ == "__main__":
    main(sys.argv)
