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
from dnsviz.config import DNSVIZ_SHARE_PATH, JQUERY_PATH, JQUERY_UI_PATH, JQUERY_UI_CSS_PATH, RAPHAEL_PATH
from dnsviz.viz.dnssec import DNSAuthGraph
from dnsviz.util import get_trusted_keys

LOCAL_MEDIA_URL = 'file://' + DNSVIZ_SHARE_PATH
DNSSEC_TEMPLATE_FILE = os.path.join(DNSVIZ_SHARE_PATH, 'html', 'dnssec-template.html')

logger = logging.getLogger('dnsviz.analysis.offline')

def usage(err=None):
    if err is not None:
        err += '\n\n'
    else:
        err = ''
    sys.stderr.write('''%sUsage: dnsviz graph [options] [domain name...]
Options:
    -f <filename>  - read names from a file
    -r <filename>  - read diagnostic queries from a file
    -t <filename>  - specify file containing trusted keys
    -R <type>[,<type>...]
                   - Process queries of only the specified type(s)
    -O             - derive the filename(s) from the format and domain name(s)
    -o <filename>  - save the output to the specified file
    -T <format>    - specify the format of the output
    -h             - display the usage and exit
''' % (err))

def finish_graph(G, name_objs, rdtypes, trusted_keys, fmt, filename, fh=None):
    assert filename is not None or fh is not None, 'Either filename or fh must be passed'

    G.add_trust(trusted_keys)
    G.remove_extra_edges()

    if fmt == 'html':
        js_img = G.draw('js')

        template_str = codecs.open(DNSSEC_TEMPLATE_FILE, 'r', 'utf-8').read()
        template_str = template_str.replace('LOCAL_MEDIA_URL', LOCAL_MEDIA_URL)
        template_str = template_str.replace('JQUERY_PATH', JQUERY_PATH)
        template_str = template_str.replace('JQUERY_UI_PATH', JQUERY_UI_PATH)
        template_str = template_str.replace('JQUERY_UI_CSS_PATH', JQUERY_UI_CSS_PATH)
        template_str = template_str.replace('RAPHAEL_PATH', RAPHAEL_PATH)
        template_str = template_str.replace('JS_CODE', js_img)
        if filename is None:
            fh.write(template_str)
        else:
            try:
                codecs.open(filename, 'w', 'utf-8').write(template_str)
            except IOError, e:
                logger.error('%s: "%s"' % (e.strerror, filename))
    else:
        if filename is None:
            fh.write(G.draw(fmt))
        else:
            try:
                G.draw(fmt, path=filename)
            except IOError, e:
                logger.error('%s: "%s"' % (e.strerror, filename))

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
            opts, args = getopt.getopt(argv[1:], 'f:r:R:t:Oo:T:h')
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

        if '-T' in opts:
            fmt = opts['-T']
        elif '-o' in opts:
            fmt = opts['-o'].split('.')[-1]
        else:
            fmt = 'dot'
        if fmt not in ('dot','png','jpg','svg','html'):
            usage('Image format unrecognized: "%s"' % fmt)
            sys.exit(1)

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
                        logger.error('No query for "%s/%s" was included in the analysis.' % (name_obj.name.to_text(), dns.rdatatype.to_text(rdtype)))

            if '-O' in opts:
                if name_obj.name == dns.name.root:
                    name = 'root'
                else:
                    name = name_obj.name.canonicalize().to_text().rstrip('.')
                finish_graph(G, [name_obj], rdtypes, trusted_keys, fmt, '%s.%s' % (name, fmt))
                G = DNSAuthGraph()

        if '-O' not in opts:
            if '-o' not in opts or opts['-o'] == '-':
                finish_graph(G, name_objs, rdtypes, trusted_keys, fmt, None, sys.stdout)
            else:
                finish_graph(G, name_objs, rdtypes, trusted_keys, fmt, opts['-o'])

    except KeyboardInterrupt:
        logger.error('Interrupted.')
        sys.exit(4)

if __name__ == "__main__":
    main(sys.argv)
