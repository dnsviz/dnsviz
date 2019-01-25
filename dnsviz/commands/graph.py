#!/usr/bin/env python
#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Created by Casey Deccio (casey@deccio.net)
#
# Copyright 2014-2016 VeriSign, Inc.
#
# Copyright 2016-2019 Casey Deccio
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
from dnsviz.config import DNSVIZ_SHARE_PATH, JQUERY_PATH, JQUERY_UI_PATH, JQUERY_UI_CSS_PATH, RAPHAEL_PATH
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

LOCAL_MEDIA_URL = 'file://' + DNSVIZ_SHARE_PATH
DNSSEC_TEMPLATE_FILE = os.path.join(DNSVIZ_SHARE_PATH, 'html', 'dnssec-template.html')

logging.basicConfig(level=logging.WARNING, format='%(message)s')
logger = logging.getLogger()

def usage(err=None):
    if err is not None:
        err += '\n\n'
    else:
        err = ''
    sys.stderr.write('''%sUsage: %s %s [options] [domain_name...]

Graph the assessment of diagnostic DNS queries.

Options:
    -f <filename>  - Read names from a file.
    -r <filename>  - Read diagnostic queries from a file.
    -t <filename>  - Use trusted keys from the designated file.
    -C             - Enforce DNS cookies strictly.
    -R <type>[,<type>...]
                   - Process queries of only the specified type(s).
    -e             - Do not remove redundant RRSIG edges from the graph.
    -O             - Derive the filename(s) from the format and domain name(s).
    -o <filename>  - Save the output to the specified file.
    -T <format>    - Use the specified output format.
    -h             - Display the usage and exit.
''' % (err, sys.argv[0], __name__.split('.')[-1]))

def finish_graph(G, name_objs, rdtypes, trusted_keys, fmt, filename, remove_edges):
    G.add_trust(trusted_keys)

    if remove_edges:
        G.remove_extra_edges()

    if fmt == 'html':
        try:
            js_img = codecs.decode(G.draw('js'), 'utf-8')
        except IOError as e:
            logger.error(str(e))
            sys.exit(3)

        try:
            with io.open(DNSSEC_TEMPLATE_FILE, 'r', encoding='utf-8') as fh:
                template_str = fh.read()
        except IOError as e:
            logger.error('Error reading template file "%s": %s' % (DNSSEC_TEMPLATE_FILE, e.strerror))
            sys.exit(3)

        template_str = template_str.replace('LOCAL_MEDIA_URL', LOCAL_MEDIA_URL)
        template_str = template_str.replace('JQUERY_PATH', JQUERY_PATH)
        template_str = template_str.replace('JQUERY_UI_PATH', JQUERY_UI_PATH)
        template_str = template_str.replace('JQUERY_UI_CSS_PATH', JQUERY_UI_CSS_PATH)
        template_str = template_str.replace('RAPHAEL_PATH', RAPHAEL_PATH)
        template_str = template_str.replace('JS_CODE', js_img)

        if filename is None:
            filename = sys.stdout.fileno()
        try:
            io.open(filename, 'wt', encoding='utf-8').write(template_str)
        except IOError as e:
            logger.error('%s: "%s"' % (e.strerror, filename))
            sys.exit(3)
    else:
        if filename is None:
            io.open(sys.stdout.fileno(), 'wb').write(G.draw(fmt))
        else:
            try:
                G.draw(fmt, path=filename)
            except IOError as e:
                if e.strerror:
                    logger.error('%s: "%s"' % (e.strerror, filename))
                else:
                    logger.error(str(e))
                sys.exit(3)

def test_pygraphviz():
    try:
        from pygraphviz import release
        try:
            major, minor = release.version.split('.')[:2]
            major = int(major)
            minor = int(re.sub(r'(\d+)[^\d].*', r'\1', minor))
            if (major, minor) < (1,1):
                logger.error('''pygraphviz version >= 1.1 is required, but version %s is installed.''' % release.version)
                sys.exit(2)
        except ValueError:
            logger.error('''pygraphviz version >= 1.1 is required, but version %s is installed.''' % release.version)
            sys.exit(2)
    except ImportError:
        logger.error('''pygraphviz is required, but not installed.''')
        sys.exit(2)

def main(argv):
    try:
        test_pygraphviz()

        try:
            opts, args = getopt.getopt(argv[1:], 'f:r:R:et:COo:T:h')
        except getopt.GetoptError as e:
            sys.stderr.write('%s\n' % str(e))
            sys.exit(1)

        # collect trusted keys
        trusted_keys = []
        for opt, arg in opts:
            if opt == '-t':
                try:
                    with io.open(arg, 'r', encoding='utf-8') as fh:
                        tk_str = fh.read()
                except IOError as e:
                    logger.error('%s: "%s"' % (e.strerror, arg))
                    sys.exit(3)
                try:
                    trusted_keys.extend(get_trusted_keys(tk_str))
                except dns.exception.DNSException:
                    logger.error('There was an error parsing the trusted keys file: "%s"' % arg)
                    sys.exit(3)

        opts = dict(opts)
        if '-h' in opts:
            usage()
            sys.exit(0)

        if '-f' in opts and args:
            sys.stderr.write('If -f is used, then domain names may not supplied as command line arguments.\n')
            sys.exit(1)

        if '-R' in opts:
            try:
                rdtypes = opts['-R'].split(',')
            except ValueError:
                sys.stderr.write('The list of types was invalid: "%s"\n' % opts['-R'])
                sys.exit(1)
            try:
                rdtypes = [dns.rdatatype.from_text(x) for x in rdtypes]
            except dns.rdatatype.UnknownRdatatype:
                sys.stderr.write('The list of types was invalid: "%s"\n' % opts['-R'])
                sys.exit(1)
        else:
            rdtypes = None

        strict_cookies = '-C' in opts

        remove_edges = '-e' not in opts

        if '-T' in opts:
            fmt = opts['-T']
        elif '-o' in opts:
            fmt = opts['-o'].split('.')[-1]
        else:
            fmt = 'dot'
        if fmt not in ('dot','png','jpg','svg','html'):
            sys.stderr.write('Image format unrecognized: "%s"\n' % fmt)
            sys.exit(1)

        if '-o' in opts and '-O' in opts:
            sys.stderr.write('The -o and -O options may not be used together.\n')
            sys.exit(1)

        if '-r' not in opts or opts['-r'] == '-':
            opt_r = sys.stdin.fileno()
        else:
            opt_r = opts['-r']
        try:
            with io.open(opt_r, 'r', encoding='utf-8') as fh:
                analysis_str = fh.read()
        except IOError as e:
            logger.error('%s: "%s"' % (e.strerror, opts.get('-r', '-')))
            sys.exit(3)
        if not analysis_str:
            if opt_r != sys.stdin.fileno():
                logger.error('No input.')
            sys.exit(3)
        try:
            analysis_structured = json.loads(analysis_str)
        except ValueError:
            logger.error('There was an error parsing the JSON input: "%s"' % opts.get('-r', '-'))
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

        names = OrderedDict()
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
                    if name not in names:
                        names[name] = None
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
                    logger.error('No names found in JSON input!')
                    sys.exit(3)
            for name in args:
                try:
                    name = dns.name.from_text(name)
                except UnicodeDecodeError as e:
                    logger.error('%s: "%s"' % (e, name))
                except dns.exception.DNSException:
                    logger.error('The domain name was invalid: "%s"' % name)
                else:
                    if name not in names:
                        names[name] = None

        latest_analysis_date = None
        name_objs = []
        cache = {}
        for name in names:
            name_str = lb2s(name.canonicalize().to_text())
            if name_str not in analysis_structured or analysis_structured[name_str].get('stub', True):
                logger.error('The analysis of "%s" was not found in the input.' % lb2s(name.to_text()))
                continue
            name_obj = OfflineDomainNameAnalysis.deserialize(name, analysis_structured, cache, strict_cookies=strict_cookies)
            name_objs.append(name_obj)

            if latest_analysis_date is None or latest_analysis_date > name_obj.analysis_end:
                latest_analysis_date = name_obj.analysis_end

        if not name_objs:
            sys.exit(4)

        if '-t' not in opts:
            trusted_keys = get_default_trusted_keys(latest_analysis_date)

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
                finish_graph(G, [name_obj], rdtypes, trusted_keys, fmt, '%s.%s' % (name, fmt), remove_edges)
                G = DNSAuthGraph()

        if '-O' not in opts:
            if '-o' not in opts or opts['-o'] == '-':
                finish_graph(G, name_objs, rdtypes, trusted_keys, fmt, None, remove_edges)
            else:
                finish_graph(G, name_objs, rdtypes, trusted_keys, fmt, opts['-o'], remove_edges)

    except KeyboardInterrupt:
        logger.error('Interrupted.')
        sys.exit(4)

if __name__ == "__main__":
    main(sys.argv)
