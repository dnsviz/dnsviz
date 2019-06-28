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

from dnsviz.analysis import status as Status
from dnsviz.analysis import TTLAgnosticOfflineDomainNameAnalysis, DNS_RAW_VERSION
from dnsviz.format import humanize_name, latin1_binary_to_string as lb2s
from dnsviz.util import get_trusted_keys, get_default_trusted_keys

logging.basicConfig(level=logging.WARNING, format='%(message)s')
logger = logging.getLogger()

def usage(err=None):
    if err is not None:
        err += '\n\n'
    else:
        err = ''
    sys.stderr.write('''%sUsage: %s %s [options] [domain_name...]

Print the assessment of diagnostic DNS queries.

Options:
    -f <filename>  - Read names from a file.
    -r <filename>  - Read diagnostic queries from a file.
    -t <filename>  - Use trusted keys from the designated file.
    -a <alg>[,<alg>...]
                   - Support only the specified DNSSEC algorithm(s).
    -d <digest_alg>[,<digest_alg>...]
                   - Support only the specified DNSSEC digest algorithm(s).
    -C             - Enforce DNS cookies strictly.
    -P             - Allow private IP addresses for authoritative DNS servers.
    -O             - Derive the filename(s) from domain name(s).
    -o <filename>  - Save the output to the specified file.
    -h             - Display the usage and exit.
''' % (err, sys.argv[0], __name__.split('.')[-1]))

def finish_graph(name_objs, filename):
    if filename is None:
        filename = sys.stdout.fileno()
    try:
        fh = io.open(filename, 'w', encoding='utf-8')
    except IOError as e:
        logger.error('%s: "%s"' % (e.strerror, filename))
        sys.exit(3)

    show_colors = fh.isatty() and os.environ.get('TERM', 'dumb') != 'dumb'

    tuples = []
    for name_obj in name_objs:
        fh.write(textualize_status_output(name_obj.zone, show_colors))

TERM_COLOR_MAP = {
    'BOLD': '\033[1m',
    'RESET': '\033[0m',
    Status.SERVER_CHECKLIST_STATUS_OK: '\033[36m',
    Status.SERVER_CHECKLIST_STATUS_INDETERMINATE: '\033[37m',
    Status.SERVER_CHECKLIST_STATUS_WARNING: '\033[33m',
    Status.SERVER_CHECKLIST_STATUS_ERROR: '\033[31m',
}

STATUS_MAP = {
    Status.SERVER_CHECKLIST_STATUS_OK: '.',
    Status.SERVER_CHECKLIST_STATUS_INDETERMINATE: '-',
    Status.SERVER_CHECKLIST_STATUS_WARNING: '?',
    Status.SERVER_CHECKLIST_STATUS_ERROR: '!',
}

def textualize_status_output(zone_obj, show_color):
    s = ''

    name_template = '%(status_color)s%(name)s%(color_reset)s\n'
    server_status_template = '[%(status_color)s %(status)s%(color_reset)s] '
    server_row_template = '    [%(status_color)s%(server_index)2d%(color_reset)s] %(server_name)s (%(server)s)\n'
    column_header_template = '[%(status_color)s%(server_index)2d%(color_reset)s] '
    server_status_header = '%(indent)s%(status_color)s%(status)s%(color_reset)s: '

    params = {}
    params['status_color'] = ''
    params['status_color_rdata'] = ''

    if show_color:
        params['color_reset'] = TERM_COLOR_MAP['RESET']
    else:
        params['color_reset'] = ''

    params['name'] = humanize_name(zone_obj.name)
    if show_color:
        params['status_color'] = TERM_COLOR_MAP['BOLD']
    s += name_template % params

    server_list = [(ip, zone_obj.get_ns_name_for_ip(ip)[0]) for ip in zone_obj.get_auth_or_designated_servers()]
    server_list = sorted(server_list, key=lambda x: (x[1][0], x[0]))

    i = 1
    if show_color:
        params['status_color'] = TERM_COLOR_MAP['BOLD']
    for server, ns_name in server_list:
        params['server_index'] = i
        params['server_name'] = humanize_name(ns_name[0])
        params['server'] = server
        s += server_row_template % params
        i += 1

    indent_size = max([len(status) for status in zone_obj.server_checklist]) + 2
    s += (' ' * indent_size) + '  '

    if show_color:
        params['status_color'] = TERM_COLOR_MAP['BOLD']
    for i in range(len(server_list)):
        params['server_index'] = i + 1
        s += column_header_template % params
    s += '\n'

    for status in zone_obj.server_checklist:
        params['indent'] = ' ' * (indent_size - len(status))
        if show_color:
            params['status_color'] = TERM_COLOR_MAP['BOLD']
        params['status'] = status
        s += server_status_header % params
        for server, ns_name in server_list:
            if server in zone_obj.server_checklist[status]:
                st = zone_obj.server_checklist[status][server]
                if show_color:
                    params['status_color'] = TERM_COLOR_MAP[st.status]
                params['status'] = STATUS_MAP[st.status]
                s += server_status_template % params
            else:
                if show_color:
                    params['status_color'] = TERM_COLOR_MAP[Status.SERVER_CHECKLIST_STATUS_INDETERMINATE]
                params['status'] = STATUS_MAP[Status.SERVER_CHECKLIST_STATUS_INDETERMINATE]
                s += server_status_template % params
        s += '\n'

    return s

def main(argv):
    try:
        try:
            opts, args = getopt.getopt(argv[1:], 'f:r:t:a:d:CPOo:h')
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

        if '-a' in opts:
            try:
                supported_algs = set([int(x) for x in opts['-a'].split(',')])
            except ValueError:
                sys.stderr.write('The list of algorithms was invalid: "%s"\n' % opts['-a'])
                sys.exit(1)
        else:
            supported_algs = None

        if '-d' in opts:
            try:
                supported_digest_algs = set([int(x) for x in opts['-d'].split(',')])
            except ValueError:
                sys.stderr.write('The list of digest algorithms was invalid: "%s"\n' % opts['-d'])
                sys.exit(1)
        else:
            supported_digest_algs = None

        strict_cookies = '-C' in opts
        allow_private = '-P' in opts

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
            name_obj = TTLAgnosticOfflineDomainNameAnalysis.deserialize(name, analysis_structured, cache, strict_cookies=strict_cookies, allow_private=allow_private)
            name_objs.append(name_obj)

            if latest_analysis_date is None or latest_analysis_date > name_obj.analysis_end:
                latest_analysis_date = name_obj.analysis_end

        if not name_objs:
            sys.exit(4)

        if '-t' not in opts:
            trusted_keys = get_default_trusted_keys(latest_analysis_date)

        for name_obj in name_objs:
            name_obj.populate_status(trusted_keys, supported_algs=supported_algs, supported_digest_algs=supported_digest_algs)

            if '-O' in opts:
                if name_obj.name == dns.name.root:
                    name = 'root'
                else:
                    name = lb2s(name_obj.name.canonicalize().to_text()).rstrip('.')
                finish_graph([name_obj], '%s.txt' % name)

        if '-O' not in opts:
            if '-o' not in opts or opts['-o'] == '-':
                finish_graph(name_objs, None)
            else:
                finish_graph(name_objs, opts['-o'])

    except KeyboardInterrupt:
        logger.error('Interrupted.')
        sys.exit(4)

if __name__ == "__main__":
    main(sys.argv)
