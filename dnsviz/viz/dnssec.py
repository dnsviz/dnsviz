#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Created by Casey Deccio (casey@deccio.net)
#
# Copyright 2012-2014 Sandia Corporation. Under the terms of Contract
# DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government retains
# certain rights in this software.
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

import codecs
import errno
import io
import json
import os
import re
import sys
import xml.dom.minidom

# minimal support for python2.6
try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict

# python3/python2 dual compatibility
try:
    from html import escape
except ImportError:
    from cgi import escape

import dns.name, dns.rdtypes, dns.rdatatype, dns.dnssec

from pygraphviz import AGraph

from dnsviz.analysis import status as Status
from dnsviz.analysis import errors as Errors
from dnsviz.analysis.online import ANALYSIS_TYPE_RECURSIVE
from dnsviz.config import DNSVIZ_SHARE_PATH
from dnsviz import crypto
from dnsviz import format as fmt
from dnsviz import query as Q
from dnsviz import response as Response
from dnsviz.util import tuple_to_dict
lb2s = fmt.latin1_binary_to_string

COLORS = { 'secure': '#0a879a', 'secure_non_existent': '#9dcfd6',
        'bogus': '#be1515', 'bogus_non_existent': '#e5a1a1',
        'insecure': '#000000', 'insecure_non_existent': '#d0d0d0',
        'misconfigured': '#f4b800',
        'indeterminate': '#f4b800',
        'expired': '#6131a3',
        'invalid': '#be1515' }

INVIS_STYLE_RE = re.compile(r'(^|,)invis(,|$)')
DASHED_STYLE_RE = re.compile(r'(^|,)dashed(,|$)')
OPTOUT_STYLE_RE = re.compile(r'BGCOLOR="lightgray"')

ICON_PATH=os.path.join(DNSVIZ_SHARE_PATH, 'icons')
WARNING_ICON=os.path.join(ICON_PATH, 'warning.png')
ERROR_ICON=os.path.join(ICON_PATH, 'error.png')

# python3/python2.6 dual compatibility
vers0, vers1, vers2 = sys.version_info[:3]
if (vers0, vers1) == (2, 6):
    execv_encode = lambda x: codecs.encode(x, sys.getfilesystemencoding())
else:
    execv_encode = lambda x: x

class DNSKEYNonExistent(object):
    def __init__(self, name, algorithm, key_tag):
        self.name = name
        self.algorithm = algorithm
        self.key_tag = key_tag

    def serialize(self):
        d = OrderedDict()
        d['flags'] = None
        d['protocol'] = None
        d['algorithm'] = self.algorithm
        d['key'] = None
        d['ttl'] = None
        d['key_length'] = None
        d['key_tag'] = self.key_tag
        return d

class RRsetNonExistent(object):
    def __init__(self, name, rdtype, nxdomain, servers_clients):
        self.name = name
        self.rdtype = rdtype
        self.nxdomain = nxdomain
        self.servers_clients = servers_clients

    def serialize(self, consolidate_clients, html_format=False, map_ip_to_ns_name=None):
        d = OrderedDict()

        if html_format:
            formatter = lambda x: escape(x, True)
        else:
            formatter = lambda x: x

        if self.rdtype == dns.rdatatype.NSEC3:
            d['name'] = fmt.format_nsec3_name(self.name)
        else:
            d['name'] = formatter(lb2s(self.name.canonicalize().to_text()))
        d['ttl'] = None
        d['type'] = dns.rdatatype.to_text(self.rdtype)
        if self.nxdomain:
            d['rdata'] = ['NXDOMAIN']
        else:
            d['rdata'] = ['NODATA']

        servers = tuple_to_dict(self.servers_clients)
        if consolidate_clients:
            servers = list(servers)
            servers.sort()
        d['servers'] = servers

        if map_ip_to_ns_name is not None:
            ns_names = list(set([lb2s(map_ip_to_ns_name(s)[0][0].canonicalize().to_text()) for s in servers]))
            ns_names.sort()
            d['ns_names'] = ns_names

        tags = set()
        nsids = []
        for server,client in self.servers_clients:
            for response in self.servers_clients[(server,client)]:
                tags.add(response.effective_query_tag())
                nsid = response.nsid_val()
                if nsid is not None:
                    nsids.append(nsid)

        if nsids:
            d['nsid_values'] = nsids
            d['nsid_values'].sort()

        d['query_options'] = list(tags)
        d['query_options'].sort()

        return d

class DNSAuthGraph:
    def __init__(self, dlv_domain=None):
        self.dlv_domain = dlv_domain

        self.G = AGraph(directed=True, strict=False, compound='true', rankdir='BT', ranksep='0.3')

        self.G.node_attr['penwidth'] = '1.5'
        self.G.edge_attr['penwidth'] = '1.5'
        self.node_info = {}
        self.node_mapping = {}
        self.node_reverse_mapping = {}
        self.nsec_rr_status = {}
        self.secure_dnskey_rrsets = set()
        self.subgraph_not_stub = set()
        self.node_subgraph_name = {}
        self.processed_rrsets = {}

        self.dnskey_ids = {}
        self.ds_ids = {}
        self.nsec_ids = {}
        self.rrset_ids = {}
        self.next_dnskey_id = 0
        self.next_ds_id = 0
        self.next_nsec_id = 0
        self.next_rrset_id = 10

        self._edge_keys = set()

    def _raphael_unit_mapping_expression(self, val, unit):
        #XXX doesn't work properly
        #if unit:
        #    return '%s*to_pixel_mapping[\'%s\']' % (val, unit)
        return val

    def _raphael_transform_str(self, trans_value):
        transform_re = re.compile(r'(scale|rotate|translate)\((-?[0-9\.]+(px|pt|cm|in)?((,\s*|\s+)-?[0-9\.]+(px|pt|cm|in)?)?)\)')
        number_units_re = re.compile(r'(-?[0-9\.]+)(px|pt|cm|in)?')

        t = ''
        for m in transform_re.findall(trans_value):
            if m[0] == 'scale':
                coords = number_units_re.findall(m[1])
                if (len(coords) > 1):
                    t += 's%s,%s,0,0' % (self._raphael_unit_mapping_expression(coords[0][0], coords[0][1]), self._raphael_unit_mapping_expression(coords[1][0], coords[1][1]))
                else:
                    t += 's%s,0,0,0' % (coords[0])
            if m[0] == 'translate':
                coords = number_units_re.findall(m[1])
                if (len(coords) > 1):
                    t += 't%s,%s' % (self._raphael_unit_mapping_expression(coords[0][0], coords[0][1]), self._raphael_unit_mapping_expression(coords[1][0], coords[1][1]))
                else:
                    t += 't%s,0,' % (self._raphael_unit_mapping_expression(coords[0][0], coords[0][1]))
        return t

    def _write_raphael_node(self, node, node_id, transform):
        required_attrs = { 'path': set(['d']), 'ellipse': set(['cx','cy','rx','ry']),
            'polygon': set(['points']), 'polyline': set(['points']),
            'text': set(['x','y']), 'image': set(['src','x','y','width','height']) }

        number_units_re = re.compile(r'(-?[0-9\.]+)(px|pt|cm|in)?')

        s = ''
        if node.nodeType != xml.dom.Node.ELEMENT_NODE:
            return s
        if node.hasAttribute('id'):
            node_id = node.getAttribute('id')
        if node.nodeName == 'svg':
            width, width_unit = number_units_re.match(node.getAttribute('width')).group(1, 2)
            height, height_unit = number_units_re.match(node.getAttribute('height')).group(1, 2)
            s += '''
	var imageWidth = %s*this.imageScale;
	var imageHeight = %s*this.imageScale;
	if (this.maxPaperWidth > 0 && imageWidth > this.maxPaperWidth) {
		paperScale = this.maxPaperWidth/imageWidth;
	} else {
		paperScale = 1.0;
	}
''' % (width, height)
            s += '\tpaper = Raphael(this.anchorElement, parseInt(paperScale*imageWidth), parseInt(paperScale*imageHeight));\n'
        else:
            if node.nodeName == 'path':
                s += '\tel = paper.path(\'%s\')' % node.getAttribute('d')
            elif node.nodeName == 'ellipse':
                s += '\tel = paper.ellipse(%s, %s, %s, %s)' % (node.getAttribute('cx'), node.getAttribute('cy'),
                        node.getAttribute('rx'), node.getAttribute('ry'))
            elif node.nodeName == 'text':
                if node.childNodes:
                    text = node.childNodes[0].nodeValue
                else:
                    text = ''
                s += '\tel = paper.text(%s, %s, \'%s\')' % (node.getAttribute('x'), node.getAttribute('y'), text)
            elif node.nodeName == 'image':
                width, width_unit = number_units_re.match(node.getAttribute('width')).group(1, 2)
                height, height_unit = number_units_re.match(node.getAttribute('height')).group(1, 2)
                s += '\tel = paper.image(\'%s\', %s, %s, %s, %s)' % (node.getAttribute('xlink:href'), node.getAttribute('x'), node.getAttribute('y'), self._raphael_unit_mapping_expression(width, width_unit),self._raphael_unit_mapping_expression(height, height_unit))
            elif node.nodeName == 'polygon' or node.nodeName == 'polyline':
                pathstring = 'M';
                coords = number_units_re.findall(node.getAttribute('points'))
                for i in range(len(coords)):
                    if i > 0:
                        if i % 2 == 0:
                            pathstring += 'L'
                        else:
                            pathstring += ','
                    pathstring += coords[i][0]
                if node.nodeName == 'polygon':
                    pathstring += 'Z'
                s += '\tel = paper.path(\'%s\')' % pathstring
            attrs = []
            for i in range(node.attributes.length):
                attr = node.attributes.item(i)
                if attr.name not in required_attrs.get(node.nodeName, set()):
                    if attr.name == 'stroke-dasharray':
                        #XXX hack
                        val = '\'\\-\''
                    elif attr.name == 'stroke-width':
                        val = attr.value+'*this.imageScale'
                    elif attr.name == 'transform':
                        transform += self._raphael_transform_str(attr.value)
                        continue
                    else:
                        val = '\'%s\'' % attr.value
                    attrs.append('\'%s\': %s' % (attr.name, val))
            if transform:
                attrs.append('\'%s\': \'%s\'' % ('transform', transform))
            if s:
                if attrs:
                    s += '.attr({%s})' % (','.join(attrs))
                s += ';\n'
                if node_id is not None and node_id in self.node_info:
                    s += '\tthis.addNodeEvent(el, node_info[\'%s\']);\n' % node_id.replace('\\', '\\\\').replace('--', '\\-\\-')

        for i in range(node.childNodes.length):
            s += self._write_raphael_node(node.childNodes[i], node_id, transform)
        return s

    def to_raphael(self):
        svg = self.G.draw(format=execv_encode('svg'), prog=execv_encode('dot'))
        dom = xml.dom.minidom.parseString(svg)

        s = 'AuthGraph.prototype.draw = function () {\n'
        s += '\tvar el, paperScale;\n'
        s += '\tvar node_info = %s;\n' % json.dumps(self.node_info)
        s += self._write_raphael_node(dom.documentElement, None, 's\'+this.imageScale+\',\'+this.imageScale+\',0,0')
        s += '\tpaper.setViewBox(0, 0, imageWidth, imageHeight);\n'
        s += '}\n'
        return codecs.encode(s, 'utf-8')

    def draw(self, format, path=None):
        if format == 'js':
            img = self.to_raphael()
            if path is None:
                return img
            else:
                io.open(path, 'w', encoding='utf-8').write(img)
        else:
            if path is None:
                return self.G.draw(format=execv_encode(format), prog=execv_encode('dot'))
            else:
                return self.G.draw(path=execv_encode(path), format=execv_encode(format), prog=execv_encode('dot'))

    def id_for_dnskey(self, name, dnskey):
        try:
            return self.dnskey_ids[(name,dnskey)]
        except KeyError:
            self.dnskey_ids[(name,dnskey)] = self.next_dnskey_id
            self.next_dnskey_id += 1
            return self.dnskey_ids[(name,dnskey)]

    def id_for_ds(self, name, ds):
        try:
            return self.ds_ids[(name,ds)]
        except KeyError:
            self.ds_ids[(name,ds)] = self.next_ds_id
            self.next_ds_id += 1
            return self.ds_ids[(name,ds)]

    def id_for_multiple_ds(self, name, ds):
        id_list = []
        for d in ds:
            id_list.append(self.id_for_ds(name, d))
        id_list.sort()
        return '_'.join(map(str, id_list))

    def id_for_nsec(self, name, rdtype, cls, nsec_set_info):
        try:
            nsec_set_info_list = self.nsec_ids[(name,rdtype,cls)]
        except KeyError:
            self.nsec_ids[(name,rdtype,cls)] = []
            nsec_set_info_list = self.nsec_ids[(name,rdtype,cls)]

        for nsec_set_info1, id in nsec_set_info_list:
            if nsec_set_info == nsec_set_info1:
                return id

        id = self.next_nsec_id
        self.nsec_ids[(name,rdtype,cls)].append((nsec_set_info, id))
        self.next_nsec_id += 1
        return id

    def dnskey_node_str(self, id, name, algorithm, key_tag):
        return 'DNSKEY-%s|%s|%d|%d' % (id, fmt.humanize_name(name), algorithm, key_tag)

    def has_dnskey(self, id, name, algorithm, key_tag):
        return self.G.has_node(self.dnskey_node_str(id, name, algorithm, key_tag))

    def get_dnskey(self, id, name, algorithm, key_tag):
        return self.G.get_node(self.dnskey_node_str(id, name, algorithm, key_tag))

    def add_dnskey(self, name_obj, dnskey):
        zone_obj = name_obj.zone
        node_str = self.dnskey_node_str(self.id_for_dnskey(name_obj.name, dnskey.rdata), name_obj.name, dnskey.rdata.algorithm, dnskey.key_tag)

        if not self.G.has_node(node_str):
            rrset_info_with_errors = [x for x in dnskey.rrset_info if name_obj.rrset_errors[x]]
            rrset_info_with_warnings = [x for x in dnskey.rrset_info if name_obj.rrset_warnings[x]]

            img_str = ''
            if dnskey.errors or rrset_info_with_errors:
                img_str = '<IMG SCALE="TRUE" SRC="%s"/>' % ERROR_ICON
            elif dnskey.warnings or rrset_info_with_warnings:
                img_str = '<IMG SCALE="TRUE" SRC="%s"/>' % WARNING_ICON

            if img_str:
                label_str = '<<TABLE BORDER="0" CELLPADDING="0"><TR><TD></TD><TD VALIGN="bottom"><FONT POINT-SIZE="%d" FACE="%s">DNSKEY</FONT></TD><TD VALIGN="bottom">%s</TD></TR><TR><TD COLSPAN="3" VALIGN="top"><FONT POINT-SIZE="%d">alg=%d, id=%d<BR/>%d bits</FONT></TD></TR></TABLE>>' % \
                        (12, 'Helvetica', img_str, 10, dnskey.rdata.algorithm, dnskey.key_tag, dnskey.key_len)
            else:
                label_str = '<<FONT POINT-SIZE="%d" FACE="%s">DNSKEY</FONT><BR/><FONT POINT-SIZE="%d">alg=%d, id=%d<BR/>%d bits</FONT>>' % \
                        (12, 'Helvetica', 10, dnskey.rdata.algorithm, dnskey.key_tag, dnskey.key_len)

            attr = {'style': 'filled', 'fillcolor': '#ffffff' }
            if dnskey.rdata.flags & fmt.DNSKEY_FLAGS['SEP']:
                attr['fillcolor'] = 'lightgray'
            if dnskey.rdata.flags & fmt.DNSKEY_FLAGS['revoke']:
                attr['penwidth'] = '4.0'

            S, zone_node_str, zone_bottom_name, zone_top_name = self.get_zone(zone_obj.name)
            S.add_node(node_str, id=node_str, shape='ellipse', label=label_str, **attr)
            self.node_subgraph_name[node_str] = zone_top_name

            consolidate_clients = name_obj.single_client()
            dnskey_serialized = dnskey.serialize(consolidate_clients=consolidate_clients, html_format=True, map_ip_to_ns_name=name_obj.zone.get_ns_name_for_ip)

            all_warnings = []
            if rrset_info_with_warnings:
                for rrset_info in rrset_info_with_warnings:
                    for warning in name_obj.rrset_warnings[rrset_info]:
                        servers_clients = warning.servers_clients
                        warning = Errors.DomainNameAnalysisError.insert_into_list(warning.copy(), all_warnings, None, None, None)
                        warning.servers_clients.update(servers_clients)
                if 'warnings' not in dnskey_serialized:
                    dnskey_serialized['warnings'] = []
                dnskey_serialized['warnings'] += [w.serialize(consolidate_clients=consolidate_clients, html_format=True) for w in all_warnings]

            all_errors = []
            if rrset_info_with_errors:
                for rrset_info in rrset_info_with_errors:
                    for error in name_obj.rrset_errors[rrset_info]:
                        servers_clients = error.servers_clients
                        error = Errors.DomainNameAnalysisError.insert_into_list(error.copy(), all_errors, None, None, None)
                        error.servers_clients.update(servers_clients)
                if 'errors' not in dnskey_serialized:
                    dnskey_serialized['errors'] = []
                dnskey_serialized['errors'] += [e.serialize(consolidate_clients=consolidate_clients, html_format=True) for e in all_errors]

            self.node_info[node_str] = [dnskey_serialized]

        if node_str not in self.node_mapping:
            self.node_mapping[node_str] = set()
        self.node_mapping[node_str].add(dnskey)
        self.node_reverse_mapping[dnskey] = node_str

        return self.G.get_node(node_str)

    def add_dnskey_non_existent(self, name, zone, algorithm, key_tag):
        node_str = self.dnskey_node_str(0, name, algorithm, key_tag)

        if not self.G.has_node(node_str):
            label_str = '<<FONT POINT-SIZE="%d" FACE="%s">DNSKEY</FONT><BR/><FONT POINT-SIZE="%d">alg=%d, id=%d</FONT>>' % \
                    (12, 'Helvetica', 10, algorithm, key_tag)

            attr = {'style': 'filled,dashed', 'color': COLORS['insecure_non_existent'], 'fillcolor': '#ffffff' }

            S, zone_node_str, zone_bottom_name, zone_top_name = self.get_zone(zone)
            S.add_node(node_str, id=node_str, shape='ellipse', label=label_str, **attr)
            self.node_subgraph_name[node_str] = zone_top_name

            dnskey_meta = DNSKEYNonExistent(name, algorithm, key_tag)

            self.node_info[node_str] = [dnskey_meta.serialize()]
            self.node_mapping[node_str] = set()

        return self.G.get_node(node_str)

    def ds_node_str(self, id, name, ds, rdtype):
        digest_types = [d.digest_type for d in ds]
        digest_types.sort()
        digest_str = '_'.join(map(str, digest_types))
        return '%s-%s|%s|%d|%d|%s' % (dns.rdatatype.to_text(rdtype), id, fmt.humanize_name(name), ds[0].algorithm, ds[0].key_tag, digest_str)

    def has_ds(self, id, name, ds, rdtype):
        return self.G.has_node(self.ds_node_str(id, name, ds, rdtype))

    def get_ds(self, id, name, ds, rdtype):
        return self.G.get_node(self.ds_node_str(id, name, ds, rdtype))

    def add_ds(self, name, ds_statuses, zone_obj, parent_obj):
        ds_info = ds_statuses[0].ds_meta
        ds = [d.ds for d in ds_statuses]
        rdtype = ds_info.rrset.rdtype
        node_str = self.ds_node_str(self.id_for_multiple_ds(name, ds), name, ds, rdtype)

        if not self.G.has_node(node_str):
            digest_types = [d.digest_type for d in ds]
            digest_types.sort()
            digest_str = ','.join(map(str, digest_types))
            if len(digest_types) != 1:
                plural = 's'
            else:
                plural = ''

            img_str = ''
            if [x for x in ds_statuses if [y for y in x.errors if isinstance(y, Errors.DSError)]] or zone_obj.rrset_errors[ds_info]:
                img_str = '<IMG SCALE="TRUE" SRC="%s"/>' % ERROR_ICON
            elif [x for x in ds_statuses if [y for y in x.warnings if isinstance(y, Errors.DSError)]] or zone_obj.rrset_warnings[ds_info]:
                img_str = '<IMG SCALE="TRUE" SRC="%s"/>' % WARNING_ICON

            attr = {'style': 'filled', 'fillcolor': '#ffffff' }
            if img_str:
                label_str = '<<TABLE BORDER="0" CELLPADDING="0"><TR><TD></TD><TD VALIGN="bottom"><FONT POINT-SIZE="%d" FACE="%s">%s</FONT></TD><TD VALIGN="bottom">%s</TD></TR><TR><TD COLSPAN="3" VALIGN="top"><FONT POINT-SIZE="%d">digest alg%s=%s</FONT></TD></TR></TABLE>>' % \
                        (12, 'Helvetica', dns.rdatatype.to_text(rdtype), img_str, 10, plural, digest_str)
            else:
                label_str = '<<FONT POINT-SIZE="%d" FACE="%s">%s</FONT><BR/><FONT POINT-SIZE="%d">digest alg%s=%s</FONT>>' % \
                        (12, 'Helvetica', dns.rdatatype.to_text(rdtype), 10, plural, digest_str)

            S, parent_node_str, parent_bottom_name, parent_top_name = self.get_zone(parent_obj.name)
            S.add_node(node_str, id=node_str, shape='ellipse', label=label_str, **attr)
            self.node_subgraph_name[node_str] = parent_top_name

            consolidate_clients = zone_obj.single_client()
            ds_serialized = [d.serialize(consolidate_clients=consolidate_clients, html_format=True, map_ip_to_ns_name=zone_obj.get_ns_name_for_ip) for d in ds_statuses]

            digest_algs = []
            digests = []
            for d in ds_serialized:
                digest_algs.append(d['digest_type'])
                digests.append(d['digest'])
            digest_algs.sort()
            digests.sort()
            consolidated_ds_serialized = ds_serialized[0]
            consolidated_ds_serialized['digest_type'] = digest_algs
            consolidated_ds_serialized['digest'] = digests

            if zone_obj.rrset_warnings[ds_info]:
                if 'warnings' not in consolidated_ds_serialized:
                    consolidated_ds_serialized['warnings'] = []
                consolidated_ds_serialized['warnings'] += [w.serialize(consolidate_clients=consolidate_clients, html_format=True) for w in zone_obj.rrset_warnings[ds_info]]

            if zone_obj.rrset_errors[ds_info]:
                if 'errors' not in consolidated_ds_serialized:
                    consolidated_ds_serialized['errors'] = []
                consolidated_ds_serialized['errors'] += [e.serialize(consolidate_clients=consolidate_clients, html_format=True) for e in zone_obj.rrset_errors[ds_info]]

            self.node_info[node_str] = [consolidated_ds_serialized]

            T, zone_node_str, zone_bottom_name, zone_top_name = self.get_zone(zone_obj.name)

            self.add_ds_map(name, node_str, ds_statuses, zone_obj, parent_obj)

        if node_str not in self.node_mapping:
            self.node_mapping[node_str] = set()
        self.node_mapping[node_str].add(ds_info)
        self.node_reverse_mapping[ds_info] = node_str

        return self.G.get_node(node_str)

    def add_ds_map(self, name, ds_node, ds_statuses, zone_obj, parent_obj):
        rdtype = ds_statuses[0].ds_meta.rrset.rdtype
        ds_status = ds_statuses[0]

        if ds_status.validation_status == Status.DS_STATUS_VALID:
            line_color = COLORS['secure']
            line_style = 'solid'
        elif ds_status.validation_status in (Status.DS_STATUS_INDETERMINATE_NO_DNSKEY, Status.DS_STATUS_INDETERMINATE_MATCH_PRE_REVOKE, Status.DS_STATUS_ALGORITHM_IGNORED):
            line_color = COLORS['insecure_non_existent']
            line_style = 'dashed'
        elif ds_status.validation_status == Status.DS_STATUS_INDETERMINATE_UNKNOWN_ALGORITHM:
            line_color = COLORS['indeterminate']
            line_style = 'solid'
        elif ds_status.validation_status == Status.DS_STATUS_INVALID_DIGEST:
            line_color = COLORS['invalid']
            line_style = 'solid'
        elif ds_status.validation_status == Status.DS_STATUS_INVALID:
            line_color = COLORS['invalid']
            line_style = 'dashed'

        if ds_status.dnskey is None:
            dnskey_node = self.add_dnskey_non_existent(zone_obj.name, zone_obj.name, ds_status.ds.algorithm, ds_status.ds.key_tag)
        else:
            dnskey_node = self.get_dnskey(self.id_for_dnskey(zone_obj.name, ds_status.dnskey.rdata), zone_obj.name, ds_status.dnskey.rdata.algorithm, ds_status.dnskey.key_tag)

        edge_id = 'digest-%s|%s|%s|%s' % (dnskey_node, ds_node, line_color.lstrip('#'), line_style)
        self.G.add_edge(dnskey_node, ds_node, id=edge_id, color=line_color, style=line_style, dir='back')

        self.node_info[edge_id] = [self.node_info[ds_node][0].copy()]
        self.node_info[edge_id][0]['description'] = 'Digest for %s' % (self.node_info[edge_id][0]['description'])

        self.node_mapping[edge_id] = set(ds_statuses)
        for d in ds_statuses:
            self.node_reverse_mapping[d] = edge_id

    def zone_node_str(self, name):
        return 'cluster_%s' % fmt.humanize_name(name)

    def has_zone(self, name):
        return self.G.get_subgraph(self.zone_node_str(name)) is not None

    def get_zone(self, name):
        node_str = self.zone_node_str(name)
        top_name = node_str + '_top'
        bottom_name = node_str + '_bottom'

        S = self.G.get_subgraph(node_str)

        return S, node_str, bottom_name, top_name

    def add_zone(self, zone_obj):
        node_str = self.zone_node_str(zone_obj.name)
        top_name = node_str + '_top'
        bottom_name = node_str + '_bottom'

        S = self.G.get_subgraph(node_str)
        if S is None:
            img_str = ''
            if zone_obj.zone_errors:
                img_str = '<IMG SCALE="TRUE" SRC="%s"/>' % ERROR_ICON
            elif zone_obj.zone_warnings:
                img_str = '<IMG SCALE="TRUE" SRC="%s"/>' % WARNING_ICON

            if zone_obj.analysis_end is not None:
                label_str = '<<TABLE BORDER="0"><TR><TD ALIGN="LEFT"><FONT POINT-SIZE="%d">%s</FONT></TD><TD ALIGN="RIGHT">%s</TD></TR><TR><TD ALIGN="LEFT" COLSPAN="2"><FONT POINT-SIZE="%d">(%s)</FONT></TD></TR></TABLE>>' % \
                        (12, zone_obj, img_str, 10, fmt.datetime_to_str(zone_obj.analysis_end))
            else:
                label_str = '<<TABLE BORDER="0"><TR><TD ALIGN="LEFT"><FONT POINT-SIZE="%d">%s</FONT></TD><TD ALIGN="RIGHT">%s</TD></TR></TABLE>>' % \
                        (12, zone_obj, img_str)
            S = self.G.add_subgraph(name=node_str, label=label_str, labeljust='l', penwidth='0.5', id=top_name)
            S.add_node(top_name, shape='point', style='invis')
            S.add_node(bottom_name, shape='point', style='invis')
            self.node_subgraph_name[top_name] = top_name
            self.node_subgraph_name[bottom_name] = top_name
            self.node_reverse_mapping[zone_obj] = top_name

            consolidate_clients = zone_obj.single_client()
            zone_serialized = OrderedDict()
            zone_serialized['description'] = '%s zone' % (zone_obj)
            if zone_obj.zone_errors:
                zone_serialized['errors'] = [e.serialize(consolidate_clients=consolidate_clients, html_format=True) for e in zone_obj.zone_errors]
            if zone_obj.zone_warnings:
                zone_serialized['warnings'] = [e.serialize(consolidate_clients=consolidate_clients, html_format=True) for e in zone_obj.zone_warnings]

            self.node_info[top_name] = [zone_serialized]

        return S, node_str, bottom_name, top_name

    def add_rrsig(self, rrsig_status, name_obj, signer_obj, signed_node, port=None):
        if signer_obj is not None:
            zone_name = signer_obj.zone.name
        else:
            zone_name = name_obj.zone.name

        if rrsig_status.dnskey is None:
            dnskey_node = self.add_dnskey_non_existent(rrsig_status.rrsig.signer, zone_name, rrsig_status.rrsig.algorithm, rrsig_status.rrsig.key_tag)
        else:
            dnskey_node = self.get_dnskey(self.id_for_dnskey(rrsig_status.rrsig.signer, rrsig_status.dnskey.rdata), rrsig_status.rrsig.signer, rrsig_status.dnskey.rdata.algorithm, rrsig_status.dnskey.key_tag)

        #XXX consider not adding icons if errors are apparent from color of line
        edge_label = ''
        if rrsig_status.errors:
            edge_label = '<<TABLE BORDER="0"><TR><TD><IMG SCALE="TRUE" SRC="%s"/></TD></TR></TABLE>>' % ERROR_ICON
        elif rrsig_status.warnings:
            edge_label = '<<TABLE BORDER="0"><TR><TD><IMG SCALE="TRUE" SRC="%s"/></TD></TR></TABLE>>' % WARNING_ICON

        if rrsig_status.validation_status == Status.RRSIG_STATUS_VALID:
            line_color = COLORS['secure']
            line_style = 'solid'
        elif rrsig_status.validation_status in (Status.RRSIG_STATUS_INDETERMINATE_NO_DNSKEY, Status.RRSIG_STATUS_INDETERMINATE_MATCH_PRE_REVOKE, Status.RRSIG_STATUS_ALGORITHM_IGNORED):
            line_color = COLORS['insecure_non_existent']
            line_style = 'dashed'
        elif rrsig_status.validation_status == Status.RRSIG_STATUS_INDETERMINATE_UNKNOWN_ALGORITHM:
            line_color = COLORS['indeterminate']
            line_style = 'solid'
        elif rrsig_status.validation_status == Status.RRSIG_STATUS_EXPIRED:
            line_color = COLORS['expired']
            line_style = 'solid'
        elif rrsig_status.validation_status == Status.RRSIG_STATUS_PREMATURE:
            line_color = COLORS['expired']
            line_style = 'solid'
        elif rrsig_status.validation_status == Status.RRSIG_STATUS_INVALID_SIG:
            line_color = COLORS['invalid']
            line_style = 'solid'
        elif rrsig_status.validation_status == Status.RRSIG_STATUS_INVALID:
            line_color = COLORS['invalid']
            line_style = 'dashed'

        attrs = {}
        edge_id = 'RRSIG-%s|%s|%s|%s' % (signed_node.replace('*', '_'), dnskey_node, line_color.lstrip('#'), line_style)
        edge_key = '%s-%s' % (line_color, line_style)
        if port is not None:
            attrs['tailport'] = port
            edge_id += '|%s' % port.replace('*', '_')
            edge_key += '|%s' % port

        # if this DNSKEY is signing data in a zone above itself (e.g., DS
        # records), then remove constraint from the edge
        signed_node_zone = self.node_subgraph_name[signed_node][8:-4]
        dnskey_node_zone = self.node_subgraph_name[dnskey_node][8:-4]
        if not signed_node_zone.endswith(dnskey_node_zone):
            attrs['constraint'] = 'false'

        if (signed_node, dnskey_node, edge_key) not in self._edge_keys:
            self._edge_keys.add((signed_node, dnskey_node, edge_key))
            self.G.add_edge(signed_node, dnskey_node, label=edge_label, id=edge_id, color=line_color, style=line_style, dir='back', **attrs)

        consolidate_clients = name_obj.single_client()
        rrsig_serialized = rrsig_status.serialize(consolidate_clients=consolidate_clients, html_format=True, map_ip_to_ns_name=name_obj.zone.get_ns_name_for_ip)

        if edge_id not in self.node_info:
            self.node_info[edge_id] = []
            self.node_mapping[edge_id] = set()
        self.node_info[edge_id].append(rrsig_serialized)
        self.node_mapping[edge_id].add(rrsig_status)
        self.node_reverse_mapping[rrsig_status] = edge_id

    def id_for_rrset(self, rrset_info):
        name, rdtype = rrset_info.rrset.name, rrset_info.rrset.rdtype
        try:
            rrset_info_list = self.rrset_ids[(name,rdtype)]
        except KeyError:
            self.rrset_ids[(name,rdtype)] = []
            rrset_info_list = self.rrset_ids[(name,rdtype)]

        for rrset_info1, id in rrset_info_list:
            if rrset_info == rrset_info1:
                return id

        id = self.next_rrset_id
        self.rrset_ids[(name,rdtype)].append((rrset_info, id))
        self.next_rrset_id += 1
        return id

    def rrset_node_str(self, name, rdtype, id):
        return 'RRset-%d|%s|%s' % (id, fmt.humanize_name(name), dns.rdatatype.to_text(rdtype))

    def has_rrset(self, name, rdtype, id):
        return self.G.has_node(self.rrset_node_str(name, rdtype, id))

    def get_rrset(self, name, rdtype, id):
        return self.G.get_node(self.rrset_node_str(name, rdtype, id))

    def add_rrset(self, rrset_info, wildcard_name, name_obj, zone_obj):
        name = wildcard_name or rrset_info.rrset.name
        node_str = self.rrset_node_str(name, rrset_info.rrset.rdtype, self.id_for_rrset(rrset_info))
        node_id = node_str.replace('*', '_')

        if not self.G.has_node(node_str):
            img_str = ''
            if name_obj.rrset_errors[rrset_info]:
                img_str = '<IMG SCALE="TRUE" SRC="%s"/>' % ERROR_ICON
            elif name_obj.rrset_warnings[rrset_info]:
                img_str = '<IMG SCALE="TRUE" SRC="%s"/>' % WARNING_ICON

            if img_str:
                node_label = '<<TABLE BORDER="0" CELLPADDING="0"><TR><TD><FONT POINT-SIZE="%d" FACE="%s">%s/%s</FONT></TD></TR><TR><TD>%s</TD></TR></TABLE>>' % \
                        (12, 'Helvetica', fmt.humanize_name(name, True), dns.rdatatype.to_text(rrset_info.rrset.rdtype), img_str)
            else:
                node_label = '<<FONT POINT-SIZE="%d" FACE="%s">%s/%s</FONT>>' % \
                        (12, 'Helvetica', fmt.humanize_name(name, True), dns.rdatatype.to_text(rrset_info.rrset.rdtype))

            attr = {}
            attr['shape'] = 'rectangle'
            attr['style'] = 'rounded,filled'
            attr['fillcolor'] = '#ffffff'

            S, zone_node_str, zone_bottom_name, zone_top_name = self.get_zone(zone_obj.name)
            S.add_node(node_str, id=node_id, label=node_label, fontsize='10', **attr)
            self.node_subgraph_name[node_str] = zone_top_name

            consolidate_clients = name_obj.single_client()
            rrset_serialized = rrset_info.serialize(consolidate_clients=consolidate_clients, html_format=True, map_ip_to_ns_name=name_obj.zone.get_ns_name_for_ip)

            if name_obj.rrset_warnings[rrset_info]:
                if 'warnings' not in rrset_serialized:
                    rrset_serialized['warnings'] = []
                rrset_serialized['warnings'] += [w.serialize(consolidate_clients=consolidate_clients, html_format=True) for w in name_obj.rrset_warnings[rrset_info]]

            if name_obj.rrset_errors[rrset_info]:
                if 'errors' not in rrset_serialized:
                    rrset_serialized['errors'] = []
                rrset_serialized['errors'] += [w.serialize(consolidate_clients=consolidate_clients, html_format=True) for w in name_obj.rrset_errors[rrset_info]]

            self.node_info[node_id] = [rrset_serialized]
            self.G.add_edge(zone_bottom_name, node_str, style='invis')

        if node_str not in self.node_mapping:
            self.node_mapping[node_str] = set()
        self.node_mapping[node_str].add(rrset_info)
        self.node_reverse_mapping[rrset_info] = node_str

        return self.G.get_node(node_str)

    def add_rrset_non_existent(self, name_obj, zone_obj, neg_response_info, nxdomain, wildcard):
        if nxdomain:
            node_str = self.rrset_node_str(neg_response_info.qname, neg_response_info.rdtype, 0)
        else:
            node_str = self.rrset_node_str(neg_response_info.qname, neg_response_info.rdtype, 1)
        node_id = node_str.replace('*', '_')

        if not self.G.has_node(node_str):
            if wildcard:
                warnings_list = errors_list = []
            else:
                if nxdomain:
                    warnings_list = name_obj.nxdomain_warnings[neg_response_info]
                    errors_list = name_obj.nxdomain_errors[neg_response_info]
                else:
                    warnings_list = name_obj.nodata_warnings[neg_response_info]
                    errors_list = name_obj.nodata_errors[neg_response_info]

            if nxdomain:
                rdtype_str = ''
            else:
                rdtype_str = '/%s' % dns.rdatatype.to_text(neg_response_info.rdtype)

            img_str = ''
            if errors_list:
                img_str = '<IMG SCALE="TRUE" SRC="%s"/>' % ERROR_ICON
            elif warnings_list:
                img_str = '<IMG SCALE="TRUE" SRC="%s"/>' % WARNING_ICON

            if img_str:
                node_label = '<<TABLE BORDER="0" CELLPADDING="0"><TR><TD><FONT POINT-SIZE="%d" FACE="%s">%s%s</FONT></TD></TR><TR><TD>%s</TD></TR></TABLE>>' % \
                        (12, 'Helvetica', fmt.humanize_name(neg_response_info.qname, True), rdtype_str, img_str)
            else:
                node_label = '<<FONT POINT-SIZE="%d" FACE="%s">%s%s</FONT>>' % \
                        (12, 'Helvetica', fmt.humanize_name(neg_response_info.qname, True), rdtype_str)

            attr = {}
            attr['shape'] = 'rectangle'
            attr['style'] = 'rounded,filled,dashed'
            if nxdomain:
                attr['style'] += ',diagonals'
            attr['fillcolor'] = '#ffffff'

            S, zone_node_str, zone_bottom_name, zone_top_name = self.get_zone(zone_obj.name)
            S.add_node(node_str, id=node_id, label=node_label, fontsize='10', **attr)
            self.node_subgraph_name[node_str] = zone_top_name

            rrset_info = RRsetNonExistent(neg_response_info.qname, neg_response_info.rdtype, nxdomain, neg_response_info.servers_clients)

            consolidate_clients = name_obj.single_client()
            rrset_serialized = rrset_info.serialize(consolidate_clients=consolidate_clients, html_format=True, map_ip_to_ns_name=name_obj.zone.get_ns_name_for_ip)

            if warnings_list:
                if 'warnings' not in rrset_serialized:
                    rrset_serialized['warnings'] = []
                rrset_serialized['warnings'] += [w.serialize(consolidate_clients=consolidate_clients, html_format=True) for w in warnings_list]

            if errors_list:
                if 'errors' not in rrset_serialized:
                    rrset_serialized['errors'] = []
                rrset_serialized['errors'] += [w.serialize(consolidate_clients=consolidate_clients, html_format=True) for w in errors_list]

            self.node_info[node_id] = [rrset_serialized]

            self.G.add_edge(zone_bottom_name, node_str, style='invis')

        if node_str not in self.node_mapping:
            self.node_mapping[node_str] = set()
        self.node_mapping[node_str].add(neg_response_info)
        self.node_reverse_mapping[neg_response_info] = node_str

        return self.G.get_node(node_str)

    def _add_errors(self, name_obj, zone_obj, name, rdtype, errors_list, code, icon, category, status, description):
        if not errors_list:
            return None

        node_str = self.rrset_node_str(name, rdtype, code)

        img_str = '<IMG SCALE="TRUE" SRC="%s"/>' % icon

        node_label = '<<TABLE BORDER="0" CELLPADDING="0"><TR><TD>%s</TD></TR><TR><TD><FONT POINT-SIZE="%d" FACE="%s" COLOR="%s"><I>%s/%s</I></FONT></TD></TR></TABLE>>' % \
                (img_str, 10, 'Helvetica', '#b0b0b0', fmt.humanize_name(name, True), dns.rdatatype.to_text(rdtype), )

        attr = {}
        attr['shape'] = 'none'
        attr['margin'] = '0'

        node_id = node_str.replace('*', '_')
        S, zone_node_str, zone_bottom_name, zone_top_name = self.get_zone(zone_obj.name)
        S.add_node(node_str, id=node_id, label=node_label, fontsize='10', **attr)
        self.node_subgraph_name[node_str] = zone_top_name

        consolidate_clients = name_obj.single_client()

        errors_serialized = OrderedDict()

        errors_serialized['description'] = '%s %s/%s' % (description, fmt.humanize_name(name), dns.rdatatype.to_text(rdtype))
        errors_serialized[category] = [e.serialize(consolidate_clients=consolidate_clients, html_format=True) for e in errors_list]
        errors_serialized['status'] = status

        self.node_info[node_id] = [errors_serialized]
        self.G.add_edge(zone_bottom_name, node_str, style='invis')

        # no need to map errors
        self.node_mapping[node_str] = set()

        return self.G.get_node(node_str)

    def add_errors(self, name_obj, zone_obj, name, rdtype, errors_list):
        return self._add_errors(name_obj, zone_obj, name, rdtype, errors_list, 2, ERROR_ICON, 'errors', 'ERROR', 'Response errors for')

    def add_warnings(self, name_obj, zone_obj, name, rdtype, warnings_list):
        return self._add_errors(name_obj, zone_obj, name, rdtype, warnings_list, 3, WARNING_ICON, 'warnings', 'WARNING', 'Response warnings for')

    def add_dname(self, dname_status, name_obj, zone_obj):
        dname_rrset_info = dname_status.synthesized_cname.dname_info
        dname_node = self.add_rrset(dname_rrset_info, None, name_obj, zone_obj)

        if dname_status.validation_status == Status.DNAME_STATUS_VALID:
            line_color = COLORS['secure']
            line_style = 'solid'
        elif dname_status.validation_status == Status.DNAME_STATUS_INDETERMINATE:
            line_color = COLORS['indeterminate']
            line_style = 'solid'
        elif dname_status.validation_status == Status.DNAME_STATUS_INVALID:
            line_color = COLORS['invalid']
            line_style = 'solid'

        if dname_status.included_cname is None:
            cname_node = self.add_rrset_non_existent(name_obj, zone_obj, Response.NegativeResponseInfo(dname_status.synthesized_cname.rrset.name, dns.rdatatype.CNAME, False), False, False)
        else:
            cname_node = self.add_rrset(dname_status.included_cname, None, name_obj, zone_obj)

        edge_id = 'dname-%s|%s|%s|%s' % (cname_node, dname_node, line_color.lstrip('#'), line_style)
        edge_key = '%s-%s' % (line_color, line_style)
        if (cname_node, dname_node, edge_key) not in self._edge_keys:
            self._edge_keys.add((cname_node, dname_node, edge_key))

            edge_label = ''
            if dname_status.errors:
                edge_label = '<<TABLE BORDER="0"><TR><TD><IMG SCALE="TRUE" SRC="%s"/></TD></TR></TABLE>>' % ERROR_ICON
            elif dname_status.warnings:
                edge_label = '<<TABLE BORDER="0"><TR><TD><IMG SCALE="TRUE" SRC="%s"/></TD></TR></TABLE>>' % WARNING_ICON

            self.G.add_edge(cname_node, dname_node, label=edge_label, id=edge_id, color=line_color, style=line_style, dir='back')
            self.node_info[edge_id] = [dname_status.serialize(html_format=True, map_ip_to_ns_name=name_obj.zone.get_ns_name_for_ip)]

        if edge_id not in self.node_mapping:
            self.node_mapping[edge_id] = set()
        self.node_mapping[edge_id].add(dname_status)
        self.node_reverse_mapping[dname_status] = edge_id

        self.add_rrsigs(name_obj, zone_obj, dname_rrset_info, dname_node)

        return cname_node

    def nsec_node_str(self, nsec_rdtype, id, name, rdtype):
        return '%s-%d|%s|%s' % (dns.rdatatype.to_text(nsec_rdtype), id, fmt.humanize_name(name), dns.rdatatype.to_text(rdtype))

    def has_nsec(self, nsec_rdtype, id, name, rdtype):
        return self.G.has_node(self.nsec_node_str(nsec_rdtype, id, name, rdtype))

    def get_nsec(self, nsec_rdtype, id, name, rdtype):
        return self.G.get_node(self.nsec_node_str(nsec_rdtype, id, name, rdtype))

    def add_nsec(self, nsec_status, name, rdtype, name_obj, zone_obj, covered_node):
        if nsec_status.nsec_set_info.use_nsec3:
            nsec_rdtype = dns.rdatatype.NSEC3
        else:
            nsec_rdtype = dns.rdatatype.NSEC
        node_str = self.nsec_node_str(nsec_rdtype, self.id_for_nsec(name, rdtype, nsec_status.__class__, nsec_status.nsec_set_info), name, rdtype)
        node_id = node_str.replace('*', '_')
        edge_id = '%sC-%s|%s' % (dns.rdatatype.to_text(nsec_rdtype), covered_node.replace('*', '_'), node_str)

        if not self.G.has_node(node_str):
            rrset_info_with_errors = [x for x in nsec_status.nsec_set_info.rrsets.values() if name_obj.rrset_errors[x]]
            rrset_info_with_warnings = [x for x in nsec_status.nsec_set_info.rrsets.values() if name_obj.rrset_warnings[x]]

            img_str = ''
            if rrset_info_with_errors:
                img_str = '<IMG SCALE="TRUE" SRC="%s"/>' % ERROR_ICON
            elif rrset_info_with_warnings:
                img_str = '<IMG SCALE="TRUE" SRC="%s"/>' % WARNING_ICON

            # if it is NXDOMAIN, not type DS
            if isinstance(nsec_status, (Status.NSEC3StatusNXDOMAIN, Status.NSEC3StatusNODATA)) and nsec_status.opt_out:
                bgcolor = 'lightgray'
            else:
                bgcolor = '#ffffff'

            #XXX it looks better when cellspacing is 0, but we can't do that
            # when there is an icon in use because of the way the graphviz
            # library draws it.
            if img_str:
                cellspacing = 0
            else:
                cellspacing = -2

            self.nsec_rr_status[node_str] = {}
            label_str = '<<TABLE BORDER="0" CELLSPACING="%d" CELLPADDING="0" BGCOLOR="%s"><TR>' % (cellspacing, bgcolor)
            for nsec_name in nsec_status.nsec_set_info.rrsets:
                nsec_name = lb2s(nsec_name.canonicalize().to_text()).replace(r'"', r'\"')
                self.nsec_rr_status[node_str][nsec_name] = ''
                label_str += '<TD PORT="%s" BORDER="2"><FONT POINT-SIZE="%d"> </FONT></TD>' % (nsec_name, 6)
            label_str += '</TR><TR><TD COLSPAN="%d" BORDER="2" CELLPADDING="3">' % len(nsec_status.nsec_set_info.rrsets)
            if img_str:
                label_str += '<TABLE BORDER="0"><TR><TD><FONT POINT-SIZE="%d" FACE="%s">%s</FONT></TD><TD>%s</TD></TR></TABLE>' % \
                        (12, 'Helvetica', dns.rdatatype.to_text(nsec_rdtype), img_str)
            else:
                label_str += '<FONT POINT-SIZE="%d" FACE="%s">%s</FONT>' % \
                        (12, 'Helvetica', dns.rdatatype.to_text(nsec_rdtype))
            label_str += '</TD></TR></TABLE>>'

            S, zone_node_str, zone_bottom_name, zone_top_name = self.get_zone(zone_obj.name)
            S.add_node(node_str, id=node_id, label=label_str, shape='none')
            self.node_subgraph_name[node_str] = zone_top_name

            consolidate_clients = name_obj.single_client()

            nsec_serialized = nsec_status.serialize(consolidate_clients=consolidate_clients, html_format=True, map_ip_to_ns_name=name_obj.zone.get_ns_name_for_ip)

            nsec_serialized_edge = nsec_serialized.copy()
            nsec_serialized_edge['description'] = 'Non-existence proof provided by %s' % (nsec_serialized['description'])

            all_warnings = []
            if rrset_info_with_warnings:
                for rrset_info in rrset_info_with_warnings:
                    for warning in name_obj.rrset_warnings[rrset_info]:
                        servers_clients = warning.servers_clients
                        warning = Errors.DomainNameAnalysisError.insert_into_list(warning.copy(), all_warnings, None, None, None)
                        warning.servers_clients.update(servers_clients)
                if 'warnings' not in nsec_serialized:
                    nsec_serialized['warnings'] = []
                nsec_serialized['warnings'] += [w.serialize(consolidate_clients=consolidate_clients, html_format=True) for w in all_warnings]

            all_errors = []
            if rrset_info_with_errors:
                for rrset_info in rrset_info_with_errors:
                    for error in name_obj.rrset_errors[rrset_info]:
                        servers_clients = error.servers_clients
                        error = Errors.DomainNameAnalysisError.insert_into_list(error.copy(), all_errors, None, None, None)
                        error.servers_clients.update(servers_clients)
                if 'errors' not in nsec_serialized:
                    nsec_serialized['errors'] = []
                nsec_serialized['errors'] += [e.serialize(consolidate_clients=consolidate_clients, html_format=True) for e in all_errors]

            self.node_info[node_id] = [nsec_serialized]

            nsec_node = self.G.get_node(node_str)

            if nsec_status.validation_status == Status.NSEC_STATUS_VALID:
                line_color = COLORS['secure']
                line_style = 'solid'
            elif nsec_status.validation_status == Status.NSEC_STATUS_INDETERMINATE:
                line_color = COLORS['indeterminate']
                line_style = 'solid'
            elif nsec_status.validation_status == Status.NSEC_STATUS_INVALID:
                line_color = COLORS['bogus']
                line_style = 'solid'

            edge_label = ''
            self.G.add_edge(covered_node, nsec_node, label=edge_label, id=edge_id, color=line_color, style=line_style, dir='back')

            self.node_info[edge_id] = [nsec_serialized_edge]

        else:
            nsec_node = self.G.get_node(node_str)

        if node_str not in self.node_mapping:
            self.node_mapping[node_str] = set()
        self.node_mapping[node_str].add(nsec_status.nsec_set_info)
        self.node_reverse_mapping[nsec_status.nsec_set_info] = node_str

        if edge_id not in self.node_mapping:
            self.node_mapping[edge_id] = set()
        self.node_mapping[edge_id].add(nsec_status)
        self.node_reverse_mapping[nsec_status] = edge_id

        return nsec_node

    def add_wildcard(self, name_obj, zone_obj, rrset_info, nsec_status, wildcard_name):
        wildcard_node = self.add_rrset(rrset_info, wildcard_name, name_obj, zone_obj)
        self.add_rrsigs(name_obj, zone_obj, rrset_info, wildcard_node)
        nxdomain_node = self.add_rrset_non_existent(name_obj, zone_obj, rrset_info.wildcard_info[wildcard_name], True, True)

        if nsec_status is not None:
            nsec_node = self.add_nsec(nsec_status, rrset_info.rrset.name, rrset_info.rrset.rdtype, name_obj, zone_obj, nxdomain_node)
            for nsec_name, rrset_info in nsec_status.nsec_set_info.rrsets.items():
                nsec_cell = lb2s(nsec_name.canonicalize().to_text())
                self.add_rrsigs(name_obj, zone_obj, rrset_info, nsec_node, port=nsec_cell)

        return wildcard_node

        #XXX consider adding this node (using, e.g., clustering)
        #rrset_node = self.add_rrset(rrset_info, None, zone_obj, zone_obj)
        #self.G.add_edge(rrset_node, nxdomain_node, color=COLORS['secure'], style='invis', dir='back')
        #self.G.add_edge(rrset_node, wildcard_node, color=COLORS['secure'], style='invis', dir='back')
        #return rrset_node

    def add_alias(self, alias, target):
        if not [x for x in self.G.out_edges(target) if x[1] == alias and x.attr['color'] == 'black']:
            alias_zone = self.node_subgraph_name[alias][8:-4]
            target_zone = self.node_subgraph_name[target][8:-4]
            if alias_zone.endswith(target_zone) and alias_zone != target_zone:
                self.G.add_edge(target, alias, color='black', dir='back', constraint='false')
            else:
                self.G.add_edge(target, alias, color='black', dir='back')

    def add_rrsigs(self, name_obj, zone_obj, rrset_info, signed_node, port=None):
        for rrsig in name_obj.rrsig_status[rrset_info]:
            signer_obj = name_obj.get_name(rrsig.signer)
            if rrsig.signer != zone_obj.name and signer_obj is not None:
                self.graph_zone_auth(signer_obj, False)
            for dnskey in name_obj.rrsig_status[rrset_info][rrsig]:
                rrsig_status = name_obj.rrsig_status[rrset_info][rrsig][dnskey]
                self.add_rrsig(rrsig_status, name_obj, signer_obj, signed_node, port=port)

    def graph_rrset_auth(self, name_obj, name, rdtype, trace=None):
        if (name, rdtype) not in self.processed_rrsets:
            self.processed_rrsets[(name, rdtype)] = []

        #XXX there are reasons for this (e.g., NXDOMAIN, after which no further
        # queries are made), but it would be good to have a sanity check, so
        # we don't simply produce an incomplete graph.  (In the case above, perhaps
        # point to the NXDOMAIN produced by another query.)
        if (name, rdtype) not in name_obj.queries:
            return []

        zone_obj = name_obj.zone
        if zone_obj is not None:
            self.graph_zone_auth(zone_obj, False)
        else:
            # in recursive analysis, if we don't contact any servers that are
            # valid and responsive, then we get a zone_obj that is None
            # (because we couldn't detect any NS records in the ancestry)
            zone_obj = name_obj
            self.add_zone(zone_obj)

        if name_obj.nxdomain_ancestor is not None:
            self.graph_rrset_auth(name_obj.nxdomain_ancestor, name_obj.nxdomain_ancestor.name, name_obj.nxdomain_ancestor.referral_rdtype)

        # if this is for DNSKEY or DS of a zone, then return, as we have
        # already take care of these types in graph_zone_auth()
        if name_obj.is_zone() and rdtype in (dns.rdatatype.DNSKEY, dns.rdatatype.DS):
            return []

        # trace is used just for CNAME chains
        if trace is None:
            trace = [name]

        cname_nodes = []
        # if this name is an alias, then graph its target, i.e., the canonical
        # name, unless this is a recursive analysis.
        if name_obj.analysis_type != ANALYSIS_TYPE_RECURSIVE:
            if name in name_obj.cname_targets:
                for target, cname_obj in name_obj.cname_targets[name].items():
                    if cname_obj is not None:
                        if target not in trace:
                            cname_nodes.extend(self.graph_rrset_auth(cname_obj, target, rdtype, trace + [target]))

        query = name_obj.queries[(name, rdtype)]
        node_to_cname_mapping = set()
        for rrset_info in query.answer_info:

            # only do qname, unless analysis type is recursive
            if not (rrset_info.rrset.name == name or name_obj.analysis_type == ANALYSIS_TYPE_RECURSIVE):
                continue

            my_name = rrset_info.rrset.name
            my_nodes = []
            if (my_name, rdtype) not in self.processed_rrsets:
                self.processed_rrsets[(my_name, rdtype)] = []

            my_name_obj = name_obj.get_name(my_name)
            my_zone_obj = my_name_obj.zone
            if my_zone_obj is not None:
                self.graph_zone_auth(my_zone_obj, False)
            else:
                my_zone_obj = my_name_obj
                self.add_zone(my_zone_obj)

            #XXX can we combine multiple DNAMEs into one?
            #XXX can we combine multiple NSEC(3) into a cluster?
            #XXX can we combine wildcard components into a cluster?
            if rrset_info in name_obj.dname_status:
                for dname_status in name_obj.dname_status[rrset_info]:
                    my_nodes.append(self.add_dname(dname_status, name_obj, my_zone_obj))
            elif rrset_info.wildcard_info:
                for wildcard_name in rrset_info.wildcard_info:
                    if name_obj.wildcard_status[rrset_info.wildcard_info[wildcard_name]]:
                        for nsec_status in name_obj.wildcard_status[rrset_info.wildcard_info[wildcard_name]]:
                            my_nodes.append(self.add_wildcard(name_obj, my_zone_obj, rrset_info, nsec_status, wildcard_name))
                    else:
                        my_nodes.append(self.add_wildcard(name_obj, my_zone_obj, rrset_info, None, wildcard_name))
            else:
                rrset_node = self.add_rrset(rrset_info, None, name_obj, my_zone_obj)
                self.add_rrsigs(name_obj, my_zone_obj, rrset_info, rrset_node)
                my_nodes.append(rrset_node)

            # if this is a CNAME record, create a node-to-target mapping
            if rrset_info.rrset.rdtype == dns.rdatatype.CNAME:
                for my_node in my_nodes:
                    node_to_cname_mapping.add((my_node, rrset_info.rrset[0].target))

            self.processed_rrsets[(my_name, rdtype)] += my_nodes

        for neg_response_info in query.nxdomain_info:
            # make sure this query was made to a server designated as
            # authoritative
            if not set([s for (s,c) in neg_response_info.servers_clients]).intersection(name_obj.zone.get_auth_or_designated_servers()):
                continue

            # only do qname, unless analysis type is recursive
            if not (neg_response_info.qname == name or name_obj.analysis_type == ANALYSIS_TYPE_RECURSIVE):
                continue

            if (neg_response_info.qname, neg_response_info.rdtype) not in self.processed_rrsets:
                self.processed_rrsets[(neg_response_info.qname, neg_response_info.rdtype)] = []

            my_name_obj = name_obj.get_name(neg_response_info.qname)
            my_zone_obj = my_name_obj.zone
            if my_zone_obj is not None:
                self.graph_zone_auth(my_zone_obj, False)
            else:
                my_zone_obj = my_name_obj
                self.add_zone(my_zone_obj)

            nxdomain_node = self.add_rrset_non_existent(name_obj, my_zone_obj, neg_response_info, True, False)
            self.processed_rrsets[(neg_response_info.qname, neg_response_info.rdtype)].append(nxdomain_node)
            for nsec_status in name_obj.nxdomain_status[neg_response_info]:
                nsec_node = self.add_nsec(nsec_status, name, rdtype, name_obj, my_zone_obj, nxdomain_node)
                for nsec_name, rrset_info in nsec_status.nsec_set_info.rrsets.items():
                    nsec_cell = lb2s(nsec_name.canonicalize().to_text())
                    self.add_rrsigs(name_obj, my_zone_obj, rrset_info, nsec_node, port=nsec_cell)

            for soa_rrset_info in neg_response_info.soa_rrset_info:
                # If no servers match the authoritative servers, then put this in the parent zone
                if not set([s for (s,c) in soa_rrset_info.servers_clients]).intersection(my_zone_obj.get_auth_or_designated_servers()) and my_zone_obj.parent is not None:
                    z_obj = my_zone_obj.parent
                else:
                    z_obj = my_zone_obj
                soa_rrset_node = self.add_rrset(soa_rrset_info, None, name_obj, z_obj)
                self.add_rrsigs(name_obj, my_zone_obj, soa_rrset_info, soa_rrset_node)

        for neg_response_info in query.nodata_info:
            # only do qname, unless analysis type is recursive
            if not (neg_response_info.qname == name or name_obj.analysis_type == ANALYSIS_TYPE_RECURSIVE):
                continue

            if (neg_response_info.qname, neg_response_info.rdtype) not in self.processed_rrsets:
                self.processed_rrsets[(neg_response_info.qname, neg_response_info.rdtype)] = []

            my_name_obj = name_obj.get_name(neg_response_info.qname)
            my_zone_obj = my_name_obj.zone
            if my_zone_obj is not None:
                self.graph_zone_auth(my_zone_obj, False)
            else:
                my_zone_obj = my_name_obj
                self.add_zone(my_zone_obj)

            nodata_node = self.add_rrset_non_existent(name_obj, my_zone_obj, neg_response_info, False, False)
            self.processed_rrsets[(neg_response_info.qname, neg_response_info.rdtype)].append(nodata_node)
            for nsec_status in name_obj.nodata_status[neg_response_info]:
                nsec_node = self.add_nsec(nsec_status, name, rdtype, name_obj, my_zone_obj, nodata_node)
                for nsec_name, rrset_info in nsec_status.nsec_set_info.rrsets.items():
                    nsec_cell = lb2s(nsec_name.canonicalize().to_text())
                    self.add_rrsigs(name_obj, my_zone_obj, rrset_info, nsec_node, port=nsec_cell)

            for soa_rrset_info in neg_response_info.soa_rrset_info:
                soa_rrset_node = self.add_rrset(soa_rrset_info, None, name_obj, my_zone_obj)
                self.add_rrsigs(name_obj, my_zone_obj, soa_rrset_info, soa_rrset_node)

        error_node = self.add_errors(name_obj, zone_obj, name, rdtype, name_obj.response_errors[query])
        if error_node is not None:
            if (name, rdtype) not in self.processed_rrsets:
                self.processed_rrsets[(name, rdtype)] = []
            self.processed_rrsets[(name, rdtype)].append(error_node)

        warning_node = self.add_warnings(name_obj, zone_obj, name, rdtype, name_obj.response_warnings[query])
        if warning_node is not None:
            if (name, rdtype) not in self.processed_rrsets:
                self.processed_rrsets[(name, rdtype)] = []
            self.processed_rrsets[(name, rdtype)].append(warning_node)

        for alias_node, target in node_to_cname_mapping:
            # if this is a recursive analysis, then we've already graphed the
            # node, above, so we graph its hierarchy and then retrieve it from
            # self.processed_rrsets
            if name_obj.analysis_type == ANALYSIS_TYPE_RECURSIVE:
                # if we didn't get the cname RRset in same response, then
                # processed_rrsets won't be populated
                try:
                    cname_nodes = self.processed_rrsets[(target, rdtype)]
                except KeyError:
                    cname_nodes = []

            for cname_node in cname_nodes:
                self.add_alias(alias_node, cname_node)

        return self.processed_rrsets[(name, rdtype)]

    def graph_zone_auth(self, name_obj, is_dlv):
        if (name_obj.name, -1) in self.processed_rrsets:
            return
        self.processed_rrsets[(name_obj.name, -1)] = True

        zone_obj = name_obj.zone
        S, zone_graph_name, zone_bottom, zone_top = self.add_zone(zone_obj)

        if zone_obj.stub:
            return

        # indicate that this zone is not a stub
        self.subgraph_not_stub.add(zone_top)

        #######################################
        # DNSKEY roles, based on what they sign
        #######################################
        all_dnskeys = name_obj.get_dnskeys()

        # Add DNSKEY nodes to graph
        for dnskey in name_obj.get_dnskeys():
            self.add_dnskey(name_obj, dnskey)

        for signed_keys, rrset_info in name_obj.get_dnskey_sets():
            for rrsig in name_obj.rrsig_status[rrset_info]:
                signer_obj = name_obj.get_name(rrsig.signer)
                if signer_obj is not None:
                    # if we have the analysis corresponding to the signer, then
                    # graph it too, if it was different from what we were
                    # expecting
                    if rrsig.signer != name_obj.name and not is_dlv:
                        self.graph_zone_auth(signer_obj, False)
                for dnskey in name_obj.rrsig_status[rrset_info][rrsig]:
                    rrsig_status = name_obj.rrsig_status[rrset_info][rrsig][dnskey]
                    if dnskey is None:
                        dnskey_node = None
                    else:
                        dnskey_node = self.get_dnskey(self.id_for_dnskey(signer_obj.name, dnskey.rdata), signer_obj.name, dnskey.rdata.algorithm, dnskey.key_tag)

                    for signed_key in signed_keys:
                        signed_key_node = self.get_dnskey(self.id_for_dnskey(name_obj.name, signed_key.rdata), name_obj.name, signed_key.rdata.algorithm, signed_key.key_tag)
                        self.add_rrsig(rrsig_status, name_obj, signer_obj, signed_key_node)

        # map negative responses for DNSKEY queries to top name of the zone
        try:
            dnskey_nodata_info = [x for x in name_obj.nodata_status if x.qname == name_obj.name and x.rdtype == dns.rdatatype.DNSKEY][0]
        except IndexError:
            pass
        else:
            self.node_reverse_mapping[dnskey_nodata_info] = zone_top
        try:
            dnskey_nxdomain_info = [x for x in name_obj.nxdomain_status if x.qname == name_obj.name and x.rdtype == dns.rdatatype.DNSKEY][0]
        except IndexError:
            pass
        else:
            self.node_reverse_mapping[dnskey_nxdomain_info] = zone_top

        # handle other responses to DNSKEY/DS queries
        for rdtype in (dns.rdatatype.DS, dns.rdatatype.DNSKEY):
            if (name_obj.name, rdtype) in name_obj.queries:

                # Handle errors and warnings for DNSKEY/DS queries
                if rdtype == dns.rdatatype.DS and zone_obj.parent is not None and not is_dlv:
                    z_obj = zone_obj.parent
                    self.graph_zone_auth(z_obj, False)
                else:
                    z_obj = zone_obj
                self.add_errors(name_obj, z_obj, name_obj.name, rdtype, name_obj.response_errors[name_obj.queries[(name_obj.name, rdtype)]])
                self.add_warnings(name_obj, z_obj, name_obj.name, rdtype, name_obj.response_warnings[name_obj.queries[(name_obj.name, rdtype)]])

                # Map CNAME responses to DNSKEY/DS queries to appropriate node
                for rrset_info in name_obj.queries[(name_obj.name, rdtype)].answer_info:
                    if rrset_info.rrset.rdtype == dns.rdatatype.CNAME:
                        rrset_node = self.add_rrset(rrset_info, None, name_obj, name_obj.zone)
                        if rrset_node not in self.node_mapping:
                            self.node_mapping[rrset_node] = []
                        self.node_mapping[rrset_node].add(rrset_info)
                        self.node_reverse_mapping[rrset_info] = rrset_node

        if not name_obj.is_zone():
            return

        if name_obj.parent is None or is_dlv:
            return

        for dlv in False, True:
            if dlv:
                parent_obj = name_obj.dlv_parent
                ds_name = name_obj.dlv_name
                rdtype = dns.rdatatype.DLV
            else:
                parent_obj = name_obj.parent
                ds_name = name_obj.name
                rdtype = dns.rdatatype.DS

            if parent_obj is None or ds_name is None:
                continue

            # if this is a DLV parent, and either we're not showing
            # DLV, or there is no DLV information for this zone, move along
            if dlv and (ds_name, rdtype) not in name_obj.queries:
                continue

            self.graph_zone_auth(parent_obj, dlv)

            P, parent_graph_name, parent_bottom, parent_top = self.add_zone(parent_obj)

            for dnskey in name_obj.ds_status_by_dnskey[rdtype]:
                ds_statuses = list(name_obj.ds_status_by_dnskey[rdtype][dnskey].values())

                # identify all validation_status/RRset/algorithm/key_tag
                # combinations, so we can cluster like DSs
                validation_statuses = set([(d.validation_status, d.ds_meta, d.ds.algorithm, d.ds.key_tag) for d in ds_statuses])

                for validation_status, rrset_info, algorithm, key_tag in validation_statuses:
                    ds_status_subset = [x for x in ds_statuses if x.validation_status == validation_status and x.ds_meta is rrset_info and x.ds.algorithm == algorithm and x.ds.key_tag == key_tag]

                    # create the DS node and edge
                    ds_node = self.add_ds(ds_name, ds_status_subset, name_obj, parent_obj)

                    self.add_rrsigs(name_obj, parent_obj, rrset_info, ds_node)

            edge_id = 0

            nsec_statuses = []
            soa_rrsets = []
            try:
                ds_nodata_info = [x for x in name_obj.nodata_status if x.qname == ds_name and x.rdtype == rdtype][0]
                nsec_statuses.extend(name_obj.nodata_status[ds_nodata_info])
                soa_rrsets.extend(ds_nodata_info.soa_rrset_info)
            except IndexError:
                ds_nodata_info = None
            try:
                ds_nxdomain_info = [x for x in name_obj.nxdomain_status if x.qname == ds_name and x.rdtype == rdtype][0]
                nsec_statuses.extend(name_obj.nxdomain_status[ds_nxdomain_info])
                soa_rrsets.extend(ds_nxdomain_info.soa_rrset_info)
            except IndexError:
                ds_nxdomain_info = None

            for nsec_status in nsec_statuses:

                nsec_node = self.add_nsec(nsec_status, ds_name, rdtype, name_obj, parent_obj, zone_top)
                # add a tail to the cluster
                self.G.get_edge(zone_top, nsec_node).attr['ltail'] = zone_graph_name
                # anchor NSEC node to bottom
                self.G.add_edge(parent_bottom, nsec_node, style='invis')

                for nsec_name, rrset_info in nsec_status.nsec_set_info.rrsets.items():
                    nsec_cell = lb2s(nsec_name.canonicalize().to_text())
                    self.add_rrsigs(name_obj, parent_obj, rrset_info, nsec_node, port=nsec_cell)

                edge_id += 1

            # add SOA
            for soa_rrset_info in soa_rrsets:
                soa_rrset_node = self.add_rrset(soa_rrset_info, None, name_obj, parent_obj)
                self.add_rrsigs(name_obj, parent_obj, soa_rrset_info, soa_rrset_node)

            # add mappings for negative responses
            self.node_mapping[zone_top] = set()
            if ds_nodata_info is not None:
                self.node_mapping[zone_top].add(ds_nodata_info)
                self.node_reverse_mapping[ds_nodata_info] = zone_top
            if ds_nxdomain_info is not None:
                self.node_mapping[zone_top].add(ds_nxdomain_info)
                self.node_reverse_mapping[ds_nxdomain_info] = zone_top

            has_warnings = name_obj.delegation_warnings[rdtype] or (ds_nxdomain_info is not None and name_obj.nxdomain_warnings[ds_nxdomain_info]) or (ds_nodata_info is not None and name_obj.nodata_warnings[ds_nodata_info])
            has_errors = name_obj.delegation_errors[rdtype] or (ds_nxdomain_info is not None and name_obj.nxdomain_errors[ds_nxdomain_info]) or (ds_nodata_info is not None and name_obj.nodata_errors[ds_nodata_info])

            edge_label = ''
            if has_errors:
                edge_label = '<<TABLE BORDER="0"><TR><TD><IMG SCALE="TRUE" SRC="%s"/></TD></TR></TABLE>>' % ERROR_ICON
            elif has_warnings:
                edge_label = '<<TABLE BORDER="0"><TR><TD><IMG SCALE="TRUE" SRC="%s"/></TD></TR></TABLE>>' % WARNING_ICON

            if name_obj.delegation_status[rdtype] == Status.DELEGATION_STATUS_SECURE:
                line_color = COLORS['secure']
                line_style = 'solid'
            elif name_obj.delegation_status[rdtype] == Status.DELEGATION_STATUS_INSECURE:
                line_color = COLORS['insecure']
                line_style = 'solid'
            elif name_obj.delegation_status[rdtype] in (Status.DELEGATION_STATUS_INCOMPLETE, Status.DELEGATION_STATUS_LAME):
                line_color = COLORS['misconfigured']
                line_style = 'dashed'
            elif name_obj.delegation_status[rdtype] == Status.DELEGATION_STATUS_BOGUS:
                line_color = COLORS['bogus']
                line_style = 'dashed'

            consolidate_clients = name_obj.single_client()
            del_serialized = OrderedDict()
            del_serialized['description'] = 'Delegation from %s to %s' % (lb2s(name_obj.parent.name.to_text()), lb2s(name_obj.name.to_text()))
            del_serialized['status'] = Status.delegation_status_mapping[name_obj.delegation_status[rdtype]]

            if has_warnings:
                del_serialized['warnings'] = []
                del_serialized['warnings'] += [w.serialize(consolidate_clients=consolidate_clients, html_format=True) for w in name_obj.delegation_warnings[rdtype]]
                del_serialized['warnings'] += [w.serialize(consolidate_clients=consolidate_clients, html_format=True) for w in name_obj.nxdomain_warnings.get(ds_nxdomain_info, [])]
                del_serialized['warnings'] += [w.serialize(consolidate_clients=consolidate_clients, html_format=True) for w in name_obj.nodata_warnings.get(ds_nodata_info, [])]

            if has_errors:
                del_serialized['errors'] = []
                del_serialized['errors'] += [e.serialize(consolidate_clients=consolidate_clients, html_format=True) for e in name_obj.delegation_errors[rdtype]]
                del_serialized['errors'] += [e.serialize(consolidate_clients=consolidate_clients, html_format=True) for e in name_obj.nxdomain_errors.get(ds_nxdomain_info, [])]
                del_serialized['errors'] += [e.serialize(consolidate_clients=consolidate_clients, html_format=True) for e in name_obj.nodata_errors.get(ds_nodata_info, [])]

            edge_id = 'del-%s|%s' % (fmt.humanize_name(zone_obj.name), fmt.humanize_name(parent_obj.name))
            self.node_info[edge_id] = [del_serialized]
            self.G.add_edge(zone_top, parent_bottom, label=edge_label, id=edge_id, color=line_color, penwidth='5.0', ltail=zone_graph_name, lhead=parent_graph_name, style=line_style, minlen='2', dir='back')

    def _set_non_existent_color(self, n):
        if DASHED_STYLE_RE.search(n.attr['style']) is None:
            return

        if n.attr['color'] == COLORS['secure']:
            n.attr['color'] = COLORS['secure_non_existent']

            # if this is an authenticated negative response, and the NSEC3
            # RR used opt out, then the node is actually insecure, rather
            # than secure.
            for n1 in self.G.out_neighbors(n):
                if n1.startswith('NSEC3') and OPTOUT_STYLE_RE.search(n1.attr['label']):
                    n.attr['color'] = COLORS['insecure_non_existent']

        elif n.attr['color'] == COLORS['bogus']:
            n.attr['color'] = COLORS['bogus_non_existent']

        else:
            n.attr['color'] = COLORS['insecure_non_existent']

    def _set_nsec_color(self, n):
        if not n.startswith('NSEC'):
            return

        #XXX we have to assign l to n.attr['label'], perform any update
        # operations on l, then assign n.attr['label'] to l's new value,
        # wrapping it in "<...>".  This is because the "<" and ">" at the start
        # and end somehow get lost when the assignment is made directly.
        l = n.attr['label']
        l = re.sub(r'^(<<TABLE)', r'\1 COLOR="%s"' % n.attr['color'], l, 1)
        if n.attr['color'] == COLORS['bogus']:
            #XXX it looks better when cellspacing is 0, but we can't do that
            # when there are cells that are colored with different colors.  In
            # this case, we need to change the cell spacing back to 0
            l = re.sub(r'(<TABLE[^>]+CELLSPACING=")-\d+"', r'\g<1>0"', l, 1)
            for nsec_name in self.nsec_rr_status[n]:
                if not self.nsec_rr_status[n][nsec_name]:
                    self.nsec_rr_status[n][nsec_name] = COLORS['bogus']
                l = re.sub(r'(<TD[^>]+PORT="%s")' % nsec_name, r'\1 COLOR="%s"' % self.nsec_rr_status[n][nsec_name], l, 1)
        n.attr['label'] = '<%s>' % l

    def _set_node_status(self, n):
        status = self.status_for_node(n)

        node_id = n.replace('*', '_')
        for serialized in self.node_info[node_id]:
            serialized['status'] = Status.rrset_status_mapping[status]

    def add_trust(self, trusted_keys, supported_algs=None):
        trusted_keys = tuple_to_dict(trusted_keys)
        if supported_algs is not None:
            supported_algs.intersection_update(crypto._supported_algs)
        else:
            supported_algs = crypto._supported_algs

        dlv_nodes = []
        trusted_zone_top_names = set([self.get_zone(z)[3] for z in trusted_keys])
        for zone in trusted_keys:
            zone_top_name = self.get_zone(zone)[3]
            if not self.G.has_node(zone_top_name) or zone_top_name not in self.subgraph_not_stub:
                continue

            # if at least one algorithm in trusted keys for the zone is
            # supported, then give zone no initial marking; otherwise mark it
            # as insecure
            algs = set([d.algorithm for d in trusted_keys[zone]])
            if algs.intersection(supported_algs):
                self.G.get_node(zone_top_name).attr['color'] = ''
            else:
                self.G.get_node(zone_top_name).attr['color'] = COLORS['insecure']

            for dnskey in trusted_keys[zone]:
                try:
                    dnskey_node = self.get_dnskey(self.id_for_dnskey(zone, dnskey), zone, dnskey.algorithm, Response.DNSKEYMeta.calc_key_tag(dnskey))
                    dnskey_node.attr['peripheries'] = 2
                    if self.G.get_node(zone_top_name).attr['color'] == '':
                        self._add_trust_to_nodes_in_chain(dnskey_node, trusted_zone_top_names, dlv_nodes, False, [])
                except KeyError:
                    dnskey_node = self.add_dnskey_non_existent(zone, zone, dnskey.algorithm, Response.DNSKEYMeta.calc_key_tag(dnskey))
                    dnskey_node.attr['peripheries'] = 2

        # determine DLV zones based on DLV nodes
        dlv_trusted_zone_top_names = []
        for dlv_node in dlv_nodes:
            dlv_trusted_zone_top_names.append(self.node_subgraph_name[dlv_node])

        # now traverse clusters and mark insecure nodes in secure delegations as bad
        for zone in trusted_keys:
            S, zone_node_str, zone_bottom_name, zone_top_name = self.get_zone(zone)
            if not self.G.has_node(zone_top_name) or zone_top_name not in self.subgraph_not_stub:
                continue

            # don't yet mark subdomains of DLV zones, as we have yet
            # to add trust to them
            if zone_top_name not in dlv_trusted_zone_top_names:
                self._add_trust_to_orphaned_nodes(zone_node_str, [])

        # now that we can show which zones are provably insecure, we
        # can apply trust from the DLV zones
        for dlv_node in dlv_nodes:
            self._add_trust_to_nodes_in_chain(dlv_node, trusted_zone_top_names, [], True, [])

        # now mark the orphaned nodes
        for dlv_node in dlv_nodes:
            zone_node_str = self.node_subgraph_name[dlv_node][:-4]
            self._add_trust_to_orphaned_nodes(zone_node_str, [])

        for n in self.G.nodes():
            # set the status of (only) the cluster top node as well
            if n.attr['shape'] == 'point' and n.endswith('_top'):
                pass
            elif n.attr['shape'] not in ('ellipse', 'rectangle') and not n.startswith('NSEC'):
                continue
            self._set_non_existent_color(n)
            self._set_nsec_color(n)
            self._set_node_status(n)

    def status_for_node(self, n, port=None):
        n = self.G.get_node(n)

        if n.attr['color'] in (COLORS['secure'], COLORS['secure_non_existent']):
            status = Status.RRSET_STATUS_SECURE
        elif n.attr['color'] in (COLORS['bogus'], COLORS['bogus_non_existent']):
            if port is not None and self.nsec_rr_status[n][port] == COLORS['secure']:
                status = Status.RRSET_STATUS_SECURE
            else:
                status = Status.RRSET_STATUS_BOGUS
        else:
            if n.startswith('DNSKEY') and \
                    DASHED_STYLE_RE.search(n.attr['style']):
                status = Status.RRSET_STATUS_NON_EXISTENT
            else:
                status = Status.RRSET_STATUS_INSECURE
        return status

    def secure_nsec3_optout_nodes_covering_node(self, n):
        return [x for x in self.G.out_neighbors(n) if x.startswith('NSEC') and \
                OPTOUT_STYLE_RE.search(x.attr['label']) is not None and \
                x.attr['color'] == COLORS['secure']]

    def secure_nsec_nodes_covering_node(self, n):
        return [x for x in self.G.out_neighbors(n) if x.startswith('NSEC') and \
                x.attr['color'] == COLORS['secure']]

    def is_invis(self, n):
        return INVIS_STYLE_RE.search(self.G.get_node(n).attr['style']) is not None

    def _add_trust_to_nodes_in_chain(self, n, trusted_zones, dlv_nodes, force, trace):
        if n in trace:
            return

        is_ds = n.startswith('DS-') or n.startswith('DLV-')
        is_dlv = n.startswith('DLV-')
        is_dnskey = n.startswith('DNSKEY-')
        is_nsec = n.startswith('NSEC')
        is_dname = n.endswith('|DNAME')

        if is_dlv and not force:
            dlv_nodes.append(n)
            return

        # if n isn't a DNSKEY, DS/DLV, or NSEC record,
        # then don't follow back edges
        if not (is_ds or is_dnskey or is_nsec or is_dname):
            return

        is_revoked = n.attr['penwidth'] == '4.0'
        is_trust_anchor = n.attr['peripheries'] == '2'

        top_name = self.G.get_node(self.node_subgraph_name[n])

        # trust anchor and revoked DNSKEY must be self-signed
        if is_revoked or is_trust_anchor:
            valid_self_loop = False
            if self.G.has_edge(n,n):
                for e1 in self.G.out_edges(n) + self.G.in_edges(n):
                    if (n,n) == e1 and \
                            e1.attr['color'] == COLORS['secure']:
                        valid_self_loop = True

                        # mark all the DNSKEY RRsets as valid
                        for rrsig in self.node_mapping[e1.attr['id']]:
                            self.secure_dnskey_rrsets.add(rrsig.rrset)

                        break

            #XXX revisit if we want to do this here
            if is_revoked and n.attr['color'] == COLORS['secure'] and not valid_self_loop:
                n.attr['color'] = COLORS['bogus']

            # mark the zone as "secure" as there is a secure entry point;
            # descendants will be so marked by following the delegation edges
            if is_trust_anchor and valid_self_loop:
                n.attr['color'] = COLORS['secure']
                top_name.attr['color'] = COLORS['secure']

        node_trusted = n.attr['color'] == COLORS['secure']

        if is_dnskey and not node_trusted:
            # Here we are shortcutting the traversal because we are no longer
            # propagating trust.  But we still need to learn of any DLV nodes.
            if not force:
                S = self.G.get_subgraph(top_name[:-4])
                for n in S.nodes():
                    if n.startswith('DLV-'):
                        dlv_nodes.append(n)
            return

        # iterate through each edge and propagate trust from this node
        for e in self.G.in_edges(n):
            p = e[0]

            # if this is an edge used for formatting node (invis), then don't
            # follow it
            if INVIS_STYLE_RE.search(e.attr['style']) is not None:
                continue

            prev_top_name = self.G.get_node(self.node_subgraph_name[p])

            # don't derive trust from parent if there is a trust anchor at the
            # child
            if is_ds and prev_top_name in trusted_zones:
                continue

            # if the previous node is already secure, then no need to follow it
            if p.attr['color'] == COLORS['secure']:
                continue

            # if this is a DLV node, then the zone it covers must be marked
            # as insecure through previous trust traversal (not because of
            # a local trust anchor, which case is handled above)
            if is_dlv:
                if prev_top_name.attr['color'] not in ('', COLORS['insecure']):
                    continue

                # reset the security of this top_name
                prev_top_name.attr['color'] = ''

            # if this is a non-matching edge (dashed) then don't follow it
            if DASHED_STYLE_RE.search(e.attr['style']) is not None:
                continue

            # derive trust for the previous node using the current node and the
            # color of the edge in between
            prev_node_trusted = node_trusted and e.attr['color'] == COLORS['secure']

            if is_ds:
                # if this is an edge between DS and DNSKEY, then the DNSKEY is
                # not considered secure unless it has a valid self-loop (in
                # addition to the connecting edge being valid)
                valid_self_loop = False
                if self.G.has_edge(p,p):
                    for e1 in self.G.out_edges(p) + self.G.in_edges(p):
                        if (p,p) == e1 and \
                                e1.attr['color'] == COLORS['secure']:
                            valid_self_loop = True

                            # mark all the DNSKEY RRsets as valid
                            for rrsig in self.node_mapping[e1.attr['id']]:
                                self.secure_dnskey_rrsets.add(rrsig.rrset)

                            break

                prev_node_trusted = prev_node_trusted and valid_self_loop

            # if p is an NSEC (set) node, then we need to check that all the
            # NSEC RRs have been authenticated before we mark this one as
            # authenticated.
            elif p.startswith('NSEC'):
                rrsig_status = list(self.node_mapping[e.attr['id']])[0]
                nsec_name = lb2s(rrsig_status.rrset.rrset.name.canonicalize().to_text()).replace(r'"', r'\"')
                if prev_node_trusted:
                    self.nsec_rr_status[p][nsec_name] = COLORS['secure']
                    for nsec_name in self.nsec_rr_status[p]:
                        if self.nsec_rr_status[p][nsec_name] != COLORS['secure']:
                            prev_node_trusted = False

            if is_nsec:
                # if this is an NSEC, then only propagate trust if the previous
                # node (i.e., the node it covers) is an RRset
                if prev_node_trusted and p.attr['shape'] == 'rectangle':
                    p.attr['color'] = COLORS['secure']

            elif prev_node_trusted:
                p.attr['color'] = COLORS['secure']

            self._add_trust_to_nodes_in_chain(p, trusted_zones, dlv_nodes, force, trace+[n])

    def _add_trust_to_orphaned_nodes(self, subgraph_name, trace):
        if subgraph_name in trace:
            return

        top_name = self.G.get_node(subgraph_name + '_top')
        bottom_name = self.G.get_node(subgraph_name + '_bottom')


        # if this subgraph (zone) is provably insecure, then don't process
        # further
        if top_name.attr['color'] == COLORS['insecure']:
            return

        # iterate through each node in the subgraph (zone) and mark as bogus
        # all nodes that are not already marked as secure
        S = self.G.get_subgraph(subgraph_name)
        for n in S.nodes():
            # don't mark invisible nodes (zone marking as secure/insecure is handled in the
            # traversal at the delegation point below).
            if INVIS_STYLE_RE.search(n.attr['style']) is not None:
                continue

            # if node is non-existent, then don't mark it, unless we are talking about an RRset
            # or a non-existent trust anchor; it doesn't make sense to mark other nodes
            # as bogus
            if DASHED_STYLE_RE.search(n.attr['style']) is not None and not (n.attr['shape'] == 'rectangle' or \
                    n.attr['peripheries'] == 2):
                continue

            # if the name is already marked as secure
            if n.attr['color'] == COLORS['secure']:
                # don't mark it as bogus
                continue

            n.attr['color'] = COLORS['bogus']

        # propagate trust through each descendant node
        for p in self.G.predecessors(bottom_name):
            e = self.G.get_edge(p, bottom_name)

            child_subgraph_name = p[:-4]

            if top_name.attr['color'] == COLORS['secure']:
                # if this subgraph (zone) is secure, and the delegation is also
                # secure, then mark the delegated subgraph (zone) as secure.
                if e.attr['color'] == COLORS['secure']:
                    p.attr['color'] = COLORS['secure']
                # if this subgraph (zone) is secure, and the delegation is not
                # bogus (DNSSEC broken), then mark it as provably insecure.
                elif e.attr['color'] != COLORS['bogus']:
                    # in this case, it's possible that the proven insecurity is
                    # dependent on NSEC/NSEC3 records that need to be
                    # authenticated.  Before marking this as insecure, reach
                    # back up for NSEC records.  If any are found, make sure at
                    # least one has been authenticated (i.e., has secure
                    # color).
                    nsec_found = False
                    nsec_authenticated = False
                    for n in self.G.out_neighbors(p):
                        if not n.startswith('NSEC'):
                            continue
                        # check that this node is in the zone we're coming from
                        if self.node_subgraph_name[n] != top_name:
                            continue
                        nsec_found = True
                        if n.attr['color'] == COLORS['secure']:
                            nsec_authenticated = True
                            break

                    # or if there are DS, then there are algorithms that are
                    # not understood (otherwise it would not be insecure).
                    # Check that at least one of the DS nodes was marked as
                    # secure.
                    ds_found = False
                    ds_authenticated = False
                    S = self.G.get_subgraph(child_subgraph_name)
                    for n in S.nodes():
                        # we're only concerned with DNSKEYs
                        if not n.startswith('DNSKEY-'):
                            continue
                        # we're looking for DS records
                        for d in self.G.out_neighbors(n):
                            if not (d.startswith('DS-') or d.startswith('DLV-')):
                                continue
                            # check that this node is in the zone we're coming from
                            if self.node_subgraph_name[d] != top_name:
                                continue
                            ds_found = True
                            if d.attr['color'] == COLORS['secure']:
                                ds_authenticated = True
                                break

                    if nsec_found and not nsec_authenticated:
                        pass
                    elif ds_found and not ds_authenticated:
                        pass
                    else:
                        p.attr['color'] = COLORS['insecure']

            # if the child was not otherwise marked, then mark it as bogus
            if p.attr['color'] == '':
                p.attr['color'] = COLORS['bogus']

            self._add_trust_to_orphaned_nodes(child_subgraph_name, trace+[subgraph_name])

    def remove_extra_edges(self, show_redundant=False):
        #XXX this assumes DNSKEYs with same name as apex
        for S in self.G.subgraphs():
            non_dnskey = set()
            all_dnskeys = set()
            ds_dnskeys = set()
            ta_dnskeys = set()
            ksks = set()
            zsks = set()
            sep_bit = set()
            revoked_dnskeys = set()
            non_existent_dnskeys = set()
            existing_dnskeys = set()

            for n in S.nodes():
                if not n.startswith('DNSKEY-'):
                    if n.attr['shape'] != 'point':
                        non_dnskey.add(n)
                    continue

                all_dnskeys.add(n)

                in_edges = self.G.in_edges(n)
                out_edges = self.G.out_edges(n)
                ds_edges = [x for x in out_edges if x[1].startswith('DS-') or x[1].startswith('DLV-')]

                is_ksk = bool([x for x in in_edges if x[0].startswith('DNSKEY-')])
                is_zsk = bool([x for x in in_edges if not x[0].startswith('DNSKEY-')])
                non_existent = DASHED_STYLE_RE.search(n.attr['style']) is not None
                has_sep_bit = n.attr['fillcolor'] == 'lightgray'

                if is_ksk:
                    ksks.add(n)
                if is_zsk:
                    zsks.add(n)
                if has_sep_bit:
                    sep_bit.add(n)
                if n.attr['peripheries'] == '2':
                    ta_dnskeys.add(n)
                if ds_edges:
                    ds_dnskeys.add(n)
                if n.attr['penwidth'] == '4.0':
                    revoked_dnskeys.add(n)
                if non_existent:
                    non_existent_dnskeys.add(n)
                else:
                    existing_dnskeys.add(n)

            seps = ds_dnskeys.union(ta_dnskeys).intersection(ksks).difference(revoked_dnskeys)
            ksk_only = ksks.difference(zsks).difference(revoked_dnskeys)
            zsk_only = zsks.difference(ksks).difference(revoked_dnskeys)

            # if all keys have only KSK roles (i.e., none are signing the zone
            # data), then try to distinguish using SEP bit
            if ksk_only and not zsks and sep_bit:
                ksk_only.intersection_update(sep_bit)

            if seps:
                top_level_keys = seps
            else:
                if ksk_only:
                    top_level_keys = ksk_only
                elif ksks:
                    top_level_keys = ksks
                elif sep_bit:
                    top_level_keys = sep_bit
                else:
                    top_level_keys = all_dnskeys

            if top_level_keys:

                # If there aren't any KSKs or ZSKs, then signing roles are
                # unknown, and the top-level keys are organized by SEP bit.
                # Because there are no roles, every key is an "island" (i.e.,
                # not signed by any top-level keys), so only look for "islands"
                # if there are ZSKs or KSKs.
                if zsks or ksks:
                    for n in all_dnskeys.difference(top_level_keys):
                        if set(self.G.out_neighbors(n)).intersection(top_level_keys):
                            # If this key is already signed by a top-level, then
                            # it's not in an island.
                            pass
                        else:
                            # Otherwise, find out what keys are connected to this one
                            neighbors = set(self.G.neighbors(n))

                            # If this key is ksk only, then it is always a top-level key.
                            if n in ksk_only:
                                top_level_keys.add(n)

                            # If this key is not a ksk, and there are ksks, then
                            # it's not a top-level key.
                            elif n not in ksks and neighbors.intersection(ksks):
                                pass

                            # If this key does not have its sep bit set, and there
                            # are others that do, then it's not a top-level key.
                            elif n not in sep_bit and neighbors.intersection(sep_bit):
                                pass

                            # Otherwise, it's on the same rank as all the others,
                            # so it is a top-level key.
                            else:
                                top_level_keys.add(n)

                # In the case where a top-level key is signing zone data, and
                # there are other top-level keys that are not signing zone data,
                # remove it from the top-level keys list, and don't add an edge
                # to the top.  This will make the other top-level keys appear
                # "higher".
                for n in list(top_level_keys):
                    if n in zsks and set(self.G.neighbors(n)).intersection(top_level_keys).intersection(ksk_only):
                        top_level_keys.remove(n)
                    else:
                        self.G.add_edge(n, self.node_subgraph_name[n], style='invis')

                # Now handle all the keys not at the top level
                non_top_level_keys = all_dnskeys.difference(top_level_keys)
                if non_top_level_keys:
                    # If there are any keys that are not at the top level, then
                    # determine whether they should be connected to the
                    # top-level keys, to the top, or left alone.
                    for n in non_top_level_keys:

                        # Non-existent DNSKEYs corresponding to DS and trust
                        # anchors should be connected to the top.
                        if n in non_existent_dnskeys:
                            if n in ds_dnskeys or n in ta_dnskeys:
                                self.G.add_edge(n, self.node_subgraph_name[n], style='invis')

                        # If not linked to any other DNSKEYs, then link to
                        # top-level keys.
                        elif not [x for x in self.G.out_neighbors(n) if x.startswith('DNSKEY')]:
                            for m in top_level_keys:
                                if not self.G.has_edge(n, m):
                                    self.G.add_edge(n, m, style='invis')

                    intermediate_keys = non_top_level_keys
                else:
                    intermediate_keys = top_level_keys

                # If there are ZSKs (and possible ZSKs only signing zone data),
                # then make those the intermediate keys, instead of using all
                # the top-level (or non-top-level) keys.
                if zsk_only:
                    intermediate_keys = zsk_only
                elif zsks:
                    intermediate_keys = zsks

                # Link non-keys to intermediate DNSKEYs
                for n in non_dnskey:
                    if [x for x in self.G.out_neighbors(n) if x.startswith('DNSKEY') or x.startswith('NSEC')]:
                        continue
                    for m in intermediate_keys:
                        # we only link to non-existent DNSKEYs corresponding to
                        # DS records if there aren't any existing DNSKEYs.
                        if m in ds_dnskeys and m in non_existent_dnskeys:
                            if existing_dnskeys:
                                continue
                        self.G.add_edge(n, m, style='invis')

            else:
                # For all non-existent non-DNSKEYs, add an edge to the top
                for n in non_dnskey:
                    if [x for x in self.G.out_neighbors(n) if x.startswith('DNSKEY') or x.startswith('NSEC')]:
                        continue
                    self.G.add_edge(n, self.node_subgraph_name[n], style='invis')

            for n in ksks:
                retain_edge_default = n in top_level_keys
                for e in self.G.in_edges(n):
                    m = e[0]
                    if not m.startswith('DNSKEY-'):
                        continue
                    if n == m:
                        continue

                    if retain_edge_default and m in top_level_keys:
                        retain_edge = False
                    else:
                        retain_edge = retain_edge_default

                    if not retain_edge:
                        if show_redundant:
                            self.G.get_edge(m, n).attr['constraint'] = 'false'
                        else:
                            try:
                                del self.node_info[e.attr.get('id', None)]
                            except KeyError:
                                pass
                            self.G.remove_edge(m, n)
