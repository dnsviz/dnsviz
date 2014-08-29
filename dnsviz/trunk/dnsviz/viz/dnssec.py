#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Author: Casey Deccio (casey@deccio.net)
#
# Copyright 2012-2014 Sandia Corporation. Under the terms of Contract
# DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government retains certain
# rights in this software.
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
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

import collections
import json
import os
import re
import sys
import xml.dom.minidom

import dns.name, dns.rdtypes, dns.rdatatype, dns.dnssec

from pygraphviz import AGraph

from dnsviz.config import DNSVIZ_SHARE_PATH
from dnsviz import crypto
from dnsviz import format as fmt
from dnsviz import response as Response
from dnsviz import status as Status
from dnsviz.util import tuple_to_dict

COLORS = { 'secure': '#0a879a', 'secure_light': '#8ffeff',
        'bogus': '#be1515', 'bogus_light': '#f17b7b',
        'insecure': '#000000', 'insecure_light': '#b7b7b7',
        'expired': '#6131a3', 'expired_light': '#ad7fed',
        'misconfigured': '#f4b800', 'misconfigured_light': '#fffa8f',
        'warnings': '#f4b800', 'warnings_light': '#fffa8f',
        'unknown': '#000000', 'insecure_light': '#b7b7b7',
        'errors': '#be1515', 'errors_light': '#f17b7b' }

ICON_PATH=os.path.join(DNSVIZ_SHARE_PATH, 'icons')
WARNING_ICON=os.path.join(ICON_PATH, 'warning.png')
ERROR_ICON=os.path.join(ICON_PATH, 'error.png')

class DNSKEYNonExistent(object):
    def __init__(self, name, algorithm, key_tag):
        self.name = name
        self.algorithm = algorithm
        self.key_tag = key_tag

    def serialize(self):
        d = collections.OrderedDict()
        d['flags'] = None
        d['protocol'] = None
        d['algorithm'] = self.algorithm
        d['key'] = None
        d['meta'] = collections.OrderedDict((
            ('ttl', None),
            ('key_length', None),
            ('key_tag', self.key_tag)
        ))
        return d

class RRsetNonExistent(object):
    def __init__(self, name, rdtype, servers_clients):
        self.name = name
        self.rdtype = rdtype
        self.servers_clients = servers_clients

    def serialize(self, consolidate_clients):
        d = collections.OrderedDict()
        if self.rdtype == dns.rdatatype.NSEC3:
            d['name'] = format.format_nsec3_name(self.name)
        else:
            d['name'] = self.name.canonicalize().to_text()
        d['ttl'] = None
        d['type'] = dns.rdatatype.to_text(self.rdtype)
        d['rdata'] = []

        servers = tuple_to_dict(self.servers_clients)
        if consolidate_clients:
            servers = list(servers)
            servers.sort()
        d['servers'] = servers
        return d

class DNSAuthGraph:
    def __init__(self, dlv_domain=None):
        self.dlv_domain = dlv_domain

        self.G = AGraph(directed=True, strict=False, compound='true', rankdir='BT', ranksep='0.3')

        self.G.node_attr['penwidth'] = '1.5'
        self.G.edge_attr['penwidth'] = '1.5'
        self.node_info = {}
        self.node_subgraph_name = {}
        self.processed_rrsets = {}

        self.dnskey_ids = {}
        self.ds_ids = {}
        self.nsec_ids = {}
        self.next_dnskey_id = 0
        self.next_ds_id = 0
        self.next_nsec_id = 0

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
                    s += '\tthis.addNodeEvent(el, node_info[\'%s\']);\n' % node_id.replace('--', '\\-\\-')

        for i in range(node.childNodes.length):
            s += self._write_raphael_node(node.childNodes[i], node_id, transform)
        return s

    def to_raphael(self):
        svg = self.G.draw(format='svg', prog='dot')
        dom = xml.dom.minidom.parseString(svg)

        s = 'AuthGraph.prototype.draw = function () {\n'
        s += '\tvar el, paperScale;\n'
        s += '\tvar node_info = %s;\n' % json.dumps(self.node_info)
        s += self._write_raphael_node(dom.documentElement, None, 's\'+this.imageScale+\',\'+this.imageScale+\',0,0')
        s += '\tpaper.setViewBox(0, 0, imageWidth, imageHeight);\n'
        s += '}\n'
        return s

    def draw(self, format, path=None):
        if format == 'js':
            img = self.to_raphael()
            if path is None:
                return img
            else:
                open(path, 'w').write(img)
        else:
            if path is None:
                return self.G.draw(format=format, prog='dot')
            else:
                return self.G.draw(path=path, format=format, prog='dot')

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

    def id_for_nsec(self, name, rdtype, nsec_set_info):
        try:
            nsec_set_info_list = self.nsec_ids[(name,rdtype)]
        except KeyError:
            self.nsec_ids[(name,rdtype)] = []
            nsec_set_info_list = self.nsec_ids[(name,rdtype)]

        for nsec_set_info1, id in nsec_set_info_list:
            if nsec_set_info == nsec_set_info1:
                return id

        id = self.next_nsec_id
        self.nsec_ids[(name,rdtype)].append((nsec_set_info, id))
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
            rrset_info_with_errors = filter(lambda x: name_obj.rrset_errors[x], dnskey.rrset_info)
            rrset_info_with_warnings = filter(lambda x: name_obj.rrset_warnings[x], dnskey.rrset_info)
            #XXX where do we put non-responses (e.g., timeout, formerr, etc.)?

            img_str = ''
            if dnskey.errors or rrset_info_with_errors:
                img_str = '<IMG SRC="%s"/>' % ERROR_ICON
            elif dnskey.warnings or rrset_info_with_warnings:
                img_str = '<IMG SRC="%s"/>' % WARNING_ICON

            #XXX algorithms that aren't supported

            if img_str:
                label_str = u'<<TABLE BORDER="0" CELLPADDING="0"><TR><TD></TD><TD VALIGN="bottom"><FONT POINT-SIZE="%d" FACE="%s">DNSKEY</FONT></TD><TD VALIGN="bottom">%s</TD></TR><TR><TD COLSPAN="3" VALIGN="top"><FONT POINT-SIZE="%d">alg=%d, id=%d</FONT></TD></TR></TABLE>>' % \
                        (12, 'Helvetica', img_str, 10, dnskey.rdata.algorithm, dnskey.key_tag)
            else:
                label_str = u'<<FONT POINT-SIZE="%d" FACE="%s">DNSKEY</FONT><BR/><FONT POINT-SIZE="%d">alg=%d, id=%d</FONT>>' % \
                        (12, 'Helvetica', 10, dnskey.rdata.algorithm, dnskey.key_tag)

            attr = {'style': 'filled', 'fillcolor': '#ffffff' }
            if dnskey.rdata.flags & fmt.DNSKEY_FLAGS['SEP']:
                attr['fillcolor'] = 'lightgray'
            if dnskey.rdata.flags & fmt.DNSKEY_FLAGS['revoke']:
                attr['penwidth'] = '4.0'

            S, zone_node_str, zone_bottom_name, zone_top_name = self.get_zone(zone_obj.name)
            S.add_node(node_str, id=node_str, shape='ellipse', label=label_str, **attr)
            self.node_subgraph_name[node_str] = zone_top_name

            consolidate_clients = name_obj.single_client()
            dnskey_serialized = dnskey.serialize(consolidate_clients=consolidate_clients)

            #XXX move all this to a separate method
            if rrset_info_with_warnings:
                aggregate_warnings = {}
                for rrset_info in dnskey.rrset_info:
                    for warning in name_obj.rrset_warnings[rrset_info]:
                        if warning not in aggregate_warnings:
                            aggregate_warnings[warning] = set()
                        aggregate_warnings[warning].update(name_obj.rrset_warnings[rrset_info][warning])

                if 'warnings' not in dnskey_serialized:
                    dnskey_serialized['warnings'] = collections.OrderedDict()
                warnings = aggregate_warnings.keys()
                warnings.sort()
                for warning in warnings:
                    warning_str = Status.response_error_mapping[warning]
                    servers = tuple_to_dict(aggregate_warnings[warning])
                    if consolidate_clients:
                        servers = list(servers)
                        servers.sort()
                    dnskey_serialized['warnings'][warning_str] = servers

            if rrset_info_with_errors:
                aggregate_errors = {}
                for rrset_info in dnskey.rrset_info:
                    for error in name_obj.rrset_errors[rrset_info]:
                        if error not in aggregate_errors:
                            aggregate_errors[error] = set()
                        aggregate_errors[error].update(name_obj.rrset_errors[rrset_info][error])

                if 'errors' not in dnskey_serialized:
                    dnskey_serialized['errors'] = collections.OrderedDict()
                errors = aggregate_errors.keys()
                errors.sort()
                for error in errors:
                    error_str = Status.response_error_mapping[error]
                    servers = tuple_to_dict(aggregate_errors[error])
                    if consolidate_clients:
                        servers = list(servers)
                        servers.sort()
                    dnskey_serialized['errors'][error_str] = servers

            self.node_info[node_str] = [dnskey_serialized]
     
        return self.G.get_node(node_str)

    def add_dnskey_non_existent(self, name, zone, algorithm, key_tag):
        node_str = self.dnskey_node_str(0, name, algorithm, key_tag)

        if not self.G.has_node(node_str):
            label_str = u'<<FONT POINT-SIZE="%d" FACE="%s">DNSKEY</FONT><BR/><FONT POINT-SIZE="%d">alg=%d, id=%d</FONT>>' % \
                    (12, 'Helvetica', 10, algorithm, key_tag)

            attr = {'style': 'filled,dashed', 'fillcolor': '#ffffff' }

            S, zone_node_str, zone_bottom_name, zone_top_name = self.get_zone(zone)
            S.add_node(node_str, id=node_str, shape='ellipse', label=label_str, **attr)
            self.node_subgraph_name[node_str] = zone_top_name

            dnskey_meta = DNSKEYNonExistent(name, algorithm, key_tag)

            self.node_info[node_str] = [dnskey_meta.serialize()]

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
            if zone_obj.rrset_errors[ds_info]:
                img_str = '<IMG SRC="%s"/>' % ERROR_ICON
            elif zone_obj.rrset_warnings[ds_info]:
                img_str = '<IMG SRC="%s"/>' % WARNING_ICON
            #XXX where do we put non-responses (e.g., timeout, formerr, etc.)?

            attr = {'style': 'filled', 'fillcolor': '#ffffff' }
            if img_str:
                label_str = u'<<TABLE BORDER="0" CELLPADDING="0"><TR><TD></TD><TD VALIGN="bottom"><FONT POINT-SIZE="%d" FACE="%s">%s</FONT></TD><TD VALIGN="bottom">%s</TD></TR><TR><TD COLSPAN="3" VALIGN="top"><FONT POINT-SIZE="%d">digest alg%s=%s</FONT></TD></TR></TABLE>>' % \
                        (12, 'Helvetica', dns.rdatatype.to_text(rdtype), img_str, 10, plural, digest_str)
            else:
                label_str = u'<<FONT POINT-SIZE="%d" FACE="%s">%s</FONT><BR/><FONT POINT-SIZE="%d">digest alg%s=%s</FONT>>' % \
                        (12, 'Helvetica', dns.rdatatype.to_text(rdtype), 10, plural, digest_str)

            S, parent_node_str, parent_bottom_name, parent_top_name = self.get_zone(parent_obj.name)
            S.add_node(node_str, id=node_str, shape='ellipse', label=label_str, **attr)
            self.node_subgraph_name[node_str] = parent_top_name

            consolidate_clients = zone_obj.single_client()
            ds_serialized = [d.serialize(consolidate_clients=consolidate_clients) for d in ds_statuses]

            digest_algs = []
            digests = []
            for d in ds_serialized:
                digest_algs.append(d['rdata']['digest_type'])
                digests.append(d['rdata']['digest'])
            digest_algs.sort()
            digests.sort()
            consolidated_ds_serialized = ds_serialized[0]
            consolidated_ds_serialized['rdata']['digest_type'] = digest_algs
            consolidated_ds_serialized['rdata']['digest'] = digests

            #XXX move all this to a separate method
            if zone_obj.rrset_warnings[ds_info]:
                warnings_serialized = collections.OrderedDict()
                warnings = zone_obj.rrset_warnings[ds_info].keys()
                warnings.sort()
                for warning in warnings:
                    warning_str = Status.response_error_mapping[warning]
                    servers = tuple_to_dict(zone_obj.rrset_warnings[ds_info][warning])
                    if consolidate_clients:
                        servers = list(servers)
                        servers.sort()
                    warnings_serialized[warning_str] = servers
                if 'warnings' not in ds:
                    consolidated_ds_serialized['warnings'] = warnings_serialized
                else:
                    consolidated_ds_serialized['warnings'].update(warnings_serialized)

            if zone_obj.rrset_errors[ds_info]:
                errors_serialized = collections.OrderedDict()
                errors = zone_obj.rrset_errors[ds_info].keys()
                errors.sort()
                for error in errors:
                    error_str = Status.response_error_mapping[error]
                    servers = tuple_to_dict(zone_obj.rrset_errors[ds_info][error])
                    if consolidate_clients:
                        servers = list(servers)
                        servers.sort()
                    errors_serialized[error_str] = servers
                if 'errors' not in ds:
                    consolidated_ds_serialized['errors'] = errors_serialized
                else:
                    consolidated_ds_serialized['errors'].update(errors_serialized)

            self.node_info[node_str] = [consolidated_ds_serialized]

            self.G.add_edge(parent_bottom_name, node_str, style='invis', minlen='0')

            T, zone_node_str, zone_bottom_name, zone_top_name = self.get_zone(zone_obj.name)

            self.add_ds_map(name, node_str, ds_statuses, zone_obj, parent_obj)

        return self.G.get_node(node_str)

    def add_ds_map(self, name, ds_node, ds_statuses, zone_obj, parent_obj):
        rdtype = ds_statuses[0].ds_meta.rrset.rdtype
        ds_status = ds_statuses[0]

        if ds_status.validation_status == Status.DS_STATUS_VALID:
            line_color = COLORS['secure']
            line_style = 'solid'
        elif ds_status.validation_status == Status.DS_STATUS_INDETERMINATE_NO_DNSKEY:
            line_color = COLORS['unknown']
            line_style = 'dashed'
        elif ds_status.validation_status == Status.DS_STATUS_INDETERMINATE_UNKNOWN_ALGORITHM:
            line_color = COLORS['unknown']
            line_style = 'solid'
        elif ds_status.validation_status == Status.DS_STATUS_INVALID_DIGEST:
            line_color = COLORS['errors']
            line_style = 'solid'
        elif ds_status.validation_status == Status.DS_STATUS_INVALID:
            line_color = COLORS['errors']
            line_style = 'dashed'
        elif ds_status.validation_status == Status.DS_STATUS_MATCH_PRE_REVOKE:
            line_color = COLORS['warnings']
            line_style = 'dashed'

        if ds_status.dnskey is None:
            dnskey_node = self.add_dnskey_non_existent(zone_obj.name, zone_obj.name, ds_status.ds.algorithm, ds_status.ds.key_tag)
        else:
            dnskey_node = self.get_dnskey(self.id_for_dnskey(zone_obj.name, ds_status.dnskey.rdata), zone_obj.name, ds_status.dnskey.rdata.algorithm, ds_status.dnskey.key_tag)

        edge_id = 'digest-%s|%s|%s|%s' % (dnskey_node, ds_node, line_color.lstrip('#'), line_style)
        self.G.add_edge(dnskey_node, ds_node, id=edge_id, color=line_color, style=line_style, dir='back')

        self.node_info[edge_id] = [self.node_info[ds_node][0].copy()]
        self.node_info[edge_id][0]['description'] = 'Digest for %s' % (self.node_info[edge_id][0]['description'])

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
            if zone_obj.analysis_end is not None:
                label_str = u'<<TABLE BORDER="0"><TR><TD ALIGN="LEFT"><FONT POINT-SIZE="%d">%s</FONT></TD></TR><TR><TD ALIGN="LEFT"><FONT POINT-SIZE="%d">(%s)</FONT></TD></TR></TABLE>>' % \
                        (12, zone_obj, 10, fmt.datetime_to_str(zone_obj.analysis_end))
            else:
                label_str = u'<<FONT POINT-SIZE="%d">%s</FONT>>' % \
                        (12, zone_obj)
            S = self.G.add_subgraph(name=node_str, label=label_str, labeljust='l', penwidth='0.5')
            S.add_node(top_name, shape='point', style='invis')
            S.add_node(bottom_name, shape='point', style='invis')
            self.node_subgraph_name[top_name] = top_name

        return S, node_str, bottom_name, top_name

    def add_rrsig(self, rrsig_status, name_obj, signer_obj, signed_node, combine_edge_id=None):
        if rrsig_status.dnskey is None:
            dnskey_node = self.add_dnskey_non_existent(signer_obj.name, signer_obj.zone.name, rrsig_status.rrsig.algorithm, rrsig_status.rrsig.key_tag)
        else:
            dnskey_node = self.get_dnskey(self.id_for_dnskey(signer_obj.name, rrsig_status.dnskey.rdata), signer_obj.name, rrsig_status.dnskey.rdata.algorithm, rrsig_status.dnskey.key_tag)

        #XXX consider not adding icons if errors are apparent from color of line
        edge_label = ''
        if rrsig_status.errors:
            edge_label = u'<<TABLE BORDER="0"><TR><TD><IMG SRC="%s"/></TD></TR></TABLE>>' % ERROR_ICON
        elif rrsig_status.warnings:
            edge_label = u'<<TABLE BORDER="0"><TR><TD><IMG SRC="%s"/></TD></TR></TABLE>>' % WARNING_ICON

        if rrsig_status.validation_status == Status.RRSIG_STATUS_VALID:
            line_color = COLORS['secure']
            line_style = 'solid'
        elif rrsig_status.validation_status == Status.RRSIG_STATUS_INDETERMINATE_NO_DNSKEY:
            line_color = COLORS['unknown']
            line_style = 'dashed'
        elif rrsig_status.validation_status == Status.RRSIG_STATUS_INDETERMINATE_UNKNOWN_ALGORITHM:
            line_color = COLORS['unknown']
            line_style = 'solid'
        elif rrsig_status.validation_status == Status.RRSIG_STATUS_EXPIRED:
            line_color = COLORS['expired']
            line_style = 'solid'
        elif rrsig_status.validation_status == Status.RRSIG_STATUS_PREMATURE:
            line_color = COLORS['expired']
            line_style = 'solid'
        elif rrsig_status.validation_status == Status.RRSIG_STATUS_INVALID_SIG:
            line_color = COLORS['errors']
            line_style = 'solid'
        elif rrsig_status.validation_status == Status.RRSIG_STATUS_INVALID:
            line_color = COLORS['errors']
            line_style = 'dashed'
        elif rrsig_status.validation_status == Status.RRSIG_STATUS_MATCH_PRE_REVOKE:
            line_color = COLORS['warnings']
            line_style = 'dashed'

        #XXX cruft - is this needed? why?
        #if line_color == COLORS['secure'] and dnskey_node == signed_node and signer_obj.name == zone_obj.name:
        #    S, zone_node_str, zone_bottom_name, zone_top_name = self.get_zone(signer_obj.name)

        if combine_edge_id is not None:
            edge_id = 'RRSIG-%s|%s|%d|%s' % (signed_node.replace('*', '_'), dnskey_node, combine_edge_id, line_style)
            edge_key = '%d-%s' % (combine_edge_id, line_style)
            try:
                edge = self.G.get_edge(signed_node, dnskey_node, edge_key)
                if line_color != COLORS['secure']:
                    edge.attr['color'] = line_color
            except KeyError:
                self.G.add_edge(signed_node, dnskey_node, label=edge_label, key=edge_key, id=edge_id, color=line_color, style=line_style, dir='back')
        else:
            edge_id = 'RRSIG-%s|%s|%s|%s' % (signed_node.replace('*', '_'), dnskey_node, line_color.lstrip('#'), line_style)
            edge_key = '%s-%s' % (line_color, line_style)
            try:
                edge = self.G.get_edge(signed_node, dnskey_node, edge_key)
            except KeyError:
                self.G.add_edge(signed_node, dnskey_node, label=edge_label, key=edge_key, id=edge_id, color=line_color, style=line_style, dir='back')

        consolidate_clients = name_obj.single_client()
        rrsig_serialized = rrsig_status.serialize(consolidate_clients=consolidate_clients)

        if edge_id not in self.node_info:
            self.node_info[edge_id] = [rrsig_serialized]
        else:
            self.node_info[edge_id].append(rrsig_serialized)

    def rrset_node_str(self, name, rdtype, id):
        return 'RRset-%d|%s|%s' % (id, fmt.humanize_name(name), dns.rdatatype.to_text(rdtype))

    def has_rrset(self, name, rdtype, id):
        return self.G.has_node(self.rrset_node_str(name, rdtype, id))

    def get_rrset(self, name, rdtype, id):
        return self.G.get_node(self.rrset_node_str(name, rdtype, id))

    def add_rrset(self, rrset_info, wildcard_name, name_obj, id):
        zone_obj = name_obj.zone
        name = wildcard_name or rrset_info.rrset.name
        node_str = self.rrset_node_str(name, rrset_info.rrset.rdtype, id)

        if not self.G.has_node(node_str):
            img_str = ''
            if name_obj.rrset_errors[rrset_info]:
                img_str = '<IMG SRC="%s"/>' % ERROR_ICON
            elif name_obj.rrset_warnings[rrset_info]:
                img_str = '<IMG SRC="%s"/>' % WARNING_ICON

            if img_str:
                node_label = u'<<TABLE BORDER="0" CELLPADDING="0"><TR><TD><FONT POINT-SIZE="%d" FACE="%s">%s/%s</FONT></TD></TR><TR><TD>%s</TD></TR></TABLE>>' % \
                        (12, 'Helvetica', fmt.humanize_name(name, True), dns.rdatatype.to_text(rrset_info.rrset.rdtype), img_str)
            else:
                node_label = u'<<FONT POINT-SIZE="%d" FACE="%s">%s/%s</FONT>>' % \
                        (12, 'Helvetica', fmt.humanize_name(name, True), dns.rdatatype.to_text(rrset_info.rrset.rdtype))

            attr = {}
            attr['shape'] = 'rectangle'
            attr['style'] = 'rounded,filled'
            attr['fillcolor'] = '#ffffff'

            node_id = node_str.replace('*', '_')
            S, zone_node_str, zone_bottom_name, zone_top_name = self.get_zone(zone_obj.name)
            S.add_node(node_str, id=node_id, label=node_label, fontsize='10', **attr)
            self.node_subgraph_name[node_str] = zone_top_name

            consolidate_clients = name_obj.single_client()
            rrset_serialized = rrset_info.serialize(consolidate_clients=consolidate_clients)
            
            if name_obj.rrset_warnings[rrset_info]:
                warnings_serialized = collections.OrderedDict()
                warnings = name_obj.rrset_warnings[rrset_info].keys()
                warnings.sort()
                for warning in warnings:
                    warning_str = Status.response_error_mapping[warning]
                    servers = tuple_to_dict(name_obj.rrset_warnings[rrset_info][warning])
                    if consolidate_clients:
                        servers = list(servers)
                        servers.sort()
                    warnings_serialized[warning_str] = servers
                if 'warnings' not in rrset_serialized:
                    rrset_serialized['warnings'] = warnings_serialized
                else:
                    rrset_serialized['warnings'].update(warnings_serialized)

            if name_obj.rrset_errors[rrset_info]:
                errors_serialized = collections.OrderedDict()
                errors = name_obj.rrset_errors[rrset_info].keys()
                errors.sort()
                for error in errors:
                    error_str = Status.response_error_mapping[error]
                    servers = tuple_to_dict(name_obj.rrset_errors[rrset_info][error])
                    if consolidate_clients:
                        servers = list(servers)
                        servers.sort()
                    errors_serialized[error_str] = servers
                if 'errors' not in rrset_serialized:
                    rrset_serialized['errors'] = errors_serialized
                else:
                    rrset_serialized['errors'].update(errors_serialized)

            self.node_info[node_id] = [rrset_serialized]
            self.G.add_edge(zone_bottom_name, node_str, style='invis', minlen='0')

        return self.G.get_node(node_str)

    def add_rrset_non_existent(self, name_obj, name, rdtype, nxdomain, wildcard, servers_clients):
        zone_obj = name_obj.zone
        if nxdomain:
            node_str = self.rrset_node_str(name, rdtype, 0)
        else:
            node_str = self.rrset_node_str(name, rdtype, 1)

        if not self.G.has_node(node_str):
            if wildcard:
                warnings_map = errors_map = {}
            else:
                if nxdomain:
                    warnings_map = name_obj.nxdomain_warnings[(name,rdtype)]
                    errors_map = name_obj.nxdomain_errors[(name,rdtype)]
                else:
                    warnings_map = name_obj.noanswer_warnings[(name,rdtype)]
                    errors_map = name_obj.noanswer_errors[(name,rdtype)]

            img_str = ''
            if errors_map:
                img_str = '<IMG SRC="%s"/>' % ERROR_ICON
            elif warnings_map:
                img_str = '<IMG SRC="%s"/>' % WARNING_ICON

            if img_str:
                node_label = u'<<TABLE BORDER="0" CELLPADDING="0"><TR><TD><FONT POINT-SIZE="%d" FACE="%s">%s/%s</FONT></TD></TR><TR><TD>%s</TD></TR></TABLE>>' % \
                        (12, 'Helvetica', fmt.humanize_name(name, True), dns.rdatatype.to_text(rdtype), img_str)
            else:
                node_label = u'<<FONT POINT-SIZE="%d" FACE="%s">%s/%s</FONT>>' % \
                        (12, 'Helvetica', fmt.humanize_name(name, True), dns.rdatatype.to_text(rdtype))

            attr = {}
            attr['shape'] = 'rectangle'
            attr['style'] = 'rounded,filled,dashed'
            if nxdomain:
                attr['style'] += ',diagonals'
            attr['fillcolor'] = '#ffffff'

            node_id = node_str.replace('*', '_')
            S, zone_node_str, zone_bottom_name, zone_top_name = self.get_zone(zone_obj.name)
            S.add_node(node_str, id=node_id, label=node_label, fontsize='10', **attr)
            self.node_subgraph_name[node_str] = zone_top_name

            rrset_info = RRsetNonExistent(name, rdtype, servers_clients)

            consolidate_clients = name_obj.single_client()
            rrset_serialized = rrset_info.serialize(consolidate_clients=consolidate_clients)

            if warnings_map:
                if 'warnings' not in rrset_serialized:
                    rrset_serialized['warnings'] = collections.OrderedDict()
                warnings = warnings_map.keys()
                warnings.sort()
                for warning in warnings:
                    servers = tuple_to_dict(warnings_map[warning])
                    if consolidate_clients:
                        servers = list(servers)
                        servers.sort()
                    rrset_serialized['warnings'][Status.response_error_mapping[warning]] = servers

            if errors_map:
                if 'errors' not in rrset_serialized:
                    rrset_serialized['errors'] = collections.OrderedDict()
                errors = errors_map.keys()
                errors.sort()
                for error in errors:
                    servers = tuple_to_dict(errors_map[error])
                    if consolidate_clients:
                        servers = list(servers)
                        servers.sort()
                    rrset_serialized['errors'][Status.response_error_mapping[error]] = servers

            self.node_info[node_id] = [rrset_serialized]
            self.G.add_edge(zone_bottom_name, node_str, style='invis', minlen='0')

        return self.G.get_node(node_str)

    def add_dname(self, dname_status, name_obj, id):
        zone_obj = name_obj.zone
        dname_rrset_info = dname_status.synthesized_cname.dname_info
        dname_node = self.add_rrset(dname_rrset_info, None, name_obj, id)

        if dname_status.validation_status == Status.DNAME_STATUS_VALID:
            line_color = COLORS['secure']
            line_style = 'solid'
        elif dname_status.validation_status == Status.DNAME_STATUS_INDETERMINATE:
            line_color = COLORS['unknown']
            line_style = 'solid'
        elif dname_status.validation_status == Status.DNAME_STATUS_INVALID:
            line_color = COLORS['errors']
            line_style = 'solid'

        if dname_status.included_cname is None:
            cname_node = self.add_rrset_non_existent(name_obj, dname_status.synthesized_cname.rrset.name, dns.rdatatype.CNAME, True, dname_status.synthesized_cname.servers_clients)
        else:
            cname_node = self.add_rrset(dname_status.included_cname, None, name_obj, id)

        edge_id = 'dname-%s|%s|%s|%s' % (cname_node, dname_node, line_color.lstrip('#'), line_style)
        edge_key = '%s-%s' % (line_color, line_style)
        try:
            edge = self.G.get_edge(cname_node, dname_node, edge_key)
        except KeyError:
            edge_label = ''
            if dname_status.errors:
                edge_label = u'<<TABLE BORDER="0"><TR><TD><IMG SRC="%s"/></TD></TR></TABLE>>' % ERROR_ICON
            elif dname_status.warnings:
                edge_label = u'<<TABLE BORDER="0"><TR><TD><IMG SRC="%s"/></TD></TR></TABLE>>' % WARNING_ICON

            self.G.add_edge(cname_node, dname_node, label=edge_label, key=edge_key, id=edge_id, color=line_color, style=line_style, dir='back')
            self.node_info[edge_id] = [dname_status.serialize()]

        self.add_rrsigs(name_obj, zone_obj, dname_rrset_info, dname_node)

        return cname_node

    def nsec_node_str(self, nsec_rdtype, id, name, rdtype):
        return '%s-%d|%s|%s' % (dns.rdatatype.to_text(nsec_rdtype), id, fmt.humanize_name(name), dns.rdatatype.to_text(rdtype))

    def has_nsec(self, nsec_rdtype, id, name, rdtype):
        return self.G.has_node(self.nsec_node_str(nsec_rdtype, id, name, rdtype))

    def get_nsec(self, nsec_rdtype, id, name, rdtype):
        return self.G.get_node(self.nsec_node_str(nsec_rdtype, id, name, rdtype))

    def add_nsec(self, nsec_status, name, rdtype, zone_obj, covered_node):
        if nsec_status.nsec_set_info.use_nsec3:
            nsec_rdtype = dns.rdatatype.NSEC3
        else:
            nsec_rdtype = dns.rdatatype.NSEC
        node_str = self.nsec_node_str(nsec_rdtype, self.id_for_nsec(name, rdtype, nsec_status.nsec_set_info), name, rdtype)

        if not self.G.has_node(node_str):
            img_str = None
            if img_str:
                label_str = u'<<TABLE BORDER="0" CELLPADDING="0"><TR><TD><FONT POINT-SIZE="%d" FACE="%s">%s</FONT></TD></TR><TR><TD>%s</TD></TR></TABLE>>' % \
                        (12, 'Helvetica', dns.rdatatype.to_text(nsec_rdtype), img_str)
            else:
                label_str = u'<<FONT POINT-SIZE="%d" FACE="%s">%s</FONT>>' % \
                        (12, 'Helvetica', dns.rdatatype.to_text(nsec_rdtype))

            attr = {}
            attr['shape'] = 'diamond'
            attr['style'] = 'filled'
            attr['fillcolor'] = '#ffffff'

            S, zone_node_str, zone_bottom_name, zone_top_name = self.get_zone(zone_obj.name)
            S.add_node(node_str, id=node_str, label=label_str, **attr)
            self.node_subgraph_name[node_str] = zone_top_name

            self.node_info[node_str] = [nsec_status.serialize()]

        nsec_node = self.G.get_node(node_str)

        if nsec_status.validation_status == Status.NSEC_STATUS_VALID:
            line_color = COLORS['secure']
            line_style = 'solid'
        elif nsec_status.validation_status == Status.NSEC_STATUS_INDETERMINATE:
            line_color = COLORS['unknown']
            line_style = 'solid'
        elif nsec_status.validation_status == Status.NSEC_STATUS_INVALID:
            line_color = COLORS['bogus']
            line_style = 'solid'

        edge_label = ''
        edge_id = '%sC-%s|%s' % (dns.rdatatype.to_text(nsec_rdtype), covered_node.replace('*', '_'), node_str)
        self.G.add_edge(covered_node, nsec_node, label=edge_label, id=edge_id, color=line_color, style=line_style, dir='back')

        self.node_info[edge_id] = [self.node_info[nsec_node][0].copy()]
        self.node_info[edge_id][0]['description'] = 'Non-existence proof provided by %s' % (self.node_info[edge_id][0]['description'])

        return nsec_node

    def add_wildcard(self, name_obj, rrset_info, nsec_status, wildcard_name, id):
        zone_obj = name_obj.zone

        wildcard_node = self.add_rrset(rrset_info, wildcard_name, name_obj, id)
        self.add_rrsigs(name_obj, zone_obj, rrset_info, wildcard_node)
        nxdomain_node = self.add_rrset_non_existent(name_obj, rrset_info.rrset.name, rrset_info.rrset.rdtype, True, True, rrset_info.servers_clients)

        if nsec_status is not None:
            nsec_node = self.add_nsec(nsec_status, rrset_info.rrset.name, rrset_info.rrset.rdtype, zone_obj, nxdomain_node)
            for rrset_info in nsec_status.nsec_set_info.rrsets.values():
                self.add_rrsigs(name_obj, zone_obj, rrset_info, nsec_node, combine_edge_id=id)

        return wildcard_node

        #XXX consider adding this node (using, e.g., clustering)
        #rrset_node = self.add_rrset(rrset_info, None, zone_obj, id)
        #self.G.add_edge(rrset_node, nxdomain_node, color=COLORS['secure'], style='solid', dir='back')
        #self.G.add_edge(rrset_node, wildcard_node, color=COLORS['secure'], style='solid', dir='back')
        #return rrset_node

    def add_alias(self, alias, target):
        if not filter(lambda x: x[1] == target and x.attr['color'] == 'black', self.G.out_edges(alias)):
            #self.G.add_edge(alias, target, color='black', constraint='false')
            self.G.add_edge(alias, target, color='black')

    def add_rrsigs(self, name_obj, zone_obj, rrset_info, signed_node, combine_edge_id=None):
        for rrsig in name_obj.rrsig_status[rrset_info]:
            signer_obj = name_obj.get_name(rrsig.signer)
            if rrsig.signer != zone_obj.name:
                self.graph_zone_auth(signer_obj, False)
            for dnskey in name_obj.rrsig_status[rrset_info][rrsig]:
                rrsig_status = name_obj.rrsig_status[rrset_info][rrsig][dnskey]
                self.add_rrsig(rrsig_status, name_obj, signer_obj, signed_node, combine_edge_id=combine_edge_id)

    def graph_rrset_auth(self, name_obj, name, rdtype):
        if (name, rdtype) in self.processed_rrsets:
            return self.processed_rrsets[(name, rdtype)]
        my_nodes_all = self.processed_rrsets[(name, rdtype)] = []

        assert rdtype not in (dns.rdatatype.DNSKEY, dns.rdatatype.DLV, dns.rdatatype.DS, dns.rdatatype.NSEC, dns.rdatatype.NSEC3)

        zone_obj = name_obj.zone

        # graph the parent
        self.graph_zone_auth(zone_obj, False)

        S, zone_graph_name, zone_bottom, zone_top = self.add_zone(zone_obj)

        id = 10
        for rrset_info in name_obj.queries[(name, rdtype)].rrset_answer_info:
            my_nodes = []
            cnames = []

            # only do qname
            if rrset_info.rrset.name != name:
                continue

            if rrset_info.rrset.rdtype == dns.rdatatype.CNAME:
                cnames.append(rrset_info.rrset[0].target)

            #XXX can we combine multiple DNAMEs into one?
            #XXX can we combine multiple NSEC(3) into a cluster?
            #XXX can we combine wildcard components into a cluster?
            if rrset_info in name_obj.dname_status:
                for dname_status in name_obj.dname_status[rrset_info]:
                    my_nodes.append(self.add_dname(dname_status, name_obj, id))
                    id += 1
            elif rrset_info.wildcard_info:
                for wildcard_name in rrset_info.wildcard_info:
                    if rrset_info.rrset.name not in name_obj.wildcard_status:
                        my_nodes.append(self.add_wildcard(name_obj, rrset_info, None, wildcard_name, id))
                        id += 1
                    else:
                        for nsec_status in name_obj.wildcard_status[rrset_info.rrset.name][wildcard_name]:
                            my_nodes.append(self.add_wildcard(name_obj, rrset_info, nsec_status, nsec_status.wildcard_name, id))
                            id += 1
            else:
                rrset_node = self.add_rrset(rrset_info, None, name_obj, id)
                self.add_rrsigs(name_obj, zone_obj, rrset_info, rrset_node)
                my_nodes.append(rrset_node)
                id += 1

            my_nodes_all += my_nodes

            for cname in cnames:
                cname_obj = name_obj.get_name(cname)
                # cname_obj might be None, if analysis did not follow it (e.g.,
                # for random names)
                if cname_obj is None:
                    continue
                cname_nodes = self.graph_rrset_auth(cname_obj, cname, rdtype)
                for my_node in my_nodes:
                    for cname_node in cname_nodes:
                        self.add_alias(my_node, cname_node)

        if (name, rdtype) in name_obj.nxdomain_servers_clients:
            nxdomain_node = self.add_rrset_non_existent(name_obj, name, rdtype, True, False, name_obj.nxdomain_servers_clients[(name,rdtype)])
            my_nodes_all.append(nxdomain_node)
            if (name, rdtype) in name_obj.nxdomain_status:
                for nsec_status in name_obj.nxdomain_status[(name,rdtype)]:
                    nsec_node = self.add_nsec(nsec_status, name, rdtype, zone_obj, nxdomain_node)
                    for rrset_info in nsec_status.nsec_set_info.rrsets.values():
                        self.add_rrsigs(name_obj, zone_obj, rrset_info, nsec_node, combine_edge_id=id)

        if (name,rdtype) in name_obj.noanswer_servers_clients:
            noanswer_node = self.add_rrset_non_existent(name_obj, name, rdtype, False, False, name_obj.noanswer_servers_clients[(name,rdtype)])
            my_nodes_all.append(noanswer_node)
            if (name,rdtype) in name_obj.noanswer_status:
                for nsec_status in name_obj.noanswer_status[(name,rdtype)]:
                    nsec_node = self.add_nsec(nsec_status, name, rdtype, zone_obj, noanswer_node)
                    for rrset_info in nsec_status.nsec_set_info.rrsets.values():
                        self.add_rrsigs(name_obj, zone_obj, rrset_info, nsec_node, combine_edge_id=id)

        return my_nodes_all

    def graph_zone_auth(self, name_obj, is_dlv):
        if (name_obj.name, -1) in self.processed_rrsets:
            return
        self.processed_rrsets[(name_obj.name, -1)] = True

        zone_obj = name_obj.zone
        S, zone_graph_name, zone_bottom, zone_top = self.add_zone(zone_obj)

        if zone_obj.stub:
            return

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
                if rrsig.signer != name_obj.name:
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
                ds_statuses = name_obj.ds_status_by_dnskey[rdtype][dnskey].values()

                # identify all validation_status/RRset/algorithm/key_tag
                # combinations, so we can cluster like DSs
                validation_statuses = set([(d.validation_status, d.ds_meta, d.ds.algorithm, d.ds.key_tag) for d in ds_statuses])

                for validation_status, rrset_info, algorithm, key_tag in validation_statuses:
                    ds_status_subset = filter(lambda x: x.validation_status == validation_status and x.ds_meta is rrset_info and x.ds.algorithm == algorithm and x.ds.key_tag == key_tag, ds_statuses)

                    # create the DS node and edge
                    ds_node = self.add_ds(ds_name, ds_status_subset, name_obj, parent_obj)

                    self.add_rrsigs(name_obj, parent_obj, rrset_info, ds_node)

            edge_id = 0
            for nsec_status in name_obj.noanswer_status.get((ds_name, rdtype), []):
                nsec_node = self.add_nsec(nsec_status, ds_name, rdtype, parent_obj, zone_top)
                # add a tail to the cluster
                self.G.get_edge(zone_top, nsec_node).attr['ltail'] = zone_graph_name
                # anchor NSEC node to bottom
                self.G.add_edge(zone_bottom, nsec_node, style='invis', minlen='0')

                for rrset_info in nsec_status.nsec_set_info.rrsets.values():
                    self.add_rrsigs(name_obj, parent_obj, rrset_info, nsec_node, combine_edge_id=edge_id)

                edge_id += 1

            edge_label = ''
            if name_obj.delegation_errors[rdtype]:
                edge_label = u'<<TABLE BORDER="0"><TR><TD><IMG SRC="%s"/></TD></TR></TABLE>>' % ERROR_ICON
            elif name_obj.delegation_warnings[rdtype]:
                edge_label = u'<<TABLE BORDER="0"><TR><TD><IMG SRC="%s"/></TD></TR></TABLE>>' % WARNING_ICON

            if name_obj.delegation_status[rdtype] == Status.DELEGATION_STATUS_SECURE:
                line_color = COLORS['secure']
                line_style = 'solid'
            elif name_obj.delegation_status[rdtype] == Status.DELEGATION_STATUS_INSECURE:
                line_color = COLORS['insecure']
                line_style = 'solid'
            elif name_obj.delegation_status[rdtype] in (Status.DELEGATION_STATUS_INCOMPLETE, Status.DELEGATION_STATUS_LAME):
                line_color = COLORS['warnings']
                line_style = 'dashed'
            elif name_obj.delegation_status[rdtype] == Status.DELEGATION_STATUS_BOGUS:
                line_color = COLORS['bogus']
                line_style = 'dashed'

            consolidate_clients = name_obj.single_client()
            del_serialized = collections.OrderedDict()
            del_serialized['description'] = 'Delegation from %s to %s' % (name_obj.parent.name.to_text(), name_obj.name.to_text())
            del_serialized['status'] = Status.delegation_status_mapping[name_obj.delegation_status[rdtype]]
            if name_obj.delegation_warnings[rdtype]:
                del_serialized['warnings'] = collections.OrderedDict()
                warnings = name_obj.delegation_warnings[rdtype].keys()
                warnings.sort()
                for warning in warnings:
                    servers = tuple_to_dict(name_obj.delegation_warnings[rdtype][warning])
                    if consolidate_clients:
                        servers = list(servers)
                        servers.sort()
                    del_serialized['warnings'][Status.delegation_error_mapping[warning]] = servers

            if name_obj.delegation_errors[rdtype]:
                del_serialized['errors'] = collections.OrderedDict()
                errors = name_obj.delegation_errors[rdtype].keys()
                errors.sort()
                for error in errors:
                    servers = tuple_to_dict(name_obj.delegation_errors[rdtype][error])
                    if consolidate_clients:
                        servers = list(servers)
                        servers.sort()
                    del_serialized['errors'][Status.delegation_error_mapping[error]] = servers

            edge_id = 'del-%s|%s' % (fmt.humanize_name(zone_obj.name), fmt.humanize_name(parent_obj.name))
            self.node_info[edge_id] = [del_serialized]
            self.G.add_edge(zone_top, parent_bottom, label=edge_label, id=edge_id, color=line_color, penwidth='5.0', ltail=zone_graph_name, lhead=parent_graph_name, style=line_style, minlen='2', dir='back')

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
            if not self.G.has_node(zone_top_name):
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
            if self.has_zone(zone):
                zone_node_str = self.zone_node_str(zone)
                # don't yet mark subdomains of DLV zones, as we have yet
                # to add trust to them
                if '%s_top' % zone_node_str not in dlv_trusted_zone_top_names:
                    self._add_trust_to_orphaned_nodes(zone_node_str, [])

        # now that we can show which zones are provably insecure, we
        # can apply trust from the DLV zones
        for dlv_node in dlv_nodes:
            self._add_trust_to_nodes_in_chain(dlv_node, trusted_zone_top_names, [], True, [])
            node_str = self.node_subgraph_name[dlv_node][:-4]
            self._add_trust_to_orphaned_nodes(node_str, [])

        for n in self.G.nodes():
            if n.attr['shape'] not in ('ellipse', 'diamond', 'rectangle'):
                continue

            style = n.attr['style'].split(',')

            if n.attr['color'] == COLORS['secure']:
                status = Status.RRSET_STATUS_SECURE
            elif n.attr['color'] == COLORS['bogus']:
                status = Status.RRSET_STATUS_BOGUS
            elif 'dashed' in style:
                status = Status.RRSET_STATUS_NON_EXISTENT
            else:
                status = Status.RRSET_STATUS_INSECURE

            node_id = n.replace('*', '_')
            for serialized in self.node_info[node_id]:
                serialized['status'] = Status.rrset_status_mapping[status]

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
                        break

            #XXX revisit if we want to do this here
            if is_revoked and n.attr['color'] == COLORS['secure'] and not valid_self_loop:
                n.attr['color'] = COLORS['bogus'] 

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

        for e in self.G.in_edges(n):
            p = e[0]

            style = e.attr['style'].split(',')
            # if this is the edge to a non-existent key, then don't follow it
            if 'dashed' in style or 'invis' in style: 
                continue

            prev_top_name = self.G.get_node(self.node_subgraph_name[p])
            # don't derive trust from parent if there is a trust anchor at the
            # child
            if is_ds and prev_top_name in trusted_zones:
                continue

            if p.attr['color'] == COLORS['secure']:
                continue

            prev_node_trusted = node_trusted and e.attr['color'] == COLORS['secure']

            # If this is a SEP node, and the top_name hasn't been
            # marked as secure, then enter here
            if is_ds:

                # if this is a DLV node, then the zone it covers must be marked
                # as insecure through previous trust traversal (not because of
                # a local trust anchor, which case is handled above)
                if is_dlv and prev_top_name.attr['color'] != COLORS['insecure']:
                    continue

                if prev_top_name.attr['color'] != COLORS['secure']:
                    prev_top_name.attr['color'] = ''

                valid_self_loop = False
                if self.G.has_edge(p,p):
                    for e1 in self.G.out_edges(p) + self.G.in_edges(p):
                        if (p,p) == e1 and \
                                e1.attr['color'] == COLORS['secure']:
                            valid_self_loop = True
                            break

                prev_node_trusted = prev_node_trusted and valid_self_loop

            if is_nsec:
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

        if top_name.attr['color'] == COLORS['insecure']:
            return

        S = self.G.get_subgraph(subgraph_name)
        for n in S.nodes():
            style = n.attr['style'].split(',')
            # if node is non-existent, then continue, unless we are talking about an RRset
            # or a non-existent trust anchor; it doesn't make sense to mark other nodes
            # as bogus
            if 'dashed' in style and not (n.attr['shape'] == 'rectangle' or \
                    n.attr['peripheries'] == 2):
                continue

            # if the name is already marked as trusted or bogus, then leave it alone
            if n.attr['color'] == COLORS['secure']:
                continue

            n.attr['color'] = COLORS['bogus']

        for p in self.G.predecessors(bottom_name):
            e = self.G.get_edge(p, bottom_name)
            if top_name.attr['color'] == COLORS['secure']:
                if e.attr['color'] == COLORS['secure']:
                    p.attr['color'] = COLORS['secure']
                elif e.attr['color'] != COLORS['bogus']:
                    p.attr['color'] = COLORS['insecure']

            child_subgraph_name = p[:-4]

            self._add_trust_to_orphaned_nodes(child_subgraph_name, trace+[subgraph_name])

    def remove_extra_edges(self, show_redundant=False):
        #XXX this assumes DNSKEYs with same name as apex
        for S in self.G.subgraphs():
            all_dnskeys = set()
            ds_dnskeys = set()
            ta_dnskeys = set()
            ksks = set()
            zsks = set()
            revoked_dnskeys = set()
            non_existent_dnskeys = set()
            signing_keys_for_dnskey = {}

            for n in S.nodes():
                if not n.startswith('DNSKEY-'):
                    continue

                all_dnskeys.add(n)

                in_edges = self.G.in_edges(n)
                out_edges = self.G.out_edges(n)
                signing_keys_for_dnskey[n] = set([x[1] for x in out_edges if x[1].startswith('DNSKEY-')])
                ds_edges = filter(lambda x: x[1].startswith('DS-') or x[1].startswith('DLV-'), out_edges)

                is_ksk = bool(filter(lambda x: x[0].startswith('DNSKEY-'), in_edges))
                is_zsk = bool(filter(lambda x: not x[0].startswith('DNSKEY-'), in_edges))
                style = n.attr['style'].split(',')
                non_existent = 'dashed' in style

                if is_ksk:
                    ksks.add(n)
                if is_zsk:
                    zsks.add(n)
                if n.attr['peripheries'] == '2':
                    ta_dnskeys.add(n)
                if ds_edges:
                    ds_dnskeys.add(n)
                if n.attr['penwidth'] == '4.0':
                    revoked_dnskeys.add(n)
                if non_existent:
                    non_existent_dnskeys.add(n)
                
            seps = ds_dnskeys.union(ta_dnskeys).intersection(ksks).difference(revoked_dnskeys)
            ksk_only = ksks.difference(zsks).difference(revoked_dnskeys)
            zsk_only = zsks.difference(revoked_dnskeys)
            if seps:
                signing_keys = seps
            else:
                if ksk_only:
                    signing_keys = ksk_only
                else:
                    signing_keys = ksks

            for n in signing_keys.union(ds_dnskeys):
                if not (n in zsk_only and ksk_only):
                    self.G.add_edge(n, self.node_subgraph_name[n], style='invis', minlen='0')

            for n in non_existent_dnskeys.intersection(ta_dnskeys):
                self.G.add_edge(n, self.node_subgraph_name[n], style='invis', minlen='0')

            for n in ksks:
                n_is_signing_key = n in signing_keys
                n_is_ksk = n in ksk_only

                retain_edge_default = n_is_signing_key or \
                        (n_is_ksk and not signing_keys_for_dnskey[n].intersection(seps))

                for e in self.G.in_edges(n):
                    m = e[0]
                    if not m.startswith('DNSKEY-'):
                        continue
                    if n == m:
                        continue

                    retain_edge = retain_edge_default

                    if retain_edge:
                        m_is_signing_key = m in signing_keys
                        m_is_zsk = m in zsk_only
                        if m_is_signing_key and not (m_is_zsk and n_is_ksk):
                            retain_edge = False

                    if not retain_edge:
                        if show_redundant:
                            self.G.get_edge(m, n).attr['contrain'] = 'false'
                        else:
                            try:
                                del self.node_info[e.attr.get('id', None)]
                            except KeyError:
                                pass
                            self.G.remove_edge(m, n)
