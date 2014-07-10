#!/usr/bin/env python
#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Author: Casey Deccio (ctdecci@sandia.gov)
#
# Copyright 2012-2013 Sandia Corporation. Under the terms of Contract
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

import datetime
import re
import sys
import xml.dom.minidom

import dns.name, dns.rdtypes, dns.rdatatype, dns.dnssec

from pygraphviz import AGraph

from django.conf import settings
from django.utils import simplejson
from django.utils.html import escape

from dnsviz import util

COLORS = { 'secure': '#0a879a', 'secure_light': '#8ffeff',
        'bogus': '#be1515', 'bogus_light': '#f17b7b',
        'insecure': '#000000', 'insecure_light': '#b7b7b7',
        'expired': '#6131a3', 'expired_light': '#ad7fed',
        'misconfigured': '#f4b800', 'misconfigured_light': '#fffa8f',
        'warnings': '#f4b800', 'warnings_light': '#fffa8f',
        'unknown': '#f4b800', 'unknown_light': '#fffa8f',
        'errors': '#be1515', 'errors_light': '#f17b7b' }

class DNSAuthGraph:
    def __init__(self, show_dlv, trusted_keys, trusted_zones, dnssec_algorithms, ds_algorithms, static_base=settings.STATIC_URL, updated=None, page_url=None):
        self.show_dlv = show_dlv
        self.trusted_keys = trusted_keys
        self.trusted_zones = trusted_zones

        self.dnssec_algorithms = dnssec_algorithms
        self.ds_algorithms = ds_algorithms

        self.static_base = static_base
        self.updated = updated
        self.page_url = page_url

        self.G = AGraph(directed=True, strict=False, compound='true', rankdir='BT', ranksep='0.3')

        self.G.node_attr['penwidth'] = '1.5'
        self.G.edge_attr['penwidth'] = '1.5'
        self.node_info = {}
        self.init_notices()
        self.node_subgraph_name = {}
        self.processed_rrsets = {}
        self.processed_nodes = {}

        self.dnskey_ids = {}
        self.ds_ids = {}
        self.nsec_ids = {}
        self.next_dnskey_id = 0
        self.next_ds_id = 0
        self.next_nsec_id = 0
        self.ds_algs = {}
        self.dnskey_algs_by_zone = {}
        self.valid_self_sign_algs = {}

    def init_notices(self):
        self.notices = {}
        for n in 'delegation status', 'DNSKEY/DS/NSEC status', 'notices', 'RRset status':
            self.notices[n] = {}

        self.notices['delegation status'] = { 'secure': set(), 'bogus': set(), 'insecure': set(), 'misconfigured': set() }
        self.notices['notices'] = { 'errors': set(), 'warnings': set(), 'RRSIG expirations': set() }
        self.notices['DNSKEY/DS/NSEC status'] = { 'secure': set(), 'bogus': set(), 'insecure': set(), 'non-existent': set() }
        self.notices['RRset status'] = { 'secure': set(), 'bogus': set(), 'insecure': set(), 'non-existent': set() }

    def serializable_notices(self):
        serializable = {}
        for cat in self.notices:
            serializable[cat] = {}
            for subcat in self.notices[cat]:
                serializable[cat][subcat] = list(self.notices[cat][subcat])
                serializable[cat][subcat].sort()
                if not serializable[cat][subcat]:
                    del serializable[cat][subcat]
            if not serializable[cat]:
                del serializable[cat]
                    
        return serializable

    def ordered_notices(self):
        formatted = []
        notices = self.serializable_notices()
        for cat in ('RRset status', 'DNSKEY/DS/NSEC status', 'delegation status', 'notices'):
            subcat_lists = []
            for subcat in ('bogus','errors','RRSIG expirations','warnings','misconfigured','secure','insecure','non-existent'):
                try:
                    items = list(notices[cat][subcat])
                    items.sort()
                    subcat_lists.append((subcat, items))
                except KeyError:
                    pass
            if subcat_lists:
                formatted.append((cat, subcat_lists))
        return formatted

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
            s += '\tthis.paper = Raphael(this.anchorElement, parseInt(paperScale*imageWidth), parseInt(paperScale*imageHeight));\n'
        else:
            if node.nodeName == 'path':
                s += '\tel = this.paper.path(\'%s\')' % node.getAttribute('d')
            elif node.nodeName == 'ellipse':
                s += '\tel = this.paper.ellipse(%s, %s, %s, %s)' % (node.getAttribute('cx'), node.getAttribute('cy'),
                        node.getAttribute('rx'), node.getAttribute('ry'))
            elif node.nodeName == 'text':
                if node.childNodes:
                    text = node.childNodes[0].nodeValue
                else:
                    text = ''
                s += '\tel = this.paper.text(%s, %s, \'%s\')' % (node.getAttribute('x'), node.getAttribute('y'), text)
            elif node.nodeName == 'image':
                width, width_unit = number_units_re.match(node.getAttribute('width')).group(1, 2)
                height, height_unit = number_units_re.match(node.getAttribute('height')).group(1, 2)
                s += '\tel = this.paper.image(\'%s\', %s, %s, %s, %s)' % (node.getAttribute('xlink:href'), node.getAttribute('x'), node.getAttribute('y'), self._raphael_unit_mapping_expression(width, width_unit),self._raphael_unit_mapping_expression(height, height_unit))
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
                s += '\tel = this.paper.path(\'%s\')' % pathstring
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
                if node_id is not None:
                    s += '\tif (this.nodeInfoContainer != undefined) this.add_node_events(el, \'%s\');\n' % node_id.replace('--', '\\-\\-')

        for i in range(node.childNodes.length):
            s += self._write_raphael_node(node.childNodes[i], node_id, transform)
        return s

    def to_raphael(self):
        svg = self.G.draw(format='svg', prog='dot')
        dom = xml.dom.minidom.parseString(svg)

        s = 'function AuthGraph(anchorElement, maxPaperWidth, imageScale, mediaURL, nodeInfoContainer) {\n'
        s += '\tthis.anchorElement = anchorElement;\n'
        s += '\tthis.maxPaperWidth = maxPaperWidth == undefined ? 0 : maxPaperWidth;\n'
        s += '\tthis.imageScale = imageScale == undefined ? 1.4 : imageScale;\n'
        s += '\tthis.mediaURL = mediaURL == undefined ? \'\' : mediaURL;\n'
        s += '\tif (nodeInfoContainer != undefined && nodeInfoContainer.nodeType != 1) {\n'
        s += '\t\tthis.nodeInfoContainer = document.getElementById(nodeInfoContainer);\n'
        s += '\t} else {\n'
        s += '\t\tthis.nodeInfoContainer = nodeInfoContainer;\n'
        s += '\t}\n'
        s += '\tthis.node_info = %s;\n' % simplejson.dumps(self.node_info)
        s += '\tthis.notices = %s;\n' % simplejson.dumps(self.ordered_notices())
        if self.updated is not None:
            s += '\tthis.updated = new Date("%s");\n' % (self.updated.isoformat('T'))
        else:
            s += '\tthis.updated = null;\n'
        if self.page_url is not None:
            s += '\tthis.page_url = "%s"\n' % (self.page_url)
        else:
            s += '\tthis.page_url = null;\n'
        s += '}\n'
        s += 'AuthGraph.prototype.draw = function () {\n'
        s += '\tvar el, paperScale;\n'
        s += self._write_raphael_node(dom.documentElement, None, 's\'+this.imageScale+\',\'+this.imageScale+\',0,0')
        s += '\tthis.paper.setViewBox(0, 0, imageWidth, imageHeight);\n'
        s += '}\n'
        s += '''
AuthGraph.prototype.slugify = function (s) {
	_slugify_strip_re = /[^\w\s-]/g;
	_slugify_hyphenate_re = /[-\s]+/g;
	s = s.replace(_slugify_strip_re, '').trim().toLowerCase();
	s = s.replace(_slugify_hyphenate_re, '-');
	return s;
}

AuthGraph.prototype.add_node_events = function (graphEl, graphElId) {
	if (this.nodeInfoContainer == undefined || !(graphElId in this.node_info)) {
		return;
	}
	var s = '<div class="tooltip-container"><div class="tooltip-data ' + this.slugify(this.node_info[graphElId]['status']) + '">\\n';
	s += '<table>';
	for (var i = 0; i < this.node_info[graphElId]['description'].length; i++) {
		var row = this.node_info[graphElId]['description'][i];
		if (row[0] != undefined) {
			s += '<tr><td><strong>' + row[0] + '</strong>:</td><td>' + row[1] + '</td></tr>';
		} else {
			s += '<tr><td>&nbsp;</td><td></td></tr>';
		}
	}
	s += '</table>';
	s += '<p class="close-floatbox"><a href="javascript:void(0);">Close</a></p></div></div>';

	var nodeInfoEl = $(s).appendTo(this.nodeInfoContainer);

	$(graphEl[0]).tooltip({
		delay: 0,
		track: true,
		showURL: false,
		bodyHandler: function() {
			return nodeInfoEl.html();
		},
		extraClass: 'no-padding'
	});

	$(graphEl[0]).css('cursor', 'pointer');
	$(graphEl[0]).click(function() {
		$.floatbox({
			content: nodeInfoEl.html(),
			fade: true,
			button: ''
		});
	});
}

AuthGraph.prototype.post_notices = function (noticesElement) {
	if (noticesElement.nodeType != 1) {
		noticesElement = document.getElementById(noticesElement);
	}
	var s = '';
	for (var catIndex = 0; catIndex < this.notices.length; catIndex++) {
		var cat = this.notices[catIndex][0];
		var subcat_lists = this.notices[catIndex][1];
		s += '<div class="notice-category">';
		s += '<h4><img src="' + this.mediaURL + this.slugify(cat) + '.png" alt="' + cat.charAt(0).toUpperCase() + cat.slice(1) + '" class="header-icon" />' + cat.charAt(0).toUpperCase() + cat.slice(1) + '</h4>';
		for (var subcatIndex = 0; subcatIndex < subcat_lists.length; subcatIndex++) {
			var subcat = subcat_lists[subcatIndex][0];
			var items = subcat_lists[subcatIndex][1];
			s += '<div class="' + this.slugify(subcat) + '">';
			s += '<h5>' + subcat.charAt(0).toUpperCase() + subcat.slice(1) + ' <span class="count">(' + items.length + ')</span></h5>';
			s += '<div><ul>';
			for (var itemIndex = 0; itemIndex < items.length; itemIndex++) {
				var item = items[itemIndex][0];
				var explanation = items[itemIndex][1];
				if (explanation == undefined) {
					s += '<li>' + item + '</li>';
				} else {
					s += '<li><strong>' + item + ':</strong>' + explanation + '</li>';
				}
			}
			s += '</ul></div></div>';
		}
		s += '</div>';
	}
	$(s).prependTo(noticesElement);
}

if (typeof String.prototype.trim !== 'function') {
	String.prototype.trim = function() {
		return this.replace(/^\s+|\s+$/g, ''); 
	}
}'''
        return s

    def draw(self, format):
        if format == 'js':
            return self.to_raphael()
        else:
            return self.G.draw(format=format, prog='dot')

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

    def id_for_nsec(self, name, rdtype, is_parent_zone, nsec_tuple_list):
        try:
            nsec_tuple_lists = self.nsec_ids[(name,rdtype,is_parent_zone)]
        except KeyError:
            self.nsec_ids[(name,rdtype,is_parent_zone)] = []
            nsec_tuple_lists = self.nsec_ids[(name,rdtype,is_parent_zone)]

        nsec_tuple_list = [t[1] for t in nsec_tuple_list]
        for tuple_list, id in nsec_tuple_lists:
            if tuple_list == nsec_tuple_list:
                return id

        id = self.next_nsec_id
        self.nsec_ids[(name,rdtype,is_parent_zone)].append((nsec_tuple_list, id))
        self.next_nsec_id += 1
        return id

    def dnskey_node_str(self, id, name, algorithm, key_tag):
        return 'DNSKEY-%s-%s-%d-%d' % (id, util.format.humanize_name(name), algorithm, key_tag)

    def has_dnskey(self, id, name, algorithm, key_tag):
        return self.G.has_node(self.dnskey_node_str(id, name, algorithm, key_tag))

    def get_dnskey(self, id, name, algorithm, key_tag):
        return self.G.get_node(self.dnskey_node_str(id, name, algorithm, key_tag))

    def add_dnskey(self, name_obj, dnskey, ttl, trust_anchor, servers_with_dnskey, servers_without_dnskey):
        zone_obj = name_obj.zone
        node_str = self.dnskey_node_str(self.id_for_dnskey(name_obj.name, dnskey), name_obj.name, dnskey.algorithm, util.dnssec.key_tag(dnskey))

        #XXX clean this up
        servers_with_dnskey = set([s[0] for s in servers_with_dnskey])
        servers_without_dnskey = set([s[0] for s in servers_without_dnskey])

        if not self.G.has_node(node_str):
            img_str = None
            servers_with_payload_issues = []
            max_payload_mapping = name_obj.get_max_payload()
            if max_payload_mapping:
                #XXX this needs to be fixed properly
                real_payload_issues = dict(filter(lambda x: x[1][1] < 4096, max_payload_mapping.items()))
                servers_with_payload_issues = list(servers_with_dnskey.intersection(set(real_payload_issues)))
                servers_with_payload_issues.sort()
                if servers_with_payload_issues:
                    img_str = '<IMG SRC="%simages/dnssec_legend/warning.png"/>' % self.static_base

            servers_with_dnskey = list(servers_with_dnskey)
            servers_with_dnskey.sort()

            if servers_without_dnskey:
                servers_without_dnskey = list(servers_without_dnskey)
                servers_without_dnskey.sort()
                servers_msg = 'This DNSKEY was not found on server(s) %s.' % (', '.join(servers_without_dnskey))
                self.notices['notices']['errors'].add((util.format.humanize_dnskey(name_obj.name, dnskey, True), servers_msg))
                img_str = '<IMG SRC="%simages/dnssec_legend/error.png"/>' % self.static_base

            if not name_obj.is_zone():
                self.notices['notices']['warnings'].add((util.format.humanize_dnskey(name_obj.name, dnskey, True), 'DNSKEY is not at zone apex (%s).' % (util.format.humanize_name(zone_obj.name, True))))

            if img_str:
                label_str = u'<<TABLE BORDER="0" CELLPADDING="0"><TR><TD>  </TD><TD VALIGN="bottom"><FONT POINT-SIZE="%d" FACE="%s">DNSKEY</FONT></TD><TD VALIGN="bottom">%s</TD></TR><TR><TD COLSPAN="3" VALIGN="top"><FONT POINT-SIZE="%d">alg=%d, id=%d</FONT></TD></TR></TABLE>>' % \
                        (12, 'Helvetica', img_str, 10, dnskey.algorithm, util.dnssec.key_tag(dnskey))
            else:
                label_str = u'<<FONT POINT-SIZE="%d" FACE="%s">DNSKEY</FONT><BR/><FONT POINT-SIZE="%d">alg=%d, id=%d</FONT>>' % \
                        (12, 'Helvetica', 10, dnskey.algorithm, util.dnssec.key_tag(dnskey))

            attr = {'style': 'filled', 'fillcolor': '#ffffff' }
            if dnskey.flags & util.format.DNSKEY_FLAGS['SEP']:
                attr['fillcolor'] = 'lightgray'
            if dnskey.flags & util.format.DNSKEY_FLAGS['revoke']:
                attr['penwidth'] = '4.0'
            elif trust_anchor:
                attr['peripheries'] = '2'

            S, zone_node_str, zone_bottom_name, zone_top_name = self.get_zone(zone_obj.name)
            S.add_node(node_str, id=node_str, shape='ellipse', label=label_str, **attr)
            self.node_subgraph_name[node_str] = zone_top_name

            # flag descriptions
            flags = []
            for flag_name, flag_val in util.format.DNSKEY_FLAGS.items():
                if flag_val & dnskey.flags:
                    flags.append(flag_name)

            # protocol description
            if dnskey.protocol == util.format.DNSKEY_PROTOCOLS['DNSSEC']:
                protocol = 'DNSSEC'
            else:
                protocol = 'unknown'

            # protocol description
            key_len = util.dnssec.key_len(dnskey)
            if key_len is None:
                key_len_str = 'unknown'
            else:
                key_len_str = '%d bits' % (key_len)

            self.node_info[node_str] = {}
            self.node_info[node_str]['description'] = [('Name', '<strong>%s</strong>' % (util.format.humanize_name(name_obj.name))),
                    ('TTL', '%d (%s)' % (ttl, util.format.humanize_time(ttl))),
                    ('RR type', '<strong>DNSKEY</strong>'),
                    ('Flags', '%d (%s)' % (dnskey.flags, ', '.join(flags))),
                    ('Protocol', '%d (%s)' % (dnskey.protocol, protocol)),
                    ('Algorithm', '%d (%s)' % (dnskey.algorithm, util.format.DNSKEY_ALGORITHMS.get(dnskey.algorithm, dnskey.algorithm))),
                    ('Key length', key_len_str),
                    ('Key tag', util.dnssec.key_tag(dnskey)),
                    ('Returned by', ', '.join(servers_with_dnskey))]

            if servers_without_dnskey:
                self.node_info[node_str]['description'].append(('<img src="%simages/dnssec_legend/error.png" alt="Error"/> Missing from' % settings.STATIC_URL, ', '.join(servers_without_dnskey)))

            if servers_with_payload_issues:
                self.node_info[node_str]['description'].append(('<img src="%simages/dnssec_legend/warning.png" alt="Warning"/> PMTU issues' % settings.STATIC_URL, ', '.join(servers_with_payload_issues)))

            if dnskey.algorithm in self.dnssec_algorithms:
                self.dnskey_algs_by_zone[zone_top_name].add(dnskey.algorithm)

        return self.G.get_node(node_str)

    def add_dnskey_non_existent(self, name_obj, algorithm, key_tag, trust_anchor):
        zone_obj = name_obj.zone
        node_str = self.dnskey_node_str('None', name_obj.name, algorithm, key_tag)

        if not self.G.has_node(node_str):
            label_str = u'<<FONT POINT-SIZE="%d" FACE="%s">DNSKEY</FONT><BR/><FONT POINT-SIZE="%d">alg=%d, id=%d</FONT>>' % \
                    (12, 'Helvetica', 10, algorithm, key_tag)

            attr = {'style': 'filled', 'fillcolor': '#ffffff' }
            attr['fillcolor'] = COLORS['warnings_light']
            if trust_anchor:
                attr['peripheries'] = '2'

            S, zone_node_str, zone_bottom_name, zone_top_name = self.get_zone(zone_obj.name)
            S.add_node(node_str, id=node_str, shape='ellipse', label=label_str, **attr)
            self.node_subgraph_name[node_str] = zone_top_name

            self.node_info[node_str] = {}
            self.node_info[node_str]['description'] = [('Name', '<strong>%s</strong>' % (util.format.humanize_name(name_obj.name))),
                    ('TTL', 'unknown'),
                    ('RR type', '<strong>DNSKEY</strong>'),
                    ('Flags', 'unknown'),
                    ('Protocol', 'unknown'),
                    ('Algorithm', '%d (%s)' % (algorithm, util.format.DNSKEY_ALGORITHMS.get(algorithm, algorithm))),
                    ('Key length', 'unknown'),
                    ('Key tag', key_tag)]

        return self.G.get_node(node_str)

    def ds_node_str(self, id, name, ds, rdtype):
        digest_types = [d.digest_type for d in ds]
        digest_types.sort()
        digest_str = '_'.join(map(str, digest_types))
        return '%s-%s-%s-%d-%d-%s' % (dns.rdatatype.to_text(rdtype), id, util.format.humanize_name(name), ds[0].algorithm, ds[0].key_tag, digest_str)

    def has_ds(self, id, name, ds, rdtype):
        return self.G.has_node(self.ds_node_str(id, name, ds, rdtype))

    def get_ds(self, id, name, ds, rdtype):
        return self.G.get_node(self.ds_node_str(id, name, ds, rdtype))

    def add_ds(self, name, ds, rdtype, ttl, zone_obj, parent_obj, servers_with_ds, servers_without_ds):
        node_str = self.ds_node_str(self.id_for_multiple_ds(name, ds), name, ds, rdtype)

        if not self.G.has_node(node_str):
            #XXX clean this up
            servers_with_ds = [s[0] for s in servers_with_ds]
            servers_with_ds.sort()

            digest_types = [d.digest_type for d in ds]
            digest_types.sort()
            digest_str = ','.join(map(str, digest_types))
            digest_algs_str = ','.join([util.format.DS_DIGEST_TYPES[t] for t in digest_types])
            if len(digest_types) != 1:
                plural = 's'
            else:
                plural = ''

            img_str = None
            if servers_without_ds:
                #XXX clean this up
                servers_without_ds = [s[0] for s in servers_without_ds]
                servers_without_ds.sort()
                servers_msg = 'The %s RR(s) were not found on server(s) %s.' % (dns.rdatatype.to_text(rdtype), ', '.join(servers_without_ds))
                self.notices['notices']['errors'].add((util.format.humanize_ds(name, ds, rdtype, True), servers_msg))
                img_str = '<IMG SRC="%simages/dnssec_legend/error.png"/>' % self.static_base

            attr = {'style': 'filled', 'fillcolor': '#ffffff' }
            if img_str:
                label_str = u'<<TABLE BORDER="0" CELLPADDING="0"><TR><TD>  </TD><TD VALIGN="bottom"><FONT POINT-SIZE="%d" FACE="%s">%s</FONT></TD><TD VALIGN="bottom">%s</TD></TR><TR><TD COLSPAN="3" VALIGN="top"><FONT POINT-SIZE="%d">digest alg%s=%s</FONT></TD></TR></TABLE>>' % \
                        (12, 'Helvetica', dns.rdatatype.to_text(rdtype), img_str, 10, plural, digest_str)
            else:
                label_str = u'<<FONT POINT-SIZE="%d" FACE="%s">%s</FONT><BR/><FONT POINT-SIZE="%d">digest alg%s=%s</FONT>>' % \
                        (12, 'Helvetica', dns.rdatatype.to_text(rdtype), 10, plural, digest_str)

            S, parent_node_str, parent_bottom_name, parent_top_name = self.get_zone(parent_obj.name)
            S.add_node(node_str, id=node_str, shape='ellipse', label=label_str, **attr)
            self.node_subgraph_name[node_str] = parent_top_name

            self.node_info[node_str] = {}
            self.node_info[node_str]['description'] = [('Name', '<strong>%s</strong>' % (util.format.humanize_name(name))),
                    ('TTL', '%d (%s)' % (ttl, util.format.humanize_time(ttl))),
                    ('RR type', '<strong>%s</strong>' % (dns.rdatatype.to_text(rdtype))),
                    ('Key tag', ds[0].key_tag),
                    ('Algorithm', '%d (%s)' % (ds[0].algorithm, util.format.DNSKEY_ALGORITHMS.get(ds[0].algorithm, ds[0].algorithm))),
                    ('Digest method%s' % (plural), '%s (%s)' % (digest_str, digest_algs_str)),
                    ('Returned by', ', '.join(servers_with_ds))]

            if servers_without_ds:
                self.node_info[node_str]['description'].append(('<img src="%simages/dnssec_legend/error.png" alt="Error"/> Missing from' % settings.STATIC_URL, ', '.join(servers_without_ds)))

            self.G.add_edge(parent_bottom_name, node_str, style='invis', minlen='0')

            T, zone_node_str, zone_bottom_name, zone_top_name = self.get_zone(zone_obj.name)

            digest_types_set = set(digest_types)
            if (zone_top_name, parent_top_name) not in self.ds_algs:
                self.ds_algs[(zone_top_name, parent_top_name)] = set()
            #XXX need to do this on a per RRset (per server) basis
            if ds[0].algorithm in self.dnssec_algorithms and \
                    digest_types_set.intersection(self.ds_algorithms):
                for digest_type in digest_types_set:
                    self.ds_algs[(zone_top_name, parent_top_name)].add((ds[0].algorithm, digest_type))

        return self.G.get_node(node_str)

    def add_ds_map(self, name, ds, ds_node, dnskey_node, revoke, rdtype, digest_valid):
        ret_val = False

        if self.G.has_edge(dnskey_node, ds_node):
            return self.G.get_edge(dnskey_node, ds_node).attr['color'] == COLORS['secure']

        # invalid signature
        if ds[0].digest_type not in self.ds_algorithms:
            line_color = COLORS['unknown']
            line_style = 'solid'
            self.notices['notices']['warnings'].add((util.format.humanize_ds(name, ds, rdtype, True), 'DNSSEC digest algorithm %d (%s) is not supported.' % (ds[0].digest_type, util.format.DS_DIGEST_TYPES.get(ds[0].digest_type, '%d' % (ds[0].digest_type)))))
            ds_status = ('unknown', 'DNSSEC digest algorithm %d (%s) is not supported.' % (ds[0].digest_type, util.format.DS_DIGEST_TYPES.get(ds[0].digest_type, '%d' % (ds[0].digest_type))))

        elif not digest_valid:
            line_style = 'dashed'
            if revoke:
                line_color = COLORS['warnings']
                self.notices['notices']['warnings'].add((util.format.humanize_ds(name, ds, rdtype, True), 'The %s RR corresponds to a DNSKEY which has been revoked.' % (dns.rdatatype.to_text(rdtype))))
                ds_status = ('non-existent', 'The %s RR corresponds to a DNSKEY which has been revoked.' % (dns.rdatatype.to_text(rdtype)))
            else:
                line_color = COLORS['errors']
                self.notices['notices']['errors'].add((util.format.humanize_ds(name, ds, rdtype, True), 'The %s RR contains an invalid digest of the corresponding DNSKEY.' % (dns.rdatatype.to_text(rdtype))))
                ds_status = ('bogus', 'The %s RR contains an invalid digest of the corresponding DNSKEY.' % (dns.rdatatype.to_text(rdtype)))
        elif revoke:
            line_color = COLORS['errors']
            line_style = 'dashed'
            self.notices['notices']['errors'].add((util.format.humanize_ds(name, ds, rdtype, True), 'The %s RR corresponds to a DNSKEY which has been revoked.' % (dns.rdatatype.to_text(rdtype))))
            ds_status = ('invalid', 'The %s RR corresponds to a DNSKEY which has been revoked.' % (dns.rdatatype.to_text(rdtype)))
        else:
            line_color = COLORS['secure']
            line_style = 'solid'
            ret_val = True
            ds_status = ('valid', None)

        edge_id = 'digest-%s--%s--%s-%s' % (dnskey_node, ds_node, line_color.lstrip('#'), line_style)
        self.G.add_edge(dnskey_node, ds_node, id=edge_id, color=line_color, style=line_style, dir='back')

        if ds_status[1]:
            ds_status_str = '<strong>%s</strong>: %s' % (ds_status[0], ds_status[1])
        else:
            ds_status_str = '<strong>%s</strong>' % (ds_status[0])
        if digest_valid:
            digest_status = 'correct'
        elif digest_valid is None:
            digest_status = '<strong>unknown</strong>'
        else:
            digest_status = '<strong>bogus</strong>'
        self.node_info[edge_id] = {}
        self.node_info[edge_id]['description'] = self.node_info[ds_node]['description'][:]
        self.node_info[edge_id]['description'].extend([('Digest', digest_status), ('Status', ds_status_str)])
        self.node_info[edge_id]['status'] = ds_status[0]

        return ret_val

    def zone_node_str(self, name):
        return 'cluster_%s' % util.format.humanize_name(name)

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
            label_str = u'<<TABLE BORDER="0"><TR><TD ALIGN="LEFT"><FONT POINT-SIZE="%d">%s</FONT></TD></TR><TR><TD ALIGN="LEFT"><FONT POINT-SIZE="%d">(%s)</FONT></TD></TR></TABLE>>' % \
                    (12, zone_obj, 10, zone_obj.updated_utc_str())
            S = self.G.add_subgraph(name=node_str, label=label_str, labeljust='l', penwidth='0.5')
            S.add_node(top_name, shape='point', style='invis')
            S.add_node(bottom_name, shape='point', style='invis')
            self.node_subgraph_name[top_name] = top_name
            self.valid_self_sign_algs[top_name] = set()
            self.dnskey_algs_by_zone[top_name] = set()

        return S, node_str, bottom_name, top_name

    def add_rrsig(self, name, zone_obj, rrset_ttl, ttl, rrsig, signer_obj, dnskey, signed_node, sig_valid, ref_date, servers_with_rrsig, combine_edge_id=None):
        #XXX clean this up
        servers_with_rrsig = [s[0] for s in servers_with_rrsig]
        servers_with_rrsig.sort()

        if rrsig.signer != zone_obj.name:
            self.notices['notices']['errors'].add((util.format.humanize_rrsig(name, rrsig, True), u'The signer name field (%s) does not match the zone name (%s).' % \
                    (util.format.humanize_name(rrsig.signer, True), util.format.humanize_name(zone_obj.name, True))))
        
        if dnskey is None:
            dnskey_node = self.add_dnskey_non_existent(signer_obj, rrsig.algorithm, rrsig.key_tag, False)
        else:
            dnskey_node = self.get_dnskey(self.id_for_dnskey(signer_obj.name, dnskey), signer_obj.name, dnskey.algorithm, util.dnssec.key_tag(dnskey))

        expiration = util.format.timestamp_to_datetime_utc(rrsig.expiration)
        inception = util.format.timestamp_to_datetime_utc(rrsig.inception)

        expiration_str = None
        inception_str = None

        edge_label = ''
        description_errors = []
        if rrset_ttl != ttl:
            edge_label = u'<<TABLE BORDER="0"><TR><TD><IMG SRC="%simages/dnssec_legend/warning.png"/></TD></TR></TABLE>>' % self.static_base
            self.notices['notices']['warnings'].add((util.format.humanize_rrsig(name, rrsig, True), 'RRSIG TTL (%d) does not match the TTL of the RRset it covers (%d).' % (ttl, rrset_ttl)))
            description_errors.append(('<img src="%simages/dnssec_legend/warning.png" alt="Warning"/> Warning' % settings.STATIC_URL,  'TTL (%d) does not match the TTL of the RRset it covers (%d).' % (ttl, rrset_ttl)))

        if ref_date <= expiration and ref_date + datetime.timedelta(seconds=min(rrset_ttl, ttl)) > expiration:
            edge_label = u'<<TABLE BORDER="0"><TR><TD><IMG SRC="%simages/dnssec_legend/error.png"/></TD></TR></TABLE>>' % self.static_base
            self.notices['notices']['errors'].add((util.format.humanize_rrsig(name, rrsig, True), 'With a TTL of %d, this RRSIG will expire in the cache of non-validating resolvers (i.e., now + TTL > expiration).' % (min(ttl, rrset_ttl))))
            description_errors.append(('<img src="%simages/dnssec_legend/error.png" alt="Error"/> Error' % settings.STATIC_URL, 'RRSIG will expire in the cache of non-validating resolvers (i.e., now + TTL > expiration).'))

        # by default edge is solid with color secure
        line_style = 'solid'
        line_color = COLORS['secure']

        rrsig_status = ('valid',None)

        #XXX is this redundant--shouldn't it be handled with value for rrsig_valid?
        if rrsig.algorithm not in self.dnssec_algorithms:
            line_color = COLORS['unknown']
            self.notices['notices']['warnings'].add((util.format.humanize_rrsig(name, rrsig, True), 'DNSSEC algorithm %d (%s) is not supported.' % (rrsig.algorithm, util.format.DNSKEY_ALGORITHMS.get(rrsig.algorithm, rrsig.algorithm))))
            rrsig_status = ('unknown','DNSSEC algorithm %d (%s) is not supported.' % (rrsig.algorithm, util.format.DNSKEY_ALGORITHMS.get(rrsig.algorithm, rrsig.algorithm)))

        # First, we check pre-requisites, which if these fail, the edge is dashed with color bogus
        elif rrsig.signer != zone_obj.name:
            line_color = COLORS['errors']
            line_style = 'dashed'
            rrsig_status = ('invalid', u'The signer name field (%s) does not match that of the zone name (%s).' % \
                    (util.format.humanize_name(rrsig.signer, True), util.format.humanize_name(zone_obj.name, True)))
        #XXX double-check this logic
        elif dnskey is not None and \
                dnskey.flags & util.format.DNSKEY_FLAGS['revoke'] and rrsig.covers() != dns.rdatatype.DNSKEY:
            line_color = COLORS['errors']
            line_style = 'dashed'
            if rrsig.key_tag != util.dnssec.key_tag(dnskey):
                self.notices['notices']['errors'].add((util.format.humanize_rrsig(name, rrsig, True), 'The RRSIG was made by a key which is now revoked.'))
                rrsig_status = ('invalid', 'The RRSIG was made by a key which is now revoked.')
            else:
                self.notices['notices']['errors'].add((util.format.humanize_rrsig(name, rrsig, True), 'The RRSIG was made by a revoked key.'))
                rrsig_status = ('invalid', 'The RRSIG was made by a revoked key.')
        #XXX double-check this logic
        elif dnskey is not None and \
                rrsig.key_tag != util.dnssec.key_tag(dnskey):
            return

        # Next, we check date validity
        elif ref_date > expiration:
            expiration_str = '<strong>%s (%s)</strong>' % ('%s UTC' % (expiration.isoformat(' ')[:-6]), util.format.format_diff(ref_date, expiration))
            line_color = COLORS['expired']
            self.notices['notices']['RRSIG expirations'].add((util.format.humanize_rrsig(name, rrsig, True), 'The RRSIG expired at %s.' % (expiration_str)))
            rrsig_status = ('expired',None)
        elif ref_date < inception:
            inception_str = '<strong>%s (%s)</strong>' % ('%s UTC' % (inception.isoformat(' ')[:-6]), util.format.format_diff(ref_date, inception))
            line_color = COLORS['expired']
            self.notices['notices']['RRSIG expirations'].add((util.format.humanize_rrsig(name, rrsig, True), 'The RRSIG is not valid until %s.' % (inception_str)))
            rrsig_status = ('not yet valid',None)

        elif dnskey is None:
            line_color = COLORS['warnings']
            line_style = 'dashed'
            self.notices['notices']['warnings'].add((util.format.humanize_rrsig(name, rrsig, True), 'No matching DNSKEY was found to validate the RRSIG.'))
            rrsig_status = ('unknown', 'No matching DNSKEY was found to validate the RRSIG.')

        # Finally, we check RRSIG validity
        elif not sig_valid:
            line_color = COLORS['errors']
            self.notices['notices']['errors'].add((util.format.humanize_rrsig(name, rrsig, True), 'The signature in the RRSIG is bogus.'))
            rrsig_status = ('bogus',None)

        if line_color == COLORS['secure'] and dnskey_node == signed_node and signer_obj.name == zone_obj.name:
            S, zone_node_str, zone_bottom_name, zone_top_name = self.get_zone(signer_obj.name)

            self.valid_self_sign_algs[zone_top_name].add(rrsig.algorithm)

        if combine_edge_id is not None:
            edge_id = 'RRSIG-%s--%s-%d-%s' % (signed_node.replace('*', '_'), dnskey_node, combine_edge_id, line_style)
            edge_key = '%d-%s' % (combine_edge_id, line_style)
            try:
                edge = self.G.get_edge(signed_node, dnskey_node, edge_key)
                if line_color != COLORS['secure']:
                    edge.attr['color'] = line_color
            except KeyError:
                self.G.add_edge(signed_node, dnskey_node, label=edge_label, key=edge_key, id=edge_id, color=line_color, style=line_style, dir='back')
        else:
            edge_id = 'RRSIG-%s--%s--%s-%s' % (signed_node.replace('*', '_'), dnskey_node, line_color.lstrip('#'), line_style)
            edge_key = '%s-%s' % (line_color, line_style)
            try:
                edge = self.G.get_edge(signed_node, dnskey_node, edge_key)
            except KeyError:
                self.G.add_edge(signed_node, dnskey_node, label=edge_label, key=edge_key, id=edge_id, color=line_color, style=line_style, dir='back')

        if expiration_str is None:
            expiration_str = '%s (%s)' % ('%s UTC' % (expiration.isoformat(' ')[:-6]), util.format.format_diff(ref_date, expiration))
        if inception_str is None:
            inception_str = '%s (%s)' % ('%s UTC' % (inception.isoformat(' ')[:-6]), util.format.format_diff(ref_date, inception))
        if sig_valid:
            sig_status = 'correct'
        elif sig_valid is None:
            sig_status = '<strong>unknown</strong>'
        else:
            sig_status = '<strong>bogus</strong>'
        if rrsig_status[1]:
            rrsig_status_str = '<strong>%s</strong>: %s' % (rrsig_status[0], rrsig_status[1])
        else:
            rrsig_status_str = '<strong>%s</strong>' % (rrsig_status[0])

        if edge_id not in self.node_info:
            self.node_info[edge_id] = {}
            self.node_info[edge_id]['description'] = []
            self.node_info[edge_id]['status'] = rrsig_status[0]
        else:
            self.node_info[edge_id]['description'].append((None, None))
            if self.node_info[edge_id]['status'] != 'valid':
                self.node_info[edge_id]['status'] = rrsig_status[0]

        self.node_info[edge_id]['description'] += [('Name', '<strong>%s</strong>' % (util.format.humanize_name(name))),
                ('TTL', '%d (%s)' % (ttl, util.format.humanize_time(ttl))),
                ('RR type', '<strong>RRSIG</strong>'),
                ('Covers', '<strong>%s</strong>' % (dns.rdatatype.to_text(rrsig.covers()))),
                ('Algorithm', '%d (%s)' % (rrsig.algorithm, util.format.DNSKEY_ALGORITHMS.get(rrsig.algorithm, rrsig.algorithm))),
                ('Expiration', expiration_str),
                ('Inception', inception_str),
                ('Key tag', '%d' % (rrsig.key_tag)),
                ('Signer', '%s' % (util.format.humanize_name(signer_obj.name))),
                ('Signature', sig_status),
                ('Returned by', ', '.join(servers_with_rrsig))] + \
                description_errors + \
                [('Status', rrsig_status_str)]

    def add_rrsig_non_existent(self, name, covers, signer, dnskey, signed_node, servers):
        dnskey_node = self.get_dnskey(self.id_for_dnskey(signer, dnskey), signer, dnskey.algorithm, util.dnssec.key_tag(dnskey))

        servers = [s[0] for s in servers]
        servers.sort()

        line_color = COLORS['errors']
        line_style = 'dashed'

        edge_id = 'RRSIG-%s--%s--%s-%s' % (signed_node.replace('*', '_'), dnskey_node, line_color.lstrip('#'), line_style)
        edge_key = '%s-%s' % (line_color, line_style)
        try:
            edge = self.G.get_edge(signed_node, dnskey_node, edge_key)
        except KeyError:
            self.G.add_edge(signed_node, dnskey_node, key=edge_key, id=edge_id, color=line_color, style=line_style, dir='back')

            servers_msg = 'This RRSIG is not returned by server(s) %s.' % (', '.join(servers))
            self.notices['notices']['errors'].add((util.format.humanize_non_existent_rrsig(name, covers, signer, dnskey.algorithm, util.dnssec.key_tag(dnskey), True), servers_msg))

        if edge_id not in self.node_info:
            self.node_info[edge_id] = {}
            self.node_info[edge_id]['description'] = []
            self.node_info[edge_id]['status'] = 'missing'
        else:
            self.node_info[edge_id]['description'].append((None, None))

        self.node_info[edge_id]['description'] += [('Name', '<strong>%s</strong>' % (util.format.humanize_name(name))),
                ('RR type', '<strong>RRSIG</strong>'),
                ('Covers', '<strong>%s</strong>' % (dns.rdatatype.to_text(covers))),
                ('Algorithm', '%d (%s)' % (dnskey.algorithm, util.format.DNSKEY_ALGORITHMS.get(dnskey.algorithm, dnskey.algorithm))),
                ('Expiration', 'unknown'),
                ('Inception', 'unknown'),
                ('Key tag', '%d' % (util.dnssec.key_tag(dnskey))),
                ('Signer', '%s' % (util.format.humanize_name(signer))),
                ('Signature', 'unknown'),
                ('Missing from', ', '.join(servers)),
                ('Status', '<strong>missing</strong>')]

    def rrset_node_str(self, name, rdtype, id):
        return 'RRset-%d-%s-%s' % (id, util.format.humanize_name(name), dns.rdatatype.to_text(rdtype))

    def has_rrset(self, name, rdtype, id):
        return self.G.has_node(self.rrset_node_str(name, rdtype, id))

    def get_rrset(self, name, rdtype, id):
        return self.G.get_node(self.rrset_node_str(name, rdtype, id))

    def add_rrset(self, rrset, wildcard_name, zone_obj, id, servers_with_rrset, exists=True):
        name = wildcard_name or rrset.name
        node_str = self.rrset_node_str(name, rrset.rdtype, id)

        if not self.G.has_node(node_str):
            servers_with_rrset = [s[0] for s in servers_with_rrset]
            servers_with_rrset.sort()

            node_label = u'%s/%s' % (util.format.humanize_name(name, True), dns.rdatatype.to_text(rrset.rdtype))

            attr = {}
            attr['shape'] = 'rectangle'
            attr['style'] = 'rounded,filled'
            if exists:
                attr['fillcolor'] = '#ffffff'
            else:
                attr['fillcolor'] = COLORS['warnings_light']

            node_id = node_str.replace('*', '_')
            S, zone_node_str, zone_bottom_name, zone_top_name = self.get_zone(zone_obj.name)
            S.add_node(node_str, id=node_id, label=node_label, fontsize='10', **attr)
            self.node_subgraph_name[node_str] = zone_top_name

            if exists and rrset.rdtype == dns.rdatatype.CNAME and not servers_with_rrset:
                synthesized = '<br />(synthesized from DNAME)'
            else:
                synthesized = ''

            self.node_info[node_id] = {}
            self.node_info[node_id]['description'] = [('Name', '<strong>%s</strong>%s' % (util.format.humanize_name(rrset.name), synthesized)), ('RR type', '<strong>%s</strong>' % (dns.rdatatype.to_text(rrset.rdtype)))]
            if exists:
                self.node_info[node_id]['description'].insert(1, ('TTL', '%d (%s)' % (rrset.ttl, util.format.humanize_time(rrset.ttl))))
                
                data = ''
                for rr in rrset:
                    data += escape(rr.to_text()) + '<br />'
                self.node_info[node_id]['description'].append(('Data', data))

            if servers_with_rrset:
                self.node_info[node_id]['description'].append(('Returned by', ', '.join(servers_with_rrset)))

            self.G.add_edge(zone_bottom_name, node_str, style='invis', minlen='0')
        return self.G.get_node(node_str)

    def nsec_node_str(self, nsec_rdtype, id, name, rdtype):
        return '%s-%d-%s-%s' % (dns.rdatatype.to_text(nsec_rdtype), id, util.format.humanize_name(name), dns.rdatatype.to_text(rdtype))

    def has_nsec(self, nsec_rdtype, id, name, rdtype):
        return self.G.has_node(self.nsec_node_str(nsec_rdtype, id, name, rdtype))

    def get_nsec(self, nsec_rdtype, id, name, rdtype):
        return self.G.get_node(self.nsec_node_str(nsec_rdtype, id, name, rdtype))

    def add_nsec(self, nsec_rdtype, id, name, rdtype, zone, nsec_tuple, servers_with_nsec, servers_without_nsec, exists=True, anchor_to_bottom=True):
        node_str = self.nsec_node_str(nsec_rdtype, id, name, rdtype)

        if not self.G.has_node(node_str):
            #XXX clean this up
            servers_with_nsec = [s[0] for s in servers_with_nsec]
            servers_with_nsec.sort()

            img_str = None
            if servers_without_nsec:
                #XXX clean this up
                servers_without_nsec = [s[0] for s in servers_without_nsec]
                servers_without_nsec.sort()
                servers_msg = 'No %s RR(s) were found on server(s) %s.' % (dns.rdatatype.to_text(nsec_rdtype), ', '.join(servers_without_nsec))
                self.notices['notices']['errors'].add((u'%s RR(s) proving non-existence of %s/%s' % (dns.rdatatype.to_text(nsec_rdtype), util.format.humanize_name(name, True), dns.rdatatype.to_text(rdtype)), servers_msg))
                img_str = '<IMG SRC="%simages/dnssec_legend/error.png"/>' % self.static_base

            if img_str:
                label_str = u'<<TABLE BORDER="0" CELLPADDING="0"><TR><TD><FONT POINT-SIZE="%d" FACE="%s">%s</FONT></TD></TR><TR><TD>%s</TD></TR></TABLE>>' % \
                        (12, 'Helvetica', dns.rdatatype.to_text(nsec_rdtype), img_str)
            else:
                label_str = u'<<FONT POINT-SIZE="%d" FACE="%s">%s</FONT>>' % \
                        (12, 'Helvetica', dns.rdatatype.to_text(nsec_rdtype))

            attr = {}
            attr['shape'] = 'diamond'
            attr['style'] = 'filled'
            if exists:
                attr['fillcolor'] = '#ffffff'
            else:
                attr['fillcolor'] = COLORS['warnings_light']

            S, zone_node_str, zone_bottom_name, zone_top_name = self.get_zone(zone)
            S.add_node(node_str, id=node_str, label=label_str, **attr)
            self.node_subgraph_name[node_str] = zone_top_name

            self.node_info[node_str] = {}
            self.node_info[node_str]['description'] = [('Description', u'%s RR(s) proving non-existence of %s/%s' % (dns.rdatatype.to_text(nsec_rdtype), util.format.humanize_name(name, True), dns.rdatatype.to_text(rdtype)))]

            if exists:
                for nsec_name, nsec_rrset, rrsigs in nsec_tuple:
                    nsec = nsec_rrset[0]
                    self.node_info[node_str]['description'] += [('', ''), ('Name', '<strong>%s</strong>' % (util.format.humanize_name(nsec_rrset.name))),
                            ('TTL', '%d (%s)' % (nsec_rrset.ttl, util.format.humanize_time(nsec_rrset.ttl))),
                            ('RR type', '<strong>%s</strong>' % (dns.rdatatype.to_text(nsec_rrset.rdtype))),
                            ('Data', nsec.to_text())]

                self.node_info[node_str]['description'] += [('', ''), ('Returned by', ', '.join(servers_with_nsec))]

            if servers_without_nsec:
                self.node_info[node_str]['description'].append(('<img src="%simages/dnssec_legend/error.png" alt="Error"/> Missing from' % settings.STATIC_URL, ', '.join(servers_without_nsec)))

            if anchor_to_bottom:
                self.G.add_edge(zone_bottom_name, node_str, style='invis', minlen='0')
        return self.G.get_node(node_str)

    def add_alias(self, alias, target):
        if not filter(lambda x: x[1] == target and x.attr['color'] == 'black', self.G.out_edges(alias)):
            #self.G.add_edge(alias, target, color='black', constraint='false')
            self.G.add_edge(alias, target, color='black')

    def graph_denial_of_existence(self, name_obj, name, rr_type, parent_obj, nsec_rrsets_rrsigs, servers_responsive_for_rrset, closest_encloser=None):
        S, zone_graph_name, zone_bottom, zone_top = self.get_zone(parent_obj.name)

        empty_rrset = dns.rrset.RRset(name, dns.rdataclass.IN, rr_type)
        my_node = self.add_rrset(empty_rrset, None, parent_obj, 1, (), exists=False)

        covered = False

        servers_with_nsec = {}
        all_servers_with_nsec = set()

        for nsec_tuple, rrset_servers in nsec_rrsets_rrsigs:
            id = self.id_for_nsec(name, nsec_rrsets_rrsigs[0][0][0][1].rdtype, False, nsec_tuple)
            if id not in servers_with_nsec:
                servers_with_nsec[id] = set()
            servers_with_nsec[id].update(rrset_servers)
            all_servers_with_nsec.update(rrset_servers)
        servers_without_nsec = servers_responsive_for_rrset.difference(all_servers_with_nsec)

        edge_id = 0
        for nsec_tuple, rrset_servers in nsec_rrsets_rrsigs:
            id = self.id_for_nsec(name, nsec_rrsets_rrsigs[0][0][0][1].rdtype, False, nsec_tuple)

            nsec_node = self.add_nsec(nsec_rrsets_rrsigs[0][0][0][1].rdtype, id, name, rr_type, parent_obj.name, nsec_tuple, servers_with_nsec[id], servers_without_nsec, anchor_to_bottom=False)

            nsec_rrsets = [t[1] for t in nsec_tuple]
            #XXX handle the case where multiple sets of params exist

            if util.nsec.validate_nsec_covering(name, rr_type, parent_obj.name, nsec_rrsets, closest_encloser):
                line_color = COLORS['secure']
                covered = True
            else:
                line_color = COLORS['bogus']
                self.notices['notices']['errors'].add((u'%s RRs proving non-existence of %s' % \
                            (dns.rdatatype.to_text(nsec_rrsets_rrsigs[0][0][0][1].rdtype), util.format.humanize_rrset(empty_rrset, True)),
                        u'The %s RR(s) are insufficient to prove non-existence of %s.' %
                            (dns.rdatatype.to_text(nsec_rrsets_rrsigs[0][0][0][1].rdtype), util.format.humanize_rrset(empty_rrset, True))))

            if not filter(lambda x: x[1] == nsec_node and x.attr['color'] == line_color, self.G.out_edges(my_node)):
                self.G.add_edge(my_node, nsec_node, color=line_color, dir='back')

            for nsec_name, nsec_rrset, rrsigs in nsec_tuple:
                algs_signing_rrset = set()
                servers_with_rrsig = {}
                for rrsig, ttl in rrsigs:
                    signer_obj = name_obj.get_name(rrsig.signer, True)
                    if rrsig.signer != parent_obj.name:
                        self.graph_zone_auth(signer_obj, False)

                    for dnskey, valid in signer_obj.dnskeys_for_rrsig(rrsig, nsec_rrset, supported_dnssec_algorithms=self.dnssec_algorithms):
                        self.add_rrsig(nsec_name, parent_obj, nsec_rrset.ttl, ttl, rrsig, signer_obj, dnskey, nsec_node, valid, name_obj.analysis_end, rrset_servers, combine_edge_id=edge_id)

                        if dnskey is None:
                            continue

                        if (rrsig.signer, dnskey) not in servers_with_rrsig:
                            servers_with_rrsig[(rrsig.signer, dnskey)] = set()
                        servers_with_rrsig[(rrsig.signer, dnskey)].update(rrset_servers)

                    algs_signing_rrset.add(rrsig.algorithm)

                for (signer, dnskey), servers in servers_with_rrsig.items():
                    if not servers:
                        continue
                    if signer != parent_obj.name:
                        continue

                    servers_without_rrsig = rrset_servers.difference(servers)
                    if servers_without_rrsig:
                        self.add_rrsig_non_existent(nsec_rrset.name, nsec_rrset.rdtype, signer, dnskey, nsec_node, servers_without_rrsig)

                if parent_obj.signed:
                    algs_not_signing_rrset = self.dnskey_algs_by_zone[zone_top].difference(algs_signing_rrset)
                    if not algs_signing_rrset:
                        self.notices['notices']['errors'].add((util.format.humanize_rrset(nsec_rrset, True),
                            'This RRset is not covered by any RRSIG.'))
                    elif algs_not_signing_rrset:
                        self.notices['notices']['errors'].add((util.format.humanize_rrset(nsec_rrset, True),
                            u'DNSKEYs exist for algorithm(s) %s in the %s zone, but the %s RRset was not signed by any DNSKEY with algorithm(s) %s.' % \
                                    (', '.join(map(str, self.dnskey_algs_by_zone[zone_top])), util.format.humanize_name(parent_obj.name, True), \
                                    util.format.humanize_rrset(nsec_rrset, True), ', '.join(map(str, algs_not_signing_rrset)))))

            edge_id += 1

        return my_node

    def graph_rrset_auth(self, name_obj, name, rr_type):
        if (name, rr_type) in self.processed_rrsets:
            return self.processed_rrsets[(name, rr_type)]
        self.processed_rrsets[(name, rr_type)] = None

        assert rr_type not in (dns.rdatatype.DNSKEY, dns.rdatatype.DLV, dns.rdatatype.DS, dns.rdatatype.NSEC, dns.rdatatype.NSEC3)

        parent_obj = name_obj.zone

        # graph the parent
        self.graph_zone_auth(parent_obj, False)

        S, zone_graph_name, zone_bottom, zone_top = self.add_zone(parent_obj)

        rrsets_rrsigs, neg_responses, dname_rrsets_rrsigs, nsec_rrsets_rrsigs = name_obj.get_aggregated_responses(name, rr_type)
        aliases_rrsets_rrsigs = util.dnsutil.aliases_from_aggregated_responses(name, rrsets_rrsigs)

        servers_responsive_for_rrset = name_obj.get_servers_authoritative_for_query(name, rr_type)

        my_nodes = []
        id = 0
        if name != dns.name.root and dname_rrsets_rrsigs:
            for rrset, rrset_servers, rrsigs in dname_rrsets_rrsigs:
                wildcard_name  = util.dnssec.reduce_wildcard(rrset, [r[0] for r in rrsigs])
                if wildcard_name is not None:
                    #XXX appropriately handle wildcard at DNAME
                    pass

                if (rrset.name, dns.rdatatype.DNAME) in self.processed_rrsets:
                    continue

                my_node = self.add_rrset(rrset, wildcard_name, parent_obj, id, rrset_servers)
                my_nodes.append(my_node)

                algs_signing_rrset = set()
                servers_with_rrsig = {}
                for rrsig, ttl, rrsig_servers in rrsigs:
                    signer_obj = name_obj.get_name(rrsig.signer, True)
                    if rrsig.signer != parent_obj.name:
                        self.graph_zone_auth(signer_obj, False)

                    for dnskey, valid in signer_obj.dnskeys_for_rrsig(rrsig, rrset, supported_dnssec_algorithms=self.dnssec_algorithms):
                        self.add_rrsig(name, parent_obj, rrset.ttl, ttl, rrsig, signer_obj, dnskey, my_node, valid, name_obj.analysis_end, rrsig_servers)

                        if dnskey is None:
                            continue

                        if (rrsig.signer, dnskey) not in servers_with_rrsig:
                            servers_with_rrsig[(rrsig.signer, dnskey)] = set()
                        servers_with_rrsig[(rrsig.signer, dnskey)].update(rrsig_servers)

                    algs_signing_rrset.add(rrsig.algorithm)

                for (signer, dnskey), servers in servers_with_rrsig.items():
                    if not servers:
                        continue
                    if signer != parent_obj.name:
                        continue

                    servers_without_rrsig = rrset_servers.difference(servers)
                    if servers_without_rrsig:
                        self.add_rrsig_non_existent(name, rrset.rdtype, signer, dnskey, my_node, servers_without_rrsig)

                if parent_obj.signed:
                    algs_not_signing_rrset = self.dnskey_algs_by_zone[zone_top].difference(algs_signing_rrset)
                    if not algs_signing_rrset:
                        self.notices['notices']['errors'].add((util.format.humanize_rrset(rrset, True),
                            'This RRset is not covered by any RRSIG.'))
                    elif algs_not_signing_rrset:
                        self.notices['notices']['errors'].add((util.format.humanize_rrset(rrset, True),
                            u'DNSKEYs exist for algorithm(s) %s in the %s zone, but the %s RRset was not signed by any DNSKEY with algorithm(s) %s.' % \
                                    (', '.join(map(str, self.dnskey_algs_by_zone[zone_top])), util.format.humanize_name(parent_obj.name, True), \
                                    util.format.humanize_rrset(rrset, True), ', '.join(map(str, algs_not_signing_rrset)))))

                if name.parent().is_subdomain(rrset.name):
                    synthesized_cname = util.dnsutil.cname_for_dname(name, rrset)
                    line_color = COLORS['secure']
                    sub_id = 0
                    if aliases_rrsets_rrsigs:
                        for cname_rrset, cname_rrset_servers, cname_rrsigs in aliases_rrsets_rrsigs:
                            my_sub_node = self.add_rrset(cname_rrset, cname_rrset.name, parent_obj, sub_id, cname_rrset_servers)
                            if cname_rrset[0].target != synthesized_cname:
                                #XXX raise error about name not matching
                                line_color = COLORS['bogus']
                            if cname_rrset.ttl not in (0, rrset.ttl):
                                #XXX raise error about TTL not matching
                                line_color = COLORS['bogus']
                            edge_id = 'dname-%s--%s--%s-%s' % (my_sub_node, my_node, line_color.lstrip('#'), 'solid')
                            self.G.add_edge(my_sub_node, my_node, id=edge_id, color=line_color, style='solid', dir='back')
                            sub_id += 1
                    if not aliases_rrsets_rrsigs or line_color != COLORS['secure']:
                        line_color = COLORS['secure']
                        cname_rrset = dns.rrset.RRset(name, dns.rdataclass.IN, dns.rdatatype.CNAME)
                        cname_rrset.update_ttl(rrset.ttl)
                        cname_rrset.add(dns.rdtypes.ANY.CNAME.CNAME(dns.rdataclass.IN, dns.rdatatype.CNAME, synthesized_cname))
                        my_sub_node = self.add_rrset(cname_rrset, cname_rrset.name, parent_obj, sub_id, [])
                        edge_id = 'dname-%s--%s--%s-%s' % (my_sub_node, my_node, line_color.lstrip('#'), 'solid')
                        self.G.add_edge(my_sub_node, my_node, id=edge_id, color=line_color, style='solid', dir='back')

                        aliases_rrsets_rrsigs.append((cname_rrset, [], []))

                else:
                    #XXX appropriately handle inappropriate at DNAME
                    continue

                id += 1

            self.processed_rrsets[(rrset.name, dns.rdatatype.DNAME)] = my_nodes

        id = 0
        if aliases_rrsets_rrsigs:
            for rrset, rrset_servers, rrsigs in aliases_rrsets_rrsigs:
                wildcard_name  = util.dnssec.reduce_wildcard(rrset, [r[0] for r in rrsigs])
                if wildcard_name is not None:
                    my_nodes.append(self.graph_denial_of_existence(name_obj, name, rr_type, parent_obj, nsec_rrsets_rrsigs, servers_responsive_for_rrset, wildcard_name.parent()))

                my_node = self.add_rrset(rrset, wildcard_name, parent_obj, id, rrset_servers)
                my_nodes.append(my_node)
                if rr_type in (dns.rdatatype.A, dns.rdatatype.AAAA, dns.rdatatype.PTR, dns.rdatatype.MX):
                    target_obj = name_obj.get_name(rrset[0].target, True)
                    if target_obj is not None:
                        cname_nodes = self.graph_rrset_auth(target_obj, target_obj.name, rr_type)
                        for cname_node in cname_nodes:
                            self.add_alias(my_node, cname_node)

                if (name, dns.rdatatype.CNAME) in self.processed_rrsets:
                    continue

                algs_signing_rrset = set()
                servers_with_rrsig = {}
                for rrsig, ttl, rrsig_servers in rrsigs:
                    signer_obj = name_obj.get_name(rrsig.signer, True)
                    if rrsig.signer != parent_obj.name:
                        self.graph_zone_auth(signer_obj, False)

                    for dnskey, valid in signer_obj.dnskeys_for_rrsig(rrsig, rrset, supported_dnssec_algorithms=self.dnssec_algorithms):
                        self.add_rrsig(name, parent_obj, rrset.ttl, ttl, rrsig, signer_obj, dnskey, my_node, valid, name_obj.analysis_end, rrsig_servers)

                        if dnskey is None:
                            continue

                        if (rrsig.signer, dnskey) not in servers_with_rrsig:
                            servers_with_rrsig[(rrsig.signer, dnskey)] = set()
                        servers_with_rrsig[(rrsig.signer, dnskey)].update(rrsig_servers)

                    algs_signing_rrset.add(rrsig.algorithm)

                for (signer, dnskey), servers in servers_with_rrsig.items():
                    if not servers:
                        continue
                    if signer != parent_obj.name:
                        continue

                    servers_without_rrsig = rrset_servers.difference(servers)
                    if servers_without_rrsig:
                        self.add_rrsig_non_existent(name, rrset.rdtype, signer, dnskey, my_node, servers_without_rrsig)

                if parent_obj.signed and not dname_rrsets_rrsigs:
                    algs_not_signing_rrset = self.dnskey_algs_by_zone[zone_top].difference(algs_signing_rrset)
                    if not algs_signing_rrset:
                        self.notices['notices']['errors'].add((util.format.humanize_rrset(rrset, True),
                            'This RRset is not covered by any RRSIG.'))
                    elif algs_not_signing_rrset:
                        self.notices['notices']['errors'].add((util.format.humanize_rrset(rrset, True),
                            u'DNSKEYs exist for algorithm(s) %s in the %s zone, but the %s RRset was not signed by any DNSKEY with algorithm(s) %s.' % \
                                    (', '.join(map(str, self.dnskey_algs_by_zone[zone_top])), util.format.humanize_name(parent_obj.name, True), \
                                    util.format.humanize_rrset(rrset, True), ', '.join(map(str, algs_not_signing_rrset)))))

                id += 1

            self.processed_rrsets[(name, dns.rdatatype.CNAME)] = my_nodes

        if rrsets_rrsigs:
            for rrset, rrset_servers, rrsigs in rrsets_rrsigs:
                # aliases and their targets were handled above
                if (rrset.name, rrset.rdtype) != (name, rr_type):
                    continue
                wildcard_name  = util.dnssec.reduce_wildcard(rrset, [r[0] for r in rrsigs])
                if wildcard_name is not None:
                    my_nodes.append(self.graph_denial_of_existence(name_obj, name, rr_type, parent_obj, nsec_rrsets_rrsigs, servers_responsive_for_rrset, wildcard_name.parent()))

                my_node = self.add_rrset(rrset, wildcard_name, parent_obj, id, rrset_servers)
                my_nodes.append(my_node)

                algs_signing_rrset = set()
                servers_with_rrsig = {}
                for rrsig, ttl, rrsig_servers in rrsigs:
                    signer_obj = name_obj.get_name(rrsig.signer, True)
                    if rrsig.signer != parent_obj.name:
                        self.graph_zone_auth(signer_obj, False)

                    for dnskey, valid in signer_obj.dnskeys_for_rrsig(rrsig, rrset, supported_dnssec_algorithms=self.dnssec_algorithms):
                        self.add_rrsig(name, parent_obj, rrset.ttl, ttl, rrsig, signer_obj, dnskey, my_node, valid, name_obj.analysis_end, rrsig_servers)
                        algs_signing_rrset.add(rrsig.algorithm)

                        if dnskey is None:
                            continue

                        if (rrsig.signer, dnskey) not in servers_with_rrsig:
                            servers_with_rrsig[(rrsig.signer, dnskey)] = set()
                        servers_with_rrsig[(rrsig.signer, dnskey)].update(rrsig_servers)

                    #XXX do something for unknown status

                for (signer, dnskey), servers in servers_with_rrsig.items():
                    if not servers:
                        continue
                    if signer != parent_obj.name:
                        continue

                    servers_without_rrsig = rrset_servers.difference(servers)
                    if servers_without_rrsig:
                        self.add_rrsig_non_existent(name, rrset.rdtype, signer, dnskey, my_node, servers_without_rrsig)

                if parent_obj.signed:
                    algs_not_signing_rrset = self.dnskey_algs_by_zone[zone_top].difference(algs_signing_rrset)
                    if not algs_signing_rrset:
                        self.notices['notices']['errors'].add((util.format.humanize_rrset(rrset, True),
                            'This RRset is not covered by any RRSIG.'))
                    elif algs_not_signing_rrset:
                        self.notices['notices']['errors'].add((util.format.humanize_rrset(rrset, True),
                            u'DNSKEYs exist for algorithm(s) %s in the %s zone, but the %s RRset was not signed by any DNSKEY with algorithm(s) %s.' % \
                                    (', '.join(map(str, self.dnskey_algs_by_zone[zone_top])), util.format.humanize_name(parent_obj.name, True), \
                                    util.format.humanize_rrset(rrset, True), ', '.join(map(str, algs_not_signing_rrset)))))

                id += 1

        elif servers_responsive_for_rrset:
            my_nodes.append(self.graph_denial_of_existence(name_obj, name, rr_type, parent_obj, nsec_rrsets_rrsigs, servers_responsive_for_rrset))

        self.processed_rrsets[(name, rr_type)] = my_nodes
        return my_nodes

    def graph_zone_auth(self, name_obj, is_dlv):
        if (name_obj.name, -1) in self.processed_rrsets:
            return
        self.processed_rrsets[(name_obj.name, -1)] = True

        zone_obj = name_obj.zone
        S, zone_graph_name, zone_bottom, zone_top = self.add_zone(zone_obj)

        #######################################
        # DNSKEY roles, based on what they sign
        #######################################
        all_dnskeys = name_obj.dnskey_set()

        ##########################
        # trust anchor definitions
        ##########################
        if name_obj.name in self.trusted_zones:
            if name_obj.name not in self.trusted_keys:
                self.trusted_keys[name_obj.name] = set()
            self.trusted_keys[name_obj.name].update(name_obj.potential_trusted_keys())
        trusted_keys_in_zone = self.trusted_keys.get(name_obj.name, set())
        existing_trusted_keys_in_zone = trusted_keys_in_zone.intersection(all_dnskeys)
        non_existent_trusted_keys_in_zone = trusted_keys_in_zone.difference(all_dnskeys)

        ds_algs_signing_dnskey_rrset = set()

        servers_responsive = name_obj.auth_servers()
        servers_responsive_for_dnskey = name_obj.get_servers_authoritative_for_query(name_obj.name, dns.rdatatype.DNSKEY)

        #XXX this needs to be fixed appropriately
        servers_without_dnskey = servers_responsive.difference(set([s[0] for s in servers_responsive_for_dnskey]))
        if all_dnskeys and servers_without_dnskey:
            empty_rrset = dns.rrset.RRset(name_obj.name, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
            self.notices['notices']['warnings'].add((util.format.humanize_rrset(empty_rrset, True),
                u'Unable to retrieve the %s RRset from server(s) %s.' % (util.format.humanize_rrset(empty_rrset, True), ', '.join(servers_without_dnskey))))

        max_payload_mapping = name_obj.get_max_payload()
        if max_payload_mapping:
            #XXX need to get this corrected--this is a hack
            real_payload_issues = dict(filter(lambda x: x[1][1] < 4096, max_payload_mapping.items()))
            if real_payload_issues:
                empty_rrset = dns.rrset.RRset(name_obj.name, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
                max_payload_low, max_payload_high = real_payload_issues.items()[0][1]
                self.notices['notices']['warnings'].add((util.format.humanize_rrset(empty_rrset, True), 'Server(s) %s are attempting to send a payload that exceeds their path MTU (between %d and %d bytes).  Some resolvers may not be able to properly receive the DNSKEY RRset with its covering RRSIGs.' % \
                        (', '.join(real_payload_issues.keys()), max_payload_low, max_payload_high)))

        # Add DNSKEY nodes to graph
        for dnskey in all_dnskeys:
            trust_anchor = dnskey in existing_trusted_keys_in_zone

            servers_with_dnskey = name_obj.servers_with_dnskey(dnskey)
            servers_without_dnskey = servers_responsive_for_dnskey.difference(servers_with_dnskey)

            #XXX TTL is generic; doesn't consider different DNSKEY RRsets on different servers
            dnskey_node = self.add_dnskey(name_obj, dnskey, name_obj.ttl_mapping[dns.rdatatype.DNSKEY], trust_anchor, servers_with_dnskey, servers_without_dnskey)

        dnskey_rrsets_rrsigs = name_obj.get_aggregated_responses(name_obj.name, dns.rdatatype.DNSKEY)[0]
        for dnskey_rrset, rrset_servers, rrsigs in dnskey_rrsets_rrsigs:
            algs_in_this_rrset = set([k.algorithm for k in dnskey_rrset])
            algs_signing_rrset = set()
            servers_with_rrsig = {}

            signed_keys = all_dnskeys.intersection(set(dnskey_rrset))

            for rrsig, ttl, rrsig_servers in rrsigs:
                signer_obj = name_obj.get_name(rrsig.signer, True)
                if rrsig.signer != name_obj.name:
                    self.graph_zone_auth(signer_obj, False)

                for dnskey, valid in signer_obj.dnskeys_for_rrsig(rrsig, dnskey_rrset, supported_dnssec_algorithms=self.dnssec_algorithms):
                    if dnskey is None:
                        dnskey_node = None
                    else:
                        dnskey_node = self.get_dnskey(self.id_for_dnskey(signer_obj.name, dnskey), signer_obj.name, dnskey.algorithm, util.dnssec.key_tag(dnskey))

                    for signed_key in signed_keys:
                        signed_key_node = self.get_dnskey(self.id_for_dnskey(name_obj.name, signed_key), name_obj.name, signed_key.algorithm, util.dnssec.key_tag(signed_key))
                        self.add_rrsig(name_obj.name, name_obj, dnskey_rrset.ttl, ttl, rrsig, signer_obj, dnskey, signed_key_node, valid, name_obj.analysis_end, rrsig_servers)

                    if dnskey is None:
                        continue

                    if (rrsig.signer, dnskey) not in servers_with_rrsig:
                        servers_with_rrsig[(rrsig.signer, dnskey)] = set()
                    servers_with_rrsig[(rrsig.signer, dnskey)].update(rrsig_servers)

                algs_signing_rrset.add(rrsig.algorithm)

            #XXX this isn't entirely accurate, but it will fit most cases
            for (signer, dnskey), servers in servers_with_rrsig.items():
                if not servers:
                    continue
                if signer != zone_obj.name:
                    continue

                servers_without_rrsig = rrset_servers.difference(servers)
                if servers_without_rrsig:
                    signed_key_node = self.get_dnskey(self.id_for_dnskey(name_obj.name, dnskey), name_obj.name, dnskey.algorithm, util.dnssec.key_tag(dnskey))
                    self.add_rrsig_non_existent(name_obj.name, dnskey_rrset.rdtype, signer, dnskey, signed_key_node, servers_without_rrsig)

                    for signed_key in signed_keys:
                        signed_key_node = self.get_dnskey(self.id_for_dnskey(name_obj.name, signed_key), name_obj.name, signed_key.algorithm, util.dnssec.key_tag(signed_key))
                        self.add_rrsig_non_existent(name_obj.name, dnskey_rrset.rdtype, signer, dnskey, signed_key_node, servers_without_rrsig)

            if zone_obj.signed:
                algs_not_signing_rrset = algs_in_this_rrset.difference(algs_signing_rrset)
                if not algs_signing_rrset:
                    self.notices['notices']['errors'].add((util.format.humanize_rrset(dnskey_rrset, True),
                            'This RRset is not covered by any RRSIG.'))
                elif algs_not_signing_rrset:
                    self.notices['notices']['errors'].add((util.format.humanize_rrset(dnskey_rrset, True),
                        u'DNSKEYs exist for algorithm(s) %s in the %s zone, but the %s RRset was not signed by any DNSKEY with algorithm(s) %s.' % \
                                (', '.join(map(str, self.dnskey_algs_by_zone[zone_top])), util.format.humanize_name(name_obj.name, True), \
                                util.format.humanize_rrset(dnskey_rrset, True), ', '.join(map(str, algs_not_signing_rrset)))))

        if not name_obj.is_zone():
            return

        # Add non-existent trust anchors to graph
        for dnskey in non_existent_trusted_keys_in_zone:
            dnskey_node = self.add_dnskey_non_existent(name_obj, dnskey.algorithm, util.dnssec.key_tag(dnskey), True)

        if name_obj.parent is None or is_dlv:
            return

        for dlv in False, True:
            # if this is a DLV parent, and either we're not showing
            # DLV, or there is no DLV information for this zone, move along
            if dlv:
                parent_obj = name_obj.dlv
                ds_name = name_obj.dlv_name()
                rdtype = dns.rdatatype.DLV
            else:
                parent_obj = name_obj.parent
                ds_name = name_obj.name
                rdtype = dns.rdatatype.DS

            if parent_obj is None or ds_name is None:
                continue

            ds_rrsets_rrsigs, ds_neg_responses, ds_dname_rrsets_rrsigs, ds_nsec_rrsets_rrsigs = name_obj.get_aggregated_responses(ds_name, rdtype)

            if dlv and (not self.show_dlv or not ds_rrsets_rrsigs):
                continue

            self.graph_zone_auth(parent_obj, dlv)

            P, parent_graph_name, parent_bottom, parent_top = self.add_zone(parent_obj)

            servers_responsive_for_ds = name_obj.get_servers_authoritative_for_query(ds_name, rdtype)

            # iterate over all distinct (algorithm,key_tag) pairs.
            # this is to consolidate DS RRs into a single node, where possible
            if ds_rrsets_rrsigs and filter(lambda x: x[0][0].rdtype == rdtype, ds_rrsets_rrsigs):
                del_line_color = COLORS['bogus']
                del_line_style = 'dashed'
                for ds_rrset, rrset_servers, rrsigs in ds_rrsets_rrsigs:
                    ds_mappings = util.dnssec.ds_by_dnskey(name_obj.name, ds_rrset, dnskey_rrsets_rrsigs, supported_ds_algorithms=self.ds_algorithms)

                    algs_signing_rrset = set()
                    servers_with_rrsig = {}
                    ds_nodes = []
                    for (alg, key_tag, dnskey), ds_tuple in ds_mappings.items():
                        # if there are different hash results, they must be
                        # individually distinguished
                        if len(set([valid for d, valid in ds_tuple])) > 1:
                            ds_set = [([ds], valid) for ds, valid in ds_tuple]
                        # otherwise lump them all into a single DS node
                        else:
                            ds_set = [([ds for ds, valid in ds_tuple], list(ds_tuple)[0][1])]

                        # create each DS node
                        for ds, valid in ds_set:
                            if dlv:
                                servers_with_ds = name_obj.servers_with_ds(ds, True)
                            else:
                                servers_with_ds = name_obj.servers_with_ds(ds)
                            servers_without_ds = servers_responsive_for_ds.difference(servers_with_ds)

                            ds_node = self.add_ds(ds_name, ds, rdtype, ds_rrset.ttl, name_obj, parent_obj, servers_with_ds, servers_without_ds)
                            ds_nodes.append(ds_node)

                            #XXX move this all into the ds_map method
                            # if there are no mappings to the DS, then add a non_existent_key edge
                            if dnskey is None:
                                dnskey_node = self.add_dnskey_non_existent(name_obj, ds[0].algorithm, ds[0].key_tag, False)
                                edge_id = 'digest-%s--%s--%s-%s' % (dnskey_node, ds_node, COLORS['warnings'].lstrip('#'), 'dashed')
                                self.G.add_edge(dnskey_node, ds_node, id=edge_id, color=COLORS['warnings'], style='dashed', dir='back')

                                self.node_info[edge_id] = {}
                                self.node_info[edge_id]['description'] = self.node_info[ds_node]['description'][:]
                                self.node_info[edge_id]['description'].extend([('Digest', '<strong>unknown</strong>'), ('Status', u'<strong>unknown</strong>: The DS RR(s) do not correspond to any DNSKEY in the %s zone.' % util.format.humanize_name(name_obj.name, True))])
                                self.node_info[edge_id]['status'] = 'unknown'

                                self.notices['notices']['warnings'].add((util.format.humanize_ds(ds_name, ds, rdtype, True), u'The DS RR(s) do not correspond to any DNSKEY in the %s zone.' % util.format.humanize_name(name_obj.name, True)))

                                revoke = False
                            else:
                                revoke = bool(dnskey.flags & util.format.DNSKEY_FLAGS['revoke'])
                                dnskey_node = self.get_dnskey(self.id_for_dnskey(name_obj.name, dnskey), name_obj.name, dnskey.algorithm, util.dnssec.key_tag(dnskey))

                                # otherwise add mappings to the DNSKEYs
                                if self.add_ds_map(ds_name, ds, ds_node, dnskey_node, revoke, rdtype, valid):
                                    #XXX do we want this to be a valid_self_loop, or just self_loop
                                    self_loop = False
                                    for e in self.G.out_edges(dnskey_node) + self.G.in_edges(dnskey_node):
                                        if (dnskey_node,dnskey_node) == e and 'solid' in e.attr['style'].split(','):
                                            self_loop = True
                                            break
                                    if self_loop:
                                        ds_algs_signing_dnskey_rrset.add(ds[0].algorithm)
                                        del_line_color = COLORS['secure']
                                        del_line_style = 'solid'

                            for rrsig, ttl, rrsig_servers in rrsigs:
                                signer_obj = name_obj.get_name(rrsig.signer, True)
                                if rrsig.signer != parent_obj.name:
                                    self.graph_zone_auth(signer_obj, False)

                                for signing_dnskey, valid_sig in signer_obj.dnskeys_for_rrsig(rrsig, ds_rrset, supported_dnssec_algorithms=self.dnssec_algorithms):
                                    self.add_rrsig(ds_name, parent_obj, ds_rrset.ttl, ttl, rrsig, signer_obj, signing_dnskey, ds_node, valid_sig, name_obj.analysis_end, rrsig_servers)

                                    if signing_dnskey is None:
                                        continue

                                    if (rrsig.signer, signing_dnskey) not in servers_with_rrsig:
                                        servers_with_rrsig[(rrsig.signer, signing_dnskey)] = set()
                                    servers_with_rrsig[(rrsig.signer, signing_dnskey)].update(rrsig_servers)

                                algs_signing_rrset.add(rrsig.algorithm)

                    for (signer, signing_dnskey), servers in servers_with_rrsig.items():
                        if not servers:
                            continue
                        if signer != parent_obj.name:
                            continue

                        servers_without_rrsig = rrset_servers.difference(servers)
                        if servers_without_rrsig:
                            for my_node in ds_nodes:
                                self.add_rrsig_non_existent(ds_rrset.name, ds_rrset.rdtype, signer, signing_dnskey, my_node, servers_without_rrsig)

                    if parent_obj.signed:
                        algs_not_signing_rrset = self.dnskey_algs_by_zone[parent_top].difference(algs_signing_rrset)
                        if not algs_signing_rrset:
                            self.notices['notices']['errors'].add((util.format.humanize_rrset(ds_rrset, True),
                                    'This RRset is not covered by any RRSIG.'))
                        elif algs_not_signing_rrset:
                            self.notices['notices']['errors'].add((util.format.humanize_rrset(ds_rrset, True),
                                u'DNSKEYs exist for algorithm(s) %s in the %s zone, but the %s RRset was not signed by any DNSKEY with algorithm(s) %s.' % \
                                        (', '.join(map(str, self.dnskey_algs_by_zone[zone_top])), util.format.humanize_name(parent_obj.name, True), \
                                        util.format.humanize_rrset(ds_rrset, True), ', '.join(map(str, algs_not_signing_rrset)))))

                ds_algs = set([d[0] for d in self.ds_algs.get((zone_top, parent_top), set())])
                ds_algs_not_signing_dnskey_rrset = ds_algs.difference(ds_algs_signing_dnskey_rrset)
                if dnskey_rrsets_rrsigs and ds_algs_not_signing_dnskey_rrset:
                    self.notices['notices']['errors'].add((util.format.humanize_rrset(dnskey_rrset, True),
                        u'DS RRs exist for algorithm(s) %s in the %s zone, but no matching DNSKEYs of algorithm(s) %s were used to sign the %s DNSKEY RRset.' % \
                                (', '.join(map(str, ds_algs)), util.format.humanize_name(parent_obj.name, True),
                                    ', '.join(map(str, ds_algs_not_signing_dnskey_rrset)), util.format.humanize_name(name_obj.name, True))))

                if not ds_algs:
                    del_line_color = COLORS['insecure']
                    del_line_style = 'solid'
                    self.notices['delegation status']['insecure'].add((u'%s to %s' % (util.format.humanize_name(parent_obj.name, True), util.format.humanize_name(name_obj.name, True)), None))
                elif del_line_color == COLORS['secure']:
                    self.notices['delegation status']['secure'].add((u'%s to %s' % (util.format.humanize_name(parent_obj.name, True), util.format.humanize_name(name_obj.name, True)), None))
                else:
                    self.notices['delegation status']['bogus'].add((u'%s to %s' % (util.format.humanize_name(parent_obj.name, True), util.format.humanize_name(name_obj.name, True)), None))

            elif ds_nsec_rrsets_rrsigs:
                covered = False

                ds_nxdomain = name_obj.is_nxdomain(ds_name, rdtype)

                servers_with_nsec = {}
                all_servers_with_nsec = set()
                for nsec_tuple, rrset_servers in ds_nsec_rrsets_rrsigs:
                    id = self.id_for_nsec(ds_name, ds_nsec_rrsets_rrsigs[0][0][0][1].rdtype, True, nsec_tuple)
                    if id not in servers_with_nsec:
                        servers_with_nsec[id] = set()
                    servers_with_nsec[id].update(rrset_servers)
                    all_servers_with_nsec.update(rrset_servers)
                servers_without_nsec = servers_responsive_for_ds.difference(all_servers_with_nsec)

                edge_id = 0
                for nsec_tuple, rrset_servers in ds_nsec_rrsets_rrsigs:
                    id = self.id_for_nsec(ds_name, ds_nsec_rrsets_rrsigs[0][0][0][1].rdtype, True, nsec_tuple)

                    nsec_node = self.add_nsec(ds_nsec_rrsets_rrsigs[0][0][0][1].rdtype, id, ds_name, rdtype, parent_obj.name, nsec_tuple, servers_with_nsec[id], servers_without_nsec)

                    nsec_rrsets = [t[1] for t in nsec_tuple]

                    if util.nsec.validate_nsec_covering(ds_name, rdtype, parent_obj.name, nsec_rrsets):
                        line_color = COLORS['secure']
                        covered = True
                    else:
                        line_color = COLORS['bogus']
                        self.notices['notices']['errors'].add((u'%s to %s' % (util.format.humanize_name(parent_obj.name, True), util.format.humanize_name(name_obj.name, True)),
                            u'The NSEC or NSEC3 RRs are insufficient to prove non-existence of %s RRs for %s.' % (dns.rdatatype.to_text(rdtype), util.format.humanize_name(name_obj.name, True))))

                    if not filter(lambda x: x[1] == nsec_node and x.attr['color'] == line_color, self.G.out_edges(zone_top)):
                        self.G.add_edge(zone_top, nsec_node, ltail=zone_graph_name, color=line_color, dir='back')

                    for nsec_name, nsec_rrset, rrsigs in nsec_tuple:
                        algs_signing_rrset = set()
                        servers_with_rrsig = {}
                        for rrsig, ttl in rrsigs:
                            signer_obj = name_obj.get_name(rrsig.signer, True)
                            if rrsig.signer != parent_obj.name:
                                self.graph_zone_auth(signer_obj, dlv)

                            for dnskey, valid in signer_obj.dnskeys_for_rrsig(rrsig, nsec_rrset, supported_dnssec_algorithms=self.dnssec_algorithms):
                                self.add_rrsig(nsec_name, parent_obj, nsec_rrset.ttl, ttl, rrsig, signer_obj, dnskey, nsec_node, valid, name_obj.analysis_end, rrset_servers, combine_edge_id=edge_id)

                                if dnskey is None:
                                    continue

                                if (rrsig.signer, dnskey) not in servers_with_rrsig:
                                    servers_with_rrsig[(rrsig.signer, dnskey)] = set()
                                servers_with_rrsig[(rrsig.signer, dnskey)].update(rrset_servers)

                            algs_signing_rrset.add(rrsig.algorithm)

                        for (signer, dnskey), servers in servers_with_rrsig.items():
                            if not servers:
                                continue
                            if signer != parent_obj.name:
                                continue

                            servers_without_rrsig = rrset_servers.difference(servers)
                            if servers_without_rrsig:
                                self.add_rrsig_non_existent(nsec_rrset.name, nsec_rrset.rdtype, signer, dnskey, nsec_node, servers_without_rrsig)

                        if parent_obj.signed:
                            algs_not_signing_rrset = self.dnskey_algs_by_zone[parent_top].difference(algs_signing_rrset)
                            if not algs_signing_rrset:
                                self.notices['notices']['errors'].add((util.format.humanize_rrset(nsec_rrset, True),
                                        'This RRset is not covered by any RRSIG.'))
                            elif algs_not_signing_rrset:
                                self.notices['notices']['errors'].add((util.format.humanize_rrset(nsec_rrset, True),
                                    u'DNSKEYs exist for algorithm(s) %s in the %s zone, but the %s RRset was not signed by any DNSKEY with algorithm(s) %s.' % \
                                            (', '.join(map(str, self.dnskey_algs_by_zone[zone_top])), util.format.humanize_name(parent_obj.name, True), \
                                            util.format.humanize_rrset(nsec_rrset, True), ', '.join(map(str, algs_not_signing_rrset)))))

                    edge_id += 1

                if covered:
                    if ds_nxdomain:
                        del_line_color = COLORS['misconfigured']
                        del_line_style = 'dashed'

                        self.notices['delegation status']['misconfigured'].add((u'%s to %s' % (util.format.humanize_name(parent_obj.name, True), util.format.humanize_name(name_obj.name, True)),
                            u'There are no delegation (NS-type) RRs for %s in %s.  As such %s authoritative servers return NXDOMAIN in response to DS queries for %s, indicating that the subdomain space does not exist.' % (util.format.humanize_name(name_obj.name, True), util.format.humanize_name(parent_obj.name, True), util.format.humanize_name(parent_obj.name, True), util.format.humanize_name(name_obj.name, True))))
                    else:
                        del_line_color = COLORS['insecure']
                        del_line_style = 'solid'
                        self.notices['delegation status']['insecure'].add((u'%s to %s' % (util.format.humanize_name(parent_obj.name, True), util.format.humanize_name(name_obj.name, True)), None))

                else:
                    del_line_color = COLORS['bogus']
                    del_line_style = 'dashed'

                    self.notices['delegation status']['bogus'].add((u'%s to %s' % (util.format.humanize_name(parent_obj.name, True), util.format.humanize_name(name_obj.name, True)),
                        u'There are no DS RRs for %s in %s, but the NSEC or NSEC3 RRs supplied were insufficient to prove their non-existence.' % (util.format.humanize_name(name_obj.name, True), util.format.humanize_name(parent_obj.name, True))))

            elif parent_obj.signed:
                del_line_color = COLORS['bogus']
                del_line_style = 'dashed'

                if parent_obj.nsec_rdtype is None:
                    nsec_rdtype = dns.rdatatype.NSEC
                else:
                    nsec_rdtype = parent_obj.nsec_rdtype
                nsec_node = self.add_nsec(nsec_rdtype, 1, ds_name, rdtype, parent_obj.name, (), set(), set(), exists=False)
                self.G.add_edge(zone_top, nsec_node, ltail=zone_graph_name, color=COLORS['bogus'], style='dashed', dir='back')

                self.notices['delegation status']['bogus'].add((u'%s to %s' % (util.format.humanize_name(parent_obj.name, True), util.format.humanize_name(name_obj.name, True)),
                    u'There are no DS RRs for %s in %s, but no %s RRs were supplied to prove their non-existence.' % (util.format.humanize_name(name_obj.name, True), util.format.humanize_name(parent_obj.name, True), dns.rdatatype.to_text(nsec_rdtype))))

            else:
                del_line_color = COLORS['insecure']
                del_line_style = 'solid'
                self.notices['delegation status']['insecure'].add((u'%s to %s' % (util.format.humanize_name(parent_obj.name, True), util.format.humanize_name(name_obj.name, True)), None))

            # graph the parent
            self.G.add_edge(zone_top, parent_bottom, color=del_line_color, penwidth='5.0', ltail=zone_graph_name, lhead=parent_graph_name, style=del_line_style, minlen='2', dir='back')

    def add_trust(self, dlv_name):
        self.processed_nodes = {}
        trusted_keys = self.trusted_keys.copy()

        if dlv_name in trusted_keys:
            dlv_tuple_extension = [(dlv_name, trusted_keys[dlv_name])]
            del trusted_keys[dlv_name]
        else:
            dlv_tuple_extension = []

        trusted_zone_top_names = set([self.get_zone(z)[3] for z in trusted_keys])
        for zone, dnskeys in trusted_keys.items() + dlv_tuple_extension:
            zone_top_name = self.get_zone(zone)[3]
            self.G.get_node(zone_top_name).attr['color'] = ''
            dnskeys_with_known_algorithms = filter(lambda x: x.algorithm in self.dnssec_algorithms, dnskeys)
            if not dnskeys_with_known_algorithms:
                self.G.get_node(zone_top_name).attr['color'] = COLORS['insecure']
            for dnskey in dnskeys:
                try:
                    n = self.get_dnskey(self.id_for_dnskey(zone, dnskey), zone, dnskey.algorithm, util.dnssec.key_tag(dnskey))
                    self._add_trust_to_nodes_in_chain(n, dlv_name, trusted_zone_top_names, [])
                except KeyError:
                    pass

        # now traverse clusters and mark insecure nodes in secure delegations as bad
        for zone in set(self.trusted_keys).union(self.trusted_zones):
            if self.has_zone(zone):
                self._add_trust_to_orphaned_nodes(self.zone_node_str(zone), [])

        for n in self.G.nodes():
            if n.attr['color'] == COLORS['secure']:
                status = 'secure'
            elif n.attr['color'] == COLORS['bogus']:
                status = 'bogus'
            elif n.attr['fillcolor'] == COLORS['warnings_light']:
                status = 'non-existent'
            else:
                status = 'insecure'

            node_name = n
            if n.attr['shape'] in ('ellipse', 'diamond'):
                cat = 'DNSKEY/DS/NSEC status'
                # skip non-existent keys
                if n.startswith('DNSKEY-'):
                    vals = n.split('-')
                    alg = int(vals[-2])
                    id = int(vals[-1])
                    name = util.format.humanize_name(dns.name.from_text('-'.join(vals[2:-2])), True)
                    node_name = '%s/DNSKEY (alg %d, id %d)' % (name, alg, id)
                elif n.startswith('DS-') or n.startswith('DLV-'):
                    vals = n.split('-')
                    ds_type = vals[0]
                    name = util.format.humanize_name(dns.name.from_text('-'.join(vals[2:-3])), True)
                    node_name = '%s/%s' % (name, ds_type)
                elif n.startswith('NSEC'):
                    vals = n.split('-')
                    nsec_type = vals[0]
                    name = util.format.humanize_name(dns.name.from_text('-'.join(vals[2:-1])), True)
                    covering_rr_type = vals[-1]
                    node_name = u'%s proving non-existence of %s/%s' % (nsec_type, name, covering_rr_type)
            elif n.attr['shape'] == 'rectangle':
                cat = 'RRset status'
                vals = n.split('-')
                name = util.format.humanize_name(dns.name.from_text('-'.join(vals[2:-1])), True)
                rr_type = vals[-1]
                node_name = u'%s/%s' % (name, rr_type)
            else:
                continue

            node_id = n.replace('*', '_')

            self.node_info[node_id]['status'] = status
            self.notices[cat][status].add((node_name,None))

            if n.attr['color'] in (COLORS['secure'], COLORS['bogus']) and \
                    n.attr['fillcolor'] == COLORS['warnings_light']:
                self.notices[cat]['non-existent'].add((node_name,None))
                status += ', non-existent'

            self.node_info[node_id]['description'].append(('Status', '<strong>%s</strong>' % status))

    def _add_trust_to_nodes_in_chain(self, n, dlv_name, trusted_zones, trace):
        #XXX if the parent is insecure, but the DLV is broken (i.e., expired RRSIGs), how do we solve that?
        if n in trace:
            return

        is_ds = n.startswith('DS-') or n.startswith('DLV-')
        is_dlv = n.startswith('DLV-')
        is_dnskey = n.startswith('DNSKEY-')
        is_nsec = n.startswith('NSEC')
        is_dname = n.endswith('-DNAME')

        # if n isn't a DNSKEY, DS/DLV, or NSEC record,
        # then don't follow back edges
        if not (is_ds or is_dnskey or is_nsec or is_dname):
            return

        # don't follow back
        if is_dnskey:
            dnssec_algorithm = int(n.split('-')[-2])
        if is_ds:
            dnssec_algorithm = int(n.split('-')[-3])
            digest_algorithms = set(map(int, n.split('-')[-1].split('_')))

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
            return

        for e in self.G.in_edges(n):
            p = e[0]

            style = e.attr['style'].split(',')
            # if this is the edge to a non-existent key, then don't follow it
            if 'dashed' in style or 'invis' in style: 
                continue

            prev_top_name = self.G.get_node(self.node_subgraph_name[p])

            if is_ds:
                if prev_top_name in trusted_zones:
                    continue

                insecure_delegation = True
                for digest_algorithm in digest_algorithms:
                    if (dnssec_algorithm, digest_algorithm) in self.ds_algs[(prev_top_name, top_name)]:
                        insecure_delegation = False
                        break

                if insecure_delegation:
                    if prev_top_name.attr['color'] not in (COLORS['secure'], COLORS['insecure']):
                        if node_trusted:
                            prev_top_name.attr['color'] = COLORS['insecure']
                    continue

            if p.attr['color'] == COLORS['secure']:
                continue

            prev_node_trusted = node_trusted and e.attr['color'] == COLORS['secure']

            # If this is a SEP node, and the top_name hasn't been
            # marked as secure, then enter here
            if is_ds:
                valid_self_loop = False
                if self.G.has_edge(p,p):
                    for e1 in self.G.out_edges(p) + self.G.in_edges(p):
                        if (p,p) == e1 and \
                                e1.attr['color'] == COLORS['secure']:
                            valid_self_loop = True
                            break

                prev_node_trusted = prev_node_trusted and valid_self_loop

                if prev_node_trusted:
                    prev_top_name.attr['color'] = COLORS['secure']

            if is_nsec:
                if prev_node_trusted:
                    prev_is_rrset = p.attr['shape'] == 'rectangle'
                    if prev_is_rrset:
                        p.attr['color'] = COLORS['secure']
                    elif p.attr['color'] != COLORS['secure']:
                        if not self.G.has_edge(prev_top_name, '%s_bottom' % (self.zone_node_str(dlv_name))):
                            p.attr['color'] = COLORS['insecure']

            elif prev_node_trusted:
                p.attr['color'] = COLORS['secure']

            self._add_trust_to_nodes_in_chain(p, dlv_name, trusted_zones, trace+[n])

    def _add_trust_to_orphaned_nodes(self, subgraph_name, trace):
        if subgraph_name in trace:
            return

        top_name = self.G.get_node(subgraph_name + '_top')
        bottom_name = self.G.get_node(subgraph_name + '_bottom')

        if top_name.attr['color'] == COLORS['insecure']:
            return

        S = self.G.get_subgraph(subgraph_name)
        for n in S.nodes():
            # if node is non-existent, then continue, unless we are talking about an RRset
            if n.attr['fillcolor'] == COLORS['warnings_light'] and n.attr['shape'] != 'rectangle':
                continue

            # if the name is already marked as trusted or bogus, then leave it alone
            if n.attr['color'] == COLORS['secure']:
                continue

            n.attr['color'] = COLORS['bogus']

        for p in self.G.predecessors(bottom_name):
            e = self.G.get_edge(p, bottom_name)
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
            published_dnskeys = set()
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
                non_existent = n.attr['fillcolor'] == COLORS['warnings_light']

                self_sig_missing = False
                vals = n.split('-')
                alg = int(vals[-2])
                id = int(vals[-1])
                name = '-'.join(vals[2:-2])
                node_name = '%s/DNSKEY (alg %d, id %d)' % (name, alg, id)

                if is_ksk:
                    ksks.add(n)
                if is_zsk:
                    zsks.add(n)
                if not (is_ksk or is_zsk):
                    published_dnskeys.add(n)
                if n.attr['peripheries'] == '2':
                    ta_dnskeys.add(n)
                    if not is_ksk and not non_existent:
                        self.notices['notices']['errors'].add((node_name, 'A trust anchor must sign the DNSKEY RRset to provide secure entry into the trusted zone.'))
                        self_sig_missing = True
                if ds_edges:
                    ds_dnskeys.add(n)
                    if not is_ksk and is_zsk and not non_existent:
                        self.notices['notices']['errors'].add((node_name, 'For a key to provide secure entry into a zone, it must be used to sign the DNSKEY RRset.'))
                        self_sig_missing = True
                if n.attr['penwidth'] == '4.0':
                    revoked_dnskeys.add(n)
                    if not is_ksk:
                        self.notices['notices']['errors'].add((node_name, 'To properly revoke a key, it must be used to sign the DNSKEY RRset in addition to having the revoke bit set.'))
                        self_sig_missing = True
                if non_existent:
                    non_existent_dnskeys.add(n)
                
                if self_sig_missing:
                    #XXX find a way to do this using DNSAuthGraph
                    self.G.add_edge(n, n, color=COLORS['errors'], style='dashed', dir='back')

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

            for k in published_dnskeys.difference(non_existent_dnskeys):
                k.attr['style'] += ',dashed'

