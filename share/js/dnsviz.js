/*
#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.  This file (or some portion thereof) is a
# derivative work authored by VeriSign, Inc., and created in 2014, based on
# code originally developed at Sandia National Laboratories.
# Created by Casey Deccio (casey@deccio.net)
#
# Copyright 2012-2014 Sandia Corporation. Under the terms of Contract
# DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government retains
# certain rights in this software.
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
*/

function AuthGraph(anchorElement, maxPaperWidth, imageScale) {
	this.anchorElement = anchorElement;
	this.maxPaperWidth = maxPaperWidth == undefined ? 0 : maxPaperWidth;
	this.imageScale = imageScale == undefined ? 1.4 : imageScale;
	this._label_map = {
		'rrsig': 'RRSIG',
		'nsec': 'NSEC',
		'nsec3': 'NSEC3',
		'cname': 'CNAME',
		'dname': 'DNAME',
		'dnskey': 'DNSKEY',
		'ds': 'DS',
		'dlv': 'DLV',
		'ttl': 'TTL',
		'rrset': 'RRset',
		'rdata': 'Record data',
	}
	this._dnssec_algorithms = {
		1: 'RSA/MD5',
		3: 'DSA/SHA1',
		5: 'RSA/SHA-1',
		6: 'DSA-NSEC3-SHA1',
		7: 'RSASHA1-NSEC3-SHA1',
		8: 'RSA/SHA-256',
		10: 'RSA/SHA-512',
		12: 'GOST R 34.10-2001',
		13: 'ECDSA Curve P-256 with SHA-256',
		14: 'ECDSA Curve P-384 with SHA-384',
	}
	this._digest_algorithms = {
		1: 'SHA-1',
		2: 'SHA-256',
		3: 'GOST R 34.11-94',
		4: 'SHA-384',
	}
}

AuthGraph.prototype.infoToHtmlTable = function (obj) {
	return '<table class="obj">' + this.infoToHtmlTableComponents(obj) + '</table>';
}

AuthGraph.prototype.infoToHtmlTableComponents = function (obj) {
	s = '';
	for (var key in obj) {
		val = obj[key];
		if (val == null) {
			continue;
		} else if (key.toLowerCase() in {'digest':null,'key':null,'signature':null,'dnskey':null}) {
			// don't print digest or key
			continue;
		} else if (key.toLowerCase() in {'rdata':null,'meta':null} && !val.hasOwnProperty('length')) {
			s += this.infoToHtmlTableComponents(val);
			continue;
		}

		s += '<tr><th valign="top" align="right">' + this.labelFromSlug(key) + ':</th><td align="left">';
		if (typeof val != "object") {
			s += val;
		} else if (val.hasOwnProperty("length")) {
			if (key.toLowerCase() in {'nsec':null,'nsec3':null} && !val.hasOwnProperty('object')) {
				var newval = [];
				var nsec_type = key.toLowerCase() == 'nsec' ? 'NSEC' : 'NSEC3';
				for (var i = 0; i < val.length; i++) {
					newval.push(val[i]['name'] + ' IN ' + nsec_type + ' ' + val[i]['rdata'][0]);
				};
				val = newval;
			}
			if (key.toLowerCase() in {'errors':null,'warnings':null}) {
				s += '<ul>';
				for (var i = 0; i < val.length; i++) {
					var servers_tags = [];
					s += '<li>' + val[i]['description'];
					if (val[i]['servers'] != undefined) {
						servers_tags = servers_tags.concat(val[i]['servers']);
					}
					if (val[i]['query_options'] != undefined) {
						servers_tags = servers_tags.concat(val[i]['query_options']);
					}
					if (servers_tags.length > 0) {
						s += ' (' + servers_tags.join(", ") + ')';
					}
					s += '</li>';
				}
				s += '</ul>';
			} else if (typeof val[0] in {'string':null,'number':null}) {
				if (key.toLowerCase() in {'servers':null,'digest_type':null}) {
					s += val.join(", ");
				} else {
					s += val.join("<br />");
				}
			} else {
				s += '<ul>';
				for (var i = 0; i < val.length; i++) {
					s += '<li>' + this.infoToHtmlTable(val[i]) + '</li>';
				}
				s += '</ul>';
			}
		} else {
			s += this.infoToHtmlTable(val);
		}
		s += '</td></tr>';
	}
	return s
}

AuthGraph.prototype.addNodeEvent = function (nodeObj, infoObj) {
	var statusStr;
	var s = '';
	if (infoObj.hasOwnProperty('length') && infoObj.length > 1) {
		statusStr = this.slugify(infoObj[0]['status']);
		s += '<ul>';
		for (var i = 0; i < infoObj.length; i++) {
			s += '<li>' + this.infoToHtmlTable(infoObj[i]) + '</li>';
		}
		s += '</ul>'
	} else {
		if (infoObj.hasOwnProperty('length')) {
			infoObj = infoObj[0];
		}
		statusStr = this.slugify(infoObj['status']);
		s += this.infoToHtmlTable(infoObj);
	}
	s = '<div class="dnsviz-' + statusStr + '">' + s + '</div>';

	$(nodeObj[0]).tooltip({ content: s, items: '*', track: true, show: false, hide: false });
	//$(nodeObj[0]).css('cursor', 'pointer');
}

if (typeof String.prototype.trim !== 'function') {
	String.prototype.trim = function() {
		return this.replace(/^\s+|\s+$/g, '');
	}
}

AuthGraph.prototype.labelFromSlug = function (str) {
	var labels = str.split(/_/);
	for (var i in labels) {
		var l = labels[i].toLowerCase();
		if (l in this._label_map) {
			labels[i] = this._label_map[l];
		}
	}
	labels[0] = labels[0].charAt(0).toUpperCase() + labels[0].slice(1);
	return labels.join(' ');
}

AuthGraph.prototype.slugify = function (str) {
	_slugify_strip_re = /[^\w_\s-]/g;
	_slugify_hyphenate_re = /[_\s-]+/g;
	str = str.replace(_slugify_strip_re, '').trim().toLowerCase();
	str = str.replace(_slugify_hyphenate_re, '-');
	return str;
}
