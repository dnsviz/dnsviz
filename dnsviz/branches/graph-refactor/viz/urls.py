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

from django.conf.urls.defaults import *
from django.contrib.staticfiles.urls import staticfiles_urlpatterns

_encoded_slash = r'S'
_dns_label_first_char = r'[_a-z0-9]'
_dns_label_middle_char = r'[_a-z0-9-]|(%s)' % _encoded_slash
_dns_label_last_char = _dns_label_first_char
_dns_label = r'((%s)(%s)*(%s))|(%s)' % \
        (_dns_label_first_char, _dns_label_middle_char, _dns_label_last_char,
            _dns_label_first_char)
dns_name = r'(%s)(\.(%s))*' % (_dns_label, _dns_label)

timestamp = r'[a-zA-Z0-9-_]{6}'

ip_chars = r'[0-9a-fA-F:\.]{,39}'

urlpatterns = patterns('viz.views',
        (r'^d/(?P<name>%s)/(?P<url_subdir>(dnssec|responses|servers)/)?$' % dns_name, 'domain_view'),
        (r'^d/(?P<name>%s)/(?P<url_subdir>dnssec)/(?P<url_file>auth_graph)\.(?P<format>png|jpg|svg|dot|js)$' % dns_name, 'dnssec_info'),
        (r'^d/(?P<name>%s)/(?P<url_subdir>dnssec)/(?P<url_file>notices)\.(?P<format>xml|json)$' % dns_name, 'dnssec_info'),
        (r'^d/(?P<name>%s)/info\.(?P<format>xml|json)$' % dns_name, 'info_view'),

        (r'^d/(?P<name>%s)/(?P<url_subdir>cache/)$' % dns_name, 'analyze_cache'),
        (r'^d/(?P<name>%s)/(?P<url_subdir>analyze/)$' % dns_name, 'analyze'),

        (r'^d/(?P<name>%s)/(?P<timestamp>%s)/(?P<url_subdir>(dnssec|responses|servers)/)?$' % (dns_name, timestamp), 'domain_view'),
        (r'^d/(?P<name>%s)/(?P<timestamp>%s)/(?P<url_subdir>dnssec/)(?P<url_file>auth_graph)\.(?P<format>png|jpg|svg|dot|js)$' % (dns_name, timestamp), 'dnssec_info'),
        (r'^d/(?P<name>%s)/(?P<timestamp>%s)/(?P<url_subdir>dnssec/)(?P<url_file>notices)\.(?P<format>xml|json)$' % (dns_name, timestamp), 'dnssec_info'),
        (r'^d/(?P<name>%s)/(?P<timestamp>%s)/info\.(?P<format>xml|json)$' % (dns_name, timestamp), 'info_view'),
        (r'^d/(?P<name>%s)/(?P<timestamp>%s)/responses/(?P<qname>%s)/(?P<rdtype>[0-9]{1,5})/(?P<server>%s)/(?P<rd>t|f)(?P<do>t|f)(?P<cd>t|f)/(?P<client>%s)/$' % (dns_name, timestamp, dns_name, ip_chars, ip_chars), 'response_by_name_view'),

        (r'^d/(?P<name>%s)/(?P<timestamp>%s)/(?P<url_subdir>cache/)(?P<server>%s)/(?P<cache_timestamp>%s)/dnssec/$' % (dns_name, timestamp, ip_chars, timestamp), 'domain_view'),
        (r'^d/(?P<name>%s)/(?P<timestamp>%s)/(?P<url_subdir>cache/)(?P<server>%s)/(?P<cache_timestamp>%s)/dnssec/(?P<url_file>auth_graph)\.(?P<format>png|jpg|svg|dot|js)$' % (dns_name, timestamp, ip_chars, timestamp), 'dnssec_info'),
        (r'^d/(?P<name>%s)/(?P<timestamp>%s)/(?P<url_subdir>cache/)(?P<server>%s)/(?P<cache_timestamp>%s)/dnssec/(?P<url_file>notices)\.(?P<format>xml|json)$' % (dns_name, timestamp, ip_chars, timestamp), 'dnssec_info'),

        (r'^r/(?P<qname>%s)/(?P<rdtype>[0-9]{1,5})/(?P<server>%s)/(?P<rd>t|f)(?P<do>t|f)(?P<cd>t|f)/(?P<client>%s)/(?P<timestamp>%s)/$' % (dns_name, ip_chars, ip_chars, timestamp), 'response_view'),

        (r'^contact/$', 'contact'),
        (r'^search/$', 'domain_search'),
)
urlpatterns += patterns('django.views.generic.simple',
        (r'^$', 'direct_to_template', { 'template': 'main.html' } ),
        (r'^d/$', 'redirect_to', { 'url': '/'}),
        (r'^doc/$', 'direct_to_template', { 'template': 'doc.html' } ),
        (r'^doc/faq/$', 'direct_to_template', { 'template': 'faq.html' } ),
        (r'^doc/dnssec/$', 'direct_to_template', { 'template': 'dnssec_legend.html' } ),
        (r'^message_submitted/$', 'direct_to_template', { 'template': 'message_submitted.html' } ),
)

urlpatterns += staticfiles_urlpatterns()
