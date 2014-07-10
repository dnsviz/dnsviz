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

import logging
import re
from tempfile import TemporaryFile
import urllib
import xmlrpclib

import dns.name, dns.rdataclass, dns.rdatatype, dns.rrset

from django.conf import settings
from django.db import transaction
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.utils import simplejson
from django.utils.html import escape
from django.utils.timezone import now, utc
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import condition

from pygraphviz import AGraph

from dnsviz import analyst, util
from dnsviz.models import *

from dnssec import DNSAuthGraph
import urls
from forms import *

def _dnssec_options_form_data(request):
    values = {}

    dnssec_form_options = set(DNSSECOptionsForm.base_fields).intersection(set(request.GET))
    if dnssec_form_options:
        options_form = DNSSECOptionsForm(request.GET)
        if options_form.is_valid():
            values = options_form.cleaned_data.copy()
        else:
            for name, field in options_form.fields.items():
                if options_form[name].errors:
                    values[name] = field.initial
                else:
                    values[name] = options_form[name].data
            options_form2 = DNSSECOptionsForm(values)
            options_form2.is_valid()
            values = options_form2.cleaned_data.copy()

    else:
        options_form = DNSSECOptionsForm()
        for name, field in options_form.fields.items():
            values[name] = field.initial
        options_form = DNSSECOptionsForm(values)
        options_form.is_valid()
        values = options_form.cleaned_data.copy()

    return options_form, values

def dynamic_content_last_modified(*args, **kwargs):
    if settings.DEBUG:
        return None
    return settings.DYNAMIC_CONTENT_UPDATE

def domain_last_modified(request, name, *args, **kwargs): 
    timestamp = kwargs.get('timestamp', None)

    if settings.DEBUG:
        return None

    # only use last-modified if a timestamp was specified
    if timestamp is None:
        return None

    name = util.format.name_url_decode(name)
    date = util.format.datetime_url_decode(timestamp)
    name_obj = DomainNameAnalysis.objects.get(name, date)
    if name_obj is None:
        return None

    return max(settings.DYNAMIC_CONTENT_UPDATE, name_obj.analysis_end)

@condition(last_modified_func=domain_last_modified)
def info_view(request, name, format=None, timestamp=None):
    name = util.format.name_url_decode(name)
    if timestamp is None:
        name_obj = DomainNameAnalysis.objects.latest(name)
    else:
        date = util.format.datetime_url_decode(timestamp)
        name_obj = DomainNameAnalysis.objects.get(name, date)

    if name_obj is None:
        raise Http404

    data = {
        'navigation': {
            'current': {
                'updated': util.format.datetime_to_timestamp(name_obj.analysis_end),
                'url': name_obj.base_url_with_timestamp(),
            }
        },
    }
    if name_obj.previous is not None:
        data['navigation']['previous'] = {
            'updated': util.format.datetime_to_timestamp(name_obj.previous.analysis_end),
            'url': name_obj.previous.base_url_with_timestamp(),
        }
    if name_obj.next is not None:
        data['navigation']['next'] = {
            'updated': util.format.datetime_to_timestamp(name_obj.next.analysis_end),
            'url': name_obj.next.base_url_with_timestamp(),
        }
    if timestamp is None:
        if name_obj.name_obj.analysis_start is not None and \
                name_obj.name_obj.analysis_start > name_obj.analysis_end:
            data['next_analysis'] = {
                'start': util.format.datetime_to_timestamp(name_obj.name_obj.next_crawl_started),
                'state': 'Analyzing'
            }
        else:
            data['next_analysis'] = {
                'start': None,
                'state': 'Not analyzing'
            }

    if format == 'json':
        mimetype = 'application/javascript'
        serialized_data = simplejson.dumps(data)
    elif format == 'xml':
        mimetype = 'application/xml'
        serialized_data = xmlrpclib.dumps((data,), allow_none=True)
    else:
        raise Exception('Unknown ajax type!')

    return HttpResponse(serialized_data, mimetype)

def reset_query_string(request):
    return HttpResponseRedirect(request.path)

@condition(last_modified_func=domain_last_modified)
def domain_view(request, name, timestamp=None, url_subdir='', **kwargs):
    if 'reset_query' in request.GET:
        return reset_query_string(request)

    name = util.format.name_url_decode(name)
    if 'date_search' in request.GET:
        date_form = domain_date_search_form(name)(request.GET)
        if date_form.is_valid():
            return HttpResponseRedirect('%s%s' % (date_form.name_obj.base_url_with_timestamp(), url_subdir))
    else:
        date_form = None

    if timestamp is None:
        name_obj = DomainNameAnalysis.objects.latest(name)
    else:
        date = util.format.datetime_url_decode(timestamp)
        name_obj = DomainNameAnalysis.objects.get(name, date)

    if not url_subdir:
        url_subdir = ''

    if name_obj is None:
        subdir_path_length = len(url_subdir.split('/'))-1
        if timestamp is None:
            return HttpResponseRedirect(('../'*subdir_path_length)+'analyze/')
        else:
            raise Http404

    if date_form is None:
        date_form = domain_date_search_form(name)(initial={'date': name_obj.updated_utc_str()[:10] })

    if not url_subdir:
        return detail_view(request, name_obj, timestamp, url_subdir, date_form, **kwargs)
    elif url_subdir == 'responses/':
        return responses_view(request, name_obj, timestamp, url_subdir, date_form, **kwargs)
    elif url_subdir == 'servers/':
        return servers_view(request, name_obj, timestamp, url_subdir, date_form, **kwargs)
    elif url_subdir == 'dnssec/':
        return dnssec_view(request, name_obj, timestamp, url_subdir, date_form, **kwargs)
    elif url_subdir == 'cache/':
        return cache_view(request, name_obj, timestamp, url_subdir, date_form, **kwargs)

def detail_view(request, name_obj, timestamp, url_subdir, date_form):
    return HttpResponseRedirect('dnssec/')

def dnssec_view(request, name_obj, timestamp, url_subdir, date_form):
    # if the name is NXDOMAIN or if there are no valid responses for NS RRs, then redirect
    if name_obj.nxdomain or not name_obj.is_resolvable():
        return render_to_response('non_resolvable.html',
                { 'name_obj': name_obj, 'timestamp': timestamp, 'url_subdir': url_subdir, 'title': name_obj,
                        'date_form': date_form },
                context_instance=RequestContext(request) )

    if timestamp is None and name_obj.zone.latest.analysis_end > name_obj.analysis_end:
        induced_update = True
    else:
        induced_update = False

    dlv_name = name_obj.dlv_domain
    options_form, values = _dnssec_options_form_data(request)
    show_dlv = dlv_name in values['ta']
    denial_of_existence = values['doe']
    dnssec_algorithms = values['a']
    ds_algorithms = values['ds']
    trusted_keys = values['tk']
    trusted_zones = values['ta']
    redundant_edges = values['red']

    use_js = 'no_js' not in request.GET

    G = DNSAuthGraph(show_dlv, trusted_keys, trusted_zones, dnssec_algorithms, ds_algorithms)
    if denial_of_existence:
        rdtypes = set(values['rr'])
    else:
        rdtypes = name_obj.canonical_rdtypes().intersection(set(values['rr']))
        
    if use_js:
        notices = set()
        node_info = {}
    else:
        qrrsets = [(name_obj.name, rdtype) for rdtype in rdtypes]
        if denial_of_existence and name_obj.is_zone():
            if name_obj.nxdomain_name:
                qrrsets.append((name_obj.nxdomain_name, name_obj.nxdomain_rdtype))
            if name_obj.nxrrset_name:
                qrrsets.append((name_obj.nxrrset_name, name_obj.nxrrset_rdtype))

        for qname, rdtype in qrrsets:
            G.graph_rrset_auth(name_obj, qname, rdtype)

        notices = G.ordered_notices()
        node_info = G.node_info

    analyzed_name_obj = name_obj
    template = 'dnssec.html'
    #XXX fix this
    #if isinstance(name_obj, .DomainNameCache):
    #    name_obj = name_obj.domain_name_column()
    #    template = 'cache.html'

    return render_to_response(template,
            { 'name_obj': name_obj, 'analyzed_name_obj': analyzed_name_obj, 'timestamp': timestamp, 'url_subdir': url_subdir, 'title': name_obj,
                'rdtypes': rdtypes, 'options_form': options_form, 'date_form': date_form,
                'notices': notices, 'node_info': node_info, 'use_js': use_js, 'induced_update': induced_update,
                'show_dnssec_options': 'show_dnssec_options' in request.COOKIES, 'query_string': request.META['QUERY_STRING'] },
            context_instance=RequestContext(request))

def cache_view(request, name_obj, timestamp, url_subdir, date_form, cache_timestamp=None, server=None):
    #XXX TODO
    raise Http404

@condition(last_modified_func=domain_last_modified)
def dnssec_info(request, name, timestamp=None, url_subdir=None, url_file=None, format=None, **kwargs):
    name = util.format.name_url_decode(name)
    if timestamp is None:
        name_obj = DomainNameAnalysis.objects.latest(name)
    else:
        date = util.format.datetime_url_decode(timestamp)
        name_obj = DomainNameAnalysis.objects.get(name, date)

    if name_obj is None:
        raise Http404

    # if the name is NXDOMAIN or if there are no valid responses for NS RRs, then don't continue
    if name_obj.nxdomain or not name_obj.is_resolvable():
        raise Http404

    # if we're being referred to without a timestamp, and the zone has been updated
    # more recently than the non-zone subdomain name, then update the subdomain, but
    # only if we're an ajax call, so the user can be notified of what is going on
    referer = request.META.get('HTTP_REFERER', '')
    if '?' in referer:
        referer = referer[:referer.index('?')]
    if referer.endswith('%s%s' % (name_obj.base_url(), url_subdir)) \
            and name_obj.zone.latest.analysis_end > name_obj.analysis_end and request.is_ajax() and format == 'js':
        c = analyst.Crawler(name_obj.name, now(), force=True)
        try:
            name_obj = c.crawl()
        except:
            logging.getLogger('dnsviz').exception('Error analyzing %s' % name_obj)
        else:
            if timestamp is not None:
                new_url = '%s%s%s.%s' % (name_obj.base_url_with_timestamp(), url_subdir, url_file, format)
                if request.META['QUERY_STRING']:
                    new_url += '?' + request.META['QUERY_STRING']
                return HttpResponseRedirect(new_url)

    #XXX fix thos
    #if url_subdir == 'cache/':
    #    pass

    dlv_name = name_obj.dlv_domain
    options_form, values = _dnssec_options_form_data(request)

    show_dlv = dlv_name in values['ta']
    denial_of_existence = values['doe']
    dnssec_algorithms = values['a']
    ds_algorithms = values['ds']
    trusted_keys = values['tk']
    trusted_zones = values['ta']
    redundant_edges = values['red']

    #XXX currently, graphviz only supports local files, so the
    #XXX following four lines cannot be used
    #if format in ('png', 'jpg'):
    #    static_base = settings.STATIC_ROOT
    #else:
    #    static_base = settings.STATIC_URL
    static_base = settings.STATIC_ROOT

    G = DNSAuthGraph(show_dlv, trusted_keys, trusted_zones, dnssec_algorithms, ds_algorithms, \
            static_base=static_base, updated=name_obj.analysis_end, page_url=name_obj.base_url_with_timestamp()+url_subdir)
    if denial_of_existence:
        rdtypes = set(values['rr'])
    else:
        rdtypes = name_obj.canonical_rdtypes().intersection(set(values['rr']))

    qrrsets = [(name_obj.name, rdtype) for rdtype in rdtypes]
    if denial_of_existence and name_obj.is_zone():
        if name_obj.nxdomain_name:
            qrrsets.append((name_obj.nxdomain_name, name_obj.nxdomain_rdtype))
        if name_obj.nxrrset_name:
            qrrsets.append((name_obj.nxrrset_name, name_obj.nxrrset_rdtype))

    for qname, rdtype in qrrsets:
        G.graph_rrset_auth(name_obj, qname, rdtype)

    G.add_trust(dlv_name)
    G.remove_extra_edges(redundant_edges)

    if url_file == 'notices':
        return dnssec_notices(request, name_obj, G, format)
    elif url_file == 'auth_graph':
        return dnssec_auth_graph(request, name_obj, G, format)

def dnssec_auth_graph(request, name_obj, G, format):
    img = G.draw(format)
    #XXX currently, graphviz only supports local files, so the
    #XXX following two lines are necessary
    if format not in ('png', 'jpg'):
        img = img.replace(settings.STATIC_ROOT, settings.STATIC_URL)
    if format == 'dot':
        mimetype = 'text/plain'
    elif format == 'jpg':
        mimetype = 'image/jpeg'
    elif format == 'png':
        mimetype = 'image/png'
    elif format == 'svg':
        mimetype = 'image/svg+xml'
    elif format == 'js':
        mimetype = 'application/javascript'
    else:
        raise Exception('Unknown file type!')

    response = HttpResponse(img, mimetype=mimetype)
    if 'download' in request.GET:
        filename = name_obj.to_text()
        if filename == '.':
            filename = 'root'
        response['Content-Disposition'] = 'attachment; filename=%s-%s.%s' % (name_obj.to_text(), name_obj.updated_utc_str('-', False), format)

    if 'graph_load_error' in request.COOKIES:
        from django.core.mail import mail_admins
        mail_admins('Graph load errors', 'Path: %s\nUser-agent: %s\nReferer: %s\nRemote host: %s\nJavaScript Error: %s\n' % \
                (request.path, request.META.get('HTTP_USER_AGENT', ''), request.META.get('HTTP_REFERER', ''),
                request.META.get('REMOTE_ADDR', ''), urllib.unquote(request.COOKIES['graph_load_error'])))
        response.delete_cookie('graph_load_error')
    return response

def dnssec_notices(request, name_obj, G, format):
    notices = G.serializable_notices()
    if format == 'json':
        mimetype = 'application/javascript'
        serialized_data = simplejson.dumps(notices)
    elif format == 'xml':
        mimetype = 'application/xml'
        serialized_data = xmlrpclib.dumps((notices,), allow_none=True)
    else:
        raise Exception('Unknown ajax type!')

    return HttpResponse(serialized_data, mimetype)

def responses_view(request, name_obj, timestamp, url_subdir, date_form):
    options_form = DNSSECOptionsForm()
    values = dict((name, field.initial) for name, field in options_form.fields.items())
    options_form = DNSSECOptionsForm(values)
    options_form.is_valid()

    zone_obj = name_obj.zone

    rdtypes = options_form.cleaned_data['rr']
    qrrsets = [(name_obj, name_obj.name, rdtype) for rdtype in rdtypes]
    if name_obj.is_zone():
        if name_obj.nxdomain_name:
            qrrsets.append((name_obj, name_obj.nxdomain_name, name_obj.nxdomain_rdtype))
        if name_obj.nxrrset_name:
            qrrsets.append((name_obj, name_obj.nxrrset_name, name_obj.nxrrset_rdtype))

    def ip_cmp(x, y):
        return cmp(util.format.ip_to_wire(y), util.format.ip_to_wire(x))

    def ip_name_cmp(x, y):
        return cmp((x[1], util.format.ip_to_wire(y[0])), (y[1], util.format.ip_to_wire(x[0])))

    qrrsets.insert(0, (zone_obj, zone_obj.name, dns.rdatatype.NS))
    qrrsets.insert(0, (zone_obj, zone_obj.name, dns.rdatatype.DNSKEY))
    if zone_obj.name != dns.name.root:
        qrrsets.insert(0, (zone_obj, zone_obj.name, dns.rdatatype.DS))
        parent_all_auth_servers = zone_obj.parent.all_servers()
        parent_server_list = [(ip, zone_obj.parent.name_for_ip(ip)[0]) for ip in parent_all_auth_servers]
        parent_server_list.sort(cmp=ip_name_cmp)

    all_auth_servers = name_obj.all_servers()
    server_list = [(ip, zone_obj.name_for_ip(ip)[0]) for ip in all_auth_servers]
    server_list.sort(cmp=ip_name_cmp)
    response_consistency = []

    for my_name_obj, name, rdtype in qrrsets:
        if rdtype == dns.rdatatype.DS:
            slist = parent_server_list
            zone_name = my_name_obj.parent_name()
        else:
            slist = server_list
            zone_name = my_name_obj.zone.name

        pos_matrix = []

        responses = my_name_obj.get_responses(name, rdtype)
        rrsets_rrsigs, neg_responses, dname_rrsets_rrsigs, nsec_rrsets_rrsigs = my_name_obj.get_aggregated_responses(name, rdtype)
        error_responses = my_name_obj.get_aggregated_error_responses(name, rdtype)
        aliases_rrsets_rrsigs = util.dnsutil.aliases_from_aggregated_responses(name, rrsets_rrsigs)

        servers_pos_responses = set()
        servers_neg_responses = set()
        servers_nsec_responses = set()
        servers_dname_responses = set()
        servers_error_responses = set()
        for rrset, rrset_servers, rrsigs in rrsets_rrsigs:
            servers_pos_responses.update([s[0] for s in rrset_servers])
        for status, servers in neg_responses.items():
            servers_neg_responses.update([s[0] for s in servers])
        for nsec_tuple, rrset_servers in nsec_rrsets_rrsigs:
            servers_nsec_responses.update([s[0] for s in rrset_servers])
        for rrset, rrset_servers, rrsigs in dname_rrsets_rrsigs:
            servers_dname_responses.update([s[0] for s in rrset_servers])
        for error, servers in error_responses:
            servers_error_responses.update([s[0] for s in servers])

        if not responses:
            continue

        if False:
        #if name != dns.name.root and dname_rrsets_rrsigs:
            for rrset, rrset_servers, rrsigs in dname_rrsets_rrsigs:
                rrset_servers = set([s[0] for s in rrset_servers])
                row_grouping = []
                row = []
                row.append((util.format.humanize_name(rrset.name, True), None))
                row.append((rrset.ttl, None))
                row.append((dns.rdatatype.to_text(rrset.rdtype), None))
                row.append(('<br />'.join([escape(rr.to_text()) for rr in rrset]), None))

                synthesized_cname = util.dnsutil.cname_for_dname(name, rrset)
                status = ('OK', 'valid')
                if aliases_rrsets_rrsigs:
                    for cname_rrset, cname_rrset_servers, cname_rrsigs in aliases_rrsets_rrsigs:
                        if cname_rrset[0].target != synthesized_cname:
                            status = ('INV', 'invalid')
                        if cname_rrset.ttl not in (0, rrset.ttl):
                            status = ('INV', 'invalid')
                row.append(status)
                for server in server_list:
                    if server in rrset_servers:
                        row.append(('OK', 'valid'))
                    #elif server in responsive_servers or rdtype in (dns.rdatatype.SOA, dns.rdatatype.DNSKEY):
                    #    #XXX dive in deeper to find out if it was an error response, timeout, EDNS issue, lame response, etc.
                    #    row.append(('no-error','OK'))
                    #    row.append('ERR')
                    else:
                        row.append(('N/A', None))
                row_grouping.append(row)

                for rrsig, ttl, rrsig_servers in rrsigs:
                    rrsig_servers = [s[0] for s in rrsig_servers]
                    row = []
                    row.append(('', None))
                    row.append((ttl, None))
                    row.append(('RRSIG', None))
                    row.append(('<div class="rr">%s</div>' % rrsig.to_text(), None))

                    signer_obj = my_name_obj.get_node(rrsig.signer, True)

                    ref_date = my_name_obj.analysis_end
                    expiration = util.format.timestamp_to_datetime_utc(rrsig.expiration)
                    inception = util.format.timestamp_to_datetime_utc(rrsig.inception)

                    status = 'OK'
                    style = 'valid'
                    for dnskey, valid in signer_obj.dnskeys_for_rrsig(rrsig, rrset):
                        if rrsig.signer != zone_obj.name:
                            status = 'INV'
                            style = 'invalid'
                        elif dnskey is not None and \
                                dnskey.flags & util.format.DNSKEY_FLAGS['revoke'] and rrsig.covers() != dns.rdatatype.DNSKEY:
                            status = 'INV'
                            style = 'invalid'
                        elif dnskey is not None and rrsig.key_tag != util.dnssec.key_tag(dnskey):
                            status = 'INV'
                            style = 'invalid'
                        elif my_name_obj.analysis_e > expiration:
                            status = 'EXP'
                            style = 'expired'
                        elif ref_date < inception:
                            status = 'PRE'
                            style = 'not-yet-valid'
                        elif dnskey is None:
                            status = 'UNK'
                            style = 'unknown'
                        elif valid is None:
                            status = 'UNK'
                            style = 'unknown'
                        elif not valid:
                            status = 'INV'
                            style = 'invalid'
                        else:
                            status = 'OK'
                            style = 'valid'
                        break
                    row.append((status, style))

                    for server in server_list:
                        if server in rrsig_servers:
                            row.append(('OK', 'valid'))
                        #elif server in responsive_servers or rdtype in (dns.rdatatype.SOA, dns.rdatatype.DNSKEY):
                        #    #XXX dive in deeper to find out if it was an error response, timeout, EDNS issue, lame response, etc.
                        #    row.append(('INV', 'invalid'))
                        else:
                            row.append(('N/A', None))
                    row_grouping.append(row)
                pos_matrix.append(row_grouping)

        for rrset, rrset_servers, rrsigs in rrsets_rrsigs:
            rrset_servers = set([s[0] for s in rrset_servers])
            row_grouping = []
            row = []
            row.append((util.format.humanize_name(rrset.name, True), 'not-styled'))
            row.append((rrset.ttl, 'not-styled'))
            row.append((dns.rdatatype.to_text(rrset.rdtype), 'not-styled'))
            rrset_str = ''
            rrset_list = list(rrset)
            rrset_list.sort(cmp=util.dnssec._rr_cmp)
            for rr in rrset_list:
                rr_str = escape(rr.to_text())
                if rrset.rdtype == dns.rdatatype.DNSKEY:
                    rr_str += ' ; <b>key tag = %d</b>' % util.dnssec.key_tag(rr)
                rrset_str += '\n<div class="rr">%s</div>' % rr_str
            row.append((rrset_str, 'not-styled'))

            status = ('OK', 'valid')
            row.append(status)

            for server, names in slist:
                try:
                    response = responses[server].values()[0]
                except KeyError:
                    response = None
                if server in rrset_servers:
                    row.append(('Y', 'valid', my_name_obj.response_url(response, rrset, 'answer'), 'Click to see the full response from server %s for %s/%s' % (server, util.format.humanize_name(name), dns.rdatatype.to_text(rdtype))))
                elif server not in responses:
                    row.append(('', 'not-queried', None, 'Server %s not queried for %s/%s.' % (server, util.format.humanize_name(name), dns.rdatatype.to_text(rdtype))))
                else:
                    row.append(('', 'not-styled'))
            row_grouping.append(row)


            servers_with_rrsig = {}
            for rrsig, ttl, rrsig_servers in rrsigs:
                rrsig_servers = [s[0] for s in rrsig_servers]
                signer_obj = my_name_obj.get_name(rrsig.signer, True)
                for dnskey, valid in signer_obj.dnskeys_for_rrsig(rrsig, rrset):
                    if dnskey is not None:
                        if (rrsig.signer, dnskey) not in servers_with_rrsig:
                            servers_with_rrsig[(rrsig.signer, dnskey)] = set()
                        servers_with_rrsig[(rrsig.signer, dnskey)].update(rrsig_servers)

            for rrsig, ttl, rrsig_servers in rrsigs:
                rrsig_servers = [s[0] for s in rrsig_servers]
                row = []
                row.append(('', 'not-styled'))
                row.append((ttl, 'not-styled'))
                row.append(('RRSIG', 'not-styled'))
                row.append(('<div class="rr">%s</div>' % rrsig.to_text(), 'not-styled'))

                signer_obj = my_name_obj.get_name(rrsig.signer, True)

                ref_date = my_name_obj.analysis_end
                expiration = util.format.timestamp_to_datetime_utc(rrsig.expiration)
                inception = util.format.timestamp_to_datetime_utc(rrsig.inception)

                status = 'OK'
                style = 'valid'
                for dnskey, valid in signer_obj.dnskeys_for_rrsig(rrsig, rrset):
                    #TODO need to account for out-of-zone names (e.g., CNAME targets) also in answer section
                    #if rrsig.signer != zone_name:
                    #    status = 'INV'
                    #    style = 'invalid'
                    if dnskey is not None and \
                            dnskey.flags & util.format.DNSKEY_FLAGS['revoke'] and rrsig.covers() != dns.rdatatype.DNSKEY:
                        status = 'INV'
                        style = 'invalid'
                    elif dnskey is not None and rrsig.key_tag != util.dnssec.key_tag(dnskey):
                        status = 'INV'
                        style = 'invalid'
                    elif ref_date > expiration:
                        status = 'EXP'
                        style = 'expired'
                    elif ref_date < inception:
                        status = 'PRE'
                        style = 'not-yet-valid'
                    elif dnskey is None:
                        status = 'UNK'
                        style = 'unknown'
                    elif valid is None:
                        status = 'UNK'
                        style = 'unknown'
                    elif not valid:
                        status = 'BOG'
                        style = 'invalid'

                row.append((status, style))

                if dnskey is not None and rrsig.signer == zone_name:
                    servers_without_rrsig = rrset_servers.difference(servers_with_rrsig[(rrsig.signer, dnskey)])
                else:
                    servers_without_rrsig = set()

                rrsig_rrset = dns.rrset.RRset(rrset.name, rrset.rdclass, dns.rdatatype.RRSIG, rrset.rdtype)
                rrsig_rrset.add(rrsig)
                rrsig_rrset.ttl = ttl
                for server, names in slist:
                    try:
                        response = responses[server].values()[0]
                    except KeyError:
                        response = None
                    if server in rrsig_servers:
                        row.append(('Y', style, my_name_obj.response_url(response, rrsig_rrset, 'answer', rrsig), 'Click to see the full response from server %s for %s/%s' % (server, util.format.humanize_name(name), dns.rdatatype.to_text(rdtype))))
                    elif server in servers_without_rrsig:
                        row.append(('<img alt="Missing" src="%simages/missing.png" />' % settings.STATIC_URL, 'errors', my_name_obj.response_url(response) + '#answer', 'No RRSIG covering %s was returned from server %s for verification by %s.  Click to see the full response from server %s for %s/%s' % (util.format.humanize_rrset(rrset), server, util.format.humanize_dnskey(zone_name, dnskey), server, util.format.humanize_name(name), dns.rdatatype.to_text(rdtype))))
                    elif server not in responses:
                        row.append(('', 'not-queried', None, 'Server %s not queried for %s/%s.' % (server, util.format.humanize_name(name), dns.rdatatype.to_text(rdtype))))
                    else:
                        row.append(('', 'not-styled'))
                row_grouping.append(row)
            pos_matrix.append(row_grouping)

        for status, servers in neg_responses.items():
            servers = [s[0] for s in servers]
            if not servers:
                continue
            row_grouping = []
            row = []
            row.append((util.format.humanize_name(name), 'non-existent'))
            row.append(('', 'non-existent'))
            row.append((dns.rdatatype.to_text(rdtype), 'non-existent'))
            row.append(('', 'non-existent'))

            if servers_pos_responses:
                if rdtype == dns.rdatatype.DNSKEY:
                    style = 'errors'
                else:
                    style = 'warnings'
            else:
                style = 'valid'
            row.append((status, style))

            for server, names in slist:
                try:
                    response = responses[server].values()[0]
                except KeyError:
                    response = None
                if server in servers:
                    row.append(('Y', style, my_name_obj.response_url(response) + '#header', 'Click to see the full response from server %s for %s/%s' % (server, util.format.humanize_name(name), dns.rdatatype.to_text(rdtype))))
                elif server not in responses:
                    row.append(('', 'not-queried', None, 'Server %s not queried for %s/%s.' % (server, util.format.humanize_name(name), dns.rdatatype.to_text(rdtype))))
                else:
                    row.append(('', 'not-styled'))
            row_grouping.append(row)

            for nsec_tuple, rrset_servers in nsec_rrsets_rrsigs:
                rrset_servers = set([s[0] for s in rrset_servers])
                nsec_rrsets = [t[1] for t in nsec_tuple]
                #XXX handle the case where multiple sets of params exist

                if util.nsec.validate_nsec_covering(name, rdtype, zone_name, nsec_rrsets):
                    nsec_status = 'OK'
                    nsec_style = 'valid'
                else:
                    nsec_status = 'ERR'
                    nsec_style = 'errors'

                for nsec_name, nsec_rrset, rrsigs in nsec_tuple:
                    row = []
                    row.append((util.format.humanize_name(nsec_rrset.name, True), 'not-styled'))
                    row.append((nsec_rrset.ttl, 'not-styled'))
                    row.append((dns.rdatatype.to_text(nsec_rrset.rdtype), 'not-styled'))
                    rrset_str = ''
                    for rr in nsec_rrset:
                        rrset_str = '<div class="rr">%s</div>' % escape(rr.to_text())
                    row.append((rrset_str, 'not-styled'))
                    row.append((nsec_status, nsec_style))

                    for server, names in slist:
                        try:
                            response = responses[server].values()[0]
                        except KeyError:
                            response = None
                        if server in rrset_servers:
                            row.append(('Y', nsec_style, my_name_obj.response_url(response, nsec_rrset, 'authority'), 'Click to see the full response from server %s for %s/%s' % (server, util.format.humanize_name(name), dns.rdatatype.to_text(rdtype))))
                        elif server not in responses:
                            row.append(('', 'not-queried', None, 'Server %s not queried for %s/%s.' % (server, util.format.humanize_name(name), dns.rdatatype.to_text(rdtype))))
                        elif server in servers_neg_responses and \
                                server not in servers_nsec_responses:
                            row.append(('<img alt="Missing" src="%simages/missing.png" />' % settings.STATIC_URL, 'errors', my_name_obj.response_url(response) + '#authority', 'No NSEC/NSEC3 RRs were supplied from server %s for authenticated denial of existence.  Click to see the full response from server %s for %s/%s' % (server, server, util.format.humanize_name(name), dns.rdatatype.to_text(rdtype))))
                        else:
                            row.append(('', 'not-styled'))
                    row_grouping.append(row)

                    for rrsig, ttl in rrsigs:
                        row = []
                        row.append(('', 'not-styled'))
                        row.append((ttl, 'not-styled'))
                        row.append(('RRSIG', 'not-styled'))
                        row.append(('<div class="rr">%s</div>' % rrsig.to_text(), 'not-styled'))

                        signer_obj = my_name_obj.get_name(rrsig.signer, True)

                        ref_date = my_name_obj.analysis_end
                        expiration = util.format.timestamp_to_datetime_utc(rrsig.expiration)
                        inception = util.format.timestamp_to_datetime_utc(rrsig.inception)

                        status = 'OK'
                        style = 'valid'
                        for dnskey, valid in signer_obj.dnskeys_for_rrsig(rrsig, nsec_rrset):
                            if rrsig.signer != zone_name:
                                status = 'INV'
                                style = 'invalid'
                            elif dnskey is not None and \
                                    dnskey.flags & util.format.DNSKEY_FLAGS['revoke'] and rrsig.covers() != dns.rdatatype.DNSKEY:
                                status = 'INV'
                                style = 'invalid'
                            elif dnskey is not None and rrsig.key_tag != util.dnssec.key_tag(dnskey):
                                status = 'INV'
                                style = 'invalid'
                            elif ref_date > expiration:
                                status = 'EXP'
                                style = 'expired'
                            elif ref_date < inception:
                                status = 'PRE'
                                style = 'not-yet-valid'
                            elif dnskey is None:
                                status = 'UNK'
                                style = 'unknown'
                            elif valid is None:
                                status = 'UNK'
                                style = 'unknown'
                            elif not valid:
                                status = 'BOG'
                                style = 'invalid'

                        row.append((status, style))

                        rrsig_rrset = dns.rrset.RRset(nsec_rrset.name, nsec_rrset.rdclass, dns.rdatatype.RRSIG, nsec_rrset.rdtype)
                        rrsig_rrset.add(rrsig)
                        rrsig_rrset.ttl = ttl
                        for server, names in slist:
                            try:
                                response = responses[server].values()[0]
                            except KeyError:
                                response = None
                            if server in rrset_servers:
                                row.append(('Y', style, my_name_obj.response_url(response, rrsig_rrset, 'authority', rrsig), 'Click to see the full response from server %s for %s/%s' % (server, util.format.humanize_name(name), dns.rdatatype.to_text(rdtype))))
                            elif server not in responses:
                                row.append(('', 'not-queried', None, 'Server %s not queried for %s/%s.' % (server, util.format.humanize_name(name), dns.rdatatype.to_text(rdtype))))
                            elif server in servers_neg_responses and \
                                    server not in servers_nsec_responses:
                                row.append(('<img alt="Missing" src="%simages/missing.png" />' % settings.STATIC_URL, 'errors', my_name_obj.response_url(response) + '#authority', 'Click to see the full response from server %s for %s/%s' % (server, util.format.humanize_name(name), dns.rdatatype.to_text(rdtype))))
                            else:
                                row.append(('', 'not-styled'))
                        row_grouping.append(row)

            pos_matrix.append(row_grouping)

        for error, servers in error_responses:
            servers = [s[0] for s in servers]
            row_grouping = []
            row = []
            row.append(('<img alt="Error" src="%simages/dnssec_legend/warning.png" />%s' % (settings.STATIC_URL, error), 'not-styled', None, None, 4))
            row.append(('', 'warnings'))

            for server, names in slist:
                try:
                    response = responses[server].values()[0]
                except KeyError:
                    response = None
                if server in servers:
                    row.append(('Y', 'warnings', my_name_obj.response_url(response) + '#header', 'Click to see the full response from server %s for %s/%s' % (server, util.format.humanize_name(name), dns.rdatatype.to_text(rdtype))))
                elif server not in responses:
                    row.append(('', 'not-queried', None, 'Server %s not queried for %s/%s.' % (server, util.format.humanize_name(name), dns.rdatatype.to_text(rdtype))))
                else:
                    row.append(('', 'not-styled'))
            row_grouping.append(row)

            pos_matrix.append(row_grouping)

        row_grouping = []
        row = []
        row.append(('RR count (Answer/Authority/Additional)', 'not-styled', None, None, 4))
        row.append(('OK', 'valid'))
        for server, names in slist:
            try:
                response = responses[server].values()[0]
            except KeyError:
                response = None
            if server in responses and response.response is not None:
                answer_ct = 0
                for i in response.response.answer: answer_ct += len(i)
                authority_ct = 0
                for i in response.response.authority: authority_ct += len(i)
                additional_ct = 0
                for i in response.response.additional: additional_ct += len(i)
                if response.response.edns >= 0:
                    additional_ct += 1
                row.append(('%d/%d/%d' % (answer_ct, authority_ct, additional_ct), 'valid', my_name_obj.response_url(response) + '#header', 'Click to see the full response from server %s for %s/%s' % (server, util.format.humanize_name(name), dns.rdatatype.to_text(rdtype))))
            elif server not in responses:
                row.append(('', 'not-queried', None, 'Server %s not queried for %s/%s.' % (server, util.format.humanize_name(name), dns.rdatatype.to_text(rdtype))))
            elif server:
                row.append(('', 'not-styled'))
        row_grouping.append(row)
        pos_matrix.append(row_grouping)

        row_grouping = []
        row = []
        row.append(('Response size (bytes)', 'not-styled', None, None, 4))
        row.append(('OK', 'valid'))
        for server, names in slist:
            try:
                response = responses[server].values()[0]
            except KeyError:
                response = None
            if server in responses and response.response is not None:
                row.append((len(response.response.to_wire()), 'valid', my_name_obj.response_url(response) + '#stats', 'Click to see the full response from server %s for %s/%s' % (server, util.format.humanize_name(name), dns.rdatatype.to_text(rdtype))))
            elif server not in responses:
                row.append(('', 'not-queried', None, 'Server %s not queried for %s/%s.' % (server, util.format.humanize_name(name), dns.rdatatype.to_text(rdtype))))
            elif server:
                row.append(('', 'not-styled'))
        row_grouping.append(row)
        pos_matrix.append(row_grouping)

        if pos_matrix:
            response_consistency.append(('Responses for %s/%s' % (util.format.humanize_name(name, True), dns.rdatatype.to_text(rdtype)), slist, pos_matrix))

    return render_to_response('responses.html',
            { 'name_obj': name_obj, 'timestamp': timestamp, 'url_subdir': url_subdir, 'title': name_obj,
                'date_form': date_form, 'response_consistency': response_consistency },
            context_instance=RequestContext(request))

def response_by_name_view(request, name, timestamp, qname, rdtype, server, rd, do, cd, client):
    name = util.format.name_url_decode(name)
    if timestamp is None:
        name_obj = DomainNameAnalysis.objects.latest(name)
    else:
        date = util.format.datetime_url_decode(timestamp)
        name_obj = DomainNameAnalysis.objects.get(name, date)

    if name_obj is None:
        raise Http404

    qname = util.format.name_url_decode(qname)
    rdtype = int(rdtype)
    rd = rd in 'tT1'
    do = do in 'tT1'
    cd = cd in 'tT1'

    try:
        response_obj = name_obj.get_responses(qname, rdtype)[server][client]
    except KeyError:
        raise Http404

    return render_to_response('response.html',
            { 'response_obj': response_obj, 'qname': util.format.humanize_name(qname, True), 'rdtype': dns.rdatatype.to_text(rdtype), 'dns_msg': response_obj.to_html() },
            context_instance=RequestContext(request))

def response_view(request, qname, rdtype, server, rd, do, cd, timestamp, client):
    qname = util.format.name_url_decode(qname)
    rdtype = int(rdtype)
    rd = rd in 'tT1'
    do = do in 'tT1'
    cd = cd in 'tT1'

    date = util.format.datetime_url_decode(timestamp)

    response_obj = DNSResponse.objects.get(qname, rdtype, server, client, rd, do, cd, date)

    if response_obj is None:
        raise Http404

    return render_to_response('response.html',
            { 'response_obj': response_obj, 'qname': util.format.humanize_name(qname, True), 'rdtype': dns.rdatatype.to_text(rdtype), 'dns_msg': response_obj.to_html() },
            context_instance=RequestContext(request))

def servers_view(request, name_obj, timestamp, url_subdir, date_form):
    zone_obj = name_obj.zone

    delegation_matrix = []
    
    def ip_cmp(x, y):
        return cmp(util.format.ip_to_wire(y), util.format.ip_to_wire(x))

    def ip_name_cmp(x, y):
        return cmp((x[1], util.format.ip_to_wire(y[0])), (y[1], util.format.ip_to_wire(x[0])))

    def stealth_cmp(x, y):
        return cmp((y[0], x[1], util.format.ip_to_wire(x[2])), (x[0], y[1], util.format.ip_to_wire(y[2])))

    all_names_list = list(zone_obj.get_ns_names())
    all_names_list.sort()

    if zone_obj.parent and zone_obj.no_non_auth_parent():
        no_non_auth_parent_msg = 'All %s servers are also authoritative for %s' % (util.format.humanize_name(zone_obj.parent_name()), util.format.humanize_name(zone_obj.name))
    else:
        no_non_auth_parent_msg = None
    #XXX need something equivalent here for lack of authoritative response for NS
    show_msg = False

    ips_from_child = zone_obj.get_servers_in_child()
    ips_from_parent = zone_obj.get_servers_in_parent()

    for name in all_names_list:
        if zone_obj.parent:
            in_bailiwick = name.is_subdomain(zone_obj.parent_name())
            glue_required = name.is_subdomain(zone_obj.name)
        else:
            in_bailiwick = None
            glue_required = None
        parent_status = { 'in_bailiwick': in_bailiwick, 'glue_required': glue_required }

        row = []
        row.append(util.format.humanize_name(name))
        # (t/f in parent), (glue IPs (or error, if missing)), (real IPs)
        if zone_obj.get_ns_names_in_parent():
            glue_mapping = zone_obj.get_glue_ip_mapping()
            parent_status['in_parent'] = name in glue_mapping
            glue_ips_v4 = filter(lambda x: not util.format.is_ipv6(x), glue_mapping.get(name, set()))
            glue_ips_v4.sort(cmp=ip_cmp)
            glue_ips_v6 = filter(lambda x: util.format.is_ipv6(x), glue_mapping.get(name, set()))
            glue_ips_v6.sort(cmp=ip_cmp)
        else:
            glue_ips_v4 = []
            glue_ips_v6 = []
            if zone_obj.ds_nxdomain():
                parent_status['in_parent'] = False
            else:
                parent_status['in_parent'] = None
                show_msg = True

        row.append({ 'parent_status': parent_status, 'glue_ips_v4': glue_ips_v4, 'glue_ips_v6': glue_ips_v6 })

        # (t/f in parent), (glue IPs (or error, if missing)), (real IPs)
        names_in_child = zone_obj.get_ns_names_in_child()
        if names_in_child:
            in_child = name in zone_obj.get_ns_names_in_child()
        elif zone_obj.get_servers_authoritative_for_query(zone_obj.name, dns.rdatatype.NS):
            in_child = None
        else:
            in_child = False

        auth_mapping = zone_obj.get_auth_ip_mapping()
        auth_ips_v4 = filter(lambda x: not util.format.is_ipv6(x), auth_mapping.get(name, set()))
        auth_ips_v4.sort(cmp=ip_cmp)
        auth_ips_v6 = filter(lambda x: util.format.is_ipv6(x), auth_mapping.get(name, set()))
        auth_ips_v6.sort(cmp=ip_cmp)

        row.append({ 'in_child': in_child, 'auth_ips_v4': auth_ips_v4, 'auth_ips_v6': auth_ips_v6 })
        delegation_matrix.append(row)

    stealth_matrix = []
    stealth_rows = []
    for server in zone_obj.get_stealth_servers():
        names, ancestor_zone = zone_obj.name_for_ip(server)
        stealth_rows.append((ancestor_zone, names, server))
    stealth_rows.sort(cmp=stealth_cmp)

    for ancestor_zone, names, server in stealth_rows:
        names = map(util.format.humanize_name, names)
        if ancestor_zone is not None:
            ancestor_zone = util.format.humanize_name(ancestor_zone)
        row = (names, ancestor_zone, server)
        stealth_matrix.append(row)

    server_status = {}

    all_auth_servers = name_obj.all_servers()
    server_list = [(ip, zone_obj.name_for_ip(ip)[0]) for ip in all_auth_servers]
    server_list.sort(cmp=ip_name_cmp)

    status_list = ('Responsive over UDP', 'Responsive over TCP', 'Answers authoritatively (AA bit)', 'SOA serial consistent',
            'SOA authority correct (NXDOMAIN)', 'SOA consistent (NXDOMAIN)', 'SOA authority correct (Empty Answer)', 'SOA consistent (Empty Answer)', 'EDNS capable', 'PMTU sufficient', 'Returns DNSKEY', 'Returns RRSIG',
            'Returns NSEC/NSEC3 (NXDOMAIN)', 'Returns RRSIG covering NSEC/NSEC3 (NXDOMAIN)', 'Returns NSEC/NSEC3 (Empty Answer)', 'Returns RRSIG covering NSEC/NSEC3 (Empty Answer)') 

    dnskey_rrsets_rrsigs = zone_obj.get_aggregated_responses(zone_obj.name, dns.rdatatype.DNSKEY)[0]
    dnskey_present = bool(dnskey_rrsets_rrsigs)
    dnskey_rrsigs_present = bool(filter(lambda x: x[2], dnskey_rrsets_rrsigs))

    soa_rrsets_rrsigs = zone_obj.get_aggregated_responses(zone_obj.name, dns.rdatatype.SOA)[0]
    soa_present = bool(soa_rrsets_rrsigs)
    soa_rrsigs_present = bool(filter(lambda x: x[2], soa_rrsets_rrsigs))

    for server, names in server_list:
        server_analysis = zone_obj.server_analyses.get(server__ip_address=server)
        server_status[server] = []

        responses = {}
        try:
            responses[(zone_obj.name, dns.rdatatype.SOA)] = zone_obj.get_responses(zone_obj.name, dns.rdatatype.SOA)[server].values()[0]
        except KeyError:
            responses[(zone_obj.name, dns.rdatatype.SOA)] = None
        try:
            responses[(zone_obj.name, dns.rdatatype.A)] = zone_obj.get_responses(zone_obj.name, dns.rdatatype.A)[server].values()[0]
        except KeyError:
            responses[(zone_obj.name, dns.rdatatype.A)] = None
        try:
            responses[(zone_obj.name, dns.rdatatype.AAAA)] = zone_obj.get_responses(zone_obj.name, dns.rdatatype.AAAA)[server].values()[0]
        except KeyError:
            responses[(zone_obj.name, dns.rdatatype.AAAA)] = None
        try:
            responses[(zone_obj.name, dns.rdatatype.DNSKEY)] = zone_obj.get_responses(zone_obj.name, dns.rdatatype.DNSKEY)[server].values()[0]
        except KeyError:
            responses[(zone_obj.name, dns.rdatatype.DNSKEY)] = None
        try:
            responses[(zone_obj.nxdomain_name, zone_obj.nxdomain_rdtype)] = zone_obj.get_responses(zone_obj.nxdomain_name, zone_obj.nxdomain_rdtype)[server].values()[0]
        except KeyError:
            responses[(zone_obj.nxdomain_name, zone_obj.nxdomain_rdtype)] = None
        try:
            responses[(zone_obj.nxrrset_name, zone_obj.nxrrset_rdtype)] = zone_obj.get_responses(zone_obj.nxrrset_name, zone_obj.nxrrset_rdtype)[server].values()[0]
        except KeyError:
            responses[(zone_obj.nxrrset_name, zone_obj.nxrrset_rdtype)] = None

        queried = dict(filter(lambda x: x[1] is not None, responses.items()))
        positive_responses = dict(filter(lambda x: x[1] is not None and x[1].response is not None and x[1].response.rcode() in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN), queried.items()))
        authoritative_responses = dict(filter(lambda x: x[1].response.flags & dns.flags.AA, positive_responses.items()))
        edns_responses = dict(filter(lambda x: x[1].response.edns >= 0, positive_responses.items()))

        # responsiveness
        diff_response = set(queried).difference(set(positive_responses))
        if not queried:
            server_status[server].append(('', 'not-queried'))
        elif diff_response:
            if positive_responses:
                server_status[server].append(('ERR', 'warnings', ))
            else:
                server_status[server].append(('ERR', 'errors'))
        else:
            server_status[server].append(('OK', 'valid'))

        # responsiveness (TCP)
        if not positive_responses:
            server_status[server].append(('', 'not-queried'))
        elif server_analysis.responsive_tcp is None:
            server_status[server].append(('', 'not-queried'))
        elif not server_analysis.responsive_tcp:
            server_status[server].append(('ERR', 'errors'))
        else:
            server_status[server].append(('OK', 'valid'))

        # authoritativeness
        diff_response = set(positive_responses).difference(set(authoritative_responses))
        if not positive_responses:
            server_status[server].append(('', 'not-queried'))
        elif diff_response:
            if authoritative_responses:
                server_status[server].append(('ERR', 'warnings'))
            else:
                server_status[server].append(('ERR', 'errors'))
        else:
            server_status[server].append(('OK', 'valid'))

        # serial
        soa_rrset_pos = None
        if (zone_obj.name, dns.rdatatype.SOA) not in authoritative_responses:
            server_status[server].append(('', 'not-queried'))
        else:
            try:
                soa_rrset_pos = responses[(zone_obj.name, dns.rdatatype.SOA)].response.find_rrset(responses[(zone_obj.name, dns.rdatatype.SOA)].response.answer, zone_obj.name, dns.rdataclass.IN, dns.rdatatype.SOA)
                serial = soa_rrset_pos[0].serial
                if serial != zone_obj.serial:
                    cls = 'warnings'
                else:
                    cls = 'valid'
                #server_status[server].append((serial, cls))
                server_status[server].append(('OK', cls))
            except KeyError:
                server_status[server].append(('', 'not-queried'))

        # SOA authority correct (NXDOMAIN)
        soa_rrset_neg = None
        if not authoritative_responses:
            server_status[server].append(('', 'not-queried'))
        elif (zone_obj.nxdomain_name, zone_obj.nxdomain_rdtype) not in authoritative_responses:
            server_status[server].append(('ERR', 'warnings'))
        #XXX find out if this test is suitable
        elif responses[(zone_obj.nxdomain_name, zone_obj.nxdomain_rdtype)].response.answer:
            server_status[server].append(('', 'not-queried'))
        else:
            try:
                soa_rrset_neg = filter(lambda x: x.rdtype == dns.rdatatype.SOA, responses[(zone_obj.nxdomain_name, zone_obj.nxdomain_rdtype)].response.authority)[0]
                if soa_rrset_neg.name != zone_obj.name:
                    server_status[server].append(('ERR', 'errors'))
                else:
                    server_status[server].append(('OK', 'valid'))
            except IndexError:
                server_status[server].append(('ERR', 'errors'))

        # SOA consistent (NXDOMAIN)
        if not (soa_rrset_pos and soa_rrset_neg):
            server_status[server].append(('', 'not-queried'))
        elif soa_rrset_pos != soa_rrset_neg:
            server_status[server].append(('ERR', 'warnings'))
        else:
            server_status[server].append(('OK', 'valid'))

        # SOA authority correct (No Answer)
        soa_rrset_neg = None
        if not authoritative_responses:
            server_status[server].append(('', 'not-queried'))
        elif (zone_obj.nxrrset_name, zone_obj.nxrrset_rdtype) not in authoritative_responses:
            server_status[server].append(('ERR', 'warnings'))
        #XXX find out if this test is suitable
        elif responses[(zone_obj.nxrrset_name, zone_obj.nxrrset_rdtype)].response.answer:
            server_status[server].append(('', 'not-queried'))
        else:
            try:
                soa_rrset_neg = filter(lambda x: x.rdtype == dns.rdatatype.SOA, responses[(zone_obj.nxrrset_name, zone_obj.nxrrset_rdtype)].response.authority)[0]
                if soa_rrset_neg.name != zone_obj.name:
                    server_status[server].append(('ERR', 'errors'))
                else:
                    server_status[server].append(('OK', 'valid'))
            except IndexError:
                server_status[server].append(('ERR', 'errors'))

        # SOA consistent (No Answer)
        if not (soa_rrset_pos and soa_rrset_neg):
            server_status[server].append(('', 'not-queried'))
        elif soa_rrset_pos != soa_rrset_neg:
            server_status[server].append(('ERR', 'warnings'))
        else:
            server_status[server].append(('OK', 'valid'))

        # EDNS capable
        diff_response = set(authoritative_responses).difference(set(edns_responses))
        if not authoritative_responses:
            server_status[server].append(('', 'not-queried'))
        elif diff_response:
            if edns_responses:
                server_status[server].append(('ERR', 'warnings'))
            else:
                server_status[server].append(('ERR', 'errors'))
        else:
            server_status[server].append(('OK', 'valid'))

        # PMTU issues
        if (zone_obj.name, dns.rdatatype.DNSKEY) not in authoritative_responses:
            server_status[server].append(('', 'not-queried'))
        elif not responses[(zone_obj.name, dns.rdatatype.DNSKEY)].response.answer:
            server_status[server].append(('', 'not-queried'))
        elif server_analysis.max_payload_high is not None:
            server_status[server].append(('ERR', 'warnings'))
        else:
            server_status[server].append(('OK', 'valid'))

        # returns DNSKEY
        dnskey_rrset = None
        if not dnskey_present or not authoritative_responses:
            server_status[server].append(('', 'not-queried'))
        elif (zone_obj.name, dns.rdatatype.DNSKEY) not in authoritative_responses:
            server_status[server].append(('ERR', 'warnings'))
        else:
            try:
                dnskey_rrset = responses[(zone_obj.name, dns.rdatatype.DNSKEY)].response.find_rrset(responses[(zone_obj.name, dns.rdatatype.DNSKEY)].response.answer, zone_obj.name, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
                server_status[server].append(('OK', 'valid'))
            except KeyError:
                server_status[server].append(('ERR', 'errors'))

        # returns RRSIG
        if not authoritative_responses:
            server_status[server].append(('', 'not-queried'))
        elif dnskey_rrset is not None and dnskey_rrsigs_present:
            try:
                dnskey_rrsig = responses[(zone_obj.name, dns.rdatatype.DNSKEY)].response.find_rrset(responses[(zone_obj.name, dns.rdatatype.DNSKEY)].response.answer, zone_obj.name, dns.rdataclass.IN, dns.rdatatype.RRSIG, dns.rdatatype.DNSKEY)
                server_status[server].append(('OK', 'valid'))
            except KeyError:
                server_status[server].append(('ERR', 'errors'))
        elif soa_present and soa_rrsigs_present and (zone_obj.name, dns.rdatatype.SOA) in authoritative_responses:
            try:
                soa_rrsig = responses[(zone_obj.name, dns.rdatatype.SOA)].response.find_rrset(responses[(zone_obj.name, dns.rdatatype.SOA)].response.answer, zone_obj.name, dns.rdataclass.IN, dns.rdatatype.RRSIG, dns.rdatatype.SOA)
                server_status[server].append(('OK', 'valid'))
            except KeyError:
                server_status[server].append(('', 'errors'))
        else:
            server_status[server].append(('', 'not-queried'))

        # Returns NSEC(3)
        nsec_rrsets = None
        if not authoritative_responses:
            server_status[server].append(('', 'not-queried'))
        elif (zone_obj.nxdomain_name, zone_obj.nxdomain_rdtype) not in authoritative_responses:
            server_status[server].append(('ERR', 'warnings'))
        else:
            nsec_rrsets = filter(lambda x: x.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3), responses[(zone_obj.nxdomain_name, zone_obj.nxdomain_rdtype)].response.authority)
            if nsec_rrsets:
                server_status[server].append(('OK', 'valid'))
            elif not (dnskey_rrsigs_present or soa_rrsigs_present):
                server_status[server].append(('', 'not-queried'))
            elif filter(lambda x: x.name == zone_obj.nxdomain_name and x.rdtype in (zone_obj.nxdomain_rdtype, dns.rdatatype.CNAME), responses[(zone_obj.nxdomain_name, zone_obj.nxdomain_rdtype)].response.answer):
                # wildcard
                server_status[server].append(('ERR', 'errors'))
            else:
                server_status[server].append(('ERR', 'errors'))

        # Returns NSEC(3)
        if not nsec_rrsets:
            server_status[server].append(('', 'not-queried'))
        else:
            nsec_rrsigs = filter(lambda x: x.rdtype == dns.rdatatype.RRSIG and x.covers in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3), responses[(zone_obj.nxdomain_name, zone_obj.nxdomain_rdtype)].response.authority)
            if nsec_rrsigs:
                server_status[server].append(('OK', 'valid'))
            else:
                server_status[server].append(('ERR', 'errors'))

        # Returns NSEC(3)
        nsec_rrsets = None
        if not authoritative_responses:
            server_status[server].append(('', 'not-queried'))
        elif (zone_obj.nxrrset_name, zone_obj.nxrrset_rdtype) not in authoritative_responses:
            server_status[server].append(('ERR', 'warnings'))
        elif filter(lambda x: x.name == zone_obj.nxrrset_name and x.rdtype in (zone_obj.nxrrset_rdtype, dns.rdatatype.CNAME), responses[(zone_obj.nxrrset_name, zone_obj.nxrrset_rdtype)].response.answer):
            server_status[server].append(('', 'not-queried'))
        else:
            nsec_rrsets = filter(lambda x: x.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3), responses[(zone_obj.nxrrset_name, zone_obj.nxrrset_rdtype)].response.authority)
            if nsec_rrsets:
                server_status[server].append(('OK', 'valid'))
            elif not (dnskey_rrsigs_present or soa_rrsigs_present):
                server_status[server].append(('', 'not-queried'))
            else:
                server_status[server].append(('ERR', 'errors'))

        # Returns NSEC(3)
        if not nsec_rrsets:
            server_status[server].append(('', 'not-queried'))
        else:
            nsec_rrsigs = filter(lambda x: x.rdtype == dns.rdatatype.RRSIG and x.covers in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3), responses[(zone_obj.nxrrset_name, zone_obj.nxrrset_rdtype)].response.authority)
            if nsec_rrsigs:
                server_status[server].append(('OK', 'valid'))
            else:
                server_status[server].append(('ERR', 'errors'))

    server_matrix = []
    for i, val in enumerate(status_list):
        row = []
        row.append((val, None))
        for server, names in server_list:
            row.append(server_status[server][i])
        server_matrix.append(row)

    return render_to_response('servers.html',
            { 'name_obj': name_obj, 'timestamp': timestamp, 'url_subdir': url_subdir, 'title': name_obj,
                'date_form': date_form, 'zone_obj': zone_obj, 'delegation': delegation_matrix, 'stealth': stealth_matrix, 'no_non_auth_parent_msg': no_non_auth_parent_msg, 'show_msg': show_msg,
                'servers': server_list, 'server_matrix': server_matrix,
                'ips_from_parent': ips_from_parent, 'ips_from_child': ips_from_child },
            context_instance=RequestContext(request))

def domain_search(request):
    name = request.GET.get('d', '')

    url_re = re.compile(r'^\s*(https?://)?(%s)/?\s*$' % urls.dns_name)
    name = url_re.sub(r'\2', name)

    ipv4_re = re.compile(r'^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$')
    if ipv4_re.match(name):
        octets = name.split('.')
        octets.reverse()
        name = '.'.join(octets) + '.in-addr.arpa'

    name_valid = True
    try:
        name = dns.name.from_unicode(name)
        name = util.format.name_url_encode(name)
    except:
        name_valid = False

    # even an valid name might not fit our (current) URL criteria
    name_re = re.compile(r'^(%s)$' % urls.dns_name)
    if name_re.match(name) is None:
        name_valid = False

    if not name_valid:
        return render_to_response('search.html',
                { 'domain_name': name, 'title': 'Search' },
                context_instance=RequestContext(request))

    return HttpResponseRedirect('../d/%s/' % name)

@csrf_exempt
@transaction.autocommit
def analyze(request, name, url_subdir=None):
    name = util.format.name_url_decode(name)
    name_obj = DomainNameAnalysis.objects.latest(name)

    if not url_subdir:
        url_subdir = ''

    googlebot_requesting_non_existent = False
    if name_obj is None:
        name_obj = DomainNameAnalysis()
        name_obj.name = name
        form_class = DomainNameAnalysisInitialForm
        googlebot_requesting_non_existent = 'Googlebot' in request.META.get('HTTP_USER_AGENT', '')
    else:
        form_class = DomainNameAnalysisForm

    error_msg = None
    if request.POST or googlebot_requesting_non_existent:
        force = True
        force_ancestry = False
        force_deps = False
        if request.POST:
            analyze_form = form_class(request.POST)
            if analyze_form.is_valid():
                if analyze_form.cleaned_data['analysis_depth'] == 2:
                    force_ancestry = True
                    force_deps = False
                elif analyze_form.cleaned_data['analysis_depth'] == 3:
                    force_ancestry = True
                    force_deps = True
        else:
            analyze_form = form_class()

        #TODO move this to something that can be used with "with"
        logger = logging.getLogger('dnsviz.analyst')
        logger.setLevel(logging.DEBUG)
        handler = util.log.QueueForIteratorHandler()
        handler.setFormatter(util.log.HTMLFormatter())
        logger.addHandler(handler)

        try:
            c = analyst.Crawler(name_obj.name, now(), force=force, force_ancestry=force_ancestry, force_deps=force_deps)
            if request.is_ajax():
                def _close_handler(x, y): handler.close()
                c.crawl_async(_close_handler, _close_handler)
                return HttpResponse(handler)
            else:
                try:
                    c.crawl()
                    return HttpResponseRedirect('../')
                except:
                    logger.exception('Exception analyzing %s' % name_obj)   
                    error_msg = u'There was an error analyzing %s.  We\'ve been notified of the problem and will look into fixing it.  Please try again later.' % name_obj
        finally:
            logger.removeHandler(handler)

    return render_to_response('analyze.html',
            { 'name_obj': name_obj, 'url_subdir': url_subdir, 'title': name_obj,
                'error_msg': error_msg, 'analyze_form': form_class() },
            context_instance=RequestContext(request))

def analyze_cache(request, name, url_subdir=None):
    #TODO
    raise Http404

def contact(request):
    if request.method == 'POST':
        form = ContactForm(request.POST)
        if form.is_valid():
            form.submit_message()
            return HttpResponseRedirect('/message_submitted/')
    else:
        form = ContactForm()

    return render_to_response('contact.html', { 'form': form },
            context_instance=RequestContext(request))
