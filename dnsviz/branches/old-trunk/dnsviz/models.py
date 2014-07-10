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
import hashlib
import StringIO
import struct
import time
import urllib

import dns.edns, dns.exception, dns.flags, dns.message, dns.name, dns.rcode, dns.rdataclass, dns.rdata, dns.rdatatype, dns.rrset

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import IntegrityError, models, transaction
from django.db.models import Q
from django.utils.html import escape
from django.utils.timezone import now, utc
from django.utils.translation import ugettext_lazy as _

import util

class UnsignedSmallIntegerField(models.SmallIntegerField):
    __metaclass__ = models.SubfieldBase
    def to_python(self, value):
        value = super(UnsignedSmallIntegerField, self).to_python(value)
        if value is None:
            return None
        if value < 0:
            value = 32767 - value
        return value

    def get_prep_value(self, value):
        value = super(UnsignedSmallIntegerField, self).get_prep_value(value)
        if value is None:
            return None
        if value > 32767:
            value = -(value - 32767)
        return value

class UnsignedIntegerField(models.IntegerField):
    __metaclass__ = models.SubfieldBase
    def to_python(self, value):
        value = super(UnsignedIntegerField, self).to_python(value)
        if value is None:
            return None
        if value < 0:
            value = 2147483647 - value
        return value

    def get_prep_value(self, value):
        value = super(UnsignedIntegerField, self).get_prep_value(value)
        if value is None:
            return None
        if value > 2147483647:
            value = -(value - 2147483647)
        return value

class UnsignedIntModel(models.Model):
    unsigned_small_int = UnsignedSmallIntegerField()
    unsigned_int = UnsignedIntegerField()
    def __unicode__(self):
        return '%d %d' % (self.unsigned_small_int, self.unsigned_int)

class DomainNameField(models.CharField):
    description = _("Domain name (with maximum length of %(max_length)s characters)")

    __metaclass__ = models.SubfieldBase

    def __init__(self, *args, **kwargs):
        self.canonicalize = kwargs.pop('canonicalize', True)
        super(DomainNameField, self).__init__(*args, **kwargs)

    def to_python(self, value):
        if value is None:
            return None
        if isinstance(value, dns.name.Name):
            name = value
        else:
            try:
                name = dns.name.from_text(value)
            except Exception, e:
                raise ValidationError('%s: %s is of type %s' % (e, value, type(value)))
        if self.canonicalize:
            name = name.canonicalize()
        return name

    def get_prep_value(self, value):
        if value is None:
            return None
        if isinstance(value, dns.name.Name):
            name = value
        else:
            name = dns.name.from_text(value)
        if self.canonicalize:
            name = name.canonicalize()
        return name.to_text()

class BinaryField(models.Field):
    __metaclass__ = models.SubfieldBase

    def db_type(self, connection):
        if connection.settings_dict['ENGINE'] in ('django.db.backends.postgresql_psycopg2', 'django.db.backends.postgresql'):
            return 'bytea'
        elif connection.settings_dict['ENGINE'] == 'django.db.backends.mysql':
            return 'blob'
        elif connection.settings_dict['ENGINE'] == 'django.db.backends.sqlite3':
            return 'BLOB'
        raise Exception('Binary data type not known for %s db backend' % connection.settings_dict['ENGINE'])

    def to_python(self, value):
        if value is None:
            return None
        if isinstance(value, basestring):
            return value
        return str(value)

    def get_prep_value(self, value):
        if value is None:
            return None
        if isinstance(value, bytearray):
            return value
        return bytearray(value)

class DomainNameManager(models.Manager):
    def offset_for_interval(self, interval):
        if interval > 604800:
            #XXX log this
            interval = 604800
        dt_now = now()
        last_sunday = dt_now.date() - datetime.timedelta(days=dt_now.isoweekday())
        last_sunday_midnight = datetime.datetime(year=last_sunday.year, month=last_sunday.month, day=last_sunday.day, tzinfo=utc)
        diff = dt_now - last_sunday_midnight
        return diff.total_seconds() % interval

    def names_to_refresh(self, interval, offset, last_offset):
        if offset > last_offset:
            f = Q(refresh_interval=interval, refresh_offset__gt=last_offset, refresh_offset__lte=offset)
        else:
            f = Q(refresh_interval=interval) & ( Q(refresh_offset__gt=last_offset) | Q(refresh_offset__lte=offset) )
        return self.filter(f)

class DomainName(models.Model):
    name = DomainNameField(max_length=2048, unique=True)
    analysis_start = models.DateTimeField(blank=True, null=True)
    refresh_interval = models.PositiveIntegerField(blank=True, null=True)
    refresh_offset = models.PositiveIntegerField(blank=True, null=True)

    objects = DomainNameManager()

    def __unicode__(self):
        return util.format.humanize_name(self.name, True)

    def __str__(self):
        return util.format.humanize_name(self.name)

    def latest_analysis(self, date=None):
        return DomainNameAnalysis.objects.latest(self.name, date)

    def clear_refresh(self):
        if (self.refresh_interval, self.refresh_offset) != (None, None):
            self.refresh_interval = None
            self.refresh_offset = None
            self.save()

    def set_refresh(self, refresh_interval, refresh_offset):
        if (self.refresh_interval, self.refresh_offset) != (refresh_interval, refresh_offset):
            self.refresh_interval = refresh_interval
            self.refresh_offset = refresh_offset
            self.save()

class DNSServer(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)

    def __unicode__(self):
        return self.ip_address

class NSMapping(models.Model):
    name = DomainNameField(max_length=2048)
    server = models.ForeignKey(DNSServer)

    class Meta:
        unique_together = (('name', 'server'),)

    def __unicode__(self):
        return '%s -> %s' % (self.name.to_unicode(), self.server)

    def __str__(self):
        return '%s -> %s' % (self.name.to_text(), self.server)

class DomainNameAnalysisManager(models.Manager):
    def latest(self, name, date=None):
        f = Q(name_obj__name=name, analysis_end__isnull=False)
        if date is not None:
            f &= Q(analysis_end__lte=date)

        try:
            return self.filter(f).latest()
        except self.model.DoesNotExist:
            return None

    def earliest(self, name, date=None):
        f = Q(name_obj__name=name, analysis_end__isnull=False)
        if date is not None:
            f &= Q(analysis_end__gte=date)

        try:
            return self.filter(f).order_by('analysis_end')[0]
        except IndexError:
            return None

    def get(self, name, date, window=datetime.timedelta(seconds=1)):
        f = Q(name_obj__name=name)
        if window is not None:
            f &= Q(analysis_end__gte=date-window, analysis_end__lt=date)

            try:
                return self.filter(f).latest()
            except self.model.DoesNotExist:
                return None
        else:
            f &= Q(analysis_end=date)
            try:
                return self.filter(f).get()
            except self.model.DoesNotExist:
                return None

class DomainNameAnalysis(models.Model):
    MAX_TTL = 100000000

    name_obj = models.ForeignKey(DomainName, related_name='analyses')
    analysis_start = models.DateTimeField()
    analysis_end = models.DateTimeField(blank=True, null=True)
    dep_analysis_end = models.DateTimeField(blank=True, null=True)

    version = models.PositiveSmallIntegerField(default=17)

    has_ns = models.BooleanField(default=False)
    has_soa = models.BooleanField(default=False)
    signed = models.BooleanField(default=False)
    nxdomain = models.BooleanField(default=False)
    empty_nonterminal = models.BooleanField(default=False)
    no_referral_response = models.BooleanField(default=False)
    cname = models.ManyToManyField(DomainName, related_name='cname_references')
    mx = models.ManyToManyField(DomainName, related_name='mx_references')
    ns = models.ManyToManyField(DomainName, related_name='ns_references')
    ptr = models.ManyToManyField(DomainName, related_name='ptr_references')
    external_signers = models.ManyToManyField(DomainName, related_name='rrsig_references')

    referral_rdtype = UnsignedSmallIntegerField(blank=True, null=True)
    cname_rdtypes_raw = models.CommaSeparatedIntegerField(max_length=64, blank=True)

    ttl_mapping_raw = models.CommaSeparatedIntegerField(max_length=2048)
    dependency_min_ttl = UnsignedIntegerField(default=MAX_TTL)

    format_errors = models.CharField(max_length=4096, blank=True)

    # the attributes below are all specific to "zones"
    nsec_rdtype = UnsignedSmallIntegerField(blank=True, null=True)

    serial = UnsignedIntegerField(blank=True, null=True)
    rname = DomainNameField(max_length=2048, blank=True, null=True)
    mname = DomainNameField(max_length=2048, blank=True, null=True)

    ns_mappings = models.ManyToManyField(NSMapping, related_name='s+')

    nxdomain_name = DomainNameField(max_length=2048, canonicalize=False, blank=True, null=True)
    nxdomain_rdtype = UnsignedSmallIntegerField(blank=True, null=True)
    nxrrset_name = DomainNameField(max_length=2048, canonicalize=False, blank=True, null=True)
    nxrrset_rdtype = UnsignedSmallIntegerField(blank=True, null=True)

    objects = DomainNameAnalysisManager()

    rd_default = False
    do_default = True
    cd_default = True
    ad_default = False

    #XXX find the right place for this
    dlv_domain = dns.name.from_text('dlv.isc.org.')

    class Meta:
        unique_together = (('name_obj', 'analysis_start'),)
        get_latest_by = 'analysis_end'

    def __init__(self, *args, **kwargs):
        super(DomainNameAnalysis, self).__init__(*args, **kwargs)
        self._server_analysis_cache = {}
        self._response_cache = {}
        self._aggregated_response_cache = {}
        self._cache_okay = self.analysis_end is not None
        self.reverse_dependencies = set()
        self.dependency = None
        self.analysis_in_progress = False

    def __unicode__(self):
        return util.format.humanize_name(self.name, True)

    def __str__(self):
        return util.format.humanize_name(self.name)

    def to_unicode(self):
        return unicode(self)

    def to_text(self):
        return str(self)

    def _get_ttl_mapping(self):
        if not hasattr(self, '_ttl_mapping') or self._ttl_mapping is None:
            self._ttl_mapping = {}
            if self.ttl_mapping_raw:
                vals = map(int, self.ttl_mapping_raw.split(','))
                for i in range(0, len(vals), 2):
                    self._ttl_mapping[vals[i]] = vals[i+1]
        return self._ttl_mapping

    ttl_mapping = property(_get_ttl_mapping)

    def _get_cname_rdtypes(self):
        if not hasattr(self, '_cname_rdtypes') or self._cname_rdtypes is None:
            self._cname_rdtypes = set()
            if self.cname_rdtypes_raw:
                self._cname_rdtypes = set(map(int, self.cname_rdtypes_raw.split(',')))
        return self._cname_rdtypes

    cname_rdtypes = property(_get_cname_rdtypes)

    def save(self, *args, **kwargs):
        ttl_mapping_list = self.ttl_mapping.items()
        ttl_mapping_list.sort()
        ttl_mapping_list_flat = [val for mapping in ttl_mapping_list for val in mapping]
        self.ttl_mapping_raw = ','.join(map(str, ttl_mapping_list_flat))

        self.cname_rdtypes_raw = ','.join(map(str, self.cname_rdtypes))
        super(DomainNameAnalysis, self).save(*args, **kwargs)

    def delete_with_reverse_dependencies(self, callback=None):
        reverse_deps = self.reverse_dependencies.copy()
        for dependent_name_obj in reverse_deps:
            dependent_name_obj.delete_with_reverse_dependencies(callback)
        self.release_analysis(callback)
        if self.pk is not None:
            self.delete()

    def save_with_reverse_dependencies(self, callback=None):
        reverse_deps = self.reverse_dependencies.copy()
        for dependent_name_obj in reverse_deps:
            dependent_name_obj.save_with_reverse_dependencies(callback)
        self.schedule_refresh()
        self.save()
        self.release_analysis(callback)

    def release_analysis(self, callback=None):
        if self.analysis_in_progress:
            DomainName.objects.filter(pk=self.name_obj.pk, analysis_start=self.analysis_start).update(analysis_start=None)
            self.name_obj.analysis_start = None
            self.analysis_in_progress = False
        if callback is not None:
            callback(self)

    def can_cache(self):
        return self._cache_okay

    def allow_cache(self):
        self._cache_okay = True

    #def reset_cache(self):
    #    self._server_analysis_cache = {}
    #    self._response_cache = {}
    #    self._parent = None
    #    self._dlv = None
    #    self._all_servers = None
    #    self._auth_servers = None

    def canonical_rdtypes(self):
        return self.rdtypes().union(self.cname_rdtypes)

    def rdtypes(self):
        return set(self.ttl_mapping)

    def min_ttl(self):
        if self.empty_nonterminal or self.nxdomain or not self.rdtypes():
            return self.zone.min_ttl()
        else:
            return min(self.ttl_mapping.values() + [self.dependency_min_ttl])

    def add_ns_mappings(self, *mappings):
        if len(mappings) == 1 and isinstance(mappings[0], dict):
            mappings = mappings[0].items()
        elif len(mappings) == 2 and not isinstance(mappings[0], (tuple, list)):
            mappings = ((mappings[0], mappings[1]),)

        for name, ip_address in mappings:
            ip_address_key = util.format.ip_to_wire(ip_address)
            self.add_designated_servers(ip_address)
            self.ns_mappings.add(NSMapping.objects.get_or_create(name=name, server=self._server_analysis_cache[ip_address_key].server)[0])

    def add_designated_servers(self, *servers):
        for server in servers:
            server_key = util.format.ip_to_wire(server)
            if server_key not in self._server_analysis_cache:
                server_obj = DNSServer.objects.get_or_create(ip_address=util.format.fix_ipv6(server))[0]
                self._server_analysis_cache[server_key] = DNSServerAnalysis.objects.get_or_create(name_analysis=self, server=server_obj)[0]

    def add_max_payload(self, server, low, high):
        server_key = util.format.ip_to_wire(server)
        self._server_analysis_cache[server_key].max_payload_low = low
        self._server_analysis_cache[server_key].max_payload_high = high
        self._server_analysis_cache[server_key].save()

    def get_max_payload(self):
        max_payload_mapping = {}
        for server_analysis in self.zone.server_analyses.filter(max_payload_low__isnull=False, max_payload_high__isnull=False):
            max_payload_mapping[server_analysis.server.ip_address] = (server_analysis.max_payload_low, server_analysis.max_payload_high)
        return max_payload_mapping

    def set_tcp_availability(self, server, val):
        server_key = util.format.ip_to_wire(server)
        self._server_analysis_cache[server_key].responsive_tcp = val
        self._server_analysis_cache[server_key].save()

    def is_zone(self):
        return self.has_ns or self.name == dns.name.root

    def get_name(self, name, dep=False):
        if dep:
            date = self.dep_analysis_end
        else:
            date = self.analysis_end
        return self.__class__.objects.latest(name, date)

    def _get_zone(self):
        if self.is_zone():
            return self
        else:
            return self.parent

    zone = property(_get_zone)

    def _get_parent(self):
        if not hasattr(self, '_parent_obj') or self._parent_obj is None:
            try:
                parent_obj = self.get_name(self.name.parent())
            except dns.name.NoParent:
                self._parent_obj = None
            else:
                if parent_obj.is_zone():
                    self._parent_obj = parent_obj
                else:
                    self._parent_obj = parent_obj.parent

        return self._parent_obj

    def _set_parent(self, name_obj):
        self._parent_obj = name_obj

    parent = property(_get_parent, _set_parent)

    def _get_name(self):
        try:
            return self.name_obj.name
        except DomainName.DoesNotExist:
            pass
        if hasattr(self, '_name'):
            return self._name
        else:
            return None

    def _set_name(self, name):
        self._name = name

    name = property(_get_name, _set_name)

    def parent_name(self):
        if self.parent is not None:
            return self.parent.name
        return None

    def dlv_name(self):
        return util.dnssec.dlv_name(self.name, self.dlv_domain)

    def _get_dlv(self):
        if not hasattr(self, '_dlv') or self._dlv is None:
            self._dlv = self.get_name(self.dlv_domain)
        return self._dlv

    def _set_dlv(self, name_obj):
        self._dlv = name_obj

    dlv = property(_get_dlv, _set_dlv)

    def all_servers(self, proto=None):
        if not hasattr(self, '_all_servers') or self._all_servers is None:
            qs = self.zone.server_analyses.all()
            if proto is not None:
                qs = qs.extra(where=['family(ip_address)=%s'], params=(proto,))
            val = set(qs.values_list('server__ip_address', flat=True))
            if not self.can_cache():
                return val
            self._all_servers = val
        return self._all_servers

    def auth_servers(self, proto=None):
        if not hasattr(self, '_auth_servers') or self._auth_servers is None:
            qs = self.zone.server_analyses.filter(Q(authoritative=True)|Q(responsive_udp=True))
            if proto is not None:
                qs = qs.extra(where=['family(ip_address)=%s'], params=(proto,))
            val = set(qs.values_list('server__ip_address', flat=True))
            if not self.can_cache():
                return val
            self._auth_servers = val
        return self._auth_servers

    def responsive_servers(self, proto=None):
        if not hasattr(self, '_responsive_servers') or self._responsive_servers is None:
            qs = self.zone.server_analyses.filter(responsive_udp=True)
            if proto is not None:
                qs = qs.extra(where=['family(ip_address)=%s'], params=(proto,))
            val = set(qs.values_list('server__ip_address', flat=True))
            if not self.can_cache():
                return val
            self._responsive_servers = val
        return self._responsive_servers

    def is_responsive(self, proto=None):
        return bool(self.responsive_servers(proto))

    def add_response(self, client, server, qname, rdtype, rdclass, rd, do, cd, ad, response, time=None, process=True):
        #XXX this doesn't work for referrals
        #assert server in self._server_analysis_cache, 'No server analysis exists for IP "%s"' % server

        if time is None:
            time = now()

        response_obj = DNSResponse.objects.create(client=client, server=server, qname=qname, rdtype=rdtype, rdclass=rdclass,
                rd=rd, do=do, cd=cd, ad=ad, time=time, analysis=self)
        response_obj.response = response
        response_obj.save()
        
        if process:
            self._process_response(response_obj)
        return response_obj

    def process_responses(self):
        self._process_responses(self.responses.all())

    def _process_responses(self, response_list):
        for response_obj in response_list:
            self._process_response(response_obj)

    def _process_response(self, response_obj):
        server_key = util.format.ip_to_wire(response_obj.server)
        if not response_obj.response_timeout:
            #TODO - check to see if response came over TCP; then don't repeat TCP check
            if server_key in self._server_analysis_cache and not self._server_analysis_cache[server_key].responsive_udp:
                self._server_analysis_cache[server_key].responsive_udp = True
                self._server_analysis_cache[server_key].save()

        if not response_obj.response_valid():
            return

        # authoritative records
        if response_obj.flags & dns.flags.AA:
            if response_obj.rdtype not in (dns.rdatatype.DS, dns.rdatatype.DLV):
                if server_key not in self._server_analysis_cache:
                    server_obj = DNSServer.objects.get_or_create(ip_address=util.format.fix_ipv6(response_obj.server))[0]
                    self._server_analysis_cache[server_key] = DNSServerAnalysis.objects.get_or_create(name_analysis=self, server=server_obj)[0]
                if not self._server_analysis_cache[server_key].authoritative or \
                        not self._server_analysis_cache[server_key].responsive_udp:
                    self._server_analysis_cache[server_key].responsive_udp = True
                    self._server_analysis_cache[server_key].authoritative = True
                    self._server_analysis_cache[server_key].save()

            rrset = None
            try:
                rrset = response_obj.response.find_rrset(response_obj.response.answer, response_obj.qname, response_obj.rdclass, response_obj.rdtype)
            except KeyError:
                try:
                    rrset = response_obj.response.find_rrset(response_obj.response.answer, response_obj.qname, response_obj.rdclass, dns.rdatatype.CNAME)
                except KeyError:
                    pass

            if rrset is not None:
                if response_obj.qname in (self.name, self.dlv_name()):
                    if rrset.rdtype == dns.rdatatype.NS:
                        self.has_ns = True
                        for ns in rrset:
                            self.ns.add(DomainName.objects.get_or_create(name=ns.target)[0])
                    elif rrset.rdtype == dns.rdatatype.SOA:
                        self.has_soa = True
                        if self.serial is None or rrset[0].serial > self.serial:
                            self.serial = rrset[0].serial
                            self.rname = rrset[0].rname
                            self.mname = rrset[0].mname
                    elif rrset.rdtype == dns.rdatatype.MX:
                        for mx in rrset:
                            self.mx.add(DomainName.objects.get_or_create(name=mx.exchange)[0])
                    elif rrset.rdtype == dns.rdatatype.CNAME:
                        self.cname.add(DomainName.objects.get_or_create(name=rrset[0].target)[0])
                    elif rrset.rdtype == dns.rdatatype.PTR:
                        self.ptr.add(DomainName.objects.get_or_create(name=rrset[0].target)[0])

                    # check whether it is signed and whether the signer matches
                    try:
                        rrsig_rrset = response_obj.response.find_rrset(response_obj.response.answer, response_obj.qname, response_obj.rdclass, dns.rdatatype.RRSIG, rrset.rdtype)
                        self.signed = True

                        for rrsig in rrsig_rrset:
                            if rrsig_rrset.covers == dns.rdatatype.DS and rrsig.signer == self.parent_name():
                                pass
                            elif rrsig_rrset.covers == dns.rdatatype.DLV and rrsig.signer == self.dlv_name():
                                pass
                            elif rrsig.signer == self.zone.name:
                                pass
                            else:
                                self.external_signers.add(DomainName.objects.get_or_create(name=rrsig.signer)[0])
                                #sys.stderr.write('warning: external signer: %s for %s(%s)\n' % (rrsig.signer, name_obj, dns.rdatatype.to_text(rrsig.covers())))
                    except KeyError:
                        pass

                    self.ttl_mapping[rrset.rdtype] = min(self.ttl_mapping.get(rrset.rdtype, self.MAX_TTL), rrset.ttl)

            else:
                try:
                    soa_rrset = filter(lambda x: x.rdtype == dns.rdatatype.SOA, response_obj.response.authority)[0]
                    if soa_rrset.name == self.name:
                        self.has_soa = True
                except IndexError:
                    pass

            if self.nsec_rdtype is None:
                nsec_rrsets = filter(lambda x: x.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3), response_obj.response.authority)
                if nsec_rrsets:
                    self.nsec_rdtype = nsec_rrsets[0].rdtype

        # delegation records
        else:
            try:
                rrset = response_obj.response.find_rrset(response_obj.response.authority, self.name, dns.rdataclass.IN, dns.rdatatype.NS)
                self.ttl_mapping[-dns.rdatatype.NS] = min(self.ttl_mapping.get(-dns.rdatatype.NS, self.MAX_TTL), rrset.ttl)
                self.has_ns = True
                for ns in rrset:
                    self.ns.add(DomainName.objects.get_or_create(name=ns.target)[0])
            except KeyError:
                pass

    def get_responses(self, qname, rdtype, rd=None, do=None, cd=None, ad=None, servers=None, extra_filter=None):
        use_cache = self.can_cache() and extra_filter is None and servers is None

        if rd is None: rd = self.rd_default
        if do is None: do = self.do_default
        if cd is None: cd = self.cd_default
        if ad is None: ad = self.ad_default

        if not isinstance(qname, dns.name.Name):
            qname = dns.name.from_text(qname)

        zone = self
        if servers is None:
            if qname != dns.name.root:
                if qname == self.name and rdtype == dns.rdatatype.DS:
                    zone = self.parent
                elif qname == self.dlv_name() and rdtype == dns.rdatatype.DLV:
                    if self.dlv is not None:
                        zone = self.dlv
                    else:
                        return {}
            servers = zone.all_servers()

        if (qname, rdtype, rd, do, cd, ad) not in self._response_cache or not use_cache:
            val = {}
            f = Q(qname=qname, rdtype=rdtype, rd=rd, do=do, ad=ad, server__in=servers)
            if extra_filter is not None:
                f &= extra_filter
            for response_obj in self.responses.filter(f & Q(cd=cd)):
                if (response_obj.response is None or response_obj.response.rcode() == dns.rcode.SERVFAIL) and not cd:
                    try:
                        response_obj = self.responses.get(f & Q(client=response_obj.client, server=response_obj.server, cd=True))
                    except DNSResponse.DoesNotExist:
                        pass
                if response_obj.server not in val:
                    val[response_obj.server] = {}
                val[response_obj.server][response_obj.client] = response_obj
            if not use_cache:
                return val
            self._response_cache[(qname, rdtype, rd, do, cd, ad)] = val
        return self._response_cache[(qname, rdtype, rd, do, cd, ad)]

    def get_referral_responses(self):
        if self.referral_rdtype is None:
            return {}
        if not self.parent:
            servers = self.auth_servers()
        else:
            servers = self.parent.auth_servers()
        if not hasattr(self, '_referral_responses') or self._referral_responses is None:
            val = self.get_responses(self.name, self.referral_rdtype, servers=servers)
            if not self.can_cache():
                return val
            self._referral_responses = val
        return self._referral_responses

    def no_non_auth_parent(self):
        responses = self.get_referral_responses()
        if not responses:
            return False
        responses_only = [r.response for server in responses for r in responses[server].values()]
        return util.dnsutil.all_authoritative_answer(self.name, self.referral_rdtype, responses_only)

    def get_glue_ip_mapping(self, include_auth_answers=False):
        if not hasattr(self, '_glue_ip_mapping') or self._glue_ip_mapping is None:
            glue_mapping = {}
            responses = self.get_referral_responses()
            for server in responses:
                for response_obj in responses[server].values():
                    if response_obj.response is None:
                        continue
                    if include_auth_answers or \
                            util.dnsutil.non_authoritative_referral_filter(self.name, self.referral_rdtype, response_obj.response):
                        ip_mapping = util.dnsutil.ips_for_ns_rrset_from_additional(self.name, response_obj.response)
                        for name, ip_set in ip_mapping.items():
                            name = name.canonicalize()
                            glue_mapping.setdefault(name, set())
                            glue_mapping[name].update(ip_set)
            if not self.can_cache():
                return glue_mapping
            self._glue_ip_mapping = glue_mapping
        return self._glue_ip_mapping

    def get_auth_ip_mapping(self):
        auth_mapping = {}
        for name in self.get_ns_names():
            auth_mapping[name] = set()
        for ns_map in self.ns_mappings.select_related('DNSServer'):
            auth_mapping[ns_map.name].add(ns_map.server.ip_address)
        return auth_mapping

    def get_ip_name_mapping(self):
        if not hasattr(self, '_ip_name_mapping') or self._ip_name_mapping is None:
            ip_name_mapping = {}
            for name, ip_set in self.get_auth_ip_mapping().items():
                for ip in ip_set:
                    if ip not in ip_name_mapping:
                        ip_name_mapping[ip] = []
                    ip_name_mapping[ip].append(name)

            for name, ip_set in self.get_glue_ip_mapping().items():
                for ip in ip_set:
                    if ip not in ip_name_mapping:
                        ip_name_mapping[ip] = [name]
                    elif name not in ip_name_mapping[ip]:
                        ip_name_mapping[ip].append(name)

            if not self.can_cache():
                return ip_name_mapping
            self._ip_name_mapping = ip_name_mapping

        return self._ip_name_mapping

    def name_for_ip(self, ip):
        ip_name_mapping = self.get_ip_name_mapping()
        try:
            return ip_name_mapping[ip], self.name
        except KeyError:
            pass

        if self.parent is None:
            return [], None
        return self.parent.name_for_ip(ip)

    def get_ns_names_in_parent(self):
        if not hasattr(self, '_ns_names_in_parent') or self._ns_names_in_parent is None:
            val = set(self.get_glue_ip_mapping())
            if not self.can_cache():
                return val
            self._ns_names_in_parent = val
        return self._ns_names_in_parent

    def get_ns_names_in_child(self):
        if not hasattr(self, '_ns_names_in_child') or self._ns_names_in_child is None:
            rdata_set = self.all_rdata(self.name, dns.rdatatype.NS)
            if not rdata_set:
                for rdtype in (dns.rdatatype.A, dns.rdatatype.MX, dns.rdatatype.AAAA, dns.rdatatype.TXT):
                    rdata_set = self.all_rdata(self.name, rdtype, 'authority', response_rdtype=dns.rdatatype.NS)
                    if rdata_set:
                        break
            val = set([rr.target.canonicalize() for rr in rdata_set])
            if not self.can_cache():
                return val
            self._ns_names_in_child = val
        return self._ns_names_in_child

    def get_ns_names(self):
        return self.get_ns_names_in_parent().union(self.get_ns_names_in_child())

    def get_servers_in_parent(self):
        if not hasattr(self, '_servers_in_parent') or self._servers_in_parent is None:
            servers = set()
            if self.parent is None:
                return servers
            glue_ips = self.get_glue_ip_mapping()
            auth_ips = self.get_auth_ip_mapping()
            for name in glue_ips:
                in_bailiwick = name.is_subdomain(self.parent_name())
                glue_required = name.is_subdomain(self.name)
                if glue_required:
                    servers.update(glue_ips[name])
                elif in_bailiwick:
                    if glue_ips[name]:
                        servers.update(glue_ips[name])
                    else:
                        servers.update(auth_ips[name])
                else:
                    servers.update(auth_ips[name])
            if not self.can_cache():
                return servers
            self._servers_in_parent = servers
        return self._servers_in_parent

    def get_servers_in_child(self):
        if not hasattr(self, '_servers_in_child') or self._servers_in_child is None:
            servers = set()
            auth_ips = self.get_auth_ip_mapping()
            for name in auth_ips:
                servers.update(auth_ips[name])
            if not self.can_cache():
                return servers
            self._servers_in_child = servers
        return self._servers_in_child

    def get_stealth_servers(self):
        if not hasattr(self, '_stealth_servers') or self._stealth_servers is None:
            servers = self.auth_servers().difference(self.get_servers_in_child().union(self.get_servers_in_parent()))
            if not self.can_cache():
                return servers
            self._stealth_servers = servers
        return self._stealth_servers

    def updated_utc_str(self, delimiter=' ', show_tz=True):
        output = self.analysis_end.replace(microsecond=0).isoformat(delimiter)[:-6]
        if show_tz:
            output += ' UTC'
        return output

    def updated_ago_str(self):
        updated_ago = now() - self.analysis_end
        return util.format.humanize_time(updated_ago.seconds, updated_ago.days)

    def timestamp_url_encoded(self):
        dt = self.analysis_end.replace(microsecond=0)
        if self.analysis_end.microsecond > 0:
            dt += datetime.timedelta(seconds=1)
        return util.format.datetime_url_encode(dt)

    def base_url(self):
        name = util.format.name_url_encode(self.name)
        return '/d/%s/' % name

    def base_url_with_timestamp(self):
        return '%s%s/' % (self.base_url(), self.timestamp_url_encoded())

    def response_url(self, response, rrset=None, section=None, rdata=None):
        s = response.base_url(rrset, section, rdata)
        return '%sresponses%s' % (self.base_url_with_timestamp(), s[2:])

    def _get_previous(self):
        if not hasattr(self, '_previous') or self._previous is None:
            self._previous = self.__class__.objects.latest(self.name, self.analysis_end - datetime.timedelta(microseconds=1))
        return self._previous

    previous = property(_get_previous)

    def _get_next(self):
        if not hasattr(self, '_next') or self._next is None:
            self._next = self.__class__.objects.earliest(self.name, self.analysis_end + datetime.timedelta(microseconds=1))
        return self._next

    next = property(_get_next)

    def _get_latest(self):
        return self.__class__.objects.latest(self.name)

    latest = property(_get_latest)

    def _get_first(self):
        return self.__class__.objects.earliest(self.name)

    first = property(_get_first)

    def is_resolvable(self, trace=None):
        if trace is None:
            trace = []
        if self in trace:
            return True
        if self.no_referral_response:
            return False
        if self.parent is not None:
            # if parent is root (i.e., TLD)
            if self.parent.parent is None:
                if not self.parent.is_responsive():
                    return False
            # otherwise (i.e., SLD or lower)
            else:
                if not self.parent.is_resolvable(trace+[self]):
                    return False
        for cname in self.cname.all():
            if not self.get_name(cname.name, True).is_resolvable(trace+[self]):
                return False
        #TODO check all dependencies, not just CNAME
        return True

    def get_servers_authoritative_for_query(self, qname, rdtype):
        servers = set()
        responses = self.get_responses(qname, rdtype)
        for server in responses:
            for client in responses[server]:
                response_obj = responses[server][client]
                if response_obj.response is None:
                    continue
                if (self.rd_default or response_obj.response.flags & dns.flags.AA) and \
                        response_obj.response.rcode() in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                    servers.add((server, client))
        return servers

    def is_nxdomain(self, qname, rdtype):
        responses = self.get_responses(qname, rdtype)
        responses_only = [r.response for server in responses for r in responses[server].values()]
        return util.dnsutil.any_nxdomain(qname, rdtype, responses_only)

    def ds_nxdomain(self):
        return self.is_nxdomain(self.name, dns.rdatatype.DS)

    def get_aggregated_responses(self, qname, rdtype, section_name='answer', response_name=None, response_rdtype=None):
        can_cache = section_name == 'answer' and response_name is None and response_rdtype is None

        if response_name is None:
            response_name = qname
        if response_rdtype is None:
            response_rdtype = rdtype

        if (qname, rdtype) not in self._aggregated_response_cache or not can_cache:
            response_mapping = []
            responses = self.get_responses(qname, rdtype)
            for server in responses:
                for client in responses[server]:
                    response_obj = responses[server][client]
                    if response_obj.response is None:
                        continue
                    if (self.rd_default or response_obj.response.flags & dns.flags.AA) and \
                            response_obj.response.rcode() in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                        response_mapping.append(((server, client), response_obj.response))
            val = util.dnsutil.aggregate_responses(response_name, response_rdtype, response_mapping, section_name)
            if not can_cache:
                return val
            self._aggregated_response_cache[(qname, rdtype)] = val
        return self._aggregated_response_cache[(qname, rdtype)]

    def get_aggregated_error_responses(self, qname, rdtype):
        errors = {}
        responses = self.get_responses(qname, rdtype)
        for server in responses:
            for client in responses[server]:
                response_obj = responses[server][client]
                if response_obj.response is not None:
                    if response_obj.response.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                        status = 'Response had RCODE \'%s\'' % dns.rcode.to_text(response_obj.response.rcode())
                        if status not in errors:
                            errors[status] = []
                        errors[status].append((server, client))
                    elif not (self.rd_default or response_obj.response.flags & dns.flags.AA):
                        if 'Not authoritative (lame)' not in errors:
                            errors['Not authoritative (lame)'] = []
                        errors['Not authoritative (lame)'].append((server, client))
                elif response_obj.response_formerr:
                    if 'Malformed response received' not in errors:
                        errors['Malformed response received'] = []
                    errors['Malformed response received'].append((server, client))
                elif response_obj.response_timeout:
                    if 'Response timed out' not in errors:
                        errors['Response timed out'] = []
                    errors['Response timed out'].append((server, client))

        return errors.items()

    def all_rdata(self, qname, rdtype, section_name='answer', response_name=None, response_rdtype=None):
        rrsets_rrsigs = self.get_aggregated_responses(qname, rdtype, section_name, response_name, response_rdtype)[0]

        if response_rdtype is None:
            response_rdtype = rdtype

        rdata_set = set()
        for rrset, servers, rrsigs in rrsets_rrsigs:
            # could be a CNAME; if not the right type, then just move along
            if rrset.rdtype == response_rdtype:
                rdata_set.update(rrset)
        return rdata_set

    def ds_set(self, use_dlv=False):
        if self.parent is None:
            return []
        if use_dlv:
            dlv_name = self.dlv_name()
            if dlv_name is None:
                return set()
            qname = dlv_name
            rdtype = dns.rdatatype.DLV
        else:
            qname = self.name
            rdtype = dns.rdatatype.DS
        return self.all_rdata(qname, rdtype)

    def dnskey_set(self):
        return self.all_rdata(self.name, dns.rdatatype.DNSKEY)

    def dnskeys_for_ds(self, ds, supported_ds_algorithms=None, use_dlv=False):
        rrsets_rrsigs = self.get_aggregated_responses(self.name, dns.rdatatype.DNSKEY)[0]
        if use_dlv:
            dlv_name = self.dlv_name()
            if dlv_name is None:
                return []
            qname = dlv_name
        else:
            qname = self.name
        return util.dnssec.dnskeys_for_ds(qname, ds, rrsets_rrsigs, supported_ds_algorithms)

    def ds_by_dnskey(self, use_dlv=False):
        grouped_ds = {}
        ds_set = self.ds_set(use_dlv=use_dlv)
        for ds in ds_set:
            for dnskey, valid in self.dnskeys_for_ds(ds):
                if (ds.algorithm, ds.key_tag, dnskey) not in grouped_ds:
                    grouped_ds[(ds.algorithm, ds.key_tag, dnskey)] = set()
                grouped_ds[(ds.algorithm, ds.key_tag, dnskey)].add((ds, valid))
        return grouped_ds

    def dnskeys_by_role(self):
        published = self.dnskey_set()

        revoked = set(filter(lambda x: x.flags & util.format.DNSKEY_FLAGS['revoke'], published))

        zsks = set()
        ksks = set()

        for rdtype in (dns.rdatatype.DNSKEY, dns.rdatatype.SOA, dns.rdatatype.MX, dns.rdatatype.A, dns.rdatatype.AAAA):
            rrsets_rrsigs, neg_responses, dname_rrsets_rrsigs, nsec_rrsets_rrsigs = self.get_aggregated_responses(self.name, rdtype)
            for rrset, servers, rrsigs in rrsets_rrsigs:
                for rrsig, ttl, servers in rrsigs:
                    for dnskey, valid in self.dnskeys_for_rrsig(rrsig, rrset):
                        if dnskey is None:
                            continue

                        if rrset.rdtype == dns.rdatatype.DNSKEY:
                            ksks.add(dnskey)
                            try:
                                published.remove(dnskey)
                            except KeyError:
                                pass
                        else:
                            zsks.add(dnskey)
                            try:
                                published.remove(dnskey)
                            except KeyError:
                                pass

        return zsks, ksks, published, revoked

    def potential_trusted_keys(self):
        zsks, ksks, published, revoked = self.dnskeys_by_role()

        active_ksks = ksks.difference(zsks).difference(revoked)
        if active_ksks:
            return active_ksks
        return ksks.difference(revoked)

    def servers_with_ds(self, ds, use_dlv=False):
        if isinstance(ds, (list, tuple)):
            ds = set(ds)
        elif not isinstance(ds, set):
            ds = set((ds,))

        if use_dlv:
            dlv_name = self.dlv_name()
            if dlv_name is None:
                return set()
            qname = dlv_name
            rdtype = dns.rdatatype.DLV
        else:
            qname = self.name
            rdtype = dns.rdatatype.DS

        servers_with_ds = set()
        rrsets_rrsigs = self.get_aggregated_responses(qname, rdtype)[0]
        for rrset, servers, rrsigs in rrsets_rrsigs:
            if not ds.difference(rrset):
                servers_with_ds.update(servers)

        return servers_with_ds

    def servers_with_dnskey(self, dnskey):
        servers_with_dnskey = set()
        rrsets_rrsigs = self.get_aggregated_responses(self.name, dns.rdatatype.DNSKEY)[0]
        for rrset, servers, rrsigs in rrsets_rrsigs:
            if dnskey in rrset:
                servers_with_dnskey.update(servers)

        return servers_with_dnskey

    def servers_with_rrset(self, rrset):
        servers_with_rrset = set()
        rrsets_rrsigs = self.get_aggregated_responses(rrset.name, rrset.rdtype)[0]

        for rrset1, servers, rrsigs in rrsets_rrsigs:
            if rrset1 == rrset:
                servers_with_rrset.update(servers)

        return servers_with_rrset

    def dnskeys_for_rrsig(self, rrsig, rrset, supported_dnssec_algorithms=None):
        rrsets_rrsigs = self.get_aggregated_responses(self.name, dns.rdatatype.DNSKEY)[0]
        return util.dnssec.dnskeys_for_rrsig(rrsig, rrset, rrsets_rrsigs, supported_dnssec_algorithms)

    def schedule_refresh(self):
        # don't schedule names that don't exist
        if self.is_responsive() and (self.nxdomain or self.empty_nonterminal or not self.rdtypes()):
            self.name_obj.clear_refresh()
            return

        # check against refresh blacklist
        for black in settings.BLACKLIST_FROM_REFRESH:
            if self.name.is_subdomain(black):
                self.name_obj.clear_refresh()
                return

        # scan dlv and root every hour
        if self.name in (dns.name.root, self.dlv_domain):
            refresh_interval = 3600
        # if we are a TLD, then re-analyze every six hours
        elif len(self.name.labels) <= 2:
            refresh_interval = 21600
        # if the servers in the parent zone are unresponsive,
        # then don't schedule a refresh for this name
        elif self.no_referral_response:
            return
        # if the servers in this zone are unresponsive,
        # then try every two days
        elif not self.is_responsive():
            refresh_interval = 172800
        # if we are a signed zone, then re-analyze every eight hours
        elif self.is_zone() and self.signed:
            refresh_interval = 28800
        # if we are an unsigned zone, then re-analyze every two days
        elif self.is_zone():
            refresh_interval = 172800
        else:
            self.name_obj.clear_refresh()
            return

        refresh_offset = int(hashlib.sha1(self.name.canonicalize().to_text()).hexdigest()[-9:], 16) % refresh_interval
        self.name_obj.set_refresh(refresh_interval, refresh_offset)

class DNSServerAnalysis(models.Model):
    name_analysis = models.ForeignKey(DomainNameAnalysis, related_name='server_analyses')
    server = models.ForeignKey(DNSServer)
    #TODO determine what responsive really means - does it mean gets a response, gets a valid response?
    responsive_udp = models.BooleanField(default=False)
    responsive_tcp = models.NullBooleanField()
    authoritative = models.NullBooleanField()
    max_payload_low = UnsignedSmallIntegerField(blank=True, null=True)
    max_payload_high = UnsignedSmallIntegerField(blank=True, null=True)

    class Meta:
        unique_together = (('name_analysis', 'server'),)

    def __unicode__(self):
        return '%s (%s)' % (self.name_analysis.name.to_unicode(), self.server)

    def __str__(self):
        return '%s (%s)' % (self.name_analysis.name.to_text(), self.server)

class ResourceRecord(models.Model):
    name = DomainNameField(max_length=2048)
    rdtype = UnsignedSmallIntegerField()
    rdclass = UnsignedSmallIntegerField()
    rdata_wire = BinaryField()

    rdata_name = DomainNameField(max_length=2048, blank=True, null=True, db_index=True)
    rdata_address = models.GenericIPAddressField(blank=True, null=True, db_index=True)

    class Meta:
        unique_together = (('name', 'rdtype', 'rdclass', 'rdata_wire'),)

    def __unicode__(self):
        return '%s %s %s %s' % (self.name.to_unicode(), dns.rdataclass.to_text(self.rdclass), dns.rdatatype.to_text(self.rdtype), self.rdata)

    def __str__(self):
        return '%s %s %s %s' % (self.name.to_text(), dns.rdataclass.to_text(self.rdclass), dns.rdatatype.to_text(self.rdtype), self.rdata)

    def _set_rdata(self, rdata):
        self._rdata = rdata
        wire = StringIO.StringIO()
        rdata.to_wire(wire)
        self.rdata_wire = wire.getvalue()
        for name, value in self.rdata_extra_field_params(rdata).items():
            setattr(self, name, value)

    def _get_rdata(self):
        if not hasattr(self, '_rdata') or self._rdata is None:
            if not self.rdata_wire:
                return None
            self._rdata = dns.rdata.from_wire(self.rdclass, self.rdtype, self.rdata_wire, 0, len(self.rdata_wire))
        return self._rdata

    rdata = property(_get_rdata, _set_rdata)

    @classmethod
    def rdata_extra_field_params(cls, rdata):
        return { 'rdata_name': None, 'rdata_address': None }

class ResourceRecordWithNameInRdata(ResourceRecord):
    _rdata_name_field = None

    class Meta:
        proxy = True

    @classmethod
    def rdata_extra_field_params(cls, rdata):
        params = super(ResourceRecordWithNameInRdata, cls).rdata_extra_field_params(rdata)
        if params:
            params.update({ 'rdata_name': getattr(rdata, cls._rdata_name_field) })
        return params

class ResourceRecordWithAddressInRdata(ResourceRecord):
    _rdata_address_field = None

    class Meta:
        proxy = True

    @classmethod
    def rdata_extra_field_params(cls, rdata):
        params = super(ResourceRecordWithAddressInRdata, cls).rdata_extra_field_params(rdata)
        if params:
            params.update({ 'rdata_address': getattr(rdata, cls._rdata_address_field) })
        return params

class ResourceRecordA(ResourceRecordWithAddressInRdata):
    class Meta:
        proxy = True

    _rdata_address_field = 'address'

class ResourceRecordSOA(ResourceRecordWithNameInRdata):
    class Meta:
        proxy = True

    _rdata_name_field = 'mname'

class ResourceRecordNS(ResourceRecordWithNameInRdata):
    class Meta:
        proxy = True

    _rdata_name_field = 'target'

class ResourceRecordMX(ResourceRecordWithNameInRdata):
    class Meta:
        proxy = True

    _rdata_name_field = 'exchange'

class ResourceRecordDNSKEYRelated(ResourceRecord):
    algorithm = models.PositiveSmallIntegerField()
    key_tag = UnsignedSmallIntegerField(db_index=True)
    expiration = models.DateTimeField(blank=True, null=True)
    inception = models.DateTimeField(blank=True, null=True)

    @classmethod
    def rdata_extra_field_params(cls, rdata):
        params = super(ResourceRecordDNSKEYRelated, cls).rdata_extra_field_params(rdata)
        if params:
            params.update({ 'algorithm': rdata.algorithm,
                    'key_tag': None,
                    'expiration': None,
                    'inception': None
            })
        return params

class ResourceRecordDNSKEY(ResourceRecordDNSKEYRelated):
    class Meta:
        proxy = True

    @classmethod
    def rdata_extra_field_params(cls, rdata):
        params = super(ResourceRecordDNSKEY, cls).rdata_extra_field_params(rdata)
        if params:
            params.update({ 'key_tag': util.dnssec.key_tag(rdata) })
        return params

class ResourceRecordDS(ResourceRecordDNSKEYRelated):
    class Meta:
        proxy = True

    @classmethod
    def rdata_extra_field_params(cls, rdata):
        params = super(ResourceRecordDS, cls).rdata_extra_field_params(rdata)
        if params:
            params.update({ 'key_tag': rdata.key_tag })
        return params

class ResourceRecordRRSIG(ResourceRecordDNSKEYRelated):
    class Meta:
        proxy = True

    @classmethod
    def rdata_extra_field_params(cls, rdata):
        params = super(ResourceRecordRRSIG, cls).rdata_extra_field_params(rdata)
        if params:
            exp = time.gmtime(rdata.expiration)
            inc = time.gmtime(rdata.inception)
            params.update({ 'key_tag': rdata.key_tag,
                    'expiration': datetime.datetime(*exp[:6], tzinfo=utc),
                    'inception': datetime.datetime(*inc[:6], tzinfo=utc)
            })
        return params

class ResourceRecordManager(models.Manager):
    _rdtype_model_map = {
            dns.rdatatype.SOA: ResourceRecordSOA,
            dns.rdatatype.A: ResourceRecordA,
            dns.rdatatype.AAAA: ResourceRecordA,
            dns.rdatatype.NS: ResourceRecordNS,
            dns.rdatatype.MX: ResourceRecordMX,
            dns.rdatatype.PTR: ResourceRecordNS,
            dns.rdatatype.CNAME: ResourceRecordNS,
            dns.rdatatype.DNAME: ResourceRecordNS,
            dns.rdatatype.SRV: ResourceRecordNS,
            dns.rdatatype.DNSKEY: ResourceRecordDNSKEY,
            dns.rdatatype.RRSIG: ResourceRecordRRSIG,
            dns.rdatatype.DS: ResourceRecordDS,
    }

    def model_for_rdtype(self, rdtype):
        return self._rdtype_model_map.get(rdtype, ResourceRecord)

ResourceRecord.add_to_class('objects', ResourceRecordManager())

class DNSResponseManager(models.Manager):
    def get(self, qname, rdtype, server, client, rd, do, cd, date, window=datetime.timedelta(seconds=1)):
        f = Q(qname=qname, rdtype=rdtype, server=server, client=client, rd=rd, do=do, cd=cd)
        if window is not None:
            f &= Q(time__gte=date-window, time__lt=date)
            try:
                return self.filter(f).latest()
            except self.model.DoesNotExist:
                return None
        else:
            f &= Q(time=date)
            try:
                return self.filter(f).get()
            except self.model.DoesNotExist:
                return None

class DNSResponse(models.Model):
    SECTIONS = { 'QUESTION': 0, 'ANSWER': 1, 'AUTHORITY': 2, 'ADDITIONAL': 3 }

    analysis = models.ForeignKey(DomainNameAnalysis, related_name='responses', blank=True, null=True)

    version = models.PositiveSmallIntegerField(default=1)

    # network parameters
    server = models.GenericIPAddressField()
    client = models.GenericIPAddressField()
    time = models.DateTimeField()

    # request parameters
    qname = DomainNameField(max_length=2048, canonicalize=False)
    rdtype = UnsignedSmallIntegerField()
    rdclass = UnsignedSmallIntegerField()

    rd = models.BooleanField()
    cd = models.BooleanField()
    ad = models.BooleanField()
    do = models.BooleanField()

    req_edns_udp_payload = UnsignedSmallIntegerField(blank=True, null=True)
    req_edns_flags = UnsignedIntegerField(blank=True, null=True)
    req_edns_options = BinaryField(blank=True, null=True)

    tcp = models.NullBooleanField()

    # response attributes
    queryid = UnsignedSmallIntegerField(default=0)
    flags = UnsignedSmallIntegerField(default=0)

    has_question = models.BooleanField(default=True)
    question_name = DomainNameField(max_length=2048, canonicalize=False, blank=True, null=True)
    question_rdtype = UnsignedSmallIntegerField(blank=True, null=True)
    question_rdclass = UnsignedSmallIntegerField(blank=True, null=True)

    edns_udp_payload = UnsignedSmallIntegerField(blank=True, null=True)
    edns_flags = UnsignedIntegerField(blank=True, null=True)
    edns_options = BinaryField(blank=True, null=True)

    # other attributes
    response_time = models.PositiveSmallIntegerField(blank=True, null=True)
    timeout_time = models.PositiveSmallIntegerField(blank=True, null=True)
    num_timeouts = models.PositiveSmallIntegerField(blank=True, null=True)
    msg_size = UnsignedSmallIntegerField(blank=True, null=True)

    response_timeout = models.BooleanField(default=False)
    response_formerr = models.BooleanField(default=False)

    objects = DNSResponseManager()

    class Meta:
        get_latest_by = 'time'

    def __init__(self, *args, **kwargs):
        super(DNSResponse, self).__init__(*args, **kwargs)
        self._response = None

    def __unicode__(self):
        return u'query: %s %s %s server: %s id: %d' % \
                (self.qname.to_unicode(), dns.rdataclass.to_text(self.rdclass), dns.rdatatype.to_text(self.rdtype),
                        self.server, self.queryid)

    def __str__(self):
        return 'query: %s %s %s server: %s id: %d' % \
                (self.qname.to_text(), dns.rdataclass.to_text(self.rdclass), dns.rdatatype.to_text(self.rdtype),
                        self.server, self.queryid)

    def _import_sections(self, response):
        rr_map_list = []
        rr_map_list.extend(self._import_section(response.answer, self.SECTIONS['ANSWER']))
        rr_map_list.extend(self._import_section(response.authority, self.SECTIONS['AUTHORITY']))
        rr_map_list.extend(self._import_section(response.additional, self.SECTIONS['ADDITIONAL']))
        ResourceRecordMapper.objects.bulk_create(rr_map_list)

    def _import_section(self, section, number):
        rr_map_list = []
        for index, rrset in enumerate(section):
            rr_cls = ResourceRecord.objects.model_for_rdtype(rrset.rdtype)
            for rr in rrset:
                sio = StringIO.StringIO()
                rr.to_wire(sio)
                rdata_wire = sio.getvalue()
                params = dict(rr_cls.rdata_extra_field_params(rr).items())
                with transaction.commit_manually():
                    try:
                        rr_obj, created = rr_cls.objects.get_or_create(name=rrset.name, rdtype=rrset.rdtype, \
                                rdclass=rrset.rdclass, rdata_wire=rdata_wire, defaults=params)
                    except:
                        transaction.rollback()
                        raise
                    else:
                        transaction.commit()
                if rrset.name.to_text() != rrset.name.canonicalize().to_text():
                    raw_name = rrset.name
                else:
                    raw_name = None
                rr_map_list.append(ResourceRecordMapper(response=self, section=number, rr=rr_obj, \
                        ttl=rrset.ttl, order=index, raw_name=raw_name))
        return rr_map_list

    def _export_sections(self, response):
        all_rr_maps = self.rr_mappings.select_related('rr').order_by('section', 'order')

        prev_section = None
        prev_order = None
        for rr_map in all_rr_maps:
            if rr_map.section != prev_section:
                if rr_map.section == self.SECTIONS['ANSWER']:
                    section = response.answer
                elif rr_map.section == self.SECTIONS['AUTHORITY']:
                    section = response.authority
                elif rr_map.section == self.SECTIONS['ADDITIONAL']:
                    section = response.additional
                prev_section = rr_map.section
                prev_order = None

            if prev_order != rr_map.order:
                if rr_map.rr.rdtype == dns.rdatatype.RRSIG:
                    covers = rr_map.rr.rdata.covers()
                else:
                    covers = dns.rdatatype.NONE
                rrset = dns.rrset.RRset(rr_map.rr.name, rr_map.rr.rdclass, rr_map.rr.rdtype, covers)
                section.append(rrset)
                response.index[(response.section_number(section),
                        rrset.name, rrset.rdclass, rrset.rdtype, rrset.covers, None)] = rrset
                prev_order = rr_map.order

            rrset.add(rr_map.rr.rdata, rr_map.ttl)

    def _set_response(self, response):
        assert self.pk is not None, 'Response object must be saved before response data can be associated with it'

        if isinstance(response, dns.message.Message):
            self._response = response
        else:
            if response == dns.exception.FormError:
                self.response_formerr = True
            if response == dns.exception.Timeout:
                self.response_timeout = True
            return

        msg_size = len(response.to_wire())
        if msg_size > 65535:
            self.msg_size = 65535
        self.msg_size = msg_size
        self.queryid = response.id
        self.flags = response.flags

        if response.edns >= 0:
            self.edns_udp_payload = response.payload
            self.edns_flags = response.ednsflags
            self.edns_options = ''
            for opt in response.options:
                s = StringIO.StringIO()
                opt.to_wire(s)
                data = s.getvalue()
                self.edns_options += struct.pack('!HH', opt.otype, len(data)) + data

        if response.question:
            self.has_question = True
            if response.question[0].name.to_text() != self.qname.to_text():
                self.question_name = response.question[0].name
            if response.question[0].rdtype != self.rdtype:
                self.question_rdtype = response.question[0].rdtype
            if response.question[0].rdclass != self.rdclass:
                self.question_rdclass = response.question[0].rdclass
        else:
            self.has_question = False

        self._import_sections(self._response)

    def response_valid(self):
        if self.response_formerr or self.response_timeout:
            return False
        return True

    def _get_response(self):
        if not hasattr(self, '_response') or self._response is None:
            # response has not been set yet
            if self.queryid is None:
                return None
            # response is not a message
            if not self.response_valid():
                return None
            self._response = dns.message.Message(self.queryid)
            self._response.flags = self.flags

            if self.has_question:
                qname, qrdclass, qrdtype = self.qname, self.rdclass, self.rdtype
                if self.question_name is not None:
                    qname = self.question_name
                if self.question_rdclass is not None:
                    qrdclass = self.question_rdclass
                if self.question_rdtype is not None:
                    qrdtype = self.question_rdtype
                self._response.question.append(dns.rrset.RRset(qname, qrdclass, qrdtype))

            if self.edns_udp_payload is not None:
                self._response.use_edns(self.edns_flags>>16, self.edns_flags, self.edns_udp_payload, 65536)
                index = 0
                while index < len(self.edns_options):
                    (otype, olen) = struct.unpack('!HH', self.edns_options[index:index + 4])
                    index += 4
                    opt = dns.edns.option_from_wire(otype, self.edns_options, index, olen)
                    self._response.options.append(opt)
                    index += olen

            self._export_sections(self._response)

        return self._response
        
    response = property(_get_response, _set_response)

    def updated_ago_str(self):
        updated_ago = now() - self.time
        return util.format.humanize_time(updated_ago.seconds, updated_ago.days)

    def base_url(self, rrset=None, section=None, rdata=None):
        name = util.format.name_url_encode(self.qname)
        
        url = '/r/%s/%d/%s/' % (name, self.rdtype, urllib.quote(self.server))
        if self.rd:
            url += 't'
        else:
            url += 'f'
        if self.do:
            url += 't'
        else:
            url += 'f'
        if self.cd:
            url += 't'
        else:
            url += 'f'
        #TODO consider ad flag
        url += '/%s/' % urllib.quote(self.client)

        if rrset is not None and section is not None:
            url += '#%s' % util.format.target_for_rrset(rrset, section, rdata)
        return url

    def timestamp_url_encoded(self):
        dt = self.time.replace(microsecond=0)
        if self.time.microsecond > 0:
            dt += datetime.timedelta(seconds=1)
        return util.format.datetime_url_encode(dt)

    def base_url_with_timestamp(self, rrset=None, section=None, rdata=None):
        s = '%s%s/' % (self.base_url(), self.timestamp_url_encoded())
        if rrset is not None and section is not None:
            s += '#%s' % util.format.target_for_rrset(rrset, section, rdata)
        return s

    def to_text(self):
        if self.response is not None:
            if self.response.question:
                question_ct = 1
            else:
                question_ct = 0
            answer_ct = 0
            for i in self.response.answer: answer_ct += len(i)
            authority_ct = 0
            for i in self.response.authority: authority_ct += len(i)
            additional_ct = 0
            for i in self.response.additional: additional_ct += len(i)
            if self.response.edns >= 0:
                additional_ct += 1
            s = ';; ->>HEADER<<- opcode: %s, status: %s, id: %d\n' % (dns.opcode.to_text(self.response.opcode()), dns.rcode.to_text(self.response.rcode()), self.response.id)
            s += ';; flags: %s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n\n' % (dns.flags.to_text(self.response.flags).lower(), question_ct, answer_ct, authority_ct, additional_ct)
            if self.response.edns >= 0:
                s += ';; OPT PSEUDOSECTION:\n'
                s += '; EDNS: version: %d, flags: %s; udp: %d\n' % (self.response.edns, dns.flags.edns_to_text(self.response.flags).lower(), self.response.payload)
            if self.response.question:
                s += ';; QUESTION SECTION:\n'
                s += ';%s          %s %s\n\n' % (self.response.question[0].name, dns.rdataclass.to_text(self.response.question[0].rdclass), dns.rdatatype.to_text(self.response.question[0].rdtype))
            for section, title in ((self.response.answer, 'ANSWER'), (self.response.authority, 'AUTHORITY'), (self.response.additional, 'ADDITIONAL')):
                if section:
                    s += ';; %s SECTION:\n' % title
                    for rrset in section:
                        for rr in rrset:
                            s += '%s\t\t%d\t%s\t%s\t%s\n' % (rrset.name, rrset.ttl, dns.rdataclass.to_text(rrset.rdclass), dns.rdatatype.to_text(rrset.rdtype), escape(rr.to_text()))
                    s += '\n'
            s += ';; SERVER: %s#53\n' % self.server
            s += ';; WHEN: %s\n' % self.time.strftime('%a %b %d %H:%M:%S %Y UTC')
            s += ';; MSG SIZE  rcvd: %d\n' % len(self.response.to_wire())
            return s

        elif self.response_formerr:
            return 'A response was received, but it was malformed.'
        elif self.response_timeout:
            return 'No response was received within the timeout period.'
        else:
            return 'No information available.'

    def to_html(self):
        if self.response is not None:
            if self.response.question:
                question_ct = 1
            else:
                question_ct = 0
            answer_ct = 0
            for i in self.response.answer: answer_ct += len(i)
            authority_ct = 0
            for i in self.response.authority: authority_ct += len(i)
            additional_ct = 0
            for i in self.response.additional: additional_ct += len(i)
            if self.response.edns >= 0:
                additional_ct += 1
            s = '<div id="header" class="section"><h3>;; -&gt;&gt;HEADER&lt;&lt;- <span id="opcode">opcode: %s</span>, <span id="status">status: %s</span>, <span id="query-id">id: %d</span></h3>\n' % (dns.opcode.to_text(self.response.opcode()), dns.rcode.to_text(self.response.rcode()), self.response.id)
            s += ';; <span id="flags">flags: '
            for val, abbr in dns.flags._flags_order:
                if val & self.response.flags:
                    s += ' <abbr title="%s">%s</abbr>' % (util.format.DNS_FLAG_DESCRIPTIONS[val], abbr.lower())
            s += '</span>; <span id="section-count">QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d</span><br /></div>\n' % (question_ct, answer_ct, authority_ct, additional_ct)
            if self.response.edns >= 0:
                s += '<div id="edns" class="section"><h3>;; OPT PSEUDOSECTION:</h3>\n'
                s += '; EDNS: <span id="edns-version">version: %d</span>, <span id="edns-flags">flags:' % self.response.edns
                for val, abbr in dns.flags._edns_flags_order:
                    if val & self.response.ednsflags:
                        s += ' <abbr title="%s">%s</abbr>' % (util.format.EDNS_FLAG_DESCRIPTIONS[val], abbr.lower())
                s += '</span>; <span id="edns-payload">udp: %d</span></div>\n' %  self.response.payload
            if self.response.question:
                s += '<div id="question" class="section"><h3>;; QUESTION SECTION:</h3>\n'
                s += '<table><tr id="question-rr"><td>;%s</td><td></td><td>%s</td><td>%s</td><td></td></tr></table></div>\n' % (self.response.question[0].name, dns.rdataclass.to_text(self.response.question[0].rdclass), dns.rdatatype.to_text(self.response.question[0].rdtype))
            for section, title in ((self.response.answer, 'ANSWER'), (self.response.authority, 'AUTHORITY'), (self.response.additional, 'ADDITIONAL')):
                if section:
                    s += '<div id="%s" class="section"><h3>;; %s SECTION:</h3><table>\n' % (title.lower(), title)
                    for rrset in section:
                        rrset_target = util.format.target_for_rrset(rrset, title)
                        s += '<tbody id="%s">' % rrset_target
                        for rr in rrset:
                            rr_target = util.format.target_for_rrset(rrset, title, rr)
                            #s += util.format.rr_to_html(rrset.name, rrset.rdclass, rrset.rdtype, rrset.ttl, rr)
                            s += '<tr id="%s"><td valign="top">%s</td><td valign="top">%d</td><td valign="top">%s</td><td valign="top">%s</td><td valign="top">%s</td></tr>\n' % (rr_target, rrset.name, rrset.ttl, dns .rdataclass.to_text(rrset.rdclass), dns.rdatatype.to_text(rrset.rdtype), escape(rr.to_text()))
                        s += '</tbody>'
                    s += '</table></div>'
            s += '<div id="stats" class="section">;; <span id="msg-server">SERVER: %s#53</span><br />\n' % self.server
            s += ';; <span id="msg-when">WHEN: %s</span><br />\n' % self.time.strftime('%a %b %d %H:%M:%S %Y UTC')
            s += ';; <span id="msg-size">MSG SIZE  rcvd: %d</span><br />\n' % len(self.response.to_wire())
            s += '</div>'
            return s
        elif self.response_formerr:
            return 'A response was received, but it was malformed.'
        elif self.response_timeout:
            return 'No response was received within the timeout period.'
        else:
            return 'No information available.'

class ResourceRecordMapper(models.Model):
    response = models.ForeignKey(DNSResponse, related_name='rr_mappings')
    section = models.PositiveSmallIntegerField()

    order = models.PositiveSmallIntegerField()
    raw_name = DomainNameField(max_length=2048, canonicalize=False, blank=True, null=True)
    rr = models.ForeignKey(ResourceRecord)
    ttl = UnsignedIntegerField()

    class Meta:
        unique_together = (('response', 'rr', 'section'),)

    def __unicode__(self):
        return unicode(self.rr)

    def __str__(self):
        return str(self.rr)

__doc__ = r'''
>>> import dns.exception, dns.message, dns.name, dns.rdata, dns.rdataclass, dns.rdatatype
>>> from dnsviz.models import *
>>> from dnsviz import util
>>> from django.db import transaction
>>> from django.utils.timezone import utc
>>> date1 = datetime.datetime(2012, 11, 5).replace(tzinfo=utc)
>>> date2 = datetime.datetime(2012, 11, 6).replace(tzinfo=utc)

Test unsigned ints and small ints
>>> f = UnsignedIntModel.objects.create(unsigned_small_int=0, unsigned_int=0)
>>> UnsignedIntModel.objects.get(pk=f.pk)
<UnsignedIntModel: 0 0>
>>> f.unsigned_small_int = 32768
>>> f.unsigned_int = 2147483648
>>> f.save()
>>> UnsignedIntModel.objects.get(pk=f.pk)
<UnsignedIntModel: 32768 2147483648>
>>> f.unsigned_small_int = 65535
>>> f.unsigned_int = 4294967295
>>> f.save()
>>> UnsignedIntModel.objects.get(pk=f.pk)
<UnsignedIntModel: 65535 4294967295>
>>> f.unsigned_small_int = 65536
>>> f.unsigned_int = 4294967296
>>> f.save()
Traceback (most recent call last):
...
DatabaseError: smallint out of range...
>>> transaction.rollback()
>>> f.unsigned_small_int = -1
>>> f.unsigned_int = -1
>>> f.save()
>>> UnsignedIntModel.objects.get(pk=f.pk)
<UnsignedIntModel: 32768 2147483648>

Test RRs
>>> def _get_rr_obj(qname, rdclass, rdtype, rdata_wire):
...   rdata = dns.rdata.from_wire(rdclass, rdtype, rdata_wire, 0, len(rdata_wire))
...   cls = ResourceRecord.objects.model_for_rdtype(rdtype)
...   rr_obj = cls(name=qname, rdclass=rdclass, rdtype=rdtype)
...   rr_obj.rdata = rdata
...   rr_obj.save()
...   rr_obj._rdata # force object to build _rdata from db
...   return rr_obj
... 
>>>

Check A record creation. rdata_address should be set correctly
>>> rr_obj = _get_rr_obj('www3.es.net.', dns.rdataclass.IN, dns.rdatatype.A, '\x907\x16\xc9')
>>> print '%s/%s/%s = %s' % (rr_obj.name.to_text(), dns.rdataclass.to_text(rr_obj.rdclass), dns.rdatatype.to_text(rr_obj.rdtype), repr(rr_obj.rdata_wire))
www3.es.net./IN/A = '\x907\x16\xc9'
>>> rr_obj.rdata
<DNS IN A rdata: 144.55.22.201>
>>> rr_obj.rdata_address
'144.55.22.201'

Check AAAA record creation. rdata_address should be set correctly.  Also make sure dns names can be accepted for creation
>>> rr_obj = _get_rr_obj(dns.name.from_text('www3.es.net'), dns.rdataclass.IN, dns.rdatatype.AAAA, ' \x01\x04\x00\x03\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10')
>>> rr_obj.rdata
<DNS IN AAAA rdata: 2001:400:310::10>
>>> rr_obj.rdata_address
'2001:400:310::10'

Check CNAME record creation. rdata_name should be set correctly.
>>> rr_obj = _get_rr_obj('www.es.net', dns.rdataclass.IN, dns.rdatatype.CNAME, '\x04www3\x02es\x03net\x00')
>>> rr_obj.rdata
<DNS IN CNAME rdata: www3.es.net.>
>>> rr_obj.rdata_name.to_text()
'www3.es.net.'

Check MX record creation. rdata_name should be set correctly.  Also, make sure both name fields are canonicalized, while case is preserved in rdata
>>> rr_obj = _get_rr_obj('eS.neT', dns.rdataclass.IN, dns.rdatatype.MX, '\x002\x04mAiL\x02eS\x03net\x00')
>>> rr_obj.rdata
<DNS IN MX rdata: 50 mAiL.eS.net.>
>>> rr_obj.name.to_text()
'es.net.'
>>> rr_obj.rdata_name.to_text()
'mail.es.net.'

Check SOA record creation
>>> rr_obj = _get_rr_obj('es.net', dns.rdataclass.IN, dns.rdatatype.SOA, '\x03ns1\x02es\x03net\x00\nhostmaster\x02es\x03net\x00w\xee?\xd3\x00\x00\x1c \x00\x00\x0e\x10\x00\x12u\x00\x00\x00\x02X')
>>> rr_obj.rdata
<DNS IN SOA rdata: ns1.es.net. hostmaster.es.net. 2012102611 7200 3600 1209600 600>
>>> rr_obj.rdata_name.to_text()
'ns1.es.net.'

Check DNSKEY record creation.  Make sure rdata fields are set correctly.
>>> rr_obj = _get_rr_obj('es.net', dns.rdataclass.IN, dns.rdatatype.DNSKEY, "\x01\x01\x03\x05\x03\x01\x00\x01\xbaf\xc61\xac>\xd9\x08\xd6{]\xa45[\xc1\x916x@V&\x9b\xfa\xbdv\xbc<\x88\xb9\x12\xfb\xa4\x15\xe4O\xb4\xec/!=\x10NJ\xd1^\xd7\x9e\x9a\xc4T\xee~\xff\xd2\x8f\xcf\xf5q\x05\xfe\xefu\xed\xaax\xd1\xbc0\xeb\\kV\xe9\xab^\xbcB\x9e\xd9\x05\xa2\x0f\x9c\xacVi\xa3\x96Y\x89\xa3\x19\xa8s\xff$\xa1'\x00\x1b\xde\xd2\x1a\x1f\x9b\xbeG\xf7S`#1Y\xf4\x04\xe6\xe0\x9c\xb8\x8b\x19\x95\xe1\x03$\xf7\xfcc\xa4\x8b\xad\xe0\xeb\x1a\x10\x8f\x8a\xe8?\x19\x1c\xdd]\x0cn2*\xff\xbf/\x1c\xec\x9e\xf5=$\x0b\n\xf8\xaa\xd2\x00\x8fL\xbc\x8f/'(\xabD\x03\xa0_\x06&y\xce\xc7r't-\x82\xc3g\xe1\xe3\x9a\xecZ\xbf/|nna\x98\xd3\x0f?F\xcf?\xda\x91~\x8e\xba\x8e\x9b\xdc\x8d%\xc96\x02\x01\xa6J\xc2+\x98\xfd\xc6\xd2y9\xacZ&`\xc5J\x1d`\x88D\x8bn\xa8\x99\xb45\xa7(2\xc7\x87\x8f\xbft\x1d\n\xde\x05")
>>> rr_obj.rdata
<DNS IN DNSKEY rdata: 257 3 5 AwEAAbpmx...

Check DS record creation.  Make sure rdata fields are set correctly.
>>> rr_obj = _get_rr_obj('es.net', dns.rdataclass.IN, dns.rdatatype.DS, "\x1a\xda\x05\x015\xa4\xacVG_\xa3\xd9\xae\x061\x18\xceA\xa1\x7f\x07\xfe'\xec")
>>> rr_obj.rdata
<DNS IN DS rdata: 6874 5 1 35a4ac56475fa3d9ae063118ce41a17f07fe27ec>

Check RRSIG record creation.  Make sure rdata fields are set correctly.
>>> rr_obj = _get_rr_obj('es.net', dns.rdataclass.IN, dns.rdatatype.RRSIG, "\x00\x06\x05\x02\x00\x01Q\x80P\x9d(\x14P\x8a\xa5\x04\x91\x17\x02es\x03net\x00*\xbb\xb0\xf3$\x99\r,\xf1\xb2\xa5\xc2\xc2u\xc7u6oU\xaf\xa3w\x13\x84\xa7\x9b\xdc\x1cf\xd1\x84\xb6T\xad\xb9i\x12\x0bd\xb0C\x84\x01\x83?\xae\x91\xe3d\xc0\xeb\x1b\x95\x99\x86^\xe1\xcc\x9b4\x8dT\xf5\xad\xcf\xd7\xfe\xc7\x85\xc4\x97R\xfa\xd8\x8bs\x1a%.&\x17\xda\xb7\xb3\xd2\xd9\xb2\xc6P\x1b\xce@\xb5\xd9\xa3h\x8d\n\x8d\xff\x7f\xc5.\xc0m\x9e\x08G\xb4|\xba\xfe\xc5\xc7\x07c\xcf07')Y%\xc5\xd4\x8e\x01\xa5")
>>> rr_obj.rdata
<DNS IN RRSIG(SOA) rdata: SOA 5 2 86400 20121109155812 20121026145812 37143 es.net. Kruw8ySZ...

Check TXT record creation.
>>> rr_obj = _get_rr_obj('example.com', dns.rdataclass.IN, dns.rdatatype.TXT, '\x0bv=spf1 -all')
>>> rr_obj.rdata
<DNS IN TXT rdata: "v=spf1 -all">

Make sure no duplicates can happen
>>> rr_obj = _get_rr_obj('www3.es.net.', dns.rdataclass.IN, dns.rdatatype.A, '\x907\x16\xc9')
Traceback (most recent call last):
...
IntegrityError: duplicate key ...
>>> transaction.rollback()

Check response creation 
>>> soa_msg_wire = '\x81}\x85\x00\x00\x01\x00\x02\x00\x04\x00\x07\x02es\x03net\x00\x00\x06\x00\x01\xc0\x0c\x00\x06\x00\x01\x00\x01Q\x80\x00\'\x03ns1\xc0\x0c\nhostmaster\xc0\x0cw\xee?\xd3\x00\x00\x1c \x00\x00\x0e\x10\x00\x12u\x00\x00\x00\x02X\xc0\x0c\x00.\x00\x01\x00\x01Q\x80\x00\x9a\x00\x06\x05\x02\x00\x01Q\x80P\x9d(\x14P\x8a\xa5\x04\x91\x17\x02es\x03net\x00*\xbb\xb0\xf3$\x99\r,\xf1\xb2\xa5\xc2\xc2u\xc7u6oU\xaf\xa3w\x13\x84\xa7\x9b\xdc\x1cf\xd1\x84\xb6T\xad\xb9i\x12\x0bd\xb0C\x84\x01\x83?\xae\x91\xe3d\xc0\xeb\x1b\x95\x99\x86^\xe1\xcc\x9b4\x8dT\xf5\xad\xcf\xd7\xfe\xc7\x85\xc4\x97R\xfa\xd8\x8bs\x1a%.&\x17\xda\xb7\xb3\xd2\xd9\xb2\xc6P\x1b\xce@\xb5\xd9\xa3h\x8d\n\x8d\xff\x7f\xc5.\xc0m\x9e\x08G\xb4|\xba\xfe\xc5\xc7\x07c\xcf07\')Y%\xc5\xd4\x8e\x01\xa5\xc0\x0c\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x02\xc0$\xc0\x0c\x00\x02\x00\x01\x00\x02\xa3\x00\x00\t\x06ns-lvk\xc0\x0c\xc0\x0c\x00\x02\x00\x01\x00\x02\xa3\x00\x00\t\x06ns-aoa\xc0\x0c\xc0\x0c\x00.\x00\x01\x00\x02\xa3\x00\x00\x9a\x00\x02\x05\x02\x00\x02\xa3\x00P\x9d(\x14P\x8a\xa5\x04\x91\x17\x02es\x03net\x00\x07y\xaa\x1a\x0bNhA\xd8\xac+\xb6\xf5\xf1\xd3\xcai\x88\xcb\xc4\x15j#x\x106\xd4\xe20\xea^\n\xa0)\x83K\xf009\x13K\xa7\x03\xbf\xaf\x9c\t6\x12?\x89Oa\xeePA\xbfI@\xae\x84\x19\xa8Y\xf3#6\x99Ei\xfe\x83\xa4\xa9\xfa+\xeb^\xb3l\xabM\x134k_\x95,\xac\x95\x8e$~\xc8\x15q\xbb\x80\xa4\xdd\x84\x1cy\xc9HP\xa4\xb5\x08\xe2\xcd.\xa5\x9b\x94\xe8\xaf\x19\xe30\xbf\'oD\xdf\x05\x0bJ\x00\x00)\x10\x00\x00\x00\x80\x00\x00\x00\xc0$\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc6\x80\x02\n\xc0$\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x04\x00\x00\x14\x00\x02\x00\x00\x00\x00\x00\x00\x00\x10\xc1 \x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc6|\xfc\x16\xc1 \x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x04\x00`\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\xc1\x0b\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc6\x81\xfc"\xc1\x0b\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x04\x00\t\x10\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02'
>>> soa_msg = dns.message.from_wire(soa_msg_wire)
>>> response_obj = DNSResponse.objects.create(qname='es.net', rdtype=dns.rdatatype.SOA, rdclass=dns.rdataclass.IN, server='127.0.0.1', client='127.0.1.1', time=date1)
>>> response_obj.response = soa_msg
>>> response_obj.save()
>>> response_obj._response = None # force response_obj to recreate _response from db
>>> print response_obj.response
id 33149
opcode QUERY
rcode NOERROR
flags QR AA RD
edns 0
eflags DO
payload 4096
;QUESTION
es.net. IN SOA
;ANSWER
es.net. 86400 IN SOA ns1.es.net. hostmaster.es.net. 2012102611 7200 3600 1209600 600
es.net. 86400 IN RRSIG SOA 5 2 86400 20121109155812 20121026145812 37143 es.net. Kruw8ySZ...
;AUTHORITY
es.net. 172800 IN NS ns1.es.net.
es.net. 172800 IN NS ns-lvk.es.net.
es.net. 172800 IN NS ns-aoa.es.net.
es.net. 172800 IN RRSIG NS 5 2 172800 20121109155812 20121026145812 37143 es.net. B3mqGgtO...
;ADDITIONAL
ns1.es.net. 172800 IN A 198.128.2.10
ns1.es.net. 172800 IN AAAA 2001:400:14:2::10
ns-aoa.es.net. 172800 IN A 198.124.252.22
ns-aoa.es.net. 172800 IN AAAA 2001:400:6000::22
ns-lvk.es.net. 172800 IN A 198.129.252.34
ns-lvk.es.net. 172800 IN AAAA 2001:400:910:1::2
>>> response_obj.msg_size
606

Check that a message with the same contents can be loaded, but RRs are reused.  Also check that queries with strings and names are case insensitive
>>> response_obj2 = DNSResponse.objects.create(qname='es.net', rdtype=dns.rdatatype.SOA, rdclass=dns.rdataclass.IN, server='127.0.0.1', client='127.0.1.1', time=date1)
>>> response_obj2.response = soa_msg
>>> response_obj2.save()
>>> response_obj == response_obj2
False
>>> ResourceRecordMapper.objects.filter(rr__name='es.net.', rr__rdtype=dns.rdatatype.SOA, rr__rdclass=dns.rdataclass.IN).count()
2
>>> ResourceRecordMapper.objects.filter(rr__name='es.NeT', rr__rdtype=dns.rdatatype.SOA, rr__rdclass=dns.rdataclass.IN).count()
2
>>> ResourceRecord.objects.filter(name='es.net.', rdtype=dns.rdatatype.SOA, rdclass=dns.rdataclass.IN).count()
1
>>> ResourceRecord.objects.filter(name=dns.name.from_text('eS.neT.'), rdtype=dns.rdatatype.SOA, rdclass=dns.rdataclass.IN).count()
1

Delete the object, and make sure the mapper is also deleted, but the RR persists
>>> response_obj2.delete()
>>> ResourceRecordMapper.objects.filter(rr__name='es.net.', rr__rdtype=dns.rdatatype.SOA, rr__rdclass=dns.rdataclass.IN).count()
1
>>> ResourceRecord.objects.filter(name='es.net.', rdtype=dns.rdatatype.SOA, rdclass=dns.rdataclass.IN).count()
1

Delete the object, and make sure the mapper is also deleted, but the RR persists with no mapprs
>>> response_obj.delete()
>>> ResourceRecordMapper.objects.filter(rr__name='es.net.', rr__rdtype=dns.rdatatype.SOA, rr__rdclass=dns.rdataclass.IN).count()
0
>>> ResourceRecord.objects.filter(name='es.net.', rdtype=dns.rdatatype.SOA, rdclass=dns.rdataclass.IN).count()
1

Create a name
>>> name_obj = DomainName.objects.create(name='net.')
>>> analysis = DomainNameAnalysis.objects.create(name_obj=name_obj, analysis_start=date1, analysis_end=date1, has_ns=True)
>>> analysis.add_ns_mappings(('a.gtld-servers.net.', '192.5.6.30'))
>>> analysis._server_analysis_cache[util.format.ip_to_wire('192.5.6.30')].authoritative = True
>>> analysis._server_analysis_cache[util.format.ip_to_wire('192.5.6.30')].save()
>>> analysis.is_zone()
True

Create and populate an analysis
>>> name_obj = DomainName.objects.create(name='es.net.')
>>> analysis = DomainNameAnalysis.objects.create(name_obj=name_obj, analysis_start=date1)
>>> analysis.get_name('net.')
<DomainNameAnalysis: net>
>>> analysis.parent
<DomainNameAnalysis: net>
>>> analysis.add_ns_mappings(('ns1.es.net.', '198.128.2.10'), ('ns1.es.net', '2001:400:14:2::10'), ('ns-aoa.es.net', '198.124.252.22'), ('ns-aoa.es.net', '2001:400:6000::22'), ('ns-lvk.es.net', '198.129.252.34'), ('ns-lvk.es.net', '2001:400:910:1::2'))

>>> referral_msg_wire = '\x19\x83\x81\x00\x00\x01\x00\x00\x00\x06\x00\x04\x02es\x03net\x00\x00\x02\x00\x01\xc0\x0c\x00\x02\x00\x01\x00\x02\xa3\x00\x00\t\x06ns-aoa\xc0\x0c\xc0\x0c\x00\x02\x00\x01\x00\x02\xa3\x00\x00\t\x06ns-lvk\xc0\x0c\xc0\x0c\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x06\x03ns1\xc0\x0c\xc0\x0c\x00+\x00\x01\x00\x01Q\x80\x00\x18\x1a\xda\x05\x015\xa4\xacVG_\xa3\xd9\xae\x061\x18\xceA\xa1\x7f\x07\xfe\'\xec\xc0\x0c\x00+\x00\x01\x00\x01Q\x80\x00$\x1a\xda\x05\x02_5G\x15\x9a\x8d!\xaev\x9a\x03\xbam\x8fG\xf6s.)\xee3\x84\x99\x80\xf7\x1f\xcfc;Q\xad\x9c\xc0\x0c\x00.\x00\x01\x00\x01Q\x80\x00\x97\x00+\x08\x02\x00\x01Q\x80P\xa4ztP\x9b/\x8c"\x19\x03net\x00\xd9\xb1\xed\x8e\x8d\xaa\xf0\x8b2\xdaK}\xd8\xe2\xbd\x11\xb3\x8bH\xa8\xa2\xf1\xea\x05L\xdb\xde\xd1GyQ\xc0\x89\xaa\xf6 \xee\xba\x1c\xa2\xbeM]3\xb7\xcf\xd5\x07\x91\xd9\xcb\x05,\xb6\x8en_\x9e\x9bM\x89\x93*\x03\xf1#\xfc`\x92\xe57\xd2\x08S~\xc4\xfd\xeb\n\xeaee\x8a\xc6uN\xd4\x8b^$\xbf\xdb\xe7\x80\xd7\x086q$Y@\xac\x9f\n\x1eY\xac^=5\xf7\x05K\xe5\xf2#;o\x9c\xbe\x7f\xaf\xa7\xe5\xac\xf9\x05\xd9\x00\x00)\x10\x00\x00\x00\x80\x00\x00\x00\xc0N\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc6\x80\x02\n\xc0$\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc6|\xfc\x16\xc09\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc6\x81\xfc"'
>>> referral_msg = dns.message.from_wire(referral_msg_wire)
>>> analysis.add_response('127.0.0.1', '192.5.6.30', 'es.net', dns.rdatatype.NS, dns.rdataclass.IN, False, True, True, False, referral_msg, date1)
<DNSResponse: query: es.net. IN NS server: 192.5.6.30 id: 6531>
>>> analysis.referral_rdtype = dns.rdatatype.NS

>>> ns_msg_wire = '\xe4w\x85\x00\x00\x01\x00\x04\x00\x00\x00\r\x02es\x03net\x00\x00\x02\x00\x01\xc0\x0c\x00\x02\x00\x01\x00\x02\xa3\x00\x00\t\x06ns-lvk\xc0\x0c\xc0\x0c\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x06\x03ns1\xc0\x0c\xc0\x0c\x00\x02\x00\x01\x00\x02\xa3\x00\x00\t\x06ns-aoa\xc0\x0c\xc0\x0c\x00.\x00\x01\x00\x02\xa3\x00\x00\x9a\x00\x02\x05\x02\x00\x02\xa3\x00P\xae\x05\xc3P\x9b\x82\xb3IS\x02es\x03net\x00uf\xe2\xb4\xa1\xcb\x85F\xb8\xfd\xe3 a\x11\xd9\x86\\\x11\xb7\xce\x9c\x80\xa9\'\xdd\xb0\xe5\xb6q\x9a\x89\x12\x11l\xab\x80c\x0f\x81x\n\x04\x1d!a\x0czn\xd1\xbd\xc9\xe86zend\x91\x12e\xeb\xedNN\xef~\xf2\x14\xa2\xf7\xf3\xe2Y#&\xc7\x1a\xdc\xb6\xf4)\x94\xa4duz$^\xe5\r\xb6\r\xe0\x84v\x14\x93<\xe5\x8f\xcf\x0f\x14\xfff\x9duXc1\x9a\x08\xb1\xa3L8\xed\xa8i\xdd@\xd4\x15lfG`\'\x00\x00)\x10\x00\x00\x00\x80\x00\x00\x00\xc09\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc6\x80\x02\n\xc09\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x04\x00\x00\x14\x00\x02\x00\x00\x00\x00\x00\x00\x00\x10\xc0K\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc6|\xfc\x16\xc0K\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x04\x00`\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\xc0$\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc6\x81\xfc"\xc0$\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x04\x00\t\x10\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\xc09\x00.\x00\x01\x00\x02\xa3\x00\x00\x9a\x00\x01\x05\x03\x00\x02\xa3\x00P\xae\x05\xc3P\x9b\x82\xb3IS\x02es\x03net\x00y\x87\xe14\xa9LAY\xc9\x19\xfa\x95\x9d\xd5\x83\x15m\x82_\xa6E\xc6\xf1\xe1~\xa9\t\xd4\x15e\xa0\r\x8e\x07\xfe;:\xc6\xa2|rH\xcd\xfbE8cv\xfd\x0f8\x04\xd84\xee\xe3\xf1`\xf2\xfd8J\xe1\xe4,\xe2\xf90$\xc7`fV\x8f:*?61\xa7\xe3\xb052Q\x92\xcc_\x9c?=O\xf7\x8eh;d\xa9Wn#\x9a\xc4\x0fa\rZ\x9c\xc4qgjm;v\xbf\xf15\xae\xc3/\xd1I\xb3\xbf\x03\xecd\xc09\x00.\x00\x01\x00\x02\xa3\x00\x00\x9a\x00\x1c\x05\x03\x00\x02\xa3\x00P\xae\x05\xc3P\x9b\x82\xb3IS\x02es\x03net\x00KG\x8c\xae\x82\x8a\xc0\x06\xad\xb9\xbd\x00\xeaa?P\x0e\xc0\x80\xb4<\xbe\x82\xe5\x9f&<T\xa6\x1dci\x95\x1d\x15n\x85\xfbk\x97\xd6G\x1c\xb9PX\xfc\x9e\x1a9\xca\xc6\x00qo\xe7\xd4\x90X\xa9\xd9\x979\x9bn\xe9-\xe1\x82\xa3\xddA\x1e\x9f\xa1E\xa03_\xf6\xee\xe3\x8a\xf5\x82l\xe8\xd0\xa2}m\xf5\x18je\xdc\xa1@\x1b\xcd2s\xd3P\xce]\xa0\xa2\xc4(\x8d\x817 \x9f\xbd \xe1\xede3\xe1\x88\xce>\xa4\x00\x92\xc0K\x00.\x00\x01\x00\x02\xa3\x00\x00\x9a\x00\x01\x05\x03\x00\x02\xa3\x00P\xae\x05\xc3P\x9b\x82\xb3IS\x02es\x03net\x00Gm9(\xcc\xc3_X\xbf.\xfe\xd3\xa3=-f\x86$4[=\x12;\xf1U\xcf\xabJ\x824\xa3!\xeb\xc8\xb3\xa2\x1aDV[t]\x9aB(\x9e\x08\x0b@\xe7\xa6\xae\xedb\x15\xe1\x19\x98\xb7\x01R\xab\xb9\x90\xee\xed\x06H\xe3\xc5+\x8b8v\xb4\xde\xe9;\x0f\xddT,\x13\xc0ZQ\xf6\x00F\xd4\x0f\x90\xdf\x9e\xce\xe0\xfe\x86\x14\x8ah\x8bB\xacin\x10l\x17\x02\rgt\x90_\x9be\x87\xed\xb5k\xf11\x8d_\xb3\x14\xca\xc0K\x00.\x00\x01\x00\x02\xa3\x00\x00\x9a\x00\x1c\x05\x03\x00\x02\xa3\x00P\xae\x05\xc3P\x9b\x82\xb3IS\x02es\x03net\x00]G*gj=e|\xaa>$\x8c\xc5J\xf1O\xd5\x93\x8d\x073\xa82\xd5\xd8\xc3\x13\xb7\xa1\xbb\xe3k\x1es\xd0\xaep\x85<w\x13\x1e\xd3\xf2\xdaU\xd4\x19\xd6\xbbxf\x05\xd3U\x93\x87\xf6\xaa\x91`:\xf7.H\x7fo\xaa\x08\xd1\x9a.)\x868\x13\xa5\xab\x8b\x99\x87IB\x06\xe6\x97\xbb40\xa2\x87\xf9(a\xfa\xd7\x05\xfe\xc6t^\x0bY\x8a\xfe\x01\xf6\x14\x1bi)|\xb0\xa2\xf0\xbc\xac:\xd0EU\xe8\xb1\x96\xb1\x87\xc7X\xc0$\x00.\x00\x01\x00\x02\xa3\x00\x00\x9a\x00\x01\x05\x03\x00\x02\xa3\x00P\xae\x05\xc3P\x9b\x82\xb3IS\x02es\x03net\x001~\xa4\x1a!\xdc[\x12AMrK\xf7M\xfa{\xf6\x88\x02\x83\xfe\xd2\x88\xa5\x15\x17\xda\xbc\x1f~\x98\xd7A\xd9\xd8c\xdb\x83I\xf1\xe5~*A\x1a;\xba8e\x07@1\x9f\x8fY\xa2\\\x1eP\x172\xa5>S12ms{Q\xe8n\xfb\xbe\xdbY\xdb\x8c\xb5\x16\xb5\xd3\xc2\xae\xe2W\x10\x8a{\xab\xb4\x96\x9b?\x8b1\x1f\x92{\x7f\xfc\xccmFe\xab\xd0\x01?%BE\xa4n\x16\x90\xe16R\xeb\xc4\x9a\xc9\x1cC8\xfe\x92\xc0$\x00.\x00\x01\x00\x02\xa3\x00\x00\x9a\x00\x1c\x05\x03\x00\x02\xa3\x00P\xae\x05\xc3P\x9b\x82\xb3IS\x02es\x03net\x00\n\xc6\x8e9\xf2\xe3\xa3\x7fx\x17\xd78\xcfKU\t\xf1\xcc\xbb\x92\xad\x84\xa5\xe3\x06@\x80\x85\x9d\x0e\x1a\x01\x8c\x9f,\x8c\x19\x9c\xde\x96j\xd5vS\xfc\xe74D\x83o\x93M]}n\xf1\xa7\x01\x90d\xc7\xc0`\xae]\xcc,\x10\xd7\x9b\x10\x03\xa6\xdd\x00\x01\x8c5g\x89\xa8%PJ\x86\xbf2\x1f\x95\xd3\xeb\xb2c|\xe8jC\x9dE\xd3\xa7L\xdd\xc2.K\x1cFz%\xa2\xa3OO\x8d\x05\xb5\x10\xaeZ\xd7\xa7d{!<u\xbe'
>>> ns_msg = dns.message.from_wire(ns_msg_wire)
>>> analysis.add_response('127.0.0.1', '198.128.2.10', 'es.net', dns.rdatatype.NS, dns.rdataclass.IN, False, True, True, False, ns_msg, date1)
<DNSResponse: query: es.net. IN NS server: 198.128.2.10 id: 58487>

>>> analysis.get_referral_responses()
{'192.5.6.30': {'127.0.0.1': <DNSResponse: query: es.net. IN NS server: 192.5.6.30 id: 6531>}}
>>> analysis.no_non_auth_parent()
False
>>> analysis.ds_nxdomain()
False
>>> analysis.get_glue_ip_mapping()
{<DNS name ns1.es.net.>: set(['198.128.2.10']), <DNS name ns-lvk.es.net.>: set(['198.129.252.34']), <DNS name ns-aoa.es.net.>: set(['198.124.252.22'])}
>>> analysis.get_auth_ip_mapping()
{<DNS name ns1.es.net.>: set(['198.128.2.10', '2001:400:14:2::10']), <DNS name ns-lvk.es.net.>: set(['198.129.252.34', '2001:400:910:1::2']), <DNS name ns-aoa.es.net.>: set(['198.124.252.22', '2001:400:6000::22'])}
>>> analysis.get_ns_names_in_parent()
set([<DNS name ns1.es.net.>, <DNS name ns-lvk.es.net.>, <DNS name ns-aoa.es.net.>])
>>> analysis.get_ns_names_in_child()
set([<DNS name ns1.es.net.>, <DNS name ns-lvk.es.net.>, <DNS name ns-aoa.es.net.>])
>>> analysis.get_ns_names()
set([<DNS name ns-aoa.es.net.>, <DNS name ns1.es.net.>, <DNS name ns-lvk.es.net.>])
>>> analysis.get_servers_in_parent()
set(['198.128.2.10', '198.124.252.22', '198.129.252.34'])
>>> analysis.get_servers_in_child()
set(['198.124.252.22', '198.129.252.34', '198.128.2.10', '2001:400:14:2::10', '2001:400:910:1::2', '2001:400:6000::22'])

>>> soa_response = analysis.add_response('127.0.0.1', '198.128.2.10', 'es.net', dns.rdatatype.SOA, dns.rdataclass.IN, False, True, True, False, soa_msg, date1)
>>> analysis.add_response('127.0.0.1', '2001:400:14:2::10', 'es.net', dns.rdatatype.SOA, dns.rdataclass.IN, False, True, True, False, soa_msg, date1)
<DNSResponse: query: es.net. IN SOA server: 2001:400:14:2::10 id: 33149>
>>> analysis.add_response('127.0.0.1', '198.124.252.22', 'es.net', dns.rdatatype.SOA, dns.rdataclass.IN, False, True, True, False, dns.exception.FormError, date1)
<DNSResponse: query: es.net. IN SOA server: 198.124.252.22 id: 0>
>>> analysis.add_response('127.0.0.1', '2001:400:6000::22', 'es.net', dns.rdatatype.SOA, dns.rdataclass.IN, False, True, True, False, dns.exception.Timeout, date1)
<DNSResponse: query: es.net. IN SOA server: 2001:400:6000::22 id: 0>

>>> analysis.serial
2012102611
>>> analysis.rname
<DNS name hostmaster.es.net.>
>>> analysis.mname
<DNS name ns1.es.net.>


>>> ds_msg_wire = '\xa9[\x85\x00\x00\x01\x00\x03\x00\x0e\x00\x10\x02es\x03net\x00\x00+\x00\x01\xc0\x0c\x00+\x00\x01\x00\x01Q\x80\x00\x18\x1a\xda\x05\x015\xa4\xacVG_\xa3\xd9\xae\x061\x18\xceA\xa1\x7f\x07\xfe\'\xec\xc0\x0c\x00+\x00\x01\x00\x01Q\x80\x00$\x1a\xda\x05\x02_5G\x15\x9a\x8d!\xaev\x9a\x03\xbam\x8fG\xf6s.)\xee3\x84\x99\x80\xf7\x1f\xcfc;Q\xad\x9c\xc0\x0c\x00.\x00\x01\x00\x01Q\x80\x00\x97\x00+\x08\x02\x00\x01Q\x80P\xa9\xc0uP\xa0u\x8d"\x19\x03net\x00\x0b/\x828\xfe\xc7\xd1BX\x16\x03\x05\xcb\xed]*6\x01\x7f\\\t\x82CVk^\x82p\x84ZO\xfb\n\x9a\x1f\xccly\x91\xbb\xe6\xf8\xc8\x11\xa4.\xbc\x88\xca\'Fy\xc5\xd1\xdd\xac\x93`\x9f\x01z\xe1S\xe7\xfa\x1e\x89\xe5\xa1C-\xe8Y_-L\x04\xd8\xea<\xa1l\xa3d\xed<\xe8.\xee\xb2.\xfb\x0f\xdd\\\xd8q\x1e~,\x0e\x9e\xf2K\xcbB\xeb\xc8\xfc\xba6\x1d\xd0\x7f\xc4\x9b\xb3\xcd\xb6\xcd\xe5\x89\x0e\xe3\xac\xfb\xd3\x87\xc0\x0f\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x11\x01b\x0cgtld-servers\xc0\x0f\xc0\x0f\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01a\xc1\x1d\xc0\x0f\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01l\xc1\x1d\xc0\x0f\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01g\xc1\x1d\xc0\x0f\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01e\xc1\x1d\xc0\x0f\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01f\xc1\x1d\xc0\x0f\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01m\xc1\x1d\xc0\x0f\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01c\xc1\x1d\xc0\x0f\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01h\xc1\x1d\xc0\x0f\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01k\xc1\x1d\xc0\x0f\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01d\xc1\x1d\xc0\x0f\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01i\xc1\x1d\xc0\x0f\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01j\xc1\x1d\xc0\x0f\x00.\x00\x01\x00\x02\xa3\x00\x00\x97\x00\x02\x08\x01\x00\x02\xa3\x00P\xaccpP\xa3\x18\x88"\x19\x03net\x009\x05\x94x\x0b\x10\xe7*G\x1b\x9a\xb3\xd9x\x03\x9d\x918\xd8\x16;\xc3\x1f\x99\x15"\xcbH\x8fG\x89\x17\x9d\x19\xcb\x84\xc1\x82\xf5\xe0\x19\xaf^\xa0\x1dT%\x84\xce\x9c\xc0\x96Z\xb9\xe50\xc4\x1eT\xf7;\t\xf6\x95\xec4\x8f\x7fBz\xb4\x15\x99\xf8\xb5\x1d\x04Y\xc6z\x1f\x92\xf5\xf4!\xe5\xfdjB7\x88\xf8K\xb2FtK\xb9h\x1f\xde\xbc\xad\xb2hv\xc8\xc1R\x05\x92#\xb3(\xb0E\xc5r\x94 a\xf6\xd5\x95\x11L\x99@\x00\x00)\x10\x00\x00\x00\x80\x00\x00\x00\xc1h\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0\x0c^\x1e\xc1\xd8\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0+\xac\x1e\xc1\xc8\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0\x1fP\x1e\xc1x\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0#3\x1e\xc1X\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0*]\x1e\xc1\x1b\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0!\x0e\x1e\xc1\x1b\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x05\x03#\x1d\x00\x00\x00\x00\x00\x00\x00\x02\x000\xc1\xb8\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc04\xb2\x1e\xc1\x98\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0\x1a\\\x1e\xc1H\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0)\xa2\x1e\xc1\xe8\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc00O\x1e\xc18\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0\x05\x06\x1e\xc18\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x05\x03\xa8>\x00\x00\x00\x00\x00\x00\x00\x02\x000\xc1\xa8\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc06p\x1e\xc1\x88\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc07S\x1e'
>>> ds_msg = dns.message.from_wire(ds_msg_wire)
>>> analysis.add_response('127.0.0.1', '192.5.6.30', 'es.net', dns.rdatatype.DS, dns.rdataclass.IN, False, True, True, False, ds_msg, date1)
<DNSResponse: query: es.net. IN DS server: 192.5.6.30 id: 43355>
>>> analysis.get_responses('es.net', dns.rdatatype.SOA, False, True, True, False)['2001:400:6000::22']['127.0.0.1']
<DNSResponse: query: es.net. IN SOA server: 2001:400:6000::22 id: 0>
>>> analysis.get_responses('es.net', dns.rdatatype.DS, False, True, True, False)['192.5.6.30']['127.0.0.1']
<DNSResponse: query: es.net. IN DS server: 192.5.6.30 id: 43355>
>>> analysis.get_responses('es.net', dns.rdatatype.DNSKEY, False, True, True, False)['2001:400:6000::22']['127.0.0.1']
Traceback (most recent call last):
...
KeyError: '2001:400:6000::22'

>>> dnskey_msg_wire = '\x1a\x07\x85\x00\x00\x01\x00\x06\x00\x00\x00\x01\x02es\x03net\x00\x000\x00\x01\xc0\x0c\x000\x00\x01\x00\x01Q\x80\x00\x88\x01\x00\x03\x05\x03\x01\x00\x01y\xe2\x7f\xe0\xc3\xa0\xcd\xcfi\xd6\x9bpI\xc8]s\xe0Z\x11\xd3,\xd1\xa7\x92\x1e\x1e\x07\r\xe9]\'\xd6\xf8Il7;\xc0\xf7i_\xd1\xfc\x93\xc3D\xde\xae\xf5\x88K\x02\x11\xf4\xd6B\xd2\x04\xc9\xdb\xb2\xe3q(\xf2\xca\xe8\xc6P\xfc\x06t\x12X\x1c\x9b`n\xfb\x16\xa0\xaa7\xfa`\x996\xe5\xbd\xb5\x01\xa2\x89\x8a,\xc7\x80\xc2\x9d\xe7\xb4\xf579S\xce\xbf\x05\xb8h\x1e\xac\xa1L\xb6\xabR8\xb7\xb1\xb8\xd2\x89\xea\xfaZW\xed\xc0\x0c\x000\x00\x01\x00\x01Q\x80\x01\x08\x01\x01\x03\x05\x03\x01\x00\x01}\xa2\xfa\x05\x89@\x10\x92\x05\xaa63\x8e\xb8\xaa\x8b[\r\x97\x88\xc4"\x93h\xd3q\xdb\xdeK\xd2O\x08\x05\xc6\x0e\xdd\x8d\xf2#\xd2P\xf2=\x18\x9c\xdcCO8\x8a\x91\xd6\xce\xc1\xa9\xd6\xf3\x05\x81t\t\xac\xa7\x84\xf3\x81\xdf\xfd~\xc3\xech\x8f\xfe\x16\xd2\xacW\xbd\x7f\x0bb^\xfc0\x99\xb3\xa9\xa5\xed\xa1t$`"\x96i\xddg\xd8\x1f\x12\x06\x98w\xf6\xaf\xa4\x97\xf8\x1e\xb1-\x17\x9b\x18?\\\x81\x85\xb2xky\x0b\xea\xfbm\x02\xe0\xf9Lx\x00eQ\x1c\xf4j\xf8\r@\x05P"\x86}\xf7\x12\x86\x9c\xc2b\xc0\xd3\x15\xb9-\xfa\x96\xd5\x8b\xc23m\xab]\x12X\xdd`@i\x13\xd1\x16\xdc.\xc1\x13]\x89\xc6\xd2\t,5\xa1\x9cg\x95\x97C\xb4\x07\xa3\xc3\x0f<k\x8b\xc4v5\x04\xfe\x12T\x1e\xdd\x94z_\xbe\x8e@-1\x81m\x18$\x86~,\xd8\x9a\xee_\xf6\xedz-h;\x8c^k{Yr\xbd\xff5[\xfd\x91(\xf0\xd0\xed\xb5\x9a`\xf3!\xc0\x0c\x000\x00\x01\x00\x01Q\x80\x00\x88\x01\x00\x03\x05\x03\x01\x00\x01\xa6UHd\x1b^>\x13\\\x9c\x85\x1c\x1f\xf1;\xc5\xf4~\x9aSo?G\xb6\xbd\x04\xda\xe3+1_\x06\xc6|"\x134\x87\xa3\xc7\xc5\x1b{#_\xbbo~\xd6#!\xc9a\xee\n\xa4\x80!\x8b\xeb\xd2k"\xb3op\xa0>\x82\x95\xba\xc5Y\x7f&fo\xfe\xf9\x0e\x85\xf9OR\xf49K|\xec,\xfeYBF\xfa\xb0\xef\x8a @\x85\x93i\xe0x"}\xeeD\xb1U\x91\xca\x07\xab\xe1\t\xed\xdeqs\xa3\xea>\x07\n\xa1E\xc0\x0c\x000\x00\x01\x00\x01Q\x80\x01\x08\x01\x01\x03\x05\x03\x01\x00\x01\xbaf\xc61\xac>\xd9\x08\xd6{]\xa45[\xc1\x916x@V&\x9b\xfa\xbdv\xbc<\x88\xb9\x12\xfb\xa4\x15\xe4O\xb4\xec/!=\x10NJ\xd1^\xd7\x9e\x9a\xc4T\xee~\xff\xd2\x8f\xcf\xf5q\x05\xfe\xefu\xed\xaax\xd1\xbc0\xeb\\kV\xe9\xab^\xbcB\x9e\xd9\x05\xa2\x0f\x9c\xacVi\xa3\x96Y\x89\xa3\x19\xa8s\xff$\xa1\'\x00\x1b\xde\xd2\x1a\x1f\x9b\xbeG\xf7S`#1Y\xf4\x04\xe6\xe0\x9c\xb8\x8b\x19\x95\xe1\x03$\xf7\xfcc\xa4\x8b\xad\xe0\xeb\x1a\x10\x8f\x8a\xe8?\x19\x1c\xdd]\x0cn2*\xff\xbf/\x1c\xec\x9e\xf5=$\x0b\n\xf8\xaa\xd2\x00\x8fL\xbc\x8f/\'(\xabD\x03\xa0_\x06&y\xce\xc7r\'t-\x82\xc3g\xe1\xe3\x9a\xecZ\xbf/|nna\x98\xd3\x0f?F\xcf?\xda\x91~\x8e\xba\x8e\x9b\xdc\x8d%\xc96\x02\x01\xa6J\xc2+\x98\xfd\xc6\xd2y9\xacZ&`\xc5J\x1d`\x88D\x8bn\xa8\x99\xb45\xa7(2\xc7\x87\x8f\xbft\x1d\n\xde\x05\xc0\x0c\x00.\x00\x01\x00\x01Q\x80\x01\x1a\x000\x05\x02\x00\x01Q\x80P\x9d(\x14P\x8a\xa5\x04\x1a\xda\x02es\x03net\x00*P\x19\xd6\r`\x94\xf7\xa6\xda\xf4\xa2D\x86\xf7\x8fc\xf7\x7f"\xd2m\x96*\xb4\xed\x88\x87\x0c\xac\xbbe\x8f\x07y\xaa:\xa3k\xf8\x9cA\xec\xfe\xc6\x89\x8c\x0c\xd1,\x00\xb5\x9db\xb9\xce\xde\x80\xc5r\x02\xcd\xf2\xa4\xc7\xa9w\x19\xe2p\xee\xdb\x9bT\x8b\xd7H\xdelQ\xa0\xcd\xa6;0c\xb7[\xbb\xad\xd8\x80\xee\xd8\x87\xca\xad\xf0u\x9b\x9d[W\xa2O\xbf{\xd1\xd0y6\xbd\xc0TF\xfc\xbb\x9c\xf9m\xb6\x8cc(\x86W\xb2\x02\x1f\x87\x02\r\x03\xfcK\x1b\x03\xee\x0b#\x1b\x99{x\x12%\xbdT\xbf[\x17\xf5\xf9k<\xb0\xe3\xa9\xa4\xd7u\xaf\xde\xd8P3d!\xcaG<\xd3\xc1\x1b\x88\x02\xb2&A\xdb\x9c,@\xa9\xa5mZQ\x1e[g!p\xb1\x8e\xfa\xa0t\xea.Dx>\xacf\xb9\xa9\xadC[b\x85\xfd/\xd795\x8ey\xb0N\xd2.\x9d+Nb\xb6\xcc\x99\xc4*d\xee\x9d\xe9\xa5\xb8\xda\xc3\x8f\xb4\xd3\xb1\xc5\xb99\x97p\xa9\x9a:\xd3g\xc7\xe4\xc0\x0c\x00.\x00\x01\x00\x01Q\x80\x00\x9a\x000\x05\x02\x00\x01Q\x80P\x9d(\x14P\x8a\xa5\x04\x91\x17\x02es\x03net\x00/\xcf\xd3hs\xb3\xe1\xd7\x8eut\xf4\xcf\xc0\x14\x98\x8e\x07Y\xf8\x90;\x08\x1a\t#W\xd6\x1a\xda\xde\xce\x03c\x95I\xd5\r\xf9%\xf9\x14\xe2\x07\xde\xf2\xd0\xee\x97I\x1f\x95\x00\xb9F?\x86ZsF\xc4\xf54)\xe5Hig\xb3\x0eQ\xa6`\x0b\xf0\xc4\xaa\xec\xd0U\xe5\x97]\xb2\xff\x1f\xfao\xe7\xd0M\x1f\xc6C\x86\xd3V\n:\x07\x9e\xb5\xd9\xe1\x9e\x1d\xa2\x08\xd9\x8f\x833h\xb5O \xd2G\x02\x03\xce\xd6\x9f\xce\x95q\xfb\xdd\x00\x00)\x10\x00\x00\x00\x80\x00\x00\x00'
>>> dnskey_msg = dns.message.from_wire(dnskey_msg_wire)

>>> analysis.add_response('127.0.0.1', '198.128.2.10', 'es.net', dns.rdatatype.DNSKEY, dns.rdataclass.IN, False, True, True, False, dnskey_msg, date1)
<DNSResponse: query: es.net. IN DNSKEY server: 198.128.2.10 id: 6663>
>>> analysis.add_response('127.0.0.1', '2001:400:14:2::10', 'es.net', dns.rdatatype.DNSKEY, dns.rdataclass.IN, False, True, True, False, dnskey_msg, date1)
<DNSResponse: query: es.net. IN DNSKEY server: 2001:400:14:2::10 id: 6663>

>>> nxdomain_msg_wire = '^^\x84\x13\x00\x01\x00\x00\x00\x06\x00\x01\tfoobar123\x02es\x03net\x00\x00\x01\x00\x01\xc0\x16\x00\x06\x00\x01\x00\x00\x02X\x00\'\x03ns1\xc0\x16\nhostmaster\xc0\x16w\xee`?\x00\x00\x1c \x00\x00\x0e\x10\x00\x12u\x00\x00\x00\x02X\xc0\x16\x00.\x00\x01\x00\x00\x02X\x00\x9a\x00\x06\x05\x02\x00\x01Q\x80P\xaf\xd3\x06P\x9dO\xf6IS\x02es\x03net\x00)\xe3\x06\x11\xe4+\xd5\xb9u\x87\xcatj\xe8\xa3\xf1\xd4\x89\xf9\xefu\x9a\x1e\x8f\x047Y\xcf\x9bm\xea\x1f\xf8\x906\xa5\xaa\xe90\xa5\xbcz\xbab\x0b\xf58\x00~#\xb3%\xe385\xb3\xdb\x02*\xef;\x8dd\\\x1c\xa8V\x8au\xc9?\xee\xb3\x1d\xdc},`-\x03\xea\x7f\xf6\x07\xaeY\xde*\x8c\xf3l\x8e\xd8\xa7\xd2\x98\x8c\x82I\xf8\x958\xab{\xda\x84\xd6A7n\xcaCg\xc9\xd4\x000V\x9b\xe9T\xdc\xeb\x07(`j\xc6\xc0\x16\x00/\x00\x01\x00\x00\x02X\x00"\x0breserve-128\x0214\x011\x02es\x03net\x00\x00\x07b\x01\x00\x08\x00\x03\x80\xc0\x16\x00.\x00\x01\x00\x00\x02X\x00\x9a\x00/\x05\x02\x00\x00\x02XP\xaf\xd3\x06P\x9dO\xf6IS\x02es\x03net\x00g\xf5C\xd0\xd2\xc3BS5S\xe9\xbc=\x07\x00\x99\x033J\x0f\xd0x$D!5P\x8e\xf5(\x8d;\xc1\x85\xdf\xfd\xd8\xc3\xd8,P\x98\xb3\xf8T\x83Q\xefM5%\xcd\xb2^\xdb\x90R\xcb\x06&\xbe\xea\xb6\xc8\xdfJ\r\xe9\xd2\xcb99\xb9\xd4\xab\xb1\xc7\x14U\xb4\xeaF\xe0Z^\x86\x88W\x9cK\xc9+\xe0\x82\xac1\x0f\x8cW\x92\x96V\xcf\xdfb\x19\xec\xc5\x8c:?\xab\xf7N\x8f\x16\xe7\x92,b\xdd#\r\xca5\x97\x18\xca\x04test\x03foo\xc0\x16\x00/\x00\x01\x00\x00\x02X\x00\x1a\tforr-opt1\x02es\x03net\x00\x00\x06@\x00\x00\x00\x00\x03\xc1\xcf\x00.\x00\x01\x00\x00\x02X\x00\x9a\x00/\x05\x04\x00\x00\x02XP\xaf\xd3\x06P\x9dO\xf6IS\x02es\x03net\x00m#$\xdc\xae\xdfy\xa0\xcbhZX\xfd\xceV\xb1\x0e\xd7\xa0\xc8\xc92\xc9\x10x\x0b\xf4\xb0\x8c.\x8b\xfch\x14\x9a!\xden\xd0\xcd\xf7\xdb\xab\xf4\xb2\x0eO\xb01or\x03\x04&\xdbJ\x8a\xad\xe0*K\xfc\x1d\x0f\xe3x\xf7\x91.\xc7,/:g\xa9q654\x9eU\x1cgJ\xee\xa2\rA>H\xbbH\x06\xaf\xfa-\xb9\xba\xf6\xce\x9b5W\xe1f\xd1s\x07\xd87\xce\xcfz\x1ad\xa2t\xa5\x9c[\x84Ca\xf1j\x8c\x83\x80\x00\x00)\x10\x00\x00\x00\x80\x00\x00\x00'
>>> nxdomain_msg = dns.message.from_wire(nxdomain_msg_wire)
>>> analysis.add_response('127.0.0.1', '2001:400:14:2::10', 'foobar123.es.net', dns.rdatatype.A, dns.rdataclass.IN, False, True, True, False, nxdomain_msg, date1)
<DNSResponse: query: foobar123.es.net. IN A server: 2001:400:14:2::10 id: 24158>

>>> dns.rdatatype.to_text(analysis.nsec_rdtype)
'NSEC'
>>> analysis.ttl_mapping
{48: 86400, 2: 172800, 43: 86400, 6: 86400, -2: 172800}
>>> analysis.rdtypes()
set([48, 2, 43, -2, 6])
>>> analysis.signed
True
>>> analysis.analysis_end = date1
>>> analysis.save()
>>> analysis.ttl_mapping_raw
'-2,172800,2,172800,6,86400,43,86400,48,86400'
>>> analysis_from_query = DomainNameAnalysis.objects.latest(name='es.net')
>>> analysis_from_query
<DomainNameAnalysis: es.net>
>>> analysis_from_query == analysis
True
>>> analysis.all_servers()
set(['198.129.252.34', '2001:400:910:1::2', '2001:400:6000::22', '198.124.252.22', '198.128.2.10', '2001:400:14:2::10'])
>>> analysis.auth_servers()
set(['198.128.2.10', '198.124.252.22', '2001:400:14:2::10'])
>>> analysis.updated_utc_str()
'2012-11-05 00:00:00 UTC'
>>> #XXX fix this one
>>> #analysis.updated_ago_str()
>>> analysis.timestamp_url_encoded()
'UJcBgA'
>>> analysis.base_url_with_timestamp()
'/d/es.net/UJcBgA/'
>>> analysis.response_url(soa_response)
'/d/es.net/UJcBgA/responses/es.net/6/198.128.2.10/ftt/127.0.0.1/'
>>> soa_response.base_url()
'/r/es.net/6/198.128.2.10/ftt/127.0.0.1/'
>>> soa_response.base_url_with_timestamp()
'/r/es.net/6/198.128.2.10/ftt/127.0.0.1/UJcBgA/'
>>> soa_response.to_text()
u';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 33149\n;; flags: qr aa rd; QUERY: 1, ANSWER: 2, AUTHORITY: 4, ADDITIONAL: 7\n\n;; OPT PSEUDOSECTION:\n; EDNS: version: 0, flags: do; udp: 4096\n;; QUESTION SECTION:\n;es.net.          IN SOA\n\n;; ANSWER SECTION:\nes.net.\t\t86400\tIN\tSOA\tns1.es.net. hostmaster.es.net. 2012102611 7200 3600 1209600 600\nes.net.\t\t86400\tIN\tRRSIG\tSOA 5 2 86400 20121109155812 20121026145812 37143 es.net. Kruw8ySZDSzxsqXCwnXHdTZvVa+jdxOE p5vcHGbRhLZUrblpEgtksEOEAYM/rpHj ZMDrG5WZhl7hzJs0jVT1rc/X/seFxJdS +tiLcxolLiYX2rez0tmyxlAbzkC12aNo jQqN/3/FLsBtnghHtHy6/sXHB2PPMDcn KVklxdSOAaU=\n\n;; AUTHORITY SECTION:\nes.net.\t\t172800\tIN\tNS\tns1.es.net.\nes.net.\t\t172800\tIN\tNS\tns-lvk.es.net.\nes.net.\t\t172800\tIN\tNS\tns-aoa.es.net.\nes.net.\t\t172800\tIN\tRRSIG\tNS 5 2 172800 20121109155812 20121026145812 37143 es.net. B3mqGgtOaEHYrCu29fHTymmIy8QVaiN4 EDbU4jDqXgqgKYNL8DA5E0unA7+vnAk2 Ej+JT2HuUEG/SUCuhBmoWfMjNplFaf6D pKn6K+tes2yrTRM0a1+VLKyVjiR+yBVx u4Ck3YQceclIUKS1COLNLqWblOivGeMw vydvRN8FC0o=\n\n;; ADDITIONAL SECTION:\nns1.es.net.\t\t172800\tIN\tA\t198.128.2.10\nns1.es.net.\t\t172800\tIN\tAAAA\t2001:400:14:2::10\nns-aoa.es.net.\t\t172800\tIN\tA\t198.124.252.22\nns-aoa.es.net.\t\t172800\tIN\tAAAA\t2001:400:6000::22\nns-lvk.es.net.\t\t172800\tIN\tA\t198.129.252.34\nns-lvk.es.net.\t\t172800\tIN\tAAAA\t2001:400:910:1::2\n\n;; SERVER: 198.128.2.10#53\n;; WHEN: Mon Nov 05 00:00:00 2012 UTC\n;; MSG SIZE  rcvd: 606\n'
>>> soa_response.to_html()
u'<div id="header" class="section"><h3>;; -&gt;&gt;HEADER&lt;&lt;- <span id="opcode">opcode: QUERY</span>, <span id="status">status: NOERROR</span>, <span id="query-id">id: 33149</span></h3>\n;; <span id="flags">flags:  <abbr title="Query Response">qr</abbr> <abbr title="Authoritative Answer">aa</abbr> <abbr title="Recursion Desired">rd</abbr></span>; <span id="section-count">QUERY: 1, ANSWER: 2, AUTHORITY: 4, ADDITIONAL: 7</span><br /></div>\n<div id="edns" class="section"><h3>;; OPT PSEUDOSECTION:</h3>\n; EDNS: <span id="edns-version">version: 0</span>, <span id="edns-flags">flags: <abbr title="DNSSEC answer OK">do</abbr></span>; <span id="edns-payload">udp: 4096</span></div>\n<div id="question" class="section"><h3>;; QUESTION SECTION:</h3>\n<table><tr id="question-rr"><td>;es.net.</td><td></td><td>IN</td><td>SOA</td><td></td></tr></table></div>\n<div id="answer" class="section"><h3>;; ANSWER SECTION:</h3><table>\n<tbody id="ans-es.net-6"><tr id="ans-es.net-6-fde65a67a77d0132e8422434ce50cefa"><td valign="top">es.net.</td><td valign="top">86400</td><td valign="top">IN</td><td valign="top">SOA</td><td valign="top">ns1.es.net. hostmaster.es.net. 2012102611 7200 3600 1209600 600</td></tr>\n</tbody><tbody id="ans-es.net-46-6"><tr id="ans-es.net-46-6-ae6e1c89f910255628798e4ab7652699"><td valign="top">es.net.</td><td valign="top">86400</td><td valign="top">IN</td><td valign="top">RRSIG</td><td valign="top">SOA 5 2 86400 20121109155812 20121026145812 37143 es.net. Kruw8ySZDSzxsqXCwnXHdTZvVa+jdxOE p5vcHGbRhLZUrblpEgtksEOEAYM/rpHj ZMDrG5WZhl7hzJs0jVT1rc/X/seFxJdS +tiLcxolLiYX2rez0tmyxlAbzkC12aNo jQqN/3/FLsBtnghHtHy6/sXHB2PPMDcn KVklxdSOAaU=</td></tr>\n</tbody></table></div><div id="authority" class="section"><h3>;; AUTHORITY SECTION:</h3><table>\n<tbody id="aut-es.net-2"><tr id="aut-es.net-2-0c178781f6043423711c5633e1a6f5db"><td valign="top">es.net.</td><td valign="top">172800</td><td valign="top">IN</td><td valign="top">NS</td><td valign="top">ns1.es.net.</td></tr>\n<tr id="aut-es.net-2-473c5dc5ac8f198c91ff25b1ca125eb8"><td valign="top">es.net.</td><td valign="top">172800</td><td valign="top">IN</td><td valign="top">NS</td><td valign="top">ns-lvk.es.net.</td></tr>\n<tr id="aut-es.net-2-f3bb7f0bfc2fd1a4b39016dc4307e459"><td valign="top">es.net.</td><td valign="top">172800</td><td valign="top">IN</td><td valign="top">NS</td><td valign="top">ns-aoa.es.net.</td></tr>\n</tbody><tbody id="aut-es.net-46-2"><tr id="aut-es.net-46-2-43f0cc0219a15f8a135884eaa220dc8c"><td valign="top">es.net.</td><td valign="top">172800</td><td valign="top">IN</td><td valign="top">RRSIG</td><td valign="top">NS 5 2 172800 20121109155812 20121026145812 37143 es.net. B3mqGgtOaEHYrCu29fHTymmIy8QVaiN4 EDbU4jDqXgqgKYNL8DA5E0unA7+vnAk2 Ej+JT2HuUEG/SUCuhBmoWfMjNplFaf6D pKn6K+tes2yrTRM0a1+VLKyVjiR+yBVx u4Ck3YQceclIUKS1COLNLqWblOivGeMw vydvRN8FC0o=</td></tr>\n</tbody></table></div><div id="additional" class="section"><h3>;; ADDITIONAL SECTION:</h3><table>\n<tbody id="add-ns1.es.net-1"><tr id="add-ns1.es.net-1-658ee61ee3dd0f88ed1011e281260bb8"><td valign="top">ns1.es.net.</td><td valign="top">172800</td><td valign="top">IN</td><td valign="top">A</td><td valign="top">198.128.2.10</td></tr>\n</tbody><tbody id="add-ns1.es.net-28"><tr id="add-ns1.es.net-28-81b7fef92b6bf34b2108eaeca77b33e7"><td valign="top">ns1.es.net.</td><td valign="top">172800</td><td valign="top">IN</td><td valign="top">AAAA</td><td valign="top">2001:400:14:2::10</td></tr>\n</tbody><tbody id="add-ns-aoa.es.net-1"><tr id="add-ns-aoa.es.net-1-90b21b31837ab28cbdf4a6ed5e22da02"><td valign="top">ns-aoa.es.net.</td><td valign="top">172800</td><td valign="top">IN</td><td valign="top">A</td><td valign="top">198.124.252.22</td></tr>\n</tbody><tbody id="add-ns-aoa.es.net-28"><tr id="add-ns-aoa.es.net-28-4dcde1a24cdbdd5f523b1725b573f80f"><td valign="top">ns-aoa.es.net.</td><td valign="top">172800</td><td valign="top">IN</td><td valign="top">AAAA</td><td valign="top">2001:400:6000::22</td></tr>\n</tbody><tbody id="add-ns-lvk.es.net-1"><tr id="add-ns-lvk.es.net-1-891eb2f8c5bdfb058a7e0e3ee0b9313e"><td valign="top">ns-lvk.es.net.</td><td valign="top">172800</td><td valign="top">IN</td><td valign="top">A</td><td valign="top">198.129.252.34</td></tr>\n</tbody><tbody id="add-ns-lvk.es.net-28"><tr id="add-ns-lvk.es.net-28-23aec2c6befe53c755d7df0811d69fae"><td valign="top">ns-lvk.es.net.</td><td valign="top">172800</td><td valign="top">IN</td><td valign="top">AAAA</td><td valign="top">2001:400:910:1::2</td></tr>\n</tbody></table></div><div id="stats" class="section">;; <span id="msg-server">SERVER: 198.128.2.10#53</span><br />\n;; <span id="msg-when">WHEN: Mon Nov 05 00:00:00 2012 UTC</span><br />\n;; <span id="msg-size">MSG SIZE  rcvd: 606</span><br />\n</div>'
>>> analysis2 = DomainNameAnalysis.objects.create(name_obj=name_obj, analysis_start=date2, analysis_end=date2)
>>> analysis.previous is None
True
>>> analysis.next == analysis2
True
>>> analysis.first == analysis
True
>>> analysis.latest == analysis2
True
>>> analysis2.previous == analysis
True
>>> analysis2.next is None
True
>>> analysis2.first == analysis
True
>>> analysis2.latest == analysis2
True
>>> rrsets_rrsigs, neg_responses, dname_rrsets_rrsigs, nsec_rrsets_rrsigs = \
...        analysis.get_aggregated_responses(analysis.name, dns.rdatatype.SOA)
>>> rrsets_rrsigs
[(<DNS es.net. IN SOA RRset>, set([('198.128.2.10', '127.0.0.1'), ('2001:400:14:2::10', '127.0.0.1')]), [(<DNS IN RRSIG(SOA) rdata: SOA 5 2 86400 20121109155812 20121026145812 37143 es.net. Kruw8ySZDSzxsqXCwnXHdTZvVa+jdxOE p5vcHGbRhLZUrblpEgtksEOEAYM/rpHj ZMDrG5WZhl7hzJs0jVT1rc/X/seFxJdS +tiLcxolLiYX2rez0tmyxlAbzkC12aNo jQqN/3/FLsBtnghHtHy6/sXHB2PPMDcn KVklxdSOAaU=>, 86400L, set([('198.128.2.10', '127.0.0.1'), ('2001:400:14:2::10', '127.0.0.1')]))])]
>>> neg_responses
{'Empty Answer': [], 'NXDOMAIN': []}
>>> dname_rrsets_rrsigs
[]
>>> nsec_rrsets_rrsigs
[]
>>> analysis.get_aggregated_error_responses(analysis.name, dns.rdatatype.SOA)
[('Response timed out', [('2001:400:6000::22', '127.0.0.1')]), ('Malformed response received', [('198.124.252.22', '127.0.0.1')])]
>>> analysis.all_rdata(analysis.name, dns.rdatatype.SOA)
set([<DNS IN SOA rdata: ns1.es.net. hostmaster.es.net. 2012102611 7200 3600 1209600 600>])
>>> ds_set = analysis.ds_set()
>>> ds_set
set([<DNS IN DS rdata: 6874 5 1 35a4ac56475fa3d9ae063118ce41a17f07fe27ec>, <DNS IN DS rdata: 6874 5 2 5f3547159a8d21ae769a03ba6d8f47f6732e29ee33849980f71fcf633b51ad9c>])
>>> analysis.ds_set(True)
set([])
>>> dnskey_set = analysis.dnskey_set()
>>> dnskey_set
set([<DNS IN DNSKEY rdata: 256 3 5 AwEAAXnif+DDoM3PadabcEnIXXPgWhHT LNGnkh4eBw3pXSfW+ElsNzvA92lf0fyT w0TervWISwIR9NZC0gTJ27LjcSjyyujG UPwGdBJYHJtgbvsWoKo3+mCZNuW9tQGi iYosx4DCnee09Tc5U86/BbhoHqyhTLar Uji3sbjSier6Wlft>, <DNS IN DNSKEY rdata: 257 3 5 AwEAAX2i+gWJQBCSBao2M464qotbDZeI xCKTaNNx295L0k8IBcYO3Y3yI9JQ8j0Y nNxDTziKkdbOwanW8wWBdAmsp4Tzgd/9 fsPsaI/+FtKsV71/C2Je/DCZs6ml7aF0 JGAilmndZ9gfEgaYd/avpJf4HrEtF5sY P1yBhbJ4a3kL6vttAuD5THgAZVEc9Gr4 DUAFUCKGffcShpzCYsDTFbkt+pbVi8Iz batdEljdYEBpE9EW3C7BE12JxtIJLDWh nGeVl0O0B6PDDzxri8R2NQT+ElQe3ZR6 X76OQC0xgW0YJIZ+LNia7l/27XotaDuM Xmt7WXK9/zVb/ZEo8NDttZpg8yE=>, <DNS IN DNSKEY rdata: 256 3 5 AwEAAaZVSGQbXj4TXJyFHB/xO8X0fppT bz9Htr0E2uMrMV8GxnwiEzSHo8fFG3sj X7tvftYjIclh7gqkgCGL69JrIrNvcKA+ gpW6xVl/JmZv/vkOhflPUvQ5S3zsLP5Z Qkb6sO+KIECFk2ngeCJ97kSxVZHKB6vh Ce3ecXOj6j4HCqFF>, <DNS IN DNSKEY rdata: 257 3 5 AwEAAbpmxjGsPtkI1ntdpDVbwZE2eEBW Jpv6vXa8PIi5EvukFeRPtOwvIT0QTkrR XteemsRU7n7/0o/P9XEF/u917ap40bww 61xrVumrXrxCntkFog+crFZpo5ZZiaMZ qHP/JKEnABve0hofm75H91NgIzFZ9ATm 4Jy4ixmV4QMk9/xjpIut4OsaEI+K6D8Z HN1dDG4yKv+/LxzsnvU9JAsK+KrSAI9M vI8vJyirRAOgXwYmec7Hcid0LYLDZ+Hj muxavy98bm5hmNMPP0bPP9qRfo66jpvc jSXJNgIBpkrCK5j9xtJ5OaxaJmDFSh1g iESLbqiZtDWnKDLHh4+/dB0K3gU=>])
>>> for ds in ds_set:
...   analysis.dnskeys_for_ds(ds)
...   analysis.servers_with_ds(ds)
[(<DNS IN DNSKEY rdata: 257 3 5 AwEAAX2i+gWJQBCSBao2M464qotbDZeI xCKTaNNx295L0k8IBcYO3Y3yI9JQ8j0Y nNxDTziKkdbOwanW8wWBdAmsp4Tzgd/9 fsPsaI/+FtKsV71/C2Je/DCZs6ml7aF0 JGAilmndZ9gfEgaYd/avpJf4HrEtF5sY P1yBhbJ4a3kL6vttAuD5THgAZVEc9Gr4 DUAFUCKGffcShpzCYsDTFbkt+pbVi8Iz batdEljdYEBpE9EW3C7BE12JxtIJLDWh nGeVl0O0B6PDDzxri8R2NQT+ElQe3ZR6 X76OQC0xgW0YJIZ+LNia7l/27XotaDuM Xmt7WXK9/zVb/ZEo8NDttZpg8yE=>, True)]
set([('192.5.6.30', '127.0.0.1')])
[(<DNS IN DNSKEY rdata: 257 3 5 AwEAAX2i+gWJQBCSBao2M464qotbDZeI xCKTaNNx295L0k8IBcYO3Y3yI9JQ8j0Y nNxDTziKkdbOwanW8wWBdAmsp4Tzgd/9 fsPsaI/+FtKsV71/C2Je/DCZs6ml7aF0 JGAilmndZ9gfEgaYd/avpJf4HrEtF5sY P1yBhbJ4a3kL6vttAuD5THgAZVEc9Gr4 DUAFUCKGffcShpzCYsDTFbkt+pbVi8Iz batdEljdYEBpE9EW3C7BE12JxtIJLDWh nGeVl0O0B6PDDzxri8R2NQT+ElQe3ZR6 X76OQC0xgW0YJIZ+LNia7l/27XotaDuM Xmt7WXK9/zVb/ZEo8NDttZpg8yE=>, True)]
set([('192.5.6.30', '127.0.0.1')])
>>> for dnskey in dnskey_set:
...   analysis.servers_with_dnskey(dnskey)
set([('198.128.2.10', '127.0.0.1'), ('2001:400:14:2::10', '127.0.0.1')])
set([('198.128.2.10', '127.0.0.1'), ('2001:400:14:2::10', '127.0.0.1')])
set([('198.128.2.10', '127.0.0.1'), ('2001:400:14:2::10', '127.0.0.1')])
set([('198.128.2.10', '127.0.0.1'), ('2001:400:14:2::10', '127.0.0.1')])

>>> analysis.ds_by_dnskey()
{(5, 6874, <DNS IN DNSKEY rdata: 257 3 5 AwEAAX2i+gWJQBCSBao2M464qotbDZeI xCKTaNNx295L0k8IBcYO3Y3yI9JQ8j0Y nNxDTziKkdbOwanW8wWBdAmsp4Tzgd/9 fsPsaI/+FtKsV71/C2Je/DCZs6ml7aF0 JGAilmndZ9gfEgaYd/avpJf4HrEtF5sY P1yBhbJ4a3kL6vttAuD5THgAZVEc9Gr4 DUAFUCKGffcShpzCYsDTFbkt+pbVi8Iz batdEljdYEBpE9EW3C7BE12JxtIJLDWh nGeVl0O0B6PDDzxri8R2NQT+ElQe3ZR6 X76OQC0xgW0YJIZ+LNia7l/27XotaDuM Xmt7WXK9/zVb/ZEo8NDttZpg8yE=>): set([(<DNS IN DS rdata: 6874 5 1 35a4ac56475fa3d9ae063118ce41a17f07fe27ec>, True), (<DNS IN DS rdata: 6874 5 2 5f3547159a8d21ae769a03ba6d8f47f6732e29ee33849980f71fcf633b51ad9c>, True)])}
>>> zsks, ksks, published, revoked = analysis.dnskeys_by_role()
>>> zsks
set([<DNS IN DNSKEY rdata: 256 3 5 AwEAAaZVSGQbXj4TXJyFHB/xO8X0fppT bz9Htr0E2uMrMV8GxnwiEzSHo8fFG3sj X7tvftYjIclh7gqkgCGL69JrIrNvcKA+ gpW6xVl/JmZv/vkOhflPUvQ5S3zsLP5Z Qkb6sO+KIECFk2ngeCJ97kSxVZHKB6vh Ce3ecXOj6j4HCqFF>])
>>> ksks
set([<DNS IN DNSKEY rdata: 257 3 5 AwEAAX2i+gWJQBCSBao2M464qotbDZeI xCKTaNNx295L0k8IBcYO3Y3yI9JQ8j0Y nNxDTziKkdbOwanW8wWBdAmsp4Tzgd/9 fsPsaI/+FtKsV71/C2Je/DCZs6ml7aF0 JGAilmndZ9gfEgaYd/avpJf4HrEtF5sY P1yBhbJ4a3kL6vttAuD5THgAZVEc9Gr4 DUAFUCKGffcShpzCYsDTFbkt+pbVi8Iz batdEljdYEBpE9EW3C7BE12JxtIJLDWh nGeVl0O0B6PDDzxri8R2NQT+ElQe3ZR6 X76OQC0xgW0YJIZ+LNia7l/27XotaDuM Xmt7WXK9/zVb/ZEo8NDttZpg8yE=>, <DNS IN DNSKEY rdata: 256 3 5 AwEAAaZVSGQbXj4TXJyFHB/xO8X0fppT bz9Htr0E2uMrMV8GxnwiEzSHo8fFG3sj X7tvftYjIclh7gqkgCGL69JrIrNvcKA+ gpW6xVl/JmZv/vkOhflPUvQ5S3zsLP5Z Qkb6sO+KIECFk2ngeCJ97kSxVZHKB6vh Ce3ecXOj6j4HCqFF>])
>>> published
set([<DNS IN DNSKEY rdata: 256 3 5 AwEAAXnif+DDoM3PadabcEnIXXPgWhHT LNGnkh4eBw3pXSfW+ElsNzvA92lf0fyT w0TervWISwIR9NZC0gTJ27LjcSjyyujG UPwGdBJYHJtgbvsWoKo3+mCZNuW9tQGi iYosx4DCnee09Tc5U86/BbhoHqyhTLar Uji3sbjSier6Wlft>, <DNS IN DNSKEY rdata: 257 3 5 AwEAAbpmxjGsPtkI1ntdpDVbwZE2eEBW Jpv6vXa8PIi5EvukFeRPtOwvIT0QTkrR XteemsRU7n7/0o/P9XEF/u917ap40bww 61xrVumrXrxCntkFog+crFZpo5ZZiaMZ qHP/JKEnABve0hofm75H91NgIzFZ9ATm 4Jy4ixmV4QMk9/xjpIut4OsaEI+K6D8Z HN1dDG4yKv+/LxzsnvU9JAsK+KrSAI9M vI8vJyirRAOgXwYmec7Hcid0LYLDZ+Hj muxavy98bm5hmNMPP0bPP9qRfo66jpvc jSXJNgIBpkrCK5j9xtJ5OaxaJmDFSh1g iESLbqiZtDWnKDLHh4+/dB0K3gU=>])
>>> revoked
set([])
>>> analysis.potential_trusted_keys()
set([<DNS IN DNSKEY rdata: 257 3 5 AwEAAX2i+gWJQBCSBao2M464qotbDZeI xCKTaNNx295L0k8IBcYO3Y3yI9JQ8j0Y nNxDTziKkdbOwanW8wWBdAmsp4Tzgd/9 fsPsaI/+FtKsV71/C2Je/DCZs6ml7aF0 JGAilmndZ9gfEgaYd/avpJf4HrEtF5sY P1yBhbJ4a3kL6vttAuD5THgAZVEc9Gr4 DUAFUCKGffcShpzCYsDTFbkt+pbVi8Iz batdEljdYEBpE9EW3C7BE12JxtIJLDWh nGeVl0O0B6PDDzxri8R2NQT+ElQe3ZR6 X76OQC0xgW0YJIZ+LNia7l/27XotaDuM Xmt7WXK9/zVb/ZEo8NDttZpg8yE=>])
>>> analysis.schedule_refresh()
>>> analysis.name_obj.refresh_interval
28800
>>> analysis.name_obj.refresh_offset
27866
'''
