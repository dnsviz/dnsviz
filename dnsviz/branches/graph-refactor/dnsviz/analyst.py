#!/usr/bin/python
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
import logging
import multiprocessing
import random
import signal
import sys
import time
import threading
import traceback

import dns.exception, dns.flags, dns.message, dns.name, dns.rdataclass, dns.rdatatype, dns.resolver

from django.conf import settings
from django.core.mail import mail_admins
from django.db import transaction, IntegrityError
from django.db.models import Q
from django.utils.timezone import now

from dnsviz.models import *
from dnsviz import util

class DomainNameAnalysisInterruption(Exception):
    pass

class DependencyAnalysisException(DomainNameAnalysisInterruption):
    pass

class NetworkConnectivityException(Exception):
    pass

class IPv4ConnectivityException(NetworkConnectivityException):
    pass

class IPv6ConnectivityException(NetworkConnectivityException):
    pass

ROOT_NS_IPS = set(['198.41.0.4', '2001:503:ba3e::2:30', # A
        '192.228.79.201', # B
        '192.33.4.12', # C
        '199.7.91.13', '2001:500:2d::d', # D
        '192.203.230.10', # E
        '192.5.5.241', '2001:500:2f::f', # F
        '192.112.36.4', # G
        '128.63.2.53', '2001:500:1::803f:235', # H
        '192.36.148.17', '2001:7fe::53', # I
        '192.58.128.30', '2001:503:c27::2:30', # J
        '193.0.14.129', '2001:7fd::1', # K
        '199.7.83.42', '2001:500:3::42', # L
        '202.12.27.33', '2001:dc3::35', # M
])
ROOT_NS_IPS_6 = set(filter(lambda x: ':' in x, ROOT_NS_IPS))
ROOT_NS_IPS_4 = ROOT_NS_IPS.difference(ROOT_NS_IPS_6)
IP6_ARPA_NAME = dns.name.from_text('ip6.arpa')
INADDR_ARPA_NAME = dns.name.from_text('in-addr.arpa')

class Crawler(object):
    def __init__(self, name, start_time, trace=None, in_progress_cache=None, notify_events=None, exception_event=None, interrupt_event=None,
            client_v4=None, client_v6=None, force=False, force_ancestry=False, force_deps=False, force_dnskey=False, threads_per_query=10):
        self.name = name
        self.start_time = start_time
        if trace is None:
            self.trace = []
        else:
            self.trace = trace
        self.force = force
        self.force_deps = force_deps
        self.force_ancestry = force_ancestry
        self.force_dnskey = force_dnskey
        self.threads_per_query = threads_per_query
        self.logger = logging.getLogger('dnsviz.analyst')
        self._dep_analysis_event = threading.Event()
        self._dependency_analyses = {}
        self._names_being_analyzed = []
        self._last_name_analyzed = None
        if in_progress_cache is None:
            self._in_progress_cache = {}
        else:
            self._in_progress_cache = in_progress_cache
        if notify_events is None:
            self._notify_events = {}
        else:
            self._notify_events = notify_events
        if exception_event is None:
            self._exception_event = threading.Event()
        else:
            self._exception_event = exception_event
        self._interrupt_event = interrupt_event

        self.client_v4 = client_v4
        self.client_v6 = client_v6
        if self.client_v4 is None:
            self.client_v4 = util.dnsutil.get_client_address('198.41.0.4')
            self.client_v6 = util.dnsutil.get_client_address('2001:503:ba3e::2:30')

        if self.client_v4 is None and self.client_v6 is None:
            raise NetworkConnectivityException('No network interfaces available for analysis!')
        if self.client_v4 is None:
            self.logger.warning('No IPv4 connectivity available for analyzing %s.' % (util.format.humanize_name(name)))
        if self.client_v6 is None:
            self.logger.warning('No IPv6 connectivity available for analyzing %s.' % (util.format.humanize_name(name)))

    def _init_dependency_analysis(self, name_obj):
        self._dependency_analyses[name_obj.name] = {(name_obj.name, None): (None, None)}

    def _finish_dependency_analysis(self, name_obj):
        del self._dependency_analyses[name_obj.name][(name_obj.name, None)]

    def _expect_dependency_analysis(self, name_obj, name, rdtype):
        self._dependency_analyses[name_obj.name][(name, rdtype)] = None, None

    def _notify_dependency_analysis_success_func(self, name_obj, name, rdtype):
        def _notify(request, result):
            self._dependency_analyses[name_obj.name][(name, rdtype)] = (result, None)
            self._dep_analysis_event.set()
        return _notify

    def _notify_dependency_analysis_failure_func(self, name_obj, name, rdtype):
        def _notify(request, exc):
            self._dependency_analyses[name_obj.name][(name, rdtype)] = (None, exc)
            self._dep_analysis_event.set()
        return _notify

    def _notify_upon_release(self, name_obj):
        try:
            self._notify_events[name_obj.name].set()
            del self._notify_events[name_obj.name]
        except KeyError:
            pass

    def _add_reverse_dependencies(self, name_obj):
        # first look for cyclic dependencies
        deps = name_obj.get_ns_names()
        deps.update(set(name_obj.cname.values_list('name', flat=True)))
        deps.update(set(name_obj.mx.values_list('name', flat=True)))
        deps.update(set(name_obj.external_signers.values_list('name', flat=True)))

        for i in range(len(self.trace)-1, -1, -1):
            potential_cyclic_dep_obj = self.trace[i][0][-1]
            if potential_cyclic_dep_obj.name in deps:
                potential_cyclic_dep_obj.reverse_dependencies.add(name_obj)
                name_obj.dependency = potential_cyclic_dep_obj
                return True

        if name_obj.name == dns.name.root:
            return False

        try:
            parent_obj = self._in_progress_cache[name_obj.name.parent()]
        except KeyError:
            return False

        if parent_obj.analysis_in_progress:
            parent_obj.reverse_dependencies.add(name_obj)
            #XXX poor man's race condition fix
            # make sure potential_dependency_obj is still in progress
            # or at least that name was saved in the short time between our addition and now
            if parent_obj.analysis_in_progress or \
                    not name_obj.analysis_in_progress:
                name_obj.dependency = parent_obj
                return True
        return False

    def _ancestor_with_exception(self, name_obj):
        # cycle through each of its ancestors to see if their
        # dependency analyses are complete and if there were any
        # exceptions
        
        for i in range(len(self._names_being_analyzed)-1, -1, -1):
            potential_ancestor_obj = self._names_being_analyzed[i]
            # if this ancestor raised exceptions then reset
            # and break out of the loop
            if name_obj.name.is_subdomain(potential_ancestor_obj.name) and \
                    potential_ancestor_obj.name in self.analysis_exceptions:
                return potential_ancestor_obj
        return None

    def _finalize_dependency_analyses(self):
        descendents_of_names_with_exceptions = set()

        try:
            while True:
                names = self._dependency_analyses.keys()
                names.sort()
                unfinished_ancestor = False
                for name in names:
                    name_obj = self._in_progress_cache[name]
                    for (dep_name, rdtype), (result, exc) in self._dependency_analyses[name].items():
                        if (result, exc) == (None, None):
                            continue

                        # there was an exception caught when handling
                        # dependencies of this name, release the analysis
                        if exc is not None:
                            # only store the analysis if there isn't already one in place
                            # for the name or if the one already stored is simply an interruption
                            if name not in self.analysis_exceptions or \
                                    isinstance(self.analysis_exceptions[name][1], DomainNameAnalysisInterruption):
                                self.analysis_exceptions[name] = exc
                            name_obj.release_analysis(self._notify_upon_release)

                        # analysis was successful
                        else:
                            # set the dependency_min_ttl and extend the rdtypes for CNAMEs
                            name_obj.dependency_min_ttl = min(name_obj.dependency_min_ttl, result.min_ttl())
                            if rdtype == dns.rdatatype.CNAME:
                                name_obj.cname_rdtypes.update(result.canonical_rdtypes())

                        del self._dependency_analyses[name][(dep_name, rdtype)]

                    # if there are still dependencies for this name, then
                    # don't do any processing--just continue to the next loop iteration
                    if self._dependency_analyses[name]:
                        unfinished_ancestor = True
                        continue

                    # set analysis time
                    name_obj.dep_analysis_end = now()

                    ancestor_with_exception = self._ancestor_with_exception(name_obj)
                    if ancestor_with_exception is not None:
                        # if there were exceptions with an ancestor, then
                        # reset the name's analysis
                        name_obj.release_analysis(self._notify_upon_release)
                        descendents_of_names_with_exceptions.add(name)

                    if not unfinished_ancestor:
                        if name not in self.analysis_exceptions and name not in descendents_of_names_with_exceptions:
                            self._add_reverse_dependencies(name_obj)
                            if name_obj.dependency is None:
                                with transaction.commit_manually():
                                    try:
                                        name_obj.save_with_reverse_dependencies(self._notify_upon_release)
                                    except:
                                        transaction.rollback()
                                        raise
                                    else:
                                        transaction.commit()

                        del self._dependency_analyses[name]
                        
                if self.analysis_finished and not self._dependency_analyses:
                    break

                self._dep_analysis_event.wait()
                self._dep_analysis_event.clear()

            for name in set(self.analysis_exceptions).union(descendents_of_names_with_exceptions):
                try:
                    name_obj = self._in_progress_cache[name]
                except KeyError:
                    # if the an exception was raised before initial analysis was
                    # finished, then it won't be in the cache
                    continue
                try:
                    if name_obj.dependency is None:
                        name_obj.delete_with_reverse_dependencies(self._notify_upon_release)
                except:
                    self.logger.exception('Error resetting analysis of %s' % name_obj)
        except Exception, e:
            if isinstance(e, IntegrityError):
                try:
                    transaction.rollback()
                except transaction.TransactionManagementError:
                    pass
            self.logger.exception('Error finalizing dependencies for %s' % self.name)
            self.analysis_exceptions[self.name] = sys.exc_info()

    def _is_referral_of_type(self, rdtype):
        try:
            return self.trace[-1][1] == rdtype
        except IndexError:
            return False

    def _is_cname_referral(self):
        return self._is_referral_of_type(dns.rdatatype.CNAME)

    def _ask_ptr_queries(self, name):
        if name.is_subdomain(IP6_ARPA_NAME):
            if len(name) == 35:
                return True
            elif self._is_cname_referral() and self.name == name:
                return True
        elif name.is_subdomain(INADDR_ARPA_NAME):
            if len(name) == 7:
                return True
            elif self._is_cname_referral() and self.name == name:
                return True
        return False

    def _ask_other_queries(self, name):
        if name.is_subdomain(IP6_ARPA_NAME) or name.is_subdomain(INADDR_ARPA_NAME):
            return False
        if len(name) < 3:
            return False
        return True

    def _is_dkim(self, name):
        return '_domainkey' in name

    def _raise_on_event(self):
        if self._exception_event.is_set():
            raise DependencyAnalysisException()
        elif self._interrupt_event and self._interrupt_event.is_set():
            raise DomainNameAnalysisInterruption()

    def crawl_async(self, callback=None, exc_callback=None):
        def _crawl():
            try:
                result = self.crawl()
                if callback is not None:
                    callback(None, result)
            except:
                if exc_callback is not None:
                    exc_callback(None, sys.exc_info())
        t = threading.Thread(target=_crawl)
        t.start()
        return t

    def crawl(self):
        with transaction.autocommit():
            self.analysis_finished = False
            self.analysis_exceptions = {}
            finalize_thread = threading.Thread(target=self._finalize_dependency_analyses)
            finalize_thread.start()
            problem_name = None

            try:
                name_obj = self._crawl(self.name)
            except Exception, e:
                if isinstance(e, IntegrityError):
                    try:
                        transaction.rollback()
                    except transaction.TransactionManagementError:
                        pass

                problem_name = self._last_name_analyzed
                if not isinstance(e, DomainNameAnalysisInterruption):
                    self.logger.exception('Error analyzing %s' % (problem_name))
                    self._exception_event.set()
                self.analysis_exceptions[problem_name] = sys.exc_info()

            finally:
                self.analysis_finished = True
                self._dep_analysis_event.set()
                finalize_thread.join()

            try:
                for name_obj in self._names_being_analyzed:
                    if name_obj.name == problem_name:
                        name_obj.delete_with_reverse_dependencies(self._notify_upon_release)
                        break
            except:
                self.logger.exception('Error resetting analysis of %s' % problem_name)


            #XXX figure out how to do this properly (i.e., with regard to logging)
            deferred = None
            for exc in self.analysis_exceptions.values():
                if isinstance(exc[1], DomainNameAnalysisInterruption):
                    deferred = exc
                    continue
                raise exc[0], exc[1], exc[2]
            if deferred is not None:
                raise deferred[0], deferred[1], deferred[2]
            
            return name_obj

    def _crawl(self, name):
        self._last_name_analyzed = name
        name_obj = self._retrieve_name_for_crawl(name, False)
        if name_obj is not None:
            return name_obj
        
        if name == dns.name.root:
            parent_obj = None
        else:
            parent_obj = self._crawl(name.parent())

        self._last_name_analyzed = name

        if parent_obj is not None:
            parent_obj = parent_obj.zone
        
        name_obj = self._retrieve_name_for_crawl(name)
        if name_obj is not None:
            return name_obj

        # create a new DomainName instance, and perform the analysis
        dname_obj = DomainName.objects.get(name=name)
        name_obj = DomainNameAnalysis.objects.create(name_obj=dname_obj, analysis_start=dname_obj.analysis_start)

        if parent_obj is not None and parent_obj.no_referral_response:
            name_obj.no_referral_response = True
            return name_obj

        name_obj.analysis_in_progress = True
        # assign parent, so it doesn't need to be looked up
        name_obj.parent = parent_obj
        self._names_being_analyzed.append(name_obj)
        self._notify_events[name] = threading.Event()

        self._raise_on_event()
        self._analyze_name(name_obj)
        name_obj.analysis_end = now()

        if name_obj.all_servers(4) and self.client_v4 is not None and not name_obj.responsive_servers(4):
            if not self._root_responsive(4):
                raise IPv4ConnectivityException('No IPv4 connectivity available!')

        if name_obj.all_servers(6) and self.client_v6 is not None and not name_obj.responsive_servers(6):
            if not self._root_responsive(6):
                raise IPv6ConnectivityException('No IPv6 connectivity available!')

        self._raise_on_event()
        self._in_progress_cache[name] = name_obj
        self._analyze_dependencies(name_obj)
        self._dep_analysis_event.set()

        return name_obj

    def _analyze_or_not(self, name):
        if name in self._in_progress_cache:
            return False

        try:
            name_obj = DomainName.objects.get(name=name).latest_analysis()
        except DomainName.DoesNotExist:
            name_obj = None

        if name_obj is None:
            return True

        force_analysis = self.force_ancestry or (self.force and name == self.name)
        updated_since_analysis_start = name_obj.analysis_end > self.start_time
        ttl_expired = now() - name_obj.analysis_end > datetime.timedelta(seconds=max(name_obj.min_ttl(), settings.MIN_ANALYSIS_INTERVAL))

        if force_analysis and not updated_since_analysis_start:
            return True
        if ttl_expired:
            return True
        return False

    def _retrieve_name_for_crawl(self, name, lock_for_analysis=True):
        while True:
            self._raise_on_event()

            try:
                return self._in_progress_cache[name]
            except KeyError:
                pass
            
            dname_obj = DomainName.objects.get_or_create(name=name)[0]
            name_obj = dname_obj.latest_analysis()

            crawl_in_progress = dname_obj.analysis_start is not None
            current_timestamp = now()

            # if no crawl is necessary, then simply return
            if not self._analyze_or_not(name):
                if name_obj is None:
                    try:
                        return self._in_progress_cache[name]
                    except KeyError:
                        pass
                else:
                    return name_obj

            elif not lock_for_analysis:
                return None

            # if a crawl is already in progress, then check that it's not stale, then wait
            elif crawl_in_progress:
                if current_timestamp - dname_obj.analysis_start > datetime.timedelta(seconds=settings.MAX_ANALYSIS_TIME):
                    #TODO periodically cleanup incomplete analyses that have been reset
                    if DomainName.objects.filter(pk=dname_obj.pk, analysis_start=dname_obj.analysis_start).update(analysis_start=None):
                        self.logger.warning('Resetting crawl of %s.' % (util.format.humanize_name(name)))
                        continue

            # if no crawl is in progress, then try to get the lock, and if successful, return.  Otherwise, wait
            else:
                if DomainName.objects.filter(pk=dname_obj.pk, analysis_start__isnull=True).update(analysis_start=current_timestamp):
                    return None

            try:
                self._notify_events[name].wait(240)
            except KeyError:
                # loop while it is still being crawled
                time.sleep(5)

    def _analyze_dependencies(self, name_obj):
        self._init_dependency_analysis(name_obj)
        # external signers
        for signer in name_obj.external_signers.all():
            #XXX handle the case where we've skipped over a non-zone that is a signer to another name below
            if name_obj.name.is_subdomain(signer.name):
                continue
            c = Crawler(signer.name, self.start_time, self.trace+[(list(self._names_being_analyzed), dns.rdatatype.RRSIG)], notify_events=self._notify_events, \
                    in_progress_cache=self._in_progress_cache, exception_event=self._exception_event, client_v4=self.client_v4, client_v6=self.client_v6, \
                    force=self.force_ancestry, force_dnskey=True)
            self._expect_dependency_analysis(name_obj, c.name, dns.rdatatype.RRSIG)
            c.crawl_async(self._notify_dependency_analysis_success_func(name_obj, c.name, dns.rdatatype.RRSIG), \
                    self._notify_dependency_analysis_failure_func(name_obj, c.name, dns.rdatatype.RRSIG))
            
        # find out-of-bailiwick names or names without glue records
        if name_obj.name != dns.name.root:
            names_without_glue = [ns_name for ns_name, ip_set in name_obj.get_glue_ip_mapping().items() if not (ip_set and ns_name.is_subdomain(name_obj.parent_name()))]
            #for ns in name_obj.get_ns_names():
            for ns in names_without_glue:
                c = Crawler(ns, self.start_time, self.trace+[(list(self._names_being_analyzed), dns.rdatatype.NS)], notify_events=self._notify_events, \
                        in_progress_cache=self._in_progress_cache, exception_event=self._exception_event, client_v4=self.client_v4, client_v6=self.client_v6)
                #XXX
                #        force=self.force_deps, force_ancestry=self.force_deps)
                self._expect_dependency_analysis(name_obj, c.name, dns.rdatatype.NS)
                c.crawl_async(self._notify_dependency_analysis_success_func(name_obj, c.name, dns.rdatatype.NS), \
                        self._notify_dependency_analysis_failure_func(name_obj, c.name, dns.rdatatype.NS))

        for mx in name_obj.mx.all():
            c = Crawler(mx.name, self.start_time, self.trace+[(list(self._names_being_analyzed), dns.rdatatype.MX)], notify_events=self._notify_events, \
                    in_progress_cache=self._in_progress_cache, exception_event=self._exception_event, client_v4=self.client_v4, client_v6=self.client_v6)
            #XXX
            #        force=self.force_deps, force_ancestry=self.force_deps)
            self._expect_dependency_analysis(name_obj, c.name, dns.rdatatype.MX)
            c.crawl_async(self._notify_dependency_analysis_success_func(name_obj, c.name, dns.rdatatype.MX), \
                    self._notify_dependency_analysis_failure_func(name_obj, c.name, dns.rdatatype.MX))

        for cname in name_obj.cname.all():
            c = Crawler(cname.name, self.start_time, self.trace+[(list(self._names_being_analyzed), dns.rdatatype.CNAME)], notify_events=self._notify_events, \
                    in_progress_cache=self._in_progress_cache, exception_event=self._exception_event, client_v4=self.client_v4, client_v6=self.client_v6, \
                    force=self.force, force_deps=self.force_deps, force_ancestry=self.force_ancestry)
            self._expect_dependency_analysis(name_obj, c.name, dns.rdatatype.CNAME)
            c.crawl_async(self._notify_dependency_analysis_success_func(name_obj, c.name, dns.rdatatype.CNAME), \
                    self._notify_dependency_analysis_failure_func(name_obj, c.name, dns.rdatatype.CNAME))

        self._finish_dependency_analysis(name_obj)

    def _analyze_name(self, name_obj):
        self.logger.info('Analyzing %s' % util.format.humanize_name(name_obj.name))

        self._analyze_ns(name_obj)
        if name_obj.nxdomain or name_obj.empty_nonterminal or name_obj.no_referral_response:
            return

        self._raise_on_event()
        if self._ask_other_queries(name_obj.name):
            self.logger.debug('Querying %s/A...' % util.format.humanize_name(name_obj.name))
            self._analyze_rrset(name_obj, name_obj.all_servers(), name_obj.name, dns.rdatatype.A, dnssec=True, nocheck=True)

        # caching is acceptable at this point
        name_obj.allow_cache()
        
        self._raise_on_event()
        if name_obj.is_zone() or \
                self.force_dnskey and self.name == name_obj.name:
            self._analyze_soa(name_obj)
            self._analyze_ds(name_obj)
            self._analyze_dnskey(name_obj)

        self._raise_on_event()
        if name_obj.is_zone():
            self._analyze_nxdomain(name_obj)
            self._analyze_noerror_no_answer(name_obj)
            self._analyze_tcp_availability(name_obj)

        self._raise_on_event()
        if self._ask_ptr_queries(name_obj.name):
            self.logger.debug('Querying %s/PTR...' % util.format.humanize_name(name_obj.name))
            self._analyze_rrset(name_obj, name_obj.auth_servers(), name_obj.name, dns.rdatatype.PTR, dnssec=True, nocheck=True)

        self._raise_on_event()
        if self._ask_other_queries(name_obj.name):
            self.logger.debug('Querying %s/AAAA...' % util.format.humanize_name(name_obj.name))
            self._analyze_rrset(name_obj, name_obj.auth_servers(), name_obj.name, dns.rdatatype.AAAA, dnssec=True, nocheck=True)
            if name_obj.is_zone():
                self.logger.debug('Querying %s/MX...' % util.format.humanize_name(name_obj.name))
                self._analyze_rrset(name_obj, name_obj.auth_servers(), name_obj.name, dns.rdatatype.MX, dnssec=True, nocheck=True)
            if name_obj.is_zone() or self._is_dkim(name_obj.name):
                self.logger.debug('Querying %s/TXT...' % util.format.humanize_name(name_obj.name))
                self._analyze_rrset(name_obj, name_obj.auth_servers(), name_obj.name, dns.rdatatype.TXT, dnssec=True, nocheck=True)

        #print 'Completed crawl of %s' % (name_obj.name)

    def _analyze_ns(self, name_obj):
        if name_obj.parent is None:
            parent_auth_servers = ROOT_NS_IPS
        else:
            parent_auth_servers = name_obj.parent.auth_servers()

        if not parent_auth_servers:
            name_obj.no_referral_response = True
            return

        # ask parent servers for NS, then A as a fallback
        for rdtype in (dns.rdatatype.NS, dns.rdatatype.A):
            # query parent servers for the name, looking for a referral
            self.logger.debug('Analyzing referral for %s/%s...' % (util.format.humanize_name(name_obj.name), dns.rdatatype.to_text(rdtype)))
            responses = util.dnsutil.query_for_all(parent_auth_servers, name_obj.name, rdtype, client_v4=self.client_v4, client_v6=self.client_v6, dnssec=True, nocheck=True, \
                    thread_count=self.threads_per_query)
            responses_only = [r[1] for r in responses]

            # if all NXDOMAIN, store responses then store and return
            if util.dnsutil.all_nxdomain(name_obj.name, rdtype, responses_only):
                name_obj.referral_rdtype = rdtype
                self._store_responses(name_obj, name_obj.name, rdtype, False, True, True, False, responses)
                name_obj.nxdomain = True
                return

            # if all authoritative NOERROR with empty answer
            if util.dnsutil.all_noerror_no_answer(name_obj.name, rdtype, responses_only):
                ## check if there are any records for name - if not, then mark as non-terminal
                #if not util.dnsutil.query_for_first_match(parent_auth_servers, name_obj.name, dns.rdatatype.ANY, \
                #        util.dnsutil.authoritative_answer_filter, util.dnsutil.nxdomain_or_noerror_no_answer_filter, dnssec=False, nocheck=True)[0]:
                #    name_obj.empty_nonterminal = True
                return

            # if we received at least one valid response, then break out
            if util.dnsutil.valid_responses(responses_only):
                break

        # store responses
        name_obj.referral_rdtype = rdtype
        self._store_responses(name_obj, name_obj.name, rdtype, False, True, True, False, responses)

        # if we didn't receive any valid responses, then return
        if not util.dnsutil.valid_responses(responses_only):
            name_obj.no_referral_response = True
            return

        glue_ip_mapping = name_obj.get_glue_ip_mapping(include_auth_answers=True)
        names_resolved = set()
        names_not_resolved = set(glue_ip_mapping)
        designated_auth_servers = set()
        servers_queried = parent_auth_servers.copy()
        while names_not_resolved:
            for name in names_not_resolved:
                if name in glue_ip_mapping:
                    name_obj.add_designated_servers(*glue_ip_mapping[name])
                    designated_auth_servers.update(glue_ip_mapping[name])
                for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    try:
                        a_rrset = dns.resolver.query(name, rdtype).rrset
                        for a_rr in a_rrset:
                            name_obj.add_ns_mappings(name, a_rr.to_text())
                            designated_auth_servers.add(a_rr.to_text())
                    #XXX consider distinguishing negative responses from non-responses
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                        pass
                names_resolved.add(name)

            servers_to_query = designated_auth_servers.difference(servers_queried)

            self.logger.debug('Querying %s/NS...' % util.format.humanize_name(name_obj.name))
            self._analyze_rrset(name_obj, servers_to_query, name_obj.name, dns.rdatatype.NS, dnssec=True, nocheck=True)
            servers_queried.update(servers_to_query)

            names_not_resolved = name_obj.get_ns_names_in_child().difference(names_resolved)

    def _analyze_ds(self, name_obj):
        if name_obj.parent is not None:
            self.logger.debug('Querying %s/DS...' % util.format.humanize_name(name_obj.name))
            self._analyze_rrset(name_obj, name_obj.parent.auth_servers(), name_obj.name, dns.rdatatype.DS, dnssec=True, nocheck=True)

            if name_obj.dlv is not None:
                dlv_name = name_obj.dlv_name()
                if dlv_name is not None:
                    self.logger.debug('Querying %s/DLV...' % util.format.humanize_name(dlv_name))
                    self._analyze_rrset(name_obj, name_obj.dlv.auth_servers(), dlv_name, dns.rdatatype.DLV, dnssec=True, nocheck=True, store_no_answer=False)

    def _analyze_dnskey(self, name_obj):
        self.logger.debug('Querying %s/DNSKEY...' % util.format.humanize_name(name_obj.name))
        dnskey_args = { 'initial_payload': 4096, 'reduced_payload': 4096, 'lifetime': 5.0, 'timeout': 2.0, 'downgrade_on_timeout': False }
        responses = util.dnsutil.query_for_all(name_obj.auth_servers(), name_obj.name, dns.rdatatype.DNSKEY, client_v4=self.client_v4, client_v6=self.client_v6, dnssec=True, nocheck=True, thread_count=self.threads_per_query, **dnskey_args)

        servers_with_no_response = set([server for (server, client), response in responses if response == dns.exception.Timeout])

        if servers_with_no_response:
            dnskey_args = { 'initial_payload': 4096, 'reduced_payload': 512, 'lifetime': 15.0, 'timeout': 3.0, 'downgrade_on_timeout': True }
            responses2 = util.dnsutil.query_for_all(servers_with_no_response, name_obj.name, dns.rdatatype.DNSKEY, client_v4=self.client_v4, client_v6=self.client_v6, dnssec=True, nocheck=True, thread_count=self.threads_per_query)
            for (server_ip, client), response in responses2:
                if not isinstance(response, dns.message.Message):
                    continue
                responses.remove(((server_ip, client), dns.exception.Timeout))
                responses.append(((server_ip, client), response))

                # it could be that it failed previously because we didn't allow it to downgrade, not because of the message size
                # if there are no DNSKEYs in the new response, then just continue
                try:
                    response.find_rrset(response.answer, name_obj.name, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
                except KeyError:
                    continue

                self.logger.debug('Analyzing PMTU issues for %s using %s/DNSKEY...' % (server_ip, util.format.humanize_name(name_obj.name)))
                max_payload_low, max_payload_high, e = util.dnsutil.find_max_payload(server_ip, name_obj.name, dns.rdatatype.DNSKEY, 512, 4096, 512, dnssec=True, nocheck=True)

                #XXX very this
                # if max_payload_high is 4096 then it was a fluke, so just continue
                if max_payload_high == 4096:
                    continue
                    
                name_obj.add_max_payload(server_ip, max_payload_low, max_payload_high)
                #XXX fix this
                #if e is not None:
                #    name_obj.format_errors = 'The message received from %s when EDNS payload was %d was malformed (%s).' % (server_ip, max_payload_low, e.__class__.__name__)

        self._store_responses(name_obj, name_obj.name, dns.rdatatype.DNSKEY, False, True, True, False, responses)

    def _analyze_tcp_availability(self, name_obj):
        servers_with_tcp_available = util.dnsutil.tcp_test_servers(name_obj.all_servers(), 3, self.threads_per_query)
        for server in name_obj.all_servers():
            tcp_available = server in servers_with_tcp_available
            name_obj.set_tcp_availability(server, tcp_available)

    def _analyze_nxdomain(self, name_obj):
        random_name = ''.join(random.sample('abcdefghijklmnopqrstuvwxyz1234567890', 10))
        try:
            name_obj.nxdomain_name = dns.name.from_text('%s.%s' % (random_name, name_obj.name.to_text().rstrip('.')))
            name_obj.nxdomain_rdtype = dns.rdatatype.A
            self.logger.debug('Analyzing negative responses for %s (NXDOMAIN)...' % name_obj)
            responses = util.dnsutil.query_for_all(name_obj.auth_servers(), name_obj.nxdomain_name, name_obj.nxdomain_rdtype, client_v4=self.client_v4, client_v6=self.client_v6, dnssec=True, nocheck=True, thread_count=self.threads_per_query)
            self._store_responses(name_obj, name_obj.nxdomain_name, name_obj.nxdomain_rdtype, False, True, True, False, responses)
        except dns.name.NameTooLong:
            pass

    def _analyze_noerror_no_answer(self, name_obj):
        name_obj.nxrrset_name = name_obj.name
        name_obj.nxrrset_rdtype = dns.rdatatype.CNAME

        self.logger.debug('Analyzing negative responses for %s (No answer)...' % name_obj)
        responses = util.dnsutil.query_for_all(name_obj.auth_servers(), name_obj.nxrrset_name, name_obj.nxrrset_rdtype, client_v4=self.client_v4, client_v6=self.client_v6, dnssec=True, nocheck=True, thread_count=self.threads_per_query)
        self._store_responses(name_obj, name_obj.nxrrset_name, name_obj.nxrrset_rdtype, False, True, True, False, responses)

        if name_obj.nsec_rdtype is None and name_obj.signed:
            try:
                dns.resolver.query(name_obj.name, dns.rdatatype.NSEC3PARAM).rrset
                name_obj.nsec_rdtype = dns.rdatatype.NSEC3
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                name_obj.nsec_rdtype = dns.rdatatype.NSEC
            except dns.exception.DNSException, e:
                #sys.stderr.write('Unable to get an authoritative response for %s/NSEC3PARAM; %s encountered\n' % (name_obj, e.__class__))
                pass

    def _analyze_soa(self, name_obj):
        self.logger.debug('Querying %s/SOA...' % util.format.humanize_name(name_obj.name))
        self._analyze_rrset(name_obj, name_obj.auth_servers(), name_obj.name, dns.rdatatype.SOA, dnssec=True, nocheck=True)

    def _store_responses(self, name_obj, name, rdtype, rd, do, cd, ad, responses):
        for (server_ip, client), response in responses:
            name_obj.add_response(client, server_ip, name, rdtype, dns.rdataclass.IN, rd, do, cd, ad, response)

    def _analyze_rrset(self, name_obj, servers, name, rdtype, store_no_answer=True, **kwargs):
        responses = util.dnsutil.query_for_all(servers, name, rdtype, client_v4=self.client_v4, client_v6=self.client_v6, thread_count=self.threads_per_query, **kwargs)

        rrsets_rrsigs, neg_responses, dname_rrsets_rrsigs, nsec_rrsets_rrsigs = util.dnsutil.aggregate_responses(name, rdtype, responses)

        if store_no_answer or rrsets_rrsigs:
            rd = kwargs.get('recurse', False)
            do = kwargs.get('dnssec', False)
            cd = kwargs.get('nocheck', False)
            self._store_responses(name_obj, name, rdtype, rd, do, cd, False, responses)

        return responses, rrsets_rrsigs, nsec_rrsets_rrsigs

    def _root_responsive(self, proto):
        if proto is None:
            root_ips = ROOT_NS_IPS
        elif proto == 4:
            root_ips = ROOT_NS_IPS_4
        else:
            root_ips = ROOT_NS_IPS_6
        return util.dnsutil.query_for_first_match(root_ips, dns.name.root, dns.rdatatype.NS, timeout=2.0, lifetime=2.0, downgrade_on_timeout=False)[0]

_analysis_params = {}

def _analyze(name):
    global _analysis_params
    name = dns.name.from_text(name)
    if [d for d in settings.BLACKLIST_FROM_REFRESH if name.is_subdomain(d)]:
        return
    name_obj = DomainNameAnalysis.objects.latest(name)
    if name_obj and (name_obj.nxdomain or name_obj.empty_nonterminal or not name_obj.rdtypes()):
        return

    c = Crawler(name, now(), **_analysis_params)
    try:
        c.crawl()
    except:
        pass

class BulkAnalyst:
    def __init__(self, num_processes=10):
        global _analysis_params
        self.logger = logging.getLogger('dnsviz.analyst')

        self.pool = multiprocessing.Pool(num_processes)
        self.interrupt_event = multiprocessing.Event()
        _analysis_params['interrupt_event'] = self.interrupt_event

    def analyze_all(self):
        self._process_all(_analyze)

    def analyze_names(self, names):
        self._process_names(names, _analyze)

    def _process_all(self, func):
        all_names = DomainName.objects.values_list('name', flat=True)
        return self._process_names(all_names, func)

    def _process_names(self, names, func):
        try:
            if names:
                self.interrupt_event.clear()
                self.pool.map_async(func, names)
        except KeyboardInterrupt:
            sys.stderr.write('Interrupting...\n')

        try:
            self.pool.close()
            self.pool.join()
        except KeyboardInterrupt:
            self.interrupt_event.set()
            sys.stderr.write('Interrupting...\n')
            try:
                self.pool.terminate()
                self.pool.join()
            except KeyboardInterrupt:
                sys.stderr.write('Terminating...\n')

    def refresh_scheduled(self):
        self.interrupt_event.clear()
        wait_time = 60
        last_refresh_offsets = {}
        last_stats = 0
        stats_interval = 600
        try:
            while True:
                refresh_intervals = set(DomainName.objects.filter(refresh_interval__isnull=False).values_list('refresh_interval', flat=True).distinct())
                for i in set(last_refresh_offsets).union(refresh_intervals):
                    if i not in last_refresh_offsets:
                        last_refresh_offsets[i] = None
                    if i not in refresh_intervals:
                        del last_refresh_offsets[i]

                # at the start of every loop check for names being crawled
                start = int(time.time())
                timestamp = now()
                tot = 0
                for interval, last_offset in last_refresh_offsets.items():
                    offset = DomainName.objects.offset_for_interval(interval)
                    if last_offset is not None:
                        names_to_refresh = set(DomainName.objects.names_to_refresh(interval, offset, last_offset).values_list('name', flat=True))
                        self.pool.map_async(_analyze, names_to_refresh)
                    last_refresh_offsets[interval] = offset

                end = int(time.time())
                elapsed = end - start
                if elapsed < wait_time:
                    time.sleep(wait_time - elapsed)
                time_since_stats = end - last_stats
                if time_since_stats >= stats_interval:
                    last_stats = end
                    print '%s: (taskqueue: %d) ' % (now(), self.pool._taskqueue.qsize())
                    #print '%s: (taskqueue: %d; inqueue: %d; outqueue: %d) ' % (now(), self.pool._taskqueue.qsize(), self.pool._inqueue.qsize(), self.pool._outqueue.qsize())

        except KeyboardInterrupt:
            sys.stderr.write('Interrupting...\n')

        try:
            self.pool.close()
            self.pool.join()
        except KeyboardInterrupt:
            self.interrupt_event.set()
            sys.stderr.write('Interrupting...\n')
            try:
                self.pool.terminate()
                self.pool.join()
            except KeyboardInterrupt:
                sys.stderr.write('Terminating...\n')

def main():
    global _analysis_params

    def file_iter(filename):
        with open(filename) as fh:
            for line in fh:
                yield line.rstrip()

    def usage():
        print '''
Usage: %s [ -t num_threads ] [ -o ] ( -f file )

Options:
    -t num_threads - parallelize with num_threads threads
    -F             - force refresh of names
    -A             - force refresh of ancestry of names
    -D             - force refresh of dependency of names
    -r             - refresh names periodically (loops forever)
    -a             - refresh all names now
    -f filename    - read names from file
    -d level       - set debug level to level
''' % sys.argv[0]

    import getopt
    import os
    try:
        opts, args = getopt.getopt(sys.argv[1:], 't:FADraf:d:')
    except getopt.GetoptError:
        usage()
        sys.exit(1)

    opts = dict(opts)
    val = int(opts.get('-d', 1))
    if val > 2:
        debug_level = logging.DEBUG
    elif val > 1:
        debug_level = logging.INFO
    elif val > 0:
        debug_level = logging.WARNING
    else:
        debug_level = logging.ERROR
    logger = logging.getLogger('dnsviz.analyst')
    handler = logging.StreamHandler()
    handler.setLevel(debug_level)
    logger.addHandler(handler)

    num_processes = int(opts.get('-t', 1))
    if num_processes < 1:
        num_processes = 1

    _analysis_params['force'] = '-F' in opts
    _analysis_params['force_ancestry'] = '-A' in opts
    _analysis_params['client_v4'] = util.dnsutil.get_client_address('198.41.0.4')
    _analysis_params['client_v6'] = util.dnsutil.get_client_address('2001:503:ba3e::2:30')

    analyst = BulkAnalyst(num_processes)
    if '-r' in opts:
        analyst.refresh_scheduled()
    elif '-a' in opts:
        analyst.analyze_all()
    else:
        if '-f' in opts:
            names = file_iter(opts['-f'])
        else:
            names = args
        analyst.analyze_names(names)

if __name__ == "__main__":
    main()
