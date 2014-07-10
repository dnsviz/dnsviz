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

import socket
import struct
import threading
import time

#XXX evaluate whether or not sys and traceback should be used for warning messages in this module
import sys
import traceback

import dns.exception, dns.flags, dns.ipv4, dns.message, dns.name, dns.query, dns.rcode, \
        dns.rdataclass, dns.rdatatype, dns.resolver

def directed_query(server_ip, qname, rdtype, rdclass=dns.rdataclass.IN, tcp=False, port=53,
        recurse=False, dnssec=False, nocheck=False, ignore_truncation=False,
        initial_payload=4096, reduced_payload=512,
        timeout=3.0, lifetime=15.0, downgrade_on_timeout=True):

    if downgrade_on_timeout:
        assert lifetime >= timeout * 5, 'If downgrade_on_timeout, lifetime must be greater than three times timeout!'

    if isinstance(qname, (str, unicode)):
        qname = dns.name.from_text(qname, None)
    if isinstance(rdtype, str):
        rdtype = dns.rdatatype.from_text(rdtype)
    if isinstance(rdclass, str):
        rdclass = dns.rdataclass.from_text(rdclass)

    start = time.time()
    request = dns.message.make_query(qname, rdtype, rdclass)
    response = None

    if recurse:
        request.flags |= dns.flags.RD
    else:
        request.flags &= ~dns.flags.RD

    # try using EDNS first
    request.use_edns(payload=initial_payload)

    # if DNSSEC is desired, set the DO bit
    if dnssec:
        request.want_dnssec(True)

    # if we want to do our own check for
    # validation
    if nocheck:
        request.flags |= dns.flags.CD

    #print 'Querying %s for %s/%s' % (server_ip, qname, dns.rdatatype.to_text(rdtype))

    backoff = 0.10
    num_timeouts = 0
    while True:
        response = None
        connect_timeout = _compute_timeout(start, timeout, lifetime)
        try:
            if tcp:
                response = dns.query.tcp(request, server_ip,
                                        connect_timeout, port)
            else:
                response = dns.query.udp(request, server_ip,
                                        connect_timeout, port)
        except (socket.error, dns.query.UnexpectedSource, EOFError):
            # network-related error, try again
            pass

        except (struct.error, dns.exception.FormError, dns.exception.SyntaxError):
            # truncated, try again with TCP
            if not tcp and not ignore_truncation:
                tcp = True
            # some servers don't handle EDNS well and add extra
            # data at the end of the packet.  Try again without
            # EDNS
            elif request.edns >= 0:
                request.want_dnssec(False)
                request.use_edns(False)
            else:
                raise

        except dns.exception.Timeout:
            num_timeouts += 1
            # after two timeouts, reduce the payload size to 512.
            # Perhaps it is timing out because the large packet is
            # unable to pass through (PMTU issues)
            if num_timeouts >= 2 and \
                    request.edns >= 0 and request.payload > reduced_payload:
                request.payload = reduced_payload
            # after four timeouts with low payload size try removing DNSSEC
            # to see if we get a response
            elif num_timeouts >= 4 and \
                    downgrade_on_timeout:
                request.want_dnssec(False)
                request.use_edns(False)

        if response is not None:
            # if the request was truncated, try again using tcp
            if (response.flags & dns.flags.TC) and not ignore_truncation:
                tcp = True

            else:
                rcode = response.rcode()
                # return the response, if a valid rcode from server
                if rcode in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN, dns.rcode.REFUSED):
                    return response
                # retry again without EDNS, if EDNS was used before
                elif request.edns >= 0:
                    request.want_dnssec(False)
                    request.use_edns(False)
                else:
                    # if some other error we don't recognize, then return
                    return response

        # sleep a bit before retrying the server
        connect_timeout = _compute_timeout(start, timeout, lifetime)
        sleep_time = min(connect_timeout, backoff)
        backoff *= 2
        time.sleep(sleep_time)

def _compute_timeout(start, timeout, lifetime):
    now = time.time()
    if now < start:
        if start - now > 1:
            # Time going backwards is bad.  Just give up.
            raise dns.exception.Timeout
        else:
            # Time went backwards, but only a little.  This can
            # happen, e.g. under vmware with older linux kernels.
            # Pretend it didn't happen.
            now = start
    duration = now - start
    if duration >= lifetime:
        raise dns.exception.Timeout
    return min(lifetime - duration, timeout)

def non_authoritative_referral_filter(qname, rdtype, response):
    return isinstance(response, dns.message.Message) and not (response.flags & dns.flags.AA) and \
            response.get_rrset(response.authority, qname, dns.rdataclass.IN, dns.rdatatype.NS) is not None

def authoritative_answer_filter(qname, rdtype, response):
    return all_authoritative_answer(qname, rdtype, (response,))

def nxdomain_filter(qname, rdtype, response):
    return all_nxdomain(qname, rdtype, (response,))

def noerror_no_answer_filter(qname, rdtype, response):
    return all_noerror_no_answer(qname, rdtype, (response,))

def nxdomain_or_noerror_no_answer_filter(qname, rdtype, response):
    return nxdomain_filter(qname, rdtype, response) or \
            noerror_no_answer_filter(qname, rdtype, response)

def all_authoritative_answer(qname, rdtype, responses):
    val = None
    for response in responses:
        if not isinstance(response, dns.message.Message):
            continue
        if response.flags & dns.flags.AA:
            if rdtype == dns.rdatatype.ANY and filter(lambda x: x.name == qname, response.answer):
                if val is None:
                    val = True
            if filter(lambda x: x.name == qname and x.rdtype in (rdtype, dns.rdatatype.CNAME), response.answer):
                if val is None:
                    val = True
        else:
            val = False

    if val is None:
        val = False
    return val

def all_nxdomain(qname, rdtype, responses):
    val = None
    for response in responses:
        if not isinstance(response, dns.message.Message):
            continue
        if response.rcode() == dns.rcode.NXDOMAIN:
            if val is None:
                val = True
        else:
            val = False

    if val is None:
        val = False
    return val

def any_nxdomain(qname, rdtype, responses):
    for response in responses:
        if not isinstance(response, dns.message.Message):
            continue
        if response.rcode() == dns.rcode.NXDOMAIN:
            return True
    return False

def all_noerror_no_answer(qname, rdtype, responses):
    val = None
    for response in responses:
        if not isinstance(response, dns.message.Message):
            continue
        try:
            soa_rrset = filter(lambda x: x.rdclass == dns.rdataclass.IN and x.rdtype == dns.rdatatype.SOA, response.authority)[0]
        except IndexError:
            soa_rrset = None
        if response.rcode() == dns.rcode.NOERROR and (response.flags & dns.flags.AA) and not response.answer:
            if soa_rrset is not None:
                if not (soa_rrset.name != qname and qname.is_subdomain(soa_rrset.name)):
                    val = False
            if val is None:
                val = True
        else:
            val = False

    if val is None:
        val = False
    return val

def any_noerror_no_answer(responses):
    for response in responses:
        if not isinstance(response, dns.message.Message):
            continue
        try:
            soa_rrset = filter(lambda x: x.rdclass == dns.rdataclass.IN and x.rdtype == dns.rdatatype.SOA, response.authority)[0]
        except IndexError:
            soa_rrset = None
        if response.rcode() == dns.rcode.NOERROR and (response.flags & dns.flags.AA) and not response.answer:
            if soa_rrset is not None and \
                        not (soa_rrset.name != qname and qname.is_subdomain(soa_rrset.name)):
                    continue
            return True
    return False

def valid_responses(responses):
    return [x for x in responses if isinstance(x, dns.message.Message) and x.rcode() in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN)]

def query_for_first_match(server_ips, qname, rdtype, filter_func=None, halt_func=None, **kwargs):
    query_kwargs = { 'timeout': 2.0, 'lifetime': 10.0 }
    query_kwargs.update(**kwargs)

    response = None
    server_ip = None

    # query each server
    for server_ip in server_ips:
        try:
            response = directed_query(server_ip, qname, rdtype, **query_kwargs)
            if filter_func is None or filter_func(qname, rdtype, response):
                return True, response, server_ip
            if halt_func is not None and halt_func(qname, rdtype, response):
                return False, response, server_ip

        except (dns.exception.Timeout, dns.exception.FormError), e:
            #sys.stderr.write('%s raised while querying %s for %s %s: %s;\n' % \
            #        (e.__class__, server_ip, qname, dns.rdatatype.to_text(rdtype), e))
            if response is None:
                response = e.__class__

    return False, response, server_ip

class QueryThread(threading.Thread):
    def __init__(self, server_ip, client, qname, rdtype, response_list, **kwargs):
        threading.Thread.__init__(self)

        self.server_ip = server_ip
        self.client = client
        self.qname = qname
        self.rdtype = rdtype
        self.response_list = response_list
        self.kwargs = kwargs

    def run(self):
        try:
            response = directed_query(self.server_ip, self.qname, self.rdtype, **self.kwargs)
            self.response_list.append(((self.server_ip, self.client), response))
        except (dns.exception.Timeout, dns.exception.FormError), e:
            self.response_list.append(((self.server_ip, self.client), e.__class__))
            #sys.stderr.write('%s raised while querying %s for %s %s: %s;\n' % \
            #        (e.__class__, self.server_ip, self.qname, dns.rdatatype.to_text(self.rdtype), e))
        except:
            sys.stderr.write('Error while querying %s for %s %s:\n%s' % (self.server_ip, self.qname, dns.rdatatype.to_text(self.rdtype), traceback.format_exc()))

def get_client_address(server):
    try:
        dns.ipv4.inet_aton(server)
        af = socket.AF_INET
    except:
        af = socket.AF_INET6
    s = socket.socket(af, socket.SOCK_DGRAM)
    try:
        s.connect((server, 53))
    except socket.error:
        return None
    return s.getsockname()[0]

def query_for_all(server_ips, qname, rdtype, client_v4=None, client_v6=None, thread_count=None, **kwargs):
    responses = []

    if client_v4 is None:
        client_v4 = get_client_address('198.41.0.4')
        client_v6 = get_client_address('2001:503:ba3e::2:30')

    if not thread_count:
        for server_ip in server_ips:
            try:
                dns.ipv4.inet_aton(server_ip)
                client = client_v4
            except:
                if client_v6 is None:
                    continue
                client = client_v6
            try:
                response = directed_query(server_ip, qname, rdtype, **kwargs)
                responses.append(((server_ip, client), response))
            except (dns.exception.Timeout, dns.exception.FormError), e:
                responses.append(((server_ip, client), e.__class__))
                #sys.stderr.write('%s raised while querying %s for %s %s: %s;\n' % \
                #        (e.__class__, server_ip, qname, dns.rdatatype.to_text(rdtype), e))
            except:
                sys.stderr.write('Error while querying %s for %s %s:\n%s' % (server_ip, qname, dns.rdatatype.to_text(rdtype), traceback.format_exc()))
    else:
        threads = []
        for server_ip in server_ips:
            try:
                dns.ipv4.inet_aton(server_ip)
                client = client_v4
            except:
                if client_v6 is None:
                    continue
                client = client_v6
            thread = QueryThread(server_ip, client, qname, rdtype, responses, **kwargs)
            while True:
                for t in threads:
                    if not t.isAlive():
                        threads.remove(t)
                if len(threads) < thread_count:
                    break
                time.sleep(0.5)
            thread.start()
            threads.append(thread)
        for t in threads:
            t.join()

    return responses

class TCPTestThread(threading.Thread):
    def __init__(self, server_ip, response_set, timeout=3, port=53):
        threading.Thread.__init__(self)

        self.server_ip = server_ip
        self.timeout = timeout
        self.port = port
        self.response_set = response_set
        try:
            dns.ipv4.inet_aton(self.server_ip)
            self.af = socket.AF_INET
        except:
            self.af = socket.AF_INET6

    def run(self):
        try:
            s = socket.socket(self.af, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.server_ip, self.port))
            self.response_set.add(self.server_ip)
        except (socket.error, socket.timeout):
            pass

def tcp_test_servers(server_ips, timeout, thread_count=None):
    tcp_available = set()

    if not thread_count:
        for server_ip in server_ips:
            try:
                try:
                    dns.ipv4.inet_aton(server_ip)
                    af = socket.AF_INET
                except:
                    af = socket.AF_INET6
                s = socket.socket(af, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((server_ip, port))
                tcp_available.add(server_ip)
            except (socket.error, socket.timeout):
                pass

    else:
        threads = []
        for server_ip in server_ips:
            thread = TCPTestThread(server_ip, tcp_available, timeout)
            while True:
                for t in threads:
                    if not t.isAlive():
                        threads.remove(t)
                if len(threads) < thread_count:
                    break
                time.sleep(0.5)
            thread.start()
            threads.append(thread)
        for t in threads:
            t.join()

    return tcp_available

def aggregate_responses(qname, rdtype, responses, section_name='answer'):
    rrsets_rrsigs = []
    neg_responses = { 'NXDOMAIN': [], 'Empty Answer': [] }
    dname_rrsets_rrsigs = []
    nsec_rrsets_rrsigs = []

    # query each server
    for (server_ip, client), response in responses:
        if not isinstance(response, dns.message.Message):
            continue

        section = getattr(response, section_name)
        try:
            i = 0
            qname_sought = qname
            while i < 20:
                try:
                    rrset = response.find_rrset(section, qname_sought, dns.rdataclass.IN, rdtype)
                    i = 20
                except KeyError:
                    #XXX fix this cleaner later
                    if rdtype in (dns.rdatatype.DNSKEY, dns.rdatatype.SOA):
                        raise

                    rrset = response.find_rrset(section, qname_sought, dns.rdataclass.IN, dns.rdatatype.CNAME)
                    qname_sought = rrset[0].target

                tuple_with_this_rrset = None

                try:
                    tuple_with_this_rrset = filter(lambda x: x[0] == rrset and x[0].ttl == rrset.ttl, rrsets_rrsigs)[0]
                except IndexError:
                    tuple_with_this_rrset = (rrset, set(), [])
                    rrsets_rrsigs.append(tuple_with_this_rrset)
                tuple_with_this_rrset[1].add((server_ip, client))

                try:
                    rrsig_rrset = response.find_rrset(section, rrset.name, dns.rdataclass.IN, dns.rdatatype.RRSIG, rrset.rdtype)
                    for rrsig in rrsig_rrset:
                        try:
                            tuple_with_this_rrsig = filter(lambda x: x[0] == rrsig, tuple_with_this_rrset[2])[0]
                        except IndexError:
                            tuple_with_this_rrsig = (rrsig, rrsig_rrset.ttl, set())
                            tuple_with_this_rrset[2].append(tuple_with_this_rrsig)
                        tuple_with_this_rrsig[2].add((server_ip, client))
                        
                except KeyError:
                    pass

                i += 1

        except KeyError:
            pass

        if response.rcode() == dns.rcode.NXDOMAIN:
            neg_responses['NXDOMAIN'].append((server_ip, client))
        elif not section:
            neg_responses['Empty Answer'].append((server_ip, client))

        if qname != dns.name.root:
            for rrset in filter(lambda x: x.rdtype == dns.rdatatype.DNAME, section):
                if not qname.parent().is_subdomain(rrset.name):
                    continue

                tuple_with_this_rrset = None

                try:
                    tuple_with_this_rrset = filter(lambda x: x[0] == rrset and x[0].ttl == rrset.ttl, dname_rrsets_rrsigs)[0]
                except IndexError:
                    tuple_with_this_rrset = (rrset, set(), [])
                    dname_rrsets_rrsigs.append(tuple_with_this_rrset)
                tuple_with_this_rrset[1].add((server_ip, client))

                try:
                    rrsig_rrset = response.find_rrset(section, rrset.name, dns.rdataclass.IN, dns.rdatatype.RRSIG, rrset.rdtype)
                    for rrsig in rrsig_rrset:
                        try:
                            tuple_with_this_rrsig = filter(lambda x: x[0] == rrsig, tuple_with_this_rrset[2])[0]
                        except IndexError:
                            tuple_with_this_rrsig = (rrsig, rrsig_rrset.ttl, set())
                            tuple_with_this_rrset[2].append(tuple_with_this_rrsig)
                        tuple_with_this_rrsig[2].add((server_ip, client))
                        
                except KeyError:
                    pass

        # check NSEC/NSEC3 RRs
        #XXX make this consider TTLs
        nsec_rrsets = filter(lambda x: x.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3), response.authority)

        if nsec_rrsets:
            nsec_tuples = [(rrset.name, rrset, []) for rrset in nsec_rrsets]
            nsec_tuples.sort()
            for nsec_tuple in nsec_tuples:
                try:
                    rrsig_rrset = response.find_rrset(response.authority, nsec_tuple[1].name, dns.rdataclass.IN, dns.rdatatype.RRSIG, nsec_tuple[1].rdtype)
                    for rrsig in rrsig_rrset:
                        nsec_tuple[2].append((rrsig, rrsig_rrset.ttl))
                    nsec_tuple[2].sort()
                except KeyError:
                    pass

            try:
                tuple_with_this_rrset = filter(lambda x: x[0] == nsec_tuples, nsec_rrsets_rrsigs)[0]
            except IndexError:
                tuple_with_this_rrset = (nsec_tuples, set())
                nsec_rrsets_rrsigs.append(tuple_with_this_rrset)
            tuple_with_this_rrset[1].add((server_ip, client))

    return rrsets_rrsigs, neg_responses, dname_rrsets_rrsigs, nsec_rrsets_rrsigs

def aliases_from_aggregated_responses(qname, rrsets_rrsigs):
    return filter(lambda x: x[0].rdtype == dns.rdatatype.CNAME and x[0].name == qname, rrsets_rrsigs)

def cname_for_dname(qname, dname_rrset):
    assert qname.parent().is_subdomain(dname_rrset.name)
    return dns.name.Name(qname.labels[:-len(dname_rrset.name)] + dname_rrset[0].target.labels)

def ips_for_name_from_resolver(qname):
    ip_mapping = {}

    for dtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
        ip_mapping[dtype] = set()
        try:
            a_rrset = dns.resolver.query(qname, dtype).rrset
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except dns.exception.DNSException, e:
            #sys.stderr.write('Unable to get an authoritative response for %s/%s; %s encountered\n' % (qname, dns.rdatatype.to_text(dtype), e.__class__))
            continue

        for a_rr in a_rrset:
            ip_mapping[dtype].add(a_rr.to_text())

    return ip_mapping

def ips_for_ns_rrset_from_resolver(qname, response):
    ip_mapping = {}
    try:
        ns_rrset = response.find_rrset(response.authority, qname, dns.rdataclass.IN, dns.rdatatype.NS)
    except KeyError:
        try:
            ns_rrset = response.find_rrset(response.answer, qname, dns.rdataclass.IN, dns.rdatatype.NS)
        except KeyError:
            return ip_mapping

    # iterate over each RR in the RR RRset
    for ns_rr in ns_rrset:
        target = ns_rr.target

        ip_mapping[target] = set()
        for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            try:
                a_rrset = dns.resolver.query(ns_rr.target, rdtype).rrset
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                continue
            except dns.exception.DNSException, e:
                #sys.stderr.write('Unable to get an authoritative response for %s/%s; %s encountered\n' % (qname, dns.rdatatype.to_text(rdtype), e.__class__))
                continue

            ip_mapping[target].update([a_rr.to_text() for a_rr in a_rrset])

    return ip_mapping

def ips_for_ns_rrset_from_additional(qname, response, bailiwick=None):
    ip_mapping = {}

    try:
        ns_rrset = response.find_rrset(response.answer, qname, dns.rdataclass.IN, dns.rdatatype.NS)
    except KeyError:
        try:
            ns_rrset = response.find_rrset(response.authority, qname, dns.rdataclass.IN, dns.rdatatype.NS)
        except KeyError:
            return ip_mapping

    # iterate over each RR in the RR RRset
    for ns_rr in ns_rrset:
        if bailiwick is not None and not ns_rr.target.subdomain(bailiwick):
            continue

        ip_mapping[ns_rr.target] = set()
        for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            try:
                a_rrset = response.find_rrset(response.additional, ns_rr.target, dns.rdataclass.IN, rdtype)
            except KeyError:
                continue

            ip_mapping[ns_rr.target].update([a_rr.to_text() for a_rr in a_rrset])

    return ip_mapping

def server_version(server_ip):
    qname = dns.name.from_text('version.bind.', None)
    try:
        response = directed_query(server_ip, qname, dns.rdatatype.TXT, dns.rdataclass.CH)
        txt_rrset = response.find_rrset(response.answer, qname, dns.rdataclass.CH, dns.rdatatype.TXT)
        return txt_rrset[0].to_text().strip('"')
    except (dns.exception.Timeout, dns.exception.FormError, KeyError):
        pass

    return ''

def server_fingerprint(server_ip):
    vendor = None
    product = None
    version = None
    other = None

    fpdns = subprocess.Popen(['fpdns', '-s', '-S', '|', server_ip], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
    fpdns.wait()
    if fpdns.returncode != 0:
        sys.stderr.write('fpdns error (%s): %s;\n' % (server_ip, fpdns.stdout.read().rstrip()))
        return vendor, product, version, other

    dst_ip, output = fpdns.stdout.read().rstrip().split(None, 1)
    vals = output.split('|')
    if not vals:
        vals.append('No match found')

    vendor = vals.pop(0)
    if vals:
        product = vals.pop(0)
    if vals:
        version = vals.pop(0)
    if vals:
        other = vals.pop(0)

    return vendor, product, version, other

def find_max_payload(server, qname, rdtype, floor, ceiling, actual, **kwargs):
    ''' floor is the highest value for which we know it works
        ceiling is the lowest value for which we know it doesn't work
    '''
    if ceiling - floor <= 1:
        return actual, floor, None
    mid = floor + ((ceiling - floor) / 2)
    try:
        try:
            response = directed_query(server, qname, rdtype, initial_payload=mid, reduced_payload=mid,
                    timeout=1.0, lifetime=1.0, ignore_truncation=True, downgrade_on_timeout=False, **kwargs)
            actual = len(response.to_wire())
            # if the entire response fit (i.e., the TC bit was not set), then just quit
            # because we're not going to benefit from testing higher payload sizes
            if not response.flags & dns.flags.TC:
                return actual, ceiling, None
            return find_max_payload(server, qname, rdtype, mid, ceiling, actual, **kwargs)
        except (dns.exception.FormError, dns.message.UnknownHeaderField), e:
            return mid, ceiling, e
    except dns.exception.Timeout:
        return find_max_payload(server, qname, rdtype, floor, mid, actual, **kwargs)

def name_ancestry(name):
    name_list = [name]
    try:
        n = name.parent()
        while True:
            name_list.append(n)
            n = n.parent()
    except dns.name.NoParent:
        pass
    return name_list
