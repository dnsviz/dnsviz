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

import binascii
import bisect
import copy
import errno
import io
import socket
import struct
import time

# minimal support for python2.6
try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict

# python3/python2 dual compatibility
try:
    import queue
except ImportError:
    import Queue as queue

import dns.edns, dns.exception, dns.flags, dns.message, dns.rcode, \
        dns.rdataclass, dns.rdatatype

from .ipaddr import *
from .response import *
from . import transport
from .format import latin1_binary_to_string as lb2s

RETRY_CAUSE_NETWORK_ERROR = RESPONSE_ERROR_NETWORK_ERROR = 1
RETRY_CAUSE_FORMERR = RESPONSE_ERROR_FORMERR = 2
RETRY_CAUSE_TIMEOUT = RESPONSE_ERROR_TIMEOUT = 3
RETRY_CAUSE_OTHER = RESPONSE_ERROR_OTHER = 4
RETRY_CAUSE_TC_SET = 5
RETRY_CAUSE_RCODE = RESPONSE_ERROR_INVALID_RCODE = 6
RETRY_CAUSE_DIAGNOSTIC = 7
retry_causes = {
        RETRY_CAUSE_NETWORK_ERROR: 'NETWORK_ERROR',
        RETRY_CAUSE_FORMERR: 'FORMERR',
        RETRY_CAUSE_TIMEOUT: 'TIMEOUT',
        RETRY_CAUSE_OTHER: 'ERROR',
        RETRY_CAUSE_TC_SET: 'TC',
        RETRY_CAUSE_RCODE: 'INVALID_RCODE',
        RETRY_CAUSE_DIAGNOSTIC: 'DIAGNOSTIC'
}
retry_cause_codes = {
        'NETWORK_ERROR': RETRY_CAUSE_NETWORK_ERROR,
        'FORMERR': RETRY_CAUSE_FORMERR,
        'TIMEOUT': RETRY_CAUSE_TIMEOUT,
        'ERROR': RETRY_CAUSE_OTHER,
        'TC': RETRY_CAUSE_TC_SET,
        'INVALID_RCODE': RETRY_CAUSE_RCODE,
        'DIAGNOSTIC': RETRY_CAUSE_DIAGNOSTIC,
}
response_errors = {
        RESPONSE_ERROR_NETWORK_ERROR: retry_causes[RETRY_CAUSE_NETWORK_ERROR],
        RESPONSE_ERROR_FORMERR: retry_causes[RETRY_CAUSE_FORMERR],
        RESPONSE_ERROR_TIMEOUT: retry_causes[RETRY_CAUSE_TIMEOUT],
        RESPONSE_ERROR_OTHER: retry_causes[RETRY_CAUSE_OTHER],
        RESPONSE_ERROR_INVALID_RCODE: retry_causes[RETRY_CAUSE_RCODE]
}
response_error_codes = {
        retry_causes[RETRY_CAUSE_NETWORK_ERROR]: RESPONSE_ERROR_NETWORK_ERROR,
        retry_causes[RETRY_CAUSE_FORMERR]: RESPONSE_ERROR_FORMERR,
        retry_causes[RETRY_CAUSE_TIMEOUT]: RESPONSE_ERROR_TIMEOUT,
        retry_causes[RETRY_CAUSE_OTHER]: RESPONSE_ERROR_OTHER,
        retry_causes[RETRY_CAUSE_RCODE]: RESPONSE_ERROR_INVALID_RCODE
}

RETRY_ACTION_NO_CHANGE = 1
RETRY_ACTION_USE_TCP = 2
RETRY_ACTION_USE_UDP = 3
RETRY_ACTION_SET_FLAG = 4
RETRY_ACTION_CLEAR_FLAG = 5
RETRY_ACTION_DISABLE_EDNS = 6
RETRY_ACTION_CHANGE_UDP_MAX_PAYLOAD = 7
RETRY_ACTION_SET_EDNS_FLAG = 8
RETRY_ACTION_CLEAR_EDNS_FLAG = 9
RETRY_ACTION_ADD_EDNS_OPTION = 10
RETRY_ACTION_REMOVE_EDNS_OPTION = 11
RETRY_ACTION_CHANGE_SPORT = 12
RETRY_ACTION_CHANGE_EDNS_VERSION = 13
RETRY_ACTION_UPDATE_DNS_COOKIE = 14
retry_actions = {
        RETRY_ACTION_NO_CHANGE: 'NO_CHANGE',
        RETRY_ACTION_USE_TCP: 'USE_TCP', # implies CHANGE_SPORT
        RETRY_ACTION_USE_UDP: 'USE_UDP', # implies CHANGE_SPORT
        RETRY_ACTION_SET_FLAG: 'SET_FLAG', # implies CHANGE_SPORT
        RETRY_ACTION_CLEAR_FLAG: 'CLEAR_FLAG', # implies CHANGE_SPORT
        RETRY_ACTION_DISABLE_EDNS: 'DISABLE_EDNS', # implies CHANGE_SPORT
        RETRY_ACTION_CHANGE_UDP_MAX_PAYLOAD: 'CHANGE_UDP_MAX_PAYLOAD', # implies USE_UDP, CHANGE_SPORT
        RETRY_ACTION_SET_EDNS_FLAG: 'SET_EDNS_FLAG', # implies CHANGE_SPORT
        RETRY_ACTION_CLEAR_EDNS_FLAG: 'CLEAR_EDNS_FLAG', # implies CHANGE_SPORT
        RETRY_ACTION_ADD_EDNS_OPTION: 'ADD_EDNS_OPTION', # implies CHANGE_SPORT
        RETRY_ACTION_REMOVE_EDNS_OPTION: 'REMOVE_EDNS_OPTION', # implies CHANGE_SPORT
        RETRY_ACTION_CHANGE_SPORT: 'CHANGE_SPORT',
        RETRY_ACTION_CHANGE_EDNS_VERSION: 'CHANGE_EDNS_VERSION', # implies CHANGE_SPORT
        RETRY_ACTION_UPDATE_DNS_COOKIE: 'UPDATE_DNS_COOKIE', # implies CHANGE_SPORT
}
retry_action_codes = {
        'NO_CHANGE': RETRY_ACTION_NO_CHANGE,
        'USE_TCP': RETRY_ACTION_USE_TCP,
        'USE_UDP': RETRY_ACTION_USE_UDP,
        'SET_FLAG': RETRY_ACTION_SET_FLAG,
        'CLEAR_FLAG': RETRY_ACTION_CLEAR_FLAG,
        'DISABLE_EDNS': RETRY_ACTION_DISABLE_EDNS,
        'CHANGE_UDP_MAX_PAYLOAD': RETRY_ACTION_CHANGE_UDP_MAX_PAYLOAD,
        'SET_EDNS_FLAG': RETRY_ACTION_SET_EDNS_FLAG,
        'CLEAR_EDNS_FLAG': RETRY_ACTION_CLEAR_EDNS_FLAG,
        'ADD_EDNS_OPTION': RETRY_ACTION_ADD_EDNS_OPTION,
        'REMOVE_EDNS_OPTION': RETRY_ACTION_REMOVE_EDNS_OPTION,
        'CHANGE_SPORT': RETRY_ACTION_CHANGE_SPORT,
        'CHANGE_EDNS_VERSION': RETRY_ACTION_CHANGE_EDNS_VERSION,
        'UPDATE_DNS_COOKIE': RETRY_ACTION_UPDATE_DNS_COOKIE,
}

DNS_COOKIE_NO_COOKIE = 0
DNS_COOKIE_CLIENT_COOKIE_ONLY = 1
DNS_COOKIE_SERVER_COOKIE_FRESH = 2
DNS_COOKIE_SERVER_COOKIE_STATIC = 3
DNS_COOKIE_SERVER_COOKIE_BAD = 4
DNS_COOKIE_IMPROPER_LENGTH = 5

MIN_QUERY_TIMEOUT = 0.1
MAX_CNAME_REDIRECTION = 40

class AcceptResponse(Exception):
    '''An exception raised to stop the process of retrying DNS queries when an
    acceptable response or error condition has been satisfied.'''
    pass

class BindError(Exception):
    '''An error resulting from unsuccessfully trying to bind to an address or port.'''
    pass

class SourceAddressBindError(BindError):
    '''An error resulting from unsuccessfully trying to bind to an address.'''
    pass

class PortBindError(BindError):
    '''An error resulting from unsuccessfully trying to bind to a port.'''
    pass

class NoValidServersToQuery(Exception):
    '''An exception raised when a query is executed and the collective
    transport handlers designated don't have the proper network capabilities to
    issue queries to all the servers.'''
    pass

class DNSQueryRetryAttempt:
    '''A failed attempt at a DNS query that invokes a subsequent retry.'''

    def __init__(self, response_time, cause, cause_arg, action, action_arg):
        self.response_time = response_time
        self.cause = cause
        self.cause_arg = cause_arg
        self.action = action
        self.action_arg = action_arg

    def __repr__(self):
        return '<Retry: %s -> %s>' % (retry_causes[self.cause], retry_actions[self.action])

    def serialize(self):
        '''Return a serialized version of the query.'''

        d = OrderedDict()
        d['time_elapsed'] = int(self.response_time * 1000)
        d['cause'] = retry_causes.get(self.cause, 'UNKNOWN')
        if self.cause_arg is not None:
            if self.cause == RETRY_CAUSE_NETWORK_ERROR:
                errno_name = errno.errorcode.get(self.cause_arg, None)
                if errno_name is not None:
                    d['cause_arg'] = errno_name
            else:
                d['cause_arg'] = self.cause_arg
        d['action'] = retry_actions.get(self.action, 'UNKNOWN')
        if self.action_arg is not None:
            d['action_arg'] = self.action_arg
        return d

    @classmethod
    def deserialize(cls, d):
        '''Return an instance built from a serialized version of the
        DNSQueryRetryAttempt.'''

        # compatibility with version 1.0
        if 'response_time' in d:
            response_time = d['response_time']
        else:
            response_time = d['time_elapsed']/1000.0
        cause = retry_cause_codes[d['cause']]
        if 'cause_arg' in d:
            if cause == RETRY_CAUSE_NETWORK_ERROR:
                # compatibility with version 1.0
                if isinstance(d['cause_arg'], int):
                    cause_arg = d['cause_arg']
                else:
                    if hasattr(errno, d['cause_arg']):
                        cause_arg = getattr(errno, d['cause_arg'])
                    else:
                        cause_arg = None
            else:
                cause_arg = d['cause_arg']
        else:
            cause_arg = None
        action = retry_action_codes[d['action']]
        if 'action_arg' in d:
            action_arg = d['action_arg']
        else:
            action_arg = None
        return DNSQueryRetryAttempt(response_time, cause, cause_arg, action, action_arg)

class DNSResponseHandlerFactory(object):
    '''A factory class that holds arguments to create a DNSResponseHandler instance.'''

    def __init__(self, cls, *args, **kwargs):
        self._cls = cls
        self._args = args
        self._kwargs = kwargs

    def build(self):
        '''Instantiate a DNSResponseHandler with the args and kwargs saved with the
        initialization of this factory.'''

        obj = self._cls.__new__(self._cls, *self._args, __instantiate=True, **self._kwargs)
        obj.__init__(*self._args, **self._kwargs)
        return obj

class DNSResponseHandler(object):
    '''A base class for handling DNS responses (or exceptions) arising from a
    query attempt.'''

    def __new__(cls, *args, **kwargs):
        '''Redirect the instantiation of a DNSResponseHandler to create instead a Factory,
        from which a DNSResponseHandler in turn is built.'''


        if kwargs.pop('__instantiate', None):
            return super(DNSResponseHandler, cls).__new__(cls)
        return DNSResponseHandlerFactory(cls, *args, **kwargs)

    def set_context(self, params, history, request):
        '''Set local parameters pertaining to DNS query.'''

        self._params = params
        self._history = history
        self._request = request

    def handle(self, response_wire, response, response_time):
        '''Handle a DNS response.  The response might be an actual DNS message or some type
        of exception that was raised during query.'''

        raise NotImplemented

    def _get_retry_qty(self, cause):
        '''Return the number of retries associated with the DNS query, optionally limited to
        those with a given cause.'''

        if cause is None:
            return len(self._history)

        total = 0
        for i in range(len(self._history) - 1, -1, -1):
            if self._history[i].cause == cause:
                total += 1
            else:
                break
        return total

    def _get_num_timeouts(self, response):
        '''Return the number of retries attributed to timeouts.'''

        if isinstance(response, dns.exception.Timeout):
            return self._get_retry_qty(RETRY_CAUSE_TIMEOUT) + 1
        return 0

    def _get_num_network_errors(self, response):
        '''Return the number of retries attributed to network errors.'''

        if isinstance(response, (socket.error, EOFError)):
            return self._get_retry_qty(RETRY_CAUSE_NETWORK_ERROR) + 1
        return 0

class ActionIndependentDNSResponseHandler(DNSResponseHandler):
    '''A DNSResponseHandler that is consulted regardless of whether or not
    the response was "handled" previously by another handler.'''

    pass

class RetryOnNetworkErrorHandler(DNSResponseHandler):
    '''Retry the query after some exponentially growing wait period upon a
    network error.'''

    def __init__(self, max_errors):
        self._max_errors = max_errors

    def handle(self, response_wire, response, response_time):
        errors = self._get_num_network_errors(response)
        if errors >= self._max_errors:
            raise AcceptResponse()

        if isinstance(response, (socket.error, EOFError)):
            if hasattr(response, 'errno'):
                errno1 = response.errno
            else:
                errno1 = None
            self._params['wait'] = 0.2*(2**errors)

            if self._params['tcp']:
                action = RETRY_ACTION_CHANGE_SPORT
            else:
                action = RETRY_ACTION_NO_CHANGE
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_NETWORK_ERROR, errno1, action, None)

class UseTCPOnTCFlagHandler(DNSResponseHandler):
    '''Retry with TCP if the TC flag is set in the response.'''

    def handle(self, response_wire, response, response_time):
        # python3/python2 dual compatibility
        if isinstance(response_wire, str):
            map_func = lambda x: ord(x)
        else:
            map_func = lambda x: x

        if response_wire is not None and map_func(response_wire[2]) & 0x02:
            self._params['tcp'] = True
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TC_SET, len(response_wire), RETRY_ACTION_USE_TCP, None)

class DisableEDNSOnFormerrHandler(DNSResponseHandler):
    '''Disable EDNS if there was some type of issue parsing the message.  Some
    servers don't handle EDNS appropriately.'''

    def handle(self, response_wire, response, response_time):
        if isinstance(response, (struct.error, dns.exception.FormError)) and self._request.edns >= 0:
            self._request.use_edns(False)
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_FORMERR, None, RETRY_ACTION_DISABLE_EDNS, None)

class ReduceUDPMaxPayloadOnTimeoutHandler(DNSResponseHandler):
    '''Reduce the EDNS UDP max payload after a given number of timeouts.  Some
    servers attempt to send payloads that exceed their PMTU.'''

    def __init__(self, reduced_payload, timeouts):
        self._reduced_payload = reduced_payload
        self._timeouts = timeouts

    def handle(self, response_wire, response, response_time):
        timeouts = self._get_num_timeouts(response)
        if not self._params['tcp'] and timeouts >= self._timeouts and self._request.payload > self._reduced_payload:
            self._request.use_edns(self._request.edns, self._request.ednsflags,
                    self._reduced_payload, options=self._request.options)
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TIMEOUT, None, RETRY_ACTION_CHANGE_UDP_MAX_PAYLOAD, self._reduced_payload)

class ClearEDNSFlagOnTimeoutHandler(DNSResponseHandler):
    '''Clear an EDNS flag after a given number of timeouts.'''

    def __init__(self, flag, timeouts):
        self._flag = flag
        self._timeouts = timeouts

    def handle(self, response_wire, response, response_time):
        timeouts = self._get_num_timeouts(response)
        if not self._params['tcp'] and timeouts >= self._timeouts and (self._request.ednsflags & self._flag):
            self._request.ednsflags &= ~(self._flag & 0xffff)
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TIMEOUT, None, RETRY_ACTION_CLEAR_EDNS_FLAG, self._flag)

class ChangeEDNSVersionOnTimeoutHandler(DNSResponseHandler):
    '''Change EDNS version after a given number of timeouts.'''

    def __init__(self, edns, timeouts):
        self._edns = edns
        self._timeouts = timeouts

    def handle(self, response_wire, response, response_time):
        timeouts = self._get_num_timeouts(response)
        if not self._params['tcp'] and timeouts >= self._timeouts and self._request.edns != self._edns:
            self._request.use_edns(self._edns, self._request.ednsflags, self._request.payload, options=self._request.options)
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TIMEOUT, None, RETRY_ACTION_CHANGE_EDNS_VERSION, self._edns)

class RemoveEDNSOptionOnTimeoutHandler(DNSResponseHandler):
    '''Remove EDNS option after a given number of timeouts.'''

    def __init__(self, timeouts):
        self._timeouts = timeouts

    def handle(self, response_wire, response, response_time):
        timeouts = self._get_num_timeouts(response)
        if not self._params['tcp'] and timeouts >= self._timeouts and self._request.options:
            opt = self._request.options[0]
            self._request.use_edns(self._request.edns, self._request.ednsflags,
                    self._request.payload, options=self._request.options[1:])
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TIMEOUT, None, RETRY_ACTION_REMOVE_EDNS_OPTION, opt.otype)

class DisableEDNSOnTimeoutHandler(DNSResponseHandler):
    '''Disable EDNS after a given number of timeouts.  Some servers don't
    respond to EDNS queries.'''

    def __init__(self, timeouts):
        self._timeouts = timeouts

    def handle(self, response_wire, response, response_time):
        timeouts = self._get_num_timeouts(response)
        if not self._params['tcp'] and timeouts >= self._timeouts and self._request.edns >= 0:
            self._request.use_edns(False)
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TIMEOUT, None, RETRY_ACTION_DISABLE_EDNS, None)

class SetFlagOnRcodeHandler(DNSResponseHandler):
    '''Set a flag when a given rcode is returned.  One example of the use of
    this class is to determine if the cause of the SERVFAIL is related to DNSSEC
    validation failure by retrying with the CD flag.'''

    def __init__(self, flag, rcode):
        self._flag = flag
        self._rcode = rcode

    def handle(self, response_wire, response, response_time):
        if isinstance(response, dns.message.Message) and response.rcode() == self._rcode and not self._request.flags & self._flag:
            self._request.flags |= self._flag
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_RCODE, self._rcode, RETRY_ACTION_SET_FLAG, self._flag)

class DisableEDNSOnRcodeHandler(DNSResponseHandler):
    '''Disable EDNS if the RCODE in the response indicates that the server
    doesn't implement EDNS.'''

    def handle(self, response_wire, response, response_time):
        if isinstance(response, dns.message.Message) and response.rcode() in (dns.rcode.NOTIMP, dns.rcode.FORMERR, dns.rcode.SERVFAIL) and self._request.edns >= 0:
            self._request.use_edns(False)
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_RCODE, response.rcode(), RETRY_ACTION_DISABLE_EDNS, None)

class RemoveEDNSOptionOnRcodeHandler(DNSResponseHandler):
    '''Remove an EDNS option if the RCODE in the response indicates that the
    server didn't handle the request properly.'''

    def __init__(self, rcode):
        self._rcode = rcode

    def handle(self, response_wire, response, response_time):
        if isinstance(response, dns.message.Message) and response.rcode() == self._rcode and self._request.options:
            opt = self._request.options[0]
            self._request.use_edns(self._request.edns, self._request.ednsflags,
                    self._request.payload, options=self._request.options[1:])
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_RCODE, response.rcode(), RETRY_ACTION_REMOVE_EDNS_OPTION, opt.otype)

class AddServerCookieOnBADCOOKIE(DNSResponseHandler):
    '''Update the DNS Cookie EDNS option with the server cookie when a
    BADCOOKIE rcode is received.'''

    def _add_server_cookie(self, response):
        try:
            client_opt = [o for o in self._request.options if o.otype == 10][0]
        except IndexError:
            return False
        try:
            server_opt = [o for o in response.options if o.otype == 10][0]
        except IndexError:
            return False
        client_cookie = client_opt.data[:8]
        server_cookie1 = client_opt.data[8:]
        server_cookie2 = server_opt.data[8:]
        if server_cookie1 == server_cookie2:
            return False
        client_opt.data = client_cookie + server_cookie2
        return True

    def handle(self, response_wire, response, response_time):
        if isinstance(response, dns.message.Message) and response.rcode() == 23:
            if self._add_server_cookie(response):
                return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_RCODE, response.rcode(), RETRY_ACTION_UPDATE_DNS_COOKIE, None)

class UseUDPOnTimeoutHandler(DNSResponseHandler):
    '''Revert to UDP if TCP connectivity fails.'''

    def __init__(self, timeouts):
        self._timeouts = timeouts

    def handle(self, response_wire, response, response_time):
        timeouts = self._get_num_timeouts(response)
        if timeouts >= self._timeouts and self._params['tcp']:
            self._params['tcp'] = False
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TIMEOUT, None, RETRY_ACTION_USE_UDP, None)

class UseUDPOnNetworkErrorHandler(DNSResponseHandler):
    '''Retry the query after some exponentially growing wait period upon a
    network error.'''

    def __init__(self, max_errors):
        self._max_errors = max_errors

    def handle(self, response_wire, response, response_time):
        errors = self._get_num_network_errors(response)
        if errors >= self._max_errors and self._params['tcp']:
            if hasattr(response, 'errno'):
                errno1 = response.errno
            else:
                errno1 = None
            self._params['tcp'] = False
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_NETWORK_ERROR, errno1, RETRY_ACTION_USE_UDP, None)

        if isinstance(response, (socket.error, EOFError)):
            if hasattr(response, 'errno'):
                errno1 = response.errno
            else:
                errno1 = None
            self._params['wait'] = 0.2*(2**errors)

            if self._params['tcp']:
                action = RETRY_ACTION_CHANGE_SPORT
            else:
                action = RETRY_ACTION_NO_CHANGE
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_NETWORK_ERROR, errno1, action, None)

class PMTUBoundingHandler(DNSResponseHandler):
    # define states
    START = 1
        # if TIMEOUT -> reduce payload -> REDUCED_PAYLOAD
        # else -> return (pass through to other handlers)
    REDUCED_PAYLOAD = 2
        # if TIMEOUT -> return
        # if TC -> set lower bound, use TCP -> TCP_FOR_TRUNCATE
        # if error -> return
        # else -> set lower bound (msg size), use TCP -> TCP_FOR_UPPER_BOUND
    USE_TCP = 3
        # if TIMEOUT -> return
        # if error -> return
        # else -> set upper bound, set increase payload (msg payload - 1) -> TCP_MINUS_ONE
    TCP_MINUS_ONE = 5
        # if TIMEOUT -> reduce payload (upper - lower)/2 -> PICKLE
        # if errors of some sort (maybe with subhandlers?) -> return
        # else -> keep upper bound, return
    PICKLE = 6
        # if upper - lower <= 1 -> use TCP -> TCP_FINAL
        # if TIMEOUT -> set upper bound, reduce payload ((upper - lower)/2 - lower)/2, PICKLE
        # -> TC???
        # if error -> return
        # else -> set lower bound, increase payload (upper - (upper - lower)/2)/2, PICKLE
    TCP_FINAL = 7
    INVALID = 8

    def __init__(self, reduced_payload, initial_timeouts, max_timeouts, bounding_timeout):
        self._reduced_payload = reduced_payload
        self._initial_timeouts = initial_timeouts
        self._max_timeouts = max_timeouts
        self._bounding_timeout = bounding_timeout

        self._lower_bound = None
        self._upper_bound = None
        self._water_mark = None
        self._state = self.START

    def handle(self, response_wire, response, response_time):
        if self._state == self.INVALID:
            return

        # python3/python2 dual compatibility
        if isinstance(response_wire, str):
            map_func = lambda x: ord(x)
        else:
            map_func = lambda x: x

        timeouts = self._get_num_timeouts(response)
        is_timeout = isinstance(response, dns.exception.Timeout)
        is_valid = isinstance(response, dns.message.Message) and response.rcode() in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN)
        is_truncated = response_wire is not None and map_func(response_wire[2]) & 0x02
        if response_wire is not None:
            response_len = len(response_wire)
        else:
            response_len = None

        if self._request.edns >= 0 and \
                (is_timeout or is_valid or is_truncated):
            pass
        else:
            self._state = self.INVALID
            return

        if self._state == self.START:
            if timeouts >= self._initial_timeouts:
                self._lower_bound = self._reduced_payload
                self._upper_bound = self._request.payload - 1
                self._request.use_edns(self._request.edns, self._request.ednsflags,
                        self._reduced_payload, options=self._request.options)
                self._state = self.REDUCED_PAYLOAD
                return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TIMEOUT, None, RETRY_ACTION_CHANGE_UDP_MAX_PAYLOAD, self._reduced_payload)

        elif self._state == self.REDUCED_PAYLOAD:
            if timeouts >= self._max_timeouts:
                self._state == self.INVALID
                return None

            if not is_timeout:
                if is_truncated or is_valid:
                    self._lower_bound = self._water_mark = response_len
                    self._params['timeout'] = self._bounding_timeout
                    self._params['tcp'] = True
                    self._state = self.USE_TCP
                    if is_truncated:
                        return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TC_SET, response_len, RETRY_ACTION_USE_TCP, None)
                    else:
                        return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_DIAGNOSTIC, response_len, RETRY_ACTION_USE_TCP, None)

        elif self._state == self.USE_TCP:
            if not is_timeout and is_valid:
                #XXX this is cheating because we're not reporting the change to UDP
                self._params['tcp'] = False
                payload = response_len - 1
                self._request.use_edns(self._request.edns, self._request.ednsflags,
                        payload, options=self._request.options)
                self._state = self.TCP_MINUS_ONE
                return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_DIAGNOSTIC, response_len, RETRY_ACTION_CHANGE_UDP_MAX_PAYLOAD, payload)

        elif self._state == self.TCP_MINUS_ONE:
            if is_timeout:
                self._upper_bound = self._request.payload - 1
                payload = self._lower_bound + (self._upper_bound + 1 - self._lower_bound)//2
                self._request.use_edns(self._request.edns, self._request.ednsflags,
                        payload, options=self._request.options)
                self._state = self.PICKLE
                return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TIMEOUT, None, RETRY_ACTION_CHANGE_UDP_MAX_PAYLOAD, payload)
            # if the size of the message is less than the watermark, then perhaps we were rate limited
            elif response_wire is not None and response_len < self._water_mark:
                # but if this isn't the first time, just quit.  it could be that
                # the server simply has some wonky way of determining how/where to truncate.
                if self._history[-1].cause == RETRY_CAUSE_DIAGNOSTIC and self._history[-1].action == RETRY_ACTION_CHANGE_SPORT:
                    self._params['tcp'] = True
                    self._state = self.TCP_FINAL
                    return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_DIAGNOSTIC, None, RETRY_ACTION_USE_TCP, None)
                else:
                    self._params['wait'] = 1.0
                    return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_DIAGNOSTIC, None, RETRY_ACTION_CHANGE_SPORT, None)
            # if the response was truncated, then the size of the payload
            # received via TCP is the largest we can receive
            elif is_truncated:
                self._params['tcp'] = True
                self._state = self.TCP_FINAL
                return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TC_SET, response_len, RETRY_ACTION_USE_TCP, None)

        elif self._state == self.PICKLE:
            if self._upper_bound - self._lower_bound <= 1:
                self._params['tcp'] = True
                self._state = self.TCP_FINAL
                if is_truncated:
                    return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TC_SET, response_len, RETRY_ACTION_USE_TCP, None)
                elif is_timeout:
                    return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TIMEOUT, None, RETRY_ACTION_USE_TCP, None)
                elif not is_valid:
                    return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_DIAGNOSTIC, None, RETRY_ACTION_USE_TCP, None)
            elif is_timeout:
                self._upper_bound = self._request.payload - 1
                payload = self._lower_bound + (self._upper_bound + 1 - self._lower_bound)//2
                self._request.use_edns(self._request.edns, self._request.ednsflags,
                        payload, options=self._request.options)
                return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TIMEOUT, None, RETRY_ACTION_CHANGE_UDP_MAX_PAYLOAD, payload)
            # if the size of the message is less than the watermark, then perhaps we were rate limited
            elif response_len < self._water_mark:
                # but if this isn't the first time, just quit.  it could be that
                # the server simply has some wonky way of determining how/where to truncate.
                if self._history[-1].cause == RETRY_CAUSE_DIAGNOSTIC and self._history[-1].action == RETRY_ACTION_CHANGE_SPORT:
                    self._params['tcp'] = True
                    self._state = self.TCP_FINAL
                    return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_DIAGNOSTIC, None, RETRY_ACTION_USE_TCP, None)
                else:
                    self._params['wait'] = 1.0
                    return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_DIAGNOSTIC, None, RETRY_ACTION_CHANGE_SPORT, None)
            elif is_valid:
                self._lower_bound = self._request.payload
                payload = self._lower_bound + (self._upper_bound + 1 - self._lower_bound)//2
                self._request.use_edns(self._request.edns, self._request.ednsflags,
                        payload, options=self._request.options)
                return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_DIAGNOSTIC, response_len, RETRY_ACTION_CHANGE_UDP_MAX_PAYLOAD, payload)

        elif self._state == self.TCP_FINAL:
            pass

        elif self._state == self.INVALID:
            pass

class ChangeTimeoutOnTimeoutHandler(ActionIndependentDNSResponseHandler):
    '''Modify timeout value when a certain number of timeouts is reached.'''

    def __init__(self, timeout, timeouts):
        self._timeout = timeout
        self._timeouts = timeouts

    def handle(self, response_wire, response, response_time):
        timeouts = self._get_num_timeouts(response)
        if isinstance(response, dns.exception.Timeout) and timeouts == self._timeouts:
            self._params['timeout'] = self._timeout

class RetryOnTimeoutHandler(DNSResponseHandler):
    '''Retry with no change when a query times out.'''

    def handle(self, response_wire, response, response_time):
        if isinstance(response, dns.exception.Timeout):
            if self._params['tcp']:
                action = RETRY_ACTION_CHANGE_SPORT
            else:
                action = RETRY_ACTION_NO_CHANGE
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TIMEOUT, None, action, None)

class DefaultAcceptHandler(DNSResponseHandler):
    '''Accept the response if there was no other reason to not accept it.'''

    def handle(self, response_wire, response, response_time):
        raise AcceptResponse()

class LifetimeHandler(ActionIndependentDNSResponseHandler):
    '''Stop handling and retrying if the designated lifetime has been
    exceeded.'''

    def __init__(self, lifetime):
        self._lifetime = lifetime
        self._start = time.time()

    def handle(self, response_wire, response, response_time):
        if self.time_remaining() <= 0:
            raise AcceptResponse()

    def time_remaining(self):
        return max(self._start + self._lifetime - time.time(), 0)

class MaxTimeoutsHandler(ActionIndependentDNSResponseHandler):
    '''Stop handling and retrying if the maximum number of timeouts has been
    exceeded.'''

    def __init__(self, max_timeouts):
        self._max_timeouts = max_timeouts

    def handle(self, response_wire, response, response_time):
        if self._get_num_timeouts(response) >= self._max_timeouts:
            raise AcceptResponse()

class DNSQueryHandler:
    '''A handler associated with a DNS query to a server.'''

    def __init__(self, query, request, server_cookie, server_cookie_status, params, response_handlers, server, client):
        self.query = query
        self.request = request
        self.params = params
        self.server_cookie = server_cookie
        self.server_cookie_status = server_cookie_status
        self._response_handlers = response_handlers
        self.history = []
        self._server = server
        self._client = client

        for handler in self._response_handlers:
            handler.set_context(self.params, self.history, self.request)

        if query.lifetime is not None:
            self._expiration = time.time() + query.lifetime
        else:
            self._expiration = None

        self._set_query_time()

    def _set_query_time(self):
        self.query_time = time.time() + self.params['wait']

    def _reset_wait(self):
        self.params['wait'] = 0

    def get_query_transport_meta(self):
        return transport.DNSQueryTransportMeta(self.request.to_wire(), self._server, self.params['tcp'], self.get_timeout(), \
                self.query.odd_ports.get(self._server, self.query.port), src=self._client, sport=self.params['sport'])

    def get_remaining_lifetime(self):
        if self._expiration is None:
            # send arbitrarily high value
            return 86400
        return max(self._expiration - time.time(), 0)

    def get_timeout(self):
        if self._expiration is None:
            return self.params['timeout']
        timeout = min(self.params['timeout'], self.get_remaining_lifetime())
        if timeout < MIN_QUERY_TIMEOUT:
            return MIN_QUERY_TIMEOUT
        return timeout

    def handle_response(self, response_wire, response, response_time, client, sport):
        retry_action = None
        try:
            for handler in self._response_handlers:
                if retry_action is None:
                    retry_action = handler.handle(response_wire, response, response_time)
                    if retry_action is not None:
                        if retry_action.action == RETRY_ACTION_NO_CHANGE:
                            self.params['sport'] = sport
                        else:
                            self.params['sport'] = None
                elif isinstance(handler, ActionIndependentDNSResponseHandler):
                    handler.handle(response_wire, response, response_time)

            if retry_action is not None:
                # If we were unable to bind to the source address, then this is
                # our fault
                if retry_action.cause == RETRY_CAUSE_NETWORK_ERROR and retry_action.cause_arg == errno.EADDRNOTAVAIL:
                    raise AcceptResponse

                # If there is no client-side connectivity, then simply return.
                #
                #XXX (Note that this only catches the case when a client IP has
                # not been explicitly specified (i.e., self._client is None).
                # Explicitly specifying a client IP that cannot connect to a
                # given destination (e.g., because it is of the wrong address
                # scope) will result in a regular network failure with
                # EHOSTUNREACH or ENETUNREACH, as there is no scope comparison
                # in this code.)
                if retry_action.cause == RETRY_CAUSE_NETWORK_ERROR and retry_action.cause_arg in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EAFNOSUPPORT) and client is None:
                    raise AcceptResponse

                # if this error was our fault, don't add it to the history
                if retry_action.cause == RETRY_CAUSE_NETWORK_ERROR and retry_action.cause_arg == errno.EMFILE:
                    pass
                else:
                    self.history.append(retry_action)

            self._set_query_time()
            self._reset_wait()

        except AcceptResponse:
            return response

class AggregateDNSResponse(object):
    ttl_cmp = False

    def __init__(self):
        self.answer_info = []
        self.nodata_info = []
        self.nxdomain_info = []
        self.referral_info = []
        self.truncated_info = []
        self.error_info = []

    def _aggregate_response(self, server, client, response, qname, rdtype, rdclass, bailiwick):
        if response.is_valid_response():
            if response.is_complete_response():
                is_referral = response.is_referral(qname, rdtype, rdclass, bailiwick)
                self._aggregate_answer(server, client, response, is_referral, qname, rdtype, rdclass)
            else:
                truncated_info = TruncatedResponse(response.message.to_wire())
                DNSResponseComponent.insert_into_list(truncated_info, self.truncated_info, server, client, response)

        else:
            self._aggregate_error(server, client, response)

    def _aggregate_answer(self, server, client, response, referral, qname, rdtype, rdclass):
        msg = response.message

        # sort with the most specific DNAME infos first
        dname_rrsets = [x for x in msg.answer if x.rdtype == dns.rdatatype.DNAME and x.rdclass == rdclass]
        dname_rrsets.sort(reverse=True)

        qname_sought = qname
        try:
            i = 0
            while i < MAX_CNAME_REDIRECTION:

                # synthesize a CNAME from a DNAME, if possible
                synthesized_cname_info = None
                for dname_rrset in dname_rrsets:
                    if qname_sought.parent().is_subdomain(dname_rrset.name):
                        synthesized_cname_info = RRsetInfo(cname_from_dname(qname_sought, dname_rrset), self.ttl_cmp, RRsetInfo(dname_rrset, self.ttl_cmp))
                        break

                try:
                    rrset_info = self._aggregate_answer_rrset(server, client, response, qname_sought, rdtype, rdclass, referral)

                    # if there was a synthesized CNAME, add it to the rrset_info
                    if rrset_info.rrset.rdtype == dns.rdatatype.CNAME and rrset_info.rrset.rdclass == rdclass and synthesized_cname_info is not None:
                        synthesized_cname_info = rrset_info.create_or_update_cname_from_dname_info(synthesized_cname_info, server, client, response, rdclass)
                        synthesized_cname_info.update_rrsig_info(server, client, response, msg.answer, rdclass, referral)

                except KeyError:
                    if synthesized_cname_info is None:
                        raise
                    synthesized_cname_info = DNSResponseComponent.insert_into_list(synthesized_cname_info, self.answer_info, server, client, response)
                    synthesized_cname_info.dname_info.update_rrsig_info(server, client, response, msg.answer, rdclass, referral)
                    rrset_info = synthesized_cname_info

                if rrset_info.rrset.rdtype == dns.rdatatype.CNAME and rrset_info.rrset.rdclass == rdclass:
                    qname_sought = rrset_info.rrset[0].target
                else:
                    break
                i += 1
        except KeyError:
            if referral and rdtype != dns.rdatatype.DS:
                # add referrals
                try:
                    rrset = [x for x in msg.authority if qname.is_subdomain(x.name) and x.rdtype == dns.rdatatype.NS and x.rdclass == rdclass][0]
                except IndexError:
                    pass
                else:
                    referral_info = ReferralResponse(rrset.name)
                    DNSResponseComponent.insert_into_list(referral_info, self.referral_info, server, client, response)

                # with referrals, don't do any further processing
                return

            # don't store no answer or NXDOMAIN info for names other than qname
            # if recursion is not desired and available
            if qname_sought != qname and not response.recursion_desired_and_available():
                return

            if msg.rcode() == dns.rcode.NXDOMAIN:
                neg_response_info_list = self.nxdomain_info
            else:
                neg_response_info_list = self.nodata_info

            neg_response_info = NegativeResponseInfo(qname_sought, rdtype, self.ttl_cmp)
            neg_response_info = DNSResponseComponent.insert_into_list(neg_response_info, neg_response_info_list, server, client, response)
            neg_response_info.create_or_update_nsec_info(server, client, response, rdclass, referral)
            neg_response_info.create_or_update_soa_info(server, client, response, rdclass, referral)

    def _aggregate_answer_rrset(self, server, client, response, qname, rdtype, rdclass, referral):
        msg = response.message

        try:
            rrset = msg.find_rrset(msg.answer, qname, rdclass, rdtype)
        except KeyError:
            rrset = msg.find_rrset(msg.answer, qname, rdclass, dns.rdatatype.CNAME)

        rrset_info = RRsetInfo(rrset, self.ttl_cmp)
        rrset_info = DNSResponseComponent.insert_into_list(rrset_info, self.answer_info, server, client, response)

        rrset_info.update_rrsig_info(server, client, response, msg.answer, rdclass, referral)

        return rrset_info

    def _aggregate_error(self, server, client, response):
        msg = response.message
        if msg is None:
            error_info = DNSResponseError(response.error, response.errno)
        else:
            error_info = DNSResponseError(RESPONSE_ERROR_INVALID_RCODE, msg.rcode())
        error_info = DNSResponseComponent.insert_into_list(error_info, self.error_info, server, client, response)

class DNSQuery(object):
    '''An simple DNS Query and its responses.'''

    def __init__(self, qname, rdtype, rdclass,
            flags, edns, edns_max_udp_payload, edns_flags, edns_options, tcp):

        self.qname = qname
        self.rdtype = rdtype
        self.rdclass = rdclass
        self.flags = flags
        self.edns = edns
        self.edns_max_udp_payload = edns_max_udp_payload
        self.edns_flags = edns_flags
        self.edns_options = edns_options
        self.tcp = tcp

        self.responses = {}

    def copy(self, bailiwick_map, default_bailiwick, with_responses=True):
        '''Return a clone of the current DNSQuery instance.  Parameters are
        passed by reference rather than copied.  Note: if it turns out that
        these member variables might be modified somehow by other instances in
        future use, then these will need to be copies.'''

        clone = DNSQuery(self.qname, self.rdtype, self.rdclass,
                self.flags, self.edns, self.edns_max_udp_payload, self.edns_flags, self.edns_options, self.tcp)

        if with_responses:
            for server in self.responses:
                bailiwick = bailiwick_map.get(server, default_bailiwick)
                for client, response in self.responses[server].items():
                    response_clone = response.copy()
                    response_clone.query = clone
                    clone.add_response(server, client, response_clone, bailiwick)

        return clone

    def join(self, query, bailiwick_map, default_bailiwick):
        if not (isinstance(query, DNSQuery)):
            raise ValueError('A DNSQuery instance can only be joined with another DNSQuery instance.')

        if not (self.qname.to_text() == query.qname.to_text() and self.rdtype == query.rdtype and \
                self.rdclass == query.rdclass and self.flags == query.flags and \
                self.edns == query.edns and self.edns_max_udp_payload == query.edns_max_udp_payload and \
                self.edns_flags == query.edns_flags and self.edns_options == query.edns_options and \
                self.tcp == query.tcp):
            raise ValueError('DNS query parameters for DNSQuery instances being joined must be the same.')

        clone = self.copy(bailiwick_map, default_bailiwick)
        for server in query.responses:
            bailiwick = bailiwick_map.get(server, default_bailiwick)
            for client, response in query.responses[server].items():
                response_clone = response.copy()
                response_clone.query = clone
                clone.add_response(server, client, response_clone, bailiwick)
        return clone

    def project(self, servers, bailiwick_map, default_bailiwick):
        if servers.difference(self.responses):
            raise ValueError('A DNSQuery can only project responses from servers that have been queried.')

        clone = self.copy(bailiwick_map, default_bailiwick, with_responses=False)
        for server in servers:
            bailiwick = bailiwick_map.get(server, default_bailiwick)
            for client, response in self.responses[server].items():
                response_clone = response.copy()
                response_clone.query = clone
                clone.add_response(server, client, response_clone, bailiwick)
        return clone

    def add_response(self, server, client, response, bailiwick):
        if server not in self.responses:
            self.responses[server] = {}
        if response.query is not None and response.query is not self:
            raise ValueError('Response for %s/%s is already associated with a query.' % (self.qname, dns.rdatatype.to_text(self.rdtype)))
        if client in self.responses[server]:
            raise ValueError('Response for %s/%s from server %s to client %s already exists.' % (self.qname, dns.rdatatype.to_text(self.rdtype), server, client))
        response.query = self
        self.responses[server][client] = response

    def is_authoritative_answer_all(self):
        val = None
        for server in self.responses:
            for response in self.responses[server].values():
                if not (response.is_valid_response() and response.is_complete_response()):
                    continue
                if response.is_authoritative() and response.is_answer(self.qname, self.rdtype):
                    val = True
                else:
                    return False

        if val is None:
            val = False
        return val

    def is_answer_any(self):
        for server in self.responses:
            for response in self.responses[server].values():
                if not (response.is_valid_response() and response.is_complete_response()):
                    continue
                if response.is_answer(self.qname, self.rdtype):
                    return True
        return False

    def is_nxdomain_all(self):
        val = None
        for server in self.responses:
            for response in self.responses[server].values():
                if not (response.is_valid_response() and response.is_complete_response()):
                    continue
                if response.is_nxdomain(self.qname, self.rdtype):
                    if val is None:
                        val = True
                else:
                    return False

        if val is None:
            val = False
        return val

    def is_not_delegation_all(self):
        val = None
        for server in self.responses:
            for response in self.responses[server].values():
                if not (response.is_valid_response() and response.is_complete_response()):
                    continue
                if response.not_delegation(self.qname, self.rdtype):
                    if val is None:
                        val = True
                else:
                    return False

        if val is None:
            val = False
        return val

    def is_valid_complete_response_any(self):
        for server in self.responses:
            for response in self.responses[server].values():
                if response.is_valid_response() and response.is_complete_response():
                    return True
        return False

    def is_valid_complete_authoritative_response_any(self):
        for server in self.responses:
            for response in self.responses[server].values():
                if response.is_valid_response() and response.is_complete_response() and response.is_authoritative():
                    return True
        return False

    def servers_with_valid_complete_response(self, bailiwick_map, default_bailiwick):
        servers_clients = set()
        for server in self.responses:
            bailiwick = bailiwick_map.get(server, default_bailiwick)
            for client, response in self.responses[server].items():
                if response.is_valid_response() and response.is_complete_response() and not response.is_referral(self.qname, self.rdtype, self.rdclass, bailiwick):
                    servers_clients.add((server, client))
        return servers_clients

    def is_nxdomain_any(self):
        for server in self.responses:
            for response in self.responses[server].values():
                if not (response.is_valid_response() and response.is_complete_response()):
                    continue
                if response.is_nxdomain(self.qname, self.rdtype):
                    return True
        return False

    def serialize(self, meta_only=False):
        d = OrderedDict((
            ('qname', lb2s(self.qname.to_text())),
            ('qclass', dns.rdataclass.to_text(self.rdclass)),
            ('qtype', dns.rdatatype.to_text(self.rdtype)),
        ))
        d['options'] = OrderedDict((
            ('flags', self.flags),
        ))
        if self.edns >= 0:
            d['options']['edns_version'] = self.edns
            d['options']['edns_max_udp_payload'] = self.edns_max_udp_payload
            d['options']['edns_flags'] = self.edns_flags
            d['options']['edns_options'] = []
            for o in self.edns_options:
                s = io.BytesIO()
                o.to_wire(s)
                d['options']['edns_options'].append((o.otype, lb2s(binascii.hexlify(s.getvalue()))))
            d['options']['tcp'] = self.tcp

        d['responses'] = OrderedDict()
        servers = list(self.responses.keys())
        servers.sort()
        for server in servers:
            d['responses'][server] = OrderedDict()
            clients = list(self.responses[server].keys())
            clients.sort()
            for client in clients:
                if meta_only:
                    d['responses'][server][client] = self.responses[server][client].serialize_meta()
                else:
                    d['responses'][server][client] = self.responses[server][client].serialize()

        return d

    @classmethod
    def deserialize(self, d, bailiwick_map, default_bailiwick, cookie_jar_map, default_cookie_jar, cookie_standin, cookie_bad):
        qname = dns.name.from_text(d['qname'])
        rdclass = dns.rdataclass.from_text(d['qclass'])
        rdtype = dns.rdatatype.from_text(d['qtype'])

        d1 = d['options']

        flags = d1['flags']
        if 'edns_version' in d1:
            edns = d1['edns_version']
            edns_max_udp_payload = d1['edns_max_udp_payload']
            edns_flags = d1['edns_flags']
            edns_options = []
            for otype, data in d1['edns_options']:
                edns_options.append(dns.edns.GenericOption(otype, binascii.unhexlify(data)))
        else:
            edns = None
            edns_max_udp_payload = None
            edns_flags = None
            edns_options = []

        tcp = d1['tcp']

        q = DNSQuery(qname, rdtype, rdclass,
                flags, edns, edns_max_udp_payload, edns_flags, edns_options, tcp)

        server_cookie = None
        server_cookie_status = DNS_COOKIE_NO_COOKIE
        if edns >= 0:
            try:
                cookie_opt = [o for o in edns_options if o.otype == 10][0]
            except IndexError:
                pass
            else:
                if len(cookie_opt.data) == 8:
                    server_cookie_status = DNS_COOKIE_CLIENT_COOKIE_ONLY
                elif len(cookie_opt.data) >= 16 and len(cookie_opt.data) <= 40:
                    if cookie_opt.data[8:] == cookie_standin:
                        # initially assume that there is a cookie for the server;
                        # change the value later if there isn't
                        server_cookie_status = DNS_COOKIE_SERVER_COOKIE_FRESH
                    elif cookie_opt.data[8:] == cookie_bad:
                        server_cookie_status = DNS_COOKIE_SERVER_COOKIE_BAD
                    else:
                        server_cookie_status = DNS_COOKIE_SERVER_COOKIE_STATIC
                else:
                    server_cookie_status = DNS_COOKIE_IMPROPER_LENGTH

        for server in d['responses']:
            server_ip = IPAddr(server)
            bailiwick = bailiwick_map.get(server_ip, default_bailiwick)
            cookie_jar = cookie_jar_map.get(server_ip, default_cookie_jar)
            server_cookie = cookie_jar.get(server_ip, None)
            status = server_cookie_status
            if status == DNS_COOKIE_SERVER_COOKIE_FRESH and server_cookie is None:
                status = DNS_COOKIE_CLIENT_COOKIE_ONLY
            for client in d['responses'][server]:
                q.add_response(server_ip, IPAddr(client), DNSResponse.deserialize(d['responses'][server][client], q, server_cookie, status), bailiwick)
        return q

class DNSQueryAggregateDNSResponse(DNSQuery, AggregateDNSResponse):
    def __init__(self, qname, rdtype, rdclass,
            flags, edns, edns_max_udp_payload, edns_flags, edns_options, tcp):
        DNSQuery.__init__(self, qname, rdtype, rdclass,
            flags, edns, edns_max_udp_payload, edns_flags, edns_options, tcp)
        AggregateDNSResponse.__init__(self)

    def add_response(self, server, client, response, bailiwick):
        super(DNSQueryAggregateDNSResponse, self).add_response(server, client, response, bailiwick)
        self._aggregate_response(server, client, response, self.qname, self.rdtype, self.rdclass, bailiwick)

class MultiQuery(object):
    '''An simple DNS Query and its responses.'''

    def __init__(self, qname, rdtype, rdclass):
        self.qname = qname
        self.rdtype = rdtype
        self.rdclass = rdclass

        self.queries = {}

    def add_query(self, query, bailiwick_map, default_bailiwick):
        if not (self.qname == query.qname and self.rdtype == query.rdtype and self.rdclass == query.rdclass):
            raise ValueError('DNS query information must be the same as that to which query is being joined.')

        edns_options_str = b''
        for o in query.edns_options:
            s = io.BytesIO()
            o.to_wire(s)
            edns_options_str += struct.pack(b'!H', o.otype) + s.getvalue()
        params = (query.qname.to_text(), query.flags, query.edns, query.edns_max_udp_payload, query.edns_flags, edns_options_str, query.tcp)
        if params in self.queries:
            self.queries[params] = self.queries[params].join(query, bailiwick_map, default_bailiwick)
        else:
            self.queries[params] = query

    def project(self, servers, bailiwick_map, default_bailiwick):
        query = self.__class__(self.qname, self.rdtype, self.rdclass)

        for params in self.queries:
            query.add_query(self.queries[params].project(servers, bailiwick_map, default_bailiwick))
        return query

    def is_nxdomain_all(self):
        for params in self.queries:
            if not self.queries[params].is_nxdomain_all():
                return False
        return True

    def is_valid_complete_authoritative_response_any(self):
        for params in self.queries:
            if self.queries[params].is_valid_complete_authoritative_response_any():
                return True
        return False

class MultiQueryAggregateDNSResponse(MultiQuery, AggregateDNSResponse):
    def __init__(self, qname, rdtype, rdclass):
        MultiQuery.__init__(self, qname, rdtype, rdclass)
        AggregateDNSResponse.__init__(self)

    def add_query(self, query, bailiwick_map, default_bailiwick):
        super(MultiQueryAggregateDNSResponse, self).add_query(query, bailiwick_map, default_bailiwick)
        for server in query.responses:
            bailiwick = bailiwick_map.get(server, default_bailiwick)
            for client, response in query.responses[server].items():
                self._aggregate_response(server, client, response, self.qname, self.rdtype, self.rdclass, bailiwick)

class TTLDistinguishingMultiQueryAggregateDNSResponse(MultiQueryAggregateDNSResponse):
    ttl_cmp = True

class ExecutableDNSQuery(DNSQuery):
    '''An executable DNS Query.'''

    default_th_factory = transport.DNSQueryTransportHandlerDNSPrivateFactory()

    def __init__(self, qname, rdtype, rdclass, servers, bailiwick,
            client_ipv4, client_ipv6, port, odd_ports, cookie_jar, cookie_standin, cookie_bad,
            flags, edns, edns_max_udp_payload, edns_flags, edns_options, tcp,
            response_handlers, query_timeout, max_attempts, lifetime):

        super(ExecutableDNSQuery, self).__init__(qname, rdtype, rdclass,
                flags, edns, edns_max_udp_payload, edns_flags, edns_options, tcp)

        if not isinstance(servers, set):
            if isinstance(servers, (list, tuple)):
                servers = set(servers)
            else:
                servers = set([servers])
        if not servers:
            raise ValueError("At least one server must be specified for an ExecutableDNSQuery")

        self.servers = servers
        self.bailiwick = bailiwick
        self.client_ipv4 = client_ipv4
        self.client_ipv6 = client_ipv6
        self.port = port
        if odd_ports is None:
            odd_ports = {}
        self.odd_ports = odd_ports
        if cookie_jar is None:
            cookie_jar = {}
        self.cookie_jar = cookie_jar
        self.cookie_standin = cookie_standin
        self.cookie_bad = cookie_bad
        self.response_handlers = response_handlers

        self.query_timeout = query_timeout

        if lifetime is None and max_attempts is None:
            raise ValueError("At least one of lifetime or max_attempts must be specified for an ExecutableDNSQuery instance.")
        self.max_attempts = max_attempts
        self.lifetime = lifetime

        self._executed = False

    def get_query_handler(self, server):
        edns_options = copy.deepcopy(self.edns_options)
        server_cookie = None
        server_cookie_status = DNS_COOKIE_NO_COOKIE

        if self.edns >= 0:
            try:
                cookie_opt = [o for o in edns_options if o.otype == 10][0]
            except IndexError:
                pass
            else:
                if len(cookie_opt.data) == 8:
                    server_cookie_status = DNS_COOKIE_CLIENT_COOKIE_ONLY
                elif len(cookie_opt.data) >= 16 and len(cookie_opt.data) <= 40:
                    if cookie_opt.data[8:] == self.cookie_standin:
                        if server in self.cookie_jar:
                            # if there is a cookie for this server,
                            # then add it
                            server_cookie = self.cookie_jar[server]
                            cookie_opt.data = cookie_opt.data[:8] + server_cookie
                            server_cookie_status = DNS_COOKIE_SERVER_COOKIE_FRESH
                        else:
                            # otherwise, send just the client cookie.
                            cookie_opt.data = cookie_opt.data[:8]
                            server_cookie_status = DNS_COOKIE_CLIENT_COOKIE_ONLY
                    elif cookie_opt.data[8:] == self.cookie_bad:
                        server_cookie_status = DNS_COOKIE_SERVER_COOKIE_BAD
                    else:
                        server_cookie_status = DNS_COOKIE_SERVER_COOKIE_STATIC
                else:
                    server_cookie_status = DNS_COOKIE_IMPROPER_LENGTH

        request = dns.message.Message()
        request.flags = self.flags
        request.find_rrset(request.question, self.qname, self.rdclass, self.rdtype, create=True, force_unique=True)
        request.use_edns(self.edns, self.edns_flags, self.edns_max_udp_payload, options=edns_options)

        if server.version == 6:
            client = self.client_ipv6
        else:
            client = self.client_ipv4

        params = { 'tcp': self.tcp, 'sport': None, 'wait': 0, 'timeout': self.query_timeout }

        response_handlers = [RetryOnNetworkErrorHandler(3).build()] + [h.build() for h in self.response_handlers] + \
            [RetryOnTimeoutHandler().build(), DefaultAcceptHandler().build()]

        if self.max_attempts is not None:
            response_handlers.append(MaxTimeoutsHandler(self.max_attempts).build())
        if self.lifetime is not None:
            response_handlers.append(LifetimeHandler(self.lifetime).build())

        return DNSQueryHandler(self, request, server_cookie, server_cookie_status, params, response_handlers, server, client)

    @classmethod
    def execute_queries(cls, *queries, **kwargs):
        '''Execute the query to a given server, and handle it appropriately.'''

        tm = kwargs.get('tm', None)
        if tm is None:
            # this starts a thread that stops when tm goes out of scope
            tm = transport.DNSQueryTransportManager()

        th_factories = kwargs.get('th_factories', None)
        if th_factories is None:
            th_factories = (cls.default_th_factory,)

        request_list = []
        response_queue = queue.Queue()

        ignore_queryid = kwargs.get('ignore_queryid', True)
        response_wire_map = {}

        query_handlers = {}
        query_time = None
        for th_factory in th_factories:
            if not th_factory.cls.singleton:
                th = th_factory.build(processed_queue=response_queue)

            for query in queries:
                qtm_for_server = False
                for server in query.servers:
                    if not th_factory.cls.allow_loopback_query and (LOOPBACK_IPV4_RE.match(server) or server == LOOPBACK_IPV6):
                        continue
                    if not th_factory.cls.allow_private_query and (RFC_1918_RE.match(server) or LINK_LOCAL_RE.match(server) or UNIQ_LOCAL_RE.match(server)):
                        continue

                    qtm_for_server = True
                    qh = query.get_query_handler(server)
                    qtm = qh.get_query_transport_meta()
                    query_handlers[qtm] = qh

                    if th_factory.cls.singleton:
                        th = th_factory.build(processed_queue=response_queue)
                        th.add_qtm(qtm)
                        th.init_req()
                        bisect.insort(request_list, (qh.query_time, th))
                    else:
                        # find the maximum query time
                        if query_time is None or qh.query_time > query_time:
                            query_time = qh.query_time
                        th.add_qtm(qtm)

                if not qtm_for_server:
                    raise NoValidServersToQuery('No valid servers to query!')

            if not th_factory.cls.singleton:
                th.init_req()
                bisect.insort(request_list, (query_time, th))

        while query_handlers:
            while request_list and time.time() >= request_list[0][0]:
                tm.handle_msg_nowait(request_list.pop(0)[1])

            t = time.time()
            if request_list and t < request_list[0][0]:
                timeout = max(request_list[0][0] - t, 0)
            else:
                timeout = None

            try:
                # pull a response from the queue
                th = response_queue.get(timeout=timeout)
            except queue.Empty:
                continue
            th.finalize()

            newth = th.factory.build(processed_queue=response_queue)
            query_time = None
            for qtm in th.qtms:
                # find its matching query meta information
                qh = query_handlers.pop(qtm)
                query = qh.query

                # define response as either a Message created from parsing
                # the wire response or an Exception
                if qtm.err is not None:
                    response = qtm.err
                else:
                    wire_zero_queryid = b'\x00\x00' + qtm.res[2:]
                    if wire_zero_queryid in response_wire_map:
                        response = response_wire_map[wire_zero_queryid]
                    else:
                        try:
                            response = dns.message.from_wire(qtm.res)
                        except Exception as e:
                            response = e
                        if ignore_queryid:
                            response_wire_map[wire_zero_queryid] = response
                if qtm.res:
                    msg_size = len(qtm.res)
                else:
                    msg_size = None
                response_time = round(qtm.end_time - qtm.start_time, 3)
                response = qh.handle_response(qtm.res, response, response_time, qtm.src, qtm.sport)

                # if no response was returned, then resubmit the modified query
                if response is None:
                    qtm = qh.get_query_transport_meta()
                    # find the maximum query time
                    if query_time is None or qh.query_time > query_time:
                        query_time = qh.query_time
                    query_handlers[qtm] = qh
                    newth.add_qtm(qtm)
                    continue

                # otherwise store away the response (or error), history, and response time
                if isinstance(response, dns.message.Message):
                    msg = response
                    err = None
                    errno1 = None
                else:
                    msg = None
                    if isinstance(response, dns.exception.Timeout):
                        err = RESPONSE_ERROR_TIMEOUT
                    elif isinstance(response, (socket.error, EOFError)):
                        err = RESPONSE_ERROR_NETWORK_ERROR
                    elif isinstance(response, (struct.error, dns.exception.FormError)):
                        err = RESPONSE_ERROR_FORMERR
                    #XXX need to determine how to handle non-parsing
                    # validation errors with dnspython (e.g., signature with
                    # no keyring)
                    else:
                        err = RESPONSE_ERROR_OTHER
                    if hasattr(response, 'errno'):
                        errno1 = response.errno
                    else:
                        errno1 = None
                response_obj = DNSResponse(msg, msg_size, err, errno1, qh.history, response_time, query, qh.server_cookie, qh.server_cookie_status)

                # if client IP is not specified, and there is a socket
                # failure, then src might be None
                if qtm.src is not None:
                    src = IPAddr(qtm.src)
                else:
                    src = qtm.src

                # If this was a network error, determine if it was a binding
                # error
                if err == RESPONSE_ERROR_NETWORK_ERROR:
                    if errno1 == errno.EADDRNOTAVAIL and qh._client is not None:
                        raise SourceAddressBindError('Unable to bind to local address %s (%s)' % (qh._client, errno.errorcode[errno1]))
                    elif errno1 == errno.EADDRINUSE or \
                            (errno1 == errno.EACCES and qtm.src is None):
                        # Address/port in use (EADDRINUSE) or insufficient
                        # permissions to bind to port
                        if qh.params['sport'] is not None:
                            raise PortBindError('Unable to bind to local port %d (%s)' % (qh.params['sport'], errno.errorcode[errno1]))
                        else:
                            raise PortBindError('Unable to bind to local port (%s)' % (errno.errorcode[errno1]))
                    elif qtm.src is None and errno1 not in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
                        # If source is None it didn't bind properly.  There are several sub-cases:
                        # 1. If the bind() failed and resulted in an errno
                        #    value of EHOSTUNREACH, it is because there was no
                        #    proper IPv4 or IPv6 connectivity; the error for
                        #    this is handled elsewhere).
                        # 2. If socket() failed and resulted in an errno value
                        #    of EAFNOSUPPORT, then there is no IPv6 support.
                        # 3. If connect() failed and resulted in an errno value
                        #    of EADDRNOTAVAIL, then there is no IPv6 support.
                        # In other cases, it was something unknown, so
                        # raise an error.
                        raise BindError('Unable to bind to local address (%s)' % (errno.errorcode.get(errno1, "unknown")))

                # if src is None, then it is a connectivity issue on our
                # side, so don't record it in the responses
                if src is not None:
                    query.add_response(qh._server, src, response_obj, query.bailiwick)

                # This query is now executed, at least in part
                query._executed = True

            if newth.qtms:
                newth.init_req()
                bisect.insort(request_list, (query_time, newth))

    def require_executed(func):
        def _func(self, *args, **kwargs):
            assert self._executed == True, "ExecutableDNSQuery has not been executed."
            return func(self, *args, **kwargs)
        return _func

    def require_not_executed(func):
        def _func(self, *args, **kwargs):
            assert self._executed == False, "ExecutableDNSQuery has already been executed."
            return func(self, *args, **kwargs)
        return _func

    def add_response(self, server, client, response, bailiwick):
        super(ExecutableDNSQuery, self).add_response(server, client, response, bailiwick)
        if not self.servers.difference(self.responses):
            self._executed = True

    @require_not_executed
    def execute(self, ignore_queryid=True, tm=None, th_factories=None):
        self.execute_queries(self, ignore_queryid=ignore_queryid, tm=tm, th_factories=th_factories)

    join = require_executed(DNSQuery.join)
    project = require_executed(DNSQuery.project)
    is_authoritative_answer_all = require_executed(DNSQuery.is_authoritative_answer_all)
    is_nxdomain_all = require_executed(DNSQuery.is_nxdomain_all)
    is_not_delegation_all = require_executed(DNSQuery.is_not_delegation_all)
    is_nxdomain_any = require_executed(DNSQuery.is_nxdomain_any)

class DNSQueryFactory(object):
    '''A simple, extensible class interface for instantiating DNSQuery objects.'''

    flags = 0
    edns = -1
    edns_max_udp_payload = 4096
    edns_flags = 0
    edns_options = []

    tcp = False

    query_timeout = 3.0
    max_attempts = 5
    lifetime = 15.0

    response_handlers = []

    def __new__(cls, qname, rdtype, rdclass, servers, bailiwick=None,
            client_ipv4=None, client_ipv6=None, port=53, odd_ports=None, cookie_jar=None, cookie_standin=None, cookie_bad=None,
            query_timeout=None, max_attempts=None, lifetime=None,
            executable=True):

        if query_timeout is None:
            query_timeout = cls.query_timeout
        if max_attempts is None:
            max_attempts = cls.max_attempts
        if lifetime is None:
            lifetime = cls.lifetime

        if executable:
            return ExecutableDNSQuery(qname, rdtype, rdclass, servers, bailiwick,
                client_ipv4, client_ipv6, port, odd_ports, cookie_jar, cookie_standin, cookie_bad,
                cls.flags, cls.edns, cls.edns_max_udp_payload, cls.edns_flags, cls.edns_options, cls.tcp,
                cls.response_handlers, query_timeout, max_attempts, lifetime)

        else:
            return DNSQuery(qname, rdtype, rdclass,
                cls.flags, cls.edns, cls.edns_max_udp_payload, cls.edns_flags, cls.edns_options, cls.tcp)

    def __init__(self, *args, **kwargs):
        raise NotImplemented()

    @classmethod
    def add_mixin(cls, mixin_cls):
        class _foo(cls):
            flags = cls.flags | getattr(mixin_cls, 'flags', 0)
            edns_flags = cls.edns_flags | getattr(mixin_cls, 'edns_flags', 0)
            edns_options = cls.edns_options + copy.deepcopy(getattr(mixin_cls, 'edns_options', []))
        return _foo

    @classmethod
    def get_cookie_opt(cls):
        try:
            return [o for o in cls.edns_options if o.otype == 10][0]
        except IndexError:
            return None

    @classmethod
    def add_server_cookie(cls, server_cookie):
        cookie_opt = cls.get_cookie_opt()
        if cookie_opt is not None:
            if len(cookie_opt.data) != 8:
                raise TypeError('COOKIE option must have length of 8.')
            cookie_opt.data += server_cookie
        return cls

    @classmethod
    def remove_cookie_option(cls):
        cookie_opt = cls.get_cookie_opt()
        if cookie_opt is not None:
            cls.edns_options.remove(cookie_opt)
        return cls

class SimpleDNSQuery(DNSQueryFactory):
    '''A simple query, no frills.'''

    pass

class RecursiveDNSQuery(SimpleDNSQuery):
    '''A simple recursive query.'''

    flags = SimpleDNSQuery.flags | dns.flags.RD

class StandardQuery(SimpleDNSQuery):
    '''A standard old-school DNS query that handles truncated packets.'''

    response_handlers = \
            SimpleDNSQuery.response_handlers + \
            [UseTCPOnTCFlagHandler()]

class StandardRecursiveQuery(StandardQuery, RecursiveDNSQuery):
    '''A standard old-school recursive DNS query that handles truncated packets.'''

    pass

class StandardRecursiveQueryCD(StandardRecursiveQuery):
    '''A recursive DNS query that retries with checking disabled if the
    response code is SERVFAIL.'''

    response_handlers = \
            StandardRecursiveQuery.response_handlers + \
            [SetFlagOnRcodeHandler(dns.flags.CD, dns.rcode.SERVFAIL)]

class EDNS0Query(StandardQuery):
    '''A standard query with EDNS0.'''

    edns = 0

class RecursiveEDNS0Query(EDNS0Query, RecursiveDNSQuery):
    '''A standard recursive query with EDNS0.'''

    pass

class DNSSECQuery(EDNS0Query):
    '''A standard query requesting DNSSEC records.'''

    edns_flags = EDNS0Query.edns_flags | dns.flags.DO

class RecursiveDNSSECQuery(DNSSECQuery, RecursiveDNSQuery):
    '''A standard recursive query requesting DNSSEC records.'''

    pass

class QuickDNSSECQuery(DNSSECQuery):
    '''A standard DNSSEC query, designed for quick turnaround.'''

    response_handlers = DNSSECQuery.response_handlers + \
            [
                    AddServerCookieOnBADCOOKIE(),
                    RemoveEDNSOptionOnRcodeHandler(dns.rcode.FORMERR),
                    DisableEDNSOnFormerrHandler(),
                    DisableEDNSOnRcodeHandler()
            ]

    query_timeout = 1.0
    max_attempts = 1
    lifetime = 3.0

class DiagnosticQuery(DNSSECQuery):
    '''A robust query with a number of handlers, designed to detect common DNS
    compatibility and connectivity issues.'''

    response_handlers = DNSSECQuery.response_handlers + \
            [
                    AddServerCookieOnBADCOOKIE(),
                    RemoveEDNSOptionOnRcodeHandler(dns.rcode.FORMERR),
                    DisableEDNSOnFormerrHandler(),
                    DisableEDNSOnRcodeHandler(),
                    ReduceUDPMaxPayloadOnTimeoutHandler(512, 4),
                    RemoveEDNSOptionOnTimeoutHandler(6),
                    ClearEDNSFlagOnTimeoutHandler(dns.flags.DO, 10),
                    DisableEDNSOnTimeoutHandler(11),
                    ChangeTimeoutOnTimeoutHandler(2.0, 2),
                    ChangeTimeoutOnTimeoutHandler(1.0, 4),
                    ChangeTimeoutOnTimeoutHandler(2.0, 5),
                    ChangeTimeoutOnTimeoutHandler(1.0, 6),
            ]
    # For timeouts:
    #  1 - no change
    #  2 - change timeout to 2 seconds
    #  3 - no change
    #  4 - reduce udp max payload to 512; change timeout to 1 second
    #  5 - change timeout to 2 seconds
    #  6 - remove EDNS option (if any); change timeout to 1 second
    #  7 - remove EDNS option (if any)
    #  8 - remove EDNS option (if any)
    #  9 - remove EDNS option (if any)
    #  10 - clear DO flag;
    #  11 - disable EDNS
    #  12 - return (give up)

    query_timeout = 1.0
    max_attempts = 12
    lifetime = 16.0

class RecursiveDiagnosticQuery(RecursiveDNSSECQuery):
    '''A robust query to a cache with a number of handlers, designed to detect
    common DNS compatibility and connectivity issues.'''

    response_handlers = DNSSECQuery.response_handlers + \
            [
                    AddServerCookieOnBADCOOKIE(),
                    RemoveEDNSOptionOnRcodeHandler(dns.rcode.FORMERR),
                    DisableEDNSOnFormerrHandler(),
                    SetFlagOnRcodeHandler(dns.flags.CD, dns.rcode.SERVFAIL),
                    DisableEDNSOnRcodeHandler(),
                    ReduceUDPMaxPayloadOnTimeoutHandler(512, 5),
                    RemoveEDNSOptionOnTimeoutHandler(7),
                    ClearEDNSFlagOnTimeoutHandler(dns.flags.DO, 11),
                    DisableEDNSOnTimeoutHandler(12),
                    ChangeTimeoutOnTimeoutHandler(2.0, 2),
                    ChangeTimeoutOnTimeoutHandler(4.0, 3),
                    ChangeTimeoutOnTimeoutHandler(8.0, 4),
                    ChangeTimeoutOnTimeoutHandler(1.0, 5),
                    ChangeTimeoutOnTimeoutHandler(2.0, 6),
                    ChangeTimeoutOnTimeoutHandler(1.0, 7),
            ]
    # For timeouts:
    #  1 - no change
    #  2 - change timeout to 2 seconds
    #  3 - change timeout to 4 seconds
    #  4 - change timeout to 8 seconds
    #  5 - reduce udp max payload to 512; change timeout to 1 second
    #  6 - change timeout to 2 seconds
    #  7 - remove EDNS option (if any); change timeout to 1 second
    #  8 - remove EDNS option (if any)
    #  9 - remove EDNS option (if any)
    #  10 - remove EDNS option (if any)
    #  11 - clear DO flag
    #  12 - disable EDNS
    #  13 - return (give up)

    query_timeout = 1.0
    max_attempts = 13
    lifetime = 26.0

class TCPDiagnosticQuery(DNSSECQuery):
    '''A robust query with a number of handlers, designed to detect common DNS
    compatibility and connectivity issues over TCP.'''

    tcp = True

    response_handlers = \
            [
                    RemoveEDNSOptionOnRcodeHandler(dns.rcode.FORMERR),
                    DisableEDNSOnFormerrHandler(),
                    DisableEDNSOnRcodeHandler(),
                    ChangeTimeoutOnTimeoutHandler(4.0, 2)
            ]
    # For timeouts:
    #  1 - no change
    #  2 - change timeout to 4 seconds
    #  3 - return

    query_timeout = 2.0
    max_attempts = 3
    lifetime = 10.0

class RecursiveTCPDiagnosticQuery(RecursiveDNSSECQuery):
    '''A robust query with a number of handlers, designed to detect common DNS
    compatibility and connectivity issues, beginning with TCP.'''

    tcp = True

    response_handlers = \
            [
                    RemoveEDNSOptionOnRcodeHandler(dns.rcode.FORMERR),
                    DisableEDNSOnFormerrHandler(),
                    SetFlagOnRcodeHandler(dns.flags.CD, dns.rcode.SERVFAIL),
                    DisableEDNSOnRcodeHandler(),
                    ChangeTimeoutOnTimeoutHandler(4.0, 2),
                    ChangeTimeoutOnTimeoutHandler(8.0, 3)
            ]
    # For timeouts:
    #  1 - no change
    #  2 - change timeout to 4 seconds
    #  3 - change timeout to 8 seconds
    #  4 - return

    query_timeout = 2.0
    max_attempts = 4
    lifetime = 18.0

class PMTUDiagnosticQuery(DNSSECQuery):

    response_handlers = \
            [PMTUBoundingHandler(512, 4, 6, 1.0)] + \
            DNSSECQuery.response_handlers + \
            [
                    AddServerCookieOnBADCOOKIE(),
                    RemoveEDNSOptionOnRcodeHandler(dns.rcode.FORMERR),
                    DisableEDNSOnFormerrHandler(),
                    DisableEDNSOnRcodeHandler(),
                    RemoveEDNSOptionOnTimeoutHandler(6),
                    ClearEDNSFlagOnTimeoutHandler(dns.flags.DO, 10),
                    DisableEDNSOnTimeoutHandler(11),
                    ChangeTimeoutOnTimeoutHandler(2.0, 2),
                    ChangeTimeoutOnTimeoutHandler(1.0, 4),
                    ChangeTimeoutOnTimeoutHandler(2.0, 5),
                    ChangeTimeoutOnTimeoutHandler(1.0, 6),
            ]
    # For timeouts:
    #  1 - no change
    #  2 - change timeout to 2 seconds
    #  3 - no change
    #  4 - reduce udp max payload to 512; change timeout to 1 second
    #  5 - change timeout to 2 seconds
    #  6 - remove EDNS option (if any); change timeout to 1 second
    #  7 - remove EDNS option (if any)
    #  8 - remove EDNS option (if any)
    #  9 - remove EDNS option (if any)
    #  10 - clear DO flag;
    #  11 - disable EDNS
    #  12 - return (give up)

    query_timeout = 1.0
    max_attempts = 12
    lifetime = 22.0 # set this a little longer due to pickle stage

class RecursivePMTUDiagnosticQuery(RecursiveDNSSECQuery):

    response_handlers = \
            [PMTUBoundingHandler(512, 5, 7, 1.0)] + \
            DNSSECQuery.response_handlers + \
            [
                    AddServerCookieOnBADCOOKIE(),
                    RemoveEDNSOptionOnRcodeHandler(dns.rcode.FORMERR),
                    DisableEDNSOnFormerrHandler(),
                    SetFlagOnRcodeHandler(dns.flags.CD, dns.rcode.SERVFAIL),
                    DisableEDNSOnRcodeHandler(),
                    RemoveEDNSOptionOnTimeoutHandler(7),
                    ClearEDNSFlagOnTimeoutHandler(dns.flags.DO, 11),
                    DisableEDNSOnTimeoutHandler(12),
                    ChangeTimeoutOnTimeoutHandler(2.0, 2),
                    ChangeTimeoutOnTimeoutHandler(4.0, 3),
                    ChangeTimeoutOnTimeoutHandler(8.0, 4),
                    ChangeTimeoutOnTimeoutHandler(1.0, 5),
                    ChangeTimeoutOnTimeoutHandler(2.0, 6),
                    ChangeTimeoutOnTimeoutHandler(1.0, 7),
            ]
    # For timeouts:
    #  1 - no change
    #  2 - change timeout to 2 seconds
    #  3 - change timeout to 4 seconds
    #  4 - change timeout to 8 seconds
    #  5 - reduce udp max payload to 512; change timeout to 1 second
    #  6 - change timeout to 2 seconds
    #  7 - remove EDNS option (if any); change timeout to 1 second
    #  8 - remove EDNS option (if any)
    #  9 - remove EDNS option (if any)
    #  10 - remove EDNS option (if any)
    #  11 - clear DO flag
    #  12 - disable EDNS
    #  13 - return (give up)

    query_timeout = 1.0
    max_attempts = 13
    lifetime = 32.0 # set this a little longer due to pickle stage

class TruncationDiagnosticQuery(DNSSECQuery):
    '''A simple query to test the results of a query with capabilities of only
    receiving back a small (512 byte) payload.'''

    response_handlers = \
            [
                    AddServerCookieOnBADCOOKIE(),
                    ChangeTimeoutOnTimeoutHandler(2.0, 2),
                    ChangeTimeoutOnTimeoutHandler(4.0, 3)
            ]
    # For timeouts:
    #  1 - no change
    #  2 - change timeout to 2 seconds
    #  3 - change timeout to 4 seconds

    edns_max_udp_payload = 512

    query_timeout = 1.0
    max_attempts = 4
    lifetime = 8.0

class RecursiveTruncationDiagnosticQuery(DNSSECQuery, RecursiveDNSQuery):
    '''A simple recursive query to test the results of a query with
    capabilities of only receiving back a small (512 byte) payload.'''

    response_handlers = \
            [
                    AddServerCookieOnBADCOOKIE(),
                    SetFlagOnRcodeHandler(dns.flags.CD, dns.rcode.SERVFAIL),
                    ChangeTimeoutOnTimeoutHandler(2.0, 2),
                    ChangeTimeoutOnTimeoutHandler(4.0, 3),
                    ChangeTimeoutOnTimeoutHandler(8.0, 4)
            ]
    # For timeouts:
    #  1 - no change
    #  2 - change timeout to 2 seconds
    #  3 - change timeout to 4 seconds
    #  4 - change timeout to 8 seconds

    edns_max_udp_payload = 512

    query_timeout = 1.0
    max_attempts = 5
    lifetime = 18.0

class EDNSVersionDiagnosticQuery(SimpleDNSQuery):
    '''A query designed to test unknown EDNS version compatibility.'''

    edns = 100
    edns_max_udp_payload = 512

    response_handlers = \
            SimpleDNSQuery.response_handlers + \
            [
                    ChangeEDNSVersionOnTimeoutHandler(0, 4),
                    ChangeTimeoutOnTimeoutHandler(2.0, 2),
                    ChangeTimeoutOnTimeoutHandler(1.0, 4)
            ]
    # For timeouts:
    #  1 - no change
    #  2 - change timeout to 2 seconds
    #  3 - no change
    #  4 - change EDNS version to 0; change timeout to 1 second
    #  5 - return

    query_timeout = 1.0
    max_attempts = 5
    lifetime = 7.0

class EDNSOptDiagnosticQuery(SimpleDNSQuery):
    '''A query designed to test unknown EDNS option compatibility.'''

    edns = 0
    edns_max_udp_payload = 512
    edns_options = [dns.edns.GenericOption(100, b'')]

    response_handlers = \
            SimpleDNSQuery.response_handlers + \
            [
                    AddServerCookieOnBADCOOKIE(),
                    RemoveEDNSOptionOnTimeoutHandler(4),
                    ChangeTimeoutOnTimeoutHandler(2.0, 2),
                    ChangeTimeoutOnTimeoutHandler(1.0, 4)
            ]

    # For timeouts:
    #  1 - no change
    #  2 - change timeout to 2 seconds
    #  3 - no change
    #  4 - remove EDNS option (if any); change timeout to 1 second
    #  5 - remove EDNS option (if any)
    #  6 - remove EDNS option (if any)
    #  7 - remove EDNS option (if any)
    #  8 - return

    query_timeout = 1.0
    max_attempts = 8
    lifetime = 11.0

class EDNSFlagDiagnosticQuery(SimpleDNSQuery):
    '''A query designed to test unknown EDNS flag compatibility.'''

    edns = 0
    edns_max_udp_payload = 512
    edns_flags = SimpleDNSQuery.edns_flags | 0x80

    response_handlers = \
            SimpleDNSQuery.response_handlers + \
            [
                    AddServerCookieOnBADCOOKIE(),
                    RemoveEDNSOptionOnTimeoutHandler(4),
                    ClearEDNSFlagOnTimeoutHandler(0x80, 8),
                    ChangeTimeoutOnTimeoutHandler(2.0, 2),
                    ChangeTimeoutOnTimeoutHandler(1.0, 4)
            ]

    # For timeouts:
    #  1 - no change
    #  2 - change timeout to 2 seconds
    #  3 - no change
    #  4 - remove EDNS option (if any); change timeout to 1 second
    #  5 - remove EDNS option (if any)
    #  6 - remove EDNS option (if any)
    #  7 - remove EDNS option (if any)
    #  8 - clear EDNS flag
    #  9 - return

    query_timeout = 1.0
    max_attempts = 9
    lifetime = 12.0

class RecursiveEDNSVersionDiagnosticQuery(SimpleDNSQuery):
    '''A query designed to test unknown EDNS version compatibility on recursive
    servers.'''

    flags = dns.flags.RD
    edns = 100
    edns_max_udp_payload = 512

    response_handlers = \
            SimpleDNSQuery.response_handlers + \
            [
                    SetFlagOnRcodeHandler(dns.flags.CD, dns.rcode.SERVFAIL),
                    ChangeEDNSVersionOnTimeoutHandler(0, 5),
                    ChangeTimeoutOnTimeoutHandler(2.0, 2),
                    ChangeTimeoutOnTimeoutHandler(4.0, 3),
                    ChangeTimeoutOnTimeoutHandler(8.0, 4),
                    ChangeTimeoutOnTimeoutHandler(1.0, 5)
            ]
    # For timeouts:
    #  1 - no change
    #  2 - change timeout to 2 seconds
    #  3 - change timeout to 4 seconds
    #  4 - change timeout to 8 seconds
    #  5 - change EDNS version to 0; change timeout to 1 second
    #  6 - return

    query_timeout = 1.0
    max_attempts = 6
    lifetime = 18.0

class RecursiveEDNSOptDiagnosticQuery(SimpleDNSQuery):
    '''A query designed to test unknown EDNS option compatibility on recursive
    servers.'''

    flags = dns.flags.RD
    edns = 0
    edns_max_udp_payload = 512
    edns_options = [dns.edns.GenericOption(100, b'')]

    response_handlers = \
            SimpleDNSQuery.response_handlers + \
            [
                    AddServerCookieOnBADCOOKIE(),
                    SetFlagOnRcodeHandler(dns.flags.CD, dns.rcode.SERVFAIL),
                    RemoveEDNSOptionOnTimeoutHandler(5),
                    ChangeTimeoutOnTimeoutHandler(2.0, 2),
                    ChangeTimeoutOnTimeoutHandler(4.0, 3),
                    ChangeTimeoutOnTimeoutHandler(8.0, 4),
                    ChangeTimeoutOnTimeoutHandler(1.0, 5)
            ]

    # For timeouts:
    #  1 - no change
    #  2 - change timeout to 2 seconds
    #  3 - change timeout to 4 seconds
    #  4 - change timeout to 8 seconds
    #  5 - remove EDNS option (if any); change timeout to 1 second
    #  6 - remove EDNS option (if any)
    #  7 - remove EDNS option (if any)
    #  8 - remove EDNS option (if any)
    #  9 - return

    query_timeout = 1.0
    max_attempts = 9
    lifetime = 21.0

class RecursiveEDNSFlagDiagnosticQuery(SimpleDNSQuery):
    '''A query designed to test unknown EDNS flag compatibility on recursive
    servers.'''

    flags = dns.flags.RD
    edns = 0
    edns_max_udp_payload = 512
    edns_flags = SimpleDNSQuery.edns_flags | 0x80

    response_handlers = \
            SimpleDNSQuery.response_handlers + \
            [
                    AddServerCookieOnBADCOOKIE(),
                    SetFlagOnRcodeHandler(dns.flags.CD, dns.rcode.SERVFAIL),
                    RemoveEDNSOptionOnTimeoutHandler(5),
                    ClearEDNSFlagOnTimeoutHandler(0x80, 9),
                    ChangeTimeoutOnTimeoutHandler(2.0, 2),
                    ChangeTimeoutOnTimeoutHandler(4.0, 3),
                    ChangeTimeoutOnTimeoutHandler(8.0, 4),
                    ChangeTimeoutOnTimeoutHandler(1.0, 5)
            ]

    # For timeouts:
    #  1 - no change
    #  2 - change timeout to 2 seconds
    #  3 - change timeout to 4 seconds
    #  4 - change timeout to 8 seconds
    #  5 - remove EDNS option (if any); change timeout to 1 second
    #  6 - remove EDNS option (if any)
    #  7 - remove EDNS option (if any)
    #  8 - remove EDNS option (if any)
    #  9 - clear EDNS flag
    #  10 - return

    query_timeout = 1.0
    max_attempts = 10
    lifetime = 22.0

def main():
    import json
    import sys
    import getopt

    def usage():
        sys.stderr.write('Usage: %s [-r] [-j] <name> <type> <server> [<server>...]\n' % (sys.argv[0]))
        sys.exit(1)

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'rj')
        opts = dict(opts)
    except getopt.error:
        usage()

    if len(args) < 3:
        usage()

    if '-r' in opts:
        cls = RecursiveDiagnosticQuery
    else:
        cls = DiagnosticQuery
    d = cls(dns.name.from_text(args[0]), dns.rdatatype.from_text(args[1]), dns.rdataclass.IN, [IPAddr(x) for x in args[2:]])
    d.execute()

    if '-j' in opts:
        print(json.dumps(d.serialize(), indent=4, separators=(',', ': ')))
    else:
        print('Responses for %s/%s:' % (args[0], args[1]))
        for server in d.responses:
            for client, response in d.responses[server].items():
                if response.message is not None:
                    print('   from %s: %s (%d bytes in %dms)' % (server, repr(response.message), len(response.message.to_wire()), int(response.response_time*1000)))
                else:
                    print('   from %s: (ERR: %s) (%dms)' % (server, repr(response.error), int(response.response_time*1000)))

                print('   (src: %s)' % (client))
                if response.history:
                    print('       (history: %s)' % (response.history))

if __name__ == '__main__':
    main()
