#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Author: Casey Deccio (casey@deccio.net)
#
# Copyright 2014 Verisign, Inc.
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

import base64
import bisect
import collections
import Queue
import socket
import StringIO
import struct
import time

import dns.exception, dns.flags, dns.message, dns.rcode, \
        dns.rdataclass, dns.rdatatype

from response import *
import transport

RETRY_CAUSE_NETWORK_ERROR = RESPONSE_ERROR_NETWORK_ERROR = 1
RETRY_CAUSE_FORMERR = RESPONSE_ERROR_FORMERR = 2
RETRY_CAUSE_TIMEOUT = RESPONSE_ERROR_TIMEOUT = 3
RETRY_CAUSE_OTHER = RESPONSE_ERROR_OTHER = 4
RETRY_CAUSE_TC_SET = 5
RETRY_CAUSE_RCODE = 6
RETRY_CAUSE_DIAGNOSTIC = 7
retry_causes = {
        RETRY_CAUSE_NETWORK_ERROR: 'NETWORK_ERROR',
        RETRY_CAUSE_FORMERR: 'FORMERR',
        RETRY_CAUSE_TIMEOUT: 'TIMEOUT',
        RETRY_CAUSE_OTHER: 'OTHER',
        RETRY_CAUSE_TC_SET: 'TC',
        RETRY_CAUSE_RCODE: 'INVALID_RCODE',
        RETRY_CAUSE_DIAGNOSTIC: 'DIAGNOSTIC'
}
retry_cause_codes = {
        'NETWORK_ERROR': RETRY_CAUSE_NETWORK_ERROR,
        'FORMERR': RETRY_CAUSE_FORMERR,
        'TIMEOUT': RETRY_CAUSE_TIMEOUT,
        'OTHER': RETRY_CAUSE_OTHER,
        'TC': RETRY_CAUSE_TC_SET,
        'INVALID_RCODE': RETRY_CAUSE_RCODE,
        'DIAGNOSTIC': RETRY_CAUSE_DIAGNOSTIC,
}
response_errors = {
        RESPONSE_ERROR_NETWORK_ERROR: retry_causes[RETRY_CAUSE_NETWORK_ERROR],
        RESPONSE_ERROR_FORMERR: retry_causes[RETRY_CAUSE_FORMERR],
        RESPONSE_ERROR_TIMEOUT: retry_causes[RETRY_CAUSE_TIMEOUT],
        RESPONSE_ERROR_OTHER: retry_causes[RETRY_CAUSE_OTHER]
}
response_error_codes = {
        retry_causes[RETRY_CAUSE_NETWORK_ERROR]: RESPONSE_ERROR_NETWORK_ERROR,
        retry_causes[RETRY_CAUSE_FORMERR]: RESPONSE_ERROR_FORMERR,
        retry_causes[RETRY_CAUSE_TIMEOUT]: RESPONSE_ERROR_TIMEOUT,
        retry_causes[RETRY_CAUSE_OTHER]: RESPONSE_ERROR_OTHER
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
retry_actions = {
        RETRY_ACTION_NO_CHANGE: 'NO_CHANGE',
        RETRY_ACTION_USE_TCP: 'USE_TCP',
        RETRY_ACTION_USE_UDP: 'USE_UDP',
        RETRY_ACTION_SET_FLAG: 'SET_FLAG',
        RETRY_ACTION_CLEAR_FLAG: 'CLEAR_FLAG',
        RETRY_ACTION_DISABLE_EDNS: 'DISABLE_EDNS',
        RETRY_ACTION_CHANGE_UDP_MAX_PAYLOAD: 'CHANGE_UDP_MAX_PAYLOAD',
        RETRY_ACTION_SET_EDNS_FLAG: 'SET_EDNS_FLAG',
        RETRY_ACTION_CLEAR_EDNS_FLAG: 'CLEAR_EDNS_FLAG',
        RETRY_ACTION_ADD_EDNS_OPTION: 'ADD_EDNS_OPTION',
        RETRY_ACTION_REMOVE_EDNS_OPTION: 'REMOVE_EDNS_OPTION',
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
}

MIN_QUERY_TIMEOUT = 0.1
MAX_CNAME_REDIRECTION = 40

class AcceptResponse(Exception):
    '''An exception raised to stop the process of retrying DNS queries when an
    acceptable response or error condition has been satisfied.'''
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
        d = collections.OrderedDict()
        d['response_time'] = self.response_time
        d['cause'] = retry_causes.get(self.cause, 'UNKNOWN')
        if self.cause_arg is not None:
            d['cause_arg'] = self.cause_arg
        d['action'] = retry_actions.get(self.action, 'UNKNOWN')
        if self.action_arg is not None:
            d['action_arg'] = self.action_arg
        return d

    @classmethod
    def deserialize(cls, d):
        response_time = d['response_time']
        cause = retry_cause_codes[d['cause']]
        if 'cause_arg' in d:
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

    reuse_sport = False

    def __new__(cls, *args, **kwargs):
        '''Redirect the instantiation of a DNSResponseHandler to create instead a Factory,
        from which a DNSResponseHandler in turn is built.'''

        if kwargs.pop('__instantiate', None):
            return super(DNSResponseHandler, cls).__new__(cls, *args, **kwargs)
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

    def _get_retry_qty(self, cause=None, consecutive=True):
        '''Return the number of retries associated with the DNS query, optionally limited to
        those with a given cause.'''

        if cause is None:
            return len(self._history)

        if consecutive:
            total = 0
            for i in range(len(self._history) - 1, -1, -1):
                if self._history[i].cause == cause:
                    total += 1
                else:
                    break
            return total

        return len(filter(lambda x: x.cause == cause, self._history))

    def _get_num_timeouts(self, response, consecutive=True):
        '''Return the number of retries attributed to timeouts.'''

        timeouts = self._get_retry_qty(RETRY_CAUSE_TIMEOUT, consecutive)
        if isinstance(response, dns.exception.Timeout):
            timeouts += 1
        return timeouts

    def _get_num_network_errors(self, response):
        '''Return the number of retries attributed to network errors.'''

        errors = self._get_retry_qty(RETRY_CAUSE_NETWORK_ERROR)
        if isinstance(response, (socket.error, EOFError)):
            errors += 1
        return errors

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
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_NETWORK_ERROR, errno1, RETRY_ACTION_NO_CHANGE, None)

class UseTCPOnTCFlagHandler(DNSResponseHandler):
    '''Retry with TCP if the TC flag is set in the response.'''

    def handle(self, response_wire, response, response_time):
        if response_wire is not None and ord(response_wire[2]) & 0x02:
            self._params['tcp'] = True
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TC_SET, len(response_wire), RETRY_ACTION_USE_TCP, None)

class DisableEDNSOnFormerrHandler(DNSResponseHandler):
    '''Disable EDNS if there was some type of issue parsing the message.  Some
    servers don't handle EDNS appropriately.'''

    def handle(self, response_wire, response, response_time):
        if isinstance(response, (struct.error, dns.exception.FormError, dns.exception.SyntaxError)) and self._request.edns >= 0:
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
        if timeouts >= self._timeouts and self._request.payload > self._reduced_payload:
            self._request.payload = self._reduced_payload
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TIMEOUT, None, RETRY_ACTION_CHANGE_UDP_MAX_PAYLOAD, self._reduced_payload)

class ClearDOFlagOnTimeoutHandler(DNSResponseHandler):
    '''Clear the EDNS DO flag after a given number of timeouts.  Some servers
    don't respond to requests with the DO flag set.'''

    def __init__(self, timeouts):
        self._timeouts = timeouts

    def handle(self, response_wire, response, response_time):
        timeouts = self._get_num_timeouts(response)
        if timeouts >= self._timeouts and (self._request.ednsflags & dns.flags.DO):
            self._request.want_dnssec(False)
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TIMEOUT, None, RETRY_ACTION_CLEAR_EDNS_FLAG, dns.flags.DO)

class DisableEDNSOnTimeoutHandler(DNSResponseHandler):
    '''Disable EDNS after a given number of timeouts.  Some servers don't
    respond to EDNS queries.'''

    def __init__(self, timeouts):
        self._timeouts = timeouts

    def handle(self, response_wire, response, response_time):
        timeouts = self._get_num_timeouts(response)
        if timeouts >= self._timeouts and self._request.edns >= 0:
            self._request.use_edns(False)
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TIMEOUT, None, RETRY_ACTION_DISABLE_EDNS, None)

class SetCDFlagOnServfailHandler(DNSResponseHandler):
    '''Set the CD flag when a SERVFAIL status is returned.  This is really used
    for analysis to determine if the cause of the SERVFAIL is related to DNSSEC
    validation failure.'''

    def handle(self, response_wire, response, response_time):
        if isinstance(response, dns.message.Message) and response.rcode() == dns.rcode.SERVFAIL and not self._request.flags & dns.flags.CD:
            self._request.flags |= dns.flags.CD
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_RCODE, response.rcode(), RETRY_ACTION_SET_FLAG, dns.flags.CD)

class DisableEDNSOnRcodeHandler(DNSResponseHandler):
    '''Disable EDNS if the RCODE in the response indicates that the server
    doesn't implement EDNS.'''

    def handle(self, response_wire, response, response_time):
        if isinstance(response, dns.message.Message) and response.rcode() in (dns.rcode.NOTIMP, dns.rcode.FORMERR, dns.rcode.SERVFAIL) and self._request.edns >= 0:
            self._request.use_edns(False)
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_RCODE, response.rcode(), RETRY_ACTION_DISABLE_EDNS, None)

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
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_NETWORK_ERROR, errno1, RETRY_ACTION_NO_CHANGE, None)

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

    def __init__(self, reduced_payload, initial_timeouts, bounding_timeout, subhandlers):
        self._reduced_payload = reduced_payload
        self._initial_timeouts = initial_timeouts
        self._bounding_timeout = bounding_timeout

        self._subhandlers = [h.build() for h in subhandlers]

        self._lower_bound = None
        self._upper_bound = None
        self._water_mark = None
        self._state = self.START

    def set_context(self, params, history, request):
        '''Set local parameters pertaining to DNS query.'''

        super(PMTUBoundingHandler, self).set_context(params, history, request)
        for handler in self._subhandlers:
            handler.set_context(params, history, request)

    def handle_sub(self, response_wire, response, response_time):
        for handler in self._subhandlers:
            handler.handle(response_wire, response, response_time)

    def handle(self, response_wire, response, response_time):
        timeouts = self._get_num_timeouts(response)
        is_timeout = isinstance(response, dns.exception.Timeout)
        is_valid = isinstance(response, dns.message.Message) and response.rcode() in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN)

        if self._request.edns < 0 or not (self._request.ednsflags & dns.flags.DO):
            self._state = self.INVALID

        if self._state == self.INVALID:
            self.handle_sub(response_wire, response, response_time)

        elif self._state == self.START:
            self.handle_sub(response_wire, response, response_time)
            if timeouts >= self._initial_timeouts:
                self._lower_bound = self._reduced_payload
                self._upper_bound = self._request.payload - 1
                self._request.payload = self._reduced_payload
                self._state = self.REDUCED_PAYLOAD
                return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TIMEOUT, None, RETRY_ACTION_CHANGE_UDP_MAX_PAYLOAD, self._reduced_payload)

        elif self._state == self.REDUCED_PAYLOAD:
            self.handle_sub(response_wire, response, response_time)
            if not is_timeout:
                if (response_wire is not None and ord(response_wire[2]) & 0x02) or is_valid:
                    self._lower_bound = self._water_mark = len(response_wire)
                    self._params['timeout'] = self._bounding_timeout
                    self._params['tcp'] = True
                    self._state = self.USE_TCP
                    if response_wire is not None and ord(response_wire[2]) & 0x02:
                        return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TC_SET, len(response_wire), RETRY_ACTION_USE_TCP, None)
                    else:
                        return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_DIAGNOSTIC, len(response_wire), RETRY_ACTION_USE_TCP, None)

        elif self._state == self.USE_TCP:
            if not is_timeout and is_valid:
                #XXX this is cheating because we're not reporting the change to UDP
                self._params['tcp'] = False
                payload = len(response_wire) - 1
                self._request.payload = payload
                self._state = self.TCP_MINUS_ONE
                return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_DIAGNOSTIC, len(response_wire), RETRY_ACTION_CHANGE_UDP_MAX_PAYLOAD, payload)
            
        elif self._state == self.TCP_MINUS_ONE:
            if is_timeout:
                self._upper_bound = self._request.payload - 1
                payload = self._lower_bound + (self._upper_bound + 1 - self._lower_bound)/2
                self._request.payload = payload
                self._state = self.PICKLE
                return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TIMEOUT, None, RETRY_ACTION_CHANGE_UDP_MAX_PAYLOAD, payload)
            # if the size of the message is less than the watermark, then perhaps we were rate limited
            elif response_wire is not None and len(response_wire) < self._water_mark:
                # but if this isn't the first time, just quit.  it could be that
                # the server simply has some wonky way of determining how/where to truncate.
                if self._history[-1].cause == RETRY_CAUSE_DIAGNOSTIC and self._history[-1].action == RETRY_ACTION_NO_CHANGE:
                    self._params['tcp'] = True
                    self._state = self.TCP_FINAL
                    return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_DIAGNOSTIC, None, RETRY_ACTION_USE_TCP, None)
                else:
                    self._params['wait'] = 1.0
                    return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_DIAGNOSTIC, None, RETRY_ACTION_NO_CHANGE, None)
            # if the response was truncated, then the size of the payload
            # received via TCP is the largest we can receive
            elif response_wire is not None and ord(response_wire[2]) & 0x02:
                self._params['tcp'] = True
                self._state = self.TCP_FINAL
                return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TC_SET, len(response_wire), RETRY_ACTION_USE_TCP, None)

        elif self._state == self.PICKLE:
            if self._upper_bound - self._lower_bound <= 1:
                self._params['tcp'] = True
                self._state = self.TCP_FINAL
                if response_wire is not None and ord(response_wire[2]) & 0x02:
                    return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TC_SET, len(response_wire), RETRY_ACTION_USE_TCP, None)
                elif is_timeout:
                    return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TIMEOUT, None, RETRY_ACTION_USE_TCP, None)
                elif not is_valid:
                    return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_DIAGNOSTIC, None, RETRY_ACTION_USE_TCP, None)
            elif is_timeout:
                self._upper_bound = self._request.payload - 1
                payload = self._lower_bound + (self._upper_bound + 1 - self._lower_bound)/2
                self._request.payload = payload
                return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TIMEOUT, None, RETRY_ACTION_CHANGE_UDP_MAX_PAYLOAD, payload)
            # if the size of the message is less than the watermark, then perhaps we were rate limited
            elif len(response_wire) < self._water_mark:
                # but if this isn't the first time, just quit.  it could be that
                # the server simply has some wonky way of determining how/where to truncate.
                if self._history[-1].cause == RETRY_CAUSE_DIAGNOSTIC and self._history[-1].action == RETRY_ACTION_NO_CHANGE:
                    self._params['tcp'] = True
                    self._state = self.TCP_FINAL
                    return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_DIAGNOSTIC, None, RETRY_ACTION_USE_TCP, None)
                else:
                    self._params['wait'] = 1.0
                    return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_DIAGNOSTIC, None, RETRY_ACTION_NO_CHANGE, None)
            elif is_valid:
                self._lower_bound = self._request.payload
                payload = self._lower_bound + (self._upper_bound + 1 - self._lower_bound)/2
                self._request.payload = payload
                return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_DIAGNOSTIC, len(response_wire), RETRY_ACTION_CHANGE_UDP_MAX_PAYLOAD, payload)

        elif self._state == self.TCP_FINAL:
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

    reuse_sport = True

    def handle(self, response_wire, response, response_time):
        if isinstance(response, dns.exception.Timeout):
            return DNSQueryRetryAttempt(response_time, RETRY_CAUSE_TIMEOUT, None, RETRY_ACTION_NO_CHANGE, None)

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

    def __init__(self, request, params, response_handlers, lifetime, server, client, port):
        self.request = request
        self.params = params
        self._response_handlers = response_handlers
        self.history = []
        self._server = server
        self._client = client
        self._port = port

        for handler in self._response_handlers:
            handler.set_context(self.params, self.history, self.request)

        if lifetime is not None:
            self._expiration = time.time() + lifetime
        else:
            self._expiration = None

        self._set_query_time()

    def _set_query_time(self):
        self.query_time = time.time() + self.params['wait']

    def _reset_wait(self):
        self.params['wait'] = 0

    def get_query_transport_meta(self, response_queue):
        return transport.DNSQueryTransportMeta(self.request.to_wire(), self._server, self.params['tcp'], self.get_timeout(), \
                self._port, src=self._client, sport=self.params['sport'], processed_queue=response_queue)

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

    def handle_response(self, response_wire, response, response_time, sport):
        retry_action = None
        try:
            for handler in self._response_handlers:
                if retry_action is None:
                    retry_action = handler.handle(response_wire, response, response_time)
                    if retry_action is not None:
                        if handler.reuse_sport and not self.params['tcp']:
                            self.params['sport'] = sport
                        else:
                            self.params['sport'] = None
                elif isinstance(handler, ActionIndependentDNSResponseHandler):
                    handler.handle(response_wire, response, response_time)

            if retry_action is not None:
                self.history.append(retry_action)

            self._set_query_time()
            self._reset_wait()

        except AcceptResponse:
            return response

class AggregateDNSResponse(object):
    def __init__(self):
        self.rdata_answer_info = {}
        self.cname_answer_info = {}
        self.rrset_answer_info = []
        self.rrset_noanswer_info = {}
        self.nxdomain_info = {}
        self.nsec_set_info = []
        self.nsec_set_info_by_server = {}
        self.error_rcode = {}
        self.error = {}

    def _aggregate_response(self, server, client, response, qname, rdtype, bailiwick):
        if response.is_valid_response():
            if response.is_complete_response():
                is_referral = response.is_referral(qname, rdtype, bailiwick)
                self._aggregate_answer(server, client, response, is_referral, qname, rdtype)
                if not is_referral or response.is_referral(qname, rdtype, bailiwick, proper=True):
                    self._aggregate_nsec(server, client, response, is_referral) 
        else:
            self._aggregate_error(server, client, response)

    def _aggregate_answer(self, server, client, response, referral, qname, rdtype):
        msg = response.message

        # sort with the most specific DNAME infos first
        dname_rrsets = filter(lambda x: x.rdtype == dns.rdatatype.DNAME, msg.answer)
        dname_rrsets.sort(reverse=True)

        qname_sought = qname
        try:
            i = 0
            while i < MAX_CNAME_REDIRECTION:

                # synthesize a CNAME from a DNAME, if possible
                synthesized_cname_info = None
                for dname_rrset in dname_rrsets:
                    if qname_sought.parent().is_subdomain(dname_rrset.name):
                        synthesized_cname_info = RRsetInfo(cname_from_dname(qname_sought, dname_rrset), RRsetInfo(dname_rrset))
                        break

                try:
                    rrset_info = self._aggregate_answer_rrset(server, client, response, qname_sought, rdtype)

                    # if there was a synthesized CNAME, add it to the rrset_info
                    if rrset_info.rrset.rdtype == dns.rdatatype.CNAME and synthesized_cname_info is not None:
                        synthesized_cname_info = rrset_info.create_or_update_cname_from_dname_info(synthesized_cname_info, server, client, response)
                        self._update_rrsig_info(server, client, response, msg.answer, synthesized_cname_info.dname_info)

                except KeyError:
                    if synthesized_cname_info is None:
                        raise
                    synthesized_cname_info = self._insert_rrset(server, client, synthesized_cname_info, response)
                    self._update_rrsig_info(server, client, response, msg.answer, synthesized_cname_info.dname_info)

                if rrset_info.rrset.rdtype == dns.rdatatype.CNAME:
                    qname_sought = rrset_info.rrset[0].target
                else:
                    break
                i += 1
        except KeyError:
            if referral:
                return

            # don't store no answer or NXDOMAIN info for names other than qname
            # if recursion is not desired and available
            if qname_sought != qname and not response.recursion_desired_and_available():
                return

            try:
                soa_rrsets = filter(lambda x: x.rdtype == dns.rdatatype.SOA and qname_sought.is_subdomain(x.name), msg.authority)
                if not soa_rrsets:
                    soa_rrsets = filter(lambda x: x.rdtype == dns.rdatatype.SOA, msg.authority)
                soa_rrsets.sort(reverse=True)
                soa_owner_name = soa_rrsets[0].name
            except IndexError:
                soa_owner_name = None

            if msg.rcode() == dns.rcode.NXDOMAIN:
                if qname_sought not in self.nxdomain_info:
                    self.nxdomain_info[qname_sought] = {}
                if soa_owner_name not in self.nxdomain_info[qname_sought]:
                    self.nxdomain_info[qname_sought][soa_owner_name] = {}
                if (server,client) not in self.nxdomain_info[qname_sought][soa_owner_name]:
                    self.nxdomain_info[qname_sought][soa_owner_name][(server,client)] = []
                self.nxdomain_info[qname_sought][soa_owner_name][(server,client)].append(response)
            else:
                if qname_sought not in self.rrset_noanswer_info:
                    self.rrset_noanswer_info[qname_sought] = {}
                if soa_owner_name not in self.rrset_noanswer_info[qname_sought]:
                    self.rrset_noanswer_info[qname_sought][soa_owner_name] = {}
                if (server,client) not in self.rrset_noanswer_info[qname_sought][soa_owner_name]:
                    self.rrset_noanswer_info[qname_sought][soa_owner_name][(server,client)] = []
                self.rrset_noanswer_info[qname_sought][soa_owner_name][(server,client)].append(response)

    def _update_rrsig_info(self, server, client, response, section, rrset_info):
        msg = response.message
        try:
            rrsig_rrset = msg.find_rrset(section, rrset_info.rrset.name, dns.rdataclass.IN, dns.rdatatype.RRSIG, rrset_info.rrset.rdtype)
            for rrsig in rrsig_rrset:
                rrset_info.create_or_update_rrsig_info(rrsig, rrsig_rrset.ttl, server, client, response)
        except KeyError:
            pass

    def _aggregate_answer_rrset(self, server, client, response, qname, rdtype):
        msg = response.message

        try:
            rrset = msg.find_rrset(msg.answer, qname, dns.rdataclass.IN, rdtype)
            answer_info = self.rdata_answer_info
        except KeyError:
            rrset = msg.find_rrset(msg.answer, qname, dns.rdataclass.IN, dns.rdatatype.CNAME)
            answer_info = self.cname_answer_info

        rrset_info = RRsetInfo(rrset)
        rrset_info = self._insert_rrset(server, client, rrset_info, response)

        for rr in rrset:
            if rr not in answer_info:
                answer_info[rr] = set()
            answer_info[rr].add(rrset_info)

        self._update_rrsig_info(server, client, response, msg.answer, rrset_info)

        return rrset_info

    def _insert_rrset(self, server, client, rrset_info, response):
        try:
            index = self.rrset_answer_info.index(rrset_info)
            rrset_info = self.rrset_answer_info[index]
        except ValueError:
            self.rrset_answer_info.append(rrset_info)

        if (server, client) not in rrset_info.servers_clients:
            rrset_info.servers_clients[(server, client)] = []
        rrset_info.servers_clients[(server, client)].append(response)

        return rrset_info

    def _aggregate_nsec(self, server, client, response, referral):
        msg = response.message

        self.nsec_set_info_by_server[response] = []
        for rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
            nsec_rrsets = filter(lambda x: x.rdtype == rdtype, msg.authority)

            if not nsec_rrsets:
                continue

            nsec_set_info = NSECSet(nsec_rrsets, referral)
            try:
                index = self.nsec_set_info.index(nsec_set_info)
                nsec_set_info = self.nsec_set_info[index]
            except ValueError:
                self.nsec_set_info.append(nsec_set_info)
            nsec_set_info.add_server_client(server, client, response)

            for name in nsec_set_info.rrsets:
                self._update_rrsig_info(server, client, response, msg.authority, nsec_set_info.rrsets[name])

            self.nsec_set_info_by_server[response].append(nsec_set_info)

    def _aggregate_error(self, server, client, response):
        msg = response.message
        if msg is None:
            if (response.error, response.errno) not in self.error:
                self.error[(response.error, response.errno)] = set()
            self.error[(response.error, response.errno)].add((server, client))
        else:
            if msg.rcode() not in self.error_rcode:
                self.error_rcode[msg.rcode()] = set()
            self.error_rcode[msg.rcode()].add((server, client))

class DNSQuery(AggregateDNSResponse):
    '''An simple DNS Query and its responses.'''

    def __init__(self, qname, rdtype, rdclass,
            flags, edns, edns_max_udp_payload, edns_flags, edns_options):

        super(DNSQuery, self).__init__()

        self.qname = qname
        self.rdtype = rdtype
        self.rdclass = rdclass
        self.flags = flags
        self.edns = edns
        self.edns_max_udp_payload = edns_max_udp_payload
        self.edns_flags = edns_flags
        self.edns_options = edns_options

        self.responses = {}

    def copy(self, bailiwick_map, default_bailiwick, with_responses=True):
        '''Return a clone of the current DNSQuery instance.  Parameters are
        passed by reference rather than copied.  Note: if it turns out that
        these member variables might be modified somehow by other instances in
        future use, then these will need to be copies.'''

        clone = DNSQuery(self.qname, self.rdtype, self.rdclass,
                self.flags, self.edns, self.edns_max_udp_payload, self.edns_flags, self.edns_options)

        if with_responses:
            for server in self.responses:
                bailiwick = bailiwick_map.get(server, default_bailiwick)
                for client, response in self.responses[server].items():
                    clone.add_response(server, client, response.copy(), bailiwick)

        return clone

    def join(self, query, bailiwick_map, default_bailiwick):
        if not (isinstance(query, DNSQuery)):
            raise ValueError('A DNSQuery instance can only be joined with another DNSQuery instance.')

        if not (self.qname == query.qname and self.rdtype == query.rdtype and \
                self.rdclass == query.rdclass and self.flags == query.flags and \
                self.edns == query.edns and self.edns_max_udp_payload == query.edns_max_udp_payload and \
                self.edns_flags == query.edns_flags and self.edns_options == query.edns_options):
            raise ValueError('DNS query parameters for DNSQuery instances being joined must be the same.')

        clone = self.copy(bailiwick_map, default_bailiwick)
        for server in query.responses:
            bailiwick = bailiwick_map.get(server, default_bailiwick)
            for client, response in query.responses[server].items():
                clone.add_response(server, client, response.copy(), bailiwick)
        return clone

    def project(self, servers, bailiwick_map, default_bailiwick):
        if servers.difference(self.responses):
            raise ValueError('A DNSQuery can only project responses from servers that have been queried.')

        clone = self.copy(bailiwick_map, default_bailiwick, with_responses=False)
        for server in servers:
            bailiwick = bailiwick_map.get(server, default_bailiwick)
            for client, response in self.responses[server].items():
                clone.add_response(server, client, response.copy(), bailiwick)
        return clone

    def add_response(self, server, client, response, bailiwick):
        if server not in self.responses:
            self.responses[server] = {}
        if response.query is not None:
            raise ValueError('Response is already associated with a query.')
        if client in self.responses[server]:
            raise ValueError('Response from server %s to client %s already exists.' % (server, client))
        response.query = self
        self.responses[server][client] = response

        flags = self.flags
        edns = self.edns
        edns_max_udp_payload = self.edns_max_udp_payload
        edns_flags = self.edns_flags
        edns_options = self.edns_options[:]

        for retry in response.history:
            if retry.action == RETRY_ACTION_SET_FLAG:
                flags |= retry.action_arg
            elif retry.action == RETRY_ACTION_CLEAR_FLAG:
                flags &= ~retry.action_arg
            elif retry.action == RETRY_ACTION_DISABLE_EDNS:
                edns = -1
            elif retry.action == RETRY_ACTION_CHANGE_UDP_MAX_PAYLOAD:
                edns_max_udp_payload = retry.action_arg
            elif retry.action == RETRY_ACTION_SET_EDNS_FLAG:
                edns_flags |= retry.action_arg
            elif retry.action == RETRY_ACTION_CLEAR_EDNS_FLAG:
                edns_flags &= ~retry.action_arg
            #XXX do the same with EDNS options

        response.set_effective_request_options(flags, edns, edns_max_udp_payload, edns_flags, edns_options)

        self._aggregate_response(server, client, response, self.qname, self.rdtype, bailiwick)

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
    
    def servers_with_valid_complete_response(self, bailiwick_map, default_bailiwick):
        servers_clients = set()
        for server in self.responses:
            bailiwick = bailiwick_map.get(server, default_bailiwick)
            for client, response in self.responses[server].items():
                if response.is_valid_response() and response.is_complete_response() and not response.is_referral(self.qname, self.rdtype, bailiwick):
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

    def serialize(self):
        d = collections.OrderedDict((
            ('qname', self.qname.to_text()),
            ('qclass', dns.rdataclass.to_text(self.rdclass)),
            ('qtype', dns.rdatatype.to_text(self.rdtype)),
            ('flags', self.flags),
        ))
        if self.edns >= 0:
            d['edns_version'] = self.edns
            d['edns_max_udp_payload'] = self.edns_max_udp_payload
            d['edns_flags'] = self.edns_flags
            d['edns_options'] = []
            for o in self.edns_options:
                s = StringIO.StringIO()
                o.to_wire(s)
                d['edns_options'].append(base64.b64encode(s.getvalue()))

        d['responses'] = collections.OrderedDict()
        servers = self.responses.keys()
        servers.sort()
        for server in servers:
            d['responses'][server] = collections.OrderedDict()
            clients = self.responses[server].keys()
            clients.sort()
            for client in clients:
                d['responses'][server][client] = self.responses[server][client].serialize()

        return d

    @classmethod
    def deserialize(self, d, bailiwick_map, default_bailiwick):
        qname = dns.name.from_text(d['qname'])
        rdclass = dns.rdataclass.from_text(d['qclass'])
        rdtype = dns.rdatatype.from_text(d['qtype'])
        flags = d['flags']
        if 'edns_version' in d:
            edns = d['edns_version']
            edns_max_udp_payload = d['edns_max_udp_payload']
            edns_flags = d['edns_flags']
            edns_options = []
            for o in d['edns_options']:
                #XXX from_wire
                #edns_options.append(foo)
                pass
        else:
            edns = None
            edns_max_udp_payload = None
            edns_flags = None
            edns_options = []

        q = DNSQuery(qname, rdtype, rdclass,
                flags, edns, edns_max_udp_payload, edns_flags, edns_options)

        for server in d['responses']:
            bailiwick = bailiwick_map.get(IPAddr(server), default_bailiwick)
            for client in d['responses'][server]:
                q.add_response(IPAddr(server), IPAddr(client), DNSResponse.deserialize(d['responses'][server][client]), bailiwick)
        return q

class MultiQuery(AggregateDNSResponse):
    '''An simple DNS Query and its responses.'''

    def __init__(self, qname, rdtype, rdclass):
        super(MultiQuery, self).__init__()
        self.qname = qname
        self.rdtype = rdtype
        self.rdclass = rdclass

        self.queries = {}

    def add_query(self, query, bailiwick_map, default_bailiwick):
        if not (self.qname == query.qname and self.rdtype == query.rdtype and self.rdclass == query.rdclass):
            raise ValueError('DNS query information must be the same as that to which query is being joined.')

        edns_options_str = ''
        for o in query.edns_options:
            s = StringIO.StringIO()
            o.to_wire(s)
            edns_options_str += o.getvalue()
        params = (query.flags, query.edns, query.edns_max_udp_payload, query.edns_flags, edns_options_str)
        if params in self.queries:
            self.queries[params] = self.queries[params].join(query, bailiwick_map, default_bailiwick)
        else:
            self.queries[params] = query
        for server in query.responses:
            bailiwick = bailiwick_map.get(server, default_bailiwick)
            for client, response in query.responses[server].items():
                self._aggregate_response(server, client, response, self.qname, self.rdtype, bailiwick)

    def project(self, servers, bailiwick_map, default_bailiwick):
        query = MultiQuery(self.qname, self.rdtype, self.rdclass)

        for params in self.queries:
            query.add_query(self.queries[params].project(servers, bailiwick_map, default_bailiwick))
        return query

class ExecutableDNSQuery(DNSQuery):
    '''An executable DNS Query.'''

    def __init__(self, qname, rdtype, rdclass, servers, bailiwick,
            client_ipv4, client_ipv6, port, tcp,
            flags, edns, edns_max_udp_payload, edns_flags, edns_options,
            response_handlers, query_timeout, max_attempts, lifetime):

        super(ExecutableDNSQuery, self).__init__(qname, rdtype, rdclass,
                flags, edns, edns_max_udp_payload, edns_flags, edns_options)

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
        self.tcp = tcp
        self.response_handlers = response_handlers

        self.query_timeout = query_timeout

        if lifetime is None and max_attempts is None:
            raise ValueError("At least one of lifetime or max_attempts must be specified for an ExecutableDNSQuery instance.")
        self.max_attempts = max_attempts
        self.lifetime = lifetime

        self._executed = False

    def get_query_handler(self, server):
        request = dns.message.Message()
        request.flags = self.flags
        request.find_rrset(request.question, self.qname, self.rdclass, self.rdtype, create=True, force_unique=True)
        request.use_edns(self.edns, self.edns_flags, self.edns_max_udp_payload, self.edns_options[:])

        if ':' in server:
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

        return DNSQueryHandler(request, params, response_handlers, self.lifetime, server, client, self.port)
        
    @classmethod
    def execute_queries(cls, *queries):
        '''Excecute the query to a given server, and handle it appropriately.'''

        th = transport.get_default_dns_transport_handler()

        request_list = []
        response_queue = Queue.Queue()

        queries_to_execute = set()
        query_handlers = {}
        for query in queries:
            for server in query.servers.difference(query.responses):
                qh = query.get_query_handler(server)
                qtm = qh.get_query_transport_meta(response_queue)
                bisect.insort(request_list, (qh.query_time, qtm))
                query_handlers[qtm] = query, qh
                queries_to_execute.add(query)

        while queries_to_execute:
            while request_list and time.time() >= request_list[0][0]:
                th.query_nowait(request_list.pop(0)[1])

            t = time.time()
            if request_list and t < request_list[0][0]:
                timeout = max(request_list[0][0] - t, 0)
            else:
                timeout = None

            try:
                # pull a response from the queue
                qtm = response_queue.get(timeout=timeout)

                # find its matching query meta information
                query, qh = query_handlers.pop(qtm)

                # define response as either a Message created from parsing
                # the wire response or an Exception
                if qtm.err is not None:
                    response = qtm.err
                else:
                    try:
                        response = dns.message.from_wire(qtm.res)
                    except Exception, e:
                        response = e
                if qtm.res:
                    msg_size = len(qtm.res)
                else:
                    msg_size = None
                response_time = round(qtm.end_time - qtm.start_time, 3)
                response = qh.handle_response(qtm.res, response, response_time, qtm.sport)

                # if no response was returned, then resubmit the modified query
                if response is None:
                    qtm = qh.get_query_transport_meta(response_queue)
                    bisect.insort(request_list, (qh.query_time, qtm))
                    query_handlers[qtm] = query, qh
                # otherwise store away the response (or error), history, and response time
                else:
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
                        elif isinstance(response, (struct.error, dns.exception.FormError, dns.exception.SyntaxError)):
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
                    response_obj = DNSResponse(msg, msg_size, err, errno1, qh.history, response_time, query.tcp)
                    query.add_response(IPAddr(qtm.dst), IPAddr(qtm.src), response_obj, query.bailiwick)

                    if not query.servers.difference(query.responses):
                        queries_to_execute.remove(query)
                        query._executed = True

            except Queue.Empty:
                pass

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
    def execute(self):
        self.execute_queries(self)

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
            client_ipv4=None, client_ipv6=None, port=53, tcp=None,
            query_timeout=None, max_attempts=None, lifetime=None,
            executable=True):

        if tcp is None:
            tcp = cls.tcp
        if query_timeout is None:
            query_timeout = cls.query_timeout
        if max_attempts is None:
            max_attempts = cls.max_attempts
        if lifetime is None:
            lifetime = cls.lifetime

        if executable:
            return ExecutableDNSQuery(qname, rdtype, rdclass, servers, bailiwick,
                client_ipv4, client_ipv6, port, tcp,
                cls.flags, cls.edns, cls.edns_max_udp_payload, cls.edns_flags, cls.edns_options,
                cls.response_handlers, query_timeout, max_attempts, lifetime)

        else:
            return DNSQuery(qname, rdtype, rdclass,
                cls.flags, cls.edns, cls.edns_max_udp_payload, cls.edns_flags, cls.edns_options)

    def __init__(self, *args, **kwargs):
        raise NotImplemented()


class SimpleDNSQuery(DNSQueryFactory):
    '''A simple query, no frills.'''

    pass

class RecursiveDNSQuery(SimpleDNSQuery):
    '''A simple recursive query.'''

    flags = SimpleDNSQuery.flags | dns.flags.RD

class StandardQuery(SimpleDNSQuery):
    '''A standard old-school DNS query that handles truncated packets.'''

    response_handlers = SimpleDNSQuery.response_handlers + [UseTCPOnTCFlagHandler()]

class StandardRecursiveQuery(StandardQuery, RecursiveDNSQuery):
    '''A standard old-school recursive DNS query that handles truncated packets.'''

    pass

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

class DiagnosticQuery(DNSSECQuery):
    '''A robust query with a number of handlers, designed to detect common DNS
    compatibility and connectivity issues.'''

    response_handlers = DNSSECQuery.response_handlers + \
            [DisableEDNSOnFormerrHandler(), DisableEDNSOnRcodeHandler(),
            ReduceUDPMaxPayloadOnTimeoutHandler(512, 4),
            ClearDOFlagOnTimeoutHandler(6), DisableEDNSOnTimeoutHandler(7),
            ChangeTimeoutOnTimeoutHandler(2.0, 3),
            ChangeTimeoutOnTimeoutHandler(1.0, 4), 
            ChangeTimeoutOnTimeoutHandler(2.0, 5)]
    # For timeouts:
    #  1 - no change
    #  2 - no change
    #  3 - change timeout to 2 seconds
    #  4 - reduce udp max payload to 512; change timeout to 1 second
    #  5 - change timeout to 2 seconds
    #  6 - clear DO flag
    #  7 - disable EDNS
    #  8 - return

    query_timeout = 1.0
    max_attempts = 8
    lifetime = 15.0

class RecursiveDiagnosticQuery(RecursiveDNSSECQuery):
    '''A robust query to a cache with a number of handlers, designed to detect
    common DNS compatibility and connectivity issues.'''

    response_handlers = DNSSECQuery.response_handlers + \
            [DisableEDNSOnFormerrHandler(), SetCDFlagOnServfailHandler(), DisableEDNSOnRcodeHandler(),
            ReduceUDPMaxPayloadOnTimeoutHandler(512, 4),
            ClearDOFlagOnTimeoutHandler(6), DisableEDNSOnTimeoutHandler(7),
            ChangeTimeoutOnTimeoutHandler(2.0, 3),
            ChangeTimeoutOnTimeoutHandler(1.0, 4), 
            ChangeTimeoutOnTimeoutHandler(2.0, 5)]
    # For timeouts:
    #  1 - no change
    #  2 - no change
    #  3 - change timeout to 2 seconds
    #  4 - reduce udp max payload to 512; change timeout to 1 second
    #  5 - change timeout to 2 seconds
    #  6 - clear DO flag
    #  7 - disable EDNS
    #  8 - return

    query_timeout = 1.0
    max_attempts = 8
    lifetime = 15.0

class TCPDiagnosticQuery(DNSSECQuery):
    '''A robust query with a number of handlers, designed to detect common DNS
    compatibility and connectivity issues, beginning with TCP.'''

    tcp = True

    response_handlers = [UseUDPOnNetworkErrorHandler(1), UseUDPOnTimeoutHandler(1),
            DisableEDNSOnFormerrHandler(), DisableEDNSOnRcodeHandler(),
            ReduceUDPMaxPayloadOnTimeoutHandler(512, 5),
            DisableEDNSOnTimeoutHandler(8),
            ChangeTimeoutOnTimeoutHandler(1.0, 1),
            ChangeTimeoutOnTimeoutHandler(2.0, 4),
            ChangeTimeoutOnTimeoutHandler(1.0, 5), 
            ChangeTimeoutOnTimeoutHandler(2.0, 6)]
    # For timeouts:
    #  1 - Change to UDP
    #  2 - no change
    #  3 - no change
    #  4 - change timeout to 2 seconds
    #  5 - reduce udp max payload to 512; change timeout to 1 second
    #  6 - change timeout to 2 seconds
    #  7 - clear DO flag
    #  8 - disable EDNS
    #  9 - return

    query_timeout = 4.0
    max_attempts = 9
    lifetime = 19.0

class RecursiveTCPDiagnosticQuery(RecursiveDNSSECQuery):
    '''A robust query with a number of handlers, designed to detect common DNS
    compatibility and connectivity issues, beginning with TCP.'''

    tcp = True

    response_handlers = [UseUDPOnNetworkErrorHandler(1), UseUDPOnTimeoutHandler(1),
            DisableEDNSOnFormerrHandler(), SetCDFlagOnServfailHandler(), DisableEDNSOnRcodeHandler(),
            ReduceUDPMaxPayloadOnTimeoutHandler(512, 5),
            DisableEDNSOnTimeoutHandler(8),
            ChangeTimeoutOnTimeoutHandler(1.0, 1),
            ChangeTimeoutOnTimeoutHandler(2.0, 4),
            ChangeTimeoutOnTimeoutHandler(1.0, 5), 
            ChangeTimeoutOnTimeoutHandler(2.0, 6)]
    # For timeouts:
    #  1 - Change to UDP
    #  2 - no change
    #  3 - no change
    #  4 - change timeout to 2 seconds
    #  5 - reduce udp max payload to 512; change timeout to 1 second
    #  6 - change timeout to 2 seconds
    #  7 - clear DO flag
    #  8 - disable EDNS
    #  9 - return

    query_timeout = 4.0
    max_attempts = 9
    lifetime = 19.0

class PMTUDiagnosticQuery(DNSSECQuery):
    
    response_handlers = [PMTUBoundingHandler(512, 4, 1.0,
            (MaxTimeoutsHandler(8),
                LifetimeHandler(15.0),
                ChangeTimeoutOnTimeoutHandler(2.0, 3),
                ChangeTimeoutOnTimeoutHandler(1.0, 4), 
                ChangeTimeoutOnTimeoutHandler(2.0, 5))),
            DisableEDNSOnFormerrHandler(), DisableEDNSOnRcodeHandler(),
            ClearDOFlagOnTimeoutHandler(6), DisableEDNSOnTimeoutHandler(7)]

    query_timeout = 1.0
    max_attempts = 15
    lifetime = 18.0

class RecursivePMTUDiagnosticQuery(RecursiveDNSSECQuery):

    response_handlers = [PMTUBoundingHandler(512, 4, 1.0,
            (MaxTimeoutsHandler(8),
                LifetimeHandler(15.0),
                ChangeTimeoutOnTimeoutHandler(2.0, 3),
                ChangeTimeoutOnTimeoutHandler(1.0, 4), 
                ChangeTimeoutOnTimeoutHandler(2.0, 5))),
            DisableEDNSOnFormerrHandler(), SetCDFlagOnServfailHandler(), DisableEDNSOnRcodeHandler(),
            ClearDOFlagOnTimeoutHandler(6), DisableEDNSOnTimeoutHandler(7)]

    query_timeout = 1.0
    max_attempts = 15
    lifetime = 18.0

class TruncationDiagnosticQuery(DNSSECQuery):
    '''A simple query to test the results of a query with capabilities of only
    receiving back a small (512 byte) payload.'''

    response_handlers = [ChangeTimeoutOnTimeoutHandler(2.0, 3)]
    # For timeouts:
    #  1 - no change
    #  2 - no change
    #  3 - change timeout to 2 seconds

    edns_max_udp_payload = 512

    query_timeout = 1.0
    max_attempts = 4
    lifetime = 5.0

class RecursiveTruncationDiagnosticQuery(DNSSECQuery, RecursiveDNSQuery):
    '''A simple recursive query to test the results of a query with
    capabilities of only receiving back a small (512 byte) payload.'''

    response_handlers = [ChangeTimeoutOnTimeoutHandler(2.0, 3)]
    # For timeouts:
    #  1 - no change
    #  2 - no change
    #  3 - change timeout to 2 seconds

    edns_max_udp_payload = 512

    query_timeout = 1.0
    max_attempts = 4
    lifetime = 5.0

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
    d = cls(dns.name.from_text(args[0]), dns.rdatatype.from_text(args[1]), dns.rdataclass.IN, args[2:])
    d.execute()

    if '-j' in opts:
        print json.dumps(d.serialize(), indent=4, separators=(',', ': '))
    else:
        print 'Responses for %s/%s:' % (args[0], args[1])
        for server in d.responses:
            for client, response in d.responses[server].items():
                if response.message is not None:
                    print '   from %s: %s (%d bytes in %dms)' % (server, repr(response.message), len(response.message.to_wire()), int(response.response_time*1000))
                else:
                    print '   from %s: (ERR: %s) (%dms)' % (server, repr(response.error), int(response.response_time*1000))

                print '   (src: %s)' % (client)
                if response.history:
                    print '       (history: %s)' % (response.history)

if __name__ == '__main__':
    main()
