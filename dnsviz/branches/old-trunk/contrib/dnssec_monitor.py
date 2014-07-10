#!/usr/bin/env python

import Queue
import signal
import smtplib
import socket
import struct
import sys
import threading
import time
import traceback

import dns.exception, dns.flags, dns.message, dns.name,\
    dns.query, dns.rdataclass, dns.rcode, dns.rdatatype

import pcapy
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder   

class DNSSECReporter:
    def __init__(self, server, dnssec_failures, other_failures, done, \
            mailhost, mail_from, rcpt):
        self.server = server
        self.dnssec_failures = dnssec_failures
        self.other_failures = other_failures
        self.done = done
        self.mailhost = mailhost
        self.mail_from = mail_from
        self.rcpt = rcpt

    def send_mail(self, msg):
        subject = 'DNS query failures from %s' % self.server

        # Add the From: and To: headers at the start!
        headers = ('From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n' % (self.mail_from, self.rcpt, subject))

        server = smtplib.SMTP(self.mailhost)
        server.sendmail(self.mail_from, self.rcpt, headers + msg)
        server.quit()

    def poll(self):
        while True:
            time.sleep(3600)
            self.report()

    def report(self, force=False):
        for (qname, rdtype), clients in self.other_failures.items():
            del self.other_failures[(qname, rdtype)]

        msg = ''
        for (qname, rdtype), clients in self.dnssec_failures.items():
            del self.dnssec_failures[(qname, rdtype)]
            msg += '%s/%s (%s)\r\n' % (qname.to_text(), dns.rdatatype.to_text(rdtype), ', '.join(clients))

        if msg or force:
            self.send_mail(msg)

    def report_on_signal(self, signum, frame):
        self.report(True)
                
class DNSSECAnalyst:
    def __init__(self, server, failure_queue, dnssec_failures, other_failures, done):
        self.server = server
        self.failure_queue = failure_queue
        self.dnssec_failures = dnssec_failures
        self.other_failures = other_failures
        self.done = done

    def poll(self):
        while True:
            qname, rdtype, client = self.failure_queue.get()

            if (qname, rdtype) in self.dnssec_failures:
                try:
                    self.dnssec_failures[(qname, rdtype)].add(client)
                except KeyError:
                    pass
                continue

            if (qname, rdtype) in self.other_failures:
                continue

            dnssec_failure = False
            try:
                response = self.directed_query(qname, rdtype, recurse=True, nocheck=True, timeout=0.2)
                if response is not None and response.rcode() != dns.rcode.SERVFAIL:
                    response = self.directed_query(qname, rdtype, recurse=True, nocheck=False, timeout=0.2)
                    dnssec_failure = response is None or response.rcode() == dns.rcode.SERVFAIL

            except dns.exception.DNSException, e:
                traceback.print_exception(*sys.exc_info())

            try:
                if dnssec_failure: 
                    self.dnssec_failures[(qname, rdtype)] = set()
                    self.dnssec_failures[(qname, rdtype)].add(client)
                else:
                    self.other_failures[(qname, rdtype)] = True
            except KeyError:
                # there could be a concurrency issue,
                # but it is of little consequence
                pass

    def directed_query(self, qname, rdtype, rdclass=dns.rdataclass.IN, \
            recurse=True, nocheck=True, dnssec=True, timeout=5.0, port=53):

        request = dns.message.make_query(qname, rdtype, rdclass)

        # try using EDNS first
        request.use_edns()

        if recurse:
            request.flags |= dns.flags.RD
        else:
            request.flags &= ~dns.flags.RD

        # if DNSSEC is desired, set the DO bit
        if dnssec:
            request.want_dnssec(True)

        # if we want to do our own check for
        # validation
        if nocheck:
            request.flags |= dns.flags.CD

        try:
            return dns.query.udp(request, self.server, timeout, port)
        # network related error
        except (socket.error, dns.query.UnexpectedSource), e:
            return None
        # malformed packet
        except (struct.error, dns.exception.FormError, IndexError), e:
            return None
        # no response
        except dns.exception.Timeout:
            return None

class ServFailMonitor:
    def __init__(self, server, device, failure_queue, done, snaplen=168):
        #snaplen 168 = 20 (IP) + 8 (udp) + 12 (DNS) + 128 (DNS data)
        self.server = server
        self.device = device
        self.snaplen = snaplen
        self.failure_queue = failure_queue
        self.done = done

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((server,53))
        self.client = s.getsockname()[0]
        self.client6 = None
        self.server6 = None

    def monitor(self):
        while True:
            try:
                pcapObj = pcapy.open_live(self.device, self.snaplen, 0, 1000)

                # At the moment the callback only accepts DNS UDP packets.
                filter_str = r'udp and src port 53'
                server_str = ''
                if self.server:
                    server_str += r'src %s' % self.server
                if self.server6:
                    if server_str:
                        server_str += ' or '
                    server_str += r'src %s' % self.server6
                if server_str:
                    filter_str += ' and (%s)' % server_str
                if self.client:
                    filter_str += r' and not dst %s' % self.client
                if self.client6:
                    filter_str += r' and not dst %s' % self.client6
                pcapObj.setfilter(filter_str)

                # Query the type of the link and instantiate a decoder accordingly.
                datalink = pcapObj.datalink()
                if pcapy.DLT_EN10MB == datalink:
                    self.decoder = EthDecoder()
                elif pcapy.DLT_LINUX_SLL == datalink:
                    self.decoder = LinuxSLLDecoder()
                else:
                    raise Exception("Datalink type not supported: " % datalink)

                # Sniff ad infinitum.
                # PacketHandler shall be invoked by pcap for every packet.
                pcapObj.loop(-1, self.packetHandler)

            except pcapy.PcapError:
                traceback.print_exception(*sys.exc_info())
            except KeyboardInterrupt:
                return
            except:
                traceback.print_exception(*sys.exc_info())
            time.sleep(1)

    def packetHandler(self, hdr, data):
        # Use the ImpactDecoder to turn the rawpacket into a hierarchy
        # of ImpactPacket instances.
        p = self.decoder.decode(data)
        ip = p.child()
        udp = ip.child()
        dns_wire = udp.get_data_as_string()

        try:
            rcode_byte, = struct.unpack('B', dns_wire[3])
            num_questions, = struct.unpack('!H', dns_wire[4:6])
        except struct.error, e:
            sys.stderr.write('warning: %s\n' % e)
            return

        rcode = rcode_byte & 0x0f

        # return if not a failure
        if rcode != dns.rcode.SERVFAIL:
            return
        # return if no question section
        if not num_questions:
            return

        # try to decode name and RR type
        try:
            index = 12
            qname, length = dns.name.from_wire(dns_wire, 12)
            index += length
            rdtype, = struct.unpack('!H', dns_wire[index:index+2])
        except (dns.exception.DNSException, IndexError, struct.error), e:
            sys.stderr.write('warning: %s raised: %s\n' % (e.__class__, e))
            return

        dst = ip.get_ip_dst()
        src = ip.get_ip_src()

        self.failure_queue.put((qname,rdtype,dst))
            
def main():
    if len(sys.argv) <= 5:
        sys.stderr.write("Usage: %s <server> <device> <mailhost> <mail_from> <rcpt>\n" % sys.argv[0])
        sys.exit(1)

    server, device, mailhost, mail_from, rcpt = sys.argv[1:6]

    failure_queue = Queue.Queue()
    dnssec_failures = {}
    other_failures = {}
    done = threading.Event()

    # Start decoding process.
    d = ServFailMonitor(server, device, failure_queue, done)
    a = DNSSECAnalyst(server, failure_queue, dnssec_failures, other_failures, done)
    r = DNSSECReporter(server, dnssec_failures, other_failures, done, mailhost, mail_from, rcpt)

    def exit(signum, frame):
        sys.exit(0)

    signal.signal(signal.SIGHUP, r.report_on_signal)
    signal.signal(signal.SIGINT, exit)

    # create a thread for each function, each a daemon,
    # so they will exit when the program exits
    monitor_thread = threading.Thread(target=d.monitor)
    analysis_thread = threading.Thread(target=a.poll)
    reporter_thread = threading.Thread(target=r.poll)
    monitor_thread.setDaemon(True)
    analysis_thread.setDaemon(True)
    reporter_thread.setDaemon(True)

    # start all threads
    monitor_thread.start()
    analysis_thread.start()
    reporter_thread.start()

    # join on the monitor thread
    while True:
        signal.pause()

# Process command-line arguments.
if __name__ == '__main__':
    main()
