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
import Queue

from django.utils.html import escape

class QueueForIteratorHandler(logging.Handler):
    def __init__(self, *args, **kwargs):
        logging.Handler.__init__(self, *args, **kwargs)
        self.queue = Queue.Queue()
        self.closed = False

    def __iter__(self):
        while True:
            try:
                s = self.queue.get(True, 3)
                yield s
            except Queue.Empty:
                if self.closed:
                    break

    def emit(self, record):
        self.queue.put(self.format(record))

    def close(self):
        logging.Handler.close(self)
        self.closed = True

class HTMLFormatter(logging.Formatter):
    def format(self, record):
        return '<div class="loglevel-%s">%s</div>' % (record.levelname.lower(), escape(record.getMessage()))
