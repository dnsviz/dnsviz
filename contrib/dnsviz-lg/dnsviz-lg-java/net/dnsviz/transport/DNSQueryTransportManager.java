/*
 * This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
 * analysis, and visualization.
 * Created by Casey Deccio (casey@deccio.net)
 *
 * Copyright 2016 VeriSign, Inc.
 *
 * DNSViz is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * DNSViz is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with DNSViz.  If not, see <http://www.gnu.org/licenses/>.
 */

package net.dnsviz.transport;

import java.io.IOException;
import java.net.SocketException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectableChannel;
import java.nio.channels.Selector;
import java.nio.channels.SelectionKey;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Date;
import java.util.Iterator;
import java.util.PriorityQueue;
import java.util.Set;

public class DNSQueryTransportManager {
	public void DNSQueryTransportManager() {
	}

	private void prepareAndQueue(DNSQueryTransportHandler qh, PriorityQueue<DNSQueryTransportHandler> q, Selector selector) throws IOException {
		qh.prepare();
		if (!qh.hasError()) {
			// if we successfully bound and connected the socket, then register this
			// socket in the write fd list
			((SelectableChannel)qh.getChannel()).register(selector, qh.getInitialSelectionOp(), qh);
			q.add(qh);
		}
	}

	public void query(DNSQueryTransportHandler [] queryHandlers) throws IOException {
		int i;
		int timeout;
		DNSQueryTransportHandler qh = null;
		DNSQueryTransportHandler standbyQH = null;
		DNSQueryTransportHandlerComparator cmp = new DNSQueryTransportHandlerComparator();
		PriorityQueue<DNSQueryTransportHandler> standbyQueue = new PriorityQueue<DNSQueryTransportHandler>(queryHandlers.length, cmp);
		PriorityQueue<DNSQueryTransportHandler> activeQueue = new PriorityQueue<DNSQueryTransportHandler>(queryHandlers.length, cmp);

		Selector selector = Selector.open();
		for (i = 0; i < queryHandlers.length; i++) {
			qh = queryHandlers[i];
			try {
				prepareAndQueue(qh, activeQueue, selector);
			} catch (IOException ex) {
				if (ex instanceof SocketException && ex.getMessage().contains("maximum number of ")) {
					/* if we couldn't create the socket because too many datagrams were
					 * open, then place this one in the standbyQueue */
					standbyQueue.add(qh);
				} else {
					throw ex;
				}
			}
		}

		while (activeQueue.peek() != null) {
			Date d = new Date();
			long currTime = d.getTime();

			// remove expired entries
			while (((qh = activeQueue.peek()) != null) && currTime >= qh.getExpiration()) {
				// remove the qh from the priority queue, and run doTimeout()
				qh = activeQueue.poll();
				qh.doTimeout();

				if (qh.getChannel() instanceof DatagramChannel) {
					/* prepare and queue one from the standbyQueue, now that
					 * there's a space available */
					standbyQH = standbyQueue.poll();
					if (standbyQH != null) {
						prepareAndQueue(standbyQH, activeQueue, selector);
					}
				}
			}
			if (qh == null) {
				// all entries have expired
				break;
			}

			timeout = (int)(qh.getExpiration() - currTime);
			/* timeout should never be less than 1 because of the loop termination test
			 * of the while loop above */

			selector.select(timeout);

			Set<SelectionKey> selectedKeys = selector.selectedKeys();
			Iterator<SelectionKey> keyIterator = selectedKeys.iterator();
			while (keyIterator.hasNext()) {
				SelectionKey key = keyIterator.next();
				qh = (DNSQueryTransportHandler)key.attachment();

				if ((key.interestOps() & SelectionKey.OP_CONNECT) != 0 && key.isConnectable()) {
					if (qh.finishConnect()) {
						if (qh.hasError()) {
							activeQueue.remove(qh);

							if (qh.getChannel() instanceof DatagramChannel) {
								/* prepare and queue one from the standbyQueue, now that
								 * there's a space available */
								standbyQH = standbyQueue.poll();
								if (standbyQH != null) {
									prepareAndQueue(standbyQH, activeQueue, selector);
								}
							}
							continue;
						} else {
							key.interestOps(SelectionKey.OP_WRITE);
						}
					}
				}

				if ((key.interestOps() & SelectionKey.OP_WRITE) != 0 && key.isWritable()) {
					if (qh.doWrite()) {
						if (qh.hasError()) {
							activeQueue.remove(qh);

							if (qh.getChannel() instanceof DatagramChannel) {
								/* prepare and queue one from the standbyQueue, now that
								 * there's a space available */
								standbyQH = standbyQueue.poll();
								if (standbyQH != null) {
									prepareAndQueue(standbyQH, activeQueue, selector);
								}
							}
							continue;
						} else {
							key.interestOps(SelectionKey.OP_READ);
						}
					}
				}

				if ((key.interestOps() & SelectionKey.OP_READ) != 0 && key.isReadable()) {
					if (qh.doRead()) {
						activeQueue.remove(qh);

						if (qh.getChannel() instanceof DatagramChannel) {
							/* prepare and queue one from the standbyQueue, now that
							 * there's a space available */

							standbyQH = standbyQueue.poll();
							if (standbyQH != null) {
								prepareAndQueue(standbyQH, activeQueue, selector);
							}
						}
						continue;
					}
				}
			}
		}
	}
}
