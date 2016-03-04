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
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SelectionKey;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

public class DNSQueryTransportHandlerUDP extends DNSQueryTransportHandler {
	public DNSQueryTransportHandlerUDP(byte [] req, InetAddress dst, int dport, InetAddress src, int sport, long timeout) {
		super(req, dst, dport, src, sport, timeout);
	}

	public int getInitialSelectionOp() {
		return SelectionKey.OP_WRITE;
	}

	public int getStartOfReqPayload() {
		return 0;
	}

	protected void initRequestBuffer(byte [] req) {
		this.req = ByteBuffer.allocate(req.length);
		this.req.clear();
		this.req.put(req);
		this.req.flip();
	}

	protected void initResponseBuffer() {
			//TODO start more conservative and dynamically grow if more buffer space is
			//needed
			res = ByteBuffer.allocate(65536);
	}

	protected void createSocket() throws IOException {
		channel = DatagramChannel.open();
	}

	protected void connect() throws IOException {
		class connectAction implements PrivilegedExceptionAction<Object> {
			public Object run() throws IOException {
				((DatagramChannel)channel).connect(new InetSocketAddress(dst, dport));
				return null;
			}
		}
		connectAction a = new connectAction();
		try {
			AccessController.doPrivileged(a);
		} catch (PrivilegedActionException pae) {
			Exception ex = pae.getException();
			if (ex instanceof IOException) {
				throw (IOException)ex;
			} else {
				throw (RuntimeException)ex;
			}
		}
	}

	public boolean finishConnect() {
		return true;
	}

	public boolean doRead() throws IOException {
		int bytesRead;

		class readAction implements PrivilegedExceptionAction<Object> {
			private int bytesRead;
			public Object run() throws IOException {
				bytesRead = ((ReadableByteChannel)channel).read(res);
				return null;
			}
			public int getBytesRead() {
				return bytesRead;
			}
		}
		readAction a = new readAction();
		try {
			AccessController.doPrivileged(a);
			bytesRead = a.getBytesRead();
		} catch (PrivilegedActionException pae) {
			Exception ex = pae.getException();
			if (ex instanceof IOException) {
				setError((IOException)ex);
				cleanup();
				return true;
			} else {
				throw (RuntimeException)ex;
			}
		}

		if (bytesRead < 1) {
			setError(Errno.ECONNREFUSED);
			cleanup();
			return true;
		}

		//TODO check response consistency
		res.limit(bytesRead);
		cleanup();
		return true;
	}

	protected void checkSource() {
		if (src != null && src.isAnyLocalAddress()) {
			src = null;
		}
	}
}
