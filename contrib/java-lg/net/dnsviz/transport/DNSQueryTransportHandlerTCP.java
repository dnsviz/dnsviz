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
import java.nio.channels.SocketChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SelectionKey;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

public class DNSQueryTransportHandlerTCP extends DNSQueryTransportHandler {
	protected boolean lengthKnown = false;

	public DNSQueryTransportHandlerTCP(byte [] req, InetAddress dst, int dport, InetAddress src, int sport, long timeout) {
		super(req, dst, dport, src, sport, timeout);
	}

	public int getInitialSelectionOp() {
		return SelectionKey.OP_CONNECT;
	}

	public int getStartOfReqPayload() {
		return 2;
	}

	protected void initRequestBuffer(byte [] req) {
		byte b1, b2;
		b1 = (byte)((req.length >> 8) & 0xff);
		b2 = (byte)(req.length & 0xff);
		this.req = ByteBuffer.allocate(req.length + 2);
		this.req.clear();
		this.req.put(b1);
		this.req.put(b2);
		this.req.put(req);
		this.req.flip();
	}

	protected void createSocket() throws IOException {
		channel = SocketChannel.open();
	}

	protected void connect() throws IOException {
		class connectAction implements PrivilegedExceptionAction<Object> {
			public Object run() throws IOException {
				((SocketChannel)channel).connect(new InetSocketAddress(dst, dport));
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

	public boolean finishConnect() throws IOException {
		try {
			return ((SocketChannel)channel).finishConnect();
		} catch (IOException ex) {
			setError(ex);
			cleanup();
			return true;
		}
	}

	public boolean doRead() throws IOException {
		int bytesRead;
		int len;
		byte b1, b2;
		ByteBuffer buf;

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
			setError(Errno.ECONNRESET);
			cleanup();
			return true;
		}

		if (!lengthKnown && res.position() > 1) {
			res.limit(res.position());
			b1 = res.get(0);
			b2 = res.get(1);
			len = ((b1 & 0xff) << 8) | (b2 & 0xff);
			buf = ByteBuffer.allocate(len);
			buf.clear();
			res.rewind().position(2);
			buf.put(res);
			res = buf;
			lengthKnown = true;
		}
		if (!res.hasRemaining()) {
			cleanup();
			return true;
		}
		return false;
	}

	protected InetAddress getLocalAddress() {
		InetAddress ret;
		try {
			final DatagramChannel c = DatagramChannel.open();
			class getAddrAction implements PrivilegedExceptionAction<InetSocketAddress> {
				public InetSocketAddress run() throws IOException {
					c.connect(new InetSocketAddress(dst, dport));
					return (InetSocketAddress)c.getLocalAddress();
				}
			}
			getAddrAction a = new getAddrAction();
			try {
				ret = AccessController.doPrivileged(a).getAddress();
			} catch (PrivilegedActionException pae) {
				Exception ex = pae.getException();
				if (ex instanceof IOException) {
					throw (IOException)ex;
				} else {
					throw (RuntimeException)ex;
				}
			}
			c.close();
			return ret;
		} catch (IOException ex) {
			return null;
		}
	}

	protected void checkSource() {
		if (src == null || src.isAnyLocalAddress()) {
			src = getLocalAddress();
		}
	}
}
