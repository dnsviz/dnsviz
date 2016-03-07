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
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NoRouteToHostException;
import java.net.PortUnreachableException;
import java.net.BindException;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.channels.NetworkChannel;
import java.nio.channels.SelectableChannel;
import java.nio.channels.WritableByteChannel;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Date;
import java.util.Random;

import java.net.UnknownHostException;

import net.dnsviz.util.Base64Encoder;
import net.dnsviz.util.Base64Decoder;

public abstract class DNSQueryTransportHandler {
	private final static int MAX_PORT_BIND_ATTEMPTS = 10;

	protected ByteBuffer req = null;
	protected ByteBuffer res = null;
	protected String err = null;
	protected String errno = null;

	protected InetAddress dst = null;
	protected int dport = 0;
	protected InetAddress src = null;
	protected int sport = 0;

	protected NetworkChannel channel = null;

	protected long timeout = 0;
	protected long expiration = 0;
	protected long startTime = 0;
	protected long endTime = 0;

	protected DNSQueryTransportHandler(byte [] req, InetAddress dst, int dport, InetAddress src, int sport, long timeout) {
		this.dst = dst;
		this.dport = dport;
		this.src = src;
		this.sport = sport;

		this.timeout = timeout;

		initRequestBuffer(req);
	}

	public abstract int getInitialSelectionOp();

	public abstract int getStartOfReqPayload();

	public NetworkChannel getChannel() {
		return channel;
	}

	public long getExpiration() {
		return expiration;
	}

	public boolean hasError() {
		return err != null;
	}

	public void setError(IOException ex) throws IOException {
		if (ex instanceof SocketException) {
			String m = ex.getMessage();
			if (ex instanceof ConnectException) {
				if (m.contains("timed out")) {
					err = "TIMEOUT";
				} else if (m.contains("refused")) {
					err = "NETWORK_ERROR";
					errno = Errno.getName(Errno.ECONNREFUSED);
				}
			} else if (ex instanceof BindException) {
				if (m.contains("an't assign requested address")) {
					err = "NETWORK_ERROR";
					errno = Errno.getName(Errno.EADDRNOTAVAIL);
				} else if (m.contains("ddress already in use")) {
					err = "NETWORK_ERROR";
					errno = Errno.getName(Errno.EADDRINUSE);
				}
			} else if (ex instanceof NoRouteToHostException) {
				err = "NETWORK_ERROR";
				errno = Errno.getName(Errno.EHOSTUNREACH);
			} else if (ex instanceof PortUnreachableException) {
				err = "NETWORK_ERROR";
				errno = Errno.getName(Errno.ECONNREFUSED);
			} else if (m.contains("ermission denied")) {
				err = "NETWORK_ERROR";
				errno = Errno.getName(Errno.EACCES);
			}
		}

		/* if we weren't able to identify the error, then throw it */
		if (err == null) {
			throw ex;
		}
	}

	public void setError(int code) {
		err = "NETWORK_ERROR";
		errno = Errno.getName(code);
	}

	public void setError(String name) {
		err = name;
	}

	public String getError() {
		return err;
	}

	public String getErrno() {
		return errno;
	}

	public long timeElapsed() {
		return endTime - startTime;
	}

	public long getSPort() {
		return sport;
	}

	public InetAddress getSource() {
		return src;
	}

	protected abstract void initRequestBuffer(byte [] req);

	protected void initResponseBuffer() {
		//TODO start more conservative and dynamically grow if more buffer space is
		//needed
		res = ByteBuffer.allocate(65536);
	}

	protected abstract void createSocket() throws IOException;

	protected void configureSocket() throws IOException {
		((SelectableChannel)channel).configureBlocking(false);
	}

	protected void bindSocket() throws IOException {
		class bindAction implements PrivilegedExceptionAction<Object> {
			private int port = 0;
			public Object run() throws IOException {
				channel.bind(new InetSocketAddress(src, port));
				return null;
			}
			public void setPort(int port) {
				this.port = port;
			}
		}
		bindAction a = new bindAction();
		if (sport > 0) {
			a.setPort(sport);
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
		} else {
			Random r = new Random();

			int i = 0;
			while (true) {
				// 65536 - 1024 = 64512
				a.setPort(r.nextInt(64512) + 1024);
				try {
					AccessController.doPrivileged(a);
					break;
				} catch (PrivilegedActionException pae) {
					Exception ex = pae.getException();
					if (ex instanceof BindException) {
						if (++i > MAX_PORT_BIND_ATTEMPTS || !ex.getMessage().contains("ddress already in use")) {
							throw (BindException)ex;
						}
					} else if (ex instanceof IOException) {
						throw (IOException)ex;
					} else {
						throw (RuntimeException)ex;
					}
				}
			}
		}
	}

	public void prepare() throws IOException {
		initResponseBuffer();
		try {
			createSocket();
			configureSocket();
			bindSocket();
			setStart();
			connect();
		} catch (IOException ex) {
			setError(ex);
			cleanup();
		}
	}

	protected void setSocketInfo() {
		InetSocketAddress addr;

		class getAddrAction implements PrivilegedExceptionAction<InetSocketAddress> {
			public InetSocketAddress run() throws IOException {
				return (InetSocketAddress)channel.getLocalAddress();
			}
		}
		getAddrAction a = new getAddrAction();
		try {
			addr = AccessController.doPrivileged(a);
		} catch (PrivilegedActionException pae) {
			Exception ex = pae.getException();
			if (ex instanceof IOException) {
				return;
			} else {
				throw (RuntimeException)ex;
			}
		}
		src = addr.getAddress();
		sport = addr.getPort();
	}

	protected void setStart() {
		Date d = new Date();
		expiration = d.getTime() + timeout;
		startTime = d.getTime();
	}

	protected abstract void connect() throws IOException;

	protected abstract boolean finishConnect() throws IOException;

	public boolean doWrite() throws IOException {
		class writeAction implements PrivilegedExceptionAction<Object> {
			public Object run() throws IOException {
				((WritableByteChannel)channel).write(req);
				return null;
			}
		}
		writeAction a = new writeAction();
		try {
			AccessController.doPrivileged(a);
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
		if (!req.hasRemaining()) {
			return true;
		}
		return false;
	}

	public abstract boolean doRead() throws IOException;

	public void doTimeout() {
		err = "TIMEOUT";
		cleanup();
	}

	protected void setEnd() {
		// set end (and start, if necessary) times, as appropriate
		Date d = new Date();
		endTime = d.getTime();
		if (startTime == 0) {
			startTime = endTime;
		}
	}

	protected void closeSocket() {
		try {
			channel.close();
		}	catch (IOException ex) {
			/* do nothing here */
		}
	}

	public void cleanup() {
		setEnd();
		setSocketInfo();
		closeSocket();
	}

	protected abstract void checkSource();

	public void finalize() {
		checkSource();
		if (req != null) {
			req.rewind();
		}
		if (err != null) {
			res = null;
		} else if (res != null) {
			res.rewind();
		}
	}

	public String getEncodedResponse() {
		String res;
		byte [] buf;
		Base64Encoder e = new Base64Encoder();

		if (this.res != null) {
			buf = new byte [this.res.limit()];
			this.res.get(buf);
			return new String(e.encode(buf));
		} else {
			return null;
		}
	}
}
