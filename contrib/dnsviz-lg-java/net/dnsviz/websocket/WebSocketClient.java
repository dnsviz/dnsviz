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

package net.dnsviz.websocket;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Random;

import net.dnsviz.util.Base64Encoder;

public class WebSocketClient {
	final static protected String WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	final static protected int WEBSOCKET_VERSION = 13;

	protected SocketChannel channel = null;

	protected ByteBuffer buffer = null;

	public WebSocketClient(String host, int port, String path, String origin) throws IOException {
		channel = SocketChannel.open();
		channel.connect(new InetSocketAddress(InetAddress.getByName(host), port));

		buffer = ByteBuffer.allocate(8192);

		String clientKey = keyForClient();
		String serverKey = keyForServer(clientKey);
		sendRequestHeaders(path, host, origin, clientKey);
		getResponseHeaders(serverKey);
	}

	public void close() throws IOException {
		channel.close();
	}

	protected String keyForServer(String clientKey) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA");
			byte [] b = md.digest((clientKey + WEBSOCKET_GUID).getBytes());
			return new String(new Base64Encoder().encode(b));
		} catch (NoSuchAlgorithmException ex) {
			return "";
		}
	}

	protected String keyForClient() {
		BigInteger n = new BigInteger(64, new Random());
		return new String(new Base64Encoder().encode(n.toByteArray()));
	}

	protected void sendRequestHeaders(String path, String host, String origin, String clientKey) throws IOException {
		String headers = "GET " + path + " HTTP/1.1\r\n" +
			"Host: " + host + "\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Key: " + clientKey + "\r\n" +
			"Origin: " + origin + "\r\n" +
			"Sec-WebSocket-Version: " + WEBSOCKET_VERSION + "\r\n\r\n";
		ByteBuffer buf = ByteBuffer.allocate(headers.length());
		buf.put(headers.getBytes());
		buf.flip();
		channel.write(buf);
	}

	protected void getResponseHeaders(String serverKey) throws IOException {
		String headers = "";
		String [] headerLines;
		ByteBuffer buf;
		byte [] bytes;
		int endOfHeadersIndex = -1;
		int endOfName = -1;
		boolean upgradeFound = false;
		boolean connectionFound = false;
		boolean acceptFound = false;

		buf = ByteBuffer.allocate(2048);

		while (true) {
			channel.read(buf);
			bytes = new byte [buf.position()];
			buf.rewind();
			buf.get(bytes);
			headers += new String(bytes);
			buf.clear();

			endOfHeadersIndex = headers.indexOf("\r\n\r\n");
			if (endOfHeadersIndex >= 0) {
				endOfHeadersIndex += 4;
				break;
			}
			endOfHeadersIndex = headers.indexOf("\n\n");
			if (endOfHeadersIndex >= 0) {
				endOfHeadersIndex += 2;
				break;
			}
			endOfHeadersIndex = headers.indexOf("\r\r");
			if (endOfHeadersIndex >= 0) {
				endOfHeadersIndex += 2;
				break;
			}
		}

		// put any buffered data beyond headers into buffer
		if (headers.length() > endOfHeadersIndex) {
			buffer.put(headers.substring(endOfHeadersIndex).getBytes());
		}

		headerLines = headers.split("\r\n|\n|\r");
		if (!headerLines[0].matches("HTTP/\\d\\.\\d+ 101 .*")) {
			throw new IOException("Invalid status response: " + headerLines[0]);
		}

		for (int i = 1; i < headerLines.length; i++) {
			if (headerLines[i].matches("Upgrade:\\s*websocket\\s*")) {
				upgradeFound = true;
			} else if (headerLines[i].matches("Connection:\\s*Upgrade\\s*")) {
				connectionFound = true;
			} else if (headerLines[i].matches("Sec-WebSocket-Accept:\\s*" + serverKey.replaceAll("\\+", "\\\\+") + "\\s*")) {
				acceptFound = true;
			}
		}

		if (!upgradeFound) {
			throw new IOException("Invalid response: Upgrade header not found");
		}
		if (!connectionFound) {
			throw new IOException("Invalid response: Connection header not found");
		}
		if (!acceptFound) {
			throw new IOException("Invalid response: Sec-WebSocket-Accept header not found or key not correct.");
		}
	}

	public byte [] read() throws IOException {
		ByteBuffer buf = ByteBuffer.allocate(2048);

		int byte0;
		int byte1;
		int byte1b;
		int headerLen;
		long frameLen = -1;
		boolean hasMore = true;
		LinkedList<byte []> frames = new LinkedList<byte []>();
		byte [] frame;
		byte [] message;
		long totalLength = 0;
		int index = 0;

		// first read any content from buffer
		if (buffer.position() > 0) {
			buffer.flip();
			buf.put(buffer);
			buffer.clear();
		}

		while (hasMore) {
			while (buf.position() < 2) {
				channel.read(buf);
			}

			byte0 = buf.get(0) & 0xff;
			byte1 = buf.get(1) & 0xff;
			byte1b = byte1 & 0x7f;

			// mask must not be set
			if ((byte1 & 0x80) != 0) {
				throw new IOException("Mask is set in frame");
			}

			// check whether FIN flag is set or not
			hasMore = (byte0 & 0x80) == 0;

			// determine the header length
			if (byte1b <= 125) {
					headerLen = 2;
			} else if (byte1b == 126) {
					headerLen = 4;
			} else { // byte1b == 127:
					headerLen = 10;
			}

			while (buf.position() < headerLen) {
				channel.read(buf);
			}

			if (byte1b <= 125) {
				frameLen = byte1b;
			} else if (byte1b == 126) {
				frameLen = ((buf.get(2) & 0xff) << 8) | (buf.get(3) & 0xff);
			} else if (byte1b == 127) {
				frameLen = (buf.getLong(2));
			}
			totalLength += frameLen;

			// put any leftover content from buf into buffer
			if (buf.position() >= headerLen) {
				buf.flip().position(headerLen);
				buffer.put(buf);
			}

			if (frameLen > 0x7fffffff) {
				throw new IOException("Frame size too big for buffer");
			}

			// allocate a buffer that is for the whole frame, or the size of the
			// previous buffer, whichever is greater
			buf = ByteBuffer.allocate(Math.max((int)frameLen, buffer.position()));
			// fill buf with content from buffer first
			if (buffer.position() > 0) {
				buffer.flip();
				buf.put(buffer);
				buffer.clear();
			}

			while (buf.hasRemaining()) {
				channel.read(buf);
			}

			// create a byte array with the bytes
			frame = new byte[(int)frameLen];
			buf.flip();
			buf.get(frame, 0, (int)frameLen);
			frames.add(frame);

			// if there is any content remaining if buf, put it into buffer, so it
			// will persist
			if (buf.hasRemaining()) {
				buffer.put(buf);
			}

		}

		if (totalLength > 0x7fffffff) {
			throw new IOException("Total message size too big for array");
		}
		message = new byte[(int)totalLength];
		Iterator<byte []> iterator = frames.iterator();
		while (iterator.hasNext()) {
			frame = iterator.next();
			System.arraycopy(frame, 0, message, index, frame.length);
			index += frame.length;
		}
		return message;
	}

	public void write(byte [] data) throws IOException {
		ByteBuffer buf = null;
		int headerLen;
		byte [] mask;

		if (data.length <= 125) {
			headerLen = 6;
		} else if (data.length <= 0xffff) {
			headerLen = 8;
		} else { // 0xffff < data.length <= 2^63
			headerLen = 14;
		}

		buf = ByteBuffer.allocate(headerLen + data.length);
		buf.put((byte)(0x81));
		if (data.length <= 125) {
			buf.put((byte)(data.length | 0x80));
		} else if (data.length <= 0xffff) {
			buf.put((byte)(126 | 0x80));
			buf.put((byte)((data.length >> 8) & 0xff));
			buf.put((byte)(data.length & 0xff));
		} else { // 0xffff < data.length <= 2^63
			buf.put((byte)(127 | 0x80));
			buf.put((byte)0);
			buf.put((byte)0);
			buf.put((byte)0);
			buf.put((byte)0);
			buf.put((byte)((data.length >> 24) & 0xff));
			buf.put((byte)((data.length >> 16) & 0xff));
			buf.put((byte)((data.length >> 8) & 0xff));
			buf.put((byte)(data.length & 0xff));
		}

		mask = new byte [4];
		BigInteger n = new BigInteger(32, new Random());
		System.arraycopy(n.toByteArray(), 0, mask, 0, 4);
		buf.put(mask);

		for (int i = 0; i < data.length; i++) {
			buf.put((byte)(mask[i % mask.length]^data[i]));
		}
		buf.flip();
		while (buf.hasRemaining()) {
			channel.write(buf);
		}
	}
}
