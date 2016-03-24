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

package net.dnsviz.util;

import net.dnsviz.util.Base64;

public class Base64Encoder {
	public byte [] encode(byte [] msg) {
		int msgBits;
		int leftover;
		byte [] ret;
		int i;
		int bitIndex;
		int index;
		int offset;
		byte next;
		byte val;

		msgBits = msg.length << 3;
		leftover = msgBits % 24;
		if (leftover > 0) {
			msgBits += 24 - leftover;
		}
		ret = new byte [msgBits/6];

		for (i = 0; i < ret.length; i++) {
			bitIndex = i * 6;
			index = bitIndex / 8;
			offset = bitIndex % 8;
			if (index >= msg.length) {
				ret[i] = Base64.pad;
			} else {
				if (offset <= 2) {
					val = (byte)((msg[index] >> (2 - offset)) & 0x3f);
				} else {
					if (index + 1 < msg.length) {
						next = msg[index + 1];
					} else {
						next = 0;
					}
					val = (byte)(((msg[index] << (offset - 2)) | ((next >> (10 - offset)) & ~(0xff << (offset - 2)))) & 0x3f);
				}
				ret[i] = Base64.alphabet[val];
			}
		}
		return ret;
	}
}
