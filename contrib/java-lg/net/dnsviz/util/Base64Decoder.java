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

public class Base64Decoder {
	public byte [] decode(byte [] msg) {
		int msgBits;
		int i;
		byte [] ret;
		int bitIndex;
		int index;
		int offset;
		byte val;

		msgBits = msg.length * 6;
		if (msg[msg.length - 1] == Base64.pad) {
			msgBits -= 6;
		}
		if (msg[msg.length - 2] == Base64.pad) {
			msgBits -= 6;
		}
		msgBits -= (msgBits % 8);

		ret = new byte [msgBits >> 3];
		for (i = 0; i < ret.length; i++) {
			ret[i] = 0;
		}
		for (i = 0; i < msg.length; i++) {
			assert(Base64.isValid(msg[i]));
			val = Base64.values[msg[i]];
			bitIndex = i * 6;
			index = bitIndex / 8;
			offset = bitIndex % 8;
			if (index >= ret.length) {
				break;
			} else {
				if (offset <= 2) {
					ret[index] |= (byte)(val << (2 - offset));
				} else {
					ret[index] |= (byte)(val >> (offset - 2));
					if (index + 1 < ret.length) {
						ret[index + 1] |= (byte)(val << (10 - offset));
					}
				}
			}
		}
		return ret;
	}
}
