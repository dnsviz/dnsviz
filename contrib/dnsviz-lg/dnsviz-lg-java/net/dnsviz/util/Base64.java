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

public class Base64 {

	public static byte [] alphabet = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', '+', '/'
	};

	public static byte [] values = {
		0, 0, 0, 0, 0, 0, 0, 0,         // 0 - 7
		0, 0, 0, 0, 0, 0, 0, 0,         // 8 - 15
		0, 0, 0, 0, 0, 0, 0, 0,         // 16 - 23
		0, 0, 0, 0, 0, 0, 0, 0,         // 24 - 31
		0, 0, 0, 0, 0, 0, 0, 0,         // 32 - 39
		0, 0, 0, 62, 0, 0, 0, 63,       // 40 - 47
		52, 53, 54, 55, 56, 57, 58, 59, // 48 - 55
		60, 61, 0, 0, 0, 0, 0, 0,       // 56 - 63
		0, 0, 1, 2, 3, 4, 5, 6,         // 64 - 71
		7, 8, 9, 10, 11, 12, 13, 14,    // 72 - 79
		15, 16, 17, 18, 19, 20, 21, 22, // 80 - 87
		23, 24, 25, 0, 0, 0, 0, 0,      // 88 - 95
		0, 26, 27, 28, 29, 30, 31, 32,  // 96 - 103
		33, 34, 35, 36, 37, 38, 39, 40, // 104 - 111
		41, 42, 43, 44, 45, 46, 47, 48, // 112 - 119
		49, 50, 51, 0, 0, 0, 0, 0       // 120 - 127
	};

	public static boolean isValid(byte b) {
		return (b >= 0 && b <= 127) && (b == 65 || values[b] != 0);
	}

	public static byte pad = '=';

}
