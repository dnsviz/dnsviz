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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.FileSystems;
import java.util.LinkedList;
import java.util.regex.Pattern;

public class DNSSettings {

	public InetAddress [] getDNSServers() {
		final Pattern ipCharsRE = Pattern.compile("[0-9a-fA-F\\.:]+(%.+)?");
		String line;
		boolean foundColon;
		boolean lineHasColon;
		BufferedReader reader;
		ProcessBuilder [] pbs;
		Process p;

		LinkedList<InetAddress> addresses = new LinkedList<InetAddress>();
		InetAddress [] ret;
		InetAddress addr;
		String [] words;

		try {
			String[] lines = Files.readAllLines(FileSystems.getDefault().getPath("/", "etc", "resolv.conf")).toArray(new String[0]);
			for (int i = 0; i < lines.length; i++) {
				words = lines[i].split("\\s+");
				if (words.length > 1 && words[0].equals("nameserver")) {
					try {
						addr = InetAddress.getByName(words[1]);
						if (!addresses.contains(addr)) {
							addresses.add(addr);
						}
					} catch (UnknownHostException e) {
						/* Bad address. Move along */
					}
				}
			}
		} catch (IOException e) {
			/* File not found, error opening or reading, etc.  Move along. */
		}

		pbs = new ProcessBuilder [] {
			/* Windows XP */
			new ProcessBuilder("netsh", "interface", "ip", "show", "dns"),
			/* Windows 7, Windows 8, Windows Server 2012R2 */
			new ProcessBuilder("netsh", "interface", "ipv4", "show", "dnsservers"),
			new ProcessBuilder("netsh", "interface", "ipv6", "show", "dnsservers")
		};

		for (int i = 0; i < pbs.length; i++) {
			try {
				p = pbs[i].start();

				reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
				foundColon = false;
				lineHasColon = false;
				while ((line = reader.readLine()) != null) {
					words = line.split("\\s+");
					lineHasColon = words.length > 1 && words[words.length - 2].endsWith(":") && ipCharsRE.matcher(words[words.length - 1]).matches();
					if (foundColon && !lineHasColon) {
						if (!(words.length == 2 && words[0].equals(""))) {
							foundColon = false;
						}
					}
					if (lineHasColon || foundColon) {
						try {
							addr = InetAddress.getByName(words[words.length - 1]);
							if (!addresses.contains(addr)) {
								addresses.add(addr);
							}
						} catch (UnknownHostException e) {
							/* Bad address. Move along */
						}
					}
					if (lineHasColon) {
						foundColon = true;
					}
				}
			} catch (IOException e) {
					/* Command not found, bad arguments. etc.  Move along. */
			}
		}

		return addresses.toArray(new InetAddress[addresses.size()]);
	}
}
