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

package net.dnsviz.applet;

import java.applet.Applet;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;

import net.dnsviz.transport.DNSQueryTransportHandler;
import net.dnsviz.util.DNSSettings;

import net.dnsviz.lookingglass.DNSLookingGlass;

public class DNSLookingGlassApplet extends Applet {
	static final long serialVersionUID = 0;
	private Exception err = null;
	private DNSLookingGlass lg = null;

	public DNSLookingGlassApplet() {
		lg = new DNSLookingGlass();
	}

	public DNSQueryTransportHandler getDNSQueryTransportHandler(String req, String dst, int dport, String src, int sport, long timeout, boolean tcp) {
		err = null;
		try {
			return lg.getDNSQueryTransportHandler(req, dst, dport, src, sport, timeout, tcp);
		} catch (Exception ex) {
			err = ex;
			return null;
		}
	}

	public void executeQueries(DNSQueryTransportHandler [] qths) {
		err = null;
		try {
			lg.executeQueries(qths);
		} catch (Exception ex) {
			err = ex;
		}
	}

	public InetAddress [] getDNSServers() {
		return new DNSSettings().getDNSServers();
	}

	public boolean hasError() {
		return err != null;
	}

	public Exception getError() {
		return err;
	}

	public String getErrorTrace() {
		if (err == null) {
			return null;
		}
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		err.printStackTrace(pw);
		return sw.toString();
	}
}
