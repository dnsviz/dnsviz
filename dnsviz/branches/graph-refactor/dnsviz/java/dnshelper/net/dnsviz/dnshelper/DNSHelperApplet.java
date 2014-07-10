package net.dnsviz.dnshelper;

import java.applet.Applet;
import java.net.UnknownHostException;

public class DNSHelperApplet extends Applet {
	static final long serialVersionUID = 0;

	public DNSCacheAnalyst getDNSCacheAnalyst(String server) {
		try {
			return new DNSCacheAnalyst(server);
		} catch (UnknownHostException e) {
			return null;
		}
	}
	public String [] getDefaultServers() {
		return DNSCacheAnalyst.getDefaultServers();
	}
}
