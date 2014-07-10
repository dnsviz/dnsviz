package net.dnsviz.dnshelper;

import java.net.UnknownHostException;

public class DNSCacheAnalystAsync extends DNSCacheAnalyst {

private final boolean ASYNC = true;

public DNSCacheAnalystAsync(String server) throws UnknownHostException {
	super(server);
}

}
