package net.dnsviz.dnshelper;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;

import org.xbill.DNS.*;

public class DNSCacheAnalyst {

public class ResponseHandler implements ResolverListener {
	private Record record;
	private int [] rdtypes;
	private HashMap<String,DNSResponseObject> responseMap;
	private DNSCacheAnalyst analyst;

	public ResponseHandler(Record record, int[] rdtypes, HashMap<String,DNSResponseObject> responseMap, DNSCacheAnalyst analyst) {
		this.record = record;
		this.rdtypes = rdtypes;
		this.responseMap = responseMap;
		this.analyst = analyst;
	}

	public void handleException(Object id, Exception e) {
		DNSResponseObject response = new DNSResponseObject(record, analyst.getServer(), analyst.getLocalAddress(), e, new Date());
		Message m;
		try {
			m = analyst.query(record, new int [] { Flags.RD, Flags.CD });
			response.setResponseCD(m);
			followCname(m);
		} catch (Exception f) {
		}
		responseMap.put(response.getRecordID(), response);
	}

	public void receiveMessage(Object id, Message m) {
		DNSResponseObject response = new DNSResponseObject(record, analyst.getServer(), analyst.getLocalAddress(), m, new Date());

		if (m.getRcode() == Rcode.SERVFAIL) {
			try {
				m = analyst.query(record, new int [] { Flags.RD, Flags.CD });
				response.setResponseCD(m);
			} catch (Exception f) {
			}
		}
		followCname(m);

		responseMap.put(response.getRecordID(), response);
	}

	private void followCname(Message m) {
		Record [] sectionRecords;
		int i;

		if (m.findRRset(record.getName(), Type.CNAME, Section.ANSWER)) {
			sectionRecords = m.getSectionArray(Section.ANSWER);
			for (i = 0; i < sectionRecords.length; i++) {
				if (sectionRecords[i].getName().equals(record.getName()) && sectionRecords[i].getType() == Type.CNAME) {
					try {
						analyst.analyze(((CNAMERecord)sectionRecords[i]).getTarget().toString(), rdtypes, responseMap);
					} catch (TextParseException e) {
					}
				}
			}
		}
	}
}

private final boolean ASYNC = false;
protected String server;
protected String localAddress;
protected ExtendedResolver resolver;

public DNSCacheAnalyst(String server) throws UnknownHostException {
	int i;
	DatagramSocket tempSocket;

	this.server = server;
	resolver = new ExtendedResolver(new String [] { server });
	resolver.setEDNS(0, 4096, ExtendedFlags.DO, new ArrayList());
	resolver.setTimeout(3);

	final InetAddress serverAddr = InetAddress.getByName(server);
	localAddress = AccessController.doPrivileged(new PrivilegedAction<String> () {
		public String run() {
			try {
				DatagramSocket tempSocket = new DatagramSocket();
				tempSocket.connect(serverAddr, 53);
				return tempSocket.getLocalAddress().toString();
			} catch (SocketException e) {
				return null;
			}
		}
	});
	if (localAddress.charAt(0) == '/') {
		localAddress = localAddress.substring(1, localAddress.length());
	}
	if (localAddress.charAt(localAddress.length() - 2) == '%') {
		localAddress = localAddress.substring(0, localAddress.length() - 2);
	}
}

public HashMap<String,DNSResponseObject> analyze(String qnameString, int [] rdtypes) throws TextParseException {
	return analyze(qnameString, rdtypes, null);
}

public HashMap<String,DNSResponseObject> analyze(String qnameString, int [] rdtypes, HashMap<String,DNSResponseObject> responseMap) throws TextParseException {
	String [] labels;
	String nameString;
	int i, j;
	Name qname;
	boolean mapOwner;

	if (responseMap == null) {
		responseMap = new HashMap<String,DNSResponseObject> ();
		mapOwner = true;
	} else {
		mapOwner = false;
	}

	Name.fromString(qnameString, Name.root);
	if (qnameString.endsWith("."))
		qnameString = qnameString.substring(0, qnameString.length() - 1);
	labels = qnameString.split("\\.");

	for (i = 0; i <= labels.length; i++) {
		nameString = "";
		for (j = i; j < labels.length; j++) {
			nameString = nameString + labels[j] + ".";
		}
		if (nameString.length() == 0) {
			nameString = ".";
		}

		qname = Name.fromString(nameString, Name.root);
		for (j = 0; j < rdtypes.length; j++) {
			handleQuery(qname, rdtypes[j], rdtypes, responseMap);
		}
		handleQuery(qname, Type.DNSKEY, rdtypes, responseMap);
		if (!qname.equals(Name.root)) {
			handleQuery(qname, Type.DS, rdtypes, responseMap);
			handleQuery(Name.fromString(nameString + "dlv.isc.org."), Type.DLV, rdtypes, responseMap);
		}
		handleQuery(qname, Type.NS, rdtypes, responseMap);
	}
	handleQuery(Name.fromString("dlv.isc.org."), Type.DNSKEY, rdtypes, responseMap);

	if (ASYNC && mapOwner) {
		while (responseMap.containsValue(null)) {
			try {
				// consider using wait/notify on responseMap instead of sleeping
				Thread.sleep(500);
			} catch (InterruptedException e) {
			}
		}
	}
	return responseMap;
}

protected void handleQuery(Name qname, int rdtype, int [] rdtypes, HashMap<String,DNSResponseObject> responseMap) {
	Record r = Record.newRecord(qname, rdtype, DClass.IN);
	ResponseHandler handler;

	if (!responseMap.containsKey(DNSCacheAnalyst.getRecordID(r))) {
		responseMap.put(DNSCacheAnalyst.getRecordID(r), null);
		handler = new ResponseHandler(r, rdtypes, responseMap, this);
		if (ASYNC) {
			query(r, new int [] { Flags.RD } , handler);
		} else {
			try {
				handler.receiveMessage(null, query(r, new int [] { Flags.RD } ));
			} catch (Exception e) {
				handler.handleException(null, e);
			}
		}
	}
}

public Message query(String qname, int rdtype, int rdclass) throws TextParseException, IOException {
	return query(qname, rdtype, rdclass, new int [] { Flags.RD } );
}

public Message query(String qname, int rdtype, int rdclass, int [] flags) throws TextParseException, IOException {
	Record r = Record.newRecord(Name.fromString(qname, Name.root), rdtype, rdclass);
	return query(r, flags);
}

public Message query(Record r, int [] flags) throws TextParseException, IOException {
	final Resolver resolver = this.resolver;
	final Message request = Message.newQuery(r);
	int i;

	for (i = 0; i < flags.length; i++) {
		request.getHeader().setFlag(flags[i]);
	}
	
	try {
		return AccessController.doPrivileged(new PrivilegedExceptionAction<Message> () {
			public Message run() throws IOException {
				return resolver.send(request);
			}
		});
	} catch (PrivilegedActionException e) {
		throw (IOException) e.getException();
	}
}

public void query(Record r, int [] flags, final ResolverListener handler) {
	final Resolver resolver = this.resolver;
	final Message request = Message.newQuery(r);
	int i;

	for (i = 0; i < flags.length; i++) {
		request.getHeader().setFlag(flags[i]);
	}
	
	AccessController.doPrivileged(new PrivilegedAction<Object> () {
		public Object run() {
			resolver.sendAsync(request, handler);
			return null;
		}
	});
}

public String getServer() {
	return server;
}

public String getLocalAddress() {
	return localAddress;
}

public static String [] getDefaultServers() {
	ResolverConfig config;
	config = AccessController.doPrivileged(new PrivilegedAction<ResolverConfig> () {
		public ResolverConfig run() {
			return ResolverConfig.getCurrentConfig();
		}
	});
	return config.servers();
}

public static String getRecordID(Record r) {
	String s = r.getName().toString();
	if (s.endsWith(".") && s.length() > 1) {
		s = s.substring(0, s.length() - 1);
	}
	return s + "/" + Type.string(r.getType());
}

public static void main(String [] args) throws UnknownHostException, TextParseException {
	DNSCacheAnalyst a = new DNSCacheAnalyst(args[0]);
	HashMap<String,DNSResponseObject> responseMap;
	System.out.println(a.getLocalAddress());
	responseMap = a.analyze(args[1], new int [] {1});
	System.out.println(responseMap.get(args[2]).getEncodedResponse());
	System.out.println(responseMap.get(args[2]).getEncodedResponseCD());
}

}
