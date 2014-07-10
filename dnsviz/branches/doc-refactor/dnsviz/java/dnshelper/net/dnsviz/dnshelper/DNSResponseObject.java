package net.dnsviz.dnshelper;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.Date;

import org.xbill.DNS.*;
import org.xbill.DNS.utils.*;

public class DNSResponseObject {

private Record record;
private String server;
private String client;
private Message response;
private Message responseCD;
private Date timestamp;
private boolean timeout;
private boolean formErr;

public DNSResponseObject(Record record, String server, String client, Message response, Date timestamp) {
	this.record = record;
	this.server = server;
	this.client = client;
	this.response = response;
	this.responseCD = null;
	this.timestamp = timestamp;
	timeout = false;
	formErr = false;
}

public DNSResponseObject(Record record, String server, String client, Exception e, Date timestamp) {
	this.record = record;
	this.server = server;
	this.client = client;
	this.response = null;
	this.responseCD = null;
	this.timestamp = timestamp;
	timeout = e instanceof SocketTimeoutException;
	formErr= false;
}

public Record getRecord() {
	return record;
}

public String getRecordID() {
	return DNSCacheAnalyst.getRecordID(record);
}

public String getServer() {
	return server;
}

public String getClient() {
	return client;
}

public Message getResponse() {
	return response;
}

public Message getResponseCD() {
	return responseCD;
}

public void setResponseCD(Message m) {
	responseCD = m;
}

public String getEncodedResponse() {
	if (response == null) {
		return "";
	}
	byte [] wire = response.toWire();
	return base64.toString(wire);
}

public String getEncodedResponseCD() {
	if (responseCD == null) {
		return "";
	}
	byte [] wire = responseCD.toWire();
	return base64.toString(wire);
}

public Date getTimestamp() {
	return timestamp;
}

public long getTimestampInSeconds() {
	return timestamp.getTime()/1000;
}

public boolean getTimeout() {
	return timeout;
}

public boolean getFormErr() {
	return formErr;
}

}
