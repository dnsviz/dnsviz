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

package net.dnsviz.lookingglass;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

import net.dnsviz.transport.DNSQueryTransportHandler;
import net.dnsviz.transport.DNSQueryTransportHandlerTCP;
import net.dnsviz.transport.DNSQueryTransportHandlerUDP;
import net.dnsviz.transport.DNSQueryTransportManager;
import net.dnsviz.util.Base64Decoder;
import net.dnsviz.util.Base64Encoder;
import net.dnsviz.websocket.WebSocketClient;

public class DNSLookingGlass {
	public DNSLookingGlass() {
	}

	protected DNSQueryTransportHandler [] getDNSQueryTransportHandlers(JSONObject obj) throws JSONException, UnknownHostException {
		DNSQueryTransportHandler [] ret;
		JSONArray requests;
		String [] vers;
		String src;
		int sport;
		JSONObject reqObj;

		vers = Double.toString(obj.getDouble("version")).split("\\.");
		if (Integer.parseInt(vers[0]) != 1 || Integer.parseInt(vers[1]) > 0) {
			throw new JSONException("Version of JSON input is invalid");
		}

		requests = obj.getJSONArray("requests");
		ret = new DNSQueryTransportHandler [requests.length()];
		for (int i = 0; i < requests.length(); i++) {
			reqObj = requests.getJSONObject(i);
			if (reqObj.has("src")) {
				src = reqObj.getString("src");
			} else {
				src = null;
			}
			if (reqObj.has("sport")) {
				sport = reqObj.getInt("sport");
			} else {
				sport = 0;
			}
			ret[i] = getDNSQueryTransportHandler(reqObj.getString("req"), reqObj.getString("dst"), reqObj.getInt("dport"), src, sport, reqObj.getLong("timeout"), reqObj.getBoolean("tcp"));
		}
		return ret;
	}

	protected JSONObject getEncodedResponses(DNSQueryTransportHandler [] qths) {
		JSONObject ret;
		JSONObject response;

		JSONArray responses = new JSONArray();
		for (int i = 0; i < qths.length; i++) {
			response = new JSONObject();
			response.put("res", qths[i].getEncodedResponse());
			if (qths[i].getError() != null) {
				response.put("err", qths[i].getError());
				if (qths[i].getErrno() != null) {
					response.put("errno", qths[i].getErrno());
				}
			}
			if (qths[i].getSource() != null) {
				response.put("src", qths[i].getSource().getHostAddress());
			} else {
				response.put("src", (String)null);
			}
			if (qths[i].getSPort() != 0) {
				response.put("sport", qths[i].getSPort());
			} else {
				response.put("sport", (String)null);
			}
			response.put("time_elapsed", qths[i].timeElapsed());
			responses.put(response);
		}

		ret = new JSONObject();
		ret.put("version", "1.0");
		ret.put("responses", responses);
		return ret;
	}

	public DNSQueryTransportHandler getDNSQueryTransportHandler(String req, String dst, int dport, String src, int sport, long timeout, boolean tcp) throws UnknownHostException {
		Base64Decoder d = new Base64Decoder();
		byte [] byteReq = d.decode(req.getBytes());
		InetAddress srcAddr = null;
		InetAddress dstAddr = null;
		if (dst != null) {
			dstAddr = InetAddress.getByName(dst);
		}
		if (src != null) {
			srcAddr = InetAddress.getByName(src);
		}
		if (tcp) {
			return new DNSQueryTransportHandlerTCP(byteReq, dstAddr, dport, srcAddr, sport, timeout);
		} else {
			return new DNSQueryTransportHandlerUDP(byteReq, dstAddr, dport, srcAddr, sport, timeout);
		}
	}

	public void executeQueries(DNSQueryTransportHandler [] qths) throws IOException {
		int i;
		DNSQueryTransportManager qtm = new DNSQueryTransportManager();
		qtm.query(qths);
		for (i = 0; i < qths.length; i++) {
			qths[i].finalize();
		}
	}

	protected void interact(WebSocketClient ws) throws IOException {
		byte [] input;
		while ((input = ws.read()).length > 0) {
			ws.write(run(new String(input)).getBytes());
		}
	}

	public String run(String json) {
		JSONObject ret;
		try {
			DNSQueryTransportHandler [] qths = getDNSQueryTransportHandlers(new JSONObject(json));
			executeQueries(qths);
			return getEncodedResponses(qths).toString();
		} catch (Exception ex) {
			ret = new JSONObject();
			ret.put("version", "1.0");
			ret.put("error", getErrorTrace(ex));
			return ret.toString();
		}
	}

	protected String getErrorTrace(Exception err) {
		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw);
		err.printStackTrace(pw);
		return sw.toString();
	}

	public static void main(String [] args) throws IOException {
		WebSocketClient ws = new WebSocketClient(args[0], Integer.parseInt(args[1]), args[2], args[3]);
		DNSLookingGlass lg = new DNSLookingGlass();
		lg.interact(ws);
	}
}
