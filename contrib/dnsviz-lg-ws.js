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

var ORIGINS = new Array();
var WEBSOCKET_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
var WEBSOCKET_VERSION = 13;
var PROTOCOL = 'dns-looking-glass';

function setupSocket(webSocket, filename) {
	var crypto = require('crypto');
	var fs = require('fs');
	var net = require('net');
	var path = require('path');
	var os = require('os');

	// Create a (hopefully) unique filename for the UNIX domain socket
	var sockname;
	var sha1 = crypto.createHash('sha1');
	sha1.update(filename, 'ascii');
	sockname = path.join(os.tmpdir(), sha1.digest('hex'));

	var srv = net.createServer();

	srv.on('connection', function(socket) {
		// if there are any errors with the new connection,
		// then write them to the console before closing.
		socket.on('error', function(e) {
			console.error('Socket ' + e.toString());
		});

		// once connected, send UNIX domain socket data
		// to webSocket, and vice-versa
		socket.on('data', function(data) {
			webSocket.write(data);
		});
		// (use function for this one, so it can be removed later)
		var sendDataToSocket = function(data) {
			socket.write(data);
		};
		webSocket.on('data', sendDataToSocket);

		// when the socket is closed, don't send data from
		// the webSocket to it anymore
		socket.on('close', function() {
			webSocket.removeListener('data', sendDataToSocket);
		});
	});

	// if there is an error on either the webSocket or the listening socket
	// then report it to the console
	srv.on('error', function(e) {
		console.error('Listen Socket ' + e.toString());
		webSocket.end();
	});
	webSocket.on('error', function(e) {
		console.error('WebSocket ' + e.toString());
		srv.close();
	});

	// when the Web client closes its end of the webSocket, close the server
	webSocket.on('end', function() {
		srv.close();
	});

	srv.listen(sockname, function(e) {
		fs.chmod(sockname, 0660);
	});
}

function checkHeaders(key, origin, version, protocols) {
	var msg = '';
	if (key == null) {
		return {
			code: 400,
			msg: 'Bad Request',
			extraHeader: '',
			content: 'Key not found'
		};
	}
	if (origin == null) {
		return {
			code: 400,
			msg: 'Bad Request',
			extraHeader: '',
			content: 'Origin not found'
		};
	}
	var origin_match = false;
	for (var i = 0; i < ORIGINS.length; i++) {
		if (origin == ORIGINS[i]) {
			origin_match = true;
			break;
		}
	}
	if (!origin_match) {
		return {
			code: 403,
			msg: 'Forbidden',
			extraHeader: '',
			content: 'Invalid origin'
		};
	}
	if (version == null) {
		return {
			code: 400,
			msg: 'Bad Request',
			extraHeader: '',
			content: 'Version not found'
		};
	}
	if (version != WEBSOCKET_VERSION) {
		return {
			code: 426,
			msg: 'Upgrade Required',
			extraHeader: 'Sec-WebSocket-Version: ' + WEBSOCKET_VERSION + '\r\n',
			content: 'Unsupported version'
		};
	}
	/*TODO protocols*/
	return null;
}

function handleUpgrade(req, socket, head) {
	var key = req.headers['sec-websocket-key'];
	var origin = req.headers['origin'];
	var version = req.headers['sec-websocket-version'];
	var protocols = req.headers['sec-websocket-protocol'];
	var error = checkHeaders(key, origin, version, protocols);
	if (error != null) {
		var errorResponse = 'HTTP/1.1 ' + error.code + ' ' + error.msg + '\r\n' +
				error.extraHeader +
				'Content-Length: ' + error.content.length + '\r\n\r\n' +
				error.content;
		socket.write(errorResponse, function() {
			socket.end();
			console.log(new Date() + ' ' + req.method + ' ' + req.url + ' ' + error.code + ' ' + error.msg + ' (' + error.content + ')');
		});
		return;
	}

	var crypto = require('crypto');
	var sha1 = crypto.createHash('sha1');
	sha1.update(key + WEBSOCKET_GUID, 'ascii');
	var successResponse = 'HTTP/1.1 101 Switching Protocols\r\n' +
		'Upgrade: websocket\r\n' +
		'Connection: Upgrade\r\n' +
		'Sec-WebSocket-Accept: ' + sha1.digest('base64') + '\r\n\r\n';

	var qs = require('url').parse(req.url, true);
	socket.write(successResponse, function() {
		setupSocket(socket, qs.query.fn);
		console.log(new Date() + ' ' + req.method + ' ' + req.url + ' 101 upgraded');
	});
}

function usage() {
	console.error('Usage: ' + process.argv[0] + ' ' + process.argv[1] + ' ip:port[,ip:port...] [ origin[,origin...] ]');
}

function main() {
	if (process.argv.length < 3) {
		usage();
		process.exit(1);
	}
	var ips = process.argv[2].split(",");
	if (process.argv.length > 3) {
		var origins = process.argv[3].split(",");
		for (var i = 0; i < origins.length; i++) {
			ORIGINS.push(origins[i]);
		}
	}

	// Create an HTTP server
	var http = require('http');
	var srv = http.createServer();
	var repr = new Array();
	srv.on('upgrade', handleUpgrade);
	srv.on('error', function(e) {
		console.error(e.toString());
		srv.close();
	});

	srv.on('listening', function() {
		var all_repr = repr.join(", ");
		console.log(new Date() + ' Listening for connections on ' + all_repr);
	});

	for (var i = 0; i < ips.length; i++) {
		var ip_port = ips[i].split(':');
		if (ip_port.length < 2) {
			usage();
			process.exit(1);
		}

		var host = ip_port.slice(0, ip_port.length - 1).join(':');
		var port = ip_port[ip_port.length - 1];
		if (host[0] == "[" && host[host.length - 1] == "]") {
			host = host.slice(1, host.length - 1);
		}

		if (host.indexOf(":") >= 0) {
			repr.push("[" + host + "]:" + port);
		} else {
			repr.push(host + ":" + port);
		}

		ORIGINS.push('http://' + repr[i]);
		ORIGINS.push('https://' + repr[i]);

		srv.listen(port, host);
	}
}

main();
