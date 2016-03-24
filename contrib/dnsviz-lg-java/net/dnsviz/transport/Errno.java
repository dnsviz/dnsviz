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

package net.dnsviz.transport;

public class Errno {

public static final int E2BIG = 7;
public static final int EACCES = 13;
public static final int EADDRINUSE = 98;
public static final int EADDRNOTAVAIL = 99;
public static final int EADV = 68;
public static final int EAFNOSUPPORT = 97;
public static final int EAGAIN = 11;
public static final int EALREADY = 114;
public static final int EBADE = 52;
public static final int EBADF = 9;
public static final int EBADFD = 77;
public static final int EBADMSG = 74;
public static final int EBADR = 53;
public static final int EBADRQC = 56;
public static final int EBADSLT = 57;
public static final int EBFONT = 59;
public static final int EBUSY = 16;
public static final int ECHILD = 10;
public static final int ECHRNG = 44;
public static final int ECOMM = 70;
public static final int ECONNABORTED = 103;
public static final int ECONNREFUSED = 111;
public static final int ECONNRESET = 104;
public static final int EDEADLK = 35;
public static final int EDEADLOCK = 35;
public static final int EDESTADDRREQ = 89;
public static final int EDOM = 33;
public static final int EDOTDOT = 73;
public static final int EDQUOT = 122;
public static final int EEXIST = 17;
public static final int EFAULT = 14;
public static final int EFBIG = 27;
public static final int EHOSTDOWN = 112;
public static final int EHOSTUNREACH = 113;
public static final int EIDRM = 43;
public static final int EILSEQ = 84;
public static final int EINPROGRESS = 115;
public static final int EINTR = 4;
public static final int EINVAL = 22;
public static final int EIO = 5;
public static final int EISCONN = 106;
public static final int EISDIR = 21;
public static final int EISNAM = 120;
public static final int EL2HLT = 51;
public static final int EL2NSYNC = 45;
public static final int EL3HLT = 46;
public static final int EL3RST = 47;
public static final int ELIBACC = 79;
public static final int ELIBBAD = 80;
public static final int ELIBEXEC = 83;
public static final int ELIBMAX = 82;
public static final int ELIBSCN = 81;
public static final int ELNRNG = 48;
public static final int ELOOP = 40;
public static final int EMFILE = 24;
public static final int EMLINK = 31;
public static final int EMSGSIZE = 90;
public static final int EMULTIHOP = 72;
public static final int ENAMETOOLONG = 36;
public static final int ENAVAIL = 119;
public static final int ENETDOWN = 100;
public static final int ENETRESET = 102;
public static final int ENETUNREACH = 101;
public static final int ENFILE = 23;
public static final int ENOANO = 55;
public static final int ENOBUFS = 105;
public static final int ENOCSI = 50;
public static final int ENODATA = 61;
public static final int ENODEV = 19;
public static final int ENOENT = 2;
public static final int ENOEXEC = 8;
public static final int ENOLCK = 37;
public static final int ENOLINK = 67;
public static final int ENOMEM = 12;
public static final int ENOMSG = 42;
public static final int ENONET = 64;
public static final int ENOPKG = 65;
public static final int ENOPROTOOPT = 92;
public static final int ENOSPC = 28;
public static final int ENOSR = 63;
public static final int ENOSTR = 60;
public static final int ENOSYS = 38;
public static final int ENOTBLK = 15;
public static final int ENOTCONN = 107;
public static final int ENOTDIR = 20;
public static final int ENOTEMPTY = 39;
public static final int ENOTNAM = 118;
public static final int ENOTSOCK = 88;
public static final int ENOTSUP = 95;
public static final int ENOTTY = 25;
public static final int ENOTUNIQ = 76;
public static final int ENXIO = 6;
public static final int EOPNOTSUPP = 95;
public static final int EOVERFLOW = 75;
public static final int EPERM = 1;
public static final int EPFNOSUPPORT = 96;
public static final int EPIPE = 32;
public static final int EPROTO = 71;
public static final int EPROTONOSUPPORT = 93;
public static final int EPROTOTYPE = 91;
public static final int ERANGE = 34;
public static final int EREMCHG = 78;
public static final int EREMOTE = 66;
public static final int EREMOTEIO = 121;
public static final int ERESTART = 85;
public static final int EROFS = 30;
public static final int ESHUTDOWN = 108;
public static final int ESOCKTNOSUPPORT = 94;
public static final int ESPIPE = 29;
public static final int ESRCH = 3;
public static final int ESRMNT = 69;
public static final int ESTALE = 116;
public static final int ESTRPIPE = 86;
public static final int ETIME = 62;
public static final int ETIMEDOUT = 110;
public static final int ETOOMANYREFS = 109;
public static final int ETXTBSY = 26;
public static final int EUCLEAN = 117;
public static final int EUNATCH = 49;
public static final int EUSERS = 87;
public static final int EWOULDBLOCK = 11;
public static final int EXDEV = 18;
public static final int EXFULL = 54;

public static final String [] errorCode = {
	null,
	"EPERM", /* 1 */
	"ENOENT", /* 2 */
	"ESRCH", /* 3 */
	"EINTR", /* 4 */
	"EIO", /* 5 */
	"ENXIO", /* 6 */
	"E2BIG", /* 7 */
	"ENOEXEC", /* 8 */
	"EBADF", /* 9 */
	"ECHILD", /* 10 */
	"EAGAIN", /* 11 */
	"ENOMEM", /* 12 */
	"EACCES", /* 13 */
	"EFAULT", /* 14 */
	"ENOTBLK", /* 15 */
	"EBUSY", /* 16 */
	"EEXIST", /* 17 */
	"EXDEV", /* 18 */
	"ENODEV", /* 19 */
	"ENOTDIR", /* 20 */
	"EISDIR", /* 21 */
	"EINVAL", /* 22 */
	"ENFILE", /* 23 */
	"EMFILE", /* 24 */
	"ENOTTY", /* 25 */
	"ETXTBSY", /* 26 */
	"EFBIG", /* 27 */
	"ENOSPC", /* 28 */
	"ESPIPE", /* 29 */
	"EROFS", /* 30 */
	"EMLINK", /* 31 */
	"EPIPE", /* 32 */
	"EDOM", /* 33 */
	"ERANGE", /* 34 */
	"EDEADLK", /* 35 */
	"ENAMETOOLONG", /* 36 */
	"ENOLCK", /* 37 */
	"ENOSYS", /* 38 */
	"ENOTEMPTY", /* 39 */
	"ELOOP", /* 40 */
	null,
	"ENOMSG", /* 42 */
	"EIDRM", /* 43 */
	"ECHRNG", /* 44 */
	"EL2NSYNC", /* 45 */
	"EL3HLT", /* 46 */
	"EL3RST", /* 47 */
	"ELNRNG", /* 48 */
	"EUNATCH", /* 49 */
	"ENOCSI", /* 50 */
	"EL2HLT", /* 51 */
	"EBADE", /* 52 */
	"EBADR", /* 53 */
	"EXFULL", /* 54 */
	"ENOANO", /* 55 */
	"EBADRQC", /* 56 */
	"EBADSLT", /* 57 */
	null,
	"EBFONT", /* 59 */
	"ENOSTR", /* 60 */
	"ENODATA", /* 61 */
	"ETIME", /* 62 */
	"ENOSR", /* 63 */
	"ENONET", /* 64 */
	"ENOPKG", /* 65 */
	"EREMOTE", /* 66 */
	"ENOLINK", /* 67 */
	"EADV", /* 68 */
	"ESRMNT", /* 69 */
	"ECOMM", /* 70 */
	"EPROTO", /* 71 */
	"EMULTIHOP", /* 72 */
	"EDOTDOT", /* 73 */
	"EBADMSG", /* 74 */
	"EOVERFLOW", /* 75 */
	"ENOTUNIQ", /* 76 */
	"EBADFD", /* 77 */
	"EREMCHG", /* 78 */
	"ELIBACC", /* 79 */
	"ELIBBAD", /* 80 */
	"ELIBSCN", /* 81 */
	"ELIBMAX", /* 82 */
	"ELIBEXEC", /* 83 */
	"EILSEQ", /* 84 */
	"ERESTART", /* 85 */
	"ESTRPIPE", /* 86 */
	"EUSERS", /* 87 */
	"ENOTSOCK", /* 88 */
	"EDESTADDRREQ", /* 89 */
	"EMSGSIZE", /* 90 */
	"EPROTOTYPE", /* 91 */
	"ENOPROTOOPT", /* 92 */
	"EPROTONOSUPPORT", /* 93 */
	"ESOCKTNOSUPPORT", /* 94 */
	"ENOTSUP", /* 95 */
	"EPFNOSUPPORT", /* 96 */
	"EAFNOSUPPORT", /* 97 */
	"EADDRINUSE", /* 98 */
	"EADDRNOTAVAIL", /* 99 */
	"ENETDOWN", /* 100 */
	"ENETUNREACH", /* 101 */
	"ENETRESET", /* 102 */
	"ECONNABORTED", /* 103 */
	"ECONNRESET", /* 104 */
	"ENOBUFS", /* 105 */
	"EISCONN", /* 106 */
	"ENOTCONN", /* 107 */
	"ESHUTDOWN", /* 108 */
	"ETOOMANYREFS", /* 109 */
	"ETIMEDOUT", /* 110 */
	"ECONNREFUSED", /* 111 */
	"EHOSTDOWN", /* 112 */
	"EHOSTUNREACH", /* 113 */
	"EALREADY", /* 114 */
	"EINPROGRESS", /* 115 */
	"ESTALE", /* 116 */
	"EUCLEAN", /* 117 */
	"ENOTNAM", /* 118 */
	"ENAVAIL", /* 119 */
	"EISNAM", /* 120 */
	"EREMOTEIO", /* 121 */
	"EDQUOT" /* 122 */
};

public static String getName(int code) {
	String ret;
	if (code < 0 || code >= errorCode.length) {
		return "";
	}
	ret = errorCode[code];
	if (ret == null) {
		return "";
	} else {
		return ret;
	}
}

}
