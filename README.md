# DNSViz


## Description

DNSViz is a tool suite for analysis and visualization of Domain Name System
(DNS) behavior, including its security extensions (DNSSEC).  This tool suite
powers the Web-based analysis available at http://dnsviz.net/


## Installation


### Dependencies

* python (2.7.x) - http://www.python.org/

  python 2.7.x is required.

* dnspython (1.11.0 or later) - http://www.dnspython.org/

  dnspython is required.  Version 1.10.0 is sufficient if you're not issuing
  TLSA queries, but more generally version 1.11.0 or greater is required.

* pygraphviz (1.1 or later) - http://pygraphviz.github.io/

  pygraphviz is required if visualization is desired (e.g., via the `dnsviz`
  tool) or if security status of responses is desired (e.g., using the -t
  option with the `dnsgrok` tool).   Online analysis (using `dnsget`) and
  offline analysis (e.g., using `dnsgrok` without the -t) can be performed
  without pygraphviz.  Version 1.1 or greater is required because of the support
  for unicode names and HTML-like labels, both of which are utilized in the
  visual output.

* M2Crypto (0.21.1 or later) - https://github.com/martinpaljak/M2Crypto

  M2Crypto is required if cryptographic validation of signatures and digests is
  desired (and thus is highly recommended).  The current code will display
  warnings if the cryptographic elements cannot be verified.

  Note that support for the following DNSSEC algorithms is not yet available in
  stock releases of M2Crypto: 3 (DSA-SHA1), 6 (DSA-NSEC3-SHA1),
  12 (GOST R 34.10-2001), 13 (ECDSA Curve P-256 with SHA-256), 14 (ECDSA Curve
  P-384 with SHA-384).  However, the patch included in "contrib/m2crypto.patch"
  can be applied to M2Crypto 0.21.1 or M2Crypto 0.22.3 to support these
  algorithms:

  ```
  $ patch -p1 < /path/to/dnsviz-source/contrib/m2crypto.patch
  ```

### Build and Install

A typical build and install is performed with the following commands:

```
$ python setup.py build
$ sudo python setup.py install
```

To see all installation options, run the following:

```
$ python setup.py --help
```


## Usage

DNSViz is invoked using a series of included command-line utilities: `dnsget`,
`dnsgrok`, and `dnsviz`.  Run any of the command-line tools with -h (help) to
display all options associated with their usage.


### dnsget

`dnsget` takes one or more domain names as input and performs a series of
queries to either recursive (default) or authoritative DNS servers, the results
of which are serialized into JSON format.


#### Examples

Analyze the domain name example.com using your configured DNS resolvers (i.e.,
in /etc/resolv.conf) and store the queries and responses in the file named
"example.com.json":
```
$ dnsget example.com > example.com.json
```

Same thing:
```
$ dnsget -o example.com.json example.com
```

Analyze the domain name example.com by querying its authoritative servers
directly:
```
$ dnsget -A -o example.com.json example.com
```

Analyze the domain name example.com by querying explicitly-defined
authoritative servers, rather than learning the servers through referrals from
the IANA root servers:
```
$ dnsget -A \
  -x example.com:a.iana-servers.org=199.43.132.53,a.iana-servers.org=2001:500:8c::53 \
  -x example.com:b.iana-servers.org=199.43.133.53,b.iana-servers.org=2001:500:8d::53 \
  -o example.com.json example.com
```

Same, but have `dnsget` resolve the names:
```
$ dnsget -A \
  -x example.com:a.iana-servers.org,b.iana-servers.org \
  -o example.com.json example.com
```

Analyze the domain name example.com and its entire ancestry by querying
authoritative servers and following delegations, starting at the root:
```
$ dnsget -A -a . -o example.com.json example.com
```

Analyze multiple names in parallel (four threads) using explicit recursive
resolvers (replace *192.0.1.2* and *2001:db8::1* with legitimate resolver
addresses):
```
$ dnsget -s 192.0.2.1,2001:db8::1 -t 4 -o multiple.json \
  example.com sandia.gov verisignlabs.com dnsviz.net
```


### dnsgrok

`dnsgrok` takes serialized query results in JSON format (i.e., output from
`dnsget`) as input and assesses specified domain names based on their
corresponding content in the input.  The output is also serialized into JSON
format.


#### Examples

Process the query/response output produced by `dnsget`, and store the
serialized results in a file named "example.com-chk.json":
```
$ dnsgrok < example.com.json > example.com-chk.json
```

Same thing:
```
$ dnsgrok -r example.com.json -o example.com-chk.json example.com
```

Same thing, but with "pretty", formatted JSON:
```
$ dnsgrok -p -r example.com.json -o example.com-chk.json
```

Show only info-level information: descriptions, statuses, warnings, and errors:
```
$ dnsgrok -p -l info -r example.com.json -o example.com-chk.json
```

Show descriptions only if there are related warnings or errors:
```
$ dnsgrok -p -l warning -r example.com.json -o example.com-chk.json
```

Show descriptions only if there are related errors:
```
$ dnsgrok -p -l error -r example.com.json -o example.com-chk.json
```

Add DNSSEC trust anchors to indicate security status of responses.
```
$ dig +noall +answer . dnskey | awk '$5 % 2 { print $0 }' > tk.txt
$ dnsgrok -p -l info -t tk.txt -r example.com.json -o example.com-chk.json
```

Pipeline dnsget output directly to dnsgrok:
```
$ dnsget example.com | \
      dnsgrok -p -l info -t tk.txt -o example.com-chk.json
```

Same thing, but save the raw output (for re-use) along the way:
```
$ dnsget example.com | tee example.com.json | \
      dnsgrok -p -l info -t tk.txt -o example.com-chk.json
```

Assess multiple names at once with error level:
```
$ dnsgrok -p -l error -t tk.txt -r multiple.json -o example.com-chk.json
```


### dnsviz

`dnsviz` takes serialized query results in JSON format (i.e., output from
`dnsget`) as input and assesses specified domain names based on their
corresponding content in the input.  The output is an image file, a `dot`
(directed graph) file, or an HTML file, depending on the options passed.


#### Examples

Process the query/response output produced by `dnsget`, and produce a graph
visually representing the results in a png file named "example.com.png".
```
$ dnsviz -Tpng < example.com.json > example.com.png
```

Same thing:
```
$ dnsviz -Tpng -o example.com.png example.com < example.com.json
```

Same thing, but produce interactive HTML format:
interactive HTML output in a file named "example.com.html":
```
$ dnsviz -Thtml < example.com.json > example.com.html
```

Same thing (filename is derived from domain name and output format):
```
$ dnsviz -Thtml -O -r example.com.json
```

Add DNSSEC trust anchors to the graph:
```
$ dig +noall +answer . dnskey | awk '$5 % 2 { print $0 }' > tk.txt
$ dnsviz -Thtml -O -r example.com.json -t tk.txt
```

Pipeline dnsget output directly to dnsviz:
```
$ dnsget example.com | \
      dnsviz -Thtml -O -t tk.txt
```

Same thing, but save the raw output (for re-use) along the way:
```
$ dnsget example.com | tee example.com.json | \
      dnsviz -Thtml -O -t tk.txt
```

Process analysis of multiple domain names, creating an image for each name
processed:
```
$ dnsviz -Thtml -O -r multiple.json -t tk.txt
```

Process analysis of multiple domain names, creating a single image for all
names.
```
$ dnsviz -Thtml -r multiple.json -t tk.txt
```
