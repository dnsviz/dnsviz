# ![DNSViz](doc/images/logo-220x100.png)

## Description

DNSViz is a tool suite for analysis and visualization of Domain Name System
(DNS) behavior, including its security extensions (DNSSEC).  This tool suite
powers the Web-based analysis available at http://dnsviz.net/


## Installation


### Dependencies

* python (2.6/2.7/3.4) - http://www.python.org/

  python 2.6, 2.7, or 3.4 is required.  For python 3.4 the other third-party
  dependencies must also support python 3.4.  Note that for python 2.6 the
  importlib (https://pypi.python.org/pypi/importlib) and ordereddict
  (https://pypi.python.org/pypi/ordereddict) packages are also required.

* dnspython (1.11.0 or later) - http://www.dnspython.org/

  dnspython is required.  Version 1.10.0 is sufficient if you're not issuing
  TLSA queries, but more generally version 1.11.0 or greater is required.

* pygraphviz (1.1 or later) - http://pygraphviz.github.io/

  pygraphviz is required for most functionality.   `dnsviz probe` and `dnsviz grok`
  (without the -t option) can be used without pygraphviz installed.  Version 1.1
  or greater is required because of the support for unicode names and HTML-like
  labels, both of which are utilized in the visual output.

* M2Crypto (0.24.0 or later) - https://gitlab.com/m2crypto/m2crypto

  M2Crypto is required if cryptographic validation of signatures and digests is
  desired (and thus is highly recommended).  The current code will display
  warnings if the cryptographic elements cannot be verified.

  Note that M2Crypto version 0.21.1 or later can be used to validate some
  DNSSEC algorithms, but support for the following DNSSEC algorithms is not
  available in releases of M2Crypto prior to 0.24.0 without a patch:
  3 (DSA-SHA1), 6 (DSA-NSEC3-SHA1), 12 (GOST R 34.10-2001),
  13 (ECDSA Curve P-256 with SHA-256), 14 (ECDSA Curve P-384 with SHA-384).
  There are two patches included in the `contrib` directory that can be
  applied to pre-0.24.0 versions to get this functionality:
  `contrib/m2crypto-pre0.23.patch` or `contrib/m2crypto-0.23.patch`.  For
  example:

  ```
  $ patch -p1 < /path/to/dnsviz-source/contrib/m2crypto-pre0.23.patch
  ```

* (optional) ISC BIND - https://www.isc.org/downloads/bind/

  When calling `dnsviz probe` if the `-N` option is used or if a zone file is
  used in conjunction with the `-x` option, `named(8)` is looked for in PATH
  and invoked to serve the zone file.  ISC BIND is only needed in this specific
  case, and `named(8)` does not need to be running.


### Generic Build and Install

A generic build and install is performed with the following commands:

```
$ python setup.py build
$ sudo python setup.py install
```

To see all installation options, run the following:

```
$ python setup.py --help
```


### RPM Build and Install (RHEL6 or RHEL7)

Install pygraphviz and M2Crypto, after installing their build dependencies.
```
$ sudo yum install python-setuptools gcc python-devel graphviz-devel openssl-devel
$ sudo easy_install pbr
$ sudo easy_install m2crypto pygraphviz
```

(RHEL6 only) Install the EPEL repository, and the necessary python libraries
from that repository.
```
$ sudo yum install epel-release
$ sudo yum install python-importlib python-ordereddict
```

Install dnspython.
```
$ sudo yum install python-dns
```

Install rpm-build tools, then build and install the DNSViz RPM.
```
$ sudo yum install rpm-build
$ python setup.py bdist_rpm --install-script contrib/rpm-install.sh --distribution-name el${RHEL_VERS}
$ sudo rpm -iv dist/dnsviz-*-1.noarch.rpm
```
Note that a custom install script is used to properly install the DNSViz man
pages.  The value of ${RHEL_VERS} corresponds to the RHEL version (e.g., 6 or
7).


## Usage

DNSViz is invoked using the `dnsviz` command-line utility.  `dnsviz` itself
uses several subcommands: `probe`, `grok`, `graph`, `print`, and `query`.  See
the man pages associated with each subcommand, in the form of
"dnsviz-<subcommand> (1)" (e.g., "man dnsviz-probe") for more detailed
documentation and usage.

### dnsviz probe

`dnsviz probe` takes one or more domain names as input and performs a series of
queries to either recursive (default) or authoritative DNS servers, the results
of which are serialized into JSON format.


#### Examples

Analyze the domain name example.com using your configured DNS resolvers (i.e.,
in `/etc/resolv.conf`) and store the queries and responses in the file named
"example.com.json":
```
$ dnsviz probe example.com > example.com.json
```

Same thing:
```
$ dnsviz probe -o example.com.json example.com
```

Analyze the domain name example.com by querying its authoritative servers
directly:
```
$ dnsviz probe -A -o example.com.json example.com
```

Analyze the domain name example.com by querying explicitly-defined
authoritative servers, rather than learning the servers through referrals from
the IANA root servers:
```
$ dnsviz probe -A \
  -x example.com:a.iana-servers.org=199.43.132.53,a.iana-servers.org=[2001:500:8c::53] \
  -x example.com:b.iana-servers.org=199.43.133.53,b.iana-servers.org=[2001:500:8d::53] \
  -o example.com.json example.com
```

Same, but have `dnsviz probe` resolve the names:
```
$ dnsviz probe -A \
  -x example.com:a.iana-servers.org,b.iana-servers.org \
  -o example.com.json example.com
```

Analyze the domain name example.com and its entire ancestry by querying
authoritative servers and following delegations, starting at the root:
```
$ dnsviz probe -A -a . -o example.com.json example.com
```

Analyze multiple names in parallel (four threads) using explicit recursive
resolvers (replace *192.0.1.2* and *2001:db8::1* with legitimate resolver
addresses):
```
$ dnsviz probe -s 192.0.2.1,[2001:db8::1] -t 4 -o multiple.json \
  example.com sandia.gov verisignlabs.com dnsviz.net
```


### dnsviz grok

`dnsviz grok` takes serialized query results in JSON format (i.e., output from
`dnsviz probe`) as input and assesses specified domain names based on their
corresponding content in the input.  The output is also serialized into JSON
format.


#### Examples

Process the query/response output produced by `dnsviz probe`, and store the
serialized results in a file named "example.com-chk.json":
```
$ dnsviz grok < example.com.json > example.com-chk.json
```

Same thing:
```
$ dnsviz grok -r example.com.json -o example.com-chk.json example.com
```

Show only info-level information: descriptions, statuses, warnings, and errors:
```
$ dnsviz grok -l info -r example.com.json -o example.com-chk.json
```

Show descriptions only if there are related warnings or errors:
```
$ dnsviz grok -l warning -r example.com.json -o example.com-chk.json
```

Show descriptions only if there are related errors:
```
$ dnsviz grok -l error -r example.com.json -o example.com-chk.json
```

Use root key as DNSSEC trust anchor, to additionally indicate
authentication status of responses:
```
$ dig +noall +answer . dnskey | awk '$5 % 2 { print $0 }' > tk.txt
$ dnsviz grok -l info -t tk.txt -r example.com.json -o example.com-chk.json
```

Pipe `dnsviz probe` output directly to `dnsviz grok`:
```
$ dnsviz probe example.com | \
      dnsviz grok -l info -o example.com-chk.json
```

Same thing, but save the raw output (for re-use) along the way:
```
$ dnsviz probe example.com | tee example.com.json | \
      dnsviz grok -l info -o example.com-chk.json
```

Assess multiple names at once with error level:
```
$ dnsviz grok -l error -r multiple.json -o example.com-chk.json
```


### dnsviz graph

`dnsviz graph` takes serialized query results in JSON format (i.e., output from
`dnsviz probe`) as input and assesses specified domain names based on their
corresponding content in the input.  The output is an image file, a `dot`
(directed graph) file, or an HTML file, depending on the options passed.


#### Examples

Process the query/response output produced by `dnsviz probe`, and produce a
graph visually representing the results in a png file named "example.com.png".
```
$ dnsviz graph -Tpng < example.com.json > example.com.png
```

Same thing:
```
$ dnsviz graph -Tpng -o example.com.png example.com < example.com.json
```

Same thing, but produce interactive HTML format:
interactive HTML output in a file named "example.com.html":
```
$ dnsviz graph -Thtml < example.com.json > example.com.html
```

Same thing (filename is derived from domain name and output format):
```
$ dnsviz graph -Thtml -O -r example.com.json
```

Use alternate DNSSEC trust anchor:
```
$ dig +noall +answer example.com dnskey | awk '$5 % 2 { print $0 }' > tk.txt
$ dnsviz graph -Thtml -O -r example.com.json -t tk.txt
```

Pipe `dnsviz probe` output directly to `dnsviz graph`:
```
$ dnsviz probe example.com | \
      dnsviz graph -Thtml -O
```

Same thing, but save the raw output (for re-use) along the way:
```
$ dnsviz probe example.com | tee example.com.json | \
      dnsviz graph -Thtml -O
```

Process analysis of multiple domain names, creating an image for each name
processed:
```
$ dnsviz graph -Thtml -O -r multiple.json
```

Process analysis of multiple domain names, creating a single image for all
names.
```
$ dnsviz graph -Thtml -r multiple.json > multiple.html
```


### dnsviz print

`dnsviz print` takes serialized query results in JSON format (i.e., output from
`dnsviz probe`) as input and assesses specified domain names based on their
corresponding content in the input.  The output is textual output suitable for
file or terminal display.


#### Examples

Process the query/response output produced by `dnsviz probe`, and output the
results to the terminal:
```
$ dnsviz print < example.com.json
```

Use alternate DNSSEC trust anchor:
```
$ dig +noall +answer example.com dnskey | awk '$5 % 2 { print $0 }' > tk.txt
$ dnsviz print -r example.com.json -t tk.txt
```

Pipe `dnsviz probe` output directly to `dnsviz print`:
```
$ dnsviz probe example.com | \
      dnsviz print
```

Same thing, but save the raw output (for re-use) along the way:
```
$ dnsviz probe example.com | tee example.com.json | \
      dnsviz print
```


### dnsviz query

`dnsviz query` is a wrapper that couples the functionality of `dnsviz probe`
and `dnsviz print` into a tool with minimal dig-like usage, used to make
analysis queries and return the textual output to terminal or file output in
one go.


#### Examples

Analyze the domain name example.com using the first of your configured DNS
resolvers (i.e., in `/etc/resolv.conf`):
```
$ dnsviz query example.com
```

Same, but specify an alternate trust anchor:
```
$ dnsviz query +trusted-key=tk.txt example.com
```

Analyze example.com through the recursive resolver at 192.0.2.1:
```
$ dnsviz query @192.0.2.1 +trusted-key=tk.txt example.com
```


## Pre-Deployment DNS Testing

The examples in this section demonstrate usage of DNSViz for pre-deployment
testing.


### Pre-Delegation Testing

The following examples involve issuing diagnostic queries for a zone before it
is ever delegated.

Issue queries against a zone file on the local system (`example.com.zone`).
`named(8)` is invoked to serve the file locally:
```
$ dnsviz probe -A -x example.com+:example.com.zone example.com
```
(Note the use of "+", which designates that the parent servers should not be
queried for DS records.)

Issue queries to a server that is serving the zone:
```
$ dnsviz probe -A -x example.com+:192.0.2.1 example.com
```
(Note that this server doesn't need to be a server in the NS RRset for
example.com.)

Issue queries to the servers in the authoritative NS RRset, specified by name
and/or address:
```
$ dnsviz probe -A \
      -x example.com+:ns1.example.com=192.0.2.1 \
      -x example.com+:ns2.example.com=192.0.2.1,ns2.example.com=[2001:db8::1] \
      example.com
```

Specify the names and addresses corresponding to the future delegation NS
records and (as appropriate) A/AAAA glue records in the parent zone (com):
```
$ dnsviz probe -A \
      -N example.com:ns1.example.com=192.0.2.1 \
      -N example.com:ns2.example.com=192.0.2.1,ns2.example.com=[2001:db8::1] \
      example.com
```

Also supply future DS records:
```
$ dnsviz probe -A \
      -N example.com:ns1.example.com=192.0.2.1 \
      -N example.com:ns2.example.com=192.0.2.1,ns2.example.com=[2001:db8::1] \
      -D example.com:dsset-example.com. \
      example.com
```


### Pre-Deployment Testing of Authoritative Zone Changes

The following examples involve issuing diagnostic queries for a delegated zone
before changes are deployed.

Issue diagnostic queries for a new zone file that has been created but not yet
been deployed (i.e., with changes to DNSKEY or other records):
```
$ dnsviz probe -A -x example.com:example.com.zone example.com
```
(Note the absence of "+", which designates that the parent servers will be
queried for DS records.)

Issue queries to a server that is serving the new version of the zone:
```
$ dnsviz probe -A -x example.com:192.0.2.1 example.com
```
(Note that this server doesn't need to be a server in the NS RRset for
example.com.)


### Pre-Deployment Testing of Delegation Changes

The following examples involve issuing diagnostic queries for a delegated zone
before changes are deployed to the delegation, glue, or DS records for that
zone.

Specify the names and addresses corresponding to the new delegation NS records
and (as appropriate) A/AAAA glue records in the parent zone (com):
```
$ dnsviz probe -A \
      -N example.com:ns1.example.com=192.0.2.1 \
      -N example.com:ns2.example.com=192.0.2.1,ns2.example.com=[2001:db8::1] \
      example.com
```

Also supply the replacement DS records:
```
$ dnsviz probe -A \
      -N example.com:ns1.example.com=192.0.2.1 \
      -N example.com:ns2.example.com=192.0.2.1,ns2.example.com=[2001:db8::1] \
      -D example.com:dsset-example.com. \
      example.com
```
