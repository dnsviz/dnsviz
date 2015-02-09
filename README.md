# DNSViz


## Description

DNSViz is a tool suite for analysis and visualization of Domain Name System
(DNS) behavior, including its security extensions (DNSSEC).


## Installation


### Dependencies

* python (2.7.x) - http://www.python.org/

	python 2.7.x is required.

* dnspython (1.11.0 or later) - http://www.dnspython.org/

	dnspython is required.  Version 1.10.0 is sufficient if you're not issuing
  TLSA queries, but more generally version 1.11.0 or greater is required.

* pygraphviz (1.1 or later) - http://pygraphviz.github.io/

	pygraphviz is required if visualization is desired (e.g., via the `dnsviz`
  tool).  Online analysis (using `dnsget`) and offline analysis (e.g., using
  `dnsgrok`) can be performed without pygraphviz.  Version 1.1 or greater is
  required because of the support for unicode names and HTML-like labels, both of
  which are utilized in the visual output.

* M2Crypto (0.21.1 or later) - https://github.com/martinpaljak/M2Crypto

	M2Crypto is required if cryptographic validation of signatures and digests is
  desired (and thus is highly recommended).  The current code will display
  warnings if the cryptographic elements cannot be verified.

	Note that support for the following DNSSEC algorithms is not yet available in
  stock releases of M2Crypto: 3 (DSA-SHA1), 6 (DSA-NSEC3-SHA1),
	12 (GOST R 34.10-2001), 13 (ECDSA Curve P-256 with SHA-256), 14 (ECDSA Curve
	P-384 with SHA-384).  However, the patch included in `contrib/m2crypto.patch`
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
`dnsgrok`, and `dnsviz`.  Run any of the command-line tools without arguments
to display all options associated with their usage.


### dnsget

`dnsget` takes one or more domain names as input and performs a series of
queries, the results of which are serialized into JSON format.

Example:
```
$ dnsget example.com > example.com.json
```


### dnsgrok

`dnsgrok` takes serialized query results in JSON format (i.e., output from
`dnsget`) as input and assesses specified domain names based on their
corresponding content in the input.  The output is also serialized into JSON
format.

Example:
```
dnsgrok example.com < example.com.json > example.com-assessed.json
```


### dnsviz

`dnsviz` takes serialized query results in JSON format (i.e., output from
`dnsget`) as input and assesses specified domain names based on their
corresponding content in the input.  The output is an image file, a `dot`
(directed graph) file, or an HTML file, depending on the options passed.

Example:
```
$ dnsviz -Thtml -O example.com < example.com.json
```
