Name:           dnsviz
Version:        0.8.2
Release:        1%{?dist}
Summary:        Tools for analyzing and visualizing DNS and DNSSEC behavior

License:        GPLv2+
URL:            https://github.com/dnsviz/dnsviz
Source0:        https://github.com/dnsviz/dnsviz/releases/download/v%{version}/%{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python2-devel
BuildRequires:  graphviz
BuildRequires:  make
# python2-pygraphviz should be >= 1.4
Requires:       python2-pygraphviz >= 1.3
Requires:       m2crypto >= 0.28.0
Requires:       python2-dns >= 1.13
Requires:       python2-libnacl

%description
DNSViz is a tool suite for analysis and visualization of Domain Name System
(DNS) behavior, including its security extensions (DNSSEC).  This tool suite
powers the Web-based analysis available at http://dnsviz.net/

%prep
%autosetup

%build
%py2_build

%install
#XXX Normally the py2_install macro would be used here,
# but dnsviz/config.py is build with the install command,
# so install MUST call the build subcommand, so config.py
# will be proplerly placed.  With py2_install, the
# --skip-build argument is used.
%{__python2} %{py_setup} %{?py_setup_args} install -O1 --root %{buildroot} %{?*}

#XXX no checks yet
#%check
#%{__python2} setup.py test

%clean
rm -rf %{buildroot}

%files
%license LICENSE
%doc README.md
%{python2_sitelib}/%{name}/*
%{python2_sitelib}/%{name}-%{version}-py2.7.egg-info/*
%{_bindir}/%{name}
%{_datadir}/%{name}/*
%{_defaultdocdir}/%{name}/dnsviz-graph.html
%{_defaultdocdir}/%{name}/images/*png
%{_mandir}/man1/%{name}.1*
%{_mandir}/man1/%{name}-probe.1*
%{_mandir}/man1/%{name}-graph.1*
%{_mandir}/man1/%{name}-grok.1*
%{_mandir}/man1/%{name}-print.1*
%{_mandir}/man1/%{name}-query.1*

%changelog
* Tue Mar  12 2019 Casey Deccio
  0.8.2 release
* Wed Feb  6 2019 Casey Deccio
  0.8.1 release
* Fri Jan  25 2019 Casey Deccio
  0.8.0 release
