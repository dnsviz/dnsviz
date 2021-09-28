Name:           dnsviz
Version:        0.9.3
Release:        1%{?dist}
Summary:        Tools for analyzing and visualizing DNS and DNSSEC behavior

License:        GPLv2+
URL:            https://github.com/dnsviz/dnsviz
Source0:        https://github.com/dnsviz/dnsviz/releases/download/v%{version}/%{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  graphviz
BuildRequires:  make
Requires:       python3-pygraphviz >= 1.3
Requires:       python3-m2crypto >= 0.28.0
Requires:       python3-dns >= 1.13

%description
DNSViz is a tool suite for analysis and visualization of Domain Name System
(DNS) behavior, including its security extensions (DNSSEC).  This tool suite
powers the Web-based analysis available at http://dnsviz.net/

%prep
%autosetup

%build
%py3_build

%install
#XXX Normally the py3_install macro would be used here,
# but dnsviz/config.py is build with the install command,
# so install MUST call the build subcommand, so config.py
# will be proplerly placed.  With py3_install, the
# --skip-build argument is used.
%{__python3} %{py_setup} %{?py_setup_args} install -O1 --root %{buildroot} %{?*}

#XXX no checks yet
#%check
#%{__python3} setup.py test

%clean
rm -rf %{buildroot}

%files
%license LICENSE
%doc README.md
%{python3_sitelib}/%{name}/*
%{python3_sitelib}/%{name}-%{version}-*.egg-info/*
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
* Mon Sep  27 2021 Casey Deccio
  0.9.4 release
* Thu Mar  11 2021 Casey Deccio
  0.9.3 release
* Fri Feb  5 2021 Casey Deccio
  0.9.2 release
* Tue Jan  19 2021 Casey Deccio
  0.9.1 release
* Fri Jan  8 2021 Casey Deccio
  0.9.0 release
* Wed Feb  6 2019 Casey Deccio
  0.8.1 release
* Fri Jan  25 2019 Casey Deccio
  0.8.0 release
