Summary: DPM Apache httpd CGI
Name: DPM-httpd-cgi
Version: @VERSION@
Release: @RELEASE@@RELEASE.SUFFIX@
License: GPL
Vendor: gLite
Group: grid/lcg
Requires: httpd >= 2.0, mod_ssl >= 2.0, gridsite-apache >= 1.1.18, dpm-libs >= 1.7.4, vdt_globus_essentials
AutoReqProv: no
Prefix: /opt/lcg
Source: %{name}-%{version}.tar.gz
BuildRoot: %{_builddir}/%{name}-root

%define debug_package %{nil}
%define _unpackaged_files_terminate_build  %{nil}

%description
The DPM CGI enables high performance file upload via 
httpd PUT or POST request.

%prep
rm -rf $RPM_BUILD_ROOT
%setup -q

%build
./configure --prefix=%{prefix} ${EXTRA_CONFIGURE_OPTIONS}
make

%install
make DESTDIR=$RPM_BUILD_ROOT install

%clean
echo rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%dir %{prefix}/var/dpm/https/cgi-bin/
%{prefix}/var/dpm/https/cgi-bin/https_dpm_redirector_cgi.cgi

%changelog

