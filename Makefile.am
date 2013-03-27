#######################################################################
## Makefile.am for https redirection on a DPM server
##
##
## Author: Andreas Joachim Peters <andreas.joachim.peters@cern.ch>
## 
## Initial version: 3.7.2007
##
## Version info: $Id: Makefile.am,v 1.4 2007/10/15 20:51:58 szamsu Exp $
## Checked in by $Author: szamsu $
#######################################################################

cgidir = $(localstatedir)/dpm/https/cgi-bin
cgi_PROGRAMS = https_dpm_redirector_cgi.cgi

INCLUDES = -I. -I$(DPM_LOCATION)/include -I$(DPM_LOCATION)/include/dpm -I$(GLOBUS_LOCATION)/include/$(GLOBUS_FLAVOR)

AM_LDFLAGS = -Wl,-rpath,$(GLOBUS_LOCATION)/lib

https_dpm_redirector_cgi_cgi_SOURCES = https_dpm_redirector_cgi.c https_dpm_redirector_cgi.h https_dpm_util_cgi.c https_dpm_util_cgi.h
https_dpm_redirector_cgi_cgi_LDADD = -ldl $(DPM_LDFLAGS) -ldpm -L$(GLOBUS_LOCATION)/lib/ -lglobus_gss_assist -lssl
https_dpm_redirector_cgi_cgi_LDFLAGS = -all-static

EXTRA_DIST = README
