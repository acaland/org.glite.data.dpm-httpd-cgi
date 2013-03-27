#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(dpm-httpd-cgi, 1.2.0,[andreas.joachim.peters@cern.ch])

AC_CONFIG_SRCDIR([https_dpm_redirector_cgi.c])

# use C++ for the compilation of tests
dnl currently commented out, since older versions of libtool (<1.5) contain
dnl a test similar to AM_PROG_CC_C_O which triggers locking by libtool itself
dnl if AC_LANG(C++) is in effect.
dnl Since the locking is implemented via a hardlink to a file, this does not
dnl work on AFS
dnl AC_LANG(C++)
AC_CANONICAL_HOST
MYGLOBUS_FLAVOR=gcc32
MYGLOBUS_LOCATION=/opt/globus

case "${host}" in
   ia64-*-linux*)
      MYGLOBUS_FLAVOR=gcc64
      ;;
   x86_64-*-linux*)
      MYGLOBUS_FLAVOR=gcc64
      ;;
esac

AC_PROG_MAKE_SET
AC_CANONICAL_TARGET
case "$target_os" in
   tiger*)
     AC_DEFINE(__macos__)
     ;;
   darwin*)
     AC_DEFINE(__macos__) ;;
   apple*)
     AC_DEFINE(__macos__)
     ;;
   linux*)
     # TODO: check why two different macros are used for this
     AC_DEFINE(__linux__)
     AC_DEFINE(__linux)
     ;;
   solaris*)
     AC_DEFINE(__sun)
     CC_PREFERENCE="cc gcc"
     DFLT_OPT="-O2"
     ;;
   *)
     AC_MSG_WARN([untested operating system])
   ;;
esac

if test "x$GLOBUS_LOCATION" = "x" ; then
   if test -d $MYGLOBUS_LOCATION ; then
      GLOBUS_LOCATION=$MYGLOBUS_LOCATION;
   fi    
fi

if test "x$GLOBUS_FLAVOR" = "x" ; then
   GLOBUS_FLAVOR=$MYGLOBUS_FLAVOR;
fi

AC_ARG_WITH( globus-flavor,   [ --with-globus-flavor[=FLAVOR]    GLOBUS Flavor], , [with_globus_flavor="$MYGLOBUS_FLAVOR"] )
AC_ARG_WITH( globus-location, [ --with-globus-location[=DIR]     GLOBUS Location], , [with_globus_location="$MYGLOBUS_LOCATION"] )
AC_ARG_WITH( dpm-location,    [ --with-dpm-location[=DIR]        DPM Location], , [with_dpm_location="/opt/lcg"] )

AC_MSG_CHECKING(for Globus directory)

# make sure that a well known include file exists
if test -d $with_globus_location/include/$with_globus_flavor/; then
     GLOBUS_LOCATION=$with_globus_location
     AC_MSG_RESULT(GLOBUS found!)
else
     AC_MSG_ERROR( $with_globus_location/include/$with_globus_flavor/globus_config.h not found.  Check the value you specified with --with-globus-location & --with-globus-flavor)
fi

AC_MSG_CHECKING(for DPM api)
if test -e $with_dpm_location/include/dpm/dpm_api.h; then
     DPM_LOCATION=$with_dpm_location
     AC_MSG_RESULT(DPM api found!)
else
     AC_MSG_ERROR( $with_dpm_location/include/dpm/dpm_api.h not found.  Check the value you specified with --with-dpm-location )
fi


AM_INIT_AUTOMAKE(1.6 foreign)

echo "GLOBUS_LOCATION   = $GLOBUS_LOCATION";
echo "GLOBUS_FLAVOR     = $GLOBUS_FLAVOR";
echo "DPM_LOCATION      = $DPM_LOCATION";

# we cannot simply replace DPM's libdir, as its VOMS dependency 
# library is still located inside 'lib', instead of 'lib64'
DPM_LDFLAGS=-L${DPM_LOCATION}/lib
case "${host}" in
   x86_64-*-linux*)
      AC_SUBST([libdir], ['${exec_prefix}/lib64'])
      DPM_LDFLAGS="-L${DPM_LOCATION}/lib64 ${DPM_LDFLAGS}"
      ;;
esac
AC_SUBST([DPM_LDFLAGS])

# Set GLOBUS ENV
AC_SUBST(GLOBUS_FLAVOR)
AC_SUBST(GLOBUS_LOCATION)

# Set DPM ENV
AC_SUBST(DPM_LOCATION)

# Do all testing using C
AC_LANG([C])

# Checks for programs.
AC_PROG_CC

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_STAT
AC_CHECK_FUNCS([gettimeofday mkdir strdup])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

