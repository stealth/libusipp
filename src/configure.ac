#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.62])
AC_INIT(libusi++, 2.22, [BUG-REPORT-ADDRESS])
AC_CONFIG_SRCDIR([arp.cc])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_RANLIB

LDFLAGS="$LDFLAGS -L/usr/local/lib64 -L/usr/local/lib"
CXXFLAGS="$CXXFLAGS -fPIC -I/usr/local/include"

# Checks for libraries.
AC_CHECK_LIB(pcap, pcap_open_live,,echo Need libpcap installed;exit)
AC_CHECK_FUNCS_ONCE(pcap_inject)
AC_CHECK_LIB(dnet, ip_open)
AC_CHECK_LIB(dumbnet, ip_open)

host=`uname`;

case "$host" in
	*inux*)
		;;
	*Free*BSD*)
		CXXFLAGS="-DBROKEN_BSD -DIMMEDIATE $CXXFLAGS"
		;;
	*free*bsd*)
		CXXFLAGS="-DBROKEN_BSD -DIMMEDIATE $CXXFLAGS"
		;;
	*BSD*)
		CXXFLAGS="$CXXFLAGS -DIMMEDIATE"
		;;
	*bsd*)
		CXXFLAGS="$CXXFLAGS -DIMMEDIATE"
		;;
	*Darwin*)
		CXXFLAGS="-DBROKEN_BSD $CXXFLAGS"
		;;
	*)
		echo "Sorry, $host not supported yet."
		;;
esac


AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(nsl, inet_ntoa)


# Checks for header files.
AC_CHECK_HEADERS([netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h unistd.h])


# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([gethostbyaddr gethostbyname gethostname inet_ntoa memset select socket strerror])

r=`grep DLT_IEEE802_11_RADIO /usr/include/pcap/bpf.h 2>/dev/null`
r+=`grep DLT_IEEE802_11_RADIO /usr/local/include/pcap/bpf.h 2>/dev/null`
case "$r" in
	*DLT_IEEE802_11_RADIO*)
		AC_DEFINE([HAVE_RADIOTAP], [1], [Define if radiotap exists.])
		echo "Enabling 80211 radiotap"
		;;
	*)
esac

r=`grep pcap_set_immediate_mode /usr/include/pcap/pcap.h 2>/dev/null`
r+=`grep pcap_set_immediate_mode /usr/local/include/pcap/pcap.h 2>/dev/null`
case "$r" in
	*pcap_set_immediate*)
		AC_DEFINE([HAVE_PCAP_SET_IMMEDIATE_MODE], [1], [Define if you have pcap_set_immediate_mode.])
		echo "Enabling pcap_set_immediate"
		;;
	*)
esac


AC_CONFIG_FILES([Makefile])
AC_OUTPUT

rm -f ../usi++/config.h||true
cp config.h ../usi++/config.h

