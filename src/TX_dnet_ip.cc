/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/
#include "usi++/TX_dnet_ip.h"
#include "usi++/object.h"
#include <string>
#include <cerrno>
#include <sys/types.h>


namespace usipp {

#ifdef HAVE_LIBDNET

TX_dnet_ip::TX_dnet_ip()
{
	dip = ip_open();
	if (!dip)
		die("TX_dnet_ip::ip_open:", PERROR, errno);
}


int TX_dnet_ip::sendpack(const std::string &payload)
{
	return sendpack(payload.c_str(), payload.size());
}


int TX_dnet_ip::sendpack(const void *buf, size_t len, struct sockaddr *s)
{
	if (!dip)
		return die("TX_dnet_ip::sendpack: No IP interface opened!", STDERR, -1);

	ssize_t r = (int)ip_send(dip, buf, len);
	if (r < 0)
		return die("TX_dnet_ip::sendpack::ip_send:", PERROR, errno);
	return r;
}


int TX_dnet_ip::broadcast()
{
	return 0;
}

#endif

} // namespace

