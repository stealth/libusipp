/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/

#include "config.h"
#include "usi++/usi++.h"

#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#ifdef IMMEDIATE
#include <net/bpf.h>
#endif

#ifdef USI_DEBUG
#include <iostream>
#endif

namespace usipp {

using namespace std;


pcap::pcap()
	: RX()
{
	// Initialize
	d_localnet = d_netmask = 0;
	d_filter_string = "";
	d_cooked = "";
	d_dev = "";
	d_pd = NULL;
	memset(&d_tv, 0, sizeof(d_tv));
	d_timeout = false;
	memset(&d_ether, 0, sizeof(d_ether));
}


/* This constructor should be used to
 *  initialize raw-d_datalink-objects, means not IP/TCP/ICMP etc.
 *  We need this b/c unlike in derived classes, pcap::init_device()
 *  cannot set a filter!
 */
pcap::pcap(const string &filterStr)
	: RX()
{
	// Initialize
	d_localnet = d_netmask = 0;
	d_filter_string = filterStr;
	d_cooked = "";
	d_dev = "";
	d_pd = NULL;
	memset(&d_tv, 0, sizeof(d_tv));
	d_timeout = false;
	memset(&d_ether, 0, sizeof(d_ether));
}


pcap::~pcap()
{
	if (d_pd != NULL)
		pcap_close(d_pd);
}


pcap::pcap(const pcap &rhs)
{
	if (this == &rhs)
		return;
	d_datalink = rhs.d_datalink;
	d_framelen = rhs.d_framelen;
	d_filter = rhs.d_filter;
	d_phdr = rhs.d_phdr;

	d_ether = rhs.d_ether;
	d_80211 = rhs.d_80211;
	d_cooked = rhs.d_cooked;

	d_filter_string = rhs.d_filter_string;
	d_dev = rhs.d_dev;
	d_has_promisc = rhs.d_has_promisc;
	d_snaplen = rhs.d_snaplen;

	d_localnet = rhs.d_localnet;
	d_netmask = rhs.d_netmask;

	if (rhs.d_pd)
		init_device(d_dev, d_has_promisc, d_snaplen);

	return;
}


pcap &pcap::operator=(const pcap &rhs)
{
	if (this == &rhs)
		return *this;
	d_datalink = rhs.d_datalink;
	d_framelen = rhs.d_framelen;
	d_filter = rhs.d_filter;
	d_phdr = rhs.d_phdr;

	d_ether = rhs.d_ether;
	d_80211 = rhs.d_80211;
	d_cooked = rhs.d_cooked;

	d_filter_string = rhs.d_filter_string;
	d_dev = rhs.d_dev;
	d_has_promisc = rhs.d_has_promisc;
	d_snaplen = rhs.d_snaplen;

	d_localnet = rhs.d_localnet;
	d_netmask = rhs.d_netmask;

	if (rhs.d_pd) {
		if (d_pd)
			pcap_close(d_pd);
		init_device(d_dev, d_has_promisc, d_snaplen);
	}

	return *this;
}


/*  Return the actual d_datalink of the object.
 */
int pcap::get_datalink()
{
   	return d_datalink;
}


/*  Return the actual framlen of the object.
 *  (d_framelen depends on d_datalink)
 */
int pcap::get_framelen()
{
	return d_framelen;
}


/* Get the cooked header, if any (HAVE_RADIOTAP)
 */
string &pcap::get_cooked(string &hdr)
{
	hdr = d_cooked;
	return hdr;
}


/*  Fill buffer with src-hardware-adress of actuall packet,
 *  use 'd_datalink' to determine what HW the device is.
 *  Now only ethernet s supportet, but it's extensinable.
 */
string &pcap::get_l2src(string &hwaddr)
{
	switch (d_datalink) {
	case DLT_EN10MB:
		hwaddr = string(reinterpret_cast<char *>(d_ether.ether_shost), ETH_ALEN);
	default:
		hwaddr = "";
	}
	return hwaddr;
}


/*  Fill buffer with dst-hardware-adress of actuall packet,
 *  use 'd_datalink' to determine what HW the device is.
 *  Now only ethernet s supportet.
 */
string &pcap::get_l2dst(string &hwaddr)
{
	switch (d_datalink) {
	case DLT_EN10MB:
		hwaddr = string(reinterpret_cast<char *>(d_ether.ether_dhost), ETH_ALEN);
	default:
		hwaddr = "";
	}
	return hwaddr;
}


/*  Get protocol-type of ethernet-frame
 *  Maybe moves to ethernet-class in future?
 */
uint16_t pcap::get_etype()
{
   	return ntohs(d_ether.ether_type);
}


/*  Initialize a device ("eth0" for example) for packet-
 *  capturing. It MUST be called before sniffpack() is launched.
 *  Set 'promisc' to 1 if you want the device running in promiscous mode.
 *  Fetch at most 'd_snaplen' bytes per call.
 */
int pcap::init_device(const string &dev, int promisc, size_t d_snaplen)
{
	char ebuf[PCAP_ERRBUF_SIZE];
	memset(ebuf, 0, PCAP_ERRBUF_SIZE);

	string e = "";

	if ((d_pd = pcap_open_live(dev.c_str(), d_snaplen, promisc, 500, ebuf)) == NULL) {
		e = "pcap::init_device::pcap_open_live:";
		e += ebuf;
		return die(e, STDERR, -1);
	}

// Ehem, BSD workarounnd. BSD won't timeout on select()
// unless we force immediate return for read() (in pcap)
// for uncomplete packets (queue not full?)
#ifdef IMMEDIATE
	int v = 1;
	if (ioctl(pcap_fileno(d_pd), BIOCIMMEDIATE, &v) < 0) {
		e = "pcap::init_device::ioctl(..., BIOCIMMEDIATE, 1):";
		e += strerror(errno);
		return die(e, STDERR, -1);
	}
#endif

	// ignore error, as device might be down or not IP-based
	pcap_lookupnet(dev.c_str(), &d_localnet, &d_netmask, ebuf);

	if (d_filter_string.size() > 0) {
		/* The d_filter_string must be filled by derived classes, such
		 * as IP, where the virtual init_device() simply sets d_filter_string
		 * to "ip" and then calls pcap::init_device().
		 */
		if (pcap_compile(d_pd, &d_filter, d_filter_string.c_str(), 1, d_netmask) < 0) {
			e = "pcap::init_device::pcap_compile:";
			e += pcap_geterr(d_pd);
			return die(e, STDERR, -1);
		}

		if (pcap_setfilter(d_pd, &d_filter) < 0) {
			e = "pcap::init_device::pcap_setfilter:";
			e += pcap_geterr(d_pd);
			return die(e, STDERR, -1);
		}
	}


	if ((d_datalink = pcap_datalink(d_pd)) < 0) {
		e = "pcap::init_device::pcap_datalink:";
		e += pcap_geterr(d_pd);
		return die(e, STDERR, -1);
	}

	// turn d_datalink into d_framelen
	switch (d_datalink) {
	case DLT_EN10MB:
		d_framelen = sizeof(d_ether);
		break;
#ifdef HAVE_RADIOTAP
	case DLT_IEEE802_11_RADIO:
		d_framelen = sizeof(d_80211);
		break;
#endif
	case DLT_PPP:
		d_framelen = 4;
		break;
	case DLT_PPP_BSDOS:
		d_framelen = 24;
		break;
	case DLT_SLIP:
		d_framelen = 24;
		break;
	case DLT_RAW:
		d_framelen = 0;
		break;
	// loopback
	case DLT_NULL:
		d_framelen = 4;
		break;
	case DLT_LINUX_SLL:
		d_framelen = 16;
		break;
	default:
		return die("pcap::init_device: Unknown datalink type.", STDERR, -1);
	}

	d_dev = dev;
	d_has_promisc = promisc;
	d_snaplen = d_snaplen;
	return 0;
}


/*  set a new filter for capturing
 */
int pcap::setfilter(const string &s)
{
	char ebuf[PCAP_ERRBUF_SIZE];
	memset(ebuf, 0, PCAP_ERRBUF_SIZE);

	string e = "";

	if (!d_pd)
		return die("pcap::setfilter: Device not initialized.", STDERR, -1);

	d_filter_string = s;

	if (pcap_compile(d_pd, &d_filter, d_filter_string.c_str(), 1, d_netmask) < 0) {
		e = "pcap::setfilter::pcap_compile:";
		e += pcap_geterr(d_pd);
		return die(e, STDERR, -1);
	}

	if (pcap_setfilter(d_pd, &d_filter) < 0) {
		e = "pcap::setfilter::pcap_setfilter:";
		e += pcap_geterr(d_pd);
		return die(e, STDERR, -1);
	}
	return 0;
}


string &pcap::sniffpack(string &s)
{
	s = "";
	char buf[4096];
	int r = this->sniffpack(buf, sizeof(buf));
	if (r > 0)
		s = string(buf, r);
	return s;
}


int pcap::sniffpack(void *s, size_t len)
{
   	char *tmp;

	memset(s, 0, len);

	d_timeout = false;
	if (!d_pd)
		return die("pcap::sniffpack: Device not initialized.", STDERR, -1);

	if (d_tv.tv_sec != 0 || d_tv.tv_usec != 0) {	// TO was set
		while (1) {
			fd_set rset;
			FD_ZERO(&rset);
			int fd = pcap_fileno(d_pd);
			FD_SET(fd, &rset);
			timeval tmp = d_tv;

			// wait for packet
			int sr;
			if ((sr = select(fd + 1, &rset, NULL, NULL, &tmp)) < 0) {
				if (errno == EINTR)
					continue;
				else
					return -1;
			} else if (sr == 0) { // timed out
				d_timeout = true;
				return 0;
			} else		// got packet
				break;
		}
	}

	while ((tmp = (char*)pcap_next(d_pd, &d_phdr)) == NULL);

	uint16_t cooked_hdr = 0;

	switch (d_datalink) {
	case DLT_EN10MB:
		memcpy(&d_ether, tmp, d_framelen);
		break;
#ifdef HAVE_RADIOTAP
	case DLT_IEEE802_11_RADIO:
		cooked_hdr = ((ieee80211_radiotap_header *)tmp)->len;
		d_cooked = string(tmp, cooked_hdr);
		memcpy(&d_80211, tmp + cooked_hdr, d_framelen);
		break;
#endif
	case DLT_PPP:
		break;
	case DLT_PPP_BSDOS:
		break;
	case DLT_SLIP:
		break;
	case DLT_RAW:
		break;
	case DLT_LINUX_SLL:
		break;
	default:
		return die("pcap::sniffpack: Unknown d_datalink.", STDERR, -1);
	}

#ifdef USI_DEBUG
	cerr<<"pcap::d_phdr.len="<<d_phdr.len<<endl;
 	cerr<<"pcap::d_framelen="<<d_framelen<<endl;
#endif

	// d_framelen was already calculated by init_device
	memcpy(s, tmp + cooked_hdr + d_framelen,
	       d_phdr.len - cooked_hdr - d_framelen < len ? d_phdr.len - cooked_hdr - d_framelen : len);
	return d_phdr.len - cooked_hdr - d_framelen < len ? d_phdr.len - cooked_hdr - d_framelen : len;
}


// give back layer2 frame
void *pcap::get_frame(void *hwframe, size_t len)
{
	// switch over the hardware-layer of the packet
	switch (d_datalink) {
   	case DLT_EN10MB:
		memcpy(hwframe, &d_ether, (len<sizeof(d_ether)?len:sizeof(d_ether)));
		break;
#ifdef HAVE_RADIOTAP
	case DLT_IEEE802_11_RADIO:
		memcpy(hwframe, &d_80211, (len<sizeof(d_80211)?len:sizeof(d_80211)));
		break;
#endif
	default:
	   	return NULL;
	}
	return hwframe;
}

string &pcap::get_frame(string &frame)
{
	frame = "";

	char buf[1024];

	switch (d_datalink) {
	case DLT_EN10MB:
		memcpy(buf, &d_ether, sizeof(d_ether));
		frame = string(buf, sizeof(d_ether));
		break;
#ifdef HAVE_RADIOTAP
	case DLT_IEEE802_11_RADIO:
		memcpy(buf, &d_80211, sizeof(d_80211));
		frame = string(buf, sizeof(d_80211));
		break;
#endif
	default:
		;
	}

	return frame;
}


int pcap::timeout(const struct timeval &tv)
{
	d_tv = tv;
	d_timeout = false;
	return 0;
}


bool pcap::timeout()
{
	return d_timeout;
}

} // namespace usipp

