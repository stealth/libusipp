/*
 * This file is part of the libusi++ packet capturing/sending framework.
 *
 * (C) 2000-2016 by Sebastian Krahmer,
 *                  sebastian [dot] krahmer [at] gmail [dot] com
 *
 * libusi++ is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * libusi++ is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libusi++.  If not, see <http://www.gnu.org/licenses/>.
 */

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
	d_frame2 = "";
	d_llc = "";
	d_qos = "";
	d_dev = "";
	d_pd = NULL;
	memset(&d_tv, 0, sizeof(d_tv));
	d_timeout = false;
	d_packet = NULL;
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
	d_frame2 = "";
	d_llc = "";
	d_qos = "";
	d_dev = "";
	d_pd = NULL;
	memset(&d_tv, 0, sizeof(d_tv));
	d_timeout = false;
	d_packet = NULL;
	memset(&d_ether, 0, sizeof(d_ether));
}


pcap::~pcap()
{
	if (d_pd != NULL)
		pcap_close(d_pd);
}


pcap::pcap(const pcap &rhs)
	: RX(rhs)
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
	d_frame2 = rhs.d_frame2;
	d_llc = rhs.d_llc;
	d_qos = rhs.d_qos;

	d_filter_string = rhs.d_filter_string;
	d_dev = rhs.d_dev;
	d_has_promisc = rhs.d_has_promisc;
	d_snaplen = rhs.d_snaplen;

	d_localnet = rhs.d_localnet;
	d_netmask = rhs.d_netmask;

	d_packet = NULL;

	if (rhs.d_pd)
		init_device(d_dev, d_has_promisc, d_snaplen);

	return;
}


pcap &pcap::operator=(const pcap &rhs)
{
	if (this == &rhs)
		return *this;
	RX::operator=(rhs);

	d_datalink = rhs.d_datalink;
	d_framelen = rhs.d_framelen;
	d_filter = rhs.d_filter;
	d_phdr = rhs.d_phdr;

	d_ether = rhs.d_ether;
	d_80211 = rhs.d_80211;
	d_cooked = rhs.d_cooked;
	d_frame2 = rhs.d_frame2;
	d_llc = rhs.d_llc;
	d_qos = rhs.d_qos;

	d_filter_string = rhs.d_filter_string;
	d_dev = rhs.d_dev;
	d_has_promisc = rhs.d_has_promisc;
	d_snaplen = rhs.d_snaplen;

	d_localnet = rhs.d_localnet;
	d_netmask = rhs.d_netmask;

	d_packet = NULL;

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
		hwaddr = string(reinterpret_cast<char *>(d_ether.ether_shost), numbers::eth_alen);
		break;
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
		hwaddr = string(reinterpret_cast<char *>(d_ether.ether_dhost), numbers::eth_alen);
		break;
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
 *  Fetch at most 'snaplen' bytes per call.
 */
int pcap::init_device(const string &dev, int promisc, size_t snaplen)
{
	char ebuf[PCAP_ERRBUF_SIZE];
	memset(ebuf, 0, PCAP_ERRBUF_SIZE);

	string e = "";

	bool is_file = (dev.find("file://") == 0);

	d_snaplen = snaplen;

	if (is_file) {
		if ((d_pd = pcap_open_offline(dev.c_str() + 7, ebuf)) == NULL) {
			e = "pcap::init_device::pcap_open_offline:";
			e += ebuf;
			return die(e, STDERR, -1);
		}
		pcap_set_snaplen(d_pd, snaplen);
	} else {
		if ((d_pd = pcap_create(dev.c_str(), ebuf)) == NULL) {
			e = "pcap::init_device::pcap_create:";
			e += ebuf;
			return die(e, STDERR, -1);
		}
		if (pcap_set_immediate_mode(d_pd, 1) < 0)
			return die("pcap::init_device: Unable to set immediate mode.", STDERR, -1);

		pcap_set_promisc(d_pd, 1);
		pcap_set_timeout(d_pd, 0);

		if (pcap_set_snaplen(d_pd, snaplen) < 0)
			return die("pcap::init_device: Unable to set snaplen.", STDERR, -1);

		int r = pcap_activate(d_pd);
		if (r < 0 && r != PCAP_WARNING_PROMISC_NOTSUP)
			return die("pcap::init_device: Cant activate device.", STDERR, -1);
	}

	// ignore error, as device might be down or not IP-based
	if (!is_file)
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


void one_packet(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *bytes)
{
	// "this"
	pcap *p = reinterpret_cast<pcap *>(user);
	p->d_packet = reinterpret_cast<const char *>(bytes);
	memcpy(&p->d_phdr, h, sizeof(*h));
}


int pcap::sniffpack(void *s, size_t len)
{
	d_packet = NULL;

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

	while (pcap_dispatch(d_pd, 1, one_packet, reinterpret_cast<unsigned char *>(this)) != 1 || d_phdr.caplen < d_framelen);

	if (d_packet == NULL)
		return die("pcap::sniffpack: Packet returned is NULL.", STDERR, -1);

	// The pcap source code reads as pcap_next() requires additional copy
	// operations, so it might be noticable slower on GBit links.
	// So use pcap_dispatch() for now.
	//while ((d_packet = (char*)pcap_next(d_pd, &d_phdr)) == NULL);

	string::size_type cooked_hdr = 0, idx = d_framelen;

	d_frame2 = "";
	d_llc = "";
	d_qos = "";

	switch (d_datalink) {
	case DLT_EN10MB:
		memcpy(&d_ether, d_packet, d_framelen);
		break;
#ifdef HAVE_RADIOTAP
	case DLT_IEEE802_11_RADIO:
		cooked_hdr = ((ieee80211::radiotap_hdr *)d_packet)->hlen;
		d_cooked = string(d_packet, cooked_hdr);
		memcpy(&d_80211, d_packet + cooked_hdr, d_framelen);
		idx += cooked_hdr;

		// WDS contain 4th address field
		if (d_80211.fc.bits.from_ds && d_80211.fc.bits.to_ds && (idx + 6 <= d_phdr.caplen)) {
			d_frame2 = string(d_packet + idx, 6);
			idx += 6;
		}
		if (d_80211.fc.bits.type == 2 && idx + 8 <= d_phdr.caplen) {			// Data ...
			if (d_80211.fc.bits.subtype == 8 && idx + 10 <= d_phdr.caplen) {	// ... with QoS
				d_qos = string(d_packet + idx, 2);
				idx += 2;
			}
			d_llc = string(d_packet + idx, 8);
			idx += 8;
		}
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

	memcpy(s, d_packet + idx, d_phdr.caplen - idx < len ? d_phdr.caplen - idx : len);
	return d_phdr.caplen - idx < len ? d_phdr.caplen - idx : len;
}


// return layer2 frame
void *pcap::get_frame(void *hwframe, size_t len)
{
	string s = "";
	get_frame(s);
	if (s.size() <= len) {
		memcpy(hwframe, s.c_str(), s.size());
		return hwframe;
	}
	return NULL;
}

string &pcap::get_frame(string &frame)
{
	frame = "";

	char buf[1024];
	string::size_type blen = 0;

	switch (d_datalink) {
	case DLT_EN10MB:
		memcpy(buf, &d_ether, sizeof(d_ether));
		frame = string(buf, sizeof(d_ether));
		break;
#ifdef HAVE_RADIOTAP
	case DLT_IEEE802_11_RADIO:
		memcpy(buf, &d_80211, sizeof(d_80211));
		blen = sizeof(d_80211);
		if (d_frame2.size() > 0 && d_frame2.size() < sizeof(buf) - sizeof(d_80211)) {
			memcpy(buf + sizeof(d_80211), d_frame2.c_str(), d_frame2.size());
			blen += d_frame2.size();
		}
		frame = string(buf, blen);
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

