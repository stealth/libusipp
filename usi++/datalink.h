/*
 * This file is part of the libusi++ packet capturing/sending framework.
 *
 * (C) 2000-2013 by Sebastian Krahmer,
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
 * along with psc.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __datalink_h__
#define __datalink_h__

#include "usi-structs.h"
#include "RX.h"
#include <stdio.h>
#include <string>
#include <stdint.h>

extern "C" {
#include <pcap.h>
}

#include "config.h"

#ifdef HAVE_RADIOTAP
#include "radiotap.h"
#endif

//#include "config.h"

namespace usipp {

/*! \class pcap
 *  \brief libpcap RX provider implementation
 */
class pcap : public RX {
private:
	struct timeval d_tv;

	// Heavily used by libpcap
	int d_datalink;
	size_t d_framelen, d_snaplen;

	// pcap-descriptor
	pcap_t *d_pd;

	// netaddress and netmask
	uint32_t d_localnet, d_netmask;

	// The actual filter-program
	struct bpf_program d_filter;

	// The pcap-header for every packet fetched
	struct pcap_pkthdr d_phdr;

	// filled by init_device()
	std::string d_dev;
	int d_has_promisc;

	// true when timed out
	bool d_timeout;


protected:

	struct ether_header d_ether;

#ifdef HAVE_RADIOTAP
	struct wifi_hdr d_80211;
#endif

	std::string d_cooked;
	std::string d_filter_string;

public:

	/*! This constructor should be used to
	 *  initialize raw-datalink-objects, means not IP/TCP/ICMP etc.
	 *  We need this b/c unlike in derived classes, datalink::init_device()
	 *  cannot set a filter!
	 */
	pcap(const std::string &);


	/*! default constructor */
	pcap();


	/*! Copy-constructor
	 */
	pcap(const pcap &);

	/*! destructor */
	virtual ~pcap();


	/*! assignment operator */
	pcap &operator=(const pcap &);


	/*! Fill buffer with src-hardware-adress of actuall packet,
	 *  use get_datalink() to determine what HW the device is.
	 *  Only ethernet is supportet yet, but it's extensible.
	 */
	virtual std::string &get_l2src(std::string &);

	/*! Fill buffer with dst-hardware-adress of actuall packet,
 	 *  use get_datalink() to determine what HW the device is.
	 *  Only ethernet is supportet yet, but it's extensible.
	 */
	virtual std::string &get_l2dst(std::string &);

	/*! Initialize a device ("eth0" for example) for packet-
	 *  capturing. It MUST be called before sniffpack() is launched.
	 *  Set 'promisc' to 1 if you want the device running in promiscous mode.
	 *  Fetch at most 'snaplen' bytes per call.
	 */
	virtual int init_device(const std::string &dev, int promisc, size_t snaplen);

	/*! set a new filter for capturing
	 */
	virtual int setfilter(const std::string &filter);

	/*! sniff a packet */
	virtual std::string &sniffpack(std::string &);

	/*! sniff a packet
	*/
	virtual int sniffpack(void *, size_t);

	/*! Set a timeout. Implements RX::timeout() = 0. */
	virtual int timeout(const struct timeval &);

	/*! Returns true when recv() timed out */
	virtual bool timeout();

	/*! See RX::tag() */
	virtual int tag() { return RX_TAG_PCAP; }


	/*! Return HW-frame (ethernet header) */
	void *get_frame(void *, size_t);

	/*! get the HW-frame as string */
	std::string &get_frame(std::string &);


	/*! Get pcap_t struct to obtain fileno etc for select. */
	pcap_t *handle() { return d_pd; }

	/*! Get protocol-type of ethernet-frame
	 *  Maybe moves to ethernet-class in future?
	 */
	uint16_t get_etype();

	/*! Return the actual datalink of the object.
	 */
	int get_datalink();

	/*! Return the cooked header if any, e.g. RADIOTAP header */
	std::string &get_cooked(std::string &);

	/*! Return the actual framlen of the object.
	 *  (framelen depends on datalink) Not the len of the whole frame,
	 *  only that of the header.
	 */
	int get_framelen();


}; // class pcap {}


} // namespace usipp

#endif // __datalink_h__

