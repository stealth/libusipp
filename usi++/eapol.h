/*
 * This file is part of the libusi++ packet capturing/sending framework.
 *
 * (C) 2014 by Sebastian Krahmer,
 *             sebastian [dot] krahmer [at] gmail [dot] com
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

#ifndef __eapol_h__
#define __eapol_h__


#include "usi-structs.h"
#include "Layer2.h"
#include "TX_pcap_eth.h"
#include <stdio.h>
#include <stdint.h>
#include <string>

namespace usipp {

enum {
	EAPOL_PTYPE_PACKET	= 	0,
	EAPOL_PTYPE_START	=	1,
	EAPOL_PTYPE_LOGOFF	=	2,
	EAPOL_PTYPE_KEY		=	3,
	EAPOL_PTYPE_ASF_ALERT	=	4,
	EAPOL_PTYPE_MKA		=	5,
	EAPOL_PTYPE_ANNOUNCE_GEN	=	6,
	EAPOL_PTYPE_ANNOUNCE_SPEC	=	7,
	EAPOL_PTYPE_ANNOUNCE_REQ	=	8
};


struct eapol_p {
	uint8_t version;
	uint8_t type;
	uint16_t len;
};

/*! \class EAPOL
 *  \brief send and capture EAP over LAN packets (802.1x)
 */
class EAPOL : public Layer2 {

	eapol_p eapol_hdr;
	TX_pcap_eth *d_tx;

public:

	/*! Open device 'dev' for packet-capturing
	 * dev needs to match device in call to init_device().
	 */
	EAPOL(const std::string &);

	/*! destructor */
	virtual ~EAPOL();

	/*! Set source address of underlying TX (just for convenience) */
	int set_l2src(const std::string &);

	/*! Set destination address of underlying TX (just for convenience), will
	 *  be multicast 01-80-c2-00-00-03 by default
	 */
	int set_l2dst(const std::string &);

	/*! Sniff an EAPOL packet. Returns EAPOL packet body */
	virtual std::string &sniffpack(std::string &);

	/*! Sniff an EAPOL packet. Returns EAPOL packet body */
	virtual int sniffpack(void *, size_t);

	/*! Send an EAPOL packet. You must provide EAPOL packet body.
	 */
	virtual int sendpack(const void *, size_t);

	/*! Send an EAPOL packet. You must provide EAPOL packet body.
	 */
	virtual int sendpack(const std::string &);


	/*! get EAPOL packet type */
	uint8_t get_type()
	{
		return eapol_hdr.type;
	}

	/*! set EAPOL packet pyte */
	void set_type(uint8_t t)
	{
		eapol_hdr.type = t;
	}

	/*! Get len of EAPOL payload */
	uint16_t get_len()
	{
		return ntohs(eapol_hdr.len);
	}

	/*! set EAPOL version (default 1) */
	uint8_t get_version()
	{
		return eapol_hdr.version;
	}


};

} // namespace
#endif

