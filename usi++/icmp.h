/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/

#ifndef _ICMP_H_
#define _ICMP_H_

#include "usi-structs.h"
#include "datalink.h"
#include "ip.h"
#include <string>
#include <stdint.h>


namespace usipp {


/*! \class ICMP icmp.h
 *  \brief the ICMP class
 */
/*! \example icmp_sniff.cc
 */

class ICMP : public IP {
private:
   	struct icmphdr icmphdr;
public:
	/*! Expects host.
	 */
	ICMP(const std::string &);

	virtual ~ICMP();

	/*! Copy-Construktor */
	ICMP(const ICMP &);

	/*! Assign-operator */
	ICMP &operator=(const ICMP &);

	/*! send an ICMP-packet containing 'payload' which
	 *  is 'paylen' bytes long
	 */
	virtual int sendpack(const void *, size_t);

	/*! send a ICMP-packet with string 'payload' as payload.
	 */
	virtual int sendpack(const std::string &);

	/*! handle packets, that are NOT actually for the
	 *  local adress!
	 */
	virtual int sniffpack(void *, size_t);

	/*! Initialize a device ("eth0" for example) for packet-
	 *  capturing. It MUST be called before sniffpack() is launched.
	 *  Set 'promisc' to 1 if you want the device running in promiscous mode.
	 *  Fetch at most 'snaplen' bytes per call.
	 */
	virtual int init_device(const std::string&, int, size_t);

	/*! Set the type-field in the actuall ICMP-packet.
	 */
	uint8_t set_type(uint8_t);

	/*! Set ICMP-code.
 	 */
	uint8_t set_code(uint8_t);

	/*! Set id field in the actuall ICMP-packet
	 */
	uint16_t set_icmpId(uint16_t);

	/*! Set the sequecenumber of the actuall ICMP-packet.
	 */
	uint16_t set_seq(uint16_t);

	/*! Set new GW address if applicable (network order). */
	uint32_t set_gateway(uint32_t);

	/*! Set MUT field if applicable. */
	uint16_t set_mtu(uint16_t);

	/*! Get the type-field from the actuall ICMP-packet.
 	 */
	uint8_t get_type();

	/*! Get ICMP-code.
 	 */
	uint8_t get_code();

	/*! Get the id field from actuall ICMP-packet.
	 */
	uint16_t get_icmpId();

	/*! Get the sequence-number of actuall ICMP-packet
	 */
	uint16_t get_seq();

	/*! Get new gateway address if applicable. */
	uint32_t get_gateway();

	/*! Get MTU field if applicable (in network order). */
	uint16_t get_mtu();
}; // class ICMP{}


typedef ICMP ICMP4;

} // namespace usipp
#endif // _ICMP_H_

