/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/

#ifndef __ip_h__
#define __ip_h__

#include "usi-structs.h"
#include "datalink.h"
#include "object.h"
#include "Layer2.h"
#include <stdio.h>
#include <stdint.h>
#include <string>


namespace usipp {

/*! \class IP
 *  \brief the IP class
 *  \example trace.cc
 */
class IP : public Layer2 {
protected:
	usipp::iphdr iph;
	char ipOptions[40];
	bool calc_csum;

	/*! */
	char *reassemble(char *, int, int *);

	/*! pseudo header for derived classes like UDP or TCP.
	 *  needs to be here so that derived classes can be templates as
	 *  UDP<IP6> needs a different pseudo header
	 */
	struct pseudohdr d_pseudo;
public:

	/*! Construct an IP object. Requires destination address as
	 *  string (FQDN or IP address) and protocol. Tries to set source
	 *  address to what it finds out via its own hostname. If that fails,
	 *  the src address will be 0.
	 */
	IP(const std::string &dst, uint8_t);

	/*! Construct an IP object. Requires destination address as
	 *  32bit network ordered integer and a protocol. Tries to set source
	 *  address to what it finds out via its own hostname. If that fails,
	 *  the src address will be 0.
	 */
	IP(uint32_t dst, uint8_t);

	/*! Destructor
	 */
	virtual ~IP();

	/*! Returns headerlen/4.
	 */
	uint8_t get_hlen();

	/*! returns IP-version. Should always be 4.
	 */
	uint8_t get_vers();

	/*! Get Type Of Service.
	 */
	uint8_t get_tos();

	/*! Get total length of packet, including any data.
	 *  Return len in host byte order.
	 */
	uint16_t get_totlen();

	/*! Get IP ID field.
	 */
	uint16_t get_id();

	/*! Get fragmentation offset.
	 */
	uint16_t get_fragoff();

	/*! Get fragmentation flags. */
	uint16_t get_fflags();

	/*! Get Time To Live field (TTL)
	 */
	uint8_t get_ttl();

	/*! Get protocol, UDP, TCP etc
	 */
	uint8_t get_proto();

	/*! Get IP-header checksum
	 */
	uint16_t get_sum();

	/*! Get source address of packet in network order.
	*/
	uint32_t get_src();

	/*! Get destination address of packet in network order.
 	 */
	uint32_t get_dst();

	/*! assingment operator
 	 */
	IP &operator=(const IP&);

	/*! copy constructor
	 */
	IP(const IP&);

	/*! Get source address in dotted IP form.
	 */
	std::string &get_src(std::string &);

	/*! Get destination address in dotted IP form.
	 */
	std::string &get_dst( std::string &);

	/*! Set header-len in number of 32 bit words. 5 (5*4 = 20) in normal case.
	 *  Contructor does this for you, so you should not use this.
	 */
	uint8_t set_hlen(uint8_t);

	/*! Set version-field. Normally not needed.
	 */
	uint8_t set_vers(uint8_t);

	/*! Set IP TOS field. */
	uint8_t set_tos(uint8_t);

	/*! Set total length of packet. Not needed. (Kernel will
	 *  set this on most OS anyways)
	 */
	uint16_t set_totlen(uint16_t);

	/*! Set ID-field. Also not needed.
	 */
	uint16_t set_id(uint16_t);

	/*! Set IP fragmentation offset. */
	uint16_t set_fragoff(uint16_t);

	/*! Set IP fragmentation flags */
	uint16_t set_fflags(uint16_t);

	/*! Set time-to-live field. Not needed.
	 */
	uint8_t set_ttl(uint8_t);

	/*! Set protocol. If you use derived classes, you don't need to
	 *  do it yourself.
	 */
	uint8_t set_proto(uint8_t);

	/*! Set IP checksum (usually its always computed by kernel anyway) */
	uint16_t set_sum(uint16_t);

	/*! Set source address. Expects network byte ordered.
	*/
	uint32_t set_src(uint32_t);

	/*! Set destination address. Expects network byte order.
	 */
	uint32_t set_dst(uint32_t);

	/*! Set source address. Expects FQDN or IP string.
	 */
	int set_src(const std::string &ip_or_name);

	/*! Set destination address. Not needed if the destination given
	 *  in the constructor is OK.
	 */
	int set_dst(const std::string &);

	/*! Return a reference to the raw IP header for direct
	 *  manipulation.
	 *  Useful for ICMP packets which require original IP headers.
	 */
	iphdr &get_iphdr();

	/*! set raw IP header */
	iphdr &set_iphdr(const iphdr &);

	/*! Obtain IP options. Returns the passed string ref. */
	virtual std::string &get_options(std::string &);

	/*! Set IP options as a blob */
	virtual int set_options(const std::string &);


	/*! Turn IP header checksum calculation on or off.
	 *  _Default value_ is off (but _default argument_ when called is 'on'),
	 *  but its needed if a Layer2 TX object is used (TX_dnet_eth).
	 *  The _default argument_ is on.
	 *  If usi++ detects other TX layers than TX_IP, it is automatically enabled.
	 */
	virtual void checksum(bool cs = 1);

	/*! Send a Packet.
	 */
	virtual int sendpack(const void *payload, size_t paylen);

	/*! Send a packet containg a payload of string.*/
	virtual int sendpack(const std::string &);


	/*! Capture an packet from the NIC.
	*/
	virtual std::string &sniffpack(std::string &);


	/*! Capture an packet from the NIC.
	*/
	virtual int sniffpack(void *buf, size_t len);

	/*! Initial setup for device, enable promisc (p), max capture len (l) */
	virtual int init_device(const std::string &, int p, size_t l);
};


} // namespace

#endif // __ip_h__

