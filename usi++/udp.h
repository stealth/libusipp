/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/


#ifndef __udp_h__
#define __udp_h__

#include <string>
#include <stdint.h>

#include "usi-structs.h"
#include "datalink.h"
#include "ip6.h"
#include "ip.h"

namespace usipp {

/*! \class UDP
 *  \brief Available as UDP4 and UDP6
 *  \example udp_spoof.cc
 *  \example udp6_spoof.cc
 */
template<typename T>
class UDP : public T {
private:
	struct udphdr d_udph;
public:

	/*! Construct an UDP object, destinated to a host (FQDN or IP string).
	 */
	UDP(const std::string &);

	/*! Destructor
	 */
	virtual ~UDP();

	/*! Copy Constructor
	 */
	UDP(const UDP<T> &);

	/*! Assignment operator.
	 */
	UDP<T> &operator=(const UDP<T>&);

	/*! Get the source port of the UDP datagram.
	 */
	uint16_t get_srcport();


	/*! Get the destination port of the UDP datagram.
	 */
	uint16_t get_dstport();

	/*! Return length of UDP header plus contained data.
	 */
	uint16_t get_len();

	/*! Return the checksum of UDP datagram.
	 */
	uint16_t get_udpsum();

	/*! Set the sourceport in the UDP header.
	*/
	uint16_t set_srcport(uint16_t);

	/*! Set the destination port in the UDP header.
	 */
	uint16_t set_dstport(uint16_t);

	/*! Set the length of the UDP datagram.
	 */
	uint16_t set_len(uint16_t);

	/*! Set the UDP checksum. Calling this function with s != 0
	 *  will prevent sendpack() from setting the checksum.
	 */
	uint16_t set_udpsum(uint16_t);

	/*! Return complete UDP header.
	 *  Usefull for some types of ICMP messages.
	 */
	udphdr &get_udphdr();

	/*! Send an UDP datagram containing 'paylen' bytes of data.
	 */
	virtual int sendpack(const void*, size_t);

	/*! Send a packet conating a string of payload. */
	virtual int sendpack(const std::string &);

	/*! Capture packets that are not for our host.
	 */
	virtual int sniffpack(void*, size_t);

	/*! Initialize a device ("eth0" for example) for packet-
	*  capturing. It MUST be called before sniffpack() is launched.
	*  Set 'promisc' to 1 if you want the device running in promiscous mode.
	*  Fetch at most 'snaplen' bytes per call.
	*/
	virtual int init_device(const std::string &, int promisc, size_t snaplen);

};   // class UDP {}

/*! \class UDP4
 */
typedef UDP<IP> UDP4;

/*! \class UDP6
 */
typedef UDP<IP6> UDP6;


} // namespace usipp

#endif // _UDP_H_


