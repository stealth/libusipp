/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/


#ifndef __tcp_h__
#define __tcp_h__

#include "usi-structs.h"
#include "datalink.h"
#include "ip.h"
#include "ip6.h"


#include <string>
#include <stdint.h>


namespace usipp {

/*! \class TCP
 *  \brief available as TCP4 and TCP6
 */
template<typename T>
class TCP : public T {
private:
	usipp::tcphdr tcph;
	char tcpOptions[40];
public:

	/*! Construct a TCP object destinated to a hostname (FQDN or or IP-address string).
	 */
	TCP(const std::string &);

	/*! destructor
	 */
	virtual ~TCP();

	/*! assignment operator
	 */
	TCP<T> &operator=(const TCP<T>&);

	/*! copy constructor
	 */
	TCP(const TCP<T>&);

	/*! Get source port of packet in host byte order.
	 */
	uint16_t get_srcport();

	/*! Get destination port in host byte order.
	 */
	uint16_t get_dstport();

	/*! Get sequence number of packet.
	 */
	uint32_t get_seq();

	/*! Get acknowlegdement number of packet.
	 */
	uint32_t get_ack();

	/*! Get TCP-data offset, sometimes called TCP-header-length.
	 *  Should be 20 in most cases.
	 */
	uint8_t get_off();

	/*! Get TCP-flags. Can be either of
	 *  TH_SYN
	 *  TH_ACK
	 *  TH_FIN
	 *  TH_RST
	 *  TH_PUSH
	 *  TH_URG
	 * or any combination of these (althought common combinations are SYN|ACK or
	 * similar)
	 */
	uint16_t get_flags();

	/*! Get TCP window size. */
	uint16_t get_win();

	/*! Get the TCP checksum */
	uint16_t get_tcpsum();

	/*! Get TCP urgent pointer for OOB data.
	 */
	uint16_t get_urg();

	/*! Set source port
	 */
	uint16_t set_srcport(uint16_t);

	/*! Set destination-port
	 */
	uint16_t set_dstport(uint16_t);

	/*! Set TCP sequence number.
	 */
	uint32_t set_seq(uint32_t);

	/*! Set TCP acknoledgenumber.
	 */
	uint32_t set_ack(uint32_t);

	/*! Set TCP header offset. */
	uint8_t set_off(uint8_t);

	/*! Set TCP flags*/
	uint16_t set_flags(uint16_t);

	/*! Set TCP window */
	uint16_t set_win(uint16_t);

	/*! Set TCP-checksum.
	 * Doing these will prevent sendpack() from doing this for you.
	 * It's not recommented that you do so, because the sum will most
	 * likely be wrong (pseudoheader).
	 */
	uint16_t set_tcpsum(uint16_t);

	/*! Set TCP urgent pointer for OOB data. */
	uint16_t set_urg(uint16_t);

	/*! Return reference to raw TCP header.
	 */
	tcphdr &get_tcphdr();

	/* The following functions are already defined in IP {}.
	 * We need them too for TCP {}, and TCP{} calls IP::function() then.
	 */


	/*! Capture an packet from the NIC.
	*/
	virtual std::string &sniffpack(std::string &);

	/*! Capture a packet from the NIC.
	 */
	virtual int sniffpack(void *buf, size_t buflen);

	/*! Send a packet.
	 */
	virtual int sendpack(const void *payload, size_t paylen);

	/*! Send a TCP packet with payload.
	 */
	virtual int sendpack(const std::string &);

	/*! Just sets filter to "tcp" and calls IP::init_device(), passing
	 *  the arguments along.
	 */
	virtual int init_device(const std::string &, int, size_t);

	/*! Set TCP-options. If providing the empty "" string, options are cleared.
	 * Return -1 if options too large or not aligned.
 	 */
	int set_options(const std::string &);

	/*! Get TCP options.
	 */
	std::string &get_options(std::string &);
};

typedef TCP<IP> TCP4;
typedef TCP<IP6> TCP6;


} // namespace usipp

#endif

