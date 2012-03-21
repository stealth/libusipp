#ifndef __ip6_h__
#define __ip6_h__

#include "usi-structs.h"
#include "datalink.h"
#include "Layer2.h"

#include <string>
#include <stdint.h>
#include <vector>


namespace usipp {


/*! \class IP6
 *  \brief IP6 class
 */
class IP6 : public Layer2 {

public:
	/*! New IP6 packet with destination address and next-header proto.
	 *  Tries to set source
	 *  address to what it finds out via its own hostname. If that fails,
	 *  the src address will be 0.
	 */
	IP6(const struct in6_addr &dst, uint8_t proto);

	/*! New IP6 packet with destination address (hostname or IP6 string)
	 *  and next-header 'proto'.
	 *  Tries to set source
	 *  address to what it finds out via its own hostname. If that fails,
	 *  the src address will be 0.
	 */
	IP6(const std::string &dst, uint8_t proto);

	/*! Copy constructor */
	IP6(const IP6&);

	/*! assignment operator */
	IP6 &operator=(const IP6 &);

	/*! destructor */
	virtual ~IP6();

	/*! Get IP6 source address */
	struct in6_addr get_src();

	/*! Get IP6 destination address */
	struct in6_addr get_dst();

	/*! Set IP6 source address */
	struct in6_addr &set_src(const struct in6_addr &);

	/*! Set IP6 source address, hostname or IP6-string */
	int set_src(const std::string &);

	/*! Set IP6 destination address */
	struct in6_addr &set_dst(const struct in6_addr &);

	/*! Set IP6 destination address, hostname or IP6-string */
	int set_dst(const std::string &);

	/*! Get hop limit field */
	uint8_t get_hoplimit();

	/*! Set hop limit field */
	uint8_t set_hoplimit(uint8_t);

	/*! Get the next header value */
	uint8_t get_proto();

	/*! Set the next header value */
	uint8_t set_proto(uint8_t);

	/*! Get payload len in host byte order */
	uint16_t get_payloadlen();

	/*! Clear all IP6 extension headers, if any. Resets next header
	 *  field of IP6 header to the original Upper Layer value given during
	 *  object construction.
	 */
	void clear_headers();

	/*! How many extension headers for this IP6 packet exist? */
	uint16_t num_headers();

	/*! return the extension header as string at index or return empty
	 * string
	 */
	std::string &next_header(uint16_t idx, std::string &);

	/*! Add another extension header to this IP6 packet. The caller has to
	 *  set all the next header fields of ALL headers by himself, including
	 *  the IP6 header.
	 */
	int next_header(const std::string &);

	/*! Send an IP6 packet with payload */
	virtual int sendpack(const void *, size_t);

	/*! Send an IP6 packet with payload */
	virtual int sendpack(const std::string &);

	/*! initializse device for sniffing */
	virtual int init_device(const std::string &, int, size_t);

	/*! Sniff a IP6 packet and set up internal fields. */
	virtual int sniffpack(void *, size_t);

private:
	struct ip6_hdr iph;
	uint8_t d_proto;
	std::vector<std::string> e_hdrs;
	uint16_t e_hdrs_len;
	TX *d_tx;

protected:
	struct pseudohdr6 d_pseudo;

};

};

#endif

