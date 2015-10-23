// c++ arpw.cc -lusi++ -ldnet -lpcap

/* Output looks similar to tcpdump -p arp
 */
#include <usi++/usi++.h>
#include <string>
#include <cstring>
#include <iostream>

using namespace usipp;
using namespace std;


char *print_mac(unsigned char *mac)
{
	static char m[100];	// uhhh.... :)

	memset(m, 0, sizeof(m));
	snprintf(m, sizeof(m), "%02x:%02x:%02x:%02x:%02x:%02x", *mac, mac[1], mac[2], mac[3], mac[4], mac[5]);
	return m;
}


int main(int argc, char **argv)
{
	usipp::ether_arp ea;

	string dev = "eth0";
	if (argc > 1)
		dev = argv[1];

	ARP *a = new ARP(dev);

	if (a->init_device(dev, 1, 100) < 0) {
		cerr<<a->why()<<endl;
		return 1;
	}

	char sip[100], dip[100];

	while (1) {
		// The ARP header is already in the ARP object,
		// we only receive the payload
		a->sniffpack((char *)&ea + sizeof(ea.ea_hdr),
		             sizeof(ea) - sizeof(ea.ea_hdr));
		if (a->get_op() == numbers::arpop_request) {
			in_addr in1; memcpy(&in1.s_addr, ea.arp_tpa, 4);
			in_addr in2; memcpy(&in2.s_addr, ea.arp_spa, 4);
			cout<<"arp who has "<<inet_ntop(AF_INET, &in1, dip, sizeof(dip))
			    <<" tell "<<inet_ntop(AF_INET, &in2, sip, sizeof(sip))<<endl;
		}
		if (a->get_op() == numbers::arpop_reply) {
			in_addr in; memcpy(&in.s_addr, ea.arp_spa, 4);
			cout<<inet_ntop(AF_INET, &in, sip, sizeof(sip))<<" is at "
			    <<print_mac(ea.arp_sha)<<endl;
		}
	}
	return 0;
}
