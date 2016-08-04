// c++ arpw.cc -lusi++ -ldnet -lpcap -std=c++11

/* Output looks similar to tcpdump -p arp
 */
#include <usi++/usi++.h>
#include <string>
#include <cstring>
#include <iostream>
#include <arpa/inet.h>


using namespace usipp;
using namespace std;


int main(int argc, char **argv)
{
	usipp::ether_arp *ea = NULL;

	string dev = "eth0", l2 = "";
	if (argc > 1)
		dev = argv[1];

	ARP *a = new ARP;

	if (a->init_device(dev, 1, 1500) < 0) {
		cerr<<a->why()<<endl;
		return 1;
	}

	char sip[100], dip[100], buf[min_packet_size];

	ea = reinterpret_cast<ether_arp *>(buf);

	while (1) {
		// The ARP header is already in the ARP object,
		// we only receive the payload
		if (a->sniffpack(buf, sizeof(buf)) <= 0)
			cerr<<"Error sniffing packet:"<<a->why();
		if (a->get_op() == numbers::arpop_request) {
			in_addr in1; memcpy(&in1.s_addr, ea->arp_tpa, 4);
			in_addr in2; memcpy(&in2.s_addr, ea->arp_spa, 4);
			cout<<"["<<bin2mac(a->raw_rx()->get_l2src(l2))<<"] -> ["
			    <<bin2mac(a->raw_rx()->get_l2dst(l2))<<"] arp who has "<<inet_ntop(AF_INET, &in1, dip, sizeof(dip))
			    <<" tell "<<inet_ntop(AF_INET, &in2, sip, sizeof(sip))<<endl;
		}
		if (a->get_op() == numbers::arpop_reply) {
			in_addr in; memcpy(&in.s_addr, ea->arp_spa, 4);
			cout<<"["<<bin2mac(a->raw_rx()->get_l2src(l2))<<"] -> ["
			    <<bin2mac(a->raw_rx()->get_l2dst(l2))<<"] "
			    <<inet_ntop(AF_INET, &in, sip, sizeof(sip))<<" is at "
			    <<bin2mac(string(reinterpret_cast<char *>(&ea->arp_sha), sizeof(ea->arp_sha)))<<endl;
		}
	}
	return 0;
}

