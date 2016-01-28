// c++ icmp6_sniff.cc -lusi++ -lpcap -ldnet
#include <iostream>
#include <string>
#include <cstdlib>
#include <cstring>
#include <usi++/usi++.h>

using namespace std;
using namespace usipp;


int main(int argc, char **argv)
{
	ICMP6 *icmp = new ICMP6("::1");
	char buf[usipp::min_packet_size] = {0};
	string src = "", dst = "", l2 = "";

	if (argc < 2) {
		cout<<argv[0]<<" [intf]\n";
		return 1;
	}

	if (icmp->init_device(argv[1], 1, 500) < 0) {
		cerr<<icmp->why()<<endl;
		return 1;
	}

	string smac, dmac;
	while (1) {
    		// blocks
		cout<<icmp->sniffpack(buf, sizeof(buf))<<endl;
		cout<<"["<<bin2mac(icmp->rx()->get_l2src(l2))<<"->"<<bin2mac(icmp->rx()->get_l2dst(l2))<<"]:";
		cout<<"type:"<<(int)icmp->get_type()<<" ["<<icmp->get_src(src)<<" -> "
		    <<icmp->get_dst(dst)<<"] "<<"seq: "<<icmp->get_seq()
		    <<" ttl: "<<(int)icmp->get_hoplimit()<<" id: "<<icmp->get_icmpId()<<endl;

	}
	return 0;
}

