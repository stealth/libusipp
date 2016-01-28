// c++ icmp_sniff.cc -lusi++ -lpcap -ldnet
#include <iostream>
#include <string>
#include <cstdlib>
#include <cstring>
#include <usi++/usi++.h>

using namespace std;
using namespace usipp;


int main(int argc, char **argv)
{
	ICMP *icmp = new ICMP("127.0.0.1");
	char buf[usipp::min_packet_size] = {0};
	string src = "", dst = "", l2 = "";

	if (argc < 2) {
		cout<<argv[0]<<" [intf]\n";
		return 1;
	}

	if (icmp->init_device(argv[1], 1, 1500) < 0) {
		cerr<<icmp->why()<<endl;
		return 1;
	}

	while (1) {
    		// blocks
		int r = icmp->sniffpack(buf, sizeof(buf));
cerr<<r<<endl;
		if (r < 0) {
			cerr<<icmp->why()<<endl;
			continue;
		}
		cout<<"["<<bin2mac(icmp->rx()->get_l2src(l2))<<"->"<<bin2mac(icmp->rx()->get_l2dst(l2))<<"]:";
		cout<<"type:"<<(int)icmp->get_type()<<" ["<<icmp->get_src(src)<<" -> "
		    <<icmp->get_dst(dst)<<"] "<<"seq: "<<icmp->get_seq()
		    <<" ttl: "<<(int)icmp->get_ttl()<<" id: "<<icmp->get_icmpId()<<endl;
		    //<<buf<<endl;

	}
	return 0;
}

