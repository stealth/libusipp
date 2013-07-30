// c++ icmp_sniff.cc -lusi++ -lpcap -ldnet
#include <iostream>
#include <string>
#include <cstdlib>
#include <cstring>
#include <usi++/usi++.h>

using namespace std;
using namespace usipp;

#define PRINT_MAC

string l2mac(string &l2)
{
	char m[100];

	memset(m, 0, sizeof(m));
	const unsigned char *mac = reinterpret_cast<const unsigned char *>(l2.c_str());
	snprintf(m, sizeof(m), "%02x:%02x:%02x:%02x:%02x:%02x", *mac, mac[1], mac[2],
		mac[3], mac[4], mac[5]);
	return m;
}


int main(int argc, char **argv)
{
   	ICMP icmp("127.0.0.1");
	char buf[1000] = {0};
	string src, dst;

	if (argc < 2) {
		cout<<argv[0]<<" [intf]\n";
		exit(1);
	}
	icmp.init_device(argv[1], 1, 500);

	string smac, dmac;
	while(1){
		memset(buf,0,1000);
    		// blocks
	   	cout<<icmp.sniffpack(buf, 1000)<<endl;
#ifdef PRINT_MAC
		cout<<"["<<l2mac(icmp.rx()->get_l2src(smac))<<"->"<<l2mac(icmp.rx()->get_l2dst(dmac))<<"]:";
#endif
		cout<<"type:"<<(int)icmp.get_type()<<" ["<<icmp.get_src(src)<<" -> "
		    <<icmp.get_dst(dst)<<"] "<<"seq: "<<icmp.get_seq()
		    <<" ttl: "<<(int)icmp.get_ttl()<<" id: "<<icmp.get_icmpId()<<endl;
		    //<<buf<<endl;

	}
	return 0;
}

