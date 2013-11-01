#include <iostream>
#include <usi++/usi++.h>

using namespace std;
using namespace usipp;

int main()
{
	usipp::pcap *wmon = new usipp::pcap;

	if (wmon->init_device("eth0", 1, 1500) < 0) {
		cerr<<wmon->why()<<endl;
		return 1;
	}

	string pkt = "", s = "";
	for (;;) {
		cerr<<"pkt: "<<wmon->sniffpack(pkt).size()<<endl;
		cerr<<"cooked hdr: "<<wmon->get_cooked(s).size()<<endl
		    <<"frame: "<<wmon->get_frame(s).size()<<endl;
	}

	return 0;
}



