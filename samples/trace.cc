// c++ trace.cc -lusi++ -ldnet -lpcap

#include <iostream>
#include <usi++/usi++.h>

#include <unistd.h>
#include <string>
#include <stdlib.h>

using namespace std;
using namespace usipp;


void usage()
{
	cout<<"Usage: trace <-s src> <-d dst> [-T port] [-t type] [-D dev] [-U port] [-Ii]\n\n"
	      "-U use normal UDP style trace to 'port'\n"
	      "-T use TCP style trace (SYN) to 'port'\n"
	      "-I use ICMP trace with type 'type' (defaults to ECHO_REPLY)\n"
	      "-D use 'dev' for capturing. default eth0\n"
	      "-i use raw IP packets for trace\n\n";
	exit(0);
}

int ip_trace(const string &dst, const string &src, const string &dev, int type)
{
	ICMP sn("127.0.0.1");
	IP ip(dst, type);

	ip.set_src(src);

	sn.init_device(dev, 0, 500);
	sn.setfilter("icmp and (icmp[0] == 11 or icmp[0] == 0 or icmp[0] == 3)");

	string h1, h2;
	for (int i = 1; i < 64; i++) {
		ip.set_ttl(i);
		ip.sendpack("");
		sn.sniffpack(NULL, 0);

		cout<<"  "<<i<<"  "<<sn.get_src(h1, 1)<<" ("<<sn.get_src(h2)<<")\n";
		if (sn.get_type() == 3 || sn.get_type() == 0)
			break;
	}
	return 0;
}

int icmp_trace(const string &dst, const string &src, const string &dev, int type)
{
	ICMP sn("127.0.0.1");
	ICMP icmp(dst);

	icmp.set_src(src);
	icmp.set_type(type);

	sn.init_device(dev, 0, 500);
	sn.setfilter("icmp and (icmp[0] == 11 or icmp[0] == 0 or icmp[0] == 3)");

	string h1, h2;
	for (int i = 1; i < 64; i++) {
		icmp.set_ttl(i);
		icmp.sendpack("");
		sn.sniffpack(NULL, 0);

		cout<<"  "<<i<<"  "<<sn.get_src(h1, 1)<<" ("<<sn.get_src(h2)<<")\n";
		if (sn.get_type() == 3 || sn.get_type() == 0)
			break;
	}
	return 0;
}



int udp_trace(const string &dst, const string &src, const string &dev, int port)
{
	ICMP sn("127.0.0.1");
	UDP4 udp(dst);

	udp.set_src(src);
	udp.set_dstport(port);
	udp.set_srcport(53);

	sn.init_device(dev, 0, 500);
	sn.setfilter("icmp and (icmp[0] == 11 or icmp[0] == 3)");

	string h1, h2;
	for (int i = 1; i < 64; i++) {
		udp.set_ttl(i);
		udp.sendpack("");
		sn.sniffpack(NULL, 0);

		cout<<"  "<<i<<"  "<<sn.get_src(h1, 1)<<" ("<<sn.get_src(h2, 0)<<")\n";
		if (sn.get_type() == 3)
			break;
	}
	return 0;
}


int tcp_trace(const string &dst, const string &src, const string &dev, int port)
{
	TCP4 tcp(dst);
	IP sn("127.0.0.1", 123);

	tcp.set_dstport(port);
	tcp.set_src(src);
	tcp.set_srcport(1234);
	tcp.set_ack(0);

	// The dnet includes poison global namespace with a lot of #define's.
	// If you want to use usipp's definitions, you have to undef them first
#undef TH_SYN
	tcp.set_flags(usipp::TH_SYN);

	sn.init_device(dev, 0, 500);
	sn.setfilter("(icmp and icmp[0] == 11) or (tcp and dst port 1234)");

	string h1, h2;
	for (int i = 1; i < 64; i++) {
		tcp.set_ttl(i);
		tcp.sendpack("");
		sn.sniffpack(NULL, 0);
		cout<<"  "<<i<<"  "<<sn.get_src(h1, 1)<<" ("<<sn.get_src(h2, 0)<<")\n";
		if (sn.get_proto() == IPPROTO_TCP)
			break;
	}
	return 0;
}


int main(int argc, char **argv)
{

	int c;
	int type = 1, port = 53;
	bool udp = false, tcp = false, icmp = false, ip = false;
	string source = "", dest = "", dev = "eth0";

	while ((c = getopt(argc, argv, "D:d:s:t:U:T:Ii")) != -1) {
		switch (c) {
		case 't':
			type = atoi(optarg);
			break;
		case 's':
			source = optarg;
			break;
		case 'd':
			dest = optarg;
			break;
		case 'U':
			udp = true;
			port = atoi(optarg);
			break;
		case 'T':
			tcp = true;
			port = atoi(optarg);
			break;
		case 'I':
			icmp = true;
			break;
		case 'D':
			dev = optarg;
			break;
		case 'i':
			ip = true;
			break;
		default:
			usage();
		}
	}

	if (!dest.length() || !source.length())
		usage();
	cout<<"[=== IP datagrams to "<<dest<<" are routed through ===]\n\n";

	if (udp)
		udp_trace(dest, source, dev, port);
	else if (tcp)
		tcp_trace(dest, source, dev, port);
	else if (icmp)
		icmp_trace(dest, source, dev, type);
	else if (ip)
		ip_trace(dest, source, dev, type);
	else
		cerr<<"You must at least give me UDP,TCP,ICMP or IP!\n";
	cout<<endl;
	return 0;
}


