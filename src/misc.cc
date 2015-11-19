#include <stdint.h>
#include <string>
#include <cstring>
#include "usi++/usi-structs.h"

namespace usipp {


using namespace std;

// ripped code, slightly modified
// to pad odd length automagically (UDP,TCP)
unsigned short
in_cksum (unsigned short *ptr, int nbytes, bool may_pad)
{

  uint32_t sum;
  uint16_t oddbyte, answer;


  /* For psuedo-headers: odd len's require
   * padding. We assume that UDP,TCP always
   * gives enough room for computation */
  if (nbytes % 2 && may_pad)
	++nbytes;
  /*
   * Our algorithm is simple, using a 32-bit accumulator (sum),
   * we add sequential 16-bit words to it, and at the end, fold back
   * all the carry bits from the top 16 bits into the lower 16 bits.
   */

  sum = 0;
  while (nbytes > 1)
    {
      sum += *ptr++;
      nbytes -= 2;
    }

  /* mop up an odd byte, if necessary */
  if (nbytes == 1)
    {
      oddbyte = 0;		/* make sure top half is zero */
      *((unsigned char *) & oddbyte) = *(unsigned char *) ptr;	/* one byte only */
      sum += oddbyte;
    }

  /*
   * Add back carry outs from top 16 bits to low 16 bits.
   */

  sum = (sum >> 16) + (sum & 0xffff);	/* add high-16 to low-16 */
  sum += (sum >> 16);		/* add carry */
  answer = ~sum;		/* ones-complement, then truncate to 16 bits */
  return (answer);
}


string mac2bin(const string &src)
{
	unsigned char mac[numbers::eth_alen];

	if (src.size() == numbers::eth_alen) {
		memcpy(mac, src.c_str(), numbers::eth_alen);
		return src;
	}
	if (sscanf(src.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
	           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != numbers::eth_alen)
		return "";
	return string(reinterpret_cast<char *>(mac), numbers::eth_alen);
}


string bin2mac(const string &mac)
{
	char m[100];

	memset(m, 0, sizeof(m));
	snprintf(m, sizeof(m), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0]&0xff, mac[1]&0xff, mac[2]&0xff, mac[3]&0xff, mac[4]&0xff, mac[5]&0xff);
	return string(m);
}


} // namespace usipp


