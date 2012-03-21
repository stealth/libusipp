#include <stdint.h>


namespace usipp {

typedef uint16_t u_short;


// ripped code, slightly modified
// to pad odd length automagically (UDP,TCP)
unsigned short
in_cksum (unsigned short *ptr, int nbytes, bool may_pad)
{

  register long sum;		/* assumes long == 32 bits */
  u_short oddbyte;
  register u_short answer;	/* assumes u_short == 16 bits */


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


} // namespace usipp


