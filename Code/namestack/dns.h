#ifndef __DNS_H__
#define __DNS_H__

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <sys/types.h>
#include <netinet/in.h>
#endif

/* The format of a resource record (RR) is defined in RFC 1035, section 3.2.1,
 * as:
 * (bit offset)
 *                1
 * 0              5
 * +--------------+
 * /     NAME     /
 * +--------------+
 * |     TYPE     |
 * +--------------+
 * |    CLASS     |
 * +--------------+
 * |      TTL     |
 * |              |
 * +--------------+
 * | RDLENGTH     |
 * +--------------+
 * /    RDATA     /
 * +--------------+
 */

/* Returns the number of bytes in the name beginning at ptr.
 * start is the beginning of the message (not the name!), and len is
 * the message's length in bytes.  (These are used as a failsafe, to terminate
 * parsing a malformed name.)
 */
uint16_t advance_name(const u_char *ptr, const u_char *start, uint16_t len);

/* Parses an RR, beginning at ptr, into its type, class, ttl, rdlength, and
 * rdata.
 * Returns 0 if the parsed RR is sane, nonzero otherwise.
 */
int parse_rr(const u_char *ptr, const u_char *start, uint16_t len,
             uint16_t *ptype, uint16_t *pclass, uint32_t *pttl,
             uint16_t *prdlength, const u_char **prdata);

/* Given a DNS response in ptr, with length len, finds the nth answer of type t
 * in the response.  If it's found, returns a pointer to its data (in *prdata)
 * and the length of that data (in *prdlength), and returns 0.  If it isn't
 * found, returns nonzero.
 * This is meant to be called in a loop, with n = 0 for the first iteration of
 * the loop, n = 1 for the second iteration, until find_answer_of_type returns
 * a nonzero value.
 */
int find_answer_of_type(const u_char *ptr, uint16_t len, uint16_t t,
			uint16_t n, uint16_t *prdlength, const u_char **prdata);

#endif
