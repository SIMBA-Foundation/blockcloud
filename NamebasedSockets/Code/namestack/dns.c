#include "dns.h"
#ifdef __KERNEL__
#include <linux/in.h>
#include "nameser.h"
#else
#include <string.h> /* NULL */
#define BIND_8_COMPAT
#include <arpa/nameser.h>
#endif /* __KERNEL__ */

uint16_t advance_name(const u_char *ptr, const u_char *start, uint16_t len)
{
	int has_pointer = 0;
	const u_char *original_ptr = ptr;

	for (; ptr - start < len; )
	{
		if ((*ptr & 0xc0) == 0xc0)
		{
			has_pointer = 1;
			ptr += sizeof(uint16_t);
			/* A pointer always terminates this loop */
			break;
		}
		else
		{
			u_char label_len = *ptr;

			ptr += label_len + 1;
			if (!label_len)
			{
				/* An empty label indicates the end of the name
				 */
				break;
			}
		}
	}
	return ptr - original_ptr;
}

int parse_rr(const u_char *ptr, const u_char *start, uint16_t len,
			 uint16_t *ptype, uint16_t *pclass, uint32_t *pttl,
			 uint16_t *prdlength, const u_char **prdata)
{
	const u_char *original_ptr = ptr;
	int overrun = 0;
	uint16_t rdlength;

	ptr += advance_name(ptr, start, len);

	if (ptr - original_ptr + sizeof(uint16_t) > len)
	{
		overrun = 1;
		goto out;
	}
	if (ptype)
		*ptype = htons(*(uint16_t *)ptr);
	ptr += sizeof(uint16_t);

	if (ptr - original_ptr + sizeof(uint16_t) > len)
	{
		overrun = 1;
		goto out;
	}
	if (pclass)
		*pclass = htons(*(uint16_t *)ptr);
	ptr += sizeof(uint16_t);

	if (ptr - original_ptr + sizeof(uint32_t) > len)
	{
		overrun = 1;
		goto out;
	}
	if (pttl)
		*pttl = htonl(*(uint32_t *)ptr);
	ptr += sizeof(uint32_t);

	if (ptr - original_ptr + sizeof(uint16_t) > len)
	{
		overrun = 1;
		goto out;
	}
	rdlength = htons(*(uint16_t *)ptr);
	if (prdlength)
		*prdlength = rdlength;
	ptr += sizeof(uint16_t);

	if (ptr - original_ptr + rdlength > len)
	{
		overrun = 1;
		goto out;
	}
	if (prdata)
		*prdata = ptr;
out:
	return overrun;
}

int find_answer_of_type(const u_char *ptr, uint16_t len, uint16_t t,
			uint16_t n, uint16_t *prdlength, const u_char **prdata)
{
	const u_char *original_ptr = ptr;
	const HEADER *header = (const HEADER *)ptr;
	uint16_t qdcount, ancount;
	int i, matching_answers, overrun = 0;

	if (len < sizeof(HEADER))
	{
		overrun = 1;
		goto out;
	}
	qdcount = ntohs(header->qdcount);
	ancount = ntohs(header->ancount);
	/* Advance past questions */
	ptr += sizeof(HEADER);
	for (i = 0; i < qdcount; i++)
	{
		ptr += advance_name(ptr, original_ptr, len);
		if (ptr - original_ptr + sizeof(uint16_t) > len)
		{
			overrun = 1;
			goto out;
		}
		ptr += sizeof(uint16_t);
		if (ptr - original_ptr + sizeof(uint16_t) > len)
		{
			overrun = 1;
			goto out;
		}
		ptr += sizeof(uint16_t);
	}
	/* Walk through answers, looking for nth instance of type t */
	for (i = 0, matching_answers = 0; i < ancount; i++)
	{
		uint16_t type, rdlength;
		const u_char *rdata;

		overrun = parse_rr(ptr, original_ptr, len, &type, NULL, NULL,
				   &rdlength, &rdata);
		if (!overrun)
		{
			ptr = rdata + rdlength;
			if (type == t)
			{
				if (matching_answers == n)
				{
					/* Found the desired instance */
					if (prdlength)
						*prdlength = rdlength;
					if (prdata)
						*prdata = rdata;
					break;
				}
				else
					matching_answers++;
			}
		}
	}
	if (!overrun && i >= ancount)
	{
		/* This isn't really an overrun, but the desired instance
		 * wasn't found.
		 */
		overrun = 1;
	}
out:
	return overrun;
}
