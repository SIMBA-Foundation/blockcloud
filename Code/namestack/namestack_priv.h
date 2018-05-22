#ifndef NAMESTACK_PRIV_H
#define NAMESTACK_PRIV_H

#include <linux/types.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/inname.h>

struct name_stream_sock
{
	struct sock sk;
	struct sockaddr_name sname;
	struct sockaddr_name dname;
	u_char *dname_answer;
	int dname_answer_len;
	uint16_t dname_answer_index;
	int async_error;
	struct socket *ipv4_sock;
	struct socket *ipv6_sock;
	struct sock *(*orig_syn_recv_sock)(struct sock *sk, struct sk_buff *skb,
					   struct request_sock *req,
					   struct dst_entry *dst);
};

static inline struct name_stream_sock *name_stream_sk(const struct sock *sk)
{
	return (struct name_stream_sock *)sk;
}

/* Registration/unregistration functions */
extern int name_af_init(void);
extern void name_af_exit(void);

/* Name resolution functions */
typedef void (*query_resolv_cb)(const __u8 *response, int len, void *data);
int name_send_query(const char *name, query_resolv_cb cb, void *data);
void name_cancel_query(void *data);

struct inet6_ifaddr;
struct in_ifaddr;

/* Selects best addresses to use.  For now, assumes that each name should use
 * the same heuristic for choosing an address.  Returns a list of IPv6 and
 * IPv4 addresses, in order of preference.
 * Returns 0 on success, an error code on failure.  On success, free the
 * returned addresses with kfree().
 */
int choose_addresses(int *num_v6_addresses, struct in6_addr **v6_addresses,
		     int *num_v4_addresses, __be32 **v4_addresses);

/* Matches the sin6_addr portion of the address to a scope id on the local
 * host, and sets sin6's scope id to the matching scope id.
 * Returns 0 if found, an error code on failure.
 */
int match_v6_address_to_scope(struct sockaddr_in6 *sin6);

/* Attempts to choose a scope id on which sin6 is reachable, and sets
 * sin6's scope id to the matching scope id.
 * Returns 0 if found, an error code on failure.
 */
int choose_scope_for_v6_address(struct sockaddr_in6 *sin6);

/* Name registration (bind()/DNS update) functions */
typedef void (*qualify_cb)(const char *name, void *data);
int name_fully_qualify(const char *name, qualify_cb cb, void *data);
typedef void (*register_cb)(int result, const char *name, void *data);
/* FIXME: needs to be given a list of addresses */
int name_send_registration(const char *name, const struct in6_addr *v6_addresses,
			   int num_v6_addresses, const __be32 *v4_addresses,
			   int num_v4_addresses, register_cb cb, void *data);
void name_delete_registration(const char *name);

/* Name cache functions */
int name_cache_init(void);
int name_cache_add(const char *name, struct socket *sock);
void name_cache_delete(const char *name);
void name_cache_free(void);

#endif /* NAMESTACK_PRIV_H */
