#include <linux/ctype.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/net.h>
#include <linux/module.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <net/inet6_hashtables.h>
#include <net/ipv6.h>
#include <net/tcp_states.h>
#include <net/transp_v6.h>
#include <linux/inname.h>
#include "dns.h"
#include "nameser.h"
#include "namestack_priv.h"

enum {
	NAME_RESOLVING = TCP_MAX_STATES, /* Don't overlap with TCP states */
	NAME_BINDING,
	NAME_CONNECTING,
};

enum {
	NAMEF_RESOLVING   = (1 << NAME_RESOLVING),
	NAMEF_BINDING     = (1 << NAME_BINDING),
	NAMEF_CONNECTING  = (1 << NAME_CONNECTING),
};

static void name_stream_state_change(struct sock *sk)
{
	struct name_stream_sock *name;

	read_lock(&sk->sk_callback_lock);
	if (!(name = sk->sk_user_data))
		goto out;

	printk(KERN_INFO "sk_state is %d\n", sk->sk_state);
	switch (sk->sk_state) {
	case TCP_ESTABLISHED:
		name->sk.sk_state = TCP_ESTABLISHED;
		name->sk.sk_state_change(&name->sk);
		break;
	case TCP_FIN_WAIT1:
		/* The client initiated a shutdown of the socket */
		break;
	case TCP_CLOSE_WAIT:
		/* The server initiated a shutdown of the socket */
	case TCP_SYN_SENT:
	case TCP_CLOSING:
		/*
		 * If the server closed down the connection, make sure that
		 * we back off before reconnecting
		 */
		break;
	case TCP_LAST_ACK:
		break;
	case TCP_CLOSE:
		break;
	}
 out:
	read_unlock(&sk->sk_callback_lock);
}

static int name_is_local(const char *name)
{
	const char *p;

        if (!name[0])
		return 0;
	p = name + strlen(name) - 1;
	if (*p != '.')
		return 0;
	for (p = p - 1; *p != '.' && p >= name; p--)
		;
	if (p == name)
		return 0;
	return !strcasecmp(p + 1, "localhost.");
}

/* If name ends in the IPv4 canonical suffix .in-addr.arpa., returns a
 * pointer to the suffix, beginning with the dot.  Otherwise returns NULL.
 */
static const char *name_find_v4_canonical_suffix(const char *name)
{
	static const char canon_v4_suffix[] = ".in-addr.arpa.";

	if (strlen(name) > strlen(canon_v4_suffix)) {
		const char *p = name + strlen(name) - strlen(canon_v4_suffix);

		if (!strcasecmp(p, canon_v4_suffix))
			return p;
	}
	return NULL;
}

/* If name ends in the IPv6 canonical suffix .ip6.arpa., returns a
 * pointer to the suffix, beginning with the dot.  Otherwise returns NULL.
 */
static const char *name_find_v6_canonical_suffix(const char *name)
{
	static const char canon_v6_suffix[] = ".ip6.arpa.";

	if (strlen(name) > strlen(canon_v6_suffix)) {
		const char *p = name + strlen(name) - strlen(canon_v6_suffix);

		if (!strcasecmp(p, canon_v6_suffix))
			return p;
	}
	return NULL;
}

static inline int name_is_canonical(const char *name)
{
	return name_find_v4_canonical_suffix(name) != NULL ||
	       name_find_v6_canonical_suffix(name) != NULL;
}

static int name_stream_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct name_stream_sock *name = name_stream_sk(sk);

	if (!sk)
		goto out;

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_state_change(sk);

	if (name->dname_answer) {
		kfree(name->dname_answer);
		name->dname_answer = NULL;
		name->dname_answer_len = 0;
		name->dname_answer_index = 0;
	}
	if (name->sname.sname_addr.name[0]) {
		name_cache_delete(name->sname.sname_addr.name);
		if (!name_is_local(name->sname.sname_addr.name) &&
		    !name_is_canonical(name->sname.sname_addr.name))
			name_delete_registration(name->sname.sname_addr.name);
	}
	if (name->ipv6_sock) {
		kernel_sock_shutdown(name->ipv6_sock, SHUT_WR);
		sock_release(name->ipv6_sock);
		name->ipv6_sock = NULL;
	}
	if (name->ipv4_sock) {
		kernel_sock_shutdown(name->ipv4_sock, SHUT_WR);
		sock_release(name->ipv4_sock);
		name->ipv4_sock = NULL;
	}

	sock_set_flag(sk, SOCK_DEAD);
	sock->sk = NULL;
	sk_refcnt_debug_release(sk);
	sock_put(sk);
out:
	return 0;
}

/* Stolen from net/ipv6/ipv6_sockglue.c */
static
struct ipv6_txoptions *ipv6_update_options(struct sock *sk,
					   struct ipv6_txoptions *opt)
{
	if (inet_sk(sk)->is_icsk) {
		/* The original version of this only updates the options if the
		 * socket is not listening or closed, but I want the options to
		 * be set even on SYN/SYN-ACK packets, so I update the socket
		 * irrespective of state.
		 */
		if (opt) {
			struct inet_connection_sock *icsk = inet_csk(sk);
			icsk->icsk_ext_hdr_len = opt->opt_flen + opt->opt_nflen;
			icsk->icsk_sync_mss(sk, icsk->icsk_pmtu_cookie);
		}
		opt = xchg(&inet6_sk(sk)->opt, opt);
	} else {
		write_lock(&sk->sk_dst_lock);
		opt = xchg(&inet6_sk(sk)->opt, opt);
		write_unlock(&sk->sk_dst_lock);
	}
	sk_dst_reset(sk);

	return opt;
}

/* Stolen from net/ipv6/exthdrs.c.  That one takes an ipv6_opt_hdr from user-
 * space, but this doesn't, so the copy_from_user is removed.
 */
static int ipv6_renew_option(void *ohdr,
			     struct ipv6_opt_hdr *newopt, int newoptlen,
			     int inherit,
			     struct ipv6_opt_hdr **hdr,
			     char **p)
{
	if (inherit) {
		if (ohdr) {
			memcpy(*p, ohdr, ipv6_optlen((struct ipv6_opt_hdr *)ohdr));
			*hdr = (struct ipv6_opt_hdr *)*p;
			*p += CMSG_ALIGN(ipv6_optlen(*(struct ipv6_opt_hdr **)hdr));
		}
	} else {
		if (newopt) {
			memcpy(*p, newopt, newoptlen);
			*hdr = (struct ipv6_opt_hdr *)*p;
			*p += CMSG_ALIGN(newoptlen);
		}
	}
	return 0;
}

/* Identical to ipv6_renew_options in net/ipv6/exthdrs.c, but calls the
 * modified ipv6_renew_option (above).
 */
struct ipv6_txoptions *
namestack_ipv6_renew_options(struct sock *sk, struct ipv6_txoptions *opt,
		   int newtype,
		   struct ipv6_opt_hdr *newopt, int newoptlen)
{
	int tot_len = 0;
	char *p;
	struct ipv6_txoptions *opt2;
	int err;

	if (opt) {
		if (newtype != IPV6_HOPOPTS && opt->hopopt)
			tot_len += CMSG_ALIGN(ipv6_optlen(opt->hopopt));
		if (newtype != IPV6_RTHDRDSTOPTS && opt->dst0opt)
			tot_len += CMSG_ALIGN(ipv6_optlen(opt->dst0opt));
		if (newtype != IPV6_RTHDR && opt->srcrt)
			tot_len += CMSG_ALIGN(ipv6_optlen(opt->srcrt));
		if (newtype != IPV6_DSTOPTS && opt->dst1opt)
			tot_len += CMSG_ALIGN(ipv6_optlen(opt->dst1opt));
	}

	if (newopt && newoptlen)
		tot_len += CMSG_ALIGN(newoptlen);

	if (!tot_len)
		return NULL;

	tot_len += sizeof(*opt2);
	opt2 = sock_kmalloc(sk, tot_len, GFP_ATOMIC);
	if (!opt2)
		return ERR_PTR(-ENOBUFS);

	memset(opt2, 0, tot_len);

	opt2->tot_len = tot_len;
	p = (char *)(opt2 + 1);

	err = ipv6_renew_option(opt ? opt->hopopt : NULL, newopt, newoptlen,
				newtype != IPV6_HOPOPTS,
				&opt2->hopopt, &p);
	if (err)
		goto out;

	err = ipv6_renew_option(opt ? opt->dst0opt : NULL, newopt, newoptlen,
				newtype != IPV6_RTHDRDSTOPTS,
				&opt2->dst0opt, &p);
	if (err)
		goto out;

	err = ipv6_renew_option(opt ? opt->srcrt : NULL, newopt, newoptlen,
				newtype != IPV6_RTHDR,
				(struct ipv6_opt_hdr **)&opt2->srcrt, &p);
	if (err)
		goto out;

	err = ipv6_renew_option(opt ? opt->dst1opt : NULL, newopt, newoptlen,
				newtype != IPV6_DSTOPTS,
				&opt2->dst1opt, &p);
	if (err)
		goto out;

	opt2->opt_nflen = (opt2->hopopt ? ipv6_optlen(opt2->hopopt) : 0) +
			  (opt2->dst0opt ? ipv6_optlen(opt2->dst0opt) : 0) +
			  (opt2->srcrt ? ipv6_optlen(opt2->srcrt) : 0);
	opt2->opt_flen = (opt2->dst1opt ? ipv6_optlen(opt2->dst1opt) : 0);

	return opt2;
out:
	sock_kfree_s(sk, opt2, opt2->tot_len);
	return ERR_PTR(err);
}

struct name_opt_hdr
{
	__u8 type;
	__u8 len;
	/* Followed by the actual name */
};

/* FIXME: Change name options to the "real" values once they're known.  Must
 * <= 63.
 */
#define NAME_OPTION_SOURCE_NAME 17
#define NAME_OPTION_DEST_NAME   18

static void rfc1035_encode_name(char *dst, const char *name)
{
	const char *p = name;

	while (p && *p)
	{
		const char *dot = strchr(p, '.');

		if (dot)
		{
			unsigned char len = dot - p;

			*dst = len;
			memcpy(dst + 1, p, len);
			dst += len + 1;
			p = dot + 1;
		}
		else
			p = NULL;
	}
	*dst = 0;
}

static int set_name_option(struct socket *sock, const char *name, __u8 opt_type)
{
	struct sock *sk = sock->sk;
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct ipv6_txoptions *opt;
	char *name_opt_buf;
	struct ipv6_opt_hdr *opt_hdr;
	struct name_opt_hdr *name_opt_hdr;
	int err, name_opt_len;

 	if (np->opt && np->opt->dst1opt) {
 		name_opt_len = ipv6_optlen(np->opt->dst1opt);
 		name_opt_len += sizeof(struct name_opt_hdr) + strlen(name) + 1;
 		err = -ENOMEM;
 		name_opt_buf = kmalloc(name_opt_len, GFP_ATOMIC);
 		if (!name_opt_buf)
 			goto out;
 		memset(name_opt_buf, 0, name_opt_len);
 		memcpy(name_opt_buf, np->opt->dst1opt,
 		       ipv6_optlen(np->opt->dst1opt));
 
 		opt_hdr = (struct ipv6_opt_hdr *)name_opt_buf;
 		name_opt_hdr = (struct name_opt_hdr *)(opt_hdr + 1);
 		name_opt_hdr = (struct name_opt_hdr *)((char *)name_opt_hdr +
 			sizeof(struct name_opt_hdr) + name_opt_hdr->len);
 		name_opt_hdr->type = opt_type;
 		/* Happily the RFC1035-encoded name has the same length as the
 		 * C string.
 		 */
 		name_opt_hdr->len = strlen(name) + 1;
 		rfc1035_encode_name((char *)(name_opt_hdr + 1), name);
 		opt_hdr->nexthdr = 0;
 		opt_hdr->hdrlen = (name_opt_len + 1) >> 3;
 	}
 	else {
 		struct ipv6_opt_hdr tmp_opt_hdr;
 
 		/* Use to calculate the required length */
 		tmp_opt_hdr.nexthdr = 0;
 		/* FIXME: this is the reverse of ipv6_optlen, used to calculate
 		 * name_opt_len.  Are you sure it's correct?  Is there a nice
 		 * macro/calculation somewhere?
 		 */
 		tmp_opt_hdr.hdrlen =
 			(sizeof(struct name_opt_hdr) + strlen(name) + 1) >> 3;
 		name_opt_len = ipv6_optlen(&tmp_opt_hdr);
 		err = -ENOMEM;
 		name_opt_buf = kmalloc(name_opt_len, GFP_ATOMIC);
 		if (!name_opt_buf)
 			goto out;
 
 		memset(name_opt_buf, 0, name_opt_len);
 		opt_hdr = (struct ipv6_opt_hdr *)name_opt_buf;
 		name_opt_hdr = (struct name_opt_hdr *)(opt_hdr + 1);
 		name_opt_hdr->type = opt_type;
 		/* Happily the RFC1035-encoded name has the same length as the
 		 * C string.
 		 */
 		name_opt_hdr->len = strlen(name) + 1;
 		rfc1035_encode_name((char *)(name_opt_hdr + 1), name);
 		opt_hdr->nexthdr = 0;
 		opt_hdr->hdrlen =
 			(sizeof(struct name_opt_hdr) + name_opt_hdr->len) >> 3;
 	}
	/* Rather than calling kernel_setsockopt, set the option directly to
	 * avoid a permissions check on the calling process.
	 */
	opt = namestack_ipv6_renew_options(sk, np->opt, IPV6_DSTOPTS,
				 (struct ipv6_opt_hdr *)name_opt_buf,
				 name_opt_len);
	if (IS_ERR(opt)) {
		err = PTR_ERR(opt);
		goto out;
	}
	err = 0;
	opt = ipv6_update_options(sk, opt);
	if (opt)
		sock_kfree_s(sk, opt, opt->tot_len);
out:
	if (name_opt_buf)
		kfree(name_opt_buf);
	return err;
}

#if defined(CONFIG_NAMESTACK_MODULE)
/* Stolen from net/ipv6/exthdrs.c */
int ipv6_find_tlv(struct sk_buff *skb, int offset, int type)
{
	const unsigned char *nh = skb_network_header(skb);
	int packet_len = skb->tail - skb->network_header;
	struct ipv6_opt_hdr *hdr;
	int len;

	if (offset + 2 > packet_len)
		goto bad;
	hdr = (struct ipv6_opt_hdr *)(nh + offset);
	len = ((hdr->hdrlen + 1) << 3);

	if (offset + len > packet_len)
		goto bad;

	offset += 2;
	len -= 2;

	while (len > 0) {
		int opttype = nh[offset];
		int optlen;

		if (opttype == type)
			return offset;

		switch (opttype) {
		case IPV6_TLV_PAD0:
			optlen = 1;
			break;
		default:
			optlen = nh[offset + 1] + 2;
			if (optlen > len)
				goto bad;
			break;
		}
		offset += optlen;
		len -= optlen;
	}
	/* not_found */
 bad:
	return -1;
}
#endif

static char *rfc1035_decode_name(const u8 *p, int len)
{
	const u8 *q;
	int name_len = 0;
	char *name = NULL;

	for (q = p; *q && q - p <= len; q += *q + 1)
		name_len += *q + 1;
	if (!*q && q - p <= len) {
		name_len += 1;
		name = kmalloc(name_len, GFP_ATOMIC);
		if (name) {
			char *dst;

			for (q = p, dst = name; *q && q - p <= len;
			     dst += *q + 1, q += *q + 1) {
				memcpy(dst, q + 1, *q);
				dst[*q] = '.';
			}
			*dst = 0;
		}
	}
	return name;
}

static inline char *name_option_to_str(struct sk_buff *skb, u16 offset)
{
	const unsigned char *nh = skb_network_header(skb);
	const struct name_opt_hdr *name_hdr =
		(const struct name_opt_hdr *)(nh + offset);
	const u8 *name_ptr = (const u8 *)(name_hdr + 1);

	return rfc1035_decode_name(name_ptr, name_hdr->len);
}

static int name_option_matches(struct sk_buff *skb, u16 offset,
			       const char *name)
{
	int matches = 0;
	char *option_name = name_option_to_str(skb, offset);

	if (option_name) {
		matches = !strcmp(name, option_name);
		printk(KERN_INFO "destination name %s %s %s\n", option_name,
		       matches ? "matches" : "doesn't match", name);
		kfree(option_name);
	}
	return matches;
}

struct syn_entry
{
	struct in6_addr peer_addr;
	__be16 peer_port;
	struct name_addr name;
	struct hlist_node entry;
};

/* NAME_SYN_BUCKETS must be a power of 2, or the "& (NAME_SYN_BUCKETS - 1)"
 * below must be changed to "% NAME_SYN_BUCKETS".
 */
#define NAME_SYN_BUCKETS 16
static struct hlist_head name_stream_syns[NAME_SYN_BUCKETS];
static DEFINE_SPINLOCK(name_stream_syn_lock);

static void name_stream_store_syn(struct sock *sk, struct sk_buff *skb,
				  int source_name_offset)
{
	u32 bucket;
	char *source_name;
	const struct inet_sock *inet = inet_sk(sk);
	const struct ipv6_pinfo *np = inet6_sk(sk);
	const struct in6_addr *saddr = &np->rcv_saddr;
	const __u16 port = inet->dport;

	bucket = inet6_sk_ehashfn(sk) & (NAME_SYN_BUCKETS - 1);

	source_name = name_option_to_str(skb, source_name_offset);
	if (source_name) {
		struct syn_entry *entry, *found = NULL;
		struct hlist_node *node;

		printk(KERN_INFO "see source name option %s\n",
		       (char *)source_name);
		printk(KERN_INFO "port is %d, bucket is %d\n", port, bucket);

		/* FIXME: lock each bucket rather than the whole table. */
		spin_lock_irq(&name_stream_syn_lock);
		hlist_for_each_entry(entry,
				     node,
				     &name_stream_syns[bucket],
				     entry)
		{
			if (!memcmp(saddr, &entry->peer_addr, sizeof(saddr))
			    && port == entry->peer_port)
			{
				found = entry;
				break;
			}
		}
		if (found)
		{
			/* An entry with the same IP address and port exists,
			 * replace its name.
			 */
			strcpy(found->name.name, source_name);
		}
		else
		{
			found = kzalloc(sizeof(struct syn_entry), GFP_ATOMIC);

			/* No entry was found, insert a new entry into the
			 * list.
			 */
			if (found)
			{
				strcpy(found->name.name, source_name);
				memcpy(&found->peer_addr, saddr, sizeof(saddr));
				found->peer_port = port;
				hlist_add_head(&found->entry,
					       &name_stream_syns[bucket]);
			}
		}
		spin_unlock_irq(&name_stream_syn_lock);
		kfree(source_name);
	}
}

static struct sock *name_v6_recv_syn(struct sock *sk, struct sk_buff *skb,
				     struct request_sock *req,
				     struct dst_entry *dst)
{
	struct name_stream_sock *name = sk->sk_user_data;
	struct sock *ret = NULL;
	u16 offset;
	struct ipv6_opt_hdr *exthdr =
		(struct ipv6_opt_hdr *)(ipv6_hdr(skb) + 1);
	const unsigned char *nh = skb_network_header(skb);
	unsigned int packet_len = skb->tail - skb->network_header;
	u8 *nexthdr;
	int source_name_offset = -1, dest_name_offset = -1;

	nexthdr = &ipv6_hdr(skb)->nexthdr;
	offset = sizeof(struct ipv6hdr);
	while (offset + 1 <= packet_len) {
		switch (*nexthdr) {
		case NEXTHDR_DEST:
			if (dest_name_offset == -1)
				dest_name_offset = ipv6_find_tlv(skb, offset,
					NAME_OPTION_DEST_NAME);
			if (source_name_offset == -1)
				source_name_offset = ipv6_find_tlv(skb, offset,
					NAME_OPTION_SOURCE_NAME);
			break;
		}

		offset += ipv6_optlen(exthdr);
		nexthdr = &exthdr->nexthdr;
		exthdr = (struct ipv6_opt_hdr *)(nh + offset);
	}
	/* Only accept if there's no dest name option or if the dest name
	 * matches our (source) name.
	 */
	if (dest_name_offset == -1 ||
	    name_option_matches(skb, dest_name_offset,
				name->sname.sname_addr.name)) {
		ret = name->orig_syn_recv_sock(sk, skb, req, dst);
		if (ret) {
			if (source_name_offset != -1) {
				/* The SYN packet contains a source name option,
				 * so store it for subsequent use by
				 * name_stream_accept.
				 * (The more obvious thing to do would be to
				 * return a struct sock * that contained the
				 * name in it directly, but the kernel makes
				 * assumptions about the return type of this
				 * function that I never fully understood.  The
				 * effect was to hang or crash the kernel.
				 * This approach works around my own lack of
				 * understanding.)
				 */
				name_stream_store_syn(ret, skb,
						      source_name_offset);
			}
		}
	}
	return ret;
}

static struct inet_connection_sock_af_ops name_tcp6_af_ops;
static int name_tcp6_af_ops_init;

static int name_create_v6_sock(int type, int protocol, struct socket **sock,
			       struct name_stream_sock *name)
{
	int err = sock_create_kern(PF_INET6, type, protocol, sock);

	if (!err) {
		err = set_name_option(*sock, name->sname.sname_addr.name,
				      NAME_OPTION_SOURCE_NAME);
	}
	if (!err) {
		int on = 1;

		err = kernel_setsockopt(*sock, IPPROTO_IPV6, IPV6_V6ONLY,
					(char *)&on, sizeof(on));
	}
	if (!err) {
		struct inet_connection_sock *icsk = inet_csk((*sock)->sk);

		(*sock)->sk->sk_user_data = name;
		(*sock)->sk->sk_state_change = name_stream_state_change;
		if (!name_tcp6_af_ops_init) {
			memcpy(&name_tcp6_af_ops, icsk->icsk_af_ops,
			       sizeof(struct inet_connection_sock_af_ops));
			name_tcp6_af_ops.syn_recv_sock = name_v6_recv_syn;
			name_tcp6_af_ops_init = 1;
		}
		name->orig_syn_recv_sock = icsk->icsk_af_ops->syn_recv_sock;
		icsk->icsk_af_ops = &name_tcp6_af_ops;
	}
	return err;
}

static int name_create_v4_sock(int type, int protocol, struct socket **sock,
			       struct name_stream_sock *name)
{
	int err = sock_create_kern(PF_INET, type, protocol, sock);

	if (!err) {
		(*sock)->sk->sk_user_data = name;
		(*sock)->sk->sk_state_change = name_stream_state_change;
	}
	return err;
}

static int name_bind_to_fqdn(struct name_stream_sock *name, const char *fqdn,
			     const __be32 *v4addr,
			     const struct in6_addr *v6addr)
{
	int err = 0;

	printk(KERN_INFO "bound to %s\n", fqdn);
	/* If a particular port or address is specified, bind() must fail if
	 * the port or address is unavailable, hence we must create the
	 * transport sockets if they don't already exist so we may attempt to
	 * bind to the specified address and port.  If no address or port is
	 * specified, name_register() has already checked that the name is
	 * available, so bind() succeeds without needing to create the sockets
	 * yet.  (The sockets will be created as necessary during connect() or
	 * listen().)
	 */
	if (name->sname.sname_port || v4addr) {
		struct sockaddr_in sin;

		if (!name->ipv4_sock) {
			err = name_create_v4_sock(SOCK_STREAM, 0,
						  &name->ipv4_sock, name);
			if (err)
				goto out;
		}
		memset(&sin, 0, sizeof(sin));
		if (v4addr)
			memcpy(&sin.sin_addr.s_addr, &v4addr, sizeof(v4addr));
		sin.sin_port = name->sname.sname_port;
		err = kernel_bind(name->ipv4_sock, (struct sockaddr *)&sin,
				  sizeof(sin));
		if (err)
			goto out;
	}
	if (name->sname.sname_port || v6addr) {
		struct sockaddr_in6 sin;

		if (!name->ipv6_sock) {
			err = name_create_v6_sock(SOCK_STREAM, 0,
						  &name->ipv6_sock, name);
			if (err)
				goto out;
		}
		memset(&sin, 0, sizeof(sin));
		if (v6addr) {
			memcpy(&sin.sin6_addr, v6addr, sizeof(sin.sin6_addr));
			/* If it's a link-local address, match the address to
			 * a scope id that defines the interface on which it'll
			 * be used.
			 */
			if (sin.sin6_addr.s6_addr[0] == 0xfe &&
			    sin.sin6_addr.s6_addr[1] == 0x80)
			{
				err = match_v6_address_to_scope(&sin);
				if (err)
					goto out;
			}
		}
		sin.sin6_port = name->sname.sname_port;
		err = kernel_bind(name->ipv6_sock, (struct sockaddr *)&sin,
				  sizeof(sin));
	}
out:
	return err;
}

static void name_register_cb(int result, const char *bound_name, void *data)
{
	struct socket *sock = data;
	struct sock *sk = sock->sk;
	struct name_stream_sock *name = name_stream_sk(sk);

	if (!result)
		result = name_bind_to_fqdn(name, bound_name, NULL, NULL);
	sk->sk_state &= ~NAMEF_BINDING;
	name->async_error = -result;
}

/* Parses the canonical name into the IPv4 address it represents, in host
 * byte order.
 * Returns -EINVAL if the name is not an IPv4 address, and 0 otherwise.
 */
static int name_parse_canonical_v4(const char *name, unsigned int *addr)
{
	const char *p;
	int i, r;
	unsigned int a1, a2, a3, a4;

	p = name_find_v4_canonical_suffix(name);
	if (!p)
		return -EINVAL;
	/* Skip past the 4 octets of the IP address */
	for (i = 0; i < 4; i++) {
		for (--p; p > name && isdigit(*p); --p)
			;
		if (p > name && *p != '.')
			return -EINVAL;
	}
	if (p > name)
		++p;
	r = sscanf(p, "%u.%u.%u.%u.", &a4, &a3, &a2, &a1);
	if (r != 4)
		return -EINVAL;
	if (a1 > 255 || a2 > 255 || a3 > 255 || a4 > 255)
		return -EINVAL;
	*addr = (a4 << 24) | (a3 << 16) | (a2 << 8) | a1;
	return 0;
}

static int name_parse_v6_label(const char *label, uint8_t addr[16],
			       int *bytesParsed, const char **endPtr)
{
	const char *p = label;
	uint8_t *dst = addr;
	int nibbleCount = 0;

	memset(addr, 0, 16 * sizeof(uint8_t));
	*bytesParsed = 0;
	if (*(p++) != '\\') return -EINVAL;
	if (*(p++) != '[') return -EINVAL;
	/* Only hexadecimal labels are supported */
	if (*(p++) != 'x') return -EINVAL;
	for (; isalnum(*p); p++)
	{
		uint8_t nibble;

		if (isdigit(*p))
			nibble = *p - '0';
		else if (*p >= 'a' && *p <= 'f')
			nibble = 10 + *p - 'a';
		else if (*p >= 'A' && *p <= 'F')
			nibble = 10 + *p - 'A';
		else
			return -EINVAL;
		if (nibbleCount & 1)
			*(dst++) |= nibble;
		else
			*dst = nibble << 4;
		nibbleCount++;
	}
	if (*p == ']')
	{
		*bytesParsed = nibbleCount >> 1;
		*endPtr = p + 1;
		return 0;
	}
	else if (*p == '/')
	{
		int bitCount = 0;

		for (++p; isdigit(*p); ++p) {
			bitCount *= 10;
			bitCount += *p - '0';
		}
		if (*p != ']')
			return -EINVAL;
		if (bitCount >> 3 != nibbleCount >> 1)
			return -EINVAL;
		*bytesParsed = bitCount >> 3;
		*endPtr = p + 1;
		return 0;
	}
	else
		return -EINVAL;
}

/* Parses the canonical name into the IPv6 address it represents, in host
 * byte order.
 * Returns -EINVAL if the name is not an IPv6 address, and 0 otherwise.
 */
static int name_parse_canonical_v6(const char *name, struct in6_addr *v6addr)
{
	const char *next, *p;
	uint8_t labelAddr[16];
	int r, bytesParsed;

	p = name_find_v6_canonical_suffix(name);
	if (!p)
		return -EINVAL;
	for (--p; p > name && *p != '.'; --p)
		;
	if (*p == '.')
		++p;
	/* This only parses a single label, because the canonical form of an
	 * address requires the fewest labels (1) possible to specify the
	 * address (see RFC2673.)
	 */
	r = name_parse_v6_label(p, labelAddr, &bytesParsed, &next);
	if (!r) {
		if (bytesParsed != sizeof(labelAddr))
			r = -EINVAL;
		else
			memcpy(v6addr->s6_addr, labelAddr, sizeof(labelAddr));
	}
	return r;
}

static int name_register(struct socket *sock, const char *fully_qualified_name,
			__be16 port)
{
	struct sock *sk = sock->sk;
	struct name_stream_sock *name = name_stream_sk(sk);
	int err;

	printk(KERN_INFO "name qualified as %s\n", fully_qualified_name);
	strcpy(name->sname.sname_addr.name, fully_qualified_name);
	name->sname.sname_port = port;
	err = name_cache_add(fully_qualified_name, sock);
	if (err)
		goto out;
	//assert(strlen(fully_qualified_name) > 1);
	if (!strchr(fully_qualified_name, '.')) {
		/* FIXME: name doesn't exist in any domain.  Do I need to make
		 * a canonical name out of it?
		 */
		name_cache_delete(fully_qualified_name);
		err = -EINVAL;
		goto out;
	}
	if (name_is_local(fully_qualified_name)) {
		__be32 v4loopback = htonl(INADDR_LOOPBACK);
		struct in6_addr v6loopback = { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } };

		err = name_bind_to_fqdn(name, fully_qualified_name, &v4loopback,
					&v6loopback);
	}
	else if (name_find_v4_canonical_suffix(fully_qualified_name) != NULL) {
		__be32 v4addr;

		err = name_parse_canonical_v4(fully_qualified_name, &v4addr);
		if (!err)
			err = name_bind_to_fqdn(name, fully_qualified_name,
						&v4addr, NULL);
	}
	else if (name_find_v6_canonical_suffix(fully_qualified_name) != NULL) {
		struct in6_addr v6addr;

		err = name_parse_canonical_v6(fully_qualified_name, &v6addr);
		if (!err)
			err = name_bind_to_fqdn(name, fully_qualified_name,
						NULL, &v6addr);
	}
	else {
		struct in6_addr *v6_addresses;
		__be32 *v4_addresses;
		int num_v6_addresses;
		int num_v4_addresses;

		err = choose_addresses(&num_v6_addresses, &v6_addresses,
				       &num_v4_addresses, &v4_addresses);
		if (!err) {
			err = name_send_registration(fully_qualified_name,
						     v6_addresses,
						     num_v6_addresses,
						     v4_addresses,
						     num_v4_addresses,
						     name_register_cb, sock);
			kfree(v6_addresses);
			kfree(v4_addresses);
		}
	}
	if (err)
		name_cache_delete(fully_qualified_name);

out:
	if (err) {
		name->async_error = -err;
		sk->sk_state &= ~NAMEF_BINDING;
		sk->sk_state_change(sk);
	}
	return err;
}

static void name_qualify_cb(const char *fully_qualified_name, void *data)
{
	struct socket *sock = data;
	struct sock *sk = sock->sk;
	struct name_stream_sock *name = name_stream_sk(sk);

	name_register(sock, fully_qualified_name, name->sname.sname_port);
}

static long name_wait_for_bind(struct sock *sk, long timeo)
{
	DEFINE_WAIT(wait);

	prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);
	while ((1 << sk->sk_state) & NAMEF_BINDING) {
		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
		if (signal_pending(current) || !timeo)
			break;
		prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);
	}
	finish_wait(sk->sk_sleep, &wait);
	return timeo;
}

static int name_qualify_and_register(struct sockaddr_name *addr,
				     struct socket *sock)
{
	int err, len;
	long timeo;
	struct sock *sk;
	struct name_stream_sock *name;

	len = strlen(addr->sname_addr.name);
	if (addr->sname_addr.name[len - 1] == '.') {
		/* Name is already fully qualified, register it directly */
		err = name_register(sock, addr->sname_addr.name,
				    addr->sname_port);
	}
	else {
		sk = sock->sk;
		name = name_stream_sk(sk);

		/* Copy the port to the socket's source name, it'll be used
		 * in name_qualify_cb.
		 */
		name->sname.sname_port = addr->sname_port;
		err = name_fully_qualify(addr->sname_addr.name,
					 name_qualify_cb, sock);
		if (err)
			goto out;

		timeo = sock_sndtimeo(sk, 0);
		if ((1 << sk->sk_state) & NAMEF_BINDING) {
			if (!timeo || !name_wait_for_bind(sk, timeo))
				goto out;
			err = sock_intr_errno(timeo);
			if (signal_pending(current))
				goto out;
		}
		if (name->async_error)
			err = name->async_error;
		else
			err = 0;
	}

out:
	return err;
}
static int
name_stream_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_name *addr = (struct sockaddr_name *)uaddr;
	struct sock *sk;
	struct name_stream_sock *name;
	int err;

	if (addr_len < sizeof(struct sockaddr_name))
		return -EINVAL;
	printk(KERN_INFO "requesting bind to %s\n", addr->sname_addr.name);

	sk = sock->sk;
	name = name_stream_sk(sk);
	lock_sock(sk);

	switch (sock->state) {
	default:
		err = -EINVAL;
		goto out;
	case SS_CONNECTED:
		err = -EISCONN;
		goto out;
	case SS_UNCONNECTED:
		sk->sk_state |= NAMEF_BINDING;
		break;
	};

	if (name->sname.sname_addr.name[0]) {
		/* This socket is already bound. */
		err = -EINVAL;
		goto out;
	}

	err = name_qualify_and_register(addr, sock);

out:
	release_sock(sk);
	return err;
}

static long name_wait_for_connect(struct sock *sk, long timeo)
{
	DEFINE_WAIT(wait);

	prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);
	while ((1 << sk->sk_state) & (NAMEF_RESOLVING | NAMEF_CONNECTING)) {
		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
		if (signal_pending(current) || !timeo)
			break;
		prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);
	}
	finish_wait(sk->sk_sleep, &wait);
	return timeo;
}

static int name_stream_connect_to_v6_address(struct sock *sk, uint16_t rdlength,
					     const u_char *rdata)
{
	struct name_stream_sock *name = name_stream_sk(sk);
	struct sockaddr_in6 sin6;
	struct in6_addr *addr;
	char address[46], *p;
	int i, in_zero = 0, err;

	if (rdlength != sizeof(struct in6_addr)) {
		printk(KERN_WARNING
		       "address record %d has invalid length %d\n",
		       name->dname_answer_index, rdlength);
		return -EHOSTUNREACH;
	}
	addr = (struct in6_addr *)rdata;
	p = address;
	for (i = 0; i < 7; i++)
	{
		if (!addr->s6_addr16[i])
		{
			if (!in_zero)
			{
				*p++ = ':';
				in_zero = 1;
			}
		}
		else
		{
			int n;

			sprintf(p, "%x:%n", ntohs(addr->s6_addr16[i]), &n);
			p += n;
			in_zero = 0;
		}
	}
	sprintf(p, "%x", ntohs(addr->s6_addr16[7]));
	printk(KERN_INFO "connect to IPv6 address %s:%d\n", address,
	       ntohs(name->dname.sname_port));
	err = sock_create_kern(PF_INET6, SOCK_STREAM, 0, &name->ipv6_sock);
	if (err)
		goto out;
	name->ipv6_sock->sk->sk_user_data = name;
	name->ipv6_sock->sk->sk_state_change = name_stream_state_change;
	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = name->dname.sname_port;
	memcpy(&sin6.sin6_addr, addr, sizeof(*addr));
	/* If the destination is a link-local address, choose the scope id
	 * that defines the interface with which to attempt the connection.
	 * FIXME: if it's ambiguous, should we try on every interface with
	 * an IPv6 address?
	 */
	if (sin6.sin6_addr.s6_addr[0] == 0xfe &&
	    sin6.sin6_addr.s6_addr[1] == 0x80)
	{
		err = choose_scope_for_v6_address(&sin6);
		if (err) {
			printk(KERN_WARNING "choose_scope_for_v6_address failed: %d\n",
			       err);
			goto out;
                }
		else
			printk(KERN_INFO "chose scope %d\n",
			       sin6.sin6_scope_id);
	}

	if (name->sname.sname_addr.name[0]) {
		err = set_name_option(name->ipv6_sock,
				      name->sname.sname_addr.name,
				      NAME_OPTION_SOURCE_NAME);
		if (err)
			goto out;
	}

	err = set_name_option(name->ipv6_sock, name->dname.sname_addr.name,
			      NAME_OPTION_DEST_NAME);
	if (err)
		goto out;

	err = kernel_connect(name->ipv6_sock, (struct sockaddr *)&sin6,
			     sizeof(sin6), O_NONBLOCK);
	/* The expected error is EINPROGRESS, as the socket connection kicks
	 * off.  Return success in this case.
	 */
	if (err == -EINPROGRESS)
		err = 0;
out:
	return err;
}

static int name_stream_connect_to_v4_address(struct sock *sk, uint16_t rdlength,
					     const u_char *rdata)
{
	struct name_stream_sock *name = name_stream_sk(sk);
	int err;
	struct sockaddr_in sin;
	uint32_t addr;
	char address[16], *p;
	const u_char *addrp;

	if (rdlength != sizeof(uint32_t)) {
		printk(KERN_WARNING
		       "address record %d has invalid length %d\n",
		       name->dname_answer_index, rdlength);
		return -EHOSTUNREACH;
	}
	addr = *(uint32_t *)rdata;
	p = address;
	for (addrp = (u_char *)&addr;
	     addrp - (u_char *)&addr < sizeof(uint32_t);
	     addrp++)
	{
		int n;

		sprintf(p, "%d%n", *addrp, &n);
		p += n;
		if (addrp < (u_char *)&addr + sizeof(uint32_t) - 1)
			*p++ = '.';
	}
	printk(KERN_INFO "connect to IPv4 address %s:%d\n", address,
	       ntohs(name->dname.sname_port));
	err = sock_create_kern(PF_INET, SOCK_STREAM, 0, &name->ipv4_sock);
	if (err)
		goto out;
	name->ipv4_sock->sk->sk_user_data = name;
	name->ipv4_sock->sk->sk_state_change = name_stream_state_change;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = name->dname.sname_port;
	sin.sin_addr.s_addr = *(uint32_t *)rdata;
	err = kernel_connect(name->ipv4_sock, (struct sockaddr *)&sin,
			     sizeof(sin), O_NONBLOCK);
	/* The expected error is EINPROGRESS, as the socket connection kicks
	 * off.  Return success in this case.
	 */
	if (err == -EINPROGRESS)
		err = 0;
out:
	return err;
}

static void name_stream_connect_to_resolved_name(struct sock *sk)
{
	struct name_stream_sock *name = name_stream_sk(sk);
	uint16_t rdlength;
	const u_char *rdata;
	int err;

	if (!find_answer_of_type(name->dname_answer, name->dname_answer_len,
				 T_CNAME, 0, &rdlength, &rdata)) {
		char *fqdn = rfc1035_decode_name(rdata, rdlength);

		/* The response contains a CNAME.  Use this as the destination
		 * name, rather than name the application provided.
		 */
		if (fqdn) {
			printk(KERN_INFO "connecting to %s\n", fqdn);
			strcpy(name->dname.sname_addr.name, fqdn);
			kfree(fqdn);
		}
	}
	if (!find_answer_of_type(name->dname_answer, name->dname_answer_len,
				 T_AAAA, name->dname_answer_index, &rdlength,
				 &rdata)) {
		err = name_stream_connect_to_v6_address(sk, rdlength,
							    rdata);
		if (err) {
			/* FIXME: get next address rather than closing the
			 * connection request.
			 */
			sk->sk_state = TCP_CLOSE;
			sk->sk_state_change(sk);
		}
	}
	else if (!find_answer_of_type(name->dname_answer,
				      name->dname_answer_len,
				      T_A, name->dname_answer_index, &rdlength,
				      &rdata)) {
		err = name_stream_connect_to_v4_address(sk, rdlength,
							    rdata);
		if (err) {
			/* FIXME: get next address rather than closing the
			 * connection request.
			 */
			sk->sk_state = TCP_CLOSE;
			sk->sk_state_change(sk);
		}
	}
	else {
		printk(KERN_WARNING "no supported address type found\n");
		sk->sk_state = TCP_CLOSE;
		sk->sk_state_change(sk);
		err = -EHOSTUNREACH;
	}
	name->async_error = err;
}

static void name_stream_query_resolve(const u_char *response, int len,
				      void *data)
{
	struct socket *sock = data;
	struct sock *sk = sock->sk;

	if (len > 0)
	{
		struct name_stream_sock *name = name_stream_sk(sk);

		name->dname_answer = kmalloc(len, GFP_ATOMIC);
		if (!name->dname_answer)
		{
			/* Allocation failure, close request */
			sk->sk_state = TCP_CLOSE;
			sk->sk_state_change(sk);
		}
		else
		{
			name->dname_answer_len = len;
			name->dname_answer_index = 0;
			memcpy(name->dname_answer, response, len);
			sk->sk_state = NAME_CONNECTING;
			sk->sk_state_change(sk);
			name_stream_connect_to_resolved_name(sk);
		}
	}
	else
	{
		/* Name resolution failure, close request */
		sk->sk_state = TCP_CLOSE;
		sk->sk_state_change(sk);
	}
}

static int name_stream_connect(struct socket *sock, struct sockaddr *uaddr,
			       int addr_len, int flags)
{
	struct sockaddr_name *sname = (struct sockaddr_name *)uaddr;
	int err;
	struct sock *sk;
	struct name_stream_sock *name;
	long timeo;

	if (addr_len < sizeof(struct sockaddr_name))
		return -EINVAL;
	if (uaddr->sa_family != AF_NAME)
		return -EAFNOSUPPORT;

	printk(KERN_INFO "name_stream_connect requested to %s:%d\n",
	       sname->sname_addr.name, ntohs(sname->sname_port));

	sk = sock->sk;
	name = name_stream_sk(sk);
	lock_sock(sk);

	switch (sock->state) {
	default:
		err = -EINVAL;
		goto out;
	case SS_CONNECTED:
		err = -EISCONN;
		goto out;
	case SS_CONNECTING:
		err = -EALREADY;
		/* Fall out of switch with err, set for this state */
		break;
	case SS_UNCONNECTED:
		err = -EISCONN;

		sock->state = SS_CONNECTING;
		sk->sk_state = NAME_RESOLVING;
		memcpy(&name->dname, uaddr, addr_len);
		if (name_is_local(name->dname.sname_addr.name)) {
			__u8 loopback[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };
			struct in6_addr in6;

			memcpy(&in6.s6_addr, &loopback, sizeof(in6.s6_addr));
			err = name_stream_connect_to_v6_address(sk, sizeof(in6),
								(const u_char *)&in6);
		}
		else if (name_find_v4_canonical_suffix(
			name->dname.sname_addr.name) != NULL) {
			__be32 v4;

			err = name_parse_canonical_v4(
				name->dname.sname_addr.name, &v4);
			if (!err)
				err = name_stream_connect_to_v4_address(sk,
					sizeof(v4), (const u_char *)&v4);
		}
		else if (name_find_v6_canonical_suffix(
			name->dname.sname_addr.name) != NULL) {
			struct in6_addr in6;

			err = name_parse_canonical_v6(
				name->dname.sname_addr.name, &in6);
			if (!err)
				err = name_stream_connect_to_v6_address(sk,
					sizeof(in6), in6.s6_addr);
		}
		else
			err = name_send_query(sname->sname_addr.name,
					      name_stream_query_resolve, sock);
		if (err)
			goto out;

		/* Just entered SS_CONNECTING state; the only
		 * difference is that return value in non-blocking
		 * case is EINPROGRESS, rather than EALREADY.
		 */
		err = -EINPROGRESS;
		break;
	}

	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	if ((1 << sk->sk_state) & (NAMEF_RESOLVING | NAMEF_CONNECTING)) {
		if (!timeo || !name_wait_for_connect(sk, timeo)) {
			/* err set above */
			goto out;
		}
		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			goto out;
	}

	if ((1 << sk->sk_state) & (TCPF_CLOSE)) {
		sock->state = SOCK_DEAD;
		if (name->async_error)
			err = name->async_error;
		else
			err = -EHOSTUNREACH;
	}
	else {
		sock->state = SS_CONNECTED;
		err = 0;
	}

out:
	release_sock(sk);
	return err;
}

static int name_stream_wait_for_accept(struct socket *sock, long timeo)
{
	struct sock *sk = sock->sk;
	DEFINE_WAIT(wait);

	prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);
	while ((1 << sk->sk_state) & TCPF_LISTEN) {
		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
		if (signal_pending(current) || !timeo)
			break;
		prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);
	}
	finish_wait(sk->sk_sleep, &wait);
	return timeo;
}

static struct sock *name_alloc_stream_socket(struct net *net,
					     struct socket *sock);

static struct socket *create_stream_sock_from_sk(int pf, struct sock *sk)
{
	int err;
	struct socket *sock = NULL;

	err = sock_create_kern(pf, SOCK_STREAM, 0, &sock);
	if (err)
		goto out;
	sock_orphan(sock->sk);
	sock_graft(sk, sock);
out:
	return sock;
}

static int get_name_from_v6_sock(struct sockaddr_name *name,
				 struct socket *sock)
{
	struct sockaddr_in6 addr;
	int err, len = sizeof(addr);

	name->sname_family = AF_NAME;
	/* FIXME: get name from options if they're present */
	/* FIXME: what's the real domain? */
	err = sock->ops->getname(sock, (struct sockaddr *)&addr, &len, 1);
	if (err)
		goto out;
	sprintf(name->sname_addr.name,
		"\\[x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x/128].ip6.arpa",
		addr.sin6_addr.s6_addr[0],
		addr.sin6_addr.s6_addr[1],
		addr.sin6_addr.s6_addr[2],
		addr.sin6_addr.s6_addr[3],
		addr.sin6_addr.s6_addr[4],
		addr.sin6_addr.s6_addr[5],
		addr.sin6_addr.s6_addr[6],
		addr.sin6_addr.s6_addr[7],
		addr.sin6_addr.s6_addr[8],
		addr.sin6_addr.s6_addr[9],
		addr.sin6_addr.s6_addr[10],
		addr.sin6_addr.s6_addr[11],
		addr.sin6_addr.s6_addr[12],
		addr.sin6_addr.s6_addr[13],
		addr.sin6_addr.s6_addr[14],
		addr.sin6_addr.s6_addr[15]);
	name->sname_port = addr.sin6_port;
out:
	return err;
}

static int get_name_from_v4_sock(struct sockaddr_name *name,
				 struct socket *sock)
{
	/* FIXME: what's the real domain? */
	static const char domain[] = ".in-addr.arpa";
	struct sockaddr_in addr;
	int err, len = sizeof(addr);
	char *p;
	const u_char *addrp;

	name->sname_family = AF_NAME;
	/* Create a canonical name for the legacy peer.
	 * FIXME: should I attempt a reverse DNS lookup of the peer address?
	 */
	err = sock->ops->getname(sock, (struct sockaddr *)&addr, &len, 1);
	if (err)
		goto out;
	p = name->sname_addr.name;
	for (addrp = (u_char *)&addr.sin_addr.s_addr +
	     sizeof(addr.sin_addr.s_addr) - 1;
	     addrp - (u_char *)&addr.sin_addr.s_addr >= 0;
	     addrp--)
	{
		int n;

		sprintf(p, "%d%n", *addrp, &n);
		p += n;
		if (addrp > (u_char *)&addr.sin_addr.s_addr)
			*p++ = '.';
	}
	strcat(p, domain);
	name->sname_port = addr.sin_port;
out:
	return err;
}

static int name_stream_accept(struct socket *sock, struct socket *newsock,
			      int flags)
{
	struct sock *sk = sock->sk, *v6_sk, *v4_sk;
	struct sock *new_v6_sk = NULL, *new_v4_sk = NULL, *incoming_sock;
	struct inet_connection_sock *v6_icsk, *v4_icsk;
	struct name_stream_sock *name = name_stream_sk(sk), *new_name;
	int err;

	lock_sock(sk);
	/* This handles accepting connections on two incoming sockets, the IPv6
	 * and the IPv4 socket.  Rather than call kernel_accept on each one,
	 * call each one's sk_prot->accept in non-blocking mode, and wait until
	 * one of them has accepted.
	 * We "know" that each of them has an sk_prot->accept method, because
	 * they are one of AF_INET or AF_INET6 sockets:  see inet_accept, used
	 * by both, in ipv4/af_inet.c.
	 */
	err = -EINVAL;
	if (!name->ipv6_sock || !name->ipv6_sock->sk->sk_prot->accept)
		goto out_err;
	if (!name->ipv4_sock || !name->ipv4_sock->sk->sk_prot->accept)
		goto out_err;

	err = -EAGAIN;
	new_v6_sk = name->ipv6_sock->sk->sk_prot->accept(name->ipv6_sock->sk,
							 O_NONBLOCK, &err);
	if (unlikely(new_v6_sk))
		goto handle_incoming;
	if (err != -EAGAIN)
		goto out_err;
	new_v4_sk = name->ipv4_sock->sk->sk_prot->accept(name->ipv4_sock->sk,
							 O_NONBLOCK, &err);
	if (unlikely(new_v4_sk))
		goto handle_incoming;
	if (err != -EAGAIN)
		goto out_err;

	sk->sk_state = TCP_LISTEN;

	v6_sk = name->ipv6_sock->sk;
	v6_icsk = inet_csk(v6_sk);
	v4_sk = name->ipv4_sock->sk;
	v4_icsk = inet_csk(v4_sk);

	if (reqsk_queue_empty(&v6_icsk->icsk_accept_queue) &&
	    reqsk_queue_empty(&v4_icsk->icsk_accept_queue)) {
		long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);

		err = -EAGAIN;
		if (!timeo)
			goto out_wait_err;
		release_sock(sk);
		err = name_stream_wait_for_accept(sock, timeo);
		if (err)
			goto out_wait_err;
	}
	if (!reqsk_queue_empty(&v6_icsk->icsk_accept_queue))
		new_v6_sk = reqsk_queue_get_child(&v6_icsk->icsk_accept_queue,
						  v6_sk);
	else if (!reqsk_queue_empty(&v4_icsk->icsk_accept_queue))
		new_v4_sk = reqsk_queue_get_child(&v4_icsk->icsk_accept_queue,
						  v4_sk);
	release_sock(sk);

handle_incoming:
	if (new_v4_sk) {
		err = -ENOMEM;
		incoming_sock = name_alloc_stream_socket(&init_net, newsock);
		if (!incoming_sock)
			goto out_err;
		new_name = name_stream_sk(incoming_sock);
		new_name->ipv4_sock = create_stream_sock_from_sk(PF_INET,
								 new_v4_sk);
		if (!new_name->ipv4_sock) {
			sock_put(incoming_sock);
			goto out_err;
		}
		get_name_from_v4_sock(&new_name->dname, new_name->ipv4_sock);
	}
	else {
		const struct inet_sock *inet = inet_sk(new_v6_sk);
		const struct ipv6_pinfo *np = inet6_sk(new_v6_sk);
		const struct in6_addr *saddr = &np->rcv_saddr;
		const __u16 port = inet->dport;
		u32 bucket;
		struct syn_entry *entry, *found = NULL;
		struct hlist_node *node;
		int get_name_from_addr = 1;

		err = -ENOMEM;
		incoming_sock = name_alloc_stream_socket(&init_net, newsock);
		if (!incoming_sock)
			goto out_err;
		new_name = name_stream_sk(incoming_sock);
		new_name->ipv6_sock = create_stream_sock_from_sk(PF_INET6,
								 new_v6_sk);
		if (!new_name->ipv6_sock) {
			sock_put(incoming_sock);
			goto out_err;
		}
		bucket = inet6_sk_ehashfn(new_v6_sk) & (NAME_SYN_BUCKETS - 1);
		printk(KERN_INFO "accepted a connection from port %d, bucket %d\n",
		       port, bucket);
		/* FIXME: lock each bucket rather than the whole table. */
		spin_lock_irq(&name_stream_syn_lock);
		hlist_for_each_entry(entry,
				     node,
				     &name_stream_syns[bucket],
				     entry)
		{
			if (!memcmp(saddr, &entry->peer_addr, sizeof(saddr))
			    && port == entry->peer_port)
			{
				found = entry;
				break;
			}
		}
		if (found)
		{
			strcpy(new_name->dname.sname_addr.name,
			       found->name.name);
			new_name->dname.sname_port = found->peer_port;
			get_name_from_addr = 0;
			hlist_del(&found->entry);
			kfree(found);
		}
		spin_unlock_irq(&name_stream_syn_lock);
		if (get_name_from_addr)
			get_name_from_v6_sock(&new_name->dname,
					      new_name->ipv6_sock);
	}
	memcpy(&new_name->sname, &name->sname, sizeof(name->sname));
	printk(KERN_INFO "connection accepted from %s\n",
	       new_name->dname.sname_addr.name);
	sock_graft(incoming_sock, newsock);
	newsock->state = SS_CONNECTED;
	err = 0;
	release_sock(sk);
	return err;

out_wait_err:
	release_sock(sk);

out_err:
	release_sock(sk);
	return err;
}

static int name_stream_getname(struct socket *sock, struct sockaddr *uaddr,
			       int *uaddr_len, int peer)
{
	struct sock *sk = sock->sk;
	struct name_stream_sock *name = name_stream_sk(sk);
	struct sockaddr_name *sname = (struct sockaddr_name *)uaddr;

	if (peer) {
		if (sock->state != SS_CONNECTED)
			return -ENOTCONN;
		memcpy(sname, &name->dname, sizeof(struct sockaddr_name));
	}
	else {
		memcpy(sname, &name->sname, sizeof(struct sockaddr_name));
	}
	*uaddr_len = sizeof(struct sockaddr_name);
	return 0;
}

static int name_stream_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	struct name_stream_sock *name = name_stream_sk(sk);
	int err = -EINVAL;

	lock_sock(sk);
	if (sock->state != SS_UNCONNECTED)
		goto out;

	/* FIXME: what does it mean to listen on more than one socket?  And
	 * what does backlog mean?
	 */
	if (!name->ipv6_sock) {
		err = name_create_v6_sock(SOCK_STREAM, 0, &name->ipv6_sock,
					  name);
		if (err)
			goto out;
	}
	if (!name->ipv4_sock) {
		err = name_create_v4_sock(SOCK_STREAM, 0, &name->ipv4_sock,
					  name);
		if (err)
			goto out;
	}
	err = kernel_listen(name->ipv6_sock, backlog);
	if (!err)
		err = kernel_listen(name->ipv4_sock, backlog);

out:
	release_sock(sk);
	return err;
}

static int name_stream_sendmsg(struct kiocb *iocb, struct socket *sock,
			       struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;
	struct name_stream_sock *name = name_stream_sk(sk);
	struct socket *connected_sock;

	if (sock->state != SS_CONNECTED)
		return -ENOTCONN;
	if (name->ipv6_sock)
		connected_sock = name->ipv6_sock;
	else if (name->ipv4_sock)
		connected_sock = name->ipv4_sock;
	else
		return -ENOTCONN;
	return connected_sock->ops->sendmsg(iocb, connected_sock, msg, len);
}

static int name_stream_recvmsg(struct kiocb *iocb, struct socket *sock,
			       struct msghdr *msg, size_t len, int flags)
{
	struct sock *sk = sock->sk;
	struct name_stream_sock *name = name_stream_sk(sk);
	struct socket *connected_sock;

	if (sock->state != SS_CONNECTED)
		return -ENOTCONN;
	if (name->ipv6_sock)
		connected_sock = name->ipv6_sock;
	else if (name->ipv4_sock)
		connected_sock = name->ipv4_sock;
	else
		return -ENOTCONN;
	return connected_sock->ops->recvmsg(iocb, connected_sock, msg, len,
					    flags);
}

#ifdef CONFIG_COMPAT
static int name_compat_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	return -ENOIOCTLCMD;
}
#endif

static const struct proto_ops name_stream_ops = {
	.family = PF_NAME,
	.owner = THIS_MODULE,
	.release = name_stream_release,
	.bind = name_stream_bind,
	.connect = name_stream_connect,
	.socketpair = sock_no_socketpair,
	.accept = name_stream_accept,
	.getname = name_stream_getname,
	.poll = sock_no_poll,
	.ioctl = sock_no_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = name_compat_ioctl,
#endif
	.listen = name_stream_listen,
	.shutdown = sock_no_shutdown,
	.setsockopt = sock_no_setsockopt,
	.getsockopt = sock_no_getsockopt,
	.sendmsg = name_stream_sendmsg,
	.recvmsg = name_stream_recvmsg,
	.mmap = sock_no_mmap,
	.sendpage = sock_no_sendpage,
};

static struct proto name_stream_proto = {
	.name = "NAME_STREAM",
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct name_stream_sock),
};

static struct sock *name_alloc_stream_socket(struct net *net,
					     struct socket *sock)
{
	struct sock *sk = sk_alloc(net, AF_NAME, GFP_ATOMIC,
				   &name_stream_proto);
	struct name_stream_sock *name;

	if (!sk)
		goto out;

	sock->ops = &name_stream_ops;
	sock_init_data(sock, sk);

	name = name_stream_sk(sk);
	memset(&name->sname, 0, sizeof(name->sname));
	memset(&name->dname, 0, sizeof(name->dname));
	name->dname_answer = NULL;
	name->dname_answer_len = 0;
	name->dname_answer_index = 0;
	name->async_error = 0;
	name->ipv4_sock = NULL;
	name->ipv6_sock = NULL;
out:
	return sk;
}

static int name_dgram_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (!sk)
		goto out;

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_state_change(sk);

	sock_set_flag(sk, SOCK_DEAD);
	sock->sk = NULL;
	sk_refcnt_debug_release(sk);
	sock_put(sk);
out:
	return 0;
}

static const struct proto_ops name_dgram_ops = {
	.family = PF_NAME,
	.owner = THIS_MODULE,
	.release = name_dgram_release,
	.bind = sock_no_bind,
	.connect = sock_no_connect,
	.socketpair = sock_no_socketpair,
	.accept = sock_no_accept,
	.getname = sock_no_getname,
	.poll = sock_no_poll,
	.ioctl = sock_no_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = name_compat_ioctl,
#endif
	.listen = sock_no_listen,
	.shutdown = sock_no_shutdown,
	.setsockopt = sock_no_setsockopt,
	.getsockopt = sock_no_getsockopt,
	.sendmsg = sock_no_sendmsg,
	.recvmsg = sock_no_recvmsg,
	.mmap = sock_no_mmap,
	.sendpage = sock_no_sendpage,
};

struct name_dgram_sock
{
	struct sock sk;
	struct sockaddr_name sname;
	struct sockaddr_name dname;
};

static struct proto name_dgram_proto = {
	.name = "NAME_DGRAM",
	.owner = THIS_MODULE,
	.obj_size = sizeof(struct name_dgram_sock),
};

static inline struct name_dgram_sock *name_dgram_sk(const struct sock *sk)
{
	return (struct name_dgram_sock *)sk;
}

static struct sock *name_alloc_dgram_socket(struct net *net,
					    struct socket *sock)
{
	struct sock *sk = sk_alloc(net, AF_NAME, GFP_ATOMIC, &name_dgram_proto);
	struct name_dgram_sock *name;

	if (!sk)
		goto out;

	sock->ops = &name_dgram_ops;
	sock_init_data(sock, sk);

	name = name_dgram_sk(sk);
	memset(&name->sname, 0, sizeof(name->sname));
	memset(&name->dname, 0, sizeof(name->dname));
out:
	return sk;
}

static int name_create(struct net *net, struct socket *sock, int protocol)
{
	struct sock *sk;
	int rc;

	if (net != &init_net)
		return -EAFNOSUPPORT;

	rc = 0;
	switch (sock->type)
	{
	case SOCK_STREAM:
		rc = -ENOMEM;
		if ((sk = name_alloc_stream_socket(net, sock)))
			rc = 0;
		break;
	case SOCK_DGRAM:
		rc = -ENOMEM;
		if ((sk = name_alloc_dgram_socket(net, sock)))
			rc = 0;
		break;
	default:
		rc = -EPROTONOSUPPORT;
	}

	return rc;
}

static struct net_proto_family name_family_ops = {
	.family = PF_NAME,
	.create = name_create,
	.owner = THIS_MODULE,
};

int name_af_init(void)
{
	int rc;

	rc = proto_register(&name_stream_proto, 1);
	if (rc)
		goto out;

	rc = proto_register(&name_dgram_proto, 1);
	if (rc)
		goto out;

	rc = sock_register(&name_family_ops);
out:
	return rc;
}

void name_af_exit(void)
{
	int i;

	proto_unregister(&name_stream_proto);
	proto_unregister(&name_dgram_proto);
	sock_unregister(name_family_ops.family);
	for (i = 0; i < NAME_SYN_BUCKETS; i++)
	{
		struct syn_entry *entry;
		struct hlist_node *node, *next;

		hlist_for_each_entry_safe(entry,
					  node,
					  next,
					  &name_stream_syns[i],
					  entry)
		{
			hlist_del(node);
			kfree(entry);
		}
	}
}

EXPORT_SYMBOL(name_af_init);
EXPORT_SYMBOL(name_af_exit);
