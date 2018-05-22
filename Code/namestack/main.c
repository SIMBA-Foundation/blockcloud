#include <linux/kernel.h>
#include <linux/module.h>  
#include <net/sock.h>
#include <linux/netlink.h>
#include <net/net_namespace.h>
#include "namestacknl.h"
#include "namestack_priv.h"

static DEFINE_MUTEX(nos_mutex);
static struct sock *nls = NULL;
static int daemon_pid;
static atomic_t req_id = ATOMIC_INIT(0);

struct pending_node
{
	atomic_t ref;
	__u32 seq;
	void *cb;
	void *data;
	struct pending_node *next;
};

static DEFINE_SPINLOCK(pending_queue_lock);
static struct pending_node *pending_queue = NULL;

static inline void lock_pending_queue(void)
{
	spin_lock(&pending_queue_lock);
}

static inline void unlock_pending_queue(void)
{
	spin_unlock(&pending_queue_lock);
}

/* Logically inserts a new node into the pending queue.  Must *not* be called
 * from an interrupt handler.
 * Literally it instead looks for a node with a reference count of 0 first, and
 * reclaims it if it finds one.  Otherwise it allocates a new node to insert
 * into the pending queue.  This mechanism allows pending_queue_find_and_remove
 * to avoid taking the queue lock, which is important since it's called from
 * an irq handler.
 */
static int pending_queue_push(struct sk_buff *sk, __u32 seq,
			      void *cb, void *data)
{
	struct pending_node *ptr, *node = NULL;
	int err = -ENOMEM, insert = 0;

	printk(KERN_INFO "pending queue is %p\n", pending_queue);
	lock_pending_queue();
	for (ptr = pending_queue, node = NULL; ptr && !node; ptr = ptr->next)
		if (ptr->ref.counter == 0)
		{
			/* Found a node that needs to be freed, claim it */
			ptr->ref.counter = 1;
			node = ptr;
		}
	unlock_pending_queue();
	if (!node)
	{
		node = kmalloc(sizeof(struct pending_node), GFP_ATOMIC);
		if (node)
		{
			node->ref.counter = 1;
			insert = 1;
		}
	}
	if (node)
	{
		err = 0;
		node->seq = seq;
		node->cb = cb;
		node->data = data;
		if (insert)
		{
			lock_pending_queue();
			node->next = pending_queue;
			pending_queue = node;
			unlock_pending_queue();
		}
	}
	return err;
}

static struct pending_node *pending_queue_find_and_remove(__u32 seq)
{
	struct pending_node *node = NULL;

	for (node = pending_queue; node; node = node->next)
		if (atomic_read(&node->ref) && node->seq == seq)
			break;
	if (node)
	{
		/* "Free" the node by decrementing its reference counter.
		 * It'll actually get freed later, in pending_queue_free.
		 */
		atomic_dec(&node->ref);
	}
	return node;
}

/* Frees any memory allocated by the pending node queue. */
static void pending_queue_free(void)
{
	struct pending_node *ptr;

	for (ptr = pending_queue; ptr; )
	{
		struct pending_node *next = ptr->next;

		kfree(ptr);
		ptr = next;
	}
}

static int
namestack_send_message(int pid, int type, const void *payload, int size)
{
	struct sk_buff *skb;
	int len = NLMSG_SPACE(size);
	struct nlmsghdr *nlh;

	skb = alloc_skb(len, GFP_ATOMIC);
	if (!skb) {
		printk(KERN_ERR "Could not allocate skb to send message\n");
		return -ENOMEM;
	}
	nlh = __nlmsg_put(skb, pid, 0, type, (len - sizeof(*nlh)), 0);
	nlh->nlmsg_flags = 0;
	memcpy(NLMSG_DATA(nlh), payload, size);
	return netlink_unicast(nls, skb, pid, MSG_DONTWAIT);
}

static int
handle_register(const struct sk_buff *skb, const struct nlmsghdr *nlh)
{
	printk("received register message from user %d, process %d\n",
		NETLINK_CREDS(skb)->uid,
		NETLINK_CREDS(skb)->pid);
	/* FIXME: should check whether user is root first.  Not doing for now
	 * to simplify testing.
	 */
	daemon_pid = NETLINK_CREDS(skb)->pid;
	return namestack_send_message(daemon_pid, NAME_STACK_REGISTER, NULL, 0);
}

static int
handle_name_reply(const struct sk_buff *skb, const struct nlmsghdr *nlh)
{
	struct pending_node *node;

	printk("received reply message from user %d, process %d\n",
		NETLINK_CREDS(skb)->uid,
		NETLINK_CREDS(skb)->pid);
	node = pending_queue_find_and_remove(nlh->nlmsg_seq);
	if (node)
	{
		int len;

		printk(KERN_INFO "found reply on pending queue\n");
		if (NLMSG_PAYLOAD(nlh, 0) >= sizeof(len))
		{
			memcpy(&len, NLMSG_DATA(nlh), sizeof(len));
			printk(KERN_INFO "len is %d\n", len);
			if (NLMSG_PAYLOAD(nlh, 0) >= len + sizeof(len))
			{
				query_resolv_cb cb = node->cb;

				cb(NLMSG_DATA(nlh) + sizeof(len), len,
				   node->data);
			}
			else
				printk(KERN_WARNING
				       "invalid payload length in reply\n");
		}
		else
			printk(KERN_WARNING
			       "invalid payload length in reply\n");
	}
	else
		printk(KERN_WARNING "reply for unknown request\n");
	/* Send an empty REPLY as an ack */
	return namestack_send_message(NETLINK_CREDS(skb)->pid,
		NAME_STACK_NAME_REPLY, NULL, 0);
}

#define MAX_NAME_LEN 256

static int
handle_register_reply(const struct sk_buff *skb, const struct nlmsghdr *nlh)
{
	struct pending_node *node;

	printk("received reply message from user %d, process %d\n",
		NETLINK_CREDS(skb)->uid,
		NETLINK_CREDS(skb)->pid);
	node = pending_queue_find_and_remove(nlh->nlmsg_seq);
	if (node)
	{
		int result;

		printk(KERN_INFO "found reply on pending queue\n");
		if (NLMSG_PAYLOAD(nlh, 0) >= sizeof(result))
		{
			int name_len;
			char name_buf[MAX_NAME_LEN];
			register_cb cb = node->cb;

			memcpy(&result, NLMSG_DATA(nlh), sizeof(result));
			memcpy(&name_len, NLMSG_DATA(nlh) + sizeof(int),
			       sizeof(int));
			if (name_len)
				memcpy(name_buf,
				       NLMSG_DATA(nlh) + 2 * sizeof(int),
				       name_len);
			name_buf[name_len] = 0;
			printk(KERN_INFO "result is %d\n", result);
			cb(result, name_buf, node->data);
		}
		else
			printk(KERN_WARNING
			       "invalid payload length in reply\n");
	}
	else
		printk(KERN_WARNING "reply for unknown request\n");
	/* Send an empty REPLY as an ack */
	return namestack_send_message(NETLINK_CREDS(skb)->pid,
		NAME_STACK_NAME_REPLY, NULL, 0);
}

static int
handle_qualify_reply(const struct sk_buff *skb, const struct nlmsghdr *nlh)
{
	struct pending_node *node;

	printk("received qualify reply message from user %d, process %d\n",
		NETLINK_CREDS(skb)->uid,
		NETLINK_CREDS(skb)->pid);
	node = pending_queue_find_and_remove(nlh->nlmsg_seq);
	if (node)
	{
		printk(KERN_INFO "found reply on pending queue\n");
		if (NLMSG_PAYLOAD(nlh, 0) >= sizeof(int))
		{
			int name_len;
			char name_buf[MAX_NAME_LEN];
			qualify_cb cb = node->cb;

			memcpy(&name_len, NLMSG_DATA(nlh), sizeof(int));
			if (name_len)
				memcpy(name_buf, NLMSG_DATA(nlh) + sizeof(int),
				       name_len);
			name_buf[name_len] = 0;
			cb(name_buf, node->data);
		}
		else
			printk(KERN_WARNING
			       "invalid payload length in reply\n");
	}
	else
		printk(KERN_WARNING "reply for unknown request\n");
	/* Send an empty REPLY as an ack */
	return namestack_send_message(NETLINK_CREDS(skb)->pid,
		NAME_STACK_QUALIFY_REPLY, NULL, 0);
}

static int
nos_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int err = 0;

	printk(KERN_INFO "got message type %d\n", nlh->nlmsg_type);
	switch (nlh->nlmsg_type) {
	case NAME_STACK_REGISTER:
		err = handle_register(skb, nlh);
		break;
	case NAME_STACK_NAME_REPLY:
		err = handle_name_reply(skb, nlh);
		break;
	case NAME_STACK_REGISTER_REPLY:
		err = handle_register_reply(skb, nlh);
		break;
	case NAME_STACK_QUALIFY_REPLY:
		err = handle_qualify_reply(skb, nlh);
		break;
	default:
		err = -ENOSYS;
	}

	return err;
}

static void
nos_rcv_skb(struct sk_buff *skb)
{
	mutex_lock(&nos_mutex);
	while (skb->len >= NLMSG_SPACE(0)) {
		int err;
		uint32_t rlen;
		struct nlmsghdr *nlh;

		nlh = nlmsg_hdr(skb);
		if (nlh->nlmsg_len < sizeof(*nlh) || skb->len < nlh->nlmsg_len)
			break;

		rlen = NLMSG_ALIGN(nlh->nlmsg_len);
		if (rlen > skb->len)
			rlen = skb->len;

		err = nos_rcv_msg(skb, nlh);
		skb_pull(skb, rlen);
	}
	mutex_unlock(&nos_mutex);
}

static __init int namestack_init(void)
{
	int rc;

	printk(KERN_INFO "name-oriented stack module loading\n");

	nls = netlink_kernel_create(&init_net, NETLINK_NAME_ORIENTED_STACK,
		0, nos_rcv_skb, NULL, THIS_MODULE);
	if (!nls) {
		printk(KERN_ERR "namestackmod: failed to create netlink socket\n");
		return -ENOMEM;
	}
	rc = name_af_init();
	if (!rc)
		rc = name_cache_init();
	return rc;
}

static void __exit namestack_exit(void)
{
	name_cache_free();
	name_af_exit();
	netlink_kernel_release(nls);
	/* Only after no new requests can be received is it safe to free the
	 * pending request queue.
	 */
	pending_queue_free();
	printk(KERN_INFO "name-oriented stack module unloading\n");
}

static int
namestack_send_message_tracked(int pid, int type, const void *payload, int size,
			       void *cb, void *data)
{
	struct sk_buff *skb;
	int len = NLMSG_SPACE(size), seq, err;
	struct nlmsghdr *nlh;

	skb = alloc_skb(len, GFP_ATOMIC);
	if (!skb) {
		printk(KERN_ERR "Could not allocate skb to send message\n");
		return -ENOMEM;
	}
	seq = atomic_inc_return(&req_id);
	nlh = __nlmsg_put(skb, pid, seq, type, (len - sizeof(*nlh)), 0);
	nlh->nlmsg_flags = 0;
	memcpy(NLMSG_DATA(nlh), payload, size);
	err = pending_queue_push(skb, seq, cb, data);
	if (err) {
		printk(KERN_ERR "Allocation failure, can't send message\n");
		goto out;
	}
	err = netlink_unicast(nls, skb, pid, MSG_DONTWAIT);
	if (err > 0) {
		/* A positive return value indicates how many bytes were sent
		 * successfully, which is equivalent to success since sends
		 * aren't fragmented in any way.
		 */
		err = 0;
	}
out:
	return err;
}

int name_send_query(const char *name, query_resolv_cb cb, void *data)
{
	int err;

	if (!daemon_pid) {
		printk(KERN_WARNING "no resolver daemon, unable to send query\n");
		err = -ENOSYS;
	}
	else {
		printk(KERN_INFO "resolving %s\n", name);
		/* FIXME:  who handles retrying in case of failure? */
		err = namestack_send_message_tracked(daemon_pid,
						     NAME_STACK_NAME_QUERY,
						     name, strlen(name) + 1,
						     cb, data);
	}
	return err;
}

int name_fully_qualify(const char *name, qualify_cb cb, void *data)
{
	int err;

	if (!daemon_pid) {
		printk(KERN_WARNING "no resolver daemon, unable to send query\n");
		err = -ENOSYS;
	}
	else {
		printk(KERN_INFO "qualifying %s\n", name);
		/* FIXME:  who handles retrying in case of failure? */
		err = namestack_send_message_tracked(daemon_pid,
						     NAME_STACK_QUALIFY_QUERY,
						     name, strlen(name) + 1,
						     cb, data);
	}
	return err;
}

int name_send_registration(const char *name,
			   const struct in6_addr *v6_addresses,
			   int num_v6_addresses,
			   const __be32 *v4_addresses,
			   int num_v4_addresses,
			   register_cb cb, void *data)
{
	int err;

	if (!daemon_pid) {
		printk(KERN_WARNING "no resolver daemon, unable to send query\n");
		err = -ENOSYS;
	}
	else {
		char *payload, *ptr;
		size_t name_len, len;

		printk(KERN_INFO "registering %s\n", name);
		name_len = strlen(name) + 1;
		len = name_len;
		len += sizeof(int) + num_v6_addresses * sizeof(struct in6_addr);
		len += sizeof(int) + num_v4_addresses * sizeof(__be32);
		err = -ENOMEM;
		payload = kmalloc(len, GFP_ATOMIC);
		if (!payload)
			goto out;
		ptr = payload;
		memcpy(ptr, name, name_len);
		ptr += name_len;
		memcpy(ptr, &num_v6_addresses, sizeof(int));
		ptr += sizeof(int);
		memcpy(ptr, v6_addresses,
		       num_v6_addresses * sizeof(struct in6_addr));
		ptr += num_v6_addresses * sizeof(struct in6_addr);
		memcpy(ptr, &num_v4_addresses, sizeof(int));
		ptr += sizeof(int);
		memcpy(ptr, v4_addresses, num_v4_addresses * sizeof(__be32));
		/* FIXME:  who handles retrying in case of failure? */
		err = namestack_send_message_tracked(daemon_pid,
						     NAME_STACK_REGISTER_QUERY,
						     payload, len,
						     cb, data);
		kfree(payload);
	}
out:
	return err;
}

void name_delete_registration(const char *name)
{
	int err;

	if (!daemon_pid) {
		printk(KERN_WARNING "no resolver daemon, unable to send query\n");
		err = -ENOSYS;
	}
	else {
		printk(KERN_INFO "deleting registered name %s\n", name);
		/* FIXME:  who handles retrying in case of failure? */
		err = namestack_send_message(daemon_pid,
					     NAME_STACK_REGISTER_DELETE,
					     name, strlen(name) + 1);
	}
}

module_init(namestack_init);
module_exit(namestack_exit);
