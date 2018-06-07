#include <linux/kernel.h>
#include <linux/module.h>  
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/net_namespace.h>
#include <net/if_inet6.h>

static void print_ip4addr(const __be32 *addr)
{
	char address[16], *p;
	const u_char *addrp;

	p = address;
	for (addrp = (u_char *)addr;
	     addrp - (u_char *)addr < sizeof(__be32);
	     addrp++)
	{
		int n;

		sprintf(p, "%d%n", *addrp, &n);
		p += n;
		if (addrp < (u_char *)addr + sizeof(__be32) - 1)
			*p++ = '.';
	}
	printk(KERN_INFO "IPv4 address %s\n", address);
}

static void print_ip6addr(const struct in6_addr *addr)
{
	char address[46], *p;
	int i, in_zero = 0;

	p = address;
	for (i = 0; i < 7; i++)
	{
		if (!addr->s6_addr16[i])
		{
			if (i == 0)
				*p++ = ':';
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
	printk(KERN_INFO "IPv6 address %s\n", address);
}

/* FIXME: this should use some heuristic to determine a preferred
 * interface/address.  For now, it simply chooses the first up, non-loopback
 * address as the "best".
 * It also should determine a public/reachable address for an interface.
 */
int choose_addresses(int *num_v6_addresses, struct in6_addr **v6_addresses,
		     int *num_v4_addresses, __be32 **v4_addresses)
{
	struct net *net = &init_net;
	struct net_device *dev;
	int n_v6_addresses = 0;
	int n_v4_addresses = 0;
	struct in6_addr *pv6;
	__be32 *pv4;
	int err;

	/* FIXME: lock net? */
	for_each_netdev(net, dev) {
		if (!(dev->flags & IFF_UP))
			continue;
		if (dev->flags & IFF_LOOPBACK)
			continue;
		if (dev->ip6_ptr) {
			struct inet6_dev *in6 = dev->ip6_ptr;
			struct inet6_ifaddr *addr;

			for (addr = in6->addr_list; addr; addr = addr->if_next)
				n_v6_addresses++;
		}
		if (dev->ip_ptr) {
			struct in_device *in4 = dev->ip_ptr;
			struct in_ifaddr *addr;

			for (addr = in4->ifa_list; addr; addr = addr->ifa_next)
				n_v4_addresses++;
		}
	}
	err = -ENOMEM;
	if (n_v6_addresses) {
		*v6_addresses = kmalloc(n_v6_addresses *
					sizeof(struct inet6_ifaddr),
					GFP_ATOMIC);
		if (!*v6_addresses)
			goto out;
		else
			*num_v6_addresses = n_v6_addresses;
	}
	else {
		*v6_addresses = NULL;
		*num_v6_addresses = 0;
	}
	if (n_v4_addresses) {
		*v4_addresses = kmalloc(n_v4_addresses *
					sizeof(struct in_ifaddr),
					GFP_ATOMIC);
		if (!*v4_addresses) {
			kfree(*v6_addresses);
			goto out;
		}
		else
			*num_v4_addresses = n_v4_addresses;
	}
	else {
		*v4_addresses = NULL;
		*num_v4_addresses = 0;
	}
	err = 0;
	pv6 = *v6_addresses;
	pv4 = *v4_addresses;
	for_each_netdev(net, dev) {
		if (!(dev->flags & IFF_UP))
			continue;
		if (dev->flags & IFF_LOOPBACK)
			continue;
		printk(KERN_INFO "adding addresses from %s\n", dev->name);
		if (dev->ip6_ptr) {
			struct inet6_dev *in6 = dev->ip6_ptr;
			struct inet6_ifaddr *addr;

			for (addr = in6->addr_list; addr;
			     addr = addr->if_next) {
				print_ip6addr(&addr->addr);
				*pv6 = addr->addr;
				pv6++;
			}
		}
		if (dev->ip_ptr) {
			struct in_device *in4 = dev->ip_ptr;
			struct in_ifaddr *addr;

			for (addr = in4->ifa_list; addr;
			     addr = addr->ifa_next) {
				print_ip4addr(&addr->ifa_address);
				*pv4 = addr->ifa_address;
				pv4++;
			}
		}
	}
out:
	return err;
}

int match_v6_address_to_scope(struct sockaddr_in6 *sin6)
{
	struct net *net = &init_net;
	struct net_device *dev;

	/* FIXME: lock net? */
	for_each_netdev(net, dev) {
		if (!(dev->flags & IFF_UP))
			continue;
		if (dev->flags & IFF_LOOPBACK)
			continue;
		if (dev->ip6_ptr) {
			struct inet6_dev *in6 = dev->ip6_ptr;
			struct inet6_ifaddr *addr;

			for (addr = in6->addr_list; addr; addr = addr->if_next)
				if (!memcmp(&addr->addr,
				    sin6->sin6_addr.s6_addr,
				    sizeof(addr->addr)))
				{
					sin6->sin6_scope_id = dev->ifindex;
					return 0;
				}
		}
	}
	return -ENODEV;
}

int choose_scope_for_v6_address(struct sockaddr_in6 *sin6)
{
	/* FIXME: for now, always picks the first interface with an IPv6
	 * address, or the first up interface if that fails.  Should instead:
	 * 1. Use the source name's scope ID, if the socket is bound to a local
	 *    name and the local name is a link-local address.
	 * 2. Allow choosing among multiple possible interfaces.
	 */
	struct net *net = &init_net;
	struct net_device *dev;

	/* FIXME: lock net? */
	for_each_netdev(net, dev) {
		if (!(dev->flags & IFF_UP))
			continue;
		if (dev->flags & IFF_LOOPBACK)
			continue;
		if (dev->ip6_ptr) {
			struct inet6_dev *in6 = dev->ip6_ptr;
			struct inet6_ifaddr *addr;

			for (addr = in6->addr_list; addr; addr = addr->if_next) {
				printk(KERN_INFO "using scope id %d for %s\n",
				       dev->ifindex, dev->name);
				sin6->sin6_scope_id = dev->ifindex;
				return 0;
			}
		}
	}
	/* If no IPv6 address was configured, hope for the best with the first
	 * up interface.
	 */
	for_each_netdev(net, dev) {
		if (!(dev->flags & IFF_UP))
			continue;
		if (dev->flags & IFF_LOOPBACK)
			continue;
		printk(KERN_INFO "using scope id %d for %s\n",
		       dev->ifindex, dev->name);
		sin6->sin6_scope_id = dev->ifindex;
		return 0;
	}
	/* No interface, that'll definitely fail */
	return -ENODEV;
}
