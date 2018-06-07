#include <linux/types.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/inname.h>
#include "namestack_priv.h"

struct name_sock_list
{
	struct list_head entry;
	struct socket *sock;
};

static u32 name_cache_shift;
#define name_cache_size (1 << name_cache_shift)
static struct name_sock_list *name_cache;
static DEFINE_SPINLOCK(name_cache_lock);

static inline void lock_name_cache(void)
{
	spin_lock(&name_cache_lock);
}

static inline void unlock_name_cache(void)
{
	spin_unlock(&name_cache_lock);
}

int name_cache_init(void)
{
	int err;

	name_cache_shift = 4;
	name_cache = kmalloc(name_cache_size * sizeof(struct name_sock_list),
			     GFP_ATOMIC);
	if (name_cache) {
		int i;

		for (i = 0; i < name_cache_size; i++) {
			INIT_LIST_HEAD(&name_cache[i].entry);
			name_cache[i].sock = NULL;
		}
		err = 0;
	}
	else {
		/* defensive line to protect against a broken caller */
		name_cache_shift = 0;
		err = -ENOMEM;
	}
	return err;
}

static inline u32 name_hash(const char *name)
{
	return jhash(name, strlen(name), 0) & (name_cache_size - 1);
}

static struct name_sock_list *__name_cache_find(const char *name, u32 bucket)
{
	struct name_sock_list *ptr;

	list_for_each_entry(ptr, &name_cache[bucket].entry, entry) {
		struct sock *sk = ptr->sock->sk;
		struct name_stream_sock *name_sk = name_stream_sk(sk);

		if (!strcmp(name_sk->sname.sname_addr.name, name))
			return ptr;
	}
	return NULL;
}

int name_cache_add(const char *name, struct socket *sock)
{
	int err;
	u32 bucket = name_hash(name);
	struct name_sock_list *ptr;

	lock_name_cache();
	ptr = __name_cache_find(name, bucket);
	if (ptr) {
		err = -EALREADY;
		goto out;
	}
	ptr = kmalloc(sizeof(struct name_sock_list), GFP_ATOMIC);
	if (!ptr) {
		err = -ENOMEM;
		goto out;
	}
	ptr->sock = sock;
	INIT_LIST_HEAD(&ptr->entry);
	list_add_tail(&name_cache[bucket].entry, &ptr->entry);
	err = 0;
out:
	unlock_name_cache();
	return err;
}

void name_cache_delete(const char *name)
{
	u32 bucket = name_hash(name);
	struct name_sock_list *ptr;

	lock_name_cache();
	ptr = __name_cache_find(name, bucket);
	if (ptr) {
		list_del(&ptr->entry);
		kfree(ptr);
	}
	unlock_name_cache();
}

void name_cache_free(void)
{
	int i;

	for (i = 0; i < name_cache_size; i++) {
		struct name_sock_list *itr, *next;

		list_for_each_entry_safe(itr, next, &name_cache[i].entry,
					 entry) {
			list_del(&itr->entry);
			kfree(itr);
		}
	}
	kfree(name_cache);
}
