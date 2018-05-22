#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xd76291be, "struct_module" },
	{ 0x5c8b5f8a, "release_sock" },
	{ 0xc9c55f8e, "per_cpu__current_task" },
	{ 0x31d24d3b, "kmalloc_caches" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0x44ea7bd, "sock_init_data" },
	{ 0x608c2831, "warn_on_slowpath" },
	{ 0x60400b7f, "pv_lock_ops" },
	{ 0x349cba85, "strchr" },
	{ 0xd42b7232, "_write_unlock_bh" },
	{ 0xd0d8621b, "strlen" },
	{ 0x1a75caa3, "_read_lock" },
	{ 0x4100f34e, "sock_no_setsockopt" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0xb992cb9c, "sock_no_getsockopt" },
	{ 0xfb7f6b3b, "sock_no_ioctl" },
	{ 0xd95a1be7, "sock_release" },
	{ 0x7e73bd98, "dst_release" },
	{ 0x973873ab, "_spin_lock" },
	{ 0x75c24363, "sock_no_getname" },
	{ 0x5d59da1f, "sock_create_kern" },
	{ 0x577cc638, "mutex_unlock" },
	{ 0xa9501966, "kernel_listen" },
	{ 0x3c2c5af5, "sprintf" },
	{ 0x3176b90a, "sock_no_poll" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x359daffb, "sock_no_sendpage" },
	{ 0x5c3c5415, "sock_no_mmap" },
	{ 0xe32298f8, "sock_no_recvmsg" },
	{ 0xb360c848, "kernel_setsockopt" },
	{ 0x661d32b2, "netlink_kernel_create" },
	{ 0xc7deb1bb, "sock_no_socketpair" },
	{ 0x76859ae, "kernel_connect" },
	{ 0x583c5b17, "sk_alloc" },
	{ 0x8d3894f2, "_ctype" },
	{ 0xa2a1e5c9, "_write_lock_bh" },
	{ 0xb72397d5, "printk" },
	{ 0x23b81f81, "sock_no_bind" },
	{ 0x42224298, "sscanf" },
	{ 0xecde1418, "_spin_lock_irq" },
	{ 0x7d215dfa, "lock_sock_nested" },
	{ 0x2fcfcea2, "netlink_kernel_release" },
	{ 0xaafdc258, "strcasecmp" },
	{ 0x62249269, "sock_no_listen" },
	{ 0x3d73892b, "kmem_cache_free" },
	{ 0x8aaf8654, "mutex_lock" },
	{ 0x31bcd8d4, "sock_no_accept" },
	{ 0xf18bf4de, "kernel_sock_shutdown" },
	{ 0x224fd5b7, "sk_free" },
	{ 0xd2d60909, "netlink_unicast" },
	{ 0xf20241d0, "skb_pull" },
	{ 0x62907de9, "init_net" },
	{ 0xe49defe3, "sock_kfree_s" },
	{ 0xfca14ef5, "sock_no_shutdown" },
	{ 0x61651be, "strcat" },
	{ 0x146659e6, "proto_register" },
	{ 0x9d258f, "_write_lock" },
	{ 0xc0a38b5d, "kmem_cache_alloc" },
	{ 0xed633abc, "pv_irq_ops" },
	{ 0x74eec3c0, "__alloc_skb" },
	{ 0xa5e7a426, "sock_register" },
	{ 0xd62c833f, "schedule_timeout" },
	{ 0x591f038e, "proto_unregister" },
	{ 0xb6bf9d13, "sock_kmalloc" },
	{ 0x81a2fcd4, "sock_no_connect" },
	{ 0x37a0cba, "kfree" },
	{ 0x33d92f9a, "prepare_to_wait" },
	{ 0x62737e1d, "sock_unregister" },
	{ 0x46c21e19, "sock_no_sendmsg" },
	{ 0xa48fe94b, "kernel_bind" },
	{ 0x9ccb2622, "finish_wait" },
	{ 0xa2a5fd77, "inet_ehash_secret" },
	{ 0x5aec188e, "skb_put" },
	{ 0xe914e41e, "strcpy" },
	{ 0xda10ec3, "security_sock_graft" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "6DEA2A3375FFAFE7C8DE9A4");
