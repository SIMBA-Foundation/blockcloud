#include <sys/types.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/inname.h>
#ifndef AF_NAME
/* WARNING:  this is kernel-version specific.  Kernel version 2.6.27 has
 * AF_ISDN = 34, AF_MAX = 35.  Kernel version 2.6.28 has AF_PHONET = 35,
 * AF_MAX = 36.  My own modified kernel version 2.6.27 has AF_NAME = 36 (and
 * AF_MAX = 36.)
 */
#define AF_NAME 35
#endif
#ifndef PF_NAME
#define PF_NAME AF_NAME
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [-p port] name\n", progname);
	exit(1);
}

static int validate_name(const char *name, struct sockaddr_name *addr)
{
	int ret = 0;
	char *colon;

	addr->sname_family = AF_NAME;
	if ((colon = strchr(name, ':')))
	{
		if (colon - name < sizeof(addr->sname_addr.name))
		{
			memcpy(addr->sname_addr.name, name, colon - name);
			addr->sname_addr.name[colon - name] = 0;
			if (*(colon + 1))
				addr->sname_port = htons(atoi(colon + 1));
			else
				addr->sname_port = 0;
			ret = 1;
		}
	}
	else if (strlen(name) < sizeof(addr->sname_addr.name))
	{
		strcpy(addr->sname_addr.name, name);
		addr->sname_port = 0;
		ret = 1;
	}
	return ret;
}

static void do_accept_loop(int fd)
{
	while (1)
	{
		struct sockaddr_name peer_addr;
		socklen_t len = sizeof(peer_addr);
		int client_fd;

		client_fd = accept(fd, (struct sockaddr *)&peer_addr, &len);
		if (client_fd < 0)
			perror("accept");
		else
		{
			static const char hello[] = "hello";
			int ret;

			/* For now this only handles one client at a time,
			 * which is reasonable for such a simple protocol.
			 * A more complex (longer-running) protocol should
			 * probably get its own process/thread.
			 */
			printf("connection accepted from %s\n",
			       peer_addr.sname_addr.name);
			ret = write(client_fd, hello, sizeof(hello));
			if (ret < 0)
				perror("write");
			else
			{
				char buf[100];

				printf("wrote hello message\n");
				ret = read(client_fd, buf, sizeof(buf));
				if (ret < 0)
					perror("read");
				else
					printf("got a reply: %s\n", buf);
			}
			close(client_fd);
		}
	}
}

int main(int argc, const char *argv[])
{
	const char *name;
	struct sockaddr_name addr;
	int domain, type, protocol;
	short port = 0;
	int fd;

	/* Look for options */
	if (argc > 1)
	{
		int i;

		for (i = 1; i < argc; i++)
		{
			if ((*argv[i] == '-' || *argv[i] == '/') &&
			   (argv[i][1] == 'p' || argv[i][1] == 'P') &&
			   i < argc - 1)
			{
				port = atoi(argv[i + 1]);
				if (argc - i > 2)
					memmove(argv + i, argv + i + 2,
						(argc - i - 2) * sizeof(char *));
				argc -= 2;
			}
		}
	}
	/* Now that options are removed, look for name arguments */
	if (argc > 1)
	{
		if (!validate_name(argv[1], &addr))
		{
			fprintf(stderr, "name too long\n");
			usage(argv[0]);
		}
	}
	else
		usage(argv[0]);
	domain = PF_NAME;
	type = SOCK_STREAM;
	protocol = 0;
	printf("creating a socket with domain = %d, type = %d, protocol = %d\n",
		domain, type, protocol);
	fd = socket(domain, type, protocol);
	if (fd >= 0)
	{
		int ret;

		printf("got a socket!\n");
		if (port)
			addr.sname_port = htons(port);
		printf("binding to %s:%d\n", addr.sname_addr.name,
		       ntohs(addr.sname_port));
		ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
		if (ret < 0)
			perror("bind");
		else
		{
			printf("bind succeeded!\n");
			ret = listen(fd, 0);
			if (ret < 0)
				perror("listen");
			else
				do_accept_loop(fd);
		}
		close(fd);
	}
	else
	{
		perror("socket");
		fprintf(stderr, "errno = %d\n", errno);
	}
	return 0;
}
