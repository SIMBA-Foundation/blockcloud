#include <assert.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/inname.h>
#ifndef AF_NAME
/* WARNING:  this is kernel-version specific.  Kernel version 2.6.27 has
 * AF_ISDN = 34, AF_MAX = 35.  Kernel version 2.6.28 has AF_PHONET = 35,
 * AF_MAX = 36.  My own modified kernel version 2.6.27 has AF_NAME = 35 (and
 * AF_MAX = 36.)
 */
#define AF_NAME 35
#endif
#ifndef PF_NAME
#define PF_NAME AF_NAME
#endif
#include <errno.h>
#include <stdio.h>
#include <string.h>

static int name_is_local(const char *name)
{
	const char *p;

	assert(strlen(name) > 1);
	p = name + strlen(name) - 1;
	if (*p != '.')
		return 0;
	for (p = p - 1; *p != '.' && p >= name; p--)
		;
	if (p == name)
		return 0;
	return !strcmp(p + 1, "localhost.");
}

static int resolve_name(int af, const char *name, short port,
			struct sockaddr *addr, socklen_t *len)
{
	int ret;

	switch (af)
	{
	case AF_NAME:
		if (*len < sizeof(struct sockaddr_name))
		{
			*len = sizeof(struct sockaddr_name);
			errno = EINVAL;
			ret = -1;
		}
		else
		{
			struct sockaddr_name *sname =
				(struct sockaddr_name *)addr;

			*len = sizeof(struct sockaddr_name);
			addr->sa_family = af;
			strcpy(sname->sname_addr.name, name);
			sname->sname_port = htons(port);
		}
		ret = 0;
		break;
	default:
		if (name_is_local(name))
		{
			switch (af)
			{
			case AF_INET:
				if (*len < sizeof(struct sockaddr_in))
				{
					*len = sizeof(struct sockaddr_in);
					errno = EINVAL;
					ret = -1;
				}
				else
				{
					struct sockaddr_in *sin =
						(struct sockaddr_in *)addr;

					*len = sizeof(struct sockaddr_in);
					sin->sin_family = af;
					sin->sin_port = htons(port);
					sin->sin_addr.s_addr =
						htonl(INADDR_LOOPBACK);
					ret = 0;
				}
				break;
			case AF_INET6:
				if (*len < sizeof(struct sockaddr_in6))
				{
					*len = sizeof(struct sockaddr_in6);
					errno = EINVAL;
					ret = -1;
				}
				else
				{
					struct sockaddr_in6 *sin6 =
						(struct sockaddr_in6 *)addr;

					*len = sizeof(struct sockaddr_in6);
					sin6->sin6_family = af;
					sin6->sin6_port = htons(port);
					memcpy(sin6->sin6_addr.s6_addr,
					       &in6addr_loopback,
					       sizeof(in6addr_loopback));
					ret = 0;
				}
				break;
			default:
				fprintf(stderr, "fixme: localhost, af = %d\n",
					af);
				errno = EINVAL;
				ret = -1;
			}
		}
		else
		{
			struct addrinfo hints, *answer;

			memset(&hints, 0, sizeof(hints));
			hints.ai_family = af;
			/* FIXME: add special case for domain matching this
			 * computer's domain.
			 */
			if (!(ret = getaddrinfo(name, NULL, &hints, &answer)))
			{
				if (*len < answer->ai_addrlen)
				{
					*len = answer->ai_addrlen;
					errno = EINVAL;
					ret = -1;
				}
				else
				{
					*len = answer->ai_addrlen;
					memcpy(addr, answer->ai_addr,
					       answer->ai_addrlen);
					switch (answer->ai_family)
					{
					case AF_INET:
						((struct sockaddr_in *)addr)->
							sin_port = htons(port);
						break;
					case AF_INET6:
						((struct sockaddr_in6 *)addr)->
							sin6_port = htons(port);
						break;
					default:
						fprintf(stderr,
							"warning: port ignored for address family %d\n",
							af);
					}
				}
				freeaddrinfo(answer);
			}
		}
	}
	return ret;
}

int main(int argc, const char *argv[])
{
	static const char google[] = "www.google.com";
	static const char *default_names[] = { google };
	int nNames, i;
	const char **names, *source_name = NULL;
	int domain = PF_NAME, type, protocol;
	short port = 0;
	int fd;

	/* Look for options */
	if (argc > 1)
	{
		for (i = 1; i < argc; )
		{
			if ((*argv[i] == '-' || *argv[i] == '/') &&
			   (argv[i][1] == 'f' || argv[i][1] == 'F') &&
			   i < argc - 1)
			{
				domain = atoi(argv[i + 1]);
				if (argc - i > 2)
					memmove(argv + i, argv + i + 2,
						(argc - i - 2) * sizeof(char *));
				argc -= 2;
				continue;
			}
			else if ((*argv[i] == '-' || *argv[i] == '/') &&
				 (argv[i][1] == 'p' || argv[i][1] == 'P') &&
				 i < argc - 1)
			{
				port = atoi(argv[i + 1]);
				if (argc - i > 2)
					memmove(argv + i, argv + i + 2,
						(argc - i - 2) * sizeof(char *));
				argc -= 2;
				continue;
			}
			else if ((*argv[i] == '-' || *argv[i] == '/') &&
				 (argv[i][1] == 's' || argv[i][1] == 'S') &&
				 i < argc - 1)
			{
				source_name = argv[i + 1];
				if (argc - i > 2)
					memmove(argv + i, argv + i + 2,
						(argc - i - 2) * sizeof(char *));
				argc -= 2;
				continue;
			}
			i++;
		}
	}
	/* Now that options are removed, look for name arguments */
	if (argc > 1)
	{
		nNames = argc - 1;
		names = &argv[1];
	}
	else
	{
		nNames = sizeof(default_names) / sizeof(default_names[0]);
		names = default_names;
	}
	type = SOCK_STREAM;
	protocol = 0;
	printf("creating a socket with domain = %d, type = %d, protocol = %d\n",
		domain, type, protocol);
	fd = socket(domain, type, protocol);
	if (fd >= 0)
	{
		struct sockaddr_name name;
		socklen_t len = sizeof(name);
		int ret;

		printf("got a socket!\n");
		if (source_name && domain == PF_NAME)
		{
			printf("binding to %s\n", source_name);
			name.sname_family = AF_NAME;
			strcpy(name.sname_addr.name, source_name);
			ret = bind(fd, (struct sockaddr *)&name, sizeof(name));
			if (ret < 0)
				perror("bind");
			else
				printf("bound to %s\n", source_name);
		}
		for (i = 0; i < nNames; i++)
		{
			int len;

			printf("connecting to %s:%d:\n", names[i], port);
			len = sizeof(name);
			if (!(ret = resolve_name(domain, names[i], port,
						 (struct sockaddr *)&name,
						 &len)))
			{
				ret = connect(fd, (struct sockaddr *)&name,
					      len);
				if (ret < 0)
					perror("connect");
				else
				{
					char buf[100];

					printf("connect succeeded!\n");
					ret = read(fd, buf, sizeof(buf));
					if (ret < 0)
						perror("read");
					else
					{
						static const char reply[] =
							"greetings";

						printf("got a message: %s\n",
						       buf);
						ret = write(fd, reply,
							    sizeof(reply));
						if (ret < 0)
							perror("write");
						else
							printf("wrote a reply\n");
					}
				}
			}
			else
				perror("resolve");
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
