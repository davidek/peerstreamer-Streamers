/*
 * Copyright (c) 2010-2011 Luca Abeni
 * Copyright (c) 2010-2011 Csaba Kiraly
 *
 * This file is part of PeerStreamer.
 *
 * PeerStreamer is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * PeerStreamer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with PeerStreamer.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include <sys/types.h>
#ifndef _WIN32
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>     /* For struct ifreq */
#include <netdb.h>
#else
#include <winsock2.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "net_helpers.h"
extern enum L3PROTOCOL {IPv4, IPv6} l3;

char *iface_addr(const char *iface)
{
#ifndef _WIN32
    struct ifaddrs *if_addr, *ifap;
	int family, res;
	char host_id[NI_MAXHOST], *host_addr;
	int ifcount;
	memset (host_id, 0, NI_MAXHOST);

	if (getifaddrs(&if_addr) == -1)
	{
	  perror("getif_addrs");
	  return NULL;
	}
	ifcount = 0;
	for (ifap = if_addr; ifap != NULL; ifap = ifap->ifa_next)
	{
		if (ifap->ifa_addr == NULL)
		{
			ifcount++;
			continue;
		}
		family = ifap->ifa_addr->sa_family;
		if (l3 == IPv4 && family == AF_INET && !strcmp (ifap->ifa_name, iface))
		{
			host_addr = malloc((size_t)INET_ADDRSTRLEN);

			res = getnameinfo(ifap->ifa_addr, sizeof(struct sockaddr_in),
					host_id, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			if (res != 0)
			{ /* failure to get IPv6 address */

			continue;
			}
			host_addr = malloc((size_t)INET_ADDRSTRLEN);
			strcpy(host_addr, strtok(host_id, "%"));
			break;
		}
		if (l3 == IPv6 && family == AF_INET6 && !strcmp (ifap->ifa_name, iface))
		{
			host_addr = malloc((size_t)INET6_ADDRSTRLEN);

			res = getnameinfo(ifap->ifa_addr, sizeof(struct sockaddr_in6),
					host_id, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			if (res != 0)
			{ /* failure to get IPv6 address */

			continue;
			}
			host_addr = malloc((size_t)INET6_ADDRSTRLEN);
			strcpy(host_addr, strtok(host_id, "%"));
			break;
		}

	}
	return host_addr;
#else
    if(iface != NULL && strcmp(iface, "lo") == 0) return (l3==IPv4?"127.0.0.1":"::1");
    if(iface != NULL && inet_addr(iface) != INADDR_NONE) return strdup(iface);
    return default_ip_addr();
#endif
}


char *simple_ip_addr()
{
  char hostname[256];
  struct hostent *host_entry;
  char *ip;

  fprintf(stderr, "Trying to guess IP ...");
  if (gethostname(hostname, sizeof hostname) < 0) {
    fprintf(stderr, "can't get hostname\n");
    return NULL;
  }
  fprintf(stderr, "hostname is: %s ...", hostname);

  host_entry = gethostbyname(hostname);
  if (! host_entry) {
    fprintf(stderr, "can't resolve IP\n");
    return NULL;
  }
  ip = strdup(inet_ntoa(*(struct in_addr*)host_entry->h_addr));
  fprintf(stderr, "IP is: %s ...", ip);

  return ip;
}


const char *autodetect_ip_address() {
#ifdef __linux__

	static char addr[128] = "";
	char iface[IFNAMSIZ] = "";
	char line[128] = "x";
	struct ifaddrs *ifaddr, *ifa;
	char *ret = NULL;
	int res;

	FILE *r = fopen("/proc/net/route", "r");
	if (!r) return NULL;

	while (1) {
		char dst[32];
		char ifc[IFNAMSIZ];

		fgets(line, 127, r);
		if (feof(r)) break;
		if ((sscanf(line, "%s\t%s", iface, dst) == 2) && !strcpy(dst, "00000000")) {
			strcpy(iface, ifc);
		 	break;
		}
	}
	if (iface[0] == 0) return NULL;

	if (getifaddrs(&ifaddr) < 0) {
		perror("getifaddrs");
		return NULL;
	}

	ifa = ifaddr;
	while (ifa) {
		if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET && 
			ifa->ifa_name && !strcmp(ifa->ifa_name, iface))  {
            if (l3 == IPv4 && ifa->ifa_addr->sa_family == AF_INET){
                void *tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
                res = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), line, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                printf("dev: %-8s address: <%s> \n", ifa->ifa_name, line);
                if (inet_ntop(AF_INET, tmpAddrPtr, addr, 127)) {
                        ret = addr;
                } else {
                        perror("inet_ntop error");
                        ret = NULL;
                }
                break;
            }
            if (l3 == IPv6 && ifa->ifa_addr->sa_family == AF_INET6){
                void *tmpAddrPtr=&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
                if (inet_ntop(AF_INET6, tmpAddrPtr, addr, 127)) {
                      ret = addr;
                } else {
                        perror("inet_ntop error");
                        ret = NULL;
                }
                break;
            }
			break;
		}
	ifa=ifa->ifa_next;
	}

	freeifaddrs(ifaddr);
	return ret;
#else
        return simple_ip_addr();
#endif
}


const char *hostname_ip_addr()
{
#ifndef _WIN32
  const char *ip;
  char hostname[256];
  struct addrinfo * result;
  struct addrinfo * res;
  int error;

  if (gethostname(hostname, sizeof hostname) < 0) {
    fprintf(stderr, "can't get hostname\n");
    return NULL;
  }
  fprintf(stderr, "hostname is: %s ...", hostname);

  /* resolve the domain name into a list of addresses */
  error = getaddrinfo(hostname, NULL, NULL, &result);
  if (error != 0) {
    fprintf(stderr, "can't resolve IP: %s\n", gai_strerror(error));
    return NULL;
  }

  /* loop over all returned results and do inverse lookup */
  for (res = result; res != NULL; res = res->ai_next) {
    ip = inet_ntoa(((struct sockaddr_in*)res->ai_addr)->sin_addr);
    fprintf(stderr, "IP is: %s ...", ip);
    if ( strncmp("127.", ip, 4) == 0) {
      fprintf(stderr, ":( ...");
      ip = NULL;
    } else {
      break;
    }
  }
  freeaddrinfo(result);

  return ip;
#else
  return NULL;
#endif
}

char *default_ip_addr()
{
  const char *ip = NULL;

  fprintf(stderr, "Trying to guess IP ...");

  ip = autodetect_ip_address();

  if (!ip) {
    fprintf(stderr, "cannot detect IP!\n");
    return NULL;
  }
  fprintf(stderr, "IP is: %s ...\n", ip);

  return strdup(ip);
}
