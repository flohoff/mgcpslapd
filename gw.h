#ifndef MGCPSLAP_GW_H
#define MGCPSLAP_GW_H

#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <event.h>

#include <stdint.h>

struct gateway_s {
	char	name[128];

	struct {
		int status;

		struct {
			struct in_addr	in;
			time_t		ttl;

			struct event	timer;
			struct timeval	tv;
		} addr;

		struct {
			int		socket;
			struct event	event;
			struct timeval	tv;
		} conn;

#define SLAP_MAXMSG_SIZE	524
		int	valid;
		uint8_t	readbuffer[SLAP_MAXMSG_SIZE];
	} slap;
};

int gw_init(void );
struct gateway_s *gw_lookup(char *);
struct gateway_s *gw_lookup_or_create(char *);

#endif
