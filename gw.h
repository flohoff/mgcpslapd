#ifndef MGCPSLAP_GW_H
#define MGCPSLAP_GW_H

#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <event.h>

#include <stdint.h>

//#define SLAP_MAXMSG_SIZE	524
#define SLAP_BUFFER_SIZE	512

struct gateway_s {
	char	name[128];

	struct {
		int	status;

		struct {
			time_t		recv;
			struct timeval	recvtv;
			struct event	recvtimer;

			struct timeval	sendtv;
			struct event	sendtimer;
		} hb;

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

		struct {
			int	valid;
			uint8_t	buffer[SLAP_BUFFER_SIZE];
		} read;

		struct {
			int	valid;
			uint8_t	buffer[SLAP_BUFFER_SIZE];
		} write;
	} slap;
};

int gw_init(void );
struct gateway_s *gw_lookup(char *);
struct gateway_s *gw_lookup_or_create(char *);

#endif
