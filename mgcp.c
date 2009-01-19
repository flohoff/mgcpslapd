
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <event.h>
#include <evdns.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "socket.h"
#include "valstring.h"
#include "logging.h"
#include "gw.h"
#include "slap.h"

#define MGCP_PORT	2427
#define MAX_BUFFER	4096

static int		mgcpsock;
static struct event	mgcpsockevent;

#define MGCP_MAX_LINES		64
#define MGCP_MAX_CMDPART	8

struct sepstr_s {
	char	*ptr;
	int	len;
};

struct mgcppkt_s {
	struct sockaddr_in	sin;
	socklen_t		sinlen;

	char	buffer[MAX_BUFFER];
	ssize_t	pktlen;

	int			lines;
	struct sepstr_s		line[MGCP_MAX_LINES];

	int			cmdparts;
	struct sepstr_s		cmdpart[MGCP_MAX_CMDPART];
};

enum {
	MGCP_VERB_UNKNOWN = 0,
	MGCP_VERB_AUEP,
	MGCP_VERB_CRCX,
	MGCP_VERB_DLCX,
	MGCP_VERB_MDCX,
};

static valstring mgcpverb[] = {
	{ MGCP_VERB_AUEP,	"AUEP" },
	{ MGCP_VERB_CRCX,	"CRCX" },
	{ MGCP_VERB_DLCX,	"DLCX" },
	{ MGCP_VERB_MDCX,	"MDCX" },
	{ 0, NULL },
};

static int mgcp_splitbuffer(char *buffer, int len, char sep, struct sepstr_s *parts, int maxparts) {
	int	i=0,j=0;

	parts->ptr=buffer;
	parts->len=0;

	while(i<len && j<maxparts) {
		if (buffer[i] != sep) {
			parts->len++;
		} else {
			buffer[i++]=0x0;

			parts++;
			j++;
			parts->ptr=buffer+i;
			parts->len=0;
		}
		i++;
	}

	return (parts->len) ? j+1 : j;
}

/*
	AUEP 900339904 S3/DS1-1/1@t3COM-verl-de01 MGCP 1.0
	F:
*/
static void mgcp_process_auep(struct mgcppkt_s *mp) {
	struct sepstr_s		ep[2];
	int			i;
	struct gateway_s	*gw;

	/* Split endpoint at the @ */
	i=mgcp_splitbuffer(mp->cmdpart[2].ptr, mp->cmdpart[2].len, '@', ep, 2);

	/* We have at least timeslot@domain */
	if (i<2)
		return;

	gw=gw_lookup_or_create(ep[1].ptr);

	if (!slap_isactive(gw))
		return;

}

void mgcp_init_gateway(struct gateway_s *gw) {

}

/* AUEP 1201 aaln/1@rgw-2567.whatever.net MGCP 1.0 */
static void mgcp_parsepkt(struct mgcppkt_s *mp) {
	int	i, cmd;

	mp->lines=mgcp_splitbuffer(mp->buffer, mp->pktlen, 0xa,
				mp->line, MGCP_MAX_LINES);

	mp->cmdparts=mgcp_splitbuffer(mp->line[0].ptr, mp->line[0].len, 0x20,
				mp->cmdpart, MGCP_MAX_CMDPART);

	/* Is this really an MGCP packet */
	if (mp->cmdparts < 5 || strncmp(mp->cmdpart[3].ptr, "MGCP", 4))
		return;

	for(i=0;i<mp->cmdparts;i++)
		logwrite(LOG_DEBUG, "Elem %02d: (%2d) %s", i, mp->cmdpart[i].len, mp->cmdpart[i].ptr);

	/* Unknown command */
	if (!vstr_str2val(mp->cmdpart[0].ptr, mgcpverb, &cmd)) {
		logwrite(LOG_DEBUG, "mgcp verb not found %s", mp->cmdpart[0].ptr);
		return;
	}

	if (strchr(mp->cmdpart[2].ptr, '*') || strchr(mp->cmdpart[2].ptr, '$')) {
		logwrite(LOG_ERROR, "endpoint contains wildcard: %s", mp->cmdpart[2].ptr);
	}

	switch(cmd) {
		case(MGCP_VERB_AUEP):
			mgcp_process_auep(mp);
			break;
	}
}

static void mgcp_read(int fd, short event, void *arg) {
	struct mgcppkt_s	*mp;

	mp=calloc(1, sizeof(struct mgcppkt_s));
	mp->sinlen=sizeof(mp->sin);

	mp->pktlen=recvfrom(fd, &mp->buffer, MAX_BUFFER, 0,
			 (struct sockaddr *) &mp->sin, &mp->sinlen);

	mgcp_parsepkt(mp);

}

int mgcp_init(void ) {

	mgcpsock=socket_open(NULL, MGCP_PORT);
	socket_set_nonblock(mgcpsock);

	event_set(&mgcpsockevent, mgcpsock,
		EV_READ|EV_PERSIST, mgcp_read, NULL);
	event_add(&mgcpsockevent, NULL);

	return 0;
}

