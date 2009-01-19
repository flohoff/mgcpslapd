
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <event.h>

#include "socket.h"
#include "valstring.h"


#define MGCP_PORT	2427
#define MAX_BUFFER	4096


static int		mgcpsock;
static struct event	mgcpsockevent;

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

/*
AUEP 900339904 S3/DS1-1/1@t3COM-verl-de01 MGCP 1.0
F:
*/

static int mgcp_splitcmdline(char *buffer, ssize_t len, int *elements,
		char **eptr, int *elen) {

	int	i=0,j=0;

	elen[j]=0;
	eptr[j++]=buffer+i;

	while(i<len && j < *elements) {
		if (buffer[i] == 0xa) {
			buffer[i]=0x0;
			break;
		}

		if (buffer[i] != ' ') {
			elen[j-1]++;
		} else {
			elen[j]=0;
			eptr[j++]=buffer+i+1;
			buffer[i]=0x0;
		}

		i++;
	}

	*elements=j;

	return i;
}

static void mgcp_parsepkt(char *buffer, ssize_t len) {
	int	i=0,j=0;
	char	*eptr[8];
	int	elen[8];
	int	elem=8;
	int	cmd=0;

	j=mgcp_splitcmdline(buffer, len, &elem, eptr, elen);

	/* Is this really an MGCP packet */
	if (strncmp(eptr[3], "MGCP", 4))
		return;

	for(i=0;i<elem;i++)
		printf("Elem %02d: (%2d) %s\n", i, elen[i], eptr[i]);

	if (vstr_str2val(eptr[0], mgcpverb, &cmd)) {
		printf("Command found %d\n", cmd);
	}
}


static void mgcp_read(int fd, short event, void *arg) {
	ssize_t			pktlen;
	char			buffer[MAX_BUFFER];
	struct sockaddr_in	sin;
	socklen_t		sinlen=sizeof(sin);

	pktlen=recvfrom(fd, &buffer, MAX_BUFFER, 0,
			 (struct sockaddr *) &sin, &sinlen);

	mgcp_parsepkt(buffer, pktlen);

}

int mgcp_init(void ) {

	mgcpsock=socket_open(NULL, MGCP_PORT);
	socket_set_nonblock(mgcpsock);

	event_set(&mgcpsockevent, mgcpsock, 
		EV_READ|EV_PERSIST, mgcp_read, NULL);
	event_add(&mgcpsockevent, NULL);

	return 0;
}
