
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <event.h>

#include "socket.h"

#define MGCP_PORT	2427


static int		mgcpsock;
static struct event	mgcpsockevent;

static void mgcp_read(int fd, short event, void *arg) {

}

int mgcp_init(void ) {

	mgcpsock=socket_open(NULL, MGCP_PORT);
	socket_set_nonblock(mgcpsock);

	event_set(&mgcpsockevent, mgcpsock, 
		EV_READ|EV_PERSIST, mgcp_read, NULL);
	event_add(&mgcpsockevent, NULL);

	return 0;
}
