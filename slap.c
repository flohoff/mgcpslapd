#include <event.h>
#include <evdns.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/param.h>

#include "gw.h"
#include "slap.h"
#include "logging.h"
#include "socket.h"

int slap_isactive(struct gateway_s *gw) {
	return (gw->slap.status == SLAP_ACTIVE);
}

#define DNS_FAIL_RETRY_TIME	60
#define DNS_REFRESH_TIME	300
#define SLAP_PORT		5003

#define SLAPCONN_FAIL_RETRY	6		/* Failure on connect retry timer */

static void slap_dns_callback(int result, char type, int count, int ttl, void *addresses, void *arg);

static void slap_dns_resolve(int fd, short event, void *arg) {
	struct gateway_s	*gw=arg;
	evdns_resolve_ipv4(gw->name, 0, slap_dns_callback, gw);
}

static void slap_dns_retry(struct gateway_s *gw, int time) {

	gw->slap.addr.tv.tv_sec=time;
	gw->slap.addr.tv.tv_usec=0;

	evtimer_set(&gw->slap.addr.timer, &slap_dns_resolve, gw);
	evtimer_add(&gw->slap.addr.timer, &gw->slap.addr.tv);
}


static void slap_connect(struct gateway_s *);
static void slap_conn_init(struct gateway_s *);

static void slap_conn_retry_conn(int fd, short event, void *arg) {
	struct gateway_s	*gw=arg;
	slap_conn_init(gw);
}

static void slap_conn_retry(struct gateway_s *gw, int time) {

	gw->slap.conn.tv.tv_sec=time;
	gw->slap.conn.tv.tv_usec=0;

	evtimer_set(&gw->slap.conn.event, &slap_conn_retry_conn, gw);
	evtimer_add(&gw->slap.conn.event, &gw->slap.conn.tv);
}

static void slap_conn_established(int fd, short event, void *arg) {
	struct gateway_s	*gw=arg;
	int			error, rc;
	socklen_t		elen=sizeof(error);

	if (event == EV_WRITE) {
		rc=getsockopt(gw->slap.conn.socket, SOL_SOCKET, SO_ERROR, &error, &elen);

		if (rc < 0) {
			logwrite(LOG_ERROR, "getsockopt after slap connect returned %s", strerror(errno));
		}

		if (error == 0) {
			gw->slap.status=SLAP_CONNECTED;
			/* FIXME - We should now register correct event callbacks or attach
			   a bufferevent thingy ....
			 */
		} else {
			slap_conn_retry(gw, SLAPCONN_FAIL_RETRY);
		}
	} else if (event == EV_TIMEOUT) {
		/* Probably we should drop the socket and recreate it - otherwise we
		   keep on trying on the same tcp session until it aborts
		 */
		socket_close(gw->slap.conn.socket);
		slap_conn_init(gw);
	}
}

#define SLAP_CONNECT_TIMEOUT	3

/* Connect to the gateway and schedule a timeout or writeable event */
static void slap_connect(struct gateway_s *gw) {
	int	i;

	i=socket_connect(gw->slap.conn.socket, NULL, gw->slap.addr.in.s_addr, SLAP_PORT);

	/*
	EINPROGRESS
	      The socket is non-blocking and the connection cannot be
	      completed immediately.  It is  possible  to select(2) or
	      poll(2) for completion by selecting the socket for writing.
	      After select(2) indicates writability, use getsockopt(2)
	      to read the SO_ERROR option at level SOL_SOCKET to determine
	      whether connect() completed successfully (SO_ERROR is zero)
	      or unsuccessfully (SO_ERROR is one of the usual error
	      codes listed here, explaining the reason for the failure).
	*/
	if (i == -1) {
		if (errno != EINPROGRESS) {
			logwrite(LOG_DEBUG, "Connect to %s failed: %s", gw->name, strerror(errno));

			socket_close(gw->slap.conn.socket);
			gw->slap.conn.socket=0;

			slap_conn_retry(gw, SLAPCONN_FAIL_RETRY);
		} else {
			gw->slap.conn.tv.tv_sec=SLAP_CONNECT_TIMEOUT;
			gw->slap.conn.tv.tv_usec=0;

			event_set(&gw->slap.conn.event, gw->slap.conn.socket, EV_WRITE, slap_conn_established, gw);
			event_add(&gw->slap.conn.event, &gw->slap.conn.tv);

			gw->slap.status=SLAP_CONN_PROGRESS;
		}
	} else {
		/* FIXME - in non blocking mode this should not happen but it can happe
		   so we need to handle it - connect immediatly returned a connection and we
		   need to progress with SLAP
		 */
		gw->slap.status=SLAP_CONNECTED;
		logwrite(LOG_ERROR, "slap connected immediatly for gw %s", gw->name);
	}
}

/* Open a socket and start connecting */
static void slap_conn_init(struct gateway_s *gw) {
	logwrite(LOG_DEBUG, "Init connection called for gateway %s", gw->name);

	gw->slap.conn.socket=socket_open(NULL, 0, IPPROTO_TCP);
	socket_set_nonblock(gw->slap.conn.socket);

	slap_connect(gw);
}

static void slap_dns_callback(int result, char type, int count,
			int ttl, void *addresses, void *arg) {

	struct gateway_s	*gw=arg;
	uint32_t		addr;

	if (result != DNS_ERR_NONE || type != DNS_IPv4_A) {
		slap_dns_retry(gw, DNS_FAIL_RETRY_TIME);
		return;
	}

	if (count != 1)
		logwrite(LOG_ERROR, "dns resolve of %s returned %d records - using first", gw->name, count);

	addr=*((uint32_t *) addresses);

	logwrite(LOG_DEBUG, "successfully resolved %s", gw->name);

	if (addr != gw->slap.addr.in.s_addr) {
		if (!slap_isactive(gw)) {
			gw->slap.addr.in.s_addr=addr;
			slap_conn_init(gw);
		} else {
			logwrite(LOG_ERROR, "slap connection up and address change for gateway %s", gw->name);
		}
	}

	slap_dns_retry(gw, MIN(DNS_REFRESH_TIME, ttl));
}

static void slap_dns_init(struct gateway_s *gw) {
	evdns_resolve_ipv4(gw->name, 0, slap_dns_callback, gw);
}

void slap_init_gateway(struct gateway_s *gw) {
	slap_dns_init(gw);
}

void slap_init(void ) {

}
