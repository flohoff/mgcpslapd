#include <event.h>
#include <evdns.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/param.h>
#include <unistd.h>
#include <glib.h>

#include "gw.h"
#include "slap.h"
#include "logging.h"
#include "socket.h"
#include "util.h"

static int		slapsock;
static struct event	slapevent;
GHashTable		*gwbyaddr;

#define DNS_FAIL_RETRY_TIME	60
#define DNS_REFRESH_TIME	300
#define SLAP_PORT		5003

#define SLAP_CONNECT_TIMEOUT	3		/* SLAP connect timeout */
#define SLAPCONN_FAIL_RETRY	6		/* Failure on connect retry timer */

int slap_isactive(struct gateway_s *gw) {
	return (gw->slap.status == SLAP_ACTIVE);
}

//static void slap_connect(struct gateway_s *);


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
			/* Update SLAP gwbyaddr table */
			if (gw->slap.addr.in.s_addr)
				g_hash_table_remove(gwbyaddr, &gw->slap.addr.in.s_addr);

			gw->slap.addr.in.s_addr=addr;

			g_hash_table_insert(gwbyaddr, &gw->slap.addr.in.s_addr, gw);
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

static int slap_msglen(struct gateway_s *gw) {
	ss7_v2_header_t		*ss7head=(ss7_v2_header_t *) &gw->slap.readbuffer;

	return ss7head->payload_len+SLAP_MSGHDR_MINLEN;
}

static int slap_msg_complete(struct gateway_s *gw) {
	if (gw->slap.valid >= SLAP_MSGHDR_MINLEN) {
		if (gw->slap.valid >= slap_msglen(gw))
			return 1;
	}
	return 0;
}

/* Delete message from input buffer - move bytes to front and update
 * valid byte counter
 */
static void slap_msg_zap(struct gateway_s *gw) {
	int	len=slap_msglen(gw);
	if (len > gw->slap.valid)
		memmove(gw->slap.readbuffer, gw->slap.readbuffer+len, gw->slap.valid-len);
	gw->slap.valid-=len;
}

static void slap_msg_process(struct gateway_s *gw) {
	logwrite(LOG_DEBUG, "processing SLAP message for gw %s", gw->name);
	dump_hex(LOG_DEBUG, "SLAPMSG", gw->slap.readbuffer, slap_msglen(gw));
	slap_msg_zap(gw);
}

static void slap_read(struct gateway_s *gw, int fd) {
	ssize_t		len;
	int		maxread;

	maxread=SLAP_MAXMSG_SIZE-gw->slap.valid;

	len=read(fd, gw->slap.readbuffer+gw->slap.valid, maxread);

	if (len == 0) {
		/*
		 * FIXME The tcp connection dropped - we need to signal to MGCP 
		 * and clear state
		 * Then we need to restart the connection timer
		 */
		logwrite(LOG_ERROR, "slap_read returned %d bytes for gw %s", len, gw->name);
	}

	gw->slap.valid+=len;

	/* Do we have the header until the length byte */
	if (slap_msg_complete(gw))
		slap_msg_process(gw);
}

static void slap_read_callback(int fd, short event, void *arg) {
	struct gateway_s	*gw=arg;
	if (event & EV_READ)
		slap_read(gw, fd);
}


static void slap_connected(struct gateway_s *gw, int socket) {
	gw->slap.status=SLAP_CONNECTED;
	gw->slap.conn.socket=socket;

	event_set(&gw->slap.conn.event, gw->slap.conn.socket, EV_READ|EV_PERSIST, slap_read_callback, gw);
	event_add(&gw->slap.conn.event, NULL);
}

static void slap_accept(int fd, short event, void *arg) {
	struct sockaddr_in	sin;
	struct gateway_s	*gw;
	int			socket;
	socklen_t		sinlen=sizeof(sin);

	if (event & EV_READ) {
		socket=accept(fd, (struct sockaddr *) &sin, &sinlen);
		if (socket < 0) {
			logwrite(LOG_ERROR, "accept returned errorr: %s", strerror(errno));
		} else {
			logwrite(LOG_DEBUG, "incoming SLAP connect from gateway %s", inet_ntoa(sin.sin_addr));

			gw=g_hash_table_lookup(gwbyaddr, &sin.sin_addr.s_addr);

			if (!gw) {
				logwrite(LOG_ERROR, "gateway %s unknown", inet_ntoa(sin.sin_addr));
				close(socket);
				return;
			}

			slap_connected(gw, socket);
		}
	}
}

void slap_init(void ) {
	gwbyaddr=g_hash_table_new(g_int_hash, g_int_equal);

	/* FIXME - Error handling - may use assert here */
	slapsock=socket_open(NULL, SLAP_PORT, IPPROTO_TCP);
	socket_set_nonblock(slapsock);
	socket_listen(slapsock, 25);

	event_set(&slapevent, slapsock, EV_READ|EV_PERSIST, slap_accept, NULL);
	event_add(&slapevent, NULL);
}
