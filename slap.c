#include <event.h>
#include <evdns.h>
#include <string.h>
#include <stdlib.h>
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

int slap_isactive(struct gateway_s *gw) {
	return (gw->slap.status == SLAP_ACTIVE);
}

static void slap_dns_callback(int result, char type, int count, int ttl, void *addresses, void *arg);
static void slap_conn_notify(struct gateway_s *gw, short ev);

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
	ss7_v2_header_t		*ss7head=(ss7_v2_header_t *) &gw->slap.read.buffer;

	return ss7head->payload_len+SLAP_MSGHDR_LEN;
}

static int slap_msg_complete(struct gateway_s *gw) {
	if (gw->slap.read.valid >= SLAP_MSGHDR_LEN) {
		if (gw->slap.read.valid >= slap_msglen(gw))
			return 1;
	}
	return 0;
}

/* Delete message from input buffer - move bytes to front and update
 * valid byte counter
 */
static void slap_msg_zap(struct gateway_s *gw) {
	int	len=slap_msglen(gw);
	if (len < gw->slap.read.valid)
		memmove(gw->slap.read.buffer, gw->slap.read.buffer+len, gw->slap.read.valid-len);
	gw->slap.read.valid-=len;
}

static void slap_recvhb_stop(struct gateway_s *);
static void slap_sendhb_stop(struct gateway_s *);

static void slap_connection_drop(struct gateway_s *gw) {

	event_del(&gw->slap.conn.event);
	socket_close(gw->slap.conn.socket);

	gw->slap.status=SLAP_INACTIVE;

	slap_recvhb_stop(gw);
	slap_sendhb_stop(gw);
}

static void slap_recvhb_stop(struct gateway_s *gw) {
	evtimer_del(&gw->slap.hb.recvtimer);
}

/* Callback in case remote end heartbeat do not come in ... */
static void slap_recvhb_fail(int fd, short event, void *arg) {
	struct gateway_s	*gw=arg;
	logwrite(LOG_ERROR, "SLAP remote heartbeat fail for %s", gw->name);
	slap_connection_drop(gw);
}

static void slap_recvhb_extend(struct gateway_s *gw) {
	slap_recvhb_stop(gw);

	gw->slap.hb.recvtv.tv_sec=SLAP_HB_TIME_NE*SLAP_HB_FAILCOUNT;
	gw->slap.hb.recvtv.tv_usec=0;

	evtimer_set(&gw->slap.hb.recvtimer, slap_recvhb_fail, gw);
	evtimer_add(&gw->slap.hb.recvtimer, &gw->slap.hb.recvtv);
}

static void slap_msg_recvhb(struct gateway_s *gw) {
	gw->slap.hb.recv=time(NULL);
}



static int slap_send_append_bytes(struct gateway_s *gw, uint8_t *buf, int skip, int len) {
	int	heap=SLAP_BUFFER_SIZE-gw->slap.write.valid;

	logwrite(LOG_DEBUG, "appending to buffer - SLAP connection slow? %s", gw->name);

	if (len > heap) {
		logwrite(LOG_ERROR, "SLAP write buffer overflow for gateway %s", gw->name);
		slap_connection_drop(gw);
		return 0;
	}

	memcpy(gw->slap.write.buffer+gw->slap.write.valid,
		buf+skip,
		len);

	gw->slap.write.valid+=len;

	return len;
}

static int slap_send_bytes(struct gateway_s *gw, uint8_t *buf, ssize_t len) {
	int	rc;

	rc=write(gw->slap.conn.socket, buf, len);

	if (rc<0) {
		logwrite(LOG_ERROR, "SLAP write to gateways %s returned %s", gw->name, strerror(errno));
		slap_connection_drop(gw);
		return 0;
	}

	dump_hex(LOG_DEBUG, "SLAPOUT", buf, rc);

	return rc;
}

static int slap_send_buffer(struct gateway_s *gw) {
	int	rc;

	logwrite(LOG_DEBUG, "sending from buffer - SLAP connection slow? %s", gw->name);

	rc=slap_send_bytes(gw, gw->slap.write.buffer, gw->slap.write.valid);

	if (!rc)
		return 0;

	/* Move bytes left in the buffer to the front */
	if (gw->slap.write.valid > rc) {
		memmove(gw->slap.write.buffer,
			gw->slap.write.buffer+rc,
			gw->slap.write.valid-rc);
	}

	gw->slap.write.valid-=rc;

	return rc;
}

static int slap_send_append_msg(struct gateway_s *gw, ss7_v2_header_t *hdr) {
	int	len=hdr->payload_len+SLAP_MSGHDR_LEN;

	return slap_send_append_bytes(gw, (uint8_t *) hdr, 0, len);
}

static int slap_send_msg(struct gateway_s *gw, ss7_v2_header_t *hdr) {
	int	len=hdr->payload_len+SLAP_MSGHDR_LEN;
	int	rc;

	rc=slap_send_bytes(gw, (uint8_t *) hdr, len);
	if (!rc)
		return rc;

	if (rc < len) {
		if (!slap_send_append_bytes(gw, (uint8_t *) hdr, rc, len-rc)) {
			slap_connection_drop(gw);
			return 0;
		}
	}

	return rc;
}

static void slap_send_notify(struct gateway_s *gw) {

}

static int slap_send(struct gateway_s *gw, ss7_v2_header_t *hdr) {

	/* If we have bytes in the buffer - send them first */
	if (gw->slap.write.valid != 0)
		if (!slap_send_buffer(gw))
			return 0;

	/*
	 * If we emptied the buffer - try to send our message
	 * directly afterwards otherwise append it to the buffer
	 */
	if (gw->slap.write.valid == 0) {
		if (!slap_send_msg(gw, hdr))
			return 0;
	} else {
		if (!slap_send_append_msg(gw, hdr))
			return 0;
	}

	/* Still buffered bytes - notify if socket writeable */
	if (gw->slap.write.valid)
		slap_send_notify(gw);

	return 1;
}


static void slap_sendhb_extend(struct gateway_s *);

static void slap_sendhb(int fd, short event, void *arg) {
	struct gateway_s	*gw=arg;
	ss7_v2_header_t		hb;

	hb.protocol_id=SLAP_MAGIC;
	hb.version=SLAP_VERSION;
	hb.app_class=SLAP_AC_HEARTBEAT;
	hb.payload_len=0;

	hb.chassis_id=gw->slap.addr.in.s_addr;
	hb.location_id=0;

	slap_send(gw, &hb);

	slap_sendhb_extend(gw);
}

static void slap_sendhb_stop(struct gateway_s *gw) {
	evtimer_del(&gw->slap.hb.sendtimer);
}

static void slap_sendhb_extend(struct gateway_s *gw) {
	slap_sendhb_stop(gw);

	gw->slap.hb.sendtv.tv_sec=SLAP_HB_TIME_FE;
	gw->slap.hb.sendtv.tv_usec=0;

	evtimer_set(&gw->slap.hb.sendtimer, slap_sendhb, gw);
	evtimer_add(&gw->slap.hb.sendtimer, &gw->slap.hb.sendtv);
}

static void slap_sendhb_init(struct gateway_s *gw) {
	slap_sendhb_extend(gw);
}






static void slap_msg_process(struct gateway_s *gw) {
	ss7_v2_header_t		*hdr=(ss7_v2_header_t *) &gw->slap.read.buffer;

	logwrite(LOG_DEBUG, "processing SLAP message for gw %s", gw->name);
	dump_hex(LOG_DEBUG, "SLAPIN ", gw->slap.read.buffer, slap_msglen(gw));

	/* Any packet acts as a heartbeat */
	slap_recvhb_extend(gw);

	switch(hdr->app_class) {
		case(SLAP_AC_HEARTBEAT):
			slap_msg_recvhb(gw);
			break;
	}

	slap_msg_zap(gw);
}

static void slap_read(struct gateway_s *gw, int fd) {
	ssize_t		len;
	int		maxread;

	maxread=SLAP_BUFFER_SIZE-gw->slap.read.valid;

	len=read(fd, gw->slap.read.buffer+gw->slap.read.valid, maxread);

	if (len == 0) {
		/*
		 * FIXME The tcp connection dropped - we need to signal to MGCP 
		 * and clear state
		 * Then we need to restart the connection timer
		 */
		logwrite(LOG_DEBUG, "SLAP Connection from %s/%s dropped", gw->name, inet_ntoa(gw->slap.addr.in));
		slap_connection_drop(gw);
	}

	logwrite(LOG_DEBUG, "SLAP read %d bytes on gw %s", len, gw->name);

	gw->slap.read.valid+=len;

	dump_hex(LOG_DEBUG, "SLAPINBUF ", gw->slap.read.buffer, MIN(32,gw->slap.read.valid));
	logwrite(LOG_DEBUG, "SLAP msg complete %d size %d", slap_msg_complete(gw), slap_msglen(gw));

	while(slap_msg_complete(gw))
		slap_msg_process(gw);
}

static void slap_conn_callback(int fd, short event, void *arg) {
	struct gateway_s	*gw=arg;
	logwrite(LOG_DEBUG, "got event %04x on fd %d", event, fd);

	if (event & EV_READ)
		slap_read(gw, fd);

	if (event & EV_WRITE) {

		if (!slap_send_buffer(gw))
			return;

		/* No bytes left - turn of WRITE notify */
		if (!gw->slap.write.valid)
			slap_conn_notify(gw, EV_READ|EV_PERSIST);
	}
}

static void slap_conn_notify(struct gateway_s *gw, short ev) {
	logwrite(LOG_DEBUG, "setting event notify on socket %d to %04x", gw->slap.conn.socket, ev);
	event_set(&gw->slap.conn.event, gw->slap.conn.socket, ev, slap_conn_callback, gw);
	event_add(&gw->slap.conn.event, NULL);
}

static void slap_connected(struct gateway_s *gw, int socket) {

	/* Dont allow duplicate connections */
	if (gw->slap.status != SLAP_INACTIVE) {
		logwrite(LOG_ERROR, "SLAP got connection for gateway %s while state %d", gw->name, gw->slap.status);
		close(socket);
		return;
	}

	gw->slap.status=SLAP_CONNECTED;
	gw->slap.conn.socket=socket;

	/* Zap in and out buffer */
	gw->slap.write.valid=0;
	gw->slap.read.valid=0;

	slap_conn_notify(gw, EV_READ|EV_PERSIST);

	slap_sendhb_init(gw);
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
	if (slapsock<0) {
		logwrite(LOG_ERROR, "Failed to bind to SLAP port %d", SLAP_PORT);
		exit(-1);
	}
	socket_set_nonblock(slapsock);
	socket_listen(slapsock, 25);

	event_set(&slapevent, slapsock, EV_READ|EV_PERSIST, slap_accept, NULL);
	event_add(&slapevent, NULL);
}
