#include <event.h>
#include <evdns.h>
#include <string.h>
#include <stdio.h>
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
#include "mgcp.h"

static int		slapsock;
static struct event	slapevent;
static GHashTable	*gwbyaddr;

#define SLAP_MAX_MSG_SIZE	1024

struct slapmsg_s {
	int	len;
	char	buffer[SLAP_MAX_MSG_SIZE];
};

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

static int slap_msg_payload_len(ss7_v2_header_t *hdr) {
	return hdr->payload_len;
}

static int slap_msg_len(ss7_v2_header_t *hdr) {
	return hdr->payload_len+SLAP_MSGHDR_LEN;
}

static int slap_msg_complete(struct gateway_s *gw) {
	ss7_v2_header_t *hdr=(ss7_v2_header_t *) &gw->slap.read.buffer;
	if (gw->slap.read.valid >= SLAP_MSGHDR_LEN) {
		if (gw->slap.read.valid >= slap_msg_len(hdr))
			return 1;
	}
	return 0;
}

uint8_t *slap_msg_payloadptr(ss7_v2_header_t *hdr) {
	hdr++;
	return (uint8_t *) hdr;
}

/* Delete message from input buffer - move bytes to front and update
 * valid byte counter
 */
static void slap_msg_zap(struct gateway_s *gw) {
	ss7_v2_header_t *hdr=(ss7_v2_header_t *) &gw->slap.read.buffer;
	int		len=slap_msg_len(hdr);

	if (len < gw->slap.read.valid)
		memmove(gw->slap.read.buffer, gw->slap.read.buffer+len, gw->slap.read.valid-len);

	gw->slap.read.valid-=len;
}

static void slap_recvhb_stop(struct gateway_s *);
static void slap_sendhb_stop(struct gateway_s *);

static void slap_connection_drop(struct gateway_s *gw) {
	int		i;

	logwrite(LOG_ERROR, "Dropping SLAP connection for gateway %s", gw->name);

	event_del(&gw->slap.conn.event);

	socket_close(gw->slap.conn.socket);

	gw->slap.status=SLAP_INACTIVE;

	slap_recvhb_stop(gw);
	slap_sendhb_stop(gw);

	/* Reset state - 0-UNKNOWN,1-UP, 2-DOWN */
	for(i=0;i<MAX_SLOT;i++)
		gw->slot[i].status=0;

	gw_set_status(gw, GW_STATUS_UNAVAIL);
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

static void slap_msg_recvhb(struct gateway_s *gw, ss7_v2_header_t *hdr) {
	gw->slap.hb.recv=time(NULL);
}

void slap_msg_create(struct slapmsg_s *msg, int appclass, int slot) {
	ss7_v2_header_t		*hb=(ss7_v2_header_t *) &msg->buffer;

	hb->protocol_id=SLAP_MAGIC;
	hb->version=SLAP_VERSION;
	hb->app_class=appclass;
	hb->payload_len=0;

	hb->location_id=ntohl(slot-1);

	msg->len=sizeof(ss7_v2_header_t);
}

void slap_msg_append_cc(struct slapmsg_s *msg, int msgtype, int span, int callid) {
	char		*p=msg->buffer+sizeof(ss7_v2_header_t);
	slap_cc_t	*cc=(slap_cc_t *) p;

	cc->msg_type=msgtype;
	cc->ds1_id=span;
	cc->CES=0;
	cc->reserved_1=0;
	cc->reserved_2=0;
	cc->call_id_msb=callid>>8;
	cc->call_id_lsb=callid&0xff;

	msg->len+=sizeof(slap_cc_t);
}

void slap_msg_create_cc(struct slapmsg_s *msg, int msgtype, int slot, int span, int callid) {
	slap_msg_create(msg, SLAP_AC_CALLCONTROL, slot);
	slap_msg_append_cc(msg, msgtype, span, callid);
}

void slap_msg_cc_append_ie_bearer(struct slapmsg_s *msg, int bearer) {
	char	*p=msg->buffer+msg->len;

#define COMS_IE_BEARER_CAPABILITY	0x04
#define COMS_BC_IXC_SPEECH		0x80
#define COMS_BC_IXC_UNRESTDIG		0x88
#define COMS_BC_XFERMODE_CIRCUIT	0x80
#define COMS_BC_DATARATE_64K		0x90

	p[0]=0x0;				/* Reserved */
	p[1]=COMS_IE_BEARER_CAPABILITY;	/* Element ID */
	p[2]=0x0a;				/* Length */
	p[3]=0x80;				/* Coding Standard */
	p[4]=COMS_BC_IXC_SPEECH;		/* Information transfer capability */
	p[5]=COMS_BC_XFERMODE_CIRCUIT;		/* Transfer Mode */
	p[6]=COMS_BC_DATARATE_64K;		/* Transfer Rate */
	p[7]=0x80;				/* Structure - unused */
	p[8]=0x80;				/* Configuration - unused */
	p[9]=0x80;				/* Establishment - unused */
	p[10]=0x80;				/* Symmetry - unused */
	p[11]=0x00;				/* Information Transfer Rate */
	p[12]=0x00;				/* Layer 1 Protocol */

	msg->len+=10+3;
}

void slap_msg_cc_append_ie_channelid(struct slapmsg_s *msg, int channel) {
	char		*p=msg->buffer+msg->len;
	uint32_t	cmap=1<<channel;

#define COMS_IE_CHANNEL_ID		0x18
#define COMS_CHIP_INTTYPE_PRIMARY_RATE	0x81
#define COMS_CHID_DCHAN_NO		0x80
#define COMS_CHID_CHSEL_AS_INDICATED	0x81
#define COMS_CHID_TYPE_B		0x03

	p[0]=0x0;				/* Reserved */
	p[1]=COMS_IE_CHANNEL_ID;		/* Element ID */
	p[2]=0x0c;				/* Length -> 0x0c -> E1*/
	p[3]=COMS_CHIP_INTTYPE_PRIMARY_RATE;	/* Interface type*/
	p[4]=0x81;				/* Preferred/Exclusive 0x80/0x81 */
	p[5]=COMS_CHID_DCHAN_NO;		/* D-Channel indicator */
	p[6]=COMS_CHID_CHSEL_AS_INDICATED;	/* Information channel select */
	p[7]=0x80;				/* Interface ID 1 */
	p[8]=0x80;				/* Interface ID 2 */
	p[9]=0x80;				/* Coding standard CCIT Standard */
	p[10]=COMS_CHID_TYPE_B;			/* Channel type */

	p[11]=(cmap>>24)&0xff;			/* Channel map */
	p[12]=(cmap>>16)&0xff;			/* Channel map */
	p[13]=(cmap>>8)&0xff;			/* Channel map */
	p[14]=cmap&0xff;			/* Channel map */

	msg->len+=12+3;
}


/*
   0000011A  dc 01 01 3c 3e 35 f7 05  00 00 00 01 1b 00 01 00 ...<>5.. ........ 
   aa bb  
   a -> 0x1b COMS_SETUP_IND
   b -> Span 0
   0000012A  00 b0 51 34 00 04 0a 80  88 80 90 80 80 80 80 00 ..Q4.... ........
   cc cc dd    ee ff gg
   c -> Call id
   d -> Len of IEs
   e -> Bearer
   f -> Len
   g -> Coding standard
   0000013A  00 00 18 0c 81 81 80 81  80 80 80 03 00 02 00 00 ........ ........
   aa bb cc
   a -> Reserved
   b -> Channel IE
   c -> Length
   0000014A  00 6c 0b 82 81 00 81 36  36 37 37 34 37 35 00 70 .l.....6 677475.p
   0000015A  07 82 81 31 39 31 36 31                          ...19161 
 */

void slap_msg_cc_finish(struct slapmsg_s *msg) {
	char		*p=msg->buffer+sizeof(ss7_v2_header_t);
	slap_cc_t	*cc=(slap_cc_t *) p;
	ss7_v2_header_t	*hb=(ss7_v2_header_t *) &msg->buffer;

	hb->payload_len=msg->len-sizeof(ss7_v2_header_t);
	cc->len_of_ies=msg->len-sizeof(ss7_v2_header_t)-sizeof(slap_cc_t);
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

static int slap_send(struct gateway_s *gw, struct slapmsg_s *msg) {
	ss7_v2_header_t *hdr=(ss7_v2_header_t *) &msg->buffer;

	hdr->chassis_id=gw->slap.addr.in.s_addr;

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
	struct slapmsg_s	msg;

	slap_msg_create(&msg, SLAP_AC_HEARTBEAT, 0);

	slap_send(gw, &msg);

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


/* 2009-01-21 15:11:07.993 slap_msg_process/394 Unknown SLAP Message 0c from gateways t3COM-verl-de01
 * 2009-01-21 15:11:07.993 SLAPIN  dc 31 0c 50 d9 bc 3f 4c 00 00 00 02 7c 01 01 73   .1.P..?L....|..s
 * 2009-01-21 15:11:07.994 SLAPIN  02 00 02 74 21 00 00 00 00 00 00 00 00 00 00 00   ...t!...........
 * 2009-01-21 15:11:07.994 SLAPIN  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
 * 2009-01-21 15:11:07.994 SLAPIN  00 00 00 00 00 00 7f 21 00 00 00 00 00 00 00 00   .......!........
 * 2009-01-21 15:11:07.994 SLAPIN  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
 * 2009-01-21 15:11:07.994 SLAPIN  00 00 00 00 00 00 00 00 00 7a 01 1f               .........z..    
 */
static void slap_msg_recv_register(struct gateway_s *gw, ss7_v2_header_t *hdr) {
	uint8_t		*msg=slap_msg_payloadptr(hdr);
	uint32_t	slot=ntohl(hdr->location_id);
	uint8_t		msglen=slap_msg_payload_len(hdr);
	uint8_t		*end=msg+msglen;
	uint8_t		span=0xff;

	while(msg < end) {
		uint8_t	field=*msg++;
		uint8_t	flen=*msg++;

		switch(field) {
			case(SLAP_LINK_STATUS): {
				uint8_t status=*(msg+1);
				span=*msg;

				gw_ds1_set_status(gw, slot, span, status);

				logwrite(LOG_DEBUG, "REGISTER contained link status slot %d span %d status %d",
						slot, span, status);

				break;
			}
			case(SLAP_DS0_STATUS): {
				uint8_t	chan;
				span=*msg;

				/* Check if we have non idle ds0s - This shouldnt happen
				  and i am unshure on how to handle that - so for now
				  log an error.
				*/
				for(chan=0;chan<flen-1;chan++) {
					uint8_t	ds0status=*(msg+1+chan);

					if (ds0status)
						logwrite(LOG_ERROR, "SLAP REGISTER has non idle ds0 %d status %d", chan, ds0status);

					gw_ds0_set_status(gw, slot, span, chan, ds0status);
				}
			}
			case(SLAP_DS0_BLOCKING): {
				uint8_t	ds0;
				span=*msg;

				for(ds0=0;ds0<flen-1;ds0++) {
					uint8_t	ds0block=*(msg+1+ds0);

					if (ds0block)
						logwrite(LOG_ERROR, "SLAP REGISTER has blocked ds0 %d status %d", ds0, ds0block);
				}
			}
			case(SLAP_TOTAL_MDM_AVAIL):
			case(SLAP_STARTUP_TEMP):
				break;
			default:
				logwrite(LOG_ERROR, "SLAP REGISTER message contained field %02x len %d", field, flen);
				break;
		}
		msg+=flen;
	}
}

/*
   2009-01-21 14:01:56.089 slap_msg_process/321 processing SLAP message for gw t3COM-verl-de01
   2009-01-21 14:01:56.089 SLAPIN  dc 31 0b 0c d9 bc 3f 4c 00 00 00 0f 7b 0a d9 bc   .1....?L....{...
   2009-01-21 14:01:56.089 SLAPIN  3f 4c 00 00 00 02 00 01                           ?L......        
 */
static void slap_msg_recv_event(struct gateway_s *gw, ss7_v2_header_t *hdr) {
	uint8_t		*msg=slap_msg_payloadptr(hdr);
	uint8_t		msglen=slap_msg_payload_len(hdr);
	uint8_t		*end=msg+msglen;

	while(msg < end) {
		uint8_t	field=*msg++;
		uint8_t	flen=*msg++;

		switch(field) {
			case(SLAP_STATUS_CHANGE): {
				status_chg_t	*sc=(status_chg_t *) msg;

				logwrite(LOG_DEBUG, "Status change: ESIG %08x SLOT: %d Status: %d",
						ntohl(sc->esig), ntohl(sc->slot), ntohs(sc->status));

				gw_slot_set_status(gw, ntohl(sc->slot), ntohs(sc->status));

				/* FIXME
				 *
				 * 00 -> 01 Unknown -> Up
				 * 00 -> 02 Unknown -> Down
				 * 01 -> 02 Up -> Down
				 * 02 -> Up Down -> up
				 *
				 */

				break;
			}
			case(SLAP_LINK_STATUS): {
				uint8_t	span=*msg;
				uint8_t	status=*(msg+1);

				gw_ds1_set_status(gw, ntohl(hdr->location_id), span, status);

				logwrite(LOG_DEBUG, "Link change: gw %s slot: %d span: %d status: %d",
					gw->name, ntohl(hdr->location_id), span, status);

			}
			default:
				logwrite(LOG_ERROR, "SLAP Status change message contained field %02x len %d", field, flen);
				break;
		}
		msg+=flen;
	}
}

/*
   2009-01-21 14:01:56.190 slap_msg_process/321 processing SLAP message for gw t3COM-verl-de01
   2009-01-21 14:01:56.190 SLAPIN  dc 31 0c 50 d9 bc 3f 4c 00 00 00 02 7c 01 01 73   .1.P..?L....|..s
   2009-01-21 14:01:56.190 SLAPIN  02 00 02 74 21 00 00 00 00 00 00 00 00 00 00 00   ...t!...........
   2009-01-21 14:01:56.190 SLAPIN  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
   2009-01-21 14:01:56.190 SLAPIN  00 00 00 00 00 00 7f 21 00 00 00 00 00 00 00 00   .......!........
   2009-01-21 14:01:56.190 SLAPIN  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
   2009-01-21 14:01:56.190 SLAPIN  00 00 00 00 00 00 00 00 00 7a 01 1f               .........z..    
 */


static void slap_msg_process(struct gateway_s *gw) {
	ss7_v2_header_t		*hdr=(ss7_v2_header_t *) &gw->slap.read.buffer;

	if (hdr->protocol_id != SLAP_MAGIC) {
		logwrite(LOG_ERROR, "SLAP packet without SLAP magic 0xdc for gateway %s", gw->name);
		slap_connection_drop(gw);
	}

	dump_hex(LOG_DEBUG, "SLAPIN ", gw->slap.read.buffer, slap_msg_len(hdr));

	/* Any packet acts as a heartbeat */
	slap_recvhb_extend(gw);

	switch(hdr->app_class) {
		case(SLAP_AC_HEARTBEAT):
			slap_msg_recvhb(gw, hdr);
			break;
		case(SLAP_AC_EVENT):
			slap_msg_recv_event(gw, hdr);
			break;
		case(SLAP_AC_REGISTER):
			slap_msg_recv_register(gw, hdr);
			break;
		default:
			logwrite(LOG_ERROR, "Unknown SLAP Message %02x from gateways %s",
					hdr->app_class, gw->name);
			dump_hex(LOG_DEBUG, "SLAPIN ", gw->slap.read.buffer, slap_msg_len(hdr));
			break;
	}

	/* FIXME: We want to make this more explicit - for now its okay */
	if (gw->slap.status == SLAP_CONNECTED)
		gw->slap.status=SLAP_ACTIVE;

	slap_msg_zap(gw);
}

static void slap_read(struct gateway_s *gw, int fd) {
	ssize_t		len;
	int		maxread;

	maxread=SLAP_BUFFER_SIZE-gw->slap.read.valid;

	len=read(fd, gw->slap.read.buffer+gw->slap.read.valid, maxread);

	if (len == 0) {
		logwrite(LOG_DEBUG, "SLAP connection from %s/%s dropped by remote", gw->name, inet_ntoa(gw->slap.addr.in));
		slap_connection_drop(gw);
		return;
	}

	gw->slap.read.valid+=len;

	/* Process all messages in the input buffer */
	while(slap_msg_complete(gw))
		slap_msg_process(gw);
}

int slap_call_drop(struct gateway_s *gw, int slot, int span, int chan, int callid) {
	struct slapmsg_s	slapmsg;

	slap_msg_create_cc(&slapmsg, SLAP_COMS_DISC_IND, slot, span, callid);
	slap_msg_cc_finish(&slapmsg);
	slap_send(gw, &slapmsg);
}

int slap_call_incoming(struct gateway_s *gw, int slot, int span, int chan,
		int bearer, char *anumber, char *number, int callid) {
	struct slapmsg_s	slapmsg;

	slap_msg_create_cc(&slapmsg, SLAP_COMS_SETUP_IND, slot, span, callid);
	slap_msg_cc_append_ie_bearer(&slapmsg, bearer);
	slap_msg_cc_append_ie_channelid(&slapmsg, chan);

	slap_msg_cc_finish(&slapmsg);

	slap_send(gw, &slapmsg);

	slap_sendhb_extend(gw);

	return 0;
}

static void slap_conn_callback(int fd, short event, void *arg) {
	struct gateway_s	*gw=arg;

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

	gw_set_status(gw, GW_STATUS_AVAIL);
}

static void slap_accept(int fd, short event, void *arg) {
	struct sockaddr_in	sin;
	struct gateway_s	*gw;
	int			socket;
	socklen_t		sinlen=sizeof(sin);

	if (event & EV_READ) {
		socket=accept(fd, (struct sockaddr *) &sin, &sinlen);
		if (socket < 0) {
			logwrite(LOG_ERROR, "accept returned error: %s", strerror(errno));
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

	logwrite(LOG_INFO, "Opened SLAP port %d for incoming connections", SLAP_PORT);

	socket_set_nonblock(slapsock);
	socket_listen(slapsock, 25);

	event_set(&slapevent, slapsock, EV_READ|EV_PERSIST, slap_accept, NULL);
	event_add(&slapevent, NULL);
}
