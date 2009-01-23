
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <event.h>
#include <evdns.h>
#include <ctype.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <glib.h>

#include "socket.h"
#include "valstring.h"
#include "logging.h"
#include "gw.h"
#include "slap.h"
#include "mgcp.h"
#include "util.h"

#define MGCP_PORT	2427
#define MAX_BUFFER	4096

static int		mgcpsock;
static int		nextmsgid;
static struct event	mgcpsockevent;
GList			*pktfreelist=NULL;
GHashTable		*sendpkttable;

#define MGCP_MAX_LINES		64
#define MGCP_MAX_CMDPART	8

enum {
	PKT_TYPE_COMMAND,
	PKT_TYPE_RESULT
};

struct mgcppkt_s {
	GList			list;

	int			type;		/* Command or Result */

	struct gateway_s	*gw;

	int			verb;		/* e.g. MGCP_VERB_AUEP if type=MGCP_TYPE_COMMAND */
	int			result;		/* 200 if type=MGCP_TYPE_RESULT*/
	int			msgid;

	GString			*resultstr;
	GString			*endpoint;
	GString			*body;

	GString			*msg;
	int			ack;
	int			sent;
	struct event		timer;
	struct timeval		tv;
};

struct sepstr_s {
	char	*ptr;
	int	len;
};

enum {
	MGCP_VERB_UNKNOWN = 0,
	MGCP_VERB_AUEP,
	MGCP_VERB_RSIP,
	MGCP_VERB_CRCX,
	MGCP_VERB_DLCX,
	MGCP_VERB_MDCX,
};

static valstring mgcpverb[] = {
	{ MGCP_VERB_AUEP,	"AUEP" },
	{ MGCP_VERB_RSIP,	"RSIP" },
	{ MGCP_VERB_CRCX,	"CRCX" },
	{ MGCP_VERB_DLCX,	"DLCX" },
	{ MGCP_VERB_MDCX,	"MDCX" },
	{ 0, NULL },
};

static valstring rsipstr[] = {
	{ MGCP_RSIP_RESTART,	"restart" },
	{ MGCP_RSIP_FORCED,	"forced" },
	{ 0, NULL },
};

enum {
	MGCP_L_UNKNOWN = 0,
	MGCP_L_E,
	MGCP_L_NASBT,
	MGCP_L_NASCDN,
	MGCP_L_NASCGN,
};

static valstring localoption[] = {
	{ MGCP_L_E,		"e" },
	{ MGCP_L_NASBT,		"nas/bt" },
	{ MGCP_L_NASCDN,	"nas/cdn" },
	{ MGCP_L_NASCGN,	"nas/cgn" },
	{ 0, NULL },
};

enum {
	MGCP_BT_UNKNOWN = 0,
	MGCP_BT_MODEM,
	MGCP_BT_DIGITAL,
};

static valstring bearertype[] = {
	{ MGCP_BT_MODEM,	"modem" },
	{ MGCP_BT_DIGITAL,	"digital" },
	{ 0, NULL },
};

#
#define MAX_MSG_SIZE		512
#define MAX_BODY_SIZE		512
#define MAX_EP_SIZE		64
#define MAX_RESULTSTR_SIZE	32

static void mgcp_pkt_put(struct mgcppkt_s *pkt) {
	logwrite(LOG_DEBUG, "returning pkt to list %p", pkt);

	g_string_erase(pkt->msg, 0, -1);
	g_string_erase(pkt->endpoint, 0, -1);
	g_string_erase(pkt->body, 0, -1);
	g_string_erase(pkt->resultstr, 0, -1);

	pktfreelist=g_list_concat(&pkt->list, pktfreelist);
}

static struct mgcppkt_s *mgcp_pkt_get(void ) {
	struct mgcppkt_s	*pkt;
	GList			*first;

	first=g_list_first(pktfreelist);

	if (!first) {
		pkt=g_slice_new0(struct mgcppkt_s);

		pkt->msg=g_string_sized_new(MAX_MSG_SIZE);
		pkt->endpoint=g_string_sized_new(MAX_EP_SIZE);
		pkt->body=g_string_sized_new(MAX_BODY_SIZE);
		pkt->resultstr=g_string_sized_new(MAX_RESULTSTR_SIZE);

		pkt->list.data=pkt;

		logwrite(LOG_DEBUG, "returning newly allocated pkt %p", pkt);

		return pkt;
	}

	pktfreelist=g_list_remove_link(pktfreelist, first);

	logwrite(LOG_DEBUG, "returning pkt from list %p %p", first->data, first);

	return first->data;
}

#if 0
static int mgcp_splitbuffer_copy(char *dest, char *buffer, int len,
	char *sep, struct sepstr_s *parts, int maxparts) {
	int	i=0,j=0;

	parts->ptr=dest;
	parts->len=0;

	while(i<len && j<maxparts) {
		/* Find char in sep haystack */
		if (!strchr(sep, buffer[i])) {
			parts->len++;
			dest[i]=buffer[i];
		} else {
			dest[i++]=0x0;

			parts++;
			j++;
			parts->ptr=dest+i;
			parts->len=0;
		}
		i++;
	}

	if (parts->len == 0)
		parts[0].ptr=NULL;
	else
		parts[1].ptr=NULL;

	return (parts->len) ? j+1 : j;
}
#endif

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

	if (parts->len == 0)
		parts[0].ptr=NULL;
	else
		parts[1].ptr=NULL;

	return (parts->len) ? j+1 : j;
}

static int mgcp_pkt_complete(struct mgcppkt_s *pkt) {


	if (pkt->type == PKT_TYPE_COMMAND) {
		const char	*verb;

		verb=vstr_val2str(mgcpverb, pkt->verb, NULL);

		pkt->msgid=nextmsgid++;

		if (!verb)
			return 0;

		/* Command msg */
		g_string_printf(pkt->msg, "%s %d %s@%s MGCP 1.0\n%s",
			verb,
			pkt->msgid,
			pkt->endpoint->str,
			pkt->gw->name,
			pkt->body->str);

	} else {

		/* Result msg */
		g_string_printf(pkt->msg, "%d %d %s\n%s",
			pkt->result,
			pkt->msgid,
			pkt->resultstr->str,
			pkt->body->str);
	}
	return 1;
}

static void mgcp_pkt_send_pure(struct mgcppkt_s *pkt) {
	int		rc;

	dump_hex(LOG_DEBUG, "MGCPOUT ", (uint8_t *) pkt->msg->str, pkt->msg->len);

	rc=sendto(mgcpsock,
		pkt->msg->str, pkt->msg->len+1,
		0,
		(struct sockaddr *) &pkt->gw->mgcp.addr.sin,
		sizeof(struct sockaddr_in));

	if (rc<0) {
		logwrite(LOG_ERROR, "sendto failed with %s", strerror(errno));
	}

	pkt->sent++;
}

static void mgcp_pkt_retranstimer_start(struct mgcppkt_s *pkt);

#define MGCP_PKT_DELETE		30
#define MGCP_PKT_RETRY_TIMER	3
#define MGCP_PKT_RETRANSMIT	5

static void mgcp_pkt_delete(int fd, short event, void *arg) {
	struct mgcppkt_s	*pkt=arg;

	g_hash_table_remove(sendpkttable, &pkt->msgid);

	mgcp_pkt_put(pkt);
}

static void mgcp_pkt_deltimer_start(struct mgcppkt_s *pkt) {
	pkt->tv.tv_sec=MGCP_PKT_DELETE;
	pkt->tv.tv_usec=0;

	evtimer_set(&pkt->timer, &mgcp_pkt_delete, pkt);
	evtimer_add(&pkt->timer, &pkt->tv);
}


static void mgcp_pkt_retransmit(int fd, short event, void *arg) {
	struct mgcppkt_s	*pkt=arg;

	mgcp_pkt_send_pure(pkt);

	if (pkt->sent < MGCP_PKT_RETRANSMIT)
		mgcp_pkt_retranstimer_start(pkt);
	else
		mgcp_pkt_deltimer_start(pkt);
}

static void mgcp_pkt_retranstimer_stop(struct mgcppkt_s *pkt) {
	evtimer_del(&pkt->timer);
}

static void mgcp_pkt_retranstimer_start(struct mgcppkt_s *pkt) {
	pkt->tv.tv_sec=MGCP_PKT_RETRY_TIMER;
	pkt->tv.tv_usec=0;

	evtimer_set(&pkt->timer, &mgcp_pkt_retransmit, pkt);
	evtimer_add(&pkt->timer, &pkt->tv);
}

static void mgcp_pkt_send(struct mgcppkt_s *pkt) {

	if (!mgcp_pkt_complete(pkt)) {
		logwrite(LOG_ERROR, "MGCP pkt complete failed");
		mgcp_pkt_put(pkt);
		return;
	}

	mgcp_pkt_send_pure(pkt);

	logwrite(LOG_ERROR, "MGCP - adding msgid %d", pkt->msgid);
	g_hash_table_insert(sendpkttable, &pkt->msgid, pkt);

	/*
	 * In case of a command retransmit
	 * In case of a reply start delete timer
	 */
	if (pkt->type == PKT_TYPE_COMMAND)
		mgcp_pkt_retranstimer_start(pkt);
	else
		mgcp_pkt_deltimer_start(pkt);
}

void mgcp_send_rsip_span(struct gateway_s *gw, int slot, int span, int restart, int delay) {
	struct mgcppkt_s	*pkt;

	pkt=mgcp_pkt_get();

	pkt->gw=gw;
	pkt->type=PKT_TYPE_COMMAND;
	pkt->verb=MGCP_VERB_RSIP;
	g_string_printf(pkt->endpoint, "S/%d/ds1-%d/*", slot+1, span);
	g_string_printf(pkt->body, "RM: %s\nRD: %d\n",
		vstr_val2str(rsipstr, restart, "restart"), delay);

	mgcp_pkt_send(pkt);
}

void mgcp_send_rsip_gw(struct gateway_s *gw, int restart, int delay) {
	struct mgcppkt_s	*pkt;

	pkt=mgcp_pkt_get();

	pkt->gw=gw;
	pkt->type=PKT_TYPE_COMMAND;
	pkt->verb=MGCP_VERB_RSIP;
	g_string_printf(pkt->endpoint, "*");
	g_string_printf(pkt->body, "RM: %s\nRD: %d\n",
		vstr_val2str(rsipstr, restart, "restart"), delay);

	mgcp_pkt_send(pkt);
}

void mgcp_init_gateway(struct gateway_s *gw) {

}

/* Parse endpoint into seperate struct. This is slow as hell but
   correctness first.

   FIXME: Speed up

   S3/DS1-1/1@t3COM-verl-de01
 */
static struct endpoint_s *mgcp_parse_endpoint(char *epstr) {
	struct endpoint_s	*ep;
	gchar			**result;
	int			ns;

	result=g_regex_split_simple("^s(\\d+)/ds1-(\\d+)/(\\d+)@(.*)$", epstr, G_REGEX_CASELESS, 0);

	for(ns=0;result[ns];ns++);

	if (ns < 5) {
		logwrite(LOG_ERROR, "Endpoint %s unparsable %d", epstr, ns);
		return NULL;
	}

	ep=g_slice_new0(struct endpoint_s);

	ep->slot=strtol(result[1], NULL, 10);
	ep->span=strtol(result[2], NULL, 10);
	ep->chan=strtol(result[3], NULL, 10);

	/* Copy the domain part lowercase 0 terminated */
	for(ns=0;result[4][ns];ns++)
		ep->domain[ns]=tolower(result[4][ns]);
	ep->domain[ns]=0x0;

	g_strfreev(result);

	return ep;
}

static struct endpoint_s *mgcp_get_endpoint(char *epstr) {
	struct endpoint_s	*ep;

	/* Split endpoint at the @ */
	ep=mgcp_parse_endpoint(epstr);
	if (!ep)
		return NULL;

	ep->gw=gw_lookup_or_create(ep->domain);

	return ep;
}

enum {
	MGCP_EP_UNKNOWN = 0,
	MGCP_EP_TEMPUNAVAIL,
	MGCP_EP_AVAIL
};

static int mgcp_endpoint_status(struct endpoint_s *ep) {
	if (!ep->gw)
		return MGCP_EP_UNKNOWN;

	return MGCP_EP_AVAIL;
}
 /*
  * 2009-01-23 09:22:53.498 MGCPIN  43 52 43 58 20 32 31 35 20 73 33 2f 64 73 31 2d   CRCX 215 s3/ds1-
  * 2009-01-23 09:22:53.498 MGCPIN  31 2f 31 40 74 33 63 6f 6d 2d 76 65 72 6c 2d 64   1/1@t3com-verl-d
  * 2009-01-23 09:22:53.498 MGCPIN  65 30 31 20 4d 47 43 50 20 31 2e 30 0a 43 3a 20   e01 MGCP 1.0.C: 
  * 2009-01-23 09:22:53.498 MGCPIN  33 0a 4c 3a 20 65 3a 6f 66 66 2c 6e 61 73 2f 62   3.L: e:off,nas/b
  * 2009-01-23 09:22:53.498 MGCPIN  74 3a 6d 6f 64 65 6d 2c 6e 61 73 2f 63 64 6e 3a   t:modem,nas/cdn:
  * 2009-01-23 09:22:53.498 MGCPIN  34 39 35 32 34 31 39 30 38 35 31 30 36 2c 6e 61   4952419085106,na
  * 2009-01-23 09:22:53.498 MGCPIN  73 2f 63 67 6e 3a 34 39 35 32 34 36 38 30 31 31   s/cgn:4952468011
  * 2009-01-23 09:22:53.498 MGCPIN  38 35 0a 4d 3a 20 6e 61 73 2f 64 61 74 61 0a 52   85.M: nas/data.R
  * 2009-01-23 09:22:53.498 MGCPIN  3a 20 6e 61 73 2f 61 75 28 4e 29 2c 6e 61 73 2f   : nas/au(N),nas/
  * 2009-01-23 09:22:53.498 MGCPIN  61 78 28 4e 29 2c 6e 61 73 2f 6f 66 28 4e 29 0a   ax(N),nas/of(N).
  * 2009-01-23 09:22:53.498 MGCPIN  53 3a 20 20 0a 58 3a 20 44 36 0a                  S:  .X: D6.     
  */

struct localconnect_s {
	int	bearer;
	char	*anumber;
	char	*bnumber;

	struct {
		char	*token;
		char	*value;
	} tv[25];

	char	buffer[128];
};

struct sepstr_s *mgcp_line_find(struct sepstr_s *lines, char *prefix) {
	int	len=strlen(prefix);
	while(lines->ptr) {
		if (strncasecmp(lines->ptr, prefix, len) == 0)
			return lines;
		lines++;
	}
	return NULL;
}

/* L: e:off,nas/bt:modem,nas/cdn:4952419085106,nas/cgn:495246801185 */
static int mgcp_parse_localconnect(struct sepstr_s *lines, struct localconnect_s *lc) {
	struct sepstr_s	*local;
	char		*l, *dst;
	int		i;

	local=mgcp_line_find(lines, "L:");

	if (!local) {
		logwrite(LOG_ERROR, "Could not find an L: line");
		return 0;
	}

	if (local->len > sizeof(lc->buffer)) {
		logwrite(LOG_ERROR, "lc->buffer too small %d vs %d", local->len, sizeof(lc->buffer));
		return 0;
	}

	/* Skip L: and an arbitrary number of spaces */
	l=local->ptr+2;
	while(*l == ' ' || *l == '\t')
		l++;

	/* Split L: line into token/value pairs */
	i=0;
	dst=lc->buffer;
	lc->tv[i].token=dst;
	while(*l) {
		switch(*l) {
			case(':'):
				*dst++=0x0;
				lc->tv[i].value=dst;
				break;
			case(','):
				*dst++=0x0;
				i++;
				lc->tv[i].token=dst;
				lc->tv[i].value=NULL;
				break;
			case('\n'):
			case('\r'):
				break;
			default:
				*dst++=*l;
				break;
		}
		l++;
	}

	*dst++=0x0;

	i++;
	lc->tv[i].token=NULL;
	lc->tv[i].value=NULL;

	for(i=0;lc->tv[i].token;i++) {
		int	value;
		if (!vstr_str2val(lc->tv[i].token, localoption, &value)) {
			logwrite(LOG_ERROR, "Unknown L: option %s", lc->tv[i].token);
			continue;
		}

		switch(value) {
			case(MGCP_L_NASBT):
				if(!vstr_str2val(lc->tv[i].value, bearertype, &lc->bearer))
					logwrite(LOG_ERROR, "Unknown bearer type %s", lc->tv[i].value);
				break;
			case(MGCP_L_NASCDN):
				lc->bnumber=lc->tv[i].value;
				break;
			case(MGCP_L_NASCGN):
				lc->anumber=lc->tv[i].value;
				break;
		}
	}
	return 1;
}

static void mgcp_process_crcx(struct sepstr_s *lines, int verb, int msgid, struct endpoint_s *ep) {
	struct localconnect_s	lc;

	if (!mgcp_parse_localconnect(lines, &lc))
		return;

	logwrite(LOG_DEBUG, "CRCX from %s to %s type %s", lc.anumber, lc.bnumber,
		vstr_val2str(bearertype, lc.bearer, "Unknown"));

}
/*
	AUEP 900339904 S3/DS1-1/1@t3COM-verl-de01 MGCP 1.0
	F:
*/

static void mgcp_process_auep(struct sepstr_s *lines, int verb, int msgid, struct endpoint_s *ep) {
	struct mgcppkt_s	*pkt;

	pkt=mgcp_pkt_get();

	pkt->type=PKT_TYPE_RESULT;
	pkt->gw=ep->gw;
	pkt->msgid=msgid;

	switch(mgcp_endpoint_status(ep)) {
		case(MGCP_EP_AVAIL):
			pkt->result=200;
			g_string_printf(pkt->resultstr, "ok");
			break;
		case(MGCP_EP_UNKNOWN):
			pkt->result=500;
			g_string_printf(pkt->resultstr, "Endpoint unknown");
			break;
		default:
			pkt->result=405;
			g_string_printf(pkt->resultstr, "Restarting");
			break;
	}

	mgcp_pkt_send(pkt);

	return;
}

static void mgcp_cmdmsg_parse(struct sepstr_s *lines, int verb, int msgid, struct endpoint_s *ep) {
	switch(verb) {
		case(MGCP_VERB_AUEP):
			mgcp_process_auep(lines, verb, msgid, ep);
			break;
		case(MGCP_VERB_CRCX):
			mgcp_process_crcx(lines, verb, msgid, ep);
			break;
		default:
			logwrite(LOG_ERROR, "MGCP unhandled VERB %s/%d", vstr_val2str(mgcpverb, verb, "n/a"), verb);
			break;
	}
}

static void mgcp_update_address(struct gateway_s *gw, struct sockaddr_in *sin) {
	/* Copy originating address if we dont have any */
	if (!gw->mgcp.addr.sin.sin_addr.s_addr)
		memcpy(&gw->mgcp.addr.sin, sin, sizeof(struct sockaddr_in));
}

static void mgcp_respmsg_parse(struct sepstr_s *lines, int result, int msgid) {
	struct mgcppkt_s	*pkt;

	pkt=g_hash_table_lookup(sendpkttable, &msgid);

	if (!pkt) {
		logwrite(LOG_ERROR, "Got response for unknown msgid %d", msgid);
		return;
	}

	pkt->ack++;

	mgcp_pkt_retranstimer_stop(pkt);
	mgcp_pkt_deltimer_start(pkt);
}

static void mgcp_msg_process(struct sepstr_s *lines, int nolines, struct sockaddr_in *sin) {
	struct sepstr_s		cmd[MGCP_MAX_CMDPART];
	int			cmdparts;
	struct endpoint_s	*ep;
	int			msgid;
	int			verbid;
	int			result;

	cmdparts=mgcp_splitbuffer(lines[0].ptr, lines[0].len, 0x20, cmd, MGCP_MAX_CMDPART);

	/* FIXME - need to check for parsability */
	msgid=strtol(cmd[1].ptr, NULL, 10);

	/* Is it a response ? */
	if  (*cmd[0].ptr >= '0' && *cmd[0].ptr <= '9') {
		result=strtol(cmd[0].ptr, NULL, 10);

		mgcp_respmsg_parse(lines+1, result, msgid);
	} else {
		if (!vstr_str2val(cmd[0].ptr, mgcpverb, &verbid)) {
			logwrite(LOG_DEBUG, "MGCP verb not found %s", cmd[0]);
			return;
		}

		ep=mgcp_get_endpoint(cmd[2].ptr);

		mgcp_update_address(ep->gw, sin);
		mgcp_cmdmsg_parse(lines+1, verbid, msgid, ep);

		g_slice_free(struct endpoint_s, ep);
	}
}

static void mgcp_read_pktin(char *buffer, int len, struct sockaddr_in *sin) {
	struct sepstr_s		lines[MGCP_MAX_LINES];
	int			l, i, j;

	l=mgcp_splitbuffer(buffer, len, 0x0a, lines, MGCP_MAX_LINES);

	if (l == MGCP_MAX_LINES)
		logwrite(LOG_ERROR, "MGCP packet contained MGCP_MAX_LINES %d\n", l);

	/* We may have piggypacked messages seperated by a "." line - Try to find
	 * end of message and process one after another
	 */
	i=0;
	while(i<l) {
		j=i;
		for(;i<l;i++)
			if (lines[i].len == 1 && *lines[i].ptr == '.')
				break;

		logwrite(LOG_DEBUG, "Split packet: j %d i %d l %d", i, j, l);

		mgcp_msg_process(&lines[j], i-j, sin);
	}
}

static void mgcp_read(int fd, short event, void *arg) {
	char			buffer[MAX_BUFFER];
	struct sockaddr_in	sin;
	ssize_t			len;
	socklen_t		sinlen=sizeof(sin);

	len=recvfrom(fd, &buffer, MAX_BUFFER, 0,
			 (struct sockaddr *) &sin, &sinlen);

	dump_hex(LOG_DEBUG, "MGCPIN ", (uint8_t *) buffer, len);

	mgcp_read_pktin(buffer, len, &sin);
}

int mgcp_init(void ) {

	sendpkttable=g_hash_table_new(g_int_hash, g_int_equal);

	mgcpsock=socket_open(NULL, MGCP_PORT, IPPROTO_UDP);
	socket_set_nonblock(mgcpsock);

	event_set(&mgcpsockevent, mgcpsock,
		EV_READ|EV_PERSIST, mgcp_read, NULL);
	event_add(&mgcpsockevent, NULL);

	/* FIXME - Need to better initialize */
	nextmsgid=1;

	return 0;
}

