
#include <glib.h>
#include <stdlib.h>
#include <string.h>

#include "gw.h"
#include "slap.h"
#include "mgcp.h"
#include "logging.h"

static GHashTable	*gwtable;
static GList		*callfreelist=NULL;

static void gw_call_put(struct call_s *call) {
	logwrite(LOG_DEBUG, "returning call to freelist %p", call);
	callfreelist=g_list_concat(&call->list, callfreelist);
}

static struct call_s *gw_call_get(void ) {
	struct call_s		*call;
	GList			*first;

	first=g_list_first(callfreelist);

	if (!first) {
		call=g_slice_new0(struct call_s);

		call->list.data=call;

		logwrite(LOG_DEBUG, "returning newly allocated call %p", call);

		return call;
	}

	callfreelist=g_list_remove_link(callfreelist, first);

	logwrite(LOG_DEBUG, "returning call from freelist %p %p", first->data, first);

	return first->data;
}

void gw_slot_create(struct gateway_s *gw, int slot) {
	logwrite(LOG_DEBUG, "Createing slot on %s slot %d", gw->name, slot);
}

void gw_ds1_create(struct gateway_s *gw, int slot, int ds1) {
	logwrite(LOG_DEBUG, "Createing ds1 on %s slot %d ds1 %d", gw->name, slot, ds1);

	if (!gw->slot[slot].ds1[ds1])
		gw->slot[slot].ds1[ds1]=calloc(1, sizeof(struct ds1_s));
}

struct ds1_s *gw_ds1_get(struct gateway_s *gw, int slot, int ds1) {
	return gw->slot[slot].ds1[ds1];
}

struct ds0_s *gw_ds0_get(struct gateway_s *gw, int slot, int ds1no, int ds0no) {
	struct ds1_s	*ds1=gw_ds1_get(gw, slot, ds1no);

	if (!ds1)
		return NULL;

	return &ds1->ds0[ds0no];
}

void gw_ds0_set_status(struct gateway_s *gw, int slot, int span, int chan, int status) {
	struct ds1_s *ds1=gw_ds1_get(gw, slot, span);

	if (!ds1)
		return;

	ds1->ds0[chan].status=status;
}

void gw_ds1_set_status(struct gateway_s *gw, int slot, int span, int status) {
	struct ds1_s *ds1=gw_ds1_get(gw, slot, span);

	if (!ds1)
		return;

	if (ds1->status != DS1_STATUS_UP) {
		if (status == DS1_STATUS_UP) {
			mgcp_send_rsip_span(gw, slot, span, MGCP_RSIP_RESTART, 0);
		}
	} else if (ds1->status == DS1_STATUS_UP) {
		if (status != DS1_STATUS_UP) {
			mgcp_send_rsip_span(gw, slot, span, MGCP_RSIP_FORCED, 0);
		}
	}

	ds1->status=status;
}

void gw_slot_set_status(struct gateway_s *gw, int slot, int status) {
	int	i;
	if (status == 2) {
		for(i=0;i<3;i++)
			gw_ds1_set_status(gw, slot, i, DS1_STATUS_UNKNOWN);
	}
	gw->slot[slot].status=status;
}

void gw_set_status(struct gateway_s *gw, int status) {
	if (gw->status != GW_STATUS_AVAIL)
		if (status == GW_STATUS_AVAIL)
			mgcp_send_rsip_gw(gw, MGCP_RSIP_RESTART, 5);

	if (gw->status == GW_STATUS_AVAIL)
		if (status != GW_STATUS_AVAIL)
			mgcp_send_rsip_gw(gw, MGCP_RSIP_FORCED, 0);

	gw->status=status;
}

int gw_ds0_idle(struct ds0_s *ds0) {
	return (ds0->status == DS0_IDLE);
}

/* Okay - this is tricky - we need a callid for SLAP and
   for MGCP for later reference.

   MGCP has a HEX string and SLAP uses a 15 bit identifier
   with an identifier of 0 beeing illegal.

 */
int gw_callid_next(struct gateway_s *gw) {
	gw->callid++;
	gw->callid&=0x7fff;
	if (gw->callid == 0)
		gw->callid++;

	/* FIXME: Check for existing callid */
	return gw->callid;
}

static void gw_call_delete(int fd, short event, void *arg) {
	struct call_s	*call=arg;

	if (call->status != CALL_IDLE) {
		logwrite(LOG_ERROR, "Call delete called with non idle CALL gateway %s callid %d",
			call->ep.gw->name, call->callid);
	}

	g_hash_table_remove(call->ep.gw->calltable, &call->callid);
	gw_call_put(call);
}

void gw_call_deltimer_start(struct call_s *call) {
	call->tv.tv_sec=CALL_TIMER_DEL;
	call->tv.tv_usec=0;

	evtimer_set(&call->timer, &gw_call_delete, call);
	evtimer_add(&call->timer, &call->tv);
}

void gw_slap_call_drop_req(struct gateway_s *gw, int callid) {
	struct call_s	*call;

	logwrite(LOG_ERROR, "Call drop from SLAP - callid %d gw %s", callid, gw->name);

	call=g_hash_table_lookup(gw->calltable, &callid);

	if (!call) {
		logwrite(LOG_ERROR, "Unknown callid in deny from SLAP - callid %d gw %s", callid, gw->name);
		return;
	}

	call->status=CALL_DROP;

	mgcp_call_drop_req(&call->ep, callid);
}

void gw_slap_call_drop_ack(struct gateway_s *gw, int callid) {
	struct call_s	*call;

	logwrite(LOG_DEBUG, "Call drop ack from SLAP - callid %d gw %s", callid, gw->name);

	call=g_hash_table_lookup(gw->calltable, &callid);

	if (!call) {
		logwrite(LOG_ERROR, "Unknown callid in dropack from SLAP - callid %d gw %s", callid, gw->name);
		return;
	}

	mgcp_call_drop_ack(&call->ep, call->mgcpmsgid, callid);

	call->status=CALL_IDLE;
	call->ds0->status=DS0_IDLE;

	gw_call_deltimer_start(call);
	call->ds0->call=NULL;
}

void gw_mgcp_call_drop_ack(struct gateway_s *gw, int connid) {
	struct call_s	*call;

	call=g_hash_table_lookup(gw->calltable, &connid);

	if (!call) {
		logwrite(LOG_ERROR, "Could not find ConnectionID %x from %s",
				connid, gw->name);
		return;
	}

	call->status=CALL_IDLE;
	call->ds0->status=DS0_IDLE;

	gw_call_deltimer_start(call);
	call->ds0->call=NULL;
}

void gw_mgcp_call_drop_req(struct endpoint_s *ep, int mgcpmsgid, int connid) {
	struct call_s	*call;

	if (connid) {
		call=g_hash_table_lookup(ep->gw->calltable, &connid);

		if (!call) {
			logwrite(LOG_ERROR, "Could not find ConnectionID %x from %s", connid, ep->gw->name);
			return;
		}
	} else {
		struct ds0_s *ds0;
		ds0=gw_ds0_get(ep->gw, ep->slot, ep->span, ep->chan);

		if (!ds0) {
			logwrite(LOG_ERROR, "Could not find DS0 from endpoint %s %d %d %d",
				ep->gw->name, ep->slot, ep->span, ep->chan);
			return;
		}
		if (!ds0->call) {
			logwrite(LOG_ERROR, "No call on DS0 from endpoint %s %d %d %d",
				ep->gw->name, ep->slot, ep->span, ep->chan);
			return;

		}
		call=ds0->call;
	}

	call->mgcpmsgid=mgcpmsgid;

	call->status=CALL_DROP;

	slap_call_drop(call->ep.gw, call->ep.slot, call->ep.span, call->ep.chan, call->callid);
}

void gw_slap_call_proceed(struct gateway_s *gw, int callid) {
	struct call_s	*call;

	logwrite(LOG_DEBUG, "Call proceed from SLAP - callid %d gw %s", callid, gw->name);

	call=g_hash_table_lookup(gw->calltable, &callid);

	if (!call) {
		logwrite(LOG_ERROR, "Unknown callid in proceed from SLAP - callid %d gw %s", callid, gw->name);
		return;
	}

	call->status=CALL_ESTABLISHED;

	mgcp_call_proceed(&call->ep, call->mgcpmsgid, callid);
}

int gw_mgcp_call_setup(struct endpoint_s *ep, int mgcpmsgid,
		char *anumber, char *bnumber, int bearer) {
	struct ds0_s	*ds0=gw_ds0_get(ep->gw, ep->slot, ep->span, ep->chan);
	struct call_s	*call=gw_call_get();
#if 0
	if (!gw_ds0_idle(ds0)) {
		mgcp_send_busy(ep, mgcpmsgid);
		return 0;
	}
#endif

	call->ds0=ds0;
	ds0->call=call;

	call->status=CALL_INCOMING;
	ds0->status=DS0_BUSY;

	memcpy(&call->ep, ep, sizeof(struct endpoint_s));
	strncpy(call->anumber, anumber, NUMBER_MAX_SIZE);
	strncpy(call->bnumber, bnumber, NUMBER_MAX_SIZE);

	call->callid=gw_callid_next(ep->gw);
	call->bearertype=bearer;

	/* Store msgid for later status response messages */
	call->mgcpmsgid=mgcpmsgid;

	g_hash_table_insert(ep->gw->calltable, &call->callid, call);

	slap_call_incoming(ep->gw, ep->slot, ep->span, ep->chan,
		bearer, call->anumber, call->bnumber, call->callid);

	return call->callid;
}

void gw_slap_call_deny(struct gateway_s *gw, int callid) {
	struct call_s	*call;

	logwrite(LOG_ERROR, "Call deny from SLAP - callid %d gw %s", callid, gw->name);

	call=g_hash_table_lookup(gw->calltable, &callid);

	if (!call) {
		logwrite(LOG_ERROR, "Unknown callid in deny from SLAP - callid %d gw %s", callid, gw->name);
		return;
	}

	mgcp_call_deny(&call->ep, call->mgcpmsgid, callid);

	call->status=CALL_IDLE;
	call->ds0->status=DS0_IDLE;

	gw_call_deltimer_start(call);
	call->ds0->call=NULL;
}


struct gateway_s *gw_lookup(char *name) {
	return g_hash_table_lookup(gwtable, name);
}

struct gateway_s *gw_create(char *name) {
	struct gateway_s	*gw;

	logwrite(LOG_INFO, "Created gateway with name %s", name);

	gw=calloc(1, sizeof(struct gateway_s));

	strncpy(gw->name, name, sizeof(gw->name));

	g_hash_table_insert(gwtable, gw->name, gw);
	gw->calltable=g_hash_table_new(g_int_hash, g_int_equal);

	slap_init_gateway(gw);
	mgcp_init_gateway(gw);

	return gw;
}

struct gateway_s *gw_lookup_or_create(char *name) {
	struct gateway_s	*gw;

	gw=gw_lookup(name);
	if (gw)
		return gw;

	return gw_create(name);
}

int gw_init(void ) {
	gwtable=g_hash_table_new(g_str_hash, g_str_equal);

	return 0;
}
