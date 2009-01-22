
#include <glib.h>
#include <stdlib.h>
#include <string.h>

#include "gw.h"
#include "slap.h"
#include "mgcp.h"
#include "logging.h"

GHashTable		*gwtable;

struct ds1_s *gw_ds1_get_or_create(struct gateway_s *gw, int slot, int ds1) {
	if (!gw->slot[slot].ds1[ds1])
		gw->slot[slot].ds1[ds1]=calloc(1, sizeof(struct ds1_s));

	return gw->slot[slot].ds1[ds1];
}

void gw_ds1_set_status(struct gateway_s *gw, int slot, int span, int status) {
	struct ds1_s *ds1=gw_ds1_get_or_create(gw, slot, span);

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

void gw_ds0_set_status(struct gateway_s *gw, int slot, int span, int chan, int status) {
	struct ds1_s *ds1=gw_ds1_get_or_create(gw, slot, span);
	ds1->ds0[chan].status=status;
}

void gw_slot_set_status(struct gateway_s *gw, int slot, int status) {
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

struct gateway_s *gw_lookup(char *name) {
	return g_hash_table_lookup(gwtable, name);
}

struct gateway_s *gw_create(char *name) {
	struct gateway_s	*gw;

	logwrite(LOG_INFO, "Created gateway with name %s", name);

	gw=calloc(1, sizeof(struct gateway_s));

	strncpy(gw->name, name, sizeof(gw->name));

	g_hash_table_insert(gwtable, gw->name, gw);

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
