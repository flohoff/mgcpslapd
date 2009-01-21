
#include <glib.h>
#include <stdlib.h>
#include <string.h>

#include "gw.h"
#include "slap.h"
#include "mgcp.h"
#include "logging.h"

GHashTable		*gwtable;

int gw_create_ds1(struct gateway_s *gw, int slot, int ds1) {
	if (gw->slot[slot].ds1[ds1])
		return 1;

	gw->slot[slot].ds1[ds1]=calloc(1, sizeof(struct ds1_s));

	return 1;
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
