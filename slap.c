#include <event.h>
#include <evdns.h>
#include <sys/time.h>
#include <sys/param.h>

#include "gw.h"
#include "slap.h"
#include "logging.h"

int slap_isactive(struct gateway_s *gw) {
	return (gw->slap.status == SLAP_ACTIVE);
}

#define DNS_FAIL_RETRY_TIME	60
#define DNS_REFRESH_TIME	300

static void slap_dns_callback(int result, char type, int count, int ttl, void *addresses, void *arg);

static void slap_dns_resolve(int fd, short event, void *arg) {
	struct gateway_s	*gw=arg;
	evdns_resolve_ipv4(gw->name, 0, slap_dns_callback, gw);
}

static void slap_dns_retry(int time, struct gateway_s *gw) {

	gw->slap.addr.tv.tv_sec=time;
	gw->slap.addr.tv.tv_usec=0;

	evtimer_set(&gw->slap.addr.timer, &slap_dns_resolve, gw);
	evtimer_add(&gw->slap.addr.timer, &gw->slap.addr.tv);
}

static void slap_init_connection(struct gateway_s *gw) {
	logwrite(LOG_DEBUG, "Init connection called for gateway %s", gw->name);
}

static void slap_dns_callback(int result, char type, int count,
			int ttl, void *addresses, void *arg) {

	struct gateway_s	*gw=arg;
	uint32_t		addr;

	if (result != DNS_ERR_NONE || type != DNS_IPv4_A) {
		slap_dns_retry(DNS_FAIL_RETRY_TIME, gw);
		return;
	}

	if (count != 1)
		logwrite(LOG_ERROR, "dns resolve of %s returned %d records - using first", gw->name, count);

	addr=*((uint32_t *) addresses);

	if (addr != gw->slap.addr.in.s_addr) {
		if (!slap_isactive(gw)) {
			gw->slap.addr.in.s_addr=addr;
			slap_init_connection(gw);
		} else {
			logwrite(LOG_ERROR, "slap connection up and address change for gateway %s", gw->name);
		}
	}

	slap_dns_retry(MIN(DNS_REFRESH_TIME, ttl), gw);
}

static void slap_dns_init(struct gateway_s *gw) {
	evdns_resolve_ipv4(gw->name, 0, slap_dns_callback, gw);
}

void slap_init_gateway(struct gateway_s *gw) {
	slap_dns_init(gw);
}

void slap_init(void ) {

}
