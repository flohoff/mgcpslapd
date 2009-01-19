#include <stdint.h>
#include <sys/types.h>
#include <event.h>
#include <evdns.h>

#include "mgcp.h"
#include "slap.h"
#include "gw.h"

int main(int argc, char **argv) {

	/* Initialize libevent */
	event_init();
	evdns_init();
	//evdns_resolv_conf_parse(DNS_OPTION_NAMESERVERS|DNS_OPTION_SEARCH, "/etc/resolv.conf");

	gw_init();
	mgcp_init();
	slap_init();

	/* Pigs can fly */
	event_dispatch();

	return 0;
}
