#include <stdint.h>
#include <sys/types.h>
#include <event.h>

#include "mgcp.h"

int main(int argc, char **argv) {

	/* Initialize libevent */
	event_init();

	mgcp_init();

	/* Pigs can fly */
	event_dispatch();

	return 0;
}
