#ifndef MGCPSLAP_SLAP_H
#define MGCPSLAP_SLAP_H

#include "gw.h"

#define SLAP_MAXMSG_SIZE	524
#define SLAP_MSGHDR_MINLEN	12

enum {
	SLAP_INACTIVE = 0,
	SLAP_CONN_PROGRESS,
	SLAP_CONNECTED,
	SLAP_ACTIVE
};

/* Common message header format - SLAP Page 5 */
typedef struct {
	uint8_t		protocol_id;
	uint8_t		version;
	uint8_t		app_class;
	uint8_t		payload_len;

	uint32_t	chassis_id;
	uint32_t	location_id;
} ss7_v2_header_t;

void slap_init(void );
int slap_isactive(struct gateway_s *);
void slap_init_gateway(struct gateway_s *);

#endif
