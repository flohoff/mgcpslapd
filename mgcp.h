#include "gw.h"

enum {
	MGCP_RSIP_RESTART,
	MGCP_RSIP_FORCED
};

int mgcp_init(void );
void mgcp_init_gateway(struct gateway_s *gw);
void mgcp_send_rsip_span(struct gateway_s *gw, int slot, int span, int restart, int delay);
void mgcp_send_rsip_gw(struct gateway_s *gw, int restart, int delay);
void mgcp_send_busy(struct endpoint_s *ep, int msgid);
