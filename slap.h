#ifndef MGCPSLAP_SLAP_H
#define MGCPSLAP_SLAP_H

#include "gw.h"

#define SLAP_MSGHDR_LEN		12

#define SLAP_HB_TIME_NE		15
#define SLAP_HB_FAILCOUNT	3
#define SLAP_HB_TIME_FE		15

#define SLAP_MAGIC		0xdc
#define SLAP_VERSION		0x01

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

typedef struct {
	uint32_t	esig;
	uint32_t	slot;
	uint16_t	status;
} status_chg_t;

typedef struct {
	uint8_t		msg_type;
	uint8_t		ds1_id;

	uint8_t		CES;
	uint8_t		reserved_1;
	uint8_t		reserved_2;
	uint8_t		call_id_msb;
	uint8_t		call_id_lsb;
	uint8_t		len_of_ies;
} slap_cc_t;

#define SLAP_AC_CALLCONTROL	0x01
#define	SLAP_AC_HEARTBEAT	0x02
#define SLAP_AC_CMDREQ		0x03
#define SLAP_AC_CMDACK		0x04
#define SLAP_AC_QUERYREQ	0x05
#define SLAP_AC_QUERYACK	0x06
#define	SLAP_AC_EVENT		0x0b
#define	SLAP_AC_REGISTER	0x0c

#define DNS_FAIL_RETRY_TIME	60
#define DNS_REFRESH_TIME	300
#define SLAP_PORT		5003

#define SLAP_CONNECT_TIMEOUT	3		/* SLAP connect timeout */
#define SLAPCONN_FAIL_RETRY	6		/* Failure on connect retry timer */
#define SLAP_ACTIVE_DELAY	3		/* Delay to send an MGCP RSIP after connected */

#define SLAP_STATUS_CHANGE	0x7b
#define SLAP_STARTUP_TEMP	0x7c
#define SLAP_LINK_STATUS	0x73
#define SLAP_DS0_STATUS		0x74
#define SLAP_TOTAL_MDM_AVAIL	0x7a
#define SLAP_DS0_BLOCKING	0x7f


#define SLAP_COMS_SETUP_IND	0x1b
#define SLAP_COMS_CALL_PROC_REQ	0x04

#define SLAP_COMS_CONNECT_REQ	0x0c
#define SLAP_COMS_CONNECT_ACK	0x0d

#define SLAP_COMS_DISC_REQ	0x32
#define SLAP_COMS_DISC_IND	0x33

#define SLAP_COMS_CLEAR_CONF	0x05
#define SLAP_COMS_CLEAR_IND	0x06
#define SLAP_COMS_CLEAR_REQ	0x07
#define SLAP_COMS_CLEAR_RESP	0x08

void slap_init(void );
int slap_isactive(struct gateway_s *);
void slap_init_gateway(struct gateway_s *);
int slap_callid_next(struct gateway_s *);
int slap_call_incoming(struct gateway_s *, int slot, int span, int chan,
			int bearer, char *anumber, char *number, int callid);
void slap_call_drop_req(struct gateway_s *, int slot, int span, int chan, int callid);
void slap_call_drop_ack(struct gateway_s *, int slot, int span, int chan, int callid);

#endif
