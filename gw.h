#ifndef MGCPSLAP_GW_H
#define MGCPSLAP_GW_H

#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <event.h>

#include <stdint.h>
#include <glib.h>

//#define SLAP_MAXMSG_SIZE	524
#define SLAP_BUFFER_SIZE	512

#define MAX_DS0_PERDS1		32
#define MAX_DS1_PERSLOT		3
#define MAX_SLOT		14

#define NUMBER_MAX_SIZE		20

#define CALL_TIMER_DEL		30

enum {
	DS1_STATUS_UNKNOWN = 0,
	DS1_STATUS_UP = 1,
	DS1_STATUS_DOWN = 2
};

enum {
	DS0_UNKNOWN = 0,
	DS0_IDLE,
	DS0_BUSY,
};

enum {
	GW_STATUS_UNAVAIL = 0,
	GW_STATUS_AVAIL = 1
};

enum {
	BT_UNKNOWN = 0,
	BT_MODEM,
	BT_DIGITAL,
};

enum {
	CALL_IDLE,
	CALL_INCOMING,
	CALL_ESTABLISHED,
	CALL_DROP,
};

struct call_s;

struct ds0_s {
	uint8_t		status;
	struct call_s	*call;
};

struct ds1_s {
	uint8_t		status;
	uint8_t		numds0;
	struct ds0_s	ds0[MAX_DS0_PERDS1];
};

struct slot_s {
	uint8_t		status;
	uint8_t		numds1;
	struct ds1_s	*ds1[MAX_DS1_PERSLOT];
};

struct gateway_s {
	char		name[128];
	int		status;
	int		callid;			/* Next CallID to use */
	GHashTable	*calltable;

	struct slot_s	slot[MAX_SLOT];

	struct {
		struct {
			struct sockaddr_in	sin;
		} addr;
	} mgcp;

	struct {
		int	status;

		struct {
			time_t		recv;
			struct timeval	recvtv;
			struct event	recvtimer;

			struct timeval	sendtv;
			struct event	sendtimer;
		} hb;

		struct {
			struct in_addr	in;
			time_t		ttl;

			struct event	timer;
			struct timeval	tv;
		} addr;

		struct {
			int		socket;
			struct event	event;
			struct timeval	tv;
		} conn;

		struct {
			int	valid;
			uint8_t	buffer[SLAP_BUFFER_SIZE];
		} read;

		struct {
			int	valid;
			uint8_t	buffer[SLAP_BUFFER_SIZE];
		} write;
	} slap;
};

struct endpoint_s {
	char			domain[64];
	int			slot;
	int			span;
	int			chan;

	struct gateway_s	*gw;
};

struct call_s {
	GList			list;

	int			status;

	int			bearertype;
	char			anumber[NUMBER_MAX_SIZE];
	char			bnumber[NUMBER_MAX_SIZE];

	int			callid;		/* SLAP call id / MGCP ConnectionID */
	int			mgcpmsgid;	/* MGCP Call setup msgid */

	struct endpoint_s	ep;
	struct ds0_s		*ds0;

	struct event		timer;
	struct timeval		tv;
};

int gw_init(void );
struct gateway_s *gw_lookup(char *);
struct gateway_s *gw_lookup_or_create(char *);
void gw_set_status(struct gateway_s *gw, int status);

void gw_slot_create(struct gateway_s *gw, int slot);
void gw_slot_set_status(struct gateway_s *gw, int slot, int status);

void gw_ds1_create(struct gateway_s *gw, int slot, int ds1);
void gw_ds1_set_status(struct gateway_s *gw, int slot, int span, int status);
struct ds1_s *gw_ds1_get(struct gateway_s *gw, int slot, int ds1);

void gw_ds0_set_status(struct gateway_s *gw, int slot, int span, int chan, int status);

int gw_mgcp_call_setup(struct endpoint_s *ep, int mgcpmsgid, char *anumber, char *bnumber, int bearer);
void gw_mgcp_call_drop_req(struct endpoint_s *ep, int mgcpmsgid, int connid);
void gw_mgcp_call_drop_ack(struct gateway_s *gw, int connid);

void gw_slap_call_proceed(struct gateway_s *gw, int callid);
void gw_slap_call_deny(struct gateway_s *gw, int callid);
void gw_slap_call_drop_ack(struct gateway_s *gw, int callid);
void gw_slap_call_drop_req(struct gateway_s *gw, int callid);

#endif
