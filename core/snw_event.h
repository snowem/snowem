#ifndef _SNOW_CORE_EVENT_H__
#define _SNOW_CORE_EVENT_H__

#ifdef __cplusplus
extern "C" {
#endif

enum snw_event_type
{
	snw_ev_connect        = 1001,
	snw_ev_disconnect     = 1002,
	snw_ev_data           = 1003,
};

typedef struct snw_event snw_event_t;
struct snw_event {
	uint32_t magic_num;		// magic = 'EVNT'
	uint32_t event_type;
	uint32_t flow;	
	uint32_t ipaddr;
	uint32_t port;
	uint32_t other;	
};

#define SNW_EVENT_HEADER_LEN 24
#define SNW_EVENT_MAGIC_NUM 0x45564E54

#ifdef __cplusplus
}
#endif

#endif
