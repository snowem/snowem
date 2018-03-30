#ifndef _SNOW_CORE_CONNECTION_H_
#define _SNOW_CORE_CONNECTION_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


enum {
   WSS_SOCKET_UDP = 1,
   ICE_SOCKET_UDP = 2,
};

typedef struct snw_connection snw_connection_t;
struct snw_connection {
   uint32_t       flowid;
   uint32_t       peerid;
   uint32_t       srctype;
   uint32_t       ipaddr;
   uint16_t       port;
};

#ifdef __cplusplus
}
#endif

#endif //_SNOW_CORE_CONNECTION_H_



