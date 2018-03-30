#ifndef _SNOW_CORE_PEER_H_
#define _SNOW_CORE_PEER_H_

#include <stdint.h>

#include "types.h"

enum {
   PEER_TYPE_UNKNOWN = 0,
   PEER_TYPE_PUBLISHER = 1,
   PEER_TYPE_PLAYER = 2,
   PEER_TYPE_P2P = 3,
};


typedef struct snw_peer snw_peer_t;
struct snw_peer {
   uint32_t peerid;
   uint32_t flowid;
   uint32_t channelid;
   int      peer_type;
};

snw_hashbase_t*
snw_peer_init();

snw_peer_t*
snw_peer_get(snw_hashbase_t *ctx, uint32_t peerid, int *is_new);

snw_peer_t*
snw_peer_search(snw_hashbase_t *ctx, uint32_t peerid);

snw_peer_t*
snw_peer_insert(snw_hashbase_t *ctx, snw_peer_t *sitem);

int 
snw_peer_remove(snw_hashbase_t *ctx, snw_peer_t *sitem);

#endif //_SNOW_CORE_PEER_H_


