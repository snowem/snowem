#ifndef _SNOW_CORE_CHANNEL_H_
#define _SNOW_CORE_CHANNEL_H_


#ifdef __cplusplus
extern "C" {
#endif

#include "cache.h"
#include "linux_list.h"
#include "types.h"

#define SNW_CORE_CHANNEL_USER_NUM_MAX 100
#define SNW_SUBCHANNEL_NUM_MAX 10

typedef struct snw_peer_list snw_peer_list_t;
struct snw_peer_list {
   uint32_t peers[SNW_CORE_CHANNEL_USER_NUM_MAX];
   struct list_head list;
};

/* Channel type */
enum {
   SNW_BCST_CHANNEL_TYPE = 0,
   SNW_CALL_CHANNEL_TYPE = 1,
   SNW_CONF_CHANNEL_TYPE = 2,
};

typedef struct snw_subchannel snw_subchannel_t;
struct snw_subchannel {
  uint32_t peerid;
  uint32_t channelid;
};

typedef struct snw_channel snw_channel_t;
struct snw_channel {
   uint32_t id;       //channelid
   uint32_t type;     //channel type
   uint32_t flowid;   //owner's flowid
   uint32_t peerid;   //owner's peerid
   uint32_t parentid; //parent channel's id
   char     name[ROOM_NAME_LEN];
   snw_subchannel_t subchannels[SNW_SUBCHANNEL_NUM_MAX];

   int      idx;
   uint32_t peers[SNW_CORE_CHANNEL_USER_NUM_MAX];
};

snw_hashbase_t*
snw_channel_init();

snw_channel_t*
snw_channel_get(snw_hashbase_t *ctx, uint32_t id, int *is_new);

snw_channel_t*
snw_channel_search(snw_hashbase_t *ctx, uint32_t id);

snw_channel_t*
snw_channel_insert(snw_hashbase_t *ctx, snw_channel_t *sitem);

int 
snw_channel_remove(snw_hashbase_t *ctx, snw_channel_t *sitem);



#ifdef __cplusplus
}
#endif

#endif //_SNOW_ICE_CHANNEL_H_
