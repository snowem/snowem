#ifndef _SNOW_CORE_ROOMINFO_H_
#define _SNOW_CORE_ROOMINFO_H_

#include <stdint.h>

#include "types.h"

typedef struct snw_roominfo snw_roominfo_t;
struct snw_roominfo {
   uint32_t id;
   char     name[64];
   uint32_t channelid;
   uint64_t expired_ts;
   uint64_t last_ts;
};

snw_hashbase_t*
snw_roominfo_init();

snw_roominfo_t*
snw_roominfo_get(snw_hashbase_t *ctx, const char* name, int len, int *is_new);

snw_roominfo_t*
snw_roominfo_search(snw_hashbase_t *ctx, const char *name, int len);

snw_roominfo_t*
snw_roominfo_insert(snw_hashbase_t *ctx, snw_roominfo_t *sitem);

int 
snw_roominfo_remove(snw_hashbase_t *ctx, snw_roominfo_t *sitem);

#endif //_SNOW_CORE_ROOMINFO_H_


