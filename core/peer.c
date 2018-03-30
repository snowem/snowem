#include <stdio.h>

#include "cache.h"
#include "log.h"
#include "peer.h"

inline int
peer_key(const void *item)
{  
   snw_peer_t *so =  (snw_peer_t *)item;
   return so->peerid;
}

inline int
peer_eq(const void *arg1, const void *arg2)
{  
   snw_peer_t *item1 = (snw_peer_t *)arg1;
   snw_peer_t *item2 = (snw_peer_t *)arg2;
   return (item1->peerid == item2->peerid);
}

inline int
peer_isempty(const void *arg)
{
   snw_peer_t *item = (snw_peer_t *)arg;
   return (item->peerid == 0);
}

inline int            
peer_setempty(const void *arg)
{
   snw_peer_t *item = (snw_peer_t *)arg;
   item->peerid = 0;
   return 0;
}


snw_hashbase_t*
snw_peer_init() {
   snw_hashbase_t *ctx;
   int ret = 0;

   ctx = (snw_hashbase_t *)malloc(sizeof(snw_hashbase_t));
   if (ctx == 0) return 0;

   snw_cache_init(ctx, CORE_PEER_SHM_KEY, CORE_PEER_HASHTIME, 
         CORE_PEER_HASHLEN, sizeof(snw_peer_t),1, peer_eq, 
         peer_key, peer_isempty, peer_setempty);
   if (ret < 0) return 0;

   return ctx;
}

snw_peer_t*
snw_peer_get(snw_hashbase_t *ctx, uint32_t peerid, int *is_new) {
   snw_peer_t key;
   snw_peer_t *so;
  
   if (!ctx) return 0;
    
   key.peerid = peerid;
   so = CACHE_GET(ctx, &key, is_new, snw_peer_t*);

   if (so == 0)
      return 0;

   if (!(*is_new)) {
      return so;
   }

   // reset new session
   memset(so, 0, sizeof(snw_peer_t));
   so->peerid = peerid;

   return so;
}

/*CACHE_SEARCH(ctx, sitem, snw_peer_t*);*/
snw_peer_t*
snw_peer_search(snw_hashbase_t *ctx, uint32_t peerid) {
   snw_peer_t sitem;
   sitem.peerid = peerid;
   return (snw_peer_t*)snw_cache_search(ctx, &sitem);
}

/*CACHE_INSERT(ctx, sitem, snw_peer_t*);*/
snw_peer_t*
snw_peer_insert(snw_hashbase_t *ctx, snw_peer_t *sitem) {
   return (snw_peer_t*)snw_cache_insert(ctx, sitem);
}

/*CACHE_REMOVE(ctx, sitem, snw_peer_t*);*/
int 
snw_peer_remove(snw_hashbase_t *ctx, snw_peer_t *sitem) {
   return snw_cache_remove(ctx, sitem);
}


/*void
peer_remove(uint32_t key)
{
   hashbase_t *base = g_handle_base;
   snw_peer_t *item = 0;
   char *table = 0;
   int   value = 0;
   uint32_t      i;

   if ( base == NULL )
      return;

   if ( key == 0 )
      return;

   table = (char*)base->hb_cache;

   for ( i=0; i < base->hb_time; i++ ) {
      value = key % base->hb_base[i];
      item = (snw_peer_t*)(table
                   + i*base->hb_len*base->hb_objsize
                   + value*base->hb_objsize);
      if ( item->peerid == key ) {
         item->peerid = 0;
      }
   }

   return;
}*/


