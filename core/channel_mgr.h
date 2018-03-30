#ifndef _SNOW_CORE_CHANNEL_MGR_H_
#define _SNOW_CORE_CHANNEL_MGR_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "linux_list.h"

#define MAX_CHANNEL_NUM 10000

typedef struct snw_elem snw_elem_t;
struct snw_elem {
   struct list_head  list;
   uint32_t  flowid;
   void     *obj;
};

typedef struct snw_set snw_set_t;
struct snw_set {
   struct list_head  freelist;
   struct list_head  usedlist;
   uint32_t          totalnum;
   uint32_t          usednum;
   uint32_t          baseidx;

   snw_elem_t       *data;
};

snw_set_t*
snw_set_init(uint32_t base, uint32_t num);

uint32_t
snw_set_getid(snw_set_t *s);

void
snw_set_freeid(snw_set_t *s, uint32_t id);

void
snw_set_setobj(snw_set_t *s, uint32_t id, void *obj);

void*
snw_set_getobj(snw_set_t *s, uint32_t id);

void
snw_set_free(snw_set_t *s);

#ifdef __cplusplus
}
#endif

#endif // _CHANNEL_MGR_H_







