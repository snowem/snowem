
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "channel_mgr.h"

int
snw_set_is_in_range(snw_set_t *s, uint32_t id) {
   if (!s) return 0;
   return s->totalnum > (id - s->baseidx);
}

snw_set_t*
snw_set_init(uint32_t base, uint32_t num) {
   snw_elem_t *flow;
   snw_set_t *flowset;
   uint32_t i, size;
   uint32_t total_size;
   int res;

   flowset = (snw_set_t *)malloc(sizeof(*flowset));
   if (flowset == 0) {
      return 0;
   }
   size = (sizeof(snw_elem_t)+3) & ~0x3;
   total_size = num * size;

   res = posix_memalign((void **)&flowset->data, getpagesize(), total_size);
   if (res != 0) {
      assert(0);
      if (flowset) free(flowset);
      return 0;
   }

   /* init flow set */
   flowset->totalnum = num;
   flowset->usednum = 0;
   flowset->baseidx = base;
   INIT_LIST_HEAD(&flowset->freelist);
   INIT_LIST_HEAD(&flowset->usedlist);
   for (i = 1; i < num; i++) {
      flow = flowset->data + i;
      INIT_LIST_HEAD(&flow->list);
      //flow->flowid = i;
      flow->flowid = i + flowset->baseidx;
      flow->obj = 0;
      if (random()%2) {
         list_add(&flow->list, &flowset->freelist);
      } else {
         list_add_tail(&flow->list, &flowset->freelist);
      }
   }

   return flowset;
}

uint32_t
snw_set_getid(snw_set_t *s) {
   uint32_t id = 0;
   snw_elem_t *flow = 0;

   if (s == 0) return 0;

   if (!list_empty(&s->freelist)) {
      flow = list_first_entry(&s->freelist,snw_elem_t,list);
      id = flow->flowid;
      list_move_tail(&flow->list,&s->usedlist); 
      s->usednum++;
   } 

   return id;
}

void
snw_set_freeid(snw_set_t *s, uint32_t id) {
   snw_elem_t *flow = 0;

   if (s == 0 || id == 0)
      return;
   
   if (!snw_set_is_in_range(s,id))
      return;
   
   flow = s->data + (id - s->baseidx);
   flow->obj = 0;
   list_move_tail(&flow->list,&s->freelist);
   if (s->usednum == 0)
      return;
   else 
      s->usednum--;

   return;
}

void
snw_set_setobj(snw_set_t *s, uint32_t id, void *obj) {
   snw_elem_t *flow = 0;

   if (s == 0 || id == 0)
      return;
   
   if (!snw_set_is_in_range(s,id))
      return;
 
   flow = s->data + (id - s->baseidx);
   flow->obj = obj;
   return;
}

void*
snw_set_getobj(snw_set_t *s, uint32_t id) {
   snw_elem_t *flow = 0;

   if (s == 0 || id == 0)
      return 0;
   
   if (!snw_set_is_in_range(s,id))
      return 0;

   flow = s->data + (id - s->baseidx);
   return flow->obj;
}

void
snw_set_free(snw_set_t *set) {
   /*FIXME: impl*/
   return;
}



