/*
 * (C) Copyright 2017 Jackie Dinh <jackiedinh8@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "flow.h"

snw_flowset_t*
snw_flowset_init(uint32_t num) {
   snw_flow_t *flow;
   snw_flowset_t *flowset;
   uint32_t i, size;
   uint32_t total_size;
   int res;

   flowset = (snw_flowset_t *)malloc(sizeof(*flowset));
   if (flowset == 0) {
      return 0;
   }
   size = (sizeof(snw_flow_t)+3) & ~0x3;
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
   //flowset->baseidx = random()%1000000;
   flowset->baseidx = SNW_CORE_FLOW_BASE_IDX;
   LIST_INIT(&flowset->freelist);
   LIST_INIT(&flowset->usedlist);
   for (i = 1; i < num; i++) {
      flow = flowset->data + i;
      flow->flowid = i + flowset->baseidx;
      flow->obj = 0;
      if (random()%2) {
         //TODO: insert at tail
         LIST_INSERT_HEAD(&flowset->freelist,flow,list);
      } else {
         LIST_INSERT_HEAD(&flowset->freelist,flow,list);
      }
   }

   return flowset;
}

uint32_t
snw_flowset_getid(snw_flowset_t *s) {
   uint32_t id = 0;
   snw_flow_t *flow = 0;

   if (s == 0) return 0;

   if (!LIST_EMPTY(&s->freelist)) {
      flow = LIST_FIRST(&s->freelist);
      id = flow->flowid;
      LIST_REMOVE(flow,list);
      LIST_INSERT_HEAD(&s->usedlist,flow,list); 
      s->usednum++;
   } 

   return id;
}

void
snw_flowset_freeid(snw_flowset_t *s, uint32_t id) {
   snw_flow_t *flow = 0;

   if (s == 0 || id == 0)
      return;
   
   if (!snw_flowset_is_in_range(s,id))
      return;

   flow = s->data + (id - s->baseidx);
   flow->obj = 0; //XXX: ensure obj is freed

   LIST_REMOVE(flow,list);
   LIST_INSERT_HEAD(&s->freelist,flow,list);
   if (s->usednum == 0)
      return;
   else 
      s->usednum--;

   return;
}

void
snw_flowset_setobj(snw_flowset_t *s, uint32_t id, void *obj) {
   snw_flow_t *flow = 0;

   if (s == 0 || id == 0)
      return;
   
   if (!snw_flowset_is_in_range(s,id))
      return;
 
   flow = s->data + (id - s->baseidx);
   flow->obj = obj;
   return;
}

void*
snw_flowset_getobj(snw_flowset_t *s, uint32_t id) {
   snw_flow_t *flow = 0;

   if (s == 0 || id == 0)
      return 0;
   
   if (!snw_flowset_is_in_range(s,id))
      return 0;

   flow = s->data + (id - s->baseidx);
   return flow->obj;
}

void
snw_flowset_free(snw_flowset_t *set) {
   /*FIXME: impl*/
   return;
}

int
snw_flowset_is_in_range(snw_flowset_t *s, uint32_t id) {
   if (!s) return 0;
   return s->totalnum > (id - s->baseidx);
}




