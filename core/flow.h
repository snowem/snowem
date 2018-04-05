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

#ifndef _SNOW_CORE_FLOW_H_
#define _SNOW_CORE_FLOW_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "core/bsd_queue.h"

#define SNW_CORE_FLOW_BASE_IDX 33212368
#define SNW_CORE_FLOW_NUM_MAX  10*1024

#define LIST_INSERT_TAIL(head,type,elm,field) do {\
  type *listelm = LIST_FIRST(head);\
  LIST_INSERT_BEFORE(listelm, elm, field);\
} while(0);

typedef struct snw_flow snw_flow_t;
struct snw_flow {
   LIST_ENTRY(snw_flow) list;
   uint32_t  flowid;
   void     *obj;
};
typedef LIST_HEAD(flow_head, snw_flow) flow_head_t;

typedef struct snw_flowset snw_flowset_t;
struct snw_flowset {
   flow_head_t freelist;
   flow_head_t usedlist;
   uint32_t          totalnum;
   uint32_t          usednum;
   uint32_t          baseidx;

   snw_flow_t       *data;
};

snw_flowset_t*
snw_flowset_init(uint32_t num);

uint32_t
snw_flowset_getid(snw_flowset_t *s);

void
snw_flowset_freeid(snw_flowset_t *s, uint32_t id);

void
snw_flowset_setobj(snw_flowset_t *s, uint32_t id, void *obj);

void*
snw_flowset_getobj(snw_flowset_t *s, uint32_t id);

void
snw_flowset_free(snw_flowset_t *s);

int
snw_flowset_is_in_range(snw_flowset_t *s, uint32_t id);

#ifdef __cplusplus
}
#endif

#endif //_SNOW_CORE_FLOW_H_
