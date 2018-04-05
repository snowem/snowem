/*
 * (C) Copyright 2016 Jackie Dinh <jackiedinh8@gmail.com>
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

#ifndef _SNOW_CORE_CHANNEL_MGR_H_
#define _SNOW_CORE_CHANNEL_MGR_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "core/bsd_queue.h"

#define MAX_CHANNEL_NUM 10000

typedef struct snw_elem snw_elem_t;
struct snw_elem {
   LIST_ENTRY(snw_elem) list;
   uint32_t  flowid;
   void     *obj;
};
typedef LIST_HEAD(elem_head, snw_elem) elem_head_t;


typedef struct snw_set snw_set_t;
struct snw_set {
   elem_head_t       freelist;
   elem_head_t       usedlist;
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







