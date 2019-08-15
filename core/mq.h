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

#ifndef _SNOW_CORE_MQ_H_
#define _SNOW_CORE_MQ_H_ 

#ifdef __cplusplus
extern "C" {
#endif

#include "shm.h"

#define MQ_HEADER_SIZE 2*sizeof(uint32_t)

enum {
  SNW_MQ_FIFO = 1,
  SNW_MQ_PIPE = 2,
};

typedef struct snw_shmctrl snw_shmctrl_t;
struct snw_shmctrl
{
   uint32_t  head;
   uint32_t  tail;
   uint32_t  wait_sec;
   uint32_t  wait_usec;
   uint32_t  period_time;
   uint32_t  write_cnt;
   uint32_t  rate;
   time_t    last_time;
   uint32_t  enqueued_msg_cnt;
   uint32_t  dequeued_msg_cnt;
   uint32_t  reserved[16];
}__attribute__((packed));

typedef struct snw_shmmq snw_shmmq_t;
struct snw_shmmq
{
  int             type;
  uint32_t        fd; //fifo
  int             pipe[2];
  snw_shm_t      *shm;
  snw_shmctrl_t  *shm_ctrl;
  char           *data;
  uint32_t        size;
}__attribute__((packed));

void
print_shmmq(snw_shmmq_t *mq);

snw_shmmq_t*
snw_shmmq_new(int type);

int
snw_shmmq_init(snw_shmmq_t *mq,
      int32_t wait_sec, int32_t wait_usec,
      int32_t shm_key, int32_t shm_size);

void
snw_shmmq_release(snw_shmmq_t *mq);

int
snw_shmmq_enqueue(snw_shmmq_t *mq,
      const time_t uiCurTime, const void* data,
      uint32_t data_len, uint32_t flow);

int
snw_shmmq_dequeue(snw_shmmq_t *mq, void* buf,
      uint32_t buf_size, uint32_t *data_len, uint32_t *flow);

#ifdef __cplusplus
}
#endif

#endif//_SNOW_CORE_MQ_H_

