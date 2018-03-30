/*
 * Copyright (c) 2015 Jackie Dinh <jackiedinh8@gmail.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *  1 Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  2 Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution.
 *  3 Neither the name of the <organization> nor the 
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY 
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @(#)mq.h
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
snw_shmmq_init(snw_shmmq_t *mq, const char* fifo_path, 
      int32_t wait_sec, int32_t wait_usec, 
      int32_t shm_key, int32_t shm_size);

int 
snw_shmmq_init_new(snw_shmmq_t *mq,
      int32_t wait_sec, int32_t wait_usec, 
      int32_t shm_key, int32_t shm_size);

void 
snw_shmmq_release(snw_shmmq_t *mq);

int 
snw_shmmq_enqueue(snw_shmmq_t *mq, 
      const time_t uiCurTime, const void* data, 
      uint32_t data_len, uint32_t flow);

//int 
//snw_shmmq_enqueue_new(snw_shmmq_t *mq, 
//      const time_t uiCurTime, const void* data, 
//      uint32_t data_len, uint32_t flow);

int 
snw_shmmq_dequeue(snw_shmmq_t *mq, void* buf, 
      uint32_t buf_size, uint32_t *data_len, uint32_t *flow);

//int 
//snw_shmmq_dequeue_new(snw_shmmq_t *mq, void* buf, 
//      uint32_t buf_size, uint32_t *data_len, uint32_t *flow);

#ifdef __cplusplus
}
#endif

#endif//_SNOW_CORE_MQ_H_

