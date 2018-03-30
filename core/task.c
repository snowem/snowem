/*
 * Copyright (c) 2018 Jackie Dinh <jackiedinh8@gmail.com>
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
 * @(#)task.c
 */

#include <stdio.h>
#include <stdint.h>
#include <sys/shm.h>
#include <unistd.h>

#include "core.h"
#include "mq.h"
#include "log.h"
#include "task.h"

snw_task_ctx_t*
snw_create_task_context(snw_context_t *core_ctx, uint32_t req_key, uint32_t resp_key, int size) {
  snw_task_ctx_t *ctx = 0;
  snw_shmmq_t *req_mq = 0;
  snw_shmmq_t *resp_mq = 0;

  ctx = (snw_task_ctx_t*)malloc(sizeof(snw_task_ctx_t));
  if (!ctx) return 0;

  req_mq = snw_shmmq_new(SNW_MQ_PIPE);
  resp_mq = snw_shmmq_new(SNW_MQ_PIPE);
  if (req_mq == 0 || resp_mq == 0) return 0;

  if (pipe(req_mq->pipe) || pipe(resp_mq->pipe)) {
     fprintf(stderr, "error: cannot create pipe");
     return 0;
  }
  snw_shmmq_init_new(req_mq, 0, 0, req_key, size);
  snw_shmmq_init_new(resp_mq, 0, 0, resp_key,size);
  ctx->req_mq = req_mq;
  ctx->resp_mq = resp_mq;
  ctx->ctx = core_ctx;

  return ctx;
}

int
snw_task_post_msg(snw_task_ctx_t *ctx, char *msg, int len, int flowid) {
  return snw_shmmq_enqueue(ctx->req_mq,0,msg,len,flowid);
}

void
snw_task_setup(snw_context_t *ctx, uint32_t key_req,
    uint32_t key_resp, int size, task_callback_fn parent_cb,
    task_callback_fn child_cb) {
  snw_task_ctx_t *task_ctx = 0;
  struct timeval tv;
  struct event *ev;
  int pid = -1;

  task_ctx = snw_create_task_context(ctx, key_req, key_resp, size);

  pid = fork();
  if (pid < 0) {
     fprintf(stderr, "error: cannot fork a process");
  } else if (pid == 0) { //child
     if (child_cb) child_cb(task_ctx,ctx);
     return;
  } else { // parent
     if (parent_cb) parent_cb(task_ctx,ctx);
  }

  return;
}

