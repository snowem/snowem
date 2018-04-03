/*
 * (C) Copyright 2018 Jackie Dinh <jackiedinh8@gmail.com>
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

