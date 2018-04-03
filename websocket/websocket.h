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

#ifndef _WEBSOCKET_WEBSOCKET_H_
#define _WEBSOCKET_WEBSOCKET_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "core/core.h"
#include "core/flow.h"
#include "core/task.h"

typedef struct snw_websocket_context snw_websocket_context_t;
struct snw_websocket_context {
  snw_context_t  *ctx;
  snw_flowset_t  *flowset;
  SSL_CTX        *ssl_ctx;
  snw_log_t      *log;
  snw_task_ctx_t *task_ctx;
  const char     *wss_cert_file;
  const char     *wss_key_file;
	struct event_base *ev_base;
};

void
snw_websocket_init(snw_context_t *ctx, snw_task_ctx_t *task_ctx, dispatch_fn cb);

int
snw_websocket_send_msg(snw_websocket_context_t *ctx, char *buf, int len, uint32_t flow);

void
snw_net_task_cb(snw_task_ctx_t *task_ctx, void *data);

#ifdef __cplusplus
}
#endif

#endif /* EVWS_EVWS_H_ */
