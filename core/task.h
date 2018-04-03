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

#ifndef _SNOW_CORE_TASK_H_
#define _SNOW_CORE_TASK_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "core/mq.h"

typedef struct snw_task_ctx snw_task_ctx_t;
struct snw_task_ctx {
  snw_context_t   *ctx;
  snw_log_t       *log;
  snw_shmmq_t     *req_mq;
  snw_shmmq_t     *resp_mq;
};

typedef void (*task_callback_fn)(snw_task_ctx_t *ctx, void *data);

void
snw_task_setup(snw_context_t *ctx, uint32_t key_req,
    uint32_t key_resp, int size, task_callback_fn parent_cb,
    task_callback_fn child_cb);

#ifdef __cplusplus
}
#endif

#endif // _SNOW_CORE_TASK_H_
