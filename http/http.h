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

#ifndef _SNOW_CORE_HTTP_H_
#define _SNOW_CORE_HTTP_H_ 

#ifdef __cplusplus
extern "C" {
#endif

#include <evhttp.h>

#include "core/core.h"
#include "core/task.h"


typedef struct snw_http_context snw_http_context_t;
struct snw_http_context {
   snw_context_t  *ctx;
   snw_log_t      *log;
   snw_flowset_t  *flowset;
	 struct event_base  *ev_base;
   struct evhttp      *httpd;
   SSL_CTX            *ssl_ctx;
   snw_task_ctx_t     *task_ctx;
};

void
snw_http_setup(snw_context_t *ctx);

void
snw_http_task_cb(snw_task_ctx_t *ctx, void *data);

#ifdef __cplusplus
}
#endif

#endif//_SNOW_CORE_HTTP_H_

