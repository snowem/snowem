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
 * @(#)mq.h
 */

#ifndef _SNOW_CORE_HTTP_H_
#define _SNOW_CORE_HTTP_H_ 

#include <string>

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

