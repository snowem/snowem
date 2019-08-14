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

#include <assert.h>
#include <bsd/bsd.h>
#include <stdio.h>

#include "core/core.h"
#include "core/log.h"
#include "ice.h"
#include "ice_subscribe.h"
#include "ice_session.h"
#include "ice_stream.h"
#include "ice/sctp.h"
#include "json-c/json.h"
#include "sdp.h"
#include "process.h"
#include "rtp/rtp.h"

void
snw_ice_api_handler(snw_ice_context_t *ice_ctx, char *data, uint32_t len, uint32_t flowid) {
   snw_log_t *log = 0;
   json_object *jobj = 0, *jmsgtype = 0, *japi = 0;
   snw_ice_api_t *a = 0;
   uint32_t msgtype = 0, api = 0;

   if (!ice_ctx) return;
   log = ice_ctx->log;
   
   jobj = json_tokener_parse(data);
   if (!jobj) {
      ERROR(log,"error json format, s=%s",data);
      return;
   }
   DEBUG(log,"api handler parsed json: %s",
         json_object_to_json_string_ext(
           jobj, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));

   json_object_object_get_ex(jobj,"msgtype",&jmsgtype);
   json_object_object_get_ex(jobj,"api",&japi);
   if (!jmsgtype || json_object_get_type(jmsgtype) != json_type_int
       || !japi || json_object_get_type(japi) != json_type_int) {
     ERROR(log,"error json format, s=%s",data);
     goto done;
   }
   msgtype = json_object_get_int(jmsgtype);
   if (msgtype != SNW_ICE) {
      ERROR(log, "wrong msg, msgtype=%u data=%s", msgtype, data);
      goto done;
   }
   api = json_object_get_int(japi);

   TRACE(log, "looking for api handler, api=%u", api);
   TAILQ_FOREACH(a,&ice_ctx->api_handlers,list) {
      if (a->msgtype == msgtype) {
         snw_ice_handlers_t *h = 0;
         TAILQ_FOREACH(h,&a->handlers,list) {
            if (h->api == api)
              h->handler(ice_ctx,jobj,0,flowid);
         }
      }
   }

done:
   json_object_put(jobj);
   return;
}

void
snw_ice_dispatch_msg(int fd, short int event, void* data) {
   static char buf[MAX_BUFFER_SIZE];
   snw_ice_context_t *ice_ctx = (snw_ice_context_t*)data;
   uint32_t len = 0;
   uint32_t flowid = 0;
   uint32_t cnt = 0;
   int ret = 0; 

   while (true) {
      len = 0;
      flowid = 0;
      cnt++;
      if (cnt >= 100) break;

      ret = snw_shmmq_dequeue(ice_ctx->task_ctx->req_mq, buf, MAX_BUFFER_SIZE, &len, &flowid);
      if ((len == 0 && ret == 0) || (ret < 0))
         return;

      buf[len] = 0; // null-terminated string
      TRACE(ice_ctx->log,"dequeue msg from core, flowid=%u, len=%u, cnt=%d, data=%s",
          flowid, len, cnt, buf);
      snw_ice_api_handler(ice_ctx, buf, len, flowid);
   }

   return;
}

//FIXME: uncomment remove this code
static char *server_pem = NULL;
static char *server_key = NULL;
SSL_CTX *
ice_dtls_init(snw_ice_context_t *ctx, const char* pem, const char *key) {
   snw_log_t *log = 0;

   if (!ctx) return 0;
   log = ctx->log;

   DEBUG(log, "using certificates: pem=%s, key%s", pem, key);

   server_pem = strdup(pem);
   server_key = strdup(key);
   SSL_library_init();
   SSL_load_error_strings();
   OpenSSL_add_all_algorithms();

   if (dtls_init(ctx, server_pem, server_key) < 0) { 
      ERROR(log, "failed to init dtls");
      exit(1);
   }

   return ctx->ssl_ctx;
}

void 
snw_ice_log_cb(int severity, const char *msg, void *data) {
   snw_ice_context_t *ice_ctx = (snw_ice_context_t *)data;
   snw_log_t *log = 0;

   if (!ice_ctx) return;
   log = ice_ctx->log;

   snw_log_write_pure(log,SNW_ERROR,"%s",msg);
   return; 
}

snw_ice_api_t g_ice_apis[] = {
   {.msgtype = SNW_ICE},
   //{.msgtype = SNW_CORE},
   //{.msgtype = SNW_EVENT},
   //{.msgtype = SNW_SIG},
   //{.msgtype = SNW_CHANNEL}
};

void
ice_rtp_established(snw_ice_session_t *session) {
   snw_ice_context_t *ice_ctx = 0;
   snw_log_t *log = 0;

   if (!session) return;
   ice_ctx = session->ice_ctx;
   log = ice_ctx->log;

   DEBUG(log, "ice connection established, streamid=%u", session->streamid);
   if ( IS_FLAG(session,ICE_SUBSCRIBER) ) {
      //TODO: request fir
      /*root["cmd"] = SNW_ICE;
      root["subcmd"] = SNW_ICE_FIR;
      root["flowid"] = session->flowid;
      output = writer.write(root);
      snw_shmmq_enqueue(ice_ctx->task_ctx->resp_mq,0,output.c_str(),output.size(),session->flowid);*/
   } else if IS_FLAG(session,ICE_PUBLISHER) {
      //broadcast info
   } else if IS_FLAG(session,ICE_REPLAY) {
      // start replaying a stream.
   }

   return;
}

void
snw_ice_init_log(snw_context_t *ctx) {
   ctx->log = snw_log_init(ctx->ice_log_file, ctx->log_level,
       ctx->log_rotate_num, ctx->log_file_maxsize);
   if (ctx->log == 0) {
      exit(-1);
   }

   return;
}

int
snw_ice_init_ssl(snw_context_t *ctx) {
   SSL_CTX  *server_ctx = NULL;

   /* Initialize the OpenSSL library */
   SSL_load_error_strings();
   SSL_library_init();
   OpenSSL_add_all_algorithms();

   /* We MUST have entropy, or else there's no point to crypto. */
   if (!RAND_poll()) return -1;

   server_ctx = SSL_CTX_new(SSLv23_server_method());
   if (server_ctx == NULL) {
      ERROR(ctx->log,"failed to init ssll");
      return -2;
   }

   DEBUG(ctx->log,"using certificates: cert_file=%s, key_file=%s",ctx->ice_cert_file,ctx->ice_key_file);
   if (! SSL_CTX_use_certificate_chain_file(server_ctx, ctx->ice_cert_file) ||
       ! SSL_CTX_use_PrivateKey_file(server_ctx, ctx->ice_key_file, SSL_FILETYPE_PEM)) {
       ERROR(ctx->log,"failed to read cert or key files");
       return -3;
   }
   ctx->ssl_ctx = server_ctx;

   return 0;
}

snw_ice_handlers_t g_ice_handlers[] = {
   {.msgtype = SNW_ICE, .api = SNW_ICE_CREATE, .handler = snw_ice_create_msg},
   {.msgtype = SNW_ICE, .api = SNW_ICE_CONNECT, .handler = snw_ice_connect_msg},
   {.msgtype = SNW_ICE, .api = SNW_ICE_PUBLISH, .handler = snw_ice_publish_msg},
   {.msgtype = SNW_ICE, .api = SNW_ICE_PLAY, .handler = snw_ice_play_msg},
   {.msgtype = SNW_ICE, .api = SNW_ICE_STOP, .handler = snw_ice_stop_msg},
   {.msgtype = SNW_ICE, .api = SNW_ICE_SDP, .handler = snw_ice_sdp_msg},
   {.msgtype = SNW_ICE, .api = SNW_ICE_CANDIDATE, .handler = snw_ice_candidate_msg},
   {.msgtype = SNW_ICE, .api = SNW_ICE_CONTROL, .handler = snw_ice_auth_msg},
   {.msgtype = SNW_ICE, .api = SNW_ICE_AUTH, .handler = snw_ice_control_msg},
   {.msgtype = SNW_ICE, .api = SNW_ICE_FIR, .handler = snw_ice_fir_msg}
};

void 
snw_ice_init(snw_context_t *ctx, snw_task_ctx_t *task_ctx) {
   snw_ice_api_t *h = 0;
   snw_ice_context_t *ice_ctx;
   struct event *q_event;
   int api_num = sizeof(g_ice_apis)/sizeof(snw_ice_api_t);
   int handler_num = sizeof(g_ice_handlers)/sizeof(snw_ice_handlers_t);

   if (!ctx) return;

   ice_ctx = (snw_ice_context_t *)malloc(sizeof(snw_ice_context_t));
   if (ice_ctx == 0) return;
   memset(ice_ctx,0,sizeof(snw_ice_context_t));
   ice_ctx->ctx = ctx;
   ice_ctx->log = ctx->log;
   ice_ctx->task_ctx = task_ctx;

   if (ctx->ice_log_enabled)
      ice_set_log_callback(snw_ice_log_cb,ice_ctx);

   ice_ctx->ev_base = ctx->ev_base;
   ice_ctx->ev_ctx = create_event_ctx(ice_ctx->ev_base);
   if (!ice_ctx->ev_ctx) return;

   snw_ice_sdp_init(ice_ctx);
   snw_ice_session_init(ice_ctx);
   if (snw_ice_subscribe_init(ice_ctx) < 0) {
     assert(0);
   }
   snw_ice_stream_mempool_init(ice_ctx);
   snw_component_mempool_init(ice_ctx);

   ice_ctx->rtcpmux_enabled = 0;
   ice_ctx->ice_lite_enabled = 1;
   ice_ctx->ipv6_enabled = 0;
   ice_ctx->ice_tcp_enabled = 0;
   ice_ctx->recording_enabled = ctx->recording_enabled;
   ice_ctx->recording_folder = ctx->recording_folder;

   ice_dtls_init(ice_ctx, ctx->wss_cert_file, ctx->wss_key_file);

   q_event = event_new(ctx->ev_base, task_ctx->req_mq->pipe[0], 
         EV_TIMEOUT|EV_READ|EV_PERSIST, snw_ice_dispatch_msg, ice_ctx);
   event_add(q_event, NULL);

   TAILQ_INIT(&ice_ctx->api_handlers);
   for (int i=0; i<api_num; i++) {
      TAILQ_INIT(&g_ice_apis[i].handlers);
      TAILQ_INSERT_TAIL(&ice_ctx->api_handlers, &g_ice_apis[i], list);
   }

   TAILQ_FOREACH(h, &ice_ctx->api_handlers,list) {
      for (int j=0; j<handler_num; j++) {
         if (h->msgtype == g_ice_handlers[j].msgtype)
            TAILQ_INSERT_TAIL(&h->handlers, &g_ice_handlers[j], list);
      }
   }

   snw_rtp_init(ice_ctx);
   snw_ice_sctp_init(ice_ctx);

   event_base_dispatch(ctx->ev_base);
   return;
}


void
snw_ice_task_cb(snw_task_ctx_t *task_ctx, void *data) {
   snw_context_t *ctx = (snw_context_t *)data;

   setproctitle("\\_ ice");

   if (ctx == 0)
      return;

   ctx->ev_base = event_base_new();
   if (ctx->ev_base == 0) {
      exit(-2);
   }

   /*initialize stuff before ice process*/
   snw_ice_init_log(ctx);
   snw_ice_init_ssl(ctx);

   snw_ice_init(ctx,task_ctx);
   return;
}

