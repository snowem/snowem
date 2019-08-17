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

#include <bsd/bsd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "core/conf.h"
#include "core/conn.h"
#include "core/core.h"
#include "core/log.h"
#include "core/module.h"
#include "core/msg.h"
#include "core/snow.h"
#include "core/snw_event.h"
#include "core/task.h"
#include "core/utils.h"
#include "http/http.h"
#include "json-c/json.h"
#include "websocket/websocket.h"

int
snw_core_ice_create_msg(snw_context_t *ctx, void *data, int len, uint32_t flowid) {
  snw_log_t *log = ctx->log;
  json_object *jobj = (json_object*)data;
  snw_stream_t *stream = 0;
  uint32_t streamid = 0;
  const char *str = 0;
  int is_new = 0;

  //Step1: get stream id from a pool.
  streamid = snw_set_getid(ctx->stream_mgr);
  if (streamid == 0) {
     ERROR(log, "can not get stream, flowid=%u", flowid);
     return -1;
  }

  DEBUG(log, "get new stream, streamid=%u, is_new=%u, flowid=%u", streamid, is_new, flowid);
  stream = snw_stream_get(ctx->stream_cache,streamid,&is_new);
  if (!stream || !is_new) {
    ERROR(log, "no new stream, streamid=%u, is_new=%u, flowid=%u", streamid, is_new, flowid);
    return -2;
  }
  stream->flowid = flowid;

  DEBUG(log,"create a stream, streamid=%u", streamid);
  json_object_object_add(jobj,"streamid",json_object_new_int(streamid));
  json_object_object_add(jobj,"flowid",json_object_new_int(flowid));
  json_object_object_add(jobj,"rc",json_object_new_int(0));
  str = snw_json_msg_to_string(jobj);
  if (!str) return -1;
  DEBUG(log,"create a stream, streamid=%s", str);
  snw_shmmq_enqueue(ctx->http_task->req_mq,0,str,strlen(str),flowid);

  return 0;
}

int
snw_core_ice_publish_msg(snw_context_t *ctx, void *data, int len, uint32_t flowid) {
  snw_log_t *log = ctx->log;
  json_object *jobj = (json_object*)data;
  uint32_t streamid = 0;
  snw_stream_t *stream = 0;

  streamid = snw_json_msg_get_int(jobj,"streamid");

  if (streamid == (uint32_t)-1)
    return -1;

  stream = snw_stream_search(ctx->stream_cache, streamid);
  if (!stream) {
    ERROR(log,"stream not found, flowid=%u, streamid=%u", flowid, streamid);
    return -1;
  }

  DEBUG(log,"publish req, flowid=%u, type=%u", flowid, stream->type);
  stream->type = STREAM_TYPE_PUBLISHER;

  //TODO: broadcast info to external party
  return 0;
}

int
snw_core_ice_play_msg(snw_context_t *ctx, void *data, int len, uint32_t flowid) {
  //TODO: broadcast info to external party
  return 0;
}

int
snw_ice_handler(snw_context_t *ctx, snw_conn_t *conn, json_object *jobj) {
  uint32_t flowid = conn->flowid;
  uint32_t api = 0;
  const char *str = 0;
  int ret = -1;
  snw_log_t *log = ctx->log;

  api = snw_json_msg_get_int(jobj,"api");
  switch(api) {
     case SNW_ICE_CREATE:
        ret = snw_core_ice_create_msg(ctx,jobj,0,flowid);
        return ret;
     case SNW_ICE_CONNECT:
        {
          uint32_t streamid = 0;
          snw_conn_t *new_conn = 0;
          int is_new = 0;

          streamid = snw_json_msg_get_int(jobj, "streamid");
          if (streamid == (uint32_t)-1) {
            ERROR(log, "streamid not found, flowid=%u", flowid);
            ret = -1;
            break;
          }
          new_conn = snw_conn_get(ctx->conn_cache, flowid, &is_new);
          if (!new_conn || !is_new) {
            ERROR(log, "failed to allocate conn, flowid=%u", flowid);
            ret = -1;
            break;
          }
          new_conn->streamid = streamid;
          new_conn->srctype = conn->srctype;
          new_conn->ipaddr = conn->ipaddr;
          new_conn->port = conn->port;
          ret = 0;
          break;
        }
     case SNW_ICE_PUBLISH:
        ret = snw_core_ice_publish_msg(ctx,jobj,0,flowid);
        break;
     case SNW_ICE_PLAY:
        ret = snw_core_ice_play_msg(ctx,jobj,0,flowid);
        break;
     default:
        ret = 0;
        break;
  }

  if (ret < 0) {
    ERROR(log, "msg handler err, ret = %u", ret);
    return -1;
  }

  str = snw_json_msg_to_string(jobj);
  if (!str) return -1;
  DEBUG(log, "forward msg to ice, len=%u, str=%s", strlen(str), str);
  snw_shmmq_enqueue(ctx->ice_task->req_mq,0,str,strlen(str),flowid);

  return 0;
}

int
snw_module_handler(snw_context_t *ctx, snw_conn_t *conn, uint32_t type, char *data, uint32_t len) {
   snw_module_t *m = 0;

   LIST_FOREACH(m,&ctx->modules,list) {
      if (m->type == type) {
         m->methods->handle_msg(m,conn,data,len);
      }
   }

   return 0;
}

int
snw_core_process_msg(snw_context_t *ctx, snw_conn_t *conn, char *data, uint32_t len) {
   snw_log_t *log = ctx->log;
   json_object *jobj = 0;
   uint32_t msgtype = 0;

   jobj = json_tokener_parse(data);
   if (!jobj) {
      ERROR(log,"error json format, s=%s",data);
      return -1;
   }

   DEBUG(log,"core handler parsed json: %s",
         json_object_to_json_string_ext(
           jobj, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));

   msgtype = snw_json_msg_get_int(jobj,"msgtype");
   if (msgtype != SNW_ICE) {
      ERROR(log, "wrong msg, msgtype=%u data=%s", msgtype, data);
      goto done;
   }

   switch(msgtype) {
      case SNW_ICE:
         snw_ice_handler(ctx,conn,jobj);
         break;
      default:
         snw_module_handler(ctx,conn,msgtype,data,len);
         break;
   }

done:
   json_object_put(jobj);
   return 0;
}

int
snw_core_connect(snw_context_t *ctx, snw_conn_t *conn) {

   //TODO: handle connect activity etc
   //      for example, limit connections per ip
   return 0;
}

void
snw_core_disconnect_stream(snw_context_t *ctx, snw_stream_t *stream) {
  snw_log_t *log = ctx->log;
  json_object *req = json_object_new_object();
  const char *str = 0;

  if (!stream || !req) return;

  json_object_object_add(req,"msgtype",json_object_new_int(SNW_ICE));
  json_object_object_add(req,"api",json_object_new_int(SNW_ICE_STOP));
  json_object_object_add(req,"streamid",json_object_new_int(stream->id));
  str = snw_json_msg_to_string(req);
  if (!str) {
    json_object_put(req);
    return;
  }
  DEBUG(log, "send event to ice streamid=%u, flowid=%u, s=%s", 
      stream->id, stream->flowid, str);

  snw_shmmq_enqueue(ctx->ice_task->req_mq,0,str, strlen(str),stream->flowid);

  json_object_put(req);
  snw_stream_remove(ctx->stream_cache, stream);
  return;
}

int
snw_core_disconnect(snw_context_t *ctx, snw_conn_t *c) {
   snw_log_t *log = ctx->log;
   snw_conn_t *conn = 0;
   json_object *req = 0;

   conn = snw_conn_search(ctx->conn_cache, c->flowid);
   if (!conn) {
     ERROR(log, "conn not found, flowid=%u", c->flowid);
     return 0;
   }

   DEBUG(log,"remove connection, flowid=%u, streamid=%u",
       conn->flowid, conn->streamid);

   req = json_object_new_object();
   if (req) {
     const char *str = 0;
     json_object_object_add(req,"msgtype",json_object_new_int(SNW_ICE));
     json_object_object_add(req,"api",json_object_new_int(SNW_ICE_STOP));
     json_object_object_add(req,"streamid",json_object_new_int(conn->streamid));
     str = snw_json_msg_to_string(req);
     if (!str) {
       json_object_put(req);
       return -1;
     }
     TRACE(log, "forward stop msg to ice, len=%u, str=%s", strlen(str), str);
     snw_shmmq_enqueue(ctx->ice_task->req_mq, 0, str, strlen(str), conn->flowid);
     json_object_put(req);
   }

   snw_conn_remove(ctx->conn_cache, conn);
   return 0;
}

int
snw_net_preprocess_msg(snw_context_t *ctx, char *buffer, uint32_t len, uint32_t flowid) {
   snw_event_t* header = (snw_event_t*) buffer; 
   snw_log_t *log = (snw_log_t*)ctx->log;
   snw_conn_t conn;

   ctx->cur_time = time(0);

   if (len < SNW_EVENT_HEADER_LEN) {
      ERROR(log, "msg too small, len=%u,flowid=%u",len,flowid);
      return -1;
   }

   if (header->magic_num != SNW_EVENT_MAGIC_NUM) {
      ERROR(log, "no event header, len=%u,flowid=%u, magic=%u",
            len,flowid,header->magic_num);
      return -2;
   }

   memset(&conn, 0, sizeof(conn));
   conn.flowid = flowid;
   conn.srctype = WSS_SOCKET_UDP;
   conn.port = header->port;
   conn.ipaddr = header->ipaddr;

   if(header->event_type == snw_ev_connect) {
      snw_core_connect(ctx,&conn);
      return 0;
   }

   if(header->event_type == snw_ev_disconnect) {
      snw_core_disconnect(ctx, &conn);
      return 0;
   }

   DEBUG(log, "get msg, srctype: %u, ip: %s, port: %u, flow: %u, data_len: %u, msg_len: %u",
       conn.srctype,
       ip_to_str(conn.ipaddr),
       conn.port,
       conn.flowid,
       len,
       len - sizeof(snw_event_t));

   snw_core_process_msg(ctx,&conn,buffer+sizeof(snw_event_t),len-sizeof(snw_event_t));
   return 0;
}

int
snw_process_msg_from_ice(snw_context_t *ctx, char *buffer, uint32_t len, uint32_t flowid) {

   snw_shmmq_enqueue(ctx->net_task->req_mq, 0, buffer, len, flowid);
   return 0;
}

int
snw_process_msg_from_http(snw_context_t *ctx, char *data, uint32_t len, uint32_t flowid) {
   snw_log_t *log = ctx->log;
   json_object *jobj = 0;
   uint32_t msgtype = 0;
   uint32_t api = 0;

   jobj = json_tokener_parse(data);
   if (!jobj) {
      ERROR(log,"error json format, s=%s",data);
      return -1;
   }

   DEBUG(log,"http handler parsed json: %s",
         json_object_to_json_string_ext(
           jobj, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));

   msgtype = snw_json_msg_get_int(jobj,"msgtype");
   api = snw_json_msg_get_int(jobj,"api");
   if (msgtype == (uint32_t)-1 || api == (uint32_t)-1) {
     json_object_put(jobj);
     return -1;
   }

   if (msgtype != SNW_ICE) {
     json_object_put(jobj);
     return -1;
   }

   switch(api) {
     case SNW_ICE_CREATE:
       snw_core_ice_create_msg(ctx,jobj,0,flowid);
       break;
     default:
       ERROR(log,"unsupported http request, api=%u",api);
       break;
   }

   json_object_put(jobj);
   return 0;
}

void
snw_ice_msg(int fd, short int event,void* data) {
   static char buffer[MAX_BUFFER_SIZE];
   snw_context_t *ctx = (snw_context_t *)data;
   uint32_t len = 0;
   uint32_t flowid = 0;
   uint32_t cnt = 0;

#ifdef USE_ADAPTIVE_CONTROL
   while(true){
      len = 0; flowid = 0; cnt++;
      if ( cnt >= 10000) {
         DEBUG(ctx->log, "breaking the loop, cnt=%d", cnt);
         break;
      }
#endif
      snw_shmmq_dequeue(ctx->ice_task->resp_mq, buffer, MAX_BUFFER_SIZE, &len, &flowid);

      if (len == 0) return;

      buffer[len] = 0;
      TRACE(ctx->log,"dequeue msg from ice, flowid=%u, len=%u, cnt=%d, data=%s",
          flowid, len, cnt, buffer);
      snw_process_msg_from_ice(ctx, buffer, len, flowid);

#ifdef USE_ADAPTIVE_CONTROL
   }
#endif

   return;

}

void
snw_net_msg(int fd, short int event,void* data) {
   static char buffer[MAX_BUFFER_SIZE];
   snw_context_t *ctx = (snw_context_t *)data;
   uint32_t len = 0;
   uint32_t flowid = 0;
   uint32_t cnt = 0;

#ifdef USE_ADAPTIVE_CONTROL
   while(true){
      len = 0; flowid = 0; cnt++;
      if ( cnt >= 10000) {
         DEBUG(ctx->log, "breaking the loop, cnt=%d", cnt);
         break;
      }
#endif
      snw_shmmq_dequeue(ctx->net_task->resp_mq, buffer, MAX_BUFFER_SIZE, &len, &flowid);

      if (len == 0 || len >= MAX_BUFFER_SIZE) return;

      DEBUG(ctx->log,"dequeue msg from net, flowid=%u, len=%u, cnt=%d",
          flowid, len, cnt);
      buffer[len] = 0; // null-terminated string
      snw_net_preprocess_msg(ctx,buffer,len,flowid);

#ifdef USE_ADAPTIVE_CONTROL
   }
#endif

   return;
}

void
snw_http_msg(int fd, short int event,void* data) {
   static char buffer[MAX_BUFFER_SIZE];
   snw_context_t *ctx = (snw_context_t *)data;
   uint32_t len = 0;
   uint32_t flowid = 0;
   uint32_t cnt = 0;

#ifdef USE_ADAPTIVE_CONTROL
   while(true){
      len = 0; flowid = 0; cnt++;
      if ( cnt >= 10000) {
         DEBUG(ctx->log, "breaking the loop, cnt=%d", cnt);
         break;
      }
#endif
      snw_shmmq_dequeue(ctx->http_task->resp_mq, buffer, MAX_BUFFER_SIZE, &len, &flowid);
      if (len == 0) return;

      DEBUG(ctx->log,"dequeue msg from http, flowid=%u, len=%u, cnt=%d",
          flowid, len, cnt);
      buffer[len] = 0;
      snw_process_msg_from_http(ctx,buffer,len,flowid);

#ifdef USE_ADAPTIVE_CONTROL
   }
#endif

   return;
}

void
snw_main_process(snw_context_t *ctx) {

   if (ctx == 0) return;

   /*initialize main log*/
   ctx->log = snw_log_init(ctx->main_log_file, ctx->log_level,
       ctx->log_rotate_num, ctx->log_file_maxsize);
   if (ctx->log == 0) {
      exit(-1);
   }

   snw_module_init(ctx);

   ctx->conn_cache = snw_conn_init();
   if (ctx->conn_cache == 0) {
      ERROR(ctx->log,"failed to init peer cache");
      return;
   }

   ctx->stream_cache = snw_stream_init();
   if (ctx->stream_cache == 0) {
      ERROR(ctx->log,"failed to init stream cache");
      return;
   }

   ctx->stream_mgr = snw_set_init(6408638, 10000);
   if (ctx->stream_mgr == 0) {
      ERROR(ctx->log,"failed to init stream set");
      return;
   }

   event_base_dispatch(ctx->ev_base);
   return;
}

void
snw_core_ice_cb(snw_task_ctx_t *task_ctx, void *data) {
  snw_context_t *ctx = (snw_context_t *)data;
  struct event *q_event;

  ctx->ice_task = task_ctx;

  //TODO: create snw_task_register_callback(int type, callback)
  q_event = event_new(ctx->ev_base, task_ctx->resp_mq->pipe[0], 
    EV_TIMEOUT|EV_READ|EV_PERSIST, snw_ice_msg, ctx);
  event_add(q_event, NULL);
}

void
snw_core_net_cb(snw_task_ctx_t *task_ctx, void *data) {
  snw_context_t *ctx = (snw_context_t *)data;
  struct event *q_event;

  ctx->net_task = task_ctx;

  q_event = event_new(ctx->ev_base, task_ctx->resp_mq->pipe[0], 
    EV_TIMEOUT|EV_READ|EV_PERSIST, snw_net_msg, ctx);
  event_add(q_event, NULL);
}

void
snw_core_http_cb(snw_task_ctx_t *task_ctx, void *data) {
  snw_context_t *ctx = (snw_context_t *)data;
  struct event *q_event;

  ctx->http_task = task_ctx;

  q_event = event_new(ctx->ev_base, task_ctx->resp_mq->pipe[0],
    EV_TIMEOUT|EV_READ|EV_PERSIST, snw_http_msg, ctx);
  event_add(q_event, NULL);
}

void
print_help() {

   printf("usage: snowem <path-to-config_file>\n");

   return;
}

int
main(int argc, char** argv, char **envp) {
   snw_context_t *ctx;

   if (argc < 2) {
     print_help();
     exit(0);
   }

   setproctitle_init(argc, argv, envp);

   srand(time(NULL));
   ctx = snw_create_context();
   if (ctx == NULL) exit(-1);
   if (argc < 2) exit(-2);

   snw_config_init(ctx, argv[1]);

   ctx->ev_base = event_base_new();
   if (ctx->ev_base == 0) exit(-3);
   daemonize();

   snw_task_setup(ctx,CORE2ICE_KEY,ICE2CORE_KEY,SHAREDMEM_SIZE,
       snw_core_ice_cb, snw_ice_task_cb);

   snw_task_setup(ctx,CORE2NET_KEY,NET2CORE_KEY,SHAREDMEM_SIZE,
       snw_core_net_cb, snw_net_task_cb);

   snw_task_setup(ctx,CORE2HTTP_KEY,HTTP2CORE_KEY,SHAREDMEM_SIZE,
       snw_core_http_cb, snw_http_task_cb);

   setproctitle("master sig %s %s", argv[0], argv[1]);

   snw_main_process(ctx);

   return 0;
}

