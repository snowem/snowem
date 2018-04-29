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

#include <bsd/bsd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#ifdef linux
#include <time.h>
#endif

#include "core/http.h"
#include "core/log.h"

void
snw_http_init_log(snw_http_context_t *ctx) {
   ctx->log = snw_log_init(ctx->ctx->http_log_file, ctx->ctx->log_level,
       ctx->ctx->log_rotate_num, ctx->ctx->log_file_maxsize);
   if (ctx->log == 0) {
      exit(-1);   
   }

   return;
}

int
snw_http_init_ssl(snw_http_context_t *ctx) {
   snw_context_t *main_ctx = (snw_context_t*)ctx->ctx;
   SSL_CTX  *server_ctx = NULL;
   std::string cert_str,key_str;

   /* Initialize the OpenSSL library */
   SSL_load_error_strings();
   SSL_library_init();
   OpenSSL_add_all_algorithms();

   /* We MUST have entropy, or else there's no point to crypto. */
   if (!RAND_poll())
      return -1;

   server_ctx = SSL_CTX_new(SSLv23_server_method());
   if (server_ctx == NULL) { 
      ERROR(ctx->log,"failed to create ssl ctx");
      return -2; 
   }

   DEBUG(ctx->log,"ssl info, cert_file=%s, key_file=%s",
         main_ctx->wss_cert_file, main_ctx->wss_key_file);

   if (! SSL_CTX_use_certificate_chain_file(server_ctx, main_ctx->wss_cert_file) ||
       ! SSL_CTX_use_PrivateKey_file(server_ctx, main_ctx->wss_key_file, SSL_FILETYPE_PEM)) {
       ERROR(ctx->log,"failed to read cert or key files");
       return -3;
   }
   ctx->ssl_ctx = server_ctx;

   return 0;
}

struct evbuffer*
snw_http_get_buf_by_file(snw_http_context_t *ctx, const char *name) {
  struct evbuffer *buf = 0;
  int fd = -1;
  int len = 0;

  buf = evbuffer_new();
  if (!buf) return 0;

  fd = open(name,O_RDONLY);
  if (fd < 0) return 0;
  len = lseek(fd, 0, SEEK_END);
  if (len < 0) {
    close(fd);
    return 0;
  }
  lseek(fd, 0, SEEK_SET);
  evbuffer_add_file(buf,fd,0,len);

  return buf;
}


void
snw_process_http_get(snw_http_context_t *ctx, struct evhttp_request *req) {

  evhttp_send_error(req,HTTP_NOTFOUND,"File not found");
  return;
}

void
snw_process_http_post(snw_http_context_t *ctx, struct evhttp_request *req) {
  snw_log_t *log = ctx->log;
  static char* data[MAX_HTTP_BUFFER_SIZE];
  size_t datalen = 0;
  size_t readlen = 0;
  struct evbuffer *inbuf = 0;
  uint32_t flowid = 0;

  inbuf = evhttp_request_get_input_buffer(req);
  if (!inbuf) {
    //TODO: call err handler
    return;
  }
  readlen = evbuffer_get_length(inbuf);
  datalen = evbuffer_copyout(inbuf,data, readlen);
  data[datalen] = 0;

  flowid = snw_flowset_getid(ctx->flowset);
  if (flowid ==0) {
     ERROR(log, "connection limit reached");
     return;
  }

  DEBUG(log, "new req: %s, flowid=%u, datalen=%lu, readlen=%lu data=%s",
    evhttp_request_uri(req), flowid, datalen, readlen, data);
  snw_flowset_setobj(ctx->flowset,flowid,req);

  snw_shmmq_enqueue(ctx->task_ctx->resp_mq, 0, data, datalen, flowid);

  return;
}

void
snw_process_http_options(snw_http_context_t *ctx, struct evhttp_request *req) {
  snw_log_t *log = ctx->log;
  struct evbuffer *buf = 0;

  DEBUG(log, "Requested: %s", evhttp_request_uri(req));

  buf = evbuffer_new();
  if (buf == NULL) return;

  evhttp_add_header(evhttp_request_get_output_headers(req),
                     "Access-Control-Allow-Headers", "*");
  evhttp_add_header(evhttp_request_get_output_headers(req),
                     "Access-Control-Allow-Origin", "*");
  evbuffer_add_printf(buf, "Requested: %s\n", evhttp_request_uri(req));
  evhttp_send_reply(req, HTTP_OK, "OK", buf);

  if (buf) evbuffer_free(buf);
  return;
}

void
snw_process_http_put(snw_http_context_t *ctx, struct evhttp_request *req) {
  snw_log_t *log = ctx->log;
  struct evbuffer *buf = 0;

  ERROR(log, "Requested: %s", evhttp_request_uri(req));

  buf = evbuffer_new();
  if (buf == NULL) return;

  evbuffer_add_printf(buf, "Requested: %s\n", evhttp_request_uri(req));
  evhttp_send_reply(req, HTTP_OK, "OK", buf);

  if (buf) evbuffer_free(buf);
  return;
}

void
snw_process_http_head(snw_http_context_t *ctx, struct evhttp_request *req) {
  snw_log_t *log = ctx->log;
  struct evbuffer *buf = 0;

  ERROR(log, "Requested: %s", evhttp_request_uri(req));

  buf = evbuffer_new();
  if (buf == NULL) return;

  evbuffer_add_printf(buf, "Requested: %s\n", evhttp_request_uri(req));
  evhttp_send_reply(req, HTTP_OK, "OK", buf);

  if (buf) evbuffer_free(buf);
  return;
}

void
snw_process_http_delete(snw_http_context_t *ctx, struct evhttp_request *req) {
  snw_log_t *log = ctx->log;
  struct evbuffer *buf = 0;

  ERROR(log, "Requested: %s", evhttp_request_uri(req));

  buf = evbuffer_new();
  if (buf == NULL) return;

  //snw_flowset_getid();

  evbuffer_add_printf(buf, "Requested: %s\n", evhttp_request_uri(req));
  evhttp_send_reply(req, HTTP_OK, "OK", buf);

  if (buf) evbuffer_free(buf);
  return;
}

void
snw_process_http_request(struct evhttp_request *req, void *arg) {
  snw_http_context_t *ctx = (snw_http_context_t*)arg;
  snw_log_t *log = ctx->log;
  evhttp_cmd_type type;

  type = evhttp_request_get_command(req);
  DEBUG(log, "get http method, type=%u", type);
  switch(type) {
    case EVHTTP_REQ_GET:
      snw_process_http_get(ctx,req);
      break;
    case EVHTTP_REQ_POST:
      snw_process_http_post(ctx,req);
      break;
    case EVHTTP_REQ_OPTIONS:
      snw_process_http_options(ctx,req);
      break;
    case EVHTTP_REQ_HEAD:
      snw_process_http_head(ctx,req);
      break;
    case EVHTTP_REQ_PUT:
      snw_process_http_put(ctx,req);
      break;
    case EVHTTP_REQ_DELETE:
      snw_process_http_delete(ctx,req);
      break;
    default:
      ERROR(log, "not supported http method, type=%u", type);
      break;
  }

  return;
}

static
struct bufferevent* snw_setup_connection_https(struct event_base *base, void *arg) {
  snw_http_context_t *ctx = (snw_http_context_t*)arg;
  struct bufferevent* r;
  SSL_CTX *ssl_ctx = ctx->ssl_ctx;

  r = bufferevent_openssl_socket_new (base,
        -1, SSL_new (ssl_ctx), BUFFEREVENT_SSL_ACCEPTING,
        BEV_OPT_CLOSE_ON_FREE);

  return r;
}

static snw_log_t *g_log = 0;
void
snw_libevent_log_cb(int severity, const char *msg) {
  if (g_log)
    ERROR(g_log, "libevent: %s",msg);
}

int
snw_http_send_msg(snw_http_context_t *ctx, char *buf, int len, uint32_t flowid) {
  struct evhttp_request *req = 0;
  struct evbuffer *outbuf = 0;

  DEBUG(ctx->log,"send http msg, len=%u, data=%s",len,buf);

  req = (struct evhttp_request *)snw_flowset_getobj(ctx->flowset,flowid);
  if (!req) return -1;

  evhttp_add_header(evhttp_request_get_output_headers(req),
                     "Content-type", "application/json");
  evhttp_add_header(evhttp_request_get_output_headers(req),
                     "Access-Control-Allow-Origin", "*");

  outbuf = evhttp_request_get_output_buffer(req);
  if (outbuf == NULL) return -2;
  evbuffer_add_printf(outbuf, "%s\n", buf);
  evhttp_send_reply(req, HTTP_OK, "OK", outbuf);

  snw_flowset_freeid(ctx->flowset,flowid);
  return 0;
}

void
snw_http_dispatch_msg(int fd, short int event,void* data) {
   static char buf[MAX_BUFFER_SIZE];
   snw_http_context_t *http_ctx = (snw_http_context_t *)data;
   uint32_t len = 0;
   uint32_t flowid = 0;
   uint32_t cnt = 0;
   int ret = 0;

   while (true) {
     len = 0;
     flowid = 0;
     cnt++;

     if (cnt >= 100) {
         break;
     }

     ret = snw_shmmq_dequeue(http_ctx->task_ctx->req_mq, buf, MAX_BUFFER_SIZE, &len, &flowid);
     if ( (len == 0 && ret == 0) || (ret < 0) )
        return;

     buf[len] = 0;
     snw_http_send_msg(http_ctx,buf,len,flowid);
   }

   return;
}

void
snw_http_task_cb(snw_task_ctx_t *task_ctx, void *data) {
  snw_context_t *ctx = (snw_context_t *)data;
  snw_http_context_t *http_ctx = 0;
  snw_flowset_t *flowset = 0;
  struct event *q_event;

  setproctitle("\\_ http");

  if (ctx == 0)
    return;

  http_ctx = (snw_http_context_t*)malloc(sizeof(snw_http_context_t));
  if (!http_ctx) exit(-4);
  http_ctx->ctx = ctx;
  http_ctx->task_ctx = task_ctx;

  http_ctx->ev_base = event_base_new();
  if (http_ctx->ev_base == 0) {
    exit(-2);
  }

  //snw_http_init_shmqueue(ctx);
  snw_http_init_log(http_ctx);
  snw_http_init_ssl(http_ctx);

  if (ctx->libevent_log_enabled) {
    g_log = http_ctx->log;
    event_enable_debug_logging(EVENT_DBG_ALL);
    event_set_log_callback(snw_libevent_log_cb);
  }

  flowset = snw_flowset_init(SNW_CORE_FLOW_NUM_MAX);
  if (flowset == 0) {
     free(http_ctx);
     assert(0);
  }
  http_ctx->flowset = flowset;
  http_ctx->httpd = evhttp_new(http_ctx->ev_base);
  if (!http_ctx->httpd) exit(-3);

  //FIXME: ipaddress
  if (evhttp_bind_socket(http_ctx->httpd, "0.0.0.0", 8868) != 0)
    exit(-4);

  evhttp_set_allowed_methods(http_ctx->httpd,
      EVHTTP_REQ_GET |
      EVHTTP_REQ_POST |
      EVHTTP_REQ_OPTIONS |
      EVHTTP_REQ_HEAD |
      EVHTTP_REQ_PUT |
      EVHTTP_REQ_DELETE);

  evhttp_set_bevcb(http_ctx->httpd, snw_setup_connection_https, http_ctx);
  evhttp_set_gencb(http_ctx->httpd, snw_process_http_request, http_ctx);

  //get response from main
  q_event = event_new(http_ctx->ev_base, task_ctx->req_mq->pipe[0],
        EV_TIMEOUT|EV_READ|EV_PERSIST, snw_http_dispatch_msg, http_ctx);
  event_add(q_event, NULL);

  event_base_dispatch(http_ctx->ev_base);
  return;
}

