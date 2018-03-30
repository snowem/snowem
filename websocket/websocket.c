#include <assert.h>

#include "core/core.h"
#include "core/log.h"
#include "core/types.h"
#include "core/snw_event.h"
#include "evws.h"
#include "websocket.h"
#include "wslistener.h"

static const char* subprotocols[] = {"default"};

static void
notify_event(struct evwsconn* conn, uint32_t type,
     snw_websocket_context_t *ctx) {
  snw_event_t event;
  time_t cur_time;

  DEBUG(ctx->log, "notify event, flowid=%u, event=%u", conn->flowid, event);

  cur_time = time(NULL);
  memset(&event,0,sizeof(event));
  event.magic_num = SNW_EVENT_MAGIC_NUM;
  event.event_type = type; //i.e. snw_ev_connect;
  event.ipaddr = conn->ip;
  event.port = conn->port;
  event.flow = conn->flowid;
  event.other = bufferevent_getfd(conn->bev);
  
  snw_shmmq_enqueue(ctx->task_ctx->resp_mq,
      cur_time,&event,sizeof(event),conn->flowid);

  return;
}

void
close_handler(struct evwsconn* conn, void* user_data) {
  snw_websocket_context_t *ctx = (snw_websocket_context_t *)user_data;
  //snw_event_t event;
  //time_t cur_time;

  DEBUG(ctx->log,"close connection, flowid=%u",conn->flowid);

  /*cur_time = time(NULL);
  memset(&event,0,sizeof(event));
  event.magic_num = SNW_EVENT_MAGIC_NUM;
  event.event_type = snw_ev_disconnect;
  event.ipaddr = conn->ip;
  event.port = conn->port;
  event.flow = conn->flowid;
  event.other = bufferevent_getfd(conn->bev);*/

  notify_event(conn,snw_ev_disconnect,ctx);

  snw_flowset_freeid(ctx->flowset,conn->flowid);
  evwsconn_free(conn);
}


void
error_handler(struct evwsconn* conn, void* user_data) {
  snw_event_t event;
  time_t cur_time;
  snw_websocket_context_t *ctx = (snw_websocket_context_t *)user_data;
  
  DEBUG(ctx->log,"error connection, flowid=%u",conn->flowid);

  cur_time = time(NULL);
  memset(&event,0,sizeof(event));
  event.magic_num = SNW_EVENT_MAGIC_NUM;
  event.event_type = snw_ev_disconnect;
  event.ipaddr = conn->ip;
  event.port = conn->port;
  event.flow = conn->flowid;
  event.other = bufferevent_getfd(conn->bev);

  snw_shmmq_enqueue(ctx->task_ctx->resp_mq,
      cur_time,&event,sizeof(event),conn->flowid);

  snw_flowset_freeid(ctx->flowset,conn->flowid);
  evwsconn_free(conn);
} 

void message_handler(struct evwsconn* conn, enum evws_data_type data_type,
     const unsigned char* data, int len, void* user_data) {
  static char buf[MAX_BUFFER_SIZE];
  snw_event_t event;
  time_t cur_time;
  snw_websocket_context_t *ctx = (snw_websocket_context_t *)user_data;

  DEBUG(ctx->log, "message handler, flowid=%u, len=%u", conn->flowid, len);

  cur_time = time(NULL);
  memset(&event,0,sizeof(event));
  event.magic_num = SNW_EVENT_MAGIC_NUM;
  event.event_type = snw_ev_data;
  event.ipaddr = conn->ip;
  event.port = conn->port;
  event.flow = conn->flowid;
  event.other = bufferevent_getfd(conn->bev);

  memcpy(buf, &event, sizeof(event));
  memcpy(buf+sizeof(event),data,len);
   
  snw_shmmq_enqueue(ctx->task_ctx->resp_mq,
      cur_time,buf,len+sizeof(event),conn->flowid);

  return;
}


void 
new_wsconnection(struct evwsconnlistener *wslistener, struct evwsconn *conn, 
                 struct sockaddr *address, int socklen, void* user_data) {
  uint32_t flowid = 0;
  snw_websocket_context_t *ctx = (snw_websocket_context_t *)user_data;


  flowid = snw_flowset_getid(ctx->flowset);
  if (flowid ==0) {
     ERROR(ctx->log, "connection limit reached");
     return;
  }

  DEBUG(ctx->log, "new connection, conn=%p, flowid=%u, baseidx=%u", 
           conn, flowid,ctx->flowset->baseidx);
  conn->flowid = flowid;
  conn->ip = ((struct sockaddr_in*) address)->sin_addr.s_addr;
  conn->port = ((struct sockaddr_in*) address)->sin_port;
  snw_flowset_setobj(ctx->flowset,flowid,conn);

  evwsconn_set_cbs(conn, message_handler, close_handler, error_handler, ctx);
  notify_event(conn,snw_ev_connect,ctx);

  return;
}

void ws_listener_error(struct evwsconnlistener *wslistener, void* user_data) {
  snw_context_t *ctx = (snw_context_t *)user_data;
  ERROR(ctx->log, "Error on Web Socket listener: %s", strerror(errno));
  exit(-1);
}

int
snw_websocket_send_msg(snw_websocket_context_t *ws_ctx, char *buf, int len, uint32_t flow) {
   struct evwsconn* conn = 0;

   DEBUG(ws_ctx->log, "get connection, flowid=%u, baseidx=%u", flow, ws_ctx->flowset->baseidx);
   conn = (struct evwsconn*)snw_flowset_getobj(ws_ctx->flowset,flow);
   if (conn == NULL) {
      ERROR(ws_ctx->log, "connection not found, flowid=%u", flow);
      return -3;
   }

   ERROR(ws_ctx->log, "send msg, conn=%p, flowid=%u, num=%u, msg=%s", 
          conn, flow, ws_ctx->flowset->totalnum,buf);
   evwsconn_send_message(conn, EVWS_DATA_TEXT, (const unsigned char*)buf, len);

   return 0;
}

void
snw_websocket_dispatch_msg(int fd, short int event,void* data) {
   static char buf[MAX_BUFFER_SIZE];
   snw_websocket_context_t *ws_ctx = (snw_websocket_context_t *)data;
   uint32_t len = 0;
   uint32_t flowid = 0;
   uint32_t cnt = 0;
   int ret = 0; 
   
   while (true) {
     len = 0;
     flowid = 0;
     cnt++;

     if ( cnt >= 100) {
         break;
     }

     ret = snw_shmmq_dequeue(ws_ctx->task_ctx->req_mq, buf, MAX_BUFFER_SIZE, &len, &flowid);
     if ( (len == 0 && ret == 0) || (ret < 0) )
        return;
     
     buf[len] = 0;
     snw_websocket_send_msg(ws_ctx,buf,len,flowid);
   }

   return;
}

int
snw_websocket_init_ssl(snw_websocket_context_t *ctx) {
   SSL_CTX  *server_ctx = NULL;

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
         ctx->wss_cert_file,ctx->wss_key_file);

   if (! SSL_CTX_use_certificate_chain_file(server_ctx, ctx->wss_cert_file) ||
       ! SSL_CTX_use_PrivateKey_file(server_ctx, ctx->wss_key_file, SSL_FILETYPE_PEM)) {
       ERROR(ctx->log,"failed to read cert or key files");
       return -3;
   }
   ctx->ssl_ctx = server_ctx;

   return 0;
}

void
snw_net_task_cb(snw_task_ctx_t *task_ctx, void *data) {
   snw_context_t *ctx = (snw_context_t *)data;
   struct event *q_event;
   struct sockaddr_in sin;
   struct evwsconnlistener* levws = 0;
   snw_websocket_context_t *ws_ctx = 0;
   snw_flowset_t *flowset = 0;

   if (ctx == 0) return;

   ws_ctx = (snw_websocket_context_t*)malloc(sizeof(*ws_ctx));
   if (ws_ctx == 0) {
      ERROR(ctx->log, "can not create ws context");
      assert(0);
   }
   memset(ws_ctx,0,sizeof(*ws_ctx));
   ws_ctx->ctx = ctx;
   ws_ctx->task_ctx = task_ctx;

   ws_ctx->ev_base = event_base_new();
   if (ws_ctx->ev_base == 0) {
      exit(-2);
   }

   ws_ctx->log = snw_log_init(ctx->websocket_log_file, ctx->log_level,
       ctx->log_rotate_num, ctx->log_file_maxsize);
   if (ws_ctx->log == 0) {
      exit(-1);   
   }

   ws_ctx->wss_cert_file = strdup(ctx->wss_cert_file);
   ws_ctx->wss_key_file = strdup(ctx->wss_key_file);
   snw_websocket_init_ssl(ws_ctx);

   flowset = snw_flowset_init(SNW_CORE_FLOW_NUM_MAX);
   if (flowset == 0) {
      free(ws_ctx);
      assert(0);
   }
   ws_ctx->flowset = flowset;

   q_event = event_new(ws_ctx->ev_base, task_ctx->req_mq->pipe[0], 
         EV_TIMEOUT|EV_READ|EV_PERSIST, snw_websocket_dispatch_msg, ws_ctx);
   event_add(q_event, NULL);   

   memset(&sin, 0, sizeof(sin));
   sin.sin_family = AF_INET;
   sin.sin_addr.s_addr = inet_addr(ctx->wss_ip);
   sin.sin_port = htons(ctx->wss_port);

   DEBUG(ws_ctx->log,"wss_ip: %s, wss_port: %d", ctx->wss_ip, ctx->wss_port);

   levws = evwsconnlistener_new_bind(ws_ctx->ev_base, 
      new_wsconnection, ws_ctx,
      LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1, 
      subprotocols, ws_ctx->ssl_ctx,
      (struct sockaddr*)&sin, sizeof(sin));
   if (!levws) {
      ERROR(ws_ctx->log, "Error creating Web Socket listener: %s", strerror(errno));
      exit(-1);
   }
   evwsconnlistener_set_error_cb(levws, ws_listener_error);
   event_base_dispatch(ws_ctx->ev_base);

   return;
}


