/*
 * libevws
 *
 * Copyright (c) 2013 github.com/crunchyfrog
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "evws.h"
#include "evws-internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <event2/event.h>
#include <event2/bufferevent_ssl.h>
#include <event2/buffer.h>
#include <wslay/wslay.h>

#include "core/log.h"

static void ws_error(struct evwsconn* conn) {
  conn->alive = 0;
  if (conn->error_cb)
    conn->error_cb(conn, conn->user_data);
}

static void evwsconn_closing_cb(struct bufferevent *bev, void *conn_ptr) {
  struct evwsconn *conn = (struct evwsconn *)conn_ptr;
  conn->alive = 0;
  if (conn->close_cb)
    conn->close_cb(conn, conn->user_data);
}

static void evwsconn_event_cb(struct bufferevent *bev, short events,
    void *conn_ptr) {
  struct evwsconn *conn = (struct evwsconn *)conn_ptr;
  if (events & BEV_EVENT_EOF) {
    if (conn->close_cb)
      conn->close_cb(conn, conn->user_data);
  } else {
    ws_error(conn);
  }
}

static void evwsconn_do_write(struct evwsconn* conn) {
  if (wslay_event_want_write(conn->ctx)) {
    if (wslay_event_send(conn->ctx) < 0) {
      ws_error(conn);
      return;
    }
  }
  if (wslay_event_get_close_sent(conn->ctx)) {
    bufferevent_setcb(conn->bev, NULL, evwsconn_closing_cb, evwsconn_event_cb,
        conn);
  }
}

static void evwsconn_read_cb(struct bufferevent *bev, void *conn_ptr) {
  struct evwsconn *conn = (struct evwsconn *)conn_ptr;
  int ret;
  if ((ret = wslay_event_recv(conn->ctx)) < 0) {
    ws_error(conn);
    return;
  }
  evwsconn_do_write(conn);
}

static ssize_t send_callback(wslay_event_context_ptr ctx, const uint8_t *data,
    size_t len, int flags, void *conn_ptr) {
  struct evwsconn *conn = (struct evwsconn *)conn_ptr;
  struct evbuffer* output = bufferevent_get_output(conn->bev);
  if (evbuffer_add(output, data, len) < 0) {
    wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
    return -1;
  }
  return len;
}

static ssize_t recv_callback(wslay_event_context_ptr ctx, uint8_t *buf,
    size_t len, int flags, void *conn_ptr) {
  struct evwsconn *conn = (struct evwsconn *)conn_ptr;
  struct evbuffer* input = bufferevent_get_input(conn->bev);
  int ret = evbuffer_remove(input, buf, len);
  if (ret < 0) {
    wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
    return -1;
  }
  return ret;
}

static void on_msg_recv_callback(wslay_event_context_ptr ctx,
    const struct wslay_event_on_msg_recv_arg *arg, void *conn_ptr) {
  struct evwsconn *conn = (struct evwsconn *)conn_ptr;
  if(!wslay_is_ctrl_frame(arg->opcode)) {
    if (conn->message_cb) {
      enum evws_data_type data_type;
      switch(arg->opcode) {
      case WSLAY_TEXT_FRAME: data_type = EVWS_DATA_TEXT; break;
      case WSLAY_BINARY_FRAME: data_type = EVWS_DATA_BINARY; break;
      default:
        fprintf(stderr, "Internal error, unexpected type: %d", arg->opcode);
        exit(-1);
        break;
      }
      conn->message_cb(conn, data_type, arg->msg, arg->msg_length,
          conn->user_data);
    }
  }
}

static void internal_evwsconn_free(evutil_socket_t sock, short events,
    void* conn_ptr) {
  struct evwsconn* conn = (struct evwsconn*)conn_ptr;
  SSL *ctx = bufferevent_openssl_get_ssl(conn->bev);
  if (ctx != NULL) {
    /*
     * SSL_RECEIVED_SHUTDOWN tells SSL_shutdown to act as if we had already
     * received a close notify from the other end.  SSL_shutdown will then
     * send the final close notify in reply.  The other end will receive the
     * close notify and send theirs.  By this time, we will have already
     * closed the socket and the other end's real close notify will never be
     * received.  In effect, both sides will think that they have completed a
     * clean shutdown and keep their sessions valid.  This strategy will fail
     * if the socket is not ready for writing, in which case this hack will
     * lead to an unclean shutdown and lost session on the other end.
     */
    SSL_set_shutdown(ctx, SSL_RECEIVED_SHUTDOWN);
    SSL_shutdown(ctx);
  }
  bufferevent_free(conn->bev);
  wslay_event_context_free(conn->ctx);
  free(conn);
}

struct evwsconn* evwsconn_new(struct bufferevent* bev,
    const char* subprotocol) {

  WSS_DEBUG("evwsconn new");

  struct evwsconn *conn = (struct evwsconn *)malloc(sizeof(struct evwsconn));
  memset(conn, 0, sizeof(struct evwsconn));
  conn->alive = 1;
  conn->bev = bev;
  bufferevent_setcb(conn->bev, evwsconn_read_cb, NULL, evwsconn_event_cb,
      conn);
  struct wslay_event_callbacks callbacks = {recv_callback, send_callback,
      NULL, NULL, NULL, NULL, on_msg_recv_callback};
  wslay_event_context_server_init(&conn->ctx, &callbacks, conn);
  conn->subprotocol = subprotocol;
  return conn;
}

const char* evwsconn_get_subprotocol(struct evwsconn *conn) {
  return conn->subprotocol;
}

void evwsconn_free(struct evwsconn* conn) {
  if (conn == NULL) {
    return;
  }
  conn->message_cb = NULL;
  conn->close_cb = NULL;
  conn->error_cb = NULL;
  event_base_once(bufferevent_get_base(conn->bev), -1, EV_TIMEOUT,
      &internal_evwsconn_free, conn, NULL);
}

void evwsconn_set_cbs(struct evwsconn *conn, evwsconn_message_cb message_cb,
    evwsconn_close_cb close_cb, evwsconn_error_cb error_cb,
    void* user_data) {
  conn->message_cb = message_cb;
  conn->close_cb = close_cb;
  conn->error_cb = error_cb;
  conn->user_data = user_data;
}

void evwsconn_send_message(struct evwsconn *conn, enum evws_data_type data_type,
    const unsigned char* data, size_t len) {
  if (!conn->alive) {
    return;
  }
  struct wslay_event_msg msg = {
      data_type == EVWS_DATA_TEXT ? WSLAY_TEXT_FRAME : WSLAY_BINARY_FRAME,
      data, len};
  if (wslay_event_queue_msg(conn->ctx, &msg) < 0) {
    ws_error(conn);
    return;
  }
  evwsconn_do_write(conn);
}

void evwsconn_send_close(struct evwsconn *conn) {
  if (!conn->alive) {
    return;
  }
  if (wslay_event_queue_close(conn->ctx, 0, NULL, 0) < 0) {
    ws_error(conn);
    return;
  }
  evwsconn_do_write(conn);
}
