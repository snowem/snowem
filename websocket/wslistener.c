/*
 * libevws
 *
 * Copyright (c) 2013 Alexander Carobus
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

#include "wslistener.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/err.h>
#include <event2/bufferevent_ssl.h>
#include <event2/buffer.h>

#include "evws.h"
#include "evws-internal.h"
#include "evws_util.h"

#include "core/log.h"
#include "core/utils.h"

#define MAX_HTTP_HEADER_SIZE 8192

struct evwspendingconn {
  struct evwsconnlistener* levws;
  struct bufferevent* bev;
  struct sockaddr *address;
  int socklen;
  struct evwspendingconn* next;
};

struct evwsconnlistener {
  struct evconnlistener* lev;
  evwsconnlistener_cb cb;
  evwsconnlistener_errorcb errorcb;
  void* user_data;
  const char** supported_subprotocols;
  SSL_CTX* server_ctx;
  struct evwspendingconn* head;
};

static void remove_pending(struct evwspendingconn* pending) {
  if (!pending || !pending->levws) {
    return;
  }
  struct evwspendingconn* curr = pending->levws->head;
  if (curr == pending) {
    pending->levws->head = curr->next;
  } else {
    while(curr && curr->next != pending)
      curr = curr->next;
    if (curr) {
      curr->next = curr->next->next;
    }
  }
  pending->levws = NULL;
}

static void free_pending(struct evwspendingconn* pending) {
  if (pending->bev)
    bufferevent_free(pending->bev);
  free(pending->address);
  free(pending);
}

static void pending_read(struct bufferevent *bev, void *pending_ptr) {

  struct evwspendingconn* pending = (struct evwspendingconn *)pending_ptr;
  struct evbuffer* input = bufferevent_get_input(pending->bev);
  struct evbuffer_ptr end = evbuffer_search(input, "\r\n\r\n", 4, NULL);
  size_t len = evbuffer_get_length(input);

  //WSS_DEBUG("pending read, len=%u,pos=%d",len,end.pos);
  //char buf[4096] = {0};
  //evbuffer_copyout(input,buf,len);
  //hexdump(buf,len,"frame");

  if (end.pos == -1) {
    if (len > MAX_HTTP_HEADER_SIZE) {
      remove_pending(pending);
      free_pending(pending);
    }
    return; // full request not yet found
  }

  unsigned char* data = evbuffer_pullup(input, len);
  char accept_key[29];

  struct evwsconnlistener* levws = pending->levws;
  const char* subprotocol = NULL;
  if (evaluate_websocket_handshake((char*)data, len,
      levws->supported_subprotocols, accept_key, &subprotocol)) {
    remove_pending(pending);
    free_pending(pending);
    return;
  }

  evbuffer_drain(input, len);

  bufferevent_setcb(pending->bev, NULL, NULL, NULL, pending);

  struct evbuffer* output = bufferevent_get_output(pending->bev);
  evbuffer_add_printf(output,
      "HTTP/1.1 101 Switching Protocols\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Accept: %s\r\n", accept_key);

  if (subprotocol != NULL) {
    evbuffer_add_printf(output, "Sec-WebSocket-Protocol: %s\r\n\r\n",
        subprotocol);
  } else {
    evbuffer_add_printf(output, "\r\n");
  }

  remove_pending(pending);
  struct evwsconn *wsconn = evwsconn_new(pending->bev, subprotocol);
  pending->bev = NULL;
  levws->cb(levws, wsconn, pending->address, pending->socklen,
      levws->user_data);
  free_pending(pending);
}

static void pending_event(struct bufferevent *bev, short events,
    void *pending_ptr) {
  struct evwspendingconn* pending = (struct evwspendingconn *)pending_ptr;
  if (events & BEV_EVENT_EOF) {
    WSS_ERROR("Connection closed");
  } else if (events & BEV_EVENT_ERROR) {
    WSS_ERROR("Connection error, errno=%d",errno);
    if (errno != 0) {
      WSS_ERROR("Got an error on the connection: %s", strerror(errno));
    }
    unsigned long ssl_error = ERR_get_error();
    if (ssl_error != 0) {
      WSS_ERROR("SSL error: %s", ERR_error_string(ssl_error, NULL));
    }
    ssl_error = bufferevent_get_openssl_error(bev);
    if (ssl_error != 0) {
      WSS_ERROR("Got an SSL error on the connection: %s",
          ERR_error_string(ssl_error, NULL));
    }

  } else if (events & BEV_EVENT_CONNECTED) {
    WSS_DEBUG("SSL connected");

    return; // SSL connected
  } else {
    WSS_ERROR("Unknown event: %x", (int)events);
  }

  remove_pending(pending);
  free_pending(pending);
}

static void lev_cb(struct evconnlistener *evlistener,
    evutil_socket_t fd, struct sockaddr *address, int socklen,
    void *levws_ptr) {
  struct evwsconnlistener* levws = (struct evwsconnlistener *)levws_ptr;
  struct event_base *base = evconnlistener_get_base(levws->lev);

  struct evwspendingconn *pending =
      (struct evwspendingconn *)malloc(sizeof(struct evwspendingconn));
  pending->levws = levws;

  if (levws->server_ctx == NULL) {
    //WSS_DEBUG("handle normal bev, fd=%u",fd);
    pending->bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
  } else {
    SSL *client_ctx = SSL_new(levws->server_ctx);
    if (client_ctx == NULL) {
      WSS_ERROR("Unable to get client_ctx, fd=%d",fd);
      exit(-1);
    }
    //WSS_DEBUG("handle ssl bev, fd=%u",fd);
    pending->bev = bufferevent_openssl_socket_new(base, fd, client_ctx,
        BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);

    if ( pending->bev == NULL ) {
       WSS_ERROR("failed to create ssl bev, fd=%u",fd);
    }
  }

  bufferevent_setcb(pending->bev, pending_read, NULL, pending_event, pending);
  bufferevent_enable(pending->bev, EV_READ);

  pending->address = (struct sockaddr *)malloc(socklen);
  memcpy(pending->address, address, socklen);
  pending->socklen = socklen;

  pending->next = levws->head;
  levws->head = pending;
}

static void lev_error_cb(struct evconnlistener *evlistener, void* levws_ptr) {
  struct evwsconnlistener* levws = (struct evwsconnlistener *)levws_ptr;
  if (levws->errorcb)
    levws->errorcb(levws, levws->user_data);
}

struct evwsconnlistener *evwsconnlistener_new(struct event_base *base,
    evwsconnlistener_cb cb, void *user_data, unsigned flags, int backlog,
    const char* subprotocols[], SSL_CTX* server_ctx, evutil_socket_t fd) {
  struct evwsconnlistener *levws =
      (struct evwsconnlistener *)malloc(sizeof(struct evwsconnlistener));
  if (!levws)
    return NULL;

  levws->lev = evconnlistener_new(base, lev_cb, levws, flags, backlog, fd);
  if (!levws->lev) {
    free(levws);
    return NULL;
  }
  levws->cb = cb;
  levws->errorcb = NULL;
  levws->user_data = user_data;
  levws->supported_subprotocols = subprotocols;
  levws->server_ctx = server_ctx;
  levws->head = NULL;

  return levws;
}

struct evwsconnlistener *evwsconnlistener_new_bind(struct event_base *base,
    evwsconnlistener_cb cb, void *user_data, unsigned flags, int backlog,
    const char* subprotocols[], SSL_CTX* server_ctx,
    const struct sockaddr *addr, int socklen) {

  struct evwsconnlistener *levws =
      (struct evwsconnlistener *)malloc(sizeof(struct evwsconnlistener));
  if (!levws)
    return NULL;
  levws->lev = evconnlistener_new_bind(base, lev_cb, levws, flags, backlog,
      addr, socklen);

  if (!levws->lev) {
    perror("cannot bind ip\n");
    free(levws);
    return NULL;
  }

  levws->cb = cb;
  levws->errorcb = NULL;
  levws->user_data = user_data;
  levws->supported_subprotocols = subprotocols;
  levws->server_ctx = server_ctx;
  levws->head = NULL;

  return levws;
}

void evwsconnlistener_free(struct evwsconnlistener *levws) {
  if (levws == NULL) {
    return;
  }
  struct evwspendingconn* curr = levws->head;
  while (curr) {
    struct evwspendingconn* temp = curr;
    curr = curr->next;
    free_pending(temp);
  }
  evconnlistener_free(levws->lev);
  free(levws);
}

struct evconnlistener *evconnlistener_get_evconnlistener(
    struct evwsconnlistener *levws) {
  return levws->lev;
}

void evwsconnlistener_set_cb(struct evwsconnlistener *levws,
    evwsconnlistener_cb cb, void *user_data) {
  levws->cb = cb;
  levws->user_data = user_data;
}

void evwsconnlistener_set_error_cb(struct evwsconnlistener *levws,
    evwsconnlistener_errorcb errorcb) {
  levws->errorcb = errorcb;
  evconnlistener_set_error_cb(levws->lev, errorcb ? lev_error_cb : NULL);
}
