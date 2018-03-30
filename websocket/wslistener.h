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

#ifndef EVWS_WSLISTENER_H_
#define EVWS_WSLISTENER_H_

/**
   @file evws/wslistener.h
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/ssl.h>

#include <event2/listener.h>

struct sockaddr;
struct evwsconnlistener;
struct evwsconn;

/**
   A callback invoked when the listener has a new WebSocket connection
   and the handshake has been successfully completed.

   NOTE: The callback must take ownership of the evwsconn struct and
   deallocate it (via evwsconn_free()) when done with it.

   @param listener The evwsconnlistener
   @param conn The new evwsconn struct for the new connection
   @param address The source address of the connection
   @param socklen The length of the address
   @param user_data The pointer passed to evwsconnlistener_new
 */
typedef void (*evwsconnlistener_cb)(struct evwsconnlistener *listener,
    struct evwsconn *conn, struct sockaddr *address, int socklen,
    void *user_data);

/**
   A callback invoked when an error occurs on the listener.

   @param listener The evwsconnlistener
   @param user_data The pointer passed to evwsconnlistener_new
 */
typedef void (*evwsconnlistener_errorcb)(struct evwsconnlistener *listener,
    void *user_data);

/**
   Allocate a new evwsconnlistener object to listen for incoming WebSocket
   connections a given file descriptor.

   @param base The event base from libevent
   @param cb The connection callback as defined above
   @param user_data A user-supplied pointer that will be passed to the
      callbacks
   @param flags Any number of LEV_OPT_* flags from libevent
   @param backlog Passed to the listen() call to determine the length of the
      acceptable connection backlog.  Set to -1 for reasonable default.
   @param subprotocols An array of subprotocols that are supported by the
      server.  If no subprotocols are supported, NULL may be sent.
   @param server_ctx The server SSL context is SSL is to be used on the
      connection.  If SSL is not desired, NULL should be sent.
   @param fd The file descriptor to listen on.  It must be a non-blocking
      file descriptor, and it should already be bound to an appropriate
      port and address.
 */
struct evwsconnlistener *evwsconnlistener_new(struct event_base *base,
    evwsconnlistener_cb cb, void *user_data, unsigned flags, int backlog,
    const char* subprotocols[], SSL_CTX* server_ctx, evutil_socket_t fd);

/**
   Allocate a new evwsconnlistener object to listen for incoming WebSocket
   connections a given file descriptor.

   @param base The event base from libevent
   @param cb The connection callback as defined above
   @param user_data A user-supplied pointer that will be passed to the
      callbacks
   @param flags Any number of LEV_OPT_* flags from libevent
   @param backlog Passed to the listen() call to determine the length of the
      acceptable connection backlog.  Set to -1 for reasonable default.
   @param subprotocols An array of subprotocols that are supported by the
      server.  If no subprotocols are supported, NULL may be sent.
   @param server_ctx The server SSL context is SSL is to be used on the
      connection.  If SSL is not desired, NULL should be sent.
   @param addr The address to listen for connections on.
   @param socklen The length of the address.
 */
struct evwsconnlistener *evwsconnlistener_new_bind(struct event_base *base,
    evwsconnlistener_cb cb, void *user_data, unsigned flags, int backlog,
    const char* subprotocols[], SSL_CTX* server_ctx,
    const struct sockaddr *addr, int socklen);

/** Disable and deallocate an evwsconnlistener. */
void evwsconnlistener_free(struct evwsconnlistener *levws);

/** Return an evwsconnlistener's associated evconnlistener. */
struct evconnlistener *evconnlistener_get_evconnlistener(
    struct evwsconnlistener *levws);

/** Change the callback on the listener to cb and its user_data. */
void evwsconnlistener_set_cb(struct evwsconnlistener *levws,
    evwsconnlistener_cb cb, void *user_data);

/** Set an evwsconnlistener's error callback. */
void evwsconnlistener_set_error_cb(struct evwsconnlistener *levws,
    evwsconnlistener_errorcb errorcb);

#ifdef __cplusplus
}
#endif

#endif /* EVWS_WSLISTENER_H_ */
