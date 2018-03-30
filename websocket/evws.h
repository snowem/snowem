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

#ifndef EVWS_EVWS_H_
#define EVWS_EVWS_H_


#include <wslay/wslay.h>

#ifdef __cplusplus
extern "C" {
#endif

struct evwsconn;

/** Types of data in messages sent and received by a WebSocket connection */
enum evws_data_type {
  EVWS_DATA_TEXT = 0,
  EVWS_DATA_BINARY = 1,
};

/**
   A callback invoked when a new message been received on the WebSocket
   connection

   @param conn The evwsconn that received the data
   @param data_type The type of data received
   @param data The data received
   @param len The length of the data
   @param user_data The user-supplied pointer passed to evwsconn_set_cbs
 */
typedef void (*evwsconn_message_cb)(struct evwsconn *conn,
    enum evws_data_type, const unsigned char* data, int len, void *user_data);

/**
   A callback invoked when the WebSocket connection has been closed.

   @param conn The evwsconn that received the data
   @param user_data The user-supplied pointer passed to evwsconn_set_cbs
 */
typedef void (*evwsconn_close_cb)(struct evwsconn *conn, void *user_data);

/**
   A callback invoked when an unrecoverable error has occured on the
   WebSocket connection.

   @param conn The evwsconn that received the data
   @param user_data The user-supplied pointer passed to evwsconn_set_cbs
 */
typedef void (*evwsconn_error_cb)(struct evwsconn *conn, void *user_data);

/**
   Sets (or changes) callbacks on a WebSocket connection.

   @param conn The evwsconn that received the data
   @param message_cb Message (new data received) callback
   @param close_cb Close callback
   @param error_cb Error callback
   @param user_data The user-supplied pointer passed to evwsconn_set_cbs
 */
void evwsconn_set_cbs(struct evwsconn *conn, evwsconn_message_cb message_cb,
    evwsconn_close_cb close_cb, evwsconn_error_cb error_cb,
    void* user_data);

/**
   Send a new message on the WebSocket connection.

   @param conn The evwsconn on which to send the message
   @param data_type The type of data to be sent
   @param data The data to send
   @param len The length of the data
 */
void evwsconn_send_message(struct evwsconn *conn,
    enum evws_data_type data_type, const unsigned char* data, size_t len);


/**
   Get the subprotocol used for this connection.

   @param conn The evwsconn for which to get the subprotocol
  */
const char* evwsconn_get_subprotocol(struct evwsconn *conn);

/**
   Send a close message to client and, once sent, close the connection.

   NOTE: evwsconn_close_cb() will still be called when the connection is
   closed.  Calling evwsconn_free() before that callback will prevent the
   close message from being sent as required to cleanly close a WebSocket
   connection.
  */
void evwsconn_send_close(struct evwsconn *conn);

/** Disable and deallocate an evwsconn */
void evwsconn_free(struct evwsconn* conn);

struct evwsconn {
  unsigned char alive : 1;
  struct bufferevent* bev;
  wslay_event_context_ptr ctx;
  evwsconn_message_cb message_cb;
  evwsconn_close_cb close_cb;
  evwsconn_error_cb error_cb;
  const char* subprotocol;

  uint32_t   ip;
  uint32_t   port;
  uint32_t   flowid;
  void      *user_data;
  void      *ice_handle;
};



#ifdef __cplusplus
}
#endif

#endif /* EVWS_EVWS_H_ */
