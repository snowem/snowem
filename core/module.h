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

#ifndef _SNOW_MODULES_MODULE_H_
#define _SNOW_MODULES_MODULE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "bsd_queue.h"
#include "types.h"

/* Built-in module (msg) type */
enum {
   SNW_MSGTYPE_MIN = 1,
   SNW_ICE = SNW_MSGTYPE_MIN,
   SNW_CORE = 2,
   SNW_EVENT = 3,
   SNW_SIG = 4,
   SNW_CHANNEL = 5,

   /* reserve range */
   SNW_MSGTYPE_MAX = 255,
};

/* ICE api code */
enum {
   // public api
   SNW_ICE_MIN = 1,
   SNW_ICE_CREATE = SNW_ICE_MIN,
   SNW_ICE_CONNECT = 2,
   SNW_ICE_PUBLISH = 3,
   SNW_ICE_PLAY = 4,
   SNW_ICE_STOP = 5,
   SNW_ICE_CONTROL = 6,
   SNW_ICE_AUTH = 7,

   // internal api
   SNW_ICE_SDP = 128,
   SNW_ICE_CANDIDATE = 129,
   SNW_ICE_FIR = 130,

   /* reserved range */
   SNW_ICE_MAX = 255,
};

/* CORE api code */
enum {
   SNW_CORE_MIN = 1,
   SNW_CORE_RTP = SNW_CORE_MIN,
   SNW_CORE_RTCP = 2,

   /* reserved range */
   SNW_CORE_MAX = 255,
};

/* EVENT api code */
enum {
   SNW_EVENT_MIN = 1,
   SNW_EVENT_ICE_CONNECTED = SNW_EVENT_MIN,
   SNW_EVENT_ADD_STREAM = 2,
   SNW_EVENT_REMOVE_STREAM = 3,
   SNW_EVENT_JOINED_STREAM = 4,

   /* reserved range */
   SNW_EVENT_MAX = 255,
};

/* SIG api code */
enum {
   SNW_SIG_MIN = 1,
   SNW_SIG_AUTH = SNW_SIG_MIN,
   SNW_SIG_CREATE = 2,
   SNW_SIG_CONNECT = 3,
   SNW_SIG_CALL = 4,
   SNW_SIG_PUBLISH = 5,
   SNW_SIG_PLAY = 6,

   // internal api
   SNW_SIG_SDP = 128,
   SNW_SIG_CANDIDATE = 129,

   SNW_SIG_MAX = 255,
};

/* CHANNEL api code */
enum {
   SNW_CHANNEL_MIN = 1,
   SNW_CHANNEL_CREATE = SNW_CHANNEL_MIN,
   SNW_CHANNEL_DELETE = 2,
   SNW_CHANNEL_QUERY = 3,
   SNW_CHANNEL_CONNECT = 4,
   SNW_CHANNEL_DISCONNECT = 5,
   SNW_CHANNEL_CREATE_STREAM = 6,

   SNW_CHANNEL_MAX = 255,
};

typedef struct snw_module_callbacks snw_module_callbacks_t;
struct snw_module_callbacks {

int   (*enqueue)(void *mq, const time_t curtime, const void* data, 
                 uint32_t len, uint32_t flow);
};

typedef struct snw_module_methods snw_module_methods_t;
struct snw_module_methods {
   void               (*handle_msg)(void *ctx, void *conn, char *buffer, int len);
};

struct snw_module {
   LIST_ENTRY(snw_module) list;
   uint32_t               type; //module type
   uint32_t               version;
   char                  *name;
   char                  *sofile;
   void                  *ctx;
   void                  *data;

   snw_module_methods_t *methods;

   void               (*init)(void *ctx);
   void               (*fini)();

   char                 reserve[128];
};
typedef LIST_HEAD(module_head, snw_module) module_head_t;

void
snw_module_init(snw_context_t *ctx);

void
snw_module_enqueue(void *mq, const time_t curtime, const void* data,
                  uint32_t len, uint32_t flow);


#ifdef __cplusplus
}
#endif

#endif //_SNOW_MODULES_MODULE_H_



