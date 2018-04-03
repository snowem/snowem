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

#ifndef _SNOW_CORE_CONNECTION_H_
#define _SNOW_CORE_CONNECTION_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


enum {
   WSS_SOCKET_UDP = 1,
   ICE_SOCKET_UDP = 2,
};

typedef struct snw_connection snw_connection_t;
struct snw_connection {
   uint32_t       flowid;
   uint32_t       peerid;
   uint32_t       srctype;
   uint32_t       ipaddr;
   uint16_t       port;
};

#ifdef __cplusplus
}
#endif

#endif //_SNOW_CORE_CONNECTION_H_



