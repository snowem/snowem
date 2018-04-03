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

#ifndef _ICE_VP8_H
#define _ICE_VP8_H

#include "core/types.h"
#include "rtp/packet.h"

typedef struct vp8_desc vp8_desc_t;
struct vp8_desc {
//#if __BYTE_ORDER == __BIG_ENDIAN
//   uint8_t X:1;
//   uint8_t R1:1;
//   uint8_t N:1;
//   uint8_t S:1;
//   uint8_t R2:1;
//   uint8_t PID:3;
//#elif __BYTE_ORDER == __LITTLE_ENDIAN
   uint8_t PID:3;
   uint8_t R2:1;
   uint8_t S:1;
   uint8_t N:1;
   uint8_t R1:1;
   uint8_t X:1;
//#endif
   char ext[5];
};

typedef struct vp8_xext vp8_xext_t;
struct vp8_xext {
//#if __BYTE_ORDER == __BIG_ENDIAN
//   uint8_t I:1;
//   uint8_t L:1;
//   uint8_t T:1;
//   uint8_t K:1;
//   uint8_t RSV:4;
//#elif __BYTE_ORDER == __LITTLE_ENDIAN
   uint8_t RSV:4;
   uint8_t K:1;
   uint8_t T:1;
   uint8_t L:1;
   uint8_t I:1;
//#endif
};

//typedef struct vp8_header vp8_header_t;
//struct vp8_header {
//};

int rtp_list_size(rtp_packet_t* head);
void ice_rtp_is_vp8(rtp_packet_t *head, int type, char* buf, int len);

#endif //_ICE_VP8_H




