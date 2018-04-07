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

#include "rtp/rtp_utils.h"

int
snw_rtp_get_hdrlen(rtp_hdr_t *hdr) {
   //uint16_t id = 0;
   int hdrlen = 0;
   int extlen = 0;
   char *p, *buf;

   if (!hdr) return 0;

   hdrlen = MIN_RTP_HEADER_SIZE + 4*hdr->cc;
   buf = (char*)hdr;
   if (hdr->x) {
      uint16_t len;
      p = buf + hdrlen; 
      //id = ntohs(*((uint16_t*)p));
      len = ntohs(*((uint16_t*)(p+2)));
      extlen = 4 + 4*len;
      hdrlen += extlen;
   }

   return hdrlen;
}
