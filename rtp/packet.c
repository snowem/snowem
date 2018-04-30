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

#include "rtp/packet.h"
#include "rtp/rtp.h"

int
rtp_list_size(rtp_packet_head_t* head) {
   int cnt = 0;
   rtp_packet_t *n;
   TAILQ_FOREACH(n,head,list){ cnt++; }
   return cnt;
}

void
rtp_list_add(rtp_packet_head_t* head, rtp_packet_t *item) {

   if (head == NULL || item == NULL)
      return;

   TAILQ_INSERT_TAIL(head,item,list);

   return;
}

rtp_packet_t*
rtp_list_remove_last(rtp_packet_head_t* head) {
   if (head == NULL) return NULL;

   if (!TAILQ_EMPTY(head)) {
      rtp_packet_t *p = 0;
      p = TAILQ_LAST(head,rtp_list_head);
      TAILQ_REMOVE(head,p,list);
      return p;
   }

   return NULL;
}

/*int rtp_list_size(rtp_packet_head_t* head) {
   int cnt = 0;
   rtp_packet_t *n;
   LIST_FOREACH(n,head,list){ cnt++; }
   return cnt;
}*/


