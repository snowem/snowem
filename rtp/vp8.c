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

#include "core/log.h"
#include "core/types.h"
#include "rtp/vp8.h"
#include "rtp/rtp.h"

int g_max_rtp_queue = 3001;
void ice_rtp_is_vp8(rtp_packet_head_t *head, int type, char* buf, int len) {
   rtp_packet_t *rtp = NULL;
   rtp_hdr_t   *rtp_hdr = NULL;
   vp8_desc_t   *vp8 = NULL;
   int rtp_bytes = 0;
   int vp8_desc_bytes = 0;
   int is_key_frame = 0;

   if (len < RTP_HEADER_SIZE )
      return;

   if (!type) {   
      rtp_hdr = (rtp_hdr_t*)buf;
      rtp_bytes = RTP_HEADER_SIZE + rtp_hdr->cc*4;
      vp8 = (vp8_desc_t*)(buf + rtp_bytes);

      //DEBUG("vp8 desc info, markerbit=%u,vp8_desc_t=%u, X=%u, R1=%u, N=%u, S=%u, R2=%u, PID=%u",
      //      rtp_hdr->markerbit, *(unsigned char*)vp8, vp8->X, vp8->R1, vp8->N, vp8->S, vp8->R2, vp8->PID);

      vp8_desc_bytes = 1;
      if ( vp8->X ) {
         vp8_xext_t *x = (vp8_xext_t*)vp8->ext;
         vp8_desc_bytes += 1;
         if ( x->I ) {
            vp8_desc_bytes += 1;
            if ( vp8->ext[1] & 0x80 ) {
               vp8_desc_bytes += 1;
            }
         }
         if ( x->L ) vp8_desc_bytes += 1;
         if ( x->T || x->K ) vp8_desc_bytes += 1;
      }

      if ( vp8->S == 1 && vp8->PID == 0 ) {
         unsigned char c = *(buf + rtp_bytes + vp8_desc_bytes);
         //int got_keyframe = !(c&0x01);
         is_key_frame= !(c&0x01);
      }
   }

   /* Save the packet for retransmissions that may be needed later */
   rtp = SNW_MALLOC(rtp_packet_t);
   if ( rtp == NULL )
      return;
   SNW_MEMZERO(rtp,rtp_packet_t);
   rtp->data = (char*)malloc(len);
   if ( rtp->data == NULL ) {
      free(rtp);
      return;
   }
   memcpy(rtp->data,buf,len);
   rtp->length = len;
   //rtp->media = video;
   rtp->keyframe = is_key_frame;
   rtp->control = type;
   /*if (is_key_frame)
   {  
      //DEBUG("recv key frame, remove all old list, start list with newest keyframe first");
      struct list_head *h;
      int iListSize = rtp_list_size(head);
      //list_for_each(h,&head->list){
      for (int i = 0; i < iListSize; i++){
         rtp_packet_t *p = rtp_list_remove_last(head);
         free(p->data);
         p->data = NULL;
         free(p);        
      }
   }*/
   rtp->last_retransmit = 0;
   rtp_list_add(head,rtp);
   if(rtp_list_size(head) > g_max_rtp_queue) {
      rtp_packet_t *p = rtp_list_remove_last(head);
      free(p->data);
      p->data = NULL;
      free(p);
   }
   //DEBUG("vp8 rtp list, size=%u",rtp_list_size(head));


   return;
}



