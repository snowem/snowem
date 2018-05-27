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

#include <net/if.h>
#include <ifaddrs.h>
#include <sys/types.h>

#include "core/module.h"
#include "core/mq.h"
#include "core/msg.h"
#include "core/log.h"
#include "core/utils.h"
#include "ice/ice_channel.h"
#include "ice/ice_session.h"
#include "ice/process.h"
#include "json-c/json.h"
#include "sdp.h"
#include "rtp/rtcp.h"

void ice_send_candidate(snw_ice_session_t *session,
    int video, char *buffer, int len) {
   snw_log_t *log = 0;
   json_object *jobj = 0, *candobj = 0;
   const char *str = 0;

   if (!session) return;
   log = session->ice_ctx->log;

   jobj = json_object_new_object();
   candobj = json_object_new_object();
   if (!jobj || !candobj) return;
   json_object_object_add(jobj, "msgtype", json_object_new_int(SNW_ICE));
   json_object_object_add(jobj, "api", json_object_new_int(SNW_ICE_CANDIDATE));
   json_object_object_add(jobj, "streamid", json_object_new_int(session->streamid));
   json_object_object_add(jobj, "channelid", json_object_new_int(session->channelid));
   json_object_object_add(jobj, "flowid", json_object_new_int(session->flowid));
   json_object_object_add(jobj, "callid", json_object_new_string("callid"));
   if (video) {
     json_object_object_add(candobj, "label", json_object_new_int(1));
     json_object_object_add(candobj, "id", json_object_new_string("video"));
   } else {
     json_object_object_add(candobj, "label", json_object_new_int(0));
     json_object_object_add(candobj, "id", json_object_new_string("audio"));
   }
   json_object_object_add(candobj, "type", json_object_new_string("candidate"));
   json_object_object_add(candobj, "candidate", json_object_new_string(buffer));
   json_object_object_add(jobj, "candidate", candobj);
   str = snw_json_msg_to_string(jobj);
   if (!str) return;

   DEBUG(log, "sending candidate, candidate=%s", str);
   snw_shmmq_enqueue(session->ice_ctx->task_ctx->resp_mq,0,
     str,strlen(str),session->flowid);

   json_object_put(jobj);

   return;
}

void
snw_ice_send_local_candidate(snw_ice_session_t *session, int video, uint32_t stream_id, uint32_t component_id) {
   snw_log_t *log = 0;
   agent_t* agent = 0;
   snw_ice_stream_t *stream = 0;
   snw_ice_component_t *component = 0;
   candidate_head_t *candidates = NULL;
   candidate_t *c = NULL;
   int len;

   if (!session || !session->agent)
      return;
   log = session->ice_ctx->log;

   agent = session->agent;
   stream = snw_ice_stream_find(&session->streams, stream_id);
   if(!stream) {
      ERROR(log, "stream not found, sid=%d", stream_id);
      return;
   }

   component = snw_component_find(&stream->components, component_id);
   if (!component) {
      ERROR(log, "component not found in a stream, cid=%u, sid=%u", 
            component_id, stream_id);
      return;
   }

   candidates = ice_agent_get_local_candidates(agent, stream_id, component_id);
   if (candidates == 0 )
      return;

   //DEBUG(log, "got list of candidates, size=%u, sid=%u, cid=%u",
   //      list_size(&candidates->list), stream_id, component_id);

   TAILQ_FOREACH(c,candidates,list) {
      char buffer[100] = {0};
      char address[ICE_ADDRESS_STRING_LEN], base_address[ICE_ADDRESS_STRING_LEN];
      int port = 0, base_port = 0;
      address_to_string(&(c->addr), (char *)&address);
      port = address_get_port(&(c->addr));
      address_to_string(&(c->base_addr), (char *)&base_address);
      base_port = address_get_port(&(c->base_addr));

      DEBUG(log, "candidate info, sid=%u, cid=%u, addr=%s, port=%u, priority=%u, foundation=%u",
            c->stream_id, c->component_id, address, port, c->priority, c->foundation);

      if (c->type == ICE_CANDIDATE_TYPE_HOST) {
         if (c->transport == ICE_CANDIDATE_TRANSPORT_UDP) {
            len = snprintf(buffer, 100, "candidate:%s %d %s %d %s %d typ host generation 0",
                  c->foundation, c->component_id, "udp", c->priority, address, port);
         } else {
            WARN(log, "only ice-udp supported");
            candidate_free(c);
            continue;
         }
      } else if (c->type == ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE) {
         if (c->transport == ICE_CANDIDATE_TRANSPORT_UDP) {
            address_to_string(&(c->base_addr), (char *)&base_address);
            int base_port = address_get_port(&(c->base_addr));
            len = snprintf(buffer, 100, "candidate:%s %d %s %d %s %d typ srflx raddr %s rport %d",
                  c->foundation, c->component_id, "udp", c->priority, address, port, base_address, base_port);
         } else {
            DEBUG(log, "only ice-udp supported");
            candidate_free(c);
            continue;
         }
      } else if(c->type == ICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
         WARN(log, "skipping prflx candidate");
         candidate_free(c);
         continue;
      } else if(c->type == ICE_CANDIDATE_TYPE_RELAYED) {
         if(c->transport == ICE_CANDIDATE_TRANSPORT_UDP) {
            len = snprintf(buffer, 100, "candidate:%s %d %s %d %s %d typ relay raddr %s rport %d",
                  c->foundation, c->component_id, "udp", c->priority, address, port, base_address, base_port);
         } else {
            WARN(log, "only ice-udp supported");
            candidate_free(c);
            continue;
         }
      }

      if ( len > 0 ) {
         ice_send_candidate(session,video,buffer,len);
      }

      candidate_free(c);
   }

   //FIXME: free list of candidates
   //candidate_t *c = NULL;
   /*TAILQ_FOREACH(c,&candidates,list) {
      candidate_free(c);
      TAILQ_REMOVE(candidates,c,list);
   }*/

   return;
}

void
snw_ice_sdp_send_candidates(snw_ice_session_t *session) {
   snw_ice_stream_t *s = 0;

   LIST_FOREACH(s,&session->streams,list) {
      snw_ice_send_local_candidate(session, s->is_video, s->id, 1);
      if (!SET_FLAG(session, WEBRTC_RTCPMUX))
         snw_ice_send_local_candidate(session, s->is_video, s->id, 2);
   }

   return;
}

void
snw_ice_send_msg_to_core(snw_ice_context_t *ice_ctx, json_object *jobj, 
      uint32_t flowid, int rc) {
   const char *str;

   json_object_object_add(jobj,"rc",json_object_new_int(rc));
   str = snw_json_msg_to_string(jobj);
   if (!str) return;
   snw_shmmq_enqueue(ice_ctx->task_ctx->resp_mq,0,str,strlen(str),flowid);

   return;
}

void
snw_ice_create_msg(snw_ice_context_t *ice_ctx, void *data, int len, uint32_t flowid) {
   snw_log_t *log = ice_ctx->log;
   json_object *jobj = (json_object*)data;
   snw_ice_channel_t *channel = 0;
   uint32_t channelid = 0;
   int is_new = 0;

   //TODO: this function never be called.
   if (!jobj) return;

   channelid = snw_json_msg_get_int(jobj,"channelid");
   DEBUG(log,"create ice channel, flowid=%u, channelid=%u", 
            flowid, channelid);

   channel = (snw_ice_channel_t*)snw_ice_channel_get(ice_ctx,channelid,&is_new);
   if (!channel || !is_new) {
      ERROR(log,"failed to create ice channel, flowid=%u, is_new=%u", 
            flowid, is_new);
      snw_ice_send_msg_to_core(ice_ctx,jobj,flowid,-1);
      return;
   }

   DEBUG(log,"create ice channel, flowid=%u, channelid=%u", 
            flowid, channelid);
   //TODO: not useful for frontend?
   json_object_object_add(jobj,"id",json_object_new_int(flowid));
   json_object_object_add(jobj,"channelid",json_object_new_int(channelid));
   snw_ice_send_msg_to_core(ice_ctx,jobj,flowid,0);

   return;
}

int
snw_ice_generate_sdp(snw_ice_session_t *session) {
   snw_log_t *log = session->ice_ctx->log;
   char *sdp = 0;

   if (!session) return -1;

   sdp = snw_ice_sdp_create(session);
   if (!sdp) {
      return -2;
   }

   TRACE(log,"generated sdp, local_sdp=%s",sdp);
   session->local_sdp = sdp; //XXX: save sdp for debugging.

   return 0;
}

static void
snw_ice_cb_candidate_gathering_done(agent_t *agent, uint32_t stream_id, void *user_data) {
   snw_ice_session_t *session = (snw_ice_session_t *)user_data;
   snw_log_t *log = session->ice_ctx->log;
   json_object *jobj = 0, *sdpobj = 0;
   const char *str = 0;
   int ret = 0;

   if (!session) return;

   session->streams_gathering_done++;
   DEBUG(log, "gathering done, stream=%d, cdone=%u, streams_num=%u",
         stream_id, session->streams_gathering_done, session->streams_num);

   snw_ice_stream_t *stream = snw_ice_stream_find(&session->streams, stream_id);
   if (!stream) {
      ERROR(log, "stream not found, sid=%d", stream_id);
      return;
   }
   stream->gathering_done = 1;

   if (session->streams_gathering_done == session->streams_num) {
      ret = snw_ice_generate_sdp(session);
      if (ret < 0 || !session->local_sdp) {
         ERROR(log, "failed to generate sdp, ret=%d, local_sdp=%s",
              ret,session->local_sdp);
         return;
      }

      jobj = json_object_new_object();
      sdpobj = json_object_new_object();
      if (!jobj || !sdpobj) return;
      json_object_object_add(jobj, "msgtype", json_object_new_int(SNW_ICE));
      json_object_object_add(jobj, "api", json_object_new_int(SNW_ICE_SDP));
      json_object_object_add(jobj, "streamid", json_object_new_int(session->streamid));
      json_object_object_add(jobj, "channelid", json_object_new_int(session->channelid));
      json_object_object_add(jobj, "flowid", json_object_new_int(session->flowid));
      json_object_object_add(sdpobj, "type", json_object_new_string("offer"));
      json_object_object_add(sdpobj, "sdp", json_object_new_string(session->local_sdp));
      json_object_object_add(jobj, "sdp", sdpobj);
      str = snw_json_msg_to_string(jobj);
      if (!str) return;

      //send sdp into to client.
      TRACE(log, "sending sdp offer to peer, flowid=%u, len=%u, sdp=%s", 
                 session->flowid, strlen(str), str);
      snw_shmmq_enqueue(session->ice_ctx->task_ctx->resp_mq,0,
        str,strlen(str),session->flowid);

      json_object_put(jobj);

      snw_ice_sdp_send_candidates(session);
   }

   return;
}

void
snw_ice_cb_new_selected_pair(agent_t *agent, uint32_t stream_id,
       uint32_t component_id, char *local, char *remote, void *data) {
   snw_log_t *log = 0;
   snw_ice_session_t *session = 0;
   snw_ice_stream_t *stream = 0;
   snw_ice_component_t *component = 0;

   session = (snw_ice_session_t *)data;
   if (!session) return;
   log = session->ice_ctx->log;

   if (component_id > 1 && IS_FLAG(session, WEBRTC_RTCPMUX)) {
      ERROR(log, "wait for webrtc rtcpmux, cid=%u",component_id);
      return;
   }

   DEBUG(log, "new selected pair, cid=%d, sid=%d, local=%s, remote=%s",
                component_id, stream_id, local, remote);
   stream = snw_ice_stream_find(&session->streams, stream_id);
   if (!stream) {
      ERROR(log, "stream not found, sid=%u", stream_id);
      return;
   }

   component = snw_component_find(&stream->components, component_id);
   if (!component) {
      ERROR(log, "component not found, cid=%u, sid=%u", component_id, stream_id);
      return;
   }

   if (component->dtls != 0) {
      return;
   }

   component->fir_latest = get_monotonic_time();
   component->dtls = dtls_create(session->ice_ctx, component, stream->dtls_type);
   if (!component->dtls) {
      ERROR(log, "dtls context is null");
      return;
   }

   dtls_do_handshake(component->dtls);

   //FIXME: set timeout to call dtls_retry
   return;
}

void
snw_ice_cb_component_state_changed(agent_t *agent,
         uint32_t stream_id, uint32_t component_id, uint32_t state, void *data) {
   snw_ice_session_t *session = (snw_ice_session_t *)data;
   snw_log_t *log = 0;
   snw_ice_stream_t *stream = 0;
   snw_ice_component_t *component = 0;

   if (!session) return;
   log = session->ice_ctx->log;

   DEBUG(log, "component state changed, cid=%u, sid=%u, state=%d",
         component_id, stream_id, state);

   stream = snw_ice_stream_find(&session->streams, stream_id);
   if (!stream) {
      ERROR(log, "stream not found, sid=%u", stream_id);
      return;
   }

   component = snw_component_find(&stream->components, component_id);
   if (!component) {
      ERROR(log, "component not found, cid=%u, sid=%u", 
            component_id, stream_id);
      return;
   }
   component->state = state;
   if ((state == ICE_COMPONENT_STATE_CONNECTED || state == ICE_COMPONENT_STATE_READY)) {
      SET_FLAG(session,WEBRTC_READY);
   }

   if(state == ICE_COMPONENT_STATE_FAILED) {
     //FIXME: get a lot of this err
     //WARN(log, "ice component failed, cid=%u, sid=%u",component_id,stream_id);
   }  

   return;
}  

void
snw_ice_cb_new_remote_candidate(agent_t *agent, uint32_t stream_id,
                     uint32_t component_id, char *foundation, void *data) {
   char address[ICE_ADDRESS_STRING_LEN], base_address[ICE_ADDRESS_STRING_LEN];
   snw_ice_session_t *session = (snw_ice_session_t *)data;
   snw_log_t *log = 0;
   snw_ice_stream_t *stream = 0;
   snw_ice_component_t *component = 0;
   candidate_t *candidate = 0;
   candidate_head_t *candidates = 0;
   candidate_t *c = NULL;
   int port = 0, base_port = 0;
   char buffer[100];

   if (!session) return;
   log = session->ice_ctx->log;

   DEBUG(log, "discovered new remote candidate, cid=%u, sid=%u, foundation=%s",
          component_id, stream_id, foundation);

   if (component_id > 1 && IS_FLAG(session, WEBRTC_RTCPMUX)) {
      DEBUG(log, "ignore new candidate, component=%d,rtcpmux=%u",
            component_id, IS_FLAG(session, WEBRTC_RTCPMUX));
      return;
   }

   stream = snw_ice_stream_find(&session->streams, stream_id);
   if (!stream) {
      ERROR(log, "stream not found, sid=%u", stream_id);
      return;
   }

   component = snw_component_find(&stream->components, component_id);
   if (!component) {
      ERROR(log, "component not found, cid=%u, sid=%u", component_id, stream_id);
      return;
   }
   candidates = ice_agent_get_remote_candidates(agent, component_id, stream_id);
   //FIXME: clean candidates
   TAILQ_FOREACH(c,candidates,list) {
      if(candidate == 0) {
         if(!strcasecmp(c->foundation, foundation)) {
            candidate = c;
            continue;
         }
      }
   }

   if(candidate == 0) {
      ERROR(log, "candidate not found, foundation %s", foundation);
      return;
   }

   if(candidate->type != ICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
      goto candidatedone;
   }

   DEBUG(log, "stream info, sid=%u, cid=%u", candidate->stream_id, candidate->component_id);

   {//DEBUG
      address_to_string(&(candidate->addr), (char *)&address);
      port = address_get_port(&(candidate->addr));
      address_to_string(&(candidate->base_addr), (char *)&base_address);
      base_port = address_get_port(&(candidate->base_addr));
      DEBUG(log, "Address:    %s:%d", address, port);
      DEBUG(log, "Priority:   %d", candidate->priority);
      DEBUG(log, "Foundation: %s", candidate->foundation);
   }

   if(candidate->transport == ICE_CANDIDATE_TRANSPORT_UDP) {
      snprintf(buffer, 100,
         "%s %d %s %d %s %d typ prflx raddr %s rport %d\r\n",
            candidate->foundation,
            candidate->component_id,
            "udp",
            candidate->priority,
            address,
            port,
            base_address,
            base_port);
   } else {
      ERROR(log, "transport not supported, transport=%u", 
            candidate->transport);
   }

candidatedone:
   candidate_free(candidate); //XXX: also free 'candidates'
   return;
}

int
snw_ice_add_local_addresses(snw_ice_session_t *session) {
   struct ifaddrs *ifaddr, *ifa;
   int family, s;
   char host[NI_MAXHOST];

   if (getifaddrs(&ifaddr) == -1) {
      return -1;
   } else {
      for(ifa = ifaddr; ifa != 0; ifa = ifa->ifa_next) {
         address_t addr_local;

         if (ifa->ifa_addr == 0)
            continue;

         if (!((ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_RUNNING)))
            continue;

         if (ifa->ifa_flags & IFF_LOOPBACK)
            continue;

         family = ifa->ifa_addr->sa_family;
         if (family != AF_INET && family != AF_INET6)
            continue;

         if (family == AF_INET6 )
            continue;

         s = getnameinfo(ifa->ifa_addr,
               (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
               host, NI_MAXHOST, 0, 0, NI_NUMERICHOST);
         if(s != 0) {
            continue;
         }
         if (!strcmp(host, "0.0.0.0") || !strcmp(host, "::") || !strncmp(host, "fe80:", 5))
            continue;

         // add interface to the ICE agent
         address_init(&addr_local);
         if(address_set_from_string(&addr_local, host) != ICE_OK) {
            continue;
         }
         ice_agent_add_local_address(session->agent, &addr_local);
         break;
      }
      freeifaddrs(ifaddr);
   }

   return 0;
}

void 
send_rtcp_pkt_internal(snw_ice_session_t *session, int video, int encrypted, char *buf, int len) {
   static char sbuf[ICE_BUFSIZE];
   snw_log_t *log = 0;
   snw_ice_stream_t *stream = 0;
   snw_ice_component_t *component = 0;

   if (!session) return;
   log = session->ice_ctx->log;

   stream = IS_FLAG(session, WEBRTC_BUNDLE)
               ? (session->audio_stream ? session->audio_stream : session->video_stream)
               : (video ? session->video_stream : session->audio_stream);

   if (!stream) return;

   component = IS_FLAG(session, WEBRTC_RTCPMUX) ? 
         stream->rtp_component : stream->rtcp_component;
   if (!component) return;

   //FIXME: check cdone equal to num of stream
   if (!stream->gathering_done) {
      return;
   }

   if (!component->dtls 
       || component->dtls->state != DTLS_STATE_CONNECTED 
       || !component->dtls->srtp_out) {
      return;
   }

   if (encrypted) {
      ice_agent_send(session->agent, stream->id, component->id,
                                 (const char *)buf, len);
   } else {
      int enc_len = 0;
      int ret = 0;

      memcpy(&sbuf, buf, len);
      enc_len = len;
      ret = srtp_protect_rtcp(component->dtls->srtp_out, &sbuf, &enc_len);
      if (ret != err_status_ok) {
         ERROR(log, "encrypting srtp pkt failed, len=%d, enc_len=%d, ret=%d", 
               len, enc_len, ret);
      } else {
         ice_agent_send(session->agent, stream->id, component->id,
                                    (const char *)&sbuf, enc_len);
      }
   }
   return;
}

void
send_rtp_pkt_internal(snw_ice_session_t *session, 
  int video, int encrypted, char* buf, int len) {
   static char sbuf[ICE_BUFSIZE];
   snw_log_t *log = 0;
   snw_ice_stream_t *stream = 0;
   snw_ice_component_t *component = 0;
   rtp_hdr_t *header = (rtp_hdr_t *)&sbuf;
   int enc_len = len;
   int ret = 0;

   if (len > ICE_BUFSIZE) return;

   if (!session) return;
   log = session->ice_ctx->log;

   stream = IS_FLAG(session, WEBRTC_BUNDLE)
         ? (session->audio_stream ? session->audio_stream : session->video_stream)
         : (video ? session->video_stream : session->audio_stream);

   if (!stream) return;

   component = stream->rtp_component;
   if (!component || !stream->gathering_done) return;
   if (!component->dtls 
       || component->dtls->state != DTLS_STATE_CONNECTED
       || !component->dtls->srtp_out) {
      return;
   }

   memcpy(&sbuf, buf, len);
   header->ssrc = htonl(video ? stream->local_video_ssrc : stream->local_audio_ssrc);
   ret = srtp_protect(component->dtls->srtp_out, &sbuf, &enc_len);
   if (ret != err_status_ok) {
      uint32_t timestamp = ntohl(header->ts);
      uint16_t seq = ntohs(header->seq);
      ERROR(log, "encrypting srtp pkt failed, ret=%d, flowid=%u,"
                 " len=%d, enc_len>%d, ts=%u, seq=%u",
            ret, session->flowid, len, enc_len, timestamp, seq);
      return;
   } 
   
   ret = ice_agent_send(session->agent, stream->id, component->id,
                                 (const char *)&sbuf, enc_len);
   if (ret < enc_len) {
      WARN(log, "only sent %d bytes? (was %d)", ret, enc_len);
   }

   //TODO: impl circular buffer to keep sent packets for restransmission.

   return;
}

void
send_pkt_callback(void *session, int control, 
      int video, char* buf, int len) {
   return send_rtp_pkt((snw_ice_session_t*)session,
               control, video, buf, len);
}

void 
send_rtp_pkt(snw_ice_session_t *session, 
   int control, int video, char* buf, int len) {

   if (!session || !buf) return;

   if (control) {
      send_rtcp_pkt_internal(session,video,0,buf,len);
   } else {
      send_rtp_pkt_internal(session,video,0,buf,len);
   }

   return;
}

void 
ice_relay_rtcp(snw_ice_session_t *session, int video, char *buf, int len) {
   
   if (!session || !buf || len < 1)
      return;

   //FIXME: check stuff
   send_rtp_pkt(session,1,video,buf,len);
   return;
}

void
snw_ice_broadcast_rtp_pkg(snw_ice_session_t *session, 
      snw_ice_stream_t *stream, snw_ice_component_t *component,
      int video, char *buf, int len) {
   snw_ice_context_t *ice_ctx = 0;
   snw_log_t *log = 0;
   snw_ice_session_t *s = 0;
   uint32_t flowid = 0;

   if (!session) return;
   ice_ctx = session->ice_ctx;
   log = ice_ctx->log;

   for (int i=0; i<SNW_ICE_CHANNEL_USER_NUM_MAX; i++) {
     
      if (session->channel->players[i] != 0) {
         rtp_hdr_t *header = (rtp_hdr_t *)buf;
         //uint16_t seq = ntohs(header->seq);

         flowid = session->channel->players[i];
         //TRACE(log, "relay rtp pkt, flowid=%u, peerid=%u, media_type=%u, "
         //           "pkg_type=%u, seq=%u, length=%u",
         //     session->flowid, flowid, video, header->pt, seq,len);
         s = (snw_ice_session_t*)snw_ice_session_search(ice_ctx,flowid);
         if (s) {
            send_rtp_pkt(s, 0, video, buf, len);
            { // handle pkg out
               snw_rtp_ctx_t *rtp_ctx = 0;
               uint32_t remote_ssrc = 0;
               rtp_ctx = &s->rtp_ctx;

               //FIXME: more checks here
               rtp_ctx->session = s;
               rtp_ctx->stream = s->audio_stream;
               rtp_ctx->component = s->audio_stream->rtp_component; 
               rtp_ctx->epoch_curtime = session->curtime;
               rtp_ctx->ntp_curtime = session->curtime + NTP_EPOCH_DIFF;
               rtp_ctx->pkt_type = video ? RTP_VIDEO : RTP_AUDIO;
               remote_ssrc = /*htonl*/(video ? s->audio_stream->local_video_ssrc : 
                                               s->audio_stream->local_audio_ssrc);

               //TRACE(log, "handle package out, flowid=%u, seq=%u, ssrc=%u, remote_ssrc=%u, s=%p",
               //      s->flowid, ntohs(header->seq), ntohl(header->ssrc), remote_ssrc, rtp_ctx->session);
               header->ssrc = htonl(remote_ssrc);
               snw_rtp_handle_pkg_out(rtp_ctx,buf,len);
            }
         } else {
            ERROR(log, "session not found, flowid=%u",flowid);
            continue;
         }
      }
   }

   return;
}

void
ice_rtp_incoming_msg(snw_ice_session_t *session, snw_ice_stream_t *stream,
      snw_ice_component_t *component, char* buf, int len) {
   snw_rtp_ctx_t *rtp_ctx = 0;
   snw_log_t *log = 0;
   rtp_hdr_t *header = (rtp_hdr_t *)buf;
   err_status_t ret;
   uint32_t ssrc = 0;
   uint32_t timestamp = 0;
   uint16_t seq = 0;
   int buflen = len;
   int video = 0;

   if (!session || !stream || !component) return;
   log = session->ice_ctx->log;
   rtp_ctx = &session->rtp_ctx;

   ssrc = ntohl(header->ssrc);
   timestamp = ntohl(header->ts);
   seq = ntohs(header->seq);
   /* XXX: stream ssrc should be set by sdp offer/answer? */
   if (ssrc != stream->remote_audio_ssrc
       && ssrc != stream->remote_video_ssrc) {
      ERROR(log, "wrong ssrc, ssrc=%u, ts=%u, seq=%u", 
           ssrc, timestamp, seq);
      return;
   }
   video = ((stream->remote_video_ssrc == ssrc) ? 1 : 0);

   //TRACE(log, "rtp message, flowid=%u, len=%u, video=%u, "
   //           "ssrc=%u, a_ssrc=%u, v_ssrc=%u",
   //           session->flowid, len, video, ssrc,
   //           stream->remote_audio_ssrc,
   //           stream->remote_video_ssrc);

   ret = srtp_unprotect(component->dtls->srtp_in, buf, &buflen);
   if (ret != err_status_ok) {
      ERROR(log, "decrypting srtp pkt failed, len=%d, buflen=%d, "
                 "ts=%u, seq=%u, res=%u",
            len, buflen, timestamp, seq, ret);
      return;
   } 

   //forward to rtp handler, i.e h264
   rtp_ctx->stream = stream;
   rtp_ctx->component = component; 
   rtp_ctx->epoch_curtime = session->curtime;
   rtp_ctx->ntp_curtime = rtp_ctx->epoch_curtime + NTP_EPOCH_DIFF;
   if (video)
      rtp_ctx->pkt_type = RTP_VIDEO;
   else 
      rtp_ctx->pkt_type = RTP_AUDIO;
   snw_rtp_handle_pkg_in(rtp_ctx,buf,buflen);

   if (IS_FLAG(session,ICE_PUBLISHER)) {
      snw_ice_broadcast_rtp_pkg(session,stream,component,video,buf,buflen);
   } else if (IS_FLAG(session,ICE_SUBSCRIBER)) {
      //do nothing
   }

   /*if (IS_FLAG(session,ICE_PUBLISHER)) {
      //snw_ice_handle_lost_packets(session,stream,
      //    component,ntohs(header->seq),video);
      snw_ice_send_fir(session,component,0);
   }*/

   return;
}

int
snw_ice_resend_pkt(snw_ice_session_t *session, snw_ice_component_t *component,
              int video, int seqno, int64_t now) {
   //FIXME: impl
   //snw_log_t *log = session->ice_ctx->log;
   //DEBUG(log, "resend seq, flowid=%u, seqno=%u, ts=%llu",
   //      session->flowid, seqno, now);
   return 0;
}

void 
ice_rtcp_incoming_msg(snw_ice_session_t *session, snw_ice_stream_t *stream,
                          snw_ice_component_t *component, char* buf, int len) {
   snw_log_t *log = 0;
   snw_rtp_ctx_t *rtp_ctx = 0;
   err_status_t ret;
   int buflen = len;

   if (!session) return;
   log = session->ice_ctx->log;
   rtp_ctx = &session->rtp_ctx;

   ret = srtp_unprotect_rtcp(component->dtls->srtp_in, buf, &buflen);
   if (ret != err_status_ok) {
      DEBUG(log, "decrypting srtp pkt failed, ret=%u, len=%d, buflen=%d", ret, len, buflen);
      return;
   }
   
   //forward to rtcp handler
   rtp_ctx->stream = stream;
   rtp_ctx->component = component; 
   rtp_ctx->epoch_curtime = session->curtime;
   rtp_ctx->ntp_curtime = rtp_ctx->epoch_curtime + NTP_EPOCH_DIFF;
   rtp_ctx->pkt_type = RTP_RTCP;
   snw_rtp_handle_pkg_in(rtp_ctx,buf,buflen);
  
   return;
}

void ice_data_recv_cb(agent_t *agent, uint32_t stream_id,
          uint32_t component_id, char *buf, uint32_t len, void *data) {
   snw_log_t *log = 0;
   snw_ice_session_t *session = 0;
   snw_ice_stream_t *stream = 0;
   snw_ice_component_t *component = 0;
   int pt = 0;

   component = (snw_ice_component_t *)data;
   if (!component || !component->stream 
       || !component->stream->session) 
      return;

   stream = component->stream;
   session = stream->session;
   log = session->ice_ctx->log;
   session->curtime = get_epoch_time();

   pt = snw_rtp_get_pkt_type(buf,len);
   //TRACE(log, "get packet type, flowid=%u, pt=%u",
   //           session->flowid, pt);
   if (pt == UNKNOWN_PT) {
      ERROR(log, "unknown packet type, flowid=%u, len=%u", 
                 session->flowid, len);
      return;
   }

   if (pt == DTLS_PT) {
      dtls_process_incoming_msg(component->dtls, buf, len);
      return;
   }

   if (!component->dtls 
       || component->dtls->state != DTLS_STATE_CONNECTED
       || !component->dtls->srtp_in) {
      WARN(log, "dtls not setup yet, flowid=%u", session->flowid);
   } else {
      if (pt == RTP_PT) {
         ice_rtp_incoming_msg(session,stream,component,buf,len);
      } else if (pt == RTCP_PT) {
         ice_rtcp_incoming_msg(session,stream,component,buf,len);
      }
   }

   return;
}


snw_ice_component_t*
snw_ice_create_media_component(snw_ice_session_t *session, snw_ice_stream_t *stream, uint32_t cid, int is_rtcp) {
   snw_ice_component_t *rtp = 0;

   if (!session) return 0;

   rtp = snw_component_allocate(session->ice_ctx);
   if (!rtp) return 0;

   rtp->stream = stream;
   rtp->id = cid;
   rtp->is_started = 0;
   TAILQ_INIT(&rtp->remote_candidates);
   snw_component_insert(&stream->components, rtp);
   if (is_rtcp)
      stream->rtcp_component = rtp;
   else
      stream->rtp_component = rtp;

   //ice_agent_set_port_range(session->agent, stream->id, cid, rtp_range_min, rtp_range_max);
   return rtp;
}


int
snw_ice_create_media_stream(snw_ice_session_t *session, int video) {
   snw_log_t *log = 0;
   snw_ice_stream_t *stream = 0;
   snw_ice_component_t *rtp = 0;
   snw_ice_component_t *rtcp = 0;
   uint32_t stream_id;

   if (!session) return -1;
   log = session->ice_ctx->log;

   stream_id = ice_agent_add_stream(session->agent, IS_FLAG(session, WEBRTC_RTCPMUX) ? 1 : 2);
   stream = snw_ice_stream_allocate(session->ice_ctx);
   if (stream == 0) {
      return -2;
   }
   stream->id = stream_id;
   stream->session = session;
   stream->gathering_done = 0;
   stream->is_disable = 0;
   stream->is_video = video;
   stream->dtls_type = DTLS_TYPE_ACTPASS;
   LIST_INIT(&stream->components);
   snw_ice_stream_insert(&session->streams,stream);
      
   if (video) {
      session->video_stream = stream;
      stream->local_video_ssrc = random();
      stream->remote_video_ssrc = 0;
      stream->local_audio_ssrc = 0;
      stream->remote_audio_ssrc = 0;
      DEBUG(log, "created video stream, sid=%u(%p)",
             session->video_stream->id, session->video_stream);
   } else {
      stream->local_audio_ssrc = random();
      stream->remote_audio_ssrc = 0;
      if (IS_FLAG(session, WEBRTC_BUNDLE)) {
         stream->local_video_ssrc = random();
         DEBUG(log, "generate ssrc, a_ssrc=%u, v_ssrc=%u",
               stream->local_audio_ssrc, stream->local_video_ssrc);
      } else {
         stream->local_video_ssrc = 0;
      }
      stream->remote_video_ssrc = 0;
      session->audio_stream = stream;
   }

   rtp = snw_ice_create_media_component(session,stream,1,0);
   if (rtp == 0) {
      return -3;
   }

   if (!IS_FLAG(session, WEBRTC_RTCPMUX)) {
      rtcp = snw_ice_create_media_component(session,stream,2,1);
      if(rtcp == 0) {
         return -3;
      }
   }

   DEBUG(log, "initialize media stream, video=%u, stream_id=%u", 
              video, stream_id);
   ice_agent_gather_candidates(session->agent, stream_id);
   ice_agent_attach_recv(session->agent, stream_id, 1, ice_data_recv_cb, rtp);
   if (!IS_FLAG(session, WEBRTC_RTCPMUX) && rtcp != 0)
      ice_agent_attach_recv(session->agent, stream_id, 2, ice_data_recv_cb, rtcp);

   return 0;
}

int
snw_ice_session_setup(snw_ice_context_t *ice_ctx, snw_ice_session_t *session) {
   snw_log_t *log = 0;
   agent_t *agent;
   int ret = 0; 

   if (!ice_ctx || !session) return -1;
   log = ice_ctx->log;

   agent = (agent_t*)ice_agent_new(ice_ctx->ev_ctx,ICE_COMPATIBILITY_RFC5245,0);
   if (!agent) return -1;


   // set callbacks and handlers for ice protocols
   ice_set_candidate_gathering_done_cb(agent, snw_ice_cb_candidate_gathering_done, session);
   ice_set_new_selected_pair_cb(agent, snw_ice_cb_new_selected_pair, session);
   ice_set_component_state_changed_cb(agent, snw_ice_cb_component_state_changed, session);
   ice_set_new_remote_candidate_cb(agent, snw_ice_cb_new_remote_candidate, session);

   session->ice_ctx = ice_ctx;
   session->agent = agent;
   session->streams_gathering_done = 0;
   session->streams_num = 0;
   session->control_mode = ICE_CONTROLLED_MODE;
   //TODO: get settings from client
   SET_FLAG(session, WEBRTC_AUDIO | WEBRTC_VIDEO | WEBRTC_BUNDLE);

   DEBUG(log,"creating ice agent, flowid=%u, ice_lite=%u, control_mode=%u",
         session->flowid, ice_ctx->ice_lite_enabled, session->control_mode);

   ret = snw_ice_add_local_addresses(session);
   if (ret < 0) {
      //FIXME: clean resources
      return -2;
   }

   if (IS_FLAG(session, WEBRTC_AUDIO)) { 
      session->streams_num++;
      ret = snw_ice_create_media_stream(session,0);
      if (ret < 0) {
         ERROR(log, "failed to create media stream, ret=%d", ret);
         return ret;
      }
   }

   if (IS_FLAG(session, WEBRTC_VIDEO)
       && (!IS_FLAG(session, WEBRTC_AUDIO) || !IS_FLAG(session, WEBRTC_BUNDLE))) {
      session->streams_num++;
      ret = snw_ice_create_media_stream(session,1);
      if (ret < 0) {
         ERROR(log, "ret=%d", ret);
         return ret;
      }
   }

   return 0;
}

static int
snw_ice_offer_sdp(snw_ice_context_t *ice_ctx, 
      snw_ice_session_t *session, uint32_t flowid) {
   snw_log_t *log;
   int ret = 0;

   if (!ice_ctx || !session) return -1;
   log = ice_ctx->log;

   ret = snw_ice_session_setup(ice_ctx, session);
   if (ret < 0) {
      ERROR(log, "failed to setup ice session, ret=%d",ret);
      return -2;
   }

   return 0;
}

void
snw_ice_connect_msg(snw_ice_context_t *ice_ctx, void *data, int len, uint32_t flowid) {
   snw_log_t *log = ice_ctx->log;
   snw_ice_session_t *session;
   snw_ice_channel_t *channel;
   json_object *jobj = (json_object*)data;
   uint32_t stream_type = 0;
   uint32_t channelid = 0;
   uint32_t streamid = 0;
   int is_new = 0;
   
   if (!jobj) return;

   channelid = snw_json_msg_get_int(jobj,"channelid");
   stream_type = snw_json_msg_get_int(jobj,"stream_type");
   streamid = snw_json_msg_get_int(jobj,"streamid");
   if (channelid == (uint32_t)-1 || stream_type == (uint32_t)-1 || streamid == (uint32_t)-1)
     return;
 
   DEBUG(log,"connect msg, streamid=%u", streamid);
   session = (snw_ice_session_t*)snw_ice_session_get(ice_ctx,streamid,&is_new);
   if (!session) {
      ERROR(log,"failed to get session, flowid=%u",flowid);
      return;
   }

   if (!is_new) {
      WARN(log,"old session, flowid=%u, ice_ctx=%p",session->flowid, session->ice_ctx);
      snw_ice_offer_sdp(ice_ctx,session,flowid);
      return;
   }

   is_new = 0;
   channel = (snw_ice_channel_t*)snw_ice_channel_get(ice_ctx,streamid,&is_new); //TODO: used to use channelid
   if (!channel || !is_new) {
      ERROR(log,"failed to create ice channel, flowid=%u, is_new=%u", 
            flowid, is_new);
      snw_ice_send_msg_to_core(ice_ctx,jobj,flowid,-1);
      return;
   }

   DEBUG(log,"init new session, channelid=%u, stream_type=%u, flowid=%u", 
         channelid, stream_type, session->flowid);
   
   session->channelid = channelid;
   session->flowid = flowid;
   session->channel = channel;
   session->control_mode = ICE_CONTROLLED_MODE;
   session->flags = 0;
   snw_rtp_ctx_init(&session->rtp_ctx);
   session->rtp_ctx.session = session;
   session->rtp_ctx.log = log;
   session->rtp_ctx.send_pkt = send_pkt_callback;
   LIST_INIT(&session->streams);

   if ( !(stream_type == STREAM_TYPE_PUBLISHER
        || stream_type == STREAM_TYPE_SUBSCRIBER
        || stream_type == STREAM_TYPE_P2P) ) {
      ERROR(log,"unknown peer type, flowid=%u, stream_type=%s", flowid, stream_type);
      session->stream_type = PEER_TYPE_UNKNOWN;
      return;
   }
   session->stream_type = stream_type;
   snw_ice_offer_sdp(ice_ctx,session,flowid);

   return;
}

void 
ice_component_cleanup(snw_ice_context_t *ice_ctx, snw_ice_component_t *component) {

   if (!component) return;

   if (component->dtls != 0) {
      dtls_free(component->dtls);
      component->dtls = 0;
   }
   
   snw_component_deallocate(ice_ctx, component);
   return;
}

void
ice_component_free(snw_ice_context_t *ice_ctx, ice_component_head_t *components, 
      snw_ice_component_t *component) {
   snw_log_t *log = 0;
   snw_ice_component_t *c = 0;
   snw_ice_component_t *t = 0;

   if (!components || !component) return;
   log = ice_ctx->log;
 
   LIST_FOREACH(t,components,list) {
     if (t->id == component->id) {
       c = t;
       break;
     }
   }

   if (c) {
      LIST_REMOVE(c,list);
      ice_component_cleanup(ice_ctx,c);
   } else {
      ERROR(log,"component not found, cid=%u", component->id);
   }

   return;
}


void 
ice_stream_cleanup(snw_ice_context_t *ice_ctx, snw_ice_stream_t *stream) {
   snw_log_t *log = 0;

   if (!stream)
      return;
   log = ice_ctx->log;   

   //FIXME: delete components
   TRACE(log, "stream cleanup, sid=%u",stream->id);
   if (stream->rtp_component != 0) {
      ice_component_free(ice_ctx, &stream->components, stream->rtp_component);
   }

   if (stream->rtcp_component != 0) {
      ice_component_free(ice_ctx, &stream->components, stream->rtcp_component);
   }

   snw_ice_stream_deallocate(ice_ctx,stream);

   return;
}

void 
ice_stream_free(snw_ice_context_t *ice_ctx, ice_stream_head_t *streams, snw_ice_stream_t *stream) {
   snw_log_t *log = 0;
   snw_ice_stream_t *d = 0; 
   snw_ice_stream_t *s = 0;
         
   if (!streams || !stream)
      return;
   log = ice_ctx->log;

   LIST_FOREACH(s,streams,list) {
      if (s->id == stream->id) {
         LIST_REMOVE(s,list);
         d = s;
      }
   }

   if (d) {
      ice_stream_cleanup(ice_ctx, d);
   } else {
      ERROR(log, "stream not found, sid=%u", stream->id);
   }

   return;
}

void 
snw_ice_session_free(snw_ice_context_t *ice_ctx, snw_ice_session_t *session) {
   snw_ice_stream_t *s = 0;

   if (!session || !ice_ctx) return;

   if (session->agent) {
      ice_agent_free(session->agent);
      session->agent = 0;
   }

   if (session->local_sdp) {
      free(session->local_sdp);
      session->local_sdp = 0;
   }

   if (session->remote_sdp) {
      free(session->remote_sdp);
      session->remote_sdp = 0;
   }
   
   if (session->publishid != 0) {
      snw_channel_remove_subscriber(ice_ctx, session->publishid, 
        session->streamid);
   }

   //FIXME: free streams & components
   if (LIST_EMPTY(&session->streams))
      return;

   LIST_FOREACH(s,&session->streams,list) {
      LIST_REMOVE(s,list);
      ice_stream_cleanup(session->ice_ctx,s);
   }

   CLEAR_FLAG(session, WEBRTC_READY);

   snw_ice_session_remove(ice_ctx,session);

   return;
}

void
snw_ice_stop_msg(snw_ice_context_t *ice_ctx, void *data, int len, uint32_t flowid) {
   snw_log_t *log = ice_ctx->log;
   snw_ice_session_t *session;
   json_object *jobj = (json_object*)data;
   uint32_t streamid = 0;

   DEBUG(log, "stop a stream, flowid=%u, streamid=%u", flowid, streamid);

   streamid = snw_json_msg_get_int(jobj,"streamid");
   if (streamid == (uint32_t)-1) return;

   DEBUG(log, "stop a stream, flowid=%u, streamid=%u", flowid, streamid);

   session = (snw_ice_session_t*)snw_ice_session_search(ice_ctx,streamid);
   if (!session) {
      ERROR(log,"session not found, flowid=%u",flowid);
      return;
   }

   DEBUG(log, "stop a stream, flowid=%u, streamid=%u", flowid, streamid);
   snw_ice_session_free(ice_ctx,session);

   return;
}

int
snw_ice_merge_streams(snw_ice_session_t *session, int audio, int video) {

   if (!session) return -1;

   if (audio) {
      if( !LIST_EMPTY(&session->streams) && session->video_stream) {
         session->audio_stream->local_video_ssrc = session->video_stream->local_video_ssrc;
         session->audio_stream->remote_video_ssrc = session->video_stream->remote_video_ssrc;
         ice_agent_attach_recv(session->agent, session->video_stream->id, 1, 0, 0);
         ice_agent_attach_recv(session->agent, session->video_stream->id, 2, 0, 0);
         ice_agent_remove_stream(session->agent, session->video_stream->id);
         ice_stream_free(session->ice_ctx,&session->streams, session->video_stream);
      }
      session->video_stream = 0;
   } else if (video) {
      //FIXME: what to do?
   }

   return 0;
}  

int
snw_ice_merge_components(snw_ice_session_t *session) {

   if (!session) return -1;

   if(session->audio_stream && !LIST_EMPTY(&session->audio_stream->components) ) {
      ice_agent_attach_recv(session->agent, session->audio_stream->id, 2, 0, 0);
      ice_component_free(session->ice_ctx, &session->audio_stream->components, 
            session->audio_stream->rtcp_component);
      session->audio_stream->rtcp_component = 0;
   }

   if(session->video_stream && !LIST_EMPTY(&session->video_stream->components)) {
      ice_agent_attach_recv(session->agent, session->video_stream->id, 2, 0, 0);
      ice_component_free(session->ice_ctx, &session->video_stream->components, 
           session->video_stream->rtcp_component);
      session->video_stream->rtcp_component = 0;
   }

   return 0;
}


int ice_setup_remote_credentials(snw_ice_session_t *session, snw_ice_stream_t *stream, snw_ice_component_t *component) {
   snw_log_t *log = 0;
   candidate_t *c = 0;
   char *ufrag = 0, *pwd = 0;

   if (!session) return -1;
   log = session->ice_ctx->log;

   /* FIXME: make sense? */
   TAILQ_FOREACH(c,&component->remote_candidates,list) {
      DEBUG(log, "remote stream info, sid=%d, cid=%d", c->stream_id, c->component_id);
      if (c->username && !ufrag)
         ufrag = c->username;
      if (c->password && !pwd)
         pwd = c->password;

      //PRINT_CANDIDATE(c);
      if (address_is_private(&(c->addr)) ) {
         char address[ICE_ADDRESS_STRING_LEN];
         address_to_string(&(c->addr), (char *)&address);
         //TAILQ_REMOVE(head,c,list);
         /* FIXME: removing private ips causes failure of ICE process */
      }
   }

   if (ufrag && pwd) {
      DEBUG(log, "setting remote credentials, ufrag=%s,pwd=%s",ufrag,pwd);
      if (ice_agent_set_remote_credentials(session->agent, stream->id, ufrag, pwd) != ICE_OK) {
         ERROR(log, "failed to set remote credentials, sid=%u, cid=%u",stream->id, component->id);
         return -1;
      }
   }

   return 0;
}

void 
ice_setup_remote_candidates(snw_ice_session_t *session, uint32_t stream_id, uint32_t component_id) {
   snw_log_t *log = 0;
   snw_ice_stream_t *stream = 0;
   snw_ice_component_t *component = 0;
   int added = 0;
   
   if (!session || !session->agent || LIST_EMPTY(&session->streams))
      return;
   log = session->ice_ctx->log;

   stream = snw_ice_stream_find(&session->streams, stream_id);
   if (!stream || LIST_EMPTY(&stream->components)) {
      ERROR(log, "stream not found, sid=%d, cid=%d", stream_id, component_id);
      return;
   }  
      
   if (stream->is_disable) {
      ERROR(log, "stream info, disabled=%u, sid=%u, cid=%u", 
            stream->is_disable, stream_id, component_id);
      return;
   }     
      
   component = snw_component_find(&stream->components, component_id);
   if (!component) {
      ERROR(log, "component not found, sid=%u, cid=%u", stream_id, component_id);
      return;
   }

   if(component->is_started) {
      DEBUG(log, "component started, sid=%u, cid=%u", stream_id, component_id);
      return;
   }

   if(TAILQ_EMPTY(&component->remote_candidates)) {
      WARN(log, "candidate list is empty");
      return;
   }

   ice_setup_remote_credentials(session,stream,component);
   added = ice_agent_set_remote_candidates(session->agent, stream_id, 
                component_id, &component->remote_candidates);
   if(added <=  0 ) { //FIXME: compare to size of list candidates
      ERROR(log, "failed to set remote candidates, added=%u", added);
   } else {
      DEBUG(log, "remote candidates set, added=%u",added);
      component->is_started = 1;
   }

   return;
}

void
snw_ice_sdp_msg(snw_ice_context_t *ice_ctx, void *data, int len, uint32_t flowid) {
   snw_log_t *log = ice_ctx->log;
   snw_ice_session_t *session;
   json_object *jobj = (json_object*)data;
   json_object *jsepobj = 0;
   ice_sdp_attr_t sdp_attr;
   const char *jsep_type = 0;
   const char *jsep_sdp = 0;
   uint32_t streamid = 0;
   int ret = 0;

   streamid = snw_json_msg_get_int(jobj,"streamid");
   if (streamid == (uint32_t)-1) {
     ERROR(log, "streamid not found");
     return;
   }

   session = (snw_ice_session_t*)snw_ice_session_search(ice_ctx, streamid);
   if (session == 0) {
      ERROR(log, "failed to malloc");
      return;
   }

   jsepobj = snw_json_msg_get_object(jobj,"sdp");
   if (!jsepobj) goto error;
   jsep_type = snw_json_msg_get_string(jsepobj,"type");
   if (!jsep_type) goto error;

   if (!strcasecmp(jsep_type, "answer")) {
      // only handle answer
   } else if(!strcasecmp(jsep_type, "offer")) {
      ERROR(log, "not handling offer, type=%s", jsep_type);
      goto error;
   } else {
      ERROR(log, "unknown message type, type=%s", jsep_type);
      goto error;
   }

   jsep_sdp = snw_json_msg_get_string(jsepobj,"sdp");
   if (!jsep_sdp) goto error;

   TRACE(log, "Remote SDP, trickle=%u, s=%s", sdp_attr.trickle, jsep_sdp);

   ret = snw_ice_get_sdp_attr(ice_ctx,jsep_sdp,&sdp_attr);
   if (ret < 0) {
      ERROR(log, "invalid sdp, sdp=%s",jsep_sdp);
      goto error;
   }

   if (!IS_FLAG(session, WEBRTC_READY)) {
      session->remote_sdp = strdup(jsep_sdp);
      snw_ice_sdp_handle_answer(session, jsep_sdp);

      DEBUG(log, "setting webrtc flags, bundle=%u,rtcpmux=%u,trickle=%u",
               sdp_attr.bundle,sdp_attr.rtcpmux,sdp_attr.trickle);
      if (sdp_attr.bundle) {
         SET_FLAG(session, WEBRTC_BUNDLE);
         snw_ice_merge_streams(session,sdp_attr.audio,sdp_attr.video);
      } else {
         CLEAR_FLAG(session, WEBRTC_BUNDLE);
      }

      if (sdp_attr.rtcpmux) {
         SET_FLAG(session, WEBRTC_RTCPMUX);
         snw_ice_merge_components(session);
      } else {
         CLEAR_FLAG(session, WEBRTC_RTCPMUX);
      }

      ////FIXME: handle trickle anywhere?
      //if (sdp_attr.trickle) {
      //   SET_FLAG(session, WEBRTC_TRICKLE);
      //} else {
      //   CLEAR_FLAG(session, WEBRTC_TRICKLE);
      //}
      snw_ice_send_msg_to_core(ice_ctx, jobj, flowid, 0);
      return;

   } else {
      ERROR(log, "state error, flags=%u",session->flags);
   }

error:
   snw_ice_send_msg_to_core(ice_ctx, jobj, flowid, -1);
   return;
}

int ice_sdp_handle_candidate(snw_ice_stream_t *stream, const char *candidate) {
   snw_log_t *log = 0;
   snw_ice_session_t *session = 0;
   snw_ice_component_t *component = 0;
   candidate_t *c = 0;
   char foundation[16], transport[4], type[6]; 
   char ip[32], relip[32];
   uint32_t component_id, priority, port, relport;
   int ret;

   if (stream == 0 || candidate == 0)
      return -1; 

   session = stream->session;
   if (session == 0)
      return -2; 
   log = session->ice_ctx->log;

   if (strstr(candidate, "candidate:") == candidate) {
      candidate += strlen("candidate:");
   }   

   /* format: foundation component tranpsort priority ip port type ??? ??? ??? ??? */
   ret = sscanf(candidate, "%15s %30u %3s %30u %31s %30u typ %5s %*s %31s %*s %30u",
                           foundation, &component_id, transport, &priority,
                           ip, &port, type, relip, &relport);

   DEBUG(log, "candidate info, ret=%u, cid=%d, sid=%d, type=%s, transport=%s, refaddr=%s:%d, addr=%s:%d",
         ret, component_id, stream->id, type, transport, relip, relport, ip, port);

   if (ret >= 7) {
      component = snw_component_find(&stream->components, component_id);
      if (component == 0) {
         ERROR(log, "component not found, cid=%u, sid=%u", component_id, stream->id);
         return -3; 
      }   
      c = snw_ice_remote_candidate_new(type,transport);
      if (c != 0) {
         DEBUG(log, "new candidate, cid=%u, sid=%u", component_id, stream->id);
         c->component_id = component_id;
         c->stream_id = stream->id;

         if (!strcasecmp(transport, "udp")) {
            c->transport = ICE_CANDIDATE_TRANSPORT_UDP;
         } else {
            /* FIXME: support other transport, see secion-4.5 in rfc6544 */
            candidate_free(c);
            return -4;
         }

         strncpy(c->foundation, foundation, ICE_CANDIDATE_MAX_FOUNDATION);
         c->priority = priority;
         address_set_from_string(&c->addr, ip);
         address_set_port(&c->addr, port);
         c->username = strdup(stream->remote_user);
         c->password = strdup(stream->remote_pass);
         address_set_from_string(&c->base_addr, relip);
         address_set_port(&c->base_addr, relport);
         /* FIXME: new candidate is not free when component->is_started = 0*/
         snw_ice_try_start_component(session,stream,component,c);
      }
   } else {
      ERROR(log, "failed to parse candidate, ret=%d, s=%s", ret, candidate);
      return ret;
   }
   return 0;
}

int 
snw_ice_process_new_candidate(snw_ice_session_t *session, json_object *candidate) {
   snw_log_t *log = 0;
   int done = -1, mline = -1;
   const char *mid = 0, *rc = 0;
   snw_ice_stream_t *stream = 0;
   int video = 0;
   int ret = 0;

   if (!session) return -1;
   log = session->ice_ctx->log;

   done = snw_json_msg_get_bool(candidate,"done");
   if (done != -1) {
      DEBUG(log, "gathering remote candidates is done");
      SET_FLAG(session, WEBRTC_GATHER_DONE);
      return 0;
   }

   mid = snw_json_msg_get_string(candidate,"id");
   mline = snw_json_msg_get_int(candidate,"label");
   rc = snw_json_msg_get_string(candidate,"candidate");
   if (!mid || mline == -1 || !rc)
     return -1;

   DEBUG(log, "remote candidate, mid=%s, candidate=%s", mid, rc);
   if ( !strncasecmp(mid,"video",5) ) {
      video = 1;
   }

   stream = video ? session->video_stream : session->audio_stream;
   if(stream == 0) {
      return -5;
   }

   ret = ice_sdp_handle_candidate(stream, rc);
   if(ret != 0) {
      ERROR(log, "failed to handle candidate, ret=%d", ret);
      return -6;
   }

   return 0;
}

void
snw_ice_candidate_msg(snw_ice_context_t *ice_ctx, void *data, int len, uint32_t flowid) {
   snw_log_t *log = ice_ctx->log;
   snw_ice_session_t *session;
   json_object *jobj = (json_object*)data;
   json_object *cand_obj = 0;
   uint32_t streamid = 0;
   int ret = -1;

   streamid = snw_json_msg_get_int(jobj,"streamid");
   if (streamid == (uint32_t)-1) {
     ERROR(log, "streamid not found");
     return;
   }

   session = (snw_ice_session_t*)snw_ice_session_search(ice_ctx, streamid);
   if (!session) {
      DEBUG(log, "session not found, flowid=%u", flowid);
      return;
   }

   cand_obj = snw_json_msg_get_object(jobj,"candidate");
   if (!cand_obj) return;

   DEBUG(log,"candidate info: %s",
         json_object_to_json_string_ext(
           cand_obj, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));

   if (!session->audio_stream && !session->video_stream) {
      ERROR(log, "no stream available");
      return;
   }

   if ((ret = snw_ice_process_new_candidate(session, cand_obj)) != 0) { 
      DEBUG(log, "got error, ret=%d", ret);
      return;
   }    

   snw_ice_send_msg_to_core(ice_ctx, jobj, flowid, 0);
   return;
}

void
snw_ice_publish_msg(snw_ice_context_t *ice_ctx, void *data, int len, uint32_t flowid) {
   snw_log_t *log = 0;
   snw_ice_session_t *session = 0;
   json_object *jobj = (json_object*)data;
   uint32_t channelid = 0;
   uint32_t streamid = 0;

   if (!ice_ctx) return;
   log = ice_ctx->log;

   DEBUG(log, "channel is publishing, flowid=%u, channelid=%u", 
         flowid, channelid);

   channelid = snw_json_msg_get_int(jobj,"channelid");
   streamid = snw_json_msg_get_int(jobj,"streamid");
   if (channelid == (uint32_t)-1 || streamid == (uint32_t)-1) return;

   DEBUG(log, "channel is publishing, flowid=%u, channelid=%u", 
         flowid, channelid);

   session = (snw_ice_session_t*)snw_ice_session_search(ice_ctx, streamid);
   if (!session) return;

   if (session->channelid != channelid) {
      ERROR(log,"channelid not match, flowid=%u, channleid=%u, session_channelid=%u ",
          flowid,channelid, session->channelid);
      return;
   }

   DEBUG(log, "channel is publishing, flowid=%u, streamid=%u, channelid=%u", 
         flowid, streamid, channelid);
   SET_FLAG(session,ICE_PUBLISHER);
   return;
}

void
snw_ice_play_msg(snw_ice_context_t *ice_ctx, void *data, int len, uint32_t flowid) {
   snw_log_t *log = ice_ctx->log;
   snw_ice_session_t *session = 0;
   json_object *jobj = (json_object*)data;
   uint32_t channelid = 0;
   uint32_t streamid = 0;
   uint32_t publishid = 0;

   if (!ice_ctx) return;

   channelid = snw_json_msg_get_int(jobj,"channelid");
   streamid = snw_json_msg_get_int(jobj,"streamid");
   publishid = snw_json_msg_get_int(jobj,"publishid");
   if (channelid == (uint32_t)-1 
       || streamid == (uint32_t)-1
       || publishid == (uint32_t)-1) {
     DEBUG(log, "play a stream, flowid=%u, channelid=%u, streamid=%u, publishid=%u", 
         flowid, channelid, streamid, publishid);
     return;
   }

   session = (snw_ice_session_t*)snw_ice_session_search(ice_ctx, streamid);
   if (!session) return;
   SET_FLAG(session,ICE_SUBSCRIBER);

   snw_channel_add_subscriber(ice_ctx, publishid, streamid);
   session->publishid = publishid;
  
   return;
}

void
snw_ice_auth_msg(snw_ice_context_t *ice_ctx, void *data, int len, uint32_t flowid) {
   return;
}

void
snw_ice_control_msg(snw_ice_context_t *ice_ctx, void *data, int len, uint32_t flowid) {
   return;
}

void
snw_ice_fir_msg(snw_ice_context_t *ice_ctx, void *data, int len, uint32_t flowid) {
   return;
}



