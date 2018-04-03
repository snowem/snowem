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

#include <sofia-sip/sdp.h>

#include "core/log.h"
#include "core/utils.h"
#include "ice.h"
#include "ice_types.h"
#include "ice_session.h"
#include "ice_stream.h"
#include "sdp.h"
#include "process.h"

static su_home_t *g_home = NULL;

int
snw_ice_sdp_init(snw_ice_context_t *ctx) {

   g_home = (su_home_t*)su_home_new(sizeof(su_home_t));
   if(su_home_init(g_home) < 0) {
      ERROR(ctx->log,"error setting up sofia-sdp");
      return -1; 
   }   
   return 0;
}

void
snw_ice_sdp_deinit(void) {
   su_home_deinit(g_home);
   su_home_unref(g_home);
   g_home = NULL;
}

sdp_parser_t*
snw_ice_sdp_get_parser(snw_ice_context_t *ctx, const char *sdp) {
   sdp_parser_t *parser = NULL;

   if (!sdp) {
      ERROR(ctx->log,"sdp is null, sdp=%p",sdp);
      return NULL;
   }   

   parser = sdp_parse(g_home, sdp, strlen(sdp), 0); 
   return parser;
}

int
snw_ice_get_sdp_attr(snw_ice_context_t *ice_ctx, char *sdp, ice_sdp_attr_t *sdp_attr) {
   snw_log_t *log = ice_ctx->log;
   sdp_parser_t *parser;
   sdp_session_t *parsed_sdp = NULL;
   sdp_media_t *m = NULL;
   sdp_attribute_t *a;

   if (!sdp_attr) {
      ERROR(log,"null pointer");
      return -1;
   }

   parser = snw_ice_sdp_get_parser(ice_ctx, sdp);
   if (!parser) {
      return -2;
   }

   parsed_sdp = sdp_session(parser);
   if (!parsed_sdp) {
      ERROR(log,"failed to parse sdp, err=%s", sdp_parsing_error(parser));
      sdp_parser_free(parser);
      return -2;
   } 

   m = parsed_sdp->sdp_media;
   memset(sdp_attr,0,sizeof(*sdp_attr));
   DEBUG(log,"sdp attribute, audio=%u, video=%u, bundle=%u, trickle=%u, rtcpmux=%u", 
         sdp_attr->audio, 
         sdp_attr->video, 
         sdp_attr->bundle, 
         sdp_attr->trickle,
         sdp_attr->rtcpmux);
   while (m) {
      if (m->m_type == sdp_media_audio && m->m_port > 0) {
         sdp_attr->audio = sdp_attr->audio + 1;
         a = m->m_attributes;
         while (a) {
            if (strcasecmp(a->a_name,"rtcp-mux")) {
               sdp_attr->rtcpmux = 1;
            } else if (strcasecmp(a->a_name,"ice-options")) {
               //get trickle info
            }
            a = a->a_next;
         }
      } else if (m->m_type == sdp_media_video && m->m_port > 0) {
         sdp_attr->video = sdp_attr->video + 1;
         a = m->m_attributes;
         while (a) {
            if (strcasecmp(a->a_name,"rtcp-mux")) {
               sdp_attr->rtcpmux = 1;
            } else if (strcasecmp(a->a_name,"ice-options")) {
               //get trickle info
            }
            a = a->a_next;
         }
      }
      m = m->m_next;
   }  

   a = parsed_sdp->sdp_attributes;
   while (a) {
      if (!strcasecmp(a->a_name,"group") && strstr(a->a_value,"BUNDLE") ) {
         sdp_attr->bundle = 1;
      } else {
         //get other info
      }
      a = a->a_next;
   }

   //default to handle trickle
   sdp_attr->trickle = 1;

   sdp_parser_free(parser);
   return 0;
}

void 
snw_ice_sdp_add_global_attrs(snw_ice_session_t *session, int audio, int video, char* sdp) {
   snw_log_t *log = session->ice_ctx->log;
   static char buffer[512];
   int64_t sessid = 0;

   /* Version v= */
   strncat(sdp, "v=0\r\n", ICE_BUFSIZE - strlen(sdp));

   /* Origin o= */
   sessid = get_epoch_time();
   snprintf(buffer, 512, "o=%s %lu %lu IN IP4 127.0.0.1\r\n", "-", sessid, sessid);
   strncat(sdp, buffer, ICE_BUFSIZE - strlen(sdp));

   /* session name s= */
   snprintf(buffer, 512, "s=%s\r\n", "Snowem");
   strncat(sdp, buffer, ICE_BUFSIZE - strlen(sdp));

   /* timing t= */
   snprintf(buffer, 512, "t=%lu %lu\r\n", (long)0, (long)0); //TODO: specify start and stop time.
   strncat(sdp, buffer, ICE_BUFSIZE - strlen(sdp));

   /* lite ice a= */
   strncat(sdp, "a=ice-lite\r\n", ICE_BUFSIZE - strlen(sdp));

   /* bundle: add new global attribute */
   strncat(sdp, "a=group:BUNDLE", ICE_BUFSIZE - strlen(sdp));
   if (audio) {
      snprintf(buffer, 512, " %s", "audio");
      strncat(sdp, buffer, ICE_BUFSIZE - strlen(sdp));
   }
   if (video) {
      snprintf(buffer, 512, " %s", "video");
      strncat(sdp, buffer, ICE_BUFSIZE - strlen(sdp));
   }
   strncat(sdp, "\r\n", ICE_BUFSIZE - strlen(sdp));

   /* msid-semantic: add new global attribute */
   strncat(sdp, "a=msid-semantic: WMS Snowem\r\n", ICE_BUFSIZE - strlen(sdp));
   //snprintf(buffer, 512, "a=%s\r\n", name);
   //snprintf(buffer, 512, "a=%s:%s\r\n", name, value);
   //strncat(sdp, buffer, ICE_BUFSIZE);
   return;
}

void 
snw_ice_sdp_add_media_application(snw_ice_session_t *session, int video, char* sdp) {
   char buffer[512];

   /* sendrecv & rtcp-mux */
   strncat(sdp, "a=sendrecv\r\n", ICE_BUFSIZE);
   snprintf(buffer, 512, "a=rtcp-mux\r\n");
   strncat(sdp, buffer, ICE_BUFSIZE);

   /* RTP maps */
   if (video) {
     snprintf(buffer, 512, 
       "a=rtpmap:%d H264/90000\r\n"
       "a=fmtp:%d level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n"
       "a=rtcp-fb:%d ccm fir\r\na=rtcp-fb:%d nack\r\na=rtcp-fb:%d nack pli\r\na=rtcp-fb:%d goog-remb\r\n",
       VP8_PT, VP8_PT, VP8_PT, VP8_PT, VP8_PT, VP8_PT);
     strncat(sdp,buffer,ICE_BUFSIZE - strlen(sdp));
   } else {
     snprintf(buffer, 512, "a=rtpmap:%s opus/48000/2\r\n", RTP_OPUS_FORMAT);
     strncat(sdp,buffer,ICE_BUFSIZE - strlen(sdp));
   }

   return;
}

void 
snw_ice_sdp_add_credentials(snw_ice_session_t *session, int video, char* sdp) {
   snw_log_t *log = 0;
   snw_ice_stream_t *stream = 0;
   char buffer[512];
   char *ufrag = 0;
   char *password = 0;
   const char *dtls_mode = 0;

   if (!session) return;
   log = session->ice_ctx->log;

   if (video) {
      uint32_t id = (session->video_stream == 0) ? 0 : session->video_stream->id;

      DEBUG(log, "add credentials, id=%u, bundle=%u",id,IS_FLAG(session, WEBRTC_BUNDLE));

      if (id == 0 && IS_FLAG(session, WEBRTC_BUNDLE))
          id = session->audio_stream->id > 0 ? 
                   session->audio_stream->id : 
                   session->video_stream->id;

      stream = snw_stream_find(&session->streams, id);
   } else {
      stream = snw_stream_find(&session->streams, session->audio_stream->id);
   }

   if (!stream) return;

   ice_agent_get_local_credentials(session->agent, stream->id, &ufrag, &password);
   memset(buffer, 0, 512);

   switch(stream->dtls_type) {
      case DTLS_TYPE_ACTPASS:
         dtls_mode = "actpass";
         break;
      case DTLS_TYPE_SERVER:
         dtls_mode = "passive";
         break;
      case DTLS_TYPE_CLIENT:
         dtls_mode = "active";
         break;
      default:
         dtls_mode = NULL;
         break;
   }

   snprintf(buffer, 512,
      "a=ice-ufrag:%s\r\n"
      "a=ice-pwd:%s\r\n"
      "a=ice-options:trickle\r\n"
      "a=fingerprint:sha-256 %s\r\n"
      "a=setup:%s\r\n"
      "a=connection:new\r\n",
      ufrag, password,
      session->ice_ctx->local_fingerprint,
      dtls_mode);
   strncat(sdp, buffer, ICE_BUFSIZE);

   if (ufrag != NULL) free(ufrag);
   if (password != NULL) free(password);

   return;
}

void 
snw_ice_sdp_add_single_ssrc(snw_ice_session_t *session, int video, char *sdp) {
   snw_ice_stream_t *stream = NULL;
   char buffer[512];

   if (video) {
      uint32_t id = (session->video_stream == 0) ? 0 : session->video_stream->id;

      //DEBUG("add credentials, id=%u, bundle=%u",id,IS_FLAG(session, WEBRTC_BUNDLE));
      if (id == 0 && IS_FLAG(session, WEBRTC_BUNDLE))
          id = session->audio_stream->id > 0 ? 
                   session->audio_stream->id : 
                   session->video_stream->id;

      stream = snw_stream_find(&session->streams, id);
   } else {
      stream = snw_stream_find(&session->streams, session->audio_stream->id);
   }

   if (stream == NULL)
      return;

   // recvonly does not need this.
   if (!video) {
      snprintf(buffer, 512,
         "a=ssrc:%u cname:snowemaudio\r\n"
         "a=ssrc:%u msid:snowem snowema0\r\n"
         "a=ssrc:%u mslabel:snowem\r\n"
         "a=ssrc:%u label:snowema0\r\n",
         stream->local_audio_ssrc, stream->local_audio_ssrc, 
         stream->local_audio_ssrc, stream->local_audio_ssrc);
      strncat(sdp, buffer, ICE_BUFSIZE);
   } else {
      snprintf(buffer, 512,
         "a=ssrc:%u cname:snowemvideo\r\n"
         "a=ssrc:%u msid:snowem snowemv0\r\n"
         "a=ssrc:%u mslabel:snowem\r\n"
         "a=ssrc:%u label:snowemv0\r\n",
         stream->local_video_ssrc, stream->local_video_ssrc, 
         stream->local_video_ssrc, stream->local_video_ssrc);
      strncat(sdp, buffer, ICE_BUFSIZE);
   }

   return;
}

void 
ice_generate_candidate_attribute(snw_ice_session_t *session, char *sdp, 
      uint32_t stream_id, uint32_t component_id) {
   snw_log_t *log = 0;
   agent_t* agent = 0;
   snw_ice_stream_t *stream = 0;
   snw_ice_component_t *component = 0;
   struct list_head *i,*n;
   candidate_t *candidates;


   if (!session || !session->agent || !sdp)
      return;
   log = session->ice_ctx->log;

   agent = session->agent;
   stream = snw_stream_find(&session->streams, stream_id);
   if(!stream) {
      ERROR(log, "stream not found, sid=%u", stream_id);
      return;
   }

   component = snw_component_find(&stream->components, component_id);
   if (!component) {
      ERROR(log, "component not found, cid=%u, sid=%u", component_id, stream_id);
      return;
   }

   candidates = ice_agent_get_local_candidates(agent, stream_id, component_id);
   if (candidates == NULL )
      return;

   DEBUG(log, "got candidates, size=%u, sid=%u, cid=%u",
         list_size(&candidates->list), stream_id, component_id);

   list_for_each_safe(i,n,&candidates->list) {
      char buffer[100] = {0};
      candidate_t *c = list_entry(i,candidate_t,list);
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
            snprintf(buffer, 100, "a=candidate:%s %d %s %d %s %d typ host generation 0\r\n",
                  c->foundation, c->component_id, "udp", c->priority, address, port);
         } else {
            WARN(log, "only ice-udp supported for host candidate");
            candidate_free(c);
            continue;
         }
      } else if (c->type == ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE) {
         if (c->transport == ICE_CANDIDATE_TRANSPORT_UDP) {
            address_to_string(&(c->base_addr), (char *)&base_address);
            int base_port = address_get_port(&(c->base_addr));
            snprintf(buffer, 100, "a=candidate:%s %d %s %d %s %d typ srflx raddr %s rport %d\r\n",
                  c->foundation, c->component_id, "udp", c->priority, address, port, base_address, base_port);
         } else {
            WARN(log, "only ice-udp supported for srflx candidate");
            candidate_free(c);
            continue;
         }
      } else if(c->type == ICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
         WARN(log, "skipping prflx candidate");
         candidate_free(c);
         continue;
      } else if(c->type == ICE_CANDIDATE_TYPE_RELAYED) {
         if(c->transport == ICE_CANDIDATE_TRANSPORT_UDP) {
            snprintf(buffer, 100, "a=candidate:%s %d %s %d %s %d typ relay raddr %s rport %d\r\n",
                  c->foundation, c->component_id, "udp", c->priority, address, port, base_address, base_port);
         } else {
            DEBUG(log, "only ice-udp supported");
            candidate_free(c);
            continue;
         }
      }
      strncat(sdp, buffer, ICE_BUFSIZE);
      DEBUG(log, "output, sdp=%s", buffer);
      candidate_free(c);
   }

   DEBUG(log, "FXIME: free list of candidates");
   /*list_for_each_safe(i,n,&candidates->list) {
      candidate_t *c = list_entry(i,candidate_t,list);
      candidate_free(c);
      list_del(i);
   }*/

   return;
}

void 
snw_ice_sdp_add_candidates(snw_ice_session_t *session, sdp_media_t *m, int video, char *sdp) {
   snw_ice_stream_t *stream = NULL;

   if (m == NULL) return;

   if (video) {
      uint32_t id = (session->video_stream == 0) ? 0 : session->video_stream->id;
      if (id == 0 && IS_FLAG(session, WEBRTC_BUNDLE))
          id = session->audio_stream->id > 0 ? 
                    session->audio_stream->id : 
                    session->video_stream->id;
      stream = snw_stream_find(&session->streams, id);
   } else {
      stream = snw_stream_find(&session->streams, session->audio_stream->id);
   }

   if (stream == NULL) return;

   ice_generate_candidate_attribute(session, sdp, stream->id, 1);
   if(!SET_FLAG(session, WEBRTC_RTCPMUX) && m->m_type != sdp_media_application)
      ice_generate_candidate_attribute(session, sdp, stream->id, 2);

   return;
}

void 
snw_ice_sdp_add_mline(snw_ice_session_t *session, int video, char* sdp) {
   snw_log_t *log = session->ice_ctx->log;
   char buffer[512];
   int ipv6 = 0; //FIXME: ipv6 not support now

   /* media */
   snprintf(buffer, 512, "m=%s 1 %s", video ? "video" : "audio", RTP_PROFILE);
   strncat(sdp, buffer, ICE_BUFSIZE);

   /* Add media format*/
   //TODO: design to have more than one format or rtmp   
   if (video) {
     snprintf(buffer, 512, " %s\r\n", RTP_VP8_FORMAT);
   } else {
     snprintf(buffer, 512, " %s\r\n", RTP_OPUS_FORMAT);
   }
   strncat(sdp, buffer, ICE_BUFSIZE);


   /* Media connection c= */
   snprintf(buffer, 512, "c=IN %s 0.0.0.0\r\n", ipv6 ? "IP6" : "IP4");
   strncat(sdp, buffer, ICE_BUFSIZE);

   if (video) {
      snprintf(buffer, 512, "a=mid:%s\r\n", "video");
   } else {
      snprintf(buffer, 512, "a=mid:%s\r\n", "audio");
   }
   strncat(sdp, buffer, ICE_BUFSIZE);
   
   /* ICE rtcpmux and related stuff */
   snw_ice_sdp_add_media_application(session,video,sdp);
   
   /* ICE ufrag and pwd, and related stuff */
   snw_ice_sdp_add_credentials(session,video,sdp);

   /* add single ssrc, not support multi-ssrc by now */
   snw_ice_sdp_add_single_ssrc(session,video,sdp);

   /* add candidates */
   //snw_ice_sdp_add_candidates(session,m,video,sdp);

   return;
}

char*
snw_ice_sdp_create(snw_ice_session_t *session) {
   char *sdp = 0;

   if (!session) return 0;

   sdp = (char*)malloc(ICE_BUFSIZE);
   if(!sdp) return 0;
   sdp[0] = '\0';

   snw_ice_sdp_add_global_attrs(session,1,1,sdp);
   snw_ice_sdp_add_mline(session,0,sdp);
   snw_ice_sdp_add_mline(session,1,sdp);

   return sdp;
}

void 
snw_ice_try_start_component(snw_ice_session_t *session, snw_ice_stream_t *stream, 
      snw_ice_component_t *component, candidate_t *candidate) {
   candidate_t candidates;
   candidate_t *c = NULL;
   int added = 0;

   if (!session || !stream || !component || !candidate)
      return;

   list_add(&candidate->list,&component->remote_candidates.list);
   if (!IS_FLAG(session, WEBRTC_START)) {
      SET_FLAG(session, WEBRTC_START);
   }

   if (!component->is_started) {
      ice_setup_remote_candidates(session, component->stream->id, component->id);
   } else {
      c = candidate_copy(candidate);
      memset(&candidates,0,sizeof(candidate_t));
      INIT_LIST_HEAD(&candidates.list);
      list_add(&c->list,&candidates.list);
      added = ice_agent_set_remote_candidates(session->agent,stream->id,
                                              component->id,&candidates); 
      if (added < 1) {
         //ERROR("failed to add candidate, added=%u",added);
      }

      //DEBUG("candidate added, added=%u",added);
      /* clean resources */
      INIT_LIST_HEAD(&candidates.list);
      candidate_free(c);
   }

   return;
}

candidate_t*
snw_ice_remote_candidate_new(char *type, char *transport) {
   candidate_t* c = NULL;

   if(strcasecmp(transport, "udp")) {
      return NULL;
   }

   if(!strcasecmp(type, "host")) {
      c = candidate_new(ICE_CANDIDATE_TYPE_HOST);
   } else if (!strcasecmp(type, "srflx")) {
      c = candidate_new(ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE);
   } else if(!strcasecmp(type, "prflx")) {
      c = candidate_new(ICE_CANDIDATE_TYPE_PEER_REFLEXIVE);
   } else if(!strcasecmp(type, "relay")) {
      //c = candidate_new(ICE_CANDIDATE_TYPE_RELAYED);
      //DEBUG("relay candidate not supported, type:%s", type);
   } else {
      //DEBUG("Unknown remote candidate, type:%s", type);
   }

   return c;
}

int 
snw_ice_sdp_handle_candidate(snw_ice_stream_t *stream, const char *candidate) {
   snw_ice_session_t *session = NULL;
   snw_ice_component_t *component = NULL;
   candidate_t *c = NULL;
   char foundation[16], transport[4], type[6]; 
   char ip[32], relip[32];
   uint32_t component_id, priority, port, relport;
   int ret;

   if (stream == NULL || candidate == NULL)
      return -1;

   session = stream->session;
   if (session == NULL)
      return -2;

   if (strstr(candidate, "candidate:") == candidate) {
      candidate += strlen("candidate:");
   }

   /* format: foundation component tranpsort priority ip port type ??? ??? ??? ??? */
   ret = sscanf(candidate, "%15s %30u %3s %30u %31s %30u typ %5s %*s %31s %*s %30u",
                           foundation, &component_id, transport, &priority,
                           ip, &port, type, relip, &relport);

   if (ret >= 7) {
      component = snw_component_find(&stream->components, component_id);
      if (component == NULL) {
         //ERROR("component not found, cid=%u, sid=%u", component_id, stream->id);
         return -3;
      } 

      c = snw_ice_remote_candidate_new(type,transport);
      if (c != NULL) {
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

         snw_ice_try_start_component(session,stream,component,c);
      }
   } else {
      //ERROR("failed to parse candidate, ret=%d, s=%s", ret, candidate);
      return ret;
   }
   return 0;
}

int 
snw_sdp_stream_update_ssrc(snw_ice_stream_t *stream, const char *ssrc_attr, int video) {
   int64_t ssrc;

   if (stream == NULL || ssrc_attr == NULL)
      return -1;

   ssrc = atoll(ssrc_attr);
   if (ssrc == 0)
      return -2;

   if (video) {
      if ( stream->remote_video_ssrc == 0 ) {
         stream->remote_video_ssrc = ssrc;
      } else {
         //ERROR("video ssrc updated, ssrc=%u, new_ssrc=%u", 
         //      stream->remote_video_ssrc,ssrc);
         return -3;
      }
   } else {
      if(stream->remote_audio_ssrc == 0) {
         stream->remote_audio_ssrc = ssrc;
      } else {
         //ERROR("audio ssrc update, ssrc=%u, new_ssrc=%u", 
         //      stream->remote_audio_ssrc,ssrc);
         return -4;
      }
   }

   return 0;
}

int
snw_ice_sdp_get_local_credentials(snw_ice_session_t *session, snw_ice_stream_t *stream, sdp_media_t *m) {
   snw_log_t *log = 0;
   sdp_attribute_t *a;
   const char *remote_user = NULL, *remote_pass = NULL;
   const char *remote_hashing = NULL, *remote_fingerprint = NULL;
   
   if (stream == NULL || m == NULL)
      return -1;
   log = session->ice_ctx->log;

   a = m->m_attributes;
   while(a) {
      if(a->a_name) {
         if(!strcasecmp(a->a_name, "mid")) {
            if(m->m_type == sdp_media_audio && m->m_port > 0) {
               //DEBUG(log, "Audio mid: %s", a->a_value);
            } else if(m->m_type == sdp_media_video && m->m_port > 0) {
               //DEBUG(log, "Video mid: %s", a->a_value);
            } else if(m->m_type == sdp_media_application) {
               //
            }
         } else if(!strcasecmp(a->a_name, "fingerprint")) {
            if(strcasestr(a->a_value, "sha-256 ") == a->a_value) {
               remote_hashing = "sha-256";
               remote_fingerprint = a->a_value + strlen("sha-256 ");
            } else if(strcasestr(a->a_value, "sha-1 ") == a->a_value) {
               remote_hashing = "sha-1";
               remote_fingerprint = a->a_value + strlen("sha-1 ");
            } else {
               //FIXME
            }
         } else if(!strcasecmp(a->a_name, "setup")) {
            if(!strcasecmp(a->a_value, "actpass") || !strcasecmp(a->a_value, "passive"))
               stream->dtls_type = DTLS_TYPE_CLIENT;
            else if(!strcasecmp(a->a_value, "active"))
               stream->dtls_type = DTLS_TYPE_SERVER;
         } else if(!strcasecmp(a->a_name, "ice-ufrag")) {
            remote_user = a->a_value;
         } else if(!strcasecmp(a->a_name, "ice-pwd")) {
            remote_pass = a->a_value;
         }
      }
      a = a->a_next;
   }

   if (!remote_user || !remote_pass || !remote_fingerprint || !remote_hashing) {
      return -2;
   }

   memcpy(stream->remote_hashing,remote_hashing,strlen(remote_hashing));
   memcpy(stream->remote_fingerprint,remote_fingerprint,strlen(remote_fingerprint));
   memcpy(stream->remote_user,remote_user,strlen(remote_user));
   memcpy(stream->remote_pass,remote_pass,strlen(remote_pass));

   TRACE(log, "stream info, stream=%p",stream);
   TRACE(log, "stream info, rhash=%s",stream->remote_hashing);
   TRACE(log, "stream info, rfingerprint=%s, len=%u",
         stream->remote_fingerprint, strlen(stream->remote_fingerprint));
   TRACE(log, "stream info, ruser=%s",stream->remote_user);
   TRACE(log, "stream info, rpass=%s",stream->remote_pass);

   return 0;
}

int 
snw_ice_sdp_get_global_credentials(snw_ice_session_t *session, sdp_session_t *remote_sdp) {
   sdp_attribute_t *a = NULL;
   const char *remote_user = NULL, *remote_pass = NULL; 
   const char *remote_hashing = NULL, *remote_fingerprint = NULL;

   a = remote_sdp->sdp_attributes;
   while (a) {
      if (a->a_name) {
         if (!strcasecmp(a->a_name, "fingerprint")) {
            //DEBUG("global credentials, value=%s", a->a_value);
            if (strcasestr(a->a_value, "sha-256 ") == a->a_value) {
               remote_hashing = "sha-256";
               remote_fingerprint = a->a_value + strlen("sha-256 ");
            } else if (strcasestr(a->a_value, "sha-1 ") == a->a_value) {
               remote_hashing = "sha-1";
               remote_fingerprint = a->a_value + strlen("sha-1 ");
            } else {
               //DEBUG("unknown algorithm, s=%s",a->a_name);
            }    
         } else if(!strcasecmp(a->a_name, "ice-ufrag")) {
            remote_user = a->a_value;
         } else if(!strcasecmp(a->a_name, "ice-pwd")) {
            remote_pass = a->a_value;
         }
      }
      a = a->a_next;
   }

   if (!remote_user || !remote_pass || !remote_hashing || !remote_fingerprint) {
      //ERROR("global credentials not found");
      return -1;
   }

   memcpy(session->remote_user,remote_user,strlen(remote_user));
   memcpy(session->remote_pass,remote_pass,strlen(remote_pass));
   memcpy(session->remote_hashing,remote_hashing,strlen(remote_hashing));
   memcpy(session->remote_fingerprint,remote_fingerprint,strlen(remote_fingerprint));

   //DEBUG("global credentials, ruser=%s, rpass=%s, rhashing=%s, rfingerprint=%s",
   //      session->remote_user, session->remote_pass, 
   //      session->remote_hashing, session->remote_fingerprint);

   return 0;
}

int 
snw_ice_sdp_get_candidate(snw_ice_session_t *session, snw_ice_stream_t *stream, sdp_media_t *m) {
   sdp_attribute_t *a = NULL;

   a = m->m_attributes;
   while (a) {
      if (a->a_name) {
         if (!strcasecmp(a->a_name, "candidate")) {
            int ret = snw_ice_sdp_handle_candidate(stream, (const char *)a->a_value);
            if (ret != 0) {
               //DEBUG("failed to parse candidate, ret=%d", ret);
            }
         }

         if (!strcasecmp(a->a_name, "ssrc")) {
            int video = m->m_type == sdp_media_video;
            int ret = snw_sdp_stream_update_ssrc(stream, (const char *)a->a_value, video);
            if (ret != 0) {
               //DEBUG("failed to update SSRC, ret=%d", ret);
            }
         }
      }
      a = a->a_next;
   }

   return 0;
}

int 
snw_ice_sdp_handle_answer(snw_ice_session_t *session, char *sdp) {
   snw_log_t *log = 0;
   snw_ice_stream_t *stream = NULL;
   sdp_session_t *remote_sdp = NULL;
   sdp_media_t *m = NULL;
   sdp_parser_t *parser = 0;
   int audio = 0, video = 0; 

   if (!session || !session->ice_ctx) return -1;
   log = session->ice_ctx->log;

   parser = snw_ice_sdp_get_parser(session->ice_ctx, sdp);
   if (!parser) {
      ERROR(log, "invalid sdp, sdp=%s",sdp);
      return -1;
   }

   remote_sdp = sdp_session(parser);
   if (!remote_sdp) {
      sdp_parser_free(parser);
      return -1;
   }

   snw_ice_sdp_get_global_credentials(session,remote_sdp);

   m = remote_sdp->sdp_media;
   while (m) {
      if (m->m_type == sdp_media_audio) {
         if (m->m_port > 0) {
            audio++;
            if(audio > 1) {
               m = m->m_next;
               continue;
            }
            stream = snw_stream_find(&session->streams, session->audio_stream->id);
         } else {
            CLEAR_FLAG(session, WEBRTC_AUDIO);
         }
      } else if(m->m_type == sdp_media_video) {
         if (m->m_port > 0) {
            video++;
            if (video > 1) {
               m = m->m_next;
               continue;
            }
            if(!IS_FLAG(session, WEBRTC_BUNDLE)) {
               stream = snw_stream_find(&session->streams, session->video_stream->id);
            } else {
               uint32_t id = session->audio_stream->id > 0 ? 
                                session->audio_stream->id : 
                                session->video_stream->id;
               stream = snw_stream_find(&session->streams, id);
            }
         } else {
            CLEAR_FLAG(session, WEBRTC_VIDEO);
         }
      } else if(m->m_type == sdp_media_application) {
         /* TODO: support data channel */

      } else {
         WARN(log,"unsupported media line, s=%d",m->m_type);
         m = m->m_next;
         continue;
      }
      
      snw_ice_sdp_get_local_credentials(session,stream,m);
      snw_ice_sdp_get_candidate(session,stream,m);
      m = m->m_next;
   }

   sdp_parser_free(parser);
   return 0;
}


