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

#include <bsd/bsd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "core/channel.h"
#include "core/conf.h"
#include "core/conn.h"
#include "core/connection.h"
#include "core/core.h"
#include "core/log.h"
#include "core/module.h"
#include "core/msg.h"
#include "core/roominfo.h"
#include "core/snow.h"
#include "core/snw_event.h"
#include "core/task.h"
#include "core/utils.h"
#include "http/http.h"
#include "json-c/json.h"
#include "websocket/websocket.h"

int
snw_ice_handler(snw_context_t *ctx, snw_connection_t *conn, uint32_t type, char *data, uint32_t len) {

   snw_shmmq_enqueue(ctx->ice_task->req_mq, 0, data, len, conn->flowid);
   return 0;
}

int
snw_sig_auth_msg(snw_context_t *ctx, void *data, int len, uint32_t flowid) {
  json_object *jobj = (json_object*)data;
  const char *auth_data = 0;

  auth_data = snw_json_msg_get_string(jobj,"auth_data");
  if (!auth_data) return -1;

  //TODO: move logic to channel.auth
  return 0;
}

int
snw_sig_create_msg(snw_context_t *ctx, void *data, int len, uint32_t flowid) {
  snw_log_t *log = ctx->log;
  json_object *jobj = (json_object*)data;
  snw_channel_t *channel = 0;
  snw_conn_t *conn = 0;
  uint32_t channelid = 0;
  const char *str = 0;
  uint32_t channel_type = 0;
  uint32_t peerid = 0;
  int is_new = 0;
  
  peerid = snw_json_msg_get_int(jobj,"id");
  if (peerid == (uint32_t)-1)
    return -1;
  conn = snw_conn_search(ctx->conn_cache,peerid);
  if (!conn) {
    ERROR(log, "peer not found, flowid=%u, peerid=%u", flowid, peerid);
    return -1;
  }

  str = snw_json_msg_get_string(jobj,"type");
  if (!str) return -1;

  if (!strncmp(str,"broadcast",9)) {
    channel_type = SNW_LIVE_CHANNEL_TYPE;
  } else 
  if (!strncmp(str,"call",4)) {
    channel_type = SNW_CALL_CHANNEL_TYPE;
  } else 
  if (!strncmp(str,"conference",10)) {
    channel_type = SNW_CONF_CHANNEL_TYPE;
  } else {
    ERROR(log, "unknow channel type: %s", str);
    return -2;
  }

  //Step1: get channel id from a pool.
  channelid = snw_set_getid(ctx->channel_mgr);
  if (channelid == 0) {
     ERROR(log, "can not create channel, flowid=%u", flowid);
     return -1;
  }

  //Step2: get channel object.
  channel = snw_channel_get(ctx->channel_cache,channelid,&is_new);
  if (channel == 0) {
     ERROR(log, "can not create channel, flowid=%u", flowid);
     return -1;
  }
  if (!is_new) {
     ERROR(log,"reseting existing channel, channelid=%u",channelid);
     memset(channel,0,sizeof(snw_channel_t));
     channel->id = channelid;
  }
  channel->flowid = flowid; //TODO: no need to have flowid
  channel->type = channel_type;
       
  DEBUG(log,"create channel, channelid=%u", channelid);

  json_object_object_add(jobj,"channelid",json_object_new_int(channelid));
  json_object_object_add(jobj,"rc",json_object_new_int(0));
  str = snw_json_msg_to_string(jobj);
  if (!str) return -1;
  snw_shmmq_enqueue(ctx->net_task->req_mq,0,str,strlen(str),flowid);

  //inform ice component about new channel
  json_object_object_add(jobj,"msgtype",json_object_new_int(SNW_ICE));
  json_object_object_add(jobj,"api",json_object_new_int(SNW_ICE_CREATE));
  str = snw_json_msg_to_string(jobj);
  if (!str) return -1;
  snw_shmmq_enqueue(ctx->ice_task->req_mq,0,str,strlen(str),flowid);
 
  return 0;
}

int
snw_sig_connect_msg(snw_context_t *ctx, void *data, int len, uint32_t flowid) {
  snw_log_t *log = ctx->log;
  json_object *jobj = (json_object*)data;
  snw_conn_t *conn = 0;
  snw_channel_t *channel = 0;
  const char *str = 0;
  const char *peer_type = 0;
  uint32_t channelid = 0;
  uint32_t peerid = 0;
  int forward_to_ice = 0;
   
  peerid = snw_json_msg_get_int(jobj,"id");
  conn = snw_conn_search(ctx->conn_cache,peerid);
  if (!conn) {
     ERROR(log, "peer not found, peerid=%u", peerid);
     return -1;
  }

  channelid = snw_json_msg_get_int(jobj,"channelid");
  channel = snw_channel_search(ctx->channel_cache,channelid);
  if (!channel) {
    ERROR(log, "channel not found, channelid=%u", channelid);
    return -1;
  }

  peer_type = snw_json_msg_get_string(jobj,"peer_type");
  if (!peer_type) return -1;

  if (!strncmp(peer_type,"pub",3)) {
    //conn->peer_type = STREAM_TYPE_PUBLISHER;
    forward_to_ice = 1;
  } else if (!strncmp(peer_type,"pla",3)) {
    //conn->peer_type = STREAM_TYPE_PLAYER;
    forward_to_ice = 1;
  } else if (!strncmp(peer_type,"p2p",3)) {
    //conn->peer_type = STREAM_TYPE_P2P;
  } else {
    ERROR(log,"unknown peer type, flowid=%u, peer_type=%s",flowid,peer_type);
    //conn->peer_type = STREAM_TYPE_UNKNOWN;
    return -2;
  }

  if (forward_to_ice) {
     //TODO: remove ice_connect from client request
  }

  if (channel->flowid == 0) {
    DEBUG(log,"first user in channel, flowid=%u, channelid=%u",
      flowid, channel->id);
    channel->flowid = flowid;
  } else if (channel->flowid != flowid) {
    json_object *notify;

    DEBUG(log,"notify peer joined event, flowid=%u, channel_flowid=%u",
      conn->flowid, channel->flowid);
    notify = json_object_new_object();
    if (!notify) {
      ERROR(log,"falied to notify to ice, flowid=%u",conn->flowid);
      return -1;
    }
    json_object_object_add(notify,"msgtype",json_object_new_int(SNW_EVENT));
    json_object_object_add(notify,"api",json_object_new_int(SNW_EVENT_ADD_STREAM));
    json_object_object_add(notify,"remoteid",json_object_new_int(conn->flowid));
    //json_object_object_add(notify,"peerid",json_object_new_int(channel->peerid));
    json_object_object_add(notify,"channelid",json_object_new_int(channelid));
    //json_object_object_add(notify,"is_p2p",
    //    json_object_new_int(conn->peer_type == PEER_TYPE_P2P ? 1 : 0));

    str = snw_json_msg_to_string(notify);
    if (str) {
       snw_shmmq_enqueue(ctx->net_task->req_mq,0,str,strlen(str),channel->flowid);
    }
    json_object_put(notify);
  }

  return 0;
}

int
snw_sig_call_msg(snw_context_t *ctx, void *data, int len, uint32_t flowid) {
  json_object *jobj = (json_object*)data;
  const char *str = 0;
  uint32_t peerid = 0;
   
  peerid = snw_json_msg_get_int(jobj,"remoteid");

  //TODO: verify peer in channel
  //channelid = snw_json_msg_get_int(jobj,"channelid");
      
  str = snw_json_msg_to_string(jobj);
  if (!str) return -1;

  snw_shmmq_enqueue(ctx->net_task->req_mq,0,str,strlen(str),peerid);

  return 0;
}

void
snw_sig_add_subchannel(snw_channel_t *channel, uint32_t peerid, uint32_t channelid) {

  if (!channel) return;

  for (int i=0; i < SNW_SUBCHANNEL_NUM_MAX; i++) {
    if (channel->subchannels[i].channelid == 0) {
      channel->subchannels[i].peerid = peerid;
      channel->subchannels[i].channelid = channelid;
      break;
    }
  }

  return;
}

void
snw_sig_remove_subchannel(snw_channel_t *channel, uint32_t peerid, uint32_t channelid) {

  if (!channel) return;

  for (int i=0; i < SNW_SUBCHANNEL_NUM_MAX; i++) {
    if (channel->subchannels[i].channelid == channelid
        && channel->subchannels[i].peerid == peerid) {
      channel->subchannels[i].peerid = 0;
      channel->subchannels[i].channelid = 0;
      break;
    }
  }

  return;
}

int
snw_sig_publish_subchannel(snw_context_t *ctx, uint32_t flowid,
    snw_channel_t *channel) {
  snw_log_t *log = ctx->log;
  uint32_t channelid = 0;
  int is_new = 0;
  snw_channel_t *subchannel = 0;
  json_object *req = 0;
  const char *str = 0;

  channelid = snw_set_getid(ctx->channel_mgr);
  if (channelid == 0) {
    ERROR(log, "can not create channel, flowid=%u", flowid);
    return -1;
  }

  subchannel = snw_channel_get(ctx->channel_cache,channelid,&is_new);
  if (channel == 0) {
    ERROR(log, "can not create channel, flowid=%u", flowid);
    return -2;
  }
  if (!is_new) {
    ERROR(log,"reseting existing channel, channelid=%u",channelid);
    memset(channel,0,sizeof(snw_channel_t));
    subchannel->id = channelid;
    return -3;
  }
  subchannel->flowid = channel->flowid;
  //subchannel->peerid = channel->peerid;
  subchannel->parentid = channel->id;
  subchannel->type = SNW_LIVE_CHANNEL_TYPE;
  snw_sig_add_subchannel(channel, flowid, channelid);

  //inform ice component about new channel
  //FIXME: this will generate resp msg to client, need a way to distinguish it from
  //       normal case.
  req = json_object_new_object();
  if (!req) return -1;
  json_object_object_add(req,"msgtype",json_object_new_int(SNW_ICE));
  json_object_object_add(req,"api",json_object_new_int(SNW_ICE_CREATE));
  json_object_object_add(req,"channelid",json_object_new_int(channelid));
  str = snw_json_msg_to_string(req);
  if (!str) {
    json_object_put(req);
    return -1;
  }
  snw_shmmq_enqueue(ctx->ice_task->req_mq,0,str,strlen(str),flowid);

  // publish subchannel
  json_object_object_add(req,"api",json_object_new_int(SNW_ICE_PUBLISH));
  str = snw_json_msg_to_string(req);
  if (!str) {
    json_object_put(req);
    return -1;
  }
  snw_shmmq_enqueue(ctx->ice_task->req_mq,0,str,strlen(str),flowid);

  json_object_put(req);
  return channelid;
}

void
snw_sig_broadcast_new_subchannel(snw_context_t *ctx, 
    uint32_t channelid, uint32_t subchannelid, uint32_t flowid) {
  snw_log_t *log = ctx->log;
  snw_channel_t *channel = 0;
  json_object *jobj = 0;
  const char *str = 0;

  channel = snw_channel_search(ctx->channel_cache,channelid);
  if (!channel) {
    ERROR(log, "channel not found, channelid=%u", channelid);
    return;
  }

  jobj = json_object_new_object();
  if (!jobj) return;
  json_object_object_add(jobj,"msgtype",json_object_new_int(SNW_EVENT));
  json_object_object_add(jobj,"api",json_object_new_int(SNW_EVENT_ADD_SUBCHANNEL));
  json_object_object_add(jobj,"peerid",json_object_new_int(flowid));
  json_object_object_add(jobj,"channelid",json_object_new_int(channelid));
  json_object_object_add(jobj,"subchannelid",json_object_new_int(subchannelid));
  str = snw_json_msg_to_string(jobj);
  DEBUG(log, "send event of new subchannel to peer,"
      " scid=%u, flowid=%u, s=%s", 
      subchannelid, flowid, str);

  for (int i=0; i<channel->idx; i++) {
    snw_shmmq_enqueue(ctx->net_task->req_mq,0,str, strlen(str),channel->peers[i]);
  }

  return;
}

void
snw_core_channel_add_peer(snw_context_t *ctx,
    uint32_t channelid, uint32_t flowid) {
  snw_log_t *log = ctx->log;
  snw_channel_t *channel = 0;

  channel = snw_channel_search(ctx->channel_cache,channelid);
  if (!channel) {
    ERROR(log, "channel not found, channelid=%u", channelid);
    return;
  }

  if (channel->idx >= SNW_USER_NUM_MAX) {
     ERROR(log, "channel info full, flowid=%u, channelid=%u", flowid, channelid);
     return;
  }
  channel->peers[channel->idx] = flowid;
  channel->idx++;

  return;
}

void
snw_core_channel_remove_subscriber(snw_context_t *ctx,
    uint32_t channelid, uint32_t flowid) {
  //TODO: impl
  return;
}

int
snw_sig_publish_msg_old(snw_context_t *ctx, void *data, int len, uint32_t flowid) {
  snw_log_t *log = ctx->log;
  json_object *jobj = (json_object*)data;
  json_object *subchannels = 0;
  const char *str = 0;
  uint32_t channelid = 0;
  uint32_t sub_channelid = 0;
  snw_channel_t *channel = 0;
  uint32_t peerid = 0;
  snw_conn_t *conn = 0;

  peerid = snw_json_msg_get_int(jobj,"id");
  conn = snw_conn_search(ctx->conn_cache, peerid);
  if (!conn) {
    ERROR(log,"peer not found, flowid=%u, peerid=%u", flowid, peerid);
    return -1;
  }

  channelid = snw_json_msg_get_int(jobj,"channelid");
  snw_core_channel_add_peer(ctx,channelid,flowid);

  channel = snw_channel_search(ctx->channel_cache,channelid);
  if (!channel) {
    ERROR(log, "channel not found, channelid=%u", channelid);
    return -1;
  }
  DEBUG(log,"publish req, flowid=%u, channelid=%u, type=%u",
    flowid, channelid, channel->type);

  if (channel->type == SNW_CONF_CHANNEL_TYPE) {
    sub_channelid = snw_sig_publish_subchannel(ctx, flowid, channel);
    snw_sig_broadcast_new_subchannel(ctx,channelid,sub_channelid,flowid);
    conn->channelid = sub_channelid;

    //response with list of published streams in the channel
    subchannels = json_object_new_array();
    if (!subchannels) return -1;
    for (int i=0; i < SNW_SUBCHANNEL_NUM_MAX; i++) {
      if (channel->subchannels[i].channelid != 0) {
        json_object *item = json_object_new_object();
        if (!item) {
          json_object_put(subchannels);
          return -1;
        }

        DEBUG(log,"subchannel info: pid=%u, cid=%u", 
          channel->subchannels[i].peerid, channel->subchannels[i].channelid);
        json_object_object_add(item,"peerid",json_object_new_int(channel->subchannels[i].peerid));
        json_object_object_add(item,"subchannelid",json_object_new_int(channel->subchannels[i].channelid));
        json_object_array_add(subchannels,item);
      }
    }
    json_object_object_add(jobj,"subchannels",subchannels);
    json_object_object_add(jobj,"rc",json_object_new_int(0));
    str = snw_json_msg_to_string(jobj);
    if (!str) return -1;
    snw_shmmq_enqueue(ctx->net_task->req_mq,0,str,strlen(str),flowid);
    return 0;
  }

  if (channel->type != SNW_CALL_CHANNEL_TYPE
      && channel->type != SNW_LIVE_CHANNEL_TYPE) {
    ERROR(log, "unknow channel type, type=%u", channel->type);
    return -2;
  }

  json_object_object_add(jobj,"msgtype",json_object_new_int(SNW_ICE));
  json_object_object_add(jobj,"api",json_object_new_int(SNW_ICE_PUBLISH));
  if (!str) return -1;
  snw_shmmq_enqueue(ctx->ice_task->req_mq,0,str,strlen(str),flowid);
 
  return 0;
}

int
snw_sig_broadcast_new_stream(snw_context_t *ctx,
     snw_channel_t *channel, uint32_t streamid) {
  snw_log_t *log = ctx->log;
  json_object *jobj = 0;
  json_object *jarray = 0;
  json_object *jitem = 0;
  const char *str = 0;
  int i = 0;

  jobj = json_object_new_object();
  if (!jobj) {
    ERROR(log,"falied to alloc json object, streamid=%u",streamid);
    return -1;
  }

  json_object_object_add(jobj,"msgtype",json_object_new_int(SNW_EVENT));
  json_object_object_add(jobj,"api",json_object_new_int(SNW_EVENT_ADD_STREAM));
  json_object_object_add(jobj,"channelid",json_object_new_int(channel->id));

  jarray = json_object_new_array();
  jitem = json_object_new_object();
  if ( !jarray || !jitem) {
    json_object_put(jobj);
    if (jarray) json_object_put(jarray);
    if (jitem) json_object_put(jitem);
  }

  json_object_object_add(jitem,"streamid",json_object_new_int(streamid));
  json_object_array_add(jarray, jitem);
  json_object_object_add(jobj,"streams",jarray);

  str = snw_json_msg_to_string(jobj);
  if (!str) {
    json_object_put(jobj);
    return -2;
  }
 
  DEBUG(log,"broadcast new stream, streamid=%u, str=%s", streamid, str);

  for (i=0; i < channel->lastidx; i++) {
    snw_shmmq_enqueue(ctx->net_task->req_mq,0,str,strlen(str),channel->flows[i]);
  }
 
  json_object_put(jobj);

  return 0;
}

int
snw_sig_publish_msg(snw_context_t *ctx, void *data, int len, uint32_t flowid) {
  snw_log_t *log = ctx->log;
  json_object *jobj = (json_object*)data;
  const char *str = 0;
  uint32_t streamid = 0;
  uint32_t channelid = 0;
  snw_channel_t *channel = 0;
  snw_stream_t *stream = 0;

  streamid = snw_json_msg_get_int(jobj,"streamid");
  channelid = snw_json_msg_get_int(jobj,"channelid");

  if (streamid == (uint32_t)-1 || channelid == (uint32_t)-1)
    return -1;

  stream = snw_stream_search(ctx->stream_cache, streamid);
  if (!stream) {
    ERROR(log,"stream not found, flowid=%u, streamid=%u", flowid, streamid);
    return -1;
  }

  channel = snw_channel_search(ctx->channel_cache,channelid);
  if (!channel || stream->channelid != channelid) {
    ERROR(log, "channel not found, channelid=%u", channelid);
    return -1;
  }

  DEBUG(log,"publish req, flowid=%u, channelid=%u, type=%u",
    flowid, channelid, channel->type);

  if (channel->type == SNW_CONF_CHANNEL_TYPE) {
    stream->type = STREAM_TYPE_PUBLISHER;

    // inform ice component of new status
    json_object_object_add(jobj,"msgtype",json_object_new_int(SNW_ICE));
    json_object_object_add(jobj,"api",json_object_new_int(SNW_ICE_PUBLISH));
    str = snw_json_msg_to_string(jobj);
    if (!str) return -1;
    snw_shmmq_enqueue(ctx->ice_task->req_mq,0,str,strlen(str),flowid);

    // broadcast new stream
    snw_sig_broadcast_new_stream(ctx, channel, streamid);
    return 0;
  }

  if (channel->type != SNW_CALL_CHANNEL_TYPE
      && channel->type != SNW_LIVE_CHANNEL_TYPE) {
    ERROR(log, "unknow channel type, type=%u", channel->type);
    return -2;
  }


  return 0;
}

int
snw_sig_play_msg(snw_context_t *ctx, void *data, int len, uint32_t flowid) {
  snw_log_t *log = ctx->log;
  json_object *jobj = (json_object*)data;
  const char *str = 0;
  uint32_t channelid = 0;

  //FIXME: do we need this?
  channelid = snw_json_msg_get_int(jobj,"channelid");
  snw_core_channel_add_peer(ctx, channelid, flowid);

  DEBUG(log,"play req, flowid=%u, channelid=%u",
    flowid, channelid);

  json_object_object_add(jobj,"msgtype",json_object_new_int(SNW_ICE));
  json_object_object_add(jobj,"api",json_object_new_int(SNW_ICE_PLAY));
  str = snw_json_msg_to_string(jobj);
  if (!str) return -1;
  snw_shmmq_enqueue(ctx->ice_task->req_mq,0,str,strlen(str),flowid);

  return 0;
}

int
snw_sig_sdp_msg(snw_context_t *ctx, void *data, int len, uint32_t flowid) {
  json_object *jobj = (json_object*)data;
  const char *str = 0;
  uint32_t remoteid = 0;
   
  remoteid = snw_json_msg_get_int(jobj,"remoteid");
  str = snw_json_msg_to_string(jobj);
  if (!str) return -1;
  snw_shmmq_enqueue(ctx->net_task->req_mq,0,str,strlen(str),remoteid);

  return 0;
}

int
snw_sig_candidate_msg(snw_context_t *ctx, void *data, int len, uint32_t flowid) {
  json_object *jobj = (json_object*)data;
  const char *str = 0;
  uint32_t remoteid = 0;
   
  remoteid = snw_json_msg_get_int(jobj,"remoteid");
  str = snw_json_msg_to_string(jobj);
  if (!str) return -1;
  snw_shmmq_enqueue(ctx->net_task->req_mq,0,str,strlen(str),remoteid);

  return 0;
}

int
snw_sig_handler(snw_context_t *ctx, snw_connection_t *conn, json_object *jobj) {
  snw_log_t *log = ctx->log;
  uint32_t flowid = conn->flowid;
  uint32_t api = 0;

  api = snw_json_msg_get_int(jobj,"api");
  switch(api) {
     case SNW_SIG_AUTH:
        snw_sig_auth_msg(ctx,jobj,0,flowid);
        break;
     case SNW_SIG_CREATE:
        snw_sig_create_msg(ctx,jobj,0,flowid);
        break;
     case SNW_SIG_CONNECT:
        snw_sig_connect_msg(ctx,jobj,0,flowid);
        break;
     case SNW_SIG_CALL:
        snw_sig_call_msg(ctx,jobj,0,flowid);
        break;
     case SNW_SIG_PUBLISH:
        snw_sig_publish_msg(ctx,jobj,0,flowid);
        break;
     case SNW_SIG_PLAY:
        snw_sig_play_msg(ctx,jobj,0,flowid);
        break;
     case SNW_SIG_SDP:
        snw_sig_sdp_msg(ctx,jobj,0,flowid);
        break;
     case SNW_SIG_CANDIDATE:
        snw_sig_candidate_msg(ctx,jobj,0,flowid);
        break;
     default:
        DEBUG(log, "unknown api, api=%u", api);
        break;
  }

  return 0;
}

void
snw_channel_delete_flow(snw_context_t *ctx, snw_channel_t *channel, uint32_t flowid) {
  int i = 0;

  for (i=0; i < channel->lastidx; i++) {
    if (channel->flows[i] == flowid)
      break;
  }

  if (i >= channel->lastidx)
    return;

  channel->flows[i] = channel->flows[channel->lastidx];
  channel->lastidx--;

  return;
}

void
snw_channel_add_flow(snw_context_t *ctx, snw_channel_t *channel, uint32_t flowid) {
  snw_log_t *log = ctx->log;
  json_object *notify = 0;
  const char *str = 0;
  int i = 0;

  if (!channel 
      || channel->lastidx >= SNW_USER_NUM_MAX) {
    WARN(log, "channel is full, id=%d", channel->id);
    return;
  }

  channel->flows[channel->lastidx] = flowid;

  if (channel->type == SNW_CALL_CHANNEL_TYPE) {

    DEBUG(log,"notify peer joined event, flowid=%u, id=%u", flowid, channel->id);
    notify = json_object_new_object();
    if (!notify) {
      ERROR(log,"falied to notify to ice, flowid=%u",flowid);
      channel->flows[channel->lastidx] = 0; //reset
      return;
    }

    json_object_object_add(notify,"msgtype",json_object_new_int(SNW_EVENT));
    json_object_object_add(notify,"api",json_object_new_int(SNW_EVENT_ADD_STREAM));
    json_object_object_add(notify,"channelid",json_object_new_int(channel->id));
    str = snw_json_msg_to_string(notify);
    if (str) {
      json_object_put(notify);
      channel->flows[channel->lastidx] = 0; //reset
      return;
    }
 
    for (i=0; i < channel->lastidx; i++) {
      snw_shmmq_enqueue(ctx->net_task->req_mq,0,str,strlen(str),channel->flows[i]);
    }
    channel->lastidx++;
    json_object_put(notify);
  } else {
    channel->lastidx++;
  }

  return;
}

int
snw_channel_connect_msg(snw_context_t *ctx, void *data, int len, uint32_t flowid) {
  snw_log_t *log = ctx->log;
  json_object *jobj = (json_object*)data;
  json_object *streams = 0;
  snw_channel_t *channel = 0;
  snw_conn_t *conn = 0;
  uint32_t channelid = 0;
  const char *str = 0;
  int is_new = 0;
   
  channelid = snw_json_msg_get_int(jobj,"channelid");
  channel = snw_channel_search(ctx->channel_cache,channelid);
  if (!channel) {
    ERROR(log, "channel not found, channelid=%u", channelid);
    return -1;
  }

  conn = snw_conn_get(ctx->conn_cache, flowid, &is_new);
  if (!conn || !is_new) {
    ERROR(log, "cannot create conn, flowid=%u, channelid=%u",
        flowid, channelid);
    return -1;
  }
  conn->channelid = channelid;

  DEBUG(log, "connect msg, channelid=%u, flowid=%u, idx=%u", 
      channelid, flowid, channel->streams.idx);

  snw_channel_add_flow(ctx,channel,flowid);

  // notify all published streams to this new connection
  if (channel->streams.idx>0) {
    int i = 0;

    DEBUG(log,"connect msg get array of streams");
    streams = json_object_new_array();
    if (!streams) return -2;

    for (i=0; i<channel->streams.idx; i++) {
      snw_stream_t *stream = 0;
      json_object *item = 0;

      stream = snw_stream_search(ctx->stream_cache,channel->streams.list[i]);
      DEBUG(log,"connect msg search for stream, streamid=%u", channel->streams.list[i]);
      if (!stream || stream->type != STREAM_TYPE_PUBLISHER) {
        DEBUG(log,"connect msg stream not found, streamid=%u",channel->streams.list[i]);
        continue;
      }

      DEBUG(log,"connect msg search for stream, streamid=%u, type=%u",
           channel->streams.list[i], stream->type);

      item = json_object_new_object();
      if (!item) {
        json_object_put(streams);
        return -1;
      }

      DEBUG(log,"connect msg insert stream, streamid=%u",stream->id);
      json_object_object_add(item,"streamid",json_object_new_int(stream->id));
      json_object_array_add(streams,item);
    }
  }

  json_object_object_add(jobj,"streams",streams);
  json_object_object_add(jobj,"rc",json_object_new_int(0));
  json_object_object_add(jobj,"flowid",json_object_new_int(flowid));

  /*  subchannels = json_object_new_array();
    if (!subchannels) return -1;
    for (int i=0; i < SNW_SUBCHANNEL_NUM_MAX; i++) {
      if (channel->subchannels[i].channelid != 0) {
        json_object *item = json_object_new_object();
        if (!item) {
          json_object_put(subchannels);
          return -1;
        }

        DEBUG(log,"subchannel info: pid=%u, cid=%u", 
          channel->subchannels[i].peerid, channel->subchannels[i].channelid);
        json_object_object_add(item,"peerid",json_object_new_int(channel->subchannels[i].peerid));
        json_object_object_add(item,"subchannelid",json_object_new_int(channel->subchannels[i].channelid));
        json_object_array_add(subchannels,item);
      }
    }
    json_object_object_add(jobj,"subchannels",subchannels);
  */

  str = snw_json_msg_to_string(jobj);
  if (str) {
    DEBUG(log,"connect msg send result, str=%s",str);
    snw_shmmq_enqueue(ctx->net_task->req_mq,0,str,strlen(str),flowid);
  }
 
  return 0;
}

int
snw_channel_create_stream_msg(snw_context_t *ctx, void *data, int len, uint32_t flowid) {
  snw_log_t *log = ctx->log;
  json_object *jobj = (json_object*)data;
  snw_channel_t *channel = 0;
  snw_stream_t *stream = 0;
  uint32_t streamid = 0;
  uint32_t channelid = 0;
  const char *str = 0;
  int is_new = 0;
  
  //Step1: get stream id from a pool.
  streamid = snw_set_getid(ctx->stream_mgr);
  if (streamid == 0) {
     ERROR(log, "can not get stream, flowid=%u", flowid);
     return -1;
  }

  DEBUG(log, "get new stream, streamid=%u, is_new=%u, flowid=%u", streamid, is_new, flowid);
  stream = snw_stream_get(ctx->stream_cache,streamid,&is_new);
  if (!stream || !is_new) {
    ERROR(log, "no new stream, streamid=%u, is_new=%u, flowid=%u", streamid, is_new, flowid);
    return -2;
  }
  stream->flowid = flowid;

  //Step2: get channel object.
  channelid = snw_json_msg_get_int(jobj,"channelid");
  channel = snw_channel_search(ctx->channel_cache,channelid);
  if (channel == 0) {
     ERROR(log, "channel not found, channelid=%u, flowid=%u", channelid, flowid);
     return -1;
  }


  //TODO: move to sig_connect_msg
  DEBUG(log, "add stream to channel, idx=%u, streamid=%u, channelid=%u", 
      channel->streams.idx, streamid, channelid);

  snw_list_add_item(&channel->streams,streamid);
  stream->channelid = channelid;
     
  DEBUG(log,"create a stream, streamid=%u, channelid=%u", streamid, channelid);

  json_object_object_add(jobj,"streamid",json_object_new_int(streamid));
  json_object_object_add(jobj,"flowid",json_object_new_int(flowid));
  json_object_object_add(jobj,"rc",json_object_new_int(0));
  str = snw_json_msg_to_string(jobj);
  if (!str) return -1;
  snw_shmmq_enqueue(ctx->net_task->req_mq,0,str,strlen(str),flowid);

  return 0;
}

int
snw_channel_handler(snw_context_t *ctx, snw_connection_t *conn, json_object *jobj) {
  snw_log_t *log = ctx->log;
  uint32_t flowid = conn->flowid;
  uint32_t api = 0;

  api = snw_json_msg_get_int(jobj,"api");
  switch(api) {
    case SNW_CHANNEL_CONNECT:
        snw_channel_connect_msg(ctx,jobj,0,flowid);
        break;
    case SNW_CHANNEL_DISCONNECT:
        break;
    case SNW_CHANNEL_CREATE_STREAM:
        snw_channel_create_stream_msg(ctx,jobj,0,flowid);
        break;
    default:
        DEBUG(log, "unknown api, api=%u", api);
        break;
  }


  return 0;
}

int
snw_module_handler(snw_context_t *ctx, snw_connection_t *conn, uint32_t type, char *data, uint32_t len) {
   snw_module_t *m = 0;

   LIST_FOREACH(m,&ctx->modules,list) {
      if (m->type == type) {
         m->methods->handle_msg(m,conn,data,len);
      }
   }

   return 0;
}

int
snw_core_process_msg(snw_context_t *ctx, snw_connection_t *conn, char *data, uint32_t len) {
   snw_log_t *log = ctx->log;
   json_object *jobj = 0;
   uint32_t msgtype = 0;

   jobj = json_tokener_parse(data);
   if (!jobj) {
      ERROR(log,"error json format, s=%s",data);
      return -1;
   }

   DEBUG(log,"core handler parsed json: %s",
         json_object_to_json_string_ext(
           jobj, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));

   msgtype = snw_json_msg_get_int(jobj,"msgtype");
   if (msgtype != SNW_ICE && msgtype != SNW_SIG && msgtype != SNW_CHANNEL) {
      ERROR(log, "wrong msg, msgtype=%u data=%s", msgtype, data);
      goto done;
   }

   switch(msgtype) {
      case SNW_ICE:
         snw_ice_handler(ctx,conn,msgtype,data,len);
         break;
      case SNW_SIG:
         snw_sig_handler(ctx,conn,jobj);
         break;
      case SNW_CHANNEL:
         snw_channel_handler(ctx,conn,jobj);
         break;
      default:
         snw_module_handler(ctx,conn,msgtype,data,len);
         break;
   }

done:
   json_object_put(jobj);
   return 0;
}

int
snw_core_connect(snw_context_t *ctx, snw_connection_t *conn) {

   //TODO: handle connect activity etc
   //      for example, limit connections per ip
   return 0;
}

void
snw_core_disconnect_stream(snw_context_t *ctx, snw_stream_t *stream) {
  snw_log_t *log = ctx->log;
  json_object *req = json_object_new_object();
  const char *str = 0;
     
  if (!stream || !req) return;

  json_object_object_add(req,"msgtype",json_object_new_int(SNW_ICE));
  json_object_object_add(req,"api",json_object_new_int(SNW_ICE_STOP));
  json_object_object_add(req,"channelid",json_object_new_int(stream->channelid));
  json_object_object_add(req,"streamid",json_object_new_int(stream->id));
  str = snw_json_msg_to_string(req);
  if (!str) {
    json_object_put(req);
    return;
  }
  DEBUG(log, "send event to ice streamid=%u, flowid=%u, s=%s", 
      stream->id, stream->flowid, str);

  snw_shmmq_enqueue(ctx->ice_task->req_mq,0,str, strlen(str),stream->flowid);

  json_object_put(req);
  snw_stream_remove(ctx->stream_cache, stream);
  return;
}

int
snw_core_disconnect(snw_context_t *ctx, snw_connection_t *connection) {
   snw_log_t *log = ctx->log;
   const char *str = 0;
   snw_conn_t *conn = 0;
   uint32_t channelid = 0;
   uint32_t flowid = 0;
   snw_channel_t *channel = 0;
   json_object *jobj = 0;
   json_object *jarray = 0;
   int i = 0;
   int found_deleted_streams = 0;

   flowid = connection->flowid;
   conn = snw_conn_search(ctx->conn_cache, connection->flowid);
   if (!conn) {
     ERROR(log,"conn not found, flowid=%u", flowid);
     return -1;
   }

   DEBUG(log,"connection found, flowid=%u, peer_flowid=%u",
       conn->flowid, conn->flowid);

   channelid = conn->channelid;
   channel = snw_channel_search(ctx->channel_cache, channelid);
   if (!channel) {
      WARN(log, "channel not found, channelid=%u", channelid);
      return 0;
   }

   DEBUG(log,"channel found, flowid=%u, channelid=%u",
      conn->flowid, channelid);
   
   jarray = json_object_new_array();
   if ( !jarray) {
     ERROR(log, "cannot alloc json object");
     return -1;
   }

   for (i=0; i<channel->streams.idx; i++) {
     snw_stream_t *s = 0;
     DEBUG(log,"check stream, streamid=%u", channel->streams.list[i]);
     s = snw_stream_search(ctx->stream_cache,channel->streams.list[i]);
     if (!s) {
       DEBUG(log,"stream not found, streamid=%u", channel->streams.list[i]);
       continue;
     }

     if (s->flowid == conn->flowid) {
       json_object *jitem = 0;

       if (s->type != STREAM_TYPE_PUBLISHER) {
         snw_core_disconnect_stream(ctx,s);
         continue;
       }

       found_deleted_streams = 1;
       jitem = json_object_new_object();
       if (!jitem) {
         if (jarray) json_object_put(jarray);
         ERROR(log, "cannot alloc json object");
         return -3;
       }

       json_object_object_add(jitem,"streamid",json_object_new_int(s->id));
       json_object_array_add(jarray, jitem);
       snw_core_disconnect_stream(ctx,s);
     }
   }


   if (found_deleted_streams) {
     jobj = json_object_new_object();
     if (!jobj) {
       if (jarray) json_object_put(jarray);
       ERROR(log, "cannot alloc json object");
       return -3;
     }
     json_object_object_add(jobj,"msgtype",json_object_new_int(SNW_EVENT));
     json_object_object_add(jobj,"api",json_object_new_int(SNW_EVENT_REMOVE_STREAM));
     json_object_object_add(jobj,"channelid",json_object_new_int(channel->id));

     json_object_object_add(jobj,"streams",jarray);

     str = snw_json_msg_to_string(jobj);
     if (!str) {
       json_object_put(jobj);
       return -2;
     }

     snw_channel_delete_flow(ctx,channel,flowid);
     for (i=0; i < channel->lastidx; i++) {
       snw_shmmq_enqueue(ctx->net_task->req_mq,0,str,strlen(str),channel->flows[i]);
     }
   } else {
     snw_channel_delete_flow(ctx,channel,flowid);
     if (jarray) json_object_put(jarray);
   }

   snw_conn_remove(ctx->conn_cache, conn);

   return 0;
}

int
snw_net_preprocess_msg(snw_context_t *ctx, char *buffer, uint32_t len, uint32_t flowid) {
   snw_event_t* header = (snw_event_t*) buffer; 
   snw_log_t *log = (snw_log_t*)ctx->log;
   snw_connection_t conn;

   ctx->cur_time = time(0);

   if (len < SNW_EVENT_HEADER_LEN) {
      ERROR(log, "msg too small, len=%u,flowid=%u",len,flowid);
      return -1;
   }

   if (header->magic_num != SNW_EVENT_MAGIC_NUM) {        
      ERROR(log, "no event header, len=%u,flowid=%u, magic=%u",
            len,flowid,header->magic_num);
      return -2;
   }    

   memset(&conn, 0, sizeof(conn));
   conn.flowid = flowid;
   conn.srctype = WSS_SOCKET_UDP;
   conn.port = header->port;
   conn.ipaddr = header->ipaddr;

   if(header->event_type == snw_ev_connect) {     
      snw_core_connect(ctx,&conn);
      return 0;
   }    

   if(header->event_type == snw_ev_disconnect) {     
      snw_core_disconnect(ctx,&conn);
      return 0;
   }

   DEBUG(log, "get msg, srctype: %u, ip: %s, port: %u, flow: %u, data_len: %u, msg_len: %u",
       conn.srctype,
       ip_to_str(conn.ipaddr),
       conn.port,
       conn.flowid,
       len,
       len - sizeof(snw_event_t));

   snw_core_process_msg(ctx,&conn,buffer+sizeof(snw_event_t),len-sizeof(snw_event_t));
   return 0;
}

int
snw_process_msg_from_ice(snw_context_t *ctx, char *buffer, uint32_t len, uint32_t flowid) {

   snw_shmmq_enqueue(ctx->net_task->req_mq, 0, buffer, len, flowid);
   return 0;
}

int
snw_process_http_create_req(snw_context_t *ctx, void *data, uint32_t len, uint32_t flowid) {
  snw_log_t *log = ctx->log;
  json_object *jobj = (json_object*)data;
  const char *str = 0;
  const char *roomname = 0;
  snw_roominfo_t *room = 0;
  snw_channel_t *channel = 0;
  uint32_t channelid;
  uint32_t channel_type;
  int is_new = 0;
  int ret = -1;

  roomname = snw_json_msg_get_string(jobj,"name");
  channel_type = snw_json_msg_get_int(jobj,"type");
  if (!roomname || channel_type == (uint32_t)-1) {
    goto error;
  }

  if ( !((channel_type == SNW_LIVE_CHANNEL_TYPE)
       || (channel_type == SNW_CALL_CHANNEL_TYPE)
       || (channel_type == SNW_CONF_CHANNEL_TYPE)) ) {
    ERROR(log, "unknown channel type: %u", channel_type);
    goto error;
  }

  /*if (!strncmp(type_str,"broadcast",9)) {
    channel_type = SNW_LIVE_CHANNEL_TYPE;
  } else
  if (!strncmp(type_str,"call",4)) {
    channel_type = SNW_CALL_CHANNEL_TYPE;
  } else
  if (!strncmp(type_str,"conference",10)) {
    channel_type = SNW_CONF_CHANNEL_TYPE;
  } else {
    ERROR(log, "unknow channel type: %s", type_str);
    goto error;
  }*/

  DEBUG(log,"create channel with name, name=%s",roomname);
  room = snw_roominfo_get(ctx->roominfo_cache,
    roomname,strlen(roomname),&is_new);
  if (!room) {
    ERROR(log,"failed to get room name, s=%s",roomname);
    return -4;
  }

  if (is_new) {
    channelid = snw_set_getid(ctx->channel_mgr);
    if (channelid == 0) {
      snw_roominfo_remove(ctx->roominfo_cache, room);
      return -5;
    }
    is_new = 0;
    channel = snw_channel_get(ctx->channel_cache,channelid,&is_new);
    if (!channel) {
      snw_roominfo_remove(ctx->roominfo_cache, room);
      return -6;
    }
    memcpy(channel->name,room->name,ROOM_NAME_LEN);
    channel->type = channel_type;
    room->channelid = channelid;
    DEBUG(log,"create channelid, is_new=%u, name=%s", is_new, roomname);
    json_object_object_add(jobj,"channelid",json_object_new_int(room->channelid));
    json_object_object_add(jobj,"rc",json_object_new_int(0));
    str = snw_json_msg_to_string(jobj);
  } else {
    WARN(log,"room exists, is_new=%u, name=%s", is_new, roomname);
    json_object_object_add(jobj,"channelid",json_object_new_int(room->channelid));
    json_object_object_add(jobj,"rc",json_object_new_int(0));
    str = snw_json_msg_to_string(jobj);
  }

  if (!str) goto error;
  snw_shmmq_enqueue(ctx->http_task->req_mq, 0, str, strlen(str), flowid);
  ret = 0;

error:
  return ret;
}

int
snw_process_http_delete_req(snw_context_t *ctx, void *data, uint32_t len, uint32_t flowid) {
  snw_log_t *log = ctx->log;
  json_object *jobj = (json_object*)data;
  snw_channel_t *channel = 0;
  snw_roominfo_t *room = 0;
  char buff[64] = {0};
  const char *str = 0;
  uint32_t channelid = 0;

  channelid = snw_json_msg_get_int(jobj,"channelid");
  channel = snw_channel_search(ctx->channel_cache,channelid);
  if (!channel) {
    snprintf(buff,64,"channel not found, channelid=%u", channelid);
    json_object_object_add(jobj,"errmsg",json_object_new_string(buff));
    json_object_object_add(jobj,"rc",json_object_new_int(-1));
    str = snw_json_msg_to_string(jobj);
    if (str)
      snw_shmmq_enqueue(ctx->http_task->req_mq, 0, str, strlen(str), flowid);
    return 0;
  }

  //TODO: notify channel removal

  room = snw_roominfo_search(ctx->roominfo_cache,
    channel->name,strlen(channel->name));
  if (!room) {
    WARN(log,"failed to get room name, s=%s",channel->name);
  } else {
    snw_roominfo_remove(ctx->roominfo_cache, room);
  }

  DEBUG(log,"remove channel, channelid=%u",channelid);
  snw_channel_remove(ctx->channel_cache,channel);

  json_object_object_add(jobj,"rc",json_object_new_int(0));
  str = snw_json_msg_to_string(jobj);
  if (!str) return -1;
  snw_shmmq_enqueue(ctx->http_task->req_mq, 0, str, strlen(str), flowid);
  return 0;
}

int
snw_process_http_query_req(snw_context_t *ctx, void *data, uint32_t len, uint32_t flowid) {
  snw_log_t *log = ctx->log;
  json_object *jobj = (json_object*)data;
  snw_roominfo_t *room = 0;
  snw_channel_t *channel = 0;
  const char *str = 0;
  const char *roomname = 0;
  uint32_t channelid = 0;
  int roomlen = 0;

  roomname = snw_json_msg_get_string(jobj,"name");
  channelid = snw_json_msg_get_int(jobj,"channelid");

  DEBUG(log,"query room, channelid=%d, name=%s",channelid, roomname);

  if (channelid != (uint32_t)-1) {
    char buff[64] = {0};
    DEBUG(log,"search channel, channelid=%u, name=%s",channelid, roomname);
    channel = snw_channel_search(ctx->channel_cache,channelid);
    if (!channel) {
      DEBUG(log,"not found channel, channelid=%u, name=%s",channelid, roomname);
      snprintf(buff,64,"channel not found, channelid=%u", channelid);
      json_object_object_add(jobj,"errmsg",json_object_new_string(buff));
      json_object_object_add(jobj,"rc",json_object_new_int(-1));
      str = snw_json_msg_to_string(jobj);
    } else if (roomname) {
      roomlen = strlen(roomname) > ROOM_NAME_LEN ? ROOM_NAME_LEN : strlen(roomname);
      if (!strncmp(channel->name,roomname,roomlen)) {
        //id and name match
        DEBUG(log,"found channel, channelid=%u, name=%s",channelid, roomname);
        json_object_object_add(jobj,"rc",json_object_new_int(0));
        str = snw_json_msg_to_string(jobj);
      } else {
        WARN(log,"name %s does not match channel name=%s", roomname,channel->name);
        snprintf(buff,64,"room mismatch, req_name=%s, name=%s", roomname,channel->name);
        json_object_object_add(jobj,"errmsg",json_object_new_string(buff));
        json_object_object_add(jobj,"rc",json_object_new_int(-1));
        str = snw_json_msg_to_string(jobj);
      }
    } else {
      //fill room name
      json_object_object_add(jobj,"name",json_object_new_string(channel->name));
      json_object_object_add(jobj,"rc",json_object_new_int(0));
      str = snw_json_msg_to_string(jobj);
   }
  } else if (roomname != 0) {
    //no channel in req
    room = snw_roominfo_search(ctx->roominfo_cache, roomname,strlen(roomname));
    json_object_object_add(jobj,"channelid",json_object_new_int(room->channelid));
    json_object_object_add(jobj,"rc",json_object_new_int(0));
    str = snw_json_msg_to_string(jobj);
  } else {
    //no channel id or name available in req
    json_object_object_add(jobj,"errmsg",json_object_new_string("channel not found"));
    json_object_object_add(jobj,"rc",json_object_new_int(-1));
    str = snw_json_msg_to_string(jobj);
  }

  if (!str) return -1;
  snw_shmmq_enqueue(ctx->http_task->req_mq, 0, str, strlen(str), flowid);
  return 0;
}

int
snw_process_msg_from_http(snw_context_t *ctx, char *data, uint32_t len, uint32_t flowid) {
   snw_log_t *log = ctx->log;
   json_object *jobj = 0;
   uint32_t msgtype = 0;
   uint32_t api = 0;

   jobj = json_tokener_parse(data);
   if (!jobj) {
      ERROR(log,"error json format, s=%s",data);
      return -1;
   }

   DEBUG(log,"http handler parsed json: %s",
         json_object_to_json_string_ext(
           jobj, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));

   msgtype = snw_json_msg_get_int(jobj,"msgtype");
   api = snw_json_msg_get_int(jobj,"api");
   if (msgtype == (uint32_t)-1 || api == (uint32_t)-1) {
     json_object_put(jobj);
     return -1;
   }

   if (msgtype != SNW_CHANNEL) {
     json_object_put(jobj);
     return -1;
   }

   switch(api) {
     case SNW_CHANNEL_CREATE:
       snw_process_http_create_req(ctx,jobj,0,flowid);
       break;
     case SNW_CHANNEL_DELETE:
       snw_process_http_delete_req(ctx,jobj,0,flowid);
       break;
     case SNW_CHANNEL_QUERY:
       snw_process_http_query_req(ctx,jobj,0,flowid);
       break;

     default:
       ERROR(log,"unknown http request, api=%u",api);
       break;
   }

   json_object_put(jobj);
   return 0;
}

void
snw_ice_msg(int fd, short int event,void* data) {
   static char buffer[MAX_BUFFER_SIZE];
   snw_context_t *ctx = (snw_context_t *)data;
   uint32_t len = 0;
   uint32_t flowid = 0;
   uint32_t cnt = 0;

#ifdef USE_ADAPTIVE_CONTROL
   while(true){
      len = 0; flowid = 0; cnt++;
      if ( cnt >= 10000) {
         DEBUG(ctx->log, "breaking the loop, cnt=%d", cnt);
         break;
      }
#endif
      snw_shmmq_dequeue(ctx->ice_task->resp_mq, buffer, MAX_BUFFER_SIZE, &len, &flowid);

      if (len == 0) return;

      DEBUG(ctx->log,"dequeue msg from ice, flowid=%u, len=%u, cnt=%d",
          flowid, len, cnt);
      buffer[len] = 0;
      snw_process_msg_from_ice(ctx,buffer,len,flowid);

#ifdef USE_ADAPTIVE_CONTROL
   }
#endif

   return;

}

void
snw_net_msg(int fd, short int event,void* data) {
   static char buffer[MAX_BUFFER_SIZE];
   snw_context_t *ctx = (snw_context_t *)data;
   uint32_t len = 0;
   uint32_t flowid = 0;
   uint32_t cnt = 0;

#ifdef USE_ADAPTIVE_CONTROL
   while(true){
      len = 0; flowid = 0; cnt++;
      if ( cnt >= 10000) {
         DEBUG(ctx->log, "breaking the loop, cnt=%d", cnt);
         break;
      }
#endif
      snw_shmmq_dequeue(ctx->net_task->resp_mq, buffer, MAX_BUFFER_SIZE, &len, &flowid);

      if (len == 0 || len >= MAX_BUFFER_SIZE) return;

      DEBUG(ctx->log,"dequeue msg from net, flowid=%u, len=%u, cnt=%d",
          flowid, len, cnt);
      buffer[len] = 0; // null-terminated string
      snw_net_preprocess_msg(ctx,buffer,len,flowid);

#ifdef USE_ADAPTIVE_CONTROL
   }
#endif

   return;
}

void
snw_http_msg(int fd, short int event,void* data) {
   static char buffer[MAX_BUFFER_SIZE];
   snw_context_t *ctx = (snw_context_t *)data;
   uint32_t len = 0;
   uint32_t flowid = 0;
   uint32_t cnt = 0;

#ifdef USE_ADAPTIVE_CONTROL
   while(true){
      len = 0; flowid = 0; cnt++;
      if ( cnt >= 10000) {
         DEBUG(ctx->log, "breaking the loop, cnt=%d", cnt);
         break;
      }
#endif
      snw_shmmq_dequeue(ctx->http_task->resp_mq, buffer, MAX_BUFFER_SIZE, &len, &flowid);
      if (len == 0) return;

      DEBUG(ctx->log,"dequeue msg from http, flowid=%u, len=%u, cnt=%d",
          flowid, len, cnt);
      buffer[len] = 0;
      snw_process_msg_from_http(ctx,buffer,len,flowid);

#ifdef USE_ADAPTIVE_CONTROL
   }
#endif

   return;
}

void
snw_main_process(snw_context_t *ctx) {

   if (ctx == 0) return;

   /*initialize main log*/
   ctx->log = snw_log_init(ctx->main_log_file, ctx->log_level,
       ctx->log_rotate_num, ctx->log_file_maxsize);
   if (ctx->log == 0) {
      exit(-1);   
   }

   snw_module_init(ctx);
   ctx->channel_cache = snw_channel_init();
   if (ctx->channel_cache == 0) {
      ERROR(ctx->log,"failed to init channel cache");
      return;
   }

   ctx->conn_cache = snw_conn_init();
   if (ctx->conn_cache == 0) {
      ERROR(ctx->log,"failed to init peer cache");
      return;
   }

   ctx->roominfo_cache = snw_roominfo_init();
   if (ctx->roominfo_cache == 0) {
      ERROR(ctx->log,"failed to init roominfo cache");
      return;
   }

   ctx->stream_cache = snw_stream_init();
   if (ctx->stream_cache == 0) {
      ERROR(ctx->log,"failed to init stream cache");
      return;
   }

   ctx->channel_mgr = snw_set_init(1100000, 10000);
   if (ctx->channel_mgr == 0) {
      ERROR(ctx->log,"failed to init channel set");
      return;
   }

   ctx->stream_mgr = snw_set_init(6408638, 10000);
   if (ctx->stream_mgr == 0) {
      ERROR(ctx->log,"failed to init stream set");
      return;
   }

   event_base_dispatch(ctx->ev_base);
   return;
}

void
snw_core_ice_cb(snw_task_ctx_t *task_ctx, void *data) {
  snw_context_t *ctx = (snw_context_t *)data;
  struct event *q_event;
   
  ctx->ice_task = task_ctx;   

  //TODO: create snw_task_register_callback(int type, callback)
  q_event = event_new(ctx->ev_base, task_ctx->resp_mq->pipe[0], 
    EV_TIMEOUT|EV_READ|EV_PERSIST, snw_ice_msg, ctx);
  event_add(q_event, NULL);
}

void
snw_core_net_cb(snw_task_ctx_t *task_ctx, void *data) {
  snw_context_t *ctx = (snw_context_t *)data;
  struct event *q_event;
   
  ctx->net_task = task_ctx;   

  //TODO: create snw_task_register_callback(int type, callback)
  q_event = event_new(ctx->ev_base, task_ctx->resp_mq->pipe[0], 
    EV_TIMEOUT|EV_READ|EV_PERSIST, snw_net_msg, ctx);
  event_add(q_event, NULL);
}

void
snw_core_http_cb(snw_task_ctx_t *task_ctx, void *data) {
  snw_context_t *ctx = (snw_context_t *)data;
  struct event *q_event;
   
  ctx->http_task = task_ctx;   

  //TODO: create snw_task_register_callback(int type, callback)
  q_event = event_new(ctx->ev_base, task_ctx->resp_mq->pipe[0],
    EV_TIMEOUT|EV_READ|EV_PERSIST, snw_http_msg, ctx);
  event_add(q_event, NULL);
}

void
print_help() {

   printf("usage: snowem <path-to-config_file>\n");

   return;
}

int
main(int argc, char** argv, char **envp) {
   snw_context_t *ctx;

   if (argc < 2) {
     print_help();
     exit(0);
   }

   setproctitle_init(argc,argv,envp);

   srand(time(NULL));
   ctx = snw_create_context();
   if (ctx == NULL) exit(-1);
   if (argc < 2) exit(-2);

   snw_config_init(ctx,argv[1]);

   ctx->ev_base = event_base_new();
   if (ctx->ev_base == 0) exit(-3);
   daemonize();

   snw_task_setup(ctx,CORE2ICE_KEY,ICE2CORE_KEY,SHAREDMEM_SIZE,
       snw_core_ice_cb, snw_ice_task_cb);

   snw_task_setup(ctx,CORE2NET_KEY,NET2CORE_KEY,SHAREDMEM_SIZE,
       snw_core_net_cb, snw_net_task_cb);

   snw_task_setup(ctx,CORE2HTTP_KEY,HTTP2CORE_KEY,SHAREDMEM_SIZE,
       snw_core_http_cb, snw_http_task_cb);

   setproctitle("master sig %s %s", argv[0], argv[1]);

   snw_main_process(ctx);

   return 0;
}

