
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <json/json.h>

#include "channel.h"
#include "conf.h"
#include "connection.h"
#include "core.h"
#include "http.h"
#include "log.h"
#include "module.h"
#include "peer.h"
#include "roominfo.h"
#include "snow.h"
#include "snw_event.h"
#include "task.h"
#include "utils.h"
#include "websocket/websocket.h"

int
snw_ice_handler(snw_context_t *ctx, snw_connection_t *conn, uint32_t type, char *data, uint32_t len) {

   snw_shmmq_enqueue(ctx->ice_task->req_mq, 0, data, len, conn->flowid);
   return 0;
}

int
snw_sig_auth_msg(snw_context_t *ctx, snw_connection_t *conn, Json::Value &root) {
   snw_log_t *log = ctx->log;
   snw_peer_t *peer = 0;
   Json::FastWriter writer;
   std::string output;
   std::string auth_data;
   uint32_t peerid = 0;
   int is_new = 0;
   
   try {
      auth_data = root["auth_data"].asString();
      DEBUG(log,"auth_data, s=%s", auth_data.c_str());

      //FIXME: send event to redis, and get id instead of using flowid.
      peerid = conn->flowid; 
      peer = snw_peer_get(ctx->peer_cache,peerid,&is_new);
      if (peer == 0) {
         ERROR(log, "can not create peer, flowid=%u", conn->flowid);
         return -1;
      }
      if (!is_new) {
         ERROR(log,"reseting existing peer, flowid=%u", conn->flowid);
         memset(peer,0,sizeof(snw_peer_t));
         peer->peerid = peerid;
      }
      peer->flowid = conn->flowid;
      SET_FLOW2PEER(conn->flowid,peerid);

      root["id"] = peer->peerid;
      root["rc"] = 0;
      output = writer.write(root);
      snw_shmmq_enqueue(ctx->net_task->req_mq,0,output.c_str(),output.size(),peer->flowid);
   } catch (...) {
      ERROR(log, "json format error");
      return -1;
   }
   return 0;
}

int
snw_sig_create_msg(snw_context_t *ctx, snw_connection_t *conn, Json::Value &root) {
   snw_log_t *log = ctx->log;
   Json::FastWriter writer;
   std::string output;
   snw_channel_t *channel = 0;
   snw_peer_t *peer = 0;
   uint32_t channelid = 0;
   std::string type_str;
   uint32_t channel_type = 0;
   uint32_t peerid = 0;
   int is_new = 0;
   
   try {
      peerid = root["id"].asUInt();
      peer = snw_peer_search(ctx->peer_cache,peerid);
      if (!peer) {
         ERROR(log, "peer not found, flowid=%u, peerid=%u", conn->flowid, peerid);
         return -1;
      }

      type_str = root["type"].asString();
      if (!strncmp(type_str.c_str(),"broadcast",9)) {
        channel_type = SNW_BCST_CHANNEL_TYPE;
      } else 
      if (!strncmp(type_str.c_str(),"call",4)) {
        channel_type = SNW_CALL_CHANNEL_TYPE;
      } else 
      if (!strncmp(type_str.c_str(),"conference",10)) {
        channel_type = SNW_CONF_CHANNEL_TYPE;
      } else {
        ERROR(log, "unknow channel type: %s", type_str.c_str());
        return -2;
      }

      //Step1: get channel id from a pool.
      channelid = snw_set_getid(ctx->channel_mgr);
      if (channelid == 0) {
         ERROR(log, "can not create channel, flowid=%u", conn->flowid);
         return -1;
      }

      //Step2: get channel object.
      channel = snw_channel_get(ctx->channel_cache,channelid,&is_new);
      if (channel == 0) {
         ERROR(log, "can not create channel, flowid=%u", conn->flowid);
         return -1;
      }
      if (!is_new) {
         ERROR(log,"reseting existing channel, channelid=%u",channelid);
         memset(channel,0,sizeof(snw_channel_t));
         channel->id = channelid;
      }
      channel->flowid = conn->flowid; //TODO: no need to have flowid
      channel->peerid = peer->peerid;
      channel->type = channel_type;
       
      DEBUG(log,"create channel, channelid=%u", channelid);
      root["channelid"] = channelid;
      root["rc"] = 0;
      output = writer.write(root);
      snw_shmmq_enqueue(ctx->net_task->req_mq,0,output.c_str(),
           output.size(),conn->flowid);

      //inform ice component about new channel
      root["msgtype"] = SNW_ICE;
      root["api"] = SNW_ICE_CREATE;
      output = writer.write(root);
      snw_shmmq_enqueue(ctx->ice_task->req_mq,0,output.c_str(),
            output.size(),conn->flowid);
   } catch (...) {
      ERROR(log, "json format error");
      return -1;
   }
   return 0;
}

int
snw_sig_connect_msg(snw_context_t *ctx, snw_connection_t *conn, Json::Value &root) {
   snw_log_t *log = ctx->log;
   Json::FastWriter writer;
   snw_peer_t *peer = 0;
   snw_channel_t *channel = 0;
   std::string output;
   std::string peer_type;
   uint32_t channelid = 0;
   uint32_t peerid = 0;
   int forward_to_ice = 0;
   
   try {
      peerid = root["id"].asUInt();
      channelid = root["channelid"].asUInt();
      peer_type = root["peer_type"].asString();
   } catch (...) {
      ERROR(log, "json format error");
      return -1;
   }

   channel = snw_channel_search(ctx->channel_cache,channelid);
   if (!channel) {
      ERROR(log, "channel not found, channelid=%u", channelid);
      return -1;
   }

   peer = snw_peer_search(ctx->peer_cache,peerid);
   if (!peer) {
      ERROR(log, "peer not found, peerid=%u", peerid);
      return -1;
   }

   if (!strncmp(peer_type.c_str(),"pub",3)) {
      peer->peer_type = PEER_TYPE_PUBLISHER;
      forward_to_ice = 1;
   } else if (!strncmp(peer_type.c_str(),"pla",3)) {
      peer->peer_type = PEER_TYPE_PLAYER;
      forward_to_ice = 1;
   } else if (!strncmp(peer_type.c_str(),"p2p",3)) {
      peer->peer_type = PEER_TYPE_P2P;
   } else {
      ERROR(log,"unknown peer type, flowid=%u, peer_type=%s",conn->flowid,peer_type.c_str());
      peer->peer_type = PEER_TYPE_UNKNOWN;
      return -2;
   }

   if (forward_to_ice) {
      //TODO: remove ice_connect from client request
   }

   if (channel->flowid != conn->flowid) {
     Json::Value notify;
     Json::FastWriter writer;
     std::string output;

     DEBUG(log,"notify peer joined event, flowid=%u",peer->flowid);
     notify["msgtype"] = SNW_EVENT;
     notify["api"] = SNW_EVENT_PEER_JOINED;
     notify["remoteid"] = peer->flowid;
     notify["peerid"] = channel->peerid;
     notify["channelid"] = channelid;
     notify["is_p2p"] = peer->peer_type == PEER_TYPE_P2P ? 1 : 0;
     output = writer.write(notify);
     snw_shmmq_enqueue(ctx->ice_task->req_mq,0,output.c_str(),output.size(),channel->flowid);
   }

   return 0;
}

int
snw_sig_call_msg(snw_context_t *ctx, snw_connection_t *conn, Json::Value &root) {
   snw_log_t *log = ctx->log;
   Json::FastWriter writer;
   std::string output;
   std::string peer_type;
   uint32_t peerid = 0;
   
   try {
      peerid = root["remoteid"].asUInt();

      //TODO: verify peer in channel
      //channelid = root["channelid"].asUInt();
      
      output = writer.write(root);
      //FIXME: correct me, not ice2core!!!
      snw_shmmq_enqueue(ctx->ice_task->req_mq,0,output.c_str(),output.size(),peerid);
   } catch (...) {
      ERROR(log, "json format error");
   }

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
snw_sig_publish_subchannel(snw_context_t *ctx, snw_connection_t *conn,
    snw_channel_t *channel, Json::Value &root) {
  snw_log_t *log = ctx->log;
  uint32_t channelid = 0;
  int is_new = 0;
  snw_channel_t *subchannel = 0;
  Json::FastWriter writer;
  Json::Value req;
  std::string output;

  channelid = snw_set_getid(ctx->channel_mgr);
  if (channelid == 0) {
    ERROR(log, "can not create channel, flowid=%u", conn->flowid);
    return -1;
  }

  subchannel = snw_channel_get(ctx->channel_cache,channelid,&is_new);
  if (channel == 0) {
    ERROR(log, "can not create channel, flowid=%u", conn->flowid);
    return -2;
  }
  if (!is_new) {
    ERROR(log,"reseting existing channel, channelid=%u",channelid);
    memset(channel,0,sizeof(snw_channel_t));
    subchannel->id = channelid;
    return -3;
  }
  subchannel->flowid = channel->flowid;
  subchannel->peerid = channel->peerid;
  subchannel->parentid = channel->id;
  subchannel->type = SNW_BCST_CHANNEL_TYPE;
  snw_sig_add_subchannel(channel, conn->flowid, channelid);

  //inform ice component about new channel
  //FIXME: this will generate resp msg to client, need a way to distinguish it from
  //       normal case.
  req["msgtype"] = SNW_ICE;
  req["api"] = SNW_ICE_CREATE;
  req["channelid"] = channelid;
  output = writer.write(req);
  snw_shmmq_enqueue(ctx->ice_task->req_mq,0,output.c_str(),
        output.size(),conn->flowid);

  // publish subchannel
  req["api"] = SNW_ICE_PUBLISH;
  output = writer.write(req);
  snw_shmmq_enqueue(ctx->ice_task->req_mq,0,output.c_str(),
        output.size(),conn->flowid);

  return channelid;
}

void
snw_sig_broadcast_new_subchannel(snw_context_t *ctx, 
    uint32_t channelid, uint32_t subchannelid, uint32_t flowid) {
  snw_log_t *log = ctx->log;
  snw_channel_t *channel = 0;
  Json::Value req;
  Json::FastWriter writer;
  std::string output;

  channel = snw_channel_search(ctx->channel_cache,channelid);
  if (!channel) {
    ERROR(log, "channel not found, channelid=%u", channelid);
    return;
  }

  req["msgtype"] = SNW_EVENT;
  req["api"] = SNW_EVENT_ADD_SUBCHANNEL;
  req["peerid"] = flowid;
  req["channelid"] = channelid;
  req["subchannelid"] = subchannelid;
  output = writer.write(req);
  DEBUG(log, "send event of new subchannel to peer,"
      " scid=%u, flowid=%u, s=%s", 
      subchannelid, flowid, output.c_str());

  for (int i=0; i<channel->idx; i++) {
    snw_shmmq_enqueue(ctx->net_task->req_mq,0,output.c_str(),
      output.size(),channel->peers[i]);
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

  if (channel->idx >= SNW_CORE_CHANNEL_USER_NUM_MAX) {
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
snw_sig_publish_msg(snw_context_t *ctx, snw_connection_t *conn,
    Json::Value &root) {
  snw_log_t *log = ctx->log;
  Json::FastWriter writer;
  std::string output;
  uint32_t channelid = 0;
  uint32_t sub_channelid = 0;
  snw_channel_t *channel = 0;
  uint32_t peerid = 0;
  snw_peer_t *peer = 0;

   try {

     peerid = root["id"].asUInt();
     peer = snw_peer_search(ctx->peer_cache, peerid);
     if (!peer) {
       ERROR(log,"peer not found, flowid=%u, peerid=%u", conn->flowid, peerid);
       return -1;
     }

     channelid = root["channelid"].asUInt();
     snw_core_channel_add_peer(ctx,channelid,conn->flowid);

     channel = snw_channel_search(ctx->channel_cache,channelid);
     if (!channel) {
       ERROR(log, "channel not found, channelid=%u", channelid);
       return -1;
     }
     DEBUG(log,"publish req, flowid=%u, channelid=%u, type=%u",
       conn->flowid, channelid, channel->type);

     if (channel->type == SNW_CONF_CHANNEL_TYPE) {
       sub_channelid = snw_sig_publish_subchannel(ctx, conn, channel, root);
       snw_sig_broadcast_new_subchannel(ctx,channelid,sub_channelid,conn->flowid);
       peer->peer_type = PEER_TYPE_PUBLISHER;
       peer->channelid = sub_channelid;

       //response with list of published streams in the channel
       root["subchannels"] = Json::Value(Json::arrayValue);
       for (int i=0; i < SNW_SUBCHANNEL_NUM_MAX; i++) {
         Json::Value item;
         if (channel->subchannels[i].channelid != 0) {
           DEBUG(log,"subchannel info: pid=%u, cid=%u", 
             channel->subchannels[i].peerid, channel->subchannels[i].channelid);
           item["peerid"] = channel->subchannels[i].peerid;
           item["subchannelid"] = channel->subchannels[i].channelid;
           root["subchannels"].append(item);
         }
       }
       root["rc"] = 0;
       output = writer.write(root);
       snw_shmmq_enqueue(ctx->net_task->req_mq,0,output.c_str(),
            output.size(),conn->flowid);
       return 0;
     }

     if (channel->type != SNW_CALL_CHANNEL_TYPE
         && channel->type != SNW_BCST_CHANNEL_TYPE) {
       ERROR(log, "unknow channel type, type=%u", channel->type);
       return -2;
     }

     root["msgtype"] = SNW_ICE;
     root["api"] = SNW_ICE_PUBLISH;
     output = writer.write(root);
     snw_shmmq_enqueue(ctx->ice_task->req_mq,0,output.c_str(),output.size(),conn->flowid);
   } catch (...) {
     ERROR(log, "json format error");
   }

   return 0;
}

int
snw_sig_play_msg(snw_context_t *ctx, snw_connection_t *conn, Json::Value &root) {
   snw_log_t *log = ctx->log;
   Json::FastWriter writer;
   std::string output;
   uint32_t channelid = 0;
   uint32_t peerid = 0;
   snw_peer_t *peer = 0;

   try {
     peerid = root["id"].asUInt();
     peer = snw_peer_search(ctx->peer_cache, peerid);
     if (!peer) {
       ERROR(log,"peer not found, flowid=%u, peerid=%u", conn->flowid, peerid);
       return -1;
     }
     peer->peer_type = PEER_TYPE_PLAYER;
     peer->channelid = channelid;

     channelid = root["channelid"].asUInt();
     snw_core_channel_add_peer(ctx, channelid, conn->flowid);

     DEBUG(log,"play req, flowid=%u, channelid=%u",
       conn->flowid, channelid);

     root["msgtype"] = SNW_ICE;
     root["api"] = SNW_ICE_PLAY;
     output = writer.write(root);
     snw_shmmq_enqueue(ctx->ice_task->req_mq,0,output.c_str(),output.size(),conn->flowid);

   } catch (...) {
     ERROR(log, "json format error");
   }

   return 0;
}

int
snw_sig_sdp_msg(snw_context_t *ctx, snw_connection_t *conn, Json::Value &root) {
   snw_log_t *log = ctx->log;
   Json::FastWriter writer;
   std::string output;
   uint32_t remoteid = 0;
   
   try {
      remoteid = root["remoteid"].asUInt();
      output = writer.write(root);
      snw_shmmq_enqueue(ctx->net_task->req_mq,0,output.c_str(),output.size(),remoteid);
   } catch (...) {
      ERROR(log, "json format error");
      return -1;
   }
   return 0;
}

int
snw_sig_candidate_msg(snw_context_t *ctx, snw_connection_t *conn, Json::Value &root) {
   snw_log_t *log = ctx->log;
   Json::FastWriter writer;
   std::string output;
   uint32_t remoteid = 0;
   
   try {
      remoteid = root["remoteid"].asUInt();
      output = writer.write(root);
      snw_shmmq_enqueue(ctx->net_task->req_mq,0,output.c_str(),output.size(),remoteid);
   } catch (...) {
      ERROR(log, "json format error");
      return -1;
   }
   return 0;
}

int
snw_sig_handler(snw_context_t *ctx, snw_connection_t *conn, Json::Value &root) {
   snw_log_t *log = ctx->log;
   uint32_t api = 0;

   try {
      api = root["api"].asUInt();
      DEBUG(log, "sig handler, flowid=%u, api=%u", conn->flowid, api);
      switch(api) {
         case SNW_SIG_AUTH:
            snw_sig_auth_msg(ctx,conn,root);
            break;
         case SNW_SIG_CREATE:
            snw_sig_create_msg(ctx,conn,root);
            break;
         case SNW_SIG_CONNECT:
            snw_sig_connect_msg(ctx,conn,root);
            break;
         case SNW_SIG_CALL:
            snw_sig_call_msg(ctx,conn,root);
            break;
         case SNW_SIG_PUBLISH:
            snw_sig_publish_msg(ctx,conn,root);
            break;
         case SNW_SIG_PLAY:
            snw_sig_play_msg(ctx,conn,root);
            break;
         case SNW_SIG_SDP:
            snw_sig_sdp_msg(ctx,conn,root);
            break;
         case SNW_SIG_CANDIDATE:
            snw_sig_candidate_msg(ctx,conn,root);
            break;
         default:
            DEBUG(log, "unknown api, api=%u", api);
            break;
      }
   } catch(...) {
      return -1;
   }

   return 0;
}

int
snw_module_handler(snw_context_t *ctx, snw_connection_t *conn, uint32_t type, char *data, uint32_t len) {
   struct list_head *p;
   
   list_for_each(p,&ctx->modules.list) {
      snw_module_t *m = list_entry(p,snw_module_t,list);
      if (m->type == type) {
         m->methods->handle_msg(m,conn,data,len);
      }
   }

   return 0;
}

int
snw_core_process_msg(snw_context_t *ctx, snw_connection_t *conn, char *data, uint32_t len) {
   snw_log_t *log = ctx->log;
   Json::Value root;
   Json::Reader reader;
   uint32_t msgtype = 0;
   //uint32_t api = 0;
   int ret;

   ret = reader.parse(data,data+len,root,0);
   if (!ret) {
      ERROR(log,"error json format, data=%s",data);
      return -1;
   }

   try {
      msgtype = root["msgtype"].asUInt();
      //api = root["api"].asUInt();

      switch(msgtype) {
         case SNW_ICE:
            snw_ice_handler(ctx,conn,msgtype,data,len);
            break;

         case SNW_SIG:
            snw_sig_handler(ctx,conn,root);
            break;

         default:
            snw_module_handler(ctx,conn,msgtype,data,len);
            break;
      }
      
   } catch (...) {
      ERROR(log, "json format error, data=%s", data);
   }

   return 0;
}

int
snw_core_connect(snw_context_t *ctx, snw_connection_t *conn) {

   //TODO: handle connect activity etc
   //      for example, limit connections per ip
   return 0;
}

int
snw_core_disconnect(snw_context_t *ctx, snw_connection_t *conn) {
   snw_log_t *log = ctx->log;
   Json::Value root;
   Json::FastWriter writer;
   std::string output;
   uint32_t peerid;
   snw_peer_t *peer = 0;
   uint32_t channelid = 0;
   snw_channel_t *channel = 0;
   snw_channel_t *pchannel = 0;

   try {
     root["msgtype"] = SNW_ICE;
     root["api"] = SNW_ICE_STOP;
     root["id"] = conn->flowid;
     output = writer.write(root);
     snw_shmmq_enqueue(ctx->ice_task->req_mq,0,output.c_str(),output.size(),conn->flowid);
   } catch(...) {
     ERROR(log,"failed to send req to ice");
   }

   peerid = GET_FLOW2PEER(conn->flowid);
   peer = snw_peer_search(ctx->peer_cache, peerid);
   if (!peer) {
     ERROR(log,"peer not found, peerid=%u",peerid);
     return -1;
   }

   if (peer->peer_type != PEER_TYPE_PUBLISHER) {
     snw_peer_remove(ctx->peer_cache, peer);
     return 0;
   }

   channelid = peer->channelid;
   snw_peer_remove(ctx->peer_cache, peer);

   channel = snw_channel_search(ctx->channel_cache, channelid);
   if (!channel) {
      WARN(log, "channel not found, channelid=%u", channelid);
      return 0;
   }

   if (channel->type == SNW_BCST_CHANNEL_TYPE) {
     // send event to subscriber
     Json::Value req;
     Json::FastWriter writer;
     std::string output;

     req["msgtype"] = SNW_EVENT;
     req["api"] = SNW_EVENT_DEL_SUBCHANNEL;
     req["peerid"] = conn->flowid;
     req["channelid"] = channel->parentid;
     req["subchannelid"] = channel->id;
     output = writer.write(req);
     DEBUG(log, "send event of new subchannel to peer,"
        " scid=%u, flowid=%u, s=%s", channel->id, conn->flowid, output.c_str());

     for (int i=0; i<channel->idx; i++) {
       snw_shmmq_enqueue(ctx->net_task->req_mq,0,output.c_str(),
         output.size(),channel->peers[i]);
     }
     
     //update subchannel list of parent
     pchannel = snw_channel_search(ctx->channel_cache, channel->parentid);
     if (!pchannel) {
       WARN(log, "parent channel not found, channelid=%u", channel->parentid);
       return 0;
     }
     snw_sig_remove_subchannel(pchannel, peerid, channel->id);

     // FIXME: check and clean channel, need info from ice
     //snw_channel_remove(ctx->channel_cache, channel);
   } else
   if (channel->type == SNW_CONF_CHANNEL_TYPE) {
     // TODO: check and clean
   }

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
snw_process_msg_from_http(snw_context_t *ctx, char *data, uint32_t len, uint32_t flowid) {
   snw_log_t *log = ctx->log;
   Json::Value root;
   Json::Reader reader;
   Json::FastWriter writer;
   snw_roominfo_t *room = 0;
   snw_channel_t *channel = 0;
   uint32_t msgtype = 0;
   uint32_t api = 0;
   std::string roomname;
   std::string output;
   uint32_t channelid;
   std::string type_str;
   uint32_t channel_type;
   int is_new = 0;
   int ret;

   ret = reader.parse(data,data+len,root,0);
   if (!ret) {
      ERROR(log,"error json format, data=%s",data);
      return -1;
   }

   try {
      msgtype = root["msgtype"].asUInt();
      api = root["api"].asUInt();
      roomname = root["name"].asString();
      type_str = root["type"].asString();
      
   } catch (...) {
      ERROR(log, "json format error, data=%s", data);
      return -1;
   }

   if (msgtype != SNW_CHANNEL ||  api != SNW_CHANNEL_CREATE)
     return -2;

   if (!strncmp(type_str.c_str(),"broadcast",9)) {
     channel_type = SNW_BCST_CHANNEL_TYPE;
   } else 
   if (!strncmp(type_str.c_str(),"call",4)) {
     channel_type = SNW_CALL_CHANNEL_TYPE;
   } else 
   if (!strncmp(type_str.c_str(),"conference",10)) {
     channel_type = SNW_CONF_CHANNEL_TYPE;
   } else {
     ERROR(log, "unknow channel type: %s", type_str.c_str());
     return -2;
   }

   //handle create channel
   DEBUG(log,"create channel with name, name=%s",roomname.c_str());
   if (roomname.size() == 0)
     return -3;
   room = snw_roominfo_get(ctx->roominfo_cache,
     roomname.c_str(),roomname.size(),&is_new);
   if (!room) {
     ERROR(log,"failed to get room name, s=%s",roomname.c_str());
     return -4;
   }
   DEBUG(log,"create channelid, is_new=%u, name=%s", is_new, roomname.c_str());
   if (!is_new) goto done;

   channelid = snw_set_getid(ctx->channel_mgr);
   if (channelid == 0) {
     snw_roominfo_remove(ctx->roominfo_cache, room);
     return -5;
   }
   channel = snw_channel_get(ctx->channel_cache,channelid,&is_new);
   if (!channel) {
     snw_roominfo_remove(ctx->roominfo_cache, room);
     return -6;
   }
   memcpy(channel->name,room->name,ROOM_NAME_LEN);
   channel->type = channel_type;
   room->channelid = channelid;


done:
   root["channelid"] = room->channelid;
   root["rc"] = 0;
   output = writer.write(root);
   snw_shmmq_enqueue(ctx->http_task->req_mq, 0, 
   output.c_str(), output.size(), flowid);
 
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

   ctx->peer_cache = snw_peer_init();
   if (ctx->peer_cache == 0) {
      ERROR(ctx->log,"failed to init peer cache");
      return;
   }

   ctx->roominfo_cache = snw_roominfo_init();
   if (ctx->roominfo_cache == 0) {
      ERROR(ctx->log,"failed to init roominfo cache");
      return;
   }

   ctx->channel_mgr = snw_set_init(1100000, 10000);
   if (ctx->channel_mgr == 0) {
      ERROR(ctx->log,"failed to init channel set");
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

int
main(int argc, char** argv) {
   snw_context_t *ctx;

   //TODO: get arguments from cmd line.

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

   snw_main_process(ctx);

   return 0;
}

