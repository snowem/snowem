/*
 * (C) Copyright 2018 Jackie Dinh <jackiedinh8@gmail.com>
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

#include "core/bsd_queue.h"
#include "core/log.h"
#include "ice/dtls.h"
#include "ice/ice_component.h"
#include "ice/sctp.h"

void
snw_ice_sctp_handle_assoc_change(snw_ice_sctp_ctx_t *sctp, union sctp_notification *data) {
  snw_log_t *log = 0;
  struct sctp_assoc_change *e = &data->sn_assoc_change;

  if (!data || !sctp || !sctp->dtls || !sctp->dtls->ctx) return;
  log = sctp->dtls->ctx->log;

  DEBUG(log, "assoc change"); (void)e;
  //TODO: impl logic

  return;
}

void
snw_ice_sctp_handle_peer_address_change(snw_ice_sctp_ctx_t *sctp, union sctp_notification *data) {
  struct sctp_paddr_change *e = &data->sn_paddr_change;
  snw_log_t *log = 0;

  if (!data || !sctp || !sctp->dtls || !sctp->dtls->ctx) return;
  log = sctp->dtls->ctx->log;

  DEBUG(log, "peer addr change"); (void)e;
  //TODO: impl logic

  return;
}

void
snw_ice_sctp_handle_remote_error(snw_ice_sctp_ctx_t *sctp, union sctp_notification *data) {
  struct sctp_remote_error *e = &data->sn_remote_error;
  snw_log_t *log = 0;

  if (!sctp || !sctp->dtls || !sctp->dtls->ctx) return;
  log = sctp->dtls->ctx->log;

  DEBUG(log, "remote error"); (void)e;
  //TODO: impl logic

  return;
}

void
snw_ice_sctp_handle_shutdown_event(snw_ice_sctp_ctx_t *sctp, union sctp_notification *data) {
  struct sctp_shutdown_event *e = &data->sn_shutdown_event;
  snw_log_t *log = 0;

  if (!sctp || !sctp->dtls || !sctp->dtls->ctx) return;
  log = sctp->dtls->ctx->log;

  DEBUG(log, "Shutdown event"); (void)e;
  //TODO: impl logic

  return;
}

void
snw_ice_sctp_handle_adaptation_indication(snw_ice_sctp_ctx_t *sctp, union sctp_notification *data) {
  struct sctp_adaptation_event *e = &data->sn_adaptation_event;
  snw_log_t *log = 0;

  if(!sctp || !sctp->dtls || !sctp->dtls->ctx) return;
  log = sctp->dtls->ctx->log;

  DEBUG(log, "adaptation indication"); (void)e;
  //TODO: impl logic

  return;
}

void
snw_ice_sctp_handle_partial_delivery_event(snw_ice_sctp_ctx_t *sctp, union sctp_notification *data) {
  return;
}

void
snw_ice_sctp_handle_authentification_event(snw_ice_sctp_ctx_t *sctp, union sctp_notification *data) {
  return;
}

void
snw_ice_sctp_handle_stream_reset_event(snw_ice_sctp_ctx_t *sctp, union sctp_notification *data) {
  return;
}

void
snw_ice_sctp_handle_sender_dry_event(snw_ice_sctp_ctx_t *sctp, union sctp_notification *data) {
  return;
}

void
snw_ice_sctp_handle_notifications_stopped_event(snw_ice_sctp_ctx_t *sctp, union sctp_notification *data) {
  return;
}

void
snw_ice_sctp_handle_assoc_reset_event(snw_ice_sctp_ctx_t *sctp, union sctp_notification *data) {
  return;
}

void
snw_ice_sctp_handle_stream_change_event(snw_ice_sctp_ctx_t *sctp, union sctp_notification *data) {
  return;
}

void
snw_ice_sctp_handle_send_failed_event(snw_ice_sctp_ctx_t *sctp, union sctp_notification *data) {
  struct sctp_send_failed_event *e = &data->sn_send_failed_event;
  snw_log_t *log = 0;

  if (!sctp || !sctp->dtls || !sctp->dtls->ctx) return;
  log = sctp->dtls->ctx->log;

  DEBUG(log, "sender failed event"); (void)e;
  //TODO: impl logic

  return;
}

typedef struct snw_sctp_notification_handler snw_sctp_notification_handler_t;
struct snw_sctp_notification_handler {
   uint32_t         type;
   void             (*handler)(snw_ice_sctp_ctx_t *sctp, union sctp_notification *data);
};

snw_sctp_notification_handler_t g_notification_handlers[] = {
   {.type = SCTP_ASSOC_CHANGE, .handler = snw_ice_sctp_handle_assoc_change},
   {.type = SCTP_PEER_ADDR_CHANGE, .handler = snw_ice_sctp_handle_peer_address_change},
   {.type = SCTP_REMOTE_ERROR, .handler = snw_ice_sctp_handle_remote_error},
   {.type = SCTP_SHUTDOWN_EVENT, .handler = snw_ice_sctp_handle_shutdown_event},
   {.type = SCTP_ADAPTATION_INDICATION, .handler = snw_ice_sctp_handle_adaptation_indication},
   {.type = SCTP_PARTIAL_DELIVERY_EVENT, .handler = snw_ice_sctp_handle_partial_delivery_event},
   {.type = SCTP_AUTHENTICATION_EVENT, .handler = snw_ice_sctp_handle_authentification_event},
   {.type = SCTP_STREAM_RESET_EVENT, .handler = snw_ice_sctp_handle_stream_reset_event},
   {.type = SCTP_SENDER_DRY_EVENT, .handler = snw_ice_sctp_handle_sender_dry_event},
   {.type = SCTP_NOTIFICATIONS_STOPPED_EVENT, .handler = snw_ice_sctp_handle_notifications_stopped_event},
   {.type = SCTP_ASSOC_RESET_EVENT, .handler = snw_ice_sctp_handle_assoc_reset_event},
   {.type = SCTP_STREAM_CHANGE_EVENT, .handler = snw_ice_sctp_handle_stream_change_event},
   {.type = SCTP_SEND_FAILED_EVENT, .handler = snw_ice_sctp_handle_send_failed_event}
};

void
snw_ice_sctp_handle_notification(snw_ice_sctp_ctx_t *sctp, union sctp_notification *notification, size_t n) {
  snw_log_t *log = 0;
  int cnt = sizeof(g_notification_handlers)/sizeof(snw_sctp_notification_handler_t);
  int i = 0;

  if (!sctp || !sctp->dtls || !sctp->dtls->ctx) return;
  log = sctp->dtls->ctx->log;

  if (notification->sn_header.sn_length != (uint32_t)n) {
    ERROR(log, "corrupted notification");
    return;
  }

  for (i = 0; i < cnt; i++) {
    if (g_notification_handlers[i].type == notification->sn_header.sn_type 
        && !g_notification_handlers[i].handler)
      g_notification_handlers[i].handler(sctp, notification);
  }

  return;
}

int
snw_ice_sctp_send_open_ack_message(snw_ice_sctp_ctx_t *sctp, struct socket *sock, uint16_t stream) {
  snw_log_t *log = 0;
  snw_sctp_datachannel_ack_t ack;
  struct sctp_sndinfo info;

  if (!sock || !sctp || !sctp->dtls || !sctp->dtls->ctx) return 0;
  log = sctp->dtls->ctx->log;

  memset(&ack, 0, sizeof(snw_sctp_datachannel_ack_t));
  ack.msg_type = DATA_CHANNEL_ACK;

  memset(&info, 0, sizeof(struct sctp_sndinfo));
  info.snd_sid = stream;
  info.snd_flags = SCTP_EOR;
  info.snd_ppid = htonl(DATA_CHANNEL_PPID_CONTROL);

  if (usrsctp_sendv(sock, &ack, sizeof(snw_sctp_datachannel_ack_t),
                    0, 0, &info, (socklen_t)sizeof(struct sctp_sndinfo),
                    SCTP_SENDV_SNDINFO, 0) < 0) {
    ERROR(log, "usrsctp_sendv failed, errno=%d", errno);
    return -1;
  }
  DEBUG(log, "usrsctp_sendv ack succeeded, errno=%d", errno);

  return 0;
}

void
snw_ice_sctp_handle_open_request_message(snw_ice_sctp_ctx_t *sctp,
    snw_sctp_datachannel_open_request_t *req, size_t length, uint16_t streamid) {
  snw_log_t *log = 0;
  snw_sctp_channel_t *channel;

  if (!sctp || !sctp->dtls || !sctp->dtls->ctx) return;
  log = sctp->dtls->ctx->log;

  DEBUG(log, "handle open request message, streamid=%u", streamid);

  channel = &sctp->channel;
  if (channel->state == DATA_CHANNEL_OPEN) {
    ERROR(log, "channel is occupied");
    return;
  }

  channel->state = DATA_CHANNEL_CONNECTING;
  channel->pr_value = ntohs(req->reliability_params);
  channel->stream = streamid;
  channel->flags = 0;
  channel->unordered = 0;
  switch (req->channel_type) {
    case DATA_CHANNEL_RELIABLE:
      channel->pr_policy = SCTP_PR_SCTP_NONE;
      break;
    case DATA_CHANNEL_RELIABLE_UNORDERED:
      channel->pr_policy = SCTP_PR_SCTP_NONE;
      channel->unordered = 1;
      break;
    case DATA_CHANNEL_PARTIAL_RELIABLE_TIMED:
      channel->pr_policy = SCTP_PR_SCTP_TTL;
      break;
    case DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED:
      channel->pr_policy = SCTP_PR_SCTP_TTL;
      channel->unordered = 1;
      break;
    case DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT:
      channel->pr_policy = SCTP_PR_SCTP_RTX;
      channel->unordered = 1;
      break;
    case DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED:
      channel->pr_policy = SCTP_PR_SCTP_RTX;
      channel->unordered = 1;
      break;
    default:
      channel->pr_policy = SCTP_PR_SCTP_NONE;
      break;
  }

  DEBUG(log, "Opened channel, streamid=%u, unordered=%d, policy=%d, value=%d)",
    channel->stream, channel->unordered, channel->pr_policy, channel->pr_value);

  if (snw_ice_sctp_send_open_ack_message(sctp, sctp->sock, streamid) < 0) {
    if(errno == EAGAIN) {
      channel->flags |= DATA_CHANNEL_FLAGS_SEND_ACK;
    } else {
      channel->state = DATA_CHANNEL_CLOSED;
      channel->unordered = 0;
      channel->pr_policy = 0;
      channel->pr_value = 0;
      channel->stream = 0;
      channel->flags = 0;
    }
  }

  return;
}

int
snw_ice_sctp_send_text(snw_ice_sctp_ctx_t *sctp, char *buf, size_t len) {
  snw_log_t *log = 0;
  snw_sctp_channel_t *channel = 0;
  struct sctp_sendv_spa spa;

  if (!sctp || !sctp->dtls || !sctp->dtls->ctx || !buf || len <= 0)
    return -1;
  log = sctp->dtls->ctx->log;

  channel = &sctp->channel;
  if ((channel->state != DATA_CHANNEL_OPEN) && (channel->state != DATA_CHANNEL_CONNECTING)) {
    DEBUG(log, "invalid state, state=%d", channel->state);
    return -1;
  }

  memset(&spa, 0, sizeof(struct sctp_sendv_spa));
  spa.sendv_sndinfo.snd_sid = channel->stream;
  if ((channel->state == DATA_CHANNEL_OPEN) && (channel->unordered)) {
    spa.sendv_sndinfo.snd_flags = SCTP_EOR | SCTP_UNORDERED;
  } else {
    spa.sendv_sndinfo.snd_flags = SCTP_EOR;
  }
  spa.sendv_sndinfo.snd_ppid = htonl(DATA_CHANNEL_PPID_DOMSTRING);
  spa.sendv_flags = SCTP_SEND_SNDINFO_VALID;
  if ((channel->pr_policy == SCTP_PR_SCTP_TTL)
      || (channel->pr_policy == SCTP_PR_SCTP_RTX)) {
    spa.sendv_prinfo.pr_policy = channel->pr_policy;
    spa.sendv_prinfo.pr_value = channel->pr_value;
    spa.sendv_flags |= SCTP_SEND_PRINFO_VALID;
  }

  if (usrsctp_sendv(sctp->sock, buf, len, 0, 0,
      &spa, (socklen_t)sizeof(struct sctp_sendv_spa),
      SCTP_SENDV_SPA, 0) < 0) {
    DEBUG(log, "sctp_sendv error, errno=%d", errno);
    return -1;
  }

  return 0;
}

void
snw_ice_sctp_send_data(snw_ice_sctp_ctx_t *sctp, char *buf, int len) {
  snw_log_t *log = 0;

  if(!sctp || !sctp->dtls || !sctp->dtls->ctx || !buf || len <= 0) return;
  log = sctp->dtls->ctx->log;

  DEBUG(log, "SCTP data to send, len=%u", len);
  if (sctp->channel.state == DATA_CHANNEL_CLOSED) {
    ERROR(log, "invalid state to send data, state=%u", sctp->channel.state);
    return;
  }

  snw_ice_sctp_send_text(sctp, buf, len);
}

void
snw_ice_sctp_handle_data_message(snw_ice_sctp_ctx_t *sctp,
    char *buffer, size_t length, uint16_t stream) {
  snw_log_t *log = 0;
  snw_sctp_channel_t *channel = 0;

  if (!sctp || !sctp->dtls || !sctp->dtls->ctx
      || !buffer || length <= 0)
    return;
  log = sctp->dtls->ctx->log;

  channel = &sctp->channel;
  DEBUG(log, "handle sctp data message, length=%zu, state=%u", length, channel->state);

  if (channel->state == DATA_CHANNEL_CONNECTING) {
    channel->state = DATA_CHANNEL_OPEN;
  }

  if (channel->state != DATA_CHANNEL_OPEN) {
    ERROR(log, "no open channel for data from sctp stack");
    return;
  } else {
    dtls_notify_sctp_data(sctp->dtls, buffer, (int)length);
  }
  return;
}

void
snw_ice_sctp_handle_message(snw_ice_sctp_ctx_t *sctp, char *buf, size_t len,
    uint32_t ppid, uint16_t stream, int flags) {
  snw_log_t *log = 0;
  snw_sctp_datachannel_open_request_t *req;
  snw_sctp_datachannel_ack_t *msg;

  if(!sctp || !sctp->dtls || !sctp->dtls->ctx || !buf || len <= 0) return;
  log = sctp->dtls->ctx->log;

  DEBUG(log, "handle sctp msg, len=%ld, ppid=%u, streamid=%u", len, ppid, stream);

  switch (ppid) {
    case DATA_CHANNEL_PPID_CONTROL:
      DEBUG(log, "got channel ppid control");
      if(len < sizeof(snw_sctp_datachannel_ack_t)) {
        return;
      }
      msg = (snw_sctp_datachannel_ack_t *)buf;
      switch (msg->msg_type) {
        case DATA_CHANNEL_OPEN_REQUEST:
          if(len < sizeof(snw_sctp_datachannel_open_request_t)) {
            ERROR(log, "corrupted open request");
            return;
          }
          req = (snw_sctp_datachannel_open_request_t *)buf;
          snw_ice_sctp_handle_open_request_message(sctp, req, len, stream);
          break;
        case DATA_CHANNEL_OPEN_RESPONSE:
          DEBUG(log, "open response unhandled");
          break;
        case DATA_CHANNEL_ACK:
          DEBUG(log, "ack msg unhandled");
          break;
        default:
          ERROR(log, "unknown message, type=%u", msg->msg_type);
          break;
      }
      break;
    case DATA_CHANNEL_PPID_DOMSTRING:
    case DATA_CHANNEL_PPID_BINARY:
      snw_ice_sctp_handle_data_message(sctp, buf, len, stream);
      break;
    default:
      DEBUG(log, "message info, len=%u, ppid=%u, streamid=%u", len, ppid, stream);
      break;
  }

  return;
}

int
snw_ice_sctp_incoming_data(struct socket *sock, union sctp_sockstore addr,
    void *data, size_t datalen, struct sctp_rcvinfo rcv, int flags, void *user_data) {
  snw_ice_sctp_ctx_t *sctp = (snw_ice_sctp_ctx_t *)user_data;
  snw_log_t *log = 0;

  if(!sctp || !sctp->dtls || !sctp->dtls->ctx) return 0;
  log = sctp->dtls->ctx->log;

  DEBUG(log, "got incoming sctp data, len=%ld", datalen);

  if (data) {
    if (flags & MSG_NOTIFICATION) {
      snw_ice_sctp_handle_notification(sctp, (union sctp_notification *)data, datalen);
    } else {
      snw_ice_sctp_handle_message(sctp, data, datalen, ntohl(rcv.rcv_ppid), rcv.rcv_sid, flags);
    }
  }

  return 1;
}

int snw_ice_sctp_outcoming_data(void *user_data, void *buf, size_t len, uint8_t tos, uint8_t set_df) {
  snw_ice_sctp_ctx_t *sctp = (snw_ice_sctp_ctx_t *)user_data;
  snw_log_t *log = 0;

  if (!buf || !sctp || !sctp->dtls || !sctp->dtls->ctx || len <=0)
    return -1;
  log = sctp->dtls->ctx->log;

  DEBUG(log, "sending sctp data to dtls, len=%zu", len);
  dtls_send_sctp_outcoming_data(sctp->dtls, buf, len);

  return 0;
}

static snw_log_t *g_log = 0;
void debug_printf(const char *fmt, ...) {
   static char buffer[4*1024] = {0};
   va_list argptr;

   if (!g_log) return;

   va_start(argptr, fmt);
   vsnprintf(buffer, 4*1024, fmt, argptr);
   va_end(argptr);

   DEBUG(g_log,"%s", buffer);
}

int
snw_ice_sctp_init(snw_ice_context_t *ctx) {
  g_log = ctx->log;
  usrsctp_init_nothreads(0, snw_ice_sctp_outcoming_data, 0/*debug_printf*/);
  return 0;
}

void
snw_ice_sctp_deinit(void) {
  usrsctp_finish();
  return;
}

int
snw_ice_sctp_ctx_init(dtls_ctx_t *dtls, snw_ice_sctp_ctx_t *sctp, uint16_t port) {
  snw_sctp_channel_t *channel = 0;

  if (!sctp) return -1;

  memset(sctp, 0, sizeof(snw_ice_sctp_ctx_t));
  sctp->dtls = dtls;
  sctp->local_port = 5000;
  sctp->remote_port = port;

  // init sctp channel & streams
  channel = &sctp->channel;
  channel->id = 0;
  channel->state = DATA_CHANNEL_CLOSED;
  channel->pr_policy = SCTP_PR_SCTP_NONE;
  channel->pr_value = 0;
  channel->stream = 0;
  channel->unordered = 0;
  channel->flags = 0;

  usrsctp_register_address((void *)sctp);
  usrsctp_sysctl_set_sctp_ecn_enable(0);
  sctp->sock_state = SCTP_SOCKET_STATE_INIT;

  return 0;
}

int
snw_ice_sctp_socket_init(snw_ice_sctp_ctx_t *sctp) {
  struct socket *sock = 0;
  uint16_t event_types[] = {
    //minimum set of interested events
    SCTP_ASSOC_CHANGE,
    SCTP_PEER_ADDR_CHANGE,
    SCTP_REMOTE_ERROR,
    SCTP_SHUTDOWN_EVENT,
    SCTP_ADAPTATION_INDICATION
  };
  struct sctp_event event;
  struct sctp_initmsg initmsg;
  int i = 0;

  if (!sctp) return -1;

  sock = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP,
      snw_ice_sctp_incoming_data, 0, 0, (void *)sctp);
  if (!sock) {
    return -2;
  }
  sctp->sock = sock;

  if (usrsctp_set_non_blocking(sock, 1) < 0) {
    usrsctp_close(sock);
    return -3;
  }

  memset(&event, 0, sizeof(event));
  event.se_assoc_id = SCTP_ALL_ASSOC;
  event.se_on = 1;
  for(i = 0; i < sizeof(event_types)/sizeof(uint16_t); i++) {
    event.se_type = event_types[i];
    if(usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) < 0) {
      usrsctp_close(sock);
      return -4;
    }
  }

  memset(&initmsg, 0, sizeof(struct sctp_initmsg));
  initmsg.sinit_num_ostreams = 4;
  initmsg.sinit_max_instreams = 64;
  if(usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(struct sctp_initmsg)) < 0) {
    usrsctp_close(sock);
    return -5;
  }
  sctp->sock_state = SCTP_SOCKET_STATE_OPEN;

  return 0;
}

int
snw_ice_sctp_socket_connect(snw_ice_sctp_ctx_t *sctp) {
  struct sockaddr_conn local_conn;
  struct sockaddr_conn remote_conn;
  int ret = -1;

  if (!sctp) return -1;

  memset(&local_conn, 0, sizeof(struct sockaddr_conn));
  local_conn.sconn_family = AF_CONN;
  local_conn.sconn_port = htons(sctp->local_port);
  local_conn.sconn_addr = (void *)sctp;
  ret = usrsctp_bind(sctp->sock, (struct sockaddr *)&local_conn,
                   sizeof(struct sockaddr_conn));
  if (ret < 0) {
    return ret;
  }

  memset(&remote_conn, 0, sizeof(struct sockaddr_conn));
  remote_conn.sconn_family = AF_CONN;
  remote_conn.sconn_port = htons(sctp->remote_port);
  remote_conn.sconn_addr = (void *)sctp;
  ret = usrsctp_connect(sctp->sock, (struct sockaddr *)&remote_conn,
                        sizeof(struct sockaddr_conn));
  if (ret < 0 && errno != EINPROGRESS) {
    return ret;
  }
  sctp->sock_state = SCTP_SOCKET_STATE_CONNECTING;

  return 0;
}

snw_ice_sctp_ctx_t*
snw_ice_sctp_create(snw_ice_context_t *ice_ctx, dtls_ctx_t *dtls, uint16_t port) {
  snw_log_t *log = 0;
  snw_ice_sctp_ctx_t *sctp = 0;

  if (!ice_ctx || !dtls) return 0;
  log = ice_ctx->log;

  //TODO: move to dtls_ctx
  sctp = (snw_ice_sctp_ctx_t*)malloc(sizeof(snw_ice_sctp_ctx_t));
  if (!sctp) return 0;

  if (snw_ice_sctp_ctx_init(dtls, sctp, port) < 0) {
    ERROR(log, "failed to init sctp context");
    goto free;
  }

  if (snw_ice_sctp_socket_init(sctp) < 0) {
    ERROR(log, "failed to init sctp socket");
    goto free;
  }

  if (snw_ice_sctp_socket_connect(sctp) < 0) {
    ERROR(log, "failed to connect sctp socket");
    goto free;
  }

  return sctp;
free:
  ERROR(log, "cannot create sctp context");
  snw_ice_sctp_free(sctp);
  return 0;
}

void
snw_ice_sctp_free(snw_ice_sctp_ctx_t *sctp) {

  if (!sctp) return;

  if (sctp->sock_state > SCTP_SOCKET_STATE_INIT)
    usrsctp_close(sctp->sock);

  free(sctp);
  return;
}

int
snw_ice_sctp_data_from_dtls(snw_ice_sctp_ctx_t *sctp, char *buf, int len) {
  snw_log_t *log = 0;

  if (!buf || !sctp || !sctp->dtls || !sctp->dtls->ctx || len <=0)
    return -1;
  log = sctp->dtls->ctx->log;

  DEBUG(log, "got data from dtls stack, sctp=%p, len=%d", sctp, len);
  usrsctp_conninput((void *)sctp, buf, len, 0);
  return 0;
}


