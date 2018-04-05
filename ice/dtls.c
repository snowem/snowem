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

#include "dtls.h"

#include "core/log.h"
#include "core/types.h"
#include "core/session.h"
#include "core/utils.h"
#include "ice.h"
#include "ice_types.h"
#include "ice_session.h"

void
dtls_callback(const SSL *ssl, int where, int ret) {
   //FIXME: check useful ssl events
   return;
}

int
dtls_verify_cb(int preverify_ok, X509_STORE_CTX *ctx) {
   //FIXME: do real verification
   return 1;
}


int
dtls_bio_handshake_new(BIO *bio) {
  
   bio->init = 1;
   bio->flags = 0;
   
   return 1;
}

int
dtls_bio_handshake_free(BIO *bio) {

   if (bio == NULL)
      return 0;
      
   bio->ptr = NULL;
   bio->init = 0;
   bio->flags = 0;
   return 1;
}

int
dtls_send_data(dtls_ctx_t *dtls, int len) {
   snw_ice_session_t *session = 0;
   snw_ice_component_t *component = 0;
   snw_ice_stream_t *stream = 0;
   snw_log_t *log = 0;
   char data[DTLS_BUFFER_SIZE];
   int sent, bytes;

   if (!dtls) return -1;

   component = (snw_ice_component_t *)dtls->component;
   if (!component || !component->stream || !component->stream->session) 
      return -2;

   stream = component->stream;
   session = stream->session;
   log = session->ice_ctx->log;
   if (!session || !session->agent || !dtls->out_bio) {
      return -3;
   }

   //FIXME: a loop is needed to read and send all data?
   sent = BIO_read(dtls->out_bio, data, DTLS_MTU_SIZE);
   if (sent <= 0) {
      ERROR(log, "failed to read dtls data, sent=%d", sent);
      return -1;
   }

   TRACE(log, "sending dtls msg, len=%u, sent=%u", len, sent);
   bytes = ice_agent_send(session->agent, component->stream->id, 
                          component->id, data, sent);

   if (bytes < sent) {
      ERROR(log, "failed to send dtls message, cid=%u, sid=%u, len=%d", 
            component->id, stream->id, bytes);
   } 

   return 0;
}

int
dtls_bio_handshake_write(BIO *bio, const char *in, int inl) {
   snw_log_t *log = 0;
   dtls_ctx_t *dtls = 0;
   int ret = 0;

   dtls = (dtls_ctx_t *)bio->ptr;
   log = dtls->ctx->log;

   ret = BIO_write(bio->next_bio, in, inl);

   TRACE(log, "write dtls msg to filter, len=%d, written_len=%ld", inl, ret);
   dtls_send_data(dtls,ret); 

   return ret;
}

int
dtls_bio_handshake_read(BIO *bio, char *buf, int len) {
   snw_log_t *log = 0;
   dtls_ctx_t *dtls = 0;

   dtls = (dtls_ctx_t *)bio->ptr;
   log = dtls->ctx->log;

   DEBUG(log, "dtls read, len=%d", len);

   return 0;
}

long
dtls_bio_handshake_ctrl(BIO *bio, int cmd, long num, void *ptr) {

   switch(cmd) {
      case BIO_CTRL_FLUSH:
         return 1;
      case BIO_CTRL_DGRAM_QUERY_MTU:
         return DTLS_MTU_SIZE;
      default:
         ;
   }
   return 0;
}

static BIO_METHOD dtls_bio_handshake_methods = {
   BIO_TYPE_FILTER,
   "dtls handshake",
   dtls_bio_handshake_write,
   dtls_bio_handshake_read,
   NULL,
   NULL,
   dtls_bio_handshake_ctrl,
   dtls_bio_handshake_new,
   dtls_bio_handshake_free,
   NULL
};

int
srtp_print_fingerprint(char *buf, unsigned int len, 
      unsigned char *rfingerprint, unsigned int rsize) {
   unsigned int i = 0;

   if (len < (rsize*3 - 1))
      return -1;

   for (i = 0; i < rsize; i++) {
      snprintf(buf + i*3, 4, "%.2X:", rfingerprint[i]);
   }
   buf[rsize*3-1] = 0;

   return 0;
}

int
dtls_init(snw_ice_context_t *ctx, char *server_pem, char *server_key) {
   unsigned char fingerprint[EVP_MAX_MD_SIZE];
   snw_log_t *log = 0;
   BIO *certbio = 0;
   X509 *cert = 0;
   unsigned int size;

   ctx->ssl_ctx = SSL_CTX_new(DTLSv1_method());
   if (!ctx->ssl_ctx) {
      ERROR(log, "failed to create ssl context");
      return -1;
   }

   SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, dtls_verify_cb);
   SSL_CTX_set_tlsext_use_srtp(ctx->ssl_ctx, "SRTP_AES128_CM_SHA1_80");
   if (!server_pem || !SSL_CTX_use_certificate_file(ctx->ssl_ctx, server_pem, SSL_FILETYPE_PEM)) {
      ERROR(log, "certificate error, err=%s", DTLS_ERR_STR);
      return -2;
   }

   if (!server_key || !SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, server_key, SSL_FILETYPE_PEM)) {
      ERROR(log, "certificate key error, err=%s", DTLS_ERR_STR);
      return -3;
   }

   if (!SSL_CTX_check_private_key(ctx->ssl_ctx)) {
      ERROR(log, "certificate check error,err-%s", DTLS_ERR_STR);
      return -4;
   }

   SSL_CTX_set_read_ahead(ctx->ssl_ctx,1);
   certbio = BIO_new(BIO_s_file());
   if (!certbio) {
      return -5;
   }

   if (BIO_read_filename(certbio, server_pem) == 0) {
      ERROR(log, "failed to read certificate, err=%s", DTLS_ERR_STR);
      BIO_free_all(certbio);
      return -6;
   }

   cert = PEM_read_bio_X509(certbio, NULL, 0, NULL);
   if (!cert) {
      ERROR(log, "failed to read certificate, err=%s", DTLS_ERR_STR);
      BIO_free_all(certbio);
      return -7;
   }

   if (X509_digest(cert, EVP_sha256(), (unsigned char *)fingerprint, &size) == 0) {
      ERROR(log, "failed to convert X509 structure, err=%s", DTLS_ERR_STR);
      X509_free(cert);
      BIO_free_all(certbio);
      return -8;
   }
   
   srtp_print_fingerprint((char *)&ctx->local_fingerprint,160,fingerprint,size);
   DEBUG(log, "fingerprint of certificate: %s", ctx->local_fingerprint);
   X509_free(cert);
   BIO_free_all(certbio);
   SSL_CTX_set_cipher_list(ctx->ssl_ctx, DTLS_CIPHERS);

   /* Initialize libsrtp */
   if(srtp_init() != err_status_ok) {
      ERROR(log, "failed to init srtp");
      return -9;
   }

   return 0;
}

dtls_ctx_t *
dtls_create(snw_ice_context_t *ice_ctx, void *component, int type) {
   snw_log_t *log = 0;
   dtls_ctx_t *dtls = 0;

   if (!ice_ctx) return 0;
   log = ice_ctx->log;

   dtls = (dtls_ctx_t*)malloc(sizeof(dtls_ctx_t));
   if (!dtls) return 0;
   
   memset(dtls,0,sizeof(dtls_ctx_t));
   dtls->ctx = ice_ctx;
   dtls->component = component;
   dtls->ssl = SSL_new(ice_ctx->ssl_ctx);
   if (!dtls->ssl) goto fail;

   SSL_set_ex_data(dtls->ssl, 0, dtls);
   SSL_set_info_callback(dtls->ssl, dtls_callback);
   dtls->in_bio = BIO_new(BIO_s_mem());
   if (!dtls->in_bio) goto fail;

   BIO_set_mem_eof_return(dtls->in_bio, -1);

   dtls->out_bio = BIO_new(BIO_s_mem());
   if (!dtls->out_bio)  goto fail;
   
   BIO_set_mem_eof_return(dtls->out_bio, -1);

   dtls->dtls_bio = BIO_new(&dtls_bio_handshake_methods);
   if (!dtls->dtls_bio)  goto fail;
   
   dtls->dtls_bio->ptr = dtls;

   BIO_push(dtls->dtls_bio, dtls->out_bio);
   SSL_set_bio(dtls->ssl, dtls->in_bio, dtls->dtls_bio);

   dtls->type = type;
   if (dtls->type == DTLS_TYPE_CLIENT) {
      SSL_set_connect_state(dtls->ssl);
   } else {
      SSL_set_accept_state(dtls->ssl);
   }

   return dtls;

fail:
   ERROR(log, "failed to create dtls ctx, err=%s", DTLS_ERR_STR);
   dtls_free(dtls);
   return 0;
}

void
dtls_do_handshake(dtls_ctx_t *dtls) {
   snw_log_t *log;
   snw_ice_component_t *c = (snw_ice_component_t*)dtls->component;

   if (dtls == NULL || dtls->ssl == NULL)
      return;
   log = c->stream->session->ice_ctx->log;

   TRACE(log, "start dtls handshake, flowid=%u", 
         c->stream->session->flowid);
   SSL_do_handshake(dtls->ssl);
   return;
}

void
ice_dtls_handshake_done(snw_ice_session_t *session, snw_ice_component_t *component) {
   snw_ice_context_t *ice_ctx = 0;
   snw_log_t *log = 0;
   snw_ice_stream_t *s = 0;

   if (!session || !component)
      return;
   ice_ctx = session->ice_ctx;
   log = ice_ctx->log;

   DEBUG(log, "srtp handshake is completed, cid=%u, sid=%u",
         component->id, component->stream->id);

   LIST_FOREACH(s,&session->streams,list) {
      snw_ice_component_t *c;
      if (s->is_disable)
         continue;
      LIST_FOREACH(c,&s->components,list) {
         if (!c->dtls || c->dtls->state != DTLS_STATE_CONNECTED) {
            DEBUG(log, "component not ready, sid=%u, cid=%u",s->id, c->id);
            return;
         }    
      } 
   }

   SET_FLAG(session, WEBRTC_READY);
   ice_rtp_established(session);
   return;
}

int
dtls_srtp_create(srtp_t *srtp, unsigned char *key, int key_len, unsigned char *salt, int salt_len) {
   unsigned char policy_key[SRTP_MASTER_LENGTH];
   srtp_policy_t policy;
   err_status_t ret;

   memset(&policy,0,sizeof(policy));
   crypto_policy_set_rtp_default(&(policy.rtp));
   crypto_policy_set_rtcp_default(&(policy.rtcp));
   policy.ssrc.type = ssrc_any_inbound;
   policy.key = (unsigned char *)policy_key;
   memcpy(policy.key, key, key_len);
   memcpy(policy.key + key_len, salt, salt_len);
   policy.next = NULL;
   
   ret = srtp_create(srtp, &policy);
   if (ret != err_status_ok) {
      return -1;
   }

   return 0;
}

int
dtls_srtp_setup(dtls_ctx_t *dtls, snw_ice_session_t *session, snw_ice_component_t *component) {
   unsigned char *local_key, *local_salt, *remote_key, *remote_salt;
   snw_log_t *log = 0;
   int ret = 0;

   if (!dtls || !session || !component) return -1;
   log = session->ice_ctx->log;
   
   if (!SSL_export_keying_material(dtls->ssl, dtls->material, SRTP_MASTER_LENGTH*2, 
            "EXTRACTOR-dtls_srtp", 19, NULL, 0, 0)) {
      ERROR(log, "failed to get keying material, cid=%u, sid=%u, err=%s",
         component->id, component->stream->id, ERR_reason_error_string(ERR_get_error()));
      return -2;
   }

   if (dtls->type == DTLS_TYPE_CLIENT) {
      local_key = dtls->material;
      remote_key = local_key + SRTP_MASTER_KEY_LENGTH;
      local_salt = remote_key + SRTP_MASTER_KEY_LENGTH;
      remote_salt = local_salt + SRTP_MASTER_SALT_LENGTH;
   } else {
      remote_key = dtls->material;
      local_key = remote_key + SRTP_MASTER_KEY_LENGTH;
      remote_salt = local_key + SRTP_MASTER_KEY_LENGTH;
      local_salt = remote_salt + SRTP_MASTER_SALT_LENGTH;
   }

   ret = dtls_srtp_create(&dtls->srtp_in,remote_key,SRTP_MASTER_KEY_LENGTH,
                          remote_salt,SRTP_MASTER_SALT_LENGTH);
   if (ret != 0) {
      ERROR(log, "failed to create srtp_in session, cid=%u, sid=%u, ret=%d", 
             component->id, component->stream->id, ret);
      return -3;
   }

   ret = dtls_srtp_create(&dtls->srtp_out,local_key,SRTP_MASTER_KEY_LENGTH,
                          local_salt,SRTP_MASTER_SALT_LENGTH);
   if (ret != 0) {
      ERROR(log, "failed to create srtp_out session, cid=%u, sid=%u, ret=%d", 
             component->id, component->stream->id, ret);
      return -4;
   }

   DEBUG(log,"dtls connected, cid=%u, sid=%u", 
         component->id, component->stream->id);
   dtls->state = DTLS_STATE_CONNECTED;
   ice_dtls_handshake_done(session, component);
     
   return 0;
}

int
dtls_established(dtls_ctx_t *dtls) {
   unsigned char data[EVP_MAX_MD_SIZE];
   char fingerprint[160];
   snw_ice_component_t *component = 0;
   snw_ice_stream_t *stream = 0;
   snw_ice_session_t *session = 0;
   snw_log_t *log = 0;
   X509 *rcert = 0;
   unsigned int len = 0;

   if (!dtls) return -1;

   component = (snw_ice_component_t *)dtls->component;
   if (!component || !component->stream 
       || !component->stream->session
       || !component->stream->session->agent) 
      return -2;
   stream = component->stream;
   session = stream->session;
   log = session->ice_ctx->log;

   if (!stream->remote_fingerprint) {
      ERROR(log,"no remote fingerprint, flowid=%u", session->flowid);
      return -4;
   }

   rcert = SSL_get_peer_certificate(dtls->ssl);
   if (!rcert) {
      ERROR(log,"no remote certificate, s=%s", 
            ERR_reason_error_string(ERR_get_error()));
      return -3;
   } 

   if (stream->remote_hashing && !strcasecmp(stream->remote_hashing, "sha-1")) {
      X509_digest(rcert, EVP_sha1(), (unsigned char *)data, &len);
   } else {
      X509_digest(rcert, EVP_sha256(), (unsigned char *)data, &len);
   }

   srtp_print_fingerprint(fingerprint,160,data,len);
   if (!strcasecmp(fingerprint, stream->remote_fingerprint)) {
      dtls_srtp_setup(dtls,session,component);
   } else {
      ERROR(log, "fingerprint mismatch, got=%s, expected=%s", 
            fingerprint, stream->remote_fingerprint);
      dtls->state = DTLS_STATE_ERROR;
   }

   if (rcert) X509_free(rcert);
   return 0;
}

int
dtls_process_incoming_msg(dtls_ctx_t *dtls, char *buf, uint16_t len) {
   char data[DTLS_BUFFER_SIZE];
   snw_log_t *log = 0;
   snw_ice_component_t *component = 0;
   int ret = 0;
   int written = 0;

   if (!dtls || !dtls->ssl || !dtls->in_bio) {
      return -1;
   }
   component = (snw_ice_component_t*)dtls->component;
   log = component->stream->session->ice_ctx->log;
   

   written = BIO_write(dtls->in_bio, buf, len);
   if (written != len) {
      ERROR(log, "failed to write, written=%u, len=%u", written, len);
   } else {
      TRACE(log, "dtls message, len=%u, written-%u",len, written);
   }

   // http://net-snmp.sourceforge.net/wiki/index.php/DTLS_Implementation_Notes
   ret = SSL_read(dtls->ssl, &data, DTLS_BUFFER_SIZE);
   if (ret < 0) {
      unsigned long err = SSL_get_error(dtls->ssl, ret);
      if (err == SSL_ERROR_SSL) {
         char error[256];
         ERR_error_string_n(ERR_get_error(), error, 256);
         ERROR(log,"ssl read error, ret=%d, err=%s", read, error);
         return -2;
      }
   }

   if (!SSL_is_init_finished(dtls->ssl)) {
      return -3;
   }

   if (dtls->state == DTLS_STATE_CONNECTED) {
      WARN(log,"dtls data not supported, ret=%u",ret);
   } else {
      dtls_established(dtls);
   }

   return 0;
}

void
dtls_free(dtls_ctx_t *dtls) {

   if(!dtls)
      return;
   
   if(!dtls->ssl) {
      SSL_free(dtls->ssl);
   }
  
   //FIXME: free bio structs
   dtls->in_bio = 0;
   dtls->out_bio = 0;
   dtls->dtls_bio = 0;

   if (dtls->state == DTLS_STATE_CONNECTED) {
      if(dtls->srtp_in) {
         srtp_dealloc(dtls->srtp_in);
         dtls->srtp_in = NULL;
      }
      if(dtls->srtp_out) {
         srtp_dealloc(dtls->srtp_out);
         dtls->srtp_out = NULL;
      }
      
   }

   free(dtls);
   return;
}

