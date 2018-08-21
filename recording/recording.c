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

#include "recording/recording.h"
#include "rtp/rtp.h"
#include "rtp/rtp_utils.h"
#include "rtp/vp8.h"

int
snw_record_init(void *c) {
  static int is_init = 0;
  snw_ice_context_t *ctx = (snw_ice_context_t*)c;
  snw_log_t *log = 0;
   
  if (!ctx) return -1;
  log = ctx->log;

  if (!is_init) {
    av_register_all();
    avcodec_register_all();
    avformat_network_init();
    is_init = 1;
    DEBUG(log, "recording init done, is_init=%u", is_init);
  }

  return 0;
}

int64_t
snw_record_get_time() {
  struct timeval now;
  gettimeofday(&now, NULL);
  return now.tv_sec * 1000 + now.tv_usec / 1000;
}

int
snw_record_handle_pkg_in(void *data, char *buf, int buflen) {
  snw_rtp_ctx_t *ctx = (snw_rtp_ctx_t*)data;
  snw_log_t *log;

  if (!ctx || !ctx->log || !buf) return -1;
  log = ctx->log;

  if (!ctx->recording_enabled) return 0;

  //DEBUG(log,"record-in handling, pkt_type=%u", ctx->pkt_type);
  //print_rtp_header(log,buf,buflen,"record"); 

  if (ctx->pkt_type == RTP_RECORD) {
    snw_record_cmd_t *cmd = (snw_record_cmd_t*)buf;

    DEBUG(log,"record msg, cmd=%u", cmd->cmd);
    if (cmd->cmd == RTP_RECORD_STOP) {
      DEBUG(log,"stop record msg, cmd=%u", cmd->cmd);
      if (ctx->record_ctx) {
        snw_record_close(ctx->record_ctx);
        free(ctx->record_ctx);
        ctx->record_ctx = 0;
      }
    }

    if (cmd->cmd == RTP_RECORD_START) {
      DEBUG(log,"start record msg, cmd=%u", cmd->cmd);
      if (!ctx->record_ctx) {
        DEBUG(log,"create recording context, pkt_type=%u", ctx->pkt_type);
        ctx->record_ctx = snw_record_create(ctx);
      } else {
        //already created
      }
    }

    return 0;
  }

  if (buflen <= MIN_RTP_HEADER_SIZE) {
    return -1;
  }

  if (!ctx->record_ctx) {
    return -1;
  }

  if (ctx->record_ctx->first_ts == 0) {
    ctx->record_ctx->first_ts = snw_record_get_time();
  }

  snw_record_write_frame(ctx->record_ctx, ctx->pkt_type, buf, buflen);

  return 0;
}

int
snw_record_handle_pkg_out(void *data, char *buf, int buflen) {
  snw_rtp_ctx_t *ctx = (snw_rtp_ctx_t*)data;

  if (!ctx || !buf || buflen <= MIN_RTP_HEADER_SIZE) {
    return -1;
  }

  return 0;
}
 
int
snw_record_fini() {
   return 0;
}

snw_rtp_module_t g_rtp_record_module = { 
   "record",
   0,/*ctx*/
   RTP_AUDIO | RTP_VIDEO | RTP_RECORD,
   0,
   snw_record_init, 
   snw_record_handle_pkg_in, 
   snw_record_handle_pkg_out, 
   snw_record_fini,
   0 /*next*/
};

int
snw_record_create_audio_stream(snw_record_ctx_t *ctx) {
  AVCodec* audio_codec = 0;

  if (!ctx) return -1;

  audio_codec = avcodec_find_encoder(ctx->audio_codec);
  if (!audio_codec) {
    //ERROR(log,"Could not find audio codec");
    return -1;
  }

  ctx->audio_stream = avformat_new_stream(ctx->av_ctx, audio_codec);
  ctx->audio_stream->id = 1;
  ctx->audio_stream->codec->codec_id = ctx->audio_codec;
  ctx->audio_stream->codec->sample_rate = 44100;
  ctx->audio_stream->time_base = (AVRational) { 1, ctx->audio_stream->codec->sample_rate };
  ctx->audio_stream->codec->channels = 1;
  if (ctx->av_ctx->oformat->flags & AVFMT_GLOBALHEADER) {
    ctx->audio_stream->codec->flags |= CODEC_FLAG_GLOBAL_HEADER;
  }

  return 0;
}

int
snw_record_create_video_stream(snw_record_ctx_t *ctx) {
  AVCodec* video_codec = 0;
  AVCodecContext* codec_ctx = 0;
  AVCodecParameters * codec_params = 0;

  if (!ctx) return -1;

  video_codec = avcodec_find_encoder(ctx->video_codec);
  if (!video_codec) return 0;

  codec_ctx = avcodec_alloc_context3(video_codec);
  if (!codec_ctx) return 0;

  codec_ctx->codec_id = ctx->av_ctx->oformat->video_codec;
  codec_ctx->width = 640;
  codec_ctx->height = 480;
  codec_ctx->time_base = (AVRational) { 1, 30 };
  codec_ctx->pix_fmt = AV_PIX_FMT_YUV420P;

  codec_params = avcodec_parameters_alloc();
  avcodec_parameters_from_context(codec_params, codec_ctx);

  ctx->video_stream = avformat_new_stream(ctx->av_ctx, 0);
  ctx->video_stream->id = 0;
  ctx->video_stream->time_base = codec_ctx->time_base;
  ctx->video_stream->codecpar = codec_params;
  ctx->video_stream->avg_frame_rate = av_inv_q(ctx->video_stream->time_base);

  ctx->video_stream->codec->pix_fmt = AV_PIX_FMT_YUV420P;
  if (ctx->av_ctx->oformat->flags & AVFMT_GLOBALHEADER) {
    ctx->video_stream->codec->flags |= CODEC_FLAG_GLOBAL_HEADER;
  }
  ctx->av_ctx->oformat->flags |= AVFMT_VARIABLE_FPS;
  avcodec_free_context(&codec_ctx);

  return 0;
}

snw_record_ctx_t*
snw_record_create(void *data) {
  snw_rtp_ctx_t *rtp_ctx = (snw_rtp_ctx_t*)data;
  snw_log_t *log = 0;
  snw_record_ctx_t *ctx = 0;
  AVFormatContext *av_ctx = 0;
  char name[128];

  if (!rtp_ctx || !rtp_ctx->log) return 0;
  log = rtp_ctx->log;

  ctx = (snw_record_ctx_t*)malloc(sizeof(snw_record_ctx_t));
  if (!ctx) return 0;

  memset(ctx,0,sizeof(snw_record_ctx_t));
  ctx->video_state = VIDEO_STATE_START;
  ctx->video_data_ptr = ctx->video_data;
  ctx->log = log;

  av_ctx = avformat_alloc_context();
  if (av_ctx == 0){
    ERROR(log,"Error allocating memory for IO context");
  } else {

    memset(name,0,128);
    snprintf(name,128,"%s/test_%u.webm",rtp_ctx->recording_folder, rand());
    memcpy(av_ctx->filename, name, sizeof(av_ctx->filename));
    DEBUG(log,"create recording, name=%s", name);

    // Force webm format recording (vp8 + opus)
    av_ctx->oformat = av_guess_format("webm", av_ctx->filename, 0);
    if (!av_ctx->oformat){
      //ERROR(log,"Error guessing format %s", av_ctx->filename);
    } else {
      av_ctx->oformat->video_codec = AV_CODEC_ID_VP8;
      av_ctx->oformat->audio_codec = AV_CODEC_ID_NONE;
    }
  }
  
  ctx->av_ctx = av_ctx;
  //ctx->audio_codec = AV_CODEC_ID_NONE;
  //ctx->video_codec = AV_CODEC_ID_NONE;
  ctx->audio_codec = AV_CODEC_ID_OPUS;
  ctx->video_codec = AV_CODEC_ID_VP8;


  snw_record_create_video_stream(ctx);
  snw_record_create_audio_stream(ctx);

  { 
    ctx->av_ctx->streams[0] = ctx->video_stream;
    ctx->av_ctx->streams[1] = ctx->audio_stream;
    if (avio_open(&ctx->av_ctx->pb, ctx->av_ctx->filename, AVIO_FLAG_WRITE) < 0) {
      //ERROR(log,"Error opening output file");
      return 0;
    }
 
    if (avformat_write_header(ctx->av_ctx, 0) < 0) {
      //ERROR(log,"Error writing header");
      return 0;
    }
  }
 
  return ctx;
}

int
snw_record_write_raw_data(snw_record_ctx_t *r, int audio, int64_t ts,  char *data, int len) {
  AVPacket av_packet;

  if (!r || !r->log) return -1;

  av_init_packet(&av_packet);
  av_packet.data = data;
  av_packet.size = len;
  av_packet.pts = ts;

  /*{//DEBUG
    snw_log_t *log = 0;
    log = r->log;
    DEBUG(log,"write raw data, audio=%u, ts=%llu", audio, ts);
  }*/

  av_packet.stream_index = audio ? 1 : 0;
  av_interleaved_write_frame(r->av_ctx, &av_packet); // pointer to local object???

  return 0;
}

int
snw_record_write_audio_frame(snw_record_ctx_t *r, char* buf, int len) {
  snw_log_t *log = 0;
  rtp_hdr_t *hdr;
  int hdrlen = 0;
  uint16_t cur_seq = 0;
  uint64_t cur_ts = 0;
  int64_t written_ts = 0;

  if (!r || !r->log) return -1;
  log = r->log;

  //parsing rtp header
  hdr = (rtp_hdr_t*)buf;
  hdrlen = snw_rtp_get_hdrlen(hdr);
  cur_seq = htons(hdr->seq);
  cur_ts = htonl(hdr->ts);
  r->cur_ts = cur_ts;

  r->last_audio_seq_num = cur_seq;

  if (r->audio_offset_ts == 0) {
    r->audio_offset_ts = snw_record_get_time() - r->first_ts;
  }

  if (r->first_audio_ts == 0) {
    r->first_audio_ts = cur_ts;
  }
  
  if (cur_ts - r->first_audio_ts < 0) {
     cur_ts += 0xFFFFFFFF;
  }

  if (!r->has_keyframe)
    return -1;

  written_ts = (cur_ts - r->first_audio_ts) / 
     (r->audio_stream->codec->sample_rate / r->audio_stream->time_base.den); 
  written_ts += r->audio_offset_ts / (1000 / r->audio_stream->time_base.den);
  snw_record_write_raw_data(r,1,written_ts,buf+hdrlen,len-hdrlen);

  return 0;
}

int
snw_record_write_vp8_frame(snw_record_ctx_t *r) {
  snw_log_t *log = 0;
  uint64_t cur_ts = 0;
  uint64_t written_ts = 0;

  if (!r || !r->log) return -1;
  log = r->log;

  cur_ts = r->cur_ts;
  if (cur_ts - r->first_video_ts < 0) {
     cur_ts += 0xFFFFFFFF;
  }

  written_ts = (cur_ts - r->first_video_ts) /
     (90000 / r->video_stream->time_base.den);
  written_ts += r->video_offset_ts / (1000 / r->video_stream->time_base.den);
  snw_record_write_raw_data(r,0,written_ts,r->video_data,r->video_data_len);

  //reset buffer
  r->video_data_ptr = r->video_data;
  r->video_data_len = 0;
  r->video_state = VIDEO_STATE_START;

  return 0;
}

int
snw_record_handle_vp8_frame(snw_record_ctx_t *r, int start_frame,
    int end_frame, char* data, int len) {
  snw_log_t *log = 0;

  if (!r || !r->log) return -1;
  log = r->log;

  //DEBUG(log,"video state, state=%u, start=%u, end=%u",
  //    r->video_state, start_frame, end_frame);

  if (r->video_state == VIDEO_STATE_START) {

    if (start_frame && end_frame) { //standalone frame
      //check buffer overflow
      if (r->video_data_len + len > MAX_VIDEO_BUFFER_SIZE) {
        //reset buffer
        r->video_data_ptr = r->video_data;
        r->video_data_len = 0;
        r->video_state = VIDEO_STATE_START;
        return -1;
      }

      memcpy(r->video_data_ptr, data, len);
      r->video_data_ptr += len;
      r->video_data_len += len;

      snw_record_write_vp8_frame(r);

    } else if (start_frame && !end_frame) { //copy buffer
      if (r->video_data_len + len > MAX_VIDEO_BUFFER_SIZE) {
        //reset buffer
        r->video_data_ptr = r->video_data;
        r->video_data_len = 0;
        r->video_state = VIDEO_STATE_START;
        return -1;
      }

      memcpy(r->video_data_ptr, data, len);
      r->video_data_ptr += len;
      r->video_data_len += len;
      r->video_state = VIDEO_STATE_END;

    } else { //not start frame, drop it.

    }

  } else if (r->video_state == VIDEO_STATE_END) {
    if (start_frame && end_frame) {
      //standalone frame, reset buffer before copy
      r->video_data_ptr = r->video_data;
      r->video_data_len = 0;
      r->video_state = VIDEO_STATE_START;

      if (r->video_data_len + len > MAX_VIDEO_BUFFER_SIZE) {
        return -1;
      }

      memcpy(r->video_data_ptr, data, len);
      r->video_data_ptr += len;
      r->video_data_len += len;

      snw_record_write_vp8_frame(r);

    } else if (!start_frame && !end_frame) {
      if (r->video_data_len + len > MAX_VIDEO_BUFFER_SIZE) {
        r->video_data_ptr = r->video_data;
        r->video_data_len = 0;
        r->video_state = VIDEO_STATE_START;
        return -1;
      }

      memcpy(r->video_data_ptr, data, len);
      r->video_data_ptr += len;
      r->video_data_len += len;

    } else if (start_frame && !end_frame) {
      r->video_data_ptr = r->video_data;
      r->video_data_len = 0;
      r->video_state = VIDEO_STATE_START;

      if (r->video_data_len + len > MAX_VIDEO_BUFFER_SIZE) {
        return -1;
      }

      memcpy(r->video_data_ptr, data, len);
      r->video_data_ptr += len;
      r->video_data_len += len;

    } else if (!start_frame && end_frame) {

      if (r->video_data_len + len > MAX_VIDEO_BUFFER_SIZE) {
        r->video_data_ptr = r->video_data;
        r->video_data_len = 0;
        r->video_state = VIDEO_STATE_START;
        return -1;
      }

      memcpy(r->video_data_ptr, data, len);
      r->video_data_ptr += len;
      r->video_data_len += len;
      snw_record_write_vp8_frame(r);
    }

  } else {
    // wrong state
  }

  return 0;
}

int
snw_record_write_video_frame(snw_record_ctx_t *r, char* buf, int len) {
  snw_log_t *log = 0;
  rtp_hdr_t *hdr = 0;
  int hdrlen = 0, data_len = 0;
  char *data;
  uint16_t cur_seq = 0;
  uint64_t cur_ts = 0;

  if (!r || !r->log) return -1;
  log = r->log;

  hdr = (rtp_hdr_t*)buf;
  hdrlen = snw_rtp_get_hdrlen(hdr);
  cur_seq = htons(hdr->seq);
  cur_ts = htonl(hdr->ts);

  r->cur_ts = cur_ts;
  r->last_video_seq_num = cur_seq;

  if (r->video_offset_ts == 0) {
    r->video_offset_ts = snw_record_get_time() - r->first_ts;
  }

  if (r->first_video_ts == 0) {
    r->first_video_ts = cur_ts;
  }

  data = buf + hdrlen;
  data_len = len - hdrlen;

  if (r->video_codec == AV_CODEC_ID_VP8) { //parsing vp8 data
    vp8_desc_t *vp8_hdr = (vp8_desc_t*)data;
    data++;
    data_len--;

    //DEBUG(log,"vp8 desc, hdrlen=%u, len=%u, marker=%u, X=%u, N=%u, S=%u, PID=%u",
    //          hdrlen, data_len, hdr->m, vp8_hdr->X, vp8_hdr->N, vp8_hdr->S, vp8_hdr->PID);
    if (vp8_hdr->X) {
      vp8_xext_t *xext =  (vp8_xext_t*)data;
      data++;
      data_len--;
      //DEBUG(log,"parsing vp8 extension, len=%u, I=%u, L=%u, T=%u, K=%u",
      //          data_len, xext->I, xext->L, xext->T, xext->K);
      if (xext->I) {
        if (*data & 0x80) {
          data++;
          data_len--;
        }
        data++;
        data_len--;
      }

      if (xext->L) {
        data++;
        data_len--;
      }

      if (xext->T || xext->K) {
        data++;
        data_len--;
      }
    }

    if (data_len > 0 && vp8_hdr->S && vp8_hdr->PID == 0 && !r->has_keyframe) {
      r->has_keyframe = !(*data & 0x01);
      DEBUG(log,"got key frame, has_keyframe=%u",r->has_keyframe);
    }

    if (!r->has_keyframe)
      return -1;

    snw_record_handle_vp8_frame(r, vp8_hdr->S, hdr->m, data, data_len);
  } else {

  }

  return 0;
}

int
snw_record_write_frame(snw_record_ctx_t *r, int pkt_type, char *data, int len) {
  snw_log_t *log = 0;

  if (!r || !r->log) return -1;
  log = r->log;

  if (pkt_type == RTP_AUDIO) {
    snw_record_write_audio_frame(r, data, len);
  } else if (pkt_type == RTP_VIDEO) {
    snw_record_write_video_frame(r, data, len);
  } else {
    // unknown pkt type
    return -1;
  }

  return 0;
}

int
snw_record_close(snw_record_ctx_t *r) {

  if (!r) return -1;

  if (r->audio_stream != 0 && r->video_stream != 0 && r->av_ctx != 0) {
    av_write_trailer(r->av_ctx);
  }
 
  if (r->av_ctx != 0) {
    avio_close(r->av_ctx->pb);
    avformat_free_context(r->av_ctx);
    r->av_ctx = 0;
  }

  return 0;
}


