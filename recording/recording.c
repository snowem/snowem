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

int
snw_record_init(void *c) {
  static int is_init = 0;
  snw_ice_context_t *ctx = (snw_ice_context_t*)c;
  snw_log_t *log = 0;
  int i = 0;
   
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

int
snw_record_handle_pkg_in(void *data, char *buf, int buflen) {
  snw_rtp_ctx_t *ctx = (snw_rtp_ctx_t*)data;
  snw_log_t *log;
  int i = 0;

  if (!ctx || !buf || buflen <= MIN_RTP_HEADER_SIZE) {
    return -1;
  }
  log = ctx->log;

  //DEBUG(log,"record-in handling, pkt_type=%u", ctx->pkt_type);
  //print_rtp_header(log,buf,buflen,"record"); 

  if (!ctx->record_ctx) {
    ctx->record_ctx = snw_record_create(0);
    ctx->record_ctx->log = log;
    DEBUG(log,"create recording context, pkt_type=%u", ctx->pkt_type);
  }

  if (!ctx->record_ctx) {
    return -1;
  }

  snw_record_write_frame(ctx->record_ctx, ctx->pkt_type, buf, buflen);

  return 0;
}

int
snw_record_handle_pkg_out(void *data, char *buf, int buflen) {
  snw_rtp_ctx_t *ctx = (snw_rtp_ctx_t*)data;
  snw_log_t *log;
  int i = 0;

  if (!ctx || !buf || buflen <= MIN_RTP_HEADER_SIZE) {
    return -1;
  }
  log = ctx->log;

  //print_rtp_header(log,buf,buflen,"audio"); 
  //HEXDUMP(log,(char*)buf,buflen,"rtp");
  return 0;
}
 
int
snw_record_fini() {
   return 0;
}

snw_rtp_module_t g_rtp_record_module = { 
   "audio",
   0,/*ctx*/
   RTP_AUDIO | RTP_VIDEO,
   0,
   snw_record_init, 
   snw_record_handle_pkg_in, 
   snw_record_handle_pkg_out, 
   snw_record_fini,
   0 /*next*/
};

snw_record_ctx_t*
snw_record_create(uint32_t id) {
  snw_record_ctx_t *ctx = 0;
  AVFormatContext *av_ctx = 0;

  ctx = (snw_record_ctx_t*)malloc(sizeof(snw_record_ctx_t));
  if (!ctx) return 0;
  memset(ctx,0,sizeof(snw_record_ctx_t));

  av_ctx = avformat_alloc_context();
  if (av_ctx==NULL){
    //ERROR("Error allocating memory for IO context");
  } else {

    memcpy(av_ctx->filename, "./recording/test.webm",sizeof(av_ctx->filename));

    // Force webm format recording (vp8 + opus)
    av_ctx->oformat = av_guess_format("webm", av_ctx->filename, NULL);
    if (!av_ctx->oformat){
      //ERROR("Error guessing format %s", av_ctx->filename);
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

  {
    AVCodec* video_codec = 0;
    video_codec = avcodec_find_encoder(ctx->video_codec);
    if (!video_codec) return 0;
    ctx->video_stream = avformat_new_stream(ctx->av_ctx, video_codec);
    ctx->video_stream->id = 0;
    ctx->video_stream->codec->codec_id = ctx->video_codec;
    ctx->video_stream->codec->width = 640;
    ctx->video_stream->codec->height = 480;
    ctx->video_stream->time_base = (AVRational) { 1, 30 };
    
    //ctx->video_stream->metadata = genVideoMetadata();
    ctx->video_stream->codec->pix_fmt = AV_PIX_FMT_YUV420P;
    if (ctx->av_ctx->oformat->flags & AVFMT_GLOBALHEADER) {
      ctx->video_stream->codec->flags |= CODEC_FLAG_GLOBAL_HEADER;
    }   
    ctx->av_ctx->oformat->flags |= AVFMT_VARIABLE_FPS;
  }

  {
    AVCodec* audio_codec = avcodec_find_encoder(ctx->audio_codec);
    if (!audio_codec) {
      //ELOG_ERROR("Could not find audio codec");
      return 0;
    }
 
    ctx->audio_stream = avformat_new_stream(ctx->av_ctx, audio_codec);
    ctx->audio_stream->id = 1;
    ctx->audio_stream->codec->codec_id = ctx->audio_codec;
    ctx->audio_stream->codec->sample_rate = 44100;//audio_map_.clock_rate;
    ctx->audio_stream->time_base = (AVRational) { 1, ctx->audio_stream->codec->sample_rate };
    ctx->audio_stream->codec->channels = 1;//audio_map_.channels;
    if (ctx->av_ctx->oformat->flags & AVFMT_GLOBALHEADER) {
      ctx->audio_stream->codec->flags |= CODEC_FLAG_GLOBAL_HEADER;
    }
  }

  { 
    ctx->av_ctx->streams[0] = ctx->video_stream;
    ctx->av_ctx->streams[1] = ctx->audio_stream;
    if (avio_open(&ctx->av_ctx->pb, ctx->av_ctx->filename, AVIO_FLAG_WRITE) < 0) {
      //ELOG_ERROR("Error opening output file");
      return 0;
    }
 
    if (avformat_write_header(ctx->av_ctx, 0) < 0) {
      //ELOG_ERROR("Error writing header");
      return 0;
    }
  }
 
  return ctx;
}

int
snw_record_write_audio_frame(snw_record_ctx_t *r, char* buf, int len) {
  snw_log_t *log = 0;
  rtp_hdr_t *hdr;
  uint16_t id = 0;
  int hdrlen = 0;
  int extlen = 0;
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

  {
    static int cnt = 0;
    static int is_close = 0;
    cnt++;
    if (cnt > 1000) {
      if (!is_close) {
        snw_record_close(r);
        is_close = 1;
      }
      return 0;
    }
  }
 
  //print_rtp_header(log,buf,buflen,"record"); 
  DEBUG(log,"pkt info, cur_seq=%u, cur_ts=%u", cur_seq, cur_ts);
  r->last_audio_seq_num = cur_seq;
  if (r->first_audio_ts = 0) {
    r->first_audio_ts = cur_ts;
  }
  
  if (cur_ts - r->first_audio_ts < 0) {
     // we wrapped.  add 2^32 to correct this. We only handle a single wrap around
     // since that's 13 hours of recording, minimum.
     cur_ts += 0xFFFFFFFF;
  }

  written_ts = (cur_ts - r->first_audio_ts) / 
     (r->audio_stream->codec->sample_rate / r->audio_stream->time_base.den); 

  //TODO: check this out
  //written_ts += audio_offset_ms_ / (1000 / audio_stream_->time_base.den);

  {
    AVPacket av_packet;
    av_init_packet(&av_packet);
    av_packet.data = buf + hdrlen;
    av_packet.size = len - hdrlen;
    av_packet.pts = written_ts;
    av_packet.stream_index = 1;
    av_interleaved_write_frame(r->av_ctx, &av_packet); // pointer to local object???
  }

  return 0;
}

int
snw_record_write_video_frame(snw_record_ctx_t *r, char* buf, int len) {

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

  //print_rtp_header(log,buf,buflen,"record"); 
  //HEXDUMP(log,(char*)buf,buflen,"rtp");
  return 0;
}

int
snw_record_close(snw_record_ctx_t *r) {

  if (!r) return -1;

  if (r->audio_stream != 0 && r->video_stream != 0 && r->av_ctx != 0) {
    av_write_trailer(r->av_ctx);
  }
 
  if (r->video_stream && r->video_stream->codec != 0) {
    avcodec_close(r->video_stream->codec);
  }
 
  if (r->audio_stream && r->audio_stream->codec != 0) {
    avcodec_close(r->audio_stream->codec);
  }
 
  if (r->av_ctx != 0) {
    avio_close(r->av_ctx->pb);
    avformat_free_context(r->av_ctx);
    r->av_ctx = 0;
  }

  return 0;
}


