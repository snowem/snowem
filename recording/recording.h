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

#ifndef _SNOW_RECORDING_RECORD_H_
#define _SNOW_RECORDING_RECORD_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>

#include "core/log.h"
#include "rtp/types.h"

int snw_record_init(void *ctx);
int snw_record_handle_pkg_in(void *ctx, char *buffer, int len);
int snw_record_handle_pkg_out(void *ctx, char *buffer, int len);
int snw_record_fini();

extern snw_rtp_module_t g_rtp_record_module;

typedef struct snw_record_ctx snw_record_ctx_t;
struct snw_record_ctx {
  uint32_t id;
  snw_log_t *log;

  //need buffers to queue audio and video pkts

  enum AVCodecID   video_codec;
  enum AVCodecID   audio_codec;

  uint64_t         first_audio_ts;
  uint64_t         first_video_ts;
  uint16_t         last_audio_seq_num;
  uint16_t         last_video_seq_num;
  AVFormatContext *av_ctx;
  AVStream        *video_stream;
  AVStream        *audio_stream;
};

snw_record_ctx_t*
snw_record_create(uint32_t id);

int
snw_record_write_frame(snw_record_ctx_t *r, int pkt_type, char *data, int len);

int
snw_record_close(snw_record_ctx_t *r);

#ifdef __cplusplus
}
#endif

#endif // _SNOW_RECORDING_RECORD_H_
