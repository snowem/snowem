
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "rtmp.h"

snw_rtmp_ctx_t*
snw_rtmp_ctx_new(const char* url) {
   snw_rtmp_ctx_t* ctx;
   int ret = 0;

   ctx = (snw_rtmp_ctx_t*)malloc(sizeof(snw_rtmp_ctx_t));
   if (!ctx) return 0;
   memset(ctx,0,sizeof(snw_rtmp_ctx_t));

   ret = snw_rtmp_init(ctx,url);
   if (ret < 0) return 0;

   return ctx;
}

int
ice_aac_rtmp_init(snw_rtmp_ctx_t *ctx, const char* raw_file) {
   int raw_fd = -1;
   off_t file_size = 0;
   int ret;

   if (!ctx || !raw_file) {
      return -1;
   }
 
   raw_fd = open(raw_file, O_RDONLY);
   if (raw_fd < 0) {
      RTMP_ERROR("open audio raw file %s failed.", raw_file);
      return -2;
   }
    
   file_size = lseek(raw_fd, 0, SEEK_END);
   if (file_size <= 0) {
      RTMP_ERROR("audio raw file %s empty.", raw_file);
      close(raw_fd);
      return -3;
   }
   RTMP_DEBUG("read entirely audio raw file, size=%dKB", (int)(file_size / 1024));
    
   ctx->audio_raw = (char*)malloc(file_size);
   if (!ctx->audio_raw) {
      RTMP_ERROR("alloc raw buffer failed for file %s.", raw_file);
      close(raw_fd);
      return -4;
   }
   ctx->file_size = file_size;
   ctx->audio_pos = ctx->audio_raw;
   ctx->delta_ts = 45; //ms
   ctx->audio_ts = 45; //ms
    
   lseek(raw_fd, 0, SEEK_SET);
   ssize_t nb_read = 0;
   if ((nb_read = read(raw_fd, ctx->audio_raw, ctx->file_size)) != ctx->file_size) {
      RTMP_ERROR("buffer %s failed, expect=%dKB, actual=%dKB.", 
            raw_file, (int)(file_size / 1024), (int)(nb_read / 1024));
      close(raw_fd);
      return -5;
   }

   close(raw_fd); 
   return ret;
}



//"rtmp://live-api.facebook.com:80/rtmp/2048813932015190?ds=1&a=ATiH7SKrqDT6Z8eE"
int
snw_rtmp_init(snw_rtmp_ctx_t *ctx, const char* rtmp_url) {
   int ret;

   if (!ctx  || !rtmp_url) {
      return -1;
   }
 
    // connect rtmp context
   srs_rtmp_t rtmp = srs_rtmp_create(rtmp_url);
    
   if (srs_rtmp_handshake(rtmp) != 0) {
      RTMP_ERROR("simple handshake failed.");
      goto rtmp_destroy;
   }
    
   if (srs_rtmp_connect_app(rtmp) != 0) {
      RTMP_ERROR("connect vhost/app failed.");
      goto rtmp_destroy;
   }
    
   if (srs_rtmp_publish_stream(rtmp) != 0) {
      RTMP_ERROR("publish stream failed.");
      goto rtmp_destroy;
   }

   RTMP_DEBUG("publish stream success");

   ctx->rtmp = rtmp;

   //AUDIO TEST
   ret = ice_aac_rtmp_init(ctx,"sample/audio.raw.aac");
   if (ret < 0) return -1;

   return 0;

rtmp_destroy:    
    srs_rtmp_destroy(rtmp);
    return -1;
}

void
snw_rtmp_update_ts(snw_rtmp_ctx_t *ctx, uint32_t ts) {

   if (!ctx) return;

   if (ctx->first_video_ts == 0)
      ctx->first_video_ts = ts;
   ctx->current_ts = ts;
   ctx->pts = (ctx->current_ts - ctx->first_video_ts)/90;
   ctx->dts = ctx->pts;
   return;
}

int
read_audio_frame(char* data, int size, char** pp, char** frame, int* frame_size) 
{
    char* p = *pp;
    
    // @remark, for this demo, to publish aac raw file to SRS,
    // we search the adts frame from the buffer which cached the aac data.
    // please get aac adts raw data from device, it always a encoded frame.
    if (!srs_aac_is_adts(p, size - (p - data))) {
        //srs_human_trace("aac adts raw data invalid.");
        return -1;
    }
    
    // @see srs_audio_write_raw_frame
    // each frame prefixed aac adts header, '1111 1111 1111'B, that is 0xFFF., 
    // for instance, frame = FF F1 5C 80 13 A0 FC 00 D0 33 83 E8 5B
    *frame = p;
    // skip some data. 
    // @remark, user donot need to do this.
    p += srs_aac_adts_frame_size(p, size - (p - data));
    
    *pp = p;
    *frame_size = p - *frame;
    if (*frame_size <= 0) {
        //srs_human_trace("aac adts raw data invalid.");
        return -1;
    }
    
    return 0;
}

int
snw_rtmp_send_audio_frame(snw_rtmp_ctx_t *ctx) {
   char sound_format = 10;
   // 0 = Linear PCM, platform endian
   // 1 = ADPCM
   // 2 = MP3
   // 7 = G.711 A-law logarithmic PCM
   // 8 = G.711 mu-law logarithmic PCM
   // 10 = AAC
   // 11 = Speex
   char sound_rate = 2; // 2 = 22 kHz
   char sound_size = 1; // 1 = 16-bit samples
   char sound_type = 1; // 1 = Stereo sound
   int ret = 0;

   if (!ctx) {
      return -1;
   }
 
   //FIXME: this loop leads to infinite in some scenario!!!
   while (ctx->audio_ts < ctx->pts) { 
      if (ctx->audio_pos < ctx->audio_raw + ctx->file_size) {
        char* data = NULL;
        int size = 0;
        if (read_audio_frame(ctx->audio_raw, ctx->file_size, 
               &ctx->audio_pos, &data, &size) < 0) {
            RTMP_ERROR("read a frame from file buffer failed.");
            return -2;
        }
        
        ctx->audio_ts += ctx->delta_ts;
        
        if ((ret = srs_audio_write_raw_frame(ctx->rtmp, 
            sound_format, sound_rate, sound_size, sound_type,
            data, size, ctx->audio_ts)) != 0
        ) {
            RTMP_ERROR("send audio raw data failed. ret=%d", ret);
            return -3;
        }
        
        RTMP_DEBUG("sent packet: type=%s, time=%d, size=%d, codec=%d, rate=%d, sample=%d, channel=%d", 
            srs_human_flv_tag_type2string(SRS_RTMP_TYPE_AUDIO), ctx->audio_ts, size, 
            sound_format, sound_rate, sound_size, sound_type);
        
      }
   }
 
   if (ctx->audio_pos >= ctx->audio_raw + ctx->file_size) {
      ctx->audio_pos = ctx->audio_raw;
   }

   return 0;
}


int
snw_rtmp_handle_pkg(snw_rtmp_ctx_t *ctx, char *buf, int buflen) {
   static char data[MAX_BUFFER_SIZE];
   static char sync_bytes[4] = { 0x00, 0x00, 0x00, 0x01};
   int ret;

   if (!ctx || !buf || buflen <= 0) {
      return -1;
   }

   memcpy(data,sync_bytes,4); 
   memcpy(data+4,buf,buflen);

   // send out the h264 packet over RTMP
   RTMP_DEBUG("send h264 frame, len=%u, dts=%u", buflen+4, ctx->dts);
   ret = srs_h264_write_raw_frames(ctx->rtmp, data, buflen+4, ctx->dts, ctx->pts);
   if (ret != 0) {
      if (srs_h264_is_dvbsp_error(ret)) {
         RTMP_DEBUG("rtmp: ignore drop video error, code=%d", ret);
      } else if (srs_h264_is_duplicated_sps_error(ret)) {
         RTMP_DEBUG("rtmp: ignore duplicated sps, code=%d", ret);
      } else if (srs_h264_is_duplicated_pps_error(ret)) {
         RTMP_DEBUG("rtmp: ignore duplicated pps, code=%d", ret);
      } else {
         RTMP_ERROR("rtmp: send h264 raw data failed. ret=%d", ret);
         return -2;
      }
   }
   
   snw_rtmp_send_audio_frame(ctx);

   return 0;
}


