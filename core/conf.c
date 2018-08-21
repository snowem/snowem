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

#include <libconfig.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>

#include "core.h"
#include "conf.h"

void
snw_config_init(snw_context_t *ctx, const char *file) {
   config_t cfg;
   config_setting_t *setting;
   const char *str;
   int number;

   config_init(&cfg);
   if (!config_read_file(&cfg, file)) {
      fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
            config_error_line(&cfg), config_error_text(&cfg));
      config_destroy(&cfg);
      exit(0);
   }

   if (config_lookup_string(&cfg, "ice_cert_file", &str)) {
      ctx->ice_cert_file = strdup(str);
   } else {
      fprintf(stderr,"ice_cert_file %s not found\n", str);
      exit(0);
   }

   if (config_lookup_string(&cfg, "ice_key_file", &str)) {
      ctx->ice_key_file = strdup(str);
   } else {
      fprintf(stderr,"ice_key_file %s not found\n", str);
      exit(0);
   }

   if (config_lookup_string(&cfg, "wss_cert_file", &str)) {
      ctx->wss_cert_file = strdup(str);
   } else {
      fprintf(stderr,"wss_cert_file %s not found\n", str);
      exit(0);
   }

   if (config_lookup_string(&cfg, "wss_key_file", &str)) {
      ctx->wss_key_file = strdup(str);
   } else {
      fprintf(stderr,"wss_key_file %s not found\n", str);
      exit(0);
   }

   if (config_lookup_int(&cfg, "wss_bind_port", &number)) {
      ctx->wss_port = (uint16_t)number;
   } else {
      fprintf(stderr,"wss_bind_port not found\n");
      exit(0);
   }

   if (config_lookup_string(&cfg, "wss_bind_ip", &str)) {
      ctx->wss_ip = strdup(str);
   } else {
      fprintf(stderr,"wss_bind_ip not found\n");
      exit(0);
   }

   //// Debug leve: TRACE: 0, DEBUG: 1, INFO: 2, WARN: 3, ERROR: 4, FATAL: 5
   if (config_lookup_int(&cfg, "log_level", &number)) {
      ctx->log_level = number;
   } else {
      ctx->log_level = 3;
   }

   if (config_lookup_int(&cfg, "log_rotate_num", &number)) {
      ctx->log_rotate_num = number;
   } else {
      ctx->log_rotate_num = 10;
   }

   if (config_lookup_int(&cfg, "log_file_maxsize", &number)) {
      ctx->log_rotate_num = number;
   } else {
      ctx->log_rotate_num = 10000000;
   }

   if (config_lookup_int(&cfg, "ice_log_enabled", &number)) {
      ctx->ice_log_enabled = number;
   } else {
      ctx->ice_log_enabled = 0;
   }

   if (config_lookup_string(&cfg, "main_log", &str)) {
      ctx->main_log_file = strdup(str);
      ctx->base_log_path = strdup(dirname(strdup(str)));
   } else {
      fprintf(stderr,"main_log %s not found\n", str);
      exit(0);
   }

   if (config_lookup_string(&cfg, "ice_log", &str)) {
      ctx->ice_log_file = strdup(str);
   } else {
      fprintf(stderr,"main_log %s not found\n", str);
      exit(0);
   }

   if (config_lookup_int(&cfg, "websocket_log_enabled", &number)) {
      ctx->websocket_log_enabled = number;
   } else {
      ctx->websocket_log_enabled = 0;
   }

   if (config_lookup_string(&cfg, "websocket_log_file", &str)) {
      ctx->websocket_log_file = strdup(str);
   } else {
      if (ctx->websocket_log_enabled != 0) {
        int len = strlen(ctx->base_log_path) + strlen("/snowem_websocket.log") + 1;
        char *tmp = (char*) malloc(len);
        if (tmp) {
          snprintf(tmp,len,"%s%s",ctx->base_log_path,"/snowem_websocket.log");
          tmp[len] = '\0';
          ctx->websocket_log_file = tmp;
        } else {
          ctx->websocket_log_file = 0;
        }
      } else {
        ctx->websocket_log_file = 0;
      }
   }

   if (config_lookup_int(&cfg, "http_log_enabled", &number)) {
      ctx->http_log_enabled = number;
   } else {
      ctx->http_log_enabled = 0;
   }

   if (config_lookup_string(&cfg, "http_log_file", &str)) {
      ctx->http_log_file = strdup(str);
   } else {
      if (ctx->http_log_enabled != 0) {
        int len = strlen(ctx->base_log_path) + strlen("/snowem_http.log") + 1;
        char *tmp = (char*) malloc(len);
        if (tmp) {
          snprintf(tmp,len,"%s%s",ctx->base_log_path,"/snowem_http.log");
          tmp[len] = '\0';
          ctx->http_log_file = tmp;
        } else {
          ctx->http_log_file = 0;
        }
      } else {
        ctx->http_log_file = 0;
      }
   }

   if (config_lookup_int(&cfg, "http_log_enabled", &number)) {
      ctx->http_log_enabled = number;
   } else {
      ctx->http_log_enabled = 0;
   }

   if (config_lookup_int(&cfg, "recording_enabled", &number)) {
      ctx->recording_enabled = number;
   } else {
      ctx->recording_enabled = 0;
   }

   if (config_lookup_string(&cfg, "recording_folder", &str)) {
      ctx->recording_folder = strdup(str);
   } else {
      if (ctx->recording_enabled != 0) {
        fprintf(stderr,"recording_folder not found\n");
        ctx->recording_folder = 0;
      }
   }

   setting = config_lookup(&cfg, "modules");
   if (setting != NULL) {
      snw_module_t *module;
      const char *name, *sofile;
      int type;
      int count = config_setting_length(setting);
      int i;

      for (i = 0; i < count; ++i) {
         config_setting_t *elem = config_setting_get_elem(setting, i);
         if (!(config_setting_lookup_string(elem,"name",&name) 
               && config_setting_lookup_string(elem,"sofile",&sofile)
               && config_setting_lookup_int(elem,"type",&type)))
            continue;

         module = (snw_module_t*)malloc(sizeof(snw_module_t));
         if (!module) return;
         module->name = strdup(name);
         module->type = type;
         module->sofile = strdup(sofile);
         LIST_INSERT_HEAD(&ctx->modules,module,list);
      }
   }

   return;
}





