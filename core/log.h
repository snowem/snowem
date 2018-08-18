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

#ifndef _SNOW_CORE_LOG_H_
#define _SNOW_CORE_LOG_H_

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <stdio.h>
#include <sys/time.h>

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {           
	SNW_TRACE = 0,
  SNW_DEBUG = 1,
	SNW_INFO  = 2,
  SNW_WARN  = 3,
  SNW_ERROR = 4,
  SNW_FATAL = 5
};

#define ESTIMATED_HEADLOG_LEN 32

struct snw_log {
   int             _fd;
   uint32_t        _level;
   uint32_t        _rotate_num;
   size_t          _size_limit;
   size_t          _current_size;
   const char*     _log_file_name;
   int             _current_index;
};

snw_log_t*
snw_log_init(const char* filename, uint32_t level, uint32_t rotate_num, size_t size_limit);

void 
snw_log_write(snw_log_t *log, uint32_t level, const char* sourcefilename, int line, const char* msg, ...);

void 
snw_log_write_pure(snw_log_t *log, uint32_t level, const char* msg, ...);

#define LOG(_log_,_level_,fmt, ...) \
{ snw_log_write(_log_,_level_,__FUNCTION__, __LINE__,fmt, ##__VA_ARGS__); }
//{ snw_log_write(_log_,_level_,__FILE__, __LINE__,fmt, ##__VA_ARGS__); }

//#define TEMPLATE(_log_,_fmt, ...) do {} while(0)
#define TRACE(_log_,_fmt, ...) do {LOG(_log_, SNW_TRACE,_fmt,##__VA_ARGS__);} while(0)
#define INTO(_log_,_fmt, ...) do {LOG(_log_, SNW_INFO,_fmt,##__VA_ARGS__);} while(0)
#define DEBUG(_log_,_fmt, ...) do {LOG(_log_, SNW_DEBUG,_fmt,##__VA_ARGS__);} while(0)
#define WARN(_log_,_fmt, ...)  do {LOG(_log_, SNW_WARN,_fmt,##__VA_ARGS__);} while(0)
#define ERROR(_log_,_fmt, ...) do {LOG(_log_, SNW_ERROR,_fmt,##__VA_ARGS__);} while(0)
#define FATAL(_log_,_fmt, ...) do {} while(0)


#define WSS_DEBUG(...)  do {} while(0)
#define WSS_ERROR(...)  do {} while(0)

#ifdef __cplusplus
}
#endif

#endif // _SNOW_CORE_LOG_H_
