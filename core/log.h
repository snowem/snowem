/*
 * Copyright (c) 2015 Jackie Dinh <jackiedinh8@gmail.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *  1 Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  2 Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution.
 *  3 Neither the name of the <organization> nor the 
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY 
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @(#)log.h
 */

#ifndef _SNOW_CORE_LOG_H_
#define _SNOW_CORE_LOG_H_

#include <string.h>
#include <dirent.h>
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

#define TRACE(_log_,_fmt, ...) do {} while(0)
#define INFO(_log_,_fmt, ...)  do {} while(0)
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
