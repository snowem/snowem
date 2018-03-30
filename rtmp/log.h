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

#ifndef _RTMP_LOG_H_
#define _RTMP_LOG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <dirent.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <stdio.h>
#include <sys/time.h>

enum {           
   RTMP_LOG_DEBUG = 0,
	RTMP_LOG_INFO = 1,
   RTMP_LOG_WARN = 2,
   RTMP_LOG_ERROR = 3,
   RTMP_LOG_FATAL = 4
};

#define RTMP_FUNCLINE "%s:%u"
#define RTMP_DEBUG(fmt, ...) \
{  rtmp_log(RTMP_LOG_DEBUG, RTMP_FUNCLINE "[RTMP_DEBUG]: " fmt, __FUNCTION__,__LINE__, ##__VA_ARGS__); }
#define RTMP_INFO(fmt, ...) \
{  rtmp_log(RTMP_LOG_INFO, RTMP_FUNCLINE "[RTMP_INFO]: " fmt , __FUNCTION__,__LINE__, ##__VA_ARGS__); }
#define RTMP_ERROR(fmt, ...) \
{  rtmp_log(RTMP_LOG_ERROR, RTMP_FUNCLINE "[RTMP_ERROR]: " fmt, __FUNCTION__,__LINE__, ##__VA_ARGS__); }

typedef void (*rtmp_log_cb)(int severity, const char *msg, void *data);
void rtmp_set_log_callback(rtmp_log_cb cb, void *data);
void rtmp_log(int severity, const char* msg, ...);

#ifdef __cplusplus
}
#endif

#endif // _RTMP_LOG_H_


