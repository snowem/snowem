/*
 * (C) Copyright 2015 Jackie Dinh <jackiedinh8@gmail.com>
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

#define _WITH_DPRINTF
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>

#include "log.h"

int
snw_log_open_file(snw_log_t *log, int mode) {

  if (!log) return -1;
  log->_fd = open(log->_log_file_name, mode, 0666);
  if (log->_fd < 0) {
    return -1;
  }
  
  log->_current_size = lseek(log->_fd,0,SEEK_END);
  return 0;
}

char*
snw_get_file_name(snw_log_t *log, int idx) {
  char *buf;
  int len = 0;
  int n_idx = idx;
  int digits = 0;

  if (idx==0)
    return strdup(log->_log_file_name);

  while (n_idx != 0 ) {
    n_idx = n_idx / 10;
    digits++;
  }

  len = strlen(log->_log_file_name) + digits + 2;
  buf = (char*)malloc(len);
  if (!buf) return 0;
  memset(buf,0,len);
  snprintf(buf,len,"%s.%d", log->_log_file_name, idx);
  return buf;
}

void
snw_log_rotate_file(snw_log_t *log, int idx) {
  char *filename = 0;
  char *newfilename = 0;

  if (idx < log->_rotate_num) {
    snw_log_rotate_file(log,idx+1);
    filename = snw_get_file_name(log,idx);
    newfilename = snw_get_file_name(log,idx+1);
    rename(filename,newfilename);
  } else {
    filename = snw_get_file_name(log,idx);
    remove(filename);
  }

  if (filename) free(filename);
  if (newfilename) free(newfilename);
  return;
}

snw_log_t*
snw_log_init(const char* filename, uint32_t level,
    uint32_t rotate_num, size_t size_limit) {
  snw_log_t *log;
  int ret = 0;
  int len = 0;
  char *dir_name;
  char *abs_file_name;

  log = (snw_log_t*) malloc(sizeof(*log));
  if (!log) return 0;
  memset(log, 0, sizeof(*log));

  // other settings
  log->_level = level;
  log->_rotate_num = rotate_num;
  log->_size_limit = size_limit;
  log->_log_file_name = strdup(filename);
  log->_current_size = 0;
  log->_current_index = 0;
   
  ret = snw_log_open_file(log,O_WRONLY|O_APPEND);
  if (ret < 0) {
    ret = snw_log_open_file(log,O_CREAT|O_TRUNC|O_WRONLY);
    if (ret < 0) {
      if(log) free(log);
      return 0;  
    }
  }

  return log;
}

void
snw_log_write(snw_log_t *log, uint32_t level, const char* source, 
    int line, const char* msg, ...) {
  static char dest[4*1024] = {0};
  static const char* level_str[] = 
        {"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"};
  static char timebuf[32];
  size_t len = 0;
  time_t t;
  struct tm *lt = 0;
  va_list argptr;

  if (log == NULL) return;
  if (log->_fd == -1) return;

  if (level >= log->_level) {
    if (log->_size_limit != 0 && log->_current_size >= log->_size_limit) {
      snw_log_rotate_file(log,0);
      snw_log_open_file(log,O_CREAT|O_TRUNC|O_WRONLY);
    }

    t = time(NULL);
    lt = localtime(&t);
    if (!lt) return;
    len = strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", lt);
    timebuf[len] = '\0';

    va_start(argptr, msg);
    len += vsnprintf(dest, 4*1024, msg, argptr);
    va_end(argptr);

    dprintf(log->_fd, "[%s %s %s:%d]: %s\n", timebuf,
      level_str[level], source, line, dest);
    //FIXME: bad estimate len
    log->_current_size += len + ESTIMATED_HEADLOG_LEN;
  }

  return;
}

void 
snw_log_write_pure(snw_log_t *log, uint32_t level, const char* msg, ...) {
  static char dest[4*1024] = {0};
  size_t len = 0;

  if (log == NULL)
    return;

  if (log->_fd == -1)
    return;

  if (level >= log->_level) {
    if (log->_size_limit != 0 && log->_current_size >= log->_size_limit) {
      snw_log_rotate_file(log,0);
      snw_log_open_file(log,O_CREAT|O_TRUNC|O_WRONLY);
    }

    va_list argptr;
    va_start(argptr, msg);
    len = vsnprintf(dest, 4*1024, msg, argptr);
    va_end(argptr);
    dprintf(log->_fd, "%s\n", dest);
    log->_current_size += len + ESTIMATED_HEADLOG_LEN;
  }

  return;
}
