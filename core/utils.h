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

#ifndef _SNOW_CORE_UTILS_H_
#define _SNOW_CORE_UTILS_H_

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define NTP_EPOCH_DIFF 2208988800000L

void print_buffer(char *p, int len, const char *prefix);
char* trimwhitespace(char *str);
char* ip_to_str(unsigned int ip);
int64_t get_ntp_time(void);
int64_t get_epoch_time(void);
int64_t get_monotonic_time(void);
int create_dir(const char *dir, mode_t mode);

#endif // _UTILS_H_







