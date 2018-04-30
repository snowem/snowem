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

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <time.h>

#include "log.h"
#include "utils.h"

void
print_buffer(char *p, int len, const char *prefix)
{
   char buf[128];
   int i, j, i0; 

   if ( p == 0 ) { 
      printf("null pointer\n");
      return;
   }   
   /* get the length in ASCII of the length of the packet. */

   /* hexdump routine */
   for (i = 0; i < len; ) { 
      memset(buf, sizeof(buf), ' ');
      sprintf(buf, "%5d: ", i); 
      i0 = i;  
      for (j=0; j < 16 && i < len; i++, j++) 
         sprintf(buf+7+j*3, "%02x ", (uint8_t)(p[i]));
      i = i0; 
      for (j=0; j < 16 && i < len; i++, j++) 
         sprintf(buf+7+j + 48, "%c",
            isprint(p[i]) ? p[i] : '.');
      printf("%s: %s\n", prefix, buf);
   }   
}

char*
trimwhitespace(char *str)
{
  char *end;

  // Trim leading space
  while(isspace(*str)) str++;

  if(*str == 0)  // All spaces?
    return str;

  // Trim trailing space
  end = str + strlen(str) - 1;
  while(end > str && isspace(*end)) end--;

  // Write new null terminator
  *(end+1) = 0;

  return str;
}

char* 
ip_to_str(unsigned int ip)
{       
   struct in_addr inaddr;
   inaddr.s_addr=ip;
   return (inet_ntoa(inaddr));
}       

int64_t get_ntp_time(void) {
   struct timespec ts; 
   clock_gettime (CLOCK_REALTIME, &ts);
   return ((ts.tv_sec + 2208988800L)*1000) + (ts.tv_nsec/(1000000));
} 

int64_t get_epoch_time(void) {
   struct timespec ts; 
   clock_gettime (CLOCK_REALTIME, &ts);
   return (ts.tv_sec*1000) + (ts.tv_nsec/(1000000));
}           

int64_t get_monotonic_time(void) {
   struct timespec ts; 
   clock_gettime (CLOCK_MONOTONIC, &ts);
   return (ts.tv_sec*((int64_t)1000)) + (ts.tv_nsec/((int64_t)1000000));
}

int create_dir(const char *dir, mode_t mode) {
   char tmp[256];
   char *p = NULL;
   size_t len;

   int res = 0;
   snprintf(tmp, sizeof(tmp), "%s", dir);
   len = strlen(tmp);
   if(tmp[len - 1] == '/')
      tmp[len - 1] = 0;
   for(p = tmp + 1; *p; p++) {
      if(*p == '/') {
         *p = 0;
         res = mkdir(tmp, mode);
         if(res != 0 && errno != EEXIST) {
            //ERROR("Error creating folder %s\n", tmp);
            return res;
         }
         *p = '/';
      }
   }
   res = mkdir(tmp, mode);
   if(res != 0 && errno != EEXIST)
      return res;
   return 0;
} 


