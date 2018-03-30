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







