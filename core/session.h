#ifndef _SNOW_CORE_SESSION_H_
#define _SNOW_CORE_SESSION_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct snw_session snw_session_t;
struct snw_session {
   uint32_t       sessionid;
   uint32_t       flowid;
};

#ifdef __cplusplus
}
#endif

#endif //_SNOW_CORE_CONNECTION_H_



