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

#define DECLARE_MODULE(name) &(g_rtp_##name##_module),

#ifdef USE_MODULE_COMMON
DECLARE_MODULE(nack)
DECLARE_MODULE(audio)
DECLARE_MODULE(video)
DECLARE_MODULE(rtcp)
DECLARE_MODULE(record)
#endif //USE_MODULE_COMMON

#ifdef USE_MODULE_AUDIO
//DECLARE_MODULE(record)
#endif //USE_MODULE_AUDIO

#ifdef USE_MODULE_VIDEO
//DECLARE_MODULE(record)
//DECLARE_MODULE(h264)
#endif //USE_MODULE_VIDEO

#ifdef USE_MODULE_H264
DECLARE_MODULE(rtmp)
#endif //USE_MODULE_H264

#ifdef USE_MODULE_RTCP
#endif //USE_MODULE_RTCP

