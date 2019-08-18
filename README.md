Snowem is a lightweight live streaming server, based on webrtc technology. Snowem has three built-in subsystems. 

 * `RESTful Web Service` is used for channel management.
 * `Websocket Sevrer` plays a role of signaling service in WebRTC stack.
 * `Media Server` is basically SFU in WebRTC stack, it handles ICE protocol and forward media streams among peers.

## Compile and setup Snowem

Snowem depends on the following libraries to build:  

 * libopenssl.  
 * libevent v2.1.xxx with openssl support.  
 * libnettle.  
 * libsofia-sip-ua.  
 * libsrtp.  
 * libconfig.
 * libbsd

Notes: 

 * on Ubuntu system, one may install the following packages:

```
apt-get install libbsd-dev libbsd0 libssl1.0.0 libssl-dev libevent-dev \
libsofia-sip-ua-dev libsofia-sip-ua0 libsrtp0 libsrtp0-dev libnettle6 \
nettle-dev libconfig9 libconfig-dev libbsd0 libbsd-dev
```
 
 * for installing libevent 2.1.xx, one may do the following:  
 
```
wget https://github.com/libevent/libevent/releases/download/release-2.1.8-stable/libevent-2.1.8-stable.tar.gz
tar xfz libevent-2.1.8-stable.tar.gz 
cd libevent-2.1.8-stable
./configure --prefix=/usr/local
make && make install
```

 * on Ubuntu system, supporting ffmpeg requires to install the following packages:

```
apt-get install libavutil-dev libavresample-dev libavfilter-dev\
libavdevice-dev libavcodec-dev libavformat-dev
```

To build Snowem, execute the following commands: 

```
git clone https://github.com/snowem/snowem.git
cd snowem
git submodule init
git submodule update
mkdir build
cd build
cmake ..
make
make install
```

## Run Snowem

The configuration file is written in format of libconfig. The sample file is available at [snowem.conf](https://github.com/snowem/snowem/blob/master/conf/snowem.conf).

```
# General settings
cert_file = "<path-to-cert-file>"
key_file = "<path-to-key-file>"

# Websocket settings
wss_bind_ip = "0.0.0.0"
wss_bind_port = 8443

# Log level: TRACE=0, DEBUG=1, INFO=2, WARN=3, ERROR=4, FATAL=5
log_level = 1
log_file_maxsize = 10000000
log_rotate_num = 10
base_log_path = "<path-to-dir>"
```
To run Snowem, simple execute:
```
snowem <path-to>/snowem.conf
```
Check live demo at [here](https://snowem.io/).

## Example

Source code of example is available at [here](https://github.com/snowem/sdkjs/example).

**To publish atream**: if no camera available, then video file can be used as media source, check [here](https://github.com/snowem/sdkjs/example).

```
var config = {
    'type': 'camera',
    'localNode': document.getElementById('localVideo'),
    'remoteNode':  document.getElementById('remoteVideo'),
    'media': {
      'audio': true,
      'video': true,
    },
  }
  var publishStream = new snowem.Stream(host, 8443)
  publishStream.publish(config)
```

**To play a remote stream**: to play a remote stream, you need stream id of the remote stream.

```
var config = {
  'streamid': streamId,
  'remoteNode':  document.getElementById('remoteVideo'),
  'audio': true,
  'video': true
 };
var playStream = new snowem.Stream(host, 8443)
playStream.play(config)
```

