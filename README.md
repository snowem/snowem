Snowem is a lightweight live streaming server, based on webrtc technology. Snowem has three built-in subsystems. 

 * `RESTful Web Service` is used for channel management.
 * `Websocket Sevrer` plays a role of signaling service in WebRTC stack.
 * `Media Server` is basically SFU in WebRTC stack, it handles ICE protocol and forward media streams among peers.


### Live Demo

Check at [here](https://snowem.io/).

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

The configuration file is written in format of libconfig. To properly configure Snowem, one needs to provide certificates for both built-in websocket server and media server to establishing secure video streams. Basically, it looks like this:

```
//certificate used by built-in websocket server.
wss_cert_file = "<path-to>/wss_fullchain.pem"
wss_key_file = "<path-to>/wss_privkey.pem"
wss_bind_ip = "<ip_of_websocket_server>"
wss_bind_port = 443
//certificate used by media server.
ice_cert_file = "<path-to>/ice_fullchain.pem"
ice_key_file = "<path-to>/ice_privkey.pem"
// TRACE: 0, INFO: 1, DEBUG: 2, WARN: 3, ERROR: 4, FATAL: 5
log_level = 0
```

Note: one may find configuration sample file at [snowem.conf](https://github.com/snowem/snowem/blob/master/conf/snowem.conf). To run Snowem, simple execute:

```
snowem <path-to>/snowem.conf
```

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

