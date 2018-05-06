Snowem is a lightweight live streaming server, based on webrtc technology. Basically, a video stream is identified by a channel id - an integer. Snowem has three built-in subsystems, which are designed for developers to easily integrate video streams into their applictions. 

 * `RESTful Web Service` is used for channel management.
 * `Websocket Sevrer` plays a role of signaling service in WebRTC stack.
 * `Media Server` is basically SFU in WebRTC stack, it handles ICE protocol and forward media streams among peers.

Check [the official site](https://snowem.io/) for more details and demo.

Let's start to setup Snowem.

## Compile and setup Snowem

Snowem depends on the following libraries to build:  

 * libopenssl.  
 * libevent v2.1.xxx with openssl support.  
 * libnettle.  
 * libsofia-sip-ua.  
 * libsrtp.  
 * libconfig.

Notes: 

 * on Ubuntu system, one may install the following packages:

```
apt-get install libbsd-dev libbsd0 libssl1.0.0 libssl-dev libevent-dev \
libsofia-sip-ua-dev libsofia-sip-ua0 libsrtp0 libsrtp0-dev libnettle6 \
nettle-dev libconfig9 libconfig-dev
```
 
 * for installing libevent 2.1.xx, one may do the following:  
 
```
wget https://github.com/libevent/libevent/releases/download/release-2.1.8-stable/libevent-2.1.8-stable.tar.gz
tar xfz libevent-2.1.8-stable.tar.gz 
cd libevent-2.1.8-stable
./configure --prefix=/usr/local
make && make install
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

## A Quick Start

Steps to integrate video streams using [javascript sdk](https://github.com/snowem/sdkjs).

**Step 1**: Integrate directly SnowSDK javascript sdk into your web application.    
When SnowSDK is loaded, it invokes _snowAsyncInit_ if it is defined. Once it is called, you can initlialize SnowSDK with _init_ function. The _init_ function requires domain name or ip address of Snowem Websocket Service.

```
(function(d){
  var js, id = 'snowsdk', ref = d.getElementsByTagName('script')[0];
  if (d.getElementById(id)) {return;}
  js = d.createElement('script'); js.id = id; js.async = true;
  js.src = "https://snowem.io/js/snowsdk.js";
  ref.parentNode.insertBefore(js, ref);
}(document));

window.snowAsyncInit = function() {
  var config = { 
    'ip': "your-wss-ip",
    'port': 443
  };  
  SnowSDK.init(config);
  start_app();
}

function start_app() {
  // start your code here
}
```

**Step 2**: Create a channel.  
To publish a video stream, one need to get a channel id from Snowem server. 

```
var config = { 
  'name': "snowem test room",
  'type': "broadcast"
  }   
function onSuccess(resp) {
  console.log("resp: " + resp.channelid);
  //for example, use channel id to publish your media stream
}
function onError(resp) {
  console.log("resp: " + resp);
}
SnowSDK.createChannel(config, onSuccess, onError);
```

**Step 3**: Create PeerAgent object.   
A PeerAgent object is used to establish connection to built-in websocket server and do all signaling part for WebRTC stack working.  

```
var config = { 
   'media_constraints' : { audio: true, 
                           video: {
                              mandatory:{
                                 maxWidth: 480,
                                 maxHeight: 270,
                                 minWidth: 480,
                                 minHeight: 270 
                          }}},
    'peerconnection_config' : {'iceServers':[{'urls':'stun:stun.l.google.com:19302',
                                                   'urls':'stun:stun1.l.google.com:19302'}],
                                    'iceTransports': 'all'},
    'sdp_constraints' : {'mandatory': {
         'OfferToReceiveAudio':true,
         'OfferToReceiveVideo':true }}
   }   
var peer = new SnowSDK.PeerAgent(config);
```

**Step 4**: Publish a video stream to a channel.   

After successful creating channel and PeerAgent object, one can publish a video stream.

``` javascript
var settings = { 
   'channelid': peer.channelId, 
   'local_video_elm': document.getElementById('localVideo')
};  
peer.onAddPeerStream = function(info) {
  console.log("peerid: ", info.peerid);
  //make use of remote stream
  //remote_video_elm.srcObject = info.stream;
}
peer.onRemovePeerStream = function(info) {
  console.log("removing stream from peerid: " + info.peerid);
}
peer.publish(settings);
```

**Step 5**: Play a video stream  

One can play a video stream with a given channel id.

```
peer.play(channelid);
```

### Further Resource

Check out our javascript sdk [here](https://github.com/snowem/sdkjs) for more examples.   
For full documentation, check [here](https://docs.snowem.io/).  

