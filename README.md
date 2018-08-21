Snowem is a lightweight live streaming server, based on webrtc technology. Snowem has three built-in subsystems. 

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

// Recording settings
recording_enabled = 1
recording_folder = "/var/snowem/recordings"
```

Note: one may find configuration sample file at [snowem.conf](https://github.com/snowem/snowem/blob/master/conf/snowem.conf). To run Snowem, simple execute:

```
snowem <path-to>/snowem.conf
```
## Quick Demo
Assume snowem server runs on ip address x.y.z.t. Login to that server, if you do not have nodejs and express framework, install them:
```
curl -sL https://deb.nodesource.com/setup_8.x | sudo -E bash -
sudo apt-get install -y nodejs
```

Download demp application from [javascript sdk](https://github.com/snowem/sdkjs)and modify js/app.js to point to correct Snowem server by setting 'wss_ip' to x.y.z.t.

```
git clone https://github.com/snowem/sdkjs.git
cd sdkjs
npm install
node index.js
```
Open chrome browser on https://x.y.z.t:8000. Enjoy the demo.

## Quick Start

Steps to integrate video streams using [javascript sdk](https://github.com/snowem/sdkjs).

**Step 1**: Integrate directly SnowSDK javascript sdk into your web application.    
When SnowSDK is loaded, it invokes _snowAsyncInit_ if it is defined. Once it is called, you can initlialize SnowSDK with _init_ function. The _init_ function requires domain name or ip address of Snowem Websocket Service.

```
// put these lines in your html code.
<script type="text/javascript" src="js/adapter.js"></script>
<script type="text/javascript" src="js/snowsdk.js"></script>
```
```
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
**Step 2**: Create Stream object.   
Stream object is used to capture media content from camera or html video tag.
```
var config = {
  'audio': true,
  'video': true
 };
 var stream = new SnowSDK.Stream(config);
```

**Step 3**: Create a channel and publish/play a stream
Channel object is used to communicate with snowem server. Once a channel is obtained, local stream can be published on it or remote stream can be locally played.
```
function onSuccess(channel) {
  // channel object contain all needed info, see docs for details
  channel.listen("onConnected", function() {
   // after successfully connecting to snowem server, a stream can be published on the channel.
   channel.publish(existingStream);
  }); 

  channel.listen("onAddStream", function(stream) {
   // stream object contain media stream which can be play by channel.play
   channel.play(stream);
  }); 

  channel.listen("onRemoveStream", function(stream) {
   // stream object to be removed.
  }); 
  // connect channel to snowem server.
  channel.connect();  
}
function onError(resp) {
  console.log("resp: " + resp);
}
var config = { 
  'name': "test",
  'type': "conference",
  'key': "none"
}  
SnowSDK.createChannel(config, onSuccess, onError);
```
### Further Resource

Check out our javascript sdk [here](https://github.com/snowem/sdkjs) for more examples.   
For full documentation, check [here](https://docs.snowem.io/).  

