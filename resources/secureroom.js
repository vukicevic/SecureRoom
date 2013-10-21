/**
 * SecureRoom - Encrypted web browser based text communication software
 * Copyright (C) 2013 Nenad Vukicevic
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 **/

var app = {
  keychain: {},
  keymap: {},
  rejected: {},
  keysize: 1024,
  ciphersize: 128,
  nickname: null,
  signkey: null,
  encryptkey: null,
  myid: null,
  messages: 0,
  room: '',
  server: '',

  cbKeygen: null,

  setCallbacks: function(g) {
    this.cbKeygen = g;
  },

  completeKeyGeneration: function() {
    if (app.signkey.ready && app.encryptkey.ready) {
      var key = new PublicKey({ "name": app.nickname,
                                "encrypt": { "type": 2,
                                             "created": app.encryptkey.time, 
                                             "mpi": { "e": app.encryptkey.mpi.e,
                                                      "n": app.encryptkey.mpi.n} },
                                "sign": {"type": 3,
                                         "created": app.signkey.time,
                                         "mpi": { "e": app.signkey.mpi.e,
                                                  "n": app.signkey.mpi.n} } });

      app.myid = key.sign.id;
      app.keychain[app.myid] = key;
      app.keymap[key.encrypt.id] = app.myid;

      if (app.room == '') app.room = app.myid.substr(-8);
      app.cbKeygen();
    } else {
      window.setTimeout("app.completeKeyGeneration()", 200);
    }
  },

  generateKeys: function(nick) {
    this.nickname   = nick.replace(/[`~!@#$%^&*()_|+\-=?;:'",.<>\{\}\[\]\\\/]/gi, '');
    this.signkey    = new Keygen(this.keysize);
    this.encryptkey = new Keygen(this.keysize);

    this.completeKeyGeneration();
  },

  getServer: function() {
    return (app.getParameter('server')) ? 'wss://'+app.getParameter('server')+':443/ws/' : 'wss://'+document.location.host+':443/ws/';
  },
  
  getRoom: function() {
    var path = window.location.pathname.substr(window.location.pathname.lastIndexOf('/')+1);
    if (path == 'index.html') {
      path = (app.getParameter('room')) ?  app.getParameter('room') : '';
    }    
    return path;
  },
  
  getParameter: function(name) {
    var match = RegExp('[?&]' + name + '=([^&]*)').exec(window.location.search);
    return match && decodeURIComponent(match[1].replace(/\+/g, ' '));
  }
}

var comm = {
  socket: null,
  connected: false,

  cbConnect: null,
  cbDisconnect: null,
  cbMessage: null,
  cbKey: null,

  setCallbacks: function(o, c, m, k) {
    this.cbConnect = o;
    this.cbDisconnect = c;
    this.cbMessage = m;
    this.cbKey = k;
  },

  connect: function() {
    try {
      this.socket = new WebSocket(app.server+app.room);
      this.socket.onopen = function() {
        comm.connected = true;
        comm.cbConnect();
        comm.sendKey();
      }

      this.socket.onmessage = function(event){
        var obj = JSON.parse(event.data);
        console.log(obj);
        if (obj.type == 'key') {
            var key = comm.receiveKey(obj.data);
            if (typeof app.keychain[key.sign.id] == "undefined" && typeof app.rejected[key.sign.id] == "undefined") comm.cbKey(key);
        } else if (obj.type == 'message') {
            comm.cbMessage(comm.receiveMessage(obj.data));
        }
      }

      this.socket.onclose = function(){
        comm.connected = false;
        comm.cbDisconnect();
      }
    } catch (e) {
      console.log(e);
    }
  },

  encryptMessage: function(message) {
    var padkey, 
        keyid,
        paddata,
        count = 0;

    if (Object.keys(app.keychain).length < 2) return null;

    for (keyid in app.keychain) {
      if (app.myid != keyid && app.keychain[keyid].active) {
        message.encrypted.sessionkeys[app.keychain[keyid].encrypt.id] = asymmetric.encrypt(app.keychain[keyid].encrypt, message.plaintext.sessionkey);
        count++;
      }
    }

    if (count == 0) return null;

    //random x+2 octets & plaintext, where x is block size
    paddata = random.generate(app.ciphersize);
    paddata = paddata.concat(paddata.slice(-2)).concat(message.plaintext.data);
    return symmetric.encrypt(message.plaintext.sessionkey, paddata);
  },

  decryptMessage: function(message) {
    var keyid, 
        padkey;

    for (keyid in message.encrypted.sessionkeys) {
      if (keyid == app.keychain[app.myid].encrypt.id) {
         message.plaintext.sessionkey = asymmetric.decrypt(app.encryptkey, message.encrypted.sessionkeys[keyid]);
         break;
      }
    }

    if (message.plaintext.sessionkey) {
      //discard x+2 random data, should check (x-1 == x+1 && x ==x+2)
      return symmetric.decrypt(message.plaintext.sessionkey, message.encrypted.data).slice(message.plaintext.sessionkey.length+2);
    } else {
      return null;
    }
  },

  sendMessage: function(text) {
    var message = new Message();

    message.metadata.sendtime = Math.round(+new Date()/1000);
    message.metadata.recvtime = message.metadata.sendtime;
    message.metadata.sender = app.keychain[app.myid].sign.id;

    message.plaintext.string = text;
    message.plaintext.data = array.fromString(text).concat(0).concat(array.fromWord(message.metadata.sendtime)).concat(array.fromHex(message.metadata.sender));

    message.metadata.signature = asymmetric.sign(app.signkey, message.plaintext.data);
    message.metadata.verified = true;

    message.plaintext.data = message.plaintext.data.concat(message.metadata.signature);
    message.encrypted.data = this.encryptMessage(message);

    //console.debug(message);

    if (message.encrypted.data != null) {
      var str = JSON.stringify({"type": "message",
                                "data": message.encrypted});
      console.log(str);
      this.socket.send(str);
    }

    return message;
  },

  receiveMessage: function(data) {
    var message = new Message(data),
        i;

    message.metadata.recvtime = Math.round(+new Date()/1000);
    message.plaintext.data = this.decryptMessage(message);

    if (message.plaintext.data == null) return null;
    i = message.plaintext.data.indexOf(0);

    message.plaintext.string   = array.toString(message.plaintext.data.slice(0, i));
    message.metadata.sendtime  = array.toWord(message.plaintext.data.slice(i+1, i+5));
    message.metadata.sender    = array.toHex(message.plaintext.data.slice(i+5, i+13));
    message.metadata.signature = message.plaintext.data.slice(i+13);

    if (typeof app.keychain[message.metadata.sender] == 'undefined') return null; //messages from rejected and unknown senders will be ignored at this point

    message.metadata.verified  = asymmetric.verify(app.keychain[message.metadata.sender].sign, message.plaintext.data.slice(0,i+13), message.metadata.signature);

    //console.debug(message);

    return message;
  },

  sendKey: function() {
    var str = JSON.stringify({"type": "key",
                              "data": { "name":    app.keychain[app.myid].name,
                                        "encrypt": { "type": app.keychain[app.myid].encrypt.type,
                                                      "created": app.keychain[app.myid].encrypt.created,
                                                      "mpi": app.keychain[app.myid].encrypt.mpi },
                                        "sign":    { "type": app.keychain[app.myid].sign.type,
                                                     "created": app.keychain[app.myid].sign.created,
                                                     "mpi": app.keychain[app.myid].sign.mpi } } });

    this.socket.send(str);
  },

  receiveKey: function(data) {
    return new PublicKey(data);
  }
}

var array = {
  toString: function(input) {
    var out = '',
      i = 0,
      c1, c2, c3;

    while (i < input.length) {
      c1 = input[i++];
      if (c1 < 128) {
        out += String.fromCharCode(c1);
      } else if((c1 > 191) && (c1 < 224)) {
        c2 = input[i++];
        out += String.fromCharCode(((c1 & 0x1f) << 6) | (c2 & 0x3f));
      } else {
        c2 = input[i++];
        c3 = input[i++];
        out += String.fromCharCode(((c1 & 0x0f) << 12) | ((c2 & 0x3f) << 6) | (c3 & 0x3f));
      }
    }
    return out;
  },

  fromString: function(input) {
    for (var c, j = 0, out = [], i = 0; i < input.length; i++) {
      c = input.charCodeAt(i);
      if ( c < 128 ) {
        out[j++] = c;
      } else if ( (c > 127) && (c < 2048) ) {
        out[j++] = (c >> 6) | 192;
        out[j++] = (c & 0x3f) | 128;
      } else {
        out[j++] = (c >> 12) | 224;
        out[j++] = ((c >> 6) & 0x3f) | 128;
        out[j++] = (c & 0x3f) | 128;
      }
    }
    return out;
  },

  toHex: function(a) {
    for (var o = '', i = 0; i < a.length; i++) {
      o += ('0'+a[i].toString(16)).substr(-2);
    }
    return o;
  },

  fromHex: function(h) {
    return h.match(/.{2}/g).map(function(v) {
      return parseInt(v, 16);
    });
  },

  toWord: function(a) {
    return (a[0]*16777216 + a[1]*65536 + a[2]*256 + a[3]);
  },

  fromWord: function(t) {
    return [t>>24, (t>>16)&0xff, (t>>8)&0xff, t&0xff];
  },
}

function PublicKey(data) {
  this.name    = '';
  this.encrypt = null;
  this.sign    = null;
  this.active  = true;

  this.calcMpiLength = function(mpi, bits) {
    for (var i = 0, m = 128; i < 8; i++, m /= 2) {
      if (mpi[0] >= m) break;
    }

    m = mpi.length*8 - i;

    return (bits) ?  m : [m >> 8, m & 0xff];
  }

  this.calcFingerprint = function(data, iskey) {
    if (iskey) {
      data = [4].concat(array.fromWord(data.created)).concat([data.type]).concat(this.calcMpiLength(data.mpi.n)).concat(data.mpi.n).concat(this.calcMpiLength(data.mpi.e)).concat(data.mpi.e);
    }

    return array.toHex(hash.digest([0x99, (data.length >> 8), (data.length & 0xff)].concat(data)));
  }

  this.calcKeyInfo = function(key) {
    key.size        = this.calcMpiLength(key.mpi.n, true);
    key.fingerprint = this.calcFingerprint(key, true);
    key.id          = key.fingerprint.substr(-16);
  }

  if (typeof data != 'undefined') {
    this.name = data.name;
    
    this.encrypt = data.encrypt;
    this.calcKeyInfo(this.encrypt);

    this.sign = data.sign;
    this.calcKeyInfo(this.sign);
  }
}

function Message(message) {
  this.encrypted = {sessionkeys: {}, data: []};
  this.plaintext = {sessionkey: null, data: null, string: null};
  this.metadata  = {sender: null, signature: null, sendtime: null, recvtime: null, verified: false};

  if (typeof message == 'undefined') {
    this.plaintext.sessionkey = random.generate(app.ciphersize);
  } else {
    this.encrypted = message;
  }
}