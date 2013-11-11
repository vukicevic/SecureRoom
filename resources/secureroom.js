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
      var key = new PublicKey({ name: app.nickname,
                                encrypt: { created: app.encryptkey.created, 
                                           mpi: { e: app.encryptkey.mpi.e, n: app.encryptkey.mpi.n }
                                         },
                                sign: { created: app.signkey.created,
                                        mpi: { e: app.signkey.mpi.e, n: app.signkey.mpi.n }
                                      }
                              });

      app.myid                   = key.sign.id;
      app.keychain[app.myid]     = key;
      app.keymap[key.encrypt.id] = app.myid;

      app.signkey.size    = key.sign.size;
      app.encryptkey.size = key.encrypt.size;

      if (app.room == '') app.room = app.myid.substr(-8);

      app.generateKeySignature();
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

  generateKeySignature: function() {
    var shsh = keytools.generateSignatureHash(app.keychain[app.myid].sign, app.nickname),
        ehsh = keytools.generateSignatureHash(app.keychain[app.myid].sign, app.keychain[app.myid].encrypt);

    app.keychain[app.myid].sign.signature    = asymmetric.sign(app.signkey, shsh, true);
    app.keychain[app.myid].encrypt.signature = asymmetric.sign(app.signkey, ehsh, true);
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
        switch (obj.type) {
        case 'key':
          var key = comm.receiveKey(obj.data);
          if (typeof app.keychain[key.sign.id] == "undefined" 
                && typeof app.rejected[key.sign.id] == "undefined")
                  comm.cbKey(key);

          break;
        case 'message':
          comm.cbMessage(comm.receiveMessage(obj.data));

          break;
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

  encryptMessage: function(message, data) {
    var keyid,
        paddata;

    if (Object.keys(app.keychain).length < 2) return null;

    for (keyid in app.keychain) {
      if (app.myid != keyid && app.keychain[keyid].active) {
        message.encrypted.keys[app.keychain[keyid].encrypt.id] = asymmetric.encrypt(app.keychain[keyid].encrypt, message.sessionkey);
      }
    }

    if (Object.keys(message.encrypted.keys).length == 0) return null;

    //random x+2 octets & plaintext, where x is block size
    paddata = random.generate(app.ciphersize);
    paddata = paddata.concat(paddata.slice(-2))
                     .concat(data);

    return symmetric.encrypt(message.sessionkey, paddata);
  },

  decryptMessage: function(message) {
    var keyid;

    for (keyid in message.encrypted.keys) {
      if (keyid == app.keychain[app.myid].encrypt.id) {
         message.sessionkey = asymmetric.decrypt(app.encryptkey, message.encrypted.keys[keyid]);
         break;
      }
    }

    if (message.sessionkey) {
      //discard x+2 random data, should check (x-1 == x+1 && x ==x+2)
      return symmetric.decrypt(message.sessionkey, message.encrypted.data)
                      .slice(message.sessionkey.length+2);
    } else {
      return null;
    }
  },

  sendMessage: function(text) {
    var rawdata, message = new Message();

    message.sendtime = Math.round(+new Date()/1000);
    message.recvtime = message.sendtime;
    message.sender   = app.myid;

    message.plaintext = text;
    rawdata = array.fromString(text)
                   .concat(0)
                   .concat(array.fromWord(message.sendtime))
                   .concat(array.fromHex(message.sender));

    message.signature = asymmetric.sign(app.signkey, rawdata);
    message.verified  = true;

    rawdata = rawdata.concat(message.signature);
    message.encrypted.data = this.encryptMessage(message, rawdata);

    if (message.encrypted.data != null)
      this.socket.send(JSON.stringify({"type": "message", "data": message.encrypted}));

    return message;
  },

  receiveMessage: function(data) {
    var message = new Message(data),
        rawdata = this.decryptMessage(message),
        i = rawdata.indexOf(0);

    message.recvtime = Math.round(+new Date()/1000);

    if (rawdata == null) return null;

    message.plaintext = array.toString(rawdata.slice(0, i));
    message.sendtime  = array.toWord(rawdata.slice(i+1, i+5));
    message.sender    = array.toHex(rawdata.slice(i+5, i+13));
    message.signature = rawdata.slice(i+13);

    if (typeof app.keychain[message.sender] == 'undefined') return null; //messages from rejected and unknown senders will be ignored at this point

    message.verified  = asymmetric.verify(app.keychain[message.sender].sign, rawdata.slice(0,i+13), message.signature);

    return message;
  },

  sendKey: function() {
    this.socket.send(JSON.stringify({"type": "key", "data": app.keychain[app.myid]}));
  },

  receiveKey: function(data) {
    return new PublicKey(data);
  }
}

var array = {
  //to/from string not currently handling charcode < 16 - if needed use ('0'+s).slice(-2);
  toString: function(input) {
    return decodeURIComponent(input.map(function(v) {return '%'+v.toString(16);}).join(''));
  },

  //replace match not followed by %: %25(?!%) - not needed as % is double encoded to %2525 anyway
  fromString: function(input) {
    return encodeURIComponent(input.split('').map(function(v){return (v.charCodeAt(0) < 128) ? '%'+v.charCodeAt(0).toString(16) : v;}).join('')).replace(/%25/g,'%')
            .slice(1).split('%').map(function(v){return parseInt(v, 16);});
  },

  toHex: function(input) {
    return input.map(function(v){return ('0'+v.toString(16)).slice(-2);}).join('');
  },

  fromHex: function(h) {
    return h.match(/.{2}/g).map(function(v){return parseInt(v, 16);});
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

  this.calcMpiLength = function(mpi, bits) {
    for (var i = 0, m = 128; i < 8; i++, m /= 2) {
      if (mpi[0] >= m) break;
    }

    m = mpi.length*8 - i;

    return (bits) ?  m : [m >> 8, m & 0xff];
  }

  this.calcFingerprint = function(data, type) {
    data = [4].concat(array.fromWord(data.created))
              .concat([type])
              .concat(this.calcMpiLength(data.mpi.n))
              .concat(data.mpi.n)
              .concat(this.calcMpiLength(data.mpi.e))
              .concat(data.mpi.e);

    return array.toHex(hash.digest([0x99, (data.length >> 8), (data.length & 0xff)].concat(data)));
  }

  this.calcKeyInfo = function(key, type) {
    key.size        = this.calcMpiLength(key.mpi.n, true);
    key.fingerprint = this.calcFingerprint(key, type);
    key.id          = key.fingerprint.substr(-16);
  }

  if (typeof data != 'undefined') {
    this.name = data.name;
    
    this.encrypt = data.encrypt;
    this.calcKeyInfo(this.encrypt, 2);

    this.sign = data.sign;
    this.calcKeyInfo(this.sign, 3);
  }
}

function Message(message) {
  this.encrypted  = {keys: {}, data: null};
  
  this.sessionkey = null;
  this.plaintext  = null;

  this.sender     = null;
  this.sendtime   = null;
  this.recvtime   = null;
  
  this.signature  = null;
  this.verified   = false;

  if (typeof message == 'undefined') {
    this.sessionkey = random.generate(app.ciphersize);
  } else {
    this.encrypted = message;
  }

  Object.defineProperty(this, "recipients", {
    get: function() {
        return Object.keys(this.encrypted.keys);
    }
  });
}
