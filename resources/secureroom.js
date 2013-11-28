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

function SecureRoom(callback) {
  var chain = {},
      prefs = {};

      prefs.room   = window.location.pathname.substr(window.location.pathname.lastIndexOf('/')+1);
      if (prefs.room == 'index.html') prefs.room = UrlUtil.getParameter('room');

      prefs.server = (UrlUtil.getParameter('server')) ? 'wss://'+UrlUtil.getParameter('server')+':443/ws/'
                                                      : 'wss://'+document.location.host+':443/ws/';

      prefs.cipher = {size: 128, type: 'AES'};
      prefs.key    = {size: 1024, type: 'RSA'};
      prefs.myid   = null;
      prefs.name   = null;
   
  function buildKey(n, t, d, c, m, s) {
    var key = { name: n, type: t, data: d, time: c, mode: m, sign: s,
                size: ArrayUtil.bitLength(d.n),
                iden: KeyUtil.generateFingerprint(t, d, c) },
        id  = key.iden.substr(-16);

    if (typeof chain[id] == "undefined") chain[id] = key;

    return id;
  }

  function onGenerate(data) {
    if (prefs.myid) {
      var id = buildKey(prefs.name, C.TYPE_RSA_ENCRYPT, data, +new Date, C.STATUS_ENABLED);
      chain[prefs.myid].peer = id;
      chain[id].peer = prefs.myid;

      chain[id].sign = Asymmetric.sign(chain[prefs.myid].data, KeyUtil.generateSignatureHash(chain[prefs.myid], chain[id]), true);

      callback();
    } else {
      prefs.myid = buildKey(prefs.name, C.TYPE_RSA_SIGN, data, +new Date, C.STATUS_ENABLED);

      chain[prefs.myid].sign = Asymmetric.sign(chain[prefs.myid].data, KeyUtil.generateSignatureHash(chain[prefs.myid]), true);
    }
  }

  return {
    generateKeys: function(name) {
      prefs.name = name;
      KeyGen(prefs.key.size, onGenerate)();
      KeyGen(prefs.key.size, onGenerate)();
    },

    getKeys: function(type, status) {
      var result = [];
      for (var id in Object.keys(chain))
        if (id != prefs.myid 
          && chain[id].type == type
            && chain[id].status == status)
              result.push(id);

      return result;
    },

    getKey: function(id) {
      return chain[id];
    },

    getPeer: function(id) {
      return chain[chain[id].peer];
    },

    hasKey: function(id) {
      return (typeof chain[id] != "undefined")
    },

    myKey: function() {
      var eid = myId(C.TYPE_RSA_ENCRYPT),
          sid = myId(C.TYPE_RSA_SIGN);

      return {
        name: prefs.name,
        key1: {type: C.TYPE_RSA_SIGN, time: chain[sid].time, data: {e: chain[sid].data.e, n: chain[sid].data.n}},
        key2: {type: C.TYPE_RSA_ENCRYPT, time: chain[eid], data: {e: chain[eid].data.e, n: chain[eid].data.n}}
      }
    },

    setKey: function(name, key1, key2) {
      var id1 = buildKey(name, key1.type, key1.data, key1.time, C.STATUS_PENDING, key1.sign),
          id2 = buildKey(name, key2.type, key2.data, key2.time, C.STATUS_PENDING, key2.sign);

      chain[id1].peer = id2;
      chain[id2].peer = id1;

      //verify key signature, reject outright if sig is wrong

      return (key1.type == C.TYPE_RSA_SIGN) ? id1 : id2;
    },

    toggleKey: function(id, mode) {
      chain[id].mode = mode;
      chain[chain[id].peer].mode = mode;
    },

    isEnabled: function(id) {
      return (chain[id].mode == C.STATUS_ENABLED);
    },

    isRejected: function(id) {
      return (chain[id].mode == C.STATUS_REJECTED);
    },

    myId: function(type) {
      return (type == C.TYPE_RSA_SIGN) ? prefs.myid : chain[prefs.myid].peer;
    },

    myName: function() {
      return prefs.name;
    },

    getRoom: function() {
      return prefs.room;
    },

    setRoom: function(room) {
      if (!room || prefs.room == room) return;

      var opts = (window.location.search) ? window.location.search+'&room=' : '?room=',
          path = (window.location.pathname.indexOf('index.html') > -1) ? window.location.pathname+opts+room : window.location.pathname+room;
      
      window.history.replaceState({} , 'SecureRoom', path);
      prefs.room = room;
    },

    getServer: function() {
      return prefs.server+prefs.room;
    },

    setServer: function(server) {
      prefs.server = server;
    },

    getName: function() {
      return prefs.name;
    },

    setName: function(name) {
      prefs.name = name;
    },

    //key/cipher
    setSize: function(type, size) {
      prefs[type].size = size;
    },

    getSize: function(type) {
      return prefs[type].size;
    }
  }
}

/*var app = {
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

      if (!app.getRoom()) app.setRoom(app.myid.substr(-8));

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
    var shsh = KeyUtil.generateSignatureHash(app.keychain[app.myid].sign, app.nickname),
        ehsh = KeyUtil.generateSignatureHash(app.keychain[app.myid].sign, app.keychain[app.myid].encrypt);

    app.keychain[app.myid].sign.signature    = Asymmetric.sign(app.signkey, shsh, true);
    app.keychain[app.myid].encrypt.signature = Asymmetric.sign(app.signkey, ehsh, true);
  },

  getServer: function() {
    return (app.server = ( app.getParameter('server')) 
                            ? 'wss://'+app.getParameter('server')+':443/ws/'
                            : 'wss://'+document.location.host+':443/ws/' );
  },
  
  getRoom: function() {
    if (app.room) return app.room;

    app.room = window.location.pathname.substr(window.location.pathname.lastIndexOf('/')+1);
    if (app.room == 'index.html')
      app.room = app.getParameter('room');

    return app.room;
  },

  setRoom: function(room) {
    if (!room) return;

    var opts = (window.location.search) ? window.location.search+'&room=' : '?room=',
        path = (window.location.pathname.indexOf('index.html') > -1) ? window.location.pathname+opts+room : window.location.pathname+room;
    
    window.history.replaceState({} , 'SecureRoom', path);
    app.room = room;
  },
  
  getParameter: function(name) {
    var match = RegExp('[?&]' + name + '=([^&]*)').exec(window.location.search);
    return (match) ? decodeURIComponent(match[1].replace(/\+/g, ' ')) : '';
  }
}*/

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
      this.socket = new WebSocket(App.getServer());
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
          comm.cbKey(comm.receiveKey(obj.data));
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
    for (var id in App.getKeys(C.TYPE_RSA_ENCRYPT, C.STATUS_ENABLED))
      message.encrypted.keys[id] = Asymmetric.encrypt(App.getKey(id), message.sessionkey);

    if (typeof id == "undefined") return null;

    var paddata = random.generate(App.getSize("cipher"));
    paddata = paddata.concat(paddata.slice(-2))
                     .concat(data);

    return Symmetric.encrypt(message.sessionkey, paddata);
  },

  decryptMessage: function(message) {
    var id = App.myId(C.TYPE_RSA_ENCRYPT);

    if (message.encrypted.keys[id]) {
      message.sessionkey = Asymmetric.decrypt(App.getKey(id), message.encrypted.keys[id]);
      return Symmetric.decrypt(message.sessionkey, message.encrypted.data).slice(message.sessionkey.length+2);
    }

    return null;
  },

  sendMessage: function(text) {
    var rawdata, message = new Message();

    message.sendtime = Math.round(new Date/1000);
    message.recvtime = message.sendtime;
    message.sender   = App.myId(C.TYPE_RSA_SIGN);

    message.plaintext = text;
    rawdata = ArrayUtil.fromString(text)
                .concat(0)
                .concat(ArrayUtil.fromWord(message.sendtime))
                .concat(ArrayUtil.fromHex(message.sender));

    message.signature = Asymmetric.sign(App.getKey(message.sender), rawdata);
    message.verified  = true;

    rawdata = rawdata.concat(message.signature);
    message.encrypted.data = this.encryptMessage(message, rawdata);

    if (message.encrypted.data)
      this.socket.send(JSON.stringify({"type": "message", "data": message.encrypted}));

    return message;
  },

  receiveMessage: function(data) {
    var message = new Message(data),
        rawdata = this.decryptMessage(message),
        i = rawdata.indexOf(0);

    message.recvtime = Math.round(+new Date()/1000);

    if (rawdata == null) return null;

    message.plaintext = ArrayUtil.toString(rawdata.slice(0, i));
    message.sendtime  = ArrayUtil.toWord(rawdata.slice(i+1, i+5));
    message.sender    = ArrayUtil.toHex(rawdata.slice(i+5, i+13));
    message.signature = rawdata.slice(i+13);

    if (!App.hasKey(message.sender) || App.isRejected(message.sender)) return null; //messages from rejected and unknown senders will be ignored at this point

    message.verified  = Asymmetric.verify(App.getKey(message.sender), rawdata.slice(0,i+13), message.signature);

    return message;
  },

  sendKey: function() {
    this.socket.send(JSON.stringify({"type": "key", "data": App.myKey()}));
  },

  receiveKey: function(data) {
    return App.setKey(data.name, data.key1, data.key2);
  }
}

/*function PublicKey(data) {
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
    data = [4].concat(ArrayUtil.fromWord(data.created))
              .concat([type])
              .concat(this.calcMpiLength(data.mpi.n))
              .concat(data.mpi.n)
              .concat(this.calcMpiLength(data.mpi.e))
              .concat(data.mpi.e);

    return ArrayUtil.toHex(hash.digest([0x99, (data.length >> 8), (data.length & 0xff)].concat(data)));
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
}*/

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

function MessageTools(message) {
  return {
    strength: function() {
      var id, min = 8192;

      for (id in message.encrypted.keys) {
        if (!App.hasKey(id)) {
          min = 8192;
          break;
        }
        min = Math.min(App.getKey(id).size, min);
      }

      return { term: 'Weakest Key', data: (min < 8192) ? min+' bits' : 'Unknown' };
    },

    recipients: function() {
      var id, list = [];

      for (id in message.encrypted.keys)
        if (App.hasKey(id))
          list.push((App.isRejected(id)) ? 'Rejected' : PrintUtil.text(App.getKey(id).name));
        else
          list.push('Unknown');

      return { term: 'Recipients', data: list.join(', ') };
    }
  }
}