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
      var id = buildKey(prefs.name, C.TYPE_RSA_ENCRYPT, data, Math.round(Date.now()/1000), C.STATUS_ENABLED);
      chain[prefs.myid].peer = id;
      chain[id].peer = prefs.myid;
      chain[id].sign = Asymmetric.sign(chain[prefs.myid], KeyUtil.generateSignatureHash(chain[prefs.myid], chain[id]), true);

      if (!prefs.room) {
        prefs.room = prefs.myid.substr(-5);
        var opts = (window.location.search) ? window.location.search+'&room=' : '?room=',
            path = (window.location.pathname.indexOf('index.html') > -1) ? window.location.pathname+opts+prefs.room : window.location.pathname+prefs.room;
      
        window.history.replaceState({} , 'SecureRoom', path);
      }

      callback();
    } else {
      prefs.myid = buildKey(prefs.name, C.TYPE_RSA_SIGN, data, Math.round(Date.now()/1000), C.STATUS_ENABLED);
      chain[prefs.myid].sign = Asymmetric.sign(chain[prefs.myid], KeyUtil.generateSignatureHash(chain[prefs.myid]), true);
    }
  }

  return {
    generateKeys: function(name) {
      prefs.name = name;
      KeyGen(prefs.key.size, onGenerate)();
      KeyGen(prefs.key.size, onGenerate)();
    },

    getKeys: function(type, mode) {
      var result = [];
      for (var id in chain)
        if (id != prefs.myid && chain[id].peer != prefs.myid
          && chain[id].type == type
            && chain[id].mode == mode)
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
      return (typeof chain[id] != "undefined");
    },

    shareKey: function() {
      var ek = chain[this.myId(C.TYPE_RSA_ENCRYPT)],
          sk = chain[this.myId(C.TYPE_RSA_SIGN)];

      return {
        name: prefs.name,
        key1: {type: sk.type, time: sk.time, data: {e: sk.data.e, n: sk.data.n}, sign: sk.sign},
        key2: {type: ek.type, time: ek.time, data: {e: ek.data.e, n: ek.data.n}, sign: ek.sign}
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
      chain[id].mode = mode; chain[chain[id].peer].mode = mode;
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

    getSize: function(type) {
      return prefs[type].size;
    },
    //key/cipher
    setSize: function(type, size) {
      prefs[type].size = size;
    }
  }
}

var Comm = {
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
        Comm.connected = true;
        Comm.cbConnect();
        Comm.sendKey();
      }

      this.socket.onmessage = function(event){
        var obj = JSON.parse(event.data);
        console.log(obj);
        switch (obj.type) {
        case 'key':
          Comm.cbKey(Comm.receiveKey(obj.data));
          break;
        case 'message':
          Comm.cbMessage(Comm.receiveMessage(obj.data));
          break;
        }
      }

      this.socket.onclose = function(){
        Comm.connected = false;
        Comm.cbDisconnect();
      }
    } catch (e) {
      console.log(e);
    }
  },

  encryptMessage: function(message, data) {
    for (var i = 0, d = App.getKeys(C.TYPE_RSA_ENCRYPT, C.STATUS_ENABLED); i < d.length; i++)
      message.encrypted.keys[d[i]] = Asymmetric.encrypt(App.getKey(d[i]), message.sessionkey);

    if (i == 0) return null;

    var paddata = Random.generate(App.getSize("cipher"));
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

    message.sendtime = Math.round(Date.now()/1000);
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
        rawdata = this.decryptMessage(message), i;

    if (rawdata == null) return null;

    i = rawdata.indexOf(0);
    message.recvtime  = Math.round(Date.now()/1000);
    message.plaintext = ArrayUtil.toString(rawdata.slice(0, i));
    message.sendtime  = ArrayUtil.toWord(rawdata.slice(i+1, i+5));
    message.sender    = ArrayUtil.toHex(rawdata.slice(i+5, i+13));
    message.signature = rawdata.slice(i+13);

    if (!App.hasKey(message.sender) || App.isRejected(message.sender)) return null; //messages from rejected and unknown senders will be ignored at this point

    message.verified  = Asymmetric.verify(App.getKey(message.sender), rawdata.slice(0,i+13), message.signature);

    return message;
  },

  sendKey: function() {
    this.socket.send(JSON.stringify({"type": "key", "data": App.shareKey()}));
  },

  receiveKey: function(data) {
    return App.setKey(data.name, data.key1, data.key2);
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
    this.sessionkey = Random.generate(App.getSize('cipher'));
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