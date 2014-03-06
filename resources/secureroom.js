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

function SecureRoom(onGenerateCallback) {
  var chain  = [],
      prefs  = {};

  prefs.room = window.location.pathname.substr(window.location.pathname.lastIndexOf("/")+1);

  if (prefs.room === "index.html")
    prefs.room = UrlUtil.getParameter("room");

  prefs.server = UrlUtil.getParameter("server") ? "wss://"+UrlUtil.getParameter("server")+":443/ws/"
                                                : "wss://"+document.location.host+":443/ws/";

  prefs.cipher = {size: 128,  type: "AES"};
  prefs.key    = {size: 1024, type: "RSA"};

  function makeRoom(room) {
    if (!prefs.room) {
      prefs.room = room;
      var opts = (window.location.search) ? window.location.search+"&room=" : "?room=",
          path = (window.location.pathname.indexOf("index.html") > -1) ? window.location.pathname+opts+prefs.room
                                                                       : window.location.pathname+prefs.room;

      window.history.replaceState({} , "SecureRoom", path);
    }
  }

  function onGenerate(data, time) {
    if (prefs.user) {
      prefs.user.ephemeral = new Key(data, Math.round(Date.now()/1000));

      prefs.user.master.sign(prefs.user.master);
      prefs.user.ephemeral.sign(prefs.user.master);

      prefs.user.status = "active";

      makeRoom(prefs.user.id.substr(-5));
      
      onGenerateCallback();
    } else {
      prefs.user = new User(new Key(data, Math.round(Date.now()/1000), prefs.name));
    }

    console.log("Key generation time (ms): " + time);
  }

  function findUserById(id) {
    return (prefs.user.id === id || prefs.user.ephemeral.id === id) ? prefs.user : chain.filter(function(user){ return user.master.id === id || user.ephemeral.id === id }).pop();
  }

  return {
    generateKeys: function(name) {
      prefs.name = name;

      KeyGen(primitives.crunch, primitives.random)(prefs.key.size, onGenerate);
      KeyGen(primitives.crunch, primitives.random)(prefs.key.size, onGenerate);
    },

    getUsers: function() {
      var args = Array.prototype.slice.call(arguments);
      return chain.filter(function(user) { return args.indexOf(user.status) >= 0 });
    },

    getUser: function(id) {
      return findUserById(id);
    },

    addUser: function(mkey, ekey) {
      var m = new Key(mkey.material, mkey.created, mkey.name),
          e = new Key(ekey.material, ekey.created),
          user;

      m.signatures = mkey.signatures;
      e.signatures = ekey.signatures;

      user = new User(m);
      user.ephemeral = e;

      if (typeof findUserById(user.id) === "undefined" && m.verify(m) && e.verify(m)) {
        chain.push(user);
      }

      return user;
    },

    myUser: function() {
      return prefs.user;
    },

    getRoom: function() {
      return prefs.room;
    },

    getServer: function() {
      return prefs.server + prefs.room;
    },

    setServer: function(server) {
      prefs.server = server;
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

function SecureComm(secureApp, onConnectCallback, onDisconnectCallback, onMessageCallback, onKeyCallback) {
  var socket;

  function isConnected() {
    return (typeof socket !== "undefined" && socket.readyState < 2);
  }

  function onConnectEvent() {
    sendKey();
    onConnectCallback();
  }

  function onDisconnectEvent() {
    onDisconnectCallback();
  }

  function onDataEvent(event) {
    var receivedJSON = JSON.parse(event.data);

    switch (receivedJSON.type) {
      case 'key':
        onKeyCallback(receiveKey(receivedJSON.data));
        break;
      case 'message':
        onMessageCallback(receiveMessage(receivedJSON.data));
        break;
    }

    console.log(receivedJSON);
  }

  function onErrorEvent(error) {
    console.log(error);
  }

  function connect(server) {
    if (isConnected())
      socket.close();

    try {
      socket = new WebSocket(server);

      socket.addEventListener("open", onConnectEvent);
      socket.addEventListener("message", onDataEvent);
      socket.addEventListener("error", onErrorEvent);
      socket.addEventListener("close", onDisconnectEvent);
    } catch (e) {
      console.log(e);
    }
  }

  function encryptSessionKey(recipients, sessionkey) {
    var encrypted = {};

    recipients.forEach(function(id) {
      encrypted[id] = primitives.asymmetric.encrypt(secureApp.getUser(id).ephemeral, sessionkey);
    });

    return encrypted;
  }

  function encryptMessage(message) {
    var sessionkey = primitives.random.generate(secureApp.getSize("cipher")),
        encrypted;

    if (message.recipients.length) {
      encrypted = {};
      encrypted.keys = encryptSessionKey(message.recipients, sessionkey);
      encrypted.data = primitives.symmetric.encrypt(sessionkey, primitives.random.generate(128).concat(message.pack()).concat(message.signature));
    }

    return encrypted;
  }

  function decryptMessage(encrypted) {
    var id = secureApp.myUser().ephemeral.id,
        sessionkey, decrypted;

    if (encrypted.keys[id]) {
      sessionkey = primitives.asymmetric.decrypt(secureApp.myUser().ephemeral, encrypted.keys[id]);
      decrypted  = primitives.symmetric.decrypt(sessionkey, encrypted.data).slice(16);
    }

    return decrypted;
  }

  function sendMessage(plaintext) {
    var message    = new Message(),
        recipients = secureApp.getUsers("active").map(function(user) { return user.ephemeral.id }),
        encrypted;

    message.create(plaintext, secureApp.myUser().master);
    message.recipients = recipients;

    encrypted = encryptMessage(message);

    if (typeof encrypted !== "undefined" && isConnected())
      socket.send(JSON.stringify({"type": "message", "data": encrypted}));

    return message;
  }

  function receiveMessage(encrypted) {
    var message   = new Message(),
        decrypted = decryptMessage(encrypted);

    if (typeof decrypted !== "undefined") {
      message.receive(decrypted);
      var sender = secureApp.getUser(message.sender);
      if (sender.status !== "rejected" && sender.status !== "pending") {
        message.verify(sender.master);
        message.recipients = Object.keys(encrypted.keys);
      }
    }

    return message;
  }

  function sendKey() {
    if (isConnected())
      socket.send(JSON.stringify({"type": "key", "data": secureApp.myUser().json}));
  }

  function receiveKey(data) {
    return secureApp.addUser(data.master, data.ephemeral);
  }

  return {
    sendKey: function() {
      sendKey();
    },
    sendMessage: function(plaintext) {
      onMessageCallback(sendMessage(plaintext));
    },
    connect: function() {
      connect(secureApp.getServer());
    }
  }
}

function Message() {
  this.plaintext;
  this.sender;
  this.sendtime;
  this.timediff;
  this.recipients;
  this.signature;
  this.verified = false;
}

Message.prototype.pack = function() {
  return ArrayUtil.fromString(this.plaintext).concat(0).concat(ArrayUtil.fromWord(this.sendtime)).concat(ArrayUtil.fromHex(this.sender));
}

Message.prototype.receive = function(data, key) {
  var i = data.indexOf(0);

  this.plaintext = ArrayUtil.toString(data.slice(0, i));
  this.sendtime  = ArrayUtil.toWord(data.slice(i+1, i+5));
  this.sender    = ArrayUtil.toHex(data.slice(i+5, i+13));
  this.signature = data.slice(i+13);

  this.timediff = Math.round(Date.now()/1000) - this.sendtime;
}

Message.prototype.verify = function(key) {
  this.verified = primitives.asymmetric.verify(key, primitives.hash.digest(this.pack()), this.signature);
}

Message.prototype.create = function(data, key) {
  this.sendtime  = Math.round(Date.now()/1000);
  this.timediff  = 0;
  this.sender    = key.id;
  this.plaintext = data;

  this.signature = primitives.asymmetric.sign(key, primitives.hash.digest(this.pack()));
  this.verified  = true;
}


function Key(material, created, name) {
  this.material    = material;
  this.created     = created;
  this.name        = name;
  this.signatures  = {};

  this.type        = (typeof name !== "undefined") ? 3 : 2;
  this.fingerprint = this.generateFingerprint();
}

Key.prototype = {
  get id () {
    return this.fingerprint.substr(-16);
  },

  get json () {
    var json = {};
    
    json.created    = this.created;
    json.signatures = this.signatures;
    
    json.material   = {};
    json.material.e = this.material.e;
    json.material.n = this.material.n;

    if (typeof name !== "undefined")
      json.name = this.name;

    return json;
  },

  get size () {
    return ArrayUtil.bitLength(this.material.n);
  }
}

Key.prototype.makeBase = function() {
  return [4].concat(ArrayUtil.fromWord(this.created)).concat(this.type).concat(ArrayUtil.makeMpi(this.material.n)).concat(ArrayUtil.makeMpi(this.material.e));
}

Key.prototype.makeSignatureBase = function() {
  return (this.type === 3)
    ? [4,19,3,2,0,26,5,2].concat(ArrayUtil.fromWord(this.created)).concat(2,27,3,5,9).concat(ArrayUtil.fromWord(86400)).concat(4,11,7,8,9,2,21,2,2,22,0)
    : [4,24,2,2,0,15,5,2].concat(ArrayUtil.fromWord(this.created)).concat(2,27,4,5,9).concat(ArrayUtil.fromWord(86400));
}

Key.prototype.generateFingerprint = function() {
  var base = this.makeBase();
  return ArrayUtil.toHex(primitives.hash.digest([153].concat(ArrayUtil.fromHalf(base.length)).concat(base)));
}

Key.prototype.generateSignatureHash = function(signer) {
  var keyHead, sigHead, suffix, 
      base = signer.makeBase();

  if (this.type === 3) {
    keyHead = [180].concat(ArrayUtil.fromWord(this.name.length)).concat(ArrayUtil.fromString(this.name));
  } else {
    keyHead = this.makeBase();
    keyHead = [153].concat(ArrayUtil.fromHalf(keyHead.length)).concat(keyHead);
  }

  sigHead = this.makeSignatureBase();
  suffix  = [4,255].concat(ArrayUtil.fromWord(sigHead.length));

  return primitives.hash.digest(
    [153].concat(ArrayUtil.fromHalf(base.length)).concat(base).concat(keyHead).concat(sigHead).concat(suffix)
  );
}

Key.prototype.sign = function(signer) {
  if (signer.isPrivate() && signer.isMaster()) {
      var signatureHash = this.generateSignatureHash(signer),
          sigdata = {};

       sigdata.signature = primitives.asymmetric.sign(signer, signatureHash);
       sigdata.hashcheck = signatureHash.slice(0, 2);
      this.signatures[signer.id] = sigdata;
  }
}

Key.prototype.verify = function(signer) {
  if (typeof this.signatures[signer.id] !== "undefined") {
     return primitives.asymmetric.verify(signer, this.generateSignatureHash(signer), this.signatures[signer.id].signature);
  }
}

Key.prototype.isMaster = function() {
  return this.type === 3;
}

Key.prototype.isPrivate = function() {
  return typeof this.material.d !== "undefined";
}


function User(key) {
  this.master    = key;
  this.ephemeral = null; 
  this.status    = "pending"; //active, disabled, rejected
}

User.prototype = {
    get name () {
      return this.master.name;
    },

    get id () {
      return this.master.id;
    },

    get json () {
      return {"master": this.master.json, "ephemeral": this.ephemeral.json};
    }
}