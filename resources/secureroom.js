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
  var crunch = Crunch(),
      oracle = Asymmetric(crunch, Hash()),
      chain  = [],
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
  }

  function findUserById(id) {
    return (prefs.user.id === id || prefs.user.ephemeral.id === id) ? prefs.user : chain.filter(function(user){ return user.master.id === id || user.ephemeral.id === id }).pop();
  }

  return {
    generateKeys: function(name) {
      prefs.name = name;

      KeyGen(prefs.key.size, onGenerate, crunch)();
      KeyGen(prefs.key.size, onGenerate, crunch)();
    },

    getKeys: function(mode) {
      return chain.filter(function(user) {
        return user.status === mode;
      });
    },

    getKey: function(id) {
      return findUserById(id);
    },

    shareKey: function() {
      return prefs.user.json;
    },

    setKey: function(mkey, ekey) {
      var m = new Key(mkey.material, mkey.created, mkey.name),
          e = new Key(ekey.material, ekey.created),
          user;

      m.signatures = mkey.signatures;
      e.signatures = ekey.signatures;

      user = new User(m);
      user.ephemeral = e;

      if (m.verify(m) && e.verify(m)) {
        chain.push(user);
      } else {
        console.log("Key not verified");
      }
      
      return user;
    },

    toggleKey: function(id, status) {
      var user = findUserById(id);

      if (typeof user !== "undefined")
        user.status = status;
    },

    myUser: function() {
      return prefs.user;
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
  var socket,
      oracle = Asymmetric(Crunch(), Hash());

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

    recipients.forEach(function(user) {
      encrypted[user.ephemeral.id] = oracle.encrypt(user.ephemeral, sessionkey);
    });

    return encrypted;
  }

  function encryptMessage(message) {
    var sessionkey = Random.generate(secureApp.getSize("cipher")),
        recipients = message.getRecipients(),
        encrypted;

    if (recipients.length) {
      encrypted = {};
      encrypted.keys = encryptSessionKey(recipients, sessionkey);
      encrypted.data = Symmetric.encrypt(sessionkey, Random.generate(128).concat(message.pack()));
    }

    return encrypted;
  }

  function decryptMessage(encrypted) {
    var id = secureApp.myUser().ephemeral.id,
        sessionkey, decrypted;

    if (encrypted.keys[id]) {
      sessionkey = oracle.decrypt(secureApp.myUser().ephemeral, encrypted.keys[id]);
      decrypted  = Symmetric.decrypt(sessionkey, encrypted.data).slice(16);
    }

    return decrypted;
  }

  function sendMessage(plaintext) {
    var message    = Message(oracle),
        recipients = secureApp.getKeys("active"),
        encrypted;

    message.create(plaintext, secureApp.myUser().master);
    message.setRecipients(recipients);

    encrypted = encryptMessage(message);

    if (typeof encrypted !== "undefined" && isConnected())
      socket.send(JSON.stringify({"type": "message", "data": encrypted}));

    return message;
  }

  function receiveMessage(encrypted) {
    var message   = Message(oracle),
        decrypted = decryptMessage(encrypted);

    if (typeof decrypted !== "undefined") {
      message.unpack(decrypted);
      var sender = secureApp.getKey(message.getSender());
      if (sender.status !== "rejected" && sender.status !== "pending") {
        message.verify(sender.master);
        message.setRecipients(Object.keys(encrypted.keys));
      }
    }

    return message;
  }

  function sendKey() {
    if (isConnected())
      socket.send(JSON.stringify({"type": "key", "data": secureApp.shareKey()}));
  }

  function receiveKey(data) {
    return secureApp.setKey(data.master, data.ephemeral);
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

function Message(oracle) {
  var plaintext, sender, sendtime, recvtime, recipients, signature, verified = false;

  function pack() {
    return ArrayUtil.fromString(plaintext)
      .concat(0)
      .concat(ArrayUtil.fromWord(sendtime))
      .concat(ArrayUtil.fromHex(sender));
  }

  return {
    unpack: function(data) {
      var i = data.indexOf(0);

      recvtime  = Math.round(Date.now()/1000);

      plaintext = ArrayUtil.toString(data.slice(0, i));
      sendtime  = ArrayUtil.toWord(data.slice(i+1, i+5));
      sender    = ArrayUtil.toHex(data.slice(i+5, i+13));
      signature = data.slice(i+13);
    },

    pack: function() {
      return pack().concat(signature);
    },

    create: function(data, key) {
      sendtime  = recvtime = Math.round(Date.now()/1000);
      sender    = key.id;
      plaintext = data;

      signature = oracle.sign(key, pack());
      verified  = true;
    },

    verify: function(key) {
      verified = oracle.verify(key, pack(), signature);
    },

    isVerified: function() {
      return verified;
    },

    getText: function() {
      return plaintext;
    },

    getSender: function() {
      return sender;
    },

    getTime: function() {
      return recvtime;
    },

    getTimeDiff: function() {
      return recvtime - sendtime;
    },

    getRecipients: function() {
      return recipients;
    },

    setRecipients: function(data) {
      recipients = data;
    }
  };
}

function Key(material, created, name) {
  this.material    = material;
  this.created     = created;
  this.name        = name;
  this.signatures  = {};

  this.type        = (typeof name !== "undefined") ? 3 : 2;
  this.fingerprint = this.generateFingerprint();
}

Key.hash   = Hash();
Key.oracle = Asymmetric(Crunch(), Key.hash);

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

  //TEMP WORKAROUNG
  get data () {
    return this.material;
  },
  //TEMP WORKAROUNG

  get size () {
    return ArrayUtil.bitLength(this.material.n);
  }
}

Key.prototype.makeBase = function() {
  return [4].concat(ArrayUtil.fromWord(this.created))
         .concat([this.type])
         .concat(ArrayUtil.makeMpi(this.material.n))
         .concat(ArrayUtil.makeMpi(this.material.e));
}

Key.prototype.makeSignatureBase = function() {
  return (this.type === 3)
  ? [4,19,3,2,0,26,5,2]
    .concat(ArrayUtil.fromWord(this.created))
    .concat([2,27,3,5,9])
    .concat(ArrayUtil.fromWord(86400))
    .concat([4,11,7,8,9,2,21,2,2,22,0])
  : [4,24,2,2,0,15,5,2]
    .concat(ArrayUtil.fromWord(this.created))
    .concat([2,27,4,5,9])
    .concat(ArrayUtil.fromWord(86400));
}

Key.prototype.generateFingerprint = function() {
  var base = this.makeBase();
  return ArrayUtil.toHex(Key.hash.digest([153].concat(ArrayUtil.fromHalf(base.length)).concat(base)));
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

  return Key.hash.digest(
    [153].concat(ArrayUtil.fromHalf(base.length)).concat(base).concat(keyHead).concat(sigHead).concat(suffix)
  );
}

Key.prototype.sign = function(signer) {
  if (signer.isPrivate() && signer.isMaster()) {
      var signatureHash = this.generateSignatureHash(signer),
          sigdata = {};

       sigdata.signature = Key.oracle.sign(signer, signatureHash, true);
       sigdata.hashcheck = signatureHash.slice(0, 2);
      this.signatures[signer.id] = sigdata;
  }
}

Key.prototype.verify = function(signer) {
  if (typeof this.signatures[signer.id] !== "undefined") {
     return Key.oracle.verify(signer, this.generateSignatureHash(signer), this.signatures[signer.id].signature, true);
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