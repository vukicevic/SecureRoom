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
    if (prefs.myid) {
      prefs.user.ephemeral = Key(data, Math.round(Date.now()/1000));

      prefs.user.master.sign(prefs.user.master);
      prefs.user.ephemeral.sign(prefs.user.master);

      prefs.user.status = "active";

      makeRoom(prefs.myid.substr(-5));

      onGenerateCallback();
    } else {
      prefs.user = User(Key(data, Math.round(Date.now()/1000), prefs.name));
      prefs.myid = prefs.user.master.id;
    }
  }

  function findUserById(id) {
    return chain.filter(function(user) {
      return user.master.id === id || user.ephemeral.id === id;
    }).pop();
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

    setKey: function(master, ephemeral) {
      var m = Key(master.material, master.created, master.name),
          e = Key(ephemeral.material, ephemeral.created),
          u;

      m.signatures = master.signatures;
      e.signatures = ephemeral.signatures;

      u = User(m);
      u.ephemeral = e;

      if (m.verify(m) && e.verify(m))
        chain.push(u);

      return u;
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

    recipients.forEach(function(v) {
      encrypted[v] = oracle.encrypt(secureApp.getKey(v).ephemeral, sessionkey);
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
    var message   = Message(oracle),
        recipient = secureApp.getKeys("active"),
        encrypted;

    message.create(plaintext, secureApp.myUser().master);
    message.setRecipients(recipient);

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
  var hash   = Hash(),
    oracle = Asymmetric(Crunch(), hash),
    
    type        = (typeof name !== "undefined") ? 3 : 2,
    fingerprint = generateFingerprint(),
    signatures  = {};

  function makeBase() {
    return [4]
        .concat(ArrayUtil.fromWord(created))
        .concat([type])
        .concat(ArrayUtil.makeMpi(material.n))
        .concat(ArrayUtil.makeMpi(material.e));
  }

  function makeEphemeralSigBase() {
    return [4,24,2,2,0,15,5,2]
      .concat(ArrayUtil.fromWord(created))
      .concat([2,27,4,5,9])
      .concat(ArrayUtil.fromWord(86400));
  }

  function makeMasterSigBase() {
    return [4,19,3,2,0,26,5,2]
      .concat(ArrayUtil.fromWord(created))
      .concat([2,27,3,5,9])
      .concat(ArrayUtil.fromWord(86400))
      .concat([4,11,7,8,9,2,21,2,2,22,0]);
  }

  function generateFingerprint() {
    var base = makeBase();

    return ArrayUtil.toHex(hash.digest([153].concat(ArrayUtil.fromHalf(base.length)).concat(base)));
  }

  function generateSignatureHash(signer) {
    var keyHead, sigHead, suffix, 
      base = signer.base;

    if (typeof name !== "undefined") {
      keyHead = [180]
            .concat(ArrayUtil.fromWord(name.length))
            .concat(ArrayUtil.fromString(name));

      sigHead = makeMasterSigBase();
    } else {
      keyHead = makeBase();
      keyHead = [153].concat(ArrayUtil.fromHalf(keyHead.length)).concat(keyHead);

      sigHead = makeEphemeralSigBase();
    }

    suffix  = [4,255].concat(ArrayUtil.fromWord(sigHead.length));

    return hash.digest(
      [153].concat(ArrayUtil.fromHalf(base.length)).concat(base).concat(keyHead).concat(sigHead).concat(suffix)
    );
  }

  return {

    get base () {
      return makeBase();
    },

    get signatureBase () {
      return (type === 3) ? makeMasterSigBase() : makeEphemeralSigBase();
    },

    get created () {
      return created;
    },

    get fingerprint () {
      return fingerprint;
    },

    get id () {
      return fingerprint.substr(-16);
    },

    get json () {
      var json = {};
      
      json.created    = created;
      json.signatures = signatures;
      
      json.material   = {};
      json.material.e = material.e;
      json.material.n = material.n;

      if (typeof name !== "undefined")
        json.name = name;

      return json;
    },

    get material () {
      return material;
    },

    //TEMP WORKAROUNG
    get data () {
      return material;
    },
    //TEMP WORKAROUNG

    get name () {
      return name;
    },

    get signatures () {
      return signatures;
    },

    get size () {
      return ArrayUtil.bitLength(material.n);
    },

    get type () {
      return type;
    },

    set signatures (value) {
      signatures = value;
    },

    sign: function(signer) {
      if (signer.isPrivate() && signer.isMaster()) {
        var signatureHash = generateSignatureHash(signer),
          sigdata = {};

        sigdata.signature = oracle.sign(signer, signatureHash, true);
        sigdata.hashcheck = signatureHash.slice(0, 2);

        signatures[signer.id] = sigdata;
      }
    },

    verify: function(signer) {
      if (typeof signatures[signer.id] !== "undefined") {
        return oracle.verify(signer, generateSignatureHash(signer), signatures[signer.id].signature, true);
      }
    },

    isMaster: function() {
      return type === 3;
    },

    isPrivate: function() {
      return typeof material.d !== "undefined";
    }
  }
}

function User(master) {
  var emphemeral, 
    status = "pending"; //active, disabled, rejected

  return {
    get name () {
      return master.name;
    },

    get id () {
      return master.id;
    },

    get json () {
      return {"master": master.json, "ephemeral": ephemeral.json};
    },

    get master () {
      return master;
    },

    get ephemeral () {
      return ephemeral;
    },

    get status () {
      return status;
    },

    set status (value) {
      status = value;
    },

    set ephemeral (key) {
      ephemeral = key;
    }
  }
}