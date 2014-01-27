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

function SecureRoom(onGenerateCallback, onConnectCallback, onDisconnectCallback, onMessageCallback, onKeyCallback) {
  var chain = {},
      prefs = {},
      comms = Comm(onConnectCallback, onDisconnectCallback, onMessageCallback, onKeyCallback),
      maths = Crunch();

      prefs.room   = window.location.pathname.substr(window.location.pathname.lastIndexOf("/")+1);
      if (prefs.room === "index.html") prefs.room = UrlUtil.getParameter("room");

      prefs.server = (UrlUtil.getParameter("server")) ? "wss://"+UrlUtil.getParameter("server")+":443/ws/"
                                                      : "wss://"+document.location.host+":443/ws/";

      prefs.cipher = {size: 128,  type: "AES"};
      prefs.key    = {size: 1024, type: "RSA"};
      prefs.myid   = null;
      prefs.name   = null;

  function buildKey(n, t, d, c, m, s) {
    var key = { name: n, type: t, data: d, time: c, mode: m, sign: s,
                size: ArrayUtil.bitLength(d.n),
                iden: KeyUtil.generateFingerprint(t, d, c) },
        id  = key.iden.substr(-16);

    if (typeof chain[id] === "undefined") chain[id] = key;

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
        var opts = (window.location.search) ? window.location.search+"&room=" : "?room=",
            path = (window.location.pathname.indexOf("index.html") > -1) ? window.location.pathname+opts+prefs.room
                                                                         : window.location.pathname+prefs.room;

        window.history.replaceState({} , "SecureRoom", path);
      }

      onGenerateCallback();
    } else {
      prefs.myid = buildKey(prefs.name, C.TYPE_RSA_SIGN, data, Math.round(Date.now()/1000), C.STATUS_ENABLED);
      chain[prefs.myid].sign = Asymmetric.sign(chain[prefs.myid], KeyUtil.generateSignatureHash(chain[prefs.myid]), true);
    }
  }

  return {
    calc: maths,
    comm: comms,

    generateKeys: function(name) {
      prefs.name = name;
      KeyGen(prefs.key.size, onGenerate, maths)();
      KeyGen(prefs.key.size, onGenerate, maths)();
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

      //TODO: verify key signature, reject outright if sig is wrong

      return (key1.type === C.TYPE_RSA_SIGN) ? id1 : id2;
    },

    toggleKey: function(id, mode) {
      chain[id].mode = mode; chain[chain[id].peer].mode = mode;
    },

    isEnabled: function(id) {
      return (chain[id].mode === C.STATUS_ENABLED);
    },

    isRejected: function(id) {
      return (chain[id].mode === C.STATUS_REJECTED);
    },

    isPending: function(id) {
      return (chain[id].mode === C.STATUS_PENDING);
    },

    myId: function(type) {
      return (type === C.TYPE_RSA_SIGN) ? prefs.myid : chain[prefs.myid].peer;
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

var C = {
  TYPE_RSA_SIGN: 3,
  TYPE_RSA_ENCRYPT: 2,
  STATUS_DISABLED: 2,
  STATUS_ENABLED: 1,
  STATUS_PENDING: 0,
  STATUS_REJECTED: -1
};

function Comm(onConnectCallback, onDisconnectCallback, onMessageCallback, onKeyCallback) {
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

  function encryptSessionKey(recipient, sessionkey) {
    for (var encrypted = {}, i = 0; i < recipient.length; i++)
      encrypted[recipient[i]] = Asymmetric.encrypt(App.getKey(recipient[i]), sessionkey);

    return encrypted;
  }

  function encryptMessage(message) {
    var sessionkey = Random.generate(App.getSize("cipher")),
        recipient = message.getRecipients(),
        encrypted;

    if (recipient.length) {
      encrypted = {};
      encrypted.keys = encryptSessionKey(recipient, sessionkey);
      encrypted.data = Symmetric.encrypt(sessionkey, Random.generate(128).concat(message.pack()));
    }

    return encrypted;
  }

  function decryptMessage(encrypted) {
    var id = App.myId(C.TYPE_RSA_ENCRYPT),
        sessionkey, decrypted;

    if (encrypted.keys[id]) {
      sessionkey = Asymmetric.decrypt(App.getKey(id), encrypted.keys[id]);
      decrypted = Symmetric.decrypt(sessionkey, encrypted.data).slice(16);
    }

    return decrypted;
  }

  function sendMessage(plaintext) {
    var message   = Message(),
        recipient = App.getKeys(C.TYPE_RSA_ENCRYPT, C.STATUS_ENABLED),
        encrypted;

    message.create(plaintext);
    message.setRecipients(recipient);

    encrypted = encryptMessage(message);

    if (typeof encrypted !== "undefined" && isConnected())
      socket.send(JSON.stringify({"type": "message", "data": encrypted}));

    return message;
  }

  function receiveMessage(encrypted) {
    var message   = Message(),
        decrypted = decryptMessage(encrypted);

    if (typeof decrypted !== "undefined") {
      message.unpack(decrypted);
      if (App.hasKey(message.getSender()) && !App.isRejected(message.getSender()) && !App.isPending(message.getSender())) {
        message.verify();
        message.setRecipients(Object.keys(encrypted.keys));
      }
    }

    return message;
  }

  function sendKey() {
    if (isConnected())
      socket.send(JSON.stringify({"type": "key", "data": App.shareKey()}));
  }

  function receiveKey(data) {
    return App.setKey(data.name, data.key1, data.key2);
  }

  return {
    sendKey: function() {
      sendKey();
    },
    sendMessage: function(plaintext) {
      onMessageCallback(sendMessage(plaintext));
    },
    connect: function() {
      connect(App.getServer());
    }
  }
}

function Message() {
  var plaintext, sender, sendtime, recvtime, recipients, signature, verified = false;

  function pack() {
    return ArrayUtil.fromString(plaintext)
      .concat(0)
      .concat(ArrayUtil.fromWord(sendtime))
      .concat(ArrayUtil.fromHex(sender));
  }

  function sign() {
    signature = Asymmetric.sign(App.getKey(sender), pack());
    verified = true;
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

    create: function(data) {
      sendtime  = recvtime = Math.round(Date.now()/1000);
      sender    = App.myId(C.TYPE_RSA_SIGN);
      plaintext = data;

      sign();
    },

    verify: function() {
      verified = Asymmetric.verify(App.getKey(sender), pack(), signature);
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

    getRecipientsByName: function() {
      return recipients.map(function(id) {
        return (App.hasKey(id)) ? (!App.isRejected(id)) ? PrintUtil.text(App.getKey(id).name) : 'Rejected' : 'Unknown';
      });
    },

    setRecipients: function(data) {
      recipients = data;
    }
  };
}

function KeyHelper(name, master, ephemeral) {

  function genPacketMpi(a) {
    return ArrayUtil.fromHalf(ArrayUtil.bitLength(a)).concat(a);
  }

  function genPacketLength(l) {
    return (l < 256) ? [l] : (l < 65536) ? ArrayUtil.fromHalf(l) : ArrayUtil.fromWord(l);
  }

  function genPacketTag(t, l) {
    return (l > 65535) ? [t*4 + 130] : (l > 255) ? [t*4 + 129] : [t*4 + 128];
  }

  function genEphemeralSigHead() {
    return [4,24,2,2,0,15,5,2].concat(ArrayUtil.fromWord(ephemeral.time+2))
                              .concat([2,27,4,5,9])
                              .concat(ArrayUtil.fromWord(86400));
  }

  function genMasterSigHead() {
    return [4,19,3,2,0,26,5,2].concat(ArrayUtil.fromWord(master.time+2))
                              .concat([2,27,3,5,9])
                              .concat(ArrayUtil.fromWord(86400))
                              .concat([4,11,7,8,9,2,21,2,2,22,0]);
  }

  function genBase(key) {
    return [4].concat(ArrayUtil.fromWord(key.created))
              .concat([key.type])
              .concat(genPacketMpi(key.data.n))
              .concat(genPacketMpi(key.data.e));
  }

  function genSigHash(head, tail) {
    return Hash.digest(
      [153].concat(ArrayUtil.fromHalf(head.length)).concat(head).concat(tail)
    );
  }

  function genEphemeralSigHash() {
    var keyHead, sigHead, suffix;

    keyHead = genBase(ephemeral);
    keyHead = [153].concat(ArrayUtil.fromHalf(keyHead.length)).concat(keyHead);

    sigHead = genEphemeralSigHead();
    suffix  = [4,255].concat(ArrayUtil.fromWord(sigHead.length));

    return genSigHash(genBase(ephemeral), keyHead.concat(sigHead).concat(suffix));
  }

  function genMasterSigHash() {
    var keyHead, sigHead, suffix;

    keyHead = [180].concat(ArrayUtil.fromWord(name.length))
                   .concat(ArrayUtil.fromString(name));

    sigHead = genMasterSigHead();
    suffix  = [4,255].concat(ArrayUtil.fromWord(sigHead.length));

    return genSigHash(genBase(master), keyHead.concat(sigHead).concat(suffix));
  }

  function genSigPacket(hash, head, signature) {
    var packet = head.concat([0, 10, 9, 16])
                     .concat(ArrayUtil.fromHex(master.iden.substr(-16)))//TODO: extract ID some better way
                     .concat(hash.slice(0, 2))
                     .concat(genPacketMpi(signature));

    return genPacketTag(2, packet.length).concat(genPacketLength(packet.length)).concat(packet);
  }

  function getNamePacket() {
    var namePacket = ArrayUtil.fromString(name);
    return genPacketTag(13, namePacket.length).concat(genPacketLength(namePacket.length)).concat(namePacket);
  }

  function getEphemeralSigPacket() {
    var head = genEphemeralSigHead(),
        hash = genEphemeralSigHash(),
        signature = genSignature(hash);

    return genSigPacket(hash, head, signature);
  }

  function getMasterSigPacket() {
    var head = genMasterSigHead(),
        hash = genMasterSigHash(),
        signature = genSignature(hash);

    return genSigPacket(hash, head, signature);
  }

  function genSignature(hash) {
    return Asymmetric.sign(master, hash, true);
  }

  function genFingerprint(base) {
    return ArrayUtil.toHex(Hash.digest([153].concat(ArrayUtil.fromHalf(base.length)).concat(base)));
  }

  function getPublicGpgPacket(key) {
    var len = 10 + key.data.n.length + key.data.e.length,
        tag = (key.type === C.TYPE_RSA_SIGN) ? 6 : 14;

    return genPacketTag(tag, len).concat(genPacketLength(len)).concat(genBase(key));
  }

  function getSecretGpgPacket(key) {
    var len = 21 + key.data.n.length + key.data.e.length + key.data.d.length + key.data.p.length + key.data.q.length + key.data.u.length,
        tag = (key.type === C.TYPE_RSA_SIGN) ? 5 : 7,
        tmp, sum;

    tmp = [0].concat(genPacketMpi(key.data.d));

    tmp = (App.calc.compare(key.data.p, key.data.q) === -1)
      ? tmp.concat(genPacketMpi(key.data.p)).concat(genPacketMpi(key.data.q))
      : tmp.concat(genPacketMpi(key.data.q)).concat(genPacketMpi(key.data.p));

    tmp = tmp.concat(genPacketMpi(key.data.u));
    sum = tmp.reduce(function(a, b) { return a + b }) % 65536;
    tmp = tmp.concat(ArrayUtil.fromHalf(sum));

    return genPacketTag(tag, len).concat(genPacketLength(len)).concat(genBase(key)).concat(tmp);
  }

  return {
    getPublicGpgKey: function() {
      return getPublicGpgPacket(master)
        .concat(getNamePacket())
        .concat(getMasterSigPacket())
        .concat(getPublicGpgPacket(ephemeral))
        .concat(getEphemeralSigPacket());
    },

    getSecretGpgKey: function() {
      return getSecretGpgPacket(master)
        .concat(getNamePacket())
        .concat(getMasterSigPacket())
        .concat(getSecretGpgPacket(ephemeral))
        .concat(getEphemeralSigPacket());
    },

    genEphemeralFingerprint: function() {
      return genFingerprint(genBase(ephemeral));
    },

    genMasterFingerprint: function() {
      return genFingerprint(genBase(master));
    }
  }
}