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
      return Object.keys(chain).filter(function(id) {
        return id !== prefs.myid && id !== chain[prefs.myid].peer && chain[id].type === type && chain[id].mode === mode;
      });
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

  function makeMpi(a) {
    return ArrayUtil.fromHalf(ArrayUtil.bitLength(a)).concat(a);
  }

  function makeLength(l) {
    return (l < 256) ? [l] : (l < 65536) ? ArrayUtil.fromHalf(l) : ArrayUtil.fromWord(l);
  }

  function makeOrderedMpi(p, q) {
    return (App.calc.compare(p, q) === -1) ? makeMpi(p).concat(makeMpi(q)) : makeMpi(q).concat(makeMpi(p));
  }

  function makeTag(t, l) {
    return (l > 65535) ? [t*4 + 130] : (l > 255) ? [t*4 + 129] : [t*4 + 128];
  }

  function generateSigHash(head, tail) {
    return Hash.digest(
      [153].concat(ArrayUtil.fromHalf(head.length)).concat(head).concat(tail)
    );
  }

  function generateEphemeralSigHash() {
    var keyHead, sigHead, suffix;

    keyHead = makeBase(ephemeral);
    keyHead = [153].concat(ArrayUtil.fromHalf(keyHead.length)).concat(keyHead);

    sigHead = makeEphemeralSigHead();
    suffix  = [4,255].concat(ArrayUtil.fromWord(sigHead.length));

    return generateSigHash(makeBase(master), keyHead.concat(sigHead).concat(suffix));
  }

  function generateMasterSigHash() {
    var keyHead, sigHead, suffix;

    keyHead = [180].concat(ArrayUtil.fromWord(name.length))
                   .concat(ArrayUtil.fromString(name));

    sigHead = makeMasterSigHead();
    suffix  = [4,255].concat(ArrayUtil.fromWord(sigHead.length));

    return generateSigHash(makeBase(master), keyHead.concat(sigHead).concat(suffix));
  }

  function generateSignature(hash) {
    return Asymmetric.sign(master, hash, true);
  }

  function generateFingerprint(base) {
    return ArrayUtil.toHex(Hash.digest([153].concat(ArrayUtil.fromHalf(base.length)).concat(base)));
  }

  function generateChecksum(array) {
    return ArrayUtil.fromHalf(array.reduce(function(a, b) { return a + b }) % 65536);
  }

  function makeEphemeralSigHead() {
    return [4,24,2,2,0,15,5,2].concat(ArrayUtil.fromWord(ephemeral.time+2))
                              .concat([2,27,4,5,9])
                              .concat(ArrayUtil.fromWord(86400));
  }

  function makeMasterSigHead() {
    return [4,19,3,2,0,26,5,2].concat(ArrayUtil.fromWord(master.time+2))
                              .concat([2,27,3,5,9])
                              .concat(ArrayUtil.fromWord(86400))
                              .concat([4,11,7,8,9,2,21,2,2,22,0]);
  }

  function makeSigPacket(hash, head, signature) {
    var packet = head.concat([0, 10, 9, 16])
                     .concat(ArrayUtil.fromHex(master.iden.substr(-16)))//TODO: extract ID more elegantly
                     .concat(hash.slice(0, 2))
                     .concat(makeMpi(signature));

    return makeTag(2, packet.length).concat(makeLength(packet.length)).concat(packet);
  }

  function makeEphemeralSigPacket() {
    var head = makeEphemeralSigHead(),
        hash = generateEphemeralSigHash(),
        signature = generateSignature(hash);

    return makeSigPacket(hash, head, signature);
  }

  function makeMasterSigPacket() {
    var head = makeMasterSigHead(),
        hash = generateMasterSigHash(),
        signature = generateSignature(hash);

    return makeSigPacket(hash, head, signature);
  }

  function makeBase(key) {
    return [4].concat(ArrayUtil.fromWord(key.time))
              .concat([key.type])
              .concat(makeMpi(key.data.n))
              .concat(makeMpi(key.data.e));
  }

  function makePublicKeyPacket(key) {
    var len = 10 + key.data.n.length + key.data.e.length,
        tag = (key.type === C.TYPE_RSA_SIGN) ? 6 : 14;

    return makeTag(tag, len).concat(makeLength(len)).concat(makeBase(key));
  }

  function makeSecretKeyPacket(key) {
    var len = 21 + key.data.n.length + key.data.e.length + key.data.d.length + key.data.p.length + key.data.q.length + key.data.u.length,
        tag = (key.type === C.TYPE_RSA_SIGN) ? 5 : 7,
        tmp = [0].concat(makeMpi(key.data.d))
                 .concat(makeOrderedMpi(key.data.p, key.data.q))
                 .concat(makeMpi(key.data.u));

    return makeTag(tag, len).concat(makeLength(len)).concat(makeBase(key)).concat(tmp).concat(generateChecksum(tmp));
  }

  function makeNamePacket() {
    var packet = ArrayUtil.fromString(name);
    return makeTag(13, packet.length).concat(makeLength(packet.length)).concat(packet);
  }

  return {
    getPublicGpgKey: function() {
      var packets = makePublicKeyPacket(master)
        .concat(makeNamePacket())
        .concat(makeMasterSigPacket())
        .concat(makePublicKeyPacket(ephemeral))
        .concat(makeEphemeralSigPacket());

      return ArmorUtil.dress({"type": "PUBLIC KEY BLOCK", "headers": {"Version": "SecureRoom 1.0"}, "packets": packets});
    },

    getSecretGpgKey: function() {
      var packets = makeSecretKeyPacket(master)
        .concat(makeNamePacket())
        .concat(makeMasterSigPacket())
        .concat(makeSecretKeyPacket(ephemeral))
        .concat(makeEphemeralSigPacket());

      return ArmorUtil.dress({"type": "PRIVATE KEY BLOCK", "headers": {"Version": "SecureRoom 1.0"}, "packets": packets});
    },

    getEphemeralFingerprint: function() {
      return generateFingerprint(makeBase(ephemeral));
    },

    getMasterFingerprint: function() {
      return generateFingerprint(makeBase(master));
    }
  }
}