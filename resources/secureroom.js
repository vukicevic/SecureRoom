/**
 * SecureRoom - Encrypted web browser based text communication software
 * Copyright (C) 2014 Nenad Vukicevic
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

function SecureRoom (onGenerateCallback, onConnectChangeCallback, onMessageCallback, onUserCallback) {
  this.vault  = new Vault;
  this.config = {};

  this.onConnect  = onConnectChangeCallback;
  this.onGenerate = onGenerateCallback;

  this.onMessage = function (message) {
    if (typeof message.data !== "undefined") {
      message = new Message(message);
      message.decrypt(this.user);

      var sender = this.vault.findUser(message.sender);
      if (sender && sender.accepted) {
        message.verify(sender);
      }
    }

    if (message.verified) {
      onMessageCallback(message);
    }
  };

  this.onUser = function (data) {
    var user = new User(data);

    if (!this.vault.hasUser(user.id) && user.verified) {
      this.vault.addUser(user);
      onUserCallback(user);
    }
  };
}

SecureRoom.prototype.generateUser = function (name, size) {
  this.user = new User(name);
  this.user.status = "active";
  this.user.generateKeys(size, this.onGenerate.bind(this));
}

SecureRoom.prototype.connectToServer = function () {
  this.channel = new CommChannel(this.config.server + this.config.room, this.onConnect.bind(this), this.onMessage.bind(this), this.onUser.bind(this));
}

SecureRoom.prototype.sendMessage = function (text) {
  var message = new Message(text);
  message.sign(this.user);
  message.encrypt(this.vault.findUsers("active"));

  this.channel.sendMessage(message);
  this.onMessage(message);
}

function Vault() {
  this.users = [];
}

Vault.prototype.addUser = function (user) {
  this.users.push(user);
}

Vault.prototype.findUser = function (id) {
  return this.users.filter(function (user) { return user.master.id === id || user.ephemeral.id === id }).pop();
}

Vault.prototype.findUsers = function (/* Call with desired user status - multiple accepted */) {
  var args = Array.prototype.slice.call(arguments);
  return this.users.filter(function (user) { return args.indexOf(user.status) >= 0 });
}

Vault.prototype.hasUser = function (id) {
  return this.users.some(function (user) { return user.master.id === id || user.ephemeral.id === id });
}

function CommChannel(server, onConnectChangeCallback, onMessageCallback, onUserCallback) {
  try {
    this.socket = new WebSocket(server);

    this.socket.addEventListener("open", onConnectChangeCallback);
    this.socket.addEventListener("close", onConnectChangeCallback);
    this.socket.addEventListener("message", function (event) {

      var receivedJSON = JSON.parse(event.data);

      switch (receivedJSON.type) {
        case "user":
          onUserCallback(receivedJSON.data);
          break;
        case "message":
          onMessageCallback(receivedJSON.data);
          break;
      }

    });
  } catch (e) {
    console.log(e);
  }
}

CommChannel.prototype.send = function (type, data) {
  if (this.isConnected()) {
    this.socket.send(JSON.stringify({"type": type, "data": data}));
  }
}

CommChannel.prototype.sendMessage = function (message) {
  this.send("message", message.toJSON());
}

CommChannel.prototype.sendUser = function (user) {
  this.send("user", user.toJSON());
}

CommChannel.prototype.isConnected = function () {
  return (typeof this.socket !== "undefined" && this.socket.readyState < 2);
}

function Message (data) {
  if (typeof data === "string") {
    this.plaintext = data;
    this.encrypted = {"keys": {}, "data": null};
  } else {
    this.encrypted = data;
  }
 
  this.sendtime = Math.round(Date.now()/1000);
  this.timediff = 0;
  this.sender;
  this.signature;
  this.verified = false;
}

Message.primitives = {
  random: Random(),
  hash: Hash(),
  symmetric: Symmetric(),
  asymmetric: Asymmetric(Crunch(), Hash(), Random())
}  

Message.prototype = {
  get recipients () {
    return Object.keys(this.encrypted.keys);
  }
}

Message.prototype.toJSON = function () {
  return this.encrypted;
}

Message.prototype.pack = function () {
  return ArrayUtil.fromString(this.plaintext).concat(0).concat(ArrayUtil.fromWord(this.sendtime)).concat(ArrayUtil.fromHex(this.sender));
}

Message.prototype.unpack = function (data) {
  var i = data.indexOf(0);

  this.plaintext = ArrayUtil.toString(data.slice(0, i));
  this.sendtime  = ArrayUtil.toWord(data.slice(i+1, i+5));
  this.sender    = ArrayUtil.toHex(data.slice(i+5, i+13));
  this.signature = data.slice(i+13);

  this.timediff = Math.round(Date.now()/1000) - this.sendtime;
}

Message.prototype.verify = function (user) {
  if (typeof user !== "undefined") {
    this.verified = Message.primitives.asymmetric.verify(user.master, Message.primitives.hash.digest(this.pack()), this.signature);
  }
}

Message.prototype.sign = function (user) {
  this.sender    = user.id;
  this.signature = Message.primitives.asymmetric.sign(user.master, Message.primitives.hash.digest(this.pack()));
  this.verified  = true;
}

Message.prototype.encrypt = function (recipients) {
  if (recipients.length) {
    var sessionkey = Message.primitives.random.generate(128);

    recipients.forEach(function (user) {
      this.encrypted.keys[user.ephemeral.id] = Message.primitives.asymmetric.encrypt(user.ephemeral, sessionkey);
    }, this);

    this.encrypted.data = Message.primitives.symmetric.encrypt(sessionkey, Message.primitives.random.generate(128).concat(this.pack()).concat(this.signature));
  }
}

Message.prototype.decrypt = function (receiver) {
  var sessionkey, decrypted;

  if (this.recipients.indexOf(receiver.ephemeral.id) >= 0 && receiver.ephemeral.isPrivate()) {
    sessionkey = Message.primitives.asymmetric.decrypt(receiver.ephemeral, this.encrypted.keys[receiver.ephemeral.id]);
    decrypted  = Message.primitives.symmetric.decrypt(sessionkey, this.encrypted.data).slice(16);
  }

  if (typeof decrypted !== "undefined") {
    this.unpack(decrypted);
  }
}

function User (data) {
  this.status = "pending";

  if (typeof data === "string") {
    this.name = data;
  } else {
    this.name = data.master.name;
    this.master = new Key(data.master.material, data.master.created, this.name);
    this.ephemeral = new Key(data.ephemeral.material, data.ephemeral.created);

    this.master.signatures = data.master.signatures;
    this.ephemeral.signatures = data.ephemeral.signatures;
  }
}

User.primitives = {
  asymmetric: Asymmetric(Crunch(), Hash(), Random())
}

User.prototype = {
  get id () {
    return this.master.id;
  },

  get verified () {
    return this.master.verify(this.master) && this.ephemeral.verify(this.master);
  },

  get accepted () {
    return this.status === "active" || this.status === "disabled";
  }
}

User.prototype.toJSON = function () {
  return {"master": this.master.toJSON(), "ephemeral": this.ephemeral.toJSON()};
}

User.prototype.addKey = function (callback, material) {
  if (typeof this.master === "undefined") {
    this.master = new Key(material, Math.round(Date.now()/1000), this.name);
    this.master.sign(this.master);
  } else {
    this.ephemeral = new Key(material, Math.round(Date.now()/1000));
    this.ephemeral.sign(this.master);
    
    callback();
  }
}

User.prototype.generateKeys = function (size, callback) {
  var cb = this.addKey.bind(this, callback);
  User.primitives.asymmetric.generate(size, cb);
  User.primitives.asymmetric.generate(size, cb);
}

function Key(material, created, name) {
  this.material    = material;
  this.created     = created;
  this.name        = name;
  this.signatures  = {};

  this.type        = (typeof name !== "undefined") ? 3 : 2;
  this.fingerprint = this.generateFingerprint();
}

Key.primitives = {
  hash: Hash(),
  asymmetric: Asymmetric(Crunch(), Hash(), Random())
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

    json.name = this.name;

    return json;
  },

  get size () {
    return ArrayUtil.bitLength(this.material.n);
  }
}

Key.prototype.toJSON = function () {
  var json = {};
    
  json.created    = this.created;
  json.signatures = this.signatures;
    
  json.material   = {};
  json.material.e = this.material.e;
  json.material.n = this.material.n;

  json.name = this.name;

  return json;
}

Key.prototype.makeBase = function () {
  return [4].concat(ArrayUtil.fromWord(this.created)).concat(this.type).concat(ArrayUtil.toMpi(this.material.n)).concat(ArrayUtil.toMpi(this.material.e));
}

Key.prototype.makeSignatureBase = function () {
  return (this.type === 3)
    ? [4,19,3,2,0,26,5,2].concat(ArrayUtil.fromWord(this.created)).concat(2,27,3,5,9).concat(ArrayUtil.fromWord(86400)).concat(4,11,7,8,9,2,21,2,2,22,0)
    : [4,24,2,2,0,15,5,2].concat(ArrayUtil.fromWord(this.created)).concat(2,27,4,5,9).concat(ArrayUtil.fromWord(86400));
}

Key.prototype.generateFingerprint = function () {
  var base = this.makeBase();
  return ArrayUtil.toHex(Key.primitives.hash.digest([153].concat(ArrayUtil.fromHalf(base.length)).concat(base)));
}

Key.prototype.generateSignatureHash = function (signer) {
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

  return Key.primitives.hash.digest(
    [153].concat(ArrayUtil.fromHalf(base.length)).concat(base).concat(keyHead).concat(sigHead).concat(suffix)
  );
}

Key.prototype.sign = function (signer) {
  if (signer.isPrivate() && signer.isMaster()) {
      var signatureHash = this.generateSignatureHash(signer),
          sigdata = {};

       sigdata.signature = Key.primitives.asymmetric.sign(signer, signatureHash);
       sigdata.hashcheck = signatureHash.slice(0, 2);
      this.signatures[signer.id] = sigdata;
  }
}

Key.prototype.verify = function (signer) {
  if (signer.id in this.signatures) {
     return Key.primitives.asymmetric.verify(signer, this.generateSignatureHash(signer), this.signatures[signer.id].signature);
  }
}

Key.prototype.isMaster = function () {
  return this.type === 3;
}

Key.prototype.isPrivate = function () {
  return typeof this.material.d !== "undefined";
}