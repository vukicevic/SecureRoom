function SecureRoom(onGenerateCallback, onConnectCallback, onDisconnectCallback, onMessageCallback, onUserCallback) {
  this.vault  = new Vault();
  this.config = {};

  this.channel;
  this.user;

  this.config.room = window.location.pathname.substr(window.location.pathname.lastIndexOf("/")+1);

  if (this.config.room === "index.html") {
    this.config.room = UrlUtil.getParameter("room");
  }

  this.config.server = UrlUtil.getParameter("server") ? "wss://"+UrlUtil.getParameter("server")+":443/ws/" : "wss://"+document.location.host+":443/ws/";

  this.config.cipher = {"size": 128,  "type": "AES"};
  this.config.key    = {"size": 1024, "type": "RSA"};

  this.onConnect = function() {
    onConnectCallback();
  };

  this.onDisconnect = function() {
    onDisconnectCallback();
  };

  this.onMessage = function(data) {
    var message = new Message(data);

    message.decrypt(this.user);
    message.verify(this.vault.getUser(message.sender));

    if (message.verified) {
      onMessageCallback(message);
    }
  };

  /* Key algo specific */
  this.onGenerate = function(data, time) {
    if (typeof this.user !== "undefined") {
      this.user.ephemeral = new Key(data, Math.round(Date.now()/1000));

      this.user.master.sign(this.user.master);
      this.user.ephemeral.sign(this.user.master);

      this.user.status = "active";

      this.room = this.user.id.substr(-5);

      this.vault.addUser(this.user);
        
      onGenerateCallback();
    } else {
      this.user = new User(new Key(data, Math.round(Date.now()/1000), this.config.name));
    }

    console.log("Key generation time (ms): " + time);
  };

  this.onUser = function(data) {
    var mkey = new Key(data.master.material, data.master.created, data.master.name),
        ekey = new Key(data.ephemeral.material, data.ephemeral.created), 
        user;

    mkey.signatures = data.master.signatures;
    ekey.signatures = data.ephemeral.signatures;

    if (!this.vault.hasUser(mkey.id) && mkey.verify(mkey) && ekey.verify(mkey)) {
      user = new User(mkey);
      user.ephemeral = ekey;

      this.vault.addUser(user);

      onUserCallback(user);
    }
  };
  /* Key algo specific */
}

SecureRoom.prototype.createRoom = function() {
  if (this.config.room !== "") {
    this.config.room = room;

    var opts = (window.location.search) ? window.location.search+"&room=" : "?room=",
        path = (window.location.pathname.indexOf("index.html") > -1) ? window.location.pathname+opts+this.config.room : window.location.pathname+this.config.room;

    window.history.replaceState({} , "SecureRoom", path);
  }
}

SecureRoom.prototype.generateUser = function(name) {
  this.config.name = name;

  KeyGen(primitives.crunch, primitives.random)(this.config.key.size, this.onGenerate);
  KeyGen(primitives.crunch, primitives.random)(this.config.key.size, this.onGenerate);
}

SecureRoom.prototype.connectToServer = function() {
  this.channel = new CommChannel(this.config.server + this.config.room, this.onConnect, this.onDisconnect, this.onMessage, this.onUser);
}


function User(data) {
  this.status = "pending";

  this.master;
  this.ephemeral;

  if (typeof data.master !== "undefined") {
    
  } else {
    this.master = data;
    this.master.sign(this.master);
  }
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
    },

    get verified () {
      return this.master.verified && this.ephemeral.verified;
    }
}

User.prototype.addEphemeralKey = function(key) {
  if (this.master.isPrivate()) {
    this.ephemeral = key;
    this.ephemeral.sign(this.master);
  }
}


function Vault() {
  this.users = [];
}

Vault.prototype.addUser = function(user) {
  this.users.push(user);
}

Vault.prototype.getUser = function(id) {
  return this.users.filter(function(user) { return user.master.id === id || user.ephemeral.id === id }).pop();
}

Vault.prototype.getUsers = function(/* Call with desired user status - multiple accepted */) {
  var args = Array.prototype.slice.call(arguments);
  
  return this.users.filter(function(user) { return args.indexOf(user.status) >= 0 });
}

Vault.prototype.hasUser = function(id) {
  return this.users.some(function(user) { return user.master.id === id || user.ephemeral.id === id });
}

function CommChannel(server, onConnectCallback, onDisconnectCallback, onMessageCallback, onUserCallback) {
  try {
    this.socket = new WebSocket(server);

    this.socket.addEventListener("open", onConnectCallback);
    this.socket.addEventListener("close", onDisconnectCallback);

    this.socket.addEventListener("message", function (event) {
      var receivedJSON = JSON.parse(event.data);

      switch (receivedJSON.type) {
        case 'user':
          onUserCallback(receivedJSON.data); break;
        case 'message':
          onMessageCallback(receivedJSON.data); break;
      }

      console.log(receivedJSON);
    });
  } catch (e) {
    console.log(e);
  }
}

CommChannel.prototype.sendMessage = function (message) {
  if (this.isConnected()) {
    this.socket.send(JSON.stringify({"type": "message", "data": message.encrypted}));
  }
}

CommChannel.prototype.sendUser = function (user) {
  if (this.isConnected()) {
    this.socket.send(JSON.stringify({"type": "user", "data": user.json}));
  }
}

CommChannel.prototype.isConnected = function () {
  return (typeof this.socket !== "undefined" && this.socket.readyState < 2);
}


function Message(data) {
  if (typeof data === "string") {
    this.plaintext = data;
  } else {
    this.encrypted = data;
  }
 
  this.sendtime = Math.round(Date.now()/1000);
  this.timediff = 0;
  this.sender;
  this.recipients;
  this.signature;
  this.verified = false;
}

Message.prototype.pack = function() {
  return ArrayUtil.fromString(this.plaintext).concat(0).concat(ArrayUtil.fromWord(this.sendtime)).concat(ArrayUtil.fromHex(this.sender));
}

Message.prototype.unpack = function(data) {
  var i = data.indexOf(0);

  this.plaintext = ArrayUtil.toString(data.slice(0, i));
  this.sendtime  = ArrayUtil.toWord(data.slice(i+1, i+5));
  this.sender    = ArrayUtil.toHex(data.slice(i+5, i+13));
  this.signature = data.slice(i+13);

  this.timediff = Math.round(Date.now()/1000) - this.sendtime;
}

Message.prototype.verify = function(user) {
  if (typeof user !== "undefined") {
    this.verified = primitives.asymmetric.verify(user.master, primitives.hash.digest(this.pack()), this.signature);
  }
}

Message.prototype.sign = function(user) {
  this.sender    = user.id;
  this.signature = primitives.asymmetric.sign(user.master, primitives.hash.digest(this.pack()));
  this.verified  = true;
}

Message.prototype.encrypt = function (sender, recipients, sessionkey) {
  this.encrypted = {"keys": {}, "data": null};

  if (recipients.length) {
    recipients.forEach(function(user) {
      this.encrypted.keys[user.id] = primitives.asymmetric.encrypt(user.ephemeral, sessionkey);
    });

    this.encrypted.data = primitives.symmetric.encrypt(sessionkey, primitives.random.generate(128).concat(this.pack()).concat(this.signature));
  }
}

Message.prototype.decrypt = function (receiver) {
  var sessionkey, decrypted;

  this.recipients = Object.keys(this.encrypted.keys);

  if (this.recipients.indexOf(receiver.id) >= 0 && receiver.ephemeral.isPrivate()) {
    sessionkey = primitives.asymmetric.decrypt(receiver.ephemeral, this.encrypted.keys[id]);
    decrypted  = primitives.symmetric.decrypt(sessionkey, this.encrypted.data).slice(16);
  }

  if (typeof decrypted !== "undefined") {
    this.unpack(decrypted);
  }
}