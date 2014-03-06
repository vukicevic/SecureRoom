function SecureComm(server, onConnectCallback, onDisconnectCallback, onMessageCallback, onUserCallback) {

  try {
    this.socket = new WebSocket(server);

    this.socket.addEventListener("open", onConnectCallback);
    this.socket.addEventListener("close", onDisconnectCallback);
    this.socket.addEventListener("message", function (event) {
      var receivedJSON = JSON.parse(event.data);

      switch (receivedJSON.type) {
        case 'user':
          onUserCallback(receivedJSON.data);
          break;
        case 'message':
          onMessageCallback(receivedJSON.data);
          break;
      }

      console.log(receivedJSON);
    });
  } catch (e) {
    console.log(e);
  }

}

SecureComm.prototype.sendMessage = function (message) {
  this.socket.send(JSON.stringify({"type": "message", "data": message.json}));
}

SecureComm.prototype.sendUser = function (user) {
  this.socket.send(JSON.stringify({"type": "user", "data": user.json}));
}



function Message(data, encrypted) {
  this.data = data;
  this.encrypted = encrypted;
 
  this.sendtime = Math.round(Date.now()/1000);
  this.timediff = 0;
  this.sender;
  this.recipients;
  this.signature;
  this.verified = false;
}

Message.prototype.pack = function() {
  if (!this.encrypted) {
    return ArrayUtil.fromString(this.data).concat(0).concat(ArrayUtil.fromWord(this.sendtime)).concat(ArrayUtil.fromHex(this.sender));
  }
}

Message.prototype.unpack = function(data) {
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

Message.prototype.sign = function(key) {
  this.sender    = key.id;
  this.signature = primitives.asymmetric.sign(key, primitives.hash.digest(this.pack()));
  this.verified  = true;
}

Message.prototype.encrypt = function (sender, recipients) {

}

Message.prototype.decrypt = function (receiver) {

}