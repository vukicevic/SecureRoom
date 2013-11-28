function SecureRoom(callback) {
  var chain = {},
      prefs = {};

      prefs.room   = window.location.pathname.substr(window.location.pathname.lastIndexOf('/')+1);
      if (prefs.room == 'index.html') prefs.room = UrlUtil.getParameter('room');

      prefs.server = (UrlUtil.getParameter('server')) ? 'wss://'+UrlUtil.getParameter('server')+':443/ws/'
                                                      : 'wss://'+document.location.host+':443/ws/' );

      prefs.cipher = {size: 128, type: 'AES'};
      prefs.key    = {size: 1024, type: 'RSA'};
      prefs.myid   = null;
      prefs.name   = null;
   
  function buildKey(n, t, d, c, m, s) {
    var key = { name: n, type: t, data: d, time: c, mode: m, sign: s,
                size: ArrayUtil.bitLength(d.n),
                iden: KeyTools.generateFingerprint(t, d, x) },
        id  = key.iden.substr(-16);

    chain[id] = key;

    return id;
  }

  function onGenerate(data) {
    if (prefs.myid) {
      var id = buildKey(prefs.name, C.TYPE_RSA_ENCRYPT, data, +new Date, C.STATUS_ACTIVE);
      chain[prefs.myid].peer = id;
      chain[id].peer = prefs.myid;

      chain[id].sign = Asymmetric.sign(chain[prefs.myid].data, KeyUtil.generateSignatureHash(chain[prefs.myid], chain[id]), true);

      callback();
    } else {
      prefs.myid = buildKey(prefs.name, C.TYPE_RSA_SIGN, data, +new Date, C.STATUS_ACTIVE);

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
      status = status || C.STATUS_ACTIVE;
      return chain.filter(function(e) {
        if (e.type == type && e.status == status) return e;
      });
    },

    getKey: function(id) {
      return chain[id];
    },

    setKey: function(name, key1, key2) {
      var id1 = buildKey(name, key1.type, key1.data, key1.time, C.STATUS_PENDING, key1.sign),
          id2 = buildKey(name, key2.type, key2.data, key2.time, C.STATUS_PENDING, key2.sign);

      chain[id1].peer = id2;
      chain[id2].peer = id1;

      //verify key signature, reject outright if sig is wrong

      return (key1.type == C.TYPE_RSA_SIGN) ? id1 : id2;
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

var C = {
  TYPE_RSA_SIGN: 3,
  TYPE_RSA_ENCRYPT: 2,
  STATUS_ACTIVE: 1,
  STATUS_PENDING: 0,
  STATUS_REJECTED: -1,
}
/*
TODO: change KeyUtil.generateSignatureHash & other functions because of Key changes
TODO: change Asymmetric functions because of Key data struct changes
*/