function Key(n, d, t, x, s) {
  return {
    name: n,
    type: t,
    time: x,
    data: d,
    size: ArrayUtil.bitLength(d.n),
    fingerprint: KeyTools.generateFingerprint(t, d, x),
    sibling: s
  }
}

function SecureRoom(callback) {
  var chain = {},
      prefs = {};

      prefs.room   = getRoom();
      prefs.server = getServer();
      prefs.cipher = {size: 128, type: 'AES'};
      prefs.key    = {size: 1024, type: 'RSA'};
      prefs.myid   = null;
      prefs.name   = null;

   
  function buildKey(type, data, time, name, sibling) {
    var key = {};
    
    key.name = name;
    key.type = type;
    key.time = time;
    
    key.public   = {};
    key.public.e = data.e; delete data.e;
    key.public.n = data.n; delete data.n;

    key.private  = data;

    key.size        = ArrayUtil.bitLength(key.public.n);
    key.fingerprint = KeyTools.generateFingerprint(key.type, key.public, key.time);
    key.sibling     = sibling;

    return key;
  }

  function getKey(id) {
    return chain[id];
  }

  function getKeys(type, status) {
    status = status || Const.STATUS_ACTIVE;
    return chain.filter(function(e) {
      if (e.type == type && e.status == status) return e;
    });
  }

  function onGenerate(data) {
    var key, id;
    
    if (prefs.myid) {
      key = buildKey(Const.TYPE_RSA_ENCRYPT, data, +new Date, prefs.name, prefs.myid);
      chain[prefs.myid].sibling = key.fingerprint.substr(-16);
    } else {
      key = buildKey(Const.TYPE_RSA_SIGN, data, +new Date, prefs.name);
      prefs.myid = key.fingerprint.substr(-16);
    }

    key.status = Const.STATUS_ACTIVE;
    chain[key.fingerprint.substr(-16)] = key;

    callback();
  }

  function setRoom(room) {
    if (!room) return;

    var opts = (window.location.search) ? window.location.search+'&room=' : '?room=',
        path = (window.location.pathname.indexOf('index.html') > -1) ? window.location.pathname+opts+room : window.location.pathname+room;
    
    window.history.replaceState({} , 'SecureRoom', path);
    prefs.room = room;
  }

  function getServer() {
    return (UrlUtil.getParameter('server')) ? 'wss://'+UrlUtil.getParameter('server')+':443/ws/'
                                            : 'wss://'+document.location.host+':443/ws/' );
  }

  function getRoom() {
    if (prefs.room) return prefs.room;

    prefs.room = window.location.pathname.substr(window.location.pathname.lastIndexOf('/')+1);
    if (prefs.room == 'index.html')
      prefs.room = UrlUtil.getParameter('room');

    return prefs.room;
  }

  return {
    generateKeys: function(name) {
      prefs.name = name;
      KeyGen(prefs.key.size, onGenerate)();
      KeyGen(prefs.key.size, onGenerate)();
    }
  },
}

var Const = {
  TYPE_RSA_SIGN: 3,
  TYPE_RSA_ENCRYPT: 2,
  STATUS_ACTIVE: 1,
  STATUS_PENDING: 0,
  STATUS_REJECTED: -1,
}