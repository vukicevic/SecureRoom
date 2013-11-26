/*            acceptKey: function(key) {
              this._addKey(key, "enabled");
            },

            rejectKey: function(key) {
              this._addKey(key, "rejected");
            },

            disableKey: function(id) {
              if (!this.isRejected(id))
                this._vault[id].status = "disabled";
            },

            enableKey: function(id) {
              if (!this.isRejected(id))
                this._vault[id].status = "enabled";
            }*/

function SecureRoom(callback) {
  var chain = {},
      prefs = {};

      prefs.room   = getRoom();
      prefs.server = getServer();
      prefs.cipher = {size: 128, type: 'AES'};
      prefs.key    = {size: 1024, type: 'RSA'};
      prefs.myid   = null;
      prefs.name   = null;

   
  function buildKey(type, data, time, name) {
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

    return key;
  }

  function onGenerate(data) {
    var key, id;
    
    if (prefs.myid) {
      key = buildKey(2, data, +new Date, prefs.name);
      key.sibling = prefs.myid;
      chain[prefs.myid].sibling = key.fingerprint.substr(-16);
    } else {
      key = buildKey(3, data, +new Date, prefs.name);
      prefs.myid = key.fingerprint.substr(-16);
    }

    key.status = 'active';
    key[key.fingerprint.substr(-16)] = key;

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