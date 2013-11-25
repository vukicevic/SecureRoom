keychain: { _vault: {},
            _map: {},

            hasKey: function(id) {
              return (typeof this._vault[id] != "undefined" || typeof this._map[id] != "undefined");
            },

            isEnabled: function(id) {
              return (this.hasKey(id) && this.getKey(id).status == "enabled");
            },

            isRejected: function(id) {
              return (this.hasKey(id) && this.getKey(id).status == "rejected");
            },

            getKey: function(id) {
              return this._vault[id] || this._vault[this._map[id]];
            },

            getKeyType: function(id) {
              if (typeof this._vault[id] != "undefined") {
                return "sign";
              } else if (typeof this._map[id] != "undefined") {
                return "encrypt";
              }

              return;
            },

            getKeyProperty: function(id, property) {
              if (this.hasKey(id)) {
                return this.getKey(id).meta[this.getKeyType(id)][property];
              }

              return;
            },

            acceptKey: function(key) {
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
            },

            _addKey: function(key, status) {
              var meta = this._generateMeta(key);
              
              this._vault[meta.sign.id].key    = key;
              this._vault[meta.sign.id].name   = key.name;
              this._vault[meta.sign.id].meta   = meta;
              this._vault[meta.sign.id].status = status;
              this._map[meta.encrypt.id]       = meta.sign.id;
            },

            _generateMeta: function(key) {
              var meta = {sign: {}, encrypt: {}};
              
              meta.sign.fingerprint    = this._generateFingerprint(key.sign, 3);
              meta.sign.size           = this._mpiLength(key.sign.mpi.n);
              meta.sign.id             = meta.sign.fingerprint.substr(-16);

              meta.encrypt.fingerprint = this._generateFingerprint(key.encrypt, 2);
              meta.encrypt.size        = this._mpiLength(key.encrypt.mpi.n);
              meta.encrypt.id          = meta.encrypt.fingerprint.substr(-16);

              return meta;
            },

            _mpiLength: function(mpi) {
              for (var i = 0, m = 128; i < 8; i++, m /= 2)
                if (mpi[0] >= m) break;

              return (mpi.length*8 - i);
            },

            _generateFingerprint: function(key, type) {
              var nlen = this._mpiLength(key.mpi.n),
                  elen = this._mpiLength(key.mpi.e),
                  data = [4].concat(array.fromWord(key.created))
                            .concat([type])
                            .concat([nlen>>8, nlen&0xff])
                            .concat(key.mpi.n)
                            .concat([elen>>8, elen&0xff])
                            .concat(key.mpi.e);

              return array.toHex(hash.digest([0x99, (data.length >> 8), (data.length & 0xff)].concat(data)));
            }
          }



chain = {'abcde123': {type: '', created: '', mpi: '', private: '', size: '', fingerprint: '', signature: '', name: '', sister: ''}}

function SecureRoom(callback) {
  var chain = {},
      prefs = {},
      mykey = '';

      prefs.room   = getRoom();
      prefs.server = getServer();
      prefs.cipher = {size: 128, type: 'AES'};
      prefs.key    = {size: 1024, type: 'RSA'};

   
  function buildKey() {
    //type
    //created
    //mpi

    //size
    //fingerpring
    //signature
  }

  function onGenerate(type, data) {
    return;
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
      var kg = KeyGen(prefs.key.size, onGenerate)
      kg();
      kg();
    }
  },
}

var UrlUtil = {
  getParameter: function(name) {
    var match = RegExp('[?&]' + name + '=([^&]*)').exec(window.location.search);
    return (match) ? decodeURIComponent(match[1].replace(/\+/g, ' ')) : '';
  }
}