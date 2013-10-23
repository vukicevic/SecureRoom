keychain: { _keystore: {},
            _reverser: {},

            hasKey: function(id) {
              return (typeof this._keystore[id] != "undefined" || typeof this._reverser[id] != "undefined");
            },

            isEnabled: function(id) {
              return (this.hasKey(id) && this.getKey(id).status == "enabled");
            },

            isRejected: function(id) {
              return (this.hasKey(id) && this.getKey(id).status == "rejected");
            },

            getKey: function(id) {
              return this._keystore[id] || this._keystore[this._reverser[id]];
            },

            getKeyProperty: function(id, property) {
              if (typeof this._keystore[id] != "undefined") {
                return this._keystore[id].meta.sign[property];
              } else if (typeof this._reverser[id] != "undefined") {
                return this._keystore[this._reverser[id]].meta.encrypt[property];
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
                this._keystore[id].status = "disabled";
            },

            enableKey: function(id) {
              if (!this.isRejected(id))
                this._keystore[id].status = "enabled";
            },

            _addKey: function(key, status) {
              var meta = this._generateMeta(key);
              
              this._keystore[meta.signId].key    = key;
              this._keystore[meta.signId].name   = key.name;
              this._keystore[meta.signId].meta   = meta;
              this._keystore[meta.signId].status = status;
              this._reverser[meta.encryptId]     = meta.signId;
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