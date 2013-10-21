{
keychain: { accepted: {},
              rejected: {},
              reverser: {},

              getKey: function(id) {
                return this.accepted[id];
              },

              getKeyByMapping: function(id) {
                return this.accepted[this.reverser[id]];
              },

              acceptKey: function(key) {
                var meta = { "sign": {},
                             "encrypt": {} };

                meta.sign.fingerprint    = this.calcFingerprint(key.sign);
                meta.encrypt.fingerprint = this.calcFingerprint(key.encrypt);

                meta.sign.size = this.calcMpiLength(key.sign.mpi.n, true);
                meta.encrypt.size = this.calcMpiLength(key.encrypt.mpi.n, true);

                var sid = meta.sign.fingerprint.substr(-16),
                    eid = meta.encrypt.fingerprint.substr(-16);

                this.accepted[sid].key    = key;
                this.accepted[sid].name   = key.name;
                this.accepted[sid].meta   = meta;
                this.accepted[sid].active = true;

                this.reverser[eid] = sid;
              },

              rejectKey: function(key) {
                var sid = this.calcFingerprint(key.sign).substr(-16),
                    eid = this.calcFingerprint(key.encrypt).substr(-16);

                    this.rejected[sid] = Math.round(+new Date()/1000);
                    this.reverser[eid] = sid;
              },

              calcMpiLength: function(mpi, bits) {
                for (var i = 0, m = 128; i < 8; i++, m /= 2)
                  if (mpi[0] >= m)
                    break;

                m = mpi.length*8 - i;
                return (bits) ?  m : [m >> 8, m & 0xff];
              },

              calcFingerprint: function(data) {
                data = [4].concat(array.fromWord(data.created)).concat([data.type]).concat(this.calcMpiLength(data.mpi.n)).concat(data.mpi.n).concat(this.calcMpiLength(data.mpi.e)).concat(data.mpi.e);
                return array.toHex(hash.digest([0x99, (data.length >> 8), (data.length & 0xff)].concat(data)));
              }
            }
}