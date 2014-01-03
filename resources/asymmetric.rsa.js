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

var Asymmetric = {
  algorithm: 1,
  name: 'RSA',

  encrypt: function(key, data) {
    var pad = this.encryptPadding.encode(data, key.size);
    return mpi.c28to8(mpi.exp(mpi.c8to28(pad), mpi.c8to28(key.data.e), mpi.c8to28(key.data.n)));
  },

  decrypt: function(key, data) {
    var pad = mpi.c28to8(mpi.gar(mpi.c8to28(data), mpi.c8to28(key.data.p), mpi.c8to28(key.data.q), mpi.c8to28(key.data.d), mpi.c8to28(key.data.u), mpi.c8to28(key.data.dp), mpi.c8to28(key.data.dq)));
    return this.encryptPadding.decode(pad);
  },

  sign: function(key, data, prehashed) {
    var dat = this.signaturePadding.encode(key.size, data, prehashed);
    return mpi.c28to8(mpi.gar(mpi.c8to28(dat), mpi.c8to28(key.data.p), mpi.c8to28(key.data.q), mpi.c8to28(key.data.d), mpi.c8to28(key.data.u), mpi.c8to28(key.data.dp), mpi.c8to28(key.data.dq)));
  },

  verify: function(key, data, signature, prehashed) {
    var dat = mpi.c8to28(this.signaturePadding.encode(key.size, data, prehashed)),
        sig = mpi.exp(mpi.c8to28(signature), mpi.c8to28(key.data.e), mpi.c8to28(key.data.n));

    return (mpi.cmp(dat, sig) === 0);
  },

  signaturePadding: {
    name: 'EMSA-PKCS1-v1_5',

    encode: function(keysize, data, prehashed) {
      var pad = [],
          len = Math.floor((keysize + 7)/8) - (3 + hash.der.length + hash.length);

      while(len--)
        pad[len] = 255;

      if (!prehashed)
        data = hash.digest(data);

      return [1].concat(pad)
                .concat([0])
                .concat(hash.der)
                .concat(data);
    }
  },

  encryptPadding: {
    name: 'RSA-OAEP',

    mgf: function(z, l) {
      for (var t = [], c = [0,0,0,0], s = Math.ceil(l/20)-1, i = 0; i <= s; i++) {
        c[3] = i; //only implemented for l<5120 (i<256), only using lsb, key size can't be >5120
        t = t.concat(hash.digest(z.concat(c)));
      }
      return t.slice(0, l);
    },

    decode: function(data) {
      if (data.length < 41) return [];

      var le = 20,
          ms = data.slice(0, le),
          md = data.slice(le),
          sm = this.mgf(md, le),
          sd = mpi.xor(ms, sm),
          dm = this.mgf(sd, data.length-le),
          db = mpi.xor(md, dm);

      while (le < data.length) {
        if (db[le++] === 1) break;
      }

      //skip checking hash, if incorrect, it won't work anyway
      //return (mpi.cmp(db.slice(0, 20), sha1.hash(this.a28to8(this.pub.n))) === 0) ? db.slice(le) : [];
      return db.slice(le);
    },

    encode: function(data, size) {
      if ((data.length*8) > (size-328)) return [];

      var ln = Math.floor((size-8)/8),
          ps = mpi.zero.slice(0, ln-data.length-41),
          db = [218, 57, 163, 238, 94, 107, 75, 13, 50, 85, 191, 239, 149, 96, 24, 144, 175, 216, 7, 9].concat(ps.concat([1].concat(data))),
          sd = Random.generate(160),
          dm = this.mgf(sd, ln-20),
          md = mpi.xor(db, dm),
          sm = this.mgf(md, 20),
          ms = mpi.xor(sd, sm);

      return ms.concat(md);
    }
  }
}

function KeyGen(size, callback) {
  var w = {}, time, timer;

  function createWorker (worker, callback) {
    w[worker] = new Worker('resources/primes.js');
    w[worker].onmessage = function (e) {
      this.data = e.data;
      callback();
    };

    w[worker].postMessage(mpi.c8to28(Random.generate(size/2)));
  };

  function process() {
    if (w.p.data && w.q.data) {
      timer = null;
      var data = {};

      data.n = mpi.cut(mpi.mul(w.p.data, w.q.data));
      data.f = mpi.mul(mpi.dec(w.p.data), mpi.dec(w.q.data));

      var t = [257,65537,17,41,19], i = 0;
      do {
        data.e = [t[Math.floor(Math.random()*t.length)]];
        data.d = mpi.inv(data.e, data.f);
      } while (data.d.length == 0 && i++ < t.length);

      if (data.d.length == 0) {
        createWorker('p', process);
        createWorker('q', process);

        return;
      }

      data.u  = mpi.c28to8(mpi.cut(mpi.inv(w.p.data, w.q.data)));
      data.dp = mpi.c28to8(mpi.mod(data.d, mpi.dec(w.p.data)));
      data.dq = mpi.c28to8(mpi.mod(data.d, mpi.dec(w.q.data)));

      data.n = mpi.c28to8(data.n);
      data.f = mpi.c28to8(data.f);
      data.e = mpi.c28to8(data.e);
      data.d = mpi.c28to8(data.d);
      data.p = mpi.c28to8(w.p.data);
      data.q = mpi.c28to8(w.q.data);

      callback(data, Date.now() - time);
    }
  };

  function timeout() {
    return window.setTimeout(function() {
      if (!w.p.data) {
        w.p.terminate();
        createWorker('p', process);
      }

      if (!w.q.data) {
        w.q.terminate();
        createWorker('q', process);
      }

      if (!w.q.data || !w.p.data) timer = timeout();
    }, Math.floor((size*size)/100), w);
  };

  return function() { 
    time = Date.now();

    createWorker('p', process);
    createWorker('q', process);

    timer = timeout();
  };
}