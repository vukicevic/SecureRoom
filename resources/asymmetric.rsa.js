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

function Asymmetric(crunch, hash) {
  //EMSA-PKCS1-v1_5
  function emsaEncode(keysize, data, prehashed) {
    var pad = [],
        len = ~~((keysize + 7)/8) - (3 + hash.der.length + hash.length);

    while(len--)
      pad[len] = 255;

    if (!prehashed)
      data = hash.digest(data);

    return [1].concat(pad)
      .concat([0])
      .concat(hash.der)
      .concat(data);
  }

  //RSA-OAEP
  function oaepMgf(z, l) {
    for (var t = [], c = [0,0,0,0], s = Math.ceil(l/20)-1, i = 0; i <= s; i++) {
      c[3] = i; //only implemented for l<5120 (i<256), key size can't be >5120
      t = t.concat(hash.digest(z.concat(c)));
    }

    return t.slice(0, l);
  }

  function oaepDecode(data) {
    if (data.length < 41) return [];

    var le = 20,
        ms = data.slice(0, le),
        md = data.slice(le),
        sm = oaepMgf(md, le),
        sd = crunch.xor(ms, sm),
        dm = oaepMgf(sd, data.length-le),
        db = crunch.xor(md, dm);

    //skip checking hash, (crunch.compare(db.slice(0, 20), Hash('')) === 0)

    return db.slice(db.indexOf(1, le)+1);
  }

  function oaepEncode(data, size) {
    if ((data.length*8) > (size-328)) return [];

    var ln = ~~((size-8)/8),
        ps = crunch.zero(ln - data.length - 41),
        db = [218, 57, 163, 238, 94, 107, 75, 13, 50, 85, 191, 239, 149, 96, 24, 144, 175, 216, 7, 9].concat(ps).concat([1]).concat(data),
        sd = Random.generate(hash.length * 8),
        dm = oaepMgf(sd, ln - 20),
        md = crunch.xor(db, dm),
        sm = oaepMgf(md, 20),
        ms = crunch.xor(sd, sm);

    return ms.concat(md);
  }

  return {
    encrypt: function(key, data) {
      var pad = oaepEncode(data, key.size);
      return crunch.exp(pad, key.data.e, key.data.n);
    },

    decrypt: function(key, data) {
      var pad = crunch.gar(data, key.data.p, key.data.q, key.data.d, key.data.u, key.data.dp, key.data.dq);
      return oaepDecode(pad);
    },

    sign: function(key, data, prehashed) {
      var dat = emsaEncode(key.size, data, prehashed);
      return crunch.gar(dat, key.data.p, key.data.q, key.data.d, key.data.u, key.data.dp, key.data.dq);
    },

    verify: function(key, data, signature, prehashed) {
      var dat = emsaEncode(key.size, data, prehashed),
          sig = crunch.exp(signature, key.data.e, key.data.n);

      return (crunch.compare(dat, sig) === 0);
    }
  }
}

function KeyGen(size, callback, crunch) {
  var w = {}, time, timer;

  if (typeof crunch === "undefined")
    crunch = Crunch();

  function createWorker (worker, callback) {
    w[worker] = new Worker("resources/external/crunch.js");

    w[worker].onmessage = function (e) {
      this.data = e.data;
      callback();
    };

    w[worker].postMessage({"func": "nextPrime",
                           "args": [Random.generate(size/2)]});
  }

  function process() {
    if (w.p.data && w.q.data) {
      timer = null;
      var mpi = {},
          exp = [[17], [19], [41], [1,1], [1,0,1]].sort(function(){ return 0.5 - Math.random() });

      mpi.n = crunch.cut(crunch.mul(w.p.data, w.q.data));
      mpi.f = crunch.mul(crunch.decrement(w.p.data), crunch.decrement(w.q.data));

      do {
        mpi.e = exp.pop();
        mpi.d = crunch.inv(mpi.e, mpi.f);
      } while (mpi.d.length === 0 && exp.length);

      if (mpi.d.length === 0) {
        createWorker('p', process);
        createWorker('q', process);

        return;
      }

      mpi.u  = crunch.cut(crunch.inv(w.p.data, w.q.data));
      mpi.dp = crunch.mod(mpi.d, crunch.decrement(w.p.data));
      mpi.dq = crunch.mod(mpi.d, crunch.decrement(w.q.data));

      if (crunch.compare(w.p.data, w.q.data) <= 0) {
        mpi.p = w.p.data.slice();
        mpi.q = w.q.data.slice();
      } else {
        mpi.p = w.q.data.slice();
        mpi.q = w.p.data.slice();
      }

      callback(mpi, Date.now() - time);
    }
  }

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

      if (!w.q.data || !w.p.data)
        timer = timeout();

    }, Math.floor((size*size)/100), w);
  }

  return function() {
    time = Date.now();

    createWorker('p', process);
    createWorker('q', process);

    timer = timeout();
  };
}