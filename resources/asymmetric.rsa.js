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

function Asymmetric(crunch, hash, random) {
  //EMSA-PKCS1-v1_5
  function emsaEncode(keysize, data) {
    var pad = [],
        len = ~~((keysize + 7)/8) - (3 + hash.der.length + hash.length);

    while(len--)
      pad[len] = 255;

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
        sd = random.generate(hash.length * 8),
        dm = oaepMgf(sd, ln - 20),
        md = crunch.xor(db, dm),
        sm = oaepMgf(md, 20),
        ms = crunch.xor(sd, sm);

    return ms.concat(md);
  }

  return {
    encrypt: function(key, data) {
      var encoded = oaepEncode(data, key.size);
      return crunch.exp(encoded, key.material.e, key.material.n);
    },

    decrypt: function(key, data) {
      var decrypted = crunch.gar(data, key.material.p, key.material.q, key.material.d, key.material.u, key.material.dp, key.material.dq);
      return oaepDecode(decrypted);
    },

    sign: function(key, data) {
      var encoded = emsaEncode(key.size, data);
      return crunch.gar(encoded, key.material.p, key.material.q, key.material.d, key.material.u, key.material.dp, key.material.dq);
    },

    verify: function(key, data, signature) {
      var encoded = emsaEncode(key.size, data),
          signature = crunch.exp(signature, key.material.e, key.material.n);

      return (crunch.compare(encoded, signature) === 0);
    }
  }
}

function KeyGen(crunch, random) {
  var w = {}, time, timer, size, user;

  function createWorker (worker, callback) {
    w[worker] = new Worker("resources/external/crunch.js");

    w[worker].onmessage = function (e) {
      this.data = e.data;
      callback();
    };

    w[worker].postMessage({"func": "nextPrime",
                           "args": [random.generate(size/2)]});
  }

  function process() {
    if (w.p.data && w.q.data) {
      timer = null;
      var mpi = {},
          exp = [[17], [19], [41], [1,1], [1,0,1]].sort(function(){ return 0.5 - Math.random() });

      if (crunch.compare(w.p.data, w.q.data) <= 0) {
        mpi.p = w.p.data.slice();
        mpi.q = w.q.data.slice();
      } else {
        mpi.p = w.q.data.slice();
        mpi.q = w.p.data.slice();
      }

      mpi.n = crunch.cut(crunch.mul(mpi.p, mpi.q));
      mpi.f = crunch.mul(crunch.decrement(mpi.p), crunch.decrement(mpi.q));

      do {
        mpi.e = exp.pop();
        mpi.d = crunch.inv(mpi.e, mpi.f);
      } while (mpi.d.length === 0 && exp.length);

      if (mpi.d.length > 0) {
        mpi.u  = crunch.cut(crunch.inv(mpi.p, mpi.q));
        mpi.dp = crunch.mod(mpi.d, crunch.decrement(mpi.p));
        mpi.dq = crunch.mod(mpi.d, crunch.decrement(mpi.q));

        //Date.now() - time
        user.addKey(mpi);
      } else {
        createWorker('p', process);
        createWorker('q', process);
      }
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

  return function(s, c) {
    size = s;
    user = c;
    time = Date.now();

    createWorker('p', process);
    createWorker('q', process);

    timer = timeout();
  };
}