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
    return mpi.c28to8(mpi.exp(mpi.c8to28(pad), mpi.c8to28(key.mpi.e), mpi.c8to28(key.mpi.n)));
  },

  decrypt: function(key, data) {
    var pad = mpi.c28to8(mpi.gar(mpi.c8to28(data), mpi.c8to28(key.mpi.p), mpi.c8to28(key.mpi.q), mpi.c8to28(key.mpi.d), mpi.c8to28(key.mpi.u), mpi.c8to28(key.mpi.dp), mpi.c8to28(key.mpi.dq)));
    return this.encryptPadding.decode(pad);
  },

  sign: function(key, data, prehashed) {
    var dat = this.signaturePadding.encode(key.size, data, prehashed);
    return mpi.c28to8(mpi.gar(mpi.c8to28(dat), mpi.c8to28(key.mpi.p), mpi.c8to28(key.mpi.q), mpi.c8to28(key.mpi.d), mpi.c8to28(key.mpi.u), mpi.c8to28(key.mpi.dp), mpi.c8to28(key.mpi.dq)));
  },

  verify: function(key, data, signature, prehashed) {
    var dat = mpi.c8to28(this.signaturePadding.encode(key.size, data, prehashed)),
        sig = mpi.exp(mpi.c8to28(signature), mpi.c8to28(key.mpi.e), mpi.c8to28(key.mpi.n));

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
          sd = random.generate(160),
          dm = this.mgf(sd, ln-20),
          md = mpi.xor(db, dm),
          sm = this.mgf(md, 20),
          ms = mpi.xor(sd, sm);

      return ms.concat(md);
    }
  }
}

function Keygen(bits) {
  this.size  = bits;
  this.mpi   = {n: [], e: [], p: [], q: [], f: [], d: [], u: [], dp: [], dq: []};
  this.created = 0;
  this.ready = false;
  this.timer = null;

  this.createPworker = function() {
    this.wp = new Worker('resources/primes.js');
    this.wp.parent = this;
    this.wp.onmessage = function (e) {
      this.parent.mpi.p = e.data;
      this.parent.process();
      this.terminate();
    };

    this.wp.postMessage(mpi.c8to28(random.generate(this.size/2)));
    this.timeout();
  };

  this.createQworker = function() {
    this.wq = new Worker('resources/primes.js');
    this.wq.parent = this;
    this.wq.onmessage = function (e) {
      this.parent.mpi.q = e.data;
      this.parent.process();
      this.terminate();
    };

    this.wq.postMessage(mpi.c8to28(random.generate(this.size/2)));
    this.timeout();
  };

  this.timeout = function() {
    var self = this;
    self.timer = window.setTimeout(function() {
      if (self.mpi.p.length == 0) {
        self.wp.terminate();
        self.createPworker();
      }

      if (self.mpi.q.length == 0) {
        self.wq.terminate();
        self.createQworker();
      }
    }, this.size*10); //tune for longer keys, slower computers
  }

  this.process = function() {
    if (this.mpi.p.length == 0 || this.mpi.q.length == 0) return;

    this.timer = null;

    this.mpi.n = mpi.cut(mpi.mul(this.mpi.p, this.mpi.q));
    this.mpi.f = mpi.mul(mpi.dec(this.mpi.p), mpi.dec(this.mpi.q));

    var t = [257,65537,17,41,19], i = 0;
    do {
      this.mpi.e = [t[Math.floor(Math.random()*t.length)]];
      this.mpi.d = mpi.inv(this.mpi.e, this.mpi.f);
    } while (this.mpi.d.length == 0 && i++ < t.length);

    if (this.mpi.d.length != 0) {
      this.ready = true;
      this.created = Math.round(+new Date()/1000);
    } else {
      this.mpi.p = null;
      this.mpi.q = null;

      this.createPworker();
      this.createQworker();

      return;
    }

    //Upon completion convert to 8 bit arrays
    this.mpi.u  = mpi.c28to8(mpi.cut(mpi.inv(this.mpi.p, this.mpi.q)));
    this.mpi.dp = mpi.c28to8(mpi.mod(this.mpi.d, mpi.dec(this.mpi.p)));
    this.mpi.dq = mpi.c28to8(mpi.mod(this.mpi.d, mpi.dec(this.mpi.q)));

    this.mpi.n = mpi.c28to8(this.mpi.n);
    this.mpi.f = mpi.c28to8(this.mpi.f);
    this.mpi.e = mpi.c28to8(this.mpi.e);
    this.mpi.d = mpi.c28to8(this.mpi.d);
    this.mpi.p = mpi.c28to8(this.mpi.p);
    this.mpi.q = mpi.c28to8(this.mpi.q);
  };

  this.createPworker();
  this.createQworker();
}

var mpi = {
  bits: 28,
  bmax: 268435456,
  bdmx: 72057594037927936,
  bmsk: 268435455,
  bhlf: 14,
  bhmx: 16384,
  bhmk: 16383,
  zero: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
  sneg: false,

  //Check number of leading zeroes
  nlz: function nlz(x) {
    for (var l = x.length, i = 0; i < l; i++) {
      if (x[i] != 0) return i;
    }
  },

  //Cut leading zeros
  cut: function cut(x) {
    for (var l = x.length, i = 0; i < l; i++) {
      if (x[i] != 0) return x.slice(i);
    }
    return [0];
  },

  //Compare arrays, return 0 if equal, 1 if x > y and -1 if y > x
  //Not safe for signed numbers or front zero padded
  cmp: function cmp(x, y) {
    var xl = x.length,
        yl = y.length; //zero front pad problem

    //negative number problem
    if (xl < yl) {
      return -1;
    } else if (xl > yl) {
      return 1;
    }

    for (var i = 0; i < xl; i++) {
      if (x[i] < y[i]) return -1;
      if (x[i] > y[i]) return 1;
    }

    return 0;
  },

  //Most significant bit set
  msb: function msb(x) {
    var r = this.bits - 1, b = 16;
    while (b > 0) {
      if ((t = x >>> b) != 0) { x = t; r -= b; }
      b >>= 1;// /=2
    }
    return r;
  },

  //Least significant bit set
  lsb: function lsb(x) {
    if (x === 0) return 0;
    var r = 0;
    while (!(x&1)) {
      x >>>= 1;
      r++;
    }
    return r;
  },

  //14.7 Addition
  add: function add(x, y) {
    var n = x.length,
        t = y.length,
        l = Math.max(n, t),
        w = [];

    if (n < t) {
      x = this.zero.slice(0, t-n).concat(x);
    } else if (n > t) {
      y = this.zero.slice(0, n-t).concat(y);
    }

    for (var c = 0, i = l-1; i >= 0; i--) {
      w[i] = x[i] + y[i] + c;

      if (w[i] > this.bmsk) {
        c = 1;
        w[i] -= this.bmax;
      } else {
        c = 0;
      }
    }
    if ( c === 1 ) w.unshift(c);
    return w;
  },

  //14.9 Subtraction
  sub: function sub(x, y) {
    var n = x.length,
        t = y.length,
        l = Math.max(n,t),
        w = this.zero.slice(0, l);

    for (var m, s, c = 0; l > 0; ) {
      m = (n-- > 0) ? x[n] : 0;
      s = (t-- > 0) ? y[t] : 0;

      w[--l] = m - s - c;

      if ( w[l] < 0 ) {
        c = 1;
        w[l] += this.bmax;
      } else {
        c = 0;
      }
    }

    if (c === 1 && !arguments[2]) {
      w = this.sub(this.zero.slice(0, l), w, true);
      w[this.nlz(w)] *= -1;
      this.sneg = true;
    } else {
      this.sneg = false;
    }
    return w;
  },

  //14.12 Multiplication
  mul: function mul(x, y) {
    var n = x.length - 1,
      t = y.length - 1,
      w = this.zero.slice(0, n+t+2);

    for (var l1, l2, h1, h2, t1, t2, c, j, i = t; i >= 0; i--) {
      c = 0;
      l1 = y[i] & this.bhmk;
      h1 = y[i] >> this.bhlf;
      for (j = n; j >= 0; j--) {
        l2 = x[j] & this.bhmk;
        h2 = x[j] >> this.bhlf;

        t1 = h1*l2 + h2*l1;
        t2 = l1*l2 + ((t1 & this.bhmk) << this.bhlf) + w[j+i+1] + c;
        w[j+i+1] = t2 & this.bmsk;
        c = h1*h2 + (t1 >> this.bhlf) + (t2 >> this.bits);
      }
      w[i] = c;
    }
    if (w[0] === 0) w.shift();
    return w;
  },

  //14.16 Squaring
  sqr: function sqr(x) {
    var t = x.length,
        w = this.zero.slice(0, 2*t);

    for ( var l1, l2, h1, h2, t1, t2, uv, c = 0, j, i = t-1; i >= 0; i-- ) {
      l1 = x[i] & this.bhmk;
      h1 = x[i] >> this.bhlf;
      t1 = 2*h1*l1;
      t2 = l1*l1 + ((t1 & this.bhmk) << this.bhlf) + w[2*i+1];
      w[2*i+1] = t2 & this.bmsk;
      c = h1*h1 + (t1 >> this.bhlf) + (t2 >> this.bits);
      for ( j = i-1; j >= 0; j-- ) {
        l2 = (2 * x[j]) & this.bhmk;
        h2 = x[j] >> (this.bhlf - 1);

        t1 = h2*l1 + h1*l2;
        t2 = l2*l1 + ((t1 & this.bhmk) << this.bhlf) + w[j+i+1] + c;
        w[j+i+1] = t2 & this.bmsk;
        c = h2*h1 + (t1 >> this.bhlf) + (t2 >> this.bits);
      }
      w[i] = c;
    }
    return (w[0] === 0) ? this.cut(w) : w;
  },

  //Right shift array
  rsh: function rsh(z, s) {
    var ss = s % this.bits,
        ls = Math.floor(s/this.bits),
        l = z.length - ls,
        x = z.slice(0,l);

    if (ss) {
      while (--l) x[l] = ((x[l] >> ss) | (x[l-1] << (this.bits-ss))) & this.bmsk;
      x[l] = (x[l] >> ss);
      return this.cut(x);
    }
    return x;
  },

  //Left shift array
  lsh: function lsh(x, s) {
    var ss = s % this.bits,
        ls = Math.floor(s/this.bits),
        l = x.length,
        r = [];
        t = 0;

    if (ss) {
      while (l--) {
        r[l] = (x[l] << ss) + t;
        t = x[l] >>> (this.bits-ss);
        r[l] &= this.bmsk;
      }
      if (t != 0) r.unshift(t);
    }
    return r.concat(this.zero.slice(0, ls));
  },

  //14.20 Division, not guaranteed to work with >=28-bit
  div: function div(x, y, remainder) {
    var s = this.msb(y[0]) - 1;
    if (s > 0) {
      x = this.lsh(x, s);
      y = this.lsh(y, s);
    }

    var d = x.length - y.length,
        q = [0],
        k = y.concat(this.zero.slice(0, d)),
        yt = y[0]*this.bmax + y[1];

    //only mmcp as last resort. if x0>k0 then do, if x0<k0 then dont, check only if x0=k0
    while ( x[0] > k[0] || (x[0] === k[0] && this.cmp(x, k) > -1) ) {
      q[0] += 1;
      x = this.sub(x,k);
    }

    for ( var p, xt, i1 = 1, i = 0; i < d; i++, i1++ ) {
      q[i1] = (x[i] === y[0]) ? this.bmsk : Math.floor((x[i]*this.bmax + x[i1])/y[0]);
      xt = x[i]*this.bdmx + x[i1]*this.bmax + x[i+2];

      while ( q[i1]*yt > xt ) q[i1]--;//condition check fails due to precision problem with bits = 28

      k = this.mul(y, [q[i1]]).concat(this.zero.slice(0, d-i1));//concat after multiply
      x = this.sub(x, k);

      if (this.sneg) {
        x[this.nlz(x)] *= -1;
        x = this.sub(y.concat(this.zero.slice(0, d-i1)), x);
        q[i1]--;
      }
    }

    return (remainder) ? (s > 0) ? this.rsh(x, s) : this.cut(x) : this.cut(q);
  },

  //Modulus
  mod: function mod(x, y) {
    switch(this.cmp(x,y)) {
    case -1:
      return x;
    case 0:
      return 0;
    default:
      return this.div(x, y, true);
    }
  },

  //Signed addition
  sad: function sad(x,y) {
    var a, b;
    if (x[0] >= 0) {
      if (y[0] >= 0) {
        return this.add(x,y);
      } else {
        b = y.slice(0);
        b[0] *= -1;
        return this.cut(this.sub(x,b));
      }
    } else {
      if (y[0] >= 0) {
        a = x.slice(0);
        a[0] *= -1;
        return this.cut(this.sub(y,a));
      } else {
        a = x.slice(0);
        b = y.slice(0);
        a[0] *= -1;
        b[0] *= -1;
        a = this.add(a,b);
        a[0] *= -1;
        return a;
      }
    }
  },

  //Signed subtraction
  ssb: function ssb(x,y) {
    var a, b;
    if (x[0] >= 0) {
      if (y[0] >= 0) {
        return this.cut(this.sub(x,y));
      } else {
        b = y.slice(0);
        b[0] *= -1;
        return this.add(x,b);
      }
    } else {
      if (y[0] >= 0) {
        a = x.slice(0);
        a[0] *= -1;
        b = this.add(a,y);
        b[0] *= -1;
        return b;
      } else {
        a = x.slice(0);
        b = y.slice(0);
        a[0] *= -1;
        b[0] *= -1;
        return this.cut(this.sub(b,a));
      }
    }
  },

    //Signed right shift
  srs: function srs(x,s) {
    if (x[0] < 0) {
      x[0] *= -1;
      x = this.rsh(x,s);
      x[0] *= -1;
      return x;
    }
    return this.rsh(x,s);
  },

  //14.61 Binary extended gcd algorithm to return mod inverse
  gcd: function gcd(x, y) {
    var s, g, a, b, c, d, u, v;
    g = Math.min(this.lsb(x[x.length-1]), this.lsb(y[y.length-1]));
    x = this.rsh(x, g); y = this.rsh(y, g);
    a = [1]; b = [0]; c = [0]; d = [1];
    u = x.slice(0);  v = y.slice(0);

    while (this.cmp(u,[0x0]) != 0) {
      s = this.lsb(u[u.length-1]);
      u = this.rsh(u,s);
      while (s--) {
        if ( (a[a.length-1]&1) === 0 && (b[b.length-1]&1) === 0 ) {
          a = this.srs(a,1);
          b = this.srs(b,1);
        } else {
          a = this.srs(this.sad(a,y),1);
          b = this.srs(this.ssb(b,x),1);
        }
      }

      s = this.lsb(v[v.length-1]);
      v = this.rsh(v,s);
      while (s--) {
        if ( (c[c.length-1]&1) === 0 && (d[d.length-1]&1) === 0 ) {
          c = this.srs(c,1);
          d = this.srs(d,1);
        } else {
          c = this.srs(this.sad(c,y),1);
          d = this.srs(this.ssb(d,x),1);
        }
      }

      if ( this.cmp(u,v) >= 0 ) {
        u = this.sub(u,v);
        a = this.ssb(a,c);
        b = this.ssb(b,d);
      } else {
        v = this.sub(v,u);
        c = this.ssb(c,a);
        d = this.ssb(d,b);
      }
    }
    return (this.cmp(v,[0x1]) != 0) ? [] : d;
  },

  //Mod inverse, 1/x mod y
  inv: function inv(x, y) {
    var u = this.gcd(y, x);
    while (u[0] < 0) {
      u[0] *= -1;
      u = this.sub(y, u);
    }
    return u;
  },

  //14.42 Barret modular reduction
  bmr: function bmr(x, m, mu) {
    if (this.cmp(x,m) < 0) return x; //if equal, return 0;
    var k, q1, q2, q3, r1, r2, r, s;
    k = m.length;
    if (undefined == mu) mu = this.div([1].concat(this.zero.slice(0,2*k)), m);

    q1 = x.slice(0,x.length-(k-1));
    q2 = this.mul(q1, mu);
    q3 = q2.slice(0,q2.length-(k+1));

    s = x.length-(k+1);
    r1 = (s > 0) ? x.slice(s) : x.slice(0);

    r2 = this.mul(q3,m);
    s = r2.length-(k+1);
    if (s > 0) r2 = r2.slice(s);

    r = this.cut(this.sub(r1,r2));
    if (r[0] < 0) {
      r[0] *= -1;
      r = this.cut(this.sub([1].concat(this.zero.slice(0,k+1)), r));
    }
    while (this.cmp(r,m) >= 0) {
      r = this.cut(this.sub(r,m));
    }
    return r;
  },

  //Modular exponentiation with Barret reduction
  exp: function exp(x, e, n) {
    var i, j,
      r = [0x1],
      l = e.length * this.bits,
      c = this.msb(e[0]),
      mu = this.div([1].concat(this.zero.slice(0,2*n.length)), n);

    while (--l > c) {
      j = Math.floor(l/this.bits);
      i = this.bits - (l%this.bits) - 1;
      if (e[j] & (0x1 << i)) r = this.bmr(this.mul(r,x), n, mu);
      x = this.bmr(this.sqr(x), n, mu);
    }

    return this.bmr(this.mul(r,x), n, mu);
  },

  //14.71 Modified Garner's algo
  gar: function gar2(x, p, q, d, u, dp1, dq1) {
    var vp, vq, t;

    if (undefined == dp1) {
      dp1 = this.mod(d, this.dec(p));
      dq1 = this.mod(d, this.dec(q));
    }

    vp = this.exp(this.mod(x,p), dp1, p); //replace mod(x,p) with bmr(x,p) for keysizes with "saturated" modulus
    vq = this.exp(this.mod(x,q), dq1, q); //replace mod(x,q)

    if (this.cmp(vq,vp) < 0) {
      t = this.cut(this.sub(vp,vq));
      t = this.cut(this.bmr(this.mul(t,u), q));
      t = this.cut(this.sub(q,t));
    } else {
      t = this.cut(this.sub(vq,vp));
      t = this.cut(this.bmr(this.mul(t,u), q)); //bmr instead of mod, mod/div fails too frequently because of known precision issue with 28 bits
    }

    return this.cut(this.add(vp, this.mul(t, p)));
  },

  //mod where n < 2^bhmx
  mds: function mds(x, n) {
    for(var i = 0, c = 0, l = x.length; i < l; i++) {
      c = ((x[i] >> this.bhlf) + (c << this.bhlf)) % n;
      c = ((x[i] & this.bhmk) + (c << this.bhlf)) % n;
    }
    return c;
  },

  //xor
  xor: function xor(x, y) {
    if (x.length != y.length) return [];
    for(var r = [], l = x.length, i = 0; i < l; i++) {
      r[i] = x[i] ^ y[i];
    }
    return r;
  },

  //quicker decrement
  dec: function dec(x) {
    var l = x.length - 1,
      o = x.slice();

    if (o[l] > 0) {
      o[l] -= 1;
    } else {
      o = this.sub(o, [1]);
    }

    return o;
  },

  c8to28: function c8to28(a) {
    var i = [0,0,0,0,0,0].slice((a.length-1)%7).concat(a),
        o = [];

    for (var p = 0; p < i.length; p += 7) {
      o.push(i[p]*1048576 + i[p+1]*4096 + i[p+2]*16 + (i[p+3]>>4));
      o.push((i[p+3]&0xf)*16777216 + i[p+4]*65536 + i[p+5]*256 + i[p+6]);
    }

    if (o[0] == 0) o.shift();

    return o;
  },

  c28to8: function c28to8(a) {
    var b = [0].slice((a.length-1)%2).concat(a),
        o = [];

    for (var c, j = 0, i = 0; i < b.length; j += 7) {
      c = b[i++];
      o[j]   = (c >> 20);
      o[j+1] = (c >> 12) & 0xff;
      o[j+2] = (c >> 4) & 0xff;
      o[j+3] = (c << 4) & 0xf0;

      c = b[i++];
      o[j+3] += (c >> 24);
      o[j+4] = (c >> 16) & 0xff;
      o[j+5] = (c >> 8) & 0xff;
      o[j+6] = c & 0xff;
    }

    for (i = 0; i < o.length; i++) {
      if (o[i] != 0) return o.slice(i);
    }
  }
}



/**/

function KeyGen(size, callback) {
  var w = {}, timer;

  function createWorker (worker, callback) {
    w[worker] = new Worker('resources/primes.js');
    w[worker].ready = false;
    w[worker].onmessage = function (e) {
      this.data = e.data;
      this.ready = true;
      callback();
      this.terminate();
    };

    w[worker].postMessage(mpi.c8to28(random.generate(size/2)));
  };

  function process() {
    if (w.p.ready && w.q.ready) {
      var data = {};
      timer = null;

      data.n = mpi.cut(mpi.mul(w.p.data, w.q.data));
      data.f = mpi.mul(mpi.dec(w.p.data), mpi.dec(w.q.data));

      var t = [257,65537,17,41,19], i = 0;
      do {
        data.e = [t[Math.floor(Math.random()*t.length)]];
        data.d = mpi.inv(data.e, data.f);
      } while (data.d.length == 0 && i++ < t.length);

      if (data.d.length == 0) {
        w.p = null;
        w.q = null;

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

      callback(data);
    }
  };

  return function() { 
    createWorker('p', process);
    createWorker('q', process);

    timer = window.setTimeout(function() {
      if (!w.p.ready) {
        w.p.terminate();
        createWorker('p', process);
      }

      if (!w.q.ready) {
        w.q.terminate();
        createWorker('q', process);
      }
    }, size*10, w); //tune for longer keys, slower computers
  };
}

function test(data) {
  console.log(data);
}