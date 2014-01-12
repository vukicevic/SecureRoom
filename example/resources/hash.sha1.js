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

hash = {
  length: 20,
  algorithm: 2,
  name: 'SHA-1',
  der: [48, 33, 48, 9, 6, 5, 43, 14, 3, 2, 26, 5, 0, 4, 20],

  digest: function digest(data) {
    var p = 0,
        W, k, f, i, a, b, c, d, e,
        x = this.implode(data),
        l = x.length,
        th = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
        tk = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];

    while (p < l) {
      W = x.slice(p, p+16);

      a = th[0];
      b = th[1];
      c = th[2];
      d = th[3];
      e = th[4];

      for (i = 0; i < 80; i++) {
        if (i > 15) {
          W[i] = this.rotl((W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16]), 1);
        }

        if (i < 20) {
          f = (b & c) | ((~b) & d);
          k = tk[0];
        } else if (i < 40) {
          f = b ^ c ^ d;
          k = tk[1];
        } else if (i < 60) {
          f = (b & c) | (b & d) | (c & d);
          k = tk[2];
        } else {
          f = b ^ c ^ d;
          k = tk[3];
        }

        k = this.rotl(a, 5) + f + e + k + W[i];
        e = d;
        d = c;
        c = this.rotl(b, 30);
        b = a;
        a = k & 0xffffffff;
      }

      th[0] = (th[0] + a) & 0xffffffff;
      th[1] = (th[1] + b) & 0xffffffff;
      th[2] = (th[2] + c) & 0xffffffff;
      th[3] = (th[3] + d) & 0xffffffff;
      th[4] = (th[4] + e) & 0xffffffff;

      p += 16;
    }

    return this.explode(th);
  },

  rotl: function rotl(x, n) {
    return ((x << n) | (x >>> 32-n));
  },
  
  //below are a8to32/a32to8 functions with added padding, length, etc
  implode: function implode(x) {
    for (var c, s = [24, 16, 8, 0], r = [], p = 0, o = 0, i = 0, l = x.length; i < l; i++) {
      o |= x[i] << s[p++];
      if (p > 3) {
        r.push(o);
        p = 0;
        o = 0;
      }
    }

    if ( p > 0 ) {
      o |= 0x80 << s[p];
      r.push(o);
      l = r.length * 32 - s[p-1];
    } else {
      l = r.length * 32;
      r.push(0x80000000);
    }

    i = r.length % 16;
    c = (i < 15) ? (14 - i) : 15;

    while (c--) {
      r.push(0);
    }

    r.push(0); //Ignore upper 32 bits, messages of length >= 2^32 will not be hashed
    r.push(l);

    return r;
  },

	//don't touch the signed shift >>> :)
  explode: function explode(w) {
    for (var i = 0, o = [], l = w.length; i < l; i++) {
      o.push( w[i] >>> 24);
      o.push((w[i] >>> 16) & 0xff);
      o.push((w[i] >>>  8) & 0xff);
      o.push( w[i] & 0xff);
    }
    return o;
  }
};
