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

var Symmetric = {
  algorighm: 7, //8,9
  name: 'AES',
  mode: 'CFB',
  size: 16,

  Nk: 0,
  Nr: 0,
  B: [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
      0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
      0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
      0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
      0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
      0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
      0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
      0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
      0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
      0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
      0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
      0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
      0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
      0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
      0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
      0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16],
  R: [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d,0x9a,0x2f],

  encrypt: function(key, data) {
    return this.cipher(key, data, true);
  },

  decrypt: function(key, data) {
    return this.cipher(key, data, false);
  },
  
  setKey: function(key) {
    this.size = key.length;
    this.Nk = key.length/4;
    this.Nr = this.Nk+6;

    var i, j, k,
        l = (this.Nr+1) * 4,
        T = [],
        W = key.slice();

    for (i = this.Nk; i < l; i++) {
      j = i * 4;
      T = W.slice(j-4,j);

      if (i%this.Nk == 0) {
        T.push(T.shift());
        T = this.subBytes(T);
        T[0] ^= this.R[(i/this.Nk)-1];
      } else if (this.Nk > 6 && i%this.Nk == 4) {
        T = this.subBytes(T);
      }

      k = (i - this.Nk) * 4;
      W[j]   = W[k]   ^ T[0];
      W[j+1] = W[k+1] ^ T[1];
      W[j+2] = W[k+2] ^ T[2];
      W[j+3] = W[k+3] ^ T[3];
    }

    return W;
  },

  cipher: function(key, data, encrypt) {
    var l = data.length,
        O = [],
        W = this.setKey(key),
        S = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    for (var j, i = 0; i < l; i += 16) {
      S = this.addRoundKey(0, W, S);
      for (j = 1; j <= this.Nr; j++) {
        S = this.subBytes(S);
        S = this.shiftRows(S);
        if (j < this.Nr) S = this.mixColumns(S);
        S = this.addRoundKey(j*16, W, S);
      }

      for (j = 16; j >= 0; j--) {
        O[i+j] = data[i+j] ^ S[j];
        S[j] = (encrypt) ? O[i+j] : data[i+j];
      }
    }

    return O.slice(0, l);
  },

  addRoundKey: function(k, W, S) {
    for (var i = 0; i < 16; i++) {
      S[i] ^= W[k+i];
    }
    return S;
  },

  mixColumns: function(S) {
    for (var T, B, i = 0; i < 16;) {
      T = S.slice(i, i+4);
      B = T.map(function(v){return (v > 127) ? v*2 ^ 0x011b : v*2;});

      S[i++] = B[0] ^ B[1] ^ T[1] ^ T[2] ^ T[3];
      S[i++] = T[0] ^ B[1] ^ B[2] ^ T[2] ^ T[3];
      S[i++] = T[0] ^ T[1] ^ B[2] ^ B[3] ^ T[3];
      S[i++] = B[0] ^ T[0] ^ T[1] ^ T[2] ^ B[3];
    }
    return S;
  },

  shiftRows: function(S) {
    var t1, t2;

    t1 = S[1];
    S[1] = S[5];
    S[5] = S[9];
    S[9] = S[13];
    S[13] = t1;

    t1 = S[2]; t2 = S[6];
    S[2] = S[10];
    S[6] = S[14];
    S[10] = t1;
    S[14] = t2;

    t1 = S[15];
    S[15] = S[11];
    S[11] = S[7];
    S[7] = S[3];
    S[3] = t1;

    return S;
  },

  subBytes: function(S) {
    return S.map(function(v){return Symmetric.B[v];});
  }
};