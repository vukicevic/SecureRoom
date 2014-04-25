/**
 * SecureRoom - Encrypted web browser based text communication software
 * Copyright (C) 2014 Nenad Vukicevic
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

function Symmetric() {
  const B = [99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22];
  const R = [1,2,4,8,16,32,64,128,27,54,108,216,171,77,154,47];

    var Nk = 0,
        Nr = 0;

  function setKey(key) {
    Nk = key.length/4;
    Nr = Nk+6;

    var i, j, k,
        l = (Nr+1) * 4,
        T = [],
        W = key.slice();

    for (i = Nk; i < l; i++) {
      j = i * 4;
      T = W.slice(j-4,j);

      if (i % Nk === 0) {
        T.push(T.shift());
        T = subBytes(T, B);
        T[0] ^= R[(i/Nk)-1];
      } else if (Nk > 6 && i % Nk === 4) {
        T = subBytes(T, B);
      }

      k = (i - Nk) * 4;
      W[j]   = W[k]   ^ T[0];
      W[j+1] = W[k+1] ^ T[1];
      W[j+2] = W[k+2] ^ T[2];
      W[j+3] = W[k+3] ^ T[3];
    }

    return W;
  }

  function cipher(key, data, encrypt) {
    var l = data.length,
        O = [],
        W = setKey(key),
        S = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        i, j;

    for (i = 0; i < l; i += 16) {
      S = addRoundKey(0, W, S);
      for (j = 1; j <= Nr; j++) {
        S = subBytes(S, B);
        S = shiftRows(S);
        if (j < Nr) S = mixColumns(S);
        S = addRoundKey(j*16, W, S);
      }

      for (j = 16; j >= 0; j--) {
        O[i+j] = data[i+j] ^ S[j];
        S[j] = (encrypt) ? O[i+j] : data[i+j];
      }
    }

    return O.slice(0, l);
  }

  function addRoundKey(k, W, S) {
    return S.map(function(v, i) { return v ^ W[k+i] });
  }

  function mixColumns(S) {
    for (var T, U, i = 0; i < 16;) {
      T = S.slice(i, i+4);
      U = T.map(function(v){return (v > 127) ? v*2 ^ 0x011b : v*2});

      S[i++] = U[0] ^ U[1] ^ T[1] ^ T[2] ^ T[3];
      S[i++] = T[0] ^ U[1] ^ U[2] ^ T[2] ^ T[3];
      S[i++] = T[0] ^ T[1] ^ U[2] ^ U[3] ^ T[3];
      S[i++] = U[0] ^ T[0] ^ T[1] ^ T[2] ^ U[3];
    }

    return S;
  }

  function shiftRows(S) {
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
  }

  function subBytes(S, T) {
    return S.map(function(v) { return T[v] });
  }

  return {
    encrypt: function(key, data) {
      return cipher(key, data, true);
    },

    decrypt: function(key, data) {
      return cipher(key, data, false);
    }
  }
}