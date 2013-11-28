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
 
var KeyUtil = {
  createTag: function(tag, length) {
    tag = tag*4 + 128;
  
    if (length > 65535) {
      tag += 2;
    } else if (length > 255) {
      tag += 1;
    }
  
    return tag;
  },
  
  createLength: function(l) {
    return (l < 256) ? [l] : (l < 65536) ? ArrayUtil.fromHalf(l) : ArrayUtil.fromWord(l);
  },

  createMpi: function(mpi) {
    return ArrayUtil.fromHalf(ArrayUtil.bitLength(mpi)).concat(mpi);
  },

  createKeyPacket: function(key, type, privateMpi) {
    var len, tag, result, tmp;

    if (privateMpi) {
      len = 21 + key.mpi.n.length + key.mpi.e.length + privateMpi.d.length + privateMpi.p.length + privateMpi.q.length + privateMpi.u.length;
      tag = (type == 3) ? 5 : 7;
      tmp = [0].concat(this.createMpi(privateMpi.d));
      
      if (mpi.cmp(privateMpi.p, privateMpi.q) == -1) {
        tmp = tmp.concat(this.createMpi(privateMpi.p))
                 .concat(this.createMpi(privateMpi.q));
      } else {
        tmp = tmp.concat(this.createMpi(privateMpi.q))
                 .concat(this.createMpi(privateMpi.p));
      }
      
      tmp = tmp.concat(this.createMpi(privateMpi.u));
      
      for (var c = 0, i = 0; i < tmp.length; i++)
        c += tmp[i];

      tmp = tmp.concat(ArrayUtil.fromHalf(c%65536));
    } else {
      len = 10 + key.mpi.n.length + key.mpi.e.length;
      tag = (type == 3) ? 6 : 14;
      tmp = [];
    }

    result = [this.createTag(tag, len)].concat(this.createLength(len))
                                       .concat(this.generateKeyData(type, key.mpi, key.created));

    return result.concat(tmp);
  },

  createNamePacket: function(name) {
    var namePacket = ArrayUtil.fromString(name);
    return [this.createTag(13, namePacket.length)].concat(this.createLength(namePacket.length)).concat(namePacket);
  },

  createSignaturePacket: function(signer, data) {
    var sigMeta, sigHash, sigPacket, sigSigned;

    if (typeof data == "string") {
      sigMeta   = this.signSignatureMeta(signer);
      sigSigned = signer.signature;
    } else {
      sigMeta   = this.encryptSignatureMeta(data);
      sigSigned = data.signature;
    }

    sigHash   = this.generateSignatureHash(signer, data);
    sigPacket = sigMeta.concat([0,10,9,16])
                       .concat(ArrayUtil.fromHex(signer.id))
                       .concat(sigHash.slice(0,2))
                       .concat(this.createMpi(sigSigned));

    return [this.createTag(2, sigPacket.length)].concat(this.createLength(sigPacket.length)).concat(sigPacket);
  },

  encryptSignatureMeta: function(encrypt) {
    return [4,24,2,2,0,15,5,2].concat(ArrayUtil.fromWord(encrypt.created+2))
                              .concat([2,27,4,5,9])
                              .concat(ArrayUtil.fromWord(86400));
  },

  signSignatureMeta: function(sign) {
    return [4,19,3,2,0,26,5,2].concat(ArrayUtil.fromWord(sign.created+2))
                              .concat([2,27,3,5,9])
                              .concat(ArrayUtil.fromWord(86400))
                              .concat([4,11,7,8,9,2,21,2,2,22,0]);
  },

  generateKeyData: function(type, data, time) {
    return [4].concat(ArrayUtil.fromWord(time))
              .concat([type])
              .concat(this.createMpi(data.n))
              .concat(this.createMpi(data.e));
  },

  generateFingerprint: function(type, data, time) {
    data = this.generateKeyData(type, data, time);
    return ArrayUtil.toHex(hash.digest([0x99].concat(ArrayUtil.fromHalf(data.length)).concat(data)));
  },

  generateSignatureHash: function(sign, data) {
    var sdat, edat, meta, suff;

    sdat = this.generateKeyData(3, sign.mpi, sign.created);
    sdat = [153].concat(ArrayUtil.fromHalf(sdat.length)).concat(sdat);

    if(typeof data == "string") {
      edat = [180].concat(ArrayUtil.fromWord(data.length))
                  .concat(ArrayUtil.fromString(data));

      meta = this.signSignatureMeta(sign);
    } else {
      edat = this.generateKeyData(2, data.mpi, data.created);
      edat = [153].concat(ArrayUtil.fromHalf(edat.length)).concat(edat);

      meta = this.encryptSignatureMeta(data);
    }

    suff = [4,255].concat(ArrayUtil.fromWord(meta.length));

    return hash.digest(
      sdat.concat(edat).concat(meta).concat(suff)
    );
  },

  exportKey: function(name, sign, encrypt, privateSignMpi, privateEncryptMpi) {
    var headers       = {"Version": "SecureRoom 1.0"},
        type          = (privateSignMpi) ? "PRIVATE KEY BLOCK" : "PUBLIC KEY BLOCK",
        namePacket    = this.createNamePacket(name),
        encryptPacket = this.createKeyPacket(encrypt, 2, privateEncryptMpi),
        signPacket    = this.createKeyPacket(sign, 3, privateSignMpi),
        signSigPacket = this.createSignaturePacket(sign, name), 
        encSigPacket  = this.createSignaturePacket(sign, encrypt);
    
    return ArmorUtil.dress({"type": type, "headers": headers, "packets": signPacket.concat(namePacket).concat(signSigPacket).concat(encryptPacket).concat(encSigPacket)});
  }
}

var ArmorUtil = {
  crc: function(data) {
    var crc = 0xb704ce,
        ply = 0x1864cfb,
        len = data.length,
        i, h = 0;

    while (h < len) {
      crc ^= data[h++]*65536;
      for (i = 0; i < 8; i++) {
        crc *= 2;
        if (crc > 16777215) crc ^= ply;
      }
    }

    return (crc & 0xffffff);
  },

  strip: function(input) {
    var temp,
        output = {type: null, headers: {}, packets: null, checksum: null, valid: false},
        pattern = /^-{5}BEGIN\sPGP\s(.+)-{5}\n([\s\S]+)\n\n([\s\S]+)\n=(.+)\n-{5}END\sPGP\s\1-{5}$/gm;

    input = input.replace(/\r\n/g,'\n');

    if (pattern.test(input)) {
      temp = input.replace(pattern, '$1,$2,$3,$4').split(',');

      temp[1].match(/.+: .+/gm).map(function(item) {
        var pair = item.split(': ');
        output.headers[pair[0]] = pair[1];
      });
      temp[3] = Base64Util.decode(temp[3]);

      output.type     = temp[0];
      output.packets  = Base64Util.decode(temp[2]);
      output.checksum = temp[3][0]*65536 + temp[3][1]*256 + temp[3][2];
      output.valid    = (ArmorUtil.crc(output.packets) == output.checksum);
    }

    return output;
  },

  dress: function(input) {
    var output;

    input.checksum = ArmorUtil.crc(input.packets);
    input.valid    = true;

    output  = '-----BEGIN PGP ' + input.type + '-----\n'

    for (var header in input.headers) {
      output += header + ': ' + input.headers[header] + '\n';
    }

    output += '\n' + Base64Util.encode(input.packets, true) + '\n';
    output += '=' + Base64Util.encode([input.checksum>>16, (input.checksum>>8)&0xff, input.checksum&0xff]) + '\n';
    output += '-----END PGP ' + input.type + '-----';

    return output;
  }
}

var Base64Util = {
  r64 : ['A','B','C','D','E','F','G','H',
         'I','J','K','L','M','N','O','P',
         'Q','R','S','T','U','V','W','X',
         'Y','Z','a','b','c','d','e','f',
         'g','h','i','j','k','l','m','n',
         'o','p','q','r','s','t','u','v',
         'w','x','y','z','0','1','2','3',
         '4','5','6','7','8','9','+','/',
         '='],

  decode : function(input) {
    var c1, c2, c3,
        i1, i2, i3, i4,
        i = 0,
        j = 0;

    input   = input.replace(/[^A-Za-z0-9\+\/\=]/g, '');
    var len = input.length,
        out = [];

    while ( i < len ) {
      i1 = this.r64.indexOf(input.charAt(i++));
      i2 = this.r64.indexOf(input.charAt(i++));
      i3 = this.r64.indexOf(input.charAt(i++));
      i4 = this.r64.indexOf(input.charAt(i++));

      c1 = ( i1         << 2) | (i2 >> 4);
      c2 = ((i2 & 0x0f) << 4) | (i3 >> 2);
      c3 = ((i3 & 0x03) << 6) | (i4);

      out[j++] = c1;
      if (i3 != 64) out[j++] = c2;
      if (i4 != 64) out[j++] = c3;
    }

    return out;
  },

  encode : function(input, linebreak) {
    var c1, c2, c3,
        i1, i2, i3, i4,
        i = 0, j = 0,
        out = [],
        len = input.length;

    while ( i < len ) {
      c1 = input[i++];
      c2 = input[i++];
      c3 = input[i++];

      i1 = (c1 >> 2);
      i2 = (c1 &  0x03) << 4 | c2 >> 4;
      i3 = (c2 &  0x0f) << 2 | c3 >> 6;
      i4 = (c3 &  0x3f);

      if ( isNaN(c2) ) {
        i3 = i4 = 64;
      } else if ( isNaN(c3) ) {
        i4 = 64;
      }

      out[j++] = this.r64[i1];
      out[j++] = this.r64[i2];
      out[j++] = this.r64[i3];
      out[j++] = this.r64[i4];

      if (linebreak && i%48 == 0 && i < len) {
        out[j++] = "\n";
      }
    }

    return out.join('');
  }
}

var PrintUtil = {
  time: function(timestamp) {
    var date = new Date(timestamp*1000);
    return ('0'+date.getHours()).slice(-2)+' '+('0'+date.getMinutes()).slice(-2)+' '+('0'+date.getSeconds()).slice(-2);
  },

  date: function(timestamp) {
    var date = new Date(timestamp*1000);
    return date.getHours()+':'+('0'+date.getMinutes()).slice(-2)+':'+('0'+date.getSeconds()).slice(-2)+' '+date.getDate()+'/'+(date.getMonth()+1)+'/'+date.getFullYear();
  },

  text: function(text) {
    return text.replace(/["<>&]/g, function(m){return ({'"':'&quot;','<':'&lt;','>':'&gt;','&':'&amp;'})[m]});
  },

  bool: function(boolean) {
    return (boolean) ? 'True' : 'False';
  },

  number: function(number) {
    return number.toString();
  },

  id: function(id) {
    return id.match(/.{2}/g).map(function(v){return v;}).join(':').toUpperCase();
  }
}

var ArrayUtil = {
  //to/from string not currently handling charcode < 16 - if needed use ('0'+s).slice(-2);
  toString: function(a) {
    return decodeURIComponent(a.map(function(v) {return '%'+v.toString(16);}).join(''));
  },

  fromString: function(s) {
    return encodeURIComponent(s.split('').map(function(v){return (v.charCodeAt(0) < 128) ? '%'+v.charCodeAt(0).toString(16) : v;}).join('')).replace(/%25/g,'%')
            .slice(1).split('%').map(function(v){return parseInt(v, 16);});
  },

  toHex: function(a) {
    return a.map(function(v){return ('0'+v.toString(16)).slice(-2);}).join('');
  },

  fromHex: function(s) {
    return s.match(/.{2}/g).map(function(v){return parseInt(v, 16);});
  },

  toWord: function(a) {
    return (a[0]*16777216 + a[1]*65536 + a[2]*256 + a[3]);
  },

  fromWord: function(n) {
    return [n>>24, (n>>16)&0xff, (n>>8)&0xff, n&0xff];
  },

  fromHalf: function(n) {
    return [n>>8, n&0xff];
  },

  bitLength: function(a) {
    for (var i = 128, l = a.length*8; i >= 1; i /= 2) 
      if (a[0] >= i) return l; else --l;
  }
}

var UrlUtil = {
  getParameter: function(name) {
    var match = RegExp('[?&]' + name + '=([^&]*)').exec(window.location.search);
    return (match) ? decodeURIComponent(match[1].replace(/\+/g, ' ')) : '';
  }
}

var C = {
  TYPE_RSA_SIGN: 3,
  TYPE_RSA_ENCRYPT: 2,
  STATUS_DISABLED: 2,
  STATUS_ENABLED: 1,
  STATUS_PENDING: 0,
  STATUS_REJECTED: -1,
}