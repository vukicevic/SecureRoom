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
    return (length > 65535) ? tag*4 + 130 : (length > 255) ? tag*4 + 129 : tag*4 + 128;
  },

  createLength: function(l) {
    return (l < 256) ? [l] : (l < 65536) ? ArrayUtil.fromHalf(l) : ArrayUtil.fromWord(l);
  },

  createBerLength: function(l) {
    if (l < 128) return [l];

    var ll = Math.floor(Math.log(l)/Math.log(256))+1,
        pr = [128 + ll];

    while (ll--) pr.push( (l >> (ll*8)) & 255 );

    return pr;
  },

  createMpi: function(mpi) {
    return ArrayUtil.fromHalf(ArrayUtil.bitLength(mpi)).concat(mpi);
  },


  createKeyPacketBase: function(key) {
    return [4].concat(ArrayUtil.fromWord(key.time))
              .concat([key.type])
              .concat(this.createMpi(key.data.n))
              .concat(this.createMpi(key.data.e));
  },

  createKeyPacket: function(tag, length, key) {
    return [this.createTag(tag, length)].concat(this.createLength(length))
                                        .concat(this.createKeyPacketBase(key));
  },

  createSecretKeyPacket: function(key) {
    var len = 21 + key.data.n.length + key.data.e.length + key.data.d.length + key.data.p.length + key.data.q.length + key.data.u.length,
        tag = (key.type === C.TYPE_RSA_SIGN) ? 5 : 7,
        tmp = [0].concat(this.createMpi(key.data.d)),
        sum;

    tmp = (App.calc.compare(key.data.p, key.data.q) === -1)
            ? tmp.concat(this.createMpi(key.data.p)).concat(this.createMpi(key.data.q))
            : tmp.concat(this.createMpi(key.data.q)).concat(this.createMpi(key.data.p));

    tmp = tmp.concat(this.createMpi(key.data.u));
    sum = tmp.reduce(function(a, b) { return a + b }) % 65536;
    tmp = tmp.concat(ArrayUtil.fromHalf(sum));

    return this.createKeyPacket(tag, len, key).concat(tmp);
  },

  createPublicKeyPacket: function(key) {
    var len = 10 + key.data.n.length + key.data.e.length,
        tag = (key.type === C.TYPE_RSA_SIGN) ? 6 : 14;

    return this.createKeyPacket(tag, len, key);
  },

  createNamePacket: function(name) {
    var namePacket = ArrayUtil.fromString(name);
    return [this.createTag(13, namePacket.length)].concat(this.createLength(namePacket.length)).concat(namePacket);
  },

  createSignaturePacket: function(sKey, eKey) {
    var sigMeta, sigHash, sigPacket, sigSigned;

    if (eKey) {
      sigMeta   = this.encryptSignatureMeta(eKey);
      sigSigned = eKey.sign;
    } else {
      sigMeta   = this.signSignatureMeta(sKey);
      sigSigned = sKey.sign;
    }

    sigHash   = this.generateSignatureHash(sKey, eKey);
    sigPacket = sigMeta.concat([0,10,9,16])
                       .concat(ArrayUtil.fromHex(sKey.iden.substr(-16)))
                       .concat(sigHash.slice(0,2))
                       .concat(this.createMpi(sigSigned));

    return [this.createTag(2, sigPacket.length)].concat(this.createLength(sigPacket.length)).concat(sigPacket);
  },

  encryptSignatureMeta: function(eKey) {
    return [4,24,2,2,0,15,5,2].concat(ArrayUtil.fromWord(eKey.time+2))
                              .concat([2,27,4,5,9])
                              .concat(ArrayUtil.fromWord(86400));
  },

  signSignatureMeta: function(sKey) {
    return [4,19,3,2,0,26,5,2].concat(ArrayUtil.fromWord(sKey.time+2))
                              .concat([2,27,3,5,9])
                              .concat(ArrayUtil.fromWord(86400))
                              .concat([4,11,7,8,9,2,21,2,2,22,0]);
  },

  generateSignatureHash: function(sKey, eKey) {
    var sdat, edat, meta, suff;

    sdat = this.createKeyPacketBase(sKey);
    sdat = [153].concat(ArrayUtil.fromHalf(sdat.length)).concat(sdat);

    if (eKey) {
      edat = this.createKeyPacketBase(eKey);
      edat = [153].concat(ArrayUtil.fromHalf(edat.length)).concat(edat);

      meta = this.encryptSignatureMeta(eKey);
    } else {
      edat = [180].concat(ArrayUtil.fromWord(sKey.name.length))
                  .concat(ArrayUtil.fromString(sKey.name));

      meta = this.signSignatureMeta(sKey);
    }

    suff = [4,255].concat(ArrayUtil.fromWord(meta.length));

    return Hash.digest(
      sdat.concat(edat).concat(meta).concat(suff)
    );
  },

  generateFingerprint: function(type, data, time) {
    data = this.createKeyPacketBase({"type": type, "data": data, "time": time});
    return ArrayUtil.toHex(Hash.digest([0x99].concat(ArrayUtil.fromHalf(data.length)).concat(data)));
  },

  exportKey: function(sKey, eKey, secret) {
    var headers       = {"Version": "SecureRoom 1.0"},
        namePacket    = this.createNamePacket(sKey.name),
        signSigPacket = this.createSignaturePacket(sKey),
        encSigPacket  = this.createSignaturePacket(sKey, eKey),
        type, encryptPacket, signPacket;

    if (secret) {
      type          = "PRIVATE KEY BLOCK";
      encryptPacket = this.createSecretKeyPacket(eKey);
      signPacket    = this.createSecretKeyPacket(sKey);
    } else {
      type          = "PUBLIC KEY BLOCK";
      encryptPacket = this.createPublicKeyPacket(eKey);
      signPacket    = this.createPublicKeyPacket(sKey);
    }

    return ArmorUtil.dress({"type": type, "headers": headers, "packets": signPacket.concat(namePacket).concat(signSigPacket).concat(encryptPacket).concat(encSigPacket)});
  },

  exportSSH: function(key) {
    var prefix = [0, 0, 0, 7, 115, 115, 104, 45, 114, 115, 97];

    prefix = prefix.concat(ArrayUtil.fromWord(key.data.e.length))
                   .concat(key.data.e)
                   .concat(ArrayUtil.fromWord(key.data.n.length))
                   .concat(key.data.n);

    return "ssh-rsa " + Base64Util.encode(prefix) + " " + key.name;
  },

  exportPK1: function(key, secret) {
    var pref = [48], type, data;

    if (secret) {
      type = " PRIVATE KEY-----\n";
      data = [2,1,0,2].concat(this.createBerLength(key.data.n.length)).concat(key.data.n)
                      .concat([2]).concat(this.createBerLength(key.data.e.length)).concat(key.data.e)
                      .concat([2]).concat(this.createBerLength(key.data.d.length)).concat(key.data.d)
                      .concat([2]).concat(this.createBerLength(key.data.p.length)).concat(key.data.p)
                      .concat([2]).concat(this.createBerLength(key.data.q.length)).concat(key.data.q)
                      .concat([2]).concat(this.createBerLength(key.data.dp.length)).concat(key.data.dp)
                      .concat([2]).concat(this.createBerLength(key.data.dq.length)).concat(key.data.dq)
                      .concat([2]).concat(this.createBerLength(key.data.u.length)).concat(key.data.u);

    } else {
      type = " PUBLIC KEY-----\n";
      data = [2].concat(this.createBerLength(key.data.n.length)).concat(key.data.n)
                .concat([2]).concat(this.createBerLength(key.data.e.length)).concat(key.data.e);
    }

    return "-----BEGIN RSA" + type + Base64Util.encode(pref.concat(this.createBerLength(data.length)).concat(data), true) + "\n-----END RSA" + type;
  }
};

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

    output  = '-----BEGIN PGP ' + input.type + '-----\n';

    for (var header in input.headers) {
      output += header + ': ' + input.headers[header] + '\n';
    }

    output += '\n' + Base64Util.encode(input.packets, true) + '\n';
    output += '=' + Base64Util.encode([input.checksum>>16, (input.checksum>>8)&0xff, input.checksum&0xff]) + '\n';
    output += '-----END PGP ' + input.type + '-----';

    return output;
  }
};

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

    input   = input.replace(/[^A-Za-z0-9\+\/=]/g, '');
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
};

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
};

var ArrayUtil = {
  //to/from string not currently handling charcode < 16 - if needed use ('0'+s).slice(-2);
  toString: function(a) {
    return decodeURIComponent(a.map(function(v){ return '%'+v.toString(16) }).join(''));
  },

  fromString: function(s) {
    return encodeURIComponent(s.split('').map(function(v){ return (v.charCodeAt(0) < 128) ? '%'+v.charCodeAt(0).toString(16) : v }).join('')).replace(/%25/g,'%')
            .slice(1).split('%').map(function(v){ return parseInt(v, 16) });
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
    for (var i = 128, l = a.length*8; i >= 1; i /= 2, l--)
      if (a[0] >= i) break;

    return l;
  }
};

var UrlUtil = {
  getParameter: function(name) {
    var match = new RegExp('[?&]' + name + '=([^&]*)').exec(window.location.search);
    return (match) ? decodeURIComponent(match[1].replace(/\+/g, ' ')) : '';
  }
};