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
    return s.match(/.{2}/g).map(function(v){return parseInt(v, 16)});
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
  },

  makeMpi: function(a) {
    return ArrayUtil.fromHalf(ArrayUtil.bitLength(a)).concat(a);
  }
};

var UrlUtil = {
  getParameter: function(name) {
    var match = new RegExp('[?&]' + name + '=([^&]*)').exec(window.location.search);
    return (match) ? decodeURIComponent(match[1].replace(/\+/g, ' ')) : '';
  }
};

function ExportUtil() {
  function makeLength(l) {
    return (l < 256) ? [l] : (l < 65536) ? ArrayUtil.fromHalf(l) : ArrayUtil.fromWord(l);
  }

  function makeTag(t, l) {
    return (l > 65535) ? [t*4 + 130] : (l > 255) ? [t*4 + 129] : [t*4 + 128];
  }

  function makeNamePacket(name) {
    var packet = ArrayUtil.fromString(name);
    
    return makeTag(13, packet.length).concat(makeLength(packet.length)).concat(packet);
  }

  function makePublicKeyPacket(key) {
    var len = 10 + key.material.n.length + key.material.e.length,
      tag = (key.type === 3) ? 6 : 14;

    return makeTag(tag, len).concat(makeLength(len)).concat(key.base);
  }

  function makeSecretKeyPacket(key) {
    var len = 21 + key.material.n.length + key.material.e.length + key.material.d.length + key.material.p.length + key.material.q.length + key.material.u.length,
      tag = (key.type === 3) ? 5 : 7,
      tmp = [0].concat(ArrayUtil.makeMpi(key.material.d))
           .concat(ArrayUtil.makeMpi(key.material.p))
           .concat(ArrayUtil.makeMpi(key.material.q))
           .concat(ArrayUtil.makeMpi(key.material.u));

    return makeTag(tag, len).concat(makeLength(len)).concat(key.base).concat(tmp).concat(ArrayUtil.fromHalf(tmp.reduce(function(a, b) { return a + b }) % 65536));
  }

  function makeSignaturePacket(key) {
    var head = key.signatureBase,
      list = [],
      pack, id;
      
    for (id in key.signatures) {
      pack = head.concat([0, 10, 9, 16])
          .concat(ArrayUtil.fromHex(key.id))
          .concat(key.signatures[id].hashcheck)
          .concat(ArrayUtil.makeMpi(key.signatures[id].signature));
    
      list = list.concat(makeTag(2, pack.length)).concat(makeLength(pack.length)).concat(pack);
    }

    return list;
  }

  return {
    publicGpg: function(user) {
      var p = makePublicKeyPacket(user.master)
          .concat(makeNamePacket(user.name))
          .concat(makeSignaturePacket(user.master))
          .concat(makePublicKeyPacket(user.ephemeral))
          .concat(makeSignaturePacket(user.ephemeral));

      return ArmorUtil.dress({"type": "PUBLIC KEY BLOCK", "headers": {"Version": "SecureRoom"}, "packets": p});
    },

    privateGpg: function(user) {
      var p = makeSecretKeyPacket(user.master)
          .concat(makeNamePacket(user.name))
          .concat(makeSignaturePacket(user.master))
          .concat(makeSecretKeyPacket(user.ephemeral))
          .concat(makeSignaturePacket(user.ephemeral));

      return ArmorUtil.dress({"type": "PRIVATE KEY BLOCK", "headers": {"Version": "SecureRoom"}, "packets": p});
    }
  }
}