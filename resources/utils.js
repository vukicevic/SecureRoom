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

var PrintUtil = {
  time: function(timestamp) {
    var date = new Date(timestamp*1000);
    return ("0" + date.getHours()).slice(-2) + " " + ("0" + date.getMinutes()).slice(-2) + " " + ("0" + date.getSeconds()).slice(-2);
  },

  date: function(timestamp) {
    var date = new Date(timestamp*1000);
    return date.getHours() + ":" + ("0"+date.getMinutes()).slice(-2) + ":" + ("0"+date.getSeconds()).slice(-2) + " " + date.getDate() + "/" + (date.getMonth()+1) + "/" + date.getFullYear();
  },

  text: function(text) {
    return text.replace(/["<>&]/g, function(m) { return ({'"': '&quot;', '<': '&lt;', '>': '&gt;', '&': '&amp;'})[m] });
  },

  bool: function(boolean) {
    return (boolean) ? "True" : "False";
  },

  number: function(number) {
    return number.toString();
  },

  id: function(id) {
    return id.match(/.{2}/g).map(function(v) { return v }).join(":").toUpperCase();
  }
};

var ArrayUtil = {
  toString: function(a) {
    return decodeURIComponent(a.map(function(v) { return "%"+v.toString(16) }).join(""));
  },

  fromString: function(s) {
    return encodeURIComponent(s.split("").map(function(v) { return (v.charCodeAt() < 128) ? "%" + v.charCodeAt().toString(16) : v }).join("")).replace(/%25/g, "%")
            .slice(1).split("%").map(function(v) { return parseInt(v, 16) });
  },

  toHex: function(a) {
    return a.map(function(v) { return ("0"+v.toString(16)).slice(-2) }).join("");
  },

  fromHex: function(s) {
    return s.match(/.{2}/g).map(function(v) { return parseInt(v, 16) });
  },

  toWord: function(a) {
    return a[0]*16777216 + a[1]*65536 + a[2]*256 + a[3];
  },

  fromWord: function(n) {
    return [n>>24, (n>>16)&0xff, (n>>8)&0xff, n&0xff];
  },

  fromHalf: function(n) {
    return [n>>8, n&0xff];
  },

  bitLength: function(a) {
    for (var i = 128, l = a.length*8; i >= 1; i /= 2, l--)
      if (a[0] >= i) 
        break;

    return l;
  },

  toMpi: function(a) {
    return ArrayUtil.fromHalf(ArrayUtil.bitLength(a)).concat(a);
  },

  fromBase64: function(s) {
    return Array.prototype.map.call(atob(s), function(c) { return c.charCodeAt() });
  },

  toBase64: function(a) {
    return btoa(String.fromCharCode.apply(null, a));
  }
};

function ExportUtil() {
  var ArmorUtil = {
    crc: function(data) {
      var crc = 0xb704ce,
          ply = 0x1864cfb,
          len = data.length,
          i, h = 0;

      while (h < len) {
        crc ^= data[h++] * 65536;
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

      input = input.replace(/\r\n/g, "\n");

      if (pattern.test(input)) {
        temp = input.replace(pattern, "$1,$2,$3,$4").split(",");

        temp[1].match(/.+: .+/gm).map(function(item) {
          var pair = item.split(": ");
          output.headers[pair[0]] = pair[1];
        });

        output.type     = temp[0];
        output.packets  = ArrayUtil.fromBase64(temp[2].split("\n").join(""));
        output.checksum = ArrayUtil.toWord(ArrayUtil.fromBase64(temp[3]).unshift(0));
        output.valid    = (this.crc(output.packets) == output.checksum);
      }

      return output;
    },

    dress: function(input) {
      var output = "-----BEGIN PGP " + input.type + "-----\n";

      input.checksum = this.crc(input.packets);

      for (var header in input.headers) {
        output += header + ": " + input.headers[header] + "\n";
      }

      output += "\n" + ArrayUtil.toBase64(input.packets).match(/.{1,64}/g).join("\n") + "\n";
      output += "=" + ArrayUtil.toBase64([input.checksum>>16, (input.checksum>>8)&0xff, input.checksum&0xff]) + "\n";
      output += "-----END PGP " + input.type + "-----";

      return output;
    }
  }

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

    return makeTag(tag, len).concat(makeLength(len)).concat(key.makeBase());
  }

  function makeSecretKeyPacket(key) {
    var len = 21 + key.material.n.length + key.material.e.length + key.material.d.length + key.material.p.length + key.material.q.length + key.material.u.length,
      tag = (key.type === 3) ? 5 : 7,
      tmp = [0].concat(ArrayUtil.toMpi(key.material.d))
           .concat(ArrayUtil.toMpi(key.material.p))
           .concat(ArrayUtil.toMpi(key.material.q))
           .concat(ArrayUtil.toMpi(key.material.u));

    return makeTag(tag, len).concat(makeLength(len)).concat(key.makeBase()).concat(tmp).concat(ArrayUtil.fromHalf(tmp.reduce(function(a, b) { return a + b }) % 65536));
  }

  function makeSignaturePacket(key) {
    var head = key.makeSignatureBase(),
      list = [],
      pack, id;
      
    for (id in key.signatures) {
      pack = head.concat(0,10,9,16)
          .concat(ArrayUtil.fromHex(key.id))
          .concat(key.signatures[id].hashcheck)
          .concat(ArrayUtil.toMpi(key.signatures[id].signature));
    
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