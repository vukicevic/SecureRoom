var keytools = {

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
    if (l < 256) {
      return [l];
    } else if (l < 65536) {
      return [l>>8, l&0xff];
    } else {
      return array.fromWord(l);
    }
  },

  createMpiLength: function(mpi) {
    for (var i = 0, m = 128; i < 8; i++, m /= 2)
      if (mpi[0] >= m) 
        break;

    m = mpi.length*8 - i;

    return [m >> 8, m & 0xff];
  },

  createKey: function(key) {
    var namePacket = array.fromString(key.name),
        encryptPacket,
        signPacket, 
        elen = 10 + key.encrypt.mpi.n.length + key.encrypt.mpi.e.length,
        slen = 10 + key.sign.mpi.n.length + key.sign.mpi.e.length;
    
    //check length, currently assumed less than 256
    namePacket = [this.createTag(13, namePacket.length)].concat(this.createLength(namePacket.length))
                                                        .concat(namePacket);
    
    encryptPacket = [this.createTag(6, elen)].concat(this.createLength(elen))
                                             .concat([4])
                                             .concat(array.fromWord(key.encrypt.created))
                                             .concat([2])
                                             .concat(this.createMpiLength(key.encrypt.mpi.n))
                                             .concat(key.encrypt.mpi.n)
                                             .concat(this.createMpiLength(key.encrypt.mpi.e))
                                             .concat(key.encrypt.mpi.e);

    signPacket = [this.createTag(14, slen)].concat(this.createLength(slen))
                                           .concat([4])
                                           .concat(array.fromWord(key.sign.created))
                                           .concat([3])
                                           .concat(this.createMpiLength(key.sign.mpi.n))
                                           .concat(key.sign.mpi.n)
                                           .concat(this.createMpiLength(key.sign.mpi.e))
                                           .concat(key.sign.mpi.e);

    return encryptPacket.concat(namePacket)
                        .concat(signPacket);
  },

  exportPublicKey: function(key) {
    var packets = this.createKey(key);
        headers = {"Version": "SecureRoom 1.0"},
        type    = "PUBLIC KEY BLOCK";

    return armor.dress({"type": type, "headers": headers, "packets": packets});
  }
}

var armor = {
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
      temp[3] = base64.decode(temp[3]);

      output.type     = temp[0];
      output.packets  = base64.decode(temp[2]);
      output.checksum = temp[3][0]*65536 + temp[3][1]*256 + temp[3][2];
      output.valid    = (armor.crc(output.packets) == output.checksum);
    }

    return output;
  },

  dress: function(input) {
    var output;

    input.checksum = armor.crc(input.packets);
    input.valid    = true;

    output  = '-----BEGIN PGP ' + input.type + '-----\n'

    for (var header in input.headers) {
      output += header + ': ' + input.headers[header] + '\n';
    }

    output += '\n' + base64.encode(input.packets, true) + '\n';
    output += '=' + base64.encode([input.checksum>>16, (input.checksum>>8)&0xff, input.checksum&0xff]) + '\n';
    output += '-----END PGP ' + input.type + '-----';

    return output;
  }
}

var base64 = {
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
