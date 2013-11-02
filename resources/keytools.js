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

  createMpi: function(mpi) {
    for (var i = 0, m = 128; i < 8; i++, m /= 2)
      if (mpi[0] >= m) 
        break;

    m = mpi.length*8 - i;

    return [m >> 8, m & 0xff].concat(mpi);
  },

  createKeyPacket: function(key, type, private) {
    var len = 10 + key.mpi.n.length + key.mpi.e.length,
        tag, result, temp;

    if (type == 3) {
      tag = (private) ? 5 : 6;
    } else {
      tag = (private) ? 7 : 14;
    }

    result = [this.createTag(tag, len)].concat(this.createLength(len))
                                       .concat([4])
                                       .concat(array.fromWord(key.created))
                                       .concat([type])
                                       .concat(this.createMpi(key.mpi.n))
                                       .concat(this.createMpi(key.mpi.e));

    if (private) {
      temp = [0].concat(this.createMpi(key.mpi.d));
      
      if (mpi.cmp(key.mpi.p, key.mpi.q) == -1) {
        temp = temp.concat(this.createMpi(key.mpi.p)).concat(this.createMpi(key.mpi.q));
      } else {
        temp = temp.concat(this.createMpi(key.mpi.q)).concat(this.createMpi(key.mpi.p));
      }
      
      temp = temp.concat(this.createMpi(key.mpi.u));
      
      for (var c = 0, i = 0; i < temp.length; i++)
        c += temp[i];

      result = result.concat(temp.concat([(c%65536) >> 8, (c%65536) & 0xff]));

    }

    return result;
  },

  createNamePacket: function(name) {
    var namePacket = array.fromString(name);
    return [this.createTag(13, namePacket.length)].concat(this.createLength(namePacket.length)).concat(namePacket);
  },

  createSignaturePacket: function(meta, hash, signature) {
    var sigPacket = meta.concat(hash.slice(0,2)).concat(signature);
    return [this.createTag(2, sigPacket.length)].concat(this.createLength(sigPacket.length)).concat(sigPacket);
  },

  signSignatureHash: function(meta, sign, name) {
    var sdat, udat, suff;

    sdat = [153,0,0,4].concat(array.fromWord(sign.created))
                      .concat([3])
                      .concat(this.createMpi(sign.mpi.n))
                      .concat(this.createMpi(sign.mpi.e));

    sdat[1] = (sdat.length-3) >> 8;
    sdat[2] = (sdat.length-3) && 0xff;

    udat = [180].concat(array.fromWord(name.length))
                .concat(array.fromString(name));

    suff = [4,255].concat(array.fromWord(meta.length-12));

    return hash.digest(
      sdat.concat(udat).concat(meta.slice(0, meta.length-12)).concat(suff);
    );
  },

  encryptSignatureHash: function(meta, sign, encrypt) {
    var sdat, edat, suff;

    sdat = [153,0,0,4].concat(array.fromWord(sign.created))
                      .concat([3])
                      .concat(this.createMpi(sign.mpi.n))
                      .concat(this.createMpi(sign.mpi.e));

    sdat[1] = (sdat.length-3) >> 8;
    sdat[2] = (sdat.length-3) && 0xff;

    edat = [153,0,0,4].concat(array.fromWord(encrypt.created))
                      .concat([2])
                      .concat(this.createMpi(encrypt.mpi.n))
                      .concat(this.createMpi(encrypt.mpi.e));

    edat[1] = (edat.length-3) >> 8;
    edat[2] = (edat.length-3) && 0xff;

    suff = [4,255].concat(array.fromWord(meta.length-12));

    return hash.digest(
      sdat.concat(edat).concat(meta.slice(0, meta.length-12)).concat(suff);
    );
  },

  encryptSignatureMeta: function(encrypt) {
    return [4,24,2,2,0,15,5,2].concat(array.fromWord(encrypt.created))
                              .concat([2,27,4,5,9])
                              .concat(array.fromWord(encrypt.created+86400))
                              .concat([0,10,9,16])
                              .concat(array.fromHex(encrypt.id));
  },

  signSignatureMeta: function(sign) {
    return [4,19,3,2,0,26,5,2].concat(array.fromWord(sign.created))
                              .concat([2,27,3,5,9])
                              .concat(array.fromWord(sign.created+86400))
                              .concat([4,11,7,8,9,2,21,2,2,22,0])
                              .concat([0,10,9,16])
                              .concat(array.fromHex(sign.id));
  },

  exportKey: function(name, encrypt, sign, private) {
    var headers       = {"Version": "SecureRoom 1.0"},
        type          = (private) ? "PRIVATE KEY BLOCK" : "PUBLIC KEY BLOCK",
        namePacket    = this.createNamePacket(name),
        encryptPacket = this.createKeyPacket(encrypt, 2, private),
        signPacket    = this.createKeyPacket(sign, 3, private);
    
    return armor.dress({"type": type, "headers": headers, "packets": signPacket.concat(namePacket).concat(encryptPacket)});
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
