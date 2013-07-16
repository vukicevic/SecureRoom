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

var random = {
  /*
  Generates an octet array with random values, with specified total size in bits
  s - Size to generate, in bits
  */
  generate: function(size) {
    var a = [],
        l = Math.ceil(size/8),
        t, i;
      
    t = new Uint8Array(l);
    window.crypto.getRandomValues(t);
    for (i = 0; i < l; i++) a[i] = t[i];

    return a;
  }
}
