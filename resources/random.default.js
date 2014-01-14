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

var Random = {
  /*
  Generates an octet array with random values, with specified total size in bits
  s - Size to generate, in bits
  */
  generate: function(size) {
    var c = window.crypto || window.msCrypto;
        t = new Uint8Array(Math.ceil(size/8));
    
    c.getRandomValues(t);

    return Array.prototype.slice.call(t);
  }
}
