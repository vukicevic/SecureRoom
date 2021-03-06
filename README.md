SecureRoom
==========

Encrypted, browser-based, communication processed entirely client-side. Key generation, key distribution, encryption, decryption, verification - everything is done in your browser. No plugins, no server-side key-management.

SecureRoom uses proven cryptographic algorithms to provide a secure, encrypted communication channel for message exchange. Because keys are generated for one-time use, forward secrecy is built in.

It can be used locally (Firefox) or via princip.secureroom.net (latest Chrome, Firefox or IE).

Using SecureRoom locally
========================

Download the [latest version](https://github.com/vukicevic/SecureRoom/archive/master.zip).

Extract and open the file index.html in a web browser.

There are two parameters which can be set when loading the page, room and server. The server is required as a proxy for the encrypted messages.

####Server

Define the websocket server which will relay communication (you can use princip.secureroom.net) by either setting it in the settings menu, or via a search parameter, e.g:

    index.html?server=wss%3A%2F%2Fprincip.secureroom.net
    
####Room

A room name is automatically generated when the room creator generates their keys.

To join an existing room, or define a custom room name, set the room parameter:

    index.html?server=wss%3A%2F%2Fprincip.secureroom.net&room=MyVerySecureRoom


