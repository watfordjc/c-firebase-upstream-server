firebase-upstream-server
========================

firebase-upstream-server is an implementation of the Firebase XMPP Connection Server protocol.

It connects to the FCM XMPP servers using a configuration file, and sends line-delimited JSON to stdout.
Informational, debug, and error messages are sent to stderr.

It is currently minimally functional.

Build Instructions
------------------

From the src directory, run the following command (other C compilers
are available):

    gcc firebase-upstream-server.c -o firebase-upstream-server -lstrophe -lssl -lcrypto -lconfig -ljson-c

Requirements
------------

firebase-upstream-server requires:

- libstrophe and its dependencies
- openssl
- libconfig
- libjson-c

Configuration
-------------

See conf/xmpp.conf.example for an example configuration file.
