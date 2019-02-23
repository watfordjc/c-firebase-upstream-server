firebase-upstream-server
========================

firebase-upstream-server is a fork of a code example of libstrophe.

It is a work in progress, and is not currently functional.

Build Instructions
------------------

From the src directory, run the following command (other C compilers
are available):

    gcc firebase-upstream-server.c -o firebase-upstream-server -lstrophe -lssl -lcrypto

Requirements
------------

firebase-upstream-server requires:

- libstrophe and its dependencies
- openssl
