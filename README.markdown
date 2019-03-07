firebase-upstream-server
========================

firebase-upstream-server is an implementation of the Firebase XMPP Connection Server protocol.

It connects to the FCM XMPP servers using a configuration file (`--conf <file>`), and sends line-delimited JSON to stdout.
Informational, debug, and error messages are sent to stderr.

There are command line options available for alternative JSON-streaming formats:
- application/json-seq (`--seq`)
- length-prefixed (`--len-prefixed`)
- concatenated (`--concat`)
- NUL-terminated (`--null`, `-Z`)

It is currently minimally functional.

Build Instructions
------------------

From the src directory, run the following command (other C compilers
are available):

    gcc firebase-upstream-server.c -o firebase-upstream-server -lstrophe -lssl -lcrypto -lconfig -ljson-c -lpthread

Requirements
------------

firebase-upstream-server requires:

- [libstrophe](https://github.com/strophe/libstrophe) and its dependencies ([libexpat](https://github.com/libexpat/libexpat)/[libxml2](https://github.com/GNOME/libxml2), [openssl](https://github.com/openssl/openssl))
- [openssl](https://github.com/openssl/openssl)
- [libconfig](https://github.com/hyperrealm/libconfig)
- [libjson-c](https://github.com/json-c/json-c)

Configuration
-------------

See [conf/xmpp.conf.example](conf/xmpp.conf.example) for an example configuration file.
