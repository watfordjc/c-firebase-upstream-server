firebase-upstream-server
========================

firebase-upstream-server is an implementation of the Firebase XMPP Connection Server protocol in C.

It connects to the FCM XMPP servers using a configuration file (`--conf <file>`), and sends line-delimited JSON to stdout.
Informational, debug, and error messages are sent to stderr.

There are command line options available for alternative JSON-streaming formats:
- application/json-seq (`--seq`)
- length-prefixed (`--len-prefixed`)
- concatenated (`--concat`)
- NUL-terminated (`--null`, `-Z`)

It is currently minimally functional.
- Supports simultaneous connections to multiple servers using multiple accounts.
- Connection draining support using threading (untested).
- Automatic reconnection using exponential back-off (128 second maximum between retries).

Build Instructions
------------------

From the src directory, run the following commands (other C compilers
are available):

    gcc -c config-parse.c
    gcc -c firebase-upstream-server.c
    gcc -o firebase-upstream-server firebase-upstream-server.o config-parse.o -lconfig -lssl -lcrypto -lstrophe -ljson-c -lpthread

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
