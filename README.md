# HAProxy TLS/QUIC tests

This repository contains a small test suite for interop testing with a HAProxy build and
various clients. It focusess on the TLS handshake, not on HTTP or proxy settings/performance.

## Installation

You need the following prerequites:

* a built HAProxy projec
* pytest and python cryptography installed
* Apache httpd on your system
* `openssl` and `curl` available

```
# clone from github
> autoreconf -i
> ./configure --with-haproy=<path to built haproxy project>

# if `httpd` and `apachtctl` can not be found in $PATH, use
> ./configure --with-haproy=<path> --with-httpd=<path to httpd install>

# for QUIC tests, you need a built `ngtcp2` project with example clients
> ./configure --with-haproy=<path> --with-ngtcp2=<path to built ngtcp2 project>

```

## Running

If `openssl` and `curl` can be found in your $PATH:

```
# run all tests
> pytest

# have more verbose output
> pytest -vvv

# run test matching names (prefix, see pytest doc for more options)
> pytest -k test_02
```

If your default `openssl` is not really a OpenSSL one (macOS), you can specify where to find a correct one:

```
# run all tests
> OPENSSL=/path/to/real/openssl pytest
```

