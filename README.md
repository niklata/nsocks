# nsocks
Copyright (C) 2013-2017 Nicholas J. Kain.

License: Two-clause BSD.

## Introduction

nsocks is a SOCKS5 or SOCKS4 proxying daemon that is designed for
high performance.  It uses zero-copy I/O whenever possible, and is
aggressively multithreaded so that it will fully take advantage of
multicore machines.  nsocks uses lock-free algorithms whenever possible
in order to aid scalability.

SOCKS proxies are useful when routing decisions are to be made by clients
rather than by the router.  In particular, nsocks was written so as to
allow applications running on a client network to choose network egress
routes without a significant performance burden on the router compared
to NAT or simple packet forwarding.

nsocks has been designed to be secure and function with minimal privilege.

## Use of Zerocopy I/O

nsocks uses Linux's `splice()` system call for zerocopy I/O between
sockets and pipes.  nsocks will function on other platforms, but it
will perform normal I/O that involves copying the data through userspace
memory buffers.

Additionally, zerocopy I/O is only possible for TCP connections.
The SOCKS protocol is designed in such a way that zerocopy would not
make any significant difference in performance for UDP.

## Requirements

* Linux kernel
* GCC or Clang
* CMake
* [ASIO 1.11](https://think-async.com)
* [ncmlib](https://github.com/niklata/ncmlib)
* [fmtlib](https://github.com/fmtlib/fmt)
* [Boost](https://boost.org)

## Standard Usage

Install dependencies.  In the nsocks directory, symlinks should be created.
Assuming that asio, ncmlib, and fmtlib live in the same directory as
the nsocks directory:
```
$ ls
asio fmt ncmlib nsocks
$ cd nsocks
$ ln -s ../asio/include asio
$ ln -s ../ncmlib .
$ ln -s ../fmt/format.[ch]pp fmt/
```
Compile and install nsocks.
* Create a build directory: `mkdir build && cd build`
* Create the makefiles: `cmake ..`
* Build nsocks: `make`
* Install the `nsocks/nsocks` executable in a normal place.  I would
  suggest `/usr/sbin` or `/usr/local/sbin`.
* Set up a user and chroot path (_optional, but recommended_).

Run nsocks.  Use `nsocks --help` to see all possible options.

Example configuration file (`/etc/nsocks-raw.conf`):
```
threads = 2
address = 192.168.1.1:1080
user = nsocks
chroot = /var/empty
disable-ipv6 = true
deny-dst = 192.168.1.0/24
deny-dst = 3133:7::/48
bind-allow-src = 192.168.1.0/24
bind-allow-src = 3133:7::/48
bind-lowest-port = 64000
bind-highest-port = 65000
splice-size = 1048576
handshake-gc-interval = 1
```

To use this example configuration, invoke nsocks as follows:

`nsocks -c /etc/nsocks-raw.conf`

## Downloads

* [GitLab](https://github.com/niklata/nsocks)
* [BitBucket](https://gitlab.com/niklata/nsocks)
* [GitHub](https://bitbucket.com/niklata/nsocks)

## Portability

nsocks could be ported to non-Linux systems, but will require new code
to replace the splice mechanism used in Linux.  Some security hardening
features (seccomp-bpf syscall filtering, `SO_LOCK_FILTER`) would need to
be disabled, too.

