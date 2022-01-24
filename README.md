# nsocks
Copyright (C) 2013-2017 Nicholas J. Kain.

License: Two-clause BSD.

# nsocks is OBSOLETE and UNMAINTAINED, use muonsocks instead

## Postmortem

ASIO has (as of 2017) an issue where DNS lookups are all queued to a single
thread.  This can create noticeable delays when the SOCKS5 server is performing
DNS lookups on behalf of a client and the lookup is slow.  ASIO's flexible
design makes it possible to work around this issue without modifying ASIO
itself, but it is rather ugly to do so.  A thread-per-connection model simply
doesn't have this issue, as blocking lookups can be used on the connection
threads.

The traditional single-threaded async-readiness loop server that works so well
for web servers is not such a great win for proxy servers.  Proxy servers
need to have two buffers that are kept small to prevent bufferbloat.  This
is a natural fit to the thread-per-connection model, since we essentially
want something very similar to blocking synchronous i/o, except where the
thread-per-connection can service both halves of the duplex connection
concurrently.

splice(), at least when used with ASIO, never provided performance gains that
made the significant increase in code complexity worthwhile.  It's quite
possible that performance gains might be more significant without the overhead
of ASIO, but even in that case, buffer management is made much more complex by
having to splice through two different pipes for a duplex connection, and to
recycle pipes so as to mitigate the overhead of creating and destroying pipes
all the time.  Further, nsocks fell back to recv/send for short or slow
read/write patterns, which mitigated low-performance cases of splice(), but
added significant complexity.

The sheer complexity of nsocks made it hard to verify correct behavior in all
possible corner-cases, and the performance gains from such a complex model just
didn't exist.

muonsocks implements a very simple thread-per-connection model, using simple
send/recv and a low-overhead poll() loop, but provides great performance
and is very robust and easy to maintain.

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

* [GitLab](https://gitlab.com/niklata/nsocks)
* [BitBucket](https://bitbucket.com/niklata/nsocks)
* [GitHub](https://github.com/niklata/nsocks)

## Portability

nsocks could be ported to non-Linux systems, but will require new code
to replace the splice mechanism used in Linux.  Some security hardening
features (`SO_LOCK_FILTER`) would need to be disabled, too.

