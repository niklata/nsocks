/* nsocks.c - socks5 server
 *
 * (c) 2013-2016 Nicholas J. Kain <njkain at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define NSOCKS_VERSION "0.9"

#include <memory>
#include <string>
#include <vector>
#include <thread>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <errno.h>
#include <fmt/format.h>
#include <nk/from_string.hpp>
#include <nk/optionarg.hpp>
#include <asio.hpp>
extern "C" {
#include "nk/privilege.h"
#include "nk/pidfile.h"
#include "nk/seccomp-bpf.h"
}
#include "socksclient.hpp"

asio::io_service io_service;
static asio::signal_set asio_signal_set(io_service);
static std::vector<std::unique_ptr<ClientListener>> listeners;
static uid_t nsocks_uid;
static gid_t nsocks_gid;
static std::size_t num_worker_threads = 1;
static int gflags_detach;
static bool use_seccomp{false};

static void process_signals()
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGPIPE);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);
    sigaddset(&mask, SIGTSTP);
    sigaddset(&mask, SIGTTIN);
    sigaddset(&mask, SIGHUP);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
        fmt::print("sigprocmask failed\n");
        std::quick_exit(EXIT_FAILURE);
    }
    asio_signal_set.add(SIGINT);
    asio_signal_set.add(SIGTERM);
    asio_signal_set.async_wait([](const std::error_code &, int signum) { io_service.stop(); });
}

static int enforce_seccomp(bool changed_uidgid)
{
    if (!use_seccomp)
        return 0;
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        EXAMINE_SYSCALL,
        ALLOW_SYSCALL(sendmsg),
        ALLOW_SYSCALL(recvmsg),
        ALLOW_SYSCALL(splice),
        ALLOW_SYSCALL(epoll_wait),
        ALLOW_SYSCALL(epoll_ctl),
        ALLOW_SYSCALL(sendto),
        ALLOW_SYSCALL(recvfrom),
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(getpeername),
        ALLOW_SYSCALL(getsockname),
        ALLOW_SYSCALL(stat),
        ALLOW_SYSCALL(open),
        ALLOW_SYSCALL(close),
        ALLOW_SYSCALL(setsockopt),
        ALLOW_SYSCALL(getsockopt),
        ALLOW_SYSCALL(shutdown),
        ALLOW_SYSCALL(connect),
        ALLOW_SYSCALL(socket),
        ALLOW_SYSCALL(timerfd_settime),
        ALLOW_SYSCALL(accept),
        ALLOW_SYSCALL(bind),
        ALLOW_SYSCALL(listen),
        ALLOW_SYSCALL(ioctl),

        ALLOW_SYSCALL(futex),
        ALLOW_SYSCALL(pipe2),
        ALLOW_SYSCALL(fcntl),
        ALLOW_SYSCALL(poll),

        ALLOW_SYSCALL(rt_sigreturn),
        ALLOW_SYSCALL(rt_sigaction),
#ifdef __NR_sigreturn
        ALLOW_SYSCALL(sigreturn),
#endif
#ifdef __NR_sigaction
        ALLOW_SYSCALL(sigaction),
#endif
        // Allowed by vDSO
        ALLOW_SYSCALL(getcpu),
        ALLOW_SYSCALL(time),
        ALLOW_SYSCALL(gettimeofday),
        ALLOW_SYSCALL(clock_gettime),

        // operator new
        ALLOW_SYSCALL(brk),
        ALLOW_SYSCALL(mmap),
        ALLOW_SYSCALL(munmap),

        ALLOW_SYSCALL(fstat),
        ALLOW_SYSCALL(clone),
        ALLOW_SYSCALL(mprotect),

        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(exit),
        KILL_PROCESS,
    };
    struct sock_fprog prog;
    memset(&prog, 0, sizeof prog);
    prog.len = (unsigned short)(sizeof filter / sizeof filter[0]);
    prog.filter = filter;
    if (!changed_uidgid && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return -1;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
        return -1;
    fmt::print("seccomp filter installed.  Please disable seccomp if you encounter problems.\n");
    std::fflush(stdout);
    return 0;
}

static void hostmask_vec_add(const std::vector<std::string> &svec,
                             std::vector<std::pair<asio::ip::address, unsigned int>> &dvec,
                             const char sname[])
{
    for (const auto &i: svec) {
        std::string addr(i);
        int mask = -1;
        auto loc = addr.rfind("/");
        if (loc != std::string::npos) {
            auto mstr = addr.substr(loc + 1);
            try {
                mask = nk::from_string<int>(mstr);
            } catch (const std::exception &) {
                fmt::print("bad mask in {}: '{}'\n", sname, addr);
                std::exit(EXIT_FAILURE);
            }
            addr.erase(loc);
        }
        try {
            auto addy = asio::ip::address::from_string(addr);
            if (mask < 0)
                mask = addy.is_v4() ? 32 : 128;
            if (addy.is_v4())
                mask = std::min(mask, 32);
            else
                mask = std::min(mask, 128);
            dvec.emplace_back(addy, mask);
        } catch (const std::error_code&) {
            fmt::print("bad address in {}: '{}'\n", sname, addr);
            std::exit(EXIT_FAILURE);
        }
    }
}

static void print_version()
{
    fmt::print("nsocks " NSOCKS_VERSION ", socks5 server.\n"
               "Copyright (c) 2013-2016 Nicholas J. Kain\n"
               "All rights reserved.\n\n"
               "Redistribution and use in source and binary forms, with or without\n"
               "modification, are permitted provided that the following conditions are met:\n\n"
               "- Redistributions of source code must retain the above copyright notice,\n"
               "  this list of conditions and the following disclaimer.\n"
               "- Redistributions in binary form must reproduce the above copyright notice,\n"
               "  this list of conditions and the following disclaimer in the documentation\n"
               "  and/or other materials provided with the distribution.\n\n"
               "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\"\n"
               "AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE\n"
               "IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE\n"
               "ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE\n"
               "LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR\n"
               "CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF\n"
               "SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS\n"
               "INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN\n"
               "CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)\n"
               "ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE\n"
               "POSSIBILITY OF SUCH DAMAGE.\n");
}

enum OpIdx {
    OPT_UNKNOWN, OPT_HELP, OPT_VERSION, OPT_BACKGROUND, OPT_PIDFILE,
    OPT_CHROOT, OPT_USER, OPT_THREADS, OPT_SCHUNKSIZE, OPT_RCHUNKSIZE,
    OPT_SPLICESIZE, OPT_LISTENQ, OPT_NOIPV6, OPT_PREFERIPV4, OPT_DENYDST,
    OPT_BINDOK, OPT_UDPOK, OPT_HSHAKEGC, OPT_BINDGC, OPT_BINDLPORT,
    OPT_BINDHPORT, OPT_NOBIND, OPT_NOUDP, OPT_SECCOMP, OPT_VERBOSE
};
static const option::Descriptor usage[] = {
    { OPT_UNKNOWN,    0,  "",           "", Arg::Unknown,
        "nsocks " NSOCKS_VERSION ", socks5 server.\n"
        "Copyright (c) 2013-2016 Nicholas J. Kain\n"
        "nsocks [options] listen-address[:port]...\n\nOptions:\n"},
    { OPT_HELP,       0, "h",              "help",    Arg::None, "\t-h, \t--help  \tPrint usage and exit." },
    { OPT_VERSION,    0, "v",           "version",    Arg::None, "\t-v, \t--version  \tPrint version and exit." },
    { OPT_BACKGROUND, 0, "b",        "background",    Arg::None, "\t-b, \t--background  \tRun as a background daemon." },
    { OPT_PIDFILE,    0, "f",           "pidfile",  Arg::String, "\t-f, \t--pidfile  \tPath to process id file." },
    { OPT_CHROOT,     0, "C",            "chroot",  Arg::String, "\t-C, \t--chroot  \tPath in which nident should chroot itself." },
    { OPT_USER,       0, "u",              "user",  Arg::String, "\t-u, \t--user  \tUser name that nident should run as." },
    { OPT_THREADS,    0, "T",           "threads", Arg::Integer, "\t-T, \t--threads  \tNumber of worker threads that nsocks should use." },
    { OPT_SCHUNKSIZE, 0,  "",    "send-chunksize", Arg::Integer, "\t    \t--send-chunksize  \tBytes of ram used as buffer when sending data for a connection." },
    { OPT_RCHUNKSIZE, 0,  "", "receive-chunksize", Arg::Integer, "\t    \t--receive-chunksize  \tBytes of ram used as buffer when receiving data for a connection." },
    { OPT_SPLICESIZE, 0,  "",       "splice-size", Arg::Integer, "\t    \t--splice-size  \tMax byte size of the pipe buffer used for splicing data." },
    { OPT_LISTENQ,    0, "L",       "listenqueue", Arg::Integer, "\t-L  \t--listenqueue  \tMaximum number of pending client connections." },
    { OPT_NOIPV6,     0,  "",      "disable-ipv6",    Arg::None, "\t    \t--disable-ipv6  \tHost kernel doesn't support ipv6." },
    { OPT_PREFERIPV4, 0,  "",       "prefer-ipv4",    Arg::None, "\t    \t--prefer-ipv4  \tPrefer ipv4 addresses when looking up hostnames." },
    { OPT_DENYDST,    0,  "",          "deny-dst",  Arg::String, "\t    \t--deny-dst  \tDenies connections to the specified 'host/netmask'." },
    { OPT_BINDOK,     0,  "",    "bind-allow-src",  Arg::String, "\t    \t--bind-allow-src  \tAllows bind requests from the specified 'host/netmask'." },
    { OPT_UDPOK,      0,  "",     "udp-allow-src",  Arg::String, "\t    \t--udp-allow-src  \tAllows udp associate requests from the specified 'host/netmask'." },
    { OPT_HSHAKEGC,   0,  "",  "handshake-gc-sec", Arg::Integer, "\t    \t--handshake-gc-sec  \tSeconds between gc sweeps of unfinished handshakes." },
    { OPT_BINDGC,     0,  "", "bindlisten-gc-sec", Arg::Integer, "\t    \t--bindlisten-gc-sec  \tSeconds between gc sweeps of listening bind sockets." },
    { OPT_BINDLPORT,  0,  "",  "bind-lowest-port", Arg::Integer, "\t    \t--bind-lowest-port  \tLowest port that will be assigned to bind requests." },
    { OPT_BINDHPORT,  0,  "", "bind-highest-port", Arg::Integer, "\t    \t--bind-highest-port  \tHighest port that will be assigned to bind requests." },
    { OPT_NOBIND,     0,  "",      "disable-bind",    Arg::None, "\t    \t--disable-bind  \tIgnore client bind requests." },
    { OPT_NOUDP,     0,  "",        "disable-udp",    Arg::None, "\t    \t--disable-udp  \tIgnore client udp associate requests." },
    { OPT_SECCOMP,    0,  "",   "seccomp-enforce",    Arg::None, "\t    \t--seccomp-enforce  \tEnforce seccomp syscall restrictions." },
    { OPT_VERBOSE,    0, "V",           "verbose",    Arg::None, "\t    \t--verbose  \tLog diagnostic information." },
    {0,0,0,0,0,0}
};
static void process_options(int ac, char *av[])
{
    ac-=ac>0; av+=ac>0;
    option::Stats stats(usage, ac, av);
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvla"
    option::Option options[stats.options_max], buffer[stats.buffer_max];
#pragma GCC diagnostic pop
    option::Parser parse(usage, ac, av, options, buffer);
#else
    auto options = std::make_unique<option::Option[]>(stats.options_max);
    auto buffer = std::make_unique<option::Option[]>(stats.buffer_max);
    option::Parser parse(usage, ac, av, options.get(), buffer.get());
#endif
    if (parse.error())
        std::exit(EXIT_FAILURE);
    if (options[OPT_HELP]) {
        uint16_t col{80};
        const auto cols = getenv("COLUMNS");
        if (cols) col = nk::from_string<uint16_t>(cols);
        option::printUsage(fwrite, stdout, usage, col);
        std::exit(EXIT_FAILURE);
    }
    if (options[OPT_VERSION]) {
        print_version();
        std::exit(EXIT_FAILURE);
    }

    std::vector<std::string> addrlist, denydstlist, bindallowsrclist,
        udpallowsrclist;
    std::string pidfile, chroot_path;
    size_t hs_secs{5}, bindlisten_secs{180};
    uint16_t bind_lowest_port(0), bind_highest_port(0);

    for (int i = 0; i < parse.optionsCount(); ++i) {
        option::Option &opt = buffer[i];
        switch (opt.index()) {
            case OPT_BACKGROUND: gflags_detach = 1; break;
            case OPT_PIDFILE: pidfile = std::string(opt.arg); break;
            case OPT_CHROOT: chroot_path = std::string(opt.arg); break;
            case OPT_USER:
                if (nk_uidgidbyname(opt.arg, &nsocks_uid, &nsocks_gid)) {
                    fmt::print("invalid user '{}' specified\n", opt.arg);
                    std::exit(EXIT_FAILURE);
                }
                break;
            case OPT_THREADS:
                num_worker_threads = std::max(1,nk::from_string<int>(opt.arg)); break;
            case OPT_SCHUNKSIZE:
                SocksTCP::set_send_buffer_chunk_size
                    (std::max(128,nk::from_string<int>(opt.arg))); break;
            case OPT_RCHUNKSIZE:
                SocksTCP::set_receive_buffer_chunk_size
                    (std::max(128,nk::from_string<int>(opt.arg))); break;
            case OPT_SPLICESIZE:
                SocksTCP::set_splice_pipe_size(std::max(4096,nk::from_string<int>(opt.arg)));
                break;
            case OPT_LISTENQ:
                set_listen_queuelen(std::max(1,nk::from_string<int>(opt.arg))); break;
            case OPT_NOIPV6: g_disable_ipv6 = true; break;
            case OPT_PREFERIPV4: g_prefer_ipv4 = true; break;
            case OPT_DENYDST: denydstlist.emplace_back(opt.arg); break;
            case OPT_BINDOK: bindallowsrclist.emplace_back(opt.arg); break;
            case OPT_UDPOK: udpallowsrclist.emplace_back(opt.arg); break;
            case OPT_HSHAKEGC: hs_secs = std::max(1,nk::from_string<int>(opt.arg)); break;
            case OPT_BINDGC: bindlisten_secs = std::max(1,nk::from_string<int>(opt.arg)); break;
            case OPT_BINDLPORT:
                bind_lowest_port = std::min(65535,std::max(0,nk::from_string<int>(opt.arg)));
                break;
            case OPT_BINDHPORT:
                bind_highest_port = std::min(65535,std::max(0,nk::from_string<int>(opt.arg)));
                break;
            case OPT_NOBIND: g_disable_bind = true; break;
            case OPT_NOUDP: g_disable_udp = true; break;
            case OPT_SECCOMP: use_seccomp = true; break;
            case OPT_VERBOSE: g_verbose_logs = true; break;
        }
    }
    for (int i = 0; i < parse.nonOptionsCount(); ++i) {
        addrlist.emplace_back(parse.nonOption(i));
    }

    init_conntrackers(hs_secs, bindlisten_secs);
    init_bind_port_assigner(bind_lowest_port, bind_highest_port);

    for (const auto &i: addrlist) {
        std::string addr(i);
        int port = 1080;
        auto loc = addr.rfind(":");
        if (loc != std::string::npos) {
            auto pstr = addr.substr(loc + 1);
            try {
                port = nk::from_string<uint16_t>(pstr);
            } catch (const std::exception &) {
                fmt::print("bad port in address '{}', defaulting to 1080\n", addr);
            }
            addr.erase(loc);
        }
        try {
            auto addy = asio::ip::address::from_string(addr);
            auto ep = asio::ip::tcp::endpoint(addy, port);
            listeners.emplace_back(std::make_unique<ClientListener>(ep));
        } catch (const std::error_code&) {
            fmt::print("bad address: {}\n", addr);
        }
    }
    if (!addrlist.size()) {
        auto ep = asio::ip::tcp::endpoint(asio::ip::tcp::v6(), 1080);
        listeners.emplace_back(std::make_unique<ClientListener>(ep));
    }

    hostmask_vec_add(denydstlist, g_dst_deny_masks, "deny-dst");
    hostmask_vec_add(bindallowsrclist, g_client_bind_allow_masks,
                     "bind-allow-src");
    hostmask_vec_add(udpallowsrclist, g_client_udp_allow_masks,
                     "udp-allow-src");

    if (gflags_detach) {
        if (daemon(0,0)) {
            fmt::print("detaching fork failed\n");
            std::exit(EXIT_FAILURE);
        }
    }

    if (pidfile.size())
        write_pid(pidfile.c_str());

    umask(077);
    process_signals();

    /* This is tricky -- we *must* use a name that will not be in hosts,
     * otherwise, at least with eglibc, the resolve and NSS libraries will not
     * be properly loaded.  The '.invalid' label is RFC-guaranteed to never
     * be installed into the root zone, so we use that to avoid harassing
     * DNS servers at start.
     */
    (void) gethostbyname("fail.invalid");

    if (chroot_path.size())
        nk_set_chroot(chroot_path.c_str());
    if (nsocks_uid || nsocks_gid)
        nk_set_uidgid(nsocks_uid, nsocks_gid, NULL, 0);

    if (enforce_seccomp(nsocks_uid || nsocks_gid))
        fmt::print("seccomp filter cannot be installed\n");
}

int main(int ac, char *av[])
{
    process_options(ac, av);

    if (num_worker_threads > 1) {
        std::vector<std::thread> threads;
        for (std::size_t i = 0; i < num_worker_threads; ++i)
            threads.emplace_back([]() { io_service.run(); });
        for (std::size_t i = 0; i < threads.size(); ++i)
            threads[i].join();
    } else
        io_service.run();

    std::exit(EXIT_SUCCESS);
}

