/* nsocks.c - socks5 server
 *
 * (c) 2013-2014 Nicholas J. Kain <njkain at gmail dot com>
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
#include <fstream>
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
#include <getopt.h>

#include <boost/asio.hpp>
#include <boost/program_options.hpp>

#include "make_unique.hpp"
#include "socksclient.hpp"

extern "C" {
#include "defines.h"
#include "log.h"
#include "chroot.h"
#include "pidfile.h"
#include "seccomp-bpf.h"
}

namespace po = boost::program_options;

boost::asio::io_service io_service;
static std::vector<std::unique_ptr<ClientListener>> listeners;
static int nsocks_uid, nsocks_gid;
static std::size_t num_worker_threads = 1;

static boost::asio::signal_set asio_signal_set(io_service);

static void process_signals()
{
    asio_signal_set.add(SIGINT);
    asio_signal_set.add(SIGTERM);
    asio_signal_set.async_wait(
        [](const boost::system::error_code &, int signum) {
            io_service.stop();
        });
}

static void fix_signals(void) {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGPIPE);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);
    sigaddset(&mask, SIGTSTP);
    sigaddset(&mask, SIGTTIN);
    sigaddset(&mask, SIGHUP);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
        suicide("sigprocmask failed");
}

#if 0
// XXX: This is not updated for nsocks.
static int enforce_seccomp(void)
{
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE,
        EXAMINE_SYSCALL,
        ALLOW_SYSCALL(sendmsg),
        ALLOW_SYSCALL(recvmsg),
        ALLOW_SYSCALL(read),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(sendto), // used for glibc syslog routines
        ALLOW_SYSCALL(epoll_wait),
        ALLOW_SYSCALL(epoll_ctl),
        ALLOW_SYSCALL(getpeername),
        ALLOW_SYSCALL(getsockname),
        ALLOW_SYSCALL(stat),
        ALLOW_SYSCALL(open),
        ALLOW_SYSCALL(close),
        ALLOW_SYSCALL(connect),
        ALLOW_SYSCALL(socket),
        ALLOW_SYSCALL(accept),
        ALLOW_SYSCALL(ioctl),
        ALLOW_SYSCALL(rt_sigreturn),
#ifdef __NR_sigreturn
        ALLOW_SYSCALL(sigreturn),
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

        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(exit),
        KILL_PROCESS,
    };
    struct sock_fprog prog;
    memset(&prog, 0, sizeof prog);
    prog.len = (unsigned short)(sizeof filter / sizeof filter[0]);
    prog.filter = filter;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return -1;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
        return -1;
    return 0;
}
#endif

static po::variables_map fetch_options(int ac, char *av[])
{
    std::string config_file;

    po::options_description cli_opts("Command-line-exclusive options");
    cli_opts.add_options()
        ("config,c", po::value<std::string>(&config_file),
         "path to configuration file")
        ("detach,d", "run as a background daemon (default)")
        ("nodetach,n", "stay attached to TTY")
        ("verbose,V", "print details of normal operation")
        ("help,h", "print help message")
        ("version,v", "print version information")
        ;

    po::options_description gopts("Options");
    gopts.add_options()
        ("pidfile,f", po::value<std::string>(),
         "path to process id file")
        ("chroot,C", po::value<std::string>(),
         "path in which nsocks should chroot itself")
        ("address,a", po::value<std::vector<std::string> >()->composing(),
         "'address[:port]' on which to listen (default all local)")
        ("user,u", po::value<std::string>(),
         "user name that nsocks should run as")
        ("group,g", po::value<std::string>(),
         "group name that nsocks should run as")
        ("threads,T", po::value<std::size_t>()->default_value(1),
         "number of worker threads that nsocks should use")
        ("send-chunksize", po::value<std::size_t>()->default_value(768),
         "bytes of ram used as buffer when sending data for a connection")
        ("receive-chunksize", po::value<std::size_t>()->default_value(1536),
         "bytes of ram used as buffer when receiving data for a connection")
        ("max-buffer-ms", po::value<unsigned int>()->default_value(250),
         "max milliseconds that data can stay buffered in splice pipeline")
        ("listenqueue,L", po::value<std::size_t>(),
         "maximum number of pending client connections")
        ("disable-ipv6", "disable proxy to ipv6 destinations")
        ("prefer-ipv4", "prefer ipv4 addresses when looking up hostnames")
        ("deny-dst", po::value<std::vector<std::string>>()->composing(),
         "denies connections to the specified 'host/netmask'")
        ("bind-allow-src", po::value<std::vector<std::string>>()->composing(),
         "allows bind requests from the specified 'host/netmask'")
        ("handshake-gc-interval", po::value<std::size_t>()->default_value(5),
         "seconds between gc sweeps of unfinished handshakes")
        ("bindlisten-gc-interval", po::value<std::size_t>()->default_value(180),
         "seconds between gc sweeps of listening bind sockets")
        ("bind-lowest-port", po::value<uint16_t>(),
         "lowest port that will be assigned to bind requests")
        ("bind-highest-port", po::value<uint16_t>(),
         "highest port that will be assigned to bind requests")
        ("disable-bind", "ignore client bind requests")
        ("udp-allow-src", po::value<std::vector<std::string>>()->composing(),
         "allows udp associate requests from the specified 'host/netmask'")
        ("disable-udp", "ignore client udp associate requests")
        ;

    po::options_description cmdline_options;
    cmdline_options.add(cli_opts).add(gopts);
    po::options_description cfgfile_options;
    cfgfile_options.add(gopts);

    po::positional_options_description p;
    p.add("address", -1);
    po::variables_map vm;
    try {
        po::store(po::command_line_parser(ac, av).
                  options(cmdline_options).positional(p).run(), vm);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
    po::notify(vm);

    if (config_file.size()) {
        std::ifstream ifs(config_file.c_str());
        if (!ifs) {
            std::cerr << "Could not open config file: " << config_file << "\n";
            std::exit(EXIT_FAILURE);
        }
        po::store(po::parse_config_file(ifs, cfgfile_options), vm);
        po::notify(vm);
    }

    if (vm.count("help")) {
        std::cout << "nsocks " << NSOCKS_VERSION << ", socks5 server.\n"
                  << "Copyright (c) 2013-2014 Nicholas J. Kain\n"
                  << av[0] << " [options] addresses...\n"
                  << cmdline_options << std::endl;
        std::exit(EXIT_FAILURE);
    }
    if (vm.count("version")) {
        std::cout << "nsocks " << NSOCKS_VERSION << ", socks5 server.\n" <<
            "Copyright (c) 2013-2014 Nicholas J. Kain\n"
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
            "POSSIBILITY OF SUCH DAMAGE.\n";
        std::exit(EXIT_FAILURE);
    }
    return vm;
}

static void hostmask_vec_add(const std::vector<std::string> &svec,
                             std::vector<std::pair<boost::asio::ip::address,
                                                   unsigned int>> &dvec,
                             const char sname[])
{
    for (const auto &i: svec) {
        std::string addr(i);
        int mask = -1;
        auto loc = addr.rfind("/");
        if (loc != std::string::npos) {
            auto mstr = addr.substr(loc + 1);
            try {
                mask = boost::lexical_cast<int>(mstr);
            } catch (const boost::bad_lexical_cast&) {
                std::cerr << "bad mask in " << sname << ": '" << addr << "'\n";
                std::exit(EXIT_FAILURE);
            }
            addr.erase(loc);
        }
        try {
            auto addy = boost::asio::ip::address::from_string(addr);
            if (mask < 0)
                mask = addy.is_v4() ? 32 : 128;
            if (addy.is_v4())
                mask = std::min(mask, 32);
            else
                mask = std::min(mask, 128);
            dvec.emplace_back(addy, mask);
        } catch (const boost::system::error_code&) {
            std::cerr << "bad address in " << sname << ": '" << addr << "'\n";
            std::exit(EXIT_FAILURE);
        }
    }
}

static void process_options(int ac, char *av[])
{
    std::vector<std::string> addrlist, denydstlist, bindallowsrclist,
        udpallowsrclist;
    std::string pidfile, chroot_path;

    auto vm(fetch_options(ac, av));

    auto hs_secs = vm["handshake-gc-interval"].as<std::size_t>();
    auto bindlisten_secs = vm["bindlisten-gc-interval"].as<std::size_t>();

    if (vm.count("detach"))
        gflags_detach = 1;
    if (vm.count("nodetach"))
        gflags_detach = 0;
    if (vm.count("verbose"))
        g_verbose_logs = true;
    if (vm.count("pidfile"))
        pidfile = vm["pidfile"].as<std::string>();
    if (vm.count("chroot"))
        chroot_path = vm["chroot"].as<std::string>();
    if (vm.count("address"))
        addrlist = vm["address"].as<std::vector<std::string> >();
    if (vm.count("deny-dst"))
        denydstlist = vm["deny-dst"].as<std::vector<std::string>>();
    if (vm.count("bind-allow-src"))
        bindallowsrclist = vm["bind-allow-src"].as<std::vector<std::string>>();
    if (vm.count("udp-allow-src"))
        udpallowsrclist = vm["udp-allow-src"].as<std::vector<std::string>>();
    if (vm.count("user")) {
        auto t = vm["user"].as<std::string>();
        try {
            nsocks_uid = boost::lexical_cast<unsigned int>(t);
        } catch (const boost::bad_lexical_cast&) {
            auto pws = getpwnam(t.c_str());
            if (pws) {
                nsocks_uid = (int)pws->pw_uid;
                if (!nsocks_gid)
                    nsocks_gid = (int)pws->pw_gid;
            } else suicide("invalid uid specified");
        }
    }
    if (vm.count("group")) {
        auto t = vm["group"].as<std::string>();
        try {
            nsocks_gid = boost::lexical_cast<unsigned int>(t);
        } catch (const boost::bad_lexical_cast&) {
            auto grp = getgrnam(t.c_str());
            if (grp) {
                nsocks_gid = (int)grp->gr_gid;
            } else suicide("invalid gid specified");
        }
    }
    if (vm.count("threads"))
        num_worker_threads = vm["threads"].as<std::size_t>();
    if (vm.count("send-chunksize")) {
        auto t = vm["send-chunksize"].as<std::size_t>();
        SocksClient::set_send_buffer_chunk_size(t);
    }
    if (vm.count("receive-chunksize")) {
        auto t = vm["receive-chunksize"].as<std::size_t>();
        SocksClient::set_receive_buffer_chunk_size(t);
    }
    if (vm.count("max-buffer-ms")) {
        auto t = vm["max-buffer-ms"].as<unsigned int>();
        set_max_buffer_ms(t);
    }
    if (vm.count("listenqueue")) {
        auto t = vm["listenqueue"].as<std::size_t>();
        set_listen_queuelen(t);
    }
    if (vm.count("disable-ipv6"))
        g_disable_ipv6 = true;
    if (vm.count("prefer-ipv4"))
        g_prefer_ipv4 = true;
    if (vm.count("disable-bind"))
        g_disable_bind = true;
    if (vm.count("disable-udp"))
        g_disable_udp = true;

    uint16_t bind_lowest_port(0), bind_highest_port(0);
    if (vm.count("bind-lowest-port"))
        bind_lowest_port = vm["bind-lowest-port"].as<uint16_t>();
    if (vm.count("bind-highest-port"))
        bind_highest_port = vm["bind-lowest-port"].as<uint16_t>();

    init_conntrackers(hs_secs, bindlisten_secs);
    init_bind_port_assigner(bind_lowest_port, bind_highest_port);

    if (!addrlist.size()) {
        auto ep = boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v6(), 1080);
        listeners.emplace_back(nk::make_unique<ClientListener>(ep));
    } else
        for (const auto &i: addrlist) {
            std::string addr(i);
            int port = 1080;
            auto loc = addr.rfind(":");
            if (loc != std::string::npos) {
                auto pstr = addr.substr(loc + 1);
                try {
                    port = boost::lexical_cast<unsigned short>(pstr);
                } catch (const boost::bad_lexical_cast&) {
                    std::cout << "bad port in address '" << addr
                              << "', defaulting to 1080" << std::endl;
                }
                addr.erase(loc);
            }
            try {
                auto addy = boost::asio::ip::address::from_string(addr);
                auto ep = boost::asio::ip::tcp::endpoint(addy, port);
                listeners.emplace_back(nk::make_unique<ClientListener>(ep));
            } catch (const boost::system::error_code&) {
                std::cout << "bad address: " << addr << std::endl;
            }
        }

    hostmask_vec_add(denydstlist, g_dst_deny_masks, "deny-dst");
    hostmask_vec_add(bindallowsrclist, g_client_bind_allow_masks,
                     "bind-allow-src");
    hostmask_vec_add(udpallowsrclist, g_client_udp_allow_masks,
                     "udp-allow-src");

    if (gflags_detach)
        if (daemon(0,0))
            suicide("detaching fork failed");

    if (pidfile.size() && file_exists(pidfile.c_str(), "w"))
        write_pid(pidfile.c_str());

    umask(077);
    fix_signals();

    // bool v4only = false;
    // nlink = std::unique_ptr<Netlink>(new Netlink(v4only));
    // if (!nlink->open(NETLINK_INET_DIAG)) {
    //     std::cerr << "failed to create netlink socket" << std::endl;
    //     exit(EXIT_FAILURE);
    // }

    if (chroot_path.size()) {
        if (getuid())
            suicide("root required for chroot\n");
        if (chdir(chroot_path.c_str()))
            suicide("failed to chdir(%s)\n", chroot_path.c_str());
        if (chroot(chroot_path.c_str()))
            suicide("failed to chroot(%s)\n", chroot_path.c_str());
    }
    if (nsocks_uid != 0 || nsocks_gid != 0)
        drop_root(nsocks_uid, nsocks_gid);

    // if (enforce_seccomp())
    //     log_line("seccomp filter cannot be installed");

}

static void set_iostream_async()
{
    // Don't sync with C stdio, and don't sync cin and cout since we're not
    // interactive and are just streaming messages.
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(nullptr);
    std::cout.tie(nullptr);
}

int main(int ac, char *av[])
{
    set_iostream_async();

    gflags_log_name = const_cast<char *>("nsocks");

    process_options(ac, av);
    process_signals();

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

