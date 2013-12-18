/* nsocks.c - socks5 server
 *
 * (c) 2013 Nicholas J. Kain <njkain at gmail dot com>
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

#include "socksclient.hpp"

extern "C" {
#include "defines.h"
#include "malloc.h"
#include "log.h"
#include "chroot.h"
#include "pidfile.h"
#include "strl.h"
#include "exec.h"
#include "network.h"
#include "strlist.h"
#include "seccomp-bpf.h"
}

namespace po = boost::program_options;

boost::asio::io_service io_service;
bool gChrooted = false;

static void sighandler(int sig)
{
    exit(EXIT_SUCCESS);
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

    struct sigaction sa;
    memset(&sa, 0, sizeof (struct sigaction));
    sa.sa_handler = sighandler;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGINT);
    sigaddset(&sa.sa_mask, SIGTERM);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
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

int main(int ac, char *av[]) {
    int uid = 0, gid = 0;
    //bool v4only = false;
    std::string pidfile, chroot_path, config_file;
    std::vector<std::unique_ptr<ClientListener>> listeners;
    std::vector<std::string> addrlist;

    gflags_log_name = const_cast<char *>("nsocks");

    po::options_description cli_opts("Command-line-exclusive options");
    cli_opts.add_options()
        ("config,c", po::value<std::string>(&config_file),
         "path to configuration file")
        ("detach,d", "run as a background daemon (default)")
        ("nodetach,n", "stay attached to TTY")
        ("quiet,q", "don't print to std(out|err) or log")
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
#ifndef USE_SPLICE
        ("chunksize,S", po::value<std::size_t>(),
         "size of memory buffer used to proxy data between sockets")
#endif
        ("listenqueue,L", po::value<std::size_t>(),
         "maximum number of pending client connections")
        ("disable-ipv6", "disable proxy to ipv6 destinations")
        ("prefer-ipv4", "prefer ipv4 addresses when looking up hostnames")
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
            return 0;
        }
        po::store(po::parse_config_file(ifs, cfgfile_options), vm);
        po::notify(vm);
    }

    if (vm.count("help")) {
        std::cout << "nsocks " << NSOCKS_VERSION << ", socks5 server.\n"
                  << "Copyright (c) 2013 Nicholas J. Kain\n"
                  << av[0] << " [options] addresses...\n"
                  << gopts << std::endl;
        return 1;
    }
    if (vm.count("version")) {
        std::cout << "nsocks " << NSOCKS_VERSION << ", socks5 server.\n" <<
            "Copyright (c) 2013 Nicholas J. Kain\n"
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
        return 1;
    }
    if (vm.count("detach"))
        gflags_detach = 1;
    if (vm.count("nodetach"))
        gflags_detach = 0;
    if (vm.count("quiet"))
        gflags_quiet = 1;
    if (vm.count("pidfile"))
        pidfile = vm["pidfile"].as<std::string>();
    if (vm.count("chroot"))
        chroot_path = vm["chroot"].as<std::string>();
    if (vm.count("address"))
        addrlist = vm["address"].as<std::vector<std::string> >();
    if (vm.count("user")) {
        auto t = vm["user"].as<std::string>();
        try {
            uid = boost::lexical_cast<unsigned int>(t);
        } catch (const boost::bad_lexical_cast&) {
            auto pws = getpwnam(t.c_str());
            if (pws) {
                uid = (int)pws->pw_uid;
                if (!gid)
                    gid = (int)pws->pw_gid;
            } else suicide("invalid uid specified");
        }
    }
    if (vm.count("group")) {
        auto t = vm["group"].as<std::string>();
        try {
            gid = boost::lexical_cast<unsigned int>(t);
        } catch (const boost::bad_lexical_cast&) {
            auto grp = getgrnam(t.c_str());
            if (grp) {
                gid = (int)grp->gr_gid;
            } else suicide("invalid gid specified");
        }
    }
#ifndef USE_SPLICE
    if (vm.count("chunksize")) {
        auto t = vm["chunksize"].as<std::size_t>();
        set_buffer_chunk_size(t);
    }
#endif
    if (vm.count("listenqueue")) {
        auto t = vm["listenqueue"].as<std::size_t>();
        set_listen_queuelen(t);
    }
    if (vm.count("disable-ipv6"))
        g_disable_ipv6 = true;
    if (vm.count("prefer-ipv4"))
        g_prefer_ipv4 = true;

    if (gflags_detach)
        if (daemon(0,0))
            suicide("detaching fork failed");

    if (pidfile.size() && file_exists(pidfile.c_str(), "w"))
        write_pid(pidfile.c_str());

    umask(077);
    fix_signals();
    ncm_fix_env(uid, 0);

    init_conntracker_hs();

    if (!addrlist.size()) {
        auto ep = boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v6(), 1080);
        listeners.emplace_back(std::unique_ptr<ClientListener>(
                                   new ClientListener(ep)));
    } else
        for (auto i = addrlist.cbegin(); i != addrlist.cend(); ++i) {
            std::string addr = *i;
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
                listeners.emplace_back(std::unique_ptr<ClientListener>(
                                            new ClientListener(ep)));
            } catch (const boost::system::error_code&) {
                std::cout << "bad address: " << addr << std::endl;
            }
        }
    addrlist.clear();

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
        gChrooted = true;
        chroot_path.clear();
    }
    if (uid != 0 || gid != 0)
        drop_root(uid, gid);

    /* Cover our tracks... */
    pidfile.clear();

    // if (enforce_seccomp())
    //     log_line("seccomp filter cannot be installed");

    io_service.run();

    exit(EXIT_SUCCESS);
}

