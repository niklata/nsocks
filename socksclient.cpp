/* socksclient.cpp - socks client request handling
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

#define SPLICE_CACHE_SIZE 20

#include <forward_list>
#include <vector>
#include <mutex>

#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include <boost/lexical_cast.hpp>
#include <boost/dynamic_bitset.hpp>

#include <random>
#include "xorshift.hpp"

#ifdef HAS_64BIT
#include <boost/lockfree/stack.hpp>
#endif

#include "socksclient.hpp"
#include "socks_tracker.hpp"
#include "asio_addrcmp.hpp"

#define MAX_BIND_TRIES 10
#define MAX_PIPE_FLUSH_TRIES 10
#define UDP_BUFSIZE 1536

namespace ba = boost::asio;

extern ba::io_service io_service;
extern bool gParanoid;
extern bool gChrooted;

bool g_verbose_logs = false;
bool g_prefer_ipv4 = false;
bool g_disable_ipv6 = false;
bool g_disable_bind = false;
bool g_disable_udp = false;

static std::size_t listen_queuelen = 256;
void set_listen_queuelen(std::size_t len) { listen_queuelen = len; }

std::size_t SocksTCP::send_buffer_chunk_size = 1024;
std::size_t SocksTCP::receive_buffer_chunk_size = 2048;
std::size_t SocksTCP::send_minsplice_size = 768;
std::size_t SocksTCP::receive_minsplice_size = 1536;
int SocksTCP::splice_pipe_size = 1024 * 256;
void SocksTCP::set_send_buffer_chunk_size(std::size_t size) {
    send_buffer_chunk_size = size;
    send_minsplice_size = size / 4 * 3;
}
void SocksTCP::set_receive_buffer_chunk_size(std::size_t size) {
    receive_buffer_chunk_size = size;
    receive_minsplice_size = size / 4 * 3;
}
void SocksTCP::set_splice_pipe_size(int size) {
    splice_pipe_size = std::max(PIPE_BUF, size);
}

static std::random_device g_random_secure;
static nk::rng::xorshift64m g_random_prng(0);

static int resolver_prunetimer_sec = 60;

static std::mutex tcp_resolver_lock;
static std::unique_ptr<boost::asio::ip::tcp::resolver> tcp_resolver;
static std::unique_ptr<boost::asio::deadline_timer> tcp_resolver_timer;
static std::size_t tcp_resolver_timer_seq;

static std::mutex udp_resolver_lock;
static std::unique_ptr<boost::asio::ip::udp::resolver> udp_resolver;
static std::unique_ptr<boost::asio::deadline_timer> udp_resolver_timer;
static std::size_t udp_resolver_timer_seq;

static std::mutex print_lock;
template <typename... Args>
static void logfmt(Args&&... args)
{
    std::lock_guard<std::mutex> wl(print_lock);
    fmt::print(std::forward<Args>(args)...);
    std::fflush(stdout);
}

#include "bind_port_assigner.hpp"

static void print_trackers_logentry(const std::string &host, uint16_t port);

static std::unique_ptr<ephTrackerVec<SocksInit>> conntracker_hs;
static std::unique_ptr<ephTrackerList<SocksInit>> conntracker_bindlisten;

// The only purpose of this tracker is for find_by_addr_port for BIND.
static connTracker<SocksTCP> conntracker_tcp;

#ifdef USE_SPLICE
#ifdef HAS_64BIT
static std::atomic<std::size_t> num_free_pipes;
static boost::lockfree::stack
<uint64_t, boost::lockfree::capacity<SPLICE_CACHE_SIZE>> free_pipes;
#else
static std::mutex free_pipe_lock;
// XXX: Allow runtime customization.
static std::size_t max_free_pipes = SPLICE_CACHE_SIZE;
static std::vector<std::pair<int, int>> free_pipes;
#endif
#endif

void init_prng()
{
    std::array<uint32_t, nk::rng::xorshift64m::state_size> seed_data;
    std::generate_n(seed_data.data(), seed_data.size(),
                    std::ref(g_random_secure));
    std::seed_seq seed_seq(std::begin(seed_data), std::end(seed_data));
    g_random_prng.seed(seed_seq);
}

void init_conntrackers(std::size_t hs_secs, std::size_t bindlisten_secs)
{
    conntracker_hs = std::make_unique<ephTrackerVec<SocksInit>>
        (io_service, hs_secs);
    conntracker_bindlisten = std::make_unique<ephTrackerList<SocksInit>>
        (io_service, bindlisten_secs);
}

#ifdef USE_SPLICE
void pipe_close_raw(std::size_t p_len,
                    ba::posix::stream_descriptor &sa,
                    ba::posix::stream_descriptor &sb)
{
    boost::system::error_code ec;
    auto sao = sa.is_open();
    auto sbo = sb.is_open();
    if (p_len == 0 && sao && sbo) {
#ifdef HAS_64BIT
        auto s0 = sa.release();
        auto s1 = sb.release();
        uint64_t sp = static_cast<uint64_t>(s0);
        sp |= static_cast<uint64_t>(s1) << 32U;
        if (free_pipes.bounded_push(sp)) {
            if (g_verbose_logs) {
                ++num_free_pipes;
                logfmt("cached a pipe (total: {})\n", num_free_pipes);
            }
        } else {
            close(s0);
            close(s1);
        }
#else
        std::pair<int, int> fp;
        fp.first = sa.release();
        fp.second = sb.release();
        std::lock_guard<std::mutex> wl(free_pipe_lock);
        if (free_pipes.size() < max_free_pipes) {
            free_pipes.push_back(std::move(fp));
            if (g_verbose_logs)
                logfmt("cached a pipe (total: {})\n",
                       free_pipes.size());
        } else {
            close(fp.first);
            close(fp.second);
        }
#endif
        return;
    }
    if (sao)
        sa.close(ec);
    if (sbo)
        sb.close(ec);
    p_len = 0;
}
#endif

static inline void cancel_paired_sockets(boost::asio::ip::tcp::socket &a,
                                         boost::asio::ip::tcp::socket &b)
{
    boost::system::error_code ec;
    auto ao = a.is_open();
    auto bo = b.is_open();
    if (ao)
        a.cancel(ec);
    if (bo)
        b.cancel(ec);
}

static inline void close_paired_sockets(boost::asio::ip::tcp::socket &a,
                                        boost::asio::ip::tcp::socket &b)
{
    boost::system::error_code ec;
    auto ao = a.is_open();
    auto bo = b.is_open();
    if (ao)
        a.cancel(ec);
    if (bo)
        b.cancel(ec);
    if (ao)
        a.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    if (bo)
        b.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    if (ao)
        a.close(ec);
    if (bo)
        b.close(ec);
}

std::vector<std::pair<boost::asio::ip::address, unsigned int>>
g_dst_deny_masks;
std::vector<std::pair<boost::asio::ip::address, unsigned int>>
g_client_bind_allow_masks;
std::vector<std::pair<boost::asio::ip::address, unsigned int>>
g_client_udp_allow_masks;

static std::atomic<std::size_t> socks_alive_count;
static std::atomic<std::size_t> udp_alive_count;

static void print_trackers_logentry(const std::string &host, uint16_t port)
{
    logfmt("Connection to {}:{} DESTRUCTED (total: HS{}, BL{} || T{}, U{} / {})\n",
           host, port,
           conntracker_hs? conntracker_hs->size() : 0,
           conntracker_bindlisten? conntracker_bindlisten->size() : 0,
           conntracker_tcp.size(), udp_alive_count,
           socks_alive_count);
}

static std::unique_ptr<BindPortAssigner> BPA;
static std::unique_ptr<BindPortAssigner> UPA;

void init_bind_port_assigner(uint16_t lowport, uint16_t highport)
{
    if (g_disable_bind)
        return;
    if (lowport < 1024 || highport < 1024) {
        logfmt("For BIND requests to be satisfied, bind-lowest-port and bind-highest-port\n"
               "must both be set to non-equal values >= 1024.  BIND requests will be\n"
               "disabled until this configuration problem is corrected.\n");
        g_disable_bind = true;
        return;
    }
    if (lowport > highport)
        std::swap(lowport, highport);
    BPA = std::make_unique<BindPortAssigner>(lowport, highport);
}

void init_udp_associate_assigner(uint16_t lowport, uint16_t highport)
{
    if (g_disable_udp)
        return;
    if (lowport < 1024 || highport < 1024) {
        logfmt("For UDP ASSOCIATE requests to be satisfied, udp-lowest-port and\n"
               "udp-highest-port must both be set to non-equal values >= 1024.  UDP\n"
               "ASSOCIATE requests will be disabled until this configuration problem\n"
               "is corrected.\n");
        g_disable_udp = true;
        return;
    }
    if (lowport > highport)
        std::swap(lowport, highport);
    UPA = std::make_unique<BindPortAssigner>(lowport, highport);
}

static inline size_t send_reply_code_v5(std::array<char, 24> &arr,
                                        SocksInit::ReplyCode replycode)
{
    arr[0] = 0x05;
    arr[1] = replycode;
    arr[2] = 0;
    return 3;
}

static inline size_t send_reply_binds_v5(std::array<char, 24> &arr,
                                         std::size_t asiz,
                                         ba::ip::tcp::endpoint ep)
{
    auto bnd_addr = ep.address();
    if (bnd_addr.is_v4()) {
        auto v4b = bnd_addr.to_v4().to_bytes();
        arr[asiz++] = 0x01;
        for (auto &i: v4b)
            arr[asiz++] = i;
    } else {
        auto v6b = bnd_addr.to_v6().to_bytes();
        arr[asiz++] = 0x04;
        for (auto &i: v6b)
            arr[asiz++] = i;
    }
    union {
        uint16_t p;
        char b[2];
    } portu;
    portu.p = htons(ep.port());
    arr[asiz++] = portu.b[0];
    arr[asiz++] = portu.b[1];
    return asiz;
}

static inline size_t send_reply_code_v4(std::array<char, 24> &arr,
                                        SocksInit::ReplyCode replycode)
{
    arr[0] = 0;
    uint8_t rc;
    switch (replycode) {
        case SocksInit::RplSuccess: rc = 90; break;
        default:
        case SocksInit::RplFail: rc = 91; break;
        case SocksInit::RplDeny: rc = 91; break;
        case SocksInit::RplNetUnreach: rc = 91; break;
        case SocksInit::RplHostUnreach: rc = 91; break;
        case SocksInit::RplConnRefused: rc = 91; break;
        case SocksInit::RplTTLExpired: rc = 91; break;
        case SocksInit::RplCmdNotSupp: rc = 91; break;
        case SocksInit::RplAddrNotSupp: rc = 91; break;
        case SocksInit::RplIdentUnreach: rc = 92; break;
        case SocksInit::RplIdentWrong: rc = 93; break;
    }
    arr[1] = rc;
    return 2;
}

static inline size_t send_reply_binds_v4(std::array<char, 24> &arr,
                                         std::size_t asiz,
                                         ba::ip::tcp::endpoint ep)
{
    union {
        uint16_t p;
        char b[2];
    } portu;
    portu.p = htons(ep.port());
    arr[asiz++] = portu.b[0];
    arr[asiz++] = portu.b[1];

    auto bnd_addr = ep.address();
    assert(bnd_addr.is_v4());
    auto v4b = bnd_addr.to_v4().to_bytes();
    for (auto &i: v4b)
        arr[asiz++] = i;
    return asiz;
}

static const char * const replyCodeString[] = {
    "Success",
    "Fail",
    "Deny",
    "NetUnreach",
    "HostUnreach",
    "ConnRefused",
    "TTLExpired",
    "CmdNotSupp",
    "AddrNotSupp",
    "IdentUnreach",
    "IdentWrong",
};

SocksInit::SocksInit(ba::io_service &io_service,
                     ba::ip::tcp::socket client_socket)
        : tracked_(true), strand_(io_service),
          client_socket_(std::move(client_socket)),
          remote_socket_(io_service), pstate_(ParsedState::Parsed_None),
          ibSiz_(0), poff_(0), ptmp_(0), is_socks_v4_(false),
          bind_listen_(false), auth_none_(false), auth_gssapi_(false),
          auth_unpw_(false)
{
    if (g_verbose_logs)
        ++socks_alive_count;
    client_socket_.non_blocking(true);
    client_socket_.set_option(boost::asio::ip::tcp::no_delay(true));
    client_socket_.set_option(boost::asio::socket_base::keep_alive(true));
#ifdef TCP_QUICKACK
    const boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_QUICKACK> quickack(true);
    client_socket_.set_option(quickack);
#endif
}

SocksInit::~SocksInit()
{
    untrack();
    if (g_verbose_logs) {
        --socks_alive_count;
        print_trackers_logentry(dst_hostname_.size() ? dst_hostname_
                                  : dst_address_.to_string(),
                                  dst_port_);
    }
}

SocksInit::BoundSocket::BoundSocket(boost::asio::io_service &io_service,
                                    boost::asio::ip::tcp::endpoint lep)
        : acceptor_(io_service), local_endpoint_(lep)
{
    boost::system::error_code ec;
    acceptor_.open(lep.protocol(), ec);
    if (ec)
        throw std::runtime_error("open failed");
    acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
    if (ec)
        throw std::runtime_error("set_option/reuse_address failed");
    acceptor_.non_blocking(true, ec);
    if (ec)
        throw std::runtime_error("non_blocking failed");
    acceptor_.bind(lep, ec);
    if (ec)
        throw std::domain_error("bind failed");
    acceptor_.listen(1, ec);
    if (ec)
        throw std::runtime_error("listen failed");
}

SocksInit::BoundSocket::~BoundSocket()
{
    assert(BPA);
    BPA->release_port(local_endpoint_.port());
}

void SocksInit::untrack()
{
    if (!bind_listen_)
        return;
    bool cxr(true);
    if (tracked_.compare_exchange_strong(cxr, false)) {
        boost::system::error_code ec;
        if (bound_)
            bound_->acceptor_.cancel(ec);
        conntracker_bindlisten->erase(get_tracker_iterator(),
                                      get_tracker_idx());
    }
}

void SocksInit::cancel_sockets()
{
    cancel_paired_sockets(remote_socket_, client_socket_);
}

void SocksInit::terminate()
{
    close_paired_sockets(remote_socket_, client_socket_);
    untrack();
}

void SocksInit::read_greet()
{
    auto sfd = shared_from_this();
    client_socket_.async_read_some
        (ba::buffer(sockbuf_.data() + ibSiz_, sockbuf_.size() - ibSiz_),
         strand_.wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             size_t consumed;
             boost::optional<SocksInit::ReplyCode> rc;
             if (ec) goto ec_err;
             if (!bytes_xferred)
                 return;
             ibSiz_ += bytes_xferred;
             if ((rc = parse_greet(consumed))) {
                 if (*rc != RplSuccess)
                     send_reply(*rc);
                 return;
             } else {
                 ibSiz_ -= consumed;
                 poff_ -= consumed;
                 memmove(sockbuf_.data(), sockbuf_.data() + consumed, ibSiz_);
             }
             read_greet();
             return;
ec_err:
             if (ec != ba::error::eof && ec != ba::error::operation_aborted) {
                 logfmt("read_greet() error: {}\n",
                        boost::system::system_error(ec).what());
             }
             terminate();
         }));
}

// We don't support authentication.
static const char reply_greetz[2] = {'\x5','\x0'};

boost::optional<SocksInit::ReplyCode>
SocksInit::parse_greet(std::size_t &consumed)
{
    consumed = 0;
    switch (pstate_) {
    case Parsed_None: {
        if (ibSiz_ - poff_ < 1)
            return boost::optional<ReplyCode>();
        ++consumed;
        auto c = sockbuf_[poff_++];
        if (c == 0x05) {
            pstate_ = Parsed5G_Version;
        } else if (c == 0x04) {
            pstate_ = Parsed4G_Version;
            is_socks_v4_ = true;
            goto p4g_version;
        } else
            return RplFail;
    }
    case Parsed5G_Version: {
        if (ibSiz_ - poff_ < 1)
            return boost::optional<ReplyCode>();
        pstate_ = Parsed5G_NumAuth;
        ++consumed;
        ptmp_ = static_cast<uint8_t>(sockbuf_[poff_++]);
    }
    case Parsed5G_NumAuth: {
        size_t aendsiz = static_cast<size_t>(poff_)
                       + static_cast<size_t>(ptmp_);
        for (;poff_ < aendsiz && poff_ < ibSiz_; ++poff_,--ptmp_) {
            ++consumed;
            auto atype = static_cast<uint8_t>(sockbuf_[poff_]);
            if (atype == 0x0)
                auth_none_ = true;
            else if (atype == 0x1)
                auth_gssapi_ = true;
            else if (atype == 0x2)
                auth_unpw_ = true;
        }
        if (ptmp_ == 0) {
            pstate_ = Parsed5G_Auth;
            if (poff_ != ibSiz_) // Reject if there are excess bytes in buffer.
                return RplFail;
            if (!auth_none_)
                return RplFail;
        } else if (ptmp_ > 0) {
            return boost::optional<ReplyCode>();
        } else {
            return RplFail;
        }
    }
    case Parsed5G_Auth: {
        auto sfd = shared_from_this();
        ba::async_write(
            client_socket_, ba::buffer(reply_greetz, sizeof reply_greetz),
            strand_.wrap(
                [this, sfd](const boost::system::error_code &ec,
                            std::size_t bytes_xferred)
                {
                    if (ec) {
                        logfmt("failed writing reply_greetz: {}\n",
                               boost::system::system_error(ec).what());
                        terminate();
                    }
                }));
        pstate_ = Parsed5G_Replied;
        return boost::optional<ReplyCode>();
    }
p4g_version:
    case Parsed4G_Version: {
        if (ibSiz_ - poff_ < 1)
            return boost::optional<ReplyCode>();
        pstate_ = Parsed4G_Cmd;
        ++consumed;
        auto c = sockbuf_[poff_++];
        if (c == 0x1) {
            cmd_code_ = CmdTCPConnect;
        } else if (c == 0x2) {
            cmd_code_ = CmdTCPConnect;
        } else {
            return RplCmdNotSupp;
        }
    }
    case Parsed4G_Cmd: {
        if (ibSiz_ - poff_ < 2)
            return boost::optional<ReplyCode>();
        pstate_ = Parsed4G_DPort;
        consumed += 2;
        uint16_t tmp;
        memcpy(&tmp, sockbuf_.data() + poff_, 2);
        dst_port_ = ntohs(tmp);
        poff_ += 2;
    }
    case Parsed4G_DPort: {
        if (ibSiz_ - poff_ < 4)
            return boost::optional<ReplyCode>();
        pstate_ = Parsed4G_DAddr;
        consumed += 4;
        ba::ip::address_v4::bytes_type v4o;
        memcpy(v4o.data(), sockbuf_.data() + poff_, 4);
        dst_address_ = ba::ip::address_v4(v4o);
        poff_ += 4;
    }
    case Parsed4G_DAddr: {
        // Null-terminated userid.
        for (; poff_ < ibSiz_; ++poff_) {
            ++consumed;
            ++ptmp_;
            if (sockbuf_[poff_] == '\0') {
                ptmp_ = 0;
                pstate_ = Parsed_Finished;
                goto parsed_finished;
            }
            if (ptmp_ == UCHAR_MAX)
                return RplFail;
        }
        return boost::optional<ReplyCode>();
    }
    case Parsed5G_Replied: {
        if (ibSiz_ - poff_ < 1)
            return boost::optional<ReplyCode>();
        pstate_ = Parsed5CR_Version;
        ++consumed;
        auto c = sockbuf_[poff_++];
        if (c != 0x5)
            return RplFail;
    }
    case Parsed5CR_Version: {
        if (ibSiz_ - poff_ < 1)
            return boost::optional<ReplyCode>();
        pstate_ = Parsed5CR_Cmd;
        ++consumed;
        auto c = sockbuf_[poff_++];
        if (c == 0x1) {
            cmd_code_ = CmdTCPConnect;
        } else if (c == 0x2) {
            cmd_code_ = CmdTCPBind;
        } else if (c == 0x3) {
            cmd_code_ = CmdUDP;
        } else
            return RplCmdNotSupp;
    }
    case Parsed5CR_Cmd: {
        if (ibSiz_ - poff_ < 1)
            return boost::optional<ReplyCode>();
        pstate_ = Parsed5CR_Resv;
        ++consumed;
        auto c = sockbuf_[poff_++];
        if (c != 0x0)
            return RplFail;
    }
    case Parsed5CR_Resv: {
        if (ibSiz_ - poff_ < 1)
            return boost::optional<ReplyCode>();
        pstate_ = Parsed5CR_AddrType;
        ++consumed;
        auto c = sockbuf_[poff_++];
        if (c == 0x1) {
            addr_type_ = AddrIPv4;
        } else if (c == 0x4) {
            addr_type_ = AddrIPv6;
        } else if (c == 0x3) {
            addr_type_ = AddrDNS;
        } else
            return RplAddrNotSupp;
    }
    case Parsed5CR_AddrType: {
        if (addr_type_ == AddrIPv4) {
            if (ibSiz_ - poff_ < 4)
                return boost::optional<ReplyCode>();
            pstate_ = Parsed5CR_DAddr;
            consumed += 4;
            ba::ip::address_v4::bytes_type v4o;
            memcpy(v4o.data(), sockbuf_.data() + poff_, 4);
            dst_address_ = ba::ip::address_v4(v4o);
            poff_ += 4;
        } else if (addr_type_ == AddrIPv6) {
            if (ibSiz_ - poff_ < 16)
                return boost::optional<ReplyCode>();
            pstate_ = Parsed5CR_DAddr;
            consumed += 16;
            ba::ip::address_v6::bytes_type v6o;
            memcpy(v6o.data(), sockbuf_.data() + poff_, 16);
            dst_address_ = ba::ip::address_v6(v6o);
            poff_ += 16;
            if (g_disable_ipv6)
                return RplAddrNotSupp;
        } else if (addr_type_ == AddrDNS) {
            if (ibSiz_ - poff_ < 1)
                return boost::optional<ReplyCode>();
            pstate_ = Parsed5CR_DNSLen;
            consumed++;
            ptmp_ = static_cast<uint8_t>(sockbuf_[poff_++]);
            if (ptmp_ == 0)
                return RplAddrNotSupp;
            dst_hostname_.reserve(ptmp_);
            goto parsed5cr_dnslen;
        } else {
            uint8_t atype = addr_type_;
            logfmt("parse_greet(): unknown address type: {}\n", atype);
            return RplAddrNotSupp;
        }
    }
parsed5cr_daddr:
    case Parsed5CR_DAddr: {
        if (ibSiz_ - poff_ < 2)
            return boost::optional<ReplyCode>();
        pstate_ = Parsed_Finished;
        consumed += 2;
        uint16_t tmp;
        memcpy(&tmp, sockbuf_.data() + poff_, 2);
        dst_port_ = ntohs(tmp);
        poff_ += 2;
    }
parsed_finished:
    case Parsed_Finished: {
        ibSiz_ = 0;
        poff_ = 0;
        dispatch_connrq();
        return RplSuccess;
    }
parsed5cr_dnslen:
    case Parsed5CR_DNSLen: {
        uint8_t csiz = std::min(static_cast<uint8_t>(ibSiz_ - poff_), ptmp_);
        if (csiz > 0) {
            // Guard against overflow.  Should never trigger.
            if (poff_ > static_cast<uint8_t>(UCHAR_MAX - csiz)) {
                logfmt("parse_greet(): dnslen guard poff_={} csiz={}\n",
                       poff_, csiz);
                return RplFail;
            }
            consumed += csiz;
            ptmp_ -= csiz;
            dst_hostname_.append(sockbuf_.data() + poff_, csiz);
            poff_ += csiz;
        }
        if (ptmp_ > 0)
            return boost::optional<ReplyCode>();
        goto parsed5cr_daddr;
    }
    default: throw std::logic_error("undefined parse state");
    }
    return boost::optional<ReplyCode>();
}

void SocksInit::kick_tcp_resolver_timer()
{
    if (!tcp_resolver_timer)
        tcp_resolver_timer =
            std::make_unique<boost::asio::deadline_timer>(io_service);
    tcp_resolver_timer->expires_from_now
        (boost::posix_time::seconds(resolver_prunetimer_sec));
    auto seq = tcp_resolver_timer_seq;
    tcp_resolver_timer->async_wait(
        [this, seq](const boost::system::error_code& error)
        {
            if (error)
                return;
            std::lock_guard<std::mutex> wl(tcp_resolver_lock);
            auto cseq = tcp_resolver_timer_seq;
            if (cseq == seq) {
                tcp_resolver->cancel();
                tcp_resolver.reset();
                return;
            }
            kick_tcp_resolver_timer();
        });
}

bool SocksInit::dns_choose_address(DNSType addrtype, boost::asio::ip::tcp::resolver::iterator it,
                                   const size_t cv4, const size_t cv6)
{
    static const ba::ip::tcp::resolver::iterator rie;
    if (addrtype == DNSType::None)
        return false;
    size_t total_choices(addrtype == DNSType::Any ? cv4 + cv6
                                                  : (addrtype == DNSType::V6 ? cv6
                                                                             : cv4));
    if (total_choices == 0)
        return false;
    size_t choicenum = g_random_prng() % total_choices;
    size_t i(0);
    for (; it != rie; ++it) {
        if (addrtype == DNSType::V4 && !it->endpoint().address().is_v4())
            continue;
        if (addrtype == DNSType::V6 && it->endpoint().address().is_v4())
            continue;
        if (i == choicenum) {
            dst_address_ = it->endpoint().address();
            return true;
        }
        ++i;
    }
    return false;
}

void SocksInit::dns_lookup()
{
    ba::ip::tcp::resolver::query query
        (dst_hostname_, boost::lexical_cast<std::string>(dst_port_));
    auto sfd = shared_from_this();
    try {
        std::lock_guard<std::mutex> wl(tcp_resolver_lock);
        if (!tcp_resolver) {
            tcp_resolver = std::make_unique<boost::asio::ip::tcp::resolver>
                (io_service);
            kick_tcp_resolver_timer();
        }
        tcp_resolver->async_resolve
            (query, strand_.wrap(
             [this, sfd](const boost::system::error_code &ec,
                         ba::ip::tcp::resolver::iterator it)
             {
                 if (ec) {
                     send_reply(RplHostUnreach);
                     return;
                 }
                 std::size_t cv6(0), cv4(0);
                 static const ba::ip::tcp::resolver::iterator rie;
                 ba::ip::tcp::resolver::iterator oit(it);
                 for (; it != rie; ++it) {
                     if (it->endpoint().address().is_v4()) ++cv4;
                     else ++cv6;
                 }
                 bool got_addr;
                 if (g_prefer_ipv4 || g_disable_ipv6) {
                     got_addr = dns_choose_address(DNSType::V4, oit, cv4, cv6);
                     if (!got_addr && !g_disable_ipv6)
                         got_addr = dns_choose_address(DNSType::V6, oit, cv4, cv6);
                 } else {
                     got_addr = dns_choose_address(DNSType::Any, oit, cv4, cv6);
                 }
                 if (!got_addr) {
                     send_reply(RplHostUnreach);
                     return;
                 }
                 // Shouldn't trigger, but be safe.
                 if (g_disable_ipv6 && dst_address_.is_v6()) {
                     send_reply(RplHostUnreach);
                     return;
                 }
                 // It's possible for the resolver to return an address
                 // that is unspecified after lookup, eg, host file blocking.
                 if (dst_address_.is_unspecified()) {
                     send_reply(RplHostUnreach);
                     return;
                 }
                 dispatch_connrq(true);
             }));
        ++tcp_resolver_timer_seq;
    } catch (const std::exception &) {
        send_reply(RplHostUnreach);
    }
}

void SocksInit::dispatch_connrq(bool did_dns)
{
    if (!did_dns && dst_hostname_.size() > 0 && dst_address_.is_unspecified()) {
        dns_lookup();
        return;
    }
    // The name has been resolved to an address or we have an address.
    switch (cmd_code_) {
    case CmdTCPConnect: dispatch_tcp_connect(); break;
    case CmdTCPBind: dispatch_tcp_bind(); break;
    case CmdUDP: dispatch_udp(); break;
    default: send_reply(RplCmdNotSupp); break;
    }
}

static const auto loopback_addr_v4 = ba::ip::address_v4::from_string("127.0.0.0");
static const auto loopback_addr_v6 = ba::ip::address_v6::from_string("::1");

static bool is_dst_denied(const ba::ip::address &addr)
{
    // Deny proxy attempts to the local loopback addresses.
    if (addr == loopback_addr_v6 ||
        nk::asio::compare_ip(addr, loopback_addr_v4, 8))
        return true;
    for (const auto &i: g_dst_deny_masks) {
        auto r = nk::asio::compare_ip(addr, std::get<0>(i), std::get<1>(i));
        if (r) {
            logfmt("DENIED connection to {}\n", addr.to_string());
            return true;
        }
    }
    return false;
}

void SocksInit::dispatch_tcp_connect()
{
    if (is_dst_denied(dst_address_)) {
        send_reply(RplDeny);
        return;
    }
    // Connect to the remote address.  If we connect successfully, then
    // open a proxying local tcp socket and inform the requesting client.
    auto ep = ba::ip::tcp::endpoint(dst_address_, dst_port_);
    auto sfd = shared_from_this();
    remote_socket_.async_connect
        (ep, strand_.wrap(
         [this, sfd](const boost::system::error_code &ec)
         {
             if (ec) {
                 send_reply(errorToReplyCode(ec));
                 return;
             }
             if (g_verbose_logs) {
                 boost::system::error_code ecc;
                 auto cep = client_socket_.remote_endpoint(ecc);
                 logfmt("TCP Connect @{} -> {}:{}\n",
                        !ecc? cep.address().to_string() : "NONE",
                        addr_type_ != AddrDNS ?
                        dst_address_.to_string() : dst_hostname_, dst_port_);
             }
             set_remote_socket_options();
             bool is_socks_v4(is_socks_v4_);

             boost::system::error_code eec;
             auto ep = remote_socket_.remote_endpoint(eec);
             if (eec) {
                 logfmt("TCP Connect: bad remote endpoint: {}\n",
                        eec.message());
                 send_reply(RplFail);
                 return;
             }

             conntracker_tcp.emplace(ep, io_service,
                   std::move(client_socket_), std::move(remote_socket_),
                   std::move(dst_address_), dst_port_, false, is_socks_v4,
                   std::move(dst_hostname_));
         }));
}

SocksInit::ReplyCode
SocksInit::errorToReplyCode(const boost::system::error_code &ec)
{
    ReplyCode rc(RplConnRefused);
    if (ec == ba::error::access_denied ||
        ec == ba::error::connection_refused) {
        rc = RplConnRefused;
    } else if (ec == ba::error::address_family_not_supported ||
               ec == ba::error::fault || ec == ba::error::service_not_found ||
               ec == ba::error::socket_type_not_supported) {
        rc = RplAddrNotSupp;
    } else if (ec == ba::error::timed_out) {
        rc = RplTTLExpired;
    } else if (ec == ba::error::host_unreachable) {
        rc = RplHostUnreach;
    } else if (ec == ba::error::network_unreachable) {
        rc = RplNetUnreach;
    }
    return rc;
}

bool SocksInit::is_bind_client_allowed() const
{
    boost::system::error_code ec;
    auto cep = client_socket_.remote_endpoint(ec);
    if (ec) {
        logfmt("DENIED bind request; client has bad remote_endpoint: {}\n",
               ec.message());
        return false;
    }
    auto laddr = cep.address();
    for (const auto &i: g_client_bind_allow_masks) {
        auto r = nk::asio::compare_ip(laddr, std::get<0>(i), std::get<1>(i));
        if (r)
            return true;
    }
    logfmt("DENIED bind request from {}\n", laddr.to_string());
    return false;
}

bool SocksInit::create_bind_socket(ba::ip::tcp::endpoint ep)
{
    int tries = 0;
    while (true) {
        ++tries;
        if (tries > MAX_BIND_TRIES) {
            logfmt("fatal error creating BIND socket: can't find unused port\n");
            break;
        }
        try {
            bound_ = std::make_unique<BoundSocket>(io_service, ep);
        } catch (const std::runtime_error &e) {
            logfmt("fatal error creating BIND socket: {}\n", e.what());
            break;
        } catch (const std::domain_error &e) {
            continue;
        }
        return true;
    }
    send_reply(RplFail);
    return false;
}

void SocksInit::dispatch_tcp_bind()
{
    if (g_disable_bind) {
        send_reply(RplDeny);
        return;
    }
    assert(BPA);
    ba::ip::tcp::endpoint bind_ep;
    auto rcnct = conntracker_tcp.find_by_addr_port
        (dst_address_, dst_port_);
    try {
        if (rcnct) {
            // Bind to the local IP that is associated with the
            // client-specified dst_address_ and dst_port_.
            boost::system::error_code ec;
            auto rlep = (*rcnct)->remote_socket_local_endpoint(ec);
            if (ec) {
                send_reply(RplDeny);
                return;
            }
            bind_ep = ba::ip::tcp::endpoint(rlep.address(), BPA->get_port());
        } else {
            if (!is_bind_client_allowed()) {
                send_reply(RplDeny);
                return;
            }
            bind_ep = ba::ip::tcp::endpoint
                (!g_disable_ipv6 ? ba::ip::tcp::v6() : ba::ip::tcp::v4(),
                 BPA->get_port());
        }
    } catch (const std::out_of_range &) {
        // No ports are free for use as a local endpoint.
        send_reply(RplFail);
        return;
    }

    if (!create_bind_socket(bind_ep))
        return;
    bind_listen_ = true;
    conntracker_bindlisten->store(shared_from_this());

    auto sfd = shared_from_this();
    bound_->acceptor_.async_accept
        (remote_socket_, strand_.wrap(
         [this, sfd](const boost::system::error_code &ec)
         {
             if (ec) {
                 send_reply(RplFail);
                 return;
             }
             logfmt("Accepted a connection to a BIND socket.\n");
             set_remote_socket_options();
             bool is_socks_v4(is_socks_v4_);

             boost::system::error_code eec;
             auto ep = remote_socket_.remote_endpoint(eec);
             if (eec) {
                 logfmt("BIND socket: bad remote endpoint: {}\n",
                        eec.message());
                 send_reply(RplFail);
                 return;
             }

             conntracker_tcp.emplace(ep, io_service,
                   std::move(client_socket_), std::move(remote_socket_),
                   std::move(dst_address_), dst_port_, true, is_socks_v4,
                   std::move(dst_hostname_));
         }));
    send_reply(RplSuccess);
}

bool SocksInit::is_udp_client_allowed(boost::asio::ip::address laddr) const
{
    for (const auto &i: g_client_udp_allow_masks) {
        auto r = nk::asio::compare_ip(laddr, std::get<0>(i), std::get<1>(i));
        if (r)
            return true;
    }
    logfmt("DENIED udp associate request from {}\n",
           laddr.to_string());
    return false;
}

// DST.ADDR and DST.PORT are ignored.
void SocksInit::dispatch_udp()
{
    if (g_disable_udp) {
        send_reply(RplDeny);
        return;
    }
    assert(UPA);
    boost::system::error_code ec;
    auto client_rep = client_socket_.remote_endpoint(ec);
    if (ec || !is_udp_client_allowed(client_rep.address())) {
        send_reply(RplDeny);
        return;
    }
    ba::ip::udp::endpoint udp_client_ep, udp_remote_ep;
    uint16_t udp_local_port, udp_remote_port;
    auto client_lep = client_socket_.local_endpoint(ec);
    if (ec) {
        send_reply(RplFail);
        return;
    }
    auto laddr(client_lep.address());
    try {
        udp_local_port = UPA->get_port();
        udp_client_ep = ba::ip::udp::endpoint(laddr, udp_local_port);
    } catch (const std::out_of_range &) {
        // No ports are free for use as a local endpoint.
        send_reply(RplFail);
        return;
    }
    try {
        udp_remote_port = UPA->get_port();
        udp_remote_ep = ba::ip::udp::endpoint
            (!g_disable_ipv6 ? ba::ip::udp::v6() : ba::ip::udp::v4(),
             udp_remote_port);
    } catch (const std::out_of_range &) {
        // No ports are free for use as a remote endpoint.
        UPA->release_port(udp_local_port);
        send_reply(RplFail);
        return;
    }

    auto ct = std::make_shared<SocksUDP>
        (io_service, std::move(client_socket_),
         udp_client_ep, udp_remote_ep,
         ba::ip::udp::endpoint(client_rep.address(), client_rep.port()));
    ct->start();
}

void SocksInit::send_reply(ReplyCode replycode)
{
    std::size_t ssiz(0);
    if (!is_socks_v4_) {
        assert(replycode != RplIdentWrong && replycode != RplIdentUnreach);
        ssiz = send_reply_code_v5(sockbuf_, replycode);
        if (replycode == RplSuccess) {
            if (cmd_code_ != CmdTCPBind || !bound_) {
                throw std::logic_error
                    ("cmd_code_ != CmdTCPBind || !bound_ in send_reply(RplSuccess).\n");
            } else
                ssiz = send_reply_binds_v5(sockbuf_, ssiz,
                                           bound_->local_endpoint_);
        }
    } else {
        ssiz = send_reply_code_v4(sockbuf_, replycode);
        if (!bound_) {
            for (auto i = 0; i < 6; ++i)
                sockbuf_[ssiz++] = 0;
        }
        else ssiz = send_reply_binds_v4(sockbuf_, ssiz,
                                        bound_->local_endpoint_);
    }
    auto sfd = shared_from_this();
    ba::async_write
        (client_socket_,
         ba::buffer(sockbuf_.data(), ssiz),
         strand_.wrap(
         [this, sfd, replycode](const boost::system::error_code &ec,
                                std::size_t bytes_xferred)
         {
             if (ec || replycode != RplSuccess) {
                 boost::system::error_code ecc;
                 auto cep = client_socket_.remote_endpoint(ecc);
                 logfmt("REJECT @{} -> {}:{} [{}]\n",
                     !ecc? cep.address().to_string() : "NONE",
                     addr_type_ != AddrDNS ?
                     dst_address_.to_string() : dst_hostname_,
                     dst_port_, replyCodeString[replycode]);
                 terminate();
             }
         }));
}

SocksTCP::SocksTCP(ba::io_service &io_service,
                   boost::asio::ip::tcp::socket client_socket,
                   boost::asio::ip::tcp::socket remote_socket,
                   boost::asio::ip::address dst_address,
                   uint16_t dst_port, bool is_bind, bool is_socks_v4,
                   std::string dst_hostname)
        : tracked_(true),
          dst_hostname_(dst_hostname), dst_address_(dst_address),
          strand_(io_service), client_socket_(std::move(client_socket)),
          remote_socket_(std::move(remote_socket)),
          dst_port_(dst_port), is_socks_v4_(is_socks_v4), is_bind_(is_bind)
#ifdef USE_SPLICE
          ,
          flush_invoked_(false), pToRemote_len_(0), pToClient_len_(0),
          pToRemoteR_(io_service), pToClientR_(io_service),
          pToRemoteW_(io_service), pToClientW_(io_service)
#endif
{
    if (g_verbose_logs)
        ++socks_alive_count;
}

SocksTCP::~SocksTCP()
{
#ifdef USE_SPLICE
    pipe_close_raw(pToClient_len_, pToClientR_, pToClientW_);
    pipe_close_raw(pToRemote_len_, pToRemoteR_, pToRemoteW_);
#endif
    untrack();
    close_paired_sockets(client_socket_, remote_socket_);
    if (g_verbose_logs) {
        --socks_alive_count;
        print_trackers_logentry(dst_hostname_.size() ? dst_hostname_
                                  : dst_address_.to_string(),
                                  dst_port_);
    }
}

void SocksTCP::untrack()
{
    bool cxr(true);
    if (tracked_.compare_exchange_strong(cxr, false))
        conntracker_tcp.erase(get_tracker_iterator());
}

#ifdef USE_SPLICE
bool SocksTCP::init_pipe(boost::asio::posix::stream_descriptor &preader,
                         boost::asio::posix::stream_descriptor &pwriter)
{
    int pipes[2];
#ifdef HAS_64BIT
    uint64_t sp;
    bool got_free_pipe = free_pipes.pop(sp);
    if (got_free_pipe) {
        pipes[0] = static_cast<uint32_t>(sp & 0xffffffffUL);
        pipes[1] = static_cast<uint32_t>(sp >> 32U);
        if (g_verbose_logs) {
            --num_free_pipes;
            logfmt("init_pipe: Got cached pipe=[{},{}]\n",
                   pipes[0], pipes[1]);
        }
    }
#else
    bool got_free_pipe(false);
    {
        std::lock_guard<std::mutex> wl(free_pipe_lock);
        if (free_pipes.size()) {
            got_free_pipe = true;
            auto fp = free_pipes.back();
            pipes[0] = fp.first;
            pipes[1] = fp.second;
            free_pipes.pop_back();
            if (g_verbose_logs)
                logfmt("init_pipe: Got cached pipe=[{},{}]\n",
                       pipes[0], pipes[1]);
        }
    }
#endif
    if (!got_free_pipe) {
        if (pipe2(pipes, O_NONBLOCK))
            return false;
        auto r = fcntl(pipes[0], F_SETPIPE_SZ, splice_pipe_size);
        if (r < splice_pipe_size)
            logfmt("init_pipe: Pipe size could only be set to {}.\n", r);
        else if (r == -1) {
            switch (errno) {
                case EPERM: logfmt("init_pipe: EPERM when trying to set splice pipe size to {}.\n", splice_pipe_size);
                default: logfmt("init_pipe: fcntl(F_SETPIPE_SZ) returned errno={}.\n", errno);
            }
        }
    }
    preader.assign(pipes[0]);
    pwriter.assign(pipes[1]);
    return true;
}

// Must be called while holding a shared_ptr
void SocksTCP::flush_then_terminate(FlushDirection dir)
{
    if (flush_invoked_)
        return;
    flush_invoked_ = true; // Latch to make sure flushers run once and don't get cancelled.
    auto cso = client_socket_.is_open();
    auto rso = remote_socket_.is_open();
    if (cso) client_socket_.cancel();
    if (rso) remote_socket_.cancel();
    if (cso || rso) {
        auto sfd = shared_from_this();
        strand_.post([this, sfd, cso, rso, dir] {
                     boost::system::error_code ec;
                     if (cso)
                         client_socket_.shutdown(ba::ip::tcp::socket::shutdown_receive, ec);
                     if (rso)
                         remote_socket_.shutdown(ba::ip::tcp::socket::shutdown_receive, ec);
                     if (cso && pToClient_len_ > 0 && dir != FlushDirection::Remote) {
                         doFlushPipeToClient(0);
                     }
                     if (rso && pToRemote_len_ > 0 && dir != FlushDirection::Client) {
                         doFlushPipeToRemote(0);
                     }
                     });
    }
}

inline void SocksTCP::tcp_client_socket_read_again
(const std::shared_ptr<SocksTCP> &sfd,
 size_t bytes_xferred, bool splice_ok)
{
    // logfmt("sbx={} sms={}\n", bytes_xferred,
    //            send_minsplice_size);
    if (splice_ok && bytes_xferred >= send_minsplice_size) {
        if (init_pipe(pToRemoteR_, pToRemoteW_)) {
            // logfmt("client->remote switched to splice\n");
            tcp_client_socket_read_splice();
            return;
        } else
            logfmt("init_pipe_client failed\n");
    }
    tcp_client_socket_read();
}

inline void SocksTCP::tcp_remote_socket_read_again
(const std::shared_ptr<SocksTCP> &sfd,
 size_t bytes_xferred, bool splice_ok)
{
    // logfmt("rbx={} rms={}\n", bytes_xferred,
    //            receive_minsplice_size);
    if (splice_ok && bytes_xferred >= receive_minsplice_size) {
        if (init_pipe(pToClientR_, pToClientW_)) {
            // logfmt("remote->client switched to splice\n");
            tcp_remote_socket_read_splice();
            return;
        } else
            logfmt("init_pipe_remote failed\n");
    }
    tcp_remote_socket_read();
}

inline void SocksTCP::splicePipeToClient_err()
{
    boost::system::error_code ecc;
    auto cep = client_socket_.remote_endpoint(ecc);
    logfmt("splicePipeToClient_err: {} -> {}:{} [{}] => TERMINATE\n",
           !ecc? cep.address().to_string() : "NONE",
           dst_hostname_.size()? dst_hostname_ : dst_address_.to_string(),
           dst_port_, strerror(errno));
    // If we get an error, the socket fd is already closed.
    // In this case, we do not want to flush this half
    // of the connection.
    flush_then_terminate(FlushDirection::Remote);
}

inline void SocksTCP::splicePipeToRemote_err()
{
    boost::system::error_code ecc;
    auto cep = remote_socket_.remote_endpoint(ecc);
    logfmt("splicePipeToRemote_err: {} -> {}:{} [{}] => TERMINATE\n",
           !ecc? cep.address().to_string() : "NONE",
           dst_hostname_.size()? dst_hostname_ : dst_address_.to_string(),
           dst_port_, strerror(errno));
    // If we get an error, the socket fd is already closed.
    // In this case, we do not want to flush this half
    // of the connection.
    flush_then_terminate(FlushDirection::Client);
}

inline int SocksTCP::splicePipeToClient()
{
    if (pToClient_len_ <= 0)
        return 0;
    auto n = splice(pToClientR_.native_handle(), NULL,
                    client_socket_.native_handle(), NULL,
                    splice_pipe_size, SPLICE_F_NONBLOCK);
    if (n > 0) {
        pToClient_len_ -= n;
        return 0;
    }
    if (n < 0 && (errno == EINTR || errno == EAGAIN))
        return -1;
    return -2;
}

inline int SocksTCP::splicePipeToRemote()
{
    if (pToRemote_len_ <= 0)
        return 0;
    auto n = splice(pToRemoteR_.native_handle(), NULL,
                    remote_socket_.native_handle(), NULL,
                    splice_pipe_size, SPLICE_F_NONBLOCK);
    if (n > 0) {
        pToRemote_len_ -= n;
        return 0;
    }
    if (n < 0 && (errno == EINTR || errno == EAGAIN))
        return -1;
    return -2;
}

void SocksTCP::tcp_client_socket_write_splice(int tries)
{
    ++tries;
    auto sfd = shared_from_this();
    remote_socket_.async_write_some
        (ba::null_buffers(), strand_.wrap(
         [this, sfd, tries](const boost::system::error_code &ec,
                            std::size_t bytes_xferred)
         {
             if (ec) goto ec_err;
             if (splicePipeToRemote() < -1) {
                 splicePipeToRemote_err();
                 return;
             }
             if (pToRemote_len_ > 0) {
                 tcp_client_socket_write_splice(tries);
                 return;
             }
             if (tries < 3)
                 tcp_client_socket_read_splice();
             else
                 tcp_client_socket_read_stopsplice();
             return;
ec_err:
             if (ec != ba::error::operation_aborted) {
                 logfmt("cs: [{}] async_write_some: {}\n",
                        dst_hostname_.size()?  dst_hostname_ : dst_address_.to_string(),
                        boost::system::system_error(ec).what());
                 flush_then_terminate(FlushDirection::Client);
             }
         }));
}

void SocksTCP::tcp_remote_socket_write_splice(int tries)
{
    ++tries;
    auto sfd = shared_from_this();
    client_socket_.async_write_some
        (ba::null_buffers(), strand_.wrap(
         [this, sfd, tries](const boost::system::error_code &ec,
                            std::size_t bytes_xferred)
         {
             if (ec) goto ec_err;
             if (splicePipeToClient() < -1) {
                 splicePipeToClient_err();
                 return;
             }
             if (pToClient_len_ > 0) {
                 tcp_remote_socket_write_splice(tries);
                 return;
             }
             if (tries < 3)
                 tcp_remote_socket_read_splice();
             else
                 tcp_remote_socket_read_stopsplice();
             return;
ec_err:
             if (ec != ba::error::operation_aborted) {
                 logfmt("rs: [{}] async_write_some: {}\n",
                        dst_hostname_.size()?  dst_hostname_ : dst_address_.to_string(),
                        boost::system::system_error(ec).what());
                 flush_then_terminate(FlushDirection::Remote);
             }
         }));
}

// Write data read from the client socket to the connect socket.
void SocksTCP::tcp_client_socket_read_splice()
{
    auto sfd = shared_from_this();
    client_socket_.async_read_some
        (ba::null_buffers(), strand_.wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             ssize_t spliced;
             if (ec) goto ec_err;
             if ((spliced = splice(client_socket_.native_handle(), NULL,
                                   pToRemoteW_.native_handle(), NULL,
                                   splice_pipe_size, SPLICE_F_NONBLOCK)) <= 0) // 0 is EOF
                 goto splice_err;
             pToRemote_len_ += spliced;
             // XXX: Could keep track of the average splice size of the
             //      last n reads and revert to normal reads if below
             //      a threshold.
             if (splicePipeToRemote() < -1) {
                 splicePipeToRemote_err();
                 return;
             }
             if (pToRemote_len_ > 0)
                 tcp_client_socket_write_splice(0);
             else
                 tcp_client_socket_read_splice();
             return;
splice_err:
             if (spliced == 0) {
                 flush_then_terminate(FlushDirection::Remote);
                 return;
             }
             switch (errno) {
                 case EINTR: tcp_client_socket_read_splice(); return;
                 // EAGAIN can mean the pipe is full, or it can mean that
                 // the pipe write would block for another reason.
                 case EAGAIN: tcp_client_socket_write_splice(0); return;
                 case EBADF:
                     // Splicing from a client_socket_ that has been shutdown()'ed
                     // will fail with EBADF.
                     if (flush_invoked_) {
                         logfmt("cs: [{}] noticed shutdown: {}\n", dst_hostname_.size()?
                                dst_hostname_ : dst_address_.to_string(), strerror(errno));
                         flush_then_terminate(FlushDirection::Remote);
                         return;
                     }
                 default: break;
             }
             logfmt("cs: [{}] splice: {}\n", dst_hostname_.size()?
                    dst_hostname_ : dst_address_.to_string(), strerror(errno));
             flush_then_terminate(FlushDirection::Remote);
             return;
ec_err:
             if (ec != ba::error::operation_aborted) {
                 logfmt("cs: [{}] async_read_some: {}\n", dst_hostname_.size()?
                        dst_hostname_ : dst_address_.to_string(),
                        boost::system::system_error(ec).what());
                 flush_then_terminate(FlushDirection::Remote);
             }
         }));
}

// Write data read from the connect socket to the client socket.
void SocksTCP::tcp_remote_socket_read_splice()
{
    auto sfd = shared_from_this();
    remote_socket_.async_read_some
        (ba::null_buffers(), strand_.wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             ssize_t spliced;
             if (ec) goto ec_err;
             if ((spliced = splice(remote_socket_.native_handle(), NULL,
                                   pToClientW_.native_handle(), NULL,
                                   splice_pipe_size, SPLICE_F_NONBLOCK)) <= 0) // 0 is EOF
                 goto splice_err;
             pToClient_len_ += spliced;
             // XXX: Could keep track of the average splice size of the
             //      last n reads and revert to normal reads if below
             //      a threshold.
             if (splicePipeToClient() < -1) {
                 splicePipeToClient_err();
                 return;
             }
             if (pToClient_len_ > 0)
                 tcp_remote_socket_write_splice(0);
             else
                 tcp_remote_socket_read_splice();
             return;
splice_err:
             if (spliced == 0) {
                 flush_then_terminate(FlushDirection::Client);
                 return;
             }
             switch (errno) {
                 case EINTR: tcp_remote_socket_read_splice(); return;
                 // EAGAIN can mean the pipe is full, or it can mean that
                 // the pipe write would block for another reason.
                 case EAGAIN: tcp_remote_socket_write_splice(0); return;
                 case EBADF:
                     // Splicing from a remote_socket_ that has been shutdown()'ed
                     // will fail with EBADF.
                     if (flush_invoked_) {
                         logfmt("rs: [{}] noticed shutdown: {}\n", dst_hostname_.size()?
                                dst_hostname_ : dst_address_.to_string(), strerror(errno));
                         flush_then_terminate(FlushDirection::Client);
                         return;
                     }
                 default: break;

             }
             logfmt("rs: [{}] splice: {}\n", dst_hostname_.size()?
                    dst_hostname_ : dst_address_.to_string(), strerror(errno));
             flush_then_terminate(FlushDirection::Client);
             return;
ec_err:
             if (ec != ba::error::operation_aborted) {
                 logfmt("rs: [{}] async_read_some: {}\n", dst_hostname_.size()?
                        dst_hostname_ : dst_address_.to_string(),
                        boost::system::system_error(ec).what());
                 flush_then_terminate(FlushDirection::Client);
             }
         }));
}

void SocksTCP::doFlushPipeToRemote(int tries)
{
    ++tries;
    auto sfd = shared_from_this();
    remote_socket_.async_write_some
        (ba::null_buffers(), strand_.wrap(
         [this, sfd, tries](const boost::system::error_code &ec,
                            std::size_t bytes_xferred)
         {
             int spc;
             if (ec) {
                 if (ec == ba::error::operation_aborted)
                     return;
                 logfmt("rs-flush: [{}] async_write_some: {}\n",
                        dst_hostname_.size()?  dst_hostname_ : dst_address_.to_string(),
                        boost::system::system_error(ec).what());
                 return;
             }
             if ((spc = splicePipeToRemote()) < 0) {
                 if (spc == -1 && tries < MAX_PIPE_FLUSH_TRIES)
                     doFlushPipeToRemote(tries);
                 return;
             }
             if (pToRemote_len_ == 0)
                 return;
             doFlushPipeToRemote(tries);
         }));
}

void SocksTCP::doFlushPipeToClient(int tries)
{
    ++tries;
    auto sfd = shared_from_this();
    client_socket_.async_write_some
        (ba::null_buffers(), strand_.wrap(
         [this, sfd, tries](const boost::system::error_code &ec,
                            std::size_t bytes_xferred)
         {
             int spc;
             if (ec) {
                 if (ec == ba::error::operation_aborted)
                     return;
                 logfmt("cs-flush: [{}] async_write_some: {}\n",
                        dst_hostname_.size()?  dst_hostname_ : dst_address_.to_string(),
                        boost::system::system_error(ec).what());
                 return;
             }
             if ((spc = splicePipeToClient()) < 0) {
                 if (spc == -1 && tries < MAX_PIPE_FLUSH_TRIES)
                     doFlushPipeToClient(tries);
                 return;
             }
             if (pToClient_len_ == 0)
                 return;
             doFlushPipeToClient(tries);
         }));
}
#endif

// Write data read from the client socket to the connect socket.
void SocksTCP::tcp_client_socket_read()
{
    ba::streambuf::mutable_buffers_type ibm
        = client_buf_.prepare(send_buffer_chunk_size);
    auto sfd = shared_from_this();
    client_socket_.async_read_some
        (ba::buffer(ibm), strand_.wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 if (ec != ba::error::operation_aborted)
                     flush_then_terminate(FlushDirection::Remote);
                 return;
             }
             client_buf_.commit(bytes_xferred);
             // Client is trying to send data to the remote server.  Write it
             // to the remote_socket_.
             boost::system::error_code ecx;
             auto cbs = client_buf_.size();
             auto r = remote_socket_.send
                 (ba::buffer(client_buf_.data(), cbs), 0, ecx);
             if (r) {
                 client_buf_.consume(r);
                 if (r == cbs) {
                     tcp_client_socket_read_again(sfd, r, !client_buf_.size());
                     return;
                 }
             } else if (ecx != ba::error::would_block) {
                 if (ecx != ba::error::operation_aborted)
                     flush_then_terminate(FlushDirection::Client);
                 return;
             }
             ba::async_write
                 (remote_socket_, client_buf_, strand_.wrap(
                  [this, sfd](const boost::system::error_code &ec,
                              std::size_t bytes_xferred)
                  {
                      if (ec) {
                          if (ec != ba::error::operation_aborted)
                              flush_then_terminate(FlushDirection::Client);
                          return;
                      }
                      client_buf_.consume(bytes_xferred);
                      tcp_client_socket_read_again(sfd, bytes_xferred,
                                                   client_buf_.size() == 0);
                  }));
         }));
}

// Write data read from the connect socket to the client socket.
void SocksTCP::tcp_remote_socket_read()
{
    ba::streambuf::mutable_buffers_type ibm
        = remote_buf_.prepare(receive_buffer_chunk_size);
    auto sfd = shared_from_this();
    remote_socket_.async_read_some
        (ba::buffer(ibm), strand_.wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 if (ec != ba::error::operation_aborted)
                     flush_then_terminate(FlushDirection::Client);
                 return;
             }
             remote_buf_.commit(bytes_xferred);
             // Remote server is trying to send data to the client.  Write it
             // to the client_socket_.
             boost::system::error_code ecx;
             auto rbs = remote_buf_.size();
             auto r = client_socket_.send
                 (ba::buffer(remote_buf_.data(), rbs), 0, ecx);
             remote_buf_.consume(r);
             if (r) {
                 if (r == rbs) {
                     tcp_remote_socket_read_again(sfd, r, !remote_buf_.size());
                     return;
                 }
             } else if (ecx != ba::error::would_block) {
                 if (ecx != ba::error::operation_aborted)
                     flush_then_terminate(FlushDirection::Remote);
                 return;
             }
             ba::async_write
                 (client_socket_, remote_buf_, strand_.wrap(
                  [this, sfd](const boost::system::error_code &ec,
                              std::size_t bytes_xferred)
                  {
                      if (ec) {
                          if (ec != ba::error::operation_aborted)
                              flush_then_terminate(FlushDirection::Remote);
                          return;
                      }
                      remote_buf_.consume(bytes_xferred);
                      tcp_remote_socket_read_again(sfd, bytes_xferred,
                                                   remote_buf_.size() == 0);
                  }));
         }));
}

bool SocksTCP::matches_dst(const boost::asio::ip::address &addr,
                           uint16_t port) const
{
    if (!nk::asio::compare_ip(addr, dst_address_, 128))
        return false;
    if (dst_port_ != port)
        return false;
    if (is_bind_)
        return false;
    return true;
}

void SocksTCP::start(ba::ip::tcp::endpoint ep)
{
    std::array<char, 24> sbuf;
    std::size_t ssiz;

    if (!is_socks_v4_) {
        ssiz = send_reply_code_v5(sbuf, SocksInit::ReplyCode::RplSuccess);
        ssiz = send_reply_binds_v5(sbuf, ssiz, ep);
    } else {
        ssiz = send_reply_code_v4(sbuf, SocksInit::ReplyCode::RplSuccess);
        ssiz = send_reply_binds_v4(sbuf, ssiz, ep);
    }

    auto ibm = client_buf_.prepare(ssiz);
    auto siz = std::min(ssiz, boost::asio::buffer_size(ibm));
    memcpy(boost::asio::buffer_cast<char *>(ibm), sbuf.data(), siz);
    client_buf_.commit(siz);

    auto sfd = shared_from_this();
    ba::async_write
        (client_socket_, client_buf_, strand_.wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             client_buf_.consume(bytes_xferred);
             if (ec) {
                 if (ec != ba::error::operation_aborted) {
                     boost::system::error_code ecc;
                     auto cep = client_socket_.remote_endpoint(ecc);
                     logfmt("TCP Start: @{}-> {}:{} [{}]\n",
                            !ecc? cep.address().to_string() : "NONE",
                            !dst_hostname_.size() ?
                            dst_address_.to_string() : dst_hostname_,
                            dst_port_, ec.message());
                 }
                 return;
             }
             tcp_client_socket_read();
             tcp_remote_socket_read();
         }));
}

SocksUDP::SocksUDP(ba::io_service &io_service,
                   ba::ip::tcp::socket tcp_client_socket,
                   ba::ip::udp::endpoint client_ep,
                   ba::ip::udp::endpoint remote_ep,
                   ba::ip::udp::endpoint client_remote_ep)
        : tcp_client_socket_(std::move(tcp_client_socket)),
          client_endpoint_(client_ep), remote_endpoint_(remote_ep),
          client_remote_endpoint_(client_remote_ep),
          strand_(io_service),
          client_socket_(io_service, client_ep),
          remote_socket_(io_service, remote_ep)
{
    if (g_verbose_logs) {
        ++socks_alive_count;
        ++udp_alive_count;
    }
}

SocksUDP::~SocksUDP()
{
    if (g_verbose_logs) {
        --socks_alive_count;
        --udp_alive_count;
        print_trackers_logentry("(n/a)", 0);
    }
}

void SocksUDP::terminate()
{
    close_udp_sockets();
}

void SocksUDP::start()
{
    std::array<char, 24> sbuf;
    std::size_t ssiz;

    ssiz = send_reply_code_v5(sbuf, SocksInit::ReplyCode::RplSuccess);
    boost::system::error_code ecc;
    auto ep = client_socket_.local_endpoint(ecc);
    if (ecc) {
        logfmt("SocksUDP::start(): client socket has bad endpoint: {}\n",
               ecc.message());
        terminate();
        return;
    }
    ssiz = send_reply_binds_v5
        (sbuf, ssiz, ba::ip::tcp::endpoint(ep.address(), ep.port()));
    memcpy(out_header_.data(), sbuf.data(), ssiz);
    auto sfd = shared_from_this();
    ba::async_write
        (tcp_client_socket_, ba::buffer(out_header_.data(), ssiz),
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 if (ec != ba::error::operation_aborted) {
                     boost::system::error_code ecr;
                     auto rep = tcp_client_socket_.remote_endpoint(ecr);
                     logfmt("UDP Start: @{} [{}]\n",
                            !ecr? rep.address().to_string() : "NONE",
                            ec.message());
                     terminate();
                 }
                 return;
             }
             udp_tcp_socket_read();
             udp_client_socket_read();
             udp_remote_socket_read();
         });
}

void SocksUDP::close_udp_sockets()
{
    assert(UPA);
    boost::system::error_code ec;
    auto clep = client_socket_.local_endpoint(ec);
    if (!ec)
        UPA->release_port(clep.port());
    auto rlep = remote_socket_.local_endpoint(ec);
    if (!ec)
        UPA->release_port(rlep.port());
}

// Listen for data on client_socket_.  If we get EOF, then terminate the
// entire SocksUDP.
void SocksUDP::udp_tcp_socket_read()
{
    auto sfd = shared_from_this();
    tcp_client_socket_.async_read_some
        (ba::buffer(tcp_inbuf_.data(),
                    tcp_inbuf_.size()), strand_.wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 if (ec != ba::error::operation_aborted) {
                     logfmt("Client closed TCP socket for UDP associate: {}\n",
                            boost::system::system_error(ec).what());
                     terminate();
                 }
                 return;
             }
             udp_tcp_socket_read();
         }));
}

void SocksUDP::udp_client_socket_read()
{
    inbuf_.clear();
    inbuf_.resize(UDP_BUFSIZE);
    auto sfd = shared_from_this();
    client_socket_.async_receive_from
        (ba::buffer(inbuf_),
         csender_endpoint_, strand_.wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 if (ec != ba::error::operation_aborted) {
                     logfmt("Error on client UDP socket: {}\n",
                            boost::system::system_error(ec).what());
                     terminate();
                 }
                 return;
             }
             if (csender_endpoint_ == client_remote_endpoint_) {
                 std::size_t headersiz = 4;
                 if (bytes_xferred < 4)
                     goto nosend;
                 if (inbuf_[0] != '\0')
                     goto nosend;
                 if (inbuf_[1] != '\0')
                     goto nosend;
                 auto fragn = inbuf_[2];
                 if (fragn != '\0') {
                     if (!frags_)
                         frags_ = std::make_unique<UDPFrags>(io_service);
                     if (fragn > 127 && !frags_->buf_.size())
                         fragn = '\0';
                 }
                 auto atyp = inbuf_[3];
                 ba::ip::address daddr;
                 std::string dnsname;
                 switch (atyp) {
                     case 1: { // IPv4
                         if (bytes_xferred < 10)
                             goto nosend;
                         ba::ip::address_v4::bytes_type v4o;
                         memcpy(v4o.data(), inbuf_.data() + headersiz, 4);
                         daddr_ = ba::ip::address_v4(v4o);
                         headersiz += 4;
                         break;
                     }
                     case 3: { // DNS
                         if (bytes_xferred < 8)
                             goto nosend;
                         size_t dnssiz = inbuf_[headersiz++];
                         if (bytes_xferred - headersiz < dnssiz + 2)
                             goto nosend;
                         dnsname = std::string
                             (reinterpret_cast<const  char *>
                              (inbuf_.data() + headersiz), dnssiz);
                         headersiz += dnssiz;
                         break;
                     }
                     case 4: { // IPv6
                         if (bytes_xferred < 22)
                             goto nosend;
                         ba::ip::address_v6::bytes_type v6o;
                         memcpy(v6o.data(), inbuf_.data() + headersiz, 16);
                         daddr_ = ba::ip::address_v6(v6o);
                         headersiz += 16;
                         break;
                     }
                     default: goto nosend; break;
                 }
                 memcpy(&dport_, inbuf_.data() + headersiz, 2);
                 dport_ = ntohs(dport_);
                 headersiz += 2;
                 poffset_ = headersiz;
                 psize_ = bytes_xferred - headersiz;

                 if (fragn != '\0' && udp_frag_handle(fragn, atyp, dnsname))
                     return;

                 if (dnsname.size() > 0)
                     udp_dns_lookup(dnsname);
                 else
                     udp_proxy_packet();
                 return;
             }
           nosend:
             udp_client_socket_read();
         }));
}

bool SocksUDP::udp_frags_different(uint8_t fragn, uint8_t atyp,
                                      const std::string &dnsname)
{
    if (fragn <= frags_->lastn_)
        return true;
    if (dport_ != frags_->port_)
        return true;
    if (atyp != 3) {
        if (daddr_ != frags_->addr_)
            return true;
    } else { // DNS
        if (dnsname != frags_->dns_)
            return true;
    }
    return false;
}

// If true then the caller doesn't need to proceed.
bool SocksUDP::udp_frag_handle(uint8_t fragn, uint8_t atyp,
                                  const std::string &dnsname)
{
    const bool new_frags(frags_->buf_.size() == 0);
    const bool send_frags(fragn > 127);
    if (new_frags || udp_frags_different(fragn, atyp, dnsname)) {
        frags_->reset();
        frags_->lastn_ = fragn;
        frags_->port_ = dport_;
        if (atyp != 3)
            frags_->addr_ = daddr_;
        else // DNS
            frags_->dns_ = dnsname;
    }
    frags_->buf_.insert
        (frags_->buf_.end(),
         inbuf_.begin() + poffset_,
         inbuf_.end());
    if (send_frags) {
        inbuf_ = std::move(frags_->buf_);
        poffset_ = 0;
        psize_ = inbuf_.size();
        frags_->reset();
    } else {
        frags_->reaper_start();
        udp_client_socket_read();
        return true;
    }
    return false;
}

// Forward it to the remote socket.
void SocksUDP::udp_proxy_packet()
{
    if (is_dst_denied(daddr_)) {
        udp_client_socket_read();
        return;
    }
    auto sfd = shared_from_this();
    remote_socket_.async_send_to
        (ba::buffer(inbuf_.data() + poffset_, psize_),
         ba::ip::udp::endpoint(daddr_, dport_), 0, strand_.wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             udp_client_socket_read();
         }));
}

void SocksUDP::kick_udp_resolver_timer()
{
    if (!udp_resolver_timer)
        udp_resolver_timer =
            std::make_unique<boost::asio::deadline_timer>(io_service);
    udp_resolver_timer->expires_from_now
        (boost::posix_time::seconds(resolver_prunetimer_sec));
    auto seq = udp_resolver_timer_seq;
    udp_resolver_timer->async_wait(
        [this, seq](const boost::system::error_code& error)
        {
            if (error)
                return;
            std::lock_guard<std::mutex> wl(udp_resolver_lock);
            auto cseq = udp_resolver_timer_seq;
            if (cseq == seq) {
                udp_resolver->cancel();
                udp_resolver.reset();
                return;
            }
            kick_udp_resolver_timer();
        });
}

void SocksUDP::udp_dns_lookup(const std::string &dnsname)
{
    ba::ip::udp::resolver::query query
        (dnsname, boost::lexical_cast<std::string>(dport_));
    auto sfd = shared_from_this();
    try {
        std::lock_guard<std::mutex> wl(udp_resolver_lock);
        if (!udp_resolver) {
            udp_resolver = std::make_unique<boost::asio::ip::udp::resolver>
                (io_service);
            kick_udp_resolver_timer();
        }
        udp_resolver->async_resolve
            (query, strand_.wrap(
             [this, sfd](const boost::system::error_code &ec,
                         ba::ip::udp::resolver::iterator it)
             {
                 if (ec) {
                     if (ec != ba::error::operation_aborted)
                         udp_client_socket_read();
                     return;
                 }
                 ba::ip::udp::resolver::iterator fv4, fv6, rie;
                 for (; it != rie; ++it) {
                     bool isv4 = it->endpoint().address().is_v4();
                     if (isv4) {
                         if (g_prefer_ipv4) {
                             daddr_ = it->endpoint().address();
                             udp_proxy_packet();
                             return;
                         }
                         if (fv4 == rie)
                             fv4 = it;
                     } else {
                         if (!g_prefer_ipv4) {
                             daddr_ = it->endpoint().address();
                             udp_proxy_packet();
                             return;
                         }
                         if (fv6 == rie)
                             fv6 = it;
                     }
                 }
                 daddr_ = g_prefer_ipv4 ? fv4->endpoint().address()
                                              : fv6->endpoint().address();
                 if (g_disable_ipv6 && !daddr_.is_v4()) {
                     udp_client_socket_read();
                     return;
                 }
                 udp_proxy_packet();
             }));
        ++udp_resolver_timer_seq;
    } catch (const std::exception &) {
        udp_client_socket_read();
    }
}

void SocksUDP::udp_remote_socket_read()
{
    auto sfd = shared_from_this();
    outbuf_.clear();
    out_bufs_.clear();
    outbuf_.reserve(UDP_BUFSIZE);
    remote_socket_.async_receive_from
        (ba::buffer(outbuf_),
         rsender_endpoint_, strand_.wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 if (ec != ba::error::operation_aborted) {
                     logfmt("Error on remote UDP socket: {}\n",
                            boost::system::system_error(ec).what());
                     terminate();
                 }
                 return;
             }
             // Attach the header.
             auto saddr = rsender_endpoint_.address();
             uint16_t sport = rsender_endpoint_.port();
             std::size_t ohs = 4;
             if (saddr.is_v4()) {
                 out_header_[0] = 0;
                 out_header_[1] = 0;
                 out_header_[2] = 0;
                 out_header_[3] = 1;
                 auto v4b = saddr.to_v4().to_bytes();
                 for (auto &i: v4b)
                     out_header_[ohs++] = i;
             } else {
                 out_header_[0] = 0;
                 out_header_[1] = 0;
                 out_header_[2] = 0;
                 out_header_[3] = 4;
                 auto v6b = saddr.to_v6().to_bytes();
                 for (auto &i: v6b)
                     out_header_[ohs++] = i;
             }
             union {
                 uint16_t p;
                 char b[2];
             } portu;
             portu.p = htons(sport);
             out_header_[ohs++] = portu.b[0];
             out_header_[ohs++] = portu.b[1];
             // Forward it to the client socket.
             out_bufs_.push_back(boost::asio::buffer(out_header_.data(), ohs));
             out_bufs_.push_back(boost::asio::buffer(outbuf_));
             client_socket_.async_send_to
                 (out_bufs_, client_remote_endpoint_, strand_.wrap(
                  [this, sfd](const boost::system::error_code &ec,
                              std::size_t bytes_xferred)
                  {
                      udp_remote_socket_read();
                  }));
         }));
}

ClientListener::ClientListener(const ba::ip::tcp::endpoint &endpoint)
        : acceptor_(io_service), endpoint_(endpoint), socket_(io_service)
{
    acceptor_.open(endpoint_.protocol());
    acceptor_.set_option(ba::ip::tcp::acceptor::reuse_address(true));
    acceptor_.non_blocking(true);
    acceptor_.bind(endpoint_);
    acceptor_.listen(listen_queuelen);
    start_accept();
}

void ClientListener::start_accept()
{
    acceptor_.async_accept
        (socket_, endpoint_,
         [this](const boost::system::error_code &ec)
         {
             if (!ec)
                 conntracker_hs->emplace(acceptor_.get_io_service(),
                                         std::move(socket_));
             start_accept();
         });
}
