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

#include <boost/dynamic_bitset.hpp>

#include <nk/tyche.hpp>

#ifdef HAS_64BIT
#include <boost/lockfree/stack.hpp>
#endif

#include "socksclient.hpp"
#include "socks_tracker.hpp"
#include "asio_addrcmp.hpp"

#define MAX_BIND_TRIES 10
#define MAX_PIPE_FLUSH_TRIES 10
#define UDP_BUFSIZE 1536

#define SPLICE_MIN_XFER 64

extern asio::io_service io_service;
extern bool gParanoid;
extern bool gChrooted;

std::unique_ptr<nk::net::adns_resolver> g_adns;

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

static nk::rng::tyche g_random_prng;

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

void init_conntrackers(std::size_t hs_secs, std::size_t bindlisten_secs)
{
    conntracker_hs = std::make_unique<ephTrackerVec<SocksInit>>
        (io_service, hs_secs);
    conntracker_bindlisten = std::make_unique<ephTrackerList<SocksInit>>
        (io_service, bindlisten_secs);
}

#ifdef USE_SPLICE
void pipe_close_raw(std::size_t p_len,
                    asio::posix::stream_descriptor &sa,
                    asio::posix::stream_descriptor &sb)
{
    std::error_code ec;
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

static inline void close_paired_sockets(asio::ip::tcp::socket &a, asio::ip::tcp::socket &b)
{
    std::error_code ec;
    a.close(ec);
    b.close(ec);
}

std::vector<std::pair<asio::ip::address, unsigned int>> g_dst_deny_masks;
std::vector<std::pair<asio::ip::address, unsigned int>> g_client_bind_allow_masks;
std::vector<std::pair<asio::ip::address, unsigned int>> g_client_udp_allow_masks;

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

static inline size_t send_reply_code_v5(std::array<char, 24> &arr, SocksInit::ReplyCode replycode)
{
    arr[0] = 0x05;
    arr[1] = replycode;
    arr[2] = 0;
    return 3;
}

static inline size_t send_reply_binds_v5(std::array<char, 24> &arr, std::size_t asiz,
                                         asio::ip::tcp::endpoint ep)
{
    const auto bnd_addr = ep.address();
    if (bnd_addr.is_v4()) {
        const auto v4b = bnd_addr.to_v4().to_bytes();
        arr[asiz++] = 0x01;
        for (const auto &i: v4b)
            arr[asiz++] = i;
    } else {
        const auto v6b = bnd_addr.to_v6().to_bytes();
        arr[asiz++] = 0x04;
        for (const auto &i: v6b)
            arr[asiz++] = i;
    }
    const uint16_t p{htons(ep.port())};
    memcpy(&arr[asiz], &p, sizeof p);
    asiz += sizeof p;
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

static inline size_t send_reply_binds_v4(std::array<char, 24> &arr, std::size_t asiz,
                                         asio::ip::tcp::endpoint ep)
{
    const uint16_t p{htons(ep.port())};
    memcpy(&arr[asiz], &p, sizeof p);
    asiz += sizeof p;

    const auto bnd_addr = ep.address();
    assert(bnd_addr.is_v4());
    const auto v4b = bnd_addr.to_v4().to_bytes();
    for (const auto &i: v4b)
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

SocksInit::SocksInit(asio::io_service &io_service, asio::ip::tcp::socket client_socket)
        : tracked_(true), strand_(io_service),
          client_socket_(std::move(client_socket)),
          remote_socket_(io_service), pstate_(ParsedState::Parsed_None),
          ibSiz_(0), poff_(0), ptmp_(0), is_socks_v4_(false), socks_v4_dns_(false),
          auth_none_(false), auth_gssapi_(false), auth_unpw_(false), dnsq_v6_{g_disable_ipv6},
          dnsq_v4_{false}
{
    if (g_verbose_logs)
        ++socks_alive_count;
    client_socket_.non_blocking(true);
    client_socket_.set_option(asio::ip::tcp::no_delay(true));
    client_socket_.set_option(asio::socket_base::keep_alive(true));
#ifdef TCP_QUICKACK
    const asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_QUICKACK> quickack(true);
    client_socket_.set_option(quickack);
#endif
}

SocksInit::~SocksInit()
{
    if (bound_) {
        bool cxr(true);
        if (tracked_.compare_exchange_strong(cxr, false)) {
            conntracker_bindlisten->erase(get_tracker_iterator(),
                                          get_tracker_idx());
        }
    }
    if (g_verbose_logs) {
        --socks_alive_count;
        print_trackers_logentry(dst_hostname_.size() ? dst_hostname_
                                  : dst_address_.to_string(),
                                  dst_port_);
    }
}

SocksInit::BoundSocket::BoundSocket(asio::io_service &io_service, asio::ip::tcp::endpoint lep)
        : acceptor_(io_service), local_endpoint_(lep)
{
    std::error_code ec;
    acceptor_.open(lep.protocol(), ec);
    if (ec)
        throw std::runtime_error("open failed");
    acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true), ec);
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

void SocksInit::expire_timeout()
{
    auto sfd = shared_from_this();
    strand_.post([self{std::move(sfd)}]() {
        self->set_untracked();
        self->terminate();
    });
}

void SocksInit::expire_timeout_nobind()
{
    logfmt("SocketInit: timed out\n");
    auto sfd = shared_from_this();
    strand_.post([self{std::move(sfd)}]() {
        if (!self->is_bind_listen())
            self->terminate();
    });
}

void SocksInit::terminate()
{
    std::error_code ec;
    if (bound_)
        bound_->acceptor_.cancel(ec);
    close_paired_sockets(remote_socket_, client_socket_);
}

void SocksInit::read_greet()
{
    auto sfd = shared_from_this();
    client_socket_.async_read_some
        (asio::buffer(sockbuf_.data() + ibSiz_, sockbuf_.size() - ibSiz_),
         strand_.wrap(
         [this, sfd{std::move(sfd)}](const std::error_code &ec, std::size_t bytes_xferred)
         {
             size_t consumed;
             std::optional<SocksInit::ReplyCode> rc;
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
             if (ec == asio::error::operation_aborted) {
                 return;
             } else if (ec != asio::error::eof) {
                 logfmt("read_greet() error: {}\n", std::system_error(ec).what());
             }
             terminate();
         }));
}

// We don't support authentication.
static const char reply_greetz[2] = {'\x5','\x0'};

std::optional<SocksInit::ReplyCode>
SocksInit::parse_greet(std::size_t &consumed)
{
    consumed = 0;
    switch (pstate_) {
    case Parsed_None: {
        if (ibSiz_ - poff_ < 1)
            return {};
        ++consumed;
        auto c = sockbuf_[poff_++];
        if (c == 0x05) {
            pstate_ = Parsed5G_Version;
        } else if (c == 0x04) {
            pstate_ = Parsed4G_Version;
            is_socks_v4_ = true;
            goto p4g_version;
        } else {
            logfmt("Fail: Parsed_None\n");
            return RplFail;
        }
    }
    case Parsed5G_Version: {
        if (ibSiz_ - poff_ < 1)
            return {};
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
            if (poff_ != ibSiz_) { // Reject if there are excess bytes in buffer.
                logfmt("Fail: Parsed5G_NumAuth: poff_ != ibSiz_\n");
                return RplFail;
            }
            if (!auth_none_) {
                logfmt("Fail: Parsed5G_NumAuth: !auth_none_\n");
                return RplFail;
            }
        } else if (ptmp_ > 0) {
            return {};
        } else {
            logfmt("Fail: Parsed5G_NumAuth\n");
            return RplFail;
        }
    }
    case Parsed5G_Auth: {
        auto sfd = shared_from_this();
        asio::async_write(
            client_socket_, asio::buffer(reply_greetz, sizeof reply_greetz),
            strand_.wrap(
                [this, sfd{std::move(sfd)}](const std::error_code &ec, std::size_t bytes_xferred)
                {
                    if (ec) {
                        logfmt("failed writing reply_greetz: {}\n", std::system_error(ec).what());
                        terminate();
                    }
                }));
        pstate_ = Parsed5G_Replied;
        return {};
    }
p4g_version:
    case Parsed4G_Version: {
        if (ibSiz_ - poff_ < 1)
            return {};
        pstate_ = Parsed4G_Cmd;
        ++consumed;
        auto c = sockbuf_[poff_++];
        if (c == 0x1) {
            cmd_code_ = CmdTCPConnect;
        } else if (c == 0x2) {
            cmd_code_ = CmdTCPBind;
        } else {
            return RplCmdNotSupp;
        }
    }
    case Parsed4G_Cmd: {
        if (ibSiz_ - poff_ < 2)
            return {};
        pstate_ = Parsed4G_DPort;
        consumed += 2;
        uint16_t tmp;
        memcpy(&tmp, sockbuf_.data() + poff_, 2);
        dst_port_ = ntohs(tmp);
        poff_ += 2;
    }
    case Parsed4G_DPort: {
        if (ibSiz_ - poff_ < 4)
            return {};
        pstate_ = Parsed4G_DAddr;
        consumed += 4;
        if (sockbuf_[poff_  ] == 0x0 &&
            sockbuf_[poff_+1] == 0x0 &&
            sockbuf_[poff_+2] == 0x0 &&
            sockbuf_[poff_+3] != 0x0) {
            socks_v4_dns_ = true;
        } else {
            asio::ip::address_v4::bytes_type v4o;
            memcpy(v4o.data(), sockbuf_.data() + poff_, 4);
            dst_address_ = asio::ip::address_v4(v4o);
            dst_eps_.emplace_back(dst_address_, dst_port_);
        }
        poff_ += 4;
    }
    case Parsed4G_DAddr: {
        // Null-terminated userid.
        for (auto i = poff_; i < ibSiz_; ++i) {
            if (sockbuf_[i] == '\0') {
                poff_ += (i - poff_ + 1);
                consumed += (i - poff_ + 1);
                if (!socks_v4_dns_) {
                    pstate_ = Parsed_Finished;
                    goto parsed_finished;
                } else {
                    pstate_ = Parsed4G_Userid;
                    break;
                }
            }
            if (i - poff_ > 64) {
                logfmt("Fail: Parsed4G_DAddr\n");
                return RplFail;
            }
        }
        if (pstate_ != Parsed4G_Userid)
            return {};
    }
    case Parsed4G_Userid: {
        // Null-terminated DNS hostname.
        for (auto i = poff_; i < ibSiz_; ++i) {
            if (sockbuf_[i] == '\0') {
                dst_hostname_.append(sockbuf_.data() + poff_, i - poff_);
                poff_ += (i - poff_ + 1);
                consumed += (i - poff_ + 1);
                pstate_ = Parsed_Finished;
                goto parsed_finished;
            }
            if (i - poff_ > 512) {
                logfmt("Fail: Parsed4G_Userid\n");
                return RplFail;
            }
        }
        return {};
    }
    case Parsed5G_Replied: {
        if (ibSiz_ - poff_ < 1)
            return {};
        pstate_ = Parsed5CR_Version;
        ++consumed;
        auto c = sockbuf_[poff_++];
        if (c != 0x5) {
            logfmt("Fail: Parsed5G_Replied\n");
            return RplFail;
        }
    }
    case Parsed5CR_Version: {
        if (ibSiz_ - poff_ < 1)
            return {};
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
            return {};
        pstate_ = Parsed5CR_Resv;
        ++consumed;
        auto c = sockbuf_[poff_++];
        if (c != 0x0) {
            logfmt("Fail: Parsed5CR_Cmd\n");
            return RplFail;
        }
    }
    case Parsed5CR_Resv: {
        if (ibSiz_ - poff_ < 1)
            return {};
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
                return {};
            pstate_ = Parsed5CR_DAddr;
            consumed += 4;
            asio::ip::address_v4::bytes_type v4o;
            memcpy(v4o.data(), sockbuf_.data() + poff_, 4);
            dst_address_ = asio::ip::address_v4(v4o);
            dst_eps_.emplace_back(dst_address_, dst_port_);
            poff_ += 4;
        } else if (addr_type_ == AddrIPv6) {
            if (ibSiz_ - poff_ < 16)
                return {};
            pstate_ = Parsed5CR_DAddr;
            consumed += 16;
            asio::ip::address_v6::bytes_type v6o;
            memcpy(v6o.data(), sockbuf_.data() + poff_, 16);
            dst_address_ = asio::ip::address_v6(v6o);
            dst_eps_.emplace_back(dst_address_, dst_port_);
            poff_ += 16;
            if (g_disable_ipv6)
                return RplAddrNotSupp;
        } else if (addr_type_ == AddrDNS) {
            if (ibSiz_ - poff_ < 1)
                return {};
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
            return {};
        pstate_ = Parsed_Finished;
        consumed += 2;
        uint16_t tmp;
        memcpy(&tmp, sockbuf_.data() + poff_, 2);
        dst_port_ = ntohs(tmp);
        poff_ += 2;
    }
parsed_finished:
        ibSiz_ = 0;
        poff_ = 0;
        dispatch_connrq();
    case Parsed_Finished: {
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
            return {};
        goto parsed5cr_daddr;
    }
    default: throw std::logic_error("undefined parse state");
    }
    return {};
}

static const auto loopback_addr_v4 = asio::ip::address_v4::from_string("127.0.0.0");
static const auto loopback_addr_v6 = asio::ip::address_v6::from_string("::1");

static bool is_dst_denied(const asio::ip::address &addr)
{
    // Deny proxy attempts to the local loopback addresses.
    if (addr == loopback_addr_v6 ||
        asio::compare_ip(addr, loopback_addr_v4, 8))
        return true;
    for (const auto &i: g_dst_deny_masks) {
        auto r = asio::compare_ip(addr, std::get<0>(i), std::get<1>(i));
        if (r) {
            logfmt("DENIED connection to {}\n", addr.to_string());
            return true;
        }
    }
    return false;
}

void SocksInit::dnslookup_cb(void *self_, int status, int timeouts, struct hostent *host)
{
    auto spp = reinterpret_cast<std::shared_ptr<SocksInit> *>(self_);
    auto self = std::move(*spp);
    delete spp;
    if (!self) return;

    std::error_code ec{};
    switch (status) {
    case ARES_SUCCESS:
        break;
    case ARES_ENOTIMP:
        ec = asio::error::socket_type_not_supported;
        break;
    case ARES_EBADNAME:
        ec = asio::error::no_data;
        break;
    case ARES_ENOTFOUND:
        ec = asio::error::host_not_found;
        break;
    case ARES_ENOMEM:
        ec = asio::error::no_memory;
        break;
    case ARES_EDESTRUCTION:
        ec = asio::error::shut_down;
        break;
    default:
        ec = asio::error::no_recovery;
        break;
    }

    std::vector<asio::ip::address> addrs;
    {
        size_t rsv{0};
        for (auto p = host->h_addr_list; *p; ++p, ++rsv);
        addrs.reserve(rsv);
    }
    for (auto p = host->h_addr_list; *p; ++p) {
        char addr_buf[64];
        ares_inet_ntop(host->h_addrtype, *p, addr_buf, sizeof addr_buf);
        std::error_code ecc;
        auto a = asio::ip::address::from_string(addr_buf, ecc);
        if (ecc) continue;
        // It's possible for the resolver to return an address
        // that is unspecified after lookup, eg, host file blocking.
        if (a.is_unspecified()) continue;
        addrs.emplace_back(std::move(a));
    }
    std::shuffle(addrs.begin(), addrs.end(), g_random_prng);

    self->strand_.post([s = self, e = ec, v = std::move(addrs)]() {
        s->dns_complete(e, v);
    });
}

void SocksInit::dns_complete(const std::error_code &ec, const std::vector<asio::ip::address> &addrs)
{
    if (!client_socket_.is_open())
        return;

    if (ec) {
        if (ec == asio::error::operation_aborted)
            return;
        logfmt("DNS lookup failed: '{}'\n", dst_hostname_);
        send_reply(RplHostUnreach);
        return;
    }

    for (const auto &i: addrs) {
        if (is_dst_denied(i)) continue;
        dst_eps_.emplace_back(i, dst_port_);
    }

    if (dst_eps_.empty()) {
        if (!dnsq_v6_) {
            raw_dns_lookup(AF_INET6);
        } else if (!dnsq_v4_) {
            raw_dns_lookup(AF_INET);
        } else {
            logfmt("DNS has no associated addresses: '{}'\n", dst_hostname_);
            send_reply(RplHostUnreach);
        }
        return;
    }
    dispatch_tcp_connect();
}

void SocksInit::raw_dns_lookup(int af)
{
    // Handle the case where dst_hostname_ is actually an ip address.
    if (!dst_hostname_.empty()) {
        std::error_code ec;
        auto a = asio::ip::address::from_string(dst_hostname_, ec);
        if (!ec) {
            dst_eps_.emplace_back(a, dst_port_);
            dispatch_tcp_connect();
            return;
        }
    }
    if (af == AF_INET) dnsq_v4_ = true;
    if (af == AF_INET6) dnsq_v6_ = true;
    auto spp = new std::shared_ptr<SocksInit>{shared_from_this()};
    g_adns->query_hostname(dst_hostname_.c_str(), af, SocksInit::dnslookup_cb, spp);
}

void SocksInit::dispatch_connrq()
{
    if (!dst_hostname_.empty()) {
        raw_dns_lookup((g_prefer_ipv4 || g_disable_ipv6) ? AF_INET : AF_INET6);
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

void SocksInit::dispatch_tcp_connect()
{
    // Connect to the remote address.  If we connect successfully, then
    // open a proxying local tcp socket and inform the requesting client.
    auto sfd = shared_from_this();
    asio::async_connect(remote_socket_, dst_eps_, strand_.wrap(
         [this, sfd{std::move(sfd)}](const std::error_code &ec, asio::ip::tcp::endpoint ep)
         {
             if (ec) {
                 if (ec == asio::error::operation_aborted)
                    return;
                 send_reply(errorToReplyCode(ec));
                 return;
             }
             if (const auto ecc = set_remote_socket_options(); ecc) {
                 logfmt("set_remote_socket_options failed\n");
                 send_reply(errorToReplyCode(ecc));
                 return;
             }
             conntracker_tcp.emplace(ep, io_service,
                   std::move(client_socket_), std::move(remote_socket_),
                   ep.address(), dst_port_, false, bool(is_socks_v4_),
                   std::move(dst_hostname_));
         }));
}

SocksInit::ReplyCode
SocksInit::errorToReplyCode(const std::error_code &ec)
{
    ReplyCode rc(RplConnRefused);
    logfmt("ASIO error code: {}: {}\n", ec.value(), ec.message());
    if (ec == asio::error::access_denied ||
        ec == asio::error::connection_refused) {
        rc = RplConnRefused;
    } else if (ec == asio::error::address_family_not_supported ||
               ec == asio::error::fault || ec == asio::error::service_not_found ||
               ec == asio::error::socket_type_not_supported) {
        rc = RplAddrNotSupp;
    } else if (ec == asio::error::timed_out || ec == asio::error::operation_aborted) {
        rc = RplTTLExpired;
    } else if (ec == asio::error::host_unreachable) {
        rc = RplHostUnreach;
    } else if (ec == asio::error::network_unreachable) {
        rc = RplNetUnreach;
    }
    return rc;
}

bool SocksInit::is_bind_client_allowed() const
{
    std::error_code ec;
    auto cep = client_socket_.remote_endpoint(ec);
    if (ec) {
        logfmt("DENIED bind request; client has bad remote_endpoint: {}\n",
               ec.message());
        return false;
    }
    auto laddr = cep.address();
    for (const auto &i: g_client_bind_allow_masks) {
        auto r = asio::compare_ip(laddr, std::get<0>(i), std::get<1>(i));
        if (r)
            return true;
    }
    logfmt("DENIED bind request from {}\n", laddr.to_string());
    return false;
}

bool SocksInit::create_bind_socket(asio::ip::tcp::endpoint ep)
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
    asio::ip::tcp::endpoint bind_ep;
    auto rcnct = conntracker_tcp.find_by_addr_port(dst_address_, dst_port_);
    try {
        if (rcnct) {
            // Bind to the local IP that is associated with the
            // client-specified dst_address_ and dst_port_.
            std::error_code ec;
            auto rlep = (*rcnct)->remote_socket_local_endpoint(ec);
            if (ec) {
                send_reply(RplDeny);
                return;
            }
            bind_ep = asio::ip::tcp::endpoint(rlep.address(), BPA->get_port());
        } else {
            if (!is_bind_client_allowed()) {
                send_reply(RplDeny);
                return;
            }
            bind_ep = asio::ip::tcp::endpoint
                (!g_disable_ipv6 ? asio::ip::tcp::v6() : asio::ip::tcp::v4(),
                 BPA->get_port());
        }
    } catch (const std::out_of_range &) {
        // No ports are free for use as a local endpoint.
        logfmt("Fail: dispatch_tcp_bind: no ports are free\n");
        send_reply(RplFail);
        return;
    }

    if (!create_bind_socket(bind_ep)) {
        logfmt("Fail: dispatch_tcp_bind: no ports are free\n");
        send_reply(RplFail);
        return;
    }
    conntracker_bindlisten->store(shared_from_this());

    auto sfd = shared_from_this();
    bound_->acceptor_.async_accept
        (remote_socket_, strand_.wrap(
         [this, sfd{std::move(sfd)}](const std::error_code &ec)
         {
             if (ec) {
                 logfmt("Fail: dispatch_tcp_bind: accept failed\n");
                 send_reply(RplFail);
                 return;
             }
             logfmt("Accepted a connection to a BIND socket.\n");

             std::error_code ecc;
             auto ep = remote_socket_.local_endpoint(ecc);
             if (ecc) {
                 logfmt("TCP Bind: [{}] rs.local_endpoint: {}\n", dst_hostname_.size()?
                        dst_hostname_ : dst_address_.to_string(), ecc.message());
                 send_reply(RplFail);
                 return;
             }

             if (const auto ecc = set_remote_socket_options(); ecc) {
                   logfmt("set_remote_socket_options failed {}: {}\n", ecc.value(), ecc.message());
                   send_reply(RplFail);
                   return;
             }
             conntracker_tcp.emplace(ep, io_service,
                   std::move(client_socket_), std::move(remote_socket_),
                   std::move(dst_address_), dst_port_, true, bool(is_socks_v4_),
                   std::move(dst_hostname_));
         }));
    // Here we send the first response; the BND field corresponds
    // to remote_socket_.local_endpoint().
    std::size_t ssiz(0);
    if (!is_socks_v4_) {
        ssiz = send_reply_code_v5(sockbuf_, RplSuccess);
        ssiz = send_reply_binds_v5(sockbuf_, ssiz, bind_ep);
    } else {
        ssiz = send_reply_code_v4(sockbuf_, RplSuccess);
        ssiz = send_reply_binds_v4(sockbuf_, ssiz, bind_ep);
    }
    do_send_reply(RplSuccess, ssiz);
}

bool SocksInit::is_udp_client_allowed(asio::ip::address laddr) const
{
    for (const auto &i: g_client_udp_allow_masks) {
        auto r = asio::compare_ip(laddr, std::get<0>(i), std::get<1>(i));
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
    std::error_code ec;
    auto client_rep = client_socket_.remote_endpoint(ec);
    if (ec || !is_udp_client_allowed(client_rep.address())) {
        send_reply(RplDeny);
        return;
    }
    asio::ip::udp::endpoint udp_client_ep, udp_remote_ep;
    uint16_t udp_local_port, udp_remote_port;
    auto client_lep = client_socket_.local_endpoint(ec);
    if (ec) {
        send_reply(RplFail);
        return;
    }
    auto laddr(client_lep.address());
    try {
        udp_local_port = UPA->get_port();
        udp_client_ep = asio::ip::udp::endpoint(laddr, udp_local_port);
    } catch (const std::out_of_range &) {
        // No ports are free for use as a local endpoint.
        send_reply(RplFail);
        return;
    }
    try {
        udp_remote_port = UPA->get_port();
        udp_remote_ep = asio::ip::udp::endpoint
            (!g_disable_ipv6 ? asio::ip::udp::v6() : asio::ip::udp::v4(),
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
         asio::ip::udp::endpoint(client_rep.address(), client_rep.port()));
    ct->start();
}

void SocksInit::do_send_reply(ReplyCode replycode, std::size_t ssiz)
{
    auto sfd = shared_from_this();
    asio::async_write
        (client_socket_,
         asio::buffer(sockbuf_.data(), ssiz),
         strand_.wrap(
         [this, sfd{std::move(sfd)}, replycode](const std::error_code &ec,
                                                std::size_t bytes_xferred)
         {
             if (ec || replycode != RplSuccess) {
                 std::error_code ecc;
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

// Only used for sending error replies.
void SocksInit::send_reply(ReplyCode replycode)
{
    std::size_t ssiz(0);
    assert(replycode != RplSuccess);
    if (!is_socks_v4_) {
        assert(replycode != RplIdentWrong && replycode != RplIdentUnreach);
        ssiz = send_reply_code_v5(sockbuf_, replycode);
    } else {
        ssiz = send_reply_code_v4(sockbuf_, replycode);
        for (auto i = 0; i < 6; ++i)
            sockbuf_[ssiz++] = 0;
    }
    do_send_reply(replycode, ssiz);
}

SocksTCP::SocksTCP(asio::io_service &io_service, asio::ip::tcp::socket client_socket,
                   asio::ip::tcp::socket remote_socket, asio::ip::address dst_address,
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
    bool cxr(true);
    if (tracked_.compare_exchange_strong(cxr, false))
        conntracker_tcp.erase(get_tracker_iterator());
    close_paired_sockets(client_socket_, remote_socket_);
    if (g_verbose_logs) {
        --socks_alive_count;
        print_trackers_logentry(dst_hostname_.size() ? dst_hostname_
                                  : dst_address_.to_string(),
                                  dst_port_);
    }
}

#ifdef USE_SPLICE
bool SocksTCP::init_pipe(asio::posix::stream_descriptor &preader,
                         asio::posix::stream_descriptor &pwriter)
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
        strand_.post([this, sfd{std::move(sfd)}, cso, rso, dir] {
                     std::error_code ec;
                     if (cso)
                         client_socket_.shutdown(asio::ip::tcp::socket::shutdown_receive, ec);
                     if (rso)
                         remote_socket_.shutdown(asio::ip::tcp::socket::shutdown_receive, ec);
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

inline SocksTCP::splicePipeRet SocksTCP::spliceRemoteToPipe()
{
    auto spliced = splice(remote_socket_.native_handle(), NULL,
                          pToClientW_.native_handle(), NULL,
                          splice_pipe_size, SPLICE_F_NONBLOCK);
    if (spliced > 0) {
        pToClient_len_ += spliced;
        return splicePipeRet::ok;
    }
    if (spliced == 0 || (spliced < 0 && errno == EPIPE)) {
        flush_then_terminate(FlushDirection::Client);
        return splicePipeRet::eof;
    }
    switch (errno) {
    case EINTR: tcp_remote_socket_read_splice(); return splicePipeRet::interrupt;
    case EAGAIN:
                // EAGAIN can mean the pipe is full, or it can mean that
                // the pipe write would block for another reason.
                if (pToClient_len_ > 0) {
                    tcp_remote_socket_write_splice(0);
                    return splicePipeRet::interrupt;
                }
                tcp_remote_socket_read_splice();
                return splicePipeRet::would_block;
    case EBADF:
                 // Splicing from a remote_socket_ that has been shutdown()'ed
                 // will fail with EBADF.
                 if (flush_invoked_) {
                     logfmt("rs: [{}] noticed shutdown: {}\n", dst_hostname_.size()?
                            dst_hostname_ : dst_address_.to_string(), strerror(errno));
                     flush_then_terminate(FlushDirection::Client);
                     return splicePipeRet::error;
                 }
    default: break;
    }
    logfmt("rs: [{}] splice: {}\n", dst_hostname_.size()?
           dst_hostname_ : dst_address_.to_string(), strerror(errno));
    flush_then_terminate(FlushDirection::Client);
    return splicePipeRet::error;
}

inline SocksTCP::splicePipeRet SocksTCP::spliceClientToPipe()
{
    auto spliced = splice(client_socket_.native_handle(), NULL,
                          pToRemoteW_.native_handle(), NULL,
                          splice_pipe_size, SPLICE_F_NONBLOCK);
    if (spliced > 0) {
        pToRemote_len_ += spliced;
        return splicePipeRet::ok;
    }
    if (spliced == 0 || (spliced < 0 && errno == EPIPE)) {
        flush_then_terminate(FlushDirection::Remote);
        return splicePipeRet::eof;
    }
    switch (errno) {
    case EINTR: tcp_client_socket_read_splice(); return splicePipeRet::interrupt;
    case EAGAIN:
                // EAGAIN can mean the pipe is full, or it can mean that
                // the pipe write would block for another reason.
                if (pToRemote_len_ > 0) {
                    tcp_client_socket_write_splice(0);
                    return splicePipeRet::interrupt;
                }
                tcp_client_socket_read_splice();
                return splicePipeRet::would_block;
    case EBADF:
                 // Splicing from a client_socket_ that has been shutdown()'ed
                 // will fail with EBADF.
                 if (flush_invoked_) {
                     logfmt("cs: [{}] noticed shutdown: {}\n", dst_hostname_.size()?
                            dst_hostname_ : dst_address_.to_string(), strerror(errno));
                     flush_then_terminate(FlushDirection::Remote);
                     return splicePipeRet::error;
                 }
    default: break;
    }
    logfmt("cs: [{}] splice: {}\n", dst_hostname_.size()?
           dst_hostname_ : dst_address_.to_string(), strerror(errno));
    flush_then_terminate(FlushDirection::Remote);
    return splicePipeRet::error;
}

inline SocksTCP::splicePipeRet SocksTCP::splicePipeToClient(size_t *xferred)
{
    if (xferred) *xferred = 0;
    if (pToClient_len_ <= 0)
        return splicePipeRet::ok;
    auto n = splice(pToClientR_.native_handle(), NULL,
                    client_socket_.native_handle(), NULL,
                    splice_pipe_size, SPLICE_F_NONBLOCK);
    if (xferred && n > 0) *xferred = n;
    if (n > 0) {
        pToClient_len_ -= n;
        return splicePipeRet::ok;
    }
    if (n == 0 || (n < 0 && errno == EPIPE))
        return splicePipeRet::eof;
    if (n < 0 && (errno == EINTR || errno == EAGAIN))
        return splicePipeRet::interrupt;
    return splicePipeRet::error;
}

inline SocksTCP::splicePipeRet SocksTCP::splicePipeToRemote(size_t *xferred)
{
    if (xferred) *xferred = 0;
    if (pToRemote_len_ <= 0)
        return splicePipeRet::ok;
    auto n = splice(pToRemoteR_.native_handle(), NULL,
                    remote_socket_.native_handle(), NULL,
                    splice_pipe_size, SPLICE_F_NONBLOCK);
    if (xferred && n > 0) *xferred = n;
    if (n > 0) {
        pToRemote_len_ -= n;
        return splicePipeRet::ok;
    }
    if (n == 0 || (n < 0 && errno == EPIPE))
        return splicePipeRet::eof;
    if (n < 0 && (errno == EINTR || errno == EAGAIN))
        return splicePipeRet::interrupt;
    return splicePipeRet::error;
}

void SocksTCP::tcp_client_socket_write_splice(int tries)
{
    ++tries;
    auto sfd = shared_from_this();
    remote_socket_.async_write_some
        (asio::null_buffers(), strand_.wrap(
         [this, sfd{std::move(sfd)}, tries](const std::error_code &ec, std::size_t bytes_xferred)
         {
             splicePipeRet spr;
             if (ec) goto ec_err;
             if ((spr = splicePipeToRemote()) < splicePipeRet::interrupt) goto splice_err;
             if (pToRemote_len_ > 0) {
                 tcp_client_socket_write_splice(tries);
                 return;
             }
             if (tries < 3)
                 tcp_client_socket_read_splice();
             else
                 tcp_client_socket_read_stopsplice();
             return;
splice_err:
             if (spr != splicePipeRet::eof) {
                 logfmt("rs/tcp_client_socket_write_splice: [{}] splice: {}\n",
                        dst_hostname_.size()?  dst_hostname_ : dst_address_.to_string(),
                        strerror(errno));
             }
             flush_then_terminate(FlushDirection::Client);
             return;
ec_err:
             if (ec != asio::error::operation_aborted) {
                 logfmt("cs: [{}] async_write_some: {}\n",
                        dst_hostname_.size()?  dst_hostname_ : dst_address_.to_string(),
                        std::system_error(ec).what());
                 flush_then_terminate(FlushDirection::Client);
             }
         }));
}

void SocksTCP::tcp_remote_socket_write_splice(int tries)
{
    ++tries;
    auto sfd = shared_from_this();
    client_socket_.async_write_some
        (asio::null_buffers(), strand_.wrap(
         [this, sfd{std::move(sfd)}, tries](const std::error_code &ec, std::size_t bytes_xferred)
         {
             splicePipeRet spr;
             if (ec) goto ec_err;
             if ((spr = splicePipeToClient()) < splicePipeRet::interrupt) goto splice_err;
             if (pToClient_len_ > 0) {
                 tcp_remote_socket_write_splice(tries);
                 return;
             }
             if (tries < 3)
                 tcp_remote_socket_read_splice();
             else
                 tcp_remote_socket_read_stopsplice();
             return;
splice_err:
             if (spr != splicePipeRet::eof) {
                 logfmt("cs/tcp_remote_socket_write_splice: [{}] splice: {}\n",
                        dst_hostname_.size()?  dst_hostname_ : dst_address_.to_string(),
                        strerror(errno));
             }
             flush_then_terminate(FlushDirection::Remote);
             return;
ec_err:
             if (ec != asio::error::operation_aborted) {
                 logfmt("rs: [{}] async_write_some: {}\n",
                        dst_hostname_.size()?  dst_hostname_ : dst_address_.to_string(),
                        std::system_error(ec).what());
                 flush_then_terminate(FlushDirection::Remote);
             }
         }));
}

// Write data read from the client socket to the connect socket.
void SocksTCP::tcp_client_socket_read_splice()
{
    auto sfd = shared_from_this();
    client_socket_.async_read_some
        (asio::null_buffers(), strand_.wrap(
         [this, sfd{std::move(sfd)}](const std::error_code &ec, std::size_t bytes_xferred)
         {
             splicePipeRet spr;
             if (ec) goto ec_err;
             while (spliceClientToPipe() == splicePipeRet::ok) {
                 size_t xf;
                 if ((spr = splicePipeToRemote(&xf)) < splicePipeRet::interrupt) goto spr_err;
                 // XXX: Could use a windowed average of xf.
                 if (xf < SPLICE_MIN_XFER && pToRemote_len_ == 0) {
                     tcp_client_socket_read_stopsplice();
                     return;
                 }
             }
             return;
spr_err:
             if (spr != splicePipeRet::eof) {
                 logfmt("rs/tcp_client_socket_read_splice: [{}] splice: {}\n",
                        dst_hostname_.size()?  dst_hostname_ : dst_address_.to_string(),
                        strerror(errno));
             }
             flush_then_terminate(FlushDirection::Client);
             return;
ec_err:
             if (ec != asio::error::operation_aborted) {
                 logfmt("cs: [{}] async_read_some: {}\n", dst_hostname_.size()?
                        dst_hostname_ : dst_address_.to_string(),
                        std::system_error(ec).what());
                 flush_then_terminate(FlushDirection::Remote);
             }
         }));
}

// Write data read from the connect socket to the client socket.
void SocksTCP::tcp_remote_socket_read_splice()
{
    auto sfd = shared_from_this();
    remote_socket_.async_read_some
        (asio::null_buffers(), strand_.wrap(
         [this, sfd{std::move(sfd)}](const std::error_code &ec, std::size_t bytes_xferred)
         {
             splicePipeRet spr;
             if (ec) goto ec_err;
             while (spliceRemoteToPipe() == splicePipeRet::ok) {
                 size_t xf;
                 if ((spr = splicePipeToClient(&xf)) < splicePipeRet::interrupt) goto spr_err;
                 // XXX: Could use a windowed average of xf.
                 if (xf < SPLICE_MIN_XFER && pToClient_len_ == 0) {
                     tcp_remote_socket_read_stopsplice();
                     return;
                 }
             }
             return;
spr_err:
             if (spr != splicePipeRet::eof) {
                 logfmt("cs/tcp_remote_socket_read_splice: [{}] splice: {}\n",
                        dst_hostname_.size()?  dst_hostname_ : dst_address_.to_string(),
                        strerror(errno));
             }
             flush_then_terminate(FlushDirection::Remote);
             return;
ec_err:
             if (ec != asio::error::operation_aborted) {
                 logfmt("rs: [{}] async_read_some: {}\n", dst_hostname_.size()?
                        dst_hostname_ : dst_address_.to_string(),
                        std::system_error(ec).what());
                 flush_then_terminate(FlushDirection::Client);
             }
         }));
}

void SocksTCP::doFlushPipeToRemote(int tries)
{
    ++tries;
    auto sfd = shared_from_this();
    remote_socket_.async_write_some
        (asio::null_buffers(), strand_.wrap(
         [this, sfd{std::move(sfd)}, tries](const std::error_code &ec, std::size_t bytes_xferred)
         {
             splicePipeRet spc;
             if (ec) {
                 if (ec == asio::error::operation_aborted)
                     return;
                 logfmt("rs-flush: [{}] async_write_some: {}\n",
                        dst_hostname_.size()?  dst_hostname_ : dst_address_.to_string(),
                        std::system_error(ec).what());
                 return;
             }
             if ((spc = splicePipeToRemote()) != splicePipeRet::ok) {
                 if (spc == splicePipeRet::interrupt && tries < MAX_PIPE_FLUSH_TRIES)
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
        (asio::null_buffers(), strand_.wrap(
         [this, sfd{std::move(sfd)}, tries](const std::error_code &ec, std::size_t bytes_xferred)
         {
             splicePipeRet spc;
             if (ec) {
                 if (ec == asio::error::operation_aborted)
                     return;
                 logfmt("cs-flush: [{}] async_write_some: {}\n",
                        dst_hostname_.size()?  dst_hostname_ : dst_address_.to_string(),
                        std::system_error(ec).what());
                 return;
             }
             if ((spc = splicePipeToClient()) != splicePipeRet::ok) {
                 if (spc == splicePipeRet::interrupt && tries < MAX_PIPE_FLUSH_TRIES)
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
    asio::streambuf::mutable_buffers_type ibm
        = client_buf_.prepare(send_buffer_chunk_size);
    auto sfd = shared_from_this();
    client_socket_.async_read_some
        (asio::buffer(ibm), strand_.wrap(
         [this, sfd{std::move(sfd)}](const std::error_code &ec, std::size_t bytes_xferred)
         {
             if (ec) {
                 if (ec != asio::error::operation_aborted)
                     flush_then_terminate(FlushDirection::Remote);
                 return;
             }
             client_buf_.commit(bytes_xferred);
             // Client is trying to send data to the remote server.  Write it
             // to the remote_socket_.
             std::error_code ecx;
             auto cbs = client_buf_.size();
             auto r = remote_socket_.send
                 (asio::buffer(client_buf_.data(), cbs), 0, ecx);
             if (r) {
                 client_buf_.consume(r);
                 if (r == cbs) {
                     tcp_client_socket_read_again(sfd, r, !client_buf_.size());
                     return;
                 }
             } else if (ecx != asio::error::would_block) {
                 if (ecx != asio::error::operation_aborted)
                     flush_then_terminate(FlushDirection::Client);
                 return;
             }
             asio::async_write
                 (remote_socket_, client_buf_, strand_.wrap(
                  [this, sfd{std::move(sfd)}](const std::error_code &ec, std::size_t bytes_xferred)
                  {
                      if (ec) {
                          if (ec != asio::error::operation_aborted)
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
    asio::streambuf::mutable_buffers_type ibm
        = remote_buf_.prepare(receive_buffer_chunk_size);
    auto sfd = shared_from_this();
    remote_socket_.async_read_some
        (asio::buffer(ibm), strand_.wrap(
         [this, sfd{std::move(sfd)}](const std::error_code &ec, std::size_t bytes_xferred)
         {
             if (ec) {
                 if (ec != asio::error::operation_aborted)
                     flush_then_terminate(FlushDirection::Client);
                 return;
             }
             remote_buf_.commit(bytes_xferred);
             // Remote server is trying to send data to the client.  Write it
             // to the client_socket_.
             std::error_code ecx;
             auto rbs = remote_buf_.size();
             auto r = client_socket_.send
                 (asio::buffer(remote_buf_.data(), rbs), 0, ecx);
             remote_buf_.consume(r);
             if (r) {
                 if (r == rbs) {
                     tcp_remote_socket_read_again(sfd, r, !remote_buf_.size());
                     return;
                 }
             } else if (ecx != asio::error::would_block) {
                 if (ecx != asio::error::operation_aborted)
                     flush_then_terminate(FlushDirection::Remote);
                 return;
             }
             asio::async_write
                 (client_socket_, remote_buf_, strand_.wrap(
                  [this, sfd{std::move(sfd)}](const std::error_code &ec, std::size_t bytes_xferred)
                  {
                      if (ec) {
                          if (ec != asio::error::operation_aborted)
                              flush_then_terminate(FlushDirection::Remote);
                          return;
                      }
                      remote_buf_.consume(bytes_xferred);
                      tcp_remote_socket_read_again(sfd, bytes_xferred,
                                                   remote_buf_.size() == 0);
                  }));
         }));
}

bool SocksTCP::matches_dst(const asio::ip::address &addr, uint16_t port) const
{
    if (!asio::compare_ip(addr, dst_address_, 128))
        return false;
    if (dst_port_ != port)
        return false;
    if (is_bind_)
        return false;
    return true;
}

void SocksTCP::start(asio::ip::tcp::endpoint ep)
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
    auto siz = std::min(ssiz, asio::buffer_size(ibm));
    memcpy(asio::buffer_cast<char *>(ibm), sbuf.data(), siz);
    client_buf_.commit(siz);

    auto sfd = shared_from_this();
    asio::async_write
        (client_socket_, client_buf_, strand_.wrap(
         [this, sfd{std::move(sfd)}](const std::error_code &ec, std::size_t bytes_xferred)
         {
             client_buf_.consume(bytes_xferred);
             if (ec) {
                 if (ec != asio::error::operation_aborted) {
                     std::error_code ecc;
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

SocksUDP::SocksUDP(asio::io_service &io_service, asio::ip::tcp::socket tcp_client_socket,
                   asio::ip::udp::endpoint client_ep, asio::ip::udp::endpoint remote_ep,
                   asio::ip::udp::endpoint client_remote_ep)
        : tcp_client_socket_(std::move(tcp_client_socket)),
          client_endpoint_(client_ep), remote_endpoint_(remote_ep),
          client_remote_endpoint_(client_remote_ep),
          strand_(io_service),
          client_socket_(io_service, client_ep),
          remote_socket_(io_service, remote_ep), dnsq_v6_{false}, dnsq_v4_{false}
{
    if (g_verbose_logs) {
        ++socks_alive_count;
        ++udp_alive_count;
    }
}

SocksUDP::~SocksUDP()
{
    close_udp_sockets();
    if (g_verbose_logs) {
        --socks_alive_count;
        --udp_alive_count;
        print_trackers_logentry("(n/a)", 0);
    }
}

void SocksUDP::start()
{
    std::array<char, 24> sbuf;
    std::size_t ssiz;

    ssiz = send_reply_code_v5(sbuf, SocksInit::ReplyCode::RplSuccess);
    std::error_code ecc;
    auto ep = client_socket_.local_endpoint(ecc);
    if (ecc) {
        logfmt("SocksUDP::start(): client socket has bad endpoint: {}\n",
               ecc.message());
        return;
    }
    ssiz = send_reply_binds_v5
        (sbuf, ssiz, asio::ip::tcp::endpoint(ep.address(), ep.port()));
    memcpy(out_header_.data(), sbuf.data(), ssiz);
    auto sfd = shared_from_this();
    asio::async_write
        (tcp_client_socket_, asio::buffer(out_header_.data(), ssiz),
         [this, sfd{std::move(sfd)}](const std::error_code &ec, std::size_t bytes_xferred)
         {
             if (ec) {
                 if (ec != asio::error::operation_aborted) {
                     std::error_code ecr;
                     auto rep = tcp_client_socket_.remote_endpoint(ecr);
                     logfmt("UDP Start: @{} [{}]\n",
                            !ecr? rep.address().to_string() : "NONE",
                            ec.message());
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
    std::error_code ec;
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
        (asio::buffer(tcp_inbuf_.data(),
                    tcp_inbuf_.size()), strand_.wrap(
         [this, sfd{std::move(sfd)}](const std::error_code &ec, std::size_t bytes_xferred)
         {
             if (ec) {
                 if (ec != asio::error::operation_aborted) {
                     logfmt("Client closed TCP socket for UDP associate: {}\n",
                            std::system_error(ec).what());
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
        (asio::buffer(inbuf_),
         csender_endpoint_, strand_.wrap(
         [this, sfd{std::move(sfd)}](const std::error_code &ec, std::size_t bytes_xferred)
         {
             if (ec) {
                 if (ec != asio::error::operation_aborted) {
                     logfmt("Error on client UDP socket: {}\n", std::system_error(ec).what());
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
                 asio::ip::address daddr;
                 switch (atyp) {
                     case 1: { // IPv4
                         if (bytes_xferred < 10)
                             goto nosend;
                         asio::ip::address_v4::bytes_type v4o;
                         memcpy(v4o.data(), inbuf_.data() + headersiz, 4);
                         daddr_ = asio::ip::address_v4(v4o);
                         headersiz += 4;
                         break;
                     }
                     case 3: { // DNS
                         if (bytes_xferred < 8)
                             goto nosend;
                         size_t dnssiz = inbuf_[headersiz++];
                         if (bytes_xferred - headersiz < dnssiz + 2)
                             goto nosend;
                         dnsname_ = std::string
                             (reinterpret_cast<const  char *>
                              (inbuf_.data() + headersiz), dnssiz);
                         headersiz += dnssiz;
                         break;
                     }
                     case 4: { // IPv6
                         if (bytes_xferred < 22)
                             goto nosend;
                         asio::ip::address_v6::bytes_type v6o;
                         memcpy(v6o.data(), inbuf_.data() + headersiz, 16);
                         daddr_ = asio::ip::address_v6(v6o);
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

                 if (fragn != '\0' && udp_frag_handle(fragn, atyp))
                     return;

                 if (!dnsname_.empty())
                     dns_lookup();
                 else
                     udp_proxy_packet();
                 return;
             }
           nosend:
             udp_client_socket_read();
         }));
}

bool SocksUDP::udp_frags_different(uint8_t fragn, uint8_t atyp)
{
    if (fragn <= frags_->lastn_)
        return true;
    if (dport_ != frags_->port_)
        return true;
    if (atyp != 3) {
        if (daddr_ != frags_->addr_)
            return true;
    } else { // DNS
        if (dnsname_ != frags_->dns_)
            return true;
    }
    return false;
}

// If true then the caller doesn't need to proceed.
bool SocksUDP::udp_frag_handle(uint8_t fragn, uint8_t atyp)
{
    const bool new_frags(frags_->buf_.size() == 0);
    const bool send_frags(fragn > 127);
    if (new_frags || udp_frags_different(fragn, atyp)) {
        frags_->reset();
        frags_->lastn_ = fragn;
        frags_->port_ = dport_;
        if (atyp != 3)
            frags_->addr_ = daddr_;
        else // DNS
            frags_->dns_ = dnsname_;
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
        (asio::buffer(inbuf_.data() + poffset_, psize_),
         asio::ip::udp::endpoint(daddr_, dport_), 0, strand_.wrap(
         [this, sfd{std::move(sfd)}](const std::error_code &ec, std::size_t bytes_xferred)
         {
             udp_client_socket_read();
         }));
}

void SocksUDP::dnslookup_cb(void *self_, int status, int timeouts, struct hostent *host)
{
    auto self = std::move(((SocksUDP *)self_)->selfref_);

    const auto try_other_af = [&self]() {
        if (self->dnsq_v6_ && self->dnsq_v4_) return false;
        if (self->dnsq_v4_) {
            if (!g_disable_ipv6) {
                self->strand_.post([self]() {
                    self->raw_dns_lookup(AF_INET6);
                });
                return true;
            }
        } else if (self->dnsq_v6_) {
            self->strand_.post([self]() {
                self->raw_dns_lookup(AF_INET);
            });
            return true;
        }
        return false;
    };

    if (status != ARES_SUCCESS) {
        bool retry{false};
        if (status  == ARES_ENODATA)
            retry = try_other_af();
        if (!retry) {
            self->strand_.post([self, status, timeouts]() {
                logfmt("DNS lookup failed: status={} timeouts={}\n", status, timeouts);
                self->udp_client_socket_read();
            });
        }
        return;
    }

    size_t ipchoices{0};
    for (auto p = host->h_addr_list; *p; ++p) ++ipchoices;
    if (ipchoices == 0) {
        try_other_af();
        return;
    }

    for (auto p = host->h_addr_list; *p; ++p) {
        if (g_disable_ipv6 && host->h_addrtype == AF_INET6)
            continue;
        char addr_buf[64];
        ares_inet_ntop(host->h_addrtype, *p, addr_buf, sizeof addr_buf);
        std::error_code ec;
        auto a = asio::ip::address::from_string(addr_buf, ec);
        if (ec) continue;
        // It's possible for the resolver to return an address
        // that is unspecified after lookup, eg, host file blocking.
        if (a.is_unspecified()) continue;
        self->strand_.post([self, a = std::move(a)]() {
            self->daddr_ = std::move(a);
            self->udp_proxy_packet();
        });
    }
    self->strand_.post([self]() {
        self->udp_client_socket_read();
    });
}

void SocksUDP::raw_dns_lookup(int af)
{
    selfref_ = shared_from_this();
    std::error_code ec;
    asio::ip::address a;
    if (!dnsname_.empty())
        a = asio::ip::address::from_string(dnsname_, ec);
    if (dnsname_.empty() || ec) {
        if (af == AF_INET) dnsq_v4_ = true;
        if (af == AF_INET6) dnsq_v6_ = true;
        g_adns->query_hostname(dnsname_.c_str(), af, SocksUDP::dnslookup_cb, this);
    } else {
        daddr_ = std::move(a);
        strand_.post([self = shared_from_this()]() {
            self->udp_proxy_packet();
        });
    }
}

void SocksUDP::dns_lookup()
{
    raw_dns_lookup((g_prefer_ipv4 || g_disable_ipv6) ? AF_INET : AF_INET6);
}

void SocksUDP::udp_remote_socket_read()
{
    auto sfd = shared_from_this();
    outbuf_.clear();
    out_bufs_.clear();
    outbuf_.reserve(UDP_BUFSIZE);
    remote_socket_.async_receive_from
        (asio::buffer(outbuf_),
         rsender_endpoint_, strand_.wrap(
         [this, sfd{std::move(sfd)}](const std::error_code &ec, std::size_t bytes_xferred)
         {
             if (ec) {
                 if (ec != asio::error::operation_aborted) {
                     logfmt("Error on remote UDP socket: {}\n", std::system_error(ec).what());
                 }
                 return;
             }
             // Attach the header.
             const auto saddr = rsender_endpoint_.address();
             const uint16_t sport = rsender_endpoint_.port();
             std::size_t ohs = 4;
             if (saddr.is_v4()) {
                 out_header_[0] = 0;
                 out_header_[1] = 0;
                 out_header_[2] = 0;
                 out_header_[3] = 1;
                 const auto v4b = saddr.to_v4().to_bytes();
                 for (const auto &i: v4b)
                     out_header_[ohs++] = i;
             } else {
                 out_header_[0] = 0;
                 out_header_[1] = 0;
                 out_header_[2] = 0;
                 out_header_[3] = 4;
                 const auto v6b = saddr.to_v6().to_bytes();
                 for (const auto &i: v6b)
                     out_header_[ohs++] = i;
             }
             const uint16_t p{htons(sport)};
             memcpy(&out_header_[ohs], &p, sizeof p);
             ohs += sizeof p;
             // Forward it to the client socket.
             out_bufs_.push_back(asio::buffer(out_header_.data(), ohs));
             out_bufs_.push_back(asio::buffer(outbuf_));
             client_socket_.async_send_to
                 (out_bufs_, client_remote_endpoint_, strand_.wrap(
                  [this, sfd{std::move(sfd)}](const std::error_code &ec, std::size_t bytes_xferred)
                  {
                      udp_remote_socket_read();
                  }));
         }));
}

ClientListener::ClientListener(const asio::ip::tcp::endpoint &endpoint)
        : acceptor_(io_service), endpoint_(endpoint), socket_(io_service)
{
    acceptor_.open(endpoint_.protocol());
    acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    acceptor_.non_blocking(true);
    acceptor_.bind(endpoint_);
    acceptor_.listen(listen_queuelen);
    start_accept();
}

void ClientListener::start_accept()
{
    acceptor_.async_accept
        (socket_, endpoint_,
         [this](const std::error_code &ec)
         {
             if (!ec)
                 conntracker_hs->emplace(acceptor_.get_io_service(),
                                         std::move(socket_));
             start_accept();
         });
}
