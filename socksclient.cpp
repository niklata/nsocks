/* socksclient.cpp - socks client request handling
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

#define SPLICE_CACHE_SIZE 20

#include <iostream>
#include <forward_list>
#include <vector>
#include <mutex>

#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include <boost/lexical_cast.hpp>
#include <boost/dynamic_bitset.hpp>

#include <boost/random/random_device.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/variate_generator.hpp>

#ifdef HAS_64BIT
#include <boost/lockfree/stack.hpp>
#endif

#include "socksclient.hpp"
#include "socks_tracker.hpp"
#include "asio_addrcmp.hpp"

#define MAX_BIND_TRIES 10
#define UDP_BUFSIZE 1536
#define MAX_IDENT_LEN 1024

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

static unsigned int max_buffer_ms = 250;
void set_max_buffer_ms(unsigned int n) { max_buffer_ms = n; }

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

static boost::random::random_device g_random_secure;
static boost::random::mt19937 g_random_prng(g_random_secure());

#include "bind_port_assigner.hpp"

static std::unique_ptr <boost::asio::strand> strand_C;
static std::unique_ptr <boost::asio::strand> strand_R;

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

static std::atomic<bool> cPipeTimerSet;
static std::unique_ptr<boost::asio::deadline_timer> cPipeTimer;
static std::forward_list<std::weak_ptr<SocksTCP>> cSpliceList;
static std::forward_list<std::weak_ptr<SocksTCP>> rSpliceList;
static std::unique_ptr<boost::asio::deadline_timer> rPipeTimer;
static std::atomic<bool> rPipeTimerSet;
#endif

void init_conntrackers(std::size_t hs_secs, std::size_t bindlisten_secs)
{
    strand_C = nk::make_unique<boost::asio::strand>(io_service);
    strand_R = nk::make_unique<boost::asio::strand>(io_service);
#ifdef USE_SPLICE
    cPipeTimer = nk::make_unique<boost::asio::deadline_timer>(io_service);
    rPipeTimer = nk::make_unique<boost::asio::deadline_timer>(io_service);
#endif
    conntracker_hs = nk::make_unique<ephTrackerVec<SocksInit>>
        (io_service, hs_secs);
    conntracker_bindlisten = nk::make_unique<ephTrackerList<SocksInit>>
        (io_service, bindlisten_secs);
}

static inline void tcp_socket_close(ba::ip::tcp::socket &s)
{
    boost::system::error_code ec;
    s.shutdown(ba::ip::tcp::socket::shutdown_both, ec);
    s.close(ec);
}

static inline void close_cr_socket(ba::ip::tcp::socket &s)
{
    if (!s.is_open())
        return;
    boost::system::error_code ec;
    s.cancel(ec);
    tcp_socket_close(s);
}

#ifdef USE_SPLICE
void pipe_close_raw(std::atomic<std::size_t> &p_len,
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
                std::cerr << "cached a pipe (total: " << num_free_pipes << ")\n";
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
                std::cerr << "cached a pipe (total: " << free_pipes.size() << ")\n";
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

bool pipe_close(ba::posix::stream_descriptor &sa,
                ba::posix::stream_descriptor &sb,
                std::atomic<std::size_t> &p_len,
                ba::ip::tcp::socket &s_reader,
                ba::ip::tcp::socket &s_writer)
{
    boost::system::error_code ec;
    bool ret(false);
    auto sro = s_reader.is_open();
    if (sro)
        s_reader.cancel(ec);
    if (s_writer.is_open()) {
        ret = true;
        s_writer.cancel(ec);
    }
    pipe_close_raw(p_len, sa, sb);
    if (sro)
        tcp_socket_close(s_reader);
    if (ret)
        s_writer.shutdown(ba::ip::tcp::socket::shutdown_receive, ec);
    return ret;
}
#endif

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
    std::cout << "Connection to " << host << ":" << port
              << " DESTRUCTED (total: HS";
    if (conntracker_hs)
        std::cout << conntracker_hs->size() << ", BL";
    else
        std::cout << "X, BL";
    if (conntracker_bindlisten)
        std::cout << conntracker_bindlisten->size() << " || T";
    else
        std::cout << "X || T";
    std::cout << conntracker_tcp.size() << ", U"
              << udp_alive_count
              << " / " << socks_alive_count << ")" << std::endl;
}

static std::unique_ptr<BindPortAssigner> BPA;
static std::unique_ptr<BindPortAssigner> UPA;

void init_bind_port_assigner(uint16_t lowport, uint16_t highport)
{
    if (g_disable_bind)
        return;
    if (lowport < 1024 || highport < 1024) {
        std::cout << "For BIND requests to be satisfied, bind-lowest-port and bind-highest-port\n"
                  << "must both be set to non-equal values >= 1024.  BIND requests will be\n"
                  << "disabled until this configuration problem is corrected." << std::endl;
        g_disable_bind = true;
        return;
    }
    if (lowport > highport)
        std::swap(lowport, highport);
    BPA = nk::make_unique<BindPortAssigner>(lowport, highport);
}

void init_udp_associate_assigner(uint16_t lowport, uint16_t highport)
{
    if (g_disable_udp)
        return;
    if (lowport < 1024 || highport < 1024) {
        std::cout << "For UDP ASSOCIATE requests to be satisfied, udp-lowest-port and\n"
                  << "udp-highest-port must both be set to non-equal values >= 1024.  UDP\n"
                  << "ASSOCIATE requests will be disabled until this configuration problem\n"
                  << "is corrected." << std::endl;
        g_disable_udp = true;
        return;
    }
    if (lowport > highport)
        std::swap(lowport, highport);
    UPA = nk::make_unique<BindPortAssigner>(lowport, highport);
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
        : tracked_(true), client_socket_(std::move(client_socket)),
          remote_socket_(io_service), ibSiz_(0), poff_(0), ptmp_(0),
          pstate_(ParsedState::Parsed_None), is_socks_v4_(false),
          bind_listen_(false), auth_none_(false), auth_gssapi_(false),
          auth_unpw_(false)
{
    if (g_verbose_logs)
        ++socks_alive_count;
    client_socket_.non_blocking(true);
    client_socket_.set_option(boost::asio::socket_base::keep_alive(true));
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
    if (tracked_.compare_exchange_strong(cxr, false))
        conntracker_bindlisten->erase(get_tracker_iterator(),
                                      get_tracker_idx());
}

void SocksInit::cancel()
{
    boost::system::error_code ec;
    if (bound_)
        bound_->acceptor_.cancel(ec);
    close_cr_socket(client_socket_);
    close_cr_socket(remote_socket_);
}

void SocksInit::terminate()
{
    cancel();
    untrack();
}

void SocksInit::read_greet()
{
    auto sfd = shared_from_this();
    client_socket_.async_read_some
        (ba::buffer(sockbuf_.data() + ibSiz_, sockbuf_.size() - ibSiz_),
         strand_C->wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 if (ec != ba::error::operation_aborted) {
                     std::cerr << "read_greet() error: "
                               << boost::system::system_error(ec).what()
                               << std::endl;
                     terminate();
                 }
                 return;
             }
             if (!bytes_xferred)
                 return;
             ibSiz_ += bytes_xferred;
             size_t consumed;
             auto rc = parse_greet(consumed);
             if (rc) {
                 if (*rc != RplSuccess)
                     send_reply(*rc);
                 return;
             } else {
                 ibSiz_ -= consumed;
                 poff_ -= consumed;
                 memmove(sockbuf_.data(), sockbuf_.data() + consumed, ibSiz_);
             }
             read_greet();
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
        size_t aendsiz = poff_ + ptmp_;
        for (;poff_ < aendsiz && poff_ < ibSiz_; ++poff_,--ptmp_) {
            ++consumed;
            uint8_t atype = static_cast<uint8_t>(sockbuf_[poff_]);
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
            strand_C->wrap(
                [this, sfd](const boost::system::error_code &ec,
                            std::size_t bytes_xferred)
                {
                    if (ec && ec != ba::error::operation_aborted) {
                        std::cerr << "failed writing reply_greetz: "
                                  << boost::system::system_error(ec).what()
                                  << std::endl;
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
            if (ptmp_ > MAX_IDENT_LEN)
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
            goto parsed5cr_dnslen;
        } else {
            std::cerr << "parse_greet(): unknown address type: "
                      << addr_type_ << "\n";
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
        uint16_t csiz = std::min(static_cast<uint16_t>(ibSiz_ - poff_), ptmp_);
        if (csiz < 1)
            return boost::optional<ReplyCode>();
        consumed += csiz;
        dst_hostname_.append(sockbuf_.data() + poff_, csiz);
        poff_ += csiz;
        auto dsiz = dst_hostname_.size();
        if (dsiz < csiz)
            return boost::optional<ReplyCode>();
        else if (dsiz > csiz) {
            std::cerr << "parse_greet(): Bad DNS name length="<<dsiz<<".\n";
            return RplAddrNotSupp;
        }
        goto parsed5cr_daddr;
    }
    default: throw std::logic_error("undefined parse state");
    }
    return boost::optional<ReplyCode>();
}

void SocksInit::dispatch_connrq()
{
    if (dst_hostname_.size() > 0 && dst_address_.is_unspecified()) {
        ba::ip::tcp::resolver::query query
            (dst_hostname_, boost::lexical_cast<std::string>(dst_port_));
        auto sfd = shared_from_this();
        try {
            init_resolver(client_socket_.get_io_service());
            tcp_resolver_->async_resolve
                (query, strand_C->wrap(
                 [this, sfd](const boost::system::error_code &ec,
                             ba::ip::tcp::resolver::iterator it)
                 {
                     if (ec) {
                         if (ec != ba::error::operation_aborted)
                             send_reply(RplHostUnreach);
                         return;
                     }
                     ba::ip::tcp::resolver::iterator fv4, fv6, rie;
                     for (; it != rie; ++it) {
                         bool isv4 = it->endpoint().address().is_v4();
                         if (isv4) {
                             if (g_prefer_ipv4) {
                                 dst_address_ = it->endpoint().address();
                                 dispatch_connrq();
                                 return;
                             }
                             if (fv4 == rie)
                                 fv4 = it;
                         } else {
                             if (!g_prefer_ipv4) {
                                 dst_address_ = it->endpoint().address();
                                 dispatch_connrq();
                                 return;
                             }
                             if (fv6 == rie)
                                 fv6 = it;
                         }
                     }
                     dst_address_ = g_prefer_ipv4 ? fv4->endpoint().address()
                                                  : fv6->endpoint().address();
                     if (g_disable_ipv6 && !dst_address_.is_v4()) {
                         send_reply(RplHostUnreach);
                         return;
                     }
                     dispatch_connrq();
                 }));
        } catch (const std::exception &) {
            send_reply(RplHostUnreach);
        }
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
            std::cerr << "DENIED connection to " << addr.to_string() << "\n";
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
        (ep, strand_C->wrap(
         [this, sfd](const boost::system::error_code &ec)
         {
             if (ec) {
                 if (ec != ba::error::operation_aborted)
                     send_reply(errorToReplyCode(ec));
                 return;
             }
             if (g_verbose_logs) {
                 std::cout << "TCP Connect @"
                           << client_socket_.remote_endpoint().address()
                           << " " << remote_socket_.local_endpoint().address()
                           << " -> "
                           << (addr_type_ != AddrDNS
                               ? dst_address_.to_string() : dst_hostname_)
                           << ":" << dst_port_ << std::endl;
             }
             set_remote_socket_options();
             bool is_socks_v4(is_socks_v4_);
             conntracker_tcp.emplace(io_service,
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
    auto laddr = client_socket_.remote_endpoint().address();
    for (const auto &i: g_client_bind_allow_masks) {
        auto r = nk::asio::compare_ip(laddr, std::get<0>(i), std::get<1>(i));
        if (r)
            return true;
    }
    std::cerr << "DENIED bind request from " << laddr.to_string() << "\n";
    return false;
}

bool SocksInit::create_bind_socket(ba::ip::tcp::endpoint ep)
{
    int tries = 0;
    while (true) {
        ++tries;
        if (tries > MAX_BIND_TRIES) {
            std::cerr << "fatal error creating BIND socket: can't find unused port\n";
            break;
        }
        try {
            bound_ = nk::make_unique<BoundSocket>(io_service, ep);
        } catch (const std::runtime_error &e) {
            std::cerr << "fatal error creating BIND socket: " << e.what() << "\n";
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
            auto laddr((*rcnct)->remote_socket_local_endpoint().address());
            bind_ep = ba::ip::tcp::endpoint(laddr, BPA->get_port());
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
        (remote_socket_, strand_C->wrap(
         [this, sfd](const boost::system::error_code &ec)
         {
             if (ec) {
                 send_reply(RplFail);
                 return;
             }
             std::cout << "Accepted a connection to a BIND socket." << std::endl;
             set_remote_socket_options();
             bool is_socks_v4(is_socks_v4_);
             conntracker_tcp.emplace(io_service,
                   std::move(client_socket_),
                   std::move(remote_socket_),
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
    std::cerr << "DENIED udp associate request from " << laddr.to_string() << "\n";
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
    auto client_ep = client_socket_.remote_endpoint();
    if (!is_udp_client_allowed(client_ep.address())) {
        send_reply(RplDeny);
        return;
    }
    ba::ip::udp::endpoint udp_client_ep, udp_remote_ep;
    uint16_t udp_local_port, udp_remote_port;
    auto laddr(client_socket_.local_endpoint().address());
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
         ba::ip::udp::endpoint(client_ep.address(), client_ep.port()));
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
         strand_C->wrap(
         [this, sfd, replycode](const boost::system::error_code &ec,
                                std::size_t bytes_xferred)
         {
             if (ec || replycode != RplSuccess) {
                 std::cout << "REJECT @"
                     << client_socket_.remote_endpoint().address()
                     << " (none) -> "
                     << (addr_type_ != AddrDNS
                         ? dst_address_.to_string() : dst_hostname_)
                     << ":" << dst_port_
                     << " [" << replyCodeString[replycode]
                     << "]" << std::endl;
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
        : terminated_(false),
          dst_hostname_(dst_hostname), dst_address_(dst_address),
          client_socket_(std::move(client_socket)),
          remote_socket_(std::move(remote_socket)),
          dst_port_(dst_port), is_socks_v4_(is_socks_v4), is_bind_(is_bind),
#ifdef USE_SPLICE
          kicking_client_pipe_bg_(false), kicking_remote_pipe_bg_(false),
          pToRemote_len_(0), pToClient_len_(0),
          sdToRemote_(io_service), sdToClient_(io_service),
          pToRemote_(io_service), pToClient_(io_service)
#endif
{
    if (g_verbose_logs)
        ++socks_alive_count;
}

SocksTCP::~SocksTCP()
{
    if (!terminated_)
        untrack();
    if (g_verbose_logs) {
        --socks_alive_count;
        print_trackers_logentry(dst_hostname_.size() ? dst_hostname_
                                  : dst_address_.to_string(),
                                  dst_port_);
    }
}

void SocksTCP::untrack()
{
    conntracker_tcp.erase(get_tracker_iterator());
}

void SocksTCP::cancel()
{
    close_remote_socket();
    close_client_socket();
}

void SocksTCP::terminate()
{
    bool cxr(false);
    if (!terminated_.compare_exchange_strong(cxr, true))
        return;
    cancel();
    untrack();
    // std::cout << "Connection to "
    //           << (dst_hostname_.size() ? dst_hostname_
    //                                    : dst_address_.to_string())
    //           << ":" << dst_port_ << " called terminate()." << std::endl;
}


#ifdef USE_SPLICE

bool SocksTCP::init_pipe_client()
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
            std::cerr << "toRemote: Got cached pipe=[" << pipes[0] << "," << pipes[1] << "]\n";
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
                std::cerr << "toRemote: Got cached pipe=[" << pipes[0] << "," << pipes[1] << "]\n";
        }
    }
#endif
    if (!got_free_pipe) {
        if (pipe2(pipes, O_NONBLOCK))
            return false;
        auto r = fcntl(pipes[0], F_SETPIPE_SZ, splice_pipe_size);
        if (r < splice_pipe_size)
            std::cerr << "toRemote: Pipe size could only be set to " << r << ".\n";
        else if (r == -1) {
            switch (errno) {
                case EPERM: std::cerr << "toRemote: EPERM when trying to set splice pipe size to " << splice_pipe_size << ".\n";
                default: std::cerr << "toRemote: fcntl(F_SETPIPE_SZ) returned errno=" << errno << ".\n";
            }
        }
    }
    sdToRemote_.assign(pipes[0]);
    pToRemote_.assign(pipes[1]);
    return true;
}

bool SocksTCP::init_pipe_remote()
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
            std::cerr << "toClient: Got cached pipe=[" << pipes[0] << "," << pipes[1] << "]\n";
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
                std::cerr << "toClient: Got cached pipe=[" << pipes[0] << "," << pipes[1] << "]\n";
        }
    }
#endif
    if (!got_free_pipe) {
        if (pipe2(pipes, O_NONBLOCK))
            return false;
        auto r = fcntl(pipes[0], F_SETPIPE_SZ, splice_pipe_size);
        if (r < splice_pipe_size)
            std::cerr << "toClient: Pipe size could only be set to " << r << ".\n";
        else if (r == -1) {
            switch (errno) {
                case EPERM: std::cerr << "toClient: EPERM when trying to set splice pipe size to " << splice_pipe_size << ".\n";
                default: std::cerr << "toClient: fcntl(F_SETPIPE_SZ) returned errno=" << errno << ".\n";
            }
        }
    }
    sdToClient_.assign(pipes[0]);
    pToClient_.assign(pipes[1]);
    return true;
}

void SocksTCP::terminate_client()
{
    bool remote_open = close_client_socket();
    if (terminated_)
        return;
    if (remote_open && pToRemote_len_ > 0)
        flushPipeToRemote(true);
    terminate();
}

void SocksTCP::terminate_remote()
{
    bool client_open = close_remote_socket();
    if (terminated_)
        return;
    if (client_open && pToClient_len_ > 0)
        flushPipeToClient(true);
    terminate();
}

static void kickClientPipeTimer()
{
    bool cmpbool(false);
    if (cPipeTimerSet.compare_exchange_strong(cmpbool, true)) {
        cPipeTimer->expires_from_now
            (boost::posix_time::milliseconds(max_buffer_ms / 2U));
        cPipeTimer->async_wait(strand_R->wrap(
            [](const boost::system::error_code& error)
                {
                    cPipeTimerSet = false;
                    if (error)
                        return;
                    bool erase_ipp(false);
                    auto now = std::chrono::high_resolution_clock::now();
                    std::forward_list<std::weak_ptr<SocksTCP>>::iterator i, ip, ipp;
                    const auto end = cSpliceList.end();
                    for (i = cSpliceList.begin(),
                         ip = cSpliceList.before_begin(),
                         ipp = cSpliceList.before_begin();
                         i != end;)
                    {
                        auto k = i->lock();
                        erase_ipp = (!k || !k->is_remote_splicing() ||
                                     !k->kickClientPipe(now));
                        ipp = ip, ip = i++;
                        if (erase_ipp) {
                            cSpliceList.erase_after(ipp);
                            ip = ipp;
                        }
                    }
                    if (!cSpliceList.empty())
                        kickClientPipeTimer();
                }));
    }
}

static void kickRemotePipeTimer()
{
    bool cmpbool(false);
    if (rPipeTimerSet.compare_exchange_strong(cmpbool, true)) {
        rPipeTimer->expires_from_now
            (boost::posix_time::milliseconds(max_buffer_ms / 2U));
        rPipeTimer->async_wait(strand_C->wrap(
            [](const boost::system::error_code& error)
                {
                    rPipeTimerSet = false;
                    if (error)
                        return;
                    bool erase_ipp(false);
                    auto now = std::chrono::high_resolution_clock::now();
                    std::forward_list<std::weak_ptr<SocksTCP>>::iterator i, ip, ipp;
                    const auto end = rSpliceList.end();
                    for (i = rSpliceList.begin(),
                         ip = rSpliceList.before_begin(),
                         ipp = rSpliceList.before_begin();
                         i != end;)
                    {
                        auto k = i->lock();
                        erase_ipp = (!k || !k->is_client_splicing() ||
                                     !k->kickRemotePipe(now));
                        ipp = ip, ip = i++;
                        if (erase_ipp) {
                            rSpliceList.erase_after(ipp);
                            ip = ipp;
                        }
                    }
                    if (!rSpliceList.empty())
                        kickRemotePipeTimer();
                }));
    }
}

// Ret: Is the connection still alive and splicing?
bool SocksTCP::kickClientPipe(const std::chrono::high_resolution_clock::time_point &now)
{
    if (std::chrono::duration_cast<std::chrono::milliseconds>
        (now - remote_read_ts_).count() < max_buffer_ms / 2U)
        return true;
    boost::system::error_code ec;
    remote_socket_.cancel(ec);
    size_t l = pToClient_len_;
    if (l == 0) {
        tcp_remote_socket_read_stopsplice();
        return false;
    }
    auto n = splicePipeToClient();
    if (!n)
        return false;
    if (l - *n > 0) {
        kickClientPipeBG();
        return false;
    }
    tcp_remote_socket_read_stopsplice();
    return false;
}

void SocksTCP::kickClientPipeBG()
{
    if (kicking_client_pipe_bg_)
        return;
    kicking_client_pipe_bg_ = true;
    auto sfd = shared_from_this();
    client_socket_.async_write_some
        (ba::null_buffers(), strand_R->wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             kicking_client_pipe_bg_ = false;
             if (ec) {
                 if (ec != ba::error::operation_aborted) {
                     std::cerr << "kickClientPipeBG error: "
                               << boost::system::system_error(ec).what()
                               << "\n";
                     terminate_client();
                 }
                 return;
             }
             if (!splicePipeToClient())
                 return;
             if (pToClient_len_ > 0)
                 kickClientPipeBG();
             else
                 tcp_remote_socket_read_stopsplice();
         }));
}

// Ret: Is the connection still alive and splicing?
bool SocksTCP::kickRemotePipe(const std::chrono::high_resolution_clock::time_point &now)
{
    if (std::chrono::duration_cast<std::chrono::milliseconds>
        (now - client_read_ts_).count() < max_buffer_ms / 2U)
        return true;
    boost::system::error_code ec;
    client_socket_.cancel(ec);
    size_t l = pToRemote_len_;
    if (l == 0) {
        tcp_client_socket_read_stopsplice();
        return false;
    }
    auto n = splicePipeToRemote();
    if (!n)
        return false;
    if (l - *n > 0) {
        kickRemotePipeBG();
        return false;
    }
    tcp_client_socket_read_stopsplice();
    return false;
}

void SocksTCP::kickRemotePipeBG()
{
    if (kicking_remote_pipe_bg_)
        return;
    kicking_remote_pipe_bg_ = true;
    auto sfd = shared_from_this();
    remote_socket_.async_write_some
        (ba::null_buffers(), strand_C->wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             kicking_remote_pipe_bg_ = false;
             if (ec) {
                 if (ec != ba::error::operation_aborted) {
                     std::cerr << "kickRemotePipeBG error: "
                               << boost::system::system_error(ec).what()
                               << "\n";
                     terminate_remote();
                 }
                 return;
             }
             if (!splicePipeToRemote())
                 return;
             if (pToRemote_len_ > 0)
                 kickRemotePipeBG();
             else
                 tcp_client_socket_read_stopsplice();
         }));
}

void SocksTCP::addToSpliceClientList()
{
    cSpliceList.emplace_front(shared_from_this());
    kickClientPipeTimer();
}

void SocksTCP::addToSpliceRemoteList()
{
    rSpliceList.emplace_front(shared_from_this());
    kickRemotePipeTimer();
}

// Write data read from the client socket to the connect socket.
void SocksTCP::tcp_client_socket_read_splice()
{
    auto sfd = shared_from_this();
    client_socket_.async_read_some
        (ba::null_buffers(), strand_C->wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 if (ec != ba::error::operation_aborted) {
                     std::cerr << "EC-C: "
                               << boost::system::system_error(ec).what()
                               << "\n";
                     terminate_client();
                 }
                 return;
             }
             if (pToRemote_len_ > 0 && !splicePipeToRemote())
                 return;
             try {
                 auto n = spliceit(client_socket_.native_handle(),
                                   pToRemote_.native_handle());
                 if (!n) {
                     terminate_client();
                     return;
                 }
                 pToRemote_len_ += *n;
                 if (*n < send_minsplice_size) {
                     if (pToRemote_len_ > 0)
                         flushPipeToRemote(false);
                     else
                         tcp_client_socket_read_stopsplice();
                     return;
                 }
             } catch (const std::runtime_error &e) {
                 std::cerr << "tcp_client_socket_read_splice() TERMINATE: "
                           << e.what() << "\n";
                 terminate_client();
                 return;
             }
             if (!splicePipeToRemote())
                 return;
             if (pToRemote_len_ > 0)
                 client_read_ts_ = std::chrono::high_resolution_clock::now();
             tcp_client_socket_read_splice();
         }));
}

// Write data read from the connect socket to the client socket.
void SocksTCP::tcp_remote_socket_read_splice()
{
    auto sfd = shared_from_this();
    remote_socket_.async_read_some
        (ba::null_buffers(), strand_R->wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 if (ec != ba::error::operation_aborted) {
                     std::cerr << "EC-R: "
                               << boost::system::system_error(ec).what()
                               << "\n";
                     terminate_remote();
                 }
                 return;
             }
             if (pToClient_len_ > 0 && !splicePipeToClient())
                 return;
             try {
                 auto n = spliceit(remote_socket_.native_handle(),
                                   pToClient_.native_handle());
                 if (!n) {
                     terminate_remote();
                     return;
                 }
                 pToClient_len_ += *n;
                 if (*n < receive_minsplice_size) {
                     if (pToClient_len_ > 0)
                         flushPipeToClient(false);
                     else
                         tcp_remote_socket_read_stopsplice();
                     return;
                 }
             } catch (const std::runtime_error &e) {
                 std::cerr << "tcp_remote_socket_read_splice() TERMINATE: "
                           << e.what() << "\n";
                 terminate_remote();
                 return;
             }
             if (!splicePipeToClient())
                 return;
             if (pToClient_len_ > 0)
                 remote_read_ts_ = std::chrono::high_resolution_clock::now();
             tcp_remote_socket_read_splice();
         }));
}

void SocksTCP::doFlushPipeToRemote(bool closing)
{
    auto sfd = shared_from_this();
    remote_socket_.async_write_some
        (ba::null_buffers(), strand_C->wrap(
         [this, sfd, closing](const boost::system::error_code &ec,
                              std::size_t bytes_xferred)
         {
             if (ec) {
                 if (ec != ba::error::operation_aborted) {
                     std::cerr << "doFlushPipeToRemote error: "
                               << boost::system::system_error(ec).what()
                               << "\n";
                     terminate_remote();
                 }
                 return;
             }
             if (!splicePipeToRemote())
                 return;
             if (pToRemote_len_ == 0) {
                 if (!closing) tcp_client_socket_read_splice();
                 else terminate_remote();
                 return;
             }
             doFlushPipeToRemote(closing);
         }));
}

void SocksTCP::doFlushPipeToClient(bool closing)
{
    auto sfd = shared_from_this();
    client_socket_.async_write_some
        (ba::null_buffers(), strand_R->wrap(
         [this, sfd, closing](const boost::system::error_code &ec,
                              std::size_t bytes_xferred)
         {
             if (ec) {
                 if (ec != ba::error::operation_aborted) {
                     std::cerr << "doFlushPipeToClient error: "
                               << boost::system::system_error(ec).what()
                               << "\n";
                     terminate_client();
                 }
                 return;
             }
             if (!splicePipeToClient())
                 return;
             if (pToClient_len_ == 0) {
                 if (!closing) tcp_remote_socket_read_splice();
                 else terminate_client();
                 return;
             }
             doFlushPipeToClient(closing);
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
        (ba::buffer(ibm), strand_C->wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 if (ec != ba::error::operation_aborted)
                     terminate_client();
                 return;
             }
             client_buf_.commit(bytes_xferred);
             // Client is trying to send data to the remote server.  Write it
             // to the remote_socket_.
             boost::system::error_code ecx;
             auto cbs = client_buf_.size();
             auto r = remote_socket_.send
                 (ba::buffer(client_buf_.data(), cbs), 0, ecx);
             client_buf_.consume(r);
             if (r == cbs) {
                 tcp_client_socket_read_again(r, client_buf_.size() == 0);
                 return;
             } else if (r == 0 && ecx != ba::error::would_block) {
                 if (ecx != ba::error::operation_aborted)
                     terminate_client();
                 return;
             }
             ba::async_write(remote_socket_, client_buf_, strand_C->wrap(
                             [this, sfd](const boost::system::error_code &ec,
                                         std::size_t bytes_xferred)
                             {
                                 if (ec) {
                                     if (ec != ba::error::operation_aborted)
                                         terminate_client();
                                     return;
                                 }
                                 client_buf_.consume(bytes_xferred);
                                 tcp_client_socket_read_again
                                     (bytes_xferred, client_buf_.size() == 0);
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
        (ba::buffer(ibm), strand_R->wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 if (ec != ba::error::operation_aborted)
                     terminate_remote();
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
             if (r == rbs) {
                 tcp_remote_socket_read_again(r, remote_buf_.size() == 0);
                 return;
             } else if (r == 0 && ecx != ba::error::would_block) {
                 if (ecx != ba::error::operation_aborted)
                     terminate_remote();
                 return;
             }
             ba::async_write(client_socket_, remote_buf_, strand_R->wrap(
                             [this, sfd](const boost::system::error_code &ec,
                                         std::size_t bytes_xferred)
                             {
                                 if (ec) {
                                     if (ec != ba::error::operation_aborted)
                                         terminate_remote();
                                     return;
                                 }
                                 remote_buf_.consume(bytes_xferred);
                                 tcp_remote_socket_read_again
                                     (bytes_xferred, remote_buf_.size() == 0);
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

void SocksTCP::start()
{
    std::array<char, 24> sbuf;
    std::size_t ssiz;

    if (!is_socks_v4_) {
        ssiz = send_reply_code_v5(sbuf, SocksInit::ReplyCode::RplSuccess);
        if (!is_bind_)
            ssiz = send_reply_binds_v5(sbuf, ssiz,
                                       remote_socket_.local_endpoint());
        else
            ssiz = send_reply_binds_v5(sbuf, ssiz,
                                       remote_socket_.remote_endpoint());
    } else {
        ssiz = send_reply_code_v4(sbuf, SocksInit::ReplyCode::RplSuccess);
        if (!is_bind_)
            ssiz = send_reply_binds_v4(sbuf, ssiz,
                                       remote_socket_.local_endpoint());
        else
            ssiz = send_reply_binds_v4(sbuf, ssiz,
                                       remote_socket_.remote_endpoint());
    }
    auto sfd = shared_from_this();
    auto ibm = client_buf_.prepare(ssiz);
    auto siz = std::min(ssiz, boost::asio::buffer_size(ibm));
    memcpy(boost::asio::buffer_cast<char *>(ibm), sbuf.data(), siz);
    client_buf_.commit(siz);
    ba::async_write
        (client_socket_, client_buf_, strand_R->wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             client_buf_.consume(bytes_xferred);
             if (ec) {
                 std::cout << "ERROR @"
                     << client_socket_.remote_endpoint().address()
                     << " (tcp:none) -> "
                     << (!dst_hostname_.size() ? dst_address_.to_string()
                                               : dst_hostname_)
                     << ":" << dst_port_
                     << " [sending success reply]" << std::endl;
                 terminate();
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
          client_socket_(io_service, client_ep),
          remote_socket_(io_service, remote_ep),
          resolver_(io_service)
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

void SocksUDP::cancel()
{
    close_udp_sockets();
}

void SocksUDP::terminate()
{
    cancel();
}

void SocksUDP::start()
{
    std::array<char, 24> sbuf;
    std::size_t ssiz;

    ssiz = send_reply_code_v5(sbuf, SocksInit::ReplyCode::RplSuccess);
    auto ep = client_socket_.local_endpoint();
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
                 std::cout << "ERROR @"
                     << tcp_client_socket_.remote_endpoint().address()
                     << " (udp:none) -> (udp:none) [sending success reply]"
                     << std::endl;
                 terminate();
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
    UPA->release_port(client_socket_.local_endpoint().port());
    UPA->release_port(remote_socket_.local_endpoint().port());
}

// Listen for data on client_socket_.  If we get EOF, then terminate the
// entire SocksUDP.
void SocksUDP::udp_tcp_socket_read()
{
    auto sfd = shared_from_this();
    tcp_client_socket_.async_read_some
        (ba::buffer(tcp_inbuf_.data(),
                    tcp_inbuf_.size()), strand_C->wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 if (ec != ba::error::operation_aborted) {
                     std::cerr << "Client closed TCP socket for UDP associate: "
                               << boost::system::system_error(ec).what()
                               << std::endl;
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
         csender_endpoint_, strand_C->wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 if (ec != ba::error::operation_aborted) {
                     std::cerr << "Error on client UDP socket: "
                               << boost::system::system_error(ec).what()
                               << std::endl;
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
                         frags_ = nk::make_unique<UDPFrags>(io_service);
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
         ba::ip::udp::endpoint(daddr_, dport_), 0, strand_C->wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             udp_client_socket_read();
         }));
}

void SocksUDP::udp_dns_lookup(const std::string &dnsname)
{
    ba::ip::udp::resolver::query query
        (dnsname, boost::lexical_cast<std::string>(dport_));
    auto sfd = shared_from_this();
    try {
        resolver_.async_resolve
            (query, strand_C->wrap(
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
         rsender_endpoint_, strand_C->wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 if (ec != ba::error::operation_aborted) {
                     std::cerr << "Error on remote UDP socket: "
                               << boost::system::system_error(ec).what()
                               << std::endl;
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
                 (out_bufs_, client_remote_endpoint_, strand_C->wrap(
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
