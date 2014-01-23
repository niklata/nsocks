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

#include <iostream>
#include <unordered_map>
#include <mutex>

#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include <boost/optional.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/dynamic_bitset.hpp>

#include <boost/random/random_device.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/variate_generator.hpp>

#include "socksclient.hpp"
#include "asio_addrcmp.hpp"
#include "make_unique.hpp"

#define MAX_BIND_TRIES 10

namespace ba = boost::asio;

extern ba::io_service io_service;
extern bool gParanoid;
extern bool gChrooted;

bool g_prefer_ipv4 = false;
bool g_disable_ipv6 = false;
bool g_disable_bind = false;
bool g_disable_udp = false;

static std::size_t listen_queuelen = 256;
void set_listen_queuelen(std::size_t len) { listen_queuelen = len; }

static std::size_t buffer_chunk_size = 4096;
void set_buffer_chunk_size(std::size_t size) { buffer_chunk_size = size; }

static boost::random::random_device g_random_secure;
static boost::random::mt19937 g_random_prng(g_random_secure());

class ephConnTracker : boost::noncopyable
{
public:
    ephConnTracker(ba::io_service &iosrv, std::size_t cyclefreq)
        : cyclefreq_(cyclefreq), hidx_(0), swapTimer_(iosrv) {}
    ~ephConnTracker()
    {
        for (std::size_t j = 0; j < 2; ++j)
            for (auto &i: hash_[j]) {
                i.second->cancel();
                i.second->set_terminated();
            }
    }
    void store(std::shared_ptr<SocksClient> ssc)
    {
        std::lock_guard<std::mutex> wl(lock_);
        hash_[hidx_].emplace(ssc.get(), ssc);
        if (swapTimer_.expires_from_now() <=
            boost::posix_time::time_duration(0,0,0,0))
            setTimer();
    }
    bool remove(std::size_t hidx, SocksClient* sc)
    {
        std::lock_guard<std::mutex> wl(lock_);
        return !!hash_[hidx].erase(sc);
    }
    bool remove(SocksClient* sc) {
        std::size_t hi = hidx_;
        if (!remove(hi, sc))
            return remove(hi ^ 1, sc);
        return true;
    }
    std::size_t size() { return hash_[0].size() + hash_[1].size(); }
private:
    void doSwap() {
        std::size_t hnext = hidx_ ^ 1;
        // std::cerr << "doSwap wiped " << hash_[hnext].size()
        //           << " items from hash " << hnext << "\n";
        for (auto &i: hash_[hnext])
            i.second->cancel();
        hash_[hnext].clear();
        hidx_ = hnext;
    }
    void setTimer(void) {
        swapTimer_.expires_from_now(boost::posix_time::seconds(cyclefreq_));
        swapTimer_.async_wait([this](const boost::system::error_code& error)
                              {
                                  if (error)
                                      return;
                                  std::lock_guard<std::mutex> wl(lock_);
                                  doSwap();
                                  if (size())
                                      setTimer();
                              });
    }
    std::mutex lock_;
    const std::size_t cyclefreq_;
    std::atomic<std::size_t> hidx_;
    ba::deadline_timer swapTimer_;
    std::unordered_map<SocksClient*, std::shared_ptr<SocksClient>> hash_[2];
};

static std::unique_ptr<ephConnTracker> conntracker_hs;
static std::unique_ptr<ephConnTracker> conntracker_bindlisten;

class connTracker : boost::noncopyable
{
public:
    explicit connTracker(SocksClientType client_type,
                         std::unique_ptr<ephConnTracker> &ct)
        : client_type_(client_type), ct_(ct) {}
    ~connTracker()
    {
        for (auto &i: hash_) {
            i.second->cancel();
            i.second->set_terminated();
        }
    }
    void store(std::shared_ptr<SocksClient> ssc)
    {
        std::lock_guard<std::mutex> wl(lock_);
        ssc->setClientType(client_type_);
        hash_.emplace(ssc.get(), ssc);
        assert(ct_);
        if (!ct_->remove(ssc.get()))
            std::cerr << "Store to non-handshake tracker for connection that wasn't in the handshake tracker! SocksClient=" << ssc.get() << "\n";
    }
    bool remove(SocksClient* sc)
    {
        std::lock_guard<std::mutex> wl(lock_);
        return !!hash_.erase(sc);
    }
    boost::optional<std::shared_ptr<SocksClient>>
    find_by_addr_port(boost::asio::ip::address addr, uint16_t port)
    {
        std::lock_guard<std::mutex> wl(lock_);
        for (auto &i: hash_) {
            if (i.second->matches_dst(addr, port))
                return i.second;
        }
        return boost::optional<std::shared_ptr<SocksClient>>();
    }
    std::size_t size() const { return hash_.size(); }
private:
    std::mutex lock_;
    SocksClientType client_type_;
    std::unique_ptr<ephConnTracker> &ct_;
    std::unordered_map<SocksClient*, std::shared_ptr<SocksClient>> hash_;
};

static connTracker conntracker_connect(SCT_CONNECT, conntracker_hs);
static connTracker conntracker_bind(SCT_BIND, conntracker_bindlisten);
static connTracker conntracker_udp(SCT_UDP, conntracker_hs);

void init_conntrackers(std::size_t hs_secs, std::size_t bindlisten_secs)
{
    conntracker_hs = nk::make_unique<ephConnTracker>
        (io_service, hs_secs);
    conntracker_bindlisten = nk::make_unique<ephConnTracker>
        (io_service, bindlisten_secs);
}

std::vector<std::pair<boost::asio::ip::address, unsigned int>>
g_dst_deny_masks;
std::vector<std::pair<boost::asio::ip::address, unsigned int>>
g_client_bind_allow_masks;
std::vector<std::pair<boost::asio::ip::address, unsigned int>>
g_client_udp_allow_masks;

class BindPortAssigner : boost::noncopyable
{
public:
    BindPortAssigner(uint16_t start, uint16_t end)
            : ports_used_(end - start + 1), random_portrange_(start, end),
              random_port_(g_random_prng, random_portrange_),
              start_port_(start), end_port_(end)
    {
        assert(start <= end);
    }
    uint16_t get_port()
    {
        std::lock_guard<std::mutex> wl(lock_);
        auto rp = random_port_();
        for (int i = rp; i <= end_port_; ++i) {
            auto p = i - start_port_;
            if (ports_used_[p])
                continue;
            ports_used_[p] = 1;
            return p;
        }
        for (int i = start_port_; i < rp; ++i) {
            auto p = i - start_port_;
            if (ports_used_[p])
                continue;
            ports_used_[p] = 1;
            return p;
        }
        throw std::out_of_range("no free ports");
    }
    void release_port(uint16_t port)
    {
        std::lock_guard<std::mutex> wl(lock_);
        if (port < start_port_ || port > end_port_) {
            std::cerr << "BindPortAssigner::release_port: port="
                      << port << " out of range\n";
            return;
        }
        ports_used_[port - start_port_] = 0;
    }
private:
    std::mutex lock_;
    boost::dynamic_bitset<> ports_used_;
    boost::uniform_int<uint16_t> random_portrange_;
    boost::variate_generator<boost::mt19937&, boost::uniform_int<uint16_t>>
        random_port_;
    uint16_t start_port_;
    uint16_t end_port_;
};

static std::unique_ptr<BindPortAssigner> BPA;
static std::unique_ptr<BindPortAssigner> UPA;

void init_bind_port_assigner(uint16_t lowport, uint16_t highport)
{
    if (g_disable_bind)
        return;
    if (lowport < 1024 || highport < 1024) {
        std::cout << "For BIND requests to be satisfied, bind-lowest-port and bind-highest-port\n"
                  << "must both be set to non-equal values >= 1024.  BIND requests will be\n"
                  << "disabled until this configuration problem is corrected.\n";
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
                  << "is corrected.\n";
        g_disable_udp = true;
        return;
    }
    if (lowport > highport)
        std::swap(lowport, highport);
    UPA = nk::make_unique<BindPortAssigner>(lowport, highport);
}

static std::atomic<std::size_t> socks_alive_count;

SocksClient::SocksClient(ba::io_service &io_service,
                         ba::ip::tcp::socket socket)
        : strand_(io_service),
          client_socket_(std::move(socket)), remote_socket_(io_service),
          tcp_resolver_(io_service), state_(STATE_WAITGREET),
          client_type_(SCT_INIT), ibSiz_(0),
#ifdef USE_SPLICE
          pToRemote_len_(0), pToClient_len_(0),
          sdToRemote_(io_service), sdToClient_(io_service),
          pToRemote_(io_service), pToClient_(io_service),
#endif
          writePending_(false),
          auth_none_(false), auth_gssapi_(false), auth_unpw_(false)
{
    ++socks_alive_count;
    client_socket_.non_blocking(true);
    client_socket_.set_option(boost::asio::socket_base::keep_alive(true));
}

SocksClient::~SocksClient()
{
    if (state_ != STATE_TERMINATED)
        untrack();
    --socks_alive_count;
    std::cout << "Connection to "
              << (addr_type_ != AddrDNS ? dst_address_.to_string()
                                        : dst_hostname_)
              << ":" << dst_port_ << " DESTRUCTED (total: ";
    if (conntracker_hs)
        std::cout << conntracker_hs->size() << ",";
    else
        std::cout << "X,";
    if (conntracker_bindlisten)
        std::cout << conntracker_bindlisten->size() << "|";
    else
        std::cout << "X|";
    std::cout << conntracker_connect.size() << ","
              << conntracker_bind.size() << ","
              << conntracker_udp.size()
              << " / " << socks_alive_count << ")\n";
}

void SocksClient::close_client_socket()
{
    boost::system::error_code ec;
    if (client_socket_.is_open()) {
        client_socket_.shutdown(ba::ip::tcp::socket::shutdown_both, ec);
        client_socket_.close(ec);
    }
#ifdef USE_SPLICE
    pToClient_len_ = 0;
    if (sdToClient_.is_open())
        sdToClient_.close(ec);
    if (pToClient_.is_open())
        pToClient_.close(ec);
#endif
}

void SocksClient::close_remote_socket()
{
    boost::system::error_code ec;
    if (remote_socket_.is_open()) {
        remote_socket_.shutdown(ba::ip::tcp::socket::shutdown_both, ec);
        remote_socket_.close(ec);
    }
#ifdef USE_SPLICE
    pToRemote_len_ = 0;
    if (sdToRemote_.is_open())
        sdToRemote_.close(ec);
    if (pToRemote_.is_open())
        pToRemote_.close(ec);
#endif
}

void SocksClient::close_bind_listen_socket()
{
    if (!bound_)
        return;
    assert(BPA);
    auto bind_port = bound_->local_endpoint_.port();
    bound_.reset();
    BPA->release_port(bind_port);
}

void SocksClient::close_udp_sockets()
{
    if (!udp_)
        return;
    assert(UPA);
    auto udp_c_port = udp_->client_socket_.local_endpoint().port();
    auto udp_r_port = udp_->remote_socket_.local_endpoint().port();
    udp_.reset();
    UPA->release_port(udp_c_port);
    UPA->release_port(udp_r_port);
}

void SocksClient::untrack()
{
    switch (client_type_) {
    case SCT_INIT:
        conntracker_hs->remove(this);
        if (cmd_code_ == CmdTCPBind)
            conntracker_bindlisten->remove(this);
        break;
    case SCT_CONNECT: conntracker_connect.remove(this); break;
    case SCT_BIND: conntracker_bind.remove(this); break;
    case SCT_UDP: conntracker_udp.remove(this); break;
    }
}

void SocksClient::cancel()
{
    close_remote_socket();
    close_client_socket();
    close_bind_listen_socket();
    close_udp_sockets();
}

void SocksClient::terminate()
{
    if (state_ == STATE_TERMINATED)
        return;
    state_ = STATE_TERMINATED;
    cancel();
    untrack();
    // std::cout << "Connection to "
    //           << (addr_type_ != AddrDNS ? dst_address_.to_string()
    //                                     : dst_hostname_)
    //           << ":" << dst_port_ << " called terminate().\n";
}

void SocksClient::read_handshake()
{
    auto sfd = shared_from_this();
    client_socket_.async_read_some
        (ba::buffer(inBytes_.data() + ibSiz_, inBytes_.size() - ibSiz_),
         strand_.wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 std::cerr << "Client read error: "
                           << boost::system::system_error(ec).what()
                           << std::endl;
                 terminate();
                 return;
             }
             if (!bytes_xferred)
                 return;
             ibSiz_ += bytes_xferred;
             if (state_ == STATE_WAITGREET) {
                 if (!process_greet()) {
                     std::cerr << "process_greet(): returned false -> terminate!\n";
                     terminate();
                     return;
                 }
             } else if (state_ == STATE_WAITCONNRQ) {
                 // On failure we will terminate via the send_reply() response.
                 auto rc = process_connrq();
                 if (rc != RplSuccess) {
                     send_reply(rc);
                     state_ = STATE_GOTCONNRQ;
                 }
             }
             if (state_ == STATE_WAITGREET || state_ == STATE_WAITCONNRQ)
                 read_handshake();
         }));
}

// We don't support authentication.
static const char reply_greetz[2] = {'\x5','\x0'};

// Returns false if the object needs to be destroyed by the caller.
// State can change: STATE_WAITGREET -> STATE_WAITCONNRQ
bool SocksClient::process_greet()
{
    if (state_ != STATE_WAITGREET)
        return false;

    size_t poff = 0;

    // We only accept Socks5.
    if (poff == ibSiz_)
        return true;
    if (inBytes_[poff] != 0x05)
        return false;
    ++poff;

    // Number of authentication methods supported.
    if (poff == ibSiz_)
        return true;
    size_t nauth = static_cast<uint8_t>(inBytes_[poff]);
    ++poff;

    // Types of authentication methods supported.
    size_t aendsiz = nauth + 2;
    // If buffer is too long, kill the connection.  If it's not long enough,
    // wait for more data.  If it's just right, proceed.
    if (ibSiz_ > aendsiz)
        return false;
    if (ibSiz_ < aendsiz)
        return true;
    for (;poff < aendsiz; ++poff) {
        uint8_t atype = static_cast<uint8_t>(inBytes_[poff]);
        if (atype == 0x0)
            auth_none_ = true;
        if (atype == 0x1)
            auth_gssapi_ = true;
        if (atype == 0x2)
            auth_unpw_ = true;
    }
    ibSiz_ = 0;
    if (!auth_none_)
        return false;

    assert(!writePending_);
    writePending_ = true;
    auto sfd = shared_from_this();
    ba::async_write(
        client_socket_, ba::buffer(reply_greetz, sizeof reply_greetz),
        strand_.wrap(
        [this, sfd](const boost::system::error_code &ec,
                    std::size_t bytes_xferred)
        {
            writePending_ = false;
            if (ec) {
                std::cerr << "Client write error: "
                          << boost::system::system_error(ec).what()
                          << std::endl;
                terminate();
                return;
            }
        }));
    state_ = STATE_WAITCONNRQ;
    return true;
}

// Returns false if the object needs to be destroyed by the caller.
// State can change: STATE_WAITCONNRQ -> STATE_GOTCONNRQ
SocksClient::ReplyCode SocksClient::process_connrq()
{
    if (state_ != STATE_WAITCONNRQ)
        return RplFail;

    size_t poff = 0;

    // We only accept Socks5.
    if (poff == ibSiz_)
        return RplSuccess;
    if (inBytes_[poff] != 0x05)
        return RplFail;
    ++poff;

    // Client command.
    if (poff == ibSiz_)
        return RplSuccess;
    switch (static_cast<uint8_t>(inBytes_[poff])) {
    case 0x1: cmd_code_ = CmdTCPConnect; break;
    case 0x2: cmd_code_ = CmdTCPBind; break;
    case 0x3: cmd_code_ = CmdUDP; break;
    default: return RplCmdNotSupp;
    }
    ++poff;

    // Must be zero (reserved).
    if (poff == ibSiz_)
        return RplSuccess;
    if (inBytes_[poff] != 0x0)
        return RplFail;
    ++poff;

    // Address type.
    if (poff == ibSiz_)
        return RplSuccess;
    switch (static_cast<uint8_t>(inBytes_[poff])) {
    case 0x1: addr_type_ = AddrIPv4; break;
    case 0x3: addr_type_ = AddrDNS; break;
    case 0x4: addr_type_ = AddrIPv6; break;
    default: return RplAddrNotSupp;
    }
    ++poff;

    // Destination address.
    if (poff == ibSiz_)
        return RplSuccess;
    switch (addr_type_) {
        case AddrIPv4: {
            // ibSiz_ = 10, poff = 4
            if (ibSiz_ - poff != 6)
                return RplFail;
            ba::ip::address_v4::bytes_type v4o;
            memcpy(v4o.data(), inBytes_.data() + poff, 4);
            dst_address_ = ba::ip::address_v4(v4o);
            poff += 4;
            break;
        }
        case AddrIPv6: {
            if (ibSiz_ - poff != 18)
                return RplFail;
            ba::ip::address_v6::bytes_type v6o;
            memcpy(v6o.data(), inBytes_.data() + poff, 16);
            dst_address_ = ba::ip::address_v6(v6o);
            poff += 16;
            if (g_disable_ipv6)
                return RplAddrNotSupp;
            break;
        }
        case AddrDNS: {
            size_t dnssiz = static_cast<uint8_t>(inBytes_[poff]);
            ++poff;
            if (ibSiz_ - poff != dnssiz + 2)
                return RplFail;
            dst_hostname_ = std::string(inBytes_.data() + poff, dnssiz);
            poff += dnssiz;
            break;
        }
        default:
            std::cerr << "reply_greet(): unknown address type: "
                      << addr_type_ << "\n";
            return RplAddrNotSupp;
    }

    // Destination port.
    if (poff == ibSiz_)
        return RplSuccess;
    if (ibSiz_ - poff != 2)
        return RplFail;
    uint16_t tmp;
    memcpy(&tmp, inBytes_.data() + poff, 2);
    dst_port_ = ntohs(tmp);
    state_ = STATE_GOTCONNRQ;
    ibSiz_ = 0;
    dispatch_connrq();
    return RplSuccess;
}

void SocksClient::dispatch_connrq()
{
    if (dst_hostname_.size() > 0 && dst_address_.is_unspecified()) {
        ba::ip::tcp::resolver::query query
            (dst_hostname_, boost::lexical_cast<std::string>(dst_port_));
        auto sfd = shared_from_this();
        try {
            tcp_resolver_.async_resolve
                (query, strand_.wrap(
                 [this, sfd](const boost::system::error_code &ec,
                             ba::ip::tcp::resolver::iterator it)
                 {
                     if (ec) {
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

bool SocksClient::is_dst_denied(const ba::ip::address &addr) const
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

void SocksClient::dispatch_tcp_connect()
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
             set_remote_socket_options();
             // Now we have a live socket, so we need to inform the client
             // and then begin proxying data.
             conntracker_connect.store(shared_from_this());
             if (!init_splice_pipes()) {
                 send_reply(RplFail);
                 return;
             }
             // std::cout << "TCP Connect from "
             //           << client_socket_.remote_endpoint().address()
             //           << " to "
             //           << (addr_type_ != AddrDNS ? dst_address_.to_string()
             //                                     : dst_hostname_)
             //           << ":" << dst_port_ << "\n";
             send_reply(RplSuccess);
         }));
    std::cout << "TCP Connect @" << client_socket_.remote_endpoint().address()
              << " " << remote_socket_.local_endpoint().address()
              << " -> "
              << (addr_type_ != AddrDNS ? dst_address_.to_string()
                                        : dst_hostname_)
              << ":" << dst_port_ << "\n";
}

SocksClient::ReplyCode
SocksClient::errorToReplyCode(const boost::system::error_code &ec)
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

static const char * const replyCodeString[] = {
    "Success",
    "Fail",
    "Deny",
    "NetUnreach",
    "HostUnreach",
    "ConnRefused",
    "TTLExpired",
    "RplCmdNotSupp",
    "RplAddrNotSupp",
};

#ifdef USE_SPLICE
bool SocksClient::init_splice_pipes()
{
    int err;
    int pipes[2];
    err = pipe2(pipes, O_NONBLOCK);
    if (err) {
        send_reply(RplFail);
        return false;
    }
    sdToRemote_.assign(pipes[0]);
    pToRemote_.assign(pipes[1]);
    err = pipe2(pipes, O_NONBLOCK);
    if (err) {
        send_reply(RplFail);
        return false;
    }
    sdToClient_.assign(pipes[0]);
    pToClient_.assign(pipes[1]);
    return true;
}

// Can throw std::runtime_error
static size_t spliceit(int infd, int outfd, std::size_t len)
{
  retry:
    //std::cerr << "Splicing " << infd << "->" << outfd << " len=" << len << "\n";
    auto spliced = splice(infd, NULL, outfd, NULL, len,
                          SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
    if (spliced < 0) {
        switch (errno) {
            case EAGAIN: return 0;
            case EINTR: goto retry;
            default: throw std::runtime_error(strerror(errno));
        }
    }
    return spliced;
}

void SocksClient::terminate_client()
{
    close_client_socket();
    if (state_ != STATE_TERMINATED) {
        if (remote_socket_.is_open() && pToRemote_len_ > 0) {
            boost::system::error_code ec;
            remote_socket_.shutdown(ba::ip::tcp::socket::shutdown_receive, ec);
            remote_socket_.cancel(ec);
            do_sdToRemote_read();
        } else
            terminate();
    }
}

void SocksClient::terminate_remote()
{
    close_remote_socket();
    if (state_ != STATE_TERMINATED) {
        if (client_socket_.is_open() && pToClient_len_ > 0) {
            boost::system::error_code ec;
            client_socket_.shutdown(ba::ip::tcp::socket::shutdown_receive, ec);
            client_socket_.cancel(ec);
            do_sdToClient_read();
        } else
            terminate();
    }
}

// Write data read from the client socket to the connect socket.
void SocksClient::do_client_socket_connect_read()
{
    auto sfd = shared_from_this();
    // Client is trying to send data to the remote server.  Splice it to the
    // pToRemote_ pipe.
    client_socket_.async_read_some
        (ba::null_buffers(), strand_.wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 std::cerr << "\nEC-C=" << ec << "\n";
                 terminate_client();
                 return;
             }
             try {
                 auto bytes = client_socket_.available();
                 if (!bytes) {
                     std::cerr << "\nZEROBYTES-C\n";
                     terminate_client();
                     return;
                 }
                 spliceClientToPipe(bytes);
             } catch (const std::runtime_error &e) {
                 std::cerr << "do_client_socket_connect_read() TERMINATE: "
                           << e.what() << "\n";
                 terminate_client();
                 return;
             }
             try {
                 splicePipeToRemote();
             } catch (const std::runtime_error &e) {
                 std::cerr << "do_client_socket_connect_read() TERMINATE: "
                           << e.what() << "\n";
                 terminate_remote();
                 return;
             }
             do_client_socket_connect_read();
         }));
}

// Write data read from the connect socket to the client socket.
void SocksClient::do_remote_socket_read()
{
    auto sfd = shared_from_this();
    // Remote server is trying to send data to the client.  Splice it to the
    // pToClient_ pipe.
    remote_socket_.async_read_some
        (ba::null_buffers(), strand_.wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 std::cerr << "\nEC-R=" << ec << "\n";
                 terminate_remote();
                 return;
             }
             try {
                 auto bytes = remote_socket_.available();
                 if (!bytes) {
                     std::cerr << "\nZEROBYTES-R\n";
                     terminate_remote();
                     return;
                 }
                 spliceRemoteToPipe(bytes);
             } catch (const std::runtime_error &e) {
                 std::cerr << "do_remote_socket_read() TERMINATE: "
                           << e.what() << "\n";
                 terminate_remote();
                 return;
             }
             try {
                 splicePipeToClient();
             } catch (const std::runtime_error &e) {
                 std::cerr << "do_remote_socket_read() TERMINATE: "
                           << e.what() << "\n";
                 terminate_client();
                 return;
             }
             do_remote_socket_read();
         }));
}

void SocksClient::do_sdToRemote_read()
{
    //std::cerr << "Polling sdToRemote for reads.\n";
    auto sfd = shared_from_this();
    // The pToRemote_ pipe has data.  Splice it to remote_socket_.
    sdToRemote_.async_read_some
        (ba::null_buffers(), strand_.wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 std::cerr << "crPIPE error: "
                           << boost::system::system_error(ec).what() << "\n";
                 terminate_remote();
                 return;
             }
             try {
                 splicePipeToRemote();
                 if (pToRemote_len_ > 0)
                     do_sdToRemote_read();
                 else if (!pToClient_.is_open())
                     terminate();
             } catch (const std::runtime_error &e) {
                 std::cerr << "do_sdToRemote_read() TERMINATE: "
                           << e.what() << "\n";
                 terminate_remote();
                 return;
             }
         }));
}

void SocksClient::do_sdToClient_read()
{
    //std::cerr << "Polling sdToClient for reads.\n";
    auto sfd = shared_from_this();
    // The pToClient_ pipe has data.  Splice it to client_socket_.
    sdToClient_.async_read_some
        (ba::null_buffers(), strand_.wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 std::cerr << "rcPIPE error: "
                           << boost::system::system_error(ec).what() << "\n";
                 terminate_client();
                 return;
             }
             try {
                 splicePipeToClient();
                 if (pToClient_len_ > 0)
                     do_sdToClient_read();
                 else if (!pToRemote_.is_open())
                     terminate();
             } catch (const std::runtime_error &e) {
                 std::cerr << "do_sdToClient_read() TERMINATE: "
                           << e.what() << "\n";
                 terminate_client();
                 return;
             }
         }));
}

void SocksClient::spliceClientToPipe(std::size_t bytes)
{
    //std::cerr << "client->crPIPE: ";
    if (!sdToRemote_.is_open()) {
        terminate_remote();
        return;
    }
    pToRemote_len_ += spliceit(client_socket_.native_handle(),
                               pToRemote_.native_handle(), bytes);
}

void SocksClient::spliceRemoteToPipe(std::size_t bytes)
{
    //std::cerr << "remote->rcPIPE: ";
    if (!sdToClient_.is_open()) {
        terminate_client();
        return;
    }
    pToClient_len_ += spliceit(remote_socket_.native_handle(),
                               pToClient_.native_handle(), bytes);
}

void SocksClient::splicePipeToClient()
{
    if (!client_socket_.is_open()) {
        terminate_client();
        return;
    }
    //std::cerr << "rcPIPE->client: ";
    pToClient_len_ -= spliceit(sdToClient_.native_handle(),
                               client_socket_.native_handle(), pToClient_len_);
}

void SocksClient::splicePipeToRemote()
{
    if (!remote_socket_.is_open()) {
        terminate_remote();
        return;
    }
    //std::cerr << "crPIPE->remote: ";
    pToRemote_len_ -= spliceit(sdToRemote_.native_handle(),
                               remote_socket_.native_handle(), pToRemote_len_);
}
#else
// Write data read from the client socket to the connect socket.
void SocksClient::do_client_socket_connect_read()
{
    ba::streambuf::mutable_buffers_type ibm
        = client_buf_.prepare(buffer_chunk_size);
    auto sfd = shared_from_this();
    client_socket_.async_read_some
        (ba::buffer(ibm), strand_.wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 terminate();
                 return;
             }
             client_buf_.commit(bytes_xferred);
             // Client is trying to send data to the remote server.  Write it
             // to the remote_socket_.
             ba::async_write(remote_socket_, client_buf_, strand_.wrap(
                             [this, sfd](const boost::system::error_code &ec,
                                         std::size_t bytes_xferred)
                             {
                                 if (ec) {
                                     terminate();
                                     return;
                                 }
                                 client_buf_.consume(bytes_xferred);
                                 do_client_socket_connect_read();
                             }));
         }));
}

// Write data read from the connect socket to the client socket.
void SocksClient::do_remote_socket_read()
{
    ba::streambuf::mutable_buffers_type ibm
        = remote_buf_.prepare(buffer_chunk_size);
    auto sfd = shared_from_this();
    remote_socket_.async_read_some
        (ba::buffer(ibm), strand_.wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 terminate();
                 return;
             }
             remote_buf_.commit(bytes_xferred);
             // Remote server is trying to send data to the client.  Write it
             // to the client_socket_.
             ba::async_write(client_socket_, remote_buf_, strand_.wrap(
                             [this, sfd](const boost::system::error_code &ec,
                                         std::size_t bytes_xferred)
                             {
                                 if (ec) {
                                     terminate();
                                     return;
                                 }
                                 remote_buf_.consume(bytes_xferred);
                                 do_remote_socket_read();
                             }));
         }));
}

#endif

bool SocksClient::is_bind_client_allowed() const
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

bool SocksClient::create_bind_socket(ba::ip::tcp::endpoint ep)
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

bool SocksClient::matches_dst(const boost::asio::ip::address &addr,
                              uint16_t port) const
{
    if (!nk::asio::compare_ip(addr, dst_address_, 128))
        return false;
    if (dst_port_ != port)
        return false;
    return true;
}

void SocksClient::dispatch_tcp_bind()
{
    if (g_disable_bind) {
        send_reply(RplDeny);
        return;
    }
    assert(BPA);
    ba::ip::tcp::endpoint bind_ep;
    auto rcnct = conntracker_connect.find_by_addr_port
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
    conntracker_bindlisten->store(shared_from_this());
    conntracker_hs->remove(this);

    auto sfd = shared_from_this();
    bound_->acceptor_.async_accept
        (remote_socket_, strand_.wrap(
         [this, sfd](const boost::system::error_code &ec)
         {
             if (ec || !init_splice_pipes()) {
                 send_reply(RplFail);
                 bound_.reset();
                 return;
             }
             std::cout << "Accepted a connection to a BIND socket.\n";
             set_remote_socket_options();
             conntracker_bind.store(shared_from_this());
             close_bind_listen_socket();
             send_reply(RplSuccess);
         }));
    send_reply(RplSuccess);
}

bool SocksClient::is_udp_client_allowed(boost::asio::ip::address laddr) const
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
void SocksClient::dispatch_udp()
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

    try {
        udp_ = nk::make_unique<UDPAssoc>
            (io_service, udp_client_ep, udp_remote_ep,
             ba::ip::udp::endpoint(client_ep.address(), client_ep.port()));
    } catch (const boost::system::system_error &) {
        UPA->release_port(udp_local_port);
        UPA->release_port(udp_remote_port);
        send_reply(RplFail);
        return;
    }

    conntracker_udp.store(shared_from_this());

    udp_tcp_socket_read();
    udp_client_socket_read();
    udp_remote_socket_read();

    send_reply(RplSuccess);
}

// Listen for data on client_socket_.  If we get EOF, then terminate the
// entire SocksClient.
void SocksClient::udp_tcp_socket_read()
{
    auto sfd = shared_from_this();
    client_socket_.async_read_some
        (ba::buffer(inBytes_), strand_.wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 std::cerr << "Client closed TCP socket for UDP associate: "
                           << boost::system::system_error(ec).what()
                           << std::endl;
                 terminate();
             }
             udp_tcp_socket_read();
         }));
}

void SocksClient::udp_client_socket_read()
{
    udp_->inbuf_.clear();
    udp_->inbuf_.resize(buffer_chunk_size);
    auto sfd = shared_from_this();
    udp_->client_socket_.async_receive_from
        (ba::buffer(udp_->inbuf_),
         udp_->csender_endpoint_, strand_.wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 std::cerr << "Error on client UDP socket: "
                           << boost::system::system_error(ec).what()
                           << std::endl;
                 terminate();
             }
             if (udp_->csender_endpoint_ == udp_->client_remote_endpoint_) {
                 std::size_t headersiz = 4;
                 if (bytes_xferred < 4)
                     goto nosend;
                 if (udp_->inbuf_[0] != '\0')
                     goto nosend;
                 if (udp_->inbuf_[1] != '\0')
                     goto nosend;
                 auto fragn = udp_->inbuf_[2];
                 if (fragn != '\0') {
                     if (!udp_->frags_)
                         udp_->frags_ = nk::make_unique<UDPFrags>(io_service);
                     if (fragn > 127 && !udp_->frags_->buf_.size())
                         fragn = '\0';
                 }
                 auto atyp = udp_->inbuf_[3];
                 ba::ip::address daddr;
                 std::string dnsname;
                 switch (atyp) {
                     case 1: { // IPv4
                         if (bytes_xferred < 10)
                             goto nosend;
                         ba::ip::address_v4::bytes_type v4o;
                         memcpy(v4o.data(), udp_->inbuf_.data() + headersiz, 4);
                         udp_->daddr_ = ba::ip::address_v4(v4o);
                         headersiz += 4;
                         break;
                     }
                     case 3: { // DNS
                         if (bytes_xferred < 8)
                             goto nosend;
                         size_t dnssiz = udp_->inbuf_[headersiz++];
                         if (bytes_xferred - headersiz < dnssiz + 2)
                             goto nosend;
                         dnsname = std::string
                             (reinterpret_cast<const  char *>
                              (udp_->inbuf_.data() + headersiz), dnssiz);
                         headersiz += dnssiz;
                         break;
                     }
                     case 4: { // IPv6
                         if (bytes_xferred < 22)
                             goto nosend;
                         ba::ip::address_v6::bytes_type v6o;
                         memcpy(v6o.data(), udp_->inbuf_.data() + headersiz, 16);
                         udp_->daddr_ = ba::ip::address_v6(v6o);
                         headersiz += 16;
                         break;
                     }
                     default: goto nosend; break;
                 }
                 memcpy(&udp_->dport_, udp_->inbuf_.data() + headersiz, 2);
                 udp_->dport_ = ntohs(udp_->dport_);
                 headersiz += 2;
                 udp_->poffset_ = headersiz;
                 udp_->psize_ = bytes_xferred - headersiz;

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

bool SocksClient::udp_frags_different(uint8_t fragn, uint8_t atyp,
                                      const std::string &dnsname)
{
    if (fragn <= udp_->frags_->lastn_)
        return true;
    if (udp_->dport_ != udp_->frags_->port_)
        return true;
    if (atyp != 3) {
        if (udp_->daddr_ != udp_->frags_->addr_)
            return true;
    } else { // DNS
        if (dnsname != udp_->frags_->dns_)
            return true;
    }
    return false;
}

// If true then the caller doesn't need to proceed.
bool SocksClient::udp_frag_handle(uint8_t fragn, uint8_t atyp,
                                  const std::string &dnsname)
{
    const bool new_frags(udp_->frags_->buf_.size() == 0);
    const bool send_frags(fragn > 127);
    if (new_frags || udp_frags_different(fragn, atyp, dnsname)) {
        udp_->frags_->reset();
        udp_->frags_->lastn_ = fragn;
        udp_->frags_->port_ = udp_->dport_;
        if (atyp != 3)
            udp_->frags_->addr_ = udp_->daddr_;
        else // DNS
            udp_->frags_->dns_ = dnsname;
    }
    udp_->frags_->buf_.insert
        (udp_->frags_->buf_.end(),
         udp_->inbuf_.begin() + udp_->poffset_,
         udp_->inbuf_.end());
    if (send_frags) {
        udp_->inbuf_ = std::move(udp_->frags_->buf_);
        udp_->poffset_ = 0;
        udp_->psize_ = udp_->inbuf_.size();
        udp_->frags_->reset();
    } else {
        udp_->frags_->reaper_start();
        udp_client_socket_read();
        return true;
    }
    return false;
}

// Forward it to the remote socket.
void SocksClient::udp_proxy_packet()
{
    if (is_dst_denied(udp_->daddr_)) {
        udp_client_socket_read();
        return;
    }
    auto sfd = shared_from_this();
    udp_->remote_socket_.async_send_to
        (ba::buffer(udp_->inbuf_.data() + udp_->poffset_, udp_->psize_),
         ba::ip::udp::endpoint(udp_->daddr_, udp_->dport_), 0, strand_.wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             udp_client_socket_read();
         }));
}

void SocksClient::udp_dns_lookup(const std::string &dnsname)
{
    ba::ip::udp::resolver::query query
        (dnsname, boost::lexical_cast<std::string>(udp_->dport_));
    auto sfd = shared_from_this();
    try {
        udp_->resolver_.async_resolve
            (query, strand_.wrap(
             [this, sfd](const boost::system::error_code &ec,
                         ba::ip::udp::resolver::iterator it)
             {
                 if (ec) {
                     udp_client_socket_read();
                     return;
                 }
                 ba::ip::udp::resolver::iterator fv4, fv6, rie;
                 for (; it != rie; ++it) {
                     bool isv4 = it->endpoint().address().is_v4();
                     if (isv4) {
                         if (g_prefer_ipv4) {
                             udp_->daddr_ = it->endpoint().address();
                             udp_proxy_packet();
                             return;
                         }
                         if (fv4 == rie)
                             fv4 = it;
                     } else {
                         if (!g_prefer_ipv4) {
                             udp_->daddr_ = it->endpoint().address();
                             udp_proxy_packet();
                             return;
                         }
                         if (fv6 == rie)
                             fv6 = it;
                     }
                 }
                 udp_->daddr_ = g_prefer_ipv4 ? fv4->endpoint().address()
                                              : fv6->endpoint().address();
                 if (g_disable_ipv6 && !dst_address_.is_v4()) {
                     udp_client_socket_read();
                     return;
                 }
                 udp_proxy_packet();
             }));
    } catch (const std::exception &) {
        udp_client_socket_read();
    }
}

void SocksClient::udp_remote_socket_read()
{
    auto sfd = shared_from_this();
    udp_->outbuf_.clear();
    udp_->out_header_.clear();
    udp_->out_bufs_.clear();
    udp_->outbuf_.reserve(buffer_chunk_size);
    udp_->remote_socket_.async_receive_from
        (ba::buffer(udp_->outbuf_),
         udp_->rsender_endpoint_, strand_.wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 std::cerr << "Error on remote UDP socket: "
                           << boost::system::system_error(ec).what()
                           << std::endl;
                 terminate();
             }
             // Attach the header.
             auto saddr = udp_->rsender_endpoint_.address();
             uint16_t sport = udp_->rsender_endpoint_.port();
             if (saddr.is_v4()) {
                 udp_->out_header_.append("\0\0\0\x1");
                 auto v4b = saddr.to_v4().to_bytes();
                 for (auto &i: v4b)
                     udp_->out_header_.append(1, i);
             } else {
                 udp_->out_header_.append("\0\0\0\x4");
                 auto v6b = saddr.to_v6().to_bytes();
                 for (auto &i: v6b)
                     udp_->out_header_.append(1, i);
             }
             union {
                 uint16_t p;
                 char b[2];
             } portu;
             portu.p = htons(sport);
             udp_->out_header_.append(1, portu.b[0]);
             udp_->out_header_.append(1, portu.b[1]);
             // Forward it to the client socket.
             udp_->out_bufs_.push_back(boost::asio::buffer(udp_->out_header_));
             udp_->out_bufs_.push_back(boost::asio::buffer(udp_->outbuf_));
             udp_->client_socket_.async_send_to
                 (udp_->out_bufs_, udp_->client_remote_endpoint_, strand_.wrap(
                  [this, sfd](const boost::system::error_code &ec,
                              std::size_t bytes_xferred)
                  {
                      udp_remote_socket_read();
                  }));
         }));
}

void SocksClient::send_reply_binds(ba::ip::tcp::endpoint ep)
{
    auto bnd_addr = ep.address();
    if (bnd_addr.is_v4()) {
        auto v4b = bnd_addr.to_v4().to_bytes();
        outbuf_.append(1, 0x01);
        for (auto &i: v4b)
            outbuf_.append(1, i);
    } else {
        auto v6b = bnd_addr.to_v6().to_bytes();
        outbuf_.append(1, 0x04);
        for (auto &i: v6b)
            outbuf_.append(1, i);
    }
    union {
        uint16_t p;
        char b[2];
    } portu;
    portu.p = htons(ep.port());
    outbuf_.append(1, portu.b[0]);
    outbuf_.append(1, portu.b[1]);
}

void SocksClient::send_reply(ReplyCode replycode)
{
    outbuf_.clear();
    outbuf_.append(1, 0x05);
    outbuf_.append(1, replycode);
    outbuf_.append(1, 0x00);
    if (replycode == RplSuccess) {
        switch (cmd_code_) {
        case CmdTCPConnect:
            send_reply_binds(remote_socket_.local_endpoint());
            break;
        case CmdTCPBind:
            if (bound_)
                send_reply_binds(bound_->local_endpoint_);
            else
                send_reply_binds(remote_socket_.remote_endpoint());
            break;
        case CmdUDP: {
            auto ep = udp_->client_socket_.local_endpoint();
            send_reply_binds(ba::ip::tcp::endpoint(ep.address(), ep.port()));
            break;
        }
        default:
            throw std::logic_error("Invalid cmd_code_ in send_reply().\n");
        }
    }
    sentReplyType_ = replycode;
    assert(!writePending_);
    writePending_ = true;
    auto sfd = shared_from_this();
    ba::async_write
        (client_socket_, ba::buffer(outbuf_, outbuf_.size()), strand_.wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             writePending_ = false;
             if (ec || sentReplyType_ != RplSuccess) {
                 // std::cout << "Connection killed before handshake completed from "
                 //     << client_socket_.remote_endpoint().address()
                 //     << " to "
                 //     << (addr_type_ != AddrDNS ? dst_address_.to_string()
                 //         : dst_hostname_)
                 //     << ":" << dst_port_
                 //     << " with reply code='" << replyCodeString[sentReplyType_]
                 //     << "'\n";
                 terminate();
                 return;
             }
             outbuf_.erase(0, bytes_xferred);
             if (!bound_) {
                 strand_.post([this]() { do_client_socket_connect_read(); });
                 strand_.post([this]() { do_remote_socket_read(); });
             }
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
    // std::cout << "Created a new SocksClient=" << conn.get() << ".\n";
    acceptor_.async_accept
        (socket_, endpoint_,
         [this](const boost::system::error_code &ec)
         {
             if (!ec) {
                 // std::cout << "Stored a new SocksClient="
                 //           << conn.get() << ".\n";
                 auto conn = std::make_shared<SocksClient>
                     (acceptor_.get_io_service(), std::move(socket_));
                 conntracker_hs->store(conn);
                 conn->start();
             }
             start_accept();
         });
}

