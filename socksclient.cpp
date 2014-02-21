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
#include <forward_list>
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

#include "socksclient.hpp"
#include "asio_addrcmp.hpp"

#define MAX_BIND_TRIES 10
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

static unsigned int max_buffer_ms = 250;
void set_max_buffer_ms(unsigned int n) { max_buffer_ms = n; }

std::size_t SocksTCP::send_buffer_chunk_size = 1024;
std::size_t SocksTCP::receive_buffer_chunk_size = 2048;
std::size_t SocksTCP::send_minsplice_size = 768;
std::size_t SocksTCP::receive_minsplice_size = 1536;
void SocksTCP::set_send_buffer_chunk_size(std::size_t size) {
    send_buffer_chunk_size = size;
    send_minsplice_size = size / 4 * 3;
}
void SocksTCP::set_receive_buffer_chunk_size(std::size_t size) {
    receive_buffer_chunk_size = size;
    receive_minsplice_size = size / 4 * 3;
}

static boost::random::random_device g_random_secure;
static boost::random::mt19937 g_random_prng(g_random_secure());

static std::unique_ptr <boost::asio::strand> strand_C;
static std::unique_ptr <boost::asio::strand> strand_R;

template <typename T>
class ephConnTracker : boost::noncopyable
{
public:
    ephConnTracker(ba::io_service &iosrv, std::size_t cyclefreq)
        : cyclefreq_(cyclefreq), hidx_(0), swapTimer_(iosrv) {}
    ~ephConnTracker()
    {
        for (std::size_t j = 0; j < 2; ++j)
            hash_cancel(j);
    }
    void store(std::shared_ptr<T> ssc)
    {
        {
            std::lock_guard<std::mutex> wl(lock_);
            hash_[hidx_].emplace(ssc.get(), ssc);
        }
        if (swapTimer_.expires_from_now() <=
            boost::posix_time::time_duration(0,0,0,0))
            setTimer(false);
    }
    template <typename... Args>
    void emplace(Args&&... args)
    {
        std::shared_ptr<T> y;
        {
            std::lock_guard<std::mutex> wl(lock_);
            auto x = std::make_shared<T>(std::forward<Args>(args)...);
            auto elt = hash_[hidx_].emplace(x.get(), std::move(x));
            if (elt.second)
                y = elt.first->second;
        }
        y->start();
        if (swapTimer_.expires_from_now() <=
            boost::posix_time::time_duration(0,0,0,0))
            setTimer(false);
    }
    bool remove(std::size_t hidx, T* sc)
    {
        std::lock_guard<std::mutex> wl(lock_);
        return remove_nolock(hidx, sc);
    }
    bool remove(T* sc) {
        std::lock_guard<std::mutex> wl(lock_);
        std::size_t hi = hidx_;
        if (!remove_nolock(hi, sc))
            return remove_nolock(hi ^ 1, sc);
        return true;
    }
    std::shared_ptr<T> fetch(T *sc) {
        std::lock_guard<std::mutex> wl(lock_);
        std::size_t hi = hidx_;
        auto elt = hash_[hi].find(sc);
        if (elt == hash_[hi].end()) {
            hi ^= 1;
            elt = hash_[hi].find(sc);
            if (elt == hash_[hi].end())
                throw std::out_of_range("dne");
        }
        std::shared_ptr<T> r;
        elt->second.swap(r);
        hash_[hi].erase(elt);
        return r;
    }
    std::size_t size() { return hash_[0].size() + hash_[1].size(); }
private:
    inline bool remove_nolock(std::size_t hidx, T* sc) {
        return !!hash_[hidx].erase(sc);
    }
    inline void hash_cancel(std::size_t x) {
        for (auto &i: hash_[x]) {
            i.second->cancel();
            i.second->set_terminated();
        }
    }
    void doSwap() {
        std::size_t hnext = hidx_ ^ 1;
        // std::cerr << "doSwap wiped " << hash_[hnext].size()
        //           << " items from hash " << hnext << "\n";
        hash_cancel(hnext);
        hash_[hnext].clear();
        hidx_ = hnext;
    }
    void setTimer(bool expidite) {
        if (expidite)
            swapTimer_.expires_from_now
                (boost::posix_time::seconds(cyclefreq_));
        else
            swapTimer_.expires_from_now
                (boost::posix_time::milliseconds(cyclefreq_ * 100));
        swapTimer_.async_wait([this](const boost::system::error_code& error)
                              {
                                  if (error)
                                      return;
                                  if (lock_.try_lock()) {
                                      doSwap();
                                      auto sz = size();
                                      lock_.unlock();
                                      if (sz)
                                          setTimer(false);
                                  } else
                                      setTimer(true);
                              });
    }
    std::mutex lock_;
    const std::size_t cyclefreq_;
    std::atomic<std::size_t> hidx_;
    ba::deadline_timer swapTimer_;
    std::unordered_map<T*, std::shared_ptr<T>> hash_[2];
};

static std::unique_ptr<ephConnTracker<SocksInit>> conntracker_hs;
static std::unique_ptr<ephConnTracker<SocksInit>> conntracker_bindlisten;

template <typename T>
class connTracker : boost::noncopyable
{
public:
    connTracker() {}
    ~connTracker()
    {
        for (auto &i: hash_) {
            i.second->cancel();
            i.second->set_terminated();
        }
    }
    void store(std::shared_ptr<T> ssc)
    {
        std::lock_guard<std::mutex> wl(lock_);
        hash_.emplace(ssc.get(), ssc);
    }
    template <typename... Args>
    void emplace(Args&&... args)
    {
        std::shared_ptr<T> y;
        {
            std::lock_guard<std::mutex> wl(lock_);
            auto x = std::make_shared<T>(std::forward<Args>(args)...);
            auto elt = hash_.emplace(x.get(), std::move(x));
            if (elt.second)
                y = elt.first->second;
        }
        y->start();
    }
    bool remove(T* sc)
    {
        std::lock_guard<std::mutex> wl(lock_);
        return !!hash_.erase(sc);
    }
    std::shared_ptr<T> fetch(T *sc) {
        std::lock_guard<std::mutex> wl(lock_);
        auto elt = hash_.find(sc);
        if (elt == hash_.end())
            throw std::out_of_range("dne");
        std::shared_ptr<T> r;
        elt->second.swap(r);
        hash_.erase(elt);
        return r;
    }
    bool move_if_dne(T* sc, connTracker<T> &o) {
        std::lock_guard<std::mutex> wl(lock_);
        if (hash_.find(sc) != hash_.end())
            return false;
        return hash_.emplace(sc, o.fetch(sc)).second;
    }
    boost::optional<std::shared_ptr<T>>
    find_by_addr_port(boost::asio::ip::address addr, uint16_t port)
    {
        std::lock_guard<std::mutex> wl(lock_);
        for (auto &i: hash_) {
            if (i.second->matches_dst(addr, port))
                return i.second;
        }
        return boost::optional<std::shared_ptr<T>>();
    }
    std::size_t size() const { return hash_.size(); }

    std::mutex lock_;
    std::unordered_map<T*, std::shared_ptr<T>> hash_;
};

static connTracker<SocksTCP> conntracker_tcp;
static connTracker<SocksUDP> conntracker_udp;

#ifdef USE_SPLICE
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
    conntracker_hs = nk::make_unique<ephConnTracker<SocksInit>>
        (io_service, hs_secs);
    conntracker_bindlisten = nk::make_unique<ephConnTracker<SocksInit>>
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

static std::atomic<std::size_t> socks_alive_count;

static void print_destructor_logentry(const std::string &host, uint16_t port)
{
    std::cout << "Connection to " << host << ":" << port
              << " DESTRUCTED (total: ";
    if (conntracker_hs)
        std::cout << conntracker_hs->size() << ",";
    else
        std::cout << "X,";
    if (conntracker_bindlisten)
        std::cout << conntracker_bindlisten->size() << "|";
    else
        std::cout << "X|";
    std::cout << conntracker_tcp.size() << ","
              << conntracker_udp.size()
              << " / " << socks_alive_count << ")" << std::endl;
}

SocksInit::SocksInit(ba::io_service &io_service,
                     ba::ip::tcp::socket client_socket)
        : terminated_(false), ibSiz_(0), bind_listen_(false),
          auth_none_(false), auth_gssapi_(false), auth_unpw_(false),
          client_socket_(std::move(client_socket)),
          remote_socket_(io_service)
{
    if (g_verbose_logs)
        ++socks_alive_count;
    client_socket_.non_blocking(true);
    client_socket_.set_option(boost::asio::socket_base::keep_alive(true));
}

SocksInit::~SocksInit()
{
    if (!terminated_)
        untrack();
    if (g_verbose_logs) {
        --socks_alive_count;
        print_destructor_logentry(dst_hostname_.size() ? dst_hostname_
                                  : dst_address_.to_string(),
                                  dst_port_);
    }
}

SocksTCP::SocksTCP(ba::io_service &io_service,
                   boost::asio::ip::tcp::socket client_socket,
                   boost::asio::ip::tcp::socket remote_socket,
                   boost::asio::ip::address dst_address,
                   uint16_t dst_port, bool is_bind, std::string dst_hostname)
        : terminated_(false),
          dst_hostname_(dst_hostname), dst_address_(dst_address),
          client_socket_(std::move(client_socket)),
          remote_socket_(std::move(remote_socket)),
          dst_port_(dst_port), is_bind_(is_bind),
#ifdef USE_SPLICE
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
        print_destructor_logentry(dst_hostname_.size() ? dst_hostname_
                                  : dst_address_.to_string(),
                                  dst_port_);
    }
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
static inline void pipe_close_raw(ba::posix::stream_descriptor &sa,
                                  ba::posix::stream_descriptor &sb)
{
    boost::system::error_code ec;
    auto sao = sa.is_open();
    auto sbo = sb.is_open();
    if (sao)
        sa.cancel(ec);
    if (sbo)
        sb.cancel(ec);
    if (sao)
        sa.close(ec);
    if (sbo)
        sb.close(ec);
}

static inline bool pipe_close(ba::posix::stream_descriptor &sa,
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
    p_len = 0;
    pipe_close_raw(sa, sb);
    if (sro)
        tcp_socket_close(s_reader);
    if (ret)
        s_writer.shutdown(ba::ip::tcp::socket::shutdown_receive, ec);
    return ret;
}

void SocksTCP::close_pipe_to_client()
{
    boost::system::error_code ec;
    assert(pToClient_len_ == 0);
    sdToClient_.cancel(ec);
    pToClient_len_ = 0;
    pipe_close_raw(pToClient_, sdToClient_);
}

void SocksTCP::close_pipe_to_remote()
{
    boost::system::error_code ec;
    assert(pToRemote_len_ == 0);
    sdToRemote_.cancel(ec);
    pToRemote_len_ = 0;
    pipe_close_raw(pToRemote_, sdToRemote_);
}

bool SocksTCP::close_client_socket()
{
    boost::system::error_code ec;
    sdToClient_.cancel(ec);
    return pipe_close(pToClient_, sdToClient_, pToClient_len_,
                      client_socket_, remote_socket_);
}

bool SocksTCP::close_remote_socket()
{
    boost::system::error_code ec;
    sdToRemote_.cancel(ec);
    return pipe_close(pToRemote_, sdToRemote_, pToRemote_len_,
                      remote_socket_, client_socket_);
}
#else
bool SocksTCP::close_client_socket() { close_cr_socket(client_socket_); return false; }
bool SocksTCP::close_remote_socket() { close_cr_socket(remote_socket_); return false; }
#endif

void SocksTCP::untrack()
{
    conntracker_tcp.remove(this);
}

void SocksTCP::cancel()
{
    close_remote_socket();
    close_client_socket();
}

void SocksTCP::terminate()
{
    if (terminated_)
        return;
    terminated_ = true;
    cancel();
    untrack();
    // std::cout << "Connection to "
    //           << (dst_hostname_.size() ? dst_hostname_
    //                                    : dst_address_.to_string())
    //           << ":" << dst_port_ << " called terminate()." << std::endl;
}

void SocksInit::untrack()
{
    if (!bind_listen_) conntracker_hs->remove(this);
    else conntracker_bindlisten->remove(this);
}

void SocksInit::cancel()
{
    close_cr_socket(client_socket_);
    close_cr_socket(remote_socket_);
}

void SocksInit::terminate()
{
    if (terminated_)
        return;
    terminated_ = true;
    cancel();
    untrack();
}

void SocksInit::read_greet()
{
    auto sfd = shared_from_this();
    client_socket_.async_read_some
        (ba::buffer(inBytes_.data() + ibSiz_, inBytes_.size() - ibSiz_),
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
             auto x = process_greet();
             if (x) {
                 if (*x)
                     read_conn_request();
                 else {
                     std::cerr << "process_greet(): bad input -> terminate!\n";
                     terminate();
                 }
             } else
                 read_greet();
         }));
}

void SocksInit::read_conn_request()
{
    auto sfd = shared_from_this();
    client_socket_.async_read_some
        (ba::buffer(inBytes_.data() + ibSiz_, inBytes_.size() - ibSiz_),
         strand_C->wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
             if (ec) {
                 if (ec != ba::error::operation_aborted) {
                     std::cerr << "read_conn_request() error: "
                               << boost::system::system_error(ec).what()
                               << std::endl;
                     terminate();
                 }
                 return;
             }
             if (!bytes_xferred)
                 return;
             ibSiz_ += bytes_xferred;
             auto rc = process_connrq();
             if (rc) {
                 // On failure we will terminate via the send_reply() response.
                 if (*rc != RplSuccess)
                     send_reply(*rc);
             } else
                 read_conn_request();
         }));
}

// We don't support authentication.
static const char reply_greetz[2] = {'\x5','\x0'};

// Returns false if the object needs to be destroyed by the caller.
boost::optional<bool> SocksInit::process_greet()
{
    if (terminated_)
        return false;

    size_t poff = 0;

    // We only accept Socks5.
    if (poff == ibSiz_)
        return boost::optional<bool>();
    if (inBytes_[poff] != 0x05)
        return false;
    ++poff;

    // Number of authentication methods supported.
    if (poff == ibSiz_)
        return boost::optional<bool>();
    size_t nauth = static_cast<uint8_t>(inBytes_[poff]);
    ++poff;

    // Types of authentication methods supported.
    size_t aendsiz = nauth + 2;
    // If buffer is too long, kill the connection.  If it's not long enough,
    // wait for more data.  If it's just right, proceed.
    if (ibSiz_ > aendsiz)
        return false;
    if (ibSiz_ < aendsiz)
        return boost::optional<bool>();
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
    return true;
}

// Returns false if the object needs to be destroyed by the caller.
boost::optional<SocksInit::ReplyCode> SocksInit::process_connrq()
{
    if (terminated_)
        return RplFail;

    size_t poff = 0;

    // We only accept Socks5.
    if (poff == ibSiz_)
        return boost::optional<SocksInit::ReplyCode>();
    if (inBytes_[poff] != 0x05)
        return RplFail;
    ++poff;

    // Client command.
    if (poff == ibSiz_)
        return boost::optional<SocksInit::ReplyCode>();
    switch (static_cast<uint8_t>(inBytes_[poff])) {
    case 0x1: cmd_code_ = CmdTCPConnect; break;
    case 0x2: cmd_code_ = CmdTCPBind; break;
    case 0x3: cmd_code_ = CmdUDP; break;
    default: return RplCmdNotSupp;
    }
    ++poff;

    // Must be zero (reserved).
    if (poff == ibSiz_)
        return boost::optional<SocksInit::ReplyCode>();
    if (inBytes_[poff] != 0x0)
        return RplFail;
    ++poff;

    // Address type.
    if (poff == ibSiz_)
        return boost::optional<SocksInit::ReplyCode>();
    switch (static_cast<uint8_t>(inBytes_[poff])) {
    case 0x1: addr_type_ = AddrIPv4; break;
    case 0x3: addr_type_ = AddrDNS; break;
    case 0x4: addr_type_ = AddrIPv6; break;
    default: return RplAddrNotSupp;
    }
    ++poff;

    // Destination address.
    if (poff == ibSiz_)
        return boost::optional<SocksInit::ReplyCode>();
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
        return boost::optional<SocksInit::ReplyCode>();
    if (ibSiz_ - poff != 2)
        return RplFail;
    uint16_t tmp;
    memcpy(&tmp, inBytes_.data() + poff, 2);
    dst_port_ = ntohs(tmp);
    ibSiz_ = 0;
    dispatch_connrq();
    return RplSuccess;
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
             conntracker_hs->remove(this);
             conntracker_tcp.emplace(io_service,
                   std::move(client_socket_), std::move(remote_socket_),
                   std::move(dst_address_), dst_port_, false,
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

#ifdef USE_SPLICE
bool SocksTCP::init_pipe_client()
{
    int pipes[2];
    if (pipe2(pipes, O_NONBLOCK))
        return false;
    sdToRemote_.assign(pipes[0]);
    pToRemote_.assign(pipes[1]);
    return true;
}

bool SocksTCP::init_pipe_remote()
{
    int pipes[2];
    if (pipe2(pipes, O_NONBLOCK))
        return false;
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
                    for (i = cSpliceList.begin(),
                         ip = cSpliceList.before_begin(),
                         ipp = cSpliceList.before_begin();
                         i != cSpliceList.end(); ipp = ip, ip = i++)
                    {
                        if (erase_ipp) {
                            cSpliceList.erase_after(ipp);
                            ip = ipp;
                        }
                        auto k = i->lock();
                        erase_ipp = (!k || !k->is_remote_splicing() ||
                                     !k->kickClientPipe(now));
                    }
                    if (erase_ipp)
                        cSpliceList.erase_after(ipp);
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
                    for (i = rSpliceList.begin(),
                         ip = rSpliceList.before_begin(),
                         ipp = rSpliceList.before_begin();
                         i != rSpliceList.end(); ipp = ip, ip = i++)
                    {
                        if (erase_ipp) {
                            rSpliceList.erase_after(ipp);
                            ip = ipp;
                        }
                        auto k = i->lock();
                        erase_ipp = (!k || !k->is_client_splicing() ||
                                     !k->kickRemotePipe(now));
                    }
                    if (erase_ipp)
                        rSpliceList.erase_after(ipp);
                    if (!rSpliceList.empty())
                        kickRemotePipeTimer();
                }));
    }
}

// Ret: Is the connection still alive?
bool SocksTCP::kickClientPipe(const std::chrono::high_resolution_clock::time_point &now)
{
    size_t l = pToClient_len_;
    if (l == 0)
        return true;
    if (std::chrono::duration_cast<std::chrono::milliseconds>
        (remote_read_ts_ - now).count() < max_buffer_ms / 2U)
        return true;
    auto n = splicePipeToClient(true);
    if (!n)
        return false;
    if (l - *n > 0) {
        strand_R->post([this]() { kickClientPipeBG(); });
        return true;
    }
    std::cerr << "kicked client pipe\n";
    return true;
}

void SocksTCP::kickClientPipeBG()
{
    std::cerr << "kicked client pipe (more left)\n";
    auto sfd = shared_from_this();
    sdToClient_.async_read_some
        (ba::null_buffers(), strand_R->wrap(
         [this, sfd](const boost::system::error_code &ec,
                     std::size_t bytes_xferred)
         {
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
             auto now = std::chrono::high_resolution_clock::now();
             if (std::chrono::duration_cast<std::chrono::milliseconds>
                 (remote_read_ts_ - now).count() < max_buffer_ms / 2U)
                 return;
             if (pToClient_len_ > 0)
                 kickClientPipeBG();
         }));
}

// Ret: Is the connection still alive?
bool SocksTCP::kickRemotePipe(const std::chrono::high_resolution_clock::time_point &now)
{
    size_t l = pToRemote_len_;
    if (l == 0)
        return true;
    if (std::chrono::duration_cast<std::chrono::milliseconds>
        (client_read_ts_ - now).count() < max_buffer_ms / 2U)
        return true;
    auto n = splicePipeToRemote(true);
    if (!n)
        return false;
    if (l - *n > 0) {
        strand_C->post([this]() { kickRemotePipeBG(); });
        return true;
    }
    std::cerr << "kicked remote pipe\n";
    return true;
}

void SocksTCP::kickRemotePipeBG()
{
    std::cerr << "kicked remote pipe (more left)\n";
    auto sfd = shared_from_this();
    sdToRemote_.async_read_some
        (ba::null_buffers(), strand_C->wrap(
            [this, sfd](const boost::system::error_code &ec,
                        std::size_t bytes_xferred)
            {
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
                auto now = std::chrono::high_resolution_clock::now();
                if (std::chrono::duration_cast<std::chrono::milliseconds>
                    (client_read_ts_ - now).count() < max_buffer_ms / 2U)
                    return;
                if (pToRemote_len_ > 0)
                    kickRemotePipeBG();
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
                 if (*n == 0) {
                     if (pToRemote_len_ > 0)
                         flushPipeToRemote(false);
                     else {
                         close_pipe_to_remote();
                         tcp_client_socket_read();
                     }
                     return;
                 }
                 pToRemote_len_ += *n;
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
                 if (*n == 0) {
                     if (pToClient_len_ > 0)
                         flushPipeToClient(false);
                     else {
                         close_pipe_to_client();
                         tcp_remote_socket_read();
                     }
                     return;
                 }
                 pToClient_len_ += *n;
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
    if (pToRemote_len_ == 0) {
        if (closing) terminate_remote();
        else tcp_client_socket_read_splice();
        return;
    }
    auto sfd = shared_from_this();
    sdToRemote_.async_read_some
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
             doFlushPipeToRemote(closing);
         }));
}

void SocksTCP::doFlushPipeToClient(bool closing)
{
    if (pToClient_len_ == 0) {
        if (closing) terminate_client();
        else tcp_remote_socket_read_splice();
        return;
    }
    auto sfd = shared_from_this();
    sdToClient_.async_read_some
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
    try {
        conntracker_bindlisten->store(conntracker_hs->fetch(this));
    } catch (const std::out_of_range &) {
        std::cerr << "conntracker /hs->bindlisten/ failed\n";
        send_reply(RplFail);
        return;
    }
    bind_listen_ = true;

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
             conntracker_bindlisten->remove(this);
             conntracker_tcp.emplace(io_service,
                   std::move(client_socket_),
                   std::move(remote_socket_),
                   std::move(dst_address_), dst_port_, true,
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

    conntracker_hs->remove(this);
    conntracker_udp.emplace(io_service,
        std::move(client_socket_), udp_client_ep, udp_remote_ep,
        ba::ip::udp::endpoint(client_ep.address(), client_ep.port()));
}

static inline void send_reply_code(std::string &outbuf,
                                   SocksInit::ReplyCode replycode)
{
    outbuf.clear();
    outbuf.append(1, 0x05);
    outbuf.append(1, replycode);
    outbuf.append(1, 0x00);
}

static inline void send_reply_binds(std::string &outbuf,
                                    ba::ip::tcp::endpoint ep)
{
    auto bnd_addr = ep.address();
    if (bnd_addr.is_v4()) {
        auto v4b = bnd_addr.to_v4().to_bytes();
        outbuf.append(1, 0x01);
        for (auto &i: v4b)
            outbuf.append(1, i);
    } else {
        auto v6b = bnd_addr.to_v6().to_bytes();
        outbuf.append(1, 0x04);
        for (auto &i: v6b)
            outbuf.append(1, i);
    }
    union {
        uint16_t p;
        char b[2];
    } portu;
    portu.p = htons(ep.port());
    outbuf.append(1, portu.b[0]);
    outbuf.append(1, portu.b[1]);
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

void SocksTCP::start()
{
    std::string ob;
    send_reply_code(ob, SocksInit::ReplyCode::RplSuccess);
    if (!is_bind_) send_reply_binds(ob, remote_socket_.local_endpoint());
    else send_reply_binds(ob, remote_socket_.remote_endpoint());;
    auto sfd = shared_from_this();
    auto ibm = client_buf_.prepare(ob.size());
    auto siz = std::min(ob.size(), boost::asio::buffer_size(ibm));
    memcpy(boost::asio::buffer_cast<char *>(ibm), ob.data(), siz);
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

void SocksInit::send_reply(ReplyCode replycode)
{
    send_reply_code(outbuf_, replycode);
    if (replycode == RplSuccess) {
        if (cmd_code_ != CmdTCPBind || !bound_) {
            throw std::logic_error
                ("cmd_code_ != CmdTCPBind || !bound_ in send_reply(RplSuccess).\n");
        } else
            send_reply_binds(outbuf_, bound_->local_endpoint_);
    }
    auto sfd = shared_from_this();
    ba::async_write
        (client_socket_,
         ba::buffer(outbuf_, outbuf_.size()),
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

SocksUDP::SocksUDP(ba::io_service &io_service,
                   ba::ip::tcp::socket tcp_client_socket,
                   ba::ip::udp::endpoint client_ep,
                   ba::ip::udp::endpoint remote_ep,
                   ba::ip::udp::endpoint client_remote_ep)
        : terminated_(false), tcp_client_socket_(std::move(tcp_client_socket)),
          client_endpoint_(client_ep), remote_endpoint_(remote_ep),
          client_remote_endpoint_(client_remote_ep),
          client_socket_(io_service, client_ep),
          remote_socket_(io_service, remote_ep),
          resolver_(io_service)
{
    if (g_verbose_logs)
        ++socks_alive_count;
}

SocksUDP::~SocksUDP()
{
    if (!terminated_)
        untrack();
    if (g_verbose_logs) {
        --socks_alive_count;
        print_destructor_logentry("(n/a)", 0);
    }
}

void SocksUDP::untrack()
{
    conntracker_udp.remove(this);
}

void SocksUDP::cancel()
{
    close_udp_sockets();
}

void SocksUDP::terminate()
{
    if (terminated_)
        return;
    terminated_ = true;
    cancel();
    untrack();
}

void SocksUDP::start()
{
    send_reply_code(out_header_, SocksInit::ReplyCode::RplSuccess);
    auto ep = client_socket_.local_endpoint();
    send_reply_binds(out_header_,
                     ba::ip::tcp::endpoint(ep.address(), ep.port()));
    auto sfd = shared_from_this();
    ba::async_write
        (tcp_client_socket_, ba::buffer(out_header_, out_header_.size()),
         strand_C->wrap(
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
             out_header_.clear();
             udp_tcp_socket_read();
             udp_client_socket_read();
             udp_remote_socket_read();
         }));
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
    out_header_.clear();
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
             if (saddr.is_v4()) {
                 out_header_.append("\0\0\0\x1");
                 auto v4b = saddr.to_v4().to_bytes();
                 for (auto &i: v4b)
                     out_header_.append(1, i);
             } else {
                 out_header_.append("\0\0\0\x4");
                 auto v6b = saddr.to_v6().to_bytes();
                 for (auto &i: v6b)
                     out_header_.append(1, i);
             }
             union {
                 uint16_t p;
                 char b[2];
             } portu;
             portu.p = htons(sport);
             out_header_.append(1, portu.b[0]);
             out_header_.append(1, portu.b[1]);
             // Forward it to the client socket.
             out_bufs_.push_back(boost::asio::buffer(out_header_));
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
