/* socksclient.cpp - socks client request handling
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

#include <iostream>
#include <unordered_map>

#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>

#include "socksclient.hpp"

extern "C" {
#include "log.h"
}

namespace ba = boost::asio;

extern ba::io_service io_service;
extern bool gParanoid;
extern bool gChrooted;

bool g_prefer_ipv4 = false;

static std::size_t listen_queuelen = 256;
void set_listen_queuelen(std::size_t len) { listen_queuelen = len; }

#ifdef USE_SPLICE
static std::size_t buffer_chunk_size = 4096;
void set_buffer_chunk_size(std::size_t size) { buffer_chunk_size = size; }
#endif

class ephConnTracker
{
public:
    ephConnTracker(ba::io_service &iosrv, std::size_t cyclefreq)
        : cyclefreq_(cyclefreq), hidx_(0), swapTimer_(iosrv) {}
    void store(std::shared_ptr<SocksClient> ssc)
    {
        SocksClient *p = ssc.get();
        std::cerr << "hidx_ = " << hidx_ << "\n";
        hash_[hidx_][p] = ssc;
        if (swapTimer_.expires_from_now() <=
            boost::posix_time::time_duration(0,0,0,0))
            setTimer();
    }
    bool remove(std::size_t hidx, SocksClient* sc)
    {
        auto& h = hash_[hidx];
        auto it = h.find(sc);
        if (it != h.end()) {
            h.erase(it);
            return true;
        }
        return false;
    }
    bool remove(SocksClient* sc) {
        if (!remove(hidx_, sc))
            return remove(hidx_ ^ 1, sc);
        return true;
    }
private:
    void doSwap() {
        std::size_t hnext = hidx_ ^ 1;
        hash_[hnext].clear();
        hidx_ = hnext;
    }
    void setTimer(void) {
        swapTimer_.expires_from_now(boost::posix_time::seconds(cyclefreq_));
        swapTimer_.async_wait(boost::bind(&ephConnTracker::timerHandler,
                                          this, ba::placeholders::error));
    }
    void timerHandler(const boost::system::error_code& error) {
        doSwap();
        if (hash_[0].size() || hash_[1].size())
            setTimer();
    }
    std::size_t cyclefreq_;
    std::size_t hidx_;
    ba::deadline_timer swapTimer_;
    std::unordered_map<SocksClient*, std::shared_ptr<SocksClient>> hash_[2];
};

class connTracker
{
public:
    explicit connTracker(SocksClientType client_type)
        : client_type_(client_type) {}
    void store(std::shared_ptr<SocksClient> ssc)
    {
        ssc->setClientType(client_type_);
        hash_[ssc.get()] = ssc;
    }
    bool remove(SocksClient* sc)
    {
        auto it = hash_.find(sc);
        if (it != hash_.end()) {
            hash_.erase(it);
            return true;
        }
        return false;
    }
private:
    SocksClientType client_type_;
    std::unordered_map<SocksClient*, std::shared_ptr<SocksClient>> hash_;
};

static ephConnTracker *conntracker_hs;
static connTracker conntracker_connect(SCT_CONNECT);
static connTracker conntracker_bind(SCT_BIND);
static connTracker conntracker_udp(SCT_UDP);

void init_conntracker_hs()
{
    std::cerr << "init_conntracker_hs() called\n";
    conntracker_hs = new ephConnTracker(io_service, 5);
}

#if 0
class ConnectPortAssigner
{
public:
    ConnectPortAssigner(uint16_t start, uint16_t end) :
        start_port_(start), end_port_(end), current_port_(start);
    uint16_t get_port()
    {
        uint16_t port = current_port_++;
        if (current_port_ > end_port_ || current_port_ < start_port_)
            current_port_ = start_port_;
        return port;
    }
private:
    uint16_t start_port;
    uint16_t end_port;
    uint16_t current_port;
};

static ConnectPortAssigner CPA(48000, 49000);
#endif

SocksClient::SocksClient(ba::io_service &io_service)
        : client_socket_(io_service), remote_socket_(io_service),
          tcp_resolver_(io_service), client_type_(SCT_INIT),
          markedForDeath_(false), client_socket_reading_(false),
          remote_socket_reading_(false)
#ifdef USE_SPLICE
          ,
          pToRemote_init_(false), pToClient_init_(false),
          pToRemote_reading_(false), pToClient_reading_(false),
          pToRemote_len_(0), pToClient_len_(0),
          sdToRemote_(io_service), sdToClient_(io_service)
#endif
{
    state_ = STATE_WAITGREET;
    writePending_ = false;
}

SocksClient::~SocksClient()
{
#ifdef USE_SPLICE
    if (pToRemote_init_) {
        close(pToRemote_[0]);
        close(pToRemote_[1]);
    }
    if (pToClient_init_) {
        close(pToClient_[0]);
        close(pToClient_[1]);
    }
#endif
}

void SocksClient::close_client_socket()
{
    markedForDeath_ = true;
#ifdef USE_SPLICE
    try {
        if (sdToClient_.is_open()) {
            pToClient_len_ = 0;
            sdToClient_.close();
            close(pToClient_[1]);
            pToClient_init_ = false;
        }
    } catch (...) {}
#endif
    try {
        if (client_socket_.is_open())
            client_socket_.close();
    } catch (...) {}
}

void SocksClient::close_remote_socket()
{
    markedForDeath_ = true;
#ifdef USE_SPLICE
    try {
        if (sdToRemote_.is_open()) {
            pToRemote_len_ = 0;
            sdToRemote_.close();
            close(pToRemote_[1]);
            pToRemote_init_ = false;
        }
    } catch (...) {}
#endif
    try {
        if (remote_socket_.is_open())
            remote_socket_.close();
    } catch (...) {}
}

void SocksClient::terminate()
{
    close_remote_socket();
    close_client_socket();
    switch (client_type_) {
    case SCT_INIT: conntracker_hs->remove(this); break;
    case SCT_CONNECT: conntracker_connect.remove(this); break;
    case SCT_BIND: conntracker_bind.remove(this); break;
    case SCT_UDP: conntracker_udp.remove(this); break;
    }
    state_ = STATE_DONE;
    std::cout << "Connection terminated.\n";
}

void SocksClient::conditional_terminate()
{
    bool rso = remote_socket_.is_open();
    bool cso = client_socket_.is_open();
    if (rso && cso)
        return;
    if (!rso && !cso)
        terminate();
    if (!rso && !pToClient_len_)
        terminate();
    if (!cso && !pToRemote_len_)
        terminate();
}

void SocksClient::do_read()
{
    client_socket_.async_read_some
        (ba::buffer(inBytes_),
         boost::bind(&SocksClient::read_handler, shared_from_this(),
                     ba::placeholders::error,
                     ba::placeholders::bytes_transferred));
}

void SocksClient::read_handler(const boost::system::error_code &ec,
                                    std::size_t bytes_xferred)
{
    if (state_ != STATE_DONE && ec) {
        std::cerr << "Client read error: "
                  << boost::system::system_error(ec).what() << std::endl;
        return;
    }
    if (!bytes_xferred)
        return;
    inbuf_.append(inBytes_.data(), bytes_xferred);
    if (!process_input()) {
        std::cout << "process_input(): returned false -> terminate!\n";
        terminate();
        return;
    }
    if (state_ != STATE_GOTCONNRQ)
        do_read();
}

void SocksClient::do_write()
{
    std::cout << "do_write(): '" << outbuf_ << "'\n";
    assert(!writePending_);
    writePending_ = true;
    ba::async_write(
        client_socket_, ba::buffer(outbuf_),
        boost::bind(&SocksClient::write_handler, shared_from_this(),
                    ba::placeholders::error,
                    ba::placeholders::bytes_transferred));
}

void SocksClient::write_handler(const boost::system::error_code &ec,
                                     std::size_t bytes_xferred)
{
    writePending_ = false;
    if (ec) {
        std::cerr << "Client write error: "
                  << boost::system::system_error(ec).what() << std::endl;
        return;
    }
    outbuf_.erase(0, bytes_xferred);
    if (outbuf_.size())
        do_write();
    // XXX: I think this is wrong for this program; is correct for nident.
    // else
    //     terminate();
}

void SocksClient::write()
{
    if (!writePending_)
        do_write();
}

// Returns false if the object needs to be destroyed by the caller.
bool SocksClient::process_input()
{
    switch (state_) {
    case STATE_WAITGREET:
        std::cout << "process_input(): STATE_WAITGREET\n";
        if (!process_greet())
            return false;
        break;
    case STATE_WAITCONNRQ:
        std::cout << "process_input(): STATE_WAITCONNRQ\n";
        if (!process_connrq())
            return false;
        break;
    default:
        return false;
    }
    return true;
}

// Returns false if the object needs to be destroyed by the caller.
// State can change: STATE_WAITGREET -> STATE_WAITCONNRQ
bool SocksClient::process_greet()
{
    if (state_ != STATE_WAITGREET)
        return false;
    std::cout << "process_greet(): 1\n";

    size_t poff = 0;
    size_t isiz = inbuf_.size();
    size_t nauth = 0;

    // We only accept Socks5.
    if (poff == isiz)
        return true;
    if (inbuf_[poff] != 0x05)
        return false;
    ++poff;
    std::cout << "process_greet(): 2\n";

    // Number of authentication methods supported.
    if (poff == isiz)
        return true;
    nauth = static_cast<uint8_t>(inbuf_[poff]);
    ++poff;
    std::cout << "process_greet(): 3\n";

    // Types of authentication methods supported.
    size_t aendsiz = nauth + 2;
    // If buffer is too long, kill the connection.  If it's not long enough,
    // wait for more data.  If it's just right, proceed.
    if (isiz > aendsiz)
        return false;
    std::cout << "process_greet(): 4\n";
    if (isiz < aendsiz)
        return true;
    std::cout << "process_greet(): 5\n";
    for (;poff < aendsiz; ++poff) {
        uint8_t atype = static_cast<uint8_t>(inbuf_[poff]);
        if (atype == 0x0)
            auth_none_ = true;
        if (atype == 0x1)
            auth_gssapi_ = true;
        if (atype == 0x2)
            auth_unpw_ = true;
    }
    inbuf_.clear();
    std::cout << "process_greet(): end\n";
    return reply_greet();
}

// Returns false if the object needs to be destroyed by the caller.
// State can change: STATE_WAITGREET -> STATE_WAITCONNRQ
bool SocksClient::reply_greet()
{
    if (!auth_none_)
        return false;
    std::cout << "reply_greet(): 1\n";

    outbuf_ += '\x5';
    outbuf_ += '\x0'; // We don't support authentication.
    write();
    std::cout << "reply_greet(): end -> STATE_WAITCONNRQ\n";
    state_ = STATE_WAITCONNRQ;
    return true;
}

// Returns false if the object needs to be destroyed by the caller.
// State can change: STATE_WAITCONNRQ -> STATE_GOTCONNRQ
bool SocksClient::process_connrq()
{
    if (state_ != STATE_WAITCONNRQ)
        return false;

    size_t poff = 0;
    size_t isiz = inbuf_.size();

    // We only accept Socks5.
    if (poff == isiz)
        return true;
    if (inbuf_[poff] != 0x05)
        return false;
    std::cout << "reply_greet(): SOCKS version: "
              << static_cast<uint32_t>(inbuf_[poff]) << "\n";
    ++poff;

    // Client command.
    if (poff == isiz)
        return true;
    switch (static_cast<uint8_t>(inbuf_[poff])) {
    case 0x1: cmd_code_ = CmdTCPConnect; break;
    case 0x2: cmd_code_ = CmdTCPBind; break;
    case 0x3: cmd_code_ = CmdUDP; break;
    default: return false; break;
    }
    ++poff;
    std::cout << "reply_greet(): cmd_code_ == " << cmd_code_ << "\n";

    // Must be zero (reserved).
    if (poff == isiz)
        return true;
    if (inbuf_[poff] != 0x0)
        return false;
    ++poff;
    std::cout << "reply_greet(): reserved byte is zero\n";

    // Address type.
    if (poff == isiz)
        return true;
    switch (static_cast<uint8_t>(inbuf_[poff])) {
    case 0x1: addr_type_ = AddrIPv4; break;
    case 0x3: addr_type_ = AddrDNS; break;
    case 0x4: addr_type_ = AddrIPv6; break;
    default: return false; break;
    }
    ++poff;

    // Destination address.
    if (poff == isiz)
        return true;
    switch (addr_type_) {
        case AddrIPv4: {
            std::cout << "reply_greet(): dst is ipv4\n";
            // isiz = 10, poff = 4
            std::cout << "isiz == " << isiz << " && poff == " << poff << "\n";
            if (isiz - poff != 6)
                return false;
            std::cout << "reply_greet(): ipv4 len ok\n";
            ba::ip::address_v4::bytes_type v4o;
            memcpy(v4o.data(), inbuf_.data() + poff, 4);
            dst_address_ = ba::ip::address_v4(v4o);
            poff += 4;
            break;
        }
        case AddrIPv6: {
            std::cout << "reply_greet(): dst is ipv6\n";
            if (isiz - poff != 18)
                return false;
            std::cout << "reply_greet(): ipv6 len ok\n";
            ba::ip::address_v6::bytes_type v6o;
            memcpy(v6o.data(), inbuf_.data() + poff, 16);
            dst_address_ = ba::ip::address_v6(v6o);
            poff += 16;
            break;
        }
        case AddrDNS: {
            std::cout << "reply_greet(): dst is dnshost\n";
            size_t dnssiz = static_cast<uint8_t>(inbuf_[poff]);
            ++poff;
            if (isiz - poff != dnssiz + 2)
                return false;
            std::cout << "reply_greet(): dnshost len ok\n";
            dst_hostname_ = std::string(inbuf_.data() + poff, dnssiz);
            poff += dnssiz;
            break;
        }
        default:
            std::cout << "reply_greet(): unknown address type: "
                      << addr_type_ << "\n";
            return false;
    }
    if (addr_type_ != AddrDNS)
        std::cout << "reply_greet(): dst_address_ = " << dst_address_ << "\n";
    else
        std::cout << "reply_greet(): dst_hostname_ = " << dst_hostname_ << "\n";

    // Destination port.
    if (poff == isiz)
        return true;
    if (isiz - poff != 2)
        return false;
    uint16_t tmp;
    memcpy(&tmp, inbuf_.data() + poff, 2);
    dst_port_ = ntohs(tmp);
    std::cout << "reply_greet(): dst_port_ = " << dst_port_ << "\n";
    inbuf_.clear();
    state_ = STATE_GOTCONNRQ;
    std::cout << "reply_greet(): end -> STATE_GOTCONNRQ\n";
    dispatch_connrq();
    return true;
}

void SocksClient::resolve_handler(const boost::system::error_code &ec,
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
    dispatch_connrq();
}

void SocksClient::dispatch_connrq()
{
    if (dst_hostname_.size() > 0 && dst_address_.is_unspecified()) {
        ba::ip::tcp::resolver::query query
            (dst_hostname_, boost::lexical_cast<std::string>(dst_port_));
        try {
            tcp_resolver_.async_resolve
                (query, boost::bind(&SocksClient::resolve_handler,
                                    shared_from_this(),
                                    ba::placeholders::error,
                                    ba::placeholders::iterator));
        } catch (std::exception const e) {
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

bool SocksClient::dispatch_tcp_connect()
{
    std::cout << "dispatch_tcp_connect()\n";
    // Connect to the remote address.  If we connect successfully, then
    // open a proxying local tcp socket and inform the requesting client.
    auto ep = ba::ip::tcp::endpoint(dst_address_, dst_port_);
    remote_socket_.async_connect
        (ep, boost::bind(&SocksClient::tcp_connect_handler, shared_from_this(),
                         ba::placeholders::error));
    return true;
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

void SocksClient::tcp_connect_handler(const boost::system::error_code &ec)
{
    if (ec) {
        send_reply(errorToReplyCode(ec));
        return;
    }
    remote_socket_.non_blocking(true);
    remote_socket_.set_option(ba::socket_base::keep_alive(true));
    // Now we have a live socket, so we need to inform the client and then
    // begin proxying data.
    conntracker_connect.store(shared_from_this());
    conntracker_hs->remove(this);
#ifdef USE_SPLICE
    int err;
    err = pipe2(pToRemote_, O_NONBLOCK);
    if (err) {
        send_reply(RplFail);
        return;
    }
    pToRemote_init_ = true;
    err = pipe2(pToClient_, O_NONBLOCK);
    if (err) {
        send_reply(RplFail);
        return;
    }
    pToClient_init_ = true;
    sdToRemote_.assign(pToRemote_[0]);
    sdToClient_.assign(pToClient_[0]);
    //do_sdToRemote_read();
    //do_sdToClient_read();
#endif
    std::cout << "Successful setup.  Starting to proxy.\n";
    send_reply(RplSuccess);
}

#ifdef USE_SPLICE
// Write data read from the client socket to the connect socket.
void SocksClient::do_client_socket_connect_read()
{
    if (client_socket_reading_)
        return;
    client_socket_reading_ = true;
    client_socket_.async_read_some
        (ba::null_buffers(),
         boost::bind(&SocksClient::client_socket_read_handler,
                     shared_from_this(), ba::placeholders::error,
                     ba::placeholders::bytes_transferred));
}

// Write data read from the connect socket to the client socket.
void SocksClient::do_remote_socket_read()
{
    if (remote_socket_reading_)
        return;
    remote_socket_reading_ = true;
    remote_socket_.async_read_some
        (ba::null_buffers(),
         boost::bind(&SocksClient::remote_socket_read_handler,
                     shared_from_this(), ba::placeholders::error,
                     ba::placeholders::bytes_transferred));
}

void SocksClient::do_sdToRemote_read()
{
    if (pToRemote_reading_)
        return;
    pToRemote_reading_ = true;
    sdToRemote_.async_read_some
        (ba::null_buffers(),
         boost::bind(&SocksClient::sdToRemote_read_handler,
                     shared_from_this(), ba::placeholders::error,
                     ba::placeholders::bytes_transferred));
}

void SocksClient::do_sdToClient_read()
{
    if (pToClient_reading_)
        return;
    pToClient_reading_ = true;
    sdToClient_.async_read_some
        (ba::null_buffers(),
         boost::bind(&SocksClient::sdToClient_read_handler,
                     shared_from_this(), ba::placeholders::error,
                     ba::placeholders::bytes_transferred));
}

// Can throw std::runtime_error
static size_t spliceit(int infd, int outfd, std::size_t len)
{
    std::cerr << "Splicing " << infd << "->" << outfd << " len=" << len << "\n";
    auto spliced = splice(infd, NULL, outfd, NULL, len,
                          SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
    if (spliced < 0) {
        spliced = 0;
        switch (errno) {
        case EAGAIN:
        case EINTR: break;
        case EBADF: throw std::runtime_error("splice EBADF"); break;
        case EINVAL: throw std::runtime_error("splice EINVAL"); break;
        case ENOMEM: throw std::runtime_error("splice ENOMEM"); break;
        case ESPIPE: throw std::runtime_error("splice ESPIPE"); break;
        default: throw std::runtime_error(strerror(errno)); break;
        }
    }
    return spliced;
}

// Client is trying to send data to the remote server.  Splice it to the
// pToRemote_ pipe.
void SocksClient::
client_socket_read_handler(const boost::system::error_code &ec,
                           std::size_t bytes_xferred)
{
    client_socket_reading_ = false;
    if (ec) {
        close_client_socket();
        conditional_terminate();
        return;
    }
    auto bytes = client_socket_.available();
    if (!bytes) {
        close_client_socket();
        conditional_terminate();
        /* do_sdToRemote_read(); */
        return;
    }
    try {
        std::cerr << "client->crPIPE: ";
        pToRemote_len_ += spliceit(client_socket_.native(), pToRemote_[1], bytes);
    } catch (const std::runtime_error &e) {
        std::cerr << "client_socket_read_handler() TERMINATE: " << e.what() << "\n";
        close_client_socket();
        conditional_terminate();
        return;
    }
    splicePipeToRemote();
    do_client_socket_connect_read();
    if (pToRemote_len_) {
        std::cerr << "Polling sdToRemote for reads.\n";
        do_sdToRemote_read();
    }
}

// Remote server is trying to send data to the client.  Splice it to the
// pToClient_ pipe.
void SocksClient::
remote_socket_read_handler(const boost::system::error_code &ec,
                           std::size_t bytes_xferred)
{
    remote_socket_reading_ = false;
    if (ec) {
        close_remote_socket();
        conditional_terminate();
        return;
    }
    auto bytes = remote_socket_.available();
    if (!bytes) {
        close_remote_socket();
        conditional_terminate();
        /* do_sdToClient_read(); */
        return;
    }
    try {
        std::cerr << "remote->rcPIPE: ";
        pToClient_len_ += spliceit(remote_socket_.native(), pToClient_[1], bytes);
    } catch (const std::runtime_error &e) {
        std::cerr << "remote_socket_read_handler() TERMINATE: "<< e.what() << "\n";
        close_remote_socket();
        conditional_terminate();
        return;
    }
    splicePipeToClient();
    do_remote_socket_read();
    if (pToClient_len_) {
        std::cerr << "Polling sdToClient for reads.\n";
        do_sdToClient_read();
    }
}

void SocksClient::splicePipeToClient()
{
    if (!client_socket_.is_open()) {
        pToClient_len_ = 0;
        return;
    }
    try {
        std::cerr << "rcPIPE->client: ";
        pToClient_len_ -= spliceit(pToClient_[0], client_socket_.native(),
                                 pToClient_len_);
    } catch (const std::runtime_error &e) {
        std::cerr << "sdToClient_read_handler() TERMINATE: "<< e.what() << "\n";
        terminate();
        return;
    }
}

void SocksClient::splicePipeToRemote()
{
    if (!remote_socket_.is_open()) {
        pToRemote_len_ = 0;
        return;
    }
    try {
        std::cerr << "crPIPE->remote: ";
        pToRemote_len_ -= spliceit(pToRemote_[0], remote_socket_.native(),
                                 pToRemote_len_);
    } catch (const std::runtime_error &e) {
        std::cerr << "sdToRemote_read_handler() TERMINATE: "<< e.what() << "\n";
        terminate();
        return;
    }
}

// The pToRemote_ pipe has data.  Splice it to remote_socket_.
void SocksClient::sdToRemote_read_handler(const boost::system::error_code &ec,
                                        std::size_t bytes_xferred)
{
    pToRemote_reading_ = false;
    if (ec) {
        std::cerr << "crPIPE error: " << boost::system::system_error(ec).what()
                  << "\n";
        terminate();
        return;
    }
    splicePipeToRemote();
    if (markedForDeath_ && pToRemote_len_ == 0) {
        conditional_terminate();
        return;
    }
    if (pToRemote_len_ > 0)
        do_sdToRemote_read();
    else if (markedForDeath_)
        conditional_terminate();
}

// The pToClient_ pipe has data.  Splice it to client_socket_.
void SocksClient::sdToClient_read_handler(const boost::system::error_code &ec,
                                        std::size_t bytes_xferred)
{
    pToClient_reading_ = false;
    if (ec) {
        std::cerr << "rcPIPE error: " << boost::system::system_error(ec).what()
                  << "\n";
        terminate();
        return;
    }
    splicePipeToClient();
    if (pToClient_len_ > 0)
        do_sdToClient_read();
    else if (markedForDeath_)
        conditional_terminate();
}
#else
// Write data read from the client socket to the connect socket.
void SocksClient::do_client_socket_connect_read()
{
    //std::cout << "do_client_socket_connect_read: start\n";
    ba::streambuf::mutable_buffers_type ibm
        = client_buf_.prepare(buffer_chunk_size);
    client_socket_.async_read_some
        (ba::buffer(ibm),
         boost::bind(&SocksClient::client_socket_read_handler,
                     shared_from_this(), ba::placeholders::error,
                     ba::placeholders::bytes_transferred));
}

// Write data read from the connect socket to the client socket.
void SocksClient::do_remote_socket_read()
{
    //std::cout << "do_remote_socket_read: start\n";
    ba::streambuf::mutable_buffers_type ibm
        = remote_buf_.prepare(buffer_chunk_size);
    remote_socket_.async_read_some
        (ba::buffer(ibm),
         boost::bind(&SocksClient::remote_socket_read_handler,
                     shared_from_this(), ba::placeholders::error,
                     ba::placeholders::bytes_transferred));
}

// Client is trying to send data to the remote server.  Write it to the
// remote_socket_.
void SocksClient::client_socket_read_handler(const boost::system::error_code &ec,
                                          std::size_t bytes_xferred)
{
    if (ec) {
        terminate();
        return;
    }
    client_buf_.commit(bytes_xferred);
    std::cout << "client->remote writing: '" << bytes_xferred << "'\n";
    ba::async_write(remote_socket_,
                    client_buf_,
                    boost::bind(&SocksClient::handle_client_write,
                                shared_from_this(),
                                ba::placeholders::error,
                                ba::placeholders::bytes_transferred));
}

void SocksClient::handle_client_write(const boost::system::error_code &ec,
                                      std::size_t bytes_xferred)
{
    //std::cout << "handle_client_write: start\n";
    if (ec) {
        terminate();
        return;
    }
    client_buf_.consume(bytes_xferred);
    do_client_socket_connect_read();
}

// Remote server is trying to send data to the client.  Write it to the
// client_socket_.
void SocksClient::
remote_socket_read_handler(const boost::system::error_code &ec,
                                std::size_t bytes_xferred)
{
    if (ec) {
        terminate();
        return;
    }
    //std::cout << "remote_socket_read_handler: start\n";
    remote_buf_.commit(bytes_xferred);
    std::cout << "remote->client writing: '" << bytes_xferred << "'\n";
    ba::async_write(client_socket_,
                    remote_buf_,
                    boost::bind(&SocksClient::handle_remote_write,
                                shared_from_this(),
                                ba::placeholders::error,
                                ba::placeholders::bytes_transferred));
}

void SocksClient::handle_remote_write(const boost::system::error_code &ec,
                                      std::size_t bytes_xferred)
{
    //std::cout << "handle_remote_write: start\n";
    if (ec) {
        terminate();
        return;
    }
    remote_buf_.consume(bytes_xferred);
    do_remote_socket_read();
}
#endif

bool SocksClient::dispatch_tcp_bind()
{
    send_reply(RplCmdNotSupp);
    return false;
}

bool SocksClient::dispatch_udp()
{
    send_reply(RplCmdNotSupp);
    return false;
}

void SocksClient::send_reply(ReplyCode replycode)
{
    outbuf_.clear();
    outbuf_.append(1, 0x05);
    outbuf_.append(1, replycode);
    outbuf_.append(1, 0x00);
    if (replycode == RplSuccess) {
        auto bnd_addr = remote_socket_.local_endpoint().address();
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
        portu.p = htons(remote_socket_.local_endpoint().port());
        outbuf_.append(1, portu.b[0]);
        outbuf_.append(1, portu.b[1]);
    }
    sentReplyType_ = replycode;
    std::cout << "send_reply: calling async_write()\n";
    ba::async_write(client_socket_, ba::buffer(outbuf_, outbuf_.size()),
                    boost::bind(&SocksClient::handle_reply_write,
                                shared_from_this(),
                                ba::placeholders::error,
                                ba::placeholders::bytes_transferred));
    std::cout << "send_reply: called async_write()\n";
}

void SocksClient::handle_reply_write(const boost::system::error_code &ec,
                                     std::size_t bytes_xferred)
{
    std::cout << "handle_reply_write: start\n";
    if (ec || sentReplyType_ != RplSuccess) {
        terminate();
        return;
    }
    do_client_socket_connect_read();
    do_remote_socket_read();
    std::cout << "handle_reply_write: end\n";
}

ClientListener::ClientListener(const ba::ip::tcp::endpoint &endpoint)
        : acceptor_(io_service), endpoint_(endpoint)
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
    auto conn = std::make_shared<SocksClient>(acceptor_.get_io_service());
    conntracker_hs->store(conn);
    acceptor_.async_accept(conn->client_socket(), endpoint_,
                           boost::bind(&ClientListener::accept_handler,
                                       this, conn,
                                       ba::placeholders::error));
}

void ClientListener::accept_handler(std::shared_ptr<SocksClient> conn,
                                    const boost::system::error_code &ec)
{
    if (ec)
        return;
    conn->start_client_socket();
    start_accept();
}

