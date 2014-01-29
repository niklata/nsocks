/* socksclient.hpp - socks client request handling
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

#ifndef NK_SOCKSCLIENT_H
#define NK_SOCKSCLIENT_H

#include <string>
#include <memory>
#include <atomic>
#include <netdb.h>

#include <boost/asio.hpp>
#include <boost/utility.hpp>
#include <boost/optional.hpp>

#define SPLICE_SIZE (1024 * 1024)

enum SocksClientType {
    SCT_INIT = 0,
    SCT_CONNECT,
    SCT_BIND,
    SCT_UDP,
};

class SocksClient
    : public std::enable_shared_from_this<SocksClient>, boost::noncopyable
{
public:
    enum SocksClientState {
        STATE_WAITGREET,
        STATE_WAITCONNRQ,
        STATE_GOTCONNRQ,
        STATE_TERMINATED
    };

    SocksClient(boost::asio::io_service &io_service,
                boost::asio::ip::tcp::socket socket);
    ~SocksClient();
    void cancel();
    void terminate();

    inline void start() {
        read_handshake();
    }
    inline void setClientType(SocksClientType ct) {
        client_type_ = ct;
    }
    inline void set_terminated() { state_ = STATE_TERMINATED; }
    bool matches_dst(const boost::asio::ip::address &addr,
                     uint16_t port) const;
    inline boost::asio::ip::tcp::endpoint remote_socket_local_endpoint() const
    {
        return remote_socket_.local_endpoint();
    }

private:
    // Can throw std::runtime_error
    static inline boost::optional<std::size_t> spliceit(int infd, int outfd)
    {
      retry:
        auto spliced = splice(infd, NULL, outfd, NULL, SPLICE_SIZE,
                              SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
        if (spliced <= 0) {
            if (spliced == 0)
                return boost::optional<std::size_t>();
            switch (errno) {
                case EAGAIN: return boost::optional<std::size_t>(0);
                case EINTR: goto retry;
                default: throw std::runtime_error(strerror(errno));
            }
        }
        return spliced;
    }

    enum ParseState {
        ParseInvalid,
        ParseBadPort,
        ParseServerPort,
        ParseClientPort,
        ParseDone
    };

    enum CommandCode {
        CmdTCPConnect,
        CmdTCPBind,
        CmdUDP
    };

    enum AddressType {
        AddrIPv4,
        AddrIPv6,
        AddrDNS
    };

    enum ReplyCode {
        RplSuccess = 0,
        RplFail    = 1,
        RplDeny    = 2,
        RplNetUnreach = 3,
        RplHostUnreach = 4,
        RplConnRefused = 5,
        RplTTLExpired = 6,
        RplCmdNotSupp = 7,
        RplAddrNotSupp = 8
    };

    struct BoundSocket {
        BoundSocket(boost::asio::io_service &io_service,
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
        boost::asio::ip::tcp::acceptor acceptor_;
        boost::asio::ip::tcp::endpoint local_endpoint_;
    };

    struct UDPFrags {
        UDPFrags(boost::asio::io_service &io_service)
                : timer_(io_service), lastn_(0) {}
        boost::asio::deadline_timer timer_;
        std::vector<uint8_t> buf_;
        boost::asio::ip::address addr_;
        std::string dns_;
        uint16_t port_;
        uint8_t lastn_;

        void reset() {
            boost::system::error_code ec;
            timer_.cancel(ec);
            buf_.clear();
            dns_.clear();
            addr_ = boost::asio::ip::address();
            port_ = 0;
            lastn_ = 0;
        }
        void reaper_start() {
            timer_.expires_from_now(boost::posix_time::seconds(5));
            timer_.async_wait(
                [this](const boost::system::error_code& error)
                {
                    if (error)
                        return;
                    reset();
                });
        }
    };

    struct UDPAssoc {
        UDPAssoc(boost::asio::io_service &io_service,
                 boost::asio::ip::udp::endpoint client_ep,
                 boost::asio::ip::udp::endpoint remote_ep,
                 boost::asio::ip::udp::endpoint client_remote_ep)
          : client_endpoint_(client_ep), remote_endpoint_(remote_ep),
            client_remote_endpoint_(client_remote_ep),
            client_socket_(io_service, client_ep),
            remote_socket_(io_service, remote_ep),
            resolver_(io_service)
        {}
        boost::asio::ip::udp::endpoint client_endpoint_;
        boost::asio::ip::udp::endpoint remote_endpoint_;
        boost::asio::ip::udp::endpoint client_remote_endpoint_;
        boost::asio::ip::udp::endpoint csender_endpoint_;
        boost::asio::ip::udp::endpoint rsender_endpoint_;
        boost::asio::ip::udp::socket client_socket_;
        boost::asio::ip::udp::socket remote_socket_;
        boost::asio::ip::udp::resolver resolver_;
        boost::asio::ip::address daddr_;
        std::vector<uint8_t> inbuf_;
        std::vector<uint8_t> outbuf_;
        std::string out_header_;
        std::vector<boost::asio::const_buffer> out_bufs_;
        std::size_t poffset_;
        std::size_t psize_;
        uint16_t dport_;
        std::unique_ptr<UDPFrags> frags_;
    };

    boost::asio::strand strand_;
    boost::asio::strand strandR_;

    // Maximum packet size for handshakes is 262
    std::array<char, 272> inBytes_;
    std::string dst_hostname_;
    std::string outbuf_;
    std::unique_ptr<BoundSocket> bound_;
    std::unique_ptr<UDPAssoc> udp_;
    boost::asio::ip::address dst_address_;
    boost::asio::ip::tcp::socket client_socket_;
    boost::asio::ip::tcp::socket remote_socket_;
    boost::asio::ip::tcp::resolver tcp_resolver_;
    std::atomic<SocksClientState> state_;
    SocksClientType client_type_;
    CommandCode cmd_code_;
    AddressType addr_type_;
    ReplyCode sentReplyType_;
    uint16_t dst_port_;
    uint16_t ibSiz_;

#ifdef USE_SPLICE
    // Used for splice().
    std::atomic<std::size_t> pToRemote_len_;
    boost::asio::deadline_timer rPipeTimer_;
    std::atomic<bool> rPipeTimerSet_;
    std::atomic<std::size_t> pToClient_len_;
    boost::asio::deadline_timer cPipeTimer_;
    std::atomic<bool> cPipeTimerSet_;
    boost::asio::posix::stream_descriptor sdToRemote_;
    boost::asio::posix::stream_descriptor sdToClient_;
    boost::asio::posix::stream_descriptor pToRemote_;
    boost::asio::posix::stream_descriptor pToClient_;
    bool init_splice_pipes();
    void terminate_client();
    void terminate_remote();
    void flushPipeToRemote();
    void flushPipeToClient();
    void kickClientPipeTimer();
    void kickRemotePipeTimer();
    inline bool spliceClientToPipe()
    {
        auto n = spliceit(client_socket_.native_handle(),
                          pToRemote_.native_handle());
        if (!n) return false;
        pToRemote_len_ += *n;
        return true;
    }

    inline bool spliceRemoteToPipe()
    {
        auto n = spliceit(remote_socket_.native_handle(),
                          pToClient_.native_handle());
        if (!n) return false;
        pToClient_len_ += *n;
        return true;
    }

    inline bool splicePipeToClient()
    {
        try {
            auto n = spliceit(sdToClient_.native_handle(),
                              client_socket_.native_handle());
            if (!n) return false;
            pToClient_len_ -= *n;
        } catch (...) {return false; }
        return true;
    }

    inline bool splicePipeToRemote()
    {
        try {
            auto n = spliceit(sdToRemote_.native_handle(),
                              remote_socket_.native_handle());
            if (!n) return false;
            pToRemote_len_ -= *n;
        } catch (...) {return false; }
        return true;
    }
#else
    boost::asio::streambuf client_buf_;
    boost::asio::streambuf remote_buf_;
    inline bool init_splice_pipes() { return true; }
#endif

    bool auth_none_;
    bool auth_gssapi_;
    bool auth_unpw_;

    inline void set_remote_socket_options()
    {
        remote_socket_.non_blocking(true);
        remote_socket_.set_option(boost::asio::socket_base::keep_alive(true));
    }
    void read_handshake();
    bool process_greet();
    ReplyCode process_connrq();
    void dispatch_connrq();

    void dispatch_tcp_connect();
    void start_tcp_connect_accept();

    bool is_dst_denied(const boost::asio::ip::address &addr) const;

    void do_client_socket_connect_read();
    void do_remote_socket_read();

    bool is_bind_client_allowed() const;
    void dispatch_tcp_bind();
    bool create_bind_socket(boost::asio::ip::tcp::endpoint ep);

    bool is_udp_client_allowed(boost::asio::ip::address laddr) const;
    void dispatch_udp();
    void udp_tcp_socket_read();
    void udp_client_socket_read();
    void udp_remote_socket_read();
    bool udp_frags_different(uint8_t fragn, uint8_t atyp,
                             const std::string &dnsname);
    bool udp_frag_handle(uint8_t fragn, uint8_t atyp,
                         const std::string &dnsname);
    void udp_proxy_packet();
    void udp_dns_lookup(const std::string &dnsname);

    void send_reply(ReplyCode replycode);
    void send_reply_binds(boost::asio::ip::tcp::endpoint ep);
    void untrack();
    void close_client_socket();
    void close_remote_socket();
    void close_bind_listen_socket();
    void close_udp_sockets();

    ReplyCode errorToReplyCode(const boost::system::error_code &ec);

    ParseState parse_request();
};

class ClientListener : boost::noncopyable
{
public:
    ClientListener(const boost::asio::ip::tcp::endpoint &endpoint);
    const boost::asio::ip::tcp::acceptor &socket() const { return acceptor_; }
private:
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ip::tcp::endpoint endpoint_;
    boost::asio::ip::tcp::socket socket_;

    void start_accept();
};

void set_buffer_chunk_size(std::size_t size);
void set_listen_queuelen(std::size_t len);

extern void init_conntrackers(std::size_t hs_secs, std::size_t bindlisten_secs);
extern void init_bind_port_assigner(uint16_t lowport, uint16_t highport);
extern void init_udp_associate_assigner(uint16_t lowport, uint16_t highport);
extern bool g_prefer_ipv4;
extern bool g_disable_ipv6;
extern bool g_disable_bind;
extern bool g_disable_udp;

extern std::vector<std::pair<boost::asio::ip::address, unsigned int>>
g_dst_deny_masks;
extern std::vector<std::pair<boost::asio::ip::address, unsigned int>>
g_client_bind_allow_masks;
extern std::vector<std::pair<boost::asio::ip::address, unsigned int>>
g_client_udp_allow_masks;

#undef SPLICE_SIZE

#endif /* NK_SOCKSCLIENT_H */

