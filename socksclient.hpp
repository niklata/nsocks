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
#include <netdb.h>

#include <boost/asio.hpp>
#include <boost/utility.hpp>

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
    bool matches_dst(const boost::asio::ip::address &addr,
                     uint16_t port) const;
    inline boost::asio::ip::tcp::endpoint remote_socket_local_endpoint() const
    {
        return remote_socket_.local_endpoint();
    }

private:
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

    struct UDPAssoc {
        UDPAssoc(boost::asio::io_service &io_service,
                 boost::asio::ip::udp::endpoint client_ep,
                 boost::asio::ip::udp::endpoint remote_ep,
                 boost::asio::ip::udp::endpoint client_remote_ep)
          : client_endpoint_(client_ep), remote_endpoint_(remote_ep),
            client_remote_endpoint_(client_remote_ep),
            client_socket_(io_service, client_ep),
            remote_socket_(io_service, remote_ep)
        {}
        boost::asio::ip::udp::endpoint client_endpoint_;
        boost::asio::ip::udp::endpoint remote_endpoint_;
        boost::asio::ip::udp::endpoint client_remote_endpoint_;
        boost::asio::ip::udp::endpoint csender_endpoint_;
        boost::asio::ip::udp::endpoint rsender_endpoint_;
        boost::asio::ip::udp::socket client_socket_;
        boost::asio::ip::udp::socket remote_socket_;
        std::vector<uint8_t> inbuf_;
        std::vector<uint8_t> outbuf_;
        std::string out_header_;
        std::vector<boost::asio::const_buffer> out_bufs_;
    };

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
    SocksClientState state_;
    SocksClientType client_type_;
    CommandCode cmd_code_;
    AddressType addr_type_;
    ReplyCode sentReplyType_;
    uint16_t dst_port_;
    uint16_t ibSiz_;

#ifdef USE_SPLICE
    // Used for splice().
    size_t pToRemote_len_;
    size_t pToClient_len_;
    boost::asio::posix::stream_descriptor sdToRemote_;
    boost::asio::posix::stream_descriptor sdToClient_;
    boost::asio::posix::stream_descriptor pToRemote_;
    boost::asio::posix::stream_descriptor pToClient_;
    bool pToRemote_reading_;
    bool pToClient_reading_;
    bool init_splice_pipes();
    void terminate_client();
    void terminate_remote();
    void do_sdToRemote_read();
    void do_sdToClient_read();
    void spliceClientToPipe(std::size_t bytes);
    void spliceRemoteToPipe(std::size_t bytes);
    void splicePipeToClient();
    void splicePipeToRemote();
#else
    boost::asio::streambuf client_buf_;
    boost::asio::streambuf remote_buf_;
    inline bool init_splice_pipes() { return true; }
#endif

    bool writePending_;
    bool auth_none_;
    bool auth_gssapi_;
    bool auth_unpw_;
    bool client_socket_reading_;
    bool remote_socket_reading_;

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

    void send_reply(ReplyCode replycode);
    void send_reply_binds(boost::asio::ip::tcp::endpoint ep);
    void write_reply();
    bool create_reply();
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

#endif /* NK_SOCKSCLIENT_H */

