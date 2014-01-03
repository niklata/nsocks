/* socksclient.hpp - socks client request handling
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

#ifndef NK_SOCKSCLIENT_H
#define NK_SOCKSCLIENT_H

#include <string>
#include <memory>
#include <netdb.h>

#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <boost/enable_shared_from_this.hpp>

enum SocksClientType {
    SCT_INIT = 0,
    SCT_CONNECT,
    SCT_BIND,
    SCT_UDP,
};

class SocksClient
    : public std::enable_shared_from_this<SocksClient>
{
public:
    enum SocksClientState {
        STATE_WAITGREET,
        STATE_WAITCONNRQ,
        STATE_GOTCONNRQ,
        STATE_TERMINATED
    };

    SocksClient(boost::asio::io_service &io_service);
    ~SocksClient();

    inline void start_client_socket() {
        client_socket_.non_blocking(true);
        client_socket_.set_option(boost::asio::socket_base::keep_alive(true));
        do_read();
    }
    inline boost::asio::ip::tcp::socket &client_socket() {
        return client_socket_;
    }
    inline void setClientType(SocksClientType ct) {
        client_type_ = ct;
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

    boost::array<char, 32> inBytes_;
    std::string inbuf_;
    std::string dst_hostname_;
    std::string outbuf_;
    std::unique_ptr<BoundSocket> bound_;
    boost::asio::ip::address local_address_; // XXX: Populate this.
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

#ifdef USE_SPLICE
    // Used for splice().
    size_t pToRemote_len_;
    size_t pToClient_len_;
    boost::asio::posix::stream_descriptor sdToRemote_;
    boost::asio::posix::stream_descriptor sdToClient_;
    int pToRemote_[2];
    int pToClient_[2];
    bool pToRemote_init_;
    bool pToClient_init_;
    bool pToRemote_reading_;
    bool pToClient_reading_;
    bool init_splice_pipes();
    void do_sdToRemote_read();
    void do_sdToClient_read();
    void sdToRemote_read_handler(const boost::system::error_code &ec,
                               std::size_t bytes_xferred);
    void sdToClient_read_handler(const boost::system::error_code &ec,
                               std::size_t bytes_xferred);
    void splicePipeToClient();
    void splicePipeToRemote();
#else
    boost::asio::streambuf client_buf_;
    boost::asio::streambuf remote_buf_;
    inline bool init_splice_pipes() { return true; }
    void handle_client_write(const boost::system::error_code &ec,
                             std::size_t bytes_xferred);
    void handle_remote_write(const boost::system::error_code &ec,
                             std::size_t bytes_xferred);
#endif

    bool writePending_;
    bool auth_none_;
    bool auth_gssapi_;
    bool auth_unpw_;
    bool markedForDeath_;
    bool client_socket_reading_;
    bool remote_socket_reading_;

    inline void set_remote_socket_options()
    {
        remote_socket_.non_blocking(true);
        remote_socket_.set_option(boost::asio::socket_base::keep_alive(true));
    }

    void do_read();
    void do_write();
    void read_handler(const boost::system::error_code &ec,
                      std::size_t bytes_xferred);
    void write_handler(const boost::system::error_code &ec,
                       std::size_t bytes_xferred);
    bool process_input();
    bool process_greet();
    bool reply_greet();
    bool process_connrq();
    void resolve_handler(const boost::system::error_code &ec,
                         boost::asio::ip::tcp::resolver::iterator it);
    void dispatch_connrq();

    void dispatch_tcp_connect();
    void start_tcp_connect_accept();

    bool is_dst_denied();

    void tcp_connect_handler(const boost::system::error_code &ec);
    void do_client_socket_connect_read();
    void do_remote_socket_read();
    void client_socket_read_handler(const boost::system::error_code &ec,
                                 std::size_t bytes_xferred);
    void remote_socket_read_handler(const boost::system::error_code &ec,
                                         std::size_t bytes_xferred);

    bool is_bind_client_allowed();
    void dispatch_tcp_bind();
    bool create_bind_socket(boost::asio::ip::tcp::endpoint ep);
    void bind_accept_handler(const boost::system::error_code &ec);
    bool dispatch_udp();
    void send_reply(ReplyCode replycode);
    void send_reply_binds(boost::asio::ip::tcp::endpoint ep);
    void handle_reply_write(const boost::system::error_code &ec,
                            std::size_t bytes_xferred);
    bool create_reply();
    void write();
    void terminate();
    void conditional_terminate();
    void close_client_socket();
    void close_remote_socket();

    ReplyCode errorToReplyCode(const boost::system::error_code &ec);

    ParseState parse_request();
};

class ClientListener
{
public:
    ClientListener(const boost::asio::ip::tcp::endpoint &endpoint);
    const boost::asio::ip::tcp::acceptor &socket() { return acceptor_; }
private:
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ip::tcp::endpoint endpoint_;

    void start_accept();
    void accept_handler(std::shared_ptr<SocksClient> conn,
                        const boost::system::error_code &ec);
};

void set_buffer_chunk_size(std::size_t size);
void set_listen_queuelen(std::size_t len);

extern void init_conntracker_hs();
extern bool g_prefer_ipv4;
extern bool g_disable_ipv6;

extern std::vector<std::pair<boost::asio::ip::address, unsigned int>>
g_dst_deny_masks;
extern std::vector<std::pair<boost::asio::ip::address, unsigned int>>
g_client_bind_allow_masks;

#endif /* NK_SOCKSCLIENT_H */

