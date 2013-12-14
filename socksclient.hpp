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

class SocksClient
    : public std::enable_shared_from_this<SocksClient>
{
public:
    enum SocksClientState {
        STATE_WAITGREET,
        STATE_WAITCONNRQ,
        STATE_GOTCONNRQ,
        STATE_DONE // XXX
    };

    SocksClient(boost::asio::io_service &io_service);
    ~SocksClient();

    void start() { do_read(); }
    boost::asio::ip::tcp::socket &socket() { return client_socket_; }

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

    SocksClientState state_;
    boost::asio::ip::tcp::socket client_socket_;
    boost::asio::ip::tcp::socket remote_socket_;
    boost::asio::ip::tcp::resolver tcp_resolver_;
    boost::array<char, 4096> inBytes_;
    std::string inbuf_;
    bool writePending_;
    bool auth_none_;
    bool auth_gssapi_;
    bool auth_unpw_;
    CommandCode cmd_code_;
    AddressType addr_type_;
    std::string dst_hostname_;
    boost::asio::ip::address local_address_; // XXX: Populate this.
    boost::asio::ip::address dst_address_;
    uint16_t dst_port_;

    std::string outbuf_;
    ReplyCode sentReplyType_;

#ifdef USE_SPLICE
    // Used for splice().
    // XXX: These need to be closed on class destruction.
    int pToConn_[2];
    int pToSock_[2];
    bool pToConn_init_;
    bool pToSock_init_;
    boost::asio::posix::stream_descriptor sdToConn_;
    boost::asio::posix::stream_descriptor sdToSock_;
    void do_sdToConn_read();
    void do_sdToSock_read();
    void sdToConn_read_handler(const boost::system::error_code &ec,
                               std::size_t bytes_xferred);
    void sdToSock_read_handler(const boost::system::error_code &ec,
                               std::size_t bytes_xferred);
#else
    boost::asio::streambuf client_buf_;
    boost::asio::streambuf remote_buf_;
    void handle_client_write(const boost::system::error_code &ec,
                             std::size_t bytes_xferred);
    void handle_remote_write(const boost::system::error_code &ec,
                             std::size_t bytes_xferred);
#endif

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

    bool dispatch_tcp_connect();
    void start_tcp_connect_accept();

    void tcp_connect_handler(const boost::system::error_code &ec);
    void do_client_socket_connect_read();
    void do_remote_socket_read();
    void client_socket_read_handler(const boost::system::error_code &ec,
                                 std::size_t bytes_xferred);
    void remote_socket_read_handler(const boost::system::error_code &ec,
                                         std::size_t bytes_xferred);

    bool dispatch_tcp_bind();
    bool dispatch_udp();
    void send_reply(ReplyCode replycode);
    void handle_reply_write(const boost::system::error_code &ec,
                            std::size_t bytes_xferred);
    bool create_reply();
    void write();
    void terminate();

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

extern unsigned int max_client_bytes;

#endif /* NK_SOCKSCLIENT_H */
