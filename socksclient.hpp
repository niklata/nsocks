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
#include <list>
#include <netdb.h>

#include <boost/asio.hpp>
#include <boost/utility.hpp>
#include <boost/optional.hpp>

#include "make_unique.hpp"

class SocksInit
    : public std::enable_shared_from_this<SocksInit>, boost::noncopyable
{
public:
    SocksInit(boost::asio::io_service &io_service,
              boost::asio::ip::tcp::socket socket);
    ~SocksInit();
    void terminate();
    void cancel();
    inline void set_untracked() { tracked_ = false; }
    inline void start() { read_greet(); }
    inline bool is_bind_listen() const { return bind_listen_; }
    void set_tracker_iterator(std::list<std::weak_ptr<SocksInit>>::iterator it,
                              unsigned char lidx) {
        assert(bound_);
        bound_->tracker_iterator_ = it;
        bound_->tracker_idx_ = lidx;
    }
    inline std::list<std::weak_ptr<SocksInit>>::iterator
    get_tracker_iterator() const {
        return bound_->tracker_iterator_;
    }
    inline unsigned char get_tracker_idx() const {
        return bound_->tracker_idx_;
    }

    enum ReplyCode {
        RplSuccess = 0,
        RplFail    = 1,
        RplDeny    = 2,
        RplNetUnreach = 3,
        RplHostUnreach = 4,
        RplConnRefused = 5,
        RplTTLExpired = 6,
        RplCmdNotSupp = 7,
        RplAddrNotSupp = 8,
        RplIdentUnreach = 9,
        RplIdentWrong = 10,
    };

private:
    enum ParsedState {
        // greet
        Parsed_None = 0,
        // greet_v5
        Parsed5G_Version,
        Parsed5G_NumAuth,
        Parsed5G_Auth,
        Parsed5G_Replied,
        // process_connrq
        Parsed5CR_Version,
        Parsed5CR_Cmd,
        Parsed5CR_Resv,
        Parsed5CR_AddrType,
        Parsed5CR_DNSLen,
        Parsed5CR_DAddr,

        // greet_v4
        Parsed4G_Version,
        Parsed4G_Cmd,
        Parsed4G_DPort,
        Parsed4G_DAddr,

        Parsed_Finished
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

    struct BoundSocket {
        BoundSocket(boost::asio::io_service &io_service,
                    boost::asio::ip::tcp::endpoint lep);
        ~BoundSocket();
        boost::asio::ip::tcp::acceptor acceptor_;
        boost::asio::ip::tcp::endpoint local_endpoint_;
        std::list<std::weak_ptr<SocksInit>>::iterator tracker_iterator_;
        unsigned char tracker_idx_;
    };

    inline void init_resolver(boost::asio::io_service &io_service) {
        tcp_resolver_ = nk::make_unique<boost::asio::ip::tcp::resolver>
            (io_service);
    }

    inline void set_remote_socket_options()
    {
        remote_socket_.non_blocking(true);
        remote_socket_.set_option(boost::asio::socket_base::keep_alive(true));
    }

    void untrack();
    void read_greet();
    boost::optional<ReplyCode> parse_greet(std::size_t &consumed);
    void dispatch_connrq();

    void dispatch_tcp_connect();

    bool is_bind_client_allowed() const;
    void dispatch_tcp_bind();
    bool create_bind_socket(boost::asio::ip::tcp::endpoint ep);

    bool is_udp_client_allowed(boost::asio::ip::address laddr) const;
    void dispatch_udp();

    void send_reply(ReplyCode replycode);
    ReplyCode errorToReplyCode(const boost::system::error_code &ec);

    std::array<char, 24> sockbuf_;
    std::atomic<bool> tracked_;
    std::unique_ptr<boost::asio::ip::tcp::resolver> tcp_resolver_;
    std::unique_ptr<BoundSocket> bound_;
    std::string dst_hostname_; // Shared
    boost::asio::ip::address dst_address_; // Shared
    boost::asio::ip::tcp::socket client_socket_; // Shared
    boost::asio::ip::tcp::socket remote_socket_; // Shared
    uint16_t ibSiz_;
    uint16_t poff_;
    uint16_t ptmp_;
    uint16_t dst_port_; // Shared
    uint8_t pstate_;
    uint8_t cmd_code_;
    uint8_t addr_type_;
    bool is_socks_v4_:1;
    bool bind_listen_:1;
    bool auth_none_:1;
    bool auth_gssapi_:1;
    bool auth_unpw_:1;
};

class SocksTCP
    : public std::enable_shared_from_this<SocksTCP>, boost::noncopyable
{
public:
    SocksTCP(boost::asio::io_service &io_service,
             boost::asio::ip::tcp::socket client_socket,
             boost::asio::ip::tcp::socket remote_socket,
             boost::asio::ip::address dst_address,
             uint16_t dst_port, bool is_bind, bool is_socks_v4,
             std::string dst_hostname = "");
    ~SocksTCP();
    void start();
    void cancel();
    void terminate();

    inline void set_terminated() { terminated_ = true; }
    void set_tracker_iterator(std::list<std::weak_ptr<SocksTCP>>::iterator it) {
        tracker_iterator_ = it;
    }
    inline std::list<std::weak_ptr<SocksTCP>>::iterator
    get_tracker_iterator() const {
        return tracker_iterator_;
    }
    bool matches_dst(const boost::asio::ip::address &addr,
                     uint16_t port) const;
    inline boost::asio::ip::tcp::endpoint remote_socket_local_endpoint() const
    {
        return remote_socket_.local_endpoint();
    }

    static void set_send_buffer_chunk_size(std::size_t size);
    static void set_receive_buffer_chunk_size(std::size_t size);
    static void set_splice_pipe_size(int size);

private:
    void untrack();

    // Can throw std::runtime_error
    // Return of boost::optional<std::size_t>() implies EOF
    // Return of 0 implies EAGAIN
    //
    // If we get EAGAIN here when writing a pipe, then it means that the
    // pipe is full.
    static inline boost::optional<std::size_t> spliceit(int infd, int outfd)
    {
      retry:
        auto spliced = splice(infd, NULL, outfd, NULL, splice_pipe_size,
                              SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
        if (spliced <= 0) {
            if (spliced == 0)
                return boost::optional<std::size_t>();
            switch (errno) {
                case EAGAIN: return std::size_t(0);
                case EINTR: goto retry;
                default: throw std::runtime_error(strerror(errno));
            }
        }
        return spliced;
    }

    std::atomic<bool> terminated_;
    std::list<std::weak_ptr<SocksTCP>>::iterator tracker_iterator_;
    boost::asio::streambuf client_buf_;
    boost::asio::streambuf remote_buf_;

    // Shared with SocksInit
    std::string dst_hostname_;
    boost::asio::ip::address dst_address_;
    boost::asio::ip::tcp::socket client_socket_;
    boost::asio::ip::tcp::socket remote_socket_;
    uint16_t dst_port_;
    bool is_socks_v4_:1;
    bool is_bind_:1;

#ifdef USE_SPLICE
    bool kicking_client_pipe_bg_;
    bool kicking_remote_pipe_bg_;
    std::atomic<std::size_t> pToRemote_len_;
    std::atomic<std::size_t> pToClient_len_;
    std::chrono::high_resolution_clock::time_point client_read_ts_;
    std::chrono::high_resolution_clock::time_point remote_read_ts_;
    boost::asio::posix::stream_descriptor sdToRemote_;
    boost::asio::posix::stream_descriptor sdToClient_;
    boost::asio::posix::stream_descriptor pToRemote_;
    boost::asio::posix::stream_descriptor pToClient_;
    bool init_pipe_client();
    bool init_pipe_remote();
    void close_pipe_to_client();
    void close_pipe_to_remote();
    void tcp_client_socket_read_splice();
    void tcp_remote_socket_read_splice();
    void doFlushPipeToRemote(bool closing);
    void doFlushPipeToClient(bool closing);
public:
    void terminate_client();
    void terminate_remote();
    inline bool is_remote_splicing() { return pToClient_.is_open(); }
    inline bool is_client_splicing() { return pToRemote_.is_open(); }
    bool kickClientPipe(const std::chrono::high_resolution_clock::time_point &now);
    bool kickRemotePipe(const std::chrono::high_resolution_clock::time_point &now);
private:
    void addToSpliceClientList();
    void addToSpliceRemoteList();
    void kickClientPipeBG();
    void kickRemotePipeBG();

    inline boost::optional<std::size_t> splicePipeToClient()
    {
        try {
            auto n = spliceit(sdToClient_.native_handle(),
                              client_socket_.native_handle());
            if (n) pToClient_len_ -= *n;
            else throw std::runtime_error("EOF");
            return n;
        } catch (const std::runtime_error &e) {
            std::cerr << "splicePipeToClient: TERMINATE/"
                      << e.what() <<"/\n";
            terminate_client();
            return boost::optional<std::size_t>();
        }
    }
    inline boost::optional<std::size_t> splicePipeToRemote()
    {
        try {
            auto n = spliceit(sdToRemote_.native_handle(),
                              remote_socket_.native_handle());
            if (n) pToRemote_len_ -= *n;
            else throw std::runtime_error("EOF");
            return n;
        } catch (const std::runtime_error &e) {
            std::cerr << "splicePipeToRemote: TERMINATE/"
                      << e.what() <<"/\n";
            terminate_remote();
            return boost::optional<std::size_t>();
        }
    }

    inline void flushPipeToRemote(bool closing)
    {
        if (!splicePipeToRemote())
            return;
        doFlushPipeToRemote(closing);
    }

    inline void flushPipeToClient(bool closing)
    {
        if (!splicePipeToClient())
            return;
        doFlushPipeToClient(closing);
    }

    inline void tcp_client_socket_read_again(size_t bytes_xferred,
                                             bool splice_ok)
    {
        // std::cerr << "sbx=" << bytes_xferred << " sms="
        //           << send_minsplice_size << "\n";
        if (splice_ok && bytes_xferred >= send_minsplice_size) {
            if (init_pipe_client()) {
                // std::cerr << "client->remote switched to splice\n";
                addToSpliceRemoteList();
                tcp_client_socket_read_splice();
                return;
            } else
                std::cerr << "init_pipe_client failed\n";
        }
        tcp_client_socket_read();
    }
    inline void tcp_remote_socket_read_again(size_t bytes_xferred,
                                             bool splice_ok)
    {
        // std::cerr << "rbx=" << bytes_xferred << " rms="
        //           << receive_minsplice_size << "\n";
        if (splice_ok && bytes_xferred >= receive_minsplice_size) {
            if (init_pipe_remote()) {
                // std::cerr << "remote->client switched to splice\n";
                addToSpliceClientList();
                tcp_remote_socket_read_splice();
                return;
            } else
                std::cerr << "init_pipe_remote failed\n";
        }
        tcp_remote_socket_read();
    }
#else
    inline void terminate_client() { terminate(); }
    inline void terminate_remote() { terminate(); }
    inline void tcp_remote_socket_read_again(size_t bytes_xferred)
        { tcp_remote_socket_read(); }
    inline void tcp_client_socket_read_again(size_t bytes_xferred)
        { tcp_client_socket_read(); }
#endif

    static std::size_t send_buffer_chunk_size;
    static std::size_t receive_buffer_chunk_size;
    static std::size_t send_minsplice_size;
    static std::size_t receive_minsplice_size;
    static int splice_pipe_size;

    void tcp_client_socket_read();
    void tcp_remote_socket_read();

    bool close_client_socket();
    bool close_remote_socket();
    void close_bind_listen_socket();
};

class SocksUDP
    : public std::enable_shared_from_this<SocksUDP>, boost::noncopyable
{
public:
    SocksUDP(boost::asio::io_service &io_service,
             boost::asio::ip::tcp::socket tcp_client_socket,
             boost::asio::ip::udp::endpoint client_ep,
             boost::asio::ip::udp::endpoint remote_ep,
             boost::asio::ip::udp::endpoint client_remote_ep);
    ~SocksUDP();
    void start();
    void terminate();
    void cancel();
private:
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

    void udp_tcp_socket_read();
    void udp_client_socket_read();
    void udp_remote_socket_read();
    bool udp_frags_different(uint8_t fragn, uint8_t atyp,
                             const std::string &dnsname);
    bool udp_frag_handle(uint8_t fragn, uint8_t atyp,
                         const std::string &dnsname);
    void udp_proxy_packet();
    void udp_dns_lookup(const std::string &dnsname);
    void close_udp_sockets();

    // Shared with SocksInit
    boost::asio::ip::tcp::socket tcp_client_socket_;

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
    std::array<char, 24> out_header_;
    std::vector<boost::asio::const_buffer> out_bufs_;
    std::size_t poffset_;
    std::size_t psize_;
    uint16_t dport_;
    std::unique_ptr<UDPFrags> frags_;
    std::array<char, 16> tcp_inbuf_;
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

void set_listen_queuelen(std::size_t len);
void set_max_buffer_ms(unsigned int n);

extern void init_conntrackers(std::size_t hs_secs, std::size_t bindlisten_secs);
extern void init_bind_port_assigner(uint16_t lowport, uint16_t highport);
extern void init_udp_associate_assigner(uint16_t lowport, uint16_t highport);
extern bool g_verbose_logs;
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

