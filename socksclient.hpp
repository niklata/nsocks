/* socksclient.hpp - socks client request handling
 *
 * (c) 2013-2017 Nicholas J. Kain <njkain at gmail dot com>
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

#include <asio.hpp>
#include <boost/optional.hpp>
#include <fmt/format.h>

#include "nadns/dns.hpp"

extern std::unique_ptr<nk::net::adns_resolver> g_adns;

#ifdef USE_SPLICE
extern void pipe_close_raw(std::size_t p_len, asio::posix::stream_descriptor &sa,
                           asio::posix::stream_descriptor &sb);
#endif

class SocksInit : public std::enable_shared_from_this<SocksInit>
{
public:
    SocksInit(asio::io_service &io_service, asio::ip::tcp::socket socket);
    SocksInit(const SocksInit &) = delete;
    SocksInit& operator=(const SocksInit &) = delete;
    ~SocksInit();
    void terminate();
    void cancel_sockets();
    inline void set_untracked() { tracked_ = false; }
    inline void start() { read_greet(); }
    inline bool is_bind_listen() const { return !!bound_; }
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
        Parsed4G_Userid,

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
        BoundSocket(asio::io_service &io_service, asio::ip::tcp::endpoint lep);
        ~BoundSocket();
        asio::ip::tcp::acceptor acceptor_;
        asio::ip::tcp::endpoint local_endpoint_;
        std::list<std::weak_ptr<SocksInit>>::iterator tracker_iterator_;
        unsigned char tracker_idx_;
    };

    inline std::error_code set_remote_socket_options()
    {
        std::error_code ec;
        remote_socket_.non_blocking(true, ec);
        if (ec) return ec;
        remote_socket_.set_option(asio::ip::tcp::no_delay(true), ec);
        if (ec) return ec;
        remote_socket_.set_option(asio::socket_base::keep_alive(true), ec);
        if (ec) return ec;
#ifdef TCP_QUICKACK
        const asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_QUICKACK> quickack(true);
        remote_socket_.set_option(quickack, ec);
        if (ec) return ec;
#endif
        return ec;
    }

    static void dnslookup_cb(void *self_, int status, int timeouts, struct hostent *host);

    void read_greet();
    boost::optional<ReplyCode> parse_greet(std::size_t &consumed);
    enum class DNSType { None, V4, V6, Any };
    void raw_dns_lookup(int af);
    void dispatch_connrq();

    void dispatch_tcp_connect();

    bool is_bind_client_allowed() const;
    void dispatch_tcp_bind();
    bool create_bind_socket(asio::ip::tcp::endpoint ep);

    bool is_udp_client_allowed(asio::ip::address laddr) const;
    void dispatch_udp();

    void do_send_reply(ReplyCode replycode, std::size_t ssiz);
    void send_reply(ReplyCode replycode);
    ReplyCode errorToReplyCode(const std::error_code &ec);

    std::array<char, 24> sockbuf_;
    std::atomic<bool> tracked_;
    std::unique_ptr<BoundSocket> bound_;
    std::shared_ptr<SocksInit> selfref_; // Use for keeping alive during adns queries.
    std::vector<asio::ip::tcp::endpoint> dst_eps_;
    std::string dst_hostname_; // Shared
    asio::ip::address dst_address_; // Shared
    asio::io_service::strand strand_;
    asio::ip::tcp::socket client_socket_; // Shared
    asio::ip::tcp::socket remote_socket_; // Shared
    uint16_t dst_port_; // Shared
    uint8_t pstate_;
    uint8_t ibSiz_;
    uint8_t poff_;
    uint8_t ptmp_;
    uint8_t cmd_code_:4;
    uint8_t addr_type_:4;
    bool is_socks_v4_:1;
    bool socks_v4_dns_:1;
    bool bind_listen_:1;
    bool auth_none_:1;
    bool auth_gssapi_:1;
    bool auth_unpw_:1;
    bool dnsq_v6_:1;
    bool dnsq_v4_:1;
};

class SocksTCP : public std::enable_shared_from_this<SocksTCP>
{
public:
    SocksTCP(asio::io_service &io_service, asio::ip::tcp::socket client_socket,
             asio::ip::tcp::socket remote_socket, asio::ip::address dst_address,
             uint16_t dst_port, bool is_bind, bool is_socks_v4, std::string dst_hostname = "");
    SocksTCP(const SocksTCP &) = delete;
    SocksTCP& operator=(const SocksTCP &) = delete;
    ~SocksTCP();
    void start(asio::ip::tcp::endpoint ep);
    void terminate() {}

    inline void set_untracked() { tracked_ = false; }
    void set_tracker_iterator(std::list<std::weak_ptr<SocksTCP>>::iterator it) {
        tracker_iterator_ = it;
    }
    inline std::list<std::weak_ptr<SocksTCP>>::iterator
    get_tracker_iterator() const {
        return tracker_iterator_;
    }
    bool matches_dst(const asio::ip::address &addr, uint16_t port) const;
    inline asio::ip::tcp::endpoint remote_socket_local_endpoint(std::error_code &ec) const
    {
        return remote_socket_.local_endpoint(ec);
    }

    static void set_send_buffer_chunk_size(std::size_t size);
    static void set_receive_buffer_chunk_size(std::size_t size);
    static void set_splice_pipe_size(int size);

private:
    enum class FlushDirection { Both, Client, Remote };

    std::atomic<bool> tracked_;
    std::list<std::weak_ptr<SocksTCP>>::iterator tracker_iterator_;
    asio::streambuf client_buf_;
    asio::streambuf remote_buf_;

    // Shared with SocksInit
    std::string dst_hostname_;
    asio::ip::address dst_address_;
    asio::io_service::strand strand_;
    asio::ip::tcp::socket client_socket_;
    asio::ip::tcp::socket remote_socket_;
    uint16_t dst_port_;
    bool is_socks_v4_:1;
    bool is_bind_:1;

#ifdef USE_SPLICE
    bool flush_invoked_:1;
    std::size_t pToRemote_len_;
    std::size_t pToClient_len_;
    std::chrono::high_resolution_clock::time_point client_read_ts_;
    std::chrono::high_resolution_clock::time_point remote_read_ts_;
    asio::posix::stream_descriptor pToRemoteR_;
    asio::posix::stream_descriptor pToClientR_;
    asio::posix::stream_descriptor pToRemoteW_;
    asio::posix::stream_descriptor pToClientW_;
    void flush_then_terminate(FlushDirection dir);
    bool init_pipe(asio::posix::stream_descriptor &preader,
                   asio::posix::stream_descriptor &pwriter);
    void tcp_client_socket_write_splice(int tries);
    void tcp_remote_socket_write_splice(int tries);
    void tcp_client_socket_read_splice();
    void tcp_remote_socket_read_splice();
    void doFlushPipeToRemote(int tries);
    void doFlushPipeToClient(int tries);
private:

    enum class splicePipeRet { ok = 0, would_block = -1, interrupt = -2, eof = -3, error = -4 };

    inline splicePipeRet spliceRemoteToPipe();
    inline splicePipeRet spliceClientToPipe();
    inline splicePipeRet splicePipeToClient(size_t *xferred = nullptr);
    inline splicePipeRet splicePipeToRemote(size_t *xferred = nullptr);
    inline void tcp_client_socket_read_stopsplice() {
        assert(pToRemote_len_ == 0);
        pipe_close_raw(pToRemote_len_, pToRemoteR_, pToRemoteW_);
        tcp_client_socket_read();
    }
    inline void tcp_remote_socket_read_stopsplice() {
        assert(pToClient_len_ == 0);
        pipe_close_raw(pToClient_len_, pToClientR_, pToClientW_);
        tcp_remote_socket_read();
    }

    inline void tcp_client_socket_read_again
    (const std::shared_ptr<SocksTCP> &sfd,
     size_t bytes_xferred, bool splice_ok);
    inline void tcp_remote_socket_read_again
    (const std::shared_ptr<SocksTCP> &sfd,
     size_t bytes_xferred, bool splice_ok);
#else
    inline void flush_then_terminate(FlushDirection dir) { }
    inline void tcp_remote_socket_read_again
    (const std::shared_ptr<SocksTCP> &sfd,
     size_t bytes_xferred, bool splice_ok)
        { tcp_remote_socket_read(); }
    inline void tcp_client_socket_read_again
    (const std::shared_ptr<SocksTCP> &sfd,
     size_t bytes_xferred, bool splice_ok)
        { tcp_client_socket_read(); }
#endif

    static std::size_t send_buffer_chunk_size;
    static std::size_t receive_buffer_chunk_size;
    static std::size_t send_minsplice_size;
    static std::size_t receive_minsplice_size;
    static int splice_pipe_size;

    void tcp_client_socket_read();
    void tcp_remote_socket_read();

    void close_bind_listen_socket();
};

class SocksUDP : public std::enable_shared_from_this<SocksUDP>
{
public:
    SocksUDP(asio::io_service &io_service, asio::ip::tcp::socket tcp_client_socket,
             asio::ip::udp::endpoint client_ep, asio::ip::udp::endpoint remote_ep,
             asio::ip::udp::endpoint client_remote_ep);
    SocksUDP(const SocksUDP &) = delete;
    SocksUDP& operator=(const SocksUDP &) = delete;
    ~SocksUDP();
    void start();
    void terminate() {}
private:
    struct UDPFrags {
        UDPFrags(asio::io_service &io_service) : timer_(io_service), lastn_(0) {}
        asio::deadline_timer timer_;
        std::vector<uint8_t> buf_;
        asio::ip::address addr_;
        std::string dns_;
        uint16_t port_;
        uint8_t lastn_;

        void reset() {
            std::error_code ec;
            timer_.cancel(ec);
            buf_.clear();
            dns_.clear();
            addr_ = asio::ip::address();
            port_ = 0;
            lastn_ = 0;
        }
        void reaper_start() {
            timer_.expires_from_now(boost::posix_time::seconds(5));
            timer_.async_wait(
                [this](const std::error_code& error)
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
    bool udp_frags_different(uint8_t fragn, uint8_t atyp);
    bool udp_frag_handle(uint8_t fragn, uint8_t atyp);
    void udp_proxy_packet();
    static void dnslookup_cb(void *self_, int status, int timeouts, struct hostent *host);
    void raw_dns_lookup(int af);
    void dns_lookup();
    void close_udp_sockets();

    // Shared with SocksInit
    asio::ip::tcp::socket tcp_client_socket_;

    std::shared_ptr<SocksUDP> selfref_; // Use for keeping alive during adns queries.
    asio::ip::udp::endpoint client_endpoint_;
    asio::ip::udp::endpoint remote_endpoint_;
    asio::ip::udp::endpoint client_remote_endpoint_;
    asio::ip::udp::endpoint csender_endpoint_;
    asio::ip::udp::endpoint rsender_endpoint_;
    asio::io_service::strand strand_;
    asio::ip::udp::socket client_socket_;
    asio::ip::udp::socket remote_socket_;
    asio::ip::address daddr_;
    std::string dnsname_;
    std::vector<uint8_t> inbuf_;
    std::vector<uint8_t> outbuf_;
    std::array<char, 24> out_header_;
    std::vector<asio::const_buffer> out_bufs_;
    std::size_t poffset_;
    std::size_t psize_;
    uint16_t dport_;
    std::unique_ptr<UDPFrags> frags_;
    std::array<char, 16> tcp_inbuf_;
    bool dnsq_v6_:1;
    bool dnsq_v4_:1;
};

class ClientListener
{
public:
    ClientListener(const asio::ip::tcp::endpoint &endpoint);
    ClientListener(const ClientListener &) = delete;
    ClientListener& operator=(const ClientListener &) = delete;
    const asio::ip::tcp::acceptor &socket() const { return acceptor_; }
private:
    asio::ip::tcp::acceptor acceptor_;
    asio::ip::tcp::endpoint endpoint_;
    asio::ip::tcp::socket socket_;

    void start_accept();
};

void set_listen_queuelen(std::size_t len);
void set_max_buffer_ms(unsigned int n);

void init_conntrackers(std::size_t hs_secs, std::size_t bindlisten_secs);
void init_bind_port_assigner(uint16_t lowport, uint16_t highport);
void init_udp_associate_assigner(uint16_t lowport, uint16_t highport);
extern bool g_verbose_logs;
extern bool g_prefer_ipv4;
extern bool g_disable_ipv6;
extern bool g_disable_bind;
extern bool g_disable_udp;

extern std::vector<std::pair<asio::ip::address, unsigned int>> g_dst_deny_masks;
extern std::vector<std::pair<asio::ip::address, unsigned int>> g_client_bind_allow_masks;
extern std::vector<std::pair<asio::ip::address, unsigned int>> g_client_udp_allow_masks;

#endif /* NK_SOCKSCLIENT_H */

