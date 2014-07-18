/* bind_port_assigner.hpp - allocates and tracks ports from a range
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

#ifndef NJK_BIND_PORT_ASSIGNER_HPP_
#define NJK_BIND_PORT_ASSIGNER_HPP_

class BindPortAssigner : boost::noncopyable
{
public:
    BindPortAssigner(uint16_t start, uint16_t end)
            : ports_used_(end - start + 1), random_portrange_(start, end),
              start_port_(start), end_port_(end)
    {
        assert(start <= end);
    }
    uint16_t get_port()
    {
        std::lock_guard<std::mutex> wl(lock_);
        auto rp = random_portrange_(g_random_prng);
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
    std::uniform_int_distribution<uint16_t> random_portrange_;
    uint16_t start_port_;
    uint16_t end_port_;
};

#endif
