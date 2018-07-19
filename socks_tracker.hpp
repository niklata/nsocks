/* socks_tracker.hpp - socks tracker templates
 *
 * (c) 2013-2015 Nicholas J. Kain <njkain at gmail dot com>
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

#ifndef NJK_SOCKS_TRACKER_HPP_
#define NJK_SOCKS_TRACKER_HPP_

template <typename T>
class ephTrackerVec
{
public:
    ephTrackerVec(asio::io_service &iosrv, std::size_t cyclefreq)
            : cyclefreq_(cyclefreq), hidx_(0),
              swapTimer_(iosrv), timer_set_(false) {}
    ephTrackerVec(const ephTrackerVec &) = delete;
    ephTrackerVec& operator=(const ephTrackerVec &) = delete;
    ~ephTrackerVec()
    {
        std::lock_guard<std::mutex> wl(lock_);
        std::error_code ec;
        swapTimer_.cancel(ec);
        for (std::size_t j = 0; j < 2; ++j)
            vec_cancel(j);
    }
    template <typename... Args>
    void emplace(Args&&... args)
    {
        auto x = std::make_shared<T>(std::forward<Args>(args)...);
        {
            std::lock_guard<std::mutex> wl(lock_);
            vec_[hidx_].emplace_back(x);
            setTimer();
        }
        x->start();
    }
    std::size_t size() {
        std::lock_guard<std::mutex> wl(lock_);
        return vec_[0].size() + vec_[1].size();
    }
private:
    inline void vec_cancel(std::size_t x) {
        for (auto &i: vec_[x]) {
            auto j = i.lock();
            if (j) j->expire_timeout_nobind();
        }
        vec_[x].clear();
    }
    // Must be called holding lock_.
    void setTimer() {
        if (timer_set_) return;
        timer_set_ = true;
        swapTimer_.expires_from_now(boost::posix_time::seconds(cyclefreq_));
        swapTimer_.async_wait([this](const std::error_code& error)
                              {
                                  std::lock_guard<std::mutex> wl(lock_);
                                  timer_set_ = false;
                                  if (error)
                                      return;
                                  const auto hcurrent = hidx_;
                                  const auto hnext = hidx_ ^ 1;
                                  vec_cancel(hnext);
                                  hidx_ = hnext;
                                  if (!vec_[hcurrent].empty())
                                      setTimer();
                              });
    }
    std::mutex lock_;
    const std::size_t cyclefreq_;
    std::size_t hidx_;
    asio::deadline_timer swapTimer_;
    std::vector<std::weak_ptr<T>> vec_[2];
    bool timer_set_;
};

template <typename T>
class ephTrackerList
{
public:
    ephTrackerList(asio::io_service &iosrv, std::size_t cyclefreq)
        : cyclefreq_(cyclefreq), timer_set_(false), hidx_(0),
          swapTimer_(iosrv) {}
    ephTrackerList(const ephTrackerList &) = delete;
    ephTrackerList& operator=(const ephTrackerList &) = delete;
    ~ephTrackerList()
    {
        std::error_code ec;
        swapTimer_.cancel(ec);
        for (std::size_t j = 0; j < 2; ++j)
            list_cancel(j);
    }
    void store(std::shared_ptr<T> &&ssc)
    {
        {
            std::lock_guard<std::mutex> wl(lock_);
            list_[hidx_].emplace_front(ssc);
            ssc->set_tracker_iterator(list_[hidx_].begin(), hidx_);
        }
        if (swapTimer_.expires_from_now() <=
            boost::posix_time::time_duration(0,0,0,0))
            setTimer();
    }
    void erase(typename std::list<std::weak_ptr<T>>::iterator it, std::size_t lidx) {
        std::lock_guard<std::mutex> wl(lock_);
        list_[lidx].erase(it);
    }
    template <typename... Args>
    void emplace(Args&&... args)
    {
        auto x = std::make_shared<T>(std::forward<Args>(args)...);
        {
            std::lock_guard<std::mutex> wl(lock_);
            list_[hidx_].emplace_front(x);
            x->set_tracker_iterator(list_[hidx_].begin(), hidx_);
        }
        x->start();
        if (swapTimer_.expires_from_now() <=
            boost::posix_time::time_duration(0,0,0,0))
            setTimer();
    }
    std::size_t size() {
        std::lock_guard<std::mutex> wl(lock_);
        return list_[0].size() + list_[1].size();
    }
private:
    inline void list_cancel(std::size_t x) {
        auto end = list_[x].end();
        for (auto i = list_[x].begin(); i != end;) {
            auto j = i->lock();
            if (j) j->expire_timeout();
            list_[x].erase(i++);
        }
    }
    bool doSwap() {
        std::size_t hnext = hidx_ ^ 1;
        std::lock_guard<std::mutex> wl(lock_);
        list_cancel(hnext);
        bool is_empty = !!list_[hidx_].size();
        hidx_ = hnext;
        return is_empty;
    }
    void setTimer() {
        bool cxr(false);
        if (!timer_set_.compare_exchange_strong(cxr, true))
            return;
        swapTimer_.expires_from_now
            (boost::posix_time::seconds(cyclefreq_));
        swapTimer_.async_wait([this](const std::error_code& error)
                              {
                                  if (error) {
                                      timer_set_ = false;
                                      return;
                                  }
                                  auto is_empty = doSwap();
                                  timer_set_ = false;
                                  if (!is_empty)
                                      setTimer();
                              });
    }
    std::mutex lock_;
    const std::size_t cyclefreq_;
    std::atomic<bool> timer_set_;
    std::atomic<std::size_t> hidx_;
    asio::deadline_timer swapTimer_;
    std::list<std::weak_ptr<T>> list_[2];
};

template <typename T>
class connTracker
{
public:
    connTracker() {}
    connTracker(const connTracker &) = delete;
    connTracker& operator=(const connTracker &) = delete;
    ~connTracker()
    {
        for (auto &i: list_) {
            auto j = i.lock();
            if (!j)
                continue;
            j->set_untracked();
            j->terminate();
        }
    }
    void erase(typename std::list<std::weak_ptr<T>>::iterator it) {
        std::lock_guard<std::mutex> wl(lock_);
        list_.erase(it);
    }
    template <typename... Args>
    void emplace(asio::ip::tcp::endpoint ep, Args&&... args)
    {
        auto x = std::make_shared<T>(std::forward<Args>(args)...);
        {
            std::lock_guard<std::mutex> wl(lock_);
            list_.emplace_front(x);
            x->set_tracker_iterator(list_.begin());
        }
        x->start(ep);
    }
    std::optional<std::shared_ptr<T>>
    find_by_addr_port(asio::ip::address addr, uint16_t port)
    {
        std::lock_guard<std::mutex> wl(lock_);
        for (auto &i: list_) {
            auto j = i.lock();
            if (!j)
                continue;
            if (j->matches_dst(addr, port))
                return j;
        }
        return {};
    }
    std::size_t size() {
        std::lock_guard<std::mutex> wl(lock_);
        return list_.size();
    }

    std::mutex lock_;
    std::list<std::weak_ptr<T>> list_;
};

#endif
