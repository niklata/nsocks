/* socks_tracker.hpp - socks tracker templates
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

#ifndef NJK_SOCKS_TRACKER_HPP_
#define NJK_SOCKS_TRACKER_HPP_

template <typename T>
class ephTrackerVec : boost::noncopyable
{
public:
    ephTrackerVec(boost::asio::io_service &iosrv, std::size_t cyclefreq)
        : cyclefreq_(cyclefreq), hidx_(0), swapTimer_(iosrv) {}
    ~ephTrackerVec()
    {
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
        }
        x->start();
        if (swapTimer_.expires_from_now() <=
            boost::posix_time::time_duration(0,0,0,0))
            setTimer(false);
    }
    std::size_t size() { return vec_[0].size() + vec_[1].size(); }
private:
    inline void vec_cancel(std::size_t x) {
        for (auto &i: vec_[x]) {
            auto j = i.lock();
            if (j && !j->is_bind_listen())
                j->cancel();
        }
    }
    void doSwap() {
        std::size_t hnext = hidx_ ^ 1;
        vec_cancel(hnext);
        vec_[hnext].clear();
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
                                  //print_trackers_logentry("[DOSWAP-]", hidx_);
                                  if (lock_.try_lock()) {
                                      doSwap();
                                      auto sz = size();
                                      lock_.unlock();
                                      //print_trackers_logentry("[DOSWAP+]", hidx_);
                                      if (sz)
                                          setTimer(false);
                                  } else
                                      setTimer(true);
                              });
    }
    std::mutex lock_;
    const std::size_t cyclefreq_;
    std::atomic<std::size_t> hidx_;
    boost::asio::deadline_timer swapTimer_;
    std::vector<std::weak_ptr<T>> vec_[2];
};

template <typename T>
class ephTrackerList : boost::noncopyable
{
public:
    ephTrackerList(boost::asio::io_service &iosrv, std::size_t cyclefreq)
        : cyclefreq_(cyclefreq), hidx_(0), swapTimer_(iosrv) {}
    ~ephTrackerList()
    {
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
            setTimer(false);
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
            setTimer(false);
    }
    std::size_t size() { return list_[0].size() + list_[1].size(); }
private:
    inline void list_cancel(std::size_t x) {
        auto end = list_[x].end();
        typename std::list<std::weak_ptr<T>>::iterator ip;
        for (auto i = list_[x].begin(); i != end;) {
            auto j = i->lock();
            if (j) {
                j->set_untracked();
                j->cancel();
            }
            ip = i++;
            list_[x].erase(ip);
        }
    }
    void doSwap() {
        std::size_t hnext = hidx_ ^ 1;
        list_cancel(hnext);
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
    boost::asio::deadline_timer swapTimer_;
    std::list<std::weak_ptr<T>> list_[2];
};

template <typename T>
class connTracker : boost::noncopyable
{
public:
    connTracker() {}
    ~connTracker()
    {
        for (auto &i: list_) {
            auto j = i.lock();
            if (!j)
                continue;
            j->cancel();
            j->set_terminated();
        }
    }
    void erase(typename std::list<std::weak_ptr<T>>::iterator it) {
        std::lock_guard<std::mutex> wl(lock_);
        list_.erase(it);
    }
    template <typename... Args>
    void emplace(Args&&... args)
    {
        auto x = std::make_shared<T>(std::forward<Args>(args)...);
        {
            std::lock_guard<std::mutex> wl(lock_);
            list_.emplace_front(x);
            x->set_tracker_iterator(list_.begin());
        }
        x->start();
    }
    boost::optional<std::shared_ptr<T>>
    find_by_addr_port(boost::asio::ip::address addr, uint16_t port)
    {
        std::lock_guard<std::mutex> wl(lock_);
        for (auto &i: list_) {
            auto j = i.lock();
            if (!j)
                continue;
            if (j->matches_dst(addr, port))
                return j;
        }
        return boost::optional<std::shared_ptr<T>>();
    }
    std::size_t size() const { return list_.size(); }

    std::mutex lock_;
    std::list<std::weak_ptr<T>> list_;
};

#endif
