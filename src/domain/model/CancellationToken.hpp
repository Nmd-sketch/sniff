#pragma once
#include <atomic>

namespace domain {

class CancellationToken {
public:
    void requestStop() noexcept {
        m_stopped.store(true, std::memory_order_relaxed);
    }

    bool isStopped() const noexcept {
        return m_stopped.load(std::memory_order_relaxed);
    }

private:
    std::atomic<bool> m_stopped{false};
};

}  // namespace domain