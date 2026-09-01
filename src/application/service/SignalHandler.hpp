#pragma once
#include <atomic>

#include "../../domain/model/CancellationToken.hpp"

namespace application {

namespace signal_handler_detail {
/* Single active registration at a time (a CLI has exactly one controller);
   overwritten by the platform implementation. */
extern std::atomic<domain::CancellationToken*> s_active_token;
}

class SignalHandler {
public:
    explicit SignalHandler(domain::CancellationToken& token);
    ~SignalHandler();

    SignalHandler(const SignalHandler&) = delete;
    SignalHandler& operator=(const SignalHandler&) = delete;
};

}  // namespace application
