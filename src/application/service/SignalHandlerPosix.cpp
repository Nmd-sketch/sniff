#include "SignalHandler.hpp"

#include <csignal>

namespace {

void onInterrupt(int) {
    if (auto* token = application::signal_handler_detail::s_active_token.load();
        token != nullptr) {
        token->requestStop();
    }
}

}  // namespace

namespace application {
namespace signal_handler_detail {

std::atomic<domain::CancellationToken*> s_active_token = nullptr;

}  // namespace signal_handler_detail
}  // namespace application

application::SignalHandler::SignalHandler(domain::CancellationToken& token) {
    signal_handler_detail::s_active_token = &token;

    struct sigaction action {};
    action.sa_handler = onInterrupt;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    sigaction(SIGINT, &action, nullptr);
}

application::SignalHandler::~SignalHandler() {
    struct sigaction default_action {};
    default_action.sa_handler = SIG_DFL;
    sigemptyset(&default_action.sa_mask);
    sigaction(SIGINT, &default_action, nullptr);

    signal_handler_detail::s_active_token = nullptr;
}
