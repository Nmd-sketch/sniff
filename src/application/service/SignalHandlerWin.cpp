#include "SignalHandler.hpp"

#include <windows.h>

namespace {

BOOL WINAPI onConsoleCtrl(DWORD) {
    if (application::signal_handler_detail::s_active_token != nullptr) {
        application::signal_handler_detail::s_active_token->requestStop();
    }
    return TRUE;
}

}  // namespace

namespace application {
namespace signal_handler_detail {

domain::CancellationToken* s_active_token = nullptr;

}  // namespace signal_handler_detail
}  // namespace application

application::SignalHandler::SignalHandler(domain::CancellationToken& token) {
    signal_handler_detail::s_active_token = &token;
    SetConsoleCtrlHandler(onConsoleCtrl, TRUE);
}

application::SignalHandler::~SignalHandler() {
    SetConsoleCtrlHandler(onConsoleCtrl, FALSE);
    signal_handler_detail::s_active_token = nullptr;
}