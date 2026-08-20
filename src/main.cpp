#include <memory>
#include <string>
#include <vector>
#ifdef _WIN32 
    #include <windows.h>
#endif
#include "application/service/SearchService.hpp"
#include "infrastructure/scanner/Win32Scanner.hpp"
#include "interface/cli/CliController.hpp"

static std::string WideToUTF8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();

    int size = WideCharToMultiByte(
        CP_UTF8,
        0,
        wstr.c_str(),
        (int)wstr.length(),
        nullptr,
        0,
        nullptr,
        nullptr
    );

    if (size <= 0) return std::string();

    std::string res(size, 0);
    WideCharToMultiByte(
        CP_UTF8,
        0,
        wstr.c_str(),
        (int)wstr.length(),
        &res[0],
        size,
        nullptr,
        nullptr
    );

    return res;
}

static std::vector<std::string> parse_cmd() {
    int arg_num = 0;
    std::vector<std::string> results;
LPWSTR* l = CommandLineToArgvW(GetCommandLineW(), &arg_num);
    for (int i = 1; i < arg_num; ++i) {
        results.push_back(WideToUTF8(l[i]));
    }
    LocalFree(l);
    return results;
}


int main() {
    std::vector<std::string> args = parse_cmd();

    infrastructure::Win32Scanner scanner;
    application::SearchService service(scanner);
    CliController controller(service);

    return controller.run(args);
}
