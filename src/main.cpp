#include <memory>
#include <string>
#include <vector>

#include "application/service/SearchService.hpp"
#include "infrastructure/scanner/Win32Scanner.hpp"
#include "interface/cli/CliController.hpp"

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);

    infrastructure::Win32Scanner scanner;
    application::SearchService service(scanner);
    CliController controller(service);

    return controller.run(args);
}