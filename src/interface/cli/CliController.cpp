#include "CliController.hpp"

#include <iostream>
#include <memory>

#include "../../application/dto/Config.hpp"
#include "../../application/dto/QueryResult.hpp"
#include "../../application/dto/ScanConfig.hpp"
#include "../../application/port/ISearchService.hpp"
#include "../../application/service/SignalHandler.hpp"
#include "../../domain/model/CancellationToken.hpp"
#include "../formatter/Formatter.hpp"
#include "../formatter/JsonFormatter.hpp"
#include "../formatter/TableFormatter.hpp"
#include "../formatter/TreeFormatter.hpp"
#include "CommandParser.hpp"

namespace {

constexpr int EXIT_OK = 0;
constexpr int EXIT_ERROR = 1;
constexpr int EXIT_INTERRUPTED = 130;  // 128 + SIGINT

std::unique_ptr<Formatter> makeFormatter(FormatType type) {
    switch (type) {
        case FormatType::JSON:
            return std::make_unique<JsonFormatter>();
        case FormatType::TREE:
            return std::make_unique<TreeFormatter>();
        case FormatType::TABLE:
            return std::make_unique<TableFormatter>();
    }
    return std::make_unique<TableFormatter>();
}

}  // namespace

CliController::CliController(application::ISearchService& service)
    : m_service(service) {}

int CliController::run(const std::vector<std::string>& args) const {
    CommandParser parser;
    if (!parser.parse(args)) {
        std::cerr << "sniff: " << parser.lastError() << '\n';
        return EXIT_ERROR;
    }

    const auto& commands = parser.getCommands();
    if (commands.empty()) {
        std::cerr << "sniff: no search pattern given\n";
        return EXIT_ERROR;
    }

    application::Config config;
    config.pattern = commands[0];
    config.paths.assign(commands.begin() + 1, commands.end());
    config.specs = parser.getFilterSpecs();

    application::ScanConfig scan;
    scan.paths = config.paths;
    scan.specs = config.specs;

    domain::CancellationToken token;
    application::SignalHandler interrupt(token);

    application::QueryResult result = m_service.search(scan, token);

    if (result.aborted) {
        std::cerr << "sniff: interrupted\n";
        return EXIT_INTERRUPTED;
    }

    std::cout << makeFormatter(parser.getFormatType())->formatEntries(result.entries);
    return EXIT_OK;
}