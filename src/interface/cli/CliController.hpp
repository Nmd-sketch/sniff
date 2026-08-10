#pragma once
#include <string>
#include <vector>

namespace application { class ISearchService; }

class CliController {
public:
    explicit CliController(application::ISearchService& service);

    int run(const std::vector<std::string>& args) const;

private:
    application::ISearchService& m_service;
};