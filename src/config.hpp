#pragma once

#include <set>
#include <util.hpp>

struct Config
{
    std::set<std::string> paths;
    std::string outputPath;
};

Result<Config> readConfig();