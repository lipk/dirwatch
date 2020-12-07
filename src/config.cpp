#include <config.hpp>
#include <fstream>
#include <nlohmann/json.hpp>

Result<Config> readConfig()
{
    std::ifstream input(CONFIG_FILE_PATH);
    if (!input.is_open()) {
        return ERROR("Can't read config file");
    }
    Config res;
    try {
        auto json = nlohmann::json::parse(input);
        if (!json["outputPath"].is_string()) {
            return ERROR("outputPath missing or nor a string");
        }
        res.outputPath = json["outputPath"].get<std::string>();

        if (!json["dirs"].is_array()) {
            return ERROR("dirs missing or not an array");
        }
        for (const auto& item : json["dirs"]) {
            if (!item.is_object()) {
                return ERROR("array item not an object");
            }
            if (!item["path"].is_string()) {
                return ERROR("path missing or not a string");
            }
            res.paths.insert(item["path"].get<std::string>());
        }
    } catch (const std::invalid_argument& arg) {
        return ERROR(arg.what());
    }
    return std::move(res);
}
