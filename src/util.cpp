#include <sstream>
#include <util.hpp>

Error::Error(std::string message)
    : message(std::move(message))
{}

void ScopeGuard::disable()
{
    this->active = false;
}

ScopeGuard::ScopeGuard(std::function<void()> func)
    : active(true)
    , func(std::move(func))
{}

ScopeGuard::~ScopeGuard()
{
    if (active) {
        func();
    }
}

PathParts::PathParts(const std::string& path)
{
    if (path.empty()) {
        return;
    }
    size_t pos = 0;
    if (path[0] == '/') {
        pos = 1;
    }
    size_t next = path.find('/', pos);
    while (next != std::string::npos) {
        this->parts.push_back(path.substr(pos, next - pos));
        pos = next + 1;
        next = path.find('/', pos);
    }
    this->parts.push_back(path.substr(pos, next - pos));

    for (size_t i = 1; i < this->parts.size();) {
        if (i > 0 && parts[i] == ".." && parts[i - 1] != "..") {
            this->parts.erase(this->parts.begin() + i - 1,
                              this->parts.begin() + i + 1);
            i--;
        } else if (parts[i] == ".") {
            this->parts.erase(this->parts.begin() + i);
        } else {
            i++;
        }
    }
}

PathParts::PathParts(std::vector<std::string> parts)
    : parts(std::move(parts))
{}

Result<PathParts> PathParts::tryRemoveRoot(const PathParts& root) const
{
    if (root.parts.size() > this->parts.size()) {
        return ERROR("not root");
    }

    for (size_t i = 0; i < root.parts.size(); ++i) {
        if (root.parts[i] != this->parts[i]) {
            return ERROR("not root");
        }
    }
    std::vector<std::string> newParts(this->parts.begin() + root.parts.size(),
                                      this->parts.end());
    return PathParts(std::move(newParts));
}

PathParts PathParts::childPath() const
{
    return PathParts(
        std::vector<std::string>(this->parts.begin() + 1, this->parts.end()));
}

const std::vector<std::string>& PathParts::getParts() const
{
    return this->parts;
}

std::string PathParts::toString(bool absolute) const
{
    std::stringstream result;
    for (size_t i = 0; i < this->parts.size(); ++i) {
        if (i > 0 || absolute) {
            result << '/';
        }
        result << this->parts[i];
    }
    return result.str();
}
