#include <watch.hpp>

#include <filesystem>
#include <iostream>
#include <libaudit.h>
#include <string.h>

namespace {

audit_rule_data* newAuditRuleData()
{
    auto rule =
        reinterpret_cast<audit_rule_data*>(malloc(sizeof(audit_rule_data)));
    memset(rule, 0, sizeof(audit_rule_data));
    return rule;
}

}

Watch::Watch(int fd, bool isDir)
    : isDir(isDir)
    , auditFd(fd)
{}

Result<> Watch::addRule(const std::string& path,
                        const std::string& id,
                        int permissions)
{
    auto rule = newAuditRuleData();
    ScopeGuard freeRule([&]() { audit_rule_free_data(rule); });

    RETURN_IF_C_ERROR(audit_add_watch_dir(
        this->isDir ? AUDIT_DIR : AUDIT_WATCH, &rule, path.c_str()));
    RETURN_IF_C_ERROR(audit_rule_syscallbyname_data(rule, "all"));
    RETURN_IF_C_ERROR(audit_update_watch_perms(rule, permissions));

    std::string key = "key=" + id;
    RETURN_IF_C_ERROR(
        audit_rule_fieldpair_data(&rule, key.c_str(), AUDIT_FILTER_UNSET));
    RETURN_IF_C_ERROR(audit_add_rule_data(
        this->auditFd, rule, AUDIT_FILTER_EXIT, AUDIT_ALWAYS));

    this->rules.push_back(rule);
    freeRule.disable();

    return NO_ERROR;
}

Watch::Watch(Watch&& other)
    : rules(std::move(other.rules))
    , isDir(other.isDir)
    , auditFd(other.auditFd)
{
    other.rules.clear();
}

Watch::~Watch()
{
    for (const auto& rule : this->rules) {
        if (audit_delete_rule_data(
                this->auditFd, rule, AUDIT_FILTER_EXIT, AUDIT_ALWAYS) < 0) {
            LOG << __FILE__ << ":" << __LINE__ << ": " << strerror(errno)
                << std::endl;
        }
        audit_rule_free_data(rule);
    }
}

Result<Watch> Watch::create(int auditFd,
                            const std::string& path,
                            bool isDirectory)
{
    Watch watch(auditFd, isDirectory);
    watch.isDir = isDirectory;
    RETURN_IF_ERROR(watch.addRule(path, "w" + path, AUDIT_PERM_WRITE));
    if (!isDirectory) {
        RETURN_IF_ERROR(watch.addRule(path, "r" + path, AUDIT_PERM_READ));
        RETURN_IF_ERROR(watch.addRule(path, "x" + path, AUDIT_PERM_EXEC));
        RETURN_IF_ERROR(watch.addRule(path, "a" + path, AUDIT_PERM_ATTR));
    }
    return std::move(watch);
}

DirectoryWatch::DirectoryWatch(std::string path, int auditFd)
    : path(std::move(path))
    , pathParts(this->path)
    , auditFd(auditFd)
{}

Result<DirectoryWatch> DirectoryWatch::create(int auditFd,
                                              const std::string& path)
{
    DirectoryWatch res(path, auditFd);
    RETURN_OR_SET(auto w, Watch::create(auditFd, path, true /*isDirectory*/));
    res.watch = std::make_shared<Watch>(std::move(w));

    for (const auto& entry : std::filesystem::directory_iterator(path)) {
        if (entry.is_regular_file()) {
            RETURN_OR_SET(
                auto w,
                Watch::create(auditFd, entry.path(), false /*isDirectory*/));
            res.files.emplace(entry.path().filename(), std::move(w));
        } else if (entry.is_directory()) {
            RETURN_OR_SET(auto w,
                          DirectoryWatch::create(auditFd, entry.path()));
            res.dirs.emplace(entry.path().filename(), std::move(w));
        }
    }

    return std::move(res);
}

bool DirectoryWatch::contains(const PathParts& path) const
{
    return !path.tryRemoveRoot(this->pathParts).isError();
}

Result<PathParts> DirectoryWatch::getRelPath(const PathParts& path) const
{
    return path.tryRemoveRoot(this->pathParts);
}

Result<> DirectoryWatch::watchPath(const PathParts& relPath)
{
    if (relPath.getParts().empty()) {
        return ERROR("empty relpath");
    }

    if (relPath.getParts().size() == 1) {
        auto name = relPath.getParts().back();
        if (this->files.count(name) > 0 || this->dirs.count(name) > 0) {
            return NO_ERROR;
        }

        auto fullPath = this->path + "/" + relPath.getParts().back();
        auto type = std::filesystem::status(fullPath).type();
        if (type == std::filesystem::file_type::directory) {
            RETURN_OR_SET(auto w,
                          DirectoryWatch::create(this->auditFd, fullPath));
            this->dirs.emplace(relPath.getParts().back(), std::move(w));
        } else if (type == std::filesystem::file_type::regular) {
            RETURN_OR_SET(
                auto w,
                Watch::create(this->auditFd, fullPath, false /*isDirectory*/));
            this->files.emplace(relPath.getParts().back(), std::move(w));
        } else {
            return ERROR("invalid file type");
        }
        return NO_ERROR;
    }
    auto childIt = this->dirs.find(relPath.getParts().front());
    if (childIt == this->dirs.end()) {
        return ERROR("child not found " + relPath.getParts().front());
    }

    RETURN_IF_ERROR(childIt->second.watchPath(relPath.childPath()));
    return NO_ERROR;
}

Result<> DirectoryWatch::unwatchPath(const PathParts& relPath)
{
    if (relPath.getParts().empty()) {
        return ERROR("empty relpath");
    }

    if (relPath.getParts().size() == 1) {
        auto name = relPath.getParts().back();
        this->files.erase(name);
        this->dirs.erase(name);
        return NO_ERROR;
    }

    auto childIt = this->dirs.find(relPath.getParts().front());
    if (childIt == this->dirs.end()) {
        return ERROR("child not found");
    }

    RETURN_IF_ERROR(childIt->second.unwatchPath(relPath.childPath()));
    return NO_ERROR;
}
