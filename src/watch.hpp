#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <libaudit.h>

#include <util.hpp>

class Watch
{
    std::vector<audit_rule_data*> rules;
    bool isDir;
    int auditFd;

    Watch(int auditFd, bool isDir);

    Result<> addRule(const std::string& path,
                     const std::string& id,
                     int permissions);

public:
    Watch(const Watch&) = delete;
    Watch& operator=(const Watch&) = delete;
    Watch& operator=(Watch&&) = delete;

    Watch(Watch&& other);

    ~Watch();

    static Result<Watch> create(int auditFd,
                                const std::string& path,
                                bool isDirectory);

    bool isDirectory() const { return this->isDir; }
};

class DirectoryWatch
{
    std::shared_ptr<Watch> watch;
    std::map<std::string, Watch> files;
    std::map<std::string, DirectoryWatch> dirs;
    std::string path;
    PathParts pathParts;
    int auditFd;

    DirectoryWatch(std::string path, int auditFd);

public:
    static Result<DirectoryWatch> create(int auditFd, const std::string& path);

    bool contains(const PathParts& path) const;

    Result<PathParts> getRelPath(const PathParts& path) const;

    Result<> watchPath(const PathParts& relPath);

    Result<> unwatchPath(const PathParts& relPath);
};