#pragma once

#include <map>
#include <string>

#include <config.hpp>
#include <fstream>
#include <util.hpp>
#include <vector>
#include <watch.hpp>

enum class AccessType
{
    Read,
    Write,
    Execute,
    Attribute,
    Create,
    Delete
};

struct Record
{
    std::map<std::string, std::string> params;
    long timestamp;
    long sequenceNumber;

    static Result<Record> parse(std::string data);
};

class Event
{
    std::string keyPath;
    std::string basePath;
    std::vector<std::pair<std::string, std::string>> additionalPaths;
    AccessType accessType;
    long timestamp;
    std::string uid, pid;

    Result<std::string> resolvePath(const std::string& path) const;
    Result<AccessType> resolveAction(const std::string& action) const;

public:
    // return value: true if the sequence is finished, false if more messages
    // are expected
    bool receiveRecord(int type, const Record& record);

    Result<std::vector<std::pair<std::string, AccessType>>> calculateActions()
        const;

    const std::string& getUid() const;
    const std::string& getPid() const;
    long getTimestamp() const;

    bool shouldProcess() const;
};

class EventHandler
{
    std::vector<DirectoryWatch> watches;
    std::map<long, Event> pendingEvents;
    std::ofstream outputFile;
    int auditFd;

    EventHandler(int auditFd);

    Result<> watchDirectory(const std::string& path);

    Result<> printLog(long timestamp,
                      const std::string& path,
                      AccessType access,
                      const std::string& pid,
                      const std::string& uid);

    size_t directoryIndex(const PathParts& path);

    Result<> processEvent(const Event& event);

public:
    static Result<std::shared_ptr<EventHandler>> create(int auditFd,
                                                        const Config& config);

    Result<> nextRecord();
};
