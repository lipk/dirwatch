#include <event.hpp>

#include <iostream>
#include <libaudit.h>
#include <sstream>
#include <string.h>

namespace {
Result<std::pair<AccessType, std::string>> getAccessTypeAndPath(
    std::string auditKey)
{
    if (auditKey.size() < 2) {
        return ERROR("invalid key");
    }
    AccessType acc;
    switch (auditKey[0]) {
        case 'r':
            acc = AccessType::Read;
            break;
        case 'w':
            acc = AccessType::Write;
            break;
        case 'x':
            acc = AccessType::Execute;
            break;
        case 'a':
            acc = AccessType::Attribute;
            break;
        default:
            return ERROR("invalid key");
    }

    auditKey.erase(0, 1);

    return std::make_pair(acc, std::move(auditKey));
}

std::string accessTypeString(AccessType acc)
{
    switch (acc) {
        case AccessType::Read:
            return "read";
        case AccessType::Write:
            return "write";
        case AccessType::Execute:
            return "exec";
        case AccessType::Attribute:
            return "attr";
        case AccessType::Create:
            return "create";
        case AccessType::Delete:
            return "delete";
    }
    // we shouldn't reach this line
    return "weird";
}
}

Result<Record> Record::parse(std::string data)
{
    Record rec;

    std::stringstream str(std::move(data));
    char buf[20];
    long trash;

    auto expect = [&](const std::string& what) -> Result<> {
        str.read(buf, what.size());
        if (str.gcount() != what.size() ||
            strncmp(buf, what.c_str(), what.size())) {
            return ERROR("parse error, missing " + what);
        }
        return NO_ERROR;
    };

    auto readUntil = [&](char end, bool allowEscape) -> std::string {
        std::string result;
        bool escaping = false;
        for (char next = str.get(); !str.eof(); next = str.get()) {
            if (allowEscape && escaping) {
                result.push_back(next);
                continue;
            }
            if (next == end) {
                break;
            }
            result.push_back(next);
            escaping = next == '\\';
        }
        return result;
    };

    // TODO: better whitespace skipping

    // starts with "audit(timestamp.decimal:serial): "
    expect("audit(");
    str >> rec.timestamp;
    expect(".");
    str >> trash;
    expect(":");
    str >> rec.sequenceNumber;
    expect("): ");

    // params are in key=value format, possibly key='value with spaces'
    while (!str.eof()) {
        auto key = readUntil('=', false /*allowEscape*/);
        if (str.eof()) {
            if (key.empty()) {
                break;
            }
            return ERROR("parse error");
        }
        if (key.empty()) {
            return ERROR("missing key");
        }
        if (rec.params.count(key) > 0) {
            return ERROR("duplicate key");
        }

        char c = str.get();
        if (str.eof()) {
            return ERROR("parse error");
        }
        std::string value;
        if (c == '\'' || c == '"') {
            value = readUntil(c, true /*allowEscape*/);
            if (str.eof()) {
                return ERROR("parse error");
            }
            auto c2 = str.get();
            if (!str.eof() && c2 != ' ') {
                return ERROR("parse error");
            }
        } else {
            value.push_back(c);
            value += readUntil(' ', false /*allowEscape*/);
            // no eof check, it's ok to run out here
        }

        rec.params.emplace(std::move(key), std::move(value));
    }

    return std::move(rec);
}

bool Event::receiveRecord(int type, const Record& record)
{
    if (type == AUDIT_SYSCALL) {
        auto keyIt = record.params.find("key");
        if (keyIt == record.params.end()) {
            return true;
        }
        auto res = getAccessTypeAndPath(keyIt->second);
        if (res.isError()) {
            return true;
        }
        auto accPath = std::get<1>(res);
        this->keyPath = accPath.second;
        this->accessType = accPath.first;
        this->timestamp = record.timestamp;

        auto uidIt = record.params.find("uid");
        auto pidIt = record.params.find("pid");

        if (uidIt == record.params.end() || pidIt == record.params.end()) {
            return true;
        }

        this->uid = uidIt->second;
        this->pid = pidIt->second;
    } else if (type == AUDIT_PATH) {
        auto nameIt = record.params.find("name");
        if (nameIt == record.params.end()) {
            return false;
        }
        auto nameTypeIt = record.params.find("nametype");
        if (nameTypeIt == record.params.end()) {
            return false;
        }
        if (nameTypeIt->second != "PARENT") {
            this->additionalPaths.emplace_back(nameTypeIt->second,
                                               nameIt->second);
        }
    } else if (type == AUDIT_CWD) {
        auto cwdIt = record.params.find("cwd");
        if (cwdIt == record.params.end()) {
            return false;
        }
        this->basePath = cwdIt->second;
    } else if (type == AUDIT_EOE) {
        return true;
    }
    return false;
}

Result<std::string> Event::resolvePath(const std::string& path) const
{
    if (path.empty()) {
        return ERROR("empty path");
    }
    if (path[0] == '/') {
        return path;
    }
    if (this->basePath.empty()) {
        return ERROR("missing parent path");
    }
    return this->basePath + "/" + path;
}

Result<AccessType> Event::resolveAction(const std::string& action) const
{
    if (action == "NORMAL") {
        return this->accessType;
    } else if (action == "CREATE") {
        return AccessType::Create;
    } else if (action == "DELETE") {
        return AccessType::Delete;
    }
    return ERROR("unrecognized action");
}

Result<std::vector<std::pair<std::string, AccessType>>>
Event::calculateActions() const
{
    std::vector<std::pair<std::string, AccessType>> result;
    for (const auto& [a, p] : this->additionalPaths) {
        RETURN_OR_SET(auto fp, this->resolvePath(p));
        RETURN_OR_SET(auto act, this->resolveAction(a));
        result.emplace_back(std::move(fp), act);
    }
    return std::move(result);
}

const std::string& Event::getUid() const
{
    return this->uid;
}

const std::string& Event::getPid() const
{
    return this->pid;
}

long Event::getTimestamp() const
{
    return this->timestamp;
}

EventHandler::EventHandler(int auditFd)
    : auditFd(auditFd)
{}

Result<> EventHandler::watchDirectory(const std::string& path)
{
    RETURN_OR_SET(auto watch, DirectoryWatch::create(this->auditFd, path));
    this->watches.emplace_back(std::move(watch));

    return NO_ERROR;
}

Result<> EventHandler::printLog(long timestamp,
                                const std::string& path,
                                AccessType access,
                                const std::string& pid,
                                const std::string& uid)
{
    this->outputFile << timestamp << "\t" << path << "\t" << accessTypeString(access)
         << "\t" << pid << "\t" << uid << std::endl;
    return NO_ERROR;
}

size_t EventHandler::directoryIndex(const PathParts& path)
{
    for (size_t i = 0; i < this->watches.size(); ++i) {
        if (this->watches[i].contains(path)) {
            return i;
        }
    }

    return this->watches.size();
}

Result<> EventHandler::processEvent(const Event& event)
{
    RETURN_OR_SET(auto actions, event.calculateActions());

    for (const auto& [path, action] : actions) {
        PathParts fsPath(path);
        auto idx = this->directoryIndex(fsPath);
        if (idx == this->watches.size()) {
            continue;
        }
        RETURN_OR_SET(auto relPath, this->watches[idx].getRelPath(fsPath));
        if (action == AccessType::Create) {
            RETURN_IF_ERROR(this->watches[idx].watchPath(relPath));
        } else if (action == AccessType::Delete) {
            RETURN_IF_ERROR(this->watches[idx].unwatchPath(relPath));
        }
        auto normPath = fsPath.toString(true /*absolute*/);
        RETURN_IF_ERROR(this->printLog(event.getTimestamp(),
                                       normPath,
                                       action,
                                       event.getPid(),
                                       event.getUid()));
    }

    return NO_ERROR;
}

Result<std::shared_ptr<EventHandler>> EventHandler::create(int auditFd,
                                                           const Config& config)
{
    auto eventHandler =
        std::shared_ptr<EventHandler>(new EventHandler(auditFd));
    eventHandler->outputFile.open(config.outputPath, std::ios_base::app);
    if (!eventHandler->outputFile.is_open()) {
        return ERROR("can't open output file");
    }

    for (const auto& path : config.paths) {
        RETURN_IF_ERROR(eventHandler->watchDirectory(path));
    }

    return std::move(eventHandler);
}

Result<> EventHandler::nextRecord()
{
    audit_reply reply;

    RETURN_IF_C_ERROR(
        audit_get_reply(this->auditFd, &reply, GET_REPLY_BLOCKING, 0));

    // audit_get_reply seems to return garbage sometimes, try to filter it out
    if (reply.type < 1000 || reply.type > 1807) {
        return NO_ERROR;
    }

    std::string msgData(reply.message, reply.len);
    RETURN_OR_SET(auto msg, Record::parse(msgData));

    auto ev = this->pendingEvents.find(msg.sequenceNumber);
    if (ev == this->pendingEvents.end() && reply.type == AUDIT_SYSCALL) {
        ev = this->pendingEvents.emplace(msg.sequenceNumber, Event()).first;
    }
    if (ev != this->pendingEvents.end() &&
        ev->second.receiveRecord(reply.type, msg)) {
        auto res = this->processEvent(this->pendingEvents[msg.sequenceNumber]);
        if (res.isError()) {
            LOG << std::get<0>(res).message << std::endl;
        }
        this->pendingEvents.erase(msg.sequenceNumber);
    }

    return NO_ERROR;
}
