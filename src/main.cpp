#include <libaudit.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <iostream>

#include <config.hpp>
#include <event.hpp>
#include <util.hpp>

std::shared_ptr<EventHandler> eventHandler;

void sigHandler(int)
{
    eventHandler.reset();
    exit(0);
}

Result<> doStuff()
{
    RETURN_OR_SET(auto config, readConfig());
    RETURN_OR_SET_C(auto fd, audit_open());
    ScopeGuard closeAudit([&]() { audit_close(fd); });

    RETURN_OR_SET(eventHandler, EventHandler::create(fd, config));
    ScopeGuard deleteEH([&]() { eventHandler.reset(); });
    signal(SIGTERM, &sigHandler);
    signal(SIGINT, &sigHandler);

    RETURN_IF_C_ERROR(audit_set_pid(fd, getpid(), WAIT_YES));
    RETURN_IF_C_ERROR(audit_set_enabled(fd, 1));

    while (true) {
        if (auto res = eventHandler->nextRecord(); res.isError()) {
            LOG << std::get<0>(res).message << std::endl;
        }
    }

    return NO_ERROR;
}

int main()
{
    if (auto res = doStuff(); res.isError()) {
        LOG << std::get<0>(res).message << std::endl;
        return 1;
    }
    return 0;
}