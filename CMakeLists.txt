CMAKE_MINIMUM_REQUIRED(VERSION 3.1)
PROJECT(dirwatch)

SET(CMAKE_CXX_STANDARD 17)

SET(CONFIG_DIR /etc/config)
SET(INSTALL_DIR /usr/local/bin)
SET(SYSTEMD_DIR /lib/systemd/system)

SET(SOURCES
    src/main.cpp
    src/config.cpp
    src/config.hpp
    src/event.cpp
    src/event.hpp
    src/util.cpp
    src/util.hpp
    src/watch.cpp
    src/watch.hpp)

add_compile_definitions(CONFIG_FILE_PATH="${CONFIG_DIR}/dirwatch.json")
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/json)

ADD_EXECUTABLE(dirwatch ${SOURCES})
target_link_libraries(dirwatch audit)

install(TARGETS dirwatch RUNTIME
    DESTINATION ${INSTALL_DIR})
install(FILES misc/dirwatch.json
    DESTINATION ${CONFIG_DIR})
install(FILES misc/dirwatch.service
    DESTINATION ${SYSTEMD_DIR})

ADD_CUSTOM_TARGET(format
    COMMAND clang-format -style=file -i ${SOURCES} ${TEST_SOURCES}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
