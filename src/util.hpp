#pragma once

#include <functional>
#include <string>
#include <variant>

// Macro-helper macros
#define TOSTRING(x) TOSTRING2(x)
#define TOSTRING2(x) #x

#define CONCAT_(x, y) x##y
#define CONCAT(x, y) CONCAT_(x, y)

#define UNIQUE_IDENTIFIER CONCAT(veryUniqueIdentifier, __COUNTER__)

// Error handling related stuff
struct NoError
{};

#define NO_ERROR NoError()

struct Error
{
    std::string message;
    Error(std::string message);
};

#define ERROR(msg)                                                             \
    Error(std::string(__FILE__ ":" TOSTRING(__LINE__) "  ") + std::string(msg))

template<class ValueT = NoError>
struct Result : public std::variant<Error, ValueT>
{
    Result(ValueT val)
        : std::variant<Error, ValueT>(std::move(val))
    {}

    Result(Error err)
        : std::variant<Error, ValueT>(std::move(err))
    {}

    bool isError() const
    {
        return this->index() == 0 || this->index() == std::variant_npos;
    }
};

#define RETURN_IF_ERROR(expr)                                                  \
    if (auto _res = (expr); _res.isError())                                    \
    return ERROR(std::get<0>(_res).message)

#define RETURN_IF_C_ERROR(expr)                                                \
    if (expr < 0)                                                              \
    return ERROR(strerror(errno))

#define RETURN_OR_SET(var, expr)                                               \
    RETURN_OR_SET_IMPL(var, expr, UNIQUE_IDENTIFIER)

#define RETURN_OR_SET_IMPL(var, expr, tmp)                                     \
    auto tmp = (expr);                                                         \
    if (tmp.isError())                                                         \
        return ERROR(std::get<0>(tmp).message);                                \
    var = std::move(std::get<1>(tmp))

#define RETURN_OR_SET_C(var, expr)                                             \
    RETURN_OR_SET_C_IMPL(var, expr, UNIQUE_IDENTIFIER)

#define RETURN_OR_SET_C_IMPL(var, expr, tmp)                                   \
    auto tmp = (expr);                                                         \
    if (tmp < 0)                                                               \
        return ERROR(strerror(errno));                                         \
    var = tmp;

#define LOG std::cerr << "[dirwatch] "

// ScopeGuard
struct ScopeGuard
{
    bool active;
    std::function<void()> func;

    void disable();

    ScopeGuard(std::function<void()> func);
    ~ScopeGuard();
};

// PathParts
class PathParts
{
    std::vector<std::string> parts;

public:
    PathParts(const std::string& path);
    PathParts(std::vector<std::string> parts);

    Result<PathParts> tryRemoveRoot(const PathParts& root) const;
    PathParts childPath() const;

    const std::vector<std::string>& getParts() const;
    std::string toString(bool absolute) const;
};