#pragma once
#include <optional>
#include <string>
#include <variant>


template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;
/**
 * @brief Represents a command to add a new credential.
 */
struct AddCommand {
    std::string service;
    std::string login;
};
/**
 * @brief Retrieves a credential (optionally for a specific login).
 */
struct GetCommand {
    std::string service;
    std::optional<std::string> login = std::nullopt;
};
/**
 * @brief Copies a credential to clipboard (optionally for a specific login).
 */
struct CopyCommand {
    std::string service;
    std::optional<std::string> login = std::nullopt;
};
/**
 * @brief Updates an existing credential.
 */
struct UpdateCommand {
    std::string service;
    std::string login;
};
/**
 * @brief Deletes a credential for a specific service and login.
 */
struct DeleteCommand {
    std::string service;
    std::string login;
};
/**
 * @brief Lists all stored credentials.
 */
struct ListCommand {};
/**
 * @brief Displays help information.
 */
struct HelpCommand {};
/**
 * @brief Terminates the application.
 */
struct ExitCommand {};
/**
 * @brief A variant type holding any possible user command.
 */
using Command = std::variant<
    AddCommand,
    GetCommand,
    CopyCommand,
    UpdateCommand,
    DeleteCommand,
    ListCommand,
    HelpCommand,
    ExitCommand
>;

