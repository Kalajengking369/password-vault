#include <iostream>
#include <variant>
#include "command/CommandParser.h"
#include "manager/PasswordManager.h"
#include "manager/MasterPasswordManager.h"
#include "utils/Getpass.h"

int main() {
    if (sodium_init() < 0) {
        std::cout << "Sodium init failed" << std::endl;
        return 1;
    }

    const std::string masterPassword = "masterPassword.hash";
    const std::string dbFile = "passwords.db";

    MasterPasswordManager masterPasswordManager(masterPassword);
    if (!masterPasswordManager.authenticate()) {
        std::cout << "Failed to authenticate." << std::endl;
        return 1;
    }

    const PasswordManager manager(dbFile, masterPasswordManager.getEncryptionKey());
    std::string line;
    bool running = true;

    std::cout << "You are logged in." << std::endl;
    std::cout << "Type 'help' to see the list of commands." << std::endl;

    while (running) {
        std::cout << "> ";
        if (!std::getline(std::cin, line)) {
            break;
        }
        if (line.empty() || line.find_first_not_of(" \t\r\n") == std::string::npos) {
            continue;
        }

        auto command = parseCommand(line);
        if (!command.has_value()) {
            std::cout << "Unknown command. Type 'help' for available commands." << std::endl;
            continue;
        }

        std::visit(overloaded {
            [&](const AddCommand& c) {
                const SecureBuffer password(128);
                std::cout << "Password: ";
                getpass(password.get(), password.size());
                manager.add(c.service, c.login, password);
            },
            [&](const GetCommand& c) { manager.get(c.service, c.login); },
            [&](const CopyCommand& c) { manager.copy(c.service, c.login); },
            [&](const UpdateCommand& c) {
                const SecureBuffer password(128);
                std::cout << "Password: ";
                getpass(password.get(), password.size());
                manager.update(c.service, c.login, password);
            },
            [&](const DeleteCommand& c) { manager.remove(c.service, c.login); },
            [&](const ListCommand&) { manager.list(); },
            [&](const HelpCommand&) { manager.help(); },
            [&](const ExitCommand&) { running = false; },
        }, *command);
    }

    return 0;
}
