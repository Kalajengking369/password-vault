#pragma once
#include <iostream>
#include <array>
#include <optional>
#include <sodium.h>
#include "sqlite_modern_cpp.h"
#include "crypto/DatabaseDecryptGuard.h"
#include <thread>
#include <clip.h>

/**
 * @class PasswordManager
 * @brief Manages secure storage and retrieval of passwords with SQLite and encryption.
 *
 * Provides functions to add, retrieve, update, delete, and encrypt/decrypt passwords,
 * as well as clipboard functionality.
 */
class PasswordManager {
public:
    /**
     * @brief Constructor to initialize the database and encryption key.
     * @param dbFilename Path to the SQLite database file.
     * @param encryptionKey The encryption key for securing password storage.
     */
    PasswordManager(std::string  dbFilename,
        const std::array<unsigned char, crypto_secretbox_KEYBYTES> &encryptionKey);
    /**
     * @brief Safely erases encryption key from memory upon destruction.
     */
    ~PasswordManager();
    /**
     * @brief Adds a new service, login, and password to the database.
     * The entry is added only if the combination of service and login
     * does not already exist in the database. If the entry already exists,
     * it will be ignored, and no changes will be made.
     * @param service The name of the service.
     * @param login The login for the service.
     * @param password The password to store for the service.
     */
    void add(const std::string& service, const std::string& login, const SecureBuffer& password) const;
    /**
     * @brief Retrieves and displays stored password for a service and login.
     * @param service The service name.
     * @param loginOpt Optional login filter for narrowing results.
     */
    void get(const std::string& service, const std::optional<std::string>& loginOpt) const;
    /**
     * @brief Copies a password associated with a service/login to the clipboard.
     * @param service The service name.
     * @param loginOpt Optional login filter for narrowing results.
     */
    void copy(const std::string& service, const std::optional<std::string>& loginOpt) const;
    /**
     * @brief Updates the password stored for a specific service and login.
     * @param service The name of the service.
     * @param login The associated login/username to update.
     * @param password The new password to store.
     */
    void update(const std::string& service, const std::string& login, const SecureBuffer& password) const;
    /**
     * @brief Removes a password entry associated with a service and login.
     * @param service The service for which the entry should be removed.
     * @param login The login associated with the entry.
     */
    void remove(const std::string& service, const std::string& login) const;
    /**
     * @brief Lists all stored services along with associated logins in the database.
     */
    void list() const;
    /**
     * @brief Displays a help message outlining available options and functions.
     */
    void help() const;

private:
    std::unique_ptr<sqlite::database> db; ///< SQLite database connection.
    const std::string databaseFilename; ///< Path to the database file.
    /**
     * @brief Encrypts passwords.
     * @return Encrypted password.
     */
    [[nodiscard]] std::string encryptPassword(const SecureBuffer& password) const;
    /**
     * @brief Decrypts encrypted password.
     * @return Decrypted password.
     */
    [[nodiscard]] SecureBuffer decryptPassword(const std::string& encryptedPassword) const;
    /**
     * @brief Decrypts and displays a stored password for a service and login.
     */
    void showDecryptedPassword(const std::string &service,
        const std::string &login,
        const std::string &encryptedPassword) const;

    std::array<unsigned char, crypto_secretbox_KEYBYTES> encryptionKey; ///< Key for encryption/decryption
};
