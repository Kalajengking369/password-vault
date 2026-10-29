#pragma once
#include <iostream>
#include <array>
#include <optional>
#include "sqlite_modern_cpp.h"
#include <fstream>
#include <sodium.h>
#include "crypto/SecureBuffer.h"
#include "utils/Getpass.h"

/**
 * @class MasterPasswordManager
 * @brief Manages a master password, including authentication, storage, and encryption key derivation.
 *
 * Handles secure hashing and storage of a master password, verifying user input, and
 * deriving encryption keys using libsodium.
 */

class MasterPasswordManager {
public:
    /**
     * @brief Initializes the manager.
     * @param masterPasswordFile
     */
    explicit MasterPasswordManager(std::string  masterPasswordFile);
    /**
     * @brief Safely erases encryption key from memory upon destruction.
     */
    ~MasterPasswordManager();
    /**
     * @brief Authenticates the user or set a new master password.
     * @return true if successfully authenticated or password set, false otherwise.
     */
    bool authenticate();
    /**
     * @return A derived encryption key.
     */
    [[nodiscard]] const std::array<unsigned char, crypto_secretbox_KEYBYTES> getEncryptionKey() const;
private:
    const std::string masterPasswordFile; ///< File path for the stored master password.
    /**
     * @brief Verifies a user-provided password against the stored hash.
     * @param password Input password.
     * @return true if the input matches the stored hash, false otherwise.
     */
    [[nodiscard]] bool verifyPassword(const SecureBuffer& password) const;
    /**
     * @brief Hashes and saves a new master password securely.
     * @param password The new master password to be hashed and stored.
     * @throw std::runtime_error If hashing or file operations fail.
     */
    void setMasterPassword(const SecureBuffer& password) const;
    /**
     * @brief Loads the hashed master password.
     * @return The hashed password if it exists, otherwise std::nullopt.
     */
    [[nodiscard]] std::optional<std::string> loadMasterPassword() const;
    /**
     * @brief Writes a hashed password to the password file.
     * @param password The hashed password to store.
     * @throw std::runtime_error If the file operation fails.
     */
    void saveMasterPassword(const std::string& password) const;
    std::array<unsigned char, crypto_secretbox_KEYBYTES> encryptionKey{};///< Encryption key.
    /**
     * @brief Derives an encryption key from the provided password.
     * @param password The master password for deterministic key derivation.
     * @throw std::runtime_error If key derivation fails.
     */
    void deriveKeyFromPassword(const SecureBuffer& password);
    /**
     * @brief Checks if a password meets strength criteria.
     * @param password The password to validate.
     * @return true if the password is strong enough, false otherwise.
     */
    [[nodiscard]] bool isStrongPassword(const SecureBuffer& password) const;
};