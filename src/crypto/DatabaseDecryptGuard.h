#pragma once
#include <array>
#include "DatabaseEncryptor.h"
#include <iostream>

/**
 * @class DatabaseDecryptGuard
 * @brief Manages the decryption and encryption lifecycle of a database file.
 *
 * The DatabaseDecryptGuard class ensures that a database file is decrypted
 * during its scope and re-encrypted upon destruction, using the provided encryption key.
 * This makes it safer to work with sensitive information while ensuring automatic cleanup.
 */
class DatabaseDecryptGuard {
public:
    /**
     * @brief Constructs a DatabaseDecryptGuard and decrypts the provided database file.
     * @param filename The path to the encrypted database file.
     * @param encryptionKey The key used for decrypting and re-encrypting the database.
     */
    DatabaseDecryptGuard(const std::string& filename, const std::array<unsigned char, crypto_secretbox_KEYBYTES> &encryptionKey);
    /**
     * @brief Destructs the DatabaseDecryptGuard and re-encrypts the database file.
     * Safely erases encryption key from memory upon destruction.
     * Re-encryption errors are caught to prevent std::terminate during stack unwinding.
     */
    ~DatabaseDecryptGuard();
    DatabaseDecryptGuard(const DatabaseDecryptGuard&) = delete; ///< Copy constructor is disabled.
    DatabaseDecryptGuard& operator=(const DatabaseDecryptGuard&) = delete; ///< Copy assignment operator is disabled.
private:
    std::string filename; ///< Path to the target database file.
    std::array<unsigned char, crypto_secretbox_KEYBYTES> encryptionKey; ///< Encryption key for managing database encryption/decryption.
};
