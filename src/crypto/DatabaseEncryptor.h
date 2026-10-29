#pragma once
#include <string>
#include <sodium.h>
#include <array>
#include <fstream>
#include <filesystem>
#include <vector>
#include "SecureBuffer.h"
/**
 * @class DatabaseEncryptor
 * @brief Handles encryption and decryption of database files using libsodium.
 *
 * Provides static methods to securely encrypt and decrypt SQLite database files
 */
class DatabaseEncryptor {
public:
    /**
     * @brief Encrypts a database file using the specified encryption key.
     * @param dbFile Path to the database file.
     * @param encryptionKey Key for encrypting the file contents.
     * @throws std::runtime_error If the file does not exist or cannot be encrypted.
     */
    static void encryptDatabase(const std::string& dbFile, const std::array<unsigned char, crypto_secretbox_KEYBYTES>& encryptionKey);
    /**
     * @brief Decrypts a database file using the specified encryption key.
     * @param dbFile Path to the encrypted database file.
     * @param encryptionKey Key for decrypting the file contents.
     * @throws std::runtime_error If the file does not exist, is invalid, or cannot be decrypted.
     */
    static void decryptDatabase(const std::string& dbFile, const std::array<unsigned char, crypto_secretbox_KEYBYTES>& encryptionKey);
};
