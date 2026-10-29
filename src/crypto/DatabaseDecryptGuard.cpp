#include "DatabaseDecryptGuard.h"

DatabaseDecryptGuard::DatabaseDecryptGuard(const std::string &filename, const std::array<unsigned char, crypto_secretbox_KEYBYTES> &encryptionKey)
    : filename(filename), encryptionKey(encryptionKey) {
    DatabaseEncryptor::decryptDatabase(filename, encryptionKey);
}

DatabaseDecryptGuard::~DatabaseDecryptGuard() {
    try {
        DatabaseEncryptor::encryptDatabase(filename, encryptionKey);
    } catch (const std::exception& e) {
        std::cerr << "Warning: Failed to re-encrypt database: " << e.what() << std::endl;
    }
    sodium_memzero(encryptionKey.data(), encryptionKey.size());
}
