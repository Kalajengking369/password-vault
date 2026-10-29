#include "DatabaseEncryptor.h"

void DatabaseEncryptor::encryptDatabase(const std::string& dbFile, const std::array<unsigned char, crypto_secretbox_KEYBYTES>& encryptionKey) {
    if (!std::filesystem::exists(dbFile)) {
        throw std::runtime_error("Database does not exist.");
    }

    std::ifstream inFile(dbFile, std::ios::binary | std::ios::ate);
    if (!inFile.is_open()) {
        throw std::runtime_error("Failed to open database file for encryption.");
    }

    size_t fileSize = inFile.tellg();
    inFile.seekg(0, std::ios::beg);

    SecureBuffer plaintextBuf(fileSize);
    inFile.read(plaintextBuf.get(), fileSize);
    inFile.close();

    // Allocate space for ciphertext (original size + MAC overhead)
    std::vector<unsigned char> ciphertext(fileSize + crypto_secretbox_MACBYTES);

    // Generate a new nonce for this encryption
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);

    // Encrypt the plaintext using the nonce and provided key
    crypto_secretbox_easy(ciphertext.data(),
                          reinterpret_cast<unsigned char*>(plaintextBuf.get()),
                          fileSize,
                          nonce,
                          encryptionKey.data());

    // Overwrite the original file: write nonce + ciphertext
    std::ofstream outFile(dbFile, std::ios::binary | std::ios::trunc);
    outFile.write(reinterpret_cast<const char*>(nonce), sizeof nonce);
    outFile.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    outFile.close();
}


void DatabaseEncryptor::decryptDatabase(const std::string& dbFile, const std::array<unsigned char, crypto_secretbox_KEYBYTES>& encryptionKey) {
    if (!std::filesystem::exists(dbFile)) {
        throw std::runtime_error("Database does not exist.");
    }

    std::ifstream inFile(dbFile, std::ios::binary | std::ios::ate);
    if (!inFile.is_open()) {
        throw std::runtime_error("Failed to open database file for decryption.");
    }

    size_t fileSize = inFile.tellg();
    inFile.seekg(0, std::ios::beg);

    // File must be at least large enough to contain nonce and MAC
    if (fileSize < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        throw std::runtime_error("Database is too small to be encrypted.");
    }

    // Read the nonce from the beginning of the file
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    inFile.read(reinterpret_cast<char*>(nonce), sizeof nonce);

    // Read the ciphertext (remaining bytes)
    std::vector<unsigned char> ciphertext(fileSize - sizeof nonce);
    inFile.read(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());
    inFile.close();

    // Allocate buffer for the decrypted plaintext
    SecureBuffer plaintextBuf(ciphertext.size() - crypto_secretbox_MACBYTES);

    // Attempt to decrypt the ciphertext using the nonce and key
    if (crypto_secretbox_open_easy(
            reinterpret_cast<unsigned char*>(plaintextBuf.get()),
            ciphertext.data(),
            ciphertext.size(),
            nonce,
            encryptionKey.data()) != 0) {
        throw std::runtime_error("Failed to decrypt database.");
            }

    // Overwrite the file with the decrypted plaintext
    std::ofstream outFile(dbFile, std::ios::binary | std::ios::trunc);
    outFile.write(plaintextBuf.get(), plaintextBuf.size());
    outFile.close();
}
