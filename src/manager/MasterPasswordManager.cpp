#include "MasterPasswordManager.h"

#include <utility>
#include <filesystem>

MasterPasswordManager::MasterPasswordManager(std::string masterPasswordFile) : masterPasswordFile(std::move(masterPasswordFile)){}

MasterPasswordManager::~MasterPasswordManager() {
    sodium_memzero(encryptionKey.data(), encryptionKey.size());
}

bool MasterPasswordManager::authenticate() {
    const SecureBuffer passwordBuf(128);
    const auto masterPassword = loadMasterPassword();
    if (!masterPassword.has_value()) {
        std::cout << "Set a master password (min 8 chars, with upper, lower, digit, special char): ";

        do {
            getpass(passwordBuf.get(), passwordBuf.size());
            if (!isStrongPassword(passwordBuf)) {
                std::cout << "Password too weak. Try again: ";
            }
        } while (!isStrongPassword(passwordBuf));

        setMasterPassword(passwordBuf);
        deriveKeyFromPassword(passwordBuf);

        return true;
    }

    std::cout << "Enter master password: ";

    for (int i = 3; i > 0; i--) {
        getpass(passwordBuf.get(), passwordBuf.size());
        if (verifyPassword(passwordBuf)) {
            deriveKeyFromPassword(passwordBuf);

            return true;
        }
        if (i != 1)
            std::cout << "Wrong password. " << (i - 1) << " attempts left." << std::endl;
    }

    return false;
}


const std::array<unsigned char, crypto_secretbox_KEYBYTES> MasterPasswordManager::getEncryptionKey() const {
    return encryptionKey;
}

bool MasterPasswordManager::verifyPassword(const SecureBuffer &password) const {
    const auto masterHash = loadMasterPassword();
    if (!masterHash.has_value()) return false;
    return crypto_pwhash_str_verify(masterHash->c_str(), password.getConst(), password.length()) == 0;
}

void MasterPasswordManager::setMasterPassword(const SecureBuffer &password) const {
    char hashedPassword[crypto_pwhash_STRBYTES];
    // Hash the password using libsodium's password hashing function.
    // OPSLIMIT and MEMLIMIT define computation/memory cost
    if (crypto_pwhash_str(hashedPassword, password.getConst(), password.length(), crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        throw std::runtime_error("Failed to hash password");
        }

    saveMasterPassword(std::string{hashedPassword});
    sodium_memzero(hashedPassword, sizeof(hashedPassword));
}


std::optional<std::string> MasterPasswordManager::loadMasterPassword() const {
    try {
        std::ifstream file(masterPasswordFile, std::ios::binary);
        if (!file.is_open()) {
            return std::nullopt;
        }

        std::string hash;
        file.seekg(0, std::ios::end);
        const size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);

        hash.resize(fileSize);
        file.read(&hash[0], fileSize);

        return hash;

    } catch (...) {
        return std::nullopt;
    }
}

void MasterPasswordManager::saveMasterPassword(const std::string& password) const {
    try {
        std::ofstream file(masterPasswordFile, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open file for writing.");
        }

        file.write(password.c_str(), password.size());
        file.close();
    } catch (...) {
        throw std::runtime_error("Failed to write password to file.");
    }
}

void MasterPasswordManager::deriveKeyFromPassword(const SecureBuffer& password) {
    unsigned char salt[crypto_pwhash_SALTBYTES];
    const std::string saltFile = masterPasswordFile + ".salt";

    if (std::filesystem::exists(saltFile)) {
        // Load existing salt from file
        std::ifstream file(saltFile, std::ios::binary);
        if (!file.is_open() || !file.read(reinterpret_cast<char*>(salt), sizeof(salt))) {
            throw std::runtime_error("Failed to read salt file.");
        }
    } else {
        // Generate a new random salt and persist it
        randombytes_buf(salt, sizeof(salt));
        std::ofstream file(saltFile, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to create salt file.");
        }
        file.write(reinterpret_cast<const char*>(salt), sizeof(salt));
        file.close();
    }

    // Derive a symmetric encryption key from the password using libsodium.
    // OPSLIMIT and MEMLIMIT define computation/memory cost
    if (crypto_pwhash(encryptionKey.data(), encryptionKey.size(),
                      password.getConst(), password.length(),
                      salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        throw std::runtime_error("Failed to derive encryption key from password.");
                      }

    sodium_memzero(salt, sizeof(salt));
}


bool MasterPasswordManager::isStrongPassword(const SecureBuffer &password) const {
    const size_t length = password.length();
    if (length < 8) return false;

    const char* data = password.getConst();
    bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;

    for (size_t i = 0; i < length; ++i) {
        if (std::isupper(data[i])) hasUpper = true;
        if (std::islower(data[i])) hasLower = true;
        if (std::isdigit(data[i])) hasDigit = true;
        if (std::ispunct(data[i])) hasSpecial = true;
    }
    return hasUpper && hasLower && hasDigit && hasSpecial;
}

