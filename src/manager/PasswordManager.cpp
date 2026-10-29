#include "PasswordManager.h"


PasswordManager::PasswordManager(std::string  dbFilename, const std::array<unsigned char, crypto_secretbox_KEYBYTES> &encryptionKey)
    : databaseFilename(std::move(dbFilename)), encryptionKey(encryptionKey) {
    if (!std::filesystem::exists(databaseFilename)) {
        db = std::make_unique<sqlite::database>(databaseFilename);
        try {
            *db << "CREATE TABLE IF NOT EXISTS passwords ("
                    "   id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,"
                    "   login TEXT,"
                    "   service TEXT,"
                    "   password TEXT,"
                    "   UNIQUE(service, login)"
                    ");";
            DatabaseEncryptor::encryptDatabase(databaseFilename, encryptionKey);
        } catch (...) {
           throw std::runtime_error("Error creating database: ");
        }
    }else {
        db = std::make_unique<sqlite::database>(databaseFilename);
    }
}

PasswordManager::~PasswordManager() {
    sodium_memzero(encryptionKey.data(), encryptionKey.size());
}

void PasswordManager::add(const std::string &service, const std::string &login, const SecureBuffer &password) const {
    DatabaseDecryptGuard guard(databaseFilename, encryptionKey);
    const std::string encryptedPassword = encryptPassword(password);
    try {
        *db << "INSERT OR IGNORE INTO passwords (service, login, password) VALUES (?,?,?);"
        << service
        << login
        << encryptedPassword;

        if (db->rows_modified() == 0) {
            std::cout << "Password for " << service << " with login " << login << " already exists." << std::endl;
        } else {
            std::cout << service << " was successfully added." << std::endl;
        }

    }catch (const sqlite::sqlite_exception& e) {
        std::cout << e.what() << std::endl;
    }
}

void PasswordManager::get(const std::string& service, const std::optional<std::string>& loginOpt) const {
    DatabaseDecryptGuard guard(databaseFilename, encryptionKey);

    try {
        std::vector<std::pair<std::string, std::string>> results;

        if (loginOpt) {
            *db << "SELECT login, password FROM passwords WHERE service = ? AND login = ?;"
                << service
                << *loginOpt
                >> [&](const std::string& login, const std::string& encryptedPassword) {
                    results.emplace_back(login, encryptedPassword);
                };

            if (results.empty()) {
                std::cout << "No credentials found for service '" << service << "' and login '" << *loginOpt << "'." << std::endl;
                return;
            }

            const auto& [login, encryptedPassword] = results.front();
            showDecryptedPassword(service, login, encryptedPassword);
            return;
        }

        *db << "SELECT login, password FROM passwords WHERE service = ?;"
            << service
            >> [&](const std::string& login, const std::string& encryptedPassword) {
                results.emplace_back(login, encryptedPassword);
            };

        if (results.empty()) {
            std::cout << "No credentials found for service '" << service << "'." << std::endl;
            return;
        }

        if (results.size() == 1) {
            const auto& [login, encryptedPassword] = results.front();
            showDecryptedPassword(service, login, encryptedPassword);
            return;
        }

        for (size_t i = 0; i < results.size(); ++i) {
            std::cout << i + 1 << ". " << results[i].first << std::endl;
        }

        int choiceInt;
        std::string choice;
        while (true) {
            std::cout << "Select which credentials to reveal (1-" << results.size() << "): ";
            std::getline(std::cin, choice);
            try {
                choiceInt = std::stoi(choice);
            } catch (const std::exception&) {
                std::cout << "Invalid choice. Try again." << std::endl;
                continue;
            }
            if (choiceInt < 1 || choiceInt > static_cast<int>(results.size())) {
                std::cout << "Invalid choice. Try again." << std::endl;
                continue;
            }
            break;
        }

        const auto& [selectedLogin, selectedEncryptedPassword] = results[choiceInt - 1];
        showDecryptedPassword(service, selectedLogin, selectedEncryptedPassword);

    } catch (const sqlite::sqlite_exception& e) {
        std::cerr << "Database error: " << e.what() << std::endl;
    }
}

void PasswordManager::copy(const std::string &service, const std::optional<std::string> &loginOpt) const {
    DatabaseDecryptGuard guard(databaseFilename, encryptionKey);

    try {
        std::vector<std::pair<std::string, std::string>> results;

        if (loginOpt) {
            *db << "SELECT login, password FROM passwords WHERE service = ? AND login = ?;"
                << service
                << *loginOpt
                >> [&](const std::string& login, const std::string& encryptedPassword) {
                    results.emplace_back(login, encryptedPassword);
                };

            if (results.empty()) {
                std::cout << "No credentials found for service '" << service << "' and login '" << *loginOpt << "'." << std::endl;
                return;
            }

            const auto& [login, encryptedPassword] = results.front();
            const SecureBuffer decrypted = decryptPassword(encryptedPassword);
            clip::set_text(decrypted.getConst());
            std::cout << "Password copied to clipboard." << std::endl;
            return;
        }

        *db << "SELECT login, password FROM passwords WHERE service = ?;"
            << service
            >> [&](const std::string& login, const std::string& encryptedPassword) {
                results.emplace_back(login, encryptedPassword);
            };

        if (results.empty()) {
            std::cout << "No credentials found for service '" << service << "'." << std::endl;
            return;
        }

        if (results.size() == 1) {
            const auto& [login, encryptedPassword] = results.front();
            const SecureBuffer decrypted = decryptPassword(encryptedPassword);
            clip::set_text(decrypted.getConst());
            std::cout << "Password copied to clipboard." << std::endl;
            return;
        }

        std::cout << "Found multiple entries for service '" << service << "':" << std::endl;
        for (size_t i = 0; i < results.size(); ++i)
            std::cout << i + 1 << ". " << results[i].first << std::endl;

        std::string choice;
        int choiceInt = 0;
        while (true) {
            std::cout << "Select which login to copy (1-" << results.size() << "): ";
            std::getline(std::cin, choice);
            try {
                choiceInt = std::stoi(choice);
            } catch (...) {
                std::cout << "Invalid input. Try again." << std::endl;
                continue;
            }
            if (choiceInt >= 1 && choiceInt <= static_cast<int>(results.size()))
                break;

            std::cout << "Invalid choice. Try again." << std::endl;
        }

        const auto& [selectedLogin, selectedEncryptedPassword] = results[choiceInt - 1];
        const SecureBuffer decrypted = decryptPassword(selectedEncryptedPassword);
        clip::set_text(decrypted.getConst());
        std::cout << "Password copied to clipboard." << std::endl;

    } catch (const sqlite::sqlite_exception& e) {
        std::cerr << "Database error: " << e.what() << std::endl;
    }
}


void PasswordManager::update(const std::string& service, const std::string& login,const SecureBuffer& password) const {
    DatabaseDecryptGuard guard(databaseFilename, encryptionKey);
    const std::string encryptedPassword = encryptPassword(password);
    try {
        *db << "UPDATE passwords SET password = ? WHERE service = ? and login = ?;"
        << encryptedPassword
        << service
        << login;
        if (db->rows_modified()) {
            std::cout << "Password for " << service << " with login: " << login << " was successfully updated." << std::endl;
        }else {
            std::cout << "No " << service << " service was found." << std::endl;
        }

    }catch (sqlite::sqlite_exception& e) {
        std::cout << e.what() << std::endl;
    }
}

void PasswordManager::remove(const std::string& service, const std::string& login) const {
    DatabaseDecryptGuard guard(databaseFilename, encryptionKey);
    try {
        *db << "DELETE FROM passwords WHERE service = ? and login = ?;"
        << service
        << login;
        if (db->rows_modified()) {
            std::cout << "Service " << service << " with login: " << login << " was successfully removed." << std::endl;
        }else {
            std::cout << "No " << service << " service was found." << std::endl;
        }
    }catch (sqlite::sqlite_exception& e) {
        std::cout << e.what() << std::endl;
    }
}

void PasswordManager::list() const {
    DatabaseDecryptGuard guard(databaseFilename, encryptionKey);
    try {
        bool found = false;
        int index = 1;
        *db << "SELECT service, login FROM passwords;"
        >> [&](const std::string& service, const std::string& login) {
            std::cout << index++ << ". Service: " << service << std::endl
                      << "   Login:   " << login << std::endl
                      << std::string(20, '-') << std::endl;
            found = true;
        };

        if (!found) {
            std::cout << "No services found." << std::endl;
        }
    }catch (sqlite::sqlite_exception& e) {
        std::cout << e.what() << std::endl;
    }
}

void PasswordManager::help() const {
    std::cout << std::string(30, '-') << std::endl;
    std::cout << "add    | service | login" << std::endl;
    std::cout << "get    | service" << std::endl;
    std::cout << "get    | service | login" << std::endl;
    std::cout << "copy   | service" << std::endl;
    std::cout << "copy   | service | login" << std::endl;
    std::cout << "update | service | login" << std::endl;
    std::cout << "delete | service | login" << std::endl;
    std::cout << "list" << std::endl;
    std::cout << "help" << std::endl;
    std::cout << "exit" << std::endl;
    std::cout << std::string(30, '-') << std::endl;
}

std::string PasswordManager::encryptPassword(const SecureBuffer& password) const {
    const size_t passwordLen = password.length();
    // Include null terminator (+1) so decrypted plaintext is always a valid C-string
    const size_t payloadLen = passwordLen + 1;

    // Generate a nonce for each encryption
    std::array<unsigned char, crypto_secretbox_NONCEBYTES> nonce{};
    randombytes_buf(nonce.data(), nonce.size());

    // Allocate space for the ciphertext (actual password length with null-terminator + MAC overhead)
    std::vector<unsigned char> ciphertext(payloadLen + crypto_secretbox_MACBYTES);

    // Encrypt the password including null-terminator using libsodium's secretbox
    if (crypto_secretbox_easy(ciphertext.data(),
                              reinterpret_cast<const unsigned char*>(password.getConst()),
                              payloadLen,
                              nonce.data(),
                              encryptionKey.data()) != 0) {
        throw std::runtime_error("Error encrypting password.");
    }

    // Combine nonce + ciphertext into a single string
    std::string result;
    result.reserve(nonce.size() + ciphertext.size());
    result.append(reinterpret_cast<const char*>(nonce.data()), nonce.size());
    result.append(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());

    return result;
}


SecureBuffer PasswordManager::decryptPassword(const std::string& encryptedPassword) const {
    // Validate size: must be at least nonce + MAC
    if (encryptedPassword.size() <= crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        throw std::runtime_error("Invalid encrypted password format.");
    }

    // Raw pointer to underlying encrypted data
    const auto* raw = reinterpret_cast<const unsigned char*>(encryptedPassword.data());

    // Extract nonce from beginning of data
    std::array<unsigned char, crypto_secretbox_NONCEBYTES> nonce{};
    std::memcpy(nonce.data(), raw, nonce.size());

    // Extract the ciphertext (everything after the nonce)
    const size_t ciphertextSize = encryptedPassword.size() - nonce.size();
    const unsigned char* ciphertext = raw + nonce.size();

    // Prepare buffer for decrypted data (original password)
    std::vector<unsigned char> decrypted(ciphertextSize - crypto_secretbox_MACBYTES);

    // Decrypt using libsodium's secretbox
    if (crypto_secretbox_open_easy(decrypted.data(),
                                   ciphertext,
                                   ciphertextSize,
                                   nonce.data(),
                                   encryptionKey.data()) != 0) {
        throw std::runtime_error("Error decrypting password.");
                                   }
    // Wrap into SecureBuffer and wipe plaintext copy from memory
    SecureBuffer result(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
    sodium_memzero(decrypted.data(), decrypted.size());

    return result;
}


void PasswordManager::showDecryptedPassword(const std::string& service, const std::string& login, const std::string& encryptedPassword) const {
    try {
        const SecureBuffer decryptedPassword = decryptPassword(encryptedPassword);

        std::cout << "Service:  " << service << "\n"
                  << "Login:    " << login << "\n"
                  << "Password: " << decryptedPassword.getConst() << std::flush;

        // Give user time to read the password for 5 seconds.
        std::this_thread::sleep_for(std::chrono::seconds(5));

        // Clear the password from the terminal
        std::cout << "\r\033[KPassword: ";
        std::cout << std::string(12, '*') << std::endl;
    } catch (...) {
        std::cout << "Failed to decrypt password: ";
    }
}
