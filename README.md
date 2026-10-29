# 🔐 Secure Password Vault (CLI)

[![C++20](https://img.shields.io/badge/C%2B%2B-20-00599C?logo=c%2B%2B&logoColor=white)](https://en.cppreference.com/w/cpp/20)
[![CMake](https://img.shields.io/badge/CMake-3.20%2B-064F8C?logo=cmake&logoColor=white)](https://cmake.org/)
[![Cryptography](https://img.shields.io/badge/Crypto-libsodium-blue?logo=security)](https://libsodium.gitbook.io/)
[![Database](https://img.shields.io/badge/Database-SQLite3-003B57?logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A lightweight, modern **C++20** command-line password manager designed with security and memory safety as first principles. Powered by **libsodium** authenticated encryption, **RAII** memory zeroing, and **SQLite** encrypted local persistence.

---

## ✨ Key Features & Security Architecture

- **🔒 Authenticated Symmetric Encryption**: Sensitive credential payloads are encrypted using industry-standard **libsodium** primitives (`crypto_secretbox_easy`, Argon2-based key derivation).
- **🛡️ RAII Memory Protection (`SecureBuffer`)**: Sensitive cryptographic keys and plaintexts in RAM are protected using custom RAII wrappers. Buffers are automatically scrubbed upon destruction via `sodium_memzero()` to mitigate cold-boot or memory inspection attacks. Copy semantics are explicitly deleted (`= delete`) while move semantics are preserved.
- **⚡ Scoped Database Guard (`DatabaseDecryptGuard`)**: Encrypted SQLite storage is managed through scoped guards, ensuring decrypted files are re-encrypted when the guard goes out of scope. Re-encryption errors are caught in the destructor to prevent `std::terminate` during stack unwinding.
- **👁️ Masked Terminal Input (`Getpass`)**: Master password input is completely hidden in terminal sessions to prevent shoulder-surfing.
- **📋 Native Clipboard Integration**: Directly copy credentials to the system clipboard via the cross-platform `clip` library.
- **⏱️ Timed Terminal Exposure**: Passwords fetched to standard output are displayed for only 5 seconds before the password line is overwritten with asterisks.
- **📦 Modern CMake Dependency Management**: Uses `FetchContent` to automatically download `libsodium` and `clip` during compilation. SQLite3 and `sqlite_modern_cpp` are bundled in the `libs/` directory.

---

## 🏗️ Architecture

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        Master Authentication                           │
│  User Input (Getpass) ──► Argon2 Key Derivation ──► SecureBuffer (RAM) │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     DatabaseDecryptGuard (RAII)                        │
│  Encrypted SQLite File (Disk) ◄──► Decrypted SQLite File (Temporary)   │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
              ┌────────────────────┴────────────────────┐
              ▼                                         ▼
   ┌──────────────────────┐                  ┌──────────────────────┐
   │ Interactive CLI      │                  │ OS Clipboard         │
   │ (add, update, list)  │                  │ (Native Integration) │
   └──────────────────────┘                  └──────────────────────┘
```

---

## 🚀 Getting Started

### Prerequisites

- **CMake**: Version 3.20 or newer
- **C++ Compiler**: GCC 11+, Clang 13+, or MSVC supporting **C++20**
- **Git**: Required for automatic dependency fetching via `FetchContent`

---

### Build Instructions

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Kalajengking369/password-vault.git
   cd password-vault
   ```

2. **Generate build configuration with CMake**:
   ```bash
   cmake -B build -DCMAKE_BUILD_TYPE=Release
   ```

3. **Compile the binary**:
   ```bash
   cmake --build build --config Release
   ```
   *(The executable `password-vault` will be output into the `build/` directory).*

---

## 🎮 Usage & Commands

Run the compiled executable:

```bash
./build/password-vault
```

Upon launching, enter your **Master Password** to authenticate and unlock the vault:

```text
Enter Master Password: ********
Vault unlocked. Type 'help' for available commands.
```

### Available Commands

| Command | Syntax | Description |
|---|---|---|
| `add` | `add <service> <login>` | Encrypt and store a new credential |
| `get` | `get <service> [login]` | Retrieve and display password in terminal for 5 seconds |
| `copy` | `copy <service> [login]` | Copy decrypted password directly to OS clipboard |
| `update` | `update <service> <login>` | Update an existing credential |
| `delete` | `delete <service> <login>` | Remove a stored credential from the vault |
| `list` | `list` | List all saved services and associated logins |
| `help` | `help` | Display list of supported commands |
| `exit` | `exit` | Securely close the database and exit |

---

## 📚 Dependencies

The project relies on clean, modern libraries:

- **[libsodium](https://github.com/robinlinden/libsodium-cmake)**: Modern, portable cryptography library. *(Fetched via CMake FetchContent)*
- **[SQLite3](https://sqlite.org/)**: Self-contained, serverless transactional database engine. *(Bundled in `libs/`)*
- **[sqlite_modern_cpp](https://github.com/SqliteModernCpp/sqlite_modern_cpp)**: Modern C++ RAII wrapper around the SQLite C API. *(Bundled in `libs/`)*
- **[Clip](https://github.com/dacap/clip)**: Cross-platform C++ library for native clipboard access. *(Fetched via CMake FetchContent)*

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 👤 Author

- **Pavel Valošek**
- GitHub: [@Kalajengking369](https://github.com/Kalajengking369)
- Email: paja03.pv@gmail.com
- Study Programme: Informatics, VŠB – Technical University of Ostrava
