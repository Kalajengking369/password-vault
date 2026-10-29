#include "Getpass.h"

void getpass(char* buffer, size_t bufferSize) {
#ifdef _WIN32
    if (!_isatty(_fileno(stdin))) {
        if (std::cin.getline(buffer, bufferSize)) {
            size_t len = strlen(buffer);
            if (len > 0 && buffer[len - 1] == '\r') {
                buffer[len - 1] = '\0';
            }
        }
        return;
    }
    size_t i = 0;
    char ch;
    // Read characters until Enter ('\r') or buffer limit is reached
    while ((ch = _getch()) != '\r' && i < bufferSize - 1) {
        if (ch == '\b' && i > 0) { // Handle backspace
            --i;
            std::cout << "\b \b"; // Erase last character
        } else if (ch >= 32 && ch <= 126) { // Accept printable characters
            buffer[i++] = ch;
            std::cout << '*';
        }
    }
    buffer[i] = '\0';
#else
    // Uses Unix-specific getpass() to read the password safely
    char* pwd = getpass("Password: ");
    strncpy(buffer, pwd, bufferSize - 1);
    buffer[bufferSize - 1] = '\0';
    sodium_memzero(pwd, strlen(pwd)); // Securely erase temporary buffer
#endif
    std::cout << std::endl;
}
