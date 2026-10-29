#pragma once
#include <sodium.h>
#include <algorithm>
#include <cstring>
#include <stdexcept>

/**
 * @class SecureBuffer
 * @brief Manages secure memory allocation and erasure for sensitive data.
 *
 * Provides a wrapper for securely allocated memory using libsodium, ensuring
 * sensitive data is erased from memory upon destruction.
 */
class SecureBuffer {
public:
    /**
     * @brief Allocates a secure buffer of the given size.
     * @param size The size of the buffer to allocate.
     * @throws std::runtime_error If secure memory allocation fails.
     */
    explicit SecureBuffer(size_t size);
    /**
     * @brief Allocates a secure buffer and copies input data into it.
     * @param input The input data to copy.
     * @param size The size of the input data.
     */
    explicit SecureBuffer(const char* input, size_t size);
    /**
     * @brief Safely erases and frees the allocated buffer.
     */
    ~SecureBuffer();
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;
    /**
     * @brief Returns a writable pointer to the data.
     * @return A writable pointer to the buffer.
     */
    [[nodiscard]] char* get() const;
    /**
     * @brief Returns a read-only pointer to the data.
     * @return A read-only pointer to the buffer.
     */
    [[nodiscard]] const char* getConst() const;
    /**
     * @brief Gets the size of the buffer.
     * @return The size of the buffer.
     */
    [[nodiscard]] size_t size() const;
    /**
     * @brief Gets the length of the data in the buffer.
     * @return The null-terminated length of the data in the buffer.
     */
    [[nodiscard]] size_t length() const;
private:
    char* data; ///< Pointer to the secured buffer.
    size_t bufferSize; ///< Size of the buffer.
};
