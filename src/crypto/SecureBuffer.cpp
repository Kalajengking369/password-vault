#include "SecureBuffer.h"

SecureBuffer::SecureBuffer(const size_t size) : bufferSize(size) {
    data = static_cast<char*>(sodium_malloc(size)); // Allocation of secure memory using sodium_malloc
    if (data == nullptr) {
        throw std::runtime_error("Failed to allocate secure memory.");
    }
    std::fill_n(data, size, '\0');
}

SecureBuffer::SecureBuffer(const char* input, const size_t size) : SecureBuffer(size + 1) {
    std::copy_n(input, size, data);
    data[size] = '\0';
}

SecureBuffer::~SecureBuffer() {
    if (data != nullptr) {
        sodium_memzero(data, bufferSize);
        sodium_free(data); // Freeing securely allocated memory
        data = nullptr;
    }
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data(other.data), bufferSize(other.bufferSize) {
    other.data = nullptr;
    other.bufferSize = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        if (data != nullptr) {
            sodium_memzero(data, bufferSize);
            sodium_free(data);
        }
        data = other.data;
        bufferSize = other.bufferSize;
        other.data = nullptr;
        other.bufferSize = 0;
    }
    return *this;
}

char* SecureBuffer::get() const {
    return data;
}

const char* SecureBuffer::getConst() const {
    return data;
}

size_t SecureBuffer::size() const {
    return bufferSize;
}

size_t SecureBuffer::length() const {
    return data ? strlen(data) : 0;
}
