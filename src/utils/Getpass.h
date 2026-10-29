#pragma once
#include <iostream>
#ifdef _WIN32
#include <conio.h>
#include <io.h>
#else
#include <unistd.h>
#include <cstring>
#include <sodium.h>
#endif
/**
 * @brief Safely captures a password as user input.
 *
 * Reads a password from user input while protecting their privacy
 * by masking the input. Behavior differs across
 * platforms (Windows vs. Unix).
 *
 * @param buffer A buffer to store the entered password.
 * @param bufferSize Maximum size of the password buffer.
 */
void getpass(char* buffer, size_t bufferSize);
