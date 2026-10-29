#pragma once
#include "Commands.h"
#include <optional>
#include <vector>
#include <sstream>
#include <cstring>

/**
 * @brief Parses a user input string into a Command variant.
 *
 * Recognizes commands like "add", "get", "update", etc., and maps them
 * to their corresponding Command struct.
 *
 * @param input The raw user input string
 * @return A std::optional<Command>. Returns std::nullopt if the input
 *         is invalid or doesn't match a known command pattern.
 */
std::optional<Command> parseCommand(const std::string& input);
