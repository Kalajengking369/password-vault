#include "CommandParser.h"

std::optional<Command> parseCommand(const std::string& input) {
    std::istringstream iss(input);
    std::vector<std::string> tokens;
    std::string tok;
    while (iss >> tok) tokens.push_back(tok);

    if (tokens.empty()) return std::nullopt;

    const std::string& cmd = tokens[0];
    if (cmd == "add" && tokens.size() == 3) return AddCommand{tokens[1], tokens[2]};
    if (cmd == "get" && tokens.size() == 2) return GetCommand{tokens[1]};
    if (cmd == "get" && tokens.size() == 3) return GetCommand{tokens[1], tokens[2]};
    if (cmd == "copy" && tokens.size() == 2) return CopyCommand{tokens[1]};
    if (cmd == "copy" && tokens.size() == 3) return CopyCommand{tokens[1], tokens[2]};
    if (cmd == "update" && tokens.size() == 3) return UpdateCommand{tokens[1], tokens[2]};
    if (cmd == "delete" && tokens.size() == 3) return DeleteCommand{tokens[1], tokens[2]};
    if (cmd == "list") return ListCommand{};
    if (cmd == "help") return HelpCommand{};
    if (cmd == "exit") return ExitCommand{};

    return std::nullopt;
}