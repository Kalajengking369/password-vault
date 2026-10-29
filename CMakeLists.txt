cmake_minimum_required(VERSION 3.20)
project(password-vault LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)

include(FetchContent)
set(FETCHCONTENT_BASE_DIR ${CMAKE_SOURCE_DIR}/libs)

# ===================
# Fetch: clip
# ===================
set(CLIP_ENABLE_IMAGE OFF CACHE BOOL "" FORCE)
set(CLIP_EXAMPLES OFF CACHE BOOL "" FORCE)
set(CLIP_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
        clip
        GIT_REPOSITORY https://github.com/dacap/clip.git
        GIT_TAG main
)
FetchContent_MakeAvailable(clip)

# ===================
# Fetch: libsodium
# ===================
FetchContent_Declare(
        libsodium-cmake
        GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
        GIT_TAG master
)
FetchContent_MakeAvailable(libsodium-cmake)

# ===================
# SQLite C library
# ===================
add_library(sqlite3 STATIC libs/sqlite3/sqlite3.c)
set_target_properties(sqlite3 PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(sqlite3 PUBLIC ${CMAKE_SOURCE_DIR}/libs/sqlite3)

# ===================
# Main Executable
# ===================
add_executable(password-vault
        src/main.cpp
        src/command/CommandParser.cpp
        src/command/CommandParser.h
        src/command/Commands.h
        src/manager/PasswordManager.cpp
        src/manager/PasswordManager.h
        src/manager/MasterPasswordManager.cpp
        src/manager/MasterPasswordManager.h
        src/crypto/DatabaseEncryptor.cpp
        src/crypto/DatabaseEncryptor.h
        src/crypto/DatabaseDecryptGuard.cpp
        src/crypto/DatabaseDecryptGuard.h
        src/crypto/SecureBuffer.cpp
        src/crypto/SecureBuffer.h
        src/utils/Getpass.cpp
        src/utils/Getpass.h
)

# ===================
# Include Directories
# ===================
target_include_directories(password-vault
        PRIVATE
        ${CMAKE_SOURCE_DIR}/libs/sqlite_modern_cpp
        ${CMAKE_SOURCE_DIR}/src
        ${clip_SOURCE_DIR}
)

# ===================
# Linking
# ===================
target_link_libraries(password-vault
        PRIVATE
        sqlite3
        sodium
        clip
)
