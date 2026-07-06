# SPDX-License-Identifier: BSD-3-Clause
#
# Builds the `ethwallet` module: the Rust `aero_core` static library (via Corrosion) plus the
# thin Qt/C++ wrapper that replaces Feather's `libwalletqt`.
#
# In the forked Feather tree, add `add_subdirectory(ethwallet)` from `src/CMakeLists.txt` and link
# the `ethwallet` target instead of the old `libwalletqt`/`monero` targets.

# --- Import the Rust core via Corrosion ---
include(FetchContent)
FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_TAG v0.5
)
FetchContent_MakeAvailable(Corrosion)

# `../../../core` is the aero_core crate (relative to this file: frontend/src/ethwallet).
corrosion_import_crate(MANIFEST_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../../core/Cargo.toml)

# --- Qt wrapper library ---
find_package(Qt6 REQUIRED COMPONENTS Core Concurrent)

add_library(ethwallet STATIC
    Wallet.cpp
    Wallet.h
    WalletManager.cpp
    WalletManager.h
    HistoryModel.cpp
    HistoryModel.h
    aero_core.h
)

target_include_directories(ethwallet PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(ethwallet
    PUBLIC
        Qt6::Core
        Qt6::Concurrent
        aero_core            # the Rust staticlib target created by Corrosion
)

# On Windows the Rust std links against these system libs; MSVC/MinGW both need them.
if (WIN32)
    target_link_libraries(ethwallet PUBLIC ws2_32 userenv bcrypt ntdll)
endif()

set_target_properties(ethwallet PROPERTIES
    AUTOMOC ON
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)
