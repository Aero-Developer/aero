# SPDX-License-Identifier: BSD-3-Clause
# Aero GUI — a Qt6 Widgets app that reuses Feather's actual .ui layouts + stylesheet, wired to
# the Rust `aero_core` backend (via the ethwallet C++ shim).
cmake_minimum_required(VERSION 3.18)
# The version here is the one stamped into the .exe. Keep it equal to the release tag being cut:
# a binary whose declared version matches a published, hashed release is one an antivirus reputation
# service can actually look up, and one a user can report a bug against.
project(aero_gui VERSION 0.1.38 LANGUAGES CXX C) # C is for the vendored quirc QR decoder

# Compile the Windows resource (.rc) that gives the executable its icon.
if(WIN32)
    enable_language(RC)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# uic finds Feather's .ui files here (they are #included as ui_*.h).
set(CMAKE_AUTOUIC_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/ui)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Concurrent Network)

# Prebuilt Rust core (cdylib). Build it first: `cargo build --release`. The library name and the
# link target differ per platform: Windows links the .dll.a import lib and ships the .dll next to
# the exe; Linux/macOS link the shared object directly (with an rpath of $ORIGIN/@loader_path).
set(AERO_CORE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../core)
set(AERO_CORE_OUT ${AERO_CORE_DIR}/target/release)
if(WIN32)
    set(AERO_CORE_LINK ${AERO_CORE_OUT}/libaero_core.dll.a)
    set(AERO_CORE_RUNTIME ${AERO_CORE_OUT}/aero_core.dll)
elseif(APPLE)
    set(AERO_CORE_LINK ${AERO_CORE_OUT}/libaero_core.dylib)
    set(AERO_CORE_RUNTIME ${AERO_CORE_OUT}/libaero_core.dylib)
else()
    set(AERO_CORE_LINK ${AERO_CORE_OUT}/libaero_core.so)
    set(AERO_CORE_RUNTIME ${AERO_CORE_OUT}/libaero_core.so)
endif()

set(ETHWALLET_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../src/ethwallet)

# WIN32 => GUI subsystem app on Windows (no console); MACOSX_BUNDLE => a proper Aero.app on macOS.
# Each flag is ignored on the other platforms.
add_executable(aero_gui WIN32 MACOSX_BUNDLE
    main.cpp
    AeroMainWindow.cpp
    AeroMainWindow.h
    TorManager.cpp
    TorManager.h
    WalletWizard.cpp
    WalletWizard.h
    XmrTradeTab.cpp
    XmrTradeTab.h
    Updater.cpp
    Updater.h
    qrcodegen.cpp
    qrcodegen.hpp
    # Vendored quirc QR decoder (image-based Scan). MIT.
    quirc/quirc.c
    quirc/decode.c
    quirc/identify.c
    quirc/version_db.c

    # promoted-widget stand-ins + InfoFrame
    components.h
    components.cpp
    widgets/PayToEdit.h
    widgets/PasswordSetWidget.h
    widgets/PasswordSetWidget.cpp
    widgets/TextEdit.h
    widgets/TextEdit.cpp
    model/SubaddressView.h
    model/HistoryView.h

    # ethwallet shim
    ${ETHWALLET_DIR}/Wallet.cpp
    ${ETHWALLET_DIR}/Wallet.h
    ${ETHWALLET_DIR}/WalletManager.cpp
    ${ETHWALLET_DIR}/WalletManager.h
    ${ETHWALLET_DIR}/HistoryModel.cpp
    ${ETHWALLET_DIR}/HistoryModel.h
    ${ETHWALLET_DIR}/AddressModel.cpp
    ${ETHWALLET_DIR}/AddressModel.h

    # Feather layouts + resources
    ui/MainWindow.ui
    ui/SendWidget.ui
    ui/ReceiveWidget.ui
    ui/HistoryWidget.ui
    ui/PageMenu.ui
    ui/PageWalletFile.ui
    ui/PageWalletSeed.ui
    ui/PageSetPassword.ui
    ui/PageOpenWallet.ui
    ui/PasswordSetWidget.ui
    assets.qrc
    qdarkstyle/style.qrc
)

target_include_directories(aero_gui PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src   # so "ethwallet/Wallet.h" resolves
    ${ETHWALLET_DIR}
)

# The version the updater compares against, and the one the About box shows.
#
# This is the project version above, and it has to be: the release zip, the PE FileVersion and the
# number in the signed update manifest all come from that single `project(... VERSION ...)` line, so
# there is no second place to forget to bump. `aero_version()` from the Rust core is the core crate's
# own version and is deliberately NOT used here - the two have drifted before, and the number that
# decides whether to replace the application must not be the one nobody remembers to update.
target_compile_definitions(aero_gui PRIVATE AERO_APP_VERSION="${PROJECT_VERSION}")

# Embed the .ico so the .exe itself shows the Aero logo (Windows only; .rc needs the RC compiler).
if(WIN32)
    set(AERO_RC_DIR ${CMAKE_CURRENT_SOURCE_DIR})
    set(AERO_VERSION ${PROJECT_VERSION})
    set(AERO_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
    set(AERO_VERSION_MINOR ${PROJECT_VERSION_MINOR})
    set(AERO_VERSION_PATCH ${PROJECT_VERSION_PATCH})
    set(AERO_REPO "Aero-Developer/aero")
    configure_file(appicon.rc.in ${CMAKE_CURRENT_BINARY_DIR}/appicon.rc @ONLY)
    target_sources(aero_gui PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/appicon.rc)
endif()

# What an executable says about itself is part of what antivirus heuristics score it on, and a
# GNU-ld default says the wrong things. Left alone it stamps the PE as targeting Windows Server 2003,
# which no legitimate 2026 application does, and leaves the exploit-mitigation bits to chance.
# Declaring Windows 10 and asking for the mitigations by name costs nothing and removes two of the
# cheap signals that push an unsigned binary over a machine-learning threshold.
#
# The subsystem version is NOT the OS version and must not be raised to match it. It is the version
# of the Win32 subsystem the image demands, and the loader refuses outright - 0xc000007b, before a
# single DLL is mapped - any ordinary application that asks for more than 6.2. Windows' own binaries
# carry 10.0 because components of Windows are exempt; ours are not, and 0.1.28 shipped an
# executable that no machine on earth could start. 6.2 is the ceiling, and is what MSVC emits for
# exactly this reason. Anything above it is not "newer", it is unloadable.
if(WIN32 AND (MINGW OR CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang"))
    target_link_options(aero_gui PRIVATE
        -Wl,--major-os-version,10 -Wl,--minor-os-version,0
        -Wl,--major-subsystem-version,6 -Wl,--minor-subsystem-version,2
        -Wl,--dynamicbase        # ASLR
        -Wl,--nxcompat           # DEP
        -Wl,--high-entropy-va    # 64-bit ASLR
    )
endif()

target_link_libraries(aero_gui PRIVATE
    Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Concurrent Qt6::Network
    ${AERO_CORE_LINK}
)

# macOS: build Aero.app with sane bundle metadata; the binary + dylib live in Contents/MacOS and the
# core dylib is found via an @loader_path rpath. (Qt frameworks + Tor are added at package time by
# macdeployqt / ci/package-macos.sh.)
if(APPLE)
    set_target_properties(aero_gui PROPERTIES
        OUTPUT_NAME "Aero"
        MACOSX_BUNDLE_BUNDLE_NAME "Aero"
        MACOSX_BUNDLE_GUI_IDENTIFIER "io.aero.wallet"
        MACOSX_BUNDLE_BUNDLE_VERSION "1.0"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "1.0")
    # Optional app icon: use assets/Aero.icns if present (CI can generate it from the logo PNG).
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/assets/Aero.icns")
        target_sources(aero_gui PRIVATE assets/Aero.icns)
        set_source_files_properties(assets/Aero.icns PROPERTIES
            MACOSX_PACKAGE_LOCATION "Resources")
        set_target_properties(aero_gui PROPERTIES MACOSX_BUNDLE_ICON_FILE "Aero.icns")
    endif()
endif()

# Find the core shared library next to the executable at runtime.
if(APPLE)
    set_target_properties(aero_gui PROPERTIES INSTALL_RPATH "@loader_path")
    set_target_properties(aero_gui PROPERTIES BUILD_WITH_INSTALL_RPATH TRUE)
elseif(NOT WIN32)
    set_target_properties(aero_gui PROPERTIES INSTALL_RPATH "$ORIGIN")
    set_target_properties(aero_gui PROPERTIES BUILD_WITH_INSTALL_RPATH TRUE)
endif()

# Copy the Rust shared library next to the executable so it runs in place.
add_custom_command(TARGET aero_gui POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${AERO_CORE_RUNTIME} $<TARGET_FILE_DIR:aero_gui>/
)

# Checks HistoryModel's swap reconciliation without a wallet, a network or keys. Off by default: it
# is a test, not part of the wallet. Build with -DAERO_BUILD_HISTORY_CHECK=ON and run history_check.
option(AERO_BUILD_HISTORY_CHECK "Build the HistoryModel swap-status check" OFF)
if(AERO_BUILD_HISTORY_CHECK)
    add_executable(history_check
        HistoryCheck.cpp
        ${ETHWALLET_DIR}/HistoryModel.cpp
        ${ETHWALLET_DIR}/HistoryModel.h
    )
    target_include_directories(history_check PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../src
        ${ETHWALLET_DIR}
    )
    target_link_libraries(history_check PRIVATE Qt6::Core Qt6::Gui)
endif()

# Opens the XMR1 trading window on its own against a watch-only wallet, for looking at it while
# working on it. Off by default: it is a development tool, not part of the wallet.
option(AERO_BUILD_XMR_PREVIEW "Build the standalone XMR1 trading-window preview" OFF)
if(AERO_BUILD_XMR_PREVIEW)
    add_executable(xmr_preview
        XmrPreview.cpp
        XmrTradeTab.cpp
        XmrTradeTab.h
        ${ETHWALLET_DIR}/Wallet.cpp
        ${ETHWALLET_DIR}/Wallet.h
        ${ETHWALLET_DIR}/HistoryModel.cpp
        ${ETHWALLET_DIR}/HistoryModel.h
        qdarkstyle/style.qrc
        assets.qrc
    )
    target_include_directories(xmr_preview PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../src
        ${ETHWALLET_DIR}
    )
    target_link_libraries(xmr_preview PRIVATE
        Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Concurrent Qt6::Network
        ${AERO_CORE_LINK}
    )
    add_custom_command(TARGET xmr_preview POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${AERO_CORE_RUNTIME} $<TARGET_FILE_DIR:xmr_preview>/
    )
endif()

# Shows the "new update" dialog without a release behind it, for looking at the wording and layout.
# Off by default: a development tool, and the only build in which the offer dialog can be raised
# without a verified signature.
option(AERO_BUILD_UPDATE_PREVIEW "Build the standalone update-dialog preview" OFF)
if(AERO_BUILD_UPDATE_PREVIEW)
    add_executable(update_preview
        UpdatePreview.cpp
        Updater.cpp
        Updater.h
        qdarkstyle/style.qrc
    )
    target_compile_definitions(update_preview PRIVATE
        AERO_APP_VERSION="${PROJECT_VERSION}"
        AERO_UPDATE_PREVIEW
    )
    target_include_directories(update_preview PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../src
        ${ETHWALLET_DIR}
    )
    target_link_libraries(update_preview PRIVATE
        Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Concurrent Qt6::Network
        ${AERO_CORE_LINK}
    )
    add_custom_command(TARGET update_preview POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${AERO_CORE_RUNTIME} $<TARGET_FILE_DIR:update_preview>/
    )
endif()
