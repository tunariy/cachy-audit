/**
 * @file system.hpp
 * @brief OS interaction helpers: running shell commands and reading package
 *        and kernel information.
 */

#pragma once

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <sys/utsname.h>

namespace cachy_audit::internal {

/**
 * @brief Executes a command and returns its output, one line per entry.
 *        Throws std::runtime_error if the pipe cannot be opened.
 */
[[nodiscard]] inline std::vector<std::string> exec(std::string_view cmd) {
    std::vector<std::string> lines;
    lines.reserve(10);

    /** @brief Closes the pipe with pclose. */
    struct PipeDeleter {
        void operator()(FILE* f) const {
            if (f != nullptr) pclose(f);
        }
    };
    // popen needs a null-terminated string, string_view does not guarantee one
    const std::unique_ptr<FILE, PipeDeleter> pipe{popen(std::string{cmd}.c_str(), "r")};

    if (!pipe)
        throw std::runtime_error{std::string{"Failed to open a pipe to stdout: "} +
                                 std::strerror(errno)};

    std::array<char, 256> buffer{};
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe.get()) != nullptr) {
        std::string line{buffer.data()};

        if (!line.empty() && line.back() == '\n')
            line.pop_back();  // Remove trailing newline
        lines.push_back(std::move(line));
    }

    return lines;
}

/**
 * @brief Current kernel version without the release suffix, e.g. "7.2.4" for
 *        uname release "7.2.4-3-cachyos".
 */
[[nodiscard]] inline std::string get_kernel_version() {
    utsname u{};
    uname(&u);
    std::string v{u.release};
    if (const auto pos = v.find('-'); pos != std::string::npos) v.erase(pos);
    return v;
}

/** @brief Installed packages via "pacman -Q", one "name version" per entry. */
[[nodiscard]] inline std::vector<std::string> get_installed_packages() {
    return exec("pacman -Q");
}

}  // namespace cachy_audit::internal
