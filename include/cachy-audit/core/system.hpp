#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace cachy_audit::internal {

/**
 * @brief Executes a command and returns its output, one line per entry.
 *        Throws std::runtime_error if the pipe cannot be opened.
 */
[[nodiscard]] std::vector<std::string> exec(std::string_view cmd);

/**
 * @brief Current kernel version without the release suffix, e.g. "7.2.4" for
 *        uname release "7.2.4-3-cachyos".
 */
[[nodiscard]] std::string get_kernel_version();

/** @brief Installed packages via "pacman -Q", one "name version" per entry. */
[[nodiscard]] std::vector<std::string> get_installed_packages();

}  // namespace cachy_audit::internal
