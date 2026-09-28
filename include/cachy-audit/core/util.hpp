#pragma once

#include <string>
#include <string_view>
#include <utility>

namespace cachy_audit {

/**
 * @brief Splits a "name version" line (from pacman -Q) at the first space;
 *        returns {str, ""} when there is no space.
 */
[[nodiscard]] inline std::pair<std::string, std::string>
split_by_space(std::string_view str) {
    const auto pos = str.find(' ');
    if (pos == std::string_view::npos) return {std::string{str}, {}};
    return {std::string{str.substr(0, pos)}, std::string{str.substr(pos + 1)}};
}

/** @brief Strips the pacman epoch and pkgrel: "1:2.14-1.1" -> "2.14". */
[[nodiscard]] inline std::string split_upstream_version(std::string ver) {
    if (const auto pos = ver.find(':'); pos != std::string::npos) ver.erase(0, pos + 1);
    if (const auto pos = ver.rfind('-'); pos != std::string::npos) ver.erase(pos);
    return ver;
}

}  // namespace cachy_audit
