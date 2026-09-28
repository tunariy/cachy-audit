#pragma once

#include <string_view>

namespace cachy_audit::alpm {

/**
 * @brief Compares two package versions in [epoch:]upstream[-pkgrel] form,
 *        following libalpm's alpm_pkg_vercmp.
 * @return <0 if a is older, 0 if equal, >0 if a is newer
 */
[[nodiscard]] int vercmp(std::string_view a, std::string_view b) noexcept;

}  // namespace cachy_audit::alpm
