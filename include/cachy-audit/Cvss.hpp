#pragma once

#include <string_view>

namespace cachy_audit::cvss {

/**
 * @brief Computes the base score from a CVSS v3.x vector string, e.g.
 *        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" -> 9.8.
 *        Throws std::invalid_argument on malformed or unsupported vectors.
 */
[[nodiscard]] float base_score(std::string_view vec);

}  // namespace cachy_audit::cvss
