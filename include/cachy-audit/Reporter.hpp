#pragma once

#include "cachy-audit/Package.hpp"

#include <cstddef>
#include <iosfwd>
#include <vector>

namespace cachy_audit {

/**
 * @brief Prints the findings grouped per package, worst first, with
 *        severity-colored badges, followed by a summary line. findings are
 *        sorted in place.
 */
void print_report(std::ostream& os, std::vector<PackageFinding> findings,
                  std::size_t packages_scanned, bool color);

}  // namespace cachy_audit
