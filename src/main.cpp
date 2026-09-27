/**
 * @file main.cpp
 * @brief Entry point: collect installed packages, query the CVE databases,
 *        print a colored report.
 */

#include <cachy-audit/CveQuerier.hpp>
#include <cachy-audit/Reporter.hpp>
#include <cachy-audit/core/color.hpp>
#include <cachy-audit/core/system.hpp>
#include <cachy-audit/core/util.hpp>

#include <cstdlib>
#include <exception>
#include <iostream>
#include <vector>

namespace {

/** @brief Installed packages via pacman. */
[[nodiscard]] std::vector<cachy_audit::Package> collect_installed_packages() {
    std::vector<cachy_audit::Package> packages{};
    for (const auto& line : cachy_audit::internal::get_installed_packages()) {
        auto [name, version] = cachy_audit::split_by_space(line);
        if (!name.empty()) packages.emplace_back(std::move(name), std::move(version));
    }
    return packages;
}

}  // namespace

/**
 * @brief Program entry point.
 * @return EXIT_SUCCESS on a completed scan (even when CVEs were found),
 *         EXIT_FAILURE on errors
 */
int main() {
    try {
        const auto packages = collect_installed_packages();
        std::clog << "Scanning " << packages.size() << " installed packages...\n";

        cachy_audit::CveQuerier querier{};
        auto findings = querier.query(packages);

        cachy_audit::print_report(std::cout, std::move(findings), packages.size(),
                                  cachy_audit::term::supports_color());
        return EXIT_SUCCESS;
    } catch (const std::exception& e) {
        std::cerr << "cachy-audit: error: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
}
