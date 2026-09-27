/**
 * @file vercmp.hpp
 * @brief Package version comparison compatible with libalpm (pacman).
 */

#pragma once

#include <algorithm>
#include <string_view>
#include <utility>

namespace cachy_audit::alpm {

namespace detail {

    [[nodiscard]] constexpr bool is_alnum(char c) noexcept {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
               (c >= 'A' && c <= 'Z');
    }

    [[nodiscard]] constexpr bool is_digit(char c) noexcept {
        return c >= '0' && c <= '9';
    }

    /**
     * @brief rpmvercmp as used by libalpm: compares the upstream-version or
     *        pkgrel part of two package versions, segment by segment.
     */
    [[nodiscard]] inline int rpmvercmp(std::string_view a,
                                       std::string_view b) noexcept {
        if (a == b) return 0;

        std::size_t i = 0, j = 0;
        while (i < a.size() && j < b.size()) {
            // separators are insignificant
            while (i < a.size() && !is_alnum(a[i])) ++i;
            while (j < b.size() && !is_alnum(b[j])) ++j;
            if (i >= a.size() || j >= b.size()) break;

            const bool num_a = is_digit(a[i]);
            const bool num_b = is_digit(b[j]);

            std::size_t s = i;
            i = num_a ? a.find_first_not_of("0123456789", i)
                      : a.find_first_not_of(
                            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", i);
            if (i == std::string_view::npos) i = a.size();
            auto seg_a = a.substr(s, i - s);

            s = j;
            j = num_b ? b.find_first_not_of("0123456789", j)
                      : b.find_first_not_of(
                            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", j);
            if (j == std::string_view::npos) j = b.size();
            auto seg_b = b.substr(s, j - s);

            // a numeric segment always beats an alphabetic one
            if (num_a != num_b) return num_a ? 1 : -1;

            if (num_a) {
                // strip leading zeros, then the longer number wins
                seg_a.remove_prefix(
                    std::min(seg_a.find_first_not_of('0'), seg_a.size()));
                seg_b.remove_prefix(
                    std::min(seg_b.find_first_not_of('0'), seg_b.size()));
                if (seg_a.size() != seg_b.size())
                    return seg_a.size() < seg_b.size() ? -1 : 1;
            }
            if (const auto cmp = seg_a.compare(seg_b); cmp != 0)
                return cmp < 0 ? -1 : 1;
        }

        // whichever side still has alphanumeric data left over is newer
        if (i < a.size() && j >= b.size()) return 1;
        if (i >= a.size() && j < b.size()) return -1;
        return 0;
    }

    /** @brief Parses and strips a leading "epoch:" prefix; 0 when there is none. */
    [[nodiscard]] constexpr long parse_epoch(std::string_view& v) noexcept {
        const auto colon = v.find(':');
        if (colon == std::string_view::npos || colon == 0) return 0;
        long epoch = 0;
        for (std::size_t k = 0; k < colon; ++k) {
            if (!is_digit(v[k])) return 0;
            epoch = epoch * 10 + (v[k] - '0');
        }
        v.remove_prefix(colon + 1);
        return epoch;
    }

}  // namespace detail

/**
 * @brief Compares two package versions in [epoch:]upstream[-pkgrel] form,
 *        following libalpm's alpm_pkg_vercmp.
 * @return <0 if a is older, 0 if equal, >0 if a is newer
 */
[[nodiscard]] inline int vercmp(std::string_view a, std::string_view b) noexcept {
    if (a == b) return 0;

    const long epoch_a = detail::parse_epoch(a);
    const long epoch_b = detail::parse_epoch(b);
    if (epoch_a != epoch_b) return epoch_a < epoch_b ? -1 : 1;

    const auto split_rel = [](std::string_view v) {
        if (const auto dash = v.rfind('-'); dash != std::string_view::npos)
            return std::pair{v.substr(0, dash), v.substr(dash + 1)};
        return std::pair{v, std::string_view{}};
    };
    const auto [ver_a, rel_a] = split_rel(a);
    const auto [ver_b, rel_b] = split_rel(b);

    if (const int r = detail::rpmvercmp(ver_a, ver_b); r != 0) return r;
    if (!rel_a.empty() && !rel_b.empty()) return detail::rpmvercmp(rel_a, rel_b);
    return 0;
}

}  // namespace cachy_audit::alpm
