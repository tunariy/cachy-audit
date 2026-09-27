/**
 * @file Cvss.hpp
 * @brief Parser for CVSS v3.x vector strings, computing the base score per the
 *        official specification.
 */

#pragma once

#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>

namespace cachy_audit::cvss {

namespace detail {

    /** @brief Official CVSS v3.x rounding: round up to one decimal. */
    [[nodiscard]] inline float roundup(float x) noexcept {
        const auto scaled = std::lround(x * 100000.0F);
        if (scaled % 10000 == 0) return static_cast<float>(scaled) / 100000.0F;
        return static_cast<float>(scaled / 10000 + 1) / 10.0F;
    }

    // Metric weight tables from the CVSS v3.x specification.

    [[nodiscard]] inline float av_value(char v) {
        switch (v) {
            case 'N': return 0.85F;
            case 'A': return 0.62F;
            case 'L': return 0.55F;
            case 'P': return 0.20F;
            default: throw std::invalid_argument{"CVSS: invalid AV metric"};
        }
    }

    [[nodiscard]] inline float ac_value(char v) {
        switch (v) {
            case 'L': return 0.77F;
            case 'H': return 0.44F;
            default: throw std::invalid_argument{"CVSS: invalid AC metric"};
        }
    }

    [[nodiscard]] inline float pr_value(char v, bool scope_changed) {
        switch (v) {
            case 'N': return 0.85F;
            case 'L': return scope_changed ? 0.68F : 0.62F;
            case 'H': return scope_changed ? 0.50F : 0.27F;
            default: throw std::invalid_argument{"CVSS: invalid PR metric"};
        }
    }

    [[nodiscard]] inline float ui_value(char v) {
        switch (v) {
            case 'N': return 0.85F;
            case 'R': return 0.62F;
            default: throw std::invalid_argument{"CVSS: invalid UI metric"};
        }
    }

    [[nodiscard]] inline float cia_value(char v) {
        switch (v) {
            case 'H': return 0.56F;
            case 'L': return 0.22F;
            case 'N': return 0.0F;
            default: throw std::invalid_argument{"CVSS: invalid C/I/A metric"};
        }
    }

}  // namespace detail

/**
 * @brief Computes the base score from a CVSS v3.x vector string, e.g.
 *        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" -> 9.8.
 *        Throws std::invalid_argument on malformed or unsupported vectors.
 */
[[nodiscard]] inline float base_score(std::string_view vec) {
    if (!vec.starts_with("CVSS:3."))
        throw std::invalid_argument{"Unsupported CVSS vector: " + std::string{vec}};

    std::unordered_map<std::string_view, std::string_view> metrics{};
    std::size_t pos = 0;
    while (pos <= vec.size()) {
        const auto slash = vec.find('/', pos);
        const auto token = vec.substr(
            pos, slash == std::string_view::npos ? std::string_view::npos : slash - pos);
        if (const auto colon = token.find(':');
            colon != std::string_view::npos && !token.starts_with("CVSS"))
            metrics[token.substr(0, colon)] = token.substr(colon + 1);
        if (slash == std::string_view::npos) break;
        pos = slash + 1;
    }

    const auto metric = [&metrics](std::string_view key) {
        const auto it = metrics.find(key);
        if (it == metrics.end() || it->second.size() != 1)
            throw std::invalid_argument{"CVSS vector missing metric: " +
                                        std::string{key}};
        return it->second.front();
    };

    const bool scope_changed = metric("S") == 'C';

    const float av = detail::av_value(metric("AV"));
    const float ac = detail::ac_value(metric("AC"));
    const float pr = detail::pr_value(metric("PR"), scope_changed);
    const float ui = detail::ui_value(metric("UI"));
    const float c = detail::cia_value(metric("C"));
    const float i = detail::cia_value(metric("I"));
    const float a = detail::cia_value(metric("A"));

    const float isc = 1.0F - (1.0F - c) * (1.0F - i) * (1.0F - a);
    const float impact =
        scope_changed
            ? 7.52F * (isc - 0.029F) - 3.25F * std::pow(isc - 0.02F, 15.0F)
            : 6.42F * isc;
    const float exploitability = 8.22F * av * ac * pr * ui;

    if (impact <= 0.0F) return 0.0F;

    const float score =
        scope_changed ? std::min(1.08F * (impact + exploitability), 10.0F)
                      : std::min(impact + exploitability, 10.0F);
    return detail::roundup(score);
}

}  // namespace cachy_audit::cvss
