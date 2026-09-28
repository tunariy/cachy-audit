#pragma once

#include <cachy-audit/Package.hpp>

#include <unistd.h>

#include <string>
#include <string_view>

namespace cachy_audit::term {

inline constexpr std::string_view RESET{"\033[0m"};
inline constexpr std::string_view BOLD{"\033[1m"};
inline constexpr std::string_view DIM{"\033[2m"};
inline constexpr std::string_view RED{"\033[31m"};
inline constexpr std::string_view GREEN{"\033[32m"};
inline constexpr std::string_view YELLOW{"\033[33m"};
inline constexpr std::string_view CYAN{"\033[36m"};
inline constexpr std::string_view GRAY{"\033[90m"};
inline constexpr std::string_view BRIGHT_RED{"\033[91m"};
inline constexpr std::string_view BOLD_BRIGHT_RED{"\033[1;91m"};

/** @brief Only emit colors when stdout is an interactive terminal. */
[[nodiscard]] inline bool supports_color() noexcept {
    return ::isatty(STDOUT_FILENO) == 1;
}

/** @brief Display color for a severity; empty when colors are disabled. */
[[nodiscard]] inline std::string_view severity_color(SeverityLevel sev,
                                                     bool enabled) noexcept {
    if (!enabled) return {};
    switch (sev) {
    case SeverityLevel::Critical:
        return BOLD_BRIGHT_RED;
    case SeverityLevel::High:
        return RED;
    case SeverityLevel::Medium:
        return YELLOW;
    case SeverityLevel::Low:
        return CYAN;
    case SeverityLevel::None:
        return GREEN;
    case SeverityLevel::Unknown:
        return GRAY;
    }
    return {};
}

/**
 * @brief Wraps text in an OSC 8 escape so terminals render it as a clickable
 *        link; returns the text unchanged when disabled or the url is empty.
 */
[[nodiscard]] inline std::string hyperlink(std::string_view url, std::string text,
                                           bool enabled) {
    if (!enabled || url.empty()) return text;
    return "\033]8;;" + std::string{url} + "\033\\" + text + "\033]8;;\033\\";
}

}  // namespace cachy_audit::term
