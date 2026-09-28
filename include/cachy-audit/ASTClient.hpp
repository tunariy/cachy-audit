#pragma once

#include "cachy-audit/Package.hpp"
#include "cachy-audit/core/curl.hpp"

#include "nlohmann/json.hpp"

#include <string>
#include <unordered_map>
#include <vector>

namespace cachy_audit {

using json = nlohmann::json;

/** @brief Queries the Arch Security Tracker for package issues. */
class ASTClient {
  public:
    /**
     * @brief Looks packages up in the issue dump (downloaded lazily on first call).
     * @return json array parallel to pkgs; an element is either null (no
     *         issues) or an object with an "issues" array of AST issue entries
     */
    [[nodiscard]] json queryBatch(const std::vector<Package>& pkgs);

  private:
    /** @brief Downloads and indexes the issue dump if that has not happened yet. */
    void ensure_dump();

    network::Curl m_Curl{};
    json m_Dump{};
    std::unordered_map<std::string, json> m_Index{}; /**< package -> issues */
};

}  // namespace cachy_audit
