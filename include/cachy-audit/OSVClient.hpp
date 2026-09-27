/**
 * @file OSVClient.hpp
 * @brief Client for the OSV vulnerability database (osv.dev), used for the
 *        kernel packages. Handles OSV's result pagination transparently.
 */

#pragma once

#include "cachy-audit/Package.hpp"
#include "cachy-audit/core/consts.hpp"
#include "cachy-audit/core/curl.hpp"

#include "nlohmann/json.hpp"

#include <algorithm>
#include <span>
#include <string>
#include <vector>

namespace cachy_audit {

using json = nlohmann::json;

/** @brief Queries the OSV API, single or batched, following pagination. */
class OSVClient {
  public:
    /** @brief All known vulns for one package, as a json object with a "vulns" array. */
    [[nodiscard]] json query(const Package& pkg) {
        return json{{"vulns", paged_query(make_payload(pkg))}};
    }

    /**
     * @brief Queries many packages in batches of chunk_size.
     * @return json array parallel to pkgs; each element is an object with a
     *         "vulns" array
     */
    [[nodiscard]] json queryBatch(const std::vector<Package>& pkgs,
                                  std::size_t chunk_size = 200) {
        json results = json::array();

        for (std::size_t i = 0; i < pkgs.size(); i += chunk_size) {
            const auto chunk =
                std::span{pkgs}.subspan(i, std::min(chunk_size, pkgs.size() - i));

            json queries = json::array();
            for (const auto& pkg : chunk)
                queries.push_back(make_payload(pkg));

            auto res = post({{"queries", queries}}, internal::OSV_API_BATCH);
            const auto& batch_results = res["results"];
            for (std::size_t k = 0; k < batch_results.size(); ++k) {
                json vulns = json::array();
                collect_page(batch_results[k], vulns);

                // OSV paginates per query — follow with the single-query endpoint
                auto token = page_token(batch_results[k]);
                for (std::size_t pages = 1; !token.empty() && pages < MAX_PAGES;
                     ++pages) {
                    json body = queries[k];
                    body["page_token"] = token;
                    const auto page = post(body);
                    collect_page(page, vulns);
                    token = page_token(page);
                }

                results.push_back(json{{"vulns", std::move(vulns)}});
            }
        }
        return results;
    }

  private:
    /**
     * @brief OSV serves vulns in pages and may return an empty first page with
     *        just a next_page_token — keep fetching until the token is gone,
     *        bounded by MAX_PAGES so a misbehaving API cannot loop forever.
     */
    [[nodiscard]] json paged_query(json body) {
        json vulns = json::array();
        for (std::size_t pages = 0; pages < MAX_PAGES; ++pages) {
            const auto page = post(body);
            collect_page(page, vulns);
            const auto token = page_token(page);
            if (token.empty()) break;
            body["page_token"] = token;
        }
        return vulns;
    }

    /**
     * @brief Hard cap on pagination, far beyond anything OSV serves today
     *        (the worst kernel sees 5 pages).
     */
    static constexpr std::size_t MAX_PAGES{100};

    /** @brief Appends the "vulns" array of one response page to vulns. */
    static void collect_page(const json& page, json& vulns) {
        if (const auto it = page.find("vulns"); it != page.end() && it->is_array())
            for (const auto& v : *it) vulns.push_back(v);
    }

    /** @brief Extracts "next_page_token" from a response; empty when there is none. */
    [[nodiscard]] static std::string page_token(const json& page) {
        if (const auto it = page.find("next_page_token");
            it != page.end() && it->is_string())
            return it->get<std::string>();
        return {};
    }

    /**
     * @brief OSV query body for a package; kernels map to the "Kernel"/"Linux"
     *        ecosystem with the running kernel's version.
     */
    [[nodiscard]] static json make_payload(const Package& pkg) {
        if (is_kernel_pkg(pkg)) {
            return {{"package",
                     {{"name", std::string{internal::KERNEL_OSV_NAME}},
                      {"ecosystem", std::string{internal::KERNEL_ECOSYSTEM}}}},
                    {"version", internal::get_kernel_version()}};
        }

        return {{"package", {{"name", pkg.name}}},
                {"version", split_upstream_version(pkg.version)}};
    }

    /**
     * @brief POSTs a json body and parses the json response.
     *        Throws std::runtime_error on transport/HTTP errors.
     */
    [[nodiscard]] json post(const json& body,
                            std::string_view url = internal::OSV_API_BASE) {
        network::Slist headers{};
        headers.append("Content-Type: application/json")
            .append("User-Agent: " + std::string{internal::USER_AGENT});

        auto payload = body.dump();
        return json::parse(m_Curl.query(std::string{url}, headers.get(), payload));
    }

    network::Curl m_Curl{};
};

}  // namespace cachy_audit
