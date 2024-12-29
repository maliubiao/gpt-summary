Response:
The user wants a summary of the functionality of the `net/dns/host_cache.cc` file in Chromium's networking stack. They are particularly interested in:

1. **Functionality of the file:** What does this code do?
2. **Relationship with JavaScript:** Does this code interact with JavaScript in any way?
3. **Logic and Input/Output:** Can we infer the logic by examining the code and provide hypothetical inputs and outputs?
4. **Common User/Programming Errors:** What are some common mistakes related to this code?
5. **User Path to this Code:** How does a user's actions eventually lead to this code being executed? (Debugging context)
6. **Summary of Functionality (Part 1):**  A concise overview based on the provided code snippet.

**Plan:**

1. **Analyze the Includes and Namespaces:** Identify the core components this code interacts with (DNS, networking, caching).
2. **Examine the `HostCache` Class:** Understand its purpose and key methods (Lookup, Set, Invalidate, etc.).
3. **Examine the `Key` and `Entry` Classes:** Understand what data is stored and how it's structured.
4. **Identify Functionality related to DNS Caching:**  Focus on how hostnames are resolved and the results are stored.
5. **Consider JavaScript Interaction:** Think about where DNS resolution might be triggered by the browser's JavaScript engine.
6. **Infer Logic and Provide Examples:** Based on the methods and data structures, create hypothetical scenarios.
7. **Consider Potential Errors:** Think about common pitfalls related to caching and DNS.
8. **Trace User Actions:**  Outline a possible user journey that involves DNS resolution.
9. **Summarize the Functionality:**  Condense the findings into a concise summary for Part 1.
```
这是目录为net/dns/host_cache.cc的chromium 网络栈的源代码文件， 请列举一下它的功能,
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

**`net/dns/host_cache.cc` 的功能:**

这个文件实现了 Chromium 网络栈中的 **DNS 缓存 (Host Cache)** 功能。 它的主要职责是：

1. **存储 DNS 查询结果:**  缓存主机名（hostname）到其对应的 IP 地址（或其他 DNS 记录）的映射关系，以减少重复的 DNS 查询，提高网络访问速度和效率。
2. **管理缓存条目:**  负责缓存条目的添加、查找、更新和删除。
3. **处理缓存过期:**  根据 DNS 记录的 TTL (Time To Live) 值，管理缓存条目的有效期，并在过期后进行刷新或移除。
4. **支持不同的查询类型:**  缓存不同类型的 DNS 查询结果，例如 A 记录 (IPv4 地址)、AAAA 记录 (IPv6 地址)、HTTPS 记录等。
5. **考虑安全性和隐私:**  可能支持区分安全（HTTPS）和非安全（HTTP）的缓存条目，并处理与网络匿名化相关的键。
6. **提供性能指标:**  记录缓存的命中率、过期率等，用于性能分析和优化。
7. **支持持久化 (可选):**  允许将缓存内容持久化到磁盘，以便在 Chromium 重启后恢复缓存状态 (这部分可能在其他相关文件中实现，但 `host_cache.cc` 提供了与持久化相关的接口 `PersistenceDelegate`)。
8. **处理网络状态变化:** 当网络状态发生变化时，可能需要使部分或全部缓存失效。
9. **支持主机解析器的不同来源:**  区分来自不同 HostResolverSource 的缓存条目。

**与 JavaScript 的关系 (举例说明):**

JavaScript 代码本身不能直接访问或操作这个 C++ 实现的 DNS 缓存。 但是，当 JavaScript 发起网络请求时，例如通过 `fetch()` API 或 `<script>` 标签加载资源时，Chromium 浏览器会进行以下步骤，其中会涉及到 DNS 缓存：

1. **JavaScript 发起请求:** JavaScript 代码调用 `fetch('https://example.com/data.json')`。
2. **浏览器解析 URL:** 浏览器解析 URL，提取出主机名 `example.com`。
3. **DNS 查询 (可能需要):**  浏览器首先会检查 DNS 缓存中是否已经存在 `example.com` 的对应 IP 地址。
    *   **缓存命中:** 如果缓存中存在有效的条目，浏览器直接使用缓存的 IP 地址，跳过实际的 DNS 查询，加速连接建立。
    *   **缓存未命中或已过期:** 如果缓存中不存在或已过期，浏览器会发起 DNS 查询请求操作系统或配置的 DNS 服务器。
4. **连接建立:**  获取到 IP 地址后，浏览器会建立 TCP 连接，并进行后续的 TLS 握手 (如果是 HTTPS)。

**假设输入与输出 (逻辑推理):**

**假设输入:**

*   **Lookup 请求:**  `HostCache::Lookup(Key("example.com", DNS_QUERY_TYPE_A, ...), now)`，请求查找主机名 "example.com" 的 A 记录。
*   **缓存状态:** 假设缓存中存在一个针对 "example.com" 的 A 记录条目，其 IP 地址为 `93.184.216.34`，TTL 剩余 60 秒。
*   **当前时间:** `now` 是当前的时间戳。

**可能输出:**

*   如果当前时间在缓存条目的有效期内 (TTL 尚未过期)，`Lookup` 方法会返回一个指向缓存条目的指针，其中包含 IP 地址 `93.184.216.34` 和剩余 TTL。
*   如果当前时间超过了缓存条目的有效期，`Lookup` 方法可能会返回 `nullptr` (或根据实现返回一个标记为过期的条目，并可能触发后台 DNS 刷新)。

**涉及用户或编程常见的使用错误 (举例说明):**

1. **误解缓存行为:** 开发者可能会错误地认为 DNS 缓存是完全可靠和实时的。例如，在 DNS 记录更新后，旧的缓存条目仍然会生效一段时间，导致连接到旧的 IP 地址。
2. **过度依赖缓存:**  在某些对实时性要求很高的应用中，过度依赖 DNS 缓存可能会导致问题。例如，当一个服务迁移到新的 IP 地址后，客户端由于缓存可能仍然连接到旧的地址。
3. **不当的缓存清理:**  在某些情况下，可能需要手动清理 DNS 缓存，例如在网络配置更改后。用户或开发者可能不知道如何正确地清理缓存，导致连接问题。在 Chromium 中，可以通过访问 `chrome://net-internals/#dns` 来清除 DNS 缓存。
4. **编程错误导致缓存污染:**  虽然 `host_cache.cc` 是底层实现，但上层调用代码的错误逻辑可能会导致将错误的 DNS 结果写入缓存，从而影响后续的网络请求。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在地址栏输入 URL 或点击链接:**  例如，用户输入 `https://www.example.com` 并按下回车。
2. **浏览器发起导航:** 浏览器开始处理导航请求。
3. **获取主机名:** 浏览器从 URL 中提取主机名 `www.example.com`。
4. **HostResolver 调用:**  网络栈中的 `HostResolver` 组件会被调用，负责将主机名解析为 IP 地址。
5. **HostCache 查询:** `HostResolver` 在执行实际的 DNS 查询之前，会先查询 `HostCache`。
6. **`HostCache::Lookup()` 被调用:**  如果需要查询 `www.example.com` 的 IP 地址，`HostCache::Lookup()` 方法会被调用，以检查缓存中是否存在相应的条目。
7. **后续处理:** 根据 `Lookup()` 的结果，可能会直接使用缓存的 IP 地址，或者发起实际的 DNS 查询。

**作为调试线索:**  当用户遇到网络连接问题，例如无法访问某个网站时，检查 DNS 缓存状态是一个重要的调试步骤。通过 `chrome://net-internals/#dns` 可以查看当前缓存的内容，判断是否是由于缓存了错误的或过期的 DNS 记录导致的。

**归纳一下它的功能 (第1部分):**

在提供的代码片段中，`net/dns/host_cache.cc` 的主要功能是 **定义了 DNS 缓存的数据结构和核心操作接口**。 它定义了 `HostCache` 类，用于存储和管理 DNS 查询结果的缓存条目。 关键的组成部分包括：

*   **`HostCache::Key`:**  定义了缓存条目的唯一标识符，包括主机名、查询类型、标记和网络匿名化密钥等。
*   **`HostCache::Entry`:** 定义了缓存条目的内容，包括 IP 地址、别名、TTL、错误信息、来源等。
*   **`HostCache` 类:**  提供了缓存的查找 (`Lookup`, `LookupStale`), 设置 (`Set`), 失效 (`Invalidate`), 清理 (`clear`, `ClearForHosts`) 等核心方法。

这段代码还包含了用于序列化和反序列化缓存条目的方法，以及用于记录缓存操作相关的 NetLog 信息和性能指标的机制。  它初步构建了一个高效的、可管理的 DNS 缓存框架。

Prompt: 
```
这是目录为net/dns/host_cache.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/host_cache.h"

#include <algorithm>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <set>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <vector>

#include "base/check_op.h"
#include "base/containers/contains.h"
#include "base/functional/bind.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/histogram_functions_internal_overloads.h"
#include "base/metrics/histogram_macros.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/string_number_conversions.h"
#include "base/time/default_tick_clock.h"
#include "base/types/optional_util.h"
#include "base/value_iterators.h"
#include "net/base/address_family.h"
#include "net/base/ip_endpoint.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/trace_constants.h"
#include "net/base/tracing.h"
#include "net/base/url_util.h"
#include "net/dns/host_resolver.h"
#include "net/dns/host_resolver_internal_result.h"
#include "net/dns/https_record_rdata.h"
#include "net/dns/public/dns_protocol.h"
#include "net/dns/public/host_resolver_source.h"
#include "net/log/net_log.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "url/scheme_host_port.h"

namespace net {

namespace {

// String constants for dictionary keys.
const char kSchemeKey[] = "scheme";
const char kHostnameKey[] = "hostname";
const char kPortKey[] = "port";
const char kDnsQueryTypeKey[] = "dns_query_type";
const char kFlagsKey[] = "flags";
const char kHostResolverSourceKey[] = "host_resolver_source";
const char kSecureKey[] = "secure";
const char kNetworkAnonymizationKey[] = "network_anonymization_key";
const char kExpirationKey[] = "expiration";
const char kTtlKey[] = "ttl";
const char kPinnedKey[] = "pinned";
const char kNetworkChangesKey[] = "network_changes";
const char kNetErrorKey[] = "net_error";
const char kIpEndpointsKey[] = "ip_endpoints";
const char kEndpointAddressKey[] = "endpoint_address";
const char kEndpointPortKey[] = "endpoint_port";
const char kEndpointMetadatasKey[] = "endpoint_metadatas";
const char kEndpointMetadataWeightKey[] = "endpoint_metadata_weight";
const char kEndpointMetadataValueKey[] = "endpoint_metadata_value";
const char kAliasesKey[] = "aliases";
const char kAddressesKey[] = "addresses";
const char kTextRecordsKey[] = "text_records";
const char kHostnameResultsKey[] = "hostname_results";
const char kHostPortsKey[] = "host_ports";
const char kCanonicalNamesKey[] = "canonical_names";

base::Value IpEndpointToValue(const IPEndPoint& endpoint) {
  base::Value::Dict dictionary;
  dictionary.Set(kEndpointAddressKey, endpoint.ToStringWithoutPort());
  dictionary.Set(kEndpointPortKey, endpoint.port());
  return base::Value(std::move(dictionary));
}

std::optional<IPEndPoint> IpEndpointFromValue(const base::Value& value) {
  if (!value.is_dict())
    return std::nullopt;

  const base::Value::Dict& dict = value.GetDict();
  const std::string* ip_str = dict.FindString(kEndpointAddressKey);
  std::optional<int> port = dict.FindInt(kEndpointPortKey);

  if (!ip_str || !port ||
      !base::IsValueInRangeForNumericType<uint16_t>(port.value())) {
    return std::nullopt;
  }

  IPAddress ip;
  if (!ip.AssignFromIPLiteral(*ip_str))
    return std::nullopt;

  return IPEndPoint(ip, base::checked_cast<uint16_t>(port.value()));
}

base::Value EndpointMetadataPairToValue(
    const std::pair<HttpsRecordPriority, ConnectionEndpointMetadata>& pair) {
  base::Value::Dict dictionary;
  dictionary.Set(kEndpointMetadataWeightKey, pair.first);
  dictionary.Set(kEndpointMetadataValueKey, pair.second.ToValue());
  return base::Value(std::move(dictionary));
}

std::optional<std::pair<HttpsRecordPriority, ConnectionEndpointMetadata>>
EndpointMetadataPairFromValue(const base::Value& value) {
  if (!value.is_dict())
    return std::nullopt;

  const base::Value::Dict& dict = value.GetDict();
  std::optional<int> priority = dict.FindInt(kEndpointMetadataWeightKey);
  const base::Value* metadata_value = dict.Find(kEndpointMetadataValueKey);

  if (!priority || !base::IsValueInRangeForNumericType<HttpsRecordPriority>(
                       priority.value())) {
    return std::nullopt;
  }

  if (!metadata_value)
    return std::nullopt;
  std::optional<ConnectionEndpointMetadata> metadata =
      ConnectionEndpointMetadata::FromValue(*metadata_value);
  if (!metadata)
    return std::nullopt;

  return std::pair(base::checked_cast<HttpsRecordPriority>(priority.value()),
                   std::move(metadata).value());
}

bool IPEndPointsFromLegacyAddressListValue(
    const base::Value::List& value,
    std::vector<IPEndPoint>& ip_endpoints) {
  DCHECK(ip_endpoints.empty());
  for (const auto& it : value) {
    IPAddress address;
    const std::string* addr_string = it.GetIfString();
    if (!addr_string || !address.AssignFromIPLiteral(*addr_string)) {
      return false;
    }
    ip_endpoints.emplace_back(address, 0);
  }
  return true;
}

template <typename T>
void MergeLists(T& target, const T& source) {
  target.insert(target.end(), source.begin(), source.end());
}

template <typename T>
void MergeContainers(T& target, const T& source) {
  target.insert(source.begin(), source.end());
}

// Used to reject empty and IP literal (whether or not surrounded by brackets)
// hostnames.
bool IsValidHostname(std::string_view hostname) {
  if (hostname.empty())
    return false;

  IPAddress ip_address;
  if (ip_address.AssignFromIPLiteral(hostname) ||
      ParseURLHostnameToAddress(hostname, &ip_address)) {
    return false;
  }

  return true;
}

const std::string& GetHostname(
    const absl::variant<url::SchemeHostPort, std::string>& host) {
  const std::string* hostname;
  if (absl::holds_alternative<url::SchemeHostPort>(host)) {
    hostname = &absl::get<url::SchemeHostPort>(host).host();
  } else {
    DCHECK(absl::holds_alternative<std::string>(host));
    hostname = &absl::get<std::string>(host);
  }

  DCHECK(IsValidHostname(*hostname));
  return *hostname;
}

std::optional<DnsQueryType> GetDnsQueryType(int dns_query_type) {
  for (const auto& type : kDnsQueryTypes) {
    if (base::strict_cast<int>(type.first) == dns_query_type)
      return type.first;
  }
  return std::nullopt;
}

const std::string GetHistogramName(std::string_view histogram_name,
                                   const HostCache::Key& key) {
  constexpr std::string_view kHistogramPrefix = "Net.DNS.HostCache.";

  return base::StrCat(
      {kHistogramPrefix, histogram_name,
       IsGoogleHostWithAlpnH3(GetHostname(key.host)) ? ".GoogleHost" : ""});
}

}  // namespace

// Used in histograms; do not modify existing values.
enum HostCache::SetOutcome : int {
  SET_INSERT = 0,
  SET_UPDATE_VALID = 1,
  SET_UPDATE_STALE = 2,
  MAX_SET_OUTCOME
};

HostCache::Key::Key(absl::variant<url::SchemeHostPort, std::string> host,
                    DnsQueryType dns_query_type,
                    HostResolverFlags host_resolver_flags,
                    HostResolverSource host_resolver_source,
                    const NetworkAnonymizationKey& network_anonymization_key)
    : host(std::move(host)),
      dns_query_type(dns_query_type),
      host_resolver_flags(host_resolver_flags),
      host_resolver_source(host_resolver_source),
      network_anonymization_key(network_anonymization_key) {
  DCHECK(IsValidHostname(GetHostname(this->host)));
  if (absl::holds_alternative<url::SchemeHostPort>(this->host))
    DCHECK(absl::get<url::SchemeHostPort>(this->host).IsValid());
}

HostCache::Key::Key() = default;
HostCache::Key::Key(const Key& key) = default;
HostCache::Key::Key(Key&& key) = default;

HostCache::Key::~Key() = default;

HostCache::Entry::Entry(int error,
                        Source source,
                        std::optional<base::TimeDelta> ttl)
    : error_(error), source_(source), ttl_(ttl.value_or(kUnknownTtl)) {
  // If |ttl| has a value, must not be negative.
  DCHECK_GE(ttl.value_or(base::TimeDelta()), base::TimeDelta());
  DCHECK_NE(OK, error_);

  // host_cache.h defines its own `HttpsRecordPriority` due to
  // https_record_rdata.h not being allowed in the same places, but the types
  // should still be the same thing.
  static_assert(std::is_same<net::HttpsRecordPriority,
                             HostCache::Entry::HttpsRecordPriority>::value,
                "`net::HttpsRecordPriority` and "
                "`HostCache::Entry::HttpsRecordPriority` must be same type");
}

HostCache::Entry::Entry(
    const std::set<std::unique_ptr<HostResolverInternalResult>>& results,
    base::Time now,
    base::TimeTicks now_ticks,
    Source empty_source) {
  std::vector<const HostResolverInternalResult*> data_results;
  const HostResolverInternalResult* metadata_result = nullptr;
  std::vector<const HostResolverInternalResult*> error_results;
  std::vector<const HostResolverInternalResult*> alias_results;

  std::optional<base::TimeDelta> smallest_ttl =
      TtlFromInternalResults(results, now, now_ticks);
  std::optional<Source> source;
  for (const std::unique_ptr<HostResolverInternalResult>& result : results) {
    Source result_source;
    switch (result->source()) {
      case HostResolverInternalResult::Source::kDns:
        result_source = SOURCE_DNS;
        break;
      case HostResolverInternalResult::Source::kHosts:
        result_source = SOURCE_HOSTS;
        break;
      case HostResolverInternalResult::Source::kUnknown:
        result_source = SOURCE_UNKNOWN;
        break;
    }

    switch (result->type()) {
      case HostResolverInternalResult::Type::kData:
        if (!result->AsData().endpoints().empty() &&
            result->AsData().endpoints().front().GetFamily() ==
                ADDRESS_FAMILY_IPV6) {
          // If a data result contains IPv6 addresses, put it at the front to
          // ensure we generally keep IPv6 addresses sorted before IPv4
          // addresses.
          data_results.insert(data_results.begin(), result.get());
        } else {
          data_results.push_back(result.get());
        }
        break;
      case HostResolverInternalResult::Type::kMetadata:
        DCHECK(!metadata_result);  // Expect at most one metadata result.
        metadata_result = result.get();
        break;
      case HostResolverInternalResult::Type::kError:
        error_results.push_back(result.get());
        break;
      case HostResolverInternalResult::Type::kAlias:
        alias_results.push_back(result.get());
        break;
    }

    // Expect all results to have the same source.
    DCHECK(!source.has_value() || source.value() == result_source);
    source = result_source;
  }

  ttl_ = smallest_ttl.value_or(kUnknownTtl);
  source_ = source.value_or(empty_source);

  if (!data_results.empty() || metadata_result) {
    error_ = OK;

    // Any errors should be an ignorable ERR_NAME_NOT_RESOLVED from a single
    // transaction.
    CHECK(base::ranges::all_of(
        error_results, [](const HostResolverInternalResult* error_result) {
          return error_result->query_type() != DnsQueryType::UNSPECIFIED &&
                 error_result->AsError().error() == ERR_NAME_NOT_RESOLVED;
        }));
  } else if (!error_results.empty()) {
    error_ = ERR_NAME_NOT_RESOLVED;
    bool any_error_cacheable = false;
    for (const HostResolverInternalResult* error_result : error_results) {
      if (error_result->expiration().has_value() ||
          error_result->timed_expiration().has_value()) {
        any_error_cacheable = true;
      }

      if (error_result->AsError().error() != ERR_NAME_NOT_RESOLVED ||
          error_result->query_type() == DnsQueryType::UNSPECIFIED) {
        // If not just a single-transaction ERR_NAME_NOT_RESOLVED, the error is
        // an actual failure. Expected to then be the only error result.
        CHECK_EQ(error_results.size(), 1u);

        error_ = error_result->AsError().error();
      }
    }

    // Must get at least one TTL from an error result, not e.g. alias results,
    // for an error to overall be cacheable.
    if (!any_error_cacheable) {
      ttl_ = kUnknownTtl;
    }
  } else {
    // Only alias results (or completely empty results). Never cacheable due to
    // being equivalent to an error result without TTL.
    error_ = ERR_NAME_NOT_RESOLVED;
    ttl_ = kUnknownTtl;
  }

  if (!data_results.empty()) {
    for (const HostResolverInternalResult* data_result : data_results) {
      DCHECK(!data_result->AsData().endpoints().empty() ||
             !data_result->AsData().strings().empty() ||
             !data_result->AsData().hosts().empty());
      // Data results should always be cacheable.
      DCHECK(data_result->expiration().has_value() ||
             data_result->timed_expiration().has_value());

      MergeLists(ip_endpoints_, data_result->AsData().endpoints());
      MergeLists(text_records_, data_result->AsData().strings());
      MergeLists(hostnames_, data_result->AsData().hosts());
      canonical_names_.insert(data_result->domain_name());
      aliases_.insert(data_result->domain_name());
    }

    for (const auto* alias_result : alias_results) {
      aliases_.insert(alias_result->domain_name());
      aliases_.insert(alias_result->AsAlias().alias_target());
    }
  }

  if (metadata_result) {
    // Metadata results should always be cacheable.
    DCHECK(metadata_result->expiration().has_value() ||
           metadata_result->timed_expiration().has_value());

    endpoint_metadatas_ = metadata_result->AsMetadata().metadatas();

    // Even if otherwise empty, having the metadata result object signifies
    // receiving a compatible HTTPS record.
    https_record_compatibility_ = std::vector<bool>{true};

    if (data_results.empty() && endpoint_metadatas_.empty()) {
      error_ = ERR_NAME_NOT_RESOLVED;
    }
  }
}

HostCache::Entry::Entry(const Entry& entry) = default;

HostCache::Entry::Entry(Entry&& entry) = default;

HostCache::Entry::~Entry() = default;

std::vector<HostResolverEndpointResult> HostCache::Entry::GetEndpoints() const {
  std::vector<HostResolverEndpointResult> endpoints;

  if (ip_endpoints_.empty()) {
    return endpoints;
  }

  std::vector<ConnectionEndpointMetadata> metadatas = GetMetadatas();

  if (!metadatas.empty() && canonical_names_.size() == 1) {
    // Currently Chrome uses HTTPS records only when A and AAAA records are at
    // the same canonical name and that matches the HTTPS target name.
    for (ConnectionEndpointMetadata& metadata : metadatas) {
      if (!base::Contains(canonical_names_, metadata.target_name)) {
        continue;
      }
      endpoints.emplace_back();
      endpoints.back().ip_endpoints = ip_endpoints_;
      endpoints.back().metadata = std::move(metadata);
    }
  }

  // Add a final non-alternative endpoint at the end.
  endpoints.emplace_back();
  endpoints.back().ip_endpoints = ip_endpoints_;

  return endpoints;
}

std::vector<ConnectionEndpointMetadata> HostCache::Entry::GetMetadatas() const {
  std::vector<ConnectionEndpointMetadata> metadatas;
  HttpsRecordPriority last_priority = 0;
  for (const auto& metadata : endpoint_metadatas_) {
    // Ensure metadatas are iterated in priority order.
    DCHECK_GE(metadata.first, last_priority);
    last_priority = metadata.first;

    metadatas.push_back(metadata.second);
  }

  return metadatas;
}

std::optional<base::TimeDelta> HostCache::Entry::GetOptionalTtl() const {
  if (has_ttl())
    return ttl();
  else
    return std::nullopt;
}

// static
HostCache::Entry HostCache::Entry::MergeEntries(Entry front, Entry back) {
  // Only expected to merge OK or ERR_NAME_NOT_RESOLVED results.
  DCHECK(front.error() == OK || front.error() == ERR_NAME_NOT_RESOLVED);
  DCHECK(back.error() == OK || back.error() == ERR_NAME_NOT_RESOLVED);

  // Build results in |front| to preserve unmerged fields.

  front.error_ =
      front.error() == OK || back.error() == OK ? OK : ERR_NAME_NOT_RESOLVED;

  MergeLists(front.ip_endpoints_, back.ip_endpoints_);
  MergeContainers(front.endpoint_metadatas_, back.endpoint_metadatas_);
  MergeContainers(front.aliases_, back.aliases_);
  MergeLists(front.text_records_, back.text_records());
  MergeLists(front.hostnames_, back.hostnames());
  MergeLists(front.https_record_compatibility_,
             back.https_record_compatibility_);
  MergeContainers(front.canonical_names_, back.canonical_names_);

  // Only expected to merge entries from same source.
  DCHECK_EQ(front.source(), back.source());

  if (front.has_ttl() && back.has_ttl()) {
    front.ttl_ = std::min(front.ttl(), back.ttl());
  } else if (back.has_ttl()) {
    front.ttl_ = back.ttl();
  }

  front.expires_ = std::min(front.expires(), back.expires());
  front.network_changes_ =
      std::max(front.network_changes(), back.network_changes());

  front.total_hits_ = front.total_hits_ + back.total_hits_;
  front.stale_hits_ = front.stale_hits_ + back.stale_hits_;

  return front;
}

HostCache::Entry HostCache::Entry::CopyWithDefaultPort(uint16_t port) const {
  Entry copy(*this);

  for (IPEndPoint& endpoint : copy.ip_endpoints_) {
    if (endpoint.port() == 0) {
      endpoint = IPEndPoint(endpoint.address(), port);
    }
  }

  for (HostPortPair& hostname : copy.hostnames_) {
    if (hostname.port() == 0) {
      hostname = HostPortPair(hostname.host(), port);
    }
  }

  return copy;
}

HostCache::Entry& HostCache::Entry::operator=(const Entry& entry) = default;

HostCache::Entry& HostCache::Entry::operator=(Entry&& entry) = default;

HostCache::Entry::Entry(int error,
                        std::vector<IPEndPoint> ip_endpoints,
                        std::set<std::string> aliases,
                        Source source,
                        std::optional<base::TimeDelta> ttl)
    : error_(error),
      ip_endpoints_(std::move(ip_endpoints)),
      aliases_(std::move(aliases)),
      source_(source),
      ttl_(ttl ? ttl.value() : kUnknownTtl) {
  DCHECK(!ttl || ttl.value() >= base::TimeDelta());
}

HostCache::Entry::Entry(const HostCache::Entry& entry,
                        base::TimeTicks now,
                        base::TimeDelta ttl,
                        int network_changes)
    : error_(entry.error()),
      ip_endpoints_(entry.ip_endpoints_),
      endpoint_metadatas_(entry.endpoint_metadatas_),
      aliases_(entry.aliases()),
      text_records_(entry.text_records()),
      hostnames_(entry.hostnames()),
      https_record_compatibility_(entry.https_record_compatibility_),
      source_(entry.source()),
      pinning_(entry.pinning()),
      canonical_names_(entry.canonical_names()),
      ttl_(entry.ttl()),
      expires_(now + ttl),
      network_changes_(network_changes) {}

HostCache::Entry::Entry(
    int error,
    std::vector<IPEndPoint> ip_endpoints,
    std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>
        endpoint_metadatas,
    std::set<std::string> aliases,
    std::vector<std::string>&& text_records,
    std::vector<HostPortPair>&& hostnames,
    std::vector<bool>&& https_record_compatibility,
    Source source,
    base::TimeTicks expires,
    int network_changes)
    : error_(error),
      ip_endpoints_(std::move(ip_endpoints)),
      endpoint_metadatas_(std::move(endpoint_metadatas)),
      aliases_(std::move(aliases)),
      text_records_(std::move(text_records)),
      hostnames_(std::move(hostnames)),
      https_record_compatibility_(std::move(https_record_compatibility)),
      source_(source),
      expires_(expires),
      network_changes_(network_changes) {}

void HostCache::Entry::PrepareForCacheInsertion() {
  https_record_compatibility_.clear();
}

bool HostCache::Entry::IsStale(base::TimeTicks now, int network_changes) const {
  EntryStaleness stale;
  stale.expired_by = now - expires_;
  stale.network_changes = network_changes - network_changes_;
  stale.stale_hits = stale_hits_;
  return stale.is_stale();
}

void HostCache::Entry::CountHit(bool hit_is_stale) {
  ++total_hits_;
  if (hit_is_stale)
    ++stale_hits_;
}

void HostCache::Entry::GetStaleness(base::TimeTicks now,
                                    int network_changes,
                                    EntryStaleness* out) const {
  DCHECK(out);
  out->expired_by = now - expires_;
  out->network_changes = network_changes - network_changes_;
  out->stale_hits = stale_hits_;
}

base::Value HostCache::Entry::NetLogParams() const {
  return base::Value(GetAsValue(false /* include_staleness */));
}

base::Value::Dict HostCache::Entry::GetAsValue(bool include_staleness) const {
  base::Value::Dict entry_dict;

  if (include_staleness) {
    // The kExpirationKey value is using TimeTicks instead of Time used if
    // |include_staleness| is false, so it cannot be used to deserialize.
    // This is ok as it is used only for netlog.
    entry_dict.Set(kExpirationKey, NetLog::TickCountToString(expires()));
    entry_dict.Set(kTtlKey, base::saturated_cast<int>(ttl().InMilliseconds()));
    entry_dict.Set(kNetworkChangesKey, network_changes());
    // The "pinned" status is meaningful only if "network_changes" is also
    // preserved.
    if (pinning())
      entry_dict.Set(kPinnedKey, *pinning());
  } else {
    // Convert expiration time in TimeTicks to Time for serialization, using a
    // string because base::Value doesn't handle 64-bit integers.
    base::Time expiration_time =
        base::Time::Now() - (base::TimeTicks::Now() - expires());
    entry_dict.Set(kExpirationKey,
                   base::NumberToString(expiration_time.ToInternalValue()));
  }

  if (error() != OK) {
    entry_dict.Set(kNetErrorKey, error());
  } else {
    base::Value::List ip_endpoints_list;
    for (const IPEndPoint& ip_endpoint : ip_endpoints_) {
      ip_endpoints_list.Append(IpEndpointToValue(ip_endpoint));
    }
    entry_dict.Set(kIpEndpointsKey, std::move(ip_endpoints_list));

    base::Value::List endpoint_metadatas_list;
    for (const auto& endpoint_metadata_pair : endpoint_metadatas_) {
      endpoint_metadatas_list.Append(
          EndpointMetadataPairToValue(endpoint_metadata_pair));
    }
    entry_dict.Set(kEndpointMetadatasKey, std::move(endpoint_metadatas_list));

    base::Value::List alias_list;
    for (const std::string& alias : aliases()) {
      alias_list.Append(alias);
    }
    entry_dict.Set(kAliasesKey, std::move(alias_list));

    // Append all resolved text records.
    base::Value::List text_list_value;
    for (const std::string& text_record : text_records()) {
      text_list_value.Append(text_record);
    }
    entry_dict.Set(kTextRecordsKey, std::move(text_list_value));

    // Append all the resolved hostnames.
    base::Value::List hostnames_value;
    base::Value::List host_ports_value;
    for (const HostPortPair& hostname : hostnames()) {
      hostnames_value.Append(hostname.host());
      host_ports_value.Append(hostname.port());
    }
    entry_dict.Set(kHostnameResultsKey, std::move(hostnames_value));
    entry_dict.Set(kHostPortsKey, std::move(host_ports_value));

    base::Value::List canonical_names_list;
    for (const std::string& canonical_name : canonical_names()) {
      canonical_names_list.Append(canonical_name);
    }
    entry_dict.Set(kCanonicalNamesKey, std::move(canonical_names_list));
  }

  return entry_dict;
}

// static
std::optional<base::TimeDelta> HostCache::Entry::TtlFromInternalResults(
    const std::set<std::unique_ptr<HostResolverInternalResult>>& results,
    base::Time now,
    base::TimeTicks now_ticks) {
  std::optional<base::TimeDelta> smallest_ttl;
  for (const std::unique_ptr<HostResolverInternalResult>& result : results) {
    if (result->expiration().has_value()) {
      smallest_ttl = std::min(smallest_ttl.value_or(base::TimeDelta::Max()),
                              result->expiration().value() - now_ticks);
    }
    if (result->timed_expiration().has_value()) {
      smallest_ttl = std::min(smallest_ttl.value_or(base::TimeDelta::Max()),
                              result->timed_expiration().value() - now);
    }
  }
  return smallest_ttl;
}

// static
const HostCache::EntryStaleness HostCache::kNotStale = {base::Seconds(-1), 0,
                                                        0};

HostCache::HostCache(size_t max_entries)
    : max_entries_(max_entries),
      tick_clock_(base::DefaultTickClock::GetInstance()) {}

HostCache::~HostCache() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  RecordEraseAll(EraseReason::kEraseDestruct, tick_clock_->NowTicks());
}

const std::pair<const HostCache::Key, HostCache::Entry>*
HostCache::Lookup(const Key& key, base::TimeTicks now, bool ignore_secure) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (caching_is_disabled())
    return nullptr;

  auto* result = LookupInternalIgnoringFields(key, now, ignore_secure);
  if (!result) {
    RecordLookup(LookupOutcome::kLookupMissAbsent, now, key, nullptr);
    return nullptr;
  }

  auto* entry = &result->second;
  if (entry->IsStale(now, network_changes_)) {
    RecordLookup(LookupOutcome::kLookupMissStale, now, result->first, entry);
    return nullptr;
  }

  entry->CountHit(/* hit_is_stale= */ false);
  RecordLookup(LookupOutcome::kLookupHitValid, now, result->first, entry);
  return result;
}

const std::pair<const HostCache::Key, HostCache::Entry>* HostCache::LookupStale(
    const Key& key,
    base::TimeTicks now,
    HostCache::EntryStaleness* stale_out,
    bool ignore_secure) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (caching_is_disabled())
    return nullptr;

  auto* result = LookupInternalIgnoringFields(key, now, ignore_secure);
  if (!result) {
    RecordLookup(LookupOutcome::kLookupMissAbsent, now, key, nullptr);
    return nullptr;
  }

  auto* entry = &result->second;
  bool is_stale = entry->IsStale(now, network_changes_);
  entry->CountHit(/* hit_is_stale= */ is_stale);
  RecordLookup(is_stale ? LookupOutcome::kLookupHitStale
                        : LookupOutcome::kLookupHitValid,
               now, result->first, entry);

  if (stale_out)
    entry->GetStaleness(now, network_changes_, stale_out);
  return result;
}

// static
std::pair<const HostCache::Key, HostCache::Entry>*
HostCache::GetLessStaleMoreSecureResult(
    base::TimeTicks now,
    std::pair<const HostCache::Key, HostCache::Entry>* result1,
    std::pair<const HostCache::Key, HostCache::Entry>* result2) {
  // Prefer a non-null result if possible.
  if (!result1 && !result2)
    return nullptr;
  if (result1 && !result2)
    return result1;
  if (!result1 && result2)
    return result2;

  // Both result1 are result2 are non-null.
  EntryStaleness staleness1, staleness2;
  result1->second.GetStaleness(now, 0, &staleness1);
  result2->second.GetStaleness(now, 0, &staleness2);
  if (staleness1.network_changes == staleness2.network_changes) {
    // Exactly one of the results should be secure.
    DCHECK(result1->first.secure != result2->first.secure);
    // If the results have the same number of network changes, prefer a
    // non-expired result.
    if (staleness1.expired_by.is_negative() &&
        staleness2.expired_by >= base::TimeDelta()) {
      return result1;
    }
    if (staleness1.expired_by >= base::TimeDelta() &&
        staleness2.expired_by.is_negative()) {
      return result2;
    }
    // Both results are equally stale, so prefer a secure result.
    return (result1->first.secure) ? result1 : result2;
  }
  // Prefer the result with the fewest network changes.
  return (staleness1.network_changes < staleness2.network_changes) ? result1
                                                                   : result2;
}

std::pair<const HostCache::Key, HostCache::Entry>*
HostCache::LookupInternalIgnoringFields(const Key& initial_key,
                                        base::TimeTicks now,
                                        bool ignore_secure) {
  std::pair<const HostCache::Key, HostCache::Entry>* preferred_result =
      LookupInternal(initial_key);

  if (ignore_secure) {
    Key effective_key = initial_key;
    effective_key.secure = !initial_key.secure;
    preferred_result = GetLessStaleMoreSecureResult(
        now, preferred_result, LookupInternal(effective_key));
  }

  return preferred_result;
}

std::pair<const HostCache::Key, HostCache::Entry>* HostCache::LookupInternal(
    const Key& key) {
  auto it = entries_.find(key);
  return (it != entries_.end()) ? &*it : nullptr;
}

void HostCache::Set(const Key& key,
                    const Entry& entry,
                    base::TimeTicks now,
                    base::TimeDelta ttl) {
  TRACE_EVENT0(NetTracingCategory(), "HostCache::Set");
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (caching_is_disabled())
    return;

  bool has_active_pin = false;
  bool result_changed = false;
  auto it = entries_.find(key);
  if (it != entries_.end()) {
    has_active_pin = HasActivePin(it->second);

    // TODO(juliatuttle): Remember some old metadata (hit count or frequency or
    // something like that) if it's useful for better eviction algorithms?
    result_changed = entry.error() == OK && !it->second.ContentsEqual(entry);
    entries_.erase(it);
  } else {
    result_changed = true;
    // This loop almost always runs at most once, for total runtime
    // O(max_entries_).  It only runs more than once if the cache was over-full
    // due to pinned entries, and this is the first call to Set() after
    // Invalidate().  The amortized cost remains O(size()) per call to Set().
    while (size() >= max_entries_ && EvictOneEntry(now)) {
    }
  }

  Entry entry_for_cache(entry, now, ttl, network_changes_);
  entry_for_cache.set_pinning(entry.pinning().value_or(has_active_pin));
  entry_for_cache.PrepareForCacheInsertion();
  AddEntry(key, std::move(entry_for_cache));

  if (delegate_ && result_changed)
    delegate_->ScheduleWrite();
}

const HostCache::Key* HostCache::GetMatchingKeyForTesting(
    std::string_view hostname,
    HostCache::Entry::Source* source_out,
    HostCache::EntryStaleness* stale_out) const {
  for (const EntryMap::value_type& entry : entries_) {
    if (GetHostname(entry.first.host) == hostname) {
      if (source_out != nullptr)
        *source_out = entry.second.source();
      if (stale_out != nullptr) {
        entry.second.GetStaleness(tick_clock_->NowTicks(), network_changes_,
                                  stale_out);
      }
      return &entry.first;
    }
  }

  return nullptr;
}

void HostCache::AddEntry(const Key& key, Entry&& entry) {
  DCHECK_EQ(0u, entries_.count(key));
  DCHECK(entry.pinning().has_value());
  entries_.emplace(key, std::move(entry));
}

void HostCache::Invalidate() {
  ++network_changes_;
}

void HostCache::set_persistence_delegate(PersistenceDelegate* delegate) {
  // A PersistenceDelegate shouldn't be added if there already was one, and
  // shouldn't be removed (by setting to nullptr) if it wasn't previously there.
  DCHECK_NE(delegate == nullptr, delegate_ == nullptr);
  delegate_ = delegate;
}

void HostCache::clear() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  RecordEraseAll(EraseReason::kEraseClear, tick_clock_->NowTicks());

  // Don't bother scheduling a write if there's nothing to clear.
  if (size() == 0)
    return;

  entries_.clear();
  if (delegate_)
    delegate_->ScheduleWrite();
}

void HostCache::ClearForHosts(
    const base::RepeatingCallback<bool(const std::string&)>& host_filter) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (host_filter.is_null()) {
    clear();
    return;
  }

  bool changed = false;
  base::TimeTicks now = tick_clock_->NowTicks();
  for (auto it = entries_.begin(); it != entries_.end();) {
    auto next_it = std::next(it);

    if (host_filter.Run(GetHostname(it->first.host))) {
      RecordErase(EraseReason::kEraseClear, now, it->first, it->second);
      entries_.erase(it);
      changed = true;
    }

    it = next_it;
  }

  if (delegate_ && changed)
    delegate_->ScheduleWrite();
}

void HostCache::GetList(base::Value::List& entry_list,
                        bool include_staleness,
                        SerializationType serialization_type) const {
  entry_list.clear();

  for (const auto& pair : entries_) {
    const Key& key = pair.first;
    const Entry& entry = pair.second;

    base::Value network_anonymization_key_value;
    if (serialization_type == SerializationType::kRestorable) {
      // Don't save entries associated with ephemeral NetworkAnonymizationKeys.
      if (!key.network_anonymization_key.ToValue(
              &network_anonymization_key_value)) {
        continue;
      }
    } else {
      // ToValue()
"""


```