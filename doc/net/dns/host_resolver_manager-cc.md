Response:
My thinking process to analyze the code and generate the response involved several steps:

1. **Understand the Goal:** The request asks for a functional summary of `host_resolver_manager.cc`, its relationship to JavaScript, logical reasoning with examples, common usage errors, debugging clues, and a high-level summary. It explicitly mentions this is Part 1 of 3.

2. **Initial Code Scan (Headers):** I started by quickly scanning the included header files. This immediately gives clues about the file's responsibilities:
    * `net/dns/...`:  Confirms it's part of the DNS resolution mechanism.
    * `net/base/...`: Indicates interaction with core networking concepts like addresses, errors, priorities.
    * `base/...`: Shows use of Chromium's base library for things like threading, containers, metrics, logging, and time.
    * `url/...`:  Suggests handling of URLs and host/port information.
    * `#if BUILDFLAG(...)`: Highlights platform-specific code.

3. **Core Class Identification:** The name of the file directly points to the main class: `HostResolverManager`. I looked for its constructor and destructor to get a sense of its lifecycle and initialization/cleanup.

4. **Key Member Variables:** I scanned for important member variables. This provided insights into the manager's state and dependencies:
    * `dispatcher_`:  Indicates managing concurrent resolution requests.
    * `jobs_`: Suggests tracking active resolution jobs.
    * `host_cache_`:  Confirms the use of caching for DNS results.
    * `dns_client_`:  Points to the underlying DNS client implementation (potentially built-in or system).
    * `system_dns_config_notifier_`:  Shows it reacts to system DNS configuration changes.
    * `mdns_client_`: Indicates support for mDNS (multicast DNS).
    * `tick_clock_`: For time-related operations and potential testing.
    * `registered_contexts_`: Manages different contexts that can request DNS resolution.

5. **Key Methods Analysis:** I focused on the most important methods:
    * `CreateRequest()`:  The primary way to initiate a host resolution. The arguments reveal what information is needed for a resolution.
    * `ResolveLocally()`:  Handles local resolution strategies (cache, hosts file, etc.).
    * `Start()` methods for different task types: Indicate how different resolution strategies are initiated.
    * Methods related to configuration (`SetDnsConfigOverrides`, `SetInsecureDnsClientEnabled`).
    * Methods related to probing (`CreateDohProbeRequest`).
    * Methods dealing with mDNS (`CreateMdnsListener`).

6. **Functional Grouping:** Based on the analysis of members and methods, I started grouping functionalities:
    * **Request Management:** Creating, queuing, and executing resolution requests.
    * **Caching:**  Storing and retrieving DNS results.
    * **DNS Client Interaction:**  Using a `DnsClient` for actual DNS queries.
    * **System Integration:**  Reacting to system DNS changes, using the hosts file.
    * **mDNS Support:**  Handling local network name resolution.
    * **Probing:** Checking network capabilities (like IPv6).
    * **Configuration:** Allowing for overrides and settings.
    * **Error Handling:**  Returning `NetError` codes.

7. **JavaScript Relationship (Crucial Point):** I considered how this C++ code relates to the browser's JavaScript environment. The key connection is that JavaScript APIs (like `fetch`, `XMLHttpRequest`, `WebSocket`) trigger network requests, which eventually lead to DNS resolution. I looked for concepts in the code that would be relevant to JavaScript developers, such as hostnames, protocols (HTTP, HTTPS, WS, WSS), and potential error scenarios. I also considered the asynchronous nature of DNS resolution and how that aligns with JavaScript's event-driven model.

8. **Logical Reasoning and Examples:**  For logical reasoning, I selected a core function like `ResolveLocally()`. I thought about a simple input (a hostname) and what the expected output would be (IP addresses). I also considered different scenarios and how the code might behave (cache hit, cache miss, hosts file entry, etc.).

9. **Common Usage Errors:**  I thought about how a *programmer* using the Chromium networking stack might misuse this component. For example, not handling errors, incorrect configuration, or not understanding the caching behavior.

10. **Debugging Clues:** I identified how a developer might use this code during debugging. Logging (via `NetLog`), breakpoints, and understanding the flow of execution through different methods are key. The inclusion of the user's action (typing a URL, clicking a link) leading to this point is important.

11. **High-Level Summary (Part 1):**  Finally, I summarized the core responsibilities of `HostResolverManager` based on my analysis. I focused on its role as a central point for DNS resolution, managing different resolution strategies, and interacting with other networking components. The "Part 1" indication suggested a broader scope across multiple files, so I kept the summary at a relatively high level.

12. **Refinement and Organization:** I reviewed my notes and organized them into the requested sections, ensuring clarity and providing concrete examples where needed. I paid attention to the specific wording of the prompt to address all its points. I also made sure the tone was informative and helpful.
好的，让我们来分析一下 `net/dns/host_resolver_manager.cc` 这个文件的功能。

**功能归纳（第1部分）：**

这个文件的主要作用是实现 Chromium 网络栈中的 **主机名解析管理器 (Host Resolver Manager)**。  它负责协调和管理各种主机名解析的方法，最终将主机名（例如 "www.google.com"）转换为 IP 地址。

更具体地说，到目前为止的代码揭示了以下关键功能：

1. **主机名解析请求的创建和管理:**
   - 提供了创建 `HostResolver::ResolveHostRequest` 的接口，允许网络栈的其他部分请求解析特定的主机名。
   -  管理这些请求的生命周期。

2. **多种解析策略的协调:**
   -  代码中包含对多种解析方式的处理，例如：
     - **本地解析:**  检查是否是本地主机名 (localhost)。
     - **缓存查找:**  查询 DNS 缓存以获取之前解析过的结果。
     - **配置文件 (Hosts 文件):**  查找操作系统 hosts 文件中配置的映射。
     - **系统 DNS 解析器:**  调用操作系统底层的 DNS 解析功能。
     - **异步 DNS (Async DNS):**  使用 Chromium 内置的 DNS 客户端进行解析。
     - **mDNS (Multicast DNS):**  用于局域网内的设备发现。
     - **DoH (DNS over HTTPS) 探测:** 用于检测 DoH 服务器的可达性。
     - **NAT64 处理:**  在 IPv6-only 网络中处理 IPv4 字面量。
     - **HTTPS SVCB 查询:**  用于查询 HTTPS 服务的 SVCB 记录。

3. **DNS 客户端的集成和管理:**
   -  包含了 `DnsClient` 的实例 (`dns_client_`)，用于执行实际的 DNS 查询（如果启用了内置 DNS）。
   -  提供了设置 DNS 配置覆盖 (`SetDnsConfigOverrides`) 和启用/禁用不安全 DNS 查询 (`SetInsecureDnsClientEnabled`) 的方法。

4. **网络状态变化的监听和响应:**
   -  监听网络连接类型 (`NetworkChangeNotifier::AddConnectionTypeObserver`) 和 IP 地址变化 (`NetworkChangeNotifier::AddIPAddressObserver`)。
   -  根据网络状态变化，可能会触发缓存失效和正在进行的解析任务的取消。

5. **缓存管理:**
   -  虽然具体的缓存实现可能在其他文件中，但这里可以看到与缓存交互的逻辑，例如 `MaybeServeFromCache`。
   -  提供了失效缓存的方法 (`InvalidateCaches`).

6. **并发控制:**
   -  使用 `PrioritizedDispatcher` 来限制并发的系统 DNS 查询数量，避免对系统资源造成过大的压力。

7. **配置选项:**
   -  接受 `HostResolver::ManagerOptions` 参数，允许配置最大并发解析数、是否检查 IPv6 等。

8. **NetLog 集成:**
   -  使用 `net::NetLog` 记录关键事件，方便调试和监控。

9. **IPv6 可达性检测:**
   -  实现了 IPv6 探测机制，用于判断当前网络是否支持 IPv6，并据此调整解析策略（例如，如果检测到 IPv6 不可用，则可能只进行 IPv4 查询）。

**与 JavaScript 的关系及举例说明:**

尽管 `host_resolver_manager.cc` 是 C++ 代码，它与 JavaScript 的功能有密切关系。 当 JavaScript 代码发起网络请求时（例如使用 `fetch()` 或 `XMLHttpRequest()`），浏览器需要将请求中的主机名解析为 IP 地址。  `HostResolverManager` 正是负责这个过程的核心组件。

**举例说明：**

1. **用户在浏览器地址栏输入 "www.example.com" 并按下回车:**
   - JavaScript 的 URL 解析逻辑会提取出主机名 "www.example.com"。
   - 浏览器内核会将这个主机名传递给 `HostResolverManager` 请求解析。
   - `HostResolverManager` 可能会先检查本地缓存，如果没有，则会发起 DNS 查询。
   - 最终解析得到的 IP 地址会返回给浏览器内核，用于建立与服务器的连接。

2. **JavaScript 代码中使用 `fetch("https://api.example.com/data")`:**
   - `fetch()` API 内部会调用底层的网络请求机制。
   - 在发起 HTTPS 连接之前，浏览器需要知道 `api.example.com` 的 IP 地址。
   - `HostResolverManager` 负责解析 `api.example.com`，并且由于是 HTTPS 请求，它还可能查询 HTTPS SVCB 记录以获取更优的连接信息。

**逻辑推理、假设输入与输出:**

假设输入：

- **主机名:** "test.example.net"
- **网络状态:** IPv4 和 IPv6 连接都可用
- **DNS 缓存:**  为空
- **Hosts 文件:**  没有 "test.example.net" 的条目
- **Secure DNS Mode:** 关闭

逻辑推理：

1. `ResolveLocally` 会先检查是否是本地主机名，结果为否。
2. 缓存查找会失败（`TaskType::CACHE_LOOKUP`）。
3. Hosts 文件查找会失败（`TaskType::HOSTS`）。
4. 系统 DNS 解析器会被调用（`TaskType::SYSTEM`）。
5. 系统 DNS 解析器会向配置的 DNS 服务器查询 "test.example.net" 的 A 和 AAAA 记录。

假设输出：

- 如果 "test.example.net" 仅有 IPv4 地址，输出会包含一个 IPv4 的 `IPEndPoint` 列表。
- 如果 "test.example.net" 同时有 IPv4 和 IPv6 地址，输出会包含一个包含 IPv4 和 IPv6 的 `IPEndPoint` 列表。
- 如果 "test.example.net" 不存在，输出的错误码将是 `ERR_NAME_NOT_RESOLVED`。

**用户或编程常见的使用错误:**

1. **未处理 DNS 解析错误:** 开发者在发起网络请求后，没有正确处理 DNS 解析失败的情况（例如 `ERR_NAME_NOT_RESOLVED`），导致程序出现异常或无法正常工作。

   ```javascript
   fetch("https://invalid-hostname-example.com")
     .then(response => {
       // ... 处理响应
     })
     .catch(error => {
       console.error("网络请求失败:", error); // 应该处理 DNS 解析错误
     });
   ```

2. **过度依赖缓存假设:**  开发者假设 DNS 结果会一直被缓存，而忽略了 DNS 记录的 TTL (Time To Live)，可能导致程序使用了过期的 IP 地址。

3. **错误配置 DNS 设置:** 用户可能在操作系统层面错误配置了 DNS 服务器，导致 `HostResolverManager` 无法正确解析主机名。这通常不在编程层面直接控制，但会影响程序的运行。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入 URL 并访问:**
   - 用户在地址栏输入一个包含主机名的 URL，例如 "www.example.com"。
   - 浏览器内核会解析 URL，提取出主机名。
   - 浏览器会检查本地缓存中是否有该主机名的 IP 地址。
   - 如果缓存未命中，浏览器会调用 `HostResolverManager` 发起解析请求。

2. **JavaScript 代码发起网络请求:**
   - 网页上的 JavaScript 代码使用 `fetch()`、`XMLHttpRequest()` 或其他网络 API 请求资源。
   - 这些 API 内部会触发浏览器内核的网络请求流程。
   - 在建立连接之前，浏览器需要解析请求 URL 中的主机名，这会调用 `HostResolverManager`。

3. **点击网页上的链接:**
   - 用户点击网页上的一个链接，链接指向新的域名或子域名。
   - 浏览器需要解析链接中的主机名，这也会触发 `HostResolverManager` 的工作。

**总结（针对第1部分）：**

到目前为止，`net/dns/host_resolver_manager.cc` 的核心功能是作为 Chromium 中枢的主机名解析器，负责接收解析请求，协调各种解析策略（缓存、hosts 文件、系统 DNS、异步 DNS 等），并管理底层的 DNS 客户端。它直接支撑着浏览器中所有需要将域名转换为 IP 地址的网络操作，与 JavaScript 发起的网络请求紧密相关。  代码中已经展现了对多种解析方法和网络状态变化的初步处理逻辑。

### 提示词
```
这是目录为net/dns/host_resolver_manager.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/host_resolver_manager.h"

#include <cmath>
#include <cstdint>
#include <iterator>
#include <limits>
#include <memory>
#include <numeric>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_set>
#include <utility>
#include <vector>

#include "base/check_op.h"
#include "base/compiler_specific.h"
#include "base/containers/circular_deque.h"
#include "base/containers/contains.h"
#include "base/containers/flat_set.h"
#include "base/containers/linked_list.h"
#include "base/debug/debugger.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/safe_ref.h"
#include "base/memory/weak_ptr.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/no_destructor.h"
#include "base/not_fatal_until.h"
#include "base/numerics/safe_conversions.h"
#include "base/observer_list.h"
#include "base/ranges/algorithm.h"
#include "base/sequence_checker.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/threading/scoped_blocking_call.h"
#include "base/time/default_tick_clock.h"
#include "base/time/time.h"
#include "base/types/optional_util.h"
#include "base/values.h"
#include "build/build_config.h"
#include "net/base/address_family.h"
#include "net/base/address_list.h"
#include "net/base/completion_once_callback.h"
#include "net/base/features.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/network_change_notifier.h"
#include "net/base/network_interfaces.h"
#include "net/base/prioritized_dispatcher.h"
#include "net/base/request_priority.h"
#include "net/base/trace_constants.h"
#include "net/base/tracing.h"
#include "net/base/url_util.h"
#include "net/dns/dns_alias_utility.h"
#include "net/dns/dns_client.h"
#include "net/dns/dns_names_util.h"
#include "net/dns/dns_response.h"
#include "net/dns/dns_response_result_extractor.h"
#include "net/dns/dns_transaction.h"
#include "net/dns/dns_util.h"
#include "net/dns/host_cache.h"
#include "net/dns/host_resolver_dns_task.h"
#include "net/dns/host_resolver_internal_result.h"
#include "net/dns/host_resolver_manager_job.h"
#include "net/dns/host_resolver_manager_request_impl.h"
#include "net/dns/host_resolver_manager_service_endpoint_request_impl.h"
#include "net/dns/host_resolver_mdns_listener_impl.h"
#include "net/dns/host_resolver_mdns_task.h"
#include "net/dns/host_resolver_nat64_task.h"
#include "net/dns/host_resolver_proc.h"
#include "net/dns/host_resolver_system_task.h"
#include "net/dns/httpssvc_metrics.h"
#include "net/dns/loopback_only.h"
#include "net/dns/mdns_client.h"
#include "net/dns/public/dns_protocol.h"
#include "net/dns/public/dns_query_type.h"
#include "net/dns/public/host_resolver_results.h"
#include "net/dns/public/resolve_error_info.h"
#include "net/dns/public/secure_dns_mode.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/dns/public/util.h"
#include "net/dns/record_parsed.h"
#include "net/dns/resolve_context.h"
#include "net/dns/test_dns_config_service.h"
#include "net/http/http_network_session.h"
#include "net/log/net_log.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_source_type.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/client_socket_factory.h"
#include "net/url_request/url_request_context.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

#if BUILDFLAG(ENABLE_MDNS)
#include "net/dns/mdns_client_impl.h"
#endif

#if BUILDFLAG(IS_WIN)
#include <Winsock2.h>
#include "net/base/winsock_init.h"
#endif

#if BUILDFLAG(IS_POSIX) || BUILDFLAG(IS_FUCHSIA)
#include <net/if.h>
#include "net/base/sys_addrinfo.h"
#if BUILDFLAG(IS_ANDROID)
#include "base/android/build_info.h"
#else  // !BUILDFLAG(IS_ANDROID)
#include <ifaddrs.h>
#endif  // BUILDFLAG(IS_ANDROID)
#endif  // BUILDFLAG(IS_POSIX) || BUILDFLAG(IS_FUCHSIA)

namespace net {

namespace {

// Limit the size of hostnames that will be resolved to combat issues in
// some platform's resolvers.
const size_t kMaxHostLength = 4096;

// Time between IPv6 probes, i.e. for how long results of each IPv6 probe are
// cached.
const int kIPv6ProbePeriodMs = 1000;

// Google DNS address used for IPv6 probes.
const uint8_t kIPv6ProbeAddress[] = {0x20, 0x01, 0x48, 0x60, 0x48, 0x60,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x88, 0x88};

// True if |hostname| ends with either ".local" or ".local.".
bool ResemblesMulticastDNSName(std::string_view hostname) {
  return hostname.ends_with(".local") || hostname.ends_with(".local.");
}

bool ConfigureAsyncDnsNoFallbackFieldTrial() {
  const bool kDefault = false;

  // Configure the AsyncDns field trial as follows:
  // groups AsyncDnsNoFallbackA and AsyncDnsNoFallbackB: return true,
  // groups AsyncDnsA and AsyncDnsB: return false,
  // groups SystemDnsA and SystemDnsB: return false,
  // otherwise (trial absent): return default.
  std::string group_name = base::FieldTrialList::FindFullName("AsyncDns");
  if (!group_name.empty()) {
    return base::StartsWith(group_name, "AsyncDnsNoFallback",
                            base::CompareCase::INSENSITIVE_ASCII);
  }
  return kDefault;
}

base::Value::Dict NetLogIPv6AvailableParams(bool ipv6_available, bool cached) {
  base::Value::Dict dict;
  dict.Set("ipv6_available", ipv6_available);
  dict.Set("cached", cached);
  return dict;
}

// Maximum of 64 concurrent resolver calls (excluding retries).
// Between 2010 and 2020, the limit was set to 6 because of a report of a broken
// home router that would fail in the presence of more simultaneous queries.
// In 2020, we conducted an experiment to see if this kind of router was still
// present on the Internet, and found no evidence of any remaining issues, so
// we increased the limit to 64 at that time.
const size_t kDefaultMaxSystemTasks = 64u;

PrioritizedDispatcher::Limits GetDispatcherLimits(
    const HostResolver::ManagerOptions& options) {
  PrioritizedDispatcher::Limits limits(NUM_PRIORITIES,
                                       options.max_concurrent_resolves);

  // If not using default, do not use the field trial.
  if (limits.total_jobs != HostResolver::ManagerOptions::kDefaultParallelism)
    return limits;

  // Default, without trial is no reserved slots.
  limits.total_jobs = kDefaultMaxSystemTasks;

  // Parallelism is determined by the field trial.
  std::string group =
      base::FieldTrialList::FindFullName("HostResolverDispatch");

  if (group.empty())
    return limits;

  // The format of the group name is a list of non-negative integers separated
  // by ':'. Each of the elements in the list corresponds to an element in
  // |reserved_slots|, except the last one which is the |total_jobs|.
  std::vector<std::string_view> group_parts = base::SplitStringPiece(
      group, ":", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (group_parts.size() != NUM_PRIORITIES + 1) {
    NOTREACHED();
  }

  std::vector<size_t> parsed(group_parts.size());
  for (size_t i = 0; i < group_parts.size(); ++i) {
    if (!base::StringToSizeT(group_parts[i], &parsed[i])) {
      NOTREACHED();
    }
  }

  const size_t total_jobs = parsed.back();
  parsed.pop_back();

  const size_t total_reserved_slots =
      std::accumulate(parsed.begin(), parsed.end(), 0u);

  // There must be some unreserved slots available for the all priorities.
  if (total_reserved_slots > total_jobs ||
      (total_reserved_slots == total_jobs && parsed[MINIMUM_PRIORITY] == 0)) {
    NOTREACHED();
  }

  limits.total_jobs = total_jobs;
  limits.reserved_slots = parsed;
  return limits;
}

base::Value::Dict NetLogResults(const HostCache::Entry& results) {
  base::Value::Dict dict;
  dict.Set("results", results.NetLogParams());
  return dict;
}

std::vector<IPEndPoint> FilterAddresses(std::vector<IPEndPoint> addresses,
                                        DnsQueryTypeSet query_types) {
  DCHECK(!query_types.Has(DnsQueryType::UNSPECIFIED));
  DCHECK(!query_types.empty());

  const AddressFamily want_family =
      HostResolver::DnsQueryTypeSetToAddressFamily(query_types);

  if (want_family == ADDRESS_FAMILY_UNSPECIFIED)
    return addresses;

  // Keep only the endpoints that match `want_family`.
  addresses.erase(
      base::ranges::remove_if(
          addresses,
          [want_family](AddressFamily family) { return family != want_family; },
          &IPEndPoint::GetFamily),
      addresses.end());
  return addresses;
}

int GetPortForGloballyReachableCheck() {
  if (!base::FeatureList::IsEnabled(
          features::kUseAlternativePortForGloballyReachableCheck)) {
    return 443;
  }
  return features::kAlternativePortForGloballyReachableCheck.Get();
}

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
//
// LINT.IfChange(DnsClientCapability)
enum class DnsClientCapability {
  kSecureDisabledInsecureDisabled = 0,
  kSecureDisabledInsecureEnabled = 1,
  kSecureEnabledInsecureDisabled = 2,
  kSecureEnabledInsecureEnabled = 3,
  kMaxValue = kSecureEnabledInsecureEnabled,
};
// LINT.ThenChange(/tools/metrics/histograms/metadata/net/enums.xml:DnsClientCapability)

void RecordDnsClientCapabilityMetrics(const DnsClient* dns_client) {
  if (!dns_client) {
    return;
  }
  DnsClientCapability capability;
  if (dns_client->CanUseSecureDnsTransactions()) {
    if (dns_client->CanUseInsecureDnsTransactions()) {
      capability = DnsClientCapability::kSecureEnabledInsecureEnabled;
    } else {
      capability = DnsClientCapability::kSecureEnabledInsecureDisabled;
    }
  } else {
    if (dns_client->CanUseInsecureDnsTransactions()) {
      capability = DnsClientCapability::kSecureDisabledInsecureEnabled;
    } else {
      capability = DnsClientCapability::kSecureDisabledInsecureDisabled;
    }
  }
  base::UmaHistogramEnumeration("Net.DNS.DnsConfig.DnsClientCapability",
                                capability);
}
}  // namespace

//-----------------------------------------------------------------------------

bool ResolveLocalHostname(std::string_view host,
                          std::vector<IPEndPoint>* address_list) {
  address_list->clear();
  if (!IsLocalHostname(host))
    return false;

  address_list->emplace_back(IPAddress::IPv6Localhost(), 0);
  address_list->emplace_back(IPAddress::IPv4Localhost(), 0);

  return true;
}

class HostResolverManager::ProbeRequestImpl
    : public HostResolver::ProbeRequest,
      public ResolveContext::DohStatusObserver {
 public:
  ProbeRequestImpl(base::WeakPtr<ResolveContext> context,
                   base::WeakPtr<HostResolverManager> resolver)
      : context_(std::move(context)), resolver_(std::move(resolver)) {}

  ProbeRequestImpl(const ProbeRequestImpl&) = delete;
  ProbeRequestImpl& operator=(const ProbeRequestImpl&) = delete;

  ~ProbeRequestImpl() override {
    // Ensure that observers are deregistered to avoid wasting memory.
    if (context_)
      context_->UnregisterDohStatusObserver(this);
  }

  int Start() override {
    DCHECK(resolver_);
    DCHECK(!runner_);

    if (!context_)
      return ERR_CONTEXT_SHUT_DOWN;

    context_->RegisterDohStatusObserver(this);

    StartRunner(false /* network_change */);
    return ERR_IO_PENDING;
  }

  // ResolveContext::DohStatusObserver
  void OnSessionChanged() override { CancelRunner(); }

  void OnDohServerUnavailable(bool network_change) override {
    // Start the runner asynchronously, as this may trigger reentrant calls into
    // HostResolverManager, which are not allowed during notification handling.
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&ProbeRequestImpl::StartRunner,
                       weak_ptr_factory_.GetWeakPtr(), network_change));
  }

 private:
  void StartRunner(bool network_change) {
    DCHECK(resolver_);
    DCHECK(!resolver_->invalidation_in_progress_);

    if (!context_)
      return;  // Reachable if the context ends before a posted task runs.

    if (!runner_)
      runner_ = resolver_->CreateDohProbeRunner(context_.get());
    if (runner_)
      runner_->Start(network_change);
  }

  void CancelRunner() {
    runner_.reset();

    // Cancel any asynchronous StartRunner() calls.
    weak_ptr_factory_.InvalidateWeakPtrs();
  }

  base::WeakPtr<ResolveContext> context_;

  std::unique_ptr<DnsProbeRunner> runner_;
  base::WeakPtr<HostResolverManager> resolver_;

  base::WeakPtrFactory<ProbeRequestImpl> weak_ptr_factory_{this};
};

//-----------------------------------------------------------------------------

HostResolverManager::HostResolverManager(
    const HostResolver::ManagerOptions& options,
    SystemDnsConfigChangeNotifier* system_dns_config_notifier,
    NetLog* net_log)
    : HostResolverManager(PassKey(),
                          options,
                          system_dns_config_notifier,
                          handles::kInvalidNetworkHandle,
                          net_log) {}

HostResolverManager::HostResolverManager(
    base::PassKey<HostResolverManager>,
    const HostResolver::ManagerOptions& options,
    SystemDnsConfigChangeNotifier* system_dns_config_notifier,
    handles::NetworkHandle target_network,
    NetLog* net_log)
    : host_resolver_system_params_(nullptr, options.max_system_retry_attempts),
      net_log_(net_log),
      system_dns_config_notifier_(system_dns_config_notifier),
      target_network_(target_network),
      check_ipv6_on_wifi_(options.check_ipv6_on_wifi),
      ipv6_reachability_override_(base::FeatureList::IsEnabled(
          features::kEnableIPv6ReachabilityOverride)),
      tick_clock_(base::DefaultTickClock::GetInstance()),
      https_svcb_options_(
          options.https_svcb_options
              ? *options.https_svcb_options
              : HostResolver::HttpsSvcbOptions::FromFeatures()) {
  PrioritizedDispatcher::Limits job_limits = GetDispatcherLimits(options);
  dispatcher_ = std::make_unique<PrioritizedDispatcher>(job_limits);
  max_queued_jobs_ = job_limits.total_jobs * 100u;

  DCHECK_GE(dispatcher_->num_priorities(), static_cast<size_t>(NUM_PRIORITIES));

#if BUILDFLAG(IS_WIN)
  EnsureWinsockInit();
#endif
#if (BUILDFLAG(IS_POSIX) && !BUILDFLAG(IS_APPLE) && !BUILDFLAG(IS_ANDROID)) || \
    BUILDFLAG(IS_FUCHSIA)
  RunLoopbackProbeJob();
#endif
  // Network-bound HostResolverManagers don't need to act on network changes.
  if (!IsBoundToNetwork()) {
    NetworkChangeNotifier::AddIPAddressObserver(this);
    NetworkChangeNotifier::AddConnectionTypeObserver(this);
  }
  if (system_dns_config_notifier_)
    system_dns_config_notifier_->AddObserver(this);
  EnsureSystemHostResolverCallReady();

  auto connection_type =
      IsBoundToNetwork()
          ? NetworkChangeNotifier::GetNetworkConnectionType(target_network)
          : NetworkChangeNotifier::GetConnectionType();
  UpdateConnectionType(connection_type);

#if defined(ENABLE_BUILT_IN_DNS)
  dns_client_ = DnsClient::CreateClient(net_log_);
  dns_client_->SetInsecureEnabled(
      options.insecure_dns_client_enabled,
      options.additional_types_via_insecure_dns_enabled);
  dns_client_->SetConfigOverrides(options.dns_config_overrides);
#else
  DCHECK(options.dns_config_overrides == DnsConfigOverrides());
#endif

  allow_fallback_to_systemtask_ = !ConfigureAsyncDnsNoFallbackFieldTrial();
}

HostResolverManager::~HostResolverManager() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  // Prevent the dispatcher from starting new jobs.
  dispatcher_->SetLimitsToZero();
  // It's now safe for Jobs to call KillDnsTask on destruction, because
  // OnJobComplete will not start any new jobs.
  jobs_.clear();

  if (target_network_ == handles::kInvalidNetworkHandle) {
    NetworkChangeNotifier::RemoveIPAddressObserver(this);
    NetworkChangeNotifier::RemoveConnectionTypeObserver(this);
  }
  if (system_dns_config_notifier_)
    system_dns_config_notifier_->RemoveObserver(this);
}

// static
std::unique_ptr<HostResolverManager>
HostResolverManager::CreateNetworkBoundHostResolverManager(
    const HostResolver::ManagerOptions& options,
    handles::NetworkHandle target_network,
    NetLog* net_log) {
#if BUILDFLAG(IS_ANDROID)
  DCHECK(NetworkChangeNotifier::AreNetworkHandlesSupported());
  return std::make_unique<HostResolverManager>(
      PassKey(), options, nullptr /* system_dns_config_notifier */,
      target_network, net_log);
#else   // !BUILDFLAG(IS_ANDROID)
  NOTIMPLEMENTED();
  return nullptr;
#endif  // BUILDFLAG(IS_ANDROID)
}

std::unique_ptr<HostResolver::ResolveHostRequest>
HostResolverManager::CreateRequest(
    absl::variant<url::SchemeHostPort, HostPortPair> host,
    NetworkAnonymizationKey network_anonymization_key,
    NetLogWithSource net_log,
    std::optional<ResolveHostParameters> optional_parameters,
    ResolveContext* resolve_context) {
  return CreateRequest(HostResolver::Host(std::move(host)),
                       std::move(network_anonymization_key), std::move(net_log),
                       std::move(optional_parameters), resolve_context);
}

std::unique_ptr<HostResolver::ResolveHostRequest>
HostResolverManager::CreateRequest(
    HostResolver::Host host,
    NetworkAnonymizationKey network_anonymization_key,
    NetLogWithSource net_log,
    std::optional<ResolveHostParameters> optional_parameters,
    ResolveContext* resolve_context) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!invalidation_in_progress_);

  DCHECK_EQ(resolve_context->GetTargetNetwork(), target_network_);
  // ResolveContexts must register (via RegisterResolveContext()) before use to
  // ensure cached data is invalidated on network and configuration changes.
  DCHECK(registered_contexts_.HasObserver(resolve_context));

  return std::make_unique<RequestImpl>(
      std::move(net_log), std::move(host), std::move(network_anonymization_key),
      std::move(optional_parameters), resolve_context->GetWeakPtr(),
      weak_ptr_factory_.GetWeakPtr(), tick_clock_);
}

std::unique_ptr<HostResolver::ProbeRequest>
HostResolverManager::CreateDohProbeRequest(ResolveContext* context) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  return std::make_unique<ProbeRequestImpl>(context->GetWeakPtr(),
                                            weak_ptr_factory_.GetWeakPtr());
}

std::unique_ptr<HostResolver::MdnsListener>
HostResolverManager::CreateMdnsListener(const HostPortPair& host,
                                        DnsQueryType query_type) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_NE(DnsQueryType::UNSPECIFIED, query_type);

  auto listener =
      std::make_unique<HostResolverMdnsListenerImpl>(host, query_type);

  MDnsClient* client;
  int rv = GetOrCreateMdnsClient(&client);

  if (rv == OK) {
    std::unique_ptr<net::MDnsListener> inner_listener = client->CreateListener(
        DnsQueryTypeToQtype(query_type), host.host(), listener.get());
    listener->set_inner_listener(std::move(inner_listener));
  } else {
    listener->set_initialization_error(rv);
  }
  return listener;
}

std::unique_ptr<HostResolver::ServiceEndpointRequest>
HostResolverManager::CreateServiceEndpointRequest(
    url::SchemeHostPort scheme_host_port,
    NetworkAnonymizationKey network_anonymization_key,
    NetLogWithSource net_log,
    ResolveHostParameters parameters,
    ResolveContext* resolve_context) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!invalidation_in_progress_);
  DCHECK_EQ(resolve_context->GetTargetNetwork(), target_network_);
  if (resolve_context) {
    DCHECK(registered_contexts_.HasObserver(resolve_context));
  }

  return std::make_unique<ServiceEndpointRequestImpl>(
      std::move(scheme_host_port), std::move(network_anonymization_key),
      std::move(net_log), std::move(parameters),
      resolve_context ? resolve_context->GetWeakPtr() : nullptr,
      weak_ptr_factory_.GetWeakPtr(), tick_clock_);
}

void HostResolverManager::SetInsecureDnsClientEnabled(
    bool enabled,
    bool additional_dns_types_enabled) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (!dns_client_)
    return;

  bool enabled_before = dns_client_->CanUseInsecureDnsTransactions();
  bool additional_types_before =
      enabled_before && dns_client_->CanQueryAdditionalTypesViaInsecureDns();
  dns_client_->SetInsecureEnabled(enabled, additional_dns_types_enabled);

  // Abort current tasks if `CanUseInsecureDnsTransactions()` changes or if
  // insecure transactions are enabled and
  // `CanQueryAdditionalTypesViaInsecureDns()` changes. Changes to allowing
  // additional types don't matter if insecure transactions are completely
  // disabled.
  if (dns_client_->CanUseInsecureDnsTransactions() != enabled_before ||
      (dns_client_->CanUseInsecureDnsTransactions() &&
       dns_client_->CanQueryAdditionalTypesViaInsecureDns() !=
           additional_types_before)) {
    AbortInsecureDnsTasks(ERR_NETWORK_CHANGED, false /* fallback_only */);
  }
}

base::Value::Dict HostResolverManager::GetDnsConfigAsValue() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return dns_client_ ? dns_client_->GetDnsConfigAsValueForNetLog()
                     : base::Value::Dict();
}

void HostResolverManager::SetDnsConfigOverrides(DnsConfigOverrides overrides) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (!dns_client_ && overrides == DnsConfigOverrides())
    return;

  // Not allowed to set overrides if compiled without DnsClient.
  DCHECK(dns_client_);

  bool transactions_allowed_before =
      dns_client_->CanUseSecureDnsTransactions() ||
      dns_client_->CanUseInsecureDnsTransactions();
  bool changed = dns_client_->SetConfigOverrides(std::move(overrides));

  if (changed) {
    NetworkChangeNotifier::TriggerNonSystemDnsChange();

    // Only invalidate cache if new overrides have resulted in a config change.
    InvalidateCaches();

    // Need to update jobs iff transactions were previously allowed because
    // in-progress jobs may be running using a now-invalid configuration.
    if (transactions_allowed_before) {
      UpdateJobsForChangedConfig();
    }
  }
}

void HostResolverManager::RegisterResolveContext(ResolveContext* context) {
  registered_contexts_.AddObserver(context);
  context->InvalidateCachesAndPerSessionData(
      dns_client_ ? dns_client_->GetCurrentSession() : nullptr,
      false /* network_change */);
}

void HostResolverManager::DeregisterResolveContext(
    const ResolveContext* context) {
  registered_contexts_.RemoveObserver(context);

  // Destroy Jobs when their context is closed.
  RemoveAllJobs(context);
}

void HostResolverManager::SetTickClockForTesting(
    const base::TickClock* tick_clock) {
  tick_clock_ = tick_clock;
}

void HostResolverManager::SetIPv6ReachabilityOverride(
    bool reachability_override) {
  ipv6_reachability_override_ = reachability_override;
}

void HostResolverManager::SetMaxQueuedJobsForTesting(size_t value) {
  DCHECK_EQ(0u, dispatcher_->num_queued_jobs());
  DCHECK_GE(value, 0u);
  max_queued_jobs_ = value;
}

void HostResolverManager::SetHaveOnlyLoopbackAddresses(bool result) {
  if (result) {
    additional_resolver_flags_ |= HOST_RESOLVER_LOOPBACK_ONLY;
  } else {
    additional_resolver_flags_ &= ~HOST_RESOLVER_LOOPBACK_ONLY;
  }
}

void HostResolverManager::SetMdnsSocketFactoryForTesting(
    std::unique_ptr<MDnsSocketFactory> socket_factory) {
  DCHECK(!mdns_client_);
  mdns_socket_factory_ = std::move(socket_factory);
}

void HostResolverManager::SetMdnsClientForTesting(
    std::unique_ptr<MDnsClient> client) {
  mdns_client_ = std::move(client);
}

void HostResolverManager::SetDnsClientForTesting(
    std::unique_ptr<DnsClient> dns_client) {
  DCHECK(dns_client);
  if (dns_client_) {
    if (!dns_client->GetSystemConfigForTesting())
      dns_client->SetSystemConfig(dns_client_->GetSystemConfigForTesting());
    dns_client->SetConfigOverrides(dns_client_->GetConfigOverridesForTesting());
  }
  dns_client_ = std::move(dns_client);
  // Inform `registered_contexts_` of the new `DnsClient`.
  InvalidateCaches();
}

void HostResolverManager::SetLastIPv6ProbeResultForTesting(
    bool last_ipv6_probe_result) {
  SetLastIPv6ProbeResult(last_ipv6_probe_result);
}

// static
bool HostResolverManager::IsLocalTask(TaskType task) {
  switch (task) {
    case TaskType::SECURE_CACHE_LOOKUP:
    case TaskType::INSECURE_CACHE_LOOKUP:
    case TaskType::CACHE_LOOKUP:
    case TaskType::CONFIG_PRESET:
    case TaskType::HOSTS:
      return true;
    default:
      return false;
  }
}

void HostResolverManager::InitializeJobKeyAndIPAddress(
    const NetworkAnonymizationKey& network_anonymization_key,
    const ResolveHostParameters& parameters,
    const NetLogWithSource& source_net_log,
    JobKey& out_job_key,
    IPAddress& out_ip_address) {
  out_job_key.network_anonymization_key = network_anonymization_key;
  out_job_key.source = parameters.source;

  const bool is_ip = out_ip_address.AssignFromIPLiteral(
      out_job_key.host.GetHostnameWithoutBrackets());

  out_job_key.secure_dns_mode =
      GetEffectiveSecureDnsMode(parameters.secure_dns_policy);
  out_job_key.flags = HostResolver::ParametersToHostResolverFlags(parameters) |
                      additional_resolver_flags_;

  if (parameters.dns_query_type != DnsQueryType::UNSPECIFIED) {
    out_job_key.query_types = {parameters.dns_query_type};
    return;
  }

  DnsQueryTypeSet effective_types = {DnsQueryType::A, DnsQueryType::AAAA};

  // Disable AAAA queries when we cannot do anything with the results.
  bool use_local_ipv6 = true;
  if (dns_client_) {
    const DnsConfig* config = dns_client_->GetEffectiveConfig();
    if (config) {
      use_local_ipv6 = config->use_local_ipv6;
    }
  }
  // When resolving IPv4 literals, there's no need to probe for IPv6. When
  // resolving IPv6 literals, there's no benefit to artificially limiting our
  // resolution based on a probe. Prior logic ensures that this is an automatic
  // query, so the code requesting the resolution should be amenable to
  // receiving an IPv6 resolution.
  if (!use_local_ipv6 && !is_ip && !last_ipv6_probe_result_ &&
      !ipv6_reachability_override_) {
    out_job_key.flags |= HOST_RESOLVER_DEFAULT_FAMILY_SET_DUE_TO_NO_IPV6;
    effective_types.Remove(DnsQueryType::AAAA);
  }

  // Optimistically enable feature-controlled queries. These queries may be
  // skipped at a later point.

  // `https_svcb_options_.enable` has precedence, so if enabled, ignore any
  // other related features.
  if (https_svcb_options_.enable && out_job_key.host.HasScheme()) {
    static const char* const kSchemesForHttpsQuery[] = {
        url::kHttpScheme, url::kHttpsScheme, url::kWsScheme, url::kWssScheme};
    if (base::Contains(kSchemesForHttpsQuery, out_job_key.host.GetScheme())) {
      effective_types.Put(DnsQueryType::HTTPS);
    }
  }

  out_job_key.query_types = effective_types;
}

HostCache::Entry HostResolverManager::ResolveLocally(
    bool only_ipv6_reachable,
    const JobKey& job_key,
    const IPAddress& ip_address,
    ResolveHostParameters::CacheUsage cache_usage,
    SecureDnsPolicy secure_dns_policy,
    HostResolverSource source,
    const NetLogWithSource& source_net_log,
    HostCache* cache,
    std::deque<TaskType>* out_tasks,
    std::optional<HostCache::EntryStaleness>* out_stale_info) {
  DCHECK(out_stale_info);
  *out_stale_info = std::nullopt;

  CreateTaskSequence(job_key, cache_usage, secure_dns_policy, out_tasks);

  if (!ip_address.IsValid()) {
    // Check that the caller supplied a valid hostname to resolve. For
    // MULTICAST_DNS, we are less restrictive.
    // TODO(ericorth): Control validation based on an explicit flag rather
    // than implicitly based on |source|.
    const bool is_valid_hostname =
        job_key.source == HostResolverSource::MULTICAST_DNS
            ? dns_names_util::IsValidDnsName(job_key.host.GetHostname())
            : IsCanonicalizedHostCompliant(job_key.host.GetHostname());
    if (!is_valid_hostname) {
      return HostCache::Entry(ERR_NAME_NOT_RESOLVED,
                              HostCache::Entry::SOURCE_UNKNOWN);
    }
  }

  bool resolve_canonname = job_key.flags & HOST_RESOLVER_CANONNAME;
  bool default_family_due_to_no_ipv6 =
      job_key.flags & HOST_RESOLVER_DEFAULT_FAMILY_SET_DUE_TO_NO_IPV6;

  // The result of |getaddrinfo| for empty hosts is inconsistent across systems.
  // On Windows it gives the default interface's address, whereas on Linux it
  // gives an error. We will make it fail on all platforms for consistency.
  if (job_key.host.GetHostname().empty() ||
      job_key.host.GetHostname().size() > kMaxHostLength) {
    return HostCache::Entry(ERR_NAME_NOT_RESOLVED,
                            HostCache::Entry::SOURCE_UNKNOWN);
  }

  if (ip_address.IsValid()) {
    // Use NAT64Task for IPv4 literal when the network is IPv6 only.
    if (HostResolver::MayUseNAT64ForIPv4Literal(job_key.flags, source,
                                                ip_address) &&
        only_ipv6_reachable) {
      out_tasks->push_front(TaskType::NAT64);
      return HostCache::Entry(ERR_DNS_CACHE_MISS,
                              HostCache::Entry::SOURCE_UNKNOWN);
    }

    return ResolveAsIP(job_key.query_types, resolve_canonname, ip_address);
  }

  // Special-case localhost names, as per the recommendations in
  // https://tools.ietf.org/html/draft-west-let-localhost-be-localhost.
  std::optional<HostCache::Entry> resolved =
      ServeLocalhost(job_key.host.GetHostname(), job_key.query_types,
                     default_family_due_to_no_ipv6);
  if (resolved)
    return resolved.value();

  // Do initial cache lookups.
  while (!out_tasks->empty() && IsLocalTask(out_tasks->front())) {
    TaskType task = out_tasks->front();
    out_tasks->pop_front();
    if (task == TaskType::SECURE_CACHE_LOOKUP ||
        task == TaskType::INSECURE_CACHE_LOOKUP ||
        task == TaskType::CACHE_LOOKUP) {
      bool secure = task == TaskType::SECURE_CACHE_LOOKUP;
      HostCache::Key key = job_key.ToCacheKey(secure);

      bool ignore_secure = task == TaskType::CACHE_LOOKUP;
      resolved = MaybeServeFromCache(cache, key, cache_usage, ignore_secure,
                                     source_net_log, out_stale_info);
      if (resolved) {
        // |MaybeServeFromCache()| will update |*out_stale_info| as needed.
        DCHECK(out_stale_info->has_value());
        source_net_log.AddEvent(
            NetLogEventType::HOST_RESOLVER_MANAGER_CACHE_HIT,
            [&] { return NetLogResults(resolved.value()); });

        // TODO(crbug.com/40178456): Call StartBootstrapFollowup() if the Secure
        // DNS Policy is kBootstrap and the result is not secure.  Note: A naive
        // implementation could cause an infinite loop if |resolved| always
        // expires or is evicted before the followup runs.
        return resolved.value();
      }
      DCHECK(!out_stale_info->has_value());
    } else if (task == TaskType::CONFIG_PRESET) {
      resolved = MaybeReadFromConfig(job_key);
      if (resolved) {
        source_net_log.AddEvent(
            NetLogEventType::HOST_RESOLVER_MANAGER_CONFIG_PRESET_MATCH,
            [&] { return NetLogResults(resolved.value()); });
        StartBootstrapFollowup(job_key, cache, source_net_log);
        return resolved.value();
      }
    } else if (task == TaskType::HOSTS) {
      resolved = ServeFromHosts(job_key.host.GetHostname(), job_key.query_types,
                                default_family_due_to_no_ipv6, *out_tasks);
      if (resolved) {
        source_net_log.AddEvent(
            NetLogEventType::HOST_RESOLVER_MANAGER_HOSTS_HIT,
            [&] { return NetLogResults(resol
```