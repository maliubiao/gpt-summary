Response:
Let's break down the thought process for analyzing the provided C++ code snippet of `mock_host_resolver.cc`.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of the `MockHostResolverBase` class and its functionalities. Key areas to cover are:

* **Core Functionality:** What does this class *do*?
* **JavaScript Relevance:**  Does it interact with JavaScript (directly or indirectly)?
* **Logical Reasoning (Input/Output):** How can we demonstrate its behavior with examples?
* **Common User Errors:** What mistakes could developers make while using it?
* **Debugging Context:** How does a user's action lead to this code?
* **Summary:** Condense the core functionality.

**2. Initial Code Scan and Keyword Identification:**

A quick scan reveals several important keywords and concepts:

* `MockHostResolver`:  This immediately suggests a testing or simulation component. It's a "fake" resolver.
* `HostResolver`: This indicates it's mimicking a real DNS resolver.
* `ResolveHostRequest`, `ServiceEndpointRequest`, `ProbeRequest`, `MdnsListener`: These are the different types of resolution requests it handles.
* `RuleResolver`:  Suggests configurable rules for resolving hostnames.
* `HostCache`:  Implies a caching mechanism for resolved addresses.
* `AddRule`, `AddIPLiteralRule`, `AddSimulatedFailure`: These are the methods used to define the mock resolver's behavior.
* `Start`, `Resolve`, `OnAsyncCompleted`:  These are core methods related to the resolution process.
* `AddressList`, `IPEndPoint`, `DnsQueryType`: These are data structures related to DNS resolution.
* `JavaScript` (explicitly mentioned in the prompt):  Requires careful consideration of how networking relates to the browser's JavaScript engine.

**3. Deeper Dive into Functionality (and Iterative Refinement):**

* **Core Purpose:** The code clearly simulates a DNS resolver. It doesn't perform actual DNS lookups. This is crucial for testing network-dependent code without relying on external DNS servers.

* **Rule-Based Resolution:** The `RuleResolver` is a key component. The `AddRule` methods allow setting up specific responses for hostname patterns. This makes testing various scenarios easy (successful resolution, failures, timeouts, specific IP addresses).

* **Caching:** The presence of `HostCache` indicates the mock resolver can simulate DNS caching behavior. This allows testing how components react to cached responses.

* **Different Request Types:**  The different `RequestImpl` classes (for regular DNS, service endpoints, DoH probes, and mDNS) show the breadth of network scenarios it can simulate.

* **Asynchronous Nature:**  The `Start` method and callbacks (`CompletionOnceCallback`) point to an asynchronous model, mimicking real DNS resolution.

* **JavaScript Connection:** This requires more thought. While the C++ code doesn't directly execute JavaScript, it's a fundamental part of Chromium's network stack. JavaScript in a browser *relies* on DNS resolution to make network requests. The mock resolver would be used in testing environments to control how these DNS lookups behave, thereby influencing the behavior of JavaScript making network requests (e.g., testing error handling when a DNS lookup fails).

* **Input/Output Examples:** Concrete examples are needed to illustrate the rules in action. Define a rule (e.g., "example.com" resolves to 127.0.0.1) and show how a resolution request for "example.com" would produce that IP address. Include failure and timeout scenarios.

* **User Errors:** Think about common mistakes developers might make when *using* this mock resolver in their tests. Forgetting to add rules, adding overlapping rules, or not understanding the matching logic are potential issues.

* **Debugging Context:** How does someone end up looking at this code?  Likely while debugging a networking issue in a Chromium component or while writing tests that use this mock resolver. Trace back from a user action (typing a URL, clicking a link) through the browser's network stack.

* **Summary:** Condense the key functionalities into a few concise points. Emphasize its role in testing and simulation.

**4. Structuring the Analysis:**

Organize the findings into the categories requested:

* **Functionality:**  List the core features.
* **JavaScript Relationship:** Explain the indirect connection through the browser's networking stack and testing.
* **Logical Reasoning:** Provide clear input/output examples.
* **Common Errors:**  Describe potential pitfalls.
* **User Journey (Debugging):** Outline the steps leading to this code.
* **Summary:**  Offer a concise overview.

**5. Language and Clarity:**

Use clear and concise language. Avoid jargon where possible, or explain it. Use bullet points and code formatting to improve readability.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  "Maybe this directly interacts with V8 (the JavaScript engine)."  **Correction:**  The interaction is more indirect, through the browser's networking layer. The mock resolver influences how network requests initiated by JavaScript behave.
* **Initial example:** A simple success case. **Refinement:** Add examples for failure and timeout to demonstrate the full range of its capabilities.
* **Initial user error:**  A general statement. **Refinement:** Provide specific examples of common mistakes.

By following this structured thought process, including iterative refinement and focusing on the specific aspects requested in the prompt, we can arrive at a comprehensive and accurate analysis of the `mock_host_resolver.cc` code.
这是对 `net/dns/mock_host_resolver.cc` 文件第一部分的分析和功能归纳。

**文件功能概览:**

`mock_host_resolver.cc` 文件定义了一个用于模拟 DNS 主机解析器的类 `MockHostResolverBase` 及其相关辅助类。这个模拟解析器主要用于测试环境中，允许开发者控制 DNS 解析的行为，而无需依赖真实的 DNS 服务器。它可以模拟成功的解析、失败的解析、超时等各种情况，并允许预先定义主机名和 IP 地址之间的映射关系。

**具体功能列表:**

1. **模拟 DNS 解析:**
   - 允许为特定的主机名配置预期的 IP 地址或错误。
   - 可以模拟解析成功并返回预定义的 IP 地址列表。
   - 可以模拟解析失败，返回特定的网络错误代码（例如 `ERR_NAME_NOT_RESOLVED`）。
   - 可以模拟解析超时（`ERR_DNS_TIMED_OUT`）。

2. **规则配置 (`RuleResolver`):**
   - 使用 `RuleResolver` 类来管理主机名和解析结果之间的映射规则。
   - 规则可以基于主机名模式（使用通配符）。
   - 可以为规则配置成功的 IP 地址列表、别名 (canonical name)、或错误代码。
   - 允许添加针对特定 IP 地址的规则。
   - 可以清空所有已配置的规则。

3. **缓存模拟 (`HostCache`):**
   - 可以配置一个模拟的 DNS 缓存 `HostCache`。
   - 可以将解析结果加载到缓存中，以便后续请求可以使用缓存的结果。
   - 模拟缓存的行为，包括缓存命中和未命中。

4. **异步解析模拟:**
   - 模拟真实的 DNS 解析器的异步行为。
   - 可以让解析请求处于挂起状态，并在稍后手动触发完成。
   - 允许控制异步解析请求的优先级。

5. **不同类型的解析请求:**
   - 支持模拟 `HostResolver::ResolveHostRequest` 用于标准的主机名解析。
   - 支持模拟 `HostResolver::ServiceEndpointRequest` 用于解析服务终结点 (包含 IPv4 和 IPv6 地址)。
   - 支持模拟 `HostResolver::ProbeRequest` 用于模拟 DoH 探测请求。
   - 支持模拟 `HostResolver::MdnsListener` 用于模拟 mDNS 监听器。

6. **mDNS 模拟 (`MdnsListenerImpl`):**
   - 允许模拟 mDNS 监听器，并触发不同类型的 mDNS 结果（地址、文本、主机名、未处理的结果）。

7. **内部状态管理 (`State`):**
   - 使用 `State` 类来管理模拟解析器的内部状态，例如挂起的请求和 DoH 探测请求。

**与 JavaScript 功能的关系及举例:**

`MockHostResolverBase` 自身是用 C++ 编写的，并不直接包含 JavaScript 代码。然而，它在 Chromium 的网络栈中扮演着关键角色，而网络栈是 JavaScript 与互联网交互的桥梁。在测试环境中，`MockHostResolverBase` 可以用来控制 JavaScript 发起的网络请求的 DNS 解析行为。

**举例说明:**

假设一个 JavaScript 应用需要访问 `api.example.com`。在集成测试中，我们可以使用 `MockHostResolverBase` 来模拟 `api.example.com` 的解析结果：

```c++
// 在 C++ 测试代码中：
mock_host_resolver()->AddRule("api.example.com", "127.0.0.1");
```

现在，当 JavaScript 代码尝试访问 `api.example.com` 时（例如通过 `fetch` API），`MockHostResolverBase` 会返回 `127.0.0.1` 作为解析结果，而不是进行真实的 DNS 查询。这允许测试在特定的 IP 地址下，JavaScript 应用的行为是否正确。

**逻辑推理、假设输入与输出:**

**假设输入:**

1. 调用 `AddRule("test.example.com", "192.168.1.1")` 配置规则。
2. 创建一个解析 `test.example.com` 的请求。

**输出:**

当解析请求完成时，会返回 IP 地址 `192.168.1.1`。

**假设输入 (错误情况):**

1. 调用 `AddRule("error.example.com", ERR_NAME_NOT_RESOLVED)` 配置规则，模拟解析失败。
2. 创建一个解析 `error.example.com` 的请求。

**输出:**

解析请求会返回错误码 `ERR_NAME_NOT_RESOLVED`。

**涉及用户或编程常见的使用错误及举例:**

1. **忘记添加规则:** 如果尝试解析一个没有配置规则的主机名，`MockHostResolverBase` 默认会返回错误。
   ```c++
   // 忘记添加规则 for unknown.example.com
   std::unique_ptr<net::HostResolver::ResolveHostRequest> request =
       mock_host_resolver()->CreateRequest(... "unknown.example.com" ...);
   int error = request->Start(callback); // error 将会是 ERR_NAME_NOT_RESOLVED (或其他默认错误)
   ```

2. **规则冲突或覆盖:** 如果添加了多个匹配同一主机名的规则，可能会导致意外的结果，取决于规则添加的顺序和匹配逻辑。需要仔细管理规则，确保意图明确。

3. **异步解析处理不当:** 如果启用了按需解析模式，需要手动调用 `ResolveNow` 或 `ResolveAllPending` 来完成挂起的请求，否则回调不会被触发。

**用户操作如何一步步到达这里作为调试线索:**

1. **用户在浏览器中输入 URL 或点击链接:**  例如，用户输入 `http://test.example.com`。
2. **浏览器发起网络请求:**  浏览器需要知道 `test.example.com` 的 IP 地址才能建立连接。
3. **DNS 解析过程:**  Chromium 的网络栈会启动 DNS 解析。
4. **在测试环境中，使用 `MockHostResolverBase`:** 如果当前运行的是测试环境，并且配置了使用 `MockHostResolverBase`，那么实际的 DNS 查询会被模拟的解析器拦截。
5. **`MockHostResolverBase` 根据规则返回结果:**  如果之前通过 `AddRule` 添加了针对 `test.example.com` 的规则，`MockHostResolverBase` 会根据该规则返回预定义的 IP 地址或错误。
6. **如果出现 DNS 相关问题，开发者可能会查看 `net/dns/mock_host_resolver.cc`:**  例如，如果测试中网络请求失败，开发者可能会检查 `MockHostResolverBase` 的配置，查看是否添加了正确的规则，或者是否存在配置错误。

**功能归纳 (第 1 部分):**

`MockHostResolverBase` 的主要功能是提供一个可编程和可控的 DNS 解析器模拟器，用于 Chromium 网络栈的单元测试和集成测试。它允许开发者定义主机名到 IP 地址的映射规则，模拟成功的和失败的 DNS 解析场景，并控制异步解析的行为。这使得在不依赖真实 DNS 服务器的情况下，可以可靠地测试网络相关的代码逻辑。

### 提示词
```
这是目录为net/dns/mock_host_resolver.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/mock_host_resolver.h"

#include <stdint.h>

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/check_op.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/no_destructor.h"
#include "base/notreached.h"
#include "base/strings/pattern.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/task/single_thread_task_runner.h"
#include "base/threading/platform_thread.h"
#include "base/time/default_tick_clock.h"
#include "base/time/tick_clock.h"
#include "base/time/time.h"
#include "base/types/optional_util.h"
#include "build/build_config.h"
#include "net/base/address_family.h"
#include "net/base/address_list.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/net_export.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/request_priority.h"
#include "net/base/test_completion_callback.h"
#include "net/dns/dns_alias_utility.h"
#include "net/dns/dns_names_util.h"
#include "net/dns/dns_util.h"
#include "net/dns/host_cache.h"
#include "net/dns/host_resolver.h"
#include "net/dns/host_resolver_manager.h"
#include "net/dns/host_resolver_system_task.h"
#include "net/dns/https_record_rdata.h"
#include "net/dns/public/dns_query_type.h"
#include "net/dns/public/host_resolver_results.h"
#include "net/dns/public/host_resolver_source.h"
#include "net/dns/public/mdns_listener_update_type.h"
#include "net/dns/public/resolve_error_info.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/log/net_log_with_source.h"
#include "net/url_request/url_request_context.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "url/scheme_host_port.h"

#if BUILDFLAG(IS_WIN)
#include "net/base/winsock_init.h"
#endif

namespace net {

namespace {

// Cache size for the MockCachingHostResolver.
const unsigned kMaxCacheEntries = 100;
// TTL for the successful resolutions. Failures are not cached.
const unsigned kCacheEntryTTLSeconds = 60;

absl::variant<url::SchemeHostPort, std::string> GetCacheHost(
    const HostResolver::Host& endpoint) {
  if (endpoint.HasScheme()) {
    return endpoint.AsSchemeHostPort();
  }

  return endpoint.GetHostname();
}

std::optional<HostCache::Entry> CreateCacheEntry(
    std::string_view canonical_name,
    const std::vector<HostResolverEndpointResult>& endpoint_results,
    const std::set<std::string>& aliases) {
  std::optional<std::vector<net::IPEndPoint>> ip_endpoints;
  std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>
      endpoint_metadatas;
  for (const auto& endpoint_result : endpoint_results) {
    if (!ip_endpoints) {
      ip_endpoints = endpoint_result.ip_endpoints;
    } else {
      // TODO(crbug.com/40203587): Support caching different IP endpoints
      // resutls.
      CHECK(*ip_endpoints == endpoint_result.ip_endpoints)
          << "Currently caching MockHostResolver only supports same IP "
             "endpoints results.";
    }

    if (!endpoint_result.metadata.supported_protocol_alpns.empty()) {
      endpoint_metadatas.emplace(/*priority=*/1, endpoint_result.metadata);
    }
  }
  DCHECK(ip_endpoints);
  auto endpoint_entry = HostCache::Entry(OK, *ip_endpoints, aliases,
                                         HostCache::Entry::SOURCE_UNKNOWN);
  endpoint_entry.set_canonical_names(std::set{std::string(canonical_name)});
  if (endpoint_metadatas.empty()) {
    return endpoint_entry;
  }
  return HostCache::Entry::MergeEntries(
      HostCache::Entry(OK, std::move(endpoint_metadatas),
                       HostCache::Entry::SOURCE_UNKNOWN),
      endpoint_entry);
}
}  // namespace

int ParseAddressList(std::string_view host_list,
                     std::vector<net::IPEndPoint>* ip_endpoints) {
  ip_endpoints->clear();
  for (std::string_view address : base::SplitStringPiece(
           host_list, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL)) {
    IPAddress ip_address;
    if (!ip_address.AssignFromIPLiteral(address)) {
      LOG(WARNING) << "Not a supported IP literal: " << address;
      return ERR_UNEXPECTED;
    }
    ip_endpoints->push_back(IPEndPoint(ip_address, 0));
  }
  return OK;
}

// Base class for
// MockHostResolverBase::{RequestImpl,ServiceEndpointRequestImpl}.
class MockHostResolverBase::RequestBase {
 public:
  RequestBase(Host request_endpoint,
              const NetworkAnonymizationKey& network_anonymization_key,
              const std::optional<ResolveHostParameters>& optional_parameters,
              base::WeakPtr<MockHostResolverBase> resolver)
      : request_endpoint_(std::move(request_endpoint)),
        network_anonymization_key_(network_anonymization_key),
        parameters_(optional_parameters ? optional_parameters.value()
                                        : ResolveHostParameters()),
        priority_(parameters_.initial_priority),
        host_resolver_flags_(ParametersToHostResolverFlags(parameters_)),
        resolve_error_info_(ResolveErrorInfo(ERR_IO_PENDING)),
        resolver_(resolver) {}

  RequestBase(const RequestBase&) = delete;
  RequestBase& operator=(const RequestBase&) = delete;

  virtual ~RequestBase() {
    if (id_ > 0) {
      if (resolver_) {
        resolver_->DetachRequest(id_);
      }
      id_ = 0;
      resolver_ = nullptr;
    }
  }

  void DetachFromResolver() {
    id_ = 0;
    resolver_ = nullptr;
  }

  void SetError(int error) {
    // Should only be called before request is marked completed.
    DCHECK(!complete_);
    resolve_error_info_ = ResolveErrorInfo(error);
  }

  // Sets `endpoint_results_`, `fixed_up_dns_alias_results_`,
  // `address_results_` and `staleness_` after fixing them up.
  // Also sets `error` to OK.
  void SetEndpointResults(
      std::vector<HostResolverEndpointResult> endpoint_results,
      std::set<std::string> aliases,
      std::optional<HostCache::EntryStaleness> staleness) {
    DCHECK(!complete_);
    DCHECK(!endpoint_results_);
    DCHECK(!parameters_.is_speculative);

    endpoint_results_ = std::move(endpoint_results);
    for (auto& result : *endpoint_results_) {
      result.ip_endpoints = FixupEndPoints(result.ip_endpoints);
    }

    fixed_up_dns_alias_results_ = FixupAliases(aliases);

    // `HostResolver` implementations are expected to provide an `AddressList`
    // result whenever `HostResolverEndpointResult` is also available.
    address_results_ = EndpointResultToAddressList(
        *endpoint_results_, *fixed_up_dns_alias_results_);

    staleness_ = std::move(staleness);

    SetError(OK);
    SetEndpointResultsInternal();
  }

  void OnAsyncCompleted(size_t id, int error) {
    DCHECK_EQ(id_, id);
    id_ = 0;

    // Check that error information has been set and that the top-level error
    // code is valid.
    DCHECK(resolve_error_info_.error != ERR_IO_PENDING);
    DCHECK(error == OK || error == ERR_NAME_NOT_RESOLVED ||
           error == ERR_DNS_NAME_HTTPS_ONLY);

    DCHECK(!complete_);
    complete_ = true;

    DCHECK(callback_);
    std::move(callback_).Run(error);
  }

  const Host& request_endpoint() const { return request_endpoint_; }

  const NetworkAnonymizationKey& network_anonymization_key() const {
    return network_anonymization_key_;
  }

  const ResolveHostParameters& parameters() const { return parameters_; }

  int host_resolver_flags() const { return host_resolver_flags_; }

  size_t id() { return id_; }

  RequestPriority priority() const { return priority_; }

  void set_id(size_t id) {
    DCHECK_GT(id, 0u);
    DCHECK_EQ(0u, id_);

    id_ = id;
  }

  bool complete() { return complete_; }

  // Similar get GetAddressResults() and GetResolveErrorInfo(), but only exposed
  // through the HostResolver::ResolveHostRequest interface, and don't have the
  // DCHECKs that `complete_` is true.
  const std::optional<AddressList>& address_results() const {
    return address_results_;
  }
  ResolveErrorInfo resolve_error_info() const { return resolve_error_info_; }

 protected:
  std::vector<IPEndPoint> FixupEndPoints(
      const std::vector<IPEndPoint>& endpoints) {
    std::vector<IPEndPoint> corrected;
    for (const IPEndPoint& endpoint : endpoints) {
      DCHECK_NE(endpoint.GetFamily(), ADDRESS_FAMILY_UNSPECIFIED);
      if (parameters_.dns_query_type == DnsQueryType::UNSPECIFIED ||
          parameters_.dns_query_type ==
              AddressFamilyToDnsQueryType(endpoint.GetFamily())) {
        if (endpoint.port() == 0) {
          corrected.emplace_back(endpoint.address(),
                                 request_endpoint_.GetPort());
        } else {
          corrected.push_back(endpoint);
        }
      }
    }
    return corrected;
  }

  std::set<std::string> FixupAliases(const std::set<std::string> aliases) {
    if (aliases.empty()) {
      return std::set<std::string>{
          std::string(request_endpoint_.GetHostnameWithoutBrackets())};
    }
    return aliases;
  }

  // Helper method of SetEndpointResults() for subclass specific logic.
  virtual void SetEndpointResultsInternal() {}

  const Host request_endpoint_;
  const NetworkAnonymizationKey network_anonymization_key_;
  const ResolveHostParameters parameters_;
  RequestPriority priority_;
  int host_resolver_flags_;

  std::optional<AddressList> address_results_;
  std::optional<std::vector<HostResolverEndpointResult>> endpoint_results_;
  std::optional<std::set<std::string>> fixed_up_dns_alias_results_;
  std::optional<HostCache::EntryStaleness> staleness_;
  ResolveErrorInfo resolve_error_info_;

  // Used while stored with the resolver for async resolution.  Otherwise 0.
  size_t id_ = 0;

  CompletionOnceCallback callback_;
  // Use a WeakPtr as the resolver may be destroyed while there are still
  // outstanding request objects.
  base::WeakPtr<MockHostResolverBase> resolver_;
  bool complete_ = false;
};

class MockHostResolverBase::RequestImpl
    : public RequestBase,
      public HostResolver::ResolveHostRequest {
 public:
  RequestImpl(Host request_endpoint,
              const NetworkAnonymizationKey& network_anonymization_key,
              const std::optional<ResolveHostParameters>& optional_parameters,
              base::WeakPtr<MockHostResolverBase> resolver)
      : RequestBase(std::move(request_endpoint),
                    network_anonymization_key,
                    optional_parameters,
                    std::move(resolver)) {}

  RequestImpl(const RequestImpl&) = delete;
  RequestImpl& operator=(const RequestImpl&) = delete;

  ~RequestImpl() override = default;

  int Start(CompletionOnceCallback callback) override {
    DCHECK(callback);
    // Start() may only be called once per request.
    DCHECK_EQ(0u, id_);
    DCHECK(!complete_);
    DCHECK(!callback_);
    // Parent HostResolver must still be alive to call Start().
    DCHECK(resolver_);

    int rv = resolver_->Resolve(this);
    DCHECK(!complete_);
    if (rv == ERR_IO_PENDING) {
      DCHECK_GT(id_, 0u);
      callback_ = std::move(callback);
    } else {
      DCHECK_EQ(0u, id_);
      complete_ = true;
    }

    return rv;
  }

  const AddressList* GetAddressResults() const override {
    DCHECK(complete_);
    return base::OptionalToPtr(address_results_);
  }

  const std::vector<HostResolverEndpointResult>* GetEndpointResults()
      const override {
    DCHECK(complete_);
    return base::OptionalToPtr(endpoint_results_);
  }

  const std::vector<std::string>* GetTextResults() const override {
    DCHECK(complete_);
    static const base::NoDestructor<std::vector<std::string>> empty_result;
    return empty_result.get();
  }

  const std::vector<HostPortPair>* GetHostnameResults() const override {
    DCHECK(complete_);
    static const base::NoDestructor<std::vector<HostPortPair>> empty_result;
    return empty_result.get();
  }

  const std::set<std::string>* GetDnsAliasResults() const override {
    DCHECK(complete_);
    return base::OptionalToPtr(fixed_up_dns_alias_results_);
  }

  net::ResolveErrorInfo GetResolveErrorInfo() const override {
    DCHECK(complete_);
    return resolve_error_info_;
  }

  const std::optional<HostCache::EntryStaleness>& GetStaleInfo()
      const override {
    DCHECK(complete_);
    return staleness_;
  }

  void ChangeRequestPriority(RequestPriority priority) override {
    priority_ = priority;
  }
};

class MockHostResolverBase::ServiceEndpointRequestImpl
    : public RequestBase,
      public HostResolver::ServiceEndpointRequest {
 public:
  ServiceEndpointRequestImpl(
      Host request_endpoint,
      const NetworkAnonymizationKey& network_anonymization_key,
      const std::optional<ResolveHostParameters>& optional_parameters,
      base::WeakPtr<MockHostResolverBase> resolver)
      : RequestBase(std::move(request_endpoint),
                    network_anonymization_key,
                    optional_parameters,
                    std::move(resolver)) {}

  ServiceEndpointRequestImpl(const ServiceEndpointRequestImpl&) = delete;
  ServiceEndpointRequestImpl& operator=(const ServiceEndpointRequestImpl&) =
      delete;

  ~ServiceEndpointRequestImpl() override = default;

  // HostResolver::ServiceEndpointRequest implementations:
  int Start(Delegate* delegate) override {
    CHECK(delegate);
    CHECK(!delegate_);
    CHECK_EQ(id_, 0u);
    CHECK(!complete_);
    CHECK(resolver_);

    int rv = resolver_->Resolve(this);
    DCHECK(!complete_);
    if (rv == ERR_IO_PENDING) {
      CHECK_GT(id_, 0u);
      delegate_ = delegate;
      callback_ = base::BindOnce(
          &ServiceEndpointRequestImpl::NotifyDelegateOfCompletion,
          weak_ptr_factory_.GetWeakPtr());
    } else {
      CHECK_EQ(id_, 0u);
      complete_ = true;
    }

    return rv;
  }

  const std::vector<ServiceEndpoint>& GetEndpointResults() override {
    return service_endpoint_results_;
  }

  const std::set<std::string>& GetDnsAliasResults() override {
    if (fixed_up_dns_alias_results_.has_value()) {
      return *fixed_up_dns_alias_results_;
    }
    static const base::NoDestructor<std::set<std::string>> kEmptyDnsAliases;
    return *kEmptyDnsAliases.get();
  }

  bool EndpointsCryptoReady() override { return true; }

  ResolveErrorInfo GetResolveErrorInfo() override {
    return resolve_error_info_;
  }

  void ChangeRequestPriority(RequestPriority priority) override {
    priority_ = priority;
  }

 private:
  void SetEndpointResultsInternal() override {
    if (!endpoint_results_.has_value()) {
      return;
    }

    std::vector<ServiceEndpoint> service_endpoints;
    for (const auto& endpoint : *endpoint_results_) {
      std::vector<IPEndPoint> ipv4_endpoints;
      std::vector<IPEndPoint> ipv6_endpoints;
      for (const auto& ip_endpoint : endpoint.ip_endpoints) {
        if (ip_endpoint.address().IsIPv6()) {
          ipv6_endpoints.emplace_back(ip_endpoint);
        } else {
          ipv4_endpoints.emplace_back(ip_endpoint);
        }
      }
      service_endpoints.emplace_back(std::move(ipv4_endpoints),
                                     std::move(ipv6_endpoints),
                                     endpoint.metadata);
    }

    service_endpoint_results_ = std::move(service_endpoints);
  }

  void NotifyDelegateOfCompletion(int rv) {
    CHECK(delegate_);
    CHECK_NE(rv, ERR_IO_PENDING);
    delegate_.ExtractAsDangling()->OnServiceEndpointRequestFinished(rv);
  }

  raw_ptr<Delegate> delegate_;
  std::vector<ServiceEndpoint> service_endpoint_results_;

  base::WeakPtrFactory<ServiceEndpointRequestImpl> weak_ptr_factory_{this};
};

class MockHostResolverBase::ProbeRequestImpl
    : public HostResolver::ProbeRequest {
 public:
  explicit ProbeRequestImpl(base::WeakPtr<MockHostResolverBase> resolver)
      : resolver_(std::move(resolver)) {}

  ProbeRequestImpl(const ProbeRequestImpl&) = delete;
  ProbeRequestImpl& operator=(const ProbeRequestImpl&) = delete;

  ~ProbeRequestImpl() override {
    if (resolver_) {
      resolver_->state_->ClearDohProbeRequestIfMatching(this);
    }
  }

  int Start() override {
    DCHECK(resolver_);
    resolver_->state_->set_doh_probe_request(this);

    return ERR_IO_PENDING;
  }

 private:
  base::WeakPtr<MockHostResolverBase> resolver_;
};

class MockHostResolverBase::MdnsListenerImpl
    : public HostResolver::MdnsListener {
 public:
  MdnsListenerImpl(const HostPortPair& host,
                   DnsQueryType query_type,
                   base::WeakPtr<MockHostResolverBase> resolver)
      : host_(host), query_type_(query_type), resolver_(resolver) {
    DCHECK_NE(DnsQueryType::UNSPECIFIED, query_type_);
    DCHECK(resolver_);
  }

  ~MdnsListenerImpl() override {
    if (resolver_)
      resolver_->RemoveCancelledListener(this);
  }

  int Start(Delegate* delegate) override {
    DCHECK(delegate);
    DCHECK(!delegate_);
    DCHECK(resolver_);

    delegate_ = delegate;
    resolver_->AddListener(this);

    return OK;
  }

  void TriggerAddressResult(MdnsListenerUpdateType update_type,
                            IPEndPoint address) {
    delegate_->OnAddressResult(update_type, query_type_, std::move(address));
  }

  void TriggerTextResult(MdnsListenerUpdateType update_type,
                         std::vector<std::string> text_records) {
    delegate_->OnTextResult(update_type, query_type_, std::move(text_records));
  }

  void TriggerHostnameResult(MdnsListenerUpdateType update_type,
                             HostPortPair host) {
    delegate_->OnHostnameResult(update_type, query_type_, std::move(host));
  }

  void TriggerUnhandledResult(MdnsListenerUpdateType update_type) {
    delegate_->OnUnhandledResult(update_type, query_type_);
  }

  const HostPortPair& host() const { return host_; }
  DnsQueryType query_type() const { return query_type_; }

 private:
  const HostPortPair host_;
  const DnsQueryType query_type_;

  raw_ptr<Delegate> delegate_ = nullptr;

  // Use a WeakPtr as the resolver may be destroyed while there are still
  // outstanding listener objects.
  base::WeakPtr<MockHostResolverBase> resolver_;
};

MockHostResolverBase::RuleResolver::RuleKey::RuleKey() = default;

MockHostResolverBase::RuleResolver::RuleKey::~RuleKey() = default;

MockHostResolverBase::RuleResolver::RuleKey::RuleKey(const RuleKey&) = default;

MockHostResolverBase::RuleResolver::RuleKey&
MockHostResolverBase::RuleResolver::RuleKey::operator=(const RuleKey&) =
    default;

MockHostResolverBase::RuleResolver::RuleKey::RuleKey(RuleKey&&) = default;

MockHostResolverBase::RuleResolver::RuleKey&
MockHostResolverBase::RuleResolver::RuleKey::operator=(RuleKey&&) = default;

MockHostResolverBase::RuleResolver::RuleResult::RuleResult() = default;

MockHostResolverBase::RuleResolver::RuleResult::RuleResult(
    std::vector<HostResolverEndpointResult> endpoints,
    std::set<std::string> aliases)
    : endpoints(std::move(endpoints)), aliases(std::move(aliases)) {}

MockHostResolverBase::RuleResolver::RuleResult::~RuleResult() = default;

MockHostResolverBase::RuleResolver::RuleResult::RuleResult(const RuleResult&) =
    default;

MockHostResolverBase::RuleResolver::RuleResult&
MockHostResolverBase::RuleResolver::RuleResult::operator=(const RuleResult&) =
    default;

MockHostResolverBase::RuleResolver::RuleResult::RuleResult(RuleResult&&) =
    default;

MockHostResolverBase::RuleResolver::RuleResult&
MockHostResolverBase::RuleResolver::RuleResult::operator=(RuleResult&&) =
    default;

MockHostResolverBase::RuleResolver::RuleResolver(
    std::optional<RuleResultOrError> default_result)
    : default_result_(std::move(default_result)) {}

MockHostResolverBase::RuleResolver::~RuleResolver() = default;

MockHostResolverBase::RuleResolver::RuleResolver(const RuleResolver&) = default;

MockHostResolverBase::RuleResolver&
MockHostResolverBase::RuleResolver::operator=(const RuleResolver&) = default;

MockHostResolverBase::RuleResolver::RuleResolver(RuleResolver&&) = default;

MockHostResolverBase::RuleResolver&
MockHostResolverBase::RuleResolver::operator=(RuleResolver&&) = default;

const MockHostResolverBase::RuleResolver::RuleResultOrError&
MockHostResolverBase::RuleResolver::Resolve(
    const Host& request_endpoint,
    DnsQueryTypeSet request_types,
    HostResolverSource request_source) const {
  for (const auto& rule : rules_) {
    const RuleKey& key = rule.first;
    const RuleResultOrError& result = rule.second;

    if (absl::holds_alternative<RuleKey::NoScheme>(key.scheme) &&
        request_endpoint.HasScheme()) {
      continue;
    }

    if (key.port.has_value() &&
        key.port.value() != request_endpoint.GetPort()) {
      continue;
    }

    DCHECK(!key.query_type.has_value() ||
           key.query_type.value() != DnsQueryType::UNSPECIFIED);
    if (key.query_type.has_value() &&
        !request_types.Has(key.query_type.value())) {
      continue;
    }

    if (key.query_source.has_value() &&
        request_source != key.query_source.value()) {
      continue;
    }

    if (absl::holds_alternative<RuleKey::Scheme>(key.scheme) &&
        (!request_endpoint.HasScheme() ||
         request_endpoint.GetScheme() !=
             absl::get<RuleKey::Scheme>(key.scheme))) {
      continue;
    }

    if (!base::MatchPattern(request_endpoint.GetHostnameWithoutBrackets(),
                            key.hostname_pattern)) {
      continue;
    }

    return result;
  }

  if (default_result_)
    return default_result_.value();

  NOTREACHED() << "Request " << request_endpoint.GetHostname()
               << " did not match any MockHostResolver rules.";
}

void MockHostResolverBase::RuleResolver::ClearRules() {
  rules_.clear();
}

// static
MockHostResolverBase::RuleResolver::RuleResultOrError
MockHostResolverBase::RuleResolver::GetLocalhostResult() {
  HostResolverEndpointResult endpoint;
  endpoint.ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), /*port=*/0)};
  return RuleResult(std::vector{endpoint});
}

void MockHostResolverBase::RuleResolver::AddRule(RuleKey key,
                                                 RuleResultOrError result) {
  // Literals are always resolved to themselves by MockHostResolverBase,
  // consequently we do not support remapping them.
  IPAddress ip_address;
  DCHECK(!ip_address.AssignFromIPLiteral(key.hostname_pattern));

  CHECK(rules_.emplace(std::move(key), std::move(result)).second)
      << "Duplicate rule key";
}

void MockHostResolverBase::RuleResolver::AddRule(RuleKey key,
                                                 std::string_view ip_literal) {
  std::vector<HostResolverEndpointResult> endpoints;
  endpoints.emplace_back();
  CHECK_EQ(ParseAddressList(ip_literal, &endpoints[0].ip_endpoints), OK);
  AddRule(std::move(key), RuleResult(std::move(endpoints)));
}

void MockHostResolverBase::RuleResolver::AddRule(
    std::string_view hostname_pattern,
    RuleResultOrError result) {
  RuleKey key;
  key.hostname_pattern = std::string(hostname_pattern);
  AddRule(std::move(key), std::move(result));
}

void MockHostResolverBase::RuleResolver::AddRule(
    std::string_view hostname_pattern,
    std::string_view ip_literal) {
  std::vector<HostResolverEndpointResult> endpoints;
  endpoints.emplace_back();
  CHECK_EQ(ParseAddressList(ip_literal, &endpoints[0].ip_endpoints), OK);
  AddRule(hostname_pattern, RuleResult(std::move(endpoints)));
}

void MockHostResolverBase::RuleResolver::AddRule(
    std::string_view hostname_pattern,
    Error error) {
  RuleKey key;
  key.hostname_pattern = std::string(hostname_pattern);

  AddRule(std::move(key), error);
}

void MockHostResolverBase::RuleResolver::AddIPLiteralRule(
    std::string_view hostname_pattern,
    std::string_view ip_literal,
    std::string_view canonical_name) {
  RuleKey key;
  key.hostname_pattern = std::string(hostname_pattern);

  std::set<std::string> aliases;
  if (!canonical_name.empty())
    aliases.emplace(canonical_name);

  std::vector<HostResolverEndpointResult> endpoints;
  endpoints.emplace_back();
  CHECK_EQ(ParseAddressList(ip_literal, &endpoints[0].ip_endpoints), OK);
  AddRule(std::move(key), RuleResult(std::move(endpoints), std::move(aliases)));
}

void MockHostResolverBase::RuleResolver::AddIPLiteralRuleWithDnsAliases(
    std::string_view hostname_pattern,
    std::string_view ip_literal,
    std::vector<std::string> dns_aliases) {
  std::vector<HostResolverEndpointResult> endpoints;
  endpoints.emplace_back();
  CHECK_EQ(ParseAddressList(ip_literal, &endpoints[0].ip_endpoints), OK);
  AddRule(hostname_pattern,
          RuleResult(
              std::move(endpoints),
              std::set<std::string>(dns_aliases.begin(), dns_aliases.end())));
}

void MockHostResolverBase::RuleResolver::AddIPLiteralRuleWithDnsAliases(
    std::string_view hostname_pattern,
    std::string_view ip_literal,
    std::set<std::string> dns_aliases) {
  std::vector<std::string> aliases_vector;
  base::ranges::move(dns_aliases, std::back_inserter(aliases_vector));

  AddIPLiteralRuleWithDnsAliases(hostname_pattern, ip_literal,
                                 std::move(aliases_vector));
}

void MockHostResolverBase::RuleResolver::AddSimulatedFailure(
    std::string_view hostname_pattern) {
  AddRule(hostname_pattern, ERR_NAME_NOT_RESOLVED);
}

void MockHostResolverBase::RuleResolver::AddSimulatedTimeoutFailure(
    std::string_view hostname_pattern) {
  AddRule(hostname_pattern, ERR_DNS_TIMED_OUT);
}

void MockHostResolverBase::RuleResolver::AddRuleWithFlags(
    std::string_view host_pattern,
    std::string_view ip_literal,
    HostResolverFlags /*flags*/,
    std::vector<std::string> dns_aliases) {
  std::vector<HostResolverEndpointResult> endpoints;
  endpoints.emplace_back();
  CHECK_EQ(ParseAddressList(ip_literal, &endpoints[0].ip_endpoints), OK);
  AddRule(host_pattern, RuleResult(std::move(endpoints),
                                   std::set<std::string>(dns_aliases.begin(),
                                                         dns_aliases.end())));
}

MockHostResolverBase::State::State() = default;
MockHostResolverBase::State::~State() = default;

MockHostResolverBase::~MockHostResolverBase() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // Sanity check that pending requests are always cleaned up, by waiting for
  // completion, manually cancelling, or calling OnShutdown().
  DCHECK(!state_->has_pending_requests());
}

void MockHostResolverBase::OnShutdown() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // Cancel all pending requests.
  for (auto& request : state_->mutable_requests()) {
    request.second->DetachFromResolver();
  }
  state_->mutable_requests().clear();

  // Prevent future requests by clearing resolution rules and the cache.
  rule_resolver_.ClearRules();
  cache_ = nullptr;

  state_->ClearDohProbeRequest();
}

std::unique_ptr<HostResolver::ResolveHostRequest>
MockHostResolverBase::CreateRequest(
    url::SchemeHostPort host,
    NetworkAnonymizationKey network_anonymization_key,
    NetLogWithSource net_log,
    std::optional<ResolveHostParameters> optional_parameters) {
  return std::make_unique<RequestImpl>(
      Host(std::move(host)), network_anonymization_key, optional_parameters,
      weak_ptr_factory_.GetWeakPtr());
}

std::unique_ptr<HostResolver::ResolveHostRequest>
MockHostResolverBase::CreateRequest(
    const HostPortPair& host,
    const NetworkAnonymizationKey& network_anonymization_key,
    const NetLogWithSource& source_net_log,
    const std::optional<ResolveHostParameters>& optional_parameters) {
  return std::make_unique<RequestImpl>(Host(host), network_anonymization_key,
                                       optional_parameters,
                                       weak_ptr_factory_.GetWeakPtr());
}

std::unique_ptr<HostResolver::ServiceEndpointRequest>
MockHostResolverBase::CreateServiceEndpointRequest(
    Host host,
    NetworkAnonymizationKey network_anonymization_key,
    NetLogWithSource net_log,
    ResolveHostParameters parameters) {
  return std::make_unique<ServiceEndpointRequestImpl>(
      std::move(host), network_anonymization_key, parameters,
      weak_ptr_factory_.GetWeakPtr());
}

std::unique_ptr<HostResolver::ProbeRequest>
MockHostResolverBase::CreateDohProbeRequest() {
  return std::make_unique<ProbeRequestImpl>(weak_ptr_factory_.GetWeakPtr());
}

std::unique_ptr<HostResolver::MdnsListener>
MockHostResolverBase::CreateMdnsListener(const HostPortPair& host,
                                         DnsQueryType query_type) {
  return std::make_unique<MdnsListenerImpl>(host, query_type,
                                            weak_ptr_factory_.GetWeakPtr());
}

HostCache* MockHostResolverBase::GetHostCache() {
  return cache_.get();
}

int MockHostResolverBase::LoadIntoCache(
    absl::variant<url::SchemeHostPort, HostPortPair> endpoint,
    const NetworkAnonymizationKey& network_anonymization_key,
    const std::optional<ResolveHostParameters>& optional_parameters) {
  return LoadIntoCache(Host(std::move(endpoint)), network_anonymization_key,
                       optional_parameters);
}

int MockHostResolverBase::LoadIntoCache(
    const Host& endpoint,
    const NetworkAnonymizationKey& network_anonymization_key,
    const std::optional<ResolveHostParameters>& optional_parameters) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(cache_);

  ResolveHostParameters parameters =
      optional_parameters.value_or(ResolveHostParameters());

  std::vector<HostResolverEndpointResult> endpoints;
  std::set<std::string> aliases;
  std::optional<HostCache::EntryStaleness> stale_info;
  int rv = ResolveFromIPLiteralOrCache(
      endpoint, network_anonymization_key, parameters.dns_query_type,
      ParametersToHostResolverFlags(parameters), parameters.source,
      parameters.cache_usage, &endpoints, &aliases, &stale_info);
  if (rv != ERR_DNS_CACHE_MISS) {
    // Request already in cache (or IP literal). No need to load it.
    return rv;
  }

  // Just like the real resolver, refuse to do anything with invalid
  // hostnames.
  if (!dns_names_util::IsValidDnsName(endpoint.GetHostnameWithoutBrackets()))
    return ERR_NAME_NOT_RESOLVED;

  RequestImpl request(endpoint, network_anonymization_key, optional_parameters,
                      weak_ptr_factory_.GetWeakPtr());
  return DoSynchronousResolution(request);
}

void MockHostResolverBase::ResolveAllPending() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(ondemand_mode_);
  for (auto& [id, request] : state_->mutable_requests()) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&MockHostResolverBase::ResolveNow,
                                  weak_ptr_factory_.GetWeakPtr(), id));
  }
}

size_t MockHostResolverBase::last_id() {
  if (!has_pending_requests())
    return 0;
  return state_->mutable_requests().rbegin()->first;
}

void MockHostResolverBase::ResolveNow(size_t id) {
  auto it = state_->mutable_requests().find(id);
  if (it == state_->mutable_requests().end())
    return;  // was canceled

  RequestBase* req = it->second;
  state_->mutable_requests().erase(it);

  int error = DoSynchronousResolution(*req);
  req->OnAsyncCompleted(id, error);
}

void MockHostResolverBase::DetachRequest(size_t id) {
  auto it = state_->mutable_requests().find(id);
  CHECK(it != state_->mutable_requests().end());
  state_->mutable_requests().erase(it);
}

std::string_view MockHostResolverBase::request_host(size_t id) {
  DCHECK(request(id));
  return request(id)->request_endpoint().GetHostnameWithoutBrackets();
}

RequestPriority MockHostResolverBase::request_priority(size_t id) {
  DCHECK(request(id));
  return request(id)->priority();
}

const NetworkAnonymizationKey&
MockHostResolverBase::request_network_anonymization_key(size_t id) {
  DCHECK(request(id));
  return request(id)->network_anonymization_key();
}

void MockHostResolverBase::ResolveOnlyRequestNow() {
  DCHECK_EQ(1u, state_->mutable_requests().size());
  ResolveNow(state_->mutable_requests().begin()->first);
}

void MockHostResolverBase::TriggerMdnsListeners(
    const HostPortPair& host,
    DnsQueryType query_type,
    MdnsListenerUpdateType update_type,
    const IPEndPoint& address_result) {
  for (MdnsListenerImpl* listener : listeners_) {
    if (listener->host() == host && listener->query_type() == query_type)
      listener->TriggerAddressResult(update_type, addr
```