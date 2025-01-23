Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The primary request is to analyze the `DnsTaskResultsManager.cc` file, focusing on its functionality, relationship to JavaScript, logic, potential errors, and debugging.

2. **Initial Scan and Keyword Identification:** Quickly read through the code, looking for key terms and structures:
    * Class name: `DnsTaskResultsManager`
    * Members: `delegate_`, `host_`, `query_types_`, `net_log_`, `per_domain_results_`, `current_endpoints_`, `aliases_`, etc.
    * Methods: `ProcessDnsTransactionResults`, `GetCurrentEndpoints`, `UpdateEndpoints`, etc.
    * Data structures: `std::vector`, `std::multimap`, `std::set`, custom structs like `PerDomainResult` and `ServiceEndpoint`.
    * DNS related terms: `DnsQueryType`, `IPEndpoint`, `HTTPSRecordPriority`, `ConnectionEndpointMetadata`.
    * Timing related terms: `base::TimeTicks`, `base::Timer`.
    * Error handling: `net::ERR_NAME_NOT_RESOLVED`.

3. **Identify Core Functionality:** Based on the keywords and structure, determine the main purpose of the class. It manages and organizes results from DNS queries, particularly for service endpoints (SVCB/HTTPS records). The name itself is a big clue. Key responsibilities seem to be:
    * Receiving DNS results.
    * Storing results per domain.
    * Combining IPv4/IPv6 addresses and metadata.
    * Prioritizing endpoints.
    * Notifying a delegate when endpoints are updated.

4. **Analyze Key Methods in Detail:** Focus on the most important methods:
    * `ProcessDnsTransactionResults`: This is the core method for receiving and processing DNS results. Pay attention to how it handles different `DnsQueryType` values (A, AAAA, HTTPS) and different result types (`kData`, `kMetadata`, `kAlias`, `kError`). The logic for handling the AAAA response delay is also important.
    * `UpdateEndpoints`: This method takes the raw DNS results and transforms them into a sorted list of `ServiceEndpoint` objects. Understand the sorting criteria (IPv6 preference, metadata presence).
    * `GetCurrentEndpoints`: Simple accessor for the processed endpoints.

5. **Relationship with JavaScript:**  Consider where this code fits within the browser architecture. DNS resolution is a fundamental network operation. JavaScript interacts with network resources through browser APIs like `fetch()` or `XMLHttpRequest`. The connection isn't direct but indirect:
    * JavaScript initiates a network request.
    * The browser's networking stack (including this code) resolves the hostname.
    * The resolved IP addresses and potentially metadata are used to establish a connection.
    * The JavaScript code receives the response.

6. **Logical Reasoning and Hypothetical Scenarios:** Think about how the code behaves in different situations:
    * What happens if only A records are found?
    * What happens if only AAAA records are found?
    * What happens if both A and AAAA records are found, but AAAA is slow?
    * How is HTTPS metadata handled?
    * What happens with aliases (CNAMEs)?
    * How are errors like `ERR_NAME_NOT_RESOLVED` handled?

7. **User/Programming Errors:**  Consider common mistakes related to DNS and networking:
    * Incorrect DNS configuration on the user's machine.
    * Network connectivity issues.
    * Misconfigured DNS records for a website.
    * Issues with HTTPS record configuration.

8. **Debugging Clues and User Actions:**  Trace how a user action leads to this code being executed:
    * User types a URL in the address bar.
    * JavaScript in a web page makes a `fetch()` call.
    * The browser needs to resolve the hostname in the URL.
    * The `HostResolver` component initiates DNS queries.
    * This `DnsTaskResultsManager` receives and processes the results of those queries.

9. **Structure the Output:** Organize the findings into logical sections based on the prompt's requirements: Functionality, JavaScript relationship, Logic/Hypothetical Scenarios, User/Programming Errors, and Debugging. Use clear and concise language, providing specific examples where needed.

10. **Review and Refine:**  Read through the analysis to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For example, initially, I might focus too much on the internal mechanics. I need to remember to connect it back to the user's experience and JavaScript.

By following this structured approach, you can effectively analyze and understand complex C++ code like this and address all aspects of the prompt. The key is to break down the problem into smaller, manageable parts and build your understanding incrementally.
好的，让我们来分析一下 `net/dns/dns_task_results_manager.cc` 这个文件。

**功能概述**

`DnsTaskResultsManager` 的主要职责是管理和组织来自 DNS 查询任务的结果，特别是针对支持 SVCB (Service Binding) 和 HTTPS 记录的场景。它接收来自 `HostResolverDnsTask` 的 DNS 查询结果，并将这些原始结果组织成更容易使用的 `ServiceEndpoint` 列表。

更具体地说，它的功能包括：

1. **接收和存储 DNS 查询结果：** 它接收来自不同类型的 DNS 查询（例如 A, AAAA, HTTPS）的结果，并将这些结果存储在内部的数据结构中 (`per_domain_results_`)。
2. **处理不同类型的 DNS 记录：** 它能够处理不同类型的 DNS 记录，包括 IP 地址（A 和 AAAA 记录）、HTTPS 记录（包含元数据）和 CNAME 别名记录。
3. **关联元数据和 IP 地址：** 对于 HTTPS 查询，它会将返回的 HTTPS 记录中的元数据（例如优先级、ALPN）与相应的 IP 地址关联起来。
4. **管理 IPv4 和 IPv6 地址：** 它分别存储 IPv4 和 IPv6 地址，并根据一定的策略（例如，优先选择同时支持 IPv6 的端点）对它们进行排序。
5. **处理 AAAA 查询延迟：** 当只收到 A 记录时，它会启动一个定时器，等待 AAAA 记录的响应。如果在超时时间内收到 AAAA 记录，它会更新端点列表。
6. **排序和优先级排序：** 它会对生成的 `ServiceEndpoint` 列表进行排序，优先考虑具有元数据的端点，然后在具有相同元数据或没有元数据的端点之间，优先考虑支持 IPv6 的端点。
7. **别名管理：** 它会跟踪解析过程中遇到的域名别名。
8. **通知代理（Delegate）：** 当服务端点列表更新时，它会通知其代理 (`delegate_`)。

**与 JavaScript 的关系**

`DnsTaskResultsManager` 本身是用 C++ 编写的，属于 Chromium 网络栈的底层实现，**不直接**与 JavaScript 代码交互。 然而，它的功能对 JavaScript 代码通过浏览器发起的网络请求至关重要。

**举例说明：**

当 JavaScript 代码使用 `fetch()` API 或 `XMLHttpRequest` 发起一个网络请求时，浏览器需要解析目标主机名以获取其 IP 地址。  `DnsTaskResultsManager` 就参与了这个过程：

1. JavaScript 发起请求到 `https://example.com`.
2. Chromium 网络栈的更上层模块会请求 `HostResolver` 解析 `example.com`。
3. `HostResolver` 可能会启动多个 DNS 查询任务，包括查询 A 记录、AAAA 记录和 HTTPS 记录。
4. `DnsTaskResultsManager` 会接收这些查询任务的结果，例如：
    * A 记录：`192.0.2.1`
    * AAAA 记录：`2001:db8::1`
    * HTTPS 记录：优先级 1，`alpn="h2"`
5. `DnsTaskResultsManager` 会将这些结果组织成 `ServiceEndpoint` 对象，可能创建一个包含以下信息的条目：
    * `ipv4_endpoints`: `[192.0.2.1:443]`
    * `ipv6_endpoints`: `[2001:db8::1:443]`
    * `metadata`: `priority=1`, `alpn="h2"`
6. 最终，排序后的 `ServiceEndpoint` 列表会被传递回 `HostResolver`，然后被网络栈用于建立与 `example.com` 服务器的连接。

**逻辑推理与假设输入输出**

**假设输入：**

* `host_`:  `example.com:443`
* `query_types_`:  包含 `DnsQueryType::A`, `DnsQueryType::AAAA`, `DnsQueryType::HTTPS`
* 接收到以下 DNS 查询结果：
    * **A 查询 (example.com):**  成功，返回 `192.0.2.1`
    * **AAAA 查询 (example.com):** 成功，返回 `2001:db8::1`
    * **HTTPS 查询 (example.com):** 成功，返回元数据：优先级 1, `alpn="h2"`

**逻辑推理：**

1. `ProcessDnsTransactionResults` 会分别处理 A、AAAA 和 HTTPS 查询的结果。
2. 对于 A 查询，`per_domain_results_["example.com"]` 将包含 IPv4 地址 `192.0.2.1:443`。
3. 对于 AAAA 查询，`per_domain_results_["example.com"]` 将包含 IPv6 地址 `2001:db8::1:443`。
4. 对于 HTTPS 查询，`is_metadata_ready_` 会被设置为 `true`，并且 `per_domain_results_["example.com"]` 的 `metadatas` 将包含优先级为 1 的元数据。
5. `UpdateEndpoints` 方法会被调用。
6. `UpdateEndpoints` 会遍历 `per_domain_results_`，并为 `example.com` 创建 `ServiceEndpoint` 对象。由于存在元数据，它会为每个元数据条目创建一个 `ServiceEndpoint`。
7. 创建的 `ServiceEndpoint` 对象将包含 IPv4 地址、IPv6 地址以及 HTTPS 元数据。
8. 端点列表会被排序，优先考虑具有元数据的端点。

**假设输出（`current_endpoints_`）:**

```
[
  {
    ipv4_endpoints: [192.0.2.1:443],
    ipv6_endpoints: [2001:db8::1:443],
    metadata: { priority: 1, alpn: "h2" }
  }
]
```

**用户或编程常见的使用错误**

`DnsTaskResultsManager` 是 Chromium 内部的网络栈组件，开发者通常不会直接使用或配置它。 然而，与它相关的用户或编程错误可能体现在 DNS 配置或服务器配置方面：

1. **DNS 配置错误：** 用户本地的 DNS 服务器配置不正确，导致无法解析主机名或解析到错误的 IP 地址。这会导致 `DnsTaskResultsManager` 收到错误的结果。
2. **服务器 DNS 记录配置错误：** 网站管理员配置了错误的 DNS 记录，例如：
    * **缺少 A 或 AAAA 记录：** 导致无法解析到 IP 地址。
    * **错误的 IP 地址：** 导致连接到错误的服务器。
    * **错误的 HTTPS 记录：** 例如，优先级设置不当，导致客户端尝试连接到不可用的服务。
3. **网络连接问题：** 用户的网络连接不稳定或存在问题，导致 DNS 查询失败。

**举例说明用户操作导致的错误：**

用户在浏览器地址栏中输入了一个错误的域名，例如 `www.exampllle.com`。 由于该域名不存在，DNS 查询将会失败。 `DnsTaskResultsManager` 会收到一个表示 "域名未解析" 的错误结果 (`ERR_NAME_NOT_RESOLVED`)。  这最终会导致浏览器显示一个 "无法访问此网站" 的错误页面。

**用户操作如何一步步地到达这里（作为调试线索）**

以下是一个用户操作导致 `DnsTaskResultsManager` 工作的典型流程，可以作为调试线索：

1. **用户在浏览器地址栏输入 URL 并按下回车键，或点击一个链接。** 例如，用户输入 `https://www.example.com`.
2. **浏览器解析 URL。**
3. **网络栈发起主机名解析。**  `HostResolver` 组件开始工作。
4. **`HostResolver` 创建 `HostResolverDnsTask`。**  这会启动实际的 DNS 查询。
5. **`HostResolverDnsTask` 向操作系统或配置的 DNS 服务器发送 DNS 查询请求 (A, AAAA, HTTPS)。**
6. **DNS 服务器响应查询。**
7. **`HostResolverDnsTask` 接收 DNS 响应。**
8. **`HostResolverDnsTask` 将解析结果传递给 `DnsTaskResultsManager` 的 `ProcessDnsTransactionResults` 方法。**  这是我们分析的这个文件的关键入口点。
9. **`DnsTaskResultsManager` 处理接收到的结果，存储 IP 地址和元数据。**
10. **当所有相关的 DNS 查询完成或超时后，`DnsTaskResultsManager` 调用 `UpdateEndpoints` 来生成排序后的 `ServiceEndpoint` 列表。**
11. **`DnsTaskResultsManager` 通过 `delegate_` 通知 `HostResolver` 服务端点已更新。**
12. **`HostResolver` 将解析结果（包含 IP 地址和可能的元数据）传递给连接层。**
13. **连接层使用这些信息建立与服务器的 TCP 或 QUIC 连接。**
14. **浏览器开始加载网页内容。**

**调试线索:**

* **网络日志 (NetLog):** Chromium 的 NetLog 是一个强大的调试工具，可以记录网络栈中发生的各种事件，包括 DNS 查询的详细信息、`DnsTaskResultsManager` 处理的结果以及端点更新的时间。通过 NetLog，可以追踪 DNS 查询的整个过程，查看接收到的原始 DNS 响应，以及 `DnsTaskResultsManager` 如何处理这些响应。
* **断点调试：**  在 `DnsTaskResultsManager` 的关键方法（例如 `ProcessDnsTransactionResults` 和 `UpdateEndpoints`）设置断点，可以逐步查看代码的执行流程，检查变量的值，了解 DNS 结果是如何被处理和组织的。
* **查看 `per_domain_results_` 和 `current_endpoints_` 的内容：**  在调试过程中，检查这些内部数据结构的内容可以帮助理解 `DnsTaskResultsManager` 的状态和最终生成的端点列表。

总而言之，`DnsTaskResultsManager` 是 Chromium 网络栈中一个重要的组件，负责有效地管理和组织 DNS 查询结果，特别是对于支持 SVCB 和 HTTPS 记录的现代网络环境至关重要。它不直接与 JavaScript 交互，但其功能是支持浏览器发起网络请求的基础。 理解其工作原理有助于诊断与 DNS 解析相关的网络问题。

### 提示词
```
这是目录为net/dns/dns_task_results_manager.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/dns_task_results_manager.h"

#include <algorithm>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "base/strings/string_number_conversions.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "net/base/connection_endpoint_metadata.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/dns/host_resolver.h"
#include "net/dns/host_resolver_dns_task.h"
#include "net/dns/host_resolver_internal_result.h"
#include "net/dns/https_record_rdata.h"
#include "net/dns/public/dns_query_type.h"
#include "net/dns/public/host_resolver_results.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_with_source.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "url/scheme_host_port.h"

namespace net {

namespace {

// Prioritize with-ipv6 over ipv4-only.
bool CompareServiceEndpointAddresses(const ServiceEndpoint& a,
                                     const ServiceEndpoint& b) {
  const bool a_has_ipv6 = !a.ipv6_endpoints.empty();
  const bool b_has_ipv6 = !b.ipv6_endpoints.empty();
  if ((a_has_ipv6 && b_has_ipv6) || (!a_has_ipv6 && !b_has_ipv6)) {
    return false;
  }

  if (b_has_ipv6) {
    return false;
  }

  return true;
}

// Prioritize with-metadata, with-ipv6 over ipv4-only.
// TODO(crbug.com/41493696): Consider which fields should be prioritized. We
// may want to have different sorting algorithms and choose one via config.
bool CompareServiceEndpoint(const ServiceEndpoint& a,
                            const ServiceEndpoint& b) {
  const bool a_has_metadata = a.metadata != ConnectionEndpointMetadata();
  const bool b_has_metadata = b.metadata != ConnectionEndpointMetadata();
  if (a_has_metadata && b_has_metadata) {
    return CompareServiceEndpointAddresses(a, b);
  }

  if (a_has_metadata) {
    return true;
  }

  if (b_has_metadata) {
    return false;
  }

  return CompareServiceEndpointAddresses(a, b);
}

}  // namespace

// Holds service endpoint results per domain name.
struct DnsTaskResultsManager::PerDomainResult {
  PerDomainResult() = default;
  ~PerDomainResult() = default;

  PerDomainResult(PerDomainResult&&) = default;
  PerDomainResult& operator=(PerDomainResult&&) = default;
  PerDomainResult(const PerDomainResult&) = delete;
  PerDomainResult& operator=(const PerDomainResult&) = delete;

  std::vector<IPEndPoint> ipv4_endpoints;
  std::vector<IPEndPoint> ipv6_endpoints;

  std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata> metadatas;
};

DnsTaskResultsManager::DnsTaskResultsManager(Delegate* delegate,
                                             HostResolver::Host host,
                                             DnsQueryTypeSet query_types,
                                             const NetLogWithSource& net_log)
    : delegate_(delegate),
      host_(std::move(host)),
      query_types_(query_types),
      net_log_(net_log) {
  CHECK(delegate_);
}

DnsTaskResultsManager::~DnsTaskResultsManager() = default;

void DnsTaskResultsManager::ProcessDnsTransactionResults(
    DnsQueryType query_type,
    std::set<const HostResolverInternalResult*> results) {
  CHECK(query_types_.Has(query_type));

  bool should_update_endpoints = false;
  bool should_notify = false;

  if (query_type == DnsQueryType::HTTPS) {
    // Chrome does not yet support HTTPS follow-up queries so metadata is
    // considered ready when the HTTPS response is received.
    CHECK(!is_metadata_ready_);
    is_metadata_ready_ = true;
    should_notify = true;
  }

  if (query_type == DnsQueryType::AAAA) {
    aaaa_response_received_ = true;
    if (resolution_delay_timer_.IsRunning()) {
      resolution_delay_timer_.Stop();
      RecordResolutionDelayResult(/*timedout=*/false);
      // Need to update endpoints when there are IPv4 addresses.
      if (HasIpv4Addresses()) {
        should_update_endpoints = true;
      }
    }
  }

  for (const auto& result : results) {
    aliases_.insert(result->domain_name());

    switch (result->type()) {
      case HostResolverInternalResult::Type::kData: {
        PerDomainResult& per_domain_result =
            GetOrCreatePerDomainResult(result->domain_name());
        for (const auto& ip_endpoint : result->AsData().endpoints()) {
          CHECK_EQ(ip_endpoint.port(), 0);
          // TODO(crbug.com/41493696): This will eventually need to handle
          // DnsQueryType::HTTPS to support getting ipv{4,6}hints.
          if (ip_endpoint.address().IsIPv4()) {
            per_domain_result.ipv4_endpoints.emplace_back(ip_endpoint.address(),
                                                          host_.GetPort());
          } else {
            CHECK(ip_endpoint.address().IsIPv6());
            per_domain_result.ipv6_endpoints.emplace_back(ip_endpoint.address(),
                                                          host_.GetPort());
          }
        }

        should_update_endpoints |= !result->AsData().endpoints().empty();

        break;
      }
      case HostResolverInternalResult::Type::kMetadata: {
        CHECK_EQ(query_type, DnsQueryType::HTTPS);
        for (auto [priority, metadata] : result->AsMetadata().metadatas()) {
          // Associate the metadata with the target name instead of the domain
          // name since the metadata is for the target name.
          PerDomainResult& per_domain_result =
              GetOrCreatePerDomainResult(metadata.target_name);
          per_domain_result.metadatas.emplace(priority, metadata);
        }

        should_update_endpoints |= !result->AsMetadata().metadatas().empty();

        break;
      }
      case net::HostResolverInternalResult::Type::kAlias:
        aliases_.insert(result->AsAlias().alias_target());

        break;
      case net::HostResolverInternalResult::Type::kError:
        // Need to update endpoints when AAAA response is NODATA but A response
        // has at least one valid address.
        // TODO(crbug.com/41493696): Revisit how to handle errors other than
        // NODATA. Currently we just ignore errors here and defer
        // HostResolverManager::Job to create an error result and notify the
        // error to the corresponding requests. This means that if the
        // connection layer has already attempted a connection using an
        // intermediate endpoint, the error might not be treated as fatal. We
        // may want to have a different semantics.
        PerDomainResult& per_domain_result =
            GetOrCreatePerDomainResult(result->domain_name());
        if (query_type == DnsQueryType::AAAA &&
            result->AsError().error() == ERR_NAME_NOT_RESOLVED &&
            !per_domain_result.ipv4_endpoints.empty()) {
          CHECK(per_domain_result.ipv6_endpoints.empty());
          should_update_endpoints = true;
        }

        break;
    }
  }

  const bool waiting_for_aaaa_response =
      query_types_.Has(DnsQueryType::AAAA) && !aaaa_response_received_;
  if (waiting_for_aaaa_response) {
    if (query_type == DnsQueryType::A && should_update_endpoints) {
      // A is responded, start the resolution delay timer.
      CHECK(!resolution_delay_timer_.IsRunning());
      resolution_delay_start_time_ = base::TimeTicks::Now();
      net_log_.BeginEvent(
          NetLogEventType::HOST_RESOLVER_SERVICE_ENDPOINTS_RESOLUTION_DELAY);
      // Safe to unretain since `this` owns the timer.
      resolution_delay_timer_.Start(
          FROM_HERE, kResolutionDelay,
          base::BindOnce(&DnsTaskResultsManager::OnAaaaResolutionTimedout,
                         base::Unretained(this)));
    }

    return;
  }

  if (should_update_endpoints) {
    UpdateEndpoints();
    return;
  }

  if (should_notify && !current_endpoints_.empty()) {
    delegate_->OnServiceEndpointsUpdated();
  }
}

const std::vector<ServiceEndpoint>& DnsTaskResultsManager::GetCurrentEndpoints()
    const {
  return current_endpoints_;
}

const std::set<std::string>& DnsTaskResultsManager::GetAliases() const {
  return aliases_;
}

bool DnsTaskResultsManager::IsMetadataReady() const {
  return !query_types_.Has(DnsQueryType::HTTPS) || is_metadata_ready_;
}

DnsTaskResultsManager::PerDomainResult&
DnsTaskResultsManager::GetOrCreatePerDomainResult(
    const std::string& domain_name) {
  auto it = per_domain_results_.find(domain_name);
  if (it == per_domain_results_.end()) {
    it = per_domain_results_.try_emplace(it, domain_name,
                                         std::make_unique<PerDomainResult>());
  }
  return *it->second;
}

void DnsTaskResultsManager::OnAaaaResolutionTimedout() {
  CHECK(!aaaa_response_received_);
  RecordResolutionDelayResult(/*timedout=*/true);
  UpdateEndpoints();
}

void DnsTaskResultsManager::UpdateEndpoints() {
  std::vector<ServiceEndpoint> new_endpoints;

  for (const auto& [domain_name, per_domain_result] : per_domain_results_) {
    if (per_domain_result->ipv4_endpoints.empty() &&
        per_domain_result->ipv6_endpoints.empty()) {
      continue;
    }

    if (per_domain_result->metadatas.empty()) {
      ServiceEndpoint endpoint;
      endpoint.ipv4_endpoints = per_domain_result->ipv4_endpoints;
      endpoint.ipv6_endpoints = per_domain_result->ipv6_endpoints;
      new_endpoints.emplace_back(std::move(endpoint));
    } else {
      for (const auto& [_, metadata] : per_domain_result->metadatas) {
        ServiceEndpoint endpoint;
        endpoint.ipv4_endpoints = per_domain_result->ipv4_endpoints;
        endpoint.ipv6_endpoints = per_domain_result->ipv6_endpoints;
        // TODO(crbug.com/41493696): Just adding per-domain metadata does not
        // work properly when the target name of HTTPS is an alias, e.g:
        //   example.com.     60 IN CNAME svc.example.com.
        //   svc.example.com. 60 IN AAAA  2001:db8::1
        //   svc.example.com. 60 IN HTTPS 1 example.com alpn="h2"
        // In this case, svc.example.com should have metadata with alpn="h2" but
        // the current logic doesn't do that. To handle it correctly we need to
        // go though an alias tree for the domain name.
        endpoint.metadata = metadata;
        new_endpoints.emplace_back(std::move(endpoint));
      }
    }
  }

  // TODO(crbug.com/41493696): Determine how to handle non-SVCB connection
  // fallback. See https://datatracker.ietf.org/doc/html/rfc9460#section-3-8
  // HostCache::Entry::GetEndpoints() appends a final non-alternative endpoint
  // at the end to ensure that the connection layer can fall back to non-SVCB
  // connection. For ServiceEndpoint request API, the current plan is to handle
  // non-SVCB connection fallback in the connection layer. The approach might
  // not work when Chrome tries to support HTTPS follow-up queries and aliases.

  // Stable sort preserves metadata priorities.
  std::stable_sort(new_endpoints.begin(), new_endpoints.end(),
                   CompareServiceEndpoint);
  current_endpoints_ = std::move(new_endpoints);

  if (current_endpoints_.empty()) {
    return;
  }

  net_log_.AddEvent(NetLogEventType::HOST_RESOLVER_SERVICE_ENDPOINTS_UPDATED,
                    [&] {
                      base::Value::Dict dict;
                      base::Value::List endpoints;
                      for (const auto& endpoint : current_endpoints_) {
                        endpoints.Append(endpoint.ToValue());
                      }
                      dict.Set("endpoints", std::move(endpoints));
                      return dict;
                    });

  delegate_->OnServiceEndpointsUpdated();
}

bool DnsTaskResultsManager::HasIpv4Addresses() {
  for (const auto& [_, per_domain_result] : per_domain_results_) {
    if (!per_domain_result->ipv4_endpoints.empty()) {
      return true;
    }
  }
  return false;
}

void DnsTaskResultsManager::RecordResolutionDelayResult(bool timedout) {
  net_log_.EndEvent(
      NetLogEventType::HOST_RESOLVER_SERVICE_ENDPOINTS_RESOLUTION_DELAY, [&]() {
        base::TimeDelta elapsed =
            base::TimeTicks::Now() - resolution_delay_start_time_;
        base::Value::Dict dict;
        dict.Set("timedout", timedout);
        dict.Set("elapsed", base::NumberToString(elapsed.InMilliseconds()));
        return dict;
      });
}

}  // namespace net
```