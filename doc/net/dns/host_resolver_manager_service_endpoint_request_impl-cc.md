Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

**1. Initial Skim and Identification of Core Purpose:**

* **Keywords:**  The filename `host_resolver_manager_service_endpoint_request_impl.cc` immediately suggests involvement in DNS resolution, specifically for "service endpoints."  The `HostResolverManager` is a key component in Chrome's network stack.
* **Includes:** The included headers (`net/dns/...`, `net/http/...`, `net/socket/...`, `net/url_request/...`) confirm this is network-related code within the Chromium project.
* **Class Name:** The main class `HostResolverManager::ServiceEndpointRequestImpl` clearly indicates it's an implementation class for a service endpoint request managed by the `HostResolverManager`.

**2. Deeper Dive into Functionality - Method by Method (Conceptual Order):**

* **Constructor:**  Understand the parameters passed to the constructor. These are the inputs needed to initiate a service endpoint resolution: `scheme_host_port`, `network_anonymization_key`, `NetLogWithSource`, `ResolveHostParameters`, `ResolveContext`, `HostResolverManager`, and `tick_clock`. Realize these represent the target host, privacy settings, logging, resolver options, context, manager, and timing.
* **Start():** This looks like the entry point for initiating the resolution process. It takes a `Delegate` as an argument, suggesting an asynchronous operation with a callback mechanism. The initial state `kCheckIPv6Reachability` hints at the first step in the process. Error handling for context shutdown (`ERR_CONTEXT_SHUT_DOWN`) is noted.
* **GetEndpointResults() & GetDnsAliasResults():** These methods provide access to the results of the resolution. Notice the conditional logic based on `finalized_result_` and the `job_`. This implies there are different stages of the resolution process. The TODO about `FixUpDnsAliases()` is a minor observation.
* **EndpointsCryptoReady():**  This function checks if the metadata associated with the endpoints is ready. This likely relates to DNSSEC or similar security features.
* **GetResolveErrorInfo():**  A simple accessor for error information.
* **ChangeRequestPriority():** Allows dynamic adjustment of the resolution priority. The interaction with the `job_` is important.
* **AssignJob():**  This method is called by the `HostResolverManager` to associate a `Job` (likely representing the actual resolution task) with the request.
* **OnJobCompleted():** This is the callback when the resolution job finishes successfully or with an error. The `SetFinalizedResultFromLegacyResults()` call is key – it populates the result data. The error handling and delegate notification are crucial. *Self-deletion potential is a very important observation.*
* **OnJobCancelled():**  Handles the cancellation of the resolution job. Again, delegate notification and self-deletion are potential issues.
* **OnServiceEndpointsChanged():**  This seems to handle updates to the endpoint list during the resolution process, suggesting a streaming or incremental resolution approach.
* **GetWeakPtr():**  Standard practice for managing lifetime and avoiding dangling pointers in asynchronous operations.
* **DoLoop():** This is the core state machine driving the resolution process. The `switch` statement based on `next_state_` is a classic pattern.
* **DoCheckIPv6Reachability() & DoCheckIPv6ReachabilityComplete():**  These states implement an IPv6 reachability check, potentially optimizing the resolution process. The handling of `HostResolverSource::LOCAL_ONLY` is a detail worth noting.
* **DoStartJob():** This state initiates the actual resolution job. The local cache lookup (`ResolveLocally`) is a performance optimization. The creation of a `Job` if the local lookup fails is the next step.
* **OnIOComplete():**  A generic callback for asynchronous operations within the state machine.
* **SetFinalizedResultFromLegacyResults():** This function takes the results from the older `HostCache::Entry` format and converts them into the `ServiceEndpoint` format. The logic for handling IPv4/IPv6 endpoints and the inclusion/exclusion of metadata is important. The comment about non-SVCB endpoints is a crucial detail for understanding potential future changes.
* **LogCancelRequest():** Logs the cancellation event for debugging.
* **GetClientSocketFactory():**  Retrieves the socket factory, which is needed for network operations.

**3. Connecting to JavaScript and User Actions:**

* **JavaScript Connection:**  Think about how DNS resolution is triggered from the browser's perspective. Loading a web page (typing in the address bar, clicking a link), using WebSockets, or making API calls using `fetch()` or `XMLHttpRequest` all involve resolving hostnames.
* **User Actions:**  Trace the user actions that lead to network requests: typing a URL, clicking a link, a website making an API request, etc.
* **Debugging:** Consider how a developer would debug DNS issues. Network inspection tools in the browser's developer console would be the primary tool. The `net-internals` page in Chrome provides much more detailed information about network activity, including DNS resolution.

**4. Identifying Potential Issues and Edge Cases:**

* **Cancellation:**  The asynchronous nature of DNS resolution means cancellation is a common scenario (user navigates away, request times out). The `OnJobCancelled()` method highlights this.
* **Context Shutdown:**  The `ERR_CONTEXT_SHUT_DOWN` check in `Start()` is important for handling browser shutdown scenarios.
* **Caching:**  The interaction with the host cache is crucial for performance. Understanding the different cache levels and how they are consulted is important.
* **Secure DNS:**  The mention of `secure_dns_policy` indicates the code is aware of and potentially handles DNS over HTTPS or DNS over TLS.
* **Network Partitioning:** The `NetworkAnonymizationKey` suggests support for privacy features.

**5. Structuring the Explanation:**

Organize the information logically:

* **Functionality Overview:** Start with a high-level summary of the file's purpose.
* **Key Functions:** Describe the role of each important method.
* **JavaScript Relationship:**  Explain how JavaScript actions trigger this code. Provide concrete examples.
* **Logical Deduction (Assumptions and Outputs):** Create simple scenarios to illustrate the input/output behavior of key methods.
* **Common Errors:** Identify potential issues users or developers might encounter.
* **User Journey and Debugging:** Explain how a user's actions lead to this code and how to debug related problems.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this file *directly* interfaces with JavaScript.
* **Correction:**  Realize it's a lower-level network component. JavaScript interacts with higher-level APIs (`fetch`, etc.), which eventually call into the network stack. The connection is indirect.
* **Initial thought:** Focus only on successful resolution.
* **Correction:**  Recognize the importance of error handling, cancellation, and edge cases.
* **Initial thought:**  Simply list the functions.
* **Correction:** Group related functions and explain the overall workflow and state transitions.

By following this detailed analysis and refinement process, the comprehensive explanation provided previously can be generated. The key is to start broad, dive deep into the code, and then connect it back to the user and developer experience.
这个文件 `net/dns/host_resolver_manager_service_endpoint_request_impl.cc` 是 Chromium 网络栈中负责处理 **服务终端（Service Endpoint）解析请求** 的实现。 它属于 `HostResolverManager` 组件，专门处理需要解析 SRV 记录（Service Resource Record）或 HTTPS 记录（HTTP Service Binding）的请求。

**主要功能：**

1. **发起和管理服务终端解析请求:**  这个类 `ServiceEndpointRequestImpl` 的实例代表一个正在进行的服务终端解析请求。它接收解析目标的主机名、网络匿名化密钥、网络日志、解析参数等信息。

2. **状态管理:** 它使用状态机 (`DoLoop` 函数和相关的 `State` 枚举) 来管理解析请求的生命周期，包括检查 IPv6 可达性、启动解析 Job 等。

3. **与 `HostResolverManager` 交互:**  它与 `HostResolverManager` 紧密协作，例如：
   - 获取 `HostResolverManager` 的弱引用 (`manager_`)。
   - 调用 `HostResolverManager` 的方法来启动实际的解析 Job (`CreateAndStartJobForServiceEndpointRequest`)。
   - 从 `HostResolverManager` 获取本地缓存的结果 (`ResolveLocally`)。
   - 注册和接收解析 Job 完成或取消的通知 (`OnJobCompleted`, `OnJobCancelled`)。

4. **与 `Job` 交互:** 当 `HostResolverManager` 为该请求创建一个解析 Job 时，会调用 `AssignJob` 方法将 `Job` 对象关联到 `ServiceEndpointRequestImpl`。它会监控 `Job` 的状态，并在 `Job` 完成、取消或服务终端更新时收到通知。

5. **处理解析结果:**  当解析 Job 完成时，`OnJobCompleted` 方法会接收解析结果（`HostCache::Entry`）。它会将结果转换为 `ServiceEndpoint` 列表和 DNS 别名，并存储在 `finalized_result_` 中。

6. **处理解析错误:**  如果解析过程中发生错误，会将错误信息存储在 `error_info_` 中。

7. **支持请求取消:**  通过 `CancelServiceEndpointRequest` 方法可以取消正在进行的解析请求。

8. **提供解析结果:**  `GetEndpointResults` 和 `GetDnsAliasResults` 方法用于获取解析到的服务终端列表和 DNS 别名。

9. **通知委托 (Delegate):**  通过 `Delegate` 接口 (`ServiceEndpointRequestImpl::Delegate`) 向调用者报告解析状态的变更，例如解析完成、更新等。

10. **处理 IPv6 可达性:**  在解析之前，它会检查 IPv6 的可达性，这可能会影响解析策略。

11. **支持请求优先级调整:**  `ChangeRequestPriority` 方法允许在请求进行中调整其优先级。

**与 JavaScript 的关系:**

这个 C++ 代码本身不直接与 JavaScript 代码交互。 然而，它所提供的功能是 JavaScript 代码在网络请求过程中所依赖的基础。

**举例说明：**

假设一个 JavaScript 应用程序使用 `fetch` API 请求一个使用 HTTPS 协议的资源，并且服务器配置了 HTTPS 记录（HTTPS RR）。

1. **JavaScript 发起请求:** JavaScript 代码调用 `fetch("https://example.com/api")`。
2. **URL 解析和处理:**  Chromium 浏览器接收到请求，并解析 URL。
3. **服务终端解析:** 由于是 HTTPS 请求，网络栈可能会尝试解析 `_https._tcp.example.com` 的 HTTPS 记录。 这时，`HostResolverManager` 会创建一个 `ServiceEndpointRequestImpl` 的实例来处理这个解析请求。
4. **C++ 代码工作:** `ServiceEndpointRequestImpl` 内部会进行 DNS 查询，获取 HTTPS 记录中定义的服务器地址、端口和其他参数（例如，支持的 ALPN 协议）。
5. **结果返回:** 解析结果（服务终端列表）会通过 `Delegate` 回调传递给 `HostResolverManager`。
6. **连接建立:** 网络栈使用解析到的服务终端信息来建立与服务器的连接。
7. **数据传输:**  最终，JavaScript 代码才能接收到服务器返回的数据。

**逻辑推理（假设输入与输出）：**

**假设输入:**

* `scheme_host_port`: `https://example.com:443`
* `parameters_`:  默认解析参数
* 网络状况：IPv4 和 IPv6 均可达
* DNS 服务器配置： `_https._tcp.example.com` 有有效的 HTTPS 记录

**预期输出（调用 `GetEndpointResults`）：**

一个包含 `ServiceEndpoint` 对象的 `std::vector`，其中包含了从 HTTPS 记录解析出的 IP 地址、端口、ALPN 协议等信息。例如：

```
[
  {
    ipv4_endpoints: [ "203.0.113.1:443" ],
    ipv6_endpoints: [ "2001:db8::1:443" ],
    metadata: {
      alpn: [ "h3", "h2", "http/1.1" ],
      echconfig: ... // 如果有的话
    }
  }
]
```

**假设输入:**

* `scheme_host_port`: `https://no-srv-record.com:443`
* `parameters_`: 默认解析参数
* 网络状况：IPv4 和 IPv6 均可达
* DNS 服务器配置： `_https._tcp.no-srv-record.com` 没有 HTTPS 记录

**预期输出（调用 `GetEndpointResults`）：**

一个包含一个默认 `ServiceEndpoint` 对象的 `std::vector`，其中包含了直接解析 `no-srv-record.com` 得到的 A 或 AAAA 记录的 IP 地址和默认端口 (443)。

```
[
  {
    ipv4_endpoints: [ "192.0.2.1:443" ],
    ipv6_endpoints: [ "2001:db8::2:443" ],
    metadata: {} // 没有额外的 HTTPS 记录信息
  }
]
```

**用户或编程常见的使用错误：**

1. **网络配置错误:** 用户的网络连接存在问题，例如 DNS 服务器无法访问，导致解析失败。这会导致 `ServiceEndpointRequestImpl` 最终报告错误。

2. **DNS 配置错误:**  网站的 DNS 配置不正确，例如缺少必要的 SRV 或 HTTPS 记录，或者记录配置错误。这会导致 `ServiceEndpointRequestImpl` 无法解析到预期的服务终端。

3. **安全策略阻止:**  某些安全策略或防火墙可能会阻止对特定类型的 DNS 记录的查询，例如 HTTPS 记录。

4. **浏览器缓存:**  浏览器可能会缓存 DNS 解析结果。如果 DNS 记录发生更改，但浏览器仍然使用缓存的结果，可能会导致连接问题。虽然 `ServiceEndpointRequestImpl` 本身不直接处理缓存，但它会受到 `HostCache` 的影响。

5. **代码错误（极少直接影响到这里）：**  虽然不太可能直接由用户的 JavaScript 代码错误触发到这个 C++ 层面，但如果 Chromium 的上层网络代码（例如处理 `fetch` 的代码）使用 `HostResolverManager` 的方式不正确，可能会间接导致问题。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户在浏览器地址栏输入 URL 并回车，或者点击一个链接。**
2. **浏览器解析 URL，确定协议和主机名。**
3. **如果是 HTTPS 或需要 SRV 记录的服务，浏览器会触发服务终端解析。**
4. **Chromium 网络栈的 URLRequest 组件会调用 `HostResolverManager` 来解析主机名。**
5. **`HostResolverManager` 判断需要进行服务终端解析（例如，HTTPS 协议）。**
6. **`HostResolverManager` 创建一个 `ServiceEndpointRequestImpl` 实例来处理这个特定的解析请求.**
7. **`ServiceEndpointRequestImpl` 内部会进行一系列操作，例如检查缓存、发起 DNS 查询等。**
8. **如果需要进行实际的 DNS 查询，`ServiceEndpointRequestImpl` 会与 `DnsClient` 或相关的 DNS 组件交互。**
9. **DNS 查询的结果会被处理，并最终通过 `Delegate` 回调报告给上层组件。**

**调试线索：**

* **使用 Chromium 的 `net-internals` 工具 (`chrome://net-internals/#dns`)**: 可以查看 DNS 查询的详细信息，包括是否发起了 SRV 或 HTTPS 记录的查询，以及查询的结果。
* **查看网络请求日志 (`chrome://net-internals/#events`)**: 可以查看与特定请求相关的网络事件，包括 DNS 解析的开始和结束，以及任何错误信息。
* **使用 DNS 查询工具 (例如 `dig`)**:  可以手动查询 SRV 或 HTTPS 记录，以验证 DNS 服务器的配置是否正确。
* **检查浏览器设置**:  例如，检查是否启用了实验性的 QUIC 协议或 DNS over HTTPS，这些设置可能会影响服务终端解析的行为。
* **断点调试 (对于 Chromium 开发人员):**  可以在 `ServiceEndpointRequestImpl` 的关键方法（例如 `Start`, `OnJobCompleted`, `DoLoop`）设置断点，以跟踪解析请求的执行流程。

总之，`net/dns/host_resolver_manager_service_endpoint_request_impl.cc` 是 Chromium 网络栈中一个关键的组件，负责处理服务终端的 DNS 解析，这是现代网络协议（如 HTTPS）高效、安全连接的基础。虽然 JavaScript 代码不直接操作这个类，但用户的网络行为最终会触发这里的代码执行。

### 提示词
```
这是目录为net/dns/host_resolver_manager_service_endpoint_request_impl.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/dns/host_resolver_manager_service_endpoint_request_impl.h"

#include "base/memory/safe_ref.h"
#include "base/no_destructor.h"
#include "base/notreached.h"
#include "base/types/optional_util.h"
#include "net/base/net_errors.h"
#include "net/dns/dns_alias_utility.h"
#include "net/dns/dns_task_results_manager.h"
#include "net/dns/host_resolver.h"
#include "net/dns/host_resolver_manager.h"
#include "net/dns/public/resolve_error_info.h"
#include "net/http/http_network_session.h"
#include "net/socket/client_socket_factory.h"
#include "net/url_request/url_request_context.h"
#include "url/scheme_host_port.h"

namespace net {

HostResolverManager::ServiceEndpointRequestImpl::FinalizedResult::
    FinalizedResult(std::vector<ServiceEndpoint> endpoints,
                    std::set<std::string> dns_aliases)
    : endpoints(std::move(endpoints)), dns_aliases(std::move(dns_aliases)) {}

HostResolverManager::ServiceEndpointRequestImpl::FinalizedResult::
    ~FinalizedResult() = default;

HostResolverManager::ServiceEndpointRequestImpl::FinalizedResult::
    FinalizedResult(FinalizedResult&&) = default;
HostResolverManager::ServiceEndpointRequestImpl::FinalizedResult&
HostResolverManager::ServiceEndpointRequestImpl::FinalizedResult::operator=(
    FinalizedResult&&) = default;

HostResolverManager::ServiceEndpointRequestImpl::ServiceEndpointRequestImpl(
    url::SchemeHostPort scheme_host_port,
    NetworkAnonymizationKey network_anonymization_key,
    NetLogWithSource net_log,
    ResolveHostParameters parameters,
    base::WeakPtr<ResolveContext> resolve_context,
    base::WeakPtr<HostResolverManager> manager,
    const base::TickClock* tick_clock)
    : host_(std::move(scheme_host_port)),
      network_anonymization_key_(
          NetworkAnonymizationKey::IsPartitioningEnabled()
              ? std::move(network_anonymization_key)
              : NetworkAnonymizationKey()),
      net_log_(std::move(net_log)),
      parameters_(std::move(parameters)),
      resolve_context_(std::move(resolve_context)),
      manager_(std::move(manager)),
      tick_clock_(tick_clock),
      priority_(parameters_.initial_priority) {}

HostResolverManager::ServiceEndpointRequestImpl::~ServiceEndpointRequestImpl() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!job_.has_value()) {
    return;
  }

  LogCancelRequest();

  // Clear the delegate to avoid calling delegate's callback after destruction.
  // The following CancelServiceEndpointRequest() could result in calling
  // OnJobCancelled() synchronously.
  delegate_ = nullptr;

  job_.value()->CancelServiceEndpointRequest(this);
}

int HostResolverManager::ServiceEndpointRequestImpl::Start(Delegate* delegate) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(!delegate_);
  CHECK(manager_);

  if (!resolve_context_) {
    error_info_ = ResolveErrorInfo(ERR_CONTEXT_SHUT_DOWN);
    return ERR_CONTEXT_SHUT_DOWN;
  }

  delegate_ = delegate;

  next_state_ = State::kCheckIPv6Reachability;
  return DoLoop(OK);
}

const std::vector<ServiceEndpoint>&
HostResolverManager::ServiceEndpointRequestImpl::GetEndpointResults() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (finalized_result_.has_value()) {
    return finalized_result_->endpoints;
  }

  if (job_ && job_.value()->dns_task_results_manager()) {
    return job_.value()->dns_task_results_manager()->GetCurrentEndpoints();
  }

  static const base::NoDestructor<std::vector<ServiceEndpoint>> kEmptyEndpoints;
  return *kEmptyEndpoints.get();
}

const std::set<std::string>&
HostResolverManager::ServiceEndpointRequestImpl::GetDnsAliasResults() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (finalized_result_.has_value()) {
    return finalized_result_->dns_aliases;
  }

  if (job_ && job_.value()->dns_task_results_manager()) {
    // TODO(crbug.com/41493696): Call dns_alias_utility::FixUpDnsAliases().
    return job_.value()->dns_task_results_manager()->GetAliases();
  }

  static const base::NoDestructor<std::set<std::string>> kEmptyDnsAliases;
  return *kEmptyDnsAliases.get();
}

bool HostResolverManager::ServiceEndpointRequestImpl::EndpointsCryptoReady() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (finalized_result_.has_value()) {
    return true;
  }

  if (job_) {
    CHECK(job_.value()->dns_task_results_manager());
    return job_.value()->dns_task_results_manager()->IsMetadataReady();
  }

  NOTREACHED();
}

ResolveErrorInfo
HostResolverManager::ServiceEndpointRequestImpl::GetResolveErrorInfo() {
  return error_info_;
}

void HostResolverManager::ServiceEndpointRequestImpl::ChangeRequestPriority(
    RequestPriority priority) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!job_.has_value()) {
    priority_ = priority;
    return;
  }
  job_.value()->ChangeServiceEndpointRequestPriority(this, priority);
}

void HostResolverManager::ServiceEndpointRequestImpl::AssignJob(
    base::SafeRef<Job> job) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(!job_.has_value());
  job_ = job;
}

void HostResolverManager::ServiceEndpointRequestImpl::OnJobCompleted(
    const HostCache::Entry& results,
    bool obtained_securely) {
  CHECK(job_);
  CHECK(delegate_);
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  job_.reset();
  SetFinalizedResultFromLegacyResults(results);

  const bool is_secure_network_error =
      obtained_securely && results.error() != OK;
  error_info_ = ResolveErrorInfo(results.error(), is_secure_network_error);
  delegate_->OnServiceEndpointRequestFinished(
      HostResolver::SquashErrorCode(results.error()));
  // Do not add code below. `this` may be deleted at this point.
}

void HostResolverManager::ServiceEndpointRequestImpl::OnJobCancelled() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(job_);

  job_.reset();

  // The owner of `this` has already destroyed `this`.
  if (!delegate_) {
    return;
  }

  LogCancelRequest();

  finalized_result_ = FinalizedResult(/*endpoints=*/{}, /*dns_aliases=*/{});
  error_info_ = ResolveErrorInfo(ERR_DNS_REQUEST_CANCELLED);
  delegate_->OnServiceEndpointRequestFinished(
      HostResolver::SquashErrorCode(ERR_DNS_REQUEST_CANCELLED));
  // Do not add code below. `this` may be deleted at this point.
}

void HostResolverManager::ServiceEndpointRequestImpl::
    OnServiceEndpointsChanged() {
  // This method is called asynchronously via a posted task. `job_` could
  // be completed or cancelled before executing the task.
  if (finalized_result_.has_value()) {
    return;
  }

  CHECK(job_);
  CHECK(job_.value()->dns_task_results_manager());
  CHECK(delegate_);
  delegate_->OnServiceEndpointsUpdated();
  // Do not add code below. `this` may be deleted at this point.
}

base::WeakPtr<HostResolverManager::ServiceEndpointRequestImpl>
HostResolverManager::ServiceEndpointRequestImpl::GetWeakPtr() {
  return weak_ptr_factory_.GetWeakPtr();
}

int HostResolverManager::ServiceEndpointRequestImpl::DoLoop(int rv) {
  do {
    State state = next_state_;
    next_state_ = State::kNone;
    switch (state) {
      case State::kCheckIPv6Reachability:
        rv = DoCheckIPv6Reachability();
        break;
      case State::kCheckIPv6ReachabilityComplete:
        rv = DoCheckIPv6ReachabilityComplete(rv);
        break;
      case State::kStartJob:
        rv = DoStartJob();
        break;
      case State::kNone:
        NOTREACHED() << "Invalid state";
    }
  } while (next_state_ != State::kNone && rv != ERR_IO_PENDING);

  return rv;
}

int HostResolverManager::ServiceEndpointRequestImpl::DoCheckIPv6Reachability() {
  next_state_ = State::kCheckIPv6ReachabilityComplete;
  // LOCAL_ONLY requires a synchronous response, so it cannot wait on an async
  // reachability check result and cannot make assumptions about reachability.
  // Return ERR_NAME_NOT_RESOLVED when LOCAL_ONLY is specified and the check
  // is blocked. See also the comment in
  // HostResolverManager::RequestImpl::DoIPv6Reachability().
  if (parameters_.source == HostResolverSource::LOCAL_ONLY) {
    int rv = manager_->StartIPv6ReachabilityCheck(
        net_log_, GetClientSocketFactory(), base::DoNothingAs<void(int)>());
    if (rv == ERR_IO_PENDING) {
      next_state_ = State::kNone;
      finalized_result_ = FinalizedResult(/*endpoints=*/{}, /*dns_aliases=*/{});
      error_info_ = ResolveErrorInfo(ERR_NAME_NOT_RESOLVED);
      return ERR_NAME_NOT_RESOLVED;
    }
    return OK;
  }
  return manager_->StartIPv6ReachabilityCheck(
      net_log_, GetClientSocketFactory(),
      base::BindOnce(&ServiceEndpointRequestImpl::OnIOComplete,
                     weak_ptr_factory_.GetWeakPtr()));
}

int HostResolverManager::ServiceEndpointRequestImpl::
    DoCheckIPv6ReachabilityComplete(int rv) {
  next_state_ = rv == OK ? State::kStartJob : State::kNone;
  return rv;
}

int HostResolverManager::ServiceEndpointRequestImpl::DoStartJob() {
  JobKey job_key(host_, resolve_context_.get());
  IPAddress ip_address;
  manager_->InitializeJobKeyAndIPAddress(
      network_anonymization_key_, parameters_, net_log_, job_key, ip_address);

  // Try to resolve locally first.
  std::optional<HostCache::EntryStaleness> stale_info;
  std::deque<TaskType> tasks;
  HostCache::Entry results = manager_->ResolveLocally(
      /*only_ipv6_reachable=*/false, job_key, ip_address,
      parameters_.cache_usage, parameters_.secure_dns_policy,
      parameters_.source, net_log_, host_cache(), &tasks, &stale_info);
  if (results.error() != ERR_DNS_CACHE_MISS ||
      parameters_.source == HostResolverSource::LOCAL_ONLY || tasks.empty()) {
    SetFinalizedResultFromLegacyResults(results);
    error_info_ = ResolveErrorInfo(results.error());
    return results.error();
  }

  manager_->CreateAndStartJobForServiceEndpointRequest(std::move(job_key),
                                                       std::move(tasks), this);
  return ERR_IO_PENDING;
}

void HostResolverManager::ServiceEndpointRequestImpl::OnIOComplete(int rv) {
  DoLoop(rv);
}

void HostResolverManager::ServiceEndpointRequestImpl::
    SetFinalizedResultFromLegacyResults(const HostCache::Entry& results) {
  CHECK(!finalized_result_);
  if (results.error() == OK && !parameters_.is_speculative) {
    std::vector<IPEndPoint> ipv4_endpoints;
    std::vector<IPEndPoint> ipv6_endpoints;
    for (const auto& ip_endpoint : results.ip_endpoints()) {
      std::vector<IPEndPoint>& ip_endpoints =
          ip_endpoint.address().IsIPv6() ? ipv6_endpoints : ipv4_endpoints;
      if (ip_endpoint.port() == 0) {
        ip_endpoints.emplace_back(ip_endpoint.address(), host_.GetPort());
      } else {
        ip_endpoints.emplace_back(ip_endpoint);
      }
    }

    // See HostCache::Entry::GetEndpoints.
    std::vector<ServiceEndpoint> endpoints;
    if (!ipv4_endpoints.empty() || !ipv6_endpoints.empty()) {
      for (const auto& metadata : results.GetMetadatas()) {
        if (!base::Contains(results.canonical_names(), metadata.target_name)) {
          continue;
        }

        ServiceEndpoint endpoint;
        endpoint.ipv4_endpoints = ipv4_endpoints;
        endpoint.ipv6_endpoints = ipv6_endpoints;
        endpoint.metadata = metadata;
        endpoints.emplace_back(std::move(endpoint));
      }

      // Append Non-SVCB endpoints at the end for fallback.
      // TODO(crbug.com/41493696): Revisit how to handle non-SVCB endpoints once
      // the connection layer starts using this API. Adding non-SVCB endpoints
      // here might be inconsistent with intermediate results generated by
      // DnsTaskResultsManager, which doesn't append non-SVCB endpoints.
      ServiceEndpoint non_alternative_endpoint;
      non_alternative_endpoint.ipv4_endpoints = ipv4_endpoints;
      non_alternative_endpoint.ipv6_endpoints = ipv6_endpoints;
      endpoints.emplace_back(std::move(non_alternative_endpoint));
    }

    finalized_result_ =
        FinalizedResult(std::move(endpoints),
                        dns_alias_utility::FixUpDnsAliases(results.aliases()));
  } else {
    finalized_result_ = FinalizedResult(/*endpoints=*/{}, /*dns_aliases=*/{});
  }
}

void HostResolverManager::ServiceEndpointRequestImpl::LogCancelRequest() {
  net_log_.AddEvent(NetLogEventType::CANCELLED);
  net_log_.EndEvent(NetLogEventType::HOST_RESOLVER_MANAGER_REQUEST);
}

ClientSocketFactory*
HostResolverManager::ServiceEndpointRequestImpl::GetClientSocketFactory() {
  if (resolve_context_->url_request_context()) {
    return resolve_context_->url_request_context()
        ->GetNetworkSessionContext()
        ->client_socket_factory;
  }
  return ClientSocketFactory::GetDefaultFactory();
}

}  // namespace net
```