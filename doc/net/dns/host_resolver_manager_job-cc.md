Response:
The user wants a summary of the functionality of the `host_resolver_manager_job.cc` file in the Chromium network stack. I need to identify the key responsibilities of the `Job` class within this file. Specifically, I should look for:

1. **Core purpose:** What problem does this class solve?
2. **Key operations:** What are the main actions it performs?
3. **Interactions with other components:** How does it relate to other parts of the networking stack?
4. **Relationship to JavaScript (if any):** Does this code directly impact JavaScript execution?
5. **Logical reasoning:**  Are there conditional flows or decision-making processes that can be represented as input/output scenarios?
6. **Potential user errors:**  Can misconfiguration or incorrect usage lead to this code being executed in unexpected ways?
7. **Debugging context:** How does a user's action lead to this code being executed, which can be useful for debugging?

After analyzing the code, I can see that `HostResolverManager::Job` is central to handling DNS resolution requests. It manages a sequence of asynchronous tasks to resolve a host, taking into account caching, different resolution mechanisms (system resolver, DNS, mDNS), and potential fallbacks.

Here's a possible breakdown of its functionalities:

- **Request Management:** Receiving and managing DNS resolution requests from different parts of Chromium.
- **Task Orchestration:**  Sequencing and executing different resolution tasks (system resolver, DNS, mDNS, cache lookups).
- **Caching:** Interacting with the HostCache to retrieve and store resolution results.
- **Priority Handling:** Managing the priority of resolution requests.
- **Error Handling:** Dealing with resolution failures and potential fallbacks.
- **NetLog Integration:**  Logging events and information for debugging purposes.

Now, let's think about the specific requirements:

- **Functionality List:** This will be a summary of the points above.
- **Relationship with JavaScript:** Indirectly related. JavaScript initiates network requests, which may trigger DNS resolution handled by this code. I can provide an example of a JavaScript `fetch()` call.
- **Logical Reasoning (Input/Output):**  Consider a simple case:  A request comes in, the cache is checked, and then a DNS query is initiated.
    - **Input:** Hostname "example.com", query type A, empty cache.
    - **Output:**  Initiation of a `HostResolverDnsTask`.
- **User/Programming Errors:**  Incorrectly configured DNS settings on the user's system could lead to this code being involved in error handling. A programming error could be requesting resolution for an invalid hostname.
- **User Action to Reach Here:** A user typing a URL into the address bar or a script making a network request.
- **Summary for Part 1:**  Focus on the core responsibilities of managing and orchestrating DNS resolution tasks.
这是 `net/dns/host_resolver_manager_job.cc` 文件的第一部分，主要定义了 `HostResolverManager::Job` 类及其相关的辅助结构和函数。`HostResolverManager::Job` 负责执行单个主机名解析请求，它会协调一系列不同的解析任务（例如系统 DNS 解析、标准的 DNS 查询、mDNS 查询）并管理缓存交互。

**`HostResolverManager::Job` 的主要功能归纳如下：**

1. **管理单个主机名解析请求的生命周期:**  `Job` 对象从创建到完成，负责跟踪解析状态、优先级，以及关联的请求。
2. **协调不同的解析任务:**  根据配置和当前状态，`Job` 决定执行哪些解析任务（例如 `HostResolverSystemTask`，`HostResolverDnsTask`，`HostResolverMdnsTask`，缓存查找）。
3. **处理缓存交互:**  与 `HostCache` 交互，检查缓存中是否存在结果，并将新的解析结果写入缓存。
4. **管理请求优先级:**  维护关联请求的优先级，并根据最高优先级调整自身执行优先级。
5. **处理解析结果和错误:**  接收来自各种解析任务的结果，处理成功和失败的情况，并根据需要进行重试或回退。
6. **管理并发和调度:**  通过 `PrioritizedDispatcher` 管理任务的并发执行和调度。
7. **记录网络日志:**  使用 `NetLog` 记录关键事件，用于调试和性能分析。
8. **处理安全 DNS (Secure DNS):**  支持并协调安全 DNS 的解析流程。
9. **处理 mDNS (Multicast DNS):**  支持本地网络内的主机名解析。
10. **处理 NAT64:**  支持 IPv6 网络中的 IPv4 主机名解析。
11. **关联并通知请求方:**  维护与 `HostResolverManager::RequestImpl` 和 `HostResolverManager::ServiceEndpointRequestImpl` 的关联，并在解析完成时通知它们。

**它与 JavaScript 功能的关系：**

`HostResolverManager::Job` 本身不直接包含 JavaScript 代码或执行 JavaScript。然而，它在网络栈中扮演着关键的角色，直接影响 JavaScript 发起的网络请求的性能和成功率。

**举例说明：**

当 JavaScript 代码执行以下操作时，可能会间接地触发 `HostResolverManager::Job` 的执行：

```javascript
fetch('https://www.example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

**步骤分解：**

1. **JavaScript 发起 `fetch` 请求:**  `fetch` API 调用会创建一个网络请求。
2. **浏览器查找主机名:**  浏览器需要知道 `www.example.com` 的 IP 地址才能建立连接。
3. **DNS 解析启动:**  网络栈的 DNS 解析器开始工作，这可能会涉及到创建一个 `HostResolverManager::Job` 对象来解析 `www.example.com`。
4. **`Job` 执行解析任务:**  `Job` 可能会先检查本地缓存，如果没有找到，则会启动一个或多个 DNS 查询任务。
5. **IP 地址返回:**  一旦解析成功，`Job` 会将 IP 地址返回给请求发起者。
6. **建立 TCP 连接:**  浏览器使用解析得到的 IP 地址与 `www.example.com` 的服务器建立 TCP 连接。
7. **发送 HTTP 请求:**  浏览器发送实际的 HTTP 请求。
8. **接收响应:**  服务器返回 HTTP 响应，`fetch` API 的 Promise 会 resolve。

**逻辑推理与假设输入/输出：**

**假设输入：**

*   请求解析的主机名: `"example.net"`
*   请求的 DNS 查询类型: `DnsQueryType::A` (查找 IPv4 地址)
*   本地 DNS 缓存为空。
*   未启用安全 DNS。

**逻辑推理：**

1. `HostResolverManager` 创建一个新的 `Job` 对象来处理该请求。
2. `Job` 会检查本地 `HostCache`，但由于缓存为空，没有找到结果。
3. `Job` 的任务队列中包含了 `TaskType::SYSTEM` (使用操作系统的 DNS 解析器)。
4. `Job` 启动 `HostResolverSystemTask`。

**假设输出：**

*   `HostResolverSystemTask` 向操作系统发起 DNS 查询。
*   操作系统返回 `"example.net"` 的 IPv4 地址列表。
*   `Job` 接收到 IP 地址列表。
*   `Job` 将结果存储到 `HostCache` 中。
*   `Job` 通知请求方解析成功，并返回 IP 地址列表。

**用户或编程常见的使用错误：**

1. **用户本地 DNS 配置错误:**  如果用户的操作系统 DNS 配置不正确（例如 DNS 服务器地址错误或无法访问），`HostResolverSystemTask` 可能会失败，`Job` 可能会尝试其他任务或最终返回错误 `ERR_NAME_NOT_RESOLVED`。
    *   **用户操作:** 用户手动配置了错误的 DNS 服务器 IP 地址。
    *   **调试线索:** 在 `NetLog` 中会看到 `HostResolverSystemTask` 失败的记录，并可能看到操作系统返回的错误信息。
2. **程序请求解析无效的主机名:**  如果程序传递给 DNS 解析 API 一个格式错误或不存在的主机名，`Job` 会尝试解析，但最终会失败。
    *   **编程错误:** 代码中使用了变量来存储主机名，但该变量的值在特定情况下被设置为了无效字符串（例如空字符串或包含非法字符）。
    *   **调试线索:** `NetLog` 会显示 `Job` 尝试解析该无效主机名，并最终返回 `ERR_NAME_NOT_RESOLVED`。
3. **网络连接问题:**  如果用户的网络连接中断，所有 DNS 解析任务都可能失败。
    *   **用户操作:** 用户断开了网络连接（例如关闭 Wi-Fi）。
    *   **调试线索:** `NetLog` 中会显示多个 DNS 解析任务尝试失败，并可能包含网络相关的错误码。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户在浏览器地址栏输入 URL 并按下回车。**
2. **浏览器解析 URL，提取主机名。**
3. **浏览器的网络组件（例如 `URLRequestContext`）请求 `HostResolverManager` 解析该主机名。**
4. **`HostResolverManager` 查找是否已存在处理该主机名解析的 `Job`。**
5. **如果不存在，`HostResolverManager` 创建一个新的 `Job` 对象。**
6. **`Job` 对象根据配置和当前状态，开始执行一系列的解析任务（例如缓存查找，`HostResolverSystemTask`，`HostResolverDnsTask` 等）。**
7. **如果需要进行系统 DNS 查询，`HostResolverSystemTask` 会被创建和启动。**
8. **如果需要进行标准的 DNS 查询，`HostResolverDnsTask` 会被创建和启动。**

通过查看 `NetLog`，开发者可以跟踪这些步骤，了解是哪个 `Job` 对象处理了特定的解析请求，以及该 `Job` 执行了哪些任务，并最终得到了什么样的结果。这对于诊断 DNS 解析问题非常有用。

Prompt: 
```
这是目录为net/dns/host_resolver_manager_job.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/host_resolver_manager_job.h"

#include <deque>
#include <memory>
#include <optional>
#include <vector>

#include "base/containers/linked_list.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/safe_ref.h"
#include "base/memory/weak_ptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/not_fatal_until.h"
#include "base/task/sequenced_task_runner.h"
#include "base/time/time.h"
#include "net/base/address_family.h"
#include "net/base/features.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/network_handle.h"
#include "net/base/prioritized_dispatcher.h"
#include "net/base/url_util.h"
#include "net/dns/dns_client.h"
#include "net/dns/dns_task_results_manager.h"
#include "net/dns/host_cache.h"
#include "net/dns/host_resolver.h"
#include "net/dns/host_resolver_dns_task.h"
#include "net/dns/host_resolver_internal_result.h"
#include "net/dns/host_resolver_manager.h"
#include "net/dns/host_resolver_manager_request_impl.h"
#include "net/dns/host_resolver_manager_service_endpoint_request_impl.h"
#include "net/dns/host_resolver_mdns_task.h"
#include "net/dns/host_resolver_nat64_task.h"
#include "net/dns/host_resolver_system_task.h"
#include "net/dns/public/dns_query_type.h"
#include "net/dns/public/secure_dns_mode.h"
#include "net/log/net_log_with_source.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "url/url_constants.h"

namespace net {

namespace {

// Default TTL for successful resolutions with HostResolverSystemTask.
const unsigned kCacheEntryTTLSeconds = 60;

// Default TTL for unsuccessful resolutions with HostResolverSystemTask.
const unsigned kNegativeCacheEntryTTLSeconds = 0;

// Minimum TTL for successful resolutions with HostResolverDnsTask.
const unsigned kMinimumTTLSeconds = kCacheEntryTTLSeconds;

// ICANN uses this localhost address to indicate a name collision.
//
// The policy in Chromium is to fail host resolving if it resolves to
// this special address.
//
// Not however that IP literals are exempt from this policy, so it is still
// possible to navigate to http://127.0.53.53/ directly.
//
// For more details: https://www.icann.org/news/announcement-2-2014-08-01-en
const uint8_t kIcanNameCollisionIp[] = {127, 0, 53, 53};

bool ContainsIcannNameCollisionIp(const std::vector<IPEndPoint>& endpoints) {
  for (const auto& endpoint : endpoints) {
    const IPAddress& addr = endpoint.address();
    if (addr.IsIPv4() && IPAddressStartsWith(addr, kIcanNameCollisionIp)) {
      return true;
    }
  }
  return false;
}

// Creates NetLog parameters for HOST_RESOLVER_MANAGER_JOB_ATTACH/DETACH events.
base::Value::Dict NetLogJobAttachParams(const NetLogSource& source,
                                        RequestPriority priority) {
  base::Value::Dict dict;
  source.AddToEventParameters(dict);
  dict.Set("priority", RequestPriorityToString(priority));
  return dict;
}

bool IsSchemeHttpsOrWss(const HostResolver::Host& host) {
  if (!host.HasScheme()) {
    return false;
  }
  const std::string& scheme = host.GetScheme();
  return scheme == url::kHttpsScheme || scheme == url::kWssScheme;
}

}  // namespace

HostResolverManager::JobKey::JobKey(HostResolver::Host host,
                                    ResolveContext* resolve_context)
    : host(std::move(host)), resolve_context(resolve_context->GetWeakPtr()) {}

HostResolverManager::JobKey::~JobKey() = default;

HostResolverManager::JobKey::JobKey(const JobKey& other) = default;
HostResolverManager::JobKey& HostResolverManager::JobKey::operator=(
    const JobKey& other) = default;

bool HostResolverManager::JobKey::operator<(const JobKey& other) const {
  return std::forward_as_tuple(query_types.ToEnumBitmask(), flags, source,
                               secure_dns_mode, &*resolve_context, host,
                               network_anonymization_key) <
         std::forward_as_tuple(other.query_types.ToEnumBitmask(), other.flags,
                               other.source, other.secure_dns_mode,
                               &*other.resolve_context, other.host,
                               other.network_anonymization_key);
}

bool HostResolverManager::JobKey::operator==(const JobKey& other) const {
  return !(*this < other || other < *this);
}

HostCache::Key HostResolverManager::JobKey::ToCacheKey(bool secure) const {
  if (query_types.size() != 1) {
    // This function will produce identical cache keys for `JobKey` structs
    // that differ only in their (non-singleton) `query_types` fields. When we
    // enable new query types, this behavior could lead to subtle bugs. That
    // is why the following DCHECK restricts the allowable query types.
    DCHECK(Difference(query_types, {DnsQueryType::A, DnsQueryType::AAAA,
                                    DnsQueryType::HTTPS})
               .empty());
  }
  const DnsQueryType query_type_for_key = query_types.size() == 1
                                              ? *query_types.begin()
                                              : DnsQueryType::UNSPECIFIED;
  absl::variant<url::SchemeHostPort, std::string> host_for_cache;
  if (host.HasScheme()) {
    host_for_cache = host.AsSchemeHostPort();
  } else {
    host_for_cache = std::string(host.GetHostnameWithoutBrackets());
  }
  HostCache::Key key(std::move(host_for_cache), query_type_for_key, flags,
                     source, network_anonymization_key);
  key.secure = secure;
  return key;
}

handles::NetworkHandle HostResolverManager::JobKey::GetTargetNetwork() const {
  return resolve_context ? resolve_context->GetTargetNetwork()
                         : handles::kInvalidNetworkHandle;
}

HostResolverManager::Job::Job(
    const base::WeakPtr<HostResolverManager>& resolver,
    JobKey key,
    ResolveHostParameters::CacheUsage cache_usage,
    HostCache* host_cache,
    std::deque<TaskType> tasks,
    RequestPriority priority,
    const NetLogWithSource& source_net_log,
    const base::TickClock* tick_clock,
    const HostResolver::HttpsSvcbOptions& https_svcb_options)
    : resolver_(resolver),
      key_(std::move(key)),
      cache_usage_(cache_usage),
      host_cache_(host_cache),
      tasks_(tasks),
      priority_tracker_(priority),
      tick_clock_(tick_clock),
      https_svcb_options_(https_svcb_options),
      net_log_(
          NetLogWithSource::Make(source_net_log.net_log(),
                                 NetLogSourceType::HOST_RESOLVER_IMPL_JOB)) {
  source_net_log.AddEvent(NetLogEventType::HOST_RESOLVER_MANAGER_CREATE_JOB);

  net_log_.BeginEvent(NetLogEventType::HOST_RESOLVER_MANAGER_JOB, [&] {
    return NetLogJobCreationParams(source_net_log.source());
  });

  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
    dns_task_results_manager_ = std::make_unique<DnsTaskResultsManager>(
        this, key_.host, key_.query_types, net_log_);
  }
}

HostResolverManager::Job::~Job() {
  bool was_queued = is_queued();
  bool was_running = is_running();
  // Clean up now for nice NetLog.
  Finish();
  if (was_running) {
    // This Job was destroyed while still in flight.
    net_log_.EndEventWithNetErrorCode(
        NetLogEventType::HOST_RESOLVER_MANAGER_JOB, ERR_ABORTED);
  } else if (was_queued) {
    // Job was cancelled before it could run.
    // TODO(szym): is there any benefit in having this distinction?
    net_log_.AddEvent(NetLogEventType::CANCELLED);
    net_log_.EndEvent(NetLogEventType::HOST_RESOLVER_MANAGER_JOB);
  }
  // else CompleteRequests logged EndEvent.
  while (!requests_.empty()) {
    // Log any remaining Requests as cancelled.
    RequestImpl* req = requests_.head()->value();
    req->RemoveFromList();
    CHECK(key_ == req->GetJobKey());
    req->OnJobCancelled(key_);
  }

  while (!service_endpoint_requests_.empty()) {
    ServiceEndpointRequestImpl* request =
        service_endpoint_requests_.head()->value();
    request->RemoveFromList();
    request->OnJobCancelled();
  }
}

void HostResolverManager::Job::Schedule(bool at_head) {
  DCHECK(!is_queued());
  PrioritizedDispatcher::Handle handle;
  DCHECK(dispatched_);
  if (!at_head) {
    handle = resolver_->dispatcher_->Add(this, priority());
  } else {
    handle = resolver_->dispatcher_->AddAtHead(this, priority());
  }
  // The dispatcher could have started |this| in the above call to Add, which
  // could have called Schedule again. In that case |handle| will be null,
  // but |handle_| may have been set by the other nested call to Schedule.
  if (!handle.is_null()) {
    DCHECK(handle_.is_null());
    handle_ = handle;
  }
}

void HostResolverManager::Job::AddRequest(RequestImpl* request) {
  // Job currently assumes a 1:1 correspondence between ResolveContext and
  // HostCache. Since the ResolveContext is part of the JobKey, any request
  // added to any existing Job should share the same HostCache.
  DCHECK_EQ(host_cache_, request->host_cache());
  // TODO(crbug.com/40181080): Check equality of whole host once Jobs are
  // separated by scheme/port.
  DCHECK_EQ(key_.host.GetHostnameWithoutBrackets(),
            request->request_host().GetHostnameWithoutBrackets());

  request->AssignJob(weak_ptr_factory_.GetSafeRef());

  AddRequestCommon(request->priority(), request->source_net_log(),
                   request->parameters().is_speculative);

  requests_.Append(request);

  UpdatePriority();
}

void HostResolverManager::Job::ChangeRequestPriority(RequestImpl* req,
                                                     RequestPriority priority) {
  DCHECK_EQ(key_.host, req->request_host());

  priority_tracker_.Remove(req->priority());
  req->set_priority(priority);
  priority_tracker_.Add(req->priority());
  UpdatePriority();
}

void HostResolverManager::Job::CancelRequest(RequestImpl* request) {
  DCHECK_EQ(key_.host, request->request_host());
  DCHECK(!requests_.empty());

  CancelRequestCommon(request->priority(), request->source_net_log());

  if (num_active_requests() > 0) {
    UpdatePriority();
    request->RemoveFromList();
  } else {
    // If we were called from a Request's callback within CompleteRequests,
    // that Request could not have been cancelled, so num_active_requests()
    // could not be 0. Therefore, we are not in CompleteRequests().
    CompleteRequestsWithError(ERR_DNS_REQUEST_CANCELLED,
                              /*task_type=*/std::nullopt);
  }
}

void HostResolverManager::Job::AddServiceEndpointRequest(
    ServiceEndpointRequestImpl* request) {
  CHECK_EQ(host_cache_, request->host_cache());

  request->AssignJob(weak_ptr_factory_.GetSafeRef());

  AddRequestCommon(request->priority(), request->net_log(),
                   request->parameters().is_speculative);

  service_endpoint_requests_.Append(request);

  UpdatePriority();
}

void HostResolverManager::Job::CancelServiceEndpointRequest(
    ServiceEndpointRequestImpl* request) {
  CancelRequestCommon(request->priority(), request->net_log());

  if (num_active_requests() > 0) {
    UpdatePriority();
    request->RemoveFromList();
  } else {
    // See comments in CancelRequest().
    CompleteRequestsWithError(ERR_DNS_REQUEST_CANCELLED,
                              /*task_type=*/std::nullopt);
  }
}

void HostResolverManager::Job::ChangeServiceEndpointRequestPriority(
    ServiceEndpointRequestImpl* request,
    RequestPriority priority) {
  priority_tracker_.Remove(request->priority());
  request->set_priority(priority);
  priority_tracker_.Add(request->priority());
  UpdatePriority();
}

void HostResolverManager::Job::Abort() {
  CompleteRequestsWithError(ERR_NETWORK_CHANGED, /*task_type=*/std::nullopt);
}

base::OnceClosure HostResolverManager::Job::GetAbortInsecureDnsTaskClosure(
    int error,
    bool fallback_only) {
  return base::BindOnce(&Job::AbortInsecureDnsTask,
                        weak_ptr_factory_.GetWeakPtr(), error, fallback_only);
}

void HostResolverManager::Job::AbortInsecureDnsTask(int error,
                                                    bool fallback_only) {
  bool has_system_fallback = base::Contains(tasks_, TaskType::SYSTEM);
  if (has_system_fallback) {
    for (auto it = tasks_.begin(); it != tasks_.end();) {
      if (*it == TaskType::DNS) {
        it = tasks_.erase(it);
      } else {
        ++it;
      }
    }
  }

  if (dns_task_ && !dns_task_->secure()) {
    if (has_system_fallback) {
      KillDnsTask();
      dns_task_error_ = OK;
      RunNextTask();
    } else if (!fallback_only) {
      CompleteRequestsWithError(error, /*task_type=*/std::nullopt);
    }
  }
}

void HostResolverManager::Job::OnEvicted() {
  DCHECK(!is_running());
  DCHECK(is_queued());
  handle_.Reset();

  net_log_.AddEvent(NetLogEventType::HOST_RESOLVER_MANAGER_JOB_EVICTED);

  // This signals to CompleteRequests that parts of this job never ran.
  // Job must be saved in |resolver_| to be completed asynchronously.
  // Otherwise the job will be destroyed with requests silently cancelled
  // before completion runs.
  DCHECK(self_iterator_);
  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&Job::CompleteRequestsWithError,
                                weak_ptr_factory_.GetWeakPtr(),
                                ERR_HOST_RESOLVER_QUEUE_TOO_LARGE,
                                /*task_type=*/std::nullopt));
}

bool HostResolverManager::Job::ServeFromHosts() {
  DCHECK_GT(num_active_requests(), 0u);
  std::optional<HostCache::Entry> results = resolver_->ServeFromHosts(
      key_.host.GetHostnameWithoutBrackets(), key_.query_types,
      key_.flags & HOST_RESOLVER_DEFAULT_FAMILY_SET_DUE_TO_NO_IPV6, tasks_);
  if (results) {
    // This will destroy the Job.
    CompleteRequests(results.value(), base::TimeDelta(), true /* allow_cache */,
                     true /* secure */, TaskType::HOSTS);
    return true;
  }
  return false;
}

void HostResolverManager::Job::OnAddedToJobMap(JobMap::iterator iterator) {
  DCHECK(!self_iterator_);
  CHECK(iterator != resolver_->jobs_.end(), base::NotFatalUntil::M130);
  self_iterator_ = iterator;
}

void HostResolverManager::Job::OnRemovedFromJobMap() {
  DCHECK(self_iterator_);
  self_iterator_ = std::nullopt;
}

void HostResolverManager::Job::RunNextTask() {
  // If there are no tasks left to try, cache any stored results and complete
  // the request with the last stored result. All stored results should be
  // errors.
  if (tasks_.empty()) {
    // If there are no stored results, complete with an error.
    if (completion_results_.size() == 0) {
      CompleteRequestsWithError(ERR_NAME_NOT_RESOLVED,
                                /*task_type=*/std::nullopt);
      return;
    }

    // Cache all but the last result here. The last result will be cached
    // as part of CompleteRequests.
    for (size_t i = 0; i < completion_results_.size() - 1; ++i) {
      const auto& result = completion_results_[i];
      DCHECK_NE(OK, result.entry.error());
      MaybeCacheResult(result.entry, result.ttl, result.secure);
    }
    const auto& last_result = completion_results_.back();
    DCHECK_NE(OK, last_result.entry.error());
    CompleteRequests(last_result.entry, last_result.ttl, true /* allow_cache */,
                     last_result.secure,
                     last_result.secure ? TaskType::SECURE_DNS : TaskType::DNS);
    return;
  }

  TaskType next_task = tasks_.front();

  // Schedule insecure DnsTasks and HostResolverSystemTasks with the
  // dispatcher.
  if (!dispatched_ &&
      (next_task == TaskType::DNS || next_task == TaskType::SYSTEM ||
       next_task == TaskType::MDNS)) {
    dispatched_ = true;
    job_running_ = false;
    Schedule(false);
    DCHECK(is_running() || is_queued());

    // Check for queue overflow.
    PrioritizedDispatcher& dispatcher = *resolver_->dispatcher_;
    if (dispatcher.num_queued_jobs() > resolver_->max_queued_jobs_) {
      Job* evicted = static_cast<Job*>(dispatcher.EvictOldestLowest());
      DCHECK(evicted);
      evicted->OnEvicted();
    }
    return;
  }

  if (start_time_ == base::TimeTicks()) {
    net_log_.AddEvent(NetLogEventType::HOST_RESOLVER_MANAGER_JOB_STARTED);
    start_time_ = tick_clock_->NowTicks();
  }
  tasks_.pop_front();
  job_running_ = true;

  switch (next_task) {
    case TaskType::SYSTEM:
      StartSystemTask();
      break;
    case TaskType::DNS:
      StartDnsTask(false /* secure */);
      break;
    case TaskType::SECURE_DNS:
      StartDnsTask(true /* secure */);
      break;
    case TaskType::MDNS:
      StartMdnsTask();
      break;
    case TaskType::INSECURE_CACHE_LOOKUP:
      InsecureCacheLookup();
      break;
    case TaskType::NAT64:
      StartNat64Task();
      break;
    case TaskType::SECURE_CACHE_LOOKUP:
    case TaskType::CACHE_LOOKUP:
    case TaskType::CONFIG_PRESET:
    case TaskType::HOSTS:
      // These task types should have been handled synchronously in
      // ResolveLocally() prior to Job creation.
      NOTREACHED();
  }
}

base::Value::Dict HostResolverManager::Job::NetLogJobCreationParams(
    const NetLogSource& source) {
  base::Value::Dict dict;
  source.AddToEventParameters(dict);
  dict.Set("host", key_.host.ToString());
  base::Value::List query_types_list;
  for (DnsQueryType query_type : key_.query_types) {
    query_types_list.Append(kDnsQueryTypes.at(query_type));
  }
  dict.Set("dns_query_types", std::move(query_types_list));
  dict.Set("secure_dns_mode", base::strict_cast<int>(key_.secure_dns_mode));
  dict.Set("network_anonymization_key",
           key_.network_anonymization_key.ToDebugString());
  return dict;
}

void HostResolverManager::Job::Finish() {
  if (is_running()) {
    // Clean up but don't run any callbacks.
    system_task_ = nullptr;
    KillDnsTask();
    mdns_task_ = nullptr;
    job_running_ = false;

    if (dispatched_) {
      // Job should only ever occupy one slot after any tasks that may have
      // required additional slots, e.g. DnsTask, have been killed, and
      // additional slots are expected to be vacated as part of killing the
      // task.
      DCHECK_EQ(1, num_occupied_job_slots_);
      if (resolver_) {
        resolver_->dispatcher_->OnJobFinished();
      }
      num_occupied_job_slots_ = 0;
    }
  } else if (is_queued()) {
    DCHECK(dispatched_);
    if (resolver_) {
      resolver_->dispatcher_->Cancel(handle_);
    }
    handle_.Reset();
  }
}

void HostResolverManager::Job::KillDnsTask() {
  if (dns_task_) {
    if (dispatched_) {
      while (num_occupied_job_slots_ > 1 || is_queued()) {
        ReduceByOneJobSlot();
      }
    }
    dns_task_.reset();
  }
  dns_task_results_manager_.reset();
}

void HostResolverManager::Job::ReduceByOneJobSlot() {
  DCHECK_GE(num_occupied_job_slots_, 1);
  DCHECK(dispatched_);
  if (is_queued()) {
    if (resolver_) {
      resolver_->dispatcher_->Cancel(handle_);
    }
    handle_.Reset();
  } else if (num_occupied_job_slots_ > 1) {
    if (resolver_) {
      resolver_->dispatcher_->OnJobFinished();
    }
    --num_occupied_job_slots_;
  } else {
    NOTREACHED();
  }
}

void HostResolverManager::Job::AddRequestCommon(
    RequestPriority request_priority,
    const NetLogWithSource& request_net_log,
    bool is_speculative) {
  priority_tracker_.Add(request_priority);
  request_net_log.AddEventReferencingSource(
      NetLogEventType::HOST_RESOLVER_MANAGER_JOB_ATTACH, net_log_.source());
  net_log_.AddEvent(
      NetLogEventType::HOST_RESOLVER_MANAGER_JOB_REQUEST_ATTACH, [&] {
        return NetLogJobAttachParams(request_net_log.source(), priority());
      });
  if (!is_speculative) {
    had_non_speculative_request_ = true;
  }
}

void HostResolverManager::Job::CancelRequestCommon(
    RequestPriority request_priority,
    const NetLogWithSource& request_net_log) {
  priority_tracker_.Remove(request_priority);
  net_log_.AddEvent(
      NetLogEventType::HOST_RESOLVER_MANAGER_JOB_REQUEST_DETACH, [&] {
        return NetLogJobAttachParams(request_net_log.source(), priority());
      });
}

void HostResolverManager::Job::UpdatePriority() {
  if (is_queued()) {
    handle_ = resolver_->dispatcher_->ChangePriority(handle_, priority());
  }
}

void HostResolverManager::Job::Start() {
  handle_.Reset();
  ++num_occupied_job_slots_;

  if (num_occupied_job_slots_ >= 2) {
    if (!dns_task_) {
      resolver_->dispatcher_->OnJobFinished();
      return;
    }
    StartNextDnsTransaction();
    DCHECK_EQ(num_occupied_job_slots_,
              dns_task_->num_transactions_in_progress());
    if (dns_task_->num_additional_transactions_needed() >= 1) {
      Schedule(true);
    }
    return;
  }

  DCHECK(!is_running());
  DCHECK(!tasks_.empty());
  RunNextTask();
  // Caution: Job::Start must not complete synchronously.
}

void HostResolverManager::Job::StartSystemTask() {
  DCHECK(dispatched_);
  DCHECK_EQ(1, num_occupied_job_slots_);
  DCHECK(HasAddressType(key_.query_types));

  std::optional<HostResolverSystemTask::CacheParams> cache_params;
  if (key_.resolve_context->host_resolver_cache()) {
    cache_params.emplace(*key_.resolve_context->host_resolver_cache(),
                         key_.network_anonymization_key);
  }

  system_task_ = HostResolverSystemTask::Create(
      std::string(key_.host.GetHostnameWithoutBrackets()),
      HostResolver::DnsQueryTypeSetToAddressFamily(key_.query_types),
      key_.flags, resolver_->host_resolver_system_params_, net_log_,
      key_.GetTargetNetwork(), std::move(cache_params));

  // Start() could be called from within Resolve(), hence it must NOT directly
  // call OnSystemTaskComplete, for example, on synchronous failure.
  system_task_->Start(base::BindOnce(&Job::OnSystemTaskComplete,
                                     base::Unretained(this),
                                     tick_clock_->NowTicks()));
}

void HostResolverManager::Job::OnSystemTaskComplete(
    base::TimeTicks start_time,
    const AddressList& addr_list,
    int /*os_error*/,
    int net_error) {
  DCHECK(system_task_);

  base::TimeDelta duration = tick_clock_->NowTicks() - start_time;
  if (net_error == OK) {
    UMA_HISTOGRAM_LONG_TIMES_100("Net.DNS.SystemTask.SuccessTime", duration);
  } else {
    UMA_HISTOGRAM_LONG_TIMES_100("Net.DNS.SystemTask.FailureTime", duration);
  }

  if (dns_task_error_ != OK && net_error == OK) {
    // This HostResolverSystemTask was a fallback resolution after a failed
    // insecure DnsTask.
    resolver_->OnFallbackResolve(dns_task_error_);
  }

  if (ContainsIcannNameCollisionIp(addr_list.endpoints())) {
    net_error = ERR_ICANN_NAME_COLLISION;
  }

  base::TimeDelta ttl = base::Seconds(kNegativeCacheEntryTTLSeconds);
  if (net_error == OK) {
    ttl = base::Seconds(kCacheEntryTTLSeconds);
  }

  auto aliases = std::set<std::string>(addr_list.dns_aliases().begin(),
                                       addr_list.dns_aliases().end());

  // Source unknown because the system resolver could have gotten it from a
  // hosts file, its own cache, a DNS lookup or somewhere else.
  // Don't store the |ttl| in cache since it's not obtained from the server.
  CompleteRequests(
      HostCache::Entry(
          net_error,
          net_error == OK ? addr_list.endpoints() : std::vector<IPEndPoint>(),
          std::move(aliases), HostCache::Entry::SOURCE_UNKNOWN),
      ttl, /*allow_cache=*/true, /*secure=*/false, TaskType::SYSTEM);
}

void HostResolverManager::Job::InsecureCacheLookup() {
  // Insecure cache lookups for requests allowing stale results should have
  // occurred prior to Job creation.
  DCHECK(cache_usage_ != ResolveHostParameters::CacheUsage::STALE_ALLOWED);
  std::optional<HostCache::EntryStaleness> stale_info;
  std::optional<HostCache::Entry> resolved = resolver_->MaybeServeFromCache(
      host_cache_, key_.ToCacheKey(/*secure=*/false), cache_usage_,
      false /* ignore_secure */, net_log_, &stale_info);

  if (resolved) {
    DCHECK(stale_info);
    DCHECK(!stale_info.value().is_stale());
    CompleteRequestsWithoutCache(resolved.value(), std::move(stale_info),
                                 TaskType::INSECURE_CACHE_LOOKUP);
  } else {
    RunNextTask();
  }
}

void HostResolverManager::Job::StartDnsTask(bool secure) {
  DCHECK_EQ(secure, !dispatched_);
  DCHECK_EQ(dispatched_ ? 1 : 0, num_occupied_job_slots_);
  DCHECK(!resolver_->ShouldForceSystemResolverDueToTestOverride());

  // Need to create the task even if we're going to post a failure instead of
  // running it, as a "started" job needs a task to be properly cleaned up.
  dns_task_ = std::make_unique<HostResolverDnsTask>(
      resolver_->dns_client_.get(), key_.host, key_.network_anonymization_key,
      key_.query_types, &*key_.resolve_context, secure, key_.secure_dns_mode,
      this, net_log_, tick_clock_, !tasks_.empty() /* fallback_available */,
      https_svcb_options_);
  dns_task_->StartNextTransaction();
  // Schedule a second transaction, if needed. DoH queries can bypass the
  // dispatcher and start all of their transactions immediately.
  if (secure) {
    while (dns_task_->num_additional_transactions_needed() >= 1) {
      dns_task_->StartNextTransaction();
    }
    DCHECK_EQ(dns_task_->num_additional_transactions_needed(), 0);
  } else if (dns_task_->num_additional_transactions_needed() >= 1) {
    Schedule(true);
  }
}

void HostResolverManager::Job::StartNextDnsTransaction() {
  DCHECK(dns_task_);
  DCHECK_EQ(dns_task_->secure(), !dispatched_);
  DCHECK(!dispatched_ || num_occupied_job_slots_ ==
                             dns_task_->num_transactions_in_progress() + 1);
  DCHECK_GE(dns_task_->num_additional_transactions_needed(), 1);
  dns_task_->StartNextTransaction();
}

void HostResolverManager::Job::OnDnsTaskFailure(
    const base::WeakPtr<HostResolverDnsTask>& dns_task,
    base::TimeDelta duration,
    bool allow_fallback,
    const HostCache::Entry& failure_results,
    bool secure) {
  DCHECK_NE(OK, failure_results.error());

  if (!secure) {
    DCHECK_NE(key_.secure_dns_mode, SecureDnsMode::kSecure);
    UMA_HISTOGRAM_LONG_TIMES_100("Net.DNS.InsecureDnsTask.FailureTime",
                                 duration);
  }

  if (!dns_task) {
    return;
  }

  UMA_HISTOGRAM_LONG_TIMES_100("Net.DNS.JobQueueTime.Failure",
                               total_transaction_time_queued_);

  // If one of the fallback tasks doesn't complete the request, store a result
  // to use during request completion.
  base::TimeDelta ttl =
      failure_results.has_ttl() ? failure_results.ttl() : base::Seconds(0);
  completion_results_.push_back({failure_results, ttl, secure});

  dns_task_error_ = failure_results.error();
  KillDnsTask();

  if (!allow_fallback) {
    tasks_.clear();
  }

  RunNextTask();
}

void HostResolverManager::Job::OnDnsTaskComplete(
    base::TimeTicks start_time,
    bool allow_fallback,
    HostResolverDnsTask::Results results,
    bool secure) {
  DCHECK(dns_task_);

  HostCache::Entry legacy_results(results, base::Time::Now(),
                                  tick_clock_->NowTicks(),
                                  HostCache::Entry::SOURCE_DNS);

  // Tasks containing address queries are only considered successful overall
  // if they find address results. However, DnsTask may claim success if any
  // transaction, e.g. a supplemental HTTPS transaction, finds results.
  DCHECK(!key_.query_types.Has(DnsQueryType::UNSPECIFIED));
  if (HasAddressType(key_.query_types) && legacy_results.error() == OK &&
      legacy_results.ip_endpoints().empty()) {
    legacy_results.set_error(ERR_NAME_NOT_RESOLVED);
  }

  base::TimeDelta duration = tick_clock_->NowTicks() - start_time;
  if (legacy_results.error() != OK) {
    OnDnsTaskFailure(dns_task_->AsWeakPtr(), duration, allow_fallback,
                     legacy_results, secure);
    return;
  }

  UMA_HISTOGRAM_LONG_TIMES_100("Net.DNS.DnsTask.SuccessTime", duration);

  UMA_HISTOGRAM_LONG_TIMES_100("Net.DNS.JobQueueTime.Success",
                               total_transaction_time_queued_);

  // Reset the insecure DNS failure counter if an insecure DnsTask completed
  // successfully.
  if (!secure) {
    resolver_->dns_client_->ClearInsecureFallbackFailures();
  }

  base::TimeDelta bounded_ttl =
      std::max(legacy_results.ttl(), base::Seconds(kMinimumTTLSeconds));

  if (ContainsIcannNameCollisionIp(legacy_results.ip_endpoints())) {
    CompleteRequestsWithError(ERR_ICANN_NAME_COLLISION,
                              secure ? TaskType::SECURE_DNS : TaskType::DNS);
    return;
  }

  CompleteRequests(legacy_results, bounded_ttl, true /* allow_cache */, secure,
                   secure ? TaskType::SECURE_DNS : TaskType::DNS);
}

void HostResolverManager::Job::OnIntermediateTransactionsComplete(
    std::optional<HostResolverDnsTask::SingleTransactionResults>
        single_transaction_results) {
  if (dispatched_) {
    DCHECK_GE(num_occupied_job_slots_,
              dns_task_->num_transactions_in_progress());
    int unused_slots =
        num_occupied_job_slots_ - dns_task_->num_transactions_in_progress();

    // Reuse vacated slots for any remaining transactions.
    while (unused_slots > 0 &&
           dns_task_->num_additional_transactions_needed() > 0) {
      dns_task_->StartNextTransaction();
      --unused_slots;
    }

    // If all remaining transactions found a slot, no more needed from the
    // dispatcher.
    if (is_queued() && dns_task_->num_additional_transactions_needed() == 0) {
      resolver_->dispatcher_->Cancel(handle_);
      handle_.Reset();
    }

    // Relinquish any remaining extra slots.
    while (unused_slots > 0) {
      ReduceByOneJobSlot();
      --unused_slots;
    }
  } else if (dns_task_->num_additional_transactions_needed() >= 1) {
    dns_task_->StartNextTransaction();
  }

  if (dns_task_results_manager_ && single_transaction_results.has_value()) {
    dns_task_results_manager_->ProcessDnsTransactionResults(
        single_transaction_results->query_type,
        std::move(single_transaction_results->results));
    // `this` may be deleted. Do not add code below.
  }
}

void HostResolverManager::Job::AddTransactionTimeQueued(
    base::TimeDelta time_queued) {
  total_transaction_time_queued_ += time_queued;
}

void HostResolverManager::Job::OnServiceEndpointsUpdated() {
  // Requests could be destroyed while executing callbacks. Post tasks
  // instead of calling callbacks synchronously to prevent requests from being
  // destroyed in the following for loop.
  for (auto* request = service_endpoint_requests_.head();
       request != service_endpoint_requests_.end(); request = request->next()) {
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&ServiceEndpointRequestImpl::OnServiceEndpointsChanged,
                       request->value()->GetWeakPtr()));
  }
}

void HostResolverManager::Job::StartMdnsTask() {
  // No flags are supported for MDNS except
  // HOST_RESOLVER_DEFAULT_FAMILY_SET_DUE_TO_NO_IPV6 (which is not actually an
  // input flag).
  DCHECK_EQ(0, key_.flags & ~HOST_RESOLVER_DEFAULT_FAMILY_SET_DUE_TO_NO_IPV6);

  MDnsClient* client = nullptr;
  int rv = resolver_->GetOrCreateMdnsClient(&client);
  mdns_task_ = std::make_unique<HostResolverMdnsTask>(
      client, std::string(key_.host.GetHostnameWithoutBrackets()),
      key_.query_types);

  if (rv == OK) {
    mdns_task_->Start(
        base::BindOnce(&Job::OnMdnsTaskComplete, base::Unretained(this)));
  } else {
    // Could not create an mDNS client. Since we cannot complete synchronously
    // from here, post a failure without starting the task.
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&Job::OnMdnsImmediateFailure,
                                  weak_ptr_factory_.GetWeakPtr(), rv));
  }
}

void HostResolverManager::Job::OnMdnsTaskComplete() {
  DCHECK(mdns_task_);
  // TODO(crbug.com/40577881): Consider adding MDNS-specific logging.

  HostCache::Entry results = mdns_task_->GetResults();

  if (ContainsIcannNameCollisionIp(results.ip_endpoints())) {
    CompleteRequestsWithError(ERR_ICANN_NAME_COLLISION, TaskType::MDNS);
    return;
  }
  // MDNS uses a separate cache, so skip saving result to cache.
  // TODO(crbug.com/40611558): Consider merging caches.
  CompleteRequestsWithoutCache(results, std::nullopt /* stale_info */,
                               TaskType::MDNS);
}

void HostResolverManager::Job::OnMdnsImmediateFailure(int rv) {
  DCHECK(mdns_task_);
  DCHECK_NE(OK, rv);

  CompleteRequestsWithError(rv, TaskType::MDNS);
}

void HostResolverManager::Job::StartNat64Task() {
  DCHECK(!nat64_task_);
  nat64_task_ = std::make_unique<HostResolve
"""


```