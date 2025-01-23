Response:
Let's break down the thought process for analyzing this `http_stream_pool.cc` file and answering the prompt.

**1. Understanding the Core Functionality (The "What")**

* **Initial Scan:** The filename and the `#include` directives give strong hints. `net/http`, `HttpStreamPool`, `HttpNetworkSession`, `HttpStreamRequest`, `SpdySession`, `QuicSessionPool` all point to managing HTTP connections, especially for performance and optimization.
* **Key Data Structures:**  The presence of `groups_` (a map), and the `Group` class immediately suggests a way to organize connections. The comments about "pool" and "group" are important.
* **Connection Management Concepts:**  Keywords like "idle," "connecting," "handed out," "preconnect," "flush," "close" indicate the lifecycle management of connections.
* **Protocol Support:** Mentions of "Spdy" and "QUIC" clearly indicate support for these protocols alongside HTTP/1.1.
* **Optimization Techniques:**  "Happy Eyeballs V3" and its feature parameters (`kHttpStreamPoolMaxStreamPerPool`, etc.) point to connection establishment optimizations. The mention of alternative services also fits this.
* **Network Awareness:** `NetworkChangeNotifier` suggests reacting to network changes.

**2. Identifying Key Responsibilities (The "Why")**

* **Connection Reuse:** The core purpose is clearly to reuse existing connections to improve performance and reduce latency. This is evident from the "pool" concept.
* **Resource Management:**  Limiting the number of concurrent connections (`max_stream_sockets_per_pool_`, `max_stream_sockets_per_group_`) is crucial for preventing resource exhaustion.
* **Protocol Negotiation:**  Choosing between HTTP/1.1, HTTP/2 (SPDY), and QUIC is a key responsibility.
* **Resilience:** Handling network changes and server configuration updates is important for reliability.
* **Prioritization:**  Serving higher-priority requests first is a desirable feature.

**3. Connecting to JavaScript (The "How" - Indirectly)**

* **Browser Context:**  Realize that this C++ code is part of the Chromium browser. JavaScript running in web pages makes HTTP requests.
* **Abstraction Layers:**  JavaScript doesn't directly interact with this C++ code. There are layers of abstraction. JavaScript uses Web APIs like `fetch()` or `XMLHttpRequest`. These APIs are implemented in C++ in the browser.
* **The Chain of Events:**  JavaScript `fetch()` -> C++ network stack -> `HttpStreamPool` (this file) to manage the underlying connection.
* **Focus on Observable Effects:**  Think about what JavaScript developers *experience* that is influenced by this code: faster page loads, fewer connection errors, the ability to use modern protocols like HTTP/2 and QUIC.

**4. Logic and Hypothetical Scenarios (The "What If")**

* **Preconnect:**  Imagine a webpage knowing it will need resources from a specific server. The browser might pre-establish a connection. Hypothesize the input parameters (target URL, number of connections) and the expected outcome (a connection being established and ready).
* **Max Connections:**  Consider a scenario where a page tries to open many connections to the same server. The `max_stream_sockets_per_pool_` limit would kick in. Hypothesize the input (multiple requests for the same origin) and the output (some requests being delayed until a connection becomes available).

**5. User and Programming Errors (The "What Not To Do")**

* **User Errors (Less Direct):** User actions that indirectly trigger issues with connection management. A flaky network leading to `ERR_NETWORK_CHANGED` is an example.
* **Programming Errors (More Direct - Within the Chromium codebase, not by web developers):** Misusing the `HttpStreamPool` API within Chromium. For instance, failing to properly handle callbacks, leading to memory leaks or unexpected state. *Initially, I might think about JS errors, but the prompt is about the *C++ code* and its direct usage.*

**6. Debugging Clues (The "Where to Look")**

* **NetLog:** The code extensively uses `net_log_`. This is the primary tool for debugging network issues in Chromium. Explain how a developer would enable and use it.
* **Specific Events:** Mention the relevant `NetLogEventType` related to this class (although not explicitly listed in the provided snippet, experience with Chromium's networking would guide this).
* **Breakpoints:**  Suggest setting breakpoints in this file if a networking issue related to connection pooling is suspected.

**7. Iteration and Refinement:**

* **Review the Prompt:** Go back to the original request and ensure all parts have been addressed.
* **Clarity and Precision:** Use clear and concise language. Avoid jargon where possible or explain it.
* **Structure:** Organize the answer logically with clear headings.

**Self-Correction/Refinement Example During the Process:**

* **Initial Thought:** "JavaScript interacts with this through `fetch()`."
* **Refinement:** "While true, it's more accurate to say JavaScript *indirectly* interacts. Focus on the browser's C++ implementation of `fetch()` as the intermediary."
* **Initial Thought:** "A web developer might cause errors by opening too many connections."
* **Refinement:** "The `HttpStreamPool` is designed to *prevent* this. The errors are more likely to be within the Chromium codebase itself when *using* the `HttpStreamPool` incorrectly."

By following this kind of detailed breakdown, even with limited initial knowledge, you can systematically analyze the code and generate a comprehensive and accurate response.
好的，让我们来分析一下 `net/http/http_stream_pool.cc` 这个 Chromium 网络栈的源代码文件。

**文件功能概要:**

`http_stream_pool.cc` 文件实现了 `HttpStreamPool` 类，这个类是 Chromium 网络栈中负责管理和复用 HTTP(S) 连接的核心组件。它的主要功能包括：

1. **连接池管理:**  维护一个 HTTP 和 HTTPS 连接的池，用于提高网络请求的性能。它会根据目标服务器的 scheme、host、port 以及网络隔离键（NetworkAnonymizationKey）等信息，将连接分组管理。
2. **连接复用:** 尝试为新的请求复用已有的空闲连接，避免重复建立连接的开销，包括 TCP 握手、TLS 协商等。
3. **连接建立:** 当没有可复用的连接时，负责发起新的连接建立过程。
4. **连接限制:**  控制连接池中连接的总数，以及每个目标服务器组的连接数，防止资源过度消耗。
5. **协议支持:**  支持 HTTP/1.1、HTTP/2 (SPDY) 和 QUIC 协议的连接管理。
6. **Happy Eyeballs:**  实现了 Happy Eyeballs 算法（及其变种），在同时尝试 IPv4 和 IPv6 连接时，选择先建立成功的连接。
7. **预连接 (Preconnect):**  允许提前建立连接，以减少后续实际请求的延迟。
8. **网络状态感知:**  监听网络状态变化（例如 IP 地址变化），并根据需要清理连接池。
9. **SSL 配置更新:** 监听 SSL 配置的变化，并刷新相关的连接组。
10. **请求排队和优先级管理:**  当连接数达到限制时，对新的连接请求进行排队，并根据优先级进行处理。
11. **QUIC 会话管理:**  与 `QuicSessionPool` 协同工作，管理 QUIC 连接。
12. **一致性检查 (Debug Feature):**  提供一个用于调试和验证连接池状态一致性的功能。

**与 JavaScript 功能的关系 (间接):**

`HttpStreamPool` 本身是用 C++ 实现的，JavaScript 代码无法直接访问它。但是，JavaScript 通过浏览器提供的 Web API 发起的网络请求（例如使用 `fetch` 或 `XMLHttpRequest`）最终会路由到 Chromium 的网络栈，并由 `HttpStreamPool` 来管理底层的 HTTP(S) 连接。

**举例说明:**

假设一个网页的 JavaScript 代码发起了一个 HTTPS 请求：

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

当这个 `fetch` 请求被发起时，浏览器的网络栈会执行以下（简化的）步骤：

1. **请求信息分析:**  网络栈会解析请求的 URL、方法、Headers 等信息。
2. **连接查找:**  `HttpStreamPool` 会根据 `https://example.com` 以及相关的网络隔离键等信息，查找是否有可复用的空闲连接。
3. **连接复用或新建:**
   - 如果找到空闲连接，则会将其分配给这个请求。
   - 如果没有找到，`HttpStreamPool` 会负责发起与 `example.com` 的新的 HTTPS 连接（包括 DNS 解析、TCP 连接、TLS 握手）。
4. **数据传输:**  一旦连接建立，数据就会通过该连接进行传输。
5. **连接归还:** 请求完成后，连接可能会被放回连接池，供后续请求复用。

**逻辑推理 (假设输入与输出):**

**假设输入:**

*  `HttpStreamPool` 当前状态：
    *  已有一个到 `https://example.com` 的空闲 HTTP/2 连接。
    *  连接池总连接数未达到上限。
*  新的请求：
    *  目标 URL: `https://example.com/image.png`
    *  请求优先级：`MEDIUM`

**预期输出:**

*  `HttpStreamPool` 会找到已有的空闲连接，并将其分配给这个新的请求。
*  不会发起新的连接建立过程。
*  `total_handed_out_stream_count_` 会增加。
*  `total_idle_stream_count_` 会减少。

**假设输入:**

*  `HttpStreamPool` 当前状态：
    *  没有到 `https://anotherexample.com` 的连接。
    *  连接池总连接数未达到上限。
*  新的请求：
    *  目标 URL: `https://anotherexample.com/api/data`
    *  请求优先级：`HIGH`

**预期输出:**

*  `HttpStreamPool` 会创建一个新的连接到 `https://anotherexample.com`。
*  `total_connecting_stream_count_` 会增加。
*  一旦连接建立成功，`total_connecting_stream_count_` 减少，`total_handed_out_stream_count_` 增加。

**用户或编程常见的使用错误 (指 Chromium 内部编程):**

由于 `HttpStreamPool` 是 Chromium 内部的组件，普通 Web 开发者不会直接与其交互。这里的错误通常是指 Chromium 内部开发者在使用 `HttpStreamPool` API 时可能犯的错误：

1. **未正确处理回调:**  例如，在使用 `RequestStream` 或 `Preconnect` 时，没有正确处理完成回调，可能导致资源泄漏或程序逻辑错误。
2. **在高并发场景下未考虑连接限制:**  在某些内部模块中，如果大量请求同时发起，可能会超出连接池的限制，导致请求被延迟或失败。需要合理地控制请求的并发量。
3. **错误地设置连接属性:**  例如，在创建 `HttpStreamRequestInfo` 时，错误地设置了代理信息、SSL 配置等，可能导致连接建立失败。
4. **在连接生命周期管理上的错误:**  例如，没有在适当的时候释放连接资源，导致连接池中积累过多的无效连接。
5. **忽视网络状态变化:**  某些模块可能没有正确处理 `HttpStreamPool` 因网络状态变化而发出的通知，导致使用已经失效的连接。

**用户操作如何一步步到达这里 (作为调试线索):**

当 Chromium 开发者需要调试与 HTTP 连接管理相关的问题时，`http_stream_pool.cc` 是一个重要的入口点。以下是一些可能的用户操作，最终会涉及到这个文件：

1. **用户加载一个包含大量资源（图片、CSS、JS）的网页:**  浏览器会为这些资源发起多个 HTTP(S) 请求，`HttpStreamPool` 会尝试复用连接或建立新连接。如果连接复用逻辑有问题，或者连接数限制不合理，可能会导致加载缓慢或失败。
2. **用户访问使用 HTTP/2 或 QUIC 协议的网站:**  `HttpStreamPool` 需要处理这些协议的连接建立和管理。如果协议协商或会话管理出现问题，可能会导致连接失败或性能下降。
3. **用户在网络环境不稳定的情况下浏览网页:**  例如，在移动网络下，IP 地址可能会频繁变化。`HttpStreamPool` 需要正确处理 `OnIPAddressChanged` 事件，清理无效连接。如果处理不当，可能会导致连接中断或请求失败。
4. **用户更改了系统的代理设置:**  `HttpStreamPool` 需要根据新的代理设置建立连接。如果代理配置错误，可能会导致连接无法建立。
5. **用户访问使用了服务端推送 (Server Push) 功能的网站:**  `HttpStreamPool` 需要管理这些被服务端主动推送的资源连接。

**调试线索:**

当怀疑问题与 `HttpStreamPool` 相关时，可以采取以下调试步骤：

1. **使用 `chrome://net-export/` (NetLog):**  捕获浏览器的网络事件日志，可以详细查看连接的建立、复用、关闭等过程，以及相关的错误信息。在 NetLog 中搜索与 `HttpStreamPool` 相关的事件。
2. **使用 `chrome://flags/` 调整实验性功能:**  `HttpStreamPool` 的行为可能受到某些实验性功能的影响。可以尝试启用或禁用相关的 flag 来观察问题是否消失。例如，与 Happy Eyeballs 相关的 flag。
3. **在 `http_stream_pool.cc` 中添加日志或断点:**  对于 Chromium 开发者，可以在关键的代码路径上添加 `VLOG` 输出或者设置断点，以便更深入地了解连接池的状态和执行流程。关注 `groups_` 的变化、连接计数器的变化、以及各种事件处理函数（如 `OnIPAddressChanged`）。
4. **查看 `chrome://net-internals/#http2` 和 `chrome://net-internals/#quic`:**  这些页面提供了关于 HTTP/2 和 QUIC 连接的更详细信息，可以辅助判断问题是否与特定协议的连接管理有关。
5. **检查相关的 Field Trial 参数:**  `kHttpStreamPoolMaxStreamPerPool` 等参数可以通过 Field Trial 进行配置。检查当前生效的参数值是否合理。

总而言之，`http_stream_pool.cc` 是 Chromium 网络栈中至关重要的一个文件，它直接影响着网络请求的性能和稳定性。理解其功能和工作原理对于调试网络相关的问题至关重要。

### 提示词
```
这是目录为net/http/http_stream_pool.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/http/http_stream_pool.h"

#include <algorithm>
#include <map>
#include <memory>
#include <ostream>
#include <set>
#include <string>

#include "base/containers/flat_set.h"
#include "base/functional/bind.h"
#include "base/memory/weak_ptr.h"
#include "base/metrics/field_trial_params.h"
#include "base/notreached.h"
#include "base/task/sequenced_task_runner.h"
#include "net/base/completion_once_callback.h"
#include "net/base/features.h"
#include "net/base/host_port_pair.h"
#include "net/base/load_states.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/network_change_notifier.h"
#include "net/base/proxy_chain.h"
#include "net/base/session_usage.h"
#include "net/http/alternative_service.h"
#include "net/http/http_network_session.h"
#include "net/http/http_stream_key.h"
#include "net/http/http_stream_pool_group.h"
#include "net/http/http_stream_pool_job_controller.h"
#include "net/http/http_stream_request.h"
#include "net/log/net_log_with_source.h"
#include "net/quic/quic_session_pool.h"
#include "net/socket/next_proto.h"
#include "net/socket/ssl_client_socket.h"
#include "net/spdy/spdy_session.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_versions.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"

namespace net {

namespace {

constexpr base::FeatureParam<size_t> kHttpStreamPoolMaxStreamPerPool{
    &features::kHappyEyeballsV3,
    HttpStreamPool::kMaxStreamSocketsPerPoolParamName.data(),
    HttpStreamPool::kDefaultMaxStreamSocketsPerPool};

constexpr base::FeatureParam<size_t> kHttpStreamPoolMaxStreamPerGroup{
    &features::kHappyEyeballsV3,
    HttpStreamPool::kMaxStreamSocketsPerGroupParamName.data(),
    HttpStreamPool::kDefaultMaxStreamSocketsPerGroup};

constexpr base::FeatureParam<bool> kEnableConsistencyCheck{
    &features::kHappyEyeballsV3,
    HttpStreamPool::kEnableConsistencyCheckParamName.data(), false};

// Represents total stream counts in the pool. Only used for consistency check.
struct StreamCounts {
  size_t handed_out = 0;
  size_t idle = 0;
  size_t connecting = 0;

  auto operator<=>(const StreamCounts&) const = default;

  base::Value::Dict ToValue() const {
    base::Value::Dict dict;
    dict.Set("handed_out", static_cast<int>(handed_out));
    dict.Set("idle", static_cast<int>(idle));
    dict.Set("connecting", static_cast<int>(connecting));
    return dict;
  }
};

std::ostream& operator<<(std::ostream& os, const StreamCounts& counts) {
  return os << "{ handed_out: " << counts.handed_out
            << ", idle: " << counts.idle
            << ", connecting: " << counts.connecting << " }";
}

}  // namespace

HttpStreamPool::HttpStreamPool(HttpNetworkSession* http_network_session,
                               bool cleanup_on_ip_address_change)
    : http_network_session_(http_network_session),
      stream_attempt_params_(
          StreamAttemptParams::FromHttpNetworkSession(http_network_session_)),
      cleanup_on_ip_address_change_(cleanup_on_ip_address_change),
      net_log_(NetLogWithSource::Make(http_network_session_->net_log(),
                                      NetLogSourceType::HTTP_STREAM_POOL)),
      max_stream_sockets_per_pool_(kHttpStreamPoolMaxStreamPerPool.Get()),
      // Ensure that the per-group limit is less than or equals to the per-pool
      // limit.
      max_stream_sockets_per_group_(
          std::min(kHttpStreamPoolMaxStreamPerPool.Get(),
                   kHttpStreamPoolMaxStreamPerGroup.Get())) {
  CHECK(http_network_session_);
  if (cleanup_on_ip_address_change) {
    NetworkChangeNotifier::AddIPAddressObserver(this);
  }

  http_network_session_->ssl_client_context()->AddObserver(this);

  if (kEnableConsistencyCheck.Get()) {
    CheckConsistency();
  }
}

HttpStreamPool::~HttpStreamPool() {
  http_network_session_->ssl_client_context()->RemoveObserver(this);

  if (cleanup_on_ip_address_change_) {
    NetworkChangeNotifier::RemoveIPAddressObserver(this);
  }
}

void HttpStreamPool::OnShuttingDown() {
  is_shutting_down_ = true;
}

std::unique_ptr<HttpStreamRequest> HttpStreamPool::RequestStream(
    HttpStreamRequest::Delegate* delegate,
    HttpStreamPoolRequestInfo request_info,
    RequestPriority priority,
    const std::vector<SSLConfig::CertAndStatus>& allowed_bad_certs,
    bool enable_ip_based_pooling,
    bool enable_alternative_services,
    const NetLogWithSource& net_log) {
  auto controller = std::make_unique<JobController>(
      this, std::move(request_info), enable_ip_based_pooling,
      enable_alternative_services);
  JobController* controller_raw_ptr = controller.get();
  // Put `controller` into `job_controllers_` before calling RequestStream() to
  // make sure `job_controllers_` always contains `controller` when
  // OnJobControllerComplete() is called.
  job_controllers_.emplace(std::move(controller));

  return controller_raw_ptr->RequestStream(delegate, priority,
                                           allowed_bad_certs, net_log);
}

int HttpStreamPool::Preconnect(HttpStreamPoolRequestInfo request_info,
                               size_t num_streams,
                               CompletionOnceCallback callback) {
  auto controller = std::make_unique<JobController>(
      this, std::move(request_info), /*enable_ip_based_pooling=*/true,
      /*enable_alternative_services=*/true);
  JobController* controller_raw_ptr = controller.get();
  // SAFETY: Using base::Unretained() is safe because `this` will own
  // `controller` when Preconnect() return ERR_IO_PENDING.
  int rv = controller_raw_ptr->Preconnect(
      num_streams, base::BindOnce(&HttpStreamPool::OnPreconnectComplete,
                                  base::Unretained(this), controller_raw_ptr,
                                  std::move(callback)));
  if (rv == ERR_IO_PENDING) {
    job_controllers_.emplace(std::move(controller));
  }
  return rv;
}

void HttpStreamPool::IncrementTotalIdleStreamCount() {
  CHECK_LT(TotalActiveStreamCount(), kDefaultMaxStreamSocketsPerPool);
  ++total_idle_stream_count_;
}

void HttpStreamPool::DecrementTotalIdleStreamCount() {
  CHECK_GT(total_idle_stream_count_, 0u);
  --total_idle_stream_count_;
}

void HttpStreamPool::IncrementTotalHandedOutStreamCount() {
  CHECK_LT(TotalActiveStreamCount(), kDefaultMaxStreamSocketsPerPool);
  ++total_handed_out_stream_count_;
}

void HttpStreamPool::DecrementTotalHandedOutStreamCount() {
  CHECK_GT(total_handed_out_stream_count_, 0u);
  --total_handed_out_stream_count_;
}

void HttpStreamPool::IncrementTotalConnectingStreamCount() {
  CHECK_LT(TotalActiveStreamCount(), kDefaultMaxStreamSocketsPerPool);
  ++total_connecting_stream_count_;
}

void HttpStreamPool::DecrementTotalConnectingStreamCount(size_t amount) {
  CHECK_GE(total_connecting_stream_count_, amount);
  total_connecting_stream_count_ -= amount;
}

void HttpStreamPool::OnIPAddressChanged() {
  CHECK(cleanup_on_ip_address_change_);
  for (const auto& group : groups_) {
    group.second->FlushWithError(ERR_NETWORK_CHANGED, kIpAddressChanged);
  }
}

void HttpStreamPool::OnSSLConfigChanged(
    SSLClientContext::SSLConfigChangeType change_type) {
  for (const auto& group : groups_) {
    group.second->Refresh(kSslConfigChanged);
  }
  ProcessPendingRequestsInGroups();
}

void HttpStreamPool::OnSSLConfigForServersChanged(
    const base::flat_set<HostPortPair>& servers) {
  for (const auto& group : groups_) {
    if (GURL::SchemeIsCryptographic(group.first.destination().scheme()) &&
        servers.contains(
            HostPortPair::FromSchemeHostPort(group.first.destination()))) {
      group.second->Refresh(kSslConfigChanged);
    }
  }
  ProcessPendingRequestsInGroups();
}

void HttpStreamPool::OnGroupComplete(Group* group) {
  auto it = groups_.find(group->stream_key());
  CHECK(it != groups_.end());
  groups_.erase(it);
}

void HttpStreamPool::OnJobControllerComplete(JobController* job_controller) {
  auto it = job_controllers_.find(job_controller);
  CHECK(it != job_controllers_.end());
  job_controllers_.erase(it);
}

void HttpStreamPool::FlushWithError(
    int error,
    std::string_view net_log_close_reason_utf8) {
  for (auto& group : groups_) {
    group.second->FlushWithError(error, net_log_close_reason_utf8);
  }
}

void HttpStreamPool::CloseIdleStreams(
    std::string_view net_log_close_reason_utf8) {
  for (auto& group : groups_) {
    group.second->CloseIdleStreams(net_log_close_reason_utf8);
  }
}

bool HttpStreamPool::IsPoolStalled() {
  if (!ReachedMaxStreamLimit()) {
    return false;
  }
  return FindHighestStalledGroup() != nullptr;
}

void HttpStreamPool::ProcessPendingRequestsInGroups() {
  if (is_shutting_down_) {
    return;
  }

  // Loop until there is nothing more to do.
  while (true) {
    Group* group = FindHighestStalledGroup();
    if (!group) {
      return;
    }

    if (ReachedMaxStreamLimit()) {
      if (!CloseOneIdleStreamSocket()) {
        return;
      }
    }

    group->ProcessPendingRequest();
  }
}

bool HttpStreamPool::RequiresHTTP11(
    const url::SchemeHostPort& destination,
    const NetworkAnonymizationKey& network_anonymization_key) {
  return http_network_session()->http_server_properties()->RequiresHTTP11(
      destination, network_anonymization_key);
}

bool HttpStreamPool::IsQuicBroken(
    const url::SchemeHostPort& destination,
    const NetworkAnonymizationKey& network_anonymization_key) {
  return http_network_session()
      ->http_server_properties()
      ->IsAlternativeServiceBroken(
          AlternativeService(NextProto::kProtoQUIC,
                             HostPortPair::FromSchemeHostPort(destination)),
          network_anonymization_key);
}

bool HttpStreamPool::CanUseQuic(
    const url::SchemeHostPort& destination,
    const NetworkAnonymizationKey& network_anonymization_key,
    bool enable_ip_based_pooling,
    bool enable_alternative_services) {
  if (http_network_session()->ShouldForceQuic(destination, ProxyInfo::Direct(),
                                              /*is_websocket=*/false)) {
    return true;
  }
  return enable_ip_based_pooling && enable_alternative_services &&
         GURL::SchemeIsCryptographic(destination.scheme()) &&
         !RequiresHTTP11(destination, network_anonymization_key) &&
         !IsQuicBroken(destination, network_anonymization_key);
}

quic::ParsedQuicVersion HttpStreamPool::SelectQuicVersion(
    const AlternativeServiceInfo& alternative_service_info) {
  if (alternative_service_info.protocol() != NextProto::kProtoQUIC) {
    return quic::ParsedQuicVersion::Unsupported();
  }
  return http_network_session()->context().quic_context->SelectQuicVersion(
      alternative_service_info.advertised_versions());
}

bool HttpStreamPool::CanUseExistingQuicSession(
    const QuicSessionAliasKey& quic_session_alias_key,
    bool enable_ip_based_pooling,
    bool enable_alternative_services) {
  const url::SchemeHostPort& destination = quic_session_alias_key.destination();
  return destination.IsValid() &&
         CanUseQuic(
             destination,
             quic_session_alias_key.session_key().network_anonymization_key(),
             enable_ip_based_pooling, enable_alternative_services) &&
         http_network_session()->quic_session_pool()->CanUseExistingSession(
             quic_session_alias_key.session_key(), destination);
}

void HttpStreamPool::SetDelegateForTesting(
    std::unique_ptr<TestDelegate> delegate) {
  delegate_for_testing_ = std::move(delegate);
}

base::Value::Dict HttpStreamPool::GetInfoAsValue() const {
  // Using "socket" instead of "stream" for compatibility with ClientSocketPool.
  base::Value::Dict dict;
  dict.Set("handed_out_socket_count",
           static_cast<int>(total_handed_out_stream_count_));
  dict.Set("connecting_socket_count",
           static_cast<int>(total_connecting_stream_count_));
  dict.Set("idle_socket_count", static_cast<int>(total_idle_stream_count_));
  dict.Set("max_socket_count", static_cast<int>(max_stream_sockets_per_pool_));
  dict.Set("max_sockets_per_group",
           static_cast<int>(max_stream_sockets_per_group_));

  base::Value::Dict group_dicts;
  for (const auto& [key, group] : groups_) {
    group_dicts.Set(key.ToString(), group->GetInfoAsValue());
  }

  if (!group_dicts.empty()) {
    dict.Set("groups", std::move(group_dicts));
  }
  return dict;
}

HttpStreamPool::Group& HttpStreamPool::GetOrCreateGroupForTesting(
    const HttpStreamKey& stream_key) {
  return GetOrCreateGroup(stream_key);
}

HttpStreamPool::Group* HttpStreamPool::GetGroupForTesting(
    const HttpStreamKey& stream_key) {
  return GetGroup(stream_key);
}

HttpStreamPool::Group& HttpStreamPool::GetOrCreateGroup(
    const HttpStreamKey& stream_key,
    std::optional<QuicSessionAliasKey> quic_session_alias_key) {
  auto it = groups_.find(stream_key);
  if (it == groups_.end()) {
    it = groups_.try_emplace(
        it, stream_key,
        std::make_unique<Group>(this, stream_key, quic_session_alias_key));
  }
  return *it->second;
}

HttpStreamPool::Group* HttpStreamPool::GetGroup(
    const HttpStreamKey& stream_key) {
  auto it = groups_.find(stream_key);
  return it == groups_.end() ? nullptr : it->second.get();
}

HttpStreamPool::Group* HttpStreamPool::FindHighestStalledGroup() {
  Group* highest_stalled_group = nullptr;
  std::optional<RequestPriority> highest_priority;

  for (const auto& group : groups_) {
    std::optional<RequestPriority> priority =
        group.second->GetPriorityIfStalledByPoolLimit();
    if (!priority) {
      continue;
    }
    if (!highest_priority || *priority > *highest_priority) {
      highest_priority = priority;
      highest_stalled_group = group.second.get();
    }
  }

  return highest_stalled_group;
}

bool HttpStreamPool::CloseOneIdleStreamSocket() {
  if (total_idle_stream_count_ == 0) {
    return false;
  }

  for (auto& group : groups_) {
    if (group.second->CloseOneIdleStreamSocket()) {
      return true;
    }
  }
  NOTREACHED();
}

base::WeakPtr<SpdySession> HttpStreamPool::FindAvailableSpdySession(
    const HttpStreamKey& stream_key,
    const SpdySessionKey& spdy_session_key,
    bool enable_ip_based_pooling,
    const NetLogWithSource& net_log) {
  if (!GURL::SchemeIsCryptographic(stream_key.destination().scheme())) {
    return nullptr;
  }

  base::WeakPtr<SpdySession> spdy_session =
      http_network_session()->spdy_session_pool()->FindAvailableSession(
          spdy_session_key, enable_ip_based_pooling, /*is_websocket=*/false,
          net_log);
  if (spdy_session) {
    if (RequiresHTTP11(stream_key.destination(),
                       stream_key.network_anonymization_key())) {
      spdy_session->MakeUnavailable();
      Group* group = GetGroup(stream_key);
      if (group) {
        group->OnRequiredHttp11();
      }
      return nullptr;
    }
  }
  return spdy_session;
}

void HttpStreamPool::OnPreconnectComplete(JobController* job_controller,
                                          CompletionOnceCallback callback,
                                          int rv) {
  OnJobControllerComplete(job_controller);
  std::move(callback).Run(rv);
}

void HttpStreamPool::CheckConsistency() {
  CHECK(kEnableConsistencyCheck.Get());

  const StreamCounts pool_total_counts = {
      .handed_out = total_handed_out_stream_count_,
      .idle = total_idle_stream_count_,
      .connecting = total_connecting_stream_count_};

  if (groups_.empty()) {
    VLOG_IF(1, pool_total_counts == StreamCounts())
        << "Total stream counts are not zero: " << pool_total_counts;
  } else {
    StreamCounts groups_total_counts;
    base::Value::Dict groups;
    for (const auto& [key, group] : groups_) {
      groups_total_counts.handed_out += group->HandedOutStreamSocketCount();
      groups_total_counts.idle += group->IdleStreamSocketCount();
      groups_total_counts.connecting += group->ConnectingStreamSocketCount();
      groups.Set(key.ToString(), group->GetInfoAsValue());
    }

    const bool ok = pool_total_counts == groups_total_counts;
    NetLogEventType event_type =
        ok ? NetLogEventType::HTTP_STREAM_POOL_CONSISTENCY_CHECK_OK
           : NetLogEventType::HTTP_STREAM_POOL_CONSISTENCY_CHECK_FAIL;
    net_log_.AddEvent(event_type, [&] {
      base::Value::Dict dict;
      dict.Set("pool_total_counts", pool_total_counts.ToValue());
      dict.Set("groups_total_counts", groups_total_counts.ToValue());
      dict.Set("groups", std::move(groups));
      return dict;
    });
    VLOG_IF(1, !ok) << "Stream counts mismatch: pool=" << pool_total_counts
                    << ", groups=" << groups_total_counts;
  }

  base::SequencedTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&HttpStreamPool::CheckConsistency,
                     weak_ptr_factory_.GetWeakPtr()),
      base::Seconds(3));
}

}  // namespace net
```