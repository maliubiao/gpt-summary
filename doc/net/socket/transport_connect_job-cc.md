Response:
Let's break down the thought process for analyzing this C++ code and generating the comprehensive explanation.

**1. Initial Reading and High-Level Understanding:**

* **Goal:**  Understand the purpose of `transport_connect_job.cc` in the Chromium networking stack.
* **Keywords:**  "connect job," "transport," "socket." This immediately suggests it's related to establishing network connections.
* **Structure:** Notice the `#include` directives. These tell us about dependencies on core Chromium components like `base`, `net`, `url`, and potentially third-party libraries like `abseil`. The namespace `net` confirms it's part of the networking layer.
* **Key Classes:** Identify the main class: `TransportConnectJob`. Also, note related classes like `TransportSocketParams`, `TransportConnectSubJob`, and the use of `HostResolver`.
* **Overall Impression:** This file seems to manage the process of connecting to a network endpoint, potentially trying different strategies (like IPv4 and IPv6) and handling DNS resolution.

**2. Deeper Dive into Functionality (Iterative Process):**

* **`TransportSocketParams`:**  Examine its members (`destination_`, `network_anonymization_key_`, etc.). These provide context for the connection: where to connect, security settings, and which protocols are supported. The DCHECKs related to ALPN for HTTP and HTTPS are important details.
* **`TransportConnectJob` Constructor:** Analyze its parameters. It takes `TransportSocketParams`, a `Delegate`, and uses `HostResolver`. This reinforces the idea of a connection management class that relies on DNS resolution.
* **State Machine (`DoLoop` and `next_state_`):** Recognize the classic state machine pattern. This is crucial for understanding the connection lifecycle. Map out the states: `RESOLVE_HOST`, `TRANSPORT_CONNECT`, etc. This reveals the steps involved in making a connection.
* **DNS Resolution (`DoResolveHost`, `DoResolveHostComplete`):**  See how it interacts with `HostResolver`. Note the use of `HostResolver::CreateRequest` and the handling of successful and failed resolution. The `OnHostResolutionCallback` is a point of customization.
* **Connection Establishment (`DoTransportConnect`, `TransportConnectSubJob`):** Observe the creation of `TransportConnectSubJob` for IPv4 and IPv6. The fallback mechanism using a timer (`fallback_timer_`) is a significant detail.
* **Sub-Job Completion (`HandleSubJobComplete`, `OnSubJobComplete`):**  Understand how the main job reacts to the success or failure of the sub-jobs. The logic for handling fallback and preventing further attempts on suspend is key.
* **Error Handling:** Notice the use of `net::OK` and `net::ERR_*` constants, indicating error management within the networking stack.
* **Metrics:**  The `UMA_HISTOGRAM_CUSTOM_TIMES` calls indicate the collection of performance data related to DNS resolution and TCP connection times.
* **SVCB and ALPN Logic (`IsSvcbOptional`, `IsEndpointResultUsable`):** This highlights modern networking features and protocol negotiation. Focus on how ALPN selection influences connection attempts.

**3. Identifying Relationships with JavaScript:**

* **Triggering Network Requests:** Think about how web pages initiate connections. JavaScript's `fetch`, `XMLHttpRequest`, `WebSocket`, and even loading resources through `<img>`, `<script>`, etc., all rely on the underlying network stack.
* **Browser API Mapping:**  Consider how JavaScript APIs translate to C++ code. A `fetch()` call might eventually lead to the creation of a `TransportConnectJob`.
* **Error Reporting:**  Recognize that network errors surfaced in JavaScript (e.g., "net::ERR_NAME_NOT_RESOLVED") originate from the C++ networking layer.

**4. Constructing Examples and Scenarios:**

* **Logical Reasoning (Hypothetical Input/Output):**  Focus on the DNS resolution phase. Imagine a successful DNS lookup resulting in IPv4 and IPv6 addresses. Then consider a failed lookup.
* **User/Programming Errors:**  Think about common mistakes developers make, like incorrect URLs or forgetting to handle network errors. Relate these back to the C++ code's functionality.
* **User Steps to Reach the Code (Debugging):** Trace the user's actions from typing a URL to the browser initiating a connection. Emphasize the role of DNS resolution and the different connection attempts.

**5. Structuring the Explanation:**

* **Start with a concise summary:**  Provide the core functionality upfront.
* **Break down the code into logical sections:**  Address classes, the state machine, DNS resolution, connection establishment, etc.
* **Provide concrete examples:**  Illustrate the concepts with JavaScript interactions, hypothetical scenarios, and error cases.
* **Explain the debugging perspective:**  Guide the reader on how to use this information for troubleshooting.
* **Maintain clarity and avoid overly technical jargon where possible.**

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "It's just about connecting to a server."
* **Correction:** Realize the complexity involves DNS resolution (including SVCB), IPv4/IPv6 fallback, ALPN negotiation, and error handling.
* **Initial thought:** "JavaScript directly calls this C++ code."
* **Correction:** Understand the abstraction layers. JavaScript uses browser APIs, which are implemented in C++ and eventually interact with the networking stack.
* **Ensure accuracy:** Double-check the interpretation of the code, especially the more complex parts like SVCB and ALPN. Referencing documentation or related code if needed.

By following these steps, combining code analysis with knowledge of web technologies and browser architecture, a comprehensive and accurate explanation of the `transport_connect_job.cc` file can be generated.
这个文件 `net/socket/transport_connect_job.cc` 是 Chromium 网络栈中负责建立**传输层连接**的核心组件。它处理了连接到一个服务器的底层细节，包括 DNS 解析、尝试不同的 IP 地址（IPv4 和 IPv6）以及处理连接的成功或失败。

以下是它的主要功能：

**核心功能:**

1. **管理连接尝试:** `TransportConnectJob` 负责协调尝试连接到服务器的过程。它会获取目标服务器的地址信息，并尝试使用不同的 IP 地址（如果可用）建立连接。

2. **DNS 解析:**  如果目标地址是域名，`TransportConnectJob` 会发起 DNS 解析请求，将域名转换为 IP 地址。它使用 `HostResolver` 组件来完成这个任务。

3. **IPv4 和 IPv6 连接尝试:**  为了提高连接成功率和效率，`TransportConnectJob` 通常会并行或按顺序尝试使用 IPv4 和 IPv6 地址进行连接。它使用 `TransportConnectSubJob` 来执行实际的连接操作。

4. **连接超时和重试:**  它管理连接尝试的超时，并在连接失败时（如果还有其他地址可用）尝试使用其他地址进行连接。

5. **ALPN (Application-Layer Protocol Negotiation) 支持:**  对于支持 ALPN 的协议（例如 HTTPS），`TransportConnectJob` 会考虑服务器支持的协议，并在建立连接时进行协议协商。

6. **SVCB/HTTPS 资源记录支持:**  它支持 DNS 的 SVCB 和 HTTPS 资源记录，允许客户端发现并连接到服务器提供的备用连接方式，例如使用不同的端口或协议。

7. **网络状态感知:**  它可以感知网络状态的变化，例如网络连接中断或恢复。

8. **性能指标收集:**  它会记录连接过程中的各种指标，例如 DNS 解析时间、连接建立时间等，用于性能分析和优化。

**与 JavaScript 的关系 (间接):**

`TransportConnectJob` 本身不是直接由 JavaScript 代码调用的。相反，它是 JavaScript 发起的网络请求背后的基础设施。

**举例说明:**

当你在浏览器中访问一个网页 (例如 `https://www.example.com`) 时，会发生以下过程，其中 `TransportConnectJob` 发挥着关键作用：

1. **JavaScript 发起请求:**  浏览器中的渲染引擎执行 JavaScript 代码，该代码可能通过 `fetch` API 或加载一个资源 (例如 `<img>` 标签) 发起对 `www.example.com` 的 HTTP 或 HTTPS 请求。

2. **网络栈处理请求:** 浏览器会将这个请求传递给网络栈。

3. **创建 `TransportConnectJob`:** 网络栈会创建一个 `TransportConnectJob` 实例，目标地址是 `www.example.com:443` (HTTPS 的默认端口)。

4. **DNS 解析:** `TransportConnectJob` 使用 `HostResolver` 查询 `www.example.com` 的 IP 地址。

5. **连接尝试:**
   - `TransportConnectJob` 可能会同时或按顺序创建 `TransportConnectSubJob` 来尝试连接解析到的 IPv4 和 IPv6 地址。
   - 如果是 HTTPS 请求，并且 DNS 返回了 SVCB/HTTPS 记录，它会考虑这些记录中指定的连接参数。
   - 它会尝试建立 TCP 连接。

6. **连接成功或失败:**
   - 如果连接成功，`TransportConnectJob` 会将建立的 socket 返回给上层网络栈。
   - 如果连接失败，它会尝试其他地址（如果有），或者报告连接错误。

7. **数据传输:** 一旦连接建立，浏览器就可以通过这个连接发送 HTTP 请求并接收服务器的响应。

8. **JavaScript 接收响应:** 最终，服务器的响应会传递回浏览器中的 JavaScript 代码。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* **目标地址:** `www.google.com:80` (HTTP 连接)
* **DNS 解析结果:**
    * IPv4 地址: `172.217.160.142`
    * IPv6 地址: `2404:6800:4007:818::200e`

**逻辑推理过程:**

1. `TransportConnectJob` 创建。
2. DNS 解析已完成，获得 IPv4 和 IPv6 地址。
3. `TransportConnectJob` 创建两个 `TransportConnectSubJob`: 一个用于 IPv4，一个用于 IPv6。
4. 假设 IPv6 连接先尝试并成功建立。

**输出:**

* 成功建立到 `2404:6800:4007:818::200e:80` 的 TCP 连接。
* `TransportConnectJob` 将建立的 socket 返回。

**假设输入:**

* **目标地址:** `nonexistent.example.com:443` (HTTPS 连接)
* **DNS 解析结果:**  `ERR_NAME_NOT_RESOLVED` (域名无法解析)

**逻辑推理过程:**

1. `TransportConnectJob` 创建。
2. DNS 解析失败，返回 `ERR_NAME_NOT_RESOLVED`。

**输出:**

* 连接失败，返回 `ERR_NAME_NOT_RESOLVED` 错误。

**用户或编程常见的使用错误:**

1. **阻止 DNS 解析或连接:**  用户的防火墙或网络配置可能阻止 DNS 解析或连接到特定的端口或 IP 地址。这会导致 `TransportConnectJob` 连接失败。

   **例子:**  用户配置了防火墙规则，阻止所有到 80 端口的连接。当浏览器尝试访问 `http://www.example.com` 时，`TransportConnectJob` 会因为无法建立 TCP 连接而失败。

2. **网络连接问题:**  用户的设备可能没有连接到互联网，或者网络连接不稳定。这会导致 DNS 解析失败或连接尝试超时。

   **例子:**  用户断开了 Wi-Fi 连接。当浏览器尝试加载网页时，`TransportConnectJob` 会因为无法连接到网络而失败。

3. **服务器不可用:**  目标服务器可能宕机或暂时不可用。这会导致连接尝试失败。

   **例子:**  用户尝试访问一个维护中的网站。`TransportConnectJob` 可能会成功解析域名，但无法建立 TCP 连接或在建立连接后收到连接拒绝。

4. **错误的 URL 或主机名:**  用户可能在地址栏中输入了错误的 URL 或主机名。这会导致 DNS 解析失败。

   **例子:**  用户输入了 `htpp://www.example.com` (错误的协议)。虽然这可能不会直接影响 `TransportConnectJob` 的核心逻辑，但在上层处理 URL 时就会发现错误。但是，如果用户输入了不存在的域名，例如 `www.nonexistentexample.com`，`TransportConnectJob` 会因为 DNS 解析失败而无法建立连接。

5. **TLS/SSL 配置错误 (对于 HTTPS):**  如果服务器的 TLS/SSL 配置不正确，或者客户端不支持服务器要求的加密套件，HTTPS 连接可能会失败。这会在 `TransportConnectJob` 的后续阶段（例如 TLS 握手）中体现出来。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入 URL 并按下回车键，或者点击一个链接。**

2. **浏览器解析 URL，确定协议、主机名和端口。**

3. **如果需要建立新的连接，网络栈会创建一个 `TransportConnectJob` 实例。**

4. **`TransportConnectJob` 开始执行以下步骤:**
   - **`STATE_RESOLVE_HOST`:**  如果目标是域名，则调用 `HostResolver` 进行 DNS 解析。
   - **`STATE_RESOLVE_HOST_COMPLETE`:**  处理 DNS 解析的结果 (成功或失败)。
   - **`STATE_RESOLVE_HOST_CALLBACK_COMPLETE`:**  执行 DNS 解析后的回调，允许进一步处理解析结果。
   - **`STATE_TRANSPORT_CONNECT`:**  尝试建立 TCP 连接。这可能会创建 `TransportConnectSubJob` 实例来并行或按顺序尝试不同的 IP 地址。
   - **`STATE_TRANSPORT_CONNECT_COMPLETE`:** 处理连接尝试的结果 (成功或失败)。

5. **如果连接成功，`TransportConnectJob` 会将建立的 socket 返回给上层网络栈。**

6. **如果连接失败，`TransportConnectJob` 会尝试其他地址 (如果可用) 或报告错误。**

**调试线索:**

* **NetLog:** Chromium 的 NetLog 工具是调试网络问题的强大工具。它可以记录 `TransportConnectJob` 的状态转换、DNS 解析结果、连接尝试以及发生的错误。通过查看 NetLog，你可以跟踪连接建立的整个过程，了解在哪里出现了问题。
* **断点调试:**  开发者可以使用调试器 (例如 gdb 或 lldb) 在 `transport_connect_job.cc` 中设置断点，逐步执行代码，查看变量的值，并理解代码的执行流程。这可以帮助理解特定的连接尝试是如何进行的，以及为什么会失败。
* **查看错误代码:**  `TransportConnectJob` 返回的错误代码 (例如 `ERR_NAME_NOT_RESOLVED`, `ERR_CONNECTION_REFUSED`, `ERR_CONNECTION_TIMED_OUT`) 可以提供关于连接失败原因的重要线索。

总之，`net/socket/transport_connect_job.cc` 是 Chromium 网络栈中一个至关重要的组件，负责管理底层的传输层连接建立过程。理解它的功能和工作原理对于调试网络问题至关重要。

### 提示词
```
这是目录为net/socket/transport_connect_job.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/transport_connect_job.h"

#include <memory>
#include <utility>

#include "base/check_op.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "net/base/features.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/trace_constants.h"
#include "net/base/tracing.h"
#include "net/dns/public/host_resolver_results.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/log/net_log_event_type.h"
#include "net/socket/socket_tag.h"
#include "net/socket/transport_connect_sub_job.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

namespace net {

namespace {

// TODO(crbug.com/40181080): Delete once endpoint usage is converted to using
// url::SchemeHostPort when available.
HostPortPair ToLegacyDestinationEndpoint(
    const TransportSocketParams::Endpoint& endpoint) {
  if (absl::holds_alternative<url::SchemeHostPort>(endpoint)) {
    return HostPortPair::FromSchemeHostPort(
        absl::get<url::SchemeHostPort>(endpoint));
  }

  DCHECK(absl::holds_alternative<HostPortPair>(endpoint));
  return absl::get<HostPortPair>(endpoint);
}

}  // namespace

TransportSocketParams::TransportSocketParams(
    Endpoint destination,
    NetworkAnonymizationKey network_anonymization_key,
    SecureDnsPolicy secure_dns_policy,
    OnHostResolutionCallback host_resolution_callback,
    base::flat_set<std::string> supported_alpns)
    : destination_(std::move(destination)),
      network_anonymization_key_(std::move(network_anonymization_key)),
      secure_dns_policy_(secure_dns_policy),
      host_resolution_callback_(std::move(host_resolution_callback)),
      supported_alpns_(std::move(supported_alpns)) {
#if DCHECK_IS_ON()
  auto* scheme_host_port = absl::get_if<url::SchemeHostPort>(&destination_);
  if (scheme_host_port) {
    if (scheme_host_port->scheme() == url::kHttpsScheme) {
      // HTTPS destinations will, when passed to the DNS resolver, return
      // SVCB/HTTPS-based routes. Those routes require ALPN protocols to
      // evaluate. If there are none, `IsEndpointResultUsable` will correctly
      // skip each route, but it doesn't make sense to make a DNS query if we
      // can't handle the result.
      DCHECK(!supported_alpns_.empty());
    } else if (scheme_host_port->scheme() == url::kHttpScheme) {
      // HTTP (not HTTPS) does not currently define ALPN protocols, so the list
      // should be empty. This means `IsEndpointResultUsable` will skip any
      // SVCB-based routes. HTTP also has no SVCB mapping, so `HostResolver`
      // will never return them anyway.
      //
      // `HostResolver` will still query SVCB (rather, HTTPS) records for the
      // corresponding HTTPS URL to implement an upgrade flow (section 9.5 of
      // draft-ietf-dnsop-svcb-https-08), but this will result in DNS resolution
      // failing with `ERR_DNS_NAME_HTTPS_ONLY`, not SVCB-based routes.
      DCHECK(supported_alpns_.empty());
    }
  }
#endif
}

TransportSocketParams::~TransportSocketParams() = default;

std::unique_ptr<TransportConnectJob> TransportConnectJob::Factory::Create(
    RequestPriority priority,
    const SocketTag& socket_tag,
    const CommonConnectJobParams* common_connect_job_params,
    const scoped_refptr<TransportSocketParams>& params,
    Delegate* delegate,
    const NetLogWithSource* net_log) {
  return std::make_unique<TransportConnectJob>(priority, socket_tag,
                                               common_connect_job_params,
                                               params, delegate, net_log);
}

TransportConnectJob::EndpointResultOverride::EndpointResultOverride(
    HostResolverEndpointResult result,
    std::set<std::string> dns_aliases)
    : result(std::move(result)), dns_aliases(std::move(dns_aliases)) {}
TransportConnectJob::EndpointResultOverride::EndpointResultOverride(
    EndpointResultOverride&&) = default;
TransportConnectJob::EndpointResultOverride::EndpointResultOverride(
    const EndpointResultOverride&) = default;
TransportConnectJob::EndpointResultOverride::~EndpointResultOverride() =
    default;

TransportConnectJob::TransportConnectJob(
    RequestPriority priority,
    const SocketTag& socket_tag,
    const CommonConnectJobParams* common_connect_job_params,
    const scoped_refptr<TransportSocketParams>& params,
    Delegate* delegate,
    const NetLogWithSource* net_log,
    std::optional<EndpointResultOverride> endpoint_result_override)
    : ConnectJob(priority,
                 socket_tag,
                 ConnectionTimeout(),
                 common_connect_job_params,
                 delegate,
                 net_log,
                 NetLogSourceType::TRANSPORT_CONNECT_JOB,
                 NetLogEventType::TRANSPORT_CONNECT_JOB_CONNECT),
      params_(params) {
  if (endpoint_result_override) {
    has_dns_override_ = true;
    endpoint_results_ = {std::move(endpoint_result_override->result)};
    dns_aliases_ = std::move(endpoint_result_override->dns_aliases);
    DCHECK(!endpoint_results_.front().ip_endpoints.empty());
    DCHECK(IsEndpointResultUsable(endpoint_results_.front(),
                                  IsSvcbOptional(endpoint_results_)));
  }
}

// We don't worry about cancelling the host resolution and TCP connect, since
// ~HostResolver::Request and ~TransportConnectSubJob will take care of it.
TransportConnectJob::~TransportConnectJob() = default;

LoadState TransportConnectJob::GetLoadState() const {
  switch (next_state_) {
    case STATE_RESOLVE_HOST:
    case STATE_RESOLVE_HOST_COMPLETE:
    case STATE_RESOLVE_HOST_CALLBACK_COMPLETE:
      return LOAD_STATE_RESOLVING_HOST;
    case STATE_TRANSPORT_CONNECT:
    case STATE_TRANSPORT_CONNECT_COMPLETE: {
      LoadState load_state = LOAD_STATE_IDLE;
      if (ipv6_job_ && ipv6_job_->started()) {
        load_state = ipv6_job_->GetLoadState();
      }
      // This method should return LOAD_STATE_CONNECTING in preference to
      // LOAD_STATE_WAITING_FOR_AVAILABLE_SOCKET when possible because "waiting
      // for available socket" implies that nothing is happening.
      if (ipv4_job_ && ipv4_job_->started() &&
          load_state != LOAD_STATE_CONNECTING) {
        load_state = ipv4_job_->GetLoadState();
      }
      return load_state;
    }
    case STATE_NONE:
      return LOAD_STATE_IDLE;
  }
}

bool TransportConnectJob::HasEstablishedConnection() const {
  // No need to ever return true, since NotifyComplete() is called as soon as a
  // connection is established.
  return false;
}

ConnectionAttempts TransportConnectJob::GetConnectionAttempts() const {
  return connection_attempts_;
}

ResolveErrorInfo TransportConnectJob::GetResolveErrorInfo() const {
  return resolve_error_info_;
}

std::optional<HostResolverEndpointResult>
TransportConnectJob::GetHostResolverEndpointResult() const {
  CHECK_LT(current_endpoint_result_, endpoint_results_.size());
  return endpoint_results_[current_endpoint_result_];
}

base::TimeDelta TransportConnectJob::ConnectionTimeout() {
  // TODO(eroman): The use of this constant needs to be re-evaluated. The time
  // needed for TCPClientSocketXXX::Connect() can be arbitrarily long, since
  // the address list may contain many alternatives, and most of those may
  // timeout. Even worse, the per-connect timeout threshold varies greatly
  // between systems (anywhere from 20 seconds to 190 seconds).
  // See comment #12 at http://crbug.com/23364 for specifics.
  return base::Minutes(4);
}

void TransportConnectJob::OnIOComplete(int result) {
  result = DoLoop(result);
  if (result != ERR_IO_PENDING)
    NotifyDelegateOfCompletion(result);  // Deletes |this|
}

int TransportConnectJob::DoLoop(int result) {
  DCHECK_NE(next_state_, STATE_NONE);

  int rv = result;
  do {
    State state = next_state_;
    next_state_ = STATE_NONE;
    switch (state) {
      case STATE_RESOLVE_HOST:
        DCHECK_EQ(OK, rv);
        rv = DoResolveHost();
        break;
      case STATE_RESOLVE_HOST_COMPLETE:
        rv = DoResolveHostComplete(rv);
        break;
      case STATE_RESOLVE_HOST_CALLBACK_COMPLETE:
        DCHECK_EQ(OK, rv);
        rv = DoResolveHostCallbackComplete();
        break;
      case STATE_TRANSPORT_CONNECT:
        DCHECK_EQ(OK, rv);
        rv = DoTransportConnect();
        break;
      case STATE_TRANSPORT_CONNECT_COMPLETE:
        rv = DoTransportConnectComplete(rv);
        break;
      default:
        NOTREACHED();
    }
  } while (rv != ERR_IO_PENDING && next_state_ != STATE_NONE);

  return rv;
}

int TransportConnectJob::DoResolveHost() {
  connect_timing_.domain_lookup_start = base::TimeTicks::Now();

  if (has_dns_override_) {
    DCHECK_EQ(1u, endpoint_results_.size());
    connect_timing_.domain_lookup_end = connect_timing_.domain_lookup_start;
    next_state_ = STATE_TRANSPORT_CONNECT;
    return OK;
  }

  next_state_ = STATE_RESOLVE_HOST_COMPLETE;

  HostResolver::ResolveHostParameters parameters;
  parameters.initial_priority = priority();
  parameters.secure_dns_policy = params_->secure_dns_policy();
  if (absl::holds_alternative<url::SchemeHostPort>(params_->destination())) {
    request_ = host_resolver()->CreateRequest(
        absl::get<url::SchemeHostPort>(params_->destination()),
        params_->network_anonymization_key(), net_log(), parameters);
  } else {
    request_ = host_resolver()->CreateRequest(
        absl::get<HostPortPair>(params_->destination()),
        params_->network_anonymization_key(), net_log(), parameters);
  }

  return request_->Start(base::BindOnce(&TransportConnectJob::OnIOComplete,
                                        base::Unretained(this)));
}

int TransportConnectJob::DoResolveHostComplete(int result) {
  TRACE_EVENT0(NetTracingCategory(),
               "TransportConnectJob::DoResolveHostComplete");
  connect_timing_.domain_lookup_end = base::TimeTicks::Now();
  // Overwrite connection start time, since for connections that do not go
  // through proxies, |connect_start| should not include dns lookup time.
  connect_timing_.connect_start = connect_timing_.domain_lookup_end;
  resolve_error_info_ = request_->GetResolveErrorInfo();

  if (result != OK) {
    // If hostname resolution failed, record an empty endpoint and the result.
    connection_attempts_.push_back(ConnectionAttempt(IPEndPoint(), result));
    return result;
  }

  DCHECK(request_->GetAddressResults());
  DCHECK(request_->GetDnsAliasResults());
  DCHECK(request_->GetEndpointResults());

  // Invoke callback.  If it indicates |this| may be slated for deletion, then
  // only continue after a PostTask.
  next_state_ = STATE_RESOLVE_HOST_CALLBACK_COMPLETE;
  if (!params_->host_resolution_callback().is_null()) {
    OnHostResolutionCallbackResult callback_result =
        params_->host_resolution_callback().Run(
            ToLegacyDestinationEndpoint(params_->destination()),
            *request_->GetEndpointResults(), *request_->GetDnsAliasResults());
    if (callback_result == OnHostResolutionCallbackResult::kMayBeDeletedAsync) {
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(&TransportConnectJob::OnIOComplete,
                                    weak_ptr_factory_.GetWeakPtr(), OK));
      return ERR_IO_PENDING;
    }
  }

  return result;
}

int TransportConnectJob::DoResolveHostCallbackComplete() {
  const auto& unfiltered_results = *request_->GetEndpointResults();
  bool svcb_optional = IsSvcbOptional(unfiltered_results);
  std::set<IPEndPoint> ip_endpoints_seen;
  for (const auto& result : unfiltered_results) {
    if (!IsEndpointResultUsable(result, svcb_optional)) {
      continue;
    }
    // The TCP connect itself does not depend on any metadata, so we can dedup
    // by IP endpoint. In particular, the fallback A/AAAA route will often use
    // the same IP endpoints as the HTTPS route. If they do not work for one
    // route, there is no use in trying a second time.
    std::vector<IPEndPoint> ip_endpoints;
    for (const auto& ip_endpoint : result.ip_endpoints) {
      auto [iter, inserted] = ip_endpoints_seen.insert(ip_endpoint);
      if (inserted) {
        ip_endpoints.push_back(ip_endpoint);
      }
    }
    if (!ip_endpoints.empty()) {
      HostResolverEndpointResult new_result;
      new_result.ip_endpoints = std::move(ip_endpoints);
      new_result.metadata = result.metadata;
      endpoint_results_.push_back(std::move(new_result));
    }
  }
  dns_aliases_ = *request_->GetDnsAliasResults();

  // No need to retain `request_` beyond this point.
  request_.reset();

  if (endpoint_results_.empty()) {
    // In the general case, DNS may successfully return routes, but none are
    // compatible with this `ConnectJob`. This should not happen for HTTPS
    // because `HostResolver` will reject SVCB/HTTPS sets that do not cover the
    // default "http/1.1" ALPN.
    return ERR_NAME_NOT_RESOLVED;
  }

  next_state_ = STATE_TRANSPORT_CONNECT;
  return OK;
}

int TransportConnectJob::DoTransportConnect() {
  next_state_ = STATE_TRANSPORT_CONNECT_COMPLETE;

  const HostResolverEndpointResult& endpoint =
      GetEndpointResultForCurrentSubJobs();
  std::vector<IPEndPoint> ipv4_addresses, ipv6_addresses;
  for (const auto& ip_endpoint : endpoint.ip_endpoints) {
    switch (ip_endpoint.GetFamily()) {
      case ADDRESS_FAMILY_IPV4:
        ipv4_addresses.push_back(ip_endpoint);
        break;

      case ADDRESS_FAMILY_IPV6:
        ipv6_addresses.push_back(ip_endpoint);
        break;

      default:
        DVLOG(1) << "Unexpected ADDRESS_FAMILY: " << ip_endpoint.GetFamily();
        break;
    }
  }

  if (!ipv4_addresses.empty()) {
    ipv4_job_ = std::make_unique<TransportConnectSubJob>(
        std::move(ipv4_addresses), this, SUB_JOB_IPV4);
  }

  if (!ipv6_addresses.empty()) {
    ipv6_job_ = std::make_unique<TransportConnectSubJob>(
        std::move(ipv6_addresses), this, SUB_JOB_IPV6);
    int result = ipv6_job_->Start();
    if (result != ERR_IO_PENDING)
      return HandleSubJobComplete(result, ipv6_job_.get());
    if (ipv4_job_) {
      // This use of base::Unretained is safe because |fallback_timer_| is
      // owned by this object.
      fallback_timer_.Start(
          FROM_HERE, kIPv6FallbackTime,
          base::BindOnce(&TransportConnectJob::StartIPv4JobAsync,
                         base::Unretained(this)));
    }
    return ERR_IO_PENDING;
  }

  DCHECK(!ipv6_job_);
  DCHECK(ipv4_job_);
  int result = ipv4_job_->Start();
  if (result != ERR_IO_PENDING)
    return HandleSubJobComplete(result, ipv4_job_.get());
  return ERR_IO_PENDING;
}

int TransportConnectJob::DoTransportConnectComplete(int result) {
  // Make sure nothing else calls back into this object.
  ipv4_job_.reset();
  ipv6_job_.reset();
  fallback_timer_.Stop();

  if (result == OK) {
    DCHECK(!connect_timing_.connect_start.is_null());
    DCHECK(!connect_timing_.domain_lookup_start.is_null());
    // `HandleSubJobComplete` should have called `SetSocket`.
    DCHECK(socket());
    base::TimeTicks now = base::TimeTicks::Now();
    base::TimeDelta total_duration = now - connect_timing_.domain_lookup_start;
    UMA_HISTOGRAM_CUSTOM_TIMES("Net.DNS_Resolution_And_TCP_Connection_Latency2",
                               total_duration, base::Milliseconds(1),
                               base::Minutes(10), 100);

    base::TimeDelta connect_duration = now - connect_timing_.connect_start;
    UMA_HISTOGRAM_CUSTOM_TIMES("Net.TCP_Connection_Latency", connect_duration,
                               base::Milliseconds(1), base::Minutes(10), 100);
  } else {
    // Don't try the next route if entering suspend mode.
    if (result != ERR_NETWORK_IO_SUSPENDED) {
      // If there is another endpoint available, try it.
      current_endpoint_result_++;
      if (current_endpoint_result_ < endpoint_results_.size()) {
        next_state_ = STATE_TRANSPORT_CONNECT;
        result = OK;
      }
    }
  }

  return result;
}

int TransportConnectJob::HandleSubJobComplete(int result,
                                              TransportConnectSubJob* job) {
  DCHECK_NE(result, ERR_IO_PENDING);
  if (result == OK) {
    SetSocket(job->PassSocket(), dns_aliases_);
    return result;
  }

  if (result == ERR_NETWORK_IO_SUSPENDED) {
    // Don't try other jobs if entering suspend mode.
    return result;
  }

  switch (job->type()) {
    case SUB_JOB_IPV4:
      ipv4_job_.reset();
      break;

    case SUB_JOB_IPV6:
      ipv6_job_.reset();
      // Start the other job, rather than wait for the fallback timer.
      if (ipv4_job_ && !ipv4_job_->started()) {
        fallback_timer_.Stop();
        result = ipv4_job_->Start();
        if (result != ERR_IO_PENDING) {
          return HandleSubJobComplete(result, ipv4_job_.get());
        }
      }
      break;
  }

  if (ipv4_job_ || ipv6_job_) {
    // Wait for the other job to complete, rather than reporting |result|.
    return ERR_IO_PENDING;
  }

  return result;
}

void TransportConnectJob::OnSubJobComplete(int result,
                                           TransportConnectSubJob* job) {
  result = HandleSubJobComplete(result, job);
  if (result != ERR_IO_PENDING) {
    OnIOComplete(result);
  }
}

void TransportConnectJob::StartIPv4JobAsync() {
  DCHECK(ipv4_job_);
  net_log().AddEvent(NetLogEventType::TRANSPORT_CONNECT_JOB_IPV6_FALLBACK);
  int result = ipv4_job_->Start();
  if (result != ERR_IO_PENDING)
    OnSubJobComplete(result, ipv4_job_.get());
}

int TransportConnectJob::ConnectInternal() {
  next_state_ = STATE_RESOLVE_HOST;
  return DoLoop(OK);
}

void TransportConnectJob::ChangePriorityInternal(RequestPriority priority) {
  if (next_state_ == STATE_RESOLVE_HOST_COMPLETE) {
    DCHECK(request_);
    // Change the request priority in the host resolver.
    request_->ChangeRequestPriority(priority);
  }
}

bool TransportConnectJob::IsSvcbOptional(
    base::span<const HostResolverEndpointResult> results) const {
  // If SVCB/HTTPS resolution succeeded, the client supports ECH, and all routes
  // support ECH, disable the A/AAAA fallback. See Section 10.1 of
  // draft-ietf-dnsop-svcb-https-08.

  auto* scheme_host_port =
      absl::get_if<url::SchemeHostPort>(&params_->destination());
  if (!scheme_host_port || scheme_host_port->scheme() != url::kHttpsScheme) {
    return true;  // This is not a SVCB-capable request at all.
  }

  if (!common_connect_job_params()->ssl_client_context ||
      !common_connect_job_params()->ssl_client_context->config().ech_enabled) {
    return true;  // ECH is not supported for this request.
  }

  return !HostResolver::AllProtocolEndpointsHaveEch(results);
}

bool TransportConnectJob::IsEndpointResultUsable(
    const HostResolverEndpointResult& result,
    bool svcb_optional) const {
  // A `HostResolverEndpointResult` with no ALPN protocols is the fallback
  // A/AAAA route. This is always compatible. We assume the ALPN-less option is
  // TCP-based.
  if (result.metadata.supported_protocol_alpns.empty()) {
    // See draft-ietf-dnsop-svcb-https-08, Section 3.
    return svcb_optional;
  }

  // See draft-ietf-dnsop-svcb-https-08, Section 7.1.2. Routes are usable if
  // there is an overlap between the route's ALPN protocols and the configured
  // ones. This ensures we do not, e.g., connect to a QUIC-only route with TCP.
  // Note that, if `params_` did not specify any ALPN protocols, no
  // SVCB/HTTPS-based routes will match and we will effectively ignore all but
  // plain A/AAAA routes.
  for (const auto& alpn : result.metadata.supported_protocol_alpns) {
    if (params_->supported_alpns().contains(alpn)) {
      return true;
    }
  }
  return false;
}

const HostResolverEndpointResult&
TransportConnectJob::GetEndpointResultForCurrentSubJobs() const {
  CHECK_LT(current_endpoint_result_, endpoint_results_.size());
  return endpoint_results_[current_endpoint_result_];
}

}  // namespace net
```