Response:
Let's break down the thought process for analyzing the `quic_session_attempt.cc` file and answering the prompt.

**1. Initial Understanding of the File's Purpose:**

The filename `quic_session_attempt.cc` immediately suggests this file is responsible for *attempting* to establish a QUIC session. The presence of `#include "net/quic/quic_session_attempt.h"` confirms this. Keywords like "session," "connect," "crypto," and "network" are likely to be central.

**2. High-Level Functionality Scan:**

I'd quickly scan the code for key classes, methods, and data members.

* **`QuicSessionAttempt` class:** This is the main actor. It has a `Start()` method, indicating the initiation point of the attempt. The constructor takes various parameters like IP endpoint, QUIC version, crypto config, etc., suggesting it encapsulates the necessary information for a connection attempt.
* **`Delegate` interface:**  The constructor takes a `Delegate*`, implying a callback mechanism to notify other parts of the system about the progress and outcome of the attempt.
* **`DoLoop()` method and `State` enum:** This points to a state machine implementation, handling the different stages of the connection attempt. Common states like "CreateSession," "CryptoConnect," and "ConfirmConnection" are good indicators.
* **`CreateSessionSync` and `CreateSessionAsync`:**  The presence of both synchronous and asynchronous session creation methods suggests flexibility in how the connection is established.
* **`CryptoConnect()`:**  Clearly responsible for the TLS handshake over QUIC.
* **Metrics logging (UMA_HISTOGRAM_*):**  The code is instrumented to collect performance data, which is a common practice in networking stacks.
* **Error handling:**  Checking for `rv != OK` and logging error locations are important for debugging and understanding failures.

**3. Detailed Analysis of Key Functions and Logic:**

Now, I'd delve into the more crucial parts:

* **`Start()`:**  This is the entry point. It initializes the state machine and calls `DoLoop()`. The use of a `CompletionOnceCallback` suggests asynchronous operation.
* **`DoLoop()` and the State Machine:**  I'd trace the transitions between states and the actions performed in each state. The `switch` statement in `DoLoop()` is the heart of the state machine. I'd note the order of operations: creating the session, performing the crypto handshake, and then confirming the connection.
* **`DoCreateSession()`:**  Pay attention to the distinction between direct connections and proxied connections. The use of `CreateSessionOnProxyStream` is significant. The conditional logic based on `features::kAsyncQuicSession` is important.
* **`DoCryptoConnect()`:**  This focuses on the TLS handshake. The error handling for `QUIC_PROOF_INVALID` is notable.
* **`DoConfirmConnection()`:**  This is where the attempt is finalized. The logic for checking for existing sessions (`HasMatchingIpSession`) and activating the new session is key. The retry logic on alternate networks before the handshake is also interesting.
* **Callbacks (`OnCreateSessionComplete`, `OnCryptoConnectComplete`):**  Understand how these callbacks interact with the state machine and the `Delegate`.

**4. Addressing the Specific Prompt Questions:**

* **Functionality:** Based on the analysis above, I'd summarize the core responsibilities: initiating, managing the state, and completing a QUIC session establishment attempt, handling both direct and proxied connections, and incorporating error handling and performance monitoring.
* **Relationship to JavaScript:**  This is a C++ file in the Chromium network stack. It doesn't directly interact with JavaScript in the browser's rendering engine. However, it provides the underlying transport mechanism that JavaScript (via browser APIs like `fetch`) uses to communicate over QUIC. The connection established here will eventually carry data requested by JavaScript. I'd use an example like a `fetch()` call initiating a network request.
* **Logical Reasoning (Hypothetical Input/Output):** I'd choose a simplified scenario to illustrate the flow. A successful connection is the easiest to demonstrate. I'd define the input parameters (like the target IP and port) and describe the expected output (a successful QUIC session). I'd also consider a failure scenario (like an invalid server certificate) to show error handling.
* **User/Programming Errors:** I'd think about common misconfigurations or coding mistakes that could lead to problems in this part of the network stack. Examples include incorrect server certificates, network connectivity issues, or inconsistencies in QUIC version negotiation.
* **User Operation to Reach This Code (Debugging):** I'd trace a typical user action that triggers a network request. Starting with the user typing a URL or clicking a link, I'd follow the path through DNS resolution and then to the connection establishment phase where this code is executed.

**5. Refinement and Structuring the Answer:**

Finally, I'd organize the information clearly, using headings and bullet points to make it easy to read and understand. I'd ensure that the answers are concise and directly address the questions in the prompt. I'd double-check for accuracy and clarity.

This structured approach, starting with a high-level understanding and gradually diving deeper, allows for a comprehensive analysis of the code and enables answering the various aspects of the prompt effectively. The focus is on understanding the *purpose* of the code and how its different parts contribute to that purpose.
这个文件 `net/quic/quic_session_attempt.cc` 的主要功能是**尝试建立一个新的 QUIC 会话连接**。它封装了建立 QUIC 连接所需的步骤和状态管理。

以下是它的具体功能分解：

**核心功能：**

1. **发起和管理 QUIC 会话建立过程:**  `QuicSessionAttempt` 类负责协调建立 QUIC 连接的各个阶段，包括创建会话对象、执行 TLS 握手（CryptoConnect）、处理连接结果等。

2. **支持直接连接和代理连接:**  代码中存在两种构造函数，分别处理直接连接到目标服务器以及通过代理服务器建立连接的情况。

3. **处理异步和同步的会话创建:**  根据 `net::features::kAsyncQuicSession` 特性标志，可以使用异步或同步的方式创建底层的 QUIC 会话。

4. **处理连接失败和重试:**  当连接失败时，该类会负责清理资源，并可能根据策略决定是否在备用网络上重试连接（特别是在握手完成之前）。

5. **与 `QuicSessionPool` 交互:**  `QuicSessionAttempt` 需要与 `QuicSessionPool` 交互，以便创建新的会话，并在成功建立连接后激活会话，以便后续的请求可以复用该连接。

6. **记录连接相关的指标:**  代码中使用了大量的 `UMA_HISTOGRAM_*` 宏来记录连接尝试的各种指标，例如连接耗时、失败原因、是否在备用网络上重试等，用于性能分析和监控。

7. **处理 DNS 别名:** 如果启用了 DNS 别名，它会考虑使用已解析的 DNS 别名来匹配已存在的会话。

8. **处理连接 IP 地址池化:**  在成功建立连接后，会检查是否已经存在具有相同 IP 地址的活动会话，如果存在，则关闭当前会话并使用已有的会话，以提高连接复用率。

**与 JavaScript 功能的关系：**

`quic_session_attempt.cc` 是 Chromium 网络栈的底层 C++ 代码，它并不直接与 JavaScript 交互。但是，当浏览器中的 JavaScript 代码（例如通过 `fetch` API 或 `XMLHttpRequest`）发起一个 HTTPS 请求时，如果服务器支持 QUIC 协议，Chromium 网络栈会尝试使用 QUIC 建立连接。`quic_session_attempt.cc` 正是在这个过程中发挥作用的。

**举例说明：**

假设你在浏览器地址栏中输入 `https://www.example.com` 并按下回车键。

1. **JavaScript 发起请求:** 浏览器的渲染引擎会解析 URL，并确定需要发起一个 HTTPS 请求。
2. **网络栈介入:**  Chromium 的网络栈开始处理这个请求。它会首先进行 DNS 解析，获取 `www.example.com` 的 IP 地址。
3. **尝试 QUIC 连接:** 如果网络栈认为可以使用 QUIC，它会尝试找到一个已存在的到 `www.example.com` 的 QUIC 会话。如果找不到，或者需要建立新的连接，就会创建 `QuicSessionAttempt` 对象。
4. **`quic_session_attempt.cc` 工作:** `QuicSessionAttempt` 对象会执行一系列操作，例如创建 QUIC 连接、执行 TLS 握手等，最终建立与服务器的 QUIC 连接。
5. **数据传输:** 一旦 QUIC 连接建立成功，JavaScript 发起的请求的数据就可以通过这个连接发送到服务器，服务器的响应也会通过这个连接返回给浏览器，最终被 JavaScript 处理并渲染到页面上。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* `delegate_`: 一个实现了 `QuicSessionAttempt::Delegate` 接口的对象，用于接收连接状态的通知。
* `ip_endpoint_`:  目标服务器的 IP 地址和端口号，例如 `203.0.113.42:443`。
* `quic_version_`:  要使用的 QUIC 协议版本，例如 `QuicVersion::v1`。
* 其他配置参数，例如证书校验标志、DNS 解析时间等。

**可能输出 (成功情况):**

* `Start()` 方法返回 `OK`。
* `delegate_->OnQuicSessionCreationComplete(OK)` 被调用。
* `QuicSessionPool` 中会添加一个新的到目标服务器的活动 QUIC 会话。

**可能输出 (失败情况):**

* `Start()` 方法返回一个非 `OK` 的错误码，例如 `ERR_CONNECTION_REFUSED` 或 `ERR_QUIC_HANDSHAKE_FAILED`。
* `delegate_->OnQuicSessionCreationComplete(错误码)` 被调用。
* `QuicSessionPool` 中不会添加新的活动会话（或者添加了但很快被移除）。
* 可能会记录相关的错误信息到网络日志中。

**涉及用户或者编程常见的使用错误 (作为调试线索):**

1. **服务器配置错误:**
   * **用户操作:** 用户尝试访问一个启用了 QUIC 但配置错误的服务器。
   * **可能发生的错误:** `ERR_QUIC_PROTOCOL_ERROR`, `ERR_QUIC_HANDSHAKE_FAILED`。
   * **调试线索:** 网络日志可能会显示握手失败的具体原因，例如证书校验失败、协议版本不匹配等。`HistogramProtocolErrorLocation` 可能会记录错误发生的具体阶段。

2. **网络问题:**
   * **用户操作:** 用户的网络环境不稳定，或者存在防火墙阻止 QUIC 连接。
   * **可能发生的错误:** `ERR_CONNECTION_TIMED_OUT`, `ERR_NETWORK_CHANGED`。
   * **调试线索:** 网络日志可能会显示连接超时或网络变更的事件。`retry_on_alternate_network_before_handshake_` 相关的逻辑可能会被触发。

3. **客户端配置问题 (不太常见，因为通常是 Chromium 内部处理):**
   * **编程错误:** 在 Chromium 的配置中，QUIC 被错误地禁用，或者相关的证书配置不正确。
   * **可能发生的错误:** 可能根本不会尝试建立 QUIC 连接，或者在早期阶段就失败。
   * **调试线索:** 需要检查 Chromium 的 QUIC 相关配置和标志。

4. **代理配置问题:**
   * **用户操作:** 用户使用了配置错误的代理服务器，导致 QUIC 连接无法通过代理建立。
   * **可能发生的错误:** 连接相关的错误，类似于直接连接失败的情况。
   * **调试线索:** 需要检查代理服务器的配置和日志。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

以下是一个用户操作导致 `quic_session_attempt.cc` 代码被执行的步骤：

1. **用户在浏览器地址栏输入一个 `https://` 开头的 URL 并按下回车键，或者点击了一个 HTTPS 链接。**  这是触发网络请求的起始点。

2. **浏览器进程的 UI 线程接收到请求，并传递给网络进程 (Network Service)。**

3. **网络进程开始处理请求。首先，它会检查缓存中是否有可用的资源。** 如果没有，则需要发起网络连接。

4. **网络进程进行 DNS 解析，获取目标服务器的 IP 地址。**  这可能涉及到查询本地缓存、操作系统 DNS 缓存，或者向 DNS 服务器发起查询。

5. **网络进程检查是否已经存在到目标服务器的活动 QUIC 会话。** `QuicSessionPool` 会负责管理已存在的 QUIC 会话。

6. **如果不存在可用的 QUIC 会话，网络进程会决定是否尝试建立一个新的 QUIC 连接。** 这取决于多种因素，例如服务器是否支持 QUIC、客户端是否启用了 QUIC、是否存在历史连接信息等。

7. **如果决定尝试建立 QUIC 连接，网络进程会创建一个 `QuicSessionAttempt` 对象。**  创建对象时会传入必要的参数，例如目标 IP 地址、端口号、QUIC 版本等。

8. **调用 `QuicSessionAttempt::Start()` 方法，开始执行 QUIC 连接的建立过程。**  这就是进入 `quic_session_attempt.cc` 代码的关键点。

9. **`QuicSessionAttempt::DoLoop()` 方法会被调用，驱动状态机，执行创建会话、TLS 握手等步骤。**

10. **在 `DoCreateSession()` 中，会根据配置选择同步或异步的方式创建底层的 QUIC 会话。**

11. **如果创建会话成功，会调用 `DoCryptoConnect()` 执行 TLS 握手。**

12. **握手成功后，会调用 `DoConfirmConnection()` 确认连接，并尝试激活会话。**

13. **如果在任何阶段发生错误，会执行相应的错误处理逻辑，并通知 `Delegate` 对象。**

**调试线索:**

* **NetLog (chrome://net-export/):**  这是最重要的调试工具。它可以记录网络栈中发生的各种事件，包括 DNS 解析、连接建立、数据传输等。通过分析 NetLog，可以详细了解 QUIC 连接尝试的每一步，查看是否有错误发生，以及错误发生的时间和原因。你可以搜索与 "QUIC_SESSION_POOL_JOB_CONNECT" 相关的事件，来跟踪连接尝试的过程。

* **chrome://flags/:**  可以检查和修改 Chromium 的实验性功能，包括 QUIC 相关的设置。确保 QUIC 未被禁用。

* **Wireshark 或 tcpdump:** 可以捕获网络数据包，查看 QUIC 握手的具体过程，例如 ClientHello、ServerHello 等消息的内容，以便排查 TLS 握手相关的问题。

* **断点调试:**  如果你正在开发或调试 Chromium 本身，可以在 `quic_session_attempt.cc` 中设置断点，逐步跟踪代码的执行流程，查看变量的值，理解代码的逻辑。

通过以上分析，可以较为全面地了解 `net/quic/quic_session_attempt.cc` 文件的功能，它在 QUIC 连接建立过程中的作用，以及如何利用调试工具来排查相关问题。

### 提示词
```
这是目录为net/quic/quic_session_attempt.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/quic/quic_session_attempt.h"

#include "base/auto_reset.h"
#include "base/feature_list.h"
#include "net/base/completion_once_callback.h"
#include "net/base/features.h"
#include "net/base/net_error_details.h"
#include "net/base/net_errors.h"
#include "net/dns/public/host_resolver_results.h"
#include "net/log/net_log_with_source.h"
#include "net/quic/address_utils.h"
#include "net/quic/quic_http_stream.h"
#include "net/quic/quic_session_pool.h"
#include "net/spdy/multiplexed_session_creation_initiator.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_versions.h"

namespace net {

namespace {

enum class JobProtocolErrorLocation {
  kSessionStartReadingFailedAsync = 0,
  kSessionStartReadingFailedSync = 1,
  kCreateSessionFailedAsync = 2,
  kCreateSessionFailedSync = 3,
  kCryptoConnectFailedSync = 4,
  kCryptoConnectFailedAsync = 5,
  kMaxValue = kCryptoConnectFailedAsync,
};

void HistogramProtocolErrorLocation(enum JobProtocolErrorLocation location) {
  UMA_HISTOGRAM_ENUMERATION("Net.QuicStreamFactory.DoConnectFailureLocation",
                            location);
}

void LogStaleConnectionTime(base::TimeTicks start_time) {
  UMA_HISTOGRAM_TIMES("Net.QuicSession.StaleConnectionTime",
                      base::TimeTicks::Now() - start_time);
}

void LogValidConnectionTime(base::TimeTicks start_time) {
  UMA_HISTOGRAM_TIMES("Net.QuicSession.ValidConnectionTime",
                      base::TimeTicks::Now() - start_time);
}

}  // namespace

QuicSessionAttempt::QuicSessionAttempt(
    Delegate* delegate,
    IPEndPoint ip_endpoint,
    ConnectionEndpointMetadata metadata,
    quic::ParsedQuicVersion quic_version,
    int cert_verify_flags,
    base::TimeTicks dns_resolution_start_time,
    base::TimeTicks dns_resolution_end_time,
    bool retry_on_alternate_network_before_handshake,
    bool use_dns_aliases,
    std::set<std::string> dns_aliases,
    std::unique_ptr<QuicCryptoClientConfigHandle> crypto_client_config_handle,
    MultiplexedSessionCreationInitiator session_creation_initiator)
    : delegate_(delegate),
      ip_endpoint_(std::move(ip_endpoint)),
      metadata_(std::move(metadata)),
      quic_version_(std::move(quic_version)),
      cert_verify_flags_(cert_verify_flags),
      dns_resolution_start_time_(dns_resolution_start_time),
      dns_resolution_end_time_(dns_resolution_end_time),
      was_alternative_service_recently_broken_(
          pool()->WasQuicRecentlyBroken(key().session_key())),
      retry_on_alternate_network_before_handshake_(
          retry_on_alternate_network_before_handshake),
      use_dns_aliases_(use_dns_aliases),
      dns_aliases_(std::move(dns_aliases)),
      crypto_client_config_handle_(std::move(crypto_client_config_handle)),
      session_creation_initiator_(session_creation_initiator) {
  CHECK(delegate_);
  DCHECK_NE(quic_version_, quic::ParsedQuicVersion::Unsupported());
}

QuicSessionAttempt::QuicSessionAttempt(
    Delegate* delegate,
    IPEndPoint local_endpoint,
    IPEndPoint proxy_peer_endpoint,
    quic::ParsedQuicVersion quic_version,
    int cert_verify_flags,
    std::unique_ptr<QuicChromiumClientStream::Handle> proxy_stream,
    const HttpUserAgentSettings* http_user_agent_settings,
    MultiplexedSessionCreationInitiator session_creation_initiator)
    : delegate_(delegate),
      ip_endpoint_(std::move(proxy_peer_endpoint)),
      quic_version_(std::move(quic_version)),
      cert_verify_flags_(cert_verify_flags),
      was_alternative_service_recently_broken_(
          pool()->WasQuicRecentlyBroken(key().session_key())),
      retry_on_alternate_network_before_handshake_(false),
      use_dns_aliases_(false),
      proxy_stream_(std::move(proxy_stream)),
      http_user_agent_settings_(http_user_agent_settings),
      local_endpoint_(std::move(local_endpoint)),
      session_creation_initiator_(session_creation_initiator) {
  CHECK(delegate_);
  DCHECK_NE(quic_version_, quic::ParsedQuicVersion::Unsupported());
}

QuicSessionAttempt::~QuicSessionAttempt() = default;

int QuicSessionAttempt::Start(CompletionOnceCallback callback) {
  CHECK_EQ(next_state_, State::kNone);

  next_state_ = State::kCreateSession;
  int rv = DoLoop(OK);
  if (rv != ERR_IO_PENDING) {
    return rv;
  }

  callback_ = std::move(callback);
  return rv;
}

void QuicSessionAttempt::PopulateNetErrorDetails(
    NetErrorDetails* details) const {
  if (session_) {
    details->connection_info = QuicHttpStream::ConnectionInfoFromQuicVersion(
        session_->connection()->version());
    details->quic_connection_error = session_->error();
  } else {
    details->connection_info = connection_info_;
    details->quic_connection_error = quic_connection_error_;
  }
}

int QuicSessionAttempt::DoLoop(int rv) {
  CHECK(!in_loop_);
  CHECK_NE(next_state_, State::kNone);

  base::AutoReset<bool> auto_reset(&in_loop_, true);
  do {
    State state = next_state_;
    next_state_ = State::kNone;
    switch (state) {
      case State::kNone:
        CHECK(false) << "Invalid state";
        break;
      case State::kCreateSession:
        rv = DoCreateSession();
        break;
      case State::kCreateSessionComplete:
        rv = DoCreateSessionComplete(rv);
        break;
      case State::kCryptoConnect:
        rv = DoCryptoConnect(rv);
        break;
      case State::kConfirmConnection:
        rv = DoConfirmConnection(rv);
        break;
    }
  } while (next_state_ != State::kNone && rv != ERR_IO_PENDING);
  return rv;
}

int QuicSessionAttempt::DoCreateSession() {
  quic_connection_start_time_ = base::TimeTicks::Now();
  next_state_ = State::kCreateSessionComplete;

  const bool require_confirmation = was_alternative_service_recently_broken_;
  net_log().AddEntryWithBoolParams(
      NetLogEventType::QUIC_SESSION_POOL_JOB_CONNECT, NetLogEventPhase::BEGIN,
      "require_confirmation", require_confirmation);

  int rv;
  if (proxy_stream_) {
    std::string user_agent;
    if (http_user_agent_settings_) {
      user_agent = http_user_agent_settings_->GetUserAgent();
    }
    // Proxied connections are not on any specific network.
    network_ = handles::kInvalidNetworkHandle;
    rv = pool()->CreateSessionOnProxyStream(
        base::BindOnce(&QuicSessionAttempt::OnCreateSessionComplete,
                       weak_ptr_factory_.GetWeakPtr()),
        key(), quic_version_, cert_verify_flags_, require_confirmation,
        std::move(local_endpoint_), std::move(ip_endpoint_),
        std::move(proxy_stream_), std::move(user_agent), net_log(), network_);
  } else {
    if (base::FeatureList::IsEnabled(net::features::kAsyncQuicSession)) {
      return pool()->CreateSessionAsync(
          base::BindOnce(&QuicSessionAttempt::OnCreateSessionComplete,
                         weak_ptr_factory_.GetWeakPtr()),
          key(), quic_version_, cert_verify_flags_, require_confirmation,
          ip_endpoint_, metadata_, dns_resolution_start_time_,
          dns_resolution_end_time_, net_log(), network_,
          session_creation_initiator_);
    }
    rv = pool()->CreateSessionSync(
        key(), quic_version_, cert_verify_flags_, require_confirmation,
        ip_endpoint_, metadata_, dns_resolution_start_time_,
        dns_resolution_end_time_, net_log(), &session_, &network_,
        session_creation_initiator_);

    DVLOG(1) << "Created session on network: " << network_;
  }
  if (rv == ERR_QUIC_PROTOCOL_ERROR) {
    DCHECK(!session_);
    HistogramProtocolErrorLocation(
        JobProtocolErrorLocation::kCreateSessionFailedSync);
  }
  return rv;
}

int QuicSessionAttempt::DoCreateSessionComplete(int rv) {
  session_creation_finished_ = true;
  if (rv != OK) {
    CHECK(!session_);
    return rv;
  }

  next_state_ = State::kCryptoConnect;
  if (!session_->connection()->connected()) {
    return ERR_CONNECTION_CLOSED;
  }

  CHECK(session_);
  session_->StartReading();
  if (!session_->connection()->connected()) {
    if (base::FeatureList::IsEnabled(net::features::kAsyncQuicSession)) {
      HistogramProtocolErrorLocation(
          JobProtocolErrorLocation::kSessionStartReadingFailedAsync);
    } else {
      HistogramProtocolErrorLocation(
          JobProtocolErrorLocation::kSessionStartReadingFailedSync);
    }
    return ERR_QUIC_PROTOCOL_ERROR;
  }
  return OK;
}

int QuicSessionAttempt::DoCryptoConnect(int rv) {
  if (rv != OK) {
    // Reset `session_` to avoid dangling pointer.
    ResetSession();
    return rv;
  }

  DCHECK(session_);
  next_state_ = State::kConfirmConnection;
  rv = session_->CryptoConnect(
      base::BindOnce(&QuicSessionAttempt::OnCryptoConnectComplete,
                     weak_ptr_factory_.GetWeakPtr()));

  if (rv != ERR_IO_PENDING) {
    LogValidConnectionTime(quic_connection_start_time_);
  }

  if (!session_->connection()->connected() &&
      session_->error() == quic::QUIC_PROOF_INVALID) {
    return ERR_QUIC_HANDSHAKE_FAILED;
  }

  if (rv == ERR_QUIC_PROTOCOL_ERROR) {
    HistogramProtocolErrorLocation(
        JobProtocolErrorLocation::kCryptoConnectFailedSync);
  }

  return rv;
}

int QuicSessionAttempt::DoConfirmConnection(int rv) {
  UMA_HISTOGRAM_TIMES("Net.QuicSession.TimeFromResolveHostToConfirmConnection",
                      base::TimeTicks::Now() - dns_resolution_start_time_);
  net_log().EndEvent(NetLogEventType::QUIC_SESSION_POOL_JOB_CONNECT);

  if (was_alternative_service_recently_broken_) {
    UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.ConnectAfterBroken", rv == OK);
  }

  if (retry_on_alternate_network_before_handshake_ && session_ &&
      !session_->OneRttKeysAvailable() &&
      network_ == pool()->default_network()) {
    if (session_->error() == quic::QUIC_NETWORK_IDLE_TIMEOUT ||
        session_->error() == quic::QUIC_HANDSHAKE_TIMEOUT ||
        session_->error() == quic::QUIC_PACKET_WRITE_ERROR) {
      // Retry the connection on an alternate network if crypto handshake failed
      // with network idle time out or handshake time out.
      DCHECK(network_ != handles::kInvalidNetworkHandle);
      network_ = pool()->FindAlternateNetwork(network_);
      connection_retried_ = network_ != handles::kInvalidNetworkHandle;
      UMA_HISTOGRAM_BOOLEAN(
          "Net.QuicStreamFactory.AttemptMigrationBeforeHandshake",
          connection_retried_);
      UMA_HISTOGRAM_ENUMERATION(
          "Net.QuicStreamFactory.AttemptMigrationBeforeHandshake."
          "FailedConnectionType",
          NetworkChangeNotifier::GetNetworkConnectionType(
              pool()->default_network()),
          NetworkChangeNotifier::ConnectionType::CONNECTION_LAST + 1);
      if (connection_retried_) {
        UMA_HISTOGRAM_ENUMERATION(
            "Net.QuicStreamFactory.MigrationBeforeHandshake.NewConnectionType",
            NetworkChangeNotifier::GetNetworkConnectionType(network_),
            NetworkChangeNotifier::ConnectionType::CONNECTION_LAST + 1);
        net_log().AddEvent(
            NetLogEventType::QUIC_SESSION_POOL_JOB_RETRY_ON_ALTERNATE_NETWORK);
        // Notify requests that connection on the default network failed.
        delegate_->OnConnectionFailedOnDefaultNetwork();
        DVLOG(1) << "Retry connection on alternate network: " << network_;
        session_ = nullptr;
        next_state_ = State::kCreateSession;
        return OK;
      }
    }
  }

  if (connection_retried_) {
    UMA_HISTOGRAM_BOOLEAN("Net.QuicStreamFactory.MigrationBeforeHandshake2",
                          rv == OK);
    if (rv == OK) {
      UMA_HISTOGRAM_BOOLEAN(
          "Net.QuicStreamFactory.NetworkChangeDuringMigrationBeforeHandshake",
          network_ == pool()->default_network());
    } else {
      base::UmaHistogramSparse(
          "Net.QuicStreamFactory.MigrationBeforeHandshakeFailedReason", -rv);
    }
  } else if (network_ != handles::kInvalidNetworkHandle &&
             network_ != pool()->default_network()) {
    UMA_HISTOGRAM_BOOLEAN("Net.QuicStreamFactory.ConnectionOnNonDefaultNetwork",
                          rv == OK);
  }

  if (rv != OK) {
    // Reset `session_` to avoid dangling pointer.
    ResetSession();
    return rv;
  }

  DCHECK(!pool()->HasActiveSession(key().session_key()));
  // There may well now be an active session for this IP.  If so, use the
  // existing session instead.
  if (pool()->HasMatchingIpSession(
          key(), {ToIPEndPoint(session_->connection()->peer_address())},
          /*aliases=*/{}, use_dns_aliases_)) {
    QuicSessionPool::LogConnectionIpPooling(true);
    session_->connection()->CloseConnection(
        quic::QUIC_CONNECTION_IP_POOLED,
        "An active session exists for the given IP.",
        quic::ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    session_ = nullptr;
    return OK;
  }
  QuicSessionPool::LogConnectionIpPooling(false);

  pool()->ActivateSession(
      key(), session_,
      use_dns_aliases_ ? std::move(dns_aliases_) : std::set<std::string>());

  return OK;
}

void QuicSessionAttempt::OnCreateSessionComplete(
    base::expected<CreateSessionResult, int> result) {
  CHECK_EQ(next_state_, State::kCreateSessionComplete);
  if (result.has_value()) {
    session_ = result->session;
    network_ = result->network;
    DVLOG(1) << "Created session on network: " << network_;
  } else {
    if (result.error() == ERR_QUIC_PROTOCOL_ERROR) {
      HistogramProtocolErrorLocation(
          JobProtocolErrorLocation::kCreateSessionFailedAsync);
    }
  }

  int rv = DoLoop(result.error_or(OK));

  delegate_->OnQuicSessionCreationComplete(rv);

  if (rv != ERR_IO_PENDING && !callback_.is_null()) {
    std::move(callback_).Run(rv);
  }
}

void QuicSessionAttempt::OnCryptoConnectComplete(int rv) {
  CHECK_EQ(next_state_, State::kConfirmConnection);

  // This early return will be triggered when CloseSessionOnError is called
  // before crypto handshake has completed.
  if (!session_) {
    LogStaleConnectionTime(quic_connection_start_time_);
    return;
  }

  if (rv == ERR_QUIC_PROTOCOL_ERROR) {
    HistogramProtocolErrorLocation(
        JobProtocolErrorLocation::kCryptoConnectFailedAsync);
  }

  rv = DoLoop(rv);
  if (rv != ERR_IO_PENDING && !callback_.is_null()) {
    std::move(callback_).Run(rv);
  }
}

void QuicSessionAttempt::ResetSession() {
  CHECK(session_);
  connection_info_ = QuicHttpStream::ConnectionInfoFromQuicVersion(
      session_->connection()->version());
  quic_connection_error_ = session_->error();
  session_ = nullptr;
}

}  // namespace net
```