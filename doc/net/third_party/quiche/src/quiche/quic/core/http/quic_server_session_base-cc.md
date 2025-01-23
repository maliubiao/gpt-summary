Response:
Let's break down the thought process to analyze the provided C++ code for `quic_server_session_base.cc`.

1. **Understand the Goal:** The request asks for the functionalities of this specific file within the Chromium network stack, its relation to JavaScript, logical reasoning with input/output examples, common user/programming errors, and debugging information.

2. **Initial Code Scan and Keyword Identification:**  The first step is to quickly read through the code, looking for keywords and class names that provide hints about its purpose. Keywords like `Server`, `Session`, `HTTP`, `Quic`, `Crypto`, `Config`, `Resumption`, `Bandwidth`, `Settings`, `Stream`, `Connection` immediately stand out. This suggests the file deals with the server-side handling of QUIC connections at the HTTP layer, focusing on session management, cryptography, and performance optimization.

3. **Identify Core Responsibilities:** Based on the keywords and initial scan, we can start grouping functionalities. The class `QuicServerSessionBase` seems to be the central entity. Its constructor and methods like `Initialize`, `OnConfigNegotiated`, `OnConnectionClosed`, `OnCongestionWindowChange`, `ShouldCreateIncomingStream`, `ShouldCreateOutgoingBidirectionalStream`, `ShouldCreateOutgoingUnidirectionalStream`, etc., clearly indicate session lifecycle management, connection events handling, stream creation decisions, and congestion control interactions.

4. **Analyze Key Methods in Detail:**  Now, delve deeper into the important methods:

    * **`Initialize()`:**  Creates the crypto stream, calls the parent's initialization, and sends settings. This suggests setting up the secure connection.
    * **`OnConfigNegotiated()`:** Handles post-negotiation tasks, specifically looking at cached network parameters for RTT and bandwidth resumption. The checks for `kTRTT`, `kNRES`, `kBWRE`, `kBWMX` are important for understanding feature enabling/disabling.
    * **`OnConnectionClosed()`:**  Cleans up resources, particularly the crypto stream.
    * **`OnCongestionWindowChange()`:** This is crucial for bandwidth resumption. The logic involving `kMinIntervalBetweenServerConfigUpdatesRTTs`, `kMinIntervalBetweenServerConfigUpdatesMs`, `kMinPacketsBetweenServerConfigUpdates`, and the 50% bandwidth change threshold are key aspects of its function.
    * **`ShouldCreate*Stream()` methods:** These control stream creation based on connection state and stream IDs.
    * **`GenerateCachedNetworkParameters()`:** This function is responsible for collecting and packaging network performance information to be potentially sent to the client for future connection resumption.

5. **Look for JavaScript Connections:**  The request specifically asks about connections to JavaScript. There's no direct JavaScript interaction within this C++ code. However, the code deals with HTTP over QUIC, which *is* the underlying transport for web browsers (which run JavaScript). The connection to JavaScript is *indirect*. The server's behavior here directly impacts the performance and functionality experienced by JavaScript code in the browser when making network requests. Focus on concepts like connection establishment, security (crypto), and performance optimization (bandwidth resumption) as these are directly relevant to the browser's ability to load web pages and execute JavaScript efficiently.

6. **Identify Logical Reasoning Points:**  The `OnCongestionWindowChange` method is a prime example of logical reasoning. It takes the current congestion state and makes decisions about whether to send a bandwidth update. To illustrate this, create a simple scenario:

    * **Input:**  Simulate time passing, packets being sent, and changes in estimated bandwidth.
    * **Output:** Determine if a server config update is sent based on the various conditions.

7. **Pinpoint Potential User/Programming Errors:**  Think about common mistakes developers might make when interacting with or extending this kind of code. Consider:

    * **Incorrect Configuration:** Setting up the crypto configuration incorrectly could prevent secure connections.
    * **Resumption Issues:**  Misunderstanding the conditions for resumption could lead to it not working as expected.
    * **Stream Management:** Incorrectly handling stream IDs or attempting to create streams in the wrong state.

8. **Trace User Actions to Reach the Code:** Imagine a user browsing the web. How does their interaction lead to this server-side code being executed?  Start from the user typing a URL and trace the path:

    * User types URL.
    * Browser resolves the domain and initiates a connection.
    * If QUIC is negotiated, the browser establishes a QUIC connection to the server.
    * This `QuicServerSessionBase` instance is created on the server to handle that connection.
    * Actions like loading resources, submitting forms, etc., trigger the creation of streams managed by this session.

9. **Structure the Answer:** Organize the findings into the requested categories: Functionalities, JavaScript Relationship, Logical Reasoning, User/Programming Errors, and Debugging. Use clear and concise language. Provide code snippets or examples where relevant.

10. **Review and Refine:**  Read through the answer to ensure accuracy, clarity, and completeness. Check for any logical inconsistencies or missing information. Ensure the examples are easy to understand and directly relate to the code. For instance, initially, I might have only stated "manages the server-side QUIC session." While true, it lacks specifics. Refining it to include "handling connection setup, security negotiation (TLS/SSL), stream management, and performance optimizations like bandwidth resumption" is much more informative. Similarly, when explaining the JavaScript connection, simply saying "it's used by browsers" is too vague. Specifying *how* it's used (transport for web requests) and what aspects are relevant to JavaScript (performance, security) provides better context.
这个文件 `net/third_party/quiche/src/quiche/quic/core/http/quic_server_session_base.cc` 是 Chromium 网络栈中 QUIC 协议实现的服务器端会话基类。它定义了 QUIC 服务器会话的基本行为和功能，是所有具体 QUIC 服务器会话的父类。

**主要功能:**

1. **会话生命周期管理:**
   - 初始化会话：`Initialize()` 方法负责创建和配置加密流 (`QuicCryptoServerStream`)，并调用父类 (`QuicSpdySession`) 的初始化方法。
   - 处理配置协商：`OnConfigNegotiated()` 方法在 QUIC 连接配置协商完成后被调用，用于处理诸如带宽恢复等特定于服务器的逻辑。
   - 处理连接关闭：`OnConnectionClosed()` 方法处理连接关闭事件，并执行必要的清理工作，例如取消挂起的加密回调。

2. **加密处理:**
   - 关联加密流：通过 `crypto_stream_` 成员持有 `QuicCryptoServerStreamBase` 实例，负责 QUIC 连接的加密和身份验证。
   - 发送服务器配置更新 (SCUP)：在满足一定条件时，例如拥塞窗口发生变化，并且自上次发送 SCUP 以来经过了足够的时间，会通过加密流发送服务器配置更新给客户端，以优化连接性能。
   - 获取 SSL 配置：`GetSSLConfig()` 方法返回服务器的 SSL 配置。

3. **流管理:**
   - 决定是否创建流：`ShouldCreateIncomingStream()`, `ShouldCreateOutgoingBidirectionalStream()`, `ShouldCreateOutgoingUnidirectionalStream()` 方法决定是否允许创建特定类型的 QUIC 流，例如判断是否是客户端发起的流，以及加密是否已经建立。

4. **带宽恢复 (Bandwidth Resumption):**
   - 启用和禁用带宽恢复：根据客户端发送的连接选项 (`kBWRE`, `kBWMX`) 决定是否启用带宽恢复。
   - 使用缓存的网络参数：如果客户端提供了来自相同服务区域的缓存网络参数，并且时间戳足够新，则会尝试恢复连接状态，包括带宽估计。
   - 发送带宽估计更新：`OnCongestionWindowChange()` 方法负责检测拥塞窗口的变化，并在满足条件时通过服务器配置更新 (SCUP) 将新的带宽估计发送给客户端。

5. **发送设置 (Settings) 帧:**
   - `SendSettingsToCryptoStream()` 方法将服务器的 HTTP/3 或 HTTP/2 设置序列化并通过加密流发送给客户端。

6. **生成缓存的网络参数:**
   - `GenerateCachedNetworkParameters()` 方法收集当前连接的网络状态信息，例如最小 RTT、带宽估计等，用于生成 `CachedNetworkParameters` 对象，以便将来客户端可以进行连接恢复。

**与 JavaScript 的关系:**

这个 C++ 代码本身不直接与 JavaScript 交互。然而，它在 Chromium 网络栈中扮演着关键角色，直接影响着运行在浏览器中的 JavaScript 代码的网络性能和功能：

* **HTTP/3 的底层支持:** QUIC 是 HTTP/3 的底层传输协议。当浏览器使用 HTTP/3 与服务器通信时，服务器端的 `QuicServerSessionBase` 及其子类负责处理底层的 QUIC 连接管理、加密、流控制等。这直接影响了 JavaScript 发起的网络请求的效率和速度。
* **性能优化:** `QuicServerSessionBase` 中实现的带宽恢复功能可以显著提升页面加载速度和用户体验。当用户在一段时间后重新访问同一个服务器时，如果服务器能够恢复之前的连接状态（包括带宽估计），就可以更快地建立连接并传输数据，这对于 JavaScript 发起的资源加载（例如脚本、图片、CSS）至关重要。
* **安全性:**  `QuicCryptoServerStream` 负责处理 QUIC 连接的加密，这确保了 JavaScript 通过网络发送和接收的数据的安全性。

**举例说明 JavaScript 的关系:**

假设一个用户通过浏览器访问一个支持 HTTP/3 的网站。当浏览器发起连接时，服务器端会创建一个 `QuicServerSessionBase` 实例来处理这个连接。

1. **初始连接:** 当浏览器首次连接到服务器时，`OnConfigNegotiated()` 方法会被调用。如果客户端之前访问过这个服务器，并且服务器支持带宽恢复，那么服务器可能会收到客户端提供的缓存网络参数。服务器会使用这些参数来初始化连接的拥塞控制状态，从而可能更快地达到较高的传输速率。这使得 JavaScript 代码可以更快地加载所需的资源。

   * **假设输入:** 客户端发送包含之前连接的带宽估计的连接选项。
   * **输出:** 服务器的拥塞控制算法以一个更高的初始窗口启动，从而允许更快的数据传输。JavaScript 代码可以更快地下载页面上的图片和脚本。

2. **带宽估计更新:**  在连接持续期间，如果服务器检测到网络条件发生显著变化（例如，可用带宽增加），`OnCongestionWindowChange()` 方法可能会触发发送服务器配置更新 (SCUP)。

   * **假设输入:** 服务器检测到可用带宽增加了 60%。
   * **输出:** 服务器向客户端发送包含新的带宽估计的 SCUP 帧。客户端浏览器会使用这个新的估计来调整其发送速率，从而可能提高后续 JavaScript 发起的网络请求的吞吐量。

**用户或编程常见的使用错误:**

1. **服务器配置错误:**  如果服务器的 QUIC 配置不正确，例如加密配置缺失或错误，会导致连接建立失败。用户在浏览器中会看到连接错误或页面加载失败。

   * **用户操作:** 用户尝试访问一个仅支持 HTTP/3 且服务器配置错误的网站。
   * **到达这里的步骤:**
      1. 浏览器发送 ClientHello 消息。
      2. 服务器尝试创建 `QuicServerSessionBase` 实例。
      3. `QuicCryptoServerStream` 初始化失败，因为配置错误。
      4. 连接无法建立，`OnConnectionClosed()` 被调用，并可能记录错误信息。

2. **不正确的证书配置:**  如果服务器没有正确配置 TLS 证书，或者证书已过期，浏览器会拒绝连接。

   * **用户操作:** 用户尝试访问一个 HTTPS 网站，但服务器的 TLS 证书无效。
   * **到达这里的步骤:**
      1. 浏览器发送 ClientHello 消息。
      2. 服务器创建 `QuicCryptoServerStream`。
      3. TLS 握手失败，因为证书验证失败。
      4. `OnConnectionClosed()` 被调用，指示 TLS 握手错误。

3. **没有正确处理连接选项:**  如果服务器没有正确解析和处理客户端发送的连接选项，可能会导致带宽恢复等功能无法正常工作。

   * **编程错误:**  在 `OnConfigNegotiated()` 方法中，没有正确检查和处理 `kBWRE` 或 `kBWMX` 等连接选项。
   * **用户操作:** 用户从一个之前访问过的网站重新连接。
   * **到达这里的步骤:**
      1. 浏览器发送包含 `kBWRE` 的 ClientHello 消息。
      2. 服务器创建 `QuicServerSessionBase` 实例。
      3. `OnConfigNegotiated()` 被调用，但由于编程错误，`bandwidth_resumption_enabled_` 未被正确设置为 `true`。
      4. 后续的 `OnCongestionWindowChange()` 不会发送带宽估计更新，即使网络条件发生变化。

**用户操作如何一步步的到达这里，作为调试线索:**

假设用户在浏览器中输入一个 URL 并按下回车键，访问一个使用 QUIC 协议的网站：

1. **DNS 解析:** 浏览器首先进行 DNS 查询，获取目标服务器的 IP 地址。
2. **连接尝试:** 浏览器尝试与服务器建立连接。如果浏览器和服务器都支持 QUIC，并且网络条件允许，浏览器会尝试建立 QUIC 连接。
3. **QUIC 握手:** 浏览器发送一个 Initial QUIC 数据包，其中包含连接 ID 和支持的 QUIC 版本等信息。
4. **服务器响应:** 服务器接收到连接请求后，会创建一个 `QuicServerSessionBase` 的实例（或其子类）来处理这个新的连接。
5. **配置协商:** 服务器通过 `QuicCryptoServerStream` 进行 TLS 握手，并协商 QUIC 的连接参数，例如最大数据包大小、流控制参数等。`OnConfigNegotiated()` 方法在这个阶段会被调用。
6. **数据传输:**  连接建立成功后，浏览器可以开始发送 HTTP 请求，请求网页的 HTML、CSS、JavaScript、图片等资源。这些请求会通过 QUIC 流进行传输。
7. **会话管理:** `QuicServerSessionBase` 负责管理这些 QUIC 流，处理数据的发送和接收，以及维护连接的状态。
8. **带宽恢复 (如果启用):** 在连接过程中，如果服务器检测到可以发送带宽估计更新，`OnCongestionWindowChange()` 会被调用，并通过加密流发送更新。
9. **连接关闭:** 当用户关闭浏览器标签页或窗口，或者网络连接中断时，QUIC 连接会被关闭，`OnConnectionClosed()` 方法会被调用，清理资源。

**作为调试线索:**

* **查看 QUIC 事件日志:** Chromium 提供了 QUIC 事件日志，可以记录 QUIC 连接的详细信息，包括连接建立、配置协商、流的创建和关闭、拥塞控制事件等。通过查看这些日志，可以了解 `QuicServerSessionBase` 的生命周期和行为。
* **断点调试:**  可以使用调试器（如 gdb 或 lldb）在 `QuicServerSessionBase` 的关键方法上设置断点，例如 `Initialize()`, `OnConfigNegotiated()`, `OnConnectionClosed()`, `OnCongestionWindowChange()` 等，来跟踪代码的执行流程，检查变量的值，并理解服务器在特定事件发生时的行为。
* **网络抓包:** 使用 Wireshark 等网络抓包工具可以捕获 QUIC 连接的网络数据包，分析 QUIC 握手过程、QUIC 帧的类型和内容，以及服务器发送的服务器配置更新等信息。这可以帮助理解服务器和客户端之间的交互，以及可能出现的问题。
* **QUIC 内部状态检查:** Chromium 提供了可以查看 QUIC 连接内部状态的工具或方法，例如查看连接的拥塞窗口、RTT、带宽估计等。这可以帮助诊断性能问题或带宽恢复相关的问题。

总而言之，`net/third_party/quiche/src/quiche/quic/core/http/quic_server_session_base.cc` 是 QUIC 服务器端实现的核心组件，负责管理 QUIC 会话的生命周期、处理加密、管理 QUIC 流，并实现诸如带宽恢复等重要的性能优化功能，它间接地但至关重要地影响着浏览器中 JavaScript 代码的网络性能和安全性。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/quic_server_session_base.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/http/quic_server_session_base.h"

#include <algorithm>
#include <cstdlib>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "quiche/quic/core/proto/cached_network_parameters_proto.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_stream.h"
#include "quiche/quic/core/quic_tag.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace quic {

QuicServerSessionBase::QuicServerSessionBase(
    const QuicConfig& config, const ParsedQuicVersionVector& supported_versions,
    QuicConnection* connection, Visitor* visitor,
    QuicCryptoServerStreamBase::Helper* helper,
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache)
    : QuicSpdySession(connection, visitor, config, supported_versions),
      crypto_config_(crypto_config),
      compressed_certs_cache_(compressed_certs_cache),
      helper_(helper),
      bandwidth_resumption_enabled_(false),
      bandwidth_estimate_sent_to_client_(QuicBandwidth::Zero()),
      last_scup_time_(QuicTime::Zero()) {}

QuicServerSessionBase::~QuicServerSessionBase() {}

void QuicServerSessionBase::Initialize() {
  crypto_stream_ =
      CreateQuicCryptoServerStream(crypto_config_, compressed_certs_cache_);
  QuicSpdySession::Initialize();
  SendSettingsToCryptoStream();
}

void QuicServerSessionBase::OnConfigNegotiated() {
  QuicSpdySession::OnConfigNegotiated();

  const CachedNetworkParameters* cached_network_params =
      crypto_stream_->PreviousCachedNetworkParams();

  // Set the initial rtt from cached_network_params.min_rtt_ms, which comes from
  // a validated address token. This will override the initial rtt that may have
  // been set by the transport parameters.
  if (version().UsesTls() && cached_network_params != nullptr) {
    if (cached_network_params->serving_region() == serving_region_) {
      QUIC_CODE_COUNT(quic_server_received_network_params_at_same_region);
      if (config()->HasReceivedConnectionOptions() &&
          ContainsQuicTag(config()->ReceivedConnectionOptions(), kTRTT)) {
        QUIC_DLOG(INFO)
            << "Server: Setting initial rtt to "
            << cached_network_params->min_rtt_ms()
            << "ms which is received from a validated address token";
        connection()->sent_packet_manager().SetInitialRtt(
            QuicTime::Delta::FromMilliseconds(
                cached_network_params->min_rtt_ms()),
            /*trusted=*/true);
      }
    } else {
      QUIC_CODE_COUNT(quic_server_received_network_params_at_different_region);
    }
  }

  if (!config()->HasReceivedConnectionOptions()) {
    return;
  }

  if (GetQuicReloadableFlag(quic_enable_disable_resumption) &&
      version().UsesTls() &&
      ContainsQuicTag(config()->ReceivedConnectionOptions(), kNRES) &&
      crypto_stream_->ResumptionAttempted()) {
    QUIC_RELOADABLE_FLAG_COUNT(quic_enable_disable_resumption);
    const bool disabled = crypto_stream_->DisableResumption();
    QUIC_BUG_IF(quic_failed_to_disable_resumption, !disabled)
        << "Failed to disable resumption";
  }

  // Enable bandwidth resumption if peer sent correct connection options.
  const bool last_bandwidth_resumption =
      ContainsQuicTag(config()->ReceivedConnectionOptions(), kBWRE);
  const bool max_bandwidth_resumption =
      ContainsQuicTag(config()->ReceivedConnectionOptions(), kBWMX);
  bandwidth_resumption_enabled_ =
      last_bandwidth_resumption || max_bandwidth_resumption;

  // If the client has provided a bandwidth estimate from the same serving
  // region as this server, then decide whether to use the data for bandwidth
  // resumption.
  if (cached_network_params != nullptr &&
      cached_network_params->serving_region() == serving_region_) {
    if (!version().UsesTls()) {
      // Log the received connection parameters, regardless of how they
      // get used for bandwidth resumption.
      connection()->OnReceiveConnectionState(*cached_network_params);
    }

    if (bandwidth_resumption_enabled_) {
      // Only do bandwidth resumption if estimate is recent enough.
      const uint64_t seconds_since_estimate =
          connection()->clock()->WallNow().ToUNIXSeconds() -
          cached_network_params->timestamp();
      if (seconds_since_estimate <= kNumSecondsPerHour) {
        connection()->ResumeConnectionState(*cached_network_params,
                                            max_bandwidth_resumption);
      }
    }
  }
}

void QuicServerSessionBase::OnConnectionClosed(
    const QuicConnectionCloseFrame& frame, ConnectionCloseSource source) {
  QuicSession::OnConnectionClosed(frame, source);
  // In the unlikely event we get a connection close while doing an asynchronous
  // crypto event, make sure we cancel the callback.
  if (crypto_stream_ != nullptr) {
    crypto_stream_->CancelOutstandingCallbacks();
  }
}

void QuicServerSessionBase::OnCongestionWindowChange(QuicTime now) {
  if (!bandwidth_resumption_enabled_) {
    return;
  }
  // Only send updates when the application has no data to write.
  if (HasDataToWrite()) {
    return;
  }

  // If not enough time has passed since the last time we sent an update to the
  // client, or not enough packets have been sent, then return early.
  const QuicSentPacketManager& sent_packet_manager =
      connection()->sent_packet_manager();
  int64_t srtt_ms =
      sent_packet_manager.GetRttStats()->smoothed_rtt().ToMilliseconds();
  int64_t now_ms = (now - last_scup_time_).ToMilliseconds();
  int64_t packets_since_last_scup = 0;
  const QuicPacketNumber largest_sent_packet =
      connection()->sent_packet_manager().GetLargestSentPacket();
  if (largest_sent_packet.IsInitialized()) {
    packets_since_last_scup =
        last_scup_packet_number_.IsInitialized()
            ? largest_sent_packet - last_scup_packet_number_
            : largest_sent_packet.ToUint64();
  }
  if (now_ms < (kMinIntervalBetweenServerConfigUpdatesRTTs * srtt_ms) ||
      now_ms < kMinIntervalBetweenServerConfigUpdatesMs ||
      packets_since_last_scup < kMinPacketsBetweenServerConfigUpdates) {
    return;
  }

  // If the bandwidth recorder does not have a valid estimate, return early.
  const QuicSustainedBandwidthRecorder* bandwidth_recorder =
      sent_packet_manager.SustainedBandwidthRecorder();
  if (bandwidth_recorder == nullptr || !bandwidth_recorder->HasEstimate()) {
    return;
  }

  // The bandwidth recorder has recorded at least one sustained bandwidth
  // estimate. Check that it's substantially different from the last one that
  // we sent to the client, and if so, send the new one.
  QuicBandwidth new_bandwidth_estimate =
      bandwidth_recorder->BandwidthEstimate();

  int64_t bandwidth_delta =
      std::abs(new_bandwidth_estimate.ToBitsPerSecond() -
               bandwidth_estimate_sent_to_client_.ToBitsPerSecond());

  // Define "substantial" difference as a 50% increase or decrease from the
  // last estimate.
  bool substantial_difference =
      bandwidth_delta >
      0.5 * bandwidth_estimate_sent_to_client_.ToBitsPerSecond();
  if (!substantial_difference) {
    return;
  }

  if (version().UsesTls()) {
    if (version().HasIetfQuicFrames() && MaybeSendAddressToken()) {
      bandwidth_estimate_sent_to_client_ = new_bandwidth_estimate;
    }
  } else {
    std::optional<CachedNetworkParameters> cached_network_params =
        GenerateCachedNetworkParameters();

    if (cached_network_params.has_value()) {
      bandwidth_estimate_sent_to_client_ = new_bandwidth_estimate;
      QUIC_DVLOG(1) << "Server: sending new bandwidth estimate (KBytes/s): "
                    << bandwidth_estimate_sent_to_client_.ToKBytesPerSecond();

      QUICHE_DCHECK_EQ(
          BandwidthToCachedParameterBytesPerSecond(
              bandwidth_estimate_sent_to_client_),
          cached_network_params->bandwidth_estimate_bytes_per_second());

      crypto_stream_->SendServerConfigUpdate(&*cached_network_params);

      connection()->OnSendConnectionState(*cached_network_params);
    }
  }

  last_scup_time_ = now;
  last_scup_packet_number_ =
      connection()->sent_packet_manager().GetLargestSentPacket();
}

bool QuicServerSessionBase::ShouldCreateIncomingStream(QuicStreamId id) {
  if (!connection()->connected()) {
    QUIC_BUG(quic_bug_10393_2)
        << "ShouldCreateIncomingStream called when disconnected";
    return false;
  }

  if (QuicUtils::IsServerInitiatedStreamId(transport_version(), id)) {
    QUIC_BUG(quic_bug_10393_3)
        << "ShouldCreateIncomingStream called with server initiated "
           "stream ID.";
    return false;
  }

  return true;
}

bool QuicServerSessionBase::ShouldCreateOutgoingBidirectionalStream() {
  if (!connection()->connected()) {
    QUIC_BUG(quic_bug_12513_2)
        << "ShouldCreateOutgoingBidirectionalStream called when disconnected";
    return false;
  }
  if (!crypto_stream_->encryption_established()) {
    QUIC_BUG(quic_bug_10393_4)
        << "Encryption not established so no outgoing stream created.";
    return false;
  }

  return CanOpenNextOutgoingBidirectionalStream();
}

bool QuicServerSessionBase::ShouldCreateOutgoingUnidirectionalStream() {
  if (!connection()->connected()) {
    QUIC_BUG(quic_bug_12513_3)
        << "ShouldCreateOutgoingUnidirectionalStream called when disconnected";
    return false;
  }
  if (!crypto_stream_->encryption_established()) {
    QUIC_BUG(quic_bug_10393_5)
        << "Encryption not established so no outgoing stream created.";
    return false;
  }

  return CanOpenNextOutgoingUnidirectionalStream();
}

QuicCryptoServerStreamBase* QuicServerSessionBase::GetMutableCryptoStream() {
  return crypto_stream_.get();
}

const QuicCryptoServerStreamBase* QuicServerSessionBase::GetCryptoStream()
    const {
  return crypto_stream_.get();
}

int32_t QuicServerSessionBase::BandwidthToCachedParameterBytesPerSecond(
    const QuicBandwidth& bandwidth) const {
  return static_cast<int32_t>(std::min<int64_t>(
      bandwidth.ToBytesPerSecond(), std::numeric_limits<int32_t>::max()));
}

void QuicServerSessionBase::SendSettingsToCryptoStream() {
  if (!version().UsesTls()) {
    return;
  }
  std::string settings_frame = HttpEncoder::SerializeSettingsFrame(settings());

  std::unique_ptr<ApplicationState> serialized_settings =
      std::make_unique<ApplicationState>(
          settings_frame.data(),
          settings_frame.data() + settings_frame.length());
  GetMutableCryptoStream()->SetServerApplicationStateForResumption(
      std::move(serialized_settings));
}

QuicSSLConfig QuicServerSessionBase::GetSSLConfig() const {
  QUICHE_DCHECK(crypto_config_ && crypto_config_->proof_source());

  QuicSSLConfig ssl_config = crypto_config_->ssl_config();

  ssl_config.disable_ticket_support =
      GetQuicFlag(quic_disable_server_tls_resumption);

  if (!crypto_config_ || !crypto_config_->proof_source()) {
    return ssl_config;
  }

  absl::InlinedVector<uint16_t, 8> signature_algorithms =
      crypto_config_->proof_source()->SupportedTlsSignatureAlgorithms();
  if (!signature_algorithms.empty()) {
    ssl_config.signing_algorithm_prefs = std::move(signature_algorithms);
  }

  return ssl_config;
}

std::optional<CachedNetworkParameters>
QuicServerSessionBase::GenerateCachedNetworkParameters() const {
  const QuicSentPacketManager& sent_packet_manager =
      connection()->sent_packet_manager();
  const QuicSustainedBandwidthRecorder* bandwidth_recorder =
      sent_packet_manager.SustainedBandwidthRecorder();

  CachedNetworkParameters cached_network_params;
  cached_network_params.set_timestamp(
      connection()->clock()->WallNow().ToUNIXSeconds());

  if (!sent_packet_manager.GetRttStats()->min_rtt().IsZero()) {
    cached_network_params.set_min_rtt_ms(
        sent_packet_manager.GetRttStats()->min_rtt().ToMilliseconds());
  }

  // Populate bandwidth estimates if any.
  if (bandwidth_recorder != nullptr && bandwidth_recorder->HasEstimate()) {
    const int32_t bw_estimate_bytes_per_second =
        BandwidthToCachedParameterBytesPerSecond(
            bandwidth_recorder->BandwidthEstimate());
    const int32_t max_bw_estimate_bytes_per_second =
        BandwidthToCachedParameterBytesPerSecond(
            bandwidth_recorder->MaxBandwidthEstimate());
    QUIC_BUG_IF(quic_bug_12513_1, max_bw_estimate_bytes_per_second < 0)
        << max_bw_estimate_bytes_per_second;
    QUIC_BUG_IF(quic_bug_10393_1, bw_estimate_bytes_per_second < 0)
        << bw_estimate_bytes_per_second;

    cached_network_params.set_bandwidth_estimate_bytes_per_second(
        bw_estimate_bytes_per_second);
    cached_network_params.set_max_bandwidth_estimate_bytes_per_second(
        max_bw_estimate_bytes_per_second);
    cached_network_params.set_max_bandwidth_timestamp_seconds(
        bandwidth_recorder->MaxBandwidthTimestamp());

    cached_network_params.set_previous_connection_state(
        bandwidth_recorder->EstimateRecordedDuringSlowStart()
            ? CachedNetworkParameters::SLOW_START
            : CachedNetworkParameters::CONGESTION_AVOIDANCE);
  }

  if (!serving_region_.empty()) {
    cached_network_params.set_serving_region(serving_region_);
  }

  return cached_network_params;
}

}  // namespace quic
```