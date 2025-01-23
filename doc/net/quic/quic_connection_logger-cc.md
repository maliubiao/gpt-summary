Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

**1. Understanding the Goal:**

The core request is to understand the functionality of `quic_connection_logger.cc`, especially its connection to JavaScript, potential logical inferences, common errors, and how a user might trigger its execution.

**2. Initial Code Scan - Identifying Key Areas:**

My first pass involves quickly scanning the code for keywords and patterns that reveal the purpose of the file. I'd look for:

* **Class Name:** `QuicConnectionLogger` -  suggests logging connection-related information.
* **Includes:**  Headers like `<algorithm>`, `<limits>`, `<memory>`, `<utility>`, `<vector>`, `"base/metrics/...`", `"net/..."`, and the `quiche` directory strongly indicate system-level network functionality, including performance metrics. The `base/metrics` headers are a dead giveaway for performance tracking and statistics.
* **Constructor/Destructor:**  The constructor takes a `QuicSession`, suggesting it's tied to a QUIC connection. The destructor has `UMA_HISTOGRAM_COUNTS_1M` calls, confirming its role in recording metrics.
* **Method Names:**  Methods like `OnPacketSent`, `OnPacketReceived`, `OnPacketLoss`, `OnStreamFrame`, `OnConnectionClose`, etc., clearly indicate event-driven logging related to the QUIC protocol.
* **Histograms:** The numerous `UMA_HISTOGRAM_*` calls throughout the code are the strongest indicator of its primary function: collecting and reporting performance and diagnostic data about QUIC connections.
* **`event_logger_`:**  This member variable and its associated calls (`event_logger_.On...`) suggest a delegation pattern for more detailed logging.
* **Lack of Direct JavaScript Interaction:** A quick scan doesn't show any obvious direct interaction with JavaScript APIs.

**3. Deduction of Core Functionality:**

Based on the initial scan, I can confidently conclude that `QuicConnectionLogger` is responsible for logging events and collecting metrics related to a QUIC connection in Chromium's network stack. It's not directly involved in the core data processing or protocol handling but acts as an observer and recorder.

**4. Analyzing Interactions and Data Flow:**

Next, I'd examine the individual methods to understand what specific information is being logged and how it's triggered.

* **`OnPacketSent` / `OnPacketReceived`:**  Record packet sizes and potentially flag unusually small initial packets.
* **`OnPacketLoss`:**  Logs packet loss events.
* **Frame-related methods (`OnStreamFrame`, `OnRstStreamFrame`, etc.):** Log various QUIC frame types, often with specific error code tracking.
* **`OnCryptoHandshakeMessageReceived` / `OnCryptoHandshakeMessageSent`:** Capture details of the QUIC handshake process.
* **`OnConnectionClosed`:** Logs connection closure events and reasons.
* **`UpdateReceivedFrameCounts`:** Tracks the number of received frames, distinguishing between regular and duplicate frames.
* **`ReceivedPacketLossRate`:** Calculates the packet loss rate based on received packet numbers.

**5. Addressing the JavaScript Connection:**

Given the absence of direct JavaScript interaction in the code, I'd deduce that the connection is *indirect*. JavaScript in a web browser (e.g., through a fetch request) can trigger network activity that uses the QUIC protocol. This QUIC connection's events are then logged by `QuicConnectionLogger`. The histograms generated might later be collected and used for performance analysis or debugging within Chromium, potentially benefiting developers or influencing future browser behavior.

**6. Constructing Examples (Logical Inference):**

For logical inference examples, I'd choose a simple scenario, like receiving packets. I'd create hypothetical inputs (packet headers with specific numbers) and trace how the code would update internal state (e.g., `largest_received_packet_number_`, `num_out_of_order_received_packets_`). The key is to demonstrate the logic within specific methods.

**7. Identifying User/Programming Errors:**

I'd consider common network-related issues or incorrect usage of the QUIC API that could indirectly trigger logging in this class. Examples include:

* **Network Issues:** Packet loss (triggering `OnPacketLoss`), out-of-order delivery (`OnPacketHeader` logic).
* **Server Behavior:**  The server sending a `CONNECTION_CLOSE` frame (`OnConnectionCloseFrame`).
* **Incorrect Implementation:** While the logger itself isn't prone to direct programmer error, incorrect QUIC implementation elsewhere might lead to logged errors.

**8. Tracing User Actions:**

To explain how a user reaches this code, I'd start with a high-level user action (e.g., visiting a website) and progressively break it down:

* User types a URL or clicks a link.
* Browser initiates a network request.
* If QUIC is negotiated, a `QuicSession` is created.
* A `QuicConnectionLogger` is instantiated for that session.
* Network events during the connection (packet sends, receives, errors) trigger the logging methods.

**9. Structuring the Answer:**

Finally, I'd organize the information logically, addressing each part of the prompt clearly:

* **功能 (Functions):** Start with a concise summary, then detail specific logging responsibilities.
* **与 JavaScript 的关系 (Relationship with JavaScript):** Explain the indirect relationship.
* **逻辑推理 (Logical Inference):** Provide clear examples with inputs and outputs.
* **用户或编程常见的使用错误 (Common User/Programming Errors):** Give concrete examples.
* **用户操作是如何一步步的到达这里，作为调试线索 (How User Actions Lead Here):** Detail the step-by-step process.

**Self-Correction/Refinement:**

Throughout the process, I'd review my understanding and ensure accuracy. For example, I might initially overstate the direct connection to JavaScript and then correct myself by emphasizing the indirect nature. I'd also double-check the code to ensure my logical inference examples are accurate. The goal is to provide a comprehensive and correct explanation.
好的，我们来详细分析一下 `net/quic/quic_connection_logger.cc` 这个文件。

**功能 (Functions):**

`QuicConnectionLogger` 类的主要功能是记录和统计与 QUIC 连接相关的各种事件和性能指标。它充当一个观察者，监听 `QuicSession` 中发生的各种活动，并将这些信息记录下来，以便进行调试、性能分析和统计。

以下是其主要功能点的详细说明：

1. **记录连接生命周期事件:**  例如，连接建立、握手完成、连接关闭等。通过 `OnConnectionClosed` 方法记录连接关闭的原因和来源。
2. **记录数据包的发送和接收:** 记录发送和接收的数据包的大小、类型（例如 Initial, Handshake, 0-RTT, Forward Secure）、加密级别等信息。通过 `OnPacketSent` 和 `OnPacketReceived` 方法实现。
3. **记录数据包丢失和重传:**  通过 `OnPacketLoss` 方法记录丢失的数据包的编号、加密级别和传输类型。
4. **记录 QUIC 帧的发送和接收:** 记录各种 QUIC 帧的类型，例如 `STREAM_FRAME`（数据流帧）、`ACK_FRAME`（确认帧）、`RST_STREAM_FRAME`（重置流帧）、`CONNECTION_CLOSE_FRAME`（连接关闭帧）等等。通过 `OnFrameAddedToPacket` 和各种 `On...Frame` 方法实现。
5. **记录拥塞控制和流量控制相关信息:** 记录 PING 帧的发送情况，以及连接和流的流量控制是否被阻塞。
6. **记录加密握手过程:** 记录接收和发送的加密握手消息 (`CryptoHandshakeMessage`)，例如 `SHLO` (Server Hello)。
7. **记录 RTT (往返时延) 的变化:**  通过 `OnRttChanged` 方法，并将 RTT 的更新通知 `SocketPerformanceWatcher`。
8. **统计连接的性能指标:**  例如，乱序接收的数据包数量、重复数据包数量、无法解密的数据包数量、最小 RTT、平滑 RTT 等。这些统计信息在析构函数中通过 `UMA_HISTOGRAM_*` 宏记录到 Chromium 的指标系统中。
9. **记录地址信息:** 记录本地和远端地址，并检测在握手过程中地址是否发生不匹配。
10. **记录证书验证结果:**  通过 `OnCertificateVerified` 方法记录证书验证的结果。
11. **记录传输参数:** 记录发送、接收和恢复的 QUIC 传输参数。
12. **记录 0-RTT 被拒绝的原因:** 通过 `OnZeroRttRejected` 方法记录。
13. **记录加密客户端 Hello (ECH) 的发送:** 通过 `OnEncryptedClientHelloSent` 方法记录。

**与 JavaScript 的关系 (Relationship with JavaScript):**

`QuicConnectionLogger` 本身是用 C++ 编写的，直接与 JavaScript 没有代码级别的交互。然而，它记录的信息对于理解和调试从 JavaScript 发起的网络请求非常重要。

当一个网页中的 JavaScript 代码（例如使用 `fetch` API）发起一个使用 QUIC 协议的网络请求时，Chromium 的网络栈会创建并维护一个 `QuicSession` 来处理这个连接。`QuicConnectionLogger` 作为这个 `QuicSession` 的一部分，会记录连接的各种事件。

**举例说明:**

假设一个 JavaScript 代码发起了一个 `fetch` 请求到一个支持 QUIC 的服务器：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

在这个过程中，`QuicConnectionLogger` 可能会记录以下事件：

* **`OnPacketSent`:**  记录发送给服务器的 QUIC 数据包，包括请求头等信息。
* **`OnPacketReceived`:** 记录从服务器接收到的 QUIC 数据包，包括响应数据。
* **`OnStreamFrame`:** 记录传输实际 HTTP 数据的 QUIC 流帧。
* **`OnIncomingAck`:** 记录收到的 ACK 帧，用于确认数据包已成功接收。
* **`OnRttChanged`:**  记录连接 RTT 的变化，这会影响请求的性能。
* **`OnConnectionClosed`:** 如果连接关闭，会记录关闭的原因。

**最终，这些通过 `QuicConnectionLogger` 记录的指标和事件可以被 Chromium 的开发者用来：**

* **调试网络问题:** 例如，如果请求失败，可以查看日志来分析是否发生了数据包丢失、连接错误等。
* **分析性能:**  例如，可以统计 RTT、数据包丢失率等指标来评估 QUIC 连接的性能。
* **监控 QUIC 协议的实现:**  验证协议的正确性，发现潜在的问题。

**逻辑推理 (Logical Inference):**

我们可以通过分析代码中的逻辑来推断在特定输入下会发生什么。

**假设输入:**

1. **场景 1: 收到一个乱序的数据包。**
   - `largest_received_packet_number_` 当前值为 10。
   - 接收到一个数据包，其 `header.packet_number` 为 8。

2. **场景 2: 发送一个小于最小初始数据包大小的 Initial 数据包。**
   - 发送一个加密级别为 `ENCRYPTION_INITIAL` 的数据包，其 `packet_length` 为 1000 字节。 (假设 `kMinClientInitialPacketLength` 为 1200)

**输出:**

1. **场景 1 输出:**
   - `OnPacketHeader` 方法会被调用。
   - `header.packet_number < last_received_packet_number_` 为真 (8 < 10)。
   - `num_out_of_order_received_packets_` 的值会增加 1。
   - 如果之前接收到的数据包大小 (`previous_received_packet_size_`) 小于当前接收到的数据包大小 (`last_received_packet_size_`)，则 `num_out_of_order_large_received_packets_` 的值也会增加 1。
   - `UMA_HISTOGRAM_COUNTS_1M("Net.QuicSession.OutOfOrderGapReceived", ...)` 会记录乱序的间隔 (10 - 8 = 2)。

2. **场景 2 输出:**
   - `OnPacketSent` 方法会被调用。
   - `encryption_level == quic::ENCRYPTION_INITIAL` 为真。
   - `UMA_HISTOGRAM_CUSTOM_COUNTS("Net.QuicSession.SendPacketSize.Initial", ...)` 会记录发送的数据包大小 (1000)。
   - `packet_length < kMinClientInitialPacketLength` 为真 (1000 < 1200)。
   - `UMA_HISTOGRAM_CUSTOM_COUNTS("Net.QuicSession.TooSmallInitialSentPacket", ...)` 会记录与最小大小的差值 (1200 - 1000 = 200)。

**用户或编程常见的使用错误 (Common User or Programming Errors):**

虽然 `QuicConnectionLogger` 本身不直接处理用户或编程错误，但它记录的信息可以帮助诊断这些错误。

**例子:**

1. **用户网络问题导致连接不稳定:**
   - **错误:** 用户网络环境不稳定，导致数据包丢失严重。
   - **`QuicConnectionLogger` 记录:**  会记录大量的 `OnPacketLoss` 事件，`ReceivedPacketLossRate()` 的值会很高。
   - **调试线索:**  高数据包丢失率可能表明用户网络存在问题。

2. **服务器配置错误导致连接被拒绝:**
   - **错误:**  服务器的 QUIC 配置不正确，例如不支持客户端请求的版本。
   - **`QuicConnectionLogger` 记录:** 可能会记录 `OnProtocolVersionMismatch` 事件，或者 `OnConnectionClosed` 事件，错误码指示版本协商失败。
   - **调试线索:**  版本不匹配的错误码可以帮助定位服务器配置问题。

3. **客户端或服务器的 QUIC 实现错误:**
   - **错误:**  客户端或服务器的 QUIC 协议实现存在 bug，导致连接异常关闭。
   - **`QuicConnectionLogger` 记录:**  可能会记录一些异常的事件序列，或者 `OnConnectionClosed` 事件，错误码指示内部错误。
   - **调试线索:**  异常的日志信息可以帮助开发者定位代码中的 bug。

**用户操作是如何一步步的到达这里，作为调试线索 (How User Actions Lead Here as a Debugging Clue):**

1. **用户在 Chrome 浏览器中输入一个 HTTPS URL 并访问。**
2. **Chrome 浏览器开始与服务器建立连接。**
3. **Chrome 尝试与服务器进行 QUIC 协议握手 (如果服务器支持并且满足条件)。**
4. **如果 QUIC 握手成功，会创建一个 `QuicSession` 对象来管理这个连接。**
5. **在创建 `QuicSession` 的过程中，会创建一个 `QuicConnectionLogger` 对象，并将其与该 `QuicSession` 关联。**
6. **在连接的整个生命周期中，`QuicSession` 中发生的各种事件（例如发送/接收数据包、帧，连接状态变化等）会触发 `QuicConnectionLogger` 相应的方法被调用。**
7. **`QuicConnectionLogger` 将这些事件信息记录下来，通常是通过 Chromium 的 NetLog 系统或 UMA 指标系统。**

**作为调试线索:**

当用户遇到网络问题（例如页面加载缓慢、连接中断等）并向开发者报告时，开发者可以：

1. **启用 Chrome 的 NetLog 功能:**  NetLog 会记录浏览器内部的网络事件，包括 `QuicConnectionLogger` 记录的信息。
2. **重现用户遇到的问题。**
3. **查看 NetLog 记录:**  分析 `QuicConnectionLogger` 记录的事件，例如：
   - 是否有大量的数据包丢失？
   - RTT 是否很高且不稳定？
   - 是否发生了连接关闭，关闭的原因是什么？
   - 是否有协议版本不匹配的情况？
   - 是否有证书验证失败的情况？
4. **根据 NetLog 中的信息，开发者可以更准确地定位问题所在，例如是用户网络问题、服务器配置问题还是客户端/服务器的 QUIC 实现问题。**

总而言之，`net/quic/quic_connection_logger.cc` 是 Chromium QUIC 实现中一个至关重要的组件，它负责记录连接的各种细节，为调试、性能分析和协议演进提供了宝贵的数据支持。虽然它不直接与 JavaScript 交互，但它记录的信息对于理解和优化基于 QUIC 的 Web 应用性能至关重要。

### 提示词
```
这是目录为net/quic/quic_connection_logger.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_connection_logger.h"

#include <algorithm>
#include <limits>
#include <memory>
#include <utility>
#include <vector>

#include "base/metrics/histogram_base.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/values.h"
#include "net/base/ip_address.h"
#include "net/cert/x509_certificate.h"
#include "net/quic/address_utils.h"
#include "net/quic/quic_address_mismatch.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/crypto_handshake_message.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/crypto_protocol.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_connection_id.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_packets.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_socket_address_coder.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_time.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_utils.h"

using quic::kMaxOutgoingPacketSize;
using std::string;

namespace net {

namespace {

// If |address| is an IPv4-mapped IPv6 address, returns ADDRESS_FAMILY_IPV4
// instead of ADDRESS_FAMILY_IPV6. Othewise, behaves like GetAddressFamily().
AddressFamily GetRealAddressFamily(const IPAddress& address) {
  return address.IsIPv4MappedIPv6() ? ADDRESS_FAMILY_IPV4
                                    : GetAddressFamily(address);
}

}  // namespace

QuicConnectionLogger::QuicConnectionLogger(
    quic::QuicSession* session,
    const char* const connection_description,
    std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
    const NetLogWithSource& net_log)
    : session_(session),
      connection_description_(connection_description),
      socket_performance_watcher_(std::move(socket_performance_watcher)),
      event_logger_(session, net_log) {}

QuicConnectionLogger::~QuicConnectionLogger() {
  UMA_HISTOGRAM_COUNTS_1M("Net.QuicSession.OutOfOrderPacketsReceived",
                          num_out_of_order_received_packets_);
  UMA_HISTOGRAM_COUNTS_1M("Net.QuicSession.OutOfOrderLargePacketsReceived",
                          num_out_of_order_large_received_packets_);
  UMA_HISTOGRAM_COUNTS_1M("Net.QuicSession.IncorrectConnectionIDsReceived",
                          num_incorrect_connection_ids_);
  UMA_HISTOGRAM_COUNTS_1M("Net.QuicSession.UndecryptablePacketsReceived",
                          num_undecryptable_packets_);
  UMA_HISTOGRAM_COUNTS_1M("Net.QuicSession.DuplicatePacketsReceived",
                          num_duplicate_packets_);
  UMA_HISTOGRAM_COUNTS_1M("Net.QuicSession.BlockedFrames.Received",
                          num_blocked_frames_received_);
  UMA_HISTOGRAM_COUNTS_1M("Net.QuicSession.BlockedFrames.Sent",
                          num_blocked_frames_sent_);

  const quic::QuicConnectionStats& stats = session_->connection()->GetStats();
  UMA_HISTOGRAM_TIMES("Net.QuicSession.MinRTT",
                      base::Microseconds(stats.min_rtt_us));
  UMA_HISTOGRAM_TIMES("Net.QuicSession.SmoothedRTT",
                      base::Microseconds(stats.srtt_us));

  if (num_frames_received_ > 0) {
    int duplicate_stream_frame_per_thousand =
        num_duplicate_frames_received_ * 1000 / num_frames_received_;
    if (num_packets_received_ < 100) {
      UMA_HISTOGRAM_CUSTOM_COUNTS(
          "Net.QuicSession.StreamFrameDuplicatedShortConnection",
          duplicate_stream_frame_per_thousand, 1, 1000, 75);
    } else {
      UMA_HISTOGRAM_CUSTOM_COUNTS(
          "Net.QuicSession.StreamFrameDuplicatedLongConnection",
          duplicate_stream_frame_per_thousand, 1, 1000, 75);
    }
  }

  RecordAggregatePacketLossRate();
}

void QuicConnectionLogger::OnFrameAddedToPacket(const quic::QuicFrame& frame) {
  switch (frame.type) {
    case quic::PADDING_FRAME:
      break;
    case quic::STREAM_FRAME:
      break;
    case quic::ACK_FRAME: {
      break;
    }
    case quic::RST_STREAM_FRAME:
      base::UmaHistogramSparse("Net.QuicSession.RstStreamErrorCodeClient",
                               frame.rst_stream_frame->error_code);
      break;
    case quic::CONNECTION_CLOSE_FRAME:
      break;
    case quic::GOAWAY_FRAME:
      break;
    case quic::WINDOW_UPDATE_FRAME:
      break;
    case quic::BLOCKED_FRAME:
      ++num_blocked_frames_sent_;
      break;
    case quic::STOP_WAITING_FRAME:
      break;
    case quic::PING_FRAME:
      UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.ConnectionFlowControlBlocked",
                            session_->IsConnectionFlowControlBlocked());
      UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.StreamFlowControlBlocked",
                            session_->IsStreamFlowControlBlocked());
      break;
    case quic::MTU_DISCOVERY_FRAME:
      break;
    case quic::NEW_CONNECTION_ID_FRAME:
      break;
    case quic::MAX_STREAMS_FRAME:
      break;
    case quic::STREAMS_BLOCKED_FRAME:
      break;
    case quic::PATH_RESPONSE_FRAME:
      break;
    case quic::PATH_CHALLENGE_FRAME:
      break;
    case quic::STOP_SENDING_FRAME:
      base::UmaHistogramSparse("Net.QuicSession.StopSendingErrorCodeClient",
                               frame.stop_sending_frame.error_code);
      break;
    case quic::MESSAGE_FRAME:
      break;
    case quic::CRYPTO_FRAME:
      break;
    case quic::NEW_TOKEN_FRAME:
      break;
    case quic::RETIRE_CONNECTION_ID_FRAME:
      break;
    default:
      DCHECK(false) << "Illegal frame type: " << frame.type;
  }
  event_logger_.OnFrameAddedToPacket(frame);
}

void QuicConnectionLogger::OnStreamFrameCoalesced(
    const quic::QuicStreamFrame& frame) {
  event_logger_.OnStreamFrameCoalesced(frame);
}

void QuicConnectionLogger::OnPacketSent(
    quic::QuicPacketNumber packet_number,
    quic::QuicPacketLength packet_length,
    bool has_crypto_handshake,
    quic::TransmissionType transmission_type,
    quic::EncryptionLevel encryption_level,
    const quic::QuicFrames& retransmittable_frames,
    const quic::QuicFrames& nonretransmittable_frames,
    quic::QuicTime sent_time,
    uint32_t batch_id) {
  // 4.4.1.4.  Minimum Packet Size
  // The payload of a UDP datagram carrying the Initial packet MUST be
  // expanded to at least 1200 octets
  const quic::QuicPacketLength kMinClientInitialPacketLength = 1200;
  switch (encryption_level) {
    case quic::ENCRYPTION_INITIAL:
      UMA_HISTOGRAM_CUSTOM_COUNTS("Net.QuicSession.SendPacketSize.Initial",
                                  packet_length, 1, kMaxOutgoingPacketSize, 50);
      if (packet_length < kMinClientInitialPacketLength) {
        UMA_HISTOGRAM_CUSTOM_COUNTS(
            "Net.QuicSession.TooSmallInitialSentPacket",
            kMinClientInitialPacketLength - packet_length, 1,
            kMinClientInitialPacketLength, 50);
      }
      break;
    case quic::ENCRYPTION_HANDSHAKE:
      UMA_HISTOGRAM_CUSTOM_COUNTS("Net.QuicSession.SendPacketSize.Handshake",
                                  packet_length, 1, kMaxOutgoingPacketSize, 50);
      break;
    case quic::ENCRYPTION_ZERO_RTT:
      UMA_HISTOGRAM_CUSTOM_COUNTS("Net.QuicSession.SendPacketSize.0RTT",
                                  packet_length, 1, kMaxOutgoingPacketSize, 50);
      break;
    case quic::ENCRYPTION_FORWARD_SECURE:
      UMA_HISTOGRAM_CUSTOM_COUNTS(
          "Net.QuicSession.SendPacketSize.ForwardSecure", packet_length, 1,
          kMaxOutgoingPacketSize, 50);
      break;
    case quic::NUM_ENCRYPTION_LEVELS:
      NOTREACHED();
  }

  event_logger_.OnPacketSent(packet_number, packet_length, has_crypto_handshake,
                             transmission_type, encryption_level,
                             retransmittable_frames, nonretransmittable_frames,
                             sent_time, batch_id);
}

void QuicConnectionLogger::OnPacketLoss(
    quic::QuicPacketNumber lost_packet_number,
    quic::EncryptionLevel encryption_level,
    quic::TransmissionType transmission_type,
    quic::QuicTime detection_time) {
  event_logger_.OnPacketLoss(lost_packet_number, encryption_level,
                             transmission_type, detection_time);
}

void QuicConnectionLogger::OnConfigProcessed(
    const quic::QuicSentPacketManager::DebugDelegate::SendParameters&
        parameters) {
  event_logger_.OnConfigProcessed(parameters);
}

void QuicConnectionLogger::OnPingSent() {
  no_packet_received_after_ping_ = true;
}

void QuicConnectionLogger::OnPacketReceived(
    const quic::QuicSocketAddress& self_address,
    const quic::QuicSocketAddress& peer_address,
    const quic::QuicEncryptedPacket& packet) {
  if (local_address_from_self_.GetFamily() == ADDRESS_FAMILY_UNSPECIFIED) {
    local_address_from_self_ = ToIPEndPoint(self_address);
    UMA_HISTOGRAM_ENUMERATION(
        "Net.QuicSession.ConnectionTypeFromSelf",
        GetRealAddressFamily(ToIPEndPoint(self_address).address()),
        ADDRESS_FAMILY_LAST);
  }

  previous_received_packet_size_ = last_received_packet_size_;
  last_received_packet_size_ = packet.length();
  event_logger_.OnPacketReceived(self_address, peer_address, packet);
}

void QuicConnectionLogger::OnUnauthenticatedHeader(
    const quic::QuicPacketHeader& header) {
  event_logger_.OnUnauthenticatedHeader(header);
}

void QuicConnectionLogger::OnIncorrectConnectionId(
    quic::QuicConnectionId connection_id) {
  ++num_incorrect_connection_ids_;
}

void QuicConnectionLogger::OnUndecryptablePacket(
    quic::EncryptionLevel decryption_level,
    bool dropped) {
  ++num_undecryptable_packets_;
  event_logger_.OnUndecryptablePacket(decryption_level, dropped);
}

void QuicConnectionLogger::OnAttemptingToProcessUndecryptablePacket(
    quic::EncryptionLevel decryption_level) {
  event_logger_.OnAttemptingToProcessUndecryptablePacket(decryption_level);
}

void QuicConnectionLogger::OnDuplicatePacket(
    quic::QuicPacketNumber packet_number) {
  ++num_duplicate_packets_;
  event_logger_.OnDuplicatePacket(packet_number);
}

void QuicConnectionLogger::OnProtocolVersionMismatch(
    quic::ParsedQuicVersion received_version) {
  // TODO(rtenneti): Add logging.
}

void QuicConnectionLogger::OnPacketHeader(const quic::QuicPacketHeader& header,
                                          quic::QuicTime receive_time,
                                          quic::EncryptionLevel level) {
  if (!first_received_packet_number_.IsInitialized()) {
    first_received_packet_number_ = header.packet_number;
  } else if (header.packet_number < first_received_packet_number_) {
    // Ignore packets with packet numbers less than
    // first_received_packet_number_.
    return;
  }
  ++num_packets_received_;
  if (!largest_received_packet_number_.IsInitialized()) {
    largest_received_packet_number_ = header.packet_number;
  } else if (largest_received_packet_number_ < header.packet_number) {
    uint64_t delta = header.packet_number - largest_received_packet_number_;
    if (delta > 1) {
      // There is a gap between the largest packet previously received and
      // the current packet.  This indicates either loss, or out-of-order
      // delivery.
      UMA_HISTOGRAM_COUNTS_1M(
          "Net.QuicSession.PacketGapReceived",
          static_cast<base::HistogramBase::Sample>(delta - 1));
    }
    largest_received_packet_number_ = header.packet_number;
  }
  if (header.packet_number - first_received_packet_number_ <
      received_packets_.size()) {
    received_packets_[header.packet_number - first_received_packet_number_] =
        true;
  }
  if (last_received_packet_number_.IsInitialized() &&
      header.packet_number < last_received_packet_number_) {
    ++num_out_of_order_received_packets_;
    if (previous_received_packet_size_ < last_received_packet_size_)
      ++num_out_of_order_large_received_packets_;
    UMA_HISTOGRAM_COUNTS_1M(
        "Net.QuicSession.OutOfOrderGapReceived",
        static_cast<base::HistogramBase::Sample>(last_received_packet_number_ -
                                                 header.packet_number));
  } else if (no_packet_received_after_ping_) {
    if (last_received_packet_number_.IsInitialized()) {
      UMA_HISTOGRAM_COUNTS_1M(
          "Net.QuicSession.PacketGapReceivedNearPing",
          static_cast<base::HistogramBase::Sample>(
              header.packet_number - last_received_packet_number_));
    }
    no_packet_received_after_ping_ = false;
  }
  last_received_packet_number_ = header.packet_number;
  event_logger_.OnPacketHeader(header, receive_time, level);
}

void QuicConnectionLogger::OnStreamFrame(const quic::QuicStreamFrame& frame) {
  event_logger_.OnStreamFrame(frame);
}

void QuicConnectionLogger::OnPathChallengeFrame(
    const quic::QuicPathChallengeFrame& frame) {
  event_logger_.OnPathChallengeFrame(frame);
}

void QuicConnectionLogger::OnPathResponseFrame(
    const quic::QuicPathResponseFrame& frame) {
  event_logger_.OnPathResponseFrame(frame);
}

void QuicConnectionLogger::OnCryptoFrame(const quic::QuicCryptoFrame& frame) {
  event_logger_.OnCryptoFrame(frame);
}

void QuicConnectionLogger::OnStopSendingFrame(
    const quic::QuicStopSendingFrame& frame) {
  base::UmaHistogramSparse("Net.QuicSession.StopSendingErrorCodeServer",
                           frame.error_code);
  event_logger_.OnStopSendingFrame(frame);
}

void QuicConnectionLogger::OnStreamsBlockedFrame(
    const quic::QuicStreamsBlockedFrame& frame) {
  event_logger_.OnStreamsBlockedFrame(frame);
}

void QuicConnectionLogger::OnMaxStreamsFrame(
    const quic::QuicMaxStreamsFrame& frame) {
  event_logger_.OnMaxStreamsFrame(frame);
}

void QuicConnectionLogger::OnIncomingAck(
    quic::QuicPacketNumber ack_packet_number,
    quic::EncryptionLevel ack_decrypted_level,
    const quic::QuicAckFrame& frame,
    quic::QuicTime ack_receive_time,
    quic::QuicPacketNumber largest_observed,
    bool rtt_updated,
    quic::QuicPacketNumber least_unacked_sent_packet) {
  const size_t kApproximateLargestSoloAckBytes = 100;
  if (last_received_packet_number_ - first_received_packet_number_ <
          received_acks_.size() &&
      last_received_packet_size_ < kApproximateLargestSoloAckBytes) {
    received_acks_[last_received_packet_number_ -
                   first_received_packet_number_] = true;
  }

  event_logger_.OnIncomingAck(ack_packet_number, ack_decrypted_level, frame,
                              ack_receive_time, largest_observed, rtt_updated,
                              least_unacked_sent_packet);
}

void QuicConnectionLogger::OnRstStreamFrame(
    const quic::QuicRstStreamFrame& frame) {
  base::UmaHistogramSparse("Net.QuicSession.RstStreamErrorCodeServer",
                           frame.error_code);
  event_logger_.OnRstStreamFrame(frame);
}

void QuicConnectionLogger::OnConnectionCloseFrame(
    const quic::QuicConnectionCloseFrame& frame) {
  event_logger_.OnConnectionCloseFrame(frame);
}

void QuicConnectionLogger::OnWindowUpdateFrame(
    const quic::QuicWindowUpdateFrame& frame,
    const quic::QuicTime& receive_time) {
  event_logger_.OnWindowUpdateFrame(frame, receive_time);
}

void QuicConnectionLogger::OnBlockedFrame(const quic::QuicBlockedFrame& frame) {
  ++num_blocked_frames_received_;
  event_logger_.OnBlockedFrame(frame);
}

void QuicConnectionLogger::OnGoAwayFrame(const quic::QuicGoAwayFrame& frame) {
  UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.GoAwayReceivedForConnectionMigration",
                        frame.error_code == quic::QUIC_ERROR_MIGRATING_PORT);

  event_logger_.OnGoAwayFrame(frame);
}

void QuicConnectionLogger::OnPingFrame(
    const quic::QuicPingFrame& frame,
    quic::QuicTime::Delta ping_received_delay) {
  event_logger_.OnPingFrame(frame, ping_received_delay);
}

void QuicConnectionLogger::OnPaddingFrame(const quic::QuicPaddingFrame& frame) {
  event_logger_.OnPaddingFrame(frame);
}

void QuicConnectionLogger::OnNewConnectionIdFrame(
    const quic::QuicNewConnectionIdFrame& frame) {
  event_logger_.OnNewConnectionIdFrame(frame);
}

void QuicConnectionLogger::OnNewTokenFrame(
    const quic::QuicNewTokenFrame& frame) {
  event_logger_.OnNewTokenFrame(frame);
}

void QuicConnectionLogger::OnRetireConnectionIdFrame(
    const quic::QuicRetireConnectionIdFrame& frame) {
  event_logger_.OnRetireConnectionIdFrame(frame);
}

void QuicConnectionLogger::OnMessageFrame(const quic::QuicMessageFrame& frame) {
  event_logger_.OnMessageFrame(frame);
}

void QuicConnectionLogger::OnHandshakeDoneFrame(
    const quic::QuicHandshakeDoneFrame& frame) {
  event_logger_.OnHandshakeDoneFrame(frame);
}

void QuicConnectionLogger::OnCoalescedPacketSent(
    const quic::QuicCoalescedPacket& coalesced_packet,
    size_t length) {
  event_logger_.OnCoalescedPacketSent(coalesced_packet, length);
}

void QuicConnectionLogger::OnVersionNegotiationPacket(
    const quic::QuicVersionNegotiationPacket& packet) {
  event_logger_.OnVersionNegotiationPacket(packet);
}

void QuicConnectionLogger::OnCryptoHandshakeMessageReceived(
    const quic::CryptoHandshakeMessage& message) {
  if (message.tag() == quic::kSHLO) {
    std::string_view address;
    quic::QuicSocketAddressCoder decoder;
    if (message.GetStringPiece(quic::kCADR, &address) &&
        decoder.Decode(address.data(), address.size())) {
      local_address_from_shlo_ =
          IPEndPoint(ToIPAddress(decoder.ip()), decoder.port());
      UMA_HISTOGRAM_ENUMERATION(
          "Net.QuicSession.ConnectionTypeFromPeer",
          GetRealAddressFamily(local_address_from_shlo_.address()),
          ADDRESS_FAMILY_LAST);

      int sample = GetAddressMismatch(local_address_from_shlo_,
                                      local_address_from_self_);
      // If `sample` is negative, we are seemingly talking to an older server
      // that does not support the feature, so we can't report the results in
      // the histogram.
      if (sample >= 0) {
        UMA_HISTOGRAM_ENUMERATION("Net.QuicSession.SelfShloAddressMismatch",
                                  static_cast<QuicAddressMismatch>(sample),
                                  QUIC_ADDRESS_MISMATCH_MAX);
      }
    }
  }
  event_logger_.OnCryptoHandshakeMessageReceived(message);
}

void QuicConnectionLogger::OnCryptoHandshakeMessageSent(
    const quic::CryptoHandshakeMessage& message) {
  event_logger_.OnCryptoHandshakeMessageSent(message);
}

void QuicConnectionLogger::OnConnectionClosed(
    const quic::QuicConnectionCloseFrame& frame,
    quic::ConnectionCloseSource source) {
  event_logger_.OnConnectionClosed(frame, source);
}

void QuicConnectionLogger::OnSuccessfulVersionNegotiation(
    const quic::ParsedQuicVersion& version) {
  event_logger_.OnSuccessfulVersionNegotiation(version);
}

void QuicConnectionLogger::UpdateReceivedFrameCounts(
    quic::QuicStreamId stream_id,
    int num_frames_received,
    int num_duplicate_frames_received) {
  if (!quic::QuicUtils::IsCryptoStreamId(session_->transport_version(),
                                         stream_id)) {
    num_frames_received_ += num_frames_received;
    num_duplicate_frames_received_ += num_duplicate_frames_received;
  }
}

void QuicConnectionLogger::OnCertificateVerified(
    const CertVerifyResult& result) {
  event_logger_.OnCertificateVerified(result);
}

float QuicConnectionLogger::ReceivedPacketLossRate() const {
  if (!largest_received_packet_number_.IsInitialized())
    return 0.0f;
  float num_packets =
      largest_received_packet_number_ - first_received_packet_number_ + 1;
  float num_missing = num_packets - num_packets_received_;
  return num_missing / num_packets;
}

void QuicConnectionLogger::OnRttChanged(quic::QuicTime::Delta rtt) const {
  // Notify socket performance watcher of the updated RTT value.
  if (!socket_performance_watcher_)
    return;

  int64_t microseconds = rtt.ToMicroseconds();
  if (microseconds != 0 &&
      socket_performance_watcher_->ShouldNotifyUpdatedRTT()) {
    socket_performance_watcher_->OnUpdatedRTTAvailable(
        base::Microseconds(rtt.ToMicroseconds()));
  }
}

void QuicConnectionLogger::OnTransportParametersSent(
    const quic::TransportParameters& transport_parameters) {
  event_logger_.OnTransportParametersSent(transport_parameters);
}

void QuicConnectionLogger::OnTransportParametersReceived(
    const quic::TransportParameters& transport_parameters) {
  event_logger_.OnTransportParametersReceived(transport_parameters);
}

void QuicConnectionLogger::OnTransportParametersResumed(
    const quic::TransportParameters& transport_parameters) {
  event_logger_.OnTransportParametersResumed(transport_parameters);
}

void QuicConnectionLogger::OnZeroRttRejected(int reason) {
  event_logger_.OnZeroRttRejected(reason);
}

void QuicConnectionLogger::OnEncryptedClientHelloSent(
    std::string_view client_hello) {
  event_logger_.OnEncryptedClientHelloSent(client_hello);
}

void QuicConnectionLogger::RecordAggregatePacketLossRate() const {
  // We don't report packet loss rates for short connections under 22 packets in
  // length to avoid tremendously anomalous contributions to our histogram.
  // (e.g., if we only got 5 packets, but lost 1, we'd otherwise
  // record a 20% loss in this histogram!). We may still get some strange data
  // (1 loss in 22 is still high :-/).
  if (!largest_received_packet_number_.IsInitialized() ||
      largest_received_packet_number_ - first_received_packet_number_ < 22) {
    return;
  }

  string prefix("Net.QuicSession.PacketLossRate_");
  base::HistogramBase* histogram = base::Histogram::FactoryGet(
      prefix + connection_description_, 1, 1000, 75,
      base::HistogramBase::kUmaTargetedHistogramFlag);
  histogram->Add(static_cast<base::HistogramBase::Sample>(
      ReceivedPacketLossRate() * 1000));
}

}  // namespace net
```