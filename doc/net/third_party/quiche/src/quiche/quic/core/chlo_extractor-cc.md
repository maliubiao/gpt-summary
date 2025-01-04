Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The core request is to understand the functionality of `chlo_extractor.cc`, its relation to JavaScript (if any), its logic, potential errors, and how a user might trigger its execution.

2. **Identify the Core Class:** The filename and the `namespace quic` hint that the central entity is `ChloExtractor`. Looking at the `Extract` static method immediately suggests it's the entry point for the functionality.

3. **Analyze `ChloExtractor::Extract`:**
    * **Input Parameters:** `QuicEncryptedPacket`, `ParsedQuicVersion`, `QuicTagVector`, `Delegate*`, `uint8_t connection_id_length`. These give clues about the function's purpose. It takes an encrypted packet, version information, tag indicators, a delegate, and connection ID length.
    * **Key Objects:** `QuicFramer`, `ChloFramerVisitor`. These are the workhorses. The `QuicFramer` is responsible for parsing the QUIC packet, and `ChloFramerVisitor` seems to be a specialized visitor for finding CHLOs.
    * **Workflow:**  It creates a `QuicFramer` with the given version and perspective (server-side). It then creates a `ChloFramerVisitor` to handle specific events during the parsing. The `framer.ProcessPacket(packet)` call is the core parsing action.
    * **Return Value:** It returns `true` if a CHLO is found or if the CHLO contains specific tags.

4. **Deep Dive into `ChloFramerVisitor`:** This is where the core logic resides.
    * **Inheritance:** It inherits from `QuicFramerVisitorInterface` and `CryptoFramerVisitorInterface`. This means it needs to implement methods defined in these interfaces to react to different parts of the QUIC and crypto parsing process.
    * **Constructor:** Takes the `QuicFramer`, tag indicators, and a delegate.
    * **Key Member Variables:** `found_chlo_`, `chlo_contains_tags_`, `connection_id_`. These track the state of the extraction process.
    * **`On...` Methods:**  The various `On...` methods (e.g., `OnStreamFrame`, `OnCryptoFrame`, `OnHandshakeMessage`) are the event handlers. Focus on the ones that are likely to be related to the CHLO.
        * **`OnProtocolVersionMismatch`:** Handles version negotiation.
        * **`OnUnauthenticatedPublicHeader`:** Extracts the connection ID.
        * **`OnStreamFrame` and `OnCryptoFrame`:** These are where the potential CHLO data resides, depending on the QUIC version. The code checks for the "CHLO" prefix.
        * **`OnHandshakeData`:**  This seems to be the central handler for CHLO data. It uses a `CryptoFramer` to parse the crypto handshake message. It also checks for the presence of the indicated tags.
        * **`OnHandshakeMessage`:** This is called when a *complete* handshake message is parsed. It notifies the delegate.
    * **Logic for Finding CHLO:** It looks for a stream or crypto frame that starts with "CHLO" and is at offset 0. It also checks for specific tags within the CHLO.
    * **Delegate Usage:**  The `Delegate` interface allows the `ChloExtractor` to notify other parts of the system when a CHLO is found.

5. **Relate to JavaScript (if applicable):**  QUIC is a transport layer protocol, and this code deals with packet parsing. JavaScript running in a web browser doesn't directly interact with this low-level parsing. The connection is indirect – the browser uses QUIC, and this code runs on the *server* side to process the connection initiation. Therefore, the relationship is about the overall QUIC communication initiated by a JavaScript-driven browser request.

6. **Logical Reasoning (Input/Output):**  Consider a scenario where a client sends an initial QUIC connection attempt (CHLO).
    * **Input:** A raw, encrypted QUIC packet containing a ClientHello.
    * **Processing:** The `Extract` method parses the packet, the `ChloFramerVisitor` identifies the CHLO, and checks for the presence of specified tags.
    * **Output:** `true` if a CHLO is found (or contains the tags), `false` otherwise. The `Delegate` would also be notified if a complete CHLO is parsed.

7. **Common User/Programming Errors:** Think about what could go wrong when *using* the `ChloExtractor` or when a client is trying to connect.
    * **Incorrect Version:** The server might not support the client's QUIC version.
    * **Malformed Packet:**  The client might send a corrupt or invalid packet.
    * **Missing Tags:** The server might be configured to only accept CHLOs with certain tags, and the client doesn't provide them.
    * **Incorrect Configuration:**  The `create_session_tag_indicators` might be configured incorrectly on the server.

8. **User Operation and Debugging:**  How does a user's action lead to this code?
    * **Browser Request:** A user types a URL or clicks a link.
    * **QUIC Connection Attempt:** The browser (if QUIC is enabled) initiates a QUIC connection to the server. This involves sending an initial packet containing the CHLO.
    * **Server Receives Packet:** The server receives this packet.
    * **`ChloExtractor::Extract` is Called:** The server's QUIC implementation calls `ChloExtractor::Extract` to analyze the incoming packet and extract the CHLO.

9. **Structure the Answer:** Organize the findings into clear sections (Functionality, JavaScript Relationship, Logic, Errors, Debugging). Use bullet points and code snippets where appropriate to make it easier to understand.

10. **Review and Refine:** Read through the explanation to ensure accuracy, clarity, and completeness. Make sure the examples are relevant and easy to follow. For instance, initially, I might have only focused on the pure C++ aspects. But remembering the "JavaScript relationship" requirement forces a broader perspective to include the browser's role.
这个C++源代码文件 `chlo_extractor.cc` 的主要功能是从一个 QUIC 加密数据包中提取客户端的初始握手消息 (Client Hello, CHLO)。更具体地说，它旨在在握手过程的早期阶段，甚至在完整解密之前，识别并提取 CHLO，以便服务器可以快速做出一些决策，例如确定要使用哪个服务器配置。

以下是该文件的详细功能分解：

**核心功能：提取 Client Hello (CHLO)**

1. **解析 QUIC 数据包:**  `ChloExtractor::Extract` 方法是入口点。它使用 `QuicFramer` 类来解析传入的 `QuicEncryptedPacket`。`QuicFramer` 负责将原始字节流分解为 QUIC 协议定义的帧（如 STREAM 帧、CRYPTO 帧等）。

2. **查找 CHLO 数据:** `ChloFramerVisitor` 类继承自 `QuicFramerVisitorInterface` 和 `CryptoFramerVisitorInterface`，它作为 `QuicFramer` 的观察者，在解析过程中被调用。它会检查以下两种情况来寻找 CHLO 数据：
   - **旧版本 QUIC (v46 及以下):** CHLO 通常在 Stream ID 为 0 的 STREAM 帧中，偏移量为 0，并且数据以 "CHLO" 开头。
   - **新版本 QUIC (v47 及以上):** CHLO 在 CRYPTO 帧中，偏移量为 0，并且数据以 "CHLO" 开头。

3. **部分解析 CHLO:**  即使数据包尚未完全解密，只要能找到以 "CHLO" 开头的数据，`ChloExtractor` 就会尝试部分解析 CHLO 内容。它使用 `CryptoFramer` 来进一步解析 CHLO 数据，识别其中的标签 (tags)。

4. **检查特定标签 (Tag Indicators):**  `ChloExtractor::Extract` 接收一个 `create_session_tag_indicators` 参数，这是一个 `QuicTagVector`。`ChloFramerVisitor` 会检查提取到的 CHLO 中是否包含这些特定的标签。这些标签通常用于快速判断客户端的某些特性，以便服务器尽早做出决策。

5. **通知委托 (Delegate):** 如果找到了完整的 CHLO 消息，`ChloFramerVisitor` 会调用其委托对象 (`ChloExtractor::Delegate`) 的 `OnChlo` 方法，将 QUIC 版本、连接 ID 和解析后的 `CryptoHandshakeMessage` 传递给它。即使只是部分解析，并且找到了指定的标签，也会通知委托。

**与 JavaScript 的关系：间接关系**

`chlo_extractor.cc` 是 Chromium 网络栈的底层 C++ 代码，它直接处理网络协议。JavaScript 通常在浏览器的高层运行，通过 Web API 与底层网络栈交互。

**关系举例：**

1. **用户在浏览器中发起 HTTPS 请求：** 当用户在浏览器地址栏输入 `https://example.com` 并按下回车键时，浏览器会尝试与服务器建立安全连接。如果浏览器和服务器都支持 QUIC，浏览器可能会尝试使用 QUIC 协议。

2. **QUIC 连接的初始握手：**  作为 QUIC 连接建立的一部分，浏览器会构建一个包含客户端支持的协议、扩展等信息的 CHLO 消息，并将其封装在 QUIC 数据包中发送给服务器。

3. **服务器接收数据包并调用 `ChloExtractor`：** 服务器接收到这个数据包后，可能会调用 `chlo_extractor.cc` 中的 `ChloExtractor::Extract` 方法来快速提取 CHLO 信息。

4. **服务器根据 CHLO 信息做出决策：** 服务器可能会根据 CHLO 中包含的信息（例如 ALPN 协商的协议、支持的 QUIC 版本等）来选择合适的处理方式，例如选择哪个应用层协议（HTTP/3 或其他）、选择哪个服务器配置等。

5. **JavaScript 通过 API 与连接交互：**  一旦 QUIC 连接建立成功，浏览器中的 JavaScript 代码就可以通过 Fetch API 或 WebSocket API 等与服务器进行数据交互，而底层的 QUIC 连接细节对 JavaScript 是透明的。

**总结：** `chlo_extractor.cc` 并不直接运行 JavaScript 代码，但它在浏览器发起的网络请求（通常由 JavaScript 代码触发）的底层处理过程中扮演着重要的角色。它可以帮助服务器快速理解客户端的连接意图，从而优化连接建立过程。

**逻辑推理、假设输入与输出：**

**假设输入：** 一个包含初始 CHLO 消息的加密 QUIC 数据包。

```
// 假设这是一个简化表示，实际的 QUIC 数据包结构更复杂
const char kEncryptedChloPacket[] = {
  // ... QUIC 头部 ...
  // ... 加密的 CHLO 数据，可能在 STREAM 帧或 CRYPTO 帧中 ...
  'C', 'H', 'L', 'O',
  // ... CHLO 的其他内容，例如标签 ...
};
```

**处理过程：**

1. `ChloExtractor::Extract` 被调用，传入 `kEncryptedChloPacket`、QUIC 版本信息、需要检查的标签列表等。
2. `QuicFramer` 解析数据包，找到 STREAM 帧或 CRYPTO 帧。
3. `ChloFramerVisitor` 检查帧的偏移量和数据是否以 "CHLO" 开头。
4. 如果找到 CHLO，`CryptoFramer` 会被用来解析 CHLO 的内容。
5. `ChloFramerVisitor` 检查 CHLO 中是否包含 `create_session_tag_indicators` 中指定的标签。
6. 如果找到完整的 CHLO，调用 `delegate_->OnChlo(...)`。

**可能输出：**

* **如果成功提取 CHLO 且包含指定标签：** `ChloExtractor::Extract` 返回 `true`，并且委托对象的 `OnChlo` 方法被调用，传递了解析后的 `CryptoHandshakeMessage`。
* **如果成功提取 CHLO 但不包含指定标签：** `ChloExtractor::Extract` 返回 `true`，并且委托对象的 `OnChlo` 方法被调用。
* **如果找到疑似 CHLO 但只包含部分数据和指定标签：** `ChloExtractor::Extract` 返回 `true`，但 `OnChlo` 可能不会被完整调用或者只进行部分处理。
* **如果数据包格式错误或不包含 CHLO：** `ChloExtractor::Extract` 返回 `false`。

**用户或编程常见的使用错误：**

1. **服务器配置错误：** `create_session_tag_indicators` 配置不当，导致服务器无法正确识别客户端的 CHLO，从而拒绝连接。例如，如果服务器配置了需要特定的 ALPN 值，但客户端的 CHLO 中没有包含该值。

2. **客户端 QUIC 实现问题：** 客户端发送的 CHLO 消息格式不符合 QUIC 规范，导致服务器解析失败。例如，CHLO 数据没有以 "CHLO" 开头，或者关键的标签缺失。

3. **网络中间件干扰：** 某些网络中间件可能会修改或丢弃 QUIC 数据包，导致服务器无法接收到完整的 CHLO 消息。

4. **调试代码中的假设：**  在调试依赖 CHLO 提取的代码时，错误地假设某些标签总是存在，但实际情况并非如此，导致程序逻辑错误。

**用户操作如何一步步到达这里 (调试线索)：**

假设用户报告无法访问某个使用 QUIC 的网站。以下是可能到达 `chlo_extractor.cc` 的调试线索：

1. **用户在浏览器地址栏输入 URL 并回车。**
2. **浏览器尝试与服务器建立连接。**
3. **浏览器和服务器协商使用 QUIC 协议。**
4. **浏览器构建并发送一个包含 CHLO 消息的 QUIC 数据包。**
5. **服务器接收到该数据包。**
6. **服务器的 QUIC 实现层开始处理接收到的数据包。**
7. **为了快速识别连接意图，服务器调用 `ChloExtractor::Extract` 来尝试提取 CHLO 信息。**
8. **如果在 `ChloExtractor::Extract` 中发生错误（例如，数据包无法解析、CHLO 格式错误、缺少必要的标签），服务器可能会：**
   - **记录错误日志：**  开发者可以通过查看服务器日志来发现 `ChloExtractor` 相关的错误信息。
   - **拒绝连接：** 服务器可能会发送一个连接关闭帧，导致浏览器显示连接失败的错误。
   - **回退到 TCP：** 如果 QUIC 连接失败，浏览器可能会尝试使用传统的 TCP 连接。

**作为调试线索，可以检查以下内容：**

* **服务器日志：**  查看是否有与 `ChloExtractor` 相关的错误或警告信息。
* **网络抓包：** 使用 Wireshark 等工具抓取客户端和服务器之间的网络数据包，检查客户端发送的 CHLO 消息的内容是否正确。
* **QUIC 版本和配置：**  确认客户端和服务器使用的 QUIC 版本是否兼容，以及服务器的 QUIC 配置是否正确，特别是 `create_session_tag_indicators` 的配置。
* **客户端配置：** 检查客户端浏览器或应用程序的 QUIC 相关设置，确保没有禁用或配置错误。

总而言之，`chlo_extractor.cc` 是 Chromium 网络栈中一个关键的组件，它负责在 QUIC 连接的早期阶段快速提取客户端的握手信息，这对于服务器的快速决策和优化连接建立过程至关重要。虽然它不直接与 JavaScript 交互，但它是支撑基于 JavaScript 的 Web 应用使用 QUIC 协议的基础设施的一部分。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/chlo_extractor.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/chlo_extractor.h"

#include <memory>
#include <optional>

#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/crypto_framer.h"
#include "quiche/quic/core/crypto/crypto_handshake.h"
#include "quiche/quic/core/crypto/crypto_handshake_message.h"
#include "quiche/quic/core/crypto/quic_decrypter.h"
#include "quiche/quic/core/crypto/quic_encrypter.h"
#include "quiche/quic/core/frames/quic_ack_frequency_frame.h"
#include "quiche/quic/core/frames/quic_reset_stream_at_frame.h"
#include "quiche/quic/core/quic_framer.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"

namespace quic {

namespace {

class ChloFramerVisitor : public QuicFramerVisitorInterface,
                          public CryptoFramerVisitorInterface {
 public:
  ChloFramerVisitor(QuicFramer* framer,
                    const QuicTagVector& create_session_tag_indicators,
                    ChloExtractor::Delegate* delegate);

  ~ChloFramerVisitor() override = default;

  // QuicFramerVisitorInterface implementation
  void OnError(QuicFramer* /*framer*/) override {}
  bool OnProtocolVersionMismatch(ParsedQuicVersion version) override;
  void OnPacket() override {}
  void OnVersionNegotiationPacket(
      const QuicVersionNegotiationPacket& /*packet*/) override {}
  void OnRetryPacket(QuicConnectionId /*original_connection_id*/,
                     QuicConnectionId /*new_connection_id*/,
                     absl::string_view /*retry_token*/,
                     absl::string_view /*retry_integrity_tag*/,
                     absl::string_view /*retry_without_tag*/) override {}
  bool OnUnauthenticatedPublicHeader(const QuicPacketHeader& header) override;
  bool OnUnauthenticatedHeader(const QuicPacketHeader& header) override;
  void OnDecryptedPacket(size_t /*length*/,
                         EncryptionLevel /*level*/) override {}
  bool OnPacketHeader(const QuicPacketHeader& header) override;
  void OnCoalescedPacket(const QuicEncryptedPacket& packet) override;
  void OnUndecryptablePacket(const QuicEncryptedPacket& packet,
                             EncryptionLevel decryption_level,
                             bool has_decryption_key) override;
  bool OnStreamFrame(const QuicStreamFrame& frame) override;
  bool OnCryptoFrame(const QuicCryptoFrame& frame) override;
  bool OnAckFrameStart(QuicPacketNumber largest_acked,
                       QuicTime::Delta ack_delay_time) override;
  bool OnAckRange(QuicPacketNumber start, QuicPacketNumber end) override;
  bool OnAckTimestamp(QuicPacketNumber packet_number,
                      QuicTime timestamp) override;
  bool OnAckFrameEnd(QuicPacketNumber start,
                     const std::optional<QuicEcnCounts>& ecn_counts) override;
  bool OnStopWaitingFrame(const QuicStopWaitingFrame& frame) override;
  bool OnPingFrame(const QuicPingFrame& frame) override;
  bool OnRstStreamFrame(const QuicRstStreamFrame& frame) override;
  bool OnConnectionCloseFrame(const QuicConnectionCloseFrame& frame) override;
  bool OnNewConnectionIdFrame(const QuicNewConnectionIdFrame& frame) override;
  bool OnRetireConnectionIdFrame(
      const QuicRetireConnectionIdFrame& frame) override;
  bool OnNewTokenFrame(const QuicNewTokenFrame& frame) override;
  bool OnStopSendingFrame(const QuicStopSendingFrame& frame) override;
  bool OnPathChallengeFrame(const QuicPathChallengeFrame& frame) override;
  bool OnPathResponseFrame(const QuicPathResponseFrame& frame) override;
  bool OnGoAwayFrame(const QuicGoAwayFrame& frame) override;
  bool OnMaxStreamsFrame(const QuicMaxStreamsFrame& frame) override;
  bool OnStreamsBlockedFrame(const QuicStreamsBlockedFrame& frame) override;
  bool OnWindowUpdateFrame(const QuicWindowUpdateFrame& frame) override;
  bool OnBlockedFrame(const QuicBlockedFrame& frame) override;
  bool OnPaddingFrame(const QuicPaddingFrame& frame) override;
  bool OnMessageFrame(const QuicMessageFrame& frame) override;
  bool OnHandshakeDoneFrame(const QuicHandshakeDoneFrame& frame) override;
  bool OnAckFrequencyFrame(const QuicAckFrequencyFrame& farme) override;
  bool OnResetStreamAtFrame(const QuicResetStreamAtFrame& frame) override;
  void OnPacketComplete() override {}
  bool IsValidStatelessResetToken(
      const StatelessResetToken& token) const override;
  void OnAuthenticatedIetfStatelessResetPacket(
      const QuicIetfStatelessResetPacket& /*packet*/) override {}
  void OnKeyUpdate(KeyUpdateReason /*reason*/) override;
  void OnDecryptedFirstPacketInKeyPhase() override;
  std::unique_ptr<QuicDecrypter> AdvanceKeysAndCreateCurrentOneRttDecrypter()
      override;
  std::unique_ptr<QuicEncrypter> CreateCurrentOneRttEncrypter() override;

  // CryptoFramerVisitorInterface implementation.
  void OnError(CryptoFramer* framer) override;
  void OnHandshakeMessage(const CryptoHandshakeMessage& message) override;

  // Shared implementation between OnStreamFrame and OnCryptoFrame.
  bool OnHandshakeData(absl::string_view data);

  bool found_chlo() { return found_chlo_; }
  bool chlo_contains_tags() { return chlo_contains_tags_; }

 private:
  QuicFramer* framer_;
  const QuicTagVector& create_session_tag_indicators_;
  ChloExtractor::Delegate* delegate_;
  bool found_chlo_;
  bool chlo_contains_tags_;
  QuicConnectionId connection_id_;
};

ChloFramerVisitor::ChloFramerVisitor(
    QuicFramer* framer, const QuicTagVector& create_session_tag_indicators,
    ChloExtractor::Delegate* delegate)
    : framer_(framer),
      create_session_tag_indicators_(create_session_tag_indicators),
      delegate_(delegate),
      found_chlo_(false),
      chlo_contains_tags_(false),
      connection_id_(EmptyQuicConnectionId()) {}

bool ChloFramerVisitor::OnProtocolVersionMismatch(ParsedQuicVersion version) {
  if (!framer_->IsSupportedVersion(version)) {
    return false;
  }
  framer_->set_version(version);
  return true;
}

bool ChloFramerVisitor::OnUnauthenticatedPublicHeader(
    const QuicPacketHeader& header) {
  connection_id_ = header.destination_connection_id;
  // QuicFramer creates a NullEncrypter and NullDecrypter at level
  // ENCRYPTION_INITIAL. While those are the correct ones to use with some
  // versions of QUIC, others use the IETF-style initial crypters, so those need
  // to be created and installed.
  framer_->SetInitialObfuscators(header.destination_connection_id);
  return true;
}
bool ChloFramerVisitor::OnUnauthenticatedHeader(
    const QuicPacketHeader& /*header*/) {
  return true;
}
bool ChloFramerVisitor::OnPacketHeader(const QuicPacketHeader& /*header*/) {
  return true;
}

void ChloFramerVisitor::OnCoalescedPacket(
    const QuicEncryptedPacket& /*packet*/) {}

void ChloFramerVisitor::OnUndecryptablePacket(
    const QuicEncryptedPacket& /*packet*/, EncryptionLevel /*decryption_level*/,
    bool /*has_decryption_key*/) {}

bool ChloFramerVisitor::OnStreamFrame(const QuicStreamFrame& frame) {
  if (QuicVersionUsesCryptoFrames(framer_->transport_version())) {
    // CHLO will be sent in CRYPTO frames in v47 and above.
    return false;
  }
  absl::string_view data(frame.data_buffer, frame.data_length);
  if (QuicUtils::IsCryptoStreamId(framer_->transport_version(),
                                  frame.stream_id) &&
      frame.offset == 0 && absl::StartsWith(data, "CHLO")) {
    return OnHandshakeData(data);
  }
  return true;
}

bool ChloFramerVisitor::OnCryptoFrame(const QuicCryptoFrame& frame) {
  if (!QuicVersionUsesCryptoFrames(framer_->transport_version())) {
    // CHLO will be in stream frames before v47.
    return false;
  }
  absl::string_view data(frame.data_buffer, frame.data_length);
  if (frame.offset == 0 && absl::StartsWith(data, "CHLO")) {
    return OnHandshakeData(data);
  }
  return true;
}

bool ChloFramerVisitor::OnHandshakeData(absl::string_view data) {
  CryptoFramer crypto_framer;
  crypto_framer.set_visitor(this);
  if (!crypto_framer.ProcessInput(data)) {
    return false;
  }
  // Interrogate the crypto framer and see if there are any
  // intersecting tags between what we saw in the maybe-CHLO and the
  // indicator set.
  for (const QuicTag tag : create_session_tag_indicators_) {
    if (crypto_framer.HasTag(tag)) {
      chlo_contains_tags_ = true;
    }
  }
  if (chlo_contains_tags_ && delegate_) {
    // Unfortunately, because this is a partial CHLO,
    // OnHandshakeMessage was never called, so the ALPN was never
    // extracted. Fake it up a bit and send it to the delegate so that
    // the correct dispatch can happen.
    crypto_framer.ForceHandshake();
  }

  return true;
}

bool ChloFramerVisitor::OnAckFrameStart(QuicPacketNumber /*largest_acked*/,
                                        QuicTime::Delta /*ack_delay_time*/) {
  return true;
}

bool ChloFramerVisitor::OnResetStreamAtFrame(
    const QuicResetStreamAtFrame& /*frame*/) {
  return true;
}

bool ChloFramerVisitor::OnAckRange(QuicPacketNumber /*start*/,
                                   QuicPacketNumber /*end*/) {
  return true;
}

bool ChloFramerVisitor::OnAckTimestamp(QuicPacketNumber /*packet_number*/,
                                       QuicTime /*timestamp*/) {
  return true;
}

bool ChloFramerVisitor::OnAckFrameEnd(
    QuicPacketNumber /*start*/,
    const std::optional<QuicEcnCounts>& /*ecn_counts*/) {
  return true;
}

bool ChloFramerVisitor::OnStopWaitingFrame(
    const QuicStopWaitingFrame& /*frame*/) {
  return true;
}

bool ChloFramerVisitor::OnPingFrame(const QuicPingFrame& /*frame*/) {
  return true;
}

bool ChloFramerVisitor::OnRstStreamFrame(const QuicRstStreamFrame& /*frame*/) {
  return true;
}

bool ChloFramerVisitor::OnConnectionCloseFrame(
    const QuicConnectionCloseFrame& /*frame*/) {
  return true;
}

bool ChloFramerVisitor::OnStopSendingFrame(
    const QuicStopSendingFrame& /*frame*/) {
  return true;
}

bool ChloFramerVisitor::OnPathChallengeFrame(
    const QuicPathChallengeFrame& /*frame*/) {
  return true;
}

bool ChloFramerVisitor::OnPathResponseFrame(
    const QuicPathResponseFrame& /*frame*/) {
  return true;
}

bool ChloFramerVisitor::OnGoAwayFrame(const QuicGoAwayFrame& /*frame*/) {
  return true;
}

bool ChloFramerVisitor::OnWindowUpdateFrame(
    const QuicWindowUpdateFrame& /*frame*/) {
  return true;
}

bool ChloFramerVisitor::OnBlockedFrame(const QuicBlockedFrame& /*frame*/) {
  return true;
}

bool ChloFramerVisitor::OnNewConnectionIdFrame(
    const QuicNewConnectionIdFrame& /*frame*/) {
  return true;
}

bool ChloFramerVisitor::OnRetireConnectionIdFrame(
    const QuicRetireConnectionIdFrame& /*frame*/) {
  return true;
}

bool ChloFramerVisitor::OnNewTokenFrame(const QuicNewTokenFrame& /*frame*/) {
  return true;
}

bool ChloFramerVisitor::OnPaddingFrame(const QuicPaddingFrame& /*frame*/) {
  return true;
}

bool ChloFramerVisitor::OnMessageFrame(const QuicMessageFrame& /*frame*/) {
  return true;
}

bool ChloFramerVisitor::OnHandshakeDoneFrame(
    const QuicHandshakeDoneFrame& /*frame*/) {
  return true;
}

bool ChloFramerVisitor::OnAckFrequencyFrame(
    const QuicAckFrequencyFrame& /*frame*/) {
  return true;
}

bool ChloFramerVisitor::IsValidStatelessResetToken(
    const StatelessResetToken& /*token*/) const {
  return false;
}

bool ChloFramerVisitor::OnMaxStreamsFrame(
    const QuicMaxStreamsFrame& /*frame*/) {
  return true;
}

bool ChloFramerVisitor::OnStreamsBlockedFrame(
    const QuicStreamsBlockedFrame& /*frame*/) {
  return true;
}

void ChloFramerVisitor::OnKeyUpdate(KeyUpdateReason /*reason*/) {}

void ChloFramerVisitor::OnDecryptedFirstPacketInKeyPhase() {}

std::unique_ptr<QuicDecrypter>
ChloFramerVisitor::AdvanceKeysAndCreateCurrentOneRttDecrypter() {
  return nullptr;
}

std::unique_ptr<QuicEncrypter>
ChloFramerVisitor::CreateCurrentOneRttEncrypter() {
  return nullptr;
}

void ChloFramerVisitor::OnError(CryptoFramer* /*framer*/) {}

void ChloFramerVisitor::OnHandshakeMessage(
    const CryptoHandshakeMessage& message) {
  if (delegate_ != nullptr) {
    delegate_->OnChlo(framer_->transport_version(), connection_id_, message);
  }
  found_chlo_ = true;
}

}  // namespace

// static
bool ChloExtractor::Extract(const QuicEncryptedPacket& packet,
                            ParsedQuicVersion version,
                            const QuicTagVector& create_session_tag_indicators,
                            Delegate* delegate, uint8_t connection_id_length) {
  QUIC_DVLOG(1) << "Extracting CHLO using version " << version;
  QuicFramer framer({version}, QuicTime::Zero(), Perspective::IS_SERVER,
                    connection_id_length);
  ChloFramerVisitor visitor(&framer, create_session_tag_indicators, delegate);
  framer.set_visitor(&visitor);
  if (!framer.ProcessPacket(packet)) {
    return false;
  }
  return visitor.found_chlo() || visitor.chlo_contains_tags();
}

}  // namespace quic

"""

```