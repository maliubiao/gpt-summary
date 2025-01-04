Response:
My thinking process to analyze the provided code and answer the prompt's questions goes like this:

1. **Understand the Goal:** The prompt asks for a summary of the functionality of the `QuicConfig` class, its relationship to JavaScript, logical inferences, potential user errors, debugging information, and a final overall summary. Crucially, it specifies this is the *second* part of a multi-part analysis. This means I should focus on the *new* functionality presented in this snippet and build upon the understanding from the assumed first part.

2. **Initial Code Scan (High-Level):** I quickly read through the code, identifying the different methods and members. I notice methods for setting and getting various configuration parameters related to QUIC connections. Keywords like "retry," "stateless reset," "idle timeout," "streams," "flow control," "handshake," and "transport parameters" stand out.

3. **Categorize Functionality:** I start grouping related methods together to understand the broader categories of configuration being handled. This helps create a structured summary. The categories I identify are:

    * **Retry and Connection IDs:** Handling retry source connection ID.
    * **Stateless Reset:** Managing stateless reset tokens.
    * **Session Management:**  Tracking if negotiation is complete and handling session tags.
    * **Default Settings:** Providing default configuration values.
    * **Handshake Message Integration:** Methods for encoding configuration into handshake messages (`ToHandshakeMessage`) and processing received handshake messages (`ProcessPeerHello`).
    * **Transport Parameter Mapping:** Methods for converting `QuicConfig` into and from IETF QUIC transport parameters (`FillTransportParameters`, `ProcessTransportParameters`).
    * **Preferred Address:** Handling alternate server addresses for connection migration.
    * **Reliable Stream Reset:** Configuring support for reliable stream resets.
    * **Internal Helpers:**  Methods like `ClearGoogleHandshakeMessage` and `GetPreferredAddressToSend`.

4. **Detailed Analysis of Each Category:**  I examine the methods within each category more closely, paying attention to:

    * **Purpose of the method:** What does it do?
    * **Input and output:** What data does it take and return?
    * **Conditions and checks:** Are there any `if` statements or assertions (`QUICHE_DCHECK`) that control the behavior?
    * **Relationship to other methods:** How does this method interact with other parts of the class?

5. **JavaScript Relevance:** I consider how the configuration options managed by `QuicConfig` might relate to JavaScript in a browser environment. Key areas of connection are:

    * **Network performance:**  Idle timeouts, flow control, and congestion control directly impact the speed and reliability of network requests initiated by JavaScript.
    * **Security:** Stateless reset tokens are a security mechanism.
    * **Connection management:**  Features like connection migration (handled through preferred addresses) affect how the browser maintains connections.
    * **WebSockets and other APIs:** While not directly exposed, the underlying QUIC configuration influences the behavior of these higher-level APIs.

6. **Logical Inferences (Hypothetical Scenarios):** I create simple scenarios with hypothetical inputs and outputs to illustrate how certain methods work. For instance, setting and getting the retry source connection ID.

7. **User/Programming Errors:** I think about common mistakes developers might make when working with network configurations, particularly in the context of QUIC. Examples include:

    * Incorrectly setting or interpreting timeout values.
    * Mismatched configuration between client and server.
    * Not handling negotiation failures.
    * Misunderstanding the purpose of different configuration options.

8. **Debugging Information (User Steps):** I consider how a developer might end up examining this code during debugging. The typical scenario involves network issues or unexpected behavior in a web application, leading to inspection of the underlying QUIC implementation. I outline the steps a developer might take to trace the execution to `quic_config.cc`.

9. **Part 2 Summary (Focus on New Information):** Since this is part 2, I focus on summarizing the functionality *introduced* or elaborated upon in this specific code snippet. I avoid repeating information I assume was covered in part 1. This involves highlighting features like retry connection IDs, stateless reset tokens, and the more detailed handling of transport parameters and handshake messages.

10. **Review and Refine:** I review my entire analysis, ensuring clarity, accuracy, and completeness. I check for any inconsistencies or areas where further explanation might be needed. I make sure the language is accessible and avoids overly technical jargon where possible. I specifically verify that the Part 2 summary builds upon the assumed knowledge from Part 1.

By following these steps, I can systematically analyze the code and provide a comprehensive answer that addresses all aspects of the prompt. The focus on breaking down the code into functional categories and then considering the implications for JavaScript, debugging, and potential errors makes the analysis more practical and insightful.
这是对 `net/third_party/quiche/src/quiche/quic/core/quic_config.cc` 文件代码片段的分析（第二部分）。

**归纳其功能：**

在第一部分的基础上，这段代码继续定义了 `QuicConfig` 类的成员函数，用于更细致地管理和处理 QUIC 连接的配置参数，尤其是在握手阶段和传输参数交换过程中。  其核心功能可以归纳为以下几点：

* **处理重试源连接ID (Retry Source Connection ID):**  允许设置、检查和获取用于连接重试机制的源连接ID。这在服务器尝试向客户端发起连接重试时使用。
* **处理无状态重置令牌 (Stateless Reset Token):**  提供了设置、检查发送和接收的无状态重置令牌的功能。无状态重置是 QUIC 中一种用于单方面终止连接的机制，无需维护连接状态。
* **管理会话标签指示符 (Session Tag Indicators):**  允许设置和获取用于指示创建会话的标签，可能用于服务端对客户端会话进行分类或管理。
* **设置默认配置 (SetDefaults):**  提供了一个便捷的方法将 `QuicConfig` 对象的所有关键配置项设置为预定义的默认值。
* **生成握手消息 (ToHandshakeMessage):**  将 `QuicConfig` 中存储的配置信息编码到 `CryptoHandshakeMessage` 对象中，以便在 QUIC 握手过程中发送给对端。这包括各种超时时间、流控参数、连接选项等。
* **处理对端握手消息 (ProcessPeerHello):**  解析从对端接收到的 `CryptoHandshakeMessage`，从中提取配置信息并更新本地的 `QuicConfig`。该方法会进行一些基本的校验，例如确保收到的空闲超时时间不会超过本地设置的值（对于服务器而言）。
* **填充传输参数 (FillTransportParameters):**  将 `QuicConfig` 中的配置转换为 IETF QUIC 标准的 `TransportParameters` 结构，以便在 QUIC 握手或连接迁移时发送给对端。
* **处理传输参数 (ProcessTransportParameters):**  解析从对端接收到的 `TransportParameters` 结构，从中提取配置信息并更新本地的 `QuicConfig`。  这个方法处理了更多的 IETF QUIC 定义的传输参数，例如初始最大数据量、最大流数量、ACK 延迟等。
* **管理备用服务器地址 (Alternate Server Address):**  支持设置和获取备用服务器地址，用于连接迁移等场景。区分了 IPv4 和 IPv6 地址，并支持 NAT 情况下的映射地址。
* **管理可靠流重置 (Reliable Stream Reset):**  允许设置和检查是否支持可靠的流重置机制。

**与 JavaScript 的关系：**

虽然 `quic_config.cc` 是 C++ 代码，直接与 JavaScript 没有代码层面的交互，但它所管理的功能直接影响基于 QUIC 协议的 Web 应用的性能和行为，而这些 Web 应用通常由 JavaScript 代码驱动。

**举例说明：**

* **空闲超时 (Idle Timeout):** `QuicConfig` 中设置的空闲超时时间 (`SetIdleNetworkTimeout`) 决定了当连接在一段时间内没有活动时，QUIC 连接会被关闭。这直接影响到用户在 Web 页面上操作的流畅性。如果超时时间设置过短，用户可能会频繁遇到连接中断的情况，JavaScript 代码需要处理这些错误并可能需要重新建立连接。
* **流控 (Flow Control):**  `QuicConfig` 中设置的流控窗口大小 (`SetInitialStreamFlowControlWindowToSend`, `SetInitialSessionFlowControlWindowToSend`) 限制了数据发送方在收到确认之前可以发送的数据量。这会影响 Web 页面加载资源的速度，JavaScript 代码通常不需要直接处理流控，但其性能会受到流控参数的影响。
* **连接迁移 (Connection Migration):** `QuicConfig` 中设置的备用服务器地址 (`SetIPv4AlternateServerAddressToSend`, `SetIPv6AlternateServerAddressToSend`) 允许连接在网络环境变化时迁移到新的地址，而不会中断连接。这对于移动设备用户来说非常重要，JavaScript 代码通常不需要感知底层的连接迁移过程，但可以受益于其带来的连接稳定性和连续性。

**逻辑推理（假设输入与输出）：**

假设我们有以下场景：

* **输入:** 一个 `QuicConfig` 对象 `config`，并且对端发送了一个 `TransportParameters`，其中 `max_idle_timeout_ms` 的值为 10000 毫秒 (10 秒)。本地 `config` 的 `max_idle_timeout_to_send_` 设置为 15 秒。

* **`ProcessTransportParameters` 方法的执行:**  `config.ProcessTransportParameters(received_transport_parameters, false, &error_details)`

* **输出:**  `config.received_max_idle_timeout_` 将被设置为 10 秒 (`QuicTime::Delta::FromMilliseconds(10000)`), 因为接收到的值小于本地设置的值。`negotiated_` 标志会被设置为 `true`。 `error_details` 将为空字符串，表示没有错误。

**用户或编程常见的使用错误：**

* **不匹配的配置:**  客户端和服务器端的 `QuicConfig` 配置参数应该在握手阶段进行协商，但如果由于某种原因（例如配置错误）导致关键参数不匹配（例如，客户端支持某个功能，但服务器不支持），可能会导致连接建立失败或运行异常。
    * **示例:** 客户端设置了 `reliable_stream_reset_ = true`，但服务器端没有启用该功能，当客户端尝试发送可靠的 RST_STREAM 帧时，服务器可能无法正确处理。
* **错误地设置超时时间:**  将空闲超时时间设置得过短可能导致连接频繁断开，影响用户体验。反之，设置得过长可能会浪费资源。
    * **示例:** 用户在服务器端将 `kMaximumIdleTimeoutSecs` 设置为 5 秒，导致客户端在短暂的静默期后就断开连接，用户需要频繁刷新页面。
* **忽视协商结果:**  在 `ProcessPeerHello` 或 `ProcessTransportParameters` 之后，没有检查返回的错误码，可能导致程序在配置协商失败的情况下继续运行，从而产生不可预测的行为。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器中访问一个使用了 QUIC 协议的网站。**
2. **浏览器（QUIC 客户端）尝试与服务器建立 QUIC 连接。**
3. **在连接建立的握手阶段，客户端和服务器需要交换配置信息。**
4. **客户端或服务器端的 QUIC 实现会创建 `QuicConfig` 对象来管理本地的连接配置。**
5. **在发送握手消息时，会调用 `config.ToHandshakeMessage()` 或 `config.FillTransportParameters()` 将配置信息编码到消息中。**
6. **在接收到对端的握手消息时，会调用 `config.ProcessPeerHello()` 或 `config.ProcessTransportParameters()` 来解析对端的配置信息。**
7. **如果调试过程中发现连接建立失败或某些 QUIC 功能异常，开发者可能会逐步跟踪代码执行流程，查看 `QuicConfig` 对象中的配置值是否正确，以及 `ProcessPeerHello` 或 `ProcessTransportParameters` 方法是否返回了错误。**
8. **开发者可能会在这些方法中设置断点，例如查看接收到的传输参数的值，或者检查本地配置在发送前的状态。**

**总结（第二部分的功能）：**

总而言之，这段代码片段继续完善了 `QuicConfig` 类的功能，使其能够更全面地管理 QUIC 连接的各种配置参数，特别是涉及到握手阶段的配置协商和传输参数的交换。它提供了设置默认值、编码配置到握手消息、解析对端配置、以及管理连接迁移和可靠流重置等关键功能。这些功能对于建立稳定、高效和安全的 QUIC 连接至关重要。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_config.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
nd_ = retry_source_connection_id;
}

bool QuicConfig::HasReceivedRetrySourceConnectionId() const {
  return received_retry_source_connection_id_.has_value();
}

QuicConnectionId QuicConfig::ReceivedRetrySourceConnectionId() const {
  if (!HasReceivedRetrySourceConnectionId()) {
    QUIC_BUG(quic_bug_10575_15) << "No received retry source connection ID";
    return EmptyQuicConnectionId();
  }
  return *received_retry_source_connection_id_;
}

void QuicConfig::SetStatelessResetTokenToSend(
    const StatelessResetToken& stateless_reset_token) {
  stateless_reset_token_.SetSendValue(stateless_reset_token);
}

bool QuicConfig::HasStatelessResetTokenToSend() const {
  return stateless_reset_token_.HasSendValue();
}

bool QuicConfig::HasReceivedStatelessResetToken() const {
  return stateless_reset_token_.HasReceivedValue();
}

const StatelessResetToken& QuicConfig::ReceivedStatelessResetToken() const {
  return stateless_reset_token_.GetReceivedValue();
}

bool QuicConfig::negotiated() const { return negotiated_; }

void QuicConfig::SetCreateSessionTagIndicators(QuicTagVector tags) {
  create_session_tag_indicators_ = std::move(tags);
}

const QuicTagVector& QuicConfig::create_session_tag_indicators() const {
  return create_session_tag_indicators_;
}

void QuicConfig::SetDefaults() {
  SetIdleNetworkTimeout(QuicTime::Delta::FromSeconds(kMaximumIdleTimeoutSecs));
  SetMaxBidirectionalStreamsToSend(kDefaultMaxStreamsPerConnection);
  SetMaxUnidirectionalStreamsToSend(kDefaultMaxStreamsPerConnection);
  max_time_before_crypto_handshake_ =
      QuicTime::Delta::FromSeconds(kMaxTimeForCryptoHandshakeSecs);
  max_idle_time_before_crypto_handshake_ =
      QuicTime::Delta::FromSeconds(kInitialIdleTimeoutSecs);
  max_undecryptable_packets_ = kDefaultMaxUndecryptablePackets;

  SetInitialStreamFlowControlWindowToSend(kMinimumFlowControlSendWindow);
  SetInitialSessionFlowControlWindowToSend(kMinimumFlowControlSendWindow);
  SetMaxAckDelayToSendMs(GetDefaultDelayedAckTimeMs());
  SetAckDelayExponentToSend(kDefaultAckDelayExponent);
  SetMaxPacketSizeToSend(kMaxIncomingPacketSize);
  SetMaxDatagramFrameSizeToSend(kMaxAcceptedDatagramFrameSize);
  SetReliableStreamReset(false);
}

void QuicConfig::ToHandshakeMessage(
    CryptoHandshakeMessage* out, QuicTransportVersion transport_version) const {
  // Idle timeout has custom rules that are different from other values.
  // We configure ourselves with the minumum value between the one sent and
  // the one received. Additionally, when QUIC_CRYPTO is used, the server
  // MUST send an idle timeout no greater than the idle timeout it received
  // from the client. We therefore send the received value if it is lower.
  QuicFixedUint32 max_idle_timeout_seconds(kICSL, PRESENCE_REQUIRED);
  uint32_t max_idle_timeout_to_send_seconds =
      max_idle_timeout_to_send_.ToSeconds();
  if (received_max_idle_timeout_.has_value() &&
      received_max_idle_timeout_->ToSeconds() <
          max_idle_timeout_to_send_seconds) {
    max_idle_timeout_to_send_seconds = received_max_idle_timeout_->ToSeconds();
  }
  max_idle_timeout_seconds.SetSendValue(max_idle_timeout_to_send_seconds);
  max_idle_timeout_seconds.ToHandshakeMessage(out);

  // Do not need a version check here, max...bi... will encode
  // as "MIDS" -- the max initial dynamic streams tag -- if
  // doing some version other than IETF QUIC.
  max_bidirectional_streams_.ToHandshakeMessage(out);
  if (VersionHasIetfQuicFrames(transport_version)) {
    max_unidirectional_streams_.ToHandshakeMessage(out);
    ack_delay_exponent_.ToHandshakeMessage(out);
  }
  if (max_ack_delay_ms_.GetSendValue() != GetDefaultDelayedAckTimeMs()) {
    // Only send max ack delay if it is using a non-default value, because
    // the default value is used by QuicSentPacketManager if it is not
    // sent during the handshake, and we want to save bytes.
    max_ack_delay_ms_.ToHandshakeMessage(out);
  }
  bytes_for_connection_id_.ToHandshakeMessage(out);
  initial_round_trip_time_us_.ToHandshakeMessage(out);
  initial_stream_flow_control_window_bytes_.ToHandshakeMessage(out);
  initial_session_flow_control_window_bytes_.ToHandshakeMessage(out);
  connection_migration_disabled_.ToHandshakeMessage(out);
  connection_options_.ToHandshakeMessage(out);
  if (alternate_server_address_ipv6_.HasSendValue()) {
    alternate_server_address_ipv6_.ToHandshakeMessage(out);
  } else {
    alternate_server_address_ipv4_.ToHandshakeMessage(out);
  }
  stateless_reset_token_.ToHandshakeMessage(out);
}

QuicErrorCode QuicConfig::ProcessPeerHello(
    const CryptoHandshakeMessage& peer_hello, HelloType hello_type,
    std::string* error_details) {
  QUICHE_DCHECK(error_details != nullptr);

  QuicErrorCode error = QUIC_NO_ERROR;
  if (error == QUIC_NO_ERROR) {
    // Idle timeout has custom rules that are different from other values.
    // We configure ourselves with the minumum value between the one sent and
    // the one received. Additionally, when QUIC_CRYPTO is used, the server
    // MUST send an idle timeout no greater than the idle timeout it received
    // from the client.
    QuicFixedUint32 max_idle_timeout_seconds(kICSL, PRESENCE_REQUIRED);
    error = max_idle_timeout_seconds.ProcessPeerHello(peer_hello, hello_type,
                                                      error_details);
    if (error == QUIC_NO_ERROR) {
      if (max_idle_timeout_seconds.GetReceivedValue() >
          max_idle_timeout_to_send_.ToSeconds()) {
        // The received value is higher than ours, ignore it if from the client
        // and raise an error if from the server.
        if (hello_type == SERVER) {
          error = QUIC_INVALID_NEGOTIATED_VALUE;
          *error_details =
              "Invalid value received for " + QuicTagToString(kICSL);
        }
      } else {
        received_max_idle_timeout_ = QuicTime::Delta::FromSeconds(
            max_idle_timeout_seconds.GetReceivedValue());
      }
    }
  }
  if (error == QUIC_NO_ERROR) {
    error = max_bidirectional_streams_.ProcessPeerHello(peer_hello, hello_type,
                                                        error_details);
  }
  if (error == QUIC_NO_ERROR) {
    error = max_unidirectional_streams_.ProcessPeerHello(peer_hello, hello_type,
                                                         error_details);
  }
  if (error == QUIC_NO_ERROR) {
    error = bytes_for_connection_id_.ProcessPeerHello(peer_hello, hello_type,
                                                      error_details);
  }
  if (error == QUIC_NO_ERROR) {
    error = initial_round_trip_time_us_.ProcessPeerHello(peer_hello, hello_type,
                                                         error_details);
  }
  if (error == QUIC_NO_ERROR) {
    error = initial_stream_flow_control_window_bytes_.ProcessPeerHello(
        peer_hello, hello_type, error_details);
  }
  if (error == QUIC_NO_ERROR) {
    error = initial_session_flow_control_window_bytes_.ProcessPeerHello(
        peer_hello, hello_type, error_details);
  }
  if (error == QUIC_NO_ERROR) {
    error = connection_migration_disabled_.ProcessPeerHello(
        peer_hello, hello_type, error_details);
  }
  if (error == QUIC_NO_ERROR) {
    error = connection_options_.ProcessPeerHello(peer_hello, hello_type,
                                                 error_details);
  }
  if (error == QUIC_NO_ERROR) {
    QuicFixedSocketAddress alternate_server_address(kASAD, PRESENCE_OPTIONAL);
    error = alternate_server_address.ProcessPeerHello(peer_hello, hello_type,
                                                      error_details);
    if (error == QUIC_NO_ERROR && alternate_server_address.HasReceivedValue()) {
      const QuicSocketAddress& received_address =
          alternate_server_address.GetReceivedValue();
      if (received_address.host().IsIPv6()) {
        alternate_server_address_ipv6_.SetReceivedValue(received_address);
      } else if (received_address.host().IsIPv4()) {
        alternate_server_address_ipv4_.SetReceivedValue(received_address);
      }
    }
  }
  if (error == QUIC_NO_ERROR) {
    error = stateless_reset_token_.ProcessPeerHello(peer_hello, hello_type,
                                                    error_details);
  }

  if (error == QUIC_NO_ERROR) {
    error = max_ack_delay_ms_.ProcessPeerHello(peer_hello, hello_type,
                                               error_details);
  }
  if (error == QUIC_NO_ERROR) {
    error = ack_delay_exponent_.ProcessPeerHello(peer_hello, hello_type,
                                                 error_details);
  }
  if (error == QUIC_NO_ERROR) {
    negotiated_ = true;
  }
  return error;
}

bool QuicConfig::FillTransportParameters(TransportParameters* params) const {
  if (original_destination_connection_id_to_send_.has_value()) {
    params->original_destination_connection_id =
        *original_destination_connection_id_to_send_;
  }

  params->max_idle_timeout_ms.set_value(
      max_idle_timeout_to_send_.ToMilliseconds());

  if (stateless_reset_token_.HasSendValue()) {
    StatelessResetToken stateless_reset_token =
        stateless_reset_token_.GetSendValue();
    params->stateless_reset_token.assign(
        reinterpret_cast<const char*>(&stateless_reset_token),
        reinterpret_cast<const char*>(&stateless_reset_token) +
            sizeof(stateless_reset_token));
  }

  params->max_udp_payload_size.set_value(GetMaxPacketSizeToSend());
  params->max_datagram_frame_size.set_value(GetMaxDatagramFrameSizeToSend());
  params->initial_max_data.set_value(
      GetInitialSessionFlowControlWindowToSend());
  // The max stream data bidirectional transport parameters can be either local
  // or remote. A stream is local iff it is initiated by the endpoint that sent
  // the transport parameter (see the Transport Parameter Definitions section of
  // draft-ietf-quic-transport). In this function we are sending transport
  // parameters, so a local stream is one we initiated, which means an outgoing
  // stream.
  params->initial_max_stream_data_bidi_local.set_value(
      GetInitialMaxStreamDataBytesOutgoingBidirectionalToSend());
  params->initial_max_stream_data_bidi_remote.set_value(
      GetInitialMaxStreamDataBytesIncomingBidirectionalToSend());
  params->initial_max_stream_data_uni.set_value(
      GetInitialMaxStreamDataBytesUnidirectionalToSend());
  params->initial_max_streams_bidi.set_value(
      GetMaxBidirectionalStreamsToSend());
  params->initial_max_streams_uni.set_value(
      GetMaxUnidirectionalStreamsToSend());
  params->max_ack_delay.set_value(GetMaxAckDelayToSendMs());
  if (min_ack_delay_ms_.HasSendValue()) {
    params->min_ack_delay_us.set_value(min_ack_delay_ms_.GetSendValue() *
                                       kNumMicrosPerMilli);
  }
  params->ack_delay_exponent.set_value(GetAckDelayExponentToSend());
  params->disable_active_migration =
      connection_migration_disabled_.HasSendValue() &&
      connection_migration_disabled_.GetSendValue() != 0;

  if (alternate_server_address_ipv6_.HasSendValue() ||
      alternate_server_address_ipv4_.HasSendValue()) {
    TransportParameters::PreferredAddress preferred_address;
    if (alternate_server_address_ipv6_.HasSendValue()) {
      preferred_address.ipv6_socket_address =
          alternate_server_address_ipv6_.GetSendValue();
    }
    if (alternate_server_address_ipv4_.HasSendValue()) {
      preferred_address.ipv4_socket_address =
          alternate_server_address_ipv4_.GetSendValue();
    }
    if (preferred_address_connection_id_and_token_) {
      preferred_address.connection_id =
          preferred_address_connection_id_and_token_->first;
      auto* begin = reinterpret_cast<const char*>(
          &preferred_address_connection_id_and_token_->second);
      auto* end =
          begin + sizeof(preferred_address_connection_id_and_token_->second);
      preferred_address.stateless_reset_token.assign(begin, end);
    }
    params->preferred_address =
        std::make_unique<TransportParameters::PreferredAddress>(
            preferred_address);
  }

  if (active_connection_id_limit_.HasSendValue()) {
    params->active_connection_id_limit.set_value(
        active_connection_id_limit_.GetSendValue());
  }

  if (initial_source_connection_id_to_send_.has_value()) {
    params->initial_source_connection_id =
        *initial_source_connection_id_to_send_;
  }

  if (retry_source_connection_id_to_send_.has_value()) {
    params->retry_source_connection_id = *retry_source_connection_id_to_send_;
  }

  if (initial_round_trip_time_us_.HasSendValue()) {
    params->initial_round_trip_time_us.set_value(
        initial_round_trip_time_us_.GetSendValue());
  }
  if (connection_options_.HasSendValues() &&
      !connection_options_.GetSendValues().empty()) {
    params->google_connection_options = connection_options_.GetSendValues();
  }

  if (google_handshake_message_to_send_.has_value()) {
    params->google_handshake_message = google_handshake_message_to_send_;
  }

  params->discard_length = discard_length_to_send_;

  params->reliable_stream_reset = reliable_stream_reset_;

  params->custom_parameters = custom_transport_parameters_to_send_;

  return true;
}

QuicErrorCode QuicConfig::ProcessTransportParameters(
    const TransportParameters& params, bool is_resumption,
    std::string* error_details) {
  if (!is_resumption && params.original_destination_connection_id.has_value()) {
    received_original_destination_connection_id_ =
        *params.original_destination_connection_id;
  }

  if (params.max_idle_timeout_ms.value() > 0 &&
      params.max_idle_timeout_ms.value() <
          static_cast<uint64_t>(max_idle_timeout_to_send_.ToMilliseconds())) {
    // An idle timeout of zero indicates it is disabled.
    // We also ignore values higher than ours which will cause us to use the
    // smallest value between ours and our peer's.
    received_max_idle_timeout_ =
        QuicTime::Delta::FromMilliseconds(params.max_idle_timeout_ms.value());
  }

  if (!is_resumption && !params.stateless_reset_token.empty()) {
    StatelessResetToken stateless_reset_token;
    if (params.stateless_reset_token.size() != sizeof(stateless_reset_token)) {
      QUIC_BUG(quic_bug_10575_16) << "Bad stateless reset token length "
                                  << params.stateless_reset_token.size();
      *error_details = "Bad stateless reset token length";
      return QUIC_INTERNAL_ERROR;
    }
    memcpy(&stateless_reset_token, params.stateless_reset_token.data(),
           params.stateless_reset_token.size());
    stateless_reset_token_.SetReceivedValue(stateless_reset_token);
  }

  if (params.max_udp_payload_size.IsValid()) {
    max_udp_payload_size_.SetReceivedValue(params.max_udp_payload_size.value());
  }

  if (params.max_datagram_frame_size.IsValid()) {
    max_datagram_frame_size_.SetReceivedValue(
        params.max_datagram_frame_size.value());
  }

  initial_session_flow_control_window_bytes_.SetReceivedValue(
      params.initial_max_data.value());

  // IETF QUIC specifies stream IDs and stream counts as 62-bit integers but
  // our implementation uses uint32_t to represent them to save memory.
  max_bidirectional_streams_.SetReceivedValue(
      std::min<uint64_t>(params.initial_max_streams_bidi.value(),
                         std::numeric_limits<uint32_t>::max()));
  max_unidirectional_streams_.SetReceivedValue(
      std::min<uint64_t>(params.initial_max_streams_uni.value(),
                         std::numeric_limits<uint32_t>::max()));

  // The max stream data bidirectional transport parameters can be either local
  // or remote. A stream is local iff it is initiated by the endpoint that sent
  // the transport parameter (see the Transport Parameter Definitions section of
  // draft-ietf-quic-transport). However in this function we are processing
  // received transport parameters, so a local stream is one initiated by our
  // peer, which means an incoming stream.
  initial_max_stream_data_bytes_incoming_bidirectional_.SetReceivedValue(
      params.initial_max_stream_data_bidi_local.value());
  initial_max_stream_data_bytes_outgoing_bidirectional_.SetReceivedValue(
      params.initial_max_stream_data_bidi_remote.value());
  initial_max_stream_data_bytes_unidirectional_.SetReceivedValue(
      params.initial_max_stream_data_uni.value());

  if (!is_resumption) {
    max_ack_delay_ms_.SetReceivedValue(params.max_ack_delay.value());
    if (params.ack_delay_exponent.IsValid()) {
      ack_delay_exponent_.SetReceivedValue(params.ack_delay_exponent.value());
    }
    if (params.preferred_address != nullptr) {
      if (params.preferred_address->ipv6_socket_address.port() != 0) {
        alternate_server_address_ipv6_.SetReceivedValue(
            params.preferred_address->ipv6_socket_address);
      }
      if (params.preferred_address->ipv4_socket_address.port() != 0) {
        alternate_server_address_ipv4_.SetReceivedValue(
            params.preferred_address->ipv4_socket_address);
      }
      // TODO(haoyuewang) Treat 0 length connection ID sent in preferred_address
      // as a connection error of type TRANSPORT_PARAMETER_ERROR when server
      // fully supports it.
      if (!params.preferred_address->connection_id.IsEmpty()) {
        preferred_address_connection_id_and_token_ = std::make_pair(
            params.preferred_address->connection_id,
            *reinterpret_cast<const StatelessResetToken*>(
                &params.preferred_address->stateless_reset_token.front()));
      }
    }
    if (params.min_ack_delay_us.value() != 0) {
      if (params.min_ack_delay_us.value() >
          params.max_ack_delay.value() * kNumMicrosPerMilli) {
        *error_details = "MinAckDelay is greater than MaxAckDelay.";
        return IETF_QUIC_PROTOCOL_VIOLATION;
      }
      min_ack_delay_ms_.SetReceivedValue(params.min_ack_delay_us.value() /
                                         kNumMicrosPerMilli);
    }
  }

  if (params.disable_active_migration) {
    connection_migration_disabled_.SetReceivedValue(1u);
  }

  active_connection_id_limit_.SetReceivedValue(
      params.active_connection_id_limit.value());

  if (!is_resumption) {
    if (params.initial_source_connection_id.has_value()) {
      received_initial_source_connection_id_ =
          *params.initial_source_connection_id;
    }
    if (params.retry_source_connection_id.has_value()) {
      received_retry_source_connection_id_ = *params.retry_source_connection_id;
    }
  }

  if (params.initial_round_trip_time_us.value() > 0) {
    initial_round_trip_time_us_.SetReceivedValue(
        params.initial_round_trip_time_us.value());
  }
  if (params.google_connection_options.has_value()) {
    connection_options_.SetReceivedValues(*params.google_connection_options);
  }
  if (params.google_handshake_message.has_value()) {
    received_google_handshake_message_ = params.google_handshake_message;
  }

  received_custom_transport_parameters_ = params.custom_parameters;

  discard_length_received_ = params.discard_length;

  if (reliable_stream_reset_) {
    reliable_stream_reset_ = params.reliable_stream_reset;
  }

  if (!is_resumption) {
    negotiated_ = true;
  }
  *error_details = "";
  return QUIC_NO_ERROR;
}

void QuicConfig::ClearGoogleHandshakeMessage() {
  google_handshake_message_to_send_.reset();
  received_google_handshake_message_.reset();
}

std::optional<QuicSocketAddress> QuicConfig::GetPreferredAddressToSend(
    quiche::IpAddressFamily address_family) const {
  if (alternate_server_address_ipv6_.HasSendValue() &&
      address_family == quiche::IpAddressFamily::IP_V6) {
    return alternate_server_address_ipv6_.GetSendValue();
  }

  if (alternate_server_address_ipv4_.HasSendValue() &&
      address_family == quiche::IpAddressFamily::IP_V4) {
    return alternate_server_address_ipv4_.GetSendValue();
  }
  return std::nullopt;
}

void QuicConfig::SetIPv4AlternateServerAddressForDNat(
    const QuicSocketAddress& alternate_server_address_ipv4_to_send,
    const QuicSocketAddress& mapped_alternate_server_address_ipv4) {
  SetIPv4AlternateServerAddressToSend(alternate_server_address_ipv4_to_send);
  mapped_alternate_server_address_ipv4_ = mapped_alternate_server_address_ipv4;
}

void QuicConfig::SetIPv6AlternateServerAddressForDNat(
    const QuicSocketAddress& alternate_server_address_ipv6_to_send,
    const QuicSocketAddress& mapped_alternate_server_address_ipv6) {
  SetIPv6AlternateServerAddressToSend(alternate_server_address_ipv6_to_send);
  mapped_alternate_server_address_ipv6_ = mapped_alternate_server_address_ipv6;
}

std::optional<QuicSocketAddress> QuicConfig::GetMappedAlternativeServerAddress(
    quiche::IpAddressFamily address_family) const {
  if (mapped_alternate_server_address_ipv6_.has_value() &&
      address_family == quiche::IpAddressFamily::IP_V6) {
    return *mapped_alternate_server_address_ipv6_;
  }

  if (mapped_alternate_server_address_ipv4_.has_value() &&
      address_family == quiche::IpAddressFamily::IP_V4) {
    return *mapped_alternate_server_address_ipv4_;
  }
  return GetPreferredAddressToSend(address_family);
}

void QuicConfig::ClearAlternateServerAddressToSend(
    quiche::IpAddressFamily address_family) {
  if (address_family == quiche::IpAddressFamily::IP_V4) {
    alternate_server_address_ipv4_.ClearSendValue();
  } else if (address_family == quiche::IpAddressFamily::IP_V6) {
    alternate_server_address_ipv6_.ClearSendValue();
  }
}

bool QuicConfig::SupportsServerPreferredAddress(Perspective perspective) const {
  return perspective == Perspective::IS_CLIENT ||
         HasClientSentConnectionOption(kSPAD, perspective) ||
         GetQuicFlag(quic_always_support_server_preferred_address);
}

void QuicConfig::SetReliableStreamReset(bool reliable_stream_reset) {
  reliable_stream_reset_ = reliable_stream_reset;
}

bool QuicConfig::SupportsReliableStreamReset() const {
  return reliable_stream_reset_;
}

}  // namespace quic

"""


```