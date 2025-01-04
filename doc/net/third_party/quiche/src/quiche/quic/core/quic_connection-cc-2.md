Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of Chromium's QUIC implementation. I need to identify the key actions performed by this code, focusing on how it handles different QUIC frame types. I also need to consider if these actions relate to JavaScript functionality, provide examples, discuss logical inferences with input/output, highlight potential user or programming errors, and outline how a user might reach this code during debugging.

Here's a breakdown of the code's actions:

1. **Handling incoming QUIC frames:** The code consists of several `On...Frame` methods (e.g., `OnPathChallengeFrame`, `OnPathResponseFrame`, `OnConnectionCloseFrame`). Each of these methods is responsible for processing a specific type of QUIC frame received from the peer.

2. **Path Validation:**  The `OnPathChallengeFrame` and `OnPathResponseFrame` methods deal with the QUIC path validation mechanism, ensuring the connection is still valid on the current network path.

3. **Connection Closure:** The `OnConnectionCloseFrame` method handles the termination of the QUIC connection, logging details about the closure.

4. **Stream Management:** The `OnMaxStreamsFrame` and `OnStreamsBlockedFrame` methods manage the flow control of streams within the QUIC connection.

5. **Flow Control:** The `OnWindowUpdateFrame` method updates the flow control window for a stream or the entire connection.

6. **Connection ID Management:** The `OnNewConnectionIdFrame` and `OnRetireConnectionIdFrame` methods handle the exchange and retirement of connection IDs for connection migration purposes.

7. **New Token Handling:** The `OnNewTokenFrame` method processes new tokens provided by the server for future connection establishment.

8. **Generic Message Handling:** The `OnMessageFrame` method handles arbitrary data messages outside of streams.

9. **Handshake Completion:** The `OnHandshakeDoneFrame` method signals the completion of the QUIC handshake.

10. **ACK Frequency:** The `OnAckFrequencyFrame` method handles requests from the peer to adjust the frequency of acknowledgment packets.

11. **Stream Reset:** The `OnResetStreamAtFrame` method handles requests to reset a stream at a specific offset.

12. **Blocking Indication:** The `OnBlockedFrame` method indicates that a stream is blocked due to flow control.

13. **Packet Completion and Probing:** The `OnPacketComplete` method is called after processing a complete packet, and `MaybeRespondToConnectivityProbingOrMigration` deals with responding to connectivity probes.

14. **Stateless Reset:** The code handles stateless reset packets in `OnAuthenticatedIetfStatelessResetPacket`.

15. **Key Updates:** The `OnKeyUpdate` and `OnDecryptedFirstPacketInKeyPhase` methods manage the process of updating encryption keys.

16. **Sending Data:** The `SendCryptoData`, `SendStreamData`, and `SendControlFrame` methods handle sending different types of data over the connection.

17. **Write Blocking:** `HandleWriteBlocked` checks if the connection is blocked on writing data.

18. **Deferred Sending:** `MaybeSendInResponseToPacket` manages sending data in response to received packets.

Now, let's address the specific points in the request:

*   **JavaScript Relationship:**  QUIC connections are often used by web browsers to fetch resources. JavaScript running in a browser initiates these requests, which then utilize the underlying network stack, including this `QuicConnection` code.

*   **Logical Inference:** I can demonstrate logical flow based on the received frame type.

*   **User/Programming Errors:**  I can point out common mistakes that might lead to these code sections being executed.

*   **Debugging:** I can illustrate how a developer might step through this code.

Finally, I need to summarize the overall functionality of this specific code portion as part 3 of 10. It primarily focuses on handling incoming QUIC frames and the immediate actions taken in response.
这是 `net/third_party/quiche/src/quiche/quic/core/quic_connection.cc` 文件的一部分，主要负责处理接收到的各种 QUIC 帧（Frame）。它定义了 `QuicConnection` 类中一系列以 `On...Frame` 开头的方法，每个方法对应处理一种特定的 QUIC 帧类型。

**以下是这段代码的主要功能归纳：**

1. **处理路径挑战 (PATH_CHALLENGE):**
    *   验证连接状态，确保在连接打开时处理。
    *   记录收到的数据包信息。
    *   避免在一个数据包中响应多个相同的 PATH_CHALLENGE 帧。
    *   根据配置决定是否主动验证对等方地址。
    *   调用 `UpdatePacketContent` 更新数据包内容状态。
    *   如果设置了调试访问器，则通知它。
    *   根据连接的视角（客户端或服务器），确定响应的目标地址。
    *   查找与路径相关的连接 ID。
    *   创建数据包创建器的上下文，以便发送响应。
    *   如果需要主动验证对等方地址，则启动反向路径验证。
    *   标记当前数据包已包含 PATH_CHALLENGE 帧。
    *   更新 ACK 超时。
    *   调用 `SendPathResponse` 发送 PATH_RESPONSE 帧。
    *   增加连接探测接收计数器。

2. **处理路径响应 (PATH_RESPONSE):**
    *   验证连接状态。
    *   增加路径响应接收计数器。
    *   调用 `UpdatePacketContent` 更新数据包内容状态。
    *   如果设置了调试访问器，则通知它。
    *   更新 ACK 超时。
    *   调用 `path_validator_.OnPathResponse` 处理路径响应。

3. **处理连接关闭 (CONNECTION_CLOSE):**
    *   验证连接状态。
    *   调用 `UpdatePacketContent` 更新数据包内容状态。
    *   如果设置了调试访问器，则通知它。
    *   记录不同类型的连接关闭错误信息（GOOGLE_QUIC, IETF_QUIC_TRANSPORT, IETF_QUIC_APPLICATION）。
    *   处理特定的错误码，例如 `QUIC_BAD_MULTIPATH_FLAG`。
    *   调用 `TearDownLocalConnectionState` 清理本地连接状态。

4. **处理最大流 (MAX_STREAMS):**
    *   验证连接状态。
    *   调用 `UpdatePacketContent` 更新数据包内容状态。
    *   如果设置了调试访问器，则通知它。
    *   更新 ACK 超时。
    *   调用 `visitor_->OnMaxStreamsFrame` 通知访问器。

5. **处理流被阻塞 (STREAMS_BLOCKED):**
    *   验证连接状态。
    *   调用 `UpdatePacketContent` 更新数据包内容状态。
    *   如果设置了调试访问器，则通知它。
    *   更新 ACK 超时。
    *   调用 `visitor_->OnStreamsBlockedFrame` 通知访问器。

6. **处理停止发送 (GOAWAY):**
    *   验证连接状态。
    *   调用 `UpdatePacketContent` 更新数据包内容状态。
    *   如果设置了调试访问器，则通知它。
    *   记录 GOAWAY 帧的信息。
    *   更新 ACK 超时。
    *   调用 `visitor_->OnGoAway` 通知访问器。

7. **处理窗口更新 (WINDOW_UPDATE):**
    *   验证连接状态。
    *   调用 `UpdatePacketContent` 更新数据包内容状态。
    *   如果设置了调试访问器，则通知它。
    *   记录 WINDOW_UPDATE 帧的信息。
    *   更新 ACK 超时。
    *   调用 `visitor_->OnWindowUpdateFrame` 通知访问器。

8. **处理新的连接 ID (NEW_CONNECTION_ID):**
    *   验证连接状态。
    *   调用 `UpdatePacketContent` 更新数据包内容状态。
    *   如果设置了调试访问器，则通知它。
    *   调用 `OnNewConnectionIdFrameInner` 进行实际处理。
    *   在服务器端，当有新的可用连接 ID 时，将其分配给默认或备用路径。
    *   如果启用了多端口，可能会触发创建多端口路径。

9. **处理请求撤销连接 ID (RETIRE_CONNECTION_ID):**
    *   验证连接状态。
    *   调用 `UpdatePacketContent` 更新数据包内容状态。
    *   如果设置了调试访问器，则通知它。
    *   调用 `self_issued_cid_manager_->OnRetireConnectionIdFrame` 处理撤销请求。
    *   更新 ACK 超时。

10. **处理新的 Token (NEW_TOKEN):**
    *   验证连接状态。
    *   调用 `UpdatePacketContent` 更新数据包内容状态。
    *   如果设置了调试访问器，则通知它。
    *   如果服务器收到 NEW_TOKEN 帧，则关闭连接。
    *   更新 ACK 超时。
    *   调用 `visitor_->OnNewTokenReceived` 通知访问器。

11. **处理消息 (MESSAGE):**
    *   验证连接状态。
    *   调用 `UpdatePacketContent` 更新数据包内容状态。
    *   如果设置了调试访问器，则通知它。
    *   更新 ACK 超时。
    *   调用 `visitor_->OnMessageReceived` 通知访问器。

12. **处理握手完成 (HANDSHAKE_DONE):**
    *   验证连接状态。
    *   仅在 TLS 连接中支持。
    *   如果服务器收到 HANDSHAKE_DONE 帧，则关闭连接。
    *   调用 `UpdatePacketContent` 更新数据包内容状态。
    *   如果设置了调试访问器，则通知它。
    *   更新 ACK 超时。
    *   调用 `visitor_->OnHandshakeDoneReceived` 通知访问器。

13. **处理 ACK 频率 (ACK_FREQUENCY):**
    *   验证连接状态。
    *   如果设置了调试访问器，则通知它。
    *   调用 `UpdatePacketContent` 更新数据包内容状态。
    *   只有在允许接收 ACK 频率帧时才处理。
    *   根据数据包的包号空间进行处理。
    *   更新 ACK 超时。

14. **处理请求重置流在特定偏移量 (RESET_STREAM_AT):**
    *   验证连接状态。
    *   如果设置了调试访问器，则通知它。
    *   调用 `UpdatePacketContent` 更新数据包内容状态。
    *   只有在协商了 `process_reset_stream_at` 时才处理。
    *   更新 ACK 超时。
    *   调用 `visitor_->OnResetStreamAt` 通知访问器。

15. **处理阻塞 (BLOCKED):**
    *   验证连接状态。
    *   调用 `UpdatePacketContent` 更新数据包内容状态。
    *   如果设置了调试访问器，则通知它。
    *   记录 BLOCKED 帧的信息。
    *   更新 ACK 超时。
    *   增加阻塞帧接收计数器。

**与 JavaScript 的功能关系及举例说明：**

这段 C++ 代码是 Chromium 网络栈的一部分，负责底层的 QUIC 连接管理。当 JavaScript 代码发起网络请求（例如使用 `fetch` API 或 WebSocket over QUIC），这些请求最终会通过 Chromium 的网络栈进行处理。

例如：

*   **`OnPathChallengeFrame` 和 `OnPathResponseFrame`:**  当网络环境发生变化，例如用户从 Wi-Fi 切换到移动数据，浏览器可能会收到 PATH_CHALLENGE 帧。这段 C++ 代码负责处理这些帧，确保连接的路径仍然有效，从而保证 JavaScript 发起的请求不会中断。
*   **`OnConnectionCloseFrame`:** 如果服务器由于某些原因关闭了 QUIC 连接，这段代码会接收并处理 CONNECTION_CLOSE 帧。浏览器可能会通过 `fetch` API 的错误回调或 WebSocket 的 `onclose` 事件通知 JavaScript 代码连接已关闭。
*   **`OnMaxStreamsFrame` 和 `OnStreamsBlockedFrame`:** QUIC 使用流来并行传输数据。这些帧用于管理并发流的数量。如果服务器发送 `MAX_STREAMS` 帧限制了可以创建的流的数量，或者发送 `STREAMS_BLOCKED` 帧指示客户端不能再创建新的流，这段 C++ 代码会处理这些限制，并可能影响 JavaScript 中并行请求的行为。
*   **`OnMessageFrame`:**  QUIC 的消息功能允许在连接上发送不属于任何流的独立消息。如果服务器发送了这样的消息，这段代码会接收并将其传递给上层，最终 JavaScript 代码可以通过某种方式接收到这些消息。

**逻辑推理、假设输入与输出：**

假设输入：接收到一个类型为 `QuicPathChallengeFrame` 的帧，其 `data_buffer` 内容为 "abcdefgh"。

```c++
bool QuicConnection::OnPathChallengeFrame(const QuicPathChallengeFrame& frame) {
  // ... 省略前面的代码 ...
  {
    // ... 省略部分代码 ...
    if (!SendPathResponse(frame.data_buffer, direct_peer_address_to_respond,
                          effective_peer_address_to_respond)) {
      QUIC_CODE_COUNT(quic_failed_to_send_path_response);
    }
    // ... 省略后面的代码 ...
  }
  return connected_;
}
```

逻辑推理：`SendPathResponse` 函数会被调用，其第一个参数是接收到的 `frame.data_buffer`，也就是 "abcdefgh"。根据 QUIC 协议，服务器需要将 PATH_CHALLENGE 帧中的数据回显到 PATH_RESPONSE 帧中。

假设输出：`SendPathResponse` 函数成功执行，并且向对等方发送了一个 `QuicPathResponseFrame`，其 `data_buffer` 的内容为 "abcdefgh"。

**用户或编程常见的使用错误及举例说明：**

*   **在连接关闭后尝试发送数据或处理帧：** 代码中大量使用了 `QUIC_BUG_IF(!connected_)` 来检查连接状态。如果编程错误导致在连接已经关闭后仍然尝试处理接收到的帧，就会触发断言，表明程序存在错误。例如，如果在连接关闭的回调函数中，仍然尝试访问连接相关的状态，就可能触发此类错误。

*   **未正确处理连接关闭：**  如果用户或程序没有正确处理连接关闭的情况，可能会导致资源泄漏或者程序崩溃。例如，如果 JavaScript 代码在接收到连接关闭事件后，没有清理相关的资源或取消未完成的请求，可能会导致问题。这段 C++ 代码负责接收并处理连接关闭帧，但上层应用需要根据此信息采取相应的行动。

*   **不理解 QUIC 的状态机导致操作顺序错误：**  例如，在握手完成之前尝试发送应用数据，可能会导致错误。这段代码会根据连接的状态来处理接收到的帧，如果接收到不符合当前状态的帧，可能会导致连接关闭。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中发起一个 HTTPS 请求或者建立一个 WebSocket 连接到支持 QUIC 的服务器。**
2. **Chromium 的网络栈选择使用 QUIC 协议进行连接。**
3. **服务器向客户端发送一个 QUIC 数据包。**
4. **客户端接收到该数据包，并由底层的网络层传递到 QUIC 协议栈。**
5. **QUIC 协议栈解析数据包的头部，识别出包含的帧类型。**
6. **根据帧类型，调用 `QuicConnection` 类中对应的 `On...Frame` 方法。** 例如，如果接收到的帧是 PATH_CHALLENGE 帧，则会调用 `OnPathChallengeFrame` 方法。

**调试线索：**

*   **抓包工具 (如 Wireshark):** 可以捕获网络数据包，查看接收到的 QUIC 帧的类型和内容，从而确定调用了哪个 `On...Frame` 方法。
*   **QUIC 事件跟踪 (Event Tracing):** Chromium 内部有 QUIC 事件跟踪机制，可以记录 QUIC 连接的各种事件，包括接收到的帧。通过查看这些跟踪信息，可以了解代码的执行路径。
*   **日志输出 (Logging):**  代码中使用了 `QUIC_DLOG` 等宏进行日志输出。可以在编译 Chromium 时开启 QUIC 相关的日志，以便在运行时查看详细的执行信息。
*   **断点调试 (Breakpoints):**  可以在 `On...Frame` 方法中设置断点，当接收到相应的帧时，程序会暂停执行，可以查看当时的连接状态和变量值，帮助理解代码的执行逻辑。

**第 3 部分功能归纳：**

这段代码是 `QuicConnection` 类中负责处理接收到的各种 QUIC 控制帧的核心部分。它根据接收到的帧类型执行相应的操作，包括路径验证、连接管理、流控制、连接 ID 管理、错误处理等。它是 QUIC 连接状态维护和正确运行的关键组成部分。 这部分代码主要关注对等方发送来的控制信息，并根据这些信息更新本地连接状态或采取相应的行动。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共10部分，请归纳一下它的功能

"""
me) {
  QUIC_BUG_IF(quic_bug_10511_8, !connected_)
      << "Processing PATH_CHALLENGE frame when connection is closed. Received "
         "packet info: "
      << last_received_packet_info_;
  if (has_path_challenge_in_current_packet_) {
    // Only respond to the 1st PATH_CHALLENGE in the packet.
    return true;
  }
  should_proactively_validate_peer_address_on_path_challenge_ = false;
  // UpdatePacketContent() may start reverse path validation.
  if (!UpdatePacketContent(PATH_CHALLENGE_FRAME)) {
    return false;
  }
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnPathChallengeFrame(frame);
  }
  // On the server side, send response to the source address of the current
  // incoming packet according to RFC9000.
  // On the client side, send response to the default peer address which
  // should be on an existing path with a pre-assigned a destination CID.
  const QuicSocketAddress effective_peer_address_to_respond =
      perspective_ == Perspective::IS_CLIENT
          ? effective_peer_address()
          : GetEffectivePeerAddressFromCurrentPacket();
  const QuicSocketAddress direct_peer_address_to_respond =
      perspective_ == Perspective::IS_CLIENT
          ? direct_peer_address_
          : last_received_packet_info_.source_address;
  QuicConnectionId client_cid, server_cid;
  FindOnPathConnectionIds(last_received_packet_info_.destination_address,
                          effective_peer_address_to_respond, &client_cid,
                          &server_cid);
  {
    QuicPacketCreator::ScopedPeerAddressContext context(
        &packet_creator_, direct_peer_address_to_respond, client_cid,
        server_cid);
    if (should_proactively_validate_peer_address_on_path_challenge_) {
      // Conditions to proactively validate peer address:
      // The perspective is server
      // The PATH_CHALLENGE is received on an unvalidated alternative path.
      // The connection isn't validating migrated peer address, which is of
      // higher prority.
      QUIC_DVLOG(1) << "Proactively validate the effective peer address "
                    << effective_peer_address_to_respond;
      QUIC_CODE_COUNT_N(quic_kick_off_client_address_validation, 2, 6);
      ValidatePath(
          std::make_unique<ReversePathValidationContext>(
              default_path_.self_address, direct_peer_address_to_respond,
              effective_peer_address_to_respond, this),
          std::make_unique<ReversePathValidationResultDelegate>(this,
                                                                peer_address()),
          PathValidationReason::kReversePathValidation);
    }
    has_path_challenge_in_current_packet_ = true;
    MaybeUpdateAckTimeout();
    // Queue or send PATH_RESPONSE.
    if (!SendPathResponse(frame.data_buffer, direct_peer_address_to_respond,
                          effective_peer_address_to_respond)) {
      QUIC_CODE_COUNT(quic_failed_to_send_path_response);
    }
    // TODO(b/150095588): change the stats to
    // num_valid_path_challenge_received.
    ++stats_.num_connectivity_probing_received;

    // Flushing packet creator might cause connection to be closed.
  }
  return connected_;
}

bool QuicConnection::OnPathResponseFrame(const QuicPathResponseFrame& frame) {
  QUIC_BUG_IF(quic_bug_10511_9, !connected_)
      << "Processing PATH_RESPONSE frame when connection is closed. Received "
         "packet info: "
      << last_received_packet_info_;
  ++stats_.num_path_response_received;
  if (!UpdatePacketContent(PATH_RESPONSE_FRAME)) {
    return false;
  }
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnPathResponseFrame(frame);
  }
  MaybeUpdateAckTimeout();
  path_validator_.OnPathResponse(
      frame.data_buffer, last_received_packet_info_.destination_address);
  return connected_;
}

bool QuicConnection::OnConnectionCloseFrame(
    const QuicConnectionCloseFrame& frame) {
  QUIC_BUG_IF(quic_bug_10511_10, !connected_)
      << "Processing CONNECTION_CLOSE frame when connection is closed. "
         "Received packet info: "
      << last_received_packet_info_;

  // Since a connection close frame was received, this is not a connectivity
  // probe. A probe only contains a PING and full padding.
  if (!UpdatePacketContent(CONNECTION_CLOSE_FRAME)) {
    return false;
  }

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnConnectionCloseFrame(frame);
  }
  switch (frame.close_type) {
    case GOOGLE_QUIC_CONNECTION_CLOSE:
      QUIC_DLOG(INFO) << ENDPOINT << "Received ConnectionClose for connection: "
                      << connection_id() << ", with error: "
                      << QuicErrorCodeToString(frame.quic_error_code) << " ("
                      << frame.error_details << ")";
      break;
    case IETF_QUIC_TRANSPORT_CONNECTION_CLOSE:
      QUIC_DLOG(INFO) << ENDPOINT
                      << "Received Transport ConnectionClose for connection: "
                      << connection_id() << ", with error: "
                      << QuicErrorCodeToString(frame.quic_error_code) << " ("
                      << frame.error_details << ")"
                      << ", transport error code: "
                      << QuicIetfTransportErrorCodeString(
                             static_cast<QuicIetfTransportErrorCodes>(
                                 frame.wire_error_code))
                      << ", error frame type: "
                      << frame.transport_close_frame_type;
      break;
    case IETF_QUIC_APPLICATION_CONNECTION_CLOSE:
      QUIC_DLOG(INFO) << ENDPOINT
                      << "Received Application ConnectionClose for connection: "
                      << connection_id() << ", with error: "
                      << QuicErrorCodeToString(frame.quic_error_code) << " ("
                      << frame.error_details << ")"
                      << ", application error code: " << frame.wire_error_code;
      break;
  }

  if (frame.quic_error_code == QUIC_BAD_MULTIPATH_FLAG) {
    QUIC_LOG_FIRST_N(ERROR, 10)
        << "Unexpected QUIC_BAD_MULTIPATH_FLAG error."
        << " last_received_header: " << last_received_packet_info_.header
        << " encryption_level: " << encryption_level_;
  }
  TearDownLocalConnectionState(frame, ConnectionCloseSource::FROM_PEER);
  return connected_;
}

bool QuicConnection::OnMaxStreamsFrame(const QuicMaxStreamsFrame& frame) {
  QUIC_BUG_IF(quic_bug_12714_13, !connected_)
      << "Processing MAX_STREAMS frame when connection is closed. Received "
         "packet info: "
      << last_received_packet_info_;
  if (!UpdatePacketContent(MAX_STREAMS_FRAME)) {
    return false;
  }

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnMaxStreamsFrame(frame);
  }
  MaybeUpdateAckTimeout();
  return visitor_->OnMaxStreamsFrame(frame) && connected_;
}

bool QuicConnection::OnStreamsBlockedFrame(
    const QuicStreamsBlockedFrame& frame) {
  QUIC_BUG_IF(quic_bug_10511_11, !connected_)
      << "Processing STREAMS_BLOCKED frame when connection is closed. Received "
         "packet info: "
      << last_received_packet_info_;
  if (!UpdatePacketContent(STREAMS_BLOCKED_FRAME)) {
    return false;
  }

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnStreamsBlockedFrame(frame);
  }
  MaybeUpdateAckTimeout();
  return visitor_->OnStreamsBlockedFrame(frame) && connected_;
}

bool QuicConnection::OnGoAwayFrame(const QuicGoAwayFrame& frame) {
  QUIC_BUG_IF(quic_bug_12714_14, !connected_)
      << "Processing GOAWAY frame when connection is closed. Received packet "
         "info: "
      << last_received_packet_info_;

  // Since a go away frame was received, this is not a connectivity probe.
  // A probe only contains a PING and full padding.
  if (!UpdatePacketContent(GOAWAY_FRAME)) {
    return false;
  }

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnGoAwayFrame(frame);
  }
  QUIC_DLOG(INFO) << ENDPOINT << "GOAWAY_FRAME received with last good stream: "
                  << frame.last_good_stream_id
                  << " and error: " << QuicErrorCodeToString(frame.error_code)
                  << " and reason: " << frame.reason_phrase;
  MaybeUpdateAckTimeout();
  visitor_->OnGoAway(frame);
  return connected_;
}

bool QuicConnection::OnWindowUpdateFrame(const QuicWindowUpdateFrame& frame) {
  QUIC_BUG_IF(quic_bug_10511_12, !connected_)
      << "Processing WINDOW_UPDATE frame when connection is closed. Received "
         "packet info: "
      << last_received_packet_info_;

  // Since a window update frame was received, this is not a connectivity probe.
  // A probe only contains a PING and full padding.
  if (!UpdatePacketContent(WINDOW_UPDATE_FRAME)) {
    return false;
  }

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnWindowUpdateFrame(
        frame, idle_network_detector_.time_of_last_received_packet());
  }
  QUIC_DVLOG(1) << ENDPOINT << "WINDOW_UPDATE_FRAME received " << frame;
  MaybeUpdateAckTimeout();
  visitor_->OnWindowUpdateFrame(frame);
  return connected_;
}

void QuicConnection::OnClientConnectionIdAvailable() {
  QUICHE_DCHECK(perspective_ == Perspective::IS_SERVER);
  if (!peer_issued_cid_manager_->HasUnusedConnectionId()) {
    return;
  }
  if (default_path_.client_connection_id.IsEmpty()) {
    const QuicConnectionIdData* unused_cid_data =
        peer_issued_cid_manager_->ConsumeOneUnusedConnectionId();
    QUIC_DVLOG(1) << ENDPOINT << "Patch connection ID "
                  << unused_cid_data->connection_id << " to default path";
    default_path_.client_connection_id = unused_cid_data->connection_id;
    default_path_.stateless_reset_token =
        unused_cid_data->stateless_reset_token;
    QUICHE_DCHECK(!packet_creator_.HasPendingFrames());
    QUICHE_DCHECK(packet_creator_.GetDestinationConnectionId().IsEmpty());
    packet_creator_.SetClientConnectionId(default_path_.client_connection_id);
    return;
  }
  if (alternative_path_.peer_address.IsInitialized() &&
      alternative_path_.client_connection_id.IsEmpty()) {
    const QuicConnectionIdData* unused_cid_data =
        peer_issued_cid_manager_->ConsumeOneUnusedConnectionId();
    QUIC_DVLOG(1) << ENDPOINT << "Patch connection ID "
                  << unused_cid_data->connection_id << " to alternative path";
    alternative_path_.client_connection_id = unused_cid_data->connection_id;
    alternative_path_.stateless_reset_token =
        unused_cid_data->stateless_reset_token;
  }
}

NewConnectionIdResult QuicConnection::OnNewConnectionIdFrameInner(
    const QuicNewConnectionIdFrame& frame) {
  if (peer_issued_cid_manager_ == nullptr) {
    CloseConnection(
        IETF_QUIC_PROTOCOL_VIOLATION,
        "Receives NEW_CONNECTION_ID while peer uses zero length connection ID",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return NewConnectionIdResult::kProtocolViolation;
  }
  std::string error_detail;
  bool duplicate_new_connection_id = false;
  QuicErrorCode error = peer_issued_cid_manager_->OnNewConnectionIdFrame(
      frame, &error_detail, &duplicate_new_connection_id);
  if (error != QUIC_NO_ERROR) {
    CloseConnection(error, error_detail,
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return NewConnectionIdResult::kProtocolViolation;
  }
  if (duplicate_new_connection_id) {
    return NewConnectionIdResult::kDuplicateFrame;
  }
  if (perspective_ == Perspective::IS_SERVER) {
    OnClientConnectionIdAvailable();
  }
  MaybeUpdateAckTimeout();
  return NewConnectionIdResult::kOk;
}

bool QuicConnection::OnNewConnectionIdFrame(
    const QuicNewConnectionIdFrame& frame) {
  QUICHE_DCHECK(version().HasIetfQuicFrames());
  QUIC_BUG_IF(quic_bug_10511_13, !connected_)
      << "Processing NEW_CONNECTION_ID frame when connection is closed. "
         "Received packet info: "
      << last_received_packet_info_;
  if (!UpdatePacketContent(NEW_CONNECTION_ID_FRAME)) {
    return false;
  }

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnNewConnectionIdFrame(frame);
  }

  NewConnectionIdResult result = OnNewConnectionIdFrameInner(frame);
  switch (result) {
    case NewConnectionIdResult::kOk:
      if (multi_port_stats_ != nullptr) {
        MaybeCreateMultiPortPath();
      }
      break;
    case NewConnectionIdResult::kProtocolViolation:
      return false;
    case NewConnectionIdResult::kDuplicateFrame:
      break;
  }
  return true;
}

bool QuicConnection::OnRetireConnectionIdFrame(
    const QuicRetireConnectionIdFrame& frame) {
  QUICHE_DCHECK(version().HasIetfQuicFrames());
  QUIC_BUG_IF(quic_bug_10511_14, !connected_)
      << "Processing RETIRE_CONNECTION_ID frame when connection is closed. "
         "Received packet info: "
      << last_received_packet_info_;
  if (!UpdatePacketContent(RETIRE_CONNECTION_ID_FRAME)) {
    return false;
  }

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnRetireConnectionIdFrame(frame);
  }
  if (self_issued_cid_manager_ == nullptr) {
    CloseConnection(
        IETF_QUIC_PROTOCOL_VIOLATION,
        "Receives RETIRE_CONNECTION_ID while new connection ID is never issued",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }
  std::string error_detail;
  QuicErrorCode error = self_issued_cid_manager_->OnRetireConnectionIdFrame(
      frame, sent_packet_manager_.GetPtoDelay(), &error_detail);
  if (error != QUIC_NO_ERROR) {
    CloseConnection(error, error_detail,
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }
  // Count successfully received RETIRE_CONNECTION_ID frames.
  MaybeUpdateAckTimeout();
  return true;
}

bool QuicConnection::OnNewTokenFrame(const QuicNewTokenFrame& frame) {
  QUIC_BUG_IF(quic_bug_12714_15, !connected_)
      << "Processing NEW_TOKEN frame when connection is closed. Received "
         "packet info: "
      << last_received_packet_info_;
  if (!UpdatePacketContent(NEW_TOKEN_FRAME)) {
    return false;
  }

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnNewTokenFrame(frame);
  }
  if (perspective_ == Perspective::IS_SERVER) {
    CloseConnection(QUIC_INVALID_NEW_TOKEN, "Server received new token frame.",
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }
  // NEW_TOKEN frame should insitgate ACKs.
  MaybeUpdateAckTimeout();
  visitor_->OnNewTokenReceived(frame.token);
  return true;
}

bool QuicConnection::OnMessageFrame(const QuicMessageFrame& frame) {
  QUIC_BUG_IF(quic_bug_12714_16, !connected_)
      << "Processing MESSAGE frame when connection is closed. Received packet "
         "info: "
      << last_received_packet_info_;

  // Since a message frame was received, this is not a connectivity probe.
  // A probe only contains a PING and full padding.
  if (!UpdatePacketContent(MESSAGE_FRAME)) {
    return false;
  }

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnMessageFrame(frame);
  }
  MaybeUpdateAckTimeout();
  visitor_->OnMessageReceived(
      absl::string_view(frame.data, frame.message_length));
  return connected_;
}

bool QuicConnection::OnHandshakeDoneFrame(const QuicHandshakeDoneFrame& frame) {
  QUIC_BUG_IF(quic_bug_10511_15, !connected_)
      << "Processing HANDSHAKE_DONE frame when connection "
         "is closed. Received packet "
         "info: "
      << last_received_packet_info_;
  if (!version().UsesTls()) {
    CloseConnection(IETF_QUIC_PROTOCOL_VIOLATION,
                    "Handshake done frame is unsupported",
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }

  if (perspective_ == Perspective::IS_SERVER) {
    CloseConnection(IETF_QUIC_PROTOCOL_VIOLATION,
                    "Server received handshake done frame.",
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }

  // Since a handshake done frame was received, this is not a connectivity
  // probe. A probe only contains a PING and full padding.
  if (!UpdatePacketContent(HANDSHAKE_DONE_FRAME)) {
    return false;
  }

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnHandshakeDoneFrame(frame);
  }
  MaybeUpdateAckTimeout();
  visitor_->OnHandshakeDoneReceived();
  return connected_;
}

bool QuicConnection::OnAckFrequencyFrame(const QuicAckFrequencyFrame& frame) {
  QUIC_BUG_IF(quic_bug_10511_16, !connected_)
      << "Processing ACK_FREQUENCY frame when connection "
         "is closed. Received packet "
         "info: "
      << last_received_packet_info_;
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnAckFrequencyFrame(frame);
  }
  if (!UpdatePacketContent(ACK_FREQUENCY_FRAME)) {
    return false;
  }

  if (!can_receive_ack_frequency_frame_) {
    QUIC_LOG_EVERY_N_SEC(ERROR, 120) << "Get unexpected AckFrequencyFrame.";
    return false;
  }
  if (auto packet_number_space =
          QuicUtils::GetPacketNumberSpace(
              last_received_packet_info_.decrypted_level) == APPLICATION_DATA) {
    uber_received_packet_manager_.OnAckFrequencyFrame(frame);
  } else {
    QUIC_LOG_EVERY_N_SEC(ERROR, 120)
        << "Get AckFrequencyFrame in packet number space "
        << packet_number_space;
  }
  MaybeUpdateAckTimeout();
  return true;
}

bool QuicConnection::OnResetStreamAtFrame(const QuicResetStreamAtFrame& frame) {
  QUIC_BUG_IF(OnResetStreamAtFrame_connection_closed, !connected_)
      << "Processing RESET_STREAM_AT frame while the connection is closed. "
         "Received packet info: "
      << last_received_packet_info_;

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnResetStreamAtFrame(frame);
  }
  if (!UpdatePacketContent(RESET_STREAM_AT_FRAME)) {
    return false;
  }
  if (!framer_.process_reset_stream_at()) {
    CloseConnection(IETF_QUIC_PROTOCOL_VIOLATION,
                    "Received RESET_STREAM_AT while not negotiated.",
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }

  MaybeUpdateAckTimeout();
  visitor_->OnResetStreamAt(frame);
  return true;
}

bool QuicConnection::OnBlockedFrame(const QuicBlockedFrame& frame) {
  QUIC_BUG_IF(quic_bug_12714_17, !connected_)
      << "Processing BLOCKED frame when connection is closed. Received packet "
         "info: "
      << last_received_packet_info_;

  // Since a blocked frame was received, this is not a connectivity probe.
  // A probe only contains a PING and full padding.
  if (!UpdatePacketContent(BLOCKED_FRAME)) {
    return false;
  }

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnBlockedFrame(frame);
  }
  QUIC_DLOG(INFO) << ENDPOINT
                  << "BLOCKED_FRAME received for stream: " << frame.stream_id;
  MaybeUpdateAckTimeout();
  visitor_->OnBlockedFrame(frame);
  stats_.blocked_frames_received++;
  return connected_;
}

void QuicConnection::OnPacketComplete() {
  // Don't do anything if this packet closed the connection.
  if (!connected_) {
    ClearLastFrames();
    return;
  }

  if (IsCurrentPacketConnectivityProbing()) {
    QUICHE_DCHECK(!version().HasIetfQuicFrames() && !ignore_gquic_probing_);
    ++stats_.num_connectivity_probing_received;
  }

  QUIC_DVLOG(1) << ENDPOINT << "Got"
                << (SupportsMultiplePacketNumberSpaces()
                        ? (" " +
                           EncryptionLevelToString(
                               last_received_packet_info_.decrypted_level))
                        : "")
                << " packet " << last_received_packet_info_.header.packet_number
                << " for "
                << GetServerConnectionIdAsRecipient(
                       last_received_packet_info_.header, perspective_);

  QUIC_DLOG_IF(INFO, current_packet_content_ == SECOND_FRAME_IS_PADDING)
      << ENDPOINT << "Received a padded PING packet. is_probing: "
      << IsCurrentPacketConnectivityProbing();

  if (!version().HasIetfQuicFrames() && !ignore_gquic_probing_) {
    MaybeRespondToConnectivityProbingOrMigration();
  }

  current_effective_peer_migration_type_ = NO_CHANGE;

  // For IETF QUIC, it is guaranteed that TLS will give connection the
  // corresponding write key before read key. In other words, connection should
  // never process a packet while an ACK for it cannot be encrypted.
  if (!should_last_packet_instigate_acks_) {
    uber_received_packet_manager_.MaybeUpdateAckTimeout(
        should_last_packet_instigate_acks_,
        last_received_packet_info_.decrypted_level,
        last_received_packet_info_.header.packet_number,
        last_received_packet_info_.receipt_time, clock_->ApproximateNow(),
        sent_packet_manager_.GetRttStats());
  }

  ClearLastFrames();
  CloseIfTooManyOutstandingSentPackets();
}

void QuicConnection::MaybeRespondToConnectivityProbingOrMigration() {
  QUICHE_DCHECK(!version().HasIetfQuicFrames());
  if (IsCurrentPacketConnectivityProbing()) {
    visitor_->OnPacketReceived(last_received_packet_info_.destination_address,
                               last_received_packet_info_.source_address,
                               /*is_connectivity_probe=*/true);
    return;
  }
  if (perspective_ == Perspective::IS_CLIENT) {
    // This node is a client, notify that a speculative connectivity probing
    // packet has been received anyway.
    QUIC_DVLOG(1) << ENDPOINT
                  << "Received a speculative connectivity probing packet for "
                  << GetServerConnectionIdAsRecipient(
                         last_received_packet_info_.header, perspective_)
                  << " from ip:port: "
                  << last_received_packet_info_.source_address.ToString()
                  << " to ip:port: "
                  << last_received_packet_info_.destination_address.ToString();
    visitor_->OnPacketReceived(last_received_packet_info_.destination_address,
                               last_received_packet_info_.source_address,
                               /*is_connectivity_probe=*/false);
    return;
  }
}

bool QuicConnection::IsValidStatelessResetToken(
    const StatelessResetToken& token) const {
  QUICHE_DCHECK_EQ(perspective_, Perspective::IS_CLIENT);
  return default_path_.stateless_reset_token.has_value() &&
         QuicUtils::AreStatelessResetTokensEqual(
             token, *default_path_.stateless_reset_token);
}

void QuicConnection::OnAuthenticatedIetfStatelessResetPacket(
    const QuicIetfStatelessResetPacket& /*packet*/) {
  // TODO(fayang): Add OnAuthenticatedIetfStatelessResetPacket to
  // debug_visitor_.
  QUICHE_DCHECK_EQ(perspective_, Perspective::IS_CLIENT);

  if (!IsDefaultPath(last_received_packet_info_.destination_address,
                     last_received_packet_info_.source_address)) {
    // This packet is received on a probing path. Do not close connection.
    if (IsAlternativePath(last_received_packet_info_.destination_address,
                          GetEffectivePeerAddressFromCurrentPacket())) {
      QUIC_BUG_IF(quic_bug_12714_18, alternative_path_.validated)
          << "STATELESS_RESET received on alternate path after it's "
             "validated.";
      path_validator_.CancelPathValidation();
      ++stats_.num_stateless_resets_on_alternate_path;
    } else {
      QUIC_BUG(quic_bug_10511_17)
          << "Received Stateless Reset on unknown socket.";
    }
    return;
  }

  const std::string error_details = "Received stateless reset.";
  QUIC_CODE_COUNT(quic_tear_down_local_connection_on_stateless_reset);
  TearDownLocalConnectionState(QUIC_PUBLIC_RESET, NO_IETF_QUIC_ERROR,
                               error_details, ConnectionCloseSource::FROM_PEER);
}

void QuicConnection::OnKeyUpdate(KeyUpdateReason reason) {
  QUICHE_DCHECK(support_key_update_for_connection_);
  QUIC_DLOG(INFO) << ENDPOINT << "Key phase updated for " << reason;

  lowest_packet_sent_in_current_key_phase_.Clear();
  stats_.key_update_count++;

  // If another key update triggers while the previous
  // discard_previous_one_rtt_keys_alarm_ hasn't fired yet, cancel it since the
  // old keys would already be discarded.
  discard_previous_one_rtt_keys_alarm().Cancel();

  visitor_->OnKeyUpdate(reason);
}

void QuicConnection::OnDecryptedFirstPacketInKeyPhase() {
  QUIC_DLOG(INFO) << ENDPOINT << "OnDecryptedFirstPacketInKeyPhase";
  // An endpoint SHOULD retain old read keys for no more than three times the
  // PTO after having received a packet protected using the new keys. After this
  // period, old read keys and their corresponding secrets SHOULD be discarded.
  //
  // Note that this will cause an unnecessary
  // discard_previous_one_rtt_keys_alarm_ on the first packet in the 1RTT
  // encryption level, but this is harmless.
  discard_previous_one_rtt_keys_alarm().Set(
      clock_->ApproximateNow() + sent_packet_manager_.GetPtoDelay() * 3);
}

std::unique_ptr<QuicDecrypter>
QuicConnection::AdvanceKeysAndCreateCurrentOneRttDecrypter() {
  QUIC_DLOG(INFO) << ENDPOINT << "AdvanceKeysAndCreateCurrentOneRttDecrypter";
  return visitor_->AdvanceKeysAndCreateCurrentOneRttDecrypter();
}

std::unique_ptr<QuicEncrypter> QuicConnection::CreateCurrentOneRttEncrypter() {
  QUIC_DLOG(INFO) << ENDPOINT << "CreateCurrentOneRttEncrypter";
  return visitor_->CreateCurrentOneRttEncrypter();
}

void QuicConnection::ClearLastFrames() {
  should_last_packet_instigate_acks_ = false;
}

void QuicConnection::CloseIfTooManyOutstandingSentPackets() {
  // This occurs if we don't discard old packets we've seen fast enough. It's
  // possible largest observed is less than leaset unacked.
  const bool should_close =
      sent_packet_manager_.GetLargestSentPacket().IsInitialized() &&
      sent_packet_manager_.GetLargestSentPacket() >
          sent_packet_manager_.GetLeastUnacked() + max_tracked_packets_;

  if (should_close) {
    CloseConnection(
        QUIC_TOO_MANY_OUTSTANDING_SENT_PACKETS,
        absl::StrCat("More than ", max_tracked_packets_,
                     " outstanding, least_unacked: ",
                     sent_packet_manager_.GetLeastUnacked().ToUint64(),
                     ", packets_processed: ", stats_.packets_processed,
                     ", last_decrypted_packet_level: ",
                     EncryptionLevelToString(
                         last_received_packet_info_.decrypted_level)),
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  }
}

const QuicFrame QuicConnection::GetUpdatedAckFrame() {
  QUICHE_DCHECK(!uber_received_packet_manager_.IsAckFrameEmpty(
      QuicUtils::GetPacketNumberSpace(encryption_level_)))
      << "Try to retrieve an empty ACK frame";
  return uber_received_packet_manager_.GetUpdatedAckFrame(
      QuicUtils::GetPacketNumberSpace(encryption_level_),
      clock_->ApproximateNow());
}

QuicPacketNumber QuicConnection::GetLeastUnacked() const {
  return sent_packet_manager_.GetLeastUnacked();
}

bool QuicConnection::HandleWriteBlocked() {
  if (!writer_->IsWriteBlocked()) {
    return false;
  }

  visitor_->OnWriteBlocked();
  return true;
}

void QuicConnection::MaybeSendInResponseToPacket() {
  if (!connected_) {
    return;
  }

  if (IsMissingDestinationConnectionID()) {
    return;
  }

  // If the writer is blocked, don't attempt to send packets now or in the send
  // alarm. When the writer unblocks, OnCanWrite() will be called for this
  // connection to send.
  if (HandleWriteBlocked()) {
    return;
  }

  if (!defer_send_in_response_to_packets_) {
    WriteIfNotBlocked();
    return;
  }

  if (!visitor_->WillingAndAbleToWrite()) {
    QUIC_DVLOG(1)
        << "No send alarm after processing packet. !WillingAndAbleToWrite.";
    return;
  }

  // If the send alarm is already armed. Record its deadline in |max_deadline|
  // and cancel the alarm temporarily. The rest of this function will ensure
  // the alarm deadline is no later than |max_deadline| when the function exits.
  QuicTime max_deadline = QuicTime::Infinite();
  if (send_alarm().IsSet()) {
    QUIC_DVLOG(1) << "Send alarm already set to " << send_alarm().deadline();
    max_deadline = send_alarm().deadline();
    send_alarm().Cancel();
  }

  if (CanWrite(HAS_RETRANSMITTABLE_DATA)) {
    // Some data can be written immediately. Register for immediate resumption
    // so we'll keep writing after other connections.
    QUIC_BUG_IF(quic_send_alarm_set_with_data_to_send, send_alarm().IsSet());
    QUIC_DVLOG(1) << "Immediate send alarm scheduled after processing packet.";
    send_alarm().Set(clock_->ApproximateNow() +
                     sent_packet_manager_.GetDeferredSendAlarmDelay());
    return;
  }

  if (send_alarm().IsSet()) {
    // Pacing limited: CanWrite returned false, and it has scheduled a send
    // alarm before it returns.
    if (send_alarm().deadline() > max_deadline) {
      QUIC_DVLOG(1)
          << "Send alarm restored after processing packet. previous deadline:"
          << max_deadline
          << ", deadline from CanWrite:" << send_alarm().deadline();
      // Restore to the previous, earlier deadline.
      send_alarm().Update(max_deadline, QuicTime::Delta::Zero());
    } else {
      QUIC_DVLOG(1) << "Future send alarm scheduled after processing packet.";
    }
    return;
  }

  if (max_deadline != QuicTime::Infinite()) {
    QUIC_DVLOG(1) << "Send alarm restored after processing packet.";
    send_alarm().Set(max_deadline);
    return;
  }
  // Can not send data due to other reasons: congestion blocked, anti
  // amplification throttled, etc.
  QUIC_DVLOG(1) << "No send alarm after processing packet. Other reasons.";
}

size_t QuicConnection::SendCryptoData(EncryptionLevel level,
                                      size_t write_length,
                                      QuicStreamOffset offset) {
  if (write_length == 0) {
    QUIC_BUG(quic_bug_10511_18) << "Attempt to send empty crypto frame";
    return 0;
  }
  ScopedPacketFlusher flusher(this);
  return packet_creator_.ConsumeCryptoData(level, write_length, offset);
}

QuicConsumedData QuicConnection::SendStreamData(QuicStreamId id,
                                                size_t write_length,
                                                QuicStreamOffset offset,
                                                StreamSendingState state) {
  if (state == NO_FIN && write_length == 0) {
    QUIC_BUG(quic_bug_10511_19) << "Attempt to send empty stream frame";
    return QuicConsumedData(0, false);
  }

  if (perspective_ == Perspective::IS_SERVER &&
      version().CanSendCoalescedPackets() && !IsHandshakeConfirmed()) {
    if (in_probe_time_out_ && coalesced_packet_.NumberOfPackets() == 0u) {
      // PTO fires while handshake is not confirmed. Do not preempt handshake
      // data with stream data.
      QUIC_CODE_COUNT(quic_try_to_send_half_rtt_data_when_pto_fires);
      return QuicConsumedData(0, false);
    }
    if (coalesced_packet_.ContainsPacketOfEncryptionLevel(ENCRYPTION_INITIAL) &&
        coalesced_packet_.NumberOfPackets() == 1u) {
      // Handshake is not confirmed yet, if there is only an initial packet in
      // the coalescer, try to bundle an ENCRYPTION_HANDSHAKE packet before
      // sending stream data.
      sent_packet_manager_.RetransmitDataOfSpaceIfAny(HANDSHAKE_DATA);
    }
  }
  // Opportunistically bundle an ack with every outgoing packet.
  // Particularly, we want to bundle with handshake packets since we don't
  // know which decrypter will be used on an ack packet following a handshake
  // packet (a handshake packet from client to server could result in a REJ or
  // a SHLO from the server, leading to two different decrypters at the
  // server.)
  ScopedPacketFlusher flusher(this);
  return packet_creator_.ConsumeData(id, write_length, offset, state);
}

bool QuicConnection::SendControlFrame(const QuicFrame& frame) {
  if (SupportsMultiplePacketNumberSpaces() &&
      (encryption_level_ == ENCRYPTION_INITIAL ||
       encryption_level_ == ENCRYPTION_HANDSHAKE) &&
      frame.type != PING_FRAME) {
    // Allow PING frame to be sent without APPLICATION key. For example, when
    // anti-amplification limit is used, client needs to send something to avoid
    // handshake deadlock.
    QUIC_DVLOG(1) << ENDPOINT << "Failed to send control frame: " << frame
                  << " at encryption level: " << encryption_level_;
    return false;
  }
  ScopedPacketFlusher flusher(this);
  const bool consumed =
      packet_creator_.ConsumeRetransmittableControlFrame(frame);
  if (!consumed) {
    QUIC_DVLOG(1) << ENDPOINT << "Failed to send control frame: " << frame;
    return false;
  }
  if (frame.type == PING_FRAME) {
    // Flush PING frame immediately.
    packet_creator_.FlushCurrentPacket();
    stats_.ping_frames_sent++;
    if (debug_visitor_ != nullptr) {
      debug_visitor_->OnPingSent();
    }
  }
  if (frame.type == BLOCKED_FRAME) {
    stats_.blocked_frames_sent++;
  }
  return true;
}

vo
"""


```