Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `QuicSession` class in Chromium's network stack. I need to identify the main tasks this code performs related to managing QUIC streams, handling flow control, and interaction with the underlying `QuicConnection`. I should also look for connections to JavaScript, though based on the nature of this code, those will likely be indirect.

Here's a breakdown of the code's functionality:

1. **Determining if the session can write data:** The `CanWrite()` method checks various conditions like whether retransmissions are pending, if the flow controller is blocked (with special handling for crypto/header streams), and if any data streams are blocked.

2. **Logging stream information:**  `GetStreamsInfoForLogging()` collects and formats information about active, pending, and draining streams, including creation time, bytes written/read, and FIN status. This is primarily for debugging and monitoring.

3. **Checking for pending handshake:** `HasPendingHandshake()` determines if there are outstanding crypto retransmissions or buffered crypto frames, crucial for ensuring secure communication.

4. **Processing UDP packets:** `ProcessUdpPacket()` passes incoming UDP packets to the underlying `QuicConnection` for handling.

5. **Formatting connection close information:** `on_closed_frame_string()` generates a string representation of the reason for connection closure.

6. **Writing stream data:** `WritevData()` is the core function for sending data on a stream. It enforces encryption requirements and interacts with the `QuicConnection` to actually send the data. It also updates the `write_blocked_streams_` structure.

7. **Sending crypto data:** `SendCryptoData()` is specifically for sending handshake data, ensuring the correct encryption level is used.

8. **Handling control frame errors:** `OnControlFrameManagerError()` closes the connection if there's an issue with control frame management.

9. **Writing control frames:** `WriteControlFrame()` sends various control frames (like `RST_STREAM`, `WINDOW_UPDATE`) after ensuring encryption is established.

10. **Resetting streams:** `ResetStream()` handles stream resets, potentially sending `RST_STREAM` or `STOP_SENDING` frames.

11. **Sending `GOAWAY` frames:** `SendGoAway()` (for older QUIC versions) signals the impending closure of the connection to the peer.

12. **Sending `BLOCKED` and `WINDOW_UPDATE` frames:** These methods facilitate flow control by informing the peer of blocking conditions and available receive window space.

13. **Handling stream errors:** `OnStreamError()` closes the connection due to a stream-level error.

14. **Managing maximum streams:** `CanSendMaxStreams()` and `SendMaxStreams()` relate to advertising the maximum number of streams the endpoint can handle.

15. **Tracking closed streams:** `InsertLocallyClosedStreamsHighestOffset()` and `OnStreamClosed()` manage the lifecycle of streams, including tracking final byte offsets for flow control accounting and informing the stream ID manager. `ClosePendingStream()` handles closing streams that are in a pending state. `ShouldProcessFrameByPendingStream` determines if a frame should be processed by a pending stream.

16. **Handling final byte offsets:** `OnFinalByteOffsetReceived()` updates connection-level flow control when a stream's final offset is received.

17. **Checking encryption status:** `IsEncryptionEstablished()` and `OneRttKeysAvailable()` check the status of the encryption handshake.

18. **Handling config negotiation:** `OnConfigNegotiated()` is called after the QUIC configuration is negotiated, setting various parameters and potentially informing streams of new flow control limits.

19. **Handling ALPS data:** `OnAlpsData()` is a hook for application-layer protocol settings (currently returns nullopt).

20. **Adjusting initial flow control windows:** `AdjustInitialFlowControlWindows()` allows the server to modify the initial flow control settings.

21. **Handling frames on nonexistent streams:** `HandleFrameOnNonexistentOutgoingStream()` and `HandleRstOnValidNonexistentStream()` deal with receiving frames for streams that are not currently active.

22. **Handling stream flow control updates:** `OnNewStreamFlowControlWindow()`, `OnNewStreamUnidirectionalFlowControlWindow()`, and `OnNewStreamOutgoingBidirectionalFlowControlWindow()` process updates to the peer's send flow control window for different stream types.

**Relationship to JavaScript:**

The connection to JavaScript is indirect. This C++ code is part of the Chromium browser's networking stack. JavaScript running in a web page interacts with the browser's APIs (like `fetch` or WebSockets) to make network requests. These APIs eventually utilize the underlying networking stack, including this `QuicSession` code, to establish and manage QUIC connections.

* **Example:** A JavaScript `fetch()` call to a server that supports QUIC will eventually lead to the creation of a `QuicSession` object. When the JavaScript code sends data using the `fetch()` API, that data will be passed down through the browser's layers and eventually handled by the `WritevData()` function in this C++ code.

**Hypothetical Input and Output (for a single function):**

Let's take `CanWrite()` as an example:

**Input (Assumptions):**

* `ding_retransmission_` is empty (no pending retransmissions).
* `flow_controller_.IsBlocked()` returns `true` (connection-level flow control is blocking).
* `VersionUsesHttp3(transport_version())` returns `false` (not using HTTP/3).
* `write_blocked_streams_->HasWriteBlockedSpecialStream()` returns `true` (crypto or header stream is blocked).

**Output:**

* `CanWrite()` will return `true`.

**User/Programming Errors:**

* **Writing data before encryption is established:**  The `WritevData()` function explicitly checks for this. If a developer attempts to send application data before the QUIC handshake is complete, the data will not be sent, and the stream will likely become write-blocked. This can lead to hangs or unexpected behavior if the developer doesn't handle the write-blocked state correctly.
* **Incorrectly handling flow control:**  If the application layer sends more data than the peer's flow control window allows, the `QuicSession` will handle the blocking, but the application needs to be aware of this and potentially pause sending. Ignoring flow control can lead to connection errors.
* **Attempting to reset static streams:** The `ResetStream()` function includes a check to prevent resetting static streams, which are internally managed by QUIC. Trying to do so would be a programming error.

**User Operations as Debugging Clues:**

If a user reports a network issue, understanding the sequence of their actions can help pinpoint where things might be going wrong within the QUIC stack. For example:

1. **User opens a website:** This might initiate a QUIC connection. If the connection fails early, the issue could be in the handshake phase (related to `HasPendingHandshake()`).
2. **User interacts with a web page, sending data (e.g., submitting a form):** This would involve `WritevData()`. If data transmission stalls, it could be due to flow control blocking (`CanWrite()`, `flow_controller_.IsBlocked()`) or encryption not being established.
3. **User closes a tab or browser:** This would eventually lead to the `QuicSession` being closed, potentially triggering the sending of `GOAWAY` or `CONNECTION_CLOSE` frames. Examining the `on_closed_frame_string()` could provide clues about the reason for closure.
4. **User experiences slow loading or connection interruptions:** This could be related to retransmissions (`streams_with_pending_retransmission_` in `CanWrite()`) or flow control issues.

By tracing the user's actions, developers can examine logs and internal states of the `QuicSession` to identify the root cause of the problem.

**Summary of Functionality (Part 2):**

This part of the `QuicSession::cc` file focuses on the core mechanisms for **sending and managing data and control frames on QUIC streams**. It includes functions for:

* **Checking if the session is ready to send data**, taking into account retransmissions and flow control.
* **Gathering debugging information about the active streams.**
* **Writing data to streams**, enforcing encryption and handling flow control.
* **Sending QUIC control frames** like `RST_STREAM`, `STOP_SENDING`, `GOAWAY`, `BLOCKED`, and `WINDOW_UPDATE`.
* **Managing the lifecycle of QUIC streams**, including tracking closed streams and handling final byte offsets for accurate flow control accounting.
* **Handling the QUIC handshake process**, checking for pending handshake data and managing encryption state.
* **Processing incoming UDP packets** by delegating to the underlying `QuicConnection`.
* **Responding to stream and connection errors** by closing the connection.
* **Managing the maximum number of allowed streams.**
* **Handling configuration negotiation** and applying received parameters.
* **Processing updates to stream flow control windows.**

这是 `net/third_party/quiche/src/quiche/quic/core/quic_session.cc` 文件中部分代码的功能归纳。这部分代码主要负责 **管理 QUIC 会话中数据和控制帧的发送，以及维护连接的状态信息**。

**主要功能点包括：**

1. **判断会话是否可以写入数据 (`CanWrite`)**:
   - 检查是否有待处理的重传数据。
   - 检查连接级别的流量控制是否阻塞了发送。对于非 HTTP/3 连接，即使连接级别被阻塞，如果存在未被阻塞的特殊流（例如加密流或头部流），仍然可以写入。
   - 最终判断是否存在被阻塞的特殊流或数据流。

2. **获取流的信息用于日志记录 (`GetStreamsInfoForLogging`)**:
   - 记录活跃流的数量、待处理流的数量、正在排空的流的数量。
   - 记录最多 5 个流的详细信息，包括流 ID、创建延迟、已写入字节数、FIN 发送状态、是否有缓存数据、FIN 缓存状态、已读取字节数、FIN 接收状态。

3. **判断是否存在待处理的握手 (`HasPendingHandshake`)**:
   - 对于使用 Crypto 帧的版本，检查加密流是否有待处理的重传或缓存的加密帧。
   - 对于其他版本，检查加密流是否在待重传流列表中或被写入阻塞流列表阻塞。

4. **处理 UDP 数据包 (`ProcessUdpPacket`)**:
   - 将接收到的 UDP 数据包传递给底层的 `QuicConnection` 对象进行处理。

5. **获取连接关闭帧的字符串信息 (`on_closed_frame_string`)**:
   - 将连接关闭的原因和来源信息格式化为字符串。

6. **写入流数据 (`WritevData`)**:
   - 检查连接是否已断开，如果已断开则报错。
   - 检查加密是否已建立，如果未建立且不是加密流，则阻止写入。在 0-RTT 被拒绝且 1-RTT 密钥不可用时会抑制写入。
   - 设置传输类型，并使用指定的加密级别。
   - 调用底层的 `connection_->SendStreamData` 发送数据。
   - 如果是新的数据，则更新 `write_blocked_streams_` 中对应流的已写入字节数。

7. **发送加密数据 (`SendCryptoData`)**:
   - 仅适用于使用 Crypto 帧的版本。
   - 检查指定加密级别的密钥是否存在，如果不存在则关闭连接。
   - 设置传输类型，并使用指定的加密级别。
   - 调用底层的 `connection_->SendCryptoData` 发送数据。

8. **处理控制帧管理器错误 (`OnControlFrameManagerError`)**:
   - 当控制帧管理器发生错误时，关闭连接。

9. **写入控制帧 (`WriteControlFrame`)**:
   - 检查连接是否已断开，如果已断开则报错。
   - 检查加密是否已建立，如果未建立则不写入。
   - 设置传输类型，并使用获取应用数据发送的加密级别。
   - 调用底层的 `connection_->SendControlFrame` 发送控制帧。

10. **重置流 (`ResetStream`)**:
    - 如果尝试重置静态流，则关闭连接。
    - 如果流存在，则重置该流。
    - 否则，尝试发送 `STOP_SENDING` 帧和 `RST_STREAM` 帧。

11. **可能发送 RST_STREAM 帧 (`MaybeSendRstStreamFrame`)**:
    - 检查连接是否已连接。
    - 如果是旧版本 QUIC 或非单向读流，则将 `RST_STREAM` 帧写入或缓存到控制帧管理器。
    - 通知底层的 `connection_` 流已被重置。

12. **可能发送 STOP_SENDING 帧 (`MaybeSendStopSendingFrame`)**:
    - 检查连接是否已连接。
    - 如果是 IETF QUIC 且非单向写流，则将 `STOP_SENDING` 帧写入或缓存到控制帧管理器。

13. **发送 GOAWAY 帧 (`SendGoAway`)**:
    - `GOAWAY` 帧在 IETF QUIC 中不支持。
    - 如果加密未建立，则关闭连接。
    - 如果已发送过 `GOAWAY` 帧，则直接返回。
    - 将 `GOAWAY` 帧写入或缓存到控制帧管理器。

14. **发送 BLOCKED 帧 (`SendBlocked`)**:
    - 将 `BLOCKED` 帧写入或缓存到控制帧管理器。

15. **发送 WINDOW_UPDATE 帧 (`SendWindowUpdate`)**:
    - 将 `WINDOW_UPDATE` 帧写入或缓存到控制帧管理器。

16. **处理流错误 (`OnStreamError`)**:
    - 当发生流错误时，关闭连接。可以指定 IETF 传输层错误码。

17. **判断是否可以发送 MAX_STREAMS 帧 (`CanSendMaxStreams`)**:
    - 检查控制帧管理器中缓存的 `MAX_STREAMS` 帧的数量是否小于 2。

18. **发送 MAX_STREAMS 帧 (`SendMaxStreams`)**:
    - 检查配置是否已协商，如果未协商则报错。
    - 将 `MAX_STREAMS` 帧写入或缓存到控制帧管理器。

19. **插入本地关闭流的最高偏移量 (`InsertLocallyClosedStreamsHighestOffset`)**:
    - 记录本地关闭的流的最高偏移量，用于后续的流量控制计算。

20. **处理流关闭 (`OnStreamClosed`)**:
    - 从活跃流列表中移除已关闭的流。
    - 对于等待 ACK 的流，将其标记为僵尸流。
    - 对于非等待 ACK 的流，将其移动到已关闭流列表，并启动清理定时器。
    - 如果流未接收到最终偏移量，则记录其最高接收偏移量。
    - 如果流是正在排空的，则减少排空流计数器。
    - 通知流 ID 管理器流已关闭。
    - 如果连接仍然连接，并且是发起的流，则尝试创建新的外发流。

21. **关闭待处理的流 (`ClosePendingStream`)**:
    - 从待处理流列表中移除指定的流。
    - 如果连接仍然连接，则通知 IETF 流 ID 管理器流已关闭。

22. **判断是否应该由待处理流处理帧 (`ShouldProcessFrameByPendingStream`)**:
    - 检查流 ID 是否不在活跃流列表中，并且是否超过了每循环流限制或该帧类型允许由待处理流处理。

23. **接收到最终字节偏移量 (`OnFinalByteOffsetReceived`)**:
    - 当接收到本地关闭的流的最终字节偏移量时，更新连接级别的流量控制。如果违反了流量控制，则关闭连接。
    - 将接收到的字节添加到已消耗的字节数中。
    - 通知流 ID 管理器流已关闭。

24. **判断加密是否已建立 (`IsEncryptionEstablished`)**:
    - 检查加密流是否存在且已建立加密。

25. **判断 1-RTT 密钥是否可用 (`OneRttKeysAvailable`)**:
    - 检查加密流是否存在且 1-RTT 密钥可用。

26. **处理配置协商完成 (`OnConfigNegotiated`)**:
    - 应用协商的配置参数到 `connection_` 对象。
    - 对于 IETF QUIC，根据接收到的最大流数量限制，可能关闭连接。并更新 IETF 流 ID 管理器的最大外发流数量。
    - 对于旧版本 QUIC，更新流 ID 管理器的最大外发流数量。
    - 根据接收到的配置选项，调整初始的流量控制窗口大小。
    - 设置无状态重置令牌。
    - 更新 IETF 流 ID 管理器的最大内发流数量（如果使用 IETF QUIC）。
    - 更新旧版本 QUIC 流 ID 管理器的最大内发流数量。
    - 如果使用 TLS，则通知现有流新的流控限制。
    - 如果使用 Google QUIC Crypto，则通知现有流新的流控窗口。
    - 应用会话级别的流量控制窗口。
    - 对于服务器，如果支持服务器首选地址，则根据对端地址族设置连接 ID 和令牌。
    - 标记配置已完成。
    - 通知底层的 `connection_` 配置已协商完成。
    - 如果允许低流量控制限制或使用 TLS，则尝试再次写入数据。

27. **处理 ALPS 数据 (`OnAlpsData`)**:
    - 目前返回 `std::nullopt`，表示未处理 ALPS 数据。

28. **调整初始流量控制窗口 (`AdjustInitialFlowControlWindows`)**:
    - 根据提供的流窗口大小调整初始的流和会话级别的流量控制窗口。
    - 通知所有现有流和加密流新的窗口大小。

29. **处理在不存在的外发流上接收到帧 (`HandleFrameOnNonexistentOutgoingStream`)**:
    - 当接收到针对不存在的本地创建的流的帧时，关闭连接。

30. **处理在有效的但不存在的流上接收到 RST 帧 (`HandleRstOnValidNonexistentStream`)**:
    - 如果流是已关闭的流，则更新连接级别的流量控制。

31. **处理新的流流量控制窗口 (`OnNewStreamFlowControlWindow`)**:
    - 仅适用于使用 Quic Crypto 的版本。
    - 检查新的窗口大小是否小于最小值，如果小于则关闭连接。
    - 通知所有现有流和加密流新的窗口大小。

32. **处理新的单向流流量控制窗口 (`OnNewStreamUnidirectionalFlowControlWindow`)**:
    - 仅适用于使用 TLS 的版本。
    - 通知所有现有的外发单向流新的窗口大小。

33. **处理新的外发双向流流量控制窗口 (`OnNewStreamOutgoingBidirectionalFlowControlWindow`)**:
    - 仅适用于使用 TLS 的版本。
    - 通知所有现有的外发双向流新的窗口大小。

**与 JavaScript 的关系：**

这段 C++ 代码是 Chromium 网络栈的一部分，负责底层的 QUIC 协议处理。JavaScript 代码运行在浏览器环境中，通过浏览器提供的 Web API（例如 `fetch`、WebSocket）发起网络请求。当使用 QUIC 协议时，JavaScript 的请求最终会传递到这个 C++ 代码进行处理。

**举例说明：**

假设一个 JavaScript 应用使用 `fetch` API 向一个支持 QUIC 的服务器发送数据。

1. JavaScript 代码调用 `fetch()` 方法，并传入要发送的数据。
2. 浏览器内核的网络层识别出这是一个 QUIC 连接。
3. 数据被传递到 `QuicSession` 对象。
4. `WritevData()` 函数会被调用，将 JavaScript 传递的数据封装成 QUIC 数据帧并发送出去。
5. 如果服务器的流量控制窗口已满，`CanWrite()` 函数可能会返回 `false`，阻止数据发送，直到收到服务器的 `WINDOW_UPDATE` 帧。

**假设输入与输出 (以 `CanWrite` 为例):**

**假设输入：**

* `ding_retransmission_` 为空 (没有等待重传的帧)。
* `flow_controller_.IsBlocked()` 返回 `true` (连接级别的流量控制被阻塞)。
* `VersionUsesHttp3(transport_version())` 返回 `false` (当前 QUIC 版本不是 HTTP/3)。
* `write_blocked_streams_->HasWriteBlockedSpecialStream()` 返回 `true` (存在被阻塞的特殊流，例如加密流)。

**输出：**

* `CanWrite()` 返回 `true`。

**用户或编程常见的使用错误：**

1. **在加密未建立前尝试发送数据：** 用户或开发者可能在 QUIC 握手完成之前就尝试发送应用数据。`WritevData()` 函数会检查 `IsEncryptionEstablished()` 的返回值，如果加密未建立，则会阻止数据发送，导致数据被缓存或发送失败。这可能导致应用程序看似卡住或者数据丢失。

   **调试线索：** 如果发现数据发送延迟很高，可以检查 `IsEncryptionEstablished()` 的状态，以及是否有因为加密未建立而导致的写入阻塞。

2. **错误地处理流量控制：**  开发者可能没有正确处理 QUIC 的流量控制机制，导致发送的数据量超过了对端的接收能力。这会导致连接被阻塞，甚至可能导致连接被关闭。

   **调试线索：** 可以检查 `flow_controller_.IsBlocked()` 的状态，以及是否频繁触发 `SendBlocked()` 函数。如果看到大量的 `BLOCKED` 帧，可能意味着本地发送端没有充分考虑对端的接收窗口。

**用户操作如何一步步到达这里，作为调试线索：**

假设用户在浏览器中访问一个使用 QUIC 协议的网站，并进行了一些操作，导致了网络问题。

1. **用户打开网页：** 浏览器尝试与服务器建立 QUIC 连接。如果连接失败，可能是握手阶段出现问题，可以关注 `HasPendingHandshake()` 的状态和相关的加密配置。
2. **用户在网页上提交表单或上传文件：** 这会触发数据传输，`WritevData()` 函数会被调用。如果数据传输缓慢或失败，可能是流量控制问题（检查 `CanWrite()` 和 `flow_controller_.IsBlocked()`），或者网络拥塞导致需要重传（检查 `ding_retransmission_.empty()`）。
3. **用户在观看视频或进行实时通信：**  这些场景下会有持续的数据传输。如果出现卡顿或延迟，可能是流量控制或者网络质量问题。可以关注 `GetStreamsInfoForLogging()` 输出的流状态信息，查看是否有大量的重传或阻塞。
4. **用户关闭网页：** 这会触发 QUIC 连接的关闭流程。可以查看 `on_closed_frame_string()` 的输出，了解连接关闭的原因。

通过分析用户操作和相关的代码执行路径，结合日志信息，可以更有效地定位网络问题的根源。例如，如果在用户提交表单时，发现 `WritevData()` 因为加密未建立而被阻止，那么问题可能出在握手阶段。如果发现是因为流量控制阻塞，则需要检查两端的流量控制窗口状态。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
ding_retransmission_.empty()) {
    return true;
  }
  if (flow_controller_.IsBlocked()) {
    if (VersionUsesHttp3(transport_version())) {
      return false;
    }
    // Crypto and headers streams are not blocked by connection level flow
    // control.
    return write_blocked_streams_->HasWriteBlockedSpecialStream();
  }
  return write_blocked_streams_->HasWriteBlockedSpecialStream() ||
         write_blocked_streams_->HasWriteBlockedDataStreams();
}

std::string QuicSession::GetStreamsInfoForLogging() const {
  std::string info = absl::StrCat(
      "num_active_streams: ", GetNumActiveStreams(),
      ", num_pending_streams: ", pending_streams_size(),
      ", num_outgoing_draining_streams: ", num_outgoing_draining_streams(),
      " ");
  // Log info for up to 5 streams.
  size_t i = 5;
  for (const auto& it : stream_map_) {
    if (it.second->is_static()) {
      continue;
    }
    // Calculate the stream creation delay.
    const QuicTime::Delta delay =
        connection_->clock()->ApproximateNow() - it.second->creation_time();
    absl::StrAppend(
        &info, "{", it.second->id(), ":", delay.ToDebuggingValue(), ";",
        it.second->stream_bytes_written(), ",", it.second->fin_sent(), ",",
        it.second->HasBufferedData(), ",", it.second->fin_buffered(), ";",
        it.second->stream_bytes_read(), ",", it.second->fin_received(), "}");
    --i;
    if (i == 0) {
      break;
    }
  }
  return info;
}

bool QuicSession::HasPendingHandshake() const {
  if (QuicVersionUsesCryptoFrames(transport_version())) {
    return GetCryptoStream()->HasPendingCryptoRetransmission() ||
           GetCryptoStream()->HasBufferedCryptoFrames();
  }
  return streams_with_pending_retransmission_.contains(
             QuicUtils::GetCryptoStreamId(transport_version())) ||
         write_blocked_streams_->IsStreamBlocked(
             QuicUtils::GetCryptoStreamId(transport_version()));
}

void QuicSession::ProcessUdpPacket(const QuicSocketAddress& self_address,
                                   const QuicSocketAddress& peer_address,
                                   const QuicReceivedPacket& packet) {
  QuicConnectionContextSwitcher cs(connection_->context());
  connection_->ProcessUdpPacket(self_address, peer_address, packet);
}

std::string QuicSession::on_closed_frame_string() const {
  std::stringstream ss;
  ss << on_closed_frame_;
  if (source_.has_value()) {
    ss << " " << ConnectionCloseSourceToString(*source_);
  }
  return ss.str();
}

QuicConsumedData QuicSession::WritevData(QuicStreamId id, size_t write_length,
                                         QuicStreamOffset offset,
                                         StreamSendingState state,
                                         TransmissionType type,
                                         EncryptionLevel level) {
  QUIC_BUG_IF(session writevdata when disconnected, !connection()->connected())
      << ENDPOINT << "Try to write stream data when connection is closed: "
      << on_closed_frame_string();
  if (!IsEncryptionEstablished() &&
      !QuicUtils::IsCryptoStreamId(transport_version(), id)) {
    // Do not let streams write without encryption. The calling stream will end
    // up write blocked until OnCanWrite is next called.
    if (was_zero_rtt_rejected_ && !OneRttKeysAvailable()) {
      QUICHE_DCHECK(version().UsesTls() &&
                    perspective() == Perspective::IS_CLIENT);
      QUIC_DLOG(INFO) << ENDPOINT
                      << "Suppress the write while 0-RTT gets rejected and "
                         "1-RTT keys are not available. Version: "
                      << ParsedQuicVersionToString(version());
    } else if (version().UsesTls() || perspective() == Perspective::IS_SERVER) {
      QUIC_BUG(quic_bug_10866_2)
          << ENDPOINT << "Try to send data of stream " << id
          << " before encryption is established. Version: "
          << ParsedQuicVersionToString(version());
    } else {
      // In QUIC crypto, this could happen when the client sends full CHLO and
      // 0-RTT request, then receives an inchoate REJ and sends an inchoate
      // CHLO. The client then gets the ACK of the inchoate CHLO or the client
      // gets the full REJ and needs to verify the proof (before it sends the
      // full CHLO), such that there is no outstanding crypto data.
      // Retransmission alarm fires in TLP mode which tries to retransmit the
      // 0-RTT request (without encryption).
      QUIC_DLOG(INFO) << ENDPOINT << "Try to send data of stream " << id
                      << " before encryption is established.";
    }
    return QuicConsumedData(0, false);
  }

  SetTransmissionType(type);
  QuicConnection::ScopedEncryptionLevelContext context(connection(), level);

  QuicConsumedData data =
      connection_->SendStreamData(id, write_length, offset, state);
  if (type == NOT_RETRANSMISSION) {
    // This is new stream data.
    write_blocked_streams_->UpdateBytesForStream(id, data.bytes_consumed);
  }

  return data;
}

size_t QuicSession::SendCryptoData(EncryptionLevel level, size_t write_length,
                                   QuicStreamOffset offset,
                                   TransmissionType type) {
  QUICHE_DCHECK(QuicVersionUsesCryptoFrames(transport_version()));
  if (!connection()->framer().HasEncrypterOfEncryptionLevel(level)) {
    const std::string error_details = absl::StrCat(
        "Try to send crypto data with missing keys of encryption level: ",
        EncryptionLevelToString(level));
    QUIC_BUG(quic_bug_10866_3) << ENDPOINT << error_details;
    connection()->CloseConnection(
        QUIC_MISSING_WRITE_KEYS, error_details,
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return 0;
  }
  SetTransmissionType(type);
  QuicConnection::ScopedEncryptionLevelContext context(connection(), level);
  const auto bytes_consumed =
      connection_->SendCryptoData(level, write_length, offset);
  return bytes_consumed;
}

void QuicSession::OnControlFrameManagerError(QuicErrorCode error_code,
                                             std::string error_details) {
  connection_->CloseConnection(
      error_code, error_details,
      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
}

bool QuicSession::WriteControlFrame(const QuicFrame& frame,
                                    TransmissionType type) {
  QUIC_BUG_IF(quic_bug_12435_11, !connection()->connected())
      << ENDPOINT
      << absl::StrCat("Try to write control frame: ", QuicFrameToString(frame),
                      " when connection is closed: ")
      << on_closed_frame_string();
  if (!IsEncryptionEstablished()) {
    // Suppress the write before encryption gets established.
    return false;
  }
  SetTransmissionType(type);
  QuicConnection::ScopedEncryptionLevelContext context(
      connection(), GetEncryptionLevelToSendApplicationData());
  return connection_->SendControlFrame(frame);
}

void QuicSession::ResetStream(QuicStreamId id, QuicRstStreamErrorCode error) {
  QuicStream* stream = GetStream(id);
  if (stream != nullptr && stream->is_static()) {
    connection()->CloseConnection(
        QUIC_INVALID_STREAM_ID, "Try to reset a static stream",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  if (stream != nullptr) {
    stream->Reset(error);
    return;
  }

  QuicConnection::ScopedPacketFlusher flusher(connection());
  MaybeSendStopSendingFrame(id, QuicResetStreamError::FromInternal(error));
  MaybeSendRstStreamFrame(id, QuicResetStreamError::FromInternal(error), 0);
}

void QuicSession::MaybeSendRstStreamFrame(QuicStreamId id,
                                          QuicResetStreamError error,
                                          QuicStreamOffset bytes_written) {
  if (!connection()->connected()) {
    return;
  }
  if (!VersionHasIetfQuicFrames(transport_version()) ||
      QuicUtils::GetStreamType(id, perspective(), IsIncomingStream(id),
                               version()) != READ_UNIDIRECTIONAL) {
    control_frame_manager_.WriteOrBufferRstStream(id, error, bytes_written);
  }

  connection_->OnStreamReset(id, error.internal_code());
}

void QuicSession::MaybeSendStopSendingFrame(QuicStreamId id,
                                            QuicResetStreamError error) {
  if (!connection()->connected()) {
    return;
  }
  if (VersionHasIetfQuicFrames(transport_version()) &&
      QuicUtils::GetStreamType(id, perspective(), IsIncomingStream(id),
                               version()) != WRITE_UNIDIRECTIONAL) {
    control_frame_manager_.WriteOrBufferStopSending(error, id);
  }
}

void QuicSession::SendGoAway(QuicErrorCode error_code,
                             const std::string& reason) {
  // GOAWAY frame is not supported in IETF QUIC.
  QUICHE_DCHECK(!VersionHasIetfQuicFrames(transport_version()));
  if (!IsEncryptionEstablished()) {
    QUIC_CODE_COUNT(quic_goaway_before_encryption_established);
    connection_->CloseConnection(
        error_code, reason,
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }
  if (transport_goaway_sent_) {
    return;
  }
  transport_goaway_sent_ = true;

  QUICHE_DCHECK_EQ(perspective(), Perspective::IS_SERVER);
  control_frame_manager_.WriteOrBufferGoAway(
      error_code,
      QuicUtils::GetMaxClientInitiatedBidirectionalStreamId(
          transport_version()),
      reason);
}

void QuicSession::SendBlocked(QuicStreamId id, QuicStreamOffset byte_offset) {
  control_frame_manager_.WriteOrBufferBlocked(id, byte_offset);
}

void QuicSession::SendWindowUpdate(QuicStreamId id,
                                   QuicStreamOffset byte_offset) {
  control_frame_manager_.WriteOrBufferWindowUpdate(id, byte_offset);
}

void QuicSession::OnStreamError(QuicErrorCode error_code,
                                std::string error_details) {
  connection_->CloseConnection(
      error_code, error_details,
      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
}

void QuicSession::OnStreamError(QuicErrorCode error_code,
                                QuicIetfTransportErrorCodes ietf_error,
                                std::string error_details) {
  connection_->CloseConnection(
      error_code, ietf_error, error_details,
      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
}

bool QuicSession::CanSendMaxStreams() {
  return control_frame_manager_.NumBufferedMaxStreams() < 2;
}

void QuicSession::SendMaxStreams(QuicStreamCount stream_count,
                                 bool unidirectional) {
  if (!is_configured_) {
    QUIC_BUG(quic_bug_10866_5)
        << "Try to send max streams before config negotiated.";
    return;
  }
  control_frame_manager_.WriteOrBufferMaxStreams(stream_count, unidirectional);
}

void QuicSession::InsertLocallyClosedStreamsHighestOffset(
    const QuicStreamId id, QuicStreamOffset offset) {
  locally_closed_streams_highest_offset_[id] = offset;
}

void QuicSession::OnStreamClosed(QuicStreamId stream_id) {
  QUIC_DVLOG(1) << ENDPOINT << "Closing stream: " << stream_id;
  StreamMap::iterator it = stream_map_.find(stream_id);
  if (it == stream_map_.end()) {
    QUIC_BUG(quic_bug_10866_6)
        << ENDPOINT << "Stream is already closed: " << stream_id;
    return;
  }
  QuicStream* stream = it->second.get();
  StreamType type = stream->type();

  const bool stream_waiting_for_acks = stream->IsWaitingForAcks();
  if (stream_waiting_for_acks) {
    // The stream needs to be kept alive because it's waiting for acks.
    ++num_zombie_streams_;
  } else {
    closed_streams_.push_back(std::move(it->second));
    stream_map_.erase(it);
    // Do not retransmit data of a closed stream.
    streams_with_pending_retransmission_.erase(stream_id);
    if (!closed_streams_clean_up_alarm_->IsSet()) {
      closed_streams_clean_up_alarm_->Set(
          connection_->clock()->ApproximateNow());
    }
    connection_->QuicBugIfHasPendingFrames(stream_id);
  }

  if (!stream->HasReceivedFinalOffset()) {
    // If we haven't received a FIN or RST for this stream, we need to keep
    // track of the how many bytes the stream's flow controller believes it has
    // received, for accurate connection level flow control accounting.
    // If this is an outgoing stream, it is technically open from peer's
    // perspective. Do not inform stream Id manager yet.
    QUICHE_DCHECK(!stream->was_draining());
    InsertLocallyClosedStreamsHighestOffset(
        stream_id, stream->highest_received_byte_offset());
    return;
  }

  const bool stream_was_draining = stream->was_draining();
  QUIC_DVLOG_IF(1, stream_was_draining)
      << ENDPOINT << "Stream " << stream_id << " was draining";
  if (stream_was_draining) {
    QUIC_BUG_IF(quic_bug_12435_4, num_draining_streams_ == 0);
    --num_draining_streams_;
    if (!IsIncomingStream(stream_id)) {
      QUIC_BUG_IF(quic_bug_12435_5, num_outgoing_draining_streams_ == 0);
      --num_outgoing_draining_streams_;
    }
    // Stream Id manager has been informed with draining streams.
    return;
  }
  if (!VersionHasIetfQuicFrames(transport_version())) {
    stream_id_manager_.OnStreamClosed(
        /*is_incoming=*/IsIncomingStream(stream_id));
  }
  if (!connection_->connected()) {
    return;
  }
  if (IsIncomingStream(stream_id)) {
    // Stream Id manager is only interested in peer initiated stream IDs.
    if (VersionHasIetfQuicFrames(transport_version())) {
      ietf_streamid_manager_.OnStreamClosed(stream_id);
    }
    return;
  }
  if (!VersionHasIetfQuicFrames(transport_version())) {
    OnCanCreateNewOutgoingStream(type != BIDIRECTIONAL);
  }
}

void QuicSession::ClosePendingStream(QuicStreamId stream_id) {
  QUIC_DVLOG(1) << ENDPOINT << "Closing stream " << stream_id;
  QUICHE_DCHECK(VersionHasIetfQuicFrames(transport_version()));
  pending_stream_map_.erase(stream_id);
  if (connection_->connected()) {
    ietf_streamid_manager_.OnStreamClosed(stream_id);
  }
}

bool QuicSession::ShouldProcessFrameByPendingStream(QuicFrameType type,
                                                    QuicStreamId id) const {
  return stream_map_.find(id) == stream_map_.end() &&
         ((version().HasIetfQuicFrames() && ExceedsPerLoopStreamLimit()) ||
          UsesPendingStreamForFrame(type, id));
}

void QuicSession::OnFinalByteOffsetReceived(
    QuicStreamId stream_id, QuicStreamOffset final_byte_offset) {
  auto it = locally_closed_streams_highest_offset_.find(stream_id);
  if (it == locally_closed_streams_highest_offset_.end()) {
    return;
  }

  QUIC_DVLOG(1) << ENDPOINT << "Received final byte offset "
                << final_byte_offset << " for stream " << stream_id;
  QuicByteCount offset_diff = final_byte_offset - it->second;
  if (flow_controller_.UpdateHighestReceivedOffset(
          flow_controller_.highest_received_byte_offset() + offset_diff)) {
    // If the final offset violates flow control, close the connection now.
    if (flow_controller_.FlowControlViolation()) {
      connection_->CloseConnection(
          QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA,
          "Connection level flow control violation",
          ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
      return;
    }
  }

  flow_controller_.AddBytesConsumed(offset_diff);
  locally_closed_streams_highest_offset_.erase(it);
  if (!VersionHasIetfQuicFrames(transport_version())) {
    stream_id_manager_.OnStreamClosed(
        /*is_incoming=*/IsIncomingStream(stream_id));
  }
  if (IsIncomingStream(stream_id)) {
    if (VersionHasIetfQuicFrames(transport_version())) {
      ietf_streamid_manager_.OnStreamClosed(stream_id);
    }
  } else if (!VersionHasIetfQuicFrames(transport_version())) {
    OnCanCreateNewOutgoingStream(false);
  }
}

bool QuicSession::IsEncryptionEstablished() const {
  if (GetCryptoStream() == nullptr) {
    return false;
  }
  return GetCryptoStream()->encryption_established();
}

bool QuicSession::OneRttKeysAvailable() const {
  if (GetCryptoStream() == nullptr) {
    return false;
  }
  return GetCryptoStream()->one_rtt_keys_available();
}

void QuicSession::OnConfigNegotiated() {
  // In versions with TLS, the configs will be set twice if 0-RTT is available.
  // In the second config setting, 1-RTT keys are guaranteed to be available.
  if (version().UsesTls() && is_configured_ &&
      connection_->encryption_level() != ENCRYPTION_FORWARD_SECURE) {
    QUIC_BUG(quic_bug_12435_6)
        << ENDPOINT
        << "1-RTT keys missing when config is negotiated for the second time.";
    connection_->CloseConnection(
        QUIC_INTERNAL_ERROR,
        "1-RTT keys missing when config is negotiated for the second time.",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  QUIC_DVLOG(1) << ENDPOINT << "OnConfigNegotiated";
  connection_->SetFromConfig(config_);

  if (VersionHasIetfQuicFrames(transport_version())) {
    uint32_t max_streams = 0;
    if (config_.HasReceivedMaxBidirectionalStreams()) {
      max_streams = config_.ReceivedMaxBidirectionalStreams();
    }
    if (was_zero_rtt_rejected_ &&
        max_streams <
            ietf_streamid_manager_.outgoing_bidirectional_stream_count()) {
      connection_->CloseConnection(
          QUIC_ZERO_RTT_UNRETRANSMITTABLE,
          absl::StrCat(
              "Server rejected 0-RTT, aborting because new bidirectional "
              "initial stream limit ",
              max_streams, " is less than current open streams: ",
              ietf_streamid_manager_.outgoing_bidirectional_stream_count()),
          ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
      return;
    }
    QUIC_DVLOG(1) << ENDPOINT
                  << "Setting Bidirectional outgoing_max_streams_ to "
                  << max_streams;
    if (perspective_ == Perspective::IS_CLIENT &&
        max_streams <
            ietf_streamid_manager_.max_outgoing_bidirectional_streams()) {
      connection_->CloseConnection(
          was_zero_rtt_rejected_ ? QUIC_ZERO_RTT_REJECTION_LIMIT_REDUCED
                                 : QUIC_ZERO_RTT_RESUMPTION_LIMIT_REDUCED,
          absl::StrCat(
              was_zero_rtt_rejected_
                  ? "Server rejected 0-RTT, aborting because "
                  : "",
              "new bidirectional limit ", max_streams,
              " decreases the current limit: ",
              ietf_streamid_manager_.max_outgoing_bidirectional_streams()),
          ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
      return;
    }
    if (ietf_streamid_manager_.MaybeAllowNewOutgoingBidirectionalStreams(
            max_streams)) {
      OnCanCreateNewOutgoingStream(/*unidirectional = */ false);
    }

    max_streams = 0;
    if (config_.HasReceivedMaxUnidirectionalStreams()) {
      max_streams = config_.ReceivedMaxUnidirectionalStreams();
    }

    if (was_zero_rtt_rejected_ &&
        max_streams <
            ietf_streamid_manager_.outgoing_unidirectional_stream_count()) {
      connection_->CloseConnection(
          QUIC_ZERO_RTT_UNRETRANSMITTABLE,
          absl::StrCat(
              "Server rejected 0-RTT, aborting because new unidirectional "
              "initial stream limit ",
              max_streams, " is less than current open streams: ",
              ietf_streamid_manager_.outgoing_unidirectional_stream_count()),
          ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
      return;
    }

    if (max_streams <
        ietf_streamid_manager_.max_outgoing_unidirectional_streams()) {
      connection_->CloseConnection(
          was_zero_rtt_rejected_ ? QUIC_ZERO_RTT_REJECTION_LIMIT_REDUCED
                                 : QUIC_ZERO_RTT_RESUMPTION_LIMIT_REDUCED,
          absl::StrCat(
              was_zero_rtt_rejected_
                  ? "Server rejected 0-RTT, aborting because "
                  : "",
              "new unidirectional limit ", max_streams,
              " decreases the current limit: ",
              ietf_streamid_manager_.max_outgoing_unidirectional_streams()),
          ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
      return;
    }
    QUIC_DVLOG(1) << ENDPOINT
                  << "Setting Unidirectional outgoing_max_streams_ to "
                  << max_streams;
    if (ietf_streamid_manager_.MaybeAllowNewOutgoingUnidirectionalStreams(
            max_streams)) {
      OnCanCreateNewOutgoingStream(/*unidirectional = */ true);
    }
  } else {
    uint32_t max_streams = 0;
    if (config_.HasReceivedMaxBidirectionalStreams()) {
      max_streams = config_.ReceivedMaxBidirectionalStreams();
    }
    QUIC_DVLOG(1) << ENDPOINT << "Setting max_open_outgoing_streams_ to "
                  << max_streams;
    if (was_zero_rtt_rejected_ &&
        max_streams < stream_id_manager_.num_open_outgoing_streams()) {
      connection_->CloseConnection(
          QUIC_INTERNAL_ERROR,
          absl::StrCat(
              "Server rejected 0-RTT, aborting because new stream limit ",
              max_streams, " is less than current open streams: ",
              stream_id_manager_.num_open_outgoing_streams()),
          ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
      return;
    }
    stream_id_manager_.set_max_open_outgoing_streams(max_streams);
  }

  if (perspective() == Perspective::IS_SERVER) {
    if (config_.HasReceivedConnectionOptions()) {
      // The following variations change the initial receive flow control
      // window sizes.
      if (ContainsQuicTag(config_.ReceivedConnectionOptions(), kIFW6)) {
        AdjustInitialFlowControlWindows(64 * 1024);
      }
      if (ContainsQuicTag(config_.ReceivedConnectionOptions(), kIFW7)) {
        AdjustInitialFlowControlWindows(128 * 1024);
      }
      if (ContainsQuicTag(config_.ReceivedConnectionOptions(), kIFW8)) {
        AdjustInitialFlowControlWindows(256 * 1024);
      }
      if (ContainsQuicTag(config_.ReceivedConnectionOptions(), kIFW9)) {
        AdjustInitialFlowControlWindows(512 * 1024);
      }
      if (ContainsQuicTag(config_.ReceivedConnectionOptions(), kIFWA)) {
        AdjustInitialFlowControlWindows(1024 * 1024);
      }
    }

    config_.SetStatelessResetTokenToSend(GetStatelessResetToken());
  }

  if (VersionHasIetfQuicFrames(transport_version())) {
    ietf_streamid_manager_.SetMaxOpenIncomingBidirectionalStreams(
        config_.GetMaxBidirectionalStreamsToSend());
    ietf_streamid_manager_.SetMaxOpenIncomingUnidirectionalStreams(
        config_.GetMaxUnidirectionalStreamsToSend());
  } else {
    // A small number of additional incoming streams beyond the limit should be
    // allowed. This helps avoid early connection termination when FIN/RSTs for
    // old streams are lost or arrive out of order.
    // Use a minimum number of additional streams, or a percentage increase,
    // whichever is larger.
    uint32_t max_incoming_streams_to_send =
        config_.GetMaxBidirectionalStreamsToSend();
    uint32_t max_incoming_streams =
        std::max(max_incoming_streams_to_send + kMaxStreamsMinimumIncrement,
                 static_cast<uint32_t>(max_incoming_streams_to_send *
                                       kMaxStreamsMultiplier));
    stream_id_manager_.set_max_open_incoming_streams(max_incoming_streams);
  }

  if (connection_->version().handshake_protocol == PROTOCOL_TLS1_3) {
    // When using IETF-style TLS transport parameters, inform existing streams
    // of new flow-control limits.
    if (config_.HasReceivedInitialMaxStreamDataBytesOutgoingBidirectional()) {
      OnNewStreamOutgoingBidirectionalFlowControlWindow(
          config_.ReceivedInitialMaxStreamDataBytesOutgoingBidirectional());
    }
    if (config_.HasReceivedInitialMaxStreamDataBytesIncomingBidirectional()) {
      OnNewStreamIncomingBidirectionalFlowControlWindow(
          config_.ReceivedInitialMaxStreamDataBytesIncomingBidirectional());
    }
    if (config_.HasReceivedInitialMaxStreamDataBytesUnidirectional()) {
      OnNewStreamUnidirectionalFlowControlWindow(
          config_.ReceivedInitialMaxStreamDataBytesUnidirectional());
    }
  } else {  // The version uses Google QUIC Crypto.
    if (config_.HasReceivedInitialStreamFlowControlWindowBytes()) {
      // Streams which were created before the SHLO was received (0-RTT
      // requests) are now informed of the peer's initial flow control window.
      OnNewStreamFlowControlWindow(
          config_.ReceivedInitialStreamFlowControlWindowBytes());
    }
  }

  if (config_.HasReceivedInitialSessionFlowControlWindowBytes()) {
    OnNewSessionFlowControlWindow(
        config_.ReceivedInitialSessionFlowControlWindowBytes());
  }

  if (perspective_ == Perspective::IS_SERVER && version().HasIetfQuicFrames() &&
      connection_->effective_peer_address().IsInitialized()) {
    if (config_.SupportsServerPreferredAddress(perspective_)) {
      quiche::IpAddressFamily address_family =
          connection_->effective_peer_address()
              .Normalized()
              .host()
              .address_family();
      std::optional<QuicSocketAddress> expected_preferred_address =
          config_.GetMappedAlternativeServerAddress(address_family);
      if (expected_preferred_address.has_value()) {
        // Set connection ID and token if SPAD has received and a preferred
        // address of the same address family is configured.
        std::optional<QuicNewConnectionIdFrame> frame =
            connection_->MaybeIssueNewConnectionIdForPreferredAddress();
        if (frame.has_value()) {
          config_.SetPreferredAddressConnectionIdAndTokenToSend(
              frame->connection_id, frame->stateless_reset_token);
        }
        connection_->set_expected_server_preferred_address(
            *expected_preferred_address);
      }
      // Clear the alternative address of the other address family in the
      // config.
      config_.ClearAlternateServerAddressToSend(
          address_family == quiche::IpAddressFamily::IP_V4
              ? quiche::IpAddressFamily::IP_V6
              : quiche::IpAddressFamily::IP_V4);
    } else {
      // Clear alternative IPv(4|6) addresses in config if the server hasn't
      // received 'SPAD' connection option.
      config_.ClearAlternateServerAddressToSend(quiche::IpAddressFamily::IP_V4);
      config_.ClearAlternateServerAddressToSend(quiche::IpAddressFamily::IP_V6);
    }
  }

  is_configured_ = true;
  connection()->OnConfigNegotiated();

  // Ask flow controllers to try again since the config could have unblocked us.
  // Or if this session is configured on TLS enabled QUIC versions,
  // attempt to retransmit 0-RTT data if there's any.
  // TODO(fayang): consider removing this OnCanWrite call.
  if (!connection_->framer().is_processing_packet() &&
      (connection_->version().AllowsLowFlowControlLimits() ||
       version().UsesTls())) {
    QUIC_CODE_COUNT(quic_session_on_can_write_on_config_negotiated);
    OnCanWrite();
  }
}

std::optional<std::string> QuicSession::OnAlpsData(const uint8_t* /*alps_data*/,
                                                   size_t /*alps_length*/) {
  return std::nullopt;
}

void QuicSession::AdjustInitialFlowControlWindows(size_t stream_window) {
  const float session_window_multiplier =
      config_.GetInitialStreamFlowControlWindowToSend()
          ? static_cast<float>(
                config_.GetInitialSessionFlowControlWindowToSend()) /
                config_.GetInitialStreamFlowControlWindowToSend()
          : 1.5;

  QUIC_DVLOG(1) << ENDPOINT << "Set stream receive window to " << stream_window;
  config_.SetInitialStreamFlowControlWindowToSend(stream_window);

  size_t session_window = session_window_multiplier * stream_window;
  QUIC_DVLOG(1) << ENDPOINT << "Set session receive window to "
                << session_window;
  config_.SetInitialSessionFlowControlWindowToSend(session_window);
  flow_controller_.UpdateReceiveWindowSize(session_window);
  // Inform all existing streams about the new window.
  for (auto const& kv : stream_map_) {
    kv.second->UpdateReceiveWindowSize(stream_window);
  }
  if (!QuicVersionUsesCryptoFrames(transport_version())) {
    GetMutableCryptoStream()->UpdateReceiveWindowSize(stream_window);
  }
}

void QuicSession::HandleFrameOnNonexistentOutgoingStream(
    QuicStreamId stream_id) {
  QUICHE_DCHECK(!IsClosedStream(stream_id));
  // Received a frame for a locally-created stream that is not currently
  // active. This is an error.
  if (VersionHasIetfQuicFrames(transport_version())) {
    connection()->CloseConnection(
        QUIC_HTTP_STREAM_WRONG_DIRECTION, "Data for nonexistent stream",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }
  connection()->CloseConnection(
      QUIC_INVALID_STREAM_ID, "Data for nonexistent stream",
      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
}

void QuicSession::HandleRstOnValidNonexistentStream(
    const QuicRstStreamFrame& frame) {
  // If the stream is neither originally in active streams nor created in
  // GetOrCreateStream(), it could be a closed stream in which case its
  // final received byte offset need to be updated.
  if (IsClosedStream(frame.stream_id)) {
    // The RST frame contains the final byte offset for the stream: we can now
    // update the connection level flow controller if needed.
    OnFinalByteOffsetReceived(frame.stream_id, frame.byte_offset);
  }
}

void QuicSession::OnNewStreamFlowControlWindow(QuicStreamOffset new_window) {
  QUICHE_DCHECK(version().UsesQuicCrypto());
  QUIC_DVLOG(1) << ENDPOINT << "OnNewStreamFlowControlWindow " << new_window;
  if (new_window < kMinimumFlowControlSendWindow) {
    QUIC_LOG_FIRST_N(ERROR, 1)
        << "Peer sent us an invalid stream flow control send window: "
        << new_window << ", below minimum: " << kMinimumFlowControlSendWindow;
    connection_->CloseConnection(
        QUIC_FLOW_CONTROL_INVALID_WINDOW, "New stream window too low",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  // Inform all existing streams about the new window.
  for (auto const& kv : stream_map_) {
    QUIC_DVLOG(1) << ENDPOINT << "Informing stream " << kv.first
                  << " of new stream flow control window " << new_window;
    if (!kv.second->MaybeConfigSendWindowOffset(
            new_window, /* was_zero_rtt_rejected = */ false)) {
      return;
    }
  }
  if (!QuicVersionUsesCryptoFrames(transport_version())) {
    QUIC_DVLOG(1)
        << ENDPOINT
        << "Informing crypto stream of new stream flow control window "
        << new_window;
    GetMutableCryptoStream()->MaybeConfigSendWindowOffset(
        new_window, /* was_zero_rtt_rejected = */ false);
  }
}

void QuicSession::OnNewStreamUnidirectionalFlowControlWindow(
    QuicStreamOffset new_window) {
  QUICHE_DCHECK_EQ(connection_->version().handshake_protocol, PROTOCOL_TLS1_3);
  QUIC_DVLOG(1) << ENDPOINT << "OnNewStreamUnidirectionalFlowControlWindow "
                << new_window;
  // Inform all existing outgoing unidirectional streams about the new window.
  for (auto const& kv : stream_map_) {
    const QuicStreamId id = kv.first;
    if (!version().HasIetfQuicFrames()) {
      if (kv.second->type() == BIDIRECTIONAL) {
        continue;
      }
    } else {
      if (QuicUtils::IsBidirectionalStreamId(id, version())) {
        continue;
      }
    }
    if (!QuicUtils::IsOutgoingStreamId(connection_->version(), id,
                                       perspective())) {
      continue;
    }
    QUIC_DVLOG(1) << ENDPOINT << "Informing unidirectional stream " << id
                  << " of new stream flow control window " << new_window;
    if (!kv.second->MaybeConfigSendWindowOffset(new_window,
                                                was_zero_rtt_rejected_)) {
      return;
    }
  }
}

void QuicSession::OnNewStreamOutgoingBidirectionalFlowControlWindow(
    QuicStreamOffset new_window) {
  QUICHE_DCHECK_EQ(connection_->version().handshake_protocol, PROTOCOL_TLS1_3);
  QUIC_DVLOG(1) << ENDPOINT
                << "OnNewStreamOutgoingBidirectionalFlowControlWindow "
                << new_window;
  // Inform all existing outgoing bidirectional streams about the new window.
  for (auto const& kv : stream_map_) {
    const QuicStreamId id = kv.first;
    if (!version().HasIetfQuicFrames()) {
      if (kv.second->type() != BIDIRECTIONAL) {
        continue;
      }
    } else {
      if (!QuicUtils::IsBidirectionalStreamId(id, version())) {
        continue;
      }
    }
    if (!QuicUtils::IsOutgoingStreamId(connection_->version(), id,
                                       perspective())) {
      continue;
    }
    QUIC_DVLOG(1) << ENDPOINT << "Informing outgoing bidirectional stream "
                  << id << " of new stream flow control win
```