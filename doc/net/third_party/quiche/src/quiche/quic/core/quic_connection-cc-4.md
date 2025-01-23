Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from Chromium's network stack, specifically the `net/third_party/quiche/src/quiche/quic/core/quic_connection.cc` file. They also want to know about its relation to JavaScript, logical reasoning with input/output examples, common user/programming errors, how a user operation might lead to this code, and finally, a general summary of its function as part 5 of a 10-part series.

Here's a breakdown of the thought process to answer this request:

1. **Identify the core functionality:** The code snippet heavily revolves around sending QUIC packets. Keywords like `WritePacket`, `SerializedPacket`, `SendPacketToWriter`, `coalesce`, `buffer`, `flush`, and handling write errors are strong indicators.

2. **Break down the `WritePacket` function:** This function is central to the snippet. Analyze its steps:
    * Check for out-of-order packets.
    * Handle MTU discovery packets.
    * Process termination packets (connection closing).
    * Coalesce packets (combine multiple small packets).
    * Buffer packets for later sending.
    * Send packets using the `QuicPacketWriter`.
    * Handle write blocking and errors.
    * Update packet sending statistics.
    * Manage AEAD confidentiality limits (encryption key updates).

3. **Identify related helper functions:** Functions like `FlushPackets`, `IsMsgTooBig`, `ShouldDiscardPacket`, `MaybeRevertToPreviousMtu`, `OnWriteError`, `GetPacketBuffer`, `OnSerializedPacket`, and `MaybeHandleAeadConfidentialityLimits` directly support the packet sending process or handle related error conditions.

4. **Address the JavaScript connection:**  QUIC is a transport layer protocol. JavaScript in a browser communicates with servers via higher-level APIs like `fetch` or WebSockets. These APIs eventually use the browser's underlying networking stack, which includes QUIC. The connection is indirect but essential for web communication.

5. **Construct logical reasoning examples:**  Choose key scenarios within `WritePacket`:
    * **Coalescing:** Show how small packets can be combined.
    * **Buffering:** Illustrate when a packet might be queued due to write blocking.
    * **Write Error:** Demonstrate what happens when a send fails.

6. **Identify potential errors:**  Think about common pitfalls when dealing with network communication:
    * Sending data when the connection is closed.
    * Encountering MTU issues.
    * Running into write blocking scenarios.

7. **Trace user operations:**  Start with a basic user action (e.g., clicking a link) and follow the chain down to the QUIC connection:
    * User action triggers a network request.
    * Browser uses HTTP/3 (which uses QUIC).
    * The request needs to be sent as a QUIC packet.
    * The `QuicConnection::WritePacket` function is invoked.

8. **Synthesize the functionality summary:** Combine the insights from the previous steps into a concise description of the code's purpose. Focus on its role in sending and managing QUIC packets, handling errors, and optimizing transmission.

9. **Consider the "Part 5 of 10" context:** This implies the file focuses on a specific aspect of the `QuicConnection`'s lifecycle or responsibilities. Packet sending is a critical function that likely occurs after connection establishment and before teardown.

10. **Review and refine:**  Ensure the answer is clear, well-organized, and addresses all parts of the user's request. Use precise terminology and provide concrete examples. Double-check the accuracy of the logical reasoning and error scenarios. For example, initially I might forget to explicitly mention HTTP/3's role in connecting JavaScript to QUIC. Review helps catch such omissions.
这是 Chromium 网络栈中 QUIC 协议实现的关键部分，专注于 **管理和执行 QUIC 连接中数据包的发送过程**。这是第 5 部分，表明它可能专注于发送过程的某个特定阶段或方面。

**主要功能归纳：**

1. **控制数据包的写入和发送：**  `QuicConnection::WritePacket` 是核心函数，负责将准备好的 QUIC 数据包发送到网络。它处理各种发送场景，包括立即发送、缓冲、合并等。

2. **处理数据包的生命周期：**  它跟踪已发送数据包的状态，包括是否需要重传、是否已确认等。

3. **拥塞控制和流量控制：** 虽然代码片段本身没有直接展示拥塞控制的实现，但它与 `sent_packet_manager_` 交互，表明它会考虑拥塞窗口和发送速率限制。

4. **MTU 发现：**  支持路径最大传输单元（MTU）发现，允许连接利用更大的数据包，提高效率。

5. **处理连接终止数据包：**  能够发送和存储连接终止数据包，以便在连接关闭时通知对端。

6. **处理发送错误：** 监听并处理网络写入错误，并采取相应的措施，例如回退到较小的 MTU 或关闭连接。

7. **数据包合并 (Coalescing)：**  可以将多个小的 QUIC 数据包合并成一个大的网络数据包发送，以减少网络开销。

8. **处理 ECN (Explicit Congestion Notification)：** 支持显式拥塞通知，可以根据网络拥塞情况调整发送行为。

9. **处理加密密钥更新：**  监控已发送的加密数据包数量，并在接近安全限制时触发密钥更新，以保证数据安全性。

**与 JavaScript 功能的关系：**

JavaScript 本身不直接控制 QUIC 连接的底层细节。然而，当浏览器中的 JavaScript 代码发起网络请求（例如使用 `fetch` API 或 WebSocket）时，如果协商使用了 HTTP/3 协议（该协议基于 QUIC），那么底层的网络栈就会使用 `QuicConnection` 来建立和维护与服务器的 QUIC 连接，并发送和接收数据。

**举例说明：**

假设一个网页上的 JavaScript 代码使用 `fetch` API 向服务器请求一个大型图片资源：

```javascript
fetch('https://example.com/image.jpg')
  .then(response => response.blob())
  .then(imageBlob => {
    // 处理图片数据
  });
```

当这个请求发送到服务器时，浏览器的网络栈会：

1. 将 HTTP 请求封装成一个或多个 QUIC 数据帧。
2. 调用 `QuicConnection::WritePacket` 将这些数据帧打包成 QUIC 数据包。
3. `WritePacket` 可能会根据当前的网络状况和连接状态，选择立即发送、缓冲或与其它数据包合并发送。
4. 如果网络出现拥塞或错误，`WritePacket` 及其相关的错误处理机制会被触发。
5. 如果需要进行 MTU 发现，`WritePacket` 也会处理相关的 MTU 探测数据包的发送。

**逻辑推理的假设输入与输出：**

**假设输入：**

* `packet`: 一个包含要发送的 QUIC 帧的 `SerializedPacket` 对象，其 `packet_number` 为 10，包含一些应用数据。
* `connected_`: `true`，表示连接处于连接状态。
* `encryption_level_`: `ENCRYPTION_FORWARD_SECURE`，表示连接已建立安全加密。
* `packet_creator_.max_packet_length()`: 1200 字节。
* 假设当前没有写阻塞。

**输出：**

* `WritePacket` 返回 `true`，表示数据包已成功发送到下层网络写入器。
* `sent_packet_manager_` 中会记录该数据包的信息，用于重传和确认。
* 连接的发送统计信息（例如 `stats_.bytes_sent` 和 `stats_.packets_sent`）会更新。
* 如果数据包包含可重传数据，可能会启动或重置黑洞检测和空闲网络检测计时器。

**涉及用户或编程常见的使用错误：**

1. **尝试在连接关闭后发送数据：**  如果程序逻辑在连接已经关闭后仍然尝试发送数据，`WritePacket` 的开头会检查 `connected_` 状态，如果为 `false`，则会阻止发送并可能记录错误。

   ```c++
   if (!connected_) {
     QUIC_DLOG(INFO) << ENDPOINT
                     << "Not sending packet as connection is disconnected.";
     return true;
   }
   ```

2. **MTU 配置错误：** 如果用户或配置错误地设置了一个非常大的 MTU 值，导致发送的数据包超过了网络的实际支持能力，`WritePacket` 在发送过程中可能会遇到 `WRITE_STATUS_MSG_TOO_BIG` 错误。代码中会尝试处理这种情况，例如通过 `MaybeRevertToPreviousMtu()` 回退到之前的有效 MTU。

   ```c++
   if (IsMsgTooBig(writer_, result)) {
     if (is_mtu_discovery) {
       // ...
       return true;
     }
     // ...
     if (MaybeRevertToPreviousMtu()) {
       return true;
     }
     // ...
   }
   ```

3. **写阻塞处理不当：** 如果底层的网络写入器返回 `WRITE_STATUS_BLOCKED`，表示暂时无法发送数据，调用者需要等待 `OnCanWrite` 回调后再尝试发送。如果程序逻辑没有正确处理写阻塞状态，可能会导致数据发送延迟或丢失。

   ```c++
   if (IsWriteBlockedStatus(result.status)) {
     // ...
     visitor_->OnWriteBlocked();
     // ...
   }
   ```

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中访问一个使用 HTTP/3 的网站。**
2. **浏览器发起对该网站资源的请求（例如，加载网页、请求图片或视频）。**
3. **浏览器的 QUIC 协议实现尝试与服务器建立 QUIC 连接。**
4. **一旦连接建立，当需要向服务器发送数据时（例如，发送 HTTP 请求、上传数据、发送 ACK 帧等），`QuicConnection::WritePacket` 函数就会被调用。**
5. **在调试过程中，如果怀疑数据发送有问题，可以在 `QuicConnection::WritePacket` 函数中设置断点，查看传入的 `packet` 内容、连接状态、以及网络写入器的返回值，从而了解数据包是否被正确地创建和发送。**
6. **如果遇到发送错误，可以查看 `OnWriteError` 函数的调用栈，了解错误的具体原因和发生的时间。**

**作为第 5 部分的功能归纳：**

考虑到这是 10 部分中的第 5 部分，并且代码专注于数据包发送，可以推测前几部分可能涉及连接的建立、握手、密钥协商等，而后续部分可能涉及数据接收、连接关闭、错误处理的更深层次细节等。

因此，**作为第 5 部分，这段代码的核心功能是管理 QUIC 连接中数据包的发送过程，包括将数据帧封装成数据包、处理不同的发送策略（立即发送、缓冲、合并）、处理发送错误、支持 MTU 发现、并与拥塞控制和流量控制机制交互，以确保可靠和高效的数据传输。**

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
_release_time =
      std::max(now, next_release_time_result.release_time);
  packet_writer_params_.release_time_delay = next_release_time - now;
  packet_writer_params_.allow_burst = next_release_time_result.allow_burst;
  return next_release_time;
}

bool QuicConnection::WritePacket(SerializedPacket* packet) {
  if (sent_packet_manager_.GetLargestSentPacket().IsInitialized() &&
      packet->packet_number < sent_packet_manager_.GetLargestSentPacket()) {
    QUIC_BUG(quic_bug_10511_23)
        << "Attempt to write packet:" << packet->packet_number
        << " after:" << sent_packet_manager_.GetLargestSentPacket();
    CloseConnection(QUIC_INTERNAL_ERROR, "Packet written out of order.",
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return true;
  }
  const bool is_mtu_discovery = QuicUtils::ContainsFrameType(
      packet->nonretransmittable_frames, MTU_DISCOVERY_FRAME);
  const SerializedPacketFate fate = packet->fate;
  // Termination packets are encrypted and saved, so don't exit early.
  QuicErrorCode error_code = QUIC_NO_ERROR;
  const bool is_termination_packet = IsTerminationPacket(*packet, &error_code);
  QuicPacketNumber packet_number = packet->packet_number;
  QuicPacketLength encrypted_length = packet->encrypted_length;
  // Termination packets are eventually owned by TimeWaitListManager.
  // Others are deleted at the end of this call.
  if (is_termination_packet) {
    if (termination_info_ == nullptr) {
      termination_info_ = std::make_unique<TerminationInfo>(error_code);
    } else {
      QUIC_BUG_IF(quic_multiple_termination_packets_with_different_error_code,
                  error_code != termination_info_->error_code)
          << "Initial error code: " << termination_info_->error_code
          << ", new error code: " << error_code;
    }
    // Copy the buffer so it's owned in the future.
    char* buffer_copy = CopyBuffer(*packet);
    termination_info_->termination_packets.push_back(
        std::make_unique<QuicEncryptedPacket>(buffer_copy, encrypted_length,
                                              true));
    if (error_code == QUIC_SILENT_IDLE_TIMEOUT) {
      QUICHE_DCHECK_EQ(Perspective::IS_SERVER, perspective_);
      // TODO(fayang): populate histogram indicating the time elapsed from this
      // connection gets closed to following client packets get received.
      QUIC_DVLOG(1) << ENDPOINT
                    << "Added silent connection close to termination packets, "
                       "num of termination packets: "
                    << termination_info_->termination_packets.size();
      return true;
    }
  }

  QUICHE_DCHECK_LE(encrypted_length, kMaxOutgoingPacketSize);
  QUICHE_DCHECK(is_mtu_discovery ||
                encrypted_length <= packet_creator_.max_packet_length())
      << " encrypted_length=" << encrypted_length
      << " > packet_creator max_packet_length="
      << packet_creator_.max_packet_length();
  QUIC_DVLOG(1) << ENDPOINT << "Sending packet " << packet_number << " : "
                << (IsRetransmittable(*packet) == HAS_RETRANSMITTABLE_DATA
                        ? "data bearing "
                        : " ack or probing only ")
                << ", encryption level: " << packet->encryption_level
                << ", encrypted length:" << encrypted_length
                << ", fate: " << fate << " to peer " << packet->peer_address;
  QUIC_DVLOG(2) << ENDPOINT << packet->encryption_level << " packet number "
                << packet_number << " of length " << encrypted_length << ": "
                << std::endl
                << quiche::QuicheTextUtils::HexDump(absl::string_view(
                       packet->encrypted_buffer, encrypted_length));

  // Measure the RTT from before the write begins to avoid underestimating the
  // min_rtt_, especially in cases where the thread blocks or gets swapped out
  // during the WritePacket below.
  QuicTime packet_send_time = CalculatePacketSentTime();
  WriteResult result(WRITE_STATUS_OK, encrypted_length);
  QuicSocketAddress send_to_address = packet->peer_address;
  QuicSocketAddress send_from_address = self_address();
  if (perspective_ == Perspective::IS_SERVER &&
      expected_server_preferred_address_.IsInitialized() &&
      received_client_addresses_cache_.Lookup(send_to_address) ==
          received_client_addresses_cache_.end()) {
    // Given server has not received packets from send_to_address to
    // self_address(), most NATs do not allow packets from self_address() to
    // send_to_address to go through. Override packet's self address to
    // expected_server_preferred_address_.
    // TODO(b/262386897): server should validate reverse path before changing
    // self address of packets to send.
    send_from_address = expected_server_preferred_address_;
  }
  // Self address is always the default self address on this code path.
  const bool send_on_current_path = send_to_address == peer_address();
  if (!send_on_current_path) {
    QUIC_BUG_IF(quic_send_non_probing_frames_on_alternative_path,
                ContainsNonProbingFrame(*packet))
        << "Packet " << packet->packet_number
        << " with non-probing frames was sent on alternative path: "
           "nonretransmittable_frames: "
        << QuicFramesToString(packet->nonretransmittable_frames)
        << " retransmittable_frames: "
        << QuicFramesToString(packet->retransmittable_frames);
  }
  switch (fate) {
    case DISCARD:
      ++stats_.packets_discarded;
      if (debug_visitor_ != nullptr) {
        debug_visitor_->OnPacketDiscarded(*packet);
      }
      return true;
    case COALESCE:
      QUIC_BUG_IF(quic_bug_12714_24,
                  !version().CanSendCoalescedPackets() || coalescing_done_);
      if (!coalesced_packet_.MaybeCoalescePacket(
              *packet, send_from_address, send_to_address,
              helper_->GetStreamSendBufferAllocator(),
              packet_creator_.max_packet_length(),
              GetEcnCodepointToSend(send_to_address), outgoing_flow_label())) {
        // Failed to coalesce packet, flush current coalesced packet.
        if (!FlushCoalescedPacket()) {
          QUIC_BUG_IF(quic_connection_connected_after_flush_coalesced_failure,
                      connected_)
              << "QUIC connection is still connected after failing to flush "
                 "coalesced packet.";
          // Failed to flush coalesced packet, write error has been handled.
          return false;
        }
        if (!coalesced_packet_.MaybeCoalescePacket(
                *packet, send_from_address, send_to_address,
                helper_->GetStreamSendBufferAllocator(),
                packet_creator_.max_packet_length(),
                GetEcnCodepointToSend(send_to_address),
                outgoing_flow_label())) {
          // Failed to coalesce packet even it is the only packet, raise a write
          // error.
          QUIC_DLOG(ERROR) << ENDPOINT << "Failed to coalesce packet";
          result.error_code = WRITE_STATUS_FAILED_TO_COALESCE_PACKET;
          break;
        }
      }
      if (coalesced_packet_.length() < coalesced_packet_.max_packet_length()) {
        QUIC_DVLOG(1) << ENDPOINT << "Trying to set soft max packet length to "
                      << coalesced_packet_.max_packet_length() -
                             coalesced_packet_.length();
        packet_creator_.SetSoftMaxPacketLength(
            coalesced_packet_.max_packet_length() - coalesced_packet_.length());
      }
      last_ecn_codepoint_sent_ = coalesced_packet_.ecn_codepoint();
      break;
    case BUFFER:
      QUIC_DVLOG(1) << ENDPOINT << "Adding packet: " << packet->packet_number
                    << " to buffered packets";
      last_ecn_codepoint_sent_ = GetEcnCodepointToSend(send_to_address);
      buffered_packets_.emplace_back(*packet, send_from_address,
                                     send_to_address, last_ecn_codepoint_sent_,
                                     last_flow_label_sent_);
      break;
    case SEND_TO_WRITER:
      // Stop using coalescer from now on.
      coalescing_done_ = true;
      // At this point, packet->release_encrypted_buffer is either nullptr,
      // meaning |packet->encrypted_buffer| is a stack buffer, or not-nullptr,
      /// meaning it's a writer-allocated buffer. Note that connectivity probing
      // packets do not use this function, so setting release_encrypted_buffer
      // to nullptr will not cause probing packets to be leaked.
      //
      // writer_->WritePacket transfers buffer ownership back to the writer.
      packet->release_encrypted_buffer = nullptr;
      result = SendPacketToWriter(
          packet->encrypted_buffer, encrypted_length, send_from_address.host(),
          send_to_address, writer_, GetEcnCodepointToSend(send_to_address),
          outgoing_flow_label());
      // This is a work around for an issue with linux UDP GSO batch writers.
      // When sending a GSO packet with 2 segments, if the first segment is
      // larger than the path MTU, instead of EMSGSIZE, the linux kernel returns
      // EINVAL, which translates to WRITE_STATUS_ERROR and causes conneciton to
      // be closed. By manually flush the writer here, the MTU probe is sent in
      // a normal(non-GSO) packet, so the kernel can return EMSGSIZE and we will
      // not close the connection.
      if (is_mtu_discovery && writer_->IsBatchMode()) {
        result = writer_->Flush();
      }
      break;
    default:
      QUICHE_DCHECK(false);
      break;
  }

  QUIC_HISTOGRAM_ENUM(
      "QuicConnection.WritePacketStatus", result.status,
      WRITE_STATUS_NUM_VALUES,
      "Status code returned by writer_->WritePacket() in QuicConnection.");

  if (IsWriteBlockedStatus(result.status)) {
    // Ensure the writer is still write blocked, otherwise QUIC may continue
    // trying to write when it will not be able to.
    QUICHE_DCHECK(writer_->IsWriteBlocked());
    visitor_->OnWriteBlocked();
    // If the socket buffers the data, then the packet should not
    // be queued and sent again, which would result in an unnecessary
    // duplicate packet being sent.  The helper must call OnCanWrite
    // when the write completes, and OnWriteError if an error occurs.
    if (result.status != WRITE_STATUS_BLOCKED_DATA_BUFFERED) {
      QUIC_DVLOG(1) << ENDPOINT << "Adding packet: " << packet->packet_number
                    << " to buffered packets";
      buffered_packets_.emplace_back(*packet, send_from_address,
                                     send_to_address, last_ecn_codepoint_sent_,
                                     last_flow_label_sent_);
    }
  }

  // In some cases, an MTU probe can cause EMSGSIZE. This indicates that the
  // MTU discovery is permanently unsuccessful.
  if (IsMsgTooBig(writer_, result)) {
    if (is_mtu_discovery) {
      // When MSG_TOO_BIG is returned, the system typically knows what the
      // actual MTU is, so there is no need to probe further.
      // TODO(wub): Reduce max packet size to a safe default, or the actual MTU.
      QUIC_DVLOG(1) << ENDPOINT
                    << " MTU probe packet too big, size:" << encrypted_length
                    << ", long_term_mtu_:" << long_term_mtu_;
      mtu_discoverer_.Disable();
      mtu_discovery_alarm().Cancel();
      // The write failed, but the writer is not blocked, so return true.
      return true;
    }
    if (!send_on_current_path) {
      // Only handle MSG_TOO_BIG as error on current path.
      return true;
    }
  }

  if (IsWriteError(result.status)) {
    QUIC_LOG_FIRST_N(ERROR, 10)
        << ENDPOINT << "Failed writing packet " << packet_number << " of "
        << encrypted_length << " bytes from " << send_from_address.host()
        << " to " << send_to_address << ", with error code "
        << result.error_code << ". long_term_mtu_:" << long_term_mtu_
        << ", previous_validated_mtu_:" << previous_validated_mtu_
        << ", max_packet_length():" << max_packet_length()
        << ", is_mtu_discovery:" << is_mtu_discovery;
    if (MaybeRevertToPreviousMtu()) {
      return true;
    }

    OnWriteError(result.error_code);
    return false;
  }

  if (result.status == WRITE_STATUS_OK) {
    // packet_send_time is the ideal send time, if allow_burst is true, writer
    // may have sent it earlier than that.
    packet_send_time = packet_send_time + result.send_time_offset;
  }

  if (IsRetransmittable(*packet) == HAS_RETRANSMITTABLE_DATA &&
      !is_termination_packet) {
    // Start blackhole/path degrading detections if the sent packet is not
    // termination packet and contains retransmittable data.
    // Do not restart detection if detection is in progress indicating no
    // forward progress has been made since last event (i.e., packet was sent
    // or new packets were acknowledged).
    if (!blackhole_detector_.IsDetectionInProgress()) {
      // Try to start detections if no detection in progress. This could
      // because either both detections are inactive when sending last packet
      // or this connection just gets out of quiescence.
      blackhole_detector_.RestartDetection(GetPathDegradingDeadline(),
                                           GetNetworkBlackholeDeadline(),
                                           GetPathMtuReductionDeadline());
    }
    idle_network_detector_.OnPacketSent(packet_send_time,
                                        sent_packet_manager_.GetPtoDelay());
  }

  MaybeSetMtuAlarm(packet_number);
  QUIC_DVLOG(1) << ENDPOINT << "time we began writing last sent packet: "
                << packet_send_time.ToDebuggingValue();

  if (IsDefaultPath(default_path_.self_address, send_to_address)) {
    if (EnforceAntiAmplificationLimit()) {
      // Include bytes sent even if they are not in flight.
      default_path_.bytes_sent_before_address_validation += encrypted_length;
    }
  } else {
    MaybeUpdateBytesSentToAlternativeAddress(send_to_address, encrypted_length);
  }

  // Do not measure rtt of this packet if it's not sent on current path.
  QUIC_DLOG_IF(INFO, !send_on_current_path)
      << ENDPOINT << " Sent packet " << packet->packet_number
      << " on a different path with remote address " << send_to_address
      << " while current path has peer address " << peer_address();
  const bool in_flight = sent_packet_manager_.OnPacketSent(
      packet, packet_send_time, packet->transmission_type,
      IsRetransmittable(*packet), /*measure_rtt=*/send_on_current_path,
      last_ecn_codepoint_sent_);
  QUIC_BUG_IF(quic_bug_12714_25,
              perspective_ == Perspective::IS_SERVER &&
                  default_enable_5rto_blackhole_detection_ &&
                  blackhole_detector_.IsDetectionInProgress() &&
                  !sent_packet_manager_.HasInFlightPackets())
      << ENDPOINT
      << "Trying to start blackhole detection without no bytes in flight";

  if (debug_visitor_ != nullptr) {
    if (sent_packet_manager_.unacked_packets().empty()) {
      QUIC_BUG(quic_bug_10511_25)
          << "Unacked map is empty right after packet is sent";
    } else {
      debug_visitor_->OnPacketSent(
          packet->packet_number, packet->encrypted_length,
          packet->has_crypto_handshake, packet->transmission_type,
          packet->encryption_level,
          sent_packet_manager_.unacked_packets()
              .rbegin()
              ->retransmittable_frames,
          packet->nonretransmittable_frames, packet_send_time, result.batch_id);
    }
  }
  if (packet->encryption_level == ENCRYPTION_HANDSHAKE) {
    handshake_packet_sent_ = true;
  }

  if (packet->encryption_level == ENCRYPTION_FORWARD_SECURE) {
    if (!lowest_packet_sent_in_current_key_phase_.IsInitialized()) {
      QUIC_DLOG(INFO) << ENDPOINT
                      << "lowest_packet_sent_in_current_key_phase_ = "
                      << packet_number;
      lowest_packet_sent_in_current_key_phase_ = packet_number;
    }
    if (!is_termination_packet &&
        MaybeHandleAeadConfidentialityLimits(*packet)) {
      return true;
    }
  }
  if (in_flight || !retransmission_alarm().IsSet()) {
    SetRetransmissionAlarm();
  }
  SetPingAlarm();
  RetirePeerIssuedConnectionIdsNoLongerOnPath();

  // The packet number length must be updated after OnPacketSent, because it
  // may change the packet number length in packet.
  packet_creator_.UpdatePacketNumberLength(
      sent_packet_manager_.GetLeastPacketAwaitedByPeer(encryption_level_),
      sent_packet_manager_.EstimateMaxPacketsInFlight(max_packet_length()));

  stats_.bytes_sent += encrypted_length;
  ++stats_.packets_sent;
  if (packet->has_ack_ecn) {
    stats_.num_ack_frames_sent_with_ecn++;
  }

  QuicByteCount bytes_not_retransmitted =
      packet->bytes_not_retransmitted.value_or(0);
  if (packet->transmission_type != NOT_RETRANSMISSION) {
    if (static_cast<uint64_t>(encrypted_length) < bytes_not_retransmitted) {
      QUIC_BUG(quic_packet_bytes_written_lt_bytes_not_retransmitted)
          << "Total bytes written to the packet should be larger than the "
             "bytes in not-retransmitted frames. Bytes written: "
          << encrypted_length
          << ", bytes not retransmitted: " << bytes_not_retransmitted;
    } else {
      // bytes_retransmitted includes packet's headers and encryption
      // overhead.
      stats_.bytes_retransmitted +=
          (encrypted_length - bytes_not_retransmitted);
    }
    ++stats_.packets_retransmitted;
  }

  return true;
}

bool QuicConnection::MaybeHandleAeadConfidentialityLimits(
    const SerializedPacket& packet) {
  if (!version().UsesTls()) {
    return false;
  }

  if (packet.encryption_level != ENCRYPTION_FORWARD_SECURE) {
    QUIC_BUG(quic_bug_12714_26)
        << "MaybeHandleAeadConfidentialityLimits called on non 1-RTT packet";
    return false;
  }
  if (!lowest_packet_sent_in_current_key_phase_.IsInitialized()) {
    QUIC_BUG(quic_bug_10511_26)
        << "lowest_packet_sent_in_current_key_phase_ must be initialized "
           "before calling MaybeHandleAeadConfidentialityLimits";
    return false;
  }

  // Calculate the number of packets encrypted from the packet number, which is
  // simpler than keeping another counter. The packet number space may be
  // sparse, so this might overcount, but doing a key update earlier than
  // necessary would only improve security and has negligible cost.
  if (packet.packet_number < lowest_packet_sent_in_current_key_phase_) {
    const std::string error_details =
        absl::StrCat("packet_number(", packet.packet_number.ToString(),
                     ") < lowest_packet_sent_in_current_key_phase_ (",
                     lowest_packet_sent_in_current_key_phase_.ToString(), ")");
    QUIC_BUG(quic_bug_10511_27) << error_details;
    CloseConnection(QUIC_INTERNAL_ERROR, error_details,
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return true;
  }
  const QuicPacketCount num_packets_encrypted_in_current_key_phase =
      packet.packet_number - lowest_packet_sent_in_current_key_phase_ + 1;

  const QuicPacketCount confidentiality_limit =
      framer_.GetOneRttEncrypterConfidentialityLimit();

  // Attempt to initiate a key update before reaching the AEAD
  // confidentiality limit when the number of packets sent in the current
  // key phase gets within |kKeyUpdateConfidentialityLimitOffset| packets of
  // the limit, unless overridden by
  // FLAGS_quic_key_update_confidentiality_limit.
  constexpr QuicPacketCount kKeyUpdateConfidentialityLimitOffset = 1000;
  QuicPacketCount key_update_limit = 0;
  if (confidentiality_limit > kKeyUpdateConfidentialityLimitOffset) {
    key_update_limit =
        confidentiality_limit - kKeyUpdateConfidentialityLimitOffset;
  }
  const QuicPacketCount key_update_limit_override =
      GetQuicFlag(quic_key_update_confidentiality_limit);
  if (key_update_limit_override) {
    key_update_limit = key_update_limit_override;
  }

  QUIC_DVLOG(2) << ENDPOINT << "Checking AEAD confidentiality limits: "
                << "num_packets_encrypted_in_current_key_phase="
                << num_packets_encrypted_in_current_key_phase
                << " key_update_limit=" << key_update_limit
                << " confidentiality_limit=" << confidentiality_limit
                << " IsKeyUpdateAllowed()=" << IsKeyUpdateAllowed();

  if (num_packets_encrypted_in_current_key_phase >= confidentiality_limit) {
    // Reached the confidentiality limit without initiating a key update,
    // must close the connection.
    const std::string error_details = absl::StrCat(
        "encrypter confidentiality limit reached: "
        "num_packets_encrypted_in_current_key_phase=",
        num_packets_encrypted_in_current_key_phase,
        " key_update_limit=", key_update_limit,
        " confidentiality_limit=", confidentiality_limit,
        " IsKeyUpdateAllowed()=", IsKeyUpdateAllowed());
    CloseConnection(QUIC_AEAD_LIMIT_REACHED, error_details,
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return true;
  }

  if (IsKeyUpdateAllowed() &&
      num_packets_encrypted_in_current_key_phase >= key_update_limit) {
    // Approaching the confidentiality limit, initiate key update so that
    // the next set of keys will be ready for the next packet before the
    // limit is reached.
    KeyUpdateReason reason = KeyUpdateReason::kLocalAeadConfidentialityLimit;
    if (key_update_limit_override) {
      QUIC_DLOG(INFO) << ENDPOINT
                      << "reached FLAGS_quic_key_update_confidentiality_limit, "
                         "initiating key update: "
                      << "num_packets_encrypted_in_current_key_phase="
                      << num_packets_encrypted_in_current_key_phase
                      << " key_update_limit=" << key_update_limit
                      << " confidentiality_limit=" << confidentiality_limit;
      reason = KeyUpdateReason::kLocalKeyUpdateLimitOverride;
    } else {
      QUIC_DLOG(INFO) << ENDPOINT
                      << "approaching AEAD confidentiality limit, "
                         "initiating key update: "
                      << "num_packets_encrypted_in_current_key_phase="
                      << num_packets_encrypted_in_current_key_phase
                      << " key_update_limit=" << key_update_limit
                      << " confidentiality_limit=" << confidentiality_limit;
    }
    InitiateKeyUpdate(reason);
  }

  return false;
}

void QuicConnection::FlushPackets() {
  if (!connected_) {
    return;
  }

  if (!writer_->IsBatchMode()) {
    return;
  }

  if (HandleWriteBlocked()) {
    QUIC_DLOG(INFO) << ENDPOINT << "FlushPackets called while blocked.";
    return;
  }

  WriteResult result = writer_->Flush();

  QUIC_HISTOGRAM_ENUM("QuicConnection.FlushPacketStatus", result.status,
                      WRITE_STATUS_NUM_VALUES,
                      "Status code returned by writer_->Flush() in "
                      "QuicConnection::FlushPackets.");

  if (HandleWriteBlocked()) {
    QUICHE_DCHECK_EQ(WRITE_STATUS_BLOCKED, result.status)
        << "Unexpected flush result:" << result;
    QUIC_DLOG(INFO) << ENDPOINT << "Write blocked in FlushPackets.";
    return;
  }

  if (IsWriteError(result.status) && !MaybeRevertToPreviousMtu()) {
    OnWriteError(result.error_code);
  }
}

bool QuicConnection::IsMsgTooBig(const QuicPacketWriter* writer,
                                 const WriteResult& result) {
  std::optional<int> writer_error_code = writer->MessageTooBigErrorCode();
  return (result.status == WRITE_STATUS_MSG_TOO_BIG) ||
         (writer_error_code.has_value() && IsWriteError(result.status) &&
          result.error_code == *writer_error_code);
}

bool QuicConnection::ShouldDiscardPacket(EncryptionLevel encryption_level) {
  if (!connected_) {
    QUIC_DLOG(INFO) << ENDPOINT
                    << "Not sending packet as connection is disconnected.";
    return true;
  }

  if (encryption_level_ == ENCRYPTION_FORWARD_SECURE &&
      encryption_level == ENCRYPTION_INITIAL) {
    // Drop packets that are NULL encrypted since the peer won't accept them
    // anymore.
    QUIC_DLOG(INFO) << ENDPOINT
                    << "Dropping NULL encrypted packet since the connection is "
                       "forward secure.";
    return true;
  }

  return false;
}

QuicTime QuicConnection::GetPathMtuReductionDeadline() const {
  if (previous_validated_mtu_ == 0) {
    return QuicTime::Zero();
  }
  QuicTime::Delta delay = sent_packet_manager_.GetMtuReductionDelay(
      num_rtos_for_blackhole_detection_);
  if (delay.IsZero()) {
    return QuicTime::Zero();
  }
  return clock_->ApproximateNow() + delay;
}

bool QuicConnection::MaybeRevertToPreviousMtu() {
  if (previous_validated_mtu_ == 0) {
    return false;
  }

  SetMaxPacketLength(previous_validated_mtu_);
  mtu_discoverer_.Disable();
  mtu_discovery_alarm().Cancel();
  previous_validated_mtu_ = 0;
  return true;
}

void QuicConnection::OnWriteError(int error_code) {
  if (write_error_occurred_) {
    // A write error already occurred. The connection is being closed.
    return;
  }
  write_error_occurred_ = true;

  const std::string error_details = absl::StrCat(
      "Write failed with error: ", error_code, " (", strerror(error_code), ")");
  QUIC_LOG_FIRST_N(ERROR, 2) << ENDPOINT << error_details;
  std::optional<int> writer_error_code = writer_->MessageTooBigErrorCode();
  if (writer_error_code.has_value() && error_code == *writer_error_code) {
    CloseConnection(QUIC_PACKET_WRITE_ERROR, error_details,
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }
  // We can't send an error as the socket is presumably borked.
  QUIC_CODE_COUNT(quic_tear_down_local_connection_on_write_error_ietf);
  CloseConnection(QUIC_PACKET_WRITE_ERROR, error_details,
                  ConnectionCloseBehavior::SILENT_CLOSE);
}

QuicPacketBuffer QuicConnection::GetPacketBuffer() {
  if (version().CanSendCoalescedPackets() && !coalescing_done_) {
    // Do not use writer's packet buffer for coalesced packets which may
    // contain multiple QUIC packets.
    return {nullptr, nullptr};
  }
  return writer_->GetNextWriteLocation(self_address().host(), peer_address());
}

void QuicConnection::OnSerializedPacket(SerializedPacket serialized_packet) {
  if (serialized_packet.encrypted_buffer == nullptr) {
    // We failed to serialize the packet, so close the connection.
    // Specify that the close is silent, that no packet be sent, so no infinite
    // loop here.
    // TODO(ianswett): This is actually an internal error, not an
    // encryption failure.
    QUIC_CODE_COUNT(quic_tear_down_local_connection_on_serialized_packet_ietf);
    CloseConnection(QUIC_ENCRYPTION_FAILURE,
                    "Serialized packet does not have an encrypted buffer.",
                    ConnectionCloseBehavior::SILENT_CLOSE);
    return;
  }

  if (serialized_packet.retransmittable_frames.empty()) {
    // Increment consecutive_num_packets_with_no_retransmittable_frames_ if
    // this packet is a new transmission with no retransmittable frames.
    ++consecutive_num_packets_with_no_retransmittable_frames_;
  } else {
    consecutive_num_packets_with_no_retransmittable_frames_ = 0;
  }
  if (retransmittable_on_wire_behavior_ == SEND_FIRST_FORWARD_SECURE_PACKET &&
      first_serialized_one_rtt_packet_ == nullptr &&
      serialized_packet.encryption_level == ENCRYPTION_FORWARD_SECURE) {
    first_serialized_one_rtt_packet_ = std::make_unique<BufferedPacket>(
        serialized_packet, self_address(), peer_address(),
        GetEcnCodepointToSend(peer_address()), outgoing_flow_label());
  }
  SendOrQueuePacket(std::move(serialized_packet));
}

void QuicConnection::OnUnrecoverableError(QuicErrorCode error,
                                          const std::string& error_details) {
  // The packet creator or generator encountered an unrecoverable error: tear
  // down local connection state immediately.
  QUIC_CODE_COUNT(quic_tear_down_local_connection_on_unrecoverable_error_ietf);
  CloseConnection(error, error_details, ConnectionCloseBehavior::SILENT_CLOSE);
}

void QuicConnection::OnCongestionChange() {
  visitor_->OnCongestionWindowChange(clock_->ApproximateNow());

  // Uses the connection's smoothed RTT. If zero, uses initial_rtt.
  QuicTime::Delta rtt = sent_packet_manager_.GetRttStats()->smoothed_rtt();
  if (rtt.IsZero()) {
    rtt = sent_packet_manager_.GetRttStats()->initial_rtt();
  }

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnRttChanged(rtt);
  }
}

void QuicConnection::OnPathMtuIncreased(QuicPacketLength packet_size) {
  if (packet_size > max_packet_length()) {
    previous_validated_mtu_ = max_packet_length();
    SetMaxPacketLength(packet_size);
    mtu_discoverer_.OnMaxPacketLengthUpdated(previous_validated_mtu_,
                                             max_packet_length());
  }
}

void QuicConnection::OnInFlightEcnPacketAcked() {
  QUIC_BUG_IF(quic_bug_518619343_01, !GetQuicRestartFlag(quic_support_ect1))
      << "Unexpected call to OnInFlightEcnPacketAcked()";
  // Only packets on the default path are in-flight.
  if (!default_path_.ecn_marked_packet_acked) {
    QUIC_DVLOG(1) << ENDPOINT << "First ECT packet acked on active path.";
    QUIC_RESTART_FLAG_COUNT_N(quic_support_ect1, 2, 9);
    default_path_.ecn_marked_packet_acked = true;
  }
}

void QuicConnection::OnInvalidEcnFeedback() {
  QUIC_BUG_IF(quic_bug_518619343_02, !GetQuicRestartFlag(quic_support_ect1))
      << "Unexpected call to OnInvalidEcnFeedback().";
  if (disable_ecn_codepoint_validation_) {
    // In some tests, senders may send ECN marks in patterns that are not
    // in accordance with the spec, and should not fail validation as a result.
    return;
  }
  QUIC_DVLOG(1) << ENDPOINT << "ECN feedback is invalid, stop marking.";
  packet_writer_params_.ecn_codepoint = ECN_NOT_ECT;
}

std::unique_ptr<QuicSelfIssuedConnectionIdManager>
QuicConnection::MakeSelfIssuedConnectionIdManager() {
  QUICHE_DCHECK((perspective_ == Perspective::IS_CLIENT &&
                 !default_path_.client_connection_id.IsEmpty()) ||
                (perspective_ == Perspective::IS_SERVER &&
                 !default_path_.server_connection_id.IsEmpty()));
  return std::make_unique<QuicSelfIssuedConnectionIdManager>(
      kMinNumOfActiveConnectionIds,
      perspective_ == Perspective::IS_CLIENT
          ? default_path_.client_connection_id
          : default_path_.server_connection_id,
      clock_, alarm_factory_, this, context(), connection_id_generator_);
}

void QuicConnection::MaybeSendConnectionIdToClient() {
  if (perspective_ == Perspective::IS_CLIENT) {
    return;
  }
  QUICHE_DCHECK(self_issued_cid_manager_ != nullptr);
  self_issued_cid_manager_->MaybeSendNewConnectionIds();
}

void QuicConnection::OnHandshakeComplete() {
  sent_packet_manager_.SetHandshakeConfirmed();
  if (version().HasIetfQuicFrames() && perspective_ == Perspective::IS_SERVER &&
      self_issued_cid_manager_ != nullptr) {
    self_issued_cid_manager_->MaybeSendNewConnectionIds();
  }
  if (send_ack_frequency_on_handshake_completion_ &&
      sent_packet_manager_.CanSendAckFrequency()) {
    QUIC_RELOADABLE_FLAG_COUNT_N(quic_can_send_ack_frequency, 2, 3);
    auto ack_frequency_frame =
        sent_packet_manager_.GetUpdatedAckFrequencyFrame();
    // This AckFrequencyFrame is meant to only update the max_ack_delay. Set
    // packet tolerance to the default value for now.
    ack_frequency_frame.packet_tolerance =
        kDefaultRetransmittablePacketsBeforeAck;
    visitor_->SendAckFrequency(ack_frequency_frame);
    if (!connected_) {
      return;
    }
  }
  // This may have changed the retransmission timer, so re-arm it.
  SetRetransmissionAlarm();
  if (default_enable_5rto_blackhole_detection_) {
    QUIC_RELOADABLE_FLAG_COUNT_N(quic_default_enable_5rto_blackhole_detection2,
                                 2, 3);
    OnForwardProgressMade();
  }
  if (!SupportsMultiplePacketNumberSpaces()) {
    // The client should immediately ack the SHLO to confirm the handshake is
    // complete with the server.
    if (perspective_ == Perspective::IS_CLIENT && ack_frame_updated()) {
      ack_alarm().Update(clock_->ApproximateNow(), QuicTime::Delta::Zero());
    }
    return;
  }
  // Stop sending ack of handshake packet number space.
  uber_received_packet_manager_.ResetAckStates(ENCRYPTION_HANDSHAKE);
  // Re-arm ack alarm.
  ack_alarm().Update(uber_received_packet_manager_.GetEarliestAckTimeout(),
                     kAlarmGranularity);
  if (!accelerated_server_preferred_address_ &&
      received_server_preferred_address_.IsInitialized()) {
```