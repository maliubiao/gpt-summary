Response:
The user wants a summary of the functionalities of the C++ code snippet from `net/third_party/quiche/src/quiche/quic/core/quic_connection.cc`. They are specifically interested in:

1. **Listing the functionalities** of the provided code.
2. **Identifying connections to JavaScript**, with illustrative examples.
3. **Providing examples of logical reasoning** with assumed inputs and outputs.
4. **Highlighting common user/programming errors** with examples.
5. **Tracing user operations** leading to this code as debugging clues.
6. **Summarizing the functionality** of this specific section (part 7 of 10).

Let's break down the provided code and address each of these points:

**Code Breakdown:**

The code snippet focuses on several key aspects of a QUIC connection:

* **Scoped Packet Flushing:** Manages the timing of checking for application-limited sending and retransmission alarms.
* **Scoped Encryption Level Context:** Temporarily changes the encryption level for certain operations.
* **Buffered Packets:** Represents a buffered QUIC packet.
* **Received Packet Information:**  Stores information about a received packet.
* **Packet Classification:**  Determines if a packet contains retransmittable data or is a termination packet.
* **MTU Discovery:** Manages the process of finding the maximum transmission unit.
* **Connectivity Probing:**  Sends packets to check network reachability.
* **Peer Migration:** Handles changes in the peer's IP address or port.
* **Packet Content Analysis:**  Examines the frames within a received packet for various purposes, including identifying connectivity probes and triggering peer migration.
* **Application Limited State:**  Determines if the application is the bottleneck in sending data.

**Addressing the User's Requests:**

1. **Functionalities:** List each of the identified areas above.
2. **JavaScript Relationship:** Focus on how the QUIC connection lifecycle and state (like connection migration) might be reported to JavaScript through Chromium's networking APIs. Consider events or properties exposed to the web layer.
3. **Logical Reasoning:**  Choose specific scenarios like MTU discovery or peer migration and provide a simplified "if input X, then output Y" example based on the code.
4. **User/Programming Errors:** Think about how a developer might misuse the `ScopedPacketFlusher` or how incorrect configuration might impact MTU discovery.
5. **User Operations & Debugging:** Connect user actions like navigating a website or a connection interruption to the execution of the code.
6. **Summary of Part 7:** Condense the identified functionalities into a concise summary of this particular section of the `QuicConnection` class.
这是对 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_connection.cc` 文件的一部分代码的功能进行分析。根据提供的代码片段，我们可以归纳出以下功能：

**功能列表：**

1. **管理数据包刷新的作用域 (ScopedPacketFlusher):**
   - 在其生命周期结束时，检查连接是否受到应用程序限制（即应用程序没有更多数据发送）。
   - 在其生命周期结束时，如果需要，设置重传告警。
   - 暂停和恢复底层告警的调度。

2. **管理加密级别上下文的作用域 (ScopedEncryptionLevelContext):**
   - 允许在特定代码块内临时更改连接的默认加密级别。
   - 在作用域结束时，恢复到之前的加密级别。

3. **表示缓冲的数据包 (BufferedPacket):**
   - 存储已加密的数据包内容、长度、源地址、目标地址、ECN 标记和流标签。
   - 提供了不同的构造函数来创建缓冲数据包，包括从已序列化的数据包创建和分配随机数据。

4. **存储接收到的数据包信息 (ReceivedPacketInfo):**
   - 记录接收数据包的时间、源地址、目标地址、长度、ECN 标记、流标签等信息。
   - 如果数据包已解密，则包含解密后的加密级别、头部信息和帧信息。

5. **判断数据包是否包含可重传数据 (IsRetransmittable):**
   - 检查数据包的传输类型和是否包含可重传帧来判断。

6. **判断数据包是否是终止连接的数据包 (IsTerminationPacket):**
   - 检查数据包中是否包含 `CONNECTION_CLOSE` 类型的帧。

7. **设置 MTU 发现的目标值 (SetMtuDiscoveryTarget):**
   - 禁用当前的 MTU 发现机制，并启用新的目标值，但会限制在允许的最大数据包大小内。

8. **获取受限的最大数据包大小 (GetLimitedMaxPacketSize):**
   - 根据对端地址、写入器限制、对端最大数据包大小和全局最大值来确定实际可以发送的最大数据包大小。

9. **发送 MTU 发现数据包 (SendMtuDiscoveryPacket):**
   - 使用指定的目标 MTU 生成并发送一个探测数据包。

10. **发送连通性探测数据包 (SendConnectivityProbingPacket):**
    - 发送一个探测数据包到对端，以验证网络连通性。
    - 对于非 IETF QUIC，发送一个填充的 PING 帧。
    - 对于 IETF QUIC，发送一个 PATH_CHALLENGE 帧。
    - 可以使用默认的写入器或提供的特定写入器发送。

11. **使用指定的写入器发送数据包 (WritePacketUsingWriter):**
    - 将序列化的数据包通过指定的写入器发送出去。
    - 记录发送时间，处理写入结果，并在发送后更新发送数据包管理器和调试访问器。

12. **禁用 MTU 发现 (DisableMtuDiscovery):**
    - 停止 MTU 发现机制并取消相关的告警。

13. **处理 MTU 发现告警 (OnMtuDiscoveryAlarm):**
    - 检查是否应该发送新的 MTU 探测数据包，并根据 MTU 发现器的建议发送。

14. **处理有效的对端迁移验证 (OnEffectivePeerMigrationValidated):**
    - 在对端迁移验证成功后执行相关操作，例如更新统计信息、移除反放大限制，并可能发送地址令牌。

15. **启动有效的对端迁移 (StartEffectivePeerMigration):**
    - 处理对端 IP 地址或端口发生变化的情况。
    - 更新连接状态、拥塞控制器、路径信息，并可能启动反向路径验证。

16. **处理连接迁移事件 (OnConnectionMigration):**
    - 通知访问器连接迁移事件，并更新相关统计信息。

17. **判断当前数据包是否是连通性探测包 (IsCurrentPacketConnectivityProbing):**
    - 返回一个标志，指示当前正在处理的数据包是否被认为是连通性探测包。

18. **判断 ACK 帧是否已更新 (ack_frame_updated):**
    - 查询接收到的数据包管理器，判断 ACK 帧是否有更新。

19. **获取当前数据包的内容 (GetCurrentPacket):**
    - 返回当前正在处理的数据包的原始数据。

20. **判断接收到的帧是否可能表示内存损坏 (MaybeConsiderAsMemoryCorruption):**
    - 检查接收到的流帧是否可能是由于内存损坏引起的，例如在加密级别为 INITIAL 时收到类似 CHLO 或 REJ 的数据。

21. **检查是否受到应用程序限制 (CheckIfApplicationLimited):**
    - 判断连接是否因为应用程序没有更多数据发送而受到限制。

22. **更新数据包内容信息 (UpdatePacketContent):**
    - 记录接收到的数据包中包含的帧类型。
    - 对于 IETF QUIC，根据收到的帧类型可能触发对端迁移的判断和处理，以及更新从备用地址接收的字节数。
    - 对于 Google QUIC，用于识别填充的 PING 数据包，并判断是否为连通性探测包，从而触发相应的对端迁移处理。

23. **尝试启动 IETF 对端迁移 (MaybeStartIetfPeerMigration):**
    - 仅在 IETF QUIC 中生效，检查在握手完成前是否发生了对端迁移，如果发生则关闭连接。
    - 如果收到的数据包是最新接收到的数据包，且发生了待处理的对端迁移，则启动对端迁移流程。

**与 JavaScript 的关系：**

QUIC 协议在 Chromium 中作为底层网络协议实现，JavaScript 代码本身并不直接操作 `QuicConnection` 对象。然而，JavaScript 通过 Chromium 提供的 Web API (例如 `fetch`, `WebSocket`) 发起网络请求时，这些请求最终会使用底层的 QUIC 连接。

* **连接状态通知:** 当 QUIC 连接发生状态变化（例如连接迁移）时，`QuicConnection` 的状态变化可能会通过 Chromium 的内部机制通知到上层的 JavaScript 代码。例如，一个网络请求可能因为连接迁移而短暂中断然后恢复，这可能会影响 JavaScript 中 `fetch` API 返回的 Promise 的 resolve 或 reject。
* **网络性能指标:**  QUIC 连接的性能指标，如 RTT、丢包率等，会被 Chromium 收集并可能通过 Performance API 或 Network Information API 暴露给 JavaScript，帮助开发者了解网络状况。
* **错误处理:** 当 QUIC 连接遇到错误（例如，`QUIC_PEER_PORT_CHANGE_HANDSHAKE_UNCONFIRMED`）导致连接关闭时，这个错误可能会通过 JavaScript 的错误回调函数传递给开发者。

**举例说明：**

假设一个用户在网页上点击了一个按钮，触发了一个使用 `fetch` API 发起的网络请求。

1. **用户操作:** 点击按钮。
2. **JavaScript 代码:**  执行 `fetch('https://example.com/data')`.
3. **Chromium 网络栈:**
   - 如果与 `example.com` 的连接是 QUIC 连接，则会涉及 `QuicConnection` 对象的处理。
   - 如果在请求过程中，用户的网络环境发生变化，导致客户端 IP 地址或端口变化，`StartEffectivePeerMigration` 函数可能会被调用。
   - 如果对端响应了一个填充的 PING 数据包，`UpdatePacketContent` 可能会将其识别为连通性探测包。
   - 如果连接因为网络问题需要重新协商 MTU，`SetMtuDiscoveryTarget` 和 `SendMtuDiscoveryPacket` 可能会被调用。
4. **JavaScript 结果:**  `fetch` 返回的 Promise 可能会在连接迁移完成后 resolve，或者如果迁移失败，可能会 reject 并抛出错误。

**逻辑推理示例：**

**假设输入：**

* `connection_->packet_creator_.PacketFlusherAttached()` 返回 `false`。
* `connection_->pending_retransmission_alarm_` 为 `true`。

**执行的代码:**

```c++
  if (!active_) {
    // ...
    if (connection_->pending_retransmission_alarm_) {
      connection_->SetRetransmissionAlarm();
      connection_->pending_retransmission_alarm_ = false;
    }
    // ...
  }
```

**输出：**

* `connection_->SetRetransmissionAlarm()` 将被调用，设置重传告警。
* `connection_->pending_retransmission_alarm_` 将被设置为 `false`。

**用户或编程常见的使用错误：**

1. **不恰当的使用 `ScopedPacketFlusher`:** 如果在需要批量发送多个数据包时，每次发送一个数据包都创建一个 `ScopedPacketFlusher`，可能会导致过早地检查应用程序限制，即使应用程序仍然有数据要发送。这可能会降低发送效率。

   ```c++
   // 错误的做法：
   for (const auto& data_chunk : data_chunks) {
     {
       QuicConnection::ScopedPacketFlusher flusher(connection_);
       connection_->SendData(stream_id, data_chunk, /*fin=*/false);
     } // 每次循环结束都会检查应用程序限制
   }

   // 正确的做法：
   {
     QuicConnection::ScopedPacketFlusher flusher(connection_);
     for (const auto& data_chunk : data_chunks) {
       connection_->SendData(stream_id, data_chunk, /*fin=*/false);
     }
   } // 在所有数据块发送完成后才检查应用程序限制
   ```

2. **MTU 发现配置错误:**  如果 MTU 发现的目标值设置过高，超过了网络路径的最大传输能力，可能会导致数据包被分片或丢弃，影响连接性能。

**用户操作是如何一步步的到达这里，作为调试线索：**

以 `StartEffectivePeerMigration` 为例：

1. **用户操作:** 用户在移动设备上浏览网页，从 Wi-Fi 网络切换到移动蜂窝网络。
2. **操作系统事件:** 操作系统检测到网络接口的变化，IP 地址或端口可能发生改变。
3. **Chromium 网络栈:**
   - 底层网络库检测到本地网络地址的变化。
   - 接收到来自对端的属于新地址的数据包。
   - `QuicConnection::OnIncomingData` 函数被调用。
   - 数据包被解析，发现对端的地址发生了变化。
   - 根据配置和协议版本，`StartEffectivePeerMigration` 函数被调用，以处理对端地址的变更。

**这是第 7 部分，共 10 部分，请归纳一下它的功能:**

这部分代码主要负责 **连接生命周期中的关键管理和事件处理**，包括：

* **优化数据包发送:** 通过 `ScopedPacketFlusher` 管理应用程序限制和重传告警。
* **控制加密级别:** 通过 `ScopedEncryptionLevelContext` 临时调整加密设置。
* **数据包的表示和信息记录:**  定义了 `BufferedPacket` 和 `ReceivedPacketInfo` 来存储和管理数据包相关的信息。
* **网络层的功能:**  实现了 MTU 发现和连通性探测机制，以优化网络传输和检测网络连通性。
* **连接迁移的核心处理:**  处理对端 IP 地址或端口的变化，是连接保持活跃和稳定的关键部分。
* **数据包内容的分析:**  用于识别特定类型的数据包（如连通性探测包）并触发相应的处理逻辑。

总的来说，这部分代码关注于 QUIC 连接在数据发送、接收以及网络环境变化时的内部管理和控制，是保证 QUIC 连接可靠性和性能的重要组成部分。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共10部分，请归纳一下它的功能

"""
e congestion controller if not.
    //
    // Note that this means that the application limited check will happen as
    // soon as the last flusher gets destroyed, which is typically after a
    // single stream write is finished.  This means that if all the data from a
    // single write goes through the connection, the application-limited signal
    // will fire even if the caller does a write operation immediately after.
    // There are two important approaches to remedy this situation:
    // (1) Instantiate ScopedPacketFlusher before performing multiple subsequent
    //     writes, thus deferring this check until all writes are done.
    // (2) Write data in chunks sufficiently large so that they cause the
    //     connection to be limited by the congestion control.  Typically, this
    //     would mean writing chunks larger than the product of the current
    //     pacing rate and the pacer granularity.  So, for instance, if the
    //     pacing rate of the connection is 1 Gbps, and the pacer granularity is
    //     1 ms, the caller should send at least 125k bytes in order to not
    //     be marked as application-limited.
    connection_->CheckIfApplicationLimited();

    if (connection_->pending_retransmission_alarm_) {
      connection_->SetRetransmissionAlarm();
      connection_->pending_retransmission_alarm_ = false;
    }

    connection_->alarms_.ResumeUnderlyingAlarmScheduling();
  }
  QUICHE_DCHECK_EQ(active_,
                   !connection_->packet_creator_.PacketFlusherAttached());
}

QuicConnection::ScopedEncryptionLevelContext::ScopedEncryptionLevelContext(
    QuicConnection* connection, EncryptionLevel encryption_level)
    : connection_(connection), latched_encryption_level_(ENCRYPTION_INITIAL) {
  if (connection_ == nullptr) {
    return;
  }
  latched_encryption_level_ = connection_->encryption_level_;
  connection_->SetDefaultEncryptionLevel(encryption_level);
}

QuicConnection::ScopedEncryptionLevelContext::~ScopedEncryptionLevelContext() {
  if (connection_ == nullptr || !connection_->connected_) {
    return;
  }
  connection_->SetDefaultEncryptionLevel(latched_encryption_level_);
}

QuicConnection::BufferedPacket::BufferedPacket(
    const SerializedPacket& packet, const QuicSocketAddress& self_address,
    const QuicSocketAddress& peer_address, const QuicEcnCodepoint ecn_codepoint,
    uint32_t flow_label)
    : BufferedPacket(packet.encrypted_buffer, packet.encrypted_length,
                     self_address, peer_address, ecn_codepoint, flow_label) {}

QuicConnection::BufferedPacket::BufferedPacket(
    const char* encrypted_buffer, QuicPacketLength encrypted_length,
    const QuicSocketAddress& self_address,
    const QuicSocketAddress& peer_address, const QuicEcnCodepoint ecn_codepoint,
    uint32_t flow_label)
    : length(encrypted_length),
      self_address(self_address),
      peer_address(peer_address),
      ecn_codepoint(ecn_codepoint),
      flow_label(flow_label) {
  data = std::make_unique<char[]>(encrypted_length);
  memcpy(data.get(), encrypted_buffer, encrypted_length);
}

QuicConnection::BufferedPacket::BufferedPacket(
    QuicRandom& random, QuicPacketLength encrypted_length,
    const QuicSocketAddress& self_address,
    const QuicSocketAddress& peer_address)
    : length(encrypted_length),
      self_address(self_address),
      peer_address(peer_address) {
  data = std::make_unique<char[]>(encrypted_length);
  random.RandBytes(data.get(), encrypted_length);
}

QuicConnection::ReceivedPacketInfo::ReceivedPacketInfo(QuicTime receipt_time)
    : receipt_time(receipt_time) {}

QuicConnection::ReceivedPacketInfo::ReceivedPacketInfo(
    const QuicSocketAddress& destination_address,
    const QuicSocketAddress& source_address, QuicTime receipt_time,
    QuicByteCount length, QuicEcnCodepoint ecn_codepoint, uint32_t flow_label)
    : destination_address(destination_address),
      source_address(source_address),
      receipt_time(receipt_time),
      length(length),
      ecn_codepoint(ecn_codepoint),
      flow_label(flow_label) {}

std::ostream& operator<<(std::ostream& os,
                         const QuicConnection::ReceivedPacketInfo& info) {
  os << " { destination_address: " << info.destination_address.ToString()
     << ", source_address: " << info.source_address.ToString()
     << ", received_bytes_counted: " << info.received_bytes_counted
     << ", length: " << info.length
     << ", destination_connection_id: " << info.destination_connection_id;
  if (!info.decrypted) {
    os << " }\n";
    return os;
  }
  os << ", decrypted: " << info.decrypted
     << ", decrypted_level: " << EncryptionLevelToString(info.decrypted_level)
     << ", header: " << info.header << ", frames: ";
  for (const auto frame : info.frames) {
    os << frame;
  }
  os << " }\n";
  return os;
}

HasRetransmittableData QuicConnection::IsRetransmittable(
    const SerializedPacket& packet) {
  // Retransmitted packets retransmittable frames are owned by the unacked
  // packet map, but are not present in the serialized packet.
  if (packet.transmission_type != NOT_RETRANSMISSION ||
      !packet.retransmittable_frames.empty()) {
    return HAS_RETRANSMITTABLE_DATA;
  } else {
    return NO_RETRANSMITTABLE_DATA;
  }
}

bool QuicConnection::IsTerminationPacket(const SerializedPacket& packet,
                                         QuicErrorCode* error_code) {
  if (packet.retransmittable_frames.empty()) {
    return false;
  }
  for (const QuicFrame& frame : packet.retransmittable_frames) {
    if (frame.type == CONNECTION_CLOSE_FRAME) {
      *error_code = frame.connection_close_frame->quic_error_code;
      return true;
    }
  }
  return false;
}

void QuicConnection::SetMtuDiscoveryTarget(QuicByteCount target) {
  QUIC_DVLOG(2) << ENDPOINT << "SetMtuDiscoveryTarget: " << target;
  mtu_discoverer_.Disable();
  mtu_discoverer_.Enable(max_packet_length(), GetLimitedMaxPacketSize(target));
}

QuicByteCount QuicConnection::GetLimitedMaxPacketSize(
    QuicByteCount suggested_max_packet_size) {
  if (!peer_address().IsInitialized()) {
    QUIC_BUG(quic_bug_10511_30)
        << "Attempted to use a connection without a valid peer address";
    return suggested_max_packet_size;
  }

  const QuicByteCount writer_limit = writer_->GetMaxPacketSize(peer_address());

  QuicByteCount max_packet_size = suggested_max_packet_size;
  if (max_packet_size > writer_limit) {
    max_packet_size = writer_limit;
  }
  if (max_packet_size > peer_max_packet_size_) {
    max_packet_size = peer_max_packet_size_;
  }
  if (max_packet_size > kMaxOutgoingPacketSize) {
    max_packet_size = kMaxOutgoingPacketSize;
  }
  return max_packet_size;
}

void QuicConnection::SendMtuDiscoveryPacket(QuicByteCount target_mtu) {
  // Currently, this limit is ensured by the caller.
  QUICHE_DCHECK_EQ(target_mtu, GetLimitedMaxPacketSize(target_mtu));

  // Send the probe.
  packet_creator_.GenerateMtuDiscoveryPacket(target_mtu);
}

// TODO(zhongyi): change this method to generate a connectivity probing packet
// and let the caller to call writer to write the packet and handle write
// status.
bool QuicConnection::SendConnectivityProbingPacket(
    QuicPacketWriter* probing_writer, const QuicSocketAddress& peer_address) {
  QUICHE_DCHECK(peer_address.IsInitialized());
  if (!connected_) {
    QUIC_BUG(quic_bug_10511_31)
        << "Not sending connectivity probing packet as connection is "
        << "disconnected.";
    return false;
  }
  if (perspective_ == Perspective::IS_SERVER && probing_writer == nullptr) {
    // Server can use default packet writer to write packet.
    probing_writer = writer_;
  }
  QUICHE_DCHECK(probing_writer);

  if (probing_writer->IsWriteBlocked()) {
    QUIC_DLOG(INFO)
        << ENDPOINT
        << "Writer blocked when sending connectivity probing packet.";
    if (probing_writer == writer_) {
      // Visitor should not be write blocked if the probing writer is not the
      // default packet writer.
      visitor_->OnWriteBlocked();
    }
    return true;
  }

  QUIC_DLOG(INFO) << ENDPOINT
                  << "Sending path probe packet for connection_id = "
                  << default_path_.server_connection_id;

  std::unique_ptr<SerializedPacket> probing_packet;
  if (!version().HasIetfQuicFrames()) {
    // Non-IETF QUIC, generate a padded ping regardless of whether this is a
    // request or a response.
    probing_packet = packet_creator_.SerializeConnectivityProbingPacket();
  } else {
    // IETF QUIC path challenge.
    // Send a path probe request using IETF QUIC PATH_CHALLENGE frame.
    QuicPathFrameBuffer transmitted_connectivity_probe_payload;
    random_generator_->RandBytes(&transmitted_connectivity_probe_payload,
                                 sizeof(QuicPathFrameBuffer));
    probing_packet =
        packet_creator_.SerializePathChallengeConnectivityProbingPacket(
            transmitted_connectivity_probe_payload);
  }
  QUICHE_DCHECK_EQ(IsRetransmittable(*probing_packet), NO_RETRANSMITTABLE_DATA);
  return WritePacketUsingWriter(std::move(probing_packet), probing_writer,
                                self_address(), peer_address,
                                /*measure_rtt=*/true);
}

bool QuicConnection::WritePacketUsingWriter(
    std::unique_ptr<SerializedPacket> packet, QuicPacketWriter* writer,
    const QuicSocketAddress& self_address,
    const QuicSocketAddress& peer_address, bool measure_rtt) {
  const QuicTime packet_send_time = clock_->Now();
  QUIC_BUG_IF(write using blocked writer, writer->IsWriteBlocked());
  QUIC_DVLOG(2) << ENDPOINT
                << "Sending path probe packet for server connection ID "
                << default_path_.server_connection_id << std::endl
                << quiche::QuicheTextUtils::HexDump(absl::string_view(
                       packet->encrypted_buffer, packet->encrypted_length));
  WriteResult result = SendPacketToWriter(
      packet->encrypted_buffer, packet->encrypted_length, self_address.host(),
      peer_address, writer, GetEcnCodepointToSend(peer_address),
      outgoing_flow_label());

  const uint32_t writer_batch_id = result.batch_id;

  // If using a batch writer and the probing packet is buffered, flush it.
  if (writer->IsBatchMode() && result.status == WRITE_STATUS_OK &&
      result.bytes_written == 0) {
    result = writer->Flush();
  }

  if (IsWriteError(result.status)) {
    // Write error for any connectivity probe should not affect the connection
    // as it is sent on a different path.
    QUIC_DLOG(INFO) << ENDPOINT << "Write probing packet failed with error = "
                    << result.error_code;
    return false;
  }

  // Send in currrent path. Call OnPacketSent regardless of the write result.
  sent_packet_manager_.OnPacketSent(
      packet.get(), packet_send_time, packet->transmission_type,
      NO_RETRANSMITTABLE_DATA, measure_rtt, last_ecn_codepoint_sent_);

  if (debug_visitor_ != nullptr) {
    if (sent_packet_manager_.unacked_packets().empty()) {
      QUIC_BUG(quic_bug_10511_32)
          << "Unacked map is empty right after packet is sent";
    } else {
      debug_visitor_->OnPacketSent(
          packet->packet_number, packet->encrypted_length,
          packet->has_crypto_handshake, packet->transmission_type,
          packet->encryption_level,
          sent_packet_manager_.unacked_packets()
              .rbegin()
              ->retransmittable_frames,
          packet->nonretransmittable_frames, packet_send_time, writer_batch_id);
    }
  }

  if (IsWriteBlockedStatus(result.status)) {
    if (writer == writer_) {
      // Visitor should not be write blocked if the probing writer is not the
      // default packet writer.
      visitor_->OnWriteBlocked();
    }
    if (result.status == WRITE_STATUS_BLOCKED_DATA_BUFFERED) {
      QUIC_DLOG(INFO) << ENDPOINT << "Write probing packet blocked";
    }
  }

  return true;
}

void QuicConnection::DisableMtuDiscovery() {
  mtu_discoverer_.Disable();
  mtu_discovery_alarm().Cancel();
}

void QuicConnection::OnMtuDiscoveryAlarm() {
  QUICHE_DCHECK(connected());
  QUICHE_DCHECK(!mtu_discovery_alarm().IsSet());

  const QuicPacketNumber largest_sent_packet =
      sent_packet_manager_.GetLargestSentPacket();
  if (mtu_discoverer_.ShouldProbeMtu(largest_sent_packet)) {
    ++mtu_probe_count_;
    SendMtuDiscoveryPacket(
        mtu_discoverer_.GetUpdatedMtuProbeSize(largest_sent_packet));
  }
  QUICHE_DCHECK(!mtu_discovery_alarm().IsSet());
}

void QuicConnection::OnEffectivePeerMigrationValidated(
    bool /*is_migration_linkable*/) {
  if (active_effective_peer_migration_type_ == NO_CHANGE) {
    QUIC_BUG(quic_bug_10511_33) << "No migration underway.";
    return;
  }
  highest_packet_sent_before_effective_peer_migration_.Clear();
  const bool send_address_token =
      active_effective_peer_migration_type_ != PORT_CHANGE;
  active_effective_peer_migration_type_ = NO_CHANGE;
  ++stats_.num_validated_peer_migration;
  if (!framer_.version().HasIetfQuicFrames()) {
    return;
  }
  if (debug_visitor_ != nullptr) {
    const QuicTime now = clock_->ApproximateNow();
    if (now >= stats_.handshake_completion_time) {
      debug_visitor_->OnPeerMigrationValidated(
          now - stats_.handshake_completion_time);
    } else {
      QUIC_BUG(quic_bug_10511_34)
          << "Handshake completion time is larger than current time.";
    }
  }

  // Lift anti-amplification limit.
  default_path_.validated = true;
  alternative_path_.Clear();
  if (send_address_token) {
    visitor_->MaybeSendAddressToken();
  }
}

void QuicConnection::StartEffectivePeerMigration(AddressChangeType type) {
  // TODO(fayang): Currently, all peer address change type are allowed. Need to
  // add a method ShouldAllowPeerAddressChange(PeerAddressChangeType type) to
  // determine whether |type| is allowed.
  if (!framer_.version().HasIetfQuicFrames()) {
    if (type == NO_CHANGE) {
      QUIC_BUG(quic_bug_10511_35)
          << "EffectivePeerMigration started without address change.";
      return;
    }
    QUIC_DLOG(INFO)
        << ENDPOINT << "Effective peer's ip:port changed from "
        << default_path_.peer_address.ToString() << " to "
        << GetEffectivePeerAddressFromCurrentPacket().ToString()
        << ", address change type is " << type
        << ", migrating connection without validating new client address.";

    highest_packet_sent_before_effective_peer_migration_ =
        sent_packet_manager_.GetLargestSentPacket();
    default_path_.peer_address = GetEffectivePeerAddressFromCurrentPacket();
    active_effective_peer_migration_type_ = type;

    OnConnectionMigration();
    return;
  }

  if (type == NO_CHANGE) {
    UpdatePeerAddress(last_received_packet_info_.source_address);
    QUIC_BUG(quic_bug_10511_36)
        << "EffectivePeerMigration started without address change.";
    return;
  }
  // There could be pending NEW_TOKEN_FRAME triggered by non-probing
  // PATH_RESPONSE_FRAME in the same packet or pending padding bytes in the
  // packet creator.
  packet_creator_.FlushCurrentPacket();
  packet_creator_.SendRemainingPendingPadding();
  if (!connected_) {
    return;
  }

  // Action items:
  //   1. Switch congestion controller;
  //   2. Update default_path_ (addresses, validation and bytes accounting);
  //   3. Save previous default path if needed;
  //   4. Kick off reverse path validation if needed.
  // Items 1 and 2 are must-to-do. Items 3 and 4 depends on if the new address
  // is validated or not and which path the incoming packet is on.

  const QuicSocketAddress current_effective_peer_address =
      GetEffectivePeerAddressFromCurrentPacket();
  QUIC_DLOG(INFO) << ENDPOINT << "Effective peer's ip:port changed from "
                  << default_path_.peer_address.ToString() << " to "
                  << current_effective_peer_address.ToString()
                  << ", address change type is " << type
                  << ", migrating connection.";

  const QuicSocketAddress previous_direct_peer_address = direct_peer_address_;
  PathState previous_default_path = std::move(default_path_);
  active_effective_peer_migration_type_ = type;
  MaybeClearQueuedPacketsOnPathChange();
  OnConnectionMigration();

  // Update congestion controller if the address change type is not PORT_CHANGE.
  if (type == PORT_CHANGE) {
    QUICHE_DCHECK(previous_default_path.validated ||
                  (alternative_path_.validated &&
                   alternative_path_.send_algorithm != nullptr));
    // No need to store previous congestion controller because either the new
    // default path is validated or the alternative path is validated and
    // already has associated congestion controller.
  } else {
    previous_default_path.rtt_stats.emplace();
    previous_default_path.rtt_stats->CloneFrom(
        *sent_packet_manager_.GetRttStats());
    // If the new peer address share the same IP with the alternative path, the
    // connection should switch to the congestion controller of the alternative
    // path. Otherwise, the connection should use a brand new one.
    // In order to re-use existing code in sent_packet_manager_, reset
    // congestion controller to initial state first and then change to the one
    // on alternative path.
    // TODO(danzh) combine these two steps into one after deprecating gQUIC.
    previous_default_path.send_algorithm = OnPeerIpAddressChanged();

    if (alternative_path_.peer_address.host() ==
            current_effective_peer_address.host() &&
        alternative_path_.send_algorithm != nullptr &&
        alternative_path_.rtt_stats.has_value()) {
      // Update the default path with the congestion controller of the
      // alternative path.
      sent_packet_manager_.SetSendAlgorithm(
          alternative_path_.send_algorithm.release());
      sent_packet_manager_.SetRttStats(*alternative_path_.rtt_stats);

      // Explicitly clear alternative_path_.rtt_stats
      alternative_path_.rtt_stats = std::nullopt;
    }
  }
  // Update to the new peer address.
  UpdatePeerAddress(last_received_packet_info_.source_address);
  // Update the default path.
  if (IsAlternativePath(last_received_packet_info_.destination_address,
                        current_effective_peer_address)) {
    SetDefaultPathState(std::move(alternative_path_));
  } else {
    QuicConnectionId client_connection_id;
    std::optional<StatelessResetToken> stateless_reset_token;
    FindMatchingOrNewClientConnectionIdOrToken(
        previous_default_path, alternative_path_,
        last_received_packet_info_.destination_connection_id,
        &client_connection_id, &stateless_reset_token);
    SetDefaultPathState(
        PathState(last_received_packet_info_.destination_address,
                  current_effective_peer_address, client_connection_id,
                  last_received_packet_info_.destination_connection_id,
                  stateless_reset_token));
    // The path is considered validated if its peer IP address matches any
    // validated path's peer IP address.
    default_path_.validated =
        (alternative_path_.peer_address.host() ==
             current_effective_peer_address.host() &&
         alternative_path_.validated) ||
        (previous_default_path.validated && type == PORT_CHANGE);
  }
  if (!last_received_packet_info_.received_bytes_counted) {
    // Increment bytes counting on the new default path.
    default_path_.bytes_received_before_address_validation +=
        last_received_packet_info_.length;
    last_received_packet_info_.received_bytes_counted = true;
  }

  if (!previous_default_path.validated) {
    // If the old address is under validation, cancel and fail it. Failing to
    // validate the old path shouldn't take any effect.
    QUIC_DVLOG(1) << "Cancel validation of previous peer address change to "
                  << previous_default_path.peer_address
                  << " upon peer migration to " << default_path_.peer_address;
    path_validator_.CancelPathValidation();
    ++stats_.num_peer_migration_while_validating_default_path;
  }

  // Clear alternative path if the new default path shares the same IP as the
  // alternative path.
  if (alternative_path_.peer_address.host() ==
      default_path_.peer_address.host()) {
    alternative_path_.Clear();
  }

  if (default_path_.validated) {
    QUIC_DVLOG(1) << "Peer migrated to a validated address.";
    // No need to save previous default path, validate new peer address or
    // update bytes sent/received.
    if (!(previous_default_path.validated && type == PORT_CHANGE)) {
      // The alternative path was validated because of proactive reverse path
      // validation.
      ++stats_.num_peer_migration_to_proactively_validated_address;
    }
    OnEffectivePeerMigrationValidated(
        default_path_.server_connection_id ==
        previous_default_path.server_connection_id);
    return;
  }

  // The new default address is not validated yet. Anti-amplification limit is
  // enforced.
  QUICHE_DCHECK(EnforceAntiAmplificationLimit());
  QUIC_DVLOG(1) << "Apply anti-amplification limit to effective peer address "
                << default_path_.peer_address << " with "
                << default_path_.bytes_sent_before_address_validation
                << " bytes sent and "
                << default_path_.bytes_received_before_address_validation
                << " bytes received.";

  QUICHE_DCHECK(!alternative_path_.peer_address.IsInitialized() ||
                alternative_path_.peer_address.host() !=
                    default_path_.peer_address.host());

  // Save previous default path to the altenative path.
  if (previous_default_path.validated) {
    // The old path is a validated path which the connection might revert back
    // to later. Store it as the alternative path.
    alternative_path_ = std::move(previous_default_path);
    QUICHE_DCHECK(alternative_path_.send_algorithm != nullptr);
  }

  // If the new address is not validated and the connection is not already
  // validating that address, a new reverse path validation is needed.
  if (!path_validator_.IsValidatingPeerAddress(
          current_effective_peer_address)) {
    ++stats_.num_reverse_path_validtion_upon_migration;
    ValidatePath(std::make_unique<ReversePathValidationContext>(
                     default_path_.self_address, peer_address(),
                     default_path_.peer_address, this),
                 std::make_unique<ReversePathValidationResultDelegate>(
                     this, previous_direct_peer_address),
                 PathValidationReason::kReversePathValidation);
  } else {
    QUIC_DVLOG(1) << "Peer address " << default_path_.peer_address
                  << " is already under validation, wait for result.";
    ++stats_.num_peer_migration_to_proactively_validated_address;
  }
}

void QuicConnection::OnConnectionMigration() {
  if (debug_visitor_ != nullptr) {
    const QuicTime now = clock_->ApproximateNow();
    if (now >= stats_.handshake_completion_time) {
      debug_visitor_->OnPeerAddressChange(
          active_effective_peer_migration_type_,
          now - stats_.handshake_completion_time);
    }
  }
  visitor_->OnConnectionMigration(active_effective_peer_migration_type_);
  if (active_effective_peer_migration_type_ != PORT_CHANGE &&
      active_effective_peer_migration_type_ != IPV4_SUBNET_CHANGE &&
      !framer_.version().HasIetfQuicFrames()) {
    sent_packet_manager_.OnConnectionMigration(/*reset_send_algorithm=*/false);
  }
}

bool QuicConnection::IsCurrentPacketConnectivityProbing() const {
  return is_current_packet_connectivity_probing_;
}

bool QuicConnection::ack_frame_updated() const {
  return uber_received_packet_manager_.IsAckFrameUpdated();
}

absl::string_view QuicConnection::GetCurrentPacket() {
  if (current_packet_data_ == nullptr) {
    return absl::string_view();
  }
  return absl::string_view(current_packet_data_,
                           last_received_packet_info_.length);
}

bool QuicConnection::MaybeConsiderAsMemoryCorruption(
    const QuicStreamFrame& frame) {
  if (QuicUtils::IsCryptoStreamId(transport_version(), frame.stream_id) ||
      last_received_packet_info_.decrypted_level != ENCRYPTION_INITIAL) {
    return false;
  }

  if (perspective_ == Perspective::IS_SERVER &&
      frame.data_length >= sizeof(kCHLO) &&
      strncmp(frame.data_buffer, reinterpret_cast<const char*>(&kCHLO),
              sizeof(kCHLO)) == 0) {
    return true;
  }

  if (perspective_ == Perspective::IS_CLIENT &&
      frame.data_length >= sizeof(kREJ) &&
      strncmp(frame.data_buffer, reinterpret_cast<const char*>(&kREJ),
              sizeof(kREJ)) == 0) {
    return true;
  }

  return false;
}

void QuicConnection::CheckIfApplicationLimited() {
  if (!connected_) {
    return;
  }

  bool application_limited =
      buffered_packets_.empty() && !visitor_->WillingAndAbleToWrite();

  if (!application_limited) {
    return;
  }

  sent_packet_manager_.OnApplicationLimited();
}

bool QuicConnection::UpdatePacketContent(QuicFrameType type) {
  last_received_packet_info_.frames.push_back(type);
  if (version().HasIetfQuicFrames()) {
    if (perspective_ == Perspective::IS_CLIENT) {
      return connected_;
    }
    if (!QuicUtils::IsProbingFrame(type)) {
      MaybeStartIetfPeerMigration();
      return connected_;
    }
    QuicSocketAddress current_effective_peer_address =
        GetEffectivePeerAddressFromCurrentPacket();
    if (IsDefaultPath(last_received_packet_info_.destination_address,
                      last_received_packet_info_.source_address)) {
      return connected_;
    }
    if (type == PATH_CHALLENGE_FRAME &&
        !IsAlternativePath(last_received_packet_info_.destination_address,
                           current_effective_peer_address)) {
      QUIC_DVLOG(1)
          << "The peer is probing a new path with effective peer address "
          << current_effective_peer_address << ",  self address "
          << last_received_packet_info_.destination_address;
      if (!default_path_.validated) {
        // Skip reverse path validation because either handshake hasn't
        // completed or the connection is validating the default path. Using
        // PATH_CHALLENGE to validate alternative client address before
        // handshake gets comfirmed is meaningless because anyone can respond to
        // it. If the connection is validating the default path, this
        // alternative path is currently the only validated path which shouldn't
        // be overridden.
        QUIC_DVLOG(1) << "The connection hasn't finished handshake or is "
                         "validating a recent peer address change.";
        QUIC_BUG_IF(quic_bug_12714_30,
                    IsHandshakeConfirmed() && !alternative_path_.validated)
            << "No validated peer address to send after handshake comfirmed.";
      } else if (!IsReceivedPeerAddressValidated()) {
        QuicConnectionId client_connection_id;
        std::optional<StatelessResetToken> stateless_reset_token;
        FindMatchingOrNewClientConnectionIdOrToken(
            default_path_, alternative_path_,
            last_received_packet_info_.destination_connection_id,
            &client_connection_id, &stateless_reset_token);
        // Only override alternative path state upon receiving a PATH_CHALLENGE
        // from an unvalidated peer address, and the connection isn't validating
        // a recent peer migration.
        alternative_path_ =
            PathState(last_received_packet_info_.destination_address,
                      current_effective_peer_address, client_connection_id,
                      last_received_packet_info_.destination_connection_id,
                      stateless_reset_token);
        should_proactively_validate_peer_address_on_path_challenge_ = true;
      }
    }
    MaybeUpdateBytesReceivedFromAlternativeAddress(
        last_received_packet_info_.length);
    return connected_;
  }

  if (!ignore_gquic_probing_) {
    // Packet content is tracked to identify connectivity probe in non-IETF
    // version, where a connectivity probe is defined as
    // - a padded PING packet with peer address change received by server,
    // - a padded PING packet on new path received by client.

    if (current_packet_content_ == NOT_PADDED_PING) {
      // We have already learned the current packet is not a connectivity
      // probing packet. Peer migration should have already been started earlier
      // if needed.
      return connected_;
    }

    if (type == PING_FRAME) {
      if (current_packet_content_ == NO_FRAMES_RECEIVED) {
        current_packet_content_ = FIRST_FRAME_IS_PING;
        return connected_;
      }
    }

    // In Google QUIC, we look for a packet with just a PING and PADDING.
    // If the condition is met, mark things as connectivity-probing, causing
    // later processing to generate the correct response.
    if (type == PADDING_FRAME &&
        current_packet_content_ == FIRST_FRAME_IS_PING) {
      current_packet_content_ = SECOND_FRAME_IS_PADDING;
      QUIC_CODE_COUNT_N(gquic_padded_ping_received, 1, 2);
      if (perspective_ == Perspective::IS_SERVER) {
        is_current_packet_connectivity_probing_ =
            current_effective_peer_migration_type_ != NO_CHANGE;
        if (is_current_packet_connectivity_probing_) {
          QUIC_CODE_COUNT_N(gquic_padded_ping_received, 2, 2);
        }
        QUIC_DLOG_IF(INFO, is_current_packet_connectivity_probing_)
            << ENDPOINT
            << "Detected connectivity probing packet. "
               "current_effective_peer_migration_type_:"
            << current_effective_peer_migration_type_;
      } else {
        is_current_packet_connectivity_probing_ =
            (last_received_packet_info_.source_address != peer_address()) ||
            (last_received_packet_info_.destination_address !=
             default_path_.self_address);
        QUIC_DLOG_IF(INFO, is_current_packet_connectivity_probing_)
            << ENDPOINT
            << "Detected connectivity probing packet. "
               "last_packet_source_address:"
            << last_received_packet_info_.source_address
            << ", peer_address_:" << peer_address()
            << ", last_packet_destination_address:"
            << last_received_packet_info_.destination_address
            << ", default path self_address :" << default_path_.self_address;
      }
      return connected_;
    }

    current_packet_content_ = NOT_PADDED_PING;
  } else {
    QUIC_RELOADABLE_FLAG_COUNT(quic_ignore_gquic_probing);
    QUICHE_DCHECK_EQ(current_packet_content_, NO_FRAMES_RECEIVED);
  }

  if (GetLargestReceivedPacket().IsInitialized() &&
      last_received_packet_info_.header.packet_number ==
          GetLargestReceivedPacket()) {
    UpdatePeerAddress(last_received_packet_info_.source_address);
    if (current_effective_peer_migration_type_ != NO_CHANGE) {
      // Start effective peer migration immediately when the current packet is
      // confirmed not a connectivity probing packet.
      StartEffectivePeerMigration(current_effective_peer_migration_type_);
    }
  }
  current_effective_peer_migration_type_ = NO_CHANGE;
  return connected_;
}

void QuicConnection::MaybeStartIetfPeerMigration() {
  QUICHE_DCHECK(version().HasIetfQuicFrames());
  if (current_effective_peer_migration_type_ != NO_CHANGE &&
      !IsHandshakeConfirmed()) {
    QUIC_LOG_EVERY_N_SEC(INFO, 60)
        << ENDPOINT << "Effective peer's ip:port changed from "
        << default_path_.peer_address.ToString() << " to "
        << GetEffectivePeerAddressFromCurrentPacket().ToString()
        << " before handshake confirmed, "
           "current_effective_peer_migration_type_: "
        << current_effective_peer_migration_type_;
    // Peer migrated before handshake gets confirmed.
    CloseConnection(
        (current_effective_peer_migration_type_ == PORT_CHANGE
             ? QUIC_PEER_PORT_CHANGE_HANDSHAKE_UNCONFIRMED
             : QUIC_CONNECTION_MIGRATION_HANDSHAKE_UNCONFIRMED),
        absl::StrFormat(
            "Peer address changed from %s to %s before handshake is confirmed.",
            default_path_.peer_address.ToString(),
            GetEffectivePeerAddressFromCurrentPacket().ToString()),
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  if (GetLargestReceivedPacket().IsInitialized() &&
      last_received_packet_info_.header.packet_number ==
          GetLargestReceivedPacket()) {
    if (current_effective_peer_migration_type_ != NO_CHANGE) {
      // Start effective peer migration when the current packet contains a
      // non-probing frame.
      // TODO(fayang): When multiple packet number spaces is
"""


```