Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of the `QuicDispatcher` class in Chromium's QUIC implementation. I need to analyze the code and describe its roles and responsibilities.

Here's a breakdown of the code's functions:

1. **Adding Connections to Time Wait List:**  The `AddConnectionIdToTimeWaitList` function handles adding connections to the time wait list. It determines the appropriate action (sending stateless reset or connection close packets) based on the connection's state.

2. **Controlling New Connection Acceptance:** The `StartAcceptingNewConnections` and `StopAcceptingNewConnections` functions manage whether the dispatcher accepts new incoming connections.

3. **Iterating and Retrieving Sessions:** `PerformActionOnActiveSessions` and `GetSessionsSnapshot` provide ways to iterate through and obtain a snapshot of the currently active QUIC sessions.

4. **Per-Packet Context:** `GetPerPacketContext` seems to be a placeholder for obtaining per-packet context information.

5. **Deleting Closed Sessions:**  `DeleteSessions` clears the list of closed sessions and handles potential issues related to write-blocked connections.

6. **Clearing Stateless Reset Addresses:** `ClearStatelessResetAddresses` manages the list of recently seen addresses for which stateless resets were sent.

7. **Handling Write Blocking:** `OnCanWrite` and `HasPendingWrites` are related to managing write-blocked connections and the socket's writeability.

8. **Graceful Shutdown:** `Shutdown` initiates a graceful shutdown of all active QUIC sessions.

9. **Connection Closure Handling:** `OnConnectionClosed` is invoked when a QUIC connection closes. It removes the session from the active session map and adds it to a list for later cleanup.

10. **Write Blocking Notification:** `OnWriteBlocked` is called when a connection becomes write-blocked.

11. **Stream Reset and Stop Sending Handling:** `OnRstStreamReceived` and `OnStopSendingReceived` are stubs for handling stream-level control frames.

12. **Connection ID Management:** `TryAddNewConnectionId` and `OnConnectionIdRetired` manage the association of new connection IDs with existing sessions and the removal of retired connection IDs.

13. **Time Wait List Notification:** `OnConnectionAddedToTimeWaitList` logs when a connection is added to the time wait list.

14. **Stateless Termination:** `StatelesslyTerminateConnection` handles the stateless termination of connections, sending either stateless resets or connection close packets. It has two overloaded versions.

15. **Unknown Version Handling:** `ShouldCreateSessionForUnknownVersion` is a hook for deciding whether to create a session for an unknown QUIC version.

16. **Expired Packet Handling:** `OnExpiredPackets` is called when buffered packets have expired, triggering a stateless termination.

17. **Processing Buffered CHLOs:** `ProcessBufferedChlos` handles the processing of buffered client hello (CHLO) packets to establish new connections.

18. **Checking for Buffered Data:** `HasChlosBuffered` and `HasBufferedPackets` check if there are buffered CHLOs or packets for a given connection ID.

19. **Buffer Packet Failure Handling:** `OnBufferPacketFailure` logs errors when buffering packets fails.

20. **Time Wait List Manager Creation:** `CreateQuicTimeWaitListManager` creates the time wait list manager instance.

21. **Processing Incoming CHLOs:** `ProcessChlo` is a crucial function that handles incoming client hello packets, either creating a new session immediately or buffering the packet for later processing.

22. **Setting Last Error:** `SetLastError` sets the last error encountered by the dispatcher.

23. **Failed Packet Dispatch Hook:** `OnFailedToDispatchPacket` is a hook for handling cases where packet dispatch fails.

24. **Getting Supported Versions:** `GetSupportedVersions` returns the list of QUIC versions supported by the dispatcher.

25. **Delivering Buffered Packets to Sessions:** `DeliverPacketsToSession` delivers buffered packets to a newly established session.

26. **Version Support Check:** `IsSupportedVersion` checks if a given QUIC version is supported.

27. **Short Connection ID Check:** `IsServerConnectionIdTooShort` checks if a server connection ID is too short.

28. **Creating Sessions from CHLOs:** `CreateSessionFromChlo` is a key function responsible for creating a new `QuicSession` from a parsed client hello. It also handles connection ID replacement and collision detection.

29. **Handling Connection ID Collisions:** `HandleConnectionIdCollision` detects and handles connection ID collisions, potentially sending a connection close.

30. **Handling Packets with No Version:** `MaybeResetPacketsWithNoVersion` handles packets without a version, potentially sending a stateless reset.

31. **Sending Version Negotiation Packets:** `MaybeSendVersionNegotiationPacket` sends version negotiation packets when appropriate.

32. **Getting Session Count:** `NumSessions` returns the number of active QUIC sessions.

Based on this analysis, I can now generate the requested summary.
这是`net/third_party/quiche/src/quiche/quic/core/quic_dispatcher.cc` 文件 `QuicDispatcher` 类的第 2 部分代码，主要负责以下功能：

**核心功能归纳:**

* **连接生命周期管理 (后半段):**  继续处理连接的终止、清理和状态维护，例如将连接加入 `TimeWaitList`，处理连接关闭事件。
* **新连接控制:** 提供启动和停止接受新连接的能力。
* **会话管理:**  提供访问和操作当前活跃 QUIC 会话的方法。
* **连接 ID 管理:**  处理新的连接 ID 的分配和旧连接 ID 的退役。
* **无状态连接终止:**  实现无状态地终止连接，发送 `STATELESS_RESET` 或 `CONNECTION_CLOSE` 报文。
* **处理过期报文:**  处理由于缓存时间过长而过期的报文。
* **处理缓存的 CHLO (Client Hello):**  处理之前缓存的客户端连接请求，创建新的会话。
* **连接 ID 冲突处理:**  检测并处理连接 ID 冲突的情况。
* **处理无版本报文:**  对于没有版本信息的报文，可能会发送 `STATELESS_RESET` 报文。
* **发送版本协商报文:**  在适当的时候发送版本协商报文。

**与 JavaScript 的关系 (理论上间接关系):**

`QuicDispatcher` 是服务器端的组件，负责处理客户端的 QUIC 连接。如果你的 JavaScript 代码运行在浏览器中，并通过 QUIC 协议与服务器通信，那么服务器端的 `QuicDispatcher` 就在幕后处理这些连接。

**举例说明:**

假设你的 JavaScript 代码发起一个使用 QUIC 协议的 HTTPS 请求：

```javascript
// 浏览器端的 JavaScript
fetch('https://example.com', { protocol: 'quic' })
  .then(response => response.text())
  .then(data => console.log(data));
```

1. **用户操作:** 用户在浏览器地址栏输入 `https://example.com` 并按下回车，或者 JavaScript 代码执行 `fetch` 请求。
2. **网络栈处理:** 浏览器网络栈（Chromium 的一部分）会协商使用 QUIC 协议。
3. **连接建立 (未在代码片段中):**  浏览器会发送初始的连接请求（包含 Client Hello）。
4. **`QuicDispatcher` 接收 CHLO:** 服务器端的 `QuicDispatcher` 接收到这个 Client Hello 报文。
5. **`ProcessChlo` (在第一部分):**  `QuicDispatcher` 的 `ProcessChlo` 方法（在第一部分中）会解析 CHLO，并尝试创建新的 `QuicSession`。如果由于某些原因无法立即创建，CHLO 可能会被缓存。
6. **`ProcessBufferedChlos`:**  如果 CHLO 被缓存，当条件满足时（例如，允许创建更多连接），`ProcessBufferedChlos` 会被调用，从缓存中取出 CHLO 并创建 `QuicSession`。
7. **连接关闭:**  当连接完成或出现错误时，`OnConnectionClosed` 方法会被调用，清理该连接相关的资源。
8. **无状态终止:** 如果客户端发送的报文无法被处理（例如，版本不支持），`StatelesslyTerminateConnection` 方法可能会被调用，向客户端发送 `STATELESS_RESET` 或 `CONNECTION_CLOSE` 报文。

**逻辑推理 (假设输入与输出):**

假设输入一个已经关闭的连接的服务器连接 ID 到 `AddConnectionIdToTimeWaitList` 方法，并且该连接在关闭前握手尚未完成 (`!connection->IsHandshakeComplete()` 为真)。

* **假设输入:**
    * `server_connection_id`: 一个已经关闭的连接的 ID，例如 `12345`。
    * `connection->HasTerminationPackets()`: `false` (假设没有遗留的终止报文需要发送)。
    * `connection->IsHandshakeComplete()`: `false`。
    * 其他必要的上下文信息 (例如，`helper_`, `time_wait_list_manager_`) 已初始化。

* **逻辑推理:**
    1. 进入 `AddConnectionIdToTimeWaitList` 方法。
    2. `connection->HasTerminationPackets()` 为假，跳过发送已有的终止报文的逻辑。
    3. `connection->IsHandshakeComplete()` 为假，进入未完成握手的逻辑分支。
    4. 调用 `StatelessConnectionTerminator` 创建一个终止器。
    5. `terminator.CloseConnection` 被调用，发送一个 `CONNECTION_CLOSE` 报文，错误码为 `QUIC_HANDSHAKE_FAILED_SYNTHETIC_CONNECTION_CLOSE`，错误信息为 "Connection is closed by server before handshake confirmed"。
    6. 连接不会被添加到 `time_wait_list_manager_`，因为在未完成握手的情况下，`AddConnectionIdToTimeWait` 方法直接返回。

* **预期输出:**  一个 `CONNECTION_CLOSE` 报文被发送到客户端，指示握手失败。该连接的 ID 不会被添加到 `TimeWaitList`。

**用户或编程常见的使用错误:**

1. **过早停止接受新连接:**  如果 `StopAcceptingNewConnections` 被过早调用，可能会导致客户端无法建立新的连接，即使服务器有能力处理。
    * **用户操作:**  用户尝试访问网站，但由于服务器过早停止接受新连接，导致连接超时或失败。
    * **调试线索:**  服务器日志显示 `accept_new_connections_` 为 `false`，并且客户端收到连接拒绝的错误。
2. **连接 ID 冲突:**  如果服务器在生成新的连接 ID 时没有足够的随机性，可能会发生连接 ID 冲突，导致现有连接被意外终止。
    * **用户操作:**  用户在使用网站时，连接突然断开，并可能出现 "Connection ID collision" 相关的错误信息。
    * **调试线索:**  服务器日志中出现 `QUIC Connection ID collision` 的错误信息，并且 `HandleConnectionIdCollision` 方法被调用。
3. **未正确处理 `OnConnectionClosed` 事件:**  如果服务器逻辑没有正确处理 `OnConnectionClosed` 事件，可能会导致资源泄漏或状态不一致。
    * **编程错误:**  开发者忘记在 `OnConnectionClosed` 中清理与连接相关的资源。
    * **调试线索:**  内存占用持续增加，或者在会话映射中仍然存在已关闭连接的条目。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户发起连接:** 用户在浏览器中输入 URL 或点击链接，浏览器尝试与服务器建立 QUIC 连接。
2. **服务器接收报文:** 服务器的网络接口接收到来自客户端的 UDP 报文。
3. **`QuicDispatcher::ProcessPacket` (在第一部分):**  `QuicDispatcher` 的 `ProcessPacket` 方法（在第一部分中）会处理接收到的报文。
4. **连接关闭触发:**  如果连接过程中发生错误 (例如，握手失败、超时、收到对端发送的 `CONNECTION_CLOSE` 帧)，或者服务器主动关闭连接，`OnConnectionClosed` 方法会被调用。
5. **`OnConnectionClosed` 逻辑执行:**
    * 查找与 `server_connection_id` 对应的 `QuicSession`。
    * 将该会话从 `reference_counted_session_map_` 中移除。
    * 将该会话添加到 `closed_session_list_` 中，以便稍后清理。
    * 调用 `CleanUpSession` 执行进一步的清理操作。
6. **`AddConnectionIdToTimeWaitList` 的调用:** 在某些情况下，例如服务器主动关闭连接，或者接收到无法处理的报文，`AddConnectionIdToTimeWaitList` 会被调用，以便将连接 ID 加入时间等待列表，防止连接 ID 被立即重用，并可能发送 `STATELESS_RESET` 或 `CONNECTION_CLOSE` 报文。

**归纳一下它的功能:**

这部分 `QuicDispatcher` 的代码主要负责 **QUIC 连接的后生命周期管理、连接控制、会话管理以及处理异常情况 (例如连接 ID 冲突、接收到无法处理的报文)**。它确保了连接的正常关闭和资源的清理，并提供了处理新连接请求和维护当前活跃会话状态的机制。它还负责在必要时发送无状态重置或连接关闭报文，以通知对端连接的终止。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_dispatcher.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
::SEND_STATELESS_RESET;
  std::vector<std::unique_ptr<QuicEncryptedPacket>> termination_packets;
  if (connection->HasTerminationPackets()) {
    termination_packets = connection->ConsumeTerminationPackets();
    action = QuicTimeWaitListManager::SEND_CONNECTION_CLOSE_PACKETS;
  } else {
    if (!connection->IsHandshakeComplete()) {
      // TODO(fayang): Do not serialize connection close packet if the
      // connection is closed by the client.
      QUIC_CODE_COUNT(quic_v44_add_to_time_wait_list_with_handshake_failed);
      // This serializes a connection close termination packet and adds the
      // connection to the time wait list.
      // TODO(b/359200165): Fix |last_sent_packet_number|.
      StatelessConnectionTerminator terminator(
          server_connection_id,
          connection->GetOriginalDestinationConnectionId(),
          connection->version(), /*last_sent_packet_number=*/QuicPacketNumber(),
          helper_.get(), time_wait_list_manager_.get());
      terminator.CloseConnection(
          QUIC_HANDSHAKE_FAILED_SYNTHETIC_CONNECTION_CLOSE,
          "Connection is closed by server before handshake confirmed",
          /*ietf_quic=*/true, connection->GetActiveServerConnectionIds());
      return;
    }
    QUIC_CODE_COUNT(quic_v44_add_to_time_wait_list_with_stateless_reset);
  }
  time_wait_list_manager_->AddConnectionIdToTimeWait(
      action,
      TimeWaitConnectionInfo(
          /*ietf_quic=*/true,
          termination_packets.empty() ? nullptr : &termination_packets,
          connection->GetActiveServerConnectionIds(),
          connection->sent_packet_manager().GetRttStats()->smoothed_rtt()));
}

void QuicDispatcher::StartAcceptingNewConnections() {
  accept_new_connections_ = true;
}

void QuicDispatcher::StopAcceptingNewConnections() {
  accept_new_connections_ = false;
  // No more CHLO will arrive and buffered CHLOs shouldn't be able to create
  // connections.
  buffered_packets_.DiscardAllPackets();
}

void QuicDispatcher::PerformActionOnActiveSessions(
    quiche::UnretainedCallback<void(QuicSession*)> operation) const {
  absl::flat_hash_set<QuicSession*> visited_session;
  visited_session.reserve(reference_counted_session_map_.size());
  for (auto const& kv : reference_counted_session_map_) {
    QuicSession* session = kv.second.get();
    if (visited_session.insert(session).second) {
      operation(session);
    }
  }
}

// Get a snapshot of all sessions.
std::vector<std::shared_ptr<QuicSession>> QuicDispatcher::GetSessionsSnapshot()
    const {
  std::vector<std::shared_ptr<QuicSession>> snapshot;
  snapshot.reserve(reference_counted_session_map_.size());
  absl::flat_hash_set<QuicSession*> visited_session;
  visited_session.reserve(reference_counted_session_map_.size());
  for (auto const& kv : reference_counted_session_map_) {
    QuicSession* session = kv.second.get();
    if (visited_session.insert(session).second) {
      snapshot.push_back(kv.second);
    }
  }
  return snapshot;
}

std::unique_ptr<QuicPerPacketContext> QuicDispatcher::GetPerPacketContext()
    const {
  return nullptr;
}

void QuicDispatcher::DeleteSessions() {
  if (!write_blocked_list_.Empty()) {
    for (const auto& session : closed_session_list_) {
      if (write_blocked_list_.Remove(*session->connection())) {
        QUIC_BUG(quic_bug_12724_2)
            << "QuicConnection was in WriteBlockedList before destruction "
            << session->connection()->connection_id();
      }
    }
  }
  closed_session_list_.clear();
}

void QuicDispatcher::ClearStatelessResetAddresses() {
  recent_stateless_reset_addresses_.clear();
}

void QuicDispatcher::OnCanWrite() {
  // The socket is now writable.
  writer_->SetWritable();

  write_blocked_list_.OnWriterUnblocked();
}

bool QuicDispatcher::HasPendingWrites() const {
  return !write_blocked_list_.Empty();
}

void QuicDispatcher::Shutdown() {
  while (!reference_counted_session_map_.empty()) {
    QuicSession* session = reference_counted_session_map_.begin()->second.get();
    session->connection()->CloseConnection(
        QUIC_PEER_GOING_AWAY, "Server shutdown imminent",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    // Validate that the session removes itself from the session map on close.
    QUICHE_DCHECK(reference_counted_session_map_.empty() ||
                  reference_counted_session_map_.begin()->second.get() !=
                      session);
  }
  DeleteSessions();
}

void QuicDispatcher::OnConnectionClosed(QuicConnectionId server_connection_id,
                                        QuicErrorCode error,
                                        const std::string& error_details,
                                        ConnectionCloseSource source) {
  auto it = reference_counted_session_map_.find(server_connection_id);
  if (it == reference_counted_session_map_.end()) {
    QUIC_BUG(quic_bug_10287_3) << "ConnectionId " << server_connection_id
                               << " does not exist in the session map.  Error: "
                               << QuicErrorCodeToString(error);
    QUIC_BUG(quic_bug_10287_4) << QuicStackTrace();
    return;
  }

  QUIC_DLOG_IF(INFO, error != QUIC_NO_ERROR)
      << "Closing connection (" << server_connection_id
      << ") due to error: " << QuicErrorCodeToString(error)
      << ", with details: " << error_details;

  const QuicSession* session = it->second.get();
  QuicConnection* connection = it->second->connection();
  // Set up alarm to fire immediately to bring destruction of this session
  // out of current call stack.
  if (closed_session_list_.empty()) {
    delete_sessions_alarm_->Update(helper()->GetClock()->ApproximateNow(),
                                   QuicTime::Delta::Zero());
  }
  closed_session_list_.push_back(std::move(it->second));
  CleanUpSession(it->first, connection, error, error_details, source);
  bool session_removed = false;
  for (const QuicConnectionId& cid :
       connection->GetActiveServerConnectionIds()) {
    auto it1 = reference_counted_session_map_.find(cid);
    if (it1 != reference_counted_session_map_.end()) {
      const QuicSession* session2 = it1->second.get();
      // For cid == server_connection_id, session2 is a nullptr (and hence
      // session2 != session) now since we have std::move the session into
      // closed_session_list_ above.
      if (session2 == session || cid == server_connection_id) {
        reference_counted_session_map_.erase(it1);
        session_removed = true;
      } else {
        // Leave this session in the map.
        QUIC_BUG(quic_dispatcher_session_mismatch)
            << "Session is mismatched in the map. server_connection_id: "
            << server_connection_id << ". Current cid: " << cid
            << ". Cid of the other session "
            << (session2 == nullptr
                    ? "null"
                    : session2->connection()->connection_id().ToString());
      }
    } else {
      // GetActiveServerConnectionIds might return the original destination
      // ID, which is not contained in the session map.
      QUIC_BUG_IF(quic_dispatcher_session_not_found,
                  cid != connection->GetOriginalDestinationConnectionId())
          << "Missing session for cid " << cid
          << ". server_connection_id: " << server_connection_id;
    }
  }
  QUIC_BUG_IF(quic_session_is_not_removed, !session_removed);
  --num_sessions_in_session_map_;
}

void QuicDispatcher::OnWriteBlocked(
    QuicBlockedWriterInterface* blocked_writer) {
  write_blocked_list_.Add(*blocked_writer);
}

void QuicDispatcher::OnRstStreamReceived(const QuicRstStreamFrame& /*frame*/) {}

void QuicDispatcher::OnStopSendingReceived(
    const QuicStopSendingFrame& /*frame*/) {}

bool QuicDispatcher::TryAddNewConnectionId(
    const QuicConnectionId& server_connection_id,
    const QuicConnectionId& new_connection_id) {
  auto it = reference_counted_session_map_.find(server_connection_id);
  if (it == reference_counted_session_map_.end()) {
    QUIC_BUG(quic_bug_10287_7)
        << "Couldn't locate the session that issues the connection ID in "
           "reference_counted_session_map_.  server_connection_id:"
        << server_connection_id << " new_connection_id: " << new_connection_id;
    return false;
  }
  auto insertion_result = reference_counted_session_map_.insert(
      std::make_pair(new_connection_id, it->second));
  if (!insertion_result.second) {
    QUIC_CODE_COUNT(quic_cid_already_in_session_map);
  }
  return insertion_result.second;
}

void QuicDispatcher::OnConnectionIdRetired(
    const QuicConnectionId& server_connection_id) {
  reference_counted_session_map_.erase(server_connection_id);
}

void QuicDispatcher::OnConnectionAddedToTimeWaitList(
    QuicConnectionId server_connection_id) {
  QUIC_DLOG(INFO) << "Connection " << server_connection_id
                  << " added to time wait list.";
}

void QuicDispatcher::StatelesslyTerminateConnection(
    const QuicSocketAddress& self_address,
    const QuicSocketAddress& peer_address,
    QuicConnectionId server_connection_id, PacketHeaderFormat format,
    bool version_flag, bool use_length_prefix, ParsedQuicVersion version,
    QuicErrorCode error_code, const std::string& error_details,
    QuicTimeWaitListManager::TimeWaitAction action) {
  const BufferedPacketList* packet_list =
      buffered_packets_.GetPacketList(server_connection_id);

  if (packet_list == nullptr) {
    StatelesslyTerminateConnection(
        self_address, peer_address, server_connection_id, format, version_flag,
        use_length_prefix, version, error_code, error_details, action,
        /*replaced_connection_id=*/std::nullopt,
        /*last_sent_packet_number=*/QuicPacketNumber());
    return;
  }

  StatelesslyTerminateConnection(
      self_address, peer_address, packet_list->original_connection_id, format,
      version_flag, use_length_prefix, version, error_code, error_details,
      action, packet_list->replaced_connection_id,
      packet_list->GetLastSentPacketNumber());
}

void QuicDispatcher::StatelesslyTerminateConnection(
    const QuicSocketAddress& self_address,
    const QuicSocketAddress& peer_address,
    QuicConnectionId server_connection_id, PacketHeaderFormat format,
    bool version_flag, bool use_length_prefix, ParsedQuicVersion version,
    QuicErrorCode error_code, const std::string& error_details,
    QuicTimeWaitListManager::TimeWaitAction action,
    const std::optional<QuicConnectionId>& replaced_connection_id,
    QuicPacketNumber last_sent_packet_number) {
  if (format != IETF_QUIC_LONG_HEADER_PACKET && !version_flag) {
    QUIC_DVLOG(1) << "Statelessly terminating " << server_connection_id
                  << " based on a non-ietf-long packet, action:" << action
                  << ", error_code:" << error_code
                  << ", error_details:" << error_details;
    time_wait_list_manager_->AddConnectionIdToTimeWait(
        action, TimeWaitConnectionInfo(format != GOOGLE_QUIC_PACKET, nullptr,
                                       {server_connection_id}));
    return;
  }

  // If the version is known and supported by framer, send a connection close.
  if (IsSupportedVersion(version)) {
    QUIC_DVLOG(1)
        << "Statelessly terminating " << server_connection_id
        << " based on an ietf-long packet, which has a supported version:"
        << version << ", error_code:" << error_code
        << ", error_details:" << error_details << ", replaced_connection_id:"
        << (replaced_connection_id.has_value()
                ? replaced_connection_id->ToString()
                : "n/a");

    // |server_connection_id| is the original connection ID when flag is true.
    QuicConnectionId original_connection_id = server_connection_id;

    StatelessConnectionTerminator terminator(
        replaced_connection_id.value_or(original_connection_id),
        original_connection_id, version, last_sent_packet_number, helper_.get(),
        time_wait_list_manager_.get());

    std::vector<QuicConnectionId> active_connection_ids = {
        original_connection_id};
    if (replaced_connection_id.has_value()) {
      active_connection_ids.push_back(*replaced_connection_id);
    }
    // This also adds the connection to time wait list.
    terminator.CloseConnection(error_code, error_details,
                               format != GOOGLE_QUIC_PACKET,
                               /*active_connection_ids=*/
                               std::move(active_connection_ids));

    QUIC_CODE_COUNT(quic_dispatcher_generated_connection_close);
    QuicSession::RecordConnectionCloseAtServer(
        error_code, ConnectionCloseSource::FROM_SELF);
    // TODO(wub): Change the server_connection_id parameter to original+replaced
    // connection ids.
    OnStatelessConnectionCloseGenerated(self_address, peer_address,
                                        server_connection_id, version,
                                        error_code, error_details);
    return;
  }

  QUIC_DVLOG(1)
      << "Statelessly terminating " << server_connection_id
      << " based on an ietf-long packet, which has an unsupported version:"
      << version << ", error_code:" << error_code
      << ", error_details:" << error_details;
  // Version is unknown or unsupported by framer, send a version negotiation
  // with an empty version list, which can be understood by the client.
  std::vector<std::unique_ptr<QuicEncryptedPacket>> termination_packets;
  termination_packets.push_back(QuicFramer::BuildVersionNegotiationPacket(
      server_connection_id, EmptyQuicConnectionId(),
      /*ietf_quic=*/format != GOOGLE_QUIC_PACKET, use_length_prefix,
      /*versions=*/{}));
  time_wait_list_manager()->AddConnectionIdToTimeWait(
      QuicTimeWaitListManager::SEND_TERMINATION_PACKETS,
      TimeWaitConnectionInfo(/*ietf_quic=*/format != GOOGLE_QUIC_PACKET,
                             &termination_packets, {server_connection_id}));
}

bool QuicDispatcher::ShouldCreateSessionForUnknownVersion(
    const ReceivedPacketInfo& /*packet_info*/) {
  return false;
}

void QuicDispatcher::OnExpiredPackets(
    BufferedPacketList early_arrived_packets) {
  QUIC_CODE_COUNT(quic_reject_buffered_packets_expired);
  QuicErrorCode error_code = QUIC_HANDSHAKE_FAILED_PACKETS_BUFFERED_TOO_LONG;
  QuicSocketAddress self_address, peer_address;
  if (!early_arrived_packets.buffered_packets.empty()) {
    self_address = early_arrived_packets.buffered_packets.front().self_address;
    peer_address = early_arrived_packets.buffered_packets.front().peer_address;
  }

  StatelesslyTerminateConnection(
      self_address, peer_address, early_arrived_packets.original_connection_id,
      early_arrived_packets.ietf_quic ? IETF_QUIC_LONG_HEADER_PACKET
                                      : GOOGLE_QUIC_PACKET,
      /*version_flag=*/true,
      early_arrived_packets.version.HasLengthPrefixedConnectionIds(),
      early_arrived_packets.version, error_code,
      "Packets buffered for too long",
      quic::QuicTimeWaitListManager::SEND_STATELESS_RESET,
      early_arrived_packets.replaced_connection_id,
      early_arrived_packets.GetLastSentPacketNumber());
}

void QuicDispatcher::ProcessBufferedChlos(size_t max_connections_to_create) {
  // Reset the counter before starting creating connections.
  new_sessions_allowed_per_event_loop_ = max_connections_to_create;
  for (; new_sessions_allowed_per_event_loop_ > 0;
       --new_sessions_allowed_per_event_loop_) {
    QuicConnectionId server_connection_id;
    BufferedPacketList packet_list =
        buffered_packets_.DeliverPacketsForNextConnection(
            &server_connection_id);
    const std::list<BufferedPacket>& packets = packet_list.buffered_packets;
    if (packets.empty()) {
      return;
    }
    if (!packet_list.parsed_chlo.has_value()) {
      QUIC_BUG(quic_dispatcher_no_parsed_chlo_in_buffered_packets)
          << "Buffered connection has no CHLO. connection_id:"
          << server_connection_id;
      continue;
    }
    auto session_ptr = CreateSessionFromChlo(
        server_connection_id, packet_list.replaced_connection_id,
        *packet_list.parsed_chlo, packet_list.version,
        packets.front().self_address, packets.front().peer_address,
        packet_list.tls_chlo_extractor.state(),
        packet_list.connection_id_generator,
        packet_list.dispatcher_sent_packets);
    if (session_ptr != nullptr) {
      DeliverPacketsToSession(packets, session_ptr.get());
    }
  }
}

bool QuicDispatcher::HasChlosBuffered() const {
  return buffered_packets_.HasChlosBuffered();
}

// Return true if there is any packet buffered in the store.
bool QuicDispatcher::HasBufferedPackets(QuicConnectionId server_connection_id) {
  return buffered_packets_.HasBufferedPackets(server_connection_id);
}

void QuicDispatcher::OnBufferPacketFailure(
    EnqueuePacketResult result, QuicConnectionId server_connection_id) {
  QUIC_DLOG(INFO) << "Fail to buffer packet on connection "
                  << server_connection_id << " because of " << result;
}

QuicTimeWaitListManager* QuicDispatcher::CreateQuicTimeWaitListManager() {
  return new QuicTimeWaitListManager(writer_.get(), this, helper_->GetClock(),
                                     alarm_factory_.get());
}

void QuicDispatcher::ProcessChlo(ParsedClientHello parsed_chlo,
                                 ReceivedPacketInfo* packet_info) {
  if (GetQuicFlag(quic_allow_chlo_buffering) &&
      new_sessions_allowed_per_event_loop_ <= 0) {
    // Can't create new session any more. Wait till next event loop.
    QUIC_BUG_IF(quic_bug_12724_7, buffered_packets_.HasChloForConnection(
                                      packet_info->destination_connection_id));
    EnqueuePacketResult rs = buffered_packets_.EnqueuePacket(
        *packet_info, std::move(parsed_chlo), ConnectionIdGenerator());
    switch (rs) {
      case EnqueuePacketResult::SUCCESS:
        break;
      case EnqueuePacketResult::CID_COLLISION:
        buffered_packets_.DiscardPackets(
            packet_info->destination_connection_id);
        ABSL_FALLTHROUGH_INTENDED;
      case EnqueuePacketResult::TOO_MANY_PACKETS:
        ABSL_FALLTHROUGH_INTENDED;
      case EnqueuePacketResult::TOO_MANY_CONNECTIONS:
        OnBufferPacketFailure(rs, packet_info->destination_connection_id);
        break;
    }
    return;
  }

  BufferedPacketList packet_list =
      buffered_packets_.DeliverPackets(packet_info->destination_connection_id);
  // Get original_connection_id from buffered packets because
  // destination_connection_id may be replaced connection_id if any packets
  // have been sent by packet store.
  QuicConnectionId original_connection_id =
      packet_list.buffered_packets.empty()
          ? packet_info->destination_connection_id
          : packet_list.original_connection_id;

  TlsChloExtractor::State chlo_extractor_state =
      packet_list.buffered_packets.empty()
          ? TlsChloExtractor::State::kParsedFullSinglePacketChlo
          : packet_list.tls_chlo_extractor.state();

  auto session_ptr = CreateSessionFromChlo(
      original_connection_id, packet_list.replaced_connection_id, parsed_chlo,
      packet_info->version, packet_info->self_address,
      packet_info->peer_address, chlo_extractor_state,
      packet_list.connection_id_generator, packet_list.dispatcher_sent_packets);
  if (session_ptr == nullptr) {
    // The only reason that CreateSessionFromChlo returns nullptr is because
    // of CID collision, which can only happen if CreateSessionFromChlo
    // attempted to replace the CID, CreateSessionFromChlo only replaces the
    // CID when connection_id_generator is nullptr.
    QUICHE_DCHECK_EQ(packet_list.connection_id_generator, nullptr);
    return;
  }
  // Process the current packet first, then deliver queued-up packets.
  // Note that multi-packet CHLOs, if received in packet number order, will
  // not be delivered in the same order. This needs to be fixed.
  session_ptr->ProcessUdpPacket(packet_info->self_address,
                                packet_info->peer_address, packet_info->packet);
  DeliverPacketsToSession(packet_list.buffered_packets, session_ptr.get());
  --new_sessions_allowed_per_event_loop_;
}

void QuicDispatcher::SetLastError(QuicErrorCode error) { last_error_ = error; }

bool QuicDispatcher::OnFailedToDispatchPacket(
    const ReceivedPacketInfo& /*packet_info*/) {
  return false;
}

const ParsedQuicVersionVector& QuicDispatcher::GetSupportedVersions() {
  return version_manager_->GetSupportedVersions();
}

void QuicDispatcher::DeliverPacketsToSession(
    const std::list<BufferedPacket>& packets, QuicSession* session) {
  for (const BufferedPacket& packet : packets) {
    session->ProcessUdpPacket(packet.self_address, packet.peer_address,
                              *(packet.packet));
  }
}

bool QuicDispatcher::IsSupportedVersion(const ParsedQuicVersion version) {
  for (const ParsedQuicVersion& supported_version :
       version_manager_->GetSupportedVersions()) {
    if (version == supported_version) {
      return true;
    }
  }
  return false;
}

bool QuicDispatcher::IsServerConnectionIdTooShort(
    QuicConnectionId connection_id) const {
  if (connection_id.length() >= kQuicMinimumInitialConnectionIdLength ||
      connection_id.length() >= expected_server_connection_id_length_) {
    return false;
  }
  uint8_t generator_output =
      connection_id.IsEmpty()
          ? connection_id_generator_.ConnectionIdLength(0x00)
          : connection_id_generator_.ConnectionIdLength(
                static_cast<uint8_t>(*connection_id.data()));
  return connection_id.length() < generator_output;
}

std::shared_ptr<QuicSession> QuicDispatcher::CreateSessionFromChlo(
    const QuicConnectionId original_connection_id,
    const std::optional<QuicConnectionId>& replaced_connection_id,
    const ParsedClientHello& parsed_chlo, const ParsedQuicVersion version,
    const QuicSocketAddress self_address, const QuicSocketAddress peer_address,
    TlsChloExtractor::State chlo_extractor_state,
    ConnectionIdGeneratorInterface* connection_id_generator,
    absl::Span<const DispatcherSentPacket> dispatcher_sent_packets) {
  bool should_generate_cid = false;
  if (connection_id_generator == nullptr) {
    should_generate_cid = true;
    connection_id_generator = &ConnectionIdGenerator();
  }
  std::optional<QuicConnectionId> server_connection_id;

  if (should_generate_cid) {
    server_connection_id = connection_id_generator->MaybeReplaceConnectionId(
        original_connection_id, version);
    // Normalize the output of MaybeReplaceConnectionId.
    if (server_connection_id.has_value() &&
        (server_connection_id->IsEmpty() ||
         *server_connection_id == original_connection_id)) {
      server_connection_id.reset();
    }
    QUIC_DVLOG(1) << "MaybeReplaceConnectionId(" << original_connection_id
                  << ") = "
                  << (server_connection_id.has_value()
                          ? server_connection_id->ToString()
                          : "nullopt");

    if (server_connection_id.has_value()) {
      switch (HandleConnectionIdCollision(
          original_connection_id, *server_connection_id, self_address,
          peer_address, version, &parsed_chlo)) {
        case VisitorInterface::HandleCidCollisionResult::kOk:
          break;
        case VisitorInterface::HandleCidCollisionResult::kCollision:
          return nullptr;
      }
    }
  } else {
    server_connection_id = replaced_connection_id;
  }

  const bool connection_id_replaced = server_connection_id.has_value();
  if (!connection_id_replaced) {
    server_connection_id = original_connection_id;
  }

  // Creates a new session and process all buffered packets for this connection.
  std::string alpn = SelectAlpn(parsed_chlo.alpns);
  std::unique_ptr<QuicSession> session =
      CreateQuicSession(*server_connection_id, self_address, peer_address, alpn,
                        version, parsed_chlo, *connection_id_generator);
  if (ABSL_PREDICT_FALSE(session == nullptr)) {
    QUIC_BUG(quic_bug_10287_8)
        << "CreateQuicSession returned nullptr for " << *server_connection_id
        << " from " << peer_address << " to " << self_address << " ALPN \""
        << alpn << "\" version " << version;
    return nullptr;
  }

  ++stats_.sessions_created;
  if (chlo_extractor_state ==
      TlsChloExtractor::State::kParsedFullMultiPacketChlo) {
    QUIC_CODE_COUNT(quic_connection_created_multi_packet_chlo);
    session->connection()->SetMultiPacketClientHello();
  } else {
    QUIC_CODE_COUNT(quic_connection_created_single_packet_chlo);
  }
  if (!dispatcher_sent_packets.empty()) {
    session->connection()->AddDispatcherSentPackets(dispatcher_sent_packets);
  }

  if (connection_id_replaced) {
    session->connection()->SetOriginalDestinationConnectionId(
        original_connection_id);
  }

  session->connection()->OnParsedClientHelloInfo(parsed_chlo);

  QUIC_DLOG(INFO) << "Created new session for " << *server_connection_id;

  auto insertion_result = reference_counted_session_map_.insert(std::make_pair(
      *server_connection_id, std::shared_ptr<QuicSession>(std::move(session))));
  std::shared_ptr<QuicSession> session_ptr = insertion_result.first->second;
  if (!insertion_result.second) {
    QUIC_BUG(quic_bug_10287_9)
        << "Tried to add a session to session_map with existing "
           "connection id: "
        << *server_connection_id;
  } else {
    ++num_sessions_in_session_map_;
    if (connection_id_replaced) {
      auto insertion_result2 = reference_counted_session_map_.insert(
          std::make_pair(original_connection_id, session_ptr));
      QUIC_BUG_IF(quic_460317833_02, !insertion_result2.second)
          << "Original connection ID already in session_map: "
          << original_connection_id;
      // If insertion of the original connection ID fails, it might cause
      // loss of 0-RTT and other first flight packets, but the connection
      // will usually progress.
    }
  }
  return session_ptr;
}

QuicDispatcher::HandleCidCollisionResult
QuicDispatcher::HandleConnectionIdCollision(
    const QuicConnectionId& original_connection_id,
    const QuicConnectionId& replaced_connection_id,
    const QuicSocketAddress& self_address,
    const QuicSocketAddress& peer_address, ParsedQuicVersion version,
    const ParsedClientHello* parsed_chlo) {
  HandleCidCollisionResult result = HandleCidCollisionResult::kOk;
  auto existing_session_iter =
      reference_counted_session_map_.find(replaced_connection_id);
  if (existing_session_iter != reference_counted_session_map_.end()) {
    // Collide with an active session in dispatcher.
    result = HandleCidCollisionResult::kCollision;
    QUIC_CODE_COUNT(quic_connection_id_collision);
    QuicConnection* other_connection =
        existing_session_iter->second->connection();
    if (other_connection != nullptr) {  // Just make sure there is no crash.
      QUIC_LOG_EVERY_N_SEC(ERROR, 10)
          << "QUIC Connection ID collision. original_connection_id:"
          << original_connection_id
          << ", replaced_connection_id:" << replaced_connection_id
          << ", version:" << version << ", self_address:" << self_address
          << ", peer_address:" << peer_address << ", parsed_chlo:"
          << (parsed_chlo == nullptr ? "null" : parsed_chlo->ToString())
          << ", other peer address: " << other_connection->peer_address()
          << ", other CIDs: "
          << quiche::PrintElements(
                 other_connection->GetActiveServerConnectionIds())
          << ", other stats: " << other_connection->GetStats();
    }
  } else if (buffered_packets_.HasBufferedPackets(replaced_connection_id)) {
    // Collide with a buffered session in packet store.
    result = HandleCidCollisionResult::kCollision;
    QUIC_CODE_COUNT(quic_connection_id_collision_with_buffered_session);
  }

  if (result == HandleCidCollisionResult::kOk) {
    return result;
  }

  const bool collide_with_active_session =
      existing_session_iter != reference_counted_session_map_.end();
  QUIC_DLOG(INFO) << "QUIC Connection ID collision with "
                  << (collide_with_active_session ? "active session"
                                                  : "buffered session")
                  << " for original_connection_id:" << original_connection_id
                  << ", replaced_connection_id:" << replaced_connection_id;

  // The original connection ID does not correspond to an existing
  // session. It is safe to send CONNECTION_CLOSE and add to TIME_WAIT.
  StatelesslyTerminateConnection(
      self_address, peer_address, original_connection_id,
      IETF_QUIC_LONG_HEADER_PACKET,
      /*version_flag=*/true, version.HasLengthPrefixedConnectionIds(), version,
      QUIC_HANDSHAKE_FAILED_CID_COLLISION,
      "Connection ID collision, please retry",
      QuicTimeWaitListManager::SEND_CONNECTION_CLOSE_PACKETS);

  // Caller is responsible for erasing the connection from the buffered store,
  // if needed.
  return result;
}

void QuicDispatcher::MaybeResetPacketsWithNoVersion(
    const ReceivedPacketInfo& packet_info) {
  QUICHE_DCHECK(!packet_info.version_flag);
  // Do not send a stateless reset if a reset has been sent to this address
  // recently.
  if (recent_stateless_reset_addresses_.contains(packet_info.peer_address)) {
    QUIC_CODE_COUNT(quic_donot_send_reset_repeatedly);
    return;
  }
  if (packet_info.form != GOOGLE_QUIC_PACKET) {
    // Drop IETF packets smaller than the minimal stateless reset length.
    if (packet_info.packet.length() <=
        QuicFramer::GetMinStatelessResetPacketLength()) {
      QUIC_CODE_COUNT(quic_drop_too_small_short_header_packets);
      return;
    }
  } else {
    const size_t MinValidPacketLength =
        kPacketHeaderTypeSize + expected_server_connection_id_length_ +
        PACKET_1BYTE_PACKET_NUMBER + /*payload size=*/1 + /*tag size=*/12;
    if (packet_info.packet.length() < MinValidPacketLength) {
      // The packet size is too small.
      QUIC_CODE_COUNT(drop_too_small_packets);
      return;
    }
  }
  // Do not send a stateless reset if there are too many stateless reset
  // addresses.
  if (recent_stateless_reset_addresses_.size() >=
      GetQuicFlag(quic_max_recent_stateless_reset_addresses)) {
    QUIC_CODE_COUNT(quic_too_many_recent_reset_addresses);
    return;
  }
  if (recent_stateless_reset_addresses_.empty()) {
    clear_stateless_reset_addresses_alarm_->Update(
        helper()->GetClock()->ApproximateNow() +
            QuicTime::Delta::FromMilliseconds(
                GetQuicFlag(quic_recent_stateless_reset_addresses_lifetime_ms)),
        QuicTime::Delta::Zero());
  }
  recent_stateless_reset_addresses_.emplace(packet_info.peer_address);

  time_wait_list_manager()->SendPublicReset(
      packet_info.self_address, packet_info.peer_address,
      packet_info.destination_connection_id,
      packet_info.form != GOOGLE_QUIC_PACKET, packet_info.packet.length(),
      GetPerPacketContext());
}

void QuicDispatcher::MaybeSendVersionNegotiationPacket(
    const ReceivedPacketInfo& packet_info) {
  if (crypto_config()->validate_chlo_size() &&
      packet_info.packet.length() < kMinPacketSizeForVersionNegotiation) {
    return;
  }
  time_wait_list_manager()->SendVersionNegotiationPacket(
      packet_info.destination_connection_id, packet_info.source_connection_id,
      packet_info.form != GOOGLE_QUIC_PACKET, packet_info.use_length_prefix,
      GetSupportedVersions(), packet_info.self_address,
      packet_info.peer_address, GetPerPacketContext());
}

size_t QuicDispatcher::NumSessions() const {
  return num_sessions_in_session_map_;
}

}  // namespace quic
```