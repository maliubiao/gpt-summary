Response:
My thinking process to analyze the provided code snippet went through these stages:

1. **Understanding the Context:** I immediately recognized that this was a continuation of a larger source code file related to QUIC in Chromium's networking stack. The numbering ("Part 5 of 5") confirmed this. The file name, `quic_chromium_client_session.cc`, clearly indicated it deals with the client-side QUIC session management within the Chromium environment.

2. **Scanning for Key Functionality:** I quickly skimmed the code looking for keywords and patterns that signify distinct functionalities. I noticed sections related to:
    * **Network Disconnection/Degradation Monitoring:** The `OnNetworkMadeDefault` and related UMA histograms stood out.
    * **Connection Migration:**  The numerous functions prefixed with `LogMigration`, `HistogramAndLogMigration`, `Migrate`, `FinishMigrate`, and `MigrateToSocket` were strong indicators. The different migration causes (path degrading, server preferred address) were also evident.
    * **Session Information Retrieval:** The `GetInfoAsValue` function was clearly for introspection and debugging.
    * **Error Handling:** The `OnReadError` function deals with socket-level errors.
    * **Packet Processing:** The `OnPacket` function handles incoming QUIC packets.
    * **Session Lifecycle Management:** Functions like `NotifyFactoryOfSessionGoingAway`, `NotifyFactoryOfSessionClosedLater`, and `NotifyFactoryOfSessionClosed` are crucial for managing the session's lifetime.
    * **Handshake Completion:** The `OnCryptoHandshakeComplete` function signifies a key stage in the QUIC connection setup.
    * **Socket Management:** Functions interacting with `DatagramClientSocket`.
    * **Metrics and Logging:**  The extensive use of `UMA_HISTOGRAM_*` and `net_log_.AddEvent` was apparent.
    * **WebSockets Integration:** The presence of `CreateWebSocketQuicStreamAdapterImpl` and related functions signaled this specific feature.

3. **Analyzing Specific Sections:** Once I had a general understanding, I delved into the details of each identified functional area:

    * **Network Monitoring:** I noted how `OnNetworkMadeDefault` tracks the duration of disconnections and degradation using UMA histograms. The logic checks if a new network has become the default.
    * **Connection Migration:** This was a significant part. I carefully examined the different logging functions (`LogMigrationResultToHistogram`, `HistogramAndLogMigrationFailure`, `HistogramAndLogMigrationSuccess`) and how they categorize migration attempts by cause. The `Migrate` and `FinishMigrate` functions outline the process of switching to a new socket, including error handling and callbacks. `MigrateToSocket` describes the actual migration at the QUIC layer.
    * **Session Information:** I saw that `GetInfoAsValue` gathers various session statistics for debugging.
    * **Error Handling:** I understood that `OnReadError` specifically deals with socket read errors, distinguishing between different socket types and the migration state.
    * **Packet Processing:**  I noted that `OnPacket` hands off the packet and tracks ECN.
    * **Session Lifecycle:** I grasped the purpose of the `NotifyFactory*` functions in informing the session pool about the session's state changes.
    * **Handshake Completion:** I saw that `OnCryptoHandshakeComplete` updates timing information, informs handles, and potentially triggers migration back to the default network.
    * **WebSockets:**  I observed the creation of `WebSocketQuicStreamAdapter` and how it manages pending requests when a new bidirectional stream cannot be opened immediately.

4. **Identifying Relationships and Connections:** I looked for how the different functions interacted. For instance, how a network change triggers a migration attempt, which in turn uses socket management functions and logs the outcome.

5. **Considering JavaScript Relevance:** I specifically looked for interactions with higher-level browser functionality. While the code itself doesn't directly call JavaScript APIs, the fact that it handles network connections for web content makes it indirectly related. WebSockets being explicitly handled is a more direct connection.

6. **Inferring Assumptions and Scenarios:** I considered what would trigger certain code paths. For example, a user switching Wi-Fi networks would likely lead to the `OnNetworkMadeDefault` logic being executed and potentially a connection migration. A server sending a preferred address would trigger the `OnServerPreferredAddressAvailable` logic.

7. **Identifying Potential Errors:** I looked for places where things could go wrong, such as socket connection failures during migration or exceeding migration limits.

8. **Structuring the Output:** I organized my findings into clear categories (Functionality, JavaScript Relationship, Logical Inference, User/Programming Errors, User Journey, Summary) to provide a comprehensive explanation.

Essentially, I approached the code like a detective examining clues. I started with the big picture, then zoomed in on specific details, and finally pieced everything together to understand the overall function and purpose of this code snippet within the larger Chromium networking ecosystem. The "Part 5 of 5" hint was crucial in understanding this was the concluding part and thus likely contained important finalization and cleanup logic.
这是 `net/quic/quic_chromium_client_session.cc` 文件的第五部分，也是最后一部分。 从代码内容来看，这部分主要关注 **连接迁移、会话信息获取、错误处理、会话生命周期管理以及与 WebSocket 的集成**。

以下是其功能的详细列举：

**核心功能：**

* **处理网络变化和连接迁移:**
    * **`OnNetworkMadeDefault()`:**  记录网络变为默认网络时的事件，并计算断开连接或降级持续的时间，用于 UMA 统计。
    * **`LogMigrationResultToHistogram()`:**  根据连接迁移的状态（成功、失败等）和原因，将结果记录到不同的 UMA 直方图中。原因包括因路径降级而更改端口和服务器首选地址可用。
    * **`LogHandshakeStatusOnMigrationSignal()`:** 在收到迁移信号时记录握手状态，也根据不同的迁移原因进行区分。
    * **`HistogramAndLogMigrationFailure()` 和 `HistogramAndLogMigrationSuccess()`:**  记录连接迁移的失败和成功事件，包括将其添加到网络日志中，并调用 `LogMigrationResultToHistogram()`。
    * **`Migrate()`:**  启动连接迁移过程，尝试使用新的网络接口和地址。
    * **`FinishMigrate()`:**  完成连接迁移，处理 socket 配置的成功或失败，并创建新的 packet reader 和 writer。
    * **`MigrateToSocket()`:**  将连接迁移到新的 socket，更新连接的地址信息。
    * **`WriteToNewSocket()`:**  在迁移到新 socket 后发送数据。
    * **`OnServerPreferredAddressAvailable()`:**  当服务器提供首选地址时，启动探测以验证该地址是否可用。
    * **`GetCurrentNetwork()`:**  获取当前连接使用的网络句柄。

* **提供会话信息:**
    * **`GetInfoAsValue()`:**  返回包含会话信息的 `base::Value::Dict`，用于调试和监控。信息包括版本、打开的流、活跃流列表、总流数、对等地址、连接 ID、连接状态、收发包统计等。

* **处理错误:**
    * **`OnReadError()`:**  处理 socket 读取错误，并根据错误类型和迁移状态决定是否关闭连接。

* **管理会话生命周期:**
    * **`OnPacket()`:**  处理接收到的 QUIC 数据包，并更新 ECN 相关的统计信息。
    * **`NotifyFactoryOfSessionGoingAway()` 和 `NotifyFactoryOfSessionClosedLater()` 和 `NotifyFactoryOfSessionClosed()`:** 通知 `QuicSessionPool` 会话即将关闭或已关闭。
    * **`OnCryptoHandshakeComplete()`:**  在加密握手完成后执行操作，例如更新连接时间、通知请求、以及可能触发迁移回默认网络。

* **与 WebSocket 集成 (如果启用):**
    * **`CreateWebSocketQuicStreamAdapterImpl()`:**  创建一个用于 WebSocket 的 `QuicStream` 适配器。
    * **`CreateWebSocketQuicStreamAdapter()`:**  创建 WebSocket 的 `QuicStream` 适配器，如果无法立即创建（例如，达到最大流数），则将请求放入队列。

* **其他:**
    * **`gquic_zero_rtt_disabled()`:**  检查是否禁用了 gQUIC 的 0-RTT 功能。
    * **`CreateHandle()`:**  创建一个 `QuicChromiumClientSession::Handle`，用于管理会话的生命周期。
    * **`PopulateNetErrorDetails()`:**  填充 `NetErrorDetails` 结构体，包含 QUIC 相关的错误信息。
    * **`GetDefaultSocket()`:**  获取当前默认的 `DatagramClientSocket`。
    * **`GetConnectTiming()`:**  返回连接时间信息。
    * **`GetQuicVersion()`:**  返回当前使用的 QUIC 版本。
    * **`GetDnsAliasesForSessionKey()`:**  获取与给定 `QuicSessionKey` 关联的 DNS 别名。
    * **`Handle::GetGuaranteedLargestMessagePayload()`:**  获取保证的最大消息负载大小。

**与 JavaScript 的关系举例：**

虽然此代码是 C++ 实现的网络栈的一部分，但它直接支持浏览器中 JavaScript 发起的网络请求。

* **用户在浏览器中打开一个使用 HTTPS 或 HTTP/3 的网页:** JavaScript 发起 HTTP 请求，Chromium 网络栈会尝试使用 QUIC。 `QuicChromiumClientSession` 负责管理与服务器的 QUIC 连接。
* **JavaScript 使用 WebSocket API 创建 WebSocket 连接:** 此代码中的 `CreateWebSocketQuicStreamAdapter` 函数会被调用，创建一个基于 QUIC 的 WebSocket 连接。JavaScript 通过 WebSocket API 发送和接收数据，底层由这里的 QUIC 会话进行传输。
* **网络切换或信号不好导致连接不稳定:** 当网络发生变化（例如，从 Wi-Fi 切换到移动数据），或者网络质量下降时，此代码中的连接迁移逻辑会被触发，尝试在不中断用户体验的情况下切换到新的网络路径。这个过程对 JavaScript 是透明的。
* **开发者使用 Chrome 的 `chrome://net-internals/#quic` 查看 QUIC 连接信息:**  `GetInfoAsValue()` 函数提供的数据会在此页面上展示，帮助开发者调试 QUIC 连接。

**逻辑推理，假设输入与输出：**

假设用户设备从一个 Wi-Fi 网络切换到另一个 Wi-Fi 网络：

* **假设输入:**
    * `OnNetworkMadeDefault()` 被调用，表示新的 Wi-Fi 网络成为默认网络。
    * `most_recent_network_disconnected_timestamp_` 记录了旧 Wi-Fi 断开连接的时间。
    * `tick_clock_->NowTicks()` 返回当前时间。
* **逻辑推理:**
    * `disconnection_duration` 将会被计算出来，表示旧 Wi-Fi 断开连接的持续时间。
    * `degrading_duration` 也可能被计算出来，如果之前有路径降级的记录。
    * 相应的 UMA 直方图（例如，`Net.QuicNetworkDisconnectionDuration`）会被更新，记录这次断开连接的持续时间。
* **假设输出:**
    * UMA 数据被更新，用于 Chrome 的遥测分析。
    * 如果启用了连接迁移，并且满足迁移条件，可能会触发 `Migrate()` 函数，尝试迁移到新网络。

**用户或编程常见的使用错误举例：**

* **用户错误:**
    * **在网络环境不稳定的情况下，频繁切换网络:**  可能会导致连接迁移过于频繁，触发 `MigrateToSocket()` 中的 `kMaxReadersPerQuicSession` 限制，导致连接失败。
* **编程错误 (在 Chromium 网络栈的开发中):**
    * **在调用 `Migrate()` 后没有正确处理 `MigrationCallback`:** 可能导致资源泄漏或者状态不一致。
    * **在连接迁移过程中，没有正确处理 pending 的 stream:**  可能会导致数据丢失或请求失败。
    * **错误地配置 socket 选项:**  可能导致 `FinishMigrate()` 中 socket 配置失败。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户打开一个网页 (例如 `https://www.example.com`)：** 浏览器发起 DNS 查询和连接建立过程。如果服务器支持 QUIC，并且客户端启用了 QUIC，则会尝试建立 QUIC 连接。
2. **`QuicChromiumClientSession` 对象被创建:**  这个类负责管理与服务器的 QUIC 连接。
3. **网络环境发生变化 (例如，用户关闭 Wi-Fi 并使用移动数据):**  操作系统会通知网络栈网络状态的改变。
4. **`NetworkChangeNotifier::NotifyObserversOfNetworkChange()` (或其他类似机制) 被调用:**  Chromium 的网络观察者会收到通知。
5. **`QuicNetworkChangeNotifier` (或其他相关类) 监听到网络变化:**  可能会触发连接迁移的逻辑。
6. **`QuicChromiumClientSession::OnNetworkMadeDefault()` (或其他迁移触发函数) 被调用:**  开始评估是否需要进行连接迁移。
7. **如果满足迁移条件，`QuicChromiumClientSession::Migrate()` 被调用:**  尝试迁移到新的网络接口。
8. **`QuicChromiumClientSession::FinishMigrate()` 处理 socket 的创建和配置。**
9. **`QuicChromiumClientSession::MigrateToSocket()` 执行底层的连接迁移操作。**

在调试时，可以通过以下方式观察到这个过程：

* **使用 Chrome 的 `chrome://net-internals/#events` 查看网络事件:**  可以查看连接迁移的开始、失败或成功的事件。
* **使用 `chrome://net-internals/#quic` 查看 QUIC 会话的状态:**  可以看到连接是否发生了迁移，以及迁移的原因。
* **在代码中添加日志输出:**  在关键的函数中添加 `DLOG` 或 `VLOG` 输出，以便跟踪代码的执行流程。

**总结其功能：**

作为 `net/quic/quic_chromium_client_session.cc` 文件的最后一部分，这段代码主要负责 **处理 QUIC 客户端连接的复杂场景，特别是网络变化时的连接迁移，并提供会话信息和错误处理机制。它还集成了 WebSocket over QUIC 的功能，并管理着 QUIC 会话的生命周期。**  其核心目标是在网络环境变化时，尽可能地保持连接的稳定性和用户体验的连续性。

Prompt: 
```
这是目录为net/quic/quic_chromium_client_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共5部分，请归纳一下它的功能

"""
efault, the platform
      // is dropping WiFi.
      base::TimeTicks now = tick_clock_->NowTicks();
      base::TimeDelta disconnection_duration =
          now - most_recent_network_disconnected_timestamp_;
      base::TimeDelta degrading_duration =
          now - most_recent_path_degrading_timestamp_;
      UMA_HISTOGRAM_CUSTOM_TIMES("Net.QuicNetworkDisconnectionDuration",
                                 disconnection_duration, base::Milliseconds(1),
                                 base::Minutes(10), 100);
      UMA_HISTOGRAM_CUSTOM_TIMES(
          "Net.QuicNetworkDegradingDurationTillNewNetworkMadeDefault",
          degrading_duration, base::Milliseconds(1), base::Minutes(10), 100);
      most_recent_network_disconnected_timestamp_ = base::TimeTicks();
    }
    most_recent_path_degrading_timestamp_ = base::TimeTicks();
  }
}

void QuicChromiumClientSession::LogMigrationResultToHistogram(
    QuicConnectionMigrationStatus status) {
  if (current_migration_cause_ == CHANGE_PORT_ON_PATH_DEGRADING) {
    UMA_HISTOGRAM_ENUMERATION("Net.QuicSession.PortMigration", status,
                              MIGRATION_STATUS_MAX);
    current_migration_cause_ = UNKNOWN_CAUSE;
    return;
  }

  if (current_migration_cause_ == ON_SERVER_PREFERRED_ADDRESS_AVAILABLE) {
    UMA_HISTOGRAM_ENUMERATION(
        "Net.QuicSession.OnServerPreferredAddressAvailable", status,
        MIGRATION_STATUS_MAX);
    current_migration_cause_ = UNKNOWN_CAUSE;
    return;
  }

  UMA_HISTOGRAM_ENUMERATION("Net.QuicSession.ConnectionMigration", status,
                            MIGRATION_STATUS_MAX);

  // Log the connection migraiton result to different histograms based on the
  // cause of the connection migration.
  std::string histogram_name = "Net.QuicSession.ConnectionMigration." +
                               MigrationCauseToString(current_migration_cause_);
  base::UmaHistogramEnumeration(histogram_name, status, MIGRATION_STATUS_MAX);
  current_migration_cause_ = UNKNOWN_CAUSE;
}

void QuicChromiumClientSession::LogHandshakeStatusOnMigrationSignal() const {
  if (current_migration_cause_ == CHANGE_PORT_ON_PATH_DEGRADING) {
    UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.HandshakeStatusOnPortMigration",
                          OneRttKeysAvailable());
    return;
  }

  if (current_migration_cause_ == ON_SERVER_PREFERRED_ADDRESS_AVAILABLE) {
    UMA_HISTOGRAM_BOOLEAN(
        "Net.QuicSession.HandshakeStatusOnMigratingToServerPreferredAddress",
        OneRttKeysAvailable());
    return;
  }

  UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.HandshakeStatusOnConnectionMigration",
                        OneRttKeysAvailable());

  const std::string histogram_name =
      "Net.QuicSession.HandshakeStatusOnConnectionMigration." +
      MigrationCauseToString(current_migration_cause_);
  STATIC_HISTOGRAM_POINTER_GROUP(
      histogram_name, current_migration_cause_, MIGRATION_CAUSE_MAX,
      AddBoolean(OneRttKeysAvailable()),
      base::BooleanHistogram::FactoryGet(
          histogram_name, base::HistogramBase::kUmaTargetedHistogramFlag));
}

void QuicChromiumClientSession::HistogramAndLogMigrationFailure(
    QuicConnectionMigrationStatus status,
    quic::QuicConnectionId connection_id,
    const char* reason) {
  NetLogEventType event_type =
      NetLogEventType::QUIC_CONNECTION_MIGRATION_FAILURE;
  if (current_migration_cause_ == CHANGE_PORT_ON_PATH_DEGRADING) {
    event_type = NetLogEventType::QUIC_PORT_MIGRATION_FAILURE;
  } else if (current_migration_cause_ ==
             ON_SERVER_PREFERRED_ADDRESS_AVAILABLE) {
    event_type =
        NetLogEventType::QUIC_FAILED_TO_VALIDATE_SERVER_PREFERRED_ADDRESS;
  }

  net_log_.AddEvent(event_type, [&] {
    return NetLogQuicMigrationFailureParams(connection_id, reason);
  });

  // |current_migration_cause_| will be reset afterwards.
  LogMigrationResultToHistogram(status);
}

void QuicChromiumClientSession::HistogramAndLogMigrationSuccess(
    quic::QuicConnectionId connection_id) {
  NetLogEventType event_type =
      NetLogEventType::QUIC_CONNECTION_MIGRATION_SUCCESS;
  if (current_migration_cause_ == CHANGE_PORT_ON_PATH_DEGRADING) {
    event_type = NetLogEventType::QUIC_PORT_MIGRATION_SUCCESS;
  } else if (current_migration_cause_ ==
             ON_SERVER_PREFERRED_ADDRESS_AVAILABLE) {
    event_type =
        NetLogEventType::QUIC_SUCCESSFULLY_MIGRATED_TO_SERVER_PREFERRED_ADDRESS;
  }

  net_log_.AddEvent(event_type, [&] {
    return NetLogQuicMigrationSuccessParams(connection_id);
  });

  // |current_migration_cause_| will be reset afterwards.
  LogMigrationResultToHistogram(MIGRATION_STATUS_SUCCESS);
}

base::Value::Dict QuicChromiumClientSession::GetInfoAsValue(
    const std::set<HostPortPair>& aliases) {
  base::Value::Dict dict;
  dict.Set("version", ParsedQuicVersionToString(connection()->version()));
  dict.Set("open_streams", static_cast<int>(GetNumActiveStreams()));

  base::Value::List stream_list;
  auto* stream_list_ptr = &stream_list;

  PerformActionOnActiveStreams([stream_list_ptr](quic::QuicStream* stream) {
    stream_list_ptr->Append(base::NumberToString(stream->id()));
    return true;
  });

  dict.Set("active_streams", std::move(stream_list));

  dict.Set("total_streams", static_cast<int>(num_total_streams_));
  dict.Set("peer_address", peer_address().ToString());
  dict.Set("network_anonymization_key",
           session_key_.network_anonymization_key().ToDebugString());
  dict.Set("connection_id", connection_id().ToString());
  if (!connection()->client_connection_id().IsEmpty()) {
    dict.Set("client_connection_id",
             connection()->client_connection_id().ToString());
  }
  dict.Set("connected", connection()->connected());
  const quic::QuicConnectionStats& stats = connection()->GetStats();
  dict.Set("packets_sent", static_cast<int>(stats.packets_sent));
  dict.Set("packets_received", static_cast<int>(stats.packets_received));
  dict.Set("packets_lost", static_cast<int>(stats.packets_lost));
  SSLInfo ssl_info;

  base::Value::List alias_list;
  for (const auto& alias : aliases) {
    alias_list.Append(alias.ToString());
  }
  dict.Set("aliases", std::move(alias_list));

  return dict;
}

bool QuicChromiumClientSession::gquic_zero_rtt_disabled() const {
  if (!session_pool_) {
    return false;
  }
  return session_pool_->gquic_zero_rtt_disabled();
}

std::unique_ptr<QuicChromiumClientSession::Handle>
QuicChromiumClientSession::CreateHandle(url::SchemeHostPort destination) {
  return std::make_unique<QuicChromiumClientSession::Handle>(
      weak_factory_.GetWeakPtr(), std::move(destination));
}

bool QuicChromiumClientSession::OnReadError(
    int result,
    const DatagramClientSocket* socket) {
  DCHECK(socket != nullptr);
  base::UmaHistogramSparse("Net.QuicSession.ReadError.AnyNetwork", -result);
  if (socket != GetDefaultSocket()) {
    DVLOG(1) << "Ignoring read error " << ErrorToString(result)
             << " on old socket";
    base::UmaHistogramSparse("Net.QuicSession.ReadError.OtherNetworks",
                             -result);
    // Ignore read errors from sockets that are not affecting the current
    // network, i.e., sockets that are no longer active and probing socket.
    // TODO(jri): Maybe clean up old sockets on error.
    return false;
  }

  if (ignore_read_error_) {
    DVLOG(1) << "Ignoring read error " << ErrorToString(result)
             << " during pending migration";
    // Ignore read errors during pending migration. Connection will be closed if
    // pending migration failed or timed out.
    base::UmaHistogramSparse("Net.QuicSession.ReadError.PendingMigration",
                             -result);
    return false;
  }

  base::UmaHistogramSparse("Net.QuicSession.ReadError.CurrentNetwork", -result);
  if (OneRttKeysAvailable()) {
    base::UmaHistogramSparse(
        "Net.QuicSession.ReadError.CurrentNetwork.HandshakeConfirmed", -result);
  }

  DVLOG(1) << "Closing session on read error " << ErrorToString(result);
  connection()->CloseConnection(quic::QUIC_PACKET_READ_ERROR,
                                ErrorToString(result),
                                quic::ConnectionCloseBehavior::SILENT_CLOSE);
  return false;
}

bool QuicChromiumClientSession::OnPacket(
    const quic::QuicReceivedPacket& packet,
    const quic::QuicSocketAddress& local_address,
    const quic::QuicSocketAddress& peer_address) {
  ProcessUdpPacket(local_address, peer_address, packet);
  uint8_t new_incoming_ecn =
      (0x1 << static_cast<uint8_t>(packet.ecn_codepoint()));
  if (new_incoming_ecn != observed_incoming_ecn_ &&
      incoming_packets_before_ecn_transition_ > 0) {
    observed_ecn_transition_ = true;
  }
  if (!observed_ecn_transition_) {
    ++incoming_packets_before_ecn_transition_;
  }
  observed_incoming_ecn_ |= new_incoming_ecn;
  if (!connection()->connected()) {
    NotifyFactoryOfSessionClosedLater();
    return false;
  }
  return true;
}

void QuicChromiumClientSession::NotifyFactoryOfSessionGoingAway() {
  going_away_ = true;
  if (session_pool_) {
    session_pool_->OnSessionGoingAway(this);
  }
}

void QuicChromiumClientSession::NotifyFactoryOfSessionClosedLater() {
  going_away_ = true;
  DCHECK_EQ(0u, GetNumActiveStreams());
  DCHECK(!connection()->connected());
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&QuicChromiumClientSession::NotifyFactoryOfSessionClosed,
                     weak_factory_.GetWeakPtr()));
}

void QuicChromiumClientSession::NotifyFactoryOfSessionClosed() {
  going_away_ = true;
  DCHECK_EQ(0u, GetNumActiveStreams());
  // Will delete |this|.
  if (session_pool_) {
    session_pool_->OnSessionClosed(this);
  }
}

void QuicChromiumClientSession::OnCryptoHandshakeComplete() {
  if (session_pool_) {
    session_pool_->set_has_quic_ever_worked_on_current_network(true);
  }

  // Update |connect_end| only when handshake is confirmed. This should also
  // take care of any failed 0-RTT request.
  connect_timing_.connect_end = tick_clock_->NowTicks();
  DCHECK_LE(connect_timing_.connect_start, connect_timing_.connect_end);
  base::TimeDelta handshake_confirmed_time =
      connect_timing_.connect_end - connect_timing_.connect_start;
  UMA_HISTOGRAM_TIMES("Net.QuicSession.HandshakeConfirmedTime",
                      handshake_confirmed_time);

  // Also record the handshake time when ECH was advertised in DNS. The ECH
  // experiment does not change DNS behavior, so this measures the same servers
  // in both experiment and control groups.
  if (!ech_config_list_.empty()) {
    UMA_HISTOGRAM_TIMES("Net.QuicSession.HandshakeConfirmedTime.ECH",
                        handshake_confirmed_time);
  }

  // Track how long it has taken to finish handshake after we have finished
  // DNS host resolution.
  if (!connect_timing_.domain_lookup_end.is_null()) {
    UMA_HISTOGRAM_TIMES(
        "Net.QuicSession.HostResolution.HandshakeConfirmedTime",
        tick_clock_->NowTicks() - connect_timing_.domain_lookup_end);
  }

  auto it = handles_.begin();
  while (it != handles_.end()) {
    Handle* handle = *it;
    ++it;
    handle->OnCryptoHandshakeConfirmed();
  }

  NotifyRequestsOfConfirmation(OK);
  // Attempt to migrate back to the default network after handshake has been
  // confirmed if the session is not created on the default network.
  if (migrate_session_on_network_change_v2_ &&
      default_network_ != handles::kInvalidNetworkHandle &&
      GetCurrentNetwork() != default_network_) {
    current_migration_cause_ = ON_MIGRATE_BACK_TO_DEFAULT_NETWORK;
    StartMigrateBackToDefaultNetworkTimer(
        base::Seconds(kMinRetryTimeForDefaultNetworkSecs));
  }
}

void QuicChromiumClientSession::Migrate(handles::NetworkHandle network,
                                        IPEndPoint peer_address,
                                        bool close_session_on_error,
                                        MigrationCallback migration_callback) {
  quic_connection_migration_attempted_ = true;
  quic_connection_migration_successful_ = false;
  if (!session_pool_) {
    task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&QuicChromiumClientSession::DoMigrationCallback,
                       weak_factory_.GetWeakPtr(),
                       std::move(migration_callback),
                       MigrationResult::FAILURE));
    return;
  }

  if (network != handles::kInvalidNetworkHandle) {
    // This is a migration attempt from connection migration.
    ResetNonMigratableStreams();
    if (!migrate_idle_session_ && !HasActiveRequestStreams()) {
      task_runner_->PostTask(
          FROM_HERE,
          base::BindOnce(&QuicChromiumClientSession::DoMigrationCallback,
                         weak_factory_.GetWeakPtr(),
                         std::move(migration_callback),
                         MigrationResult::FAILURE));
      // If idle sessions can not be migrated, close the session if needed.
      if (close_session_on_error) {
        CloseSessionOnErrorLater(
            ERR_NETWORK_CHANGED,
            quic::QUIC_CONNECTION_MIGRATION_NO_MIGRATABLE_STREAMS,
            quic::ConnectionCloseBehavior::SILENT_CLOSE);
      }
      return;
    }
  }

  // Create and configure socket on |network|.
  std::unique_ptr<DatagramClientSocket> socket(
      session_pool_->CreateSocket(net_log_.net_log(), net_log_.source()));
  DatagramClientSocket* socket_ptr = socket.get();
  DVLOG(1) << "Force blocking the packet writer";
  static_cast<QuicChromiumPacketWriter*>(connection()->writer())
      ->set_force_write_blocked(true);
  if (base::FeatureList::IsEnabled(features::kDisableBlackholeOnNoNewNetwork)) {
    // Turn off the black hole detector since the writer is blocked.
    // Blackhole will be re-enabled once a packet is sent again.
    connection()->blackhole_detector().StopDetection(false);
  }
  CompletionOnceCallback connect_callback = base::BindOnce(
      &QuicChromiumClientSession::FinishMigrate, weak_factory_.GetWeakPtr(),
      std::move(socket), peer_address, close_session_on_error,
      std::move(migration_callback));

  if (!MidMigrationCallbackForTesting().is_null()) {
    std::move(MidMigrationCallbackForTesting()).Run();  // IN-TEST
  }

  session_pool_->ConnectAndConfigureSocket(std::move(connect_callback),
                                           socket_ptr, peer_address, network,
                                           session_key_.socket_tag());
}

void QuicChromiumClientSession::FinishMigrate(
    std::unique_ptr<DatagramClientSocket> socket,
    IPEndPoint peer_address,
    bool close_session_on_error,
    MigrationCallback callback,
    int rv) {
  if (rv != OK) {
    HistogramAndLogMigrationFailure(MIGRATION_STATUS_INTERNAL_ERROR,
                                    connection_id(),
                                    "Socket configuration failed");
    static_cast<QuicChromiumPacketWriter*>(connection()->writer())
        ->set_force_write_blocked(false);
    task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&QuicChromiumClientSession::DoMigrationCallback,
                       weak_factory_.GetWeakPtr(), std::move(callback),
                       MigrationResult::FAILURE));
    if (close_session_on_error) {
      CloseSessionOnErrorLater(ERR_NETWORK_CHANGED,
                               quic::QUIC_CONNECTION_MIGRATION_INTERNAL_ERROR,
                               quic::ConnectionCloseBehavior::SILENT_CLOSE);
    }
    return;
  }

  // Create new packet reader and writer on the new socket.
  auto new_reader = std::make_unique<QuicChromiumPacketReader>(
      std::move(socket), clock_, this, yield_after_packets_,
      yield_after_duration_, session_pool_->report_ecn(), net_log_);
  new_reader->StartReading();
  auto new_writer = std::make_unique<QuicChromiumPacketWriter>(
      new_reader->socket(), task_runner_);

  static_cast<QuicChromiumPacketWriter*>(connection()->writer())
      ->set_delegate(nullptr);
  new_writer->set_delegate(this);

  IPEndPoint self_address;
  new_reader->socket()->GetLocalAddress(&self_address);
  // Migrate to the new socket.
  if (!MigrateToSocket(ToQuicSocketAddress(self_address),
                       ToQuicSocketAddress(peer_address), std::move(new_reader),
                       std::move(new_writer))) {
    task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&QuicChromiumClientSession::DoMigrationCallback,
                       weak_factory_.GetWeakPtr(), std::move(callback),
                       MigrationResult::FAILURE));
    if (close_session_on_error) {
      CloseSessionOnErrorLater(ERR_NETWORK_CHANGED,
                               quic::QUIC_CONNECTION_MIGRATION_TOO_MANY_CHANGES,
                               quic::ConnectionCloseBehavior::SILENT_CLOSE);
    }
    return;
  }
  quic_connection_migration_successful_ = true;
  HistogramAndLogMigrationSuccess(connection_id());
  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&QuicChromiumClientSession::DoMigrationCallback,
                                weak_factory_.GetWeakPtr(), std::move(callback),
                                MigrationResult::SUCCESS));
}

void QuicChromiumClientSession::DoMigrationCallback(MigrationCallback callback,
                                                    MigrationResult rv) {
  std::move(callback).Run(rv);
}

bool QuicChromiumClientSession::MigrateToSocket(
    const quic::QuicSocketAddress& self_address,
    const quic::QuicSocketAddress& peer_address,
    std::unique_ptr<QuicChromiumPacketReader> reader,
    std::unique_ptr<QuicChromiumPacketWriter> writer) {
  // Writer must be destroyed before reader, since it points to the socket owned
  // by reader. C++ doesn't have any guarantees about destruction order of
  // arguments.
  std::unique_ptr<QuicChromiumPacketWriter> writer_moved = std::move(writer);

  // Sessions carried via a proxy should never migrate, and that is ensured
  // elsewhere (for each possible migration trigger).
  DUMP_WILL_BE_CHECK(session_key_.proxy_chain().is_direct());

  // TODO(zhongyi): figure out whether we want to limit the number of
  // connection migrations for v2, which includes migration on platform signals,
  // write error events, and path degrading on original network.
  if (!migrate_session_on_network_change_v2_ &&
      packet_readers_.size() >= kMaxReadersPerQuicSession) {
    HistogramAndLogMigrationFailure(MIGRATION_STATUS_TOO_MANY_CHANGES,
                                    connection_id(), "Too many changes");
    return false;
  }

  packet_readers_.push_back(std::move(reader));
  // Force the writer to be blocked to prevent it being used until
  // WriteToNewSocket completes.
  DVLOG(1) << "Force blocking the packet writer";
  writer_moved->set_force_write_blocked(true);
  if (!MigratePath(self_address, peer_address, writer_moved.release(),
                   /*owns_writer=*/true)) {
    HistogramAndLogMigrationFailure(MIGRATION_STATUS_NO_UNUSED_CONNECTION_ID,
                                    connection_id(),
                                    "No unused server connection ID");
    DVLOG(1) << "MigratePath fails as there is no CID available";
    return false;
  }
  // Post task to write the pending packet or a PING packet to the new
  // socket. This avoids reentrancy issues if there is a write error
  // on the write to the new socket.
  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&QuicChromiumClientSession::WriteToNewSocket,
                                weak_factory_.GetWeakPtr()));
  return true;
}

void QuicChromiumClientSession::PopulateNetErrorDetails(
    NetErrorDetails* details) const {
  details->quic_port_migration_detected = port_migration_detected_;
  details->quic_connection_error = error();
  details->source = source_;
  details->quic_connection_migration_attempted =
      quic_connection_migration_attempted_;
  details->quic_connection_migration_successful =
      quic_connection_migration_successful_;
}

const DatagramClientSocket* QuicChromiumClientSession::GetDefaultSocket()
    const {
  DCHECK(packet_readers_.back()->socket() != nullptr);
  // The most recently added socket is the currently active one.
  return packet_readers_.back()->socket();
}

handles::NetworkHandle QuicChromiumClientSession::GetCurrentNetwork() const {
  // If connection migration is enabled, alternate network interface may be
  // used to send packet, it is identified as the bound network of the default
  // socket. Otherwise, always use |default_network_|.
  return migrate_session_on_network_change_v2_
             ? GetDefaultSocket()->GetBoundNetwork()
             : default_network_;
}

void QuicChromiumClientSession::OnServerPreferredAddressAvailable(
    const quic::QuicSocketAddress& server_preferred_address) {
  // If this is a proxied connection, we cannot perform any migration, so
  // ignore the server preferred address.
  if (!session_key_.proxy_chain().is_direct()) {
    net_log_.AddEvent(NetLogEventType::QUIC_CONNECTION_MIGRATION_FAILURE, [&] {
      return NetLogQuicMigrationFailureParams(
          connection_id(),
          "Ignored server preferred address received via proxied connection");
    });
    return;
  }
  if (!allow_server_preferred_address_) {
    return;
  }

  current_migration_cause_ = ON_SERVER_PREFERRED_ADDRESS_AVAILABLE;

  net_log_.BeginEvent(
      NetLogEventType::QUIC_ON_SERVER_PREFERRED_ADDRESS_AVAILABLE);

  if (!session_pool_) {
    return;
  }

  StartProbing(base::DoNothingAs<void(ProbingResult)>(), default_network_,
               server_preferred_address);
  net_log_.EndEvent(
      NetLogEventType::QUIC_START_VALIDATING_SERVER_PREFERRED_ADDRESS);
}

const LoadTimingInfo::ConnectTiming&
QuicChromiumClientSession::GetConnectTiming() {
  connect_timing_.ssl_start = connect_timing_.connect_start;
  connect_timing_.ssl_end = connect_timing_.connect_end;
  return connect_timing_;
}

quic::ParsedQuicVersion QuicChromiumClientSession::GetQuicVersion() const {
  return connection()->version();
}

const std::set<std::string>&
QuicChromiumClientSession::GetDnsAliasesForSessionKey(
    const QuicSessionKey& key) const {
  static const base::NoDestructor<std::set<std::string>> emptyset_result;
  return session_pool_ ? session_pool_->GetDnsAliasesForSessionKey(key)
                       : *emptyset_result;
}

quic::QuicPacketLength
QuicChromiumClientSession::Handle::GetGuaranteedLargestMessagePayload() const {
  if (!session_) {
    return 0;
  }
  return session_->GetGuaranteedLargestMessagePayload();
}

#if BUILDFLAG(ENABLE_WEBSOCKETS)
std::unique_ptr<WebSocketQuicStreamAdapter>
QuicChromiumClientSession::CreateWebSocketQuicStreamAdapterImpl(
    WebSocketQuicStreamAdapter::Delegate* delegate) {
  DCHECK(connection()->connected());
  DCHECK(CanOpenNextOutgoingBidirectionalStream());
  auto websocket_quic_spdy_stream = std::make_unique<WebSocketQuicSpdyStream>(
      GetNextOutgoingBidirectionalStreamId(), this, quic::BIDIRECTIONAL);

  auto adapter = std::make_unique<WebSocketQuicStreamAdapter>(
      websocket_quic_spdy_stream.get(), delegate);
  ActivateStream(std::move(websocket_quic_spdy_stream));

  ++num_total_streams_;
  return adapter;
}

std::unique_ptr<WebSocketQuicStreamAdapter>
QuicChromiumClientSession::CreateWebSocketQuicStreamAdapter(
    WebSocketQuicStreamAdapter::Delegate* delegate,
    base::OnceCallback<void(std::unique_ptr<WebSocketQuicStreamAdapter>)>
        callback,
    StreamRequest* stream_request) {
  DCHECK(connection()->connected());
  if (!CanOpenNextOutgoingBidirectionalStream()) {
    stream_request->pending_start_time_ = tick_clock_->NowTicks();
    stream_request->for_websockets_ = true;
    stream_request->websocket_adapter_delegate_ = delegate;
    stream_request->start_websocket_callback_ = std::move(callback);

    stream_requests_.push_back(stream_request);
    UMA_HISTOGRAM_COUNTS_1000("Net.QuicSession.NumPendingStreamRequests",
                              stream_requests_.size());
    return nullptr;
  }

  return CreateWebSocketQuicStreamAdapterImpl(delegate);
}
#endif  // BUILDFLAG(ENABLE_WEBSOCKETS)

}  // namespace net

"""


```