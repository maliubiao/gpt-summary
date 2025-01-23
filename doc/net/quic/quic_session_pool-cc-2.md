Response:
The user wants to understand the functionality of the provided C++ code snippet from `net/quic/quic_session_pool.cc`. The request has several parts:

1. **List the functionalities:** I need to identify the core actions and purposes of the code.
2. **Relation to JavaScript:**  Explore if any of the functionalities directly or indirectly impact or relate to JavaScript execution in a browser context.
3. **Logical Reasoning (Input/Output):**  If the code performs logical operations, provide examples of input and the expected output.
4. **Common Usage Errors:** Identify potential mistakes developers or users might make when interacting with or using this code.
5. **User Steps to Reach Here (Debugging):**  Describe a sequence of user actions within a web browser that would lead to the execution of this code.
6. **Summary of Functionality (Part 3):**  Provide a concise overview of the code's role.

Let's break down the code snippet section by section and analyze each requirement.

**Code Section Analysis:**

* **`CreateNewSession` function:** This function seems responsible for creating a new QUIC session. It handles various configuration steps like setting connection ID, max packet length, initial RTT, and creating the `QuicChromiumClientSession` object.
* **`ActivateSession` function:** This function appears to manage active QUIC sessions, associating them with keys and IP addresses.
* **`MarkAllActiveSessionsGoingAway` function:**  This function deals with gracefully closing or marking active sessions for closure, potentially due to network changes.
* **`ConfigureInitialRttEstimate` function:** This function determines the initial Round-Trip Time (RTT) estimate for a new connection, considering cached values and network conditions.
* **Helper functions for RTT:** `GetServerNetworkStatsSmoothedRttInMicroseconds` and `GetServerNetworkStatsSmoothedRtt` retrieve cached RTT values.
* **`WasQuicRecentlyBroken` function:** Checks if QUIC connections to a specific server have recently failed.
* **`InitializeMigrationOptions` function:** Configures connection migration behaviors based on various flags and network status.
* **`InitializeCachedStateInCryptoConfig` function:** Loads and initializes cached cryptographic information for a server.
* **`ProcessGoingAwaySession` function:** Handles the cleanup and recording of statistics when a QUIC session is being closed.
* **`ActivateAndMapSessionToAliasKey` and `UnmapSessionFromSessionAliases` functions:** Manage the mapping between sessions and their alias keys.
* **`CreateCryptoConfigHandle` function:** Creates or retrieves a handle to the `QuicCryptoClientConfig`, responsible for cryptographic settings. This function also manages a cache of these configurations.
* **`OnAllCryptoClientRefReleased` function:** Handles the release of the last reference to a `QuicCryptoClientConfig`, potentially moving it to a less active cache.
* **`CollectDataOnPlatformNotification` function:** Records data related to network notifications.
* **`GetCryptoConfigForTesting` and `CryptoConfigCacheIsEmptyForTesting` functions:** Functions specifically for testing the cryptographic configuration management.

**Planning the Response:**

Now I have a good understanding of the code's purpose. I will structure my response as follows:

1. **Functionalities:**  List each function and its primary purpose in bullet points.
2. **JavaScript Relation:** Focus on how QUIC, and therefore this code, can affect JavaScript performance (faster loading) and security (encryption). Give a concrete example of a browser fetching a resource using QUIC.
3. **Logical Reasoning:** Choose a function with clear logic, like `ConfigureInitialRttEstimate`, and provide example inputs (server ID, network type, cached RTT) and the resulting output (configured RTT in the `QuicConfig`).
4. **Common Usage Errors:** Think about configuration mistakes (e.g., incorrect migration settings) or scenarios where assumptions about network behavior are wrong.
5. **User Steps:** Trace a typical browser interaction that would trigger QUIC usage: entering a URL for a website that supports QUIC.
6. **Summary:** Concisely describe the overall role of this code in managing QUIC client sessions.
这是 `net/quic/quic_session_pool.cc` 文件代码片段的第三部分，延续了前面两部分的内容，主要负责 QUIC 客户端会话的创建、激活、管理以及与加密配置相关的操作。

**功能归纳:**

这部分代码主要负责以下功能：

* **创建和初始化新的 QUIC 客户端会话:**
    * 为新的连接生成随机的连接 ID。
    * 从本地存储或 HTTP 服务器属性中获取服务器信息 (例如，服务器配置)。
    * 创建和初始化用于加密的客户端配置句柄 (`CryptoClientConfigHandle`)。
    * 创建 QUIC 连接对象 (`quic::QuicConnection`)，并配置其参数，如最大包长度。
    * 创建 `QuicChromiumClientSession` 对象，这是 Chromium 中 QUIC 客户端会话的具体实现，并将各种依赖项（例如，socket、加密配置、时钟、网络状态等）传递给它。
    * 设置连接的 keep-alive 超时。
    * 记录会话创建的 NetLog 事件。
    * 初始化新创建的会话。

* **激活和管理活跃的 QUIC 会话:**
    * 将新创建的会话添加到活跃会话的集合中 (`active_sessions_`)，并根据其密钥 (`QuicSessionAliasKey`) 进行索引。
    * 维护会话与 DNS 别名以及对端 IP 地址之间的映射关系，用于后续的会话查找和迁移。

* **处理会话的关闭和离开:**
    * 提供 `MarkAllActiveSessionsGoingAway` 函数，用于在特定情况下（例如，IP 地址变更）标记所有活跃会话即将关闭。
    * 在会话关闭时，调用 `ProcessGoingAwaySession` 来记录会话的统计信息，并更新 HTTP 服务器属性，例如标记 QUIC 是否可用，记录 RTT 和带宽估计等。

* **配置初始 RTT 估计:**
    * `ConfigureInitialRttEstimate` 函数根据缓存的服务器网络统计信息或网络连接类型（例如，2G、3G）来设置 QUIC 连接的初始 RTT 估计值，以优化连接的启动速度。

* **管理 QUIC 加密客户端配置:**
    * `CreateCryptoConfigHandle` 函数负责创建或获取用于 QUIC 加密的客户端配置句柄。它会检查是否有已存在的活跃或最近使用的配置，如果没有则创建一个新的配置。
    * 维护一个活跃的加密配置映射 (`active_crypto_config_map_`) 和一个最近使用的加密配置映射 (`recent_crypto_config_map_`)，以复用配置并减少创建开销。
    * `InitializeCachedStateInCryptoConfig` 函数使用从本地存储或 HTTP 服务器属性加载的服务器信息来初始化加密配置中的缓存状态，例如服务器配置、源地址令牌等。
    * `OnAllCryptoClientRefReleased` 函数在加密配置句柄不再被引用时，将其移动到最近使用的映射中。

* **处理网络变化和连接迁移:**
    * `InitializeMigrationOptions` 函数根据配置初始化连接迁移相关的选项，例如是否在网络变化时迁移会话，是否允许端口迁移等。
    * 监听网络变化通知 (`NetworkChangeNotifier`)，并在 IP 地址变化时采取相应的措施（例如，标记会话即将关闭）。

* **收集平台通知数据:**
    * `CollectDataOnPlatformNotification` 函数用于记录来自操作系统的网络平台通知，用于分析网络状况和 QUIC 的性能。

**与 JavaScript 功能的关系:**

QUIC 协议本身对提升 Web 应用程序的性能有重要作用，而这段代码作为 QUIC 客户端会话管理的核心部分，间接地与 JavaScript 功能相关。

**举例说明:**

当 JavaScript 发起一个网络请求（例如，使用 `fetch()` API）到支持 QUIC 的服务器时，Chromium 浏览器会尝试使用 QUIC 协议建立连接。 这段代码中的 `CreateNewSession` 函数会被调用来创建这个 QUIC 会话。  如果会话创建成功并激活，后续 JavaScript 发起的请求就可以通过这个更快速的 QUIC 连接进行传输，从而提升网页加载速度和用户体验。

**假设输入与输出 (逻辑推理):**

**假设输入 (以 `ConfigureInitialRttEstimate` 为例):**

* `server_id`:  `quic::QuicServerId("example.com", 443)`
* `network_anonymization_key`:  (假设为空，表示非匿名模式)
* `config` (初始状态): 一个空的 `quic::QuicConfig` 对象。
* HTTP 服务器属性中没有 `example.com:443` 的缓存 RTT。
* 当前网络连接类型为 `NetworkChangeNotifier::CONNECTION_3G`。
* `params_.initial_rtt_for_handshake` 为空 (未配置)。

**输出:**

`config` 对象的初始 RTT 估计值会被设置为 400 毫秒 (根据 3G 网络类型的默认值)。

**用户或编程常见的使用错误:**

* **配置连接迁移选项错误:**  例如，同时启用互相冲突的迁移选项，或者在不支持网络句柄的平台上启用依赖网络句柄的迁移功能。 这可能导致连接不稳定或者无法进行有效的迁移。
* **未正确处理会话关闭:**  如果上层代码没有正确处理 `QuicChromiumClientSession` 的关闭事件，可能会导致资源泄漏或连接状态不一致。
* **依赖过期的服务器信息:**  如果本地缓存的服务器信息（例如，服务器配置）过期或不正确，可能导致连接建立失败或出现安全问题。
* **在测试或开发环境中使用了不正确的加密配置:**  例如，使用了生产环境的证书验证逻辑，导致连接到本地测试服务器失败。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在 Chrome 浏览器地址栏中输入一个 HTTPS 网址，例如 `https://www.example.com`，该网站支持 QUIC 协议。**
2. **浏览器的网络栈首先会进行 DNS 查询，解析 `www.example.com` 的 IP 地址。**
3. **如果之前没有与该服务器建立过 QUIC 连接，或者之前的连接已失效，`QuicSessionPool` 会尝试创建一个新的 QUIC 会话。**
4. **`QuicSessionPool::FindSession` 等函数会尝试查找可复用的现有会话。 如果没有找到，则会调用 `QuicSessionPool::CreateNewSession` (代码片段所示部分)。**
5. **在 `CreateNewSession` 中，会执行以下步骤:**
    * 生成连接 ID。
    * 查找或创建 `PropertiesBasedQuicServerInfo`。
    * 创建 `CryptoClientConfigHandle`。
    * 创建底层的 `quic::QuicConnection` 对象。
    * 创建 `QuicChromiumClientSession` 对象，并将 `QuicSessionPool` 作为其一部分传递进去。
    * 调用 `session->Initialize()` 启动握手过程。
6. **如果会话创建成功，`ActivateSession` 会被调用，将新的会话添加到活跃会话池中。**

在调试网络问题时，可以通过 Chrome 的 `chrome://net-internals/#quic` 页面查看当前的 QUIC 会话状态，以及相关的事件日志，以追踪会话的创建、迁移和关闭过程。  还可以通过抓包工具 (如 Wireshark) 观察 QUIC 握手和数据传输过程。  NetLog (可以在 `chrome://net-internals/#netlog` 中启用和查看) 提供了更详细的 Chromium 网络栈内部事件记录，可以帮助定位问题。

### 提示词
```
这是目录为net/quic/quic_session_pool.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
uic::QuicUtils::CreateRandomConnectionId(random_generator_);
  std::unique_ptr<QuicServerInfo> server_info;
  if (params_.max_server_configs_stored_in_properties > 0) {
    server_info = std::make_unique<PropertiesBasedQuicServerInfo>(
        server_id, key.session_key().privacy_mode(),
        key.session_key().network_anonymization_key(), http_server_properties_);
  }
  std::unique_ptr<CryptoClientConfigHandle> crypto_config_handle =
      CreateCryptoConfigHandle(key.session_key().network_anonymization_key());
  InitializeCachedStateInCryptoConfig(*crypto_config_handle, server_id,
                                      server_info);

  QuicChromiumPacketWriter* writer =
      new QuicChromiumPacketWriter(socket.get(), task_runner_.get());
  quic::QuicConnection* connection = new quic::QuicConnection(
      connection_id, quic::QuicSocketAddress(),
      ToQuicSocketAddress(peer_address), helper_.get(), alarm_factory_.get(),
      writer, true /* owns_writer */, quic::Perspective::IS_CLIENT,
      {quic_version}, connection_id_generator_);
  connection->set_keep_alive_ping_timeout(ping_timeout_);

  // Calculate the max packet length for this connection. If the session is
  // carrying proxy traffic, add the `additional_proxy_packet_length`.
  size_t max_packet_length = params_.max_packet_length;
  if (key.session_key().session_usage() == SessionUsage::kProxy) {
    max_packet_length += params_.additional_proxy_packet_length;
  }
  // Restrict that length by the session maximum, if given.
  if (session_max_packet_length > 0) {
    max_packet_length = std::min(static_cast<size_t>(session_max_packet_length),
                                 max_packet_length);
  }
  DVLOG(1) << "Session to " << key.destination().Serialize()
           << " has max packet length " << max_packet_length;
  connection->SetMaxPacketLength(max_packet_length);

  quic::QuicConfig config = config_;
  ConfigureInitialRttEstimate(
      server_id, key.session_key().network_anonymization_key(), &config);

  // Use the factory to create a new socket performance watcher, and pass the
  // ownership to QuicChromiumClientSession.
  std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher;
  if (socket_performance_watcher_factory_) {
    socket_performance_watcher =
        socket_performance_watcher_factory_->CreateSocketPerformanceWatcher(
            SocketPerformanceWatcherFactory::PROTOCOL_QUIC,
            peer_address.address());
  }

  // Wait for handshake confirmation before allowing streams to be created if
  // either this session or the pool require confirmation.
  if (!has_quic_ever_worked_on_current_network_) {
    require_confirmation = true;
  }

  auto new_session = std::make_unique<QuicChromiumClientSession>(
      connection, std::move(socket), this, quic_crypto_client_stream_factory_,
      clock_, transport_security_state_, ssl_config_service_,
      std::move(server_info), std::move(key), require_confirmation,
      params_.migrate_sessions_early_v2,
      params_.migrate_sessions_on_network_change_v2, default_network_,
      retransmittable_on_wire_timeout_, params_.migrate_idle_sessions,
      params_.allow_port_migration, params_.idle_session_migration_period,
      params_.multi_port_probing_interval,
      params_.max_time_on_non_default_network,
      params_.max_migrations_to_non_default_network_on_write_error,
      params_.max_migrations_to_non_default_network_on_path_degrading,
      yield_after_packets_, yield_after_duration_, cert_verify_flags, config,
      std::move(crypto_config_handle),
      network_connection_.connection_description(), dns_resolution_start_time,
      dns_resolution_end_time, tick_clock_, task_runner_.get(),
      std::move(socket_performance_watcher), metadata, params_.report_ecn,
      params_.enable_origin_frame, params_.allow_server_migration,
      session_creation_initiator, net_log);
  QuicChromiumClientSession* session = new_session.get();

  all_sessions_.insert(std::move(new_session));
  writer->set_delegate(session);
  session->AddConnectivityObserver(&connectivity_monitor_);

  net_log.AddEventReferencingSource(
      NetLogEventType::QUIC_SESSION_POOL_JOB_RESULT,
      session->net_log().source());

  session->Initialize();
  bool closed_during_initialize = !base::Contains(all_sessions_, session) ||
                                  !session->connection()->connected();
  UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.ClosedDuringInitializeSession",
                        closed_during_initialize);
  if (closed_during_initialize) {
    DLOG(DFATAL) << "Session closed during initialize";
    return base::unexpected(ERR_CONNECTION_CLOSED);
  }
  return QuicSessionAttempt::CreateSessionResult{session, network};
}

void QuicSessionPool::ActivateSession(const QuicSessionAliasKey& key,
                                      QuicChromiumClientSession* session,
                                      std::set<std::string> dns_aliases) {
  DCHECK(!HasActiveSession(key.session_key()));
  UMA_HISTOGRAM_COUNTS_1M("Net.QuicActiveSessions", active_sessions_.size());
  ActivateAndMapSessionToAliasKey(session, key, std::move(dns_aliases));
  const IPEndPoint peer_address =
      ToIPEndPoint(session->connection()->peer_address());
  DCHECK(!base::Contains(ip_aliases_[peer_address], session));
  ip_aliases_[peer_address].insert(session);
  DCHECK(!base::Contains(session_peer_ip_, session));
  session_peer_ip_[session] = peer_address;
}

void QuicSessionPool::MarkAllActiveSessionsGoingAway(
    AllActiveSessionsGoingAwayReason reason) {
  net_log_.AddEvent(
      NetLogEventType::QUIC_SESSION_POOL_MARK_ALL_ACTIVE_SESSIONS_GOING_AWAY);
  base::UmaHistogramCounts10000(
      std::string("Net.QuicActiveSessionCount.") +
          AllActiveSessionsGoingAwayReasonToString(reason),
      active_sessions_.size());
  while (!active_sessions_.empty()) {
    QuicChromiumClientSession* session = active_sessions_.begin()->second;
    // If IP address change is detected, disable session's connectivity
    // monitoring by remove the Delegate.
    if (reason == kIPAddressChanged) {
      connectivity_monitor_.OnSessionGoingAwayOnIPAddressChange(session);
    }
    OnSessionGoingAway(session);
  }
}

void QuicSessionPool::ConfigureInitialRttEstimate(
    const quic::QuicServerId& server_id,
    const NetworkAnonymizationKey& network_anonymization_key,
    quic::QuicConfig* config) {
  const base::TimeDelta* srtt =
      GetServerNetworkStatsSmoothedRtt(server_id, network_anonymization_key);
  // Sometimes *srtt is negative. See https://crbug.com/1225616.
  // TODO(ricea): When the root cause of the negative value is fixed, change the
  // non-negative assertion to a DCHECK.
  if (srtt && srtt->is_positive()) {
    SetInitialRttEstimate(*srtt, INITIAL_RTT_CACHED, config);
    return;
  }

  NetworkChangeNotifier::ConnectionType type =
      network_connection_.connection_type();
  if (type == NetworkChangeNotifier::CONNECTION_2G) {
    SetInitialRttEstimate(base::Milliseconds(1200), INITIAL_RTT_CACHED, config);
    return;
  }

  if (type == NetworkChangeNotifier::CONNECTION_3G) {
    SetInitialRttEstimate(base::Milliseconds(400), INITIAL_RTT_CACHED, config);
    return;
  }

  if (params_.initial_rtt_for_handshake.is_positive()) {
    SetInitialRttEstimate(
        base::Microseconds(params_.initial_rtt_for_handshake.InMicroseconds()),
        INITIAL_RTT_DEFAULT, config);
    return;
  }

  SetInitialRttEstimate(base::TimeDelta(), INITIAL_RTT_DEFAULT, config);
}

int64_t QuicSessionPool::GetServerNetworkStatsSmoothedRttInMicroseconds(
    const quic::QuicServerId& server_id,
    const NetworkAnonymizationKey& network_anonymization_key) const {
  const base::TimeDelta* srtt =
      GetServerNetworkStatsSmoothedRtt(server_id, network_anonymization_key);
  return srtt == nullptr ? 0 : srtt->InMicroseconds();
}

const base::TimeDelta* QuicSessionPool::GetServerNetworkStatsSmoothedRtt(
    const quic::QuicServerId& server_id,
    const NetworkAnonymizationKey& network_anonymization_key) const {
  url::SchemeHostPort server("https", server_id.host(), server_id.port());
  const ServerNetworkStats* stats =
      http_server_properties_->GetServerNetworkStats(server,
                                                     network_anonymization_key);
  if (stats == nullptr) {
    return nullptr;
  }
  return &(stats->srtt);
}

bool QuicSessionPool::WasQuicRecentlyBroken(
    const QuicSessionKey& session_key) const {
  const AlternativeService alternative_service(
      kProtoQUIC, HostPortPair(session_key.server_id().host(),
                               session_key.server_id().port()));
  return http_server_properties_->WasAlternativeServiceRecentlyBroken(
      alternative_service, session_key.network_anonymization_key());
}

void QuicSessionPool::InitializeMigrationOptions() {
  // The following list of options cannot be set immediately until
  // prerequisites are met. Cache the initial setting in local variables and
  // reset them in |params_|.
  bool migrate_sessions_on_network_change =
      params_.migrate_sessions_on_network_change_v2;
  bool migrate_sessions_early = params_.migrate_sessions_early_v2;
  bool retry_on_alternate_network_before_handshake =
      params_.retry_on_alternate_network_before_handshake;
  bool migrate_idle_sessions = params_.migrate_idle_sessions;
  bool allow_port_migration = params_.allow_port_migration;
  params_.migrate_sessions_on_network_change_v2 = false;
  params_.migrate_sessions_early_v2 = false;
  params_.allow_port_migration = false;
  params_.retry_on_alternate_network_before_handshake = false;
  params_.migrate_idle_sessions = false;

  // TODO(zhongyi): deprecate |goaway_sessions_on_ip_change| if the experiment
  // is no longer needed.
  // goaway_sessions_on_ip_change and close_sessions_on_ip_change should never
  // be simultaneously set to true.
  DCHECK(!(params_.close_sessions_on_ip_change &&
           params_.goaway_sessions_on_ip_change));

  bool handle_ip_change = params_.close_sessions_on_ip_change ||
                          params_.goaway_sessions_on_ip_change;
  // If IP address changes are handled explicitly, connection migration should
  // not be set.
  DCHECK(!(handle_ip_change && migrate_sessions_on_network_change));

  if (handle_ip_change) {
    NetworkChangeNotifier::AddIPAddressObserver(this);
  }

  if (allow_port_migration) {
    params_.allow_port_migration = true;
    if (migrate_idle_sessions) {
      params_.migrate_idle_sessions = true;
    }
  }

  if (!NetworkChangeNotifier::AreNetworkHandlesSupported()) {
    return;
  }

  NetworkChangeNotifier::AddNetworkObserver(this);
  // Perform checks on the connection migration options.
  if (!migrate_sessions_on_network_change) {
    DCHECK(!migrate_sessions_early);
    return;
  }

  // Enable migration on platform notifications.
  params_.migrate_sessions_on_network_change_v2 = true;

  if (!migrate_sessions_early) {
    DCHECK(!retry_on_alternate_network_before_handshake);
    return;
  }

  // Enable migration on path degrading.
  params_.migrate_sessions_early_v2 = true;
  // Set retransmittable on wire timeout for migration on path degrading if no
  // value is specified.
  if (retransmittable_on_wire_timeout_.IsZero()) {
    retransmittable_on_wire_timeout_ = quic::QuicTime::Delta::FromMicroseconds(
        kDefaultRetransmittableOnWireTimeout.InMicroseconds());
  }

  // Enable retry on alternate network before handshake.
  if (retry_on_alternate_network_before_handshake) {
    params_.retry_on_alternate_network_before_handshake = true;
  }

  // Enable migration for idle sessions.
  if (migrate_idle_sessions) {
    params_.migrate_idle_sessions = true;
  }
}

void QuicSessionPool::InitializeCachedStateInCryptoConfig(
    const CryptoClientConfigHandle& crypto_config_handle,
    const quic::QuicServerId& server_id,
    const std::unique_ptr<QuicServerInfo>& server_info) {
  quic::QuicCryptoClientConfig::CachedState* cached =
      crypto_config_handle.GetConfig()->LookupOrCreate(server_id);

  if (!cached->IsEmpty()) {
    return;
  }

  if (!server_info || !server_info->Load()) {
    return;
  }

  cached->Initialize(server_info->state().server_config,
                     server_info->state().source_address_token,
                     server_info->state().certs, server_info->state().cert_sct,
                     server_info->state().chlo_hash,
                     server_info->state().server_config_sig, clock_->WallNow(),
                     quic::QuicWallTime::Zero());
}

void QuicSessionPool::ProcessGoingAwaySession(
    QuicChromiumClientSession* session,
    const quic::QuicServerId& server_id,
    bool session_was_active) {
  if (!http_server_properties_) {
    return;
  }

  const quic::QuicConnectionStats& stats = session->connection()->GetStats();
  const AlternativeService alternative_service(
      kProtoQUIC, HostPortPair(server_id.host(), server_id.port()));

  url::SchemeHostPort server("https", server_id.host(), server_id.port());
  // Do nothing if QUIC is currently marked as broken.
  if (http_server_properties_->IsAlternativeServiceBroken(
          alternative_service,
          session->quic_session_key().network_anonymization_key())) {
    return;
  }

  if (session->OneRttKeysAvailable()) {
    http_server_properties_->ConfirmAlternativeService(
        alternative_service,
        session->quic_session_key().network_anonymization_key());
    ServerNetworkStats network_stats;
    network_stats.srtt = base::Microseconds(stats.srtt_us);
    network_stats.bandwidth_estimate = stats.estimated_bandwidth;
    http_server_properties_->SetServerNetworkStats(
        server, session->quic_session_key().network_anonymization_key(),
        network_stats);
    return;
  }

  http_server_properties_->ClearServerNetworkStats(
      server, session->quic_session_key().network_anonymization_key());

  UMA_HISTOGRAM_COUNTS_1M("Net.QuicHandshakeNotConfirmedNumPacketsReceived",
                          stats.packets_received);

  if (!session_was_active) {
    return;
  }

  // TODO(rch):  In the special case where the session has received no packets
  // from the peer, we should consider blocking this differently so that we
  // still race TCP but we don't consider the session connected until the
  // handshake has been confirmed.
  HistogramBrokenAlternateProtocolLocation(
      BROKEN_ALTERNATE_PROTOCOL_LOCATION_QUIC_SESSION_POOL);

  // Since the session was active, there's no longer an HttpStreamFactory::Job
  // running which can mark it broken, unless the TCP job also fails. So to
  // avoid not using QUIC when we otherwise could, we mark it as recently
  // broken, which means that 0-RTT will be disabled but we'll still race.
  http_server_properties_->MarkAlternativeServiceRecentlyBroken(
      alternative_service,
      session->quic_session_key().network_anonymization_key());
}

void QuicSessionPool::ActivateAndMapSessionToAliasKey(
    QuicChromiumClientSession* session,
    QuicSessionAliasKey key,
    std::set<std::string> dns_aliases) {
  active_sessions_[key.session_key()] = session;
  dns_aliases_by_session_key_[key.session_key()] = std::move(dns_aliases);
  session_aliases_[session].insert(std::move(key));
}

void QuicSessionPool::UnmapSessionFromSessionAliases(
    QuicChromiumClientSession* session) {
  for (const auto& key : session_aliases_[session]) {
    dns_aliases_by_session_key_.erase(key.session_key());
  }
  session_aliases_.erase(session);
}

std::unique_ptr<QuicSessionPool::CryptoClientConfigHandle>
QuicSessionPool::CreateCryptoConfigHandle(
    const NetworkAnonymizationKey& network_anonymization_key) {
  NetworkAnonymizationKey actual_network_anonymization_key =
      use_network_anonymization_key_for_crypto_configs_
          ? network_anonymization_key
          : NetworkAnonymizationKey();

  // If there's a matching entry in |active_crypto_config_map_|, create a
  // CryptoClientConfigHandle for it.
  auto map_iterator =
      active_crypto_config_map_.find(actual_network_anonymization_key);
  if (map_iterator != active_crypto_config_map_.end()) {
    DCHECK_GT(map_iterator->second->num_refs(), 0);

    // If there's an active matching crypto config, there shouldn't also be an
    // inactive matching crypto config.
    DCHECK(recent_crypto_config_map_.Peek(actual_network_anonymization_key) ==
           recent_crypto_config_map_.end());

    return std::make_unique<CryptoClientConfigHandle>(map_iterator);
  }

  // If there's a matching entry in |recent_crypto_config_map_|, move it to
  // |active_crypto_config_map_| and create a CryptoClientConfigHandle for it.
  auto mru_iterator =
      recent_crypto_config_map_.Peek(actual_network_anonymization_key);
  if (mru_iterator != recent_crypto_config_map_.end()) {
    DCHECK_EQ(mru_iterator->second->num_refs(), 0);

    map_iterator = active_crypto_config_map_
                       .emplace(actual_network_anonymization_key,
                                std::move(mru_iterator->second))
                       .first;
    recent_crypto_config_map_.Erase(mru_iterator);
    return std::make_unique<CryptoClientConfigHandle>(map_iterator);
  }

  // Otherwise, create a new QuicCryptoClientConfigOwner and add it to
  // |active_crypto_config_map_|.
  std::unique_ptr<QuicCryptoClientConfigOwner> crypto_config_owner =
      std::make_unique<QuicCryptoClientConfigOwner>(
          std::make_unique<ProofVerifierChromium>(
              cert_verifier_, transport_security_state_, sct_auditing_delegate_,
              HostsFromOrigins(params_.origins_to_force_quic_on),
              actual_network_anonymization_key),
          std::make_unique<quic::QuicClientSessionCache>(), this);

  quic::QuicCryptoClientConfig* crypto_config = crypto_config_owner->config();
  crypto_config->AddCanonicalSuffix(".c.youtube.com");
  crypto_config->AddCanonicalSuffix(".ggpht.com");
  crypto_config->AddCanonicalSuffix(".googlevideo.com");
  crypto_config->AddCanonicalSuffix(".googleusercontent.com");
  crypto_config->AddCanonicalSuffix(".gvt1.com");
  crypto_config->set_alps_use_new_codepoint(params_.use_new_alps_codepoint);

  ConfigureQuicCryptoClientConfig(*crypto_config);

  if (!prefer_aes_gcm_recorded_) {
    bool prefer_aes_gcm =
        !crypto_config->aead.empty() && (crypto_config->aead[0] == quic::kAESG);
    UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.PreferAesGcm", prefer_aes_gcm);
    prefer_aes_gcm_recorded_ = true;
  }

  map_iterator = active_crypto_config_map_
                     .emplace(actual_network_anonymization_key,
                              std::move(crypto_config_owner))
                     .first;
  return std::make_unique<CryptoClientConfigHandle>(map_iterator);
}

void QuicSessionPool::OnAllCryptoClientRefReleased(
    QuicCryptoClientConfigMap::iterator& map_iterator) {
  DCHECK_EQ(0, map_iterator->second->num_refs());
  recent_crypto_config_map_.Put(map_iterator->first,
                                std::move(map_iterator->second));
  active_crypto_config_map_.erase(map_iterator);
}

void QuicSessionPool::CollectDataOnPlatformNotification(
    enum QuicPlatformNotification notification,
    handles::NetworkHandle affected_network) const {
  UMA_HISTOGRAM_ENUMERATION("Net.QuicSession.PlatformNotification",
                            notification, NETWORK_NOTIFICATION_MAX);
  connectivity_monitor_.RecordConnectivityStatsToHistograms(
      QuicPlatformNotificationToString(notification), affected_network);
}

std::unique_ptr<QuicCryptoClientConfigHandle>
QuicSessionPool::GetCryptoConfigForTesting(
    const NetworkAnonymizationKey& network_anonymization_key) {
  return CreateCryptoConfigHandle(network_anonymization_key);
}

bool QuicSessionPool::CryptoConfigCacheIsEmptyForTesting(
    const quic::QuicServerId& server_id,
    const NetworkAnonymizationKey& network_anonymization_key) {
  quic::QuicCryptoClientConfig::CachedState* cached = nullptr;
  NetworkAnonymizationKey actual_network_anonymization_key =
      use_network_anonymization_key_for_crypto_configs_
          ? network_anonymization_key
          : NetworkAnonymizationKey();
  auto map_iterator =
      active_crypto_config_map_.find(actual_network_anonymization_key);
  if (map_iterator != active_crypto_config_map_.end()) {
    cached = map_iterator->second->config()->LookupOrCreate(server_id);
  } else {
    auto mru_iterator =
        recent_crypto_config_map_.Peek(actual_network_anonymization_key);
    if (mru_iterator != recent_crypto_config_map_.end()) {
      cached = mru_iterator->second->config()->LookupOrCreate(server_id);
    }
  }
  return !cached || cached->IsEmpty();
}

}  // namespace net
```