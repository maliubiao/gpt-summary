Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the Chromium network stack and located in `net/quic/quic_session_pool.cc`.

Here's a breakdown of the code's functions:

1. **Asynchronous Socket Connection and Configuration:**  The `ConnectAndConfigureSocket` function initiates an asynchronous connection and then calls `FinishConnectAndConfigureSocket` to apply various socket settings.

2. **Synchronous Socket Configuration:** The `ConfigureSocket` function performs a synchronous connection and then configures the socket.

3. **Socket Configuration Settings:** Both asynchronous and synchronous paths apply settings like non-blocking I/O, receive buffer size, disabling fragmentation, enabling ECN reporting (if configured), and setting a large send buffer. It also sets the iOS network service type if provided.

4. **Callback Handling:**  `FinishConnectAndConfigureSocket` handles the result of the connection attempt and applies configurations. It uses callbacks (`CompletionOnceCallback`) to signal completion or errors. `DoCallback` simply executes the provided callback.

5. **Error Handling:** `OnFinishConnectAndConfigureSocketError` is called when a socket configuration step fails, logging the error and invoking the callback with an error code.

6. **IP Matching Waiving:** `CanWaiveIpMatching` determines if IP address matching can be ignored when searching for existing sessions. This can be based on alias keys, received connection options, or received origins.

7. **Network Handling:**  Functions like `FindAlternateNetwork`, `OnIPAddressChanged`, `OnNetworkConnected`, `OnNetworkDisconnected`, `OnNetworkSoonToDisconnect`, and `OnNetworkMadeDefault` manage network state changes and their impact on QUIC sessions.

8. **Socket Creation:** `CreateSocket` creates a `DatagramClientSocket` with optional receive optimization.

9. **Trust Store and Cert Verifier Changes:**  `OnTrustStoreChanged` and `OnCertVerifierChanged` handle changes in certificate trust and verification settings, potentially invalidating existing sessions.

10. **QUIC Availability Tracking:** Functions and members related to `has_quic_ever_worked_on_current_network_` track if QUIC has previously succeeded on the current network.

11. **Job Waiting Delay:** `GetTimeDelayForWaitingJob` calculates a delay before starting a new QUIC job, potentially influenced by past QUIC success or failure.

12. **DNS Alias Management:** `GetDnsAliasesForSessionKey` retrieves DNS aliases associated with a session key.

13. **Session Activation and Deactivation (Testing):** `ActivateSessionForTesting` and `DeactivateSessionForTesting` are utility functions for testing session management.

14. **Version Negotiation:** `SelectQuicVersion` selects an appropriate QUIC version based on supported ALPNs.

15. **Connection IP Pooling:** `LogConnectionIpPooling` logs whether a connection was pooled. `HasMatchingIpSession` checks for existing sessions with matching IPs.

16. **Job Completion:** `OnJobComplete` is called when a QUIC job finishes, handling success and failure cases and notifying associated requests.

17. **Session and Job Existence Checks:** `HasActiveSession` and `HasActiveJob` check if a session or job with a given key exists.

18. **Session Creation (Synchronous and Asynchronous):** `CreateSessionSync` and `CreateSessionAsync` create new QUIC sessions, with synchronous and asynchronous connection setup.

19. **Session Creation via Proxy Stream:** `CreateSessionOnProxyStream` creates a QUIC session over an existing proxy stream (like MASQUE).

20. **Session Creation Helper:** `CreateSessionHelper` encapsulates the core logic for creating a QUIC session.

**Relating to JavaScript:**

While this C++ code doesn't directly execute JavaScript, it's crucial for the functionality of web browsers and thus indirectly related to JavaScript execution:

* **Network Requests:** JavaScript code in a web page uses browser APIs (like `fetch` or `XMLHttpRequest`) to make network requests. If the browser decides to use QUIC for a request, this C++ code is responsible for establishing and managing the QUIC connection. The outcome of these C++ functions (success or failure of connection, socket configuration) directly affects whether the JavaScript network request succeeds or fails.
* **Performance:** The efficiency of the QUIC connection setup and management, handled by this code, impacts the loading speed of web pages and the responsiveness of web applications, which are directly perceived by JavaScript.
* **Network Protocol Support:** Features like connection migration, handled in this code, can improve the reliability of network requests initiated by JavaScript, especially on mobile devices with changing network conditions.

**Hypothetical Input and Output (Focusing on `ConnectAndConfigureSocket`):**

**Input:**

* `addr`: An `IPEndPoint` representing the server's IP address and port (e.g., 203.0.113.42:443).
* `network`: A `handles::NetworkHandle` representing the network interface to use (e.g., a valid network handle obtained from the operating system).
* `socket_tag`: A `SocketTag` for identifying the socket.
* `callback`: A `CompletionOnceCallback` to be invoked when the connection is complete.

**Assumptions:**
* The `DatagramClientSocket* socket` is already created.
* `params_.migrate_sessions_on_network_change_v2` is true.
* `handles::kInvalidNetworkHandle` is passed as the `network`.

**Logical Reasoning:**

1. Since `params_.migrate_sessions_on_network_change_v2` is true and the provided `network` is `handles::kInvalidNetworkHandle`, the code will call `socket->ConnectUsingDefaultNetworkAsync(addr, std::move(connect_callback))`. This attempts to connect to the specified address using the system's current default network interface.

**Output:**

* If the connection is initiated successfully, the function returns `ERR_IO_PENDING` because the connection is asynchronous. The `connect_callback` will be executed later when the connection succeeds or fails.
* The `connect_callback` (bound to `FinishConnectAndConfigureSocket`) will be invoked with the result of the connection attempt (`rv`). If `rv` is `OK`, the socket will be further configured. If `rv` is an error, the `split_callback.second` will be executed with the error.

**Common User/Programming Errors:**

* **Incorrect Network Handle:** If a user-level application somehow provides an invalid or incorrect `handles::NetworkHandle` when trying to establish a QUIC connection (though this is less likely in typical browser usage, more relevant in custom network applications), the connection attempt might fail. The code attempts to handle the unspecified network case by using the default network.
* **Firewall Issues:** A firewall blocking UDP traffic on the specified port would lead to connection errors. The `FinishConnectAndConfigureSocket` function would receive a non-OK `rv` and call `OnFinishConnectAndConfigureSocketError`.
* **Server Not Listening:** If the server at the specified `IPEndPoint` is not listening for QUIC connections, the connection attempt will fail. This would result in an error code being passed to the completion callback.
* **Resource Exhaustion:**  While less common, if the system is under heavy load and cannot allocate resources for a new socket, the `socket->ConnectAsync` call could fail.

**User Operation and Debugging:**

Let's consider a scenario where a user is trying to access a website that supports QUIC:

1. **User Enters URL:** The user types a URL (e.g., `https://www.example.com`) into the browser's address bar or clicks a link.
2. **DNS Resolution:** The browser performs a DNS lookup to find the IP address of `www.example.com`.
3. **QUIC Session Pool Interaction:** The network stack checks the `QuicSessionPool` to see if there's an existing active QUIC session to `www.example.com`.
4. **New Session Request:** If no existing session is found, the browser might decide to create a new QUIC session. This involves calling methods within `QuicSessionPool`.
5. **Socket Creation:**  `CreateSocket` is called to create a `DatagramClientSocket`.
6. **Connection Attempt:**  `ConnectAndConfigureSocket` is called to initiate the connection to the server's IP address (obtained from DNS). The specific branch taken within this function depends on the network migration settings and the provided network handle.
7. **Socket Configuration:** `FinishConnectAndConfigureSocket` is executed (asynchronously) after the connection attempt completes, configuring socket options like buffer sizes and disabling fragmentation.
8. **Session Creation (Continued):**  If the socket connection and configuration are successful, the `CreateSessionHelper` function is eventually called to create the actual QUIC session object.
9. **Data Transfer:** Once the QUIC session is established, the browser can start sending HTTP/3 requests over this connection to fetch the website's content.

**Debugging Line:** If a developer suspects issues with QUIC connection establishment, they might set a breakpoint in `ConnectAndConfigureSocket` or `FinishConnectAndConfigureSocket` to inspect:

* The target IP address and port (`addr`).
* The network handle being used (`network`).
* The result of the `socket->ConnectAsync` call (`rv`).
* The socket options being set.
* Any errors encountered during socket configuration.

**Summary of Functionality (Part 2):**

This part of the `QuicSessionPool` code focuses on the **establishment and configuration of the underlying UDP sockets used for QUIC connections**. It handles both synchronous and asynchronous connection attempts, sets necessary socket options for QUIC, and manages callbacks to signal the completion or failure of these operations. It also incorporates logic for handling network changes, particularly when migrating connections between networks is enabled. Error handling during the socket setup process is also a key function.
这是`net/quic/quic_session_pool.cc`文件的第二部分，主要功能是 **负责 QUIC 会话建立过程中底层 UDP socket 的连接和配置**。它涵盖了同步和异步两种连接方式，并对 socket 进行了必要的配置以适应 QUIC 协议的需求。

以下是这一部分功能的归纳：

1. **异步 Socket 连接和配置 (`ConnectAndConfigureSocket`, `FinishConnectAndConfigureSocket`):**
   - `ConnectAndConfigureSocket` 负责发起异步的 socket 连接。它会根据配置项 `migrate_sessions_on_network_change_v2` 和提供的网络句柄来选择合适的连接方法 (普通连接、使用默认网络连接或使用指定网络连接)。
   - 无论连接是否立即完成，`ConnectAndConfigureSocket` 都会返回 `ERR_IO_PENDING`，因为后续的配置是异步进行的。
   - `FinishConnectAndConfigureSocket` 是连接完成后的回调函数，负责进行 socket 的配置，例如设置接收和发送缓冲区大小、禁用分片 (Do Not Fragment)、设置接收 TOS (用于 ECN) 等。
   - 如果配置过程中发生错误，会调用 `OnFinishConnectAndConfigureSocketError` 来处理。

2. **同步 Socket 连接和配置 (`ConfigureSocket`):**
   - `ConfigureSocket` 负责执行同步的 socket 连接，并进行与 `FinishConnectAndConfigureSocket` 类似的配置操作。
   - 如果连接或配置过程中发生错误，会记录相应的错误类型。

3. **Socket 配置项:** 无论是异步还是同步连接，都会对 socket 进行以下配置：
   - 设置为非阻塞 I/O (`UseNonBlockingIO()`).
   - 应用 SocketTag (`ApplySocketTag()`).
   - 设置接收缓冲区大小 (`SetReceiveBufferSize()`).
   - 设置 "不分片" 标志 (`SetDoNotFragment()`).
   - 如果启用了 ECN 报告，则设置接收 TOS (`SetRecvTos()`).
   - 设置发送缓冲区大小 (`SetSendBufferSize()`).
   - 如果配置了 iOS 网络服务类型，则进行设置 (`SetIOSNetworkServiceType()`).

4. **连接错误处理 (`OnFinishConnectAndConfigureSocketError`):**
   - 当 socket 连接或配置过程中发生错误时，会调用此函数。
   - 它会记录错误类型，并通过回调函数将错误传递出去。

5. **回调执行 (`DoCallback`):**
   - 一个简单的辅助函数，用于执行连接或配置完成后的回调。

6. **IP 匹配豁免 (`CanWaiveIpMatching`):**
   - 判断在查找现有会话时是否可以忽略 IP 地址匹配。这通常发生在以下情况：
     - 目标地址与现有会话的别名键匹配。
     - 启用了忽略 IP 匹配的配置，并且现有会话收到了包含 `kNOIP` 标记的连接选项。
     - 启用了跳过 DNS 并使用 Origin 帧的功能，并且现有会话收到了目标地址的 Origin 帧。

7. **查找备用网络 (`FindAlternateNetwork`):**
   - 查找可以迁移旧网络会话的新网络。

8. **创建 Socket (`CreateSocket`):**
   - 使用 `client_socket_factory_` 创建一个新的 `DatagramClientSocket` 实例。
   - 如果配置允许，会启用 socket 的接收优化 (`EnableRecvOptimization()`).

9. **网络状态变更处理 (`OnIPAddressChanged`, `OnNetworkConnected`, `OnNetworkDisconnected`, `OnNetworkSoonToDisconnect`, `OnNetworkMadeDefault`):**
   - 这些函数响应系统网络状态的变化，并通知相关的 QUIC 会话。
   - 当 IP 地址变更时，可以根据配置选择关闭或标记所有活跃会话为即将结束。
   - 当网络连接或断开时，会遍历所有活跃的 QUIC 会话并通知它们。
   - `OnNetworkMadeDefault` 在默认网络发生变化时被调用，并通知所有会话。

10. **信任存储和证书校验器变更处理 (`OnTrustStoreChanged`, `OnCertVerifierChanged`):**
    - 当系统信任存储或证书校验器配置发生变化时，会标记所有活跃会话为即将结束，以确保安全性。

11. **跟踪 QUIC 是否在当前网络工作过 (`set_has_quic_ever_worked_on_current_network`):**
    - 用于记录 QUIC 是否在当前网络上成功工作过，并更新持久化存储中的相关信息。

12. **获取等待任务的时间延迟 (`GetTimeDelayForWaitingJob`):**
    - 计算在开始新的 QUIC 任务之前需要等待的时间延迟。这个延迟可能会受到 QUIC 在当前网络上的历史成功或失败记录的影响。

13. **获取 SessionKey 的 DNS 别名 (`GetDnsAliasesForSessionKey`):**
    - 返回与指定 `QuicSessionKey` 关联的 DNS 别名集合。

14. **激活和取消激活测试会话 (`ActivateSessionForTesting`, `DeactivateSessionForTesting`):**
    - 提供用于测试的接口，可以手动激活或取消激活一个 QUIC 会话。

15. **设置测试等待任务的时间延迟 (`SetTimeDelayForWaitingJobForTesting`):**
    - 允许在测试中设置等待任务的时间延迟。

16. **选择 QUIC 版本 (`SelectQuicVersion`):**
    - 根据已知的 QUIC 版本和服务器提供的 ALPN 信息来选择合适的 QUIC 版本。

17. **记录连接 IP 池化状态 (`LogConnectionIpPooling`):**
    - 使用 UMA 记录连接是否使用了 IP 池化。

18. **检查是否存在匹配 IP 的会话 (`HasMatchingIpSession`):**
    - 检查是否存在可以进行 IP 池化的现有会话。

19. **任务完成处理 (`OnJobComplete`):**
    - 当一个 QUIC 会话建立的任务完成时调用。它会处理成功和失败的情况，并将会话句柄或错误通知给等待该任务的请求。

20. **检查是否存在活跃的会话或任务 (`HasActiveSession`, `HasActiveJob`):**
    - 用于检查是否存在具有给定 `QuicSessionKey` 的活跃 QUIC 会话或任务。

21. **同步和异步创建会话 (`CreateSessionSync`, `CreateSessionAsync`):**
    - `CreateSessionSync` 同步地创建 QUIC 会话。
    - `CreateSessionAsync` 异步地创建 QUIC 会话，并使用回调函数通知结果.

22. **通过代理流创建会话 (`CreateSessionOnProxyStream`):**
    - 用于通过现有的代理流 (例如 MASQUE) 创建 QUIC 会话。

23. **完成会话创建 (`FinishCreateSession`):**
    - `CreateSessionAsync` 和 `CreateSessionOnProxyStream` 的回调函数，用于在 socket 连接和配置完成后进行实际的会话创建。

24. **会话创建辅助函数 (`CreateSessionHelper`):**
    - 封装了创建 QUIC 会话的核心逻辑。

总而言之，这部分代码是 QUIC 会话建立过程中的关键环节，它负责与操作系统进行底层的 socket 交互，并根据 QUIC 协议的要求对 socket 进行配置，为上层 QUIC 会话的创建和数据传输奠定基础。

### 提示词
```
这是目录为net/quic/quic_session_pool.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
IPEndPoint addr,
                                                handles::NetworkHandle network,
                                                const SocketTag& socket_tag) {
  socket->UseNonBlockingIO();

  int rv;
  auto split_callback = base::SplitOnceCallback(std::move(callback));
  CompletionOnceCallback connect_callback =
      base::BindOnce(&QuicSessionPool::FinishConnectAndConfigureSocket,
                     weak_factory_.GetWeakPtr(),
                     std::move(split_callback.first), socket, socket_tag);
  if (!params_.migrate_sessions_on_network_change_v2) {
    rv = socket->ConnectAsync(addr, std::move(connect_callback));
  } else if (network == handles::kInvalidNetworkHandle) {
    // If caller leaves network unspecified, use current default network.
    rv = socket->ConnectUsingDefaultNetworkAsync(addr,
                                                 std::move(connect_callback));
  } else {
    rv = socket->ConnectUsingNetworkAsync(network, addr,
                                          std::move(connect_callback));
  }
  // Both callbacks within `split_callback` will always be run asynchronously,
  // even if a Connect call returns synchronously. Therefore we always return
  // ERR_IO_PENDING.
  if (rv != ERR_IO_PENDING) {
    FinishConnectAndConfigureSocket(std::move(split_callback.second), socket,
                                    socket_tag, rv);
  }
}

void QuicSessionPool::FinishConnectAndConfigureSocket(
    CompletionOnceCallback callback,
    DatagramClientSocket* socket,
    const SocketTag& socket_tag,
    int rv) {
  if (rv != OK) {
    OnFinishConnectAndConfigureSocketError(
        std::move(callback), CREATION_ERROR_CONNECTING_SOCKET, rv);
    return;
  }

  socket->ApplySocketTag(socket_tag);

  rv = socket->SetReceiveBufferSize(kQuicSocketReceiveBufferSize);
  if (rv != OK) {
    OnFinishConnectAndConfigureSocketError(
        std::move(callback), CREATION_ERROR_SETTING_RECEIVE_BUFFER, rv);
    return;
  }

  rv = socket->SetDoNotFragment();
  // SetDoNotFragment is not implemented on all platforms, so ignore errors.
  if (rv != OK && rv != ERR_NOT_IMPLEMENTED) {
    OnFinishConnectAndConfigureSocketError(
        std::move(callback), CREATION_ERROR_SETTING_DO_NOT_FRAGMENT, rv);
    return;
  }

  if (report_ecn_) {
    rv = socket->SetRecvTos();
    if (rv != OK) {
      OnFinishConnectAndConfigureSocketError(
          std::move(callback), CREATION_ERROR_SETTING_RECEIVE_ECN, rv);
      return;
    }
  }

  // Set a buffer large enough to contain the initial CWND's worth of packet
  // to work around the problem with CHLO packets being sent out with the
  // wrong encryption level, when the send buffer is full.
  rv = socket->SetSendBufferSize(quic::kMaxOutgoingPacketSize * 20);
  if (rv != OK) {
    OnFinishConnectAndConfigureSocketError(
        std::move(callback), CREATION_ERROR_SETTING_SEND_BUFFER, rv);
    return;
  }

  if (params_.ios_network_service_type > 0) {
    socket->SetIOSNetworkServiceType(params_.ios_network_service_type);
  }

  socket->GetLocalAddress(&local_address_);
  if (need_to_check_persisted_supports_quic_) {
    need_to_check_persisted_supports_quic_ = false;
    if (http_server_properties_->WasLastLocalAddressWhenQuicWorked(
            local_address_.address())) {
      has_quic_ever_worked_on_current_network_ = true;
      // Clear the persisted IP address, in case the network no longer supports
      // QUIC so the next restart will require confirmation. It will be
      // re-persisted when the first job completes successfully.
      http_server_properties_->ClearLastLocalAddressWhenQuicWorked();
    }
  }

  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&QuicSessionPool::DoCallback, weak_factory_.GetWeakPtr(),
                     std::move(callback), rv));
}

bool QuicSessionPool::CanWaiveIpMatching(
    const url::SchemeHostPort& destination,
    QuicChromiumClientSession* session) const {
  // Checks if `destination` matches the alias key of `session`.
  if (destination == session->session_alias_key().destination()) {
    return true;
  }

  if (ignore_ip_matching_when_finding_existing_sessions_ &&
      session->config()->HasReceivedConnectionOptions() &&
      quic::ContainsQuicTag(session->config()->ReceivedConnectionOptions(),
                            quic::kNOIP)) {
    return true;
  }

  // Check received origins.
  if (skip_dns_with_origin_frame_ &&
      session->received_origins().contains(destination)) {
    return true;
  }
  return false;
}

void QuicSessionPool::OnFinishConnectAndConfigureSocketError(
    CompletionOnceCallback callback,
    enum CreateSessionFailure error,
    int rv) {
  DCHECK(callback);
  HistogramCreateSessionFailure(error);
  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&QuicSessionPool::DoCallback, weak_factory_.GetWeakPtr(),
                     std::move(callback), rv));
}

void QuicSessionPool::DoCallback(CompletionOnceCallback callback, int rv) {
  std::move(callback).Run(rv);
}

int QuicSessionPool::ConfigureSocket(DatagramClientSocket* socket,
                                     IPEndPoint addr,
                                     handles::NetworkHandle network,
                                     const SocketTag& socket_tag) {
  socket->UseNonBlockingIO();

  int rv;
  if (!params_.migrate_sessions_on_network_change_v2) {
    rv = socket->Connect(addr);
  } else if (network == handles::kInvalidNetworkHandle) {
    // If caller leaves network unspecified, use current default network.
    rv = socket->ConnectUsingDefaultNetwork(addr);
  } else {
    rv = socket->ConnectUsingNetwork(network, addr);
  }
  if (rv != OK) {
    HistogramCreateSessionFailure(CREATION_ERROR_CONNECTING_SOCKET);
    return rv;
  }

  socket->ApplySocketTag(socket_tag);

  rv = socket->SetReceiveBufferSize(kQuicSocketReceiveBufferSize);
  if (rv != OK) {
    HistogramCreateSessionFailure(CREATION_ERROR_SETTING_RECEIVE_BUFFER);
    return rv;
  }

  rv = socket->SetDoNotFragment();
  // SetDoNotFragment is not implemented on all platforms, so ignore errors.
  if (rv != OK && rv != ERR_NOT_IMPLEMENTED) {
    HistogramCreateSessionFailure(CREATION_ERROR_SETTING_DO_NOT_FRAGMENT);
    return rv;
  }

  if (report_ecn_) {
    rv = socket->SetRecvTos();
    if (rv != OK) {
      HistogramCreateSessionFailure(CREATION_ERROR_SETTING_RECEIVE_ECN);
      return rv;
    }
  }

  // Set a buffer large enough to contain the initial CWND's worth of packet
  // to work around the problem with CHLO packets being sent out with the
  // wrong encryption level, when the send buffer is full.
  rv = socket->SetSendBufferSize(quic::kMaxOutgoingPacketSize * 20);
  if (rv != OK) {
    HistogramCreateSessionFailure(CREATION_ERROR_SETTING_SEND_BUFFER);
    return rv;
  }

  if (params_.ios_network_service_type > 0) {
    socket->SetIOSNetworkServiceType(params_.ios_network_service_type);
  }

  socket->GetLocalAddress(&local_address_);
  if (need_to_check_persisted_supports_quic_) {
    need_to_check_persisted_supports_quic_ = false;
    if (http_server_properties_->WasLastLocalAddressWhenQuicWorked(
            local_address_.address())) {
      has_quic_ever_worked_on_current_network_ = true;
      // Clear the persisted IP address, in case the network no longer supports
      // QUIC so the next restart will require confirmation. It will be
      // re-persisted when the first job completes successfully.
      http_server_properties_->ClearLastLocalAddressWhenQuicWorked();
    }
  }

  return OK;
}

handles::NetworkHandle QuicSessionPool::FindAlternateNetwork(
    handles::NetworkHandle old_network) {
  // Find a new network that sessions bound to |old_network| can be migrated to.
  NetworkChangeNotifier::NetworkList network_list;
  NetworkChangeNotifier::GetConnectedNetworks(&network_list);
  for (handles::NetworkHandle new_network : network_list) {
    if (new_network != old_network) {
      return new_network;
    }
  }
  return handles::kInvalidNetworkHandle;
}

std::unique_ptr<DatagramClientSocket> QuicSessionPool::CreateSocket(
    NetLog* net_log,
    const NetLogSource& source) {
  auto socket = client_socket_factory_->CreateDatagramClientSocket(
      DatagramSocket::DEFAULT_BIND, net_log, source);
  if (params_.enable_socket_recv_optimization) {
    socket->EnableRecvOptimization();
  }
  return socket;
}

void QuicSessionPool::OnIPAddressChanged() {
  net_log_.AddEvent(NetLogEventType::QUIC_SESSION_POOL_ON_IP_ADDRESS_CHANGED);
  CollectDataOnPlatformNotification(NETWORK_IP_ADDRESS_CHANGED,
                                    handles::kInvalidNetworkHandle);
  // Do nothing if connection migration is turned on.
  if (params_.migrate_sessions_on_network_change_v2) {
    return;
  }

  connectivity_monitor_.OnIPAddressChanged();

  set_has_quic_ever_worked_on_current_network(false);
  if (params_.close_sessions_on_ip_change) {
    CloseAllSessions(ERR_NETWORK_CHANGED, quic::QUIC_IP_ADDRESS_CHANGED);
  } else {
    DCHECK(params_.goaway_sessions_on_ip_change);
    MarkAllActiveSessionsGoingAway(kIPAddressChanged);
  }
}

void QuicSessionPool::OnNetworkConnected(handles::NetworkHandle network) {
  CollectDataOnPlatformNotification(NETWORK_CONNECTED, network);
  if (params_.migrate_sessions_on_network_change_v2) {
    net_log_.AddEvent(NetLogEventType::QUIC_SESSION_POOL_PLATFORM_NOTIFICATION,
                      [&] {
                        base::Value::Dict dict;
                        dict.Set("signal", "OnNetworkConnected");
                        dict.Set("network", base::NumberToString(network));
                        return dict;
                      });
  }
  // Broadcast network connected to all sessions.
  // If migration is not turned on, session will not migrate but collect data.
  auto it = all_sessions_.begin();
  // Sessions may be deleted while iterating through the set.
  while (it != all_sessions_.end()) {
    QuicChromiumClientSession* session = it->get();
    ++it;
    session->OnNetworkConnected(network);
  }
}

void QuicSessionPool::OnNetworkDisconnected(handles::NetworkHandle network) {
  CollectDataOnPlatformNotification(NETWORK_DISCONNECTED, network);
  if (params_.migrate_sessions_on_network_change_v2) {
    net_log_.AddEvent(NetLogEventType::QUIC_SESSION_POOL_PLATFORM_NOTIFICATION,
                      [&] {
                        base::Value::Dict dict;
                        dict.Set("signal", "OnNetworkDisconnected");
                        dict.Set("network", base::NumberToString(network));
                        return dict;
                      });
  }
  // Broadcast network disconnected to all sessions.
  // If migration is not turned on, session will not migrate but collect data.
  auto it = all_sessions_.begin();
  // Sessions may be deleted while iterating through the set.
  while (it != all_sessions_.end()) {
    QuicChromiumClientSession* session = it->get();
    ++it;
    session->OnNetworkDisconnectedV2(/*disconnected_network*/ network);
  }
}

// This method is expected to only be called when migrating from Cellular to
// WiFi on Android, and should always be preceded by OnNetworkMadeDefault().
void QuicSessionPool::OnNetworkSoonToDisconnect(
    handles::NetworkHandle network) {
  CollectDataOnPlatformNotification(NETWORK_SOON_TO_DISCONNECT, network);
}

void QuicSessionPool::OnNetworkMadeDefault(handles::NetworkHandle network) {
  CollectDataOnPlatformNotification(NETWORK_MADE_DEFAULT, network);
  connectivity_monitor_.OnDefaultNetworkUpdated(network);

  // Clear alternative services that were marked as broken until default network
  // changes.
  if (params_.retry_on_alternate_network_before_handshake &&
      default_network_ != handles::kInvalidNetworkHandle &&
      network != default_network_) {
    http_server_properties_->OnDefaultNetworkChanged();
  }

  DCHECK_NE(handles::kInvalidNetworkHandle, network);
  default_network_ = network;

  if (params_.migrate_sessions_on_network_change_v2) {
    net_log_.AddEvent(NetLogEventType::QUIC_SESSION_POOL_PLATFORM_NOTIFICATION,
                      [&] {
                        base::Value::Dict dict;
                        dict.Set("signal", "OnNetworkMadeDefault");
                        dict.Set("network", base::NumberToString(network));
                        return dict;
                      });
  }

  auto it = all_sessions_.begin();
  // Sessions may be deleted while iterating through the set.
  while (it != all_sessions_.end()) {
    QuicChromiumClientSession* session = it->get();
    ++it;
    session->OnNetworkMadeDefault(network);
  }
  if (params_.migrate_sessions_on_network_change_v2) {
    set_has_quic_ever_worked_on_current_network(false);
  }
}

void QuicSessionPool::OnTrustStoreChanged() {
  // We should flush the sessions if we removed trust from a
  // cert, because a previously trusted server may have become
  // untrusted.
  //
  // We should not flush the sessions if we added trust to a cert.
  //
  // Since the OnTrustStoreChanged method doesn't tell us what
  // kind of change it is, we have to flush the socket
  // pools to be safe.
  MarkAllActiveSessionsGoingAway(kCertDBChanged);
}

void QuicSessionPool::OnCertVerifierChanged() {
  // Flush sessions if the CertCerifier configuration has changed.
  MarkAllActiveSessionsGoingAway(kCertVerifierChanged);
}

void QuicSessionPool::set_has_quic_ever_worked_on_current_network(
    bool has_quic_ever_worked_on_current_network) {
  has_quic_ever_worked_on_current_network_ =
      has_quic_ever_worked_on_current_network;
  if (!(local_address_ == IPEndPoint())) {
    if (has_quic_ever_worked_on_current_network_) {
      http_server_properties_->SetLastLocalAddressWhenQuicWorked(
          local_address_.address());
    } else {
      http_server_properties_->ClearLastLocalAddressWhenQuicWorked();
    }
  }
}

base::TimeDelta QuicSessionPool::GetTimeDelayForWaitingJob(
    const QuicSessionKey& session_key) {
  if (time_delay_for_waiting_job_for_testing_.has_value()) {
    return *time_delay_for_waiting_job_for_testing_;
  }

  // If |is_quic_known_to_work_on_current_network_| is false, then one of the
  // following is true:
  // 1) This is startup and QuicSessionPool::CreateSession() and
  // ConfigureSocket() have yet to be called, and it is not yet known
  // if the current network is the last one where QUIC worked.
  // 2) Startup has been completed, and QUIC has not been used
  // successfully since startup, or on this network before.
  if (!has_quic_ever_worked_on_current_network_) {
    // If |need_to_check_persisted_supports_quic_| is false, this is case 1)
    // above. If HasLastLocalAddressWhenQuicWorked() is also true, then there's
    // a chance the current network is the last one on which QUIC worked. So
    // only delay the request if there's no chance that is the case.
    if (!need_to_check_persisted_supports_quic_ ||
        !http_server_properties_->HasLastLocalAddressWhenQuicWorked()) {
      return base::TimeDelta();
    }
  }

  // QUIC was recently broken. Do not delay the main job.
  if (WasQuicRecentlyBroken(session_key)) {
    return base::TimeDelta();
  }

  int64_t srtt = 1.5 * GetServerNetworkStatsSmoothedRttInMicroseconds(
                           session_key.server_id(),
                           session_key.network_anonymization_key());
  // Picked 300ms based on mean time from
  // Net.QuicSession.HostResolution.HandshakeConfirmedTime histogram.
  const int kDefaultRTT = 300 * quic::kNumMicrosPerMilli;
  if (!srtt) {
    srtt = kDefaultRTT;
  }
  return base::Microseconds(srtt);
}

const std::set<std::string>& QuicSessionPool::GetDnsAliasesForSessionKey(
    const QuicSessionKey& key) const {
  auto it = dns_aliases_by_session_key_.find(key);

  if (it == dns_aliases_by_session_key_.end()) {
    static const base::NoDestructor<std::set<std::string>> emptyvector_result;
    return *emptyvector_result;
  }

  return it->second;
}

void QuicSessionPool::ActivateSessionForTesting(
    std::unique_ptr<QuicChromiumClientSession> new_session) {
  QuicChromiumClientSession* session = new_session.get();
  all_sessions_.insert(std::move(new_session));
  ActivateSession(session->session_alias_key(), session,
                  std::set<std::string>());
}

void QuicSessionPool::DeactivateSessionForTesting(
    QuicChromiumClientSession* session) {
  OnSessionGoingAway(session);
  auto it = all_sessions_.find(session);
  CHECK(it != all_sessions_.end());
  all_sessions_.erase(it);
}

void QuicSessionPool::SetTimeDelayForWaitingJobForTesting(
    base::TimeDelta delay) {
  time_delay_for_waiting_job_for_testing_ = delay;
}

quic::ParsedQuicVersion QuicSessionPool::SelectQuicVersion(
    const quic::ParsedQuicVersion& known_quic_version,
    const ConnectionEndpointMetadata& metadata,
    bool svcb_optional) const {
  if (metadata.supported_protocol_alpns.empty()) {
    // `metadata` doesn't contain QUIC ALPN. If we know the QUIC ALPN to use
    // externally, i.e. via Alt-Svc, use it in SVCB-optional mode. Otherwise,
    // the endpoint associated with `metadata` is not eligible for QUIC.
    return svcb_optional ? known_quic_version
                         : quic::ParsedQuicVersion::Unsupported();
  }

  // Otherwise, `metadata` came from an HTTPS/SVCB record. We can use
  // QUIC if a suitable match is found in the record's ALPN list.
  // Additionally, if this connection attempt came from Alt-Svc, the DNS
  // result must be consistent with it. See
  // https://datatracker.ietf.org/doc/html/rfc9460#name-interaction-with-alt-svc
  if (known_quic_version.IsKnown()) {
    std::string expected_alpn = quic::AlpnForVersion(known_quic_version);
    if (base::Contains(metadata.supported_protocol_alpns,
                       quic::AlpnForVersion(known_quic_version))) {
      return known_quic_version;
    }
    return quic::ParsedQuicVersion::Unsupported();
  }

  for (const auto& alpn : metadata.supported_protocol_alpns) {
    for (const auto& supported_version : supported_versions()) {
      if (alpn == AlpnForVersion(supported_version)) {
        return supported_version;
      }
    }
  }

  return quic::ParsedQuicVersion::Unsupported();
}

// static
void QuicSessionPool::LogConnectionIpPooling(bool pooled) {
  base::UmaHistogramBoolean("Net.QuicSession.ConnectionIpPooled", pooled);
}

bool QuicSessionPool::HasMatchingIpSession(
    const QuicSessionAliasKey& key,
    const std::vector<IPEndPoint>& ip_endpoints,
    const std::set<std::string>& aliases,
    bool use_dns_aliases) {
  const quic::QuicServerId& server_id(key.server_id());
  DCHECK(!HasActiveSession(key.session_key()));
  for (const auto& address : ip_endpoints) {
    if (!base::Contains(ip_aliases_, address)) {
      continue;
    }

    const SessionSet& sessions = ip_aliases_[address];
    for (QuicChromiumClientSession* session : sessions) {
      if (!session->CanPool(server_id.host(), key.session_key())) {
        continue;
      }
      std::set<std::string> dns_aliases;
      if (use_dns_aliases) {
        dns_aliases = aliases;
      }
      ActivateAndMapSessionToAliasKey(session, key, std::move(dns_aliases));
      LogFindMatchingIpSessionResult(net_log_, MATCHING_IP_SESSION_FOUND,
                                     session, key.destination());
      return true;
    }
  }

  bool can_pool = false;
  static constexpr uint32_t kMaxLoopCount = 200;
  uint32_t loop_count = 0;
  for (const auto& entry : active_sessions_) {
    ++loop_count;
    if (loop_count >= kMaxLoopCount) {
      break;
    }
    QuicChromiumClientSession* session = entry.second;
    if (!session->CanPool(server_id.host(), key.session_key())) {
      continue;
    }
    can_pool = true;
    // TODO(fayang): consider to use CanWaiveIpMatching().
    if (session->received_origins().contains(key.destination()) ||
        (ignore_ip_matching_when_finding_existing_sessions_ &&
         session->config()->HasReceivedConnectionOptions() &&
         quic::ContainsQuicTag(session->config()->ReceivedConnectionOptions(),
                               quic::kNOIP))) {
      std::set<std::string> dns_aliases;
      if (use_dns_aliases) {
        dns_aliases = aliases;
      }
      ActivateAndMapSessionToAliasKey(session, key, std::move(dns_aliases));
      LogFindMatchingIpSessionResult(net_log_, POOLED_WITH_DIFFERENT_IP_SESSION,
                                     session, key.destination());
      return true;
    }
  }
  if (can_pool) {
    LogFindMatchingIpSessionResult(net_log_, CAN_POOL_BUT_DIFFERENT_IP,
                                   /*session=*/nullptr, key.destination());
  } else {
    LogFindMatchingIpSessionResult(net_log_, CANNOT_POOL_WITH_EXISTING_SESSIONS,
                                   /*session=*/nullptr, key.destination());
  }
  return false;
}

void QuicSessionPool::OnJobComplete(
    Job* job,
    std::optional<base::TimeTicks> proxy_connect_start_time,
    int rv) {
  auto iter = active_jobs_.find(job->key().session_key());
  if (proxy_connect_start_time) {
    HttpProxyConnectJob::EmitConnectLatency(
        NextProto::kProtoQUIC, ProxyServer::Scheme::SCHEME_QUIC,
        rv == 0 ? HttpProxyConnectJob::HttpConnectResult::kSuccess
                : HttpProxyConnectJob::HttpConnectResult::kError,
        base::TimeTicks::Now() - *proxy_connect_start_time);
  }

  CHECK(iter != active_jobs_.end(), base::NotFatalUntil::M130);
  if (rv == OK) {
    if (!has_quic_ever_worked_on_current_network_) {
      set_has_quic_ever_worked_on_current_network(true);
    }

    auto session_it = active_sessions_.find(job->key().session_key());
    CHECK(session_it != active_sessions_.end());
    QuicChromiumClientSession* session = session_it->second;
    for (QuicSessionRequest* request : iter->second->requests()) {
      // Do not notify |request| yet.
      request->SetSession(session->CreateHandle(job->key().destination()));
    }
  }

  for (QuicSessionRequest* request : iter->second->requests()) {
    // Even though we're invoking callbacks here, we don't need to worry
    // about |this| being deleted, because the pool is owned by the
    // profile which can not be deleted via callbacks.
    if (rv < 0) {
      job->PopulateNetErrorDetails(request->net_error_details());
    }
    request->OnRequestComplete(rv);
  }
  active_jobs_.erase(iter);
}

bool QuicSessionPool::HasActiveSession(
    const QuicSessionKey& session_key) const {
  return base::Contains(active_sessions_, session_key);
}

bool QuicSessionPool::HasActiveJob(const QuicSessionKey& session_key) const {
  return base::Contains(active_jobs_, session_key);
}

int QuicSessionPool::CreateSessionSync(
    QuicSessionAliasKey key,
    quic::ParsedQuicVersion quic_version,
    int cert_verify_flags,
    bool require_confirmation,
    IPEndPoint peer_address,
    ConnectionEndpointMetadata metadata,
    base::TimeTicks dns_resolution_start_time,
    base::TimeTicks dns_resolution_end_time,
    const NetLogWithSource& net_log,
    raw_ptr<QuicChromiumClientSession>* session,
    handles::NetworkHandle* network,
    MultiplexedSessionCreationInitiator session_creation_initiator) {
  *session = nullptr;
  // TODO(crbug.com/40256842): This logic only knows how to try one IP
  // endpoint.
  std::unique_ptr<DatagramClientSocket> socket(
      CreateSocket(net_log.net_log(), net_log.source()));

  // If migrate_sessions_on_network_change_v2 is on, passing in
  // handles::kInvalidNetworkHandle will bind the socket to the default network.
  int rv = ConfigureSocket(socket.get(), peer_address, *network,
                           key.session_key().socket_tag());
  if (rv != OK) {
    return rv;
  }
  base::expected<QuicSessionAttempt::CreateSessionResult, int> result =
      CreateSessionHelper(std::move(key), quic_version, cert_verify_flags,
                          require_confirmation, std::move(peer_address),
                          std::move(metadata), dns_resolution_start_time,
                          dns_resolution_end_time,
                          /*session_max_packet_length=*/0, net_log, *network,
                          std::move(socket), session_creation_initiator);
  if (!result.has_value()) {
    return result.error();
  }

  *session = result->session;
  *network = result->network;
  return OK;
}

int QuicSessionPool::CreateSessionAsync(
    CreateSessionCallback callback,
    QuicSessionAliasKey key,
    quic::ParsedQuicVersion quic_version,
    int cert_verify_flags,
    bool require_confirmation,
    IPEndPoint peer_address,
    ConnectionEndpointMetadata metadata,
    base::TimeTicks dns_resolution_start_time,
    base::TimeTicks dns_resolution_end_time,
    const NetLogWithSource& net_log,
    handles::NetworkHandle network,
    MultiplexedSessionCreationInitiator session_creation_initiator) {
  // TODO(crbug.com/40256842): This logic only knows how to try one IP
  // endpoint.
  std::unique_ptr<DatagramClientSocket> socket(
      CreateSocket(net_log.net_log(), net_log.source()));
  DatagramClientSocket* socket_ptr = socket.get();
  CompletionOnceCallback connect_and_configure_callback = base::BindOnce(
      &QuicSessionPool::FinishCreateSession, weak_factory_.GetWeakPtr(),
      std::move(callback), std::move(key), quic_version, cert_verify_flags,
      require_confirmation, peer_address, std::move(metadata),
      dns_resolution_start_time, dns_resolution_end_time,
      /*session_max_packet_length=*/0, net_log, network, std::move(socket),
      session_creation_initiator);

  // If migrate_sessions_on_network_change_v2 is on, passing in
  // handles::kInvalidNetworkHandle will bind the socket to the default network.
  ConnectAndConfigureSocket(std::move(connect_and_configure_callback),
                            socket_ptr, std::move(peer_address), network,
                            key.session_key().socket_tag());
  return ERR_IO_PENDING;
}

int QuicSessionPool::CreateSessionOnProxyStream(
    CreateSessionCallback callback,
    QuicSessionAliasKey key,
    quic::ParsedQuicVersion quic_version,
    int cert_verify_flags,
    bool require_confirmation,
    IPEndPoint local_address,
    IPEndPoint proxy_peer_address,
    std::unique_ptr<QuicChromiumClientStream::Handle> proxy_stream,
    std::string user_agent,
    const NetLogWithSource& net_log,
    handles::NetworkHandle network) {
  // Use the host and port from the proxy server along with the example URI
  // template in https://datatracker.ietf.org/doc/html/rfc9298#section-2.
  const ProxyChain& proxy_chain = key.session_key().proxy_chain();
  const ProxyServer& last_proxy = proxy_chain.Last();
  const quic::QuicServerId& server_id = key.server_id();
  const std::string encocded_host =
      base::EscapeQueryParamValue(last_proxy.GetHost().c_str(), false);
  GURL url(base::StringPrintf("https://%s:%d/.well-known/masque/udp/%s/%d/",
                              last_proxy.GetHost().c_str(),
                              last_proxy.GetPort(), server_id.host().c_str(),
                              server_id.port()));

  auto socket = std::make_unique<QuicProxyDatagramClientSocket>(
      url, key.session_key().proxy_chain(), user_agent, net_log,
      proxy_delegate_);
  QuicProxyDatagramClientSocket* socket_ptr = socket.get();

  socket->ApplySocketTag(key.session_key().socket_tag());

  // No host resolution took place, so pass an empty metadata,
  // pretend resolution started and ended right now, and pass an
  // invalid network handle. Connections on an invalid network will
  // not be migrated due to network changes.
  ConnectionEndpointMetadata metadata;
  auto dns_resolution_time = base::TimeTicks::Now();

  // Maximum packet length for the session inside this stream is limited
  // by the largest message payload allowed, accounting for the quarter-stream
  // ID (up to 8 bytes) and the context ID (1 byte). If we cannot determine the
  // max payload size for the stream, or there is no room for the overhead, use
  // 0 as a sentinel value to use the default packet size.
  quic::QuicPacketLength quarter_stream_id_length =
      quiche::QuicheDataWriter::GetVarInt62Len(proxy_stream->id() / 4);
  constexpr quic::QuicPacketLength context_id_length = 1;
  quic::QuicPacketLength guaranteed_largest_message_payload =
      proxy_stream->GetGuaranteedLargestMessagePayload();
  quic::QuicPacketLength overhead =
      quarter_stream_id_length + context_id_length;
  quic::QuicPacketLength session_max_packet_length =
      guaranteed_largest_message_payload > overhead
          ? guaranteed_largest_message_payload - overhead
          : 0;

  auto [on_connected_via_stream_async, on_connected_via_stream_sync] =
      base::SplitOnceCallback(base::BindOnce(
          &QuicSessionPool::FinishCreateSession, weak_factory_.GetWeakPtr(),
          std::move(callback), std::move(key), quic_version, cert_verify_flags,
          require_confirmation, proxy_peer_address, std::move(metadata),
          dns_resolution_time, dns_resolution_time, session_max_packet_length,
          net_log, network, std::move(socket),
          MultiplexedSessionCreationInitiator::kUnknown));

  int rv = socket_ptr->ConnectViaStream(
      std::move(local_address), std::move(proxy_peer_address),
      std::move(proxy_stream), std::move(on_connected_via_stream_async));
  if (rv != ERR_IO_PENDING) {
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce([](CompletionOnceCallback callback,
                                     int rv) { std::move(callback).Run(rv); },
                                  std::move(on_connected_via_stream_sync), rv));
  }

  return ERR_IO_PENDING;
}

void QuicSessionPool::FinishCreateSession(
    CreateSessionCallback callback,
    QuicSessionAliasKey key,
    quic::ParsedQuicVersion quic_version,
    int cert_verify_flags,
    bool require_confirmation,
    IPEndPoint peer_address,
    ConnectionEndpointMetadata metadata,
    base::TimeTicks dns_resolution_start_time,
    base::TimeTicks dns_resolution_end_time,
    quic::QuicPacketLength session_max_packet_length,
    const NetLogWithSource& net_log,
    handles::NetworkHandle network,
    std::unique_ptr<DatagramClientSocket> socket,
    MultiplexedSessionCreationInitiator session_creation_initiator,
    int rv) {
  if (rv != OK) {
    std::move(callback).Run(base::unexpected(rv));
    return;
  }
  base::expected<QuicSessionAttempt::CreateSessionResult, int> result =
      CreateSessionHelper(std::move(key), quic_version, cert_verify_flags,
                          require_confirmation, std::move(peer_address),
                          std::move(metadata), dns_resolution_start_time,
                          dns_resolution_end_time, session_max_packet_length,
                          net_log, network, std::move(socket),
                          session_creation_initiator);
  std::move(callback).Run(std::move(result));
}

base::expected<QuicSessionAttempt::CreateSessionResult, int>
QuicSessionPool::CreateSessionHelper(
    QuicSessionAliasKey key,
    quic::ParsedQuicVersion quic_version,
    int cert_verify_flags,
    bool require_confirmation,
    IPEndPoint peer_address,
    ConnectionEndpointMetadata metadata,
    base::TimeTicks dns_resolution_start_time,
    base::TimeTicks dns_resolution_end_time,
    quic::QuicPacketLength session_max_packet_length,
    const NetLogWithSource& net_log,
    handles::NetworkHandle network,
    std::unique_ptr<DatagramClientSocket> socket,
    MultiplexedSessionCreationInitiator session_creation_initiator) {
  const quic::QuicServerId& server_id = key.server_id();

  if (params_.migrate_sessions_on_network_change_v2 &&
      network == handles::kInvalidNetworkHandle) {
    network = socket->GetBoundNetwork();
    if (default_network_ == handles::kInvalidNetworkHandle) {
      // QuicSessionPool may miss the default network signal before its
      // creation, update |default_network_| when the first socket is bound
      // to the default network.
      default_network_ = network;
      connectivity_monitor_.SetInitialDefaultNetwork(default_network_);
    } else {
      UMA_HISTOGRAM_BOOLEAN("Net.QuicStreamFactory.DefaultNetworkMatch",
                            default_network_ == network);
    }
  }

  if (!helper_.get()) {
    helper_ = std::make_unique<QuicChromiumConnectionHelper>(clock_,
                                                             random_generator_);
  }

  if (!alarm_factory_.get()) {
    alarm_factory_ = std::make_unique<QuicChromiumAlarmFactory>(
        base::SingleThreadTaskRunner::GetCurrentDefault().get(), clock_);
  }

  quic::QuicConnectionId connection_id =
      q
```