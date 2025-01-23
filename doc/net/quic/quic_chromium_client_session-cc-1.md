Response:
My goal was to analyze the provided C++ code snippet and explain its functionality, focusing on its role within the Chromium networking stack, potential interactions with JavaScript, and common usage errors. Here's a breakdown of my thought process:

1. **Initial Understanding of the Context:** The prompt clearly states the file is `net/quic/quic_chromium_client_session.cc` and is part of the Chromium network stack. This immediately tells me the code is about implementing a QUIC client session within Chromium. The mention of "part 2 of 5" suggests this is a larger code file being broken down for analysis.

2. **Scanning for Key Functionality:** I started by scanning the provided code, looking for the main purpose. The constructor (`QuicChromiumClientSession::QuicChromiumClientSession`) is a good starting point. It reveals the session takes numerous parameters related to QUIC configuration, network handling, and security. The destructor (`QuicChromiumClientSession::~QuicChromiumClientSession`) reveals cleanup actions, including closing the QUIC connection and logging statistics.

3. **Identifying Core Responsibilities:** Based on the constructor and destructor, and the overall context of a "client session," I inferred the primary functions:
    * **Establishing and managing a QUIC connection:** This involves handling connection parameters, the underlying `QuicConnection`, and the crypto handshake.
    * **Creating and managing QUIC streams:**  The code has methods for creating both bidirectional and unidirectional streams.
    * **Handling connection migration:** Several parameters relate to network changes and session migration.
    * **Security:** The integration with `QuicCryptoClientConfigHandle` and the handling of SSL/TLS information are evident.
    * **Logging and metrics:**  The inclusion of `NetLogWithSource` and numerous `UMA_HISTOGRAM_*` calls indicates a significant focus on logging and performance tracking.

4. **Analyzing the Constructor Parameters:** I meticulously examined the constructor parameters, understanding their roles:
    * `session_alias_key`:  For session reuse and pooling.
    * `require_confirmation`:  For enhanced security.
    * `migrate_session_*`:  Various flags related to connection migration strategies.
    * Network-related parameters (`default_network`, timeouts, probing intervals).
    * `cert_verify_flags`, `config`, `crypto_config`: Security configurations.
    * Logging and debugging information (`connection_description`, `net_log`).
    * Callbacks and task runners (`tick_clock`, `task_runner`).
    * Metadata (`ConnectionEndpointMetadata`).
    * Feature flags (`report_ecn`, `enable_origin_frame`).

5. **Analyzing the Destructor Logic:** The destructor's code confirmed its responsibility for:
    * Closing the connection cleanly.
    * Recording final handshake states.
    * Logging various connection statistics (ECN, packet counts, MTU, reordering).
    * Indicating whether the connection was ever used.

6. **Connecting to JavaScript (if applicable):** I considered how this C++ code might interact with JavaScript in a browser context. QUIC is a transport protocol underlying HTTP/3, which is used for fetching web resources. Therefore:
    * **Fetching resources:** When JavaScript initiates a network request (e.g., using `fetch`), the browser's networking stack (including this QUIC session code) handles the underlying communication.
    * **WebSockets over QUIC:**  The code mentions `WebSocketQuicStreamAdapter`, indicating support for WebSockets over QUIC, which is directly exposed to JavaScript.
    * **Service Workers:**  Service Workers can intercept network requests, and if QUIC is used, this code would be involved.
    * **No direct function calls:** It's crucial to note that JavaScript doesn't directly call methods in this C++ class. The interaction is through higher-level browser APIs.

7. **Identifying Potential Usage Errors:**  Based on my understanding of networking and the code, I identified common mistakes:
    * **Closing the session prematurely:** The destructor's checks highlight the importance of proper shutdown.
    * **Not handling connection errors:** The presence of error codes and callbacks indicates the need for error handling in the calling code.
    * **Misconfiguring QUIC parameters:** Incorrectly setting migration flags or timeouts could lead to unexpected behavior.
    * **Ignoring handshake completion:** Attempting to send data before the handshake is complete will fail.

8. **Tracing User Operations:**  I traced how a user action might lead to this code being executed:
    * **Typing a URL and pressing Enter:** This triggers a navigation, which involves DNS resolution, connection establishment (potentially using QUIC), and data transfer.
    * **Clicking a link:** Similar to typing a URL.
    * **JavaScript `fetch()` calls:**  As mentioned earlier.
    * **WebSockets:** Opening a WebSocket connection.
    * **Service Worker intercepting a request:** The Service Worker might trigger a QUIC connection to fetch a resource.

9. **Logical Reasoning (Hypothetical Input/Output):**  I devised a simple example:
    * **Input:** A user navigates to an HTTPS website that supports QUIC. The network conditions are stable.
    * **Output:**  A `QuicChromiumClientSession` is created, the handshake completes successfully, HTTP/3 requests are sent and received over QUIC streams, and the connection eventually idles or is closed gracefully.

10. **Summarizing Functionality:**  Finally, I distilled the core functionality of the provided code snippet, emphasizing its role in setting up, managing, and tearing down a QUIC client connection within the broader Chromium networking context.

**Self-Correction/Refinement During the Process:**

* **Initial focus on low-level details:** I initially got caught up in the specifics of individual parameters. I realized I needed to zoom out and focus on the higher-level responsibilities first.
* **Clarifying JavaScript interaction:** My initial explanation of JavaScript interaction was too vague. I refined it to be more specific about the types of browser APIs and scenarios involved.
* **Emphasizing the "Part 2 of 5" context:** I realized that understanding this was just a part of a larger file is important for setting the right expectations about the scope of the provided code. It's not the *entire* QUIC client session implementation.

By following these steps, I was able to generate a comprehensive explanation of the provided C++ code snippet, covering its functionality, relationship to JavaScript, potential errors, and user interaction scenarios. The key was to combine technical analysis of the code with a broader understanding of the Chromium networking architecture and web technologies.
这是 `net/quic/quic_chromium_client_session.cc` 文件（第二部分）的功能归纳：

**核心功能：QuicChromiumClientSession 的构造和析构，以及基本的初始化和资源管理。**

这段代码主要关注 `QuicChromiumClientSession` 对象的生命周期管理，包括：

1. **构造函数 `QuicChromiumClientSession::QuicChromiumClientSession(...)`**:
   - **初始化核心成员变量：**  接收大量参数，用于配置 QUIC 会话，包括：
     - 会话标识符 (`session_alias_key_`, `session_key_`)
     - 连接迁移相关的配置 (`require_confirmation_`, `migrate_session_early_v2_`, `migrate_session_on_network_change_v2_`, `migrate_idle_session_`, `allow_port_migration_`, 等)
     - 网络句柄 (`default_network_`)
     - 超时设置 (`retransmittable_on_wire_timeout`)
     - 多端口探测配置 (`multi_port_probing_interval`)
     - 最大非默认网络时间 (`max_time_on_non_default_network_`)
     - 最大迁移次数限制 (`max_migrations_to_non_default_network_on_write_error_`, `max_migrations_to_non_default_network_on_path_degrading_`)
     - 流量控制参数 (`yield_after_packets_`, `yield_after_duration_`)
     - 证书验证标志 (`cert_verify_flags`)
     - QUIC 配置 (`config`)
     - 加密配置 (`crypto_config`)
     - 调试信息 (`connection_description`)
     - DNS 解析时间 (`dns_resolution_start_time`, `dns_resolution_end_time`)
     - 时钟和任务运行器 (`tick_clock_`, `task_runner_`)
     - Socket 性能监控器 (`socket_performance_watcher`)
     - 连接端点元数据 (`metadata`)
     - 功能开关 (`report_ecn`, `enable_origin_frame`, `allow_server_preferred_address`)
     - 会话创建启动器 (`session_creation_initiator`)
     - 网络日志 (`net_log`)
   - **调用父类构造函数：** 初始化 `quic::QuicSpdyClientSessionBase`。
   - **创建关键子对象：**
     - `QuicChromiumPacketReader`：用于读取 QUIC 数据包。
     - `QuicCryptoClientStream`：用于处理 QUIC 的加密握手。
     - `QuicConnectionLogger` 和 `QuicHttp3Logger`：用于记录连接和 HTTP/3 相关的日志。
     - `PathValidationWriterDelegate`：用于路径验证。
   - **配置连接对象：** 设置最大包长度、多端口探测间隔等。
   - **记录连接开始事件：** 将会话信息记录到网络日志。

2. **析构函数 `QuicChromiumClientSession::~QuicChromiumClientSession()`**:
   - **清理资源：**
     - 移除所有连接性观察者。
     - 结束网络日志事件。
     - 检查是否有未完成的回调、活跃的请求流、未释放的句柄。
     - 取消所有待处理的流请求。
     - 解除连接对象的调试访问器。
   - **关闭连接：** 如果连接仍然打开，则使用 `QUIC_PEER_GOING_AWAY` 关闭连接。
   - **记录握手状态：**  记录连接是否成功建立加密和完成握手。
   - **记录统计信息：**  记录各种性能指标，包括 ECN 标记、重排序、MTU 探测次数、重传率等。
   - **针对 Google Host 的特殊处理：** 如果连接到 Google 主机且使用了 HTTP/3，则记录会话创建启动器信息。

3. **`Initialize()`**:
   - 设置最大入站头部列表大小。
   - 调用父类的 `Initialize()` 方法。

4. **`WriteHeadersOnHeadersStream(...)`**:
   - 将 HTTP 头部写入头部流。
   - 将 SPDY 优先级转换为 HTTP/2 权重。
   - 调用内部实现方法 `WriteHeadersOnHeadersStreamImpl`。

5. **`OnHttp3GoAway(uint64_t id)`**:
   - 处理接收到的 HTTP/3 GOAWAY 帧。
   - 通知工厂会话即将关闭。
   - 关闭 ID 大于等于 GOAWAY ID 的活跃流，并返回 `ERR_QUIC_GOAWAY_REQUEST_CAN_BE_RETRIED` 错误。

6. **`OnAcceptChFrameReceivedViaAlps(...)`**:
   - 处理通过 ALPS 接收到的 Accept-CH 帧。
   - 验证 Origin 的有效性。
   - 存储有效的 Accept-CH 条目。
   - 记录接收到的 Accept-CH 帧信息到网络日志和直方图。

7. **`OnOriginFrame(...)`**:
   - 处理接收到的 Origin 帧。
   - 限制接收到的 Origin 数量。
   - 验证 Origin URL 的有效性。
   - 存储有效的 Origin。
   - 记录接收到的 Origin 到网络日志和直方图。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不直接与 JavaScript 交互，但它是 Chromium 网络栈的一部分，负责处理底层 QUIC 协议的客户端会话。当 JavaScript 通过浏览器 API (例如 `fetch` 或 `XMLHttpRequest`) 发起网络请求时，如果协议协商结果是 QUIC (通常是 HTTP/3)，那么这个 `QuicChromiumClientSession` 对象就会被创建和使用来建立和维护与服务器的连接，并传输数据。

**举例说明：**

- 当 JavaScript 代码执行 `fetch('https://example.com')` 时，浏览器会尝试与 `example.com` 建立连接。如果服务器支持 QUIC，并且客户端配置允许，就会创建一个 `QuicChromiumClientSession` 来处理这个连接。
- 如果网页使用了 HTTP/3 的 "Early Hints" 功能，服务器可能会在发送最终响应之前推送一些资源。`QuicChromiumClientSession` 会处理这些推送流。
- 如果网站使用了 WebSockets over QUIC，那么 `QuicChromiumClientSession` 会负责建立和管理 WebSocket 连接底层的 QUIC 流。

**逻辑推理 (假设输入与输出):**

**假设输入：**

- 用户在浏览器地址栏输入 `https://quic-enabled-website.com` 并按下回车。
- 客户端配置允许使用 QUIC。
- 服务器 `quic-enabled-website.com` 支持 QUIC 协议。
- 网络环境稳定，没有丢包或网络切换。

**输出：**

1. 创建一个 `QuicChromiumClientSession` 对象，并使用与服务器协商好的 QUIC 版本和配置进行初始化。
2. `QuicCryptoClientStream` 执行 QUIC 的 TLS 握手。
3. 如果握手成功，会建立一个安全的 QUIC 连接。
4. 浏览器会创建一个或多个 `QuicChromiumClientStream` 来发送 HTTP/3 请求并接收响应。
5. 网页内容成功加载并显示在浏览器中。
6. 当连接空闲一段时间后，或者用户关闭页面，`QuicChromiumClientSession` 对象会被销毁，并记录相关的连接统计信息。

**用户或编程常见的使用错误：**

1. **过早地关闭 Session：**  如果程序在请求完成之前就销毁了 `QuicChromiumClientSession` 对象，会导致连接被强制关闭，可能导致请求失败或数据丢失。
2. **不处理连接错误：**  QUIC 连接可能会因为网络问题、服务器错误等原因关闭。程序需要适当地处理这些错误，例如重试请求或向用户显示错误信息。
3. **错误地配置 QUIC 参数：**  如果在创建 `QuicChromiumClientSession` 时传递了错误的配置参数，可能会导致连接建立失败或性能下降。例如，错误地设置连接迁移参数可能导致不必要的迁移或无法从网络变更中恢复。
4. **在握手完成前尝试发送数据：** 必须等待 QUIC 握手完成后才能安全地发送应用数据。在握手完成前尝试发送数据可能会导致错误。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器中输入 URL 并访问网站：**  这是最常见的触发点。浏览器会解析 URL，查找 IP 地址，并尝试与服务器建立连接。
2. **浏览器进行协议协商：** 在建立 TCP 连接或 UDP 通信后，浏览器会与服务器进行协议协商，看是否可以使用更高级的协议，例如 QUIC。
3. **QUIC 协商成功：** 如果协商结果是使用 QUIC，浏览器会创建 `QuicChromiumClientSession` 对象来管理这个 QUIC 连接。
4. **资源加载请求：**  一旦 QUIC 连接建立，当浏览器需要加载网页的各种资源（HTML, CSS, JavaScript, 图片等）时，会创建 `QuicChromiumClientStream` 来发送 HTTP/3 请求。
5. **WebSocket 连接：** 如果网页使用了 WebSocket，并且协议协商选择了 QUIC，那么会创建 `QuicChromiumClientSession` 来管理底层的 QUIC 连接，并创建 `WebSocketQuicStreamAdapter` 来处理 WebSocket 帧。
6. **Service Worker 拦截请求：** 如果网站注册了 Service Worker，当 Service Worker 拦截到网络请求时，可能会使用已有的 `QuicChromiumClientSession` 或者创建一个新的来完成请求。

在调试 QUIC 相关问题时，可以关注以下几点：

- **网络日志 (NetLog):** Chromium 的 NetLog 会记录详细的网络事件，包括 QUIC 连接的建立、握手过程、数据包的发送和接收、错误信息等。这是调试 QUIC 问题的关键工具。
- **`chrome://webrtc-internals`:**  虽然主要用于 WebRTC 调试，但有时也能提供关于底层网络连接的信息。
- **抓包工具 (如 Wireshark):**  可以捕获网络数据包，查看 QUIC 连接的详细通信过程。
- **断点调试：**  在 `QuicChromiumClientSession` 的构造函数、析构函数以及关键方法中设置断点，可以跟踪代码的执行流程，了解连接的状态变化。

**功能归纳：**

这段代码是 `net/quic/quic_chromium_client_session.cc` 文件的一部分，主要负责 `QuicChromiumClientSession` 类的**构造、初始化和析构**。它定义了 QUIC 客户端会话的创建过程，接收各种配置参数，创建必要的子对象（如数据包读取器、加密流、日志记录器），并负责在会话结束时清理资源和记录统计信息。它还包含了处理 HTTP/3 GOAWAY 帧和 Accept-CH/Origin 帧的逻辑。虽然不直接与 JavaScript 交互，但它是浏览器网络栈中处理 QUIC 连接的关键组件，为 JavaScript 发起的网络请求提供底层的传输支持。

### 提示词
```
这是目录为net/quic/quic_chromium_client_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
ssion_alias_key,
    bool require_confirmation,
    bool migrate_session_early_v2,
    bool migrate_sessions_on_network_change_v2,
    handles::NetworkHandle default_network,
    quic::QuicTime::Delta retransmittable_on_wire_timeout,
    bool migrate_idle_session,
    bool allow_port_migration,
    base::TimeDelta idle_migration_period,
    int multi_port_probing_interval,
    base::TimeDelta max_time_on_non_default_network,
    int max_migrations_to_non_default_network_on_write_error,
    int max_migrations_to_non_default_network_on_path_degrading,
    int yield_after_packets,
    quic::QuicTime::Delta yield_after_duration,
    int cert_verify_flags,
    const quic::QuicConfig& config,
    std::unique_ptr<QuicCryptoClientConfigHandle> crypto_config,
    const char* const connection_description,
    base::TimeTicks dns_resolution_start_time,
    base::TimeTicks dns_resolution_end_time,
    const base::TickClock* tick_clock,
    base::SequencedTaskRunner* task_runner,
    std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
    const ConnectionEndpointMetadata& metadata,
    bool report_ecn,
    bool enable_origin_frame,
    bool allow_server_preferred_address,
    MultiplexedSessionCreationInitiator session_creation_initiator,
    const NetLogWithSource& net_log)
    : quic::QuicSpdyClientSessionBase(connection,
                                      /*visitor=*/nullptr,
                                      config,
                                      connection->supported_versions()),
      session_alias_key_(std::move(session_alias_key)),
      session_key_(session_alias_key_.session_key()),
      require_confirmation_(require_confirmation),
      migrate_session_early_v2_(migrate_session_early_v2),
      migrate_session_on_network_change_v2_(
          migrate_sessions_on_network_change_v2),
      migrate_idle_session_(migrate_idle_session),
      allow_port_migration_(allow_port_migration),
      idle_migration_period_(idle_migration_period),
      max_time_on_non_default_network_(max_time_on_non_default_network),
      max_migrations_to_non_default_network_on_write_error_(
          max_migrations_to_non_default_network_on_write_error),
      max_migrations_to_non_default_network_on_path_degrading_(
          max_migrations_to_non_default_network_on_path_degrading),
      clock_(clock),
      yield_after_packets_(yield_after_packets),
      yield_after_duration_(yield_after_duration),
      most_recent_path_degrading_timestamp_(base::TimeTicks()),
      most_recent_network_disconnected_timestamp_(base::TimeTicks()),
      tick_clock_(tick_clock),
      most_recent_stream_close_time_(tick_clock_->NowTicks()),
      most_recent_write_error_timestamp_(base::TimeTicks()),
      crypto_config_(std::move(crypto_config)),
      session_pool_(session_pool),
      transport_security_state_(transport_security_state),
      ssl_config_service_(ssl_config_service),
      server_info_(std::move(server_info)),
      report_ecn_(report_ecn),
      enable_origin_frame_(enable_origin_frame),
      task_runner_(task_runner),
      net_log_(NetLogWithSource::Make(net_log.net_log(),
                                      NetLogSourceType::QUIC_SESSION)),
      logger_(std::make_unique<QuicConnectionLogger>(
          this,
          connection_description,
          std::move(socket_performance_watcher),
          net_log_)),
      http3_logger_(std::make_unique<QuicHttp3Logger>(net_log_)),
      path_validation_writer_delegate_(this, task_runner_),
      ech_config_list_(metadata.ech_config_list),
      allow_server_preferred_address_(allow_server_preferred_address),
      session_creation_initiator_(session_creation_initiator) {
  default_network_ = default_network;
  auto* socket_raw = socket.get();
  packet_readers_.push_back(std::make_unique<QuicChromiumPacketReader>(
      std::move(socket), clock, this, yield_after_packets, yield_after_duration,
      report_ecn, net_log_));
  crypto_stream_ = crypto_client_stream_factory->CreateQuicCryptoClientStream(
      session_key_.server_id(), this,
      std::make_unique<ProofVerifyContextChromium>(cert_verify_flags, net_log_),
      crypto_config_->GetConfig());
  set_debug_visitor(http3_logger_.get());
  connection->set_debug_visitor(logger_.get());
  connection->set_creator_debug_delegate(logger_.get());
  migrate_back_to_default_timer_.SetTaskRunner(task_runner_.get());
  net_log_.BeginEvent(NetLogEventType::QUIC_SESSION, [&] {
    return NetLogQuicClientSessionParams(
        net_log, &session_key_, connection_id(),
        connection->client_connection_id(), supported_versions(),
        cert_verify_flags, require_confirmation_, ech_config_list_);
  });
  // Associate the owned NetLog with the parent NetLog.
  net_log.AddEventReferencingSource(NetLogEventType::QUIC_SESSION_CREATED,
                                    net_log_.source());

  IPEndPoint address;
  if (socket_raw && socket_raw->GetLocalAddress(&address) == OK &&
      address.GetFamily() == ADDRESS_FAMILY_IPV6) {
    connection->SetMaxPacketLength(connection->max_packet_length() -
                                   kAdditionalOverheadForIPv6);
  }
  if (multi_port_probing_interval > 0) {
    connection->SetMultiPortProbingInterval(
        quic::QuicTime::Delta::FromSeconds(multi_port_probing_interval));
  }
  connect_timing_.domain_lookup_start = dns_resolution_start_time;
  connect_timing_.domain_lookup_end = dns_resolution_end_time;
  if (!retransmittable_on_wire_timeout.IsZero()) {
    connection->set_initial_retransmittable_on_wire_timeout(
        retransmittable_on_wire_timeout);
  }
}

QuicChromiumClientSession::~QuicChromiumClientSession() {
  DCHECK(callback_.is_null());

  for (auto& observer : connectivity_observer_list_) {
    observer.OnSessionRemoved(this);
  }

  net_log_.EndEvent(NetLogEventType::QUIC_SESSION);
  DCHECK(waiting_for_confirmation_callbacks_.empty());
  DCHECK(!HasActiveRequestStreams());
  DCHECK(handles_.empty());
  if (!stream_requests_.empty()) {
    // The session must be closed before it is destroyed.
    CancelAllRequests(ERR_UNEXPECTED);
  }
  connection()->set_debug_visitor(nullptr);

  if (connection()->connected()) {
    // Ensure that the connection is closed by the time the session is
    // destroyed.
    connection()->CloseConnection(quic::QUIC_PEER_GOING_AWAY,
                                  "session torn down",
                                  quic::ConnectionCloseBehavior::SILENT_CLOSE);
  }

  if (IsEncryptionEstablished()) {
    RecordHandshakeState(STATE_ENCRYPTION_ESTABLISHED);
  }
  if (OneRttKeysAvailable()) {
    RecordHandshakeState(STATE_HANDSHAKE_CONFIRMED);
  } else {
    RecordHandshakeState(STATE_FAILED);
  }

  UMA_HISTOGRAM_ENUMERATION(
      "Net.QuicSession.EcnMarksObserved",
      static_cast<EcnPermutations>(observed_incoming_ecn_));
  UMA_HISTOGRAM_COUNTS_10M(
      "Net.QuicSession.PacketsBeforeEcnTransition",
      observed_ecn_transition_ ? incoming_packets_before_ecn_transition_ : 0);
  UMA_HISTOGRAM_COUNTS_1M("Net.QuicSession.NumTotalStreams",
                          num_total_streams_);

  if (IsGoogleHostWithAlpnH3(session_key_.host())) {
    LogSessionCreationInitiatorToHistogram(session_creation_initiator_,
                                           num_total_streams_ > 0);
  }

  if (!OneRttKeysAvailable()) {
    return;
  }

  // Sending one client_hello means we had zero handshake-round-trips.
  int round_trip_handshakes = crypto_stream_->num_sent_client_hellos() - 1;

  SSLInfo ssl_info;
  // QUIC supports only secure urls.
  if (GetSSLInfo(&ssl_info) && ssl_info.cert.get()) {
    UMA_HISTOGRAM_CUSTOM_COUNTS("Net.QuicSession.ConnectRandomPortForHTTPS",
                                round_trip_handshakes, 1, 3, 4);
    if (require_confirmation_) {
      UMA_HISTOGRAM_CUSTOM_COUNTS(
          "Net.QuicSession.ConnectRandomPortRequiringConfirmationForHTTPS",
          round_trip_handshakes, 1, 3, 4);
    }
  }

  const quic::QuicConnectionStats stats = connection()->GetStats();

  // The MTU used by QUIC is limited to a fairly small set of predefined values
  // (initial values and MTU discovery values), but does not fare well when
  // bucketed.  Because of that, a sparse histogram is used here.
  base::UmaHistogramSparse("Net.QuicSession.ClientSideMtu", stats.egress_mtu);
  base::UmaHistogramSparse("Net.QuicSession.ServerSideMtu", stats.ingress_mtu);

  UMA_HISTOGRAM_COUNTS_1M("Net.QuicSession.MtuProbesSent",
                          connection()->mtu_probe_count());

  if (stats.packets_sent >= 100) {
    // Used to monitor for regressions that effect large uploads.
    UMA_HISTOGRAM_COUNTS_1000(
        "Net.QuicSession.PacketRetransmitsPerMille",
        1000 * stats.packets_retransmitted / stats.packets_sent);
  }

  if (stats.max_sequence_reordering == 0) {
    return;
  }
  const base::HistogramBase::Sample kMaxReordering = 100;
  base::HistogramBase::Sample reordering = kMaxReordering;
  if (stats.min_rtt_us > 0) {
    reordering = static_cast<base::HistogramBase::Sample>(
        100 * stats.max_time_reordering_us / stats.min_rtt_us);
  }
  UMA_HISTOGRAM_CUSTOM_COUNTS("Net.QuicSession.MaxReorderingTime", reordering,
                              1, kMaxReordering, 50);
  if (stats.min_rtt_us > 100 * 1000) {
    UMA_HISTOGRAM_CUSTOM_COUNTS("Net.QuicSession.MaxReorderingTimeLongRtt",
                                reordering, 1, kMaxReordering, 50);
  }
  UMA_HISTOGRAM_COUNTS_1M(
      "Net.QuicSession.MaxReordering",
      static_cast<base::HistogramBase::Sample>(stats.max_sequence_reordering));
}

void QuicChromiumClientSession::Initialize() {
  set_max_inbound_header_list_size(kQuicMaxHeaderListSize);
  quic::QuicSpdyClientSessionBase::Initialize();
}

size_t QuicChromiumClientSession::WriteHeadersOnHeadersStream(
    quic::QuicStreamId id,
    quiche::HttpHeaderBlock headers,
    bool fin,
    const spdy::SpdyStreamPrecedence& precedence,
    quiche::QuicheReferenceCountedPointer<quic::QuicAckListenerInterface>
        ack_listener) {
  const int weight =
      spdy::Spdy3PriorityToHttp2Weight(precedence.spdy3_priority());
  return WriteHeadersOnHeadersStreamImpl(id, std::move(headers), fin,
                                         /* parent_stream_id = */ 0, weight,
                                         /* exclusive = */ false,
                                         std::move(ack_listener));
}

void QuicChromiumClientSession::OnHttp3GoAway(uint64_t id) {
  quic::QuicSpdySession::OnHttp3GoAway(id);
  NotifyFactoryOfSessionGoingAway();

  PerformActionOnActiveStreams([id](quic::QuicStream* stream) {
    if (stream->id() >= id) {
      static_cast<QuicChromiumClientStream*>(stream)->OnError(
          ERR_QUIC_GOAWAY_REQUEST_CAN_BE_RETRIED);
    }
    return true;
  });
}

void QuicChromiumClientSession::OnAcceptChFrameReceivedViaAlps(
    const quic::AcceptChFrame& frame) {
  bool has_valid_entry = false;
  bool has_invalid_entry = false;
  for (const auto& entry : frame.entries) {
    const url::SchemeHostPort scheme_host_port(GURL(entry.origin));
    // |entry.origin| must be a valid SchemeHostPort.
    std::string serialized = scheme_host_port.Serialize();
    if (serialized.empty() || entry.origin != serialized) {
      has_invalid_entry = true;
      continue;
    }
    has_valid_entry = true;
    accept_ch_entries_received_via_alps_.emplace(std::move(scheme_host_port),
                                                 entry.value);

    net_log_.AddEvent(NetLogEventType::QUIC_ACCEPT_CH_FRAME_RECEIVED,
                      [&] { return NetLogAcceptChFrameReceivedParams(entry); });
  }
  LogAcceptChFrameReceivedHistogram(has_valid_entry, has_invalid_entry);
}

void QuicChromiumClientSession::OnOriginFrame(const quic::OriginFrame& frame) {
  if (!enable_origin_frame_) {
    return;
  }
  // The max size of an origin in ASCII serializaion can be 64kB. Choose a
  // relatively small limit on total number of received origins.
  static constexpr uint32_t kMaxOriginCount = 20;
  for (const std::string& origin_str : frame.origins) {
    if (received_origins_.size() >= kMaxOriginCount) {
      return;
    }
    GURL url(base::StrCat({origin_str, "/"}));
    if (!url.is_valid() || url.path() != "/") {
      continue;
    }
    url::SchemeHostPort origin(url);
    if (!origin.IsValid()) {
      continue;
    }
    received_origins_.insert(origin);
  }
  net_log_.AddEvent(NetLogEventType::QUIC_SESSION_ORIGIN_FRAME_RECEIVED,
                    [&] { return NetLogReceivedOrigins(received_origins_); });
  base::UmaHistogramCounts100("Net.QuicSession.NumReceivedOrigins",
                              received_origins_.size());
}

void QuicChromiumClientSession::AddHandle(Handle* handle) {
  if (going_away_) {
    handle->OnSessionClosed(connection()->version(), ERR_UNEXPECTED, error(),
                            source_, port_migration_detected_,
                            quic_connection_migration_attempted_,
                            quic_connection_migration_successful_,
                            GetConnectTiming(), WasConnectionEverUsed());
    return;
  }

  DCHECK(!base::Contains(handles_, handle));
  handles_.insert(handle);
}

void QuicChromiumClientSession::RemoveHandle(Handle* handle) {
  DCHECK(base::Contains(handles_, handle));
  handles_.erase(handle);
}

void QuicChromiumClientSession::AddConnectivityObserver(
    ConnectivityObserver* observer) {
  connectivity_observer_list_.AddObserver(observer);
  observer->OnSessionRegistered(this, GetCurrentNetwork());
}

void QuicChromiumClientSession::RemoveConnectivityObserver(
    ConnectivityObserver* observer) {
  connectivity_observer_list_.RemoveObserver(observer);
}

// TODO(zhongyi): replace migration_session_* booleans with
// ConnectionMigrationMode.
ConnectionMigrationMode QuicChromiumClientSession::connection_migration_mode()
    const {
  if (migrate_session_early_v2_) {
    return ConnectionMigrationMode::FULL_MIGRATION_V2;
  }

  if (migrate_session_on_network_change_v2_) {
    return ConnectionMigrationMode::NO_MIGRATION_ON_PATH_DEGRADING_V2;
  }

  return ConnectionMigrationMode::NO_MIGRATION;
}

int QuicChromiumClientSession::WaitForHandshakeConfirmation(
    CompletionOnceCallback callback) {
  if (!connection()->connected()) {
    return ERR_CONNECTION_CLOSED;
  }

  if (OneRttKeysAvailable()) {
    return OK;
  }

  waiting_for_confirmation_callbacks_.push_back(std::move(callback));
  return ERR_IO_PENDING;
}

int QuicChromiumClientSession::TryCreateStream(StreamRequest* request) {
  if (goaway_received()) {
    DVLOG(1) << "Going away.";
    return ERR_CONNECTION_CLOSED;
  }

  if (!connection()->connected()) {
    DVLOG(1) << "Already closed.";
    return ERR_CONNECTION_CLOSED;
  }

  if (going_away_) {
    return ERR_CONNECTION_CLOSED;
  }

  bool can_open_next = CanOpenNextOutgoingBidirectionalStream();
  if (can_open_next) {
    request->stream_ =
        CreateOutgoingReliableStreamImpl(request->traffic_annotation())
            ->CreateHandle();
    return OK;
  }

  // Calling CanOpenNextOutgoingBidirectionalStream() could close the
  // connection.
  if (!connection()->connected()) {
    return ERR_CONNECTION_CLOSED;
  }

  request->pending_start_time_ = tick_clock_->NowTicks();
  stream_requests_.push_back(request);
  UMA_HISTOGRAM_COUNTS_1000("Net.QuicSession.NumPendingStreamRequests",
                            stream_requests_.size());
  return ERR_IO_PENDING;
}

void QuicChromiumClientSession::CancelRequest(StreamRequest* request) {
  // Remove |request| from the queue while preserving the order of the
  // other elements.
  auto it = base::ranges::find(stream_requests_, request);
  if (it != stream_requests_.end()) {
    it = stream_requests_.erase(it);
  }
}

bool QuicChromiumClientSession::ShouldCreateOutgoingBidirectionalStream() {
  if (!crypto_stream_->encryption_established()) {
    DVLOG(1) << "Encryption not active so no outgoing stream created.";
    return false;
  }
  if (!CanOpenNextOutgoingBidirectionalStream()) {
    DVLOG(1) << "Failed to create a new outgoing stream. " << "Already "
             << GetNumActiveStreams() << " open.";
    return false;
  }
  if (goaway_received()) {
    DVLOG(1) << "Failed to create a new outgoing stream. "
             << "Already received goaway.";
    return false;
  }
  if (going_away_) {
    return false;
  }
  return true;
}

bool QuicChromiumClientSession::ShouldCreateOutgoingUnidirectionalStream() {
  NOTREACHED() << "Try to create outgoing unidirectional streams";
}

bool QuicChromiumClientSession::WasConnectionEverUsed() {
  const quic::QuicConnectionStats& stats = connection()->GetStats();
  return stats.bytes_sent > 0 || stats.bytes_received > 0;
}

QuicChromiumClientStream*
QuicChromiumClientSession::CreateOutgoingBidirectionalStream() {
  NOTREACHED() << "CreateOutgoingReliableStreamImpl should be called directly";
}

QuicChromiumClientStream*
QuicChromiumClientSession::CreateOutgoingUnidirectionalStream() {
  NOTREACHED() << "Try to create outgoing unidirectional stream";
}

QuicChromiumClientStream*
QuicChromiumClientSession::CreateOutgoingReliableStreamImpl(
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  DCHECK(connection()->connected());
  QuicChromiumClientStream* stream = new QuicChromiumClientStream(
      GetNextOutgoingBidirectionalStreamId(), this, server_id(),
      quic::BIDIRECTIONAL, net_log_, traffic_annotation);
  ActivateStream(base::WrapUnique(stream));
  ++num_total_streams_;
  UMA_HISTOGRAM_COUNTS_1M("Net.QuicSession.NumOpenStreams",
                          GetNumActiveStreams());
  // The previous histogram puts 100 in a bucket betweeen 86-113 which does
  // not shed light on if chrome ever things it has more than 100 streams open.
  UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.TooManyOpenStreams",
                        GetNumActiveStreams() > 100);
  return stream;
}

quic::QuicCryptoClientStream*
QuicChromiumClientSession::GetMutableCryptoStream() {
  return crypto_stream_.get();
}

const quic::QuicCryptoClientStream* QuicChromiumClientSession::GetCryptoStream()
    const {
  return crypto_stream_.get();
}

int QuicChromiumClientSession::GetRemoteEndpoint(IPEndPoint* endpoint) {
  *endpoint = ToIPEndPoint(peer_address());
  return OK;
}

// TODO(rtenneti): Add unittests for GetSSLInfo which exercise the various ways
// we learn about SSL info (sync vs async vs cached).
bool QuicChromiumClientSession::GetSSLInfo(SSLInfo* ssl_info) const {
  ssl_info->Reset();
  if (!cert_verify_result_) {
    return false;
  }

  ssl_info->cert_status = cert_verify_result_->cert_status;
  ssl_info->cert = cert_verify_result_->verified_cert;

  ssl_info->public_key_hashes = cert_verify_result_->public_key_hashes;
  ssl_info->is_issued_by_known_root =
      cert_verify_result_->is_issued_by_known_root;
  ssl_info->pkp_bypassed = pkp_bypassed_;

  ssl_info->client_cert_sent = false;
  ssl_info->handshake_type = SSLInfo::HANDSHAKE_FULL;
  ssl_info->is_fatal_cert_error = is_fatal_cert_error_;

  ssl_info->signed_certificate_timestamps = cert_verify_result_->scts;
  ssl_info->ct_policy_compliance = cert_verify_result_->policy_compliance;

  DCHECK(connection()->version().UsesTls());
  const auto& crypto_params = crypto_stream_->crypto_negotiated_params();
  uint16_t cipher_suite = crypto_params.cipher_suite;
  int ssl_connection_status = 0;
  SSLConnectionStatusSetCipherSuite(cipher_suite, &ssl_connection_status);
  SSLConnectionStatusSetVersion(SSL_CONNECTION_VERSION_QUIC,
                                &ssl_connection_status);
  ssl_info->connection_status = ssl_connection_status;

  ssl_info->key_exchange_group = crypto_params.key_exchange_group;
  ssl_info->peer_signature_algorithm = crypto_params.peer_signature_algorithm;
  ssl_info->encrypted_client_hello = crypto_params.encrypted_client_hello;
  return true;
}

std::string_view QuicChromiumClientSession::GetAcceptChViaAlps(
    const url::SchemeHostPort& scheme_host_port) const {
  auto it = accept_ch_entries_received_via_alps_.find(scheme_host_port);
  if (it == accept_ch_entries_received_via_alps_.end()) {
    LogAcceptChForOriginHistogram(false);
    return {};
  } else {
    LogAcceptChForOriginHistogram(true);
    return it->second;
  }
}

int QuicChromiumClientSession::CryptoConnect(CompletionOnceCallback callback) {
  connect_timing_.connect_start = tick_clock_->NowTicks();
  RecordHandshakeState(STATE_STARTED);
  DCHECK(flow_controller());

  if (!crypto_stream_->CryptoConnect()) {
    return ERR_QUIC_HANDSHAKE_FAILED;
  }

  if (OneRttKeysAvailable()) {
    connect_timing_.connect_end = tick_clock_->NowTicks();
    return OK;
  }

  // Unless we require handshake confirmation, activate the session if
  // we have established initial encryption.
  if (!require_confirmation_ && IsEncryptionEstablished()) {
    return OK;
  }

  callback_ = std::move(callback);
  return ERR_IO_PENDING;
}

int QuicChromiumClientSession::GetNumSentClientHellos() const {
  return crypto_stream_->num_sent_client_hellos();
}

bool QuicChromiumClientSession::CanPool(
    std::string_view hostname,
    const QuicSessionKey& other_session_key) const {
  DCHECK(connection()->connected());
  if (!session_key_.CanUseForAliasing(other_session_key)) {
    return false;
  }
  SSLInfo ssl_info;
  if (!GetSSLInfo(&ssl_info) || !ssl_info.cert.get()) {
    NOTREACHED() << "QUIC should always have certificates.";
  }

  return SpdySession::CanPool(transport_security_state_, ssl_info,
                              *ssl_config_service_, session_key_.host(),
                              hostname);
}

bool QuicChromiumClientSession::ShouldCreateIncomingStream(
    quic::QuicStreamId id) {
  if (!connection()->connected()) {
    LOG(DFATAL) << "ShouldCreateIncomingStream called when disconnected";
    return false;
  }
  if (goaway_received()) {
    DVLOG(1) << "Cannot create a new outgoing stream. "
             << "Already received goaway.";
    return false;
  }
  if (going_away_) {
    return false;
  }
  if (quic::QuicUtils::IsClientInitiatedStreamId(
          connection()->transport_version(), id) ||
      quic::QuicUtils::IsBidirectionalStreamId(id, connection()->version())) {
    LOG(WARNING) << "Received invalid push stream id " << id;
    connection()->CloseConnection(
        quic::QUIC_INVALID_STREAM_ID,
        "Server created non write unidirectional stream",
        quic::ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }
  return true;
}

QuicChromiumClientStream* QuicChromiumClientSession::CreateIncomingStream(
    quic::QuicStreamId id) {
  if (!ShouldCreateIncomingStream(id)) {
    return nullptr;
  }
  net::NetworkTrafficAnnotationTag traffic_annotation =
      net::DefineNetworkTrafficAnnotation("quic_chromium_incoming_session", R"(
      semantics {
        sender: "Quic Chromium Client Session"
        description:
          "When a web server needs to push a response to a client, an incoming "
          "stream is created to reply the client with pushed message instead "
          "of a message from the network."
        trigger:
          "A request by a server to push a response to the client."
        data: "None."
        destination: OTHER
        destination_other:
          "This stream is not used for sending data."
      }
      policy {
        cookies_allowed: NO
        setting: "This feature cannot be disabled in settings."
        policy_exception_justification:
          "Essential for network access."
      }
  )");
  return CreateIncomingReliableStreamImpl(id, traffic_annotation);
}

QuicChromiumClientStream* QuicChromiumClientSession::CreateIncomingStream(
    quic::PendingStream* pending) {
  net::NetworkTrafficAnnotationTag traffic_annotation =
      net::DefineNetworkTrafficAnnotation(
          "quic_chromium_incoming_pending_session", R"(
      semantics {
        sender: "Quic Chromium Client Session Pending Stream"
        description:
          "When a web server needs to push a response to a client, an incoming "
          "stream is created to reply to the client with pushed message instead "
          "of a message from the network."
        trigger:
          "A request by a server to push a response to the client."
        data: "This stream is only used to receive data from the server."
        destination: OTHER
        destination_other:
          "The web server pushing the response."
      }
      policy {
        cookies_allowed: NO
        setting: "This feature cannot be disabled in settings."
        policy_exception_justification:
          "Essential for network access."
      }
  )");
  return CreateIncomingReliableStreamImpl(pending, traffic_annotation);
}

QuicChromiumClientStream*
QuicChromiumClientSession::CreateIncomingReliableStreamImpl(
    quic::QuicStreamId id,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  DCHECK(connection()->connected());

  QuicChromiumClientStream* stream = new QuicChromiumClientStream(
      id, this, server_id(), quic::READ_UNIDIRECTIONAL, net_log_,
      traffic_annotation);
  ActivateStream(base::WrapUnique(stream));
  ++num_total_streams_;
  return stream;
}

QuicChromiumClientStream*
QuicChromiumClientSession::CreateIncomingReliableStreamImpl(
    quic::PendingStream* pending,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  DCHECK(connection()->connected());

  QuicChromiumClientStream* stream = new QuicChromiumClientStream(
      pending, this, server_id(), net_log_, traffic_annotation);
  ActivateStream(base::WrapUnique(stream));
  ++num_total_streams_;
  return stream;
}

void QuicChromiumClientSession::OnStreamClosed(quic::QuicStreamId stream_id) {
  most_recent_stream_close_time_ = tick_clock_->NowTicks();
  quic::QuicStream* stream = GetActiveStream(stream_id);
  if (stream != nullptr) {
    logger_->UpdateReceivedFrameCounts(stream_id, stream->num_frames_received(),
                                       stream->num_duplicate_frames_received());
  }
  quic::QuicSpdyClientSessionBase::OnStreamClosed(stream_id);
}

void QuicChromiumClientSession::OnCanCreateNewOutgoingStream(
    bool unidirectional) {
  while (CanOpenNextOutgoingBidirectionalStream() &&
         !stream_requests_.empty() &&
         crypto_stream_->encryption_established() && !goaway_received() &&
         !going_away_ && connection()->connected()) {
    StreamRequest* request = stream_requests_.front();
    // TODO(ckrasic) - analyze data and then add logic to mark QUIC
    // broken if wait times are excessive.
    UMA_HISTOGRAM_TIMES("Net.QuicSession.PendingStreamsWaitTime",
                        tick_clock_->NowTicks() - request->pending_start_time_);
    stream_requests_.pop_front();

#if BUILDFLAG(ENABLE_WEBSOCKETS)
    if (request->for_websockets_) {
      std::unique_ptr<WebSocketQuicStreamAdapter> adapter =
          CreateWebSocketQuicStreamAdapterImpl(
              request->websocket_adapter_delegate_);
      request->websocket_adapter_delegate_ = nullptr;
      std::move(request->start_websocket_callback_).Run(std::move(adapter));
      continue;
    }
#endif  // BUILDFLAG(ENABLE_WEBSOCKETS)

    request->OnRequestCompleteSuccess(
        CreateOutgoingReliableStreamImpl(request->traffic_annotation())
            ->CreateHandle());
  }
}

quic::QuicSSLConfig QuicChromiumClientSession::GetSSLConfig() const {
  quic::QuicSSLConfig config = quic::QuicSpdyClientSessionBase::GetSSLConfig();
  if (ssl_config_service_->GetSSLContextConfig().ech_enabled) {
    config.ech_grease_enabled = true;
    config.ech_config_list.assign(ech_config_list_.begin(),
                                  ech_config_list_.end());
  }
  return config;
}

void QuicChromiumClientSession::SetDefaultEncryptionLevel(
    quic::EncryptionLevel level) {
  if (!callback_.is_null() &&
      (!require_confirmation_ || level == quic::ENCRYPTION_FORWARD_SECURE ||
       level == quic::ENCRYPTION_ZERO_RTT)) {
    // Currently for all CryptoHandshakeEvent events, callback_
    // could be called because there are no error events in CryptoHandshakeEvent
    // enum. If error events are added to CryptoHandshakeEvent, then the
    // following code needs to changed.
    std::move(callback_).Run(OK);
  }
  if (level == quic::ENCRYPTION_FORWARD_SECURE) {
    OnCryptoHandshakeComplete();
    LogZeroRttStats();
  }
  if (level == quic::ENCRYPTION_ZERO_RTT) {
    attempted_zero_rtt_ = true;
  }
  quic::QuicSpdySession::SetDefaultEncryptionLevel(level);
}

void QuicChromiumClientSession::OnTlsHandshakeComplete() {
  if (!callback_.is_null()) {
    // Currently for all CryptoHandshakeEvent events, callback_
    // could be called because there are no error events in CryptoHandshakeEvent
    // enum. If error events are added to CryptoHandshakeEvent, then the
    // following code needs to changed.
    std::move(callback_).Run(OK);
  }

  OnCryptoHandshakeComplete();
  LogZeroRttStats();
  quic::QuicSpdySession::OnTlsHandshakeComplete();
}

void QuicChromiumClientSession::OnNewEncryptionKeyAvailable(
    quic::EncryptionLevel level,
    std::unique_ptr<quic::QuicEncrypter> encrypter) {
  if (!attempted_zero_rtt_ && (level == quic::ENCRYPTION_ZERO_RTT ||
                               level == quic::ENCRYPTION_FORWARD_SECURE)) {
    base::TimeTicks now = tick_clock_->NowTicks();
    DCHECK_LE(connect_timing_.connect_start, now);
    UMA_HISTOGRAM_TIMES("Net.QuicSession.EncryptionEstablishedTime",
                        now - connect_timing_.connect_start);
  }
  if (level == quic::ENCRYPTION_ZERO_RTT) {
    attempted_zero_rtt_ = true;
  }
  QuicSpdySession::OnNewEncryptionKeyAvailable(level, std::move(encrypter));

  if (!callback_.is_null() &&
      (!require_confirmation_ && level == quic::ENCRYPTION_ZERO_RTT)) {
    // Currently for all CryptoHandshakeEvent events, callback_
    // could be called because there are no error events in CryptoHandshakeEvent
    // enum. If error events are added to CryptoHandshakeEvent, then the
    // following code needs to changed.
    std::move(callback_).Run(OK);
  }
}

void QuicChromiumClientSession::LogZeroRttStats() {
  DCHECK(OneRttKeysAvailable());

  ZeroRttState state;

  ssl_early_data_reason_t early_data_reason = crypto_stream_->EarlyDataReason();
  if (early_data_reason == ssl_early_data_accepted) {
    state = ZeroRttState::kAttemptedAndSucceeded;
  } else if (early_data_reason == ssl_early_data_peer_declined ||
             early_data_reason == ssl_early_data_session_not_resumed ||
             early_data_reason == ssl_early_data_hello_retry_request) {
    state = ZeroRttState::kAttemptedAndRejected;
  } else {
    state = ZeroRttState::kNotAttempted;
  }
  UMA_HISTOGRAM_ENUMERATION("Net.QuicSession.ZeroRttState", state);
  UMA_HISTOGRAM_ENUMERATION("Net.QuicSession.ZeroRttReason", early_data_reason,
                            ssl_early_data_reason_max_value + 1);
  if (IsGoogleHost(session_key_.host())) {
    UMA_HISTOGRAM_ENUMERATION("Net.QuicSession.ZeroRttReasonGoogle",
                              early_data_reason,
                              ssl_early_data_reason_max_value + 1);
  } else {
    UMA_HISTOGRAM_ENUMERATION("Net.QuicSession.ZeroRttReasonNonGoogle",
                              early_data_reason,
                              ssl_early_data_reason_max_value + 1);
  }
}

void QuicChromiumClientSession::OnCryptoHandshakeMessageSent(
    const quic::CryptoHandshakeMessage& message) {
  logger_->OnCryptoHandshakeMessageSent(message);
}

void QuicChromiumClientSession::OnCryptoHandshakeMessageReceived(
    const quic::CryptoHandshakeMessage& message) {
  logger_->OnCryptoHandshakeMessageReceived(message);
  if (message.tag() == quic::kREJ) {
    UMA_HISTOGRAM_CUSTOM_COUNTS("Net.QuicSession.RejectLength",
                                message.GetSerialized().length(), 1000, 10000,
                                50);
    std::string_view proof;
    UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.RejectHasProof",
                          message.GetStringPiece(quic::kPROF, &proof));
  }
}

void QuicChromiumClientSession::OnGoAway(const quic::QuicGoAwayFrame& frame) {
  quic::QuicSession::OnGoAway(frame);
  NotifyFactoryOfSessionGoingAway();
  port_migration_detected_ =
      frame.error_code == quic::QUIC_ERROR_MIGRATING_PORT;
}

void QuicChromiumClientSession::OnConnectionClosed(
    const quic::QuicConnectionCloseFrame& frame,
    quic::ConnectionCloseSource source) {
  DCHECK(!connection()->connected());
  logger_->OnConnectionClosed(frame, source);
  source_ = source;

  UMA_HISTOGRAM_COUNTS_1000("Net.QuicSession.NumDefaultPathDegrading",
                            connection()->GetStats().num_path_degrading);
  if (connection()->GetStats().num_path_degrading > 0)
```