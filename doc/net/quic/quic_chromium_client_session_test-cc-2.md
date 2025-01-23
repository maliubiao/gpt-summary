Response:
The user wants a summary of the functionality of the provided C++ code snippet from `net/quic/quic_chromium_client_session_test.cc`. I need to analyze the code and identify the main features being tested. The user also asked for connections to Javascript, logical reasoning examples, common user errors, and debugging information.

**Plan:**

1. **Identify the core functionality being tested in each `TEST_P` block.**  These tests are the primary way the code demonstrates its functionality.
2. **Look for keywords and patterns related to network operations, QUIC protocol, client sessions, and testing.**
3. **Determine if any functionality has a direct link to Javascript.**  This is less likely in a low-level networking test file.
4. **Identify instances of logical reasoning and create hypothetical inputs/outputs.** This will likely involve the expected behavior of network interactions.
5. **Infer potential user or programming errors that the tests are designed to prevent.**
6. **Describe how a user might trigger the execution of this code in a Chromium browser (for debugging context).**
7. **Summarize the identified functionalities as requested.**
这是 Chromium 网络栈中 `net/quic/quic_chromium_client_session_test.cc` 文件的一部分，主要功能是 **测试 `QuicChromiumClientSession` 类的各种行为和功能**。 `QuicChromiumClientSession` 是 Chromium 中处理 QUIC 客户端会话的核心类。

以下是这段代码中测试功能的归纳：

*   **会话池化 (CanPool):** 测试在特定条件下，新的连接是否可以复用现有的会话（连接池化）。它检查了主机名、端口、隐私模式、代理链、会话用途、SocketTag、网络匿名化密钥和安全 DNS 策略等因素对池化的影响。
*   **迁移到新 Socket (MigrateToSocket):** 测试将现有的 QUIC 会话迁移到新的底层网络 Socket 的功能。这通常发生在网络地址发生变化时，例如 Wi-Fi 和移动网络切换。测试验证了迁移过程的正确性，包括数据传输和连接 ID 的更新。
*   **迁移到新 Socket (最大读取器限制):** 测试了在尝试迁移会话到新 Socket 时，对最大并发读取器数量的限制。 这旨在防止资源耗尽。
*   **迁移到新 Socket (读取错误处理):** 测试了在迁移到新 Socket 的过程中，旧 Socket 或新 Socket 上发生读取错误时的会话行为。它验证了会话是否能够正确处理这些错误并保持连接或关闭连接。
*   **重传（OnWireTimeout）:** 测试在没有待处理数据但有打开的流时，连接是否会定期发送 PING 帧以保持连接活跃，并在超时后进行重传。
*   **处理空的响应头 (ResetOnEmptyResponseHeaders):** 测试当服务器发送空的响应头时，客户端会话是否会正确地重置流并处理错误。这是一种防止某些协议错误或恶意行为的机制。
*   **连接性监控 (ConnectivityMonitor) 集成：**
    *   测试在没有网络句柄 (handles::NetworkHandle) 支持的情况下，会话如何向 `QuicConnectivityMonitor` 报告路径退化和恢复。
    *   测试在启用多端口功能的情况下，路径退化不会触发端口迁移。
    *   测试在没有网络句柄支持的情况下，通过 IP 地址变化报告的网络变化如何影响路径退化和恢复的报告。
    *   测试在支持网络句柄但不进行迁移的情况下，会话如何向 `QuicConnectivityMonitor` 报告路径退化和恢复。
    *   测试在支持网络句柄但不进行迁移的情况下，发生默认网络变化时，会话如何向 `QuicConnectivityMonitor` 报告路径退化和恢复。
*   **连接建立期间的写入错误处理 (WriteErrorDuringCryptoConnect):** 测试在 QUIC 握手阶段发生网络写入错误时，会话如何处理并向 `QuicConnectivityMonitor` 报告错误。
*   **握手完成后的写入错误处理 (WriteErrorAfterHandshakeConfirmed):** 测试在 QUIC 握手完成后发生网络写入错误时，会话如何处理并向 `QuicConnectivityMonitor` 报告错误，并考虑了网络变化的因素。
*   **ECN 标记报告 (ReportsReceivedEcn):** 测试客户端是否正确地报告接收到的带有 ECN (Explicit Congestion Notification) 标记的数据包。
*   **处理 ORIGIN 帧 (OnOriginFrame):** 测试客户端如何处理服务器发送的 ORIGIN 帧，该帧用于声明服务器支持哪些源。

**与 Javascript 的关系：**

这段 C++ 代码本身不直接与 Javascript 代码交互。然而，它所测试的功能是网络栈的核心部分，直接影响着 Chromium 浏览器中所有基于 QUIC 协议的网络请求。当 Javascript 代码发起一个网络请求时，如果使用了 QUIC 协议，那么最终会涉及到 `QuicChromiumClientSession` 的使用。

**举例说明：**

假设一个 Javascript 应用程序使用 `fetch` API 向一个支持 QUIC 的服务器发起 HTTPS 请求：

```javascript
fetch('https://www.example.org/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

1. 当浏览器解析这个请求时，会检查是否可以使用现有的 QUIC 连接。`TEST_P(QuicChromiumClientSessionTest, CanPool)` 中测试的逻辑就决定了是否可以复用之前的连接。
2. 如果需要建立新的 QUIC 连接，`QuicChromiumClientSession` 会被创建并进行握手。`TEST_P(QuicChromiumClientSessionTest, WriteErrorDuringCryptoConnect)` 测试了握手期间可能发生的错误处理。
3. 如果用户在请求过程中切换了网络（例如从 Wi-Fi 切换到移动网络），`TEST_P(QuicChromiumClientSessionTest, MigrateToSocket)` 测试的会话迁移功能就会被触发，保证连接的持续性。
4. 如果服务器发送了空的响应头，`TEST_P(QuicChromiumClientSessionTest, ResetOnEmptyResponseHeaders)` 测试的逻辑会确保客户端能够正确处理这种情况，避免应用程序出现未定义的行为。

**逻辑推理与假设输入输出：**

**例子 1: `TEST_P(QuicChromiumClientSessionTest, CanPool)`**

*   **假设输入:**
    *   现有会话连接到 `www.example.org:443`。
    *   新的请求目标是 `mail.example.org:443`。
    *   其他参数（隐私模式、代理等）保持一致。
*   **逻辑推理:**  代码中 `EXPECT_TRUE(session_->CanPool(...))` 预期在主机名不同的情况下，即使其他参数相同，也不能进行池化。
*   **预期输出:**  `CanPool` 方法返回 `false`。

**例子 2: `TEST_P(QuicChromiumClientSessionTest, MigrateToSocket)`**

*   **假设输入:**
    *   QUIC 会话正在通过一个 Socket 连接进行通信。
    *   操作系统报告网络地址变化。
    *   创建了一个新的 Socket 连接。
*   **逻辑推理:** 代码模拟了服务器发送 `NEW_CONNECTION_ID` 帧，然后客户端使用新的连接 ID 和新的 Socket 进行通信。
*   **预期输出:**  会话成功迁移到新的 Socket，并且可以通过新的 Socket 发送和接收数据。

**用户或编程常见的使用错误：**

*   **不正确地配置会话参数导致无法池化:** 开发者可能错误地设置了某些会话参数（例如，强制禁用连接池化），导致即使在可以复用连接的情况下也建立了新的连接，降低了性能。
*   **没有处理网络变化导致连接中断:**  如果应用程序没有考虑到网络变化的可能性，并且 QUIC 会话没有成功迁移到新的网络，那么用户的网络请求可能会失败。
*   **服务器实现不符合 QUIC 标准:**  例如，服务器可能错误地发送了空的响应头，而客户端需要能够正确处理这种情况，防止应用程序崩溃。
*   **在多连接场景下没有正确管理会话:**  如果应用程序同时打开了过多的 QUIC 连接而没有进行合理的管理，可能会导致资源消耗过高。

**用户操作到达此处的调试线索：**

1. **用户发起一个 HTTPS 请求到支持 QUIC 的网站:** 这是最常见的入口点。浏览器会尝试使用 QUIC 协议建立连接。
2. **用户在浏览过程中网络发生变化:** 例如，从家庭 Wi-Fi 切换到移动数据网络，或者连接到不同的 Wi-Fi 热点。 这会触发连接迁移的逻辑，相关的代码就会被执行。
3. **用户访问的网站发送了不符合 QUIC 规范的响应:**  例如，发送了空的响应头。这会触发客户端的错误处理逻辑。
4. **开发者在 Chromium 浏览器中启用 QUIC 协议的调试日志:**  开发者可以通过 Chrome 的内部标志或者命令行参数启用 QUIC 相关的日志，以便跟踪 QUIC 连接的建立、数据传输和错误处理过程。当出现问题时，这些日志可以提供线索，指向 `QuicChromiumClientSession` 类的相关代码。
5. **开发者使用网络抓包工具 (例如 Wireshark):**  抓包工具可以捕获 QUIC 连接的底层数据包，帮助开发者分析网络通信的细节，例如连接 ID 的变化、数据包的重传、以及错误帧的发送。
6. **开发者进行 Chromium 浏览器的网络栈源码调试:**  开发者可以直接在 Chromium 的源代码中设置断点，例如在 `QuicChromiumClientSession` 的方法中，以便深入了解代码的执行流程和变量状态。

**总结 (第 3 部分功能归纳):**

这部分代码主要集中在 **测试 `QuicChromiumClientSession` 在连接迁移、错误处理（包括空的响应头和网络写入错误）、连接保持活跃（通过 PING 帧）、以及与连接性监控模块集成方面的功能**。此外，它还测试了客户端对服务器发送的 ORIGIN 帧的处理，以及对接收到的 ECN 标记的报告。这些测试确保了 QUIC 客户端会话在各种网络条件和服务器行为下都能稳定可靠地工作。

### 提示词
```
这是目录为net/quic/quic_chromium_client_session_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
ity_state_source;

  MockQuicData quic_data(version_);
  quic_data.AddWrite(SYNCHRONOUS, client_maker_.MakeInitialSettingsPacket(1));
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);
  Initialize();

  transport_security_state_->EnableStaticPinsForTesting();

  ProofVerifyDetailsChromium details;
  details.cert_verify_result.verified_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  details.cert_verify_result.is_issued_by_known_root = true;
  HashValue primary_pin(HASH_VALUE_SHA256);
  EXPECT_TRUE(primary_pin.FromString(
      "sha256/Nn8jk5By4Vkq6BeOVZ7R7AC6XUUBZsWmUbJR1f1Y5FY="));
  details.cert_verify_result.public_key_hashes.push_back(primary_pin);

  ASSERT_TRUE(details.cert_verify_result.verified_cert.get());

  CompleteCryptoHandshake();
  session_->OnProofVerifyDetailsAvailable(details);
  QuicChromiumClientSessionPeer::SetHostname(session_.get(), "www.example.org");

  EXPECT_TRUE(session_->CanPool(
      "mail.example.org",
      QuicSessionKey("foo", 1234, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                     SessionUsage::kDestination, SocketTag(),
                     NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                     /*require_dns_https_alpn=*/false)));
}

TEST_P(QuicChromiumClientSessionTest, MigrateToSocket) {
  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(12345678);
  MockQuicData quic_data(version_);
  int packet_num = 1;
  int peer_packet_num = 1;
  socket_data_.reset();
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddWrite(ASYNC,
                     client_maker_.MakeInitialSettingsPacket(packet_num++));
  quic_data.AddRead(ASYNC, server_maker_.Packet(peer_packet_num++)
                               .AddNewConnectionIdFrame(cid_on_new_path,
                                                        /*sequence_number=*/1u,
                                                        /*retire_prior_to=*/0u)
                               .Build());
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);
  Initialize();
  CompleteCryptoHandshake();

  // Make new connection ID available after handshake completion.
  quic_data.Resume();
  base::RunLoop().RunUntilIdle();

  char data[] = "ABCD";
  MockQuicData quic_data2(version_);
  client_maker_.set_connection_id(cid_on_new_path);
  quic_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  quic_data2.AddWrite(SYNCHRONOUS,
                      client_maker_.Packet(packet_num++)
                          .AddAckFrame(/*first_received=*/1,
                                       /*largest_received=*/peer_packet_num - 1,
                                       /*smallest_received=*/1)
                          .AddPingFrame()
                          .Build());
  quic_data2.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_num++)
          .AddStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0), false,
                          std::string_view(data))
          .Build());
  quic_data2.AddSocketDataToFactory(&socket_factory_);
  // Create connected socket.
  std::unique_ptr<DatagramClientSocket> new_socket =
      socket_factory_.CreateDatagramClientSocket(DatagramSocket::RANDOM_BIND,
                                                 NetLog::Get(), NetLogSource());
  EXPECT_THAT(new_socket->Connect(kIpEndPoint), IsOk());

  // Create reader and writer.
  auto new_reader = std::make_unique<QuicChromiumPacketReader>(
      std::move(new_socket), &clock_, session_.get(),
      kQuicYieldAfterPacketsRead,
      quic::QuicTime::Delta::FromMilliseconds(
          kQuicYieldAfterDurationMilliseconds),
      /*report_ecn=*/true, net_log_with_source_);
  new_reader->StartReading();
  std::unique_ptr<QuicChromiumPacketWriter> new_writer(
      CreateQuicChromiumPacketWriter(new_reader->socket(), session_.get()));

  IPEndPoint local_address;
  new_reader->socket()->GetLocalAddress(&local_address);
  IPEndPoint peer_address;
  new_reader->socket()->GetPeerAddress(&peer_address);
  // Migrate session.
  EXPECT_TRUE(session_->MigrateToSocket(
      ToQuicSocketAddress(local_address), ToQuicSocketAddress(peer_address),
      std::move(new_reader), std::move(new_writer)));
  // Spin message loop to complete migration.
  base::RunLoop().RunUntilIdle();

  // Write data to session.
  QuicChromiumClientStream* stream =
      QuicChromiumClientSessionPeer::CreateOutgoingStream(session_.get());
  quic::test::QuicStreamPeer::SendBuffer(stream).SaveStreamData(data);
  quic::test::QuicStreamPeer::SetStreamBytesWritten(4, stream);
  session_->WritevData(stream->id(), 4, 0, quic::NO_FIN,
                       quic::NOT_RETRANSMISSION,
                       quic::ENCRYPTION_FORWARD_SECURE);

  EXPECT_TRUE(quic_data2.AllReadDataConsumed());
  EXPECT_TRUE(quic_data2.AllWriteDataConsumed());
}

TEST_P(QuicChromiumClientSessionTest, MigrateToSocketMaxReaders) {
  MockQuicData quic_data(version_);
  socket_data_.reset();
  int packet_num = 1;
  int peer_packet_num = 1;
  quic::QuicConnectionId next_cid = quic::QuicUtils::CreateRandomConnectionId(
      quiche::QuicheRandom::GetInstance());
  uint64_t next_cid_sequence_number = 1u;
  quic_data.AddWrite(SYNCHRONOUS,
                     client_maker_.MakeInitialSettingsPacket(packet_num++));
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC,
                    server_maker_.Packet(peer_packet_num++)
                        .AddNewConnectionIdFrame(
                            next_cid, next_cid_sequence_number,
                            /*retire_prior_to=*/next_cid_sequence_number - 1)
                        .Build());
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);
  Initialize();
  CompleteCryptoHandshake();

  // Make connection ID available for the first migration.
  quic_data.Resume();

  /* Migration succeeds when maximum number of readers is not reached.*/
  for (size_t i = 0; i < kMaxReadersPerQuicSession - 1; ++i) {
    MockQuicData quic_data2(version_);
    client_maker_.set_connection_id(next_cid);
    quic_data2.AddWrite(
        SYNCHRONOUS, client_maker_.Packet(packet_num++)
                         .AddAckFrame(/*first_received=*/1,
                                      /*largest_received=*/peer_packet_num - 1,
                                      /*smallest_received=*/1)
                         .AddPingFrame()
                         .Build());
    quic_data2.AddRead(ASYNC, ERR_IO_PENDING);
    quic_data2.AddWrite(
        ASYNC, client_maker_.Packet(packet_num++)
                   .AddRetireConnectionIdFrame(
                       /*sequence_number=*/next_cid_sequence_number - 1)
                   .Build());
    next_cid = quic::QuicUtils::CreateRandomConnectionId(
        quiche::QuicheRandom::GetInstance());
    ++next_cid_sequence_number;
    quic_data2.AddRead(ASYNC,
                       server_maker_.Packet(peer_packet_num++)
                           .AddNewConnectionIdFrame(
                               next_cid, next_cid_sequence_number,
                               /*retire_prior_to=*/next_cid_sequence_number - 1)
                           .Build());
    quic_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // Hanging read.
    quic_data2.AddSocketDataToFactory(&socket_factory_);

    // Create connected socket.
    std::unique_ptr<DatagramClientSocket> new_socket =
        socket_factory_.CreateDatagramClientSocket(
            DatagramSocket::RANDOM_BIND, NetLog::Get(), NetLogSource());
    EXPECT_THAT(new_socket->Connect(kIpEndPoint), IsOk());

    // Create reader and writer.
    auto new_reader = std::make_unique<QuicChromiumPacketReader>(
        std::move(new_socket), &clock_, session_.get(),
        kQuicYieldAfterPacketsRead,
        quic::QuicTime::Delta::FromMilliseconds(
            kQuicYieldAfterDurationMilliseconds),
        /*report_ecn=*/true, net_log_with_source_);
    new_reader->StartReading();
    std::unique_ptr<QuicChromiumPacketWriter> new_writer(
        CreateQuicChromiumPacketWriter(new_reader->socket(), session_.get()));

    IPEndPoint local_address;
    new_reader->socket()->GetLocalAddress(&local_address);
    IPEndPoint peer_address;
    new_reader->socket()->GetPeerAddress(&peer_address);
    // Migrate session.
    EXPECT_TRUE(session_->MigrateToSocket(
        ToQuicSocketAddress(local_address), ToQuicSocketAddress(peer_address),
        std::move(new_reader), std::move(new_writer)));
    // Spin message loop to complete migration.
    base::RunLoop().RunUntilIdle();
    alarm_factory_.FireAlarm(
        quic::test::QuicConnectionPeer::GetRetirePeerIssuedConnectionIdAlarm(
            session_->connection()));
    // Make new connection ID available for subsequent migration.
    quic_data2.Resume();
    base::RunLoop().RunUntilIdle();
    EXPECT_TRUE(quic_data2.AllReadDataConsumed());
    EXPECT_TRUE(quic_data2.AllWriteDataConsumed());
  }

  /* Migration fails when maximum number of readers is reached.*/
  MockQuicData quic_data2(version_);
  quic_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // Hanging read.
  quic_data2.AddSocketDataToFactory(&socket_factory_);
  // Create connected socket.
  std::unique_ptr<DatagramClientSocket> new_socket =
      socket_factory_.CreateDatagramClientSocket(DatagramSocket::RANDOM_BIND,
                                                 NetLog::Get(), NetLogSource());
  EXPECT_THAT(new_socket->Connect(kIpEndPoint), IsOk());

  // Create reader and writer.
  auto new_reader = std::make_unique<QuicChromiumPacketReader>(
      std::move(new_socket), &clock_, session_.get(),
      kQuicYieldAfterPacketsRead,
      quic::QuicTime::Delta::FromMilliseconds(
          kQuicYieldAfterDurationMilliseconds),
      /*report_ecn=*/true, net_log_with_source_);
  new_reader->StartReading();
  std::unique_ptr<QuicChromiumPacketWriter> new_writer(
      CreateQuicChromiumPacketWriter(new_reader->socket(), session_.get()));

  IPEndPoint local_address;
  new_reader->socket()->GetLocalAddress(&local_address);
  IPEndPoint peer_address;
  new_reader->socket()->GetPeerAddress(&peer_address);
  EXPECT_FALSE(session_->MigrateToSocket(
      ToQuicSocketAddress(local_address), ToQuicSocketAddress(peer_address),
      std::move(new_reader), std::move(new_writer)));
  EXPECT_TRUE(quic_data2.AllReadDataConsumed());
  EXPECT_TRUE(quic_data2.AllWriteDataConsumed());
}

TEST_P(QuicChromiumClientSessionTest, MigrateToSocketReadError) {
  MockQuicData quic_data(version_);
  socket_data_.reset();
  int packet_num = 1;
  int peer_packet_num = 1;

  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(12345678);
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddWrite(ASYNC,
                     client_maker_.MakeInitialSettingsPacket(packet_num++));
  quic_data.AddRead(ASYNC, server_maker_.Packet(peer_packet_num++)
                               .AddNewConnectionIdFrame(cid_on_new_path,
                                                        /*sequence_number=*/1u,
                                                        /*retire_prior_to=*/0u)
                               .Build());
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_NETWORK_CHANGED);

  quic_data.AddSocketDataToFactory(&socket_factory_);
  Initialize();
  CompleteCryptoHandshake();

  // Make new connection ID available after handshake completion.
  quic_data.Resume();
  base::RunLoop().RunUntilIdle();

  MockQuicData quic_data2(version_);
  client_maker_.set_connection_id(cid_on_new_path);
  quic_data2.AddWrite(SYNCHRONOUS,
                      client_maker_.Packet(packet_num++)
                          .AddAckFrame(/*first_received=*/1,
                                       /*largest_received=*/peer_packet_num - 1,
                                       /*smallest_received=*/1)
                          .AddPingFrame()
                          .Build());
  quic_data2.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data2.AddRead(ASYNC, server_maker_.Packet(1).AddPingFrame().Build());
  quic_data2.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data2.AddRead(ASYNC, ERR_NETWORK_CHANGED);
  quic_data2.AddSocketDataToFactory(&socket_factory_);

  // Create connected socket.
  std::unique_ptr<DatagramClientSocket> new_socket =
      socket_factory_.CreateDatagramClientSocket(DatagramSocket::RANDOM_BIND,
                                                 NetLog::Get(), NetLogSource());
  EXPECT_THAT(new_socket->Connect(kIpEndPoint), IsOk());

  // Create reader and writer.
  auto new_reader = std::make_unique<QuicChromiumPacketReader>(
      std::move(new_socket), &clock_, session_.get(),
      kQuicYieldAfterPacketsRead,
      quic::QuicTime::Delta::FromMilliseconds(
          kQuicYieldAfterDurationMilliseconds),
      /*report_ecn=*/true, net_log_with_source_);
  new_reader->StartReading();
  std::unique_ptr<QuicChromiumPacketWriter> new_writer(
      CreateQuicChromiumPacketWriter(new_reader->socket(), session_.get()));

  IPEndPoint local_address;
  new_reader->socket()->GetLocalAddress(&local_address);
  IPEndPoint peer_address;
  new_reader->socket()->GetPeerAddress(&peer_address);
  // Store old socket and migrate session.
  EXPECT_TRUE(session_->MigrateToSocket(
      ToQuicSocketAddress(local_address), ToQuicSocketAddress(peer_address),
      std::move(new_reader), std::move(new_writer)));
  // Spin message loop to complete migration.
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(
      quic::test::QuicConnectionPeer::GetRetirePeerIssuedConnectionIdAlarm(
          session_->connection())
          ->IsSet());

  // Read error on old socket does not impact session.
  quic_data.Resume();
  EXPECT_TRUE(session_->connection()->connected());
  quic_data2.Resume();

  // Read error on new socket causes session close.
  EXPECT_TRUE(session_->connection()->connected());
  quic_data2.Resume();
  EXPECT_FALSE(session_->connection()->connected());

  EXPECT_TRUE(quic_data.AllReadDataConsumed());
  EXPECT_TRUE(quic_data.AllWriteDataConsumed());
  EXPECT_TRUE(quic_data2.AllReadDataConsumed());
  EXPECT_TRUE(quic_data2.AllWriteDataConsumed());
}

TEST_P(QuicChromiumClientSessionTest, RetransmittableOnWireTimeout) {
  migrate_session_early_v2_ = true;

  MockQuicData quic_data(version_);
  int packet_num = 1;
  quic_data.AddWrite(SYNCHRONOUS,
                     client_maker_.MakeInitialSettingsPacket(packet_num++));
  quic_data.AddWrite(SYNCHRONOUS,
                     client_maker_.Packet(packet_num++).AddPingFrame().Build());

  quic_data.AddRead(
      ASYNC, server_maker_.Packet(1).AddAckFrame(1, packet_num - 1, 1).Build());

  quic_data.AddWrite(SYNCHRONOUS,
                     client_maker_.Packet(packet_num++).AddPingFrame().Build());
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  Initialize();
  CompleteCryptoHandshake();

  // Open a stream since the connection only sends PINGs to keep a
  // retransmittable packet on the wire if there's an open stream.
  EXPECT_TRUE(
      QuicChromiumClientSessionPeer::CreateOutgoingStream(session_.get()));

  quic::test::QuicTestAlarmProxy alarm(
      quic::test::QuicConnectionPeer::GetPingAlarm(session_->connection()));
  EXPECT_FALSE(alarm.IsSet());

  // Send PING, which will be ACKed by the server. After the ACK, there will be
  // no retransmittable packets on the wire, so the alarm should be set.
  session_->connection()->SendPing();
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(alarm.IsSet());
  EXPECT_EQ(
      clock_.ApproximateNow() + quic::QuicTime::Delta::FromMilliseconds(200),
      alarm.deadline());

  // Advance clock and simulate the alarm firing. This should cause a PING to be
  // sent.
  clock_.AdvanceTime(quic::QuicTime::Delta::FromMilliseconds(200));
  alarm.Fire();
  base::RunLoop().RunUntilIdle();

  quic_data.Resume();
  EXPECT_TRUE(quic_data.AllReadDataConsumed());
  EXPECT_TRUE(quic_data.AllWriteDataConsumed());
}

// Regression test for https://crbug.com/1043531.
TEST_P(QuicChromiumClientSessionTest, ResetOnEmptyResponseHeaders) {
  MockQuicData quic_data(version_);
  int packet_num = 1;
  quic_data.AddWrite(ASYNC,
                     client_maker_.MakeInitialSettingsPacket(packet_num++));
  quic_data.AddWrite(
      ASYNC,
      client_maker_.Packet(packet_num++)
          .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_GENERAL_PROTOCOL_ERROR)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_STREAM_GENERAL_PROTOCOL_ERROR)
          .Build());
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);
  Initialize();

  ProofVerifyDetailsChromium details;
  details.cert_verify_result.verified_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  ASSERT_TRUE(details.cert_verify_result.verified_cert.get());

  CompleteCryptoHandshake();
  session_->OnProofVerifyDetailsAvailable(details);

  auto session_handle = session_->CreateHandle(destination_);
  TestCompletionCallback callback;
  EXPECT_EQ(OK, session_handle->RequestStream(/*requires_confirmation=*/false,
                                              callback.callback(),
                                              TRAFFIC_ANNOTATION_FOR_TESTS));

  auto stream_handle = session_handle->ReleaseStream();
  EXPECT_TRUE(stream_handle->IsOpen());

  auto* stream = quic::test::QuicSessionPeer::GetOrCreateStream(
      session_.get(), stream_handle->id());

  const quic::QuicHeaderList empty_response_headers;
  static_cast<quic::QuicSpdyStream*>(stream)->OnStreamHeaderList(
      /* fin = */ false, /* frame_len = */ 0, empty_response_headers);

  // QuicSpdyStream::OnStreamHeaderList() calls
  // QuicChromiumClientStream::OnInitialHeadersComplete() with the empty
  // header list, and QuicChromiumClientStream signals an error.
  quiche::HttpHeaderBlock header_block;
  int rv = stream_handle->ReadInitialHeaders(&header_block,
                                             CompletionOnceCallback());
  EXPECT_THAT(rv, IsError(net::ERR_QUIC_PROTOCOL_ERROR));

  base::RunLoop().RunUntilIdle();
  quic_data.Resume();
  EXPECT_TRUE(quic_data.AllReadDataConsumed());
  EXPECT_TRUE(quic_data.AllWriteDataConsumed());
}

// This test verifies that when handles::NetworkHandle is not supported and
// there is no network change, session reports to the connectivity monitor
// correctly on path degrading detection and recovery.
TEST_P(QuicChromiumClientSessionTest,
       DegradingWithoutNetworkChange_NoNetworkHandle) {
  // Add a connectivity monitor for testing.
  default_network_ = handles::kInvalidNetworkHandle;
  connectivity_monitor_ =
      std::make_unique<QuicConnectivityMonitor>(default_network_);

  Initialize();

  // Fire path degrading detection.
  session_->ReallyOnPathDegrading();
  EXPECT_EQ(1u, connectivity_monitor_->GetNumDegradingSessions());

  session_->OnForwardProgressMadeAfterPathDegrading();
  EXPECT_EQ(0u, connectivity_monitor_->GetNumDegradingSessions());

  // Fire again.
  session_->ReallyOnPathDegrading();
  EXPECT_EQ(1u, connectivity_monitor_->GetNumDegradingSessions());

  // Close the session but keep the session around, the connectivity monitor
  // will not remove the tracking immediately.
  session_->CloseSessionOnError(ERR_ABORTED, quic::QUIC_INTERNAL_ERROR,
                                quic::ConnectionCloseBehavior::SILENT_CLOSE);
  EXPECT_EQ(1u, connectivity_monitor_->GetNumDegradingSessions());

  // Delete the session will remove the degrading count in connectivity
  // monitor.
  session_.reset();
  EXPECT_EQ(0u, connectivity_monitor_->GetNumDegradingSessions());
}

// This test verifies that when multi-port and port migration is enabled, path
// degrading won't trigger port migration.
TEST_P(QuicChromiumClientSessionTest, DegradingWithMultiPortEnabled) {
  // Default network is always set to handles::kInvalidNetworkHandle.
  default_network_ = handles::kInvalidNetworkHandle;
  connectivity_monitor_ =
      std::make_unique<QuicConnectivityMonitor>(default_network_);
  allow_port_migration_ = true;
  auto options = config_.SendConnectionOptions();
  config_.SetClientConnectionOptions(quic::QuicTagVector{quic::kMPQC});
  config_.SetConnectionOptionsToSend(options);

  Initialize();
  EXPECT_TRUE(session_->connection()->multi_port_stats());

  session_->ReallyOnPathDegrading();
  EXPECT_EQ(1u, connectivity_monitor_->GetNumDegradingSessions());

  EXPECT_EQ(
      UNKNOWN_CAUSE,
      QuicChromiumClientSessionPeer::GetCurrentMigrationCause(session_.get()));
}

// This test verifies that when the handles::NetworkHandle is not supported, and
// there are speculated network change reported via OnIPAddressChange, session
// still reports to the connectivity monitor correctly on path degrading
// detection and recovery.
TEST_P(QuicChromiumClientSessionTest, DegradingWithIPAddressChange) {
  // Default network is always set to handles::kInvalidNetworkHandle.
  default_network_ = handles::kInvalidNetworkHandle;
  connectivity_monitor_ =
      std::make_unique<QuicConnectivityMonitor>(default_network_);

  Initialize();

  session_->ReallyOnPathDegrading();
  EXPECT_EQ(1u, connectivity_monitor_->GetNumDegradingSessions());

  session_->OnForwardProgressMadeAfterPathDegrading();
  EXPECT_EQ(0u, connectivity_monitor_->GetNumDegradingSessions());

  session_->ReallyOnPathDegrading();
  EXPECT_EQ(1u, connectivity_monitor_->GetNumDegradingSessions());

  // When handles::NetworkHandle is not supported, network change is notified
  // via IP address change.
  connectivity_monitor_->OnIPAddressChanged();
  EXPECT_EQ(0u, connectivity_monitor_->GetNumDegradingSessions());

  // When handles::NetworkHandle is not supported and IP address changes,
  // session either goes away or gets closed. When it goes away,
  // reporting to connectivity monitor is disabled.
  connectivity_monitor_->OnSessionGoingAwayOnIPAddressChange(session_.get());

  // Even if session detects recovery or degradation, this session is no longer
  // on the default network and connectivity monitor will not update.
  session_->OnForwardProgressMadeAfterPathDegrading();
  EXPECT_EQ(0u, connectivity_monitor_->GetNumDegradingSessions());
  session_->ReallyOnPathDegrading();
  EXPECT_EQ(0u, connectivity_monitor_->GetNumDegradingSessions());

  session_->CloseSessionOnError(ERR_ABORTED, quic::QUIC_INTERNAL_ERROR,
                                quic::ConnectionCloseBehavior::SILENT_CLOSE);
  EXPECT_EQ(0u, connectivity_monitor_->GetNumDegradingSessions());

  session_.reset();
  EXPECT_EQ(0u, connectivity_monitor_->GetNumDegradingSessions());
}

// This test verifies that when handles::NetworkHandle is supported but
// migration is not supported and there's no network change, session reports to
// connectivity monitor correctly on path degrading detection or recovery.
// Default network change is currently reported with valid
// handles::NetworkHandles while session's current network interface is tracked
// by |default_network_|.
TEST_P(QuicChromiumClientSessionTest,
       DegradingOnDeafultNetwork_WithoutMigration) {
  default_network_ = kDefaultNetworkForTests;
  connectivity_monitor_ =
      std::make_unique<QuicConnectivityMonitor>(default_network_);

  Initialize();

  session_->ReallyOnPathDegrading();
  EXPECT_EQ(1u, connectivity_monitor_->GetNumDegradingSessions());

  session_->OnForwardProgressMadeAfterPathDegrading();
  EXPECT_EQ(0u, connectivity_monitor_->GetNumDegradingSessions());

  session_->ReallyOnPathDegrading();
  EXPECT_EQ(1u, connectivity_monitor_->GetNumDegradingSessions());
  // Close the session but keep the session around, the connectivity monitor
  // should not remove the count immediately.
  session_->CloseSessionOnError(ERR_ABORTED, quic::QUIC_INTERNAL_ERROR,
                                quic::ConnectionCloseBehavior::SILENT_CLOSE);
  EXPECT_EQ(1u, connectivity_monitor_->GetNumDegradingSessions());

  // Delete the session will remove the degrading count in connectivity
  // monitor.
  session_.reset();
  EXPECT_EQ(0u, connectivity_monitor_->GetNumDegradingSessions());
}

// This test verifies that when handles::NetworkHandle is supported but
// migrations is not supported and there is network changes, session reports to
// the connectivity monitor correctly on path degrading detection or recovery.
TEST_P(QuicChromiumClientSessionTest,
       DegradingWithDeafultNetworkChange_WithoutMigration) {
  default_network_ = kDefaultNetworkForTests;
  connectivity_monitor_ =
      std::make_unique<QuicConnectivityMonitor>(default_network_);

  Initialize();

  session_->ReallyOnPathDegrading();
  EXPECT_EQ(1u, connectivity_monitor_->GetNumDegradingSessions());

  session_->OnForwardProgressMadeAfterPathDegrading();
  EXPECT_EQ(0u, connectivity_monitor_->GetNumDegradingSessions());

  session_->ReallyOnPathDegrading();
  EXPECT_EQ(1u, connectivity_monitor_->GetNumDegradingSessions());

  // Simulate the default network change.
  connectivity_monitor_->OnDefaultNetworkUpdated(kNewNetworkForTests);
  EXPECT_EQ(0u, connectivity_monitor_->GetNumDegradingSessions());
  session_->OnNetworkMadeDefault(kNewNetworkForTests);

  // Session stays on the old default network, and recovers.
  session_->OnForwardProgressMadeAfterPathDegrading();
  EXPECT_EQ(0u, connectivity_monitor_->GetNumDegradingSessions());

  // Session degrades again on the old default.
  session_->ReallyOnPathDegrading();
  EXPECT_EQ(0u, connectivity_monitor_->GetNumDegradingSessions());

  // Simulate that default network switches back to the old default.
  connectivity_monitor_->OnDefaultNetworkUpdated(kDefaultNetworkForTests);
  EXPECT_EQ(0u, connectivity_monitor_->GetNumDegradingSessions());
  session_->OnNetworkMadeDefault(kDefaultNetworkForTests);

  // Session recovers again on the (old) default.
  session_->OnForwardProgressMadeAfterPathDegrading();
  EXPECT_EQ(0u, connectivity_monitor_->GetNumDegradingSessions());

  // Session degrades again on the (old) default.
  session_->ReallyOnPathDegrading();
  EXPECT_EQ(1u, connectivity_monitor_->GetNumDegradingSessions());

  session_->CloseSessionOnError(ERR_ABORTED, quic::QUIC_INTERNAL_ERROR,
                                quic::ConnectionCloseBehavior::SILENT_CLOSE);
  EXPECT_EQ(1u, connectivity_monitor_->GetNumDegradingSessions());

  session_.reset();
  EXPECT_EQ(0u, connectivity_monitor_->GetNumDegradingSessions());
}

TEST_P(QuicChromiumClientSessionTest, WriteErrorDuringCryptoConnect) {
  // Add a connectivity monitor for testing.
  default_network_ = kDefaultNetworkForTests;
  connectivity_monitor_ =
      std::make_unique<QuicConnectivityMonitor>(default_network_);

  // Use unmocked crypto stream to do crypto connect.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START_WITH_CHLO_SENT);

  MockQuicData quic_data(version_);
  // Trigger a packet write error when sending packets in crypto connect.
  quic_data.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  Initialize();
  ASSERT_THAT(session_->CryptoConnect(callback_.callback()),
              IsError(ERR_QUIC_HANDSHAKE_FAILED));
  // Verify error count is properly recorded.
  EXPECT_EQ(1u, connectivity_monitor_->GetCountForWriteErrorCode(
                    ERR_ADDRESS_UNREACHABLE));
  EXPECT_EQ(0u, connectivity_monitor_->GetCountForWriteErrorCode(
                    ERR_CONNECTION_RESET));

  // Simulate a default network change, write error stats should be reset.
  connectivity_monitor_->OnDefaultNetworkUpdated(kNewNetworkForTests);
  EXPECT_EQ(0u, connectivity_monitor_->GetCountForWriteErrorCode(
                    ERR_ADDRESS_UNREACHABLE));
}

TEST_P(QuicChromiumClientSessionTest, WriteErrorAfterHandshakeConfirmed) {
  // Add a connectivity monitor for testing.
  default_network_ = handles::kInvalidNetworkHandle;
  connectivity_monitor_ =
      std::make_unique<QuicConnectivityMonitor>(default_network_);

  MockQuicData quic_data(version_);
  int packet_num = 1;
  quic_data.AddWrite(SYNCHRONOUS,
                     client_maker_.MakeInitialSettingsPacket(packet_num++));
  // When sending the PING packet, trigger a packet write error.
  quic_data.AddWrite(SYNCHRONOUS, ERR_CONNECTION_RESET);
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  Initialize();
  CompleteCryptoHandshake();

  // Send a ping so that client has outgoing traffic before receiving packets.
  session_->connection()->SendPing();

  // Verify error count is properly recorded.
  EXPECT_EQ(1u, connectivity_monitor_->GetCountForWriteErrorCode(
                    ERR_CONNECTION_RESET));
  EXPECT_EQ(0u, connectivity_monitor_->GetCountForWriteErrorCode(
                    ERR_ADDRESS_UNREACHABLE));

  connectivity_monitor_->OnIPAddressChanged();

  // If network handle is supported, IP Address change is a no-op. Otherwise it
  // clears all stats.
  size_t expected_error_count =
      NetworkChangeNotifier::AreNetworkHandlesSupported() ? 1u : 0u;
  EXPECT_EQ(
      expected_error_count,
      connectivity_monitor_->GetCountForWriteErrorCode(ERR_CONNECTION_RESET));
}

// Much like above, but checking that ECN marks are reported.
TEST_P(QuicChromiumClientSessionTest, ReportsReceivedEcn) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(net::features::kReportEcn);

  MockQuicData mock_quic_data(version_);
  int write_packet_num = 1, read_packet_num = 0;
  quic::QuicEcnCounts ecn(1, 0, 0);  // 1 ECT(0) packet received
  mock_quic_data.AddWrite(
      ASYNC, client_maker_.MakeInitialSettingsPacket(write_packet_num++));
  mock_quic_data.AddRead(
      ASYNC, server_maker_.MakeInitialSettingsPacket(read_packet_num++));
  server_maker_.set_ecn_codepoint(quic::ECN_ECT0);
  mock_quic_data.AddRead(
      ASYNC, server_maker_.Packet(read_packet_num++).AddPingFrame().Build());
  mock_quic_data.AddWrite(SYNCHRONOUS, client_maker_.Packet(write_packet_num++)
                                           .AddAckFrame(0, 1, 0, ecn)
                                           .Build());
  server_maker_.set_ecn_codepoint(quic::ECN_ECT1);
  mock_quic_data.AddRead(
      ASYNC, server_maker_.Packet(read_packet_num++).AddPingFrame().Build());
  server_maker_.set_ecn_codepoint(quic::ECN_CE);
  mock_quic_data.AddRead(
      ASYNC, server_maker_.Packet(read_packet_num++).AddPingFrame().Build());
  ecn.ect1 = 1;
  ecn.ce = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS, client_maker_.Packet(write_packet_num++)
                                           .AddAckFrame(0, 3, 0, ecn)
                                           .Build());
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);
  Initialize();
  CompleteCryptoHandshake();
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_quic_data.AllReadDataConsumed());
  EXPECT_TRUE(mock_quic_data.AllWriteDataConsumed());
}

TEST_P(QuicChromiumClientSessionTest, OnOriginFrame) {
  const std::string kExampleOrigin1 = "https://www.example.com";
  const std::string kExampleOrigin2 = "https://www.example.com:443";
  const std::string kExampleOrigin3 = "https://www.example.com:8443";
  const std::string kExampleOrigin4 = "http://www.example.com:8080";
  const std::string kInvalidOrigin1 = "https://www.example.com/";
  const std::string kInvalidOrigin2 = "www.example.com";

  GURL url1(base::StrCat({kExampleOrigin1, "/"}));
  url::SchemeHostPort origin1(url1);
  ASSERT_TRUE(origin1.IsValid());
  GURL url2(base::StrCat({kExampleOrigin2, "/"}));
  url::SchemeHostPort origin2(url2);
  ASSERT_TRUE(origin2.IsValid());
  GURL url3(base::StrCat({kExampleOrigin3, "/"}));
  url::SchemeHostPort origin3(url3);
  ASSERT_TRUE(origin3.IsValid());
  GURL url4(base::StrCat({kExampleOrigin4, "/"}));
  url::SchemeHostPort origin4(url4);
  ASSERT_TRUE(origin4.IsValid());

  quic::OriginFrame frame;

  Initialize();

  ASSERT_TRUE(session_->received_origins().empty());

  frame.origins.push_back(kExampleOrigin1);
  session_->OnOriginFrame(frame);
  EXPECT_EQ(1u, ses
```