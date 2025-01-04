Response:
My thought process for analyzing the provided C++ code snippet and answering the user's request involved several steps:

1. **Understanding the Core Task:** The user wants to understand the functionality of the `net/quic/quic_session_pool_test.cc` file within the Chromium network stack. They are looking for a summary, connections to JavaScript (if any), logical reasoning examples, common usage errors, and debugging information related to user actions. Crucially, they specified this is part 8 of 20, indicating a need for a summary of this specific portion.

2. **Initial Code Scan for Keywords and Patterns:** I quickly scanned the code for recurring patterns and keywords that reveal the file's purpose. I noticed:
    * `TEST_P`: This indicates parameterized tests, suggesting a focus on testing different scenarios.
    * `QuicSessionPoolTest`:  This clearly points to testing the `QuicSessionPool` class.
    * `MockQuicData`: This strongly suggests the use of mock objects to simulate network behavior.
    * `socket_factory_`:  This suggests interaction with socket creation and management.
    * `crypto_client_stream_factory_`:  This indicates testing aspects of QUIC's cryptographic handshake.
    * `RequestBuilder`: This suggests testing the process of initiating requests.
    * `HttpStream`: This indicates interaction with the higher-level HTTP stream abstraction.
    * `server_preferred_address`, `allow_server_migration`, `OnPathDegradingDetected`, `NotifyNetworkMadeDefault`: These keywords suggest testing connection migration and server-initiated address changes.
    * `NetErrorDetails`: This points towards error handling and reporting during network events.

3. **Grouping Tests by Functionality:** I started grouping the individual test cases based on their apparent focus:
    * **Server Preferred Address Validation:**  `ValidateServerPreferredAddress`, `FailedToValidateServerPreferredAddress`.
    * **Server Migration:** `ServerMigrationDisabled`.
    * **Path Degradation and Port Migration:** `MigratePortOnPathDegrading_WithoutNetworkHandle_PathValidator`, `PortMigrationDisabledOnPathDegrading`, `PortMigrationProbingReceivedStatelessReset_PathValidator`, `MigratePortOnPathDegrading_WithNetworkHandle_PathValidator`, `MigratePortOnPathDegrading_WithMigration_PathValidator`.
    * **Network Change Events and Connection Migration:**  The remaining `TestPostNetworkOnMadeDefaultWhile...` tests.

4. **Inferring the Overall Purpose:** Based on the grouped tests, I concluded that `quic_session_pool_test.cc` is primarily concerned with testing the `QuicSessionPool`'s behavior in various network conditions, particularly focusing on:
    * Establishing QUIC connections.
    * Handling server-preferred addresses.
    * Managing connection migration (both client and server-initiated).
    * Reacting to network changes (like network becoming default, disconnection, etc.).
    * Testing error scenarios related to connection migration.

5. **Considering the JavaScript Connection:**  I recognized that while this C++ code directly implements the QUIC protocol, JavaScript in a browser interacts with it through higher-level APIs. The key connection is that this testing ensures the underlying QUIC implementation behaves correctly, which directly impacts the reliability and performance of network requests initiated by JavaScript in web pages.

6. **Constructing Logical Reasoning Examples:** For each key functionality area, I created simple hypothetical scenarios with assumed inputs and outputs to illustrate how the tests might work. This helps explain the code's behavior in a concrete way.

7. **Identifying Potential User/Programming Errors:**  I thought about common mistakes developers might make when using QUIC or related network APIs, such as incorrect configuration of migration settings or not handling network change events properly.

8. **Tracing User Actions to the Code:** I considered how a user action in a browser (like navigating to a website) would eventually lead to the execution of this QUIC code. The path involves DNS resolution, establishing a secure connection (where QUIC comes in), and then sending/receiving data.

9. **Summarizing the Current Portion (Part 8 of 20):**  Given that the provided snippet focuses heavily on server-preferred address validation and various aspects of connection migration (especially related to network changes), I summarized the functionality accordingly. I highlighted the testing of successful and failed validation, disabled migration scenarios, and responses to network events.

10. **Refining and Organizing the Answer:** I structured the answer logically, addressing each part of the user's request. I used clear headings and bullet points for readability. I made sure to explain the technical terms in a way that someone with less familiarity with QUIC could understand. I double-checked that the summary accurately reflected the content of the provided code snippet.

By following these steps, I could provide a comprehensive and informative answer that addresses the user's specific questions about the provided C++ code.
这是 Chromium 网络栈中 `net/quic/quic_session_pool_test.cc` 文件的第 8 部分，主要功能是 **测试 `QuicSessionPool` 在处理服务器首选地址、连接迁移以及网络变更时的行为和逻辑**。

**具体功能归纳 (基于提供的代码片段):**

1. **测试服务器首选地址的验证:**
   - `ValidateServerPreferredAddress`: 测试当服务器发送首选地址时，客户端能够成功验证并迁移到该地址的情况。
   - `FailedToValidateServerPreferredAddress`: 测试当客户端无法验证服务器首选地址时的情况，例如多次 Path Challenge 失败。

2. **测试禁用服务器迁移的情况:**
   - `ServerMigrationDisabled`: 测试当客户端配置禁用服务器迁移时，即使服务器发送了备用地址，客户端也不会迁移。

3. **测试在路径质量下降时进行端口迁移的情况:**
   - `MigratePortOnPathDegrading_WithoutNetworkHandle_PathValidator`: 测试在没有网络句柄的情况下，当检测到路径质量下降时，客户端尝试迁移到新端口的行为。
   - `PortMigrationDisabledOnPathDegrading`: 测试当客户端配置禁用端口迁移时，即使检测到路径质量下降也不会进行迁移。
   - `PortMigrationProbingReceivedStatelessReset_PathValidator`: 测试在路径探测期间收到服务器的 Stateless Reset 时的处理情况。
   - `MigratePortOnPathDegrading_WithNetworkHandle_PathValidator`:  与上一个类似，但测试场景包含网络句柄。
   - `MigratePortOnPathDegrading_WithMigration_PathValidator`: 测试当启用网络变更时的迁移功能时，路径质量下降时的端口迁移。

4. **测试在网络变更时连接迁移失败的情况 (主要关注 `TestPostNetworkOnMadeDefaultWhile...` 开头的测试):**
   - `TestPostNetworkOnMadeDefaultWhileConnectionMigrationFailOnUnexpectedErrorTwoDifferentSessions`: 测试当网络变为默认网络时，尝试迁移连接到新网络，但由于意外错误导致迁移失败，并且涉及两个不同的 Session 的情况。
   - `TestPostNetworkMadeDefaultWhileConnectionMigrationFailBeforeHandshake`: 测试在握手完成前，网络变为默认网络，导致连接迁移失败的情况。
   - `TestPostNetworkOnMadeDefaultWhileConnectionMigrationFailOnNoActiveStreams`: 测试当网络变为默认网络时，尝试迁移连接，但由于没有可迁移的活跃 Stream 而导致迁移失败的情况。
   - `TestPostNetworkOnMadeDefaultWhileConnectionMigrationFailOnUnexpectedError`:  类似于第一个 `TestPostNetworkOnMadeDefaultWhile...` 的测试，但可能涉及单个 Session 或更一般的情况。

**与 Javascript 的关系:**

这个 C++ 文件本身不包含 JavaScript 代码。但是，它测试的网络功能（QUIC 协议的连接管理和迁移）直接影响着浏览器中 JavaScript 发起的网络请求。

**举例说明:**

假设一个网页使用 JavaScript 的 `fetch()` API 发起了一个 HTTPS 请求。

1. **服务器首选地址:** 如果服务器支持并发送了首选地址，那么 `QuicSessionPool` 的测试确保了 Chromium 浏览器能够正确地验证并迁移到这个更优的地址，从而提升 JavaScript 请求的性能。

2. **连接迁移:** 当用户的网络环境发生变化（例如从 Wi-Fi 切换到移动数据）时，`QuicSessionPool` 的测试确保了 QUIC 连接能够平滑地迁移到新的网络，而不会中断 JavaScript 的网络请求，或者至少能够优雅地处理迁移失败的情况，避免 JavaScript 应用出现意外错误。

**逻辑推理的假设输入与输出:**

**示例 1: `ValidateServerPreferredAddress`**

* **假设输入:**
    * 客户端连接到初始服务器地址 (例如 127.0.0.1:12345)。
    * 服务器在握手后发送一个 `NEW_CONNECTION_ID` 帧，其中包含新的连接 ID 和首选地址 (例如 1.2.3.4:5678)。
    * 客户端发送 `PATH_CHALLENGE` 到首选地址。
    * 服务器回复 `PATH_RESPONSE`。
* **预期输出:**
    * 客户端成功验证了服务器的首选地址。
    * 客户端后续的数据包发送到服务器的首选地址 (1.2.3.4:5678)。
    * `session->connection()->GetStats().server_preferred_address_validated` 为 `true`。

**示例 2: `FailedToValidateServerPreferredAddress`**

* **假设输入:**
    * 客户端连接到初始服务器地址。
    * 服务器发送首选地址。
    * 客户端多次发送 `PATH_CHALLENGE` 到首选地址。
    * 服务器没有回复 `PATH_RESPONSE` 或回复失败。
* **预期输出:**
    * 客户端无法验证服务器的首选地址。
    * 客户端仍然使用初始服务器地址。
    * `session->connection()->GetStats().failed_to_validate_server_preferred_address` 为 `true`。

**用户或编程常见的使用错误:**

1. **错误配置连接迁移策略:** 用户或开发者可能错误地配置了 QUIC 客户端的连接迁移策略，例如错误地禁用了迁移，导致在网络环境变化时连接中断。
   * **例子:**  应用程序开发者可能通过某些实验性 Flag 或命令行参数禁用了 QUIC 的连接迁移功能，导致用户在移动过程中网络切换时体验不佳。

2. **未处理网络变更事件:** 开发者在某些场景下可能需要监听网络变更事件（尽管 QUIC 本身会尝试自动处理），如果处理不当，可能会导致应用逻辑错误。
   * **例子:** 一个在线游戏可能需要感知网络变化以调整游戏状态，如果网络切换导致 QUIC 连接迁移失败，而游戏没有正确处理这个事件，可能会导致游戏断线或数据丢失。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入 URL 并访问一个 HTTPS 网站，该网站支持 QUIC 协议。**
2. **浏览器首先进行 DNS 解析，获取服务器的 IP 地址。**
3. **浏览器尝试与服务器建立 QUIC 连接。** 这涉及到 TLS 握手，协商 QUIC 版本和参数等。
4. **在连接建立过程中或建立后，服务器可能会发送 `NEW_CONNECTION_ID` 帧，包含服务器的首选地址。**
5. **`QuicSessionPool` 负责管理 QUIC 会话，它会根据配置和服务器的指示，决定是否尝试验证并迁移到服务器的首选地址。** 相关的代码逻辑就在这个测试文件中被测试。
6. **如果用户的网络环境发生变化 (例如 Wi-Fi 断开，连接到移动数据)，`QuicSessionPool` 会尝试迁移连接到新的网络接口。** 相关的迁移逻辑和错误处理也是这个测试文件的重点。
7. **如果发生任何与连接迁移或服务器首选地址相关的错误或意外情况，这个测试文件中的测试用例可以帮助开发者理解和调试这些问题。** 例如，如果用户报告网络切换后网站加载缓慢或中断，开发者可能会查看 QUIC 相关的日志，并尝试复现这个测试文件中的某些场景。

**第 8 部分的功能总结:**

这部分测试文件专注于验证 `QuicSessionPool` 在处理以下关键场景时的正确性：

* **与服务器首选地址相关的行为：**  成功验证和迁移，以及验证失败的处理。
* **连接迁移策略的影响：** 测试启用和禁用服务器迁移时的行为。
* **路径质量下降时的端口迁移：** 测试在网络条件变差时，客户端尝试迁移到新端口的逻辑。
* **网络变更引起的连接迁移问题：**  特别是当迁移由于各种原因失败时的错误处理和状态管理。

总而言之，这部分测试是确保 Chromium QUIC 客户端能够健壮且正确地处理服务器提供的地址信息，并在网络环境变化时保持连接稳定性的关键组成部分。

Prompt: 
```
这是目录为net/quic/quic_session_pool_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共20部分，请归纳一下它的功能

"""
ion_);
  quic_data1.AddReadPauseForever();
  quic_data1.AddWrite(ASYNC,
                      client_maker_.MakeDummyCHLOPacket(packet_number++));
  // Change the encryption level after handshake is confirmed.
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  quic_data1.AddWrite(SYNCHRONOUS,
                      ConstructInitialSettingsPacket(packet_number++));
  quic_data1.AddSocketDataToFactory(socket_factory_.get());

  // Set up the second socket data provider that is used to validate server
  // preferred address.
  MockQuicData quic_data2(version_);
  client_maker_.set_connection_id(kNewCID);
  quic_data2.AddWrite(SYNCHRONOUS, client_maker_.Packet(packet_number++)
                                       .AddPathChallengeFrame()
                                       .AddPaddingFrame()
                                       .Build());
  quic_data2.AddReadPause();
  quic_data2.AddRead(
      ASYNC,
      server_maker_.Packet(1).AddPathResponseFrame().AddPaddingFrame().Build());
  quic_data2.AddReadPauseForever();
  quic_data2.AddSocketDataToFactory(socket_factory_.get());

  // Create request.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_TRUE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));
  base::RunLoop().RunUntilIdle();

  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  ASSERT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_FALSE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));
  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_FALSE(
      session->connection()->GetStats().server_preferred_address_validated);
  EXPECT_FALSE(session->connection()
                   ->GetStats()
                   .failed_to_validate_server_preferred_address);
  const quic::QuicSocketAddress peer_address = session->peer_address();

  quic_data2.Resume();
  EXPECT_FALSE(session->connection()->HasPendingPathValidation());
  EXPECT_TRUE(
      session->connection()->GetStats().server_preferred_address_validated);
  EXPECT_FALSE(session->connection()
                   ->GetStats()
                   .failed_to_validate_server_preferred_address);
  EXPECT_NE(session->peer_address(), peer_address);
  EXPECT_EQ(session->peer_address(),
            ToQuicSocketAddress(server_preferred_address));

  quic_data1.ExpectAllReadDataConsumed();
  quic_data1.ExpectAllWriteDataConsumed();
  quic_data2.ExpectAllReadDataConsumed();
  quic_data2.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, FailedToValidateServerPreferredAddress) {
  IPEndPoint server_preferred_address = IPEndPoint(IPAddress(1, 2, 3, 4), 123);
  FLAGS_quic_enable_chaos_protection = false;
  quic_params_->allow_server_migration = true;
  socket_factory_ = std::make_unique<TestPortMigrationSocketFactory>();
  Initialize();

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  quic::QuicConfig config;
  config.SetIPv4AlternateServerAddressToSend(
      ToQuicSocketAddress(server_preferred_address));
  quic::test::QuicConfigPeer::SetPreferredAddressConnectionIdAndToken(
      &config, kNewCID, quic::QuicUtils::GenerateStatelessResetToken(kNewCID));
  crypto_client_stream_factory_.SetConfig(config);
  // Use cold start mode to send crypto message for handshake.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START_WITH_CHLO_SENT);

  int packet_number = 1;
  MockQuicData quic_data1(version_);
  quic_data1.AddReadPauseForever();
  quic_data1.AddWrite(ASYNC,
                      client_maker_.MakeDummyCHLOPacket(packet_number++));
  // Change the encryption level after handshake is confirmed.
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  quic_data1.AddWrite(SYNCHRONOUS,
                      ConstructInitialSettingsPacket(packet_number++));
  quic_data1.AddSocketDataToFactory(socket_factory_.get());

  // Set up the second socket data provider that is used to validate server
  // preferred address.
  MockQuicData quic_data2(version_);
  client_maker_.set_connection_id(kNewCID);
  quic_data2.AddReadPauseForever();
  // One PATH_CHALLENGE + 2 retires.
  for (size_t i = 0; i < quic::QuicPathValidator::kMaxRetryTimes + 1; ++i) {
    quic_data2.AddWrite(SYNCHRONOUS, client_maker_.Packet(packet_number++)
                                         .AddPathChallengeFrame()
                                         .AddPaddingFrame()
                                         .Build());
  }
  quic_data2.AddSocketDataToFactory(socket_factory_.get());

  // Create request.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_TRUE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));
  base::RunLoop().RunUntilIdle();

  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  ASSERT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_FALSE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));
  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_FALSE(
      session->connection()->GetStats().server_preferred_address_validated);
  EXPECT_FALSE(session->connection()
                   ->GetStats()
                   .failed_to_validate_server_preferred_address);
  const quic::QuicSocketAddress peer_address = session->peer_address();

  auto* path_validator =
      quic::test::QuicConnectionPeer::path_validator(session->connection());
  for (size_t i = 0; i < quic::QuicPathValidator::kMaxRetryTimes + 1; ++i) {
    quic::test::QuicPathValidatorPeer::retry_timer(path_validator)->Cancel();
    path_validator->OnRetryTimeout();
  }

  EXPECT_FALSE(session->connection()->HasPendingPathValidation());
  EXPECT_FALSE(
      session->connection()->GetStats().server_preferred_address_validated);
  EXPECT_TRUE(session->connection()
                  ->GetStats()
                  .failed_to_validate_server_preferred_address);
  EXPECT_EQ(session->peer_address(), peer_address);
  EXPECT_NE(session->peer_address(),
            ToQuicSocketAddress(server_preferred_address));

  quic_data1.ExpectAllReadDataConsumed();
  quic_data1.ExpectAllWriteDataConsumed();
  quic_data2.ExpectAllReadDataConsumed();
  quic_data2.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, ServerMigrationDisabled) {
  // Add alternate IPv4 server address to config.
  IPEndPoint alt_address = IPEndPoint(IPAddress(1, 2, 3, 4), 123);
  quic_params_->allow_server_migration = false;
  FLAGS_quic_enable_chaos_protection = false;
  socket_factory_ = std::make_unique<TestPortMigrationSocketFactory>();
  Initialize();

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  quic::QuicConfig config;
  config.SetIPv4AlternateServerAddressToSend(ToQuicSocketAddress(alt_address));
  config.SetPreferredAddressConnectionIdAndTokenToSend(
      kNewCID, quic::QuicUtils::GenerateStatelessResetToken(kNewCID));
  crypto_client_stream_factory_.SetConfig(config);
  // Use cold start mode to send crypto message for handshake.
  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::COLD_START_WITH_CHLO_SENT);

  // Set up only 1 socket data provider.
  int packet_num = 1;
  MockQuicData quic_data1(version_);
  quic_data1.AddReadPauseForever();
  quic_data1.AddWrite(ASYNC, client_maker_.MakeDummyCHLOPacket(packet_num++));
  // Change the encryption level after handshake is confirmed.
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  quic_data1.AddWrite(SYNCHRONOUS,
                      ConstructInitialSettingsPacket(packet_num++));
  quic_data1.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_num++)
          .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                          StreamCancellationQpackDecoderInstruction(0))
          .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_STREAM_CANCELLED)
          .Build());
  quic_data1.AddSocketDataToFactory(socket_factory_.get());

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
  EXPECT_TRUE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));
  base::RunLoop().RunUntilIdle();

  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  ASSERT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_FALSE(HasActiveJob(kDefaultDestination, PRIVACY_MODE_DISABLED));

  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.example.org/");
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream->RegisterRequest(&request_info);
  EXPECT_EQ(OK, stream->InitializeStream(true, DEFAULT_PRIORITY, net_log_,
                                         CompletionOnceCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  IPEndPoint actual_address;
  session->GetDefaultSocket()->GetPeerAddress(&actual_address);
  // No migration should have happened.
  IPEndPoint expected_address =
      IPEndPoint(IPAddress(127, 0, 0, 1), kDefaultServerPort);
  EXPECT_EQ(actual_address, expected_address)
      << "Socket connected to: " << actual_address.address().ToString() << " "
      << actual_address.port()
      << ". Expected address: " << expected_address.address().ToString() << " "
      << expected_address.port();

  stream.reset();
  quic_data1.ExpectAllReadDataConsumed();
  quic_data1.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest,
       MigratePortOnPathDegrading_WithoutNetworkHandle_PathValidator) {
  socket_factory_ = std::make_unique<TestPortMigrationSocketFactory>();
  Initialize();

  TestSimplePortMigrationOnPathDegrading();
}

TEST_P(QuicSessionPoolTest, PortMigrationDisabledOnPathDegrading) {
  socket_factory_ = std::make_unique<TestPortMigrationSocketFactory>();
  Initialize();

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  int packet_number = 1;
  MockQuicData quic_data1(version_);
  quic_data1.AddReadPauseForever();
  quic_data1.AddWrite(SYNCHRONOUS,
                      ConstructInitialSettingsPacket(packet_number++));
  quic_data1.AddWrite(SYNCHRONOUS,
                      ConstructGetRequestPacket(
                          packet_number++,
                          GetNthClientInitiatedBidirectionalStreamId(0), true));
  quic_data1.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_number++)
          .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                          StreamCancellationQpackDecoderInstruction(0))
          .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_STREAM_CANCELLED)
          .Build());
  quic_data1.AddSocketDataToFactory(socket_factory_.get());

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL(kDefaultUrl);
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream->RegisterRequest(&request_info);
  EXPECT_EQ(OK, stream->InitializeStream(true, DEFAULT_PRIORITY, net_log_,
                                         CompletionOnceCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  // Send GET request on stream.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));
  // Disable connection migration on the request streams.
  // This should have no effect for port migration.
  QuicChromiumClientStream* chrome_stream =
      static_cast<QuicChromiumClientStream*>(
          quic::test::QuicSessionPeer::GetStream(
              session, GetNthClientInitiatedBidirectionalStreamId(0)));
  EXPECT_TRUE(chrome_stream);
  chrome_stream->DisableConnectionMigrationToCellularNetwork();

  EXPECT_EQ(0u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

  // Manually initialize the connection's self address. In real life, the
  // initialization will be done during crypto handshake.
  IPEndPoint ip;
  session->GetDefaultSocket()->GetLocalAddress(&ip);
  quic::test::QuicConnectionPeer::SetSelfAddress(session->connection(),
                                                 ToQuicSocketAddress(ip));

  // Set session config to have active migration disabled.
  quic::test::QuicConfigPeer::SetReceivedDisableConnectionMigration(
      session->config());
  EXPECT_TRUE(session->config()->DisableConnectionMigration());

  // Cause the connection to report path degrading to the session.
  // Session will start to probe a different port.
  session->connection()->OnPathDegradingDetected();
  base::RunLoop().RunUntilIdle();

  // The session should stay alive as if nothing happened.
  EXPECT_EQ(1u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  stream.reset();
  quic_data1.ExpectAllReadDataConsumed();
  quic_data1.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest,
       PortMigrationProbingReceivedStatelessReset_PathValidator) {
  socket_factory_ = std::make_unique<TestPortMigrationSocketFactory>();
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  // Using a testing task runner so that we can control time.
  auto task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), task_runner.get());

  int packet_number = 1;
  MockQuicData quic_data1(version_);
  quic_data1.AddReadPauseForever();
  quic_data1.AddWrite(SYNCHRONOUS,
                      ConstructInitialSettingsPacket(packet_number++));
  quic_data1.AddWrite(SYNCHRONOUS,
                      ConstructGetRequestPacket(
                          packet_number++,
                          GetNthClientInitiatedBidirectionalStreamId(0), true));
  quic_data1.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_number + 1)
          .AddStreamFrame(GetQpackDecoderStreamId(), /*fin=*/false,
                          StreamCancellationQpackDecoderInstruction(0))
          .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_STREAM_CANCELLED)
          .Build());
  quic_data1.AddSocketDataToFactory(socket_factory_.get());

  // Set up the second socket data provider that is used for migration probing.
  MockQuicData quic_data2(version_);
  quic::QuicConnectionId cid_on_new_path =
      quic::test::TestConnectionId(12345678);
  client_maker_.set_connection_id(cid_on_new_path);
  // Connectivity probe to be sent on the new path.
  quic_data2.AddWrite(SYNCHRONOUS, client_maker_.Packet(packet_number)
                                       .AddPathChallengeFrame()
                                       .AddPaddingFrame()
                                       .Build());
  quic_data2.AddReadPause();
  // Stateless reset to receive from the server.
  quic_data2.AddRead(ASYNC, server_maker_.MakeStatelessResetPacket());
  quic_data2.AddSocketDataToFactory(socket_factory_.get());

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Cause QUIC stream to be created.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL(kDefaultUrl);
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream->RegisterRequest(&request_info);
  EXPECT_EQ(OK, stream->InitializeStream(true, DEFAULT_PRIORITY, net_log_,
                                         CompletionOnceCallback()));

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  MaybeMakeNewConnectionIdAvailableToSession(cid_on_new_path, session);

  // Send GET request on stream.
  HttpResponseInfo response;
  HttpRequestHeaders request_headers;
  EXPECT_EQ(OK, stream->SendRequest(request_headers, &response,
                                    callback_.callback()));

  // Manually initialize the connection's self address. In real life, the
  // initialization will be done during crypto handshake.
  IPEndPoint ip;
  session->GetDefaultSocket()->GetLocalAddress(&ip);
  quic::test::QuicConnectionPeer::SetSelfAddress(session->connection(),
                                                 ToQuicSocketAddress(ip));

  EXPECT_EQ(0u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

  // Cause the connection to report path degrading to the session.
  // Session will start to probe a different port.
  session->connection()->OnPathDegradingDetected();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

  // The connection should still be alive, and not marked as going away.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());
  EXPECT_EQ(ERR_IO_PENDING, stream->ReadResponseHeaders(callback_.callback()));

  // Resume quic data and a STATELESS_RESET is read from the probing path.
  quic_data2.Resume();

  EXPECT_EQ(1u, QuicSessionPoolPeer::GetNumDegradingSessions(factory_.get()));

  // Verify that the session is still active, and the request stream is active.
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_EQ(1u, session->GetNumActiveStreams());

  stream.reset();
  quic_data1.ExpectAllReadDataConsumed();
  quic_data1.ExpectAllWriteDataConsumed();
  quic_data2.ExpectAllReadDataConsumed();
  quic_data2.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest,
       MigratePortOnPathDegrading_WithNetworkHandle_PathValidator) {
  scoped_mock_network_change_notifier_ =
      std::make_unique<ScopedMockNetworkChangeNotifier>();
  MockNetworkChangeNotifier* mock_ncn =
      scoped_mock_network_change_notifier_->mock_network_change_notifier();
  mock_ncn->ForceNetworkHandlesSupported();
  mock_ncn->SetConnectedNetworksList({kDefaultNetworkForTests});
  socket_factory_ = std::make_unique<TestPortMigrationSocketFactory>();
  Initialize();

  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kDefaultNetworkForTests);

  TestSimplePortMigrationOnPathDegrading();
}

TEST_P(QuicSessionPoolTest,
       MigratePortOnPathDegrading_WithMigration_PathValidator) {
  scoped_mock_network_change_notifier_ =
      std::make_unique<ScopedMockNetworkChangeNotifier>();
  MockNetworkChangeNotifier* mock_ncn =
      scoped_mock_network_change_notifier_->mock_network_change_notifier();
  mock_ncn->ForceNetworkHandlesSupported();
  mock_ncn->SetConnectedNetworksList({kDefaultNetworkForTests});
  // Enable migration on network change.
  quic_params_->migrate_sessions_on_network_change_v2 = true;
  socket_factory_ = std::make_unique<TestPortMigrationSocketFactory>();
  Initialize();

  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kDefaultNetworkForTests);

  TestSimplePortMigrationOnPathDegrading();
}

TEST_P(
    QuicSessionPoolTest,
    TestPostNetworkOnMadeDefaultWhileConnectionMigrationFailOnUnexpectedErrorTwoDifferentSessions) {
  scoped_mock_network_change_notifier_ =
      std::make_unique<ScopedMockNetworkChangeNotifier>();
  MockNetworkChangeNotifier* mock_ncn =
      scoped_mock_network_change_notifier_->mock_network_change_notifier();
  mock_ncn->ForceNetworkHandlesSupported();
  mock_ncn->SetConnectedNetworksList({kDefaultNetworkForTests});
  // Enable migration on network change.
  quic_params_->migrate_sessions_on_network_change_v2 = true;
  socket_factory_ = std::make_unique<TestPortMigrationSocketFactory>();
  Initialize();

  MockQuicData socket_data1(version_);
  socket_data1.AddReadPauseForever();
  socket_data1.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data1.AddWrite(ASYNC, OK);
  socket_data1.AddSocketDataToFactory(socket_factory_.get());
  client_maker_.Reset();
  MockQuicData socket_data2(version_);
  socket_data2.AddReadPauseForever();
  socket_data2.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data2.AddWrite(ASYNC, OK);
  socket_data2.AddSocketDataToFactory(socket_factory_.get());
  // Add new sockets to use post migration. Those are bad sockets and will cause
  // migration to fail.
  MockConnect connect_result = MockConnect(ASYNC, ERR_UNEXPECTED);
  SequencedSocketData socket_data3(connect_result, base::span<MockRead>(),
                                   base::span<MockWrite>());
  socket_factory_->AddSocketDataProvider(&socket_data3);
  SequencedSocketData socket_data4(connect_result, base::span<MockRead>(),
                                   base::span<MockWrite>());
  socket_factory_->AddSocketDataProvider(&socket_data4);

  url::SchemeHostPort server1(url::kHttpsScheme, kDefaultServerHostName, 443);
  url::SchemeHostPort server2(url::kHttpsScheme, kServer2HostName, 443);

  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  host_resolver_->set_synchronous_mode(true);
  host_resolver_->rules()->AddIPLiteralRule(server1.host(), "192.168.0.1", "");
  host_resolver_->rules()->AddIPLiteralRule(server2.host(), "192.168.0.2", "");

  // Create request and QuicHttpStream to create session1.
  RequestBuilder builder1(this);
  builder1.destination = server1;
  EXPECT_EQ(ERR_IO_PENDING, builder1.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream1 = CreateStream(&builder1.request);
  EXPECT_TRUE(stream1.get());

  // Create request and QuicHttpStream to create session2.
  RequestBuilder builder2(this);
  builder2.destination = server2;
  builder2.url = GURL(kServer2Url);
  EXPECT_EQ(ERR_IO_PENDING, builder2.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());

  QuicChromiumClientSession* session1 = GetActiveSession(server1);
  QuicChromiumClientSession* session2 = GetActiveSession(server2);
  EXPECT_NE(session1, session2);

  // Cause QUIC stream to be created and send GET so session1 has an open
  // stream.
  HttpRequestInfo request_info1;
  request_info1.method = "GET";
  request_info1.url = GURL(kDefaultUrl);
  request_info1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream1->RegisterRequest(&request_info1);
  EXPECT_EQ(OK, stream1->InitializeStream(true, DEFAULT_PRIORITY, net_log_,
                                          CompletionOnceCallback()));
  HttpResponseInfo response1;
  HttpRequestHeaders request_headers1;
  EXPECT_EQ(OK, stream1->SendRequest(request_headers1, &response1,
                                     callback_.callback()));

  // Cause QUIC stream to be created and send GET so session2 has an open
  // stream.
  HttpRequestInfo request_info2;
  request_info2.method = "GET";
  request_info2.url = GURL(kDefaultUrl);
  request_info2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream2->RegisterRequest(&request_info2);
  EXPECT_EQ(OK, stream2->InitializeStream(true, DEFAULT_PRIORITY, net_log_,
                                          CompletionOnceCallback()));
  HttpResponseInfo response2;
  HttpRequestHeaders request_headers2;
  EXPECT_EQ(OK, stream2->SendRequest(request_headers2, &response2,
                                     callback_.callback()));

  EXPECT_EQ(2u, crypto_client_stream_factory_.streams().size());

  crypto_client_stream_factory_.streams()[0]->setHandshakeConfirmedForce(false);
  crypto_client_stream_factory_.streams()[1]->setHandshakeConfirmedForce(false);

  std::unique_ptr<QuicChromiumClientSession::Handle> handle1 =
      session1->CreateHandle(server1);
  std::unique_ptr<QuicChromiumClientSession::Handle> handle2 =
      session2->CreateHandle(server2);
  mock_ncn->NotifyNetworkDisconnected(kDefaultNetworkForTests);
  mock_ncn->NotifyNetworkMadeDefault(kNewNetworkForTests);

  NetErrorDetails details;
  handle1->PopulateNetErrorDetails(&details);
  EXPECT_EQ(
      quic::QuicErrorCode::QUIC_CONNECTION_MIGRATION_HANDSHAKE_UNCONFIRMED,
      details.quic_connection_error);
  EXPECT_EQ(false, details.quic_connection_migration_successful);

  handle2->PopulateNetErrorDetails(&details);
  EXPECT_EQ(
      quic::QuicErrorCode::QUIC_CONNECTION_MIGRATION_HANDSHAKE_UNCONFIRMED,
      details.quic_connection_error);
  EXPECT_EQ(false, details.quic_connection_migration_successful);
}

TEST_P(QuicSessionPoolTest,
       TestPostNetworkMadeDefaultWhileConnectionMigrationFailBeforeHandshake) {
  scoped_mock_network_change_notifier_ =
      std::make_unique<ScopedMockNetworkChangeNotifier>();
  MockNetworkChangeNotifier* mock_ncn =
      scoped_mock_network_change_notifier_->mock_network_change_notifier();
  mock_ncn->ForceNetworkHandlesSupported();
  mock_ncn->SetConnectedNetworksList({kDefaultNetworkForTests});
  // Enable migration on network change.
  quic_params_->migrate_sessions_on_network_change_v2 = true;
  socket_factory_ = std::make_unique<TestPortMigrationSocketFactory>();
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  auto task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), task_runner.get());

  int packet_num = 1;
  MockQuicData quic_data(version_);
  quic_data.AddReadPauseForever();
  quic_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket(packet_num++));
  quic_data.AddReadPauseForever();

  quic_data.AddSocketDataToFactory(socket_factory_.get());

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());

  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  crypto_client_stream_factory_.last_stream()->setHandshakeConfirmedForce(
      false);

  std::unique_ptr<QuicChromiumClientSession::Handle> handle =
      session->CreateHandle(kDefaultDestination);
  mock_ncn->NotifyNetworkDisconnected(kDefaultNetworkForTests);
  mock_ncn->NotifyNetworkConnected(kNewNetworkForTests);
  mock_ncn->NotifyNetworkMadeDefault(kNewNetworkForTests);

  NetErrorDetails details;
  handle->PopulateNetErrorDetails(&details);
  EXPECT_EQ(
      quic::QuicErrorCode::QUIC_CONNECTION_MIGRATION_HANDSHAKE_UNCONFIRMED,
      details.quic_connection_error);
  EXPECT_EQ(false, details.quic_connection_migration_successful);
}

// See crbug/1465889 for more details on what scenario is being tested.
TEST_P(
    QuicSessionPoolTest,
    TestPostNetworkOnMadeDefaultWhileConnectionMigrationFailOnNoActiveStreams) {
  scoped_mock_network_change_notifier_ =
      std::make_unique<ScopedMockNetworkChangeNotifier>();
  MockNetworkChangeNotifier* mock_ncn =
      scoped_mock_network_change_notifier_->mock_network_change_notifier();
  mock_ncn->ForceNetworkHandlesSupported();
  mock_ncn->SetConnectedNetworksList({kDefaultNetworkForTests});
  // Enable migration on network change.
  quic_params_->migrate_sessions_on_network_change_v2 = true;
  socket_factory_ = std::make_unique<TestPortMigrationSocketFactory>();
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  auto task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), task_runner.get());

  int packet_num = 1;
  MockQuicData quic_data(version_);
  quic_data.AddReadPauseForever();
  quic_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket(packet_num++));
  quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_num)
          .AddConnectionCloseFrame(
              quic::QUIC_CONNECTION_MIGRATION_NO_MIGRATABLE_STREAMS,
              "net error")
          .Build());

  quic_data.AddSocketDataToFactory(socket_factory_.get());

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Ensure that session is alive and active.
  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_FALSE(session->HasActiveRequestStreams());

  std::unique_ptr<QuicChromiumClientSession::Handle> handle =
      session->CreateHandle(kDefaultDestination);
  mock_ncn->NotifyNetworkDisconnected(kDefaultNetworkForTests);
  mock_ncn->NotifyNetworkConnected(kNewNetworkForTests);
  mock_ncn->NotifyNetworkMadeDefault(kNewNetworkForTests);

  NetErrorDetails details;
  handle->PopulateNetErrorDetails(&details);
  EXPECT_EQ(
      quic::QuicErrorCode::QUIC_CONNECTION_MIGRATION_NO_MIGRATABLE_STREAMS,
      details.quic_connection_error);
  EXPECT_EQ(false, details.quic_connection_migration_successful);
}

// See crbug/1465889 for more details on what scenario is being tested.
TEST_P(
    QuicSessionPoolTest,
    TestPostNetworkOnMadeDefaultWhileConnectionMigrationFailOnUnexpectedError) {
  scoped_mock_network_change_notifier_ =
      std::make_unique<ScopedMockNetwo
"""


```