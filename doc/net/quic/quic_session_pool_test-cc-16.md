Response:
Let's break down the thought process for analyzing this code snippet and generating the response.

**1. Initial Understanding of the Context:**

The prompt clearly states this is a part of the Chromium network stack, specifically the `net/quic/quic_session_pool_test.cc` file. The "test" suffix immediately signals that this is a unit test file. The prompt also provides the specific code snippet.

**2. Dissecting the Code Snippet (Line by Line, Conceptually):**

The core of the analysis involves understanding what the code *does*. Here's a breakdown of the key elements and what they likely signify:

* **`MockQuicData`:** This class is likely a test double for simulating network interactions. It allows the test to define expected reads and writes on a socket without actually sending network packets.
* **`.AddRead(...)` and `.AddWrite(...)`:** These methods on `MockQuicData` are setting up the simulated network exchanges. `SYNCHRONOUS` and `ASYNC` suggest how the simulated operations should behave in the test environment. `ERR_IO_PENDING` and `ERR_ADDRESS_UNREACHABLE` are simulated error conditions.
* **`server_maker_.Packet(...)` and `client_maker_.Packet(...)`:** These likely belong to helper classes for constructing QUIC packets for the simulated server and client. Methods like `.AddNewConnectionIdFrame(...)`, `.AddAckFrame(...)`, and `.AddRetireConnectionIdFrame(...)` indicate the specific QUIC frames being constructed.
* **`alternate_socket_data`:** This suggests the test is simulating a connection migration scenario, where the connection moves to a different network path.
* **`RequestBuilder`:**  This is a test utility for initiating HTTP requests over QUIC.
* **`EXPECT_EQ(...)` and `EXPECT_THAT(...)`:** These are standard Google Test macros used for assertions within the tests.
* **`CreateStream(...)`:** This likely creates a `HttpStream` object, representing an HTTP request/response exchange over the QUIC session.
* **`HasActiveSession(...)`:** This function checks if a QUIC session is currently active for the given destination.
* **`scoped_mock_network_change_notifier_`:** This indicates the test is simulating network connectivity changes (disconnects and reconnects).
* **`task_runner->GetPendingTaskCount()` and `task_runner->FastForwardBy(...)`:**  This suggests the test is manipulating the event loop to simulate time passing and observe the scheduling of asynchronous tasks.
* **`quic_params_->migrate_idle_sessions` and `quic_params_->idle_session_migration_period`:** This shows the test is configuring and verifying the behavior of idle connection migration.
* **`CertDatabase::GetInstance()->NotifyObserversTrustStoreChanged()` and `cert_verifier_->SimulateOnCertVerifierChanged()`:** These simulate changes to the certificate database and verifier, testing how the QUIC session pool reacts to these events.
* **`QuicSessionPoolPeer::GetCryptoConfig(...)`:**  This accesses the QUIC crypto configuration, likely testing how it's shared or isolated.
* **`features::kPartitionConnectionsByNetworkIsolationKey`:** This indicates the test is checking behavior with and without network isolation keys enabled.

**3. Identifying Core Functionality:**

By observing the patterns in the code and the test setup, the primary function of this test file becomes clear: **testing the `QuicSessionPool`'s behavior related to connection migration and related scenarios.**  The specific scenarios being tested within this snippet are:

* **Network Disconnection and Reconnection:** Simulating a network disconnection and how the session pool handles migrating the connection and potentially migrating back.
* **Idle Connection Migration:** Testing the logic for migrating idle connections to potentially better network paths.
* **Handling Certificate Changes:** Verifying that the session pool reacts correctly to changes in the certificate database and verifier by invalidating sessions.
* **Crypto Configuration Management:**  Testing how the `QuicSessionPool` manages and shares `QuicCryptoClientConfig` instances, especially in the context of network isolation keys.

**4. Addressing Specific Prompt Points:**

* **Functionality Listing:** Based on the dissected code, listing the functions becomes straightforward (testing connection migration, idle migration, certificate changes, crypto config).
* **Relationship with JavaScript:**  Since this is low-level network code, the direct relationship with JavaScript is weak. The connection is indirect: JavaScript running in a browser relies on this kind of network code to establish QUIC connections. The example of `fetch()` is a good illustration of this indirect relationship.
* **Logical Reasoning (Input/Output):**  For the connection migration test, a reasonable assumption for input is a network disconnection. The expected output is the scheduling of migration tasks and potential session closure or migration to an alternate network.
* **User/Programming Errors:** Common errors involve incorrect configuration of network settings or assumptions about connection persistence. The example of firewalls blocking UDP is a relevant user error. The programming error example focuses on not handling connection migration events correctly.
* **User Steps to Reach Here:** Tracing back the user actions involves an HTTPS request that uses QUIC, potentially encountering network changes or long periods of inactivity.
* **Part 17 of 20:** The fact that this is part 17 suggests the entire test suite covers a broad range of `QuicSessionPool` functionality. This specific part focuses on migration and related lifecycle events.

**5. Structuring the Response:**

Organizing the findings into the categories requested by the prompt (functionality, JavaScript relation, reasoning, errors, user steps, summary) makes the answer clear and easy to understand.

**Self-Correction/Refinement during the thought process:**

* Initially, I might have focused too much on the specific QUIC frames being exchanged. While important for debugging, the *high-level* functionality of the tests is more critical for this type of summary.
* I needed to consciously think about the connection between this low-level code and the user-facing aspects, leading to the JavaScript example.
*  The "Part 17 of 20" clue is important for inferring the scope of the entire test file.

By following this methodical breakdown and considering the specific points raised in the prompt, a comprehensive and accurate response can be generated.
好的，让我们来分析一下 `net/quic/quic_session_pool_test.cc` 文件中的这段代码片段。

**功能列举:**

这段代码主要测试 `QuicSessionPool` 在处理连接迁移（Connection Migration）以及相关场景时的行为。具体来说，它测试了以下功能：

1. **网络断开和恢复场景下的连接迁移:**  模拟当前网络断开，然后恢复的情况，验证 `QuicSessionPool` 如何处理连接迁移到备用网络，以及在原网络恢复后是否会尝试迁移回原网络。
2. **自定义的空闲连接迁移周期:** 验证可以配置自定义的空闲连接迁移周期，并在达到该周期后触发迁移。
3. **处理证书数据库变更 (OnCertDBChanged):**  模拟证书数据库发生变化，例如用户添加或删除了信任的证书，验证 `QuicSessionPool` 是否会正确地关闭现有的 QUIC 会话，并为相同 origin 的新请求创建新的会话。
4. **处理证书验证器变更 (OnCertVerifierChanged):** 模拟证书验证器发生变化，验证 `QuicSessionPool` 是否会采取与证书数据库变更类似的处理措施，关闭现有会话并创建新会话。
5. **共享 Crypto 配置 (SharedCryptoConfig):** 验证具有相同后缀的域名（例如 `*.c.youtube.com`）是否可以共享 `QuicCryptoClientConfig`，从而复用 TLS 会话信息。
6. **Crypto 配置在 Proof 无效时的情况 (CryptoConfigWhenProofIsInvalid):** 测试当缓存的 TLS 握手 Proof 无效时，`QuicCryptoClientConfig` 的行为。
7. **禁用从磁盘缓存加载 (EnableNotLoadFromDiskCache):**  验证当禁用从磁盘缓存加载 TLS 信息时，连接建立流程的行为。
8. **在连接超时打开流时减少 Ping 超时 (ReducePingTimeoutOnConnectionTimeOutOpenStreams):** 测试当之前的 QUIC 连接因超时而关闭且存在打开的流时，`QuicSessionPool` 是否会降低后续连接的 Ping 超时时间。
9. **初始化 (MaybeInitialize 和 MaybeInitializeWithNetworkAnonymizationKey):** 验证 `QuicSessionPool` 的初始化过程，包括是否考虑 NetworkAnonymizationKey。
10. **Crypto 配置缓存 (CryptoConfigCache 和 CryptoConfigCacheWithNetworkAnonymizationKey):**  测试 `QuicCryptoClientConfig` 的缓存机制，包括在启用 NetworkAnonymizationKey 时的隔离行为。

**与 JavaScript 的关系及举例说明:**

这段 C++ 代码位于 Chromium 的网络栈底层，与 JavaScript 的交互是间接的。JavaScript 通过浏览器提供的 Web API (例如 `fetch` API) 发起网络请求，浏览器内部的网络模块会使用这段 C++ 代码来处理 QUIC 协议的连接管理。

**举例说明:**

假设一个网页的 JavaScript 代码使用 `fetch` API 向一个支持 QUIC 的 HTTPS 网站发起请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

当网络发生切换，或者连接长时间空闲，或者服务器更新了证书等情况时，这段 C++ 代码中测试的 `QuicSessionPool` 的逻辑就会被触发，来管理底层的 QUIC 连接，而 JavaScript 代码无需关心这些底层的连接管理细节。浏览器会处理好连接的迁移、重连等，对 JavaScript 而言，`fetch` 操作仍然能够成功完成。

**逻辑推理 (假设输入与输出):**

以 “网络断开和恢复场景下的连接迁移” 这个测试为例：

* **假设输入:**
    * 一个活动的 QUIC 会话连接到 `kDefaultDestination`。
    * JavaScript 发起了一个对 `kDefaultDestination` 的请求，并创建了一个 `HttpStream`。
    * 模拟网络断开事件 (`NotifyNetworkDisconnected(kDefaultNetworkForTests)` )。
    * 模拟网络恢复事件 (`NotifyNetworkMadeDefault(kDefaultNetworkForTests)` )。
* **预期输出:**
    * 当网络断开时，`QuicSessionPool` 会尝试将连接迁移到备用网络（如果可用）。
    * 由于没有活动的流，会话将被关闭。
    * 在原网络恢复后，会安排任务尝试迁移回原网络。
    * 如果迁移尝试失败（例如 `ERR_ADDRESS_UNREACHABLE`），会进行重试，并遵循退避策略（1秒，2秒，4秒...）。
    * 最终，由于空闲迁移超时，会话会被关闭。

**用户或编程常见的使用错误及举例说明:**

1. **用户错误：网络配置问题导致连接迁移失败。**
   * **场景:** 用户在一个网络环境下建立了 QUIC 连接，然后移动到另一个网络环境，但新网络的防火墙阻止了 UDP 流量（QUIC 基于 UDP）。
   * **结果:**  `QuicSessionPool` 尝试迁移连接到新网络会失败，可能导致请求失败或需要重新建立 TCP 连接。

2. **编程错误：不正确地处理连接迁移事件。**
   * **场景:**  虽然这段代码是测试底层的连接池，但在上层应用或者 Chromium 的其他组件中，如果开发者没有正确处理连接迁移可能带来的影响，例如没有正确处理连接 ID 的变更，可能会导致数据包丢失或连接中断。
   * **结果:** 尽管 `QuicSessionPool` 能够成功迁移连接，但由于上层逻辑错误，可能导致请求失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

为了调试与 `QuicSessionPool` 相关的连接迁移问题，可以考虑以下用户操作路径：

1. **用户发起 HTTPS 请求:** 用户在浏览器中访问一个 HTTPS 网站，并且该网站支持 QUIC 协议。
2. **建立 QUIC 连接:** Chromium 的网络栈会尝试与服务器建立 QUIC 连接。这个过程中会涉及到 `QuicSessionPool` 来管理和复用 QUIC 会话。
3. **网络环境变化:**
   * **Wi-Fi 切换:** 用户从一个 Wi-Fi 网络切换到另一个 Wi-Fi 网络。
   * **移动网络切换:** 用户从 Wi-Fi 网络切换到移动数据网络，或者反之。
   * **网络断开和恢复:** 用户的网络连接短暂中断，然后又恢复。
4. **长时间空闲:** 用户打开一个网页后，长时间没有进行任何操作，导致 QUIC 连接进入空闲状态。
5. **证书变更:** 网站的 SSL/TLS 证书发生变更，浏览器需要重新验证证书。

当上述任何一种情况发生时，都可能触发 `QuicSessionPool` 中与连接迁移、证书处理等相关的逻辑。调试时，可以关注网络事件、QUIC 连接的状态变化、以及相关的日志信息。

**归纳一下它的功能 (作为第 17 部分，共 20 部分):**

作为测试套件的一部分，这段代码（第 17 部分）主要集中在测试 `QuicSessionPool` 的 **连接迁移能力以及对相关事件（如证书变更）的响应**。结合上下文来看，整个 `quic_session_pool_test.cc` 文件很可能涵盖了 `QuicSessionPool` 的各种功能和边界情况的测试。第 17 部分深入测试了在网络环境变化和证书状态变化时，连接池的健壮性和正确性。这表明之前的部分可能已经测试了连接的建立、流的管理等基础功能，而接下来的部分可能会关注性能、错误处理、与其他网络组件的交互等方面。

总而言之，这段代码是 `QuicSessionPool` 功能测试的重要组成部分，专注于验证其在动态网络环境和安全上下文下的行为。

### 提示词
```
这是目录为net/quic/quic_session_pool_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第17部分，共20部分，请归纳一下它的功能
```

### 源代码
```cpp
.AddAckFrame(/*first_received=*/1,
                              /*largest_received=*/peer_packet_num - 1,
                              /*smallest_received=*/1)
                 .AddRetireConnectionIdFrame(/*sequence_number=*/6u)
                 .Build());
  alternate_socket_data.AddReadPause();
  alternate_socket_data.AddRead(
      ASYNC, server_maker_.Packet(peer_packet_num++)
                 .AddNewConnectionIdFrame(cid7, /*sequence_number=*/7u,
                                          /*retire_prior_to=*/1u)
                 .Build());
  alternate_socket_data.AddRead(SYNCHRONOUS,
                                ERR_IO_PENDING);  // Hanging read.
  alternate_socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Set up probing socket for migrating back to the default network.
  MockQuicData quic_data(version_);  // retry count: 0.
  quic_data.AddReadPauseForever();
  quic_data.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
  quic_data.AddSocketDataToFactory(socket_factory_.get());

  MockQuicData quic_data1(version_);  // retry count: 1
  quic_data1.AddReadPauseForever();
  quic_data1.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
  quic_data1.AddSocketDataToFactory(socket_factory_.get());

  MockQuicData quic_data2(version_);  // retry count: 2
  quic_data2.AddReadPauseForever();
  quic_data2.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
  quic_data2.AddSocketDataToFactory(socket_factory_.get());

  MockQuicData quic_data3(version_);  // retry count: 3
  quic_data3.AddReadPauseForever();
  quic_data3.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
  quic_data3.AddSocketDataToFactory(socket_factory_.get());

  MockQuicData quic_data4(version_);  // retry count: 4
  quic_data4.AddReadPauseForever();
  quic_data4.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
  quic_data4.AddSocketDataToFactory(socket_factory_.get());

  MockQuicData quic_data5(version_);  // retry count: 5
  quic_data5.AddReadPauseForever();
  quic_data5.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
  quic_data5.AddSocketDataToFactory(socket_factory_.get());

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Ensure that session is active.
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  // Trigger connection migration. Since there are no active streams,
  // the session will be closed.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  // The nearest task will complete migration.
  EXPECT_EQ(2u, task_runner->GetPendingTaskCount());
  EXPECT_EQ(base::TimeDelta(), task_runner->NextPendingTaskDelay());
  task_runner->FastForwardBy(base::TimeDelta());

  // The migrate back timer will fire. Due to default network
  // being disconnected, no attempt will be exercised to migrate back.
  EXPECT_EQ(1u, task_runner->GetPendingTaskCount());
  EXPECT_EQ(base::Seconds(kMinRetryTimeForDefaultNetworkSecs),
            task_runner->NextPendingTaskDelay());
  task_runner->FastForwardBy(task_runner->NextPendingTaskDelay());
  EXPECT_EQ(0u, task_runner->GetPendingTaskCount());

  // Deliver the signal that the old default network now backs up.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kDefaultNetworkForTests);

  // A task is posted to migrate back to the default network immediately.
  EXPECT_EQ(1u, task_runner->GetPendingTaskCount());
  EXPECT_EQ(base::TimeDelta(), task_runner->NextPendingTaskDelay());
  task_runner->FastForwardBy(base::TimeDelta());

  // Retry migrate back in 1, 2, 4, 8, 16s.
  // Session will be closed due to idle migration timeout.
  for (int i = 0; i < 5; i++) {
    // Fire retire connection ID alarm.
    base::RunLoop().RunUntilIdle();
    // Make new connection ID available.
    alternate_socket_data.Resume();
    EXPECT_TRUE(HasActiveSession(kDefaultDestination));
    // A task is posted to migrate back to the default network in 2^i seconds.
    EXPECT_EQ(1u, task_runner->GetPendingTaskCount());
    EXPECT_EQ(base::Seconds(UINT64_C(1) << i),
              task_runner->NextPendingTaskDelay());
    task_runner->FastForwardBy(task_runner->NextPendingTaskDelay());
  }

  default_socket_data.ExpectAllReadDataConsumed();
  default_socket_data.ExpectAllWriteDataConsumed();
  alternate_socket_data.ExpectAllReadDataConsumed();
  alternate_socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, CustomIdleMigrationPeriod) {
  // The customized threshold is 15s.
  quic_params_->migrate_idle_sessions = true;
  quic_params_->idle_session_migration_period = base::Seconds(15);
  InitializeConnectionMigrationV2Test(
      {kDefaultNetworkForTests, kNewNetworkForTests});
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  client_maker_.set_save_packet_frames(true);

  // Using a testing task runner and a test tick tock.
  auto task_runner = base::MakeRefCounted<base::TestMockTimeTaskRunner>();
  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), task_runner.get());
  QuicSessionPoolPeer::SetTickClock(factory_.get(),
                                    task_runner->GetMockTickClock());

  quic::QuicConnectionId cid1 = quic::test::TestConnectionId(1234567);
  quic::QuicConnectionId cid2 = quic::test::TestConnectionId(2345671);
  quic::QuicConnectionId cid3 = quic::test::TestConnectionId(3456712);
  quic::QuicConnectionId cid4 = quic::test::TestConnectionId(4567123);
  quic::QuicConnectionId cid5 = quic::test::TestConnectionId(5671234);
  quic::QuicConnectionId cid6 = quic::test::TestConnectionId(6712345);

  int peer_packet_num = 1;
  MockQuicData default_socket_data(version_);
  default_socket_data.AddRead(
      SYNCHRONOUS, server_maker_.Packet(peer_packet_num++)
                       .AddNewConnectionIdFrame(cid1, /*sequence_number=*/1u,
                                                /*retire_prior_to=*/0u)
                       .Build());
  default_socket_data.AddReadPauseForever();
  int packet_num = 1;
  default_socket_data.AddWrite(SYNCHRONOUS,
                               ConstructInitialSettingsPacket(packet_num++));
  default_socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Set up second socket data provider that is used after migration.
  MockQuicData alternate_socket_data(version_);
  client_maker_.set_connection_id(cid1);
  alternate_socket_data.AddWrite(SYNCHRONOUS,
                                 client_maker_.MakeAckAndRetransmissionPacket(
                                     packet_num++,
                                     /*first_received=*/1,
                                     /*largest_received=*/peer_packet_num - 1,
                                     /*smallest_received=*/1,
                                     /*original_packet_numbers=*/{1}));
  alternate_socket_data.AddWrite(
      SYNCHRONOUS, client_maker_.Packet(packet_num++).AddPingFrame().Build());
  alternate_socket_data.AddWrite(
      ASYNC, client_maker_.Packet(packet_num++)
                 .AddRetireConnectionIdFrame(/*sequence_number=*/0u)
                 .Build());
  alternate_socket_data.AddReadPause();
  alternate_socket_data.AddRead(
      ASYNC, server_maker_.Packet(peer_packet_num++)
                 .AddNewConnectionIdFrame(cid2, /*sequence_number=*/2u,
                                          /*retire_prior_to=*/1u)
                 .Build());
  ++packet_num;  // Probing packet on default network encounters write error.
  alternate_socket_data.AddWrite(
      ASYNC, client_maker_.Packet(packet_num++)
                 .AddAckFrame(/*first_received=*/1,
                              /*largest_received=*/peer_packet_num - 1,
                              /*smallest_received=*/1)
                 .AddRetireConnectionIdFrame(/*sequence_number=*/2u)
                 .Build());
  alternate_socket_data.AddReadPause();
  alternate_socket_data.AddRead(
      ASYNC, server_maker_.Packet(peer_packet_num++)
                 .AddNewConnectionIdFrame(cid3, /*sequence_number=*/3u,
                                          /*retire_prior_to=*/1u)
                 .Build());
  ++packet_num;  // Probing packet on default network encounters write error.
  alternate_socket_data.AddWrite(
      ASYNC, client_maker_.Packet(packet_num++)
                 .AddAckFrame(/*first_received=*/1,
                              /*largest_received=*/peer_packet_num - 1,
                              /*smallest_received=*/1)
                 .AddRetireConnectionIdFrame(/*sequence_number=*/3u)
                 .Build());
  alternate_socket_data.AddReadPause();
  alternate_socket_data.AddRead(
      ASYNC, server_maker_.Packet(peer_packet_num++)
                 .AddNewConnectionIdFrame(cid4, /*sequence_number=*/4u,
                                          /*retire_prior_to=*/1u)
                 .Build());
  ++packet_num;  // Probing packet on default network encounters write error.
  alternate_socket_data.AddWrite(
      ASYNC, client_maker_.Packet(packet_num++)
                 .AddAckFrame(/*first_received=*/1,
                              /*largest_received=*/peer_packet_num - 1,
                              /*smallest_received=*/1)
                 .AddRetireConnectionIdFrame(/*sequence_number=*/4u)
                 .Build());
  alternate_socket_data.AddReadPause();
  alternate_socket_data.AddRead(
      ASYNC, server_maker_.Packet(peer_packet_num++)
                 .AddNewConnectionIdFrame(cid5, /*sequence_number=*/5u,
                                          /*retire_prior_to=*/1u)
                 .Build());
  alternate_socket_data.AddRead(SYNCHRONOUS,
                                ERR_IO_PENDING);  // Hanging read.
  alternate_socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Set up probing socket for migrating back to the default network.
  MockQuicData quic_data(version_);  // retry count: 0.
  quic_data.AddReadPauseForever();
  quic_data.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
  quic_data.AddSocketDataToFactory(socket_factory_.get());

  MockQuicData quic_data1(version_);  // retry count: 1
  quic_data1.AddReadPauseForever();
  quic_data1.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
  quic_data1.AddSocketDataToFactory(socket_factory_.get());

  MockQuicData quic_data2(version_);  // retry count: 2
  quic_data2.AddReadPauseForever();
  quic_data2.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
  quic_data2.AddSocketDataToFactory(socket_factory_.get());

  MockQuicData quic_data3(version_);  // retry count: 3
  quic_data3.AddReadPauseForever();
  quic_data3.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
  quic_data3.AddSocketDataToFactory(socket_factory_.get());

  MockQuicData quic_data4(version_);  // retry count: 4
  quic_data4.AddReadPauseForever();
  quic_data4.AddWrite(SYNCHRONOUS, ERR_ADDRESS_UNREACHABLE);
  quic_data4.AddSocketDataToFactory(socket_factory_.get());

  // Create request and QuicHttpStream.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Ensure that session is active.
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  // Trigger connection migration. Since there are no active streams,
  // the session will be closed.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkDisconnected(kDefaultNetworkForTests);

  // The nearest task will complete migration.
  EXPECT_EQ(2u, task_runner->GetPendingTaskCount());
  EXPECT_EQ(base::TimeDelta(), task_runner->NextPendingTaskDelay());
  task_runner->FastForwardBy(base::TimeDelta());

  // The migrate back timer will fire. Due to default network
  // being disconnected, no attempt will be exercised to migrate back.
  EXPECT_EQ(1u, task_runner->GetPendingTaskCount());
  EXPECT_EQ(base::Seconds(kMinRetryTimeForDefaultNetworkSecs),
            task_runner->NextPendingTaskDelay());
  task_runner->FastForwardBy(task_runner->NextPendingTaskDelay());
  EXPECT_EQ(0u, task_runner->GetPendingTaskCount());

  // Deliver the signal that the old default network now backs up.
  scoped_mock_network_change_notifier_->mock_network_change_notifier()
      ->NotifyNetworkMadeDefault(kDefaultNetworkForTests);

  // A task is posted to migrate back to the default network immediately.
  EXPECT_EQ(1u, task_runner->GetPendingTaskCount());
  EXPECT_EQ(base::TimeDelta(), task_runner->NextPendingTaskDelay());
  task_runner->FastForwardBy(base::TimeDelta());

  // Retry migrate back in 1, 2, 4, 8s.
  // Session will be closed due to idle migration timeout.
  for (int i = 0; i < 4; i++) {
    // Fire retire connection ID alarm.
    base::RunLoop().RunUntilIdle();
    // Make new connection ID available.
    alternate_socket_data.Resume();
    EXPECT_TRUE(HasActiveSession(kDefaultDestination));
    // A task is posted to migrate back to the default network in 2^i seconds.
    EXPECT_EQ(1u, task_runner->GetPendingTaskCount());
    EXPECT_EQ(base::Seconds(UINT64_C(1) << i),
              task_runner->NextPendingTaskDelay());
    task_runner->FastForwardBy(task_runner->NextPendingTaskDelay());
  }

  default_socket_data.ExpectAllReadDataConsumed();
  default_socket_data.ExpectAllWriteDataConsumed();
  alternate_socket_data.ExpectAllReadDataConsumed();
  alternate_socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, OnCertDBChanged) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  client_maker_.Reset();
  MockQuicData socket_data2(version_);
  socket_data2.AddReadPauseForever();
  socket_data2.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data2.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream);
  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);

  // Synthesize a CertDatabase change notification and verify that stream saw
  // the event.
  CertDatabase::GetInstance()->NotifyObserversTrustStoreChanged();
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(factory_->has_quic_ever_worked_on_current_network());
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));

  // Now attempting to request a stream to the same origin should create
  // a new session.

  RequestBuilder builder2(this);
  EXPECT_EQ(ERR_IO_PENDING, builder2.CallRequest());

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2);
  QuicChromiumClientSession* session2 = GetActiveSession(kDefaultDestination);
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_NE(session, session2);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session2));

  stream2.reset();
  stream.reset();

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
  socket_data2.ExpectAllReadDataConsumed();
  socket_data2.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, OnCertVerifierChanged) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  client_maker_.Reset();
  MockQuicData socket_data2(version_);
  socket_data2.AddReadPauseForever();
  socket_data2.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data2.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream);
  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);

  // Synthesize a CertVerifier change notification and verify that stream saw
  // the event.
  cert_verifier_->SimulateOnCertVerifierChanged();
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(factory_->has_quic_ever_worked_on_current_network());
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));

  // Now attempting to request a stream to the same origin should create
  // a new session.

  RequestBuilder builder2(this);
  EXPECT_EQ(ERR_IO_PENDING, builder2.CallRequest());

  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2);
  QuicChromiumClientSession* session2 = GetActiveSession(kDefaultDestination);
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
  EXPECT_NE(session, session2);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session2));

  stream2.reset();
  stream.reset();

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
  socket_data2.ExpectAllReadDataConsumed();
  socket_data2.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, SharedCryptoConfig) {
  Initialize();

  std::vector<string> cannoncial_suffixes;
  cannoncial_suffixes.emplace_back(".c.youtube.com");
  cannoncial_suffixes.emplace_back(".googlevideo.com");

  for (const auto& cannoncial_suffix : cannoncial_suffixes) {
    string r1_host_name("r1");
    string r2_host_name("r2");
    r1_host_name.append(cannoncial_suffix);
    r2_host_name.append(cannoncial_suffix);

    url::SchemeHostPort scheme_host_port1(url::kHttpsScheme, r1_host_name, 80);
    // Need to hold onto this through the test, to keep the
    // QuicCryptoClientConfig alive.
    std::unique_ptr<QuicCryptoClientConfigHandle> crypto_config_handle =
        QuicSessionPoolPeer::GetCryptoConfig(factory_.get(),
                                             NetworkAnonymizationKey());
    quic::QuicServerId server_id1(scheme_host_port1.host(),
                                  scheme_host_port1.port());
    quic::QuicCryptoClientConfig::CachedState* cached1 =
        crypto_config_handle->GetConfig()->LookupOrCreate(server_id1);
    EXPECT_FALSE(cached1->proof_valid());
    EXPECT_TRUE(cached1->source_address_token().empty());

    // Mutate the cached1 to have different data.
    // TODO(rtenneti): mutate other members of CachedState.
    cached1->set_source_address_token(r1_host_name);
    cached1->SetProofValid();

    url::SchemeHostPort scheme_host_port2(url::kHttpsScheme, r2_host_name, 80);
    quic::QuicServerId server_id2(scheme_host_port2.host(),
                                  scheme_host_port2.port());
    quic::QuicCryptoClientConfig::CachedState* cached2 =
        crypto_config_handle->GetConfig()->LookupOrCreate(server_id2);
    EXPECT_EQ(cached1->source_address_token(), cached2->source_address_token());
    EXPECT_TRUE(cached2->proof_valid());
  }
}

TEST_P(QuicSessionPoolTest, CryptoConfigWhenProofIsInvalid) {
  Initialize();
  std::vector<string> cannoncial_suffixes;
  cannoncial_suffixes.emplace_back(".c.youtube.com");
  cannoncial_suffixes.emplace_back(".googlevideo.com");

  for (const auto& cannoncial_suffix : cannoncial_suffixes) {
    string r3_host_name("r3");
    string r4_host_name("r4");
    r3_host_name.append(cannoncial_suffix);
    r4_host_name.append(cannoncial_suffix);

    url::SchemeHostPort scheme_host_port1(url::kHttpsScheme, r3_host_name, 80);
    // Need to hold onto this through the test, to keep the
    // QuicCryptoClientConfig alive.
    std::unique_ptr<QuicCryptoClientConfigHandle> crypto_config_handle =
        QuicSessionPoolPeer::GetCryptoConfig(factory_.get(),
                                             NetworkAnonymizationKey());
    quic::QuicServerId server_id1(scheme_host_port1.host(),
                                  scheme_host_port1.port());
    quic::QuicCryptoClientConfig::CachedState* cached1 =
        crypto_config_handle->GetConfig()->LookupOrCreate(server_id1);
    EXPECT_FALSE(cached1->proof_valid());
    EXPECT_TRUE(cached1->source_address_token().empty());

    // Mutate the cached1 to have different data.
    // TODO(rtenneti): mutate other members of CachedState.
    cached1->set_source_address_token(r3_host_name);
    cached1->SetProofInvalid();

    url::SchemeHostPort scheme_host_port2(url::kHttpsScheme, r4_host_name, 80);
    quic::QuicServerId server_id2(scheme_host_port2.host(),
                                  scheme_host_port2.port());
    quic::QuicCryptoClientConfig::CachedState* cached2 =
        crypto_config_handle->GetConfig()->LookupOrCreate(server_id2);
    EXPECT_NE(cached1->source_address_token(), cached2->source_address_token());
    EXPECT_TRUE(cached2->source_address_token().empty());
    EXPECT_FALSE(cached2->proof_valid());
  }
}

TEST_P(QuicSessionPoolTest, EnableNotLoadFromDiskCache) {
  Initialize();
  factory_->set_has_quic_ever_worked_on_current_network(true);
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), runner_.get());

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  client_maker_.SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::ZERO_RTT);
  host_resolver_->set_synchronous_mode(true);
  host_resolver_->rules()->AddIPLiteralRule(kDefaultServerHostName,
                                            "192.168.0.1", "");

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());

  // If we are waiting for disk cache, we would have posted a task. Verify that
  // the CancelWaitForDataReady task hasn't been posted.
  ASSERT_EQ(0u, runner_->GetPostedTasks().size());

  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());
  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, ReducePingTimeoutOnConnectionTimeOutOpenStreams) {
  quic_params_->reduced_ping_timeout = base::Seconds(10);
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  QuicSessionPoolPeer::SetTaskRunner(factory_.get(), runner_.get());

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  client_maker_.Reset();
  MockQuicData socket_data2(version_);
  socket_data2.AddReadPauseForever();
  socket_data2.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data2.AddSocketDataToFactory(socket_factory_.get());

  url::SchemeHostPort server2(url::kHttpsScheme, kServer2HostName,
                              kDefaultServerPort);

  crypto_client_stream_factory_.set_handshake_mode(
      MockCryptoClientStream::CONFIRM_HANDSHAKE);
  host_resolver_->set_synchronous_mode(true);
  host_resolver_->rules()->AddIPLiteralRule(kDefaultServerHostName,
                                            "192.168.0.1", "");
  host_resolver_->rules()->AddIPLiteralRule(server2.host(), "192.168.0.1", "");

  // Quic should use default PING timeout when no previous connection times out
  // with open stream.
  EXPECT_EQ(quic::QuicTime::Delta::FromSeconds(quic::kPingTimeoutSecs),
            QuicSessionPoolPeer::GetPingTimeout(factory_.get()));
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());

  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);

  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());
  HttpRequestInfo request_info;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream->RegisterRequest(&request_info);
  EXPECT_EQ(OK, stream->InitializeStream(false, DEFAULT_PRIORITY, net_log_,
                                         CompletionOnceCallback()));

  DVLOG(1)
      << "Created 1st session and initialized a stream. Now trigger timeout";
  session->connection()->CloseConnection(
      quic::QUIC_NETWORK_IDLE_TIMEOUT, "test",
      quic::ConnectionCloseBehavior::SILENT_CLOSE);
  // Need to spin the loop now to ensure that
  // QuicSessionPool::OnSessionClosed() runs.
  base::RunLoop run_loop;
  run_loop.RunUntilIdle();

  // The first connection times out with open stream, QUIC should reduce initial
  // PING time for subsequent connections.
  EXPECT_EQ(quic::QuicTime::Delta::FromSeconds(10),
            QuicSessionPoolPeer::GetPingTimeout(factory_.get()));

  // Test two-in-a-row timeouts with open streams.
  DVLOG(1) << "Create 2nd session and timeout with open stream";
  TestCompletionCallback callback2;
  RequestBuilder builder2(this);
  builder2.destination = server2;
  builder2.url = GURL(kServer2Url);
  builder2.callback = callback2.callback();
  EXPECT_EQ(ERR_IO_PENDING, builder2.CallRequest());
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  QuicChromiumClientSession* session2 = GetActiveSession(server2);

  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());
  stream2->RegisterRequest(&request_info);
  EXPECT_EQ(OK, stream2->InitializeStream(false, DEFAULT_PRIORITY, net_log_,
                                          CompletionOnceCallback()));
  session2->connection()->CloseConnection(
      quic::QUIC_NETWORK_IDLE_TIMEOUT, "test",
      quic::ConnectionCloseBehavior::SILENT_CLOSE);
  // Need to spin the loop now to ensure that
  // QuicSessionPool::OnSessionClosed() runs.
  base::RunLoop run_loop2;
  run_loop2.RunUntilIdle();

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
  socket_data2.ExpectAllReadDataConsumed();
  socket_data2.ExpectAllWriteDataConsumed();
}

// Verifies that the QUIC stream factory is initialized correctly.
TEST_P(QuicSessionPoolTest, MaybeInitialize) {
  VerifyInitialization(false /* vary_network_anonymization_key */);
}

TEST_P(QuicSessionPoolTest, MaybeInitializeWithNetworkAnonymizationKey) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);
  // Since HttpServerProperties caches the feature value, have to create a new
  // one.
  http_server_properties_ = std::make_unique<HttpServerProperties>();

  VerifyInitialization(true /* vary_network_anonymization_key */);
}

// Without NetworkAnonymizationKeys enabled for HttpServerProperties, there
// should only be one global CryptoCache.
TEST_P(QuicSessionPoolTest, CryptoConfigCache) {
  const char kUserAgentId[] = "spoon";

  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndDisableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);

  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);

  const SchemefulSite kSite3(GURL("https://baz.test/"));
  const auto kNetworkAnonymizationKey3 =
      NetworkAnonymizationKey::CreateSameSite(kSite3);

  Initialize();

  // Create a QuicCryptoClientConfigHandle for kNetworkAnonymizationKey1, and
  // set the user agent.
  std::unique_ptr<QuicCryptoClientConfigHandle> crypto_config_handle1 =
      QuicSessionPoolPeer::GetCryptoConfig(factory_.get(),
                                           kNetworkAnonymizationKey1);
  crypto_config_handle1->GetConfig()->set_user_agent_id(kUserAgentId);
  EXPECT_EQ(kUserAgentId, crypto_config_handle1->GetConfig()->user_agent_id());

  // Create another crypto config handle using a different
  // NetworkAnonymizationKey while the first one is still alive should return
  // the same config, with the user agent that was just set.
  std::unique_ptr<QuicCryptoClientConfigHandle> crypto_config_handle2 =
      QuicSessionPoolPeer::GetCryptoConfig(factory_.get(),
                                           kNetworkAnonymizationKey2);
  EXPECT_EQ(kUserAgentId, crypto_config_handle2->GetConfig()->user_agent_id());

  // Destroying both handles and creating a new one with yet another
  // NetworkAnonymizationKey should again return the same config.
  crypto_config_handle1.reset();
  crypto_config_handle2.reset();

  std::unique_ptr<QuicCryptoClientConfigHandle> crypto_config_handle3 =
      QuicSessionPoolPeer::GetCryptoConfig(factory_.get(),
                                           kNetworkAnonymizationKey3);
  EXPECT_EQ(kUserAgentId, crypto_config_handle3->GetConfig()->user_agent_id());
}

// With different NetworkAnonymizationKeys enabled for HttpServerProperties,
// there should only be one global CryptoCache per NetworkAnonymizationKey.
TEST_P(QuicSessionPoolTest, CryptoConfigCacheWithNetworkAnonymizationKey) {
  const char kUserAgentId1[] = "spoon";
  const char kUserAgentId2[] = "fork";
  const char kUserAgentId3[] = "another spoon";

  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);

  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);

  const SchemefulSite kSite3(GURL("https://baz.test/"));
  const auto kNetworkAnonymizationKey3 =
      NetworkAnonymizationKey::CreateSameSite(kSite3);

  Initialize();

  // Create a QuicCryptoClientConfigHandle for kNetworkAnonymizationKey1, and
  // set the user agent.
  std::unique_ptr<QuicCryptoClientConfigHandle> crypto_config_handle1 =
      QuicSessionPoolPeer::GetCryptoConfig(factory_.get(),
                                           kNetworkAnonymizationKey1);
  crypto_config_handle1->GetConfig()->set_user_agent_id(kUserAgentId1);
  EXPECT_EQ(kUserAgentId1, crypto_config_handle1->GetConfig()->user_agent_id());

  // Create another crypto config handle using a different
  // NetworkAnonymizationKey while the first one is still alive should return a
  // different config.
  std::unique_ptr<QuicCryptoClientConfigHandle> crypto_config_handle2 =
      QuicSessionPoolPeer::GetCryptoConfig(factory_.get(),
                                           kNetworkAnonymizationKey2);
  EXPECT_EQ("", crypto_config_handle2->GetConfig()->user_agent_id());
  crypto_config_handle2->GetConfig()->set_user_agent_id(kUserAgentId2);
  EXPECT_EQ(kUserAgentId1, crypto_config_handle1->GetConfig()->user_agent_id());
  EXPECT_EQ(kUserAgentId2, crypto_config_handle2->GetConfig()->user_agent_id());

  // Creating handles with the same NAKs while the old handles are still alive
  // should result in getting the same CryptoConfigs.
  std::unique_ptr<QuicCryptoClientConfigHandle> crypto_config_handle1_2 =
      QuicSessi
```