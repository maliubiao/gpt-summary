Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's networking stack. This file seems to be a unit test for `ClientSocketPoolBase`.

Here's a plan to analyze the code and address the user's request:

1. **Identify the main purpose:** The file tests the `ClientSocketPoolBase` class.
2. **Analyze individual test cases:** Each `TEST_F` function represents a specific scenario being tested. I will summarize the functionality of each test.
3. **Look for connections to JavaScript:**  Client-side networking in Chromium interacts with JavaScript through APIs. I'll consider if any test cases demonstrate or relate to these interactions (e.g., error handling, asynchronous operations).
4. **Identify logical reasoning:** Some tests might involve setting up specific conditions and asserting the outcome. I'll analyze these to provide hypothetical inputs and expected outputs.
5. **Spot common usage errors:**  Certain tests might simulate incorrect usage or scenarios that lead to errors. I'll highlight these and provide examples of how users might encounter these issues.
6. **Determine user actions leading to these tests:**  I'll think about the sequence of user interactions that would trigger the network operations being tested.
7. **Summarize the overall functionality:** Based on the analysis of the individual test cases, I will synthesize a concise summary of the file's purpose.
```cpp
tSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));

  // Create the maximum number of sockets in another group, which will prevent
  // the backup socket from being created.
  TestCompletionCallback callback2[kDefaultMaxSockets];
  ClientSocketHandle handle2[kDefaultMaxSockets];
  for (int i = 0; i < kDefaultMaxSockets; ++i) {
    EXPECT_EQ(
        ERR_IO_PENDING,
        handle2[i].Init(TestGroupId("b"), params_, std::nullopt,
                         DEFAULT_PRIORITY, SocketTag(),
                         ClientSocketPool::RespectLimits::ENABLED,
                         callback2[i].callback(),
                         ClientSocketPool::ProxyAuthCallback(), pool_.get(),
                         NetLogWithSource()));
  }

  // Cancel the initial request.
  handle.Reset();
  callback.Reset();

  // The backup timer fires, but no crash occurs, because the global socket
  // limit has been reached.
  FastForwardBy(
      base::Milliseconds(ClientSocketPool::kMaxConnectRetryIntervalMs * 100));

  // Let the pending requests finish.
  connect_job_factory_->SignalJob(0);
  for (int i = 0; i < kDefaultMaxSockets; ++i) {
    EXPECT_THAT(callback2[i].WaitForResult(), IsOk());
  }
}

// Test that backup connect jobs are created even if the initial job has a
// higher priority than the backup job.
TEST_F(ClientSocketPoolBaseTest, BackupSocketCreatedWithLowerPriority) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSockets,
             true /* enable_backup_connect_jobs */);

  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);
  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle.Init(TestGroupId("bar"), params_, std::nullopt, HIGHEST,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));

  // The backup timer fires and starts a new ConnectJob even though the original
  // job has a higher priority.
  FastForwardBy(
      base::Milliseconds(ClientSocketPool::kMaxConnectRetryIntervalMs));
  EXPECT_EQ(2, client_socket_factory_.allocation_count());
}

// Test that the backup socket doesn't get used if the primary connects first.
TEST_F(ClientSocketPoolBaseTest, BackupSocketNotUsedIfPrimaryConnectsFirst) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSockets,
             true /* enable_backup_connect_jobs */);

  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);
  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle.Init(TestGroupId("bar"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));

  // The backup timer fires and starts a new ConnectJob.
  FastForwardBy(
      base::Milliseconds(ClientSocketPool::kMaxConnectRetryIntervalMs));
  EXPECT_EQ(2, client_socket_factory_.allocation_count());

  // The primary socket connects.
  client_socket_factory_.SignalJob(0);
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  // The backup socket should get closed.
  EXPECT_EQ(2, client_socket_factory_.abandoned_count());
}

// Test that the backup socket gets used if the primary fails to connect first.
TEST_F(ClientSocketPoolBaseTest, BackupSocketUsedIfPrimaryFailsFirst) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSockets,
             true /* enable_backup_connect_jobs */);

  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);
  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle.Init(TestGroupId("bar"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));

  // The backup timer fires and starts a new ConnectJob.
  FastForwardBy(
      base::Milliseconds(ClientSocketPool::kMaxConnectRetryIntervalMs));
  EXPECT_EQ(2, client_socket_factory_.allocation_count());

  // The primary socket fails to connect.
  connect_job_factory_->set_job_type(TestConnectJob::kMockFailingJob);
  client_socket_factory_.SignalJob(0);
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  // The backup socket should have been used.
  EXPECT_EQ(1, client_socket_factory_.abandoned_count());
}

}  // namespace net
```

**功能归纳:**

这个代码文件是 Chromium 网络栈中 `net/socket/client_socket_pool_base_unittest.cc` 的一部分，专注于测试 `ClientSocketPoolBase` 类的功能。`ClientSocketPoolBase` 负责管理客户端套接字的连接池，用于复用连接以提高网络性能。

**具体来说，这部分测试用例主要涵盖以下功能:**

* **获取连接状态 (GetLoadState):** 测试在不同的场景下，例如等待连接、正在连接、达到组限制、达到池限制等情况下，如何正确地获取连接的加载状态。
* **处理证书错误:** 测试同步和异步连接过程中遇到的证书错误 (如 `ERR_CERT_COMMON_NAME_INVALID`) 的处理流程。
* **处理额外的错误状态:** 测试在连接过程中出现额外错误状态 (例如需要客户端证书) 的处理，包括同步和异步情况。
* **连接复用和超时:**  测试空闲套接字的清理和复用机制，包括基于时间超时的清理，以及在清理超时后是否能正确复用连接。
* **处理断开连接的套接字:** 测试在多个套接字断开连接后，连接池如何处理挂起的请求，以及是否能维持请求的优先级顺序。
* **套接字限制:** 测试在达到全局或组套接字限制时，连接池的行为。
* **网络状态变更 (Flush):** 测试在网络状态发生变化时 (`FlushWithError`)，连接池如何清理旧的连接，以及如何处理正在进行的请求。
* **在回调中建立新连接:** 测试在连接建立完成的回调函数中尝试建立新连接的情况。
* **备用连接 (Backup Sockets):** 测试备用连接的功能，包括在主连接等待时启动备用连接，以及在主连接成功或失败后备用连接的处理逻辑。

**与 JavaScript 的关系:**

虽然这段 C++ 代码本身不直接包含 JavaScript 代码，但 `ClientSocketPoolBase` 的功能是为 Chromium 浏览器提供底层网络连接管理。JavaScript 通过 Chromium 提供的 Web API (如 `fetch` 或 `XMLHttpRequest`) 发起网络请求时，最终会使用到 `ClientSocketPoolBase` 来管理 TCP 连接。

**举例说明:**

假设一个网页上的 JavaScript 代码使用 `fetch` API 发起多个到同一域名的 HTTP 请求。`ClientSocketPoolBase` 会尝试复用已有的 TCP 连接，而不是为每个请求都建立新的连接。这部分测试用例就覆盖了在连接复用场景下的各种情况，例如：

* **连接已存在且空闲:** 测试 `CleanupTimedOutIdleSocketsReuse` 模拟了这种情况，当 JavaScript 发起新的请求时，可以直接复用之前空闲的连接，而不需要重新建立。
* **连接正在建立:**  其他测试用例模拟了并发请求的情况，`ClientSocketPoolBase` 会管理这些并发连接的建立过程，并维护连接的状态，JavaScript 可以通过某些内部机制获取这些状态信息（虽然 JavaScript 本身不直接访问 `GetLoadState`）。
* **连接出错:** 测试用例如 `CertError` 和 `AsyncCertError` 模拟了连接过程中出现证书错误的情况。当 JavaScript 发起的请求遇到这些错误时，会抛出相应的异常或返回错误状态。

**逻辑推理 (假设输入与输出):**

**示例 1: `LoadStateConnecting` 测试**

* **假设输入:**
    * 创建一个允许两个并发连接的连接池。
    * 发起两个到同一目标服务器的连接请求。
* **预期输出:**
    * 两个 `ClientSocketHandle` 对象都能获取到连接状态为 `LOAD_STATE_CONNECTING`。

**示例 2: `LoadStateGroupLimit` 测试**

* **假设输入:**
    * 创建一个允许最大 2 个连接，每个组最大 1 个连接的连接池。
    * 发起两个到同一分组的连接请求，第二个请求的优先级高于第一个。
* **预期输出:**
    * 第一个请求的状态为 `LOAD_STATE_WAITING_FOR_AVAILABLE_SOCKET` (因为达到了组限制)。
    * 第二个请求的状态为 `LOAD_STATE_CONNECTING` (因为它优先级更高)。

**用户或编程常见的使用错误:**

* **过早释放 `ClientSocketHandle`:** 用户（通常是 Chromium 内部的其他网络组件）在使用 `ClientSocketPoolBase` 时，如果过早地释放 `ClientSocketHandle`，可能会导致连接被意外中断。例如，在异步操作完成之前就释放了 `ClientSocketHandle`。
* **不正确处理连接错误:** 用户需要正确处理连接建立过程中可能出现的各种错误，例如证书错误、连接超时等。测试用例如 `CertError` 和 `AsyncCertError` 强调了这些错误处理的重要性。
* **不理解连接池的限制:** 用户需要了解连接池的全局和分组限制，避免因为超出限制而导致连接请求被阻塞。测试用例如 `LoadStateGroupLimit` 和 `LoadStatePoolLimit` 展示了这些限制的影响。

**用户操作到达这里的调试线索:**

作为一个开发者，当你遇到网络连接问题时，可能会需要调试 `ClientSocketPoolBase` 的行为。以下是一些可能触发到这些测试代码覆盖场景的用户操作：

1. **浏览网页:**  当用户访问一个网站时，浏览器会建立多个 TCP 连接来下载资源。如果连接池的行为不符合预期（例如连接没有被复用，或者连接建立失败），可能会触发到相关的测试场景。
2. **进行 HTTPS 连接:** HTTPS 连接涉及到 TLS 握手和证书验证。如果用户的系统时间不正确或者网站的证书有问题，可能会触发到证书错误相关的测试场景。
3. **网络状态切换:** 当用户的网络从 Wi-Fi 切换到移动网络，或者网络出现短暂中断时，会触发网络状态变更相关的测试场景，例如 `CallbackThatReleasesPool` 和 `DoNotReuseSocketAfterFlush`。
4. **下载大型文件:** 下载大型文件可能会导致建立多个并发连接，这会涉及到连接池的并发管理和限制处理，可能会触发到 `LoadStateGroupLimit` 和 `LoadStatePoolLimit` 等测试场景。
5. **使用需要客户端证书的网站:** 访问需要客户端证书的网站会触发到处理额外错误状态的测试场景，例如 `AdditionalErrorStateSynchronous` 和 `AdditionalErrorStateAsynchronous`。

**归纳一下它的功能:**

总而言之，这部分代码的功能是全面测试 Chromium 网络栈中 `ClientSocketPoolBase` 类的各种功能和边界情况，确保其能够正确地管理和复用客户端套接字连接，处理各种连接状态、错误和网络事件，从而保证浏览器网络请求的效率和稳定性。 这部分测试特别关注连接状态的获取、错误处理、连接复用、连接限制以及备用连接的机制。

### 提示词
```
这是目录为net/socket/client_socket_pool_base_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
v, IsError(ERR_IO_PENDING));
  client_socket_factory_.SetJobLoadState(1, LOAD_STATE_RESOLVING_HOST);

  // Each handle should reflect the state of its own job.
  EXPECT_EQ(LOAD_STATE_RESOLVING_HOST, handle.GetLoadState());
  EXPECT_EQ(LOAD_STATE_RESOLVING_HOST, handle2.GetLoadState());

  // Update the state of the first job.
  client_socket_factory_.SetJobLoadState(0, LOAD_STATE_CONNECTING);

  // Only the state of the first request should have changed.
  EXPECT_EQ(LOAD_STATE_CONNECTING, handle.GetLoadState());
  EXPECT_EQ(LOAD_STATE_RESOLVING_HOST, handle2.GetLoadState());

  // Update the state of the second job.
  client_socket_factory_.SetJobLoadState(1, LOAD_STATE_SSL_HANDSHAKE);

  // Only the state of the second request should have changed.
  EXPECT_EQ(LOAD_STATE_CONNECTING, handle.GetLoadState());
  EXPECT_EQ(LOAD_STATE_SSL_HANDSHAKE, handle2.GetLoadState());

  // Second job connects and the first request gets the socket.  The
  // second handle switches to the state of the remaining ConnectJob.
  client_socket_factory_.SignalJob(1);
  EXPECT_THAT(callback.WaitForResult(), IsOk());
  EXPECT_EQ(LOAD_STATE_CONNECTING, handle2.GetLoadState());
}

// Test GetLoadState in the case the per-group limit is reached.
TEST_F(ClientSocketPoolBaseTest, LoadStateGroupLimit) {
  CreatePool(2, 1);
  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);

  ClientSocketHandle handle;
  TestCompletionCallback callback;
  int rv = handle.Init(
      TestGroupId("a"), params_, std::nullopt, MEDIUM, SocketTag(),
      ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
      ClientSocketPool::ProxyAuthCallback(), pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_EQ(LOAD_STATE_CONNECTING, handle.GetLoadState());

  // Request another socket from the same pool, buth with a higher priority.
  // The first request should now be stalled at the socket group limit.
  ClientSocketHandle handle2;
  TestCompletionCallback callback2;
  rv = handle2.Init(TestGroupId("a"), params_, std::nullopt, HIGHEST,
                    SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                    callback2.callback(), ClientSocketPool::ProxyAuthCallback(),
                    pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_EQ(LOAD_STATE_WAITING_FOR_AVAILABLE_SOCKET, handle.GetLoadState());
  EXPECT_EQ(LOAD_STATE_CONNECTING, handle2.GetLoadState());

  // The first handle should remain stalled as the other socket goes through
  // the connect process.

  client_socket_factory_.SetJobLoadState(0, LOAD_STATE_SSL_HANDSHAKE);
  EXPECT_EQ(LOAD_STATE_WAITING_FOR_AVAILABLE_SOCKET, handle.GetLoadState());
  EXPECT_EQ(LOAD_STATE_SSL_HANDSHAKE, handle2.GetLoadState());

  client_socket_factory_.SignalJob(0);
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ(LOAD_STATE_WAITING_FOR_AVAILABLE_SOCKET, handle.GetLoadState());

  // Closing the second socket should cause the stalled handle to finally get a
  // ConnectJob.
  handle2.socket()->Disconnect();
  handle2.Reset();
  EXPECT_EQ(LOAD_STATE_CONNECTING, handle.GetLoadState());
}

// Test GetLoadState in the case the per-pool limit is reached.
TEST_F(ClientSocketPoolBaseTest, LoadStatePoolLimit) {
  CreatePool(2, 2);
  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);

  ClientSocketHandle handle;
  TestCompletionCallback callback;
  int rv = handle.Init(
      TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY, SocketTag(),
      ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
      ClientSocketPool::ProxyAuthCallback(), pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Request for socket from another pool.
  ClientSocketHandle handle2;
  TestCompletionCallback callback2;
  rv = handle2.Init(TestGroupId("b"), params_, std::nullopt, DEFAULT_PRIORITY,
                    SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                    callback2.callback(), ClientSocketPool::ProxyAuthCallback(),
                    pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Request another socket from the first pool.  Request should stall at the
  // socket pool limit.
  ClientSocketHandle handle3;
  TestCompletionCallback callback3;
  rv = handle3.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                    SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                    callback2.callback(), ClientSocketPool::ProxyAuthCallback(),
                    pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // The third handle should remain stalled as the other sockets in its group
  // goes through the connect process.

  EXPECT_EQ(LOAD_STATE_CONNECTING, handle.GetLoadState());
  EXPECT_EQ(LOAD_STATE_WAITING_FOR_STALLED_SOCKET_POOL, handle3.GetLoadState());

  client_socket_factory_.SetJobLoadState(0, LOAD_STATE_SSL_HANDSHAKE);
  EXPECT_EQ(LOAD_STATE_SSL_HANDSHAKE, handle.GetLoadState());
  EXPECT_EQ(LOAD_STATE_WAITING_FOR_STALLED_SOCKET_POOL, handle3.GetLoadState());

  client_socket_factory_.SignalJob(0);
  EXPECT_THAT(callback.WaitForResult(), IsOk());
  EXPECT_EQ(LOAD_STATE_WAITING_FOR_STALLED_SOCKET_POOL, handle3.GetLoadState());

  // Closing a socket should allow the stalled handle to finally get a new
  // ConnectJob.
  handle.socket()->Disconnect();
  handle.Reset();
  EXPECT_EQ(LOAD_STATE_CONNECTING, handle3.GetLoadState());
}

TEST_F(ClientSocketPoolBaseTest, CertError) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  connect_job_factory_->set_job_type(TestConnectJob::kMockCertErrorJob);

  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_EQ(
      ERR_CERT_COMMON_NAME_INVALID,
      handle.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));
  EXPECT_TRUE(handle.is_initialized());
  EXPECT_TRUE(handle.socket());
}

TEST_F(ClientSocketPoolBaseTest, AsyncCertError) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingCertErrorJob);
  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));
  EXPECT_EQ(LOAD_STATE_CONNECTING,
            pool_->GetLoadState(TestGroupId("a"), &handle));
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_CERT_COMMON_NAME_INVALID));
  EXPECT_TRUE(handle.is_initialized());
  EXPECT_TRUE(handle.socket());
}

TEST_F(ClientSocketPoolBaseTest, AdditionalErrorStateSynchronous) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  connect_job_factory_->set_job_type(
      TestConnectJob::kMockAdditionalErrorStateJob);

  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_EQ(
      ERR_CONNECTION_FAILED,
      handle.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));
  EXPECT_FALSE(handle.is_initialized());
  EXPECT_FALSE(handle.socket());
  EXPECT_TRUE(handle.is_ssl_error());
  EXPECT_TRUE(handle.ssl_cert_request_info());
}

TEST_F(ClientSocketPoolBaseTest, AdditionalErrorStateAsynchronous) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  connect_job_factory_->set_job_type(
      TestConnectJob::kMockPendingAdditionalErrorStateJob);
  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));
  EXPECT_EQ(LOAD_STATE_CONNECTING,
            pool_->GetLoadState(TestGroupId("a"), &handle));
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_CONNECTION_FAILED));
  EXPECT_FALSE(handle.is_initialized());
  EXPECT_FALSE(handle.socket());
  EXPECT_TRUE(handle.is_ssl_error());
  EXPECT_TRUE(handle.ssl_cert_request_info());
}

// Make sure we can reuse sockets.
TEST_F(ClientSocketPoolBaseTest, CleanupTimedOutIdleSocketsReuse) {
  CreatePoolWithIdleTimeouts(
      kDefaultMaxSockets, kDefaultMaxSocketsPerGroup,
      base::TimeDelta(),  // Time out unused sockets immediately.
      base::Days(1));     // Don't time out used sockets.

  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);

  ClientSocketHandle handle;
  TestCompletionCallback callback;
  int rv = handle.Init(
      TestGroupId("a"), params_, std::nullopt, LOWEST, SocketTag(),
      ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
      ClientSocketPool::ProxyAuthCallback(), pool_.get(), NetLogWithSource());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_EQ(LOAD_STATE_CONNECTING,
            pool_->GetLoadState(TestGroupId("a"), &handle));
  ASSERT_THAT(callback.WaitForResult(), IsOk());

  // Use and release the socket.
  EXPECT_EQ(1, handle.socket()->Write(nullptr, 1, CompletionOnceCallback(),
                                      TRAFFIC_ANNOTATION_FOR_TESTS));
  TestLoadTimingInfoConnectedNotReused(handle);
  handle.Reset();

  // Should now have one idle socket.
  ASSERT_EQ(1, pool_->IdleSocketCount());

  // Request a new socket. This should reuse the old socket and complete
  // synchronously.
  NetLogWithSource net_log_with_source =
      NetLogWithSource::Make(NetLogSourceType::NONE);
  rv = handle.Init(
      TestGroupId("a"), params_, std::nullopt, LOWEST, SocketTag(),
      ClientSocketPool::RespectLimits::ENABLED, CompletionOnceCallback(),
      ClientSocketPool::ProxyAuthCallback(), pool_.get(), net_log_with_source);
  ASSERT_THAT(rv, IsOk());
  EXPECT_TRUE(handle.is_reused());
  TestLoadTimingInfoConnectedReused(handle);

  ASSERT_TRUE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));

  auto entries =
      net_log_observer_.GetEntriesForSource(net_log_with_source.source());
  EXPECT_TRUE(LogContainsEvent(
      entries, 0, NetLogEventType::TCP_CLIENT_SOCKET_POOL_REQUESTED_SOCKET,
      NetLogEventPhase::NONE));
  EXPECT_TRUE(LogContainsBeginEvent(entries, 1, NetLogEventType::SOCKET_POOL));
  EXPECT_TRUE(LogContainsEntryWithType(
      entries, 2, NetLogEventType::SOCKET_POOL_REUSED_AN_EXISTING_SOCKET));
}

// Make sure we cleanup old unused sockets.
TEST_F(ClientSocketPoolBaseTest, CleanupTimedOutIdleSocketsNoReuse) {
  CreatePoolWithIdleTimeouts(
      kDefaultMaxSockets, kDefaultMaxSocketsPerGroup,
      base::TimeDelta(),   // Time out unused sockets immediately
      base::TimeDelta());  // Time out used sockets immediately

  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);

  // Startup two mock pending connect jobs, which will sit in the MessageLoop.

  ClientSocketHandle handle;
  TestCompletionCallback callback;
  int rv = handle.Init(
      TestGroupId("a"), params_, std::nullopt, LOWEST, SocketTag(),
      ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
      ClientSocketPool::ProxyAuthCallback(), pool_.get(), NetLogWithSource());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_EQ(LOAD_STATE_CONNECTING,
            pool_->GetLoadState(TestGroupId("a"), &handle));

  ClientSocketHandle handle2;
  TestCompletionCallback callback2;
  rv = handle2.Init(TestGroupId("a"), params_, std::nullopt, LOWEST,
                    SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                    callback2.callback(), ClientSocketPool::ProxyAuthCallback(),
                    pool_.get(), NetLogWithSource());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_EQ(LOAD_STATE_CONNECTING,
            pool_->GetLoadState(TestGroupId("a"), &handle2));

  // Cancel one of the requests.  Wait for the other, which will get the first
  // job.  Release the socket.  Run the loop again to make sure the second
  // socket is sitting idle and the first one is released (since ReleaseSocket()
  // just posts a DoReleaseSocket() task).

  handle.Reset();
  ASSERT_THAT(callback2.WaitForResult(), IsOk());
  // Get the NetLogSource for the socket, so the time out reason can be checked
  // at the end of the test.
  NetLogSource net_log_source2 = handle2.socket()->NetLog().source();
  // Use the socket.
  EXPECT_EQ(1, handle2.socket()->Write(nullptr, 1, CompletionOnceCallback(),
                                       TRAFFIC_ANNOTATION_FOR_TESTS));
  handle2.Reset();

  // We post all of our delayed tasks with a 2ms delay. I.e. they don't
  // actually become pending until 2ms after they have been created. In order
  // to flush all tasks, we need to wait so that we know there are no
  // soon-to-be-pending tasks waiting.
  FastForwardBy(base::Milliseconds(10));

  // Both sockets should now be idle.
  ASSERT_EQ(2, pool_->IdleSocketCount());

  // Request a new socket. This should cleanup the unused and timed out ones.
  // A new socket will be created rather than reusing the idle one.
  NetLogWithSource net_log_with_source =
      NetLogWithSource::Make(NetLogSourceType::NONE);
  TestCompletionCallback callback3;
  rv = handle.Init(TestGroupId("a"), params_, std::nullopt, LOWEST, SocketTag(),
                   ClientSocketPool::RespectLimits::ENABLED,
                   callback3.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), net_log_with_source);
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  ASSERT_THAT(callback3.WaitForResult(), IsOk());
  EXPECT_FALSE(handle.is_reused());

  // Make sure the idle socket is closed.
  ASSERT_TRUE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));

  auto entries =
      net_log_observer_.GetEntriesForSource(net_log_with_source.source());
  EXPECT_FALSE(LogContainsEntryWithType(
      entries, 1, NetLogEventType::SOCKET_POOL_REUSED_AN_EXISTING_SOCKET));
  ExpectSocketClosedWithReason(
      net_log_source2, TransportClientSocketPool::kIdleTimeLimitExpired);
}

// Make sure that we process all pending requests even when we're stalling
// because of multiple releasing disconnected sockets.
TEST_F(ClientSocketPoolBaseTest, MultipleReleasingDisconnectedSockets) {
  CreatePoolWithIdleTimeouts(
      kDefaultMaxSockets, kDefaultMaxSocketsPerGroup,
      base::TimeDelta(),  // Time out unused sockets immediately.
      base::Days(1));     // Don't time out used sockets.

  connect_job_factory_->set_job_type(TestConnectJob::kMockJob);

  // Startup 4 connect jobs.  Two of them will be pending.

  ClientSocketHandle handle;
  TestCompletionCallback callback;
  int rv = handle.Init(
      TestGroupId("a"), params_, std::nullopt, LOWEST, SocketTag(),
      ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
      ClientSocketPool::ProxyAuthCallback(), pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsOk());

  ClientSocketHandle handle2;
  TestCompletionCallback callback2;
  rv = handle2.Init(TestGroupId("a"), params_, std::nullopt, LOWEST,
                    SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                    callback2.callback(), ClientSocketPool::ProxyAuthCallback(),
                    pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsOk());

  ClientSocketHandle handle3;
  TestCompletionCallback callback3;
  rv = handle3.Init(TestGroupId("a"), params_, std::nullopt, LOWEST,
                    SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                    callback3.callback(), ClientSocketPool::ProxyAuthCallback(),
                    pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  ClientSocketHandle handle4;
  TestCompletionCallback callback4;
  rv = handle4.Init(TestGroupId("a"), params_, std::nullopt, LOWEST,
                    SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                    callback4.callback(), ClientSocketPool::ProxyAuthCallback(),
                    pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Release two disconnected sockets.

  handle.socket()->Disconnect();
  handle.Reset();
  handle2.socket()->Disconnect();
  handle2.Reset();

  EXPECT_THAT(callback3.WaitForResult(), IsOk());
  EXPECT_FALSE(handle3.is_reused());
  EXPECT_THAT(callback4.WaitForResult(), IsOk());
  EXPECT_FALSE(handle4.is_reused());
}

// Regression test for http://crbug.com/42267.
// When DoReleaseSocket() is processed for one socket, it is blocked because the
// other stalled groups all have releasing sockets, so no progress can be made.
TEST_F(ClientSocketPoolBaseTest, SocketLimitReleasingSockets) {
  CreatePoolWithIdleTimeouts(
      4 /* socket limit */, 4 /* socket limit per group */,
      base::TimeDelta(),  // Time out unused sockets immediately.
      base::Days(1));     // Don't time out used sockets.

  connect_job_factory_->set_job_type(TestConnectJob::kMockJob);

  // Max out the socket limit with 2 per group.

  ClientSocketHandle handle_a[4];
  TestCompletionCallback callback_a[4];
  ClientSocketHandle handle_b[4];
  TestCompletionCallback callback_b[4];

  for (int i = 0; i < 2; ++i) {
    EXPECT_EQ(OK, handle_a[i].Init(TestGroupId("a"), params_, std::nullopt,
                                   LOWEST, SocketTag(),
                                   ClientSocketPool::RespectLimits::ENABLED,
                                   callback_a[i].callback(),
                                   ClientSocketPool::ProxyAuthCallback(),
                                   pool_.get(), NetLogWithSource()));
    EXPECT_EQ(OK, handle_b[i].Init(TestGroupId("b"), params_, std::nullopt,
                                   LOWEST, SocketTag(),
                                   ClientSocketPool::RespectLimits::ENABLED,
                                   callback_b[i].callback(),
                                   ClientSocketPool::ProxyAuthCallback(),
                                   pool_.get(), NetLogWithSource()));
  }

  // Make 4 pending requests, 2 per group.

  for (int i = 2; i < 4; ++i) {
    EXPECT_EQ(
        ERR_IO_PENDING,
        handle_a[i].Init(TestGroupId("a"), params_, std::nullopt, LOWEST,
                         SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                         callback_a[i].callback(),
                         ClientSocketPool::ProxyAuthCallback(), pool_.get(),
                         NetLogWithSource()));
    EXPECT_EQ(
        ERR_IO_PENDING,
        handle_b[i].Init(TestGroupId("b"), params_, std::nullopt, LOWEST,
                         SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                         callback_b[i].callback(),
                         ClientSocketPool::ProxyAuthCallback(), pool_.get(),
                         NetLogWithSource()));
  }

  // Release b's socket first.  The order is important, because in
  // DoReleaseSocket(), we'll process b's released socket, and since both b and
  // a are stalled, but 'a' is lower lexicographically, we'll process group 'a'
  // first, which has a releasing socket, so it refuses to start up another
  // ConnectJob.  So, we used to infinite loop on this.
  handle_b[0].socket()->Disconnect();
  handle_b[0].Reset();
  handle_a[0].socket()->Disconnect();
  handle_a[0].Reset();

  // Used to get stuck here.
  base::RunLoop().RunUntilIdle();

  handle_b[1].socket()->Disconnect();
  handle_b[1].Reset();
  handle_a[1].socket()->Disconnect();
  handle_a[1].Reset();

  for (int i = 2; i < 4; ++i) {
    EXPECT_THAT(callback_b[i].WaitForResult(), IsOk());
    EXPECT_THAT(callback_a[i].WaitForResult(), IsOk());
  }
}

TEST_F(ClientSocketPoolBaseTest,
       ReleasingDisconnectedSocketsMaintainsPriorityOrder) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);

  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY),
              IsError(ERR_IO_PENDING));

  EXPECT_THAT((*requests())[0]->WaitForResult(), IsOk());
  EXPECT_THAT((*requests())[1]->WaitForResult(), IsOk());
  EXPECT_EQ(2u, completion_count());

  // Releases one connection.
  EXPECT_TRUE(ReleaseOneConnection(ClientSocketPoolTest::NO_KEEP_ALIVE));
  EXPECT_THAT((*requests())[2]->WaitForResult(), IsOk());

  EXPECT_TRUE(ReleaseOneConnection(ClientSocketPoolTest::NO_KEEP_ALIVE));
  EXPECT_THAT((*requests())[3]->WaitForResult(), IsOk());
  EXPECT_EQ(4u, completion_count());

  EXPECT_EQ(1, GetOrderOfRequest(1));
  EXPECT_EQ(2, GetOrderOfRequest(2));
  EXPECT_EQ(3, GetOrderOfRequest(3));
  EXPECT_EQ(4, GetOrderOfRequest(4));

  // Make sure we test order of all requests made.
  EXPECT_EQ(ClientSocketPoolTest::kIndexOutOfBounds, GetOrderOfRequest(5));
}

class TestReleasingSocketRequest : public TestCompletionCallbackBase {
 public:
  TestReleasingSocketRequest(TransportClientSocketPool* pool,
                             int expected_result,
                             bool reset_releasing_handle)
      : pool_(pool),
        expected_result_(expected_result),
        reset_releasing_handle_(reset_releasing_handle) {}

  ~TestReleasingSocketRequest() override = default;

  ClientSocketHandle* handle() { return &handle_; }

  CompletionOnceCallback callback() {
    return base::BindOnce(&TestReleasingSocketRequest::OnComplete,
                          base::Unretained(this));
  }

 private:
  void OnComplete(int result) {
    SetResult(result);
    if (reset_releasing_handle_) {
      handle_.Reset();
    }

    EXPECT_EQ(
        expected_result_,
        handle2_.Init(
            TestGroupId("a"),
            ClientSocketPool::SocketParams::CreateForHttpForTesting(),
            std::nullopt, DEFAULT_PRIORITY, SocketTag(),
            ClientSocketPool::RespectLimits::ENABLED, CompletionOnceCallback(),
            ClientSocketPool::ProxyAuthCallback(), pool_, NetLogWithSource()));
  }

  const raw_ptr<TransportClientSocketPool> pool_;
  int expected_result_;
  bool reset_releasing_handle_;
  ClientSocketHandle handle_;
  ClientSocketHandle handle2_;
};

TEST_F(ClientSocketPoolBaseTest, AdditionalErrorSocketsDontUseSlot) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  EXPECT_THAT(StartRequest(TestGroupId("b"), DEFAULT_PRIORITY), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("b"), DEFAULT_PRIORITY), IsOk());

  EXPECT_EQ(static_cast<int>(requests_size()),
            client_socket_factory_.allocation_count());

  connect_job_factory_->set_job_type(
      TestConnectJob::kMockPendingAdditionalErrorStateJob);
  TestReleasingSocketRequest req(pool_.get(), OK, false);
  EXPECT_EQ(ERR_IO_PENDING,
            req.handle()->Init(
                TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                req.callback(), ClientSocketPool::ProxyAuthCallback(),
                pool_.get(), NetLogWithSource()));
  // The next job should complete synchronously
  connect_job_factory_->set_job_type(TestConnectJob::kMockJob);

  EXPECT_THAT(req.WaitForResult(), IsError(ERR_CONNECTION_FAILED));
  EXPECT_FALSE(req.handle()->is_initialized());
  EXPECT_FALSE(req.handle()->socket());
  EXPECT_TRUE(req.handle()->is_ssl_error());
  EXPECT_TRUE(req.handle()->ssl_cert_request_info());
}

// http://crbug.com/44724 regression test.
// We start releasing the pool when we flush on network change.  When that
// happens, the only active references are in the ClientSocketHandles.  When a
// ConnectJob completes and calls back into the last ClientSocketHandle, that
// callback can release the last reference and delete the pool.  After the
// callback finishes, we go back to the stack frame within the now-deleted pool.
// Executing any code that refers to members of the now-deleted pool can cause
// crashes.
TEST_F(ClientSocketPoolBaseTest, CallbackThatReleasesPool) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingFailingJob);

  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));

  pool_->FlushWithError(ERR_NETWORK_CHANGED, "Network changed");

  // We'll call back into this now.
  callback.WaitForResult();
}

TEST_F(ClientSocketPoolBaseTest, DoNotReuseSocketAfterFlush) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);

  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));
  EXPECT_THAT(callback.WaitForResult(), IsOk());
  EXPECT_EQ(StreamSocketHandle::SocketReuseType::kUnused, handle.reuse_type());
  NetLogSource source = handle.socket()->NetLog().source();

  pool_->FlushWithError(ERR_NETWORK_CHANGED, "Network changed");

  handle.Reset();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(
      ERR_IO_PENDING,
      handle.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));
  EXPECT_THAT(callback.WaitForResult(), IsOk());
  EXPECT_EQ(StreamSocketHandle::SocketReuseType::kUnused, handle.reuse_type());

  ExpectSocketClosedWithReason(
      source, TransportClientSocketPool::kSocketGenerationOutOfDate);
}

class ConnectWithinCallback : public TestCompletionCallbackBase {
 public:
  ConnectWithinCallback(
      const ClientSocketPool::GroupId& group_id,
      const scoped_refptr<ClientSocketPool::SocketParams>& params,
      TransportClientSocketPool* pool)
      : group_id_(group_id), params_(params), pool_(pool) {}

  ConnectWithinCallback(const ConnectWithinCallback&) = delete;
  ConnectWithinCallback& operator=(const ConnectWithinCallback&) = delete;

  ~ConnectWithinCallback() override = default;

  int WaitForNestedResult() { return nested_callback_.WaitForResult(); }

  CompletionOnceCallback callback() {
    return base::BindOnce(&ConnectWithinCallback::OnComplete,
                          base::Unretained(this));
  }

 private:
  void OnComplete(int result) {
    SetResult(result);
    EXPECT_EQ(
        ERR_IO_PENDING,
        handle_.Init(group_id_, params_, std::nullopt, DEFAULT_PRIORITY,
                     SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                     nested_callback_.callback(),
                     ClientSocketPool::ProxyAuthCallback(), pool_,
                     NetLogWithSource()));
  }

  const ClientSocketPool::GroupId group_id_;
  const scoped_refptr<ClientSocketPool::SocketParams> params_;
  const raw_ptr<TransportClientSocketPool> pool_;
  ClientSocketHandle handle_;
  TestCompletionCallback nested_callback_;
};

TEST_F(ClientSocketPoolBaseTest, AbortAllRequestsOnFlush) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  // First job will be waiting until it gets aborted.
  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);

  ClientSocketHandle handle;
  ConnectWithinCallback callback(TestGroupId("a"), params_, pool_.get());
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));

  // Second job will be started during the first callback, and will
  // asynchronously complete with OK.
  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);
  pool_->FlushWithError(ERR_NETWORK_CHANGED, "Network changed");
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_NETWORK_CHANGED));
  EXPECT_THAT(callback.WaitForNestedResult(), IsOk());
}

TEST_F(ClientSocketPoolBaseTest, BackupSocketWaitsForHostResolution) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSockets,
             true /* enable_backup_connect_jobs */);

  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);
  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle.Init(TestGroupId("bar"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));
  // The backup timer fires but doesn't start a new ConnectJob while resolving
  // the hostname.
  client_socket_factory_.SetJobLoadState(0, LOAD_STATE_RESOLVING_HOST);
  FastForwardBy(
      base::Milliseconds(ClientSocketPool::kMaxConnectRetryIntervalMs * 100));
  EXPECT_EQ(1, client_socket_factory_.allocation_count());

  // Once the ConnectJob has finished resolving the hostname, the backup timer
  // will create a ConnectJob when it fires.
  client_socket_factory_.SetJobLoadState(0, LOAD_STATE_CONNECTING);
  FastForwardBy(
      base::Milliseconds(ClientSocketPool::kMaxConnectRetryIntervalMs));
  EXPECT_EQ(2, client_socket_factory_.allocation_count());
}

// Test that no backup socket is created when a ConnectJob connects before it
// completes.
TEST_F(ClientSocketPoolBaseTest, NoBackupSocketWhenConnected) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSockets,
             true /* enable_backup_connect_jobs */);

  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);
  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle.Init(TestGroupId("bar"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));
  // The backup timer fires but doesn't start a new ConnectJob while resolving
  // the hostname.
  client_socket_factory_.SetJobLoadState(0, LOAD_STATE_RESOLVING_HOST);
  FastForwardBy(
      base::Milliseconds(ClientSocketPool::kMaxConnectRetryIntervalMs * 100));
  EXPECT_EQ(1, client_socket_factory_.allocation_count());

  client_socket_factory_.SetJobLoadState(0, LOAD_STATE_SSL_HANDSHAKE);
  client_socket_factory_.SetJobHasEstablishedConnection(0);
  FastForwardBy(
      base::Milliseconds(ClientSocketPool::kMaxConnectRetryIntervalMs * 100));
  EXPECT_EQ(1, client_socket_factory_.allocation_count());
}

// Cancel a pending socket request while we're at max sockets,
// and verify that the backup socket firing doesn't cause a crash.
TEST_F(ClientSocketPoolBaseTest, BackupSocketCancelAtMaxSockets) {
  // Max 4 sockets globally, max 4 sockets per group.
  CreatePool(kDefaultMaxSockets, kDefaultMaxSockets,
             true /* enable_backup_connect_jobs */);

  // Create the first socket and set to ERR_IO_PENDING.  This starts the backup
  // timer.
  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);
  Clien
```