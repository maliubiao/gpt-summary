Response:
The user wants me to summarize the functionality of the provided C++ code snippet, which is part of a larger unit test file for Chromium's network stack, specifically focusing on the `TransportClientSocketPool`.

Here's a breakdown of the code's functionalities:

1. **Concurrent Request Handling and Cancellation:**  The code tests scenarios where multiple connection requests are made concurrently. It verifies the behavior when a request is cancelled while others are pending or active.
2. **Request Re-Initialization:**  It checks if a socket can be re-requested after being used and disconnected.
3. **Servicing Pending Requests after Cancellation/Failure:**  The tests confirm that pending requests are correctly processed after active requests are either cancelled or fail.
4. **Idle Socket Management and Timing:** The code examines how idle sockets are managed, including their reuse and the timing of connection setup (distinguishing between reused and newly created connections).
5. **Handling Network Configuration Changes:**  The tests simulate IP address changes and SSL configuration updates to ensure the socket pool correctly invalidates or manages existing connections.
6. **SSL Certificate Error Handling:** It verifies the socket pool's behavior when encountering SSL certificate errors.
7. **Backup Socket Connections:**  The code tests the functionality of creating backup socket connections when the primary connection is slow or stalled. This includes scenarios where the backup connection succeeds, is cancelled, or fails.
8. **SOCKS Proxy Support:** The tests include scenarios where SOCKS proxies are used.
9. **Specific HTTP/2 Error Handling:** There's a test case addressing a specific bug related to HTTP/2 authentication challenges when multiple requests are pending.

Now, let's structure the summary.
这个代码片段主要测试了 `TransportClientSocketPool` 在处理并发请求、取消请求、连接失败、网络状态变化以及 SSL 配置变化等场景下的行为。以下是更详细的归纳：

**核心功能归纳：**

1. **测试并发请求的处理：**
   - 验证当一个请求正在进行时，另一个相同 `GroupId` 的请求会被置于等待状态 (ERR_IO_PENDING)。
   - 模拟当第一个请求完成后，第二个请求能够继续处理。
   - 特别测试了在 host 解析同步的情况下，多个连接请求的生命周期和避免潜在的竞争条件。

2. **测试请求的取消 (CancelRequest)：**
   - 模拟在高并发请求的场景下取消一个请求，包括在连接建立之前和之后取消的情况。
   - 验证取消请求后，资源能被正确释放，并且后续的请求能按优先级顺序得到处理。
   - 检查取消请求是否会影响其他正在等待的请求的处理顺序。

3. **测试 socket 的重复请求 (RequestTwice)：**
   - 验证在 socket 使用后断开连接，可以被同一个 `GroupId` 的新请求复用。
   - 模拟在回调函数中立即发起新的连接请求的情况，测试连接池的处理能力。

4. **测试在活跃请求取消或失败后，等待请求的处理 (CancelActiveRequestWithPendingRequests, FailingActiveRequestWithPendingRequests)：**
   - 模拟创建多个待处理 (Pending) 状态的 socket 连接请求。
   - 验证当一部分活跃的连接被取消或连接失败后，剩余的等待请求能够被正确地处理。

5. **测试空闲 socket 的加载时序 (IdleSocketLoadTiming)：**
   - 验证从连接池中获取空闲 socket 的时序信息，包括连接是否被复用以及相应的加载时间信息。

6. **测试 IP 地址变化时空闲 socket 的处理 (CloseIdleSocketsOnIPAddressChange)：**
   - 模拟网络 IP 地址变化事件。
   - 验证连接池是否会正确关闭空闲的 socket 连接，以避免使用过时的连接。

7. **测试 SSL 证书错误的处理 (SSLCertError)：**
   - 模拟 SSL 连接过程中遇到证书错误 (例如：证书域名无效)。
   - 验证连接池能够正确返回相应的错误码 (ERR_CERT_COMMON_NAME_INVALID)。

8. **测试 SSL 配置变化的处理 (GracefulConfigChange)：**
   - 模拟 SSL 配置 (包括 SSL 配置本身、证书数据库、证书校验器) 的变化。
   - 验证连接池在这些变化发生后，能够优雅地处理已有的连接和等待中的请求，例如：关闭旧的空闲连接，并使用新的配置处理后续请求。

9. **测试备用 socket 连接 (BackupSocketConnect, BackupSocketCancel, BackupSocketFailAfterStall, BackupSocketFailAfterDelay)：**
   - 模拟主连接建立缓慢或停滞的情况。
   - 验证连接池是否会启动备用连接尝试，并在主连接或备用连接成功后进行处理。
   - 测试取消请求发生在备用连接尝试之前和之后的情况。
   - 模拟备用连接尝试失败的情况。

10. **测试 SOCKS 代理的使用 (SOCKS)：**
    - 验证 `TransportClientSocketPool` 可以处理使用 SOCKS 代理的连接请求。

11. **测试 HTTP/2 场景下的特定错误处理 (SpdyOneConnectJobTwoRequestsError)：**
    - 针对一个特定的 bug (crbug.com/940848)，模拟在 HTTP/2 连接中收到身份验证质询，并且存在两个等待请求的情况，确保不会发生崩溃。

**与 Javascript 功能的关系及举例：**

虽然这段代码是 C++ 写的，直接与 Javascript 交互不多，但它所测试的网络栈功能是 Javascript 在浏览器环境中发起网络请求的基础。

* **Ajax/Fetch API:** 当 Javascript 代码使用 `XMLHttpRequest` 或 `fetch` API 发起 HTTP/HTTPS 请求时，Chromium 的网络栈（包括 `TransportClientSocketPool`）负责管理底层的 socket 连接。
    * **假设输入:** Javascript 代码使用 `fetch('http://example.com')` 发起一个请求。
    * **逻辑推理:**  `TransportClientSocketPool` 会尝试从连接池中找到可用的 socket，如果没有，则会创建一个新的 socket 连接到 `example.com` 的 80 端口。
    * **输出:**  如果连接成功，Javascript 的 `fetch` API 会接收到服务器的响应。如果连接失败（例如，`example.com` 不可达），`fetch` API 会返回一个 rejected Promise 或触发 `onerror` 事件。

* **WebSockets:**  当 Javascript 使用 `WebSocket` API 创建 WebSocket 连接时，`TransportClientSocketPool` 也会参与到连接的建立过程中。虽然这个测试文件侧重于 HTTP/HTTPS，但底层的 socket 管理机制是相似的。
    * **假设输入:** Javascript 代码使用 `new WebSocket('ws://example.com/socket')` 创建一个 WebSocket 连接。
    * **逻辑推理:** `TransportClientSocketPool` (或者类似的 WebSocket 专用的连接池) 会处理与服务器建立 TCP 连接的过程。
    * **输出:** 如果连接成功，Javascript 的 `WebSocket` 对象会触发 `open` 事件。如果连接失败，则会触发 `error` 事件。

* **Service Workers:**  当 Service Worker 拦截到网络请求时，它可能会使用 `fetch` API 发起新的请求。这些请求也会经过 Chromium 的网络栈，并受到 `TransportClientSocketPool` 的管理。

**用户或编程常见的使用错误及举例：**

尽管这个是测试代码，但它反映了开发者在使用网络功能时可能遇到的问题：

* **在高并发场景下未正确处理连接复用:**  如果开发者在短时间内发起大量相同的请求，但没有合理地利用浏览器的连接池，可能会导致性能问题。`TransportClientSocketPool` 的测试确保了连接池能够有效地复用连接。

* **未处理网络连接错误:** Javascript 开发者需要编写代码来处理各种网络错误（例如，连接超时、连接被拒绝、DNS 解析失败）。`TransportClientSocketPool` 的测试覆盖了这些错误场景，确保网络栈能正确报告这些错误。
    * **举例:**  如果用户尝试访问一个不存在的网站，`TransportClientSocketPool` 可能会返回 `ERR_NAME_NOT_RESOLVED`，Javascript 代码应该捕获这个错误并向用户显示合适的提示。

* **未处理 SSL 证书错误:**  Javascript 代码通常依赖浏览器来处理 SSL 证书的验证。但是，开发者可能会遇到需要处理特定证书错误的情况（例如，通过一些特定的 API）。`TransportClientSocketPool` 的测试确保了这些错误能够被检测到。
    * **举例:**  如果用户访问的网站使用了无效的 SSL 证书，浏览器会显示警告，而 `TransportClientSocketPool` 内部会产生 `ERR_CERT_COMMON_NAME_INVALID` 等错误。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户在浏览器地址栏输入一个网址 (例如：`http://example.com`) 或点击一个链接。**
2. **浏览器解析 URL，确定协议、主机名和端口。**
3. **如果需要建立新的 TCP 连接，浏览器会查找或创建对应的 `ClientSocketPool::GroupId`。**
4. **`TransportClientSocketPool` 负责管理特定于 TCP 传输的 socket 连接。**
5. **浏览器会调用 `TransportClientSocketPool::RequestSocket()` 或类似的函数来请求一个 socket 连接。**
6. **如果连接池中有可用的空闲 socket，并且符合请求的 `GroupId`，则会直接返回该 socket。**  测试用例 `IdleSocketLoadTiming` 模拟了这种情况。
7. **如果没有可用的 socket，则会创建一个新的连接。** 这涉及到 DNS 解析、TCP 连接建立等过程。 测试用例覆盖了各种连接状态，包括同步和异步连接。
8. **如果在连接建立过程中发生错误（例如：连接超时、证书错误），`TransportClientSocketPool` 会返回相应的错误码。**  测试用例 `SSLCertError` 和模拟连接失败的用例就覆盖了这些情况。
9. **如果用户在连接建立过程中取消了请求（例如：点击了停止按钮或导航到其他页面），`TransportClientSocketPool` 会取消相应的连接尝试。** 测试用例 `CancelRequest` 模拟了这种情况。
10. **如果网络配置发生变化（例如：IP 地址变化），`TransportClientSocketPool` 会清理旧的连接。** 测试用例 `CloseIdleSocketsOnIPAddressChange` 模拟了这种情况。

总而言之，`TransportClientSocketPool` 的单元测试覆盖了网络连接建立和管理过程中的各种关键场景和边界情况，确保 Chromium 的网络栈能够稳定可靠地处理用户的网络请求。

### 提示词
```
这是目录为net/socket/transport_client_socket_pool_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
xy_annotation_tag */,
                  kDefaultPriority, SocketTag(),
                  ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
                  ClientSocketPool::ProxyAuthCallback(), pool_.get(),
                  NetLogWithSource()));

  handle.Reset();

  TestCompletionCallback callback2;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle.Init(group_id_, params_, std::nullopt /* proxy_annotation_tag */,
                  kDefaultPriority, SocketTag(),
                  ClientSocketPool::RespectLimits::ENABLED,
                  callback2.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));

  session_deps_.host_resolver->set_synchronous_mode(true);
  // At this point, handle has two ConnectingSockets out for it.  Due to the
  // setting the mock resolver into synchronous mode, the host resolution for
  // both will return in the same loop of the MessageLoop.  The client socket
  // is a pending socket, so the Connect() will asynchronously complete on the
  // next loop of the MessageLoop.  That means that the first
  // ConnectingSocket will enter OnIOComplete, and then the second one will.
  // If the first one is not cancelled, it will advance the load state, and
  // then the second one will crash.

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_FALSE(callback.have_result());

  handle.Reset();
}

TEST_F(TransportClientSocketPoolTest, CancelRequest) {
  // First request finishes asynchronously.
  EXPECT_THAT(StartRequest("a", kDefaultPriority), IsError(ERR_IO_PENDING));
  EXPECT_THAT((*requests())[0]->WaitForResult(), IsOk());

  // Make all subsequent host resolutions complete synchronously.
  session_deps_.host_resolver->set_synchronous_mode(true);

  EXPECT_THAT(StartRequest("a", kDefaultPriority), IsOk());
  EXPECT_THAT(StartRequest("a", kDefaultPriority), IsOk());
  EXPECT_THAT(StartRequest("a", kDefaultPriority), IsOk());
  EXPECT_THAT(StartRequest("a", kDefaultPriority), IsOk());
  EXPECT_THAT(StartRequest("a", kDefaultPriority), IsOk());

  // Reached per-group limit, queue up requests.
  EXPECT_THAT(StartRequest("a", LOWEST), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest("a", HIGHEST), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest("a", HIGHEST), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest("a", MEDIUM), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest("a", MEDIUM), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest("a", LOW), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest("a", HIGHEST), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest("a", LOW), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest("a", LOW), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest("a", LOWEST), IsError(ERR_IO_PENDING));

  // Cancel a request.
  size_t index_to_cancel = kMaxSocketsPerGroup + 2;
  EXPECT_FALSE((*requests())[index_to_cancel]->handle()->is_initialized());
  (*requests())[index_to_cancel]->handle()->Reset();

  ReleaseAllConnections(ClientSocketPoolTest::KEEP_ALIVE);

  EXPECT_EQ(kMaxSocketsPerGroup,
            client_socket_factory_.allocation_count());
  EXPECT_EQ(requests()->size() - kMaxSocketsPerGroup, completion_count());

  EXPECT_EQ(1, GetOrderOfRequest(1));
  EXPECT_EQ(2, GetOrderOfRequest(2));
  EXPECT_EQ(3, GetOrderOfRequest(3));
  EXPECT_EQ(4, GetOrderOfRequest(4));
  EXPECT_EQ(5, GetOrderOfRequest(5));
  EXPECT_EQ(6, GetOrderOfRequest(6));
  EXPECT_EQ(14, GetOrderOfRequest(7));
  EXPECT_EQ(7, GetOrderOfRequest(8));
  EXPECT_EQ(ClientSocketPoolTest::kRequestNotFound,
            GetOrderOfRequest(9));  // Canceled request.
  EXPECT_EQ(9, GetOrderOfRequest(10));
  EXPECT_EQ(10, GetOrderOfRequest(11));
  EXPECT_EQ(11, GetOrderOfRequest(12));
  EXPECT_EQ(8, GetOrderOfRequest(13));
  EXPECT_EQ(12, GetOrderOfRequest(14));
  EXPECT_EQ(13, GetOrderOfRequest(15));
  EXPECT_EQ(15, GetOrderOfRequest(16));

  // Make sure we test order of all requests made.
  EXPECT_EQ(ClientSocketPoolTest::kIndexOutOfBounds, GetOrderOfRequest(17));
}

class RequestSocketCallback : public TestCompletionCallbackBase {
 public:
  RequestSocketCallback(
      const ClientSocketPool::GroupId& group_id,
      scoped_refptr<ClientSocketPool::SocketParams> socket_params,
      ClientSocketHandle* handle,
      TransportClientSocketPool* pool)
      : group_id_(group_id),
        socket_params_(socket_params),
        handle_(handle),
        pool_(pool) {}

  RequestSocketCallback(const RequestSocketCallback&) = delete;
  RequestSocketCallback& operator=(const RequestSocketCallback&) = delete;

  ~RequestSocketCallback() override = default;

  CompletionOnceCallback callback() {
    return base::BindOnce(&RequestSocketCallback::OnComplete,
                          base::Unretained(this));
  }

 private:
  void OnComplete(int result) {
    SetResult(result);
    ASSERT_THAT(result, IsOk());

    if (!within_callback_) {
      // Don't allow reuse of the socket.  Disconnect it and then release it and
      // run through the MessageLoop once to get it completely released.
      handle_->socket()->Disconnect();
      handle_->Reset();
      base::RunLoop(base::RunLoop::Type::kNestableTasksAllowed).RunUntilIdle();
      within_callback_ = true;
      int rv = handle_->Init(
          group_id_, socket_params_, std::nullopt /* proxy_annotation_tag */,
          LOWEST, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
          callback(), ClientSocketPool::ProxyAuthCallback(), pool_,
          NetLogWithSource());
      EXPECT_THAT(rv, IsOk());
    }
  }

  const ClientSocketPool::GroupId group_id_;
  scoped_refptr<ClientSocketPool::SocketParams> socket_params_;
  const raw_ptr<ClientSocketHandle> handle_;
  const raw_ptr<TransportClientSocketPool> pool_;
  bool within_callback_ = false;
};

TEST_F(TransportClientSocketPoolTest, RequestTwice) {
  ClientSocketHandle handle;
  RequestSocketCallback callback(group_id_, params_, &handle, pool_.get());
  int rv =
      handle.Init(group_id_, params_, std::nullopt /* proxy_annotation_tag */,
                  LOWEST, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  // The callback is going to request "www.google.com". We want it to complete
  // synchronously this time.
  session_deps_.host_resolver->set_synchronous_mode(true);

  EXPECT_THAT(callback.WaitForResult(), IsOk());

  handle.Reset();
}

// Make sure that pending requests get serviced after active requests get
// cancelled.
TEST_F(TransportClientSocketPoolTest, CancelActiveRequestWithPendingRequests) {
  client_socket_factory_.set_default_client_socket_type(
      MockTransportClientSocketFactory::Type::kPending);

  // Queue up all the requests
  EXPECT_THAT(StartRequest("a", kDefaultPriority), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest("a", kDefaultPriority), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest("a", kDefaultPriority), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest("a", kDefaultPriority), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest("a", kDefaultPriority), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest("a", kDefaultPriority), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest("a", kDefaultPriority), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest("a", kDefaultPriority), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest("a", kDefaultPriority), IsError(ERR_IO_PENDING));

  // Now, kMaxSocketsPerGroup requests should be active.  Let's cancel them.
  ASSERT_LE(kMaxSocketsPerGroup, static_cast<int>(requests()->size()));
  for (int i = 0; i < kMaxSocketsPerGroup; i++)
    (*requests())[i]->handle()->Reset();

  // Let's wait for the rest to complete now.
  for (size_t i = kMaxSocketsPerGroup; i < requests()->size(); ++i) {
    EXPECT_THAT((*requests())[i]->WaitForResult(), IsOk());
    (*requests())[i]->handle()->Reset();
  }

  EXPECT_EQ(requests()->size() - kMaxSocketsPerGroup, completion_count());
}

// Make sure that pending requests get serviced after active requests fail.
TEST_F(TransportClientSocketPoolTest, FailingActiveRequestWithPendingRequests) {
  client_socket_factory_.set_default_client_socket_type(
      MockTransportClientSocketFactory::Type::kPendingFailing);

  const int kNumRequests = 2 * kMaxSocketsPerGroup + 1;
  ASSERT_LE(kNumRequests, kMaxSockets);  // Otherwise the test will hang.

  // Queue up all the requests
  for (int i = 0; i < kNumRequests; i++)
    EXPECT_THAT(StartRequest("a", kDefaultPriority), IsError(ERR_IO_PENDING));

  for (int i = 0; i < kNumRequests; i++)
    EXPECT_THAT((*requests())[i]->WaitForResult(),
                IsError(ERR_CONNECTION_FAILED));
}

TEST_F(TransportClientSocketPoolTest, IdleSocketLoadTiming) {
  TestCompletionCallback callback;
  ClientSocketHandle handle;
  int rv =
      handle.Init(group_id_, params_, std::nullopt /* proxy_annotation_tag */,
                  LOW, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_FALSE(handle.is_initialized());
  EXPECT_FALSE(handle.socket());

  EXPECT_THAT(callback.WaitForResult(), IsOk());
  EXPECT_TRUE(handle.is_initialized());
  EXPECT_TRUE(handle.socket());
  TestLoadTimingInfoConnectedNotReused(handle);

  handle.Reset();
  // Need to run all pending to release the socket back to the pool.
  base::RunLoop().RunUntilIdle();

  // Now we should have 1 idle socket.
  EXPECT_EQ(1, pool_->IdleSocketCount());

  rv = handle.Init(group_id_, params_, std::nullopt /* proxy_annotation_tag */,
                   LOW, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ(0, pool_->IdleSocketCount());
  TestLoadTimingInfoConnectedReused(handle);
}

TEST_F(TransportClientSocketPoolTest, CloseIdleSocketsOnIPAddressChange) {
  TestCompletionCallback callback;
  ClientSocketHandle handle;
  int rv =
      handle.Init(group_id_, params_, std::nullopt /* proxy_annotation_tag */,
                  LOW, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_FALSE(handle.is_initialized());
  EXPECT_FALSE(handle.socket());

  EXPECT_THAT(callback.WaitForResult(), IsOk());
  EXPECT_TRUE(handle.is_initialized());
  EXPECT_TRUE(handle.socket());

  handle.Reset();

  // Need to run all pending to release the socket back to the pool.
  base::RunLoop().RunUntilIdle();

  // Now we should have 1 idle socket.
  EXPECT_EQ(1, pool_->IdleSocketCount());

  // After an IP address change, we should have 0 idle sockets.
  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
  base::RunLoop().RunUntilIdle();  // Notification happens async.

  EXPECT_EQ(0, pool_->IdleSocketCount());
}

TEST(TransportClientSocketPoolStandaloneTest, DontCleanupOnIPAddressChange) {
  // This test manually sets things up in the same way
  // TransportClientSocketPoolTest does, but it creates a
  // TransportClientSocketPool with cleanup_on_ip_address_changed = false. Since
  // this is the only test doing this, it's not worth extending
  // TransportClientSocketPoolTest to support this scenario.
  base::test::SingleThreadTaskEnvironment task_environment;
  std::unique_ptr<MockCertVerifier> cert_verifier =
      std::make_unique<MockCertVerifier>();
  SpdySessionDependencies session_deps;
  session_deps.cert_verifier = std::move(cert_verifier);
  std::unique_ptr<HttpNetworkSession> http_network_session =
      SpdySessionDependencies::SpdyCreateSession(&session_deps);
  auto common_connect_job_params = std::make_unique<CommonConnectJobParams>(
      http_network_session->CreateCommonConnectJobParams());
  MockTransportClientSocketFactory client_socket_factory(NetLog::Get());
  common_connect_job_params->client_socket_factory = &client_socket_factory;

  scoped_refptr<ClientSocketPool::SocketParams> params(
      ClientSocketPool::SocketParams::CreateForHttpForTesting());
  auto pool = std::make_unique<TransportClientSocketPool>(
      kMaxSockets, kMaxSocketsPerGroup, kUnusedIdleSocketTimeout,
      ProxyChain::Direct(), /*is_for_websockets=*/false,
      common_connect_job_params.get(),
      /*cleanup_on_ip_address_change=*/false);
  const ClientSocketPool::GroupId group_id(
      url::SchemeHostPort(url::kHttpScheme, "www.google.com", 80),
      PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);
  TestCompletionCallback callback;
  ClientSocketHandle handle;
  int rv =
      handle.Init(group_id, params, std::nullopt /* proxy_annotation_tag */,
                  LOW, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_FALSE(handle.is_initialized());
  EXPECT_FALSE(handle.socket());

  EXPECT_THAT(callback.WaitForResult(), IsOk());
  EXPECT_TRUE(handle.is_initialized());
  EXPECT_TRUE(handle.socket());

  handle.Reset();
  // Need to run all pending to release the socket back to the pool.
  base::RunLoop().RunUntilIdle();
  // Now we should have 1 idle socket.
  EXPECT_EQ(1, pool->IdleSocketCount());

  // Since we set cleanup_on_ip_address_change = false, we should still have 1
  // idle socket after an IP address change.
  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
  base::RunLoop().RunUntilIdle();  // Notification happens async.
  EXPECT_EQ(1, pool->IdleSocketCount());
}

TEST_F(TransportClientSocketPoolTest, SSLCertError) {
  StaticSocketDataProvider data;
  tagging_client_socket_factory_.AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, ERR_CERT_COMMON_NAME_INVALID);
  tagging_client_socket_factory_.AddSSLSocketDataProvider(&ssl);

  const url::SchemeHostPort kEndpoint(url::kHttpsScheme, "ssl.server.test",
                                      443);

  scoped_refptr<ClientSocketPool::SocketParams> socket_params =
      base::MakeRefCounted<ClientSocketPool::SocketParams>(
          /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());

  ClientSocketHandle handle;
  TestCompletionCallback callback;
  int rv =
      handle.Init(ClientSocketPool::GroupId(
                      kEndpoint, PrivacyMode::PRIVACY_MODE_DISABLED,
                      NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                      /*disable_cert_network_fetches=*/false),
                  socket_params, std::nullopt /* proxy_annotation_tag */,
                  MEDIUM, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  tagging_pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_FALSE(handle.is_initialized());
  EXPECT_FALSE(handle.socket());

  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_CERT_COMMON_NAME_INVALID));
  EXPECT_TRUE(handle.is_initialized());
  EXPECT_TRUE(handle.socket());
}

namespace {
class TransportClientSocketPoolSSLConfigChangeTest
    : public TransportClientSocketPoolTest,
      public ::testing::WithParamInterface<
          SSLClientContext::SSLConfigChangeType> {
 public:
  void SimulateChange() {
    switch (GetParam()) {
      case SSLClientContext::SSLConfigChangeType::kSSLConfigChanged:
        session_deps_.ssl_config_service->NotifySSLContextConfigChange();
        break;
      case SSLClientContext::SSLConfigChangeType::kCertDatabaseChanged:
        // TODO(mattm): For more realistic testing this should call
        // `CertDatabase::GetInstance()->NotifyObserversCertDBChanged()`,
        // however that delivers notifications asynchronously, and running
        // the message loop to allow the notification to be delivered allows
        // other parts of the tested code to advance, breaking the test
        // expectations.
        pool_->OnSSLConfigChanged(GetParam());
        break;
      case SSLClientContext::SSLConfigChangeType::kCertVerifierChanged:
        session_deps_.cert_verifier->SimulateOnCertVerifierChanged();
        break;
    }
  }

  const char* ExpectedMessage() {
    switch (GetParam()) {
      case SSLClientContext::SSLConfigChangeType::kSSLConfigChanged:
        return TransportClientSocketPool::kNetworkChanged;
      case SSLClientContext::SSLConfigChangeType::kCertDatabaseChanged:
        return TransportClientSocketPool::kCertDatabaseChanged;
      case SSLClientContext::SSLConfigChangeType::kCertVerifierChanged:
        return TransportClientSocketPool::kCertVerifierChanged;
    }
  }
};
}  // namespace

TEST_P(TransportClientSocketPoolSSLConfigChangeTest, GracefulConfigChange) {
  // Create a request and finish connection of the socket, and release the
  // handle.
  {
    TestCompletionCallback callback;
    ClientSocketHandle handle1;
    int rv =
        handle1.Init(group_id_, params_, /*proxy_annotation_tag=*/std::nullopt,
                     LOW, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                     callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                     pool_.get(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    EXPECT_FALSE(handle1.is_initialized());
    EXPECT_FALSE(handle1.socket());

    EXPECT_THAT(callback.WaitForResult(), IsOk());
    EXPECT_TRUE(handle1.is_initialized());
    EXPECT_TRUE(handle1.socket());
    EXPECT_EQ(0, handle1.group_generation());
    EXPECT_EQ(0, pool_->IdleSocketCount());

    handle1.Reset();
  }

  // Need to run all pending to release the socket back to the pool.
  base::RunLoop().RunUntilIdle();

  // Now we should have 1 idle socket.
  EXPECT_EQ(1, pool_->IdleSocketCount());

  // Create another request and finish connection of the socket, but hold on to
  // the handle until later in the test.
  ClientSocketHandle handle2;
  {
    ClientSocketPool::GroupId group_id2(
        url::SchemeHostPort(url::kHttpScheme, "bar.example.com", 80),
        PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
        SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);
    TestCompletionCallback callback;
    int rv =
        handle2.Init(group_id2, params_, /*proxy_annotation_tag=*/std::nullopt,
                     LOW, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                     callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                     pool_.get(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    EXPECT_FALSE(handle2.is_initialized());
    EXPECT_FALSE(handle2.socket());

    EXPECT_THAT(callback.WaitForResult(), IsOk());
    EXPECT_TRUE(handle2.is_initialized());
    EXPECT_TRUE(handle2.socket());
    EXPECT_EQ(0, handle2.group_generation());
  }

  // Still only have 1 idle socket since handle2 is still alive.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, pool_->IdleSocketCount());

  // Create a pending request but don't finish connection.
  ClientSocketPool::GroupId group_id3(
      url::SchemeHostPort(url::kHttpScheme, "foo.example.com", 80),
      PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);
  TestCompletionCallback callback3;
  ClientSocketHandle handle3;
  int rv =
      handle3.Init(group_id3, params_, /*proxy_annotation_tag=*/std::nullopt,
                   LOW, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback3.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_FALSE(handle3.is_initialized());
  EXPECT_FALSE(handle3.socket());

  // Do a configuration change.
  RecordingNetLogObserver net_log_observer;
  SimulateChange();

  // Allow handle3 to advance.
  base::RunLoop().RunUntilIdle();
  // After a configuration change, we should have 0 idle sockets. The first
  // idle socket should have been closed, and handle2 and handle3 are still
  // alive.
  EXPECT_EQ(0, pool_->IdleSocketCount());

  // Verify the netlog messages recorded the correct reason for closing the
  // idle sockets.
  auto events = net_log_observer.GetEntriesWithType(
      NetLogEventType::SOCKET_POOL_CLOSING_SOCKET);
  ASSERT_EQ(events.size(), 1u);
  std::string* reason = events[0].params.FindString("reason");
  ASSERT_TRUE(reason);
  EXPECT_EQ(*reason, ExpectedMessage());

  // The pending request for handle3 should have succeeded under the new
  // generation since it didn't start until after the change.
  EXPECT_THAT(callback3.WaitForResult(), IsOk());
  EXPECT_TRUE(handle3.is_initialized());
  EXPECT_TRUE(handle3.socket());
  EXPECT_EQ(1, handle3.group_generation());

  // After releasing handle2, it does not become an idle socket since it was
  // part of the first generation.
  handle2.Reset();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, pool_->IdleSocketCount());

  // After releasing handle3, there is now one idle socket, since that socket
  // was connected during the new generation.
  handle3.Reset();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, pool_->IdleSocketCount());
}

INSTANTIATE_TEST_SUITE_P(
    All,
    TransportClientSocketPoolSSLConfigChangeTest,
    testing::Values(
        SSLClientContext::SSLConfigChangeType::kSSLConfigChanged,
        SSLClientContext::SSLConfigChangeType::kCertDatabaseChanged,
        SSLClientContext::SSLConfigChangeType::kCertVerifierChanged));

TEST_F(TransportClientSocketPoolTest, BackupSocketConnect) {
  // Case 1 tests the first socket stalling, and the backup connecting.
  MockTransportClientSocketFactory::Rule rules1[] = {
      // The first socket will not connect.
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kStalled),
      // The second socket will connect more quickly.
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kSynchronous),
  };

  // Case 2 tests the first socket being slow, so that we start the
  // second connect, but the second connect stalls, and we still
  // complete the first.
  MockTransportClientSocketFactory::Rule rules2[] = {
      // The first socket will connect, although delayed.
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kDelayed),
      // The second socket will not connect.
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kStalled),
  };

  base::span<const MockTransportClientSocketFactory::Rule> cases[2] = {rules1,
                                                                       rules2};

  for (auto rules : cases) {
    client_socket_factory_.SetRules(rules);

    EXPECT_EQ(0, pool_->IdleSocketCount());

    TestCompletionCallback callback;
    ClientSocketHandle handle;
    int rv =
        handle.Init(group_id_, params_, std::nullopt /* proxy_annotation_tag */,
                    LOW, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                    callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                    pool_.get(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    EXPECT_FALSE(handle.is_initialized());
    EXPECT_FALSE(handle.socket());

    // Create the first socket, set the timer.
    base::RunLoop().RunUntilIdle();

    // Wait for the backup socket timer to fire.
    base::PlatformThread::Sleep(
        base::Milliseconds(ClientSocketPool::kMaxConnectRetryIntervalMs + 50));

    // Let the appropriate socket connect.
    base::RunLoop().RunUntilIdle();

    EXPECT_THAT(callback.WaitForResult(), IsOk());
    EXPECT_TRUE(handle.is_initialized());
    EXPECT_TRUE(handle.socket());

    // One socket is stalled, the other is active.
    EXPECT_EQ(0, pool_->IdleSocketCount());
    handle.Reset();

    // Close all pending connect jobs and existing sockets.
    pool_->FlushWithError(ERR_NETWORK_CHANGED, "Network changed");
  }
}

// Test the case where a socket took long enough to start the creation
// of the backup socket, but then we cancelled the request after that.
TEST_F(TransportClientSocketPoolTest, BackupSocketCancel) {
  client_socket_factory_.set_default_client_socket_type(
      MockTransportClientSocketFactory::Type::kStalled);

  enum { CANCEL_BEFORE_WAIT, CANCEL_AFTER_WAIT };

  for (int index = CANCEL_BEFORE_WAIT; index < CANCEL_AFTER_WAIT; ++index) {
    EXPECT_EQ(0, pool_->IdleSocketCount());

    TestCompletionCallback callback;
    ClientSocketHandle handle;
    int rv =
        handle.Init(group_id_, params_, std::nullopt /* proxy_annotation_tag */,
                    LOW, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                    callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                    pool_.get(), NetLogWithSource());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    EXPECT_FALSE(handle.is_initialized());
    EXPECT_FALSE(handle.socket());

    // Create the first socket, set the timer.
    base::RunLoop().RunUntilIdle();

    if (index == CANCEL_AFTER_WAIT) {
      // Wait for the backup socket timer to fire.
      base::PlatformThread::Sleep(
          base::Milliseconds(ClientSocketPool::kMaxConnectRetryIntervalMs));
    }

    // Let the appropriate socket connect.
    base::RunLoop().RunUntilIdle();

    handle.Reset();

    EXPECT_FALSE(callback.have_result());
    EXPECT_FALSE(handle.is_initialized());
    EXPECT_FALSE(handle.socket());

    // One socket is stalled, the other is active.
    EXPECT_EQ(0, pool_->IdleSocketCount());
  }
}

// Test the case where a socket took long enough to start the creation
// of the backup socket and never completes, and then the backup
// connection fails.
TEST_F(TransportClientSocketPoolTest, BackupSocketFailAfterStall) {
  MockTransportClientSocketFactory::Rule rules[] = {
      // The first socket will not connect.
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kStalled),
      // The second socket will fail immediately.
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kFailing),
  };

  client_socket_factory_.SetRules(rules);

  EXPECT_EQ(0, pool_->IdleSocketCount());

  TestCompletionCallback callback;
  ClientSocketHandle handle;
  int rv =
      handle.Init(group_id_, params_, std::nullopt /* proxy_annotation_tag */,
                  LOW, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_FALSE(handle.is_initialized());
  EXPECT_FALSE(handle.socket());

  // Create the first socket, set the timer.
  base::RunLoop().RunUntilIdle();

  // Wait for the backup socket timer to fire.
  base::PlatformThread::Sleep(
      base::Milliseconds(ClientSocketPool::kMaxConnectRetryIntervalMs));

  // Let the second connect be synchronous. Otherwise, the emulated
  // host resolution takes an extra trip through the message loop.
  session_deps_.host_resolver->set_synchronous_mode(true);

  // Let the appropriate socket connect.
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_CONNECTION_FAILED));
  EXPECT_FALSE(handle.is_initialized());
  EXPECT_FALSE(handle.socket());
  ASSERT_EQ(1u, handle.connection_attempts().size());
  EXPECT_THAT(handle.connection_attempts()[0].result,
              IsError(ERR_CONNECTION_FAILED));
  EXPECT_EQ(0, pool_->IdleSocketCount());
  handle.Reset();
}

// Test the case where a socket took long enough to start the creation
// of the backup socket and eventually completes, but the backup socket
// fails.
TEST_F(TransportClientSocketPoolTest, BackupSocketFailAfterDelay) {
  MockTransportClientSocketFactory::Rule rules[] = {
      // The first socket will connect, although delayed.
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kDelayed),
      // The second socket will not connect.
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kFailing),
  };

  client_socket_factory_.SetRules(rules);
  client_socket_factory_.set_delay(base::Seconds(5));

  EXPECT_EQ(0, pool_->IdleSocketCount());

  TestCompletionCallback callback;
  ClientSocketHandle handle;
  int rv =
      handle.Init(group_id_, params_, std::nullopt /* proxy_annotation_tag */,
                  LOW, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_FALSE(handle.is_initialized());
  EXPECT_FALSE(handle.socket());

  // Create the first socket, set the timer.
  base::RunLoop().RunUntilIdle();

  // Wait for the backup socket timer to fire.
  base::PlatformThread::Sleep(
      base::Milliseconds(ClientSocketPool::kMaxConnectRetryIntervalMs));

  // Let the second connect be synchronous. Otherwise, the emulated
  // host resolution takes an extra trip through the message loop.
  session_deps_.host_resolver->set_synchronous_mode(true);

  // Let the appropriate socket connect.
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_CONNECTION_FAILED));
  EXPECT_FALSE(handle.is_initialized());
  EXPECT_FALSE(handle.socket());
  ASSERT_EQ(1u, handle.connection_attempts().size());
  EXPECT_THAT(handle.connection_attempts()[0].result,
              IsError(ERR_CONNECTION_FAILED));
  handle.Reset();
}

// Test the case that SOCKSSocketParams are provided.
TEST_F(TransportClientSocketPoolTest, SOCKS) {
  const url::SchemeHostPort kDestination(url::kHttpScheme, "host", 80);

  TransportClientSocketPool proxy_pool(
      kMaxSockets, kMaxSocketsPerGroup, kUnusedIdleSocketTimeout,
      ProxyUriToProxyChain("socks5://foopy",
                           /*default_scheme=*/ProxyServer::SCHEME_HTTP),
      /*is_for_websockets=*/false, tagging_common_connect_job_params_.get());

  for (IoMode socket_io_mode : {SYNCHRONOUS, ASYNC}) {
    scoped_refptr<ClientSocketPool::SocketParams> socket_params =
        ClientSocketPool::SocketParams::CreateForHttpForTesting();

    SOCKS5MockData data(socket_io_mode);
    data.data_provider()->set_connect_data(MockConnect(socket_io_mode, OK));
    tagging_client_socket_factory_.AddSocketDataProvider(data.data_provider());
    ClientSocketHandle handle;
    TestCompletionCallback callback;
    int rv = handle.Init(
        ClientSocketPool::GroupId(
            kDestination, PrivacyMode::PRIVACY_MODE_DISABLED,
            NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
            /*disable_cert_network_fetches=*/false),
        socket_params, TRAFFIC_ANNOTATION_FOR_TESTS, LOW, SocketTag(),
        ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
        ClientSocketPool::ProxyAuthCallback(), &proxy_pool, NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());
    EXPECT_TRUE(handle.is_initialized());
    EXPECT_TRUE(handle.socket());
    EXPECT_TRUE(data.data_provider()->AllReadDataConsumed());
    EXPECT_TRUE(data.data_provider()->AllWriteDataConsumed());
  }
}

// Make sure there's no crash when an auth challenge is received over HTTP2
// and there are two pending Requests to the socket pool, with a single
// ConnectJob.
//
// See https://crbug.com/940848
TEST_F(TransportClientSocketPoolTest, SpdyOneConnectJobTwoRequestsError) {
  const url::SchemeHostPort kEndpoint(url::kHttpsScheme,
                                      "unresolvable.host.name", 443);

  session_deps_.host_resolver->set_synchronous_mode(true);

  // Create a socket pool which only allows a single connection at a time.
  TransportClientSocketPool pool(
      1, 1, kUnusedIdleSocketTimeout,
      ProxyUriToProxyChain("https://unresolvable.proxy.name",
                           /*default_scheme=*/ProxyServer::SCHEME_HTTP),
      /*is_for_websockets=*/false, tagging_common_connect_job_params_.get());

  // First connection attempt w
```