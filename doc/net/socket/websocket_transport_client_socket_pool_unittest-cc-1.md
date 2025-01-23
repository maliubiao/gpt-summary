Response:
The user wants a summary of the functionality of the provided C++ code snippet, focusing on its relation to Javascript, logical reasoning (with input/output examples), common user/programming errors, debugging steps, and a general function summary.

Let's break down each requirement:

1. **Functionality Listing:** This involves analyzing the test cases in the code and describing what each test verifies about the `WebSocketTransportClientSocketPool`.

2. **Relation to Javascript:**  WebSockets are a common technology used in web development, and Javascript is the primary language for client-side web interaction. The connection lies in how Javascript uses the WebSocket API to establish and interact with WebSocket servers, the underlying network stack being tested here.

3. **Logical Reasoning (Input/Output):**  For some tests, we can define hypothetical inputs (e.g., DNS resolution results) and predict the output (e.g., connection success or failure).

4. **User/Programming Errors:**  Consider common mistakes developers might make when working with WebSockets, and how this code might relate to catching or preventing them.

5. **Debugging Steps:** Think about how a developer might reach this code during debugging a WebSocket issue.

6. **General Function Summary:** A concise overall description of the code's purpose.

**Mental Sandbox:**

* I'll go through each `TEST_F` block and identify its purpose. Keywords like "IPv6RapidFail," "FirstSuccessWins," "LastFailureWins," "MaxSocketsEnforced," etc., are strong indicators.
* For Javascript relation, I'll focus on the high-level concepts of establishing a WebSocket connection, handling connection failures, and resource management, as these are areas where the underlying network stack matters to the Javascript developer.
* For logical reasoning, I'll pick a couple of straightforward tests (like the IPv4 fallback) and create simple input/output scenarios.
* For errors, I'll consider things like incorrect WebSocket URLs, connection limits, and handling asynchronous connection attempts.
* Debugging steps will involve scenarios like network connectivity problems, server issues, or unexpected connection behavior.

**Constraint Checklist & Confidence Score:**

1. List functionality: Yes
2. Javascript relation: Yes
3. Javascript examples: Yes
4. Logical reasoning: Yes
5. Input/Output: Yes
6. User errors: Yes
7. Debugging steps: Yes
8. Function summary: Yes
9. Part 2 of 2: Yes (This is the final summary)

Confidence Score: 5/5 - I'm confident I can address all the requirements.

Strategizing complete. I will now proceed with generating the response based on the above analysis.
这是对 `net/socket/websocket_transport_client_socket_pool_unittest.cc` 文件剩余部分的分析和功能归纳。

**功能列举:**

这部分测试用例主要集中在以下功能：

* **IPv6 快速失败回退到 IPv4:** 测试当 IPv6 连接尝试快速失败时，连接池是否能及时回退到 IPv4 连接，避免长时间等待。
* **先连接成功者胜出:** 测试当 IPv6 和 IPv4 连接同时尝试时，哪个连接先成功建立，就使用哪个连接。
* **所有连接失败才报告失败:** 测试只有当所有可能的连接尝试（IPv6 和 IPv4）都失败后，连接池才会报告连接失败。
* **网络挂起 (ERR_NETWORK_IO_SUSPENDED) 处理:** 测试当连接尝试因为网络挂起错误失败时，连接池是否会停止尝试后续的连接。
* **全局连接超时:** 测试连接池是否会受到全局连接超时时间的限制。
* **最大连接数限制 (MaxSocketsEnforced):** 测试连接池是否会强制执行最大连接数限制。
* **等待连接释放:** 测试当达到最大连接数时，新的连接请求会进入等待状态，直到有连接被释放。
* **释放连接后激活等待连接:** 测试当一个连接被释放后，等待队列中的连接请求能否被激活并建立连接。
* **连接池状态 (IsStalled):** 测试连接池在达到最大连接数且有请求等待时，是否能正确报告 `IsStalled` 状态。
* **取消等待连接:** 测试取消一个等待中的连接请求是否会解除连接池的 `IsStalled` 状态。
* **等待连接的加载状态:** 测试等待连接的加载状态是否为 `LOAD_STATE_WAITING_FOR_AVAILABLE_SOCKET`。
* **取消等待连接释放连接池:** 测试取消一个等待中的连接请求是否会释放连接池的资源。
* **使用错误刷新连接:** 测试当调用 `FlushWithError` 方法时，所有等待中和正在建立的连接都会被强制失败。
* **刷新错误后可以建立新连接:** 测试在调用 `FlushWithError` 方法后，是否仍然可以建立新的连接。
* **刷新错误不影响已建立的连接:** 测试 `FlushWithError` 方法不会影响已经成功建立并被 `ClientSocketHandle` 持有的连接。
* **取消请求回收 Socket:** 测试在 `ClientSocketHandle` 设置 Socket 但尚未回调用户时，取消请求是否能正确回收 Socket 资源。
* **Endpoint 锁只释放一次:** 测试 WebSocket 连接完成握手并关闭后，Endpoint 锁只会被释放一次，避免资源管理错误。
* **使用正确的 NetworkAnonymizationKey:** 测试 WebSocket 连接请求是否使用了正确的 `NetworkAnonymizationKey`。
* **TransportConnectJob 处理 DNS 别名:** 测试 `TransportConnectJob` 能否正确处理 DNS 解析返回的别名列表。
* **TransportConnectJob 处理无额外 DNS 别名:** 测试 `TransportConnectJob` 在没有额外 DNS 别名时也能正常工作。
* **加载状态 (LoadState):**  测试 `TransportConnectJob` 在不同阶段的加载状态报告，包括 DNS 解析中、连接中、等待可用 Socket 等。

**与 Javascript 的关系及举例说明:**

这些测试直接关系到 Javascript 中 WebSocket API 的可靠性和性能。当 Javascript 代码使用 `new WebSocket(url)` 尝试建立 WebSocket 连接时，Chromium 的网络栈（包括这里测试的 `WebSocketTransportClientSocketPool`）负责底层的连接管理。

* **连接失败处理:** 如果 Javascript 代码尝试连接一个不存在或者暂时不可用的 WebSocket 服务器，这些测试覆盖了网络栈如何处理连接失败、超时以及快速回退到其他地址类型（例如从 IPv6 回退到 IPv4）。开发者在 Javascript 中可以通过监听 `onerror` 事件来捕获这些失败。

  ```javascript
  const websocket = new WebSocket('ws://invalid-server.example.com');
  websocket.onerror = (event) => {
    console.error('WebSocket connection failed:', event);
  };
  ```

* **连接数限制:** 浏览器对同一域名下的 WebSocket 连接数量有限制。这里的测试确保了连接池能正确地管理和限制连接数。当 Javascript 代码尝试打开过多的 WebSocket 连接时，新的连接可能会被阻塞，直到有旧的连接关闭。

  ```javascript
  for (let i = 0; i < 50; i++) {
    const ws = new WebSocket('ws://example.com/socket');
    ws.onopen = () => console.log(`Socket ${i} opened`);
    ws.onerror = (err) => console.error(`Socket ${i} error:`, err);
    // ...
  }
  ```

* **连接性能:** IPv6 快速失败回退到 IPv4 的测试保证了在 IPv6 网络出现问题时，用户能够更快地建立连接，提升用户体验，这对于 Javascript WebSocket 应用的性能至关重要。

**逻辑推理、假设输入与输出:**

**假设输入:**

1. **IPv6RapidFail 测试:**
   * DNS 解析返回两个无法连接的 IPv6 地址和一个可连接的 IPv4 地址。
   * 连接池尝试连接第一个 IPv6 地址，快速失败。
   * 连接池尝试连接第二个 IPv6 地址，快速失败。
   * IPv6 回退定时器尚未超时。

**预期输出:**

* 连接池立即尝试连接 IPv4 地址。
* 连接成功，返回 IPv4 地址的 Socket。

2. **MaxSocketsEnforced 测试:**
   * 最大连接数 `kMaxSockets` 为 32。
   * 已经有 32 个 WebSocket 连接被成功建立并持有。
   * 发起一个新的连接请求。

**预期输出:**

* 新的连接请求返回 `ERR_IO_PENDING`，表示连接正在等待，因为已达到最大连接数。

**用户或编程常见的使用错误及举例说明:**

* **忘记处理连接错误:**  Javascript 开发者可能没有正确监听 WebSocket 的 `onerror` 事件，导致连接失败时应用没有合适的反馈或重试机制。

  ```javascript
  const ws = new WebSocket('ws://potentially-problematic-server.com');
  ws.onopen = () => console.log('Connected!');
  // 缺少 onerror 处理
  ```

* **不合理的重连策略:**  如果 Javascript 代码在连接失败后立即进行大量重连尝试，可能会超出浏览器的连接数限制，导致连接池进入 `IsStalled` 状态，反而使得连接更难成功建立。

* **资源泄漏:**  如果 Javascript 代码在 WebSocket 连接关闭后没有正确地清理资源（例如，移除事件监听器），可能会导致内存泄漏，虽然这与这里的 Socket Pool 直接关系不大，但与 WebSocket 的生命周期管理相关。

**用户操作如何一步步到达这里 (调试线索):**

一个开发者可能在调试以下场景时会深入到这个代码：

1. **用户报告 WebSocket 连接不稳定或经常失败:** 开发者可能会查看网络请求日志，发现连接尝试频繁失败，需要排查网络栈的连接管理部分。
2. **应用在高并发场景下出现连接阻塞:**  当有大量用户同时使用 WebSocket 功能时，开发者可能会怀疑连接池是否达到上限，需要查看连接池的实现和限制。
3. **IPv6 网络环境下连接问题:**  用户可能在 IPv6 网络下遇到连接问题，开发者需要排查 IPv6 连接和回退到 IPv4 的逻辑是否正确。
4. **排查特定错误码:**  如果网络请求返回了特定的错误码（例如 `ERR_NETWORK_IO_SUSPENDED` 或 `ERR_TIMED_OUT`），开发者可能会追踪这些错误码在网络栈中的处理逻辑。
5. **性能分析:** 开发者可能在进行性能分析时，发现 WebSocket 连接建立时间过长，需要查看连接池的优化策略，例如快速失败回退。

**功能归纳 (第 2 部分):**

这部分代码主要负责测试 `WebSocketTransportClientSocketPool` 在各种复杂场景下的连接管理和资源控制能力。它覆盖了连接失败时的回退策略、并发连接限制、连接等待和释放机制、以及错误处理流程。通过这些详尽的测试用例，可以确保 `WebSocketTransportClientSocketPool` 能够高效、稳定地管理 WebSocket 连接，为上层的 Javascript WebSocket API 提供可靠的基础。 这些测试也验证了连接池在处理 DNS 别名和维护正确的网络隔离密钥方面的正确性。

### 提示词
```
这是目录为net/socket/websocket_transport_client_socket_pool_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
_EQ("2.2.2.2", endpoint.ToStringWithoutPort());
}

// If all IPv6 addresses fail before the IPv4 fallback timeout, then the IPv4
// connections proceed immediately.
TEST_F(WebSocketTransportClientSocketPoolTest, IPv6RapidFail) {
  MockTransportClientSocketFactory::Rule rules[] = {
      // First IPv6 socket.
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kPendingFailing),
      // Second IPv6 socket.
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kPendingFailing),
      // This is the IPv4 socket.
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kSynchronous)};

  client_socket_factory_.SetRules(rules);

  // Resolve an AddressList with two IPv6 addresses and then an IPv4 address.
  host_resolver_->rules()->AddIPLiteralRule(
      "*", "2:abcd::3:4:ff,2:abcd::3:5:ff,2.2.2.2", std::string());

  TestCompletionCallback callback;
  ClientSocketHandle handle;
  int rv =
      handle.Init(group_id_, params_, std::nullopt /* proxy_annotation_tag */,
                  LOW, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  &pool_, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_FALSE(handle.socket());

  base::TimeTicks start(base::TimeTicks::Now());
  EXPECT_THAT(callback.WaitForResult(), IsOk());
  EXPECT_LT(base::TimeTicks::Now() - start,
            TransportConnectJob::kIPv6FallbackTime);
  ASSERT_TRUE(handle.socket());

  IPEndPoint endpoint;
  handle.socket()->GetPeerAddress(&endpoint);
  EXPECT_EQ("2.2.2.2", endpoint.ToStringWithoutPort());
}

// If two sockets connect successfully, the one which connected first wins (this
// can only happen if the sockets are different types, since sockets of the same
// type do not race).
TEST_F(WebSocketTransportClientSocketPoolTest, FirstSuccessWins) {
  client_socket_factory_.set_default_client_socket_type(
      MockTransportClientSocketFactory::Type::kTriggerable);

  // Resolve an AddressList with an IPv6 addresses and an IPv4 address.
  host_resolver_->rules()->AddIPLiteralRule("*", "2:abcd::3:4:ff,2.2.2.2",
                                            std::string());

  TestCompletionCallback callback;
  ClientSocketHandle handle;
  int rv =
      handle.Init(group_id_, params_, std::nullopt /* proxy_annotation_tag */,
                  LOW, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  &pool_, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  ASSERT_FALSE(handle.socket());

  base::OnceClosure ipv6_connect_trigger =
      client_socket_factory_.WaitForTriggerableSocketCreation();
  base::OnceClosure ipv4_connect_trigger =
      client_socket_factory_.WaitForTriggerableSocketCreation();

  std::move(ipv4_connect_trigger).Run();
  std::move(ipv6_connect_trigger).Run();

  EXPECT_THAT(callback.WaitForResult(), IsOk());
  ASSERT_TRUE(handle.socket());

  IPEndPoint endpoint;
  handle.socket()->GetPeerAddress(&endpoint);
  EXPECT_EQ("2.2.2.2", endpoint.ToStringWithoutPort());
}

// We should not report failure until all connections have failed.
TEST_F(WebSocketTransportClientSocketPoolTest, LastFailureWins) {
  client_socket_factory_.set_default_client_socket_type(
      MockTransportClientSocketFactory::Type::kDelayedFailing);
  base::TimeDelta delay = TransportConnectJob::kIPv6FallbackTime / 3;
  client_socket_factory_.set_delay(delay);

  // Resolve an AddressList with 4 IPv6 addresses and 2 IPv4 addresses.
  host_resolver_->rules()->AddIPLiteralRule("*",
                                            "1:abcd::3:4:ff,2:abcd::3:4:ff,"
                                            "3:abcd::3:4:ff,4:abcd::3:4:ff,"
                                            "1.1.1.1,2.2.2.2",
                                            std::string());

  // Expected order of events:
  // After 100ms: Connect to 1:abcd::3:4:ff times out
  // After 200ms: Connect to 2:abcd::3:4:ff times out
  // After 300ms: Connect to 3:abcd::3:4:ff times out, IPv4 fallback starts
  // After 400ms: Connect to 4:abcd::3:4:ff and 1.1.1.1 time out
  // After 500ms: Connect to 2.2.2.2 times out

  TestCompletionCallback callback;
  ClientSocketHandle handle;
  base::TimeTicks start(base::TimeTicks::Now());
  int rv =
      handle.Init(group_id_, params_, std::nullopt /* proxy_annotation_tag */,
                  LOW, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  &pool_, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_CONNECTION_FAILED));

  EXPECT_GE(base::TimeTicks::Now() - start, delay * 5);

  // The order is slightly timing-dependent, so don't assert on the order.
  EXPECT_THAT(handle.connection_attempts(),
              testing::UnorderedElementsAre(
                  ConnectionAttempt(IPEndPoint(ParseIP("1:abcd::3:4:ff"), 80),
                                    ERR_CONNECTION_FAILED),
                  ConnectionAttempt(IPEndPoint(ParseIP("2:abcd::3:4:ff"), 80),
                                    ERR_CONNECTION_FAILED),
                  ConnectionAttempt(IPEndPoint(ParseIP("3:abcd::3:4:ff"), 80),
                                    ERR_CONNECTION_FAILED),
                  ConnectionAttempt(IPEndPoint(ParseIP("4:abcd::3:4:ff"), 80),
                                    ERR_CONNECTION_FAILED),
                  ConnectionAttempt(IPEndPoint(ParseIP("1.1.1.1"), 80),
                                    ERR_CONNECTION_FAILED),
                  ConnectionAttempt(IPEndPoint(ParseIP("2.2.2.2"), 80),
                                    ERR_CONNECTION_FAILED)));
}

// Test that, if an address fails due to `ERR_NETWORK_IO_SUSPENDED`, we do not
// try subsequent addresses.
TEST_F(WebSocketTransportClientSocketPoolTest, Suspend) {
  // Resolve an AddressList with 4 IPv6 addresses and 2 IPv4 addresses.
  host_resolver_->rules()->AddIPLiteralRule("*",
                                            "1:abcd::3:4:ff,2:abcd::3:4:ff,"
                                            "3:abcd::3:4:ff,4:abcd::3:4:ff,"
                                            "1.1.1.1,2.2.2.2",
                                            std::string());

  // The first connection attempt will fail, after which no more will be
  // attempted.
  MockTransportClientSocketFactory::Rule rule(
      MockTransportClientSocketFactory::Type::kFailing,
      std::vector{IPEndPoint(ParseIP("1:abcd::3:4:ff"), 80)},
      ERR_NETWORK_IO_SUSPENDED);
  client_socket_factory_.SetRules(base::span_from_ref(rule));

  TestCompletionCallback callback;
  ClientSocketHandle handle;
  int rv =
      handle.Init(group_id_, params_, std::nullopt /* proxy_annotation_tag */,
                  LOW, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  &pool_, NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsError(ERR_NETWORK_IO_SUSPENDED));
  EXPECT_THAT(handle.connection_attempts(),
              testing::ElementsAre(
                  ConnectionAttempt(IPEndPoint(ParseIP("1:abcd::3:4:ff"), 80),
                                    ERR_NETWORK_IO_SUSPENDED)));
}

// Same as above, but with a asynchronous failure.
TEST_F(WebSocketTransportClientSocketPoolTest, SuspendAsync) {
  // Resolve an AddressList with 4 IPv6 addresses and 2 IPv4 addresses.
  host_resolver_->rules()->AddIPLiteralRule("*",
                                            "1:abcd::3:4:ff,2:abcd::3:4:ff,"
                                            "3:abcd::3:4:ff,4:abcd::3:4:ff,"
                                            "1.1.1.1,2.2.2.2",
                                            std::string());

  // The first connection attempt will fail, after which no more will be
  // attempted.
  MockTransportClientSocketFactory::Rule rule(
      MockTransportClientSocketFactory::Type::kPendingFailing,
      std::vector{IPEndPoint(ParseIP("1:abcd::3:4:ff"), 80)},
      ERR_NETWORK_IO_SUSPENDED);
  client_socket_factory_.SetRules(base::span_from_ref(rule));

  TestCompletionCallback callback;
  ClientSocketHandle handle;
  int rv =
      handle.Init(group_id_, params_, std::nullopt /* proxy_annotation_tag */,
                  LOW, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  &pool_, NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsError(ERR_NETWORK_IO_SUSPENDED));
  EXPECT_THAT(handle.connection_attempts(),
              testing::ElementsAre(
                  ConnectionAttempt(IPEndPoint(ParseIP("1:abcd::3:4:ff"), 80),
                                    ERR_NETWORK_IO_SUSPENDED)));
}

// Global timeout for all connects applies. This test is disabled by default
// because it takes 4 minutes. Run with --gtest_also_run_disabled_tests if you
// want to run it.
TEST_F(WebSocketTransportClientSocketPoolTest, DISABLED_OverallTimeoutApplies) {
  const base::TimeDelta connect_job_timeout =
      TransportConnectJob::ConnectionTimeout();

  client_socket_factory_.set_default_client_socket_type(
      MockTransportClientSocketFactory::Type::kDelayedFailing);
  client_socket_factory_.set_delay(base::Seconds(1) + connect_job_timeout / 6);

  // Resolve an AddressList with 6 IPv6 addresses and 6 IPv4 addresses.
  host_resolver_->rules()->AddIPLiteralRule("*",
                                            "1:abcd::3:4:ff,2:abcd::3:4:ff,"
                                            "3:abcd::3:4:ff,4:abcd::3:4:ff,"
                                            "5:abcd::3:4:ff,6:abcd::3:4:ff,"
                                            "1.1.1.1,2.2.2.2,3.3.3.3,"
                                            "4.4.4.4,5.5.5.5,6.6.6.6",
                                            std::string());

  TestCompletionCallback callback;
  ClientSocketHandle handle;

  int rv =
      handle.Init(group_id_, params_, std::nullopt /* proxy_annotation_tag */,
                  LOW, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  &pool_, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_TIMED_OUT));
}

TEST_F(WebSocketTransportClientSocketPoolTest, MaxSocketsEnforced) {
  host_resolver_->set_synchronous_mode(true);
  for (int i = 0; i < kMaxSockets; ++i) {
    ASSERT_THAT(StartRequest(kDefaultPriority), IsOk());
    WebSocketTransportClientSocketPool::UnlockEndpoint(
        request(i)->handle(), &websocket_endpoint_lock_manager_);
    RunUntilIdle();
  }
  EXPECT_THAT(StartRequest(kDefaultPriority), IsError(ERR_IO_PENDING));
}

TEST_F(WebSocketTransportClientSocketPoolTest, MaxSocketsEnforcedWhenPending) {
  for (int i = 0; i < kMaxSockets + 1; ++i) {
    EXPECT_THAT(StartRequest(kDefaultPriority), IsError(ERR_IO_PENDING));
  }
  // Now there are 32 sockets waiting to connect, and one stalled.
  for (int i = 0; i < kMaxSockets; ++i) {
    RunUntilIdle();
    EXPECT_TRUE(request(i)->handle()->is_initialized());
    EXPECT_TRUE(request(i)->handle()->socket());
    WebSocketTransportClientSocketPool::UnlockEndpoint(
        request(i)->handle(), &websocket_endpoint_lock_manager_);
  }
  // Now there are 32 sockets connected, and one stalled.
  RunUntilIdle();
  EXPECT_FALSE(request(kMaxSockets)->handle()->is_initialized());
  EXPECT_FALSE(request(kMaxSockets)->handle()->socket());
}

TEST_F(WebSocketTransportClientSocketPoolTest, StalledSocketReleased) {
  host_resolver_->set_synchronous_mode(true);
  for (int i = 0; i < kMaxSockets; ++i) {
    ASSERT_THAT(StartRequest(kDefaultPriority), IsOk());
    WebSocketTransportClientSocketPool::UnlockEndpoint(
        request(i)->handle(), &websocket_endpoint_lock_manager_);
    RunUntilIdle();
  }

  EXPECT_THAT(StartRequest(kDefaultPriority), IsError(ERR_IO_PENDING));
  ReleaseOneConnection(ClientSocketPoolTest::NO_KEEP_ALIVE);
  EXPECT_TRUE(request(kMaxSockets)->handle()->is_initialized());
  EXPECT_TRUE(request(kMaxSockets)->handle()->socket());
}

TEST_F(WebSocketTransportClientSocketPoolTest, IsStalledTrueWhenStalled) {
  for (int i = 0; i < kMaxSockets + 1; ++i) {
    EXPECT_THAT(StartRequest(kDefaultPriority), IsError(ERR_IO_PENDING));
  }
  EXPECT_THAT(request(0)->WaitForResult(), IsOk());
  EXPECT_TRUE(pool_.IsStalled());
}

TEST_F(WebSocketTransportClientSocketPoolTest,
       CancellingPendingSocketUnstallsStalledSocket) {
  for (int i = 0; i < kMaxSockets + 1; ++i) {
    EXPECT_THAT(StartRequest(kDefaultPriority), IsError(ERR_IO_PENDING));
  }
  EXPECT_THAT(request(0)->WaitForResult(), IsOk());
  request(1)->handle()->Reset();
  RunUntilIdle();
  EXPECT_FALSE(pool_.IsStalled());
}

TEST_F(WebSocketTransportClientSocketPoolTest,
       LoadStateOfStalledSocketIsWaitingForAvailableSocket) {
  for (int i = 0; i < kMaxSockets + 1; ++i) {
    EXPECT_THAT(StartRequest(kDefaultPriority), IsError(ERR_IO_PENDING));
  }
  EXPECT_EQ(LOAD_STATE_WAITING_FOR_AVAILABLE_SOCKET,
            pool_.GetLoadState(group_id_, request(kMaxSockets)->handle()));
}

TEST_F(WebSocketTransportClientSocketPoolTest,
       CancellingStalledSocketUnstallsPool) {
  for (int i = 0; i < kMaxSockets + 1; ++i) {
    EXPECT_THAT(StartRequest(kDefaultPriority), IsError(ERR_IO_PENDING));
  }
  request(kMaxSockets)->handle()->Reset();
  RunUntilIdle();
  EXPECT_FALSE(pool_.IsStalled());
}

TEST_F(WebSocketTransportClientSocketPoolTest,
       FlushWithErrorFlushesPendingConnections) {
  EXPECT_THAT(StartRequest(kDefaultPriority), IsError(ERR_IO_PENDING));
  pool_.FlushWithError(ERR_FAILED, "Very good reason");
  EXPECT_THAT(request(0)->WaitForResult(), IsError(ERR_FAILED));
}

TEST_F(WebSocketTransportClientSocketPoolTest,
       FlushWithErrorFlushesStalledConnections) {
  for (int i = 0; i < kMaxSockets + 1; ++i) {
    EXPECT_THAT(StartRequest(kDefaultPriority), IsError(ERR_IO_PENDING));
  }
  pool_.FlushWithError(ERR_FAILED, "Very good reason");
  EXPECT_THAT(request(kMaxSockets)->WaitForResult(), IsError(ERR_FAILED));
}

TEST_F(WebSocketTransportClientSocketPoolTest,
       AfterFlushWithErrorCanMakeNewConnections) {
  for (int i = 0; i < kMaxSockets + 1; ++i) {
    EXPECT_THAT(StartRequest(kDefaultPriority), IsError(ERR_IO_PENDING));
  }
  pool_.FlushWithError(ERR_FAILED, "Very good reason");
  host_resolver_->set_synchronous_mode(true);
  EXPECT_THAT(StartRequest(kDefaultPriority), IsOk());
}

// Deleting pending connections can release the lock on the endpoint, which can
// in principle lead to other pending connections succeeding. However, when we
// call FlushWithError(), everything should fail.
TEST_F(WebSocketTransportClientSocketPoolTest,
       FlushWithErrorDoesNotCauseSuccessfulConnections) {
  host_resolver_->set_synchronous_mode(true);
  MockTransportClientSocketFactory::Rule first_rule[] = {
      // First socket
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kPending),
  };
  client_socket_factory_.SetRules(first_rule);
  // The rest of the sockets will connect synchronously.
  client_socket_factory_.set_default_client_socket_type(
      MockTransportClientSocketFactory::Type::kSynchronous);
  for (int i = 0; i < kMaxSockets; ++i) {
    EXPECT_THAT(StartRequest(kDefaultPriority), IsError(ERR_IO_PENDING));
  }
  // Now we have one socket in STATE_TRANSPORT_CONNECT and the rest in
  // STATE_OBTAIN_LOCK. If any of the sockets in STATE_OBTAIN_LOCK is given the
  // lock, they will synchronously connect.
  pool_.FlushWithError(ERR_FAILED, "Very good reason");
  for (int i = 0; i < kMaxSockets; ++i) {
    EXPECT_THAT(request(i)->WaitForResult(), IsError(ERR_FAILED));
  }
}

// This is a regression test for the first attempted fix for
// FlushWithErrorDoesNotCauseSuccessfulConnections. Because a ConnectJob can
// have both IPv4 and IPv6 subjobs, it can be both connecting and waiting for
// the lock at the same time.
TEST_F(WebSocketTransportClientSocketPoolTest,
       FlushWithErrorDoesNotCauseSuccessfulConnectionsMultipleAddressTypes) {
  host_resolver_->set_synchronous_mode(true);
  // The first |kMaxSockets| sockets to connect will be IPv6. Then we will have
  // one IPv4.
  std::vector<MockTransportClientSocketFactory::Rule> rules(
      kMaxSockets + 1, MockTransportClientSocketFactory::Rule(
                           MockTransportClientSocketFactory::Type::kStalled));
  client_socket_factory_.SetRules(rules);
  // The rest of the sockets will connect synchronously.
  client_socket_factory_.set_default_client_socket_type(
      MockTransportClientSocketFactory::Type::kSynchronous);
  for (int i = 0; i < kMaxSockets; ++i) {
    host_resolver_->rules()->ClearRules();
    // Each connect job has a different IPv6 address but the same IPv4 address.
    // So the IPv6 connections happen in parallel but the IPv4 ones are
    // serialised.
    host_resolver_->rules()->AddIPLiteralRule(
        "*",
        base::StringPrintf("%x:abcd::3:4:ff,"
                           "1.1.1.1",
                           i + 1),
        std::string());
    EXPECT_THAT(StartRequest(kDefaultPriority), IsError(ERR_IO_PENDING));
  }
  // Now we have |kMaxSockets| IPv6 sockets stalled in connect. No IPv4 sockets
  // are started yet.
  RunLoopForTimePeriod(TransportConnectJob::kIPv6FallbackTime);
  // Now we have |kMaxSockets| IPv6 sockets and one IPv4 socket stalled in
  // connect, and |kMaxSockets - 1| IPv4 sockets waiting for the endpoint lock.
  pool_.FlushWithError(ERR_FAILED, "Very good reason");
  for (int i = 0; i < kMaxSockets; ++i) {
    EXPECT_THAT(request(i)->WaitForResult(), IsError(ERR_FAILED));
  }
}

// Sockets that have had ownership transferred to a ClientSocketHandle should
// not be affected by FlushWithError.
TEST_F(WebSocketTransportClientSocketPoolTest,
       FlushWithErrorDoesNotAffectHandedOutSockets) {
  host_resolver_->set_synchronous_mode(true);
  MockTransportClientSocketFactory::Rule rules[] = {
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kSynchronous),
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kStalled)};
  client_socket_factory_.SetRules(rules);
  EXPECT_THAT(StartRequest(kDefaultPriority), IsOk());
  // Socket has been "handed out".
  EXPECT_TRUE(request(0)->handle()->socket());

  EXPECT_THAT(StartRequest(kDefaultPriority), IsError(ERR_IO_PENDING));
  // Now we have one socket handed out, and one pending.
  pool_.FlushWithError(ERR_FAILED, "Very good reason");
  EXPECT_THAT(request(1)->WaitForResult(), IsError(ERR_FAILED));
  // Socket owned by ClientSocketHandle is unaffected:
  EXPECT_TRUE(request(0)->handle()->socket());
  // Return it to the pool (which deletes it).
  request(0)->handle()->Reset();
}

// Sockets should not be leaked if CancelRequest() is called in between
// SetSocket() being called on the ClientSocketHandle and InvokeUserCallback().
TEST_F(WebSocketTransportClientSocketPoolTest, CancelRequestReclaimsSockets) {
  host_resolver_->set_synchronous_mode(true);
  MockTransportClientSocketFactory::Rule rules[] = {
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kTriggerable),
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kSynchronous)};

  client_socket_factory_.SetRules(rules);

  EXPECT_THAT(StartRequest(kDefaultPriority), IsError(ERR_IO_PENDING));

  base::OnceClosure connect_trigger =
      client_socket_factory_.WaitForTriggerableSocketCreation();

  std::move(connect_trigger).Run();  // Calls InvokeUserCallbackLater()

  request(0)->handle()->Reset();  // calls CancelRequest()

  RunUntilIdle();
  // We should now be able to create a new connection without blocking on the
  // endpoint lock.
  EXPECT_THAT(StartRequest(kDefaultPriority), IsOk());
}

// A handshake completing and then the WebSocket closing should only release one
// Endpoint, not two.
TEST_F(WebSocketTransportClientSocketPoolTest, EndpointLockIsOnlyReleasedOnce) {
  host_resolver_->set_synchronous_mode(true);
  ASSERT_THAT(StartRequest(kDefaultPriority), IsOk());
  EXPECT_THAT(StartRequest(kDefaultPriority), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(kDefaultPriority), IsError(ERR_IO_PENDING));
  // First socket completes handshake.
  WebSocketTransportClientSocketPool::UnlockEndpoint(
      request(0)->handle(), &websocket_endpoint_lock_manager_);
  RunUntilIdle();
  // First socket is closed.
  request(0)->handle()->Reset();
  // Second socket should have been released.
  EXPECT_THAT(request(1)->WaitForResult(), IsOk());
  // Third socket should still be waiting for endpoint.
  ASSERT_FALSE(request(2)->handle()->is_initialized());
  EXPECT_EQ(LOAD_STATE_WAITING_FOR_AVAILABLE_SOCKET,
            request(2)->handle()->GetLoadState());
}

// Make sure that WebSocket requests use the correct NetworkAnonymizationKey.
TEST_F(WebSocketTransportClientSocketPoolTest, NetworkAnonymizationKey) {
  const SchemefulSite kSite(GURL("https://foo.test/"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite);

  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  host_resolver_->set_ondemand_mode(true);

  TestCompletionCallback callback;
  ClientSocketHandle handle;
  ClientSocketPool::GroupId group_id(
      url::SchemeHostPort(url::kHttpScheme, "www.google.com", 80),
      PrivacyMode::PRIVACY_MODE_DISABLED, kNetworkAnonymizationKey,
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);
  EXPECT_THAT(
      handle.Init(group_id, params_, std::nullopt /* proxy_annotation_tag */,
                  kDefaultPriority, SocketTag(),
                  ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
                  ClientSocketPool::ProxyAuthCallback(), &pool_,
                  NetLogWithSource()),
      IsError(ERR_IO_PENDING));

  ASSERT_EQ(1u, host_resolver_->last_id());
  EXPECT_EQ(kNetworkAnonymizationKey,
            host_resolver_->request_network_anonymization_key(1));
}

TEST_F(WebSocketTransportClientSocketPoolTest,
       TransportConnectJobWithDnsAliases) {
  host_resolver_->set_synchronous_mode(true);
  client_socket_factory_.set_default_client_socket_type(
      MockTransportClientSocketFactory::Type::kSynchronous);

  // Resolve an AddressList with DNS aliases.
  std::string kHostName("host");
  std::vector<std::string> aliases({"alias1", "alias2", kHostName});
  host_resolver_->rules()->AddIPLiteralRuleWithDnsAliases(kHostName, "2.2.2.2",
                                                          std::move(aliases));

  TestConnectJobDelegate test_delegate;
  scoped_refptr<TransportSocketParams> params =
      base::MakeRefCounted<TransportSocketParams>(
          HostPortPair(kHostName, 80), NetworkAnonymizationKey(),
          SecureDnsPolicy::kAllow, OnHostResolutionCallback(),
          /*supported_alpns=*/base::flat_set<std::string>());

  TransportConnectJob transport_connect_job(
      DEFAULT_PRIORITY, SocketTag(), &common_connect_job_params_, params,
      &test_delegate, nullptr /* net_log */);

  test_delegate.StartJobExpectingResult(&transport_connect_job, OK,
                                        true /* expect_sync_result */);

  // Verify that the elements of the alias list are those from the
  // parameter vector.
  EXPECT_THAT(test_delegate.socket()->GetDnsAliases(),
              testing::ElementsAre("alias1", "alias2", kHostName));
}

TEST_F(WebSocketTransportClientSocketPoolTest,
       TransportConnectJobWithNoAdditionalDnsAliases) {
  host_resolver_->set_synchronous_mode(true);
  client_socket_factory_.set_default_client_socket_type(
      MockTransportClientSocketFactory::Type::kSynchronous);

  // Resolve an AddressList without additional DNS aliases. (The parameter
  // is an empty vector.)
  std::string kHostName("host");
  std::vector<std::string> aliases;
  host_resolver_->rules()->AddIPLiteralRuleWithDnsAliases(kHostName, "2.2.2.2",
                                                          std::move(aliases));

  TestConnectJobDelegate test_delegate;
  scoped_refptr<TransportSocketParams> params =
      base::MakeRefCounted<TransportSocketParams>(
          HostPortPair(kHostName, 80), NetworkAnonymizationKey(),
          SecureDnsPolicy::kAllow, OnHostResolutionCallback(),
          /*supported_alpns=*/base::flat_set<std::string>());

  TransportConnectJob transport_connect_job(
      DEFAULT_PRIORITY, SocketTag(), &common_connect_job_params_, params,
      &test_delegate, nullptr /* net_log */);

  test_delegate.StartJobExpectingResult(&transport_connect_job, OK,
                                        true /* expect_sync_result */);

  // Verify that the alias list only contains kHostName.
  EXPECT_THAT(test_delegate.socket()->GetDnsAliases(),
              testing::ElementsAre(kHostName));
}

TEST_F(WebSocketTransportClientSocketPoolTest, LoadState) {
  host_resolver_->rules()->AddRule("v6-only.test", "1:abcd::3:4:ff");
  host_resolver_->rules()->AddRule("v6-and-v4.test", "1:abcd::3:4:ff,2.2.2.2");
  host_resolver_->set_ondemand_mode(true);

  client_socket_factory_.set_default_client_socket_type(
      MockTransportClientSocketFactory::Type::kDelayedFailing);

  auto params_v6_only = base::MakeRefCounted<TransportSocketParams>(
      HostPortPair("v6-only.test", 80), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, OnHostResolutionCallback(),
      /*supported_alpns=*/base::flat_set<std::string>());
  auto params_v6_and_v4 = base::MakeRefCounted<TransportSocketParams>(
      HostPortPair("v6-and-v4.test", 80), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, OnHostResolutionCallback(),
      /*supported_alpns=*/base::flat_set<std::string>());

  // v6-only.test will first block on DNS.
  TestConnectJobDelegate test_delegate_v6_only;
  TransportConnectJob connect_job_v6_only(
      DEFAULT_PRIORITY, SocketTag(), &common_connect_job_params_,
      params_v6_only, &test_delegate_v6_only, /*net_log=*/nullptr);
  EXPECT_THAT(connect_job_v6_only.Connect(), test::IsError(ERR_IO_PENDING));
  EXPECT_THAT(connect_job_v6_only.GetLoadState(), LOAD_STATE_RESOLVING_HOST);

  // When DNS is resolved, it should block on making a connection.
  host_resolver_->ResolveOnlyRequestNow();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(connect_job_v6_only.GetLoadState(), LOAD_STATE_CONNECTING);

  // v6-and-v4.test will also first block on DNS.
  TestConnectJobDelegate test_delegate_v6_and_v4;
  TransportConnectJob connect_job_v6_and_v4(
      DEFAULT_PRIORITY, SocketTag(), &common_connect_job_params_,
      params_v6_and_v4, &test_delegate_v6_and_v4, /*net_log=*/nullptr);
  EXPECT_THAT(connect_job_v6_and_v4.Connect(), test::IsError(ERR_IO_PENDING));
  EXPECT_THAT(connect_job_v6_and_v4.GetLoadState(), LOAD_STATE_RESOLVING_HOST);

  // When DNS is resolved, it should attempt to connect to the IPv6 address, but
  // `connect_job_v6_only` holds the lock.
  host_resolver_->ResolveOnlyRequestNow();
  RunUntilIdle();
  EXPECT_THAT(connect_job_v6_and_v4.GetLoadState(),
              LOAD_STATE_WAITING_FOR_AVAILABLE_SOCKET);

  // After the IPv6 fallback timeout, it should attempt to connect to the IPv4
  // address. This lock is available, so `GetLoadState` should report it is now
  // actively connecting.
  RunLoopForTimePeriod(TransportConnectJob::kIPv6FallbackTime +
                       base::Milliseconds(50));
  EXPECT_THAT(connect_job_v6_and_v4.GetLoadState(), LOAD_STATE_CONNECTING);
}

}  // namespace

}  // namespace net
```