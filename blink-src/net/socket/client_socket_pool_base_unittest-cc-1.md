Response:
The user wants me to analyze a C++ source code file related to Chromium's network stack. This is the second part of an 8-part file.

Here's a breakdown of what I need to do:

1. **Summarize the functionality of this code snippet.**  This involves understanding the purpose of the tests within this section.
2. **Identify connections to JavaScript.**  Since this is low-level network code, direct connections to JavaScript might be limited. I need to think about how network requests initiated by JavaScript eventually interact with this code.
3. **Provide examples of logical reasoning.** This involves creating hypothetical inputs and outputs for the test cases.
4. **Illustrate common user/programming errors.** I need to identify potential mistakes developers might make when interacting with or extending this code.
5. **Explain the user journey leading to this code.** This requires thinking about how a user action in a browser triggers network requests.
6. **Since this is part 2 of 8, I need to focus on summarizing the functionality *within this specific part*.** I shouldn't try to summarize the entire file.
这是 `net/socket/client_socket_pool_base_unittest.cc` 文件的第二部分，主要功能是测试 `ClientSocketPoolBase` 类的各种限制和优先级管理机制。以下是更详细的归纳：

**主要功能归纳：**

* **连接复用和隔离测试:**  验证了对于不同的 `GroupId` (由 scheme, host, port, PrivacyMode, NetworkAnonymizationKey 和 SecureDnsPolicy 组成)，连接不会被错误地复用。即使之前已经建立了连接，对于新的 `GroupId`，也会尝试建立新的连接。
* **全局连接数限制测试 (TotalLimit):**  测试了 `ClientSocketPoolBase` 是否能正确地限制全局范围内同时存在的连接数。当达到全局连接数限制时，新的连接请求会被挂起。
* **全局连接数限制对新 Group 的影响 (TotalLimitReachedNewGroup):**  验证了当全局连接数达到限制时，不会完全阻止新的 Group 建立连接。
* **全局连接数限制与优先级 (TotalLimitRespectsPriority):**  测试了全局连接数限制下，优先级较高的请求会优先获得连接。
* **请求的重新优先级排序 (ReprioritizeOne, ReprioritizeUpReorder, ReprioritizeUpNoReorder, ReprioritizeDownReorder, ReprioritizeResetFIFO):**  详细测试了在请求等待连接期间，动态修改请求的优先级是否能够影响连接的建立顺序。涵盖了提升优先级、降低优先级以及保持相对优先级的情况。
* **全局连接数限制与 Group 连接数限制的交互 (TotalLimitRespectsGroupLimit):**  验证了全局连接数限制和单个 Group 的连接数限制同时生效时的行为，确保两者都能得到遵守。
* **计算连接中的 Socket (TotalLimitCountsConnectingSockets):** 确认了正在建立连接的 Socket 也被计入全局连接数限制中。
* **正确计算被阻塞的 Group (CorrectlyCountStalledGroups):**  测试了当达到连接数限制时，对被阻塞的 Group 的计数是否正确。
* **阻塞后取消请求和触发可用 Socket (StallAndThenCancelAndTriggerAvailableSocket):**  测试了当请求因达到连接数限制而被阻塞后，如果取消请求，能否正确触发其他等待的请求。
* **在达到 Socket 限制时取消被阻塞的 Socket (CancelStalledSocketAtSocketLimit):**  测试了当达到全局 Socket 限制时，取消一个被阻塞的请求，资源能否正确释放。
* **在达到 Socket 限制时取消等待中的 Socket (CancelPendingSocketAtSocketLimit):** 测试了当达到全局 Socket 限制时，取消一个正在等待连接的请求，能否正确触发其他等待的请求。
* **等待达到 Socket 限制的 Socket (WaitForStalledSocketAtSocketLimit):** 测试了当达到全局 Socket 限制时，一个新请求会等待，直到有连接释放。
* **在 Socket 限制时关闭空闲 Socket 并删除 Group (CloseIdleSocketAtSocketLimitDeleteGroup):**  这是一个回归测试，用于确保在达到连接数限制时，可以正确地复用或关闭空闲连接。
* **处理等待中的请求 (PendingRequests, PendingRequests_NoKeepAlive):** 测试了当 Group 的连接数达到限制时，后续请求会被放入等待队列，并根据优先级进行处理。分别测试了保持连接 (KEEP_ALIVE) 和不保持连接 (NO_KEEP_ALIVE) 的情况。
* **重置并关闭 Socket (ResetAndCloseSocket):**  测试了 `ClientSocketHandle::ResetAndCloseSocket()` 方法能够正确地关闭连接并清理资源。
* **取消请求但保留 ConnectJob (CancelRequestKeepsConnectJob):**  测试了调用 `ClientSocketHandle::Reset()` 方法后，虽然请求被取消，但底层的 `ConnectJob` 对象仍然存在。
* **取消请求并关闭 Socket (CancelRequestAndCloseSocket, CancelRequestAndCloseSocketWhenMoreRequestsThanConnectJobs):**  测试了调用 `ClientSocketHandle::ResetAndCloseSocket()` 方法后，无论是正在等待连接还是已经建立连接，底层的 `ConnectJob` 或 Socket 都会被销毁。涵盖了请求数量多于连接数量的情况。

**与 JavaScript 功能的关系：**

`ClientSocketPoolBase` 是网络栈的核心组件，负责管理 Socket 连接的复用。虽然 JavaScript 代码本身不直接操作这个类，但当 JavaScript 发起网络请求时（例如使用 `fetch` API 或 `XMLHttpRequest`），这些请求最终会通过 Chromium 的网络栈，并可能使用到 `ClientSocketPoolBase` 中管理的连接。

**举例说明：**

假设一个网页的 JavaScript 代码使用 `fetch` API 向 `http://a.test/api` 发起多个请求。

1. **连接复用和隔离:**  如果网页稍后又向 `http://b.test/api` 发起请求，`ClientSocketPoolBase` 会确保为 `http://b.test/api` 建立新的连接，而不是复用之前为 `http://a.test/api` 建立的连接（除非两者属于相同的 `GroupId`，例如 PrivacyMode 和 NetworkAnonymizationKey 也相同）。
2. **全局连接数限制:** 如果网页快速发起大量并发的 `fetch` 请求，当达到浏览器或配置的全局连接数限制时，后续的 `fetch` 请求在 JavaScript 层面会表现为 pending 状态，直到有连接被释放。
3. **优先级:** 如果 JavaScript 代码使用 `fetch` API 的优先级提示（虽然目前 `fetch` 标准对此支持有限），或者通过某些方式影响 Chromium 网络栈的请求优先级，那么在连接数受限的情况下，优先级较高的 `fetch` 请求可能会比优先级较低的请求更快地获得连接。

**逻辑推理示例：**

**假设输入:**

* `kDefaultMaxSockets` (全局最大连接数) = 4
* 网页 JavaScript 代码连续发起 7 个对不同域名的 HTTP 请求 (例如 `http://a.test/`, `http://b.test/`, ..., `http://g.test/`)，每个请求的优先级都是默认值。

**输出:**

* 最开始的 4 个请求会立即建立连接并完成。
* 后面的 3 个请求会进入等待状态 (`ERR_IO_PENDING`)。
* 当前面 4 个连接中的任意一个被释放后，等待队列中的请求会按照先进先出的顺序（因为优先级相同）依次建立连接。

**用户或编程常见的使用错误：**

* **错误地认为连接会被随意复用:** 开发者可能会错误地认为只要是同一个域名，所有请求都会复用相同的连接。但实际上，`GroupId` 的其他因素（如 PrivacyMode, NetworkAnonymizationKey, SecureDnsPolicy）也会影响连接的复用。
* **没有处理并发请求过多导致的网络延迟:**  JavaScript 开发者如果发起过多的并发请求，可能会导致请求被 `ClientSocketPoolBase` 阻塞，从而造成页面加载缓慢。应该合理控制并发请求的数量。
* **不理解请求优先级的影响:**  在需要优化性能的场景下，开发者可能没有意识到可以利用请求优先级来优先处理关键资源，从而提升用户体验。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器地址栏输入网址或点击链接:** 这会触发一个导航请求。
2. **浏览器解析 URL 并确定目标服务器:** 网络栈开始解析域名。
3. **如果需要建立新的 TCP 连接:**  网络栈会调用 `ClientSocketPoolBase` 来获取一个可用的 Socket 连接。
4. **如果 `ClientSocketPoolBase` 中没有满足条件的空闲连接且未达到连接数限制:**  会创建一个新的 `ConnectJob` 来建立连接。
5. **如果达到了连接数限制:**  新的连接请求会被放入等待队列。
6. **如果用户在页面加载过程中又执行了某些 JavaScript 代码，发起了新的网络请求 (例如加载图片、AJAX 请求):** 这些请求也会经历类似的过程，并可能与之前的请求竞争连接资源。
7. **当开发者进行网络调试时 (例如使用 Chrome 的开发者工具):**  他们可能会看到请求的状态是 "pending"，这可能就是因为 `ClientSocketPoolBase` 的连接数限制或优先级策略导致请求在等待。

**总结第二部分的功能:**

总而言之，这部分代码主要负责测试 `ClientSocketPoolBase` 类在处理并发连接请求时，如何根据全局和 Group 的连接数限制、请求优先级等因素进行连接的管理和调度，确保网络连接的合理分配和高效利用。

Prompt: 
```
这是目录为net/socket/client_socket_pool_base_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共8部分，请归纳一下它的功能

"""
] = {PrivacyMode::PRIVACY_MODE_DISABLED,
                                       PrivacyMode::PRIVACY_MODE_ENABLED};

  const SchemefulSite kSiteA(GURL("http://a.test/"));
  const SchemefulSite kSiteB(GURL("http://b.test/"));
  const NetworkAnonymizationKey kNetworkAnonymizationKeys[] = {
      NetworkAnonymizationKey::CreateSameSite(kSiteA),
      NetworkAnonymizationKey::CreateSameSite(kSiteB),
  };

  const SecureDnsPolicy kSecureDnsPolicys[] = {SecureDnsPolicy::kAllow,
                                               SecureDnsPolicy::kDisable};

  int total_idle_sockets = 0;

  // Walk through each GroupId, making sure that requesting a socket for one
  // group does not return a previously connected socket for another group.
  for (const auto& host_port_pair : kHostPortPairs) {
    SCOPED_TRACE(host_port_pair.ToString());
    for (const char* scheme : kSchemes) {
      SCOPED_TRACE(scheme);
      for (const auto& privacy_mode : kPrivacyModes) {
        SCOPED_TRACE(privacy_mode);
        for (const auto& network_anonymization_key :
             kNetworkAnonymizationKeys) {
          SCOPED_TRACE(network_anonymization_key.ToDebugString());
          for (const auto& secure_dns_policy : kSecureDnsPolicys) {
            SCOPED_TRACE(static_cast<int>(secure_dns_policy));

            connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);

            ClientSocketPool::GroupId group_id(
                url::SchemeHostPort(scheme, host_port_pair.host(),
                                    host_port_pair.port()),
                privacy_mode, network_anonymization_key, secure_dns_policy,
                /*disable_cert_network_fetches=*/false);

            EXPECT_FALSE(pool_->HasGroupForTesting(group_id));

            TestCompletionCallback callback;
            ClientSocketHandle handle;

            // Since the group is empty, requesting a socket should not complete
            // synchronously.
            EXPECT_THAT(handle.Init(group_id, params_, std::nullopt,
                                    DEFAULT_PRIORITY, SocketTag(),
                                    ClientSocketPool::RespectLimits::ENABLED,
                                    callback.callback(),
                                    ClientSocketPool::ProxyAuthCallback(),
                                    pool_.get(), NetLogWithSource()),
                        IsError(ERR_IO_PENDING));
            EXPECT_TRUE(pool_->HasGroupForTesting(group_id));
            EXPECT_EQ(total_idle_sockets, pool_->IdleSocketCount());

            EXPECT_THAT(callback.WaitForResult(), IsOk());
            EXPECT_TRUE(handle.socket());
            EXPECT_TRUE(pool_->HasGroupForTesting(group_id));
            EXPECT_EQ(total_idle_sockets, pool_->IdleSocketCount());

            // Return socket to pool.
            handle.Reset();
            EXPECT_EQ(total_idle_sockets + 1, pool_->IdleSocketCount());

            // Requesting a socket again should return the same socket as
            // before, so should complete synchronously.
            EXPECT_THAT(handle.Init(group_id, params_, std::nullopt,
                                    DEFAULT_PRIORITY, SocketTag(),
                                    ClientSocketPool::RespectLimits::ENABLED,
                                    callback.callback(),
                                    ClientSocketPool::ProxyAuthCallback(),
                                    pool_.get(), NetLogWithSource()),
                        IsOk());
            EXPECT_TRUE(handle.socket());
            EXPECT_EQ(total_idle_sockets, pool_->IdleSocketCount());

            // Return socket to pool again.
            handle.Reset();
            EXPECT_EQ(total_idle_sockets + 1, pool_->IdleSocketCount());

            ++total_idle_sockets;
          }
        }
      }
    }
  }
}

TEST_F(ClientSocketPoolBaseTest, TotalLimit) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  // TODO(eroman): Check that the NetLog contains this event.

  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("b"), DEFAULT_PRIORITY), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("c"), DEFAULT_PRIORITY), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("d"), DEFAULT_PRIORITY), IsOk());

  EXPECT_EQ(static_cast<int>(requests_size()),
            client_socket_factory_.allocation_count());
  EXPECT_EQ(requests_size() - kDefaultMaxSockets, completion_count());

  EXPECT_THAT(StartRequest(TestGroupId("e"), DEFAULT_PRIORITY),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("f"), DEFAULT_PRIORITY),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("g"), DEFAULT_PRIORITY),
              IsError(ERR_IO_PENDING));

  ReleaseAllConnections(ClientSocketPoolTest::NO_KEEP_ALIVE);

  EXPECT_EQ(static_cast<int>(requests_size()),
            client_socket_factory_.allocation_count());
  EXPECT_EQ(requests_size() - kDefaultMaxSockets, completion_count());

  EXPECT_EQ(1, GetOrderOfRequest(1));
  EXPECT_EQ(2, GetOrderOfRequest(2));
  EXPECT_EQ(3, GetOrderOfRequest(3));
  EXPECT_EQ(4, GetOrderOfRequest(4));
  EXPECT_EQ(5, GetOrderOfRequest(5));
  EXPECT_EQ(6, GetOrderOfRequest(6));
  EXPECT_EQ(7, GetOrderOfRequest(7));

  // Make sure we test order of all requests made.
  EXPECT_EQ(ClientSocketPoolTest::kIndexOutOfBounds, GetOrderOfRequest(8));
}

TEST_F(ClientSocketPoolBaseTest, TotalLimitReachedNewGroup) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  // TODO(eroman): Check that the NetLog contains this event.

  // Reach all limits: max total sockets, and max sockets per group.
  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("b"), DEFAULT_PRIORITY), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("b"), DEFAULT_PRIORITY), IsOk());

  EXPECT_EQ(static_cast<int>(requests_size()),
            client_socket_factory_.allocation_count());
  EXPECT_EQ(requests_size() - kDefaultMaxSockets, completion_count());

  // Now create a new group and verify that we don't starve it.
  EXPECT_THAT(StartRequest(TestGroupId("c"), DEFAULT_PRIORITY),
              IsError(ERR_IO_PENDING));

  ReleaseAllConnections(ClientSocketPoolTest::NO_KEEP_ALIVE);

  EXPECT_EQ(static_cast<int>(requests_size()),
            client_socket_factory_.allocation_count());
  EXPECT_EQ(requests_size() - kDefaultMaxSockets, completion_count());

  EXPECT_EQ(1, GetOrderOfRequest(1));
  EXPECT_EQ(2, GetOrderOfRequest(2));
  EXPECT_EQ(3, GetOrderOfRequest(3));
  EXPECT_EQ(4, GetOrderOfRequest(4));
  EXPECT_EQ(5, GetOrderOfRequest(5));

  // Make sure we test order of all requests made.
  EXPECT_EQ(ClientSocketPoolTest::kIndexOutOfBounds, GetOrderOfRequest(6));
}

TEST_F(ClientSocketPoolBaseTest, TotalLimitRespectsPriority) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  EXPECT_THAT(StartRequest(TestGroupId("b"), LOWEST), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("a"), MEDIUM), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("b"), HIGHEST), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("a"), LOWEST), IsOk());

  EXPECT_EQ(static_cast<int>(requests_size()),
            client_socket_factory_.allocation_count());

  EXPECT_THAT(StartRequest(TestGroupId("c"), LOWEST), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), MEDIUM), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("b"), HIGHEST), IsError(ERR_IO_PENDING));

  ReleaseAllConnections(ClientSocketPoolTest::NO_KEEP_ALIVE);

  EXPECT_EQ(requests_size() - kDefaultMaxSockets, completion_count());

  // First 4 requests don't have to wait, and finish in order.
  EXPECT_EQ(1, GetOrderOfRequest(1));
  EXPECT_EQ(2, GetOrderOfRequest(2));
  EXPECT_EQ(3, GetOrderOfRequest(3));
  EXPECT_EQ(4, GetOrderOfRequest(4));

  // Request ("b", HIGHEST) has the highest priority, then (TestGroupId("a"),
  // MEDIUM), and then ("c", LOWEST).
  EXPECT_EQ(7, GetOrderOfRequest(5));
  EXPECT_EQ(6, GetOrderOfRequest(6));
  EXPECT_EQ(5, GetOrderOfRequest(7));

  // Make sure we test order of all requests made.
  EXPECT_EQ(ClientSocketPoolTest::kIndexOutOfBounds, GetOrderOfRequest(9));
}

// Test reprioritizing a request before completion doesn't interfere with
// its completion.
TEST_F(ClientSocketPoolBaseTest, ReprioritizeOne) {
  CreatePool(kDefaultMaxSockets, 1);

  EXPECT_THAT(StartRequest(TestGroupId("a"), LOWEST), IsError(OK));
  EXPECT_THAT(StartRequest(TestGroupId("a"), MEDIUM), IsError(ERR_IO_PENDING));
  EXPECT_TRUE(request(0)->handle()->socket());
  EXPECT_FALSE(request(1)->handle()->socket());

  request(1)->handle()->SetPriority(HIGHEST);

  ReleaseOneConnection(ClientSocketPoolTest::NO_KEEP_ALIVE);

  EXPECT_TRUE(request(1)->handle()->socket());
}

// Reprioritize a request up past another one and make sure that changes the
// completion order.
TEST_F(ClientSocketPoolBaseTest, ReprioritizeUpReorder) {
  CreatePool(kDefaultMaxSockets, 1);

  EXPECT_THAT(StartRequest(TestGroupId("a"), LOWEST), IsError(OK));
  EXPECT_THAT(StartRequest(TestGroupId("a"), MEDIUM), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), LOWEST), IsError(ERR_IO_PENDING));
  EXPECT_TRUE(request(0)->handle()->socket());
  EXPECT_FALSE(request(1)->handle()->socket());
  EXPECT_FALSE(request(2)->handle()->socket());

  request(2)->handle()->SetPriority(HIGHEST);

  ReleaseAllConnections(ClientSocketPoolTest::NO_KEEP_ALIVE);

  EXPECT_EQ(1, GetOrderOfRequest(1));
  EXPECT_EQ(3, GetOrderOfRequest(2));
  EXPECT_EQ(2, GetOrderOfRequest(3));
}

// Reprioritize a request without changing relative priorities and check
// that the order doesn't change.
TEST_F(ClientSocketPoolBaseTest, ReprioritizeUpNoReorder) {
  CreatePool(kDefaultMaxSockets, 1);

  EXPECT_THAT(StartRequest(TestGroupId("a"), LOWEST), IsError(OK));
  EXPECT_THAT(StartRequest(TestGroupId("a"), MEDIUM), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), LOW), IsError(ERR_IO_PENDING));
  EXPECT_TRUE(request(0)->handle()->socket());
  EXPECT_FALSE(request(1)->handle()->socket());
  EXPECT_FALSE(request(2)->handle()->socket());

  request(2)->handle()->SetPriority(MEDIUM);

  ReleaseAllConnections(ClientSocketPoolTest::NO_KEEP_ALIVE);

  EXPECT_EQ(1, GetOrderOfRequest(1));
  EXPECT_EQ(2, GetOrderOfRequest(2));
  EXPECT_EQ(3, GetOrderOfRequest(3));
}

// Reprioritize a request past down another one and make sure that changes the
// completion order.
TEST_F(ClientSocketPoolBaseTest, ReprioritizeDownReorder) {
  CreatePool(kDefaultMaxSockets, 1);

  EXPECT_THAT(StartRequest(TestGroupId("a"), LOWEST), IsError(OK));
  EXPECT_THAT(StartRequest(TestGroupId("a"), HIGHEST), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), MEDIUM), IsError(ERR_IO_PENDING));
  EXPECT_TRUE(request(0)->handle()->socket());
  EXPECT_FALSE(request(1)->handle()->socket());
  EXPECT_FALSE(request(2)->handle()->socket());

  request(1)->handle()->SetPriority(LOW);

  ReleaseAllConnections(ClientSocketPoolTest::NO_KEEP_ALIVE);

  EXPECT_EQ(1, GetOrderOfRequest(1));
  EXPECT_EQ(3, GetOrderOfRequest(2));
  EXPECT_EQ(2, GetOrderOfRequest(3));
}

// Reprioritize a request to the same level as another and confirm it is
// put after the old request.
TEST_F(ClientSocketPoolBaseTest, ReprioritizeResetFIFO) {
  CreatePool(kDefaultMaxSockets, 1);

  EXPECT_THAT(StartRequest(TestGroupId("a"), LOWEST), IsError(OK));
  EXPECT_THAT(StartRequest(TestGroupId("a"), HIGHEST), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), MEDIUM), IsError(ERR_IO_PENDING));
  EXPECT_TRUE(request(0)->handle()->socket());
  EXPECT_FALSE(request(1)->handle()->socket());
  EXPECT_FALSE(request(2)->handle()->socket());

  request(1)->handle()->SetPriority(MEDIUM);

  ReleaseAllConnections(ClientSocketPoolTest::NO_KEEP_ALIVE);

  EXPECT_EQ(1, GetOrderOfRequest(1));
  EXPECT_EQ(3, GetOrderOfRequest(2));
  EXPECT_EQ(2, GetOrderOfRequest(3));
}

TEST_F(ClientSocketPoolBaseTest, TotalLimitRespectsGroupLimit) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  EXPECT_THAT(StartRequest(TestGroupId("a"), LOWEST), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("a"), LOW), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("b"), HIGHEST), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("b"), MEDIUM), IsOk());

  EXPECT_EQ(static_cast<int>(requests_size()),
            client_socket_factory_.allocation_count());

  EXPECT_THAT(StartRequest(TestGroupId("c"), MEDIUM), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), LOW), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("b"), HIGHEST), IsError(ERR_IO_PENDING));

  ReleaseAllConnections(ClientSocketPoolTest::NO_KEEP_ALIVE);

  EXPECT_EQ(static_cast<int>(requests_size()),
            client_socket_factory_.allocation_count());
  EXPECT_EQ(requests_size() - kDefaultMaxSockets, completion_count());

  // First 4 requests don't have to wait, and finish in order.
  EXPECT_EQ(1, GetOrderOfRequest(1));
  EXPECT_EQ(2, GetOrderOfRequest(2));
  EXPECT_EQ(3, GetOrderOfRequest(3));
  EXPECT_EQ(4, GetOrderOfRequest(4));

  // Request ("b", 7) has the highest priority, but we can't make new socket for
  // group "b", because it has reached the per-group limit. Then we make
  // socket for ("c", 6), because it has higher priority than ("a", 4),
  // and we still can't make a socket for group "b".
  EXPECT_EQ(5, GetOrderOfRequest(5));
  EXPECT_EQ(6, GetOrderOfRequest(6));
  EXPECT_EQ(7, GetOrderOfRequest(7));

  // Make sure we test order of all requests made.
  EXPECT_EQ(ClientSocketPoolTest::kIndexOutOfBounds, GetOrderOfRequest(8));
}

// Make sure that we count connecting sockets against the total limit.
TEST_F(ClientSocketPoolBaseTest, TotalLimitCountsConnectingSockets) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("b"), DEFAULT_PRIORITY), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("c"), DEFAULT_PRIORITY), IsOk());

  // Create one asynchronous request.
  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);
  EXPECT_THAT(StartRequest(TestGroupId("d"), DEFAULT_PRIORITY),
              IsError(ERR_IO_PENDING));

  // We post all of our delayed tasks with a 2ms delay. I.e. they don't
  // actually become pending until 2ms after they have been created. In order
  // to flush all tasks, we need to wait so that we know there are no
  // soon-to-be-pending tasks waiting.
  FastForwardBy(base::Milliseconds(10));

  // The next synchronous request should wait for its turn.
  connect_job_factory_->set_job_type(TestConnectJob::kMockJob);
  EXPECT_THAT(StartRequest(TestGroupId("e"), DEFAULT_PRIORITY),
              IsError(ERR_IO_PENDING));

  ReleaseAllConnections(ClientSocketPoolTest::NO_KEEP_ALIVE);

  EXPECT_EQ(static_cast<int>(requests_size()),
            client_socket_factory_.allocation_count());

  EXPECT_EQ(1, GetOrderOfRequest(1));
  EXPECT_EQ(2, GetOrderOfRequest(2));
  EXPECT_EQ(3, GetOrderOfRequest(3));
  EXPECT_EQ(4, GetOrderOfRequest(4));
  EXPECT_EQ(5, GetOrderOfRequest(5));

  // Make sure we test order of all requests made.
  EXPECT_EQ(ClientSocketPoolTest::kIndexOutOfBounds, GetOrderOfRequest(6));
}

TEST_F(ClientSocketPoolBaseTest, CorrectlyCountStalledGroups) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSockets);
  connect_job_factory_->set_job_type(TestConnectJob::kMockJob);

  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY), IsOk());

  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);

  EXPECT_EQ(kDefaultMaxSockets, client_socket_factory_.allocation_count());

  EXPECT_THAT(StartRequest(TestGroupId("b"), DEFAULT_PRIORITY),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("c"), DEFAULT_PRIORITY),
              IsError(ERR_IO_PENDING));

  EXPECT_EQ(kDefaultMaxSockets, client_socket_factory_.allocation_count());

  EXPECT_TRUE(ReleaseOneConnection(ClientSocketPoolTest::KEEP_ALIVE));
  EXPECT_EQ(kDefaultMaxSockets + 1, client_socket_factory_.allocation_count());
  EXPECT_TRUE(ReleaseOneConnection(ClientSocketPoolTest::KEEP_ALIVE));
  EXPECT_EQ(kDefaultMaxSockets + 2, client_socket_factory_.allocation_count());
  EXPECT_TRUE(ReleaseOneConnection(ClientSocketPoolTest::KEEP_ALIVE));
  EXPECT_TRUE(ReleaseOneConnection(ClientSocketPoolTest::KEEP_ALIVE));
  EXPECT_EQ(kDefaultMaxSockets + 2, client_socket_factory_.allocation_count());
}

TEST_F(ClientSocketPoolBaseTest, StallAndThenCancelAndTriggerAvailableSocket) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSockets);
  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);

  TestCompletionCallback callback;
  ClientSocketHandle stalled_handle;
  EXPECT_EQ(ERR_IO_PENDING,
            stalled_handle.Init(
                TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                pool_.get(), NetLogWithSource()));

  ClientSocketHandle handles[4];
  for (auto& handle : handles) {
    EXPECT_EQ(
        ERR_IO_PENDING,
        handle.Init(TestGroupId("b"), params_, std::nullopt, DEFAULT_PRIORITY,
                    SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                    callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                    pool_.get(), NetLogWithSource()));
  }

  // One will be stalled, cancel all the handles now.
  // This should hit the OnAvailableSocketSlot() code where we previously had
  // stalled groups, but no longer have any.
  for (auto& handle : handles) {
    handle.Reset();
  }
}

TEST_F(ClientSocketPoolBaseTest, CancelStalledSocketAtSocketLimit) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  connect_job_factory_->set_job_type(TestConnectJob::kMockJob);

  {
    ClientSocketHandle handles[kDefaultMaxSockets];
    TestCompletionCallback callbacks[kDefaultMaxSockets];
    for (int i = 0; i < kDefaultMaxSockets; ++i) {
      EXPECT_EQ(OK, handles[i].Init(TestGroupId("a" + base::NumberToString(i)),
                                    params_, std::nullopt, DEFAULT_PRIORITY,
                                    SocketTag(),
                                    ClientSocketPool::RespectLimits::ENABLED,
                                    callbacks[i].callback(),
                                    ClientSocketPool::ProxyAuthCallback(),
                                    pool_.get(), NetLogWithSource()));
    }

    // Force a stalled group.
    ClientSocketHandle stalled_handle;
    TestCompletionCallback callback;
    EXPECT_EQ(ERR_IO_PENDING,
              stalled_handle.Init(
                  TestGroupId("foo"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));

    // Cancel the stalled request.
    stalled_handle.Reset();

    EXPECT_EQ(kDefaultMaxSockets, client_socket_factory_.allocation_count());
    EXPECT_EQ(0, pool_->IdleSocketCount());

    // Dropping out of scope will close all handles and return them to idle.
  }

  EXPECT_EQ(kDefaultMaxSockets, client_socket_factory_.allocation_count());
  EXPECT_EQ(kDefaultMaxSockets, pool_->IdleSocketCount());
}

TEST_F(ClientSocketPoolBaseTest, CancelPendingSocketAtSocketLimit) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);

  {
    ClientSocketHandle handles[kDefaultMaxSockets];
    for (int i = 0; i < kDefaultMaxSockets; ++i) {
      TestCompletionCallback callback;
      EXPECT_EQ(ERR_IO_PENDING,
                handles[i].Init(
                    TestGroupId("a" + base::NumberToString(i)), params_,
                    std::nullopt, DEFAULT_PRIORITY, SocketTag(),
                    ClientSocketPool::RespectLimits::ENABLED,
                    callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                    pool_.get(), NetLogWithSource()));
    }

    // Force a stalled group.
    connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);
    ClientSocketHandle stalled_handle;
    TestCompletionCallback callback;
    EXPECT_EQ(ERR_IO_PENDING,
              stalled_handle.Init(
                  TestGroupId("foo"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));

    // Since it is stalled, it should have no connect jobs.
    EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("foo")));
    EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                      TestGroupId("foo")));
    EXPECT_EQ(0u, pool_->NumUnassignedConnectJobsInGroupForTesting(
                      TestGroupId("foo")));

    // Cancel the stalled request.
    handles[0].Reset();

    // Now we should have a connect job.
    EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("foo")));
    EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                      TestGroupId("foo")));
    EXPECT_EQ(0u, pool_->NumUnassignedConnectJobsInGroupForTesting(
                      TestGroupId("foo")));

    // The stalled socket should connect.
    EXPECT_THAT(callback.WaitForResult(), IsOk());

    EXPECT_EQ(kDefaultMaxSockets + 1,
              client_socket_factory_.allocation_count());
    EXPECT_EQ(0, pool_->IdleSocketCount());
    EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("foo")));
    EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                      TestGroupId("foo")));
    EXPECT_EQ(0u, pool_->NumUnassignedConnectJobsInGroupForTesting(
                      TestGroupId("foo")));

    // Dropping out of scope will close all handles and return them to idle.
  }

  EXPECT_EQ(1, pool_->IdleSocketCount());
}

TEST_F(ClientSocketPoolBaseTest, WaitForStalledSocketAtSocketLimit) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  connect_job_factory_->set_job_type(TestConnectJob::kMockJob);

  ClientSocketHandle stalled_handle;
  TestCompletionCallback callback;
  {
    EXPECT_FALSE(pool_->IsStalled());
    ClientSocketHandle handles[kDefaultMaxSockets];
    for (int i = 0; i < kDefaultMaxSockets; ++i) {
      EXPECT_EQ(
          OK, handles[i].Init(
                  TestGroupId(base::StringPrintf("take-2-%d", i)), params_,
                  std::nullopt, DEFAULT_PRIORITY, SocketTag(),
                  ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
                  ClientSocketPool::ProxyAuthCallback(), pool_.get(),
                  NetLogWithSource()));
    }

    EXPECT_EQ(kDefaultMaxSockets, client_socket_factory_.allocation_count());
    EXPECT_EQ(0, pool_->IdleSocketCount());
    EXPECT_FALSE(pool_->IsStalled());

    // Now we will hit the socket limit.
    EXPECT_EQ(ERR_IO_PENDING,
              stalled_handle.Init(
                  TestGroupId("foo"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));
    EXPECT_TRUE(pool_->IsStalled());

    // Dropping out of scope will close all handles and return them to idle.
  }

  // But if we wait for it, the released idle sockets will be closed in
  // preference of the waiting request.
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  EXPECT_EQ(kDefaultMaxSockets + 1, client_socket_factory_.allocation_count());
  EXPECT_EQ(3, pool_->IdleSocketCount());
}

// Regression test for http://crbug.com/40952.
TEST_F(ClientSocketPoolBaseTest, CloseIdleSocketAtSocketLimitDeleteGroup) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup,
             true /* enable_backup_connect_jobs */);
  connect_job_factory_->set_job_type(TestConnectJob::kMockJob);

  for (int i = 0; i < kDefaultMaxSockets; ++i) {
    ClientSocketHandle handle;
    TestCompletionCallback callback;
    EXPECT_EQ(
        OK,
        handle.Init(TestGroupId("a" + base::NumberToString(i)), params_,
                    std::nullopt, DEFAULT_PRIORITY, SocketTag(),
                    ClientSocketPool::RespectLimits::ENABLED,
                    callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                    pool_.get(), NetLogWithSource()));
  }

  // Flush all the DoReleaseSocket tasks.
  base::RunLoop().RunUntilIdle();

  // Stall a group.  Set a pending job so it'll trigger a backup job if we don't
  // reuse a socket.
  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);
  ClientSocketHandle handle;
  TestCompletionCallback callback;

  // "a0" is special here, since it should be the first entry in the sorted map,
  // which is the one which we would close an idle socket for.  We shouldn't
  // close an idle socket though, since we should reuse the idle socket.
  EXPECT_EQ(OK, handle.Init(
                    TestGroupId("a0"), params_, std::nullopt, DEFAULT_PRIORITY,
                    SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                    callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                    pool_.get(), NetLogWithSource()));

  EXPECT_EQ(kDefaultMaxSockets, client_socket_factory_.allocation_count());
  EXPECT_EQ(kDefaultMaxSockets - 1, pool_->IdleSocketCount());
}

TEST_F(ClientSocketPoolBaseTest, PendingRequests) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("a"), IDLE), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), LOWEST), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), MEDIUM), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), HIGHEST), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), LOW), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), LOWEST), IsError(ERR_IO_PENDING));

  ReleaseAllConnections(ClientSocketPoolTest::KEEP_ALIVE);
  EXPECT_EQ(kDefaultMaxSocketsPerGroup,
            client_socket_factory_.allocation_count());
  EXPECT_EQ(requests_size() - kDefaultMaxSocketsPerGroup, completion_count());

  EXPECT_EQ(1, GetOrderOfRequest(1));
  EXPECT_EQ(2, GetOrderOfRequest(2));
  EXPECT_EQ(8, GetOrderOfRequest(3));
  EXPECT_EQ(6, GetOrderOfRequest(4));
  EXPECT_EQ(4, GetOrderOfRequest(5));
  EXPECT_EQ(3, GetOrderOfRequest(6));
  EXPECT_EQ(5, GetOrderOfRequest(7));
  EXPECT_EQ(7, GetOrderOfRequest(8));

  // Make sure we test order of all requests made.
  EXPECT_EQ(ClientSocketPoolTest::kIndexOutOfBounds, GetOrderOfRequest(9));
}

TEST_F(ClientSocketPoolBaseTest, PendingRequests_NoKeepAlive) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("a"), LOWEST), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), MEDIUM), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), HIGHEST), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), LOW), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), LOWEST), IsError(ERR_IO_PENDING));

  ReleaseAllConnections(ClientSocketPoolTest::NO_KEEP_ALIVE);

  for (size_t i = kDefaultMaxSocketsPerGroup; i < requests_size(); ++i) {
    EXPECT_THAT(request(i)->WaitForResult(), IsOk());
  }

  EXPECT_EQ(static_cast<int>(requests_size()),
            client_socket_factory_.allocation_count());
  EXPECT_EQ(requests_size() - kDefaultMaxSocketsPerGroup, completion_count());
}

TEST_F(ClientSocketPoolBaseTest, ResetAndCloseSocket) {
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
  ASSERT_TRUE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));

  handle.ResetAndCloseSocket();
  EXPECT_FALSE(pool_->HasGroupForTesting(TestGroupId("a")));
}

// This test will start up a socket request and then call Reset() on the handle.
// The pending ConnectJob should not be destroyed.
TEST_F(ClientSocketPoolBaseTest, CancelRequestKeepsConnectJob) {
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
  handle.Reset();
  ASSERT_TRUE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
}

// This test will start up a socket request and then call ResetAndCloseSocket()
// on the handle. The pending ConnectJob or connected socket should be
// destroyed.
TEST_F(ClientSocketPoolBaseTest, CancelRequestAndCloseSocket) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  // When true, the socket connects before it's canceled.
  for (bool cancel_when_callback_pending : {false, true}) {
    if (cancel_when_callback_pending) {
      connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);
    } else {
      connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);
    }
    ClientSocketHandle handle;
    TestCompletionCallback callback;
    EXPECT_EQ(
        ERR_IO_PENDING,
        handle.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                    SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                    callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                    pool_.get(), NetLogWithSource()));
    ASSERT_TRUE(pool_->HasGroupForTesting(TestGroupId("a")));
    EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

    if (cancel_when_callback_pending) {
      client_socket_factory_.SignalJobs();
      ASSERT_TRUE(pool_->HasGroupForTesting(TestGroupId("a")));
      EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
    }

    handle.ResetAndCloseSocket();
    ASSERT_FALSE(pool_->HasGroupForTesting(TestGroupId("a")));
  }
}

TEST_F(ClientSocketPoolBaseTest,
       CancelRequestAndCloseSocketWhenMoreRequestsThanConnectJobs) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  // When true, the sockets connect before they're canceled.
  for (bool cancel_when_callback_pending : {false, true}) {
    if (cancel_when_callback_pending) {
      connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);
    } else {
      connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);
    }

    std::vector<std::unique_ptr<ClientSocketHandle>> handles;
    TestCompletionCallback callback;
    // Make |kDefaultMaxSockets + 1| socket requests.
    for (int i = 0; i < kDefaultMaxSocketsPerGroup + 1; ++i) {
      std::unique_ptr<ClientSocketHandle> handle =
          std::make_unique<ClientSocketHandle>();
      EXPECT_EQ(ERR_
"""


```