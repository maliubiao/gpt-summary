Response:
The user wants a summary of the provided C++ code for a unit test file.
The file `client_socket_pool_base_unittest.cc` is part of Chromium's network stack and tests the `ClientSocketPoolBase` class.

Here's a breakdown of the code's functionality based on the test names:

1. **Basic Functionality:**
   - Creating and checking the state of socket pools (number of idle, active, connecting sockets).
   - Requesting sockets and verifying the creation of connect jobs.
   - Handling synchronous errors during socket requests.
   - Ensuring multiple requests don't create redundant connect jobs.
   - Requesting different numbers of preconnected sockets.

2. **Preconnect Functionality:**
   - How preconnect jobs interact with normal socket requests.
   - Verifying load timing information for preconnected and reused sockets.
   - Handling scenarios where preconnected sockets are closed.
   - Testing preconnect functionality with and without backup connect jobs.
   - Handling preconnected sockets with unread data.

3. **Job Assignment:**
   - Ensuring socket requests are assigned to connect jobs.
   - How multiple requests are assigned jobs.
   - How preconnect jobs are assigned to subsequent requests.
   - How higher priority requests can steal jobs from lower priority requests.

I need to summarize these functionalities, mention if there's a relation to Javascript, provide examples of usage errors, and explain how a user operation might lead to this code being executed (as a debugging step).

**Relation to Javascript:** While this is C++ code, the functionality it tests (socket pooling, connection management) is relevant to network requests initiated by Javascript in a browser environment. For example, when a Javascript application makes an `XMLHttpRequest` or uses the `fetch` API, the underlying browser might use a `ClientSocketPoolBase` instance to manage the connections.

**User Errors:** Common user errors wouldn't directly interact with this C++ code. However, issues in the networking layer, like connection failures or performance problems, could be diagnosed by examining the behavior of `ClientSocketPoolBase`.

**Debugging:**  A developer debugging network issues in Chromium might step through this code to understand how connections are being managed, especially during preconnection or when handling concurrent requests.
这是 Chromium 网络栈中 `net/socket/client_socket_pool_base_unittest.cc` 文件的第 6 部分，该文件主要用于测试 `ClientSocketPoolBase` 类的各种功能。从提供的代码片段来看，这一部分主要集中在以下几个方面：

**功能归纳:**

1. **预连接 (Preconnect) 功能测试:**
   - **`RequestSocketsSynchronous` 和 `RequestSocketsSynchronousError`:** 测试在请求预连接套接字时，如果立即成功或遇到错误的情况。
   - **`RequestSocketsMultipleTimesDoesNothing`:**  验证多次调用 `RequestSockets` 方法预连接相同数量的套接字时，不会重复创建连接任务，除非之前的任务完成或被占用。
   - **`RequestSocketsDifferentNumSockets`:** 测试请求不同数量的预连接套接字时，连接任务的创建情况。
   - **`PreconnectJobsTakenByNormalRequests`:**  验证预连接任务创建的套接字可以被普通的套接字请求使用。
   - **`ConnectedPreconnectJobsHaveNoConnectTimes`:** 检查完全连接的预连接任务在被使用时，连接时间信息是否正确（应该标记为已重用）。
   - **`PreconnectClosesIdleSocketRemovesGroup`:**  测试当套接字池达到最大连接数时，请求预连接会关闭空闲套接字，并可能导致组被移除的情况，这是一个回归测试，用于修复之前的 bug。
   - **`PreconnectWithoutBackupJob` 和 `PreconnectWithBackupJob`:** 测试预连接功能是否支持备用连接任务（backup connect jobs），以及在有备用连接任务的情况下，主连接任务超时或阻塞时的行为。
   - **`PreconnectWithUnreadData`:** 测试预连接创建的套接字如果包含未读取的数据，是否仍然可以被后续的请求使用。

2. **连接任务 (Connect Job) 分配测试:**
   - **`RequestGetsAssignedJob`:**  验证当发起一个套接字请求时，该请求会被分配到一个正在进行的连接任务。
   - **`MultipleRequestsGetAssignedJobs`:** 测试多个套接字请求是否会被分配到不同的连接任务。
   - **`PreconnectJobGetsAssignedToRequest`:**  验证预连接任务创建的连接可以被后续的套接字请求使用。
   - **`HigherPriorityRequestStealsJob`:**  测试高优先级的套接字请求是否可以抢占低优先级请求正在使用的连接任务。
   - **`RequestStealsJobFromLowestRequestWithJob`:**  测试当有多个请求持有连接任务时，新的请求会从优先级最低的请求那里抢占连接任务。

**与 JavaScript 的关系举例说明:**

虽然这段代码是 C++，但它测试的网络连接池功能与浏览器中 JavaScript 发起的网络请求息息相关。

**举例：** 当一个网页上的 JavaScript 代码使用 `fetch` API 发起一个 HTTP 请求时，浏览器底层网络栈可能会使用 `ClientSocketPoolBase` 来管理与服务器的 TCP 连接。

- **预连接 (`RequestSockets`)：** 浏览器可能会在用户输入 URL 或即将跳转到新页面时，提前尝试与服务器建立连接，这就是预连接。这段 C++ 代码测试了这种预连接机制的正确性。
- **连接任务分配 (`RequestGetsAssignedJob`)：** 当 JavaScript 发起 `fetch` 请求时，如果连接池中没有可用的空闲连接，`ClientSocketPoolBase` 会创建一个连接任务。这段代码测试了 JavaScript 的请求是否能正确地被分配到这个连接任务上。

**假设输入与输出 (逻辑推理):**

**假设输入 (针对 `HigherPriorityRequestStealsJob`):**

1. 创建一个最大连接数为 1 的 `ClientSocketPoolBase`。
2. 设置 `connect_job_factory_` 为模拟等待状态的连接任务。
3. 发起一个默认优先级的套接字请求 `handle1`。
4. 此时，连接池中有一个正在进行的连接任务与 `handle1` 关联。
5. 发起一个更高优先级的套接字请求 `handle2`。

**预期输出:**

- 在发起 `handle1` 请求后，`pool_->NumConnectJobsInGroupForTesting(TestGroupId("a"))` 应该为 1。
- 在发起 `handle2` 请求后，连接任务仍然只有一个，`pool_->NumConnectJobsInGroupForTesting(TestGroupId("a"))` 仍然为 1。
- `handle2` 将会抢占 `handle1` 的连接任务，`pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"), &handle2)` 返回 `true`，而 `pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"), &handle1)` 返回 `false`。

**用户或编程常见的使用错误举例说明:**

这段 C++ 代码主要测试的是网络栈内部的逻辑，用户或开发者直接使用 `ClientSocketPoolBase` 的机会较少。但理解其背后的原理可以帮助诊断网络问题。

**举例 (间接关联):** 开发者可能会错误地认为发起多个相同的网络请求会复用相同的 TCP 连接，但如果连接池的配置不当或者服务器端有连接限制，可能会导致连接复用失败，创建过多的连接，最终影响性能。这段测试代码中的一些用例，如 `RequestSocketsMultipleTimesDoesNothing`，就体现了连接池避免重复创建连接的机制。

**用户操作如何一步步到达这里 (调试线索):**

假设用户在使用 Chrome 浏览器浏览网页时遇到了网络连接缓慢的问题：

1. **用户操作:** 用户在地址栏输入网址并回车，或者点击网页上的链接。
2. **浏览器行为:** Chrome 的渲染进程解析 URL，确定需要建立网络连接。
3. **网络请求:** 渲染进程通过 IPC (进程间通信) 将网络请求发送给网络服务进程。
4. **连接池查找:** 网络服务进程中的 `ClientSocketPoolBase` 会检查是否有可用的空闲连接可以复用。
5. **创建连接任务 (如果需要):** 如果没有可用连接，并且需要建立新的连接，`ClientSocketPoolBase` 会创建一个连接任务 (`ConnectJob`)。
6. **执行连接任务:** 连接任务会执行 TCP 连接的建立过程 (DNS 查询、TCP 握手等)。
7. **(如果开发者进行调试):** 当开发者怀疑是连接池管理的问题导致网络缓慢时，可能会在 Chromium 的源代码中设置断点，例如在 `ClientSocketPoolBase::RequestSockets` 或 `ClientSocketPoolBase::StartConnectJob` 等方法中，来观察连接的创建和分配过程。这个单元测试文件 `client_socket_pool_base_unittest.cc` 就是用来确保这些核心逻辑的正确性的。开发者可以通过运行这些单元测试来验证代码的预期行为。

总而言之，这段代码主要测试了 `ClientSocketPoolBase` 在处理预连接和连接任务分配时的各种场景，确保了网络连接的有效管理和复用，这对于浏览器的网络性能至关重要。

### 提示词
```
这是目录为net/socket/client_socket_pool_base_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
nGroupForTesting(TestGroupId("b")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("b")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("b")));
  EXPECT_EQ(kDefaultMaxSocketsPerGroup,
            static_cast<int>(pool_->IdleSocketCountInGroup(TestGroupId("b"))));
}

TEST_F(ClientSocketPoolBaseTest, RequestSocketsSynchronousError) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  connect_job_factory_->set_job_type(TestConnectJob::kMockFailingJob);

  EXPECT_EQ(
      OK, pool_->RequestSockets(TestGroupId("a"), params_, std::nullopt,
                                kDefaultMaxSocketsPerGroup,
                                CompletionOnceCallback(), NetLogWithSource()));

  ASSERT_FALSE(pool_->HasGroupForTesting(TestGroupId("a")));

  connect_job_factory_->set_job_type(
      TestConnectJob::kMockAdditionalErrorStateJob);

  EXPECT_EQ(
      OK, pool_->RequestSockets(TestGroupId("a"), params_, std::nullopt,
                                kDefaultMaxSocketsPerGroup,
                                CompletionOnceCallback(), NetLogWithSource()));

  ASSERT_FALSE(pool_->HasGroupForTesting(TestGroupId("a")));
}

TEST_F(ClientSocketPoolBaseTest, RequestSocketsMultipleTimesDoesNothing) {
  CreatePool(4, 4);
  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);

  TestCompletionCallback preconnect_callback;
  EXPECT_EQ(ERR_IO_PENDING,
            pool_->RequestSockets(TestGroupId("a"), params_, std::nullopt, 2,
                                  preconnect_callback.callback(),
                                  NetLogWithSource()));

  ASSERT_TRUE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(2u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(2u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(2u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  EXPECT_EQ(
      OK, pool_->RequestSockets(TestGroupId("a"), params_, std::nullopt, 2,
                                CompletionOnceCallback(), NetLogWithSource()));
  EXPECT_EQ(2u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(2u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(2u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  ClientSocketHandle handle1;
  TestCompletionCallback callback1;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle1.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback1.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource()));

  client_socket_factory_.SignalJob(0);
  EXPECT_THAT(callback1.WaitForResult(), IsOk());

  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(1u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  ClientSocketHandle handle2;
  TestCompletionCallback callback2;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle2.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback2.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource()));
  client_socket_factory_.SignalJob(0);
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_THAT(preconnect_callback.WaitForResult(), IsOk());

  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(2, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  handle1.Reset();
  handle2.Reset();

  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(2u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  EXPECT_EQ(
      OK, pool_->RequestSockets(TestGroupId("a"), params_, std::nullopt, 2,
                                CompletionOnceCallback(), NetLogWithSource()));
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(2u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
}

TEST_F(ClientSocketPoolBaseTest, RequestSocketsDifferentNumSockets) {
  CreatePool(4, 4);
  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);

  TestCompletionCallback preconnect_callback1;
  EXPECT_EQ(ERR_IO_PENDING,
            pool_->RequestSockets(TestGroupId("a"), params_, std::nullopt, 1,
                                  preconnect_callback1.callback(),
                                  NetLogWithSource()));

  ASSERT_TRUE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(1u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  TestCompletionCallback preconnect_callback2;
  EXPECT_EQ(ERR_IO_PENDING,
            pool_->RequestSockets(TestGroupId("a"), params_, std::nullopt, 2,
                                  preconnect_callback2.callback(),
                                  NetLogWithSource()));
  EXPECT_EQ(2u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(2u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(2u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  TestCompletionCallback preconnect_callback3;
  EXPECT_EQ(ERR_IO_PENDING,
            pool_->RequestSockets(TestGroupId("a"), params_, std::nullopt, 3,
                                  preconnect_callback3.callback(),
                                  NetLogWithSource()));
  EXPECT_EQ(3u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(3u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(3u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  EXPECT_EQ(
      OK, pool_->RequestSockets(TestGroupId("a"), params_, std::nullopt, 1,
                                CompletionOnceCallback(), NetLogWithSource()));
  EXPECT_EQ(3u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(3u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(3u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
}

TEST_F(ClientSocketPoolBaseTest, PreconnectJobsTakenByNormalRequests) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);

  TestCompletionCallback preconnect_callback;
  EXPECT_EQ(ERR_IO_PENDING,
            pool_->RequestSockets(TestGroupId("a"), params_, std::nullopt, 1,
                                  preconnect_callback.callback(),
                                  NetLogWithSource()));

  ASSERT_TRUE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(1u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  ClientSocketHandle handle1;
  TestCompletionCallback callback1;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle1.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback1.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource()));

  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  client_socket_factory_.SignalJobs();
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_THAT(preconnect_callback.WaitForResult(), IsOk());

  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));

  // Make sure if a preconnected socket is not fully connected when a request
  // starts, it has a connect start time.
  TestLoadTimingInfoConnectedNotReused(handle1);
  handle1.Reset();

  EXPECT_EQ(1u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
}

// Checks that fully connected preconnect jobs have no connect times, and are
// marked as reused.
TEST_F(ClientSocketPoolBaseTest, ConnectedPreconnectJobsHaveNoConnectTimes) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  connect_job_factory_->set_job_type(TestConnectJob::kMockJob);

  EXPECT_EQ(
      OK, pool_->RequestSockets(TestGroupId("a"), params_, std::nullopt, 1,
                                CompletionOnceCallback(), NetLogWithSource()));

  ASSERT_TRUE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_EQ(OK, handle.Init(
                    TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                    SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                    callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                    pool_.get(), NetLogWithSource()));

  // Make sure the idle socket was used.
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  TestLoadTimingInfoConnectedReused(handle);
  handle.Reset();
  TestLoadTimingInfoNotConnected(handle);
}

// http://crbug.com/64940 regression test.
TEST_F(ClientSocketPoolBaseTest, PreconnectClosesIdleSocketRemovesGroup) {
  const int kMaxTotalSockets = 3;
  const int kMaxSocketsPerGroup = 2;
  CreatePool(kMaxTotalSockets, kMaxSocketsPerGroup);
  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);

  // Note that group id ordering matters here.  "a" comes before "b", so
  // CloseOneIdleSocket() will try to close "a"'s idle socket.

  // Set up one idle socket in "a".
  ClientSocketHandle handle1;
  TestCompletionCallback callback1;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle1.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback1.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource()));
  ASSERT_TRUE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  client_socket_factory_.SignalJobs();
  ASSERT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));

  handle1.Reset();
  EXPECT_EQ(1u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  // Set up two active sockets in "b".
  ClientSocketHandle handle2;
  TestCompletionCallback callback2;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle1.Init(TestGroupId("b"), params_, std::nullopt, DEFAULT_PRIORITY,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback1.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource()));
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle2.Init(TestGroupId("b"), params_, std::nullopt, DEFAULT_PRIORITY,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback2.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource()));

  ASSERT_TRUE(pool_->HasGroupForTesting(TestGroupId("b")));
  EXPECT_EQ(2u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("b")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("b")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("b")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("b")));

  client_socket_factory_.SignalJobs();
  ASSERT_THAT(callback1.WaitForResult(), IsOk());
  ASSERT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("b")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("b")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("b")));
  EXPECT_EQ(2, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("b")));

  // Now we have 1 idle socket in "a" and 2 active sockets in "b".  This means
  // we've maxed out on sockets, since we set |kMaxTotalSockets| to 3.
  // Requesting 2 preconnected sockets for "a" should fail to allocate any more
  // sockets for "a", and "b" should still have 2 active sockets.

  EXPECT_EQ(
      OK, pool_->RequestSockets(TestGroupId("a"), params_, std::nullopt, 2,
                                CompletionOnceCallback(), NetLogWithSource()));
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
  EXPECT_EQ(0, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("b")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("b")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("b")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("b")));
  EXPECT_EQ(2, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("b")));

  // Now release the 2 active sockets for "b".  This will give us 1 idle socket
  // in "a" and 2 idle sockets in "b".  Requesting 2 preconnected sockets for
  // "a" should result in closing 1 for "b".
  handle1.Reset();
  handle2.Reset();
  EXPECT_EQ(2u, pool_->IdleSocketCountInGroup(TestGroupId("b")));
  EXPECT_EQ(0, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("b")));

  TestCompletionCallback preconnect_callback;
  EXPECT_EQ(ERR_IO_PENDING,
            pool_->RequestSockets(TestGroupId("a"), params_, std::nullopt, 2,
                                  preconnect_callback.callback(),
                                  NetLogWithSource()));
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(1u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
  EXPECT_EQ(0, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("b")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("b")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("b")));
  EXPECT_EQ(1u, pool_->IdleSocketCountInGroup(TestGroupId("b")));
  EXPECT_EQ(0, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("b")));
}

TEST_F(ClientSocketPoolBaseTest, PreconnectWithoutBackupJob) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup,
             true /* enable_backup_connect_jobs */);

  // Make the ConnectJob hang until it times out, shorten the timeout.
  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);
  connect_job_factory_->set_timeout_duration(base::Milliseconds(500));
  TestCompletionCallback preconnect_callback;
  EXPECT_EQ(ERR_IO_PENDING,
            pool_->RequestSockets(TestGroupId("a"), params_, std::nullopt, 1,
                                  preconnect_callback.callback(),
                                  NetLogWithSource()));
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(1u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  // Verify the backup timer doesn't create a backup job, by making
  // the backup job a pending job instead of a waiting job, so it
  // *would* complete if it were created.
  base::RunLoop loop;
  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE, loop.QuitClosure(), base::Seconds(1));
  loop.Run();
  EXPECT_FALSE(pool_->HasGroupForTesting(TestGroupId("a")));
}

TEST_F(ClientSocketPoolBaseTest, PreconnectWithBackupJob) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup,
             true /* enable_backup_connect_jobs */);

  // Make the ConnectJob hang forever.
  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);
  TestCompletionCallback preconnect_callback;
  EXPECT_EQ(ERR_IO_PENDING,
            pool_->RequestSockets(TestGroupId("a"), params_, std::nullopt, 1,
                                  preconnect_callback.callback(),
                                  NetLogWithSource()));
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(1u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
  base::RunLoop().RunUntilIdle();

  // Make the backup job be a pending job, so it completes normally.
  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);
  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));
  // Timer has started, but the backup connect job shouldn't be created yet.
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
  EXPECT_EQ(0, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  ASSERT_THAT(callback.WaitForResult(), IsOk());

  // The hung connect job should still be there, but everything else should be
  // complete.
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(1u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
}

// Tests that a preconnect that starts out with unread data can still be used.
// http://crbug.com/334467
TEST_F(ClientSocketPoolBaseTest, PreconnectWithUnreadData) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  connect_job_factory_->set_job_type(TestConnectJob::kMockUnreadDataJob);

  EXPECT_EQ(
      OK, pool_->RequestSockets(TestGroupId("a"), params_, std::nullopt, 1,
                                CompletionOnceCallback(), NetLogWithSource()));

  ASSERT_TRUE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  // Fail future jobs to be sure that handle receives the preconnected socket
  // rather than closing it and making a new one.
  connect_job_factory_->set_job_type(TestConnectJob::kMockFailingJob);
  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_EQ(OK, handle.Init(
                    TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                    SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                    callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                    pool_.get(), NetLogWithSource()));

  ASSERT_TRUE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));

  // Drain the pending read.
  EXPECT_EQ(1, handle.socket()->Read(nullptr, 1, CompletionOnceCallback()));

  TestLoadTimingInfoConnectedReused(handle);
  handle.Reset();

  // The socket should be usable now that it's idle again.
  EXPECT_EQ(1u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
}

TEST_F(ClientSocketPoolBaseTest, RequestGetsAssignedJob) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);

  ClientSocketHandle handle1;
  TestCompletionCallback callback1;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle1.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback1.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource()));

  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  EXPECT_TRUE(pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"),
                                                              &handle1));
}

TEST_F(ClientSocketPoolBaseTest, MultipleRequestsGetAssignedJobs) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);

  ClientSocketHandle handle1;
  TestCompletionCallback callback1;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle1.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback1.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource()));

  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  ClientSocketHandle handle2;
  TestCompletionCallback callback2;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle2.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback2.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource()));

  EXPECT_EQ(2u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  EXPECT_TRUE(pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"),
                                                              &handle1));
  EXPECT_TRUE(pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"),
                                                              &handle2));

  // One job completes. The other request should still have its job.
  client_socket_factory_.SignalJob(0);
  EXPECT_THAT(callback1.WaitForResult(), IsOk());

  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  EXPECT_TRUE(pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"),
                                                              &handle2));
}

TEST_F(ClientSocketPoolBaseTest, PreconnectJobGetsAssignedToRequest) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);

  TestCompletionCallback preconnect_callback;
  EXPECT_EQ(ERR_IO_PENDING,
            pool_->RequestSockets(TestGroupId("a"), params_, std::nullopt, 1,
                                  preconnect_callback.callback(),
                                  NetLogWithSource()));

  ASSERT_TRUE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(1u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  ClientSocketHandle handle1;
  TestCompletionCallback callback1;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle1.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback1.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource()));

  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  EXPECT_TRUE(pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"),
                                                              &handle1));
}

TEST_F(ClientSocketPoolBaseTest, HigherPriorityRequestStealsJob) {
  CreatePool(kDefaultMaxSockets, 1);
  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);

  ClientSocketHandle handle1;
  TestCompletionCallback callback1;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle1.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback1.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource()));

  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  EXPECT_TRUE(pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"),
                                                              &handle1));

  // Insert a higher priority request
  ClientSocketHandle handle2;
  TestCompletionCallback callback2;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle2.Init(TestGroupId("a"), params_, std::nullopt, HIGHEST,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback2.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource()));

  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  // The highest priority request should steal the job from the default priority
  // request.
  EXPECT_TRUE(pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"),
                                                              &handle2));
  EXPECT_FALSE(pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"),
                                                               &handle1));
}

TEST_F(ClientSocketPoolBaseTest, RequestStealsJobFromLowestRequestWithJob) {
  CreatePool(3, 3);
  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJo
```