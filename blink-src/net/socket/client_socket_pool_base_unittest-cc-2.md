Response:
My thought process for analyzing the provided C++ code snippet and generating the response involved several steps:

1. **Understanding the Core Task:** The primary goal is to analyze a unit test file for the Chromium network stack's `ClientSocketPoolBase`. This means focusing on what the tests are verifying about the socket pooling mechanism.

2. **High-Level Overview:** I quickly scanned the code to get a sense of the test categories. I noticed tests related to:
    * Initialization and cancellation of socket requests.
    * Limits on the number of sockets and connection jobs.
    * Handling of pending requests.
    * Scenarios involving synchronous and asynchronous operations.
    * Closing idle sockets.
    * Error handling and failure cases.
    * Load state tracking.
    * Connection reuse.
    * Request prioritization.

3. **Detailed Analysis of Each Test:** I then went through each test case individually, identifying its purpose. For example, the `ConnectCancelConnect` test clearly checks what happens when a connection attempt is initiated, then cancelled, and then another connection is requested. I looked for `EXPECT_EQ`, `ASSERT_TRUE`, `EXPECT_THAT` statements to understand the assertions being made.

4. **Identifying Key Functionality:**  From the individual tests, I started to synthesize the overall functionality being tested. This involved identifying the main components being interacted with (`ClientSocketPoolBase`, `ClientSocketHandle`, `TestConnectJobFactory`, etc.) and the actions being performed (requesting sockets, cancelling requests, releasing connections, closing sockets).

5. **Relating to JavaScript (if applicable):**  I considered how the underlying socket pooling mechanism might relate to JavaScript. The key connection is the `fetch` API in web browsers. When a JavaScript `fetch` call is made, the browser's network stack (including components like `ClientSocketPoolBase`) handles the actual connection establishment and data transfer. I focused on the fact that these low-level details are generally *hidden* from the JavaScript developer.

6. **Hypothesizing Inputs and Outputs:** For each test, I imagined a simplified scenario and considered the expected outcome. This helped me articulate the "logical reasoning" behind the test. For instance, in a test checking socket limits, the input might be making more requests than allowed, and the output would be that some requests are pending.

7. **Identifying Common User/Programming Errors:** I thought about how developers might misuse socket pooling or encounter issues related to it. Examples include resource leaks due to not properly releasing handles, or unexpected behavior related to connection reuse.

8. **Tracing User Operations (Debugging Context):** I considered how a user's action in a browser (e.g., clicking a link, submitting a form) could lead to the execution of this socket pooling code. This involved thinking about the sequence of events from a high-level browser interaction down to the network stack.

9. **Summarizing Functionality (Part 3):**  Finally, I reviewed all the analyzed tests in Part 3 to create a concise summary of the core features being tested in this particular segment of the file.

**Pre-computation and Pre-analysis (Internal Thought Process):**

* **Understanding the Naming Conventions:** I recognized that the tests use a `Test` prefix, indicating they are part of a unit testing framework (likely Google Test). The names of the tests themselves are descriptive of the scenario being tested.
* **Recognizing Common Network Concepts:**  Terms like "connection job," "idle socket," "active socket," "priority," and error codes like `ERR_IO_PENDING` are standard networking terms that helped me quickly grasp the context.
* **Understanding the Role of Mocks:** The use of `TestConnectJobFactory` and `MockClientSocket` indicated that the tests are using mock objects to control the behavior of dependencies, making the tests more isolated and predictable.
* **Inferring the Purpose of `ClientSocketPoolBase`:** Based on the tests, I inferred that `ClientSocketPoolBase` is responsible for managing a pool of client sockets, handling connection requests, and enforcing limits.

By following these steps, I could systematically analyze the C++ code snippet and generate a comprehensive and informative response that addresses all aspects of the prompt.
这是对Chromium网络堆栈中 `net/socket/client_socket_pool_base_unittest.cc` 文件第三部分的分析和功能归纳。

**功能列举:**

这部分测试用例主要集中在 `ClientSocketPoolBase` 类的以下功能：

1. **请求取消和重试:** 测试在连接建立过程中取消请求 (使用 `Reset()`)，以及取消请求后再次发起请求的行为。
2. **并发连接限制:** 测试在达到每个组的最大连接数 (`kDefaultMaxSocketsPerGroup`) 时，后续的请求会进入等待状态 (`ERR_IO_PENDING`)。
3. **连接取消对连接任务的影响:** 测试取消 `ClientSocketHandle` 如何影响正在进行的连接任务 (`ConnectJob`)，特别是当请求数量超过最大连接数时。
4. **回调函数中的请求:** 测试在连接完成的回调函数中再次发起连接请求的场景，包括同步和异步连接的情况。
5. **取消活动请求对等待请求的影响:** 测试取消已经建立连接的请求后，等待队列中的请求是否能够被处理。
6. **连接失败对等待请求的影响:** 测试当连接尝试失败时，等待队列中的请求是否能够被处理，包括同步和异步失败的情况。
7. **先取消活动请求再请求:** 测试先取消一个正在连接的请求，然后立即重新发起请求的情况。
8. **强制关闭空闲连接:** 测试 `CloseIdleSockets()` 和 `CloseIdleSocketsInGroup()` 方法的功能，包括传入关闭原因。
9. **清理不可用的空闲连接:** 测试当一个空闲连接变得不可用（例如，被远程端关闭）时，连接池如何处理这种情况。
10. **高优先级请求的处理:**  测试在高优先级请求存在时，连接池如何调度连接任务。
11. **异步连接成功和失败:** 测试异步连接请求的成功和失败场景，并验证相关的 NetLog 事件是否正确记录。
12. **多个请求取消其中一个:** 测试在多个请求同时发起的情况下，取消其中一个请求的行为。
13. **取消请求限制连接任务:** 测试取消请求如何影响正在进行的连接任务的数量。
14. **连接释放和请求服务:** 测试连接释放后，等待队列中的请求如何被服务，强调请求和服务之间的解耦。
15. **等待连接任务的完成顺序:** 测试在多个等待连接任务的情况下，请求完成的顺序。
16. **获取加载状态 (LoadState):** 测试在连接过程中获取 `ClientSocketHandle` 的加载状态的功能。

**与 Javascript 的关系 (举例说明):**

虽然这段 C++ 代码是网络栈的底层实现，但它直接支撑着浏览器中 JavaScript 的网络请求功能，例如 `fetch` API 或 `XMLHttpRequest`。

**举例说明:**

当一个 JavaScript 脚本调用 `fetch("https://example.com")` 时，浏览器会执行以下（简化的）步骤：

1. **DNS 解析:** 浏览器需要找到 `example.com` 的 IP 地址。
2. **建立连接:**  网络栈会使用 `ClientSocketPoolBase` 来查找或建立到 `example.com` 服务器的 TCP 连接。
3. **发送请求:**  一旦连接建立，浏览器会发送 HTTP 请求。
4. **接收响应:**  服务器返回 HTTP 响应。

这段代码中的测试用例模拟了 **步骤 2 (建立连接)** 的各种情况：

* **`ConnectCancelConnect`:**  如果 JavaScript 代码在 `fetch` 调用后立即取消 (`abort()`)，然后又发起一个新的 `fetch` 到同一个域名，那么底层的 `ClientSocketPoolBase` 就会经历类似 `ConnectCancelConnect` 测试中的场景。
* **并发连接限制:**  如果 JavaScript 代码同时发起多个 `fetch` 请求到同一个域名，`ClientSocketPoolBase` 会限制并发连接数，超出限制的请求会等待，就像测试中看到的那样。
* **取消活动请求对等待请求的影响:** 如果一个 JavaScript `fetch` 请求正在进行中，用户刷新页面导致请求被取消，那么 `ClientSocketPoolBase` 需要确保其他正在等待连接的请求能够被正常处理。

**假设输入与输出 (逻辑推理):**

**示例 1: `ConnectCancelConnect`**

* **假设输入:**
    1. 发起一个到 `example.com` 的连接请求 A。
    2. 在请求 A 处于 `ERR_IO_PENDING` 状态时，取消请求 A。
    3. 立即发起另一个到 `example.com` 的连接请求 B。
* **预期输出:**
    1. 请求 B 也会返回 `ERR_IO_PENDING`，因为它需要等待一个新的连接任务或复用已有的连接（如果没有被完全清理）。
    2. 最终请求 B 成功建立连接 (`IsOk()`)。
    3. 连接池中会有两个连接任务存在一段时间。

**示例 2: 并发连接限制 (基于 `StartMultiplePending` 和后续的取消):**

* **假设输入:**
    1. 将每个组的最大连接数设置为 2。
    2. 同时发起 4 个到 `example.com` 的连接请求。
* **预期输出:**
    1. 前两个请求会立即返回 `IsOk()` 或 `ERR_IO_PENDING` 并开始连接。
    2. 后两个请求会返回 `ERR_IO_PENDING` 并进入等待队列。
    3. 当前两个请求中的一个或两个完成或被取消后，等待队列中的请求会开始连接。

**用户或编程常见的使用错误 (举例说明):**

1. **忘记释放 `ClientSocketHandle`:**  在 C++ 代码中，如果开发者获取了一个 `ClientSocketHandle` 但没有在不再需要时调用 `Reset()`，可能会导致资源泄露。在 JavaScript 中，这对应于一些底层实现细节，但开发者不当使用 `XMLHttpRequest` 或 `fetch` 可能会间接导致类似的问题。
2. **过度并发连接:**  虽然 `ClientSocketPoolBase` 会进行限制，但在某些性能敏感的应用中，开发者可能会尝试发起过多的并发连接，这可能会导致性能下降，即使连接池能够处理。
3. **错误地假设连接总是会被复用:** 开发者可能会错误地假设到同一个主机的连接总是会被复用，而没有考虑到连接可能由于各种原因被关闭（例如，服务器关闭连接，网络问题等）。这对应于 JavaScript 中，开发者可能没有考虑到请求失败或需要重新建立连接的情况。

**用户操作如何一步步到达这里 (调试线索):**

假设用户在 Chrome 浏览器中访问 `https://example.com/page1` 和 `https://example.com/page2`：

1. **用户输入 URL 或点击链接:** 用户在地址栏输入 `https://example.com/page1` 或点击一个指向该链接。
2. **浏览器发起网络请求:** Chrome 的渲染进程会发起一个网络请求。
3. **查找或建立连接:** 网络请求会到达网络栈，`ClientSocketPoolBase` 会检查连接池中是否有到 `example.com` 的可用连接。
4. **创建连接任务 (如果需要):** 如果没有可用连接，`ClientSocketPoolBase` 会创建一个 `ConnectJob` 来建立新的 TCP 连接。
5. **进行 TCP 握手和 TLS 握手 (如果使用 HTTPS):** 底层的 TCP 和 TLS 代码会执行握手过程。
6. **连接建立成功:**  `ClientSocketPoolBase` 会将建立的连接放入连接池中，并通知请求方连接已建立。
7. **发送 HTTP 请求和接收响应:**  浏览器发送 HTTP 请求并接收服务器的响应。
8. **用户操作触发新的请求:** 用户可能在 `page1` 中点击一个链接指向 `https://example.com/page2`。
9. **连接复用或新建:** `ClientSocketPoolBase` 会尝试复用之前建立的到 `example.com` 的连接。如果连接仍然可用且符合复用条件，则直接使用；否则，可能需要建立新的连接（取决于连接池的状态和配置）。

当开发者需要调试网络连接相关的问题时，他们可能会查看 Chrome 的 `chrome://net-internals/#sockets` 页面，这个页面会显示当前连接池的状态，包括空闲连接、活动连接和正在进行的连接任务。这里的底层逻辑就涉及到 `ClientSocketPoolBase` 的实现。

**功能归纳 (第 3 部分):**

这部分测试用例主要关注 `ClientSocketPoolBase` 在**请求生命周期管理**方面的功能，包括：

* **连接的建立与取消:**  测试了在连接建立的不同阶段取消请求的影响，以及取消后重新请求的行为。
* **资源限制与并发控制:** 验证了连接池如何限制并发连接的数量，以及如何处理超出限制的请求。
* **请求的排队与调度:**  测试了在连接建立过程中，请求的排队、优先级处理以及在连接释放后请求被服务的方式。
* **连接状态管理:**  测试了获取连接加载状态的功能。
* **连接的清理与维护:**  验证了连接池如何处理不再需要的或不可用的连接。

总而言之，这部分测试确保了 `ClientSocketPoolBase` 能够有效地管理客户端套接字连接的生命周期，处理各种复杂的并发和取消场景，并确保网络请求的可靠性和效率。

Prompt: 
```
这是目录为net/socket/client_socket_pool_base_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共8部分，请归纳一下它的功能

"""
IO_PENDING,
                handle->Init(
                    TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                    SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                    callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                    pool_.get(), NetLogWithSource()));
      handles.push_back(std::move(handle));
      ASSERT_TRUE(pool_->HasGroupForTesting(TestGroupId("a")));
      EXPECT_EQ(
          static_cast<size_t>(std::min(i + 1, kDefaultMaxSocketsPerGroup)),
          pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
    }

    if (cancel_when_callback_pending) {
      client_socket_factory_.SignalJobs();
      ASSERT_TRUE(pool_->HasGroupForTesting(TestGroupId("a")));
      EXPECT_EQ(kDefaultMaxSocketsPerGroup,
                pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
    }

    // Calling ResetAndCloseSocket() on a handle should not cancel a ConnectJob
    // or close a socket, since there are more requests than ConnectJobs or
    // sockets.
    handles[kDefaultMaxSocketsPerGroup]->ResetAndCloseSocket();
    ASSERT_TRUE(pool_->HasGroupForTesting(TestGroupId("a")));
    if (cancel_when_callback_pending) {
      EXPECT_EQ(kDefaultMaxSocketsPerGroup,
                pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
    } else {
      EXPECT_EQ(static_cast<size_t>(kDefaultMaxSocketsPerGroup),
                pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
    }

    // Calling ResetAndCloseSocket() on other handles should cancel a ConnectJob
    // or close a socket.
    for (int i = kDefaultMaxSocketsPerGroup - 1; i >= 0; --i) {
      handles[i]->ResetAndCloseSocket();
      if (i > 0) {
        ASSERT_TRUE(pool_->HasGroupForTesting(TestGroupId("a")));
        if (cancel_when_callback_pending) {
          EXPECT_EQ(i,
                    pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
        } else {
          EXPECT_EQ(static_cast<size_t>(i),
                    pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
        }
      } else {
        EXPECT_FALSE(pool_->HasGroupForTesting(TestGroupId("a")));
      }
    }
  }
}

TEST_F(ClientSocketPoolBaseTest, ConnectCancelConnect) {
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

  // This will create a second ConnectJob, since the other ConnectJob was
  // previously assigned to a request.
  TestCompletionCallback callback2;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback2.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));

  ASSERT_TRUE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(2u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_FALSE(callback.have_result());
  ASSERT_TRUE(pool_->HasGroupForTesting(TestGroupId("a")));
  // One ConnectJob completed, and its socket is now assigned to |handle|.
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  // The other ConnectJob should have either completed, or still be connecting.
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")) +
                    pool_->IdleSocketCountInGroup(TestGroupId("a")));

  handle.Reset();
  ASSERT_TRUE(pool_->HasGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(2u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")) +
                    pool_->IdleSocketCountInGroup(TestGroupId("a")));
  EXPECT_EQ(0, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
}

TEST_F(ClientSocketPoolBaseTest, CancelRequest) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("a"), LOWEST), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), MEDIUM), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), HIGHEST), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), LOW), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), LOWEST), IsError(ERR_IO_PENDING));

  // Cancel a request.
  size_t index_to_cancel = kDefaultMaxSocketsPerGroup + 2;
  EXPECT_FALSE((*requests())[index_to_cancel]->handle()->is_initialized());
  (*requests())[index_to_cancel]->handle()->Reset();

  ReleaseAllConnections(ClientSocketPoolTest::KEEP_ALIVE);

  EXPECT_EQ(kDefaultMaxSocketsPerGroup,
            client_socket_factory_.allocation_count());
  EXPECT_EQ(requests_size() - kDefaultMaxSocketsPerGroup - 1,
            completion_count());

  EXPECT_EQ(1, GetOrderOfRequest(1));
  EXPECT_EQ(2, GetOrderOfRequest(2));
  EXPECT_EQ(5, GetOrderOfRequest(3));
  EXPECT_EQ(3, GetOrderOfRequest(4));
  EXPECT_EQ(ClientSocketPoolTest::kRequestNotFound,
            GetOrderOfRequest(5));  // Canceled request.
  EXPECT_EQ(4, GetOrderOfRequest(6));
  EXPECT_EQ(6, GetOrderOfRequest(7));

  // Make sure we test order of all requests made.
  EXPECT_EQ(ClientSocketPoolTest::kIndexOutOfBounds, GetOrderOfRequest(8));
}

// Function to be used as a callback on socket request completion.  It first
// disconnects the successfully connected socket from the first request, and
// then reuses the ClientSocketHandle to request another socket.
//
// |nested_callback| is called with the result of the second socket request.
void RequestSocketOnComplete(ClientSocketHandle* handle,
                             TransportClientSocketPool* pool,
                             TestConnectJobFactory* test_connect_job_factory,
                             TestConnectJob::JobType next_job_type,
                             TestCompletionCallback* nested_callback,
                             int first_request_result) {
  EXPECT_THAT(first_request_result, IsOk());

  test_connect_job_factory->set_job_type(next_job_type);

  // Don't allow reuse of the socket.  Disconnect it and then release it.
  if (handle->socket()) {
    handle->socket()->Disconnect();
  }
  handle->Reset();

  TestCompletionCallback callback;
  int rv = handle->Init(
      TestGroupId("a"),
      ClientSocketPool::SocketParams::CreateForHttpForTesting(), std::nullopt,
      LOWEST, SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
      nested_callback->callback(), ClientSocketPool::ProxyAuthCallback(), pool,
      NetLogWithSource());
  if (rv != ERR_IO_PENDING) {
    DCHECK_EQ(TestConnectJob::kMockJob, next_job_type);
    nested_callback->callback().Run(rv);
  } else {
    DCHECK_EQ(TestConnectJob::kMockPendingJob, next_job_type);
  }
}

// Tests the case where a second socket is requested in a completion callback,
// and the second socket connects asynchronously.  Reuses the same
// ClientSocketHandle for the second socket, after disconnecting the first.
TEST_F(ClientSocketPoolBaseTest, RequestPendingJobTwice) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);
  ClientSocketHandle handle;
  TestCompletionCallback second_result_callback;
  int rv = handle.Init(
      TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY, SocketTag(),
      ClientSocketPool::RespectLimits::ENABLED,
      base::BindOnce(&RequestSocketOnComplete, &handle, pool_.get(),
                     connect_job_factory_, TestConnectJob::kMockPendingJob,
                     &second_result_callback),
      ClientSocketPool::ProxyAuthCallback(), pool_.get(), NetLogWithSource());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_THAT(second_result_callback.WaitForResult(), IsOk());
}

// Tests the case where a second socket is requested in a completion callback,
// and the second socket connects synchronously.  Reuses the same
// ClientSocketHandle for the second socket, after disconnecting the first.
TEST_F(ClientSocketPoolBaseTest, RequestPendingJobThenSynchronous) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);
  ClientSocketHandle handle;
  TestCompletionCallback second_result_callback;
  int rv = handle.Init(
      TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY, SocketTag(),
      ClientSocketPool::RespectLimits::ENABLED,
      base::BindOnce(&RequestSocketOnComplete, &handle, pool_.get(),
                     connect_job_factory_, TestConnectJob::kMockPendingJob,
                     &second_result_callback),
      ClientSocketPool::ProxyAuthCallback(), pool_.get(), NetLogWithSource());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_THAT(second_result_callback.WaitForResult(), IsOk());
}

// Make sure that pending requests get serviced after active requests get
// cancelled.
TEST_F(ClientSocketPoolBaseTest, CancelActiveRequestWithPendingRequests) {
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
  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY),
              IsError(ERR_IO_PENDING));

  // Now, kDefaultMaxSocketsPerGroup requests should be active.
  // Let's cancel them.
  for (int i = 0; i < kDefaultMaxSocketsPerGroup; ++i) {
    ASSERT_FALSE(request(i)->handle()->is_initialized());
    request(i)->handle()->Reset();
  }

  // Let's wait for the rest to complete now.
  for (size_t i = kDefaultMaxSocketsPerGroup; i < requests_size(); ++i) {
    EXPECT_THAT(request(i)->WaitForResult(), IsOk());
    request(i)->handle()->Reset();
  }

  EXPECT_EQ(requests_size() - kDefaultMaxSocketsPerGroup, completion_count());
}

// Make sure that pending requests get serviced after active requests fail.
TEST_F(ClientSocketPoolBaseTest, FailingActiveRequestWithPendingRequests) {
  const size_t kMaxSockets = 5;
  CreatePool(kMaxSockets, kDefaultMaxSocketsPerGroup);

  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingFailingJob);

  const size_t kNumberOfRequests = 2 * kDefaultMaxSocketsPerGroup + 1;
  ASSERT_LE(kNumberOfRequests, kMaxSockets);  // Otherwise the test will hang.

  // Queue up all the requests
  for (size_t i = 0; i < kNumberOfRequests; ++i) {
    EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY),
                IsError(ERR_IO_PENDING));
  }

  for (size_t i = 0; i < kNumberOfRequests; ++i) {
    EXPECT_THAT(request(i)->WaitForResult(), IsError(ERR_CONNECTION_FAILED));
  }
}

// Make sure that pending requests that complete synchronously get serviced
// after active requests fail. See https://crbug.com/723748
TEST_F(ClientSocketPoolBaseTest, HandleMultipleSyncFailuresAfterAsyncFailure) {
  const size_t kNumberOfRequests = 10;
  const size_t kMaxSockets = 1;
  CreatePool(kMaxSockets, kMaxSockets);

  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingFailingJob);

  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY),
              IsError(ERR_IO_PENDING));

  connect_job_factory_->set_job_type(TestConnectJob::kMockFailingJob);

  // Queue up all the other requests
  for (size_t i = 1; i < kNumberOfRequests; ++i) {
    EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY),
                IsError(ERR_IO_PENDING));
  }

  // Make sure all requests fail, instead of hanging.
  for (size_t i = 0; i < kNumberOfRequests; ++i) {
    EXPECT_THAT(request(i)->WaitForResult(), IsError(ERR_CONNECTION_FAILED));
  }
}

TEST_F(ClientSocketPoolBaseTest, CancelActiveRequestThenRequestSocket) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);

  ClientSocketHandle handle;
  TestCompletionCallback callback;
  int rv = handle.Init(
      TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY, SocketTag(),
      ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
      ClientSocketPool::ProxyAuthCallback(), pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Cancel the active request.
  handle.Reset();

  rv = handle.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  EXPECT_FALSE(handle.is_reused());
  TestLoadTimingInfoConnectedNotReused(handle);
  EXPECT_EQ(2, client_socket_factory_.allocation_count());
}

TEST_F(ClientSocketPoolBaseTest, CloseIdleSocketsForced) {
  const char kReason[] = "Really nifty reason";

  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  ClientSocketHandle handle;
  TestCompletionCallback callback;
  int rv =
      handle.Init(TestGroupId("a"), params_, std::nullopt, LOWEST, SocketTag(),
                  ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
                  ClientSocketPool::ProxyAuthCallback(), pool_.get(),
                  NetLogWithSource::Make(NetLogSourceType::NONE));
  EXPECT_THAT(rv, IsOk());
  ASSERT_TRUE(handle.socket());
  NetLogSource source = handle.socket()->NetLog().source();
  handle.Reset();
  EXPECT_EQ(1, pool_->IdleSocketCount());
  pool_->CloseIdleSockets(kReason);
  ExpectSocketClosedWithReason(source, kReason);
}

TEST_F(ClientSocketPoolBaseTest, CloseIdleSocketsInGroupForced) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  TestCompletionCallback callback;
  NetLogWithSource net_log_with_source =
      NetLogWithSource::Make(NetLogSourceType::NONE);
  ClientSocketHandle handle1;
  int rv = handle1.Init(
      TestGroupId("a"), params_, std::nullopt, LOWEST, SocketTag(),
      ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
      ClientSocketPool::ProxyAuthCallback(), pool_.get(), net_log_with_source);
  EXPECT_THAT(rv, IsOk());
  ClientSocketHandle handle2;
  rv = handle2.Init(TestGroupId("a"), params_, std::nullopt, LOWEST,
                    SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                    callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                    pool_.get(), net_log_with_source);
  ClientSocketHandle handle3;
  rv = handle3.Init(TestGroupId("b"), params_, std::nullopt, LOWEST,
                    SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                    callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                    pool_.get(), net_log_with_source);
  EXPECT_THAT(rv, IsOk());
  handle1.Reset();
  handle2.Reset();
  handle3.Reset();
  EXPECT_EQ(3, pool_->IdleSocketCount());
  pool_->CloseIdleSocketsInGroup(TestGroupId("a"), "Very good reason");
  EXPECT_EQ(1, pool_->IdleSocketCount());
}

TEST_F(ClientSocketPoolBaseTest, CleanUpUnusableIdleSockets) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  ClientSocketHandle handle;
  TestCompletionCallback callback;
  NetLogWithSource net_log_with_source =
      NetLogWithSource::Make(NetLogSourceType::NONE);
  int rv = handle.Init(
      TestGroupId("a"), params_, std::nullopt, LOWEST, SocketTag(),
      ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
      ClientSocketPool::ProxyAuthCallback(), pool_.get(), net_log_with_source);
  EXPECT_THAT(rv, IsOk());
  StreamSocket* socket = handle.socket();
  ASSERT_TRUE(socket);
  handle.Reset();
  EXPECT_EQ(1, pool_->IdleSocketCount());

  // Disconnect socket now to make the socket unusable.
  NetLogSource source = socket->NetLog().source();
  socket->Disconnect();
  ClientSocketHandle handle2;
  rv = handle2.Init(TestGroupId("a"), params_, std::nullopt, LOWEST,
                    SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                    callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                    pool_.get(), net_log_with_source);
  EXPECT_THAT(rv, IsOk());
  EXPECT_FALSE(handle2.is_reused());

  // This is admittedly not an accurate error in this case, but normally code
  // doesn't secretly keep a raw pointers to sockets returned to the socket pool
  // and close them out of band, so discovering an idle socket was closed when
  // trying to reuse it normally means it was closed by the remote side.
  ExpectSocketClosedWithReason(
      source, TransportClientSocketPool::kRemoteSideClosedConnection);
}

// Regression test for http://crbug.com/17985.
TEST_F(ClientSocketPoolBaseTest, GroupWithPendingRequestsIsNotEmpty) {
  const int kMaxSockets = 3;
  const int kMaxSocketsPerGroup = 2;
  CreatePool(kMaxSockets, kMaxSocketsPerGroup);

  const RequestPriority kHighPriority = HIGHEST;

  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY), IsOk());
  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY), IsOk());

  // This is going to be a pending request in an otherwise empty group.
  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY),
              IsError(ERR_IO_PENDING));

  // Reach the maximum socket limit.
  EXPECT_THAT(StartRequest(TestGroupId("b"), DEFAULT_PRIORITY), IsOk());

  // Create a stalled group with high priorities.
  EXPECT_THAT(StartRequest(TestGroupId("c"), kHighPriority),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("c"), kHighPriority),
              IsError(ERR_IO_PENDING));

  // Release the first two sockets from TestGroupId("a").  Because this is a
  // keepalive, the first release will unblock the pending request for
  // TestGroupId("a").  The second release will unblock a request for "c",
  // because it is the next high priority socket.
  EXPECT_TRUE(ReleaseOneConnection(ClientSocketPoolTest::KEEP_ALIVE));
  EXPECT_TRUE(ReleaseOneConnection(ClientSocketPoolTest::KEEP_ALIVE));

  // Closing idle sockets should not get us into trouble, but in the bug
  // we were hitting a CHECK here.
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
  pool_->CloseIdleSockets("Very good reason");

  // Run the released socket wakeups.
  base::RunLoop().RunUntilIdle();
}

TEST_F(ClientSocketPoolBaseTest, BasicAsynchronous) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);
  ClientSocketHandle handle;
  TestCompletionCallback callback;
  NetLogWithSource net_log_with_source =
      NetLogWithSource::Make(NetLogSourceType::NONE);
  int rv = handle.Init(
      TestGroupId("a"), params_, std::nullopt, LOWEST, SocketTag(),
      ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
      ClientSocketPool::ProxyAuthCallback(), pool_.get(), net_log_with_source);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_EQ(LOAD_STATE_CONNECTING,
            pool_->GetLoadState(TestGroupId("a"), &handle));
  TestLoadTimingInfoNotConnected(handle);

  EXPECT_THAT(callback.WaitForResult(), IsOk());
  EXPECT_TRUE(handle.is_initialized());
  EXPECT_TRUE(handle.socket());
  TestLoadTimingInfoConnectedNotReused(handle);

  handle.Reset();
  TestLoadTimingInfoNotConnected(handle);

  auto entries =
      net_log_observer_.GetEntriesForSource(net_log_with_source.source());

  EXPECT_EQ(5u, entries.size());
  EXPECT_TRUE(LogContainsEvent(
      entries, 0, NetLogEventType::TCP_CLIENT_SOCKET_POOL_REQUESTED_SOCKET,
      NetLogEventPhase::NONE));
  EXPECT_TRUE(LogContainsBeginEvent(entries, 1, NetLogEventType::SOCKET_POOL));
  EXPECT_TRUE(LogContainsEvent(
      entries, 2, NetLogEventType::SOCKET_POOL_BOUND_TO_CONNECT_JOB,
      NetLogEventPhase::NONE));
  EXPECT_TRUE(LogContainsEvent(entries, 3,
                               NetLogEventType::SOCKET_POOL_BOUND_TO_SOCKET,
                               NetLogEventPhase::NONE));
  EXPECT_TRUE(LogContainsEndEvent(entries, 4, NetLogEventType::SOCKET_POOL));
}

TEST_F(ClientSocketPoolBaseTest, InitConnectionAsynchronousFailure) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingFailingJob);
  ClientSocketHandle handle;
  TestCompletionCallback callback;
  NetLogWithSource net_log_with_source =
      NetLogWithSource::Make(NetLogSourceType::NONE);
  // Set the additional error state members to ensure that they get cleared.
  handle.set_is_ssl_error(true);
  handle.set_ssl_cert_request_info(base::MakeRefCounted<SSLCertRequestInfo>());
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), net_log_with_source));
  EXPECT_EQ(LOAD_STATE_CONNECTING,
            pool_->GetLoadState(TestGroupId("a"), &handle));
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_CONNECTION_FAILED));
  EXPECT_FALSE(handle.is_ssl_error());
  EXPECT_FALSE(handle.ssl_cert_request_info());

  auto entries =
      net_log_observer_.GetEntriesForSource(net_log_with_source.source());

  EXPECT_EQ(4u, entries.size());
  EXPECT_TRUE(LogContainsEvent(
      entries, 0, NetLogEventType::TCP_CLIENT_SOCKET_POOL_REQUESTED_SOCKET,
      NetLogEventPhase::NONE));
  EXPECT_TRUE(LogContainsBeginEvent(entries, 1, NetLogEventType::SOCKET_POOL));
  EXPECT_TRUE(LogContainsEvent(
      entries, 2, NetLogEventType::SOCKET_POOL_BOUND_TO_CONNECT_JOB,
      NetLogEventPhase::NONE));
  EXPECT_TRUE(LogContainsEndEvent(entries, 3, NetLogEventType::SOCKET_POOL));
}

// Check that an async ConnectJob failure does not result in creation of a new
// ConnectJob when there's another pending request also waiting on its own
// ConnectJob.  See http://crbug.com/463960.
TEST_F(ClientSocketPoolBaseTest, AsyncFailureWithPendingRequestWithJob) {
  CreatePool(2, 2);
  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingFailingJob);

  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY),
              IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), DEFAULT_PRIORITY),
              IsError(ERR_IO_PENDING));

  EXPECT_THAT(request(0)->WaitForResult(), IsError(ERR_CONNECTION_FAILED));
  EXPECT_THAT(request(1)->WaitForResult(), IsError(ERR_CONNECTION_FAILED));

  EXPECT_EQ(2, client_socket_factory_.allocation_count());
}

TEST_F(ClientSocketPoolBaseTest, TwoRequestsCancelOne) {
  // TODO(eroman): Add back the log expectations! Removed them because the
  //               ordering is difficult, and some may fire during destructor.
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);
  ClientSocketHandle handle;
  TestCompletionCallback callback;
  ClientSocketHandle handle2;
  TestCompletionCallback callback2;

  EXPECT_EQ(
      ERR_IO_PENDING,
      handle.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));
  RecordingNetLogObserver log2;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle2.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback2.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource()));

  handle.Reset();

  // At this point, request 2 is just waiting for the connect job to finish.

  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  handle2.Reset();

  // Now request 2 has actually finished.
  // TODO(eroman): Add back log expectations.
}

TEST_F(ClientSocketPoolBaseTest, CancelRequestLimitsJobs) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);

  EXPECT_THAT(StartRequest(TestGroupId("a"), LOWEST), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), LOW), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), MEDIUM), IsError(ERR_IO_PENDING));
  EXPECT_THAT(StartRequest(TestGroupId("a"), HIGHEST), IsError(ERR_IO_PENDING));

  EXPECT_EQ(kDefaultMaxSocketsPerGroup,
            static_cast<int>(
                pool_->NumConnectJobsInGroupForTesting(TestGroupId("a"))));
  (*requests())[2]->handle()->Reset();
  (*requests())[3]->handle()->Reset();
  EXPECT_EQ(kDefaultMaxSocketsPerGroup,
            static_cast<int>(
                pool_->NumConnectJobsInGroupForTesting(TestGroupId("a"))));

  (*requests())[1]->handle()->Reset();
  EXPECT_EQ(kDefaultMaxSocketsPerGroup,
            static_cast<int>(
                pool_->NumConnectJobsInGroupForTesting(TestGroupId("a"))));

  (*requests())[0]->handle()->Reset();
  EXPECT_EQ(kDefaultMaxSocketsPerGroup,
            static_cast<int>(
                pool_->NumConnectJobsInGroupForTesting(TestGroupId("a"))));
}

// When requests and ConnectJobs are not coupled, the request will get serviced
// by whatever comes first.
TEST_F(ClientSocketPoolBaseTest, ReleaseSockets) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);

  // Start job 1 (async OK)
  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);

  std::vector<raw_ptr<TestSocketRequest, VectorExperimental>> request_order;
  size_t completion_count;  // unused
  TestSocketRequest req1(&request_order, &completion_count);
  int rv = req1.handle()->Init(
      TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY, SocketTag(),
      ClientSocketPool::RespectLimits::ENABLED, req1.callback(),
      ClientSocketPool::ProxyAuthCallback(), pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(req1.WaitForResult(), IsOk());

  // Job 1 finished OK.  Start job 2 (also async OK).  Request 3 is pending
  // without a job.
  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);

  TestSocketRequest req2(&request_order, &completion_count);
  rv = req2.handle()->Init(
      TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY, SocketTag(),
      ClientSocketPool::RespectLimits::ENABLED, req2.callback(),
      ClientSocketPool::ProxyAuthCallback(), pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  TestSocketRequest req3(&request_order, &completion_count);
  rv = req3.handle()->Init(
      TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY, SocketTag(),
      ClientSocketPool::RespectLimits::ENABLED, req3.callback(),
      ClientSocketPool::ProxyAuthCallback(), pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Both Requests 2 and 3 are pending.  We release socket 1 which should
  // service request 2.  Request 3 should still be waiting.
  req1.handle()->Reset();
  // Run the released socket wakeups.
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(req2.handle()->socket());
  EXPECT_THAT(req2.WaitForResult(), IsOk());
  EXPECT_FALSE(req3.handle()->socket());

  // Signal job 2, which should service request 3.

  client_socket_factory_.SignalJobs();
  EXPECT_THAT(req3.WaitForResult(), IsOk());

  ASSERT_EQ(3u, request_order.size());
  EXPECT_EQ(&req1, request_order[0]);
  EXPECT_EQ(&req2, request_order[1]);
  EXPECT_EQ(&req3, request_order[2]);
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
}

// The requests are not coupled to the jobs.  So, the requests should finish in
// their priority / insertion order.
TEST_F(ClientSocketPoolBaseTest, PendingJobCompletionOrder) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  // First two jobs are async.
  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingFailingJob);

  std::vector<raw_ptr<TestSocketRequest, VectorExperimental>> request_order;
  size_t completion_count;  // unused
  TestSocketRequest req1(&request_order, &completion_count);
  int rv = req1.handle()->Init(
      TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY, SocketTag(),
      ClientSocketPool::RespectLimits::ENABLED, req1.callback(),
      ClientSocketPool::ProxyAuthCallback(), pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  TestSocketRequest req2(&request_order, &completion_count);
  rv = req2.handle()->Init(
      TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY, SocketTag(),
      ClientSocketPool::RespectLimits::ENABLED, req2.callback(),
      ClientSocketPool::ProxyAuthCallback(), pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // The pending job is sync.
  connect_job_factory_->set_job_type(TestConnectJob::kMockJob);

  TestSocketRequest req3(&request_order, &completion_count);
  rv = req3.handle()->Init(
      TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY, SocketTag(),
      ClientSocketPool::RespectLimits::ENABLED, req3.callback(),
      ClientSocketPool::ProxyAuthCallback(), pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  EXPECT_THAT(req1.WaitForResult(), IsError(ERR_CONNECTION_FAILED));
  EXPECT_THAT(req2.WaitForResult(), IsOk());
  EXPECT_THAT(req3.WaitForResult(), IsError(ERR_CONNECTION_FAILED));

  ASSERT_EQ(3u, request_order.size());
  EXPECT_EQ(&req1, request_order[0]);
  EXPECT_EQ(&req2, request_order[1]);
  EXPECT_EQ(&req3, request_order[2]);
}

// Test GetLoadState in the case there's only one socket request.
TEST_F(ClientSocketPoolBaseTest, LoadStateOneRequest) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);

  ClientSocketHandle handle;
  TestCompletionCallback callback;
  int rv = handle.Init(
      TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY, SocketTag(),
      ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
      ClientSocketPool::ProxyAuthCallback(), pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_EQ(LOAD_STATE_CONNECTING, handle.GetLoadState());

  client_socket_factory_.SetJobLoadState(0, LOAD_STATE_SSL_HANDSHAKE);
  EXPECT_EQ(LOAD_STATE_SSL_HANDSHAKE, handle.GetLoadState());

  // No point in completing the connection, since ClientSocketHandles only
  // expect the LoadState to be checked while connecting.
}

// Test GetLoadState in the case there are two socket requests.
TEST_F(ClientSocketPoolBaseTest, LoadStateTwoRequests) {
  CreatePool(2, 2);
  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);

  ClientSocketHandle handle;
  TestCompletionCallback callback;
  int rv = handle.Init(
      TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY, SocketTag(),
      ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
      ClientSocketPool::ProxyAuthCallback(), pool_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  client_socket_factory_.SetJobLoadState(0, LOAD_STATE_RESOLVING_HOST);

  ClientSocketHandle handle2;
  TestCompletionCallback callback2;
  rv = handle2.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                    SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                    callback2.callback(), ClientSocketPool::ProxyAuthCallback(),
                    pool_.get(), NetLogWithSource());
  EXPECT_THAT(r
"""


```