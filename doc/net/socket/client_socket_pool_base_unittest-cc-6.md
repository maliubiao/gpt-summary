Response:
Let's break down the thought process for analyzing this code snippet and generating the comprehensive response.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the provided C++ code snippet, which is part of Chromium's networking stack, specifically related to `client_socket_pool_base_unittest.cc`. The request also asks to relate it to JavaScript (if possible), discuss logic, common errors, debugging, and summarize its function within a larger context.

**2. Initial Code Scan and Keyword Identification:**

First, a quick skim of the code reveals key terms and patterns:

* **`TEST_F(ClientSocketPoolBaseTest, ...)`:**  Indicates this is a unit test file for a class named `ClientSocketPoolBase`.
* **`ClientSocketHandle`:**  Suggests managing client sockets.
* **`ClientSocketPool`:**  The core class being tested, likely responsible for pooling and managing client sockets.
* **`TestCompletionCallback`:**  Used for asynchronous operations, waiting for results.
* **`ERR_IO_PENDING`:**  A specific error code indicating an operation is in progress.
* **`RequestPriority` (LOWEST, LOW, MEDIUM, HIGHEST, DEFAULT_PRIORITY, MAXIMUM_PRIORITY):**  Highlights the importance of request prioritization in the socket pool.
* **`SocketTag`:**  Likely a mechanism for identifying or tagging sockets.
* **`RespectLimits` (ENABLED, DISABLED):**  Indicates control over whether connection limits are enforced.
* **`NumConnectJobsInGroupForTesting`:**  A testing method to check the number of connection jobs.
* **`IdleSocketCountInGroup`:**  Another testing method, checking idle sockets.
* **`ReprioritizeRequestStealsJob`:**  A specific test case name that gives a strong hint about its function.
* **`CancelRequestReassignsJob`:**  Another informative test case name.
* **`JobCompletionReassignsJob`:**  Yet another informative test case name.
* **`MockLayeredPool`:**  Suggests testing interaction with higher-level abstractions.
* **`CloseIdleSocketsHeldByLayeredPoolWhenNeeded`:**  Another descriptive test name.
* **`IgnoreLimits`:** A test case about bypassing connection limits.
* **`ProxyAuthCallback`:** Indicates handling of proxy authentication.
* **`ERR_PROXY_AUTH_REQUESTED`:**  A specific error related to proxy authentication.

**3. Deeper Dive into Individual Tests:**

Next, each `TEST_F` function needs closer examination to understand its specific purpose:

* **`PrioritizeStalledGroup`:** Tests how requests within a stalled group are prioritized when a socket becomes available. It checks that higher priority requests get the connection first.
* **`ReprioritizeRequestStealsJob`:**  Verifies that when a request's priority is increased, it can "steal" a connection job from a lower priority request.
* **`CancelRequestReassignsJob`:**  Confirms that canceling a request with an assigned connection job allows another pending request to take that job.
* **`JobCompletionReassignsJob`:**  Checks that when a connection job completes, the resulting socket is assigned to the highest priority waiting request.
* **`CloseIdleSocketsHeldByLayeredPoolWhenNeeded` (and variations):** These tests involve a `MockLayeredPool`, suggesting interaction with higher-level components. They focus on scenarios where the socket pool is at its limit, and the pool attempts to close idle sockets held by the layered pool to accommodate new requests.
* **`IgnoreLimits` and `IgnoreLimitsCancelOtherJob`:** These tests verify the behavior when `RespectLimits::DISABLED` is used, allowing requests to bypass connection limits.
* **`ProxyAuthNoAuthCallback`:** Tests the scenario where proxy authentication is required, but no authentication callback is provided, resulting in an error.

**4. Identifying Core Functionality:**

Based on the test cases, the core functionality being tested is:

* **Request Prioritization:** How the socket pool handles requests with different priorities, especially in cases of limited resources.
* **Connection Job Management:** How the pool creates, assigns, and reassigns connection jobs to pending requests.
* **Resource Limits:**  How the pool respects and can bypass configured connection limits.
* **Interaction with Higher Layers:** How the pool interacts with higher-level components (like the `MockLayeredPool`) to manage resources.
* **Proxy Authentication:** Basic handling of proxy authentication requests.

**5. Relating to JavaScript (and Recognizing Limitations):**

The request asks about the relationship to JavaScript. While this C++ code is low-level, it's a foundational part of the browser's networking stack that directly impacts how web requests initiated by JavaScript are handled. The key connection is that when JavaScript makes an HTTP request (e.g., using `fetch` or `XMLHttpRequest`), the browser's networking code (including the `ClientSocketPool`) is responsible for establishing and managing the underlying TCP connections.

**6. Logic, Assumptions, and Examples:**

For each test, I mentally simulated the flow of execution and the expected outcomes. This involved making assumptions about the internal workings of the `ClientSocketPool` based on the test names and the assertions. For example, in `PrioritizeStalledGroup`, the assumption is that the pool maintains a prioritized queue of pending requests. The example inputs and outputs are directly derived from the test code itself (the `EXPECT_EQ` calls).

**7. Common Errors and Debugging:**

Thinking about common errors involved considering scenarios where the developer might misconfigure the socket pool, misuse the API, or misunderstand the priority mechanisms. The debugging section focused on how to trace the execution flow to pinpoint issues related to socket acquisition and connection establishment.

**8. Summarizing the Functionality (Part 7 of 8):**

Given the context of "part 7 of 8," I considered what aspects of the socket pool might be covered in this specific section. The focus on prioritization, resource limits, interaction with higher layers, and proxy authentication seemed like a natural progression in testing the overall functionality.

**9. Structuring the Response:**

Finally, I organized the information into the requested categories: Functionality, Relationship to JavaScript, Logic and Examples, Common Errors, Debugging, and Summary. This structured approach ensures clarity and addresses all aspects of the prompt.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus too much on low-level socket details.
* **Correction:**  Shift focus to the higher-level concerns of the `ClientSocketPool`, such as request management, prioritization, and resource control.
* **Initial thought:**  Overlook the connection to JavaScript.
* **Correction:** Explicitly explain how this low-level C++ code enables web requests initiated by JavaScript.
* **Initial thought:**  Provide overly simplistic examples for logic.
* **Correction:** Use the actual test cases as examples, as they provide concrete input and output scenarios.
* **Initial thought:**  Make assumptions about internal implementation details without justification.
* **Correction:** Base assumptions on the observable behavior and the names of the testing methods.

By following this iterative process of scanning, analyzing, inferring, and organizing, I was able to generate a comprehensive and accurate response to the request.
好的，这是对 `net/socket/client_socket_pool_base_unittest.cc` 文件中提供的代码片段的功能进行分析：

**功能归纳（基于提供的代码片段）：**

这个代码片段主要集中在测试 `ClientSocketPoolBase` 类的以下功能：

1. **请求优先级 (Request Prioritization):**
   - 测试当连接池资源受限时，不同优先级的请求如何被处理。
   - 验证更高优先级的请求是否能优先获得连接机会。
   - 测试当连接池已满时，更高优先级的请求是否能“抢占”正在建立连接的低优先级请求的资源。

2. **请求的取消与重新分配 (Request Cancellation and Reassignment):**
   - 测试当一个持有连接建立任务的请求被取消后，该任务是否会被重新分配给其他等待的请求。

3. **连接任务的完成与重新分配 (Connection Job Completion and Reassignment):**
   - 测试当一个连接任务完成时，新建立的连接是否会被分配给最高优先级的等待请求。
   - 验证当一个较低优先级的连接任务先完成时，较高优先级的请求会获得连接，而较低优先级的请求会获得新的连接任务。

4. **与更高层连接池的交互 (Interaction with Higher Layered Pools):**
   - 测试当底层连接池资源受限时，是否可以请求更高层连接池关闭空闲连接，以便为新请求腾出空间。
   - 涵盖了尝试关闭更高层连接池的空闲连接成功和失败的情况。
   - 涉及了空闲连接与受阻请求处于同一组的情况。

5. **忽略连接限制 (Ignoring Connection Limits):**
   - 测试当请求设置了 `RespectLimits::DISABLED` 时，是否能够绕过连接池和连接组的限制，创建新的连接。
   - 验证设置了 `RespectLimits::DISABLED` 的连接任务不会因为相同组内取消了 `RespectLimits::ENABLED` 的请求而被取消。

6. **代理认证 (Proxy Authentication):**
   - 测试当服务器需要代理认证但没有提供认证回调函数时，连接请求会失败并返回 `ERR_PROXY_AUTH_REQUESTED` 错误。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不包含 JavaScript，但它直接影响着 JavaScript 在浏览器中发起网络请求的行为。当 JavaScript 代码（例如使用 `fetch` 或 `XMLHttpRequest`）发起一个 HTTP 或 HTTPS 请求时，Chromium 的网络栈（包括 `ClientSocketPoolBase`）负责管理底层的 TCP 连接。

* **请求优先级：** JavaScript 发起的请求在 Chromium 内部会被赋予一定的优先级。`ClientSocketPoolBase` 的优先级管理机制确保了高优先级的请求（例如用户发起的页面导航）能够优先获得连接资源，从而更快地加载页面。
* **连接复用：** `ClientSocketPoolBase` 的核心功能是连接复用。JavaScript 发起的多个请求，如果目标服务器相同，可以复用已经建立的连接，减少了建立新连接的开销，提升了页面加载速度。
* **资源限制：** 浏览器为了防止资源滥用，会对同一域名下的并发连接数进行限制。`ClientSocketPoolBase` 负责执行这些限制。
* **代理：** 如果用户配置了代理服务器，JavaScript 发起的请求会通过代理。`ClientSocketPoolBase` 需要处理与代理服务器的连接和认证过程。

**举例说明：**

假设一个网页加载了多个资源，包括图片、CSS 和 JavaScript 文件。浏览器会并行地发起多个请求。

* **假设输入：**
    1. JavaScript 代码发起一个高优先级的请求，例如主文档的请求。
    2. 同时，JavaScript 代码发起多个低优先级的请求，例如加载图片。
    3. 连接池的连接数已经达到上限。
* **逻辑推理：** `ClientSocketPoolBase` 会优先处理高优先级的请求，可能会延迟或暂停低优先级请求的连接建立，直到有可用连接或者高优先级请求完成。
* **预期输出：** 主文档的请求会更快地建立连接并返回数据，而图片的加载可能会有所延迟。

**用户或编程常见的使用错误：**

* **用户错误：**
    * **网络环境不稳定：** 用户网络连接不稳定会导致连接建立失败或中断，`ClientSocketPoolBase` 会尝试重连或使用备用连接。
    * **代理配置错误：** 用户配置了错误的代理服务器地址或端口，导致连接无法建立，`ClientSocketPoolBase` 会返回相应的错误信息。
* **编程错误：**
    * **短时间内发起大量请求：** 如果 JavaScript 代码在短时间内发起大量并发请求，可能会超过连接池的限制，导致部分请求被延迟。开发者需要合理控制并发请求的数量。
    * **没有正确处理网络错误：** 开发者需要在 JavaScript 代码中正确处理 `fetch` 或 `XMLHttpRequest` 返回的错误，例如连接超时、连接被拒绝等。这些错误可能源自 `ClientSocketPoolBase` 的底层操作。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器地址栏输入网址或点击链接。**
2. **浏览器解析 URL，确定目标服务器的 IP 地址和端口。**
3. **浏览器检查是否已经存在到该服务器的可用连接（在 `ClientSocketPoolBase` 中）。**
4. **如果不存在可用连接，浏览器会向 `ClientSocketPoolBase` 请求建立新的连接。**
5. **`ClientSocketPoolBase` 根据当前的连接池状态、连接限制、请求优先级等因素，决定是否立即创建连接或将请求加入等待队列。**
6. **`ClientSocketPoolBase` 调用底层的 Socket API (如 `connect`) 尝试建立 TCP 连接。**
7. **如果需要代理，还会涉及与代理服务器的连接和认证过程。**
8. **如果建立连接失败，`ClientSocketPoolBase` 会返回相应的错误码。**
9. **如果建立连接成功，`ClientSocketPoolBase` 会将连接返回给请求方。**

在调试网络问题时，开发者可以使用 Chrome 的开发者工具的 "Network" 标签来查看网络请求的详细信息，包括连接状态、请求耗时等。如果怀疑是连接池的问题，可以查看 `chrome://net-internals/#sockets` 来获取更底层的连接信息。

**总结（针对第 7 部分，共 8 部分）：**

作为测试套件的一部分，这段代码集中测试了 `ClientSocketPoolBase` 在处理连接请求时的核心逻辑，特别是关注了请求优先级、连接任务的分配和重新分配、与更高层连接池的协作、连接限制的控制以及基本的代理认证流程。这部分测试旨在确保 `ClientSocketPoolBase` 能够高效、公平地管理网络连接资源，并能正确处理各种边界情况和错误场景，从而保障浏览器网络请求的稳定性和性能。

Prompt: 
```
这是目录为net/socket/client_socket_pool_base_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共8部分，请归纳一下它的功能

"""
b);

  ClientSocketHandle handle_lowest;
  TestCompletionCallback callback_lowest;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle_lowest.Init(TestGroupId("a"), params_, std::nullopt, LOWEST,
                         SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                         callback_lowest.callback(),
                         ClientSocketPool::ProxyAuthCallback(), pool_.get(),
                         NetLogWithSource()));

  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  ClientSocketHandle handle_highest;
  TestCompletionCallback callback_highest;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle_highest.Init(TestGroupId("a"), params_, std::nullopt, HIGHEST,
                          SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                          callback_highest.callback(),
                          ClientSocketPool::ProxyAuthCallback(), pool_.get(),
                          NetLogWithSource()));

  EXPECT_EQ(2u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  ClientSocketHandle handle_low;
  TestCompletionCallback callback_low;
  EXPECT_EQ(ERR_IO_PENDING,
            handle_low.Init(
                TestGroupId("a"), params_, std::nullopt, LOW, SocketTag(),
                ClientSocketPool::RespectLimits::ENABLED,
                callback_low.callback(), ClientSocketPool::ProxyAuthCallback(),
                pool_.get(), NetLogWithSource()));

  EXPECT_EQ(3u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  ClientSocketHandle handle_lowest2;
  TestCompletionCallback callback_lowest2;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle_lowest2.Init(TestGroupId("a"), params_, std::nullopt, LOWEST,
                          SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                          callback_lowest2.callback(),
                          ClientSocketPool::ProxyAuthCallback(), pool_.get(),
                          NetLogWithSource()));

  EXPECT_EQ(3u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  // The top three requests in the queue should have jobs.
  EXPECT_TRUE(pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"),
                                                              &handle_highest));
  EXPECT_TRUE(pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"),
                                                              &handle_low));
  EXPECT_TRUE(pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"),
                                                              &handle_lowest));
  EXPECT_FALSE(pool_->RequestInGroupWithHandleHasJobForTesting(
      TestGroupId("a"), &handle_lowest2));

  // Add another request with medium priority. It should steal the job from the
  // lowest priority request with a job.
  ClientSocketHandle handle_medium;
  TestCompletionCallback callback_medium;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle_medium.Init(TestGroupId("a"), params_, std::nullopt, MEDIUM,
                         SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                         callback_medium.callback(),
                         ClientSocketPool::ProxyAuthCallback(), pool_.get(),
                         NetLogWithSource()));

  EXPECT_EQ(3u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
  EXPECT_TRUE(pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"),
                                                              &handle_highest));
  EXPECT_TRUE(pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"),
                                                              &handle_medium));
  EXPECT_TRUE(pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"),
                                                              &handle_low));
  EXPECT_FALSE(pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"),
                                                               &handle_lowest));
  EXPECT_FALSE(pool_->RequestInGroupWithHandleHasJobForTesting(
      TestGroupId("a"), &handle_lowest2));
}

TEST_F(ClientSocketPoolBaseTest, ReprioritizeRequestStealsJob) {
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

  ClientSocketHandle handle2;
  TestCompletionCallback callback2;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle2.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback2.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource()));

  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  // The second request doesn't get a job because we are at the limit.
  EXPECT_TRUE(pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"),
                                                              &handle1));
  EXPECT_FALSE(pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"),
                                                               &handle2));

  // Reprioritizing the second request places it above the first, and it steals
  // the job from the first request.
  pool_->SetPriority(TestGroupId("a"), &handle2, HIGHEST);
  EXPECT_TRUE(pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"),
                                                              &handle2));
  EXPECT_FALSE(pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"),
                                                               &handle1));
}

TEST_F(ClientSocketPoolBaseTest, CancelRequestReassignsJob) {
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

  ClientSocketHandle handle2;
  TestCompletionCallback callback2;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle2.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback2.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource()));

  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  // The second request doesn't get a job because we are the limit.
  EXPECT_TRUE(pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"),
                                                              &handle1));
  EXPECT_FALSE(pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"),
                                                               &handle2));

  // The second request should get a job upon cancelling the first request.
  handle1.Reset();
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));

  EXPECT_TRUE(pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"),
                                                              &handle2));
}

TEST_F(ClientSocketPoolBaseTest, JobCompletionReassignsJob) {
  CreatePool(kDefaultMaxSockets, kDefaultMaxSocketsPerGroup);
  connect_job_factory_->set_job_type(TestConnectJob::kMockWaitingJob);

  ClientSocketHandle handle1;
  TestCompletionCallback callback1;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle1.Init(TestGroupId("a"), params_, std::nullopt, HIGHEST,
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

  // The lower-priority job completes first. The higher-priority request should
  // get the socket, and the lower-priority request should get the remaining
  // job.
  client_socket_factory_.SignalJob(1);
  EXPECT_THAT(callback1.WaitForResult(), IsOk());
  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->NumNeverAssignedConnectJobsInGroupForTesting(
                    TestGroupId("a")));
  EXPECT_EQ(0u,
            pool_->NumUnassignedConnectJobsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(1, pool_->NumActiveSocketsInGroupForTesting(TestGroupId("a")));
  EXPECT_EQ(0u, pool_->IdleSocketCountInGroup(TestGroupId("a")));
  EXPECT_TRUE(handle1.socket());
  EXPECT_TRUE(pool_->RequestInGroupWithHandleHasJobForTesting(TestGroupId("a"),
                                                              &handle2));
}

class MockLayeredPool : public HigherLayeredPool {
 public:
  MockLayeredPool(TransportClientSocketPool* pool,
                  const ClientSocketPool::GroupId& group_id)
      : pool_(pool), group_id_(group_id) {
    pool_->AddHigherLayeredPool(this);
  }

  ~MockLayeredPool() override { pool_->RemoveHigherLayeredPool(this); }

  int RequestSocket(TransportClientSocketPool* pool) {
    return handle_.Init(
        group_id_, ClientSocketPool::SocketParams::CreateForHttpForTesting(),
        std::nullopt, DEFAULT_PRIORITY, SocketTag(),
        ClientSocketPool::RespectLimits::ENABLED, callback_.callback(),
        ClientSocketPool::ProxyAuthCallback(), pool, NetLogWithSource());
  }

  int RequestSocketWithoutLimits(TransportClientSocketPool* pool) {
    return handle_.Init(
        group_id_, ClientSocketPool::SocketParams::CreateForHttpForTesting(),
        std::nullopt, MAXIMUM_PRIORITY, SocketTag(),
        ClientSocketPool::RespectLimits::DISABLED, callback_.callback(),
        ClientSocketPool::ProxyAuthCallback(), pool, NetLogWithSource());
  }

  bool ReleaseOneConnection() {
    if (!handle_.is_initialized() || !can_release_connection_) {
      return false;
    }
    handle_.socket()->Disconnect();
    handle_.Reset();
    return true;
  }

  void set_can_release_connection(bool can_release_connection) {
    can_release_connection_ = can_release_connection;
  }

  MOCK_METHOD0(CloseOneIdleConnection, bool());

 private:
  const raw_ptr<TransportClientSocketPool> pool_;
  ClientSocketHandle handle_;
  TestCompletionCallback callback_;
  const ClientSocketPool::GroupId group_id_;
  bool can_release_connection_ = true;
};

// Tests the basic case of closing an idle socket in a higher layered pool when
// a new request is issued and the lower layer pool is stalled.
TEST_F(ClientSocketPoolBaseTest, CloseIdleSocketsHeldByLayeredPoolWhenNeeded) {
  CreatePool(1, 1);
  connect_job_factory_->set_job_type(TestConnectJob::kMockJob);

  MockLayeredPool mock_layered_pool(pool_.get(), TestGroupId("foo"));
  EXPECT_THAT(mock_layered_pool.RequestSocket(pool_.get()), IsOk());
  EXPECT_CALL(mock_layered_pool, CloseOneIdleConnection())
      .WillOnce(
          Invoke(&mock_layered_pool, &MockLayeredPool::ReleaseOneConnection));
  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));
  EXPECT_THAT(callback.WaitForResult(), IsOk());
}

// Tests the case that trying to close an idle socket in a higher layered pool
// fails.
TEST_F(ClientSocketPoolBaseTest,
       CloseIdleSocketsHeldByLayeredPoolWhenNeededFails) {
  CreatePool(1, 1);
  connect_job_factory_->set_job_type(TestConnectJob::kMockJob);

  MockLayeredPool mock_layered_pool(pool_.get(), TestGroupId("foo"));
  mock_layered_pool.set_can_release_connection(false);
  EXPECT_THAT(mock_layered_pool.RequestSocket(pool_.get()), IsOk());
  EXPECT_CALL(mock_layered_pool, CloseOneIdleConnection())
      .WillOnce(
          Invoke(&mock_layered_pool, &MockLayeredPool::ReleaseOneConnection));
  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(callback.have_result());
}

// Same as above, but the idle socket is in the same group as the stalled
// socket, and closes the only other request in its group when closing requests
// in higher layered pools.  This generally shouldn't happen, but it may be
// possible if a higher level pool issues a request and the request is
// subsequently cancelled.  Even if it's not possible, best not to crash.
TEST_F(ClientSocketPoolBaseTest,
       CloseIdleSocketsHeldByLayeredPoolWhenNeededSameGroup) {
  CreatePool(2, 2);
  connect_job_factory_->set_job_type(TestConnectJob::kMockJob);

  // Need a socket in another group for the pool to be stalled (If a group
  // has the maximum number of connections already, it's not stalled).
  ClientSocketHandle handle1;
  TestCompletionCallback callback1;
  EXPECT_EQ(OK, handle1.Init(TestGroupId("group1"), params_, std::nullopt,
                             DEFAULT_PRIORITY, SocketTag(),
                             ClientSocketPool::RespectLimits::ENABLED,
                             callback1.callback(),
                             ClientSocketPool::ProxyAuthCallback(), pool_.get(),
                             NetLogWithSource()));

  MockLayeredPool mock_layered_pool(pool_.get(), TestGroupId("group2"));
  EXPECT_THAT(mock_layered_pool.RequestSocket(pool_.get()), IsOk());
  EXPECT_CALL(mock_layered_pool, CloseOneIdleConnection())
      .WillOnce(
          Invoke(&mock_layered_pool, &MockLayeredPool::ReleaseOneConnection));
  ClientSocketHandle handle;
  TestCompletionCallback callback2;
  EXPECT_EQ(ERR_IO_PENDING,
            handle.Init(
                TestGroupId("group2"), params_, std::nullopt, DEFAULT_PRIORITY,
                SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                callback2.callback(), ClientSocketPool::ProxyAuthCallback(),
                pool_.get(), NetLogWithSource()));
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
}

// Tests the case when an idle socket can be closed when a new request is
// issued, and the new request belongs to a group that was previously stalled.
TEST_F(ClientSocketPoolBaseTest,
       CloseIdleSocketsHeldByLayeredPoolInSameGroupWhenNeeded) {
  CreatePool(2, 2);
  std::list<TestConnectJob::JobType> job_types;
  job_types.push_back(TestConnectJob::kMockJob);
  job_types.push_back(TestConnectJob::kMockJob);
  job_types.push_back(TestConnectJob::kMockJob);
  job_types.push_back(TestConnectJob::kMockJob);
  connect_job_factory_->set_job_types(&job_types);

  ClientSocketHandle handle1;
  TestCompletionCallback callback1;
  EXPECT_EQ(OK, handle1.Init(TestGroupId("group1"), params_, std::nullopt,
                             DEFAULT_PRIORITY, SocketTag(),
                             ClientSocketPool::RespectLimits::ENABLED,
                             callback1.callback(),
                             ClientSocketPool::ProxyAuthCallback(), pool_.get(),
                             NetLogWithSource()));

  MockLayeredPool mock_layered_pool(pool_.get(), TestGroupId("group2"));
  EXPECT_THAT(mock_layered_pool.RequestSocket(pool_.get()), IsOk());
  EXPECT_CALL(mock_layered_pool, CloseOneIdleConnection())
      .WillRepeatedly(
          Invoke(&mock_layered_pool, &MockLayeredPool::ReleaseOneConnection));
  mock_layered_pool.set_can_release_connection(false);

  // The third request is made when the socket pool is in a stalled state.
  ClientSocketHandle handle3;
  TestCompletionCallback callback3;
  EXPECT_EQ(ERR_IO_PENDING,
            handle3.Init(
                TestGroupId("group3"), params_, std::nullopt, DEFAULT_PRIORITY,
                SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                callback3.callback(), ClientSocketPool::ProxyAuthCallback(),
                pool_.get(), NetLogWithSource()));

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(callback3.have_result());

  // The fourth request is made when the pool is no longer stalled.  The third
  // request should be serviced first, since it was issued first and has the
  // same priority.
  mock_layered_pool.set_can_release_connection(true);
  ClientSocketHandle handle4;
  TestCompletionCallback callback4;
  EXPECT_EQ(ERR_IO_PENDING,
            handle4.Init(
                TestGroupId("group3"), params_, std::nullopt, DEFAULT_PRIORITY,
                SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                callback4.callback(), ClientSocketPool::ProxyAuthCallback(),
                pool_.get(), NetLogWithSource()));
  EXPECT_THAT(callback3.WaitForResult(), IsOk());
  EXPECT_FALSE(callback4.have_result());

  // Closing a handle should free up another socket slot.
  handle1.Reset();
  EXPECT_THAT(callback4.WaitForResult(), IsOk());
}

// Tests the case when an idle socket can be closed when a new request is
// issued, and the new request belongs to a group that was previously stalled.
//
// The two differences from the above test are that the stalled requests are not
// in the same group as the layered pool's request, and the the fourth request
// has a higher priority than the third one, so gets a socket first.
TEST_F(ClientSocketPoolBaseTest,
       CloseIdleSocketsHeldByLayeredPoolInSameGroupWhenNeeded2) {
  CreatePool(2, 2);
  std::list<TestConnectJob::JobType> job_types;
  job_types.push_back(TestConnectJob::kMockJob);
  job_types.push_back(TestConnectJob::kMockJob);
  job_types.push_back(TestConnectJob::kMockJob);
  job_types.push_back(TestConnectJob::kMockJob);
  connect_job_factory_->set_job_types(&job_types);

  ClientSocketHandle handle1;
  TestCompletionCallback callback1;
  EXPECT_EQ(OK, handle1.Init(TestGroupId("group1"), params_, std::nullopt,
                             DEFAULT_PRIORITY, SocketTag(),
                             ClientSocketPool::RespectLimits::ENABLED,
                             callback1.callback(),
                             ClientSocketPool::ProxyAuthCallback(), pool_.get(),
                             NetLogWithSource()));

  MockLayeredPool mock_layered_pool(pool_.get(), TestGroupId("group2"));
  EXPECT_THAT(mock_layered_pool.RequestSocket(pool_.get()), IsOk());
  EXPECT_CALL(mock_layered_pool, CloseOneIdleConnection())
      .WillRepeatedly(
          Invoke(&mock_layered_pool, &MockLayeredPool::ReleaseOneConnection));
  mock_layered_pool.set_can_release_connection(false);

  // The third request is made when the socket pool is in a stalled state.
  ClientSocketHandle handle3;
  TestCompletionCallback callback3;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle3.Init(TestGroupId("group3"), params_, std::nullopt, MEDIUM,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback3.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource()));

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(callback3.have_result());

  // The fourth request is made when the pool is no longer stalled.  This
  // request has a higher priority than the third request, so is serviced first.
  mock_layered_pool.set_can_release_connection(true);
  ClientSocketHandle handle4;
  TestCompletionCallback callback4;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle4.Init(TestGroupId("group3"), params_, std::nullopt, HIGHEST,
                   SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                   callback4.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_.get(), NetLogWithSource()));
  EXPECT_THAT(callback4.WaitForResult(), IsOk());
  EXPECT_FALSE(callback3.have_result());

  // Closing a handle should free up another socket slot.
  handle1.Reset();
  EXPECT_THAT(callback3.WaitForResult(), IsOk());
}

TEST_F(ClientSocketPoolBaseTest,
       CloseMultipleIdleSocketsHeldByLayeredPoolWhenNeeded) {
  CreatePool(1, 1);
  connect_job_factory_->set_job_type(TestConnectJob::kMockJob);

  MockLayeredPool mock_layered_pool1(pool_.get(), TestGroupId("foo"));
  EXPECT_THAT(mock_layered_pool1.RequestSocket(pool_.get()), IsOk());
  EXPECT_CALL(mock_layered_pool1, CloseOneIdleConnection())
      .WillRepeatedly(
          Invoke(&mock_layered_pool1, &MockLayeredPool::ReleaseOneConnection));
  MockLayeredPool mock_layered_pool2(pool_.get(), TestGroupId("bar"));
  EXPECT_THAT(mock_layered_pool2.RequestSocketWithoutLimits(pool_.get()),
              IsOk());
  EXPECT_CALL(mock_layered_pool2, CloseOneIdleConnection())
      .WillRepeatedly(
          Invoke(&mock_layered_pool2, &MockLayeredPool::ReleaseOneConnection));
  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));
  EXPECT_THAT(callback.WaitForResult(), IsOk());
}

// Test that when a socket pool and group are at their limits, a request
// with RespectLimits::DISABLED triggers creation of a new socket, and gets the
// socket instead of a request with the same priority that was issued earlier,
// but has RespectLimits::ENABLED.
TEST_F(ClientSocketPoolBaseTest, IgnoreLimits) {
  CreatePool(1, 1);

  // Issue a request to reach the socket pool limit.
  EXPECT_EQ(OK, StartRequestWithIgnoreLimits(
                    TestGroupId("a"), MAXIMUM_PRIORITY,
                    ClientSocketPool::RespectLimits::ENABLED));
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);

  EXPECT_EQ(ERR_IO_PENDING, StartRequestWithIgnoreLimits(
                                TestGroupId("a"), MAXIMUM_PRIORITY,
                                ClientSocketPool::RespectLimits::ENABLED));
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  // Issue a request that ignores the limits, so a new ConnectJob is
  // created.
  EXPECT_EQ(ERR_IO_PENDING, StartRequestWithIgnoreLimits(
                                TestGroupId("a"), MAXIMUM_PRIORITY,
                                ClientSocketPool::RespectLimits::DISABLED));
  ASSERT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  EXPECT_THAT(request(2)->WaitForResult(), IsOk());
  EXPECT_FALSE(request(1)->have_result());
}

// Test that when a socket pool and group are at their limits, a ConnectJob
// issued for a request with RespectLimits::DISABLED is not cancelled when a
// request with RespectLimits::ENABLED issued to the same group is cancelled.
TEST_F(ClientSocketPoolBaseTest, IgnoreLimitsCancelOtherJob) {
  CreatePool(1, 1);

  // Issue a request to reach the socket pool limit.
  EXPECT_EQ(OK, StartRequestWithIgnoreLimits(
                    TestGroupId("a"), MAXIMUM_PRIORITY,
                    ClientSocketPool::RespectLimits::ENABLED));
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  connect_job_factory_->set_job_type(TestConnectJob::kMockPendingJob);

  EXPECT_EQ(ERR_IO_PENDING, StartRequestWithIgnoreLimits(
                                TestGroupId("a"), MAXIMUM_PRIORITY,
                                ClientSocketPool::RespectLimits::ENABLED));
  EXPECT_EQ(0u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  // Issue a request with RespectLimits::DISABLED, so a new ConnectJob is
  // created.
  EXPECT_EQ(ERR_IO_PENDING, StartRequestWithIgnoreLimits(
                                TestGroupId("a"), MAXIMUM_PRIORITY,
                                ClientSocketPool::RespectLimits::DISABLED));
  ASSERT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  // Cancel the pending request with RespectLimits::ENABLED. The ConnectJob
  // should not be cancelled.
  request(1)->handle()->Reset();
  ASSERT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  EXPECT_THAT(request(2)->WaitForResult(), IsOk());
  EXPECT_FALSE(request(1)->have_result());
}

TEST_F(ClientSocketPoolBaseTest, ProxyAuthNoAuthCallback) {
  CreatePool(1, 1);

  connect_job_factory_->set_job_type(TestConnectJob::kMockAuthChallengeOnceJob);

  ClientSocketHandle handle;
  TestCompletionCallback callback;
  EXPECT_EQ(
      ERR_IO_PENDING,
      handle.Init(TestGroupId("a"), params_, std::nullopt, DEFAULT_PRIORITY,
                  SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
                  callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                  pool_.get(), NetLogWithSource()));

  EXPECT_EQ(1u, pool_->NumConnectJobsInGroupForTesting(TestGroupId("a")));

  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_PROXY_AUTH_REQUESTED));
  EXPECT_FALSE(handle.is_initialized());
  EXPECT_FALSE(handle.socket());

  // The group should now be empty, and thus be deleted.
  EXPECT_FALSE(pool_->HasGroupForTesting(TestGroupId("a")));
}

class TestAuthHelper {
 public:
  TestAuthHelper() = default;

  TestAuthHelper(const TestAuthHelper&) = delete;
  TestAuthHelper& operator=(const TestAuthHelper&) = delete;

  ~TestAuthHelper() = default;

  void InitHandle(
      scoped_refptr<ClientSocketPool::SocketParams> params,
      TransportClientSocketPool* pool,
      RequestPriority priority = DEFAULT_PRIORITY,
      ClientSocketPool::RespectLimits respect_limits =
          ClientSocketPool::RespectLimits::ENABLED,
      const ClientSocketPool::GroupId& group_id_in = TestGroupId("a")) {
    EXPECT_EQ(ERR_IO_PENDING,
              handle_.Init(group_id_in, params, std::nullopt, priority,
                           SocketTag(), respect_limits, callback_.callback(),
                           base::BindRepeating(&TestAuthHelper::AuthCallback,
                                               base::Unretained(this)),
                           pool, NetLogWithSource()));
  }

  void WaitForAuth() {
    run_loop_ = std::make_unique<base::RunLoop>();
    run_loop_->Run();
    run_loop_.reset();
  }

  void WaitForAuthAndRestartSync() {
    restart_sync_ = true;
    WaitForAuth();
    restart_sync_ = false;
  }

  void WaitForAuthAndResetHandleSync() {
    reset_handle_sync_ = true;
    WaitForAuth();
    reset_handle_sync_ = false;
  }

  void RestartWithAuth() {
    DCHECK(restart_with_auth_callback_);
    std::move(restart_with_auth_callback_).Run();
  }

  int WaitForResult() {
    int result = callback_.WaitForResult();
    // There shouldn't be any callback waiting to be invoked once the request is
    // complete.
    EXPECT_FALSE(restart_with_auth_callback_);
    // The socket should only be initialized on success.
    EXPECT_EQ(result == OK, handle_.is_initialized());
    EXPECT_EQ(result == OK, handle_.socket() != nullptr);
    return result;
  }

  ClientSocketHandle* handle() { return &handle_; }
  int auth_count() const { return auth_count_; }
  int have_result() const { return callback_.have_result(); }

 private:
  void AuthCallback(const HttpResponseInfo& response,
                    HttpAuthController* auth_controller,
                    base::OnceClosure restart_with_auth_callback) {
    EXPECT_FALSE(restart_with_auth_callback_);
    EXPECT_TRUE(restart_with_auth_callback);

    // Once there's a result, this method shouldn't be invoked again.
    EXPECT_FALSE(callback_.have_result());

    ++auth_count_;
    run_loop_->Quit();
    if (restart_sync_) {
      std::move(restart_with_auth_callback).Run();
      return;
    }

    re
"""


```