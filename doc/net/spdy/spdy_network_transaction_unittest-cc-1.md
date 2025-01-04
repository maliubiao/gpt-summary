Response:
My thought process to analyze the provided C++ code snippet and generate the response goes through several stages:

1. **Understanding the Context:** I first recognize that this is part of a unit test file (`spdy_network_transaction_unittest.cc`) within the Chromium project's network stack, specifically related to the SPDY (now HTTP/2) protocol. The "part 2 of 12" indicates a larger test suite.

2. **Identifying the Core Functionality:** I scan the code for keywords and patterns: `TEST_P`, `SpdyNetworkTransactionTest`, `HttpNetworkTransaction`, `Start`, `ReadTransaction`, `SpdySerializedFrame`, `MockWrite`, `MockRead`, `SequencedSocketData`, `SettingsMap`, `TestCompletionCallback`. These tell me the code is testing the `HttpNetworkTransaction` class's interaction with the SPDY protocol. The tests involve setting up mock network interactions (writes and reads) and verifying the behavior of network transactions.

3. **Analyzing Individual Test Cases:**  I examine each `TEST_P` function separately to understand its specific goal:
    * **`SetPriority`:** This test focuses on dynamically changing the priority of a network request and verifying that the SPDY write queue reorders the frames accordingly.
    * **`GetAtEachPriority`:** This test iterates through all possible `RequestPriority` values and checks if the correct corresponding SPDY priority is set in the outgoing request frame.
    * **`ThreeGets`:**  This test initiates three concurrent GET requests to verify basic multiplexing functionality.
    * **`TwoGetsLateBinding`:** This test explores the scenario where two GET requests are started concurrently, and a connection is established later, ensuring both requests are properly bound to the connection.
    * **`TwoGetsLateBindingFromPreconnect`:** Similar to the previous test, but one of the connections is established through pre-connection.
    * **`ThreeGetsWithMaxConcurrent`:** This test introduces a `SETTINGS` frame limiting concurrent streams to 1, verifying that subsequent requests are queued and executed sequentially.
    * **`FourGetsWithMaxConcurrentPriority`:**  Builds upon the previous test by adding request priorities and confirming that higher priority requests are processed before lower priority ones, even with the concurrency limit.
    * **`ThreeGetsWithMaxConcurrentDelete`:** This test checks the scenario where a network transaction is started but then deleted while waiting for a stream due to the concurrency limit.
    * **`ThreeGetsWithMaxConcurrentSocketClose`:** This test simulates a socket closure while transactions are pending due to the concurrency limit.

4. **Summarizing Overall Functionality:** Based on the individual test cases, I synthesize a summary that highlights the key features being tested: priority handling, multiplexing, connection management (including late binding and pre-connect), and handling concurrency limits (including error scenarios like deletion and socket closure).

5. **Identifying Relationships with JavaScript:** I consider how these network-level functionalities relate to JavaScript in a web browser. The key connection is that these underlying mechanisms enable the network requests initiated by JavaScript (e.g., `fetch`, `XMLHttpRequest`) to be efficiently handled. I focus on concepts like prioritization (resource loading order), concurrency limits (browser's connection limits), and multiplexing (parallel downloads).

6. **Providing Examples for JavaScript Interaction:** To illustrate the JavaScript relationship, I create concrete examples:
    * Using `fetch` with different priority hints (though browser support is limited).
    * Observing browser behavior when many requests are made concurrently (demonstrating concurrency limits).
    * How multiplexing benefits loading multiple resources.

7. **Creating Hypothetical Input/Output for Logic:** For the `SetPriority` test, which involves a clear logical step, I construct a simplified input (initial priorities) and predict the output (reordered write queue).

8. **Identifying Potential User/Programming Errors:**  I think about common mistakes developers might make when interacting with network requests:
    * Not understanding or using priority hints effectively.
    * Making too many concurrent requests without considering browser limits.
    * Issues with error handling when connections are closed prematurely.

9. **Tracing User Operations for Debugging:**  I outline a typical user action (visiting a webpage) and how it can trigger the code under test, leading to potential debugging scenarios related to network performance or errors.

10. **Structuring the Response:** I organize the information into clear sections based on the prompt's requirements: functionality, JavaScript relationship, logical inference, common errors, user operation tracing, and finally, a concise summary of the provided code. I use clear language and provide specific examples where needed.

11. **Refining and Reviewing:**  I reread my response to ensure accuracy, clarity, and completeness, checking that it addresses all aspects of the prompt and avoids jargon where possible. I make sure the examples are relevant and easy to understand.

This systematic approach allows me to dissect the code, understand its purpose within the broader context of the Chromium network stack, and connect it to relevant concepts and practical scenarios. It mimics how a developer might approach understanding a new piece of code.
好的，让我们来分析一下 `net/spdy/spdy_network_transaction_unittest.cc` 文件中提供的第二部分代码的功能。

**本部分代码的主要功能归纳:**

这部分代码主要集中在测试 `HttpNetworkTransaction` 类在使用 SPDY 协议时，**处理多个并发请求**以及**请求优先级**的功能。它通过模拟网络交互，验证在不同的场景下，请求是否按照预期的顺序和优先级被处理。

**更细致的功能点:**

* **动态调整请求优先级:** 测试 `SetPriority` 函数，验证在请求发送后修改其优先级，是否会影响请求在 SPDY 写入队列中的顺序。
* **验证不同请求优先级的设置:** 测试 `GetAtEachPriority` 函数，遍历所有可能的请求优先级，并验证它们是否正确映射到 SPDY 协议的优先级。
* **测试基础的多路复用功能:** 测试 `ThreeGets` 函数，同时发起三个 GET 请求，验证 SPDY 协议是否能够正确地处理和响应这些并发请求。
* **测试连接的延迟绑定:** 测试 `TwoGetsLateBinding` 和 `TwoGetsLateBindingFromPreconnect` 函数，模拟在发起请求时连接尚未建立，验证请求能否在连接建立后正确地绑定并完成。
* **测试最大并发连接数限制:** 测试 `ThreeGetsWithMaxConcurrent` 和 `FourGetsWithMaxConcurrentPriority` 函数，设置 SPDY 的 `SETTINGS_MAX_CONCURRENT_STREAMS` 参数，模拟服务器限制并发请求数的情况，验证请求是否会按照优先级排队和执行。
* **测试在并发限制下删除事务:** 测试 `ThreeGetsWithMaxConcurrentDelete` 函数，模拟在有并发限制的情况下，删除一个尚未完成的事务，验证是否能正确清理资源。
* **测试在并发限制下关闭套接字:** 测试 `ThreeGetsWithMaxConcurrentSocketClose` 函数，模拟在有并发限制的情况下，关闭底层的套接字连接，验证是否能正确处理错误并清理未完成的事务。

**与 JavaScript 的功能关系及举例说明:**

这部分测试的功能直接关系到 Web 浏览器中 JavaScript 发起的网络请求的性能和行为。

* **请求优先级:**  当 JavaScript 发起多个请求时（例如，加载网页上的图片、CSS 和 JavaScript 文件），浏览器内部会根据资源的类型和重要性设置不同的优先级。SPDY/HTTP2 允许浏览器将这些优先级信息传递给服务器，以便服务器可以优先处理更重要的资源，从而提高页面加载速度。
    * **举例:** 使用 `fetch` API 时，虽然浏览器本身会自动进行优先级判断，但未来可能会有更细致的 API 允许开发者指定请求的优先级，从而更精细地控制资源加载顺序。
* **多路复用:**  JavaScript 发起多个请求时，SPDY/HTTP2 允许多个请求共享同一个 TCP 连接，避免了为每个请求都建立新连接的开销，显著提高了并发请求的效率。
    * **举例:** 一个网页同时加载多张图片，在 HTTP/1.1 中可能需要建立多个 TCP 连接，而在 SPDY/HTTP2 中，这些图片请求可以在同一个连接上并行传输。
* **并发连接限制:** 浏览器为了防止过度消耗资源，通常会对单个域名下的并发连接数进行限制。SPDY/HTTP2 的多路复用在一定程度上缓解了这个问题，但浏览器内部仍然需要管理和调度这些并发请求。
    * **举例:**  如果一个网页发起了大量的异步请求，浏览器可能会根据自身的并发连接限制，将一些请求放入队列中等待执行。

**逻辑推理、假设输入与输出:**

以 `SpdyNetworkTransactionTest::SetPriority` 测试为例：

* **假设输入:**
    * 启动三个 HTTP 请求 (`trans1`, `trans2`, `trans3`)，分别对应 stream ID 1, 3, 5。
    * 初始优先级分别为 `DEFAULT_PRIORITY`, `HIGHEST`, `MEDIUM`。
    * 第一个请求的 HEADERS 帧写入操作处于 pending 状态。
    * 将第二个请求的优先级修改为 `LOWEST`。
* **逻辑推理:**
    * 由于第一个请求的写入操作未完成，第二个和第三个请求的 HEADERS 帧会被放入 `SpdyWriteQueue`。
    * 初始时，`trans2` (HIGHEST) 应该在 `trans3` (MEDIUM) 前面。
    * 当 `trans2` 的优先级被设置为 `LOWEST` 后，`SpdyWriteQueue` 会重新排序，`trans3` 应该在 `trans2` 前面。
* **预期输出:**
    * 网络交互的 MockWrite 顺序会反映出优先级的变化，`trans3` 的 HEADERS 帧会在 `trans2` 的 HEADERS 帧之前被写入。
    * 最终的响应数据会按照重新排序后的请求顺序返回 (`stream 1`, `stream 3`, `stream 5`)。

**用户或编程常见的使用错误及举例说明:**

* **不理解或忽略请求优先级:** 开发者可能没有意识到可以通过设置请求优先级来优化资源加载顺序，导致关键资源加载延迟。
    * **举例:** 网页的首次渲染依赖于 CSS 文件，但如果 CSS 文件的请求优先级低于一些不重要的图片，可能会导致页面渲染阻塞。
* **过度依赖 SPDY/HTTP2 的多路复用而忽略并发限制:** 即使使用了 SPDY/HTTP2，浏览器仍然存在并发连接限制。如果 JavaScript 代码发起了过多的并发请求，仍然可能导致请求排队，影响性能。
    * **举例:** 在一个循环中，不加控制地发起大量的 `fetch` 请求，可能会超出浏览器的并发连接限制，导致部分请求被延迟执行。
* **在不合适的时机修改请求优先级:** 虽然可以动态修改请求优先级，但如果修改发生在请求已经开始处理之后，可能不会产生预期的效果。
    * **举例:** 在 `fetch` 请求的 `then` 回调中尝试修改其优先级，此时请求可能已经发送甚至开始接收响应了。

**用户操作如何一步步到达这里作为调试线索:**

当用户在 Chrome 浏览器中进行以下操作时，可能会触发与 SPDY 网络事务相关的代码，从而在调试时涉及到这些测试用例：

1. **用户在地址栏输入网址并回车，或点击一个链接:**  这会触发浏览器发起 HTTP 请求。如果服务器支持 SPDY/HTTP2 并且浏览器启用了该协议，那么这个请求很可能会使用 `HttpNetworkTransaction` 和相关的 SPDY 实现。
2. **用户访问一个包含多个资源的网页:** 例如，包含多张图片、CSS 文件、JavaScript 文件的网页。浏览器会并行地发起多个请求加载这些资源，这会涉及到多路复用和请求优先级的功能。
3. **用户在网页加载过程中进行某些操作:** 例如，点击一个按钮触发新的 AJAX 请求，或者滚动页面导致懒加载图片。这些操作会产生新的网络请求，可能会与正在进行的请求并发执行。
4. **开发者工具的网络面板显示异常:** 如果开发者在 Chrome 的开发者工具中观察到网络请求的顺序不符合预期，或者某些请求被延迟，这可能是 SPDY 网络事务处理出现问题。
5. **网络连接不稳定或服务器响应缓慢:** 在这些情况下，SPDY 协议的特性（如多路复用和优先级）对于优化用户体验尤为重要，但也更容易暴露潜在的问题。

**调试线索:** 如果在调试过程中发现网络请求行为异常，可以关注以下几点：

* **是否使用了 SPDY/HTTP2 协议:** 可以在开发者工具的网络面板中查看 "Protocol" 列。
* **请求的优先级是否正确设置:**  可以通过实验性的 DevTools 功能查看请求优先级。
* **是否存在大量的并发请求:** 观察网络面板中同时进行的请求数量。
* **服务器是否设置了并发连接限制:**  虽然通常在客户端测试，但服务器的配置也会影响行为。
* **网络连接状态:**  不稳定的网络连接可能导致 SPDY 连接的重置或迁移。

总而言之，这部分代码通过一系列细致的单元测试，确保了 Chromium 网络栈在处理 SPDY 协议下的并发请求和请求优先级时的正确性和健壮性，这对于提供快速和高效的网页浏览体验至关重要。

Prompt: 
```
这是目录为net/spdy/spdy_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共12部分，请归纳一下它的功能

"""
rt(&request3, callback3.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Create HEADERS frames for second and third request and enqueue them in
  // SpdyWriteQueue with their original priorities.  Writing of the first
  // HEADERS frame to the socked still has not completed.
  base::RunLoop().RunUntilIdle();

  // Second request is of HIGHEST, third of MEDIUM priority.  Changing second
  // request to LOWEST changes their relative order.  This should result in
  // already enqueued frames being reordered within SpdyWriteQueue.
  trans2.SetPriority(LOWEST);

  // Complete async write of the first HEADERS frame.
  data.Resume();

  helper.FinishDefaultTest();
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("stream 1", out.response_data);

  rv = callback2.WaitForResult();
  ASSERT_THAT(rv, IsOk());
  const HttpResponseInfo* response2 = trans2.GetResponseInfo();
  ASSERT_TRUE(response2);
  ASSERT_TRUE(response2->headers);
  EXPECT_EQ(HttpConnectionInfo::kHTTP2, response2->connection_info);
  EXPECT_EQ("HTTP/1.1 200", response2->headers->GetStatusLine());
  std::string response_data;
  ReadTransaction(&trans2, &response_data);
  EXPECT_EQ("stream 5", response_data);

  rv = callback3.WaitForResult();
  ASSERT_THAT(rv, IsOk());
  const HttpResponseInfo* response3 = trans3.GetResponseInfo();
  ASSERT_TRUE(response3);
  ASSERT_TRUE(response3->headers);
  EXPECT_EQ(HttpConnectionInfo::kHTTP2, response3->connection_info);
  EXPECT_EQ("HTTP/1.1 200", response3->headers->GetStatusLine());
  ReadTransaction(&trans3, &response_data);
  EXPECT_EQ("stream 3", response_data);

  helper.VerifyDataConsumed();
}

TEST_P(SpdyNetworkTransactionTest, GetAtEachPriority) {
  for (RequestPriority p = MINIMUM_PRIORITY; p <= MAXIMUM_PRIORITY;
       p = RequestPriority(p + 1)) {
    SpdyTestUtil spdy_test_util(/*use_priority_header=*/true);

    // Construct the request.
    spdy::SpdySerializedFrame req(
        spdy_test_util.ConstructSpdyGet(nullptr, 0, 1, p));
    MockWrite writes[] = {CreateMockWrite(req, 0)};

    spdy::SpdyPriority spdy_prio = 0;
    EXPECT_TRUE(GetSpdyPriority(req, &spdy_prio));
    // this repeats the RequestPriority-->spdy::SpdyPriority mapping from
    // spdy::SpdyFramer::ConvertRequestPriorityToSpdyPriority to make
    // sure it's being done right.
    switch (p) {
      case HIGHEST:
        EXPECT_EQ(0, spdy_prio);
        break;
      case MEDIUM:
        EXPECT_EQ(1, spdy_prio);
        break;
      case LOW:
        EXPECT_EQ(2, spdy_prio);
        break;
      case LOWEST:
        EXPECT_EQ(3, spdy_prio);
        break;
      case IDLE:
        EXPECT_EQ(4, spdy_prio);
        break;
      case THROTTLED:
        EXPECT_EQ(5, spdy_prio);
        break;
      default:
        FAIL();
    }

    spdy::SpdySerializedFrame resp(
        spdy_test_util.ConstructSpdyGetReply(nullptr, 0, 1));
    spdy::SpdySerializedFrame body(
        spdy_test_util.ConstructSpdyDataFrame(1, true));
    MockRead reads[] = {
        CreateMockRead(resp, 1), CreateMockRead(body, 2),
        MockRead(ASYNC, 0, 3)  // EOF
    };

    SequencedSocketData data(reads, writes);

    NormalSpdyTransactionHelper helper(request_, p, log_, nullptr);
    helper.RunToCompletion(&data);
    TransactionHelperResult out = helper.output();
    EXPECT_THAT(out.rv, IsOk());
    EXPECT_EQ("HTTP/1.1 200", out.status_line);
    EXPECT_EQ("hello!", out.response_data);
  }
}

// Start three gets simultaniously; making sure that multiplexed
// streams work properly.

// This can't use the TransactionHelper method, since it only
// handles a single transaction, and finishes them as soon
// as it launches them.

// TODO(gavinp): create a working generalized TransactionHelper that
// can allow multiple streams in flight.

TEST_P(SpdyNetworkTransactionTest, ThreeGets) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, false));
  spdy::SpdySerializedFrame fbody(spdy_util_.ConstructSpdyDataFrame(1, true));

  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, LOWEST));
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, false));
  spdy::SpdySerializedFrame fbody2(spdy_util_.ConstructSpdyDataFrame(3, true));

  spdy::SpdySerializedFrame req3(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 5, LOWEST));
  spdy::SpdySerializedFrame resp3(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 5));
  spdy::SpdySerializedFrame body3(spdy_util_.ConstructSpdyDataFrame(5, false));
  spdy::SpdySerializedFrame fbody3(spdy_util_.ConstructSpdyDataFrame(5, true));

  MockWrite writes[] = {
      CreateMockWrite(req, 0),
      CreateMockWrite(req2, 3),
      CreateMockWrite(req3, 6),
  };
  MockRead reads[] = {
      CreateMockRead(resp, 1),    CreateMockRead(body, 2),
      CreateMockRead(resp2, 4),   CreateMockRead(body2, 5),
      CreateMockRead(resp3, 7),   CreateMockRead(body3, 8),

      CreateMockRead(fbody, 9),   CreateMockRead(fbody2, 10),
      CreateMockRead(fbody3, 11),

      MockRead(ASYNC, 0, 12),  // EOF
  };
  SequencedSocketData data(reads, writes);
  SequencedSocketData data_placeholder1;
  SequencedSocketData data_placeholder2;

  TransactionHelperResult out;
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  // We require placeholder data because three get requests are sent out at
  // the same time which results in three sockets being connected. The first
  // on will negotiate SPDY and will be used for all requests.
  helper.AddData(&data_placeholder1);
  helper.AddData(&data_placeholder2);
  TestCompletionCallback callback1;
  TestCompletionCallback callback2;
  TestCompletionCallback callback3;

  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, helper.session());
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, helper.session());
  HttpNetworkTransaction trans3(DEFAULT_PRIORITY, helper.session());

  out.rv = trans1.Start(&request_, callback1.callback(), log_);
  ASSERT_THAT(out.rv, IsError(ERR_IO_PENDING));
  out.rv = trans2.Start(&request_, callback2.callback(), log_);
  ASSERT_THAT(out.rv, IsError(ERR_IO_PENDING));
  out.rv = trans3.Start(&request_, callback3.callback(), log_);
  ASSERT_THAT(out.rv, IsError(ERR_IO_PENDING));

  out.rv = callback1.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());
  out.rv = callback3.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());

  const HttpResponseInfo* response1 = trans1.GetResponseInfo();
  EXPECT_TRUE(response1->headers);
  EXPECT_TRUE(response1->was_fetched_via_spdy);
  out.status_line = response1->headers->GetStatusLine();
  out.response_info = *response1;

  trans2.GetResponseInfo();

  out.rv = ReadTransaction(&trans1, &out.response_data);
  helper.VerifyDataConsumed();
  EXPECT_THAT(out.rv, IsOk());

  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!hello!", out.response_data);
}

TEST_P(SpdyNetworkTransactionTest, TwoGetsLateBinding) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, false));
  spdy::SpdySerializedFrame fbody(spdy_util_.ConstructSpdyDataFrame(1, true));

  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, LOWEST));
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, false));
  spdy::SpdySerializedFrame fbody2(spdy_util_.ConstructSpdyDataFrame(3, true));

  MockWrite writes[] = {
      CreateMockWrite(req, 0),
      CreateMockWrite(req2, 3),
  };
  MockRead reads[] = {
      CreateMockRead(resp, 1),  CreateMockRead(body, 2),
      CreateMockRead(resp2, 4), CreateMockRead(body2, 5),
      CreateMockRead(fbody, 6), CreateMockRead(fbody2, 7),
      MockRead(ASYNC, 0, 8),  // EOF
  };
  SequencedSocketData data(reads, writes);

  MockConnect never_finishing_connect(SYNCHRONOUS, ERR_IO_PENDING);
  SequencedSocketData data_placeholder;
  data_placeholder.set_connect_data(never_finishing_connect);

  TransactionHelperResult out;
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  // We require placeholder data because two requests are sent out at
  // the same time which results in two sockets being connected. The first
  // on will negotiate SPDY and will be used for all requests.
  helper.AddData(&data_placeholder);
  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, helper.session());
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, helper.session());

  TestCompletionCallback callback1;
  TestCompletionCallback callback2;

  out.rv = trans1.Start(&request_, callback1.callback(), log_);
  ASSERT_THAT(out.rv, IsError(ERR_IO_PENDING));
  out.rv = trans2.Start(&request_, callback2.callback(), log_);
  ASSERT_THAT(out.rv, IsError(ERR_IO_PENDING));

  out.rv = callback1.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());
  out.rv = callback2.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());

  const HttpResponseInfo* response1 = trans1.GetResponseInfo();
  EXPECT_TRUE(response1->headers);
  EXPECT_TRUE(response1->was_fetched_via_spdy);
  out.status_line = response1->headers->GetStatusLine();
  out.response_info = *response1;
  out.rv = ReadTransaction(&trans1, &out.response_data);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!hello!", out.response_data);

  const HttpResponseInfo* response2 = trans2.GetResponseInfo();
  EXPECT_TRUE(response2->headers);
  EXPECT_TRUE(response2->was_fetched_via_spdy);
  out.status_line = response2->headers->GetStatusLine();
  out.response_info = *response2;
  out.rv = ReadTransaction(&trans2, &out.response_data);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!hello!", out.response_data);

  helper.VerifyDataConsumed();
}

TEST_P(SpdyNetworkTransactionTest, TwoGetsLateBindingFromPreconnect) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, false));
  spdy::SpdySerializedFrame fbody(spdy_util_.ConstructSpdyDataFrame(1, true));

  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, LOWEST));
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, false));
  spdy::SpdySerializedFrame fbody2(spdy_util_.ConstructSpdyDataFrame(3, true));

  MockWrite writes[] = {
      CreateMockWrite(req, 0),
      CreateMockWrite(req2, 3),
  };
  MockRead reads[] = {
      CreateMockRead(resp, 1),  CreateMockRead(body, 2),
      CreateMockRead(resp2, 4), CreateMockRead(body2, 5),
      CreateMockRead(fbody, 6), CreateMockRead(fbody2, 7),
      MockRead(ASYNC, 0, 8),  // EOF
  };
  SequencedSocketData preconnect_data(reads, writes);

  MockConnect never_finishing_connect(ASYNC, ERR_IO_PENDING);

  SequencedSocketData data_placeholder;
  data_placeholder.set_connect_data(never_finishing_connect);

  TransactionHelperResult out;
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&preconnect_data);
  // We require placeholder data because 3 connections are attempted (first is
  // the preconnect, 2nd and 3rd are the never finished connections.
  helper.AddData(&data_placeholder);
  helper.AddData(&data_placeholder);

  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, helper.session());
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, helper.session());

  TestCompletionCallback callback1;
  TestCompletionCallback callback2;

  // Preconnect the first.
  HttpStreamFactory* http_stream_factory =
      helper.session()->http_stream_factory();

  http_stream_factory->PreconnectStreams(1, request_);

  out.rv = trans1.Start(&request_, callback1.callback(), log_);
  ASSERT_THAT(out.rv, IsError(ERR_IO_PENDING));
  out.rv = trans2.Start(&request_, callback2.callback(), log_);
  ASSERT_THAT(out.rv, IsError(ERR_IO_PENDING));

  out.rv = callback1.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());
  out.rv = callback2.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());

  const HttpResponseInfo* response1 = trans1.GetResponseInfo();
  EXPECT_TRUE(response1->headers);
  EXPECT_TRUE(response1->was_fetched_via_spdy);
  out.status_line = response1->headers->GetStatusLine();
  out.response_info = *response1;
  out.rv = ReadTransaction(&trans1, &out.response_data);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!hello!", out.response_data);

  const HttpResponseInfo* response2 = trans2.GetResponseInfo();
  EXPECT_TRUE(response2->headers);
  EXPECT_TRUE(response2->was_fetched_via_spdy);
  out.status_line = response2->headers->GetStatusLine();
  out.response_info = *response2;
  out.rv = ReadTransaction(&trans2, &out.response_data);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!hello!", out.response_data);

  helper.VerifyDataConsumed();
}

// Similar to ThreeGets above, however this test adds a SETTINGS
// frame.  The SETTINGS frame is read during the IO loop waiting on
// the first transaction completion, and sets a maximum concurrent
// stream limit of 1.  This means that our IO loop exists after the
// second transaction completes, so we can assert on read_index().
TEST_P(SpdyNetworkTransactionTest, ThreeGetsWithMaxConcurrent) {
  // Construct the request.
  // Each request fully completes before the next starts.
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, false));
  spdy::SpdySerializedFrame fbody(spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy_util_.UpdateWithStreamDestruction(1);

  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, LOWEST));
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, false));
  spdy::SpdySerializedFrame fbody2(spdy_util_.ConstructSpdyDataFrame(3, true));
  spdy_util_.UpdateWithStreamDestruction(3);

  spdy::SpdySerializedFrame req3(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 5, LOWEST));
  spdy::SpdySerializedFrame resp3(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 5));
  spdy::SpdySerializedFrame body3(spdy_util_.ConstructSpdyDataFrame(5, false));
  spdy::SpdySerializedFrame fbody3(spdy_util_.ConstructSpdyDataFrame(5, true));

  spdy::SettingsMap settings;
  const uint32_t max_concurrent_streams = 1;
  settings[spdy::SETTINGS_MAX_CONCURRENT_STREAMS] = max_concurrent_streams;
  spdy::SpdySerializedFrame settings_frame(
      spdy_util_.ConstructSpdySettings(settings));
  spdy::SpdySerializedFrame settings_ack(spdy_util_.ConstructSpdySettingsAck());

  MockWrite writes[] = {
      CreateMockWrite(req, 0),
      CreateMockWrite(settings_ack, 5),
      CreateMockWrite(req2, 6),
      CreateMockWrite(req3, 10),
  };

  MockRead reads[] = {
      CreateMockRead(settings_frame, 1),
      CreateMockRead(resp, 2),
      CreateMockRead(body, 3),
      CreateMockRead(fbody, 4),
      CreateMockRead(resp2, 7),
      CreateMockRead(body2, 8),
      CreateMockRead(fbody2, 9),
      CreateMockRead(resp3, 11),
      CreateMockRead(body3, 12),
      CreateMockRead(fbody3, 13),

      MockRead(ASYNC, 0, 14),  // EOF
  };

  SequencedSocketData data(reads, writes);

  TransactionHelperResult out;
  {
    NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                       nullptr);
    helper.RunPreTestSetup();
    helper.AddData(&data);
    HttpNetworkTransaction trans1(DEFAULT_PRIORITY, helper.session());
    HttpNetworkTransaction trans2(DEFAULT_PRIORITY, helper.session());
    HttpNetworkTransaction trans3(DEFAULT_PRIORITY, helper.session());

    TestCompletionCallback callback1;
    TestCompletionCallback callback2;
    TestCompletionCallback callback3;

    out.rv = trans1.Start(&request_, callback1.callback(), log_);
    ASSERT_EQ(out.rv, ERR_IO_PENDING);
    // Run transaction 1 through quickly to force a read of our SETTINGS
    // frame.
    out.rv = callback1.WaitForResult();
    ASSERT_THAT(out.rv, IsOk());

    out.rv = trans2.Start(&request_, callback2.callback(), log_);
    ASSERT_EQ(out.rv, ERR_IO_PENDING);
    out.rv = trans3.Start(&request_, callback3.callback(), log_);
    ASSERT_EQ(out.rv, ERR_IO_PENDING);
    out.rv = callback2.WaitForResult();
    ASSERT_THAT(out.rv, IsOk());

    out.rv = callback3.WaitForResult();
    ASSERT_THAT(out.rv, IsOk());

    const HttpResponseInfo* response1 = trans1.GetResponseInfo();
    ASSERT_TRUE(response1);
    EXPECT_TRUE(response1->headers);
    EXPECT_TRUE(response1->was_fetched_via_spdy);
    out.status_line = response1->headers->GetStatusLine();
    out.response_info = *response1;
    out.rv = ReadTransaction(&trans1, &out.response_data);
    EXPECT_THAT(out.rv, IsOk());
    EXPECT_EQ("HTTP/1.1 200", out.status_line);
    EXPECT_EQ("hello!hello!", out.response_data);

    const HttpResponseInfo* response2 = trans2.GetResponseInfo();
    out.status_line = response2->headers->GetStatusLine();
    out.response_info = *response2;
    out.rv = ReadTransaction(&trans2, &out.response_data);
    EXPECT_THAT(out.rv, IsOk());
    EXPECT_EQ("HTTP/1.1 200", out.status_line);
    EXPECT_EQ("hello!hello!", out.response_data);

    const HttpResponseInfo* response3 = trans3.GetResponseInfo();
    out.status_line = response3->headers->GetStatusLine();
    out.response_info = *response3;
    out.rv = ReadTransaction(&trans3, &out.response_data);
    EXPECT_THAT(out.rv, IsOk());
    EXPECT_EQ("HTTP/1.1 200", out.status_line);
    EXPECT_EQ("hello!hello!", out.response_data);

    helper.VerifyDataConsumed();
  }
  EXPECT_THAT(out.rv, IsOk());
}

// Similar to ThreeGetsWithMaxConcurrent above, however this test adds
// a fourth transaction.  The third and fourth transactions have
// different data ("hello!" vs "hello!hello!") and because of the
// user specified priority, we expect to see them inverted in
// the response from the server.
TEST_P(SpdyNetworkTransactionTest, FourGetsWithMaxConcurrentPriority) {
  // Construct the request.
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, false));
  spdy::SpdySerializedFrame fbody(spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy_util_.UpdateWithStreamDestruction(1);

  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, LOWEST));
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, false));
  spdy::SpdySerializedFrame fbody2(spdy_util_.ConstructSpdyDataFrame(3, true));
  spdy_util_.UpdateWithStreamDestruction(3);

  spdy::SpdySerializedFrame req4(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 5, HIGHEST));
  spdy::SpdySerializedFrame resp4(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 5));
  spdy::SpdySerializedFrame fbody4(spdy_util_.ConstructSpdyDataFrame(5, true));
  spdy_util_.UpdateWithStreamDestruction(5);

  spdy::SpdySerializedFrame req3(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 7, LOWEST));
  spdy::SpdySerializedFrame resp3(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 7));
  spdy::SpdySerializedFrame body3(spdy_util_.ConstructSpdyDataFrame(7, false));
  spdy::SpdySerializedFrame fbody3(spdy_util_.ConstructSpdyDataFrame(7, true));

  spdy::SettingsMap settings;
  const uint32_t max_concurrent_streams = 1;
  settings[spdy::SETTINGS_MAX_CONCURRENT_STREAMS] = max_concurrent_streams;
  spdy::SpdySerializedFrame settings_frame(
      spdy_util_.ConstructSpdySettings(settings));
  spdy::SpdySerializedFrame settings_ack(spdy_util_.ConstructSpdySettingsAck());
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
      CreateMockWrite(settings_ack, 5),
      // By making these synchronous, it guarantees that they are not *started*
      // before their sequence number, which in turn verifies that only a single
      // request is in-flight at a time.
      CreateMockWrite(req2, 6, SYNCHRONOUS),
      CreateMockWrite(req4, 10, SYNCHRONOUS),
      CreateMockWrite(req3, 13, SYNCHRONOUS),
  };
  MockRead reads[] = {
      CreateMockRead(settings_frame, 1),
      CreateMockRead(resp, 2),
      CreateMockRead(body, 3),
      CreateMockRead(fbody, 4),
      CreateMockRead(resp2, 7),
      CreateMockRead(body2, 8),
      CreateMockRead(fbody2, 9),
      CreateMockRead(resp4, 11),
      CreateMockRead(fbody4, 12),
      CreateMockRead(resp3, 14),
      CreateMockRead(body3, 15),
      CreateMockRead(fbody3, 16),

      MockRead(ASYNC, 0, 17),  // EOF
  };
  SequencedSocketData data(reads, writes);
  TransactionHelperResult out;
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);

  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, helper.session());
  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, helper.session());
  HttpNetworkTransaction trans3(DEFAULT_PRIORITY, helper.session());
  HttpNetworkTransaction trans4(HIGHEST, helper.session());

  TestCompletionCallback callback1;
  TestCompletionCallback callback2;
  TestCompletionCallback callback3;
  TestCompletionCallback callback4;

  out.rv = trans1.Start(&request_, callback1.callback(), log_);
  ASSERT_THAT(out.rv, IsError(ERR_IO_PENDING));
  // Run transaction 1 through quickly to force a read of our SETTINGS frame.
  out.rv = callback1.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());

  // Finish async network reads and writes associated with |trans1|.
  base::RunLoop().RunUntilIdle();

  out.rv = trans2.Start(&request_, callback2.callback(), log_);
  ASSERT_THAT(out.rv, IsError(ERR_IO_PENDING));
  out.rv = trans3.Start(&request_, callback3.callback(), log_);
  ASSERT_THAT(out.rv, IsError(ERR_IO_PENDING));
  out.rv = trans4.Start(&request_, callback4.callback(), log_);
  ASSERT_THAT(out.rv, IsError(ERR_IO_PENDING));

  out.rv = callback2.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());

  out.rv = callback3.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());

  const HttpResponseInfo* response1 = trans1.GetResponseInfo();
  EXPECT_TRUE(response1->headers);
  EXPECT_TRUE(response1->was_fetched_via_spdy);
  out.status_line = response1->headers->GetStatusLine();
  out.response_info = *response1;
  out.rv = ReadTransaction(&trans1, &out.response_data);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!hello!", out.response_data);

  const HttpResponseInfo* response2 = trans2.GetResponseInfo();
  out.status_line = response2->headers->GetStatusLine();
  out.response_info = *response2;
  out.rv = ReadTransaction(&trans2, &out.response_data);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!hello!", out.response_data);

  // notice: response3 gets two hellos, response4 gets one
  // hello, so we know dequeuing priority was respected.
  const HttpResponseInfo* response3 = trans3.GetResponseInfo();
  out.status_line = response3->headers->GetStatusLine();
  out.response_info = *response3;
  out.rv = ReadTransaction(&trans3, &out.response_data);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!hello!", out.response_data);

  out.rv = callback4.WaitForResult();
  EXPECT_THAT(out.rv, IsOk());
  const HttpResponseInfo* response4 = trans4.GetResponseInfo();
  out.status_line = response4->headers->GetStatusLine();
  out.response_info = *response4;
  out.rv = ReadTransaction(&trans4, &out.response_data);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
  helper.VerifyDataConsumed();
  EXPECT_THAT(out.rv, IsOk());
}

// Similar to ThreeGetsMaxConcurrrent above, however, this test
// deletes a session in the middle of the transaction to ensure
// that we properly remove pendingcreatestream objects from
// the spdy_session
TEST_P(SpdyNetworkTransactionTest, ThreeGetsWithMaxConcurrentDelete) {
  // Construct the request.
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, false));
  spdy::SpdySerializedFrame fbody(spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy_util_.UpdateWithStreamDestruction(1);

  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, LOWEST));
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));
  spdy::SpdySerializedFrame body2(spdy_util_.ConstructSpdyDataFrame(3, false));
  spdy::SpdySerializedFrame fbody2(spdy_util_.ConstructSpdyDataFrame(3, true));

  spdy::SettingsMap settings;
  const uint32_t max_concurrent_streams = 1;
  settings[spdy::SETTINGS_MAX_CONCURRENT_STREAMS] = max_concurrent_streams;
  spdy::SpdySerializedFrame settings_frame(
      spdy_util_.ConstructSpdySettings(settings));
  spdy::SpdySerializedFrame settings_ack(spdy_util_.ConstructSpdySettingsAck());

  MockWrite writes[] = {
      CreateMockWrite(req, 0),
      CreateMockWrite(settings_ack, 5),
      CreateMockWrite(req2, 6),
  };
  MockRead reads[] = {
      CreateMockRead(settings_frame, 1), CreateMockRead(resp, 2),
      CreateMockRead(body, 3),           CreateMockRead(fbody, 4),
      CreateMockRead(resp2, 7),          CreateMockRead(body2, 8),
      CreateMockRead(fbody2, 9),         MockRead(ASYNC, 0, 10),  // EOF
  };

  SequencedSocketData data(reads, writes);

  TransactionHelperResult out;
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  auto trans1 = std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY,
                                                         helper.session());
  auto trans2 = std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY,
                                                         helper.session());
  auto trans3 = std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY,
                                                         helper.session());

  TestCompletionCallback callback1;
  TestCompletionCallback callback2;
  TestCompletionCallback callback3;

  out.rv = trans1->Start(&request_, callback1.callback(), log_);
  ASSERT_EQ(out.rv, ERR_IO_PENDING);
  // Run transaction 1 through quickly to force a read of our SETTINGS frame.
  out.rv = callback1.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());

  out.rv = trans2->Start(&request_, callback2.callback(), log_);
  ASSERT_EQ(out.rv, ERR_IO_PENDING);
  out.rv = trans3->Start(&request_, callback3.callback(), log_);
  trans3.reset();
  ASSERT_EQ(out.rv, ERR_IO_PENDING);
  out.rv = callback2.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());

  const HttpResponseInfo* response1 = trans1->GetResponseInfo();
  ASSERT_TRUE(response1);
  EXPECT_TRUE(response1->headers);
  EXPECT_TRUE(response1->was_fetched_via_spdy);
  out.status_line = response1->headers->GetStatusLine();
  out.response_info = *response1;
  out.rv = ReadTransaction(trans1.get(), &out.response_data);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!hello!", out.response_data);

  const HttpResponseInfo* response2 = trans2->GetResponseInfo();
  ASSERT_TRUE(response2);
  out.status_line = response2->headers->GetStatusLine();
  out.response_info = *response2;
  out.rv = ReadTransaction(trans2.get(), &out.response_data);
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!hello!", out.response_data);
  helper.VerifyDataConsumed();
  EXPECT_THAT(out.rv, IsOk());
}

namespace {

// A helper class that will delete |transaction| on error when the callback is
// invoked.
class KillerCallback : public TestCompletionCallbackBase {
 public:
  explicit KillerCallback(std::unique_ptr<HttpNetworkTransaction> transaction)
      : transaction_(std::move(transaction)) {}

  ~KillerCallback() override = default;

  CompletionOnceCallback callback() {
    return base::BindOnce(&KillerCallback::OnComplete, base::Unretained(this));
  }

 private:
  void OnComplete(int result) {
    if (result < 0) {
      transaction_.reset();
    }

    SetResult(result);
  }

  std::unique_ptr<HttpNetworkTransaction> transaction_;
};

}  // namespace

// Similar to ThreeGetsMaxConcurrrentDelete above, however, this test
// closes the socket while we have a pending transaction waiting for
// a pending stream creation.  http://crbug.com/52901
TEST_P(SpdyNetworkTransactionTest, ThreeGetsWithMaxConcurrentSocketClose) {
  // Construct the request. Each stream uses a different priority to provide
  // more useful failure information if the requests are made in an unexpected
  // order.
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, HIGHEST));
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, false));
  spdy::SpdySerializedFrame fin_body(
      spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy_util_.UpdateWithStreamDestruction(1);

  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, MEDIUM));
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 3));

  spdy::SettingsMap settings;
  const uint32_t max_concurrent_streams = 1;
  settings[spdy::SETTINGS_MAX_CONCURRENT_STREAMS] = max_concurrent_streams;
  spdy::SpdySerializedFrame settings_frame(
      spdy_util_.ConstructSpdySettings(settings));
  spdy::SpdySerializedFrame settings_ack(spdy_util_.ConstructSpdySettingsAck());

  MockWrite writes[] = {CreateMockWrite(req, 0),
                        CreateMockWrite(settings_ack, 6),
                        CreateMockWrite(req2, 7)};
  MockRead reads[] = {
      CreateMockRead(settings_frame, 1), CreateMockRead(resp, 2),
      CreateMockRead(body, 3),
      // Delay the request here. For this test to pass, the three HTTP streams
      // have to be created in order, but SpdySession doesn't actually guarantee
      // that (See note in SpdySession::ProcessPendingStreamRequests). As a
      // workaround, delay finishing up the first stream until the second and
      // third streams are waiting in the SPDY stream request queue.
      MockRead(ASYNC, ERR_IO_PENDING, 4), CreateMockRead(fin_body, 5),
      CreateMockRead(resp2, 8),
      // The exact error does not matter, but some errors, such as
      // ERR_CONNECTION_RESET, may trigger a retry, which this test does not
      // account for.
      MockRead(ASYNC, ERR_SSL_BAD_RECORD_MAC_ALERT, 9),  // Abort!
  };

  SequencedSocketData data(reads, writes);
  SequencedSocketData data_placeholder;

  TransactionHelperResult out;
  NormalSpdyTransactionHelper helper(request_, HIGHEST, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  // We require placeholder data because three get requests are sent out, so
  // there needs to be three sets of SSL connection data.
  helper.AddData(&data_placeholder);
  helper.AddData(&data_placeholder);
  HttpNetworkTransaction trans1(HIGHEST, helper.session());
  HttpNetworkTransaction trans2(MEDIUM, helper.session());
  auto trans3 = std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY,
                                                         helper.session());
  auto* trans3_ptr = trans3.get();

  TestCompletionCallback callback1;
  TestComplet
"""


```