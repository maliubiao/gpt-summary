Response:
The user wants me to analyze a C++ source code file related to network transactions in Chromium's networking stack, specifically for the SPDY protocol. I need to describe its functionality, explore potential connections to JavaScript, discuss logical inferences with example inputs/outputs, point out common usage errors, illustrate debugging approaches, and summarize the file's purpose.

**Plan:**

1. **Functionality Description:** Analyze the test cases in the provided code snippet. These tests seem to focus on verifying the behavior of `SpdyNetworkTransaction` for different HTTP methods (GET, PUT, POST, HEAD), handling of request/response headers and bodies, dealing with errors, and managing the lifecycle of transactions.
2. **JavaScript Relationship:**  Think about how network requests initiated by JavaScript in a web browser interact with the underlying network stack. JavaScript's `fetch` API or `XMLHttpRequest` ultimately lead to network transactions. Consider examples where SPDY might be used transparently.
3. **Logical Inferences:** Select a simple test case (e.g., a basic GET request) and describe the expected sequence of events, including the input (HTTP request) and output (HTTP response).
4. **User/Programming Errors:** Identify common mistakes users or developers might make that could lead to the execution paths tested in this file. Examples include incorrect request methods, malformed headers, or issues with request body data.
5. **Debugging:** Describe how a developer might arrive at this code during debugging. This could involve setting breakpoints, analyzing network logs, or examining crash reports related to network requests.
6. **Summary:** Provide a concise overview of the file's purpose based on the analysis.
这是对 `net/spdy/spdy_network_transaction_unittest.cc` 文件部分代码的分析。

**功能列举:**

这个代码片段主要包含了针对 `SpdyNetworkTransaction` 类的单元测试。`SpdyNetworkTransaction` 是 Chromium 网络栈中负责处理基于 SPDY 协议的网络请求的类。这些测试用例旨在验证 `SpdyNetworkTransaction` 在各种场景下的正确行为，包括：

*   **基本的 HTTP 方法测试 (GET, PUT, HEAD, POST):**  测试不同的 HTTP 请求方法是否能正确地构造 SPDY 帧并处理服务器的响应。
*   **处理请求体 (PUT, POST):**  测试带有请求体的数据发送是否正确，包括普通数据和文件上传。
*   **分块传输编码 (Chunked POST):** 测试分块上传数据的处理，包括延迟添加数据块的情况。
*   **空请求体 (Null Post, Empty Post):**  测试没有请求体的情况。
*   **处理服务器在上传完成前发送响应:** 验证在请求体还在发送时接收到服务器响应的处理逻辑。
*   **处理 socket write 返回 0 的情况:** 模拟底层 socket 写操作返回 0 字节的情况，验证重试机制。
*   **处理不完整的响应 (ResponseWithoutHeaders):** 测试当接收到没有头部信息的响应时的行为。
*   **处理接收到多个响应头 (ResponseWithTwoSynReplies):** 测试接收到重复的响应头时的错误处理。
*   **处理带有 Transfer-Encoding 的 RST_STREAM 帧:** 测试当服务器发送带有 `Transfer-Encoding` 头的 RST_STREAM 帧时的处理。
*   **取消事务 (CancelledTransaction, CancelledTransactionSendRst):** 测试客户端取消请求时是否能正确发送 RST_STREAM 帧。
*   **在 Read 回调中启动新的事务 (StartTransactionOnReadCallback):** 测试在读取数据回调中尝试启动新事务的情况。
*   **在 Read 回调中删除 Session (DeleteSessionOnReadCallback):** 测试在读取数据回调中删除当前 Session 的情况。
*   **处理重定向 (RedirectGetRequest, RedirectMultipleLocations):** 测试 SPDY 如何处理 HTTP 重定向，以及当存在多个 `Location` 头部时的行为。
*   **处理通过隧道连接的情况 (NoConnectionPoolingOverTunnel):**  测试在使用代理隧道时连接池的行为。

**与 JavaScript 的关系:**

虽然这段 C++ 代码本身不包含 JavaScript，但它直接支持了浏览器中 JavaScript 发起的网络请求。当 JavaScript 使用 `fetch` API 或 `XMLHttpRequest` 发起一个 HTTPS 请求，且浏览器与服务器之间协商使用了 SPDY (或 HTTP/2，它与 SPDY 有很多相似之处)，那么底层的网络通信很可能就会通过 `SpdyNetworkTransaction` 来处理。

**举例说明:**

假设一个网页上的 JavaScript 代码使用 `fetch` 发送一个简单的 GET 请求：

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

如果浏览器和 `example.com` 服务器之间使用了 SPDY，那么当这个 `fetch` 请求被发起时，Chromium 的网络栈会创建一个 `SpdyNetworkTransaction` 实例来处理这个请求。  `SpdyNetworkTransaction` 会负责将 JavaScript 发起的请求转换为 SPDY 帧，通过底层的 socket 发送给服务器，并接收服务器返回的 SPDY 帧，最终将响应数据传递回 JavaScript。

**逻辑推理 (假设输入与输出):**

**假设输入:**  一个针对 `https://test.example.com/data` 的简单的 GET 请求。

**`SpdyNetworkTransactionTest.Get` 测试用例的逻辑:**

1. **模拟网络交互:**  `MockWrite` 定义了期望发送给服务器的 SPDY 帧（包含 GET 请求头）。`MockRead` 定义了期望从服务器接收的 SPDY 帧（包含响应头和响应体）。
2. **创建 `SpdyNetworkTransaction`:** `NormalSpdyTransactionHelper` 负责创建和管理 `SpdyNetworkTransaction` 实例。
3. **启动事务:**  调用 `trans1.Start()` 启动网络事务。
4. **等待结果:** `callback1.WaitForResult()` 模拟等待网络操作完成。
5. **验证结果:**
    *   `EXPECT_THAT(out.rv, IsOk());` 验证网络请求成功 (返回码 OK)。
    *   `EXPECT_EQ("HTTP/1.1 200", out.status_line);` 验证响应状态码是 200。
    *   `EXPECT_EQ("hello!", out.response_data);` 验证接收到的响应数据是 "hello!"。

**假设输入 (对于 `SpdyNetworkTransactionTest.Put`):** 一个针对 `https://test.example.com/resource` 的 PUT 请求，没有请求体。

**输出:**

*   发送一个包含 PUT 请求头的 SPDY HEADERS 帧。
*   接收到一个包含状态码 200 的 SPDY HEADERS 帧。
*   接收到一个空的 SPDY DATA 帧 (表示响应体结束)。
*   测试断言成功，验证请求成功，状态码为 200。

**用户或编程常见的使用错误举例:**

*   **错误的请求方法:** 用户可能在 JavaScript 中错误地使用了 `POST` 方法，但没有提供请求体数据，或者服务器期望接收到请求体数据。 这可能会导致服务器返回错误，而 `SpdyNetworkTransaction` 需要正确处理这些错误情况。 例如，服务器可能返回 400 Bad Request。
*   **请求头不匹配:**  用户可能在 JavaScript 中设置了错误的请求头，导致服务器无法正确处理请求。例如，`Content-Type` 头与实际发送的数据不符。这可能会导致服务器返回 415 Unsupported Media Type。
*   **POST 请求缺少 Content-Length:**  虽然 SPDY 可以处理没有 `Content-Length` 的 POST 请求（通过分块传输），但如果用户在非 SPDY 环境下习惯了必须设置 `Content-Length`，可能会在 SPDY 环境下产生误解。测试用例 `SpdyNetworkTransactionTest.NullPost` 和 `SpdyNetworkTransactionTest.EmptyPost` 验证了 SPDY 如何处理这两种情况。
*   **取消请求过早:** 用户可能在请求还未完成时就取消了请求，例如在 JavaScript 中调用 `abort()`。 `SpdyNetworkTransactionTest.CancelledTransaction` 和 `SpdyNetworkTransactionTest.CancelledTransactionSendRst` 测试了这种情况下客户端的行为。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入网址或点击链接:**  如果网站支持 SPDY (或 HTTP/2)，浏览器会尝试与服务器建立 SPDY 连接。
2. **JavaScript 代码发起网络请求:**  网页上的 JavaScript 代码通过 `fetch` 或 `XMLHttpRequest` 向服务器请求数据。
3. **网络栈选择 SPDY 协议:**  Chromium 的网络栈判断当前连接可以使用 SPDY 协议。
4. **创建 `SpdyNetworkTransaction` 实例:**  网络栈创建一个 `SpdyNetworkTransaction` 对象来处理这个请求。
5. **发送 SPDY 帧:** `SpdyNetworkTransaction` 将请求信息封装成 SPDY 帧并通过 socket 发送出去。
6. **接收 SPDY 帧:**  `SpdyNetworkTransaction` 接收来自服务器的 SPDY 帧。
7. **处理响应:**  `SpdyNetworkTransaction` 解析接收到的 SPDY 帧，提取响应头和响应体。
8. **传递响应回 JavaScript:**  最终，响应数据被传递回 JavaScript 代码。

**作为调试线索:** 如果在网络请求过程中出现问题，例如请求失败、响应数据不正确等，开发者可能会：

*   **查看 Chrome 的 "开发者工具" (Network 面板):**  可以查看请求的详细信息，包括使用的协议、请求头、响应头、状态码等。
*   **启用网络日志 (net-internals):**  可以查看更底层的网络事件，包括 SPDY 帧的发送和接收。
*   **设置断点进行代码调试:**  如果怀疑是 `SpdyNetworkTransaction` 的问题，开发者可能会在 `net/spdy/spdy_network_transaction.cc` 或相关的代码中设置断点，逐步跟踪代码执行，查看变量的值，以找出问题所在。  例如，他们可能会在发送请求帧或接收响应帧的地方设置断点，检查帧的内容是否符合预期。

**第 3 部分功能归纳:**

这段代码（第 3 部分）主要涵盖了 `SpdyNetworkTransaction` 类在处理各种 HTTP 方法 (GET, PUT, HEAD, POST) 以及不同类型的请求体 (包括分块上传和空请求体) 时的单元测试。它验证了请求的构建、响应的解析、错误处理以及在特定场景下的行为，例如在上传完成前收到响应和处理底层 socket 写入失败的情况。  此外，还包括了取消请求、在回调中操作 session 和处理重定向等更复杂场景的测试。 这些测试确保了 `SpdyNetworkTransaction` 能够可靠地处理各种常见的和异常的网络请求，为基于 SPDY 协议的网络通信提供稳定的基础。

### 提示词
```
这是目录为net/spdy/spdy_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
ionCallback callback2;
  KillerCallback callback3(std::move(trans3));

  out.rv = trans1.Start(&request_, callback1.callback(), log_);
  ASSERT_EQ(out.rv, ERR_IO_PENDING);
  // Run transaction 1 through quickly to force a read of our SETTINGS frame.
  out.rv = callback1.WaitForResult();
  ASSERT_THAT(out.rv, IsOk());

  out.rv = trans2.Start(&request_, callback2.callback(), log_);
  ASSERT_EQ(out.rv, ERR_IO_PENDING);
  out.rv = trans3_ptr->Start(&request_, callback3.callback(), log_);
  ASSERT_EQ(out.rv, ERR_IO_PENDING);

  // Run until both transactions are in the SpdySession's queue, waiting for the
  // final request to complete.
  base::RunLoop().RunUntilIdle();
  data.Resume();

  out.rv = callback3.WaitForResult();
  EXPECT_THAT(out.rv, IsError(ERR_SSL_BAD_RECORD_MAC_ALERT));

  const HttpResponseInfo* response1 = trans1.GetResponseInfo();
  ASSERT_TRUE(response1);
  EXPECT_TRUE(response1->headers);
  EXPECT_TRUE(response1->was_fetched_via_spdy);
  out.status_line = response1->headers->GetStatusLine();
  out.response_info = *response1;
  out.rv = ReadTransaction(&trans1, &out.response_data);
  EXPECT_THAT(out.rv, IsOk());

  const HttpResponseInfo* response2 = trans2.GetResponseInfo();
  ASSERT_TRUE(response2);
  out.status_line = response2->headers->GetStatusLine();
  out.response_info = *response2;
  out.rv = ReadTransaction(&trans2, &out.response_data);
  EXPECT_THAT(out.rv, IsError(ERR_SSL_BAD_RECORD_MAC_ALERT));

  helper.VerifyDataConsumed();
}

// Test that a simple PUT request works.
TEST_P(SpdyNetworkTransactionTest, Put) {
  // Setup the request.
  request_.method = "PUT";

  quiche::HttpHeaderBlock put_headers(
      spdy_util_.ConstructPutHeaderBlock(kDefaultUrl, 0));
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyHeaders(1, std::move(put_headers), LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, writes);
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();

  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
}

// Test that a simple HEAD request works.
TEST_P(SpdyNetworkTransactionTest, Head) {
  // Setup the request.
  request_.method = "HEAD";

  quiche::HttpHeaderBlock head_headers(
      spdy_util_.ConstructHeadHeaderBlock(kDefaultUrl, 0));
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyHeaders(
      1, std::move(head_headers), LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, writes);
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();

  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
}

// Test that a simple POST works.
TEST_P(SpdyNetworkTransactionTest, Post) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kUploadDataSize, LOWEST, nullptr, 0));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(body, 1),  // POST upload frame
  };

  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  MockRead reads[] = {
      CreateMockRead(resp, 2), CreateMockRead(body, 3),
      MockRead(ASYNC, 0, 4)  // EOF
  };

  SequencedSocketData data(reads, writes);
  UsePostRequest();
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
}

// Test that a POST with a file works.
TEST_P(SpdyNetworkTransactionTest, FilePost) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kUploadDataSize, LOWEST, nullptr, 0));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(body, 1),  // POST upload frame
  };

  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  MockRead reads[] = {
      CreateMockRead(resp, 2), CreateMockRead(body, 3),
      MockRead(ASYNC, 0, 4)  // EOF
  };

  SequencedSocketData data(reads, writes);
  UseFilePostRequest();
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
}

// Test that a POST with a unreadable file fails.
TEST_P(SpdyNetworkTransactionTest, UnreadableFilePost) {
  MockWrite writes[] = {
      MockWrite(ASYNC, 0, 0)  // EOF
  };
  MockRead reads[] = {
      MockRead(ASYNC, 0, 1)  // EOF
  };

  SequencedSocketData data(reads, writes);
  UseUnreadableFilePostRequest();
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  helper.RunDefaultTest();

  base::RunLoop().RunUntilIdle();
  helper.VerifyDataNotConsumed();
  EXPECT_THAT(helper.output().rv, IsError(ERR_ACCESS_DENIED));
}

// Test that a complex POST works.
TEST_P(SpdyNetworkTransactionTest, ComplexPost) {
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyPost(
      kDefaultUrl, 1, kUploadDataSize, LOWEST, nullptr, 0));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(body, 1),  // POST upload frame
  };

  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  MockRead reads[] = {
      CreateMockRead(resp, 2), CreateMockRead(body, 3),
      MockRead(ASYNC, 0, 4)  // EOF
  };

  SequencedSocketData data(reads, writes);
  UseComplexPostRequest();
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
}

// Test that a chunked POST works.
TEST_P(SpdyNetworkTransactionTest, ChunkedPost) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructChunkedSpdyPost(nullptr, 0));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
      CreateMockWrite(body, 1),
  };

  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  MockRead reads[] = {
      CreateMockRead(resp, 2), CreateMockRead(body, 3),
      MockRead(ASYNC, 0, 4)  // EOF
  };

  SequencedSocketData data(reads, writes);
  UseChunkedPostRequest();
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);

  // These chunks get merged into a single frame when being sent.
  const size_t kFirstChunkSize = kUploadDataSize / 2;
  auto [first_chunk, second_chunk] =
      base::byte_span_from_cstring(kUploadData).split_at(kFirstChunkSize);
  upload_chunked_data_stream()->AppendData(first_chunk, false);
  upload_chunked_data_stream()->AppendData(second_chunk, true);

  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ(kUploadData, out.response_data);
}

// Test that a chunked POST works with chunks appended after transaction starts.
TEST_P(SpdyNetworkTransactionTest, DelayedChunkedPost) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructChunkedSpdyPost(nullptr, 0));
  spdy::SpdySerializedFrame chunk1(spdy_util_.ConstructSpdyDataFrame(1, false));
  spdy::SpdySerializedFrame chunk2(spdy_util_.ConstructSpdyDataFrame(1, false));
  spdy::SpdySerializedFrame chunk3(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
      CreateMockWrite(chunk1, 1),
      CreateMockWrite(chunk2, 2),
      CreateMockWrite(chunk3, 3),
  };

  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  MockRead reads[] = {
      CreateMockRead(resp, 4), CreateMockRead(chunk1, 5),
      CreateMockRead(chunk2, 6), CreateMockRead(chunk3, 7),
      MockRead(ASYNC, 0, 8)  // EOF
  };

  SequencedSocketData data(reads, writes);
  UseChunkedPostRequest();
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);

  upload_chunked_data_stream()->AppendData(
      base::byte_span_from_cstring(kUploadData), false);

  helper.RunPreTestSetup();
  helper.AddData(&data);
  ASSERT_TRUE(helper.StartDefaultTest());

  base::RunLoop().RunUntilIdle();
  upload_chunked_data_stream()->AppendData(
      base::byte_span_from_cstring(kUploadData), false);
  base::RunLoop().RunUntilIdle();
  upload_chunked_data_stream()->AppendData(
      base::byte_span_from_cstring(kUploadData), true);

  helper.FinishDefaultTest();
  helper.VerifyDataConsumed();

  std::string expected_response;
  expected_response += kUploadData;
  expected_response += kUploadData;
  expected_response += kUploadData;

  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ(expected_response, out.response_data);
}

// Test that a POST without any post data works.
TEST_P(SpdyNetworkTransactionTest, NullPost) {
  // Setup the request.
  request_.method = "POST";
  // Create an empty UploadData.
  request_.upload_data_stream = nullptr;

  // When request.upload_data_stream is NULL for post, content-length is
  // expected to be 0.
  quiche::HttpHeaderBlock req_block(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, 0));
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyHeaders(1, std::move(req_block), LOWEST, true));

  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, writes);

  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
}

// Test that a simple POST works.
TEST_P(SpdyNetworkTransactionTest, EmptyPost) {
  // Create an empty UploadDataStream.
  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  ElementsUploadDataStream stream(std::move(element_readers), 0);

  // Setup the request.
  request_.method = "POST";
  request_.upload_data_stream = &stream;

  const uint64_t kContentLength = 0;

  quiche::HttpHeaderBlock req_block(
      spdy_util_.ConstructPostHeaderBlock(kDefaultUrl, kContentLength));
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyHeaders(1, std::move(req_block), LOWEST, true));

  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, writes);

  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
}

// While we're doing a post, the server sends the reply before upload completes.
TEST_P(SpdyNetworkTransactionTest, ResponseBeforePostCompletes) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructChunkedSpdyPost(nullptr, 0));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
      CreateMockWrite(body, 3),
  };
  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 4)  // EOF
  };

  // Write the request headers, and read the complete response
  // while still waiting for chunked request data.
  SequencedSocketData data(reads, writes);
  UseChunkedPostRequest();
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);

  ASSERT_TRUE(helper.StartDefaultTest());

  base::RunLoop().RunUntilIdle();

  // Process the request headers, response headers, and response body.
  // The request body is still in flight.
  const HttpResponseInfo* response = helper.trans()->GetResponseInfo();
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());

  // Finish sending the request body.
  upload_chunked_data_stream()->AppendData(
      base::byte_span_from_cstring(kUploadData), true);
  helper.WaitForCallbackToComplete();
  EXPECT_THAT(helper.output().rv, IsOk());

  std::string response_body;
  EXPECT_THAT(ReadTransaction(helper.trans(), &response_body), IsOk());
  EXPECT_EQ(kUploadData, response_body);

  // Finish async network reads/writes.
  base::RunLoop().RunUntilIdle();
  helper.VerifyDataConsumed();
}

// The client upon cancellation tries to send a RST_STREAM frame. The mock
// socket causes the TCP write to return zero. This test checks that the client
// tries to queue up the RST_STREAM frame again.
TEST_P(SpdyNetworkTransactionTest, SocketWriteReturnsZero) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));
  MockWrite writes[] = {
      CreateMockWrite(req, 0, SYNCHRONOUS),
      MockWrite(SYNCHRONOUS, nullptr, 0, 2),
      CreateMockWrite(rst, 3, SYNCHRONOUS),
  };

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  MockRead reads[] = {
      CreateMockRead(resp, 1, ASYNC), MockRead(ASYNC, nullptr, 0, 4)  // EOF
  };

  SequencedSocketData data(reads, writes);
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  helper.StartDefaultTest();
  EXPECT_THAT(helper.output().rv, IsError(ERR_IO_PENDING));

  helper.WaitForCallbackToComplete();
  EXPECT_THAT(helper.output().rv, IsOk());

  helper.ResetTrans();
  base::RunLoop().RunUntilIdle();

  helper.VerifyDataConsumed();
}

// Test that the transaction doesn't crash when we don't have a reply.
TEST_P(SpdyNetworkTransactionTest, ResponseWithoutHeaders) {
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(body, 1), MockRead(ASYNC, 0, 3)  // EOF
  };

  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_PROTOCOL_ERROR));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
      CreateMockWrite(rst, 2),
  };
  SequencedSocketData data(reads, writes);
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_HTTP2_PROTOCOL_ERROR));
}

// Test that the transaction doesn't crash when we get two replies on the same
// stream ID. See http://crbug.com/45639.
TEST_P(SpdyNetworkTransactionTest, ResponseWithTwoSynReplies) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_PROTOCOL_ERROR));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
      CreateMockWrite(rst, 4),
  };

  spdy::SpdySerializedFrame resp0(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp0, 1), CreateMockRead(resp1, 2),
      CreateMockRead(body, 3), MockRead(ASYNC, 0, 5)  // EOF
  };

  SequencedSocketData data(reads, writes);

  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);

  HttpNetworkTransaction* trans = helper.trans();

  TestCompletionCallback callback;
  int rv = trans->Start(&request_, callback.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  EXPECT_TRUE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);
  std::string response_data;
  rv = ReadTransaction(trans, &response_data);
  EXPECT_THAT(rv, IsError(ERR_HTTP2_PROTOCOL_ERROR));

  helper.VerifyDataConsumed();
}

TEST_P(SpdyNetworkTransactionTest, ResetReplyWithTransferEncoding) {
  // Construct the request.
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_PROTOCOL_ERROR));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
      CreateMockWrite(rst, 2),
  };

  const char* const headers[] = {"transfer-encoding", "chunked"};
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(headers, 1, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 3),
      MockRead(ASYNC, 0, 4)  // EOF
  };

  SequencedSocketData data(reads, writes);
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_HTTP2_PROTOCOL_ERROR));

  helper.session()->spdy_session_pool()->CloseAllSessions();
  helper.VerifyDataConsumed();
}

TEST_P(SpdyNetworkTransactionTest, CancelledTransaction) {
  // Construct the request.
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  MockWrite writes[] = {
      CreateMockWrite(req),
  };

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  MockRead reads[] = {
      CreateMockRead(resp),
      // This following read isn't used by the test, except during the
      // RunUntilIdle() call at the end since the SpdySession survives the
      // HttpNetworkTransaction and still tries to continue Read()'ing.  Any
      // MockRead will do here.
      MockRead(ASYNC, 0, 0)  // EOF
  };

  StaticSocketDataProvider data(reads, writes);

  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  HttpNetworkTransaction* trans = helper.trans();

  TestCompletionCallback callback;
  int rv = trans->Start(&request_, callback.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  helper.ResetTrans();  // Cancel the transaction.

  // Flush the MessageLoop while the SpdySessionDependencies (in particular, the
  // MockClientSocketFactory) are still alive.
  base::RunLoop().RunUntilIdle();
  helper.VerifyDataNotConsumed();
}

// Verify that the client sends a Rst Frame upon cancelling the stream.
TEST_P(SpdyNetworkTransactionTest, CancelledTransactionSendRst) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));
  MockWrite writes[] = {
      CreateMockWrite(req, 0, SYNCHRONOUS),
      CreateMockWrite(rst, 2, SYNCHRONOUS),
  };

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  MockRead reads[] = {
      CreateMockRead(resp, 1, ASYNC), MockRead(ASYNC, nullptr, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, writes);

  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  HttpNetworkTransaction* trans = helper.trans();

  TestCompletionCallback callback;

  int rv = trans->Start(&request_, callback.callback(), log_);
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  helper.ResetTrans();
  base::RunLoop().RunUntilIdle();

  helper.VerifyDataConsumed();
}

// Verify that the client can correctly deal with the user callback attempting
// to start another transaction on a session that is closing down. See
// http://crbug.com/47455
TEST_P(SpdyNetworkTransactionTest, StartTransactionOnReadCallback) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  MockWrite writes[] = {CreateMockWrite(req)};
  MockWrite writes2[] = {CreateMockWrite(req, 0),
                         MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 3)};

  // The indicated length of this frame is longer than its actual length. When
  // the session receives an empty frame after this one, it shuts down the
  // session, and calls the read callback with the incomplete data.
  const uint8_t kGetBodyFrame2[] = {
      0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
      0x07, 'h',  'e',  'l',  'l',  'o',  '!',
  };

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a pause
      MockRead(ASYNC, reinterpret_cast<const char*>(kGetBodyFrame2),
               std::size(kGetBodyFrame2), 3),
      MockRead(ASYNC, ERR_IO_PENDING, 4),  // Force a pause
      MockRead(ASYNC, nullptr, 0, 5),      // EOF
  };
  MockRead reads2[] = {
      CreateMockRead(resp, 1), MockRead(ASYNC, nullptr, 0, 2),  // EOF
  };

  SequencedSocketData data(reads, writes);
  SequencedSocketData data2(reads2, writes2);

  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  helper.AddData(&data2);
  HttpNetworkTransaction* trans = helper.trans();

  // Start the transaction with basic parameters.
  TestCompletionCallback callback;
  int rv = trans->Start(&request_, callback.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();

  const int kSize = 3000;
  auto buf = base::MakeRefCounted<IOBufferWithSize>(kSize);
  rv = trans->Read(
      buf.get(), kSize,
      base::BindOnce(&SpdyNetworkTransactionTest::StartTransactionCallback,
                     helper.session(), default_url_, log_));
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  // This forces an err_IO_pending, which sets the callback.
  data.Resume();
  data.RunUntilPaused();

  // This finishes the read.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  helper.VerifyDataConsumed();
}

// Verify that the client can correctly deal with the user callback deleting
// the transaction. Failures will usually be flagged by thread and/or memory
// checking tools. See http://crbug.com/46925
TEST_P(SpdyNetworkTransactionTest, DeleteSessionOnReadCallback) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),                       // Force a pause
      CreateMockRead(body, 3), MockRead(ASYNC, nullptr, 0, 4),  // EOF
  };

  SequencedSocketData data(reads, writes);

  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  HttpNetworkTransaction* trans = helper.trans();

  // Start the transaction with basic parameters.
  TestCompletionCallback callback;
  int rv = trans->Start(&request_, callback.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback.WaitForResult();

  // Setup a user callback which will delete the session, and clear out the
  // memory holding the stream object. Note that the callback deletes trans.
  const int kSize = 3000;
  auto buf = base::MakeRefCounted<IOBufferWithSize>(kSize);
  rv = trans->Read(
      buf.get(), kSize,
      base::BindOnce(&SpdyNetworkTransactionTest::DeleteSessionCallback,
                     base::Unretained(&helper)));
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  data.Resume();

  // Finish running rest of tasks.
  base::RunLoop().RunUntilIdle();
  helper.VerifyDataConsumed();
}

TEST_P(SpdyNetworkTransactionTest, RedirectGetRequest) {
  MockClientSocketFactory socket_factory;
  auto context_builder =
      CreateSpdyTestURLRequestContextBuilder(&socket_factory);
  auto spdy_url_request_context = context_builder->Build();
  SpdySessionPoolPeer pool_peer(
      spdy_url_request_context->http_transaction_factory()
          ->GetSession()
          ->spdy_session_pool());
  pool_peer.SetEnableSendingInitialData(false);
  // Use a different port to avoid trying to reuse the initial H2 session.
  const char kRedirectUrl[] = "https://www.foo.com:8080/index.php";

  SSLSocketDataProvider ssl_provider0(ASYNC, OK);
  ssl_provider0.next_proto = kProtoHTTP2;
  socket_factory.AddSSLSocketDataProvider(&ssl_provider0);

  quiche::HttpHeaderBlock headers0(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  headers0["user-agent"] = "";
  headers0["accept-encoding"] = "gzip, deflate";

  spdy::SpdySerializedFrame req0(
      spdy_util_.ConstructSpdyHeaders(1, std::move(headers0), LOWEST, true));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));
  MockWrite writes0[] = {CreateMockWrite(req0, 0), CreateMockWrite(rst, 2)};

  const char* const kExtraHeaders[] = {"location", kRedirectUrl};
  spdy::SpdySerializedFrame resp0(spdy_util_.ConstructSpdyReplyError(
      "301", kExtraHeaders, std::size(kExtraHeaders) / 2, 1));
  MockRead reads0[] = {CreateMockRead(resp0, 1), MockRead(ASYNC, 0, 3)};

  SequencedSocketData data0(reads0, writes0);
  socket_factory.AddSocketDataProvider(&data0);

  SSLSocketDataProvider ssl_provider1(ASYNC, OK);
  ssl_provider1.next_proto = kProtoHTTP2;
  socket_factory.AddSSLSocketDataProvider(&ssl_provider1);

  SpdyTestUtil spdy_util1(/*use_priority_header=*/true);
  quiche::HttpHeaderBlock headers1(
      spdy_util1.ConstructGetHeaderBlock(kRedirectUrl));
  headers1["user-agent"] = "";
  headers1["accept-encoding"] = "gzip, deflate";
  spdy::SpdySerializedFrame req1(
      spdy_util1.ConstructSpdyHeaders(1, std::move(headers1), LOWEST, true));
  MockWrite writes1[] = {CreateMockWrite(req1, 0)};

  spdy::SpdySerializedFrame resp1(
      spdy_util1.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body1(spdy_util1.ConstructSpdyDataFrame(1, true));
  MockRead reads1[] = {CreateMockRead(resp1, 1), CreateMockRead(body1, 2),
                       MockRead(ASYNC, 0, 3)};

  SequencedSocketData data1(reads1, writes1);
  socket_factory.AddSocketDataProvider(&data1);

  TestDelegate delegate;

  std::unique_ptr<URLRequest> request = spdy_url_request_context->CreateRequest(
      default_url_, DEFAULT_PRIORITY, &delegate, TRAFFIC_ANNOTATION_FOR_TESTS);
  request->Start();
  delegate.RunUntilRedirect();

  EXPECT_EQ(1, delegate.received_redirect_count());

  request->FollowDeferredRedirect(std::nullopt /* removed_headers */,
                                  std::nullopt /* modified_headers */);
  delegate.RunUntilComplete();

  EXPECT_EQ(1, delegate.response_started_count());
  EXPECT_FALSE(delegate.received_data_before_response());
  EXPECT_THAT(delegate.request_status(), IsOk());
  EXPECT_EQ("hello!", delegate.data_received());

  // Pump the message loop to allow read data to be consumed.
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(data0.AllReadDataConsumed());
  EXPECT_TRUE(data0.AllWriteDataConsumed());
  EXPECT_TRUE(data1.AllReadDataConsumed());
  EXPECT_TRUE(data1.AllWriteDataConsumed());
}

TEST_P(SpdyNetworkTransactionTest, RedirectMultipleLocations) {
  const spdy::SpdyStreamId kStreamId = 1;
  // Construct the request and the RST frame.
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyGet(
      /*extra_headers=*/nullptr, /*extra_header_count=*/0, kStreamId, LOWEST));
  spdy::SpdySerializedFrame rst(spdy_util_.ConstructSpdyRstStream(
      kStreamId, spdy::ERROR_CODE_PROTOCOL_ERROR));
  MockWrite writes[] = {CreateMockWrite(req, 0), CreateMockWrite(rst, 4)};

  // Construct the response.
  const char* const kExtraResponseHeaders[] = {
      "location",
      "https://example1.test",
      "location",
      "https://example2.test",
  };
  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyReplyError(
      "301", kExtraResponseHeaders, std::size(kExtraResponseHeaders) / 2,
      kStreamId));
  spdy::SpdySerializedFrame body(
      spdy_util_.ConstructSpdyDataFrame(kStreamId, /*fin=*/true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, writes);
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_RESPONSE_HEADERS_MULTIPLE_LOCATION));
}

TEST_P(SpdyNetworkTransactionTest, NoConnectionPoolingOverTunnel) {
  // Use port 443 for two reasons:  This makes the endpoint is port 443 check in
  // NormalSpdyTransactionHelper pass, and this means that the tunnel uses the
  // same port as the servers, to further confuse things.
  const char kPacString[] = "PROXY myproxy:443";

  auto session_deps = std::make_unique<SpdySessionDependencies>(
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          kPacString, TRAFFIC_ANNOTATION_FOR_TESTS));
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                     std::move(session_deps));

  // Only one request uses the first connection.
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet("https://www.example.org", 1, LOWEST));
  MockWrite writes1[] = {
      MockWrite(ASYNC, 0,
                "CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
      CreateMockWrite(req1, 2),
  };

  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads1[] = {MockRead(ASYNC, 1, "HTTP/1.1 200 OK\r\n\r\n"),
                       CreateMockRead(resp1, 3), CreateMockRead(body1, 4),
                       MockRead(SYNCHRONOUS, ERR_IO_PENDING, 5)};

  MockConnect connect1(ASYNC, OK);
  SequencedSocketData data1(connect1, reads1, writes1);

  // Run a transaction to completion to set up a SPDY session.
  helper.RunToCompletion(&data1);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);

  // A new SPDY session should have been created.
  SpdySessionKey key1(
      HostPortPair("www.example.org", 443), PRIVACY_MODE_DISABLED,
      PacResultElementToProxyChain(kPacString), SessionUsage::kDestination,
      SocketTag(), NetworkAnony
```