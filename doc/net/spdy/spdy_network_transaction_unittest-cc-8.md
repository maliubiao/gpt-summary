Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Task:** The request asks for a functional summary of a specific C++ test file (`spdy_network_transaction_unittest.cc`) within the Chromium networking stack. It also asks to identify relationships with JavaScript, logical inferences (with input/output), common usage errors, debugging steps, and a general summary (since it's part 9 of 12).

2. **Initial Analysis of the Code Snippet:** The provided code snippet is a small part of the larger test file. It contains:
    * Mock data setup for network interactions using `MockRead` and `MockWrite`. These simulate network responses and requests.
    * Creation of SPDY/HTTP/2 frames using `spdy_util_`. This indicates the tests are specifically related to SPDY and HTTP/2 protocol handling.
    * Usage of `NormalSpdyTransactionHelper`, suggesting the tests are focused on the network transaction aspects of SPDY.
    * Assertions and expectations using `EXPECT_THAT`, `EXPECT_EQ`, etc., confirming this is indeed a testing file.
    * Specific test cases like handling stalled frames, receiving push promises, large headers, invalid header values, RST_STREAM frames, 100 Continue responses, early server responses, and handling unsupported frames (like ORIGIN).
    * Test cases related to TLS security requirements.
    * Test cases related to WebSockets, including the creation of new connections and the use of HTTP/2 for WebSockets.

3. **Infer the File's Purpose:** Based on the code, the file clearly tests the `SpdyNetworkTransaction` class. It simulates various network scenarios and verifies the correct behavior of the transaction when using the SPDY/HTTP/2 protocol.

4. **Address Specific Questions:**

    * **Functionality:**  List the various scenarios being tested. These become the key functionalities: handling different SPDY frame types, managing upload data, dealing with server push, handling large headers, error conditions, TLS requirements, and WebSocket interactions.

    * **Relationship with JavaScript:** Consider how network interactions relate to JavaScript in a browser context. JavaScript uses APIs like `fetch` or `XMLHttpRequest` to make network requests. The behavior tested in this C++ file directly impacts how those JavaScript APIs function when HTTP/2 is used. Provide examples of how a JavaScript request might trigger the code being tested (e.g., a large request, a request to a server that pushes resources, a WebSocket connection).

    * **Logical Inference (Input/Output):** Choose a simple test case from the snippet, like the "ReceivingPushIsConnectionError" test. Describe the simulated input (a PUSH_PROMISE frame) and the expected output (a GOAWAY frame and a specific error).

    * **Common Usage Errors:**  Think about what developers or users might do that could lead to the tested scenarios. Examples include misconfigured servers sending invalid frames, clients sending very large headers, or security configurations that don't meet HTTP/2 requirements.

    * **User Steps to Reach Here (Debugging):**  Trace back how a user action in the browser might lead to this code being executed. The path involves making a network request, the browser negotiating HTTP/2, and then the `SpdyNetworkTransaction` handling the communication. Emphasize debugging tools like network logs (`chrome://net-export/`) and potentially stepping through the C++ code.

    * **File Summary (Part 9 of 12):**  Since it's part 9 of a larger test suite,  summarize the specific focus of this file within the broader context. It seems to be concentrating on testing the core transaction logic of `SpdyNetworkTransaction`, covering many edge cases and error conditions.

5. **Structure the Answer:** Organize the information logically, addressing each part of the request clearly. Use bullet points or numbered lists for readability.

6. **Refine and Elaborate:** Review the answer to ensure clarity and accuracy. Add details or examples where necessary. For example, when discussing JavaScript, be specific about the APIs. When discussing user errors, provide concrete scenarios.

7. **Consider the "Part 9 of 12" Context:**  Since the prompt mentions this is part 9 of 12, I should emphasize that this file is likely focused on a *specific* aspect of the overall SPDY/HTTP/2 testing. The other parts probably cover different areas (session management, frame parsing, etc.).

By following these steps, I can construct a comprehensive and informative answer that addresses all aspects of the request. The key is to combine an understanding of the code snippet with knowledge of web networking concepts and how these components fit within the larger Chromium browser architecture.
这个文件 `net/spdy/spdy_network_transaction_unittest.cc` 是 Chromium 网络栈中专门用于测试 `SpdyNetworkTransaction` 类的单元测试文件。 `SpdyNetworkTransaction`  负责处理基于 SPDY (以及现在的 HTTP/2) 协议的网络事务 (transactions)。

**主要功能归纳:**

这个文件的主要功能是验证 `SpdyNetworkTransaction` 在各种网络场景下的正确行为。它通过模拟网络请求和响应，以及各种 SPDY/HTTP/2 帧的发送和接收，来测试以下方面：

1. **正常的请求/响应流程:** 测试基本的 GET 和 POST 请求的发送和接收，包括请求头、响应头和响应体。
2. **HTTP/2 特性测试:**
    * **流 (Streams) 的管理:** 测试创建、关闭和管理多个并发 SPDY 流的能力。
    * **头部压缩 (HPACK):**  虽然代码中没有直接体现 HPACK 的编码解码逻辑，但测试中构造和解析的头部块 (header blocks) 隐含了对 HPACK 的使用。
    * **流量控制 (Flow Control):**  测试发送窗口大小的控制，例如当接收到 `SETTINGS` 帧减小窗口大小时，发送行为的变化。
    * **服务器推送 (Push Promises):**  测试接收到 `PUSH_PROMISE` 帧时的行为，并验证是否会产生连接错误（因为客户端通常不应该在主动请求之外接收到 PUSH_PROMISE）。
    * **优先级 (Priority):** 测试请求的优先级设置是否能够正确地影响帧的发送顺序。
    * **SETTINGS 帧:**  测试处理 `SETTINGS` 帧的能力，包括更新会话参数，如初始窗口大小。
    * **WINDOW_UPDATE 帧:** 测试处理 `WINDOW_UPDATE` 帧以增加发送窗口大小的能力。
    * **RST_STREAM 帧:**  测试接收到 `RST_STREAM` 帧时的行为，包括不同的错误码。
    * **GOAWAY 帧:** 测试发送和接收 `GOAWAY` 帧以关闭连接。
3. **请求体处理:**
    * **分块上传 (Chunked Upload):** 测试处理分块上传请求的能力。
    * **上传数据量控制:** 测试在发送窗口受限的情况下，上传数据的发送行为。
4. **错误处理:** 测试在接收到各种错误帧或遇到网络错误时的行为，例如协议错误、连接错误等。
5. **大型头部和数据:** 测试处理大型请求头和响应头的情况。
6. **非标准或无效帧:** 测试忽略不支持的帧的能力 (例如 ORIGIN 帧)。
7. **TLS 安全要求:** 测试是否强制执行了 HTTP/2 的最低 TLS 版本和加密套件要求。
8. **100 Continue 响应:** 测试处理 100 Continue 中间响应的能力。
9. **早期响应:** 测试服务器在客户端发送完整请求之前发送响应的情况。
10. **WebSocket 支持 (如果启用):** 测试当发起 WebSocket 连接时，是否会建立新的 HTTP/1.1 连接，或者在支持的情况下，是否可以通过 HTTP/2 进行 WebSocket 连接。
11. **请求头回调:** 测试设置请求头回调函数并获取原始请求头信息。

**与 JavaScript 的关系及举例:**

虽然这个文件是 C++ 代码，它直接影响着 Chromium 中 JavaScript 发起的网络请求的行为。当 JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起一个 HTTPS 请求到支持 HTTP/2 的服务器时，最终会由 `SpdyNetworkTransaction` 来处理底层的 HTTP/2 通信。

**举例说明:**

* **JavaScript 发起一个大型 POST 请求:** 如果 JavaScript 代码上传大量数据，`SpdyNetworkTransaction` 需要正确地将这些数据分割成多个 `DATA` 帧，并根据流量控制进行发送。 代码中的 `TEST_P(SpdyNetworkTransactionTest, SendStalledPost)` 测试就模拟了这种情况，验证了在发送窗口受限时，上传操作会被暂停，直到接收到 `WINDOW_UPDATE` 帧。
* **JavaScript 请求一个资源，服务器启用了 HTTP/2 Push:**  虽然这个测试文件主要测试客户端行为，但服务器推送的逻辑涉及到客户端如何接收和处理 `PUSH_PROMISE` 帧。`TEST_P(SpdyNetworkTransactionTest, ReceivingPushIsConnectionError)` 测试验证了客户端在不期望的情况下收到 PUSH_PROMISE 会导致连接错误，这确保了客户端的安全性。
* **JavaScript 发起一个 WebSocket 连接:**  `TEST_P(SpdyNetworkTransactionTest, WebSocketOpensNewConnection)` 和 `TEST_P(SpdyNetworkTransactionTest, WebSocketOverHTTP2)` 测试了当 JavaScript 使用 `WebSocket` API 时，`SpdyNetworkTransaction` 如何处理，包括降级到 HTTP/1.1 或使用 HTTP/2 的 CONNECT 方法。
* **JavaScript 发起一个包含大量请求头的请求:** `TEST_P(SpdyNetworkTransactionTest, LargeRequest)` 测试了当 JavaScript 发送包含大量头部信息的请求时，`SpdyNetworkTransaction` 是否能够正确地将这些头部信息分割成多个 `HEADERS` 帧发送。

**逻辑推理 (假设输入与输出):**

以 `TEST_P(SpdyNetworkTransactionTest, ReceivingPushIsConnectionError)` 为例：

* **假设输入:**
    * 客户端发送了一个 HTTP/2 GET 请求 (模拟 `spdy_util_.ConstructSpdyGet(...)`).
    * 服务器在没有被请求的情况下，发送了一个 `PUSH_PROMISE` 帧 (模拟 `spdy_util_.ConstructSpdyPushPromise(...)`).
* **预期输出:**
    * 客户端检测到非法的服务器推送行为。
    * 客户端发送一个 `GOAWAY` 帧，关闭连接，错误码为 `PROTOCOL_ERROR`，并附带描述 "PUSH_PROMISE received" (模拟 `spdy_util_.ConstructSpdyGoAway(...)`).
    * 测试断言事务返回的错误码是 `ERR_HTTP2_PROTOCOL_ERROR`.

**用户或编程常见的使用错误及举例:**

这个测试文件主要关注底层协议的实现，直接的用户操作不太可能直接触发这里的代码，除非用户使用了不兼容 HTTP/2 的代理或网络环境。 常见的编程错误可能涉及到服务器端的实现：

* **服务器错误地发送 PUSH_PROMISE:**  如果服务器在没有收到客户端请求的情况下发送了 `PUSH_PROMISE`，客户端的 `SpdyNetworkTransaction` 会根据协议规范关闭连接。
* **服务器发送过大的头部或数据帧:**  如果服务器发送的帧超过了客户端声明的限制，可能会导致连接错误。虽然这个文件没有直接测试发送过大帧的情况，但相关的限制是在 `SpdySession` 等其他组件中处理的。
* **服务器未正确处理流量控制:** 如果服务器没有遵守客户端的流量控制，可能会导致数据发送过多或过快，虽然这不是 `SpdyNetworkTransaction` 主要负责的，但流量控制的交互会影响事务的完成。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在 Chrome 浏览器中访问一个 HTTPS 网站:**  浏览器会尝试与服务器协商使用 HTTP/2 协议。
2. **HTTP/2 协商成功:**  后续的网络请求将通过 HTTP/2 连接发送和接收。
3. **浏览器发起一个网络请求 (例如通过点击链接或 JavaScript 代码):**  `HttpNetworkTransaction` (或者其子类 `SpdyNetworkTransaction`) 会被创建来处理这个请求。
4. **`SpdyNetworkTransaction` 从 Socket 读取数据或向 Socket 写入数据:** 这时就会涉及到对 SPDY/HTTP/2 帧的解析和构建。
5. **如果服务器的行为不符合 HTTP/2 规范 (例如发送了不期望的 PUSH_PROMISE):**  `SpdyNetworkTransaction` 中的代码会检测到这个错误。
6. **在调试时，开发者可以使用 Chrome 的 `chrome://net-export/` 功能记录网络日志:**  这个日志会包含详细的 SPDY 帧信息，可以帮助开发者理解发生了什么错误。
7. **开发者也可以使用 C++ 调试器 (例如 gdb 或 lldb) 来单步调试 `SpdyNetworkTransaction` 的代码:**  设置断点在 `spdy_network_transaction_unittest.cc` 中测试的代码路径上，可以观察变量的值和程序的执行流程，从而定位问题。

**作为第 9 部分，共 12 部分，它的功能归纳:**

考虑到这是测试套件的第 9 部分，很可能前面的部分已经测试了 SPDY 协议的更基础的方面，例如帧的编码解码、会话管理等。  第 9 部分 `spdy_network_transaction_unittest.cc`  更侧重于 **测试基于 SPDY 协议的网络事务 (transactions) 的完整生命周期和各种交互场景**。它验证了 `SpdyNetworkTransaction` 作为网络请求的核心处理类，在各种正常和异常情况下的行为是否符合预期。这部分测试可能依赖于前面部分测试通过的更底层的 SPDY 功能。  接下来的部分可能专注于更高级的特性或与其他网络组件的集成测试。

### 提示词
```
这是目录为net/spdy/spdy_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
kBufferSize % kMaxSpdyFrameChunkSize != 0) {
        writes.push_back(CreateMockWrite(body2, i++));
      } else {
        writes.push_back(CreateMockWrite(body1, i++));
      }
    }
  }

  // Fill in mock reads.
  std::vector<MockRead> reads;
  // Force a pause.
  reads.emplace_back(ASYNC, ERR_IO_PENDING, i++);
  // Construct read frame for SETTINGS that makes the send_window_size
  // negative.
  spdy::SettingsMap new_settings;
  new_settings[spdy::SETTINGS_INITIAL_WINDOW_SIZE] = initial_window_size / 2;
  spdy::SpdySerializedFrame settings_frame_small(
      spdy_util_.ConstructSpdySettings(new_settings));
  // Construct read frames for WINDOW_UPDATE that makes the send_window_size
  // positive.
  spdy::SpdySerializedFrame session_window_update_init_size(
      spdy_util_.ConstructSpdyWindowUpdate(0, initial_window_size));
  spdy::SpdySerializedFrame window_update_init_size(
      spdy_util_.ConstructSpdyWindowUpdate(1, initial_window_size));

  reads.push_back(CreateMockRead(settings_frame_small, i++));
  reads.push_back(CreateMockRead(session_window_update_init_size, i++));
  reads.push_back(CreateMockRead(window_update_init_size, i++));

  spdy::SpdySerializedFrame settings_ack(spdy_util_.ConstructSpdySettingsAck());
  writes.push_back(CreateMockWrite(settings_ack, i++));

  // Stalled frames which can be sent after |settings_ack|.
  if (last_body.size() > 0) {
    writes.push_back(CreateMockWrite(body4, i++));
  }
  writes.push_back(CreateMockWrite(body5, i++));

  spdy::SpdySerializedFrame reply(
      spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  reads.push_back(CreateMockRead(reply, i++));
  reads.push_back(CreateMockRead(body2, i++));
  reads.push_back(CreateMockRead(body5, i++));
  reads.emplace_back(ASYNC, 0, i++);  // EOF

  // Force all writes to happen before any read, last write will not
  // actually queue a frame, due to window size being 0.
  SequencedSocketData data(reads, writes);

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  std::string upload_data_string(kBufferSize * num_upload_buffers, 'a');
  upload_data_string.append(kUploadData, kUploadDataSize);
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::as_byte_span(upload_data_string)));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  request_.method = "POST";
  request_.upload_data_stream = &upload_data_stream;
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);

  helper.RunPreTestSetup();
  helper.AddData(&data);

  HttpNetworkTransaction* trans = helper.trans();

  TestCompletionCallback callback;
  int rv = trans->Start(&request_, callback.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  data.RunUntilPaused();  // Write as much as we can.
  base::RunLoop().RunUntilIdle();

  SpdyHttpStream* stream = static_cast<SpdyHttpStream*>(trans->stream_.get());
  ASSERT_TRUE(stream);
  ASSERT_TRUE(stream->stream());
  EXPECT_EQ(0, stream->stream()->send_window_size());

  if (initial_window_size % kBufferSize != 0) {
    // If it does not take whole number of full upload buffer to zero out
    // initial window size, then the upload data is not at EOF, because the
    // last read must be stalled.
    EXPECT_FALSE(upload_data_stream.IsEOF());
  } else {
    // All the body data should have been read.
    // TODO(satorux): This is because of the weirdness in reading the request
    // body in OnSendBodyComplete(). See crbug.com/113107.
    EXPECT_TRUE(upload_data_stream.IsEOF());
  }

  // Read in WINDOW_UPDATE or SETTINGS frame.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  rv = callback.WaitForResult();
  helper.VerifyDataConsumed();
}

TEST_P(SpdyNetworkTransactionTest, ReceivingPushIsConnectionError) {
  quiche::HttpHeaderBlock push_headers;
  spdy_util_.AddUrlToHeaderBlock("http://www.example.org/a.dat", &push_headers);
  spdy::SpdySerializedFrame push(
      spdy_util_.ConstructSpdyPushPromise(1, 2, std::move(push_headers)));
  MockRead reads[] = {CreateMockRead(push, 1)};

  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      0, spdy::ERROR_CODE_PROTOCOL_ERROR, "PUSH_PROMISE received"));
  MockWrite writes[] = {CreateMockWrite(req, 0), CreateMockWrite(goaway, 2)};

  SequencedSocketData data(reads, writes);

  auto session_deps = std::make_unique<SpdySessionDependencies>();
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                     std::move(session_deps));
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_HTTP2_PROTOCOL_ERROR));
}

// Push streams must have even stream IDs. Test that an incoming push stream
// with odd ID is reset the same way as one with even ID.
TEST_P(SpdyNetworkTransactionTest,
       ReceivingPushWithOddStreamIdIsConnectionError) {
  quiche::HttpHeaderBlock push_headers;
  spdy_util_.AddUrlToHeaderBlock("http://www.example.org/a.dat", &push_headers);
  spdy::SpdySerializedFrame push(
      spdy_util_.ConstructSpdyPushPromise(1, 3, std::move(push_headers)));
  MockRead reads[] = {CreateMockRead(push, 1)};

  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      0, spdy::ERROR_CODE_PROTOCOL_ERROR, "PUSH_PROMISE received"));
  MockWrite writes[] = {CreateMockWrite(req, 0), CreateMockWrite(goaway, 2)};

  SequencedSocketData data(reads, writes);

  auto session_deps = std::make_unique<SpdySessionDependencies>();
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                     std::move(session_deps));
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_HTTP2_PROTOCOL_ERROR));
}

// Regression test for https://crbug.com/493348: request header exceeds 16 kB
// and thus sent in multiple frames when using HTTP/2.
TEST_P(SpdyNetworkTransactionTest, LargeRequest) {
  const std::string kKey("foo");
  const std::string kValue(1 << 15, 'z');

  request_.extra_headers.SetHeader(kKey, kValue);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  headers[kKey] = kValue;
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyHeaders(1, std::move(headers), LOWEST, true));
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
  EXPECT_EQ("hello!", out.response_data);
}

// Regression test for https://crbug.com/535629: response header exceeds 16 kB.
TEST_P(SpdyNetworkTransactionTest, LargeResponseHeader) {
  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyHeaders(1, std::move(headers), LOWEST, true));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  // HPACK decoder implementation limits string literal length to 16 kB.
  const char* response_headers[2];
  const std::string kKey(16 * 1024, 'a');
  response_headers[0] = kKey.data();
  const std::string kValue(16 * 1024, 'b');
  response_headers[1] = kValue.data();

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(response_headers, 1, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);

  SequencedSocketData data(reads, writes);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();

  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
  ASSERT_TRUE(out.response_info.headers->HasHeaderValue(kKey, kValue));
}

// End of line delimiter is forbidden according to RFC 7230 Section 3.2.
TEST_P(SpdyNetworkTransactionTest, CRLFInHeaderValue) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_PROTOCOL_ERROR));
  MockWrite writes[] = {CreateMockWrite(req, 0), CreateMockWrite(rst, 2)};

  const char* response_headers[] = {"folded", "foo\r\nbar"};
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(response_headers, 1, 1));
  MockRead reads[] = {CreateMockRead(resp, 1), MockRead(ASYNC, 0, 3)};

  SequencedSocketData data(reads, writes);

  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();

  EXPECT_THAT(out.rv, IsError(ERR_HTTP2_PROTOCOL_ERROR));
}

// Regression test for https://crbug.com/603182.
// No response headers received before RST_STREAM: error.
TEST_P(SpdyNetworkTransactionTest, RstStreamNoError) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructChunkedSpdyPost(nullptr, 0));
  MockWrite writes[] = {CreateMockWrite(req, 0, ASYNC)};

  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_NO_ERROR));
  MockRead reads[] = {CreateMockRead(rst, 1), MockRead(ASYNC, 0, 2)};

  SequencedSocketData data(reads, writes);
  UseChunkedPostRequest();
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_HTTP2_PROTOCOL_ERROR));
}

// Regression test for https://crbug.com/603182.
// Response headers and data, then RST_STREAM received,
// before request body is sent: success.
TEST_P(SpdyNetworkTransactionTest, RstStreamNoErrorAfterResponse) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructChunkedSpdyPost(nullptr, 0));
  MockWrite writes[] = {CreateMockWrite(req, 0, ASYNC)};

  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_NO_ERROR));
  MockRead reads[] = {CreateMockRead(resp, 1), CreateMockRead(body, 2),
                      CreateMockRead(rst, 3), MockRead(ASYNC, 0, 4)};

  SequencedSocketData data(reads, writes);
  UseChunkedPostRequest();
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
}

TEST_P(SpdyNetworkTransactionTest, 100Continue) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  quiche::HttpHeaderBlock informational_headers;
  informational_headers[spdy::kHttp2StatusHeader] = "100";
  spdy::SpdySerializedFrame informational_response(
      spdy_util_.ConstructSpdyReply(1, std::move(informational_headers)));
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(informational_response, 1), CreateMockRead(resp, 2),
      CreateMockRead(body, 3), MockRead(ASYNC, 0, 4)  // EOF
  };

  SequencedSocketData data(reads, writes);
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
}

// "A server can send a complete response prior to the client sending an entire
// request if the response does not depend on any portion of the request that
// has not been sent and received."  (RFC7540 Section 8.1)
// Regression test for https://crbug.com/606990.  Server responds before POST
// data are sent and closes connection: this must result in
// ERR_CONNECTION_CLOSED (as opposed to ERR_HTTP2_PROTOCOL_ERROR).
TEST_P(SpdyNetworkTransactionTest, ResponseBeforePostDataSent) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructChunkedSpdyPost(nullptr, 0));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {CreateMockRead(resp, 1), CreateMockRead(body, 2),
                      MockRead(ASYNC, 0, 3)};

  SequencedSocketData data(reads, writes);
  UseChunkedPostRequest();
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);

  helper.RunPreTestSetup();
  helper.AddData(&data);
  helper.StartDefaultTest();
  EXPECT_THAT(helper.output().rv, IsError(ERR_IO_PENDING));
  helper.WaitForCallbackToComplete();
  EXPECT_THAT(helper.output().rv, IsError(ERR_CONNECTION_CLOSED));
}

// Regression test for https://crbug.com/606990.
// Server responds before POST data are sent and resets stream with NO_ERROR.
TEST_P(SpdyNetworkTransactionTest, ResponseAndRstStreamBeforePostDataSent) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructChunkedSpdyPost(nullptr, 0));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyPostReply(nullptr, 0));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_NO_ERROR));
  MockRead reads[] = {CreateMockRead(resp, 1), CreateMockRead(body, 2),
                      CreateMockRead(rst, 3), MockRead(ASYNC, 0, 4)};

  SequencedSocketData data(reads, writes);
  UseChunkedPostRequest();
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);

  helper.RunToCompletion(&data);

  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
}

// Unsupported frames must be ignored.  This is especially important for frame
// type 0xb, which used to be the BLOCKED frame in previous versions of SPDY,
// but is going to be used for the ORIGIN frame.
// TODO(bnc): Implement ORIGIN frame support.  https://crbug.com/697333
TEST_P(SpdyNetworkTransactionTest, IgnoreUnsupportedOriginFrame) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  const char origin_frame_on_stream_zero[] = {
      0x00, 0x00, 0x05,        // Length
      0x0b,                    // Type
      0x00,                    // Flags
      0x00, 0x00, 0x00, 0x00,  // Stream ID
      0x00, 0x03,              // Origin-Len
      'f',  'o',  'o'          // ASCII-Origin
  };

  const char origin_frame_on_stream_one[] = {
      0x00, 0x00, 0x05,        // Length
      0x0b,                    // Type
      0x00,                    // Flags
      0x00, 0x00, 0x00, 0x01,  // Stream ID
      0x00, 0x03,              // Origin-Len
      'b',  'a',  'r'          // ASCII-Origin
  };

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {MockRead(ASYNC, origin_frame_on_stream_zero,
                               std::size(origin_frame_on_stream_zero), 1),
                      CreateMockRead(resp, 2),
                      MockRead(ASYNC, origin_frame_on_stream_one,
                               std::size(origin_frame_on_stream_one), 3),
                      CreateMockRead(body, 4), MockRead(ASYNC, 0, 5)};

  SequencedSocketData data(reads, writes);
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
}

class SpdyNetworkTransactionTLSUsageCheckTest
    : public SpdyNetworkTransactionTest {
 protected:
  void RunTLSUsageCheckTest(
      std::unique_ptr<SSLSocketDataProvider> ssl_provider) {
    spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
        0, spdy::ERROR_CODE_INADEQUATE_SECURITY, ""));
    MockWrite writes[] = {CreateMockWrite(goaway)};

    StaticSocketDataProvider data(base::span<MockRead>(), writes);
    NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                       nullptr);
    helper.RunToCompletionWithSSLData(&data, std::move(ssl_provider));
    TransactionHelperResult out = helper.output();
    EXPECT_THAT(out.rv, IsError(ERR_HTTP2_INADEQUATE_TRANSPORT_SECURITY));
  }
};

INSTANTIATE_TEST_SUITE_P(All,
                         SpdyNetworkTransactionTLSUsageCheckTest,
                         testing::ValuesIn(GetTestParams()));

TEST_P(SpdyNetworkTransactionTLSUsageCheckTest, TLSVersionTooOld) {
  auto ssl_provider = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  SSLConnectionStatusSetVersion(SSL_CONNECTION_VERSION_SSL3,
                                &ssl_provider->ssl_info.connection_status);

  RunTLSUsageCheckTest(std::move(ssl_provider));
}

TEST_P(SpdyNetworkTransactionTLSUsageCheckTest, TLSCipherSuiteSucky) {
  auto ssl_provider = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  // Set to TLS_RSA_WITH_NULL_MD5
  SSLConnectionStatusSetCipherSuite(0x1,
                                    &ssl_provider->ssl_info.connection_status);

  RunTLSUsageCheckTest(std::move(ssl_provider));
}

// Regression test for https://crbug.com/737143.
// This test sets up an old TLS version just like in TLSVersionTooOld,
// and makes sure that it results in an spdy::ERROR_CODE_INADEQUATE_SECURITY
// even for a non-secure request URL.
TEST_P(SpdyNetworkTransactionTest, InsecureUrlCreatesSecureSpdySession) {
  auto ssl_provider = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  SSLConnectionStatusSetVersion(SSL_CONNECTION_VERSION_SSL3,
                                &ssl_provider->ssl_info.connection_status);

  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      0, spdy::ERROR_CODE_INADEQUATE_SECURITY, ""));
  MockWrite writes[] = {CreateMockWrite(goaway)};
  StaticSocketDataProvider data(base::span<MockRead>(), writes);

  request_.url = GURL("http://www.example.org/");

  // Need secure proxy so that insecure URL can use HTTP/2.
  auto session_deps = std::make_unique<SpdySessionDependencies>(
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "HTTPS myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS));
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                     std::move(session_deps));

  helper.RunToCompletionWithSSLData(&data, std::move(ssl_provider));
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_HTTP2_INADEQUATE_TRANSPORT_SECURITY));
}

TEST_P(SpdyNetworkTransactionTest, RequestHeadersCallback) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, DEFAULT_PRIORITY));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  HttpRawRequestHeaders raw_headers;

  SequencedSocketData data(reads, writes);
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  helper.trans()->SetRequestHeadersCallback(base::BindRepeating(
      &HttpRawRequestHeaders::Assign, base::Unretained(&raw_headers)));
  helper.StartDefaultTest();
  helper.FinishDefaultTestWithoutVerification();
  EXPECT_FALSE(raw_headers.headers().empty());
  std::string value;
  EXPECT_TRUE(raw_headers.FindHeaderForTest(":path", &value));
  EXPECT_EQ("/", value);
  EXPECT_TRUE(raw_headers.FindHeaderForTest(":method", &value));
  EXPECT_EQ("GET", value);
  EXPECT_TRUE(raw_headers.request_line().empty());
}

#if BUILDFLAG(ENABLE_WEBSOCKETS)

TEST_P(SpdyNetworkTransactionTest, WebSocketOpensNewConnection) {
  base::HistogramTester histogram_tester;
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();

  // First request opens up an HTTP/2 connection.
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, DEFAULT_PRIORITY));
  MockWrite writes1[] = {CreateMockWrite(req, 0)};

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads1[] = {CreateMockRead(resp, 1), CreateMockRead(body, 2),
                       MockRead(ASYNC, ERR_IO_PENDING, 3),
                       MockRead(ASYNC, 0, 4)};

  SequencedSocketData data1(reads1, writes1);
  helper.AddData(&data1);

  // WebSocket request opens a new connection with HTTP/2 disabled.
  MockWrite writes2[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: Upgrade\r\n"
                "Upgrade: websocket\r\n"
                "Origin: http://www.example.org\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Extensions: permessage-deflate; "
                "client_max_window_bits\r\n\r\n")};

  MockRead reads2[] = {
      MockRead("HTTP/1.1 101 Switching Protocols\r\n"
               "Upgrade: websocket\r\n"
               "Connection: Upgrade\r\n"
               "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")};

  StaticSocketDataProvider data2(reads2, writes2);

  auto ssl_provider2 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  // Test that the request has HTTP/2 disabled.
  ssl_provider2->next_protos_expected_in_ssl_config = {kProtoHTTP11};
  // Force socket to use HTTP/1.1, the default protocol without ALPN.
  ssl_provider2->next_proto = kProtoHTTP11;
  ssl_provider2->ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  helper.AddDataWithSSLSocketDataProvider(&data2, std::move(ssl_provider2));

  TestCompletionCallback callback1;
  HttpNetworkTransaction trans1(DEFAULT_PRIORITY, helper.session());
  int rv = trans1.Start(&request_, callback1.callback(), log_);
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback1.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  const HttpResponseInfo* response = trans1.GetResponseInfo();
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());

  std::string response_data;
  rv = ReadTransaction(&trans1, &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello!", response_data);

  SpdySessionKey key(HostPortPair::FromURL(request_.url), PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(), SessionUsage::kDestination,
                     SocketTag(), NetworkAnonymizationKey(),
                     SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/false);
  base::WeakPtr<SpdySession> spdy_session =
      helper.session()->spdy_session_pool()->FindAvailableSession(
          key, /* enable_ip_based_pooling = */ true,
          /* is_websocket = */ false, log_);
  ASSERT_TRUE(spdy_session);
  EXPECT_FALSE(spdy_session->support_websocket());

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("wss://www.example.org/");
  request2.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_TRUE(HostPortPair::FromURL(request_.url)
                  .Equals(HostPortPair::FromURL(request2.url)));
  request2.extra_headers.SetHeader("Connection", "Upgrade");
  request2.extra_headers.SetHeader("Upgrade", "websocket");
  request2.extra_headers.SetHeader("Origin", "http://www.example.org");
  request2.extra_headers.SetHeader("Sec-WebSocket-Version", "13");

  TestWebSocketHandshakeStreamCreateHelper websocket_stream_create_helper;

  HttpNetworkTransaction trans2(DEFAULT_PRIORITY, helper.session());
  trans2.SetWebSocketHandshakeStreamCreateHelper(
      &websocket_stream_create_helper);

  TestCompletionCallback callback2;
  rv = trans2.Start(&request2, callback2.callback(), log_);
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = callback2.WaitForResult();
  ASSERT_THAT(rv, IsOk());

  // HTTP/2 connection is still open, but WebSocket request did not pool to it.
  ASSERT_TRUE(spdy_session);

  data1.Resume();
  base::RunLoop().RunUntilIdle();
  helper.VerifyDataConsumed();

  // Server did not advertise WebSocket support.
  histogram_tester.ExpectUniqueSample("Net.SpdySession.ServerSupportsWebSocket",
                                      /* support_websocket = false */ 0,
                                      /* expected_count = */ 1);
}

// Make sure that a WebSocket job doesn't pick up a newly created SpdySession
// that doesn't support WebSockets through
// HttpStreamFactory::Job::OnSpdySessionAvailable().
TEST_P(SpdyNetworkTransactionTest,
       WebSocketDoesUseNewH2SessionWithoutWebSocketSupport) {
  base::HistogramTester histogram_tester;
  auto session_deps = std::make_unique<SpdySessionDependencies>();
  NormalSpdyTransactionHelper helper(request_, HIGHEST, log_,
                                     std::move(session_deps));
  helper.RunPreTestSetup();

  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, HIGHEST));

  MockWrite writes[] = {CreateMockWrite(req, 0)};

  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body1(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {CreateMockRead(resp1, 1), CreateMockRead(body1, 2),
                      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 3)};

  SequencedSocketData data(
      // Just as with other operations, this means to pause during connection
      // establishment.
      MockConnect(ASYNC, ERR_IO_PENDING), reads, writes);
  helper.AddData(&data);

  MockWrite writes2[] = {
      MockWrite(SYNCHRONOUS, 0,
                "GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: Upgrade\r\n"
                "Upgrade: websocket\r\n"
                "Origin: http://www.example.org\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Extensions: permessage-deflate; "
                "client_max_window_bits\r\n\r\n")};

  MockRead reads2[] = {
      MockRead(SYNCHRONOUS, 1,
               "HTTP/1.1 101 Switching Protocols\r\n"
               "Upgrade: websocket\r\n"
               "Connection: Upgrade\r\n"
               "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")};
  SequencedSocketData data2(MockConnect(ASYNC, ERR_IO_PENDING), reads2,
                            writes2);
  auto ssl_provider2 = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
  // Test that the request has HTTP/2 disabled.
  ssl_provider2->next_protos_expected_in_ssl_config = {kProtoHTTP11};
  // Force socket to use HTTP/1.1, the default protocol without ALPN.
  ssl_provider2->next_proto = kProtoHTTP11;
  helper.AddDataWithSSLSocketDataProvider(&data2, std::move(ssl_provider2));

  TestCompletionCallback callback1;
  int rv = helper.trans()->Start(&request_, callback1.callback(), log_);
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  // Create HTTP/2 connection.
  base::RunLoop().RunUntilIdle();

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("wss://www.example.org/");
  request2.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_TRUE(HostPortPair::FromURL(request_.url)
                  .Equals(HostPortPair::FromURL(request2.url)));
  request2.extra_headers.SetHeader("Connection", "Upgrade");
  request2.extra_headers.SetHeader("Upgrade", "websocket");
  request2.extra_headers.SetHeader("Origin", "http://www.example.org");
  request2.extra_headers.SetHeader("Sec-WebSocket-Version", "13");

  TestWebSocketHandshakeStreamCreateHelper websocket_stream_create_helper;

  HttpNetworkTransaction trans2(MEDIUM, helper.session());
  trans2.SetWebSocketHandshakeStreamCreateHelper(
      &websocket_stream_create_helper);

  TestCompletionCallback callback2;
  rv = trans2.Start(&request2, callback2.callback(), log_);
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  // Run until waiting on both connections.
  base::RunLoop().RunUntilIdle();

  // The H2 connection completes.
  data.socket()->OnConnectComplete(MockConnect(SYNCHRONOUS, OK));
  EXPECT_EQ(OK, callback1.WaitForResult());
  const HttpResponseInfo* response = helper.trans()->GetResponseInfo();
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  std::string response_data;
  rv = ReadTransaction(helper.trans(), &response_data);
  EXPECT_THAT(rv, IsOk());
  EXPECT_EQ("hello!", response_data);

  SpdySessionKey key(HostPortPair::FromURL(request_.url), PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(), SessionUsage::kDestination,
                     SocketTag(), NetworkAnonymizationKey(),
                     SecureDnsPolicy::kAllow,
                     /*disable_cert_verification_network_fetches=*/false);

  base::WeakPtr<SpdySession> spdy_session =
      helper.session()->spdy_session_pool()->FindAvailableSession(
          key, /* enable_ip_based_pooling = */ true,
          /* is_websocket = */ false, log_);
  ASSERT_TRUE(spdy_session);
  EXPECT_FALSE(spdy_session->support_websocket());

  EXPECT_FALSE(callback2.have_result());

  // Create WebSocket stream.
  data2.socket()->OnConnectComplete(MockConnect(SYNCHRONOUS, OK));

  rv = callback2.WaitForResult();
  ASSERT_THAT(rv, IsOk());
  helper.VerifyDataConsumed();
}

TEST_P(SpdyNetworkTransactionTest, WebSocketOverHTTP2) {
  base::HistogramTester histogram_tester;
  auto session_deps = std::make_unique<SpdySessionDependencies>();
  NormalSpdyTransactionHelper helper(request_, HIGHEST, log_,
                                     std::move(session_deps));
  helper.RunPreTestSetup();

  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, HIGHEST));
  spdy::SpdySerializedFrame settings_ack(spdy_util_.ConstructSpdySettingsAck());

  quiche::HttpHeaderBlock websocket_request_headers;
  websocket_request_headers[spdy::kHttp2MethodHeader] = "CONNECT";
  websocket_request_headers[spdy::kHttp2AuthorityHeader] = "www.example.org";
  websocket_request_headers[spdy::kHttp2SchemeHeader] = "https";
  websocket_request_headers[spdy::kHttp2PathHeader] = "/";
  websocket_request_headers[spdy::kHttp2ProtocolHeader] = "websocket";
  websocket_request_headers["origin"] = "http://www.example.org";
  websocket_request_headers["sec-websocket-version"] = "13";
  websocket_request_headers["sec-websocket-extensions"] =
      "permessage-deflate; client_max_window_bits";
  spdy::SpdySerializedFrame websocket_request(spdy_util_.ConstructSpdyHeaders(
      3, std::move(websocket_request_headers), MEDIUM, false));

  spdy::SpdySerializedFrame priority1(
      spdy_util_.ConstructSpdyPriority(3, 0, MEDIUM, true));
  spdy::SpdySerializedFrame priority2(
      spdy_util_.ConstructSpdyPriority(1, 3, LOWEST, true));

  MockWrite writes[] = {
      CreateMockWrite(req, 0), CreateMockWrite(settings_ack, 2),
      CreateMockWrite(websocket_request, 4), Cr
```