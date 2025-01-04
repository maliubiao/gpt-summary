Response:
The user wants a summary of the provided C++ code snippet from `spdy_network_transaction_unittest.cc`. They are interested in the functionality, potential connections to JavaScript, logical reasoning with input/output examples, common usage errors, debugging guidance, and a concise overall summary (as it's part 5 of 12).

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Purpose:** The filename and the test names within the snippet clearly indicate this is a unit test file for `SpdyNetworkTransaction`. The primary function is to test various aspects of how the Chromium network stack handles SPDY/HTTP2 transactions.

2. **Analyze Individual Test Cases:** Go through each `TEST_P` or standalone test function and understand its specific goal.
    * The initial part with `socket_tag` tests session reuse and socket tagging.
    * `ResponseHeaders` verifies correct parsing of response headers, including handling of comma-separated values and multiple occurrences of the same header.
    * `InvalidResponseHeaders` checks how the system handles malformed headers, expecting a protocol error.
    * `CorruptFrameSessionError`, `GoAwayOnDecompressionFailure`, and `GoAwayOnFrameSizeError` focus on how the system reacts to different types of errors in the SPDY frame structure, triggering a GOAWAY frame.
    * `WriteError` tests the robustness of the transaction when encountering write failures.
    * `PartialWrite` checks if the system can handle fragmented writes of the request.
    * `NetLog` and `NetLogForResponseWithNoBody` verify that the network logging mechanism captures the correct events and data during SPDY communication.
    * The remaining tests (`BufferFull`, `Buffering`, `BufferedAll`, `BufferedClosed`, `BufferedCancelled`) explore different scenarios related to data buffering during SPDY transactions, including partial reads, multiple data frames, and handling connection closure or cancellation.

3. **Look for JavaScript Connections:**  Consider how these low-level network interactions might relate to JavaScript. JavaScript in a browser uses network APIs (like `fetch` or `XMLHttpRequest`) that ultimately rely on the underlying network stack. SPDY/HTTP2 optimizations would be transparent to the JavaScript developer but influence performance. Specifically, header handling, buffering, and error handling are relevant.

4. **Infer Logical Reasoning and Examples:**  For each test, imagine the intended input and the expected output.
    *  For `socket_tag`, the input is multiple requests with different socket tags and the output is the confirmation of session reuse with the correct tagging.
    * For `ResponseHeaders`, the input is different sets of headers, and the output is the verification of parsed header names and values.
    * For error scenarios, the input is a malformed frame, and the output is the expected error code or GOAWAY frame.

5. **Identify Potential User/Programming Errors:** Think about how developers using the network stack (though usually indirectly via higher-level APIs) might encounter issues that these tests are designed to prevent or handle. Incorrect header formatting or assumptions about data delivery could be examples.

6. **Trace User Actions (Debugging Clues):**  Consider how a user action in a browser could lead to this code being executed. A simple navigation to an HTTPS website using HTTP/2 is the most direct path. Consider scenarios where network conditions are poor or server responses are malformed.

7. **Synthesize the Overall Function:** Combine the understanding of individual tests into a concise summary of the file's purpose. Emphasize its role in verifying the correctness and robustness of the `SpdyNetworkTransaction`.

8. **Address the "Part 5 of 12" Instruction:**  Acknowledge this context and ensure the summary reflects that this is one piece of a larger testing suite.

9. **Structure the Response:** Organize the findings into the requested categories (Functionality, JavaScript Relationship, Logical Reasoning, User Errors, User Actions, Summary). Use clear and concise language.

10. **Review and Refine:**  Read through the generated response to ensure accuracy, completeness, and clarity. Check for any misunderstandings or areas that could be explained better. For instance, initially, I might have just said "tests SPDY," but refining it to specify testing of the `SpdyNetworkTransaction` and its various behaviors is more precise. Also, making the JavaScript connection more concrete with examples of header handling or error reporting improves the response.
这是 `net/spdy/spdy_network_transaction_unittest.cc` 文件的第 5 部分，主要功能是 **进一步测试 `SpdyNetworkTransaction` 类在处理各种 SPDY 协议交互时的行为，特别是关注连接的重用、响应头部的解析、错误处理、数据传输的缓冲机制以及网络日志记录。**

以下是针对您要求的详细分析：

**1. 功能列举:**

这部分代码主要测试了 `SpdyNetworkTransaction` 的以下功能：

* **Socket Tagging 和 Session 重用:** 验证当请求具有不同的 Socket Tag 时，是否会正确地重用已存在的 SPDY Session，并更新 Session 的关联信息（DNS 别名）。
* **响应头部的解析:**  测试 `SpdyNetworkTransaction` 是否能正确解析各种格式的 SPDY 响应头部，包括逗号分隔的值、重复的头部字段等。
* **无效响应头部的处理:** 验证当接收到格式错误的 SPDY 响应头部时，`SpdyNetworkTransaction` 是否能正确地检测到错误并终止连接。
* **SPDY 帧错误的连接级别处理:** 测试当接收到格式错误的 SPDY 帧（例如长度错误、压缩错误、帧大小错误）时，是否会发送 GOAWAY 帧并关闭连接。
* **写错误处理:**  验证在发送 SPDY 帧时发生写错误的情况下，`SpdyNetworkTransaction` 能否正确关闭连接。
* **部分写操作:** 测试当请求头部被分成多个部分写入时，`SpdyNetworkTransaction` 是否能够正常工作。
* **网络日志记录:**  验证 `SpdyNetworkTransaction` 在处理请求和响应时，是否会将关键事件和数据记录到 NetLog 中，方便调试。这包括请求头部、响应头部、数据帧等。
* **数据缓冲机制:** 测试 `SpdyNetworkTransaction` 的数据缓冲功能，包括：
    * 当接收到的数据多于读取请求时，数据是否会被正确缓冲。
    * 当接收到多个数据帧时，是否会合并缓冲，而不是每次都触发读取回调。
    * 当所有数据都被缓冲后，读取操作是否能立即完成。
    * 连接关闭但仍有缓冲数据时的处理。
    * 事务被取消但仍有缓冲数据时的处理。

**2. 与 JavaScript 的关系及举例说明:**

`SpdyNetworkTransaction` 是 Chromium 网络栈的底层组件，直接与 JavaScript 没有代码级别的交互。然而，它的行为直接影响到 JavaScript 发起的网络请求的性能和可靠性。

* **性能优化 (Session 重用):** JavaScript 使用 `fetch` API 或 `XMLHttpRequest` 发起多个到同一域名的 HTTPS 请求时，如果 `SpdyNetworkTransaction` 能够正确地重用 SPDY Session，则可以避免重复的 TLS 握手，从而加速页面加载速度。
    * **举例:**  一个网页加载了多个来自同一 CDN 的图片。如果 SPDY Session 重用工作正常，浏览器只需要建立一次连接，所有图片请求都能复用这个连接，减少延迟。
* **错误处理 (Invalid Response Headers, Frame Errors):**  当服务器返回无效的 SPDY 响应或发送错误的 SPDY 帧时，`SpdyNetworkTransaction` 的错误处理机制确保了浏览器能够安全地处理这些情况，避免崩溃，并可能向 JavaScript 提供错误信息，例如通过 `fetch` API 的 `response.ok` 属性或 `XMLHttpRequest` 的 `status` 属性来指示请求失败。
    * **举例:**  一个恶意服务器发送了一个缺少状态行的 SPDY 响应头部。`SpdyNetworkTransaction` 检测到这个错误，关闭连接，JavaScript 的 `fetch` Promise 将会被 reject。
* **数据传输 (Buffering):** `SpdyNetworkTransaction` 的数据缓冲机制允许浏览器在接收到数据后，不必立即将所有数据都传递给 JavaScript。这使得 JavaScript 可以以更灵活的方式读取数据，例如按需读取或分块读取，提高了处理大型响应的效率。
    * **举例:**  使用 `fetch` API 下载一个大型文件，可以通过 `response.body.getReader()` 获取一个 ReadableStream，然后逐步读取数据块。`SpdyNetworkTransaction` 的缓冲机制保证了即使网络速度不稳定，也能平滑地将数据传递给 JavaScript。
* **网络日志 (NetLog):**  虽然 JavaScript 代码本身不直接使用 NetLog，但开发者可以使用 Chrome 的 `chrome://net-export/` 功能导出网络日志，查看 `SpdyNetworkTransaction` 记录的详细信息，帮助分析网络请求的问题。
    * **举例:**  一个 JavaScript 应用遇到了间歇性的网络请求失败。开发者可以通过导出的 NetLog 查看 `SpdyNetworkTransaction` 是否记录了任何异常，例如 RST_STREAM 帧或 GOAWAY 帧，从而定位问题是客户端还是服务器端导致的。

**3. 逻辑推理、假设输入与输出:**

以下是一些示例，基于代码片段中的测试用例：

* **Socket Tagging:**
    * **假设输入:**
        * 存在一个到 `https://www.example.org` 的 SPDY Session。
        * 发起一个新的到 `https://mail.example.org` 的请求，并设置了不同的 `socket_tag`。
    * **预期输出:**
        * 会创建一个新的 SPDY Session 到 `https://mail.example.org`。
        * 原有的到 `https://www.example.org` 的 Session 不受影响。

* **Response Headers (逗号分隔):**
    * **假设输入:** 服务器返回包含以下头部的 SPDY 响应：
        ```
        :status: 200
        hello: bye
        cookie: val1, val2
        ```
    * **预期输出:**  `HttpResponseHeaders` 对象中会包含一个名为 "cookie" 的头部，其值为 "val1, val2"。

* **Invalid Response Headers:**
    * **假设输入:** 服务器返回缺少 `:status` 头的 SPDY 响应。
    * **预期输出:** `SpdyNetworkTransaction` 会检测到协议错误，发送 RST_STREAM 帧或 GOAWAY 帧，并返回 `ERR_HTTP2_PROTOCOL_ERROR`。

* **Buffering (Buffer Full):**
    * **假设输入:**
        * 服务器发送一个包含 "goodbye world" 的 SPDY DATA 帧。
        * 客户端的读取操作每次只请求 3 个字节。
    * **预期输出:**
        * `SpdyNetworkTransaction` 会将所有数据缓冲起来。
        * 客户端会分多次读取到完整的数据 "goodbye world"。

**4. 涉及用户或编程常见的使用错误:**

由于 `SpdyNetworkTransaction` 是网络栈的底层实现，普通用户或 JavaScript 开发者不会直接操作它。但是，一些配置或服务器端的错误可能会导致 `SpdyNetworkTransaction` 进入错误状态，从而影响用户体验：

* **服务器端 SPDY/HTTP2 配置错误:** 如果服务器的 SPDY/HTTP2 配置不正确，例如发送了不符合协议规范的头部或帧，会导致 `SpdyNetworkTransaction` 报告错误。用户可能会遇到页面加载失败或部分内容无法加载的情况。
* **中间代理问题:** 某些中间代理可能无法正确处理 SPDY/HTTP2 协议，导致连接中断或数据损坏，`SpdyNetworkTransaction` 可能会报告连接错误。
* **客户端网络环境问题:** 虽然不是 `SpdyNetworkTransaction` 本身的问题，但网络不稳定或防火墙阻止连接等情况会导致 `SpdyNetworkTransaction` 无法正常工作。

**5. 用户操作如何一步步到达这里，作为调试线索:**

当用户在 Chrome 浏览器中访问一个使用 HTTPS 协议的网站时，以下步骤可能会触发 `SpdyNetworkTransaction` 的执行：

1. **用户在地址栏输入 URL 并回车，或点击一个 HTTPS 链接。**
2. **浏览器首先进行 DNS 查询，解析域名对应的 IP 地址。**
3. **浏览器尝试与服务器建立 TCP 连接。**
4. **在 TCP 连接建立后，如果服务器支持 SPDY/HTTP2，浏览器会进行 TLS 握手，并在 TLS 扩展中协商使用 SPDY/HTTP2 协议。**
5. **如果协商成功，浏览器会创建一个 `SpdySession` 对象来管理与服务器的 SPDY/HTTP2 连接。**
6. **当需要发送 HTTP 请求时（例如加载网页资源），浏览器会创建一个 `HttpNetworkTransaction` 对象，并根据协议选择使用 `SpdyNetworkTransaction` 来处理 SPDY/HTTP2 请求。**
7. **`SpdyNetworkTransaction` 会将 HTTP 请求转换为 SPDY HEADERS 帧，并通过 `SpdySession` 发送给服务器。**
8. **服务器返回 SPDY 响应头部和数据帧，`SpdyNetworkTransaction` 负责接收和解析这些帧，并将数据传递给上层模块。**

**调试线索:** 如果用户遇到与 SPDY/HTTP2 相关的网络问题，例如连接失败、请求超时、内容加载错误等，可以按照以下步骤进行调试：

1. **打开 Chrome 的开发者工具 (F12)。**
2. **切换到 "Network" 面板。**
3. **重新加载页面，观察网络请求的详细信息。**
4. **查看 "Protocol" 列，确认请求是否使用了 h2 (HTTP/2)。**
5. **查看请求的 "Timing" 选项卡，分析各个阶段的耗时。**
6. **查看请求的 "Headers" 选项卡，检查请求和响应头部是否正常。**
7. **可以使用 Chrome 的 `chrome://net-internals/#events` 或 `chrome://net-export/` 功能导出网络日志，查看更底层的网络事件，包括 `SpdyNetworkTransaction` 记录的日志，例如 SPDY 帧的发送和接收、错误信息等。** 这对于诊断 SPDY 协议层面的问题非常有用。

**6. 归纳一下它的功能 (作为第 5 部分):**

作为整个 `spdy_network_transaction_unittest.cc` 测试套件的第 5 部分，这段代码专注于 **深入测试 `SpdyNetworkTransaction` 在处理复杂和异常 SPDY 协议交互时的正确性和健壮性**。它涵盖了连接管理（socket tagging 和 session 重用）、头部解析的细节、多种错误处理场景以及数据缓冲机制的各种情况。这些测试确保了 `SpdyNetworkTransaction` 能够可靠地处理 SPDY/HTTP2 通信，为用户提供稳定和高性能的网络体验。

Prompt: 
```
这是目录为net/spdy/spdy_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共12部分，请归纳一下它的功能

"""
s()->ClearRules();
  trans2.reset();

  HttpRequestInfo request3;
  request3.socket_tag = socket_tag_2;
  request3.method = "GET";
  request3.url = url2;
  request3.load_flags = 0;
  request3.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  SpdySessionKey key3(HostPortPair(url2.host(), 443), PRIVACY_MODE_DISABLED,
                      ProxyChain::Direct(), SessionUsage::kDestination,
                      socket_tag_2, NetworkAnonymizationKey(),
                      SecureDnsPolicy::kAllow,
                      /*disable_cert_verification_network_fetches=*/false);
  auto trans3 = std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY,
                                                         helper.session());
  TestCompletionCallback callback3;
  EXPECT_THAT(
      trans3->Start(&request3, callback3.callback(), NetLogWithSource()),
      IsError(ERR_IO_PENDING));

  // Wait for the third request to get headers.  It should have reused the
  // first session but changed the socket tag.
  EXPECT_THAT(callback3.WaitForResult(), IsOk());

  EXPECT_EQ(1u, helper.GetSpdySessionCount());
  EXPECT_FALSE(helper.session()->spdy_session_pool()->FindAvailableSession(
      key2, true /* enable_ip_based_pooling */, false /* is_websocket */,
      NetLogWithSource()));
  EXPECT_TRUE(helper.session()
                  ->spdy_session_pool()
                  ->GetDnsAliasesForSessionKey(key2)
                  .empty());
  EXPECT_TRUE(helper.session()->spdy_session_pool()->FindAvailableSession(
      key3, true /* enable_ip_based_pooling */, false /* is_websocket */,
      NetLogWithSource()));
  EXPECT_EQ(
      dns_aliases2,
      helper.session()->spdy_session_pool()->GetDnsAliasesForSessionKey(key3));

  response = trans3->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  ASSERT_THAT(ReadTransaction(trans3.get(), &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);

  trans3.reset();

  HttpRequestInfo request4;
  request4.socket_tag = socket_tag_2;
  request4.method = "GET";
  request4.url = url1;
  request4.load_flags = 0;
  request4.traffic_annotation =
      net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  SpdySessionKey key4(HostPortPair(url1.host(), 443), PRIVACY_MODE_DISABLED,
                      ProxyChain::Direct(), SessionUsage::kDestination,
                      socket_tag_2, NetworkAnonymizationKey(),
                      SecureDnsPolicy::kAllow,
                      /*disable_cert_verification_network_fetches=*/false);
  auto trans4 = std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY,
                                                         helper.session());
  TestCompletionCallback callback4;
  EXPECT_THAT(
      trans4->Start(&request4, callback4.callback(), NetLogWithSource()),
      IsError(ERR_IO_PENDING));

  // Wait for the third request to get headers.  It should have reused the
  // first session but changed the socket tag.
  EXPECT_THAT(callback4.WaitForResult(), IsOk());

  EXPECT_EQ(1u, helper.GetSpdySessionCount());
  EXPECT_FALSE(helper.session()->spdy_session_pool()->FindAvailableSession(
      key1, true /* enable_ip_based_pooling */, false /* is_websocket */,
      NetLogWithSource()));
  EXPECT_TRUE(helper.session()
                  ->spdy_session_pool()
                  ->GetDnsAliasesForSessionKey(key1)
                  .empty());
  EXPECT_TRUE(helper.session()->spdy_session_pool()->FindAvailableSession(
      key4, true /* enable_ip_based_pooling */, false /* is_websocket */,
      NetLogWithSource()));
  EXPECT_EQ(
      dns_aliases1,
      helper.session()->spdy_session_pool()->GetDnsAliasesForSessionKey(key4));

  response = trans4->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ("HTTP/1.1 200", response->headers->GetStatusLine());
  EXPECT_TRUE(response->was_fetched_via_spdy);
  EXPECT_TRUE(response->was_alpn_negotiated);
  ASSERT_THAT(ReadTransaction(trans4.get(), &response_data), IsOk());
  EXPECT_EQ("hello!", response_data);

  helper.VerifyDataConsumed();
}

#endif  // BUILDFLAG(IS_ANDROID)

// Verify that various response headers parse correctly through the HTTP layer.
TEST_P(SpdyNetworkTransactionTest, ResponseHeaders) {
  struct ResponseHeadersTests {
    int extra_header_count;
    const char* extra_headers[4];
    size_t expected_header_count;
    std::string_view expected_headers[8];
  } test_cases[] = {
      // No extra headers.
      {0, {}, 1, {"hello", "bye"}},
      // Comma-separated header value.
      {1,
       {"cookie", "val1, val2"},
       2,
       {"hello", "bye", "cookie", "val1, val2"}},
      // Multiple headers are preserved: they are joined with \0 separator in
      // quiche::HttpHeaderBlock.AppendValueOrAddHeader(), then split up in
      // HpackEncoder, then joined with \0 separator when
      // spdy::HpackDecoderAdapter::ListenerAdapter::OnHeader() calls
      // quiche::HttpHeaderBlock.AppendValueOrAddHeader(), then split up again
      // in
      // HttpResponseHeaders.
      {2,
       {"content-encoding", "val1", "content-encoding", "val2"},
       3,
       {"hello", "bye", "content-encoding", "val1", "content-encoding",
        "val2"}},
      // Cookie header is not split up by HttpResponseHeaders.
      {2,
       {"cookie", "val1", "cookie", "val2"},
       2,
       {"hello", "bye", "cookie", "val1; val2"}}};

  for (size_t i = 0; i < std::size(test_cases); ++i) {
    SCOPED_TRACE(i);
    SpdyTestUtil spdy_test_util(/*use_priority_header=*/true);
    spdy::SpdySerializedFrame req(
        spdy_test_util.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
    MockWrite writes[] = {CreateMockWrite(req, 0)};

    spdy::SpdySerializedFrame resp(spdy_test_util.ConstructSpdyGetReply(
        test_cases[i].extra_headers, test_cases[i].extra_header_count, 1));
    spdy::SpdySerializedFrame body(
        spdy_test_util.ConstructSpdyDataFrame(1, true));
    MockRead reads[] = {
        CreateMockRead(resp, 1), CreateMockRead(body, 2),
        MockRead(ASYNC, 0, 3)  // EOF
    };

    SequencedSocketData data(reads, writes);
    NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                       nullptr);
    helper.RunToCompletion(&data);
    TransactionHelperResult out = helper.output();

    EXPECT_THAT(out.rv, IsOk());
    EXPECT_EQ("HTTP/1.1 200", out.status_line);
    EXPECT_EQ("hello!", out.response_data);

    scoped_refptr<HttpResponseHeaders> headers = out.response_info.headers;
    ASSERT_TRUE(headers);
    EXPECT_EQ("HTTP/1.1 200", headers->GetStatusLine());
    size_t iter = 0;
    std::string name, value;
    size_t expected_header_index = 0;
    while (headers->EnumerateHeaderLines(&iter, &name, &value)) {
      ASSERT_LT(expected_header_index, test_cases[i].expected_header_count);
      EXPECT_EQ(name,
                test_cases[i].expected_headers[2 * expected_header_index]);
      EXPECT_EQ(value,
                test_cases[i].expected_headers[2 * expected_header_index + 1]);
      ++expected_header_index;
    }
    EXPECT_EQ(expected_header_index, test_cases[i].expected_header_count);
  }
}

// Verify that we don't crash on invalid response headers.
TEST_P(SpdyNetworkTransactionTest, InvalidResponseHeaders) {
  struct InvalidResponseHeadersTests {
    int num_headers;
    const char* headers[10];
  } test_cases[] = {// Response headers missing status header
                    {2, {"cookie", "val1", "cookie", "val2", nullptr}},
                    // Response headers with no headers
                    {0, {nullptr}}};

  for (size_t i = 0; i < std::size(test_cases); ++i) {
    SCOPED_TRACE(i);
    SpdyTestUtil spdy_test_util(/*use_priority_header=*/true);

    spdy::SpdySerializedFrame req(
        spdy_test_util.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
    spdy::SpdySerializedFrame rst(spdy_test_util.ConstructSpdyRstStream(
        1, spdy::ERROR_CODE_PROTOCOL_ERROR));
    MockWrite writes[] = {
        CreateMockWrite(req, 0),
        CreateMockWrite(rst, 2),
    };

    // Construct the reply.
    quiche::HttpHeaderBlock reply_headers;
    AppendToHeaderBlock(test_cases[i].headers, test_cases[i].num_headers,
                        &reply_headers);
    spdy::SpdySerializedFrame resp(
        spdy_test_util.ConstructSpdyReply(1, std::move(reply_headers)));
    MockRead reads[] = {
        CreateMockRead(resp, 1), MockRead(ASYNC, 0, 3)  // EOF
    };

    SequencedSocketData data(reads, writes);
    NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_,
                                       nullptr);
    helper.RunToCompletion(&data);
    TransactionHelperResult out = helper.output();
    EXPECT_THAT(out.rv, IsError(ERR_HTTP2_PROTOCOL_ERROR));
  }
}

TEST_P(SpdyNetworkTransactionTest, CorruptFrameSessionError) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      0, spdy::ERROR_CODE_COMPRESSION_ERROR,
      "Framer error: 24 (HPACK_TRUNCATED_BLOCK)."));
  MockWrite writes[] = {CreateMockWrite(req, 0), CreateMockWrite(goaway, 2)};

  // This is the length field that's too short.
  spdy::SpdySerializedFrame reply_wrong_length(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  size_t right_size = reply_wrong_length.size() - spdy::kFrameHeaderSize;
  size_t wrong_size = right_size - 4;
  spdy::test::SetFrameLength(&reply_wrong_length, wrong_size);

  MockRead reads[] = {
      MockRead(ASYNC, reply_wrong_length.data(), reply_wrong_length.size() - 4,
               1),
  };

  SequencedSocketData data(reads, writes);
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_HTTP2_COMPRESSION_ERROR));
}

TEST_P(SpdyNetworkTransactionTest, GoAwayOnDecompressionFailure) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      0, spdy::ERROR_CODE_COMPRESSION_ERROR,
      "Framer error: 24 (HPACK_TRUNCATED_BLOCK)."));
  MockWrite writes[] = {CreateMockWrite(req, 0), CreateMockWrite(goaway, 2)};

  // Read HEADERS with corrupted payload.
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  memset(resp.data() + 12, 0xcf, resp.size() - 12);
  MockRead reads[] = {CreateMockRead(resp, 1)};

  SequencedSocketData data(reads, writes);
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_HTTP2_COMPRESSION_ERROR));
}

TEST_P(SpdyNetworkTransactionTest, GoAwayOnFrameSizeError) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(
      0, spdy::ERROR_CODE_FRAME_SIZE_ERROR,
      "Framer error: 9 (INVALID_CONTROL_FRAME_SIZE)."));
  MockWrite writes[] = {CreateMockWrite(req, 0), CreateMockWrite(goaway, 2)};

  // Read WINDOW_UPDATE with incorrectly-sized payload.
  spdy::SpdySerializedFrame bad_window_update(
      spdy_util_.ConstructSpdyWindowUpdate(1, 1));
  spdy::test::SetFrameLength(&bad_window_update, bad_window_update.size() - 1);
  MockRead reads[] = {CreateMockRead(bad_window_update, 1)};

  SequencedSocketData data(reads, writes);
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_HTTP2_FRAME_SIZE_ERROR));
}

// Test that we shutdown correctly on write errors.
TEST_P(SpdyNetworkTransactionTest, WriteError) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  MockWrite writes[] = {
      // We'll write 10 bytes successfully
      MockWrite(ASYNC, req.data(), 10, 1),
      // Followed by ERROR!
      MockWrite(ASYNC, ERR_FAILED, 2),
      // Session drains and attempts to write a GOAWAY: Another ERROR!
      MockWrite(ASYNC, ERR_FAILED, 3),
  };

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};

  SequencedSocketData data(reads, writes);

  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  EXPECT_TRUE(helper.StartDefaultTest());
  helper.FinishDefaultTest();
  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsError(ERR_FAILED));
}

// Test that partial writes work.
TEST_P(SpdyNetworkTransactionTest, PartialWrite) {
  // Chop the HEADERS frame into 5 chunks.
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  const size_t kChunks = 5u;
  std::unique_ptr<MockWrite[]> writes = ChopWriteFrame(req, kChunks);
  for (size_t i = 0; i < kChunks; ++i) {
    writes[i].sequence_number = i;
  }

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, kChunks), CreateMockRead(body, kChunks + 1),
      MockRead(ASYNC, 0, kChunks + 2)  // EOF
  };

  SequencedSocketData data(reads, base::make_span(writes.get(), kChunks));
  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);
}

// Test that the NetLog contains good data for a simple GET request.
TEST_P(SpdyNetworkTransactionTest, NetLog) {
  static const char* const kExtraHeaders[] = {
      "user-agent",
      "Chrome",
  };
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(kExtraHeaders, 1, 1, LOWEST));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(body, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  RecordingNetLogObserver net_log_observer;

  SequencedSocketData data(reads, writes);
  request_.extra_headers.SetHeader("User-Agent", "Chrome");
  NormalSpdyTransactionHelper helper(
      request_, DEFAULT_PRIORITY,
      NetLogWithSource::Make(NetLogSourceType::NONE), nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("hello!", out.response_data);

  // Check that the NetLog was filled reasonably.
  // This test is intentionally non-specific about the exact ordering of the
  // log; instead we just check to make sure that certain events exist, and that
  // they are in the right order.
  auto entries = net_log_observer.GetEntries();

  EXPECT_LT(0u, entries.size());
  int pos = 0;
  pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP_TRANSACTION_SEND_REQUEST,
      NetLogEventPhase::BEGIN);
  pos = ExpectLogContainsSomewhere(
      entries, pos + 1, NetLogEventType::HTTP_TRANSACTION_SEND_REQUEST,
      NetLogEventPhase::END);
  pos = ExpectLogContainsSomewhere(
      entries, pos + 1, NetLogEventType::HTTP_TRANSACTION_READ_HEADERS,
      NetLogEventPhase::BEGIN);
  pos = ExpectLogContainsSomewhere(
      entries, pos + 1, NetLogEventType::HTTP_TRANSACTION_READ_HEADERS,
      NetLogEventPhase::END);
  pos = ExpectLogContainsSomewhere(entries, pos + 1,
                                   NetLogEventType::HTTP_TRANSACTION_READ_BODY,
                                   NetLogEventPhase::BEGIN);
  pos = ExpectLogContainsSomewhere(entries, pos + 1,
                                   NetLogEventType::HTTP_TRANSACTION_READ_BODY,
                                   NetLogEventPhase::END);

  // Check that we logged all the headers correctly
  pos = ExpectLogContainsSomewhere(entries, 0,
                                   NetLogEventType::HTTP2_SESSION_SEND_HEADERS,
                                   NetLogEventPhase::NONE);

  ASSERT_TRUE(entries[pos].HasParams());
  auto* header_list = entries[pos].params.FindList("headers");
  ASSERT_TRUE(header_list);
  ASSERT_EQ(6u, header_list->size());

  ASSERT_TRUE((*header_list)[0].is_string());
  EXPECT_EQ(":method: GET", (*header_list)[0].GetString());

  ASSERT_TRUE((*header_list)[1].is_string());
  EXPECT_EQ(":authority: www.example.org", (*header_list)[1].GetString());

  ASSERT_TRUE((*header_list)[2].is_string());
  EXPECT_EQ(":scheme: https", (*header_list)[2].GetString());

  ASSERT_TRUE((*header_list)[3].is_string());
  EXPECT_EQ(":path: /", (*header_list)[3].GetString());

  ASSERT_TRUE((*header_list)[4].is_string());
  EXPECT_EQ("user-agent: Chrome", (*header_list)[4].GetString());

  // Incoming HEADERS frame is logged as HTTP2_SESSION_RECV_HEADERS.
  pos = ExpectLogContainsSomewhere(entries, 0,
                                   NetLogEventType::HTTP2_SESSION_RECV_HEADERS,
                                   NetLogEventPhase::NONE);
  ASSERT_TRUE(entries[pos].HasParams());
  // END_STREAM is not set on the HEADERS frame, so `fin` is false.
  std::optional<bool> fin = entries[pos].params.FindBool("fin");
  ASSERT_TRUE(fin.has_value());
  EXPECT_FALSE(*fin);

  // Incoming DATA frame is logged as HTTP2_SESSION_RECV_DATA.
  pos = ExpectLogContainsSomewhere(entries, 0,
                                   NetLogEventType::HTTP2_SESSION_RECV_DATA,
                                   NetLogEventPhase::NONE);
  ASSERT_TRUE(entries[pos].HasParams());
  std::optional<int> size = entries[pos].params.FindInt("size");
  ASSERT_TRUE(size.has_value());
  EXPECT_EQ(static_cast<int>(strlen("hello!")), *size);
  // END_STREAM is set on the DATA frame, so `fin` is true.
  fin = entries[pos].params.FindBool("fin");
  ASSERT_TRUE(fin.has_value());
  EXPECT_TRUE(*fin);
}

TEST_P(SpdyNetworkTransactionTest, NetLogForResponseWithNoBody) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  quiche::HttpHeaderBlock response_headers;
  response_headers[spdy::kHttp2StatusHeader] = "200";
  response_headers["hello"] = "bye";
  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyResponseHeaders(
      1, std::move(response_headers), /* fin = */ true));
  MockRead reads[] = {CreateMockRead(resp, 1), MockRead(ASYNC, 0, 2)};

  RecordingNetLogObserver net_log_observer;

  SequencedSocketData data(reads, writes);
  NormalSpdyTransactionHelper helper(
      request_, DEFAULT_PRIORITY,
      NetLogWithSource::Make(NetLogSourceType::NONE), nullptr);
  helper.RunToCompletion(&data);
  TransactionHelperResult out = helper.output();
  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("", out.response_data);

  // Incoming HEADERS frame is logged as HTTP2_SESSION_RECV_HEADERS.
  auto entries = net_log_observer.GetEntries();
  int pos = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::HTTP2_SESSION_RECV_HEADERS,
      NetLogEventPhase::NONE);
  ASSERT_TRUE(entries[pos].HasParams());
  // END_STREAM is set on the HEADERS frame, so `fin` is true.
  std::optional<bool> fin = entries[pos].params.FindBool("fin");
  ASSERT_TRUE(fin.has_value());
  EXPECT_TRUE(*fin);

  // No DATA frame is received.
  EXPECT_FALSE(LogContainsEntryWithTypeAfter(
      entries, 0, NetLogEventType::HTTP2_SESSION_RECV_DATA));
}

// Since we buffer the IO from the stream to the renderer, this test verifies
// that when we read out the maximum amount of data (e.g. we received 50 bytes
// on the network, but issued a Read for only 5 of those bytes) that the data
// flow still works correctly.
TEST_P(SpdyNetworkTransactionTest, BufferFull) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  // 2 data frames in a single read.
  spdy::SpdySerializedFrame data_frame_1(
      spdy_util_.ConstructSpdyDataFrame(1, "goodby", /*fin=*/false));
  spdy::SpdySerializedFrame data_frame_2(
      spdy_util_.ConstructSpdyDataFrame(1, "e worl", /*fin=*/false));
  spdy::SpdySerializedFrame combined_data_frames =
      CombineFrames({&data_frame_1, &data_frame_2});

  spdy::SpdySerializedFrame last_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "d", /*fin=*/true));

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a pause
      CreateMockRead(combined_data_frames, 3),
      MockRead(ASYNC, ERR_IO_PENDING, 4),  // Force a pause
      CreateMockRead(last_frame, 5),
      MockRead(ASYNC, 0, 6)  // EOF
  };

  SequencedSocketData data(reads, writes);

  TestCompletionCallback callback;

  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  HttpNetworkTransaction* trans = helper.trans();
  int rv = trans->Start(&request_, callback.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  TransactionHelperResult out = helper.output();
  out.rv = callback.WaitForResult();
  EXPECT_EQ(out.rv, OK);

  const HttpResponseInfo* response = trans->GetResponseInfo();
  EXPECT_TRUE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);
  out.status_line = response->headers->GetStatusLine();
  out.response_info = *response;  // Make a copy so we can verify.

  // Read Data
  TestCompletionCallback read_callback;

  std::string content;
  do {
    // Read small chunks at a time.
    const int kSmallReadSize = 3;
    auto buf = base::MakeRefCounted<IOBufferWithSize>(kSmallReadSize);
    rv = trans->Read(buf.get(), kSmallReadSize, read_callback.callback());
    if (rv == ERR_IO_PENDING) {
      data.Resume();
      rv = read_callback.WaitForResult();
    }
    if (rv > 0) {
      content.append(buf->data(), rv);
    } else if (rv < 0) {
      NOTREACHED();
    }
  } while (rv > 0);

  out.response_data.swap(content);

  // Flush the MessageLoop while the SpdySessionDependencies (in particular, the
  // MockClientSocketFactory) are still alive.
  base::RunLoop().RunUntilIdle();

  // Verify that we consumed all test data.
  helper.VerifyDataConsumed();

  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("goodbye world", out.response_data);
}

// Verify that basic buffering works; when multiple data frames arrive
// at the same time, ensure that we don't notify a read completion for
// each data frame individually.
TEST_P(SpdyNetworkTransactionTest, Buffering) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  // 4 data frames in a single read.
  spdy::SpdySerializedFrame data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "message", /*fin=*/false));
  spdy::SpdySerializedFrame data_frame_fin(
      spdy_util_.ConstructSpdyDataFrame(1, "message", /*fin=*/true));
  spdy::SpdySerializedFrame combined_data_frames =
      CombineFrames({&data_frame, &data_frame, &data_frame, &data_frame_fin});

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a pause
      CreateMockRead(combined_data_frames, 3), MockRead(ASYNC, 0, 4)  // EOF
  };

  SequencedSocketData data(reads, writes);

  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  HttpNetworkTransaction* trans = helper.trans();

  TestCompletionCallback callback;
  int rv = trans->Start(&request_, callback.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  TransactionHelperResult out = helper.output();
  out.rv = callback.WaitForResult();
  EXPECT_EQ(out.rv, OK);

  const HttpResponseInfo* response = trans->GetResponseInfo();
  EXPECT_TRUE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);
  out.status_line = response->headers->GetStatusLine();
  out.response_info = *response;  // Make a copy so we can verify.

  // Read Data
  TestCompletionCallback read_callback;

  std::string content;
  int reads_completed = 0;
  do {
    // Read small chunks at a time.
    const int kSmallReadSize = 14;
    auto buf = base::MakeRefCounted<IOBufferWithSize>(kSmallReadSize);
    rv = trans->Read(buf.get(), kSmallReadSize, read_callback.callback());
    if (rv == ERR_IO_PENDING) {
      data.Resume();
      rv = read_callback.WaitForResult();
    }
    if (rv > 0) {
      EXPECT_EQ(kSmallReadSize, rv);
      content.append(buf->data(), rv);
    } else if (rv < 0) {
      FAIL() << "Unexpected read error: " << rv;
    }
    reads_completed++;
  } while (rv > 0);

  EXPECT_EQ(3, reads_completed);  // Reads are: 14 bytes, 14 bytes, 0 bytes.

  out.response_data.swap(content);

  // Flush the MessageLoop while the SpdySessionDependencies (in particular, the
  // MockClientSocketFactory) are still alive.
  base::RunLoop().RunUntilIdle();

  // Verify that we consumed all test data.
  helper.VerifyDataConsumed();

  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("messagemessagemessagemessage", out.response_data);
}

// Verify the case where we buffer data but read it after it has been buffered.
TEST_P(SpdyNetworkTransactionTest, BufferedAll) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  // 5 data frames in a single read.
  spdy::SpdySerializedFrame reply(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "message", /*fin=*/false));
  spdy::SpdySerializedFrame data_frame_fin(
      spdy_util_.ConstructSpdyDataFrame(1, "message", /*fin=*/true));
  spdy::SpdySerializedFrame combined_frames = CombineFrames(
      {&reply, &data_frame, &data_frame, &data_frame, &data_frame_fin});

  MockRead reads[] = {
      CreateMockRead(combined_frames, 1), MockRead(ASYNC, 0, 2)  // EOF
  };

  SequencedSocketData data(reads, writes);

  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  HttpNetworkTransaction* trans = helper.trans();

  TestCompletionCallback callback;
  int rv = trans->Start(&request_, callback.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  TransactionHelperResult out = helper.output();
  out.rv = callback.WaitForResult();
  EXPECT_EQ(out.rv, OK);

  const HttpResponseInfo* response = trans->GetResponseInfo();
  EXPECT_TRUE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);
  out.status_line = response->headers->GetStatusLine();
  out.response_info = *response;  // Make a copy so we can verify.

  // Read Data
  TestCompletionCallback read_callback;

  std::string content;
  int reads_completed = 0;
  do {
    // Read small chunks at a time.
    const int kSmallReadSize = 14;
    auto buf = base::MakeRefCounted<IOBufferWithSize>(kSmallReadSize);
    rv = trans->Read(buf.get(), kSmallReadSize, read_callback.callback());
    if (rv > 0) {
      EXPECT_EQ(kSmallReadSize, rv);
      content.append(buf->data(), rv);
    } else if (rv < 0) {
      FAIL() << "Unexpected read error: " << rv;
    }
    reads_completed++;
  } while (rv > 0);

  EXPECT_EQ(3, reads_completed);

  out.response_data.swap(content);

  // Flush the MessageLoop while the SpdySessionDependencies (in particular, the
  // MockClientSocketFactory) are still alive.
  base::RunLoop().RunUntilIdle();

  // Verify that we consumed all test data.
  helper.VerifyDataConsumed();

  EXPECT_THAT(out.rv, IsOk());
  EXPECT_EQ("HTTP/1.1 200", out.status_line);
  EXPECT_EQ("messagemessagemessagemessage", out.response_data);
}

// Verify the case where we buffer data and close the connection.
TEST_P(SpdyNetworkTransactionTest, BufferedClosed) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  MockWrite writes[] = {CreateMockWrite(req, 0)};

  // All data frames in a single read.
  // NOTE: We don't FIN the stream.
  spdy::SpdySerializedFrame data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "message", /*fin=*/false));
  spdy::SpdySerializedFrame combined_data_frames =
      CombineFrames({&data_frame, &data_frame, &data_frame, &data_frame});
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),  // Force a wait
      CreateMockRead(combined_data_frames, 3), MockRead(ASYNC, 0, 4)  // EOF
  };

  SequencedSocketData data(reads, writes);

  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  HttpNetworkTransaction* trans = helper.trans();

  TestCompletionCallback callback;

  int rv = trans->Start(&request_, callback.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  TransactionHelperResult out = helper.output();
  rv = callback.WaitForResult();
  EXPECT_EQ(rv, OK);

  const HttpResponseInfo* response = trans->GetResponseInfo();
  EXPECT_TRUE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);

  // Read Data
  TestCompletionCallback read_callback;

  std::string content;
  int reads_completed = 0;
  do {
    // Allocate a large buffer to allow buffering. If a single read fills the
    // buffer, no buffering happens.
    const int kLargeReadSize = 1000;
    auto buf = base::MakeRefCounted<IOBufferWithSize>(kLargeReadSize);
    rv = trans->Read(buf.get(), kLargeReadSize, read_callback.callback());
    if (rv == ERR_IO_PENDING) {
      data.Resume();
      rv = read_callback.WaitForResult();
    }

    if (rv < 0) {
      // This test intentionally closes the connection, and will get an error.
      EXPECT_THAT(rv, IsError(ERR_CONNECTION_CLOSED));
      break;
    }
    reads_completed++;
  } while (rv > 0);

  EXPECT_EQ(0, reads_completed);

  // Flush the MessageLoop while the SpdySessionDependencies (in particular, the
  // MockClientSocketFactory) are still alive.
  base::RunLoop().RunUntilIdle();

  // Verify that we consumed all test data.
  helper.VerifyDataConsumed();
}

// Verify the case where we buffer data and cancel the transaction.
TEST_P(SpdyNetworkTransactionTest, BufferedCancelled) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, LOWEST));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));
  MockWrite writes[] = {CreateMockWrite(req, 0), CreateMockWrite(rst, 4)};

  // NOTE: We don't FIN the stream.
  spdy::SpdySerializedFrame data_frame(
      spdy_util_.ConstructSpdyDataFrame(1, "message", /*fin=*/false));

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  MockRead reads[] = {
      CreateMockRead(resp, 1),
      MockRead(ASYNC, ERR_IO_PENDING, 2),                   // Force a wait
      CreateMockRead(data_frame, 3), MockRead(ASYNC, 0, 5)  // EOF
  };

  SequencedSocketData data(reads, writes);

  NormalSpdyTransactionHelper helper(request_, DEFAULT_PRIORITY, log_, nullptr);
  helper.RunPreTestSetup();
  helper.AddData(&data);
  HttpNetworkTransaction* trans = helper.trans();
  TestCompletionCallback callback;

  int rv = trans->Start(&request_, callback.callback(), log_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  TransactionHelperResult out = helper.output();
  out.rv = callback.WaitForResult();
  EXPECT_EQ(out.rv, OK);

  const HttpResponseInfo* response = trans->GetResponseInfo();
  EXPECT_TRUE(response->headers);
  EXPECT_TRUE(response->was_fetched_via_spdy);
  out.status_line = response->headers->GetStatusLine();
  out.response_info = *response;  // Make a copy so we can verify.

  // Read Data
  TestCompletionCallback read_callb
"""


```