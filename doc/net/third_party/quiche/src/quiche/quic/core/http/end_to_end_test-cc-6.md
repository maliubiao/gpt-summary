Response:
The user wants to understand the functionality of the provided C++ code file. The request is broken down into several parts:

1. **General Functionality:** Describe what the code does.
2. **Relationship to JavaScript:** Explain if and how it connects to JavaScript.
3. **Logical Reasoning (Input/Output):**  Provide examples of input and expected output.
4. **Common Errors:**  Point out potential user or programming mistakes.
5. **User Steps to Reach the Code:** Describe how a user's actions could lead to this code being executed (for debugging).
6. **Summary of Functionality (Part 7 of 10):**  Synthesize the purpose of this specific section of the file.

Let's go through each point:

**1. General Functionality:**

The code is a C++ unit test file for the QUIC protocol implementation in Chromium's network stack. Specifically, it focuses on end-to-end testing of HTTP over QUIC. This involves simulating client and server interactions to verify the correct behavior of various QUIC and HTTP/3 features. The tests cover aspects like:

* **Request/Response handling:** Sending requests and verifying responses.
* **Error handling:** Testing how the implementation reacts to various errors (e.g., large headers, premature connection closure).
* **Data transfer:**  Testing large uploads and downloads, handling packet loss and reordering.
* **Connection management:** Testing connection establishment, migration, and closure.
* **Security features:** Testing Pre-Shared Keys (PSK).
* **Message API:** Testing the sending of QUIC messages.
* **Multi-path QUIC:** Testing the functionality of using multiple network paths.
* **Path Degradation and Migration:** Testing how the client reacts to network quality changes.

**2. Relationship to JavaScript:**

QUIC is the underlying transport protocol for HTTP/3, which is used by web browsers (including Chrome) to communicate with web servers. JavaScript running in a browser makes HTTP requests. When a browser uses HTTP/3, the JavaScript's HTTP request will eventually be handled by the QUIC implementation, including the code in this test file. This file validates that the QUIC implementation correctly handles scenarios initiated by JavaScript's requests.

**3. Logical Reasoning (Input/Output):**

Consider the `TEST_P(EndToEndTest, Trailers)` test case:

* **Assumption Input:** The server is configured to respond to a request to `/trailer_url` with headers, a body ("body content"), and trailers (a trailing header named "some-trailing-header" with the value "trailing-header-value").
* **Actual Input (Code):** The client sends a synchronous request to `/trailer_url`.
* **Expected Output:**
    * The client receives a response with a "200" status code.
    * The client receives the body content: "body content".
    * The client correctly parses and stores the trailers: `{"some-trailing-header": "trailing-header-value"}`.

Consider the `TEST_P(EndToEndTest, WayTooLongRequestHeaders)` test case:

* **Assumption Input:** The server has a limit on the size of individual header values.
* **Actual Input (Code):** The client sends a request with a header named "key" whose value is 2MB long.
* **Expected Output (HTTP/3):** The client's connection will be closed with an error code `QUIC_QPACK_DECOMPRESSION_FAILED`.
* **Expected Output (HTTP/2):** The client's connection will be closed with an error code `QUIC_HPACK_VALUE_TOO_LONG`.

**4. Common Errors:**

* **Incorrect Server Configuration:**  If the `memory_cache_backend_` is not correctly configured with the expected responses, the tests will fail. For example, in the `Trailers` test, if the server isn't set up to send trailers for `/trailer_url`, the `EXPECT_EQ(trailers, client_->response_trailers());` assertion will fail.
* **Network Issues:**  Simulated packet loss or reordering can sometimes lead to unexpected test failures if the tests aren't robust enough or if the timing is critical. For instance, in tests with packet loss, the client might time out waiting for a response.
* **Mismatched Expectations:**  Incorrectly setting up the expected error codes or response headers in the `CheckResponseHeaders` function can lead to false negatives or positives. For example, expecting a "200" when the server is designed to return a "500" in a particular scenario.
* **Asynchronous Operations:**  Forgetting to `WaitForResponse()` or `WaitForDelayedAcks()` when dealing with asynchronous operations can lead to race conditions and unpredictable test outcomes. The `SendSynchronousRequestAndCheckResponse` helper function is used to mitigate this.

**5. User Steps to Reach the Code (Debugging):**

Let's consider a scenario where a user reports an issue with a website using HTTP/3, specifically related to large request headers. Here's how the debugging process might lead to this code:

1. **User Action:** The user visits a website using Chrome.
2. **Problem Report:** The user reports that the website fails to load, or they get an error message when submitting a form with many or very large input fields.
3. **Developer Investigation:** The developer examines the browser's developer tools (Network tab) and sees that the HTTP request fails with a QUIC-related error.
4. **Network Log Analysis:** Further analysis of the network logs might reveal a specific QUIC error code related to header compression (QPACK) or header size (HPACK).
5. **Chromium Source Code Search:** The developer searches the Chromium source code for the specific QUIC error code (e.g., `QUIC_QPACK_DECOMPRESSION_FAILED` or `QUIC_HPACK_VALUE_TOO_LONG`).
6. **Reaching the Test File:** The search results might point to `end_to_end_test.cc`, specifically the `WayTooLongRequestHeaders` test. This test simulates sending a request with an extremely large header value and checks for the expected error.
7. **Understanding the Issue:** By examining the test code and the surrounding context, the developer can understand how the QUIC implementation handles excessively large headers and potentially identify the root cause of the user's problem. The test helps confirm if the implementation is behaving as expected in such scenarios.

**6. Summary of Functionality (Part 7 of 10):**

This specific section (part 7) of the `end_to_end_test.cc` file primarily focuses on testing various aspects of **error handling, connection management, and some advanced QUIC features**. Key areas covered include:

* **Triggering server errors through header processing:** Simulating scenarios where the server responds with an error due to invalid or incomplete requests.
* **Handling HTTP Trailers:** Verifying the correct transmission and reception of trailing headers.
* **Testing with extreme data sizes and packet loss:** Ensuring the QUIC implementation handles very large request and response bodies, especially in the presence of network issues.
* **Resource management:** Checking if resources like the headers stream buffer are released when not in use.
* **Handling excessively large headers:** Validating the mechanisms for rejecting requests with overly large headers.
* **Window updates:** Observing the sending of window update frames.
* **Stateless Reset Token:** Verifying the exchange and handling of stateless reset tokens.
* **Handling connection closure during handshake:** Testing how the client reacts to server-initiated connection closures during the handshake process.
* **Preventing crashes on packet write errors:** Ensuring robustness against network write failures.
* **Connectivity probing:** Testing the functionality related to probing for active network paths.
* **Pre-Shared Keys (PSK):**  Testing the handshake process with pre-shared secrets for faster connection establishment (though some PSK tests are disabled).
* **Combined request and stream reset:** Verifying the handling of scenarios where a request and a stream reset are sent in the same packet.
* **Stream TTL:** Testing the mechanism for resetting streams that exceed their time-to-live.
* **QUIC messages:**  Testing the low-level QUIC message API for sending arbitrary data.
* **Packet reordering and connectivity probing:** Examining the interaction of reordered packets with connectivity probing.
* **Client-initiated network validation and migration:** Testing how the client verifies new network paths and migrates connections.
* **Multi-path QUIC:**  Testing the ability of the client to utilize multiple network paths simultaneously.
* **Port migration on path degrading:**  Verifying the client's ability to switch to a different local port when the current network path degrades.

In essence, this part of the test suite delves into more complex and edge-case scenarios of QUIC and HTTP/3, ensuring the robustness and correct behavior of the implementation under various conditions.

这是 `net/third_party/quiche/src/quiche/quic/core/http/end_to_end_test.cc` 文件的第 7 部分，主要涵盖了以下功能：

**核心功能归纳:**  这部分测试主要集中在 **错误处理、连接管理、数据传输的健壮性** 以及一些 **QUIC 的高级特性** 在端到端场景下的行为验证。

**具体功能列举:**

1. **触发错误响应的头部处理 (headers processing to trigger the error response):**
   - 测试当客户端发送一个过大的请求体，导致服务器在处理完请求头但尚未完全发送响应时，会触发错误响应。
   - **假设输入:** 客户端发送包含有效头部的请求，但请求体大小超过了 `kMaxOutgoingPacketSize`。
   - **预期输出:** 服务器返回 "500" 错误状态码。

2. **尾部 (Trailers):**
   - 测试 HTTP/2 尾部（trailing HEADERS 帧）的发送和接收。
   - 特别测试了尾部在 body 内容之前到达的情况。
   - **假设输入:** 服务器配置了对 `/trailer_url` 的响应，包含头部、body 和尾部。
   - **预期输出:** 客户端成功接收 body 内容和尾部，`client_->response_trailers()` 返回预期的尾部内容。

3. **禁用的大 Post 请求与丢包 (DISABLED_TestHugePostWithPacketLoss):**
   -  测试客户端向服务器发送超过 4GB 的巨大 POST 请求，并模拟丢包场景。
   -  主要目的是验证 QUIC 代码在 32 位架构下不会因为大 body 尺寸而崩溃。
   -  **假设输入:** 客户端分块发送超过 4GB 的请求体，模拟 1% 的丢包率。
   -  **预期输出:** 连接保持稳定，没有崩溃。

4. **禁用的大 Response 响应与丢包 (DISABLED_TestHugeResponseWithPacketLoss):**
   - 测试服务器向客户端发送超过 4GB 的巨大响应，并模拟丢包场景。
   - 主要目的是验证 QUIC 代码在 32 位架构下不会因为大 body 尺寸而崩溃。
   -  客户端配置为丢弃接收到的 body 内容。
   - **假设输入:** 客户端请求 `/huge_response`，服务器发送超过 4GB 的响应，模拟 1% 的丢包率。
   - **预期输出:** 连接保持稳定，没有崩溃。

5. **空闲时释放头部流缓冲区 (ReleaseHeadersStreamBufferWhenIdle):**
   - 测试当客户端没有活跃请求时，其头部流的 sequencer buffer 是否被释放。
   - 这是一种资源管理的优化。
   - **假设输入:** 客户端发送一个请求并接收到响应后进入空闲状态。
   - **预期输出:** 头部流的 sequencer buffer 未被分配 (`EXPECT_FALSE(QuicStreamSequencerPeer::IsUnderlyingBufferAllocated(sequencer));`)

6. **过长的请求头 (WayTooLongRequestHeaders):**
   - 测试发送一个头部 value 非常长的请求，导致超过了限制。
   -  验证了 HTTP/3 和 HTTP/2 的不同错误处理方式。
   - **假设输入:** 客户端发送一个头部 "key" 的 value 长度为 2MB 的请求。
   - **预期输出 (HTTP/3):** 连接错误为 `QUIC_QPACK_DECOMPRESSION_FAILED`。
   - **预期输出 (HTTP/2):** 连接错误为 `QUIC_HPACK_VALUE_TOO_LONG`。

7. **ACK 中的窗口更新 (WindowUpdateInAck):**
   - 测试在客户端发送带 body 的请求后，服务器在 ACK 中发送窗口更新帧。
   - **假设输入:** 客户端发送一个带有 100KB body 的 POST 请求。
   - **预期输出:**  客户端接收到至少一个窗口更新帧 (`EXPECT_LT(0u, observer.num_window_update_frames());`)。

8. **在 SHLO 中发送无状态重置令牌 (SendStatelessResetTokenInShlo):**
   - 测试服务器在握手阶段的 SHLO (Server Hello) 消息中发送无状态重置令牌。
   - **假设输入:** 客户端连接到服务器。
   - **预期输出:** 客户端配置中收到了无状态重置令牌，并且令牌值与根据连接 ID 生成的令牌值一致。

9. **在握手期间服务器本地关闭连接时发送无状态重置 (SendStatelessResetIfServerConnectionClosedLocallyDuringHandshake):**
   - 回归测试，防止在握手期间服务器本地关闭连接时出现问题。
   - 模拟服务器在发送 REJ 包时遇到错误。
   - **假设输入:** 客户端尝试连接，但服务器在发送第一个数据包时发生错误并关闭连接。
   - **预期输出:** 客户端连接错误为 `QUIC_HANDSHAKE_FAILED_SYNTHETIC_CONNECTION_CLOSE`。

10. **在握手后服务器本地关闭连接时发送无状态重置 (SendStatelessResetIfServerConnectionClosedLocallyAfterHandshake):**
    - 回归测试，防止在握手完成后服务器本地关闭连接时出现问题。
    - 模拟服务器在发送响应时遇到错误。
    - **假设输入:** 客户端首先发送一个成功的小请求，然后发送一个请求大响应的请求，服务器在发送大响应时发生错误并关闭连接。
    - **预期输出:** 第二个请求失败，客户端连接错误为 `QUIC_PUBLIC_RESET`。

11. **不在数据包写入错误时崩溃 (DoNotCrashOnPacketWriteError):**
    - 回归测试，防止在数据包写入错误时程序崩溃。
    - 模拟客户端发送大 body 的请求时，第五个数据包写入失败。
    - **假设输入:** 客户端发送一个带有 1MB body 的 POST 请求，模拟第五个数据包写入失败。
    - **预期输出:** 程序不会崩溃。

12. **最后一个发送的数据包是连接探测 (LastPacketSentIsConnectivityProbing):**
    - 回归测试，确保服务器对客户端最后发送的连接探测数据包的 ACK 不会导致客户端失败。
    - **假设输入:** 客户端发送一个请求并接收响应，然后发送一个连接探测包。
    - **预期输出:** 客户端不会因为收到服务器对连接探测包的 ACK 而失败。

13. **预共享密钥 (PreSharedKey):**
    - 测试使用预共享密钥 (PSK) 进行连接建立。
    - **假设输入:** 客户端和服务器配置了相同的预共享密钥。
    - **预期输出:** 连接建立成功。

14. **预共享密钥不匹配 (QUIC_TEST_DISABLED_IN_CHROME(PreSharedKeyMismatch)):**
    - 测试当客户端和服务器的预共享密钥不匹配时，连接建立失败。
    - **假设输入:** 客户端和服务器配置了不同的预共享密钥。
    - **预期输出:** 连接错误为 `QUIC_HANDSHAKE_TIMEOUT`。

15. **客户端没有预共享密钥 (QUIC_TEST_DISABLED_IN_CHROME(PreSharedKeyNoClient)):**
    - 测试当服务器配置了预共享密钥而客户端没有时，连接建立失败。
    - **假设输入:** 服务器配置了预共享密钥，客户端没有配置。
    - **预期输出:** 连接错误为 `QUIC_HANDSHAKE_TIMEOUT`。

16. **服务器没有预共享密钥 (QUIC_TEST_DISABLED_IN_CHROME(PreSharedKeyNoServer)):**
    - 测试当客户端配置了预共享密钥而服务器没有时，连接建立失败。
    - **假设输入:** 客户端配置了预共享密钥，服务器没有配置。
    - **预期输出:** 连接错误为 `QUIC_HANDSHAKE_TIMEOUT`。

17. **在一个数据包中发送请求和流重置 (RequestAndStreamRstInOnePacket):**
    - 回归测试，防止在同一个数据包中发送请求和流重置时出现问题。
    - **假设输入:** 客户端发送一个请求，并立即重置该流。
    - **预期输出:** 程序不会崩溃或超时，连接错误为 `IsQuicNoError()`。

18. **TTL 过期时重置流 (ResetStreamOnTtlExpires):**
    - 测试当流的 TTL (Time To Live) 过期时，流被正确重置。
    - **假设输入:** 客户端创建一个流并设置一个立即过期的 TTL，然后发送数据。
    - **预期输出:** 流错误为 `QUIC_STREAM_TTL_EXPIRED`。

19. **发送消息 (SendMessages):**
    - 测试 QUIC 的消息发送功能，包括发送大小不超过最大数据包大小的消息和发送多个消息直到连接被阻塞。
    - **假设输入:** 客户端发送多个不同大小的消息。
    - **预期输出:** 小于或等于 `GetCurrentLargestMessagePayload()` 的消息发送成功，更大的消息发送失败并返回 `MESSAGE_STATUS_TOO_LARGE`。

20. **重新排序的连接探测 (ReorderedConnectivityProbing):**
    - 测试在数据包重新排序的情况下，连接探测功能是否正常工作。
    - 模拟客户端 IP 地址变化，并延迟发送连接探测包。
    - **假设输入:** 客户端先发送一个请求，然后模拟 IP 地址变化，并延迟发送连接探测包，之后再次发送请求。
    - **预期输出:** 服务器和客户端都正确接收到连接探测包。

21. **客户端验证新网络 (ClientValidateNewNetwork):**
    - 测试客户端主动验证新的网络路径。
    - 模拟客户端 IP 地址变化并调用 `ValidateNewNetwork`。
    - **假设输入:** 客户端连接后，模拟 IP 地址变化并调用 `ValidateNewNetwork`，然后发送请求。
    - **预期输出:** 客户端和服务器都收到了连接性探测相关的帧。

22. **客户端多路连接 (ClientMultiPortConnection):**
    - 测试客户端使用多路连接功能，周期性地探测其他网络路径。
    - **假设输入:** 客户端启用多路连接功能并发送请求。
    - **预期输出:** 客户端和服务器都收到了路径响应帧，且在探测路径失败后，之前的路径被禁用。

23. **路径退化时客户端端口迁移 (ClientPortMigrationOnPathDegrading):**
    - 测试当网络路径质量下降时，客户端是否能迁移到新的本地端口。
    - 模拟服务器丢弃发送到客户端当前地址的数据包。
    - **假设输入:** 客户端连接后，服务器开始丢弃发送到客户端当前端口的数据包。
    - **预期输出:** 客户端迁移到新的本地端口。

24. **限制路径退化时的客户端端口迁移 (ClientLimitPortMigrationOnPathDegrading):**
    - 测试客户端在路径退化时迁移端口的次数限制。
    - 手动触发多次路径退化。
    - **假设输入:** 客户端连接后，人为触发多次路径退化。
    - **预期输出:** 客户端迁移端口的次数受到 `quic_max_num_path_degrading_to_mitigate` Flag 的限制。

**与 JavaScript 的关系:**

这个 C++ 文件是 Chromium 网络栈的一部分，负责 QUIC 协议的实现。JavaScript 在浏览器中发起网络请求时，如果启用了 HTTP/3 (基于 QUIC)，底层的通信就会使用这里测试的代码。

* **例子:**  当 JavaScript 代码使用 `fetch()` API 向一个支持 HTTP/3 的服务器发送一个 POST 请求，并且请求头的大小超过了服务器的限制时，`WayTooLongRequestHeaders` 这个测试所覆盖的逻辑就会在浏览器中执行，最终导致请求失败，并可能在浏览器的开发者工具中显示相应的 QUIC 错误信息。

**逻辑推理的假设输入与输出:**

上面每个具体功能列举中已经包含了假设输入与输出的说明。

**涉及用户或编程常见的使用错误:**

* **服务器配置错误:** 如果服务器没有正确配置以支持 HTTP/3 或 QUIC 的某些特性（例如，尾部），相关的测试就会失败。这对应于实际开发中服务器配置不当的问题。
* **客户端配置错误:**  如果客户端配置了与服务器不兼容的 QUIC 版本或参数，连接可能会失败，这与测试中预共享密钥不匹配的场景类似。
* **处理异步操作不当:**  在进行网络编程时，没有正确处理异步操作（例如，等待响应完成）会导致程序行为不可预测，这在测试中通过使用 `WaitForResponse()` 和 `WaitForDelayedAcks()` 来避免。
* **对数据大小的假设不正确:** 在发送或接收大量数据时，没有考虑到网络 MTU 或 QUIC 的分片机制，可能导致数据传输失败或性能问题，这与测试中关于大 POST 请求和大 Response 响应的测试相关。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户访问一个支持 HTTP/3 的网站:**  用户的浏览器尝试使用 HTTP/3 与服务器建立连接。
2. **发送包含特定特征的请求:** 例如，用户填写了一个包含大量数据的表单并提交（对应大 POST 请求），或者服务器返回了非常大的响应（对应大 Response 响应）。
3. **网络层遇到问题:**  例如，网络拥塞导致丢包，或者服务器对请求头的大小有限制。
4. **QUIC 代码被触发:**  Chromium 的 QUIC 协议实现（这部分测试的目标代码）开始处理这些网络事件或请求特征。
5. **触发特定的测试场景:**  例如，如果请求头过大，就会触发 `WayTooLongRequestHeaders` 测试所覆盖的代码路径。
6. **观察到错误或异常行为:**  用户可能会看到网页加载失败、错误提示或者网络请求超时。
7. **开发者进行调试:**  开发者可以使用 Chromium 的网络日志工具 ( `chrome://net-export/`) 来捕获网络事件，分析 QUIC 连接的细节，并可能通过错误码或行为模式追踪到 `end_to_end_test.cc` 中的相关测试用例，从而理解问题的根源。

**总结 (第 7 部分的功能):**

总而言之，`net/third_party/quiche/src/quiche/quic/core/http/end_to_end_test.cc` 文件的第 7 部分是一个深入的测试集，用于验证 QUIC 协议在处理各种复杂场景下的正确性和健壮性，特别是关注错误处理、大数据传输、连接管理以及一些高级特性如多路连接和连接迁移。 这些测试确保了 Chromium 的网络栈在实际用户使用中能够可靠地运行。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/end_to_end_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
headers processing to trigger the error response
  // before the request FIN is processed but receive the request FIN before the
  // response is sent completely.
  const uint32_t kRequestBodySize = kMaxOutgoingPacketSize + 10;
  std::string request_body(kRequestBodySize, 'a');

  // Send the request.
  client_->SendMessage(headers, request_body);
  client_->WaitForResponse();
  CheckResponseHeaders("500");

  // Pause the server so we can access the server's internals without races.
  server_thread_->Pause();

  QuicDispatcher* dispatcher =
      QuicServerPeer::GetDispatcher(server_thread_->server());
  QuicSession* server_session =
      QuicDispatcherPeer::GetFirstSessionIfAny(dispatcher);
  EXPECT_TRUE(server_session != nullptr);

  // The stream is not waiting for the arrival of the peer's final offset.
  EXPECT_EQ(
      0u, QuicSessionPeer::GetLocallyClosedStreamsHighestOffset(server_session)
              .size());

  server_thread_->Resume();
}

TEST_P(EndToEndTest, Trailers) {
  // Test sending and receiving HTTP/2 Trailers (trailing HEADERS frames).
  ASSERT_TRUE(Initialize());
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());

  // Set reordering to ensure that Trailers arriving before body is ok.
  SetPacketSendDelay(QuicTime::Delta::FromMilliseconds(2));
  SetReorderPercentage(30);

  // Add a response with headers, body, and trailers.
  const std::string kBody = "body content";

  HttpHeaderBlock headers;
  headers[":status"] = "200";
  headers["content-length"] = absl::StrCat(kBody.size());

  HttpHeaderBlock trailers;
  trailers["some-trailing-header"] = "trailing-header-value";

  memory_cache_backend_.AddResponse(server_hostname_, "/trailer_url",
                                    std::move(headers), kBody,
                                    trailers.Clone());

  SendSynchronousRequestAndCheckResponse("/trailer_url", kBody);
  EXPECT_EQ(trailers, client_->response_trailers());
}

// TODO(fayang): this test seems to cause net_unittests timeouts :|
TEST_P(EndToEndTest, DISABLED_TestHugePostWithPacketLoss) {
  // This test tests a huge post with introduced packet loss from client to
  // server and body size greater than 4GB, making sure QUIC code does not break
  // for 32-bit builds.
  ServerStreamThatDropsBodyFactory stream_factory;
  SetSpdyStreamFactory(&stream_factory);
  ASSERT_TRUE(Initialize());

  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  SetPacketLossPercentage(1);
  // To avoid storing the whole request body in memory, use a loop to repeatedly
  // send body size of kSizeBytes until the whole request body size is reached.
  const int kSizeBytes = 128 * 1024;
  // Request body size is 4G plus one more kSizeBytes.
  int64_t request_body_size_bytes = pow(2, 32) + kSizeBytes;
  ASSERT_LT(INT64_C(4294967296), request_body_size_bytes);
  std::string body(kSizeBytes, 'a');

  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;
  headers["content-length"] = absl::StrCat(request_body_size_bytes);

  client_->SendMessage(headers, "", /*fin=*/false);

  for (int i = 0; i < request_body_size_bytes / kSizeBytes; ++i) {
    bool fin = (i == request_body_size_bytes - 1);
    client_->SendData(std::string(body.data(), kSizeBytes), fin);
    client_->client()->WaitForEvents();
  }
  VerifyCleanConnection(true);
}

// TODO(fayang): this test seems to cause net_unittests timeouts :|
TEST_P(EndToEndTest, DISABLED_TestHugeResponseWithPacketLoss) {
  // This test tests a huge response with introduced loss from server to client
  // and body size greater than 4GB, making sure QUIC code does not break for
  // 32-bit builds.
  const int kSizeBytes = 128 * 1024;
  int64_t response_body_size_bytes = pow(2, 32) + kSizeBytes;
  ASSERT_LT(4294967296, response_body_size_bytes);
  ServerStreamThatSendsHugeResponseFactory stream_factory(
      response_body_size_bytes);
  SetSpdyStreamFactory(&stream_factory);

  StartServer();

  // Use a quic client that drops received body.
  QuicTestClient* client =
      new QuicTestClient(server_address_, server_hostname_, client_config_,
                         client_supported_versions_);
  client->client()->set_drop_response_body(true);
  client->UseWriter(client_writer_);
  client->Connect();
  client_.reset(client);
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  client_writer_->Initialize(
      QuicConnectionPeer::GetHelper(client_connection),
      QuicConnectionPeer::GetAlarmFactory(client_connection),
      std::make_unique<ClientDelegate>(client_->client()));
  initialized_ = true;
  ASSERT_TRUE(client_->client()->connected());

  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  SetPacketLossPercentage(1);
  client_->SendRequest("/huge_response");
  client_->WaitForResponse();
  VerifyCleanConnection(true);
}

TEST_P(EndToEndTest, ReleaseHeadersStreamBufferWhenIdle) {
  // Tests that when client side has no active request,
  // its headers stream's sequencer buffer should be released.
  ASSERT_TRUE(Initialize());
  client_->SendSynchronousRequest("/foo");
  if (version_.UsesHttp3()) {
    return;
  }
  QuicSpdyClientSession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  QuicHeadersStream* headers_stream =
      QuicSpdySessionPeer::GetHeadersStream(client_session);
  ASSERT_TRUE(headers_stream);
  QuicStreamSequencer* sequencer = QuicStreamPeer::sequencer(headers_stream);
  ASSERT_TRUE(sequencer);
  EXPECT_FALSE(QuicStreamSequencerPeer::IsUnderlyingBufferAllocated(sequencer));
}

// A single large header value causes a different error than the total size of
// headers exceeding a smaller limit, tested at EndToEndTest.LargeHeaders.
TEST_P(EndToEndTest, WayTooLongRequestHeaders) {
  ASSERT_TRUE(Initialize());

  HttpHeaderBlock headers;
  headers[":method"] = "GET";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;
  headers["key"] = std::string(2 * 1024 * 1024, 'a');

  client_->SendMessage(headers, "");
  client_->WaitForResponse();
  if (version_.UsesHttp3()) {
    EXPECT_THAT(client_->connection_error(),
                IsError(QUIC_QPACK_DECOMPRESSION_FAILED));
  } else {
    EXPECT_THAT(client_->connection_error(),
                IsError(QUIC_HPACK_VALUE_TOO_LONG));
  }
}

class WindowUpdateObserver : public QuicConnectionDebugVisitor {
 public:
  WindowUpdateObserver() : num_window_update_frames_(0), num_ping_frames_(0) {}

  size_t num_window_update_frames() const { return num_window_update_frames_; }

  size_t num_ping_frames() const { return num_ping_frames_; }

  void OnWindowUpdateFrame(const QuicWindowUpdateFrame& /*frame*/,
                           const QuicTime& /*receive_time*/) override {
    ++num_window_update_frames_;
  }

  void OnPingFrame(const QuicPingFrame& /*frame*/,
                   const QuicTime::Delta /*ping_received_delay*/) override {
    ++num_ping_frames_;
  }

 private:
  size_t num_window_update_frames_;
  size_t num_ping_frames_;
};

TEST_P(EndToEndTest, WindowUpdateInAck) {
  ASSERT_TRUE(Initialize());
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  WindowUpdateObserver observer;
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  client_connection->set_debug_visitor(&observer);
  // 100KB body.
  std::string body(100 * 1024, 'a');
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;

  EXPECT_EQ(kFooResponseBody,
            client_->SendCustomSynchronousRequest(headers, body));
  client_->Disconnect();
  EXPECT_LT(0u, observer.num_window_update_frames());
  EXPECT_EQ(0u, observer.num_ping_frames());
  client_connection->set_debug_visitor(nullptr);
}

TEST_P(EndToEndTest, SendStatelessResetTokenInShlo) {
  ASSERT_TRUE(Initialize());
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  QuicSpdyClientSession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  QuicConfig* config = client_session->config();
  ASSERT_TRUE(config);
  EXPECT_TRUE(config->HasReceivedStatelessResetToken());
  QuicConnection* client_connection = client_session->connection();
  ASSERT_TRUE(client_connection);
  EXPECT_EQ(QuicUtils::GenerateStatelessResetToken(
                client_connection->connection_id()),
            config->ReceivedStatelessResetToken());
  client_->Disconnect();
}

// Regression test for b/116200989.
TEST_P(EndToEndTest,
       SendStatelessResetIfServerConnectionClosedLocallyDuringHandshake) {
  connect_to_server_on_initialize_ = false;
  ASSERT_TRUE(Initialize());

  ASSERT_TRUE(server_thread_);
  server_thread_->Pause();
  QuicDispatcher* dispatcher =
      QuicServerPeer::GetDispatcher(server_thread_->server());
  if (dispatcher == nullptr) {
    ADD_FAILURE() << "Missing dispatcher";
    server_thread_->Resume();
    return;
  }
  if (dispatcher->NumSessions() > 0) {
    ADD_FAILURE() << "Dispatcher session map not empty";
    server_thread_->Resume();
    return;
  }
  // Note: this writer will only used by the server connection, not the time
  // wait list.
  QuicDispatcherPeer::UseWriter(
      dispatcher,
      // This cause the first server-sent packet, a.k.a REJ, to fail.
      new BadPacketWriter(/*packet_causing_write_error=*/0, EPERM));
  server_thread_->Resume();

  client_.reset(CreateQuicClient(client_writer_));
  EXPECT_EQ("", client_->SendSynchronousRequest("/foo"));
  EXPECT_THAT(client_->connection_error(),
              IsError(QUIC_HANDSHAKE_FAILED_SYNTHETIC_CONNECTION_CLOSE));
}

// Regression test for b/116200989.
TEST_P(EndToEndTest,
       SendStatelessResetIfServerConnectionClosedLocallyAfterHandshake) {
  // Prevent the connection from expiring in the time wait list.
  SetQuicFlag(quic_time_wait_list_seconds, 10000);
  connect_to_server_on_initialize_ = false;
  ASSERT_TRUE(Initialize());

  // big_response_body is 64K, which is about 48 full-sized packets.
  const size_t kBigResponseBodySize = 65536;
  QuicData big_response_body(new char[kBigResponseBodySize](),
                             kBigResponseBodySize, /*owns_buffer=*/true);
  AddToCache("/big_response", 200, big_response_body.AsStringPiece());

  ASSERT_TRUE(server_thread_);
  server_thread_->Pause();
  QuicDispatcher* dispatcher =
      QuicServerPeer::GetDispatcher(server_thread_->server());
  if (dispatcher == nullptr) {
    ADD_FAILURE() << "Missing dispatcher";
    server_thread_->Resume();
    return;
  }
  if (dispatcher->NumSessions() > 0) {
    ADD_FAILURE() << "Dispatcher session map not empty";
    server_thread_->Resume();
    return;
  }
  QuicDispatcherPeer::UseWriter(
      dispatcher,
      // This will cause an server write error with EPERM, while sending the
      // response for /big_response.
      new BadPacketWriter(/*packet_causing_write_error=*/20, EPERM));
  server_thread_->Resume();

  client_.reset(CreateQuicClient(client_writer_));

  // First, a /foo request with small response should succeed.
  SendSynchronousFooRequestAndCheckResponse();

  // Second, a /big_response request with big response should fail.
  EXPECT_LT(client_->SendSynchronousRequest("/big_response").length(),
            kBigResponseBodySize);
  EXPECT_THAT(client_->connection_error(), IsError(QUIC_PUBLIC_RESET));
}

// Regression test of b/70782529.
TEST_P(EndToEndTest, DoNotCrashOnPacketWriteError) {
  ASSERT_TRUE(Initialize());
  BadPacketWriter* bad_writer =
      new BadPacketWriter(/*packet_causing_write_error=*/5,
                          /*error_code=*/90);
  std::unique_ptr<QuicTestClient> client(CreateQuicClient(bad_writer));

  // 1 MB body.
  std::string body(1024 * 1024, 'a');
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;

  client->SendCustomSynchronousRequest(headers, body);
}

// Regression test for b/71711996. This test sends a connectivity probing packet
// as its last sent packet, and makes sure the server's ACK of that packet does
// not cause the client to fail.
TEST_P(EndToEndTest, LastPacketSentIsConnectivityProbing) {
  ASSERT_TRUE(Initialize());

  SendSynchronousFooRequestAndCheckResponse();

  // Wait for the client's ACK (of the response) to be received by the server.
  client_->WaitForDelayedAcks();

  // We are sending a connectivity probing packet from an unchanged client
  // address, so the server will not respond to us with a connectivity probing
  // packet, however the server should send an ack-only packet to us.
  client_->SendConnectivityProbing();

  // Wait for the server's last ACK to be received by the client.
  client_->WaitForDelayedAcks();
}

TEST_P(EndToEndTest, PreSharedKey) {
  client_config_.set_max_time_before_crypto_handshake(
      QuicTime::Delta::FromSeconds(5));
  client_config_.set_max_idle_time_before_crypto_handshake(
      QuicTime::Delta::FromSeconds(5));
  pre_shared_key_client_ = "foobar";
  pre_shared_key_server_ = "foobar";

  if (version_.UsesTls()) {
    // TODO(b/154162689) add PSK support to QUIC+TLS.
    InitializeAndCheckForTlsPskFailure();
    return;
  }

  ASSERT_TRUE(Initialize());

  SendSynchronousFooRequestAndCheckResponse();
}

// TODO: reenable once we have a way to make this run faster.
TEST_P(EndToEndTest, QUIC_TEST_DISABLED_IN_CHROME(PreSharedKeyMismatch)) {
  client_config_.set_max_time_before_crypto_handshake(
      QuicTime::Delta::FromSeconds(1));
  client_config_.set_max_idle_time_before_crypto_handshake(
      QuicTime::Delta::FromSeconds(1));
  pre_shared_key_client_ = "foo";
  pre_shared_key_server_ = "bar";

  if (version_.UsesTls()) {
    // TODO(b/154162689) add PSK support to QUIC+TLS.
    InitializeAndCheckForTlsPskFailure();
    return;
  }

  // One of two things happens when Initialize() returns:
  // 1. Crypto handshake has completed, and it is unsuccessful. Initialize()
  //    returns false.
  // 2. Crypto handshake has not completed, Initialize() returns true. The call
  //    to WaitForCryptoHandshakeConfirmed() will wait for the handshake and
  //    return whether it is successful.
  ASSERT_FALSE(Initialize() && client_->client()->WaitForOneRttKeysAvailable());
  EXPECT_THAT(client_->connection_error(), IsError(QUIC_HANDSHAKE_TIMEOUT));
}

// TODO: reenable once we have a way to make this run faster.
TEST_P(EndToEndTest, QUIC_TEST_DISABLED_IN_CHROME(PreSharedKeyNoClient)) {
  client_config_.set_max_time_before_crypto_handshake(
      QuicTime::Delta::FromSeconds(1));
  client_config_.set_max_idle_time_before_crypto_handshake(
      QuicTime::Delta::FromSeconds(1));
  pre_shared_key_server_ = "foobar";

  if (version_.UsesTls()) {
    // TODO(b/154162689) add PSK support to QUIC+TLS.
    InitializeAndCheckForTlsPskFailure(/*expect_client_failure=*/false);
    return;
  }

  ASSERT_FALSE(Initialize() && client_->client()->WaitForOneRttKeysAvailable());
  EXPECT_THAT(client_->connection_error(), IsError(QUIC_HANDSHAKE_TIMEOUT));
}

// TODO: reenable once we have a way to make this run faster.
TEST_P(EndToEndTest, QUIC_TEST_DISABLED_IN_CHROME(PreSharedKeyNoServer)) {
  client_config_.set_max_time_before_crypto_handshake(
      QuicTime::Delta::FromSeconds(1));
  client_config_.set_max_idle_time_before_crypto_handshake(
      QuicTime::Delta::FromSeconds(1));
  pre_shared_key_client_ = "foobar";

  if (version_.UsesTls()) {
    // TODO(b/154162689) add PSK support to QUIC+TLS.
    InitializeAndCheckForTlsPskFailure();
    return;
  }

  ASSERT_FALSE(Initialize() && client_->client()->WaitForOneRttKeysAvailable());
  EXPECT_THAT(client_->connection_error(), IsError(QUIC_HANDSHAKE_TIMEOUT));
}

TEST_P(EndToEndTest, RequestAndStreamRstInOnePacket) {
  // Regression test for b/80234898.
  ASSERT_TRUE(Initialize());

  // INCOMPLETE_RESPONSE will cause the server to not to send the trailer
  // (and the FIN) after the response body.
  std::string response_body(1305, 'a');
  HttpHeaderBlock response_headers;
  response_headers[":status"] = absl::StrCat(200);
  response_headers["content-length"] = absl::StrCat(response_body.length());
  memory_cache_backend_.AddSpecialResponse(
      server_hostname_, "/test_url", std::move(response_headers), response_body,
      QuicBackendResponse::INCOMPLETE_RESPONSE);

  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  client_->WaitForDelayedAcks();

  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  const QuicPacketCount packets_sent_before =
      client_connection->GetStats().packets_sent;

  client_->SendRequestAndRstTogether("/test_url");

  // Expect exactly one packet is sent from the block above.
  ASSERT_EQ(packets_sent_before + 1,
            client_connection->GetStats().packets_sent);

  // Wait for the connection to become idle.
  client_->WaitForDelayedAcks();

  // The real expectation is the test does not crash or timeout.
  EXPECT_THAT(client_->connection_error(), IsQuicNoError());
}

TEST_P(EndToEndTest, ResetStreamOnTtlExpires) {
  ASSERT_TRUE(Initialize());
  EXPECT_TRUE(client_->client()->WaitForHandshakeConfirmed());
  SetPacketLossPercentage(30);

  QuicSpdyClientStream* stream = client_->GetOrCreateStream();
  // Set a TTL which expires immediately.
  stream->MaybeSetTtl(QuicTime::Delta::FromMicroseconds(1));

  WriteHeadersOnStream(stream);
  // 1 MB body.
  std::string body(1024 * 1024, 'a');
  stream->WriteOrBufferBody(body, true);
  client_->WaitForResponse();
  EXPECT_THAT(client_->stream_error(), IsStreamError(QUIC_STREAM_TTL_EXPIRED));
}

TEST_P(EndToEndTest, SendMessages) {
  ASSERT_TRUE(Initialize());
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  QuicSession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  QuicConnection* client_connection = client_session->connection();
  ASSERT_TRUE(client_connection);

  SetPacketLossPercentage(30);
  ASSERT_GT(kMaxOutgoingPacketSize,
            client_session->GetCurrentLargestMessagePayload());
  ASSERT_LT(0, client_session->GetCurrentLargestMessagePayload());

  std::string message_string(kMaxOutgoingPacketSize, 'a');
  QuicRandom* random =
      QuicConnectionPeer::GetHelper(client_connection)->GetRandomGenerator();
  {
    QuicConnection::ScopedPacketFlusher flusher(client_session->connection());
    // Verify the largest message gets successfully sent.
    EXPECT_EQ(MessageResult(MESSAGE_STATUS_SUCCESS, 1),
              client_session->SendMessage(MemSliceFromString(absl::string_view(
                  message_string.data(),
                  client_session->GetCurrentLargestMessagePayload()))));
    // Send more messages with size (0, largest_payload] until connection is
    // write blocked.
    const int kTestMaxNumberOfMessages = 100;
    for (size_t i = 2; i <= kTestMaxNumberOfMessages; ++i) {
      size_t message_length =
          random->RandUint64() %
              client_session->GetGuaranteedLargestMessagePayload() +
          1;
      MessageResult result = client_session->SendMessage(MemSliceFromString(
          absl::string_view(message_string.data(), message_length)));
      if (result.status == MESSAGE_STATUS_BLOCKED) {
        // Connection is write blocked.
        break;
      }
      EXPECT_EQ(MessageResult(MESSAGE_STATUS_SUCCESS, i), result);
    }
  }

  client_->WaitForDelayedAcks();
  EXPECT_EQ(MESSAGE_STATUS_TOO_LARGE,
            client_session
                ->SendMessage(MemSliceFromString(absl::string_view(
                    message_string.data(),
                    client_session->GetCurrentLargestMessagePayload() + 1)))
                .status);
  EXPECT_THAT(client_->connection_error(), IsQuicNoError());
}

class EndToEndPacketReorderingTest : public EndToEndTest {
 public:
  void CreateClientWithWriter() override {
    QUIC_LOG(ERROR) << "create client with reorder_writer_";
    reorder_writer_ = new PacketReorderingWriter();
    client_.reset(EndToEndTest::CreateQuicClient(reorder_writer_));
  }

  void SetUp() override {
    // Don't initialize client writer in base class.
    server_writer_ = new PacketDroppingTestWriter();
  }

 protected:
  PacketReorderingWriter* reorder_writer_;
};

INSTANTIATE_TEST_SUITE_P(EndToEndPacketReorderingTests,
                         EndToEndPacketReorderingTest,
                         ::testing::ValuesIn(GetTestParams()),
                         ::testing::PrintToStringParamName());

TEST_P(EndToEndPacketReorderingTest, ReorderedConnectivityProbing) {
  ASSERT_TRUE(Initialize());
  if (version_.HasIetfQuicFrames() ||
      GetQuicReloadableFlag(quic_ignore_gquic_probing)) {
    return;
  }

  // Finish one request to make sure handshake established.
  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest("/foo"));

  // Wait for the connection to become idle, to make sure the packet gets
  // delayed is the connectivity probing packet.
  client_->WaitForDelayedAcks();

  QuicSocketAddress old_addr =
      client_->client()->network_helper()->GetLatestClientAddress();

  // Migrate socket to the new IP address.
  QuicIpAddress new_host = TestLoopback(2);
  EXPECT_NE(old_addr.host(), new_host);
  ASSERT_TRUE(client_->client()->MigrateSocket(new_host));

  // Write a connectivity probing after the next /foo request.
  reorder_writer_->SetDelay(1);
  client_->SendConnectivityProbing();

  ASSERT_TRUE(client_->MigrateSocketWithSpecifiedPort(old_addr.host(),
                                                      old_addr.port()));

  // The (delayed) connectivity probing will be sent after this request.
  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest("/foo"));

  // Send yet another request after the connectivity probing, when this request
  // returns, the probing is guaranteed to have been received by the server, and
  // the server's response to probing is guaranteed to have been received by the
  // client.
  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest("/foo"));

  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  if (server_connection != nullptr) {
    EXPECT_EQ(1u,
              server_connection->GetStats().num_connectivity_probing_received);
  } else {
    ADD_FAILURE() << "Missing server connection";
  }
  server_thread_->Resume();

  // Server definitely responded to the connectivity probing. Sometime it also
  // sends a padded ping that is not a connectivity probing, which is recognized
  // as connectivity probing because client's self address is ANY.
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  EXPECT_LE(1u,
            client_connection->GetStats().num_connectivity_probing_received);
}

// A writer which holds the next packet to be sent till ReleasePacket() is
// called.
class PacketHoldingWriter : public QuicPacketWriterWrapper {
 public:
  WriteResult WritePacket(const char* buffer, size_t buf_len,
                          const QuicIpAddress& self_address,
                          const QuicSocketAddress& peer_address,
                          PerPacketOptions* options,
                          const QuicPacketWriterParams& params) override {
    if (!hold_next_packet_) {
      return QuicPacketWriterWrapper::WritePacket(
          buffer, buf_len, self_address, peer_address, options, params);
    }
    QUIC_DLOG(INFO) << "Packet is held by the writer";
    packet_content_ = std::string(buffer, buf_len);
    self_address_ = self_address;
    peer_address_ = peer_address;
    options_ = (options == nullptr ? nullptr : options->Clone());
    hold_next_packet_ = false;
    return WriteResult(WRITE_STATUS_OK, buf_len);
  }

  void HoldNextPacket() {
    QUICHE_DCHECK(packet_content_.empty())
        << "There is already one packet on hold.";
    hold_next_packet_ = true;
  }

  void ReleasePacket() {
    QUIC_DLOG(INFO) << "Release packet";
    ASSERT_EQ(WRITE_STATUS_OK,
              QuicPacketWriterWrapper::WritePacket(
                  packet_content_.data(), packet_content_.length(),
                  self_address_, peer_address_, options_.release(), params_)
                  .status);
    packet_content_.clear();
  }

 private:
  bool hold_next_packet_{false};
  std::string packet_content_;
  QuicIpAddress self_address_;
  QuicSocketAddress peer_address_;
  std::unique_ptr<PerPacketOptions> options_;
  QuicPacketWriterParams params_;
};

TEST_P(EndToEndTest, ClientValidateNewNetwork) {
  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames()) {
    return;
  }
  client_.reset(EndToEndTest::CreateQuicClient(nullptr));
  SendSynchronousFooRequestAndCheckResponse();

  // Store the client IP address which was used to send the first request.
  QuicIpAddress old_host =
      client_->client()->network_helper()->GetLatestClientAddress().host();

  // Migrate socket to the new IP address.
  QuicIpAddress new_host = TestLoopback(2);
  EXPECT_NE(old_host, new_host);

  client_->client()->ValidateNewNetwork(new_host);
  // Send a request using the old socket.
  EXPECT_EQ(kBarResponseBody, client_->SendSynchronousRequest("/bar"));
  // Client should have received a PATH_CHALLENGE.
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  EXPECT_EQ(1u,
            client_connection->GetStats().num_connectivity_probing_received);

  // Send another request to make sure THE server will receive PATH_RESPONSE.
  client_->SendSynchronousRequest("/eep");

  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  if (server_connection != nullptr) {
    EXPECT_EQ(1u,
              server_connection->GetStats().num_connectivity_probing_received);
  } else {
    ADD_FAILURE() << "Missing server connection";
  }
  server_thread_->Resume();
}

TEST_P(EndToEndTest, ClientMultiPortConnection) {
  client_config_.SetClientConnectionOptions(QuicTagVector{kMPQC, kMPQM});
  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames()) {
    return;
  }
  client_.reset(EndToEndTest::CreateQuicClient(nullptr));
  QuicConnection* client_connection = GetClientConnection();
  QuicSpdyClientStream* stream = client_->GetOrCreateStream();
  ASSERT_TRUE(stream);
  // Increase the probing frequency to speed up this test.
  client_connection->SetMultiPortProbingInterval(
      QuicTime::Delta::FromMilliseconds(100));
  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_TRUE(client_->WaitUntil(1000, [&]() {
    return 1u == client_connection->GetStats().num_path_response_received;
  }));
  // Verify that the alternative path keeps sending probes periodically.
  EXPECT_TRUE(client_->WaitUntil(1000, [&]() {
    return 2u == client_connection->GetStats().num_path_response_received;
  }));
  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  // Verify that no migration has happened.
  if (server_connection != nullptr) {
    EXPECT_EQ(0u, server_connection->GetStats()
                      .num_peer_migration_to_proactively_validated_address);
  }
  server_thread_->Resume();

  // This will cause the next periodic probing to fail.
  server_writer_->set_fake_packet_loss_percentage(100);
  EXPECT_TRUE(client_->WaitUntil(
      1000, [&]() { return client_->client()->HasPendingPathValidation(); }));
  // Now wait for path validation to timeout.
  EXPECT_TRUE(client_->WaitUntil(
      2000, [&]() { return !client_->client()->HasPendingPathValidation(); }));
  server_writer_->set_fake_packet_loss_percentage(0);
  EXPECT_TRUE(client_->WaitUntil(1000, [&]() {
    return 3u == client_connection->GetStats().num_path_response_received;
  }));
  // Verify that the previous path was retired.
  EXPECT_EQ(1u, client_connection->GetStats().num_retire_connection_id_sent);
  stream->Reset(QuicRstStreamErrorCode::QUIC_STREAM_NO_ERROR);
}

TEST_P(EndToEndTest, ClientPortMigrationOnPathDegrading) {
  connect_to_server_on_initialize_ = false;
  Initialize();
  if (!version_.HasIetfQuicFrames()) {
    CreateClientWithWriter();
    return;
  }

  server_thread_->Pause();
  QuicDispatcher* dispatcher =
      QuicServerPeer::GetDispatcher(server_thread_->server());
  if (dispatcher == nullptr) {
    ADD_FAILURE() << "Missing dispatcher";
    server_thread_->Resume();
    return;
  }
  if (dispatcher->NumSessions() > 0) {
    ADD_FAILURE() << "Dispatcher session map not empty";
    server_thread_->Resume();
    return;
  }
  auto* new_writer = new DroppingPacketsWithSpecificDestinationWriter();
  // Note: this writer will only used by the server connection, not the time
  // wait list.
  QuicDispatcherPeer::UseWriter(dispatcher, new_writer);
  server_thread_->Resume();

  delete client_writer_;
  client_.reset(EndToEndTest::CreateQuicClient(nullptr));
  client_->client()->EnablePortMigrationUponPathDegrading(std::nullopt);
  ASSERT_TRUE(client_->client()->WaitForHandshakeConfirmed());
  QuicConnection* client_connection = GetClientConnection();
  QuicSocketAddress original_self_addr = client_connection->self_address();
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/bar";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;
  client_->SendMessage(headers, "aaaa", false);

  // This causes the all server sent packets to the client's current address to
  // be dropped.
  new_writer->set_peer_address_to_drop(original_self_addr);
  client_->SendData("bbbb", true);
  // The response will be dropped till client migrates to a different port.
  client_->WaitForResponse();
  QuicSocketAddress new_self_addr1 = client_connection->self_address();
  EXPECT_NE(original_self_addr, new_self_addr1);
  EXPECT_EQ(1u, GetClientConnection()->GetStats().num_path_degrading);
  EXPECT_EQ(1u, GetClientConnection()
                    ->GetStats()
                    .num_forward_progress_after_path_degrading);
  EXPECT_EQ(1u, GetClientConnection()->GetStats().num_path_response_received);
  size_t pto_count = GetClientConnection()->GetStats().pto_count;

  // Wait for new connection id to be received.
  WaitForNewConnectionIds();
  // Use 1 PTO to detect path degrading more aggressively.
  client_->client()->EnablePortMigrationUponPathDegrading({1});
  new_writer->set_peer_address_to_drop(new_self_addr1);
  client_->SendSynchronousRequest("/eep");
  QuicSocketAddress new_self_addr2 = client_connection->self_address();
  EXPECT_NE(new_self_addr1, new_self_addr2);
  EXPECT_EQ(2u, GetClientConnection()->GetStats().num_path_degrading);
  EXPECT_EQ(2u, GetClientConnection()
                    ->GetStats()
                    .num_forward_progress_after_path_degrading);
  EXPECT_EQ(2u, GetClientConnection()->GetStats().num_path_response_received);
  // It should take fewer PTOs to trigger port migration than the default(4).
  EXPECT_GT(pto_count + 4, GetClientConnection()->GetStats().pto_count);
}

TEST_P(EndToEndTest, ClientLimitPortMigrationOnPathDegrading) {
  connect_to_server_on_initialize_ = false;
  Initialize();
  if (!version_.HasIetfQuicFrames()) {
    CreateClientWithWriter();
    return;
  }
  const uint32_t max_num_path_degrading_to_mitigate =
      GetQuicFlag(quic_max_num_path_degrading_to_mitigate);

  delete client_writer_;
  client_.reset(EndToEndTest::CreateQuicClient(nullptr));
  client_->client()->EnablePortMigrationUponPathDegrading(std::nullopt);
  ASSERT_TRUE(client_->client()->WaitForHandshakeConfirmed());
  QuicConnection* client_connection = GetClientConnection();
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/bar";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;
  // Manually trigger path degrading 5 times and expect they should all trigger
  // port migration.
  for (uint32_t i = 0; i < max_num_path_degrading_to_mitigate; ++i) {
    client_->SendMessage(headers, "aaaa", false);
    QuicSocketAddress original_self_addr = client_connection->self_address();
    WaitForNewConnectionIds();
    client_connection->OnPathDegradingDetected();
    client_->SendData("bbbb", true);
    client_->WaitForResponse();
    while (client_->client()->HasPendingPathValidation()) {
      client_->client()->WaitForEvents();
    }
    QuicSocketAddress new_self_addr = client_connection->self_address();
    EXPECT_NE(original_self_addr, new_self_addr);
  }

  EXPECT_EQ(max_num_path_degrading_to_mitigate,
            GetClientConnection()->GetStats().num_path_degrading);
  EXPECT_EQ(max_num_path_degrading_to_mitigate,
            GetClientConnection()->GetStats().num_path_response_received);

  //
```