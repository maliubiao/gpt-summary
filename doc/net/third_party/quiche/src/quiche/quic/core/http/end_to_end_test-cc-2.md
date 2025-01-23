Response:
Let's break down the thought process for analyzing this code snippet.

**1. Initial Understanding and Context:**

* **Identify the language and framework:** The `.cc` extension and `TEST_P`, `ASSERT_TRUE`, `EXPECT_EQ` strongly indicate C++ and a testing framework (likely Google Test or a similar framework used within Chromium). The file path `net/third_party/quiche/src/quiche/quic/core/http/end_to_end_test.cc` gives crucial context: this is part of the QUIC implementation in Chromium, specifically for end-to-end HTTP testing.
* **Determine the core purpose:** The filename "end_to_end_test.cc" immediately suggests that the primary goal of this code is to verify the correct interaction and functionality between a QUIC client and a QUIC server in various scenarios. It's not about individual unit testing of small components, but about testing the system as a whole.
* **Recognize the iterative nature:** The prompt mentions "part 3 of 10". This tells us that the full file is large and the current snippet is just a portion. The analysis should focus on what this specific section does, but keep in mind it's part of a larger testing suite.

**2. Analyzing the Code Structure (Test Cases):**

* **Identify test functions:**  The code is organized into functions starting with `TEST_P(EndToEndTest, ...)` or `TEST(EndToEndTest, ...)`. These are individual test cases within the `EndToEndTest` class. Each test case represents a specific scenario being tested.
* **Understand the test setup and execution flow:**  Most test cases follow a pattern:
    1. **Conditional Initialization:** Some tests have `if` conditions at the beginning that might skip the test based on the current QUIC version or configuration. This is important for understanding which scenarios are relevant for different QUIC implementations. `ASSERT_TRUE(Initialize());` is a common setup step, likely responsible for setting up the client and server for the test.
    2. **Action/Stimulus:** The core of the test involves the client sending requests to the server (`SendSynchronousFooRequestAndCheckResponse`, `client_->SendMessage`, `client_->SendData`, `client_->SendCustomSynchronousRequest`).
    3. **Verification/Assertions:**  The test then uses `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, and `EXPECT_THAT` to assert that the client and server behaved as expected. This includes checking response codes, body content, connection properties (like connection ID length, early data acceptance), and internal state (like received reject messages).
    4. **Cleanup (Implicit):** While not explicitly shown in every test, the testing framework handles cleanup between test cases.

**3. Identifying Key Functionality within the Snippet:**

* **Connection ID Testing:** Several tests focus on different connection ID scenarios: forced version negotiation with specific client and server CID lengths, mixing good and bad CID lengths, and zero-length connection IDs. This highlights the importance of testing various connection ID configurations.
* **Version Negotiation:** The `ForcedVersNego...` tests directly address version negotiation, a critical part of the QUIC handshake.
* **Request/Response Basics:** Many tests (`SimpleRequestResponse`, `MultipleRequestResponse`, `MultipleStreams`, `MultipleClients`) verify the fundamental ability to send requests and receive correct responses.
* **Fragmentation and Reassembly:** Tests like `RequestOverMultiplePackets` and `MultiplePacketsRandomOrder` focus on how the client and server handle requests and responses that are split into multiple packets, especially in the presence of reordering.
* **Error Handling:**  `PostMissingBytes` checks how the server handles incomplete requests.
* **Large Data Transfers:**  Tests like `LargePostNoPacketLoss`, `LargePostWithPacketLoss`, and `LargePostNoPacketLossWithDelayAndReordering` evaluate the reliability and performance of QUIC when transferring significant amounts of data, including under adverse network conditions like packet loss and reordering.
* **Zero-RTT and Resumption:** A significant portion of the snippet tests 0-RTT connection establishment (resuming a previous session), including success and failure scenarios, and scenarios where resumption is explicitly disabled.
* **Address Token:** Several tests focus on the address token mechanism, used to prevent amplification attacks and validate client addresses.
* **Packet Loss and Network Simulation:** The use of `SetPacketLossPercentage`, `SetPacketSendDelay`, and `SetReorderPercentage` indicates the testing environment simulates various network conditions to thoroughly evaluate QUIC's robustness.

**4. Connecting to JavaScript and User Behavior:**

* **JavaScript Relevance:**  The connection to JavaScript comes through the browser context. Browsers use network stacks (like the one this code is part of) to implement web protocols. Therefore, the correct functioning of this QUIC code directly impacts the performance and reliability of web applications that use QUIC, which includes many modern websites accessed via JavaScript.
* **User Actions:**  The "user actions" section of the thought process involves tracing back how a user's interaction in a browser might lead to this QUIC code being executed. This involves the user typing a URL, clicking a link, or a web application making an API call. The browser then resolves the domain, establishes a QUIC connection (potentially involving version negotiation, handling connection IDs, and potentially attempting 0-RTT if it's a repeat visit), sends HTTP requests over that connection, and processes the responses.

**5. Identifying Potential Issues and Debugging:**

* **Common Errors:** The "user/programming errors" section thinks about common mistakes in web development that might expose QUIC behavior. For example, a developer might mistakenly expect 0-RTT to always work or not handle potential failures gracefully.
* **Debugging:** The "debugging" section considers how a developer might end up looking at this code. This involves scenarios like investigating connection failures, performance problems, or issues with specific QUIC features like 0-RTT or version negotiation.

**6. Synthesizing the Summary:**

Finally, the thought process combines the individual observations into a concise summary of the code's overall function, emphasizing the key areas of testing covered by this particular snippet. The focus is on the variety of end-to-end scenarios being tested, particularly around connection establishment, data transfer, error handling, and advanced QUIC features.

**Self-Correction/Refinement during the process:**

* **Initial assumption:** One might initially focus heavily on the HTTP aspects due to the file path. However, realizing the focus on connection IDs, version negotiation, and 0-RTT shifts the emphasis to the underlying QUIC protocol itself, with HTTP being the application-level protocol being transported.
* **Understanding `TEST_P`:** Recognizing that `TEST_P` likely indicates parameterized tests (running the same test with different parameter sets, like different QUIC versions) is important for a complete understanding.
* **Connecting the dots:** The process of explicitly linking the C++ code to JavaScript and user actions is a key step in making the analysis relevant and demonstrating a broader understanding.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/http/end_to_end_test.cc` 文件的第三部分。根据提供的代码片段，我们可以归纳出以下功能：

**核心功能：QUIC HTTP 端到端测试**

这部分代码主要包含了一系列针对 QUIC 协议上的 HTTP 通信的端到端测试用例。这些测试用例旨在验证客户端和服务器在各种场景下的交互是否符合预期。测试覆盖了 QUIC 协议的多个关键特性以及 HTTP/3 的基本功能。

**具体测试场景归纳：**

1. **连接ID相关测试:**
   - **强制版本协商和不同长度的客户端/服务器连接ID:**  测试在强制进行版本协商的情况下，客户端和服务器使用不同长度的连接ID（包括长连接ID）时的行为。
   - **混合使用正常和异常长度的连接ID:**  测试客户端使用异常长度的连接ID，而另一个客户端使用正常长度的连接ID时，服务器的处理情况。
   - **零长度连接ID:** 测试使用零长度连接ID进行通信的情况。

2. **基本的请求-响应测试:**
   - **简单的请求-响应（包含 large reject 信息）:** 测试基本的 HTTP 请求和响应流程，并验证服务器发送 large reject 信息的情况。
   - **IPv6 地址下的请求-响应:** 测试客户端和服务器在 IPv6 地址下进行通信。

3. **流控制测试:**
   - **禁止在服务器发起的双向流上发送数据 (客户端/服务器端/双方):**  测试当客户端或服务器端限制在服务器发起的双向流上发送数据时的行为。

4. **数据包处理测试:**
   - **握手完成前不应有无法解密的包:**  回归测试，确保在握手完成之前，客户端和服务器不会收到无法解密的包。
   - **分离的 FIN 包:** 测试将 HTTP 请求的 FIN 标志放在单独的数据包中发送的情况。
   - **多次请求-响应:** 测试在同一个连接上发送多个请求并接收响应。
   - **多个流:** 验证客户端能够跟踪所有活动流的响应。
   - **多个客户端:** 测试多个客户端同时与服务器进行通信。
   - **跨多个数据包的请求:** 测试发送大型请求，需要跨越多个 QUIC 数据包的情况。
   - **乱序数据包:** 测试在模拟数据包乱序的网络环境下，请求和响应的处理。

5. **错误处理测试:**
   - **POST 请求缺少数据:** 测试当发送带有 `content-length` 头部的 POST 请求，但实际发送的数据不足时，服务器的响应。

6. **大数据传输测试:**
   - **大 POST 请求（无丢包）:** 测试发送大型 POST 请求，且网络状况良好（无丢包）的情况。
   - **大 POST 请求（无丢包，高 RTT）:**  测试在高 RTT 的网络环境下发送大型 POST 请求。
   - **大 POST 请求（有丢包）:** 测试在模拟丢包的网络环境下发送大型 POST 请求，验证 QUIC 的丢包恢复机制。
   - **大 POST 请求（有丢包，且总是捆绑窗口更新）:** 回归测试，模拟特定条件下的丢包情况，并验证窗口更新的处理。
   - **大 POST 请求（有丢包，socket 阻塞）:** 测试在模拟丢包和 socket 阻塞的情况下发送大型 POST 请求。
   - **大 POST 请求（无丢包，有延迟和乱序）:** 测试在模拟延迟和乱序的网络环境下发送大型 POST 请求。

7. **0-RTT 和会话恢复测试:**
   - **Address Token (地址令牌):** 测试地址令牌机制，包括首次连接和后续的 0-RTT 连接，以及服务器重启后的处理。
   - **客户端不重用源地址令牌:** 验证客户端不会重复使用相同的源地址令牌。
   - **大 POST 请求的 0-RTT 失败:** 测试在尝试 0-RTT 连接时，如果服务器拒绝 0-RTT 数据，连接会回退到完整的握手过程。
   - **多次 0-RTT:** 测试连续进行多次 0-RTT 连接的情况。
   - **同步请求的 0-RTT 失败:**  与上面的测试类似，但使用同步请求的方式进行测试。
   - **大 POST 请求的同步请求:**  测试使用同步请求发送大型 POST 数据的情况，并验证 0-RTT 的行为。
   - **禁用会话恢复:** 测试显式禁用会话恢复功能时的连接行为。

8. **TLS 特性测试 (部分):**
   - **在握手期间发送 0-RTT 请求:** 专门针对 TLS 的测试，验证在握手过程中发送 0-RTT 请求的行为。
   - **在 0-RTT 拒绝后，1-RTT 建立前的重传:** 专门针对 TLS 的测试，验证在 0-RTT 被拒绝后，在 1-RTT 握手完成前的重传行为。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不包含 JavaScript，但它测试的网络栈是浏览器执行 JavaScript 代码的基础。

* **用户在浏览器中执行 JavaScript 发起网络请求时，最终会调用到 Chromium 的网络栈（包括 QUIC 部分）来建立连接、发送请求和接收响应。**
* 例如，如果一个 JavaScript 应用使用 `fetch()` API 向服务器发起一个 HTTPS 请求，并且浏览器和服务器协商使用了 QUIC 协议，那么这里的测试用例就间接地验证了 JavaScript 发起的请求能否正确地通过 QUIC 传输。

**举例说明：**

假设一个 JavaScript 代码如下：

```javascript
fetch('https://example.com/data', {
  method: 'POST',
  body: 'some data',
  headers: {
    'Content-Type': 'text/plain'
  }
})
.then(response => response.text())
.then(data => console.log(data));
```

当这段代码在支持 QUIC 的浏览器中执行时，如果服务器也支持 QUIC，那么 `EndToEndTest` 中的某些测试用例（如 `SimpleRequestResponse`, `LargePostNoPacketLoss`, `LargePostWithPacketLoss` 等）就在验证这种场景下的网络通信是否正常工作。

**逻辑推理 (假设输入与输出):**

以 `TEST_P(EndToEndTest, SimpleRequestResponse)` 为例：

* **假设输入:**
    * 客户端配置为支持特定的 QUIC 版本。
    * 服务器端运行并监听指定的端口。
    * 客户端向服务器发送一个针对 `/foo` 的 POST 请求，body 为 "bar"。
    * 服务器端配置为对 `/foo` 请求返回状态码 200 和 body "bar response"。

* **预期输出:**
    * 客户端成功建立与服务器的 QUIC 连接。
    * 客户端发送的请求被服务器正确接收和处理。
    * 客户端接收到服务器返回的 HTTP 响应，状态码为 200，body 为 "bar response"。
    * 客户端断开连接时，连接状态是干净的（没有错误）。

**用户或编程常见的使用错误举例说明：**

* **用户操作:** 用户可能在一个网络不稳定的环境下访问一个使用了 QUIC 的网站。 `LargePostWithPacketLoss` 等测试用例模拟了这种场景，验证 QUIC 是否能在这种情况下可靠地传输数据。如果 QUIC 实现有缺陷，用户可能会遇到请求失败、数据丢失或连接中断等问题。
* **编程错误:**  开发者在配置服务器时，可能错误地配置了支持的 QUIC 版本或连接ID长度。 `ForcedVersNegoAndClientCIDAndLongCID` 和 `MixGoodAndBadConnectionIdLengths` 等测试用例可以帮助发现这类配置错误导致的问题。例如，如果服务器不支持客户端发送的连接ID长度，可能会导致连接建立失败。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入网址或点击链接 (例如: `https://example.com`)。**
2. **浏览器首先会进行 DNS 查询解析域名 `example.com` 的 IP 地址。**
3. **浏览器尝试与服务器建立连接，并会尝试使用 QUIC 协议 (如果浏览器和服务器都支持)。**
4. **QUIC 连接建立过程会涉及到版本协商、连接ID的交换等 (对应 `ForcedVersNego...` 等测试用例)。**
5. **浏览器通过建立的 QUIC 连接发送 HTTP 请求 (对应 `SimpleRequestResponse` 等测试用例)。**
6. **如果用户上传大文件或网页包含大量资源，可能会触发类似 `LargePost...` 的测试场景。**
7. **如果网络环境不稳定，发生丢包或延迟，会触发类似 `LargePostWithPacketLoss` 或 `MultiplePacketsRandomOrder` 的测试场景。**
8. **当开发者在调试网络问题时，可能会查看 Chromium 的网络日志，如果涉及到 QUIC 连接的问题，就可能会深入到 QUIC 的源代码进行分析，而 `end_to_end_test.cc` 中的测试用例可以帮助理解 QUIC 的行为和查找问题根源。**

**总结：**

这段代码是 QUIC HTTP 端到端测试套件的一部分，专注于验证 QUIC 协议在传输 HTTP 数据时的各种场景，包括连接管理、数据传输、错误处理以及高级特性如 0-RTT 和会话恢复。这些测试确保了 Chromium 网络栈中 QUIC 实现的正确性和健壮性，从而保证用户在使用基于 QUIC 的网络服务时的良好体验。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/end_to_end_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
ion_id()
                                                .length());
}

// Forced Version Negotiation with a client connection ID and a long
// connection ID.
TEST_P(EndToEndTest, ForcedVersNegoAndClientCIDAndLongCID) {
  if (!version_.SupportsClientConnectionIds() ||
      !version_.AllowsVariableLengthConnectionIds() ||
      override_server_connection_id_length_ != kLongConnectionIdLength) {
    ASSERT_TRUE(Initialize());
    return;
  }
  client_supported_versions_.insert(client_supported_versions_.begin(),
                                    QuicVersionReservedForNegotiation());
  override_client_connection_id_length_ = 18;
  ASSERT_TRUE(Initialize());
  ASSERT_TRUE(ServerSendsVersionNegotiation());
  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_EQ(kQuicDefaultConnectionIdLength, client_->client()
                                                ->client_session()
                                                ->connection()
                                                ->connection_id()
                                                .length());
  EXPECT_EQ(override_client_connection_id_length_, client_->client()
                                                       ->client_session()
                                                       ->connection()
                                                       ->client_connection_id()
                                                       .length());
}

TEST_P(EndToEndTest, MixGoodAndBadConnectionIdLengths) {
  if (!version_.AllowsVariableLengthConnectionIds() ||
      override_server_connection_id_length_ > -1) {
    ASSERT_TRUE(Initialize());
    return;
  }

  // Start client_ which will use a bad connection ID length.
  override_server_connection_id_length_ = 9;
  ASSERT_TRUE(Initialize());
  override_server_connection_id_length_ = -1;

  // Start client2 which will use a good connection ID length.
  std::unique_ptr<QuicTestClient> client2(CreateQuicClient(nullptr));
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;
  headers["content-length"] = "3";
  client2->SendMessage(headers, "", /*fin=*/false);
  client2->SendData("eep", true);

  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_EQ(kQuicDefaultConnectionIdLength, client_->client()
                                                ->client_session()
                                                ->connection()
                                                ->connection_id()
                                                .length());

  WaitForFooResponseAndCheckIt(client2.get());
  EXPECT_EQ(kQuicDefaultConnectionIdLength, client2->client()
                                                ->client_session()
                                                ->connection()
                                                ->connection_id()
                                                .length());
}

TEST_P(EndToEndTest, SimpleRequestResponseWithLargeReject) {
  chlo_multiplier_ = 1;
  ASSERT_TRUE(Initialize());

  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_FALSE(client_->client()->EarlyDataAccepted());
  if (version_.UsesTls()) {
    // REJ messages are a QUIC crypto feature, so TLS always returns false.
    EXPECT_FALSE(client_->client()->ReceivedInchoateReject());
  } else {
    EXPECT_TRUE(client_->client()->ReceivedInchoateReject());
  }
}

TEST_P(EndToEndTest, SimpleRequestResponsev6) {
  server_address_ =
      QuicSocketAddress(QuicIpAddress::Loopback6(), server_address_.port());
  ASSERT_TRUE(Initialize());

  SendSynchronousFooRequestAndCheckResponse();
}

TEST_P(EndToEndTest,
       ClientDoesNotAllowServerDataOnServerInitiatedBidirectionalStreams) {
  set_client_initial_max_stream_data_incoming_bidirectional(0);
  ASSERT_TRUE(Initialize());
  SendSynchronousFooRequestAndCheckResponse();
}

TEST_P(EndToEndTest,
       ServerDoesNotAllowClientDataOnServerInitiatedBidirectionalStreams) {
  set_server_initial_max_stream_data_outgoing_bidirectional(0);
  ASSERT_TRUE(Initialize());
  SendSynchronousFooRequestAndCheckResponse();
}

TEST_P(EndToEndTest,
       BothEndpointsDisallowDataOnServerInitiatedBidirectionalStreams) {
  set_client_initial_max_stream_data_incoming_bidirectional(0);
  set_server_initial_max_stream_data_outgoing_bidirectional(0);
  ASSERT_TRUE(Initialize());
  SendSynchronousFooRequestAndCheckResponse();
}

// Regression test for a bug where we would always fail to decrypt the first
// initial packet. Undecryptable packets can be seen after the handshake
// is complete due to dropping the initial keys at that point, so we only test
// for undecryptable packets before then.
TEST_P(EndToEndTest, NoUndecryptablePacketsBeforeHandshakeComplete) {
  ASSERT_TRUE(Initialize());

  SendSynchronousFooRequestAndCheckResponse();

  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  QuicConnectionStats client_stats = client_connection->GetStats();
  EXPECT_EQ(
      0u,
      client_stats.undecryptable_packets_received_before_handshake_complete);

  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  if (server_connection != nullptr) {
    QuicConnectionStats server_stats = server_connection->GetStats();
    EXPECT_EQ(
        0u,
        server_stats.undecryptable_packets_received_before_handshake_complete);
  } else {
    ADD_FAILURE() << "Missing server connection";
  }
  server_thread_->Resume();
}

TEST_P(EndToEndTest, SeparateFinPacket) {
  ASSERT_TRUE(Initialize());

  // Send a request in two parts: the request and then an empty packet with FIN.
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;
  client_->SendMessage(headers, "", /*fin=*/false);
  client_->SendData("", true);
  WaitForFooResponseAndCheckIt();

  // Now do the same thing but with a content length.
  headers["content-length"] = "3";
  client_->SendMessage(headers, "", /*fin=*/false);
  client_->SendData("foo", true);
  WaitForFooResponseAndCheckIt();
}

TEST_P(EndToEndTest, MultipleRequestResponse) {
  ASSERT_TRUE(Initialize());

  SendSynchronousFooRequestAndCheckResponse();
  SendSynchronousBarRequestAndCheckResponse();
}

TEST_P(EndToEndTest, MultipleRequestResponseZeroConnectionID) {
  if (!version_.AllowsVariableLengthConnectionIds() ||
      override_server_connection_id_length_ > -1) {
    ASSERT_TRUE(Initialize());
    return;
  }
  override_server_connection_id_length_ = 0;
  expected_server_connection_id_length_ = 0;
  ASSERT_TRUE(Initialize());

  SendSynchronousFooRequestAndCheckResponse();
  SendSynchronousBarRequestAndCheckResponse();
}

TEST_P(EndToEndTest, MultipleStreams) {
  // Verifies quic_test_client can track responses of all active streams.
  ASSERT_TRUE(Initialize());

  const int kNumRequests = 10;

  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;
  headers["content-length"] = "3";

  for (int i = 0; i < kNumRequests; ++i) {
    client_->SendMessage(headers, "bar", /*fin=*/true);
  }

  while (kNumRequests > client_->num_responses()) {
    client_->ClearPerRequestState();
    ASSERT_TRUE(WaitForFooResponseAndCheckIt());
  }
}

TEST_P(EndToEndTest, MultipleClients) {
  ASSERT_TRUE(Initialize());
  std::unique_ptr<QuicTestClient> client2(CreateQuicClient(nullptr));

  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;
  headers["content-length"] = "3";

  client_->SendMessage(headers, "", /*fin=*/false);
  client2->SendMessage(headers, "", /*fin=*/false);

  client_->SendData("bar", true);
  WaitForFooResponseAndCheckIt();

  client2->SendData("eep", true);
  WaitForFooResponseAndCheckIt(client2.get());
}

TEST_P(EndToEndTest, RequestOverMultiplePackets) {
  // Send a large enough request to guarantee fragmentation.
  std::string huge_request =
      "/some/path?query=" + std::string(kMaxOutgoingPacketSize, '.');
  AddToCache(huge_request, 200, kBarResponseBody);

  ASSERT_TRUE(Initialize());

  SendSynchronousRequestAndCheckResponse(huge_request, kBarResponseBody);
}

TEST_P(EndToEndTest, MultiplePacketsRandomOrder) {
  // Send a large enough request to guarantee fragmentation.
  std::string huge_request =
      "/some/path?query=" + std::string(kMaxOutgoingPacketSize, '.');
  AddToCache(huge_request, 200, kBarResponseBody);

  ASSERT_TRUE(Initialize());
  SetPacketSendDelay(QuicTime::Delta::FromMilliseconds(2));
  SetReorderPercentage(50);

  SendSynchronousRequestAndCheckResponse(huge_request, kBarResponseBody);
}

TEST_P(EndToEndTest, PostMissingBytes) {
  ASSERT_TRUE(Initialize());

  // Add a content length header with no body.
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;
  headers["content-length"] = "3";

  // This should be detected as stream fin without complete request,
  // triggering an error response.
  client_->SendCustomSynchronousRequest(headers, "");
  EXPECT_EQ(QuicSimpleServerStream::kErrorResponseBody,
            client_->response_body());
  CheckResponseHeaders("500");
}

TEST_P(EndToEndTest, LargePostNoPacketLoss) {
  ASSERT_TRUE(Initialize());

  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());

  // 1 MB body.
  std::string body(1024 * 1024, 'a');
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;

  EXPECT_EQ(kFooResponseBody,
            client_->SendCustomSynchronousRequest(headers, body));
  // TODO(ianswett): There should not be packet loss in this test, but on some
  // platforms the receive buffer overflows.
  VerifyCleanConnection(true);
}

// Marked as slow since this adds a real-clock one second of delay.
TEST_P(EndToEndTest, QUICHE_SLOW_TEST(LargePostNoPacketLoss1sRTT)) {
  ASSERT_TRUE(Initialize());
  SetPacketSendDelay(QuicTime::Delta::FromMilliseconds(1000));

  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());

  // 100 KB body.
  std::string body(100 * 1024, 'a');
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;

  EXPECT_EQ(kFooResponseBody,
            client_->SendCustomSynchronousRequest(headers, body));
  VerifyCleanConnection(false);
}

TEST_P(EndToEndTest, LargePostWithPacketLoss) {
  // Connect with lower fake packet loss than we'd like to test.
  // Until b/10126687 is fixed, losing handshake packets is pretty
  // brutal.
  // Disable blackhole detection as this test is testing loss recovery.
  client_extra_copts_.push_back(kNBHD);
  SetPacketLossPercentage(5);
  ASSERT_TRUE(Initialize());
  EXPECT_TRUE(client_->client()->WaitForHandshakeConfirmed());
  SetPacketLossPercentage(30);

  // 10 KB body.
  std::string body(1024 * 10, 'a');
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;

  EXPECT_EQ(kFooResponseBody,
            client_->SendCustomSynchronousRequest(headers, body));
  if (override_server_connection_id_length_ == -1) {
    // If the client sends a longer connection ID, we can end up with dropped
    // packets. The packets_dropped counter increments whenever a packet arrives
    // with a new server connection ID that is not INITIAL, RETRY, or 1-RTT.
    // With packet losses, we could easily lose a server INITIAL and have the
    // first observed server packet be HANDSHAKE.
    VerifyCleanConnection(true);
  }
}

// Regression test for b/80090281.
TEST_P(EndToEndTest, LargePostWithPacketLossAndAlwaysBundleWindowUpdates) {
  // Disable blackhole detection as this test is testing loss recovery.
  client_extra_copts_.push_back(kNBHD);
  ASSERT_TRUE(Initialize());
  EXPECT_TRUE(client_->client()->WaitForHandshakeConfirmed());
  server_thread_->WaitForCryptoHandshakeConfirmed();

  // Normally server only bundles a retransmittable frame once every other
  // kMaxConsecutiveNonRetransmittablePackets ack-only packets. Setting the max
  // to 0 to reliably reproduce b/80090281.
  server_thread_->Schedule([this]() {
    QuicConnection* server_connection = GetServerConnection();
    if (server_connection != nullptr) {
      QuicConnectionPeer::
          SetMaxConsecutiveNumPacketsWithNoRetransmittableFrames(
              server_connection, 0);
    } else {
      ADD_FAILURE() << "Missing server connection";
    }
  });

  SetPacketLossPercentage(30);

  // 10 KB body.
  std::string body(1024 * 10, 'a');
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;

  EXPECT_EQ(kFooResponseBody,
            client_->SendCustomSynchronousRequest(headers, body));
  VerifyCleanConnection(true);
}

TEST_P(EndToEndTest, LargePostWithPacketLossAndBlockedSocket) {
  // Connect with lower fake packet loss than we'd like to test.  Until
  // b/10126687 is fixed, losing handshake packets is pretty brutal.
  // Disable blackhole detection as this test is testing loss recovery.
  client_extra_copts_.push_back(kNBHD);
  SetPacketLossPercentage(5);
  ASSERT_TRUE(Initialize());
  EXPECT_TRUE(client_->client()->WaitForHandshakeConfirmed());
  SetPacketLossPercentage(10);
  client_writer_->set_fake_blocked_socket_percentage(10);

  // 10 KB body.
  std::string body(1024 * 10, 'a');
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;

  EXPECT_EQ(kFooResponseBody,
            client_->SendCustomSynchronousRequest(headers, body));
}

TEST_P(EndToEndTest, LargePostNoPacketLossWithDelayAndReordering) {
  ASSERT_TRUE(Initialize());
  EXPECT_TRUE(client_->client()->WaitForHandshakeConfirmed());
  // Both of these must be called when the writer is not actively used.
  SetPacketSendDelay(QuicTime::Delta::FromMilliseconds(2));
  SetReorderPercentage(30);

  // 1 MB body.
  std::string body(1024 * 1024, 'a');
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;

  EXPECT_EQ(kFooResponseBody,
            client_->SendCustomSynchronousRequest(headers, body));
}

// TODO(b/214587920): make this test not rely on timeouts.
TEST_P(EndToEndTest, QUICHE_SLOW_TEST(AddressToken)) {
  client_config_.set_max_time_before_crypto_handshake(
      QuicTime::Delta::FromSeconds(3));
  client_config_.set_max_idle_time_before_crypto_handshake(
      QuicTime::Delta::FromSeconds(1));

  client_extra_copts_.push_back(kTRTT);
  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames()) {
    return;
  }

  SendSynchronousFooRequestAndCheckResponse();
  QuicSpdyClientSession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_FALSE(client_session->EarlyDataAccepted());
  EXPECT_FALSE(client_session->ReceivedInchoateReject());
  EXPECT_FALSE(client_->client()->EarlyDataAccepted());
  EXPECT_FALSE(client_->client()->ReceivedInchoateReject());

  client_->Disconnect();

  // The 0-RTT handshake should succeed.
  client_->Connect();
  EXPECT_TRUE(client_->client()->WaitForHandshakeConfirmed());
  ASSERT_TRUE(client_->client()->connected());
  SendSynchronousFooRequestAndCheckResponse();

  client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_TRUE(client_session->EarlyDataAccepted());
  EXPECT_TRUE(client_->client()->EarlyDataAccepted());

  server_thread_->Pause();
  QuicSpdySession* server_session = GetServerSession();
  QuicConnection* server_connection = GetServerConnection();
  if (server_session != nullptr && server_connection != nullptr) {
    // Verify address is validated via validating token received in INITIAL
    // packet.
    EXPECT_FALSE(
        server_connection->GetStats().address_validated_via_decrypting_packet);
    EXPECT_TRUE(server_connection->GetStats().address_validated_via_token);

    // Verify the server received a cached min_rtt from the token and used it as
    // the initial rtt.
    const CachedNetworkParameters* server_received_network_params =
        static_cast<const QuicCryptoServerStreamBase*>(
            server_session->GetCryptoStream())
            ->PreviousCachedNetworkParams();

    ASSERT_NE(server_received_network_params, nullptr);
    // QuicSentPacketManager::SetInitialRtt clamps the initial_rtt to between
    // [min_initial_rtt, max_initial_rtt].
    const QuicTime::Delta min_initial_rtt =
        QuicTime::Delta::FromMicroseconds(kMinTrustedInitialRoundTripTimeUs);
    const QuicTime::Delta max_initial_rtt =
        QuicTime::Delta::FromMicroseconds(kMaxInitialRoundTripTimeUs);
    const QuicTime::Delta expected_initial_rtt =
        std::max(min_initial_rtt,
                 std::min(max_initial_rtt,
                          QuicTime::Delta::FromMilliseconds(
                              server_received_network_params->min_rtt_ms())));
    EXPECT_EQ(
        server_connection->sent_packet_manager().GetRttStats()->initial_rtt(),
        expected_initial_rtt);
  } else {
    ADD_FAILURE() << "Missing server connection";
  }

  server_thread_->Resume();

  client_->Disconnect();

  // Regression test for b/206087883.
  // Mock server crash.
  StopServer();

  // The handshake fails due to idle timeout.
  client_->Connect();
  ASSERT_FALSE(client_->client()->WaitForOneRttKeysAvailable());
  client_->WaitForWriteToFlush();
  client_->WaitForResponse();
  ASSERT_FALSE(client_->client()->connected());
  EXPECT_THAT(client_->connection_error(), IsError(QUIC_NETWORK_IDLE_TIMEOUT));

  // Server restarts.
  server_writer_ = new PacketDroppingTestWriter();
  StartServer();

  // Client re-connect.
  client_->Connect();
  ASSERT_TRUE(client_->client()->WaitForHandshakeConfirmed());
  client_->WaitForWriteToFlush();
  client_->WaitForResponse();
  ASSERT_TRUE(client_->client()->connected());
  client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_FALSE(client_session->EarlyDataAccepted());
  EXPECT_FALSE(client_->client()->EarlyDataAccepted());
  server_thread_->Pause();
  server_session = GetServerSession();
  server_connection = GetServerConnection();
  // Verify address token is only used once.
  if (server_session != nullptr && server_connection != nullptr) {
    // Verify address is validated via decrypting packet.
    EXPECT_TRUE(
        server_connection->GetStats().address_validated_via_decrypting_packet);
    EXPECT_FALSE(server_connection->GetStats().address_validated_via_token);
  } else {
    ADD_FAILURE() << "Missing server connection";
  }
  server_thread_->Resume();

  client_->Disconnect();
}

// Verify that client does not reuse a source address token.
// TODO(b/214587920): make this test not rely on timeouts.
TEST_P(EndToEndTest, QUICHE_SLOW_TEST(AddressTokenNotReusedByClient)) {
  client_config_.set_max_time_before_crypto_handshake(
      QuicTime::Delta::FromSeconds(3));
  client_config_.set_max_idle_time_before_crypto_handshake(
      QuicTime::Delta::FromSeconds(1));

  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames()) {
    return;
  }

  QuicCryptoClientConfig* client_crypto_config =
      client_->client()->crypto_config();
  QuicServerId server_id = client_->client()->server_id();

  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_FALSE(GetClientSession()->EarlyDataAccepted());

  client_->Disconnect();

  QuicClientSessionCache* session_cache =
      static_cast<QuicClientSessionCache*>(client_crypto_config->session_cache());
  ASSERT_TRUE(
      !QuicClientSessionCachePeer::GetToken(session_cache, server_id).empty());

  // Pause the server thread again to blackhole packets from client.
  server_thread_->Pause();
  client_->Connect();
  EXPECT_FALSE(client_->client()->WaitForOneRttKeysAvailable());
  EXPECT_FALSE(client_->client()->connected());

  // Verify address token gets cleared.
  ASSERT_TRUE(
      QuicClientSessionCachePeer::GetToken(session_cache, server_id).empty());
  server_thread_->Resume();
}

TEST_P(EndToEndTest, LargePostZeroRTTFailure) {
  // Send a request and then disconnect. This prepares the client to attempt
  // a 0-RTT handshake for the next request.
  ASSERT_TRUE(Initialize());
  if (!version_.UsesTls() &&
      GetQuicReloadableFlag(quic_require_handshake_confirmation)) {
    return;
  }

  std::string body(20480, 'a');
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;

  EXPECT_EQ(kFooResponseBody,
            client_->SendCustomSynchronousRequest(headers, body));
  QuicSpdyClientSession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_FALSE(client_session->EarlyDataAccepted());
  EXPECT_FALSE(client_session->ReceivedInchoateReject());
  EXPECT_FALSE(client_->client()->EarlyDataAccepted());
  EXPECT_FALSE(client_->client()->ReceivedInchoateReject());

  client_->Disconnect();

  // The 0-RTT handshake should succeed.
  client_->Connect();
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  ASSERT_TRUE(client_->client()->connected());
  EXPECT_EQ(kFooResponseBody,
            client_->SendCustomSynchronousRequest(headers, body));

  client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_TRUE(client_session->EarlyDataAccepted());
  EXPECT_TRUE(client_->client()->EarlyDataAccepted());

  client_->Disconnect();

  // Restart the server so that the 0-RTT handshake will take 1 RTT.
  StopServer();
  server_writer_ = new PacketDroppingTestWriter();
  StartServer();

  client_->Connect();
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  ASSERT_TRUE(client_->client()->connected());
  EXPECT_EQ(kFooResponseBody,
            client_->SendCustomSynchronousRequest(headers, body));
  client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_FALSE(client_session->EarlyDataAccepted());
  EXPECT_FALSE(client_session->ReceivedInchoateReject());
  EXPECT_FALSE(client_->client()->EarlyDataAccepted());
  EXPECT_FALSE(client_->client()->ReceivedInchoateReject());
  VerifyCleanConnection(false);
}

// Regression test for b/168020146.
TEST_P(EndToEndTest, MultipleZeroRtt) {
  ASSERT_TRUE(Initialize());
  if (!version_.UsesTls() &&
      GetQuicReloadableFlag(quic_require_handshake_confirmation)) {
    return;
  }

  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest("/foo"));
  QuicSpdyClientSession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_FALSE(client_session->EarlyDataAccepted());
  EXPECT_FALSE(client_session->ReceivedInchoateReject());
  EXPECT_FALSE(client_->client()->EarlyDataAccepted());
  EXPECT_FALSE(client_->client()->ReceivedInchoateReject());

  client_->Disconnect();

  // The 0-RTT handshake should succeed.
  client_->Connect();
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  ASSERT_TRUE(client_->client()->connected());
  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest("/foo"));

  client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_TRUE(client_session->EarlyDataAccepted());
  EXPECT_TRUE(client_->client()->EarlyDataAccepted());

  client_->Disconnect();

  client_->Connect();
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  ASSERT_TRUE(client_->client()->connected());
  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest("/foo"));

  client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_TRUE(client_session->EarlyDataAccepted());
  EXPECT_TRUE(client_->client()->EarlyDataAccepted());

  client_->Disconnect();
}

TEST_P(EndToEndTest, SynchronousRequestZeroRTTFailure) {
  // Send a request and then disconnect. This prepares the client to attempt
  // a 0-RTT handshake for the next request.
  ASSERT_TRUE(Initialize());
  if (!version_.UsesTls() &&
      GetQuicReloadableFlag(quic_require_handshake_confirmation)) {
    return;
  }

  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest("/foo"));
  QuicSpdyClientSession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_FALSE(client_session->EarlyDataAccepted());
  EXPECT_FALSE(client_session->ReceivedInchoateReject());
  EXPECT_FALSE(client_->client()->EarlyDataAccepted());
  EXPECT_FALSE(client_->client()->ReceivedInchoateReject());

  client_->Disconnect();

  // The 0-RTT handshake should succeed.
  client_->Connect();
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  ASSERT_TRUE(client_->client()->connected());
  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest("/foo"));

  client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_TRUE(client_session->EarlyDataAccepted());
  EXPECT_TRUE(client_->client()->EarlyDataAccepted());

  client_->Disconnect();

  // Restart the server so that the 0-RTT handshake will take 1 RTT.
  StopServer();
  server_writer_ = new PacketDroppingTestWriter();
  StartServer();

  client_->Connect();
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  ASSERT_TRUE(client_->client()->connected());
  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest("/foo"));

  client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_FALSE(client_session->EarlyDataAccepted());
  EXPECT_FALSE(client_session->ReceivedInchoateReject());
  EXPECT_FALSE(client_->client()->EarlyDataAccepted());
  EXPECT_FALSE(client_->client()->ReceivedInchoateReject());

  VerifyCleanConnection(false);
}

TEST_P(EndToEndTest, LargePostSynchronousRequest) {
  // Send a request and then disconnect. This prepares the client to attempt
  // a 0-RTT handshake for the next request.
  ASSERT_TRUE(Initialize());

  std::string body(20480, 'a');
  HttpHeaderBlock headers;
  headers[":method"] = "POST";
  headers[":path"] = "/foo";
  headers[":scheme"] = "https";
  headers[":authority"] = server_hostname_;

  EXPECT_EQ(kFooResponseBody,
            client_->SendCustomSynchronousRequest(headers, body));
  QuicSpdyClientSession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_FALSE(client_session->EarlyDataAccepted());
  EXPECT_FALSE(client_session->ReceivedInchoateReject());
  EXPECT_FALSE(client_->client()->EarlyDataAccepted());
  EXPECT_FALSE(client_->client()->ReceivedInchoateReject());

  client_->Disconnect();

  // The 0-RTT handshake should succeed.
  client_->Connect();
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  ASSERT_TRUE(client_->client()->connected());
  EXPECT_EQ(kFooResponseBody,
            client_->SendCustomSynchronousRequest(headers, body));

  client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_EQ((version_.UsesTls() ||
             !GetQuicReloadableFlag(quic_require_handshake_confirmation)),
            client_session->EarlyDataAccepted());
  EXPECT_EQ((version_.UsesTls() ||
             !GetQuicReloadableFlag(quic_require_handshake_confirmation)),
            client_->client()->EarlyDataAccepted());

  client_->Disconnect();

  // Restart the server so that the 0-RTT handshake will take 1 RTT.
  StopServer();
  server_writer_ = new PacketDroppingTestWriter();
  StartServer();

  client_->Connect();
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  ASSERT_TRUE(client_->client()->connected());
  EXPECT_EQ(kFooResponseBody,
            client_->SendCustomSynchronousRequest(headers, body));

  client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_FALSE(client_session->EarlyDataAccepted());
  EXPECT_FALSE(client_session->ReceivedInchoateReject());
  EXPECT_FALSE(client_->client()->EarlyDataAccepted());
  EXPECT_FALSE(client_->client()->ReceivedInchoateReject());

  VerifyCleanConnection(false);
}

TEST_P(EndToEndTest, DisableResumption) {
  client_extra_copts_.push_back(kNRES);
  ASSERT_TRUE(Initialize());
  if (!version_.UsesTls()) {
    return;
  }
  SendSynchronousFooRequestAndCheckResponse();
  QuicSpdyClientSession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_EQ(client_session->GetCryptoStream()->EarlyDataReason(),
            ssl_early_data_no_session_offered);
  client_->Disconnect();

  SendSynchronousFooRequestAndCheckResponse();
  client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  if (GetQuicReloadableFlag(quic_enable_disable_resumption)) {
    EXPECT_EQ(client_session->GetCryptoStream()->EarlyDataReason(),
              ssl_early_data_session_not_resumed);
  } else {
    EXPECT_EQ(client_session->GetCryptoStream()->EarlyDataReason(),
              ssl_early_data_accepted);
  }
}

// This is a regression test for b/162595387
TEST_P(EndToEndTest, PostZeroRTTRequestDuringHandshake) {
  if (!version_.UsesTls()) {
    // This test is TLS specific.
    ASSERT_TRUE(Initialize());
    return;
  }
  // Send a request and then disconnect. This prepares the client to attempt
  // a 0-RTT handshake for the next request.
  NiceMock<MockQuicConnectionDebugVisitor> visitor;
  connection_debug_visitor_ = &visitor;
  ASSERT_TRUE(Initialize());

  SendSynchronousFooRequestAndCheckResponse();
  QuicSpdyClientSession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_FALSE(client_session->EarlyDataAccepted());
  EXPECT_FALSE(client_session->ReceivedInchoateReject());
  EXPECT_FALSE(client_->client()->EarlyDataAccepted());
  EXPECT_FALSE(client_->client()->ReceivedInchoateReject());

  client_->Disconnect();

  // The 0-RTT handshake should succeed.
  ON_CALL(visitor, OnCryptoFrame(_))
      .WillByDefault(Invoke([this](const QuicCryptoFrame& frame) {
        if (frame.level != ENCRYPTION_HANDSHAKE) {
          return;
        }
        // At this point in the handshake, the client should have derived
        // ENCRYPTION_ZERO_RTT keys (thus set encryption_established). It
        // should also have set ENCRYPTION_HANDSHAKE keys after receiving
        // the server's ENCRYPTION_INITIAL flight.
        EXPECT_TRUE(
            GetClientSession()->GetCryptoStream()->encryption_established());
        EXPECT_TRUE(
            GetClientConnection()->framer().HasEncrypterOfEncryptionLevel(
                ENCRYPTION_HANDSHAKE));
        HttpHeaderBlock headers;
        headers[":method"] = "POST";
        headers[":path"] = "/foo";
        headers[":scheme"] = "https";
        headers[":authority"] = server_hostname_;
        EXPECT_GT(
            client_->SendMessage(headers, "", /*fin*/ true, /*flush*/ false),
            0);
      }));
  client_->Connect();
  ASSERT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  client_->WaitForWriteToFlush();
  client_->WaitForResponse();
  ASSERT_TRUE(client_->client()->connected());
  EXPECT_EQ(kFooResponseBody, client_->response_body());

  client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_TRUE(client_session->EarlyDataAccepted());
  EXPECT_TRUE(client_->client()->EarlyDataAccepted());
}

// Regression test for b/166836136.
TEST_P(EndToEndTest, RetransmissionAfterZeroRTTRejectBeforeOneRtt) {
  if (!version_.UsesTls()) {
    // This test is TLS specific.
    ASSERT_TRUE(Initialize());
    return;
  }
  // Send a request and then disconnect. This prepares the client to attempt
  // a 0-RTT handshake for the next request.
  NiceMock<MockQuicConnectionDebugVisitor> visitor;
  connection_debug_visitor_ = &visitor;
  ASSERT_TRUE(Initialize());

  SendSynchronousFooRequestAndCheckResponse();
  QuicSpdyClientSession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_FALSE(client_session->EarlyDataAccepted());
  EXPECT_FALSE(client_session->ReceivedInchoateReject());
  EXPECT_FALSE(client_->client()->EarlyDataAccepted());
  EXPECT_FALSE(client_->client()->ReceivedInchoateReject());

  client_->Disconnect();

  client_->Connect();
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  ASSERT_TRUE(client_->client()->connected());
  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest("/foo"));

  client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_TRUE(client_session->EarlyDataAccepted());
  EXPECT_TRUE(client_->client()->EarlyDataAccepted());

  client_->Disconn
```