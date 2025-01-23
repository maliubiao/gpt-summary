Response:
Let's break down the thought process for analyzing this code snippet and generating the comprehensive response.

**1. Understanding the Goal:**

The initial request asks for an explanation of the functionality of the provided C++ code snippet from `net/http/http_stream_factory_unittest.cc`. It also specifically asks about its relationship to JavaScript, logical reasoning (with inputs/outputs), common user/programming errors, debugging steps, and a summary of its function as part of a larger sequence.

**2. Initial Code Scan and Keyword Recognition:**

The first step is to quickly scan the code for key terms and patterns. Keywords like `TEST_P`, `EXPECT_TRUE`, `EXPECT_EQ`, `StreamRequester`, `HttpRequestInfo`, `SocketTag`, `SpdySession`, `MockQuicData`, `MockConnect`, `SSLSocketDataProvider`, and function names like `RequestStreamAndWait`, `GetSpdySessionCount`, `GetSocketPoolGroupCount`, `GetHandedOutSocketCount`, `GetQuicSessionCount` jump out. These provide immediate clues about the code's purpose.

**3. Identifying the Core Functionality:**

From the keywords, it's clear this is a unit test file for `HttpStreamFactory`. The tests focus on how `HttpStreamFactory` manages HTTP and QUIC streams, especially in relation to `SocketTag`s. The code creates mock network conditions and verifies the behavior of the `HttpStreamFactory` under these conditions.

**4. Dissecting Individual Tests:**

* **`Tag` (HTTP/2):** This test verifies that requests with different `SocketTag`s result in separate HTTP/2 sessions and sockets. It also confirms that reusing the same tag reuses the existing session/socket.
* **`Tag` (QUIC):**  Similar to the HTTP/2 test, this focuses on QUIC sessions and verifies that different `SocketTag`s lead to distinct QUIC sessions.
* **`ChangeSocketTag`:** This test explores the ability to change the `SocketTag` of an existing HTTP/2 session. It shows that changing the tag before the session is active is possible, but attempting to use the session with the original tag after it's been changed will fail. It also demonstrates that once a session is active, a new request with a different tag will create a new session.
* **`ChangeSocketTagAvoidOverwrite`:** This is a regression test to ensure that changing socket tags doesn't inadvertently cause problems when multiple requests are involved and sessions are reused.
* **`MultiIPAliases`:** This test verifies that when multiple hostnames resolve to the same IP address (IP aliases), the `HttpStreamFactory` correctly tries all existing suitable sessions before creating new ones. It also considers the impact of `privacy_mode`.

**5. Analyzing the Code's Logic and Assertions:**

For each test, carefully examine the sequence of actions:
    * Setting up mock data (socket data, SSL data, QUIC data).
    * Creating `HttpRequestInfo` objects with different URLs and `SocketTag`s.
    * Using `StreamRequester` to request streams.
    * Using `EXPECT_TRUE`, `EXPECT_EQ`, and `ASSERT_TRUE` to verify the expected number of sessions, socket pool groups, handed-out sockets, and the correctness of the socket tags.

**6. Addressing Specific Questions in the Prompt:**

* **Functionality:** Summarize the purpose of each test and the overall goal of the file (testing `HttpStreamFactory`).
* **Relationship to JavaScript:** Since network requests initiated from JavaScript in a browser will eventually go through the network stack where `HttpStreamFactory` resides, there's an indirect connection. Provide an example using `fetch()`.
* **Logical Reasoning (Inputs/Outputs):** For a simple test like the first `Tag` test, define the input (`HttpRequestInfo` with specific tags) and the expected output (number of sessions, sockets, tag values).
* **Common User/Programming Errors:**  Consider scenarios where developers might misuse socket tagging, like incorrectly assuming session reuse across different tags or forgetting to set the tag.
* **Debugging Steps:** Explain how a developer might arrive at this code during debugging, tracing a network request from the browser.
* **Function Summary (Part 5 of 6):** Emphasize the focus on `SocketTag` management, session reuse, and the handling of IP aliases.

**7. Structuring the Response:**

Organize the information logically, using clear headings and bullet points. Start with a general overview and then delve into the specifics of each test. Provide code snippets as examples where appropriate.

**8. Refinement and Review:**

After drafting the initial response, review it for clarity, accuracy, and completeness. Ensure that all aspects of the prompt have been addressed. For instance, initially, I might have focused too much on the code details and not enough on the user-level implications or the JavaScript connection. Reviewing helps correct such imbalances.

**Self-Correction Example During the Process:**

Initially, I might have simply stated, "This tests socket tagging."  However, upon closer inspection, I realize the tests cover more nuanced aspects:

* Creating *new* sessions/sockets with *different* tags.
* *Reusing* sessions/sockets with the *same* tag.
* *Changing* the tag of an *existing* session (and its limitations).
* Handling IP aliasing with different sessions.

This realization prompts a more detailed and accurate description of the functionality. Similarly, for the JavaScript connection, a vague statement like "JavaScript makes network requests" isn't as helpful as a concrete `fetch()` example illustrating how a browser-initiated request eventually interacts with the underlying network stack.
这是对 Chromium 网络栈中 `net/http/http_stream_factory_unittest.cc` 文件的第 5 部分内容的代码分析和功能归纳。

**功能列举 (基于提供的代码片段):**

这部分代码主要关注 `HttpStreamFactory` 如何处理带有 `SocketTag` 的网络请求，以及如何管理 HTTP/2 和 QUIC 会话和连接。其核心功能是验证 `HttpStreamFactory` 在以下场景下的行为是否符合预期：

1. **SocketTag 的使用:**
   - 验证使用不同的 `SocketTag` 发起请求是否会创建新的 HTTP/2 和 QUIC 会话以及底层 socket 连接。
   - 验证使用相同的 `SocketTag` 发起请求是否会重用现有的 HTTP/2 和 QUIC 会话和连接。
   - 验证 socket 在连接建立之前是否被正确地打上 tag。
   - 验证可以修改 HTTP/2 会话的 socket tag，以及修改 socket tag 对后续请求的影响。
   - 验证在会话激活后，尝试使用旧的 socket tag 会失败。
   - 验证 socket tag 的修改不会导致覆盖其他连接的 tag。

2. **IP 地址别名 (IP Aliases):**
   - 验证当多个主机名解析到相同的 IP 地址时，`HttpStreamFactory` 是否会尝试重用已存在的会话（即使这些会话是针对不同的主机名创建的，只要它们是 IP 别名）。
   - 验证在 IP 别名的情况下，如果 privacy mode 不同，会创建新的会话。

**与 JavaScript 的功能关系及举例说明:**

虽然这段 C++ 代码本身并不直接包含 JavaScript，但它所测试的 `HttpStreamFactory` 是浏览器网络栈的核心组件，负责处理所有通过 HTTP(S) 和 QUIC 发起的网络请求，包括来自 JavaScript 的请求。

**举例说明:**

假设一个网页的 JavaScript 代码使用 `fetch()` API 发起两个 HTTPS 请求，这两个请求分别带有不同的 `SocketTag`。

```javascript
// 请求 1，带有 tag1
const request1 = new Request('https://example.com/api/data1', {
  // ... 其他配置
});
navigator.sendBeacon('intent://example.com#Intent;S.SocketTag=tag1;end');
fetch(request1);

// 请求 2，带有 tag2
const request2 = new Request('https://example.com/api/data2', {
  // ... 其他配置
});
navigator.sendBeacon('intent://example.com#Intent;S.SocketTag=tag2;end');
fetch(request2);
```

在这个例子中，虽然 `fetch()` API 本身不直接暴露设置 `SocketTag` 的接口，但在一些浏览器或特定场景下，可以通过其他机制（例如 `navigator.sendBeacon` 结合特定格式的 URL）来传递 `SocketTag` 信息。当这些请求到达浏览器网络栈时，`HttpStreamFactory` 会根据这些 `SocketTag` 的值来决定是否创建新的 TCP 连接和 HTTP/2 会话，或者重用已有的连接。这段 C++ 测试代码就是用来验证 `HttpStreamFactory` 在处理这种情况时的行为是否正确：两个带有不同 tag 的请求应该会使用不同的 socket 连接。

**逻辑推理 (假设输入与输出):**

**场景 1: 验证不同 SocketTag 创建不同会话 (HTTP/2)**

**假设输入:**

- 创建一个 `HttpNetworkSession` 对象。
- 创建两个 `HttpRequestInfo` 对象 (`request_info1`, `request_info2`)，它们访问相同的 URL，但分别带有不同的 `SocketTag` (`tag1`, `tag2`)。
- 使用 `StreamRequester` 分别请求这两个 stream。

**预期输出:**

- `GetSpdySessionCount()` 返回 2 (创建了两个 HTTP/2 会话)。
- `GetSocketPoolGroupCount()` 返回 1 (连接到相同的 origin，socket pool group 数量不变)。
- `GetHandedOutSocketCount()` 返回 2 (创建了两个 socket 连接)。
- `socket_factory_ptr->GetLastProducedTCPSocket()->tag()` 对于第一个请求返回 `tag1`，对于第二个请求返回 `tag2`。

**场景 2: 验证相同 SocketTag 重用会话 (HTTP/2)**

**假设输入:**

- 在上述场景 1 的基础上，再创建一个 `HttpRequestInfo` 对象 (`request_info3`)，它访问相同的 URL，并且带有与 `request_info2` 相同的 `SocketTag` (`tag2`)。
- 使用 `StreamRequester` 请求这个 stream。

**预期输出:**

- `GetSpdySessionCount()` 仍然返回 2 (没有创建新的 HTTP/2 会话)。
- `GetSocketPoolGroupCount()` 仍然返回 1。
- `GetHandedOutSocketCount()` 仍然返回 2 (没有创建新的 socket 连接，重用了之前的连接)。

**涉及用户或编程常见的使用错误及举例说明:**

1. **错误地假设不同 Tag 的请求会重用连接:** 用户或开发者可能错误地认为，只要请求的目标地址相同，即使设置了不同的 `SocketTag`，连接也会被重用。这段测试代码验证了事实并非如此，不同的 `SocketTag` 通常会导致创建新的连接。

   **示例:** 一个应用想对不同用户的请求进行区分和隔离，为每个用户的请求设置不同的 `SocketTag`。如果开发者错误地认为这不会增加连接数，可能会导致资源消耗超出预期。

2. **在会话激活后尝试修改 SocketTag:** 开发者可能尝试在某个 HTTP/2 会话已经开始处理请求后，再去修改这个会话的 `SocketTag`。这段代码的 `ChangeSocketTag` 测试验证了这种操作的局限性，一旦会话激活，尝试使用旧的 tag 会失败。

   **示例:**  一个应用在请求初期可能没有设置 `SocketTag`，然后在某个时刻决定为这个连接打上 tag。如果在这个时刻会话已经开始处理数据，修改 tag 的操作可能不会生效或导致错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中访问一个网页。**
2. **网页中的 JavaScript 代码发起一个或多个网络请求 (例如使用 `fetch()`, `XMLHttpRequest`)。**
3. **浏览器解析请求的 URL 和其他相关信息，并根据需要设置 `SocketTag` (可能通过 Intent URL 或其他机制)。**
4. **网络请求被传递到浏览器的网络栈。**
5. **`HttpStreamFactory` 负责根据请求的信息（包括 `SocketTag`）来决定如何创建或复用连接。**
6. **如果 `SocketTag` 与现有连接的 tag 不同，`HttpStreamFactory` 可能会创建一个新的 TCP 连接和 HTTP/2 或 QUIC 会话。**
7. **在调试网络连接问题时，开发者可能会查看 `chrome://net-internals` 等工具，来分析连接的创建和复用情况，以及 `SocketTag` 的影响。**
8. **如果发现连接行为与预期不符 (例如，本应该重用的连接却新建了)，开发者可能会深入到 Chromium 源代码中，查看 `HttpStreamFactory` 的实现和相关的单元测试 (如这个文件)，来理解其工作原理并找到问题所在。**

**功能归纳 (作为第 5 部分):**

这部分代码主要测试了 `HttpStreamFactory` 中关于 `SocketTag` 的核心逻辑。它验证了 `HttpStreamFactory` 能够正确地根据 `SocketTag` 的不同来创建或复用 HTTP/2 和 QUIC 会话及底层的 socket 连接。此外，它还测试了修改 HTTP/2 会话 `SocketTag` 的行为和限制。同时，也覆盖了 IP 地址别名场景下会话的复用逻辑。总而言之，这部分测试确保了 `HttpStreamFactory` 在处理带有 `SocketTag` 的网络请求时，能够按照预期的方式管理连接资源，这对实现诸如请求隔离、流量区分等功能至关重要。

### 提示词
```
这是目录为net/http/http_stream_factory_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
e stream with one tag results in one session, group and
  // socket.
  StreamRequester requester1(session.get());
  requester1.RequestStreamAndWait(session->http_stream_factory(), request_info1,
                                  DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester1.stream_done());
  EXPECT_TRUE(nullptr == requester1.websocket_stream());
  ASSERT_TRUE(nullptr != requester1.stream());

  EXPECT_EQ(1, GetSpdySessionCount(session.get()));
  EXPECT_EQ(1,
            GetSocketPoolGroupCount(session->GetSocketPool(
                HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct())));
  EXPECT_EQ(1,
            GetHandedOutSocketCount(session->GetSocketPool(
                HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct())));
  // Verify socket tagged appropriately.
  EXPECT_TRUE(tag1 == socket_factory_ptr->GetLastProducedTCPSocket()->tag());
  EXPECT_TRUE(socket_factory_ptr->GetLastProducedTCPSocket()
                  ->tagged_before_connected());

  // Verify one more stream with a different tag results in one more session and
  // socket.
  StreamRequester requester2(session.get());
  requester2.RequestStreamAndWait(session->http_stream_factory(), request_info2,
                                  DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester2.stream_done());
  EXPECT_TRUE(nullptr == requester2.websocket_stream());
  ASSERT_TRUE(nullptr != requester2.stream());

  EXPECT_EQ(2, GetSpdySessionCount(session.get()));
  EXPECT_EQ(1,
            GetSocketPoolGroupCount(session->GetSocketPool(
                HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct())));
  EXPECT_EQ(2,
            GetHandedOutSocketCount(session->GetSocketPool(
                HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct())));
  // Verify socket tagged appropriately.
  EXPECT_TRUE(tag2 == socket_factory_ptr->GetLastProducedTCPSocket()->tag());
  EXPECT_TRUE(socket_factory_ptr->GetLastProducedTCPSocket()
                  ->tagged_before_connected());

  // Verify one more stream reusing a tag does not create new sessions, groups
  // or sockets.
  StreamRequester requester3(session.get());
  requester3.RequestStreamAndWait(session->http_stream_factory(), request_info2,
                                  DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester3.stream_done());
  EXPECT_TRUE(nullptr == requester3.websocket_stream());
  ASSERT_TRUE(nullptr != requester3.stream());

  EXPECT_EQ(2, GetSpdySessionCount(session.get()));
  EXPECT_EQ(1,
            GetSocketPoolGroupCount(session->GetSocketPool(
                HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct())));
  EXPECT_EQ(2,
            GetHandedOutSocketCount(session->GetSocketPool(
                HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct())));
}

// Verify HttpStreamFactory::Job passes socket tag along properly to QUIC
// sessions and that QuicSessions have unique socket tags (e.g. one sessions
// should not be shared amongst streams with different socket tags).
TEST_P(HttpStreamFactoryBidirectionalQuicTest, Tag) {
  // SocketTag is not supported yet for HappyEyeballsV3.
  // TODO(crbug.com/346835898): Support SocketTag.
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndDisableFeature(features::kHappyEyeballsV3);

  // Prepare mock QUIC data for a first session establishment.
  MockQuicData mock_quic_data(version());
  spdy::SpdyPriority priority =
      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);
  size_t spdy_headers_frame_length;
  int packet_num = 1;
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      client_packet_maker().MakeInitialSettingsPacket(packet_num++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      client_packet_maker().MakeRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0),
          /*fin=*/true, priority,
          client_packet_maker().GetRequestHeaders("GET", "https", "/"),
          &spdy_headers_frame_length));
  size_t spdy_response_headers_frame_length;
  mock_quic_data.AddRead(
      ASYNC, server_packet_maker().MakeResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0),
                 /*fin=*/true, server_packet_maker().GetResponseHeaders("200"),
                 &spdy_response_headers_frame_length));
  mock_quic_data.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more read data.
  mock_quic_data.AddSocketDataToFactory(&socket_factory());

  // Prepare mock QUIC data for a second session establishment.
  client_packet_maker().Reset();
  MockQuicData mock_quic_data2(version());
  packet_num = 1;
  mock_quic_data2.AddWrite(
      SYNCHRONOUS,
      client_packet_maker().MakeInitialSettingsPacket(packet_num++));
  mock_quic_data2.AddWrite(
      SYNCHRONOUS,
      client_packet_maker().MakeRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0),
          /*fin=*/true, priority,
          client_packet_maker().GetRequestHeaders("GET", "https", "/"),
          &spdy_headers_frame_length));
  mock_quic_data2.AddRead(
      ASYNC, server_packet_maker().MakeResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0),
                 /*fin=*/true, server_packet_maker().GetResponseHeaders("200"),
                 &spdy_response_headers_frame_length));
  mock_quic_data2.AddRead(SYNCHRONOUS, ERR_IO_PENDING);  // No more read data.
  mock_quic_data2.AddSocketDataToFactory(&socket_factory());

  // Add hanging data for http job.
  auto hanging_data = std::make_unique<StaticSocketDataProvider>();
  MockConnect hanging_connect(SYNCHRONOUS, ERR_IO_PENDING);
  hanging_data->set_connect_data(hanging_connect);
  socket_factory().AddSocketDataProvider(hanging_data.get());
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  socket_factory().AddSSLSocketDataProvider(&ssl_data);

  // Set up QUIC as alternative_service.
  Initialize();
  AddQuicAlternativeService();

  // Prepare two different tags and corresponding HttpRequestInfos.
  SocketTag tag1(SocketTag::UNSET_UID, 0x12345678);
  HttpRequestInfo request_info1;
  request_info1.method = "GET";
  request_info1.url = default_url_;
  request_info1.load_flags = 0;
  request_info1.socket_tag = tag1;
  request_info1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  SocketTag tag2(getuid(), 0x87654321);
  HttpRequestInfo request_info2 = request_info1;
  request_info2.socket_tag = tag2;
  request_info2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Verify one stream with one tag results in one QUIC session.
  StreamRequester requester1(session());
  requester1.RequestStreamAndWait(session()->http_stream_factory(),
                                  request_info1, DEFAULT_PRIORITY,
                                  /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester1.stream_done());
  EXPECT_TRUE(nullptr == requester1.websocket_stream());
  ASSERT_TRUE(nullptr != requester1.stream());
  EXPECT_EQ(kProtoQUIC, requester1.request()->negotiated_protocol());
  EXPECT_EQ(1, GetQuicSessionCount(session()));

  // Verify socket tagged appropriately.
  EXPECT_TRUE(tag1 == socket_factory().GetLastProducedUDPSocket()->tag());
  EXPECT_TRUE(socket_factory()
                  .GetLastProducedUDPSocket()
                  ->tagged_before_data_transferred());

  // Verify one more stream with a different tag results in one more session and
  // socket.
  StreamRequester requester2(session());
  requester2.RequestStreamAndWait(session()->http_stream_factory(),
                                  request_info2, DEFAULT_PRIORITY,
                                  /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester2.stream_done());
  EXPECT_TRUE(nullptr == requester2.websocket_stream());
  ASSERT_TRUE(nullptr != requester2.stream());
  EXPECT_EQ(kProtoQUIC, requester2.request()->negotiated_protocol());
  EXPECT_EQ(2, GetQuicSessionCount(session()));

  // Verify socket tagged appropriately.
  EXPECT_TRUE(tag2 == socket_factory().GetLastProducedUDPSocket()->tag());
  EXPECT_TRUE(socket_factory()
                  .GetLastProducedUDPSocket()
                  ->tagged_before_data_transferred());

  // Verify one more stream reusing a tag does not create new sessions.
  StreamRequester requester3(session());
  requester3.RequestStreamAndWait(session()->http_stream_factory(),
                                  request_info2, DEFAULT_PRIORITY,
                                  /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester3.stream_done());
  EXPECT_TRUE(nullptr == requester3.websocket_stream());
  ASSERT_TRUE(nullptr != requester3.stream());
  EXPECT_EQ(kProtoQUIC, requester3.request()->negotiated_protocol());
  EXPECT_EQ(2, GetQuicSessionCount(session()));
}

TEST_P(HttpStreamFactoryTest, ChangeSocketTag) {
  // SocketTag is not supported yet for HappyEyeballsV3.
  // TODO(crbug.com/346835898): Support SocketTag.
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndDisableFeature(features::kHappyEyeballsV3);

  SpdySessionDependencies session_deps;
  auto socket_factory = std::make_unique<MockTaggingClientSocketFactory>();
  auto* socket_factory_ptr = socket_factory.get();
  session_deps.socket_factory = std::move(socket_factory);

  // Prepare for two HTTPS connects.
  MockRead mock_read(SYNCHRONOUS, ERR_IO_PENDING);
  SequencedSocketData socket_data(base::span_from_ref(mock_read),
                                  base::span<MockWrite>());
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);
  MockRead mock_read2(SYNCHRONOUS, ERR_IO_PENDING);
  SequencedSocketData socket_data2(base::span_from_ref(mock_read2),
                                   base::span<MockWrite>());
  socket_data2.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data2);
  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);
  // Use cert for *.example.org
  ssl_socket_data.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
  ssl_socket_data.next_proto = kProtoHTTP2;
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);
  SSLSocketDataProvider ssl_socket_data2(ASYNC, OK);
  // Use cert for *.example.org
  ssl_socket_data2.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
  ssl_socket_data2.next_proto = kProtoHTTP2;
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data2);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Prepare two different tags and corresponding HttpRequestInfos.
  SocketTag tag1(SocketTag::UNSET_UID, 0x12345678);
  HttpRequestInfo request_info1;
  request_info1.method = "GET";
  request_info1.url = GURL("https://www.example.org");
  request_info1.load_flags = 0;
  request_info1.socket_tag = tag1;
  request_info1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  SocketTag tag2(getuid(), 0x87654321);
  HttpRequestInfo request_info2 = request_info1;
  request_info2.socket_tag = tag2;
  request_info2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Prepare another HttpRequestInfo with tag1 and a different host name.
  HttpRequestInfo request_info3 = request_info1;
  request_info3.url = GURL("https://foo.example.org");
  request_info3.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Verify one stream with one tag results in one session, group and
  // socket.
  StreamRequester requester1(session.get());
  requester1.RequestStreamAndWait(session->http_stream_factory(), request_info1,
                                  DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester1.stream_done());
  EXPECT_FALSE(requester1.websocket_stream());
  ASSERT_TRUE(requester1.stream());

  EXPECT_EQ(1, GetSpdySessionCount(session.get()));
  EXPECT_EQ(1,
            GetSocketPoolGroupCount(session->GetSocketPool(
                HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct())));
  EXPECT_EQ(1,
            GetHandedOutSocketCount(session->GetSocketPool(
                HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct())));
  // Verify socket tagged appropriately.
  MockTaggingStreamSocket* socket =
      socket_factory_ptr->GetLastProducedTCPSocket();
  EXPECT_TRUE(tag1 == socket->tag());
  EXPECT_TRUE(socket->tagged_before_connected());

  // Verify the socket tag on the first session can be changed.
  StreamRequester requester2(session.get());
  requester2.RequestStreamAndWait(session->http_stream_factory(), request_info2,
                                  DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester2.stream_done());
  EXPECT_FALSE(requester2.websocket_stream());
  ASSERT_TRUE(requester2.stream());
  // Verify still have just one session.
  EXPECT_EQ(1, GetSpdySessionCount(session.get()));
  EXPECT_EQ(1,
            GetSocketPoolGroupCount(session->GetSocketPool(
                HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct())));
  EXPECT_EQ(1,
            GetHandedOutSocketCount(session->GetSocketPool(
                HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct())));
  // Verify no new sockets created.
  EXPECT_EQ(socket, socket_factory_ptr->GetLastProducedTCPSocket());
  // Verify socket tag changed.
  EXPECT_TRUE(tag2 == socket->tag());
  EXPECT_FALSE(socket->tagged_before_connected());

  // Verify attempting to use the first stream fails because the session's
  // socket tag has since changed.
  TestCompletionCallback callback1;
  requester1.stream()->RegisterRequest(&request_info1);
  EXPECT_EQ(ERR_FAILED, requester1.stream()->InitializeStream(
                            /* can_send_early = */ false, DEFAULT_PRIORITY,
                            NetLogWithSource(), callback1.callback()));

  // Verify the socket tag can be changed, this time using an IP alias
  // (different host, same IP).
  StreamRequester requester3(session.get());
  requester3.RequestStreamAndWait(session->http_stream_factory(), request_info3,
                                  DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester3.stream_done());
  EXPECT_FALSE(requester3.websocket_stream());
  ASSERT_TRUE(requester3.stream());
  // Verify still have just one session.
  EXPECT_EQ(1, GetSpdySessionCount(session.get()));
  EXPECT_EQ(1,
            GetSocketPoolGroupCount(session->GetSocketPool(
                HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct())));
  EXPECT_EQ(1,
            GetHandedOutSocketCount(session->GetSocketPool(
                HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct())));
  // Verify no new sockets created.
  EXPECT_EQ(socket, socket_factory_ptr->GetLastProducedTCPSocket());
  // Verify socket tag changed.
  EXPECT_TRUE(tag1 == socket->tag());
  EXPECT_FALSE(socket->tagged_before_connected());

  // Initialize the third stream, thus marking the session active, so it cannot
  // have its socket tag changed.
  TestCompletionCallback callback3;
  requester3.stream()->RegisterRequest(&request_info3);
  EXPECT_EQ(OK, requester3.stream()->InitializeStream(
                    /* can_send_early = */ false, DEFAULT_PRIORITY,
                    NetLogWithSource(), callback3.callback()));

  // Verify a new session is created when a request with a different tag is
  // started.
  StreamRequester requester4(session.get());
  requester4.RequestStreamAndWait(session->http_stream_factory(), request_info2,
                                  DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester4.stream_done());
  EXPECT_FALSE(requester4.websocket_stream());
  ASSERT_TRUE(requester4.stream());
  // Verify we now have two sessions.
  EXPECT_EQ(2, GetSpdySessionCount(session.get()));
  EXPECT_EQ(1,
            GetSocketPoolGroupCount(session->GetSocketPool(
                HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct())));
  EXPECT_EQ(2,
            GetHandedOutSocketCount(session->GetSocketPool(
                HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct())));
  // Verify a new socket was created.
  MockTaggingStreamSocket* socket2 =
      socket_factory_ptr->GetLastProducedTCPSocket();
  EXPECT_NE(socket, socket2);
  // Verify tag set appropriately.
  EXPECT_TRUE(tag2 == socket2->tag());
  EXPECT_TRUE(socket2->tagged_before_connected());
  // Verify tag on original socket is unchanged.
  EXPECT_TRUE(tag1 == socket->tag());

  requester3.stream()->Close(/* not_reusable = */ true);
}

// Regression test for https://crbug.com/954503.
TEST_P(HttpStreamFactoryTest, ChangeSocketTagAvoidOverwrite) {
  // SocketTag is not supported yet for HappyEyeballsV3.
  // TODO(crbug.com/346835898): Support SocketTag.
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndDisableFeature(features::kHappyEyeballsV3);

  SpdySessionDependencies session_deps;
  auto socket_factory = std::make_unique<MockTaggingClientSocketFactory>();
  auto* socket_factory_ptr = socket_factory.get();
  session_deps.socket_factory = std::move(socket_factory);

  // Prepare for two HTTPS connects.
  MockRead mock_read(SYNCHRONOUS, ERR_IO_PENDING);
  SequencedSocketData socket_data(base::span_from_ref(mock_read),
                                  base::span<MockWrite>());
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);
  MockRead mock_read2(SYNCHRONOUS, ERR_IO_PENDING);
  SequencedSocketData socket_data2(base::span_from_ref(mock_read2),
                                   base::span<MockWrite>());
  socket_data2.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data2);
  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);
  // Use cert for *.example.org
  ssl_socket_data.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
  ssl_socket_data.next_proto = kProtoHTTP2;
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);
  SSLSocketDataProvider ssl_socket_data2(ASYNC, OK);
  // Use cert for *.example.org
  ssl_socket_data2.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
  ssl_socket_data2.next_proto = kProtoHTTP2;
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data2);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Prepare three different tags and corresponding HttpRequestInfos.
  SocketTag tag1(SocketTag::UNSET_UID, 2);
  HttpRequestInfo request_info1;
  request_info1.method = "GET";
  request_info1.url = GURL("https://www.example.org");
  request_info1.load_flags = 0;
  request_info1.socket_tag = tag1;
  request_info1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  SocketTag tag2(SocketTag::UNSET_UID, 1);
  HttpRequestInfo request_info2 = request_info1;
  request_info2.socket_tag = tag2;

  HttpRequestInfo request_info3 = request_info1;
  SocketTag tag3(SocketTag::UNSET_UID, 3);
  request_info3.socket_tag = tag3;

  // Prepare another HttpRequestInfo with tag3 and a different host name.
  HttpRequestInfo request_info4 = request_info1;
  request_info4.socket_tag = tag3;
  request_info4.url = GURL("https://foo.example.org");

  // Verify one stream with one tag results in one session, group and
  // socket.
  StreamRequester requester1(session.get());
  requester1.RequestStreamAndWait(session->http_stream_factory(), request_info1,
                                  DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester1.stream_done());
  EXPECT_FALSE(requester1.websocket_stream());
  ASSERT_TRUE(requester1.stream());

  EXPECT_EQ(1, GetSpdySessionCount(session.get()));
  EXPECT_EQ(1,
            GetSocketPoolGroupCount(session->GetSocketPool(
                HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct())));
  EXPECT_EQ(1,
            GetHandedOutSocketCount(session->GetSocketPool(
                HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct())));
  // Verify socket tagged appropriately.
  MockTaggingStreamSocket* socket =
      socket_factory_ptr->GetLastProducedTCPSocket();
  EXPECT_TRUE(tag1 == socket->tag());
  EXPECT_TRUE(socket->tagged_before_connected());

  // Initialize the first stream, thus marking the session active, so it cannot
  // have its socket tag changed and be reused for the second session.
  TestCompletionCallback callback1;
  requester1.stream()->RegisterRequest(&request_info1);
  EXPECT_EQ(OK, requester1.stream()->InitializeStream(
                    /* can_send_early = */ false, DEFAULT_PRIORITY,
                    NetLogWithSource(), callback1.callback()));

  // Create a second stream with a new tag.
  StreamRequester requester2(session.get());
  requester2.RequestStreamAndWait(session->http_stream_factory(), request_info2,
                                  DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester2.stream_done());
  EXPECT_FALSE(requester2.websocket_stream());
  ASSERT_TRUE(requester2.stream());
  // Verify we now have two sessions.
  EXPECT_EQ(2, GetSpdySessionCount(session.get()));
  EXPECT_EQ(1,
            GetSocketPoolGroupCount(session->GetSocketPool(
                HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct())));
  EXPECT_EQ(2,
            GetHandedOutSocketCount(session->GetSocketPool(
                HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct())));
  // Verify a new socket was created.
  MockTaggingStreamSocket* socket2 =
      socket_factory_ptr->GetLastProducedTCPSocket();
  EXPECT_NE(socket, socket2);
  // Verify tag set appropriately.
  EXPECT_TRUE(tag2 == socket2->tag());
  EXPECT_TRUE(socket2->tagged_before_connected());
  // Verify tag on original socket is unchanged.
  EXPECT_TRUE(tag1 == socket->tag());

  // Initialize the second stream, thus marking the session active, so it cannot
  // have its socket tag changed and be reused for the third session.
  TestCompletionCallback callback2;
  requester2.stream()->RegisterRequest(&request_info2);
  EXPECT_EQ(OK, requester2.stream()->InitializeStream(
                    /* can_send_early = */ false, DEFAULT_PRIORITY,
                    NetLogWithSource(), callback2.callback()));

  // Release first stream so first session can be retagged for third request.
  requester1.stream()->Close(/* not_reusable = */ true);

  // Verify the first session can be retagged for a third request.
  StreamRequester requester3(session.get());
  requester3.RequestStreamAndWait(session->http_stream_factory(), request_info3,
                                  DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester3.stream_done());
  EXPECT_FALSE(requester3.websocket_stream());
  ASSERT_TRUE(requester3.stream());
  // Verify still have two sessions.
  EXPECT_EQ(2, GetSpdySessionCount(session.get()));
  EXPECT_EQ(1,
            GetSocketPoolGroupCount(session->GetSocketPool(
                HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct())));
  EXPECT_EQ(2,
            GetHandedOutSocketCount(session->GetSocketPool(
                HttpNetworkSession::NORMAL_SOCKET_POOL, ProxyChain::Direct())));
  // Verify no new sockets created.
  EXPECT_EQ(socket2, socket_factory_ptr->GetLastProducedTCPSocket());
  // Verify socket tag changed.
  EXPECT_TRUE(tag3 == socket->tag());
  EXPECT_FALSE(socket->tagged_before_connected());

  // Release second stream so second session can be retagged for fourth request.
  requester2.stream()->Close(/* not_reusable = */ true);

  // Request a stream with a new tag and a different host that aliases existing
  // sessions.
  StreamRequester requester4(session.get());
  requester4.RequestStreamAndWait(session->http_stream_factory(), request_info4,
                                  DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester4.stream_done());
  EXPECT_FALSE(requester4.websocket_stream());
  ASSERT_TRUE(requester4.stream());
  // Verify no new sockets created.
  EXPECT_EQ(socket2, socket_factory_ptr->GetLastProducedTCPSocket());
}

#endif  // BUILDFLAG(IS_ANDROID)

// Test that when creating a stream all sessions that alias an IP are tried,
// not just one.  This is important because there can be multiple sessions
// that could satisfy a stream request and they should all be tried.
TEST_P(HttpStreamFactoryTest, MultiIPAliases) {
  SpdySessionDependencies session_deps;

  // Prepare for two HTTPS connects.
  MockRead mock_read1(SYNCHRONOUS, ERR_IO_PENDING);
  SequencedSocketData socket_data1(base::span_from_ref(mock_read1),
                                   base::span<MockWrite>());
  socket_data1.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data1);
  MockRead mock_read2(SYNCHRONOUS, ERR_IO_PENDING);
  SequencedSocketData socket_data2(base::span_from_ref(mock_read2),
                                   base::span<MockWrite>());
  socket_data2.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data2);
  SSLSocketDataProvider ssl_socket_data1(ASYNC, OK);
  // Load cert for *.example.org
  ssl_socket_data1.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
  ssl_socket_data1.next_proto = kProtoHTTP2;
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data1);
  SSLSocketDataProvider ssl_socket_data2(ASYNC, OK);
  // Load cert for *.example.org
  ssl_socket_data2.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
  ssl_socket_data2.next_proto = kProtoHTTP2;
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data2);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Create two HttpRequestInfos, differing only in host name.
  // Both will resolve to 127.0.0.1 and hence be IP aliases.
  HttpRequestInfo request_info1;
  request_info1.method = "GET";
  request_info1.url = GURL("https://a.example.org");
  request_info1.privacy_mode = PRIVACY_MODE_DISABLED;
  request_info1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpRequestInfo request_info1_alias = request_info1;
  request_info1.url = GURL("https://b.example.org");

  // Create two more HttpRequestInfos but with different privacy_mode.
  HttpRequestInfo request_info2;
  request_info2.method = "GET";
  request_info2.url = GURL("https://a.example.org");
  request_info2.privacy_mode = PRIVACY_MODE_ENABLED;
  request_info2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  HttpRequestInfo request_info2_alias = request_info2;
  request_info2.url = GURL("https://b.example.org");

  // Open one session.
  StreamRequester requester1(session.get());
  requester1.RequestStreamAndWait(session->http_stream_factory(), request_info1,
                                  DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester1.stream_done());
  EXPECT_FALSE(requester1.websocket_stream());
  ASSERT_TRUE(requester1.stream());

  // Verify just one session created.
  EXPECT_EQ(1, GetSpdySessionCount(session.get()));
  EXPECT_EQ(1, GetPoolGroupCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()));
  EXPECT_EQ(1, GetHandedOutCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()));

  // Open another session to same IP but with different privacy mode.
  StreamRequester requester2(session.get());
  requester2.RequestStreamAndWait(session->http_stream_factory(), request_info2,
                                  DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester2.stream_done());
  EXPECT_FALSE(requester2.websocket_stream());
  ASSERT_TRUE(requester2.stream());

  // Verify two sessions are now open.
  EXPECT_EQ(2, GetSpdySessionCount(session.get()));
  EXPECT_EQ(2, GetPoolGroupCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()));
  EXPECT_EQ(2, GetHandedOutCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()));

  // Open a third session that IP aliases first session.
  StreamRequester requester3(session.get());
  requester3.RequestStreamAndWait(session->http_stream_factory(),
                                  request_info1_alias, DEFAULT_PRIORITY,
                                  /*allowed_bad_certs=*/{},
                                  /*enable_ip_based_pooling=*/true,
                                  /*enable_alternative_services=*/true);
  EXPECT_TRUE(requester3.stream_done());
  EXPECT_FALSE(requester3.websocket_stream());
  ASSERT_TRUE(requester3.stream());

  // Verify the session pool reused the first session and no new session is
  // created.  This will fail unless the session pool supports multiple
  // sessions aliasing a single IP.
  EXPECT_EQ(2, GetSpdySessionCount(session.get()));
  // When HappyEyeballsV3 is enabled, we create separate groups based on the
  // destination, even when the underlying connections share the same session.
  int expected_group_count =
      base::FeatureList::IsEnabled(features::kHappyEyeballsV3) ? 3 : 2;
  EXPECT_EQ(
      expected_group_count,
      GetPoolGroupCount(session.get(), HttpNetworkSession::NORMAL_SOCKET_POOL,
                        ProxyChain::Direct()));
  EXPECT_EQ(2, GetHandedOutCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()));

  // Open a fourth session that IP aliases the second session.
  StreamRequester requester4(session.get());
  requester4.RequestStreamAndWait(session->http_stream_factory(),
                                  request_info2_alias, DEFAULT_PR
```