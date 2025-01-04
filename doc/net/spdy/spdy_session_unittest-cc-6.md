Response:
The user wants a summary of the functionality of the provided C++ code snippet from `net/spdy/spdy_session_unittest.cc`. I need to identify the main test scenarios covered in this part of the file.

Looking at the code, the tests focus on:

1. **Sending initial settings:**  Verifying that the correct initial settings are sent by the client during the establishment of a new SPDY/HTTP2 session. This involves testing default values, overriding defaults, and handling unknown settings.
2. **Processing ALTSVC frames:**  Testing how the `SpdySession` handles ALTSVC frames received from the server, including storing and retrieving the alternative service information. This includes tests for different scenarios like processing on stream 0 vs. other streams, with and without origins, and interaction with NetworkAnonymizationKeys. It also covers cases where ALTSVC frames should be ignored due to various conditions.
3. **Mapping errors:** Testing the utility functions that map lower-level framer errors and RST_STREAM statuses to higher-level protocol errors.
4. **Connection pooling:**  Testing the `CanPool` function which determines if two connections can be pooled based on SSL certificate information, including handling certificate errors, client certificates, pinning, and Certificate Transparency (CT) requirements.

I need to address the specific questions raised in the prompt:

*   **Functionality:** Summarize the test cases as described above.
*   **Relationship to Javascript:**  Consider if any of these functionalities directly relate to how Javascript interacts with the network. The ALTSVC frame processing, which influences how the browser might switch to alternative protocols like QUIC, could be relevant.
*   **Logic and Examples:**  For the settings and ALTSVC tests, I can provide examples of input frames and the expected behavior.
*   **User/Programming Errors:** Consider common mistakes related to setting up HTTP/2 connections or handling ALTSVC information.
*   **User Operation to Reach Here:**  Think about the steps a user might take in a browser that would lead to this code being executed (though this is unit test code, so it's more about the underlying network interaction).
*   **Part of a Series:** Note that this is part 7 of 8, implying it covers a specific subset of SPDY session testing.

**Plan:**

1. Summarize the core functionalities: initial settings, ALTSVC frame processing, error mapping, and connection pooling.
2. For initial settings, give an example of overriding a default setting and the expected frame.
3. For ALTSVC, illustrate the processing of a valid frame and the resulting stored alternative service info.
4. Relate ALTSVC to Javascript by explaining how it influences protocol selection for future requests.
5. For user errors, focus on misconfiguration of HTTP/2 settings or issues related to understanding ALTSVC behavior.
6. Describe the basic browser actions that would trigger HTTP/2 connection establishment and ALTSVC processing.
7. Conclude by stating that this part focuses on these specific aspects of SPDY session behavior.
这个C++源代码文件 `net/spdy/spdy_session_unittest.cc` 的第7部分主要负责测试 Chromium 网络栈中 `SpdySession` 类的以下功能：

**1. 发送初始设置 (Sending Initial Settings):**

*   **功能:**  测试当建立一个新的 SPDY 或 HTTP/2 会话时，客户端如何发送初始的 SETTINGS 帧。这包括：
    *   验证默认的设置值是否被正确发送。
    *   验证通过 `HttpNetworkSession::Params` 设置的值是否会覆盖默认值并被发送。
    *   验证当设置的值是协议默认值时，是否不会被发送。
    *   验证未知的设置参数是否会被发送。
    *   测试了 `SpdySessionPoolPeer::SetEnableSendingInitialData(true)` 的作用，即是否在新的会话上发送初始设置。

*   **与 Javascript 的关系:**  Javascript 本身不直接控制这些底层的 SPDY/HTTP2 设置。但是，浏览器通过 Javascript 发起的网络请求最终会受到这些设置的影响。例如，`SETTINGS_MAX_CONCURRENT_STREAMS` 限制了单个连接上可以并发发送的请求数量，这会影响 Javascript 发起的多个 `fetch` 或 `XMLHttpRequest` 请求的性能。`SETTINGS_ENABLE_PUSH` 决定了服务器是否可以主动向客户端推送资源，这也会影响 Web 应用的加载速度和性能，Javascript 可以处理接收到的推送资源。

*   **假设输入与输出 (逻辑推理):**
    *   **假设输入:**  `session_deps_.http2_settings[spdy::SETTINGS_MAX_CONCURRENT_STREAMS] = 42;`
    *   **预期输出:**  发送的 SETTINGS 帧会包含 `SETTINGS_MAX_CONCURRENT_STREAMS` 参数，值为 42。

*   **用户或编程常见的使用错误:**
    *   **错误:**  开发者可能会错误地认为可以通过 Javascript 直接修改这些底层的 HTTP/2 设置来优化性能。
    *   **说明:** 这些设置通常由浏览器内核控制，开发者无法直接干预。尝试通过 Javascript 修改这些设置是无效的。

*   **用户操作到达这里的步骤 (调试线索):**
    1. 用户在浏览器地址栏输入一个使用 HTTPS 的网站地址，或者点击一个 HTTPS 链接。
    2. 浏览器的网络栈会尝试与服务器建立 HTTPS 连接。
    3. 如果服务器支持 HTTP/2，并且浏览器也配置为使用 HTTP/2，那么在 TLS 握手完成后，会尝试建立 HTTP/2 会话。
    4. `SpdySession` 类会被创建来管理这个 HTTP/2 会话。
    5. 如果 `SpdySessionPoolPeer::SetEnableSendingInitialData(true)` 被设置（通常是这样），那么就会执行发送初始 SETTINGS 帧的逻辑，这部分代码就在测试这个过程。

**2. 处理 ALTSVC 帧 (Processing ALTSVC Frames):**

*   **功能:** 测试 `SpdySession` 如何处理接收到的 ALTSVC 帧。ALTSVC 帧用于通知客户端，目标主机可以通过其他协议（例如 QUIC）和地址访问。测试涵盖了：
    *   正确解析和存储 ALTSVC 信息到 `HttpServerProperties` 中。
    *   处理在 stream 0 上接收到的 ALTSVC 帧，其中 `origin` 字段用于指定哪些来源适用这些替代服务。
    *   处理在非 stream 0 的活动 stream 上接收到的 ALTSVC 帧，此时 `origin` 隐式地是该 stream 的请求来源。
    *   忽略不符合规范的 ALTSVC 帧，例如 stream ID 不正确，或 origin 为空。
    *   处理带有 `NetworkAnonymizationKey` 的场景，确保 ALTSVC 信息与正确的 `NetworkAnonymizationKey` 关联。
    *   忽略针对不安全来源的 ALTSVC 帧。
    *   忽略在不存在的 stream 上接收到的 ALTSVC 帧。
    *   处理包含不支持的 QUIC 版本的 ALTSVC 帧。
    *   处理 origin 无法被当前证书覆盖的 ALTSVC 帧。
    *   处理无效的 origin 字段。

*   **与 Javascript 的关系:**  当浏览器接收到并处理了 ALTSVC 帧后，后续 Javascript 发起的针对相同 `origin` 的请求，浏览器可能会选择使用 ALTSVC 帧中指定的替代协议和地址，例如 QUIC。这可以提高网络连接的性能和效率，对于 Javascript 发起的 `fetch` 或 `XMLHttpRequest` 请求是透明的，但底层使用了不同的网络协议。

*   **假设输入与输出 (逻辑推理):**
    *   **假设输入:**  接收到一个 stream ID 为 0 的 ALTSVC 帧，包含 `origin: https://mail.example.org` 和一个指向 `quic://alternative.example.org:443` 的替代服务。
    *   **预期输出:**  `spdy_session_pool_->http_server_properties()` 中会存储关于 `https://mail.example.org` 的替代服务信息，指示可以通过 QUIC 连接到 `alternative.example.org:443`。

*   **用户或编程常见的使用错误:**
    *   **错误:**  服务器端配置错误的 ALTSVC 帧，例如在非 stream 0 上发送带有 `origin` 字段的帧。
    *   **说明:** 客户端会忽略这些错误的 ALTSVC 帧，导致客户端无法发现可用的替代服务。
    *   **错误:**  开发者可能误以为发送 ALTSVC 帧就能立即让所有客户端切换到替代协议。
    *   **说明:** 客户端会根据自身的策略和网络状况来决定是否使用替代服务，ALTSVC 帧只是提供了一种可能性。

*   **用户操作到达这里的步骤 (调试线索):**
    1. 用户访问一个支持 HTTP/2 和 ALTSVC 的 HTTPS 网站。
    2. 服务器在 HTTP/2 连接上发送 ALTSVC 帧，通知浏览器可以尝试使用其他协议或地址。
    3. `SpdySession` 类接收到 ALTSVC 帧并调用相应的处理逻辑，这部分代码就在测试这个处理过程。

**3. 映射错误码 (Mapping Error Codes):**

*   **功能:** 测试将底层 HTTP/2 framer 产生的错误码 (`http2::Http2DecoderAdapter::SpdyFramerError`) 映射到更高级别的 SPDY 协议错误码 (`spdy::SpdyErrorCode`) 和网络错误码 (`net::Error`) 的功能。
*   **功能:** 测试将 RST_STREAM 帧中的状态码 (`spdy::SpdyRstStreamStatus`) 映射到协议错误码 (`STATUS_CODE`) 的功能。
*   **功能:** 测试将网络错误码 (`net::Error`) 映射到 GOAWAY 帧中使用的状态码 (`spdy::SpdyErrorCode`) 的功能。

*   **与 Javascript 的关系:**  这些映射关系最终会影响到 Javascript 代码中网络请求的错误处理。例如，如果底层发生了 `ERR_HTTP2_PROTOCOL_ERROR`，那么 `fetch` 或 `XMLHttpRequest` 操作可能会抛出一个对应的错误，开发者可以捕获并处理。

*   **假设输入与输出 (逻辑推理):**
    *   **假设输入:**  HTTP/2 framer 遇到一个无效的控制帧，产生 `http2::Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME` 错误。
    *   **预期输出:**  `MapFramerErrorToProtocolError` 函数会返回 `SPDY_ERROR_INVALID_CONTROL_FRAME`，`MapFramerErrorToNetError` 函数会返回 `ERR_HTTP2_PROTOCOL_ERROR`。

*   **用户或编程常见的使用错误:**
    *   **错误:**  开发者可能依赖于特定的底层错误码来进行错误处理。
    *   **说明:**  应该使用更高级别的网络错误码或 HTTP 状态码进行处理，因为底层的协议实现可能会发生变化。

*   **用户操作到达这里的步骤 (调试线索):**
    1. 用户访问一个使用 HTTP/2 的网站，服务器发送了一个格式错误的 HTTP/2 帧。
    2. 底层的 HTTP/2 framer 会检测到错误并产生相应的错误码。
    3. `SpdySession` 会将这个错误码映射到更高级别的错误码，用于错误处理和通知。

**4. 连接池 (Connection Pooling):**

*   **功能:** 测试 `SpdySession::CanPool` 函数，该函数判断两个 HTTPS 连接是否可以被池化。池化可以重用现有的连接来发送新的请求，提高性能。测试考虑了以下因素：
    *   SSL 证书的主机名匹配。
    *   SSL 证书错误（例如证书吊销）。
    *   是否发送了客户端证书。
    *   HTTP 公钥吊销 (HPKP)。
    *   证书透明度 (CT) 的要求。

*   **与 Javascript 的关系:**  连接池对于 Javascript 发起的网络请求至关重要。当 Javascript 发起多个请求到同一个域名的 HTTPS 站点时，浏览器会尝试重用现有的连接，避免每次都建立新的连接，从而提高页面加载速度和性能。

*   **假设输入与输出 (逻辑推理):**
    *   **假设输入:**  尝试池化到 `mail.example.org` 的连接，但当前的 SSL 证书只对 `www.example.org` 有效。
    *   **预期输出:**  `SpdySession::CanPool` 函数会返回 `false`。

*   **用户或编程常见的使用错误:**
    *   **错误:**  开发者可能错误地配置了 HTTPS 服务器的证书，导致浏览器无法进行连接池化。
    *   **说明:**  确保 SSL 证书覆盖了所有需要访问的子域名，并配置了正确的证书链。

*   **用户操作到达这里的步骤 (调试线索):**
    1. 用户在浏览器中访问一个包含多个资源的 HTTPS 网站。
    2. 浏览器在下载这些资源时，会尝试重用已经建立的 HTTPS 连接。
    3. `SpdySession::CanPool` 函数会被调用来判断是否可以重用现有的 `SpdySession` 来发送新的请求。

**作为第7部分的功能归纳:**

这部分 `spdy_session_unittest.cc` 专注于测试 `SpdySession` 类在会话建立和运行过程中的关键行为：**初始化设置的发送、接收和处理服务器发送的 ALTSVC 帧以发现替代服务、错误码的映射以及连接池的判断逻辑。**  这些功能对于 HTTP/2 连接的正确建立、性能优化以及错误处理至关重要。

Prompt: 
```
这是目录为net/spdy/spdy_session_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共8部分，请归纳一下它的功能

"""
stSize;
  expected_settings[spdy::SETTINGS_ENABLE_PUSH] = 0;
  spdy::SpdySerializedFrame settings_frame(
      spdy_util_.ConstructSpdySettings(expected_settings));

  spdy::SpdySerializedFrame combined_frame =
      CombineFrames({&preface, &settings_frame});

  // Greased frame sent on stream 0 after initial SETTINGS frame.
  uint8_t kRawFrameData[] = {
      0x00, 0x00, 0x03,        // length
      0x0b,                    // type
      0xcc,                    // flags
      0x00, 0x00, 0x00, 0x00,  // stream ID
      'f',  'o',  'o'          // payload
  };
  spdy::SpdySerializedFrame grease(spdy::test::MakeSerializedFrame(
      reinterpret_cast<char*>(kRawFrameData), std::size(kRawFrameData)));

  MockWrite writes[] = {CreateMockWrite(combined_frame, 0),
                        CreateMockWrite(grease, 1)};

  MockRead reads[] = {MockRead(ASYNC, 0, 2)};

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  AddSSLSocketData();
  CreateNetworkSession();

  SpdySessionPoolPeer pool_peer(spdy_session_pool_);
  pool_peer.SetEnableSendingInitialData(true);

  CreateSpdySession();
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

enum ReadIfReadySupport {
  // ReadIfReady() is implemented by the underlying transport.
  READ_IF_READY_SUPPORTED,
  // ReadIfReady() is unimplemented by the underlying transport.
  READ_IF_READY_NOT_SUPPORTED,
};

class SpdySessionReadIfReadyTest
    : public SpdySessionTest,
      public testing::WithParamInterface<ReadIfReadySupport> {
 public:
  void SetUp() override {
    if (GetParam() == READ_IF_READY_SUPPORTED) {
      session_deps_.socket_factory->set_enable_read_if_ready(true);
    }
    SpdySessionTest::SetUp();
  }
};

INSTANTIATE_TEST_SUITE_P(All,
                         SpdySessionReadIfReadyTest,
                         testing::Values(READ_IF_READY_SUPPORTED,
                                         READ_IF_READY_NOT_SUPPORTED));

// Tests basic functionality of ReadIfReady() when it is enabled or disabled.
TEST_P(SpdySessionReadIfReadyTest, ReadIfReady) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, HIGHEST));
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
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, HIGHEST, NetLogWithSource());
  ASSERT_TRUE(spdy_stream);
  EXPECT_EQ(0u, spdy_stream->stream_id());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(spdy_stream);
  EXPECT_EQ(1u, delegate.stream_id());
}

class SendInitialSettingsOnNewSpdySessionTest : public SpdySessionTest {
 protected:
  void RunInitialSettingsTest(const spdy::SettingsMap expected_settings) {
    MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING)};

    spdy::SpdySerializedFrame preface(spdy::test::MakeSerializedFrame(
        const_cast<char*>(spdy::kHttp2ConnectionHeaderPrefix),
        spdy::kHttp2ConnectionHeaderPrefixSize));
    spdy::SpdySerializedFrame settings_frame(
        spdy_util_.ConstructSpdySettings(expected_settings));

    spdy::SpdySerializedFrame combined_frame =
        CombineFrames({&preface, &settings_frame});
    MockWrite writes[] = {CreateMockWrite(combined_frame, 0)};

    StaticSocketDataProvider data(reads, writes);
    session_deps_.socket_factory->AddSocketDataProvider(&data);
    AddSSLSocketData();

    CreateNetworkSession();

    SpdySessionPoolPeer pool_peer(spdy_session_pool_);
    pool_peer.SetEnableSendingInitialData(true);

    CreateSpdySession();

    base::RunLoop().RunUntilIdle();
    EXPECT_TRUE(data.AllWriteDataConsumed());
  }
};

// Setting values when Params::http2_settings is empty.  Note that
// spdy::SETTINGS_INITIAL_WINDOW_SIZE is sent in production, because it is set
// to a non-default value, but it is not sent in tests, because the protocol
// default value is used in tests.
TEST_F(SendInitialSettingsOnNewSpdySessionTest, Empty) {
  spdy::SettingsMap expected_settings;
  expected_settings[spdy::SETTINGS_HEADER_TABLE_SIZE] = kSpdyMaxHeaderTableSize;
  expected_settings[spdy::SETTINGS_MAX_HEADER_LIST_SIZE] =
      kSpdyMaxHeaderListSize;
  expected_settings[spdy::SETTINGS_ENABLE_PUSH] = 0;
  RunInitialSettingsTest(expected_settings);
}

// When a setting is set to the protocol default value,
// no corresponding value is sent on the wire.
TEST_F(SendInitialSettingsOnNewSpdySessionTest, ProtocolDefault) {
  // SETTINGS_ENABLE_PUSH is always overridden with value 0.
  session_deps_.http2_settings[spdy::SETTINGS_ENABLE_PUSH] = 1;

  // Explicitly set protocol default values for the following settings.
  session_deps_.http2_settings[spdy::SETTINGS_HEADER_TABLE_SIZE] = 4096;
  session_deps_.http2_settings[spdy::SETTINGS_INITIAL_WINDOW_SIZE] =
      64 * 1024 - 1;

  spdy::SettingsMap expected_settings;
  expected_settings[spdy::SETTINGS_MAX_HEADER_LIST_SIZE] =
      kSpdyMaxHeaderListSize;
  expected_settings[spdy::SETTINGS_ENABLE_PUSH] = 0;
  RunInitialSettingsTest(expected_settings);
}

// Values set in Params::http2_settings overwrite Chromium's default values.
TEST_F(SendInitialSettingsOnNewSpdySessionTest, OverwriteValues) {
  session_deps_.http2_settings[spdy::SETTINGS_HEADER_TABLE_SIZE] = 16 * 1024;
  session_deps_.http2_settings[spdy::SETTINGS_ENABLE_PUSH] = 0;
  session_deps_.http2_settings[spdy::SETTINGS_MAX_CONCURRENT_STREAMS] = 42;
  session_deps_.http2_settings[spdy::SETTINGS_INITIAL_WINDOW_SIZE] = 32 * 1024;
  session_deps_.http2_settings[spdy::SETTINGS_MAX_HEADER_LIST_SIZE] =
      101 * 1024;

  spdy::SettingsMap expected_settings;
  expected_settings[spdy::SETTINGS_HEADER_TABLE_SIZE] = 16 * 1024;
  expected_settings[spdy::SETTINGS_ENABLE_PUSH] = 0;
  expected_settings[spdy::SETTINGS_MAX_CONCURRENT_STREAMS] = 42;
  expected_settings[spdy::SETTINGS_INITIAL_WINDOW_SIZE] = 32 * 1024;
  expected_settings[spdy::SETTINGS_MAX_HEADER_LIST_SIZE] = 101 * 1024;
  RunInitialSettingsTest(expected_settings);
}

// Unknown parameters should still be sent to the server.
TEST_F(SendInitialSettingsOnNewSpdySessionTest, UnknownSettings) {
  // The following parameters are not defined in the HTTP/2 specification.
  session_deps_.http2_settings[7] = 1234;
  session_deps_.http2_settings[25] = 5678;

  spdy::SettingsMap expected_settings;
  expected_settings[spdy::SETTINGS_HEADER_TABLE_SIZE] = kSpdyMaxHeaderTableSize;
  expected_settings[spdy::SETTINGS_MAX_HEADER_LIST_SIZE] =
      kSpdyMaxHeaderListSize;
  expected_settings[spdy::SETTINGS_ENABLE_PUSH] = 0;
  expected_settings[7] = 1234;
  expected_settings[25] = 5678;
  RunInitialSettingsTest(expected_settings);
}

class AltSvcFrameTest : public SpdySessionTest {
 public:
  AltSvcFrameTest()
      : alternative_service_(
            quic::AlpnForVersion(DefaultSupportedQuicVersions().front()),
            "alternative.example.org",
            443,
            86400,
            spdy::SpdyAltSvcWireFormat::VersionVector()) {
    // Since the default |alternative_service_| is QUIC, need to enable QUIC for
    // the not added tests to be meaningful.
    session_deps_.enable_quic = true;
  }

  void AddSocketData(const spdy::SpdyAltSvcIR& altsvc_ir) {
    altsvc_frame_ = spdy_util_.SerializeFrame(altsvc_ir);
    reads_.push_back(CreateMockRead(altsvc_frame_, 0));
    reads_.emplace_back(ASYNC, 0, 1);

    data_ =
        std::make_unique<SequencedSocketData>(reads_, base::span<MockWrite>());
    session_deps_.socket_factory->AddSocketDataProvider(data_.get());
  }

  void CreateSpdySession() {
    session_ =
        ::net::CreateSpdySession(http_session_.get(), key_, NetLogWithSource());
  }

  spdy::SpdyAltSvcWireFormat::AlternativeService alternative_service_;

 private:
  spdy::SpdySerializedFrame altsvc_frame_;
  std::vector<MockRead> reads_;
  std::unique_ptr<SequencedSocketData> data_;
};

TEST_F(AltSvcFrameTest, ProcessAltSvcFrame) {
  const char origin[] = "https://mail.example.org";
  spdy::SpdyAltSvcIR altsvc_ir(/* stream_id = */ 0);
  altsvc_ir.add_altsvc(alternative_service_);
  altsvc_ir.set_origin(origin);
  AddSocketData(altsvc_ir);
  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::RunLoop().RunUntilIdle();

  const url::SchemeHostPort session_origin("https", test_url_.host(),
                                           test_url_.EffectiveIntPort());
  AlternativeServiceInfoVector altsvc_info_vector =
      spdy_session_pool_->http_server_properties()->GetAlternativeServiceInfos(
          session_origin, NetworkAnonymizationKey());
  ASSERT_TRUE(altsvc_info_vector.empty());

  altsvc_info_vector =
      spdy_session_pool_->http_server_properties()->GetAlternativeServiceInfos(
          url::SchemeHostPort(GURL(origin)), NetworkAnonymizationKey());
  ASSERT_EQ(1u, altsvc_info_vector.size());
  AlternativeService alternative_service(kProtoQUIC, "alternative.example.org",
                                         443u);
  EXPECT_EQ(alternative_service, altsvc_info_vector[0].alternative_service());
}

// Regression test for https://crbug.com/736063.
TEST_F(AltSvcFrameTest, IgnoreQuicAltSvcWithUnsupportedVersion) {
  session_deps_.enable_quic = true;

  // Note that this test only uses the legacy Google-specific Alt-Svc format.
  const char origin[] = "https://mail.example.org";
  spdy::SpdyAltSvcIR altsvc_ir(/* stream_id = */ 0);
  spdy::SpdyAltSvcWireFormat::AlternativeService quic_alternative_service(
      "quic", "alternative.example.org", 443, 86400,
      spdy::SpdyAltSvcWireFormat::VersionVector());
  quic_alternative_service.version.push_back(/* invalid QUIC version */ 1);
  altsvc_ir.add_altsvc(quic_alternative_service);
  altsvc_ir.set_origin(origin);
  AddSocketData(altsvc_ir);
  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::RunLoop().RunUntilIdle();

  const url::SchemeHostPort session_origin("https", test_url_.host(),
                                           test_url_.EffectiveIntPort());
  AlternativeServiceInfoVector altsvc_info_vector =
      spdy_session_pool_->http_server_properties()->GetAlternativeServiceInfos(
          session_origin, NetworkAnonymizationKey());
  ASSERT_TRUE(altsvc_info_vector.empty());

  altsvc_info_vector =
      spdy_session_pool_->http_server_properties()->GetAlternativeServiceInfos(
          url::SchemeHostPort(GURL(origin)), NetworkAnonymizationKey());
  ASSERT_EQ(0u, altsvc_info_vector.size());
}

TEST_F(AltSvcFrameTest, DoNotProcessAltSvcFrameForOriginNotCoveredByCert) {
  session_deps_.enable_quic = true;

  const char origin[] = "https://invalid.example.org";
  spdy::SpdyAltSvcIR altsvc_ir(/* stream_id = */ 0);
  altsvc_ir.add_altsvc(alternative_service_);
  altsvc_ir.set_origin(origin);
  AddSocketData(altsvc_ir);
  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::RunLoop().RunUntilIdle();

  const url::SchemeHostPort session_origin("https", test_url_.host(),
                                           test_url_.EffectiveIntPort());
  ASSERT_TRUE(spdy_session_pool_->http_server_properties()
                  ->GetAlternativeServiceInfos(session_origin,
                                               NetworkAnonymizationKey())
                  .empty());

  ASSERT_TRUE(
      spdy_session_pool_->http_server_properties()
          ->GetAlternativeServiceInfos(url::SchemeHostPort(GURL(origin)),
                                       NetworkAnonymizationKey())
          .empty());
}

// An ALTSVC frame on stream 0 with empty origin MUST be ignored.
// (RFC 7838 Section 4)
TEST_F(AltSvcFrameTest, DoNotProcessAltSvcFrameWithEmptyOriginOnStreamZero) {
  spdy::SpdyAltSvcIR altsvc_ir(/* stream_id = */ 0);
  altsvc_ir.add_altsvc(alternative_service_);
  AddSocketData(altsvc_ir);
  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::RunLoop().RunUntilIdle();

  const url::SchemeHostPort session_origin("https", test_url_.host(),
                                           test_url_.EffectiveIntPort());
  ASSERT_TRUE(spdy_session_pool_->http_server_properties()
                  ->GetAlternativeServiceInfos(session_origin,
                                               NetworkAnonymizationKey())
                  .empty());
}

// An ALTSVC frame on a stream other than stream 0 with non-empty origin MUST be
// ignored.  (RFC 7838 Section 4)
TEST_F(AltSvcFrameTest,
       DoNotProcessAltSvcFrameWithNonEmptyOriginOnNonZeroStream) {
  spdy::SpdyAltSvcIR altsvc_ir(/* stream_id = */ 1);
  altsvc_ir.add_altsvc(alternative_service_);
  altsvc_ir.set_origin("https://mail.example.org");
  AddSocketData(altsvc_ir);
  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::RunLoop().RunUntilIdle();

  const url::SchemeHostPort session_origin("https", test_url_.host(),
                                           test_url_.EffectiveIntPort());
  ASSERT_TRUE(spdy_session_pool_->http_server_properties()
                  ->GetAlternativeServiceInfos(session_origin,
                                               NetworkAnonymizationKey())
                  .empty());
}

TEST_F(AltSvcFrameTest, ProcessAltSvcFrameOnActiveStream) {
  spdy::SpdyAltSvcIR altsvc_ir(/* stream_id = */ 1);
  altsvc_ir.add_altsvc(alternative_service_);

  spdy::SpdySerializedFrame altsvc_frame(spdy_util_.SerializeFrame(altsvc_ir));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_REFUSED_STREAM));
  MockRead reads[] = {
      CreateMockRead(altsvc_frame, 1), CreateMockRead(rst, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  const char request_origin[] = "https://mail.example.org";
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(request_origin, 1, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };
  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session_, GURL(request_origin), MEDIUM,
      NetLogWithSource());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(request_origin));

  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  const url::SchemeHostPort session_origin("https", test_url_.host(),
                                           test_url_.EffectiveIntPort());
  ASSERT_TRUE(spdy_session_pool_->http_server_properties()
                  ->GetAlternativeServiceInfos(session_origin,
                                               NetworkAnonymizationKey())
                  .empty());

  AlternativeServiceInfoVector altsvc_info_vector =
      spdy_session_pool_->http_server_properties()->GetAlternativeServiceInfos(
          url::SchemeHostPort(GURL(request_origin)), NetworkAnonymizationKey());
  ASSERT_EQ(1u, altsvc_info_vector.size());
  EXPECT_EQ(kProtoQUIC, altsvc_info_vector[0].alternative_service().protocol);
  EXPECT_EQ("alternative.example.org",
            altsvc_info_vector[0].alternative_service().host);
  EXPECT_EQ(443u, altsvc_info_vector[0].alternative_service().port);
}

TEST_F(AltSvcFrameTest,
       ProcessAltSvcFrameOnActiveStreamWithNetworkAnonymizationKey) {
  base::test::ScopedFeatureList feature_list;
  // Need to partition connections by NetworkAnonymizationKey for
  // SpdySessionKeys to include NetworkAnonymizationKeys.
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);

  // Since HttpServerProperties caches the feature value, have to create a new
  // one.
  session_deps_.http_server_properties =
      std::make_unique<HttpServerProperties>();

  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);
  key_ = SpdySessionKey(HostPortPair::FromURL(test_url_), PRIVACY_MODE_DISABLED,
                        ProxyChain::Direct(), SessionUsage::kDestination,
                        SocketTag(), kNetworkAnonymizationKey1,
                        SecureDnsPolicy::kAllow,
                        /*disable_cert_verification_network_fetches=*/false);

  spdy::SpdyAltSvcIR altsvc_ir(/* stream_id = */ 1);
  altsvc_ir.add_altsvc(alternative_service_);

  spdy::SpdySerializedFrame altsvc_frame(spdy_util_.SerializeFrame(altsvc_ir));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_REFUSED_STREAM));
  MockRead reads[] = {
      CreateMockRead(altsvc_frame, 1), CreateMockRead(rst, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  const char request_origin[] = "https://mail.example.org";
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(request_origin, 1, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };
  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session_, GURL(request_origin), MEDIUM,
      NetLogWithSource());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(request_origin));

  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  const url::SchemeHostPort session_origin("https", test_url_.host(),
                                           test_url_.EffectiveIntPort());
  ASSERT_TRUE(spdy_session_pool_->http_server_properties()
                  ->GetAlternativeServiceInfos(session_origin,
                                               NetworkAnonymizationKey())
                  .empty());

  AlternativeServiceInfoVector altsvc_info_vector =
      spdy_session_pool_->http_server_properties()->GetAlternativeServiceInfos(
          url::SchemeHostPort(GURL(request_origin)), kNetworkAnonymizationKey1);
  ASSERT_EQ(1u, altsvc_info_vector.size());
  EXPECT_EQ(kProtoQUIC, altsvc_info_vector[0].alternative_service().protocol);
  EXPECT_EQ("alternative.example.org",
            altsvc_info_vector[0].alternative_service().host);
  EXPECT_EQ(443u, altsvc_info_vector[0].alternative_service().port);

  // Make sure the alternative service information is only associated with
  // kNetworkAnonymizationKey1.
  EXPECT_TRUE(spdy_session_pool_->http_server_properties()
                  ->GetAlternativeServiceInfos(
                      url::SchemeHostPort(GURL(request_origin)),
                      kNetworkAnonymizationKey2)
                  .empty());
  EXPECT_TRUE(spdy_session_pool_->http_server_properties()
                  ->GetAlternativeServiceInfos(
                      url::SchemeHostPort(GURL(request_origin)),
                      NetworkAnonymizationKey())
                  .empty());
}

TEST_F(AltSvcFrameTest, DoNotProcessAltSvcFrameOnStreamWithInsecureOrigin) {
  spdy::SpdyAltSvcIR altsvc_ir(/* stream_id = */ 1);
  altsvc_ir.add_altsvc(alternative_service_);

  spdy::SpdySerializedFrame altsvc_frame(spdy_util_.SerializeFrame(altsvc_ir));
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_REFUSED_STREAM));
  MockRead reads[] = {
      CreateMockRead(altsvc_frame, 1), CreateMockRead(rst, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  const char request_origin[] = "http://mail.example.org";
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(request_origin, 1, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };
  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 = CreateStreamSynchronously(
      SPDY_REQUEST_RESPONSE_STREAM, session_, GURL(request_origin), MEDIUM,
      NetLogWithSource());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(request_origin));

  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  const url::SchemeHostPort session_origin("https", test_url_.host(),
                                           test_url_.EffectiveIntPort());
  ASSERT_TRUE(spdy_session_pool_->http_server_properties()
                  ->GetAlternativeServiceInfos(session_origin,
                                               NetworkAnonymizationKey())
                  .empty());

  ASSERT_TRUE(spdy_session_pool_->http_server_properties()
                  ->GetAlternativeServiceInfos(
                      url::SchemeHostPort(GURL(request_origin)),
                      NetworkAnonymizationKey())
                  .empty());
}

TEST_F(AltSvcFrameTest, DoNotProcessAltSvcFrameOnNonExistentStream) {
  spdy::SpdyAltSvcIR altsvc_ir(/* stream_id = */ 1);
  altsvc_ir.add_altsvc(alternative_service_);
  AddSocketData(altsvc_ir);
  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::RunLoop().RunUntilIdle();

  const url::SchemeHostPort session_origin("https", test_url_.host(),
                                           test_url_.EffectiveIntPort());
  ASSERT_TRUE(spdy_session_pool_->http_server_properties()
                  ->GetAlternativeServiceInfos(session_origin,
                                               NetworkAnonymizationKey())
                  .empty());
}

// Regression test for https://crbug.com/810404.
TEST_F(AltSvcFrameTest, InvalidOrigin) {
  // This origin parses to an invalid GURL with https scheme.
  const std::string origin("https:?");
  const GURL origin_gurl(origin);
  EXPECT_FALSE(origin_gurl.is_valid());
  EXPECT_TRUE(origin_gurl.host().empty());
  EXPECT_TRUE(origin_gurl.SchemeIs(url::kHttpsScheme));

  spdy::SpdyAltSvcIR altsvc_ir(/* stream_id = */ 0);
  altsvc_ir.add_altsvc(alternative_service_);
  altsvc_ir.set_origin(origin);
  AddSocketData(altsvc_ir);
  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::RunLoop().RunUntilIdle();

  const url::SchemeHostPort session_origin("https", test_url_.host(),
                                           test_url_.EffectiveIntPort());
  AlternativeServiceInfoVector altsvc_info_vector =
      spdy_session_pool_->http_server_properties()->GetAlternativeServiceInfos(
          session_origin, NetworkAnonymizationKey());
  EXPECT_TRUE(altsvc_info_vector.empty());
}

TEST(MapFramerErrorToProtocolError, MapsValues) {
  CHECK_EQ(SPDY_ERROR_INVALID_CONTROL_FRAME,
           MapFramerErrorToProtocolError(
               http2::Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME));
  CHECK_EQ(SPDY_ERROR_INVALID_DATA_FRAME_FLAGS,
           MapFramerErrorToProtocolError(
               http2::Http2DecoderAdapter::SPDY_INVALID_DATA_FRAME_FLAGS));
  CHECK_EQ(SPDY_ERROR_HPACK_NAME_HUFFMAN_ERROR,
           MapFramerErrorToProtocolError(
               http2::Http2DecoderAdapter::SPDY_HPACK_NAME_HUFFMAN_ERROR));
  CHECK_EQ(SPDY_ERROR_UNEXPECTED_FRAME,
           MapFramerErrorToProtocolError(
               http2::Http2DecoderAdapter::SPDY_UNEXPECTED_FRAME));
}

TEST(MapFramerErrorToNetError, MapsValue) {
  CHECK_EQ(ERR_HTTP2_PROTOCOL_ERROR,
           MapFramerErrorToNetError(
               http2::Http2DecoderAdapter::SPDY_INVALID_CONTROL_FRAME));
  CHECK_EQ(ERR_HTTP2_COMPRESSION_ERROR,
           MapFramerErrorToNetError(
               http2::Http2DecoderAdapter::SPDY_DECOMPRESS_FAILURE));
  CHECK_EQ(ERR_HTTP2_FRAME_SIZE_ERROR,
           MapFramerErrorToNetError(
               http2::Http2DecoderAdapter::SPDY_CONTROL_PAYLOAD_TOO_LARGE));
  CHECK_EQ(ERR_HTTP2_FRAME_SIZE_ERROR,
           MapFramerErrorToNetError(
               http2::Http2DecoderAdapter::SPDY_OVERSIZED_PAYLOAD));
}

TEST(MapRstStreamStatusToProtocolError, MapsValues) {
  CHECK_EQ(STATUS_CODE_PROTOCOL_ERROR,
           MapRstStreamStatusToProtocolError(spdy::ERROR_CODE_PROTOCOL_ERROR));
  CHECK_EQ(
      STATUS_CODE_FRAME_SIZE_ERROR,
      MapRstStreamStatusToProtocolError(spdy::ERROR_CODE_FRAME_SIZE_ERROR));
  CHECK_EQ(
      STATUS_CODE_ENHANCE_YOUR_CALM,
      MapRstStreamStatusToProtocolError(spdy::ERROR_CODE_ENHANCE_YOUR_CALM));
  CHECK_EQ(
      STATUS_CODE_INADEQUATE_SECURITY,
      MapRstStreamStatusToProtocolError(spdy::ERROR_CODE_INADEQUATE_SECURITY));
  CHECK_EQ(
      STATUS_CODE_HTTP_1_1_REQUIRED,
      MapRstStreamStatusToProtocolError(spdy::ERROR_CODE_HTTP_1_1_REQUIRED));
}

TEST(MapNetErrorToGoAwayStatus, MapsValue) {
  CHECK_EQ(spdy::ERROR_CODE_INADEQUATE_SECURITY,
           MapNetErrorToGoAwayStatus(ERR_HTTP2_INADEQUATE_TRANSPORT_SECURITY));
  CHECK_EQ(spdy::ERROR_CODE_FLOW_CONTROL_ERROR,
           MapNetErrorToGoAwayStatus(ERR_HTTP2_FLOW_CONTROL_ERROR));
  CHECK_EQ(spdy::ERROR_CODE_PROTOCOL_ERROR,
           MapNetErrorToGoAwayStatus(ERR_HTTP2_PROTOCOL_ERROR));
  CHECK_EQ(spdy::ERROR_CODE_COMPRESSION_ERROR,
           MapNetErrorToGoAwayStatus(ERR_HTTP2_COMPRESSION_ERROR));
  CHECK_EQ(spdy::ERROR_CODE_FRAME_SIZE_ERROR,
           MapNetErrorToGoAwayStatus(ERR_HTTP2_FRAME_SIZE_ERROR));
  CHECK_EQ(spdy::ERROR_CODE_PROTOCOL_ERROR,
           MapNetErrorToGoAwayStatus(ERR_UNEXPECTED));
}

namespace {

class TestSSLConfigService : public SSLConfigService {
 public:
  TestSSLConfigService() = default;
  ~TestSSLConfigService() override = default;

  SSLContextConfig GetSSLContextConfig() override { return config_; }

  // Returns true if |hostname| is in domains_for_pooling_. This is a simpler
  // implementation than the production implementation in SSLConfigServiceMojo.
  bool CanShareConnectionWithClientCerts(
      std::string_view hostname) const override {
    return base::Contains(domains_for_pooling_, hostname);
  }

  void SetDomainsForPooling(const std::vector<std::string>& domains) {
    domains_for_pooling_ = domains;
  }

 private:
  SSLContextConfig config_;
  std::vector<std::string> domains_for_pooling_;
};

}  // namespace

TEST(CanPoolTest, CanPool) {
  // Load a cert that is valid for:
  //   www.example.org
  //   mail.example.org
  //   mail.example.com

  TransportSecurityState tss;
  TestSSLConfigService ssl_config_service;
  SSLInfo ssl_info;
  ssl_info.cert = ImportCertFromFile(GetTestCertsDirectory(),
                                     "spdy_pooling.pem");

  EXPECT_TRUE(SpdySession::CanPool(&tss, ssl_info, ssl_config_service,
                                   "www.example.org", "www.example.org"));
  EXPECT_TRUE(SpdySession::CanPool(&tss, ssl_info, ssl_config_service,
                                   "www.example.org", "mail.example.org"));
  EXPECT_TRUE(SpdySession::CanPool(&tss, ssl_info, ssl_config_service,
                                   "www.example.org", "mail.example.com"));
  EXPECT_FALSE(SpdySession::CanPool(&tss, ssl_info, ssl_config_service,
                                    "www.example.org", "mail.google.com"));
}

TEST(CanPoolTest, CanNotPoolWithCertErrors) {
  // Load a cert that is valid for:
  //   www.example.org
  //   mail.example.org
  //   mail.example.com

  TransportSecurityState tss;
  TestSSLConfigService ssl_config_service;
  SSLInfo ssl_info;
  ssl_info.cert = ImportCertFromFile(GetTestCertsDirectory(),
                                     "spdy_pooling.pem");
  ssl_info.cert_status = CERT_STATUS_REVOKED;

  EXPECT_FALSE(SpdySession::CanPool(&tss, ssl_info, ssl_config_service,
                                    "www.example.org", "mail.example.org"));
}

TEST(CanPoolTest, CanNotPoolWithClientCerts) {
  // Load a cert that is valid for:
  //   www.example.org
  //   mail.example.org
  //   mail.example.com

  TransportSecurityState tss;
  TestSSLConfigService ssl_config_service;
  SSLInfo ssl_info;
  ssl_info.cert = ImportCertFromFile(GetTestCertsDirectory(),
                                     "spdy_pooling.pem");
  ssl_info.client_cert_sent = true;

  EXPECT_FALSE(SpdySession::CanPool(&tss, ssl_info, ssl_config_service,
                                    "www.example.org", "mail.example.org"));
}

TEST(CanPoolTest, CanNotPoolWithBadPins) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      net::features::kStaticKeyPinningEnforcement);
  TransportSecurityState tss;
  tss.EnableStaticPinsForTesting();
  tss.SetPinningListAlwaysTimelyForTesting(true);
  ScopedTransportSecurityStateSource scoped_security_state_source;

  TestSSLConfigService ssl_config_service;
  SSLInfo ssl_info;
  ssl_info.cert = ImportCertFromFile(GetTestCertsDirectory(),
                                     "spdy_pooling.pem");
  ssl_info.is_issued_by_known_root = true;
  uint8_t bad_pin = 3;
  ssl_info.public_key_hashes.push_back(test::GetTestHashValue(bad_pin));

  EXPECT_FALSE(SpdySession::CanPool(&tss, ssl_info, ssl_config_service,
                                    "www.example.org", "example.test"));
}

TEST(CanPoolTest, CanNotPoolWithBadCTWhenCTRequired) {
  using testing::Return;
  using CTRequirementLevel =
      TransportSecurityState::RequireCTDelegate::CTRequirementLevel;

  TestSSLConfigService ssl_config_service;
  SSLInfo ssl_info;
  ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  ssl_info.is_issued_by_known_root = true;
  ssl_info.public_key_hashes.push_back(test::GetTestHashValue(1));
  ssl_info.ct_policy_compliance =
      ct::CTPolicyCompliance::CT_POLICY_NOT_ENOUGH_SCTS;

  MockRequireCTDelegate require_ct_delegate;
  EXPECT_CALL(require_ct_delegate, IsCTRequiredForHost("www.example.org", _, _))
      .WillRepeatedly(Return(CTRequirementLevel::NOT_REQUIRED));
  EXPECT_CALL(require_ct_delegate,
              IsCTRequiredForHost("mail.example.org", _, _))
      .WillRepeatedly(Return(CTRequirementLevel::REQUIRED));

  TransportSecurityState tss;
  tss.SetRequireCTDelegate(&require_ct_delegate);

  EXPECT_FALSE(SpdySession::CanPool(&tss, ssl_info, ssl_config_service,
                                    "www.example.org", "mail.example.org"));
}

TEST(CanPoolTest, CanPoolWithBadCTWhenCTNotRequired) {
  using testing::Return;
  using CTRequirementLevel =
      TransportSecurityState::RequireCTDelegate::CTRequirementLevel;

  TestSSLConfigService ssl_config_service;
  SSLInfo ssl_info;
  ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  ssl_info.is_issued_by_known_root = true;
  ssl_info.public_key_hashes.push_back(test::GetTestHashValue(1));
  ssl_info.ct_policy_compliance =
      ct::CTPolicyCompliance::CT_POLICY_NOT_ENOUGH_SCTS;

  MockRequireCTDelegate require_ct_delegate;
  EXPECT_CALL(require_ct_delegate, IsCTRequiredForHost("www.example.org", _, _))
      .WillRepeatedly(Return(CTRequirementLevel::NOT_REQUIRED));
  EXPECT_CALL(require_ct_delegate,
              IsCTRequiredForHost("mail.example.org", _, _))
      .WillRepeatedly(Return(CTRequirementLevel::NOT_REQUIRED));

  TransportSecurityState tss;
  tss.SetRequireCTDelegate(&require_ct_delegate);

  EXPECT_TRUE(SpdySession::CanPool(&tss, ssl_info, ssl_config_service,
                                   "www.example.org", "mail.example.org"));
}

TEST(CanPoolTest, CanPoolWithGoodCTWhenCTRequired) {
  using testing::Return;
  using CTRequirementLevel =
      TransportSecurityState::RequireCTDelegate::CTRequirementLevel;

  TestSSLConfigService ssl_config_service;
  SSLInfo ssl_info;
  ssl_info.cert =
      ImportCertFromFile(GetT
"""


```