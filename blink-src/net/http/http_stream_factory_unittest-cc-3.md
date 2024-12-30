Response:
The user wants to understand the functionality of the provided C++ code snippet from `net/http/http_stream_factory_unittest.cc`. Specifically, I need to:

1. **Identify the primary function** of the code.
2. **Determine if it relates to JavaScript**.
3. **Provide examples of logical reasoning** with hypothetical inputs and outputs.
4. **Illustrate common user/programming errors**.
5. **Explain how a user might reach this code** during debugging.
6. **Summarize the functionality** as part 4 of 6.

**Analysis of the code:**

The code defines several helper functions and test cases within a Google Test framework. The primary focus is on testing the `HttpStreamFactory` in the Chromium network stack, specifically its interaction with QUIC (and potentially other protocols) when dealing with proxies, including multi-hop proxy scenarios. The `Construct...Packet` functions are used to create mock QUIC packets for testing various scenarios.

**JavaScript Relationship:**

HTTP interactions are fundamental to web browsers, and thus indirectly related to JavaScript. JavaScript code running in a browser makes HTTP requests, and the `HttpStreamFactory` is involved in handling those requests.

**Logical Reasoning:**

The code simulates network interactions by defining expected sequences of QUIC packets. I can create examples based on these sequences.

**User/Programming Errors:**

Common errors might involve misconfiguring proxies, issues with SSL/TLS certificates, or incorrect QUIC settings.

**Debugging Path:**

A developer debugging network issues related to HTTP requests, particularly when proxies are involved, might step through this code.

**Part 4 Summary:**

Based on the content, this part of the code focuses on testing the `HttpStreamFactory`'s ability to establish HTTP connections over QUIC when using proxies, including chained proxies. It sets up mock QUIC packet exchanges to verify the correct behavior.
```cpp
                                              &spdy_headers_frame_len);
  }

  std::unique_ptr<quic::QuicEncryptedPacket>
  ConstructAckAndClientH3DatagramPacket(
      test::QuicTestPacketMaker& packet_maker,
      uint64_t packet_number,
      uint64_t largest_received,
      uint64_t smallest_received,
      uint64_t quarter_stream_id,
      uint64_t context_id,
      std::unique_ptr<quic::QuicEncryptedPacket> packet) {
    std::string datagram;
    // Allow enough space for payload and two varint-62's.
    datagram.resize(packet->length() + 2 * 8);
    quiche::QuicheDataWriter writer(datagram.capacity(), datagram.data());
    CHECK(writer.WriteVarInt62(quarter_stream_id));
    CHECK(writer.WriteVarInt62(context_id));
    CHECK(writer.WriteBytes(packet->data(), packet->length()));
    datagram.resize(writer.length());
    return packet_maker.MakeAckAndDatagramPacket(
        packet_number, largest_received, smallest_received, datagram);
  }

  std::unique_ptr<quic::QuicEncryptedPacket> ConstructClientH3DatagramPacket(
      test::QuicTestPacketMaker& packet_maker,
      uint64_t packet_number,
      uint64_t quarter_stream_id,
      uint64_t context_id,
      std::vector<std::unique_ptr<quic::QuicEncryptedPacket>> packets) {
    auto& builder = packet_maker.Packet(packet_number);
    for (auto& packet : packets) {
      std::string data;
      // Allow enough space for payload and two varint-62's.
      data.resize(packet->length() + 2 * 8);
      quiche::QuicheDataWriter writer(data.capacity(), data.data());
      CHECK(writer.WriteVarInt62(quarter_stream_id));
      CHECK(writer.WriteVarInt62(context_id));
      CHECK(writer.WriteBytes(packet->data(), packet->length()));
      data.resize(writer.length());
      builder.AddMessageFrame(data);
    }
    return builder.Build();
  }

  // Make a `QuicTestPacketMaker` for the current test with the given
  // characteristics.
  test::QuicTestPacketMaker MakePacketMaker(
      const std::string& host,
      quic::Perspective perspective,
      bool client_priority_uses_incremental = false,
      bool use_priority_header = false) {
    return test::QuicTestPacketMaker(
        version_, quic::QuicUtils::CreateRandomConnectionId(random_generator_),
        clock_, host, perspective, client_priority_uses_incremental,
        use_priority_header);
  }

  MockTaggingClientSocketFactory* socket_factory() { return &socket_factory_; }

  quic::QuicStreamId GetNthClientInitiatedBidirectionalStreamId(int n) {
    return quic::test::GetNthClientInitiatedBidirectionalStreamId(
        version_.transport_version, n);
  }

  SpdySessionDependencies& session_deps() { return session_deps_; }

  quic::ParsedQuicVersion version() const { return version_; }

 private:
  quic::test::QuicFlagSaver saver_;
  const quic::ParsedQuicVersion version_;
  std::unique_ptr<MockQuicContext> quic_context_;
  SpdySessionDependencies session_deps_;
  raw_ptr<const quic::QuicClock> clock_;
  raw_ptr<quic::QuicRandom> random_generator_;
  MockTaggingClientSocketFactory socket_factory_;
  std::unique_ptr<HttpNetworkSession> session_;
  ProofVerifyDetailsChromium verify_details_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         HttpStreamFactoryQuicTest,
                         ::testing::ValuesIn(GetTestParams()),
                         ::testing::PrintToStringParamName());

// Check that requesting an HTTP stream over a QUIC proxy sends the correct
// set of QUIC packets.
TEST_P(HttpStreamFactoryQuicTest, RequestHttpStreamOverQuicProxy) {
  static constexpr uint64_t kConnectUdpContextId = 0;
  GURL kRequestUrl("https://www.example.org");
  session_deps().proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
          {ProxyChain::ForIpProtection({ProxyServer::FromSchemeHostAndPort(
              ProxyServer::SCHEME_QUIC, "qproxy.example.org", 8888)})},
          TRAFFIC_ANNOTATION_FOR_TESTS);

  MockQuicData proxy_quic_data(version());
  quic::QuicStreamId stream_id = GetNthClientInitiatedBidirectionalStreamId(0);
  int to_proxy_packet_num = 1;
  auto to_proxy =
      MakePacketMaker("qproxy.example.org", quic::Perspective::IS_CLIENT,
                      /*client_priority_uses_incremental=*/true,
                      /*use_priority_header=*/false);
  int from_proxy_packet_num = 1;
  auto from_proxy =
      MakePacketMaker("qproxy.example.org", quic::Perspective::IS_SERVER,
                      /*client_priority_uses_incremental=*/false,
                      /*use_priority_header=*/false);
  int to_endpoint_packet_num = 1;
  auto to_endpoint =
      MakePacketMaker("www.example.org", quic::Perspective::IS_CLIENT,
                      /*client_priority_uses_incremental=*/true,
                      /*use_priority_header=*/true);

  // The browser sends initial settings to the proxy.
  proxy_quic_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket(
                                            to_proxy, to_proxy_packet_num++));

  // The browser sends CONNECT-UDP request to proxy.
  proxy_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructConnectUdpRequestPacket(
          to_proxy, to_proxy_packet_num++, stream_id, "qproxy.example.org:8888",
          "/.well-known/masque/udp/www.example.org/443/", false));

  // Proxy sends initial settings.
  proxy_quic_data.AddRead(ASYNC, ConstructInitialSettingsPacket(
                                     from_proxy, from_proxy_packet_num++));

  // Proxy responds to the CONNECT.
  proxy_quic_data.AddRead(
      ASYNC, ConstructOkResponsePacket(from_proxy, from_proxy_packet_num++,
                                       stream_id, true));
  proxy_quic_data.AddReadPauseForever();

  // The browser ACKs the OK response packet.
  proxy_quic_data.AddWrite(
      ASYNC, ConstructAckPacket(to_proxy, to_proxy_packet_num++, 1, 2, 1));

  // The browser sends initial settings to the endpoint, via proxy.
  std::vector<std::unique_ptr<quic::QuicEncryptedPacket>> datagrams;
  datagrams.push_back(
      ConstructInitialSettingsPacket(to_endpoint, to_endpoint_packet_num++));
  proxy_quic_data.AddWrite(
      ASYNC, ConstructClientH3DatagramPacket(to_proxy, to_proxy_packet_num++,
                                             stream_id, kConnectUdpContextId,
                                             std::move(datagrams)));

  proxy_quic_data.AddSocketDataToFactory(socket_factory());

  HttpNetworkSession* session = MakeSession();

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = kRequestUrl;
  request_info.load_flags = 0;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StreamRequester requester(session);
  requester.RequestStreamAndWait(session->http_stream_factory(), request_info,
                                 DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                 /*enable_ip_based_pooling=*/true,
                                 /*enable_alternative_services=*/true);

  EXPECT_TRUE(requester.stream_done());
  EXPECT_FALSE(requester.websocket_stream());
  EXPECT_TRUE(requester.stream());
  EXPECT_FALSE(requester.used_proxy_info().is_direct());

  RunUntilIdle();

  proxy_quic_data.ExpectAllReadDataConsumed();
  proxy_quic_data.ExpectAllWriteDataConsumed();
}

// Check that requesting an HTTP stream over a two QUIC proxies sends the
// correct set of QUIC packets.
TEST_P(HttpStreamFactoryQuicTest, RequestHttpStreamOverTwoQuicProxies) {
  static constexpr uint64_t kConnectUdpContextId = 0;
  GURL kRequestUrl("https://www.example.org");
  session_deps().proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
          {
              ProxyChain::ForIpProtection(
                  {ProxyServer::FromSchemeHostAndPort(
                       ProxyServer::SCHEME_QUIC, "qproxy1.example.org", 8888),
                   ProxyServer::FromSchemeHostAndPort(
                       ProxyServer::SCHEME_QUIC, "qproxy2.example.org", 8888)}),
          },
          TRAFFIC_ANNOTATION_FOR_TESTS);

  MockQuicData proxy_quic_data(version());
  quic::QuicStreamId stream_id_0 =
      GetNthClientInitiatedBidirectionalStreamId(0);
  int to_proxy1_packet_num = 1;
  auto to_proxy1 =
      MakePacketMaker("qproxy1.example.org", quic::Perspective::IS_CLIENT,
                      /*client_priority_uses_incremental=*/true,
                      /*use_priority_header=*/false);
  int from_proxy1_packet_num = 1;
  auto from_proxy1 =
      MakePacketMaker("qproxy1.example.org", quic::Perspective::IS_SERVER,
                      /*client_priority_uses_incremental=*/false,
                      /*use_priority_header=*/false);
  int to_proxy2_packet_num = 1;
  auto to_proxy2 =
      MakePacketMaker("qproxy2.example.org", quic::Perspective::IS_CLIENT,
                      /*client_priority_uses_incremental=*/true,
                      /*use_priority_header=*/false);
  int from_proxy2_packet_num = 1;
  auto from_proxy2 =
      MakePacketMaker("qproxy2.example.org", quic::Perspective::IS_SERVER,
                      /*client_priority_uses_incremental=*/false,
                      /*use_priority_header=*/false);
  int to_endpoint_packet_num = 1;
  auto to_endpoint =
      MakePacketMaker("www.example.org", quic::Perspective::IS_CLIENT,
                      /*client_priority_uses_incremental=*/true,
                      /*use_priority_header=*/true);

  // The browser sends initial settings to proxy1.
  proxy_quic_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket(
                                            to_proxy1, to_proxy1_packet_num++));

  // The browser sends CONNECT-UDP request to proxy1.
  proxy_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructConnectUdpRequestPacket(
          to_proxy1, to_proxy1_packet_num++, stream_id_0,
          "qproxy1.example.org:8888",
          "/.well-known/masque/udp/qproxy2.example.org/8888/", false));

  // Proxy1 sends initial settings.
  proxy_quic_data.AddRead(ASYNC, ConstructInitialSettingsPacket(
                                     from_proxy1, from_proxy1_packet_num++));

  // Proxy1 responds to the CONNECT.
  proxy_quic_data.AddRead(
      ASYNC, ConstructOkResponsePacket(from_proxy1, from_proxy1_packet_num++,
                                       stream_id_0, true));

  // The browser ACKs the OK response packet.
  proxy_quic_data.AddWrite(
      ASYNC, ConstructAckPacket(to_proxy1, to_proxy1_packet_num++, 1, 2, 1));

  // The browser sends initial settings and a CONNECT-UDP request to proxy2 via
  // proxy1.
  std::vector<std::unique_ptr<quic::QuicEncryptedPacket>> datagrams;
  datagrams.push_back(
      ConstructInitialSettingsPacket(to_proxy2, to_proxy2_packet_num++));
  datagrams.push_back(ConstructConnectUdpRequestPacket(
      to_proxy2, to_proxy2_packet_num++, stream_id_0,
      "qproxy2.example.org:8888",
      "/.well-known/masque/udp/www.example.org/443/", false));
  proxy_quic_data.AddWrite(
      ASYNC, ConstructClientH3DatagramPacket(to_proxy1, to_proxy1_packet_num++,
                                             stream_id_0, kConnectUdpContextId,
                                             std::move(datagrams)));

  // Proxy2 sends initial settings and an OK response to the CONNECT request,
  // via proxy1.
  datagrams.clear();
  datagrams.push_back(
      ConstructInitialSettingsPacket(from_proxy2, from_proxy2_packet_num++));
  datagrams.push_back(ConstructOkResponsePacket(
      from_proxy2, from_proxy2_packet_num++, stream_id_0, true));
  proxy_quic_data.AddRead(
      ASYNC, ConstructClientH3DatagramPacket(
                 from_proxy1, from_proxy1_packet_num++, stream_id_0,
                 kConnectUdpContextId, std::move(datagrams)));
  proxy_quic_data.AddReadPauseForever();

  // The browser ACK's the datagram from proxy1, and acks proxy2's OK response
  // packet via proxy1.
  proxy_quic_data.AddWrite(
      ASYNC,
      ConstructAckAndClientH3DatagramPacket(
          to_proxy1, to_proxy1_packet_num++, 3, 1, stream_id_0,
          kConnectUdpContextId,
          ConstructAckPacket(to_proxy2, to_proxy2_packet_num++, 1, 2, 1)));

  // The browser sends initial settings to the endpoint, via proxy2, via proxy1.
  datagrams.clear();
  std::vector<std::unique_ptr<quic::QuicEncryptedPacket>> inner_datagrams;
  inner_datagrams.push_back(
      ConstructInitialSettingsPacket(to_endpoint, to_endpoint_packet_num++));
  datagrams.push_back(ConstructClientH3DatagramPacket(
      to_proxy2, to_proxy2_packet_num++, stream_id_0, kConnectUdpContextId,
      std::move(inner_datagrams)));
  proxy_quic_data.AddWrite(
      ASYNC, ConstructClientH3DatagramPacket(to_proxy1, to_proxy1_packet_num++,
                                             stream_id_0, kConnectUdpContextId,
                                             std::move(datagrams)));

  proxy_quic_data.AddSocketDataToFactory(socket_factory());

  HttpNetworkSession* session = MakeSession();

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = kRequestUrl;
  request_info.load_flags = 0;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StreamRequester requester(session);
  requester.RequestStreamAndWait(session->http_stream_factory(), request_info,
                                 DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                 /*enable_ip_based_pooling=*/true,
                                 /*enable_alternative_services=*/true);

  EXPECT_TRUE(requester.stream_done());
  EXPECT_FALSE(requester.websocket_stream());
  EXPECT_TRUE(requester.stream());
  EXPECT_FALSE(requester.used_proxy_info().is_direct());

  RunUntilIdle();

  proxy_quic_data.ExpectAllReadDataConsumed();
  proxy_quic_data.ExpectAllWriteDataConsumed();
}

class HttpStreamFactoryBidirectionalQuicTest
    : public TestWithTaskEnvironment,
      public ::testing::WithParamInterface<quic::ParsedQuicVersion> {
 protected:
  HttpStreamFactoryBidirectionalQuicTest()
      : default_url_(kDefaultUrl),
        version_(GetParam()),
        client_packet_maker_(version_,
                             quic::QuicUtils::CreateRandomConnectionId(
                                 quic_context_.random_generator()),
                             quic_context_.clock(),
                             "www.example.org",
                             quic::Perspective::IS_CLIENT),
        server_packet_maker_(version_,
                             quic::QuicUtils::CreateRandomConnectionId(
                                 quic_context_.random_generator()),
                             quic_context_.clock(),
                             "www.example.org",
                             quic::Perspective::IS_SERVER,
                             false),
        proxy_resolution_service_(
            ConfiguredProxyResolutionService::CreateDirect()),
        ssl_config_service_(std::make_unique<SSLConfigServiceDefaults>()) {
    // Explicitly disable HappyEyeballsV3 because it doesn't support
    // bidirectional streams.
    // TODO(crbug.com/346835898): Support bidirectional streams in
    // HappyEyeballsV3.
    feature_list_.InitAndDisableFeature(features::kHappyEyeballsV3);
    FLAGS_quic_enable_http3_grease_randomness = false;
    quic_context_.AdvanceTime(quic::QuicTime::Delta::FromMilliseconds(20));
    quic::QuicEnableVersion(version_);
  }

  void TearDown() override { session_.reset(); }

  void Initialize() {
    params_.enable_quic = true;
    quic_context_.params()->supported_versions =
        quic::test::SupportedVersions(version_);

    HttpNetworkSessionContext session_context;
    session_context.http_server_properties = &http_server_properties_;
    session_context.quic_context = &quic_context_;

    // Load a certificate that is valid for *.example.org
    scoped_refptr<X509Certificate> test_cert(
        ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
    EXPECT_TRUE(test_cert.get());
    verify_details_.cert_verify_result.verified_cert = test_cert;
    verify_details_.cert_verify_result.is_issued_by_known_root = true;
    crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details_);
    crypto_client_stream_factory_.set_handshake_mode(
        MockCryptoClientStream::CONFIRM_HANDSHAKE);
    session_context.cert_verifier = &cert_verifier_;
    session_context.quic_crypto_client_stream_factory =
        &crypto_client_stream_factory_;
    session_context.transport_security_state = &transport_security_state_;
    session_context.host_resolver = &host_resolver_;
    session_context.proxy_resolution_service = proxy_resolution_service_.get();
    session_context.ssl_config_service = ssl_config_service_.get();
    session_context.client_socket_factory = &socket_factory_;
    session_ = std::make_unique<HttpNetworkSession>(params_, session_context);
    session_->quic_session_pool()->set_has_quic_ever_worked_on_current_network(
        true);
  }

  void AddQuicAlternativeService(const url::SchemeHostPort& request_url,
                                 const std::string& alternative_destination) {
    const AlternativeService alternative_service(kProtoQUIC,
                                                 alternative_destination, 443);
    base::Time expiration = base::Time::Now() + base::Days(1);
    http_server_properties_.SetQuicAlternativeService(
        request_url, NetworkAnonymizationKey(), alternative_service, expiration,
        session_->context().quic_context->params()->supported_versions);
  }

  void AddQuicAlternativeService() {
    AddQuicAlternativeService(url::SchemeHostPort(default_url_),
                              "www.example.org");
  }

  test::QuicTestPacketMaker& client_packet_maker() {
    return client_packet_maker_;
  }
  test::QuicTestPacketMaker& server_packet_maker() {
    return server_packet_maker_;
  }

  MockTaggingClientSocketFactory& socket_factory() { return socket_factory_; }

  HttpNetworkSession* session() { return session_.get(); }

  const GURL default_url_;

  quic::QuicStreamId GetNthClientInitiatedBidirectionalStreamId(int n) {
    return quic::test::GetNthClientInitiatedBidirectionalStreamId(
        version_.transport_version, n);
  }

  quic::ParsedQuicVersion version() const { return version_; }

  MockHostResolver* host_resolver() { return &host_resolver_; }

 private:
  base::test::ScopedFeatureList feature_list_;
  quic::test::QuicFlagSaver saver_;
  const quic::ParsedQuicVersion version_;
  MockQuicContext quic_context_;
  test::QuicTestPacketMaker client_packet_maker_;
  test::QuicTestPacketMaker server_packet_maker_;
  MockTaggingClientSocketFactory socket_factory_;
  std::unique_ptr<HttpNetworkSession> session_;
  MockCertVerifier cert_verifier_;
  ProofVerifyDetailsChromium verify_details_;
  MockCryptoClientStreamFactory crypto_client_stream_factory_;
  HttpServerProperties http_server_properties_;
  TransportSecurityState transport_security_state_;
  MockHostResolver host_resolver_{
      /*default_result=*/
      MockHostResolverBase::RuleResolver::GetLocalhostResult()};
  std::unique_ptr<ProxyResolutionService> proxy_resolution_service_;
  std::unique_ptr<SSLConfigServiceDefaults> ssl_config_service_;
  HttpNetworkSessionParams params_;
};

INSTANTIATE_TEST_SUITE_P(VersionIncludeStreamDependencySequence,
                         HttpStreamFactoryBidirectionalQuicTest,
                         ::testing::ValuesIn(AllSupportedQuicVersions()),
                         ::testing::PrintToStringParamName());

TEST_P(HttpStreamFactoryBidirectionalQuicTest,
       RequestBidirectionalStreamImplQuicAlternative) {
  base::test::ScopedFeatureList scoped_feature_list;
  // Explicitly disable HappyEyeballsV3 because it doesn't support bidirectional
  // streams yet.
  // TODO(crbug.com/346835898): Support bidirectional streams in
  // HappyEyeballsV3.
  scoped_feature_list.InitAndDisableFeature(features::kHappyEyeballsV3);

  MockQuicData mock_quic_data(version());
  // Set priority to default value so that
  // QuicTestPacketMaker::MakeRequestHeadersPacket() does not add mock
  // PRIORITY_UPDATE frame, which BidirectionalStreamQuicImpl currently does not
  // send.
  // TODO(crbug.com/40678380): Implement PRIORITY_UPDATE in
  // BidirectionalStreamQuicImpl.
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

  // Now request a stream.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = default_url_;
  request_info.load_flags = 0;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StreamRequester requester(session());
  requester.RequestBidirectionalStreamImpl(
      session()->http_stream_factory(), request_info, DEFAULT_PRIORITY,
      /*allowed_bad_certs=*/{},
      /*enable_ip_based_pooling=*/true,
      /*enable_alternative_services=*/true);

  requester.WaitForStream();
  EXPECT_TRUE(requester.stream_done());
  EXPECT_FALSE(requester.websocket_stream());
  ASSERT_FALSE(requester.stream());
  ASSERT_TRUE(requester.bidirectional_stream_impl());
  BidirectionalStreamImpl* stream_impl = requester.bidirectional_stream_impl();

  BidirectionalStreamRequestInfo bidi_request_info;
  bidi_request_info.method = "GET";
  bidi_request_info.url = default_url_;
  bidi_request_info.end_stream_on_headers = true;
  bidi_request_info.priority = LOWEST;

  TestBidirectionalDelegate delegate;
  stream_impl->Start(&bidi_request_info, NetLogWithSource(),
                     /*send_request_headers_automatically=*/true, &delegate,
                     nullptr, TRAFFIC_ANNOTATION_FOR_TESTS);
  delegate.WaitUntilDone();

  auto buffer = base::MakeRefCounted<IOBufferWithSize>(1);
  EXPECT_THAT(stream_impl->ReadData(buffer.get(), 1), IsOk());
  EXPECT_EQ(kProtoQUIC, stream_impl->GetProtocol());
  EXPECT_EQ("200", delegate.response_headers().find(":status")->second);
  EXPECT_EQ(0,
            GetPoolGroupCount(session(), HttpNetworkSession::NORMAL_SOCKET_POOL,
                              ProxyChain::Direct()));
  EXPECT_TRUE(requester.used_proxy_info().is_direct());
}

// Tests that if Http job fails, but Quic job succeeds, we return
// BidirectionalStreamQuicImpl.
TEST_P(HttpStreamFactoryBidirectionalQuicTest,
       RequestBidirectionalStreamImplHttpJobFailsQuicJobSucceeds) {
  base::test::ScopedFeatureList scoped_feature_list;
  // Explicitly disable HappyEyeballsV3 because it doesn't support bidirectional
  // streams yet.
  // TODO(crbug.com/346835898): Support bidirectional streams in
  // HappyEyeballsV3.
  scoped_feature_list.InitAndDisableFeature(features::kHappyEyeballsV3);

  // Set up Quic data.
  MockQuicData mock_quic_data(version());
  // Set priority to default value so that
  // QuicTestPacketMaker::MakeRequestHeadersPacket() does not add mock
  // PRIORITY_UPDATE frame, which BidirectionalStreamQuicImpl currently does not
  // send.
  // TODO(crbug.com/40678380): Implement PRIORITY_UPDATE in
  // BidirectionalStreamQuicImpl.
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

  // Make the http job fail.
  auto http_job_data = std::make_unique<StaticSocketDataProvider>();
  MockConnect failed_connect(ASYNC, ERR_CONNECTION_REFUSED);
  http_job_data->set_connect_data(failed_connect);
  socket_factory().AddSocketDataProvider(http_job_data.get());
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  socket_factory().AddSSLSocketDataProvider(&ssl_data);

  // Set up QUIC as alternative_service.
  Initialize();
  AddQuicAlternativeService();

  // Now request a stream.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = default_url_;
  request_info.load_flags = 0;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StreamRequester requester(session());
  requester.RequestBidirectionalStreamImpl(
      session()->http_stream_factory(), request_info, DEFAULT_PRIORITY,
      /*allowed_bad_certs=*/{},
      /*enable_ip_based_pooling=*/true,
      /*enable_alternative_services=*/true);

  requester.WaitForStream();
  EXPECT_TRUE(requester.stream_done());
  EXPECT_FALSE(requester.websocket_stream());
  ASSERT_FALSE(requester.stream());
  ASSERT_TRUE(requester.bidirectional_stream_impl());
  BidirectionalStreamImpl* stream_impl = requester.bidirectional_stream_impl();

  BidirectionalStreamRequestInfo bidi_request_info;
  bidi_request_info.method = "GET";
  bidi_request_info.url = default_url_;
  bidi_request_info.end_stream_on
Prompt: 
```
这是目录为net/http/http_stream_factory_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共6部分，请归纳一下它的功能

"""
                                              &spdy_headers_frame_len);
  }

  std::unique_ptr<quic::QuicEncryptedPacket>
  ConstructAckAndClientH3DatagramPacket(
      test::QuicTestPacketMaker& packet_maker,
      uint64_t packet_number,
      uint64_t largest_received,
      uint64_t smallest_received,
      uint64_t quarter_stream_id,
      uint64_t context_id,
      std::unique_ptr<quic::QuicEncryptedPacket> packet) {
    std::string datagram;
    // Allow enough space for payload and two varint-62's.
    datagram.resize(packet->length() + 2 * 8);
    quiche::QuicheDataWriter writer(datagram.capacity(), datagram.data());
    CHECK(writer.WriteVarInt62(quarter_stream_id));
    CHECK(writer.WriteVarInt62(context_id));
    CHECK(writer.WriteBytes(packet->data(), packet->length()));
    datagram.resize(writer.length());
    return packet_maker.MakeAckAndDatagramPacket(
        packet_number, largest_received, smallest_received, datagram);
  }

  std::unique_ptr<quic::QuicEncryptedPacket> ConstructClientH3DatagramPacket(
      test::QuicTestPacketMaker& packet_maker,
      uint64_t packet_number,
      uint64_t quarter_stream_id,
      uint64_t context_id,
      std::vector<std::unique_ptr<quic::QuicEncryptedPacket>> packets) {
    auto& builder = packet_maker.Packet(packet_number);
    for (auto& packet : packets) {
      std::string data;
      // Allow enough space for payload and two varint-62's.
      data.resize(packet->length() + 2 * 8);
      quiche::QuicheDataWriter writer(data.capacity(), data.data());
      CHECK(writer.WriteVarInt62(quarter_stream_id));
      CHECK(writer.WriteVarInt62(context_id));
      CHECK(writer.WriteBytes(packet->data(), packet->length()));
      data.resize(writer.length());
      builder.AddMessageFrame(data);
    }
    return builder.Build();
  }

  // Make a `QuicTestPacketMaker` for the current test with the given
  // characteristics.
  test::QuicTestPacketMaker MakePacketMaker(
      const std::string& host,
      quic::Perspective perspective,
      bool client_priority_uses_incremental = false,
      bool use_priority_header = false) {
    return test::QuicTestPacketMaker(
        version_, quic::QuicUtils::CreateRandomConnectionId(random_generator_),
        clock_, host, perspective, client_priority_uses_incremental,
        use_priority_header);
  }

  MockTaggingClientSocketFactory* socket_factory() { return &socket_factory_; }

  quic::QuicStreamId GetNthClientInitiatedBidirectionalStreamId(int n) {
    return quic::test::GetNthClientInitiatedBidirectionalStreamId(
        version_.transport_version, n);
  }

  SpdySessionDependencies& session_deps() { return session_deps_; }

  quic::ParsedQuicVersion version() const { return version_; }

 private:
  quic::test::QuicFlagSaver saver_;
  const quic::ParsedQuicVersion version_;
  std::unique_ptr<MockQuicContext> quic_context_;
  SpdySessionDependencies session_deps_;
  raw_ptr<const quic::QuicClock> clock_;
  raw_ptr<quic::QuicRandom> random_generator_;
  MockTaggingClientSocketFactory socket_factory_;
  std::unique_ptr<HttpNetworkSession> session_;
  ProofVerifyDetailsChromium verify_details_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         HttpStreamFactoryQuicTest,
                         ::testing::ValuesIn(GetTestParams()),
                         ::testing::PrintToStringParamName());

// Check that requesting an HTTP stream over a QUIC proxy sends the correct
// set of QUIC packets.
TEST_P(HttpStreamFactoryQuicTest, RequestHttpStreamOverQuicProxy) {
  static constexpr uint64_t kConnectUdpContextId = 0;
  GURL kRequestUrl("https://www.example.org");
  session_deps().proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
          {ProxyChain::ForIpProtection({ProxyServer::FromSchemeHostAndPort(
              ProxyServer::SCHEME_QUIC, "qproxy.example.org", 8888)})},
          TRAFFIC_ANNOTATION_FOR_TESTS);

  MockQuicData proxy_quic_data(version());
  quic::QuicStreamId stream_id = GetNthClientInitiatedBidirectionalStreamId(0);
  int to_proxy_packet_num = 1;
  auto to_proxy =
      MakePacketMaker("qproxy.example.org", quic::Perspective::IS_CLIENT,
                      /*client_priority_uses_incremental=*/true,
                      /*use_priority_header=*/false);
  int from_proxy_packet_num = 1;
  auto from_proxy =
      MakePacketMaker("qproxy.example.org", quic::Perspective::IS_SERVER,
                      /*client_priority_uses_incremental=*/false,
                      /*use_priority_header=*/false);
  int to_endpoint_packet_num = 1;
  auto to_endpoint =
      MakePacketMaker("www.example.org", quic::Perspective::IS_CLIENT,
                      /*client_priority_uses_incremental=*/true,
                      /*use_priority_header=*/true);

  // The browser sends initial settings to the proxy.
  proxy_quic_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket(
                                            to_proxy, to_proxy_packet_num++));

  // The browser sends CONNECT-UDP request to proxy.
  proxy_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructConnectUdpRequestPacket(
          to_proxy, to_proxy_packet_num++, stream_id, "qproxy.example.org:8888",
          "/.well-known/masque/udp/www.example.org/443/", false));

  // Proxy sends initial settings.
  proxy_quic_data.AddRead(ASYNC, ConstructInitialSettingsPacket(
                                     from_proxy, from_proxy_packet_num++));

  // Proxy responds to the CONNECT.
  proxy_quic_data.AddRead(
      ASYNC, ConstructOkResponsePacket(from_proxy, from_proxy_packet_num++,
                                       stream_id, true));
  proxy_quic_data.AddReadPauseForever();

  // The browser ACKs the OK response packet.
  proxy_quic_data.AddWrite(
      ASYNC, ConstructAckPacket(to_proxy, to_proxy_packet_num++, 1, 2, 1));

  // The browser sends initial settings to the endpoint, via proxy.
  std::vector<std::unique_ptr<quic::QuicEncryptedPacket>> datagrams;
  datagrams.push_back(
      ConstructInitialSettingsPacket(to_endpoint, to_endpoint_packet_num++));
  proxy_quic_data.AddWrite(
      ASYNC, ConstructClientH3DatagramPacket(to_proxy, to_proxy_packet_num++,
                                             stream_id, kConnectUdpContextId,
                                             std::move(datagrams)));

  proxy_quic_data.AddSocketDataToFactory(socket_factory());

  HttpNetworkSession* session = MakeSession();

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = kRequestUrl;
  request_info.load_flags = 0;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StreamRequester requester(session);
  requester.RequestStreamAndWait(session->http_stream_factory(), request_info,
                                 DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                 /*enable_ip_based_pooling=*/true,
                                 /*enable_alternative_services=*/true);

  EXPECT_TRUE(requester.stream_done());
  EXPECT_FALSE(requester.websocket_stream());
  EXPECT_TRUE(requester.stream());
  EXPECT_FALSE(requester.used_proxy_info().is_direct());

  RunUntilIdle();

  proxy_quic_data.ExpectAllReadDataConsumed();
  proxy_quic_data.ExpectAllWriteDataConsumed();
}

// Check that requesting an HTTP stream over a two QUIC proxies sends the
// correct set of QUIC packets.
TEST_P(HttpStreamFactoryQuicTest, RequestHttpStreamOverTwoQuicProxies) {
  static constexpr uint64_t kConnectUdpContextId = 0;
  GURL kRequestUrl("https://www.example.org");
  session_deps().proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
          {
              ProxyChain::ForIpProtection(
                  {ProxyServer::FromSchemeHostAndPort(
                       ProxyServer::SCHEME_QUIC, "qproxy1.example.org", 8888),
                   ProxyServer::FromSchemeHostAndPort(
                       ProxyServer::SCHEME_QUIC, "qproxy2.example.org", 8888)}),
          },
          TRAFFIC_ANNOTATION_FOR_TESTS);

  MockQuicData proxy_quic_data(version());
  quic::QuicStreamId stream_id_0 =
      GetNthClientInitiatedBidirectionalStreamId(0);
  int to_proxy1_packet_num = 1;
  auto to_proxy1 =
      MakePacketMaker("qproxy1.example.org", quic::Perspective::IS_CLIENT,
                      /*client_priority_uses_incremental=*/true,
                      /*use_priority_header=*/false);
  int from_proxy1_packet_num = 1;
  auto from_proxy1 =
      MakePacketMaker("qproxy1.example.org", quic::Perspective::IS_SERVER,
                      /*client_priority_uses_incremental=*/false,
                      /*use_priority_header=*/false);
  int to_proxy2_packet_num = 1;
  auto to_proxy2 =
      MakePacketMaker("qproxy2.example.org", quic::Perspective::IS_CLIENT,
                      /*client_priority_uses_incremental=*/true,
                      /*use_priority_header=*/false);
  int from_proxy2_packet_num = 1;
  auto from_proxy2 =
      MakePacketMaker("qproxy2.example.org", quic::Perspective::IS_SERVER,
                      /*client_priority_uses_incremental=*/false,
                      /*use_priority_header=*/false);
  int to_endpoint_packet_num = 1;
  auto to_endpoint =
      MakePacketMaker("www.example.org", quic::Perspective::IS_CLIENT,
                      /*client_priority_uses_incremental=*/true,
                      /*use_priority_header=*/true);

  // The browser sends initial settings to proxy1.
  proxy_quic_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket(
                                            to_proxy1, to_proxy1_packet_num++));

  // The browser sends CONNECT-UDP request to proxy1.
  proxy_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructConnectUdpRequestPacket(
          to_proxy1, to_proxy1_packet_num++, stream_id_0,
          "qproxy1.example.org:8888",
          "/.well-known/masque/udp/qproxy2.example.org/8888/", false));

  // Proxy1 sends initial settings.
  proxy_quic_data.AddRead(ASYNC, ConstructInitialSettingsPacket(
                                     from_proxy1, from_proxy1_packet_num++));

  // Proxy1 responds to the CONNECT.
  proxy_quic_data.AddRead(
      ASYNC, ConstructOkResponsePacket(from_proxy1, from_proxy1_packet_num++,
                                       stream_id_0, true));

  // The browser ACKs the OK response packet.
  proxy_quic_data.AddWrite(
      ASYNC, ConstructAckPacket(to_proxy1, to_proxy1_packet_num++, 1, 2, 1));

  // The browser sends initial settings and a CONNECT-UDP request to proxy2 via
  // proxy1.
  std::vector<std::unique_ptr<quic::QuicEncryptedPacket>> datagrams;
  datagrams.push_back(
      ConstructInitialSettingsPacket(to_proxy2, to_proxy2_packet_num++));
  datagrams.push_back(ConstructConnectUdpRequestPacket(
      to_proxy2, to_proxy2_packet_num++, stream_id_0,
      "qproxy2.example.org:8888",
      "/.well-known/masque/udp/www.example.org/443/", false));
  proxy_quic_data.AddWrite(
      ASYNC, ConstructClientH3DatagramPacket(to_proxy1, to_proxy1_packet_num++,
                                             stream_id_0, kConnectUdpContextId,
                                             std::move(datagrams)));

  // Proxy2 sends initial settings and an OK response to the CONNECT request,
  // via proxy1.
  datagrams.clear();
  datagrams.push_back(
      ConstructInitialSettingsPacket(from_proxy2, from_proxy2_packet_num++));
  datagrams.push_back(ConstructOkResponsePacket(
      from_proxy2, from_proxy2_packet_num++, stream_id_0, true));
  proxy_quic_data.AddRead(
      ASYNC, ConstructClientH3DatagramPacket(
                 from_proxy1, from_proxy1_packet_num++, stream_id_0,
                 kConnectUdpContextId, std::move(datagrams)));
  proxy_quic_data.AddReadPauseForever();

  // The browser ACK's the datagram from proxy1, and acks proxy2's OK response
  // packet via proxy1.
  proxy_quic_data.AddWrite(
      ASYNC,
      ConstructAckAndClientH3DatagramPacket(
          to_proxy1, to_proxy1_packet_num++, 3, 1, stream_id_0,
          kConnectUdpContextId,
          ConstructAckPacket(to_proxy2, to_proxy2_packet_num++, 1, 2, 1)));

  // The browser sends initial settings to the endpoint, via proxy2, via proxy1.
  datagrams.clear();
  std::vector<std::unique_ptr<quic::QuicEncryptedPacket>> inner_datagrams;
  inner_datagrams.push_back(
      ConstructInitialSettingsPacket(to_endpoint, to_endpoint_packet_num++));
  datagrams.push_back(ConstructClientH3DatagramPacket(
      to_proxy2, to_proxy2_packet_num++, stream_id_0, kConnectUdpContextId,
      std::move(inner_datagrams)));
  proxy_quic_data.AddWrite(
      ASYNC, ConstructClientH3DatagramPacket(to_proxy1, to_proxy1_packet_num++,
                                             stream_id_0, kConnectUdpContextId,
                                             std::move(datagrams)));

  proxy_quic_data.AddSocketDataToFactory(socket_factory());

  HttpNetworkSession* session = MakeSession();

  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = kRequestUrl;
  request_info.load_flags = 0;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StreamRequester requester(session);
  requester.RequestStreamAndWait(session->http_stream_factory(), request_info,
                                 DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                                 /*enable_ip_based_pooling=*/true,
                                 /*enable_alternative_services=*/true);

  EXPECT_TRUE(requester.stream_done());
  EXPECT_FALSE(requester.websocket_stream());
  EXPECT_TRUE(requester.stream());
  EXPECT_FALSE(requester.used_proxy_info().is_direct());

  RunUntilIdle();

  proxy_quic_data.ExpectAllReadDataConsumed();
  proxy_quic_data.ExpectAllWriteDataConsumed();
}

class HttpStreamFactoryBidirectionalQuicTest
    : public TestWithTaskEnvironment,
      public ::testing::WithParamInterface<quic::ParsedQuicVersion> {
 protected:
  HttpStreamFactoryBidirectionalQuicTest()
      : default_url_(kDefaultUrl),
        version_(GetParam()),
        client_packet_maker_(version_,
                             quic::QuicUtils::CreateRandomConnectionId(
                                 quic_context_.random_generator()),
                             quic_context_.clock(),
                             "www.example.org",
                             quic::Perspective::IS_CLIENT),
        server_packet_maker_(version_,
                             quic::QuicUtils::CreateRandomConnectionId(
                                 quic_context_.random_generator()),
                             quic_context_.clock(),
                             "www.example.org",
                             quic::Perspective::IS_SERVER,
                             false),
        proxy_resolution_service_(
            ConfiguredProxyResolutionService::CreateDirect()),
        ssl_config_service_(std::make_unique<SSLConfigServiceDefaults>()) {
    // Explicitly disable HappyEyeballsV3 because it doesn't support
    // bidirectional streams.
    // TODO(crbug.com/346835898): Support bidirectional streams in
    // HappyEyeballsV3.
    feature_list_.InitAndDisableFeature(features::kHappyEyeballsV3);
    FLAGS_quic_enable_http3_grease_randomness = false;
    quic_context_.AdvanceTime(quic::QuicTime::Delta::FromMilliseconds(20));
    quic::QuicEnableVersion(version_);
  }

  void TearDown() override { session_.reset(); }

  void Initialize() {
    params_.enable_quic = true;
    quic_context_.params()->supported_versions =
        quic::test::SupportedVersions(version_);

    HttpNetworkSessionContext session_context;
    session_context.http_server_properties = &http_server_properties_;
    session_context.quic_context = &quic_context_;

    // Load a certificate that is valid for *.example.org
    scoped_refptr<X509Certificate> test_cert(
        ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
    EXPECT_TRUE(test_cert.get());
    verify_details_.cert_verify_result.verified_cert = test_cert;
    verify_details_.cert_verify_result.is_issued_by_known_root = true;
    crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details_);
    crypto_client_stream_factory_.set_handshake_mode(
        MockCryptoClientStream::CONFIRM_HANDSHAKE);
    session_context.cert_verifier = &cert_verifier_;
    session_context.quic_crypto_client_stream_factory =
        &crypto_client_stream_factory_;
    session_context.transport_security_state = &transport_security_state_;
    session_context.host_resolver = &host_resolver_;
    session_context.proxy_resolution_service = proxy_resolution_service_.get();
    session_context.ssl_config_service = ssl_config_service_.get();
    session_context.client_socket_factory = &socket_factory_;
    session_ = std::make_unique<HttpNetworkSession>(params_, session_context);
    session_->quic_session_pool()->set_has_quic_ever_worked_on_current_network(
        true);
  }

  void AddQuicAlternativeService(const url::SchemeHostPort& request_url,
                                 const std::string& alternative_destination) {
    const AlternativeService alternative_service(kProtoQUIC,
                                                 alternative_destination, 443);
    base::Time expiration = base::Time::Now() + base::Days(1);
    http_server_properties_.SetQuicAlternativeService(
        request_url, NetworkAnonymizationKey(), alternative_service, expiration,
        session_->context().quic_context->params()->supported_versions);
  }

  void AddQuicAlternativeService() {
    AddQuicAlternativeService(url::SchemeHostPort(default_url_),
                              "www.example.org");
  }

  test::QuicTestPacketMaker& client_packet_maker() {
    return client_packet_maker_;
  }
  test::QuicTestPacketMaker& server_packet_maker() {
    return server_packet_maker_;
  }

  MockTaggingClientSocketFactory& socket_factory() { return socket_factory_; }

  HttpNetworkSession* session() { return session_.get(); }

  const GURL default_url_;

  quic::QuicStreamId GetNthClientInitiatedBidirectionalStreamId(int n) {
    return quic::test::GetNthClientInitiatedBidirectionalStreamId(
        version_.transport_version, n);
  }

  quic::ParsedQuicVersion version() const { return version_; }

  MockHostResolver* host_resolver() { return &host_resolver_; }

 private:
  base::test::ScopedFeatureList feature_list_;
  quic::test::QuicFlagSaver saver_;
  const quic::ParsedQuicVersion version_;
  MockQuicContext quic_context_;
  test::QuicTestPacketMaker client_packet_maker_;
  test::QuicTestPacketMaker server_packet_maker_;
  MockTaggingClientSocketFactory socket_factory_;
  std::unique_ptr<HttpNetworkSession> session_;
  MockCertVerifier cert_verifier_;
  ProofVerifyDetailsChromium verify_details_;
  MockCryptoClientStreamFactory crypto_client_stream_factory_;
  HttpServerProperties http_server_properties_;
  TransportSecurityState transport_security_state_;
  MockHostResolver host_resolver_{
      /*default_result=*/
      MockHostResolverBase::RuleResolver::GetLocalhostResult()};
  std::unique_ptr<ProxyResolutionService> proxy_resolution_service_;
  std::unique_ptr<SSLConfigServiceDefaults> ssl_config_service_;
  HttpNetworkSessionParams params_;
};

INSTANTIATE_TEST_SUITE_P(VersionIncludeStreamDependencySequence,
                         HttpStreamFactoryBidirectionalQuicTest,
                         ::testing::ValuesIn(AllSupportedQuicVersions()),
                         ::testing::PrintToStringParamName());

TEST_P(HttpStreamFactoryBidirectionalQuicTest,
       RequestBidirectionalStreamImplQuicAlternative) {
  base::test::ScopedFeatureList scoped_feature_list;
  // Explicitly disable HappyEyeballsV3 because it doesn't support bidirectional
  // streams yet.
  // TODO(crbug.com/346835898): Support bidirectional streams in
  // HappyEyeballsV3.
  scoped_feature_list.InitAndDisableFeature(features::kHappyEyeballsV3);

  MockQuicData mock_quic_data(version());
  // Set priority to default value so that
  // QuicTestPacketMaker::MakeRequestHeadersPacket() does not add mock
  // PRIORITY_UPDATE frame, which BidirectionalStreamQuicImpl currently does not
  // send.
  // TODO(crbug.com/40678380): Implement PRIORITY_UPDATE in
  // BidirectionalStreamQuicImpl.
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

  // Now request a stream.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = default_url_;
  request_info.load_flags = 0;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StreamRequester requester(session());
  requester.RequestBidirectionalStreamImpl(
      session()->http_stream_factory(), request_info, DEFAULT_PRIORITY,
      /*allowed_bad_certs=*/{},
      /*enable_ip_based_pooling=*/true,
      /*enable_alternative_services=*/true);

  requester.WaitForStream();
  EXPECT_TRUE(requester.stream_done());
  EXPECT_FALSE(requester.websocket_stream());
  ASSERT_FALSE(requester.stream());
  ASSERT_TRUE(requester.bidirectional_stream_impl());
  BidirectionalStreamImpl* stream_impl = requester.bidirectional_stream_impl();

  BidirectionalStreamRequestInfo bidi_request_info;
  bidi_request_info.method = "GET";
  bidi_request_info.url = default_url_;
  bidi_request_info.end_stream_on_headers = true;
  bidi_request_info.priority = LOWEST;

  TestBidirectionalDelegate delegate;
  stream_impl->Start(&bidi_request_info, NetLogWithSource(),
                     /*send_request_headers_automatically=*/true, &delegate,
                     nullptr, TRAFFIC_ANNOTATION_FOR_TESTS);
  delegate.WaitUntilDone();

  auto buffer = base::MakeRefCounted<IOBufferWithSize>(1);
  EXPECT_THAT(stream_impl->ReadData(buffer.get(), 1), IsOk());
  EXPECT_EQ(kProtoQUIC, stream_impl->GetProtocol());
  EXPECT_EQ("200", delegate.response_headers().find(":status")->second);
  EXPECT_EQ(0,
            GetPoolGroupCount(session(), HttpNetworkSession::NORMAL_SOCKET_POOL,
                              ProxyChain::Direct()));
  EXPECT_TRUE(requester.used_proxy_info().is_direct());
}

// Tests that if Http job fails, but Quic job succeeds, we return
// BidirectionalStreamQuicImpl.
TEST_P(HttpStreamFactoryBidirectionalQuicTest,
       RequestBidirectionalStreamImplHttpJobFailsQuicJobSucceeds) {
  base::test::ScopedFeatureList scoped_feature_list;
  // Explicitly disable HappyEyeballsV3 because it doesn't support bidirectional
  // streams yet.
  // TODO(crbug.com/346835898): Support bidirectional streams in
  // HappyEyeballsV3.
  scoped_feature_list.InitAndDisableFeature(features::kHappyEyeballsV3);

  // Set up Quic data.
  MockQuicData mock_quic_data(version());
  // Set priority to default value so that
  // QuicTestPacketMaker::MakeRequestHeadersPacket() does not add mock
  // PRIORITY_UPDATE frame, which BidirectionalStreamQuicImpl currently does not
  // send.
  // TODO(crbug.com/40678380): Implement PRIORITY_UPDATE in
  // BidirectionalStreamQuicImpl.
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

  // Make the http job fail.
  auto http_job_data = std::make_unique<StaticSocketDataProvider>();
  MockConnect failed_connect(ASYNC, ERR_CONNECTION_REFUSED);
  http_job_data->set_connect_data(failed_connect);
  socket_factory().AddSocketDataProvider(http_job_data.get());
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  socket_factory().AddSSLSocketDataProvider(&ssl_data);

  // Set up QUIC as alternative_service.
  Initialize();
  AddQuicAlternativeService();

  // Now request a stream.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = default_url_;
  request_info.load_flags = 0;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StreamRequester requester(session());
  requester.RequestBidirectionalStreamImpl(
      session()->http_stream_factory(), request_info, DEFAULT_PRIORITY,
      /*allowed_bad_certs=*/{},
      /*enable_ip_based_pooling=*/true,
      /*enable_alternative_services=*/true);

  requester.WaitForStream();
  EXPECT_TRUE(requester.stream_done());
  EXPECT_FALSE(requester.websocket_stream());
  ASSERT_FALSE(requester.stream());
  ASSERT_TRUE(requester.bidirectional_stream_impl());
  BidirectionalStreamImpl* stream_impl = requester.bidirectional_stream_impl();

  BidirectionalStreamRequestInfo bidi_request_info;
  bidi_request_info.method = "GET";
  bidi_request_info.url = default_url_;
  bidi_request_info.end_stream_on_headers = true;
  bidi_request_info.priority = LOWEST;

  TestBidirectionalDelegate delegate;
  stream_impl->Start(&bidi_request_info, NetLogWithSource(),
                     /*send_request_headers_automatically=*/true, &delegate,
                     nullptr, TRAFFIC_ANNOTATION_FOR_TESTS);
  delegate.WaitUntilDone();

  // Make sure the BidirectionalStream negotiated goes through QUIC.
  auto buffer = base::MakeRefCounted<IOBufferWithSize>(1);
  EXPECT_THAT(stream_impl->ReadData(buffer.get(), 1), IsOk());
  EXPECT_EQ(kProtoQUIC, stream_impl->GetProtocol());
  EXPECT_EQ("200", delegate.response_headers().find(":status")->second);
  // There is no Http2 socket pool.
  EXPECT_EQ(0,
            GetPoolGroupCount(session(), HttpNetworkSession::NORMAL_SOCKET_POOL,
                              ProxyChain::Direct()));
  EXPECT_TRUE(requester.used_proxy_info().is_direct());
}

TEST_P(HttpStreamFactoryTest, RequestBidirectionalStreamImplFailure) {
  base::test::ScopedFeatureList scoped_feature_list;
  // Explicitly disable HappyEyeballsV3 because it doesn't support bidirectional
  // streams yet.
  // TODO(crbug.com/346835898): Support bidirectional streams in
  // HappyEyeballsV3.
  scoped_feature_list.InitAndDisableFeature(features::kHappyEyeballsV3);

  SpdySessionDependencies session_deps(
      ConfiguredProxyResolutionService::CreateDirect());

  MockRead mock_read(ASYNC, OK);
  SequencedSocketData socket_data(base::span_from_ref(mock_read),
                                  base::span<MockWrite>());
  socket_data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps.socket_factory->AddSocketDataProvider(&socket_data);

  SSLSocketDataProvider ssl_socket_data(ASYNC, OK);

  // If HTTP/1 is used, BidirectionalStreamImpl should not be obtained.
  ssl_socket_data.next_proto = kProtoHTTP11;
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);

  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  // Now request a stream.
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("https://www.google.com");
  request_info.load_flags = 0;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  StreamRequester requester(session.get());
  requester.RequestBidirectionalStreamImpl(
      session->http_stream_factory(), request_info, DEFAULT_PRIORITY,
      /*allowed_bad_certs=*/{},
      /*enable_ip_based_pooling=*/true,
      /*enable_alternative_services=*/true);
  requester.WaitForStream();
  EXPECT_TRUE(requester.stream_done());
  ASSERT_THAT(requester.error_status(), IsError(ERR_FAILED));
  EXPECT_FALSE(requester.websocket_stream());
  ASSERT_FALSE(requester.stream());
  ASSERT_FALSE(requester.bidirectional_stream_impl());
  EXPECT_EQ(1, GetPoolGroupCount(session.get(),
                                 HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()));
}

#if BUILDFLAG(IS_ANDROID)
// Verify HttpStreamFactory::Job passes socket tag along properly and that
// SpdySessions have unique socket tags (e.g. one sessions should not be shared
// amongst streams with different socket tags).
TEST_P(HttpStreamFactoryTest, Tag) {
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
  ssl_socket_data.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
  ssl_socket_data.next_proto = kProtoHTTP2;
  session_deps.socket_factory->AddSSLSocketDataProvider(&ssl_socket_data);
  SSLSocketDataProvider ssl_socket_data2(ASYNC, OK);
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
  request_info1.url = GURL("https://example.org");
  request_info1.load_flags = 0;
  request_info1.socket_tag = tag1;
  request_info1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  SocketTag tag2(getuid(), 0x87654321);
  HttpRequestInfo request_info2 = request_info1;
  request_info2.socket_tag = tag2;
  request_info2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Verify on
"""


```