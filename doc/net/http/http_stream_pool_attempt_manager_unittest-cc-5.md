Response:
The user wants to understand the functionality of the C++ source code file `net/http/http_stream_pool_attempt_manager_unittest.cc` from the Chromium project. I need to explain what this code does, its relation to JavaScript (if any), any logical inferences it makes, common user errors it might prevent, and how a user's actions can lead to this code being executed. Finally, I need to summarize the functionality of this specific part (part 6 of 7).

Here's a breakdown of how to address each point:

1. **Functionality:** This file contains unit tests for the `HttpStreamPoolAttemptManager` class in Chromium's networking stack. The tests cover various scenarios related to managing attempts to establish HTTP connections, including:
    * Handling QUIC connections (including forcing QUIC, delaying attempts, and dealing with QUIC connection failures).
    * Interaction with alternative services (Alt-Svc).
    * Managing idle and active sockets in the connection pool.
    * Handling connection errors and retries.
    * Interaction with the DNS resolver and socket factory.
    * Testing preconnection logic.
    * Handling unsafe ports.
    * Disallowing HTTP/1.1.
    * Reporting bad proxies.
    * Interactions with `HttpServerProperties`.

2. **Relationship with JavaScript:**  While this is C++ code, it directly impacts how web requests are handled in the browser. JavaScript making an HTTP request will eventually trigger the underlying networking stack, where this code plays a role in managing the connection.

3. **Logical Inference:** The tests often involve setting up specific scenarios (e.g., a QUIC connection fails, an alternative service is available) and then asserting the expected behavior of the `HttpStreamPoolAttemptManager`. This involves logical deduction based on the expected workings of the connection management process.

4. **User/Programming Errors:** The tests indirectly help prevent user and programming errors by ensuring the connection management logic is robust. For instance, handling unsafe ports prevents connections to potentially malicious ports. Ensuring proper fallback mechanisms when connections fail prevents users from encountering broken web pages.

5. **User Actions and Debugging:** User actions like navigating to a website, clicking a link, or performing an action that triggers an HTTP request will lead to this code being executed. During debugging, developers can use these tests to isolate and understand issues related to connection management.

6. **Summary of Part 6:** This specific section of the tests focuses on a variety of scenarios, including:
    * Delaying stream attempts for QUIC.
    * Forcing QUIC connections.
    * Handling QUIC session failures.
    * Retrieving information about the connection pool.
    * Testing interactions with alternative services (both HTTP/2 and QUIC).
    * Managing connection attempts when alternative services fail or succeed.
    * Setting priorities for connection attempts.
    * Flushing the connection pool.
    * Handling unsafe ports.
    * Disallowing HTTP/1.1.
    * Reporting bad proxies.
    * Handling IP protection proxy configurations.
    * Destroying the `HttpNetworkSession` while connections are active.

Now, I will generate the detailed explanation incorporating these points.
```cpp
y = base::Milliseconds(10);
  quic_session_pool()->SetTimeDelayForWaitingJobForTesting(kDelay);

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();
  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  auto quic_data = std::make_unique<MockQuicData>(quic_version());
  quic_data->AddConnect(SYNCHRONOUS, ERR_CONNECTION_REFUSED);
  quic_data->AddSocketDataToFactory(socket_factory());

  SequencedSocketData tcp_data;
  socket_factory()->AddSocketDataProvider(&tcp_data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  StreamRequester requester;
  requester.set_destination(kDefaultDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester.result(), Optional(IsOk()));

  // QUIC should be marked as broken.
  const AlternativeService alternative_service(
      NextProto::kProtoQUIC,
      HostPortPair::FromSchemeHostPort(requester.GetStreamKey().destination()));
  EXPECT_TRUE(http_server_properties()->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, DelayStreamAttemptDelayPassed) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(net::features::kAsyncQuicSession);

  constexpr base::TimeDelta kDelay = base::Milliseconds(10);
  quic_session_pool()->SetTimeDelayForWaitingJobForTesting(kDelay);

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();
  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  auto quic_data = std::make_unique<MockQuicData>(quic_version());
  quic_data->AddConnect(SYNCHRONOUS, ERR_IO_PENDING);
  quic_data->AddSocketDataToFactory(socket_factory());

  SequencedSocketData tcp_data;
  socket_factory()->AddSocketDataProvider(&tcp_data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  StreamRequester requester;
  requester.set_destination(kDefaultDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());
  RunUntilIdle();
  ASSERT_FALSE(requester.result().has_value());

  FastForwardBy(kDelay);

  EXPECT_THAT(requester.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest,
       DelayStreamAttemptDisableAlternativeServicesLater) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(net::features::kAsyncQuicSession);

  constexpr base::TimeDelta kDelay = base::Milliseconds(10);
  quic_session_pool()->SetTimeDelayForWaitingJobForTesting(kDelay);

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  auto quic_data = std::make_unique<MockQuicData>(quic_version());
  quic_data->AddConnect(SYNCHRONOUS, ERR_IO_PENDING);
  quic_data->AddSocketDataToFactory(socket_factory());

  SequencedSocketData tcp_data;
  socket_factory()->AddSocketDataProvider(&tcp_data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  StreamRequester requester1;
  requester1.set_destination(kDefaultDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());
  StreamRequester requester2;
  requester2.set_destination(kDefaultDestination)
      .set_enable_alternative_services(false)
      .RequestStream(pool());

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  RunUntilIdle();
  EXPECT_THAT(requester1.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, OriginsToForceQuicOnOk) {
  origins_to_force_quic_on().insert(
      HostPortPair::FromURL(GURL(kDefaultDestination)));
  InitializeSession();

  AddQuicData();

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  StreamRequester requester;
  requester.set_destination(kDefaultDestination).RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, OriginsToForceQuicOnExistingSession) {
  origins_to_force_quic_on().insert(
      HostPortPair::FromURL(GURL(kDefaultDestination)));
  InitializeSession();

  AddQuicData();

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  // The first request. It should create a QUIC session.
  StreamRequester requester1;
  requester1.set_destination(kDefaultDestination).RequestStream(pool());
  requester1.WaitForResult();
  EXPECT_THAT(requester1.result(), Optional(IsOk()));
  EXPECT_EQ(requester1.negotiated_protocol(), NextProto::kProtoQUIC);

  // The second request. The request disables alternative services but the
  // QUIC session should be used because QUIC is forced by the
  // HttpNetworkSession. If the second request doesn't use the existing session
  // this test fails because we call AddQuicData() only once so we only added
  // mock reads and writes for only one QUIC connection.
  StreamRequester requester2;
  requester2.set_destination(kDefaultDestination)
      .set_enable_alternative_services(false)
      .RequestStream(pool());
  requester2.WaitForResult();
  EXPECT_THAT(requester2.result(), Optional(IsOk()));
  EXPECT_EQ(requester2.negotiated_protocol(), NextProto::kProtoQUIC);
}

TEST_F(HttpStreamPoolAttemptManagerTest, OriginsToForceQuicOnFail) {
  origins_to_force_quic_on().insert(
      HostPortPair::FromURL(GURL(kDefaultDestination)));
  InitializeSession();

  auto quic_data = std::make_unique<MockQuicData>(quic_version());
  quic_data->AddConnect(SYNCHRONOUS, ERR_CONNECTION_REFUSED);
  quic_data->AddSocketDataToFactory(socket_factory());

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  StreamRequester requester;
  requester.set_destination(kDefaultDestination).RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester.result(), Optional(IsError(ERR_CONNECTION_REFUSED)));
}

TEST_F(HttpStreamPoolAttemptManagerTest, OriginsToForceQuicOnPreconnectOk) {
  origins_to_force_quic_on().insert(
      HostPortPair::FromURL(GURL(kDefaultDestination)));
  InitializeSession();

  AddQuicData();

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  Preconnector preconnector(kDefaultDestination);
  preconnector.Preconnect(pool());
  RunUntilIdle();
  EXPECT_THAT(preconnector.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, OriginsToForceQuicOnPreconnectFail) {
  origins_to_force_quic_on().insert(
      HostPortPair::FromURL(GURL(kDefaultDestination)));
  InitializeSession();

  auto quic_data = std::make_unique<MockQuicData>(quic_version());
  quic_data->AddConnect(SYNCHRONOUS, ERR_CONNECTION_REFUSED);
  quic_data->AddSocketDataToFactory(socket_factory());

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  Preconnector preconnector(kDefaultDestination);
  preconnector.Preconnect(pool());
  RunUntilIdle();
  EXPECT_THAT(preconnector.result(), Optional(IsError(ERR_CONNECTION_REFUSED)));
}

TEST_F(HttpStreamPoolAttemptManagerTest, QuicSessionGoneBeforeUsing) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndDisableFeature(net::features::kAsyncQuicSession);
  origins_to_force_quic_on().insert(
      HostPortPair::FromURL(GURL(kDefaultDestination)));
  InitializeSession();

  QuicTestPacketMaker* client_maker = CreateQuicClientPacketMaker();
  MockQuicData quic_data(quic_version());
  quic_data.AddWrite(SYNCHRONOUS, client_maker->MakeInitialSettingsPacket(
                                      /*packet_number=*/1));
  quic_data.AddRead(ASYNC, ERR_SOCKET_NOT_CONNECTED);
  quic_data.AddSocketDataToFactory(socket_factory());

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  // QUIC attempt succeeds since we didn't require confirmation.
  StreamRequester requester;
  requester.set_destination(kDefaultDestination).RequestStream(pool());
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsOk()));

  // Try to initialize `stream`. The underlying socket was already closed so
  // the initialization fails.
  std::unique_ptr<HttpStream> stream = requester.ReleaseStream();
  HttpRequestInfo request_info;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream->RegisterRequest(&request_info);
  int rv =
      stream->InitializeStream(/*can_send_early=*/false, RequestPriority::IDLE,
                               NetLogWithSource(), base::DoNothing());
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_CLOSED));
}

TEST_F(HttpStreamPoolAttemptManagerTest, GetInfoAsValue) {
  // Add an idle stream to a.test and create an in-flight connection attempt for
  // b.test.
  StreamRequester requester_a;
  requester_a.set_destination("https://a.test");
  Group& group = pool().GetOrCreateGroupForTesting(requester_a.GetStreamKey());
  group.AddIdleStreamSocket(std::make_unique<FakeStreamSocket>());

  StreamRequester requester_b;
  requester_b.set_destination("https://b.test");

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  auto data_b = std::make_unique<SequencedSocketData>();
  data_b->set_connect_data(MockConnect(ASYNC, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(data_b.get());

  requester_b.RequestStream(pool());

  base::Value::Dict info = pool().GetInfoAsValue();
  EXPECT_THAT(info.FindInt("idle_socket_count"), Optional(1));
  EXPECT_THAT(info.FindInt("connecting_socket_count"), Optional(1));
  EXPECT_THAT(info.FindInt("max_socket_count"),
              Optional(pool().max_stream_sockets_per_pool()));
  EXPECT_THAT(info.FindInt("max_sockets_per_group"),
              Optional(pool().max_stream_sockets_per_group()));

  base::Value::Dict* groups_info = info.FindDict("groups");
  ASSERT_TRUE(groups_info);

  base::Value::Dict* info_a =
      groups_info->FindDict(requester_a.GetStreamKey().ToString());
  ASSERT_TRUE(info_a);
  EXPECT_THAT(info_a->FindInt("active_socket_count"), Optional(1));
  EXPECT_THAT(info_a->FindInt("idle_socket_count"), Optional(1));

  base::Value::Dict* info_b =
      groups_info->FindDict(requester_b.GetStreamKey().ToString());
  ASSERT_TRUE(info_b);
  EXPECT_THAT(info_b->FindInt("active_socket_count"), Optional(1));
  EXPECT_THAT(info_b->FindInt("idle_socket_count"), Optional(0));
}

TEST_F(HttpStreamPoolAttemptManagerTest, AltSvcH2OkOriginFail) {
  const url::SchemeHostPort kOrigin(url::kHttpsScheme, "origin.example.org",
                                    443);
  const HostPortPair kAlternative("alt.example.org", 443);

  const AlternativeService alternative_service(NextProto::kProtoHTTP2,
                                               kAlternative);
  const base::Time expiration = base::Time::Now() + base::Days(1);

  StreamRequester requester;
  requester.set_destination(kOrigin).set_alternative_service_info(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service, expiration));

  // For the alternative service. Negotiate HTTP/2 with the alternative service.
  const MockRead alt_reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  const MockWrite alt_writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  SequencedSocketData alt_data(alt_reads, alt_writes);
  socket_factory()->AddSocketDataProvider(&alt_data);
  SSLSocketDataProvider alt_ssl(ASYNC, OK);
  alt_ssl.next_proto = NextProto::kProtoHTTP2;
  socket_factory()->AddSSLSocketDataProvider(&alt_ssl);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  // For the origin. The connection is refused.
  StaticSocketDataProvider origin_data;
  origin_data.set_connect_data(MockConnect(ASYNC, ERR_CONNECTION_REFUSED));
  socket_factory()->AddSocketDataProvider(&origin_data);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.2").endpoint())
      .CompleteStartSynchronously(OK);

  requester.RequestStream(pool());
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
  requester.ResetRequest();
  EXPECT_FALSE(http_server_properties()->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, AltSvcFailOriginOk) {
  const url::SchemeHostPort kOrigin(url::kHttpsScheme, "origin.example.org",
                                    443);
  const HostPortPair kAlternative("alt.example.org", 443);

  const AlternativeService alternative_service(NextProto::kProtoHTTP2,
                                               kAlternative);
  const base::Time expiration = base::Time::Now() + base::Days(1);

  StreamRequester requester;
  requester.set_destination(kOrigin).set_alternative_service_info(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service, expiration));

  // For the alternative service. The connection is reset.
  StaticSocketDataProvider alt_data;
  alt_data.set_connect_data(MockConnect(ASYNC, ERR_CONNECTION_RESET));
  socket_factory()->AddSocketDataProvider(&alt_data);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  // For the origin. Negotiated HTTP/1.1 with the origin.
  StaticSocketDataProvider origin_data;
  socket_factory()->AddSocketDataProvider(&origin_data);
  SSLSocketDataProvider origin_ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&origin_ssl);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.2").endpoint())
      .CompleteStartSynchronously(OK);

  requester.RequestStream(pool());
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
  requester.ResetRequest();
  EXPECT_TRUE(http_server_properties()->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, AltSvcNegotiatedWithH1) {
  const url::SchemeHostPort kOrigin(url::kHttpsScheme, "origin.example.org",
                                    443);
  const HostPortPair kAlternative("alt.example.org", 443);

  const AlternativeService alternative_service(NextProto::kProtoHTTP2,
                                               kAlternative);
  const base::Time expiration = base::Time::Now() + base::Days(1);

  StreamRequester requester;
  requester.set_destination(kOrigin).set_alternative_service_info(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service, expiration));

  // For the alternative service. Negotiated with HTTP/1.1.
  StaticSocketDataProvider alt_data;
  socket_factory()->AddSocketDataProvider(&alt_data);
  SSLSocketDataProvider alt_ssl(ASYNC, OK);
  alt_ssl.next_proto = NextProto::kProtoHTTP11;
  socket_factory()->AddSSLSocketDataProvider(&alt_ssl);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  // For the origin. The connection is refused.
  StaticSocketDataProvider origin_data;
  origin_data.set_connect_data(MockConnect(ASYNC, ERR_CONNECTION_REFUSED));
  socket_factory()->AddSocketDataProvider(&origin_data);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.2").endpoint())
      .CompleteStartSynchronously(OK);

  requester.RequestStream(pool());
  requester.WaitForResult();
  EXPECT_THAT(requester.result(),
              Optional(IsError(ERR_ALPN_NEGOTIATION_FAILED)));
  requester.ResetRequest();
  // Both the origin and alternavie service failed, so the alternative service
  // should not be marked broken.
  EXPECT_FALSE(http_server_properties()->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, AltSvcCertificateError) {
  const url::SchemeHostPort kOrigin(url::kHttpsScheme, "origin.example.org",
                                    443);
  const HostPortPair kAlternative("alt.example.org", 443);

  const AlternativeService alternative_service(NextProto::kProtoHTTP2,
                                               kAlternative);
  const base::Time expiration = base::Time::Now() + base::Days(1);

  StreamRequester requester;
  requester.set_destination(kOrigin).set_alternative_service_info(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service, expiration));

  // For the alternative service. Certificate is invalid.
  StaticSocketDataProvider alt_data;
  socket_factory()->AddSocketDataProvider(&alt_data);
  SSLSocketDataProvider alt_ssl(ASYNC, ERR_CERT_DATE_INVALID);
  alt_ssl.next_proto = NextProto::kProtoHTTP11;
  socket_factory()->AddSSLSocketDataProvider(&alt_ssl);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  // For the origin. The connection is stalled forever.
  StaticSocketDataProvider origin_data;
  origin_data.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(&origin_data);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.2").endpoint())
      .CompleteStartSynchronously(OK);

  requester.RequestStream(pool());
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsError(ERR_CERT_DATE_INVALID)));
  requester.ResetRequest();
  // The alternavie service failed and origin didn't complete, so the
  // alternative service should not be marked broken.
  EXPECT_FALSE(http_server_properties()->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, AltSvcSetPriority) {
  const url::SchemeHostPort kOrigin(url::kHttpsScheme, "origin.example.org",
                                    443);
  const HostPortPair kAlternative("alt.example.org", 443);

  const AlternativeService alternative_service(NextProto::kProtoHTTP2,
                                               kAlternative);
  const base::Time expiration = base::Time::Now() + base::Days(1);

  StreamRequester requester;
  requester.set_destination(kOrigin).set_alternative_service_info(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service, expiration));

  // For the alternative service. The connection is stalled forever.
  StaticSocketDataProvider alt_data;
  alt_data.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(&alt_data);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  // For the origin. The connection is stalled forever.
  StaticSocketDataProvider origin_data;
  origin_data.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(&origin_data);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.2").endpoint())
      .CompleteStartSynchronously(OK);

  HttpStreamRequest* request =
      requester.set_priority(RequestPriority::LOW).RequestStream(pool());

  AttemptManager* origin_manager =
      pool()
          .GetOrCreateGroupForTesting(requester.GetStreamKey())
          .GetAttemptManagerForTesting();
  ASSERT_TRUE(origin_manager);
  EXPECT_EQ(origin_manager->GetPriority(), RequestPriority::LOW);

  HttpStreamKey alt_stream_key =
      StreamKeyBuilder()
          .set_destination(url::SchemeHostPort(
              url::kHttpsScheme, kAlternative.host(), kAlternative.port()))
          .Build();
  AttemptManager* alt_manager = pool()
                                    .GetOrCreateGroupForTesting(alt_stream_key)
                                    .GetAttemptManagerForTesting();
  ASSERT_TRUE(alt_manager);
  EXPECT_EQ(alt_manager->GetPriority(), RequestPriority::LOW);

  request->SetPriority(RequestPriority::HIGHEST);
  EXPECT_EQ(origin_manager->GetPriority(), RequestPriority::HIGHEST);
  EXPECT_EQ(alt_manager->GetPriority(), RequestPriority::HIGHEST);
}

TEST_F(HttpStreamPoolAttemptManagerTest, AltSvcQuicOk) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(net::features::kAsyncQuicSession);

  const url::SchemeHostPort kOrigin(url::kHttpsScheme, "origin.example.org",
                                    443);
  const HostPortPair kAlternative("alt.example.org", 443);

  const AlternativeService alternative_service(NextProto::kProtoQUIC,
                                               kAlternative);
  const base::Time expiration = base::Time::Now() + base::Days(1);

  StreamRequester requester;
  requester.set_destination(kOrigin).set_alternative_service_info(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          alternative_service, expiration, DefaultSupportedQuicVersions()));

  AddQuicData();

  // For QUIC alt-svc.
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  // For origin. Endpoint resolution never completes.
  resolver()->AddFakeRequest();

  requester.RequestStream(pool());
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
  EXPECT_EQ(requester.negotiated_protocol(), NextProto::kProtoQUIC);
}

TEST_F(HttpStreamPoolAttemptManagerTest, AltSvcQuicFailOriginOk) {
  const url::SchemeHostPort kOrigin(url::kHttpsScheme, "origin.example.org",
                                    443);
  const HostPortPair kAlternative("alt.example.org", 443);

  const AlternativeService alternative_service(NextProto::kProtoQUIC,
                                               kAlternative);
  const base::Time expiration = base::Time::Now() + base::Days(1);

  StreamRequester requester;
  requester.set_destination(kOrigin).set_alternative_service_info(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          alternative_service, expiration, DefaultSupportedQuicVersions()));

  MockQuicData quic_data(quic_version());
  quic_data.AddConnect(SYNCHRONOUS, ERR_CONNECTION_REFUSED);
  quic_data.AddSocketDataToFactory(socket_factory());

  SequencedSocketData tcp_data;
  socket_factory()->AddSocketDataProvider(&tcp_data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  // For QUIC alt-svc.
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  // For origin.
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.2").endpoint())
      .CompleteStartSynchronously(OK);

  requester.RequestStream(pool());
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
  EXPECT_NE(requester.negotiated_protocol(), NextProto::kProtoQUIC);
}

TEST_F(HttpStreamPoolAttemptManagerTest, AltSvcQuicFailOriginFail) {
  const url::SchemeHostPort kOrigin(url::kHttpsScheme, "origin.example.org",
                                    443);
  const HostPortPair kAlternative("alt.example.org", 443);

  const AlternativeService alternative_service(NextProto::kProtoQUIC,
                                               kAlternative);
  const base::Time expiration = base::Time::Now() + base::Days(1);

  StreamRequester requester;
  requester.set_destination(kOrigin).set_alternative_service_info(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          alternative_service, expiration, DefaultSupportedQuicVersions()));

  MockQuicData quic_data(quic_version());
  quic_data.AddConnect(SYNCHRONOUS, ERR_CONNECTION_REFUSED);
  quic_data.AddSocketDataToFactory(socket_factory());

  SequencedSocketData tcp_data;
  tcp_data.set_connect_data(MockConnect(ASYNC, ERR_CONNECTION_FAILED));
  socket_factory()->AddSocketDataProvider(&tcp_data);

  // For QUIC alt-svc.
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  // For origin.
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.2").endpoint())
      .CompleteStartSynchronously(OK);

  requester.RequestStream(pool());
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsError(ERR_CONNECTION_FAILED)));
}

TEST_F(HttpStreamPoolAttemptManagerTest, AltSvcQuicUseExistingSession) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(net::features::kAsyncQuicSession);

  const url::SchemeHostPort kOrigin(url::kHttpsScheme, "origin.example.org",
                                    443);
  const HostPortPair kAlternative("alt.example.org", 443);

  const AlternativeService alternative_service(NextProto::kProtoQUIC,
                                               kAlternative);
  const base::Time expiration = base::Time::Now() + base::Days(1);

  // The first request creates a QUIC session.
  auto requester1 = std::make_unique<StreamRequester>();
  requester1->set_destination(kOrigin).set_alternative_service_info(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          alternative_service, expiration, DefaultSupportedQuicVersions()));

  AddQuicData();

  // For QUIC alt-svc.
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_
### 提示词
```
这是目录为net/http/http_stream_pool_attempt_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
y = base::Milliseconds(10);
  quic_session_pool()->SetTimeDelayForWaitingJobForTesting(kDelay);

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();
  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  auto quic_data = std::make_unique<MockQuicData>(quic_version());
  quic_data->AddConnect(SYNCHRONOUS, ERR_CONNECTION_REFUSED);
  quic_data->AddSocketDataToFactory(socket_factory());

  SequencedSocketData tcp_data;
  socket_factory()->AddSocketDataProvider(&tcp_data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  StreamRequester requester;
  requester.set_destination(kDefaultDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester.result(), Optional(IsOk()));

  // QUIC should be marked as broken.
  const AlternativeService alternative_service(
      NextProto::kProtoQUIC,
      HostPortPair::FromSchemeHostPort(requester.GetStreamKey().destination()));
  EXPECT_TRUE(http_server_properties()->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, DelayStreamAttemptDelayPassed) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(net::features::kAsyncQuicSession);

  constexpr base::TimeDelta kDelay = base::Milliseconds(10);
  quic_session_pool()->SetTimeDelayForWaitingJobForTesting(kDelay);

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();
  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  auto quic_data = std::make_unique<MockQuicData>(quic_version());
  quic_data->AddConnect(SYNCHRONOUS, ERR_IO_PENDING);
  quic_data->AddSocketDataToFactory(socket_factory());

  SequencedSocketData tcp_data;
  socket_factory()->AddSocketDataProvider(&tcp_data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  StreamRequester requester;
  requester.set_destination(kDefaultDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());
  RunUntilIdle();
  ASSERT_FALSE(requester.result().has_value());

  FastForwardBy(kDelay);

  EXPECT_THAT(requester.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest,
       DelayStreamAttemptDisableAlternativeServicesLater) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(net::features::kAsyncQuicSession);

  constexpr base::TimeDelta kDelay = base::Milliseconds(10);
  quic_session_pool()->SetTimeDelayForWaitingJobForTesting(kDelay);

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  auto quic_data = std::make_unique<MockQuicData>(quic_version());
  quic_data->AddConnect(SYNCHRONOUS, ERR_IO_PENDING);
  quic_data->AddSocketDataToFactory(socket_factory());

  SequencedSocketData tcp_data;
  socket_factory()->AddSocketDataProvider(&tcp_data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  StreamRequester requester1;
  requester1.set_destination(kDefaultDestination)
      .set_quic_version(quic_version())
      .RequestStream(pool());
  StreamRequester requester2;
  requester2.set_destination(kDefaultDestination)
      .set_enable_alternative_services(false)
      .RequestStream(pool());

  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointRequestFinished(OK);
  RunUntilIdle();
  EXPECT_THAT(requester1.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, OriginsToForceQuicOnOk) {
  origins_to_force_quic_on().insert(
      HostPortPair::FromURL(GURL(kDefaultDestination)));
  InitializeSession();

  AddQuicData();

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  StreamRequester requester;
  requester.set_destination(kDefaultDestination).RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, OriginsToForceQuicOnExistingSession) {
  origins_to_force_quic_on().insert(
      HostPortPair::FromURL(GURL(kDefaultDestination)));
  InitializeSession();

  AddQuicData();

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  // The first request. It should create a QUIC session.
  StreamRequester requester1;
  requester1.set_destination(kDefaultDestination).RequestStream(pool());
  requester1.WaitForResult();
  EXPECT_THAT(requester1.result(), Optional(IsOk()));
  EXPECT_EQ(requester1.negotiated_protocol(), NextProto::kProtoQUIC);

  // The second request. The request disables alternative services but the
  // QUIC session should be used because QUIC is forced by the
  // HttpNetworkSession. If the second request doesn't use the existing session
  // this test fails because we call AddQuicData() only once so we only added
  // mock reads and writes for only one QUIC connection.
  StreamRequester requester2;
  requester2.set_destination(kDefaultDestination)
      .set_enable_alternative_services(false)
      .RequestStream(pool());
  requester2.WaitForResult();
  EXPECT_THAT(requester2.result(), Optional(IsOk()));
  EXPECT_EQ(requester2.negotiated_protocol(), NextProto::kProtoQUIC);
}

TEST_F(HttpStreamPoolAttemptManagerTest, OriginsToForceQuicOnFail) {
  origins_to_force_quic_on().insert(
      HostPortPair::FromURL(GURL(kDefaultDestination)));
  InitializeSession();

  auto quic_data = std::make_unique<MockQuicData>(quic_version());
  quic_data->AddConnect(SYNCHRONOUS, ERR_CONNECTION_REFUSED);
  quic_data->AddSocketDataToFactory(socket_factory());

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  StreamRequester requester;
  requester.set_destination(kDefaultDestination).RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester.result(), Optional(IsError(ERR_CONNECTION_REFUSED)));
}

TEST_F(HttpStreamPoolAttemptManagerTest, OriginsToForceQuicOnPreconnectOk) {
  origins_to_force_quic_on().insert(
      HostPortPair::FromURL(GURL(kDefaultDestination)));
  InitializeSession();

  AddQuicData();

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  Preconnector preconnector(kDefaultDestination);
  preconnector.Preconnect(pool());
  RunUntilIdle();
  EXPECT_THAT(preconnector.result(), Optional(IsOk()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, OriginsToForceQuicOnPreconnectFail) {
  origins_to_force_quic_on().insert(
      HostPortPair::FromURL(GURL(kDefaultDestination)));
  InitializeSession();

  auto quic_data = std::make_unique<MockQuicData>(quic_version());
  quic_data->AddConnect(SYNCHRONOUS, ERR_CONNECTION_REFUSED);
  quic_data->AddSocketDataToFactory(socket_factory());

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  Preconnector preconnector(kDefaultDestination);
  preconnector.Preconnect(pool());
  RunUntilIdle();
  EXPECT_THAT(preconnector.result(), Optional(IsError(ERR_CONNECTION_REFUSED)));
}

TEST_F(HttpStreamPoolAttemptManagerTest, QuicSessionGoneBeforeUsing) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndDisableFeature(net::features::kAsyncQuicSession);
  origins_to_force_quic_on().insert(
      HostPortPair::FromURL(GURL(kDefaultDestination)));
  InitializeSession();

  QuicTestPacketMaker* client_maker = CreateQuicClientPacketMaker();
  MockQuicData quic_data(quic_version());
  quic_data.AddWrite(SYNCHRONOUS, client_maker->MakeInitialSettingsPacket(
                                      /*packet_number=*/1));
  quic_data.AddRead(ASYNC, ERR_SOCKET_NOT_CONNECTED);
  quic_data.AddSocketDataToFactory(socket_factory());

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  // QUIC attempt succeeds since we didn't require confirmation.
  StreamRequester requester;
  requester.set_destination(kDefaultDestination).RequestStream(pool());
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsOk()));

  // Try to initialize `stream`. The underlying socket was already closed so
  // the initialization fails.
  std::unique_ptr<HttpStream> stream = requester.ReleaseStream();
  HttpRequestInfo request_info;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream->RegisterRequest(&request_info);
  int rv =
      stream->InitializeStream(/*can_send_early=*/false, RequestPriority::IDLE,
                               NetLogWithSource(), base::DoNothing());
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_CLOSED));
}

TEST_F(HttpStreamPoolAttemptManagerTest, GetInfoAsValue) {
  // Add an idle stream to a.test and create an in-flight connection attempt for
  // b.test.
  StreamRequester requester_a;
  requester_a.set_destination("https://a.test");
  Group& group = pool().GetOrCreateGroupForTesting(requester_a.GetStreamKey());
  group.AddIdleStreamSocket(std::make_unique<FakeStreamSocket>());

  StreamRequester requester_b;
  requester_b.set_destination("https://b.test");

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  auto data_b = std::make_unique<SequencedSocketData>();
  data_b->set_connect_data(MockConnect(ASYNC, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(data_b.get());

  requester_b.RequestStream(pool());

  base::Value::Dict info = pool().GetInfoAsValue();
  EXPECT_THAT(info.FindInt("idle_socket_count"), Optional(1));
  EXPECT_THAT(info.FindInt("connecting_socket_count"), Optional(1));
  EXPECT_THAT(info.FindInt("max_socket_count"),
              Optional(pool().max_stream_sockets_per_pool()));
  EXPECT_THAT(info.FindInt("max_sockets_per_group"),
              Optional(pool().max_stream_sockets_per_group()));

  base::Value::Dict* groups_info = info.FindDict("groups");
  ASSERT_TRUE(groups_info);

  base::Value::Dict* info_a =
      groups_info->FindDict(requester_a.GetStreamKey().ToString());
  ASSERT_TRUE(info_a);
  EXPECT_THAT(info_a->FindInt("active_socket_count"), Optional(1));
  EXPECT_THAT(info_a->FindInt("idle_socket_count"), Optional(1));

  base::Value::Dict* info_b =
      groups_info->FindDict(requester_b.GetStreamKey().ToString());
  ASSERT_TRUE(info_b);
  EXPECT_THAT(info_b->FindInt("active_socket_count"), Optional(1));
  EXPECT_THAT(info_b->FindInt("idle_socket_count"), Optional(0));
}

TEST_F(HttpStreamPoolAttemptManagerTest, AltSvcH2OkOriginFail) {
  const url::SchemeHostPort kOrigin(url::kHttpsScheme, "origin.example.org",
                                    443);
  const HostPortPair kAlternative("alt.example.org", 443);

  const AlternativeService alternative_service(NextProto::kProtoHTTP2,
                                               kAlternative);
  const base::Time expiration = base::Time::Now() + base::Days(1);

  StreamRequester requester;
  requester.set_destination(kOrigin).set_alternative_service_info(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service, expiration));

  // For the alternative service. Negotiate HTTP/2 with the alternative service.
  const MockRead alt_reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0)};
  const MockWrite alt_writes[] = {MockWrite(SYNCHRONOUS, ERR_IO_PENDING, 1)};
  SequencedSocketData alt_data(alt_reads, alt_writes);
  socket_factory()->AddSocketDataProvider(&alt_data);
  SSLSocketDataProvider alt_ssl(ASYNC, OK);
  alt_ssl.next_proto = NextProto::kProtoHTTP2;
  socket_factory()->AddSSLSocketDataProvider(&alt_ssl);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  // For the origin. The connection is refused.
  StaticSocketDataProvider origin_data;
  origin_data.set_connect_data(MockConnect(ASYNC, ERR_CONNECTION_REFUSED));
  socket_factory()->AddSocketDataProvider(&origin_data);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.2").endpoint())
      .CompleteStartSynchronously(OK);

  requester.RequestStream(pool());
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
  requester.ResetRequest();
  EXPECT_FALSE(http_server_properties()->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, AltSvcFailOriginOk) {
  const url::SchemeHostPort kOrigin(url::kHttpsScheme, "origin.example.org",
                                    443);
  const HostPortPair kAlternative("alt.example.org", 443);

  const AlternativeService alternative_service(NextProto::kProtoHTTP2,
                                               kAlternative);
  const base::Time expiration = base::Time::Now() + base::Days(1);

  StreamRequester requester;
  requester.set_destination(kOrigin).set_alternative_service_info(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service, expiration));

  // For the alternative service. The connection is reset.
  StaticSocketDataProvider alt_data;
  alt_data.set_connect_data(MockConnect(ASYNC, ERR_CONNECTION_RESET));
  socket_factory()->AddSocketDataProvider(&alt_data);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  // For the origin. Negotiated HTTP/1.1 with the origin.
  StaticSocketDataProvider origin_data;
  socket_factory()->AddSocketDataProvider(&origin_data);
  SSLSocketDataProvider origin_ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&origin_ssl);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.2").endpoint())
      .CompleteStartSynchronously(OK);

  requester.RequestStream(pool());
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
  requester.ResetRequest();
  EXPECT_TRUE(http_server_properties()->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, AltSvcNegotiatedWithH1) {
  const url::SchemeHostPort kOrigin(url::kHttpsScheme, "origin.example.org",
                                    443);
  const HostPortPair kAlternative("alt.example.org", 443);

  const AlternativeService alternative_service(NextProto::kProtoHTTP2,
                                               kAlternative);
  const base::Time expiration = base::Time::Now() + base::Days(1);

  StreamRequester requester;
  requester.set_destination(kOrigin).set_alternative_service_info(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service, expiration));

  // For the alternative service. Negotiated with HTTP/1.1.
  StaticSocketDataProvider alt_data;
  socket_factory()->AddSocketDataProvider(&alt_data);
  SSLSocketDataProvider alt_ssl(ASYNC, OK);
  alt_ssl.next_proto = NextProto::kProtoHTTP11;
  socket_factory()->AddSSLSocketDataProvider(&alt_ssl);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  // For the origin. The connection is refused.
  StaticSocketDataProvider origin_data;
  origin_data.set_connect_data(MockConnect(ASYNC, ERR_CONNECTION_REFUSED));
  socket_factory()->AddSocketDataProvider(&origin_data);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.2").endpoint())
      .CompleteStartSynchronously(OK);

  requester.RequestStream(pool());
  requester.WaitForResult();
  EXPECT_THAT(requester.result(),
              Optional(IsError(ERR_ALPN_NEGOTIATION_FAILED)));
  requester.ResetRequest();
  // Both the origin and alternavie service failed, so the alternative service
  // should not be marked broken.
  EXPECT_FALSE(http_server_properties()->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, AltSvcCertificateError) {
  const url::SchemeHostPort kOrigin(url::kHttpsScheme, "origin.example.org",
                                    443);
  const HostPortPair kAlternative("alt.example.org", 443);

  const AlternativeService alternative_service(NextProto::kProtoHTTP2,
                                               kAlternative);
  const base::Time expiration = base::Time::Now() + base::Days(1);

  StreamRequester requester;
  requester.set_destination(kOrigin).set_alternative_service_info(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service, expiration));

  // For the alternative service. Certificate is invalid.
  StaticSocketDataProvider alt_data;
  socket_factory()->AddSocketDataProvider(&alt_data);
  SSLSocketDataProvider alt_ssl(ASYNC, ERR_CERT_DATE_INVALID);
  alt_ssl.next_proto = NextProto::kProtoHTTP11;
  socket_factory()->AddSSLSocketDataProvider(&alt_ssl);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  // For the origin. The connection is stalled forever.
  StaticSocketDataProvider origin_data;
  origin_data.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(&origin_data);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.2").endpoint())
      .CompleteStartSynchronously(OK);

  requester.RequestStream(pool());
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsError(ERR_CERT_DATE_INVALID)));
  requester.ResetRequest();
  // The alternavie service failed and origin didn't complete, so the
  // alternative service should not be marked broken.
  EXPECT_FALSE(http_server_properties()->IsAlternativeServiceBroken(
      alternative_service, NetworkAnonymizationKey()));
}

TEST_F(HttpStreamPoolAttemptManagerTest, AltSvcSetPriority) {
  const url::SchemeHostPort kOrigin(url::kHttpsScheme, "origin.example.org",
                                    443);
  const HostPortPair kAlternative("alt.example.org", 443);

  const AlternativeService alternative_service(NextProto::kProtoHTTP2,
                                               kAlternative);
  const base::Time expiration = base::Time::Now() + base::Days(1);

  StreamRequester requester;
  requester.set_destination(kOrigin).set_alternative_service_info(
      AlternativeServiceInfo::CreateHttp2AlternativeServiceInfo(
          alternative_service, expiration));

  // For the alternative service. The connection is stalled forever.
  StaticSocketDataProvider alt_data;
  alt_data.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(&alt_data);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  // For the origin. The connection is stalled forever.
  StaticSocketDataProvider origin_data;
  origin_data.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(&origin_data);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.2").endpoint())
      .CompleteStartSynchronously(OK);

  HttpStreamRequest* request =
      requester.set_priority(RequestPriority::LOW).RequestStream(pool());

  AttemptManager* origin_manager =
      pool()
          .GetOrCreateGroupForTesting(requester.GetStreamKey())
          .GetAttemptManagerForTesting();
  ASSERT_TRUE(origin_manager);
  EXPECT_EQ(origin_manager->GetPriority(), RequestPriority::LOW);

  HttpStreamKey alt_stream_key =
      StreamKeyBuilder()
          .set_destination(url::SchemeHostPort(
              url::kHttpsScheme, kAlternative.host(), kAlternative.port()))
          .Build();
  AttemptManager* alt_manager = pool()
                                    .GetOrCreateGroupForTesting(alt_stream_key)
                                    .GetAttemptManagerForTesting();
  ASSERT_TRUE(alt_manager);
  EXPECT_EQ(alt_manager->GetPriority(), RequestPriority::LOW);

  request->SetPriority(RequestPriority::HIGHEST);
  EXPECT_EQ(origin_manager->GetPriority(), RequestPriority::HIGHEST);
  EXPECT_EQ(alt_manager->GetPriority(), RequestPriority::HIGHEST);
}

TEST_F(HttpStreamPoolAttemptManagerTest, AltSvcQuicOk) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(net::features::kAsyncQuicSession);

  const url::SchemeHostPort kOrigin(url::kHttpsScheme, "origin.example.org",
                                    443);
  const HostPortPair kAlternative("alt.example.org", 443);

  const AlternativeService alternative_service(NextProto::kProtoQUIC,
                                               kAlternative);
  const base::Time expiration = base::Time::Now() + base::Days(1);

  StreamRequester requester;
  requester.set_destination(kOrigin).set_alternative_service_info(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          alternative_service, expiration, DefaultSupportedQuicVersions()));

  AddQuicData();

  // For QUIC alt-svc.
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  // For origin. Endpoint resolution never completes.
  resolver()->AddFakeRequest();

  requester.RequestStream(pool());
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
  EXPECT_EQ(requester.negotiated_protocol(), NextProto::kProtoQUIC);
}

TEST_F(HttpStreamPoolAttemptManagerTest, AltSvcQuicFailOriginOk) {
  const url::SchemeHostPort kOrigin(url::kHttpsScheme, "origin.example.org",
                                    443);
  const HostPortPair kAlternative("alt.example.org", 443);

  const AlternativeService alternative_service(NextProto::kProtoQUIC,
                                               kAlternative);
  const base::Time expiration = base::Time::Now() + base::Days(1);

  StreamRequester requester;
  requester.set_destination(kOrigin).set_alternative_service_info(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          alternative_service, expiration, DefaultSupportedQuicVersions()));

  MockQuicData quic_data(quic_version());
  quic_data.AddConnect(SYNCHRONOUS, ERR_CONNECTION_REFUSED);
  quic_data.AddSocketDataToFactory(socket_factory());

  SequencedSocketData tcp_data;
  socket_factory()->AddSocketDataProvider(&tcp_data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory()->AddSSLSocketDataProvider(&ssl);

  // For QUIC alt-svc.
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  // For origin.
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.2").endpoint())
      .CompleteStartSynchronously(OK);

  requester.RequestStream(pool());
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
  EXPECT_NE(requester.negotiated_protocol(), NextProto::kProtoQUIC);
}

TEST_F(HttpStreamPoolAttemptManagerTest, AltSvcQuicFailOriginFail) {
  const url::SchemeHostPort kOrigin(url::kHttpsScheme, "origin.example.org",
                                    443);
  const HostPortPair kAlternative("alt.example.org", 443);

  const AlternativeService alternative_service(NextProto::kProtoQUIC,
                                               kAlternative);
  const base::Time expiration = base::Time::Now() + base::Days(1);

  StreamRequester requester;
  requester.set_destination(kOrigin).set_alternative_service_info(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          alternative_service, expiration, DefaultSupportedQuicVersions()));

  MockQuicData quic_data(quic_version());
  quic_data.AddConnect(SYNCHRONOUS, ERR_CONNECTION_REFUSED);
  quic_data.AddSocketDataToFactory(socket_factory());

  SequencedSocketData tcp_data;
  tcp_data.set_connect_data(MockConnect(ASYNC, ERR_CONNECTION_FAILED));
  socket_factory()->AddSocketDataProvider(&tcp_data);

  // For QUIC alt-svc.
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  // For origin.
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.2").endpoint())
      .CompleteStartSynchronously(OK);

  requester.RequestStream(pool());
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsError(ERR_CONNECTION_FAILED)));
}

TEST_F(HttpStreamPoolAttemptManagerTest, AltSvcQuicUseExistingSession) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(net::features::kAsyncQuicSession);

  const url::SchemeHostPort kOrigin(url::kHttpsScheme, "origin.example.org",
                                    443);
  const HostPortPair kAlternative("alt.example.org", 443);

  const AlternativeService alternative_service(NextProto::kProtoQUIC,
                                               kAlternative);
  const base::Time expiration = base::Time::Now() + base::Days(1);

  // The first request creates a QUIC session.
  auto requester1 = std::make_unique<StreamRequester>();
  requester1->set_destination(kOrigin).set_alternative_service_info(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          alternative_service, expiration, DefaultSupportedQuicVersions()));

  AddQuicData();

  // For QUIC alt-svc.
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  // For origin. Endpoint resolution never completes.
  resolver()->AddFakeRequest();

  requester1->RequestStream(pool());
  requester1->WaitForResult();
  EXPECT_THAT(requester1->result(), Optional(IsOk()));
  EXPECT_EQ(requester1->negotiated_protocol(), NextProto::kProtoQUIC);

  requester1.reset();

  // The second request uses the existing QUIC session.
  auto requester2 = std::make_unique<StreamRequester>();
  requester2->set_destination(kOrigin).set_alternative_service_info(
      AlternativeServiceInfo::CreateQuicAlternativeServiceInfo(
          alternative_service, expiration, DefaultSupportedQuicVersions()));

  requester2->RequestStream(pool());
  requester2->WaitForResult();
  EXPECT_THAT(requester2->result(), Optional(IsOk()));
  EXPECT_EQ(requester2->negotiated_protocol(), NextProto::kProtoQUIC);
}

TEST_F(HttpStreamPoolAttemptManagerTest, FlushWithError) {
  // Add an idle stream to a.test and create an in-flight connection attempt for
  // b.test.
  StreamRequester requester_a;
  requester_a.set_destination("https://a.test");
  Group& group = pool().GetOrCreateGroupForTesting(requester_a.GetStreamKey());
  group.AddIdleStreamSocket(std::make_unique<FakeStreamSocket>());

  StreamRequester requester_b;
  requester_b.set_destination("https://b.test");

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  auto data_b = std::make_unique<SequencedSocketData>();
  data_b->set_connect_data(MockConnect(ASYNC, ERR_IO_PENDING));
  socket_factory()->AddSocketDataProvider(data_b.get());

  requester_b.RequestStream(pool());

  // At this point, there are 2 active streams (one is idle and the other is
  // in-flight).
  EXPECT_EQ(pool().TotalActiveStreamCount(), 2u);

  // Flushing should destroy all active streams and in-flight attempts.
  pool().FlushWithError(ERR_ABORTED, "For testing");
  EXPECT_EQ(pool().TotalActiveStreamCount(), 0u);
}

TEST_F(HttpStreamPoolAttemptManagerTest, UnsafePort) {
  StreamRequester requester;
  requester.set_destination("http://www.example.org:7");

  const url::SchemeHostPort destination =
      requester.GetStreamKey().destination();
  ASSERT_FALSE(
      IsPortAllowedForScheme(destination.port(), destination.scheme()));

  requester.RequestStream(pool());
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsError(ERR_UNSAFE_PORT)));
}

TEST_F(HttpStreamPoolAttemptManagerTest, PreconnectUnsafePort) {
  Preconnector preconnector("http://www.example.org:7");

  const url::SchemeHostPort destination =
      preconnector.GetStreamKey().destination();
  ASSERT_FALSE(
      IsPortAllowedForScheme(destination.port(), destination.scheme()));

  preconnector.Preconnect(pool());
  preconnector.WaitForResult();
  EXPECT_THAT(preconnector.result(), Optional(IsError(ERR_UNSAFE_PORT)));
}

TEST_F(HttpStreamPoolAttemptManagerTest, DisallowH1) {
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);

  // Nagotiate to use HTTP/1.1.
  StaticSocketDataProvider data;
  socket_factory()->AddSocketDataProvider(&data);

  StreamRequester requester;
  requester.set_is_http1_allowed(false);

  requester.RequestStream(pool());
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsError(ERR_H2_OR_QUIC_REQUIRED)));
}

// Tests that a bad proxy is reported to a ProxyResolutionService when falling
// back to the direct connection succeeds.
TEST_F(HttpStreamPoolAttemptManagerTest, ReportBadProxyAfterSuccessOnDirect) {
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);
  StaticSocketDataProvider data;
  socket_factory()->AddSocketDataProvider(&data);

  // Simulate that we have a bad proxy.
  ProxyInfo proxy_info;
  proxy_info.UsePacString("PROXY badproxy:80; DIRECT");
  proxy_info.Fallback(ERR_PROXY_CONNECTION_FAILED, NetLogWithSource());

  StreamRequester requester;
  requester.set_proxy_info(proxy_info).RequestStream(pool());
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsOk()));

  // The ProxyResolutionService should know that the proxy is bad.
  auto proxy_chain = ProxyChain::FromSchemeHostAndPort(
      ProxyServer::Scheme::SCHEME_HTTP, "badproxy", 80);
  const ProxyRetryInfoMap retry_info_map =
      http_network_session()->proxy_resolution_service()->proxy_retry_info();
  auto it = retry_info_map.find(proxy_chain);
  ASSERT_TRUE(it != retry_info_map.end());
  EXPECT_THAT(it->second.net_error, IsError(ERR_PROXY_CONNECTION_FAILED));
}

TEST_F(HttpStreamPoolAttemptManagerTest, DirectProxyInfoForIpProtection) {
  const auto kIpProtectionDirectChain =
      ProxyChain::ForIpProtection(std::vector<ProxyServer>());
  ProxyInfo proxy_info;
  proxy_info.UseProxyChain(kIpProtectionDirectChain);

  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CompleteStartSynchronously(OK);
  StaticSocketDataProvider data;
  socket_factory()->AddSocketDataProvider(&data);

  StreamRequester requester;
  requester.set_proxy_info(proxy_info).RequestStream(pool());
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
  EXPECT_EQ(requester.used_proxy_info().ToDebugString(),
            proxy_info.ToDebugString());
}

// Regression test for crbug.com/369744951. Ensures that destroying
// an HttpNetworkSession, which owns an HttpStreamPool, doesn't cause a crash
// when a StreamSocket is returned to the pool in the middle of the destruction.
TEST_F(HttpStreamPoolAttemptManagerTest,
       DestroyHttpNetworkSessionWithSpdySession) {
  // Add a SpdySession. The session will be destroyed when the
  // HttpNetworkSession is being destroyed. The underlying StreamSocket will be
  // released to HttpStreamPool::Group.
  CreateFakeSpdySession(
      StreamKeyBuilder().set_destination("https://a.test").Build());

  // Create a request to a different destination. The request never finishes.
  StreamRequester requester;
  requester.set_destination("https://b.test");
  resolver()
      ->AddFakeRequest()
      ->add_endpoint(ServiceEndpointBu
```