Response:
The user wants me to analyze the C++ code snippet from a Chromium network stack unit test file.
Specifically, I need to:

1. **Summarize the functionality** of the provided code.
2. **Identify any relationship with Javascript functionality.**
3. **Provide examples of logical reasoning with hypothetical inputs and outputs.**
4. **Illustrate common user or programming errors related to this code.**
5. **Explain the user steps to reach this code for debugging.**
6. **Synthesize the function of this specific (part 4 of 13) code section.**

Let's break down the code and address each point:

**Code Analysis:**

The code consists of multiple test cases within a `QuicNetworkTransactionTest` class. These tests seem to focus on the interaction between HTTP and QUIC, especially in the context of Alternative Services (Alt-Svc). The tests verify scenarios like:

- Using Alt-Svc to upgrade an HTTP connection to QUIC.
- Respecting Network Anonymization Keys when using Alt-Svc.
- Handling multiple supported QUIC versions.
- Picking the correct QUIC version based on client and server preferences.
- Storing mutually supported QUIC versions when processing Alt-Svc headers.
- Handling QUIC connection timeouts and protocol errors.
- Retrying requests over TCP when a QUIC connection fails.

**Addressing the Requirements:**

1. **Functionality:** The code tests the logic for using Alternative Services to establish QUIC connections, including version negotiation and error handling.

2. **Javascript Relationship:** This code is part of the browser's network stack, which handles network requests initiated by Javascript. For example, a Javascript `fetch()` call to an `https://` URL could trigger the logic tested here if the server advertises a QUIC alternative.

3. **Logical Reasoning:**  Consider the `UseAlternativeServiceForQuic` test.
    - **Hypothetical Input:** An HTTP response header containing `Alt-Svc: h3-29=":443"`.
    - **Logical Processing:** The browser parses the Alt-Svc header and attempts to establish a QUIC connection to the same host on port 443 using the `h3-29` protocol.
    - **Hypothetical Output:** If the QUIC connection succeeds, subsequent requests to the same origin may use the QUIC connection.

4. **User/Programming Errors:** A common error is misconfiguring the Alt-Svc header on the server. For instance, providing an incorrect port number or protocol identifier will prevent successful QUIC connections. Another error is network configuration blocking UDP traffic, which is required for QUIC.

5. **Debugging Steps:** A user action like clicking a link or submitting a form on a website could lead to a network request. To debug how this request reaches this code:
    - **Start Chromium with debugging flags:** This allows attaching a debugger.
    - **Set breakpoints:** Place breakpoints in `QuicNetworkTransaction::Start` or related functions involved in Alt-Svc processing.
    - **Trigger the action:** Perform the user action in the browser.
    - **Step through the code:** Use the debugger to trace the execution flow and inspect variables.

6. **归纳功能 (Summary of Functionality - Part 4):** This section primarily focuses on testing the successful upgrade from HTTP to QUIC using the Alt-Svc mechanism. It verifies that the client correctly interprets the Alt-Svc header, establishes a QUIC connection, and uses it for subsequent requests. It also covers scenarios with Network Anonymization Keys and handling different QUIC versions. The latter part of this section starts to delve into error handling scenarios like timeouts and protocol errors after the QUIC handshake is complete.
这是`net/quic/quic_network_transaction_unittest.cc`文件的第4部分，主要功能集中在测试 **通过HTTP的Alt-Svc头部信息来升级连接到QUIC协议** 的场景。  它涵盖了多种情况，包括：

**核心功能:**

* **成功使用Alt-Svc升级到QUIC:** 测试当服务器返回包含`Alt-Svc`头的HTTP响应时，客户端能够识别并尝试建立QUIC连接，并且后续请求能够通过QUIC进行。
* **考虑NetworkAnonymizationKey:**  测试在使用Alt-Svc时，`NetworkAnonymizationKey`是否被正确考虑和应用，确保不同`NetworkAnonymizationKey`下的Alt-Svc信息隔离。
* **处理带有版本的Alt-Svc:**  测试当`Alt-Svc`头部指定了QUIC版本时，客户端能够正确解析并选择合适的版本进行连接。这包括客户端和服务端支持多个版本的情况，以及客户端根据服务端偏好选择版本。
* **设置带有Scheme的Alternative Service:** 测试`Alt-Svc`头部中指定Scheme的情况，确保只对相同Scheme的请求生效。
* **不为不同Origin获取Alt-Svc:** 测试确保从一个Origin收到的`Alt-Svc`信息不会被用于另一个不同的Origin。
* **存储互相支持的版本:** 测试在处理`Alt-Svc`头部时，客户端能够存储服务器声明的所有支持的QUIC版本。
* **使用所有支持版本的Alternative Service:** 测试当`Alt-Svc`头部只声明一个版本时，客户端能够正常使用。
* **处理QUIC连接超时:** 测试在QUIC握手完成后发生超时的情况，验证连接会返回`ERR_QUIC_PROTOCOL_ERROR`。
* **处理QUIC协议错误:** 测试在QUIC握手完成后发生协议错误的情况，验证连接会返回`ERR_QUIC_PROTOCOL_ERROR`。
* **连接超时后回退到TCP (开启retry_without_alt_svc_on_quic_errors):** 测试当QUIC连接超时且`retry_without_alt_svc_on_quic_errors`参数开启时，客户端会标记QUIC为不可用，并尝试通过TCP重新发送请求。

**与Javascript的功能关系:**

当Javascript代码（例如通过`fetch` API）发起一个到支持QUIC的HTTPS站点的请求时，浏览器网络栈会先尝试通过已知的QUIC信息连接。如果之前没有QUIC连接信息，或者QUIC连接失败，浏览器可能会发起一个标准的HTTPS请求。

如果服务器的HTTPS响应头中包含了`Alt-Svc`头部，指示可以通过QUIC协议访问该站点，那么浏览器就会将这些信息存储起来。当Javascript再次发起对相同站点的请求时，网络栈就可能根据存储的`Alt-Svc`信息，尝试建立QUIC连接。

**举例说明:**

假设一个网页中的Javascript代码发起了一个到 `https://mail.example.org` 的 `GET` 请求：

**假设输入 (HTTP 响应头):**

```
HTTP/1.1 200 OK
Alt-Svc: h3-29=":443"
Content-Type: text/html

<html>...</html>
```

**逻辑推理:**

1. 浏览器接收到服务器的HTTP响应，解析HTTP头部。
2. 浏览器发现`Alt-Svc: h3-29=":443"`，表示可以通过QUIC协议（h3-29版本）在 `mail.example.org` 的 443 端口建立连接。
3. 浏览器将该信息存储在 `HttpServerProperties` 中，与该Origin关联。
4. 如果Javascript再次发起对 `https://mail.example.org` 的请求，浏览器会尝试建立QUIC连接，而不是直接发起TCP连接。

**假设输出 (后续请求):**

后续对 `https://mail.example.org` 的请求会尝试通过QUIC协议进行，数据传输速度可能更快。

**用户或编程常见的使用错误:**

* **服务器配置错误的 Alt-Svc 头部:**  例如，指定了错误的端口号或协议名称，导致客户端无法建立QUIC连接。
    * **例子:** `Alt-Svc: h3-29=":80"` (HTTPS默认端口是443，这里写了80)。
* **客户端不支持服务器声明的 QUIC 版本:** 如果服务器只支持最新的QUIC版本，而客户端版本过旧，则无法升级。
* **网络环境不支持 UDP 协议:** QUIC协议基于UDP，如果网络防火墙阻止了UDP流量，则无法建立QUIC连接。
* **在测试环境中，Mock数据配置错误:** 在单元测试中，如果Mock的Socket数据或QUIC数据与预期不符，会导致测试失败。 例如，`MockRead` 和 `MockWrite` 的顺序或内容错误。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在浏览器地址栏输入 `https://mail.example.org` 并回车，或者点击了网页上指向该URL的链接。**
2. **浏览器发起一个到 `mail.example.org` 的 HTTPS 连接请求。**
3. **如果之前没有该站点的QUIC信息，浏览器会发起一个标准的 TCP 连接，并进行 TLS 握手。**
4. **服务器返回包含 `Alt-Svc` 头的 HTTP 响应。**
5. **`QuicNetworkTransaction` 或相关的网络栈组件会解析该头部，并尝试建立 QUIC 连接 (如果条件允许，例如客户端支持该版本)。**
6. **如果后续用户再次访问 `mail.example.org` 的页面或资源，网络栈会查找之前存储的 `Alt-Svc` 信息。**
7. **`QuicNetworkTransaction` 可能会被用于创建和管理这次的 QUIC 连接。**

当调试QUIC相关的网络问题时，可以关注以下几点：

* **查看 `net-internals` (chrome://net-internals/#quic):**  可以查看QUIC连接的状态、握手信息、错误等。
* **抓包 (例如使用 Wireshark):** 可以分析网络数据包，查看客户端和服务端之间的QUIC握手过程和数据传输。
* **设置断点:** 在 `net/quic` 目录下相关的代码中设置断点，例如 `QuicNetworkTransaction::Start`，查看连接的创建和管理过程。
* **查看网络请求日志:** Chrome的开发者工具中的 "Network" 标签可以查看请求的协议、状态等信息。

**归纳一下它的功能 (第4部分):**

这部分单元测试的主要功能是 **验证 Chromium 网络栈在接收到包含 Alt-Svc 头的 HTTP 响应后，能够正确地处理并尝试升级到 QUIC 连接，并且能够处理各种复杂的场景，包括版本协商、NetworkAnonymizationKey 的影响、错误处理以及回退机制。** 它确保了在通过 Alt-Svc 机制使用 QUIC 时，客户端行为的正确性和健壮性。

### 提示词
```
这是目录为net/quic/quic_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共13部分，请归纳一下它的功能
```

### 源代码
```cpp
ion_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  std::string alt_svc_header =
      "Alt-Svc: " + quic::AlpnForVersion(version_) + "=\":443\"\r\n\r\n";
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(alt_svc_header.data()),
      MockRead(kHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  AddCertificate(&ssl_data_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 2, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();

  SendRequestAndExpectHttpResponse(kHttpRespData);
  SendRequestAndExpectQuicResponse(kQuicRespData);
}

// Much like above, but makes sure NetworkAnonymizationKey is respected.
TEST_P(QuicNetworkTransactionTest,
       UseAlternativeServiceForQuicWithNetworkAnonymizationKey) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kPartitionConnectionsByNetworkIsolationKey);
  // Since HttpServerProperties caches the feature value, have to create a new
  // one.
  http_server_properties_ = std::make_unique<HttpServerProperties>();

  const SchemefulSite kSite1(GURL("https://foo.test/"));
  const net::NetworkIsolationKey kNetworkIsolationKey1(kSite1, kSite1);
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);

  const SchemefulSite kSite2(GURL("https://bar.test/"));
  const net::NetworkIsolationKey kNetworkIsolationKey2(kSite2, kSite2);
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);

  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(alt_svc_header_.data()),
      MockRead(kHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  AddCertificate(&ssl_data_);

  // Request with empty NetworkAnonymizationKey.
  StaticSocketDataProvider http_data1(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data1);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  // First request with kNetworkIsolationKey1.
  StaticSocketDataProvider http_data2(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data2);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  // Request with kNetworkIsolationKey2.
  StaticSocketDataProvider http_data3(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data3);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  // Second request with kNetworkIsolationKey1, can finally use QUIC, since
  // alternative service infrmation has been received in this context before.
  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 2, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();

  // This is first so that the test fails if alternative service info is
  // written with the right NetworkAnonymizationKey, but always queried with an
  // empty one.
  request_.network_isolation_key = NetworkIsolationKey();
  request_.network_anonymization_key = NetworkAnonymizationKey();
  SendRequestAndExpectHttpResponse(kHttpRespData);
  request_.network_isolation_key = kNetworkIsolationKey1;
  request_.network_anonymization_key = kNetworkAnonymizationKey1;
  SendRequestAndExpectHttpResponse(kHttpRespData);
  request_.network_isolation_key = kNetworkIsolationKey2;
  request_.network_anonymization_key = kNetworkAnonymizationKey2;
  SendRequestAndExpectHttpResponse(kHttpRespData);

  // Only use QUIC when using a NetworkAnonymizationKey which has been used when
  // alternative service information was received.
  request_.network_isolation_key = kNetworkIsolationKey1;
  request_.network_anonymization_key = kNetworkAnonymizationKey1;
  SendRequestAndExpectQuicResponse(kQuicRespData);
}

TEST_P(QuicNetworkTransactionTest, UseAlternativeServiceWithVersionForQuic1) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  // Both client and server supports two QUIC versions:
  // Client supports |supported_versions_[0]| and |supported_versions_[1]|,
  // server supports |version_| and |advertised_version_2|.
  // Only |version_| (same as |supported_versions_[0]|) is supported by both.
  // The QuicStreamFactoy will pick up |version_|, which is verified as the
  // PacketMakers are using |version_|.

  // Compare ALPN strings instead of ParsedQuicVersions because QUIC v1 and v2
  // have the same ALPN string.
  ASSERT_EQ(1u, supported_versions_.size());
  ASSERT_EQ(supported_versions_[0], version_);
  quic::ParsedQuicVersion advertised_version_2 =
      quic::ParsedQuicVersion::Unsupported();
  for (const quic::ParsedQuicVersion& version : quic::AllSupportedVersions()) {
    if (quic::AlpnForVersion(version) == quic::AlpnForVersion(version_)) {
      continue;
    }
    if (supported_versions_.size() != 2) {
      supported_versions_.push_back(version);
      continue;
    }
    if (supported_versions_.size() == 2 &&
        quic::AlpnForVersion(supported_versions_[1]) ==
            quic::AlpnForVersion(version)) {
      continue;
    }
    advertised_version_2 = version;
    break;
  }
  ASSERT_EQ(2u, supported_versions_.size());
  ASSERT_NE(quic::ParsedQuicVersion::Unsupported(), advertised_version_2);

  std::string QuicAltSvcWithVersionHeader =
      base::StringPrintf("Alt-Svc: %s=\":443\", %s=\":443\"\r\n\r\n",
                         quic::AlpnForVersion(advertised_version_2).c_str(),
                         quic::AlpnForVersion(version_).c_str());

  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(QuicAltSvcWithVersionHeader.c_str()), MockRead(kHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  AddCertificate(&ssl_data_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 2, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession(supported_versions_);

  SendRequestAndExpectHttpResponse(kHttpRespData);
  SendRequestAndExpectQuicResponse(kQuicRespData);
}

TEST_P(QuicNetworkTransactionTest,
       PickQuicVersionWhenMultipleVersionsAreSupported) {
  // Client and server both support more than one QUIC_VERSION.
  // Client prefers common_version_2, and then |version_|.
  // Server prefers |version_| common_version_2.
  // We should honor the server's preference.
  // The picked version is verified via checking the version used by the
  // TestPacketMakers and the response.
  // Since Chrome only supports one ALPN-negotiated version, common_version_2
  // will be another version that the common library supports even though
  // Chrome may consider it obsolete.

  // Find an alternative commonly supported version other than |version_|.
  quic::ParsedQuicVersion common_version_2 =
      quic::ParsedQuicVersion::Unsupported();
  for (const quic::ParsedQuicVersion& version : quic::AllSupportedVersions()) {
    if (version != version_ && !version.AlpnDeferToRFCv1()) {
      common_version_2 = version;
      break;
    }
  }
  ASSERT_NE(common_version_2, quic::ParsedQuicVersion::Unsupported());

  // Setting up client's preference list: {|version_|, |common_version_2|}.
  supported_versions_.clear();
  supported_versions_.push_back(common_version_2);
  supported_versions_.push_back(version_);

  // Setting up server's Alt-Svc header in the following preference order:
  // |version_|, |common_version_2|.
  std::string QuicAltSvcWithVersionHeader;
  quic::ParsedQuicVersion picked_version =
      quic::ParsedQuicVersion::Unsupported();
  QuicAltSvcWithVersionHeader =
      "Alt-Svc: " + quic::AlpnForVersion(version_) + "=\":443\"; ma=3600, " +
      quic::AlpnForVersion(common_version_2) + "=\":443\"; ma=3600\r\n\r\n";
  picked_version = version_;  // Use server's preference.

  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(QuicAltSvcWithVersionHeader.c_str()), MockRead(kHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  AddCertificate(&ssl_data_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  MockQuicData mock_quic_data(picked_version);

  // Reset QuicTestPacket makers as the version picked may not be |version_|.
  client_maker_ = std::make_unique<QuicTestPacketMaker>(
      picked_version,
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
      context_.clock(), kDefaultServerHostName, quic::Perspective::IS_CLIENT,
      /*client_priority_uses_incremental=*/true, /*use_priority_header=*/true);
  QuicTestPacketMaker server_maker(
      picked_version,
      quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
      context_.clock(), kDefaultServerHostName, quic::Perspective::IS_SERVER,
      /*client_priority_uses_incremental=*/false,
      /*use_priority_header=*/false);

  int packet_num = 1;
  if (VersionUsesHttp3(picked_version.transport_version)) {
    mock_quic_data.AddWrite(SYNCHRONOUS,
                            ConstructInitialSettingsPacket(packet_num++));
  }

  quic::QuicStreamId client_stream_0 =
      quic::test::GetNthClientInitiatedBidirectionalStreamId(
          picked_version.transport_version, 0);
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientRequestHeadersPacket(
                              packet_num++, client_stream_0, true,
                              GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(ASYNC,
                         server_maker.MakeResponseHeadersPacket(
                             1, client_stream_0, false,
                             server_maker.GetResponseHeaders("200"), nullptr));
  mock_quic_data.AddRead(
      ASYNC, server_maker.Packet(2)
                 .AddStreamFrame(client_stream_0, true,
                                 ConstructDataFrameForVersion(kQuicRespData,
                                                              picked_version))
                 .Build());
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 2, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession(supported_versions_);

  SendRequestAndExpectHttpResponse(kHttpRespData);
  SendRequestAndExpectQuicResponseMaybeFromProxy(
      kQuicRespData, 443, kQuic200RespStatusLine, picked_version, std::nullopt);
}

TEST_P(QuicNetworkTransactionTest, SetAlternativeServiceWithScheme) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  std::string alt_svc_header = base::StrCat(
      {"Alt-Svc: ",
       GenerateQuicAltSvcHeaderValue({version_}, "foo.example.com", 443), ",",
       GenerateQuicAltSvcHeaderValue({version_}, 444), "\r\n\r\n"});
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(alt_svc_header.data()),
      MockRead(kHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  AddCertificate(&ssl_data_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();
  // Send https request, ignore alternative service advertising if response
  // header advertises alternative service for mail.example.org.
  request_.url = GURL("https://mail.example.org:443");
  SendRequestAndExpectHttpResponse(kHttpRespData);
  HttpServerProperties* http_server_properties =
      session_->http_server_properties();
  url::SchemeHostPort http_server("http", "mail.example.org", 443);
  url::SchemeHostPort https_server("https", "mail.example.org", 443);
  // Check alternative service is set for the correct origin.
  EXPECT_EQ(2u, http_server_properties
                    ->GetAlternativeServiceInfos(https_server,
                                                 NetworkAnonymizationKey())
                    .size());
  EXPECT_TRUE(
      http_server_properties
          ->GetAlternativeServiceInfos(http_server, NetworkAnonymizationKey())
          .empty());
}

TEST_P(QuicNetworkTransactionTest, DoNotGetAltSvcForDifferentOrigin) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  std::string alt_svc_header = base::StrCat(
      {"Alt-Svc: ",
       GenerateQuicAltSvcHeaderValue({version_}, "foo.example.com", 443), ",",
       GenerateQuicAltSvcHeaderValue({version_}, 444), "\r\n\r\n"});
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(alt_svc_header.data()),
      MockRead(kHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  AddCertificate(&ssl_data_);

  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  CreateSession();

  // Send https request and set alternative services if response header
  // advertises alternative service for mail.example.org.
  SendRequestAndExpectHttpResponse(kHttpRespData);
  HttpServerProperties* http_server_properties =
      session_->http_server_properties();

  const url::SchemeHostPort https_server(request_.url);
  // Check alternative service is set.
  EXPECT_EQ(2u, http_server_properties
                    ->GetAlternativeServiceInfos(https_server,
                                                 NetworkAnonymizationKey())
                    .size());

  // Send http request to the same origin but with diffrent scheme, should not
  // use QUIC.
  request_.url = GURL("http://mail.example.org:443");
  SendRequestAndExpectHttpResponse(kHttpRespData);
}

TEST_P(QuicNetworkTransactionTest,
       StoreMutuallySupportedVersionsWhenProcessAltSvc) {
  // Add support for another QUIC version besides |version_|.
  for (const quic::ParsedQuicVersion& version : AllSupportedQuicVersions()) {
    if (version != version_) {
      supported_versions_.push_back(version);
      break;
    }
  }

  std::string altsvc_header = GenerateQuicAltSvcHeader(supported_versions_);
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead(altsvc_header.c_str()),
      MockRead("\r\n"),
      MockRead(kHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  AddCertificate(&ssl_data_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 2, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();

  CreateSession(supported_versions_);

  SendRequestAndExpectHttpResponse(kHttpRespData);
  SendRequestAndExpectQuicResponse(kQuicRespData);

  // Alt-Svc header contains all possible versions, so alternative services
  // should contain all of |supported_versions_|.
  const url::SchemeHostPort https_server(request_.url);
  const AlternativeServiceInfoVector alt_svc_info_vector =
      session_->http_server_properties()->GetAlternativeServiceInfos(
          https_server, NetworkAnonymizationKey());
  VerifyQuicVersionsInAlternativeServices(alt_svc_info_vector,
                                          supported_versions_);
}

TEST_P(QuicNetworkTransactionTest, UseAlternativeServiceAllSupportedVersion) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  std::string altsvc_header = base::StringPrintf(
      "Alt-Svc: %s=\":443\"\r\n\r\n", quic::AlpnForVersion(version_).c_str());
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"), MockRead(altsvc_header.c_str()),
      MockRead(kHttpRespData),
      MockRead(SYNCHRONOUS, ERR_TEST_PEER_CLOSE_AFTER_NEXT_MOCK_READ),
      MockRead(ASYNC, OK)};

  StaticSocketDataProvider http_data(http_reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&http_data);
  AddCertificate(&ssl_data_);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  MockQuicData mock_quic_data(version_);
  int packet_num = 1;
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructInitialSettingsPacket(packet_num++));
  mock_quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerResponseHeadersPacket(
                 1, GetNthClientInitiatedBidirectionalStreamId(0), false,
                 GetResponseHeaders("200")));
  mock_quic_data.AddRead(
      ASYNC, ConstructServerDataPacket(
                 2, GetNthClientInitiatedBidirectionalStreamId(0), true,
                 ConstructDataFrame(kQuicRespData)));
  mock_quic_data.AddWrite(SYNCHRONOUS,
                          ConstructClientAckPacket(packet_num++, 2, 1));
  mock_quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // No more data to read
  mock_quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  mock_quic_data.AddSocketDataToFactory(&socket_factory_);

  AddHangingNonAlternateProtocolSocketData();
  CreateSession();

  SendRequestAndExpectHttpResponse(kHttpRespData);
  SendRequestAndExpectQuicResponse(kQuicRespData);
}

// Verify that if a QUIC connection times out, the QuicHttpStream will
// return QUIC_PROTOCOL_ERROR.
TEST_P(QuicNetworkTransactionTest, TimeoutAfterHandshakeConfirmed) {
  context_.params()->retry_without_alt_svc_on_quic_errors = false;
  context_.params()->idle_connection_timeout = base::Seconds(5);
  // Turn off port migration to avoid dealing with unnecessary complexity in
  // this test.
  context_.params()->allow_port_migration = false;

  // The request will initially go out over QUIC.
  MockQuicData quic_data(version_);
  spdy::SpdyPriority priority =
      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);

  client_maker_->set_save_packet_frames(true);
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  int packet_num = 1;
  quic_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket(packet_num++));
  quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_->MakeRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          priority, GetRequestHeaders("GET", "https", "/"), nullptr));

  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);

  // QuicConnection::OnRetransmissionTimeout skips a packet number when
  // sending PTO packets.
  packet_num++;
  // PTO 1
  quic_data.AddWrite(SYNCHRONOUS,
                     client_maker_->MakeRetransmissionPacket(1, packet_num++));
  // QuicConnection::OnRetransmissionTimeout skips a packet number when
  // sending PTO packets.
  packet_num++;
  // PTO 2
  quic_data.AddWrite(SYNCHRONOUS,
                     client_maker_->MakeRetransmissionPacket(2, packet_num++));
  // QuicConnection::OnRetransmissionTimeout skips a packet number when
  // sending PTO packets.
  packet_num++;
  // PTO 3
  quic_data.AddWrite(SYNCHRONOUS,
                     client_maker_->MakeRetransmissionPacket(1, packet_num++));

  quic_data.AddWrite(SYNCHRONOUS,
                     client_maker_->Packet(packet_num++)
                         .AddConnectionCloseFrame(
                             quic::QUIC_NETWORK_IDLE_TIMEOUT,
                             "No recent network activity after 4s. Timeout:4s")
                         .Build());

  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, OK);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");

  CreateSession();
  // Use a TestTaskRunner to avoid waiting in real time for timeouts.
  QuicSessionPoolPeer::SetAlarmFactory(
      session_->quic_session_pool(),
      std::make_unique<QuicChromiumAlarmFactory>(quic_task_runner_.get(),
                                                 context_.clock()));

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Pump the message loop to get the request started.
  base::RunLoop().RunUntilIdle();
  // Explicitly confirm the handshake.
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();

  // Run the QUIC session to completion.
  quic_task_runner_->RunUntilIdle();

  ExpectQuicAlternateProtocolMapping();
  ASSERT_TRUE(quic_data.AllWriteDataConsumed());
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_QUIC_PROTOCOL_ERROR));
}

// TODO(fayang): Add time driven TOO_MANY_RTOS test.

// Verify that if a QUIC protocol error occurs after the handshake is confirmed
// the request fails with QUIC_PROTOCOL_ERROR.
TEST_P(QuicNetworkTransactionTest, ProtocolErrorAfterHandshakeConfirmed) {
  context_.params()->retry_without_alt_svc_on_quic_errors = false;
  // The request will initially go out over QUIC.
  MockQuicData quic_data(version_);
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  int packet_num = 1;
  quic_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket(packet_num++));
  quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          GetRequestHeaders("GET", "https", "/")));
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);  // Pause
  // Peer sending data from an non-existing stream causes this end to raise
  // error and close connection.
  quic_data.AddRead(ASYNC,
                    ConstructServerRstPacket(
                        1, GetNthClientInitiatedBidirectionalStreamId(47),
                        quic::QUIC_STREAM_LAST_ERROR));
  std::string quic_error_details = "Data for nonexistent stream";
  quic_data.AddWrite(
      SYNCHRONOUS,
      ConstructClientAckAndConnectionClosePacket(
          packet_num++, 1, 1, quic::QUIC_HTTP_STREAM_WRONG_DIRECTION,
          quic_error_details, quic::IETF_STOP_SENDING));
  quic_data.AddSocketDataToFactory(&socket_factory_);

  // In order for a new QUIC session to be established via alternate-protocol
  // without racing an HTTP connection, we need the host resolution to happen
  // synchronously.  Of course, even though QUIC *could* perform a 0-RTT
  // connection to the the server, in this test we require confirmation
  // before encrypting so the HTTP job will still start.
  host_resolver_.set_synchronous_mode(true);
  host_resolver_.rules()->AddIPLiteralRule("mail.example.org", "192.168.0.1",
                                           "");

  CreateSession();

  AddQuicAlternateProtocolMapping(MockCryptoClientStream::ZERO_RTT);

  HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
  TestCompletionCallback callback;
  int rv = trans.Start(&request_, callback.callback(), net_log_with_source_);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Pump the message loop to get the request started.
  base::RunLoop().RunUntilIdle();
  // Explicitly confirm the handshake.
  crypto_client_stream_factory_.last_stream()
      ->NotifySessionOneRttKeyAvailable();

  ASSERT_FALSE(quic_data.AllReadDataConsumed());
  quic_data.Resume();

  // Run the QUIC session to completion.
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(quic_data.AllWriteDataConsumed());
  ASSERT_TRUE(quic_data.AllReadDataConsumed());

  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_QUIC_PROTOCOL_ERROR));
  ExpectQuicAlternateProtocolMapping();
  ASSERT_TRUE(quic_data.AllWriteDataConsumed());
}

// Verify that with retry_without_alt_svc_on_quic_errors enabled, if a QUIC
// connection times out, then QUIC will be marked as broken and the request
// retried over TCP.
TEST_P(QuicNetworkTransactionTest, TimeoutAfterHandshakeConfirmedThenBroken2) {
  if (version_.AlpnDeferToRFCv1()) {
    // These versions currently do not support Alt-Svc.
    return;
  }
  context_.params()->idle_connection_timeout = base::Seconds(5);
  // Turn off port migration to avoid dealing with unnecessary complexity in
  // this test.
  context_.params()->allow_port_migration = false;

  // The request will initially go out over QUIC.
  MockQuicData quic_data(version_);
  spdy::SpdyPriority priority =
      ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);

  client_maker_->set_save_packet_frames(true);
  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_ZERO_RTT);
  int packet_num = 1;
  quic_data.AddWrite(SYNCHRONOUS,
                     client_maker_->MakeInitialSettingsPacket(packet_num++));
  quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_->MakeRequestHeadersPacket(
          packet_num++, GetNthClientInitiatedBidirectionalStreamId(0), true,
          priority, GetRequestHeaders("GET", "https", "/"), nullptr));

  client_maker_->SetEncryptionLevel(quic::ENCRYPTION_FORWARD_SECURE);
  // QuicConnection::OnRetransmissionTimeout skips a packet number when
  // sending PTO packets.
  packet_num++;
  // PTO 1
  quic_data.AddWrite(SYNCHRONOUS,
                     client_maker_->MakeRetransmissionPacket(1, packet_num++));

  // QuicConnection::OnRetransmissionTimeout skips a packet number when
  // sending PTO packets.
  packet_num++;
  // PTO 2
  quic_data.AddWrite(SYNCHRONOUS,
                     client_maker_->MakeRetransmissionPacket(2, packet_num++));

  // QuicConnection::OnRetransmissionTimeout skips a packet number when
  // sending PTO packets.
  packet_num++;
  // PTO 3
  quic_data.AddWrite(SYNCHRONOUS,
                     client_maker_->MakeRetransmissionPacket(1, packet_num++));

  quic_data.AddWrite(SYNCHRONOUS,
                     client_maker_->Packet(packet_num++)
                         .AddConnectionCloseFrame(
                             quic::QUIC_NETWORK_IDLE_TIMEOUT,
                             "No recent network activity after 4s. Timeout:4s")
                         .Build());

  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, OK);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  // After that fails, it will be resent via TCP.
  MockWrite http_writes[] = {
      MockWrite(SYNCHRONOUS, 0, "GET / HTTP/1.1\r\n"),
      MockWrite(SYNCHRONOUS, 1, "Host: mail.example.org\r\n"),
      MockWrite(SYNCHRONOUS, 2, "Connection: keep-alive\r\n\r\n")};

  MockRead http_reads[] = {MockRead(SYNCHRONOUS, 3, "HTTP/1.1 200 OK\r\n"),
                           MockRead(SYNCHRONOUS, 4, alt_svc_header_.data()),
                           MockRead(SYNCHRONOUS, 5, kHttpRespData),
                           MockRead(SYNCHRONOUS, OK, 6)};
  SequencedSocketData http_data(http_reads, http_writes);
  socket_factory_.AddSocketDataProvider(&http_data);
  socket_factory_.AddSSLSocketDataProvider(&ssl_data_);

  // In order for a new QUIC session to be established via alternate-protocol
  // wit
```