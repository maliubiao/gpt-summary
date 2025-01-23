Response:
The user wants a summary of the functionalities of the C++ code file `net/quic/quic_session_pool_test.cc`. I need to go through the test cases defined in the file and identify what aspects of the `QuicSessionPool` they are testing. I should also look for connections to JavaScript, logical reasoning with input/output examples, common user errors, and debugging steps. Finally, I need to provide a comprehensive summary as it's the last part of a series.

Here's a breakdown of the functionalities tested in the provided code:

1. **Handling connection refused errors:** Tests that `ERR_CONNECTION_REFUSED` closes the QUIC session.
2. **Handling large message errors:** Tests that `ERR_MSG_TOO_BIG` does *not* close the QUIC session.
3. **Handling zero-length reads:** Tests that a zero-length read does *not* close the QUIC session.
4. **Accessing DNS aliases:** Tests that DNS aliases associated with a hostname can be retrieved from a QUIC stream.
5. **No additional DNS aliases:** Tests the case where no additional DNS aliases are configured.
6. **Not using DNS aliases for proxy connections:** Tests that DNS aliasing is skipped when the connection is to a proxy.
7. **Handling connection errors during session creation with DNS aliases:** Tests that connection errors like `ERR_ADDRESS_IN_USE` are correctly handled when DNS aliases are present.
8. **Requiring DNS HTTPS ALPN (No HTTPS record):** Tests that a connection fails with `ERR_DNS_NO_MATCHING_SUPPORTED_ALPN` if the DNS record doesn't specify a supported QUIC ALPN.
9. **Requiring DNS HTTPS ALPN (Match):** Tests that a connection succeeds if the DNS record includes a matching QUIC ALPN.
10. **Requiring DNS HTTPS ALPN (Unknown ALPN):** Tests that a connection fails if the DNS record specifies an unknown ALPN.
11. **Requiring DNS HTTPS ALPN (Unknown and Supported ALPN):** Tests that a connection succeeds if the DNS record includes both an unknown and a supported ALPN.
12. **Requiring DNS HTTPS ALPN (Not ALPN name):** Tests that the ALPN name must be the correct format (not a generic version string).
13. **Requiring DNS HTTPS ALPN (Record only):** Tests that a connection can be established solely based on HTTPS records.
14. **IP Pooling with DNS Aliases:** Tests that sessions to different hostnames resolving to the same IP address can be pooled, considering DNS aliases.
15. **ECH GREASE:** Tests that ECH GREASE is enabled even if no ECH keys are provided.
16. **ECH with QUIC from Alt-Svc:** Tests that ECH configuration is picked up from DNS when QUIC is discovered via Alt-Svc.
17. **ECH with QUIC from HTTPS Record:** Tests that ECH configuration is picked up from DNS when QUIC is discovered via HTTPS records.
18. **ECH Disabled:** Tests that neither ECH nor ECH GREASE are enabled when ECH is explicitly disabled.
19. **ECH SVCB Reliant:** Tests that the connection fails if the server only supports HTTP/2 in its HTTPS record and the client requires ECH.
20. **ECH Disabled SVCB Optional:** Tests that the connection succeeds even if the server's HTTPS record only advertises HTTP/2 if the client has ECH disabled.
21. **Creating a Session Attempt:** Tests the functionality of creating a session attempt directly.

**Relation to JavaScript:** This C++ code is part of the Chromium network stack, which is used by the Chrome browser and other applications. While this specific file doesn't directly interact with JavaScript code, the functionality it tests (QUIC session management, DNS resolution, ECH) directly impacts the performance and security of network requests made by JavaScript running in a web page. For example, if a JavaScript application makes an HTTP request, the underlying network stack, including the QUIC session pool, is responsible for establishing and managing the connection.

**Logical Reasoning with Input/Output:**

* **Scenario:** Testing handling of `ERR_CONNECTION_REFUSED`.
    * **Input:** A socket connection attempt results in `ERR_CONNECTION_REFUSED`.
    * **Expected Output:** The QUIC session for that destination is closed.
* **Scenario:** Testing handling of `ERR_MSG_TOO_BIG`.
    * **Input:** A read operation on the socket returns `ERR_MSG_TOO_BIG`.
    * **Expected Output:** The QUIC session for that destination remains active.
* **Scenario:** Testing DNS Alias usage for connection pooling.
    * **Input:** Two requests to different hostnames (`kDefaultServerHostName` and `kServer2HostName`) resolve to the same IP address, with potentially overlapping DNS aliases.
    * **Expected Output:** A single QUIC session is established and shared between the two requests if DNS aliases permit pooling. The `GetDnsAliases()` method on the streams should return the expected set of aliases.

**Common User/Programming Errors:**

* **Incorrectly assuming all socket errors close the QUIC connection:** A developer might assume that any socket error will necessarily invalidate the QUIC session. This test highlights that certain errors like `ERR_MSG_TOO_BIG` are handled at a lower level and don't necessarily require closing the entire QUIC connection.
* **Not considering DNS aliases for connection pooling:** A developer might assume that only requests to the exact same hostname can share a QUIC session. This test demonstrates that connection pooling can happen based on IP address and shared DNS aliases.
* **Assuming ECH is always enabled:** This test suite includes cases where ECH is explicitly disabled, reminding developers that ECH is a configurable feature.
* **Misunderstanding the impact of HTTPS records on QUIC discovery:** Developers might not be aware that the presence and content of HTTPS records (SVCB records) can influence how QUIC connections are established, especially with features like ECH.

**User Operation to Reach This Code (Debugging Clues):**

A user action that triggers a network request using QUIC could lead to this code being executed. Here's a step-by-step example:

1. **User enters a URL in the Chrome address bar (e.g., `https://example.com`).**
2. **Chrome's network stack initiates a connection to the server.**
3. **The `QuicSessionPool` is consulted to see if an existing QUIC session to that server can be reused.**
4. **If no suitable session exists, the `QuicSessionPool` attempts to create a new one.** This involves:
    * **DNS resolution:** Looking up the IP address and potentially HTTPS records for the hostname.
    * **Socket creation:** Establishing a UDP socket connection.
    * **QUIC handshake:** Performing the cryptographic handshake to establish a secure connection.
5. **During the connection establishment or during the lifetime of the connection, various errors might occur (e.g., `ERR_CONNECTION_REFUSED`, `ERR_MSG_TOO_BIG`).** The tests in this file simulate these error conditions to verify the `QuicSessionPool`'s behavior.
6. **If the website has configured Alt-Svc or HTTPS records advertising QUIC support, the `QuicSessionPool` might use this information to establish a QUIC connection.** The ECH-related tests cover scenarios where these records include ECH configuration.
7. **If the user is behind a proxy, the `QuicSessionPool` will handle the connection differently, and DNS aliasing might be skipped.**

**Summary of `net/quic/quic_session_pool_test.cc` Functionality (Part 20 of 20):**

This final part of the `net/quic/quic_session_pool_test.cc` file focuses on verifying the resilience and advanced features of the QUIC session pool in the Chromium network stack. It comprehensively tests error handling scenarios, ensuring the pool behaves correctly when faced with connection refusals, large messages, and zero-length reads. Crucially, it delves into the intricacies of DNS aliasing and its impact on connection pooling, demonstrating how the pool can efficiently reuse connections for different hostnames resolving to the same IP, especially when considering DNS alias configurations. Furthermore, it thoroughly tests the integration of Encrypted Client Hello (ECH), covering scenarios where ECH is enabled, disabled, and discovered via different mechanisms like Alt-Svc and HTTPS records. The tests ensure that ECH configuration is correctly applied and that the session pool handles situations where ECH is required by the server. Finally, it includes a test for directly initiating a session creation attempt. As the concluding part, it confirms the robustness and feature completeness of the QUIC session pooling mechanism, which is essential for efficient and secure QUIC communication within the Chromium ecosystem.
这是目录为 `net/quic/quic_session_pool_test.cc` 的 chromium 网络栈的源代码文件，它主要的功能是**测试 `QuicSessionPool` 类的各项功能和行为**。`QuicSessionPool` 负责管理和复用 QUIC 会话，以提高网络连接的效率。

以下列举了该文件测试的主要功能点：

1. **连接错误处理:**
   - 测试当遇到 `ERR_CONNECTION_REFUSED` 错误时，`QuicSessionPool` 是否会正确地关闭连接，并且新的连接尝试不会复用该会话。
   - 测试当遇到 `ERR_MSG_TOO_BIG` 错误时，连接不会被关闭，因为这通常是流级别的错误，而不是会话级别的错误。
   - 测试接收到零长度读取时，连接不会被关闭，这通常表示连接正常，只是暂时没有数据。

2. **DNS 别名 (DNS Aliases):**
   - 测试当配置了 DNS 别名时，可以通过 `HttpStream` 获取到这些别名。
   - 测试当没有配置额外的 DNS 别名时，`HttpStream` 只能获取到请求的原始主机名。
   - 测试当请求是针对代理服务器时，不会使用 DNS 别名进行连接。
   - 测试当使用 DNS 别名创建连接时发生错误（例如 `ERR_ADDRESS_IN_USE`）时，是否能够正确处理。

3. **需要 DNS HTTPS ALPN (Require DNS HTTPS ALPN):**
   - 测试当配置了需要 DNS HTTPS ALPN 时，如果 DNS 记录中没有匹配的 ALPN 协议，连接会失败 (`ERR_DNS_NO_MATCHING_SUPPORTED_ALPN`)。
   - 测试当 DNS 记录中存在匹配的 ALPN 协议时，连接能够成功建立。
   - 测试当 DNS 记录中包含未知 ALPN 协议时，连接会失败。
   - 测试当 DNS 记录中同时包含未知和支持的 ALPN 协议时，连接能够成功建立。
   - 测试 DNS 记录中的 ALPN 协议必须是正确的格式，而不是通用的 QUIC 版本字符串。
   - 测试即使只有 HTTPS 记录（没有 A/AAAA 记录），如果 HTTPS 记录中包含 QUIC 的 ALPN，连接仍然可以建立。

4. **IP 地址池化 (IP Pooling) 和 DNS 别名:**
   - 测试当多个不同的域名解析到相同的 IP 地址，并且配置了 DNS 别名时，`QuicSessionPool` 是否能够复用底层的 QUIC 连接。

5. **ECH (Encrypted Client Hello):**
   - 测试即使 DNS 没有提供 ECH 密钥，ECH GREASE 也会被启用。
   - 测试当通过 Alt-Svc 发现 QUIC 时，ECH 配置能够从 DNS 记录中获取。
   - 测试当通过 HTTPS 记录发现 QUIC 时，ECH 配置能够从 DNS 记录中获取。
   - 测试当 ECH 功能被禁用时，既不会启用 ECH，也不会启用 ECH GREASE。
   - 测试当服务器支持 ECH 时，如果 HTTPS 记录中只声明了 HTTP/2，客户端会因为无法匹配 ALPN 而连接失败。
   - 测试当客户端禁用 ECH 时，即使服务器的 HTTPS 记录中只声明了 HTTP/2，连接仍然可以成功建立。

6. **直接创建会话尝试 (Create Session Attempt):**
   - 测试可以直接调用 `QuicSessionPool` 的方法来尝试创建一个新的 QUIC 会话。

**与 JavaScript 的关系:**

虽然此 C++ 代码文件本身不包含 JavaScript 代码，但它测试的网络栈组件是浏览器执行 JavaScript 发起的网络请求的基础。当 JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起 HTTPS 请求时，Chromium 的网络栈会尝试使用 QUIC 协议来建立连接。`QuicSessionPool` 的功能直接影响到这些请求的性能和效率。

**举例说明:**

假设一个 JavaScript 应用需要从 `https://example.com` 和 `https://alias.example.com` 获取资源，并且这两个域名解析到同一个 IP 地址，并且 `alias.example.com` 是 `example.com` 的 DNS 别名。`QuicSessionPool` 的 IP 地址池化功能会尝试复用为 `example.com` 建立的 QUIC 连接来处理对 `alias.example.com` 的请求，从而减少连接建立的延迟，提高页面加载速度。

**逻辑推理，假设输入与输出:**

* **假设输入:** 一个网络请求尝试连接到 `https://test.example.com`，但服务器返回 `ERR_CONNECTION_REFUSED`。
* **输出:** `QuicSessionPool` 会将该会话标记为不可用，并且后续对 `test.example.com` 的请求会尝试建立新的连接，而不是复用之前的失败会话。

* **假设输入:** 一个网络请求尝试连接到一个需要 HTTPS ALPN 的服务器，但 DNS 查询没有返回包含 QUIC ALPN 的 HTTPS 记录。
* **输出:** 连接尝试会失败，并返回错误码 `ERR_DNS_NO_MATCHING_SUPPORTED_ALPN`。

**用户或编程常见的使用错误:**

* **误认为所有网络错误都会导致 QUIC 会话关闭:** 开发者可能认为任何底层的 socket 错误都会直接导致 QUIC 会话的失效。但像 `ERR_MSG_TOO_BIG` 这样的错误通常是流级别的，不会直接导致整个 QUIC 会话的关闭。
* **没有意识到 DNS 别名对连接复用的影响:** 开发者可能没有考虑到 DNS 别名的情况，认为只有完全相同的域名才能复用 QUIC 连接。`QuicSessionPool` 的测试用例强调了 DNS 别名在连接复用中的作用。
* **在需要 HTTPS ALPN 的场景下，没有正确配置 DNS 记录:** 如果服务器要求客户端支持特定的 QUIC 协议版本，但 DNS 记录中没有声明相应的 ALPN，客户端将无法建立连接。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在 Chrome 浏览器中输入一个网址，例如 `https://www.example.com`。**
2. **Chrome 浏览器首先进行 DNS 查询，解析 `www.example.com` 的 IP 地址，并可能查询 HTTPS 记录 (SVCB)。**
3. **如果查询到支持 QUIC 的信息，网络栈会尝试使用 QUIC 协议建立连接。**
4. **`QuicSessionPool` 会被调用，检查是否已经存在可以复用的到 `www.example.com` 的 QUIC 会话。**
5. **如果不存在可复用的会话，`QuicSessionPool` 会尝试创建一个新的 QUIC 会话。** 这个过程涉及到 socket 的创建、QUIC 握手等步骤。
6. **在连接建立或数据传输过程中，可能会遇到各种网络错误，例如连接被拒绝（`ERR_CONNECTION_REFUSED`），或者接收到的数据过大（`ERR_MSG_TOO_BIG`）。**
7. **如果服务器配置了需要 HTTPS ALPN，并且 DNS 查询没有返回匹配的 ALPN，连接会在此阶段失败。**
8. **如果启用了 ECH，`QuicSessionPool` 在建立连接时会考虑 ECH 的配置和 DNS 返回的 ECH 密钥。**

在调试网络问题时，如果怀疑是 QUIC 连接的问题，可以检查 Chrome 的内部日志 (`chrome://net-export/`)，查看 QUIC 会话的创建、复用以及错误信息，这些信息会涉及到 `QuicSessionPool` 的行为。

**归纳 `net/quic/quic_session_pool_test.cc` 的功能 (第 20 部分，共 20 部分):**

作为整个测试套件的最后一部分，`net/quic/quic_session_pool_test.cc` 完整地测试了 `QuicSessionPool` 类的各项核心功能和边界情况。它覆盖了从基本的连接错误处理到更高级的特性，如 DNS 别名、HTTPS ALPN 协商和 ECH 集成。这部分测试旨在确保 `QuicSessionPool` 能够稳定、高效、安全地管理 QUIC 会话，并与 Chromium 网络栈的其他组件正确协作，为用户提供可靠的网络体验。完成这部分测试，意味着对 `QuicSessionPool` 的功能进行了全面的验证。

### 提示词
```
这是目录为net/quic/quic_session_pool_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第20部分，共20部分，请归纳一下它的功能
```

### 源代码
```cpp
s(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddReadPause();
  socket_data.AddRead(ASYNC, ERR_CONNECTION_REFUSED);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Create request and QuicHttpStream to trigger creation of the session.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Ensure that the session is alive and active before we read the error.
  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  // Resume the socket data to get the read error delivered.
  socket_data.Resume();
  // Ensure that the session is no longer active.
  EXPECT_FALSE(HasActiveSession(kDefaultDestination));
}

TEST_P(QuicSessionPoolTest, MessageTooBigReadErrorDoesNotCloseConnection) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddReadPause();
  socket_data.AddRead(ASYNC, ERR_MSG_TOO_BIG);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Create request and QuicHttpStream to trigger creation of the session.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Ensure that the session is alive and active before we read the error.
  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  // Resume the socket data to get the read error delivered.
  socket_data.Resume();
  // Ensure that the session is still active.
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
}

TEST_P(QuicSessionPoolTest, ZeroLengthReadDoesNotCloseConnection) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddReadPause();
  socket_data.AddRead(ASYNC, 0);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  // Create request and QuicHttpStream to trigger creation of the session.
  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  // Ensure that the session is alive and active before we read the error.
  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  EXPECT_TRUE(QuicSessionPoolPeer::IsLiveSession(factory_.get(), session));
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));

  // Resume the socket data to get the zero-length read delivered.
  socket_data.Resume();
  // Ensure that the session is still active.
  EXPECT_TRUE(HasActiveSession(kDefaultDestination));
}

TEST_P(QuicSessionPoolTest, DnsAliasesCanBeAccessedFromStream) {
  std::vector<std::string> dns_aliases(
      {"alias1", "alias2", kDefaultServerHostName});
  host_resolver_->rules()->AddIPLiteralRuleWithDnsAliases(
      kDefaultServerHostName, "192.168.0.1", std::move(dns_aliases));

  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  EXPECT_EQ(DEFAULT_PRIORITY, host_resolver_->last_request_priority());

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();

  EXPECT_THAT(stream->GetDnsAliases(),
              testing::ElementsAre("alias1", "alias2", kDefaultServerHostName));
}

TEST_P(QuicSessionPoolTest, NoAdditionalDnsAliases) {
  std::vector<std::string> dns_aliases;
  host_resolver_->rules()->AddIPLiteralRuleWithDnsAliases(
      kDefaultServerHostName, "192.168.0.1", std::move(dns_aliases));

  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  EXPECT_EQ(DEFAULT_PRIORITY, host_resolver_->last_request_priority());

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();

  EXPECT_THAT(stream->GetDnsAliases(),
              testing::ElementsAre(kDefaultServerHostName));
}

TEST_P(QuicSessionPoolTest, DoNotUseDnsAliases) {
  std::vector<std::string> dns_aliases({"alias1", "alias2"});
  host_resolver_->rules()->AddIPLiteralRuleWithDnsAliases(
      kDefaultServerHostName, "192.168.0.1", std::move(dns_aliases));

  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  // By indicating that this is a request to a proxy server, DNS aliasing will
  // not be performed.
  RequestBuilder builder(this);
  builder.session_usage = SessionUsage::kProxy;
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
  std::unique_ptr<HttpStream> stream = CreateStream(&builder.request);
  EXPECT_TRUE(stream.get());

  EXPECT_EQ(DEFAULT_PRIORITY, host_resolver_->last_request_priority());

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();

  EXPECT_TRUE(stream->GetDnsAliases().empty());
}

TEST_P(QuicSessionPoolTest, ConnectErrorInCreateWithDnsAliases) {
  std::vector<std::string> dns_aliases({"alias1", "alias2"});
  host_resolver_->rules()->AddIPLiteralRuleWithDnsAliases(
      kDefaultServerHostName, "192.168.0.1", std::move(dns_aliases));

  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddConnect(SYNCHRONOUS, ERR_ADDRESS_IN_USE);
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsError(ERR_ADDRESS_IN_USE));

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

TEST_P(QuicSessionPoolTest, RequireDnsHttpsAlpnNoHttpsRecord) {
  std::vector<HostResolverEndpointResult> endpoints(1);
  endpoints[0].ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};
  TestRequireDnsHttpsAlpn(std::move(endpoints), /*expect_success=*/false);
}

TEST_P(QuicSessionPoolTest, RequireDnsHttpsAlpnMatch) {
  std::vector<HostResolverEndpointResult> endpoints(2);
  endpoints[0].ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};
  endpoints[0].metadata.supported_protocol_alpns = {
      quic::AlpnForVersion(version_)};
  // Add a final non-protocol endpoint at the end.
  endpoints[1].ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};
  TestRequireDnsHttpsAlpn(std::move(endpoints), /*expect_success=*/true);
}

TEST_P(QuicSessionPoolTest, RequireDnsHttpsAlpnUnknownAlpn) {
  std::vector<HostResolverEndpointResult> endpoints(2);
  endpoints[0].ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};
  endpoints[0].metadata.supported_protocol_alpns = {"unknown"};
  // Add a final non-protocol endpoint at the end.
  endpoints[1].ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};
  TestRequireDnsHttpsAlpn(std::move(endpoints), /*expect_success=*/false);
}

TEST_P(QuicSessionPoolTest, RequireDnsHttpsAlpnUnknownAndSupportedAlpn) {
  std::vector<HostResolverEndpointResult> endpoints(2);
  endpoints[0].ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};
  endpoints[0].metadata.supported_protocol_alpns = {
      "unknown", quic::AlpnForVersion(version_)};
  // Add a final non-protocol endpoint at the end.
  endpoints[1].ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};
  TestRequireDnsHttpsAlpn(std::move(endpoints), /*expect_success=*/true);
}

// QUIC has many string representations of versions. Only the ALPN name is
// acceptable in HTTPS/SVCB records.
TEST_P(QuicSessionPoolTest, RequireDnsHttpsNotAlpnName) {
  std::vector<HostResolverEndpointResult> endpoints(2);
  endpoints[0].ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};
  endpoints[0].metadata.supported_protocol_alpns = {
      quic::ParsedQuicVersionToString(version_)};
  // Add a final non-protocol endpoint at the end.
  endpoints[1].ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};
  TestRequireDnsHttpsAlpn(std::move(endpoints), /*expect_success=*/false);
}

// If the only routes come from HTTPS/SVCB records (impossible until
// https://crbug.com/1417033 is implemented), we should still pick up the
// address from the HTTPS record.
TEST_P(QuicSessionPoolTest, RequireDnsHttpsRecordOnly) {
  std::vector<HostResolverEndpointResult> endpoints(1);
  endpoints[0].ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};
  endpoints[0].metadata.supported_protocol_alpns = {
      quic::AlpnForVersion(version_)};
  TestRequireDnsHttpsAlpn(std::move(endpoints), /*expect_success=*/true);
}

void QuicSessionPoolTest::TestRequireDnsHttpsAlpn(
    std::vector<HostResolverEndpointResult> endpoints,
    bool expect_success) {
  quic_params_->supported_versions = {version_};
  host_resolver_ = std::make_unique<MockHostResolver>();
  host_resolver_->rules()->AddRule(
      kDefaultServerHostName,
      MockHostResolverBase::RuleResolver::RuleResult(
          std::move(endpoints),
          /*aliases=*/std::set<std::string>{kDefaultServerHostName}));

  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  builder.quic_version = quic::ParsedQuicVersion::Unsupported();
  builder.require_dns_https_alpn = true;
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  if (expect_success) {
    EXPECT_THAT(callback_.WaitForResult(), IsOk());
  } else {
    EXPECT_THAT(callback_.WaitForResult(),
                IsError(ERR_DNS_NO_MATCHING_SUPPORTED_ALPN));
  }
}

namespace {

// Run QuicSessionPoolDnsAliasPoolingTest instances with all value
// combinations of version, H2 stream dependency or not, DNS alias use or not,
// and example DNS aliases. `expected_dns_aliases*` params are dependent on
// `use_dns_aliases`, `dns_aliases1`, and `dns_aliases2`.
struct DnsAliasPoolingTestParams {
  quic::ParsedQuicVersion version;
  bool use_dns_aliases;
  std::set<std::string> dns_aliases1;
  std::set<std::string> dns_aliases2;
  std::set<std::string> expected_dns_aliases1;
  std::set<std::string> expected_dns_aliases2;
};

std::string PrintToString(const std::set<std::string>& set) {
  std::string joined;
  for (const std::string& str : set) {
    if (!joined.empty()) {
      joined += "_";
    }
    joined += str;
  }
  return joined;
}

// Used by ::testing::PrintToStringParamName().
std::string PrintToString(const DnsAliasPoolingTestParams& p) {
  return base::StrCat({ParsedQuicVersionToString(p.version), "_",
                       (p.use_dns_aliases ? "" : "DoNot"), "UseDnsAliases_1st_",
                       PrintToString(p.dns_aliases1), "_2nd_",
                       PrintToString(p.dns_aliases2)});
}

std::vector<DnsAliasPoolingTestParams> GetDnsAliasPoolingTestParams() {
  std::vector<DnsAliasPoolingTestParams> params;
  quic::ParsedQuicVersionVector all_supported_versions =
      AllSupportedQuicVersions();
  for (const quic::ParsedQuicVersion& version : all_supported_versions) {
    params.push_back(DnsAliasPoolingTestParams{version,
                                               false /* use_dns_aliases */,
                                               {} /* dns_aliases1 */,
                                               {} /* dns_aliases2 */,
                                               {} /* expected_dns_aliases1 */,
                                               {} /* expected_dns_aliases2 */});
    params.push_back(DnsAliasPoolingTestParams{
        version,
        true /* use_dns_aliases */,
        {} /* dns_aliases1 */,
        {} /* dns_aliases2 */,
        {QuicSessionPoolTest::
             kDefaultServerHostName} /* expected_dns_aliases1 */,
        {QuicSessionPoolTest::kServer2HostName} /* expected_dns_aliases2 */});
    params.push_back(DnsAliasPoolingTestParams{version,
                                               false /* use_dns_aliases */,
                                               {"alias1", "alias2", "alias3"},
                                               {} /* dns_aliases2 */,
                                               {} /* expected_dns_aliases1 */,
                                               {} /* expected_dns_aliases2 */});
    params.push_back(DnsAliasPoolingTestParams{
        version,
        true /* use_dns_aliases */,
        {"alias1", "alias2", "alias3"} /* dns_aliases1 */,
        {} /* dns_aliases2 */,
        {"alias1", "alias2", "alias3"} /* expected_dns_aliases1 */,
        {QuicSessionPoolTest::kServer2HostName} /* expected_dns_aliases2 */});
    params.push_back(DnsAliasPoolingTestParams{
        version,
        false /* use_dns_aliases */,
        {"alias1", "alias2", "alias3"} /* dns_aliases1 */,
        {"alias3", "alias4", "alias5"} /* dns_aliases2 */,
        {} /* expected_dns_aliases1 */,
        {} /* expected_dns_aliases2 */});
    params.push_back(DnsAliasPoolingTestParams{
        version,
        true /* use_dns_aliases */,
        {"alias1", "alias2", "alias3"} /* dns_aliases1 */,
        {"alias3", "alias4", "alias5"} /* dns_aliases2 */,
        {"alias1", "alias2", "alias3"} /* expected_dns_aliases1 */,
        {"alias3", "alias4", "alias5"} /* expected_dns_aliases2 */});
    params.push_back(DnsAliasPoolingTestParams{
        version,
        false /* use_dns_aliases */,
        {} /* dns_aliases1 */,
        {"alias3", "alias4", "alias5"} /* dns_aliases2 */,
        {} /* expected_dns_aliases1 */,
        {} /* expected_dns_aliases2 */});
    params.push_back(DnsAliasPoolingTestParams{
        version,
        true /* use_dns_aliases */,
        {} /* dns_aliases1 */,
        {"alias3", "alias4", "alias5"} /* dns_aliases2 */,
        {QuicSessionPoolTest::
             kDefaultServerHostName} /* expected_dns_aliases1 */,
        {"alias3", "alias4", "alias5"} /* expected_dns_aliases2 */});
  }
  return params;
}

}  // namespace

class QuicSessionPoolDnsAliasPoolingTest
    : public QuicSessionPoolTestBase,
      public ::testing::TestWithParam<DnsAliasPoolingTestParams> {
 protected:
  QuicSessionPoolDnsAliasPoolingTest()
      : QuicSessionPoolTestBase(GetParam().version),
        use_dns_aliases_(GetParam().use_dns_aliases),
        dns_aliases1_(GetParam().dns_aliases1),
        dns_aliases2_(GetParam().dns_aliases2),
        expected_dns_aliases1_(GetParam().expected_dns_aliases1),
        expected_dns_aliases2_(GetParam().expected_dns_aliases2) {}

  const bool use_dns_aliases_;
  const std::set<std::string> dns_aliases1_;
  const std::set<std::string> dns_aliases2_;
  const std::set<std::string> expected_dns_aliases1_;
  const std::set<std::string> expected_dns_aliases2_;
};

INSTANTIATE_TEST_SUITE_P(VersionIncludeStreamDependencySequence,
                         QuicSessionPoolDnsAliasPoolingTest,
                         ::testing::ValuesIn(GetDnsAliasPoolingTestParams()),
                         ::testing::PrintToStringParamName());

TEST_P(QuicSessionPoolDnsAliasPoolingTest, IPPooling) {
  Initialize();

  const GURL kUrl1(kDefaultUrl);
  const GURL kUrl2(kServer2Url);
  const url::SchemeHostPort kOrigin1 = url::SchemeHostPort(kUrl1);
  const url::SchemeHostPort kOrigin2 = url::SchemeHostPort(kUrl2);

  host_resolver_->rules()->AddIPLiteralRuleWithDnsAliases(
      kOrigin1.host(), "192.168.0.1", std::move(dns_aliases1_));
  host_resolver_->rules()->AddIPLiteralRuleWithDnsAliases(
      kOrigin2.host(), "192.168.0.1", std::move(dns_aliases2_));

  scoped_refptr<X509Certificate> cert(
      ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
  ASSERT_TRUE(cert->VerifyNameMatch(kOrigin1.host()));
  ASSERT_TRUE(cert->VerifyNameMatch(kOrigin2.host()));

  ProofVerifyDetailsChromium verify_details;
  verify_details.cert_verify_result.verified_cert = cert;
  verify_details.cert_verify_result.is_issued_by_known_root = true;
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  SessionUsage session_usage;
  if (use_dns_aliases_) {
    session_usage = SessionUsage::kDestination;
  } else {
    session_usage = SessionUsage::kProxy;
  }
  RequestBuilder builder1(this);
  builder1.destination = kOrigin1;
  builder1.session_usage = session_usage;
  builder1.url = kUrl1;
  EXPECT_EQ(ERR_IO_PENDING, builder1.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());

  std::unique_ptr<HttpStream> stream1 = CreateStream(&builder1.request);
  EXPECT_TRUE(stream1.get());
  EXPECT_TRUE(HasActiveSession(kOrigin1, PRIVACY_MODE_DISABLED,
                               NetworkAnonymizationKey(), ProxyChain::Direct(),
                               session_usage));

  TestCompletionCallback callback2;
  RequestBuilder builder2(this);
  builder2.destination = kOrigin2;
  builder2.session_usage = session_usage;
  builder2.url = kUrl2;
  builder2.callback = callback2.callback();
  EXPECT_EQ(ERR_IO_PENDING, builder2.CallRequest());
  EXPECT_THAT(callback2.WaitForResult(), IsOk());

  std::unique_ptr<HttpStream> stream2 = CreateStream(&builder2.request);
  EXPECT_TRUE(stream2.get());
  EXPECT_TRUE(HasActiveSession(kOrigin2, PRIVACY_MODE_DISABLED,
                               NetworkAnonymizationKey(), ProxyChain::Direct(),
                               session_usage));

  QuicChromiumClientSession::Handle* session1 =
      QuicHttpStreamPeer::GetSessionHandle(stream1.get());
  QuicChromiumClientSession::Handle* session2 =
      QuicHttpStreamPeer::GetSessionHandle(stream2.get());
  EXPECT_TRUE(session1->SharesSameSession(*session2));

  EXPECT_EQ(quic::QuicServerId(kOrigin1.host(), kOrigin1.port()),
            session1->server_id());

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();

  EXPECT_EQ(expected_dns_aliases1_, stream1->GetDnsAliases());
  EXPECT_EQ(expected_dns_aliases2_, stream2->GetDnsAliases());
}

// Test that, even if DNS does not provide ECH keys, ECH GREASE is enabled.
TEST_P(QuicSessionPoolTest, EchGrease) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());

  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  ASSERT_TRUE(session);
  quic::QuicSSLConfig config = session->GetSSLConfig();
  EXPECT_TRUE(config.ech_grease_enabled);
  EXPECT_TRUE(config.ech_config_list.empty());
}

// Test that, connections where we discover QUIC from Alt-Svc (as opposed to
// HTTPS-RR), ECH is picked up from DNS.
TEST_P(QuicSessionPoolTest, EchWithQuicFromAltSvc) {
  HostResolverEndpointResult endpoint;
  endpoint.ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};
  endpoint.metadata.supported_protocol_alpns = {quic::AlpnForVersion(version_)};
  endpoint.metadata.ech_config_list = {1, 2, 3, 4};

  host_resolver_ = std::make_unique<MockHostResolver>();
  host_resolver_->rules()->AddRule(
      kDefaultServerHostName,
      MockHostResolverBase::RuleResolver::RuleResult({endpoint}));

  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  ASSERT_THAT(callback_.WaitForResult(), IsOk());

  QuicChromiumClientSession* session = GetActiveSession(kDefaultDestination);
  ASSERT_TRUE(session);
  quic::QuicSSLConfig config = session->GetSSLConfig();
  EXPECT_EQ(std::string(endpoint.metadata.ech_config_list.begin(),
                        endpoint.metadata.ech_config_list.end()),
            config.ech_config_list);
}

// Test that, connections where we discover QUIC from HTTPS-RR (as opposed to
// Alt-Svc), ECH is picked up from DNS.
TEST_P(QuicSessionPoolTest, EchWithQuicFromHttpsRecord) {
  quic_params_->supported_versions = {version_};
  HostResolverEndpointResult endpoint;
  endpoint.ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};
  endpoint.metadata.supported_protocol_alpns = {quic::AlpnForVersion(version_)};
  endpoint.metadata.ech_config_list = {1, 2, 3, 4};

  host_resolver_ = std::make_unique<MockHostResolver>();
  host_resolver_->rules()->AddRule(
      kDefaultServerHostName,
      MockHostResolverBase::RuleResolver::RuleResult({endpoint}));

  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  builder.quic_version = quic::ParsedQuicVersion::Unsupported();
  builder.require_dns_https_alpn = true;
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  ASSERT_THAT(callback_.WaitForResult(), IsOk());

  QuicChromiumClientSession* session = GetActiveSession(
      kDefaultDestination, PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      ProxyChain::Direct(), SessionUsage::kDestination,
      /*require_dns_https_alpn=*/true);
  ASSERT_TRUE(session);
  quic::QuicSSLConfig config = session->GetSSLConfig();
  EXPECT_EQ(std::string(endpoint.metadata.ech_config_list.begin(),
                        endpoint.metadata.ech_config_list.end()),
            config.ech_config_list);
}

// Test that, when ECH is disabled, neither ECH nor ECH GREASE are configured.
TEST_P(QuicSessionPoolTest, EchDisabled) {
  quic_params_->supported_versions = {version_};
  HostResolverEndpointResult endpoint;
  endpoint.ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};
  endpoint.metadata.supported_protocol_alpns = {quic::AlpnForVersion(version_)};
  endpoint.metadata.ech_config_list = {1, 2, 3, 4};

  host_resolver_ = std::make_unique<MockHostResolver>();
  host_resolver_->rules()->AddRule(
      kDefaultServerHostName,
      MockHostResolverBase::RuleResolver::RuleResult({endpoint}));

  SSLContextConfig ssl_config;
  ssl_config.ech_enabled = false;
  ssl_config_service_.UpdateSSLConfigAndNotify(ssl_config);

  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  builder.quic_version = quic::ParsedQuicVersion::Unsupported();
  builder.require_dns_https_alpn = true;
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  ASSERT_THAT(callback_.WaitForResult(), IsOk());

  QuicChromiumClientSession* session = GetActiveSession(
      kDefaultDestination, PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      ProxyChain::Direct(), SessionUsage::kDestination,
      /*require_dns_https_alpn=*/true);
  ASSERT_TRUE(session);
  quic::QuicSSLConfig config = session->GetSSLConfig();
  EXPECT_TRUE(config.ech_config_list.empty());
  EXPECT_FALSE(config.ech_grease_enabled);
}

// Test that, when the server supports ECH, the connection should use
// SVCB-reliant behavior.
TEST_P(QuicSessionPoolTest, EchSvcbReliant) {
  // The HTTPS-RR route only advertises HTTP/2 and is therefore incompatible
  // with QUIC. The fallback A/AAAA is compatible, but is ineligible in
  // ECH-capable clients.
  std::vector<HostResolverEndpointResult> endpoints(2);
  endpoints[0].ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};
  endpoints[0].metadata.supported_protocol_alpns = {"h2"};
  endpoints[0].metadata.ech_config_list = {1, 2, 3, 4};
  endpoints[1].ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};

  host_resolver_ = std::make_unique<MockHostResolver>();
  host_resolver_->rules()->AddRule(
      kDefaultServerHostName,
      MockHostResolverBase::RuleResolver::RuleResult(std::move(endpoints)));

  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(),
              IsError(ERR_DNS_NO_MATCHING_SUPPORTED_ALPN));
}

// Test that, when ECH is disabled, SVCB-reliant behavior doesn't trigger.
TEST_P(QuicSessionPoolTest, EchDisabledSvcbOptional) {
  // The HTTPS-RR route only advertises HTTP/2 and is therefore incompatible
  // with QUIC. The fallback A/AAAA is compatible, but is ineligible in
  // ECH-capable clients.
  std::vector<HostResolverEndpointResult> endpoints(2);
  endpoints[0].ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};
  endpoints[0].metadata.supported_protocol_alpns = {"h2"};
  endpoints[0].metadata.ech_config_list = {1, 2, 3, 4};
  endpoints[1].ip_endpoints = {IPEndPoint(IPAddress::IPv4Localhost(), 0)};

  host_resolver_ = std::make_unique<MockHostResolver>();
  host_resolver_->rules()->AddRule(
      kDefaultServerHostName,
      MockHostResolverBase::RuleResolver::RuleResult(std::move(endpoints)));

  // But this client is not ECH-capable, so the connection should succeed.
  SSLContextConfig ssl_config;
  ssl_config.ech_enabled = false;
  ssl_config_service_.UpdateSSLConfigAndNotify(ssl_config);

  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  RequestBuilder builder(this);
  EXPECT_EQ(ERR_IO_PENDING, builder.CallRequest());
  EXPECT_THAT(callback_.WaitForResult(), IsOk());
}

TEST_P(QuicSessionPoolTest, CreateSessionAttempt) {
  Initialize();
  ProofVerifyDetailsChromium verify_details = DefaultProofVerifyDetails();
  crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details);

  MockQuicData socket_data(version_);
  socket_data.AddReadPauseForever();
  socket_data.AddWrite(SYNCHRONOUS, ConstructInitialSettingsPacket());
  socket_data.AddSocketDataToFactory(socket_factory_.get());

  SessionAttemptHelper session_attempt(factory_.get(), version_);

  int rv = session_attempt.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  RunUntilIdle();
  EXPECT_THAT(session_attempt.result(), testing::Optional(OK));
  ASSERT_TRUE(GetActiveSession(kDefaultDestination));

  socket_data.ExpectAllReadDataConsumed();
  socket_data.ExpectAllWriteDataConsumed();
}

}  // namespace net::test
```