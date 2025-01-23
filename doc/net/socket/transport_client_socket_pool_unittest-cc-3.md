Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's networking stack. This is the last part of a four-part series. I need to:

1. **Summarize the overall function** of the code based on the provided tests.
2. **Identify relationships with JavaScript functionality**, if any. This likely involves understanding how network requests initiated in a browser (JavaScript's domain) interact with the underlying network stack.
3. **Provide examples of logical reasoning** with hypothetical inputs and outputs. This means explaining how different test scenarios would play out.
4. **Highlight common user or programming errors** that might lead to this code being executed.
5. **Describe the user actions** that would eventually lead to this code being involved in the network request.
6. **Synthesize the overall functionality** of this specific part.
这是 `net/socket/transport_client_socket_pool_unittest.cc` 文件的最后一部分，主要功能是测试 `TransportClientSocketPool` 类在处理网络连接时的各种场景，特别是关于 **SocketTagging（套接字标记）** 和 **空闲套接字超时** 的行为。

**核心功能归纳:**

1. **Socket Tagging 测试:** 这部分代码着重测试了 `TransportClientSocketPool` 在不同网络连接场景下正确应用和重用 `SocketTag` 的能力。`SocketTag` 用于标识套接字的用途或所有者，以便进行流量统计、策略控制等。测试覆盖了以下场景：
    * **直连 (Direct connections):**  测试在直连场景下，新建和复用的套接字是否正确应用了 `SocketTag`。
    * **SOCKS 代理:** 测试通过 SOCKS 代理连接时，新建和复用的套接字是否正确应用了 `SocketTag`。
    * **HTTP 代理 (有隧道和无隧道):** 测试通过 HTTP 代理连接（无论是否建立隧道）时，新建和复用的套接字是否正确应用了 `SocketTag`。
    * **连接请求的取消和优先级:** 测试当连接请求被取消或存在不同优先级请求时，`SocketTag` 的应用是否正确。
    * **连接池满的情况:** 测试当底层的 TCP 连接池满时，SSL 连接的请求如何处理，以及当 TCP 连接释放后，SSL 连接是否能正确建立并应用 `SocketTag`。

2. **空闲套接字超时测试:**  这部分测试了 `TransportClientSocketPool` 如何根据配置的超时时间清理空闲未使用的套接字。测试用例模拟了时间快进，并验证了在不同的超时配置下，空闲套接字是否按预期被移除。

**与 JavaScript 功能的关系:**

虽然这段 C++ 代码本身不直接包含 JavaScript，但它处理的网络连接是 Web 浏览器执行 JavaScript 代码时进行网络请求的基础。以下是一些关系举例：

* **场景:** 一个网页上的 JavaScript 代码使用 `fetch()` API 发起一个 HTTPS 请求。
* **关联:** 当浏览器需要建立与服务器的连接时，网络栈会使用 `TransportClientSocketPool` 来管理和复用 TCP 和 SSL 连接。这段测试代码确保了在建立这些连接的过程中，如果需要应用 `SocketTag` (例如，为了区分不同来源的流量)，能够正确地完成。
* **JavaScript 感知:** JavaScript 代码本身通常不直接感知 `SocketTag` 的存在。`SocketTag` 更多是 Chromium 内部用来管理和监控网络连接的机制。

**逻辑推理与假设输入输出:**

**示例 1: SocketTagging - 直连场景**

* **假设输入:**
    * 用户在浏览器中访问 `https://example.com`.
    * 代码尝试获取一个到 `example.com:443` 的 SSL 连接。
    * 请求关联的 `SocketTag` 为 `tag1`。
* **逻辑推理:** `TransportClientSocketPool` 会尝试查找是否有空闲的、可以复用的到 `example.com:443` 的连接。如果没有，则会创建一个新的 SSL 连接。在创建或复用连接时，会确保该连接关联了 `tag1`。随后通过该连接发送的网络数据会被标记为属于 `tag1`。
* **预期输出:**  如果成功建立连接，`handle.socket()->Write()` 操作会增加与 `tag1` 关联的流量计数（通过 `GetTaggedBytes(tag_val1)` 验证）。

**示例 2: 空闲套接字超时**

* **假设输入:**
    * 代码配置了空闲未使用套接字的超时时间为 10 秒。
    * 一个到 `www.foo.com:80` 的 HTTP 连接被建立并进入空闲状态。
    * 经过 15 秒后，代码尝试建立到 `www.bar.com:80` 的连接。
* **逻辑推理:** 当尝试建立到 `www.bar.com:80` 的连接时，`TransportClientSocketPool` 会检查是否有超时的空闲套接字。由于到 `www.foo.com:80` 的连接已经空闲超过 10 秒，它将被清理。
* **预期输出:** `session->GetSocketPool(...)->IdleSocketCount()` 在建立新连接后会减少，因为超时的套接字被移除。

**用户或编程常见的使用错误:**

* **未正确配置代理:** 如果用户配置了错误的代理服务器地址，可能会导致连接失败，最终可能会触发 `TransportClientSocketPool` 的连接重试或错误处理逻辑。
* **防火墙阻止连接:** 如果用户的防火墙阻止了到目标服务器或代理服务器的连接，`TransportClientSocketPool` 也会尝试建立连接但最终失败。
* **服务器无响应:** 如果目标服务器或代理服务器没有响应连接请求，`TransportClientSocketPool` 会等待超时并报告连接错误。
* **在 JavaScript 中发起大量并发请求:**  虽然不是 `TransportClientSocketPool` 本身的错误，但在 JavaScript 中发起过多并发请求可能导致连接池耗尽，从而触发连接排队等待。这部分测试中 `TagSSLDirectTwoSocketsFullPool` 就模拟了连接池满的情况。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入 URL 并回车，或者点击一个链接。**
2. **浏览器解析 URL，确定协议 (HTTP/HTTPS)、主机名和端口号。**
3. **如果需要连接到 HTTPS 网站，浏览器会进行 DNS 查询以获取服务器 IP 地址。**
4. **如果配置了代理服务器，浏览器会与代理服务器建立连接。**
5. **网络栈的 HTTP 或 HTTPS 代码会请求一个到目标服务器（或代理服务器）的连接。**
6. **`TransportClientSocketPool` 会被调用来获取或创建相应的 TCP 或 SSL 连接。** 这就是这段测试代码所覆盖的范围。
7. **`TransportClientSocketPool` 可能会复用现有的空闲连接，或者创建一个新的连接。**
8. **在创建新连接时，会根据需要应用 `SocketTag`。**
9. **如果连接池已满，新的连接请求可能需要等待。**
10. **如果连接在一段时间内未使用，可能会被 `TransportClientSocketPool` 清理。**

**本部分功能总结:**

作为第 4 部分，这段代码的功能主要是 **针对 `TransportClientSocketPool` 的高级测试**，重点在于验证其在处理 `SocketTag` 和空闲套接字超时方面的正确性和健壮性。它确保了在各种复杂的网络连接场景下，`SocketTag` 能够被正确地应用和重用，并且空闲的连接能够按照配置的策略被清理，从而提高网络连接的效率和资源利用率。 这些测试对于确保 Chromium 网络栈的稳定性和性能至关重要。

### 提示词
```
这是目录为net/socket/transport_client_socket_pool_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
event reuse.
  handle.socket()->Disconnect();
  handle.Reset();

  // Test connect jobs that are orphaned and then adopted, appropriately apply
  // new tag. Request socket with |tag1|.
  TestCompletionCallback callback2;
  rv = handle.Init(kGroupId, params, std::nullopt /* proxy_annotation_tag */,
                   LOW, tag1, ClientSocketPool::RespectLimits::ENABLED,
                   callback2.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_for_real_sockets_.get(), NetLogWithSource());
  EXPECT_TRUE(rv == OK || rv == ERR_IO_PENDING) << "Result: " << rv;
  // Abort and request socket with |tag2|.
  handle.Reset();
  rv = handle.Init(kGroupId, params, std::nullopt /* proxy_annotation_tag */,
                   LOW, tag2, ClientSocketPool::RespectLimits::ENABLED,
                   callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_for_real_sockets_.get(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  EXPECT_TRUE(handle.socket());
  EXPECT_TRUE(handle.socket()->IsConnected());
  // Verify socket has |tag2| applied.
  old_traffic = GetTaggedBytes(tag_val2);
  rv =
      handle.socket()->Write(write_buffer.get(), strlen(kRequest),
                             callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_EQ(static_cast<int>(strlen(kRequest)), callback.GetResult(rv));
  EXPECT_GT(GetTaggedBytes(tag_val2), old_traffic);
  // Disconnect socket to prevent reuse.
  handle.socket()->Disconnect();
  handle.Reset();
  // Eat the left over connect job from the second request.
  // TODO(pauljensen): remove when crbug.com/800731 fixed.
  rv = handle.Init(kGroupId, params, std::nullopt /* proxy_annotation_tag */,
                   LOW, tag1, ClientSocketPool::RespectLimits::ENABLED,
                   callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_for_real_sockets_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  // Disconnect socket to prevent reuse.
  handle.socket()->Disconnect();
  handle.Reset();

  // Test two connect jobs of differing priorities. Start the lower priority one
  // first but expect its socket to get vended to the higher priority request.
  ClientSocketHandle handle_high_pri;
  TestCompletionCallback callback_high_pri;
  rv = handle.Init(kGroupId, params, std::nullopt /* proxy_annotation_tag */,
                   LOW, tag1, ClientSocketPool::RespectLimits::ENABLED,
                   callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_for_real_sockets_.get(), NetLogWithSource());
  EXPECT_TRUE(rv == OK || rv == ERR_IO_PENDING) << "Result: " << rv;
  int rv_high_pri = handle_high_pri.Init(
      kGroupId, params, std::nullopt /* proxy_annotation_tag */, HIGHEST, tag2,
      ClientSocketPool::RespectLimits::ENABLED, callback_high_pri.callback(),
      ClientSocketPool::ProxyAuthCallback(), pool_for_real_sockets_.get(),
      NetLogWithSource());
  EXPECT_THAT(callback_high_pri.GetResult(rv_high_pri), IsOk());
  EXPECT_TRUE(handle_high_pri.socket());
  EXPECT_TRUE(handle_high_pri.socket()->IsConnected());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  EXPECT_TRUE(handle.socket());
  EXPECT_TRUE(handle.socket()->IsConnected());
  // Verify |handle_high_pri| has |tag2| applied.
  old_traffic = GetTaggedBytes(tag_val2);
  rv = handle_high_pri.socket()->Write(write_buffer.get(), strlen(kRequest),
                                       callback.callback(),
                                       TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_EQ(static_cast<int>(strlen(kRequest)), callback.GetResult(rv));
  EXPECT_GT(GetTaggedBytes(tag_val2), old_traffic);
  // Verify |handle| has |tag1| applied.
  old_traffic = GetTaggedBytes(tag_val1);
  rv =
      handle.socket()->Write(write_buffer.get(), strlen(kRequest),
                             callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_EQ(static_cast<int>(strlen(kRequest)), callback.GetResult(rv));
  EXPECT_GT(GetTaggedBytes(tag_val1), old_traffic);
}

TEST_F(TransportClientSocketPoolTest, TagSOCKSProxy) {
  session_deps_.host_resolver->set_synchronous_mode(true);

  TransportClientSocketPool proxy_pool(
      kMaxSockets, kMaxSocketsPerGroup, kUnusedIdleSocketTimeout,
      ProxyUriToProxyChain("socks5://proxy",
                           /*default_scheme=*/ProxyServer::SCHEME_HTTP),
      /*is_for_websockets=*/false, tagging_common_connect_job_params_.get());

  SocketTag tag1(SocketTag::UNSET_UID, 0x12345678);
  SocketTag tag2(getuid(), 0x87654321);
  const url::SchemeHostPort kDestination(url::kHttpScheme, "host", 80);
  const ClientSocketPool::GroupId kGroupId(
      kDestination, PrivacyMode::PRIVACY_MODE_DISABLED,
      NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
      /*disable_cert_network_fetches=*/false);
  scoped_refptr<ClientSocketPool::SocketParams> socks_params =
      ClientSocketPool::SocketParams::CreateForHttpForTesting();

  // Test socket is tagged when created synchronously.
  SOCKS5MockData data_sync(SYNCHRONOUS);
  data_sync.data_provider()->set_connect_data(MockConnect(SYNCHRONOUS, OK));
  tagging_client_socket_factory_.AddSocketDataProvider(
      data_sync.data_provider());
  ClientSocketHandle handle;
  int rv = handle.Init(
      kGroupId, socks_params, TRAFFIC_ANNOTATION_FOR_TESTS, LOW, tag1,
      ClientSocketPool::RespectLimits::ENABLED, CompletionOnceCallback(),
      ClientSocketPool::ProxyAuthCallback(), &proxy_pool, NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(handle.is_initialized());
  EXPECT_TRUE(handle.socket());
  EXPECT_EQ(tagging_client_socket_factory_.GetLastProducedTCPSocket()->tag(),
            tag1);
  EXPECT_TRUE(tagging_client_socket_factory_.GetLastProducedTCPSocket()
                  ->tagged_before_connected());

  // Test socket is tagged when reused synchronously.
  StreamSocket* socket = handle.socket();
  handle.Reset();
  rv = handle.Init(
      kGroupId, socks_params, TRAFFIC_ANNOTATION_FOR_TESTS, LOW, tag2,
      ClientSocketPool::RespectLimits::ENABLED, CompletionOnceCallback(),
      ClientSocketPool::ProxyAuthCallback(), &proxy_pool, NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(handle.socket());
  EXPECT_TRUE(handle.socket()->IsConnected());
  EXPECT_EQ(handle.socket(), socket);
  EXPECT_EQ(tagging_client_socket_factory_.GetLastProducedTCPSocket()->tag(),
            tag2);
  handle.socket()->Disconnect();
  handle.Reset();

  // Test socket is tagged when created asynchronously.
  SOCKS5MockData data_async(ASYNC);
  tagging_client_socket_factory_.AddSocketDataProvider(
      data_async.data_provider());
  TestCompletionCallback callback;
  rv = handle.Init(kGroupId, socks_params, TRAFFIC_ANNOTATION_FOR_TESTS, LOW,
                   tag1, ClientSocketPool::RespectLimits::ENABLED,
                   callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                   &proxy_pool, NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());
  EXPECT_TRUE(handle.is_initialized());
  EXPECT_TRUE(handle.socket());
  EXPECT_EQ(tagging_client_socket_factory_.GetLastProducedTCPSocket()->tag(),
            tag1);
  EXPECT_TRUE(tagging_client_socket_factory_.GetLastProducedTCPSocket()
                  ->tagged_before_connected());

  // Test socket is tagged when reused after being created asynchronously.
  socket = handle.socket();
  handle.Reset();
  rv = handle.Init(
      kGroupId, socks_params, TRAFFIC_ANNOTATION_FOR_TESTS, LOW, tag2,
      ClientSocketPool::RespectLimits::ENABLED, CompletionOnceCallback(),
      ClientSocketPool::ProxyAuthCallback(), &proxy_pool, NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(handle.socket());
  EXPECT_TRUE(handle.socket()->IsConnected());
  EXPECT_EQ(handle.socket(), socket);
  EXPECT_EQ(tagging_client_socket_factory_.GetLastProducedTCPSocket()->tag(),
            tag2);
}

TEST_F(TransportClientSocketPoolTest, TagSSLDirect) {
  if (!CanGetTaggedBytes()) {
    DVLOG(0) << "Skipping test - GetTaggedBytes unsupported.";
    return;
  }

  // Start test server.
  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  test_server.SetSSLConfig(net::EmbeddedTestServer::CERT_OK, SSLServerConfig());
  test_server.AddDefaultHandlers(base::FilePath());
  ASSERT_TRUE(test_server.Start());

  TestCompletionCallback callback;
  ClientSocketHandle handle;
  int32_t tag_val1 = 0x12345678;
  SocketTag tag1(SocketTag::UNSET_UID, tag_val1);
  int32_t tag_val2 = 0x87654321;
  SocketTag tag2(getuid(), tag_val2);
  const ClientSocketPool::GroupId kGroupId(
      url::SchemeHostPort(test_server.base_url()),
      PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);

  scoped_refptr<ClientSocketPool::SocketParams> socket_params =
      base::MakeRefCounted<ClientSocketPool::SocketParams>(
          /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());

  // Test socket is tagged before connected.
  uint64_t old_traffic = GetTaggedBytes(tag_val1);
  int rv = handle.Init(
      kGroupId, socket_params, std::nullopt /* proxy_annotation_tag */, LOW,
      tag1, ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
      ClientSocketPool::ProxyAuthCallback(), pool_for_real_sockets_.get(),
      NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  EXPECT_TRUE(handle.socket());
  EXPECT_TRUE(handle.socket()->IsConnected());
  EXPECT_GT(GetTaggedBytes(tag_val1), old_traffic);

  // Test reused socket is retagged.
  StreamSocket* socket = handle.socket();
  handle.Reset();
  old_traffic = GetTaggedBytes(tag_val2);
  TestCompletionCallback callback2;
  rv = handle.Init(kGroupId, socket_params,
                   std::nullopt /* proxy_annotation_tag */, LOW, tag2,
                   ClientSocketPool::RespectLimits::ENABLED,
                   callback2.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_for_real_sockets_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(handle.socket());
  EXPECT_TRUE(handle.socket()->IsConnected());
  EXPECT_EQ(handle.socket(), socket);
  const char kRequest[] = "GET / HTTP/1.1\r\n\r\n";
  scoped_refptr<IOBuffer> write_buffer =
      base::MakeRefCounted<StringIOBuffer>(kRequest);
  rv =
      handle.socket()->Write(write_buffer.get(), strlen(kRequest),
                             callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_EQ(static_cast<int>(strlen(kRequest)), callback.GetResult(rv));
  scoped_refptr<IOBufferWithSize> read_buffer =
      base::MakeRefCounted<IOBufferWithSize>(1);
  rv = handle.socket()->Read(read_buffer.get(), read_buffer->size(),
                             callback.callback());
  EXPECT_EQ(read_buffer->size(), callback.GetResult(rv));
  EXPECT_GT(GetTaggedBytes(tag_val2), old_traffic);
  // Disconnect socket to prevent reuse.
  handle.socket()->Disconnect();
  handle.Reset();
}

TEST_F(TransportClientSocketPoolTest, TagSSLDirectTwoSockets) {
  if (!CanGetTaggedBytes()) {
    DVLOG(0) << "Skipping test - GetTaggedBytes unsupported.";
    return;
  }

  // Start test server.
  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  test_server.SetSSLConfig(net::EmbeddedTestServer::CERT_OK, SSLServerConfig());
  test_server.AddDefaultHandlers(base::FilePath());
  ASSERT_TRUE(test_server.Start());

  ClientSocketHandle handle;
  int32_t tag_val1 = 0x12345678;
  SocketTag tag1(SocketTag::UNSET_UID, tag_val1);
  int32_t tag_val2 = 0x87654321;
  SocketTag tag2(getuid(), tag_val2);
  const ClientSocketPool::GroupId kGroupId(
      url::SchemeHostPort(test_server.base_url()),
      PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);
  scoped_refptr<ClientSocketPool::SocketParams> socket_params =
      base::MakeRefCounted<ClientSocketPool::SocketParams>(
          /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());

  // Test connect jobs that are orphaned and then adopted, appropriately apply
  // new tag. Request socket with |tag1|.
  TestCompletionCallback callback;
  int rv = handle.Init(
      kGroupId, socket_params, std::nullopt /* proxy_annotation_tag */, LOW,
      tag1, ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
      ClientSocketPool::ProxyAuthCallback(), pool_for_real_sockets_.get(),
      NetLogWithSource());
  EXPECT_TRUE(rv == OK || rv == ERR_IO_PENDING) << "Result: " << rv;
  // Abort and request socket with |tag2|.
  handle.Reset();
  TestCompletionCallback callback2;
  rv = handle.Init(kGroupId, socket_params,
                   std::nullopt /* proxy_annotation_tag */, LOW, tag2,
                   ClientSocketPool::RespectLimits::ENABLED,
                   callback2.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_for_real_sockets_.get(), NetLogWithSource());
  EXPECT_THAT(callback2.GetResult(rv), IsOk());
  EXPECT_TRUE(handle.socket());
  EXPECT_TRUE(handle.socket()->IsConnected());
  // Verify socket has |tag2| applied.
  uint64_t old_traffic = GetTaggedBytes(tag_val2);
  const char kRequest[] = "GET / HTTP/1.1\r\n\r\n";
  scoped_refptr<IOBuffer> write_buffer =
      base::MakeRefCounted<StringIOBuffer>(kRequest);
  rv = handle.socket()->Write(write_buffer.get(), strlen(kRequest),
                              callback2.callback(),
                              TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_EQ(static_cast<int>(strlen(kRequest)), callback2.GetResult(rv));
  scoped_refptr<IOBufferWithSize> read_buffer =
      base::MakeRefCounted<IOBufferWithSize>(1);
  rv = handle.socket()->Read(read_buffer.get(), read_buffer->size(),
                             callback2.callback());
  EXPECT_EQ(read_buffer->size(), callback2.GetResult(rv));
  EXPECT_GT(GetTaggedBytes(tag_val2), old_traffic);
}

TEST_F(TransportClientSocketPoolTest, TagSSLDirectTwoSocketsFullPool) {
  if (!CanGetTaggedBytes()) {
    DVLOG(0) << "Skipping test - GetTaggedBytes unsupported.";
    return;
  }

  // Start test server.
  EmbeddedTestServer test_server(net::EmbeddedTestServer::TYPE_HTTPS);
  test_server.SetSSLConfig(net::EmbeddedTestServer::CERT_OK, SSLServerConfig());
  test_server.AddDefaultHandlers(base::FilePath());
  ASSERT_TRUE(test_server.Start());

  TestCompletionCallback callback;
  ClientSocketHandle handle;
  int32_t tag_val1 = 0x12345678;
  SocketTag tag1(SocketTag::UNSET_UID, tag_val1);
  int32_t tag_val2 = 0x87654321;
  SocketTag tag2(getuid(), tag_val2);
  const ClientSocketPool::GroupId kGroupId(
      url::SchemeHostPort(test_server.base_url()),
      PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);
  scoped_refptr<ClientSocketPool::SocketParams> socket_params =
      base::MakeRefCounted<ClientSocketPool::SocketParams>(
          /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());

  // Test that sockets paused by a full underlying socket pool are properly
  // connected and tagged when underlying pool is freed up.
  // Fill up all slots in TCP pool.
  ClientSocketHandle tcp_handles[kMaxSocketsPerGroup];
  int rv;
  for (auto& tcp_handle : tcp_handles) {
    rv = tcp_handle.Init(
        kGroupId, socket_params, std::nullopt /* proxy_annotation_tag */, LOW,
        tag1, ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
        ClientSocketPool::ProxyAuthCallback(), pool_for_real_sockets_.get(),
        NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());
    EXPECT_TRUE(tcp_handle.socket());
    EXPECT_TRUE(tcp_handle.socket()->IsConnected());
  }
  // Request two SSL sockets.
  ClientSocketHandle handle_to_be_canceled;
  rv = handle_to_be_canceled.Init(
      kGroupId, socket_params, std::nullopt /* proxy_annotation_tag */, LOW,
      tag1, ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
      ClientSocketPool::ProxyAuthCallback(), pool_for_real_sockets_.get(),
      NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = handle.Init(kGroupId, socket_params,
                   std::nullopt /* proxy_annotation_tag */, LOW, tag2,
                   ClientSocketPool::RespectLimits::ENABLED,
                   callback.callback(), ClientSocketPool::ProxyAuthCallback(),
                   pool_for_real_sockets_.get(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  // Cancel first request.
  handle_to_be_canceled.Reset();
  // Disconnect a TCP socket to free up a slot.
  tcp_handles[0].socket()->Disconnect();
  tcp_handles[0].Reset();
  // Verify |handle| gets a valid tagged socket.
  EXPECT_THAT(callback.WaitForResult(), IsOk());
  EXPECT_TRUE(handle.socket());
  EXPECT_TRUE(handle.socket()->IsConnected());
  uint64_t old_traffic = GetTaggedBytes(tag_val2);
  const char kRequest[] = "GET / HTTP/1.1\r\n\r\n";
  scoped_refptr<IOBuffer> write_buffer =
      base::MakeRefCounted<StringIOBuffer>(kRequest);
  rv =
      handle.socket()->Write(write_buffer.get(), strlen(kRequest),
                             callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_EQ(static_cast<int>(strlen(kRequest)), callback.GetResult(rv));
  scoped_refptr<IOBufferWithSize> read_buffer =
      base::MakeRefCounted<IOBufferWithSize>(1);
  EXPECT_EQ(handle.socket()->Read(read_buffer.get(), read_buffer->size(),
                                  callback.callback()),
            ERR_IO_PENDING);
  EXPECT_THAT(callback.WaitForResult(), read_buffer->size());
  EXPECT_GT(GetTaggedBytes(tag_val2), old_traffic);
}

TEST_F(TransportClientSocketPoolTest, TagHttpProxyNoTunnel) {
  SocketTag tag1(SocketTag::UNSET_UID, 0x12345678);
  SocketTag tag2(getuid(), 0x87654321);

  TransportClientSocketPool proxy_pool(
      kMaxSockets, kMaxSocketsPerGroup, kUnusedIdleSocketTimeout,
      ProxyUriToProxyChain("http://proxy",
                           /*default_scheme=*/ProxyServer::SCHEME_HTTP),
      /*is_for_websockets=*/false, tagging_common_connect_job_params_.get());

  session_deps_.host_resolver->set_synchronous_mode(true);
  SequencedSocketData socket_data;
  socket_data.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  tagging_client_socket_factory_.AddSocketDataProvider(&socket_data);

  const url::SchemeHostPort kDestination(url::kHttpScheme, "www.google.com",
                                         80);
  const ClientSocketPool::GroupId kGroupId(
      kDestination, PrivacyMode::PRIVACY_MODE_DISABLED,
      NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
      /*disable_cert_network_fetches=*/false);
  scoped_refptr<ClientSocketPool::SocketParams> socket_params =
      ClientSocketPool::SocketParams::CreateForHttpForTesting();

  // Verify requested socket is tagged properly.
  ClientSocketHandle handle;
  int rv = handle.Init(
      kGroupId, socket_params, TRAFFIC_ANNOTATION_FOR_TESTS, LOW, tag1,
      ClientSocketPool::RespectLimits::ENABLED, CompletionOnceCallback(),
      ClientSocketPool::ProxyAuthCallback(), &proxy_pool, NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(handle.is_initialized());
  ASSERT_TRUE(handle.socket());
  EXPECT_TRUE(handle.socket()->IsConnected());
  EXPECT_EQ(tagging_client_socket_factory_.GetLastProducedTCPSocket()->tag(),
            tag1);
  EXPECT_TRUE(tagging_client_socket_factory_.GetLastProducedTCPSocket()
                  ->tagged_before_connected());

  // Verify reused socket is retagged properly.
  StreamSocket* socket = handle.socket();
  handle.Reset();
  rv = handle.Init(
      kGroupId, socket_params, TRAFFIC_ANNOTATION_FOR_TESTS, LOW, tag2,
      ClientSocketPool::RespectLimits::ENABLED, CompletionOnceCallback(),
      ClientSocketPool::ProxyAuthCallback(), &proxy_pool, NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(handle.socket());
  EXPECT_TRUE(handle.socket()->IsConnected());
  EXPECT_EQ(handle.socket(), socket);
  EXPECT_EQ(tagging_client_socket_factory_.GetLastProducedTCPSocket()->tag(),
            tag2);
  handle.socket()->Disconnect();
  handle.Reset();
}

// This creates a tunnel without SSL on top of it - something not normally done,
// though some non-HTTP consumers use this path to create tunnels for other
// uses.
TEST_F(TransportClientSocketPoolTest, TagHttpProxyTunnel) {
  SocketTag tag1(SocketTag::UNSET_UID, 0x12345678);
  SocketTag tag2(getuid(), 0x87654321);

  TransportClientSocketPool proxy_pool(
      kMaxSockets, kMaxSocketsPerGroup, kUnusedIdleSocketTimeout,
      ProxyUriToProxyChain("http://proxy",
                           /*default_scheme=*/ProxyServer::SCHEME_HTTP),
      /*is_for_websockets=*/false, tagging_common_connect_job_params_.get());

  session_deps_.host_resolver->set_synchronous_mode(true);

  std::string request =
      "CONNECT www.google.com:443 HTTP/1.1\r\n"
      "Host: www.google.com:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n\r\n";
  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, 0, request.c_str()),
  };
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, 1, "HTTP/1.1 200 Connection Established\r\n\r\n"),
  };

  SequencedSocketData socket_data(MockConnect(SYNCHRONOUS, OK), reads, writes);
  tagging_client_socket_factory_.AddSocketDataProvider(&socket_data);
  SSLSocketDataProvider ssl_data(SYNCHRONOUS, OK);
  tagging_client_socket_factory_.AddSSLSocketDataProvider(&ssl_data);

  const url::SchemeHostPort kDestination(url::kHttpsScheme, "www.google.com",
                                         443);
  const ClientSocketPool::GroupId kGroupId(
      kDestination, PrivacyMode::PRIVACY_MODE_DISABLED,
      NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
      /*disable_cert_network_fetches=*/false);

  scoped_refptr<ClientSocketPool::SocketParams> socket_params =
      base::MakeRefCounted<ClientSocketPool::SocketParams>(
          /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());

  // Verify requested socket is tagged properly.
  ClientSocketHandle handle;
  int rv = handle.Init(
      kGroupId, socket_params, TRAFFIC_ANNOTATION_FOR_TESTS, LOW, tag1,
      ClientSocketPool::RespectLimits::ENABLED, CompletionOnceCallback(),
      ClientSocketPool::ProxyAuthCallback(), &proxy_pool, NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(handle.is_initialized());
  ASSERT_TRUE(handle.socket());
  EXPECT_TRUE(handle.socket()->IsConnected());
  EXPECT_EQ(tagging_client_socket_factory_.GetLastProducedTCPSocket()->tag(),
            tag1);
  EXPECT_TRUE(tagging_client_socket_factory_.GetLastProducedTCPSocket()
                  ->tagged_before_connected());

  // Verify reused socket is retagged properly.
  StreamSocket* socket = handle.socket();
  handle.Reset();
  rv = handle.Init(
      kGroupId, socket_params, TRAFFIC_ANNOTATION_FOR_TESTS, LOW, tag2,
      ClientSocketPool::RespectLimits::ENABLED, CompletionOnceCallback(),
      ClientSocketPool::ProxyAuthCallback(), &proxy_pool, NetLogWithSource());
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(handle.socket());
  EXPECT_TRUE(handle.socket()->IsConnected());
  EXPECT_EQ(handle.socket(), socket);
  EXPECT_EQ(tagging_client_socket_factory_.GetLastProducedTCPSocket()->tag(),
            tag2);
  handle.socket()->Disconnect();
  handle.Reset();
}

#endif  // BUILDFLAG(IS_ANDROID)

// Class that enables tests to set mock time.
class TransportClientSocketPoolMockNowSourceTest
    : public TransportClientSocketPoolTest {
 public:
  TransportClientSocketPoolMockNowSourceTest(
      const TransportClientSocketPoolMockNowSourceTest&) = delete;
  TransportClientSocketPoolMockNowSourceTest& operator=(
      const TransportClientSocketPoolMockNowSourceTest&) = delete;

 protected:
  TransportClientSocketPoolMockNowSourceTest()
      : TransportClientSocketPoolTest(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}
};

// Tests that changing the idle unused socket timeout using the experiment
// works. The test first sets the value of timeout duration for idle sockets.
// Next, it opens |kNumIdleSockets| sockets. To trigger the cleanup of idle
// sockets that may have timedout, it then opens one more socket. This is
// required since requesting a new socket triggers cleanup of idle timedout
// sockets. Next, the test verifies the count of idle timed-out sockets.
TEST_F(TransportClientSocketPoolMockNowSourceTest, IdleUnusedSocketTimeout) {
  const url::SchemeHostPort kSchemeHostPort1(url::kHttpScheme, "www.foo.com",
                                             80);
  const url::SchemeHostPort kSchemeHostPort2(url::kHttpScheme, "www.bar.com",
                                             80);

  const struct {
    bool use_first_socket;
    int fast_forward_seconds;
    int unused_idle_socket_timeout_seconds;
    bool expect_idle_socket;
  } kTests[] = {
      // When the clock is fast forwarded by a duration longer than
      // |unused_idle_socket_timeout_seconds|, the first unused idle socket is
      // expected to be timedout, and cleared.
      {false, 0, 0, false},
      {false, 9, 10, true},
      {false, 11, 10, false},
      {false, 19, 20, true},
      {false, 21, 20, false},
      // If |use_first_socket| is true, then the test would write some data to
      // the socket, thereby marking it as "used". Thereafter, this idle socket
      // should be timedout based on used idle socket timeout, and changing
      // |unused_idle_socket_timeout_seconds| should not affect the
      // |expected_idle_sockets|.
      {true, 0, 0, true},
      {true, 9, 10, true},
      {true, 11, 10, true},
      {true, 19, 20, true},
      {true, 21, 20, true},
  };

  for (const auto& test : kTests) {
    SpdySessionDependencies session_deps(
        ConfiguredProxyResolutionService::CreateDirect());
    std::unique_ptr<HttpNetworkSession> session(
        SpdySessionDependencies::SpdyCreateSession(&session_deps));

    base::test::ScopedFeatureList scoped_feature_list_;
    std::map<std::string, std::string> parameters;
    parameters["unused_idle_socket_timeout_seconds"] =
        base::NumberToString(test.unused_idle_socket_timeout_seconds);
    scoped_feature_list_.InitAndEnableFeatureWithParameters(
        net::features::kNetUnusedIdleSocketTimeout, parameters);

    const char kWriteData[] = "1";
    const MockWrite kWrites[] = {MockWrite(SYNCHRONOUS, kWriteData)};

    SequencedSocketData provider_socket_1(MockConnect(ASYNC, OK),
                                          base::span<MockRead>(), kWrites);
    {
      // Create 1 socket.
      scoped_refptr<ClientSocketPool::SocketParams> socket_params =
          ClientSocketPool::SocketParams::CreateForHttpForTesting();
      session_deps.socket_factory->AddSocketDataProvider(&provider_socket_1);
      ClientSocketHandle connection;
      TestCompletionCallback callback;
      int rv = connection.Init(
          ClientSocketPool::GroupId(
              kSchemeHostPort1, PrivacyMode::PRIVACY_MODE_DISABLED,
              NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
              /*disable_cert_network_fetches=*/false),
          ClientSocketPool::SocketParams::CreateForHttpForTesting(),
          /*proxy_annotation_tag=*/std::nullopt, MEDIUM, SocketTag(),
          ClientSocketPool::RespectLimits::ENABLED, callback.callback(),
          ClientSocketPool::ProxyAuthCallback(),
          session->GetSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()),
          NetLogWithSource());
      EXPECT_THAT(callback.GetResult(rv), IsOk());
      EXPECT_FALSE(connection.socket()->WasEverUsed());

      // Writing some data to the socket should set WasEverUsed.
      if (test.use_first_socket) {
        // Generate |socket_write_data| from kMockWriteData by appending null
        // character to the latter.
        auto write_buffer = base::MakeRefCounted<StringIOBuffer>(kWriteData);
        TestCompletionCallback write_callback;
        rv = connection.socket()->Write(
            write_buffer.get(), write_buffer->size(), write_callback.callback(),
            TRAFFIC_ANNOTATION_FOR_TESTS);
        EXPECT_EQ(rv, 1);
        EXPECT_TRUE(connection.socket()->WasEverUsed());
      }
    }

    EXPECT_EQ(1, session
                     ->GetSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL,
                                     ProxyChain::Direct())
                     ->IdleSocketCount());

    // Moving the clock forward may cause the idle socket to be timedout.
    FastForwardBy(base::Seconds(test.fast_forward_seconds));

    {
      // Request a new socket to trigger cleanup of idle timedout sockets.
      scoped_refptr<ClientSocketPool::SocketParams> socket_params =
          ClientSocketPool::SocketParams::CreateForHttpForTesting();
      SequencedSocketData provider_socket_2(MockConnect(ASYNC, OK),
                                            base::span<MockRead>(),
                                            base::span<MockWrite>());
      session_deps.socket_factory->AddSocketDataProvider(&provider_socket_2);
      ClientSocketHandle connection;
      TestCompletionCallback callback;
      int rv = connection.Init(
          ClientSocketPool::GroupId(
              kSchemeHostPort2, PrivacyMode::PRIVACY_MODE_DISABLED,
              NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
              /*disable_cert_network_fetches=*/false),
          socket_params, /*proxy_annotation_tag=*/std::nullopt, MEDIUM,
          SocketTag(), ClientSocketPool::RespectLimits::ENABLED,
          callback.callback(), ClientSocketPool::ProxyAuthCallback(),
          session->GetSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL,
                                 ProxyChain::Direct()),
          NetLogWithSource());
      EXPECT_THAT(callback.GetResult(rv), IsOk());
      connection.socket()->Disconnect();
    }

    EXPECT_EQ(test.expect_idle_socket ? 1 : 0,
              session
                  ->GetSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL,
                                  ProxyChain::Direct())
                  ->IdleSocketCount());
  }
}

}  // namespace

}  // namespace net
```