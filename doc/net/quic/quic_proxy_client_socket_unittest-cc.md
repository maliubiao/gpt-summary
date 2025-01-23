Response:
Let's break down the thought process for analyzing the provided C++ unit test file.

**1. Initial Understanding: The "What"**

The first step is to recognize the file's nature. The name `quic_proxy_client_socket_unittest.cc` immediately suggests it's a unit test file for something related to `QuicProxyClientSocket`. The `#include` directives confirm this and reveal dependencies on various networking components in Chromium's stack (like `net/base`, `net/http`, `net/quic`). The `TEST_P` macros tell us it's a parameterized test suite using Google Test.

**2. Core Functionality: The "Why"**

The core purpose of this test file is to verify the behavior of the `QuicProxyClientSocket` class. This class, based on the name, is likely responsible for establishing and managing a QUIC connection to a proxy server. It simulates client-side interactions with such a socket.

**3. Identifying Key Operations: The "How"**

Scanning the test cases reveals the key operations being tested:

* **Connection Establishment (`Connect`):**  Tests like `ConnectSendsCorrectRequest`, `ConnectWithAuthRequested`, `ConnectRedirects`, and `ConnectFails` all focus on the connection process and various scenarios (successful connection, authentication, redirects, and failures).
* **Data Transmission (`Write`):**  `WriteSendsDataInDataFrame` and `WriteSplitsLargeDataIntoMultiplePackets` test how data is written to the socket, including handling large data.
* **Data Reception (`Read`):** A significant portion of the tests (`ReadReadsDataInDataFrame`, `ReadDataFromBufferedFrames`, etc.) focuses on reading data, including handling buffering, merging data from multiple frames, and splitting large frames.
* **Socket State and Information:** Tests like `WasEverUsedReturnsCorrectValue`, `GetPeerAddressReturnsCorrectValues`, `IsConnectedAndIdle`, and `GetTotalReceivedBytes` check the socket's state and its ability to provide information about the connection.
* **Header Handling:**  `ProxyDelegateExtraHeaders` specifically tests how extra headers are handled during the connection process.
* **Priority Setting:** `SetStreamPriority` checks if setting the stream priority has the expected effect.

**4. Relationship to JavaScript (or Lack Thereof):**

While QUIC is a transport protocol that underlies many web technologies, this specific C++ code is *not directly related to JavaScript*. It operates at a lower network level. The mental check is: "Does this code directly manipulate or interact with JavaScript code or the JavaScript engine?" The answer is no. It's about the underlying network communication.

**5. Logical Reasoning and Input/Output (Simulated):**

Unit tests inherently involve logical reasoning. For each test case, the *input* is a specific sequence of mocked network events (writes and reads), and the *output* is the expected behavior of the `QuicProxyClientSocket` (success, failure, specific data being sent or received). The `mock_quic_data_` object is crucial for setting up these simulated scenarios.

* **Example (ConnectSendsCorrectRequest):**
    * **Hypothetical Input:** A request to connect to a destination through a proxy.
    * **Mocked Network Input:** The test sets up `mock_quic_data_` to expect a specific CONNECT request packet being *written* and a successful server reply being *read*.
    * **Expected Output:** The `Connect` method should succeed, and the `GetConnectResponseInfo` should reflect the successful connection.

**6. Common Usage Errors and Debugging:**

The tests implicitly highlight potential errors:

* **Incorrect Proxy Configuration:** If the proxy address is wrong, the connection will fail.
* **Authentication Issues:** Incorrect credentials will lead to `ERR_PROXY_AUTH_REQUESTED`.
* **Server-Side Errors:** The proxy server might send errors or redirects, leading to connection failures.
* **Data Corruption/Incorrect Framing:**  The read/write tests ensure data integrity. Errors in framing would cause these tests to fail.

The debugging aspect is inherent to unit testing. If a test fails, it points to a problem in the `QuicProxyClientSocket` implementation. The mocked data helps isolate the issue. A developer would look at the expected vs. actual network interactions.

**7. User Operations as Debugging Clues:**

How does a user action lead here?

1. **User enters a URL in the browser.**
2. **Browser determines a proxy is needed.**
3. **Browser establishes a QUIC connection to the proxy (using `QuicProxyClientSocket`).**  *This is where this code becomes relevant.*
4. **The `Connect` method is called to establish the tunnel.**
5. **Data is sent/received through the proxy using `Write` and `Read` methods.**

If a user experiences a problem (e.g., a website doesn't load through a proxy), debugging might involve:

* **Checking proxy settings:** Is the proxy configured correctly?
* **Network logs:** Examining network logs to see the actual QUIC communication.
* **Looking for error codes:**  `ERR_PROXY_AUTH_REQUESTED` or similar codes can pinpoint the problem.

**8. Summarization (Instruction #6):**

The file's primary function is to *unit test* the `QuicProxyClientSocket` class. It verifies the correctness of its connection establishment, data transfer, and state management logic under various conditions, including successful connections, authentication requirements, redirects, and failures. It uses mocked network interactions to simulate different scenarios.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** "This might be related to how JavaScript interacts with proxies."  **Correction:** While QUIC benefits web technologies, this specific code is lower-level C++. The connection isn't *direct* JavaScript interaction.
* **Focus on individual tests:** Instead of just a high-level overview, I need to look at what *each* test is doing and the scenarios it covers.
* **Emphasize the mocking framework:**  The `mock_quic_data_` is central to understanding how these tests work. It provides the controlled environment for testing.

By following these steps, the comprehensive analysis of the unit test file can be achieved, addressing all the specific questions in the prompt.
好的，让我们来分析一下 `net/quic/quic_proxy_client_socket_unittest.cc` 这个文件。

**功能归纳 (第 1 部分):**

这个文件是 Chromium 网络栈中 `QuicProxyClientSocket` 类的单元测试文件。它的主要功能是验证 `QuicProxyClientSocket` 在各种场景下的行为是否符合预期。  更具体地说，它测试了以下关键方面的功能：

* **连接代理服务器:** 测试 `QuicProxyClientSocket` 如何建立到 QUIC 代理服务器的连接，包括发送正确的 CONNECT 请求。
* **处理代理认证:**  测试当代理服务器需要认证时，`QuicProxyClientSocket` 如何处理认证请求和凭据。
* **处理代理重定向:** 测试当代理服务器返回重定向响应时，`QuicProxyClientSocket` 的行为。
* **数据传输 (读写):** 测试通过 QUIC 代理连接发送和接收数据的能力，包括处理大数据包的分割和合并。
* **获取连接状态和信息:** 测试获取连接状态 (如是否连接、是否空闲) 和连接信息 (如对等地址、接收到的字节数) 的功能。
* **设置流优先级:** 测试设置 QUIC 流的优先级是否生效。
* **与 `ProxyDelegate` 交互:** 测试 `QuicProxyClientSocket` 如何与 `ProxyDelegate` 交互，例如在建立隧道时传递额外的请求头和接收响应头。

**与 Javascript 的关系:**

`QuicProxyClientSocket` 本身是用 C++ 实现的，属于 Chromium 浏览器的底层网络栈。它不直接与 Javascript 代码交互。然而，它的功能对于浏览器中通过 QUIC 代理访问网页至关重要。

**举例说明:**

假设一个用户在 Chrome 浏览器中访问一个需要通过 HTTPS QUIC 代理才能访问的网站。

1. **Javascript 发起请求:**  当网页上的 Javascript 代码尝试通过 `fetch` 或 `XMLHttpRequest` 发起网络请求时。
2. **浏览器路由请求:** 浏览器网络栈判断该请求需要通过配置的 HTTPS QUIC 代理。
3. **`QuicProxyClientSocket` 登场:** 浏览器会创建一个 `QuicProxyClientSocket` 实例来处理与代理服务器的连接。
4. **建立 QUIC 连接:**  `QuicProxyClientSocket` 会执行类似本测试文件中 `ConnectSendsCorrectRequest` 等测试所验证的逻辑，建立到代理服务器的 QUIC 连接并发送 CONNECT 请求。
5. **数据传输:**  一旦连接建立，Javascript 发起的请求数据会通过 `QuicProxyClientSocket` 的写入功能发送到代理服务器 (类似 `WriteSendsDataInDataFrame` 测试)。代理服务器返回的数据会通过 `QuicProxyClientSocket` 的读取功能接收 (类似 `ReadReadsDataInDataFrame` 测试)。
6. **返回给 Javascript:** 最终，接收到的数据会传递回 Javascript 代码，完成网络请求。

**逻辑推理，假设输入与输出:**

以 `ConnectSendsCorrectRequest` 测试为例：

* **假设输入:**  配置了一个 HTTPS QUIC 代理服务器，目标地址为 `destination_endpoint_`。
* **模拟网络操作:** `mock_quic_data_` 被配置为：
    * **写入:** 期望发送一个 Settings 包和一个 CONNECT 请求包。
    * **读取:** 期望接收到一个成功的服务器 CONNECT 响应包 (状态码 200)。
* **预期输出:**  `sock_->Connect` 方法应该成功返回 (没有错误)，`sock_->GetConnectResponseInfo()` 应该返回包含状态码 200 的响应头信息。`sock_->IsConnected()` 应该返回 true。

**用户或编程常见的使用错误:**

* **错误的代理配置:** 用户在浏览器设置中配置了错误的代理服务器地址或端口，可能导致 `QuicProxyClientSocket` 无法连接，测试中的 `ConnectFails` 模拟了这种情况。
* **代理需要认证但未提供凭据:** 如果代理服务器需要认证，但用户没有配置或提供了错误的用户名和密码，连接会失败，并返回 `ERR_PROXY_AUTH_REQUESTED` 错误，测试中的 `ConnectWithAuthRequested` 和 `ConnectWithAuthCredentials` 覆盖了这种情况。
* **代理服务器返回错误响应:** 代理服务器可能因为各种原因返回错误响应 (例如，目标服务器不存在)，`QuicProxyClientSocket` 需要正确处理这些错误，测试中的 `ConnectFails` 和 `ConnectRedirects` 模拟了这些场景。
* **程序逻辑错误导致数据读写不匹配:**  在程序中使用 `QuicProxyClientSocket` 时，如果写入的数据量和读取的数据量不匹配，或者读取的缓冲区大小不足，可能导致数据丢失或程序崩溃。测试中的各种读写测试用例确保了 `QuicProxyClientSocket` 能够正确处理不同大小的数据块。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在 Chrome 浏览器中尝试访问一个网站。**
2. **浏览器检测到需要使用代理服务器来访问该网站 (根据代理设置或 PAC 文件)。**
3. **浏览器网络栈选择使用 QUIC 协议连接代理服务器 (如果启用了 QUIC 且代理支持)。**
4. **网络栈会创建一个 `QuicProxyClientSocket` 实例，并调用其 `Connect` 方法来建立与代理的连接。**
5. **如果连接过程中出现问题 (例如，连接超时、认证失败)，开发人员可能会查看网络日志 (chrome://net-export/) 或使用调试工具来追踪问题。**
6. **在 Chromium 的源代码中，如果怀疑是 `QuicProxyClientSocket` 的行为导致问题，开发人员可能会查看这个单元测试文件，以了解该类的预期行为，并编写或运行相关的测试用例来验证假设。**
7. **例如，如果用户报告通过某个特定的 QUIC 代理无法访问网站，开发人员可能会尝试复现该场景，并查看 `QuicProxyClientSocket` 在连接该代理时的行为，这时就可以参考或修改这个单元测试文件来辅助调试。**

**总结 (针对第 1 部分):**

`net/quic/quic_proxy_client_socket_unittest.cc` 的主要功能是作为 `QuicProxyClientSocket` 类的单元测试套件。它通过模拟各种网络场景，验证该类在建立 QUIC 代理连接、处理认证和重定向、传输数据以及获取连接状态等方面的功能是否正确。 虽然它不是直接的 Javascript 代码，但它所测试的功能是 Chrome 浏览器通过 QUIC 代理访问网络的基础，与 Javascript 发起的网络请求息息相关。  这个文件对于保证 Chromium 网络栈的稳定性和正确性至关重要。

### 提示词
```
这是目录为net/quic/quic_proxy_client_socket_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_proxy_client_socket.h"

#include <memory>
#include <utility>

#include "base/functional/bind.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_server.h"
#include "net/base/proxy_string_util.h"
#include "net/base/test_proxy_delegate.h"
#include "net/http/http_response_headers.h"
#include "net/log/net_log.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_util.h"
#include "net/quic/quic_chromium_client_session.h"
#include "net/quic/quic_http_utils.h"
#include "net/quic/quic_proxy_client_socket_test_base.h"
#include "net/quic/test_quic_crypto_client_config_handle.h"
#include "net/quic/test_task_runner.h"
#include "net/ssl/ssl_config_service_defaults.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/common/http/http_header_block.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/qpack/qpack_test_utils.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_test_utils.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"

using testing::_;
using testing::AnyNumber;
using testing::Return;

namespace net::test {

class QuicProxyClientSocketTest : public QuicProxyClientSocketTestBase {
 public:
  void TearDown() override {
    sock_.reset();
    EXPECT_TRUE(mock_quic_data_.AllReadDataConsumed());
    EXPECT_TRUE(mock_quic_data_.AllWriteDataConsumed());
  }

  void InitializeClientSocket() override {
    sock_ = std::make_unique<QuicProxyClientSocket>(
        std::move(stream_handle_), std::move(session_handle_),
        // TODO(crbug.com/40181080) Construct `ProxyChain` with plain
        // `proxy_endpoint_` once it supports `url::SchemeHostPort`.
        ProxyChain(ProxyServer::SCHEME_HTTPS,
                   HostPortPair::FromSchemeHostPort(proxy_endpoint_)),
        /*proxy_chain_index=*/0, user_agent_,
        // TODO(crbug.com/40181080) Construct `QuicProxyClientSocket` with plain
        // `proxy_endpoint_` once it supports `url::SchemeHostPort`.
        HostPortPair::FromSchemeHostPort(destination_endpoint_),
        NetLogWithSource::Make(NetLogSourceType::NONE),
        base::MakeRefCounted<HttpAuthController>(
            HttpAuth::AUTH_PROXY, proxy_endpoint_.GetURL(),
            NetworkAnonymizationKey(), &http_auth_cache_,
            http_auth_handler_factory_.get(), host_resolver_.get()),
        proxy_delegate_.get());

    session_->StartReading();
  }

  void PopulateConnectRequestIR(
      quiche::HttpHeaderBlock* block,
      std::optional<const HttpRequestHeaders> extra_headers) override {
    (*block)[":method"] = "CONNECT";
    (*block)[":authority"] =
        HostPortPair::FromSchemeHostPort(destination_endpoint_).ToString();
    (*block)["user-agent"] = kUserAgent;
    if (extra_headers) {
      HttpRequestHeaders::Iterator it(*extra_headers);
      while (it.GetNext()) {
        std::string name = base::ToLowerASCII(it.name());
        (*block)[name] = it.value();
      }
    }
  }

  void AssertConnectSucceeds() override {
    TestCompletionCallback callback;
    ASSERT_THAT(sock_->Connect(callback.callback()),
                test::IsError(ERR_IO_PENDING));
    ASSERT_THAT(callback.WaitForResult(), test::IsOk());
  }

  void AssertConnectFails(int result) override {
    TestCompletionCallback callback;
    ASSERT_THAT(sock_->Connect(callback.callback()),
                test::IsError(ERR_IO_PENDING));
    EXPECT_EQ(result, callback.WaitForResult());
  }

  void AssertWriteReturns(const char* data, int len, int rv) override {
    auto buf = base::MakeRefCounted<IOBufferWithSize>(len);
    memcpy(buf->data(), data, len);
    EXPECT_EQ(rv,
              sock_->Write(buf.get(), buf->size(), write_callback_.callback(),
                           TRAFFIC_ANNOTATION_FOR_TESTS));
  }

  void AssertSyncWriteSucceeds(const char* data, int len) override {
    auto buf = base::MakeRefCounted<IOBufferWithSize>(len);
    memcpy(buf->data(), data, len);
    EXPECT_EQ(len,
              sock_->Write(buf.get(), buf->size(), CompletionOnceCallback(),
                           TRAFFIC_ANNOTATION_FOR_TESTS));
  }

  void AssertSyncReadEquals(const char* data, int len) override {
    auto buf = base::MakeRefCounted<IOBufferWithSize>(len);
    EXPECT_EQ(len, sock_->Read(buf.get(), len, CompletionOnceCallback()));
    EXPECT_EQ(std::string(data, len), std::string(buf->data(), len));
    ASSERT_TRUE(sock_->IsConnected());
  }

  void AssertAsyncReadEquals(const char* data, int len) override {
    auto buf = base::MakeRefCounted<IOBufferWithSize>(len);
    ASSERT_EQ(ERR_IO_PENDING,
              sock_->Read(buf.get(), len, read_callback_.callback()));
    EXPECT_TRUE(sock_->IsConnected());

    ResumeAndRun();

    EXPECT_EQ(len, read_callback_.WaitForResult());
    EXPECT_TRUE(sock_->IsConnected());
    EXPECT_EQ(std::string(data, len), std::string(buf->data(), len));
  }

  void AssertReadStarts(const char* data, int len) override {
    // Issue the read, which will be completed asynchronously.
    read_buf_ = base::MakeRefCounted<IOBufferWithSize>(len);
    ASSERT_EQ(ERR_IO_PENDING,
              sock_->Read(read_buf_.get(), len, read_callback_.callback()));
    EXPECT_TRUE(sock_->IsConnected());
  }

  void AssertReadReturns(const char* data, int len) override {
    EXPECT_TRUE(sock_->IsConnected());

    // Now the read will return.
    EXPECT_EQ(len, read_callback_.WaitForResult());
    EXPECT_EQ(std::string(data, len), std::string(read_buf_->data(), len));
  }

 protected:
  std::unique_ptr<QuicProxyClientSocket> sock_;
};

TEST_P(QuicProxyClientSocketTest, ConnectSendsCorrectRequest) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPauseForever();
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(packet_number++,
                                            quic::QUIC_STREAM_CANCELLED, 1, 1));

  InitializeSession();
  InitializeClientSocket();

  ASSERT_FALSE(sock_->IsConnected());

  AssertConnectSucceeds();

  const HttpResponseInfo* response = sock_->GetConnectResponseInfo();
  ASSERT_TRUE(response != nullptr);
  ASSERT_EQ(200, response->headers->response_code());

  // Although the underlying HTTP/3 connection uses TLS and negotiates ALPN, the
  // tunnel itself is a TCP connection to the origin and should not report these
  // values.
  net::SSLInfo ssl_info;
  EXPECT_FALSE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(sock_->GetNegotiatedProtocol(), NextProto::kProtoUnknown);
}

TEST_P(QuicProxyClientSocketTest, ProxyDelegateExtraHeaders) {
  // TODO(crbug.com/40284947): Add a version of this test for multi-hop.
  proxy_delegate_ = std::make_unique<TestProxyDelegate>();
  proxy_delegate_->set_extra_header_name(kTestHeaderName);
  // TODO(crbug.com/40181080) Construct `proxy_chain` with plain
  // `proxy_endpoint_` once it supports `url::SchemeHostPort`.
  ProxyChain proxy_chain(ProxyServer::SCHEME_HTTPS,
                         HostPortPair::FromSchemeHostPort(proxy_endpoint_));

  const char kResponseHeaderName[] = "bar";
  const char kResponseHeaderValue[] = "testing";

  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      ConstructConnectRequestPacketWithExtraHeaders(
          packet_number++,
          // Order matters! Keep these alphabetical.
          {{kTestQuicHeaderName, ProxyServerToProxyUri(proxy_chain.First())},
           {"user-agent", kUserAgent}}));
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerConnectReplyPacketWithExtraHeaders(
                 1, !kFin, {{kResponseHeaderName, kResponseHeaderValue}}));
  mock_quic_data_.AddReadPauseForever();
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(packet_number++,
                                            quic::QUIC_STREAM_CANCELLED, 1, 1));

  InitializeSession();
  InitializeClientSocket();

  ASSERT_FALSE(sock_->IsConnected());

  AssertConnectSucceeds();

  const HttpResponseInfo* response = sock_->GetConnectResponseInfo();
  ASSERT_TRUE(response != nullptr);
  ASSERT_EQ(200, response->headers->response_code());

  ASSERT_EQ(proxy_delegate_->on_tunnel_headers_received_call_count(), 1u);
  proxy_delegate_->VerifyOnTunnelHeadersReceived(proxy_chain, /*chain_index=*/0,
                                                 kResponseHeaderName,
                                                 kResponseHeaderValue);
}

TEST_P(QuicProxyClientSocketTest, ConnectWithAuthRequested) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC,
                          ConstructServerConnectAuthReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPauseForever();
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(packet_number++,
                                            quic::QUIC_STREAM_CANCELLED, 1, 1));

  InitializeSession();
  InitializeClientSocket();

  AssertConnectFails(ERR_PROXY_AUTH_REQUESTED);

  const HttpResponseInfo* response = sock_->GetConnectResponseInfo();
  ASSERT_TRUE(response != nullptr);
  ASSERT_EQ(407, response->headers->response_code());
}

TEST_P(QuicProxyClientSocketTest, ConnectWithAuthCredentials) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectAuthRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPauseForever();
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(packet_number++,
                                            quic::QUIC_STREAM_CANCELLED, 1, 1));

  InitializeSession();
  InitializeClientSocket();

  // Add auth to cache
  const std::u16string kFoo(u"foo");
  const std::u16string kBar(u"bar");
  http_auth_cache_.Add(
      url::SchemeHostPort(GURL(kProxyUrl)), HttpAuth::AUTH_PROXY, "MyRealm1",
      HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
      "Basic realm=MyRealm1", AuthCredentials(kFoo, kBar), "/");

  AssertConnectSucceeds();

  const HttpResponseInfo* response = sock_->GetConnectResponseInfo();
  ASSERT_TRUE(response != nullptr);
  ASSERT_EQ(200, response->headers->response_code());
}

// Tests that a redirect response from a CONNECT fails.
TEST_P(QuicProxyClientSocketTest, ConnectRedirects) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC,
                          ConstructServerConnectRedirectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPauseForever();
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(packet_number++,
                                            quic::QUIC_STREAM_CANCELLED, 1, 1));

  InitializeSession();
  InitializeClientSocket();

  AssertConnectFails(ERR_TUNNEL_CONNECTION_FAILED);

  const HttpResponseInfo* response = sock_->GetConnectResponseInfo();
  ASSERT_TRUE(response != nullptr);

  const HttpResponseHeaders* headers = response->headers.get();
  ASSERT_EQ(302, headers->response_code());
  ASSERT_TRUE(headers->HasHeader("set-cookie"));

  std::string location;
  ASSERT_TRUE(headers->IsRedirect(&location));
  ASSERT_EQ(location, kRedirectUrl);
}

TEST_P(QuicProxyClientSocketTest, ConnectFails) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  InitializeSession();
  InitializeClientSocket();

  ASSERT_FALSE(sock_->IsConnected());

  AssertConnectFails(ERR_QUIC_PROTOCOL_ERROR);

  ASSERT_FALSE(sock_->IsConnected());
}

TEST_P(QuicProxyClientSocketTest, WasEverUsedReturnsCorrectValue) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPauseForever();
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(packet_number++,
                                            quic::QUIC_STREAM_CANCELLED, 1, 1));

  InitializeSession();
  InitializeClientSocket();

  EXPECT_TRUE(sock_->WasEverUsed());  // Used due to crypto handshake
  AssertConnectSucceeds();
  EXPECT_TRUE(sock_->WasEverUsed());
  sock_->Disconnect();
  EXPECT_TRUE(sock_->WasEverUsed());
}

TEST_P(QuicProxyClientSocketTest, GetPeerAddressReturnsCorrectValues) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPause();
  mock_quic_data_.AddRead(ASYNC, ERR_CONNECTION_CLOSED);

  InitializeSession();
  InitializeClientSocket();

  IPEndPoint addr;
  EXPECT_THAT(sock_->GetPeerAddress(&addr), IsError(ERR_SOCKET_NOT_CONNECTED));

  AssertConnectSucceeds();
  EXPECT_TRUE(sock_->IsConnected());
  EXPECT_THAT(sock_->GetPeerAddress(&addr), IsOk());

  ResumeAndRun();

  EXPECT_FALSE(sock_->IsConnected());
  EXPECT_THAT(sock_->GetPeerAddress(&addr), IsError(ERR_SOCKET_NOT_CONNECTED));

  sock_->Disconnect();

  EXPECT_THAT(sock_->GetPeerAddress(&addr), IsError(ERR_SOCKET_NOT_CONNECTED));
}

TEST_P(QuicProxyClientSocketTest, IsConnectedAndIdle) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPause();

  std::string header = ConstructDataHeader(kLen1);
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerDataPacket(2, header + std::string(kMsg1, kLen1)));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructAckPacket(packet_number++, 2, 1));
  mock_quic_data_.AddReadPauseForever();
  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      ConstructRstPacket(packet_number++, quic::QUIC_STREAM_CANCELLED));

  InitializeSession();
  InitializeClientSocket();

  EXPECT_FALSE(sock_->IsConnectedAndIdle());

  AssertConnectSucceeds();

  EXPECT_TRUE(sock_->IsConnectedAndIdle());

  // The next read is consumed and buffered.
  ResumeAndRun();

  EXPECT_FALSE(sock_->IsConnectedAndIdle());

  AssertSyncReadEquals(kMsg1, kLen1);

  EXPECT_TRUE(sock_->IsConnectedAndIdle());
}

TEST_P(QuicProxyClientSocketTest, GetTotalReceivedBytes) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  size_t header_length;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerConnectReplyPacket(1, !kFin, &header_length));
  mock_quic_data_.AddReadPause();

  std::string data_header = ConstructDataHeader(kLen333);
  mock_quic_data_.AddRead(ASYNC,
                          ConstructServerDataPacket(
                              2, data_header + std::string(kMsg333, kLen333)));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructAckPacket(packet_number++, 2, 1));
  mock_quic_data_.AddReadPauseForever();
  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      ConstructRstPacket(packet_number++, quic::QUIC_STREAM_CANCELLED));

  InitializeSession();
  InitializeClientSocket();

  EXPECT_EQ(0, sock_->GetTotalReceivedBytes());

  AssertConnectSucceeds();

  EXPECT_EQ((int64_t)(header_length), sock_->GetTotalReceivedBytes());

  // The next read is consumed and buffered.
  ResumeAndRun();

  EXPECT_EQ((int64_t)(header_length + data_header.length()),
            sock_->GetTotalReceivedBytes());

  // The payload from the single large data frame will be read across
  // two different reads.
  AssertSyncReadEquals(kMsg33, kLen33);

  EXPECT_EQ((int64_t)(header_length + data_header.length() + kLen33),
            sock_->GetTotalReceivedBytes());

  AssertSyncReadEquals(kMsg3, kLen3);

  EXPECT_EQ((int64_t)(header_length + kLen333 + data_header.length()),
            sock_->GetTotalReceivedBytes());
}

TEST_P(QuicProxyClientSocketTest, SetStreamPriority) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  // Despite setting the priority to HIGHEST, the requests initial priority of
  // LOWEST is used.
  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      ConstructConnectRequestPacket(packet_number++,
                                    /*extra_headers=*/std::nullopt, LOWEST));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPauseForever();
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(packet_number++,
                                            quic::QUIC_STREAM_CANCELLED, 1, 1));

  InitializeSession();
  InitializeClientSocket();

  sock_->SetStreamPriority(HIGHEST);
  AssertConnectSucceeds();
}

TEST_P(QuicProxyClientSocketTest, WriteSendsDataInDataFrame) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPauseForever();
  std::string header = ConstructDataHeader(kLen1);
  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      ConstructAckAndDataPacket(packet_number++, 1, 1,
                                {header + std::string(kMsg1, kLen1)}));
  std::string header2 = ConstructDataHeader(kLen2);
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructDataPacket(packet_number++,
                                       {header2 + std::string(kMsg2, kLen2)}));
  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      ConstructRstPacket(packet_number++, quic::QUIC_STREAM_CANCELLED));

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  AssertSyncWriteSucceeds(kMsg1, kLen1);
  AssertSyncWriteSucceeds(kMsg2, kLen2);
}

TEST_P(QuicProxyClientSocketTest, WriteSplitsLargeDataIntoMultiplePackets) {
  int write_packet_index = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(write_packet_index++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(write_packet_index++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPauseForever();
  std::string header = ConstructDataHeader(kLen1);
  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      ConstructAckAndDataPacket(write_packet_index++, 1, 1,
                                {header + std::string(kMsg1, kLen1)}));

  // Expect |kNumDataPackets| data packets, each containing the max possible
  // amount of data.
  int numDataPackets = 3;
  std::string data(numDataPackets * quic::kDefaultMaxPacketSize, 'x');
  quic::QuicStreamOffset offset = kLen1 + header.length();

  numDataPackets++;
  size_t total_data_length = 0;
  for (int i = 0; i < numDataPackets; ++i) {
    size_t max_packet_data_length = GetStreamFrameDataLengthFromPacketLength(
        quic::kDefaultMaxPacketSize, version_, !kIncludeVersion,
        !kIncludeDiversificationNonce, k8ByteConnectionId,
        quic::PACKET_1BYTE_PACKET_NUMBER, offset);
    if (i == 0) {
      // 3661 is the data frame length from packet length.
      std::string header2 = ConstructDataHeader(3661);
      mock_quic_data_.AddWrite(
          SYNCHRONOUS,
          ConstructDataPacket(
              write_packet_index++,
              {header2 +
               std::string(data.c_str(), max_packet_data_length - 7)}));
      offset += max_packet_data_length - header2.length() - 1;
    } else if (i == numDataPackets - 1) {
      mock_quic_data_.AddWrite(
          SYNCHRONOUS, ConstructDataPacket(write_packet_index++,
                                           std::string(data.c_str(), 7)));
      offset += 7;
    } else {
      mock_quic_data_.AddWrite(
          SYNCHRONOUS, ConstructDataPacket(
                           write_packet_index++,
                           std::string(data.c_str(), max_packet_data_length)));
      offset += max_packet_data_length;
    }
    if (i != 3) {
      total_data_length += max_packet_data_length;
    }
  }

  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      ConstructRstPacket(write_packet_index++, quic::QUIC_STREAM_CANCELLED));

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  // Make a small write. An ACK and STOP_WAITING will be bundled. This prevents
  // ACK and STOP_WAITING from being bundled with the subsequent large write.
  // This allows the test code for computing the size of data sent in each
  // packet to not become too complicated.
  AssertSyncWriteSucceeds(kMsg1, kLen1);

  // Make large write that should be split up
  AssertSyncWriteSucceeds(data.c_str(), total_data_length);
}

// ----------- Read

TEST_P(QuicProxyClientSocketTest, ReadReadsDataInDataFrame) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPause();

  std::string header = ConstructDataHeader(kLen1);
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerDataPacket(2, header + std::string(kMsg1, kLen1)));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructAckPacket(packet_number++, 2, 1));
  mock_quic_data_.AddReadPauseForever();
  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      ConstructRstPacket(packet_number++, quic::QUIC_STREAM_CANCELLED));

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  ResumeAndRun();
  AssertSyncReadEquals(kMsg1, kLen1);
}

TEST_P(QuicProxyClientSocketTest, ReadDataFromBufferedFrames) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPause();

  std::string header = ConstructDataHeader(kLen1);
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerDataPacket(2, header + std::string(kMsg1, kLen1)));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructAckPacket(packet_number++, 2, 1));
  mock_quic_data_.AddReadPause();

  std::string header2 = ConstructDataHeader(kLen2);
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerDataPacket(3, header2 + std::string(kMsg2, kLen2)));
  mock_quic_data_.AddReadPauseForever();

  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(packet_number++,
                                            quic::QUIC_STREAM_CANCELLED, 3, 3));

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  ResumeAndRun();
  AssertSyncReadEquals(kMsg1, kLen1);

  ResumeAndRun();
  AssertSyncReadEquals(kMsg2, kLen2);
}

TEST_P(QuicProxyClientSocketTest, ReadDataMultipleBufferedFrames) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPause();

  std::string header = ConstructDataHeader(kLen1);
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerDataPacket(2, header + std::string(kMsg1, kLen1)));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructAckPacket(packet_number++, 2, 1));
  std::string header2 = ConstructDataHeader(kLen2);
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerDataPacket(3, header2 + std::string(kMsg2, kLen2)));
  mock_quic_data_.AddReadPauseForever();

  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(packet_number++,
                                            quic::QUIC_STREAM_CANCELLED, 3, 3));

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  // The next two reads are consumed and buffered.
  ResumeAndRun();

  AssertSyncReadEquals(kMsg1, kLen1);
  AssertSyncReadEquals(kMsg2, kLen2);
}

TEST_P(QuicProxyClientSocketTest, LargeReadWillMergeDataFromDifferentFrames) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPause();

  std::string header = ConstructDataHeader(kLen3);
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerDataPacket(2, header + std::string(kMsg3, kLen3)));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructAckPacket(packet_number++, 2, 1));
  std::string header2 = ConstructDataHeader(kLen3);
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerDataPacket(3, header2 + std::string(kMsg3, kLen3)));
  mock_quic_data_.AddReadPauseForever();

  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(packet_number++,
                                            quic::QUIC_STREAM_CANCELLED, 3, 3));

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  // The next two reads are consumed and buffered.
  ResumeAndRun();
  // The payload from two data frames, each with kMsg3 will be combined
  // together into a single read().
  AssertSyncReadEquals(kMsg33, kLen33);
}

TEST_P(QuicProxyClientSocketTest, MultipleShortReadsThenMoreRead) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPause();

  std::string header = ConstructDataHeader(kLen1);
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerDataPacket(2, header + std::string(kMsg1, kLen1)));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructAckPacket(packet_number++, 2, 1));

  std::string header2 = ConstructDataHeader(kLen3);
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerDataPacket(3, header2 + std::string(kMsg3, kLen3)));
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerDataPacket(4, header2 + std::string(kMsg3, kLen3)));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructAckPacket(packet_number++, 4, 3));

  std::string header3 = ConstructDataHeader(kLen2);
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerDataPacket(5, header3 + std::string(kMsg2, kLen2)));
  mock_quic_data_.AddReadPauseForever();

  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(packet_number++,
                                            quic::QUIC_STREAM_CANCELLED, 5, 5));

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  // The next 4 reads are consumed and buffered.
  ResumeAndRun();

  AssertSyncReadEquals(kMsg1, kLen1);
  // The payload from two data frames, each with kMsg3 will be combined
  // together into a single read().
  AssertSyncReadEquals(kMsg33, kLen33);
  AssertSyncReadEquals(kMsg2, kLen2);
}

TEST_P(QuicProxyClientSocketTest, ReadWillSplitDataFromLargeFrame) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPause();

  std::string header = ConstructDataHeader(kLen1);
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerDataPacket(2, header + std::string(kMsg1, kLen1)));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructAckPacket(packet_number++, 2, 1));
  std::string header2 = ConstructDataHeader(kLen33);
  mock_quic_data_.AddRead(ASYNC, ConstructServerDataPacket(
                                     3, header2 + std::string(kMsg33, kLen33)));
  mock_quic_data_.AddReadPauseForever();

  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(packet_number++,
                                            quic::QUIC_STREAM_CANCELLED, 3, 3));

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  // The next 2 reads are consumed and buffered.
  ResumeAndRun();

  AssertSyncReadEquals(kMsg1, kLen1);
  // The payload from the single large data frame will be read across
  // two different reads.
  AssertSyncReadEquals(kMsg3, kLen3);
  AssertSyncReadEquals(kMsg3, kLen3);
}

TEST_P(QuicProxyClientSocketTest, MultipleReadsFromSameLargeFrame) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(ASYNC, ConstructServerConnectReplyPacket(1, !kFin));
  mock_quic_data_.AddReadPause();

  std::string header = ConstructDataHeader(kLen333);
  mock_quic_data_.AddRead(
      ASYNC,
      ConstructServerDataPacket(2, header + std::string(kMsg333, kLen333)));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructAckPacket(packet_number++, 2, 1));
  mock_quic_data_.AddReadPauseForever();

  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      ConstructRstPacket(packet_number++, quic::QUIC_STREAM_CANCELLED));

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  // The next read is consumed and buffered.
  ResumeAndRun();

  // The payload from the single large data frame will be read across
  // two different reads.
  AssertSyncReadEquals(kMsg33, kLen33);

  // Now attempt to do a read of more data than remains buffered
  auto buf = base::MakeRefCounted<IOBufferWithSize>(kLen33);
  ASSERT_EQ(kLen3, sock_->Read(buf.get(), kLen33, CompletionOnceCallback()));
  ASSERT_EQ(std::string(kMsg3, kLen3), std::string(buf->data(), kLen3));
  ASSERT_TRUE(sock_->IsConnected());
}
```