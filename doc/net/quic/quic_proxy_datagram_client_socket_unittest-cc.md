Response:
The user wants to understand the functionality of the `quic_proxy_datagram_client_socket_unittest.cc` file in Chromium's network stack. I need to analyze the C++ code and extract its purpose.

Here's a breakdown of the thought process:

1. **Identify the core component:** The filename itself (`quic_proxy_datagram_client_socket_unittest.cc`) clearly indicates that this file contains unit tests for the `QuicProxyDatagramClientSocket` class.

2. **Understand unit testing:** Unit tests are designed to verify the behavior of individual units of code (in this case, the `QuicProxyDatagramClientSocket` class) in isolation. This means the tests will simulate various scenarios and check if the class behaves as expected.

3. **Analyze the test structure:**  The code uses the Google Test framework (`TEST_P`, `EXPECT_TRUE`, `ASSERT_EQ`, etc.). Each `TEST_P` defines a specific test case. I need to understand what each test case is trying to verify.

4. **Examine the setup (`QuicProxyDatagramClientSocketTest` class):** This class sets up the test environment. Key aspects include:
    * `QuicProxyClientSocketTestBase`: This base class likely provides common setup and helper functions for testing QUIC proxy client sockets.
    * `InitializeClientSocket()`:  This method instantiates the `QuicProxyDatagramClientSocket` being tested.
    * Mocking (`mock_quic_data_`): The tests use a mock QUIC data object to simulate network traffic (sending and receiving packets).
    * Helper functions (`ConstructSettingsPacket`, `ConstructConnectRequestPacket`, etc.): These functions are used to create realistic QUIC packets for testing.

5. **Analyze individual test cases:** For each `TEST_P`, I need to determine:
    * What scenario is being simulated?
    * What input is being provided (e.g., specific packets)?
    * What output or behavior is being asserted (e.g., a connection succeeds, a specific error is returned, data is sent correctly)?

6. **Look for connections to JavaScript:**  `QuicProxyDatagramClientSocket` deals with network communication at a low level. JavaScript in a browser uses higher-level APIs (like `fetch` or WebSockets). The connection here is likely indirect: JavaScript initiates network requests, which might eventually use this socket under the hood. I need to find a relevant example.

7. **Identify potential user/programmer errors:**  Based on the tested scenarios (e.g., writing on a closed socket), I can infer common mistakes developers might make when using this class.

8. **Trace user operations:**  Consider how a user action in a browser might lead to the execution of this code. It's likely part of a process for establishing a QUIC connection through a proxy.

9. **Consider logical inference (if any):**  While the tests primarily verify explicit behavior, some tests might imply logical deductions (e.g., how the socket handles specific error conditions). I need to be careful not to over-interpret.

10. **Structure the answer:** Organize the findings into clear sections: functionality, relation to JavaScript, logical inference (with assumptions), common errors, and debugging steps.

**Pre-computation/Pre-analysis (Example for one test case):**

Let's take `TEST_P(QuicProxyDatagramClientSocketTest, ConnectSendsCorrectRequest)`:

* **Goal:** Verify that when the `ConnectViaStream` method is called, the socket sends the correct CONNECT request to the proxy.
* **Input:** The test sets up `mock_quic_data_` to expect specific write operations (settings and connect request packets) and to return a successful connect reply.
* **Expected Output:** `AssertConnectSucceeds()` should pass, and the response headers should indicate a successful connection (HTTP 200).
* **Inference:**  The test verifies the correct construction of the initial CONNECT request, including headers like `:scheme`, `:path`, `:method`, and `:authority`.

By repeating this analysis for each test case, I can build a comprehensive understanding of the file's functionality. I'll need to be careful to distinguish between what's explicitly tested and what can be logically inferred.
这个文件 `net/quic/quic_proxy_datagram_client_socket_unittest.cc` 是 Chromium 网络栈中用于测试 `QuicProxyDatagramClientSocket` 类的单元测试文件。它的主要功能是验证 `QuicProxyDatagramClientSocket` 类的各种行为和功能是否符合预期。

以下是它的一些关键功能点：

**核心功能：**

1. **测试连接建立:** 验证客户端是否能正确地通过 QUIC 代理服务器建立连接，包括发送正确的 CONNECT 请求，处理代理服务器的响应（成功或失败）。
2. **测试请求头的正确性:**  验证发送到代理服务器的 CONNECT 请求是否包含了正确的头部信息，例如 `:scheme`, `:path`, `:method`, `:authority`, `user-agent`, `capsule-protocol` 等。
3. **测试 `ProxyDelegate` 的交互:**  测试 `QuicProxyDatagramClientSocket` 如何与 `ProxyDelegate` 交互，包括传递额外的请求头，接收并处理代理服务器的响应头信息。
4. **测试数据发送 (Write):** 验证客户端是否能通过代理服务器发送数据报，包括正确地封装数据报内容。
5. **测试数据接收 (Read):** 验证客户端是否能正确地接收来自代理服务器的数据报。
6. **测试连接关闭:** 验证在连接关闭的情况下，尝试读写操作会返回正确的错误。
7. **测试 HTTP/3 Datagram 的处理:** 验证当收到 HTTP/3 Datagram 时，数据报是否被正确地添加到接收队列中。
8. **测试数据报队列管理:** 验证数据报接收队列的上限，以及当队列满时新接收到的数据报是否会被丢弃。

**与 JavaScript 的关系：**

`QuicProxyDatagramClientSocket` 本身是一个底层的网络组件，JavaScript 代码通常不会直接操作它。但是，当浏览器中的 JavaScript 代码发起需要通过代理服务器的连接，并且底层使用了 QUIC 协议时，`QuicProxyDatagramClientSocket` 就有可能被使用。

**举例说明：**

假设一个网页上的 JavaScript 代码使用 `fetch` API 发起一个 HTTPS 请求，并且浏览器配置了使用一个 QUIC 代理服务器。

```javascript
fetch('https://example.com', {
  mode: 'no-cors' // 简化示例，避免 CORS 相关问题
}).then(response => {
  console.log('请求成功:', response);
}).catch(error => {
  console.error('请求失败:', error);
});
```

在这个场景下，当浏览器尝试建立到 `example.com` 的连接时，如果确定需要通过配置的 QUIC 代理服务器，并且协商使用了 HTTP/3，那么 Chromium 的网络栈可能会创建并使用 `QuicProxyDatagramClientSocket` 来与代理服务器建立连接，并最终通过这个连接转发 `fetch` 请求的数据。

**逻辑推理（假设输入与输出）：**

**场景：测试成功的连接建立**

* **假设输入：**
    * 代理服务器地址和端口已知。
    * 目标服务器地址和端口已知。
    * Mock 的 QUIC 会话模拟了成功的握手和设置交换。
    * Mock 的 QUIC 数据模拟了代理服务器返回了 200 OK 的 CONNECT 响应。
* **预期输出：**
    * `sock_->ConnectViaStream()` 方法返回 `OK`。
    * `sock_->IsConnected()` 返回 `true`。
    * `sock_->GetConnectResponseInfo()` 返回的 `HttpResponseInfo` 中 `response->headers->response_code()` 为 200。

**场景：测试发送数据**

* **假设输入：**
    * 已经成功建立到代理服务器的连接。
    * 要发送的数据内容为 `kMsg1` 和 `kMsg2`。
* **预期输出：**
    * `sock_->Write()` 方法成功将数据写入底层 QUIC 连接。
    * Mock 的 QUIC 数据中会记录发送了包含 `kMsg1` 和 `kMsg2` 内容的 QUIC 数据包。

**用户或编程常见的使用错误（举例说明）：**

1. **在未连接状态下尝试发送数据:**  用户可能在调用 `ConnectViaStream` 且连接未建立完成之前就尝试调用 `Write` 发送数据。
   * **测试代码体现:** `TEST_P(QuicProxyDatagramClientSocketTest, WriteOnClosedSocket)` 模拟了在连接已关闭的情况下尝试写入，预期返回 `ERR_SOCKET_NOT_CONNECTED`。
   * **用户操作:**  用户代码逻辑错误，例如在异步连接回调之前就尝试发送数据。

2. **读取过多的数据:** 用户可能尝试读取比接收缓冲区中实际存在的数据更多的数据。虽然 QUIC 有流量控制，但在应用层，读取操作仍然需要正确处理返回的字节数。
   * **测试代码体现:** 尽管此文件没有直接测试读取过多的情况，但它测试了基本的读取操作，可以作为理解读取行为的基础。
   * **用户操作:**  用户提供的缓冲区大小超过了实际接收到的数据量。

**用户操作如何一步步的到达这里（作为调试线索）：**

1. **用户在浏览器中输入一个 HTTPS 网址，或者点击一个 HTTPS 链接。**
2. **浏览器解析 URL，确定需要建立到目标服务器的连接。**
3. **如果浏览器配置了使用代理服务器，并且确定可以使用 QUIC 协议连接到该代理服务器。**
4. **网络栈会创建一个 `QuicProxyClientSocket` (可能是 `QuicProxyDatagramClientSocket` 的基类或相关类)。**
5. **`QuicProxyDatagramClientSocket` 被创建出来，负责处理与 QUIC 代理服务器的连接和数据传输。**
6. **调用 `QuicProxyDatagramClientSocket` 的 `ConnectViaStream` 方法尝试建立连接。**
7. **如果连接成功，用户后续在页面上的操作（例如发送表单，加载更多内容）可能会导致调用 `QuicProxyDatagramClientSocket` 的 `Write` 方法发送数据。**
8. **代理服务器返回的数据会通过 `QuicProxyDatagramClientSocket` 的回调函数（例如 `OnHttp3Datagram`）接收，并放入接收队列中。**
9. **用户代码调用 `Read` 方法从套接字读取数据。**

**调试线索:**

* 如果用户报告无法通过代理服务器访问某个 HTTPS 网站，或者速度很慢，可以检查是否使用了 QUIC 协议。
* 可以通过 Chrome 的 `chrome://net-internals/#quic` 页面查看 QUIC 连接的详细信息，包括是否使用了代理，连接状态，以及收发的数据包。
* 可以使用网络抓包工具（如 Wireshark）捕获网络数据包，分析 QUIC 连接的建立过程和数据传输情况。
* 单元测试文件本身可以作为理解 `QuicProxyDatagramClientSocket` 工作原理的重要参考，特别是在排查网络连接问题时。可以通过阅读测试用例来了解各种场景下的预期行为，从而更好地定位问题。

### 提示词
```
这是目录为net/quic/quic_proxy_datagram_client_socket_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_proxy_datagram_client_socket.h"

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
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_spdy_session_peer.h"
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

namespace {

constexpr char kTestHeaderName[] = "Foo";

}  // anonymous namespace

class EstablishedCryptoStream : public quic::test::MockQuicCryptoStream {
 public:
  using quic::test::MockQuicCryptoStream::MockQuicCryptoStream;

  bool encryption_established() const override { return true; }
};

class QuicProxyDatagramClientSocketTest : public QuicProxyClientSocketTestBase {
 public:
  void TearDown() override {
    sock_.reset();
    EXPECT_TRUE(mock_quic_data_.AllReadDataConsumed());
    EXPECT_TRUE(mock_quic_data_.AllWriteDataConsumed());
  }

  void InitializeClientSocket() override {
    sock_ = std::make_unique<QuicProxyDatagramClientSocket>(
        destination_endpoint_.GetURL(), proxy_chain_, user_agent_,
        NetLogWithSource::Make(NetLogSourceType::NONE), proxy_delegate_.get());
    session_->StartReading();
  }

  void PopulateConnectRequestIR(
      quiche::HttpHeaderBlock* block,
      std::optional<const HttpRequestHeaders> extra_headers) override {
    DCHECK(destination_endpoint_.scheme() == url::kHttpsScheme);

    std::string host = destination_endpoint_.host();
    uint16_t port = destination_endpoint_.port();

    (*block)[":scheme"] = destination_endpoint_.scheme();
    (*block)[":path"] = "/";
    (*block)[":protocol"] = "connect-udp";
    (*block)[":method"] = "CONNECT";
    // Port is removed if 443 since that is the default port number for HTTPS.
    (*block)[":authority"] =
        port != 443 ? base::StrCat({host, ":", base::NumberToString(port)})
                    : host;
    if (extra_headers) {
      HttpRequestHeaders::Iterator it(*extra_headers);
      while (it.GetNext()) {
        std::string name = base::ToLowerASCII(it.name());
        (*block)[name] = it.value();
      }
    }
    (*block)["user-agent"] = kUserAgent;
    (*block)["capsule-protocol"] = "?1";
  }

  void AssertConnectSucceeds() override {
    TestCompletionCallback callback;
    ASSERT_THAT(
        sock_->ConnectViaStream(local_addr_, peer_addr_,
                                std::move(stream_handle_), callback.callback()),
        IsError(ERR_IO_PENDING));
    ASSERT_THAT(callback.WaitForResult(), IsOk());
  }

  void AssertConnectFails(int result) override {
    TestCompletionCallback callback;
    ASSERT_THAT(
        sock_->ConnectViaStream(local_addr_, peer_addr_,
                                std::move(stream_handle_), callback.callback()),
        IsError(ERR_IO_PENDING));
    ASSERT_EQ(result, callback.WaitForResult());
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
    ASSERT_EQ(len, sock_->Read(buf.get(), len, CompletionOnceCallback()));
    ASSERT_EQ(std::string(data, len), std::string(buf->data(), len));
    ASSERT_TRUE(sock_->IsConnected());
  }

  void AssertAsyncReadEquals(const char* data, int len) override {
    CHECK(false);
  }

  void AssertReadStarts(const char* data, int len) override {
    read_buf_ = base::MakeRefCounted<IOBufferWithSize>(len);
    ASSERT_EQ(ERR_IO_PENDING,
              sock_->Read(read_buf_.get(), len, read_callback_.callback()));
    EXPECT_TRUE(sock_->IsConnected());
  }

  void AssertReadReturns(const char* data, int len) override {
    EXPECT_TRUE(sock_->IsConnected());

    // Now the read will return.
    EXPECT_EQ(len, read_callback_.WaitForResult());
    ASSERT_EQ(std::string(data, len), std::string(read_buf_->data(), len));
  }

 protected:
  std::unique_ptr<QuicProxyDatagramClientSocket> sock_;
};

TEST_P(QuicProxyDatagramClientSocketTest, ConnectSendsCorrectRequest) {
  int packet_number = 1;

  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerConnectReplyPacket(/*packet_number=*/1, !kFin));
  mock_quic_data_.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(
                       packet_number++, quic::QUIC_STREAM_CANCELLED,
                       /*largest_received=*/1, /*smallest_received=*/1));

  InitializeSession();
  InitializeClientSocket();

  ASSERT_FALSE(sock_->IsConnected());

  AssertConnectSucceeds();

  const HttpResponseInfo* response = sock_->GetConnectResponseInfo();
  ASSERT_TRUE(response != nullptr);
  ASSERT_EQ(200, response->headers->response_code());
}

TEST_P(QuicProxyDatagramClientSocketTest, ProxyDelegateHeaders) {
  proxy_delegate_ = std::make_unique<TestProxyDelegate>();
  proxy_delegate_->set_extra_header_name(kTestHeaderName);

  // TestProxyDelegate sets the header value to the proxy server URI.
  HttpRequestHeaders extra_expected_headers;
  extra_expected_headers.SetHeader(kTestHeaderName,
                                   ProxyServerToProxyUri(proxy_chain_.Last()));

  // Include a header in the response that the ProxyDelegate should see.
  const char kResponseHeaderName[] = "bar";
  const char kResponseHeaderValue[] = "testing";
  HttpRequestHeaders response_headers;
  response_headers.SetHeader(kResponseHeaderName, kResponseHeaderValue);

  int packet_number = 1;

  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      ConstructConnectRequestPacket(packet_number++, extra_expected_headers));
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerConnectReplyPacket(
                 /*packet_number=*/1, !kFin, /*header_length=*/nullptr,
                 response_headers));
  mock_quic_data_.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(
                       packet_number++, quic::QUIC_STREAM_CANCELLED,
                       /*largest_received=*/1, /*smallest_received=*/1));

  InitializeSession();
  InitializeClientSocket();

  ASSERT_FALSE(sock_->IsConnected());

  AssertConnectSucceeds();

  const HttpResponseInfo* response = sock_->GetConnectResponseInfo();
  ASSERT_TRUE(response != nullptr);
  ASSERT_EQ(200, response->headers->response_code());

  proxy_delegate_->VerifyOnTunnelHeadersReceived(
      proxy_chain_, /*chain_index=*/0, kResponseHeaderName,
      kResponseHeaderValue);
}

TEST_P(QuicProxyDatagramClientSocketTest, ProxyDelegateFails) {
  proxy_delegate_ = std::make_unique<TestProxyDelegate>();
  proxy_delegate_->MakeOnTunnelHeadersReceivedFail(
      ERR_TUNNEL_CONNECTION_FAILED);

  int packet_number = 1;

  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerConnectReplyPacket(/*packet_number=*/1, !kFin));
  mock_quic_data_.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(
                       packet_number++, quic::QUIC_STREAM_CANCELLED,
                       /*largest_received=*/1, /*smallest_received=*/1));

  InitializeSession();
  InitializeClientSocket();

  ASSERT_FALSE(sock_->IsConnected());

  AssertConnectFails(ERR_TUNNEL_CONNECTION_FAILED);
}

TEST_P(QuicProxyDatagramClientSocketTest, ConnectFails) {
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

TEST_P(QuicProxyDatagramClientSocketTest, WriteSendsData) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerConnectReplyPacket(/*packet_number=*/1, !kFin));
  mock_quic_data_.AddReadPauseForever();

  std::string quarter_stream_id(1, '\0');
  std::string context_id(1, '\0');

  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      ConstructAckAndDatagramPacket(
          packet_number++, /*largest_received=*/1, /*smallest_received=*/1,
          {quarter_stream_id + context_id + std::string(kMsg1, kLen1)}));
  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      ConstructDatagramPacket(packet_number++, {quarter_stream_id + context_id +
                                                std::string(kMsg2, kLen2)}));
  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      ConstructRstPacket(packet_number++, quic::QUIC_STREAM_CANCELLED));

  InitializeSession();

  quic::test::QuicSpdySessionPeer::SetHttpDatagramSupport(
      session_.get(), quic::HttpDatagramSupport::kRfc);

  InitializeClientSocket();

  AssertConnectSucceeds();

  AssertSyncWriteSucceeds(kMsg1, kLen1);
  AssertSyncWriteSucceeds(kMsg2, kLen2);
}

TEST_P(QuicProxyDatagramClientSocketTest, WriteOnClosedSocket) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerConnectReplyPacket(/*packet_number=*/1, !kFin));
  mock_quic_data_.AddReadPauseForever();
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(
                       packet_number++, quic::QUIC_STREAM_CANCELLED,
                       /*largest_received=*/1, /*smallest_received=*/1));

  InitializeSession();
  InitializeClientSocket();

  AssertConnectSucceeds();

  sock_->Close();

  AssertWriteReturns(kMsg1, kLen1, ERR_SOCKET_NOT_CONNECTED);
}

TEST_P(QuicProxyDatagramClientSocketTest, OnHttp3DatagramAddsDatagram) {
  int packet_number = 1;

  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerConnectReplyPacket(/*packet_number=*/1, !kFin));
  mock_quic_data_.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(
                       packet_number++, quic::QUIC_STREAM_CANCELLED,
                       /*largest_received=*/1, /*smallest_received=*/1));

  InitializeSession();

  quic::test::QuicSpdySessionPeer::SetHttpDatagramSupport(
      session_.get(), quic::HttpDatagramSupport::kRfc);

  InitializeClientSocket();

  AssertConnectSucceeds();

  sock_->OnHttp3Datagram(0, std::string(1, '\0') /* context_id */ +
                                std::string(kDatagramPayload, kDatagramLen));

  ASSERT_TRUE(!sock_->GetDatagramsForTesting().empty());
  ASSERT_EQ(sock_->GetDatagramsForTesting().front(), "youveGotMail");

  histogram_tester_.ExpectUniqueSample(
      QuicProxyDatagramClientSocket::kMaxQueueSizeHistogram, false, 1);
}

TEST_P(QuicProxyDatagramClientSocketTest, ReadReadsDataInQueue) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerConnectReplyPacket(/*packet_number=*/1, !kFin));
  mock_quic_data_.AddReadPause();

  mock_quic_data_.AddRead(
      ASYNC, ConstructServerDatagramPacket(
                 2, std::string(1, '\0') /* quarter_stream_id */ +
                        std::string(1, '\0') /* context_id */ +
                        std::string(kDatagramPayload,
                                    kDatagramLen)  // Actual message payload
                 ));
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckPacket(packet_number++, /*largest_received=*/2,
                                      /*smallest_received=*/1));
  mock_quic_data_.AddReadPauseForever();
  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      ConstructRstPacket(packet_number++, quic::QUIC_STREAM_CANCELLED));

  InitializeSession();

  quic::test::QuicSpdySessionPeer::SetHttpDatagramSupport(
      session_.get(), quic::HttpDatagramSupport::kRfc);

  InitializeClientSocket();

  AssertConnectSucceeds();

  ResumeAndRun();
  AssertSyncReadEquals(kDatagramPayload, kDatagramLen);

  histogram_tester_.ExpectUniqueSample(
      QuicProxyDatagramClientSocket::kMaxQueueSizeHistogram, false, 1);
}

TEST_P(QuicProxyDatagramClientSocketTest, AsyncReadWhenQueueIsEmpty) {
  int packet_number = 1;
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerConnectReplyPacket(/*packet_number=*/1, !kFin));
  mock_quic_data_.AddReadPause();

  mock_quic_data_.AddRead(
      ASYNC, ConstructServerDatagramPacket(
                 2, std::string(1, '\0') /* quarter_stream_id */ +
                        std::string(1, '\0') /* context_id */ +
                        std::string(kDatagramPayload,
                                    kDatagramLen)  // Actual message payload
                 ));
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckPacket(packet_number++, /*largest_received=*/2,
                                      /*smallest_received=*/1));
  mock_quic_data_.AddReadPauseForever();
  mock_quic_data_.AddWrite(
      SYNCHRONOUS,
      ConstructRstPacket(packet_number++, quic::QUIC_STREAM_CANCELLED));

  InitializeSession();

  quic::test::QuicSpdySessionPeer::SetHttpDatagramSupport(
      session_.get(), quic::HttpDatagramSupport::kRfc);

  InitializeClientSocket();

  AssertConnectSucceeds();

  AssertReadStarts(kDatagramPayload, kDatagramLen);

  ResumeAndRun();

  EXPECT_TRUE(read_callback_.have_result());
  AssertReadReturns(kDatagramPayload, kDatagramLen);
}

TEST_P(QuicProxyDatagramClientSocketTest,
       MaxQueueLimitDiscardsIncomingDatagram) {
  int packet_number = 1;

  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructSettingsPacket(packet_number++));
  mock_quic_data_.AddWrite(SYNCHRONOUS,
                           ConstructConnectRequestPacket(packet_number++));
  mock_quic_data_.AddRead(
      ASYNC, ConstructServerConnectReplyPacket(/*packet_number=*/1, !kFin));
  mock_quic_data_.AddRead(SYNCHRONOUS, ERR_IO_PENDING);
  mock_quic_data_.AddWrite(
      SYNCHRONOUS, ConstructAckAndRstPacket(
                       packet_number++, quic::QUIC_STREAM_CANCELLED,
                       /*largest_received=*/1, /*smallest_received=*/1));

  InitializeSession();

  quic::test::QuicSpdySessionPeer::SetHttpDatagramSupport(
      session_.get(), quic::HttpDatagramSupport::kRfc);

  InitializeClientSocket();

  AssertConnectSucceeds();

  for (size_t i = 0;
       i < QuicProxyDatagramClientSocket::kMaxDatagramQueueSize + 1; i++) {
    sock_->OnHttp3Datagram(0, std::string(1, '\0') /* context_id */ +
                                  std::string(kDatagramPayload, kDatagramLen));
  }

  ASSERT_TRUE(sock_->GetDatagramsForTesting().size() ==
              QuicProxyDatagramClientSocket::kMaxDatagramQueueSize);

  histogram_tester_.ExpectTotalCount(
      QuicProxyDatagramClientSocket::kMaxQueueSizeHistogram,
      QuicProxyDatagramClientSocket::kMaxDatagramQueueSize + 1);
  histogram_tester_.ExpectBucketCount(
      QuicProxyDatagramClientSocket::kMaxQueueSizeHistogram, false,
      QuicProxyDatagramClientSocket::kMaxDatagramQueueSize);
  histogram_tester_.ExpectBucketCount(
      QuicProxyDatagramClientSocket::kMaxQueueSizeHistogram, true, 1);
}

INSTANTIATE_TEST_SUITE_P(VersionIncludeStreamDependencySequence,
                         QuicProxyDatagramClientSocketTest,
                         ::testing::ValuesIn(AllSupportedQuicVersions()),
                         ::testing::PrintToStringParamName());

}  // namespace net::test
```