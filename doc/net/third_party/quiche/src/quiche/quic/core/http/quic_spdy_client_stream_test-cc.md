Response:
Let's break down the thought process for analyzing the C++ test file.

**1. Initial Understanding - What is this?**

The filename `quic_spdy_client_stream_test.cc` immediately tells us a few crucial things:

* **`quic`:** This is related to the QUIC protocol.
* **`spdy`:**  This suggests it's dealing with an older version of HTTP over QUIC (HTTP/2 semantics). Even though HTTP/3 is mentioned in the code, the core structure and naming are rooted in SPDY.
* **`client`:** This focuses on the client-side implementation of QUIC.
* **`stream`:** This points to testing the behavior of individual QUIC streams used for HTTP communication.
* **`test`:** This is clearly a unit test file. The presence of `TEST_P`, `INSTANTIATE_TEST_SUITE_P`, and `Mock...` classes strongly indicate this.

**2. Core Functionality Identification (High-Level):**

The primary goal of this test file is to verify the correct behavior of the `QuicSpdyClientStream` class. This involves:

* **Receiving and parsing HTTP response headers.**  This includes status codes, common headers, and handling of informational responses (1xx).
* **Receiving and processing HTTP response body data.**
* **Handling various error conditions:**  Invalid status codes, missing status codes, invalid headers, extra data.
* **Dealing with trailers (HTTP/2).**
* **Handling HTTP/3 Capsules (Datagrams and unknown types).**

**3. Detailed Analysis - Examining the Code:**

Now, let's go through the code snippets and classes:

* **Includes:**  The includes provide valuable context. We see includes for:
    * Core QUIC concepts (`quic_error_codes.h`, `quic_utils.h`)
    * HTTP-specific QUIC classes (`quic_spdy_client_session.h`, `spdy_utils.h`)
    * Testing frameworks (`quic_test.h`, `gmock`)
    * Utility classes (`absl/strings/str_cat.h`)

* **`MockQuicSpdyClientSession`:**  This is a mock object used to control the behavior of the session the stream is associated with. The `MOCK_METHOD` macro indicates it's used to set up expectations and verify calls to the session. Crucially, `WriteControlFrame` being mocked suggests testing how the stream triggers session-level actions in error scenarios.

* **`QuicSpdyClientStreamTest`:** This is the main test fixture. Key aspects:
    * **Parameterized Testing (`QuicTestWithParam`):** The `INSTANTIATE_TEST_SUITE_P` line shows that the tests are run against different QUIC versions.
    * **Mocking Core Components:**  `MockQuicConnectionHelper`, `MockAlarmFactory`, and `MockQuicConnection` are used to isolate the stream under test.
    * **Creating a `QuicSpdyClientStream` Instance:**  The setup creates a stream and attaches it to the mock session.
    * **Setting up Initial Conditions:**  Headers and body are initialized for testing.
    * **`StreamVisitor`:**  A simple visitor to observe stream closure.

* **Individual `TEST_P` Cases:**  Each test case focuses on a specific aspect of the stream's functionality. Analyzing each test name provides insights:
    * `TestReceivingIllegalResponseStatusCode`:  Tests handling of bad status codes.
    * `InvalidResponseHeader`, `MissingStatusCode`: Test header validation.
    * `TestFraming`: Basic successful response processing.
    * `HostAllowedInResponseHeader`:  Checks if certain headers are permitted.
    * `Test100ContinueBeforeSuccessful`, `TestUnknownInformationalBeforeSuccessful`, `TestMultipleInformationalBeforeSuccessful`: Test handling of 1xx informational responses.
    * `TestReceiving101`: Checks rejection of the 101 status code.
    * `TestFramingOnePacket`:  Simple data reception.
    * `TestFramingExtraData`: Tests handling of more data than expected.
    * `ReceivingTrailers`: Tests processing of trailing headers (HTTP/2).
    * `Capsules`, `CapsulesOnUnsuccessfulResponse`: Test handling of HTTP/3 capsules (datagrams and unknown types).

**4. Identifying Relationships to JavaScript:**

The connection to JavaScript comes primarily through the browser's use of the network stack. The browser (often with a JavaScript engine) uses the Chromium network stack (where this code resides) to make HTTP requests.

**5. Inferring User Actions and Debugging:**

By understanding the test cases and the stream's functionality, we can infer user actions that might lead to this code being executed and how to debug issues.

**6. Structuring the Answer:**

Finally, the information needs to be organized logically, covering the requested points: functionality, JavaScript relationship, logical reasoning (input/output), common errors, and debugging. Using clear headings and bullet points makes the answer easier to understand.

**Self-Correction/Refinement during the process:**

* Initially, I might have overemphasized the "SPDY" part of the name. However, noticing the mention of HTTP/3 and the capsule tests corrects this. It's crucial to understand that even though the class name has "Spdy," it handles both HTTP/2 (SPDY-like framing) and HTTP/3.
* When considering JavaScript, I might have initially focused on low-level networking APIs. Realizing the primary interaction is through standard browser APIs for making HTTP requests simplifies the explanation.
* For logical reasoning, it's important to choose concrete examples related to the test cases, rather than abstract scenarios.

By following this structured analysis, we can comprehensively understand the purpose and context of the given C++ test file.
这个文件 `net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_client_stream_test.cc` 是 Chromium 网络栈中用于测试 `QuicSpdyClientStream` 类的单元测试文件。`QuicSpdyClientStream` 负责处理客户端发起的 HTTP/2 或 HTTP/3 请求和接收服务器的响应。

以下是该文件的功能列表：

**主要功能：**

1. **测试 HTTP 响应头解析：**
   - 验证 `QuicSpdyClientStream` 是否能正确解析服务器返回的 HTTP 响应头，包括状态码、Content-Length 等。
   - 测试对于非法响应头的处理，例如非法的状态码格式、缺少必要的头部等。
   - 测试对 1xx 状态码（Informational）的处理，例如 100 Continue。
   - 验证对禁止的头部（例如 HTTP/3 中的 101 Switching Protocols）的处理。

2. **测试 HTTP 响应体解析：**
   - 验证 `QuicSpdyClientStream` 是否能正确接收和存储服务器返回的 HTTP 响应体数据。
   - 测试在接收到完整响应体后的数据状态。
   - 测试接收到超出 Content-Length 指示的数据时的处理（错误处理）。

3. **测试 HTTP/2 Trailers (尾部)：**
   - 验证 `QuicSpdyClientStream` 在 HTTP/2 中是否能正确处理尾部，包括包含 final-offset 的情况。

4. **测试 HTTP/3 Capsules：**
   - 验证 `QuicSpdyClientStream` 在 HTTP/3 中是否能正确处理 Capsules，包括：
     - HTTP Datagrams：用于发送无序、不可靠的用户数据。
     - Unknown Capsules：处理未知类型的 Capsules。
   - 测试在非成功响应中接收到 Capsules 的处理（应该被忽略）。

5. **错误处理测试：**
   - 验证 `QuicSpdyClientStream` 在遇到各种错误情况时是否能正确触发连接或流级别的错误。
   - 测试对违反 HTTP/2 或 HTTP/3 协议的行为的处理。

**与 JavaScript 的关系及举例说明：**

该文件测试的是网络栈的底层实现，与 JavaScript 没有直接的代码级别的交互。然而，它所测试的功能是浏览器中 JavaScript 发起的网络请求的基础。

当 JavaScript 代码（例如在网页中通过 `fetch` API 或 `XMLHttpRequest`）发起一个 HTTP 请求时，浏览器会使用底层的网络栈来处理这个请求。`QuicSpdyClientStream` 就是在这个过程中负责处理基于 QUIC 协议的 HTTP/2 或 HTTP/3 连接中的单个请求和响应的组件。

**举例说明：**

假设 JavaScript 代码发起了一个简单的 GET 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

当这个请求通过 QUIC 协议发送到服务器时，Chromium 的网络栈会创建一个 `QuicSpdyClientStream` 实例来处理这个请求。`quic_spdy_client_stream_test.cc` 中的测试用例会模拟服务器返回各种类型的响应，例如：

* **成功的 JSON 响应：** 测试 `TestFraming` 就模拟了这种情况，验证 `QuicSpdyClientStream` 能正确解析包含 JSON 数据的响应体。
* **返回 404 错误：**  相关的测试会验证 `QuicSpdyClientStream` 能正确解析状态码为 404 的响应头。
* **服务器发送 100 Continue：** `Test100ContinueBeforeSuccessful` 模拟了服务器先发送 100 Continue，然后再发送最终响应的情况，确保客户端能正确处理。
* **服务器使用了 HTTP/3 Datagrams 发送一些额外信息：** `Capsules` 测试模拟了这种情况，验证客户端能否正确提取 Datagrams 中的数据。

**逻辑推理 (假设输入与输出)：**

**假设输入 (以 `TestReceivingIllegalResponseStatusCode` 为例)：**

* **模拟的服务器响应头:** `:status: 200 ok\r\ncontent-length: 11\r\n\r\n`  (注意状态码 "200 ok" 中间有空格，这是非法的)

**预期输出:**

* `QuicSpdyClientStream` 会检测到非法的状态码格式。
* 会调用 `session_.WriteControlFrame` 发送一个错误帧（取决于具体实现）。
* 会调用 `connection_->OnStreamReset` 告知连接端点该流遇到了 `QUIC_BAD_APPLICATION_PAYLOAD` 错误。
* `stream_->stream_error()` 将返回 `QUIC_BAD_APPLICATION_PAYLOAD`。
* `stream_->ietf_application_error()` 将返回 `QuicHttp3ErrorCode::GENERAL_PROTOCOL_ERROR` (如果使用的是 HTTP/3)。

**涉及用户或编程常见的使用错误及举例说明：**

虽然这个测试文件主要关注底层实现，但它所测试的功能与用户或编程错误密切相关。

1. **服务器返回错误的 HTTP 响应格式：**
   - **错误示例：** 服务器错误地返回了 `HTTP/1.1 200 OK\nContent-Length: 10\n...` 这样的格式，而不是符合 HTTP/2 或 HTTP/3 的格式。
   - **测试覆盖：**  `TestReceivingIllegalResponseStatusCode`, `InvalidResponseHeader`, `MissingStatusCode` 等测试用例覆盖了这类错误。

2. **服务器发送了超出声明长度的数据：**
   - **错误示例：** 服务器在 `Content-Length` 中声明了 10 字节，但实际发送了 15 字节的数据。
   - **测试覆盖：** `QUIC_TEST_DISABLED_IN_CHROME(TestFramingExtraData)` 测试用例覆盖了这种情况，验证客户端是否能正确检测到并处理。

3. **HTTP/3 服务器错误地发送了 101 状态码：**
   - **错误示例：**  一个本应使用其他机制（例如 WebSocket Upgrade）的场景，服务器错误地返回了 101 Switching Protocols。
   - **测试覆盖：** `TestReceiving101` 测试用例确保客户端会拒绝这种状态码。

**用户操作如何一步步到达这里，作为调试线索：**

假设用户在使用 Chrome 浏览器访问一个网站时遇到了网络问题，并且你作为开发者需要调试这个问题。以下是一个可能的路径：

1. **用户在浏览器地址栏输入 URL 并回车，或者点击一个链接。**
2. **浏览器发起一个网络请求。** 如果网站支持 QUIC 并且浏览器启用了 QUIC，则会尝试使用 QUIC 建立连接。
3. **QUIC 连接建立后，浏览器（QUIC 客户端）会创建一个 `QuicSpdyClientSession` 来管理与服务器的会话。**
4. **对于每个 HTTP 请求，`QuicSpdyClientSession` 会创建一个 `QuicSpdyClientStream` 实例来处理该请求和响应。**
5. **如果服务器的响应存在问题（例如格式错误），`QuicSpdyClientStream` 在解析响应头或响应体时会遇到错误。**
6. **这时，`quic_spdy_client_stream_test.cc` 中测试的逻辑就会被触发。** 例如，如果服务器返回了非法的状态码，`QuicSpdyClientStream::OnStreamHeaderList` 方法会检测到这个错误，并执行相应的错误处理逻辑，就像 `TestReceivingIllegalResponseStatusCode` 测试所模拟的那样。
7. **作为调试线索，如果用户报告了页面加载错误，或者在开发者工具的网络面板中看到了连接被重置或请求失败的信息，你可能会怀疑是 HTTP 响应解析出现了问题。** 进一步查看 QUIC 相关的日志或使用网络抓包工具，可能会看到与 `QUIC_BAD_APPLICATION_PAYLOAD` 或其他 HTTP/2/3 错误码相关的错误信息，从而引导你查看 `QuicSpdyClientStream` 的实现和相关的测试用例，例如 `quic_spdy_client_stream_test.cc`。

总而言之，`quic_spdy_client_stream_test.cc` 是确保 Chromium 网络栈中 HTTP/2 和 HTTP/3 客户端流处理功能正确性的关键组成部分，它通过大量的单元测试覆盖了各种正常和异常情况，保障了用户浏览网页的稳定性和可靠性。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_client_stream_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/http/quic_spdy_client_stream.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/str_cat.h"
#include "quiche/quic/core/crypto/null_encrypter.h"
#include "quiche/quic/core/http/quic_spdy_client_session.h"
#include "quiche/quic/core/http/spdy_utils.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/test_tools/quic_spdy_session_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/simple_buffer_allocator.h"

using quiche::HttpHeaderBlock;
using testing::_;
using testing::ElementsAre;
using testing::StrictMock;

namespace quic {
namespace test {

namespace {

class MockQuicSpdyClientSession : public QuicSpdyClientSession {
 public:
  explicit MockQuicSpdyClientSession(
      const ParsedQuicVersionVector& supported_versions,
      QuicConnection* connection)
      : QuicSpdyClientSession(DefaultQuicConfig(), supported_versions,
                              connection, QuicServerId("example.com", 443),
                              &crypto_config_),
        crypto_config_(crypto_test_utils::ProofVerifierForTesting()) {}
  MockQuicSpdyClientSession(const MockQuicSpdyClientSession&) = delete;
  MockQuicSpdyClientSession& operator=(const MockQuicSpdyClientSession&) =
      delete;
  ~MockQuicSpdyClientSession() override = default;

  MOCK_METHOD(bool, WriteControlFrame,
              (const QuicFrame& frame, TransmissionType type), (override));

  using QuicSession::ActivateStream;

 private:
  QuicCryptoClientConfig crypto_config_;
};

class QuicSpdyClientStreamTest : public QuicTestWithParam<ParsedQuicVersion> {
 public:
  class StreamVisitor;

  QuicSpdyClientStreamTest()
      : connection_(new StrictMock<MockQuicConnection>(
            &helper_, &alarm_factory_, Perspective::IS_CLIENT,
            SupportedVersions(GetParam()))),
        session_(connection_->supported_versions(), connection_),
        body_("hello world") {
    session_.Initialize();
    connection_->AdvanceTime(QuicTime::Delta::FromSeconds(1));
    connection_->SetEncrypter(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<NullEncrypter>(connection_->perspective()));
    headers_[":status"] = "200";
    headers_["content-length"] = "11";

    auto stream = std::make_unique<QuicSpdyClientStream>(
        GetNthClientInitiatedBidirectionalStreamId(
            connection_->transport_version(), 0),
        &session_, BIDIRECTIONAL);
    stream_ = stream.get();
    session_.ActivateStream(std::move(stream));

    stream_visitor_ = std::make_unique<StreamVisitor>();
    stream_->set_visitor(stream_visitor_.get());
  }

  class StreamVisitor : public QuicSpdyClientStream::Visitor {
    void OnClose(QuicSpdyStream* stream) override {
      QUIC_DVLOG(1) << "stream " << stream->id();
    }
  };

  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  StrictMock<MockQuicConnection>* connection_;

  MockQuicSpdyClientSession session_;
  QuicSpdyClientStream* stream_;
  std::unique_ptr<StreamVisitor> stream_visitor_;
  HttpHeaderBlock headers_;
  std::string body_;
};

INSTANTIATE_TEST_SUITE_P(Tests, QuicSpdyClientStreamTest,
                         ::testing::ValuesIn(AllSupportedVersions()),
                         ::testing::PrintToStringParamName());

TEST_P(QuicSpdyClientStreamTest, TestReceivingIllegalResponseStatusCode) {
  headers_[":status"] = "200 ok";

  EXPECT_CALL(session_, WriteControlFrame(_, _));
  EXPECT_CALL(*connection_,
              OnStreamReset(stream_->id(), QUIC_BAD_APPLICATION_PAYLOAD));
  auto headers = AsHeaderList(headers_);
  stream_->OnStreamHeaderList(false, headers.uncompressed_header_bytes(),
                              headers);
  EXPECT_THAT(stream_->stream_error(),
              IsStreamError(QUIC_BAD_APPLICATION_PAYLOAD));
  EXPECT_EQ(stream_->ietf_application_error(),
            static_cast<uint64_t>(QuicHttp3ErrorCode::GENERAL_PROTOCOL_ERROR));
}

TEST_P(QuicSpdyClientStreamTest, InvalidResponseHeader) {
  SetQuicReloadableFlag(quic_act_upon_invalid_header, true);
  auto headers = AsHeaderList(std::vector<std::pair<std::string, std::string>>{
      {":status", "200"}, {":path", "/foo"}});
  EXPECT_CALL(*connection_,
              OnStreamReset(stream_->id(), QUIC_BAD_APPLICATION_PAYLOAD));
  stream_->OnStreamHeaderList(false, headers.uncompressed_header_bytes(),
                              headers);
  EXPECT_THAT(stream_->stream_error(),
              IsStreamError(QUIC_BAD_APPLICATION_PAYLOAD));
  EXPECT_EQ(stream_->ietf_application_error(),
            static_cast<uint64_t>(QuicHttp3ErrorCode::GENERAL_PROTOCOL_ERROR));
}

TEST_P(QuicSpdyClientStreamTest, MissingStatusCode) {
  SetQuicReloadableFlag(quic_act_upon_invalid_header, true);
  auto headers = AsHeaderList(
      std::vector<std::pair<std::string, std::string>>{{"key", "value"}});
  EXPECT_CALL(*connection_,
              OnStreamReset(stream_->id(), QUIC_BAD_APPLICATION_PAYLOAD));
  stream_->OnStreamHeaderList(false, headers.uncompressed_header_bytes(),
                              headers);
  EXPECT_THAT(stream_->stream_error(),
              IsStreamError(QUIC_BAD_APPLICATION_PAYLOAD));
  EXPECT_EQ(stream_->ietf_application_error(),
            static_cast<uint64_t>(QuicHttp3ErrorCode::GENERAL_PROTOCOL_ERROR));
}

TEST_P(QuicSpdyClientStreamTest, TestFraming) {
  auto headers = AsHeaderList(headers_);
  stream_->OnStreamHeaderList(false, headers.uncompressed_header_bytes(),
                              headers);
  quiche::QuicheBuffer header = HttpEncoder::SerializeDataFrameHeader(
      body_.length(), quiche::SimpleBufferAllocator::Get());
  std::string data = VersionUsesHttp3(connection_->transport_version())
                         ? absl::StrCat(header.AsStringView(), body_)
                         : body_;
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), /*fin=*/false, /*offset=*/0, data));
  EXPECT_EQ("200", stream_->response_headers().find(":status")->second);
  EXPECT_EQ(200, stream_->response_code());
  EXPECT_EQ(body_, stream_->data());
}

TEST_P(QuicSpdyClientStreamTest, HostAllowedInResponseHeader) {
  SetQuicReloadableFlag(quic_act_upon_invalid_header, true);
  auto headers = AsHeaderList(std::vector<std::pair<std::string, std::string>>{
      {":status", "200"}, {"host", "example.com"}});
  EXPECT_CALL(*connection_, OnStreamReset(stream_->id(), _)).Times(0u);
  stream_->OnStreamHeaderList(false, headers.uncompressed_header_bytes(),
                              headers);
  EXPECT_THAT(stream_->stream_error(), IsStreamError(QUIC_STREAM_NO_ERROR));
  EXPECT_EQ(stream_->ietf_application_error(),
            static_cast<uint64_t>(QuicHttp3ErrorCode::HTTP3_NO_ERROR));
}

TEST_P(QuicSpdyClientStreamTest, Test100ContinueBeforeSuccessful) {
  // First send 100 Continue.
  headers_[":status"] = "100";
  auto headers = AsHeaderList(headers_);
  stream_->OnStreamHeaderList(false, headers.uncompressed_header_bytes(),
                              headers);
  ASSERT_EQ(stream_->preliminary_headers().size(), 1);
  EXPECT_EQ("100",
            stream_->preliminary_headers().front().find(":status")->second);
  EXPECT_EQ(0u, stream_->response_headers().size());
  EXPECT_EQ(100, stream_->response_code());
  EXPECT_EQ("", stream_->data());
  // Then send 200 OK.
  headers_[":status"] = "200";
  headers = AsHeaderList(headers_);
  stream_->OnStreamHeaderList(false, headers.uncompressed_header_bytes(),
                              headers);
  quiche::QuicheBuffer header = HttpEncoder::SerializeDataFrameHeader(
      body_.length(), quiche::SimpleBufferAllocator::Get());
  std::string data = VersionUsesHttp3(connection_->transport_version())
                         ? absl::StrCat(header.AsStringView(), body_)
                         : body_;
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), /*fin=*/false, /*offset=*/0, data));
  // Make sure the 200 response got parsed correctly.
  EXPECT_EQ("200", stream_->response_headers().find(":status")->second);
  EXPECT_EQ(200, stream_->response_code());
  EXPECT_EQ(body_, stream_->data());
  // Make sure the 100 response is still available.
  ASSERT_EQ(stream_->preliminary_headers().size(), 1);
  EXPECT_EQ("100",
            stream_->preliminary_headers().front().find(":status")->second);
}

TEST_P(QuicSpdyClientStreamTest, TestUnknownInformationalBeforeSuccessful) {
  // First send 199, an unknown Informational (1XX).
  headers_[":status"] = "199";
  auto headers = AsHeaderList(headers_);
  stream_->OnStreamHeaderList(false, headers.uncompressed_header_bytes(),
                              headers);
  ASSERT_EQ(stream_->preliminary_headers().size(), 1);
  EXPECT_EQ("199",
            stream_->preliminary_headers().front().find(":status")->second);
  EXPECT_EQ(0u, stream_->response_headers().size());
  EXPECT_EQ(199, stream_->response_code());
  EXPECT_EQ("", stream_->data());
  // Then send 200 OK.
  headers_[":status"] = "200";
  headers = AsHeaderList(headers_);
  stream_->OnStreamHeaderList(false, headers.uncompressed_header_bytes(),
                              headers);
  quiche::QuicheBuffer header = HttpEncoder::SerializeDataFrameHeader(
      body_.length(), quiche::SimpleBufferAllocator::Get());
  std::string data = VersionUsesHttp3(connection_->transport_version())
                         ? absl::StrCat(header.AsStringView(), body_)
                         : body_;
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), /*fin=*/false, /*offset=*/0, data));
  // Make sure the 200 response got parsed correctly.
  EXPECT_EQ("200", stream_->response_headers().find(":status")->second);
  EXPECT_EQ(200, stream_->response_code());
  EXPECT_EQ(body_, stream_->data());
  // Make sure the 199 response is still available.
  ASSERT_EQ(stream_->preliminary_headers().size(), 1);
  EXPECT_EQ("199",
            stream_->preliminary_headers().front().find(":status")->second);
}

TEST_P(QuicSpdyClientStreamTest, TestMultipleInformationalBeforeSuccessful) {
  // First send 100 Continue.
  headers_[":status"] = "100";
  auto headers = AsHeaderList(headers_);
  stream_->OnStreamHeaderList(false, headers.uncompressed_header_bytes(),
                              headers);
  ASSERT_EQ(stream_->preliminary_headers().size(), 1);
  EXPECT_EQ("100",
            stream_->preliminary_headers().front().find(":status")->second);
  EXPECT_EQ(0u, stream_->response_headers().size());
  EXPECT_EQ(100, stream_->response_code());
  EXPECT_EQ("", stream_->data());

  // Then send 199, an unknown Informational (1XX).
  headers_[":status"] = "199";
  headers = AsHeaderList(headers_);
  stream_->OnStreamHeaderList(false, headers.uncompressed_header_bytes(),
                              headers);
  ASSERT_EQ(stream_->preliminary_headers().size(), 2);
  EXPECT_EQ("100",
            stream_->preliminary_headers().front().find(":status")->second);
  EXPECT_EQ("199",
            stream_->preliminary_headers().back().find(":status")->second);
  EXPECT_EQ(0u, stream_->response_headers().size());
  EXPECT_EQ(199, stream_->response_code());
  EXPECT_EQ("", stream_->data());

  // Then send 200 OK.
  headers_[":status"] = "200";
  headers = AsHeaderList(headers_);
  stream_->OnStreamHeaderList(false, headers.uncompressed_header_bytes(),
                              headers);
  quiche::QuicheBuffer header = HttpEncoder::SerializeDataFrameHeader(
      body_.length(), quiche::SimpleBufferAllocator::Get());
  std::string data = VersionUsesHttp3(connection_->transport_version())
                         ? absl::StrCat(header.AsStringView(), body_)
                         : body_;
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), /*fin=*/false, /*offset=*/0, data));

  // Make sure the 200 response got parsed correctly.
  EXPECT_EQ("200", stream_->response_headers().find(":status")->second);
  EXPECT_EQ(200, stream_->response_code());
  EXPECT_EQ(body_, stream_->data());

  // Make sure the informational responses are still available.
  ASSERT_EQ(stream_->preliminary_headers().size(), 2);
  EXPECT_EQ("100",
            stream_->preliminary_headers().front().find(":status")->second);
  EXPECT_EQ("199",
            stream_->preliminary_headers().back().find(":status")->second);
}

TEST_P(QuicSpdyClientStreamTest, TestReceiving101) {
  // 101 "Switching Protocols" is forbidden in HTTP/3 as per the
  // "HTTP Upgrade" section of draft-ietf-quic-http.
  headers_[":status"] = "101";
  EXPECT_CALL(session_, WriteControlFrame(_, _));
  EXPECT_CALL(*connection_,
              OnStreamReset(stream_->id(), QUIC_BAD_APPLICATION_PAYLOAD));
  auto headers = AsHeaderList(headers_);
  stream_->OnStreamHeaderList(false, headers.uncompressed_header_bytes(),
                              headers);
  EXPECT_THAT(stream_->stream_error(),
              IsStreamError(QUIC_BAD_APPLICATION_PAYLOAD));
}

TEST_P(QuicSpdyClientStreamTest, TestFramingOnePacket) {
  auto headers = AsHeaderList(headers_);
  stream_->OnStreamHeaderList(false, headers.uncompressed_header_bytes(),
                              headers);
  quiche::QuicheBuffer header = HttpEncoder::SerializeDataFrameHeader(
      body_.length(), quiche::SimpleBufferAllocator::Get());
  std::string data = VersionUsesHttp3(connection_->transport_version())
                         ? absl::StrCat(header.AsStringView(), body_)
                         : body_;
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), /*fin=*/false, /*offset=*/0, data));
  EXPECT_EQ("200", stream_->response_headers().find(":status")->second);
  EXPECT_EQ(200, stream_->response_code());
  EXPECT_EQ(body_, stream_->data());
}

TEST_P(QuicSpdyClientStreamTest,
       QUIC_TEST_DISABLED_IN_CHROME(TestFramingExtraData)) {
  std::string large_body = "hello world!!!!!!";

  auto headers = AsHeaderList(headers_);
  stream_->OnStreamHeaderList(false, headers.uncompressed_header_bytes(),
                              headers);
  // The headers should parse successfully.
  EXPECT_THAT(stream_->stream_error(), IsQuicStreamNoError());
  EXPECT_EQ("200", stream_->response_headers().find(":status")->second);
  EXPECT_EQ(200, stream_->response_code());
  quiche::QuicheBuffer header = HttpEncoder::SerializeDataFrameHeader(
      large_body.length(), quiche::SimpleBufferAllocator::Get());
  std::string data = VersionUsesHttp3(connection_->transport_version())
                         ? absl::StrCat(header.AsStringView(), large_body)
                         : large_body;
  EXPECT_CALL(session_, WriteControlFrame(_, _));
  EXPECT_CALL(*connection_,
              OnStreamReset(stream_->id(), QUIC_BAD_APPLICATION_PAYLOAD));

  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), /*fin=*/false, /*offset=*/0, data));

  EXPECT_NE(QUIC_STREAM_NO_ERROR, stream_->stream_error());
  EXPECT_EQ(stream_->ietf_application_error(),
            static_cast<uint64_t>(QuicHttp3ErrorCode::GENERAL_PROTOCOL_ERROR));
}

// Test that receiving trailing headers (on the headers stream), containing a
// final offset, results in the stream being closed at that byte offset.
TEST_P(QuicSpdyClientStreamTest, ReceivingTrailers) {
  // There is no kFinalOffsetHeaderKey if trailers are sent on the
  // request/response stream.
  if (VersionUsesHttp3(connection_->transport_version())) {
    return;
  }

  // Send headers as usual.
  auto headers = AsHeaderList(headers_);
  stream_->OnStreamHeaderList(false, headers.uncompressed_header_bytes(),
                              headers);

  // Send trailers before sending the body. Even though a FIN has been received
  // the stream should not be closed, as it does not yet have all the data bytes
  // promised by the final offset field.
  HttpHeaderBlock trailer_block;
  trailer_block["trailer key"] = "trailer value";
  trailer_block[kFinalOffsetHeaderKey] = absl::StrCat(body_.size());
  auto trailers = AsHeaderList(trailer_block);
  stream_->OnStreamHeaderList(true, trailers.uncompressed_header_bytes(),
                              trailers);

  // Now send the body, which should close the stream as the FIN has been
  // received, as well as all data.
  quiche::QuicheBuffer header = HttpEncoder::SerializeDataFrameHeader(
      body_.length(), quiche::SimpleBufferAllocator::Get());
  std::string data = VersionUsesHttp3(connection_->transport_version())
                         ? absl::StrCat(header.AsStringView(), body_)
                         : body_;
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), /*fin=*/false, /*offset=*/0, data));
  EXPECT_TRUE(stream_->reading_stopped());
}

TEST_P(QuicSpdyClientStreamTest, Capsules) {
  if (!VersionUsesHttp3(connection_->transport_version())) {
    return;
  }
  SavingHttp3DatagramVisitor h3_datagram_visitor;
  stream_->RegisterHttp3DatagramVisitor(&h3_datagram_visitor);
  headers_.erase("content-length");
  auto headers = AsHeaderList(headers_);
  stream_->OnStreamHeaderList(false, headers.uncompressed_header_bytes(),
                              headers);
  std::string capsule_data = {0, 6, 1, 2, 3, 4, 5, 6, 0x17, 4, 1, 2, 3, 4};
  quiche::QuicheBuffer data_frame_header =
      HttpEncoder::SerializeDataFrameHeader(
          capsule_data.length(), quiche::SimpleBufferAllocator::Get());
  std::string stream_data =
      absl::StrCat(data_frame_header.AsStringView(), capsule_data);
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), /*fin=*/false, /*offset=*/0, stream_data));
  // Datagram capsule.
  std::string http_datagram_payload = {1, 2, 3, 4, 5, 6};
  EXPECT_THAT(h3_datagram_visitor.received_h3_datagrams(),
              ElementsAre(SavingHttp3DatagramVisitor::SavedHttp3Datagram{
                  stream_->id(), http_datagram_payload}));
  // Unknown capsule.
  uint64_t capsule_type = 0x17u;
  std::string unknown_capsule_payload = {1, 2, 3, 4};
  EXPECT_THAT(h3_datagram_visitor.received_unknown_capsules(),
              ElementsAre(SavingHttp3DatagramVisitor::SavedUnknownCapsule{
                  stream_->id(), capsule_type, unknown_capsule_payload}));
  // Cleanup.
  stream_->UnregisterHttp3DatagramVisitor();
}

TEST_P(QuicSpdyClientStreamTest, CapsulesOnUnsuccessfulResponse) {
  if (!VersionUsesHttp3(connection_->transport_version())) {
    return;
  }
  SavingHttp3DatagramVisitor h3_datagram_visitor;
  stream_->RegisterHttp3DatagramVisitor(&h3_datagram_visitor);
  headers_[":status"] = "401";
  headers_.erase("content-length");
  auto headers = AsHeaderList(headers_);
  stream_->OnStreamHeaderList(false, headers.uncompressed_header_bytes(),
                              headers);
  std::string capsule_data = {0, 6, 1, 2, 3, 4, 5, 6, 0x17, 4, 1, 2, 3, 4};
  quiche::QuicheBuffer data_frame_header =
      HttpEncoder::SerializeDataFrameHeader(
          capsule_data.length(), quiche::SimpleBufferAllocator::Get());
  std::string stream_data =
      absl::StrCat(data_frame_header.AsStringView(), capsule_data);
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), /*fin=*/false, /*offset=*/0, stream_data));
  // Ensure received capsules were ignored.
  EXPECT_TRUE(h3_datagram_visitor.received_h3_datagrams().empty());
  EXPECT_TRUE(h3_datagram_visitor.received_unknown_capsules().empty());
  // Cleanup.
  stream_->UnregisterHttp3DatagramVisitor();
}

}  // namespace
}  // namespace test
}  // namespace quic

"""

```