Response:
The user wants to understand the functionality of the provided C++ source code file `quic_headers_stream_test.cc`. They also want to know if it's related to JavaScript, see examples of logical reasoning with inputs and outputs, understand common usage errors, and trace how a user might reach this code during debugging. Finally, they want a summary of the file's functionality as the first part of a two-part explanation.

Here's a plan to address each of these points:

1. **Functionality:** Analyze the code to understand its purpose. It appears to be a unit test file for `QuicHeadersStream`.
2. **JavaScript Relationship:**  Determine if and how `QuicHeadersStream` or its testing relate to JavaScript. Since it's part of Chromium's network stack, it likely plays a role in how the browser handles HTTP/2 or HTTP/3 headers over QUIC, which has implications for JavaScript in web pages.
3. **Logical Reasoning (Input/Output):**  Identify specific test cases that demonstrate logical operations and provide example inputs and expected outputs. Focus on the tests that manipulate header data or simulate different scenarios.
4. **Common Usage Errors:** Consider potential mistakes developers could make when working with `QuicHeadersStream` or its related components, and how these tests help prevent or detect them.
5. **User Operation & Debugging:**  Describe a scenario where a user's action in a web browser might indirectly lead to this code being executed or investigated during debugging.
6. **Summary:** Condense the findings into a concise summary of the file's main purpose.
这是文件 `net/third_party/quiche/src/quiche/quic/core/http/quic_headers_stream_test.cc` 的第一部分，它是一个 **C++ 单元测试文件**，专门用于测试 `QuicHeadersStream` 类的功能。 `QuicHeadersStream`  是 Chromium QUIC 协议栈中处理 HTTP/2 或 HTTP/3 首部信息的流。

**功能归纳 (第 1 部分):**

这个文件的主要功能是建立和执行各种测试用例，以验证 `QuicHeadersStream` 类的以下核心行为：

1. **首部帧的发送和接收:** 测试 `QuicHeadersStream` 如何将 HTTP 首部信息编码成 SPDY 或 HTTP/2 帧并发送，以及如何接收和解析这些帧。
2. **不同类型的首部帧处理:**  测试对不同类型 SPDY 或 HTTP/2 首部帧的处理，例如 `HEADERS` 帧（用于发送请求和响应首部），`PUSH_PROMISE` 帧（用于服务器推送），和 `PRIORITY` 帧（用于设置流的优先级）。
3. **错误处理:** 测试当接收到无效或不期望的首部帧时，`QuicHeadersStream` 如何进行错误处理，例如接收到 `DATA` 帧、`RST_STREAM` 帧等控制帧。
4. **SETTINGS 帧的处理:** 测试 `QuicHeadersStream` 如何处理 SPDY 或 HTTP/2 的 `SETTINGS` 帧，特别是那些与首部处理相关的设置，例如 `SETTINGS_HEADER_TABLE_SIZE`。
5. **数据写入和确认:** 测试 `QuicHeadersStream` 如何写入首部数据，并处理数据的确认 (ACK) 和重传。
6. **流的贡献度:** 验证 `QuicHeadersStream` 不参与连接级别的流量控制。

**与 JavaScript 的关系:**

`QuicHeadersStream` 本身是用 C++ 编写的，直接与 JavaScript 没有代码级别的联系。 然而，它在 Chromium 浏览器中扮演着关键角色，处理通过 QUIC 协议传输的 HTTP 首部信息。 当 JavaScript 发起网络请求（例如通过 `fetch` API 或 `XMLHttpRequest`）时，浏览器底层会使用 QUIC 协议栈来建立连接和传输数据。

* **例子:** 当一个 JavaScript 应用程序使用 `fetch` 发送一个 HTTP 请求时，浏览器会创建一个 QUIC 连接（如果适用）。 请求的 HTTP 首部（例如 `Content-Type`, `Authorization` 等）会被编码并通过 `QuicHeadersStream` 发送给服务器。 服务器的响应首部也会通过 `QuicHeadersStream` 接收并最终传递给 JavaScript 回调函数。

**逻辑推理的举例说明 (假设输入与输出):**

假设测试用例的目标是验证 `QuicHeadersStream` 正确发送带有优先级的请求首部。

* **假设输入:**
    * `stream_id`: 4 (一个客户端发起的双向流 ID)
    * `fin`: false (首部帧不是流的结束)
    * `priority`: 3 (SPDY 优先级，范围 0-7)
    * `headers_`: 一个包含请求首部的 `HttpHeaderBlock`，例如 `{:method: GET, :path: /index.html, host: example.com}`

* **逻辑推理:**
    1. `QuicHeadersStream` 将 `headers_` 编码成一个 SPDY `HEADERS` 帧。
    2. 由于 `priority` 不为 0， 帧的标志位应该指示存在优先级信息。
    3. SPDY 优先级 3 会被转换为 HTTP/2 的权重值 (例如，3 对应权重 4 的优先级)。
    4. 编码后的帧数据会被写入底层的 QUIC 连接。

* **预期输出:**
    *  发送的 SPDY `HEADERS` 帧包含：
        *   流 ID: 4
        *   标志位：包含优先级指示
        *   优先级信息：父流 ID 为 0，互斥标志为 false，权重值为 4。
        *   编码后的首部键值对。

**涉及用户或编程常见的使用错误 (举例说明):**

虽然用户不会直接操作 `QuicHeadersStream`，但编程错误可能导致不正确的首部信息被传递给它，或者在处理接收到的首部时出错。

* **例子 (编程错误):**  开发者在服务器端代码中错误地尝试在 `QuicHeadersStream` 上发送 `PUSH_PROMISE` 帧，而根据 HTTP/2 规范，这应该在关联的请求流上发送。  测试用例 `TEST_P(QuicHeadersStreamTest, ProcessPushPromise)` 就是用来检测这种情况的，当服务器尝试在 headers stream 上发送 `PUSH_PROMISE` 时，连接应该被关闭并报告 `QUIC_INVALID_HEADERS_STREAM_DATA` 错误。

**用户操作是如何一步步的到达这里 (作为调试线索):**

1. **用户在 Chrome 浏览器中访问一个 HTTPS 网站 (例如，`https://www.example.com`)，该网站使用 QUIC 协议。**
2. **浏览器发起一个 GET 请求来获取网页资源。**
3. **Chromium 网络栈中的更上层代码创建 HTTP 请求首部。**
4. **这些首部信息被传递到 QUIC 协议栈的 `QuicSpdyClientSession` 或 `QuicSpdyServerSession`。**
5. **`QuicSpdySession` 会使用 `QuicHeadersStream` 将这些首部信息编码成 SPDY 或 HTTP/2 的 `HEADERS` 帧。**
6. **如果在这个过程中出现问题，例如首部格式错误、接收到意外的帧类型等，开发人员在调试 Chromium 网络栈时可能会查看 `QuicHeadersStream` 的代码和相关的测试用例，例如 `quic_headers_stream_test.cc`，来理解问题的根源。**
7. **例如，如果用户报告浏览器加载网页时出现 "ERR_HTTP2_PROTOCOL_ERROR"，开发者可能会追踪到 `QuicHeadersStream` 处理接收到的帧时抛出了这个错误，并查看相应的测试用例来复现和修复问题。**

总而言之， `quic_headers_stream_test.cc` 是确保 Chromium QUIC 协议栈中负责处理 HTTP 首部信息的关键组件 `QuicHeadersStream` 能够正确、可靠地工作的重要组成部分。 它通过大量的单元测试来验证各种场景下的行为，帮助开发者预防和修复与首部处理相关的错误。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/quic_headers_stream_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/http/quic_headers_stream.h"

#include <cstdint>
#include <memory>
#include <ostream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/http2/core/http2_frame_decoder_adapter.h"
#include "quiche/http2/core/recording_headers_handler.h"
#include "quiche/http2/core/spdy_alt_svc_wire_format.h"
#include "quiche/http2/core/spdy_protocol.h"
#include "quiche/http2/test_tools/spdy_test_utils.h"
#include "quiche/quic/core/crypto/null_encrypter.h"
#include "quiche/quic/core/http/spdy_utils.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_connection_peer.h"
#include "quiche/quic/test_tools/quic_spdy_session_peer.h"
#include "quiche/quic/test_tools/quic_stream_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/quiche_endian.h"

using quiche::HttpHeaderBlock;
using spdy::ERROR_CODE_PROTOCOL_ERROR;
using spdy::RecordingHeadersHandler;
using spdy::SETTINGS_ENABLE_PUSH;
using spdy::SETTINGS_HEADER_TABLE_SIZE;
using spdy::SETTINGS_INITIAL_WINDOW_SIZE;
using spdy::SETTINGS_MAX_CONCURRENT_STREAMS;
using spdy::SETTINGS_MAX_FRAME_SIZE;
using spdy::Spdy3PriorityToHttp2Weight;
using spdy::SpdyAltSvcWireFormat;
using spdy::SpdyDataIR;
using spdy::SpdyErrorCode;
using spdy::SpdyFramer;
using spdy::SpdyFramerVisitorInterface;
using spdy::SpdyGoAwayIR;
using spdy::SpdyHeadersHandlerInterface;
using spdy::SpdyHeadersIR;
using spdy::SpdyPingId;
using spdy::SpdyPingIR;
using spdy::SpdyPriority;
using spdy::SpdyPriorityIR;
using spdy::SpdyPushPromiseIR;
using spdy::SpdyRstStreamIR;
using spdy::SpdySerializedFrame;
using spdy::SpdySettingsId;
using spdy::SpdySettingsIR;
using spdy::SpdyStreamId;
using spdy::SpdyWindowUpdateIR;
using testing::_;
using testing::AnyNumber;
using testing::AtLeast;
using testing::InSequence;
using testing::Invoke;
using testing::Return;
using testing::StrictMock;
using testing::WithArgs;

namespace quic {
namespace test {
namespace {

class MockVisitor : public SpdyFramerVisitorInterface {
 public:
  MOCK_METHOD(void, OnError,
              (http2::Http2DecoderAdapter::SpdyFramerError error,
               std::string detailed_error),
              (override));
  MOCK_METHOD(void, OnDataFrameHeader,
              (SpdyStreamId stream_id, size_t length, bool fin), (override));
  MOCK_METHOD(void, OnStreamFrameData,
              (SpdyStreamId stream_id, const char*, size_t len), (override));
  MOCK_METHOD(void, OnStreamEnd, (SpdyStreamId stream_id), (override));
  MOCK_METHOD(void, OnStreamPadding, (SpdyStreamId stream_id, size_t len),
              (override));
  MOCK_METHOD(SpdyHeadersHandlerInterface*, OnHeaderFrameStart,
              (SpdyStreamId stream_id), (override));
  MOCK_METHOD(void, OnHeaderFrameEnd, (SpdyStreamId stream_id), (override));
  MOCK_METHOD(void, OnRstStream,
              (SpdyStreamId stream_id, SpdyErrorCode error_code), (override));
  MOCK_METHOD(void, OnSettings, (), (override));
  MOCK_METHOD(void, OnSetting, (SpdySettingsId id, uint32_t value), (override));
  MOCK_METHOD(void, OnSettingsAck, (), (override));
  MOCK_METHOD(void, OnSettingsEnd, (), (override));
  MOCK_METHOD(void, OnPing, (SpdyPingId unique_id, bool is_ack), (override));
  MOCK_METHOD(void, OnGoAway,
              (SpdyStreamId last_accepted_stream_id, SpdyErrorCode error_code),
              (override));
  MOCK_METHOD(void, OnHeaders,
              (SpdyStreamId stream_id, size_t payload_length, bool has_priority,
               int weight, SpdyStreamId parent_stream_id, bool exclusive,
               bool fin, bool end),
              (override));
  MOCK_METHOD(void, OnWindowUpdate,
              (SpdyStreamId stream_id, int delta_window_size), (override));
  MOCK_METHOD(void, OnPushPromise,
              (SpdyStreamId stream_id, SpdyStreamId promised_stream_id,
               bool end),
              (override));
  MOCK_METHOD(void, OnContinuation,
              (SpdyStreamId stream_id, size_t payload_size, bool end),
              (override));
  MOCK_METHOD(
      void, OnAltSvc,
      (SpdyStreamId stream_id, absl::string_view origin,
       const SpdyAltSvcWireFormat::AlternativeServiceVector& altsvc_vector),
      (override));
  MOCK_METHOD(void, OnPriority,
              (SpdyStreamId stream_id, SpdyStreamId parent_stream_id,
               int weight, bool exclusive),
              (override));
  MOCK_METHOD(void, OnPriorityUpdate,
              (SpdyStreamId prioritized_stream_id,
               absl::string_view priority_field_value),
              (override));
  MOCK_METHOD(bool, OnUnknownFrame,
              (SpdyStreamId stream_id, uint8_t frame_type), (override));
  MOCK_METHOD(void, OnUnknownFrameStart,
              (SpdyStreamId stream_id, size_t length, uint8_t type,
               uint8_t flags),
              (override));
  MOCK_METHOD(void, OnUnknownFramePayload,
              (SpdyStreamId stream_id, absl::string_view payload), (override));
};

struct TestParams {
  TestParams(const ParsedQuicVersion& version, Perspective perspective)
      : version(version), perspective(perspective) {
    QUIC_LOG(INFO) << "TestParams:  " << *this;
  }

  TestParams(const TestParams& other)
      : version(other.version), perspective(other.perspective) {}

  friend std::ostream& operator<<(std::ostream& os, const TestParams& tp) {
    os << "{ version: " << ParsedQuicVersionToString(tp.version)
       << ", perspective: "
       << (tp.perspective == Perspective::IS_CLIENT ? "client" : "server")
       << "}";
    return os;
  }

  ParsedQuicVersion version;
  Perspective perspective;
};

// Used by ::testing::PrintToStringParamName().
std::string PrintToString(const TestParams& tp) {
  return absl::StrCat(
      ParsedQuicVersionToString(tp.version), "_",
      (tp.perspective == Perspective::IS_CLIENT ? "client" : "server"));
}

std::vector<TestParams> GetTestParams() {
  std::vector<TestParams> params;
  ParsedQuicVersionVector all_supported_versions = AllSupportedVersions();
  for (size_t i = 0; i < all_supported_versions.size(); ++i) {
    if (VersionUsesHttp3(all_supported_versions[i].transport_version)) {
      continue;
    }
    for (Perspective p : {Perspective::IS_SERVER, Perspective::IS_CLIENT}) {
      params.emplace_back(all_supported_versions[i], p);
    }
  }
  return params;
}

class QuicHeadersStreamTest : public QuicTestWithParam<TestParams> {
 public:
  QuicHeadersStreamTest()
      : connection_(new StrictMock<MockQuicConnection>(
            &helper_, &alarm_factory_, perspective(), GetVersion())),
        session_(connection_),
        body_("hello world"),
        stream_frame_(
            QuicUtils::GetHeadersStreamId(connection_->transport_version()),
            /*fin=*/false,
            /*offset=*/0, ""),
        next_promised_stream_id_(2) {
    QuicSpdySessionPeer::SetMaxInboundHeaderListSize(&session_, 256 * 1024);
    EXPECT_CALL(session_, OnCongestionWindowChange(_)).Times(AnyNumber());
    session_.Initialize();
    connection_->SetEncrypter(
        quic::ENCRYPTION_FORWARD_SECURE,
        std::make_unique<quic::NullEncrypter>(connection_->perspective()));
    headers_stream_ = QuicSpdySessionPeer::GetHeadersStream(&session_);
    headers_[":status"] = "200 Ok";
    headers_["content-length"] = "11";
    framer_ = std::unique_ptr<SpdyFramer>(
        new SpdyFramer(SpdyFramer::ENABLE_COMPRESSION));
    deframer_ = std::unique_ptr<http2::Http2DecoderAdapter>(
        new http2::Http2DecoderAdapter());
    deframer_->set_visitor(&visitor_);
    EXPECT_EQ(transport_version(), session_.transport_version());
    EXPECT_TRUE(headers_stream_ != nullptr);
    connection_->AdvanceTime(QuicTime::Delta::FromMilliseconds(1));
    client_id_1_ = GetNthClientInitiatedBidirectionalStreamId(
        connection_->transport_version(), 0);
    client_id_2_ = GetNthClientInitiatedBidirectionalStreamId(
        connection_->transport_version(), 1);
    client_id_3_ = GetNthClientInitiatedBidirectionalStreamId(
        connection_->transport_version(), 2);
    next_stream_id_ =
        QuicUtils::StreamIdDelta(connection_->transport_version());
  }

  QuicStreamId GetNthClientInitiatedId(int n) {
    return GetNthClientInitiatedBidirectionalStreamId(
        connection_->transport_version(), n);
  }

  QuicConsumedData SaveIov(size_t write_length) {
    char* buf = new char[write_length];
    QuicDataWriter writer(write_length, buf, quiche::NETWORK_BYTE_ORDER);
    headers_stream_->WriteStreamData(headers_stream_->stream_bytes_written(),
                                     write_length, &writer);
    saved_data_.append(buf, write_length);
    delete[] buf;
    return QuicConsumedData(write_length, false);
  }

  void SavePayload(const char* data, size_t len) {
    saved_payloads_.append(data, len);
  }

  bool SaveHeaderData(const char* data, int len) {
    saved_header_data_.append(data, len);
    return true;
  }

  void SaveHeaderDataStringPiece(absl::string_view data) {
    saved_header_data_.append(data.data(), data.length());
  }

  void SavePromiseHeaderList(QuicStreamId /* stream_id */,
                             QuicStreamId /* promised_stream_id */, size_t size,
                             const QuicHeaderList& header_list) {
    SaveToHandler(size, header_list);
  }

  void SaveHeaderList(QuicStreamId /* stream_id */, bool /* fin */, size_t size,
                      const QuicHeaderList& header_list) {
    SaveToHandler(size, header_list);
  }

  void SaveToHandler(size_t size, const QuicHeaderList& header_list) {
    headers_handler_ = std::make_unique<RecordingHeadersHandler>();
    headers_handler_->OnHeaderBlockStart();
    for (const auto& p : header_list) {
      headers_handler_->OnHeader(p.first, p.second);
    }
    headers_handler_->OnHeaderBlockEnd(size, size);
  }

  void WriteAndExpectRequestHeaders(QuicStreamId stream_id, bool fin,
                                    SpdyPriority priority) {
    WriteHeadersAndCheckData(stream_id, fin, priority, true /*is_request*/);
  }

  void WriteAndExpectResponseHeaders(QuicStreamId stream_id, bool fin) {
    WriteHeadersAndCheckData(stream_id, fin, 0, false /*is_request*/);
  }

  void WriteHeadersAndCheckData(QuicStreamId stream_id, bool fin,
                                SpdyPriority priority, bool is_request) {
    // Write the headers and capture the outgoing data
    EXPECT_CALL(session_, WritevData(QuicUtils::GetHeadersStreamId(
                                         connection_->transport_version()),
                                     _, _, NO_FIN, _, _))
        .WillOnce(WithArgs<1>(Invoke(this, &QuicHeadersStreamTest::SaveIov)));
    QuicSpdySessionPeer::WriteHeadersOnHeadersStream(
        &session_, stream_id, headers_.Clone(), fin,
        spdy::SpdyStreamPrecedence(priority), nullptr);

    // Parse the outgoing data and check that it matches was was written.
    if (is_request) {
      EXPECT_CALL(
          visitor_,
          OnHeaders(stream_id, saved_data_.length() - spdy::kFrameHeaderSize,
                    kHasPriority, Spdy3PriorityToHttp2Weight(priority),
                    /*parent_stream_id=*/0,
                    /*exclusive=*/false, fin, kFrameComplete));
    } else {
      EXPECT_CALL(
          visitor_,
          OnHeaders(stream_id, saved_data_.length() - spdy::kFrameHeaderSize,
                    !kHasPriority,
                    /*weight=*/0,
                    /*parent_stream_id=*/0,
                    /*exclusive=*/false, fin, kFrameComplete));
    }
    headers_handler_ = std::make_unique<RecordingHeadersHandler>();
    EXPECT_CALL(visitor_, OnHeaderFrameStart(stream_id))
        .WillOnce(Return(headers_handler_.get()));
    EXPECT_CALL(visitor_, OnHeaderFrameEnd(stream_id)).Times(1);
    if (fin) {
      EXPECT_CALL(visitor_, OnStreamEnd(stream_id));
    }
    deframer_->ProcessInput(saved_data_.data(), saved_data_.length());
    EXPECT_FALSE(deframer_->HasError())
        << http2::Http2DecoderAdapter::SpdyFramerErrorToString(
               deframer_->spdy_framer_error());

    CheckHeaders();
    saved_data_.clear();
  }

  void CheckHeaders() {
    ASSERT_TRUE(headers_handler_);
    EXPECT_EQ(headers_, headers_handler_->decoded_block());
    headers_handler_.reset();
  }

  Perspective perspective() const { return GetParam().perspective; }

  QuicTransportVersion transport_version() const {
    return GetParam().version.transport_version;
  }

  ParsedQuicVersionVector GetVersion() {
    ParsedQuicVersionVector versions;
    versions.push_back(GetParam().version);
    return versions;
  }

  void TearDownLocalConnectionState() {
    QuicConnectionPeer::TearDownLocalConnectionState(connection_);
  }

  QuicStreamId NextPromisedStreamId() {
    return next_promised_stream_id_ += next_stream_id_;
  }

  static constexpr bool kFrameComplete = true;
  static constexpr bool kHasPriority = true;

  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  StrictMock<MockQuicConnection>* connection_;
  StrictMock<MockQuicSpdySession> session_;
  QuicHeadersStream* headers_stream_;
  HttpHeaderBlock headers_;
  std::unique_ptr<RecordingHeadersHandler> headers_handler_;
  std::string body_;
  std::string saved_data_;
  std::string saved_header_data_;
  std::string saved_payloads_;
  std::unique_ptr<SpdyFramer> framer_;
  std::unique_ptr<http2::Http2DecoderAdapter> deframer_;
  StrictMock<MockVisitor> visitor_;
  QuicStreamFrame stream_frame_;
  QuicStreamId next_promised_stream_id_;
  QuicStreamId client_id_1_;
  QuicStreamId client_id_2_;
  QuicStreamId client_id_3_;
  QuicStreamId next_stream_id_;
};

// Run all tests with each version and perspective (client or server).
INSTANTIATE_TEST_SUITE_P(Tests, QuicHeadersStreamTest,
                         ::testing::ValuesIn(GetTestParams()),
                         ::testing::PrintToStringParamName());

TEST_P(QuicHeadersStreamTest, StreamId) {
  EXPECT_EQ(QuicUtils::GetHeadersStreamId(connection_->transport_version()),
            headers_stream_->id());
}

TEST_P(QuicHeadersStreamTest, WriteHeaders) {
  for (QuicStreamId stream_id = client_id_1_; stream_id < client_id_3_;
       stream_id += next_stream_id_) {
    for (bool fin : {false, true}) {
      if (perspective() == Perspective::IS_SERVER) {
        WriteAndExpectResponseHeaders(stream_id, fin);
      } else {
        for (SpdyPriority priority = 0; priority < 7; ++priority) {
          // TODO(rch): implement priorities correctly.
          WriteAndExpectRequestHeaders(stream_id, fin, 0);
        }
      }
    }
  }
}

TEST_P(QuicHeadersStreamTest, ProcessRawData) {
  for (QuicStreamId stream_id = client_id_1_; stream_id < client_id_3_;
       stream_id += next_stream_id_) {
    for (bool fin : {false, true}) {
      for (SpdyPriority priority = 0; priority < 7; ++priority) {
        // Replace with "WriteHeadersAndSaveData"
        SpdySerializedFrame frame;
        if (perspective() == Perspective::IS_SERVER) {
          SpdyHeadersIR headers_frame(stream_id, headers_.Clone());
          headers_frame.set_fin(fin);
          headers_frame.set_has_priority(true);
          headers_frame.set_weight(Spdy3PriorityToHttp2Weight(0));
          frame = framer_->SerializeFrame(headers_frame);
          EXPECT_CALL(session_, OnStreamHeadersPriority(
                                    stream_id, spdy::SpdyStreamPrecedence(0)));
        } else {
          SpdyHeadersIR headers_frame(stream_id, headers_.Clone());
          headers_frame.set_fin(fin);
          frame = framer_->SerializeFrame(headers_frame);
        }
        EXPECT_CALL(session_,
                    OnStreamHeaderList(stream_id, fin, frame.size(), _))
            .WillOnce(Invoke(this, &QuicHeadersStreamTest::SaveHeaderList));
        stream_frame_.data_buffer = frame.data();
        stream_frame_.data_length = frame.size();
        headers_stream_->OnStreamFrame(stream_frame_);
        stream_frame_.offset += frame.size();
        CheckHeaders();
      }
    }
  }
}

TEST_P(QuicHeadersStreamTest, ProcessPushPromise) {
  for (QuicStreamId stream_id = client_id_1_; stream_id < client_id_3_;
       stream_id += next_stream_id_) {
    QuicStreamId promised_stream_id = NextPromisedStreamId();
    SpdyPushPromiseIR push_promise(stream_id, promised_stream_id,
                                   headers_.Clone());
    SpdySerializedFrame frame(framer_->SerializeFrame(push_promise));
    if (perspective() == Perspective::IS_SERVER) {
      EXPECT_CALL(*connection_,
                  CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                                  "PUSH_PROMISE not supported.", _))
          .WillRepeatedly(InvokeWithoutArgs(
              this, &QuicHeadersStreamTest::TearDownLocalConnectionState));
    } else {
      EXPECT_CALL(session_, MaybeSendRstStreamFrame(promised_stream_id, _, _));
    }
    stream_frame_.data_buffer = frame.data();
    stream_frame_.data_length = frame.size();
    headers_stream_->OnStreamFrame(stream_frame_);
    stream_frame_.offset += frame.size();
  }
}

TEST_P(QuicHeadersStreamTest, ProcessPriorityFrame) {
  QuicStreamId parent_stream_id = 0;
  for (SpdyPriority priority = 0; priority < 7; ++priority) {
    for (QuicStreamId stream_id = client_id_1_; stream_id < client_id_3_;
         stream_id += next_stream_id_) {
      int weight = Spdy3PriorityToHttp2Weight(priority);
      SpdyPriorityIR priority_frame(stream_id, parent_stream_id, weight, true);
      SpdySerializedFrame frame(framer_->SerializeFrame(priority_frame));
      parent_stream_id = stream_id;
      if (perspective() == Perspective::IS_CLIENT) {
        EXPECT_CALL(*connection_,
                    CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                                    "Server must not send PRIORITY frames.", _))
            .WillRepeatedly(InvokeWithoutArgs(
                this, &QuicHeadersStreamTest::TearDownLocalConnectionState));
      } else {
        EXPECT_CALL(
            session_,
            OnPriorityFrame(stream_id, spdy::SpdyStreamPrecedence(priority)))
            .Times(1);
      }
      stream_frame_.data_buffer = frame.data();
      stream_frame_.data_length = frame.size();
      headers_stream_->OnStreamFrame(stream_frame_);
      stream_frame_.offset += frame.size();
    }
  }
}

TEST_P(QuicHeadersStreamTest, ProcessPushPromiseDisabledSetting) {
  if (perspective() != Perspective::IS_CLIENT) {
    return;
  }

  session_.OnConfigNegotiated();
  SpdySettingsIR data;
  // Respect supported settings frames SETTINGS_ENABLE_PUSH.
  data.AddSetting(SETTINGS_ENABLE_PUSH, 0);
  SpdySerializedFrame frame(framer_->SerializeFrame(data));
  stream_frame_.data_buffer = frame.data();
  stream_frame_.data_length = frame.size();
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                      "Unsupported field of HTTP/2 SETTINGS frame: 2", _));
  headers_stream_->OnStreamFrame(stream_frame_);
}

TEST_P(QuicHeadersStreamTest, ProcessLargeRawData) {
  // We want to create a frame that is more than the SPDY Framer's max control
  // frame size, which is 16K, but less than the HPACK decoders max decode
  // buffer size, which is 32K.
  headers_["key0"] = std::string(1 << 13, '.');
  headers_["key1"] = std::string(1 << 13, '.');
  headers_["key2"] = std::string(1 << 13, '.');
  for (QuicStreamId stream_id = client_id_1_; stream_id < client_id_3_;
       stream_id += next_stream_id_) {
    for (bool fin : {false, true}) {
      for (SpdyPriority priority = 0; priority < 7; ++priority) {
        // Replace with "WriteHeadersAndSaveData"
        SpdySerializedFrame frame;
        if (perspective() == Perspective::IS_SERVER) {
          SpdyHeadersIR headers_frame(stream_id, headers_.Clone());
          headers_frame.set_fin(fin);
          headers_frame.set_has_priority(true);
          headers_frame.set_weight(Spdy3PriorityToHttp2Weight(0));
          frame = framer_->SerializeFrame(headers_frame);
          EXPECT_CALL(session_, OnStreamHeadersPriority(
                                    stream_id, spdy::SpdyStreamPrecedence(0)));
        } else {
          SpdyHeadersIR headers_frame(stream_id, headers_.Clone());
          headers_frame.set_fin(fin);
          frame = framer_->SerializeFrame(headers_frame);
        }
        EXPECT_CALL(session_,
                    OnStreamHeaderList(stream_id, fin, frame.size(), _))
            .WillOnce(Invoke(this, &QuicHeadersStreamTest::SaveHeaderList));
        stream_frame_.data_buffer = frame.data();
        stream_frame_.data_length = frame.size();
        headers_stream_->OnStreamFrame(stream_frame_);
        stream_frame_.offset += frame.size();
        CheckHeaders();
      }
    }
  }
}

TEST_P(QuicHeadersStreamTest, ProcessBadData) {
  const char kBadData[] = "blah blah blah";
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA, _, _))
      .Times(::testing::AnyNumber());
  stream_frame_.data_buffer = kBadData;
  stream_frame_.data_length = strlen(kBadData);
  headers_stream_->OnStreamFrame(stream_frame_);
}

TEST_P(QuicHeadersStreamTest, ProcessSpdyDataFrame) {
  SpdyDataIR data(/* stream_id = */ 2, "ping");
  SpdySerializedFrame frame(framer_->SerializeFrame(data));

  EXPECT_CALL(*connection_, CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                                            "SPDY DATA frame received.", _))
      .WillOnce(InvokeWithoutArgs(
          this, &QuicHeadersStreamTest::TearDownLocalConnectionState));
  stream_frame_.data_buffer = frame.data();
  stream_frame_.data_length = frame.size();
  headers_stream_->OnStreamFrame(stream_frame_);
}

TEST_P(QuicHeadersStreamTest, ProcessSpdyRstStreamFrame) {
  SpdyRstStreamIR data(/* stream_id = */ 2, ERROR_CODE_PROTOCOL_ERROR);
  SpdySerializedFrame frame(framer_->SerializeFrame(data));
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                              "SPDY RST_STREAM frame received.", _))
      .WillOnce(InvokeWithoutArgs(
          this, &QuicHeadersStreamTest::TearDownLocalConnectionState));
  stream_frame_.data_buffer = frame.data();
  stream_frame_.data_length = frame.size();
  headers_stream_->OnStreamFrame(stream_frame_);
}

TEST_P(QuicHeadersStreamTest, RespectHttp2SettingsFrameSupportedFields) {
  const uint32_t kTestHeaderTableSize = 1000;
  SpdySettingsIR data;
  // Respect supported settings frames SETTINGS_HEADER_TABLE_SIZE,
  // SETTINGS_MAX_HEADER_LIST_SIZE.
  data.AddSetting(SETTINGS_HEADER_TABLE_SIZE, kTestHeaderTableSize);
  data.AddSetting(spdy::SETTINGS_MAX_HEADER_LIST_SIZE, 2000);
  SpdySerializedFrame frame(framer_->SerializeFrame(data));
  stream_frame_.data_buffer = frame.data();
  stream_frame_.data_length = frame.size();
  headers_stream_->OnStreamFrame(stream_frame_);
  EXPECT_EQ(kTestHeaderTableSize, QuicSpdySessionPeer::GetSpdyFramer(&session_)
                                      ->header_encoder_table_size());
}

// Regression test for b/208997000.
TEST_P(QuicHeadersStreamTest, LimitEncoderDynamicTableSize) {
  const uint32_t kVeryLargeTableSizeLimit = 1024 * 1024 * 1024;
  SpdySettingsIR data;
  data.AddSetting(SETTINGS_HEADER_TABLE_SIZE, kVeryLargeTableSizeLimit);
  SpdySerializedFrame frame(framer_->SerializeFrame(data));
  stream_frame_.data_buffer = frame.data();
  stream_frame_.data_length = frame.size();
  headers_stream_->OnStreamFrame(stream_frame_);
  EXPECT_EQ(16384u, QuicSpdySessionPeer::GetSpdyFramer(&session_)
                        ->header_encoder_table_size());
}

TEST_P(QuicHeadersStreamTest, RespectHttp2SettingsFrameUnsupportedFields) {
  SpdySettingsIR data;
  // Does not support SETTINGS_MAX_CONCURRENT_STREAMS,
  // SETTINGS_INITIAL_WINDOW_SIZE, SETTINGS_ENABLE_PUSH and
  // SETTINGS_MAX_FRAME_SIZE.
  data.AddSetting(SETTINGS_MAX_CONCURRENT_STREAMS, 100);
  data.AddSetting(SETTINGS_INITIAL_WINDOW_SIZE, 100);
  data.AddSetting(SETTINGS_ENABLE_PUSH, 1);
  data.AddSetting(SETTINGS_MAX_FRAME_SIZE, 1250);
  SpdySerializedFrame frame(framer_->SerializeFrame(data));
  EXPECT_CALL(*connection_,
              CloseConnection(
                  QUIC_INVALID_HEADERS_STREAM_DATA,
                  absl::StrCat("Unsupported field of HTTP/2 SETTINGS frame: ",
                               SETTINGS_MAX_CONCURRENT_STREAMS),
                  _));
  EXPECT_CALL(*connection_,
              CloseConnection(
                  QUIC_INVALID_HEADERS_STREAM_DATA,
                  absl::StrCat("Unsupported field of HTTP/2 SETTINGS frame: ",
                               SETTINGS_INITIAL_WINDOW_SIZE),
                  _));
  if (session_.perspective() == Perspective::IS_CLIENT) {
    EXPECT_CALL(*connection_,
                CloseConnection(
                    QUIC_INVALID_HEADERS_STREAM_DATA,
                    absl::StrCat("Unsupported field of HTTP/2 SETTINGS frame: ",
                                 SETTINGS_ENABLE_PUSH),
                    _));
  }
  EXPECT_CALL(*connection_,
              CloseConnection(
                  QUIC_INVALID_HEADERS_STREAM_DATA,
                  absl::StrCat("Unsupported field of HTTP/2 SETTINGS frame: ",
                               SETTINGS_MAX_FRAME_SIZE),
                  _));
  stream_frame_.data_buffer = frame.data();
  stream_frame_.data_length = frame.size();
  headers_stream_->OnStreamFrame(stream_frame_);
}

TEST_P(QuicHeadersStreamTest, ProcessSpdyPingFrame) {
  SpdyPingIR data(1);
  SpdySerializedFrame frame(framer_->SerializeFrame(data));
  EXPECT_CALL(*connection_, CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                                            "SPDY PING frame received.", _))
      .WillOnce(InvokeWithoutArgs(
          this, &QuicHeadersStreamTest::TearDownLocalConnectionState));
  stream_frame_.data_buffer = frame.data();
  stream_frame_.data_length = frame.size();
  headers_stream_->OnStreamFrame(stream_frame_);
}

TEST_P(QuicHeadersStreamTest, ProcessSpdyGoAwayFrame) {
  SpdyGoAwayIR data(/* last_good_stream_id = */ 1, ERROR_CODE_PROTOCOL_ERROR,
                    "go away");
  SpdySerializedFrame frame(framer_->SerializeFrame(data));
  EXPECT_CALL(*connection_, CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                                            "SPDY GOAWAY frame received.", _))
      .WillOnce(InvokeWithoutArgs(
          this, &QuicHeadersStreamTest::TearDownLocalConnectionState));
  stream_frame_.data_buffer = frame.data();
  stream_frame_.data_length = frame.size();
  headers_stream_->OnStreamFrame(stream_frame_);
}

TEST_P(QuicHeadersStreamTest, ProcessSpdyWindowUpdateFrame) {
  SpdyWindowUpdateIR data(/* stream_id = */ 1, /* delta = */ 1);
  SpdySerializedFrame frame(framer_->SerializeFrame(data));
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_INVALID_HEADERS_STREAM_DATA,
                              "SPDY WINDOW_UPDATE frame received.", _))
      .WillOnce(InvokeWithoutArgs(
          this, &QuicHeadersStreamTest::TearDownLocalConnectionState));
  stream_frame_.data_buffer = frame.data();
  stream_frame_.data_length = frame.size();
  headers_stream_->OnStreamFrame(stream_frame_);
}

TEST_P(QuicHeadersStreamTest, NoConnectionLevelFlowControl) {
  EXPECT_FALSE(QuicStreamPeer::StreamContributesToConnectionFlowControl(
      headers_stream_));
}

TEST_P(QuicHeadersStreamTest, AckSentData) {
  EXPECT_CALL(session_, WritevData(QuicUtils::GetHeadersStreamId(
                                       connection_->transport_version()),
                                   _, _, NO_FIN, _, _))
      .WillRepeatedly(Invoke(&session_, &MockQuicSpdySession::ConsumeData));
  InSequence s;
  quiche::QuicheReferenceCountedPointer<MockAckListener> ack_listener1(
      new MockAckListener());
  quiche::QuicheReferenceCountedPointer<MockAckListener> ack_listener2(
      new MockAckListener());
  quiche::QuicheReferenceCountedPointer<MockAckListener> ack_listener3(
      new MockAckListener());

  // Packet 1.
  headers_stream_->WriteOrBufferData("Header5", false, ack_listener1);
  headers_stream_->WriteOrBufferData("Header5", false, ack_listener1);
  headers_stream_->WriteOrBufferData("Header7", false, ack_listener2);

  // Packet 2.
  headers_stream_->WriteOrBufferData("Header9", false, ack_listener3);
  headers_stream_->WriteOrBufferData("Header7", false, ack_listener2);

  // Packet 3.
  headers_stream_->WriteOrBufferData("Header9", false, ack_listener3);

  // Packet 2 gets retransmitted.
  EXPECT_CALL(*ack_listener3, OnPacketRetransmitted(7)).Times(1);
  EXPECT_CALL(*ack_listener2, OnPacketRetransmitted(7)).Times(1);
  headers_stream_->OnStreamFrameRetransmitted(21, 7, false);
  headers_stream_->OnStreamFrameRetransmitted(28, 7, false);

  // Packets are acked in order: 2, 3, 1.
  QuicByteCount newly_acked_length = 0;
  EXPECT_CALL(*ack_listener3, OnPacketAcked(7, _));
  EXPECT_CALL(*ack_listener2, OnPacketAcked(7, _));
  EXPECT_TRUE(headers_stream_->OnStreamFrameAcked(
      21, 7, false, QuicTime::Delta::Zero(), QuicTime::Zero(),
      &newly_acked_length));
  EXPECT_EQ(7u, newly_acked_length);
  EXPECT_TRUE(headers_stream_->OnStreamFrameAcked(
      28, 7, false, QuicTime::Delta::Zero(), QuicTime::Zero(),
      &newly_acked_length));
  EXPECT_EQ(7u, newly_acked_length);

  EXPECT_CALL(*ack_listener3, OnPacketAcked(7, _));
  EXPECT_TRUE(headers_stream_->OnStreamFrameAcked(
      35, 7, false, QuicTime::Delta::Zero(), QuicTime::Zero(),
      &newly_acked_length));
  EXPECT_EQ(7u, newly_acked_length);

  EXPECT_CALL(*ack_listener1, OnPacketAcked(7, _));
  EXPECT_CALL(*ack_listener1, OnPacketAcked(7, _));
  EXPECT_TRUE(headers_stream_->OnStreamFrameAcked(
      0, 7, false, QuicTime::Delta::Zero(), QuicTime::Zero(),
      &newly_acked_length));
  EXPECT_EQ(7u, newly_acked_length);
  EXPECT_TRUE(headers_stream_->OnStreamFrameAcked(
      7, 7, false, QuicTime::Delta::Zero(), QuicTime::Zero(),
      &newly_acked_length));
  EXPECT_EQ(7u, newly_acked_length);
  // Unsent data is acked.
  EXPECT_CALL(*ack_listener2, OnPacketAcked(7, _));
  EXPECT_TRUE(headers_stream_->OnStreamFrameAcked(
      14, 10, false, QuicTime::Delta::Zero(), QuicTime::Zero(),
      &newly_acked_length));
  EXPECT_EQ(7u, newly_acked_length);
}

TEST_P(QuicHeadersStreamTest, FrameContainsMultipleHeaders) {
  // In this test, a stream frame can contain multiple headers.
  EXPECT_CALL(session_, WritevData(QuicUtils::GetHeadersStreamId(
                                       connection_->transport_version()),
                                   _, _, NO_FIN, _, _))
      .WillRepeatedly(Invoke(&session_, &MockQuicSpdySession::ConsumeData));
  InSequence s;
  quiche::QuicheReferenceCountedPointer<MockAckListener> ack_listener1(
      new MockAckListener());
  quiche::QuicheReferenceCountedPointer<MockAckListener> ack_listener2(
      new MockAckListener());
  quiche::QuicheReferenceCountedPointer<MockAckListener> ack_listener3(
      new MockAckListener());

  headers_stream_->WriteOrBufferData("Header5", false, ack_listener1);
  headers_stream_->WriteOrBufferData("Header5", false, ack_listener1);
  headers_stream_->WriteOrBufferData("Header7", false, ack_listener2);
  headers_stream_->WriteOrBufferData("Header9", false, ack_listener3);
  headers_stream_->WriteOrBufferData("Header7", false, ack_listener2);
  headers_stream_->WriteOrBufferData("Header9", false, ack_listener3);

  // Frame 1 is retransmitted.
  EXPECT_CALL(*ack_listener1, OnPacketRetransmitted(14));
  EXPECT_CALL(*ack_listener2, OnPacketRetransmitted(3));
  headers_stream_->OnStreamFrameRetransmitted(0, 17, false);

  // Frames are acked in order: 2, 3, 1.
  QuicByteCount newly_acked_length = 0;
  EXPECT_CALL(*ack_listener2, OnPacketAcked(4, _));
  EXPECT_CALL(*ack_listener3, OnPacketAcked(7, _));
  EXPECT_CALL(*ack_listener2, OnPacketAcked(2, _));
  EXPECT_TRUE(headers_stream_->OnStreamFrameAcked(
      17, 13, false, QuicTime::Delta::Zero(), QuicTime::Zero(),
      &newly_acked_length));
  EXPECT_EQ(13u, newly_acked_length);

  EXPECT_CALL(*ack_listener2, OnPacketAcked(5, _));
  EXPECT_CALL(*ack_listener3, OnPacketAcked(7, _));
  EXPECT_TRUE(headers_stream_->OnStreamFrameAcked(
      30,
"""


```