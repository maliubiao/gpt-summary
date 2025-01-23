Response:
Let's break down the thought process for analyzing this C++ test file and generating the comprehensive explanation.

1. **Understand the Core Purpose:** The filename `quic_receive_control_stream_test.cc` immediately tells us this file contains tests for the `QuicReceiveControlStream` class. The `.cc` extension signifies C++ source code. The `test` suffix confirms its testing nature.

2. **Identify Key Includes:**  The `#include` directives at the top are crucial. They reveal the dependencies and the context of the code:
    * `<ostream>`, `<string>`, `<vector>`: Standard C++ utilities for output, strings, and dynamic arrays.
    * `"absl/memory/memory.h"`, `"absl/strings/escaping.h"`, `"absl/strings/string_view.h"`:  Abseil libraries, likely for memory management and string manipulation (common in Chromium).
    * `"quiche/quic/core/http/http_constants.h"`:  Indicates this code is related to HTTP/3 (or a related QUIC-based protocol) and its constants.
    * `"quiche/quic/core/qpack/qpack_header_table.h"`:  Points to QPACK, the header compression mechanism in HTTP/3.
    * `"quiche/quic/core/quic_types.h"`, `"quiche/quic/core/quic_utils.h"`: Core QUIC types and utilities.
    * `"quiche/quic/test_tools/...`":  These includes signal that this is a testing file, and it's using mock objects and utilities specifically designed for testing the QUIC stack.

3. **Recognize Testing Framework:** The presence of `::testing::_`, `::testing::AnyNumber`, `::testing::StrictMock`, and the class `QuicTestWithParam` strongly suggest the use of Google Test (gtest) framework. This tells us the file contains test cases organized using `TEST_P` (parameterized tests) and standard gtest assertions (though they're often within the mock object expectations).

4. **Analyze the `TestParams` Structure:** This structure defines the parameters used for the parameterized tests. It holds the `ParsedQuicVersion` and the `Perspective` (client or server). This immediately tells us the tests are designed to cover different QUIC versions and both client and server roles.

5. **Examine the `GetTestParams()` Function:** This function generates the different combinations of `ParsedQuicVersion` and `Perspective` to be used by the parameterized tests. The filtering logic (`VersionUsesHttp3`) confirms the focus on HTTP/3.

6. **Understand Mock Objects:** The code uses `StrictMock<MockQuicConnection>`, `StrictMock<MockQuicSpdySession>`, and likely other mock objects through the test tools. This means the tests are isolating the `QuicReceiveControlStream` and controlling the behavior of its dependencies. The `EXPECT_CALL` macros define the expected interactions with these mock objects.

7. **Trace the Setup in `QuicReceiveControlStreamTest::QuicReceiveControlStreamTest()`:** This constructor is crucial for understanding the test environment:
    * It creates mock `QuicConnection` and `QuicSpdySession` objects.
    * It initializes the session.
    * It simulates the creation of a control stream by sending a `kControlStream` type.
    * It retrieves the `QuicReceiveControlStream` being tested.
    * It creates a regular bidirectional stream (`TestStream`), likely to simulate other stream activity.

8. **Analyze Individual `TEST_P` Cases:**  Each `TEST_P` function tests a specific scenario:
    * `ResetControlStream`: Tests how the control stream handles a reset.
    * `ReceiveSettings`: Tests processing of a valid `SETTINGS` frame.
    * `ReceiveSettingsTwice`:  Tests handling of a duplicate `SETTINGS` frame (an error condition).
    * `ReceiveSettingsFragments`: Tests handling of fragmented `SETTINGS` frames.
    * `ReceiveWrongFrame`: Tests handling of an unexpected frame type.
    * `ReceivePriorityUpdateFrameBeforeSettingsFrame`: Tests the order of frame reception.
    * `ReceiveGoAwayFrame`: Tests processing of a `GOAWAY` frame.
    * `PushPromiseOnControlStreamShouldClose`: Tests that a `PUSH_PROMISE` frame on the control stream is an error.
    * `ConsumeUnknownFrame`/`ReceiveUnknownFrame`: Tests how unknown frame types are handled.
    * `CancelPushFrameBeforeSettings`/`AcceptChFrameBeforeSettings`/`ReceiveAcceptChFrame`/`ReceiveOriginFrame`/`UnknownFrameBeforeSettings`: Tests handling of various frame types, especially the requirement for the `SETTINGS` frame to come first.

9. **Connect to JavaScript (If Applicable):** Think about how the tested functionality relates to web browsers and JavaScript. HTTP/3 is the underlying protocol for modern web communication. Settings, header compression, and error handling directly impact how a browser interacts with a server.

10. **Consider User/Programming Errors:**  Think about what mistakes developers or network configurations might cause that these tests are designed to catch. For instance, sending the wrong type of frame, sending frames in the wrong order, or sending duplicate critical frames like `SETTINGS`.

11. **Imagine the Debugging Process:** How would a developer end up looking at this test file? They might be investigating a bug related to control stream handling, HTTP/3 connection errors, or frame parsing issues. The test setup and the specific error conditions tested provide clues.

12. **Structure the Explanation:** Organize the findings logically, starting with a high-level overview, then detailing specific functionalities, JavaScript relevance, logic, errors, and debugging context. Use clear headings and examples.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  "This is just a test file."  **Correction:** It's a *specific* test file for a *critical* part of the QUIC/HTTP/3 stack (the control stream).
* **Focusing Too Narrowly:** Initially focus only on the C++ code. **Correction:**  Remember the prompt asked about JavaScript relevance and user scenarios, requiring a broader perspective.
* **Missing the "Why":** Simply listing the tests isn't enough. **Correction:** Explain *what* each test is verifying and *why* that's important.
* **Ignoring the "How":** The setup in the constructor is key. **Correction:**  Analyze the initialization process carefully to understand the test environment.
* **Not Connecting the Dots:** Fail to link the low-level C++ details to higher-level concepts like HTTP/3 and browser behavior. **Correction:**  Explicitly draw these connections.

By following these steps and being willing to refine the analysis, one can arrive at a comprehensive and informative explanation like the example provided.
这个文件 `net/third_party/quiche/src/quiche/quic/core/http/quic_receive_control_stream_test.cc` 是 Chromium 网络栈中 QUIC 协议 HTTP/3 实现的一部分，专门用于测试 `QuicReceiveControlStream` 类的功能。

以下是该文件的功能列表：

1. **测试 `QuicReceiveControlStream` 的创建和初始化:**  该文件设置了测试环境，包括模拟的 QUIC 连接和会话，并创建了一个 `QuicReceiveControlStream` 实例。
2. **测试控制流的重置 (Reset):**  `TEST_P(QuicReceiveControlStreamTest, ResetControlStream)` 测试了当接收到 RST_STREAM 帧时，控制流是否能够正确处理并关闭连接。
3. **测试接收 SETTINGS 帧:**  `TEST_P(QuicReceiveControlStreamTest, ReceiveSettings)` 测试了 `QuicReceiveControlStream` 如何正确解析和处理 HTTP/3 的 SETTINGS 帧，并更新会话的相应参数，例如 `max_outbound_header_list_size`、QPACK 相关设置。
4. **测试接收重复的 SETTINGS 帧:** `TEST_P(QuicReceiveControlStreamTest, ReceiveSettingsTwice)` 验证了当接收到第二个 SETTINGS 帧时，连接会因为违反协议而被关闭。这是因为 HTTP/3 规范规定 SETTINGS 帧只能发送一次。
5. **测试接收分片的 SETTINGS 帧:** `TEST_P(QuicReceiveControlStreamTest, ReceiveSettingsFragments)` 检查了 `QuicReceiveControlStream` 是否能够正确处理分段到达的 SETTINGS 帧。
6. **测试接收错误的帧类型:** `TEST_P(QuicReceiveControlStreamTest, ReceiveWrongFrame)` 验证了当在控制流上接收到非法的帧类型（例如 DATA 帧）时，连接会正确关闭。
7. **测试在 SETTINGS 帧之前接收到 PRIORITY_UPDATE 帧:** `TEST_P(QuicReceiveControlStreamTest, ReceivePriorityUpdateFrameBeforeSettingsFrame)` 检查了在接收到 SETTINGS 帧之前接收到其他控制帧（如 PRIORITY_UPDATE）时，连接是否会因为违反协议顺序而关闭。HTTP/3 要求控制流的第一个帧必须是 SETTINGS 帧。
8. **测试接收 GOAWAY 帧:** `TEST_P(QuicReceiveControlStreamTest, ReceiveGoAwayFrame)` 测试了 `QuicReceiveControlStream` 如何处理 GOAWAY 帧，并更新会话状态以指示已接收到 GOAWAY。
9. **测试在控制流上接收到 PUSH_PROMISE 帧:** `TEST_P(QuicReceiveControlStreamTest, PushPromiseOnControlStreamShouldClose)` 验证了在控制流上接收到 PUSH_PROMISE 帧会导致连接关闭，因为 PUSH_PROMISE 帧只能在请求流上发送。
10. **测试消费未知帧:** `TEST_P(QuicReceiveControlStreamTest, ConsumeUnknownFrame)` 和 `TEST_P(QuicReceiveControlStreamTest, ReceiveUnknownFrame)` 测试了当接收到未知的、保留的帧类型时，`QuicReceiveControlStream` 是否能够正确地跳过并继续处理后续帧，或者在 debug 模式下通知调试访问器。
11. **测试在 SETTINGS 帧之前接收到 CANCEL_PUSH 帧:** `TEST_P(QuicReceiveControlStreamTest, CancelPushFrameBeforeSettings)` 验证了在接收到 SETTINGS 帧之前接收到 CANCEL_PUSH 帧会导致连接关闭。
12. **测试在 SETTINGS 帧之前接收到 ACCEPT_CH 帧:** `TEST_P(QuicReceiveControlStreamTest, AcceptChFrameBeforeSettings)` 检查了在接收到 SETTINGS 帧之前接收到 ACCEPT_CH 帧时的行为。根据客户端和服务器的角色，可能会关闭连接。
13. **测试接收 ACCEPT_CH 帧:** `TEST_P(QuicReceiveControlStreamTest, ReceiveAcceptChFrame)` 测试了 `QuicReceiveControlStream` 如何处理 ACCEPT_CH 帧。
14. **测试接收 ORIGIN 帧:** `TEST_P(QuicReceiveControlStreamTest, ReceiveOriginFrame)` 测试了 `QuicReceiveControlStream` 如何处理 ORIGIN 帧。
15. **测试在 SETTINGS 帧之前接收到未知帧:** `TEST_P(QuicReceiveControlStreamTest, UnknownFrameBeforeSettings)` 验证了在接收到 SETTINGS 帧之前接收到任何未知帧都会导致连接关闭。

**与 JavaScript 的功能关系:**

虽然这个 C++ 代码本身并不直接包含 JavaScript，但它所测试的功能是构成现代 Web 浏览器与服务器通信基础的关键部分。

* **SETTINGS 帧:** JavaScript 通过浏览器的网络 API (例如 `fetch`) 发起 HTTP/3 请求。浏览器和服务器通过 SETTINGS 帧协商连接参数，例如最大头部列表大小、QPACK 的设置等。这些参数会影响浏览器如何编码和解码 HTTP 头部，以及服务器如何处理这些头部。
* **GOAWAY 帧:** 当服务器希望关闭连接时，会发送 GOAWAY 帧。浏览器接收到 GOAWAY 帧后，可能会停止在该连接上发送新的请求，并可能尝试在新的连接上重试。这直接影响 JavaScript 发起的网络请求的生命周期。
* **错误处理和连接关闭:** 当违反 HTTP/3 协议规则时（例如发送错误的帧序列），连接会被关闭。这会导致 JavaScript 发起的请求失败，浏览器会通过网络 API 的错误回调通知 JavaScript。

**举例说明:**

假设一个 JavaScript 应用使用 `fetch` API 发起一个 HTTP/3 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data))
  .catch(error => console.error("请求失败:", error));
```

在这个过程中，底层的 Chromium 网络栈会使用 `QuicReceiveControlStream` 来处理服务器发送的控制帧。如果服务器错误地发送了两个 SETTINGS 帧，`QuicReceiveControlStreamTest` 中的 `ReceiveSettingsTwice` 测试覆盖了这种情况。测试验证了 C++ 代码会正确地关闭连接，这最终会导致 JavaScript 的 `fetch` API 的 `catch` 回调被触发，`error` 对象会包含连接关闭的信息。

**逻辑推理、假设输入与输出:**

考虑 `TEST_P(QuicReceiveControlStreamTest, ReceiveSettings)`:

* **假设输入:**  接收到的数据流包含一个合法的 HTTP/3 SETTINGS 帧。
* **帧内容示例 (二进制):**  假设 SETTINGS 帧设置了 `SETTINGS_MAX_FIELD_SECTION_SIZE` 为 1024。其二进制表示可能类似于 `04000400` (假设使用 varint 编码)。
* **预期输出:**
    * `session_.max_outbound_header_list_size()` 的值会被更新为 1024。
    * QPACK 相关的设置（如果 SETTINGS 帧中包含）也会被相应更新。
    * 连接不会被关闭。

考虑 `TEST_P(QuicReceiveControlStreamTest, ReceiveSettingsTwice)`:

* **假设输入:**  接收到的数据流包含两个连续的 HTTP/3 SETTINGS 帧。
* **帧内容示例 (二进制):** 两次合法的 SETTINGS 帧，例如 `04000400...04000400...`
* **预期输出:**
    * 连接会被 `CloseConnection` 函数关闭，错误码为 `QUIC_HTTP_INVALID_FRAME_SEQUENCE_ON_CONTROL_STREAM`，错误描述为 "SETTINGS frame can only be received once."。
    * 会调用 `session_.OnConnectionClosed(_, _)`。

**用户或编程常见的使用错误:**

1. **服务器端错误地发送了多个 SETTINGS 帧:**  这是 HTTP/3 协议的违规行为。`ReceiveSettingsTwice` 测试覆盖了这种情况。如果服务器的 HTTP/3 实现存在 bug，可能会发生这种情况。
2. **服务器端在 SETTINGS 帧之前发送了其他控制帧:**  HTTP/3 要求控制流的第一个帧必须是 SETTINGS 帧。如果服务器的实现不正确，可能会先发送其他帧。例如，发送 PRIORITY_UPDATE 或 CANCEL_PUSH 帧。相关的测试用例 (`ReceivePriorityUpdateFrameBeforeSettingsFrame`, `CancelPushFrameBeforeSettings`) 验证了客户端会正确处理这些错误。
3. **服务器端在控制流上发送了 PUSH_PROMISE 帧:**  PUSH_PROMISE 帧只能在请求流上发送。如果服务器实现错误地在控制流上发送了 PUSH_PROMISE，`PushPromiseOnControlStreamShouldClose` 测试确保客户端会关闭连接。
4. **中间件或代理错误地修改了控制流的内容:**  如果网络中的中间件或代理不正确地处理 HTTP/3 控制流，可能会导致发送错误的帧类型或错误的帧顺序，从而触发这些测试用例中定义的错误处理逻辑。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中访问一个使用 HTTP/3 的网站。**
2. **浏览器发起与服务器的 QUIC 连接。**
3. **在 QUIC 连接建立后，浏览器或服务器会创建一个 HTTP/3 控制流。**
4. **服务器开始在控制流上发送 HTTP/3 控制帧，例如 SETTINGS 帧。**
5. **如果在服务器的 HTTP/3 实现中存在 bug，例如在发送完 SETTINGS 帧后，又错误地发送了另一个 SETTINGS 帧。**
6. **浏览器的网络栈接收到第二个 SETTINGS 帧，`QuicReceiveControlStream::OnStreamFrame` 会被调用处理该帧。**
7. **`QuicReceiveControlStream` 内部的 HTTP 解码器会检测到接收到了第二个 SETTINGS 帧，这违反了协议。**
8. **`QuicReceiveControlStream` 会调用 `connection_->CloseConnection` 来关闭 QUIC 连接，并附带相应的错误码和错误信息。**
9. **在 Chromium 的开发者工具的网络面板中，用户可能会看到连接被关闭，并显示相应的错误信息，例如 "QUIC_HTTP_INVALID_FRAME_SEQUENCE_ON_CONTROL_STREAM"。**
10. **如果开发者正在调试这个问题，他们可能会查看 Chromium 网络栈的日志，发现与 `QuicReceiveControlStream` 相关的错误信息。**
11. **为了理解问题的根源，开发者可能会查阅 `quic_receive_control_stream_test.cc` 这个测试文件，了解 Chromium 是如何测试和处理接收到重复 SETTINGS 帧的情况的。** 这个测试文件可以帮助开发者理解预期的行为以及如何验证其修复方案的正确性。

总而言之，`quic_receive_control_stream_test.cc` 文件对于确保 Chromium 的 HTTP/3 控制流处理逻辑的正确性和健壮性至关重要，它通过各种测试用例覆盖了正常情况和异常情况，帮助开发者预防和调试与 HTTP/3 控制流相关的错误。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/quic_receive_control_stream_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/http/quic_receive_control_stream.h"

#include <ostream>
#include <string>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/http/http_constants.h"
#include "quiche/quic/core/qpack/qpack_header_table.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/test_tools/qpack/qpack_encoder_peer.h"
#include "quiche/quic/test_tools/quic_spdy_session_peer.h"
#include "quiche/quic/test_tools/quic_stream_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/simple_buffer_allocator.h"

namespace quic {

class QpackEncoder;

namespace test {

namespace {
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::StrictMock;

struct TestParams {
  TestParams(const ParsedQuicVersion& version, Perspective perspective)
      : version(version), perspective(perspective) {
    QUIC_LOG(INFO) << "TestParams: " << *this;
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
  for (const auto& version : AllSupportedVersions()) {
    if (!VersionUsesHttp3(version.transport_version)) {
      continue;
    }
    for (Perspective p : {Perspective::IS_SERVER, Perspective::IS_CLIENT}) {
      params.emplace_back(version, p);
    }
  }
  return params;
}

class TestStream : public QuicSpdyStream {
 public:
  TestStream(QuicStreamId id, QuicSpdySession* session)
      : QuicSpdyStream(id, session, BIDIRECTIONAL) {}
  ~TestStream() override = default;

  void OnBodyAvailable() override {}
};

class QuicReceiveControlStreamTest : public QuicTestWithParam<TestParams> {
 public:
  QuicReceiveControlStreamTest()
      : connection_(new StrictMock<MockQuicConnection>(
            &helper_, &alarm_factory_, perspective(),
            SupportedVersions(GetParam().version))),
        session_(connection_) {
    EXPECT_CALL(session_, OnCongestionWindowChange(_)).Times(AnyNumber());
    session_.Initialize();
    EXPECT_CALL(
        static_cast<const MockQuicCryptoStream&>(*session_.GetCryptoStream()),
        encryption_established())
        .WillRepeatedly(testing::Return(true));
    QuicStreamId id = perspective() == Perspective::IS_SERVER
                          ? GetNthClientInitiatedUnidirectionalStreamId(
                                session_.transport_version(), 3)
                          : GetNthServerInitiatedUnidirectionalStreamId(
                                session_.transport_version(), 3);
    char type[] = {kControlStream};

    QuicStreamFrame data1(id, false, 0, absl::string_view(type, 1));
    session_.OnStreamFrame(data1);

    receive_control_stream_ =
        QuicSpdySessionPeer::GetReceiveControlStream(&session_);

    stream_ = new TestStream(GetNthClientInitiatedBidirectionalStreamId(
                                 GetParam().version.transport_version, 0),
                             &session_);
    session_.ActivateStream(absl::WrapUnique(stream_));
  }

  Perspective perspective() const { return GetParam().perspective; }

  QuicStreamOffset NumBytesConsumed() {
    return QuicStreamPeer::sequencer(receive_control_stream_)
        ->NumBytesConsumed();
  }

  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  StrictMock<MockQuicConnection>* connection_;
  StrictMock<MockQuicSpdySession> session_;
  QuicReceiveControlStream* receive_control_stream_;
  TestStream* stream_;
};

INSTANTIATE_TEST_SUITE_P(Tests, QuicReceiveControlStreamTest,
                         ::testing::ValuesIn(GetTestParams()),
                         ::testing::PrintToStringParamName());

TEST_P(QuicReceiveControlStreamTest, ResetControlStream) {
  EXPECT_TRUE(receive_control_stream_->is_static());
  QuicRstStreamFrame rst_frame(kInvalidControlFrameId,
                               receive_control_stream_->id(),
                               QUIC_STREAM_CANCELLED, 1234);
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_HTTP_CLOSED_CRITICAL_STREAM, _, _));
  receive_control_stream_->OnStreamReset(rst_frame);
}

TEST_P(QuicReceiveControlStreamTest, ReceiveSettings) {
  SettingsFrame settings;
  settings.values[10] = 2;
  settings.values[SETTINGS_MAX_FIELD_SECTION_SIZE] = 5;
  settings.values[SETTINGS_QPACK_BLOCKED_STREAMS] = 12;
  settings.values[SETTINGS_QPACK_MAX_TABLE_CAPACITY] = 37;
  std::string data = HttpEncoder::SerializeSettingsFrame(settings);
  QuicStreamFrame frame(receive_control_stream_->id(), false, 1, data);

  QpackEncoder* qpack_encoder = session_.qpack_encoder();
  QpackEncoderHeaderTable* header_table =
      QpackEncoderPeer::header_table(qpack_encoder);
  EXPECT_EQ(std::numeric_limits<size_t>::max(),
            session_.max_outbound_header_list_size());
  EXPECT_EQ(0u, QpackEncoderPeer::maximum_blocked_streams(qpack_encoder));
  EXPECT_EQ(0u, header_table->maximum_dynamic_table_capacity());

  receive_control_stream_->OnStreamFrame(frame);

  EXPECT_EQ(5u, session_.max_outbound_header_list_size());
  EXPECT_EQ(12u, QpackEncoderPeer::maximum_blocked_streams(qpack_encoder));
  EXPECT_EQ(37u, header_table->maximum_dynamic_table_capacity());
}

// Regression test for https://crbug.com/982648.
// QuicReceiveControlStream::OnDataAvailable() must stop processing input as
// soon as OnSettingsFrameStart() is called by HttpDecoder for the second frame.
TEST_P(QuicReceiveControlStreamTest, ReceiveSettingsTwice) {
  SettingsFrame settings;
  // Reserved identifiers, must be ignored.
  settings.values[0x21] = 100;
  settings.values[0x40] = 200;

  std::string settings_frame = HttpEncoder::SerializeSettingsFrame(settings);

  QuicStreamOffset offset = 1;
  EXPECT_EQ(offset, NumBytesConsumed());

  // Receive first SETTINGS frame.
  receive_control_stream_->OnStreamFrame(
      QuicStreamFrame(receive_control_stream_->id(), /* fin = */ false, offset,
                      settings_frame));
  offset += settings_frame.length();

  // First SETTINGS frame is consumed.
  EXPECT_EQ(offset, NumBytesConsumed());

  // Second SETTINGS frame causes the connection to be closed.
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_HTTP_INVALID_FRAME_SEQUENCE_ON_CONTROL_STREAM,
                      "SETTINGS frame can only be received once.", _))
      .WillOnce(
          Invoke(connection_, &MockQuicConnection::ReallyCloseConnection));
  EXPECT_CALL(*connection_, SendConnectionClosePacket(_, _, _));
  EXPECT_CALL(session_, OnConnectionClosed(_, _));

  // Receive second SETTINGS frame.
  receive_control_stream_->OnStreamFrame(
      QuicStreamFrame(receive_control_stream_->id(), /* fin = */ false, offset,
                      settings_frame));

  // Frame header of second SETTINGS frame is consumed, but not frame payload.
  QuicByteCount settings_frame_header_length = 2;
  EXPECT_EQ(offset + settings_frame_header_length, NumBytesConsumed());
}

TEST_P(QuicReceiveControlStreamTest, ReceiveSettingsFragments) {
  SettingsFrame settings;
  settings.values[10] = 2;
  settings.values[SETTINGS_MAX_FIELD_SECTION_SIZE] = 5;
  std::string data = HttpEncoder::SerializeSettingsFrame(settings);
  std::string data1 = data.substr(0, 1);
  std::string data2 = data.substr(1, data.length() - 1);

  QuicStreamFrame frame(receive_control_stream_->id(), false, 1, data1);
  QuicStreamFrame frame2(receive_control_stream_->id(), false, 2, data2);
  EXPECT_NE(5u, session_.max_outbound_header_list_size());
  receive_control_stream_->OnStreamFrame(frame);
  receive_control_stream_->OnStreamFrame(frame2);
  EXPECT_EQ(5u, session_.max_outbound_header_list_size());
}

TEST_P(QuicReceiveControlStreamTest, ReceiveWrongFrame) {
  // DATA frame header without payload.
  quiche::QuicheBuffer data = HttpEncoder::SerializeDataFrameHeader(
      /* payload_length = */ 2, quiche::SimpleBufferAllocator::Get());

  QuicStreamFrame frame(receive_control_stream_->id(), false, 1,
                        data.AsStringView());
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_HTTP_FRAME_UNEXPECTED_ON_CONTROL_STREAM, _, _));
  receive_control_stream_->OnStreamFrame(frame);
}

TEST_P(QuicReceiveControlStreamTest,
       ReceivePriorityUpdateFrameBeforeSettingsFrame) {
  std::string serialized_frame = HttpEncoder::SerializePriorityUpdateFrame({});
  QuicStreamFrame data(receive_control_stream_->id(), /* fin = */ false,
                       /* offset = */ 1, serialized_frame);

  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_HTTP_MISSING_SETTINGS_FRAME,
                              "First frame received on control stream is type "
                              "984832, but it must be SETTINGS.",
                              _))
      .WillOnce(
          Invoke(connection_, &MockQuicConnection::ReallyCloseConnection));
  EXPECT_CALL(*connection_, SendConnectionClosePacket(_, _, _));
  EXPECT_CALL(session_, OnConnectionClosed(_, _));

  receive_control_stream_->OnStreamFrame(data);
}

TEST_P(QuicReceiveControlStreamTest, ReceiveGoAwayFrame) {
  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_.set_debug_visitor(&debug_visitor);

  QuicStreamOffset offset = 1;

  // Receive SETTINGS frame.
  SettingsFrame settings;
  std::string settings_frame = HttpEncoder::SerializeSettingsFrame(settings);
  EXPECT_CALL(debug_visitor, OnSettingsFrameReceived(settings));
  receive_control_stream_->OnStreamFrame(
      QuicStreamFrame(receive_control_stream_->id(), /* fin = */ false, offset,
                      settings_frame));
  offset += settings_frame.length();

  GoAwayFrame goaway{/* id = */ 0};
  std::string goaway_frame = HttpEncoder::SerializeGoAwayFrame(goaway);
  QuicStreamFrame frame(receive_control_stream_->id(), false, offset,
                        goaway_frame);

  EXPECT_FALSE(session_.goaway_received());

  EXPECT_CALL(debug_visitor, OnGoAwayFrameReceived(goaway));
  receive_control_stream_->OnStreamFrame(frame);

  EXPECT_TRUE(session_.goaway_received());
}

TEST_P(QuicReceiveControlStreamTest, PushPromiseOnControlStreamShouldClose) {
  std::string push_promise_frame;
  ASSERT_TRUE(
      absl::HexStringToBytes("05"   // PUSH_PROMISE
                             "01"   // length
                             "00",  // push ID
                             &push_promise_frame));
  QuicStreamFrame frame(receive_control_stream_->id(), false, 1,
                        push_promise_frame);
  EXPECT_CALL(*connection_, CloseConnection(QUIC_HTTP_FRAME_ERROR, _, _))
      .WillOnce(
          Invoke(connection_, &MockQuicConnection::ReallyCloseConnection));
  EXPECT_CALL(*connection_, SendConnectionClosePacket(_, _, _));
  EXPECT_CALL(session_, OnConnectionClosed(_, _));
  receive_control_stream_->OnStreamFrame(frame);
}

// Regression test for b/137554973: unknown frames should be consumed.
TEST_P(QuicReceiveControlStreamTest, ConsumeUnknownFrame) {
  EXPECT_EQ(1u, NumBytesConsumed());

  QuicStreamOffset offset = 1;

  // Receive SETTINGS frame.
  std::string settings_frame = HttpEncoder::SerializeSettingsFrame({});
  receive_control_stream_->OnStreamFrame(
      QuicStreamFrame(receive_control_stream_->id(), /* fin = */ false, offset,
                      settings_frame));
  offset += settings_frame.length();

  // SETTINGS frame is consumed.
  EXPECT_EQ(offset, NumBytesConsumed());

  // Receive unknown frame.
  std::string unknown_frame;
  ASSERT_TRUE(
      absl::HexStringToBytes("21"       // reserved frame type
                             "03"       // payload length
                             "666f6f",  // payload "foo"
                             &unknown_frame));

  receive_control_stream_->OnStreamFrame(QuicStreamFrame(
      receive_control_stream_->id(), /* fin = */ false, offset, unknown_frame));
  offset += unknown_frame.size();

  // Unknown frame is consumed.
  EXPECT_EQ(offset, NumBytesConsumed());
}

TEST_P(QuicReceiveControlStreamTest, ReceiveUnknownFrame) {
  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_.set_debug_visitor(&debug_visitor);

  const QuicStreamId id = receive_control_stream_->id();
  QuicStreamOffset offset = 1;

  // Receive SETTINGS frame.
  SettingsFrame settings;
  std::string settings_frame = HttpEncoder::SerializeSettingsFrame(settings);
  EXPECT_CALL(debug_visitor, OnSettingsFrameReceived(settings));
  receive_control_stream_->OnStreamFrame(
      QuicStreamFrame(id, /* fin = */ false, offset, settings_frame));
  offset += settings_frame.length();

  // Receive unknown frame.
  std::string unknown_frame;
  ASSERT_TRUE(
      absl::HexStringToBytes("21"       // reserved frame type
                             "03"       // payload length
                             "666f6f",  // payload "foo"
                             &unknown_frame));

  EXPECT_CALL(debug_visitor, OnUnknownFrameReceived(id, /* frame_type = */ 0x21,
                                                    /* payload_length = */ 3));
  receive_control_stream_->OnStreamFrame(
      QuicStreamFrame(id, /* fin = */ false, offset, unknown_frame));
}

TEST_P(QuicReceiveControlStreamTest, CancelPushFrameBeforeSettings) {
  std::string cancel_push_frame;
  ASSERT_TRUE(
      absl::HexStringToBytes("03"   // type CANCEL_PUSH
                             "01"   // payload length
                             "01",  // push ID
                             &cancel_push_frame));

  EXPECT_CALL(*connection_, CloseConnection(QUIC_HTTP_FRAME_ERROR,
                                            "CANCEL_PUSH frame received.", _))
      .WillOnce(
          Invoke(connection_, &MockQuicConnection::ReallyCloseConnection));
  EXPECT_CALL(*connection_, SendConnectionClosePacket(_, _, _));
  EXPECT_CALL(session_, OnConnectionClosed(_, _));

  receive_control_stream_->OnStreamFrame(
      QuicStreamFrame(receive_control_stream_->id(), /* fin = */ false,
                      /* offset = */ 1, cancel_push_frame));
}

TEST_P(QuicReceiveControlStreamTest, AcceptChFrameBeforeSettings) {
  std::string accept_ch_frame;
  ASSERT_TRUE(
      absl::HexStringToBytes("4089"  // type (ACCEPT_CH)
                             "00",   // length
                             &accept_ch_frame));

  if (perspective() == Perspective::IS_SERVER) {
    EXPECT_CALL(*connection_,
                CloseConnection(
                    QUIC_HTTP_FRAME_UNEXPECTED_ON_CONTROL_STREAM,
                    "Invalid frame type 137 received on control stream.", _))
        .WillOnce(
            Invoke(connection_, &MockQuicConnection::ReallyCloseConnection));
  } else {
    EXPECT_CALL(*connection_,
                CloseConnection(QUIC_HTTP_MISSING_SETTINGS_FRAME,
                                "First frame received on control stream is "
                                "type 137, but it must be SETTINGS.",
                                _))
        .WillOnce(
            Invoke(connection_, &MockQuicConnection::ReallyCloseConnection));
  }
  EXPECT_CALL(*connection_, SendConnectionClosePacket(_, _, _));
  EXPECT_CALL(session_, OnConnectionClosed(_, _));

  receive_control_stream_->OnStreamFrame(
      QuicStreamFrame(receive_control_stream_->id(), /* fin = */ false,
                      /* offset = */ 1, accept_ch_frame));
}

TEST_P(QuicReceiveControlStreamTest, ReceiveAcceptChFrame) {
  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_.set_debug_visitor(&debug_visitor);

  const QuicStreamId id = receive_control_stream_->id();
  QuicStreamOffset offset = 1;

  // Receive SETTINGS frame.
  SettingsFrame settings;
  std::string settings_frame = HttpEncoder::SerializeSettingsFrame(settings);
  EXPECT_CALL(debug_visitor, OnSettingsFrameReceived(settings));
  receive_control_stream_->OnStreamFrame(
      QuicStreamFrame(id, /* fin = */ false, offset, settings_frame));
  offset += settings_frame.length();

  // Receive ACCEPT_CH frame.
  std::string accept_ch_frame;
  ASSERT_TRUE(
      absl::HexStringToBytes("4089"  // type (ACCEPT_CH)
                             "00",   // length
                             &accept_ch_frame));

  if (perspective() == Perspective::IS_CLIENT) {
    EXPECT_CALL(debug_visitor, OnAcceptChFrameReceived(_));
  } else {
    EXPECT_CALL(*connection_,
                CloseConnection(
                    QUIC_HTTP_FRAME_UNEXPECTED_ON_CONTROL_STREAM,
                    "Invalid frame type 137 received on control stream.", _))
        .WillOnce(
            Invoke(connection_, &MockQuicConnection::ReallyCloseConnection));
    EXPECT_CALL(*connection_, SendConnectionClosePacket(_, _, _));
    EXPECT_CALL(session_, OnConnectionClosed(_, _));
  }

  receive_control_stream_->OnStreamFrame(
      QuicStreamFrame(id, /* fin = */ false, offset, accept_ch_frame));
}

TEST_P(QuicReceiveControlStreamTest, ReceiveOriginFrame) {
  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_.set_debug_visitor(&debug_visitor);

  const QuicStreamId id = receive_control_stream_->id();
  QuicStreamOffset offset = 1;

  // Receive SETTINGS frame.
  SettingsFrame settings;
  std::string settings_frame = HttpEncoder::SerializeSettingsFrame(settings);
  EXPECT_CALL(debug_visitor, OnSettingsFrameReceived(settings));
  receive_control_stream_->OnStreamFrame(
      QuicStreamFrame(id, /* fin = */ false, offset, settings_frame));
  offset += settings_frame.length();

  // Receive ORIGIN frame.
  std::string origin_frame;
  ASSERT_TRUE(
      absl::HexStringToBytes("0C"   // type (ORIGIN)
                             "00",  // length
                             &origin_frame));

  if (GetQuicReloadableFlag(enable_h3_origin_frame)) {
    if (perspective() == Perspective::IS_CLIENT) {
      EXPECT_CALL(debug_visitor, OnOriginFrameReceived(_));
    } else {
      EXPECT_CALL(*connection_,
                  CloseConnection(
                      QUIC_HTTP_FRAME_UNEXPECTED_ON_CONTROL_STREAM,
                      "Invalid frame type 12 received on control stream.", _))
          .WillOnce(
              Invoke(connection_, &MockQuicConnection::ReallyCloseConnection));
      EXPECT_CALL(*connection_, SendConnectionClosePacket(_, _, _));
      EXPECT_CALL(session_, OnConnectionClosed(_, _));
    }
  } else {
    EXPECT_CALL(debug_visitor,
                OnUnknownFrameReceived(id, /* frame_type = */ 0x0c,
                                       /* payload_length = */ 0));
  }

  receive_control_stream_->OnStreamFrame(
      QuicStreamFrame(id, /* fin = */ false, offset, origin_frame));
}

TEST_P(QuicReceiveControlStreamTest, UnknownFrameBeforeSettings) {
  std::string unknown_frame;
  ASSERT_TRUE(
      absl::HexStringToBytes("21"       // reserved frame type
                             "03"       // payload length
                             "666f6f",  // payload "foo"
                             &unknown_frame));

  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_HTTP_MISSING_SETTINGS_FRAME,
                              "First frame received on control stream is type "
                              "33, but it must be SETTINGS.",
                              _))
      .WillOnce(
          Invoke(connection_, &MockQuicConnection::ReallyCloseConnection));
  EXPECT_CALL(*connection_, SendConnectionClosePacket(_, _, _));
  EXPECT_CALL(session_, OnConnectionClosed(_, _));

  receive_control_stream_->OnStreamFrame(
      QuicStreamFrame(receive_control_stream_->id(), /* fin = */ false,
                      /* offset = */ 1, unknown_frame));
}

}  // namespace
}  // namespace test
}  // namespace quic
```