Response:
The user wants a summary of the functionalities implemented in the C++ source code file `net/third_party/quiche/src/quiche/quic/core/quic_stream_test.cc`.

Here's a plan to address the request:

1. **Identify the core purpose of the file:** The filename strongly suggests this is a unit test file for `QuicStream`.
2. **Analyze the included headers:** These reveal the main dependencies and components being tested (e.g., `quic_stream.h`, `quic_connection.h`, `quic_session.h`).
3. **Examine the test fixtures and test cases:**  The `QuicStreamTest` class and the `TEST_P` macros define the setup and individual tests.
4. **Summarize the key functionalities being tested:**  Focus on actions performed on `QuicStream` objects and the expected outcomes.
5. **Address the specific questions:**
    - **Relationship with JavaScript:** Determine if any tested functionality directly relates to how QUIC streams are exposed or used in a browser's JavaScript environment.
    - **Logical Reasoning:** Identify tests that involve conditional behavior or state transitions and describe the input and output.
    - **Common Usage Errors:**  Look for tests that specifically check for error conditions or invalid usage scenarios.
    - **User Operations leading to this code:** Explain how user actions in a browser might trigger the underlying QUIC stream mechanisms.
6. **Provide a high-level summary:**  Concisely encapsulate the main purpose of the code.
这是 Chromium 网络栈中 QUIC 协议的 `QuicStream` 类的单元测试文件。它的主要功能是验证 `QuicStream` 类的各种行为和状态转换是否符合预期。

**以下是该文件测试的主要功能归纳：**

1. **流的基本操作:**
    - **数据写入和缓冲 (`WriteOrBufferData`):** 测试数据写入流时的缓冲行为，包括部分写入、全部写入、写入 Fin 标志等情况，以及在写入过程中流被阻塞的情况。
    - **数据消费 (`ConsumeData`):**  模拟读取流数据。
    - **流关闭 (`CloseWriteSide`, `OnClose`):** 测试流的正常关闭和异常关闭（例如收到 RST 帧）。
    - **发送 FIN 和 RST (`fin_sent`, `rst_sent`, `MaybeSendRstStreamFrame`):**  验证在不同情况下是否正确发送 FIN 或 RST 帧，以确保流的正确终止。
    - **流重置 (`Reset`):** 测试主动重置流的行为。

2. **流控制:**
    - **接收窗口更新 (`OnWindowUpdateFrame`):**  测试接收到 WINDOW_UPDATE 帧时如何更新发送窗口大小。
    - **流阻塞 (`HasWriteBlockedStreams`):**  测试在写入数据但未完全消费时，流是否被正确标记为阻塞状态。
    - **流量控制违规 (`CloseConnection`):** 测试接收到超出流量控制限制的数据时，连接是否会被关闭。
    - **停止读取 (`StopReading`):** 测试停止读取后，是否仍然能发送流量控制更新。

3. **流状态和事件处理:**
    - **数据可用事件 (`OnDataAvailable`):** 模拟数据到达时触发的事件。
    - **可写入新数据事件 (`OnCanWriteNewData`):** 模拟流变为可写时触发的事件。
    - **写入侧数据接收状态事件 (`OnWriteSideInDataRecvdState`):**  测试接收到对端发送的写入侧关闭的指示时的处理。
    - **接收到 FIN 和 RST (`fin_received`, `rst_received`):** 验证是否正确记录接收到的 FIN 和 RST 帧。
    - **最终字节偏移 (`HasReceivedFinalOffset`):**  测试是否正确记录接收到的流的最终字节偏移量（通过 FIN 或 RST）。

4. **Pending Stream (待定流) 的测试 (针对 HTTP/3):**
    - **静态性 (`PendingStreamStaticness`):** 测试 Pending Stream 是否能正确标识为静态流。
    - **类型 (`PendingStreamType`):** 测试 Pending Stream 的流类型是否正确。
    - **流量控制 (`PendingStreamTooMuchData`):**  测试对 Pending Stream 的流量控制限制。
    - **接收 RST 帧 (`PendingStreamRstStream`):** 测试 Pending Stream 接收 RST 帧的行为。
    - **接收 WINDOW_UPDATE 帧 (`PendingStreamWindowUpdate`):** 测试 Pending Stream 接收 WINDOW_UPDATE 帧的行为。
    - **接收 STOP_SENDING 帧 (`PendingStreamStopSending`):** 测试 Pending Stream 接收 STOP_SENDING 帧的行为。
    - **从 Pending Stream 激活 (`FromPendingStream`):** 测试如何从一个 Pending Stream 激活为一个正常的 `QuicStream`。
    - **接收 RESET_STREAM_AT 帧 (`ResetStreamAt`):** 测试 Pending Stream 接收 `RESET_STREAM_AT` 帧的行为。

5. **统计信息:**
    - **帧统计 (`FrameStats`):**  测试接收到的帧的数量和重复帧的数量是否被正确统计。

**与 JavaScript 的功能关系：**

`QuicStream` 是 Chromium 网络栈中处理 QUIC 连接中数据传输的核心类。虽然这个 C++ 测试文件本身不包含 JavaScript 代码，但它测试的功能直接影响着浏览器中基于 QUIC 的网络请求的行为。

**举例说明：**

假设一个 JavaScript 应用发起一个 HTTP/3 请求，底层会建立一个 QUIC 连接并创建一个或多个 `QuicStream` 来传输请求和响应数据。

- **数据接收:** 当服务器向浏览器发送响应数据时，这些数据会被封装成 QUIC 数据包，最终由 `QuicStream` 对象接收和处理。`OnDataAvailable` 事件会被触发，通知上层应用（可能是网络层的其他 C++ 代码，最终会传递给浏览器内核的 JavaScript 引擎）有数据可用。
- **流量控制:** 如果 JavaScript 应用接收数据的速度慢于服务器发送的速度，`QuicStream` 会根据流量控制机制通知服务器减速，防止数据溢出。这涉及到 `OnWindowUpdateFrame` 的处理。
- **流关闭:** 当请求完成或被取消时，`QuicStream` 会发送 FIN 标志或 RST 帧来关闭流。这直接影响着 JavaScript 中 `fetch` API 或 WebSocket 连接的生命周期。

**逻辑推理的举例说明：**

**假设输入:**

- 调用 `stream_->WriteOrBufferData(kData1, false, nullptr)` 写入 "FooAndBar" (9 字节) 的数据，且不带 FIN。
- 假设 `session_->ConsumeData` 只消费了前 5 个字节的数据。

**输出:**

- `HasWriteBlockedStreams()` 返回 `true`，因为还有 4 个字节的数据未被消费，流被写入阻塞。
- `stream_->BufferedDataBytes()` 返回 4，表示缓冲区中剩余的字节数。

**用户或编程常见的使用错误举例说明：**

- **错误地假设数据立即发送:** 开发者可能在调用 `WriteOrBufferData` 后立即认为数据已经发送出去。但实际上，数据可能被缓冲，直到连接允许发送。如果在数据被发送之前就尝试关闭连接或释放相关资源，可能会导致数据丢失或错误。
- **忽略流量控制:** 开发者如果发送大量数据而不考虑对端的接收能力，可能会导致流量控制错误，甚至连接被关闭。
- **在流关闭后尝试写入:**  如果开发者在流已经发送了 FIN 或接收到 RST 后仍然尝试向该流写入数据，会导致错误。

**用户操作如何一步步的到达这里作为调试线索：**

1. **用户在浏览器中输入一个 HTTPS 地址并访问，或者点击一个链接。**
2. **浏览器发起网络请求，如果服务器支持 HTTP/3 协议，浏览器可能会选择使用 QUIC 进行连接。**
3. **QUIC 连接建立后，会创建一个或多个 `QuicStream` 对象来传输 HTTP 请求和响应数据。**
4. **当服务器发送响应数据时，这些数据会通过 QUIC 连接到达客户端。**
5. **Chromium 网络栈中的 QUIC 实现会解析收到的 QUIC 数据包，并将数据传递给对应的 `QuicStream` 对象。**
6. **`QuicStream` 对象会调用其内部方法来处理接收到的数据，例如存储数据到接收缓冲区、更新流量控制状态等。**
7. **如果开发者在 Chromium 的 QUIC 代码中设置了断点或使用了日志记录，那么当执行到 `quic_stream_test.cc` 中测试的 `QuicStream` 的相关逻辑时，调试器或日志会记录相应的状态和信息，帮助开发者理解数据传输的过程和可能出现的问题。**

**功能归纳（第1部分）：**

该文件的第一部分主要定义了用于测试 `QuicStream` 的基础结构和一些简单的测试用例。它包括：

- **必要的头文件引入:** 包含了 `QuicStream` 及其依赖的类和测试工具的头文件。
- **常量定义:** 定义了一些测试中使用的常量，如数据内容、数据长度等。
- **`TestStream` 类:**  一个继承自 `QuicStream` 的 Mock 类，用于方便地模拟和观察 `QuicStream` 的行为，例如通过 `MOCK_METHOD` 定义可被 Mock 的方法。
- **`QuicStreamTest` 测试 fixture:**  设置了测试环境，包括创建 `MockQuicConnection`、`MockQuicSession` 和 `TestStream` 对象，并提供了一些辅助方法，如检查 FIN/RST 发送状态、获取阻塞流列表等。
- **针对 Pending Stream 的测试:**  针对 HTTP/3 中引入的 Pending Stream 进行了测试，涵盖了其基本属性、类型和接收特定帧的行为。
- **基本的写入测试:**  包含了对 `WriteOrBufferData` 方法的基础测试，验证了数据写入和缓冲的基本功能。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_stream_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_stream.h"

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/macros.h"
#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/null_encrypter.h"
#include "quiche/quic/core/frames/quic_connection_close_frame.h"
#include "quiche/quic/core/frames/quic_reset_stream_at_frame.h"
#include "quiche/quic/core/frames/quic_rst_stream_frame.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/core/quic_write_blocked_list.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_config_peer.h"
#include "quiche/quic/test_tools/quic_connection_peer.h"
#include "quiche/quic/test_tools/quic_flow_controller_peer.h"
#include "quiche/quic/test_tools/quic_session_peer.h"
#include "quiche/quic/test_tools/quic_stream_peer.h"
#include "quiche/quic/test_tools/quic_stream_sequencer_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/quiche_mem_slice_storage.h"

using testing::_;
using testing::AnyNumber;
using testing::AtLeast;
using testing::InSequence;
using testing::Invoke;
using testing::InvokeWithoutArgs;
using testing::Return;
using testing::StrictMock;

namespace quic {
namespace test {
namespace {

const char kData1[] = "FooAndBar";
const char kData2[] = "EepAndBaz";
const QuicByteCount kDataLen = 9;
const uint8_t kPacket0ByteConnectionId = 0;
const uint8_t kPacket8ByteConnectionId = 8;

class TestStream : public QuicStream {
 public:
  TestStream(QuicStreamId id, QuicSession* session, StreamType type)
      : QuicStream(id, session, /*is_static=*/false, type) {
    sequencer()->set_level_triggered(true);
  }

  TestStream(PendingStream* pending, QuicSession* session, bool is_static)
      : QuicStream(pending, session, is_static) {}

  MOCK_METHOD(void, OnDataAvailable, (), (override));

  MOCK_METHOD(void, OnCanWriteNewData, (), (override));

  MOCK_METHOD(void, OnWriteSideInDataRecvdState, (), (override));

  using QuicStream::CanWriteNewData;
  using QuicStream::CanWriteNewDataAfterData;
  using QuicStream::CloseWriteSide;
  using QuicStream::fin_buffered;
  using QuicStream::MaybeSendStopSending;
  using QuicStream::OnClose;
  using QuicStream::WriteMemSlices;
  using QuicStream::WriteOrBufferData;

  void ConsumeData(size_t num_bytes) {
    char buffer[1024];
    ASSERT_GT(ABSL_ARRAYSIZE(buffer), num_bytes);
    struct iovec iov;
    iov.iov_base = buffer;
    iov.iov_len = num_bytes;
    ASSERT_EQ(num_bytes, QuicStreamPeer::sequencer(this)->Readv(&iov, 1));
  }

 private:
  std::string data_;
};

class QuicStreamTest : public QuicTestWithParam<ParsedQuicVersion> {
 public:
  QuicStreamTest()
      : zero_(QuicTime::Delta::Zero()),
        supported_versions_(AllSupportedVersions()) {}

  void Initialize(Perspective perspective = Perspective::IS_SERVER) {
    ParsedQuicVersionVector version_vector;
    version_vector.push_back(GetParam());
    connection_ = new StrictMock<MockQuicConnection>(
        &helper_, &alarm_factory_, perspective, version_vector);
    connection_->AdvanceTime(QuicTime::Delta::FromSeconds(1));
    session_ = std::make_unique<StrictMock<MockQuicSession>>(connection_);
    session_->Initialize();
    connection_->SetEncrypter(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<NullEncrypter>(connection_->perspective()));
    QuicConfigPeer::SetReceivedInitialSessionFlowControlWindow(
        session_->config(), kMinimumFlowControlSendWindow);
    QuicConfigPeer::SetReceivedInitialMaxStreamDataBytesUnidirectional(
        session_->config(), kMinimumFlowControlSendWindow);
    QuicConfigPeer::SetReceivedInitialMaxStreamDataBytesIncomingBidirectional(
        session_->config(), kMinimumFlowControlSendWindow);
    QuicConfigPeer::SetReceivedInitialMaxStreamDataBytesOutgoingBidirectional(
        session_->config(), kMinimumFlowControlSendWindow);
    QuicConfigPeer::SetReceivedMaxUnidirectionalStreams(session_->config(), 10);
    session_->OnConfigNegotiated();

    stream_ = new StrictMock<TestStream>(kTestStreamId, session_.get(),
                                         BIDIRECTIONAL);
    EXPECT_NE(nullptr, stream_);
    EXPECT_CALL(*session_, ShouldKeepConnectionAlive())
        .WillRepeatedly(Return(true));
    // session_ now owns stream_.
    session_->ActivateStream(absl::WrapUnique(stream_));
    // Ignore resetting when session_ is terminated.
    EXPECT_CALL(*session_, MaybeSendStopSendingFrame(kTestStreamId, _))
        .Times(AnyNumber());
    EXPECT_CALL(*session_, MaybeSendRstStreamFrame(kTestStreamId, _, _))
        .Times(AnyNumber());
    write_blocked_list_ =
        QuicSessionPeer::GetWriteBlockedStreams(session_.get());
  }

  bool fin_sent() { return stream_->fin_sent(); }
  bool rst_sent() { return stream_->rst_sent(); }

  bool HasWriteBlockedStreams() {
    return write_blocked_list_->HasWriteBlockedSpecialStream() ||
           write_blocked_list_->HasWriteBlockedDataStreams();
  }

  QuicConsumedData CloseStreamOnWriteError(
      QuicStreamId id, QuicByteCount /*write_length*/,
      QuicStreamOffset /*offset*/, StreamSendingState /*state*/,
      TransmissionType /*type*/, std::optional<EncryptionLevel> /*level*/) {
    session_->ResetStream(id, QUIC_STREAM_CANCELLED);
    return QuicConsumedData(1, false);
  }

  bool ClearResetStreamFrame(const QuicFrame& frame) {
    EXPECT_EQ(RST_STREAM_FRAME, frame.type);
    DeleteFrame(&const_cast<QuicFrame&>(frame));
    return true;
  }

  bool ClearStopSendingFrame(const QuicFrame& frame) {
    EXPECT_EQ(STOP_SENDING_FRAME, frame.type);
    DeleteFrame(&const_cast<QuicFrame&>(frame));
    return true;
  }

 protected:
  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  MockQuicConnection* connection_;
  std::unique_ptr<MockQuicSession> session_;
  StrictMock<TestStream>* stream_;
  QuicWriteBlockedListInterface* write_blocked_list_;
  QuicTime::Delta zero_;
  ParsedQuicVersionVector supported_versions_;
  QuicStreamId kTestStreamId = GetNthClientInitiatedBidirectionalStreamId(
      GetParam().transport_version, 1);
  const QuicStreamId kTestPendingStreamId =
      GetNthClientInitiatedUnidirectionalStreamId(GetParam().transport_version,
                                                  1);
};

INSTANTIATE_TEST_SUITE_P(QuicStreamTests, QuicStreamTest,
                         ::testing::ValuesIn(AllSupportedVersions()),
                         ::testing::PrintToStringParamName());

using PendingStreamTest = QuicStreamTest;

INSTANTIATE_TEST_SUITE_P(PendingStreamTests, PendingStreamTest,
                         ::testing::ValuesIn(CurrentSupportedHttp3Versions()),
                         ::testing::PrintToStringParamName());

TEST_P(PendingStreamTest, PendingStreamStaticness) {
  Initialize();

  PendingStream pending(kTestPendingStreamId, session_.get());
  TestStream stream(&pending, session_.get(), false);
  EXPECT_FALSE(stream.is_static());

  PendingStream pending2(kTestPendingStreamId + 4, session_.get());
  TestStream stream2(&pending2, session_.get(), true);
  EXPECT_TRUE(stream2.is_static());
}

TEST_P(PendingStreamTest, PendingStreamType) {
  Initialize();

  PendingStream pending(kTestPendingStreamId, session_.get());
  TestStream stream(&pending, session_.get(), false);
  EXPECT_EQ(stream.type(), READ_UNIDIRECTIONAL);
}

TEST_P(PendingStreamTest, PendingStreamTypeOnClient) {
  Initialize(Perspective::IS_CLIENT);

  QuicStreamId server_initiated_pending_stream_id =
      GetNthServerInitiatedUnidirectionalStreamId(session_->transport_version(),
                                                  1);
  PendingStream pending(server_initiated_pending_stream_id, session_.get());
  TestStream stream(&pending, session_.get(), false);
  EXPECT_EQ(stream.type(), READ_UNIDIRECTIONAL);
}

TEST_P(PendingStreamTest, PendingStreamTooMuchData) {
  Initialize();

  PendingStream pending(kTestPendingStreamId, session_.get());
  // Receive a stream frame that violates flow control: the byte offset is
  // higher than the receive window offset.
  QuicStreamFrame frame(kTestPendingStreamId, false,
                        kInitialSessionFlowControlWindowForTest + 1, ".");

  // Stream should not accept the frame, and the connection should be closed.
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA, _, _));
  pending.OnStreamFrame(frame);
}

TEST_P(PendingStreamTest, PendingStreamTooMuchDataInRstStream) {
  Initialize();

  PendingStream pending1(kTestPendingStreamId, session_.get());
  // Receive a rst stream frame that violates flow control: the byte offset is
  // higher than the receive window offset.
  QuicRstStreamFrame frame1(kInvalidControlFrameId, kTestPendingStreamId,
                            QUIC_STREAM_CANCELLED,
                            kInitialSessionFlowControlWindowForTest + 1);

  // Pending stream should not accept the frame, and the connection should be
  // closed.
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA, _, _));
  pending1.OnRstStreamFrame(frame1);

  QuicStreamId bidirection_stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      session_->transport_version(), Perspective::IS_CLIENT);
  PendingStream pending2(bidirection_stream_id, session_.get());
  // Receive a rst stream frame that violates flow control: the byte offset is
  // higher than the receive window offset.
  QuicRstStreamFrame frame2(kInvalidControlFrameId, bidirection_stream_id,
                            QUIC_STREAM_CANCELLED,
                            kInitialSessionFlowControlWindowForTest + 1);
  // Bidirectional Pending stream should not accept the frame, and the
  // connection should be closed.
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA, _, _));
  pending2.OnRstStreamFrame(frame2);
}

TEST_P(PendingStreamTest, PendingStreamRstStream) {
  Initialize();

  PendingStream pending(kTestPendingStreamId, session_.get());
  QuicStreamOffset final_byte_offset = 7;
  QuicRstStreamFrame frame(kInvalidControlFrameId, kTestPendingStreamId,
                           QUIC_STREAM_CANCELLED, final_byte_offset);

  // Pending stream should accept the frame and not close the connection.
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  pending.OnRstStreamFrame(frame);
}

TEST_P(PendingStreamTest, PendingStreamWindowUpdate) {
  Initialize();

  QuicStreamId bidirection_stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      session_->transport_version(), Perspective::IS_CLIENT);
  PendingStream pending(bidirection_stream_id, session_.get());
  QuicWindowUpdateFrame frame(kInvalidControlFrameId, bidirection_stream_id,
                              kDefaultFlowControlSendWindow * 2);
  pending.OnWindowUpdateFrame(frame);
  TestStream stream(&pending, session_.get(), false);

  EXPECT_EQ(QuicStreamPeer::SendWindowSize(&stream),
            kDefaultFlowControlSendWindow * 2);
}

TEST_P(PendingStreamTest, PendingStreamStopSending) {
  Initialize();

  QuicStreamId bidirection_stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      session_->transport_version(), Perspective::IS_CLIENT);
  PendingStream pending(bidirection_stream_id, session_.get());
  QuicResetStreamError error =
      QuicResetStreamError::FromInternal(QUIC_STREAM_INTERNAL_ERROR);
  pending.OnStopSending(error);
  EXPECT_TRUE(pending.GetStopSendingErrorCode());
  auto actual_error = *pending.GetStopSendingErrorCode();
  EXPECT_EQ(actual_error, error);
}

TEST_P(PendingStreamTest, FromPendingStream) {
  Initialize();

  PendingStream pending(kTestPendingStreamId, session_.get());

  QuicStreamFrame frame(kTestPendingStreamId, false, 2, ".");
  pending.OnStreamFrame(frame);
  pending.OnStreamFrame(frame);
  QuicStreamFrame frame2(kTestPendingStreamId, true, 3, ".");
  pending.OnStreamFrame(frame2);

  TestStream stream(&pending, session_.get(), false);
  EXPECT_EQ(3, stream.num_frames_received());
  EXPECT_EQ(3u, stream.stream_bytes_read());
  EXPECT_EQ(1, stream.num_duplicate_frames_received());
  EXPECT_EQ(true, stream.fin_received());
  EXPECT_EQ(frame2.offset + 1, stream.highest_received_byte_offset());
  EXPECT_EQ(frame2.offset + 1,
            session_->flow_controller()->highest_received_byte_offset());
}

TEST_P(PendingStreamTest, FromPendingStreamThenData) {
  Initialize();

  PendingStream pending(kTestPendingStreamId, session_.get());

  QuicStreamFrame frame(kTestPendingStreamId, false, 2, ".");
  pending.OnStreamFrame(frame);

  auto stream = new TestStream(&pending, session_.get(), false);
  session_->ActivateStream(absl::WrapUnique(stream));

  QuicStreamFrame frame2(kTestPendingStreamId, true, 3, ".");
  stream->OnStreamFrame(frame2);

  EXPECT_EQ(2, stream->num_frames_received());
  EXPECT_EQ(2u, stream->stream_bytes_read());
  EXPECT_EQ(true, stream->fin_received());
  EXPECT_EQ(frame2.offset + 1, stream->highest_received_byte_offset());
  EXPECT_EQ(frame2.offset + 1,
            session_->flow_controller()->highest_received_byte_offset());
}

TEST_P(PendingStreamTest, ResetStreamAt) {
  Initialize();
  if (!VersionHasIetfQuicFrames(session_->transport_version())) {
    return;
  }

  PendingStream pending(kTestPendingStreamId, session_.get());

  QuicResetStreamAtFrame rst(0, kTestPendingStreamId, QUIC_STREAM_CANCELLED,
                             100, 3);
  pending.OnResetStreamAtFrame(rst);
  QuicStreamFrame frame(kTestPendingStreamId, false, 2, ".");
  pending.OnStreamFrame(frame);

  auto stream = new TestStream(&pending, session_.get(), false);
  session_->ActivateStream(absl::WrapUnique(stream));

  EXPECT_FALSE(stream->rst_received());
  EXPECT_FALSE(stream->read_side_closed());
  EXPECT_CALL(*stream, OnDataAvailable()).WillOnce([&]() {
    stream->ConsumeData(3);
  });
  QuicStreamFrame frame2(kTestPendingStreamId, false, 0, "..");
  stream->OnStreamFrame(frame2);
  EXPECT_TRUE(stream->read_side_closed());
  EXPECT_TRUE(stream->rst_received());
}

TEST_P(QuicStreamTest, WriteAllData) {
  Initialize();

  QuicByteCount length =
      1 + QuicPacketCreator::StreamFramePacketOverhead(
              connection_->transport_version(), kPacket8ByteConnectionId,
              kPacket0ByteConnectionId, !kIncludeVersion,
              !kIncludeDiversificationNonce, PACKET_4BYTE_PACKET_NUMBER,
              quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0,
              quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0, 0u);
  connection_->SetMaxPacketLength(length);

  EXPECT_CALL(*session_, WritevData(kTestStreamId, _, _, _, _, _))
      .WillOnce(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  stream_->WriteOrBufferData(kData1, false, nullptr);
  EXPECT_FALSE(HasWriteBlockedStreams());
}

TEST_P(QuicStreamTest, NoBlockingIfNoDataOrFin) {
  Initialize();

  // Write no data and no fin.  If we consume nothing we should not be write
  // blocked.
  EXPECT_QUIC_BUG(
      stream_->WriteOrBufferData(absl::string_view(), false, nullptr), "");
  EXPECT_FALSE(HasWriteBlockedStreams());
}

TEST_P(QuicStreamTest, BlockIfOnlySomeDataConsumed) {
  Initialize();

  // Write some data and no fin.  If we consume some but not all of the data,
  // we should be write blocked a not all the data was consumed.
  EXPECT_CALL(*session_, WritevData(kTestStreamId, _, _, _, _, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        return session_->ConsumeData(stream_->id(), 1u, 0u, NO_FIN,
                                     NOT_RETRANSMISSION, std::nullopt);
      }));
  stream_->WriteOrBufferData(absl::string_view(kData1, 2), false, nullptr);
  EXPECT_TRUE(session_->HasUnackedStreamData());
  ASSERT_EQ(1u, write_blocked_list_->NumBlockedStreams());
  EXPECT_EQ(1u, stream_->BufferedDataBytes());
}

TEST_P(QuicStreamTest, BlockIfFinNotConsumedWithData) {
  Initialize();

  // Write some data and no fin.  If we consume all the data but not the fin,
  // we should be write blocked because the fin was not consumed.
  // (This should never actually happen as the fin should be sent out with the
  // last data)
  EXPECT_CALL(*session_, WritevData(kTestStreamId, _, _, _, _, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        return session_->ConsumeData(stream_->id(), 2u, 0u, NO_FIN,
                                     NOT_RETRANSMISSION, std::nullopt);
      }));
  stream_->WriteOrBufferData(absl::string_view(kData1, 2), true, nullptr);
  EXPECT_TRUE(session_->HasUnackedStreamData());
  ASSERT_EQ(1u, write_blocked_list_->NumBlockedStreams());
}

TEST_P(QuicStreamTest, BlockIfSoloFinNotConsumed) {
  Initialize();

  // Write no data and a fin.  If we consume nothing we should be write blocked,
  // as the fin was not consumed.
  EXPECT_CALL(*session_, WritevData(kTestStreamId, _, _, _, _, _))
      .WillOnce(Return(QuicConsumedData(0, false)));
  stream_->WriteOrBufferData(absl::string_view(), true, nullptr);
  ASSERT_EQ(1u, write_blocked_list_->NumBlockedStreams());
}

TEST_P(QuicStreamTest, CloseOnPartialWrite) {
  Initialize();

  // Write some data and no fin. However, while writing the data
  // close the stream and verify that MarkConnectionLevelWriteBlocked does not
  // crash with an unknown stream.
  EXPECT_CALL(*session_, WritevData(kTestStreamId, _, _, _, _, _))
      .WillOnce(Invoke(this, &QuicStreamTest::CloseStreamOnWriteError));
  stream_->WriteOrBufferData(absl::string_view(kData1, 2), false, nullptr);
  ASSERT_EQ(0u, write_blocked_list_->NumBlockedStreams());
}

TEST_P(QuicStreamTest, WriteOrBufferData) {
  Initialize();

  EXPECT_FALSE(HasWriteBlockedStreams());
  QuicByteCount length =
      1 + QuicPacketCreator::StreamFramePacketOverhead(
              connection_->transport_version(), kPacket8ByteConnectionId,
              kPacket0ByteConnectionId, !kIncludeVersion,
              !kIncludeDiversificationNonce, PACKET_4BYTE_PACKET_NUMBER,
              quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0,
              quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0, 0u);
  connection_->SetMaxPacketLength(length);

  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        return session_->ConsumeData(stream_->id(), kDataLen - 1, 0u, NO_FIN,
                                     NOT_RETRANSMISSION, std::nullopt);
      }));
  stream_->WriteOrBufferData(kData1, false, nullptr);

  EXPECT_TRUE(session_->HasUnackedStreamData());
  EXPECT_EQ(1u, stream_->BufferedDataBytes());
  EXPECT_TRUE(HasWriteBlockedStreams());

  // Queue a bytes_consumed write.
  stream_->WriteOrBufferData(kData2, false, nullptr);
  EXPECT_EQ(10u, stream_->BufferedDataBytes());
  // Make sure we get the tail of the first write followed by the bytes_consumed
  InSequence s;
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        return session_->ConsumeData(stream_->id(), kDataLen - 1, kDataLen - 1,
                                     NO_FIN, NOT_RETRANSMISSION, std::nullopt);
      }));
  EXPECT_CALL(*stream_, OnCanWriteNewData());
  stream_->OnCanWrite();
  EXPECT_TRUE(session_->HasUnackedStreamData());

  // And finally the end of the bytes_consumed.
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        return session_->ConsumeData(stream_->id(), 2u, 2 * kDataLen - 2,
                                     NO_FIN, NOT_RETRANSMISSION, std::nullopt);
      }));
  EXPECT_CALL(*stream_, OnCanWriteNewData());
  stream_->OnCanWrite();
  EXPECT_TRUE(session_->HasUnackedStreamData());
}

TEST_P(QuicStreamTest, WriteOrBufferDataReachStreamLimit) {
  Initialize();
  std::string data("aaaaa");
  QuicStreamPeer::SetStreamBytesWritten(kMaxStreamLength - data.length(),
                                        stream_);
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillOnce(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  stream_->WriteOrBufferData(data, false, nullptr);
  EXPECT_TRUE(session_->HasUnackedStreamData());
  EXPECT_QUIC_BUG(
      {
        EXPECT_CALL(*connection_,
                    CloseConnection(QUIC_STREAM_LENGTH_OVERFLOW, _, _));
        stream_->WriteOrBufferData("a", false, nullptr);
      },
      "Write too many data via stream");
}

TEST_P(QuicStreamTest, ConnectionCloseAfterStreamClose) {
  Initialize();

  QuicRstStreamFrame rst_frame(kInvalidControlFrameId, stream_->id(),
                               QUIC_STREAM_CANCELLED, 1234);
  stream_->OnStreamReset(rst_frame);
  if (VersionHasIetfQuicFrames(session_->transport_version())) {
    // Create and inject a STOP SENDING frame to complete the close
    // of the stream. This is only needed for version 99/IETF QUIC.
    QuicStopSendingFrame stop_sending(kInvalidControlFrameId, stream_->id(),
                                      QUIC_STREAM_CANCELLED);
    session_->OnStopSendingFrame(stop_sending);
  }
  EXPECT_THAT(stream_->stream_error(), IsStreamError(QUIC_STREAM_CANCELLED));
  EXPECT_THAT(stream_->connection_error(), IsQuicNoError());
  QuicConnectionCloseFrame frame;
  frame.quic_error_code = QUIC_INTERNAL_ERROR;
  stream_->OnConnectionClosed(frame, ConnectionCloseSource::FROM_SELF);
  EXPECT_THAT(stream_->stream_error(), IsStreamError(QUIC_STREAM_CANCELLED));
  EXPECT_THAT(stream_->connection_error(), IsQuicNoError());
}

TEST_P(QuicStreamTest, RstAlwaysSentIfNoFinSent) {
  // For flow control accounting, a stream must send either a FIN or a RST frame
  // before termination.
  // Test that if no FIN has been sent, we send a RST.

  Initialize();
  EXPECT_FALSE(fin_sent());
  EXPECT_FALSE(rst_sent());

  // Write some data, with no FIN.
  EXPECT_CALL(*session_, WritevData(kTestStreamId, _, _, _, _, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        return session_->ConsumeData(stream_->id(), 1u, 0u, NO_FIN,
                                     NOT_RETRANSMISSION, std::nullopt);
      }));
  stream_->WriteOrBufferData(absl::string_view(kData1, 1), false, nullptr);
  EXPECT_TRUE(session_->HasUnackedStreamData());
  EXPECT_FALSE(fin_sent());
  EXPECT_FALSE(rst_sent());

  // Now close the stream, and expect that we send a RST.
  EXPECT_CALL(*session_, MaybeSendRstStreamFrame(kTestStreamId, _, _));
  QuicRstStreamFrame rst_frame(kInvalidControlFrameId, stream_->id(),
                               QUIC_STREAM_CANCELLED, 1234);
  stream_->OnStreamReset(rst_frame);
  if (VersionHasIetfQuicFrames(session_->transport_version())) {
    // Create and inject a STOP SENDING frame to complete the close
    // of the stream. This is only needed for version 99/IETF QUIC.
    QuicStopSendingFrame stop_sending(kInvalidControlFrameId, stream_->id(),
                                      QUIC_STREAM_CANCELLED);
    session_->OnStopSendingFrame(stop_sending);
  }
  EXPECT_FALSE(session_->HasUnackedStreamData());
  EXPECT_FALSE(fin_sent());
  EXPECT_TRUE(rst_sent());
}

TEST_P(QuicStreamTest, RstNotSentIfFinSent) {
  // For flow control accounting, a stream must send either a FIN or a RST frame
  // before termination.
  // Test that if a FIN has been sent, we don't also send a RST.

  Initialize();
  EXPECT_FALSE(fin_sent());
  EXPECT_FALSE(rst_sent());

  // Write some data, with FIN.
  EXPECT_CALL(*session_, WritevData(kTestStreamId, _, _, _, _, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        return session_->ConsumeData(stream_->id(), 1u, 0u, FIN,
                                     NOT_RETRANSMISSION, std::nullopt);
      }));
  stream_->WriteOrBufferData(absl::string_view(kData1, 1), true, nullptr);
  EXPECT_TRUE(fin_sent());
  EXPECT_FALSE(rst_sent());

  // Now close the stream, and expect that we do not send a RST.
  QuicStreamPeer::CloseReadSide(stream_);
  stream_->CloseWriteSide();
  EXPECT_TRUE(fin_sent());
  EXPECT_FALSE(rst_sent());
}

TEST_P(QuicStreamTest, OnlySendOneRst) {
  // For flow control accounting, a stream must send either a FIN or a RST frame
  // before termination.
  // Test that if a stream sends a RST, it doesn't send an additional RST during
  // OnClose() (this shouldn't be harmful, but we shouldn't do it anyway...)

  Initialize();
  EXPECT_FALSE(fin_sent());
  EXPECT_FALSE(rst_sent());

  // Reset the stream.
  EXPECT_CALL(*session_, MaybeSendRstStreamFrame(kTestStreamId, _, _)).Times(1);
  stream_->Reset(QUIC_STREAM_CANCELLED);
  EXPECT_FALSE(fin_sent());
  EXPECT_TRUE(rst_sent());

  // Now close the stream (any further resets being sent would break the
  // expectation above).
  QuicStreamPeer::CloseReadSide(stream_);
  stream_->CloseWriteSide();
  EXPECT_FALSE(fin_sent());
  EXPECT_TRUE(rst_sent());
}

TEST_P(QuicStreamTest, StreamFlowControlMultipleWindowUpdates) {
  Initialize();

  // If we receive multiple WINDOW_UPDATES (potentially out of order), then we
  // want to make sure we latch the largest offset we see.

  // Initially should be default.
  EXPECT_EQ(kMinimumFlowControlSendWindow,
            QuicStreamPeer::SendWindowOffset(stream_));

  // Check a single WINDOW_UPDATE results in correct offset.
  QuicWindowUpdateFrame window_update_1(kInvalidControlFrameId, stream_->id(),
                                        kMinimumFlowControlSendWindow + 5);
  stream_->OnWindowUpdateFrame(window_update_1);
  EXPECT_EQ(window_update_1.max_data,
            QuicStreamPeer::SendWindowOffset(stream_));

  // Now send a few more WINDOW_UPDATES and make sure that only the largest is
  // remembered.
  QuicWindowUpdateFrame window_update_2(kInvalidControlFrameId, stream_->id(),
                                        1);
  QuicWindowUpdateFrame window_update_3(kInvalidControlFrameId, stream_->id(),
                                        kMinimumFlowControlSendWindow + 10);
  QuicWindowUpdateFrame window_update_4(kInvalidControlFrameId, stream_->id(),
                                        5678);
  stream_->OnWindowUpdateFrame(window_update_2);
  stream_->OnWindowUpdateFrame(window_update_3);
  stream_->OnWindowUpdateFrame(window_update_4);
  EXPECT_EQ(window_update_3.max_data,
            QuicStreamPeer::SendWindowOffset(stream_));
}

TEST_P(QuicStreamTest, FrameStats) {
  Initialize();

  EXPECT_EQ(0, stream_->num_frames_received());
  EXPECT_EQ(0, stream_->num_duplicate_frames_received());
  QuicStreamFrame frame(stream_->id(), false, 0, ".");
  EXPECT_CALL(*stream_, OnDataAvailable()).Times(2);
  stream_->OnStreamFrame(frame);
  EXPECT_EQ(1, stream_->num_frames_received());
  EXPECT_EQ(0, stream_->num_duplicate_frames_received());
  stream_->OnStreamFrame(frame);
  EXPECT_EQ(2, stream_->num_frames_received());
  EXPECT_EQ(1, stream_->num_duplicate_frames_received());
  QuicStreamFrame frame2(stream_->id(), false, 1, "abc");
  stream_->OnStreamFrame(frame2);
}

// Verify that when we receive a packet which violates flow control (i.e. sends
// too much data on the stream) that the stream sequencer never sees this frame,
// as we check for violation and close the connection early.
TEST_P(QuicStreamTest, StreamSequencerNeverSeesPacketsViolatingFlowControl) {
  Initialize();

  // Receive a stream frame that violates flow control: the byte offset is
  // higher than the receive window offset.
  QuicStreamFrame frame(stream_->id(), false,
                        kInitialSessionFlowControlWindowForTest + 1, ".");
  EXPECT_GT(frame.offset, QuicStreamPeer::ReceiveWindowOffset(stream_));

  // Stream should not accept the frame, and the connection should be closed.
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA, _, _));
  stream_->OnStreamFrame(frame);
}

// Verify that after the consumer calls StopReading(), the stream still sends
// flow control updates.
TEST_P(QuicStreamTest, StopReadingSendsFlowControl) {
  Initialize();

  stream_->StopReading();

  // Connection should not get terminated due to flow control errors.
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA, _, _))
      .Times(0);
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .Times(AtLeast(1))
      .WillRepeatedly(Invoke(&ClearControlFrameWithTransmissionType));

  std::string data(1000, 'x');
  for (QuicStreamOffset offset = 0;
       offset < 2 * kInitialStreamFlowControlWindowForTest;
       offset += data.length()) {
    QuicStreamFrame frame(stream_->id(), false, offset, data);
    stream_->OnStreamFrame(frame);
  }
  EXPECT_LT(kInitialStreamFlowControlWindowForTest,
            QuicStreamPeer::ReceiveWindowOffset(stream_));
}

TEST_P(QuicStreamTest, FinalByteOffsetFromFin) {
  Initialize();

  EXPECT_FALSE(stream_->HasReceivedFinalOffset());

  QuicStreamFrame stream_frame_no_fin(stream_->id(), false, 1234, ".");
  stream_->OnStreamFrame(stream_frame_no_fin);
  EXPECT_FALSE(stream_->HasReceivedFinalOffset());

  QuicStreamFrame stream_frame_with_fin(stream_->id(), true, 1234, ".");
  stream_->OnStreamFrame(stream_frame_with_fin);
  EXPECT_TRUE(stream_->HasReceivedFinalOffset());
}

TEST_P(QuicStreamTest, FinalByteOffsetFromRst) {
  Initialize();

  EXPECT_FALSE(stream_->HasReceivedFinalOffset());
  QuicRstStreamFrame rst_frame(kInvalidControlFrameId, stream_->id(),
                               QUIC_STREAM_CANCELLED, 1234);
  stream_->OnStreamReset(rst_frame);
  EXPECT_TRUE(stream_->HasReceivedFinalOffset());
}

TEST_P(QuicStreamTest, InvalidFinalByteOffsetFromRst) {
  Initialize();

  EXPECT_FALSE(stream_->HasReceivedFinalOffset());
  QuicRstStreamFrame rst_frame(kInvalidControlFrameId, stream_->id(),
                               QUIC_STREAM_CANCELLED, 0xFFFFFFFFFFFF);
  // Stream should not accept the frame, and the connection should be closed.
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA, _, _));
  stream_->OnStreamReset(rst_frame);
  EXPECT_TRUE(stream_->HasReceivedFinalOffset());
}

TEST_P(QuicStreamTest, FinalByteOffsetFromZeroLengthStreamFrame) {
  // When receiving Trailers, an empty stream frame is created with the FIN set,
  // and is passed to OnStreamFrame. The Trailers may be sent in advance of
  // queued body bytes being sent, and thus the final byte offset may exceed
  // current flow control limits. Flow control should only be concerned with
  // data that has actually been sent/received, so verify that flow control
  // ignores such a stream frame.
  Initialize();

  EXPECT_FALSE(stream_->HasReceivedFinalOffset());
  const QuicStreamOffset kByteOffsetExceedingFlowControlWindow =
      kInitialSessionFlowControlWindowForTest + 1;
  const QuicStreamOffset current_stream_flow_control_offset =
      QuicStreamPeer::ReceiveWindowOffset(stream_);
  const QuicStreamOffset current_connection_flow_control_offset =
      QuicFlowControllerPeer::ReceiveWindowOffset(session_->flow_controller());
  ASSERT_GT(kByteOffsetExceedingFlowControlWindow,
            current_stream_flow_control_offset);
  ASSERT_GT(kByteOffsetExceedingFlowControlWindow,
            current_connection_flow_control_offset);
  QuicStreamFrame zero_length_stream_frame_with_fin(
      stream_->id(), /*fin=*/true, kByteOffsetExceedingFlowControlWindow,
      absl::string_view());
  EXPECT_EQ(0, zero_length_stream_frame_with_fin.data_length);

  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  stream_->OnStreamFrame(zero_length_stream_frame_with_fin);
  EXPECT_TRUE(stream_->HasReceivedFinalOffset());

  // The flow control receive offset values should not have changed.
  EXPECT_EQ(current_stream_flow_control_offset,
            QuicStreamPeer::ReceiveWindowOffset(stream_));
  EXPECT_EQ(
      current_connection_flow_control_offset,
      QuicFlowControllerPeer::ReceiveWindowOffset(session_->flow_controller()));
}

TEST_P(QuicStreamTest, OnStreamResetOffsetOverflow) {
  Initialize();
  QuicRstStreamFrame rst_frame(kInvalidControlFrameId, stream_->id(),
                               QUIC_STREAM_CANCELLED, kMaxStreamLength + 1);
  EXPECT_CALL(*connection_, CloseConnection(QUIC_STREAM_LENGTH_OVERFLOW, _, _));
  stream_->OnStreamReset(rst_frame);
}

TEST_P(QuicStreamTest, OnStreamFrameUpperLimit) {
  Initialize();

  // Modify receive window offset and sequencer buffer to
```