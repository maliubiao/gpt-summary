Response:
Let's break down the thought process for analyzing this C++ code and generating the comprehensive explanation.

**1. Understanding the Goal:**

The core request is to analyze the `SimpleSessionNotifier.cc` file from Chromium's QUIC implementation and explain its functionality, its relationship to JavaScript (if any), its logic through hypothetical examples, potential usage errors, and how a user might reach this code during debugging.

**2. Initial Code Scan and High-Level Understanding:**

* **File Path:** `net/third_party/quiche/src/quiche/quic/test_tools/simple_session_notifier.cc`  This immediately suggests it's a *test tool* within the QUIC library. "Simple" further indicates it's likely a simplified version of a more complex component. "SessionNotifier" hints at its role in informing or reacting to events within a QUIC session.
* **Includes:** The included headers provide crucial context:
    * `quiche/quic/core/...`:  Indicates core QUIC concepts like frames, error codes, types, and utilities.
    * `quiche/quic/platform/api/quic_logging.h`: Shows it uses QUIC-specific logging.
    * `quiche/quic/test_tools/quic_test_utils.h`: Confirms its role as a test utility.
* **Namespace:** `quic::test` reinforces its purpose within the testing framework.
* **Class `SimpleSessionNotifier`:**  This is the central entity. The constructor takes a `QuicConnection*`, suggesting it interacts directly with a QUIC connection.
* **Member Variables:** A quick scan reveals key state:
    * `last_control_frame_id_`:  Manages IDs for control frames.
    * `least_unacked_`, `least_unsent_`:  Track the state of control frame acknowledgments.
    * `connection_`:  The associated QUIC connection.
    * `control_frames_`:  A queue of control frames.
    * `stream_map_`:  A map tracking the state of individual QUIC streams.
    * `crypto_state_`:  Tracks the state of crypto streams at different encryption levels.
    * `crypto_bytes_transferred_`: Records which crypto bytes have been sent at each level.
    * `lost_control_frames_`:  Keeps track of lost control frames.

**3. Deeper Dive into Key Methods and Functionality:**

The next step is to examine the purpose of the major methods:

* **`WriteOrBufferData`:**  Handles sending stream data. The "buffer" aspect suggests it might handle write blocking.
* **`WriteCryptoData`:** Sends crypto data.
* **`WriteOrBufferRstStream`, `WriteOrBufferResetStreamAt`, `WriteOrBufferWindowUpate`, `WriteOrBufferPing`, `WriteOrBufferAckFrequency`:** Methods for sending various control frames. The "buffer" part is consistent.
* **`OnStreamDataConsumed`:** Updates stream state after data is sent.
* **`OnCanWrite`:**  The core logic for checking if more data can be sent, including handling retransmissions.
* **`OnStreamReset`:** Handles stream resets.
* **`WillingToWrite`:** Checks if there's anything pending to be sent.
* **`OnFrameAcked`, `OnFrameLost`:**  Crucial for tracking the status of sent frames and triggering retransmissions.
* **`RetransmitLostCryptoData`, `RetransmitLostControlFrames`, `RetransmitLostStreamData`:**  The retransmission logic.
* **`WriteBufferedCryptoData`, `WriteBufferedControlFrames`:**  Handles sending data that was previously buffered due to write blocking.
* **`Has...` methods:** Various checks for buffered or lost data.

**4. Identifying Core Functionalities:**

From the method analysis, the core functionalities emerge:

* **Buffering:** Holding data (both stream and control) when the connection is blocked.
* **Sending:**  Dispatching data and control frames via the underlying `QuicConnection`.
* **Tracking State:** Maintaining the state of streams (bytes sent, acked, FIN status) and control frames (sent, acked, lost).
* **Retransmission:** Handling the retransmission of lost data and control frames.
* **Crypto Data Handling:**  Specialized logic for handling crypto stream data at different encryption levels.

**5. Relating to JavaScript (or Lack Thereof):**

The code is C++ and directly interacts with the QUIC protocol implementation. There's no direct relationship with JavaScript in this specific file. However, it's important to note *where* this code fits within a larger context. Chromium's networking stack *does* interface with JavaScript through APIs. So, while `SimpleSessionNotifier.cc` isn't JavaScript, the *effects* of its behavior (e.g., successfully sending data, handling errors) would be observable in a JavaScript application using network features. This leads to the example of a web browser making a request.

**6. Developing Hypothetical Input/Output Examples:**

The key is to choose scenarios that illustrate core functionalities:

* **Basic Data Sending:**  Illustrates `WriteOrBufferData` and `OnStreamDataConsumed`.
* **Control Frame Sending:** Shows `WriteOrBufferRstStream` and `OnControlFrameAcked`.
* **Loss and Retransmission:** Demonstrates `OnFrameLost` and the retransmission logic in `OnCanWrite`.
* **Write Blocking:** Shows how buffering works when the connection is temporarily blocked.

For each example, define a clear initial state, the action performed by `SimpleSessionNotifier`, and the expected outcome (changes in state, calls to `QuicConnection` methods).

**7. Identifying Common Usage Errors:**

Since this is a *test tool*, the typical "user" is another part of the testing framework. Common errors in this context would involve:

* **Incorrect Assumptions about Connection State:**  Calling methods when the connection isn't in the expected state (e.g., trying to send data before the connection is established).
* **Mismatched Expectations about Acknowledgements:**  Not properly handling the asynchronous nature of acknowledgments.
* **Ignoring Write Blocking:** Trying to send too much data without checking if the connection is ready.

Provide specific examples of how these errors might manifest.

**8. Tracing User Operations to the Code:**

This requires thinking about the path a network request takes within Chromium:

1. **User Action:** The user initiates a network request (e.g., typing a URL).
2. **Browser Processes:** The browser's UI and networking components handle the request.
3. **QUIC Session Initialization:** If QUIC is negotiated, a `QuicConnection` is created.
4. **`SimpleSessionNotifier` Usage (in tests):**  In a testing scenario, a `SimpleSessionNotifier` might be used to simulate or observe the behavior of a real session. The test would directly instantiate and interact with this class.
5. **Method Calls:**  The test would call methods of `SimpleSessionNotifier` to simulate sending data, injecting losses, etc.

Emphasize that this file is primarily for *testing* and wouldn't be directly involved in the core path of a normal user interaction.

**9. Structuring the Explanation:**

Organize the information logically with clear headings and subheadings. Use bullet points, code snippets, and diagrams (if appropriate) to enhance clarity.

**10. Review and Refine:**

After drafting the explanation, review it for accuracy, completeness, and clarity. Ensure that the language is precise and avoids jargon where possible. Double-check the code examples and the hypothetical scenarios. Make sure the explanation clearly distinguishes between the role of this test tool and the real-world QUIC implementation.
这个文件 `simple_session_notifier.cc` 是 Chromium QUIC 栈中的一个测试工具，它的主要功能是 **模拟和辅助测试 QUIC 会话中发送数据和控制帧的行为，并跟踪这些帧的状态（例如，是否被确认，是否丢失）**。 它可以被用于测试 QUIC 连接的各个方面，例如拥塞控制、丢包恢复、以及不同类型的控制帧处理。

下面详细列举其功能：

**核心功能：**

1. **模拟发送数据帧 (STREAM_FRAME):**
   - `WriteOrBufferData`: 允许测试代码发送或缓冲 QUIC 流数据。
   - 它记录了每个流的状态（总字节数、已发送字节数、FIN 标志等）。
   - 如果连接当前被阻塞（write blocked），它可以将数据缓冲起来稍后发送。

2. **模拟发送加密数据 (CRYPTO_FRAME):**
   - `WriteCryptoData`: 允许测试代码发送 QUIC 加密数据，并跟踪不同加密级别的发送状态。

3. **模拟发送控制帧:**
   - 提供了一系列 `WriteOrBuffer...` 方法来发送各种 QUIC 控制帧，例如：
     - `WriteOrBufferRstStream`: 发送 RST_STREAM 帧 (流重置)。
     - `WriteOrBufferResetStreamAt`: 发送 RESET_STREAM_AT 帧 (指定偏移量重置流)。
     - `WriteOrBufferWindowUpate`: 发送 WINDOW_UPDATE 帧 (更新流的接收窗口)。
     - `WriteOrBufferPing`: 发送 PING 帧 (用于保持连接活跃或测量 RTT)。
     - `WriteOrBufferAckFrequency`: 发送 ACK_FREQUENCY 帧 (控制对端发送 ACK 的频率)。
   - 它也管理一个控制帧的队列，并在连接阻塞时缓冲这些帧。

4. **跟踪帧的状态:**
   - `OnStreamDataConsumed`: 当底层 `QuicConnection` 成功发送流数据时被调用，更新流的发送状态。
   - `OnFrameAcked`: 当收到对端发送的 ACK 帧确认了某个发送的帧时被调用，更新帧的确认状态。
   - `OnFrameLost`: 当检测到发送的帧丢失时被调用，标记帧为丢失。

5. **重传丢失的帧:**
   - `RetransmitLostCryptoData`, `RetransmitLostControlFrames`, `RetransmitLostStreamData`:  实现了重传丢失的加密数据、控制帧和流数据的逻辑。

6. **管理连接的写入状态:**
   - `OnCanWrite`:  当底层 `QuicConnection` 准备好写入更多数据时被调用，此时会尝试发送缓冲的数据或重传丢失的帧。
   - `WillingToWrite`:  检查是否有待发送的数据或丢失的帧需要重传。

7. **查询发送状态:**
   - `StreamBytesSent`: 返回已发送的总流字节数。
   - `StreamBytesToSend`: 返回待发送的总流字节数。
   - `HasUnackedCryptoData`, `HasUnackedStreamData`: 检查是否有未被确认的加密数据或流数据。
   - `IsFrameOutstanding`: 检查给定的帧是否还在等待确认。

**与 JavaScript 的关系:**

`simple_session_notifier.cc` 本身是用 C++ 编写的，直接与 QUIC 协议的实现交互，**与 JavaScript 没有直接的功能性关系。**

但是，考虑到 Chromium 的整体架构，JavaScript 代码（例如在浏览器中运行的网页应用）可以通过 Web API (例如 Fetch API, WebSockets)  使用网络功能，而这些功能底层可能会使用 QUIC 协议。

**举例说明:**

假设一个 JavaScript 网页应用发起了一个 HTTP/3 (基于 QUIC) 请求：

1. **JavaScript 发起请求:**  JavaScript 代码调用 `fetch('https://example.com')`.
2. **浏览器网络栈处理:** Chromium 的网络栈接收到这个请求，并尝试与 `example.com` 建立 QUIC 连接。
3. **`SimpleSessionNotifier` 的应用 (在测试中):** 在对 QUIC 连接的某些方面进行单元测试或集成测试时，可能会使用 `SimpleSessionNotifier` 来模拟发送 HTTP 请求的数据帧，或者模拟服务器发送响应数据帧。例如，可以测试当网络出现丢包时，客户端的重传机制是否正常工作。
4. **模拟数据发送:** 测试代码可以使用 `SimpleSessionNotifier::WriteOrBufferData` 来模拟发送包含 HTTP 请求头和 body 的 STREAM_FRAME。
5. **模拟丢包和重传:** 测试代码可以模拟丢包事件，然后观察 `SimpleSessionNotifier` 如何通过 `RetransmitLostStreamData` 重传丢失的数据。

**逻辑推理示例 (假设输入与输出):**

**场景:** 模拟发送一个带有 FIN 标志的流数据帧。

**假设输入:**

- `stream_id`: 4 (一个应用数据流的 ID)
- `data_length`: 1024 字节
- `state`: `FIN` (表示这是流的最后一个数据帧)

**SimpleSessionNotifier 的操作:**

1. `WriteOrBufferData(4, 1024, FIN)` 被调用。
2. `stream_map_[4]` 中对应的 `StreamState` 的状态会被更新：
   - `bytes_total` 增加 1024。
   - `fin_buffered` 设置为 `true`。
3. 如果连接没有被阻塞，`connection_->SendStreamData(4, 1024, current_offset, FIN)` 会被调用。
4. `OnStreamDataConsumed` 会在数据被底层连接消耗后被调用，更新 `StreamState`：
   - `bytes_sent` 增加已消耗的字节数。
   - `fin_sent` 设置为 `true`。
   - `fin_outstanding` 设置为 `true`。

**预期输出:**

- 底层 `QuicConnection` 会尝试发送一个包含 1024 字节数据的 STREAM_FRAME，并且该帧的 FIN 标志被设置。
- `stream_map_[4]` 的状态会反映出数据已被发送，并且 FIN 标志已发出但尚未被确认。

**用户或编程常见的使用错误:**

1. **在连接未建立或已关闭时尝试发送数据:**
   - **错误示例:**  在 QUIC 连接握手完成之前调用 `WriteOrBufferData` 或 `WriteOrBuffer...` 方法。
   - **后果:** 可能导致断言失败或未预期的行为，因为底层连接可能尚未准备好发送数据。
   - **调试线索:** 检查连接的状态，确保在发送数据之前连接已成功建立。

2. **不正确地处理连接阻塞 (write blocking):**
   - **错误示例:**  在 `WriteOrBufferData` 等方法返回指示连接阻塞的情况下，没有等待 `OnCanWrite` 回调就继续尝试发送大量数据。
   - **后果:**  可能导致数据丢失或性能下降，因为数据会被重复缓冲，或者超出连接的处理能力。
   - **调试线索:**  检查 `WriteOrBufferData` 的返回值，并正确实现 `OnCanWrite` 方法来处理缓冲的数据。

3. **假设帧会立即被确认:**
   - **错误示例:**  发送一个控制帧后立即进行依赖于该帧被确认的操作，而没有考虑到网络延迟和丢包的可能性。
   - **后果:**  可能导致逻辑错误，因为操作在预期的前提条件尚未满足的情况下执行。
   - **调试线索:**  使用 `OnFrameAcked` 回调来确认帧已被成功传输，或者使用超时机制来处理未按时确认的情况。

**用户操作是如何一步步的到达这里，作为调试线索:**

`simple_session_notifier.cc` 主要是用于 **测试** QUIC 连接行为的工具，它本身不太可能在正常的浏览器用户操作路径中被直接执行。  用户操作通常会触发更核心的 QUIC 实现代码。

然而，当开发者在调试与 QUIC 相关的网络问题时，他们可能会使用这个工具来：

1. **编写单元测试或集成测试:** 开发者可能会编写测试代码，其中会创建 `SimpleSessionNotifier` 的实例，并使用其方法来模拟各种 QUIC 会话场景，例如模拟发送特定类型的帧，模拟丢包，然后验证 QUIC 连接的行为是否符合预期。
2. **手动模拟网络行为:** 在某些复杂的调试场景下，开发者可能会编写临时的测试代码，使用 `SimpleSessionNotifier` 来手动控制数据和控制帧的发送，以便更精细地观察和诊断问题。
3. **查看测试日志:** 如果一个由 `SimpleSessionNotifier` 驱动的测试失败，开发者会查看测试日志，这些日志可能会包含 `simple_session_notifier.cc` 中生成的调试信息（例如，通过 `QUIC_DVLOG` 输出的信息），从而帮助他们理解问题发生的原因。

**调试线索示例:**

假设开发者正在调试一个 HTTP/3 请求在特定网络条件下出现超时的问题。他们可能会：

1. **设置测试环境:**  搭建一个模拟的网络环境，可以控制丢包率、延迟等参数。
2. **编写使用 `SimpleSessionNotifier` 的测试:**  编写一个测试用例，使用 `SimpleSessionNotifier` 模拟客户端发送 HTTP 请求，并预期在正常情况下能够收到服务器的响应。
3. **模拟网络问题:** 在测试中，模拟网络丢包或高延迟。
4. **观察 `SimpleSessionNotifier` 的行为:**  观察 `SimpleSessionNotifier` 如何处理丢包（例如，是否触发重传），以及 `OnCanWrite` 何时被调用。
5. **查看日志:**  检查测试输出的日志，看是否有关于帧丢失、重传、连接阻塞等信息，这些信息可能来自于 `simple_session_notifier.cc` 中的 `QUIC_DVLOG` 调用。

总而言之，`simple_session_notifier.cc` 作为一个测试工具，它的存在主要是为了辅助 QUIC 协议的开发和验证，帮助开发者确保 QUIC 连接在各种情况下都能正确地发送和接收数据，并处理各种网络事件。用户操作不会直接到达这个文件，但开发者会利用它来测试用户操作背后的 QUIC 实现。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/test_tools/simple_session_notifier.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/test_tools/simple_session_notifier.h"

#include "quiche/quic/core/frames/quic_frame.h"
#include "quiche/quic/core/frames/quic_reset_stream_at_frame.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

namespace quic {

namespace test {

SimpleSessionNotifier::SimpleSessionNotifier(QuicConnection* connection)
    : last_control_frame_id_(kInvalidControlFrameId),
      least_unacked_(1),
      least_unsent_(1),
      connection_(connection) {}

SimpleSessionNotifier::~SimpleSessionNotifier() {
  while (!control_frames_.empty()) {
    DeleteFrame(&control_frames_.front());
    control_frames_.pop_front();
  }
}

SimpleSessionNotifier::StreamState::StreamState()
    : bytes_total(0),
      bytes_sent(0),
      fin_buffered(false),
      fin_sent(false),
      fin_outstanding(false),
      fin_lost(false) {}

SimpleSessionNotifier::StreamState::~StreamState() {}

QuicConsumedData SimpleSessionNotifier::WriteOrBufferData(
    QuicStreamId id, QuicByteCount data_length, StreamSendingState state) {
  return WriteOrBufferData(id, data_length, state, NOT_RETRANSMISSION);
}

QuicConsumedData SimpleSessionNotifier::WriteOrBufferData(
    QuicStreamId id, QuicByteCount data_length, StreamSendingState state,
    TransmissionType transmission_type) {
  if (!stream_map_.contains(id)) {
    stream_map_[id] = StreamState();
  }
  StreamState& stream_state = stream_map_.find(id)->second;
  const bool had_buffered_data =
      HasBufferedStreamData() || HasBufferedControlFrames();
  QuicStreamOffset offset = stream_state.bytes_sent;
  QUIC_DVLOG(1) << "WriteOrBuffer stream_id: " << id << " [" << offset << ", "
                << offset + data_length << "), fin: " << (state != NO_FIN);
  stream_state.bytes_total += data_length;
  stream_state.fin_buffered = state != NO_FIN;
  if (had_buffered_data) {
    QUIC_DLOG(WARNING) << "Connection is write blocked";
    return {0, false};
  }
  const size_t length = stream_state.bytes_total - stream_state.bytes_sent;
  connection_->SetTransmissionType(transmission_type);
  QuicConsumedData consumed =
      connection_->SendStreamData(id, length, stream_state.bytes_sent, state);
  QUIC_DVLOG(1) << "consumed: " << consumed;
  OnStreamDataConsumed(id, stream_state.bytes_sent, consumed.bytes_consumed,
                       consumed.fin_consumed);
  return consumed;
}

void SimpleSessionNotifier::OnStreamDataConsumed(QuicStreamId id,
                                                 QuicStreamOffset offset,
                                                 QuicByteCount data_length,
                                                 bool fin) {
  StreamState& state = stream_map_.find(id)->second;
  if (QuicUtils::IsCryptoStreamId(connection_->transport_version(), id) &&
      data_length > 0) {
    crypto_bytes_transferred_[connection_->encryption_level()].Add(
        offset, offset + data_length);
  }
  state.bytes_sent += data_length;
  state.fin_sent = fin;
  state.fin_outstanding = fin;
}

size_t SimpleSessionNotifier::WriteCryptoData(EncryptionLevel level,
                                              QuicByteCount data_length,
                                              QuicStreamOffset offset) {
  crypto_state_[level].bytes_total += data_length;
  size_t bytes_written =
      connection_->SendCryptoData(level, data_length, offset);
  crypto_state_[level].bytes_sent += bytes_written;
  crypto_bytes_transferred_[level].Add(offset, offset + bytes_written);
  return bytes_written;
}

void SimpleSessionNotifier::WriteOrBufferRstStream(
    QuicStreamId id, QuicRstStreamErrorCode error,
    QuicStreamOffset bytes_written) {
  QUIC_DVLOG(1) << "Writing RST_STREAM_FRAME";
  const bool had_buffered_data =
      HasBufferedStreamData() || HasBufferedControlFrames();
  control_frames_.emplace_back((QuicFrame(new QuicRstStreamFrame(
      ++last_control_frame_id_, id, error, bytes_written))));
  if (error != QUIC_STREAM_NO_ERROR) {
    // Delete stream to avoid retransmissions.
    stream_map_.erase(id);
  }
  if (had_buffered_data) {
    QUIC_DLOG(WARNING) << "Connection is write blocked";
    return;
  }
  WriteBufferedControlFrames();
}

void SimpleSessionNotifier::WriteOrBufferResetStreamAt(
    QuicStreamId id, QuicRstStreamErrorCode error,
    QuicStreamOffset bytes_written, QuicStreamOffset reliable_size) {
  QUIC_DVLOG(1) << "Writing RESET_STREAM_AT_FRAME";
  const bool had_buffered_data =
      HasBufferedStreamData() || HasBufferedControlFrames();
  control_frames_.emplace_back(QuicFrame(new QuicResetStreamAtFrame(
      ++last_control_frame_id_, id, error, bytes_written, reliable_size)));
  if (error != QUIC_STREAM_NO_ERROR) {
    // Delete stream to avoid retransmissions.
    stream_map_.erase(id);
  }
  if (had_buffered_data) {
    QUIC_DLOG(WARNING) << "Connection is write blocked";
    return;
  }
  WriteBufferedControlFrames();
}

void SimpleSessionNotifier::WriteOrBufferWindowUpate(
    QuicStreamId id, QuicStreamOffset byte_offset) {
  QUIC_DVLOG(1) << "Writing WINDOW_UPDATE";
  const bool had_buffered_data =
      HasBufferedStreamData() || HasBufferedControlFrames();
  QuicControlFrameId control_frame_id = ++last_control_frame_id_;
  control_frames_.emplace_back(
      (QuicFrame(QuicWindowUpdateFrame(control_frame_id, id, byte_offset))));
  if (had_buffered_data) {
    QUIC_DLOG(WARNING) << "Connection is write blocked";
    return;
  }
  WriteBufferedControlFrames();
}

void SimpleSessionNotifier::WriteOrBufferPing() {
  QUIC_DVLOG(1) << "Writing PING_FRAME";
  const bool had_buffered_data =
      HasBufferedStreamData() || HasBufferedControlFrames();
  control_frames_.emplace_back(
      (QuicFrame(QuicPingFrame(++last_control_frame_id_))));
  if (had_buffered_data) {
    QUIC_DLOG(WARNING) << "Connection is write blocked";
    return;
  }
  WriteBufferedControlFrames();
}

void SimpleSessionNotifier::WriteOrBufferAckFrequency(
    const QuicAckFrequencyFrame& ack_frequency_frame) {
  QUIC_DVLOG(1) << "Writing ACK_FREQUENCY";
  const bool had_buffered_data =
      HasBufferedStreamData() || HasBufferedControlFrames();
  QuicControlFrameId control_frame_id = ++last_control_frame_id_;
  control_frames_.emplace_back((
      QuicFrame(new QuicAckFrequencyFrame(control_frame_id,
                                          /*sequence_number=*/control_frame_id,
                                          ack_frequency_frame.packet_tolerance,
                                          ack_frequency_frame.max_ack_delay))));
  if (had_buffered_data) {
    QUIC_DLOG(WARNING) << "Connection is write blocked";
    return;
  }
  WriteBufferedControlFrames();
}

void SimpleSessionNotifier::NeuterUnencryptedData() {
  if (QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    for (const auto& interval : crypto_bytes_transferred_[ENCRYPTION_INITIAL]) {
      QuicCryptoFrame crypto_frame(ENCRYPTION_INITIAL, interval.min(),
                                   interval.max() - interval.min());
      OnFrameAcked(QuicFrame(&crypto_frame), QuicTime::Delta::Zero(),
                   QuicTime::Zero());
    }
    return;
  }
  for (const auto& interval : crypto_bytes_transferred_[ENCRYPTION_INITIAL]) {
    QuicStreamFrame stream_frame(
        QuicUtils::GetCryptoStreamId(connection_->transport_version()), false,
        interval.min(), interval.max() - interval.min());
    OnFrameAcked(QuicFrame(stream_frame), QuicTime::Delta::Zero(),
                 QuicTime::Zero());
  }
}

void SimpleSessionNotifier::OnCanWrite() {
  if (connection_->framer().is_processing_packet()) {
    // Do not write data in the middle of packet processing because rest
    // frames in the packet may change the data to write. For example, lost
    // data could be acknowledged. Also, connection is going to emit
    // OnCanWrite signal post packet processing.
    QUIC_BUG(simple_notifier_write_mid_packet_processing)
        << "Try to write mid packet processing.";
    return;
  }
  if (!RetransmitLostCryptoData() || !RetransmitLostControlFrames() ||
      !RetransmitLostStreamData()) {
    return;
  }
  if (!WriteBufferedCryptoData() || !WriteBufferedControlFrames()) {
    return;
  }
  // Write new data.
  for (const auto& pair : stream_map_) {
    const auto& state = pair.second;
    if (!StreamHasBufferedData(pair.first)) {
      continue;
    }

    const size_t length = state.bytes_total - state.bytes_sent;
    const bool can_bundle_fin =
        state.fin_buffered && (state.bytes_sent + length == state.bytes_total);
    connection_->SetTransmissionType(NOT_RETRANSMISSION);
    QuicConnection::ScopedEncryptionLevelContext context(
        connection_,
        connection_->framer().GetEncryptionLevelToSendApplicationData());
    QuicConsumedData consumed = connection_->SendStreamData(
        pair.first, length, state.bytes_sent, can_bundle_fin ? FIN : NO_FIN);
    QUIC_DVLOG(1) << "Tries to write stream_id: " << pair.first << " ["
                  << state.bytes_sent << ", " << state.bytes_sent + length
                  << "), fin: " << can_bundle_fin
                  << ", and consumed: " << consumed;
    OnStreamDataConsumed(pair.first, state.bytes_sent, consumed.bytes_consumed,
                         consumed.fin_consumed);
    if (length != consumed.bytes_consumed ||
        (can_bundle_fin && !consumed.fin_consumed)) {
      break;
    }
  }
}

void SimpleSessionNotifier::OnStreamReset(QuicStreamId id,
                                          QuicRstStreamErrorCode error) {
  if (error != QUIC_STREAM_NO_ERROR) {
    // Delete stream to avoid retransmissions.
    stream_map_.erase(id);
  }
}

bool SimpleSessionNotifier::WillingToWrite() const {
  QUIC_DVLOG(1) << "has_buffered_control_frames: " << HasBufferedControlFrames()
                << " as_lost_control_frames: " << !lost_control_frames_.empty()
                << " has_buffered_stream_data: " << HasBufferedStreamData()
                << " has_lost_stream_data: " << HasLostStreamData();
  return HasBufferedControlFrames() || !lost_control_frames_.empty() ||
         HasBufferedStreamData() || HasLostStreamData();
}

QuicByteCount SimpleSessionNotifier::StreamBytesSent() const {
  QuicByteCount bytes_sent = 0;
  for (const auto& pair : stream_map_) {
    const auto& state = pair.second;
    bytes_sent += state.bytes_sent;
  }
  return bytes_sent;
}

QuicByteCount SimpleSessionNotifier::StreamBytesToSend() const {
  QuicByteCount bytes_to_send = 0;
  for (const auto& pair : stream_map_) {
    const auto& state = pair.second;
    bytes_to_send += (state.bytes_total - state.bytes_sent);
  }
  return bytes_to_send;
}

bool SimpleSessionNotifier::OnFrameAcked(const QuicFrame& frame,
                                         QuicTime::Delta /*ack_delay_time*/,
                                         QuicTime /*receive_timestamp*/) {
  QUIC_DVLOG(1) << "Acking " << frame;
  if (frame.type == CRYPTO_FRAME) {
    StreamState* state = &crypto_state_[frame.crypto_frame->level];
    QuicStreamOffset offset = frame.crypto_frame->offset;
    QuicByteCount data_length = frame.crypto_frame->data_length;
    QuicIntervalSet<QuicStreamOffset> newly_acked(offset, offset + data_length);
    newly_acked.Difference(state->bytes_acked);
    if (newly_acked.Empty()) {
      return false;
    }
    state->bytes_acked.Add(offset, offset + data_length);
    state->pending_retransmissions.Difference(offset, offset + data_length);
    return true;
  }
  if (frame.type != STREAM_FRAME) {
    return OnControlFrameAcked(frame);
  }
  if (!stream_map_.contains(frame.stream_frame.stream_id)) {
    return false;
  }
  auto* state = &stream_map_.find(frame.stream_frame.stream_id)->second;
  QuicStreamOffset offset = frame.stream_frame.offset;
  QuicByteCount data_length = frame.stream_frame.data_length;
  QuicIntervalSet<QuicStreamOffset> newly_acked(offset, offset + data_length);
  newly_acked.Difference(state->bytes_acked);
  const bool fin_newly_acked = frame.stream_frame.fin && state->fin_outstanding;
  if (newly_acked.Empty() && !fin_newly_acked) {
    return false;
  }
  state->bytes_acked.Add(offset, offset + data_length);
  if (fin_newly_acked) {
    state->fin_outstanding = false;
    state->fin_lost = false;
  }
  state->pending_retransmissions.Difference(offset, offset + data_length);
  return true;
}

void SimpleSessionNotifier::OnFrameLost(const QuicFrame& frame) {
  QUIC_DVLOG(1) << "Losting " << frame;
  if (frame.type == CRYPTO_FRAME) {
    StreamState* state = &crypto_state_[frame.crypto_frame->level];
    QuicStreamOffset offset = frame.crypto_frame->offset;
    QuicByteCount data_length = frame.crypto_frame->data_length;
    QuicIntervalSet<QuicStreamOffset> bytes_lost(offset, offset + data_length);
    bytes_lost.Difference(state->bytes_acked);
    if (bytes_lost.Empty()) {
      return;
    }
    for (const auto& lost : bytes_lost) {
      state->pending_retransmissions.Add(lost.min(), lost.max());
    }
    return;
  }
  if (frame.type != STREAM_FRAME) {
    OnControlFrameLost(frame);
    return;
  }
  if (!stream_map_.contains(frame.stream_frame.stream_id)) {
    return;
  }
  auto* state = &stream_map_.find(frame.stream_frame.stream_id)->second;
  QuicStreamOffset offset = frame.stream_frame.offset;
  QuicByteCount data_length = frame.stream_frame.data_length;
  QuicIntervalSet<QuicStreamOffset> bytes_lost(offset, offset + data_length);
  bytes_lost.Difference(state->bytes_acked);
  const bool fin_lost = state->fin_outstanding && frame.stream_frame.fin;
  if (bytes_lost.Empty() && !fin_lost) {
    return;
  }
  for (const auto& lost : bytes_lost) {
    state->pending_retransmissions.Add(lost.min(), lost.max());
  }
  state->fin_lost = fin_lost;
}

bool SimpleSessionNotifier::RetransmitFrames(const QuicFrames& frames,
                                             TransmissionType type) {
  QuicConnection::ScopedPacketFlusher retransmission_flusher(connection_);
  connection_->SetTransmissionType(type);
  for (const QuicFrame& frame : frames) {
    if (frame.type == CRYPTO_FRAME) {
      const StreamState& state = crypto_state_[frame.crypto_frame->level];
      const EncryptionLevel current_encryption_level =
          connection_->encryption_level();
      QuicIntervalSet<QuicStreamOffset> retransmission(
          frame.crypto_frame->offset,
          frame.crypto_frame->offset + frame.crypto_frame->data_length);
      retransmission.Difference(state.bytes_acked);
      for (const auto& interval : retransmission) {
        QuicStreamOffset offset = interval.min();
        QuicByteCount length = interval.max() - interval.min();
        connection_->SetDefaultEncryptionLevel(frame.crypto_frame->level);
        size_t consumed = connection_->SendCryptoData(frame.crypto_frame->level,
                                                      length, offset);
        if (consumed < length) {
          return false;
        }
      }
      connection_->SetDefaultEncryptionLevel(current_encryption_level);
    }
    if (frame.type != STREAM_FRAME) {
      if (GetControlFrameId(frame) == kInvalidControlFrameId) {
        continue;
      }
      QuicFrame copy = CopyRetransmittableControlFrame(frame);
      if (!connection_->SendControlFrame(copy)) {
        // Connection is write blocked.
        DeleteFrame(&copy);
        return false;
      }
      continue;
    }
    if (!stream_map_.contains(frame.stream_frame.stream_id)) {
      continue;
    }
    const auto& state = stream_map_.find(frame.stream_frame.stream_id)->second;
    QuicIntervalSet<QuicStreamOffset> retransmission(
        frame.stream_frame.offset,
        frame.stream_frame.offset + frame.stream_frame.data_length);
    EncryptionLevel retransmission_encryption_level =
        connection_->encryption_level();
    if (QuicUtils::IsCryptoStreamId(connection_->transport_version(),
                                    frame.stream_frame.stream_id)) {
      for (size_t i = 0; i < NUM_ENCRYPTION_LEVELS; ++i) {
        if (retransmission.Intersects(crypto_bytes_transferred_[i])) {
          retransmission_encryption_level = static_cast<EncryptionLevel>(i);
          retransmission.Intersection(crypto_bytes_transferred_[i]);
          break;
        }
      }
    }
    retransmission.Difference(state.bytes_acked);
    bool retransmit_fin = frame.stream_frame.fin && state.fin_outstanding;
    QuicConsumedData consumed(0, false);
    for (const auto& interval : retransmission) {
      QuicStreamOffset retransmission_offset = interval.min();
      QuicByteCount retransmission_length = interval.max() - interval.min();
      const bool can_bundle_fin =
          retransmit_fin &&
          (retransmission_offset + retransmission_length == state.bytes_sent);
      QuicConnection::ScopedEncryptionLevelContext context(
          connection_,
          QuicUtils::IsCryptoStreamId(connection_->transport_version(),
                                      frame.stream_frame.stream_id)
              ? retransmission_encryption_level
              : connection_->framer()
                    .GetEncryptionLevelToSendApplicationData());
      consumed = connection_->SendStreamData(
          frame.stream_frame.stream_id, retransmission_length,
          retransmission_offset, can_bundle_fin ? FIN : NO_FIN);
      QUIC_DVLOG(1) << "stream " << frame.stream_frame.stream_id
                    << " is forced to retransmit stream data ["
                    << retransmission_offset << ", "
                    << retransmission_offset + retransmission_length
                    << ") and fin: " << can_bundle_fin
                    << ", consumed: " << consumed;
      if (can_bundle_fin) {
        retransmit_fin = !consumed.fin_consumed;
      }
      if (consumed.bytes_consumed < retransmission_length ||
          (can_bundle_fin && !consumed.fin_consumed)) {
        // Connection is write blocked.
        return false;
      }
    }
    if (retransmit_fin) {
      QUIC_DVLOG(1) << "stream " << frame.stream_frame.stream_id
                    << " retransmits fin only frame.";
      consumed = connection_->SendStreamData(frame.stream_frame.stream_id, 0,
                                             state.bytes_sent, FIN);
      if (!consumed.fin_consumed) {
        return false;
      }
    }
  }
  return true;
}

bool SimpleSessionNotifier::IsFrameOutstanding(const QuicFrame& frame) const {
  if (frame.type == CRYPTO_FRAME) {
    QuicStreamOffset offset = frame.crypto_frame->offset;
    QuicByteCount data_length = frame.crypto_frame->data_length;
    bool ret = data_length > 0 &&
               !crypto_state_[frame.crypto_frame->level].bytes_acked.Contains(
                   offset, offset + data_length);
    return ret;
  }
  if (frame.type != STREAM_FRAME) {
    return IsControlFrameOutstanding(frame);
  }
  if (!stream_map_.contains(frame.stream_frame.stream_id)) {
    return false;
  }
  const auto& state = stream_map_.find(frame.stream_frame.stream_id)->second;
  QuicStreamOffset offset = frame.stream_frame.offset;
  QuicByteCount data_length = frame.stream_frame.data_length;
  return (data_length > 0 &&
          !state.bytes_acked.Contains(offset, offset + data_length)) ||
         (frame.stream_frame.fin && state.fin_outstanding);
}

bool SimpleSessionNotifier::HasUnackedCryptoData() const {
  if (QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    for (size_t i = 0; i < NUM_ENCRYPTION_LEVELS; ++i) {
      const StreamState& state = crypto_state_[i];
      if (state.bytes_total > state.bytes_sent) {
        return true;
      }
      QuicIntervalSet<QuicStreamOffset> bytes_to_ack(0, state.bytes_total);
      bytes_to_ack.Difference(state.bytes_acked);
      if (!bytes_to_ack.Empty()) {
        return true;
      }
    }
    return false;
  }
  if (!stream_map_.contains(
          QuicUtils::GetCryptoStreamId(connection_->transport_version()))) {
    return false;
  }
  const auto& state =
      stream_map_
          .find(QuicUtils::GetCryptoStreamId(connection_->transport_version()))
          ->second;
  if (state.bytes_total > state.bytes_sent) {
    return true;
  }
  QuicIntervalSet<QuicStreamOffset> bytes_to_ack(0, state.bytes_total);
  bytes_to_ack.Difference(state.bytes_acked);
  return !bytes_to_ack.Empty();
}

bool SimpleSessionNotifier::HasUnackedStreamData() const {
  for (const auto& it : stream_map_) {
    if (StreamIsWaitingForAcks(it.first)) return true;
  }
  return false;
}

bool SimpleSessionNotifier::OnControlFrameAcked(const QuicFrame& frame) {
  QuicControlFrameId id = GetControlFrameId(frame);
  if (id == kInvalidControlFrameId) {
    return false;
  }
  QUICHE_DCHECK(id < least_unacked_ + control_frames_.size());
  if (id < least_unacked_ ||
      GetControlFrameId(control_frames_.at(id - least_unacked_)) ==
          kInvalidControlFrameId) {
    return false;
  }
  SetControlFrameId(kInvalidControlFrameId,
                    &control_frames_.at(id - least_unacked_));
  lost_control_frames_.erase(id);
  while (!control_frames_.empty() &&
         GetControlFrameId(control_frames_.front()) == kInvalidControlFrameId) {
    DeleteFrame(&control_frames_.front());
    control_frames_.pop_front();
    ++least_unacked_;
  }
  return true;
}

void SimpleSessionNotifier::OnControlFrameLost(const QuicFrame& frame) {
  QuicControlFrameId id = GetControlFrameId(frame);
  if (id == kInvalidControlFrameId) {
    return;
  }
  QUICHE_DCHECK(id < least_unacked_ + control_frames_.size());
  if (id < least_unacked_ ||
      GetControlFrameId(control_frames_.at(id - least_unacked_)) ==
          kInvalidControlFrameId) {
    return;
  }
  if (!lost_control_frames_.contains(id)) {
    lost_control_frames_[id] = true;
  }
}

bool SimpleSessionNotifier::IsControlFrameOutstanding(
    const QuicFrame& frame) const {
  QuicControlFrameId id = GetControlFrameId(frame);
  if (id == kInvalidControlFrameId) {
    return false;
  }
  return id < least_unacked_ + control_frames_.size() && id >= least_unacked_ &&
         GetControlFrameId(control_frames_.at(id - least_unacked_)) !=
             kInvalidControlFrameId;
}

bool SimpleSessionNotifier::RetransmitLostControlFrames() {
  while (!lost_control_frames_.empty()) {
    QuicFrame pending = control_frames_.at(lost_control_frames_.begin()->first -
                                           least_unacked_);
    QuicFrame copy = CopyRetransmittableControlFrame(pending);
    connection_->SetTransmissionType(LOSS_RETRANSMISSION);
    if (!connection_->SendControlFrame(copy)) {
      // Connection is write blocked.
      DeleteFrame(&copy);
      break;
    }
    lost_control_frames_.pop_front();
  }
  return lost_control_frames_.empty();
}

bool SimpleSessionNotifier::RetransmitLostCryptoData() {
  if (QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    for (EncryptionLevel level :
         {ENCRYPTION_INITIAL, ENCRYPTION_HANDSHAKE, ENCRYPTION_ZERO_RTT,
          ENCRYPTION_FORWARD_SECURE}) {
      auto& state = crypto_state_[level];
      while (!state.pending_retransmissions.Empty()) {
        connection_->SetTransmissionType(HANDSHAKE_RETRANSMISSION);
        EncryptionLevel current_encryption_level =
            connection_->encryption_level();
        connection_->SetDefaultEncryptionLevel(level);
        QuicIntervalSet<QuicStreamOffset> retransmission(
            state.pending_retransmissions.begin()->min(),
            state.pending_retransmissions.begin()->max());
        retransmission.Intersection(crypto_bytes_transferred_[level]);
        QuicStreamOffset retransmission_offset = retransmission.begin()->min();
        QuicByteCount retransmission_length =
            retransmission.begin()->max() - retransmission.begin()->min();
        size_t bytes_consumed = connection_->SendCryptoData(
            level, retransmission_length, retransmission_offset);
        // Restore encryption level.
        connection_->SetDefaultEncryptionLevel(current_encryption_level);
        state.pending_retransmissions.Difference(
            retransmission_offset, retransmission_offset + bytes_consumed);
        if (bytes_consumed < retransmission_length) {
          return false;
        }
      }
    }
    return true;
  }
  if (!stream_map_.contains(
          QuicUtils::GetCryptoStreamId(connection_->transport_version()))) {
    return true;
  }
  auto& state =
      stream_map_
          .find(QuicUtils::GetCryptoStreamId(connection_->transport_version()))
          ->second;
  while (!state.pending_retransmissions.Empty()) {
    connection_->SetTransmissionType(HANDSHAKE_RETRANSMISSION);
    QuicIntervalSet<QuicStreamOffset> retransmission(
        state.pending_retransmissions.begin()->min(),
        state.pending_retransmissions.begin()->max());
    EncryptionLevel retransmission_encryption_level = ENCRYPTION_INITIAL;
    for (size_t i = 0; i < NUM_ENCRYPTION_LEVELS; ++i) {
      if (retransmission.Intersects(crypto_bytes_transferred_[i])) {
        retransmission_encryption_level = static_cast<EncryptionLevel>(i);
        retransmission.Intersection(crypto_bytes_transferred_[i]);
        break;
      }
    }
    QuicStreamOffset retransmission_offset = retransmission.begin()->min();
    QuicByteCount retransmission_length =
        retransmission.begin()->max() - retransmission.begin()->min();
    EncryptionLevel current_encryption_level = connection_->encryption_level();
    // Set appropriate encryption level.
    connection_->SetDefaultEncryptionLevel(retransmission_encryption_level);
    QuicConsumedData consumed = connection_->SendStreamData(
        QuicUtils::GetCryptoStreamId(connection_->transport_version()),
        retransmission_length, retransmission_offset, NO_FIN);
    // Restore encryption level.
    connection_->SetDefaultEncryptionLevel(current_encryption_level);
    state.pending_retransmissions.Difference(
        retransmission_offset, retransmission_offset + consumed.bytes_consumed);
    if (consumed.bytes_consumed < retransmission_length) {
      break;
    }
  }
  return state.pending_retransmissions.Empty();
}

bool SimpleSessionNotifier::RetransmitLostStreamData() {
  for (auto& pair : stream_map_) {
    StreamState& state = pair.second;
    QuicConsumedData consumed(0, false);
    while (!state.pending_retransmissions.Empty() || state.fin_lost) {
      connection_->SetTransmissionType(LOSS_RETRANSMISSION);
      if (state.pending_retransmissions.Empty()) {
        QUIC_DVLOG(1) << "stream " << pair.first
                      << " retransmits fin only frame.";
        consumed =
            connection_->SendStreamData(pair.first, 0, state.bytes_sent, FIN);
        state.fin_lost = !consumed.fin_consumed;
        if (state.fin_lost) {
          QUIC_DLOG(INFO) << "Connection is write blocked";
          return false;
        }
      } else {
        QuicStreamOffset offset = state.pending_retransmissions.begin()->min();
        QuicByteCount length = state.pending_retransmissions.begin()->max() -
                               state.pending_retransmissions.begin()->min();
        const bool can_bundle_fin =
            state.fin_lost && (offset + length == state.bytes_sent);
        consumed = connection_->SendStreamData(pair.first, length, offset,
                                               can_bundle_fin ? FIN : NO_FIN);
        QUIC_DVLOG(1) << "stream " << pair.first
                      << " tries to retransmit stream data [" << offset << ", "
                      << offset + length << ") and fin: " << can_bundle_fin
                      << ", consumed: " << consumed;
        state.pending_retransmissions.Difference(
            offset, offset + consumed.bytes_consumed);
        if (consumed.fin_consumed) {
          state.fin_lost = false;
        }
        if (length > consumed.bytes_consumed ||
            (can_bundle_fin && !consumed.fin_consumed)) {
          QUIC_DVLOG(1) << "Connection is write blocked";
          break;
        }
      }
    }
  }
  return !HasLostStreamData();
}

bool SimpleSessionNotifier::WriteBufferedCryptoData() {
  for (size_t i = 0; i < NUM_ENCRYPTION_LEVELS; ++i) {
    const StreamState& state = crypto_state_[i];
    QuicIntervalSet<QuicStreamOffset> buffered_crypto_data(0,
                                                           state.bytes_total);
    buffered_crypto_data.Difference(crypto_bytes_transferred_[i]);
    for (const auto& interval : buffered_crypto_data) {
      size_t bytes_written = connection_->SendCryptoData(
          static_cast<EncryptionLevel>(i), interval.Length(), interval.min());
      crypto_state_[i].bytes_sent += bytes_written;
      crypto_bytes_transferred_[i].Add(interval.min(),
                                       interval.min() + bytes_written);
      if (bytes_written < interval.Length()) {
        return false;
      }
    }
  }
  return true;
}

bool SimpleSessionNotifier::WriteBufferedControlFrames() {
  while (HasBufferedControlFrames()) {
    QuicFrame frame_to_send =
        control_frames_.at(least_unsent_ - least_unacked_);
    QuicFrame copy = CopyRetransmittableControlFrame(frame_to_send);
    connection_->SetTransmissionType(NOT_RETRANSMISSION);
    if (!connection_->SendControlFrame(copy)) {
      // Connection is write blocked.
      DeleteFrame(&copy);
      break;
    }
    ++least_unsent_;
  }
  return !HasBufferedControlFrames();
}

bool SimpleSessionNotifier::HasBufferedControlFrames() const {
  return least_unsent_ < least_unacked_ + control_frames_.size();
}

bool SimpleSessionNotifier::HasBufferedStreamData() const {
  for (const auto& pair : stream_map_) {
    const auto& state = pair.second;
    if (state.bytes_total > state.bytes_sent ||
        (state.fin_buffered && !state.fin_sent)) {
      return true;
    }
  }
  return false;
}

bool SimpleSessionNotifier::StreamIsWaitingForAcks(QuicStreamId id) const {
  if (!stream_map_.contains(id)) {
    return false;
  }
  const StreamState& state = stream_map_.find(id)->second;
  return !state.bytes_acked.Contains(0, state.bytes_sent) ||
         state.fin_outstanding;
}

bool SimpleSessionNotifier::StreamHasBufferedData(QuicStreamId id) const {
  if (!stream_map_.contains(id)) {
    return false;
  }
  const StreamState& state = stream_map_.find(id)->second;
  return state.bytes_total > state.bytes_sent ||
         (state.fin_buffered && !state.fin_sent);
}

bool SimpleSessionNotifier::HasLostStreamData() const {
  for (const auto& pair : stream_map_) {
    const auto& state = pair.second;
    if (!state.pending_retransmissions.Empty() || state.fin_lost) {
      return true;
    }
  }
  return false;
}

}  // namespace test

}  // namespace quic

"""

```