Response:
Let's break down the thought process for analyzing the provided C++ code and generating the detailed explanation.

1. **Understanding the Request:** The core request is to analyze the `quic_crypto_stream.cc` file from Chromium's QUIC implementation. This involves understanding its functionality, potential connections to JavaScript, logic, common errors, and debugging context.

2. **Initial Code Scan (Keywords and Structure):**  The first step is to quickly scan the code for keywords and overall structure. Keywords like `Crypto`, `EncryptionLevel`, `Handshake`, `Frame`, `Send`, `Receive`, `Ack`, `Retransmission`, and the file path itself (`net/third_party/quiche/src/quiche/quic/core/`) immediately suggest this file deals with the cryptographic handshake within the QUIC protocol. The presence of `#include` statements confirms dependencies on other QUIC components.

3. **Identifying Key Classes and Methods:**  The core class is `QuicCryptoStream`. The constructor and destructor are noted. Then, focus shifts to prominent methods like:
    * `OnCryptoFrame`: Handles incoming crypto data (for newer QUIC versions).
    * `OnStreamFrame`: Handles incoming stream data (for older QUIC versions).
    * `OnDataAvailable`:  Triggers processing of received data.
    * `WriteCryptoData`: Sends crypto data.
    * `OnCryptoFrameAcked`: Handles acknowledgments of sent crypto data.
    * `WritePendingCryptoRetransmission`:  Handles retransmitting lost crypto data.
    * `WriteBufferedCryptoFrames`: Sends buffered crypto data.

4. **Discerning Functionality (High-Level):** Based on the class name and method names, the primary functions are:
    * **Receiving and Processing Crypto Handshake Messages:** This involves parsing incoming data, managing encryption levels, and potentially triggering further actions based on the handshake progress.
    * **Sending Crypto Handshake Messages:**  This involves formatting and sending data needed for the handshake.
    * **Managing Encryption Levels:**  QUIC uses different encryption levels during the handshake, and this class manages data associated with each level.
    * **Handling Retransmissions:** Ensuring reliable delivery of handshake messages.
    * **Flow Control (Internal):** Managing the amount of data buffered for the handshake.

5. **Identifying Version-Specific Logic:** The code frequently checks `QuicVersionUsesCryptoFrames(session()->transport_version())`. This is a crucial indicator that the implementation handles different QUIC versions, with newer versions using dedicated `CRYPTO` frames and older versions embedding crypto data within regular `STREAM` frames. This distinction is important for understanding the code's branching logic.

6. **Considering the JavaScript Connection:**  The question explicitly asks about JavaScript. The connection isn't direct. QUIC operates at a lower network layer than typical JavaScript execution environments in browsers. The connection is *indirect*:
    * **Browsers use QUIC:**  Chromium is a browser, and it uses QUIC for network communication.
    * **JavaScript interacts with network APIs:** JavaScript code running in a browser uses APIs (like `fetch` or WebSockets) that can use QUIC under the hood.
    * **Impact on Performance and Security:** The effectiveness of the crypto handshake directly affects the security and speed of network requests initiated by JavaScript.

7. **Developing Examples (Logic, Usage Errors):**
    * **Logic Example:**  Focus on a specific method like `OnCryptoFrame`. Hypothesize an input (a `QuicCryptoFrame` at a specific encryption level) and trace its path through the code, noting the expected actions (buffering data, processing it).
    * **User/Programming Errors:** Think about scenarios where the developer using the QUIC library might make mistakes. Examples include:
        * Not handling version compatibility.
        * Incorrectly managing encryption levels.
        * Sending too much data.

8. **Tracing User Actions (Debugging Context):** Imagine a user browsing a website. Map their actions to the underlying network events that would lead to this code being executed:
    * User types a URL and presses Enter.
    * Browser initiates a QUIC connection.
    * The `QuicCryptoStream` is created to handle the handshake.
    * Crypto messages are exchanged.

9. **Structuring the Explanation:** Organize the information logically:
    * Start with a concise summary of the file's purpose.
    * Detail the main functionalities.
    * Explain the JavaScript connection (and emphasize the indirect nature).
    * Provide concrete examples for logic and errors.
    * Offer debugging insights through user action tracing.
    * Include a summary table for quick reference.

10. **Refinement and Review:** After drafting the explanation, review it for clarity, accuracy, and completeness. Ensure the language is understandable and addresses all aspects of the original request. For instance, double-check that the examples are specific and illustrate the points effectively. Make sure the version-specific logic is clearly explained.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus heavily on the cryptographic details.
* **Correction:**  Broaden the scope to include the overall handshake management, version handling, and the indirect JavaScript connection. The request is about the file's function, not just the low-level crypto.
* **Initial thought:**  Provide very technical code-level explanations.
* **Correction:**  Balance technical details with higher-level descriptions to make the explanation accessible to a wider audience. Use analogies or simpler terms where appropriate.
* **Initial thought:** Focus solely on successful operation.
* **Correction:**  Dedicate a section to common errors and debugging, as these are crucial for understanding how things can go wrong.

By following these steps and incorporating self-correction, a comprehensive and informative explanation like the example provided can be generated.
这个`quic_crypto_stream.cc`文件是Chromium网络栈中QUIC协议实现的关键部分，它负责管理QUIC连接的加密握手过程。可以将其视为QUIC连接安全建立的“指挥中心”。

**主要功能:**

1. **处理加密握手消息:**
   - 接收并解析来自对端的加密握手消息（例如：ClientHello, ServerHello, 等）。
   - 将本地生成的加密握手消息发送给对端。
   - 根据QUIC版本，处理的消息格式可能是 `CRYPTO` 帧（较新版本）或普通的 `STREAM` 帧（较旧版本）。
   - 使用 `CryptoMessageParser` 来解析接收到的数据。

2. **管理加密级别:**
   - QUIC握手过程中会经历不同的加密级别（例如：INITIAL, HANDSHAKE, 1-RTT）。
   - `QuicCryptoStream` 负责在不同的加密级别发送和接收数据。
   - 维护不同加密级别的发送缓冲区 (`substreams_`) 和接收序列器。

3. **处理数据重传:**
   - 跟踪已发送但尚未被确认的加密数据。
   - 在数据丢失或超时的情况下，负责重传必要的加密握手消息，以确保握手成功完成。

4. **流量控制（内部）:**
   - 虽然加密流不受连接级别的流量控制限制，但内部会管理每个加密级别的发送缓冲区大小，防止过度缓冲。

5. **与 `QuicSession` 交互:**
   - `QuicCryptoStream` 是 `QuicSession` 的一部分，它通过 `stream_delegate()` 与 `QuicSession` 进行通信，例如发送数据。

6. **版本兼容性处理:**
   - 代码中大量使用了 `QuicVersionUsesCryptoFrames`，表明该类需要处理不同QUIC版本之间的差异，特别是如何发送和接收加密数据。

**与 JavaScript 功能的关系 (间接):**

`QuicCryptoStream` 本身是用 C++ 编写的，直接运行在服务器或客户端的网络栈中，**不直接**与 JavaScript 代码交互。但是，它对 JavaScript 的功能有重要的间接影响：

- **HTTPS 加速:** 当用户在浏览器中访问使用 HTTPS 的网站时，如果底层使用了 QUIC 协议，`QuicCryptoStream` 负责建立安全的连接。这直接影响网页加载速度和安全性，而 JavaScript 代码通常在网页加载完成后执行。
- **Fetch API 和 WebSocket:**  JavaScript 的 `fetch` API 和 WebSocket API 可以使用 QUIC 作为底层传输协议。 `QuicCryptoStream` 成功完成握手是这些 API 能够安全可靠地工作的基础。
- **性能提升:**  QUIC 的目标之一是提高网络性能。 成功的加密握手是建立高性能连接的前提，从而提升 JavaScript 发起的网络请求的效率。

**举例说明:**

假设用户在浏览器中访问一个使用 QUIC 的 HTTPS 网站 `example.com`。

1. **用户操作:** 用户在地址栏输入 `https://example.com` 并按下回车。
2. **浏览器行为:** 浏览器开始建立与 `example.com` 服务器的 QUIC 连接。
3. **`QuicCryptoStream` 的作用:**
   - **客户端 `QuicCryptoStream`** 会生成并发送 `ClientHello` 消息。
   - **服务器端 `QuicCryptoStream`** 接收到 `ClientHello`，进行处理，并生成 `ServerHello` 等握手消息发送回客户端。
   - 这个过程中，会涉及密钥交换、身份验证等加密操作，由 `QuicCryptoStream` 调用相关的加密组件完成。
   - 如果网络出现丢包，`QuicCryptoStream` 会负责重传丢失的握手消息。
   - 当握手成功完成，双方都切换到 `1-RTT` 加密级别后，JavaScript 代码发起的 `fetch` 请求或 WebSocket 连接才能安全地传输数据。
4. **JavaScript 的作用:**  一旦 QUIC 连接建立，网页中的 JavaScript 代码可以使用 `fetch` 从服务器请求数据，或者使用 WebSocket 建立实时的双向通信。这些请求会利用已经建立的安全的 QUIC 连接。

**逻辑推理：假设输入与输出**

**场景：客户端发送 `ClientHello` 消息**

**假设输入:**

- 当前加密级别: `INITIAL`
- 要发送的数据: 包含客户端支持的协议版本、加密套件、SNI 等信息的 `ClientHello` 消息的原始字节流。

**`QuicCryptoStream::WriteCryptoData` 的内部逻辑 (简化):**

1. 检查当前 QUIC 版本是否使用 `CRYPTO` 帧。
2. 根据当前加密级别 (`INITIAL`)，选择对应的发送缓冲区 (`substreams_[INITIAL_DATA].send_buffer`)。
3. 将 `ClientHello` 数据添加到发送缓冲区。
4. 调用 `stream_delegate()->SendCryptoData`，将数据发送到网络。这会创建一个包含 `CRYPTO` 帧（如果适用）的 QUIC 数据包。

**预期输出:**

- 网络上发送出一个 QUIC 数据包，其中包含一个 `CRYPTO` 帧（或 `STREAM` 帧），其数据部分是 `ClientHello` 消息。
- 客户端的发送缓冲区中记录了已发送的数据和偏移量，以便后续进行重传管理。

**用户或编程常见的使用错误：**

1. **版本不匹配:** 如果客户端和服务器配置的 QUIC 版本不兼容，握手过程可能会失败。例如，客户端只支持旧版本，而服务器只支持新版本，则握手消息格式不兼容。
   - **用户操作:** 用户尝试访问只支持最新 QUIC 版本的网站，但用户的浏览器由于版本过旧或配置问题，只尝试使用旧版本。
   - **错误现象:** 连接建立失败，浏览器可能显示连接错误或超时。
   - **调试线索:** 抓包可以看到客户端发送的握手消息与服务器期望的格式不符，或者版本协商失败。

2. **加密配置错误:**  客户端或服务器的加密套件配置不一致，导致无法找到双方都支持的加密算法。
   - **编程错误:** 服务器管理员配置了只支持某些特定加密算法，而客户端的配置中没有包含这些算法。
   - **错误现象:** 握手失败，通常会收到加密相关的错误码。
   - **调试线索:** 查看握手过程中的协商信息，确认双方支持的加密套件。

3. **过早发送应用数据:**  在加密握手完成之前，尝试发送应用层数据。
   - **编程错误:**  应用程序在连接建立的早期就尝试发送 HTTP 请求，而此时连接可能还在进行握手。
   - **错误现象:**  数据可能被丢弃，或者连接异常终止。
   - **调试线索:**  观察数据包的加密级别，确认应用数据是否在 `1-RTT` 加密级别建立之前发送。

**用户操作如何一步步到达这里，作为调试线索:**

假设用户报告一个网站加载缓慢或连接不稳定的问题，调试人员可能需要查看 `QuicCryptoStream` 的行为。

1. **用户尝试访问网站:** 用户在浏览器地址栏输入网址并访问。
2. **浏览器发起 QUIC 连接:** 浏览器判断可以尝试使用 QUIC 连接到服务器。
3. **`QuicCryptoStream` 初始化:**  `QuicConnection` 创建 `QuicCryptoStream` 对象来管理握手。
4. **客户端发送 `ClientHello`:**  `QuicCryptoStream::WriteCryptoData` 被调用，发送初始的握手消息。
5. **网络传输:** `ClientHello` 数据包通过网络发送到服务器。
6. **服务器接收 `ClientHello`:** 服务器的 `QuicCryptoStream::OnCryptoFrame` 或 `OnStreamFrame` (取决于版本) 被调用，处理接收到的数据。
7. **服务器发送 `ServerHello`:** 服务器的 `QuicCryptoStream::WriteCryptoData` 被调用，发送响应的握手消息。
8. **客户端接收 `ServerHello`:** 客户端的 `QuicCryptoStream::OnCryptoFrame` 或 `OnStreamFrame` 被调用处理。
9. **持续握手过程:**  根据协议流程，可能需要交换更多的握手消息。
10. **握手完成或失败:**  如果一切顺利，握手完成，加密级别提升到 `1-RTT`。如果出现错误（例如版本不匹配，加密失败），握手会失败，连接会被关闭。

**调试线索:**

- **抓包分析:** 使用 Wireshark 等工具抓取网络包，可以查看握手消息的内容、加密级别、以及是否有重传等情况。这有助于判断握手过程中的哪个环节出现问题。
- **QUIC 事件日志:** Chromium 和 QUIC 库通常会提供详细的事件日志，记录握手过程中的关键事件，例如发送和接收了哪些握手消息，加密级别何时发生变化，是否有错误发生。
- **代码断点:** 在 `QuicCryptoStream` 的关键方法（例如 `OnCryptoFrame`, `WriteCryptoData`, `OnCryptoFrameAcked`) 设置断点，可以跟踪握手过程中的数据流和状态变化。
- **查看连接状态:**  检查 `QuicConnection` 和 `QuicSession` 的状态，可以了解握手是否完成，当前的加密级别等信息。

总而言之，`net/third_party/quiche/src/quiche/quic/core/quic_crypto_stream.cc` 是 QUIC 连接安全性的核心，它负责复杂的加密握手过程，确保通信的机密性和完整性。虽然它本身不直接涉及 JavaScript 代码，但其成功运行是基于 QUIC 的网络应用能够安全高效运行的基础。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_crypto_stream.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_crypto_stream.h"

#include <algorithm>
#include <optional>
#include <string>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/crypto_handshake.h"
#include "quiche/quic/core/frames/quic_crypto_frame.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_session.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"

namespace quic {

#define ENDPOINT                                                   \
  (session()->perspective() == Perspective::IS_SERVER ? "Server: " \
                                                      : "Client:"  \
                                                        " ")

QuicCryptoStream::QuicCryptoStream(QuicSession* session)
    : QuicStream(
          QuicVersionUsesCryptoFrames(session->transport_version())
              ? QuicUtils::GetInvalidStreamId(session->transport_version())
              : QuicUtils::GetCryptoStreamId(session->transport_version()),
          session,
          /*is_static=*/true,
          QuicVersionUsesCryptoFrames(session->transport_version())
              ? CRYPTO
              : BIDIRECTIONAL),
      substreams_{{{this}, {this}, {this}}} {
  // The crypto stream is exempt from connection level flow control.
  DisableConnectionFlowControlForThisStream();
}

QuicCryptoStream::~QuicCryptoStream() {}

// static
QuicByteCount QuicCryptoStream::CryptoMessageFramingOverhead(
    QuicTransportVersion version, QuicConnectionId connection_id) {
  QUICHE_DCHECK(
      QuicUtils::IsConnectionIdValidForVersion(connection_id, version));
  quiche::QuicheVariableLengthIntegerLength retry_token_length_length =
      quiche::VARIABLE_LENGTH_INTEGER_LENGTH_1;
  quiche::QuicheVariableLengthIntegerLength length_length =
      quiche::VARIABLE_LENGTH_INTEGER_LENGTH_2;
  if (!QuicVersionHasLongHeaderLengths(version)) {
    retry_token_length_length = quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0;
    length_length = quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0;
  }
  return QuicPacketCreator::StreamFramePacketOverhead(
      version, connection_id.length(), 0, /*include_version=*/true,
      /*include_diversification_nonce=*/true, PACKET_4BYTE_PACKET_NUMBER,
      retry_token_length_length, length_length,
      /*offset=*/0);
}

void QuicCryptoStream::OnCryptoFrame(const QuicCryptoFrame& frame) {
  QUIC_BUG_IF(quic_bug_12573_1,
              !QuicVersionUsesCryptoFrames(session()->transport_version()))
      << "Versions less than 47 shouldn't receive CRYPTO frames";
  EncryptionLevel level = session()->connection()->last_decrypted_level();
  if (!IsCryptoFrameExpectedForEncryptionLevel(level)) {
    OnUnrecoverableError(
        IETF_QUIC_PROTOCOL_VIOLATION,
        absl::StrCat("CRYPTO_FRAME is unexpectedly received at level ", level));
    return;
  }
  CryptoSubstream& substream =
      substreams_[QuicUtils::GetPacketNumberSpace(level)];
  substream.sequencer.OnCryptoFrame(frame);
  EncryptionLevel frame_level = level;
  if (substream.sequencer.NumBytesBuffered() >
      BufferSizeLimitForLevel(frame_level)) {
    OnUnrecoverableError(QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA,
                         "Too much crypto data received");
  }
}

void QuicCryptoStream::OnStreamFrame(const QuicStreamFrame& frame) {
  if (QuicVersionUsesCryptoFrames(session()->transport_version())) {
    QUIC_PEER_BUG(quic_peer_bug_12573_2)
        << "Crypto data received in stream frame instead of crypto frame";
    OnUnrecoverableError(QUIC_INVALID_STREAM_DATA, "Unexpected stream frame");
  }
  QuicStream::OnStreamFrame(frame);
}

void QuicCryptoStream::OnDataAvailable() {
  EncryptionLevel level = session()->connection()->last_decrypted_level();
  if (!QuicVersionUsesCryptoFrames(session()->transport_version())) {
    // Versions less than 47 only support QUIC crypto, which ignores the
    // EncryptionLevel passed into CryptoMessageParser::ProcessInput (and
    // OnDataAvailableInSequencer).
    OnDataAvailableInSequencer(sequencer(), level);
    return;
  }
  OnDataAvailableInSequencer(
      &substreams_[QuicUtils::GetPacketNumberSpace(level)].sequencer, level);
}

void QuicCryptoStream::OnDataAvailableInSequencer(
    QuicStreamSequencer* sequencer, EncryptionLevel level) {
  struct iovec iov;
  while (sequencer->GetReadableRegion(&iov)) {
    absl::string_view data(static_cast<char*>(iov.iov_base), iov.iov_len);
    if (!crypto_message_parser()->ProcessInput(data, level)) {
      OnUnrecoverableError(crypto_message_parser()->error(),
                           crypto_message_parser()->error_detail());
      return;
    }
    sequencer->MarkConsumed(iov.iov_len);
    if (one_rtt_keys_available() &&
        crypto_message_parser()->InputBytesRemaining() == 0) {
      // If the handshake is complete and the current message has been fully
      // processed then no more handshake messages are likely to arrive soon
      // so release the memory in the stream sequencer.
      sequencer->ReleaseBufferIfEmpty();
    }
  }
}

void QuicCryptoStream::WriteCryptoData(EncryptionLevel level,
                                       absl::string_view data) {
  if (!QuicVersionUsesCryptoFrames(session()->transport_version())) {
    WriteOrBufferDataAtLevel(data, /*fin=*/false, level,
                             /*ack_listener=*/nullptr);
    return;
  }
  if (data.empty()) {
    QUIC_BUG(quic_bug_10322_1) << "Empty crypto data being written";
    return;
  }
  const bool had_buffered_data = HasBufferedCryptoFrames();
  QuicStreamSendBuffer* send_buffer =
      &substreams_[QuicUtils::GetPacketNumberSpace(level)].send_buffer;
  QuicStreamOffset offset = send_buffer->stream_offset();

  // Ensure this data does not cause the send buffer for this encryption level
  // to exceed its size limit.
  if (GetQuicFlag(quic_bounded_crypto_send_buffer)) {
    QUIC_BUG_IF(quic_crypto_stream_offset_lt_bytes_written,
                offset < send_buffer->stream_bytes_written());
    uint64_t current_buffer_size =
        offset - std::min(offset, send_buffer->stream_bytes_written());
    if (current_buffer_size > 0) {
      QUIC_CODE_COUNT(quic_received_crypto_data_with_non_empty_send_buffer);
      if (BufferSizeLimitForLevel(level) <
          (current_buffer_size + data.length())) {
        QUIC_BUG(quic_crypto_send_buffer_overflow)
            << absl::StrCat("Too much data for crypto send buffer with level: ",
                            EncryptionLevelToString(level),
                            ", current_buffer_size: ", current_buffer_size,
                            ", data length: ", data.length(),
                            ", SNI: ", crypto_negotiated_params().sni);
        OnUnrecoverableError(QUIC_INTERNAL_ERROR,
                             "Too much data for crypto send buffer");
        return;
      }
    }
  }

  // Append |data| to the send buffer for this encryption level.
  send_buffer->SaveStreamData(data);
  if (kMaxStreamLength - offset < data.length()) {
    QUIC_BUG(quic_bug_10322_2) << "Writing too much crypto handshake data";
    OnUnrecoverableError(QUIC_INTERNAL_ERROR,
                         "Writing too much crypto handshake data");
    return;
  }
  if (had_buffered_data) {
    // Do not try to write if there is buffered data.
    return;
  }

  size_t bytes_consumed = stream_delegate()->SendCryptoData(
      level, data.length(), offset, NOT_RETRANSMISSION);
  send_buffer->OnStreamDataConsumed(bytes_consumed);
}

size_t QuicCryptoStream::BufferSizeLimitForLevel(EncryptionLevel) const {
  return GetQuicFlag(quic_max_buffered_crypto_bytes);
}

bool QuicCryptoStream::OnCryptoFrameAcked(const QuicCryptoFrame& frame,
                                          QuicTime::Delta /*ack_delay_time*/) {
  QuicByteCount newly_acked_length = 0;
  if (!substreams_[QuicUtils::GetPacketNumberSpace(frame.level)]
           .send_buffer.OnStreamDataAcked(frame.offset, frame.data_length,
                                          &newly_acked_length)) {
    OnUnrecoverableError(QUIC_INTERNAL_ERROR,
                         "Trying to ack unsent crypto data.");
    return false;
  }
  return newly_acked_length > 0;
}

void QuicCryptoStream::OnStreamReset(const QuicRstStreamFrame& /*frame*/) {
  stream_delegate()->OnStreamError(QUIC_INVALID_STREAM_ID,
                                   "Attempt to reset crypto stream");
}

void QuicCryptoStream::NeuterUnencryptedStreamData() {
  NeuterStreamDataOfEncryptionLevel(ENCRYPTION_INITIAL);
}

void QuicCryptoStream::NeuterStreamDataOfEncryptionLevel(
    EncryptionLevel level) {
  if (!QuicVersionUsesCryptoFrames(session()->transport_version())) {
    for (const auto& interval : bytes_consumed_[level]) {
      QuicByteCount newly_acked_length = 0;
      send_buffer().OnStreamDataAcked(
          interval.min(), interval.max() - interval.min(), &newly_acked_length);
    }
    return;
  }
  QuicStreamSendBuffer* send_buffer =
      &substreams_[QuicUtils::GetPacketNumberSpace(level)].send_buffer;
  // TODO(nharper): Consider adding a Clear() method to QuicStreamSendBuffer
  // to replace the following code.
  QuicIntervalSet<QuicStreamOffset> to_ack = send_buffer->bytes_acked();
  to_ack.Complement(0, send_buffer->stream_offset());
  for (const auto& interval : to_ack) {
    QuicByteCount newly_acked_length = 0;
    send_buffer->OnStreamDataAcked(
        interval.min(), interval.max() - interval.min(), &newly_acked_length);
  }
}

void QuicCryptoStream::OnStreamDataConsumed(QuicByteCount bytes_consumed) {
  if (QuicVersionUsesCryptoFrames(session()->transport_version())) {
    QUIC_BUG(quic_bug_10322_3)
        << "Stream data consumed when CRYPTO frames should be in use";
  }
  if (bytes_consumed > 0) {
    bytes_consumed_[session()->connection()->encryption_level()].Add(
        stream_bytes_written(), stream_bytes_written() + bytes_consumed);
  }
  QuicStream::OnStreamDataConsumed(bytes_consumed);
}

bool QuicCryptoStream::HasPendingCryptoRetransmission() const {
  if (!QuicVersionUsesCryptoFrames(session()->transport_version())) {
    return false;
  }
  for (const auto& substream : substreams_) {
    if (substream.send_buffer.HasPendingRetransmission()) {
      return true;
    }
  }
  return false;
}

void QuicCryptoStream::WritePendingCryptoRetransmission() {
  QUIC_BUG_IF(quic_bug_12573_3,
              !QuicVersionUsesCryptoFrames(session()->transport_version()))
      << "Versions less than 47 don't write CRYPTO frames";
  for (uint8_t i = INITIAL_DATA; i <= APPLICATION_DATA; ++i) {
    auto packet_number_space = static_cast<PacketNumberSpace>(i);
    QuicStreamSendBuffer* send_buffer =
        &substreams_[packet_number_space].send_buffer;
    while (send_buffer->HasPendingRetransmission()) {
      auto pending = send_buffer->NextPendingRetransmission();
      size_t bytes_consumed = stream_delegate()->SendCryptoData(
          GetEncryptionLevelToSendCryptoDataOfSpace(packet_number_space),
          pending.length, pending.offset, HANDSHAKE_RETRANSMISSION);
      send_buffer->OnStreamDataRetransmitted(pending.offset, bytes_consumed);
      if (bytes_consumed < pending.length) {
        return;
      }
    }
  }
}

void QuicCryptoStream::WritePendingRetransmission() {
  while (HasPendingRetransmission()) {
    StreamPendingRetransmission pending =
        send_buffer().NextPendingRetransmission();
    QuicIntervalSet<QuicStreamOffset> retransmission(
        pending.offset, pending.offset + pending.length);
    EncryptionLevel retransmission_encryption_level = ENCRYPTION_INITIAL;
    // Determine the encryption level to write the retransmission
    // at. The retransmission should be written at the same encryption level
    // as the original transmission.
    for (size_t i = 0; i < NUM_ENCRYPTION_LEVELS; ++i) {
      if (retransmission.Intersects(bytes_consumed_[i])) {
        retransmission_encryption_level = static_cast<EncryptionLevel>(i);
        retransmission.Intersection(bytes_consumed_[i]);
        break;
      }
    }
    pending.offset = retransmission.begin()->min();
    pending.length =
        retransmission.begin()->max() - retransmission.begin()->min();
    QuicConsumedData consumed = RetransmitStreamDataAtLevel(
        pending.offset, pending.length, retransmission_encryption_level,
        HANDSHAKE_RETRANSMISSION);
    if (consumed.bytes_consumed < pending.length) {
      // The connection is write blocked.
      break;
    }
  }
}

bool QuicCryptoStream::RetransmitStreamData(QuicStreamOffset offset,
                                            QuicByteCount data_length,
                                            bool /*fin*/,
                                            TransmissionType type) {
  QUICHE_DCHECK(type == HANDSHAKE_RETRANSMISSION || type == PTO_RETRANSMISSION);
  QuicIntervalSet<QuicStreamOffset> retransmission(offset,
                                                   offset + data_length);
  // Determine the encryption level to send data. This only needs to be once as
  // [offset, offset + data_length) is guaranteed to be in the same packet.
  EncryptionLevel send_encryption_level = ENCRYPTION_INITIAL;
  for (size_t i = 0; i < NUM_ENCRYPTION_LEVELS; ++i) {
    if (retransmission.Intersects(bytes_consumed_[i])) {
      send_encryption_level = static_cast<EncryptionLevel>(i);
      break;
    }
  }
  retransmission.Difference(bytes_acked());
  for (const auto& interval : retransmission) {
    QuicStreamOffset retransmission_offset = interval.min();
    QuicByteCount retransmission_length = interval.max() - interval.min();
    QuicConsumedData consumed = RetransmitStreamDataAtLevel(
        retransmission_offset, retransmission_length, send_encryption_level,
        type);
    if (consumed.bytes_consumed < retransmission_length) {
      // The connection is write blocked.
      return false;
    }
  }

  return true;
}

QuicConsumedData QuicCryptoStream::RetransmitStreamDataAtLevel(
    QuicStreamOffset retransmission_offset, QuicByteCount retransmission_length,
    EncryptionLevel encryption_level, TransmissionType type) {
  QUICHE_DCHECK(type == HANDSHAKE_RETRANSMISSION || type == PTO_RETRANSMISSION);
  const auto consumed = stream_delegate()->WritevData(
      id(), retransmission_length, retransmission_offset, NO_FIN, type,
      encryption_level);
  QUIC_DVLOG(1) << ENDPOINT << "stream " << id()
                << " is forced to retransmit stream data ["
                << retransmission_offset << ", "
                << retransmission_offset + retransmission_length
                << "), with encryption level: " << encryption_level
                << ", consumed: " << consumed;
  OnStreamFrameRetransmitted(retransmission_offset, consumed.bytes_consumed,
                             consumed.fin_consumed);

  return consumed;
}

uint64_t QuicCryptoStream::crypto_bytes_read() const {
  if (!QuicVersionUsesCryptoFrames(session()->transport_version())) {
    return stream_bytes_read();
  }
  uint64_t bytes_read = 0;
  for (const CryptoSubstream& substream : substreams_) {
    bytes_read += substream.sequencer.NumBytesConsumed();
  }
  return bytes_read;
}

// TODO(haoyuewang) Move this test-only method under
// quiche/quic/test_tools.
uint64_t QuicCryptoStream::BytesReadOnLevel(EncryptionLevel level) const {
  return substreams_[QuicUtils::GetPacketNumberSpace(level)]
      .sequencer.NumBytesConsumed();
}

uint64_t QuicCryptoStream::BytesSentOnLevel(EncryptionLevel level) const {
  return substreams_[QuicUtils::GetPacketNumberSpace(level)]
      .send_buffer.stream_bytes_written();
}

bool QuicCryptoStream::WriteCryptoFrame(EncryptionLevel level,
                                        QuicStreamOffset offset,
                                        QuicByteCount data_length,
                                        QuicDataWriter* writer) {
  QUIC_BUG_IF(quic_bug_12573_4,
              !QuicVersionUsesCryptoFrames(session()->transport_version()))
      << "Versions less than 47 don't write CRYPTO frames (2)";
  return substreams_[QuicUtils::GetPacketNumberSpace(level)]
      .send_buffer.WriteStreamData(offset, data_length, writer);
}

void QuicCryptoStream::OnCryptoFrameLost(QuicCryptoFrame* crypto_frame) {
  QUIC_BUG_IF(quic_bug_12573_5,
              !QuicVersionUsesCryptoFrames(session()->transport_version()))
      << "Versions less than 47 don't lose CRYPTO frames";
  substreams_[QuicUtils::GetPacketNumberSpace(crypto_frame->level)]
      .send_buffer.OnStreamDataLost(crypto_frame->offset,
                                    crypto_frame->data_length);
}

bool QuicCryptoStream::RetransmitData(QuicCryptoFrame* crypto_frame,
                                      TransmissionType type) {
  QUIC_BUG_IF(quic_bug_12573_6,
              !QuicVersionUsesCryptoFrames(session()->transport_version()))
      << "Versions less than 47 don't retransmit CRYPTO frames";
  QuicIntervalSet<QuicStreamOffset> retransmission(
      crypto_frame->offset, crypto_frame->offset + crypto_frame->data_length);
  QuicStreamSendBuffer* send_buffer =
      &substreams_[QuicUtils::GetPacketNumberSpace(crypto_frame->level)]
           .send_buffer;
  retransmission.Difference(send_buffer->bytes_acked());
  if (retransmission.Empty()) {
    return true;
  }
  for (const auto& interval : retransmission) {
    size_t retransmission_offset = interval.min();
    size_t retransmission_length = interval.max() - interval.min();
    EncryptionLevel retransmission_encryption_level =
        GetEncryptionLevelToSendCryptoDataOfSpace(
            QuicUtils::GetPacketNumberSpace(crypto_frame->level));
    size_t bytes_consumed = stream_delegate()->SendCryptoData(
        retransmission_encryption_level, retransmission_length,
        retransmission_offset, type);
    send_buffer->OnStreamDataRetransmitted(retransmission_offset,
                                           bytes_consumed);
    if (bytes_consumed < retransmission_length) {
      return false;
    }
  }
  return true;
}

void QuicCryptoStream::WriteBufferedCryptoFrames() {
  QUIC_BUG_IF(quic_bug_12573_7,
              !QuicVersionUsesCryptoFrames(session()->transport_version()))
      << "Versions less than 47 don't use CRYPTO frames";
  for (uint8_t i = INITIAL_DATA; i <= APPLICATION_DATA; ++i) {
    auto packet_number_space = static_cast<PacketNumberSpace>(i);
    QuicStreamSendBuffer* send_buffer =
        &substreams_[packet_number_space].send_buffer;
    const size_t data_length =
        send_buffer->stream_offset() - send_buffer->stream_bytes_written();
    if (data_length == 0) {
      // No buffered data for this encryption level.
      continue;
    }
    size_t bytes_consumed = stream_delegate()->SendCryptoData(
        GetEncryptionLevelToSendCryptoDataOfSpace(packet_number_space),
        data_length, send_buffer->stream_bytes_written(), NOT_RETRANSMISSION);
    send_buffer->OnStreamDataConsumed(bytes_consumed);
    if (bytes_consumed < data_length) {
      // Connection is write blocked.
      break;
    }
  }
}

bool QuicCryptoStream::HasBufferedCryptoFrames() const {
  QUIC_BUG_IF(quic_bug_12573_8,
              !QuicVersionUsesCryptoFrames(session()->transport_version()))
      << "Versions less than 47 don't use CRYPTO frames";
  for (const CryptoSubstream& substream : substreams_) {
    const QuicStreamSendBuffer& send_buffer = substream.send_buffer;
    QUICHE_DCHECK_GE(send_buffer.stream_offset(),
                     send_buffer.stream_bytes_written());
    if (send_buffer.stream_offset() > send_buffer.stream_bytes_written()) {
      return true;
    }
  }
  return false;
}

bool QuicCryptoStream::IsFrameOutstanding(EncryptionLevel level, size_t offset,
                                          size_t length) const {
  if (!QuicVersionUsesCryptoFrames(session()->transport_version())) {
    // This only happens if a client was originally configured for a version
    // greater than 45, but received a version negotiation packet and is
    // attempting to retransmit for a version less than 47. Outside of tests,
    // this is a misconfiguration of the client, and this connection will be
    // doomed. Return false here to avoid trying to retransmit CRYPTO frames on
    // the wrong transport version.
    return false;
  }
  return substreams_[QuicUtils::GetPacketNumberSpace(level)]
      .send_buffer.IsStreamDataOutstanding(offset, length);
}

bool QuicCryptoStream::IsWaitingForAcks() const {
  if (!QuicVersionUsesCryptoFrames(session()->transport_version())) {
    return QuicStream::IsWaitingForAcks();
  }
  for (const CryptoSubstream& substream : substreams_) {
    if (substream.send_buffer.stream_bytes_outstanding()) {
      return true;
    }
  }
  return false;
}

QuicCryptoStream::CryptoSubstream::CryptoSubstream(
    QuicCryptoStream* crypto_stream)
    : sequencer(crypto_stream),
      send_buffer(crypto_stream->session()
                      ->connection()
                      ->helper()
                      ->GetStreamSendBufferAllocator()) {}

#undef ENDPOINT  // undef for jumbo builds
}  // namespace quic
```