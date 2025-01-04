Response:
The user wants to understand the functionality of the `quic_framer.cc` file in the Chromium network stack, specifically focusing on the code provided in part 5 of a 9-part series.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Function:** The primary function of this code snippet is to process different types of QUIC frames received from the network. This involves reading data from the input buffer (`QuicDataReader`), validating the data according to the QUIC protocol, and then notifying a visitor object (`visitor_`) about the parsed frame.

2. **Analyze Individual Frame Processing Functions:**  Examine each function starting with `Process...Frame`:
    * `ProcessCryptoFrame`: Handles the initial handshake and key exchange data.
    * `ProcessNewTokenFrame`: Processes tokens used for connection migration and anti-amplification.
    * `ProcessStreamFrame`:  Deals with data transfer for individual streams.
    * `ProcessAckFrame` and `ProcessIetfAckFrame`: Process acknowledgment frames, indicating which packets have been received.
    * `ProcessTimestampsInAckFrame` and `ProcessIetfTimestampsInAckFrame`:  Handle timestamp information within the ACK frames.
    * `ProcessStopWaitingFrame`: (Deprecated) Used in older QUIC versions to signal which packets the sender should no longer wait for an ACK.
    * `ProcessRstStreamFrame`:  Handles stream reset requests.
    * `ProcessConnectionCloseFrame`:  Processes connection closure signals.
    * `ProcessGoAwayFrame`:  (Deprecated)  Used in older QUIC versions to gracefully terminate a connection.
    * `ProcessWindowUpdateFrame`:  Indicates the receiver's willingness to receive more data on a specific stream.
    * `ProcessBlockedFrame`:  Indicates that a stream or the entire connection is blocked due to flow control limits.
    * `ProcessPaddingFrame`:  Handles padding bytes.
    * `ProcessMessageFrame`: Processes generic message frames.

3. **Relate to JavaScript (if applicable):**  Consider how these low-level networking operations relate to higher-level JavaScript APIs used in web browsers. While JavaScript doesn't directly manipulate QUIC frames, it uses the underlying network stack to perform actions like fetching resources (`fetch API`), establishing WebSockets, or using WebRTC. The frame processing logic here is crucial for the reliable and efficient transfer of data for those JavaScript features.

4. **Identify Logic and Provide Examples:** For functions with clear logical steps (e.g., `ProcessAckFrame`, `ProcessStreamFrame`), devise simple input scenarios and the expected outcome. Focus on validation checks and data extraction.

5. **Highlight Common Errors:** Look for explicit error checks in the code (`set_detailed_error`) and think about what user or programming errors might lead to these checks failing. Consider issues like invalid data format, out-of-order packets, or exceeding flow control limits.

6. **Trace User Actions (Debugging):**  Imagine a user performing an action in a web browser (e.g., clicking a link, opening a webpage). Trace the path from that action down to the point where this code might be involved. Focus on the initiation of network requests and the reception of data.

7. **Summarize Functionality (for Part 5):** Based on the analysis of the functions in this specific code block, provide a concise summary of its purpose within the larger `QuicFramer` class. Emphasize the parsing and validation of various frame types.

8. **Structure the Response:** Organize the information logically using headings and bullet points for clarity. Start with a general overview and then delve into specifics for each function.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** Focus too much on individual bit manipulation in frame parsing.
* **Correction:** Shift focus to the higher-level purpose of each function and the overall data flow.
* **Initial thought:**  Overstate the direct connection to JavaScript.
* **Correction:**  Clarify that the connection is indirect, through the underlying network stack that supports JavaScript APIs.
* **Initial thought:**  Provide very complex examples for input/output.
* **Correction:**  Simplify examples to illustrate the core logic without getting bogged down in details.
* **Initial thought:**  List all possible user actions.
* **Correction:** Focus on common web browsing actions that trigger network requests.
这是 `net/third_party/quiche/src/quiche/quic/core/quic_framer.cc` 文件的第五部分，主要负责解析接收到的 QUIC 数据包中的各种帧（Frame）。以下是该部分代码的功能归纳和详细说明：

**功能归纳（针对第五部分）:**

这部分代码主要负责处理以下几种 QUIC 帧类型：

* **CRYPTO 帧:** 用于传输加密握手数据。
* **NEW_TOKEN 帧:** 用于服务器向客户端发送新的连接迁移令牌。
* **STREAM 帧:** 用于传输应用层数据流。
* **ACK 帧 (Google QUIC 格式和 IETF QUIC 格式):** 用于确认接收到的数据包，包含确认的包序号范围和可选的时间戳信息。

**详细功能说明:**

1. **`ProcessCryptoFrame(QuicDataReader* reader, QuicCryptoFrame* frame)`:**
   - **功能:**  解析 CRYPTO 帧，读取偏移量和数据。
   - **假设输入与输出:**
     - **假设输入:** `reader` 指向包含 CRYPTO 帧数据的缓冲区，帧类型已识别。
     - **输出:** `frame` 对象的 `offset` 和 `data_buffer` 被填充。
   - **用户/编程常见的使用错误:** 接收到的 CRYPTO 帧数据不完整或格式错误。例如，无法读取足够的字节来填充偏移量或数据长度。
   - **用户操作如何到达这里:**  在 QUIC 连接的握手阶段，客户端或服务器发送加密的握手消息，这些消息会被封装在 CRYPTO 帧中。用户发起连接或者服务器响应连接请求时会触发。

2. **`ProcessNewTokenFrame(QuicDataReader* reader, QuicNewTokenFrame* frame)`:**
   - **功能:** 解析 NEW_TOKEN 帧，读取令牌数据。
   - **假设输入与输出:**
     - **假设输入:** `reader` 指向包含 NEW_TOKEN 帧数据的缓冲区，帧类型已识别。
     - **输出:** `frame` 对象的 `token` 被填充。
   - **用户/编程常见的使用错误:** 接收到的 NEW_TOKEN 帧数据不完整或格式错误。例如，无法读取令牌长度或令牌数据本身。
   - **用户操作如何到达这里:** 当服务器希望客户端在后续连接中使用一个连接迁移令牌时，会发送 NEW_TOKEN 帧。这通常发生在首次连接建立后。

3. **`ProcessStreamFrame(QuicDataReader* reader, uint8_t frame_type, QuicStreamFrame* frame)`:**
   - **功能:** 解析 STREAM 帧，读取流 ID、偏移量和数据。
   - **逻辑推理:**  根据 `frame_type` 中的标志位判断是否包含偏移量和 FIN 标志。
   - **假设输入与输出:**
     - **假设输入:** `reader` 指向包含 STREAM 帧数据的缓冲区，帧类型已识别。
     - **输出:** `frame` 对象的 `stream_id`、`offset` 和 `data_buffer` 被填充，`fin` 标志被设置。
   - **用户/编程常见的使用错误:**
     - 接收到的 STREAM 帧数据不完整或格式错误。
     - `reliable_offset` 大于 `final_offset`，这在逻辑上是不可能的。
   - **用户操作如何到达这里:**  在 QUIC 连接建立后，应用层的数据传输会通过 STREAM 帧进行。用户浏览网页、下载文件、进行在线聊天等操作都会导致 STREAM 帧的发送和接收。

4. **`ProcessAckFrame(QuicDataReader* reader, uint8_t frame_type)`:**
   - **功能:** 解析 Google QUIC 格式的 ACK 帧，读取确认的包序号范围和时间戳信息。
   - **逻辑推理:**  根据 `frame_type` 中的标志位判断是否存在多个 ACK 块。
   - **假设输入与输出:**
     - **假设输入:** `reader` 指向包含 ACK 帧数据的缓冲区，帧类型已识别。
     - **输出:** 调用 `visitor_->OnAckFrameStart`、`visitor_->OnAckRange` 和 `visitor_->OnAckFrameEnd` 等方法通知访问者已解析的 ACK 信息。
   - **用户/编程常见的使用错误:**
     - 接收到的 ACK 帧数据不完整或格式错误。
     - `largest_acked` 小于已发送的第一个包的序号，这表示接收到了关于未发送包的确认信息。
     - ACK 块的长度计算错误导致下溢。
   - **用户操作如何到达这里:** 当接收端接收到数据包后，会发送 ACK 帧来告知发送端哪些包已经被成功接收。任何网络请求的响应都会包含 ACK 帧。

5. **`ProcessTimestampsInAckFrame(uint8_t num_received_packets, QuicPacketNumber largest_acked, QuicDataReader* reader)`:**
   - **功能:** 解析 Google QUIC 格式的 ACK 帧中的时间戳信息。
   - **逻辑推理:**  读取每个已接收数据包相对于 `largest_acked` 的序号差值和时间差值。
   - **假设输入与输出:**
     - **假设输入:** `reader` 指向包含时间戳数据的缓冲区，`largest_acked` 是 ACK 帧中确认的最大包序号。
     - **输出:** 调用 `visitor_->OnAckTimestamp` 方法通知访问者每个已接收数据包的时间戳。
   - **用户/编程常见的使用错误:**
     - 接收到的时间戳数据不完整或格式错误。
     - `delta_from_largest_observed` 过大，导致计算出的包序号小于或等于 0。
   - **用户操作如何到达这里:**  如果启用了时间戳功能，接收端会在 ACK 帧中包含接收到每个数据包的时间信息。这通常与 `ProcessAckFrame` 一起处理。

6. **`ProcessIetfAckFrame(QuicDataReader* reader, uint64_t frame_type, QuicAckFrame* ack_frame)`:**
   - **功能:** 解析 IETF QUIC 格式的 ACK 帧，读取确认的包序号范围和可选的 ECN 计数信息。
   - **逻辑推理:**  读取 ACK 块的数量，并逐个解析每个 ACK 块和间隔。
   - **假设输入与输出:**
     - **假设输入:** `reader` 指向包含 ACK 帧数据的缓冲区，帧类型已识别。
     - **输出:** `ack_frame` 对象的 `largest_acked`、`ack_delay_time` 和确认范围被填充，并调用 `visitor_->OnAckFrameStart`、`visitor_->OnAckRange` 和 `visitor_->OnAckFrameEnd` 等方法通知访问者。
   - **用户/编程常见的使用错误:**
     - 接收到的 ACK 帧数据不完整或格式错误。
     - `largest_acked` 小于已发送的第一个包的序号。
     - ACK 块或间隔的长度计算错误导致下溢。
   - **用户操作如何到达这里:**  与 Google QUIC ACK 帧类似，当接收端接收到数据包后，会发送 IETF QUIC ACK 帧。

7. **`ProcessIetfTimestampsInAckFrame(QuicPacketNumber largest_acked, QuicDataReader* reader)`:**
   - **功能:** 解析 IETF QUIC 格式的 ACK 帧中的时间戳信息。
   - **逻辑推理:** 读取时间戳范围的数量，并逐个解析每个范围内的间隙和时间戳增量。
   - **假设输入与输出:**
     - **假设输入:** `reader` 指向包含时间戳数据的缓冲区，`largest_acked` 是 ACK 帧中确认的最大包序号。
     - **输出:** 调用 `visitor_->OnAckTimestamp` 方法通知访问者每个已接收数据包的时间戳。
   - **用户/编程常见的使用错误:**
     - 接收到的时间戳数据不完整或格式错误。
     - 时间戳间隙过大，导致计算出的包序号小于 0。
     - 时间戳增量过大，导致计算出的时间戳早于 0。
   - **用户操作如何到达这里:** 如果启用了时间戳功能，接收端会在 IETF QUIC ACK 帧中包含接收到每个数据包的时间信息。这通常与 `ProcessIetfAckFrame` 一起处理。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不直接与 JavaScript 交互，但它是 Chromium 网络栈的一部分，负责处理底层的 QUIC 协议。当 JavaScript 代码通过以下 API 发起网络请求时，这些代码会被间接调用：

* **`fetch()` API:** 用于发起 HTTP 请求。QUIC 是 HTTP/3 的底层传输协议，因此 `fetch()` 请求可能会使用 QUIC。
* **`WebSocket` API:**  虽然 WebSocket 通常不直接使用 QUIC，但在某些配置下，可以基于 QUIC 实现。
* **WebRTC API:**  WebRTC 的数据通道可以使用 QUIC 作为传输协议。

**举例说明:**

例如，当你在浏览器中通过 `fetch()` API 请求一个网页时：

1. **JavaScript (`fetch()`):**  JavaScript 代码调用 `fetch('https://example.com')`。
2. **Chromium 网络栈 (C++):**
   - 网络栈会建立与 `example.com` 的 QUIC 连接（如果适用）。
   - 当 `example.com` 的服务器响应时，会发送包含网页数据的 QUIC 数据包。
   - **`QuicFramer::ProcessStreamFrame()`**  会被调用来解析包含网页数据的 STREAM 帧，并将数据传递给上层处理。
   - 当客户端确认接收到这些数据包后，会发送 ACK 帧。
   - **`QuicFramer::ProcessAckFrame()`** 或 **`QuicFramer::ProcessIetfAckFrame()`** 会被调用来处理接收到的 ACK 帧，更新已确认的包信息。

**用户操作如何一步步的到达这里，作为调试线索：**

假设用户在浏览器中点击了一个链接，导致一个网络请求被发送，最终接收到一个包含 STREAM 帧的数据包：

1. **用户操作:** 用户点击链接 `https://example.com/page.html`。
2. **浏览器事件:** 浏览器捕获点击事件。
3. **网络请求发起:** 浏览器解析 URL，发现需要建立到 `example.com` 的连接，并根据协议选择（例如，HTTP/3 使用 QUIC）发起网络请求。
4. **QUIC 连接建立 (如果尚未建立):**  QUIC 握手过程会涉及 CRYPTO 帧的交换，`ProcessCryptoFrame` 会被调用。
5. **数据传输:** 服务器发送包含 `page.html` 内容的 QUIC 数据包，其中数据被封装在 STREAM 帧中。
6. **帧解析:** 接收端的 `QuicFramer` 会接收到数据包，并根据帧类型调用相应的处理函数，例如 **`QuicFramer::ProcessStreamFrame()`**。
7. **数据传递:**  `ProcessStreamFrame` 将解析出的数据传递给 `QuicFramer` 的访问者 (通常是连接或会话对象)，以便进一步处理，最终将网页内容渲染到浏览器中。

**总结：**

这部分 `quic_framer.cc` 代码的核心功能是解析接收到的 QUIC 数据包中的关键帧类型，包括用于握手的 CRYPTO 帧、用于连接迁移的 NEW_TOKEN 帧、用于数据传输的 STREAM 帧以及用于确认数据包接收的 ACK 帧。它负责将网络字节流转换为结构化的数据，并通知上层模块进行进一步处理。对于调试而言，理解这些帧的结构和解析过程对于排查 QUIC 连接问题至关重要。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_framer.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共9部分，请归纳一下它的功能

"""
ReadVarInt62(&frame.reliable_offset)) {
    set_detailed_error("Failed to read the reliable offset.");
    return false;
  }
  if (frame.reliable_offset > frame.final_offset) {
    set_detailed_error("reliable_offset > final_offset");
    return false;
  }
  return true;
}

bool QuicFramer::ProcessAckFrame(QuicDataReader* reader, uint8_t frame_type) {
  const bool has_ack_blocks =
      ExtractBit(frame_type, kQuicHasMultipleAckBlocksOffset);
  uint8_t num_ack_blocks = 0;
  uint8_t num_received_packets = 0;

  // Determine the two lengths from the frame type: largest acked length,
  // ack block length.
  const QuicPacketNumberLength ack_block_length =
      ReadAckPacketNumberLength(ExtractBits(
          frame_type, kQuicSequenceNumberLengthNumBits, kActBlockLengthOffset));
  const QuicPacketNumberLength largest_acked_length =
      ReadAckPacketNumberLength(ExtractBits(
          frame_type, kQuicSequenceNumberLengthNumBits, kLargestAckedOffset));

  uint64_t largest_acked;
  if (!reader->ReadBytesToUInt64(largest_acked_length, &largest_acked)) {
    set_detailed_error("Unable to read largest acked.");
    return false;
  }

  if (largest_acked < first_sending_packet_number_.ToUint64()) {
    // Connection always sends packet starting from kFirstSendingPacketNumber >
    // 0, peer has observed an unsent packet.
    set_detailed_error("Largest acked is 0.");
    return false;
  }

  uint64_t ack_delay_time_us;
  if (!reader->ReadUFloat16(&ack_delay_time_us)) {
    set_detailed_error("Unable to read ack delay time.");
    return false;
  }

  if (!visitor_->OnAckFrameStart(
          QuicPacketNumber(largest_acked),
          ack_delay_time_us == kUFloat16MaxValue
              ? QuicTime::Delta::Infinite()
              : QuicTime::Delta::FromMicroseconds(ack_delay_time_us))) {
    // The visitor suppresses further processing of the packet. Although this is
    // not a parsing error, returns false as this is in middle of processing an
    // ack frame,
    set_detailed_error("Visitor suppresses further processing of ack frame.");
    return false;
  }

  if (has_ack_blocks && !reader->ReadUInt8(&num_ack_blocks)) {
    set_detailed_error("Unable to read num of ack blocks.");
    return false;
  }

  uint64_t first_block_length;
  if (!reader->ReadBytesToUInt64(ack_block_length, &first_block_length)) {
    set_detailed_error("Unable to read first ack block length.");
    return false;
  }

  if (first_block_length == 0) {
    set_detailed_error("First block length is zero.");
    return false;
  }
  bool first_ack_block_underflow = first_block_length > largest_acked + 1;
  if (first_block_length + first_sending_packet_number_.ToUint64() >
      largest_acked + 1) {
    first_ack_block_underflow = true;
  }
  if (first_ack_block_underflow) {
    set_detailed_error(absl::StrCat("Underflow with first ack block length ",
                                    first_block_length, " largest acked is ",
                                    largest_acked, ".")
                           .c_str());
    return false;
  }

  uint64_t first_received = largest_acked + 1 - first_block_length;
  if (!visitor_->OnAckRange(QuicPacketNumber(first_received),
                            QuicPacketNumber(largest_acked + 1))) {
    // The visitor suppresses further processing of the packet. Although
    // this is not a parsing error, returns false as this is in middle
    // of processing an ack frame,
    set_detailed_error("Visitor suppresses further processing of ack frame.");
    return false;
  }

  if (num_ack_blocks > 0) {
    for (size_t i = 0; i < num_ack_blocks; ++i) {
      uint8_t gap = 0;
      if (!reader->ReadUInt8(&gap)) {
        set_detailed_error("Unable to read gap to next ack block.");
        return false;
      }
      uint64_t current_block_length;
      if (!reader->ReadBytesToUInt64(ack_block_length, &current_block_length)) {
        set_detailed_error("Unable to ack block length.");
        return false;
      }
      bool ack_block_underflow = first_received < gap + current_block_length;
      if (first_received < gap + current_block_length +
                               first_sending_packet_number_.ToUint64()) {
        ack_block_underflow = true;
      }
      if (ack_block_underflow) {
        set_detailed_error(absl::StrCat("Underflow with ack block length ",
                                        current_block_length,
                                        ", end of block is ",
                                        first_received - gap, ".")
                               .c_str());
        return false;
      }

      first_received -= (gap + current_block_length);
      if (current_block_length > 0) {
        if (!visitor_->OnAckRange(
                QuicPacketNumber(first_received),
                QuicPacketNumber(first_received) + current_block_length)) {
          // The visitor suppresses further processing of the packet. Although
          // this is not a parsing error, returns false as this is in middle
          // of processing an ack frame,
          set_detailed_error(
              "Visitor suppresses further processing of ack frame.");
          return false;
        }
      }
    }
  }

  if (!reader->ReadUInt8(&num_received_packets)) {
    set_detailed_error("Unable to read num received packets.");
    return false;
  }

  if (!ProcessTimestampsInAckFrame(num_received_packets,
                                   QuicPacketNumber(largest_acked), reader)) {
    return false;
  }

  // Done processing the ACK frame.
  std::optional<QuicEcnCounts> ecn_counts = std::nullopt;
  if (!visitor_->OnAckFrameEnd(QuicPacketNumber(first_received), ecn_counts)) {
    set_detailed_error(
        "Error occurs when visitor finishes processing the ACK frame.");
    return false;
  }

  return true;
}

bool QuicFramer::ProcessTimestampsInAckFrame(uint8_t num_received_packets,
                                             QuicPacketNumber largest_acked,
                                             QuicDataReader* reader) {
  if (num_received_packets == 0) {
    return true;
  }
  uint8_t delta_from_largest_observed;
  if (!reader->ReadUInt8(&delta_from_largest_observed)) {
    set_detailed_error("Unable to read sequence delta in received packets.");
    return false;
  }

  if (largest_acked.ToUint64() <= delta_from_largest_observed) {
    set_detailed_error(
        absl::StrCat("delta_from_largest_observed too high: ",
                     delta_from_largest_observed,
                     ", largest_acked: ", largest_acked.ToUint64())
            .c_str());
    return false;
  }

  // Time delta from the framer creation.
  uint32_t time_delta_us;
  if (!reader->ReadUInt32(&time_delta_us)) {
    set_detailed_error("Unable to read time delta in received packets.");
    return false;
  }

  QuicPacketNumber seq_num = largest_acked - delta_from_largest_observed;
  if (process_timestamps_) {
    last_timestamp_ = CalculateTimestampFromWire(time_delta_us);

    visitor_->OnAckTimestamp(seq_num, creation_time_ + last_timestamp_);
  }

  for (uint8_t i = 1; i < num_received_packets; ++i) {
    if (!reader->ReadUInt8(&delta_from_largest_observed)) {
      set_detailed_error("Unable to read sequence delta in received packets.");
      return false;
    }
    if (largest_acked.ToUint64() <= delta_from_largest_observed) {
      set_detailed_error(
          absl::StrCat("delta_from_largest_observed too high: ",
                       delta_from_largest_observed,
                       ", largest_acked: ", largest_acked.ToUint64())
              .c_str());
      return false;
    }
    seq_num = largest_acked - delta_from_largest_observed;

    // Time delta from the previous timestamp.
    uint64_t incremental_time_delta_us;
    if (!reader->ReadUFloat16(&incremental_time_delta_us)) {
      set_detailed_error(
          "Unable to read incremental time delta in received packets.");
      return false;
    }

    if (process_timestamps_) {
      last_timestamp_ = last_timestamp_ + QuicTime::Delta::FromMicroseconds(
                                              incremental_time_delta_us);
      visitor_->OnAckTimestamp(seq_num, creation_time_ + last_timestamp_);
    }
  }
  return true;
}

bool QuicFramer::ProcessIetfAckFrame(QuicDataReader* reader,
                                     uint64_t frame_type,
                                     QuicAckFrame* ack_frame) {
  uint64_t largest_acked;
  if (!reader->ReadVarInt62(&largest_acked)) {
    set_detailed_error("Unable to read largest acked.");
    return false;
  }
  if (largest_acked < first_sending_packet_number_.ToUint64()) {
    // Connection always sends packet starting from kFirstSendingPacketNumber >
    // 0, peer has observed an unsent packet.
    set_detailed_error("Largest acked is 0.");
    return false;
  }
  ack_frame->largest_acked = static_cast<QuicPacketNumber>(largest_acked);
  uint64_t ack_delay_time_in_us;
  if (!reader->ReadVarInt62(&ack_delay_time_in_us)) {
    set_detailed_error("Unable to read ack delay time.");
    return false;
  }

  if (ack_delay_time_in_us >=
      (quiche::kVarInt62MaxValue >> peer_ack_delay_exponent_)) {
    ack_frame->ack_delay_time = QuicTime::Delta::Infinite();
  } else {
    ack_delay_time_in_us = (ack_delay_time_in_us << peer_ack_delay_exponent_);
    ack_frame->ack_delay_time =
        QuicTime::Delta::FromMicroseconds(ack_delay_time_in_us);
  }
  if (!visitor_->OnAckFrameStart(QuicPacketNumber(largest_acked),
                                 ack_frame->ack_delay_time)) {
    // The visitor suppresses further processing of the packet. Although this is
    // not a parsing error, returns false as this is in middle of processing an
    // ACK frame.
    set_detailed_error("Visitor suppresses further processing of ACK frame.");
    return false;
  }

  // Get number of ACK blocks from the packet.
  uint64_t ack_block_count;
  if (!reader->ReadVarInt62(&ack_block_count)) {
    set_detailed_error("Unable to read ack block count.");
    return false;
  }
  // There always is a first ACK block, which is the (number of packets being
  // acked)-1, up to and including the packet at largest_acked. Therefore if the
  // value is 0, then only largest is acked. If it is 1, then largest-1,
  // largest] are acked, etc
  uint64_t ack_block_value;
  if (!reader->ReadVarInt62(&ack_block_value)) {
    set_detailed_error("Unable to read first ack block length.");
    return false;
  }
  // Calculate the packets being acked in the first block.
  //  +1 because AddRange implementation requires [low,high)
  uint64_t block_high = largest_acked + 1;
  uint64_t block_low = largest_acked - ack_block_value;

  // ack_block_value is the number of packets preceding the
  // largest_acked packet which are in the block being acked. Thus,
  // its maximum value is largest_acked-1. Test this, reporting an
  // error if the value is wrong.
  if (ack_block_value + first_sending_packet_number_.ToUint64() >
      largest_acked) {
    set_detailed_error(absl::StrCat("Underflow with first ack block length ",
                                    ack_block_value + 1, " largest acked is ",
                                    largest_acked, ".")
                           .c_str());
    return false;
  }

  if (!visitor_->OnAckRange(QuicPacketNumber(block_low),
                            QuicPacketNumber(block_high))) {
    // The visitor suppresses further processing of the packet. Although
    // this is not a parsing error, returns false as this is in middle
    // of processing an ACK frame.
    set_detailed_error("Visitor suppresses further processing of ACK frame.");
    return false;
  }

  while (ack_block_count != 0) {
    uint64_t gap_block_value;
    // Get the sizes of the gap and ack blocks,
    if (!reader->ReadVarInt62(&gap_block_value)) {
      set_detailed_error("Unable to read gap block value.");
      return false;
    }
    // It's an error if the gap is larger than the space from packet
    // number 0 to the start of the block that's just been acked, PLUS
    // there must be space for at least 1 packet to be acked. For
    // example, if block_low is 10 and gap_block_value is 9, it means
    // the gap block is 10 packets long, leaving no room for a packet
    // to be acked. Thus, gap_block_value+2 can not be larger than
    // block_low.
    // The test is written this way to detect wrap-arounds.
    if ((gap_block_value + 2) > block_low) {
      set_detailed_error(
          absl::StrCat("Underflow with gap block length ", gap_block_value + 1,
                       " previous ack block start is ", block_low, ".")
              .c_str());
      return false;
    }

    // Adjust block_high to be the top of the next ack block.
    // There is a gap of |gap_block_value| packets between the bottom
    // of ack block N and top of block N+1.  Note that gap_block_value
    // is he size of the gap minus 1 (per the QUIC protocol), and
    // block_high is the packet number of the first packet of the gap
    // (per the implementation of OnAckRange/AddAckRange, below).
    block_high = block_low - 1 - gap_block_value;

    if (!reader->ReadVarInt62(&ack_block_value)) {
      set_detailed_error("Unable to read ack block value.");
      return false;
    }
    if (ack_block_value + first_sending_packet_number_.ToUint64() >
        (block_high - 1)) {
      set_detailed_error(
          absl::StrCat("Underflow with ack block length ", ack_block_value + 1,
                       " latest ack block end is ", block_high - 1, ".")
              .c_str());
      return false;
    }
    // Calculate the low end of the new nth ack block. The +1 is
    // because the encoded value is the blocksize-1.
    block_low = block_high - 1 - ack_block_value;
    if (!visitor_->OnAckRange(QuicPacketNumber(block_low),
                              QuicPacketNumber(block_high))) {
      // The visitor suppresses further processing of the packet. Although
      // this is not a parsing error, returns false as this is in middle
      // of processing an ACK frame.
      set_detailed_error("Visitor suppresses further processing of ACK frame.");
      return false;
    }

    // Another one done.
    ack_block_count--;
  }

  QUICHE_DCHECK(!ack_frame->ecn_counters.has_value());
  if (frame_type == IETF_ACK_RECEIVE_TIMESTAMPS) {
    QUICHE_DCHECK(process_timestamps_);
    if (!ProcessIetfTimestampsInAckFrame(ack_frame->largest_acked, reader)) {
      return false;
    }
  } else if (frame_type == IETF_ACK_ECN) {
    ack_frame->ecn_counters = QuicEcnCounts();
    if (!reader->ReadVarInt62(&ack_frame->ecn_counters->ect0)) {
      set_detailed_error("Unable to read ack ect_0_count.");
      return false;
    }
    if (!reader->ReadVarInt62(&ack_frame->ecn_counters->ect1)) {
      set_detailed_error("Unable to read ack ect_1_count.");
      return false;
    }
    if (!reader->ReadVarInt62(&ack_frame->ecn_counters->ce)) {
      set_detailed_error("Unable to read ack ecn_ce_count.");
      return false;
    }
  }

  if (!visitor_->OnAckFrameEnd(QuicPacketNumber(block_low),
                               ack_frame->ecn_counters)) {
    set_detailed_error(
        "Error occurs when visitor finishes processing the ACK frame.");
    return false;
  }

  return true;
}

bool QuicFramer::ProcessIetfTimestampsInAckFrame(QuicPacketNumber largest_acked,
                                                 QuicDataReader* reader) {
  uint64_t timestamp_range_count;
  if (!reader->ReadVarInt62(&timestamp_range_count)) {
    set_detailed_error("Unable to read receive timestamp range count.");
    return false;
  }
  if (timestamp_range_count == 0) {
    return true;
  }

  QuicPacketNumber packet_number = largest_acked;

  // Iterate through all timestamp ranges, each of which represents a block of
  // contiguous packets for which receive timestamps are being reported. Each
  // range is of the form:
  //
  // Timestamp Range {
  //    Gap (i),
  //    Timestamp Delta Count (i),
  //    Timestamp Delta (i) ...,
  //  }
  for (uint64_t i = 0; i < timestamp_range_count; i++) {
    uint64_t gap;
    if (!reader->ReadVarInt62(&gap)) {
      set_detailed_error("Unable to read receive timestamp gap.");
      return false;
    }
    if (packet_number.ToUint64() < gap) {
      set_detailed_error("Receive timestamp gap too high.");
      return false;
    }
    packet_number = packet_number - gap;
    uint64_t timestamp_count;
    if (!reader->ReadVarInt62(&timestamp_count)) {
      set_detailed_error("Unable to read receive timestamp count.");
      return false;
    }
    if (packet_number.ToUint64() < timestamp_count) {
      set_detailed_error("Receive timestamp count too high.");
      return false;
    }
    for (uint64_t j = 0; j < timestamp_count; j++) {
      uint64_t timestamp_delta;
      if (!reader->ReadVarInt62(&timestamp_delta)) {
        set_detailed_error("Unable to read receive timestamp delta.");
        return false;
      }
      // The first timestamp delta is relative to framer creation time; whereas
      // subsequent deltas are relative to the previous delta in decreasing
      // packet order.
      timestamp_delta = timestamp_delta << receive_timestamps_exponent_;
      if (i == 0 && j == 0) {
        last_timestamp_ = QuicTime::Delta::FromMicroseconds(timestamp_delta);
      } else {
        last_timestamp_ = last_timestamp_ -
                          QuicTime::Delta::FromMicroseconds(timestamp_delta);
        if (last_timestamp_ < QuicTime::Delta::Zero()) {
          set_detailed_error("Receive timestamp delta too high.");
          return false;
        }
      }
      visitor_->OnAckTimestamp(packet_number, creation_time_ + last_timestamp_);
      packet_number--;
    }
    packet_number--;
  }
  return true;
}

bool QuicFramer::ProcessStopWaitingFrame(QuicDataReader* reader,
                                         const QuicPacketHeader& header,
                                         QuicStopWaitingFrame* stop_waiting) {
  uint64_t least_unacked_delta;
  if (!reader->ReadBytesToUInt64(header.packet_number_length,
                                 &least_unacked_delta)) {
    set_detailed_error("Unable to read least unacked delta.");
    return false;
  }
  if (header.packet_number.ToUint64() <= least_unacked_delta) {
    set_detailed_error("Invalid unacked delta.");
    return false;
  }
  stop_waiting->least_unacked = header.packet_number - least_unacked_delta;

  return true;
}

bool QuicFramer::ProcessRstStreamFrame(QuicDataReader* reader,
                                       QuicRstStreamFrame* frame) {
  if (!reader->ReadUInt32(&frame->stream_id)) {
    set_detailed_error("Unable to read stream_id.");
    return false;
  }

  if (!reader->ReadUInt64(&frame->byte_offset)) {
    set_detailed_error("Unable to read rst stream sent byte offset.");
    return false;
  }

  uint32_t error_code;
  if (!reader->ReadUInt32(&error_code)) {
    set_detailed_error("Unable to read rst stream error code.");
    return false;
  }

  if (error_code >= QUIC_STREAM_LAST_ERROR) {
    // Ignore invalid stream error code if any.
    error_code = QUIC_STREAM_LAST_ERROR;
  }

  frame->error_code = static_cast<QuicRstStreamErrorCode>(error_code);

  return true;
}

bool QuicFramer::ProcessConnectionCloseFrame(QuicDataReader* reader,
                                             QuicConnectionCloseFrame* frame) {
  uint32_t error_code;
  frame->close_type = GOOGLE_QUIC_CONNECTION_CLOSE;

  if (!reader->ReadUInt32(&error_code)) {
    set_detailed_error("Unable to read connection close error code.");
    return false;
  }

  // For Google QUIC connection closes, |wire_error_code| and |quic_error_code|
  // must have the same value.
  frame->wire_error_code = error_code;
  frame->quic_error_code = static_cast<QuicErrorCode>(error_code);

  absl::string_view error_details;
  if (!reader->ReadStringPiece16(&error_details)) {
    set_detailed_error("Unable to read connection close error details.");
    return false;
  }
  frame->error_details = std::string(error_details);

  return true;
}

bool QuicFramer::ProcessGoAwayFrame(QuicDataReader* reader,
                                    QuicGoAwayFrame* frame) {
  uint32_t error_code;
  if (!reader->ReadUInt32(&error_code)) {
    set_detailed_error("Unable to read go away error code.");
    return false;
  }

  frame->error_code = static_cast<QuicErrorCode>(error_code);

  uint32_t stream_id;
  if (!reader->ReadUInt32(&stream_id)) {
    set_detailed_error("Unable to read last good stream id.");
    return false;
  }
  frame->last_good_stream_id = static_cast<QuicStreamId>(stream_id);

  absl::string_view reason_phrase;
  if (!reader->ReadStringPiece16(&reason_phrase)) {
    set_detailed_error("Unable to read goaway reason.");
    return false;
  }
  frame->reason_phrase = std::string(reason_phrase);

  return true;
}

bool QuicFramer::ProcessWindowUpdateFrame(QuicDataReader* reader,
                                          QuicWindowUpdateFrame* frame) {
  if (!reader->ReadUInt32(&frame->stream_id)) {
    set_detailed_error("Unable to read stream_id.");
    return false;
  }

  if (!reader->ReadUInt64(&frame->max_data)) {
    set_detailed_error("Unable to read window byte_offset.");
    return false;
  }

  return true;
}

bool QuicFramer::ProcessBlockedFrame(QuicDataReader* reader,
                                     QuicBlockedFrame* frame) {
  QUICHE_DCHECK(!VersionHasIetfQuicFrames(version_.transport_version))
      << "Attempt to process non-IETF QUIC frames in an IETF QUIC version.";

  if (!reader->ReadUInt32(&frame->stream_id)) {
    set_detailed_error("Unable to read stream_id.");
    return false;
  }

  return true;
}

void QuicFramer::ProcessPaddingFrame(QuicDataReader* reader,
                                     QuicPaddingFrame* frame) {
  // Type byte has been read.
  frame->num_padding_bytes = 1;
  uint8_t next_byte;
  while (!reader->IsDoneReading() && reader->PeekByte() == 0x00) {
    reader->ReadBytes(&next_byte, 1);
    QUICHE_DCHECK_EQ(0x00, next_byte);
    ++frame->num_padding_bytes;
  }
}

bool QuicFramer::ProcessMessageFrame(QuicDataReader* reader,
                                     bool no_message_length,
                                     QuicMessageFrame* frame) {
  if (no_message_length) {
    absl::string_view remaining(reader->ReadRemainingPayload());
    frame->data = remaining.data();
    frame->message_length = remaining.length();
    return true;
  }

  uint64_t message_length;
  if (!reader->ReadVarInt62(&message_length)) {
    set_detailed_error("Unable to read message length");
    return false;
  }

  absl::string_view message_piece;
  if (!reader->ReadStringPiece(&message_piece, message_length)) {
    set_detailed_error("Unable to read message data");
    return false;
  }

  frame->data = message_piece.data();
  frame->message_length = message_length;

  return true;
}

// static
absl::string_view QuicFramer::GetAssociatedDataFromEncryptedPacket(
    QuicTransportVersion version, const QuicEncryptedPacket& encrypted,
    uint8_t destination_connection_id_length,
    uint8_t source_connection_id_length, bool includes_version,
    bool includes_diversification_nonce,
    QuicPacketNumberLength packet_number_length,
    quiche::QuicheVariableLengthIntegerLength retry_token_length_length,
    uint64_t retry_token_length,
    quiche::QuicheVariableLengthIntegerLength length_length) {
  // TODO(ianswett): This is identical to QuicData::AssociatedData.
  return absl::string_view(
      encrypted.data(),
      GetStartOfEncryptedData(version, destination_connection_id_length,
                              source_connection_id_length, includes_version,
                              includes_diversification_nonce,
                              packet_number_length, retry_token_length_length,
                              retry_token_length, length_length));
}

void QuicFramer::SetDecrypter(EncryptionLevel level,
                              std::unique_ptr<QuicDecrypter> decrypter) {
  QUICHE_DCHECK_GE(level, decrypter_level_);
  QUICHE_DCHECK(!version_.KnowsWhichDecrypterToUse());
  QUIC_DVLOG(1) << ENDPOINT << "Setting decrypter from level "
                << decrypter_level_ << " to " << level;
  decrypter_[decrypter_level_] = nullptr;
  decrypter_[level] = std::move(decrypter);
  decrypter_level_ = level;
}

void QuicFramer::SetAlternativeDecrypter(
    EncryptionLevel level, std::unique_ptr<QuicDecrypter> decrypter,
    bool latch_once_used) {
  QUICHE_DCHECK_NE(level, decrypter_level_);
  QUICHE_DCHECK(!version_.KnowsWhichDecrypterToUse());
  QUIC_DVLOG(1) << ENDPOINT << "Setting alternative decrypter from level "
                << alternative_decrypter_level_ << " to " << level;
  if (alternative_decrypter_level_ != NUM_ENCRYPTION_LEVELS) {
    decrypter_[alternative_decrypter_level_] = nullptr;
  }
  decrypter_[level] = std::move(decrypter);
  alternative_decrypter_level_ = level;
  alternative_decrypter_latch_ = latch_once_used;
}

void QuicFramer::InstallDecrypter(EncryptionLevel level,
                                  std::unique_ptr<QuicDecrypter> decrypter) {
  QUICHE_DCHECK(version_.KnowsWhichDecrypterToUse());
  QUIC_DVLOG(1) << ENDPOINT << "Installing decrypter at level " << level;
  decrypter_[level] = std::move(decrypter);
}

void QuicFramer::RemoveDecrypter(EncryptionLevel level) {
  QUICHE_DCHECK(version_.KnowsWhichDecrypterToUse());
  QUIC_DVLOG(1) << ENDPOINT << "Removing decrypter at level " << level;
  decrypter_[level] = nullptr;
}

void QuicFramer::SetKeyUpdateSupportForConnection(bool enabled) {
  QUIC_DVLOG(1) << ENDPOINT << "SetKeyUpdateSupportForConnection: " << enabled;
  support_key_update_for_connection_ = enabled;
}

void QuicFramer::DiscardPreviousOneRttKeys() {
  QUICHE_DCHECK(support_key_update_for_connection_);
  QUIC_DVLOG(1) << ENDPOINT << "Discarding previous set of 1-RTT keys";
  previous_decrypter_ = nullptr;
}

bool QuicFramer::DoKeyUpdate(KeyUpdateReason reason) {
  QUICHE_DCHECK(support_key_update_for_connection_);
  if (!next_decrypter_) {
    // If key update is locally initiated, next decrypter might not be created
    // yet.
    next_decrypter_ = visitor_->AdvanceKeysAndCreateCurrentOneRttDecrypter();
  }
  std::unique_ptr<QuicEncrypter> next_encrypter =
      visitor_->CreateCurrentOneRttEncrypter();
  if (!next_decrypter_ || !next_encrypter) {
    QUIC_BUG(quic_bug_10850_58) << "Failed to create next crypters";
    return false;
  }
  key_update_performed_ = true;
  current_key_phase_bit_ = !current_key_phase_bit_;
  QUIC_DLOG(INFO) << ENDPOINT << "DoKeyUpdate: new current_key_phase_bit_="
                  << current_key_phase_bit_;
  current_key_phase_first_received_packet_number_.Clear();
  previous_decrypter_ = std::move(decrypter_[ENCRYPTION_FORWARD_SECURE]);
  decrypter_[ENCRYPTION_FORWARD_SECURE] = std::move(next_decrypter_);
  encrypter_[ENCRYPTION_FORWARD_SECURE] = std::move(next_encrypter);
  switch (reason) {
    case KeyUpdateReason::kInvalid:
      QUIC_CODE_COUNT(quic_key_update_invalid);
      break;
    case KeyUpdateReason::kRemote:
      QUIC_CODE_COUNT(quic_key_update_remote);
      break;
    case KeyUpdateReason::kLocalForTests:
      QUIC_CODE_COUNT(quic_key_update_local_for_tests);
      break;
    case KeyUpdateReason::kLocalForInteropRunner:
      QUIC_CODE_COUNT(quic_key_update_local_for_interop_runner);
      break;
    case KeyUpdateReason::kLocalAeadConfidentialityLimit:
      QUIC_CODE_COUNT(quic_key_update_local_aead_confidentiality_limit);
      break;
    case KeyUpdateReason::kLocalKeyUpdateLimitOverride:
      QUIC_CODE_COUNT(quic_key_update_local_limit_override);
      break;
  }
  visitor_->OnKeyUpdate(reason);
  return true;
}

QuicPacketCount QuicFramer::PotentialPeerKeyUpdateAttemptCount() const {
  return potential_peer_key_update_attempt_count_;
}

const QuicDecrypter* QuicFramer::GetDecrypter(EncryptionLevel level) const {
  QUICHE_DCHECK(version_.KnowsWhichDecrypterToUse());
  return decrypter_[level].get();
}

const QuicDecrypter* QuicFramer::decrypter() const {
  return decrypter_[decrypter_level_].get();
}

const QuicDecrypter* QuicFramer::alternative_decrypter() const {
  if (alternative_decrypter_level_ == NUM_ENCRYPTION_LEVELS) {
    return nullptr;
  }
  return decrypter_[alternative_decrypter_level_].get();
}

void QuicFramer::SetEncrypter(EncryptionLevel level,
                              std::unique_ptr<QuicEncrypter> encrypter) {
  QUICHE_DCHECK_GE(level, 0);
  QUICHE_DCHECK_LT(level, NUM_ENCRYPTION_LEVELS);
  QUIC_DVLOG(1) << ENDPOINT << "Setting encrypter at level " << level;
  encrypter_[level] = std::move(encrypter);
}

void QuicFramer::RemoveEncrypter(EncryptionLevel level) {
  QUIC_DVLOG(1) << ENDPOINT << "Removing encrypter of " << level;
  encrypter_[level] = nullptr;
}

void QuicFramer::SetInitialObfuscators(QuicConnectionId connection_id) {
  CrypterPair crypters;
  CryptoUtils::CreateInitialObfuscators(perspective_, version_, connection_id,
                                        &crypters);
  encrypter_[ENCRYPTION_INITIAL] = std::move(crypters.encrypter);
  decrypter_[ENCRYPTION_INITIAL] = std::move(crypters.decrypter);
}

size_t QuicFramer::EncryptInPlace(EncryptionLevel level,
                                  QuicPacketNumber packet_number, size_t ad_len,
                                  size_t total_len, size_t buffer_len,
                                  char* buffer) {
  QUICHE_DCHECK(packet_number.IsInitialized());
  if (encrypter_[level] == nullptr) {
    QUIC_BUG(quic_bug_10850_59)
        << ENDPOINT
        << "Attempted to encrypt in place without encrypter at level " << level;
    RaiseError(QUIC_ENCRYPTION_FAILURE);
    return 0;
  }

  size_t output_length = 0;
  if (!encrypter_[level]->EncryptPacket(
          packet_number.ToUint64(),
          absl::string_view(buffer, ad_len),  // Associated data
          absl::string_view(buffer + ad_len,
                            total_len - ad_len),  // Plaintext
          buffer + ad_len,                        // Destination buffer
          &output_length, buffer_len - ad_len)) {
    RaiseError(QUIC_ENCRYPTION_FAILURE);
    return 0;
  }
  if (version_.HasHeaderProtection() &&
      !ApplyHeaderProtection(level, buffer, ad_len + output_length, ad_len)) {
    QUIC_DLOG(ERROR) << "Applying header protection failed.";
    RaiseError(QUIC_ENCRYPTION_FAILURE);
    return 0;
  }

  return ad_len + output_length;
}

namespace {

const size_t kHPSampleLen = 16;

constexpr bool IsLongHeader(uint8_t type_byte) {
  return (type_byte & FLAGS_LONG_HEADER) != 0;
}

}  // namespace

bool QuicFramer::ApplyHeaderProtection(EncryptionLevel level, char* buffer,
                                       size_t buffer_len, size_t ad_len) {
  QuicDataReader buffer_reader(buffer, buffer_len);
  QuicDataWriter buffer_writer(buffer_len, buffer);
  // The sample starts 4 bytes after the start of the packet number.
  if (ad_len < last_written_packet_number_length_) {
    return false;
  }
  size_t pn_offset = ad_len - last_written_packet_number_length_;
  // Sample the ciphertext and generate the mask to use for header protection.
  size_t sample_offset = pn_offset + 4;
  QuicDataReader sample_reader(buffer, buffer_len);
  absl::string_view sample;
  if (!sample_reader.Seek(sample_offset) ||
      !sample_reader.ReadStringPiece(&sample, kHPSampleLen)) {
    QUIC_BUG(quic_bug_10850_60)
        << "Not enough bytes to sample: sample_offset " << sample_offset
        << ", sample len: " << kHPSampleLen << ", buffer len: " << buffer_len;
    return false;
  }

  if (encrypter_[level] == nullptr) {
    QUIC_BUG(quic_bug_12975_8)
        << ENDPOINT
        << "Attempted to apply header protection without encrypter at level "
        << level << " using " << version_;
    return false;
  }

  std::string mask = encrypter_[level]->GenerateHeaderProtectionMask(sample);
  if (mask.empty()) {
    QUIC_BUG(quic_bug_10850_61) << "Unable to generate header protection mask.";
    return false;
  }
  QuicDataReader mask_reader(mask.data(), mask.size());

  // Apply the mask to the 4 or 5 least significant bits of the first byte.
  uint8_t bitmask = 0x1f;
  uint8_t type_byte;
  if (!buffer_reader.ReadUInt8(&type_byte)) {
    return false;
  }
  QuicLongHeaderType header_type;
  if (IsLongHeader(type_byte)) {
    bitmask = 0x0f;
    header_type = GetLongHeaderType(type_byte, version_);
    if (header_type == INVALID_PACKET_TYPE) {
      return false;
    }
  }
  uint8_t mask_byte;
  if (!mask_reader.ReadUInt8(&mask_byte) ||
      !buffer_writer.WriteUInt8(type_byte ^ (mask_byte & bitmask))) {
    return false;
  }

  // Adjust |pn_offset| to account for the diversific
"""


```