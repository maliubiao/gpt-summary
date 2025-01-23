Response:
Let's break down the thought process for analyzing this `HttpDecoder.cc` file and answering the user's request.

1. **Understand the Core Function:** The file name `http_decoder.cc` and the inclusion of headers like `quiche/quic/core/http/http_frames.h` immediately suggest this code is responsible for taking raw byte streams and interpreting them as HTTP/3 frames. The `Decoder` suffix reinforces the idea of processing incoming data.

2. **Identify Key Classes and Methods:**  The `HttpDecoder` class is central. Looking at its constructor, destructor, and public methods (`ProcessInput`, `DecodeSettings`), we can start to infer its responsibilities. The presence of a `Visitor` interface suggests a callback pattern where the `HttpDecoder` informs another object about the decoded frames.

3. **Analyze `ProcessInput`:** This is likely the main entry point for feeding data to the decoder. The loop and the `switch` statement based on `state_` are strong indicators of a state machine, which is a common pattern for parsing protocols. This immediately tells us the decoder works incrementally.

4. **Examine the States:** The `enum State` defines the stages of processing a frame. The transitions between states (e.g., `STATE_READING_FRAME_TYPE` to `STATE_READING_FRAME_LENGTH`) reveal the structure of an HTTP/3 frame: Type, Length, Payload.

5. **Focus on Individual State Handlers (e.g., `ReadFrameType`, `ReadFrameLength`, `ReadFramePayload`):**  These methods detail how the decoder extracts information from the byte stream at each stage. The use of `QuicDataReader` is important – it's a utility for reading variable-length integers, which are fundamental to HTTP/3 framing.

6. **Look for Error Handling:** The `RaiseError` method and the checks within the state handlers (e.g., for oversized frames, invalid frame types) indicate how the decoder deals with malformed input.

7. **Identify Buffered vs. Non-Buffered Frames:** The `IsFrameBuffered` method and the states `STATE_BUFFER_OR_PARSE_PAYLOAD` and `STATE_READING_FRAME_PAYLOAD` highlight a key optimization: some frames (like `SETTINGS`) are fully buffered before parsing, while others (like `DATA`, `HEADERS`) are processed piecemeal. This is likely due to the potential size of `DATA` and `HEADERS` frames.

8. **Connect to JavaScript (the trickiest part):**  This requires understanding *where* in the Chromium network stack this code fits and how that interacts with the browser's JavaScript engine. The key insight is that this is *server-side* HTTP/3 decoding. The server needs to understand the HTTP/3 requests coming from the browser. JavaScript in the browser uses APIs like `fetch()` to initiate these requests. The *browser's* QUIC implementation (which uses this `HttpDecoder`) handles the encoding and decoding of the HTTP/3 messages. Therefore, while this specific code *doesn't run in the browser's JavaScript engine*, it's *essential* for the browser's JavaScript to successfully communicate with HTTP/3 servers.

9. **Construct Examples and Scenarios:** Based on the code's functionality, create concrete examples for:
    * **Assumed Input/Output:**  Show how the decoder processes a simple frame.
    * **User Errors:**  Think about common mistakes users (or rather, developers implementing HTTP/3 on a server) might make that would trigger errors in this code.
    * **Debugging:**  Trace how user actions in the browser lead to data being processed by this decoder.

10. **Review and Refine:**  Read through the analysis to ensure clarity, accuracy, and completeness. Ensure the examples are relevant and the connection to JavaScript is well-explained. Pay attention to the specific questions asked in the prompt.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This decoder probably directly handles JavaScript calls."  **Correction:** Realize it's on the server-side within the Chromium network stack, *supporting* the browser's JavaScript interactions.
* **Focusing too much on low-level details:**  **Correction:** Step back and explain the overall purpose and how it fits into the larger network communication picture.
* **Missing concrete examples:** **Correction:** Add specific input byte sequences and expected decoder behavior. Think about real-world scenarios like a user clicking a link or a JavaScript `fetch()` call.
* **Not explicitly addressing all prompt questions:** **Correction:** Go back and ensure each part of the user's request (functionality, JavaScript relationship, examples, debugging) is addressed clearly.

By following this iterative process of understanding the code, identifying key components, and connecting it to the broader context of web communication, a comprehensive and accurate analysis can be achieved.
这个文件 `net/third_party/quiche/src/quiche/quic/core/http/http_decoder.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，它的主要功能是 **解析（解码）HTTP/3 帧**。  它接收原始的字节流数据，并将这些数据按照 HTTP/3 的帧格式进行解析，提取出帧的类型、长度和负载，并将解析出的信息传递给其 `Visitor` 接口的实现者。

以下是它的具体功能列表：

1. **状态管理：**  `HttpDecoder` 使用状态机来管理帧的解析过程。它定义了不同的状态（例如，读取帧类型、读取帧长度、读取帧负载等），并在接收到数据时根据当前状态进行相应的处理。

2. **读取帧类型：**  从输入字节流中读取并解析 HTTP/3 帧的类型。HTTP/3 的帧类型使用变长整数 (VarInt) 编码。

3. **读取帧长度：**  从输入字节流中读取并解析 HTTP/3 帧的负载长度。帧长度也使用变长整数编码。

4. **读取帧负载：**  根据解析出的帧长度，从输入字节流中读取帧的实际负载数据。

5. **帧类型特定处理：**  对于某些特定的帧类型（例如 `SETTINGS`, `GOAWAY`, `MAX_PUSH_ID`, `PRIORITY_UPDATE_REQUEST_STREAM`, `ACCEPT_CH`, `ORIGIN`），`HttpDecoder` 会进行更具体的解析，提取出帧中包含的参数和值。

6. **缓冲部分帧：**  对于某些类型的帧（由 `IsFrameBuffered()` 决定），`HttpDecoder` 会将整个帧的负载缓冲起来，然后再进行解析。这通常用于处理结构较小的帧，例如 `SETTINGS` 帧。

7. **处理未知帧：**  对于无法识别的帧类型，`HttpDecoder` 会通知其 `Visitor`，但不会尝试解析其内部结构。

8. **错误处理：**  当解析过程中遇到错误（例如，无效的帧类型、帧长度超过限制、格式错误等），`HttpDecoder` 会记录错误信息，并通知其 `Visitor`。

9. **`Visitor` 接口：**  `HttpDecoder` 通过 `Visitor` 接口将其解析出的帧信息传递给上层模块。`Visitor` 接口定义了一系列回调方法，用于处理不同类型的帧的开始、负载和结束。

**与 JavaScript 功能的关系：**

`HttpDecoder` 本身是用 C++ 实现的，运行在 Chromium 浏览器的网络进程中，**不直接与 JavaScript 代码交互或运行在同一个进程中**。然而，它在浏览器和服务器之间的 HTTP/3 通信中扮演着至关重要的角色，而这种通信是 JavaScript 代码通过 `fetch` API 或 WebSocket API 等发起的。

当 JavaScript 代码发起一个 HTTP/3 请求时，浏览器会将请求信息编码成 HTTP/3 帧，并通过 QUIC 连接发送出去。当浏览器接收到来自服务器的 HTTP/3 响应时，网络进程中的 `HttpDecoder` 就会负责解析这些响应帧。

例如：

1. **JavaScript 发起请求：**  你的 JavaScript 代码使用 `fetch('https://example.com/data')` 发起一个 GET 请求。
2. **浏览器处理：**  浏览器会将这个请求转换为一个或多个 HTTP/3 帧，例如 `HEADERS` 帧包含请求头信息。
3. **服务器响应：**  服务器返回包含响应头信息的 `HEADERS` 帧和包含响应数据的 `DATA` 帧。
4. **`HttpDecoder` 解析：**  浏览器网络进程中的 `HttpDecoder` 接收到这些字节流，并解析出 `HEADERS` 帧和 `DATA` 帧。
5. **传递给上层：**  `HttpDecoder` 通过其 `Visitor` 接口，将解析出的帧信息（例如，响应头和数据）传递给网络栈的更高层模块。
6. **JavaScript 接收响应：**  最终，这些解析后的信息会被传递回 JavaScript 代码，你可以在 `fetch` API 的 `then` 回调中访问响应头和数据。

**逻辑推理与假设输入/输出：**

假设我们有以下 HTTP/3 字节流数据，表示一个简单的 `SETTINGS` 帧：

**假设输入（十六进制）：** `04 06 01 03 02 05`

* `04`:  帧类型，表示 `SETTINGS` 帧 (VarInt 编码的 4)。
* `06`:  帧长度，表示负载长度为 6 字节 (VarInt 编码的 6)。
* `01`:  第一个设置的 ID (VarInt 编码的 1)。
* `03`:  第一个设置的值 (VarInt 编码的 3)。
* `02`:  第二个设置的 ID (VarInt 编码的 2)。
* `05`:  第二个设置的值 (VarInt 编码的 5)。

**`HttpDecoder` 的处理步骤：**

1. **状态：`STATE_READING_FRAME_TYPE`**
   - 读取第一个字节 `04`，解析出帧类型为 `SETTINGS`。
   - 状态切换到 `STATE_READING_FRAME_LENGTH`。

2. **状态：`STATE_READING_FRAME_LENGTH`**
   - 读取下一个字节 `06`，解析出帧长度为 6 字节。
   - 因为 `SETTINGS` 帧是缓冲的，状态切换到 `STATE_BUFFER_OR_PARSE_PAYLOAD`。

3. **状态：`STATE_BUFFER_OR_PARSE_PAYLOAD`**
   - 读取剩余的 6 个字节 `01 03 02 05` 并缓冲起来。
   - 当所有负载都被缓冲后，`HttpDecoder` 解析 `SETTINGS` 帧的负载。

4. **`ParseEntirePayload` (针对 SETTINGS 帧)：**
   - 读取 `01`，解析出设置 ID 为 1。
   - 读取 `03`，解析出设置值为 3。
   - 读取 `02`，解析出设置 ID 为 2。
   - 读取 `05`，解析出设置值为 5。

**假设输出（通过 `Visitor` 接口）：**

`visitor_->OnSettingsFrameStart(header_length)` 被调用，其中 `header_length` 为帧类型和帧长度的字节数。
`visitor_->OnSettingsFrame(frame)` 被调用，其中 `frame` 对象包含解析出的设置：`{1: 3, 2: 5}`。

**用户或编程常见的使用错误：**

1. **发送无效的帧类型：**  如果客户端或服务器发送了未定义的或错误的帧类型，`HttpDecoder` 会识别出来并触发错误。
   - **例子：**  发送帧类型值为一个未定义的数字。
   - **结果：** `HttpDecoder` 会调用 `RaiseError` 并通知 `Visitor`，可能导致连接关闭。

2. **发送超过最大长度限制的帧：**  对于某些需要缓冲的帧类型，`HttpDecoder` 设置了最大长度限制 (`kPayloadLengthLimit`)。如果接收到的帧长度超过了这个限制，会触发错误。
   - **例子：**  构造一个 `SETTINGS` 帧，其声明的长度远大于实际允许的最大值。
   - **结果：** `HttpDecoder` 会调用 `RaiseError`，错误码可能是 `QUIC_HTTP_FRAME_TOO_LARGE`。

3. **`SETTINGS` 帧中包含重复的设置 ID：** HTTP/3 规范禁止在 `SETTINGS` 帧中包含重复的设置 ID。
   - **例子：**  发送一个 `SETTINGS` 帧，其中包含两个具有相同 ID 的设置。
   - **结果：** `HttpDecoder` 在 `ParseSettingsFrame` 中会检测到重复的 ID，并调用 `RaiseError`，错误码可能是 `QUIC_HTTP_DUPLICATE_SETTING_IDENTIFIER`。

4. **发送 HTTP/2 的帧到 HTTP/3 连接：** HTTP/3 连接中不应发送 HTTP/2 的帧（例如 `PRIORITY`, `PING`, `WINDOW_UPDATE`, `CONTINUATION`）。
   - **例子：**  在 HTTP/3 连接上发送一个类型为 `0x02` (PING 帧) 的帧。
   - **结果：** `HttpDecoder` 在 `ReadFrameType` 中会检测到这些帧类型并调用 `RaiseError`，错误码为 `QUIC_HTTP_RECEIVE_SPDY_FRAME`。

**用户操作如何一步步到达这里（作为调试线索）：**

假设用户在浏览器中访问 `https://example.com`，这是一个支持 HTTP/3 的网站。

1. **用户输入 URL 并按下回车：**  浏览器开始解析 URL 并确定需要建立连接。
2. **DNS 查询：**  浏览器查询 `example.com` 的 IP 地址。
3. **QUIC 连接建立：**  如果浏览器和服务器都支持 HTTP/3，并且协商使用了 QUIC，则会建立 QUIC 连接。这个过程涉及握手，可能包括 TLS 协商。
4. **发送 HTTP/3 请求：**  浏览器构建 HTTP/3 请求，包括 `HEADERS` 帧（包含请求头）和其他可能的帧。这些帧会被编码成字节流。
5. **服务器处理请求：**  服务器接收到这些字节流，其 HTTP/3 解码器（类似于 Chromium 的 `HttpDecoder`) 会解析这些帧。
6. **服务器发送 HTTP/3 响应：**  服务器构建 HTTP/3 响应，包括 `HEADERS` 帧（包含响应头）和 `DATA` 帧（包含响应内容）等，并编码成字节流。
7. **浏览器接收响应数据：**  浏览器接收到来自服务器的 HTTP/3 响应字节流。
8. **`HttpDecoder` 处理接收到的数据：**
   - 当 QUIC 层将接收到的数据传递给 HTTP/3 层时，`HttpDecoder::ProcessInput` 方法会被调用，传入接收到的字节流。
   - `HttpDecoder` 根据状态机的状态，逐步解析帧类型、帧长度和帧负载。
   - 例如，如果服务器发送了一个 `SETTINGS` 帧，`HttpDecoder` 会解析出服务器的 HTTP/3 设置。
   - 如果服务器发送了一个 `DATA` 帧，`HttpDecoder` 会将负载数据传递给 `Visitor`，最终这些数据会被传递到渲染进程，用于显示网页内容。
9. **渲染进程处理：**  渲染进程接收到解析后的响应数据，并渲染网页。

**调试线索：**

如果在调试过程中需要查看 `HttpDecoder` 的行为，可以采取以下步骤：

* **网络抓包：** 使用 Wireshark 或 Chrome 的内置网络面板抓取网络包，查看浏览器和服务器之间交换的原始 QUIC 数据包，以及其中的 HTTP/3 帧。
* **QUIC 内部日志：**  Chromium 的 QUIC 实现通常有详细的内部日志。可以配置 Chromium 启用 QUIC 的 debug 日志，查看 `HttpDecoder` 的状态变化、解析出的帧信息、以及发生的错误。
* **断点调试：**  在 Chromium 的源代码中，可以在 `HttpDecoder.cc` 的关键方法（例如 `ProcessInput`, `ReadFrameType`, `ReadFrameLength`, `BufferOrParsePayload` 等）设置断点，逐步跟踪代码执行流程，查看变量的值，了解帧是如何被解析的。
* **查看 `Visitor` 的实现：**  `HttpDecoder` 的行为最终会通过 `Visitor` 接口体现出来。查看 `Visitor` 的实现，可以了解解析出的帧信息是如何被上层模块使用的。

总而言之，`net/third_party/quiche/src/quiche/quic/core/http/http_decoder.cc` 是 Chromium 网络栈中负责解析 HTTP/3 帧的关键组件，它确保了浏览器能够正确理解来自 HTTP/3 服务器的响应，是实现 HTTP/3 协议的重要组成部分。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/http_decoder.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/http/http_decoder.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/strings/string_view.h"
#include "quiche/http2/http2_constants.h"
#include "quiche/quic/core/http/http_frames.h"
#include "quiche/quic/core/quic_data_reader.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"

namespace quic {

namespace {

// Limit on the payload length for frames that are buffered by HttpDecoder.
// If a frame header indicating a payload length exceeding this limit is
// received, HttpDecoder closes the connection.  Does not apply to frames that
// are not buffered here but each payload fragment is immediately passed to
// Visitor, like HEADERS, DATA, and unknown frames.
constexpr QuicByteCount kPayloadLengthLimit = 1024 * 1024;

}  // anonymous namespace

HttpDecoder::HttpDecoder(Visitor* visitor)
    : visitor_(visitor),
      allow_web_transport_stream_(false),
      state_(STATE_READING_FRAME_TYPE),
      current_frame_type_(0),
      current_length_field_length_(0),
      remaining_length_field_length_(0),
      current_frame_length_(0),
      remaining_frame_length_(0),
      current_type_field_length_(0),
      remaining_type_field_length_(0),
      error_(QUIC_NO_ERROR),
      error_detail_(""),
      enable_origin_frame_(GetQuicReloadableFlag(enable_h3_origin_frame)) {
  QUICHE_DCHECK(visitor_);
}

HttpDecoder::~HttpDecoder() {}

// static
bool HttpDecoder::DecodeSettings(const char* data, QuicByteCount len,
                                 SettingsFrame* frame) {
  QuicDataReader reader(data, len);
  uint64_t frame_type;
  if (!reader.ReadVarInt62(&frame_type)) {
    QUIC_DLOG(ERROR) << "Unable to read frame type.";
    return false;
  }

  if (frame_type != static_cast<uint64_t>(HttpFrameType::SETTINGS)) {
    QUIC_DLOG(ERROR) << "Invalid frame type " << frame_type;
    return false;
  }

  absl::string_view frame_contents;
  if (!reader.ReadStringPieceVarInt62(&frame_contents)) {
    QUIC_DLOG(ERROR) << "Failed to read SETTINGS frame contents";
    return false;
  }

  QuicDataReader frame_reader(frame_contents);

  while (!frame_reader.IsDoneReading()) {
    uint64_t id;
    if (!frame_reader.ReadVarInt62(&id)) {
      QUIC_DLOG(ERROR) << "Unable to read setting identifier.";
      return false;
    }
    uint64_t content;
    if (!frame_reader.ReadVarInt62(&content)) {
      QUIC_DLOG(ERROR) << "Unable to read setting value.";
      return false;
    }
    auto result = frame->values.insert({id, content});
    if (!result.second) {
      QUIC_DLOG(ERROR) << "Duplicate setting identifier.";
      return false;
    }
  }
  return true;
}

QuicByteCount HttpDecoder::ProcessInput(const char* data, QuicByteCount len) {
  QUICHE_DCHECK_EQ(QUIC_NO_ERROR, error_);
  QUICHE_DCHECK_NE(STATE_ERROR, state_);

  QuicDataReader reader(data, len);
  bool continue_processing = true;
  // BufferOrParsePayload() and FinishParsing() may need to be called even if
  // there is no more data so that they can finish processing the current frame.
  while (continue_processing && (reader.BytesRemaining() != 0 ||
                                 state_ == STATE_BUFFER_OR_PARSE_PAYLOAD ||
                                 state_ == STATE_FINISH_PARSING)) {
    // |continue_processing| must have been set to false upon error.
    QUICHE_DCHECK_EQ(QUIC_NO_ERROR, error_);
    QUICHE_DCHECK_NE(STATE_ERROR, state_);

    switch (state_) {
      case STATE_READING_FRAME_TYPE:
        continue_processing = ReadFrameType(reader);
        break;
      case STATE_READING_FRAME_LENGTH:
        continue_processing = ReadFrameLength(reader);
        break;
      case STATE_BUFFER_OR_PARSE_PAYLOAD:
        continue_processing = BufferOrParsePayload(reader);
        break;
      case STATE_READING_FRAME_PAYLOAD:
        continue_processing = ReadFramePayload(reader);
        break;
      case STATE_FINISH_PARSING:
        continue_processing = FinishParsing();
        break;
      case STATE_PARSING_NO_LONGER_POSSIBLE:
        continue_processing = false;
        QUIC_BUG(HttpDecoder PARSING_NO_LONGER_POSSIBLE)
            << "HttpDecoder called after an indefinite-length frame has been "
               "received";
        RaiseError(QUIC_INTERNAL_ERROR,
                   "HttpDecoder called after an indefinite-length frame has "
                   "been received");
        break;
      case STATE_ERROR:
        break;
      default:
        QUIC_BUG(quic_bug_10411_1) << "Invalid state: " << state_;
    }
  }

  return len - reader.BytesRemaining();
}

bool HttpDecoder::ReadFrameType(QuicDataReader& reader) {
  QUICHE_DCHECK_NE(0u, reader.BytesRemaining());
  if (current_type_field_length_ == 0) {
    // A new frame is coming.
    current_type_field_length_ = reader.PeekVarInt62Length();
    QUICHE_DCHECK_NE(0u, current_type_field_length_);
    if (current_type_field_length_ > reader.BytesRemaining()) {
      // Buffer a new type field.
      remaining_type_field_length_ = current_type_field_length_;
      BufferFrameType(reader);
      return true;
    }
    // The reader has all type data needed, so no need to buffer.
    bool success = reader.ReadVarInt62(&current_frame_type_);
    QUICHE_DCHECK(success);
  } else {
    // Buffer the existing type field.
    BufferFrameType(reader);
    // The frame is still not buffered completely.
    if (remaining_type_field_length_ != 0) {
      return true;
    }
    QuicDataReader type_reader(type_buffer_.data(), current_type_field_length_);
    bool success = type_reader.ReadVarInt62(&current_frame_type_);
    QUICHE_DCHECK(success);
  }
  if (decoded_frame_types_.size() < 10) {
    decoded_frame_types_.push_back(current_frame_type_);
  }

  // https://tools.ietf.org/html/draft-ietf-quic-http-31#section-7.2.8
  // specifies that the following frames are treated as errors.
  if (current_frame_type_ ==
          static_cast<uint64_t>(http2::Http2FrameType::PRIORITY) ||
      current_frame_type_ ==
          static_cast<uint64_t>(http2::Http2FrameType::PING) ||
      current_frame_type_ ==
          static_cast<uint64_t>(http2::Http2FrameType::WINDOW_UPDATE) ||
      current_frame_type_ ==
          static_cast<uint64_t>(http2::Http2FrameType::CONTINUATION)) {
    RaiseError(QUIC_HTTP_RECEIVE_SPDY_FRAME,
               absl::StrCat("HTTP/2 frame received in a HTTP/3 connection: ",
                            current_frame_type_));
    return false;
  }

  if (current_frame_type_ ==
      static_cast<uint64_t>(HttpFrameType::CANCEL_PUSH)) {
    RaiseError(QUIC_HTTP_FRAME_ERROR, "CANCEL_PUSH frame received.");
    return false;
  }
  if (current_frame_type_ ==
      static_cast<uint64_t>(HttpFrameType::PUSH_PROMISE)) {
    RaiseError(QUIC_HTTP_FRAME_ERROR, "PUSH_PROMISE frame received.");
    return false;
  }

  state_ = STATE_READING_FRAME_LENGTH;
  return true;
}

bool HttpDecoder::ReadFrameLength(QuicDataReader& reader) {
  QUICHE_DCHECK_NE(0u, reader.BytesRemaining());
  if (current_length_field_length_ == 0) {
    // A new frame is coming.
    current_length_field_length_ = reader.PeekVarInt62Length();
    QUICHE_DCHECK_NE(0u, current_length_field_length_);
    if (current_length_field_length_ > reader.BytesRemaining()) {
      // Buffer a new length field.
      remaining_length_field_length_ = current_length_field_length_;
      BufferFrameLength(reader);
      return true;
    }
    // The reader has all length data needed, so no need to buffer.
    bool success = reader.ReadVarInt62(&current_frame_length_);
    QUICHE_DCHECK(success);
  } else {
    // Buffer the existing length field.
    BufferFrameLength(reader);
    // The frame is still not buffered completely.
    if (remaining_length_field_length_ != 0) {
      return true;
    }
    QuicDataReader length_reader(length_buffer_.data(),
                                 current_length_field_length_);
    bool success = length_reader.ReadVarInt62(&current_frame_length_);
    QUICHE_DCHECK(success);
  }

  // WEBTRANSPORT_STREAM frames are indefinitely long, and thus require
  // special handling; the number after the frame type is actually the
  // WebTransport session ID, and not the length.
  if (allow_web_transport_stream_ &&
      current_frame_type_ ==
          static_cast<uint64_t>(HttpFrameType::WEBTRANSPORT_STREAM)) {
    visitor_->OnWebTransportStreamFrameType(
        current_length_field_length_ + current_type_field_length_,
        current_frame_length_);
    state_ = STATE_PARSING_NO_LONGER_POSSIBLE;
    return false;
  }

  if (IsFrameBuffered() &&
      current_frame_length_ > MaxFrameLength(current_frame_type_)) {
    RaiseError(QUIC_HTTP_FRAME_TOO_LARGE, "Frame is too large.");
    return false;
  }

  // Calling the following visitor methods does not require parsing of any
  // frame payload.
  bool continue_processing = true;
  const QuicByteCount header_length =
      current_length_field_length_ + current_type_field_length_;

  switch (current_frame_type_) {
    case static_cast<uint64_t>(HttpFrameType::DATA):
      continue_processing =
          visitor_->OnDataFrameStart(header_length, current_frame_length_);
      break;
    case static_cast<uint64_t>(HttpFrameType::HEADERS):
      continue_processing =
          visitor_->OnHeadersFrameStart(header_length, current_frame_length_);
      break;
    case static_cast<uint64_t>(HttpFrameType::CANCEL_PUSH):
      QUICHE_NOTREACHED();
      break;
    case static_cast<uint64_t>(HttpFrameType::SETTINGS):
      continue_processing = visitor_->OnSettingsFrameStart(header_length);
      break;
    case static_cast<uint64_t>(HttpFrameType::PUSH_PROMISE):
      QUICHE_NOTREACHED();
      break;
    case static_cast<uint64_t>(HttpFrameType::GOAWAY):
      break;
    case static_cast<uint64_t>(HttpFrameType::MAX_PUSH_ID):
      break;
    case static_cast<uint64_t>(HttpFrameType::PRIORITY_UPDATE_REQUEST_STREAM):
      continue_processing = visitor_->OnPriorityUpdateFrameStart(header_length);
      break;
    case static_cast<uint64_t>(HttpFrameType::ACCEPT_CH):
      continue_processing = visitor_->OnAcceptChFrameStart(header_length);
      break;
    case static_cast<uint64_t>(HttpFrameType::METADATA):
      continue_processing =
          visitor_->OnMetadataFrameStart(header_length, current_frame_length_);
      break;
    default:
      if (enable_origin_frame_ &&
          current_frame_type_ == static_cast<uint64_t>(HttpFrameType::ORIGIN)) {
        QUIC_CODE_COUNT_N(enable_h3_origin_frame, 1, 2);
        continue_processing = visitor_->OnOriginFrameStart(header_length);
        break;
      }
      continue_processing = visitor_->OnUnknownFrameStart(
          current_frame_type_, header_length, current_frame_length_);
      break;
  }

  remaining_frame_length_ = current_frame_length_;

  if (IsFrameBuffered()) {
    state_ = STATE_BUFFER_OR_PARSE_PAYLOAD;
    return continue_processing;
  }

  state_ = (remaining_frame_length_ == 0) ? STATE_FINISH_PARSING
                                          : STATE_READING_FRAME_PAYLOAD;
  return continue_processing;
}

bool HttpDecoder::IsFrameBuffered() {
  switch (current_frame_type_) {
    case static_cast<uint64_t>(HttpFrameType::SETTINGS):
      return true;
    case static_cast<uint64_t>(HttpFrameType::GOAWAY):
      return true;
    case static_cast<uint64_t>(HttpFrameType::MAX_PUSH_ID):
      return true;
    case static_cast<uint64_t>(HttpFrameType::PRIORITY_UPDATE_REQUEST_STREAM):
      return true;
    case static_cast<uint64_t>(HttpFrameType::ORIGIN):
      if (enable_origin_frame_) {
        QUIC_CODE_COUNT_N(enable_h3_origin_frame, 2, 2);
        return true;
      }
      return false;
    case static_cast<uint64_t>(HttpFrameType::ACCEPT_CH):
      return true;
  }

  // Other defined frame types as well as unknown frames are not buffered.
  return false;
}

bool HttpDecoder::ReadFramePayload(QuicDataReader& reader) {
  QUICHE_DCHECK(!IsFrameBuffered());
  QUICHE_DCHECK_NE(0u, reader.BytesRemaining());
  QUICHE_DCHECK_NE(0u, remaining_frame_length_);

  bool continue_processing = true;

  switch (current_frame_type_) {
    case static_cast<uint64_t>(HttpFrameType::DATA): {
      QuicByteCount bytes_to_read = std::min<QuicByteCount>(
          remaining_frame_length_, reader.BytesRemaining());
      absl::string_view payload;
      bool success = reader.ReadStringPiece(&payload, bytes_to_read);
      QUICHE_DCHECK(success);
      QUICHE_DCHECK(!payload.empty());
      continue_processing = visitor_->OnDataFramePayload(payload);
      remaining_frame_length_ -= payload.length();
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::HEADERS): {
      QuicByteCount bytes_to_read = std::min<QuicByteCount>(
          remaining_frame_length_, reader.BytesRemaining());
      absl::string_view payload;
      bool success = reader.ReadStringPiece(&payload, bytes_to_read);
      QUICHE_DCHECK(success);
      QUICHE_DCHECK(!payload.empty());
      continue_processing = visitor_->OnHeadersFramePayload(payload);
      remaining_frame_length_ -= payload.length();
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::CANCEL_PUSH): {
      QUICHE_NOTREACHED();
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::SETTINGS): {
      QUICHE_NOTREACHED();
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::PUSH_PROMISE): {
      QUICHE_NOTREACHED();
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::GOAWAY): {
      QUICHE_NOTREACHED();
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::MAX_PUSH_ID): {
      QUICHE_NOTREACHED();
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::PRIORITY_UPDATE_REQUEST_STREAM): {
      QUICHE_NOTREACHED();
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::ACCEPT_CH): {
      QUICHE_NOTREACHED();
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::METADATA): {
      QuicByteCount bytes_to_read = std::min<QuicByteCount>(
          remaining_frame_length_, reader.BytesRemaining());
      absl::string_view payload;
      bool success = reader.ReadStringPiece(&payload, bytes_to_read);
      QUICHE_DCHECK(success);
      QUICHE_DCHECK(!payload.empty());
      continue_processing = visitor_->OnMetadataFramePayload(payload);
      remaining_frame_length_ -= payload.length();
      break;
    }
    default: {
      if (enable_origin_frame_ &&
          current_frame_type_ == static_cast<uint64_t>(HttpFrameType::ORIGIN)) {
        QUICHE_NOTREACHED();
        break;
      }
      continue_processing = HandleUnknownFramePayload(reader);
      break;
    }
  }

  if (remaining_frame_length_ == 0) {
    state_ = STATE_FINISH_PARSING;
  }

  return continue_processing;
}

bool HttpDecoder::FinishParsing() {
  QUICHE_DCHECK(!IsFrameBuffered());
  QUICHE_DCHECK_EQ(0u, remaining_frame_length_);

  bool continue_processing = true;

  switch (current_frame_type_) {
    case static_cast<uint64_t>(HttpFrameType::DATA): {
      continue_processing = visitor_->OnDataFrameEnd();
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::HEADERS): {
      continue_processing = visitor_->OnHeadersFrameEnd();
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::CANCEL_PUSH): {
      QUICHE_NOTREACHED();
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::SETTINGS): {
      QUICHE_NOTREACHED();
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::PUSH_PROMISE): {
      QUICHE_NOTREACHED();
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::GOAWAY): {
      QUICHE_NOTREACHED();
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::MAX_PUSH_ID): {
      QUICHE_NOTREACHED();
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::PRIORITY_UPDATE_REQUEST_STREAM): {
      QUICHE_NOTREACHED();
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::ACCEPT_CH): {
      QUICHE_NOTREACHED();
      break;
    }
    case static_cast<uint64_t>(HttpFrameType::METADATA): {
      continue_processing = visitor_->OnMetadataFrameEnd();
      break;
    }
    default:
      if (enable_origin_frame_ &&
          current_frame_type_ == static_cast<uint64_t>(HttpFrameType::ORIGIN)) {
        QUICHE_NOTREACHED();
        break;
      }
      continue_processing = visitor_->OnUnknownFrameEnd();
  }

  ResetForNextFrame();
  return continue_processing;
}

void HttpDecoder::ResetForNextFrame() {
  current_length_field_length_ = 0;
  current_type_field_length_ = 0;
  state_ = STATE_READING_FRAME_TYPE;
}

bool HttpDecoder::HandleUnknownFramePayload(QuicDataReader& reader) {
  QuicByteCount bytes_to_read =
      std::min<QuicByteCount>(remaining_frame_length_, reader.BytesRemaining());
  absl::string_view payload;
  bool success = reader.ReadStringPiece(&payload, bytes_to_read);
  QUICHE_DCHECK(success);
  QUICHE_DCHECK(!payload.empty());
  remaining_frame_length_ -= payload.length();
  return visitor_->OnUnknownFramePayload(payload);
}

bool HttpDecoder::BufferOrParsePayload(QuicDataReader& reader) {
  QUICHE_DCHECK(IsFrameBuffered());
  QUICHE_DCHECK_EQ(current_frame_length_,
                   buffer_.size() + remaining_frame_length_);

  if (buffer_.empty() && reader.BytesRemaining() >= current_frame_length_) {
    // |*reader| contains entire payload, which might be empty.
    remaining_frame_length_ = 0;
    QuicDataReader current_payload_reader(reader.PeekRemainingPayload().data(),
                                          current_frame_length_);
    bool continue_processing = ParseEntirePayload(current_payload_reader);

    reader.Seek(current_frame_length_);
    ResetForNextFrame();
    return continue_processing;
  }

  // Buffer as much of the payload as |*reader| contains.
  QuicByteCount bytes_to_read =
      std::min<QuicByteCount>(remaining_frame_length_, reader.BytesRemaining());
  absl::StrAppend(&buffer_, reader.PeekRemainingPayload().substr(
                                /* pos = */ 0, bytes_to_read));
  reader.Seek(bytes_to_read);
  remaining_frame_length_ -= bytes_to_read;

  QUICHE_DCHECK_EQ(current_frame_length_,
                   buffer_.size() + remaining_frame_length_);

  if (remaining_frame_length_ > 0) {
    QUICHE_DCHECK(reader.IsDoneReading());
    return false;
  }

  QuicDataReader buffer_reader(buffer_);
  bool continue_processing = ParseEntirePayload(buffer_reader);
  buffer_.clear();

  ResetForNextFrame();
  return continue_processing;
}

bool HttpDecoder::ParseEntirePayload(QuicDataReader& reader) {
  QUICHE_DCHECK(IsFrameBuffered());
  QUICHE_DCHECK_EQ(current_frame_length_, reader.BytesRemaining());
  QUICHE_DCHECK_EQ(0u, remaining_frame_length_);

  switch (current_frame_type_) {
    case static_cast<uint64_t>(HttpFrameType::CANCEL_PUSH): {
      QUICHE_NOTREACHED();
      return false;
    }
    case static_cast<uint64_t>(HttpFrameType::SETTINGS): {
      SettingsFrame frame;
      if (!ParseSettingsFrame(reader, frame)) {
        return false;
      }
      return visitor_->OnSettingsFrame(frame);
    }
    case static_cast<uint64_t>(HttpFrameType::GOAWAY): {
      GoAwayFrame frame;
      if (!reader.ReadVarInt62(&frame.id)) {
        RaiseError(QUIC_HTTP_FRAME_ERROR, "Unable to read GOAWAY ID.");
        return false;
      }
      if (!reader.IsDoneReading()) {
        RaiseError(QUIC_HTTP_FRAME_ERROR, "Superfluous data in GOAWAY frame.");
        return false;
      }
      return visitor_->OnGoAwayFrame(frame);
    }
    case static_cast<uint64_t>(HttpFrameType::MAX_PUSH_ID): {
      uint64_t unused;
      if (!reader.ReadVarInt62(&unused)) {
        RaiseError(QUIC_HTTP_FRAME_ERROR,
                   "Unable to read MAX_PUSH_ID push_id.");
        return false;
      }
      if (!reader.IsDoneReading()) {
        RaiseError(QUIC_HTTP_FRAME_ERROR,
                   "Superfluous data in MAX_PUSH_ID frame.");
        return false;
      }
      return visitor_->OnMaxPushIdFrame();
    }
    case static_cast<uint64_t>(HttpFrameType::PRIORITY_UPDATE_REQUEST_STREAM): {
      PriorityUpdateFrame frame;
      if (!ParsePriorityUpdateFrame(reader, frame)) {
        return false;
      }
      return visitor_->OnPriorityUpdateFrame(frame);
    }
    case static_cast<uint64_t>(HttpFrameType::ORIGIN): {
      OriginFrame frame;
      if (!ParseOriginFrame(reader, frame)) {
        return false;
      }
      return visitor_->OnOriginFrame(frame);
    }
    case static_cast<uint64_t>(HttpFrameType::ACCEPT_CH): {
      AcceptChFrame frame;
      if (!ParseAcceptChFrame(reader, frame)) {
        return false;
      }
      return visitor_->OnAcceptChFrame(frame);
    }
    default:
      // Only above frame types are parsed by ParseEntirePayload().
      QUICHE_NOTREACHED();
      return false;
  }
}

void HttpDecoder::BufferFrameLength(QuicDataReader& reader) {
  QuicByteCount bytes_to_read = std::min<QuicByteCount>(
      remaining_length_field_length_, reader.BytesRemaining());
  bool success =
      reader.ReadBytes(length_buffer_.data() + current_length_field_length_ -
                           remaining_length_field_length_,
                       bytes_to_read);
  QUICHE_DCHECK(success);
  remaining_length_field_length_ -= bytes_to_read;
}

void HttpDecoder::BufferFrameType(QuicDataReader& reader) {
  QuicByteCount bytes_to_read = std::min<QuicByteCount>(
      remaining_type_field_length_, reader.BytesRemaining());
  bool success =
      reader.ReadBytes(type_buffer_.data() + current_type_field_length_ -
                           remaining_type_field_length_,
                       bytes_to_read);
  QUICHE_DCHECK(success);
  remaining_type_field_length_ -= bytes_to_read;
}

void HttpDecoder::RaiseError(QuicErrorCode error, std::string error_detail) {
  state_ = STATE_ERROR;
  error_ = error;
  error_detail_ = std::move(error_detail);
  visitor_->OnError(this);
}

bool HttpDecoder::ParseSettingsFrame(QuicDataReader& reader,
                                     SettingsFrame& frame) {
  while (!reader.IsDoneReading()) {
    uint64_t id;
    if (!reader.ReadVarInt62(&id)) {
      RaiseError(QUIC_HTTP_FRAME_ERROR, "Unable to read setting identifier.");
      return false;
    }
    uint64_t content;
    if (!reader.ReadVarInt62(&content)) {
      RaiseError(QUIC_HTTP_FRAME_ERROR, "Unable to read setting value.");
      return false;
    }
    auto result = frame.values.insert({id, content});
    if (!result.second) {
      RaiseError(QUIC_HTTP_DUPLICATE_SETTING_IDENTIFIER,
                 "Duplicate setting identifier.");
      return false;
    }
  }
  return true;
}

bool HttpDecoder::ParsePriorityUpdateFrame(QuicDataReader& reader,
                                           PriorityUpdateFrame& frame) {
  if (!reader.ReadVarInt62(&frame.prioritized_element_id)) {
    RaiseError(QUIC_HTTP_FRAME_ERROR, "Unable to read prioritized element id.");
    return false;
  }

  absl::string_view priority_field_value = reader.ReadRemainingPayload();
  frame.priority_field_value =
      std::string(priority_field_value.data(), priority_field_value.size());

  return true;
}

bool HttpDecoder::ParseOriginFrame(QuicDataReader& reader, OriginFrame& frame) {
  QUICHE_DCHECK(enable_origin_frame_);
  while (!reader.IsDoneReading()) {
    absl::string_view origin;
    if (!reader.ReadStringPiece16(&origin)) {
      RaiseError(QUIC_HTTP_FRAME_ERROR, "Unable to read ORIGIN origin.");
      return false;
    }
    frame.origins.push_back(std::string(origin));
  }
  return true;
}

bool HttpDecoder::ParseAcceptChFrame(QuicDataReader& reader,
                                     AcceptChFrame& frame) {
  absl::string_view origin;
  absl::string_view value;
  while (!reader.IsDoneReading()) {
    if (!reader.ReadStringPieceVarInt62(&origin)) {
      RaiseError(QUIC_HTTP_FRAME_ERROR, "Unable to read ACCEPT_CH origin.");
      return false;
    }
    if (!reader.ReadStringPieceVarInt62(&value)) {
      RaiseError(QUIC_HTTP_FRAME_ERROR, "Unable to read ACCEPT_CH value.");
      return false;
    }
    // Copy data.
    frame.entries.push_back({std::string(origin.data(), origin.size()),
                             std::string(value.data(), value.size())});
  }
  return true;
}

QuicByteCount HttpDecoder::MaxFrameLength(uint64_t frame_type) {
  QUICHE_DCHECK(IsFrameBuffered());

  switch (frame_type) {
    case static_cast<uint64_t>(HttpFrameType::SETTINGS):
      return kPayloadLengthLimit;
    case static_cast<uint64_t>(HttpFrameType::GOAWAY):
      return quiche::VARIABLE_LENGTH_INTEGER_LENGTH_8;
    case static_cast<uint64_t>(HttpFrameType::MAX_PUSH_ID):
      return quiche::VARIABLE_LENGTH_INTEGER_LENGTH_8;
    case static_cast<uint64_t>(HttpFrameType::PRIORITY_UPDATE_REQUEST_STREAM):
      return kPayloadLengthLimit;
    case static_cast<uint64_t>(HttpFrameType::ACCEPT_CH):
      return kPayloadLengthLimit;
    case static_cast<uint64_t>(HttpFrameType::ORIGIN):
      return kPayloadLengthLimit;
    default:
      QUICHE_NOTREACHED();
      return 0;
  }
}

std::string HttpDecoder::DebugString() const {
  return absl::StrCat(
      "HttpDecoder:", "\n  state: ", state_, "\n  error: ", error_,
      "\n  current_frame_type: ", current_frame_type_,
      "\n  current_length_field_length: ", current_length_field_length_,
      "\n  remaining_length_field_length: ", remaining_length_field_length_,
      "\n  current_frame_length: ", current_frame_length_,
      "\n  remaining_frame_length: ", remaining_frame_length_,
      "\n  current_type_field_length: ", current_type_field_length_,
      "\n  remaining_type_field_length: ", remaining_type_field_length_);
}

}  // namespace quic
```