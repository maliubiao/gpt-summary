Response:
Let's break down the thought process for analyzing this C++ code and answering the user's request.

**1. Understanding the Core Request:**

The user wants to understand the functionality of `websocket_basic_stream.cc`, its relationship to JavaScript, how to debug it, and potential errors. This means I need to extract the key responsibilities of this class, identify its interactions with other components (both C++ and potentially JavaScript indirectly), explain how data flows through it, and highlight common pitfalls.

**2. Initial Code Scan and Keyword Recognition:**

My first step is a quick scan of the code, looking for prominent keywords and structures. I'd notice:

* **`WebSocketBasicStream` class:** This is the central element. I'd look at its methods (public and private).
* **`ReadFrames`, `WriteFrames`:** These strongly suggest the core function of sending and receiving WebSocket data.
* **`CompletionOnceCallback`:**  Indicates asynchronous operations and callbacks.
* **`IOBuffer`, `DrainableIOBuffer`, `GrowableIOBuffer`:** These are Chromium's buffer types, crucial for handling data.
* **`WebSocketFrame`, `WebSocketFrameHeader`, `WebSocketFrameChunk`:**  These are the data structures representing WebSocket messages at different stages of processing.
* **`WebSocketParser`, `ChunkAssembler`:**  These point to the processes of parsing incoming data and assembling fragmented messages.
* **`ClientSocketHandle`:**  This indicates interaction with the underlying network socket.
* **`NetLog`:**  Signifies logging and debugging capabilities.
* **`kLargeReadBufferSize`, `kSmallReadBufferSize`:**  These suggest optimization for different network conditions.
* **`GenerateWebSocketMaskingKey`, `MaskWebSocketFramePayload`:**  Keywords related to WebSocket security.

**3. Deconstructing the Functionality:**

Based on the keywords and methods, I start piecing together the core responsibilities:

* **Receiving Data (`ReadFrames`):**  The process involves reading data from the underlying socket (`connection_->Read`), parsing it into `WebSocketFrameChunk`s, assembling those chunks into complete `WebSocketFrame`s, and then providing these frames to the caller via a callback. The code also handles leftover data from the HTTP handshake.
* **Sending Data (`WriteFrames`):**  This involves taking a vector of `WebSocketFrame`s, serializing them into a contiguous buffer (including applying masking), and then writing that buffer to the socket (`connection_->Write`).
* **Connection Management:** The `Close()` method indicates control over the underlying socket connection.
* **Optimization:** The `BufferSizeManager` and the different read buffer sizes hint at performance considerations.
* **Error Handling:** The code uses `net::Error` and converts WebSocket-specific errors.

**4. Identifying the JavaScript Connection:**

The comment within the `kTrafficAnnotation` is a key indicator: "Implementation of WebSocket API from web content (a page the user visits)." This directly links the C++ code to the JavaScript WebSocket API. I would then formulate examples of JavaScript code that would trigger the use of this C++ component.

**5. Logic and Data Flow (Hypothetical Inputs and Outputs):**

To illustrate the logic, I'd think about simple scenarios:

* **Reading:** What happens when the server sends a text message?  The input would be raw bytes on the socket. The output would be a `WebSocketFrame` with a text payload. What if the message is fragmented? The `ChunkAssembler` would play a role.
* **Writing:** What happens when JavaScript sends a binary message? The input would be a JavaScript `ArrayBuffer`. The output would be the serialized WebSocket frame sent over the socket.

**6. Common User Errors and Debugging:**

I consider typical mistakes developers make when using WebSockets:

* **Incorrect Server Implementation:**  A mismatch in the WebSocket protocol implementation on the server side is a common issue.
* **Network Problems:** Basic connectivity issues are always a possibility.
* **Incorrect JavaScript Usage:**  Using the WebSocket API incorrectly in the browser.

For debugging, I'd focus on the steps leading to this code: the initial WebSocket handshake, the subsequent data transfer, and how the browser's network stack routes the data. The `NetLog` becomes a crucial debugging tool.

**7. Structuring the Answer:**

Finally, I organize the information into clear sections, addressing each point of the user's request:

* **Functionality:** A concise summary of the class's role.
* **Relationship to JavaScript:**  Explicitly link the C++ code to the browser's WebSocket API with concrete JavaScript examples.
* **Logic and Data Flow:**  Provide hypothetical input/output scenarios for both reading and writing.
* **Common Errors:** List typical user and programming errors.
* **User Operations and Debugging:** Explain the sequence of events that leads to this code and offer debugging strategies.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe focus heavily on the buffer management.
* **Correction:** Realize that while important, the core functionality is about framing and handling WebSocket messages. Buffer management is an optimization.
* **Initial thought:** Briefly mention the JavaScript connection.
* **Correction:** Emphasize the direct link and provide clear JavaScript examples to solidify the connection.
* **Initial thought:**  List generic network errors.
* **Correction:**  Focus on errors specific to WebSocket usage and implementation.

By following these steps, combining code analysis with an understanding of the overall WebSocket architecture and common usage patterns, I can construct a comprehensive and helpful answer to the user's request.
好的，让我们来详细分析一下 `net/websockets/websocket_basic_stream.cc` 这个文件。

**功能概述:**

`WebSocketBasicStream` 类是 Chromium 网络栈中实现 WebSocket 通信的核心组件之一。它的主要功能是提供一个基本的、面向流的接口来发送和接收 WebSocket 消息帧。可以将其视为 WebSocket 连接的数据收发器。

更具体地说，`WebSocketBasicStream` 负责：

1. **读取 WebSocket 帧:** 从底层的网络连接（通常是一个 TCP socket）读取数据，并将这些原始字节解析成结构化的 `WebSocketFrame` 对象。这包括处理帧头、有效载荷以及分片等。
2. **写入 WebSocket 帧:** 将 `WebSocketFrame` 对象序列化成二进制数据，并将其发送到底层的网络连接。这包括添加帧头、应用掩码（客户端到服务端的数据需要掩码）等。
3. **管理读写缓冲区:**  它使用 `IOBuffer` 来暂存读取到的数据和待发送的数据。为了优化性能，它还会动态调整读取缓冲区的大小，根据网络吞吐量在高带宽和低带宽连接之间切换不同的缓冲区大小。
4. **处理控制帧:**  可以处理 WebSocket 的控制帧，例如 Ping、Pong 和 Close 帧。
5. **集成 NetLog:**  使用 Chromium 的 NetLog 系统来记录 WebSocket 事件，方便调试和分析网络行为。
6. **处理 HTTP 遗留数据:** 在 WebSocket 握手之后，HTTP 响应的剩余部分可能包含 WebSocket 帧数据，`WebSocketBasicStream` 可以处理这种情况。

**与 JavaScript 功能的关系及举例说明:**

`WebSocketBasicStream` 是浏览器实现 JavaScript `WebSocket` API 的基础。当 JavaScript 代码创建一个 `WebSocket` 对象并尝试连接到 WebSocket 服务器时，底层的网络通信最终会由 `WebSocketBasicStream` 来处理。

**举例说明:**

假设以下 JavaScript 代码：

```javascript
const ws = new WebSocket('ws://example.com/socket');

ws.onopen = () => {
  console.log('WebSocket connection opened');
  ws.send('Hello from JavaScript!');
};

ws.onmessage = (event) => {
  console.log('Received message:', event.data);
};

ws.onclose = () => {
  console.log('WebSocket connection closed');
};
```

当执行 `ws.send('Hello from JavaScript!')` 时，浏览器会将这个字符串数据传递给网络栈。网络栈会执行以下步骤，其中就涉及到了 `WebSocketBasicStream`：

1. **JavaScript 层:**  JavaScript 的 `WebSocket` API 将字符串 "Hello from JavaScript!" 封装成一个要发送的消息。
2. **Renderer 进程:**  这个消息会被传递到渲染器进程的网络代码。
3. **网络进程:**  网络进程会创建一个或找到现有的 `WebSocketBasicStream` 实例来处理这个连接。
4. **`WebSocketBasicStream::WriteFrames`:**  `WebSocketBasicStream` 的 `WriteFrames` 方法会被调用，将 JavaScript 传递的数据封装成一个或多个 `WebSocketFrame` 对象（例如，一个文本帧）。
5. **序列化和发送:**  `WriteFrames` 会将 `WebSocketFrame` 序列化成二进制数据，包括添加帧头、设置操作码（文本帧）、应用掩码等。
6. **Socket 写入:**  最终，序列化后的数据会通过底层的 socket 连接发送到 WebSocket 服务器。

同样，当服务器向客户端发送数据时：

1. **Socket 读取:** 底层的 socket 连接接收到来自服务器的二进制数据。
2. **`WebSocketBasicStream::ReadFrames`:** `WebSocketBasicStream` 的 `ReadFrames` 方法会被调用来读取这些数据。
3. **解析 WebSocket 帧:**  `ReadFrames` 会解析接收到的数据，将其转换成 `WebSocketFrame` 对象。
4. **传递给 JavaScript:**  解析后的数据（`event.data`）会被传递回渲染器进程，最终触发 JavaScript 的 `onmessage` 事件。

**逻辑推理、假设输入与输出:**

**假设输入 (写入):**

* JavaScript 调用 `ws.send('TestData')`。

**`WebSocketBasicStream::WriteFrames` 的行为:**

1. **计算大小:** 计算需要分配的缓冲区大小，包括帧头和有效载荷 "TestData" 的长度。
2. **创建缓冲区:** 创建一个 `IOBufferWithSize` 来存储要发送的数据。
3. **构建帧头:** 创建一个 `WebSocketFrameHeader`，设置 `opcode` 为文本帧，`masked` 为 true（因为是客户端发送），并计算 `payload_length`。
4. **写入帧头:** 将帧头写入缓冲区。
5. **写入有效载荷:** 将 "TestData" 写入缓冲区。
6. **应用掩码:** 对有效载荷应用掩码。掩码密钥由 `generate_websocket_masking_key_` 生成。
7. **调用底层 Socket 的 Write:** 调用 `connection_->Write` 将缓冲区中的数据发送出去。

**假设输出 (写入):**

假设生成的掩码密钥是 `0x12345678`，"TestData" 的字节表示是 `0x54 65 73 74 44 61 74 61`。应用掩码的操作是与掩码密钥的循环字节进行异或运算。

输出的二进制数据可能如下（简化表示，实际帧头可能更复杂）：

```
81 // 文本帧，FIN=1
88 // 掩码位设置，payload length < 126
01 23 45 67 // 掩码密钥
55 46 36 33 45 47 30 03 // 掩码后的 "TestData"
```

**假设输入 (读取):**

* 从 WebSocket 服务器接收到以下二进制数据： `81 88 1A 2B 3C 4D 5E 6F 7A 8B` (假设这是一个文本帧，payload length < 126，且已掩码)

**`WebSocketBasicStream::ReadFrames` 的行为:**

1. **从 Socket 读取:** 调用 `connection_->Read` 将数据读取到 `read_buffer_`。
2. **解析帧头:**  `WebSocketParser` 解析 `read_buffer_` 中的数据，提取帧头信息，例如 `opcode`（文本帧）、`masked`（true）、`payload_length`。
3. **提取掩码密钥:** 从帧头中提取掩码密钥 `0x1A2B3C4D`.
4. **提取有效载荷:**  提取掩码后的有效载荷 `0x5E6F7A8B`。
5. **应用掩码:** 使用提取到的掩码密钥对有效载荷进行反掩码操作。
6. **创建 `WebSocketFrame`:**  创建一个 `WebSocketFrame` 对象，包含解析后的帧头和反掩码后的有效载荷。
7. **调用回调:**  通过 `read_callback_` 将 `WebSocketFrame` 传递给上层。

**假设输出 (读取):**

* 一个 `WebSocketFrame` 对象，其 `header.opcode` 为文本帧，`header.payload_length` 为 4，`payload` 内容为反掩码后的原始数据（假设反掩码后是 "DATA" 的字节表示）。

**涉及用户或者编程常见的使用错误，举例说明:**

1. **服务端没有正确实现 WebSocket 协议:**  例如，服务端发送未掩码的数据给客户端（根据 RFC6455，服务端到客户端的数据必须是非掩码的）。`WebSocketBasicStream` 在解析时会检测到掩码位，如果发现服务端发送了掩码数据，可能会导致连接断开或者解析错误。
2. **客户端尝试发送未掩码的数据:**  虽然 `WebSocketBasicStream` 会强制对客户端发送的数据进行掩码，但如果用户或上层代码错误地构建了未掩码的帧，可能会导致服务端拒绝连接或者解析错误。
3. **处理大数据时的缓冲区溢出或内存不足:** 如果接收到非常大的 WebSocket 消息，而上层没有正确处理分片或者流式数据，可能会导致内存问题。`WebSocketBasicStream` 内部有缓冲区管理，但如果数据量超出预期，仍然可能出现问题。
4. **不正确的状态管理:** WebSocket 连接有不同的状态（连接中、关闭等）。如果上层代码没有正确管理状态，例如在连接关闭后尝试发送数据，`WebSocketBasicStream` 会返回错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

要调试涉及到 `WebSocketBasicStream` 的问题，可以按照以下步骤追踪用户操作和代码执行流程：

1. **用户在浏览器中打开一个网页。**
2. **网页中的 JavaScript 代码创建了一个 `WebSocket` 对象，并指定了 WebSocket 服务器的 URL (`ws://` 或 `wss://`)。**
3. **浏览器网络栈发起 WebSocket 握手。** 这涉及到发送 HTTP Upgrade 请求到服务器。
4. **服务器接受握手并返回 Upgrade 响应。**
5. **WebSocket 连接建立。**
6. **用户在网页上进行操作，触发 JavaScript 代码调用 `ws.send(data)` 发送数据。**
   - 这会调用到渲染器进程的 WebSocket 代码。
   - 数据会被传递到网络进程的 `WebSocketBasicStream::WriteFrames`。
7. **服务器发送数据到客户端。**
   - 底层 socket 接收到数据。
   - 网络进程的 `WebSocketBasicStream::ReadFrames` 被调用来处理接收到的数据。
8. **WebSocket 连接关闭。**
   - 可能由客户端 JavaScript 调用 `ws.close()` 发起。
   - 可能由服务器发起。
   - 无论哪一方发起，都会涉及到发送 WebSocket Close 帧，并最终调用 `WebSocketBasicStream` 的相关方法来处理关闭操作。

**调试线索:**

* **NetLog:**  启用 Chromium 的 NetLog 功能 (`chrome://net-export/`) 可以捕获详细的网络事件，包括 WebSocket 帧的发送和接收，以及相关的错误信息。这是调试 WebSocket 连接问题的首选工具。
* **开发者工具:** 浏览器的开发者工具的网络选项卡可以查看 WebSocket 连接的握手过程和消息传输情况。
* **断点调试:** 如果你有 Chromium 的源代码并进行本地构建，可以在 `WebSocketBasicStream` 的 `ReadFrames` 和 `WriteFrames` 等关键方法上设置断点，逐步跟踪代码执行，查看变量的值，理解数据是如何被处理的。
* **查看网络连接状态:** 可以检查底层的 socket 连接状态，确保连接是正常的。
* **分析错误信息:**  `WebSocketBasicStream` 返回的错误代码（例如 `ERR_CONNECTION_CLOSED`，`ERR_WS_PROTOCOL_ERROR` 等）可以提供关于问题原因的线索。

总而言之，`WebSocketBasicStream` 是 Chromium 网络栈中负责 WebSocket 数据流处理的关键组件，它连接了 JavaScript 的 `WebSocket` API 和底层的网络 socket，实现了 WebSocket 协议的帧处理、掩码、以及错误处理等核心功能。理解它的工作原理对于调试和理解 WebSocket 通信至关重要。

Prompt: 
```
这是目录为net/websockets/websocket_basic_stream.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/websockets/websocket_basic_stream.h"

#include <stddef.h>
#include <stdint.h>

#include <algorithm>
#include <limits>
#include <ostream>
#include <utility>

#include "base/check.h"
#include "base/check_op.h"
#include "base/containers/span.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/logging.h"
#include "base/numerics/safe_conversions.h"
#include "base/values.h"
#include "build/build_config.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/log/net_log_event_type.h"
#include "net/socket/client_socket_handle.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/websockets/websocket_basic_stream_adapters.h"
#include "net/websockets/websocket_errors.h"
#include "net/websockets/websocket_frame.h"

namespace net {

namespace {

// Please refer to the comment in class header if the usage changes.
constexpr net::NetworkTrafficAnnotationTag kTrafficAnnotation =
    net::DefineNetworkTrafficAnnotation("websocket_basic_stream", R"(
      semantics {
        sender: "WebSocket Basic Stream"
        description:
          "Implementation of WebSocket API from web content (a page the user "
          "visits)."
        trigger: "Website calls the WebSocket API."
        data:
          "Any data provided by web content, masked and framed in accordance "
          "with RFC6455."
        destination: OTHER
        destination_other:
          "The address that the website has chosen to communicate to."
      }
      policy {
        cookies_allowed: YES
        cookies_store: "user"
        setting: "These requests cannot be disabled."
        policy_exception_justification:
          "Not implemented. WebSocket is a core web platform API."
      }
      comments:
        "The browser will never add cookies to a WebSocket message. But the "
        "handshake that was performed when the WebSocket connection was "
        "established may have contained cookies."
      )");

// The number of bytes to attempt to read at a time. It's used only for high
// throughput connections.
// TODO(ricea): See if there is a better number or algorithm to fulfill our
// requirements:
//  1. We would like to use minimal memory on low-bandwidth or idle connections
//  2. We would like to read as close to line speed as possible on
//     high-bandwidth connections
//  3. We can't afford to cause jank on the IO thread by copying large buffers
//     around
//  4. We would like to hit any sweet-spots that might exist in terms of network
//     packet sizes / encryption block sizes / IPC alignment issues, etc.
#if BUILDFLAG(IS_ANDROID)
constexpr size_t kLargeReadBufferSize = 32 * 1024;
#else
// |2^n - delta| is better than 2^n on Linux. See crrev.com/c/1792208.
constexpr size_t kLargeReadBufferSize = 131000;
#endif

// The number of bytes to attempt to read at a time. It's set as an initial read
// buffer size and used for low throughput connections.
constexpr size_t kSmallReadBufferSize = 1000;

// The threshold to decide whether to switch the read buffer size.
constexpr double kThresholdInBytesPerSecond = 1200 * 1000;

// Returns the total serialized size of |frames|. This function assumes that
// |frames| will be serialized with mask field. This function forces the
// masked bit of the frames on.
int CalculateSerializedSizeAndTurnOnMaskBit(
    std::vector<std::unique_ptr<WebSocketFrame>>* frames) {
  constexpr uint64_t kMaximumTotalSize = std::numeric_limits<int>::max();

  uint64_t total_size = 0;
  for (const auto& frame : *frames) {
    // Force the masked bit on.
    frame->header.masked = true;
    // We enforce flow control so the renderer should never be able to force us
    // to cache anywhere near 2GB of frames.
    uint64_t frame_size = frame->header.payload_length +
                          GetWebSocketFrameHeaderSize(frame->header);
    CHECK_LE(frame_size, kMaximumTotalSize - total_size)
        << "Aborting to prevent overflow";
    total_size += frame_size;
  }
  return static_cast<int>(total_size);
}

base::Value::Dict NetLogBufferSizeParam(int buffer_size) {
  base::Value::Dict dict;
  dict.Set("read_buffer_size_in_bytes", buffer_size);
  return dict;
}

base::Value::Dict NetLogFrameHeaderParam(const WebSocketFrameHeader* header) {
  base::Value::Dict dict;
  dict.Set("final", header->final);
  dict.Set("reserved1", header->reserved1);
  dict.Set("reserved2", header->reserved2);
  dict.Set("reserved3", header->reserved3);
  dict.Set("opcode", header->opcode);
  dict.Set("masked", header->masked);
  dict.Set("payload_length", static_cast<double>(header->payload_length));
  return dict;
}

}  // namespace

WebSocketBasicStream::BufferSizeManager::BufferSizeManager() = default;

WebSocketBasicStream::BufferSizeManager::~BufferSizeManager() = default;

void WebSocketBasicStream::BufferSizeManager::OnRead(base::TimeTicks now) {
  read_start_timestamps_.push(now);
}

void WebSocketBasicStream::BufferSizeManager::OnReadComplete(
    base::TimeTicks now,
    int size) {
  DCHECK_GT(size, 0);
  // This cannot overflow because the result is at most
  // kLargeReadBufferSize*rolling_average_window_.
  rolling_byte_total_ += size;
  recent_read_sizes_.push(size);
  DCHECK_LE(read_start_timestamps_.size(), rolling_average_window_);
  if (read_start_timestamps_.size() == rolling_average_window_) {
    DCHECK_EQ(read_start_timestamps_.size(), recent_read_sizes_.size());
    base::TimeDelta duration = now - read_start_timestamps_.front();
    base::TimeDelta threshold_duration =
        base::Seconds(rolling_byte_total_ / kThresholdInBytesPerSecond);
    read_start_timestamps_.pop();
    rolling_byte_total_ -= recent_read_sizes_.front();
    recent_read_sizes_.pop();
    if (threshold_duration < duration) {
      buffer_size_ = BufferSize::kSmall;
    } else {
      buffer_size_ = BufferSize::kLarge;
    }
  }
}

WebSocketBasicStream::WebSocketBasicStream(
    std::unique_ptr<Adapter> connection,
    const scoped_refptr<GrowableIOBuffer>& http_read_buffer,
    const std::string& sub_protocol,
    const std::string& extensions,
    const NetLogWithSource& net_log)
    : read_buffer_(
          base::MakeRefCounted<IOBufferWithSize>(kSmallReadBufferSize)),
      target_read_buffer_size_(read_buffer_->size()),
      connection_(std::move(connection)),
      http_read_buffer_(http_read_buffer),
      sub_protocol_(sub_protocol),
      extensions_(extensions),
      net_log_(net_log),
      generate_websocket_masking_key_(&GenerateWebSocketMaskingKey) {
  // http_read_buffer_ should not be set if it contains no data.
  if (http_read_buffer_.get() && http_read_buffer_->offset() == 0)
    http_read_buffer_ = nullptr;
  DCHECK(connection_->is_initialized());
}

WebSocketBasicStream::~WebSocketBasicStream() { Close(); }

int WebSocketBasicStream::ReadFrames(
    std::vector<std::unique_ptr<WebSocketFrame>>* frames,
    CompletionOnceCallback callback) {
  read_callback_ = std::move(callback);
  control_frame_payloads_.clear();
  if (http_read_buffer_ && is_http_read_buffer_decoded_) {
    http_read_buffer_.reset();
  }
  return ReadEverything(frames);
}

int WebSocketBasicStream::WriteFrames(
    std::vector<std::unique_ptr<WebSocketFrame>>* frames,
    CompletionOnceCallback callback) {
  // This function always concatenates all frames into a single buffer.
  // TODO(ricea): Investigate whether it would be better in some cases to
  // perform multiple writes with smaller buffers.

  write_callback_ = std::move(callback);

  // First calculate the size of the buffer we need to allocate.
  int total_size = CalculateSerializedSizeAndTurnOnMaskBit(frames);
  auto combined_buffer = base::MakeRefCounted<IOBufferWithSize>(total_size);

  base::span<uint8_t> dest = combined_buffer->span();
  for (const auto& frame : *frames) {
    net_log_.AddEvent(net::NetLogEventType::WEBSOCKET_SENT_FRAME_HEADER,
                      [&] { return NetLogFrameHeaderParam(&frame->header); });
    WebSocketMaskingKey mask = generate_websocket_masking_key_();
    int result = WriteWebSocketFrameHeader(frame->header, &mask, dest);
    DCHECK_NE(ERR_INVALID_ARGUMENT, result)
        << "WriteWebSocketFrameHeader() says that " << dest.size()
        << " is not enough to write the header in. This should not happen.";
    dest = dest.subspan(base::checked_cast<size_t>(result));

    CHECK_LE(frame->header.payload_length,
             base::checked_cast<uint64_t>(dest.size()));
    const size_t frame_size = frame->header.payload_length;
    if (frame_size > 0) {
      dest.copy_prefix_from(frame->payload);
      MaskWebSocketFramePayload(mask, 0, dest.first(frame_size));
      dest = dest.subspan(frame_size);
    }
  }
  DCHECK(dest.empty()) << "Buffer size calculation was wrong; " << dest.size()
                       << " bytes left over.";
  auto drainable_buffer = base::MakeRefCounted<DrainableIOBuffer>(
      std::move(combined_buffer), total_size);
  return WriteEverything(drainable_buffer);
}

void WebSocketBasicStream::Close() {
  connection_->Disconnect();
}

std::string WebSocketBasicStream::GetSubProtocol() const {
  return sub_protocol_;
}

std::string WebSocketBasicStream::GetExtensions() const { return extensions_; }

const NetLogWithSource& WebSocketBasicStream::GetNetLogWithSource() const {
  return net_log_;
}

/*static*/
std::unique_ptr<WebSocketBasicStream>
WebSocketBasicStream::CreateWebSocketBasicStreamForTesting(
    std::unique_ptr<ClientSocketHandle> connection,
    const scoped_refptr<GrowableIOBuffer>& http_read_buffer,
    const std::string& sub_protocol,
    const std::string& extensions,
    const NetLogWithSource& net_log,
    WebSocketMaskingKeyGeneratorFunction key_generator_function) {
  auto stream = std::make_unique<WebSocketBasicStream>(
      std::make_unique<WebSocketClientSocketHandleAdapter>(
          std::move(connection)),
      http_read_buffer, sub_protocol, extensions, net_log);
  stream->generate_websocket_masking_key_ = key_generator_function;
  return stream;
}

int WebSocketBasicStream::ReadEverything(
    std::vector<std::unique_ptr<WebSocketFrame>>* frames) {
  DCHECK(frames->empty());

  // If there is data left over after parsing the HTTP headers, attempt to parse
  // it as WebSocket frames.
  if (http_read_buffer_.get() && !is_http_read_buffer_decoded_) {
    DCHECK_GE(http_read_buffer_->offset(), 0);
    is_http_read_buffer_decoded_ = true;
    std::vector<std::unique_ptr<WebSocketFrameChunk>> frame_chunks;
    if (!parser_.Decode(http_read_buffer_->span_before_offset(),
                        &frame_chunks)) {
      return WebSocketErrorToNetError(parser_.websocket_error());
    }
    if (!frame_chunks.empty()) {
      int result = ConvertChunksToFrames(&frame_chunks, frames);
      if (result != ERR_IO_PENDING)
        return result;
    }
  }

  // Run until socket stops giving us data or we get some frames.
  while (true) {
    if (buffer_size_manager_.buffer_size() != buffer_size_) {
      read_buffer_ = base::MakeRefCounted<IOBufferWithSize>(
          buffer_size_manager_.buffer_size() == BufferSize::kSmall
              ? kSmallReadBufferSize
              : kLargeReadBufferSize);
      buffer_size_ = buffer_size_manager_.buffer_size();
      net_log_.AddEvent(
          net::NetLogEventType::WEBSOCKET_READ_BUFFER_SIZE_CHANGED,
          [&] { return NetLogBufferSizeParam(read_buffer_->size()); });
    }
    buffer_size_manager_.OnRead(base::TimeTicks::Now());

    // base::Unretained(this) here is safe because net::Socket guarantees not to
    // call any callbacks after Disconnect(), which we call from the destructor.
    // The caller of ReadEverything() is required to keep |frames| valid.
    int result = connection_->Read(
        read_buffer_.get(), read_buffer_->size(),
        base::BindOnce(&WebSocketBasicStream::OnReadComplete,
                       base::Unretained(this), base::Unretained(frames)));
    if (result == ERR_IO_PENDING)
      return result;
    result = HandleReadResult(result, frames);
    if (result != ERR_IO_PENDING)
      return result;
    DCHECK(frames->empty());
  }
}

void WebSocketBasicStream::OnReadComplete(
    std::vector<std::unique_ptr<WebSocketFrame>>* frames,
    int result) {
  result = HandleReadResult(result, frames);
  if (result == ERR_IO_PENDING)
    result = ReadEverything(frames);
  if (result != ERR_IO_PENDING)
    std::move(read_callback_).Run(result);
}

int WebSocketBasicStream::WriteEverything(
    const scoped_refptr<DrainableIOBuffer>& buffer) {
  while (buffer->BytesRemaining() > 0) {
    // The use of base::Unretained() here is safe because on destruction we
    // disconnect the socket, preventing any further callbacks.
    int result = connection_->Write(
        buffer.get(), buffer->BytesRemaining(),
        base::BindOnce(&WebSocketBasicStream::OnWriteComplete,
                       base::Unretained(this), buffer),
        kTrafficAnnotation);
    if (result > 0) {
      buffer->DidConsume(result);
    } else {
      return result;
    }
  }
  return OK;
}

void WebSocketBasicStream::OnWriteComplete(
    const scoped_refptr<DrainableIOBuffer>& buffer,
    int result) {
  if (result < 0) {
    DCHECK_NE(ERR_IO_PENDING, result);
    std::move(write_callback_).Run(result);
    return;
  }

  DCHECK_NE(0, result);

  buffer->DidConsume(result);
  result = WriteEverything(buffer);
  if (result != ERR_IO_PENDING)
    std::move(write_callback_).Run(result);
}

int WebSocketBasicStream::HandleReadResult(
    int result,
    std::vector<std::unique_ptr<WebSocketFrame>>* frames) {
  DCHECK_NE(ERR_IO_PENDING, result);
  DCHECK(frames->empty());
  if (result < 0)
    return result;
  if (result == 0)
    return ERR_CONNECTION_CLOSED;

  buffer_size_manager_.OnReadComplete(base::TimeTicks::Now(), result);

  std::vector<std::unique_ptr<WebSocketFrameChunk>> frame_chunks;
  if (!parser_.Decode(
          read_buffer_->span().first(base::checked_cast<size_t>(result)),
          &frame_chunks)) {
    return WebSocketErrorToNetError(parser_.websocket_error());
  }
  if (frame_chunks.empty())
    return ERR_IO_PENDING;
  return ConvertChunksToFrames(&frame_chunks, frames);
}

int WebSocketBasicStream::ConvertChunksToFrames(
    std::vector<std::unique_ptr<WebSocketFrameChunk>>* frame_chunks,
    std::vector<std::unique_ptr<WebSocketFrame>>* frames) {
  for (auto& chunk : *frame_chunks) {
    DCHECK(chunk == frame_chunks->back() || chunk->final_chunk)
        << "Only last chunk can have |final_chunk| set to be false.";

    if (chunk->header) {
      net_log_.AddEvent(net::NetLogEventType::WEBSOCKET_RECV_FRAME_HEADER, [&] {
        return NetLogFrameHeaderParam(chunk->header.get());
      });
    }

    auto frame_result = chunk_assembler_.HandleChunk(std::move(chunk));

    if (!frame_result.has_value()) {
      return frame_result.error();
    }

    auto frame = std::move(frame_result.value());
    bool is_control_opcode =
        WebSocketFrameHeader::IsKnownControlOpCode(frame->header.opcode) ||
        WebSocketFrameHeader::IsReservedControlOpCode(frame->header.opcode);
    if (is_control_opcode) {
      const size_t length =
          base::checked_cast<size_t>(frame->header.payload_length);
      if (length > 0) {
        auto copied_payload =
            base::HeapArray<uint8_t>::CopiedFrom(frame->payload);
        frame->payload = copied_payload.as_span();
        control_frame_payloads_.emplace_back(std::move(copied_payload));
      }
    }

    frames->emplace_back(std::move(frame));
  }

  frame_chunks->clear();

  return frames->empty() ? ERR_IO_PENDING : OK;
}

}  // namespace net

"""

```