Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Core Purpose:** The filename "callback_visitor.cc" and the class name "CallbackVisitor" strongly suggest a visitor pattern implementation. The presence of "callback" hints that this visitor interacts with external code through function pointers. The directory "net/third_party/quiche/src/quiche/http2/adapter/" tells us it's part of an HTTP/2 implementation within a larger network stack (likely Chromium). The `adapter` part is crucial; it suggests mediating between different HTTP/2 libraries or internal representations.

2. **Identify Key Dependencies:** The `#include` statements are essential. We see:
    * Standard C/C++: `<cstring>` (for `memset`), `<cstdint>` (implicitly included).
    * Abseil: `absl/strings/escaping.h` (for string escaping, likely for logging), `absl/string_view.h` (for efficient string handling).
    * Internal Quiche/HTTP2 headers:  These are crucial for understanding the interaction with other parts of the HTTP/2 stack. Specifically, `http2_util.h`, `nghttp2.h`, `nghttp2_util.h` indicate interaction with the `nghttp2` library.
    * `quiche_endian.h`: For handling byte order.

3. **Analyze the `nghttp2_session_callbacks` Structure:**  The code explicitly defines (or redefines) `nghttp2_session_callbacks`. This is a huge clue. It means this `CallbackVisitor` is designed to work *with* the `nghttp2` library's event-driven mechanism. The structure contains function pointers for various HTTP/2 events (sending, receiving frames, handling headers, etc.). This reinforces the "callback" nature of the visitor. The `#ifdef NGHTTP2_16` block suggests compatibility handling for different `nghttp2` versions.

4. **Examine the `CallbackVisitor` Class:**
    * **Constructor:** It takes `Perspective` (client or server), `nghttp2_session_callbacks`, and `user_data`. This reinforces the connection to `nghttp2`. The constructor initializes the `callbacks_` member by copying the provided callbacks.
    * **`OnReadyToSend`:** This clearly deals with sending data. It directly calls the `send_callback` from the `nghttp2_session_callbacks` structure. The return values (positive for success, `kSendBlocked`, `kSendError`) are standard for asynchronous operations.
    * **`OnReadyToSendDataForStream` and `SendDataFrame`:** These methods log `FATAL`. This is a strong indication that this `CallbackVisitor` *doesn't* handle sending data frames directly. It relies on the `nghttp2` callback mechanism for this.
    * **`OnFrameHeader`:** This is the entry point for processing incoming frames. It handles CONTINUATION frames specially and otherwise initializes `current_frame_`. It also calls `on_begin_frame_callback`.
    * **`OnSettingsStart`, `OnSetting`, `OnSettingsEnd`, `OnSettingsAck`:** These methods handle the SETTINGS frame. They accumulate settings and then invoke `on_frame_recv_callback`.
    * **`OnBeginHeadersForStream`, `OnHeaderForStream`, `OnEndHeadersForStream`:** These methods handle headers. They categorize the headers (request, response, trailers) and call the appropriate callbacks.
    * **`OnDataPaddingLength`, `OnBeginDataForStream`, `OnDataForStream`, `OnEndStream`:** These methods handle DATA frames. They manage padding and call `on_data_chunk_recv_callback` and potentially `on_frame_recv_callback`.
    * **`OnRstStream`, `OnCloseStream`, `OnPriorityForStream`, `OnPing`, `OnPushPromiseForStream`, `OnGoAway`, `OnWindowUpdate`:** These methods handle other HTTP/2 frame types, updating the `current_frame_` and invoking the corresponding callbacks.
    * **`OnBeforeFrameSent`, `OnFrameSent`:** These methods handle callbacks *before* and *after* a frame is sent.
    * **`OnInvalidFrame`:** Handles invalid frames.
    * **`OnBeginMetadataForStream`, `OnMetadataForStream`, `OnMetadataEndForStream`, `PackMetadataForStream`:** Handle HPACK metadata extensions. Note `PackMetadataForStream` is `DFATAL`, suggesting it's not the primary method for sending metadata in this setup.
    * **`OnErrorDebug`:** Handles debug messages.
    * **`GetStreamInfo`:** Manages a map of stream-related information.
    * **`PopulateFrame`:** A helper function to populate the `nghttp2_frame` structure.

5. **Identify the Core Functionality:** The primary function of `CallbackVisitor` is to act as an intermediary between a higher-level HTTP/2 implementation (likely within Chromium) and the `nghttp2` library. It receives events from the higher level (e.g., "a header was received") and translates them into calls to the `nghttp2` callbacks. Conversely, when `nghttp2` generates output (data to send), `CallbackVisitor` handles that.

6. **Relate to JavaScript (if applicable):**  Consider how this C++ code interacts with the browser environment, which involves JavaScript. The most direct link is the network stack itself. When a JavaScript application (e.g., a website) makes an HTTP/2 request:
    * The browser's networking code (which includes this C++ code) handles the request.
    * This `CallbackVisitor` plays a role in processing the HTTP/2 protocol.
    * The results (response headers, data) are eventually passed back up to the JavaScript layer through browser APIs (like `fetch` or `XMLHttpRequest`).

7. **Logical Reasoning (Input/Output):** Focus on the core callbacks. If the input is a raw byte stream representing an HTTP/2 HEADERS frame, the `CallbackVisitor` would:
    * `OnFrameHeader` would be called first, parsing the frame header.
    * `OnBeginHeadersForStream` would be called.
    * `OnHeaderForStream` would be called multiple times, once for each header.
    * `OnEndHeadersForStream` would be called.
    * Finally, `on_frame_recv_callback` (from `nghttp2`) would be invoked, passing the constructed `nghttp2_frame` structure.

8. **User/Programming Errors:** Think about common mistakes when working with HTTP/2 or the `nghttp2` library:
    * Incorrectly implementing or configuring the `nghttp2_session_callbacks`.
    * Sending frames in the wrong order.
    * Violating HTTP/2 protocol rules.
    * Not handling errors returned by the callbacks.

9. **Debugging:**  Trace the execution flow. How does user interaction lead to this code being executed?  A user typing a URL in the address bar, clicking a link, or a JavaScript application making a network request are all potential starting points. The request goes through various layers of the browser, eventually reaching the HTTP/2 implementation where this code resides. Logging within the `CallbackVisitor` (like the `QUICHE_VLOG` statements) would be crucial for debugging.

This systematic approach, focusing on understanding the purpose, dependencies, key components, and interactions, helps in dissecting even complex C++ code like this.
这个 C++ 文件 `callback_visitor.cc` 定义了一个名为 `CallbackVisitor` 的类，它是 Chromium 网络栈中 QUICHE 库的一部分，专门用于处理 HTTP/2 协议。它的主要功能是**将底层的 nghttp2 库产生的事件（通过回调函数）转换成更高级别的、面向对象的访问者模式的接口**。

让我们详细列举它的功能：

**核心功能:**

1. **充当 nghttp2 的回调适配器:**  `CallbackVisitor` 实现了 `Http2VisitorInterface`，这个接口定义了一组抽象方法，用于处理各种 HTTP/2 事件，例如收到帧头、开始/结束头部、接收数据等。它使用 `nghttp2_session_callbacks` 结构体中定义的函数指针，将 `nghttp2` 库产生的事件转发到其自身的成员方法中。

2. **管理 HTTP/2 会话状态:** 它维护一些内部状态，例如 `current_frame_` 用于存储当前正在处理的帧的信息，`settings_` 用于存储收到的 SETTINGS 帧的设置，以及 `stream_map_` 用于跟踪流的状态信息。

3. **处理各种 HTTP/2 帧类型:**  `CallbackVisitor` 实现了 `Http2VisitorInterface` 中的方法，以处理以下常见的 HTTP/2 帧类型：
    * **HEADERS:** 处理请求或响应头部。
    * **DATA:** 处理数据帧。
    * **SETTINGS:** 处理设置帧。
    * **PING:** 处理 PING 帧。
    * **GOAWAY:** 处理 GOAWAY 帧。
    * **WINDOW_UPDATE:** 处理窗口更新帧。
    * **RST_STREAM:** 处理流重置帧。
    * **PRIORITY:** 处理优先级帧。
    * **CONTINUATION:** 处理头部块的延续帧。
    * **PUSH_PROMISE:** (未实现) 处理服务端推送帧。
    * **METADATA:** 处理元数据帧（扩展）。

4. **提供发送数据的接口:**  `OnReadyToSend` 方法允许发送序列化的 HTTP/2 帧数据。

5. **处理错误情况:**  `OnInvalidFrame` 方法处理接收到的无效帧，`OnErrorDebug` 方法处理调试消息。

6. **支持 before/after 帧发送回调:** `OnBeforeFrameSent` 和 `OnFrameSent` 方法允许在帧发送前后执行特定的逻辑。

**与 JavaScript 功能的关系 (举例说明):**

`CallbackVisitor` 本身是用 C++ 编写的，并不直接涉及 JavaScript 代码。但是，它在浏览器网络栈中扮演着关键角色，使得 JavaScript 代码能够通过浏览器发送和接收 HTTP/2 数据。

**举例说明:**

假设一个 JavaScript 应用程序使用 `fetch()` API 发起一个 HTTP/2 GET 请求：

1. **JavaScript 发起请求:** `fetch('https://example.com/data')` 在浏览器中被调用。
2. **浏览器网络栈处理:** 浏览器网络栈开始处理这个请求，确定使用 HTTP/2 协议。
3. **创建 nghttp2 会话:**  浏览器内部会创建一个 `nghttp2` 会话实例。
4. **设置回调:**  `CallbackVisitor` 的实例会被创建，并将其自身注册为 `nghttp2` 会话的回调处理程序。这意味着当 `nghttp2` 库解析或生成 HTTP/2 帧时，会调用 `CallbackVisitor` 中相应的方法。
5. **发送 HEADERS 帧:** 当需要发送请求头时，浏览器网络栈会调用 `nghttp2` 的发送函数，`nghttp2` 会调用 `CallbackVisitor` 的 `OnBeforeFrameSent` (如果设置了回调) 和内部的发送回调，最终调用到 `CallbackVisitor::OnReadyToSend` 方法，将序列化的 HEADERS 帧数据发送出去。
6. **接收数据:** 当服务器响应时，`nghttp2` 库会解析接收到的字节流，并根据帧类型调用 `CallbackVisitor` 的相应方法，例如 `OnFrameHeader`、`OnBeginHeadersForStream`、`OnHeaderForStream`、`OnEndHeadersForStream`（对于响应头），以及 `OnFrameHeader`、`OnBeginDataForStream`、`OnDataForStream`（对于响应体）。
7. **传递给 JavaScript:**  `CallbackVisitor` 处理完这些事件后，会将解析出的数据传递回浏览器网络栈的更上层，最终通过 `fetch()` API 的 Promise 对象将响应返回给 JavaScript 代码。

**逻辑推理 (假设输入与输出):**

**假设输入:** 接收到服务器发来的一个包含以下内容的 HEADERS 帧：

```
:status: 200
Content-Type: application/json
Content-Length: 123
```

**预期输出 (`CallbackVisitor` 的行为):**

1. `OnFrameHeader` 方法会被调用，参数包含流 ID、帧长度、类型 (HEADERS) 和标志。
2. `OnBeginHeadersForStream` 方法会被调用，参数包含流 ID。
3. `OnHeaderForStream` 方法会被调用三次：
    * 第一次：name = ":status", value = "200"
    * 第二次：name = "Content-Type", value = "application/json"
    * 第三次：name = "Content-Length", value = "123"
4. `OnEndHeadersForStream` 方法会被调用，参数包含流 ID。
5. `on_frame_recv_callback` (nghttp2 的回调) 会被调用，传递一个包含解析出的头部信息的 `nghttp2_frame` 结构体。

**涉及用户或编程常见的使用错误 (举例说明):**

1. **不正确的回调设置:** 如果在使用 `CallbackVisitor` 时，没有正确地配置 `nghttp2_session_callbacks` 结构体，例如 `send_callback` 为空，那么在需要发送数据时，`OnReadyToSend` 方法会返回 `kSendError`。这可能是因为用户在使用 HTTP/2 库时，没有正确初始化或连接到网络。

2. **状态管理错误:** 如果在高层代码中没有正确管理 HTTP/2 流的状态，例如在流关闭后仍然尝试发送数据，可能会导致 `CallbackVisitor` 中处理帧的方法接收到不期望的事件序列，从而导致程序错误或协议违规。

3. **处理回调返回值不当:** `nghttp2` 的回调函数通常会返回一些指示状态的值。例如，`on_header_callback` 返回非零值可能表示错误。如果 `CallbackVisitor` 没有正确处理这些返回值，可能会导致连接中断或其他不可预测的行为。例如，`OnHeaderForStream` 方法中，如果 `callbacks_->on_header_callback` 返回 `NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE`，则 `CallbackVisitor` 会返回 `HEADER_RST_STREAM`，指示需要重置流。如果高层代码忽略了这个返回值，可能会导致数据不一致。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入 URL 并回车:**  这是最常见的触发网络请求的方式。
2. **浏览器解析 URL:** 浏览器会解析输入的 URL，提取主机名、端口号等信息。
3. **DNS 查询:** 浏览器会进行 DNS 查询，获取目标服务器的 IP 地址。
4. **建立 TCP 连接 (或 QUIC 连接):**  根据协议，浏览器会与服务器建立 TCP 连接（对于 HTTP/2 over TLS）或 QUIC 连接。
5. **TLS 握手 (如果使用 HTTPS):**  如果使用 HTTPS，会进行 TLS 握手以建立安全连接。
6. **HTTP/2 协商:**  在 TLS 握手期间，浏览器和服务器会协商使用 HTTP/2 协议（通过 ALPN 扩展）。
7. **创建 nghttp2 会话:**  一旦确定使用 HTTP/2，浏览器网络栈会创建一个 `nghttp2_session` 实例，并配置 `CallbackVisitor` 作为其回调处理程序。
8. **发送 HTTP/2 请求帧:** 当 JavaScript 代码通过 `fetch()` 或其他 API 发起请求时，浏览器会将请求信息转换为 HTTP/2 帧（例如 HEADERS 帧），并调用 `nghttp2` 的发送函数。  `CallbackVisitor::OnReadyToSend` 会被调用来实际发送这些字节。
9. **接收 HTTP/2 响应帧:** 服务器的响应也会被 `nghttp2` 库解析，并触发 `CallbackVisitor` 中的各种 `On...` 方法。
10. **错误或异常情况:** 在任何阶段，如果发生错误（例如网络中断、协议错误），`nghttp2` 库会调用 `CallbackVisitor` 中相应的错误处理方法（例如 `OnInvalidFrame`），这些信息可以作为调试线索。

**调试线索:**

* **网络抓包:** 使用 Wireshark 等工具抓取网络数据包，可以查看实际发送和接收的 HTTP/2 帧内容，帮助理解 `CallbackVisitor` 处理的数据。
* **日志记录:**  `CallbackVisitor` 中使用了 `QUICHE_VLOG` 和 `QUICHE_LOG` 进行日志记录。配置合适的日志级别可以输出详细的 HTTP/2 事件处理过程。
* **断点调试:** 在 `CallbackVisitor` 的关键方法中设置断点，可以单步跟踪代码执行流程，查看变量的值，理解状态变化。
* **nghttp2 库的调试输出:**  `nghttp2` 库本身也提供了一些调试选项，可以输出更底层的协议解析信息。

总而言之，`callback_visitor.cc` 中的 `CallbackVisitor` 类是 Chromium 网络栈中 HTTP/2 实现的关键组成部分，它负责将底层的 `nghttp2` 库事件转换为更易于管理和使用的抽象接口，从而驱动整个 HTTP/2 通信流程。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/callback_visitor.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
#include "quiche/http2/adapter/callback_visitor.h"

#include <cstring>

#include "absl/strings/escaping.h"
#include "quiche/http2/adapter/http2_util.h"
#include "quiche/http2/adapter/nghttp2.h"
#include "quiche/http2/adapter/nghttp2_util.h"
#include "quiche/common/quiche_endian.h"

// This visitor implementation needs visibility into the
// nghttp2_session_callbacks type. There's no public header, so we'll redefine
// the struct here.
#ifdef NGHTTP2_16
namespace {
using FunctionPtr = void (*)(void);
}  // namespace

struct nghttp2_session_callbacks {
  nghttp2_send_callback send_callback;
  FunctionPtr send_callback2;
  nghttp2_recv_callback recv_callback;
  FunctionPtr recv_callback2;
  nghttp2_on_frame_recv_callback on_frame_recv_callback;
  nghttp2_on_invalid_frame_recv_callback on_invalid_frame_recv_callback;
  nghttp2_on_data_chunk_recv_callback on_data_chunk_recv_callback;
  nghttp2_before_frame_send_callback before_frame_send_callback;
  nghttp2_on_frame_send_callback on_frame_send_callback;
  nghttp2_on_frame_not_send_callback on_frame_not_send_callback;
  nghttp2_on_stream_close_callback on_stream_close_callback;
  nghttp2_on_begin_headers_callback on_begin_headers_callback;
  nghttp2_on_header_callback on_header_callback;
  nghttp2_on_header_callback2 on_header_callback2;
  nghttp2_on_invalid_header_callback on_invalid_header_callback;
  nghttp2_on_invalid_header_callback2 on_invalid_header_callback2;
  nghttp2_select_padding_callback select_padding_callback;
  FunctionPtr select_padding_callback2;
  nghttp2_data_source_read_length_callback read_length_callback;
  FunctionPtr read_length_callback2;
  nghttp2_on_begin_frame_callback on_begin_frame_callback;
  nghttp2_send_data_callback send_data_callback;
  nghttp2_pack_extension_callback pack_extension_callback;
  FunctionPtr pack_extension_callback2;
  nghttp2_unpack_extension_callback unpack_extension_callback;
  nghttp2_on_extension_chunk_recv_callback on_extension_chunk_recv_callback;
  nghttp2_error_callback error_callback;
  nghttp2_error_callback2 error_callback2;
};
#else
struct nghttp2_session_callbacks {
  nghttp2_send_callback send_callback;
  nghttp2_recv_callback recv_callback;
  nghttp2_on_frame_recv_callback on_frame_recv_callback;
  nghttp2_on_invalid_frame_recv_callback on_invalid_frame_recv_callback;
  nghttp2_on_data_chunk_recv_callback on_data_chunk_recv_callback;
  nghttp2_before_frame_send_callback before_frame_send_callback;
  nghttp2_on_frame_send_callback on_frame_send_callback;
  nghttp2_on_frame_not_send_callback on_frame_not_send_callback;
  nghttp2_on_stream_close_callback on_stream_close_callback;
  nghttp2_on_begin_headers_callback on_begin_headers_callback;
  nghttp2_on_header_callback on_header_callback;
  nghttp2_on_header_callback2 on_header_callback2;
  nghttp2_on_invalid_header_callback on_invalid_header_callback;
  nghttp2_on_invalid_header_callback2 on_invalid_header_callback2;
  nghttp2_select_padding_callback select_padding_callback;
  nghttp2_data_source_read_length_callback read_length_callback;
  nghttp2_on_begin_frame_callback on_begin_frame_callback;
  nghttp2_send_data_callback send_data_callback;
  nghttp2_pack_extension_callback pack_extension_callback;
  nghttp2_unpack_extension_callback unpack_extension_callback;
  nghttp2_on_extension_chunk_recv_callback on_extension_chunk_recv_callback;
  nghttp2_error_callback error_callback;
  nghttp2_error_callback2 error_callback2;
};
#endif

namespace http2 {
namespace adapter {

CallbackVisitor::CallbackVisitor(Perspective perspective,
                                 const nghttp2_session_callbacks& callbacks,
                                 void* user_data)
    : perspective_(perspective),
      callbacks_(MakeCallbacksPtr(nullptr)),
      user_data_(user_data) {
  nghttp2_session_callbacks* c;
  nghttp2_session_callbacks_new(&c);
  *c = callbacks;
  callbacks_ = MakeCallbacksPtr(c);
  memset(&current_frame_, 0, sizeof(current_frame_));
}

int64_t CallbackVisitor::OnReadyToSend(absl::string_view serialized) {
  if (!callbacks_->send_callback) {
    return kSendError;
  }
  int64_t result = callbacks_->send_callback(
      nullptr, ToUint8Ptr(serialized.data()), serialized.size(), 0, user_data_);
  QUICHE_VLOG(1) << "CallbackVisitor::OnReadyToSend called with "
                 << serialized.size() << " bytes, returning " << result;
  QUICHE_VLOG(2) << (perspective_ == Perspective::kClient ? "Client" : "Server")
                 << " sending: [" << absl::CEscape(serialized) << "]";
  if (result > 0) {
    return result;
  } else if (result == NGHTTP2_ERR_WOULDBLOCK) {
    return kSendBlocked;
  } else {
    return kSendError;
  }
}

Http2VisitorInterface::DataFrameHeaderInfo
CallbackVisitor::OnReadyToSendDataForStream(Http2StreamId /*stream_id*/,
                                            size_t /*max_length*/) {
  QUICHE_LOG(FATAL)
      << "Not implemented; should not be used with nghttp2 callbacks.";
  return {};
}

bool CallbackVisitor::SendDataFrame(Http2StreamId /*stream_id*/,
                                    absl::string_view /*frame_header*/,
                                    size_t /*payload_bytes*/) {
  QUICHE_LOG(FATAL)
      << "Not implemented; should not be used with nghttp2 callbacks.";
  return false;
}

void CallbackVisitor::OnConnectionError(ConnectionError /*error*/) {
  QUICHE_VLOG(1) << "OnConnectionError not implemented";
}

bool CallbackVisitor::OnFrameHeader(Http2StreamId stream_id, size_t length,
                                    uint8_t type, uint8_t flags) {
  QUICHE_VLOG(1) << "CallbackVisitor::OnFrameHeader(stream_id=" << stream_id
                 << ", type=" << int(type) << ", length=" << length
                 << ", flags=" << int(flags) << ")";
  if (static_cast<FrameType>(type) == FrameType::CONTINUATION) {
    if (static_cast<FrameType>(current_frame_.hd.type) != FrameType::HEADERS ||
        current_frame_.hd.stream_id == 0 ||
        current_frame_.hd.stream_id != stream_id) {
      // CONTINUATION frames must follow HEADERS on the same stream. If no
      // frames have been received, the type is initialized to zero, and the
      // comparison will fail.
      return false;
    }
    current_frame_.hd.length += length;
    current_frame_.hd.flags |= flags;
    QUICHE_DLOG_IF(ERROR, length == 0) << "Empty CONTINUATION!";
    // Still need to deliver the CONTINUATION to the begin frame callback.
    nghttp2_frame_hd hd;
    memset(&hd, 0, sizeof(hd));
    hd.stream_id = stream_id;
    hd.length = length;
    hd.type = type;
    hd.flags = flags;
    if (callbacks_->on_begin_frame_callback) {
      const int result =
          callbacks_->on_begin_frame_callback(nullptr, &hd, user_data_);
      return result == 0;
    }
    return true;
  }
  // The general strategy is to clear |current_frame_| at the start of a new
  // frame, accumulate frame information from the various callback events, then
  // invoke the on_frame_recv_callback() with the accumulated frame data.
  memset(&current_frame_, 0, sizeof(current_frame_));
  current_frame_.hd.stream_id = stream_id;
  current_frame_.hd.length = length;
  current_frame_.hd.type = type;
  current_frame_.hd.flags = flags;
  if (callbacks_->on_begin_frame_callback) {
    const int result = callbacks_->on_begin_frame_callback(
        nullptr, &current_frame_.hd, user_data_);
    return result == 0;
  }
  return true;
}

void CallbackVisitor::OnSettingsStart() {}

void CallbackVisitor::OnSetting(Http2Setting setting) {
  settings_.push_back({setting.id, setting.value});
}

void CallbackVisitor::OnSettingsEnd() {
  current_frame_.settings.niv = settings_.size();
  current_frame_.settings.iv = settings_.data();
  QUICHE_VLOG(1) << "OnSettingsEnd, received settings of size "
                 << current_frame_.settings.niv;
  if (callbacks_->on_frame_recv_callback) {
    const int result = callbacks_->on_frame_recv_callback(
        nullptr, &current_frame_, user_data_);
    QUICHE_DCHECK_EQ(0, result);
  }
  settings_.clear();
}

void CallbackVisitor::OnSettingsAck() {
  // ACK is part of the flags, which were set in OnFrameHeader().
  QUICHE_VLOG(1) << "OnSettingsAck()";
  if (callbacks_->on_frame_recv_callback) {
    const int result = callbacks_->on_frame_recv_callback(
        nullptr, &current_frame_, user_data_);
    QUICHE_DCHECK_EQ(0, result);
  }
}

bool CallbackVisitor::OnBeginHeadersForStream(Http2StreamId stream_id) {
  auto it = GetStreamInfo(stream_id);
  if (it == stream_map_.end()) {
    current_frame_.headers.cat = NGHTTP2_HCAT_HEADERS;
  } else {
    if (it->second.received_headers) {
      // At least one headers frame has already been received.
      QUICHE_VLOG(1)
          << "Headers already received for stream " << stream_id
          << ", these are trailers or headers following a 100 response";
      current_frame_.headers.cat = NGHTTP2_HCAT_HEADERS;
    } else {
      switch (perspective_) {
        case Perspective::kClient:
          QUICHE_VLOG(1) << "First headers at the client for stream "
                         << stream_id << "; these are response headers";
          current_frame_.headers.cat = NGHTTP2_HCAT_RESPONSE;
          break;
        case Perspective::kServer:
          QUICHE_VLOG(1) << "First headers at the server for stream "
                         << stream_id << "; these are request headers";
          current_frame_.headers.cat = NGHTTP2_HCAT_REQUEST;
          break;
      }
    }
    it->second.received_headers = true;
  }
  if (callbacks_->on_begin_headers_callback) {
    const int result = callbacks_->on_begin_headers_callback(
        nullptr, &current_frame_, user_data_);
    return result == 0;
  }
  return true;
}

Http2VisitorInterface::OnHeaderResult CallbackVisitor::OnHeaderForStream(
    Http2StreamId stream_id, absl::string_view name, absl::string_view value) {
  QUICHE_VLOG(2) << "OnHeaderForStream(stream_id=" << stream_id << ", name=["
                 << absl::CEscape(name) << "], value=[" << absl::CEscape(value)
                 << "])";
  if (callbacks_->on_header_callback) {
    const int result = callbacks_->on_header_callback(
        nullptr, &current_frame_, ToUint8Ptr(name.data()), name.size(),
        ToUint8Ptr(value.data()), value.size(), NGHTTP2_NV_FLAG_NONE,
        user_data_);
    if (result == 0) {
      return HEADER_OK;
    } else if (result == NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE) {
      return HEADER_RST_STREAM;
    } else {
      // Assume NGHTTP2_ERR_CALLBACK_FAILURE.
      return HEADER_CONNECTION_ERROR;
    }
  }
  return HEADER_OK;
}

bool CallbackVisitor::OnEndHeadersForStream(Http2StreamId stream_id) {
  QUICHE_VLOG(1) << "OnEndHeadersForStream(stream_id=" << stream_id << ")";
  if (callbacks_->on_frame_recv_callback) {
    const int result = callbacks_->on_frame_recv_callback(
        nullptr, &current_frame_, user_data_);
    return result == 0;
  }
  return true;
}

bool CallbackVisitor::OnDataPaddingLength(Http2StreamId /*stream_id*/,
                                          size_t padding_length) {
  current_frame_.data.padlen = padding_length;
  remaining_data_ -= padding_length;
  if (remaining_data_ == 0 &&
      (current_frame_.hd.flags & NGHTTP2_FLAG_END_STREAM) == 0 &&
      callbacks_->on_frame_recv_callback != nullptr) {
    const int result = callbacks_->on_frame_recv_callback(
        nullptr, &current_frame_, user_data_);
    return result == 0;
  }
  return true;
}

bool CallbackVisitor::OnBeginDataForStream(Http2StreamId /*stream_id*/,
                                           size_t payload_length) {
  remaining_data_ = payload_length;
  if (remaining_data_ == 0 &&
      (current_frame_.hd.flags & NGHTTP2_FLAG_END_STREAM) == 0 &&
      callbacks_->on_frame_recv_callback != nullptr) {
    const int result = callbacks_->on_frame_recv_callback(
        nullptr, &current_frame_, user_data_);
    return result == 0;
  }
  return true;
}

bool CallbackVisitor::OnDataForStream(Http2StreamId stream_id,
                                      absl::string_view data) {
  QUICHE_VLOG(1) << "OnDataForStream(stream_id=" << stream_id
                 << ", data.size()=" << data.size() << ")";
  int result = 0;
  if (callbacks_->on_data_chunk_recv_callback) {
    result = callbacks_->on_data_chunk_recv_callback(
        nullptr, current_frame_.hd.flags, stream_id, ToUint8Ptr(data.data()),
        data.size(), user_data_);
  }
  remaining_data_ -= data.size();
  if (result == 0 && remaining_data_ == 0 &&
      (current_frame_.hd.flags & NGHTTP2_FLAG_END_STREAM) == 0 &&
      callbacks_->on_frame_recv_callback) {
    // If the DATA frame contains the END_STREAM flag, `on_frame_recv` is
    // invoked later.
    result = callbacks_->on_frame_recv_callback(nullptr, &current_frame_,
                                                user_data_);
  }
  return result == 0;
}

bool CallbackVisitor::OnEndStream(Http2StreamId stream_id) {
  QUICHE_VLOG(1) << "OnEndStream(stream_id=" << stream_id << ")";
  int result = 0;
  if (static_cast<FrameType>(current_frame_.hd.type) == FrameType::DATA &&
      (current_frame_.hd.flags & NGHTTP2_FLAG_END_STREAM) != 0 &&
      callbacks_->on_frame_recv_callback) {
    // `on_frame_recv` is invoked here to ensure that the Http2Adapter
    // implementation has successfully validated and processed the entire DATA
    // frame.
    result = callbacks_->on_frame_recv_callback(nullptr, &current_frame_,
                                                user_data_);
  }
  return result == 0;
}

void CallbackVisitor::OnRstStream(Http2StreamId stream_id,
                                  Http2ErrorCode error_code) {
  QUICHE_VLOG(1) << "OnRstStream(stream_id=" << stream_id
                 << ", error_code=" << static_cast<int>(error_code) << ")";
  current_frame_.rst_stream.error_code = static_cast<uint32_t>(error_code);
  if (callbacks_->on_frame_recv_callback) {
    const int result = callbacks_->on_frame_recv_callback(
        nullptr, &current_frame_, user_data_);
    QUICHE_DCHECK_EQ(0, result);
  }
}

bool CallbackVisitor::OnCloseStream(Http2StreamId stream_id,
                                    Http2ErrorCode error_code) {
  QUICHE_VLOG(1) << "OnCloseStream(stream_id=" << stream_id
                 << ", error_code=" << static_cast<int>(error_code) << ")";
  int result = 0;
  if (callbacks_->on_stream_close_callback) {
    result = callbacks_->on_stream_close_callback(
        nullptr, stream_id, static_cast<uint32_t>(error_code), user_data_);
  }
  stream_map_.erase(stream_id);
  if (stream_close_listener_) {
    stream_close_listener_(stream_id);
  }
  return result == 0;
}

void CallbackVisitor::OnPriorityForStream(Http2StreamId /*stream_id*/,
                                          Http2StreamId parent_stream_id,
                                          int weight, bool exclusive) {
  current_frame_.priority.pri_spec.stream_id = parent_stream_id;
  current_frame_.priority.pri_spec.weight = weight;
  current_frame_.priority.pri_spec.exclusive = exclusive;
  if (callbacks_->on_frame_recv_callback) {
    const int result = callbacks_->on_frame_recv_callback(
        nullptr, &current_frame_, user_data_);
    QUICHE_DCHECK_EQ(0, result);
  }
}

void CallbackVisitor::OnPing(Http2PingId ping_id, bool is_ack) {
  QUICHE_VLOG(1) << "OnPing(ping_id=" << static_cast<int64_t>(ping_id)
                 << ", is_ack=" << is_ack << ")";
  uint64_t network_order_opaque_data =
      quiche::QuicheEndian::HostToNet64(ping_id);
  std::memcpy(current_frame_.ping.opaque_data, &network_order_opaque_data,
              sizeof(network_order_opaque_data));
  if (callbacks_->on_frame_recv_callback) {
    const int result = callbacks_->on_frame_recv_callback(
        nullptr, &current_frame_, user_data_);
    QUICHE_DCHECK_EQ(0, result);
  }
}

void CallbackVisitor::OnPushPromiseForStream(
    Http2StreamId /*stream_id*/, Http2StreamId /*promised_stream_id*/) {
  QUICHE_LOG(DFATAL) << "Not implemented";
}

bool CallbackVisitor::OnGoAway(Http2StreamId last_accepted_stream_id,
                               Http2ErrorCode error_code,
                               absl::string_view opaque_data) {
  QUICHE_VLOG(1) << "OnGoAway(last_accepted_stream_id="
                 << last_accepted_stream_id
                 << ", error_code=" << static_cast<int>(error_code)
                 << ", opaque_data=[" << absl::CEscape(opaque_data) << "])";
  current_frame_.goaway.last_stream_id = last_accepted_stream_id;
  current_frame_.goaway.error_code = static_cast<uint32_t>(error_code);
  current_frame_.goaway.opaque_data = ToUint8Ptr(opaque_data.data());
  current_frame_.goaway.opaque_data_len = opaque_data.size();
  if (callbacks_->on_frame_recv_callback) {
    const int result = callbacks_->on_frame_recv_callback(
        nullptr, &current_frame_, user_data_);
    return result == 0;
  }
  return true;
}

void CallbackVisitor::OnWindowUpdate(Http2StreamId stream_id,
                                     int window_increment) {
  QUICHE_VLOG(1) << "OnWindowUpdate(stream_id=" << stream_id
                 << ", delta=" << window_increment << ")";
  current_frame_.window_update.window_size_increment = window_increment;
  if (callbacks_->on_frame_recv_callback) {
    const int result = callbacks_->on_frame_recv_callback(
        nullptr, &current_frame_, user_data_);
    QUICHE_DCHECK_EQ(0, result);
  }
}

void CallbackVisitor::PopulateFrame(nghttp2_frame& frame, uint8_t frame_type,
                                    Http2StreamId stream_id, size_t length,
                                    uint8_t flags, uint32_t error_code,
                                    bool sent_headers) {
  frame.hd.type = frame_type;
  frame.hd.stream_id = stream_id;
  frame.hd.length = length;
  frame.hd.flags = flags;
  const FrameType frame_type_enum = static_cast<FrameType>(frame_type);
  if (frame_type_enum == FrameType::HEADERS) {
    if (sent_headers) {
      frame.headers.cat = NGHTTP2_HCAT_HEADERS;
    } else {
      switch (perspective_) {
        case Perspective::kClient:
          QUICHE_VLOG(1) << "First headers sent by the client for stream "
                         << stream_id << "; these are request headers";
          frame.headers.cat = NGHTTP2_HCAT_REQUEST;
          break;
        case Perspective::kServer:
          QUICHE_VLOG(1) << "First headers sent by the server for stream "
                         << stream_id << "; these are response headers";
          frame.headers.cat = NGHTTP2_HCAT_RESPONSE;
          break;
      }
    }
  } else if (frame_type_enum == FrameType::RST_STREAM) {
    frame.rst_stream.error_code = error_code;
  } else if (frame_type_enum == FrameType::GOAWAY) {
    frame.goaway.error_code = error_code;
  }
}

int CallbackVisitor::OnBeforeFrameSent(uint8_t frame_type,
                                       Http2StreamId stream_id, size_t length,
                                       uint8_t flags) {
  QUICHE_VLOG(1) << "OnBeforeFrameSent(stream_id=" << stream_id
                 << ", type=" << int(frame_type) << ", length=" << length
                 << ", flags=" << int(flags) << ")";
  if (callbacks_->before_frame_send_callback) {
    nghttp2_frame frame;
    bool before_sent_headers = true;
    auto it = GetStreamInfo(stream_id);
    if (it != stream_map_.end()) {
      before_sent_headers = it->second.before_sent_headers;
      it->second.before_sent_headers = true;
    }
    // The implementation of the before_frame_send_callback doesn't look at the
    // error code, so for now it's populated with 0.
    PopulateFrame(frame, frame_type, stream_id, length, flags, /*error_code=*/0,
                  before_sent_headers);
    return callbacks_->before_frame_send_callback(nullptr, &frame, user_data_);
  }
  return 0;
}

int CallbackVisitor::OnFrameSent(uint8_t frame_type, Http2StreamId stream_id,
                                 size_t length, uint8_t flags,
                                 uint32_t error_code) {
  QUICHE_VLOG(1) << "OnFrameSent(stream_id=" << stream_id
                 << ", type=" << int(frame_type) << ", length=" << length
                 << ", flags=" << int(flags) << ", error_code=" << error_code
                 << ")";
  if (callbacks_->on_frame_send_callback) {
    nghttp2_frame frame;
    bool sent_headers = true;
    auto it = GetStreamInfo(stream_id);
    if (it != stream_map_.end()) {
      sent_headers = it->second.sent_headers;
      it->second.sent_headers = true;
    }
    PopulateFrame(frame, frame_type, stream_id, length, flags, error_code,
                  sent_headers);
    return callbacks_->on_frame_send_callback(nullptr, &frame, user_data_);
  }
  return 0;
}

bool CallbackVisitor::OnInvalidFrame(Http2StreamId stream_id,
                                     InvalidFrameError error) {
  QUICHE_VLOG(1) << "OnInvalidFrame(" << stream_id << ", "
                 << InvalidFrameErrorToString(error) << ")";
  QUICHE_DCHECK_EQ(stream_id, current_frame_.hd.stream_id);
  if (callbacks_->on_invalid_frame_recv_callback) {
    return 0 ==
           callbacks_->on_invalid_frame_recv_callback(
               nullptr, &current_frame_, ToNgHttp2ErrorCode(error), user_data_);
  }
  return true;
}

void CallbackVisitor::OnBeginMetadataForStream(Http2StreamId stream_id,
                                               size_t payload_length) {
  QUICHE_VLOG(1) << "OnBeginMetadataForStream(stream_id=" << stream_id
                 << ", payload_length=" << payload_length << ")";
}

bool CallbackVisitor::OnMetadataForStream(Http2StreamId stream_id,
                                          absl::string_view metadata) {
  QUICHE_VLOG(1) << "OnMetadataForStream(stream_id=" << stream_id
                 << ", len=" << metadata.size() << ")";
  if (callbacks_->on_extension_chunk_recv_callback) {
    int result = callbacks_->on_extension_chunk_recv_callback(
        nullptr, &current_frame_.hd, ToUint8Ptr(metadata.data()),
        metadata.size(), user_data_);
    return result == 0;
  }
  return true;
}

bool CallbackVisitor::OnMetadataEndForStream(Http2StreamId stream_id) {
  if ((current_frame_.hd.flags & kMetadataEndFlag) == 0) {
    QUICHE_VLOG(1) << "Expected kMetadataEndFlag during call to "
                   << "OnMetadataEndForStream!";
    return true;
  }
  QUICHE_VLOG(1) << "OnMetadataEndForStream(stream_id=" << stream_id << ")";
  if (callbacks_->unpack_extension_callback) {
    void* payload;
    int result = callbacks_->unpack_extension_callback(
        nullptr, &payload, &current_frame_.hd, user_data_);
    if (result == 0 && callbacks_->on_frame_recv_callback) {
      current_frame_.ext.payload = payload;
      result = callbacks_->on_frame_recv_callback(nullptr, &current_frame_,
                                                  user_data_);
    }
    return (result == 0);
  }
  return true;
}

std::pair<int64_t, bool> CallbackVisitor::PackMetadataForStream(
    Http2StreamId /*stream_id*/, uint8_t* /*dest*/, size_t /*dest_len*/) {
  QUICHE_LOG(DFATAL) << "Unimplemented.";
  return {-1, false};
}

void CallbackVisitor::OnErrorDebug(absl::string_view message) {
  QUICHE_VLOG(1) << "OnErrorDebug(message=[" << absl::CEscape(message) << "])";
  if (callbacks_->error_callback2) {
    callbacks_->error_callback2(nullptr, -1, message.data(), message.size(),
                                user_data_);
  }
}

CallbackVisitor::StreamInfoMap::iterator CallbackVisitor::GetStreamInfo(
    Http2StreamId stream_id) {
  auto it = stream_map_.find(stream_id);
  if (it == stream_map_.end() && stream_id > stream_id_watermark_) {
    auto p = stream_map_.insert({stream_id, {}});
    it = p.first;
    stream_id_watermark_ = stream_id;
  }
  return it;
}

}  // namespace adapter
}  // namespace http2
```