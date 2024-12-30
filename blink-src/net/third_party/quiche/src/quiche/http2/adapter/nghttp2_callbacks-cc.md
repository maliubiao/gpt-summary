Response:
Let's break down the thought process for analyzing this C++ code and generating the response.

1. **Understand the Goal:** The core request is to analyze the provided C++ file (`nghttp2_callbacks.cc`) within the Chromium network stack. The analysis needs to cover its functionality, relationship to JavaScript, logical reasoning examples, common user errors, and debugging information.

2. **Initial Code Scan (Identify Key Components):**
   - **Includes:** Notice the inclusion of `nghttp2.h`, indicating interaction with the `nghttp2` library (a popular HTTP/2 library). Also, `quiche/` includes suggest this is part of the QUIC/HTTP/3 stack within Chromium, but the filename explicitly mentions HTTP/2. This means it's likely the HTTP/2 implementation used by QUIC or as a fallback. The presence of `Http2VisitorInterface` is crucial – this is the primary mechanism for communication between `nghttp2` and the higher-level Chromium HTTP/2 implementation.
   - **Namespace:**  `http2::adapter::callbacks` clarifies the purpose: adapting `nghttp2` callbacks for Chromium's HTTP/2 adapter.
   - **Callback Functions:** The file is filled with functions like `OnReadyToSend`, `OnBeginFrame`, `OnFrameReceived`, etc. These are clearly callbacks that `nghttp2` will invoke during its processing of HTTP/2 connections.
   - **`Http2VisitorInterface`:**  Almost every callback function receives a `user_data` pointer, which is immediately cast to `Http2VisitorInterface*`. This confirms the central role of this interface.

3. **Functional Analysis (Detailed Callback Examination):**
   - **For each callback function, ask:**
     - What event triggers this callback? (The name usually gives a hint: `OnBeginFrame` when a frame starts, `OnDataChunk` when data arrives, etc.)
     - What are the input parameters?  (Examine the function signature.)
     - What does the callback do? (Look at the code. Most callbacks call a corresponding method on the `Http2VisitorInterface`.)
     - What is the return value and its significance? (Return values often indicate success/failure or a desire to block.)
   - **Group callbacks by their purpose:**
     - **Sending Data:** `OnReadyToSend`
     - **Receiving Frames (General):** `OnBeginFrame`, `OnFrameReceived`, `OnInvalidFrameReceived`
     - **Receiving Headers:** `OnBeginHeaders`, `OnHeader`
     - **Receiving Data (Chunks):** `OnDataChunk`
     - **Stream Lifecycle:** `OnStreamClosed`
     - **Sending Frames:** `OnBeforeFrameSent`, `OnFrameSent`, `OnFrameNotSent`
     - **Errors:** `OnError`
     - **Extensions (Metadata):** `OnExtensionChunkReceived`, `OnPackExtensionCallback`, `OnUnpackExtensionCallback`
   - **Identify key data structures and their roles:**
     - `nghttp2_session`:  Represents the HTTP/2 session managed by the `nghttp2` library.
     - `nghttp2_frame`:  Represents an HTTP/2 frame.
     - `Http2VisitorInterface`: The abstraction layer that Chromium uses to interact with `nghttp2`.

4. **Relationship to JavaScript:**
   - **Indirect:** Recognize that this C++ code is part of the browser's network stack. JavaScript interacts with this stack through Web APIs (like `fetch` or `XMLHttpRequest`).
   - **Key connection:**  User actions in JavaScript trigger network requests. These requests eventually reach this C++ code for HTTP/2 handling.
   - **Examples:** Provide concrete examples of JavaScript code that would lead to these callbacks being invoked (e.g., `fetch('/data')`, `<img>` tags).
   - **Focus on the flow:** Explain how a JavaScript request translates into HTTP/2 frames and how these callbacks process those frames.

5. **Logical Reasoning (Hypothetical Input/Output):**
   - **Choose a common scenario:**  A simple GET request is a good starting point.
   - **Trace the execution:**  Imagine the sequence of callbacks that would be invoked for this request.
   - **Provide example inputs:**  Show what the parameters to the callbacks might look like.
   - **Predict the output/actions:** Describe what the callbacks would do (typically calling methods on the `Http2VisitorInterface`).
   - **Emphasize the interaction with `Http2VisitorInterface`:** Show how data is passed to the higher-level Chromium code.

6. **Common User/Programming Errors:**
   - **Think about the consequences of incorrect usage of the `Http2VisitorInterface`:**  This is the primary point of interaction.
   - **Focus on error handling:**  What happens if the visitor returns an error?  How might a developer misuse the visitor interface?
   - **Consider common HTTP/2 related errors:**  Header formatting, data size limits, stream management.
   - **Provide clear examples:** Illustrate these errors with concrete scenarios.

7. **Debugging Information (User Actions to Reach the Code):**
   - **Start with user actions:**  What does a user do that initiates a network request? (Typing a URL, clicking a link, JavaScript making a request).
   - **Trace the request through the browser:**  High-level steps:  URL parsing, DNS lookup, connection establishment (including TLS), HTTP/2 negotiation.
   - **Pinpoint where this code fits in:** After the HTTP/2 connection is established, this code handles the actual HTTP/2 frame processing.
   - **Suggest debugging techniques:** Browser developer tools (Network tab), logging (though this code already has some logging), and potentially more advanced debugging tools for Chromium development.

8. **Structure and Clarity:**
   - **Use headings and bullet points:** Organize the information logically and make it easy to read.
   - **Use clear and concise language:** Avoid jargon where possible, or explain it clearly.
   - **Provide code snippets:**  Illustrate JavaScript examples.
   - **Summarize key takeaways:** Reinforce the main points.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus heavily on `nghttp2` specifics.
* **Correction:** Shift focus to the *interaction* between `nghttp2` and Chromium via `Http2VisitorInterface`. The file's primary purpose is *adaptation*.
* **Initial thought:**  Deeply explain every `nghttp2` error code.
* **Correction:** Focus on the *categories* of errors and how the callbacks handle them, relating it back to the `Http2VisitorInterface` return values.
* **Initial thought:**  Overly technical explanation of frame structures.
* **Correction:** Explain frame types and their general purpose within the context of the callbacks.

By following these steps and iteratively refining the analysis, the comprehensive and helpful answer can be generated.
这个文件 `net/third_party/quiche/src/quiche/http2/adapter/nghttp2_callbacks.cc` 是 Chromium 网络栈中，用于将底层的 `nghttp2` 库的回调函数适配到 Chromium 更高层的 HTTP/2 适配器接口 `Http2VisitorInterface` 的关键部分。

**它的主要功能可以概括为：**

1. **作为 `nghttp2` 库和 Chromium HTTP/2 适配器之间的桥梁：**  `nghttp2` 库是一个高性能的 HTTP/2 协议实现，它通过一系列回调函数来通知上层关于 HTTP/2 连接状态和事件。这个文件中的函数实现了这些 `nghttp2` 的回调，并将这些事件转换为对 `Http2VisitorInterface` 接口方法的调用。

2. **处理 `nghttp2` 接收到的各种 HTTP/2 帧：**  文件中定义了针对不同 `nghttp2` 回调的函数，例如：
    * `OnReadyToSend`:  当 `nghttp2` 准备好发送数据时调用。
    * `OnBeginFrame`:  当开始接收一个新的 HTTP/2 帧时调用。
    * `OnFrameReceived`:  当一个完整的 HTTP/2 帧接收完成时调用。
    * `OnBeginHeaders`: 当开始接收 HTTP 头时调用。
    * `OnHeader`:  当接收到一个 HTTP 头时调用。
    * `OnDataChunk`:  当接收到数据帧的一部分数据时调用。
    * `OnStreamClosed`:  当一个 HTTP/2 流关闭时调用。
    * 等等。

3. **将 `nghttp2` 的事件通知转换为对 `Http2VisitorInterface` 的方法调用：**  每个回调函数的主要任务是从 `nghttp2` 的数据结构中提取信息，并调用 `Http2VisitorInterface` 上的相应方法，将事件通知给 Chromium 的 HTTP/2 适配器。例如，当接收到一个 `DATA` 帧时，`OnDataChunk` 会被调用，它会将接收到的数据传递给 `visitor->OnDataForStream()`。

4. **处理发送 HTTP/2 帧的事件：**
    * `OnBeforeFrameSent`: 在帧即将发送之前被调用。
    * `OnFrameSent`:  在帧成功发送之后被调用。
    * `OnFrameNotSent`: 在帧发送失败时被调用。

5. **处理错误和调试信息：**
    * `OnError`: 当 `nghttp2` 遇到错误时调用。
    * 文件中还包含了一些 `QUICHE_VLOG` 宏，用于输出详细的日志信息，方便调试。

6. **处理扩展帧 (例如 Metadata 帧)：**  文件中包含了处理自定义扩展帧类型的回调函数，例如 `OnExtensionChunkReceived`, `OnPackExtensionCallback`, `OnUnpackExtensionCallback`，这允许在 HTTP/2 的基础上添加自定义功能。

**与 JavaScript 功能的关系：**

该 C++ 文件本身并不直接包含 JavaScript 代码。然而，它在浏览器网络栈中扮演着至关重要的角色，直接影响着 JavaScript 中发起的网络请求的行为。

**举例说明：**

假设你在网页中有一个 JavaScript 的 `fetch` 请求：

```javascript
fetch('/api/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

当这个 `fetch` 请求被发送时，会经历以下步骤，最终会涉及到 `nghttp2_callbacks.cc` 中的代码：

1. **JavaScript 发起请求：**  JavaScript 的 `fetch` API 调用触发浏览器开始处理网络请求。
2. **浏览器网络栈处理：**  浏览器网络栈会解析 URL，查找域名对应的 IP 地址，建立 TCP 连接（如果是 HTTPS，还会建立 TLS 连接）。
3. **HTTP/2 协商：** 如果服务器支持 HTTP/2，浏览器和服务器会协商使用 HTTP/2 协议。
4. **构建 HTTP/2 帧：**  浏览器会将 `fetch` 请求转换为一个或多个 HTTP/2 帧，例如 `HEADERS` 帧（包含请求头）和可能的 `DATA` 帧（如果请求体有数据）。
5. **`nghttp2` 处理发送：**  Chromium 的 HTTP/2 适配器会使用 `nghttp2` 库来发送这些帧。在发送之前，`OnBeforeFrameSent` 回调函数会被调用。
6. **服务器响应：** 服务器接收到请求，处理后返回响应。
7. **`nghttp2` 处理接收：**  `nghttp2` 库接收到服务器返回的 HTTP/2 帧，例如 `HEADERS` 帧（包含响应头）和 `DATA` 帧（包含响应体）。
8. **`nghttp2` 回调触发：**  对于接收到的每个帧，`nghttp2` 库会调用相应的回调函数，例如：
    * `OnBeginFrame`：当开始接收响应的 `HEADERS` 帧或 `DATA` 帧时。
    * `OnBeginHeaders`：当开始接收响应头时。
    * `OnHeader`：对于每个接收到的响应头。
    * `OnDataChunk`：对于响应体中的每个数据块。
    * `OnFrameReceived`：当一个完整的帧接收完毕时。
9. **`nghttp2_callbacks.cc` 中的函数被调用：**  这些 `nghttp2` 回调函数在 `nghttp2_callbacks.cc` 中被实现。例如，当接收到响应头时，`OnHeader` 函数会被调用，它会将头信息传递给 `visitor->OnHeaderForStream()`。当接收到响应数据时，`OnDataChunk` 函数会被调用，它会将数据传递给 `visitor->OnDataForStream()`。
10. **`Http2VisitorInterface` 通知上层：**  `Http2VisitorInterface` 的实现会将接收到的头和数据传递给 Chromium 更高层的网络组件。
11. **响应传递给 JavaScript：**  最终，浏览器网络栈会将接收到的响应数据传递回 JavaScript 的 `fetch` API，触发 `.then(response => ...)` 中的代码执行。

**逻辑推理的举例说明：**

**假设输入：** `nghttp2` 库接收到一个 `DATA` 帧，该帧属于 stream ID 为 3 的 HTTP/2 流，包含 1024 字节的数据。

**对应的 `OnDataChunk` 回调的输入参数可能是：**

* `session`: 指向当前的 `nghttp2` 会话的指针。
* `flags`: 可能包含一些标志位，例如是否是流的结束帧。
* `stream_id`:  3
* `data`: 指向包含 1024 字节数据的缓冲区的指针。
* `len`: 1024
* `user_data`: 指向 `Http2VisitorInterface` 实例的指针。

**输出：**

`OnDataChunk` 函数会将这 1024 字节的数据传递给 `Http2VisitorInterface` 的 `OnDataForStream` 方法：

```c++
const bool result = visitor->OnDataForStream(
    stream_id, absl::string_view(reinterpret_cast<const char*>(data), len));
```

`Http2VisitorInterface` 的实现会进一步处理这些数据，例如将其添加到对应流的接收缓冲区中。

**涉及用户或编程常见的使用错误：**

1. **`Http2VisitorInterface` 实现不正确：**  `nghttp2_callbacks.cc` 依赖于 `Http2VisitorInterface` 的正确实现。如果 `Http2VisitorInterface` 的方法返回了错误的值，或者状态管理不当，可能会导致 HTTP/2 连接出现问题。例如，如果 `OnHeaderForStream` 返回指示需要重置流的错误码，`nghttp2` 会采取相应的行动。

   **举例：**  `Http2VisitorInterface` 的实现可能会错误地解析接收到的头字段，或者没有正确处理流的状态转换，导致连接异常断开。

2. **`nghttp2` 配置错误：**  虽然这个文件主要处理回调，但如果 `nghttp2` 会话本身的配置不正确（例如，设置了不合理的窗口大小），也可能导致问题。这通常不是直接在这个文件中体现，但会影响回调的触发和参数。

3. **资源管理问题：**  `Http2VisitorInterface` 的实现可能需要管理与 HTTP/2 流相关的资源。如果资源没有正确释放，可能会导致内存泄漏或其他资源耗尽问题。

4. **数据竞争和并发问题：**  HTTP/2 连接是并发的，涉及多个流的处理。如果 `Http2VisitorInterface` 的实现没有考虑线程安全，可能会出现数据竞争和未定义的行为。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入 URL 并按下回车，或者点击一个链接。**
2. **浏览器解析 URL，确定需要建立网络连接。**
3. **如果目标网站支持 HTTPS，浏览器会进行 TLS 握手。**
4. **在 TLS 握手过程中，如果双方都支持 HTTP/2，会通过 ALPN (Application-Layer Protocol Negotiation) 协商使用 HTTP/2 协议。**
5. **一旦 HTTP/2 连接建立，浏览器会构建 HTTP/2 帧来发送请求（例如 `HEADERS` 帧）。**
6. **Chromium 的 HTTP/2 适配器（它使用了 `nghttp2` 库）会将这些帧发送给服务器。**
7. **服务器接收到请求并处理，然后构建 HTTP/2 响应帧。**
8. **服务器将响应帧发送回浏览器。**
9. **浏览器的网络栈接收到这些 HTTP/2 帧。**
10. **`nghttp2` 库解析接收到的帧，并根据帧的类型调用相应的回调函数，这些回调函数就定义在 `nghttp2_callbacks.cc` 文件中。** 例如，接收到 `HEADERS` 帧会触发 `OnBeginHeaders` 和 `OnHeader` 回调，接收到 `DATA` 帧会触发 `OnDataChunk` 回调。

**作为调试线索：**

* **网络抓包：** 使用 Wireshark 或 Chrome 开发者工具的网络面板可以查看浏览器和服务器之间交互的 HTTP/2 帧，这可以帮助确定是哪个环节出了问题。
* **`QUICHE_VLOG` 日志：**  `nghttp2_callbacks.cc` 中使用了 `QUICHE_VLOG` 宏输出详细的日志信息。启用适当的日志级别可以查看回调函数的调用顺序、接收到的帧信息等，这对于理解 HTTP/2 的行为和定位问题非常有帮助。
* **断点调试：**  在 `nghttp2_callbacks.cc` 中的关键回调函数上设置断点，可以逐步跟踪代码的执行流程，查看 `nghttp2` 库传递给回调函数的参数，以及 `Http2VisitorInterface` 的行为。
* **检查 `Http2VisitorInterface` 的实现：**  如果怀疑是 Chromium 更高层处理 HTTP/2 事件的方式有问题，需要检查 `Http2VisitorInterface` 的具体实现代码。

总而言之，`net/third_party/quiche/src/quiche/http2/adapter/nghttp2_callbacks.cc` 文件是 Chromium 网络栈中 HTTP/2 功能实现的核心组成部分，它负责将底层的 `nghttp2` 库事件桥接到 Chromium 的抽象接口，使得 Chromium 的其他组件可以方便地处理 HTTP/2 通信。 用户的每一个网络请求，如果使用了 HTTP/2 协议，都会经过这里的代码。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/nghttp2_callbacks.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
#include "quiche/http2/adapter/nghttp2_callbacks.h"

#include <cstdint>
#include <cstring>
#include <utility>

#include "absl/strings/string_view.h"
#include "quiche/http2/adapter/data_source.h"
#include "quiche/http2/adapter/http2_protocol.h"
#include "quiche/http2/adapter/http2_visitor_interface.h"
#include "quiche/http2/adapter/nghttp2_data_provider.h"
#include "quiche/http2/adapter/nghttp2_util.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_endian.h"

namespace http2 {
namespace adapter {
namespace callbacks {

ssize_t OnReadyToSend(nghttp2_session* /* session */, const uint8_t* data,
                      size_t length, int flags, void* user_data) {
  QUICHE_CHECK_NE(user_data, nullptr);
  auto* visitor = static_cast<Http2VisitorInterface*>(user_data);
  const int64_t result = visitor->OnReadyToSend(ToStringView(data, length));
  QUICHE_VLOG(1) << "callbacks::OnReadyToSend(length=" << length
                 << ", flags=" << flags << ") returning " << result;
  if (result > 0) {
    return result;
  } else if (result == Http2VisitorInterface::kSendBlocked) {
    return -504;  // NGHTTP2_ERR_WOULDBLOCK
  } else {
    return -902;  // NGHTTP2_ERR_CALLBACK_FAILURE
  }
}

int OnBeginFrame(nghttp2_session* /* session */, const nghttp2_frame_hd* header,
                 void* user_data) {
  QUICHE_VLOG(1) << "callbacks::OnBeginFrame(stream_id=" << header->stream_id
                 << ", type=" << int(header->type)
                 << ", length=" << header->length
                 << ", flags=" << int(header->flags) << ")";
  QUICHE_CHECK_NE(user_data, nullptr);
  auto* visitor = static_cast<Http2VisitorInterface*>(user_data);
  bool result = visitor->OnFrameHeader(header->stream_id, header->length,
                                       header->type, header->flags);
  if (!result) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  if (header->type == NGHTTP2_DATA) {
    result = visitor->OnBeginDataForStream(header->stream_id, header->length);
  } else if (header->type == kMetadataFrameType) {
    visitor->OnBeginMetadataForStream(header->stream_id, header->length);
  }
  return result ? 0 : NGHTTP2_ERR_CALLBACK_FAILURE;
}

int OnFrameReceived(nghttp2_session* /* session */, const nghttp2_frame* frame,
                    void* user_data) {
  QUICHE_VLOG(1) << "callbacks::OnFrameReceived(stream_id="
                 << frame->hd.stream_id << ", type=" << int(frame->hd.type)
                 << ", length=" << frame->hd.length
                 << ", flags=" << int(frame->hd.flags) << ")";
  QUICHE_CHECK_NE(user_data, nullptr);
  auto* visitor = static_cast<Http2VisitorInterface*>(user_data);
  const Http2StreamId stream_id = frame->hd.stream_id;
  switch (frame->hd.type) {
    // The beginning of the DATA frame is handled in OnBeginFrame(), and the
    // beginning of the header block is handled in client/server-specific
    // callbacks. This callback handles the point at which the entire logical
    // frame has been received and processed.
    case NGHTTP2_DATA:
      if ((frame->hd.flags & NGHTTP2_FLAG_PADDED) != 0) {
        visitor->OnDataPaddingLength(stream_id, frame->data.padlen);
      }
      if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
        const bool result = visitor->OnEndStream(stream_id);
        if (!result) {
          return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
      }
      break;
    case NGHTTP2_HEADERS: {
      if (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) {
        const bool result = visitor->OnEndHeadersForStream(stream_id);
        if (!result) {
          return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
      }
      if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
        const bool result = visitor->OnEndStream(stream_id);
        if (!result) {
          return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
      }
      break;
    }
    case NGHTTP2_PRIORITY: {
      nghttp2_priority_spec priority_spec = frame->priority.pri_spec;
      visitor->OnPriorityForStream(stream_id, priority_spec.stream_id,
                                   priority_spec.weight,
                                   priority_spec.exclusive != 0);
      break;
    }
    case NGHTTP2_RST_STREAM: {
      visitor->OnRstStream(stream_id,
                           ToHttp2ErrorCode(frame->rst_stream.error_code));
      break;
    }
    case NGHTTP2_SETTINGS:
      if (frame->hd.flags & NGHTTP2_FLAG_ACK) {
        visitor->OnSettingsAck();
      } else {
        visitor->OnSettingsStart();
        for (size_t i = 0; i < frame->settings.niv; ++i) {
          nghttp2_settings_entry entry = frame->settings.iv[i];
          // The nghttp2_settings_entry uses int32_t for the ID; we must cast.
          visitor->OnSetting(Http2Setting{
              static_cast<Http2SettingsId>(entry.settings_id), entry.value});
        }
        visitor->OnSettingsEnd();
      }
      break;
    case NGHTTP2_PUSH_PROMISE:
      // This case is handled by headers-related callbacks:
      //   1. visitor->OnPushPromiseForStream() is invoked in the client-side
      //      OnHeadersStart() adapter callback, as nghttp2 only allows clients
      //      to receive PUSH_PROMISE frames.
      //   2. visitor->OnHeaderForStream() is invoked for each server push
      //      request header in the PUSH_PROMISE header block.
      //   3. This switch statement is reached once all server push request
      //      headers have been parsed.
      break;
    case NGHTTP2_PING: {
      Http2PingId ping_id;
      std::memcpy(&ping_id, frame->ping.opaque_data, sizeof(Http2PingId));
      visitor->OnPing(quiche::QuicheEndian::NetToHost64(ping_id),
                      (frame->hd.flags & NGHTTP2_FLAG_ACK) != 0);
      break;
    }
    case NGHTTP2_GOAWAY: {
      absl::string_view opaque_data(
          reinterpret_cast<const char*>(frame->goaway.opaque_data),
          frame->goaway.opaque_data_len);
      const bool result = visitor->OnGoAway(
          frame->goaway.last_stream_id,
          ToHttp2ErrorCode(frame->goaway.error_code), opaque_data);
      if (!result) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
      break;
    }
    case NGHTTP2_WINDOW_UPDATE: {
      visitor->OnWindowUpdate(stream_id,
                              frame->window_update.window_size_increment);
      break;
    }
    case NGHTTP2_CONTINUATION:
      // This frame type should not be passed to any callbacks, according to
      // https://nghttp2.org/documentation/enums.html#c.NGHTTP2_CONTINUATION.
      QUICHE_LOG(ERROR) << "Unexpected receipt of NGHTTP2_CONTINUATION type!";
      break;
    case NGHTTP2_ALTSVC:
      break;
    case NGHTTP2_ORIGIN:
      break;
  }

  return 0;
}

int OnBeginHeaders(nghttp2_session* /* session */, const nghttp2_frame* frame,
                   void* user_data) {
  QUICHE_VLOG(1) << "callbacks::OnBeginHeaders(stream_id="
                 << frame->hd.stream_id << ")";
  QUICHE_CHECK_NE(user_data, nullptr);
  auto* visitor = static_cast<Http2VisitorInterface*>(user_data);
  const bool result = visitor->OnBeginHeadersForStream(frame->hd.stream_id);
  return result ? 0 : NGHTTP2_ERR_CALLBACK_FAILURE;
}

int OnHeader(nghttp2_session* /* session */, const nghttp2_frame* frame,
             nghttp2_rcbuf* name, nghttp2_rcbuf* value, uint8_t /*flags*/,
             void* user_data) {
  QUICHE_VLOG(2) << "callbacks::OnHeader(stream_id=" << frame->hd.stream_id
                 << ", name=[" << absl::CEscape(ToStringView(name))
                 << "], value=[" << absl::CEscape(ToStringView(value)) << "])";
  QUICHE_CHECK_NE(user_data, nullptr);
  auto* visitor = static_cast<Http2VisitorInterface*>(user_data);
  const Http2VisitorInterface::OnHeaderResult result =
      visitor->OnHeaderForStream(frame->hd.stream_id, ToStringView(name),
                                 ToStringView(value));
  switch (result) {
    case Http2VisitorInterface::HEADER_OK:
      return 0;
    case Http2VisitorInterface::HEADER_CONNECTION_ERROR:
    case Http2VisitorInterface::HEADER_COMPRESSION_ERROR:
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    case Http2VisitorInterface::HEADER_RST_STREAM:
    case Http2VisitorInterface::HEADER_FIELD_INVALID:
    case Http2VisitorInterface::HEADER_HTTP_MESSAGING:
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }
  // Unexpected value.
  return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
}

int OnBeforeFrameSent(nghttp2_session* /* session */,
                      const nghttp2_frame* frame, void* user_data) {
  QUICHE_VLOG(1) << "callbacks::OnBeforeFrameSent(stream_id="
                 << frame->hd.stream_id << ", type=" << int(frame->hd.type)
                 << ", length=" << frame->hd.length
                 << ", flags=" << int(frame->hd.flags) << ")";
  QUICHE_CHECK_NE(user_data, nullptr);
  LogBeforeSend(*frame);
  auto* visitor = static_cast<Http2VisitorInterface*>(user_data);
  return visitor->OnBeforeFrameSent(frame->hd.type, frame->hd.stream_id,
                                    frame->hd.length, frame->hd.flags);
}

int OnFrameSent(nghttp2_session* /* session */, const nghttp2_frame* frame,
                void* user_data) {
  QUICHE_VLOG(1) << "callbacks::OnFrameSent(stream_id=" << frame->hd.stream_id
                 << ", type=" << int(frame->hd.type)
                 << ", length=" << frame->hd.length
                 << ", flags=" << int(frame->hd.flags) << ")";
  QUICHE_CHECK_NE(user_data, nullptr);
  auto* visitor = static_cast<Http2VisitorInterface*>(user_data);
  uint32_t error_code = 0;
  if (frame->hd.type == NGHTTP2_RST_STREAM) {
    error_code = frame->rst_stream.error_code;
  } else if (frame->hd.type == NGHTTP2_GOAWAY) {
    error_code = frame->goaway.error_code;
  }
  return visitor->OnFrameSent(frame->hd.type, frame->hd.stream_id,
                              frame->hd.length, frame->hd.flags, error_code);
}

int OnFrameNotSent(nghttp2_session* /* session */, const nghttp2_frame* frame,
                   int /* lib_error_code */, void* /* user_data */) {
  QUICHE_VLOG(1) << "callbacks::OnFrameNotSent(stream_id="
                 << frame->hd.stream_id << ", type=" << int(frame->hd.type)
                 << ", length=" << frame->hd.length
                 << ", flags=" << int(frame->hd.flags) << ")";
  if (frame->hd.type == kMetadataFrameType) {
    auto* source = static_cast<MetadataSource*>(frame->ext.payload);
    if (source == nullptr) {
      QUICHE_BUG(not_sent_payload_is_nullptr)
          << "Extension frame payload for stream " << frame->hd.stream_id
          << " is null!";
    } else {
      source->OnFailure();
    }
  }
  return 0;
}

int OnInvalidFrameReceived(nghttp2_session* /* session */,
                           const nghttp2_frame* frame, int lib_error_code,
                           void* user_data) {
  QUICHE_VLOG(1) << "callbacks::OnInvalidFrameReceived(stream_id="
                 << frame->hd.stream_id << ", InvalidFrameError="
                 << int(ToInvalidFrameError(lib_error_code)) << ")";
  QUICHE_CHECK_NE(user_data, nullptr);
  auto* visitor = static_cast<Http2VisitorInterface*>(user_data);
  const bool result = visitor->OnInvalidFrame(
      frame->hd.stream_id, ToInvalidFrameError(lib_error_code));
  return result ? 0 : NGHTTP2_ERR_CALLBACK_FAILURE;
}

int OnDataChunk(nghttp2_session* /* session */, uint8_t /*flags*/,
                Http2StreamId stream_id, const uint8_t* data, size_t len,
                void* user_data) {
  QUICHE_VLOG(1) << "callbacks::OnDataChunk(stream_id=" << stream_id
                 << ", length=" << len << ")";
  QUICHE_CHECK_NE(user_data, nullptr);
  auto* visitor = static_cast<Http2VisitorInterface*>(user_data);
  const bool result = visitor->OnDataForStream(
      stream_id, absl::string_view(reinterpret_cast<const char*>(data), len));
  return result ? 0 : NGHTTP2_ERR_CALLBACK_FAILURE;
}

int OnStreamClosed(nghttp2_session* /* session */, Http2StreamId stream_id,
                   uint32_t error_code, void* user_data) {
  QUICHE_VLOG(1) << "callbacks::OnStreamClosed(stream_id=" << stream_id
                 << ", error_code=" << error_code << ")";
  QUICHE_CHECK_NE(user_data, nullptr);
  auto* visitor = static_cast<Http2VisitorInterface*>(user_data);
  const bool result =
      visitor->OnCloseStream(stream_id, ToHttp2ErrorCode(error_code));
  return result ? 0 : NGHTTP2_ERR_CALLBACK_FAILURE;
}

int OnExtensionChunkReceived(nghttp2_session* /*session*/,
                             const nghttp2_frame_hd* hd, const uint8_t* data,
                             size_t len, void* user_data) {
  QUICHE_CHECK_NE(user_data, nullptr);
  auto* visitor = static_cast<Http2VisitorInterface*>(user_data);
  if (hd->type != kMetadataFrameType) {
    QUICHE_LOG(ERROR) << "Unexpected frame type: "
                      << static_cast<int>(hd->type);
    return NGHTTP2_ERR_CANCEL;
  }
  const bool result =
      visitor->OnMetadataForStream(hd->stream_id, ToStringView(data, len));
  return result ? 0 : NGHTTP2_ERR_CALLBACK_FAILURE;
}

int OnUnpackExtensionCallback(nghttp2_session* /*session*/, void** /*payload*/,
                              const nghttp2_frame_hd* hd, void* user_data) {
  QUICHE_CHECK_NE(user_data, nullptr);
  auto* visitor = static_cast<Http2VisitorInterface*>(user_data);
  if (hd->flags == kMetadataEndFlag) {
    const bool result = visitor->OnMetadataEndForStream(hd->stream_id);
    if (!result) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}

ssize_t OnPackExtensionCallback(nghttp2_session* /*session*/, uint8_t* buf,
                                size_t len, const nghttp2_frame* frame,
                                void* user_data) {
  QUICHE_CHECK_NE(user_data, nullptr);
  auto* source = static_cast<MetadataSource*>(frame->ext.payload);
  if (source == nullptr) {
    QUICHE_BUG(payload_is_nullptr) << "Extension frame payload for stream "
                                   << frame->hd.stream_id << " is null!";
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  const std::pair<int64_t, bool> result = source->Pack(buf, len);
  if (result.first < 0) {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  const bool end_metadata_flag = (frame->hd.flags & kMetadataEndFlag);
  QUICHE_LOG_IF(DFATAL, result.second != end_metadata_flag)
      << "Metadata ends: " << result.second
      << " has kMetadataEndFlag: " << end_metadata_flag;
  return result.first;
}

int OnError(nghttp2_session* /*session*/, int /*lib_error_code*/,
            const char* msg, size_t len, void* user_data) {
  QUICHE_VLOG(1) << "callbacks::OnError(" << absl::string_view(msg, len) << ")";
  QUICHE_CHECK_NE(user_data, nullptr);
  auto* visitor = static_cast<Http2VisitorInterface*>(user_data);
  visitor->OnErrorDebug(absl::string_view(msg, len));
  return 0;
}

nghttp2_session_callbacks_unique_ptr Create(
    nghttp2_send_data_callback send_data_callback) {
  nghttp2_session_callbacks* callbacks;
  nghttp2_session_callbacks_new(&callbacks);

  nghttp2_session_callbacks_set_send_callback(callbacks, &OnReadyToSend);
  nghttp2_session_callbacks_set_on_begin_frame_callback(callbacks,
                                                        &OnBeginFrame);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                       &OnFrameReceived);
  nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks,
                                                          &OnBeginHeaders);
  nghttp2_session_callbacks_set_on_header_callback2(callbacks, &OnHeader);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks,
                                                            &OnDataChunk);
  nghttp2_session_callbacks_set_on_stream_close_callback(callbacks,
                                                         &OnStreamClosed);
  nghttp2_session_callbacks_set_before_frame_send_callback(callbacks,
                                                           &OnBeforeFrameSent);
  nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, &OnFrameSent);
  nghttp2_session_callbacks_set_on_frame_not_send_callback(callbacks,
                                                           &OnFrameNotSent);
  nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(
      callbacks, &OnInvalidFrameReceived);
  nghttp2_session_callbacks_set_error_callback2(callbacks, &OnError);
  nghttp2_session_callbacks_set_send_data_callback(callbacks,
                                                   send_data_callback);
  nghttp2_session_callbacks_set_pack_extension_callback(
      callbacks, &OnPackExtensionCallback);
  nghttp2_session_callbacks_set_unpack_extension_callback(
      callbacks, &OnUnpackExtensionCallback);
  nghttp2_session_callbacks_set_on_extension_chunk_recv_callback(
      callbacks, &OnExtensionChunkReceived);
  return MakeCallbacksPtr(callbacks);
}

}  // namespace callbacks
}  // namespace adapter
}  // namespace http2

"""

```