Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt's questions.

**1. Understanding the Core Task:**

The primary goal is to understand the functionality of `nghttp2_adapter.cc` within the Chromium network stack. The file name and the `#include "quiche/http2/adapter/nghttp2_adapter.h"` immediately suggest that this code acts as a bridge or adapter between Chromium's internal HTTP/2 representation and the `nghttp2` library.

**2. Identifying Key Components and Concepts:**

* **`nghttp2` Library:**  Recognize this as a popular, high-performance HTTP/2 library. The adapter likely uses its API.
* **`Http2VisitorInterface`:** This is likely an interface defined within Chromium's network stack. The adapter probably uses this to notify Chromium about HTTP/2 events.
* **`NgHttp2Adapter` Class:** This is the central class in the file, performing the adaptation.
* **`Perspective` (Client/Server):**  HTTP/2 has client and server roles, so the adapter needs to handle both.
* **Callbacks:**  The `nghttp2` library uses callbacks to notify the application about events. The adapter needs to implement and manage these callbacks.
* **Data Handling:**  HTTP/2 involves sending and receiving data. Look for how the adapter manages data flow.
* **Metadata:** The code mentions "metadata frames," indicating support for HTTP/2 extensions like QPACK or similar mechanisms.
* **Settings, Priority, Ping, GoAway, Window Updates, RST_STREAM:** These are fundamental HTTP/2 concepts. The adapter should provide methods to handle them.
* **Streams:** HTTP/2 multiplexes multiple requests/responses over a single connection. Stream management is crucial.

**3. High-Level Functionality - The Adapter Pattern:**

The code implements the Adapter pattern. It takes the `nghttp2` library's API and presents a more Chromium-specific interface (`Http2VisitorInterface`). This decoupling is essential for maintaining modularity and allowing Chromium to potentially swap out the underlying HTTP/2 implementation.

**4. Detailed Code Analysis - Function by Function (Iterative Refinement):**

Go through the methods of the `NgHttp2Adapter` class and understand what each one does:

* **Constructors (`CreateClientAdapter`, `CreateServerAdapter`, `NgHttp2Adapter::NgHttp2Adapter`):** These initialize the `nghttp2` session in either client or server mode, and set up the callbacks. Notice the use of `nghttp2_option`.
* **`ProcessBytes`:** This is the core method for feeding incoming HTTP/2 data to the `nghttp2` library.
* **`Submit...` Methods (Settings, Priority, Ping, GoAway, WindowUpdate, Metadata, Request, Response, Trailer, RST):** These methods translate Chromium's high-level HTTP/2 actions into `nghttp2` API calls. Pay attention to the data structures used (e.g., `nghttp2_settings_entry`, `nghttp2_priority_spec`).
* **`Send`:**  This triggers `nghttp2` to send pending data.
* **`Get...WindowSize` Methods:** These retrieve flow control information from `nghttp2`.
* **`MarkDataConsumedForStream`:**  Used to update `nghttp2` about how much data has been processed.
* **`SetStreamUserData`, `GetStreamUserData`:**  Allows associating custom data with individual HTTP/2 streams.
* **`ResumeStream`:**  Handles flow control by telling `nghttp2` that a stream can resume sending data.
* **`FrameNotSent`:**  Handles cases where a frame wasn't sent successfully.
* **`RemoveStream`:**  Cleans up resources associated with a closed stream.
* **`DelegateReadCallback`, `DelegateSendCallback`:**  These are the crucial callbacks where the adapter interacts with Chromium's `Http2VisitorInterface` and manages `DataFrameSource`. Notice the difference in handling when a `DataFrameSource` exists versus when it doesn't.
* **Inner Classes (`NotifyingMetadataSource`, `NotifyingVisitorMetadataSource`):**  These classes manage the lifecycle of metadata transmission and ensure proper cleanup.

**5. Answering Specific Questions:**

* **Functionality:** Summarize the purpose of each key method and the overall role of the adapter.
* **Relationship with JavaScript:** Look for keywords or patterns that might relate to web browsers or JavaScript interaction. The adapter handles the underlying HTTP/2 protocol, which is used by JavaScript (e.g., `fetch` API) for network requests. The connection to JavaScript is *indirect*. Focus on how the adapter enables the network communication that JavaScript relies on.
* **Logical Reasoning (Input/Output):**  Choose a simple scenario like submitting a request. Identify the inputs (headers, data source) and the expected outputs (stream ID, potential calls to `Http2VisitorInterface`).
* **Common Usage Errors:** Think about common mistakes developers might make when using an HTTP/2 library. Examples include incorrect header formatting, flow control issues, or improper handling of asynchronous operations.
* **User Steps to Reach Here (Debugging):** Trace a typical network request initiated by a user in a web browser. Explain how the browser's network stack would eventually invoke this adapter.

**6. Refinement and Organization:**

Organize the findings into a clear and logical structure, addressing each part of the prompt. Use clear language and avoid overly technical jargon where possible. Provide concrete examples to illustrate the concepts.

**Self-Correction/Refinement During Analysis:**

* **Initial Thought:** "Maybe this directly handles JavaScript events."  **Correction:**  Realize that this is a lower-level C++ component. The interaction with JavaScript is through higher-level APIs.
* **Initial Thought:** "Just list all the methods." **Correction:** Group related methods by function (e.g., submission, flow control) for better clarity.
* **Initial Thought:** "Focus only on successful scenarios." **Correction:**  Consider error handling and potential issues (leading to the "common usage errors" section).
* **Initial Thought:** "The user directly interacts with this code." **Correction:** Understand that this is part of the *browser's* internal workings, and the user's interaction is much higher-level (e.g., clicking a link).

By following this structured approach, breaking down the problem, and iteratively refining the analysis, we can arrive at a comprehensive and accurate understanding of the `nghttp2_adapter.cc` file.
这个文件 `net/third_party/quiche/src/quiche/http2/adapter/nghttp2_adapter.cc` 是 Chromium 网络栈中 Quiche 库的一部分，它扮演着 **HTTP/2 协议适配器**的角色。 具体来说，它封装了底层的 `nghttp2` 库，并提供了一个 Chromium 网络栈更容易使用的接口 `Http2VisitorInterface`。

以下是 `nghttp2_adapter.cc` 的主要功能：

**1. 作为 `nghttp2` 库的包装器/适配器:**

* 它隐藏了 `nghttp2` 库的复杂性，为 Chromium 网络栈提供了一个更简洁、更符合其内部抽象的 API。
* 它负责将 Chromium 网络栈的 HTTP/2 事件和操作转换为 `nghttp2` 库的调用，反之亦然。

**2. HTTP/2 会话管理:**

* **创建和初始化 `nghttp2` 会话:**  它负责创建 `nghttp2` 的客户端或服务器会话，并配置相关的选项。
* **处理传入的 HTTP/2 数据:**  `ProcessBytes` 函数接收来自网络的原始字节流，并将其传递给 `nghttp2` 库进行解析和处理。
* **发送 HTTP/2 数据:**  各种 `Submit...` 函数用于构造和提交不同类型的 HTTP/2 帧（如 HEADERS, DATA, SETTINGS, PING 等），然后通过 `Send` 函数发送到网络。

**3. HTTP/2 帧的发送和接收:**

* **发送请求和响应头:** `SubmitRequest` 和 `SubmitResponse` 函数用于发送 HTTP 请求和响应的头部信息。
* **发送请求和响应数据:** 通过 `DataFrameSource` 接口来管理要发送的数据，并使用 `DataFrameReadCallback` 回调从数据源读取数据。
* **接收请求和响应数据:** 通过 `Http2VisitorInterface` 通知上层接收到的数据。
* **发送和接收尾部（Trailers）:**  `SubmitTrailer` 函数用于发送 HTTP 尾部。
* **处理其他 HTTP/2 控制帧:** 例如 SETTINGS, PING, GOAWAY, WINDOW_UPDATE, RST_STREAM 等。

**4. 流管理:**

* **创建和管理 HTTP/2 流:**  `SubmitRequest` 会创建一个新的 HTTP/2 流。
* **设置和获取流的用户数据:** 允许将自定义数据与特定的 HTTP/2 流关联起来。
* **重置流:** `SubmitRst` 函数用于发送 RST_STREAM 帧来终止一个流。
* **流的优先级控制:** `SubmitPriorityForStream` 函数用于设置流的优先级。

**5. 流控制:**

* **管理发送窗口大小:**  `GetSendWindowSize` 和 `GetStreamSendWindowSize` 函数获取发送窗口大小。
* **管理接收窗口大小:** `GetReceiveWindowSize` 和 `GetStreamReceiveWindowSize` 函数获取接收窗口大小。
* **更新窗口:** `SubmitWindowUpdate` 函数用于发送 WINDOW_UPDATE 帧来增加对端的窗口大小。
* **标记数据已被消费:** `MarkDataConsumedForStream` 函数通知 `nghttp2` 接收到的数据已被处理。

**6. HPACK (头部压缩):**

* **获取 HPACK 动态表大小:**  `GetHpackEncoderDynamicTableSize` 和 `GetHpackDecoderDynamicTableSize` 函数获取 HPACK 编解码器动态表的大小。

**7. Metadata 扩展 (例如 QPACK):**

* **提交元数据帧:** `SubmitMetadata` 函数用于发送自定义的元数据帧，这通常用于像 QPACK 这样的头部压缩机制。

**与 JavaScript 的关系：**

`nghttp2_adapter.cc` 本身 **不直接与 JavaScript 代码交互**。 它位于 Chromium 网络栈的更底层，负责处理 HTTP/2 协议的细节。 然而，它对 JavaScript 的功能至关重要，因为：

* **JavaScript 的网络请求依赖于 HTTP/2:** 当浏览器中的 JavaScript 代码通过 `fetch` API 或 `XMLHttpRequest` 发起网络请求时，如果协商成功使用了 HTTP/2 协议，那么这些请求最终会通过 Chromium 的网络栈，并由 `nghttp2_adapter.cc` 处理。
* **性能提升:**  HTTP/2 的特性（如多路复用、头部压缩等）可以显著提升网页加载速度和网络性能，而 `nghttp2_adapter.cc` 是实现这些特性的关键组件。

**举例说明 JavaScript 的关系：**

假设用户在浏览器中访问一个支持 HTTP/2 的网站。

1. **JavaScript 发起请求:** 网页上的 JavaScript 代码使用 `fetch('/api/data')` 发起一个 GET 请求。
2. **浏览器网络栈处理:** 浏览器网络栈会识别出这是一个 HTTP 请求，并尝试建立或复用一个到该网站的 HTTP/2 连接。
3. **`nghttp2_adapter.cc` 参与请求发送:** `nghttp2_adapter.cc` 会将 JavaScript 发起的请求转换为一个 HTTP/2 HEADERS 帧，并通过底层的网络连接发送出去。
4. **服务器响应:** 服务器返回一个 HTTP/2 响应，包含响应头和数据。
5. **`nghttp2_adapter.cc` 参与响应接收:**  `nghttp2_adapter.cc` 接收并解析服务器的响应帧，然后通过 `Http2VisitorInterface` 将响应头和数据传递给 Chromium 网络栈的上层。
6. **JavaScript 接收响应:**  Chromium 网络栈最终会将响应数据传递回 JavaScript 代码，`fetch` API 的 Promise 会 resolve，JavaScript 代码可以处理来自服务器的数据。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* **场景:** 客户端向服务器发送一个简单的 GET 请求。
* **输入数据:**  `ProcessBytes` 接收到来自网络的字节流，这些字节流构成了服务器发送的 HTTP/2 HEADERS 帧，其中包含 HTTP 状态码 200 和一些响应头（例如 `Content-Type: application/json`）。

**输出:**

* `nghttp2_adapter.cc` 会解析接收到的字节流。
* 它会调用 `Http2VisitorInterface` 的相应方法（例如 `OnHeaders` 或类似的方法），将流 ID、HTTP 状态码 (200) 和响应头信息传递给上层。
* 如果 HEADERS 帧标记了流的结束，还会调用 `OnEndStream`。

**假设输入:**

* **场景:** 客户端要发送一个带有少量数据的 POST 请求。
* **输入:** `SubmitRequest` 被调用，传入了请求头信息和一个实现了 `DataFrameSource` 接口的对象，该对象提供了要发送的 POST 数据。

**输出:**

* `nghttp2_adapter.cc` 会创建一个 HTTP/2 HEADERS 帧包含请求头并发送出去。
* 接着，它会使用 `DataFrameReadCallback` 从 `DataFrameSource` 中读取数据，并创建并发送一个或多个 HTTP/2 DATA 帧。
* 如果请求数据发送完毕，还会发送一个带有 END_STREAM 标志的帧。

**用户或编程常见的使用错误:**

1. **不正确的头部格式:**  传递给 `SubmitRequest` 或 `SubmitResponse` 的头部信息格式不正确，可能导致 `nghttp2` 库解析错误。
   * **例子:**  忘记在头部名称和值之间添加冒号和空格 (e.g., 应该使用 `"Content-Type: application/json"`, 而不是 `"Content-Typeapplication/json"`)。
2. **流量控制问题:**  在发送大量数据时，没有正确处理流量控制，导致发送缓冲区溢出或对端无法及时接收数据。
   * **例子:**  在 `DataFrameSource` 的 `Read` 方法中，返回了超过对端允许接收的数据量，或者没有根据对端的窗口更新来控制发送速率。
3. **错误地调用 `SubmitResponse`:** 在服务器端，尝试在没有接收到完整请求头部之前就发送响应。
4. **并发问题:**  在多线程环境下，不正确地使用 `NgHttp2Adapter` 的方法，可能导致 `nghttp2` 库的状态不一致。
5. **资源泄漏:**  没有正确管理与流相关的资源，例如 `DataFrameSource` 对象，可能导致内存泄漏。
6. **对已关闭的流进行操作:**  尝试对已经发送了 RST_STREAM 或接收到带有 END_STREAM 标志的流进行操作。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在 Chrome 浏览器中访问 `https://example.com/data`。

1. **用户在地址栏输入 URL 或点击链接:** 用户发起了一个导航操作。
2. **浏览器解析 URL:** 浏览器解析输入的 URL。
3. **DNS 查询:** 浏览器进行 DNS 查询，获取 `example.com` 的 IP 地址。
4. **建立 TCP 连接:** 浏览器与 `example.com` 的服务器建立 TCP 连接。
5. **TLS 握手:**  如果使用 HTTPS，浏览器会与服务器进行 TLS 握手，协商加密参数。
6. **HTTP/2 协商 (ALPN):** 在 TLS 握手期间，浏览器和服务器会通过 ALPN (Application-Layer Protocol Negotiation) 协商使用 HTTP/2 协议。
7. **发送 HTTP 请求 (由 JavaScript 或浏览器引擎发起):**
   * 如果是页面加载，浏览器引擎会构造一个 GET 请求。
   * 如果是 JavaScript 代码通过 `fetch` 发起请求，JavaScript 引擎会调用相应的网络 API。
8. **请求传递到 Chromium 网络栈:** 请求会传递到 Chromium 的网络栈中进行处理.
9. **`NgHttp2Stream` 或类似对象创建:** Chromium 网络栈会创建一个代表该 HTTP/2 流的对象 (例如 `NgHttp2Stream`)。
10. **调用 `NgHttp2Adapter` 的方法:** `NgHttp2Stream` 或其上层模块会调用 `NgHttp2Adapter` 的 `SubmitRequest` 方法，将请求头信息传递给 `nghttp2_adapter.cc`。
11. **`nghttp2_adapter.cc` 调用 `nghttp2` 库:** `nghttp2_adapter.cc` 会将请求头信息转换为 `nghttp2` 库可以理解的数据结构，并调用 `nghttp2_submit_request` 等函数。
12. **`nghttp2` 库生成 HTTP/2 帧:** `nghttp2` 库会生成对应的 HTTP/2 HEADERS 帧。
13. **调用 `DataFrameSendCallback`:** 如果请求包含数据，会调用 `DataFrameSendCallback` 来获取要发送的数据。
14. **数据发送到网络:** 生成的 HTTP/2 帧通过底层的网络连接发送到服务器。
15. **服务器响应到达:** 服务器发送的 HTTP/2 响应数据到达客户端。
16. **`ProcessBytes` 接收数据:**  Chromium 网络栈接收到来自网络的字节流，并调用 `NgHttp2Adapter` 的 `ProcessBytes` 方法。
17. **`nghttp2` 库解析响应:** `nghttp2` 库解析接收到的 HTTP/2 帧。
18. **调用 `Http2VisitorInterface` 的回调:** `nghttp2_adapter.cc` 会根据解析出的帧类型，调用 `Http2VisitorInterface` 的相应回调函数 (例如 `OnHeaders`, `OnData`, `OnEndStream`)，将响应信息传递给上层。
19. **响应传递回 JavaScript 或浏览器引擎:**  Chromium 网络栈将响应数据传递回发起请求的 JavaScript 代码或浏览器引擎。
20. **网页渲染或 JavaScript 处理响应:**  浏览器引擎渲染网页，或者 JavaScript 代码处理接收到的数据。

在调试过程中，如果怀疑 HTTP/2 的行为有问题，可以设置断点在 `nghttp2_adapter.cc` 的关键函数 (如 `ProcessBytes`, `SubmitRequest`, `SubmitResponse`, `DataFrameReadCallback`, `DataFrameSendCallback`) 中，来观察 HTTP/2 帧的发送和接收过程，以及数据是如何在 `nghttp2` 库和 Chromium 网络栈之间流动的。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/nghttp2_adapter.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
#include "quiche/http2/adapter/nghttp2_adapter.h"

#include <cstring>
#include <iterator>
#include <memory>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/http2/adapter/http2_visitor_interface.h"
#include "quiche/http2/adapter/nghttp2.h"
#include "quiche/http2/adapter/nghttp2_callbacks.h"
#include "quiche/http2/adapter/nghttp2_data_provider.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_endian.h"

namespace http2 {
namespace adapter {

namespace {

using ConnectionError = Http2VisitorInterface::ConnectionError;

const size_t kFrameHeaderSize = 9;

// A nghttp2-style `nghttp2_data_source_read_callback`.
ssize_t DataFrameReadCallback(nghttp2_session* /* session */, int32_t stream_id,
                              uint8_t* /* buf */, size_t length,
                              uint32_t* data_flags, nghttp2_data_source* source,
                              void* /* user_data */) {
  NgHttp2Adapter* adapter = reinterpret_cast<NgHttp2Adapter*>(source->ptr);
  return adapter->DelegateReadCallback(stream_id, length, data_flags);
}

// A nghttp2-style `nghttp2_send_data_callback`.
int DataFrameSendCallback(nghttp2_session* /* session */, nghttp2_frame* frame,
                          const uint8_t* framehd, size_t length,
                          nghttp2_data_source* source, void* /* user_data */) {
  NgHttp2Adapter* adapter = reinterpret_cast<NgHttp2Adapter*>(source->ptr);
  return adapter->DelegateSendCallback(frame->hd.stream_id, framehd, length);
}

}  // anonymous namespace

// A metadata source that notifies the owning NgHttp2Adapter upon completion or
// failure.
class NgHttp2Adapter::NotifyingMetadataSource : public MetadataSource {
 public:
  explicit NotifyingMetadataSource(NgHttp2Adapter* adapter,
                                   Http2StreamId stream_id,
                                   std::unique_ptr<MetadataSource> source)
      : adapter_(adapter), stream_id_(stream_id), source_(std::move(source)) {}

  size_t NumFrames(size_t max_frame_size) const override {
    return source_->NumFrames(max_frame_size);
  }

  std::pair<int64_t, bool> Pack(uint8_t* dest, size_t dest_len) override {
    const auto result = source_->Pack(dest, dest_len);
    if (result.first < 0 || result.second) {
      adapter_->RemovePendingMetadata(stream_id_);
    }
    return result;
  }

  void OnFailure() override {
    source_->OnFailure();
    adapter_->RemovePendingMetadata(stream_id_);
  }

 private:
  NgHttp2Adapter* const adapter_;
  const Http2StreamId stream_id_;
  std::unique_ptr<MetadataSource> source_;
};

// A metadata source that notifies the owning NgHttp2Adapter upon completion or
// failure.
class NgHttp2Adapter::NotifyingVisitorMetadataSource : public MetadataSource {
 public:
  explicit NotifyingVisitorMetadataSource(NgHttp2Adapter* adapter,
                                          Http2StreamId stream_id,
                                          Http2VisitorInterface& visitor)
      : adapter_(adapter), stream_id_(stream_id), visitor_(visitor) {}

  size_t NumFrames(size_t /*max_frame_size*/) const override {
    QUICHE_LOG(DFATAL) << "Should not be invoked.";
    return 0;
  }

  std::pair<int64_t, bool> Pack(uint8_t* dest, size_t dest_len) override {
    const auto [packed, end_metadata] =
        visitor_.PackMetadataForStream(stream_id_, dest, dest_len);
    if (packed < 0 || end_metadata) {
      adapter_->RemovePendingMetadata(stream_id_);
    }
    return {packed, end_metadata};
  }

  void OnFailure() override { adapter_->RemovePendingMetadata(stream_id_); }

 private:
  NgHttp2Adapter* const adapter_;
  const Http2StreamId stream_id_;
  Http2VisitorInterface& visitor_;
};

/* static */
std::unique_ptr<NgHttp2Adapter> NgHttp2Adapter::CreateClientAdapter(
    Http2VisitorInterface& visitor, const nghttp2_option* options) {
  auto adapter = new NgHttp2Adapter(visitor, Perspective::kClient, options);
  adapter->Initialize();
  return absl::WrapUnique(adapter);
}

/* static */
std::unique_ptr<NgHttp2Adapter> NgHttp2Adapter::CreateServerAdapter(
    Http2VisitorInterface& visitor, const nghttp2_option* options) {
  auto adapter = new NgHttp2Adapter(visitor, Perspective::kServer, options);
  adapter->Initialize();
  return absl::WrapUnique(adapter);
}

bool NgHttp2Adapter::IsServerSession() const {
  int result = nghttp2_session_check_server_session(session_->raw_ptr());
  QUICHE_DCHECK_EQ(perspective_ == Perspective::kServer, result > 0);
  return result > 0;
}

int64_t NgHttp2Adapter::ProcessBytes(absl::string_view bytes) {
  const int64_t processed_bytes = session_->ProcessBytes(bytes);
  if (processed_bytes < 0) {
    visitor_.OnConnectionError(ConnectionError::kParseError);
  }
  return processed_bytes;
}

void NgHttp2Adapter::SubmitSettings(absl::Span<const Http2Setting> settings) {
  // Submit SETTINGS, converting each Http2Setting to an nghttp2_settings_entry.
  std::vector<nghttp2_settings_entry> nghttp2_settings;
  absl::c_transform(settings, std::back_inserter(nghttp2_settings),
                    [](const Http2Setting& setting) {
                      return nghttp2_settings_entry{setting.id, setting.value};
                    });
  nghttp2_submit_settings(session_->raw_ptr(), NGHTTP2_FLAG_NONE,
                          nghttp2_settings.data(), nghttp2_settings.size());
}

void NgHttp2Adapter::SubmitPriorityForStream(Http2StreamId stream_id,
                                             Http2StreamId parent_stream_id,
                                             int weight, bool exclusive) {
  nghttp2_priority_spec priority_spec;
  nghttp2_priority_spec_init(&priority_spec, parent_stream_id, weight,
                             static_cast<int>(exclusive));
  nghttp2_submit_priority(session_->raw_ptr(), NGHTTP2_FLAG_NONE, stream_id,
                          &priority_spec);
}

void NgHttp2Adapter::SubmitPing(Http2PingId ping_id) {
  uint8_t opaque_data[8] = {};
  Http2PingId ping_id_to_serialize = quiche::QuicheEndian::HostToNet64(ping_id);
  std::memcpy(opaque_data, &ping_id_to_serialize, sizeof(Http2PingId));
  nghttp2_submit_ping(session_->raw_ptr(), NGHTTP2_FLAG_NONE, opaque_data);
}

void NgHttp2Adapter::SubmitShutdownNotice() {
  nghttp2_submit_shutdown_notice(session_->raw_ptr());
}

void NgHttp2Adapter::SubmitGoAway(Http2StreamId last_accepted_stream_id,
                                  Http2ErrorCode error_code,
                                  absl::string_view opaque_data) {
  nghttp2_submit_goaway(session_->raw_ptr(), NGHTTP2_FLAG_NONE,
                        last_accepted_stream_id,
                        static_cast<uint32_t>(error_code),
                        ToUint8Ptr(opaque_data.data()), opaque_data.size());
}

void NgHttp2Adapter::SubmitWindowUpdate(Http2StreamId stream_id,
                                        int window_increment) {
  nghttp2_submit_window_update(session_->raw_ptr(), NGHTTP2_FLAG_NONE,
                               stream_id, window_increment);
}

void NgHttp2Adapter::SubmitMetadata(Http2StreamId stream_id,
                                    size_t max_frame_size,
                                    std::unique_ptr<MetadataSource> source) {
  auto wrapped_source = std::make_unique<NotifyingMetadataSource>(
      this, stream_id, std::move(source));
  const size_t num_frames = wrapped_source->NumFrames(max_frame_size);
  size_t num_successes = 0;
  for (size_t i = 1; i <= num_frames; ++i) {
    const int result =
        nghttp2_submit_extension(session_->raw_ptr(), kMetadataFrameType,
                                 i == num_frames ? kMetadataEndFlag : 0,
                                 stream_id, wrapped_source.get());
    if (result != 0) {
      QUICHE_LOG(DFATAL) << "Failed to submit extension frame " << i << " of "
                         << num_frames;
      break;
    }
    ++num_successes;
  }
  if (num_successes > 0) {
    // Finds the MetadataSourceVec for `stream_id` or inserts a new one if not
    // present.
    auto [it, _] = stream_metadata_.insert({stream_id, MetadataSourceVec{}});
    it->second.push_back(std::move(wrapped_source));
  }
}

void NgHttp2Adapter::SubmitMetadata(Http2StreamId stream_id,
                                    size_t num_frames) {
  auto wrapped_source = std::make_unique<NotifyingVisitorMetadataSource>(
      this, stream_id, visitor_);
  size_t num_successes = 0;
  for (size_t i = 1; i <= num_frames; ++i) {
    const int result =
        nghttp2_submit_extension(session_->raw_ptr(), kMetadataFrameType,
                                 i == num_frames ? kMetadataEndFlag : 0,
                                 stream_id, wrapped_source.get());
    if (result != 0) {
      QUICHE_LOG(DFATAL) << "Failed to submit extension frame " << i << " of "
                         << num_frames;
      break;
    }
    ++num_successes;
  }
  if (num_successes > 0) {
    // Finds the MetadataSourceVec for `stream_id` or inserts a new one if not
    // present.
    auto [it, _] = stream_metadata_.insert({stream_id, MetadataSourceVec{}});
    it->second.push_back(std::move(wrapped_source));
  }
}

int NgHttp2Adapter::Send() {
  const int result = nghttp2_session_send(session_->raw_ptr());
  if (result != 0) {
    QUICHE_VLOG(1) << "nghttp2_session_send returned " << result;
    visitor_.OnConnectionError(ConnectionError::kSendError);
  }
  return result;
}

int NgHttp2Adapter::GetSendWindowSize() const {
  return session_->GetRemoteWindowSize();
}

int NgHttp2Adapter::GetStreamSendWindowSize(Http2StreamId stream_id) const {
  return nghttp2_session_get_stream_remote_window_size(session_->raw_ptr(),
                                                       stream_id);
}

int NgHttp2Adapter::GetStreamReceiveWindowLimit(Http2StreamId stream_id) const {
  return nghttp2_session_get_stream_effective_local_window_size(
      session_->raw_ptr(), stream_id);
}

int NgHttp2Adapter::GetStreamReceiveWindowSize(Http2StreamId stream_id) const {
  return nghttp2_session_get_stream_local_window_size(session_->raw_ptr(),
                                                      stream_id);
}

int NgHttp2Adapter::GetReceiveWindowSize() const {
  return nghttp2_session_get_local_window_size(session_->raw_ptr());
}

int NgHttp2Adapter::GetHpackEncoderDynamicTableSize() const {
  return nghttp2_session_get_hd_deflate_dynamic_table_size(session_->raw_ptr());
}

int NgHttp2Adapter::GetHpackDecoderDynamicTableSize() const {
  return nghttp2_session_get_hd_inflate_dynamic_table_size(session_->raw_ptr());
}

Http2StreamId NgHttp2Adapter::GetHighestReceivedStreamId() const {
  return nghttp2_session_get_last_proc_stream_id(session_->raw_ptr());
}

void NgHttp2Adapter::MarkDataConsumedForStream(Http2StreamId stream_id,
                                               size_t num_bytes) {
  int rc = session_->Consume(stream_id, num_bytes);
  if (rc != 0) {
    QUICHE_LOG(ERROR) << "Error " << rc << " marking " << num_bytes
                      << " bytes consumed for stream " << stream_id;
  }
}

void NgHttp2Adapter::SubmitRst(Http2StreamId stream_id,
                               Http2ErrorCode error_code) {
  int status =
      nghttp2_submit_rst_stream(session_->raw_ptr(), NGHTTP2_FLAG_NONE,
                                stream_id, static_cast<uint32_t>(error_code));
  if (status < 0) {
    QUICHE_LOG(WARNING) << "Reset stream failed: " << stream_id
                        << " with status code " << status;
  }
}

int32_t NgHttp2Adapter::SubmitRequest(
    absl::Span<const Header> headers,
    std::unique_ptr<DataFrameSource> data_source, bool end_stream,
    void* stream_user_data) {
  auto nvs = GetNghttp2Nvs(headers);
  std::unique_ptr<nghttp2_data_provider> provider;

  if (data_source != nullptr || !end_stream) {
    provider = std::make_unique<nghttp2_data_provider>();
    provider->source.ptr = this;
    provider->read_callback = &DataFrameReadCallback;
  }

  int32_t stream_id =
      nghttp2_submit_request(session_->raw_ptr(), nullptr, nvs.data(),
                             nvs.size(), provider.get(), stream_user_data);
  if (data_source != nullptr) {
    sources_.emplace(stream_id, std::move(data_source));
  }
  QUICHE_VLOG(1) << "Submitted request with " << nvs.size()
                 << " request headers and user data " << stream_user_data
                 << "; resulted in stream " << stream_id;
  return stream_id;
}

int NgHttp2Adapter::SubmitResponse(Http2StreamId stream_id,
                                   absl::Span<const Header> headers,
                                   std::unique_ptr<DataFrameSource> data_source,
                                   bool end_stream) {
  auto nvs = GetNghttp2Nvs(headers);
  std::unique_ptr<nghttp2_data_provider> provider;
  if (data_source != nullptr || !end_stream) {
    provider = std::make_unique<nghttp2_data_provider>();
    provider->source.ptr = this;
    provider->read_callback = &DataFrameReadCallback;
  }
  if (data_source != nullptr) {
    sources_.emplace(stream_id, std::move(data_source));
  }

  int result = nghttp2_submit_response(session_->raw_ptr(), stream_id,
                                       nvs.data(), nvs.size(), provider.get());
  QUICHE_VLOG(1) << "Submitted response with " << nvs.size()
                 << " response headers; result = " << result;
  return result;
}

int NgHttp2Adapter::SubmitTrailer(Http2StreamId stream_id,
                                  absl::Span<const Header> trailers) {
  auto nvs = GetNghttp2Nvs(trailers);
  int result = nghttp2_submit_trailer(session_->raw_ptr(), stream_id,
                                      nvs.data(), nvs.size());
  QUICHE_VLOG(1) << "Submitted trailers with " << nvs.size()
                 << " response trailers; result = " << result;
  return result;
}

void NgHttp2Adapter::SetStreamUserData(Http2StreamId stream_id,
                                       void* stream_user_data) {
  nghttp2_session_set_stream_user_data(session_->raw_ptr(), stream_id,
                                       stream_user_data);
}

void* NgHttp2Adapter::GetStreamUserData(Http2StreamId stream_id) {
  return nghttp2_session_get_stream_user_data(session_->raw_ptr(), stream_id);
}

bool NgHttp2Adapter::ResumeStream(Http2StreamId stream_id) {
  return 0 == nghttp2_session_resume_data(session_->raw_ptr(), stream_id);
}

void NgHttp2Adapter::FrameNotSent(Http2StreamId stream_id, uint8_t frame_type) {
  if (frame_type == kMetadataFrameType) {
    RemovePendingMetadata(stream_id);
  }
}

void NgHttp2Adapter::RemoveStream(Http2StreamId stream_id) {
  sources_.erase(stream_id);
}

ssize_t NgHttp2Adapter::DelegateReadCallback(int32_t stream_id,
                                             size_t max_length,
                                             uint32_t* data_flags) {
  auto it = sources_.find(stream_id);
  if (it == sources_.end()) {
    // A DataFrameSource is not available for this stream; forward to the
    // visitor.
    return callbacks::VisitorReadCallback(visitor_, stream_id, max_length,
                                          data_flags);
  } else {
    // A DataFrameSource is available for this stream.
    return callbacks::DataFrameSourceReadCallback(*it->second, max_length,
                                                  data_flags);
  }
}

int NgHttp2Adapter::DelegateSendCallback(int32_t stream_id,
                                         const uint8_t* framehd,
                                         size_t length) {
  auto it = sources_.find(stream_id);
  if (it == sources_.end()) {
    // A DataFrameSource is not available for this stream; forward to the
    // visitor.
    visitor_.SendDataFrame(stream_id, ToStringView(framehd, kFrameHeaderSize),
                           length);
  } else {
    // A DataFrameSource is available for this stream.
    it->second->Send(ToStringView(framehd, kFrameHeaderSize), length);
  }
  return 0;
}

NgHttp2Adapter::NgHttp2Adapter(Http2VisitorInterface& visitor,
                               Perspective perspective,
                               const nghttp2_option* options)
    : Http2Adapter(visitor),
      visitor_(visitor),
      options_(options),
      perspective_(perspective) {}

NgHttp2Adapter::~NgHttp2Adapter() {}

void NgHttp2Adapter::Initialize() {
  nghttp2_option* owned_options = nullptr;
  if (options_ == nullptr) {
    nghttp2_option_new(&owned_options);
    // Set some common options for compatibility.
    nghttp2_option_set_no_closed_streams(owned_options, 1);
    nghttp2_option_set_no_auto_window_update(owned_options, 1);
    nghttp2_option_set_max_send_header_block_length(owned_options, 0x2000000);
    nghttp2_option_set_max_outbound_ack(owned_options, 10000);
    nghttp2_option_set_user_recv_extension_type(owned_options,
                                                kMetadataFrameType);
    options_ = owned_options;
  }

  session_ = std::make_unique<NgHttp2Session>(
      perspective_, callbacks::Create(&DataFrameSendCallback), options_,
      static_cast<void*>(&visitor_));
  if (owned_options != nullptr) {
    nghttp2_option_del(owned_options);
  }
  options_ = nullptr;
}

void NgHttp2Adapter::RemovePendingMetadata(Http2StreamId stream_id) {
  auto it = stream_metadata_.find(stream_id);
  if (it != stream_metadata_.end()) {
    it->second.erase(it->second.begin());
    if (it->second.empty()) {
      stream_metadata_.erase(it);
    }
  }
}

}  // namespace adapter
}  // namespace http2
```