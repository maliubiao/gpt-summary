Response:
Let's break down the thought process for analyzing the provided C++ code.

**1. Understanding the Goal:**

The core request is to understand the functionality of the `nghttp2_util.cc` file within the Chromium networking stack (specifically the QUIC/HTTP/2 implementation). This involves identifying its purpose, potential interactions with JavaScript, its internal logic, and common usage pitfalls.

**2. Initial Code Scan and Keyword Identification:**

A quick scan reveals several key elements:

* **`#include` directives:**  These indicate dependencies on other parts of the codebase, including standard C++ libraries (`<cstdint>`, `<cstring>`, etc.), `absl` (Google's common libraries), and specific QUIC/HTTP/2 headers (`quiche/http2/adapter/http2_protocol.h`). The presence of `nghttp2.h` (implicitly included through other headers) is crucial.
* **Namespaces:** `http2::adapter`. This suggests it's part of the HTTP/2 adapter layer within a larger system.
* **Function names:**  Many functions have names like `MakeCallbacksPtr`, `MakeSessionPtr`, `ToUint8Ptr`, `ToStringView`, `GetNghttp2Nvs`, `ToHttp2ErrorCode`, `ToNgHttp2ErrorCode`, `MakeZeroCopyDataFrameSource`, `LogBeforeSend`, etc. These names are strongly suggestive of their purpose (creating pointers, type conversions, getting HTTP/2 name-value pairs, converting error codes, creating data sources, logging).
* **`nghttp2_` prefix:**  This immediately signals interaction with the `nghttp2` library, a popular C library for handling HTTP/2.

**3. Deconstructing Functionality - Grouping by Purpose:**

The next step is to categorize the functions based on their apparent roles:

* **Memory Management:**  `MakeCallbacksPtr`, `MakeSessionPtr`, `DeleteCallbacks`, `DeleteSession`. These clearly manage the lifecycle of `nghttp2` objects.
* **Type Conversions:** `ToUint8Ptr`, `ToStringView`, `ToHttp2ErrorCode`, `ToNgHttp2ErrorCode`, `ToInvalidFrameError`. These handle conversions between different data representations (C-style strings, `absl::string_view`, error code enums).
* **HTTP/2 Header Handling:** `GetNghttp2Nvs`, `GetResponseNghttp2Nvs`. These convert internal header representations to the `nghttp2_nv` format.
* **Data Handling:** `MakeZeroCopyDataFrameSource`. This deals with efficiently sending data.
* **Error Handling:**  Functions involving `ErrorCode` and `InvalidFrameError`.
* **Logging:** `LogBeforeSend`. This is a debugging/monitoring function.
* **Helper Functions:** `PaddingLength`, `NvsAsString`. These are smaller utility functions.

**4. Analyzing Individual Functions (Example: `GetNghttp2Nvs`)**

Let's take a closer look at `GetNghttp2Nvs`.

* **Input:** `absl::Span<const Header> headers`. This suggests an input of a collection of headers, likely represented as key-value pairs.
* **Output:** `std::vector<nghttp2_nv>`. This confirms it's converting to the `nghttp2` name-value pair format.
* **Logic:**  The code iterates through the input headers, extracts the name and value, sets the `NGHTTP2_NV_FLAG_NO_COPY_*` flags (important for performance and avoiding unnecessary copies if the underlying data is already managed correctly), and populates the `nghttp2_nv` struct.

**5. Identifying Relationships to JavaScript:**

This requires understanding where this C++ code fits within the Chromium architecture. Key connections to consider:

* **Network Stack:**  The file is clearly part of the network stack, which handles communication with web servers.
* **Chromium Architecture:** Chromium uses a multi-process architecture. The network stack often runs in a separate process.
* **Blink/V8:** The rendering engine (Blink) and the JavaScript engine (V8) run in another process.
* **Inter-Process Communication (IPC):** JavaScript interacts with the network stack through IPC.

Therefore, the relationship isn't direct function calls, but rather:

* **Data Structures:**  The data structures manipulated in this file (like HTTP headers) are representations of information that originated from JavaScript (e.g., when a web page makes an HTTP request).
* **Indirect Influence:** The way HTTP/2 communication is handled at this low level impacts the performance and behavior seen by JavaScript. For example, how headers are formatted affects the data sent over the wire.

**6. Developing Hypothetical Scenarios and Examples:**

To solidify understanding, it's helpful to create simple scenarios:

* **`GetNghttp2Nvs`:**  Imagine JavaScript code setting HTTP headers. This data would eventually be passed to the C++ network stack, and `GetNghttp2Nvs` would be used to format those headers for `nghttp2`.
* **Error Conversion:** If `nghttp2` encounters an error, the conversion functions would translate it into an error code that the higher layers of Chromium (potentially even JavaScript via an error callback) can understand.

**7. Considering User/Programming Errors:**

Think about common mistakes when working with HTTP/2 or low-level network code:

* **Incorrect Header Formatting:** Passing invalid characters or malformed header names/values.
* **Flow Control Issues:** Not respecting flow control limits, leading to connection stalls.
* **Stream Management:** Incorrectly managing HTTP/2 streams.

The code in `nghttp2_util.cc` provides utilities, but it doesn't prevent all errors. Higher layers need to enforce correct usage.

**8. Tracing User Actions:**

Imagine a user browsing a website:

1. **User Action:** User types a URL or clicks a link.
2. **Browser Process:** The browser process initiates a navigation.
3. **Renderer Process:**  The renderer process (with the JavaScript engine) might make an HTTP request using APIs like `fetch()`.
4. **Network Process:** The network process receives the request.
5. **`nghttp2_util.cc`:**  When setting up the HTTP/2 connection or sending/receiving data, functions in this file will be used to format headers, handle errors, manage data flow, and interact with the `nghttp2` library.

**9. Review and Refinement:**

Finally, review the analysis for clarity, accuracy, and completeness. Ensure that the explanations are easy to understand, even for someone not intimately familiar with the codebase. Double-check the examples and assumptions.

This step-by-step approach, combining code analysis, keyword recognition, functional decomposition, and scenario-based thinking, helps to thoroughly understand the purpose and role of a complex source code file like `nghttp2_util.cc`.
这个文件 `net/third_party/quiche/src/quiche/http2/adapter/nghttp2_util.cc` 是 Chromium 网络栈中，用于 HTTP/2 协议适配层的一个实用工具文件。 它的主要功能是提供了一系列辅助函数，用于在 Chromium 的 HTTP/2 适配器和底层的 `nghttp2` 库之间进行交互。 `nghttp2` 是一个流行的、高性能的 HTTP/2 和 HPACK 协议 C 库。

**主要功能列举:**

1. **`nghttp2` 对象管理:**
   - 提供智能指针的创建函数 (`MakeCallbacksPtr`, `MakeSessionPtr`)，用于安全地管理 `nghttp2_session_callbacks` 和 `nghttp2_session` 类型的指针，防止内存泄漏。
   - 提供删除函数 (`DeleteCallbacks`, `DeleteSession`)，虽然智能指针会自动调用，但这些函数明确了清理操作。

2. **类型转换:**
   - 提供将 `char*` 和 `const char*` 转换为 `uint8_t*` 的函数 (`ToUint8Ptr`)，方便在 `nghttp2` 的 API 中使用。
   - 提供将 `nghttp2_rcbuf*` 和 `uint8_t*` 转换为 `absl::string_view` 的函数 (`ToStringView`)，方便在 Chromium 代码中使用字符串视图。

3. **HTTP 头部处理:**
   - 提供将 Chromium 的 `Header` (通常是 `std::pair<std::string, std::string>`) 转换为 `nghttp2_nv` 结构体数组的函数 (`GetNghttp2Nvs`)，这是 `nghttp2` 库用于表示 HTTP 头部的格式。该函数还处理了 `NGHTTP2_NV_FLAG_NO_COPY_*` 标志，以优化性能，避免不必要的内存拷贝。
   - 提供将 Chromium 的 `quiche::HttpHeaderBlock` 转换为包含 `:status` 伪头部的 `nghttp2_nv` 数组的函数 (`GetResponseNghttp2Nvs`)，用于构建 HTTP 响应头部。

4. **错误码转换:**
   - 提供在 Chromium 的 `Http2ErrorCode` 枚举和 `nghttp2` 的错误码之间进行转换的函数 (`ToHttp2ErrorCode`, `ToNgHttp2ErrorCode`, `ToInvalidFrameError`)。

5. **数据帧处理:**
   - 提供一个 `DataFrameSource` 的实现 (`Nghttp2DataFrameSource`)，用于将 `nghttp2` 的数据提供者 (`nghttp2_data_provider`) 适配到 Chromium 的数据源接口。这个类允许以零拷贝的方式发送数据。
   - 提供创建 `Nghttp2DataFrameSource` 的工厂函数 (`MakeZeroCopyDataFrameSource`)。

6. **日志记录:**
   - 提供 `LogBeforeSend` 函数，用于在发送 HTTP/2 帧之前记录详细的帧信息，方便调试。

7. **其他工具函数:**
   - `ErrorString`: 将 `Http2ErrorCode` 转换为可读的字符串。
   - `PaddingLength`: 计算 HTTP/2 帧的填充长度。
   - `NvsAsString`: 将 `nghttp2_nv` 数组转换为易于阅读的字符串格式，主要用于日志记录。

**与 JavaScript 功能的关系:**

该文件本身不包含直接的 JavaScript 代码，因此没有直接的 JavaScript 功能。然而，它在幕后支持着 JavaScript 发起的网络请求。

当 JavaScript 代码（例如，在网页中使用 `fetch()` API 或 `XMLHttpRequest`）发起一个通过 HTTP/2 协议的请求时，Chromium 的网络栈会处理这个请求。  `nghttp2_util.cc` 中提供的功能在以下方面与 JavaScript 功能间接相关：

* **请求头部的构建:** JavaScript 代码设置的请求头最终会被转换为 `nghttp2_nv` 格式，用于传递给 `nghttp2` 库进行处理。 `GetNghttp2Nvs` 函数就负责这个转换过程。
* **响应头部的解析:** 当服务器返回 HTTP/2 响应时，`nghttp2` 库解析的头部信息可能会被转换成 Chromium 内部的格式，最终传递给 JavaScript 代码，使得 JavaScript 可以访问响应头。虽然这个文件没有直接处理接收，但它提供的类型转换工具是这个过程的一部分。
* **错误处理:** 如果 HTTP/2 连接或请求过程中发生错误（例如，协议错误、流被拒绝），`nghttp2` 库会报告错误，这些错误会被转换为 Chromium 的 `Http2ErrorCode`，最终可能会导致 JavaScript 中 `fetch()` API 的 Promise 被 reject，或者 `XMLHttpRequest` 触发 error 事件。
* **数据传输:** 当 JavaScript 发送或接收大量数据时，`MakeZeroCopyDataFrameSource` 提供的零拷贝数据传输机制可以提高性能，减少 JavaScript 执行的延迟。

**举例说明 (假设输入与输出):**

**场景:** JavaScript 代码发起一个带有自定义头部的 GET 请求。

**假设输入 (Chromium 的 `Header` 格式):**
```c++
std::vector<Header> headers = {
  {"Content-Type", "application/json"},
  {"X-Custom-Header", "custom-value"}
};
```

**调用 `GetNghttp2Nvs`:**
```c++
auto nghttp2_nvs = GetNghttp2Nvs(absl::MakeSpan(headers));
```

**输出 ( `std::vector<nghttp2_nv>` 格式):**
```c++
// nghttp2_nvs 的内容 (顺序可能不同):
nghttp2_nv {
  name: (uint8_t*)"Content-Type",
  namelen: 12,
  value: (uint8_t*)"application/json",
  valuelen: 16,
  flags: 0
},
nghttp2_nv {
  name: (uint8_t*)"X-Custom-Header",
  namelen: 15,
  value: (uint8_t*)"custom-value",
  valuelen: 12,
  flags: 0
}
```

**场景:**  `nghttp2` 库报告一个 `NGHTTP2_ERR_REFUSED_STREAM` 错误。

**假设输入 ( `nghttp2` 错误码):**
```c++
int nghttp2_error = NGHTTP2_ERR_REFUSED_STREAM;
```

**调用 `ToInvalidFrameError`:**
```c++
InvalidFrameError chromium_error = ToInvalidFrameError(nghttp2_error);
```

**输出 (Chromium 的 `InvalidFrameError` 枚举):**
```c++
// chromium_error 的值:
InvalidFrameError::kRefusedStream
```

**用户或编程常见的使用错误 (举例说明):**

1. **错误地管理 `nghttp2` 对象生命周期:** 如果直接使用 `nghttp2` 的 API 创建对象而不使用 `MakeCallbacksPtr` 或 `MakeSessionPtr`，并且没有正确地调用 `nghttp2_session_del` 或 `nghttp2_session_callbacks_del`，可能导致内存泄漏。

   ```c++
   // 错误示例:
   nghttp2_session_callbacks* callbacks = nghttp2_session_callbacks_new();
   // ... 使用 callbacks ...
   // 忘记调用 nghttp2_session_callbacks_del(callbacks); // 内存泄漏
   ```

2. **在调用 `GetNghttp2Nvs` 之后修改原始的头部数据:** 如果在将 Chromium 的 `Header` 转换为 `nghttp2_nv` 后，原始的 `std::string` 被修改，由于 `GetNghttp2Nvs` 默认情况下可能不会拷贝数据（取决于 `GetStringView` 的实现），这可能导致 `nghttp2` 库访问到已修改或失效的数据。虽然该文件内部会设置 `NGHTTP2_NV_FLAG_NO_COPY_*` 尝试优化，但使用者仍然需要注意数据生命周期。

   ```c++
   std::vector<Header> headers = {{"name", "value"}};
   auto nvs = GetNghttp2Nvs(absl::MakeSpan(headers));
   headers[0].second = "modified_value"; // 潜在问题
   // ... 使用 nvs ...
   ```

3. **错误地转换错误码:**  虽然 `nghttp2_util.cc` 提供了转换函数，但在不同的场景下可能会有不同的错误处理逻辑。例如，将 `NGHTTP2_ERR_STREAM_CLOSED` 错误简单地转换为 `InvalidFrameError::kStreamClosed` 可能不足以提供足够的上下文信息给上层应用。

**用户操作如何一步步的到达这里 (作为调试线索):**

假设用户在 Chrome 浏览器中访问一个支持 HTTP/2 的网站：

1. **用户在地址栏输入 URL 并回车，或点击一个链接。**
2. **Chrome 浏览器的主进程（Browser Process）接收到用户的请求。**
3. **网络进程（Network Process）被指示去获取资源。**
4. **网络进程检查目标服务器是否支持 HTTP/2。** 这通常通过 ALPN (Application-Layer Protocol Negotiation) 在 TLS 握手期间完成。
5. **如果协商成功使用 HTTP/2，网络进程会创建一个 `nghttp2_session` 对象来处理与服务器的 HTTP/2 连接。**  `MakeSessionPtr` 可能在这个阶段被使用。
6. **当需要发送 HTTP 请求头时（例如，GET 请求的头部），Chromium 的 HTTP/2 适配器会调用 `GetNghttp2Nvs` 将内部的头部表示转换为 `nghttp2` 库所需的 `nghttp2_nv` 格式。** 这些头部可能包括用户请求的 URL、Cookie、User-Agent 等。
7. **`nghttp2` 库使用这些 `nghttp2_nv` 结构体来格式化和发送 HEADERS 帧。**
8. **如果服务器返回一个错误的 HTTP/2 帧，`nghttp2` 库可能会报告一个错误码。**
9. **Chromium 的 HTTP/2 适配器会使用 `ToInvalidFrameError` 或其他错误转换函数将 `nghttp2` 的错误码转换为 Chromium 内部的错误表示。**
10. **这个错误信息可能会被记录下来，或者传递给更上层的网络代码进行处理，最终可能导致网页加载失败，并在开发者工具中显示错误信息。**

因此，当你在调试 Chrome 浏览器网络问题，特别是与 HTTP/2 相关的错误时，看到调用栈中包含 `nghttp2_util.cc` 中的函数，这意味着问题很可能涉及到 Chromium 的 HTTP/2 适配器与 `nghttp2` 库的交互，例如头部格式错误、协议违规、连接管理问题等。 这时，可以重点关注传递给这些函数的参数和返回值，以及 `nghttp2` 库本身可能返回的错误码。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/nghttp2_util.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
#include "quiche/http2/adapter/nghttp2_util.h"

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/http2/adapter/http2_protocol.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_endian.h"

namespace http2 {
namespace adapter {

namespace {

using InvalidFrameError = Http2VisitorInterface::InvalidFrameError;

void DeleteCallbacks(nghttp2_session_callbacks* callbacks) {
  if (callbacks) {
    nghttp2_session_callbacks_del(callbacks);
  }
}

void DeleteSession(nghttp2_session* session) {
  if (session) {
    nghttp2_session_del(session);
  }
}

}  // namespace

nghttp2_session_callbacks_unique_ptr MakeCallbacksPtr(
    nghttp2_session_callbacks* callbacks) {
  return nghttp2_session_callbacks_unique_ptr(callbacks, &DeleteCallbacks);
}

nghttp2_session_unique_ptr MakeSessionPtr(nghttp2_session* session) {
  return nghttp2_session_unique_ptr(session, &DeleteSession);
}

uint8_t* ToUint8Ptr(char* str) { return reinterpret_cast<uint8_t*>(str); }
uint8_t* ToUint8Ptr(const char* str) {
  return const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(str));
}

absl::string_view ToStringView(nghttp2_rcbuf* rc_buffer) {
  nghttp2_vec buffer = nghttp2_rcbuf_get_buf(rc_buffer);
  return absl::string_view(reinterpret_cast<const char*>(buffer.base),
                           buffer.len);
}

absl::string_view ToStringView(uint8_t* pointer, size_t length) {
  return absl::string_view(reinterpret_cast<const char*>(pointer), length);
}

absl::string_view ToStringView(const uint8_t* pointer, size_t length) {
  return absl::string_view(reinterpret_cast<const char*>(pointer), length);
}

std::vector<nghttp2_nv> GetNghttp2Nvs(absl::Span<const Header> headers) {
  const int num_headers = headers.size();
  std::vector<nghttp2_nv> nghttp2_nvs;
  nghttp2_nvs.reserve(num_headers);
  for (int i = 0; i < num_headers; ++i) {
    nghttp2_nv header;
    uint8_t flags = NGHTTP2_NV_FLAG_NONE;

    const auto [name, no_copy_name] = GetStringView(headers[i].first);
    header.name = ToUint8Ptr(name.data());
    header.namelen = name.size();
    if (no_copy_name) {
      flags |= NGHTTP2_NV_FLAG_NO_COPY_NAME;
    }
    const auto [value, no_copy_value] = GetStringView(headers[i].second);
    header.value = ToUint8Ptr(value.data());
    header.valuelen = value.size();
    if (no_copy_value) {
      flags |= NGHTTP2_NV_FLAG_NO_COPY_VALUE;
    }
    header.flags = flags;
    nghttp2_nvs.push_back(std::move(header));
  }

  return nghttp2_nvs;
}

std::vector<nghttp2_nv> GetResponseNghttp2Nvs(
    const quiche::HttpHeaderBlock& headers, absl::string_view response_code) {
  // Allocate enough for all headers and also the :status pseudoheader.
  const int num_headers = headers.size();
  std::vector<nghttp2_nv> nghttp2_nvs;
  nghttp2_nvs.reserve(num_headers + 1);

  // Add the :status pseudoheader first.
  nghttp2_nv status;
  status.name = ToUint8Ptr(kHttp2StatusPseudoHeader.data());
  status.namelen = kHttp2StatusPseudoHeader.size();
  status.value = ToUint8Ptr(response_code.data());
  status.valuelen = response_code.size();
  status.flags = NGHTTP2_FLAG_NONE;
  nghttp2_nvs.push_back(std::move(status));

  // Add the remaining headers.
  for (const auto& header_pair : headers) {
    nghttp2_nv header;
    header.name = ToUint8Ptr(header_pair.first.data());
    header.namelen = header_pair.first.size();
    header.value = ToUint8Ptr(header_pair.second.data());
    header.valuelen = header_pair.second.size();
    header.flags = NGHTTP2_FLAG_NONE;
    nghttp2_nvs.push_back(std::move(header));
  }

  return nghttp2_nvs;
}

Http2ErrorCode ToHttp2ErrorCode(uint32_t wire_error_code) {
  if (wire_error_code > static_cast<int>(Http2ErrorCode::MAX_ERROR_CODE)) {
    return Http2ErrorCode::INTERNAL_ERROR;
  }
  return static_cast<Http2ErrorCode>(wire_error_code);
}

int ToNgHttp2ErrorCode(InvalidFrameError error) {
  switch (error) {
    case InvalidFrameError::kProtocol:
      return NGHTTP2_ERR_PROTO;
    case InvalidFrameError::kRefusedStream:
      return NGHTTP2_ERR_REFUSED_STREAM;
    case InvalidFrameError::kHttpHeader:
      return NGHTTP2_ERR_HTTP_HEADER;
    case InvalidFrameError::kHttpMessaging:
      return NGHTTP2_ERR_HTTP_MESSAGING;
    case InvalidFrameError::kFlowControl:
      return NGHTTP2_ERR_FLOW_CONTROL;
    case InvalidFrameError::kStreamClosed:
      return NGHTTP2_ERR_STREAM_CLOSED;
  }
  return NGHTTP2_ERR_PROTO;
}

InvalidFrameError ToInvalidFrameError(int error) {
  switch (error) {
    case NGHTTP2_ERR_PROTO:
      return InvalidFrameError::kProtocol;
    case NGHTTP2_ERR_REFUSED_STREAM:
      return InvalidFrameError::kRefusedStream;
    case NGHTTP2_ERR_HTTP_HEADER:
      return InvalidFrameError::kHttpHeader;
    case NGHTTP2_ERR_HTTP_MESSAGING:
      return InvalidFrameError::kHttpMessaging;
    case NGHTTP2_ERR_FLOW_CONTROL:
      return InvalidFrameError::kFlowControl;
    case NGHTTP2_ERR_STREAM_CLOSED:
      return InvalidFrameError::kStreamClosed;
  }
  return InvalidFrameError::kProtocol;
}

class Nghttp2DataFrameSource : public DataFrameSource {
 public:
  Nghttp2DataFrameSource(nghttp2_data_provider provider,
                         nghttp2_send_data_callback send_data, void* user_data)
      : provider_(std::move(provider)),
        send_data_(std::move(send_data)),
        user_data_(user_data) {}

  std::pair<int64_t, bool> SelectPayloadLength(size_t max_length) override {
    const int32_t stream_id = 0;
    uint32_t data_flags = 0;
    int64_t result = provider_.read_callback(
        nullptr /* session */, stream_id, nullptr /* buf */, max_length,
        &data_flags, &provider_.source, nullptr /* user_data */);
    if (result == NGHTTP2_ERR_DEFERRED) {
      return {kBlocked, false};
    } else if (result < 0) {
      return {kError, false};
    } else if ((data_flags & NGHTTP2_DATA_FLAG_NO_COPY) == 0) {
      QUICHE_LOG(ERROR) << "Source did not use the zero-copy API!";
      return {kError, false};
    } else {
      const bool eof = data_flags & NGHTTP2_DATA_FLAG_EOF;
      if (eof && (data_flags & NGHTTP2_DATA_FLAG_NO_END_STREAM) == 0) {
        send_fin_ = true;
      }
      return {result, eof};
    }
  }

  bool Send(absl::string_view frame_header, size_t payload_length) override {
    nghttp2_frame frame;
    frame.hd.type = 0;
    frame.hd.length = payload_length;
    frame.hd.flags = 0;
    frame.hd.stream_id = 0;
    frame.data.padlen = 0;
    const int result = send_data_(
        nullptr /* session */, &frame, ToUint8Ptr(frame_header.data()),
        payload_length, &provider_.source, user_data_);
    QUICHE_LOG_IF(ERROR, result < 0 && result != NGHTTP2_ERR_WOULDBLOCK)
        << "Unexpected error code from send: " << result;
    return result == 0;
  }

  bool send_fin() const override { return send_fin_; }

 private:
  nghttp2_data_provider provider_;
  nghttp2_send_data_callback send_data_;
  void* user_data_;
  bool send_fin_ = false;
};

std::unique_ptr<DataFrameSource> MakeZeroCopyDataFrameSource(
    nghttp2_data_provider provider, void* user_data,
    nghttp2_send_data_callback send_data) {
  return std::make_unique<Nghttp2DataFrameSource>(
      std::move(provider), std::move(send_data), user_data);
}

absl::string_view ErrorString(uint32_t error_code) {
  return Http2ErrorCodeToString(static_cast<Http2ErrorCode>(error_code));
}

size_t PaddingLength(uint8_t flags, size_t padlen) {
  return (flags & PADDED_FLAG ? 1 : 0) + padlen;
}

struct NvFormatter {
  void operator()(std::string* out, const nghttp2_nv& nv) {
    absl::StrAppend(out, ToStringView(nv.name, nv.namelen), ": ",
                    ToStringView(nv.value, nv.valuelen));
  }
};

std::string NvsAsString(nghttp2_nv* nva, size_t nvlen) {
  return absl::StrJoin(absl::MakeConstSpan(nva, nvlen), ", ", NvFormatter());
}

#define HTTP2_FRAME_SEND_LOG QUICHE_VLOG(1)

void LogBeforeSend(const nghttp2_frame& frame) {
  switch (static_cast<FrameType>(frame.hd.type)) {
    case FrameType::DATA:
      HTTP2_FRAME_SEND_LOG << "Sending DATA on stream " << frame.hd.stream_id
                           << " with length "
                           << frame.hd.length - PaddingLength(frame.hd.flags,
                                                              frame.data.padlen)
                           << " and padding "
                           << PaddingLength(frame.hd.flags, frame.data.padlen);
      break;
    case FrameType::HEADERS:
      HTTP2_FRAME_SEND_LOG << "Sending HEADERS on stream " << frame.hd.stream_id
                           << " with headers ["
                           << NvsAsString(frame.headers.nva,
                                          frame.headers.nvlen)
                           << "]";
      break;
    case FrameType::PRIORITY:
      HTTP2_FRAME_SEND_LOG << "Sending PRIORITY";
      break;
    case FrameType::RST_STREAM:
      HTTP2_FRAME_SEND_LOG << "Sending RST_STREAM on stream "
                           << frame.hd.stream_id << " with error code "
                           << ErrorString(frame.rst_stream.error_code);
      break;
    case FrameType::SETTINGS:
      HTTP2_FRAME_SEND_LOG << "Sending SETTINGS with " << frame.settings.niv
                           << " entries, is_ack: "
                           << (frame.hd.flags & ACK_FLAG);
      break;
    case FrameType::PUSH_PROMISE:
      HTTP2_FRAME_SEND_LOG << "Sending PUSH_PROMISE";
      break;
    case FrameType::PING: {
      Http2PingId ping_id;
      std::memcpy(&ping_id, frame.ping.opaque_data, sizeof(Http2PingId));
      HTTP2_FRAME_SEND_LOG << "Sending PING with unique_id "
                           << quiche::QuicheEndian::NetToHost64(ping_id)
                           << ", is_ack: " << (frame.hd.flags & ACK_FLAG);
      break;
    }
    case FrameType::GOAWAY:
      HTTP2_FRAME_SEND_LOG << "Sending GOAWAY with last_stream: "
                           << frame.goaway.last_stream_id << " and error "
                           << ErrorString(frame.goaway.error_code);
      break;
    case FrameType::WINDOW_UPDATE:
      HTTP2_FRAME_SEND_LOG << "Sending WINDOW_UPDATE on stream "
                           << frame.hd.stream_id << " with update delta "
                           << frame.window_update.window_size_increment;
      break;
    case FrameType::CONTINUATION:
      HTTP2_FRAME_SEND_LOG << "Sending CONTINUATION, which is unexpected";
      break;
  }
}

#undef HTTP2_FRAME_SEND_LOG

}  // namespace adapter
}  // namespace http2
```