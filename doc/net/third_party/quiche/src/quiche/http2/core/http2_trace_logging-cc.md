Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

1. **Understand the Core Purpose:** The filename `http2_trace_logging.cc` and the inclusion of `<quiche/http2/core/http2_trace_logging.h>` immediately suggest that this code is responsible for logging HTTP/2 events. The presence of `SpdyFramerVisitorInterface` points to its role in observing and potentially intercepting HTTP/2 frame processing.

2. **Identify Key Components:**  Quickly scan the code for prominent elements:
    * **Includes:**  These tell us the dependencies and what functionalities are being used (e.g., `<cstdint>`, `<string>`, `absl/strings`, `quiche/http2/core/spdy_protocol.h`, `quiche/common/http/http_header_block.h`). This confirms the HTTP/2 and logging aspects.
    * **Macros:**  `FORMAT_ARG`, `FORMAT_INT_ARG`, `FORMAT_ATTR`, `FORMAT_INT_ATTR`, `FORMAT_HEADER_BLOCK`. These are clearly for simplifying log message formatting. Notice the consistent pattern of `arg_name=value`.
    * **Namespaces:** `anonymous namespace` suggests utility functions not meant for external use. `http2` namespace organizes the core functionality.
    * **Classes:** `Http2TraceLogger` and `Http2FrameLogger` are the central players. The naming suggests one logs events during frame processing, and the other logs when frames are *written*.
    * **Member Variables (in `Http2TraceLogger`):** `wrapped_`, `perspective_`, `is_enabled_`, `connection_id_`, `recording_headers_handler_`. These offer insights into what information the logger needs (the underlying framer, the role of the endpoint, whether logging is on, connection identifier, and temporary storage for headers).
    * **Methods (in `Http2TraceLogger`):**  A large number of `On...` methods, mirroring the `SpdyFramerVisitorInterface`. This confirms the observer pattern. Also, `LogReceivedHeaders`.
    * **Methods (in `Http2FrameLogger`):** `Visit...` methods corresponding to different HTTP/2 frame types. This aligns with the idea of logging frame *writing*.
    * **Logging Calls:**  Look for `HTTP2_TRACE_LOG`. Note the use of `is_enabled_` to conditionally log.

3. **Trace the Execution Flow (Conceptual):** Imagine an HTTP/2 frame arriving or being sent.
    * **Receiving:**  The `Http2TraceLogger`, acting as a wrapper around a real `SpdyFramerVisitorInterface`, intercepts the `On...` calls. It logs the event and then calls the corresponding method on the wrapped object. The `recording_headers_handler_` is a temporary object used to capture header blocks as they arrive.
    * **Sending:** The `Http2FrameLogger` is used when constructing and writing HTTP/2 frames. Its `Visit...` methods are called by the frame construction logic, allowing it to log the frame's contents before it's sent.

4. **Determine Functionality:** Based on the observations above, the core functions are:
    * **Detailed Logging:** Recording various HTTP/2 events and frame details.
    * **Conditional Logging:**  Enabling/disabling logging through `is_enabled_`.
    * **Differentiating Perspective:**  Logging whether the event is happening on the sender or receiver side.
    * **Associating Logs with Connections:** Using `connection_id_`.
    * **Capturing Header Blocks:** Specifically handling headers for logging.

5. **Analyze JavaScript Relevance (or Lack Thereof):**  This is C++ code dealing with low-level HTTP/2 framing. While JavaScript in a browser uses HTTP/2, it doesn't directly interact with this specific C++ code. The connection is indirect: this logging *helps debug* the underlying network stack that JavaScript relies on.

6. **Construct Logic Reasoning Examples:**
    * **Assume Logging Enabled:** Pick a simple scenario like receiving a HEADERS frame. Detail the input parameters and the expected log output, matching the format defined by the macros.
    * **Assume Logging Disabled:** Show that the `HTTP2_TRACE_LOG` macro will effectively do nothing, resulting in no extra output.

7. **Identify Potential Usage Errors:** Focus on the `recording_headers_handler_`. The code explicitly checks if headers were started but never finished logging. This points to a potential error in the surrounding code where header processing might be interrupted.

8. **Develop Debugging Use Case:**  Think about how a developer would use this. They'd likely enable the logging, perform actions in their application (which trigger HTTP/2 communication), and then examine the logs to understand the sequence of events and the content of the frames. Outline a step-by-step scenario.

9. **Structure the Explanation:** Organize the findings into clear sections: Functionality, JavaScript Relation, Logic Reasoning, Usage Errors, and Debugging. Use clear language and provide concrete examples. Use formatting (like bolding and code blocks) to enhance readability.

10. **Review and Refine:** Read through the explanation to ensure accuracy, completeness, and clarity. Check for any ambiguities or areas that could be explained better. For example, ensure the explanation clearly distinguishes between `Http2TraceLogger` (for incoming frames) and `Http2FrameLogger` (for outgoing frames).
这个C++源代码文件 `http2_trace_logging.cc` 属于 Chromium 的网络栈，其主要功能是为 HTTP/2 协议的帧处理过程提供详细的**跟踪日志记录**。它作为一个装饰器模式的实现，包裹了底层的 HTTP/2 帧处理逻辑，并在每个关键步骤记录日志，以便于开发者调试和分析 HTTP/2 通信过程。

以下是该文件的详细功能分解：

**1. 核心功能：HTTP/2 帧处理跟踪日志**

* **拦截和记录 Framer 事件:**  `Http2TraceLogger` 类实现了 `SpdyFramerVisitorInterface` 接口，这意味着它可以作为 HTTP/2 帧解析器（Framer）的回调接收器。每当 Framer 解析到一个新的帧头、帧数据、或者完成一个完整的帧时，`Http2TraceLogger` 都会接收到相应的回调。
* **详细记录帧信息:**  在每个回调方法中（如 `OnCommonHeader`, `OnDataFrameHeader`, `OnHeaders`, `OnSettings`, 等等），代码使用预定义的宏 (`FORMAT_ARG`, `FORMAT_INT_ARG`, `FORMAT_ATTR`) 将帧的各种属性（例如 stream ID, 长度, 类型, 标志,  header block, settings 值等）格式化并输出到日志中。
* **区分发送和接收:**  `Http2TraceLogger` 构造函数接收一个 `perspective` 参数，用于区分当前是发送方还是接收方，并在日志中进行标记，方便区分通信方向。
* **条件性日志记录:**  通过 `is_enabled_` 回调函数，可以动态地开启或关闭日志记录，避免在生产环境中产生过多的日志输出。
* **关联连接:**  `connection_id_` 用于标识当前的 HTTP/2 连接，使得日志能够关联到特定的连接实例。
* **记录接收到的完整头部块:**  `recording_headers_handler_` 用于暂存接收到的头部信息，直到整个头部块接收完成，然后将其作为一个整体记录到日志中。
* **记录发送的帧:** `Http2FrameLogger` 类实现了 `SpdyFrameVisitorInterface`，用于记录发送出去的各种 HTTP/2 帧。每个 `Visit...` 方法对应一种 HTTP/2 帧类型，并记录该帧的关键信息。

**2. 与 JavaScript 的关系（间接）**

这个 C++ 文件本身不包含任何 JavaScript 代码，它运行在 Chromium 浏览器的网络进程中。 然而，它记录的日志对于理解浏览器中 JavaScript 发起的 HTTP/2 请求至关重要。

* **调试网络请求:** 当 JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起 HTTP/2 请求时，浏览器底层的网络栈（包括这个文件中的代码）会处理这些请求。 通过查看这里的日志，开发者可以了解：
    * **请求头的具体内容:**  例如，请求方法、URL、自定义头部等。
    * **服务器的响应头:**  例如，状态码、`content-type`、`set-cookie` 等。
    * **HTTP/2 的帧交换过程:**  例如，HEADERS 帧、DATA 帧、SETTINGS 帧的发送和接收顺序及内容。
    * **连接的建立和关闭过程:**  例如，SETTINGS 帧的交换、GOAWAY 帧的发送等。
* **排查网络问题:** 当 JavaScript 应用遇到网络问题（例如请求失败、性能问题），查看这些日志可以帮助开发者定位问题根源，例如：
    * **服务器是否正确响应了请求？**
    * **是否存在协议错误？**
    * **是否存在流量控制或拥塞问题？**
* **理解浏览器行为:**  开发者可以通过分析这些日志，更深入地理解浏览器在处理 HTTP/2 连接时的行为，例如优先级处理、流的创建和关闭等。

**举例说明:**

假设一个 JavaScript 发起的 `fetch` 请求如下：

```javascript
fetch('https://example.com/api/data', {
  method: 'GET',
  headers: {
    'X-Custom-Header': 'my-value'
  }
})
.then(response => response.json())
.then(data => console.log(data));
```

当这个请求发送时，`Http2TraceLogger` 可能会记录类似以下的日志（简化示例）：

```
[INFO:http2_trace_logging.cc(207)] perspective=client connection_id=0x1234 OnCommonHeader: connection_id=0x1234 stream_id=1 length=150 type=1 flags=4
[INFO:http2_trace_logging.cc(250)] perspective=client connection_id=0x1234 OnHeaderFrameStart: connection_id=0x1234 stream_id=1
[INFO:http2_trace_logging.cc(357)] perspective=client connection_id=0x1234 Received headers; connection_id=0x1234 keys/values:" :method": "GET", " :scheme": "https", " :authority": "example.com", " :path": "/api/data", "x-custom-header": "my-value" compressed_bytes=... uncompressed_bytes=...
[INFO:http2_trace_logging.cc(264)] perspective=client connection_id=0x1234 OnHeaderFrameEnd: connection_id=0x1234 stream_id=1
[INFO:http2_trace_logging.cc(214)] perspective=server connection_id=0x1234 OnCommonHeader: connection_id=0x1234 stream_id=1 length=50 type=1 flags=0
[INFO:http2_trace_logging.cc(250)] perspective=server connection_id=0x1234 OnHeaderFrameStart: connection_id=0x1234 stream_id=1
[INFO:http2_trace_logging.cc(357)] perspective=server connection_id=0x1234 Received headers; connection_id=0x1234 keys/values:" :status": "200", "content-type": "application/json" compressed_bytes=... uncompressed_bytes=...
[INFO:http2_trace_logging.cc(264)] perspective=server connection_id=0x1234 OnHeaderFrameEnd: connection_id=0x1234 stream_id=1
[INFO:http2_trace_logging.cc(214)] perspective=server connection_id=0x1234 OnCommonHeader: connection_id=0x1234 stream_id=1 length=25 type=0 flags=0
[INFO:http2_trace_logging.cc(225)] perspective=server connection_id=0x1234 OnDataFrameHeader: connection_id=0x1234 stream_id=1 length=25 fin=true
[INFO:http2_trace_logging.cc(230)] perspective=server connection_id=0x1234 OnStreamFrameData: connection_id=0x1234 stream_id=1 len=25
[INFO:http2_trace_logging.cc(235)] perspective=server connection_id=0x1234 OnStreamEnd: connection_id=0x1234 stream_id=1
```

从这些日志中，我们可以看到客户端发送了 HEADERS 帧包含了请求头信息，服务器也返回了 HEADERS 帧包含了响应头信息，以及 DATA 帧包含了响应数据。

**3. 逻辑推理的假设输入与输出**

假设 `is_enabled_` 回调函数返回 `true` (日志记录已启用)。

**假设输入：**

* **HTTP/2 连接 ID:** `0xABCD`
* **当前视角:** `client` (客户端)
* **接收到一个 HEADERS 帧:**
    * **Stream ID:** `5`
    * **Length:** `100` 字节
    * **Flags:** `0x04` (END_STREAM)
    * **Header Block:**
        ```
        :status: 200
        content-type: application/json
        x-custom-response: ok
        ```

**预期输出（日志）：**

```
[INFO:http2_trace_logging.cc(207)] perspective=client connection_id=0xABCD OnCommonHeader: connection_id=0xABCD stream_id=5 length=100 type=1 flags=4
[INFO:http2_trace_logging.cc(250)] perspective=client connection_id=0xABCD OnHeaderFrameStart: connection_id=0xABCD stream_id=5
[INFO:http2_trace_logging.cc(357)] perspective=client connection_id=0xABCD Received headers; connection_id=0xABCD keys/values:" :status": "200", "content-type": "application/json", "x-custom-response": "ok" compressed_bytes=... uncompressed_bytes=...
[INFO:http2_trace_logging.cc(264)] perspective=client connection_id=0xABCD OnHeaderFrameEnd: connection_id=0xABCD stream_id=5
```

**假设输入（日志记录未启用）：**

* **HTTP/2 连接 ID:** `0xABCD`
* **当前视角:** `client` (客户端)
* **接收到一个 HEADERS 帧 (同上)**

**预期输出（日志）：**

不会产生与此帧相关的日志输出，因为 `is_enabled_` 返回 `false`，`HTTP2_TRACE_LOG` 宏不会执行任何操作。

**4. 用户或编程常见的使用错误**

* **忘记启用日志记录:** 开发者可能忘记在需要调试时启用相应的标志或设置，导致没有日志输出，无法排查问题。
* **日志级别设置不当:**  如果日志级别设置过高，可能无法看到详细的 HTTP/2 帧跟踪信息。
* **在生产环境中开启详细日志:**  在生产环境中开启详细的 HTTP/2 帧跟踪日志会产生大量的日志输出，影响性能并可能暴露敏感信息。
* **错误地理解日志输出:**  开发者需要理解 HTTP/2 协议的细节才能正确解读日志信息。例如，不了解流的概念可能难以理解不同 stream ID 的意义。
* **没有正确配置日志输出目标:** 可能没有将日志输出到文件或控制台，导致无法查看日志。

**5. 用户操作如何一步步到达这里 (作为调试线索)**

假设用户在使用 Chromium 浏览器访问一个使用了 HTTP/2 协议的网站，并且开发者想要调试与该网站的 HTTP/2 通信过程。

1. **用户在地址栏输入 URL 并访问网站:** 浏览器开始与服务器建立连接。如果服务器支持 HTTP/2，浏览器会进行协议升级，建立 HTTP/2 连接。
2. **浏览器网络栈处理连接建立:**  在连接建立过程中，`Http2TraceLogger` 可能会记录 SETTINGS 帧的交换，以及其他连接级别的帧。
3. **用户在网页上进行操作，触发 HTTP 请求:** 例如点击链接、提交表单、加载图片等。
4. **JavaScript 代码发起 HTTP 请求:**  如前所述，可以使用 `fetch` 或 `XMLHttpRequest`。
5. **Chromium 网络进程处理请求:**
    * **构建 HTTP/2 帧:** 网络栈会根据请求信息构建相应的 HTTP/2 帧，例如 HEADERS 帧包含请求头，DATA 帧包含请求体。 `Http2FrameLogger` 会记录这些发送的帧。
    * **发送帧到服务器:** 构建好的帧通过网络发送到服务器。
    * **接收服务器响应帧:** 服务器返回的 HTTP/2 帧会被 Chromium 的 HTTP/2 Framer 解析。
    * **`Http2TraceLogger` 接收 Framer 回调:**  每当 Framer 解析出一个新的帧头、帧数据或完成一个完整的帧时，`Http2TraceLogger` 的相应 `On...` 方法会被调用，并记录日志。
6. **开发者启用 Chromium 的网络日志功能:**  例如，通过 `chrome://net-export/` 或在启动 Chromium 时添加特定的命令行参数 `--log-net-log=netlog.json --net-log-level=0` 来启用网络日志记录。
7. **开发者分析网络日志:**  开发者可以查看生成的网络日志文件（例如 `netlog.json`），其中包含了 `Http2TraceLogger` 记录的详细 HTTP/2 帧信息，以及其他网络相关的事件，从而分析用户操作触发的网络请求的详细过程。

通过以上步骤，开发者可以利用 `http2_trace_logging.cc` 提供的日志信息，一步步追踪用户操作背后的 HTTP/2 通信过程，定位问题，并理解浏览器的网络行为。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/core/http2_trace_logging.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
#include "quiche/http2/core/http2_trace_logging.h"

#include <cstdint>
#include <memory>
#include <ostream>
#include <string>
#include <utility>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/http2/core/spdy_protocol.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_callbacks.h"

// Convenience macros for printing function arguments in log lines in the
// format arg_name=value.
#define FORMAT_ARG(arg) " " #arg "=" << arg
#define FORMAT_INT_ARG(arg) " " #arg "=" << static_cast<int>(arg)

// Convenience macros for printing Spdy*IR attributes in log lines in the
// format attrib_name=value.
#define FORMAT_ATTR(ir, attrib) " " #attrib "=" << ir.attrib()
#define FORMAT_INT_ATTR(ir, attrib) \
  " " #attrib "=" << static_cast<int>(ir.attrib())

namespace {

// Logs a container, using a user-provided object to log each individual item.
template <typename T, typename ItemLogger>
struct ContainerLogger {
  explicit ContainerLogger(const T& c, ItemLogger l)
      : container(c), item_logger(l) {}

  friend std::ostream& operator<<(std::ostream& out,
                                  const ContainerLogger& logger) {
    out << "[";
    auto begin = logger.container.begin();
    for (auto it = begin; it != logger.container.end(); ++it) {
      if (it != begin) {
        out << ", ";
      }
      logger.item_logger.Log(out, *it);
    }
    out << "]";
    return out;
  }
  const T& container;
  ItemLogger item_logger;
};

// Returns a ContainerLogger that will log |container| using |item_logger|.
template <typename T, typename ItemLogger>
auto LogContainer(const T& container, ItemLogger item_logger)
    -> decltype(ContainerLogger<T, ItemLogger>(container, item_logger)) {
  return ContainerLogger<T, ItemLogger>(container, item_logger);
}

}  // anonymous namespace

#define FORMAT_HEADER_BLOCK(ir) \
  " header_block=" << LogContainer(ir.header_block(), LogHeaderBlockEntry())

namespace http2 {

using quiche::HttpHeaderBlock;
using spdy::SettingsMap;
using spdy::SpdyAltSvcIR;
using spdy::SpdyContinuationIR;
using spdy::SpdyDataIR;
using spdy::SpdyGoAwayIR;
using spdy::SpdyHeadersIR;
using spdy::SpdyPingIR;
using spdy::SpdyPriorityIR;
using spdy::SpdyPushPromiseIR;
using spdy::SpdyRstStreamIR;
using spdy::SpdySettingsIR;
using spdy::SpdyStreamId;
using spdy::SpdyUnknownIR;
using spdy::SpdyWindowUpdateIR;

namespace {

// Defines how elements of HttpHeaderBlocks are logged.
struct LogHeaderBlockEntry {
  void Log(std::ostream& out,
           const HttpHeaderBlock::value_type& entry) const {  // NOLINT
    out << "\"" << entry.first << "\": \"" << entry.second << "\"";
  }
};

// Defines how elements of SettingsMap are logged.
struct LogSettingsEntry {
  void Log(std::ostream& out,
           const SettingsMap::value_type& entry) const {  // NOLINT
    out << spdy::SettingsIdToString(entry.first) << ": " << entry.second;
  }
};

// Defines how elements of AlternativeServiceVector are logged.
struct LogAlternativeService {
  void Log(std::ostream& out,
           const spdy::SpdyAltSvcWireFormat::AlternativeService& altsvc)
      const {  // NOLINT
    out << "{"
        << "protocol_id=" << altsvc.protocol_id << " host=" << altsvc.host
        << " port=" << altsvc.port
        << " max_age_seconds=" << altsvc.max_age_seconds << " version=";
    for (auto v : altsvc.version) {
      out << v << ",";
    }
    out << "}";
  }
};

}  // anonymous namespace

Http2TraceLogger::Http2TraceLogger(SpdyFramerVisitorInterface* parent,
                                   absl::string_view perspective,
                                   quiche::MultiUseCallback<bool()> is_enabled,
                                   const void* connection_id)
    : wrapped_(parent),
      perspective_(perspective),
      is_enabled_(std::move(is_enabled)),
      connection_id_(connection_id) {}

Http2TraceLogger::~Http2TraceLogger() {
  if (recording_headers_handler_ != nullptr &&
      !recording_headers_handler_->decoded_block().empty()) {
    HTTP2_TRACE_LOG(perspective_, is_enabled_)
        << "connection_id=" << connection_id_
        << " Received headers that were never logged! keys/values:"
        << recording_headers_handler_->decoded_block().DebugString();
  }
}

void Http2TraceLogger::OnError(Http2DecoderAdapter::SpdyFramerError error,
                               std::string detailed_error) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnError:" << FORMAT_ARG(connection_id_)
      << ", error=" << Http2DecoderAdapter::SpdyFramerErrorToString(error);
  wrapped_->OnError(error, detailed_error);
}

void Http2TraceLogger::OnCommonHeader(SpdyStreamId stream_id, size_t length,
                                      uint8_t type, uint8_t flags) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnCommonHeader:" << FORMAT_ARG(connection_id_)
      << FORMAT_ARG(stream_id) << FORMAT_ARG(length) << FORMAT_INT_ARG(type)
      << FORMAT_INT_ARG(flags);
  wrapped_->OnCommonHeader(stream_id, length, type, flags);
}

void Http2TraceLogger::OnDataFrameHeader(SpdyStreamId stream_id, size_t length,
                                         bool fin) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnDataFrameHeader:" << FORMAT_ARG(connection_id_)
      << FORMAT_ARG(stream_id) << FORMAT_ARG(length) << FORMAT_ARG(fin);
  wrapped_->OnDataFrameHeader(stream_id, length, fin);
}

void Http2TraceLogger::OnStreamFrameData(SpdyStreamId stream_id,
                                         const char* data, size_t len) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnStreamFrameData:" << FORMAT_ARG(connection_id_)
      << FORMAT_ARG(stream_id) << FORMAT_ARG(len);
  wrapped_->OnStreamFrameData(stream_id, data, len);
}

void Http2TraceLogger::OnStreamEnd(SpdyStreamId stream_id) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnStreamEnd:" << FORMAT_ARG(connection_id_) << FORMAT_ARG(stream_id);
  wrapped_->OnStreamEnd(stream_id);
}

void Http2TraceLogger::OnStreamPadLength(SpdyStreamId stream_id, size_t value) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnStreamPadLength:" << FORMAT_ARG(connection_id_)
      << FORMAT_ARG(stream_id) << FORMAT_ARG(value);
  wrapped_->OnStreamPadLength(stream_id, value);
}

void Http2TraceLogger::OnStreamPadding(SpdyStreamId stream_id, size_t len) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnStreamPadding:" << FORMAT_ARG(connection_id_)
      << FORMAT_ARG(stream_id) << FORMAT_ARG(len);
  wrapped_->OnStreamPadding(stream_id, len);
}

spdy::SpdyHeadersHandlerInterface* Http2TraceLogger::OnHeaderFrameStart(
    SpdyStreamId stream_id) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnHeaderFrameStart:" << FORMAT_ARG(connection_id_)
      << FORMAT_ARG(stream_id);
  spdy::SpdyHeadersHandlerInterface* result =
      wrapped_->OnHeaderFrameStart(stream_id);
  if (is_enabled_()) {
    recording_headers_handler_ =
        std::make_unique<spdy::RecordingHeadersHandler>(result);
    result = recording_headers_handler_.get();
  } else {
    recording_headers_handler_ = nullptr;
  }
  return result;
}

void Http2TraceLogger::OnHeaderFrameEnd(SpdyStreamId stream_id) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnHeaderFrameEnd:" << FORMAT_ARG(connection_id_)
      << FORMAT_ARG(stream_id);
  LogReceivedHeaders();
  wrapped_->OnHeaderFrameEnd(stream_id);
  recording_headers_handler_ = nullptr;
}

void Http2TraceLogger::OnRstStream(SpdyStreamId stream_id,
                                   SpdyErrorCode error_code) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnRstStream:" << FORMAT_ARG(connection_id_) << FORMAT_ARG(stream_id)
      << " error_code=" << spdy::ErrorCodeToString(error_code);
  wrapped_->OnRstStream(stream_id, error_code);
}

void Http2TraceLogger::OnSettings() { wrapped_->OnSettings(); }

void Http2TraceLogger::OnSetting(SpdySettingsId id, uint32_t value) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnSetting:" << FORMAT_ARG(connection_id_)
      << " id=" << spdy::SettingsIdToString(id) << FORMAT_ARG(value);
  wrapped_->OnSetting(id, value);
}

void Http2TraceLogger::OnSettingsEnd() {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnSettingsEnd:" << FORMAT_ARG(connection_id_);
  wrapped_->OnSettingsEnd();
}

void Http2TraceLogger::OnSettingsAck() {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnSettingsAck:" << FORMAT_ARG(connection_id_);
  wrapped_->OnSettingsAck();
}

void Http2TraceLogger::OnPing(SpdyPingId unique_id, bool is_ack) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnPing:" << FORMAT_ARG(connection_id_) << FORMAT_ARG(unique_id)
      << FORMAT_ARG(is_ack);
  wrapped_->OnPing(unique_id, is_ack);
}

void Http2TraceLogger::OnGoAway(SpdyStreamId last_accepted_stream_id,
                                SpdyErrorCode error_code) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnGoAway:" << FORMAT_ARG(connection_id_)
      << FORMAT_ARG(last_accepted_stream_id)
      << " error_code=" << spdy::ErrorCodeToString(error_code);
  wrapped_->OnGoAway(last_accepted_stream_id, error_code);
}

bool Http2TraceLogger::OnGoAwayFrameData(const char* goaway_data, size_t len) {
  return wrapped_->OnGoAwayFrameData(goaway_data, len);
}

void Http2TraceLogger::OnHeaders(SpdyStreamId stream_id, size_t payload_length,
                                 bool has_priority, int weight,
                                 SpdyStreamId parent_stream_id, bool exclusive,
                                 bool fin, bool end) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnHeaders:" << FORMAT_ARG(connection_id_) << FORMAT_ARG(stream_id)
      << FORMAT_ARG(payload_length) << FORMAT_ARG(has_priority)
      << FORMAT_INT_ARG(weight) << FORMAT_ARG(parent_stream_id)
      << FORMAT_ARG(exclusive) << FORMAT_ARG(fin) << FORMAT_ARG(end);
  wrapped_->OnHeaders(stream_id, payload_length, has_priority, weight,
                      parent_stream_id, exclusive, fin, end);
}

void Http2TraceLogger::OnWindowUpdate(SpdyStreamId stream_id,
                                      int delta_window_size) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnWindowUpdate:" << FORMAT_ARG(connection_id_)
      << FORMAT_ARG(stream_id) << FORMAT_ARG(delta_window_size);
  wrapped_->OnWindowUpdate(stream_id, delta_window_size);
}

void Http2TraceLogger::OnPushPromise(SpdyStreamId original_stream_id,
                                     SpdyStreamId promised_stream_id,
                                     bool end) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnPushPromise:" << FORMAT_ARG(connection_id_)
      << FORMAT_ARG(original_stream_id) << FORMAT_ARG(promised_stream_id)
      << FORMAT_ARG(end);
  wrapped_->OnPushPromise(original_stream_id, promised_stream_id, end);
}

void Http2TraceLogger::OnContinuation(SpdyStreamId stream_id,
                                      size_t payload_length, bool end) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnContinuation:" << FORMAT_ARG(connection_id_)
      << FORMAT_ARG(stream_id) << FORMAT_ARG(payload_length) << FORMAT_ARG(end);
  wrapped_->OnContinuation(stream_id, payload_length, end);
}

void Http2TraceLogger::OnAltSvc(
    SpdyStreamId stream_id, absl::string_view origin,
    const SpdyAltSvcWireFormat::AlternativeServiceVector& altsvc_vector) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnAltSvc:" << FORMAT_ARG(connection_id_) << FORMAT_ARG(stream_id)
      << FORMAT_ARG(origin) << " altsvc_vector="
      << LogContainer(altsvc_vector, LogAlternativeService());
  wrapped_->OnAltSvc(stream_id, origin, altsvc_vector);
}

void Http2TraceLogger::OnPriority(SpdyStreamId stream_id,
                                  SpdyStreamId parent_stream_id, int weight,
                                  bool exclusive) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnPriority:" << FORMAT_ARG(connection_id_) << FORMAT_ARG(stream_id)
      << FORMAT_ARG(parent_stream_id) << FORMAT_INT_ARG(weight)
      << FORMAT_ARG(exclusive);
  wrapped_->OnPriority(stream_id, parent_stream_id, weight, exclusive);
}

void Http2TraceLogger::OnPriorityUpdate(
    SpdyStreamId prioritized_stream_id,
    absl::string_view priority_field_value) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnPriorityUpdate:" << FORMAT_ARG(connection_id_)
      << FORMAT_ARG(prioritized_stream_id) << FORMAT_ARG(priority_field_value);
  wrapped_->OnPriorityUpdate(prioritized_stream_id, priority_field_value);
}

bool Http2TraceLogger::OnUnknownFrame(SpdyStreamId stream_id,
                                      uint8_t frame_type) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnUnknownFrame:" << FORMAT_ARG(connection_id_)
      << FORMAT_ARG(stream_id) << FORMAT_INT_ARG(frame_type);
  return wrapped_->OnUnknownFrame(stream_id, frame_type);
}

void Http2TraceLogger::OnUnknownFrameStart(spdy::SpdyStreamId stream_id,
                                           size_t length, uint8_t type,
                                           uint8_t flags) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnUnknownFrameStart:" << FORMAT_ARG(connection_id_)
      << FORMAT_ARG(stream_id) << FORMAT_ARG(length) << FORMAT_INT_ARG(type)
      << FORMAT_INT_ARG(flags);
  wrapped_->OnUnknownFrameStart(stream_id, length, type, flags);
}

void Http2TraceLogger::OnUnknownFramePayload(spdy::SpdyStreamId stream_id,
                                             absl::string_view payload) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "OnUnknownFramePayload:" << FORMAT_ARG(connection_id_)
      << FORMAT_ARG(stream_id) << " length=" << payload.size();
  wrapped_->OnUnknownFramePayload(stream_id, payload);
}

void Http2TraceLogger::LogReceivedHeaders() const {
  if (recording_headers_handler_ == nullptr) {
    // Trace logging was not enabled when the start of the header block was
    // received.
    return;
  }
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "Received headers;" << FORMAT_ARG(connection_id_) << " keys/values:"
      << recording_headers_handler_->decoded_block().DebugString()
      << " compressed_bytes="
      << recording_headers_handler_->compressed_header_bytes()
      << " uncompressed_bytes="
      << recording_headers_handler_->uncompressed_header_bytes();
}

void Http2FrameLogger::VisitRstStream(const SpdyRstStreamIR& rst_stream) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "Wrote SpdyRstStreamIR:" << FORMAT_ARG(connection_id_)
      << FORMAT_ATTR(rst_stream, stream_id)
      << " error_code=" << spdy::ErrorCodeToString(rst_stream.error_code());
}

void Http2FrameLogger::VisitSettings(const SpdySettingsIR& settings) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "Wrote SpdySettingsIR:" << FORMAT_ARG(connection_id_)
      << FORMAT_ATTR(settings, is_ack)
      << " values=" << LogContainer(settings.values(), LogSettingsEntry());
}

void Http2FrameLogger::VisitPing(const SpdyPingIR& ping) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "Wrote SpdyPingIR:" << FORMAT_ARG(connection_id_)
      << FORMAT_ATTR(ping, id) << FORMAT_ATTR(ping, is_ack);
}

void Http2FrameLogger::VisitGoAway(const SpdyGoAwayIR& goaway) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "Wrote SpdyGoAwayIR:" << FORMAT_ARG(connection_id_)
      << FORMAT_ATTR(goaway, last_good_stream_id)
      << " error_code=" << spdy::ErrorCodeToString(goaway.error_code())
      << FORMAT_ATTR(goaway, description);
}

void Http2FrameLogger::VisitHeaders(const SpdyHeadersIR& headers) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "Wrote SpdyHeadersIR:" << FORMAT_ARG(connection_id_)
      << FORMAT_ATTR(headers, stream_id) << FORMAT_ATTR(headers, fin)
      << FORMAT_ATTR(headers, has_priority) << FORMAT_INT_ATTR(headers, weight)
      << FORMAT_ATTR(headers, parent_stream_id)
      << FORMAT_ATTR(headers, exclusive) << FORMAT_ATTR(headers, padded)
      << FORMAT_ATTR(headers, padding_payload_len)
      << FORMAT_HEADER_BLOCK(headers);
}

void Http2FrameLogger::VisitWindowUpdate(
    const SpdyWindowUpdateIR& window_update) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "Wrote SpdyWindowUpdateIR:" << FORMAT_ARG(connection_id_)
      << FORMAT_ATTR(window_update, stream_id)
      << FORMAT_ATTR(window_update, delta);
}

void Http2FrameLogger::VisitPushPromise(const SpdyPushPromiseIR& push_promise) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "Wrote SpdyPushPromiseIR:" << FORMAT_ARG(connection_id_)
      << FORMAT_ATTR(push_promise, stream_id) << FORMAT_ATTR(push_promise, fin)
      << FORMAT_ATTR(push_promise, promised_stream_id)
      << FORMAT_ATTR(push_promise, padded)
      << FORMAT_ATTR(push_promise, padding_payload_len)
      << FORMAT_HEADER_BLOCK(push_promise);
}

void Http2FrameLogger::VisitContinuation(
    const SpdyContinuationIR& continuation) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "Wrote SpdyContinuationIR:" << FORMAT_ARG(connection_id_)
      << FORMAT_ATTR(continuation, stream_id)
      << FORMAT_ATTR(continuation, end_headers);
}

void Http2FrameLogger::VisitAltSvc(const SpdyAltSvcIR& altsvc) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "Wrote SpdyAltSvcIR:" << FORMAT_ARG(connection_id_)
      << FORMAT_ATTR(altsvc, stream_id) << FORMAT_ATTR(altsvc, origin)
      << " altsvc_vector="
      << LogContainer(altsvc.altsvc_vector(), LogAlternativeService());
}

void Http2FrameLogger::VisitPriority(const SpdyPriorityIR& priority) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "Wrote SpdyPriorityIR:" << FORMAT_ARG(connection_id_)
      << FORMAT_ATTR(priority, stream_id)
      << FORMAT_ATTR(priority, parent_stream_id)
      << FORMAT_INT_ATTR(priority, weight) << FORMAT_ATTR(priority, exclusive);
}

void Http2FrameLogger::VisitData(const SpdyDataIR& data) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "Wrote SpdyDataIR:" << FORMAT_ARG(connection_id_)
      << FORMAT_ATTR(data, stream_id) << FORMAT_ATTR(data, fin)
      << " data_len=" << data.data_len() << FORMAT_ATTR(data, padded)
      << FORMAT_ATTR(data, padding_payload_len);
}

void Http2FrameLogger::VisitPriorityUpdate(
    const spdy::SpdyPriorityUpdateIR& priority_update) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "Wrote SpdyPriorityUpdateIR:" << FORMAT_ARG(connection_id_)
      << FORMAT_ATTR(priority_update, stream_id)
      << FORMAT_ATTR(priority_update, prioritized_stream_id)
      << FORMAT_ATTR(priority_update, priority_field_value);
}

void Http2FrameLogger::VisitAcceptCh(
    const spdy::SpdyAcceptChIR& /*accept_ch*/) {
  QUICHE_BUG(bug_2794_2)
      << "Sending ACCEPT_CH frames is currently unimplemented.";
}

void Http2FrameLogger::VisitUnknown(const SpdyUnknownIR& ir) {
  HTTP2_TRACE_LOG(perspective_, is_enabled_)
      << "Wrote SpdyUnknownIR:" << FORMAT_ARG(connection_id_)
      << FORMAT_ATTR(ir, stream_id) << FORMAT_INT_ATTR(ir, type)
      << FORMAT_INT_ATTR(ir, flags) << FORMAT_ATTR(ir, length);
}

}  // namespace http2
```