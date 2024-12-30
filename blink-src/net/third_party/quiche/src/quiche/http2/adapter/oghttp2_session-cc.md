Response:
The user wants a summary of the C++ code in `net/third_party/quiche/src/quiche/http2/adapter/oghttp2_session.cc`. The summary should include:

1. **Functionality:** What does this code do?
2. **Relationship to JavaScript:** Does this code interact with JavaScript? If so, how?
3. **Logical Inference with examples:** If the code performs logical reasoning, provide example inputs and outputs.
4. **Common User/Programming Errors with examples:**  Highlight common mistakes when using this code.
5. **User Operations leading to this code:** Describe how a user action in a browser could eventually lead to this code being executed.
6. **Overall Functionality (Part 1):**  A concise summary of the code's purpose based on the first part of the file.

Let's break down the code section by section to determine its functionality:

*   **Includes:**  The file includes headers for standard C++ libraries, as well as specific headers from the `quiche` and `spdy` libraries. These headers suggest the code deals with HTTP/2 protocol handling, memory management, string manipulation, and potentially asynchronous operations.
*   **Namespaces:** The code resides within the `http2::adapter` namespace, suggesting it's an adapter for an HTTP/2 implementation.
*   **Anonymous Namespace:**  This section defines helper structs and functions:
    *   `ConnectionError`, `DataFrameHeaderInfo`, `SpdyFramerError`: Type aliases related to error handling and data frame information.
    *   Constants like `kMaxAllowedMetadataFrameSize`, `kDefaultHpackTableCapacity`, `kMaximumHpackTableCapacity`, `kSendError`. These suggest configuration options and error codes related to HTTP/2.
    *   `kHeadValue`: A constant string for the "HEAD" HTTP method.
    *   `FrameAttributeCollector`: A class that inherits from `spdy::SpdyFrameVisitor`. This class is used to extract information (frame type, stream ID, flags, error code) from different types of SPDY frames. This is crucial for logging and potentially decision-making based on frame attributes.
    *   `TracePerspectiveAsString`: A function that converts an `enum` representing the perspective (client or server) to a string. This is likely used for logging and debugging.
    *   `GetHttp2ErrorCode`: A function that maps `SpdyFramerError` to `Http2ErrorCode`. This handles error translation between different layers.
    *   `IsResponse`, `StatusIs1xx`: Helper functions for classifying HTTP responses.
    *   `HpackCapacityBound`:  A function to determine the HPACK encoder table capacity limit.
    *   `IsNonAckSettings`:  A function to identify SETTINGS frames that are not acknowledgments.
*   **`OgHttp2Session::PassthroughHeadersHandler`:** This nested class handles the processing of HTTP headers. It uses a `HeaderValidator` (or `NoopHeaderValidator`) to check the validity of headers. It interacts with the `Http2VisitorInterface` to notify the higher layer about header events.
*   **`OgHttp2Session::ProcessBytesResultVisitor`:**  A simple visitor to extract an `int64_t` value from different types of results from the `ProcessBytes` operation.
*   **`OgHttp2Session` Constructor:**  The constructor initializes various components:
    *   `visitor_`: A reference to an `Http2VisitorInterface`, indicating a dependency on a higher-level component for handling HTTP/2 events.
    *   `options_`: Configuration options for the session.
    *   Loggers (`receive_logger_`, `send_logger_`):  Used for debugging and tracing HTTP/2 frame processing.
    *   Header handlers (`headers_handler_`, `noop_headers_handler_`): For processing HTTP headers.
    *   Flow control manager (`connection_window_manager_`):  Handles connection-level flow control.
    *   Decoder (`decoder_`): Responsible for parsing incoming HTTP/2 frames.
    *   Encoder (`framer_.GetHpackEncoder()`):  Responsible for encoding outgoing HTTP/2 headers.
    *   Handles setting the connection preface for server sessions.
    *   Configures header validation and cookie crumbling.
*   **`OgHttp2Session` Methods:**  Several methods for managing stream data, windows, and HPACK tables.
*   **`ProcessBytes` and `ProcessBytesImpl`:** These methods are central to the class. They take raw byte input, handle the connection preface (if applicable), and pass the bytes to the decoder for processing. They also handle error conditions.

Based on this initial analysis, here's a summary of the functionalities in this part of the file:

1. **HTTP/2 Session Management:** This code defines the `OgHttp2Session` class, which appears to be a core component for managing an HTTP/2 connection. It handles the reception and processing of HTTP/2 frames.
2. **Header Processing and Validation:** The `PassthroughHeadersHandler` is responsible for validating incoming HTTP headers based on provided options and notifying a visitor interface about header events.
3. **Frame Handling:** The code uses `spdy::SpdyFramer` for serializing outgoing frames and `Http2DecoderAdapter` for parsing incoming frames. The `FrameAttributeCollector` helps extract information from frames.
4. **Flow Control:** The `connection_window_manager_` manages connection-level flow control, and methods like `GetStreamSendWindowSize`, `GetStreamReceiveWindowSize` provide access to window information.
5. **HPACK Encoding/Decoding:** The code interacts with HPACK encoders and decoders for header compression and decompression. It allows configuration of the HPACK table size.
6. **Error Handling:**  The code includes mechanisms for detecting and handling HTTP/2 errors.
7. **Logging and Debugging:**  Loggers are integrated to trace the processing of HTTP/2 frames, which is essential for debugging.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/http2/adapter/oghttp2_session.cc` 文件的第一部分。根据你提供的代码，我们可以归纳出以下功能：

**主要功能:**

*   **HTTP/2 会话管理:**  `OgHttp2Session` 类是实现 HTTP/2 会话的核心。它负责处理 HTTP/2 连接的生命周期，包括接收和发送帧、管理流、处理头部和数据等。
*   **接收数据处理:** `ProcessBytes` 方法负责接收并处理来自网络的原始字节流。它会处理连接前导码（Connection Preface），并将字节流传递给内部的 HTTP/2 解码器 (`decoder_`) 进行帧解析。
*   **HTTP 头部处理和校验:** `PassthroughHeadersHandler` 类负责处理接收到的 HTTP 头部。它可以选择性地使用 `HeaderValidator` 或 `NoopHeaderValidator` 来校验头部的有效性，并通知上层的回调接口 (`Http2VisitorInterface`)。
*   **帧的序列化和反序列化:**  代码使用了 `spdy::SpdyFramer` 来序列化即将发送的 HTTP/2 帧，并使用 `Http2DecoderAdapter` 来反序列化接收到的帧。
*   **流管理:** 代码维护了一个流的映射 (`stream_map_`) 来跟踪活跃的 HTTP/2 流。它提供了一些方法来获取和设置流的用户数据，以及查询流的发送和接收窗口大小。
*   **流量控制:**  `connection_window_manager_` 负责管理连接级别的流量控制，防止发送方发送过多的数据导致接收方过载。
*   **HPACK 支持:**  代码集成了 HPACK 编码器和解码器，用于压缩和解压缩 HTTP 头部，提高传输效率。
*   **错误处理:** 代码定义了一些错误类型 (`ConnectionError`, `SpdyFramerError`)，并在处理过程中检测和报告错误。

**与 JavaScript 的关系:**

虽然这段 C++ 代码本身不直接包含 JavaScript，但它在 Chromium 网络栈中扮演着关键角色，处理浏览器发出的 HTTP/2 请求和接收到的响应。  当 JavaScript 代码（例如，通过 `fetch` API 发起网络请求）触发一个 HTTP/2 请求时，Chromium 的网络栈会使用这个 C++ 代码来处理底层的 HTTP/2 协议细节。

**举例说明:**

1. **JavaScript 发起请求:**
    ```javascript
    fetch('https://example.com/data')
      .then(response => response.json())
      .then(data => console.log(data));
    ```
    当这段 JavaScript 代码执行时，浏览器会创建一个 HTTP/2 请求。这个请求的头部（例如 `Host`, `User-Agent` 等）会被编码成 HTTP/2 HEADERS 帧。`OgHttp2Session` 的实例会负责序列化这个帧，并将其发送到服务器。服务器返回的响应头部和数据帧也会由 `OgHttp2Session` 接收和解析，然后传递给上层，最终被 JavaScript 的 `fetch` API 的 Promise 处理。

2. **服务器推送 (Server Push):**
    如果服务器向浏览器推送资源，`OgHttp2Session` 会接收并处理 PUSH_PROMISE 帧和后续的 HEADERS 和 DATA 帧。虽然这段代码本身不涉及 JavaScript 的执行，但浏览器会将推送的资源提供给 JavaScript 环境使用，例如通过 Service Worker 的 `push` 事件。

**逻辑推理及假设输入与输出:**

*   **假设输入:**  一个包含 HTTP/2 连接前导码和 SETTINGS 帧的字节流。
    ```
    "\x50\x52\x49\x20\x13\x0d\x0a\x0a\x00\x00\x00\x04\x00\x00\x00\x00"
    ```
*   **逻辑推理:** `ProcessBytesImpl` 方法会首先检查连接前导码是否匹配 (`kHttp2ConnectionHeaderPrefix`)。如果匹配，则移除前导码，并将剩余的字节交给解码器。解码器会解析 SETTINGS 帧。
*   **预期输出:**  如果前导码匹配，并且 SETTINGS 帧格式正确，`ProcessBytes` 将返回成功处理的字节数。`OgHttp2Session` 的内部状态会更新，例如记录了接收到的 SETTINGS 参数。

**用户或编程常见的使用错误:**

1. **未正确设置 `Http2VisitorInterface`:** 用户需要提供一个实现了 `Http2VisitorInterface` 的类来接收 `OgHttp2Session` 处理 HTTP/2 事件的通知。如果未正确实现或连接这个接口，将无法获取处理结果。
    *   **错误示例:** 创建 `OgHttp2Session` 时没有传入有效的 `Http2VisitorInterface` 实例。
    *   **现象:**  即使有数据接收或发送，也无法触发相应的回调，导致程序逻辑错误。

2. **在错误的时间调用发送方法:**  在连接建立之前或连接已关闭后尝试发送数据可能会导致错误。
    *   **错误示例:**  在客户端连接到服务器之前就调用 `Send()` 方法。
    *   **现象:**  可能导致程序崩溃或发送失败。

3. **错误处理不当:**  `ProcessBytes` 方法可能会返回错误代码。如果用户没有检查并处理这些错误，可能会导致程序行为异常。
    *   **错误示例:**  忽略 `ProcessBytes` 的返回值，假设数据总是被成功处理。
    *   **现象:**  当接收到格式错误的帧时，程序可能继续执行，导致状态不一致。

**用户操作到达此处的调试线索:**

1. **用户在浏览器地址栏输入 URL 并访问一个 HTTPS 网站:**  如果网站支持 HTTP/2，浏览器会尝试与服务器建立 HTTP/2 连接。这个过程涉及到发送连接前导码和 SETTINGS 帧，`OgHttp2Session` 会负责处理这些初始步骤。
2. **用户点击网页上的链接或按钮，触发 AJAX 请求:**  如果当前连接是 HTTP/2 连接，浏览器会创建新的 HTTP/2 流来发送请求。`OgHttp2Session` 会参与序列化请求头部和数据，并将其发送到服务器。
3. **用户浏览一个使用了服务器推送的网站:** 当服务器推送资源时，`OgHttp2Session` 会接收服务器发送的 PUSH_PROMISE 和相关的帧。开发者可以通过查看网络面板或者使用抓包工具来观察这些帧的交互，从而定位到 `OgHttp2Session` 的处理过程。

**归纳一下它的功能 (第 1 部分):**

总而言之，这段代码是 Chromium 中负责处理 HTTP/2 会话的核心组件。它处理底层 HTTP/2 协议的细节，包括接收和解析帧、处理头部、管理流、进行流量控制和支持 HPACK 压缩。它作为网络栈的一部分，为浏览器与支持 HTTP/2 的服务器进行通信提供了基础。虽然它本身是 C++ 代码，但它的功能直接支撑了 JavaScript 发起的网络请求和浏览器接收到的网络响应。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/oghttp2_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
#include "quiche/http2/adapter/oghttp2_session.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/cleanup/cleanup.h"
#include "absl/memory/memory.h"
#include "absl/strings/escaping.h"
#include "quiche/http2/adapter/header_validator.h"
#include "quiche/http2/adapter/http2_protocol.h"
#include "quiche/http2/adapter/http2_util.h"
#include "quiche/http2/adapter/http2_visitor_interface.h"
#include "quiche/http2/adapter/noop_header_validator.h"
#include "quiche/http2/adapter/oghttp2_util.h"
#include "quiche/http2/core/spdy_protocol.h"
#include "quiche/common/quiche_callbacks.h"

namespace http2 {
namespace adapter {

namespace {

using ConnectionError = Http2VisitorInterface::ConnectionError;
using DataFrameHeaderInfo = Http2VisitorInterface::DataFrameHeaderInfo;
using SpdyFramerError = Http2DecoderAdapter::SpdyFramerError;

using ::spdy::SpdySettingsIR;

const uint32_t kMaxAllowedMetadataFrameSize = 65536u;
const uint32_t kDefaultHpackTableCapacity = 4096u;
const uint32_t kMaximumHpackTableCapacity = 65536u;

// Corresponds to NGHTTP2_ERR_CALLBACK_FAILURE.
const int kSendError = -902;

constexpr absl::string_view kHeadValue = "HEAD";

// TODO(birenroy): Consider incorporating spdy::FlagsSerializionVisitor here.
class FrameAttributeCollector : public spdy::SpdyFrameVisitor {
 public:
  FrameAttributeCollector() = default;
  void VisitData(const spdy::SpdyDataIR& data) override {
    frame_type_ = static_cast<uint8_t>(data.frame_type());
    stream_id_ = data.stream_id();
    flags_ =
        (data.fin() ? END_STREAM_FLAG : 0) | (data.padded() ? PADDED_FLAG : 0);
  }
  void VisitHeaders(const spdy::SpdyHeadersIR& headers) override {
    frame_type_ = static_cast<uint8_t>(headers.frame_type());
    stream_id_ = headers.stream_id();
    flags_ = END_HEADERS_FLAG | (headers.fin() ? END_STREAM_FLAG : 0) |
             (headers.padded() ? PADDED_FLAG : 0) |
             (headers.has_priority() ? PRIORITY_FLAG : 0);
  }
  void VisitPriority(const spdy::SpdyPriorityIR& priority) override {
    frame_type_ = static_cast<uint8_t>(priority.frame_type());
    frame_type_ = 2;
    stream_id_ = priority.stream_id();
  }
  void VisitRstStream(const spdy::SpdyRstStreamIR& rst_stream) override {
    frame_type_ = static_cast<uint8_t>(rst_stream.frame_type());
    frame_type_ = 3;
    stream_id_ = rst_stream.stream_id();
    error_code_ = rst_stream.error_code();
  }
  void VisitSettings(const spdy::SpdySettingsIR& settings) override {
    frame_type_ = static_cast<uint8_t>(settings.frame_type());
    frame_type_ = 4;
    flags_ = (settings.is_ack() ? ACK_FLAG : 0);
  }
  void VisitPushPromise(const spdy::SpdyPushPromiseIR& push_promise) override {
    frame_type_ = static_cast<uint8_t>(push_promise.frame_type());
    frame_type_ = 5;
    stream_id_ = push_promise.stream_id();
    flags_ = (push_promise.padded() ? PADDED_FLAG : 0);
  }
  void VisitPing(const spdy::SpdyPingIR& ping) override {
    frame_type_ = static_cast<uint8_t>(ping.frame_type());
    frame_type_ = 6;
    flags_ = (ping.is_ack() ? ACK_FLAG : 0);
  }
  void VisitGoAway(const spdy::SpdyGoAwayIR& goaway) override {
    frame_type_ = static_cast<uint8_t>(goaway.frame_type());
    frame_type_ = 7;
    error_code_ = goaway.error_code();
  }
  void VisitWindowUpdate(
      const spdy::SpdyWindowUpdateIR& window_update) override {
    frame_type_ = static_cast<uint8_t>(window_update.frame_type());
    frame_type_ = 8;
    stream_id_ = window_update.stream_id();
  }
  void VisitContinuation(
      const spdy::SpdyContinuationIR& continuation) override {
    frame_type_ = static_cast<uint8_t>(continuation.frame_type());
    stream_id_ = continuation.stream_id();
    flags_ = continuation.end_headers() ? END_HEADERS_FLAG : 0;
  }
  void VisitUnknown(const spdy::SpdyUnknownIR& unknown) override {
    frame_type_ = static_cast<uint8_t>(unknown.frame_type());
    stream_id_ = unknown.stream_id();
    flags_ = unknown.flags();
  }
  void VisitAltSvc(const spdy::SpdyAltSvcIR& /*altsvc*/) override {}
  void VisitPriorityUpdate(
      const spdy::SpdyPriorityUpdateIR& /*priority_update*/) override {}
  void VisitAcceptCh(const spdy::SpdyAcceptChIR& /*accept_ch*/) override {}

  uint32_t stream_id() { return stream_id_; }
  uint32_t error_code() { return error_code_; }
  uint8_t frame_type() { return frame_type_; }
  uint8_t flags() { return flags_; }

 private:
  uint32_t stream_id_ = 0;
  uint32_t error_code_ = 0;
  uint8_t frame_type_ = 0;
  uint8_t flags_ = 0;
};

absl::string_view TracePerspectiveAsString(Perspective p) {
  switch (p) {
    case Perspective::kClient:
      return "OGHTTP2_CLIENT";
    case Perspective::kServer:
      return "OGHTTP2_SERVER";
  }
  return "OGHTTP2_SERVER";
}

Http2ErrorCode GetHttp2ErrorCode(SpdyFramerError error) {
  switch (error) {
    case SpdyFramerError::SPDY_NO_ERROR:
      return Http2ErrorCode::HTTP2_NO_ERROR;
    case SpdyFramerError::SPDY_INVALID_STREAM_ID:
    case SpdyFramerError::SPDY_INVALID_CONTROL_FRAME:
    case SpdyFramerError::SPDY_INVALID_PADDING:
    case SpdyFramerError::SPDY_INVALID_DATA_FRAME_FLAGS:
    case SpdyFramerError::SPDY_UNEXPECTED_FRAME:
      return Http2ErrorCode::PROTOCOL_ERROR;
    case SpdyFramerError::SPDY_CONTROL_PAYLOAD_TOO_LARGE:
    case SpdyFramerError::SPDY_INVALID_CONTROL_FRAME_SIZE:
    case SpdyFramerError::SPDY_OVERSIZED_PAYLOAD:
      return Http2ErrorCode::FRAME_SIZE_ERROR;
    case SpdyFramerError::SPDY_DECOMPRESS_FAILURE:
    case SpdyFramerError::SPDY_HPACK_INDEX_VARINT_ERROR:
    case SpdyFramerError::SPDY_HPACK_NAME_LENGTH_VARINT_ERROR:
    case SpdyFramerError::SPDY_HPACK_VALUE_LENGTH_VARINT_ERROR:
    case SpdyFramerError::SPDY_HPACK_NAME_TOO_LONG:
    case SpdyFramerError::SPDY_HPACK_VALUE_TOO_LONG:
    case SpdyFramerError::SPDY_HPACK_NAME_HUFFMAN_ERROR:
    case SpdyFramerError::SPDY_HPACK_VALUE_HUFFMAN_ERROR:
    case SpdyFramerError::SPDY_HPACK_MISSING_DYNAMIC_TABLE_SIZE_UPDATE:
    case SpdyFramerError::SPDY_HPACK_INVALID_INDEX:
    case SpdyFramerError::SPDY_HPACK_INVALID_NAME_INDEX:
    case SpdyFramerError::SPDY_HPACK_DYNAMIC_TABLE_SIZE_UPDATE_NOT_ALLOWED:
    case SpdyFramerError::
        SPDY_HPACK_INITIAL_DYNAMIC_TABLE_SIZE_UPDATE_IS_ABOVE_LOW_WATER_MARK:
    case SpdyFramerError::
        SPDY_HPACK_DYNAMIC_TABLE_SIZE_UPDATE_IS_ABOVE_ACKNOWLEDGED_SETTING:
    case SpdyFramerError::SPDY_HPACK_TRUNCATED_BLOCK:
    case SpdyFramerError::SPDY_HPACK_FRAGMENT_TOO_LONG:
    case SpdyFramerError::SPDY_HPACK_COMPRESSED_HEADER_SIZE_EXCEEDS_LIMIT:
      return Http2ErrorCode::COMPRESSION_ERROR;
    case SpdyFramerError::SPDY_INTERNAL_FRAMER_ERROR:
    case SpdyFramerError::SPDY_STOP_PROCESSING:
    case SpdyFramerError::LAST_ERROR:
      return Http2ErrorCode::INTERNAL_ERROR;
  }
  return Http2ErrorCode::INTERNAL_ERROR;
}

bool IsResponse(HeaderType type) {
  return type == HeaderType::RESPONSE_100 || type == HeaderType::RESPONSE;
}

bool StatusIs1xx(absl::string_view status) {
  return status.size() == 3 && status[0] == '1';
}

// Returns the upper bound on HPACK encoder table capacity. If not specified in
// the Options, a reasonable default upper bound is used.
uint32_t HpackCapacityBound(const OgHttp2Session::Options& o) {
  return o.max_hpack_encoding_table_capacity.value_or(
      kMaximumHpackTableCapacity);
}

bool IsNonAckSettings(const spdy::SpdyFrameIR& frame) {
  return frame.frame_type() == spdy::SpdyFrameType::SETTINGS &&
         !reinterpret_cast<const SpdySettingsIR&>(frame).is_ack();
}

}  // namespace

OgHttp2Session::PassthroughHeadersHandler::PassthroughHeadersHandler(
    OgHttp2Session& session, Http2VisitorInterface& visitor)
    : session_(session), visitor_(visitor) {
  if (session_.options_.validate_http_headers) {
    QUICHE_VLOG(2) << "instantiating regular header validator";
    validator_ = std::make_unique<HeaderValidator>();
    if (session_.options_.validate_path) {
      validator_->SetValidatePath();
    }
    if (session_.options_.allow_fragment_in_path) {
      validator_->SetAllowFragmentInPath();
    }
    if (session_.options_.allow_different_host_and_authority) {
      validator_->SetAllowDifferentHostAndAuthority();
    }
  } else {
    QUICHE_VLOG(2) << "instantiating noop header validator";
    validator_ = std::make_unique<NoopHeaderValidator>();
  }
}

void OgHttp2Session::PassthroughHeadersHandler::OnHeaderBlockStart() {
  Reset();
  const bool status = visitor_.OnBeginHeadersForStream(stream_id_);
  if (!status) {
    QUICHE_VLOG(1)
        << "Visitor rejected header block, returning HEADER_CONNECTION_ERROR";
    SetResult(Http2VisitorInterface::HEADER_CONNECTION_ERROR);
  }
  validator_->StartHeaderBlock();
}

Http2VisitorInterface::OnHeaderResult InterpretHeaderStatus(
    HeaderValidator::HeaderStatus status) {
  switch (status) {
    case HeaderValidator::HEADER_OK:
    case HeaderValidator::HEADER_SKIP:
      return Http2VisitorInterface::HEADER_OK;
    case HeaderValidator::HEADER_FIELD_INVALID:
      return Http2VisitorInterface::HEADER_FIELD_INVALID;
    case HeaderValidator::HEADER_FIELD_TOO_LONG:
      return Http2VisitorInterface::HEADER_RST_STREAM;
  }
  return Http2VisitorInterface::HEADER_CONNECTION_ERROR;
}

void OgHttp2Session::PassthroughHeadersHandler::OnHeader(
    absl::string_view key, absl::string_view value) {
  if (error_encountered_) {
    QUICHE_VLOG(2) << "Early return; status not HEADER_OK";
    return;
  }
  const HeaderValidator::HeaderStatus validation_result =
      validator_->ValidateSingleHeader(key, value);
  if (validation_result == HeaderValidator::HEADER_SKIP) {
    return;
  }
  if (validation_result != HeaderValidator::HEADER_OK) {
    QUICHE_VLOG(2) << "Header validation failed with result "
                   << static_cast<int>(validation_result);
    SetResult(InterpretHeaderStatus(validation_result));
    return;
  }
  const Http2VisitorInterface::OnHeaderResult result =
      visitor_.OnHeaderForStream(stream_id_, key, value);
  SetResult(result);
}

void OgHttp2Session::PassthroughHeadersHandler::OnHeaderBlockEnd(
    size_t /* uncompressed_header_bytes */,
    size_t /* compressed_header_bytes */) {
  if (error_encountered_) {
    // The error has already been handled.
    return;
  }
  if (!validator_->FinishHeaderBlock(type_)) {
    QUICHE_VLOG(1) << "FinishHeaderBlock returned false; returning "
                   << "HEADER_HTTP_MESSAGING";
    SetResult(Http2VisitorInterface::HEADER_HTTP_MESSAGING);
    return;
  }
  if (frame_contains_fin_ && IsResponse(type_) &&
      StatusIs1xx(status_header())) {
    QUICHE_VLOG(1) << "Unexpected end of stream without final headers";
    SetResult(Http2VisitorInterface::HEADER_HTTP_MESSAGING);
    return;
  }
  const bool result = visitor_.OnEndHeadersForStream(stream_id_);
  if (!result) {
    session_.fatal_visitor_callback_failure_ = true;
    session_.decoder_.StopProcessing();
  }
}

// TODO(diannahu): Add checks for request methods.
bool OgHttp2Session::PassthroughHeadersHandler::CanReceiveBody() const {
  switch (header_type()) {
    case HeaderType::REQUEST_TRAILER:
    case HeaderType::RESPONSE_TRAILER:
    case HeaderType::RESPONSE_100:
      return false;
    case HeaderType::RESPONSE:
      // 304 responses should not have a body:
      // https://httpwg.org/specs/rfc7230.html#rfc.section.3.3.2
      // Neither should 204 responses:
      // https://httpwg.org/specs/rfc7231.html#rfc.section.6.3.5
      return status_header() != "304" && status_header() != "204";
    case HeaderType::REQUEST:
      return true;
  }
  return true;
}

void OgHttp2Session::PassthroughHeadersHandler::SetResult(
    Http2VisitorInterface::OnHeaderResult result) {
  if (result != Http2VisitorInterface::HEADER_OK) {
    error_encountered_ = true;
    session_.OnHeaderStatus(stream_id_, result);
  }
}

// A visitor that extracts an int64_t from each type of a ProcessBytesResult.
struct OgHttp2Session::ProcessBytesResultVisitor {
  int64_t operator()(const int64_t bytes) const { return bytes; }

  int64_t operator()(const ProcessBytesError error) const {
    switch (error) {
      case ProcessBytesError::kUnspecified:
        return -1;
      case ProcessBytesError::kInvalidConnectionPreface:
        return -903;  // NGHTTP2_ERR_BAD_CLIENT_MAGIC
      case ProcessBytesError::kVisitorCallbackFailed:
        return -902;  // NGHTTP2_ERR_CALLBACK_FAILURE
    }
    return -1;
  }
};

OgHttp2Session::OgHttp2Session(Http2VisitorInterface& visitor, Options options)
    : visitor_(visitor),
      options_(options),
      event_forwarder_([this]() { return !latched_error_; }, *this),
      receive_logger_(
          &event_forwarder_, TracePerspectiveAsString(options.perspective),
          [logging_enabled = GetQuicheFlag(quiche_oghttp2_debug_trace)]() {
            return logging_enabled;
          },
          this),
      send_logger_(
          TracePerspectiveAsString(options.perspective),
          [logging_enabled = GetQuicheFlag(quiche_oghttp2_debug_trace)]() {
            return logging_enabled;
          },
          this),
      headers_handler_(*this, visitor),
      noop_headers_handler_(/*listener=*/nullptr),
      connection_window_manager_(
          kInitialFlowControlWindowSize,
          [this](size_t window_update_delta) {
            SendWindowUpdate(kConnectionStreamId, window_update_delta);
          },
          options.should_window_update_fn,
          /*update_window_on_notify=*/false),
      max_outbound_concurrent_streams_(
          options.remote_max_concurrent_streams.value_or(100u)) {
  decoder_.set_visitor(&receive_logger_);
  if (options_.max_header_list_bytes) {
    // Limit buffering of encoded HPACK data to 2x the decoded limit.
    decoder_.GetHpackDecoder().set_max_decode_buffer_size_bytes(
        2 * *options_.max_header_list_bytes);
    // Limit the total bytes accepted for HPACK decoding to 4x the limit.
    decoder_.GetHpackDecoder().set_max_header_block_bytes(
        4 * *options_.max_header_list_bytes);
  }
  if (IsServerSession()) {
    remaining_preface_ = {spdy::kHttp2ConnectionHeaderPrefix,
                          spdy::kHttp2ConnectionHeaderPrefixSize};
  }
  if (options_.max_header_field_size.has_value()) {
    headers_handler_.SetMaxFieldSize(*options_.max_header_field_size);
  }
  headers_handler_.SetAllowObsText(options_.allow_obs_text);
  if (!options_.crumble_cookies) {
    // As seen in https://github.com/envoyproxy/envoy/issues/32611, some HTTP/2
    // endpoints don't properly handle multiple `Cookie` header fields.
    framer_.GetHpackEncoder()->DisableCookieCrumbling();
  }
}

OgHttp2Session::~OgHttp2Session() {}

void OgHttp2Session::SetStreamUserData(Http2StreamId stream_id,
                                       void* user_data) {
  auto it = stream_map_.find(stream_id);
  if (it != stream_map_.end()) {
    it->second.user_data = user_data;
  }
}

void* OgHttp2Session::GetStreamUserData(Http2StreamId stream_id) {
  auto it = stream_map_.find(stream_id);
  if (it != stream_map_.end()) {
    return it->second.user_data;
  }
  auto p = pending_streams_.find(stream_id);
  if (p != pending_streams_.end()) {
    return p->second.user_data;
  }
  return nullptr;
}

bool OgHttp2Session::ResumeStream(Http2StreamId stream_id) {
  auto it = stream_map_.find(stream_id);
  if (it == stream_map_.end() || !HasMoreData(it->second) ||
      !write_scheduler_.StreamRegistered(stream_id)) {
    return false;
  }
  it->second.data_deferred = false;
  write_scheduler_.MarkStreamReady(stream_id, /*add_to_front=*/false);
  return true;
}

int OgHttp2Session::GetStreamSendWindowSize(Http2StreamId stream_id) const {
  auto it = stream_map_.find(stream_id);
  if (it != stream_map_.end()) {
    return it->second.send_window;
  }
  return -1;
}

int OgHttp2Session::GetStreamReceiveWindowLimit(Http2StreamId stream_id) const {
  auto it = stream_map_.find(stream_id);
  if (it != stream_map_.end()) {
    return it->second.window_manager.WindowSizeLimit();
  }
  return -1;
}

int OgHttp2Session::GetStreamReceiveWindowSize(Http2StreamId stream_id) const {
  auto it = stream_map_.find(stream_id);
  if (it != stream_map_.end()) {
    return it->second.window_manager.CurrentWindowSize();
  }
  return -1;
}

int OgHttp2Session::GetReceiveWindowSize() const {
  return connection_window_manager_.CurrentWindowSize();
}

int OgHttp2Session::GetHpackEncoderDynamicTableSize() const {
  const spdy::HpackEncoder* encoder = framer_.GetHpackEncoder();
  return encoder == nullptr ? 0 : encoder->GetDynamicTableSize();
}

int OgHttp2Session::GetHpackEncoderDynamicTableCapacity() const {
  const spdy::HpackEncoder* encoder = framer_.GetHpackEncoder();
  return encoder == nullptr ? kDefaultHpackTableCapacity
                            : encoder->CurrentHeaderTableSizeSetting();
}

int OgHttp2Session::GetHpackDecoderDynamicTableSize() const {
  return decoder_.GetHpackDecoder().GetDynamicTableSize();
}

int OgHttp2Session::GetHpackDecoderSizeLimit() const {
  return decoder_.GetHpackDecoder().GetCurrentHeaderTableSizeSetting();
}

int64_t OgHttp2Session::ProcessBytes(absl::string_view bytes) {
  QUICHE_VLOG(2) << TracePerspectiveAsString(options_.perspective)
                 << " processing [" << absl::CEscape(bytes) << "]";
  return absl::visit(ProcessBytesResultVisitor(), ProcessBytesImpl(bytes));
}

absl::variant<int64_t, OgHttp2Session::ProcessBytesError>
OgHttp2Session::ProcessBytesImpl(absl::string_view bytes) {
  if (processing_bytes_) {
    QUICHE_VLOG(1) << "Returning early; already processing bytes.";
    return 0;
  }
  processing_bytes_ = true;
  auto cleanup = absl::MakeCleanup([this]() { processing_bytes_ = false; });

  if (options_.blackhole_data_on_connection_error && latched_error_) {
    return static_cast<int64_t>(bytes.size());
  }

  int64_t preface_consumed = 0;
  if (!remaining_preface_.empty()) {
    QUICHE_VLOG(2) << "Preface bytes remaining: " << remaining_preface_.size();
    // decoder_ does not understand the client connection preface.
    size_t min_size = std::min(remaining_preface_.size(), bytes.size());
    if (!absl::StartsWith(remaining_preface_, bytes.substr(0, min_size))) {
      // Preface doesn't match!
      QUICHE_DLOG(INFO) << "Preface doesn't match! Expected: ["
                        << absl::CEscape(remaining_preface_) << "], actual: ["
                        << absl::CEscape(bytes) << "]";
      LatchErrorAndNotify(Http2ErrorCode::PROTOCOL_ERROR,
                          ConnectionError::kInvalidConnectionPreface);
      return ProcessBytesError::kInvalidConnectionPreface;
    }
    remaining_preface_.remove_prefix(min_size);
    bytes.remove_prefix(min_size);
    if (!remaining_preface_.empty()) {
      QUICHE_VLOG(2) << "Preface bytes remaining: "
                     << remaining_preface_.size();
      return static_cast<int64_t>(min_size);
    }
    preface_consumed = min_size;
  }
  int64_t result = decoder_.ProcessInput(bytes.data(), bytes.size());
  QUICHE_VLOG(2) << "ProcessBytes result: " << result;
  if (fatal_visitor_callback_failure_) {
    QUICHE_DCHECK(latched_error_);
    QUICHE_VLOG(2) << "Visitor callback failed while processing bytes.";
    return ProcessBytesError::kVisitorCallbackFailed;
  }
  if (latched_error_ || result < 0) {
    QUICHE_VLOG(2) << "ProcessBytes encountered an error.";
    if (options_.blackhole_data_on_connection_error) {
      return static_cast<int64_t>(bytes.size() + preface_consumed);
    } else {
      return ProcessBytesError::kUnspecified;
    }
  }
  return result + preface_consumed;
}

int OgHttp2Session::Consume(Http2StreamId stream_id, size_t num_bytes) {
  auto it = stream_map_.find(stream_id);
  if (it == stream_map_.end()) {
    QUICHE_VLOG(1) << "Stream " << stream_id << " not found when consuming "
                   << num_bytes << " bytes";
  } else {
    it->second.window_manager.MarkDataFlushed(num_bytes);
  }
  connection_window_manager_.MarkDataFlushed(num_bytes);
  return 0;  // Remove?
}

void OgHttp2Session::StartGracefulShutdown() {
  if (IsServerSession()) {
    if (!queued_goaway_) {
      EnqueueFrame(std::make_unique<spdy::SpdyGoAwayIR>(
          std::numeric_limits<int32_t>::max(), spdy::ERROR_CODE_NO_ERROR,
          "graceful_shutdown"));
    }
  } else {
    QUICHE_LOG(ERROR) << "Graceful shutdown not needed for clients.";
  }
}

void OgHttp2Session::EnqueueFrame(std::unique_ptr<spdy::SpdyFrameIR> frame) {
  if (queued_immediate_goaway_) {
    // Do not allow additional frames to be enqueued after the GOAWAY.
    return;
  }

  const bool is_non_ack_settings = IsNonAckSettings(*frame);
  MaybeSetupPreface(is_non_ack_settings);

  if (frame->frame_type() == spdy::SpdyFrameType::GOAWAY) {
    queued_goaway_ = true;
    if (latched_error_) {
      PrepareForImmediateGoAway();
    }
  } else if (frame->fin() ||
             frame->frame_type() == spdy::SpdyFrameType::RST_STREAM) {
    auto iter = stream_map_.find(frame->stream_id());
    if (iter != stream_map_.end()) {
      iter->second.half_closed_local = true;
    }
    if (frame->frame_type() == spdy::SpdyFrameType::RST_STREAM) {
      // TODO(diannahu): Condition on existence in the stream map?
      streams_reset_.insert(frame->stream_id());
    }
  } else if (frame->frame_type() == spdy::SpdyFrameType::WINDOW_UPDATE) {
    UpdateReceiveWindow(
        frame->stream_id(),
        reinterpret_cast<spdy::SpdyWindowUpdateIR&>(*frame).delta());
  } else if (is_non_ack_settings) {
    HandleOutboundSettings(
        *reinterpret_cast<spdy::SpdySettingsIR*>(frame.get()));
  }
  if (frame->stream_id() != 0) {
    auto result = queued_frames_.insert({frame->stream_id(), 1});
    if (!result.second) {
      ++(result.first->second);
    }
  }
  frames_.push_back(std::move(frame));
}

int OgHttp2Session::Send() {
  if (sending_) {
    QUICHE_VLOG(1) << TracePerspectiveAsString(options_.perspective)
                   << " returning early; already sending.";
    return 0;
  }
  sending_ = true;
  auto cleanup = absl::MakeCleanup([this]() { sending_ = false; });

  if (fatal_send_error_) {
    return kSendError;
  }

  MaybeSetupPreface(/*sending_outbound_settings=*/false);

  SendResult continue_writing = SendQueuedFrames();
  if (queued_immediate_goaway_) {
    // If an immediate GOAWAY was queued, then the above flush either sent the
    // GOAWAY or buffered it to be sent on the next successful flush. In either
    // case, return early here to avoid sending other frames.
    return InterpretSendResult(continue_writing);
  }
  // Notify on new/pending streams closed due to GOAWAY receipt.
  CloseGoAwayRejectedStreams();
  // Wake streams for writes.
  while (continue_writing == SendResult::SEND_OK && HasReadyStream()) {
    const Http2StreamId stream_id = GetNextReadyStream();
    // TODO(birenroy): Add a return value to indicate write blockage, so streams
    // aren't woken unnecessarily.
    QUICHE_VLOG(1) << "Waking stream " << stream_id << " for writes.";
    continue_writing = WriteForStream(stream_id);
  }
  if (continue_writing == SendResult::SEND_OK) {
    continue_writing = SendQueuedFrames();
  }
  return InterpretSendResult(continue_writing);
}

int OgHttp2Session::InterpretSendResult(SendResult result) {
  if (result == SendResult::SEND_ERROR) {
    fatal_send_error_ = true;
    return kSendError;
  } else {
    return 0;
  }
}

bool OgHttp2Session::HasReadyStream() const {
  return !trailers_ready_.empty() ||
         (write_scheduler_.HasReadyStreams() && connection_send_window_ > 0);
}

Http2StreamId OgHttp2Session::GetNextReadyStream() {
  QUICHE_DCHECK(HasReadyStream());
  if (!trailers_ready_.empty()) {
    const Http2StreamId stream_id = *trailers_ready_.begin();
    // WriteForStream() will re-mark the stream as ready, if necessary.
    write_scheduler_.MarkStreamNotReady(stream_id);
    trailers_ready_.erase(trailers_ready_.begin());
    return stream_id;
  }
  return write_scheduler_.PopNextReadyStream();
}

int32_t OgHttp2Session::SubmitRequestInternal(
    absl::Span<const Header> headers,
    std::unique_ptr<DataFrameSource> data_source, bool end_stream,
    void* user_data) {
  // TODO(birenroy): return an error for the incorrect perspective
  const Http2StreamId stream_id = next_stream_id_;
  next_stream_id_ += 2;
  if (!pending_streams_.empty() || !CanCreateStream()) {
    // TODO(diannahu): There should probably be a limit to the number of allowed
    // pending streams.
    pending_streams_.insert(
        {stream_id,
         PendingStreamState{ToHeaderBlock(headers), std::move(data_source),
                            user_data, end_stream}});
    StartPendingStreams();
  } else {
    StartRequest(stream_id, ToHeaderBlock(headers), std::move(data_source),
                 user_data, end_stream);
  }
  return stream_id;
}

int OgHttp2Session::SubmitResponseInternal(
    Http2StreamId stream_id, absl::Span<const Header> headers,
    std::unique_ptr<DataFrameSource> data_source, bool end_stream) {
  // TODO(birenroy): return an error for the incorrect perspective
  auto iter = stream_map_.find(stream_id);
  if (iter == stream_map_.end()) {
    QUICHE_LOG(ERROR) << "Unable to find stream " << stream_id;
    return -501;  // NGHTTP2_ERR_INVALID_ARGUMENT
  }
  if (data_source != nullptr) {
    // Add data source to stream state
    iter->second.outbound_body = std::move(data_source);
    write_scheduler_.MarkStreamReady(stream_id, false);
  } else if (!end_stream) {
    iter->second.check_visitor_for_body = true;
    write_scheduler_.MarkStreamReady(stream_id, false);
  }
  SendHeaders(stream_id, ToHeaderBlock(headers), end_stream);
  return 0;
}

OgHttp2Session::SendResult OgHttp2Session::MaybeSendBufferedData() {
  int64_t result = std::numeric_limits<int64_t>::max();
  while (result > 0 && !buffered_data_.Empty()) {
    result = visitor_.OnReadyToSend(buffered_data_.GetPrefix());
    if (result > 0) {
      buffered_data_.RemovePrefix(result);
    }
  }
  if (result < 0) {
    LatchErrorAndNotify(Http2ErrorCode::INTERNAL_ERROR,
                        ConnectionError::kSendError);
    return SendResult::SEND_ERROR;
  }
  return buffered_data_.Empty() ? SendResult::SEND_OK
                                : SendResult::SEND_BLOCKED;
}

OgHttp2Session::SendResult OgHttp2Session::SendQueuedFrames() {
  // Flush any serialized prefix.
  if (const SendResult result = MaybeSendBufferedData();
      result != SendResult::SEND_OK) {
    return result;
  }
  // Serialize and send frames in the queue.
  while (!frames_.empty()) {
    const auto& frame_ptr = frames_.front();
    FrameAttributeCollector c;
    frame_ptr->Visit(&c);

    // DATA frames should never be queued.
    QUICHE_DCHECK_NE(c.frame_type(), 0);

    const bool stream_reset =
        c.stream_id() != 0 && streams_reset_.count(c.stream_id()) > 0;
    if (stream_reset &&
        c.frame_type() != static_cast<uint8_t>(FrameType::RST_STREAM)) {
      // The stream has been reset, so any other remaining frames can be
      // skipped.
      // TODO(birenroy): inform the visitor of frames that are skipped.
      DecrementQueuedFrameCount(c.stream_id(), c.frame_type());
      frames_.pop_front();
      continue;
    } else if (!IsServerSession() && received_goaway_ &&
               c.stream_id() >
                   static_cast<uint32_t>(received_goaway_stream_id_)) {
      // This frame will be ignored by the server, so don't send it. The stream
      // associated with this frame should have been closed in OnGoAway().
      frames_.pop_front();
      continue;
    }
    // Frames can't accurately report their own length; the actual serialized
    // length must be used instead.
    spdy::SpdySerializedFrame frame = framer_.SerializeFrame(*frame_ptr);
    const size_t frame_payload_length = frame.size() - spdy::kFrameHeaderSize;
    frame_ptr->Visit(&send_logger_);
    visitor_.OnBeforeFrameSent(c.frame_type(), c.stream_id(),
                               frame_payload_length, c.flags());
    const int64_t result = visitor_.OnReadyToSend(absl::string_view(frame));
    if (result < 0) {
      LatchErrorAndNotify(Http2ErrorCode::INTERNAL_ERROR,
                          ConnectionError::kSendError);
      return SendResult::SEND_ERROR;
    } else if (result == 0) {
      // Write blocked.
      return SendResult::SEND_BLOCKED;
    } else {
      frames_.pop_front();

      const bool ok =
          AfterFrameSent(c.frame_type(), c.stream_id(), frame_payload_length,
                         c.flags(), c.error_code());
      if (!ok) {
        LatchErrorAndNotify(Http2ErrorCode::INTERNAL_ERROR,
                            ConnectionError::kSendError);
        return SendResult::SEND_ERROR;
      }
      if (static_cast<size_t>(result) < frame.size()) {
        // The frame was partially written, so the rest must be buffered.
        buffered_data_.Append(
            absl::string_view(frame.data() + result, frame.size() - result));
        return SendResult::SEND_BLOCKED;
      }
    }
  }
  return SendResult::SEND_OK;
}

bool OgHttp2Session::AfterFrameSent(uint8_t frame_type_int, uint32_t stream_id,
                                    size_t payload_length, uint8_t flags,
                                    uint32_t error_code) {
  const FrameType frame_type = static_cast<FrameType>(frame_type_int);
  int result = visitor_.OnFrameSent(frame_type_int, stream_id, payload_length,
                                    flags, error_code);
  if (result < 0) {
    return false;
  }
  if (stream_id == 0) {
    if (frame_type == FrameType::SETTINGS) {
      const bool is_settings_ack = (flags & ACK_FLAG);
      if (is_settings_ack && encoder_header_table_capacity_when_acking_) {
        framer_.UpdateHeaderEncoderTableSize(
            *encoder_header_table_capacity_when_acking_);
        encoder_header_table_capacity_when_acking_ = std::nullopt;
      } else if (!is_settings_ack) {
        sent_non_ack_settings_ = true;
      }
    }
    return true;
  }

  const bool contains_fin =
      (frame_type == FrameType::DATA || frame_type == FrameType::HEADERS) &&
      (flags & END_STREAM_FLAG) == END_STREAM_FLAG;
  auto it = stream_map_.find(stream_id);
  const bool still_open_remote =
      it != stream_map_.end() && !it->second.half_closed_remote;
  if (contains_fin && still_open_remote &&
      options_.rst_stream_no_error_when_incomplete && IsServerSession()) {
    // Since the peer has not yet ended the stream, this endpoint should
    // send a RST_STREAM NO_ERROR. See RFC 7540 Section 8.1.
    frames_.push_front(std::make_unique<spdy::SpdyRstStreamIR>(
        stream_id, spdy::SpdyErrorCode::ERROR_CODE_NO_ERROR));
    auto queued_result = queued_frames_.insert({stream_id, 1});
    if (!queued_result.second) {
      ++(queued_result.first->second);
    }
    it->second.half_closed_remote = true;
  }

  DecrementQueuedFrameCount(stream_id, frame_type_int);
  return true;
}

OgHttp2Session::SendResult OgHttp2Session::WriteForStream(
    Http2StreamId stream_id) {
  auto it = stream_map_.find(stream_id);
  if (it == stream_map_.end()) {
    QUICHE_LOG(ERROR) << "Can't find stream " << stream_id
                      << " which is ready to write!";
    return SendResult::SEND_OK;
  }
  StreamState& state = it->second;
  auto reset_it = streams_reset_.find(stream_id);
  if (reset_it != streams_reset_.end()) {
    // The stream has been reset; there's no point in sending DATA or trailing
    // HEADERS.
    AbandonData(state);
    state.trailers = nullptr;
    return SendResult::SEND_OK;
  }

  SendResult connection_can_write = SendResult::SEND_OK;
  if (!IsReadyToWriteData(state)) {
    // No data to send, but there might be trailers.
    if (state.trailers != nullptr) {
      // Trailers will include END_STREAM, so the data source can be discarded.
      // Since data_deferred is true, there is no data waiting to be flushed for
      // this stream.
      AbandonData(state);
      auto block_ptr = std::move(state.trailers);
      if (state.half_closed_local) {
        QUICHE_LOG(ERROR) << "Sent fin; can't send trailers.";

        // TODO(birenroy,diannahu): Consider queuing a RST_STREAM INTERNAL_ERROR
        // instead.
        CloseStream(stream_id, Http2ErrorCode::INTERNAL_ERROR);
      } else {
        SendTrailers(stream_id, std::move(*block_ptr));
      }
    }
    return SendResult::SEND_OK;
  }
  int32_t available_window =
      std::min({connection_send_window_, state.send_window,
                static_cast<int32_t>(max_frame_payload_)});
  while (connection_can_write == SendResult::SEND_OK && available_window > 0 &&
         IsReadyToWriteData(state)) {
    DataFrameHeaderInfo info =
   
"""


```