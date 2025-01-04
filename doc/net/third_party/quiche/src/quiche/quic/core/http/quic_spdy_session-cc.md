Response:
The user wants me to analyze the provided C++ code snippet from `quic_spdy_session.cc`. I need to perform the following:

1. **Functionality Summary:** Describe what this code does.
2. **JavaScript Relationship:** Explain if and how this code interacts with JavaScript. Provide examples.
3. **Logical Inference:**  Identify any logical deductions made in the code. Provide example inputs and outputs.
4. **Common Usage Errors:** Point out potential mistakes users or programmers might make when using this code. Illustrate with examples.
5. **User Journey:**  Describe the steps a user might take in a browser that would lead to this code being executed. This should aid in debugging.
6. **Part 1 Summary:**  Concisely summarize the functionality covered in this specific code section.

Let's break down the code section by section:

* **Includes and Namespaces:** Standard C++ includes, Chromium/Quiche specific includes, and namespace declarations (`quic`).
* **Constants:** Defines constants like `kMaxUnassociatedWebTransportStreams`, `kHpackEncoderDynamicTableSizeLimit`, and `kDefaultMaxWebTransportSessions`.
* **`AlpsFrameDecoder` Class:** This is a visitor class for an `HttpDecoder`. It seems to be specifically designed to handle `ACCEPT_CH` and `SETTINGS` frames received over ALPS (Application-Layer Protocol Settings). It rejects other frame types.
* **`GetDefaultQpackMaximumDynamicTableCapacity` Function:** Returns the default maximum size for the QPACK dynamic table, potentially influenced by a flag.
* **`SizeLimitingHeaderList` Class:** This class manages a list of headers and enforces a maximum size. It's used for gQUIC (Google QUIC).
* **`QuicSpdySession::SpdyFramerVisitor` Class:**  This is a visitor for the `SpdyFramer`. It handles incoming SPDY frames, specifically dealing with `HEADERS` frames for `QuicSpdyStream`. It also manages errors and connection closures based on received frames. It's used in gQUIC.
* **`Http3DebugVisitor` Class:** A simple debug visitor for HTTP/3.
* **`QuicSpdySession` Constructor and Destructor:**  Initializes and cleans up the `QuicSpdySession` object. It sets up various internal state depending on the QUIC version.
* **`QuicSpdySession::Initialize` Method:**  Performs initialization tasks, including filling the settings frame, creating the headers stream (for gQUIC), and initializing QPACK components (for HTTP/3).
* **`QuicSpdySession::FillSettingsFrame` Method:** Populates the settings frame with various parameters like QPACK limits, datagram support, and WebTransport settings.
* **`QuicSpdySession::OnDecoderStreamError` and `OnEncoderStreamError` Methods:** Handle errors related to the QPACK decoder and encoder streams (HTTP/3).
* **`QuicSpdySession::OnStreamHeadersPriority` Method:** Sets the priority of a `QuicSpdyStream`.
* **`QuicSpdySession::OnStreamHeaderList` Method:** Processes received headers for a `QuicSpdyStream`.
* **`QuicSpdySession::OnPriorityFrame` Method:**  Handles received `PRIORITY` frames.
* **`QuicSpdySession::OnPriorityUpdateForRequestStream` Method:** Processes `PRIORITY_UPDATE` frames, particularly for client-initiated streams.
* **`QuicSpdySession::ProcessHeaderData` Method:**  Feeds header data to the HTTP/2 deframer.
* **`QuicSpdySession::WriteHeadersOnHeadersStream` Method:** Writes headers on the dedicated headers stream (gQUIC).
* **`QuicSpdySession::WritePriority` Method:** Writes a `PRIORITY` frame.
* **`QuicSpdySession::WriteHttp3PriorityUpdate` Method:** Writes a HTTP/3 `PRIORITY_UPDATE` frame.
* **`QuicSpdySession::OnHttp3GoAway` Method:** Handles the reception of an HTTP/3 `GOAWAY` frame.

Based on this breakdown, I can now formulate the response.
这是 Chromium 网络栈中 QUIC 协议 HTTP/3 和 gQUIC 实现的关键部分，文件 `quic_spdy_session.cc` 的主要功能是实现 `QuicSpdySession` 类。`QuicSpdySession` 负责管理 QUIC 连接上的 HTTP/2 或 HTTP/3 会话，处理 HTTP 语义，例如请求和响应的头信息、优先级等。

**它的主要功能可以归纳如下：**

1. **会话管理:**  作为 QUIC 连接上 HTTP 层面的抽象，管理连接的生命周期内的 HTTP 交互。
2. **HTTP 帧处理:** 解析和生成 HTTP/2 (SPDY) 和 HTTP/3 的帧，例如 HEADERS, DATA, SETTINGS, PRIORITY 等。
3. **流管理:**  管理 HTTP 流（请求和响应），创建、查找和维护 `QuicSpdyStream` 对象。
4. **头部处理:** 处理 HTTP 头部压缩和解压缩 (HPACK/QPACK)。
5. **优先级控制:**  处理和应用 HTTP 流的优先级，确保重要资源优先传输。
6. **错误处理:**  处理各种 HTTP 相关的错误，并采取相应的连接关闭或其他措施。
7. **SETTINGS 帧处理:**  处理收到的 SETTINGS 帧，更新本地的会话参数。
8. **WebTransport 支持:**  集成对 WebTransport over HTTP/3 的支持。
9. **ALPS 支持:**  处理通过 ALPS (Application-Layer Protocol Settings) 收到的特定帧 (如 ACCEPT_CH, SETTINGS)。

**与 JavaScript 的关系及举例说明:**

`QuicSpdySession` 本身是用 C++ 实现的，并不直接包含 JavaScript 代码。但是，它在浏览器网络栈中扮演着关键角色，处理着通过 JavaScript 发起的网络请求。

* **浏览器发起请求:** 当 JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起一个 HTTPS 请求时，浏览器底层网络栈会建立 QUIC 连接（如果适用）。`QuicSpdySession` 就负责处理这个连接上的 HTTP 语义。
    * **假设输入:**  JavaScript 代码 `fetch('https://example.com/data');`
    * **输出:** `QuicSpdySession` 会接收到这个请求的信息，包括请求头，并将其封装成 QUIC 帧发送出去。远端服务器的响应也会通过 `QuicSpdySession` 处理后传递给 JavaScript。

* **Service Worker:**  Service Worker 可以拦截 JavaScript 发起的网络请求。当 Service Worker 处理请求并返回响应时，这个响应可能会通过 QUIC 连接传输，并由 `QuicSpdySession` 处理。
    * **假设输入:** JavaScript 代码请求一个被 Service Worker 拦截的资源。
    * **输出:** Service Worker 生成的响应头和数据会被 `QuicSpdySession` 打包成 QUIC 帧发送回客户端。

* **WebSockets over HTTP/3:**  如果使用了基于 HTTP/3 的 WebSockets，`QuicSpdySession` 也会参与管理这些连接。虽然 WebSocket 本身有自己的帧格式，但在 HTTP/3 上建立 WebSocket 连接需要通过 HTTP 请求升级。

**逻辑推理及假设输入与输出:**

代码中存在一些逻辑推理，例如在处理 `PRIORITY_UPDATE` 帧时，会根据流 ID 判断是否是有效的请求流，以及是否超过了允许的最大并发流数量。

* **假设输入:** 收到一个 `PRIORITY_UPDATE` 帧，目标流 ID 为 10，且当前会话允许的最大传入双向流数量为 5。
* **逻辑推理:**  `OnPriorityUpdateForRequestStream` 方法会检查流 ID 10 是否在允许的范围内（基于最大传入双向流数量）。由于客户端发起的双向流 ID 从偶数开始，假设连接版本允许，前 5 个客户端发起的双向流 ID 为 0, 4, 8, 12, 16。因此流 ID 10 不在已建立或可立即建立的流的范围内。
* **输出:**  `OnPriorityUpdateForRequestStream` 方法会判断这是一个无效的流 ID，并可能调用 `connection()->CloseConnection` 关闭连接。

**用户或编程常见的使用错误及举例说明:**

* **错误地配置最大头部列表大小:**  如果服务器和客户端配置的最大头部列表大小不一致，可能会导致连接中断或请求失败。
    * **举例:**  客户端设置 `max_inbound_header_list_size_` 为 65536，但服务器期望更小的值。当客户端发送包含较大头部信息的请求时，服务器可能会因为接收到超出其限制的头部而关闭连接，错误码可能是与头部大小相关的 QUIC 错误码。

* **在不支持 HTTP/3 的环境下使用 HTTP/3 特性:**  尝试在旧版本的浏览器或网络环境下使用仅 HTTP/3 支持的功能（如 QPACK 或 WebTransport over HTTP/3）会导致连接失败或功能异常。
    * **举例:**  一个 JavaScript 应用尝试使用 WebTransport API，但用户的浏览器或网络环境只支持 HTTP/2 over QUIC。这时，WebTransport 连接将无法建立。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入一个 HTTPS URL 并回车，或点击一个 HTTPS 链接。**
2. **浏览器 DNS 解析该域名，并尝试与服务器建立 QUIC 连接（如果协议协商支持）。**
3. **QUIC 连接建立后，`QuicSpdySession` 对象被创建，负责管理该连接上的 HTTP 会话。**
4. **浏览器发送 HTTP 请求。**  这个请求的头部信息会被 `QuicSpdySession` 处理，并根据协议版本（HTTP/2 或 HTTP/3）进行帧的序列化。
5. **服务器响应到达。** 服务器发送的 HTTP 响应帧会被 `QuicSpdySession` 解析。
6. **如果涉及到 HTTP 头部，`SpdyFramerVisitor` (对于 HTTP/2) 或 QPACK 解码器 (对于 HTTP/3) 会被调用来处理头部信息。**
7. **如果收到了 SETTINGS 帧，`OnSetting` 方法会被调用更新会话参数。如果收到 ALPS 帧，`AlpsFrameDecoder` 会被调用。**
8. **如果涉及到优先级更新，`OnPriorityUpdateForRequestStream` 等方法会被调用。**

**第 1 部分功能归纳:**

这部分代码主要负责 `QuicSpdySession` 类的基础框架和初始化工作，包括：

* **类的定义和构造/析构:** 设置了 `QuicSpdySession` 的基本结构和生命周期管理。
* **HTTP/2 和 HTTP/3 的通用基础:** 包含了处理两种协议版本的一些通用逻辑。
* **内部组件的初始化:**  初始化了 SPDY framer, HTTP/3 decoder, QPACK encoder/decoder 等关键组件。
* **SETTINGS 帧的构建:**  定义了如何填充本地的 SETTINGS 帧。
* **ALPS 帧的处理:**  引入了 `AlpsFrameDecoder` 用于处理通过 ALPS 协商得到的帧。
* **头部大小限制:**  实现了对接收到的头部列表大小的限制。
* **与底层 QUIC 连接的交互:**  通过 `QuicSession` 基类提供的接口与 QUIC 连接进行交互。
* **流管理的基础:**  为后续的流创建和管理奠定了基础。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/http/quic_spdy_session.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <utility>


#include "absl/base/attributes.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/http2/core/http2_frame_decoder_adapter.h"
#include "quiche/quic/core/http/http_constants.h"
#include "quiche/quic/core/http/http_decoder.h"
#include "quiche/quic/core/http/http_frames.h"
#include "quiche/quic/core/http/quic_headers_stream.h"
#include "quiche/quic/core/http/quic_spdy_stream.h"
#include "quiche/quic/core/http/web_transport_http3.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_session.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_exported_stats.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_stack_trace.h"
#include "quiche/common/platform/api/quiche_mem_slice.h"

using http2::Http2DecoderAdapter;
using quiche::HttpHeaderBlock;
using spdy::Http2WeightToSpdy3Priority;
using spdy::Spdy3PriorityToHttp2Weight;
using spdy::SpdyErrorCode;
using spdy::SpdyFramer;
using spdy::SpdyFramerDebugVisitorInterface;
using spdy::SpdyFramerVisitorInterface;
using spdy::SpdyFrameType;
using spdy::SpdyHeadersHandlerInterface;
using spdy::SpdyHeadersIR;
using spdy::SpdyPingId;
using spdy::SpdyPriority;
using spdy::SpdyPriorityIR;
using spdy::SpdySerializedFrame;
using spdy::SpdySettingsId;
using spdy::SpdyStreamId;

namespace quic {

ABSL_CONST_INIT const size_t kMaxUnassociatedWebTransportStreams = 24;

namespace {

// Limit on HPACK encoder dynamic table size.
// Only used for Google QUIC, not IETF QUIC.
constexpr uint64_t kHpackEncoderDynamicTableSizeLimit = 16384;

constexpr QuicStreamCount kDefaultMaxWebTransportSessions = 16;

#define ENDPOINT \
  (perspective() == Perspective::IS_SERVER ? "Server: " : "Client: ")

// Class to forward ACCEPT_CH frame to QuicSpdySession,
// and ignore every other frame.
class AlpsFrameDecoder : public HttpDecoder::Visitor {
 public:
  explicit AlpsFrameDecoder(QuicSpdySession* session) : session_(session) {}
  ~AlpsFrameDecoder() override = default;

  // HttpDecoder::Visitor implementation.
  void OnError(HttpDecoder* /*decoder*/) override {}
  bool OnMaxPushIdFrame() override {
    error_detail_ = "MAX_PUSH_ID frame forbidden";
    return false;
  }
  bool OnGoAwayFrame(const GoAwayFrame& /*frame*/) override {
    error_detail_ = "GOAWAY frame forbidden";
    return false;
  }
  bool OnSettingsFrameStart(QuicByteCount /*header_length*/) override {
    return true;
  }
  bool OnSettingsFrame(const SettingsFrame& frame) override {
    if (settings_frame_received_via_alps_) {
      error_detail_ = "multiple SETTINGS frames";
      return false;
    }

    settings_frame_received_via_alps_ = true;

    error_detail_ = session_->OnSettingsFrameViaAlps(frame);
    return !error_detail_;
  }
  bool OnDataFrameStart(QuicByteCount /*header_length*/, QuicByteCount
                        /*payload_length*/) override {
    error_detail_ = "DATA frame forbidden";
    return false;
  }
  bool OnDataFramePayload(absl::string_view /*payload*/) override {
    QUICHE_NOTREACHED();
    return false;
  }
  bool OnDataFrameEnd() override {
    QUICHE_NOTREACHED();
    return false;
  }
  bool OnHeadersFrameStart(QuicByteCount /*header_length*/,
                           QuicByteCount /*payload_length*/) override {
    error_detail_ = "HEADERS frame forbidden";
    return false;
  }
  bool OnHeadersFramePayload(absl::string_view /*payload*/) override {
    QUICHE_NOTREACHED();
    return false;
  }
  bool OnHeadersFrameEnd() override {
    QUICHE_NOTREACHED();
    return false;
  }
  bool OnPriorityUpdateFrameStart(QuicByteCount /*header_length*/) override {
    error_detail_ = "PRIORITY_UPDATE frame forbidden";
    return false;
  }
  bool OnPriorityUpdateFrame(const PriorityUpdateFrame& /*frame*/) override {
    QUICHE_NOTREACHED();
    return false;
  }
  bool OnAcceptChFrameStart(QuicByteCount /*header_length*/) override {
    return true;
  }
  bool OnAcceptChFrame(const AcceptChFrame& frame) override {
    session_->OnAcceptChFrameReceivedViaAlps(frame);
    return true;
  }
  bool OnOriginFrameStart(QuicByteCount /*header_length*/) override {
    QUICHE_NOTREACHED();
    return true;
  }
  bool OnOriginFrame(const OriginFrame& /*frame*/) override { return true; }
  void OnWebTransportStreamFrameType(
      QuicByteCount /*header_length*/,
      WebTransportSessionId /*session_id*/) override {
    QUICHE_NOTREACHED();
  }
  bool OnMetadataFrameStart(QuicByteCount /*header_length*/,
                            QuicByteCount /*payload_length*/) override {
    error_detail_ = "METADATA frame forbidden";
    return false;
  }
  bool OnMetadataFramePayload(absl::string_view /*payload*/) override {
    QUICHE_NOTREACHED();
    return false;
  }
  bool OnMetadataFrameEnd() override {
    QUICHE_NOTREACHED();
    return false;
  }
  bool OnUnknownFrameStart(uint64_t /*frame_type*/,
                           QuicByteCount
                           /*header_length*/,
                           QuicByteCount /*payload_length*/) override {
    return true;
  }
  bool OnUnknownFramePayload(absl::string_view /*payload*/) override {
    return true;
  }
  bool OnUnknownFrameEnd() override { return true; }

  const std::optional<std::string>& error_detail() const {
    return error_detail_;
  }

 private:
  QuicSpdySession* const session_;
  std::optional<std::string> error_detail_;

  // True if SETTINGS frame has been received via ALPS.
  bool settings_frame_received_via_alps_ = false;
};

uint64_t GetDefaultQpackMaximumDynamicTableCapacity(Perspective perspective) {
  if (perspective == Perspective::IS_SERVER &&
      GetQuicFlag(quic_server_disable_qpack_dynamic_table)) {
    return 0;
  }

  return kDefaultQpackMaxDynamicTableCapacity;
}

// This class is only used in gQUIC.
class SizeLimitingHeaderList : public spdy::SpdyHeadersHandlerInterface {
 public:
  ~SizeLimitingHeaderList() override = default;

  void OnHeaderBlockStart() override {
    QUIC_BUG_IF(quic_bug_12518_1, current_header_list_size_ != 0)
        << "OnHeaderBlockStart called more than once!";
  }

  void OnHeader(absl::string_view name, absl::string_view value) override {
    if (current_header_list_size_ < max_header_list_size_) {
      current_header_list_size_ += name.size();
      current_header_list_size_ += value.size();
      current_header_list_size_ += kQpackEntrySizeOverhead;
      header_list_.OnHeader(name, value);
    }
  }

  void OnHeaderBlockEnd(size_t uncompressed_header_bytes,
                        size_t compressed_header_bytes) override {
    header_list_.OnHeaderBlockEnd(uncompressed_header_bytes,
                                  compressed_header_bytes);
    if (current_header_list_size_ > max_header_list_size_) {
      Clear();
    }
  }

  void set_max_header_list_size(size_t max_header_list_size) {
    max_header_list_size_ = max_header_list_size;
  }

  void Clear() {
    header_list_.Clear();
    current_header_list_size_ = 0;
  }

  const QuicHeaderList& header_list() const { return header_list_; }

 private:
  QuicHeaderList header_list_;

  // The limit on the size of the header list (defined by spec as name + value +
  // overhead for each header field). Headers over this limit will not be
  // buffered, and the list will be cleared upon OnHeaderBlockEnd().
  size_t max_header_list_size_ = std::numeric_limits<size_t>::max();

  // The total size of headers so far, including overhead.
  size_t current_header_list_size_ = 0;
};

}  // namespace

// A SpdyFramerVisitor that passes HEADERS frames to the QuicSpdyStream, and
// closes the connection if any unexpected frames are received.
// This class is only used in gQUIC.
class QuicSpdySession::SpdyFramerVisitor
    : public SpdyFramerVisitorInterface,
      public SpdyFramerDebugVisitorInterface {
 public:
  explicit SpdyFramerVisitor(QuicSpdySession* session) : session_(session) {}
  SpdyFramerVisitor(const SpdyFramerVisitor&) = delete;
  SpdyFramerVisitor& operator=(const SpdyFramerVisitor&) = delete;

  SpdyHeadersHandlerInterface* OnHeaderFrameStart(
      SpdyStreamId /* stream_id */) override {
    QUICHE_DCHECK(!VersionUsesHttp3(session_->transport_version()));
    return &header_list_;
  }

  void OnHeaderFrameEnd(SpdyStreamId /* stream_id */) override {
    QUICHE_DCHECK(!VersionUsesHttp3(session_->transport_version()));

    LogHeaderCompressionRatioHistogram(
        /* using_qpack = */ false,
        /* is_sent = */ false,
        header_list_.header_list().compressed_header_bytes(),
        header_list_.header_list().uncompressed_header_bytes());

    // Ignore pushed request headers.
    if (session_->IsConnected() && !expecting_pushed_headers_) {
      session_->OnHeaderList(header_list_.header_list());
    }
    expecting_pushed_headers_ = false;
    header_list_.Clear();
  }

  void OnStreamFrameData(SpdyStreamId /*stream_id*/, const char* /*data*/,
                         size_t /*len*/) override {
    QUICHE_DCHECK(!VersionUsesHttp3(session_->transport_version()));
    CloseConnection("SPDY DATA frame received.",
                    QUIC_INVALID_HEADERS_STREAM_DATA);
  }

  void OnStreamEnd(SpdyStreamId /*stream_id*/) override {
    // The framer invokes OnStreamEnd after processing a frame that had the fin
    // bit set.
  }

  void OnStreamPadding(SpdyStreamId /*stream_id*/, size_t /*len*/) override {
    CloseConnection("SPDY frame padding received.",
                    QUIC_INVALID_HEADERS_STREAM_DATA);
  }

  void OnError(Http2DecoderAdapter::SpdyFramerError error,
               std::string detailed_error) override {
    QuicErrorCode code;
    switch (error) {
      case Http2DecoderAdapter::SpdyFramerError::SPDY_HPACK_INDEX_VARINT_ERROR:
        code = QUIC_HPACK_INDEX_VARINT_ERROR;
        break;
      case Http2DecoderAdapter::SpdyFramerError::
          SPDY_HPACK_NAME_LENGTH_VARINT_ERROR:
        code = QUIC_HPACK_NAME_LENGTH_VARINT_ERROR;
        break;
      case Http2DecoderAdapter::SpdyFramerError::
          SPDY_HPACK_VALUE_LENGTH_VARINT_ERROR:
        code = QUIC_HPACK_VALUE_LENGTH_VARINT_ERROR;
        break;
      case Http2DecoderAdapter::SpdyFramerError::SPDY_HPACK_NAME_TOO_LONG:
        code = QUIC_HPACK_NAME_TOO_LONG;
        break;
      case Http2DecoderAdapter::SpdyFramerError::SPDY_HPACK_VALUE_TOO_LONG:
        code = QUIC_HPACK_VALUE_TOO_LONG;
        break;
      case Http2DecoderAdapter::SpdyFramerError::SPDY_HPACK_NAME_HUFFMAN_ERROR:
        code = QUIC_HPACK_NAME_HUFFMAN_ERROR;
        break;
      case Http2DecoderAdapter::SpdyFramerError::SPDY_HPACK_VALUE_HUFFMAN_ERROR:
        code = QUIC_HPACK_VALUE_HUFFMAN_ERROR;
        break;
      case Http2DecoderAdapter::SpdyFramerError::
          SPDY_HPACK_MISSING_DYNAMIC_TABLE_SIZE_UPDATE:
        code = QUIC_HPACK_MISSING_DYNAMIC_TABLE_SIZE_UPDATE;
        break;
      case Http2DecoderAdapter::SpdyFramerError::SPDY_HPACK_INVALID_INDEX:
        code = QUIC_HPACK_INVALID_INDEX;
        break;
      case Http2DecoderAdapter::SpdyFramerError::SPDY_HPACK_INVALID_NAME_INDEX:
        code = QUIC_HPACK_INVALID_NAME_INDEX;
        break;
      case Http2DecoderAdapter::SpdyFramerError::
          SPDY_HPACK_DYNAMIC_TABLE_SIZE_UPDATE_NOT_ALLOWED:
        code = QUIC_HPACK_DYNAMIC_TABLE_SIZE_UPDATE_NOT_ALLOWED;
        break;
      case Http2DecoderAdapter::SpdyFramerError::
          SPDY_HPACK_INITIAL_DYNAMIC_TABLE_SIZE_UPDATE_IS_ABOVE_LOW_WATER_MARK:
        code = QUIC_HPACK_INITIAL_TABLE_SIZE_UPDATE_IS_ABOVE_LOW_WATER_MARK;
        break;
      case Http2DecoderAdapter::SpdyFramerError::
          SPDY_HPACK_DYNAMIC_TABLE_SIZE_UPDATE_IS_ABOVE_ACKNOWLEDGED_SETTING:
        code = QUIC_HPACK_TABLE_SIZE_UPDATE_IS_ABOVE_ACKNOWLEDGED_SETTING;
        break;
      case Http2DecoderAdapter::SpdyFramerError::SPDY_HPACK_TRUNCATED_BLOCK:
        code = QUIC_HPACK_TRUNCATED_BLOCK;
        break;
      case Http2DecoderAdapter::SpdyFramerError::SPDY_HPACK_FRAGMENT_TOO_LONG:
        code = QUIC_HPACK_FRAGMENT_TOO_LONG;
        break;
      case Http2DecoderAdapter::SpdyFramerError::
          SPDY_HPACK_COMPRESSED_HEADER_SIZE_EXCEEDS_LIMIT:
        code = QUIC_HPACK_COMPRESSED_HEADER_SIZE_EXCEEDS_LIMIT;
        break;
      case Http2DecoderAdapter::SpdyFramerError::SPDY_DECOMPRESS_FAILURE:
        code = QUIC_HEADERS_STREAM_DATA_DECOMPRESS_FAILURE;
        break;
      default:
        code = QUIC_INVALID_HEADERS_STREAM_DATA;
    }
    CloseConnection(
        absl::StrCat("SPDY framing error: ", detailed_error,
                     Http2DecoderAdapter::SpdyFramerErrorToString(error)),
        code);
  }

  void OnDataFrameHeader(SpdyStreamId /*stream_id*/, size_t /*length*/,
                         bool /*fin*/) override {
    QUICHE_DCHECK(!VersionUsesHttp3(session_->transport_version()));
    CloseConnection("SPDY DATA frame received.",
                    QUIC_INVALID_HEADERS_STREAM_DATA);
  }

  void OnRstStream(SpdyStreamId /*stream_id*/,
                   SpdyErrorCode /*error_code*/) override {
    CloseConnection("SPDY RST_STREAM frame received.",
                    QUIC_INVALID_HEADERS_STREAM_DATA);
  }

  void OnSetting(SpdySettingsId id, uint32_t value) override {
    QUICHE_DCHECK(!VersionUsesHttp3(session_->transport_version()));
    session_->OnSetting(id, value);
  }

  void OnSettingsEnd() override {
    QUICHE_DCHECK(!VersionUsesHttp3(session_->transport_version()));
  }

  void OnPing(SpdyPingId /*unique_id*/, bool /*is_ack*/) override {
    CloseConnection("SPDY PING frame received.",
                    QUIC_INVALID_HEADERS_STREAM_DATA);
  }

  void OnGoAway(SpdyStreamId /*last_accepted_stream_id*/,
                SpdyErrorCode /*error_code*/) override {
    CloseConnection("SPDY GOAWAY frame received.",
                    QUIC_INVALID_HEADERS_STREAM_DATA);
  }

  void OnHeaders(SpdyStreamId stream_id, size_t /*payload_length*/,
                 bool has_priority, int weight,
                 SpdyStreamId /*parent_stream_id*/, bool /*exclusive*/,
                 bool fin, bool /*end*/) override {
    if (!session_->IsConnected()) {
      return;
    }

    if (VersionUsesHttp3(session_->transport_version())) {
      CloseConnection("HEADERS frame not allowed on headers stream.",
                      QUIC_INVALID_HEADERS_STREAM_DATA);
      return;
    }

    QUIC_BUG_IF(quic_bug_12477_1,
                session_->destruction_indicator() != 123456789)
        << "QuicSpdyStream use after free. "
        << session_->destruction_indicator() << QuicStackTrace();

    SpdyPriority priority =
        has_priority ? Http2WeightToSpdy3Priority(weight) : 0;
    session_->OnHeaders(stream_id, has_priority,
                        spdy::SpdyStreamPrecedence(priority), fin);
  }

  void OnWindowUpdate(SpdyStreamId /*stream_id*/,
                      int /*delta_window_size*/) override {
    CloseConnection("SPDY WINDOW_UPDATE frame received.",
                    QUIC_INVALID_HEADERS_STREAM_DATA);
  }

  void OnPushPromise(SpdyStreamId /*stream_id*/,
                     SpdyStreamId promised_stream_id, bool /*end*/) override {
    QUICHE_DCHECK(!VersionUsesHttp3(session_->transport_version()));
    if (session_->perspective() != Perspective::IS_CLIENT) {
      // PUSH_PROMISE sent by a client is a protocol violation.
      CloseConnection("PUSH_PROMISE not supported.",
                      QUIC_INVALID_HEADERS_STREAM_DATA);
      return;
    }

    // Push streams are ignored anyway, reset the stream to save bandwidth.
    session_->MaybeSendRstStreamFrame(
        promised_stream_id,
        QuicResetStreamError::FromInternal(QUIC_REFUSED_STREAM),
        /* bytes_written = */ 0);

    QUICHE_DCHECK(!expecting_pushed_headers_);
    expecting_pushed_headers_ = true;
  }

  void OnContinuation(SpdyStreamId /*stream_id*/, size_t /*payload_size*/,
                      bool /*end*/) override {}

  void OnPriority(SpdyStreamId stream_id, SpdyStreamId /* parent_id */,
                  int weight, bool /* exclusive */) override {
    QUICHE_DCHECK(!VersionUsesHttp3(session_->transport_version()));
    if (!session_->IsConnected()) {
      return;
    }
    SpdyPriority priority = Http2WeightToSpdy3Priority(weight);
    session_->OnPriority(stream_id, spdy::SpdyStreamPrecedence(priority));
  }

  void OnPriorityUpdate(SpdyStreamId /*prioritized_stream_id*/,
                        absl::string_view /*priority_field_value*/) override {}

  bool OnUnknownFrame(SpdyStreamId /*stream_id*/,
                      uint8_t /*frame_type*/) override {
    CloseConnection("Unknown frame type received.",
                    QUIC_INVALID_HEADERS_STREAM_DATA);
    return false;
  }

  void OnUnknownFrameStart(SpdyStreamId /*stream_id*/, size_t /*length*/,
                           uint8_t /*type*/, uint8_t /*flags*/) override {}

  void OnUnknownFramePayload(SpdyStreamId /*stream_id*/,
                             absl::string_view /*payload*/) override {}

  // SpdyFramerDebugVisitorInterface implementation
  void OnSendCompressedFrame(SpdyStreamId /*stream_id*/, SpdyFrameType /*type*/,
                             size_t payload_len, size_t frame_len) override {
    if (payload_len == 0) {
      QUIC_BUG(quic_bug_10360_1) << "Zero payload length.";
      return;
    }
    int compression_pct = 100 - (100 * frame_len) / payload_len;
    QUIC_DVLOG(1) << "Net.QuicHpackCompressionPercentage: " << compression_pct;
  }

  void OnReceiveCompressedFrame(SpdyStreamId /*stream_id*/,
                                SpdyFrameType /*type*/,
                                size_t frame_len) override {
    if (session_->IsConnected()) {
      session_->OnCompressedFrameSize(frame_len);
    }
  }

  void set_max_header_list_size(size_t max_header_list_size) {
    header_list_.set_max_header_list_size(max_header_list_size);
  }

 private:
  void CloseConnection(const std::string& details, QuicErrorCode code) {
    if (session_->IsConnected()) {
      session_->CloseConnectionWithDetails(code, details);
    }
  }

  QuicSpdySession* session_;
  SizeLimitingHeaderList header_list_;

  // True if the next OnHeaderFrameEnd() call signals the end of pushed request
  // headers.
  bool expecting_pushed_headers_ = false;
};

Http3DebugVisitor::Http3DebugVisitor() {}

Http3DebugVisitor::~Http3DebugVisitor() {}

// Expected unidirectional static streams Requirement can be found at
// https://tools.ietf.org/html/draft-ietf-quic-http-22#section-6.2.
QuicSpdySession::QuicSpdySession(
    QuicConnection* connection, QuicSession::Visitor* visitor,
    const QuicConfig& config, const ParsedQuicVersionVector& supported_versions)
    : QuicSession(connection, visitor, config, supported_versions,
                  /*num_expected_unidirectional_static_streams = */
                  VersionUsesHttp3(connection->transport_version())
                      ? static_cast<QuicStreamCount>(
                            kHttp3StaticUnidirectionalStreamCount)
                      : 0u,
                  std::make_unique<DatagramObserver>(this)),
      send_control_stream_(nullptr),
      receive_control_stream_(nullptr),
      qpack_encoder_receive_stream_(nullptr),
      qpack_decoder_receive_stream_(nullptr),
      qpack_encoder_send_stream_(nullptr),
      qpack_decoder_send_stream_(nullptr),
      qpack_maximum_dynamic_table_capacity_(
          GetDefaultQpackMaximumDynamicTableCapacity(perspective())),
      qpack_maximum_blocked_streams_(kDefaultMaximumBlockedStreams),
      max_inbound_header_list_size_(kDefaultMaxUncompressedHeaderSize),
      max_outbound_header_list_size_(std::numeric_limits<size_t>::max()),
      stream_id_(
          QuicUtils::GetInvalidStreamId(connection->transport_version())),
      frame_len_(0),
      fin_(false),
      spdy_framer_(SpdyFramer::ENABLE_COMPRESSION),
      spdy_framer_visitor_(new SpdyFramerVisitor(this)),
      debug_visitor_(nullptr),
      destruction_indicator_(123456789),
      allow_extended_connect_(perspective() == Perspective::IS_SERVER &&
                              VersionUsesHttp3(transport_version())),
      force_buffer_requests_until_settings_(false) {
  h2_deframer_.set_visitor(spdy_framer_visitor_.get());
  h2_deframer_.set_debug_visitor(spdy_framer_visitor_.get());
  spdy_framer_.set_debug_visitor(spdy_framer_visitor_.get());
}

QuicSpdySession::~QuicSpdySession() {
  QUIC_BUG_IF(quic_bug_12477_2, destruction_indicator_ != 123456789)
      << "QuicSpdySession use after free. " << destruction_indicator_
      << QuicStackTrace();
  destruction_indicator_ = 987654321;
}

void QuicSpdySession::Initialize() {
  QuicSession::Initialize();

  FillSettingsFrame();
  if (!VersionUsesHttp3(transport_version())) {
    if (perspective() == Perspective::IS_SERVER) {
      set_largest_peer_created_stream_id(
          QuicUtils::GetHeadersStreamId(transport_version()));
    } else {
      QuicStreamId headers_stream_id = GetNextOutgoingBidirectionalStreamId();
      QUICHE_DCHECK_EQ(headers_stream_id,
                       QuicUtils::GetHeadersStreamId(transport_version()));
    }
    auto headers_stream = std::make_unique<QuicHeadersStream>((this));
    QUICHE_DCHECK_EQ(QuicUtils::GetHeadersStreamId(transport_version()),
                     headers_stream->id());

    headers_stream_ = headers_stream.get();
    ActivateStream(std::move(headers_stream));
  } else {
    qpack_encoder_ = std::make_unique<QpackEncoder>(this, huffman_encoding_,
                                                    cookie_crumbling_);
    qpack_decoder_ =
        std::make_unique<QpackDecoder>(qpack_maximum_dynamic_table_capacity_,
                                       qpack_maximum_blocked_streams_, this);
    MaybeInitializeHttp3UnidirectionalStreams();
  }

  spdy_framer_visitor_->set_max_header_list_size(max_inbound_header_list_size_);

  // Limit HPACK buffering to 2x header list size limit.
  h2_deframer_.GetHpackDecoder().set_max_decode_buffer_size_bytes(
      2 * max_inbound_header_list_size_);
}

void QuicSpdySession::FillSettingsFrame() {
  settings_.values[SETTINGS_QPACK_MAX_TABLE_CAPACITY] =
      qpack_maximum_dynamic_table_capacity_;
  settings_.values[SETTINGS_QPACK_BLOCKED_STREAMS] =
      qpack_maximum_blocked_streams_;
  settings_.values[SETTINGS_MAX_FIELD_SECTION_SIZE] =
      max_inbound_header_list_size_;
  if (version().UsesHttp3()) {
    switch (LocalHttpDatagramSupport()) {
      case HttpDatagramSupport::kNone:
        break;
      case HttpDatagramSupport::kDraft04:
        settings_.values[SETTINGS_H3_DATAGRAM_DRAFT04] = 1;
        break;
      case HttpDatagramSupport::kRfc:
        settings_.values[SETTINGS_H3_DATAGRAM] = 1;
        break;
      case HttpDatagramSupport::kRfcAndDraft04:
        settings_.values[SETTINGS_H3_DATAGRAM] = 1;
        settings_.values[SETTINGS_H3_DATAGRAM_DRAFT04] = 1;
        break;
    }
  }
  if (WillNegotiateWebTransport()) {
    WebTransportHttp3VersionSet versions =
        LocallySupportedWebTransportVersions();
    if (versions.IsSet(WebTransportHttp3Version::kDraft02)) {
      settings_.values[SETTINGS_WEBTRANS_DRAFT00] = 1;
    }
    if (versions.IsSet(WebTransportHttp3Version::kDraft07)) {
      QUICHE_BUG_IF(
          WT_enabled_extended_connect_disabled,
          perspective() == Perspective::IS_SERVER && !allow_extended_connect())
          << "WebTransport enabled, but extended CONNECT is not";
      settings_.values[SETTINGS_WEBTRANS_MAX_SESSIONS_DRAFT07] =
          kDefaultMaxWebTransportSessions;
    }
  }
  if (allow_extended_connect()) {
    settings_.values[SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  }
}

void QuicSpdySession::OnDecoderStreamError(QuicErrorCode error_code,
                                           absl::string_view error_message) {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()));

  CloseConnectionWithDetails(
      error_code, absl::StrCat("Decoder stream error: ", error_message));
}

void QuicSpdySession::OnEncoderStreamError(QuicErrorCode error_code,
                                           absl::string_view error_message) {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()));

  CloseConnectionWithDetails(
      error_code, absl::StrCat("Encoder stream error: ", error_message));
}

void QuicSpdySession::OnStreamHeadersPriority(
    QuicStreamId stream_id, const spdy::SpdyStreamPrecedence& precedence) {
  QuicSpdyStream* stream = GetOrCreateSpdyDataStream(stream_id);
  if (!stream) {
    // It's quite possible to receive headers after a stream has been reset.
    return;
  }
  stream->OnStreamHeadersPriority(precedence);
}

void QuicSpdySession::OnStreamHeaderList(QuicStreamId stream_id, bool fin,
                                         size_t frame_len,
                                         const QuicHeaderList& header_list) {
  if (IsStaticStream(stream_id)) {
    connection()->CloseConnection(
        QUIC_INVALID_HEADERS_STREAM_DATA, "stream is static",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }
  QuicSpdyStream* stream = GetOrCreateSpdyDataStream(stream_id);
  if (stream == nullptr) {
    // The stream no longer exists, but trailing headers may contain the final
    // byte offset necessary for flow control and open stream accounting.
    size_t final_byte_offset = 0;
    for (const auto& header : header_list) {
      const std::string& header_key = header.first;
      const std::string& header_value = header.second;
      if (header_key == kFinalOffsetHeaderKey) {
        if (!absl::SimpleAtoi(header_value, &final_byte_offset)) {
          connection()->CloseConnection(
              QUIC_INVALID_HEADERS_STREAM_DATA,
              "Trailers are malformed (no final offset)",
              ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
          return;
        }
        QUIC_DVLOG(1) << ENDPOINT
                      << "Received final byte offset in trailers for stream "
                      << stream_id << ", which no longer exists.";
        OnFinalByteOffsetReceived(stream_id, final_byte_offset);
      }
    }

    // It's quite possible to receive headers after a stream has been reset.
    return;
  }
  stream->OnStreamHeaderList(fin, frame_len, header_list);
}

void QuicSpdySession::OnPriorityFrame(
    QuicStreamId stream_id, const spdy::SpdyStreamPrecedence& precedence) {
  QuicSpdyStream* stream = GetOrCreateSpdyDataStream(stream_id);
  if (!stream) {
    // It's quite possible to receive a PRIORITY frame after a stream has been
    // reset.
    return;
  }
  stream->OnPriorityFrame(precedence);
}

bool QuicSpdySession::OnPriorityUpdateForRequestStream(
    QuicStreamId stream_id, HttpStreamPriority priority) {
  if (perspective() == Perspective::IS_CLIENT ||
      !QuicUtils::IsBidirectionalStreamId(stream_id, version()) ||
      !QuicUtils::IsClientInitiatedStreamId(transport_version(), stream_id)) {
    return true;
  }

  QuicStreamCount advertised_max_incoming_bidirectional_streams =
      GetAdvertisedMaxIncomingBidirectionalStreams();
  if (advertised_max_incoming_bidirectional_streams == 0 ||
      stream_id > QuicUtils::GetFirstBidirectionalStreamId(
                      transport_version(), Perspective::IS_CLIENT) +
                      QuicUtils::StreamIdDelta(transport_version()) *
                          (advertised_max_incoming_bidirectional_streams - 1)) {
    connection()->CloseConnection(
        QUIC_INVALID_STREAM_ID,
        "PRIORITY_UPDATE frame received for invalid stream.",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }

  if (MaybeSetStreamPriority(stream_id, QuicStreamPriority(priority))) {
    return true;
  }

  if (IsClosedStream(stream_id)) {
    return true;
  }

  buffered_stream_priorities_[stream_id] = priority;

  if (buffered_stream_priorities_.size() >
      10 * max_open_incoming_bidirectional_streams()) {
    // This should never happen, because |buffered_stream_priorities_| should
    // only contain entries for streams that are allowed to be open by the peer
    // but have not been opened yet.
    std::string error_message =
        absl::StrCat("Too many stream priority values buffered: ",
                     buffered_stream_priorities_.size(),
                     ", which should not exceed the incoming stream limit of ",
                     max_open_incoming_bidirectional_streams());
    QUIC_BUG(quic_bug_10360_2) << error_message;
    connection()->CloseConnection(
        QUIC_INTERNAL_ERROR, error_message,
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return false;
  }

  return true;
}

size_t QuicSpdySession::ProcessHeaderData(const struct iovec& iov) {
  QUIC_BUG_IF(quic_bug_12477_4, destruction_indicator_ != 123456789)
      << "QuicSpdyStream use after free. " << destruction_indicator_
      << QuicStackTrace();
  return h2_deframer_.ProcessInput(static_cast<char*>(iov.iov_base),
                                   iov.iov_len);
}

size_t QuicSpdySession::WriteHeadersOnHeadersStream(
    QuicStreamId id, HttpHeaderBlock headers, bool fin,
    const spdy::SpdyStreamPrecedence& precedence,
    quiche::QuicheReferenceCountedPointer<QuicAckListenerInterface>
        ack_listener) {
  QUICHE_DCHECK(!VersionUsesHttp3(transport_version()));

  return WriteHeadersOnHeadersStreamImpl(
      id, std::move(headers), fin,
      /* parent_stream_id = */ 0,
      Spdy3PriorityToHttp2Weight(precedence.spdy3_priority()),
      /* exclusive = */ false, std::move(ack_listener));
}

size_t QuicSpdySession::WritePriority(QuicStreamId stream_id,
                                      QuicStreamId parent_stream_id, int weight,
                                      bool exclusive) {
  QUICHE_DCHECK(!VersionUsesHttp3(transport_version()));
  SpdyPriorityIR priority_frame(stream_id, parent_stream_id, weight, exclusive);
  SpdySerializedFrame frame(spdy_framer_.SerializeFrame(priority_frame));
  headers_stream()->WriteOrBufferData(
      absl::string_view(frame.data(), frame.size()), false, nullptr);
  return frame.size();
}

void QuicSpdySession::WriteHttp3PriorityUpdate(QuicStreamId stream_id,
                                               HttpStreamPriority priority) {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()));

  send_control_stream_->WritePriorityUpdate(stream_id, priority);
}

void QuicSpdySession::OnHttp3GoAway(uint64_t id) {
  QUIC_BUG_IF(quic_bug_12477_5, !version().UsesHttp3())
      << "HTTP/3 GOAWAY received on version " << version();

  if (last_received_http3_goaway_id_.has_value() &&
      id > *last_received_http3_goaway_id_) {
    CloseConnectionWithDetails(
        QUIC_HTTP_GOAWAY_ID_LARGER_THAN_PREVIOUS,
        absl::StrCat("GOAWAY received with ID ", id,
                     " greater than previously received ID ",
                     *last_received_http3_goaway_id_));
    return;
  }
  last_received_http3_goaway_id_ = id;

  if (perspective() == Perspective::IS_SERVER) {
    return;
  }

  // QuicStreamId is uint32_t.  Casting to this narrower type is well-defined
  // and preserves the lower 32 bits.  Both IsBidirectionalStreamId() and
  // IsIncomingStream() give correct results, because their return value is
  // determined by the least significant two bits.
  QuicStreamId stream_id = static_cast<QuicStreamId>(id);
  if (!QuicUtils::IsBidirectionalStreamId(stream_id, version()) ||
      IsIncomingStream(stream_id)) {
    CloseConnectionWithDetails(QUIC_HTTP_GOAWAY_INVALID_STREAM_ID,
                               "GOAWAY with invalid stream ID");
    return;
  }

  if (SupportsWebTransport()) {
    PerformActionOnActiveStreams([](QuicStream* stream) {
      if (!QuicUtils::IsBidirectionalStreamId(stream->id(),
                                              stream->version()) ||
          !QuicUtils::IsClientInitiatedStreamId(
              stream->version().transport_version, stream->id())) {
        return true;
      }
      QuicSpdyStream* spdy_stream = static_cast<QuicSpdyStream*>(stream);
      WebTransportHttp3* web_transport = spdy_stream->web_transport();
      if (web_transport == nullptr) {
      
"""


```