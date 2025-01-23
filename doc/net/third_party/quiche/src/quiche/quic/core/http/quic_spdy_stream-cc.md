Response:
My thinking process to generate the summary and examples goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the provided C++ code (`quic_spdy_stream.cc`) from Chromium's QUIC stack, specifically focusing on its role, relationship to JavaScript, logic, potential user errors, debugging, and a high-level summary for this first part of the file.

2. **Initial Scan and Keyword Identification:** I first scanned the code, looking for keywords and patterns that reveal its purpose. Key terms that jumped out include: `QuicSpdyStream`, `HttpDecoder`, `Headers`, `Data`, `Trailers`, `WebTransport`, `Qpack`, `HTTP/3`, `SPDY`, `Fin`, `Reset`, `Priority`. These suggest the file handles HTTP/2 and HTTP/3 streams over QUIC, managing headers, data, trailers, and potentially WebTransport functionality, using Qpack for compression.

3. **Deconstruct the Class Definition:** I focused on the `QuicSpdyStream` class itself. I noticed member variables related to header/trailer processing (`headers_decompressed_`, `trailers_decompressed_`, `header_list_`), data buffering (`sequencer_`, `body_manager_`), error handling, and WebTransport integration (`web_transport_`, `web_transport_data_`). This confirms its core function is managing the lifecycle and data flow of a single HTTP/QUIC stream.

4. **Analyze Key Methods:** I examined the prominent methods to understand their responsibilities:
    * `WriteHeaders`, `WriteOrBufferBody`, `WriteTrailers`, `WriteBodySlices`: These clearly handle sending HTTP content.
    * `Readv`, `GetReadableRegions`, `MarkConsumed`, `HasBytesToRead`, `ReadableBytes`: These manage reading received data.
    * `OnStreamHeaderList`, `OnHeadersDecoded`, `OnTrailingHeadersComplete`: These deal with processing incoming headers and trailers.
    * `OnDataAvailable`: This is a crucial method for handling incoming data and triggering the decoding process.
    * `OnStreamReset`, `ResetWithError`, `OnStopSending`:  These handle stream termination and error conditions.

5. **Identify Core Functionalities:** Based on the keywords and method analysis, I identified the main functions of the `QuicSpdyStream` class:
    * **Receiving and Processing HTTP/2 and HTTP/3 Data:** This is evident from the use of `HttpDecoder`, handling of headers, data frames, and trailers.
    * **Sending HTTP/2 and HTTP/3 Data:**  The `Write...` methods clearly show this.
    * **Header Compression/Decompression:** The presence of `QpackDecoder` and related flags indicates handling Qpack for HTTP/3.
    * **WebTransport Support:** The `web_transport_` member and related methods indicate integration with the WebTransport protocol.
    * **Error Handling:**  Methods like `OnStreamReset` and error codes suggest error management.
    * **Stream Lifecycle Management:** The class tracks the state of the stream (headers received, body read, etc.).
    * **Integration with QuicSpdySession:** The class interacts closely with the `QuicSpdySession` for connection-level operations.

6. **Address Specific Request Points:**

    * **Functionality Listing:** I created a bulleted list summarizing the identified core functionalities.
    * **Relationship with JavaScript:**  I considered how a web browser (running JavaScript) would interact with this code. The most direct link is the exchange of HTTP requests and responses. I provided examples of a `fetch` request and a server-side response, showing how the data processed by this C++ code would correspond to the data structures in JavaScript.
    * **Logical Reasoning (Hypothetical Input/Output):** I devised a simple scenario of receiving a HEADERS frame followed by a DATA frame to illustrate the flow through the decoder and the state changes within the `QuicSpdyStream`.
    * **User/Programming Errors:** I thought about common mistakes developers might make when working with HTTP streams, such as sending data after closing the stream or sending invalid headers, and how the QUIC stack would handle these errors.
    * **User Operation to Reach the Code:** I outlined the steps a user might take in a browser that would lead to the execution of this code (making a web request).
    * **Summary of Part 1:** I synthesized the identified core functionalities into a concise summary for the provided code snippet.

7. **Refine and Organize:**  I reviewed the generated information, ensuring it was clear, concise, and addressed all aspects of the request. I organized the points logically and used clear headings and formatting to improve readability. I made sure to explain the "why" behind the functionalities, not just listing them.

By following this systematic approach, I was able to break down the complex C++ code into understandable components and relate it to the broader context of web communication and JavaScript interactions. The process involves understanding the code's purpose, identifying key elements, analyzing behavior, and then synthesizing this information into a coherent and informative summary.
这是 Chromium 网络栈中处理 QUIC 协议上 SPDY (HTTP/2 的前身，但在 QUIC 的上下文中更像是一个通用的 HTTP 语义层) 流的核心实现文件的一部分。

**功能归纳 (针对提供的第一部分代码):**

总的来说，这部分代码定义了 `QuicSpdyStream` 类，负责管理通过 QUIC 连接发送和接收的单个 HTTP 或类 HTTP 的数据流。它处理了 HTTP 帧（如 HEADERS 和 DATA）的解析和生成，并与底层的 QUIC 连接和会话进行交互。

更具体地说，这部分代码主要关注以下功能：

* **HTTP 帧的接收和解析:**
    * 使用 `HttpDecoder` 来解析从 QUIC 流接收到的字节流，并将不同的 HTTP 帧（目前只处理 DATA 和 HEADERS）分发到相应的处理逻辑。
    * 定义了一个内部类 `HttpDecoderVisitor` 作为 `HttpDecoder` 的访问者，根据接收到的帧类型执行相应的操作，例如将 DATA 帧的数据传递给 `QuicSpdyStream` 或在接收到不允许的帧时关闭连接。
    * 针对 HTTP/3 和早期版本的 QUIC 有不同的处理逻辑，例如，非 HTTP/3 版本不允许在数据流上接收 HEADERS 帧。
* **HTTP 帧的发送:**
    * 提供了 `WriteHeaders`, `WriteOrBufferBody`, `WriteTrailers`, `WriteBodySlices` 等方法来构造和发送 HTTP HEADERS, DATA 和 TRAILERS 帧。
    * 实现了 HTTP/3 DATA 帧头的写入逻辑。
* **流状态管理:**
    * 跟踪流的各种状态，例如是否已接收或发送 FIN (表示流的结束)，是否已解码头部或尾部。
    * 管理接收到的头部和尾部数据 (`header_list_`, `received_trailers_`).
* **与 `QuicSpdySession` 的集成:**
    * 与 `QuicSpdySession` 类紧密协作，后者管理整个 QUIC 会话。
    * 在流创建时通知会话 (`spdy_session_->OnStreamCreated(this)`).
* **WebTransport 集成 (初步):**
    * 代码中出现了一些与 WebTransport 相关的逻辑，例如检查是否为 WebTransport 数据流，以及在发送头部时可能添加特定的头部。
* **优先级处理:**
    * 包含了处理流优先级的相关方法 (`OnStreamHeadersPriority`).
* **错误处理:**
    * 提供了 `OnUnrecoverableError` 方法来处理不可恢复的错误。
* **统计和调试:**
    * 包含了一些用于调试和统计的变量和方法。

**与 JavaScript 的功能关系：**

`QuicSpdyStream` 本身是 C++ 代码，JavaScript 无法直接访问或调用。然而，它的功能是支撑浏览器中 JavaScript 发起的网络请求的底层实现。

**举例说明：**

假设你在浏览器中通过 JavaScript 的 `fetch` API 发起一个 HTTP 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.text())
  .then(data => console.log(data));
```

在这个过程中，浏览器会执行以下（简化的）步骤，最终会涉及到 `QuicSpdyStream`：

1. **DNS 解析和连接建立:** 浏览器首先解析 `example.com` 的 IP 地址，并建立一个到服务器的 QUIC 连接。这部分由 Chromium 网络栈的其他部分处理。
2. **创建 QUIC 流:**  当 `fetch` 发起请求时，网络栈会在已建立的 QUIC 连接上创建一个新的 `QuicSpdyStream` 对象。
3. **发送 HTTP 头部:**  `fetch` API 构造的 HTTP 请求头部（例如 `GET /data HTTP/3`, `Host: example.com` 等）会被传递给 `QuicSpdyStream` 的 `WriteHeaders` 方法。该方法会将这些头部序列化成 HTTP/3 的 HEADERS 帧，并通过底层的 QUIC 连接发送出去。
4. **接收 HTTP 响应头部:** 服务器收到请求后，会发送 HTTP 响应头部。这些数据会通过 QUIC 连接到达浏览器，并被 `QuicSpdyStream` 的 `HttpDecoder` 解析。解析后的头部信息会被存储在 `header_list_` 中，并最终被 JavaScript 的 `fetch` API 的 `response` 对象访问。
5. **接收 HTTP 响应体:** 服务器发送的响应体数据会被封装在 HTTP/3 的 DATA 帧中。`QuicSpdyStream` 的 `HttpDecoderVisitor` 会将 DATA 帧的 payload 传递给 `QuicSpdyStream`，最终通过 `Readv` 等方法被 JavaScript 读取。

**假设输入与输出 (逻辑推理):**

假设输入是一个包含完整 HTTP 请求头部的字节流（HTTP/3 格式）：

**输入 (假设的 HEADERS 帧内容):**

```
00 00 04  // 帧类型 (HEADERS)
00 00 1a  // 帧长度 (26 字节)
83         // :method: GET (索引表示)
86         // :scheme: https
c1         // :path: /data
94         // host: example.com
```

**输出 (`QuicSpdyStream` 内部状态变化):**

* `headers_decompressed_` 将变为 `true`。
* `header_list_` 将包含解析后的头部信息：
  ```
  {
    ":method": "GET",
    ":scheme": "https",
    ":path": "/data",
    "host": "example.com"
  }
  ```
* 如果这是初始头部，且没有错误，可能会调用 `OnInitialHeadersComplete` 等回调方法。

**用户或编程常见的使用错误：**

* **在非 HTTP/3 连接上接收到 HEADERS 帧:** 根据代码，如果运行在非 HTTP/3 的 QUIC 连接上，并且接收到 HEADERS 帧，`HttpDecoderVisitor::OnHeadersFrameStart` 会调用 `CloseConnectionOnWrongFrame`，导致连接关闭。这是一个协议错误。
* **发送无效的 HTTP 头部:**  如果用户代码（或者更上层的 Chromium 代码）构造了不符合 HTTP 规范的头部，例如头部名称包含非法字符，可能会导致 `HttpDecoder` 解析错误，进而触发 `OnError` 回调，最终导致连接关闭。
* **在流关闭后尝试写入数据:**  如果用户代码尝试在 `QuicSpdyStream` 的写端已经关闭后调用 `WriteOrBufferBody` 等方法，可能会导致数据无法发送或程序出现错误。代码中虽然有检查 `AssertNotWebTransportDataStream`，但更底层的 QUIC 流也有自己的状态管理。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入 URL 并回车，或者点击一个链接。**
2. **浏览器解析 URL，确定协议 (HTTPS) 和域名。**
3. **浏览器查找或建立到目标服务器的 QUIC 连接。**
4. **如果需要建立新的连接，会涉及到 QUIC 的握手过程。**
5. **一旦 QUIC 连接建立，浏览器会创建一个新的 `QuicSpdyStream` 对象来发送 HTTP 请求。**
6. **`fetch` API 或其他网络请求相关的 JavaScript 代码会被调用，构造 HTTP 请求头部。**
7. **这些头部数据被传递给 `QuicSpdyStream` 的 `WriteHeaders` 方法。**
8. **`WriteHeaders` 方法会将头部数据序列化并发送到 QUIC 连接上。**
9. **服务器的响应数据到达后，会被底层的 QUIC 层接收。**
10. **QUIC 层将数据传递给与该流关联的 `QuicSpdyStream` 对象。**
11. **`QuicSpdyStream` 的 `OnDataAvailable` 方法被调用，触发 `HttpDecoder` 开始解析接收到的字节流。**
12. **`HttpDecoderVisitor` 根据解析到的帧类型调用 `QuicSpdyStream` 的相应方法，例如 `OnHeadersFrameStart`, `OnDataFramePayload` 等。**

这个过程涉及到网络栈的多个组件，`QuicSpdyStream` 位于处理 HTTP 语义和 QUIC 数据传输之间的关键位置。调试时，可以在 `QuicSpdyStream` 的关键方法（例如 `OnDataAvailable`, `WriteHeaders`, `OnStreamFrame`) 设置断点，观察流的状态变化和数据的流动。

**总结 (针对提供的第一部分):**

这部分代码定义了 `QuicSpdyStream` 类的核心结构和接收处理逻辑。它负责接收和解析来自 QUIC 流的 HTTP/3 (或早期 QUIC 版本) 帧，特别是 HEADERS 和 DATA 帧，并将数据传递给上层应用。它还提供了发送 HTTP 数据的接口，并集成了 WebTransport 的初步支持。 它的主要职责是作为 QUIC 流上 HTTP 语义的载体，连接底层的 QUIC 连接管理和上层的 HTTP 处理逻辑。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_stream.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/http/quic_spdy_stream.h"

#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "absl/base/macros.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/http2/adapter/header_validator.h"
#include "quiche/http2/core/spdy_protocol.h"
#include "quiche/http2/http2_constants.h"
#include "quiche/quic/core/http/http_constants.h"
#include "quiche/quic/core/http/http_decoder.h"
#include "quiche/quic/core/http/http_frames.h"
#include "quiche/quic/core/http/quic_spdy_session.h"
#include "quiche/quic/core/http/spdy_utils.h"
#include "quiche/quic/core/http/web_transport_http3.h"
#include "quiche/quic/core/qpack/qpack_decoder.h"
#include "quiche/quic/core/qpack/qpack_encoder.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_stream_priority.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/core/quic_write_blocked_list.h"
#include "quiche/quic/core/web_transport_interface.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_testvalue.h"
#include "quiche/common/capsule.h"
#include "quiche/common/platform/api/quiche_flag_utils.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_mem_slice_storage.h"
#include "quiche/common/quiche_text_utils.h"

using ::quiche::Capsule;
using ::quiche::CapsuleType;
using ::quiche::HttpHeaderBlock;

namespace quic {

// Visitor of HttpDecoder that passes data frame to QuicSpdyStream and closes
// the connection on unexpected frames.
class QuicSpdyStream::HttpDecoderVisitor : public HttpDecoder::Visitor {
 public:
  explicit HttpDecoderVisitor(QuicSpdyStream* stream) : stream_(stream) {}
  HttpDecoderVisitor(const HttpDecoderVisitor&) = delete;
  HttpDecoderVisitor& operator=(const HttpDecoderVisitor&) = delete;

  void OnError(HttpDecoder* decoder) override {
    stream_->OnUnrecoverableError(decoder->error(), decoder->error_detail());
  }

  bool OnMaxPushIdFrame() override {
    CloseConnectionOnWrongFrame("Max Push Id");
    return false;
  }

  bool OnGoAwayFrame(const GoAwayFrame& /*frame*/) override {
    CloseConnectionOnWrongFrame("Goaway");
    return false;
  }

  bool OnSettingsFrameStart(QuicByteCount /*header_length*/) override {
    CloseConnectionOnWrongFrame("Settings");
    return false;
  }

  bool OnSettingsFrame(const SettingsFrame& /*frame*/) override {
    CloseConnectionOnWrongFrame("Settings");
    return false;
  }

  bool OnDataFrameStart(QuicByteCount header_length,
                        QuicByteCount payload_length) override {
    return stream_->OnDataFrameStart(header_length, payload_length);
  }

  bool OnDataFramePayload(absl::string_view payload) override {
    QUICHE_DCHECK(!payload.empty());
    return stream_->OnDataFramePayload(payload);
  }

  bool OnDataFrameEnd() override { return stream_->OnDataFrameEnd(); }

  bool OnHeadersFrameStart(QuicByteCount header_length,
                           QuicByteCount payload_length) override {
    if (!VersionUsesHttp3(stream_->transport_version())) {
      CloseConnectionOnWrongFrame("Headers");
      return false;
    }
    return stream_->OnHeadersFrameStart(header_length, payload_length);
  }

  bool OnHeadersFramePayload(absl::string_view payload) override {
    QUICHE_DCHECK(!payload.empty());
    if (!VersionUsesHttp3(stream_->transport_version())) {
      CloseConnectionOnWrongFrame("Headers");
      return false;
    }
    return stream_->OnHeadersFramePayload(payload);
  }

  bool OnHeadersFrameEnd() override {
    if (!VersionUsesHttp3(stream_->transport_version())) {
      CloseConnectionOnWrongFrame("Headers");
      return false;
    }
    return stream_->OnHeadersFrameEnd();
  }

  bool OnPriorityUpdateFrameStart(QuicByteCount /*header_length*/) override {
    CloseConnectionOnWrongFrame("Priority update");
    return false;
  }

  bool OnPriorityUpdateFrame(const PriorityUpdateFrame& /*frame*/) override {
    CloseConnectionOnWrongFrame("Priority update");
    return false;
  }

  bool OnOriginFrameStart(QuicByteCount /*header_length*/) override {
    CloseConnectionOnWrongFrame("ORIGIN");
    return false;
  }

  bool OnOriginFrame(const OriginFrame& /*frame*/) override {
    CloseConnectionOnWrongFrame("ORIGIN");
    return false;
  }

  bool OnAcceptChFrameStart(QuicByteCount /*header_length*/) override {
    CloseConnectionOnWrongFrame("ACCEPT_CH");
    return false;
  }

  bool OnAcceptChFrame(const AcceptChFrame& /*frame*/) override {
    CloseConnectionOnWrongFrame("ACCEPT_CH");
    return false;
  }

  void OnWebTransportStreamFrameType(
      QuicByteCount header_length, WebTransportSessionId session_id) override {
    stream_->OnWebTransportStreamFrameType(header_length, session_id);
  }

  bool OnMetadataFrameStart(QuicByteCount header_length,
                            QuicByteCount payload_length) override {
    if (!VersionUsesHttp3(stream_->transport_version())) {
      CloseConnectionOnWrongFrame("Metadata");
      return false;
    }
    return stream_->OnMetadataFrameStart(header_length, payload_length);
  }

  bool OnMetadataFramePayload(absl::string_view payload) override {
    QUICHE_DCHECK(!payload.empty());
    if (!VersionUsesHttp3(stream_->transport_version())) {
      CloseConnectionOnWrongFrame("Metadata");
      return false;
    }
    return stream_->OnMetadataFramePayload(payload);
  }

  bool OnMetadataFrameEnd() override {
    if (!VersionUsesHttp3(stream_->transport_version())) {
      CloseConnectionOnWrongFrame("Metadata");
      return false;
    }
    return stream_->OnMetadataFrameEnd();
  }

  bool OnUnknownFrameStart(uint64_t frame_type, QuicByteCount header_length,
                           QuicByteCount payload_length) override {
    return stream_->OnUnknownFrameStart(frame_type, header_length,
                                        payload_length);
  }

  bool OnUnknownFramePayload(absl::string_view payload) override {
    return stream_->OnUnknownFramePayload(payload);
  }

  bool OnUnknownFrameEnd() override { return stream_->OnUnknownFrameEnd(); }

 private:
  void CloseConnectionOnWrongFrame(absl::string_view frame_type) {
    stream_->OnUnrecoverableError(
        QUIC_HTTP_FRAME_UNEXPECTED_ON_SPDY_STREAM,
        absl::StrCat(frame_type, " frame received on data stream"));
  }

  QuicSpdyStream* stream_;
};

#define ENDPOINT                                                   \
  (session()->perspective() == Perspective::IS_SERVER ? "Server: " \
                                                      : "Client:"  \
                                                        " ")

QuicSpdyStream::QuicSpdyStream(QuicStreamId id, QuicSpdySession* spdy_session,
                               StreamType type)
    : QuicStream(id, spdy_session, /*is_static=*/false, type),
      spdy_session_(spdy_session),
      on_body_available_called_because_sequencer_is_closed_(false),
      visitor_(nullptr),
      blocked_on_decoding_headers_(false),
      headers_decompressed_(false),
      header_list_size_limit_exceeded_(false),
      headers_payload_length_(0),
      trailers_decompressed_(false),
      trailers_consumed_(false),
      http_decoder_visitor_(std::make_unique<HttpDecoderVisitor>(this)),
      decoder_(http_decoder_visitor_.get()),
      sequencer_offset_(0),
      is_decoder_processing_input_(false),
      ack_listener_(nullptr) {
  QUICHE_DCHECK_EQ(session()->connection(), spdy_session->connection());
  QUICHE_DCHECK_EQ(transport_version(), spdy_session->transport_version());
  QUICHE_DCHECK(!QuicUtils::IsCryptoStreamId(transport_version(), id));
  QUICHE_DCHECK_EQ(0u, sequencer()->NumBytesConsumed());
  // If headers are sent on the headers stream, then do not receive any
  // callbacks from the sequencer until headers are complete.
  if (!VersionUsesHttp3(transport_version())) {
    sequencer()->SetBlockedUntilFlush();
  }

  if (VersionUsesHttp3(transport_version())) {
    sequencer()->set_level_triggered(true);
  }

  spdy_session_->OnStreamCreated(this);
}

QuicSpdyStream::QuicSpdyStream(PendingStream* pending,
                               QuicSpdySession* spdy_session)
    : QuicStream(pending, spdy_session, /*is_static=*/false),
      spdy_session_(spdy_session),
      on_body_available_called_because_sequencer_is_closed_(false),
      visitor_(nullptr),
      blocked_on_decoding_headers_(false),
      headers_decompressed_(false),
      header_list_size_limit_exceeded_(false),
      headers_payload_length_(0),
      trailers_decompressed_(false),
      trailers_consumed_(false),
      http_decoder_visitor_(std::make_unique<HttpDecoderVisitor>(this)),
      decoder_(http_decoder_visitor_.get()),
      sequencer_offset_(sequencer()->NumBytesConsumed()),
      is_decoder_processing_input_(false),
      ack_listener_(nullptr) {
  QUICHE_DCHECK_EQ(session()->connection(), spdy_session->connection());
  QUICHE_DCHECK_EQ(transport_version(), spdy_session->transport_version());
  QUICHE_DCHECK(!QuicUtils::IsCryptoStreamId(transport_version(), id()));
  // If headers are sent on the headers stream, then do not receive any
  // callbacks from the sequencer until headers are complete.
  if (!VersionUsesHttp3(transport_version())) {
    sequencer()->SetBlockedUntilFlush();
  }

  if (VersionUsesHttp3(transport_version())) {
    sequencer()->set_level_triggered(true);
  }

  spdy_session_->OnStreamCreated(this);
}

QuicSpdyStream::~QuicSpdyStream() {}

size_t QuicSpdyStream::WriteHeaders(
    HttpHeaderBlock header_block, bool fin,
    quiche::QuicheReferenceCountedPointer<QuicAckListenerInterface>
        ack_listener) {
  if (!AssertNotWebTransportDataStream("writing headers")) {
    return 0;
  }

  QuicConnection::ScopedPacketFlusher flusher(spdy_session_->connection());

  MaybeProcessSentWebTransportHeaders(header_block);

  if (web_transport_ != nullptr &&
      spdy_session_->perspective() == Perspective::IS_SERVER &&
      spdy_session_->SupportedWebTransportVersion() ==
          WebTransportHttp3Version::kDraft02) {
    header_block["sec-webtransport-http3-draft"] = "draft02";
  }

  size_t bytes_written =
      WriteHeadersImpl(std::move(header_block), fin, std::move(ack_listener));
  if (!VersionUsesHttp3(transport_version()) && fin) {
    // If HEADERS are sent on the headers stream, then |fin_sent_| needs to be
    // set and write side needs to be closed without actually sending a FIN on
    // this stream.
    // TODO(rch): Add test to ensure fin_sent_ is set whenever a fin is sent.
    SetFinSent();
    CloseWriteSide();
  }

  if (web_transport_ != nullptr &&
      session()->perspective() == Perspective::IS_CLIENT) {
    WriteGreaseCapsule();
    if (spdy_session_->http_datagram_support() ==
        HttpDatagramSupport::kDraft04) {
      // Send a REGISTER_DATAGRAM_NO_CONTEXT capsule to support servers that
      // are running draft-ietf-masque-h3-datagram-04 or -05.
      uint64_t capsule_type = 0xff37a2;  // REGISTER_DATAGRAM_NO_CONTEXT
      constexpr unsigned char capsule_data[4] = {
          0x80, 0xff, 0x7c, 0x00,  // WEBTRANSPORT datagram format type
      };
      WriteCapsule(Capsule::Unknown(
          capsule_type,
          absl::string_view(reinterpret_cast<const char*>(capsule_data),
                            sizeof(capsule_data))));
      WriteGreaseCapsule();
    }
  }

  if (connect_ip_visitor_ != nullptr) {
    connect_ip_visitor_->OnHeadersWritten();
  }

  return bytes_written;
}

void QuicSpdyStream::WriteOrBufferBody(absl::string_view data, bool fin) {
  if (!AssertNotWebTransportDataStream("writing body data")) {
    return;
  }
  if (!VersionUsesHttp3(transport_version()) || data.length() == 0) {
    WriteOrBufferData(data, fin, nullptr);
    return;
  }
  QuicConnection::ScopedPacketFlusher flusher(spdy_session_->connection());

  const bool success =
      WriteDataFrameHeader(data.length(), /*force_write=*/true);
  QUICHE_DCHECK(success);

  // Write body.
  QUIC_DVLOG(1) << ENDPOINT << "Stream " << id()
                << " is writing DATA frame payload of length " << data.length()
                << " with fin " << fin;
  WriteOrBufferData(data, fin, nullptr);
}

size_t QuicSpdyStream::WriteTrailers(
    HttpHeaderBlock trailer_block,
    quiche::QuicheReferenceCountedPointer<QuicAckListenerInterface>
        ack_listener) {
  if (fin_sent()) {
    QUIC_BUG(quic_bug_10410_1)
        << "Trailers cannot be sent after a FIN, on stream " << id();
    return 0;
  }

  if (!VersionUsesHttp3(transport_version())) {
    // The header block must contain the final offset for this stream, as the
    // trailers may be processed out of order at the peer.
    const QuicStreamOffset final_offset =
        stream_bytes_written() + BufferedDataBytes();
    QUIC_DVLOG(1) << ENDPOINT << "Inserting trailer: (" << kFinalOffsetHeaderKey
                  << ", " << final_offset << ")";
    trailer_block.insert(
        std::make_pair(kFinalOffsetHeaderKey, absl::StrCat(final_offset)));
  }

  // Write the trailing headers with a FIN, and close stream for writing:
  // trailers are the last thing to be sent on a stream.
  const bool kFin = true;
  size_t bytes_written =
      WriteHeadersImpl(std::move(trailer_block), kFin, std::move(ack_listener));

  // If trailers are sent on the headers stream, then |fin_sent_| needs to be
  // set without actually sending a FIN on this stream.
  if (!VersionUsesHttp3(transport_version())) {
    SetFinSent();

    // Also, write side of this stream needs to be closed.  However, only do
    // this if there is no more buffered data, otherwise it will never be sent.
    if (BufferedDataBytes() == 0) {
      CloseWriteSide();
    }
  }

  return bytes_written;
}

QuicConsumedData QuicSpdyStream::WritevBody(const struct iovec* iov, int count,
                                            bool fin) {
  quiche::QuicheMemSliceStorage storage(
      iov, count,
      session()->connection()->helper()->GetStreamSendBufferAllocator(),
      GetQuicFlag(quic_send_buffer_max_data_slice_size));
  return WriteBodySlices(storage.ToSpan(), fin);
}

bool QuicSpdyStream::WriteDataFrameHeader(QuicByteCount data_length,
                                          bool force_write) {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()));
  QUICHE_DCHECK_GT(data_length, 0u);
  quiche::QuicheBuffer header = HttpEncoder::SerializeDataFrameHeader(
      data_length,
      spdy_session_->connection()->helper()->GetStreamSendBufferAllocator());
  const bool can_write = CanWriteNewDataAfterData(header.size());
  if (!can_write && !force_write) {
    return false;
  }

  if (spdy_session_->debug_visitor()) {
    spdy_session_->debug_visitor()->OnDataFrameSent(id(), data_length);
  }

  unacked_frame_headers_offsets_.Add(
      send_buffer().stream_offset(),
      send_buffer().stream_offset() + header.size());
  QUIC_DVLOG(1) << ENDPOINT << "Stream " << id()
                << " is writing DATA frame header of length " << header.size();
  if (can_write) {
    // Save one copy and allocation if send buffer can accomodate the header.
    quiche::QuicheMemSlice header_slice(std::move(header));
    WriteMemSlices(absl::MakeSpan(&header_slice, 1), false);
  } else {
    QUICHE_DCHECK(force_write);
    WriteOrBufferData(header.AsStringView(), false, nullptr);
  }
  return true;
}

QuicConsumedData QuicSpdyStream::WriteBodySlices(
    absl::Span<quiche::QuicheMemSlice> slices, bool fin) {
  if (!VersionUsesHttp3(transport_version()) || slices.empty()) {
    return WriteMemSlices(slices, fin);
  }

  QuicConnection::ScopedPacketFlusher flusher(spdy_session_->connection());
  const QuicByteCount data_size = MemSliceSpanTotalSize(slices);
  if (!WriteDataFrameHeader(data_size, /*force_write=*/false)) {
    return {0, false};
  }

  QUIC_DVLOG(1) << ENDPOINT << "Stream " << id()
                << " is writing DATA frame payload of length " << data_size;
  return WriteMemSlices(slices, fin);
}

size_t QuicSpdyStream::Readv(const struct iovec* iov, size_t iov_len) {
  QUICHE_DCHECK(FinishedReadingHeaders());
  if (!VersionUsesHttp3(transport_version())) {
    return sequencer()->Readv(iov, iov_len);
  }
  size_t bytes_read = 0;
  sequencer()->MarkConsumed(body_manager_.ReadBody(iov, iov_len, &bytes_read));

  return bytes_read;
}

int QuicSpdyStream::GetReadableRegions(iovec* iov, size_t iov_len) const {
  QUICHE_DCHECK(FinishedReadingHeaders());
  if (!VersionUsesHttp3(transport_version())) {
    return sequencer()->GetReadableRegions(iov, iov_len);
  }
  return body_manager_.PeekBody(iov, iov_len);
}

void QuicSpdyStream::MarkConsumed(size_t num_bytes) {
  QUICHE_DCHECK(FinishedReadingHeaders());
  if (!VersionUsesHttp3(transport_version())) {
    sequencer()->MarkConsumed(num_bytes);
    return;
  }

  sequencer()->MarkConsumed(body_manager_.OnBodyConsumed(num_bytes));
}

bool QuicSpdyStream::IsDoneReading() const {
  bool done_reading_headers = FinishedReadingHeaders();
  bool done_reading_body = sequencer()->IsClosed();
  bool done_reading_trailers = FinishedReadingTrailers();
  return done_reading_headers && done_reading_body && done_reading_trailers;
}

bool QuicSpdyStream::HasBytesToRead() const {
  if (!VersionUsesHttp3(transport_version())) {
    return sequencer()->HasBytesToRead();
  }
  return body_manager_.HasBytesToRead();
}

QuicByteCount QuicSpdyStream::ReadableBytes() const {
  if (!VersionUsesHttp3(transport_version())) {
    return sequencer()->ReadableBytes();
  }
  return body_manager_.ReadableBytes();
}

void QuicSpdyStream::MarkTrailersConsumed() { trailers_consumed_ = true; }

uint64_t QuicSpdyStream::total_body_bytes_read() const {
  if (VersionUsesHttp3(transport_version())) {
    return body_manager_.total_body_bytes_received();
  }
  return sequencer()->NumBytesConsumed();
}

void QuicSpdyStream::ConsumeHeaderList() {
  header_list_.Clear();

  if (!FinishedReadingHeaders()) {
    return;
  }

  if (!VersionUsesHttp3(transport_version())) {
    sequencer()->SetUnblocked();
    return;
  }

  if (body_manager_.HasBytesToRead()) {
    HandleBodyAvailable();
    return;
  }

  if (sequencer()->IsClosed() &&
      !on_body_available_called_because_sequencer_is_closed_) {
    on_body_available_called_because_sequencer_is_closed_ = true;
    HandleBodyAvailable();
  }
}

void QuicSpdyStream::OnStreamHeadersPriority(
    const spdy::SpdyStreamPrecedence& precedence) {
  QUICHE_DCHECK_EQ(Perspective::IS_SERVER,
                   session()->connection()->perspective());
  SetPriority(QuicStreamPriority(HttpStreamPriority{
      precedence.spdy3_priority(), HttpStreamPriority::kDefaultIncremental}));
}

void QuicSpdyStream::OnStreamHeaderList(bool fin, size_t frame_len,
                                        const QuicHeaderList& header_list) {
  if (!spdy_session()->user_agent_id().has_value()) {
    std::string uaid;
    for (const auto& kv : header_list) {
      if (quiche::QuicheTextUtils::ToLower(kv.first) == kUserAgentHeaderName) {
        uaid = kv.second;
        break;
      }
    }
    spdy_session()->SetUserAgentId(std::move(uaid));
  }

  // TODO(b/134706391): remove |fin| argument.
  // When using Google QUIC, an empty header list indicates that the size limit
  // has been exceeded.
  // When using IETF QUIC, there is an explicit signal from
  // QpackDecodedHeadersAccumulator.
  if ((VersionUsesHttp3(transport_version()) &&
       header_list_size_limit_exceeded_) ||
      (!VersionUsesHttp3(transport_version()) && header_list.empty())) {
    OnHeadersTooLarge();
    if (IsDoneReading()) {
      return;
    }
  }
  if (!NextHeaderIsTrailer()) {
    OnInitialHeadersComplete(fin, frame_len, header_list);
  } else {
    OnTrailingHeadersComplete(fin, frame_len, header_list);
  }
}

void QuicSpdyStream::OnHeadersDecoded(QuicHeaderList headers,
                                      bool header_list_size_limit_exceeded) {
  header_list_size_limit_exceeded_ = header_list_size_limit_exceeded;
  qpack_decoded_headers_accumulator_.reset();

  QuicSpdySession::LogHeaderCompressionRatioHistogram(
      /* using_qpack = */ true,
      /* is_sent = */ false, headers.compressed_header_bytes(),
      headers.uncompressed_header_bytes());

  header_decoding_delay_ = QuicTime::Delta::Zero();

  if (blocked_on_decoding_headers_) {
    const QuicTime now = session()->GetClock()->ApproximateNow();
    if (!header_block_received_time_.IsInitialized() ||
        now < header_block_received_time_) {
      QUICHE_BUG(QuicSpdyStream_time_flows_backwards);
    } else {
      header_decoding_delay_ = now - header_block_received_time_;
    }
  }

  Http3DebugVisitor* const debug_visitor = spdy_session()->debug_visitor();
  if (debug_visitor) {
    debug_visitor->OnHeadersDecoded(id(), headers);
  }

  OnStreamHeaderList(/* fin = */ false, headers_payload_length_, headers);

  if (blocked_on_decoding_headers_) {
    blocked_on_decoding_headers_ = false;
    // Continue decoding HTTP/3 frames.
    OnDataAvailable();
  }
}

void QuicSpdyStream::OnHeaderDecodingError(QuicErrorCode error_code,
                                           absl::string_view error_message) {
  qpack_decoded_headers_accumulator_.reset();

  std::string connection_close_error_message = absl::StrCat(
      "Error decoding ", headers_decompressed_ ? "trailers" : "headers",
      " on stream ", id(), ": ", error_message);
  OnUnrecoverableError(error_code, connection_close_error_message);
}

void QuicSpdyStream::MaybeSendPriorityUpdateFrame() {
  if (!VersionUsesHttp3(transport_version()) ||
      session()->perspective() != Perspective::IS_CLIENT) {
    return;
  }
  if (priority().type() != QuicPriorityType::kHttp) {
    return;
  }

  if (last_sent_priority_ == priority()) {
    return;
  }
  last_sent_priority_ = priority();

  spdy_session_->WriteHttp3PriorityUpdate(id(), priority().http());
}

void QuicSpdyStream::OnHeadersTooLarge() { Reset(QUIC_HEADERS_TOO_LARGE); }

void QuicSpdyStream::OnInitialHeadersComplete(
    bool fin, size_t /*frame_len*/, const QuicHeaderList& header_list) {
  // TODO(b/134706391): remove |fin| argument.
  headers_decompressed_ = true;
  header_list_ = header_list;
  bool header_too_large = VersionUsesHttp3(transport_version())
                              ? header_list_size_limit_exceeded_
                              : header_list.empty();
  if (!AreHeaderFieldValuesValid(header_list)) {
    OnInvalidHeaders();
    return;
  }
  // Validate request headers if it did not exceed size limit. If it did,
  // OnHeadersTooLarge() should have already handled it previously.
  if (!header_too_large && !ValidateReceivedHeaders(header_list)) {
    QUIC_CODE_COUNT_N(quic_validate_request_header, 1, 2);
    QUICHE_DCHECK(!invalid_request_details().empty())
        << "ValidatedRequestHeaders() returns false without populating "
           "invalid_request_details_";
    if (GetQuicReloadableFlag(quic_act_upon_invalid_header)) {
      QUIC_RELOADABLE_FLAG_COUNT(quic_act_upon_invalid_header);
      OnInvalidHeaders();
      return;
    }
  }
  QUIC_CODE_COUNT_N(quic_validate_request_header, 2, 2);

  if (!header_too_large) {
    MaybeProcessReceivedWebTransportHeaders();
  }

  if (VersionUsesHttp3(transport_version())) {
    if (fin) {
      OnStreamFrame(QuicStreamFrame(id(), /* fin = */ true,
                                    highest_received_byte_offset(),
                                    absl::string_view()));
    }
    return;
  }

  if (fin && !rst_sent()) {
    OnStreamFrame(
        QuicStreamFrame(id(), fin, /* offset = */ 0, absl::string_view()));
  }
  if (FinishedReadingHeaders()) {
    sequencer()->SetUnblocked();
  }
}

bool QuicSpdyStream::CopyAndValidateTrailers(
    const QuicHeaderList& header_list, bool expect_final_byte_offset,
    size_t* final_byte_offset, quiche::HttpHeaderBlock* trailers) {
  return SpdyUtils::CopyAndValidateTrailers(
      header_list, expect_final_byte_offset, final_byte_offset, trailers);
}

void QuicSpdyStream::OnTrailingHeadersComplete(
    bool fin, size_t /*frame_len*/, const QuicHeaderList& header_list) {
  // TODO(b/134706391): remove |fin| argument.
  QUICHE_DCHECK(!trailers_decompressed_);
  if (!VersionUsesHttp3(transport_version()) && fin_received()) {
    QUIC_DLOG(INFO) << ENDPOINT
                    << "Received Trailers after FIN, on stream: " << id();
    stream_delegate()->OnStreamError(QUIC_INVALID_HEADERS_STREAM_DATA,
                                     "Trailers after fin");
    return;
  }

  if (!VersionUsesHttp3(transport_version()) && !fin) {
    QUIC_DLOG(INFO) << ENDPOINT
                    << "Trailers must have FIN set, on stream: " << id();
    stream_delegate()->OnStreamError(QUIC_INVALID_HEADERS_STREAM_DATA,
                                     "Fin missing from trailers");
    return;
  }

  size_t final_byte_offset = 0;
  const bool expect_final_byte_offset = !VersionUsesHttp3(transport_version());
  if (!CopyAndValidateTrailers(header_list, expect_final_byte_offset,
                               &final_byte_offset, &received_trailers_)) {
    QUIC_DLOG(ERROR) << ENDPOINT << "Trailers for stream " << id()
                     << " are malformed.";
    stream_delegate()->OnStreamError(QUIC_INVALID_HEADERS_STREAM_DATA,
                                     "Trailers are malformed");
    return;
  }
  trailers_decompressed_ = true;
  if (fin) {
    const QuicStreamOffset offset = VersionUsesHttp3(transport_version())
                                        ? highest_received_byte_offset()
                                        : final_byte_offset;
    OnStreamFrame(QuicStreamFrame(id(), fin, offset, absl::string_view()));
  }
}

void QuicSpdyStream::RegisterMetadataVisitor(MetadataVisitor* visitor) {
  metadata_visitor_ = visitor;
}

void QuicSpdyStream::UnregisterMetadataVisitor() {
  metadata_visitor_ = nullptr;
}

void QuicSpdyStream::OnPriorityFrame(
    const spdy::SpdyStreamPrecedence& precedence) {
  QUICHE_DCHECK_EQ(Perspective::IS_SERVER,
                   session()->connection()->perspective());
  SetPriority(QuicStreamPriority(HttpStreamPriority{
      precedence.spdy3_priority(), HttpStreamPriority::kDefaultIncremental}));
}

void QuicSpdyStream::OnStreamReset(const QuicRstStreamFrame& frame) {
  if (web_transport_data_ != nullptr) {
    WebTransportStreamVisitor* webtransport_visitor =
        web_transport_data_->adapter.visitor();
    if (webtransport_visitor != nullptr) {
      webtransport_visitor->OnResetStreamReceived(
          Http3ErrorToWebTransportOrDefault(frame.ietf_error_code));
    }
    QuicStream::OnStreamReset(frame);
    return;
  }

  if (VersionUsesHttp3(transport_version()) && !fin_received() &&
      spdy_session_->qpack_decoder()) {
    spdy_session_->qpack_decoder()->OnStreamReset(id());
    qpack_decoded_headers_accumulator_.reset();
  }

  if (VersionUsesHttp3(transport_version()) ||
      frame.error_code != QUIC_STREAM_NO_ERROR) {
    QuicStream::OnStreamReset(frame);
    return;
  }

  QUIC_DVLOG(1) << ENDPOINT
                << "Received QUIC_STREAM_NO_ERROR, not discarding response";
  set_rst_received(true);
  MaybeIncreaseHighestReceivedOffset(frame.byte_offset);
  set_stream_error(frame.error());
  CloseWriteSide();
}

void QuicSpdyStream::ResetWithError(QuicResetStreamError error) {
  if (VersionUsesHttp3(transport_version()) && !fin_received() &&
      spdy_session_->qpack_decoder() && web_transport_data_ == nullptr) {
    spdy_session_->qpack_decoder()->OnStreamReset(id());
    qpack_decoded_headers_accumulator_.reset();
  }

  QuicStream::ResetWithError(error);
}

bool QuicSpdyStream::OnStopSending(QuicResetStreamError error) {
  if (web_transport_data_ != nullptr) {
    WebTransportStreamVisitor* visitor = web_transport_data_->adapter.visitor();
    if (visitor != nullptr) {
      visitor->OnStopSendingReceived(
          Http3ErrorToWebTransportOrDefault(error.ietf_application_code()));
    }
  }

  return QuicStream::OnStopSending(error);
}

void QuicSpdyStream::OnWriteSideInDataRecvdState() {
  if (web_transport_data_ != nullptr) {
    WebTransportStreamVisitor* visitor = web_transport_data_->adapter.visitor();
    if (visitor != nullptr) {
      visitor->OnWriteSideInDataRecvdState();
    }
  }

  QuicStream::OnWriteSideInDataRecvdState();
}

void QuicSpdyStream::OnDataAvailable() {
  if (!VersionUsesHttp3(transport_version())) {
    // Sequencer must be blocked until headers are consumed.
    QUICHE_DCHECK(FinishedReadingHeaders());
  }

  if (!VersionUsesHttp3(transport_version())) {
    HandleBodyAvailable();
    return;
  }

  if (web_transport_data_ != nullptr) {
    web_transport_data_->adapter.OnDataAvailable();
    return;
  }

  if (!spdy_session()->ShouldProcessIncomingRequests()) {
    spdy_session()->OnStreamWaitingForClientSettings(id());
    return;
  }

  if (is_decoder_processing_input_) {
    // Let the outermost nested OnDataAvailable() call do the work.
    return;
  }

  if (blocked_on_decoding_headers_) {
    return;
  }

  if (spdy_session_->SupportsWebTransport()) {
    // We do this here, since at this point, we have passed the
    // ShouldProcessIncomingRequests() check above, meaning we know for a fact
    // if we should be parsing WEBTRANSPORT_STREAM or not.
    decoder_.EnableWebTransportStreamParsing();
  }

  iovec iov;
  while (session()->connection()->connected() && !reading_stopped() &&
         decoder_.error() == QUIC_NO_ERROR) {
    QUICHE_DCHECK_GE(sequencer_offset_, sequencer()->NumBytesConsumed());
    if (!sequencer()->PeekRegion(sequencer_offset_, &iov)) {
      break;
    }

    QUICHE_DCHECK(!sequencer()->IsClosed());
    is_decoder_processing_input_ = true;
    QuicByteCount processed_bytes = decoder_.ProcessInput(
        reinterpret_cast<const char*>(iov.iov_base), iov.iov_len);
    is_decoder_processing_input_ = false;
    if (!session()->connection()->connected()) {
      return;
    }
    sequencer_offset_ += processed_bytes;
    if (blocked_on_decoding_headers_) {
      return;
    }
    if (web_transport_data_ != nullptr) {
      return;
    }
  }

  // Do not call HandleBodyAvailable() until headers are consumed.
  if (!FinishedReadingHeaders()) {
    return;
  }

  if (body_manager_.HasBytesToRead()) {
    HandleBodyAvailable();
    return;
  }

  if (sequencer()->IsClosed() &&
      !on_body_available_called_because_sequencer_is_closed_) {
    on_body_available_called_because_sequencer_is_closed_ = true;
    HandleBodyAvailable();
  }
}

void QuicSpdyStream::OnClose() {
  QuicStream::OnClose();

  qpack_decoded_headers_accumulator_.reset();

  if (visitor_) {
    Visitor* visitor = visitor_;
    // Calling Visitor::OnClose() may result the destruction of the visitor,
    // so we need to ensure we don't call it again.
    visitor_ = nullptr;
    visitor->OnClose(this);
  }

  if (web_transport_ != nullptr) {
    web_transport_->OnConnectStreamClosing();
  }
  if (web_transport_data_ != nullptr) {
    WebTransportHttp3* web_transport =
        spdy_session_->GetWebTransportSession(web_transport_data_->session_id);
    if (web_transport == nullptr) {
      // Since there is no guaranteed destruction order for streams, the session
      // could be already removed from the stream map by the time we reach here.
      QUIC_DLOG(WARNING) << ENDPOINT << "WebTransport stream " << id()
                         << " attempted to notify parent session "
                         << web_transport_data_->session_id
                         << ", but the session could not be found.";
      return;
    }
    web_transport->OnStreamClosed(id());
  }
}

void QuicSpdyStream::OnCanWrite() {
  QuicStream::OnCanWrite();

  // Trailers (and hence a FIN) may have been sent ahead of queued body bytes.
  if (!HasBufferedData() && fin_sent()) {
    CloseWriteSide();
  }
}

bool QuicSpdyStream::FinishedReadingHeaders() const {
  return headers_decompressed_ && header_list_.empty();
}

bool QuicSpdyStream::ParseHeaderStatusCode(const HttpHeaderBlock& header,
                                           int* status_code) {
  HttpHeaderBlock::const_iterator it = header.find(spdy::kHttp2StatusHeader);
  if (it == header.end()) {
    return false;
  }
  const absl::string_view status(it->second);
  return ParseHeaderStatusCod
```