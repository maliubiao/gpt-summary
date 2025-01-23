Response:
The user wants to understand the functionality of the provided C++ code snippet from `oghttp2_session.cc`. The request specifically asks for:

1. **Functionality Listing:** What does this code do?
2. **JavaScript Relation:**  Is there a connection to JavaScript? If so, provide examples.
3. **Logical Reasoning:** If there's logic, give example inputs and outputs.
4. **Common Errors:** Highlight potential user or programming errors.
5. **User Journey:** Describe how a user's action might lead to this code being executed (debugging context).
6. **Summary:**  A concise summary of the functionality covered in the snippet.

Let's break down the code:

* **`WriteForStream` function:** This appears to be the core of the provided snippet. It's responsible for sending data frames for a specific HTTP/2 stream. It handles flow control, data segmentation, trailer sending, and marking streams as ready for writing.
* **`SerializeMetadata` functions (two overloads):** These functions handle the serialization of metadata frames for a given stream. They pack metadata into appropriately sized chunks.
* **`SubmitRequest`, `SubmitResponse`, `SubmitTrailer`, `SubmitMetadata` (two overloads), `SubmitSettings`:** These are public methods that provide an interface for submitting different types of data and control information to the HTTP/2 session.
* **`OnError`, `OnCommonHeader`, `OnDataFrameHeader`, `OnStreamFrameData`, `OnStreamEnd`, `OnStreamPadLength`, `OnStreamPadding`, `OnHeaderFrameStart`, `OnHeaderFrameEnd`, `OnRstStream`, `OnSettings`, `OnSetting`, `OnSettingsEnd`, `OnSettingsAck`, `OnPing`, `OnGoAway`, `OnGoAwayFrameData`, `OnHeaders`, `OnWindowUpdate`, `OnPushPromise`, `OnContinuation`, `OnAltSvc`, `OnPriority`, `OnPriorityUpdate`, `OnUnknownFrame`, `OnUnknownFrameStart`, `OnUnknownFramePayload`, `OnHeaderStatus`:** These are methods that are called by the underlying HTTP/2 framer (likely `spdy::SpdyFramer`) when different types of frames are received. They handle the logic for processing incoming frames.
* **`MaybeSetupPreface`:** This function ensures the HTTP/2 connection preface (including the connection header and initial settings) is sent when needed.
* **`GetInitialSettings`:**  This function returns the default HTTP/2 settings for the session.

**Mental Sandbox/Pre-computation:**

* **JavaScript Interaction:** HTTP/2 is the underlying protocol for many web interactions. JavaScript in a browser (or Node.js) might trigger actions that eventually lead to these C++ functions being called in the browser's network stack.
* **Logical Reasoning (Example `WriteForStream`):**
    * **Input:** `stream_id`, available window size, `StreamState` (including data source, trailers).
    * **Output:** Potentially sends a DATA frame, updates send windows, marks the stream as deferred, or closes the stream.
* **Common Errors:** Flow control violations, sending data after closing a stream, incorrect frame sequences.
* **User Journey:**  A user clicking a link or a website making an API request using `fetch()` could initiate HTTP/2 requests that lead to this code.

**Structure of the Response:**

I'll structure the response by addressing each of the user's points individually, providing specific details and examples where applicable. I will start with summarizing the functionalities in this part.这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/http2/adapter/oghttp2_session.cc` 文件的第二部分代码，主要负责处理 HTTP/2 会话中发送和接收数据帧、元数据帧以及处理接收到的各种控制帧的逻辑。以下是该部分代码功能的归纳：

**主要功能归纳：**

1. **数据发送 (`WriteForStream`):**
   - 从流的数据源 (`DataFrameSource`) 获取要发送的数据。
   - 根据连接和流的窗口大小限制以及最大帧大小，确定本次发送的数据长度。
   - 如果没有数据要发送，但有 Trailers，则准备发送 Trailers。
   - 如果没有数据且没有 Trailers，则将流标记为延迟发送。
   - 如果数据源返回错误，则关闭流。
   - 创建并序列化 DATA 帧头，并发送数据。
   - 更新连接和流的发送窗口。
   - 如果发送了 FIN 标志，则标记流为本地半关闭。
   - 在发送帧后执行清理和状态更新。
   - 如果有 Trailers 待发送且数据已发送完毕，则发送 Trailers。
   - 如果流仍然存在且有数据要发送，则将其标记为可写入。
   - 根据连接和流的发送窗口状态返回发送结果（成功、阻塞、错误）。

2. **元数据序列化 (`SerializeMetadata`):**
   - 提供了两种重载方式：一种接受 `MetadataSource` 对象，另一种直接调用 Visitor 的方法。
   - 将元数据源中的数据打包成 METADATA 帧。
   - 根据最大允许的元数据帧大小进行分片发送。
   - 设置 METADATA 帧的 END_METADATA 标志。

3. **提交各种 HTTP/2 内容 (`SubmitRequest`, `SubmitResponse`, `SubmitTrailer`, `SubmitMetadata`, `SubmitSettings`):**
   - 提供了提交请求头和数据、响应头和数据、Trailers、元数据以及设置帧的接口。
   - 对于 Trailers，如果当前有数据正在发送，则会先缓存 Trailers，等待数据发送完成后再发送。

4. **接收帧处理 (一系列 `On...` 方法):**
   - **错误处理 (`OnError`):** 处理 SpdyFramer 报告的错误。
   - **通用帧头处理 (`OnCommonHeader`):** 记录接收到的最高流 ID，并通知 Visitor。
   - **DATA 帧头处理 (`OnDataFrameHeader`):** 检查连接和流的流量控制窗口，验证是否可以接收数据。
   - **DATA 帧数据处理 (`OnStreamFrameData`):** 将接收到的数据传递给 Visitor，并根据 Content-Length 进行验证。
   - **流结束处理 (`OnStreamEnd`):** 标记流为远端半关闭，并通知 Visitor。
   - **Padding 处理 (`OnStreamPadLength`, `OnStreamPadding`):** 处理 Padding 长度，并更新流量控制。
   - **HEADERS 帧处理 (`OnHeaderFrameStart`, `OnHeaderFrameEnd`):** 初始化和结束头部处理，并记录接收到的头部类型。
   - **RST_STREAM 帧处理 (`OnRstStream`):** 标记流为远端半关闭，放弃未发送的数据，并通知 Visitor。
   - **SETTINGS 帧处理 (`OnSettings`, `OnSetting`, `OnSettingsEnd`, `OnSettingsAck`):** 处理接收到的 SETTINGS 帧，更新本地设置，并发送 ACK。
   - **PING 帧处理 (`OnPing`):** 通知 Visitor，并根据配置自动发送 PING ACK。
   - **GOAWAY 帧处理 (`OnGoAway`, `OnGoAwayFrameData`):** 处理 GOAWAY 帧，标记连接即将关闭，并通知 Visitor。
   - **HEADERS 帧处理 (`OnHeaders`):**  处理接收到的 HEADERS 帧，特别是对于服务器端，会创建新的流。
   - **WINDOW_UPDATE 帧处理 (`OnWindowUpdate`):** 更新连接和流的发送窗口。
   - **PUSH_PROMISE 帧处理 (`OnPushPromise`):**  由于服务器推送被禁用，接收到 PUSH_PROMISE 会被认为是错误。
   - **CONTINUATION 帧处理 (`OnContinuation`):** 当前为空实现。
   - **ALT-SVC 帧处理 (`OnAltSvc`):** 当前为空实现。
   - **PRIORITY 帧处理 (`OnPriority`):** 当前为空实现。
   - **PRIORITY_UPDATE 帧处理 (`OnPriorityUpdate`):** 当前为空实现。
   - **未知帧处理 (`OnUnknownFrame`, `OnUnknownFrameStart`, `OnUnknownFramePayload`):** 处理未知类型的帧，特别是 METADATA 帧。
   - **头部状态处理 (`OnHeaderStatus`):** 处理头部解析过程中遇到的错误，并可能发送 RST_STREAM 帧。

5. **连接 Preface 处理 (`MaybeSetupPreface`):**
   - 确保在连接建立初期发送 HTTP/2 连接 Preface 和初始的 SETTINGS 帧。

6. **获取初始设置 (`GetInitialSettings`):**
   - 返回连接的初始 HTTP/2 设置。

**与 JavaScript 功能的关系：**

这段 C++ 代码是浏览器或 Node.js 等环境中网络栈的一部分，负责处理底层的 HTTP/2 协议细节。JavaScript 代码通常通过更高级的 API（例如 `fetch` API 或 Node.js 的 `http2` 模块）与服务器进行交互，而这些 API 的底层实现会依赖于像这样的 C++ 代码来处理 HTTP/2 的帧和连接管理。

**举例说明：**

* **JavaScript 发起 `fetch` 请求:** 当 JavaScript 代码执行 `fetch('https://example.com/api')` 时，如果连接支持 HTTP/2，浏览器内部的网络栈就会开始建立 HTTP/2 连接。这个过程中，`MaybeSetupPreface` 会被调用来发送连接 Preface。当需要发送请求头和数据时，会调用 `SubmitRequest`，最终会调用 `WriteForStream` 将数据封装成 DATA 帧发送出去。
* **JavaScript 接收响应:** 当服务器返回 HTTP/2 响应时，网络栈会接收到 DATA 帧。`OnDataFrameHeader` 和 `OnStreamFrameData` 会被调用来处理接收到的数据，并将数据传递给 JavaScript 的 `fetch` API 对应的 Promise。如果响应包含 Trailers，`OnHeaders` 可能会被调用来处理 Trailers 头部。
* **JavaScript 处理服务器推送（虽然此处代码禁用了服务器推送）:**  在 HTTP/2 中，服务器可以主动向客户端推送资源。虽然这段代码中 `OnPushPromise` 会报告错误，但在启用了服务器推送的场景下，服务器发送 PUSH_PROMISE 帧时，网络栈会创建新的流，并将推送的资源传递给 JavaScript。

**逻辑推理示例：**

**假设输入 (在 `WriteForStream` 函数中):**

* `stream_id`: 3
* `available_window`: 1024 (字节)
* `state.data_source` 提供 512 字节的数据
* `state.trailers`: `nullptr`
* `connection_send_window_`: 2048 (字节)
* `max_frame_payload_`: 16384 (字节)

**输出:**

* 发送一个包含 512 字节数据的 DATA 帧。
* `connection_send_window_` 更新为 2048 - 512 = 1536。
* `state.send_window` 更新 (假设初始值为某个值)。
* `available_window` 在本次调用后会更新。
* 函数返回 `SendResult::SEND_OK` (假设发送成功)。

**假设输入 (在 `OnDataFrameHeader` 函数中):**

* `stream_id`: 5
* `length`: 2000 (字节)
* `connection_window_manager_.CurrentWindowSize()`: 1500 (字节)

**输出:**

* 调用 `LatchErrorAndNotify(Http2ErrorCode::FLOW_CONTROL_ERROR, ...)`，因为接收到的 DATA 帧长度超过了连接的流量控制窗口。
* 可能会发送 GOAWAY 帧来关闭连接。

**用户或编程常见的使用错误示例：**

1. **在流关闭后尝试发送数据:** 用户代码或上层逻辑可能在流已经被本地或远端关闭后，仍然尝试调用 `SubmitRequest` 或 `SubmitResponse` 发送数据。这会导致错误，并且可能触发 `WriteForStream` 中相应的错误处理逻辑。
2. **流量控制窗口耗尽:** 如果对端没有及时发送 WINDOW_UPDATE 帧，导致本地的发送窗口变为 0，尝试发送大量数据将会导致 `WriteForStream` 返回 `SendResult::SEND_BLOCKED`，并且数据发送会被延迟。编程者需要理解流量控制机制，并在上层处理这种阻塞情况。
3. **不正确的帧序列:** 例如，在发送 HEADERS 帧之前尝试发送 DATA 帧。这段代码中的 `OnDataFrameHeader` 和其他 `On...` 方法会检查帧的顺序，如果发现错误会调用 `LatchErrorAndNotify` 来报告协议错误。
4. **提交过大的元数据:**  如果 `MetadataSource` 提供的数据超过了 `kMaxAllowedMetadataFrameSize`，`SerializeMetadata` 会将其分片发送，但如果上层逻辑期望一次性发送，可能会产生误解。

**用户操作如何一步步的到达这里，作为调试线索：**

假设用户在浏览器中访问一个网站 `https://example.com`，并且该网站使用 HTTP/2 协议。

1. **用户在地址栏输入 URL 并按下回车键。**
2. **浏览器开始解析 URL，并查找与 `example.com` 相关的 IP 地址。**
3. **浏览器与服务器建立 TCP 连接（如果尚未建立）。**
4. **浏览器与服务器进行 TLS 握手，协商使用 HTTP/2 协议。**
5. **浏览器网络栈中的 HTTP/2 会话管理模块（由类似 `OgHttp2Session` 的类实现）被创建。**
6. **为了请求网页资源，浏览器会创建一个 HTTP/2 流。**
7. **浏览器调用 `SubmitRequest`，传入请求头（例如 GET 请求和 Host 头）。**
8. **`SubmitRequest` 内部会将请求头序列化成 HEADERS 帧，并可能调用 `MaybeSetupPreface` 来发送连接 Preface 和初始的 SETTINGS 帧。**
9. **如果请求有请求体（例如 POST 请求），`SubmitRequest` 也会接收一个 `DataFrameSource`，后续 `WriteForStream` 会被调用来发送 DATA 帧。**
10. **服务器收到请求后，会发送响应头和数据。**
11. **浏览器网络栈接收到服务器发送的帧，例如 HEADERS 帧和 DATA 帧，并分别调用 `OnHeaders` 和 `OnDataFrameHeader`/`OnStreamFrameData` 进行处理。**
12. **如果服务器发送了 WINDOW_UPDATE 帧，`OnWindowUpdate` 会被调用来更新本地的发送窗口。**

在调试网络问题时，如果怀疑是 HTTP/2 层的问题，可以查看网络请求的详细信息（例如 Chrome 开发者工具的 Network 选项卡），查看 HTTP/2 的帧类型和内容。如果需要深入调试 C++ 代码，可以使用断点工具，在 `WriteForStream`、`OnDataFrameHeader` 等关键函数设置断点，跟踪变量的值，例如窗口大小、帧长度等，来理解数据发送和接收的流程。

总而言之，这段代码是 Chromium 网络栈中处理 HTTP/2 协议的核心部分，负责管理 HTTP/2 连接的生命周期，包括发送和接收各种帧，以及处理流量控制、错误等细节。它与 JavaScript 的交互是通过更高层次的网络 API 来实现的。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/adapter/oghttp2_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
GetDataFrameInfo(stream_id, available_window, state);
    QUICHE_VLOG(2) << "WriteForStream | length: " << info.payload_length
                   << " end_data: " << info.end_data
                   << " end_stream: " << info.end_stream
                   << " trailers: " << state.trailers.get();
    if (info.payload_length == 0 && !info.end_data &&
        state.trailers == nullptr) {
      // An unproductive call to SelectPayloadLength() results in this stream
      // entering the "deferred" state only if no trailers are available to
      // send.
      state.data_deferred = true;
      break;
    } else if (info.payload_length == DataFrameSource::kError) {
      // TODO(birenroy,diannahu): Consider queuing a RST_STREAM INTERNAL_ERROR
      // instead.
      CloseStream(stream_id, Http2ErrorCode::INTERNAL_ERROR);
      // No more work on the stream; it has been closed.
      break;
    }
    if (info.payload_length > 0 || info.end_stream) {
      spdy::SpdyDataIR data(stream_id);
      data.set_fin(info.end_stream);
      data.SetDataShallow(info.payload_length);
      spdy::SpdySerializedFrame header =
          spdy::SpdyFramer::SerializeDataFrameHeaderWithPaddingLengthField(
              data);
      QUICHE_DCHECK(buffered_data_.Empty() && frames_.empty());
      data.Visit(&send_logger_);
      const bool success = SendDataFrame(stream_id, absl::string_view(header),
                                         info.payload_length, state);
      if (!success) {
        connection_can_write = SendResult::SEND_BLOCKED;
        break;
      }
      connection_send_window_ -= info.payload_length;
      state.send_window -= info.payload_length;
      available_window = std::min({connection_send_window_, state.send_window,
                                   static_cast<int32_t>(max_frame_payload_)});
      if (info.end_stream) {
        state.half_closed_local = true;
        MaybeFinWithRstStream(it);
      }
      const bool ok =
          AfterFrameSent(/* DATA */ 0, stream_id, info.payload_length,
                         info.end_stream ? END_STREAM_FLAG : 0x0, 0);
      if (!ok) {
        LatchErrorAndNotify(Http2ErrorCode::INTERNAL_ERROR,
                            ConnectionError::kSendError);
        return SendResult::SEND_ERROR;
      }
      if (!stream_map_.contains(stream_id)) {
        // Note: the stream may have been closed if `fin` is true.
        break;
      }
    }
    if (info.end_data ||
        (info.payload_length == 0 && state.trailers != nullptr)) {
      // If SelectPayloadLength() returned {0, false}, and there are trailers to
      // send, it's okay to send the trailers.
      if (state.trailers != nullptr) {
        auto block_ptr = std::move(state.trailers);
        if (info.end_stream) {
          QUICHE_LOG(ERROR) << "Sent fin; can't send trailers.";

          // TODO(birenroy,diannahu): Consider queuing a RST_STREAM
          // INTERNAL_ERROR instead.
          CloseStream(stream_id, Http2ErrorCode::INTERNAL_ERROR);
          // No more work on this stream; it has been closed.
          break;
        } else {
          SendTrailers(stream_id, std::move(*block_ptr));
        }
      }
      AbandonData(state);
    }
  }
  // If the stream still exists and has data to send, it should be marked as
  // ready in the write scheduler.
  if (stream_map_.contains(stream_id) && !state.data_deferred &&
      state.send_window > 0 && HasMoreData(state)) {
    write_scheduler_.MarkStreamReady(stream_id, false);
  }
  // Streams can continue writing as long as the connection is not write-blocked
  // and there is additional flow control quota available.
  if (connection_can_write != SendResult::SEND_OK) {
    return connection_can_write;
  }
  return connection_send_window_ <= 0 ? SendResult::SEND_BLOCKED
                                      : SendResult::SEND_OK;
}

void OgHttp2Session::SerializeMetadata(Http2StreamId stream_id,
                                       std::unique_ptr<MetadataSource> source) {
  const uint32_t max_payload_size =
      std::min(kMaxAllowedMetadataFrameSize, max_frame_payload_);
  auto payload_buffer = std::make_unique<uint8_t[]>(max_payload_size);

  while (true) {
    auto [written, end_metadata] =
        source->Pack(payload_buffer.get(), max_payload_size);
    if (written < 0) {
      // Unable to pack any metadata.
      return;
    }
    QUICHE_DCHECK_LE(static_cast<size_t>(written), max_payload_size);
    auto payload = absl::string_view(
        reinterpret_cast<const char*>(payload_buffer.get()), written);
    EnqueueFrame(std::make_unique<spdy::SpdyUnknownIR>(
        stream_id, kMetadataFrameType, end_metadata ? kMetadataEndFlag : 0u,
        std::string(payload)));
    if (end_metadata) {
      return;
    }
  }
}

void OgHttp2Session::SerializeMetadata(Http2StreamId stream_id) {
  const uint32_t max_payload_size =
      std::min(kMaxAllowedMetadataFrameSize, max_frame_payload_);
  auto payload_buffer = std::make_unique<uint8_t[]>(max_payload_size);

  while (true) {
    auto [written, end_metadata] = visitor_.PackMetadataForStream(
        stream_id, payload_buffer.get(), max_payload_size);
    if (written < 0) {
      // Unable to pack any metadata.
      return;
    }
    QUICHE_DCHECK_LE(static_cast<size_t>(written), max_payload_size);
    auto payload = absl::string_view(
        reinterpret_cast<const char*>(payload_buffer.get()), written);
    EnqueueFrame(std::make_unique<spdy::SpdyUnknownIR>(
        stream_id, kMetadataFrameType, end_metadata ? kMetadataEndFlag : 0u,
        std::string(payload)));
    if (end_metadata) {
      return;
    }
  }
}

int32_t OgHttp2Session::SubmitRequest(
    absl::Span<const Header> headers,
    std::unique_ptr<DataFrameSource> data_source, bool end_stream,
    void* user_data) {
  return SubmitRequestInternal(headers, std::move(data_source), end_stream,
                               user_data);
}

int OgHttp2Session::SubmitResponse(Http2StreamId stream_id,
                                   absl::Span<const Header> headers,
                                   std::unique_ptr<DataFrameSource> data_source,
                                   bool end_stream) {
  return SubmitResponseInternal(stream_id, headers, std::move(data_source),
                                end_stream);
}

int OgHttp2Session::SubmitTrailer(Http2StreamId stream_id,
                                  absl::Span<const Header> trailers) {
  // TODO(birenroy): Reject trailers when acting as a client?
  auto iter = stream_map_.find(stream_id);
  if (iter == stream_map_.end()) {
    QUICHE_LOG(ERROR) << "Unable to find stream " << stream_id;
    return -501;  // NGHTTP2_ERR_INVALID_ARGUMENT
  }
  StreamState& state = iter->second;
  if (state.half_closed_local) {
    QUICHE_LOG(ERROR) << "Stream " << stream_id << " is half closed (local)";
    return -514;  // NGHTTP2_ERR_INVALID_STREAM_STATE
  }
  if (state.trailers != nullptr) {
    QUICHE_LOG(ERROR) << "Stream " << stream_id
                      << " already has trailers queued";
    return -514;  // NGHTTP2_ERR_INVALID_STREAM_STATE
  }
  if (!HasMoreData(state)) {
    // Enqueue trailers immediately.
    SendTrailers(stream_id, ToHeaderBlock(trailers));
  } else {
    // Save trailers so they can be written once data is done.
    state.trailers =
        std::make_unique<quiche::HttpHeaderBlock>(ToHeaderBlock(trailers));
    trailers_ready_.insert(stream_id);
  }
  return 0;
}

void OgHttp2Session::SubmitMetadata(Http2StreamId stream_id,
                                    std::unique_ptr<MetadataSource> source) {
  SerializeMetadata(stream_id, std::move(source));
}

void OgHttp2Session::SubmitMetadata(Http2StreamId stream_id) {
  SerializeMetadata(stream_id);
}

void OgHttp2Session::SubmitSettings(absl::Span<const Http2Setting> settings) {
  auto frame = PrepareSettingsFrame(settings);
  EnqueueFrame(std::move(frame));
}

void OgHttp2Session::OnError(SpdyFramerError error,
                             std::string detailed_error) {
  QUICHE_VLOG(1) << "Error: "
                 << http2::Http2DecoderAdapter::SpdyFramerErrorToString(error)
                 << " details: " << detailed_error;
  // TODO(diannahu): Consider propagating `detailed_error`.
  LatchErrorAndNotify(GetHttp2ErrorCode(error), ConnectionError::kParseError);
}

void OgHttp2Session::OnCommonHeader(spdy::SpdyStreamId stream_id, size_t length,
                                    uint8_t type, uint8_t flags) {
  current_frame_type_ = type;
  highest_received_stream_id_ = std::max(static_cast<Http2StreamId>(stream_id),
                                         highest_received_stream_id_);
  if (streams_reset_.contains(stream_id)) {
    return;
  }
  const bool result = visitor_.OnFrameHeader(stream_id, length, type, flags);
  if (!result) {
    fatal_visitor_callback_failure_ = true;
    decoder_.StopProcessing();
  }
}

void OgHttp2Session::OnDataFrameHeader(spdy::SpdyStreamId stream_id,
                                       size_t length, bool /*fin*/) {
  auto iter = stream_map_.find(stream_id);
  if (iter == stream_map_.end() || streams_reset_.contains(stream_id)) {
    // The stream does not exist; it could be an error or a benign close, e.g.,
    // getting data for a stream this connection recently closed.
    if (static_cast<Http2StreamId>(stream_id) > highest_processed_stream_id_) {
      // Receiving DATA before HEADERS is a connection error.
      LatchErrorAndNotify(Http2ErrorCode::PROTOCOL_ERROR,
                          ConnectionError::kWrongFrameSequence);
    }
    return;
  }

  if (static_cast<int64_t>(length) >
      connection_window_manager_.CurrentWindowSize()) {
    // Peer exceeded the connection flow control limit.
    LatchErrorAndNotify(
        Http2ErrorCode::FLOW_CONTROL_ERROR,
        Http2VisitorInterface::ConnectionError::kFlowControlError);
    return;
  }

  if (static_cast<int64_t>(length) >
      iter->second.window_manager.CurrentWindowSize()) {
    // Peer exceeded the stream flow control limit.
    EnqueueFrame(std::make_unique<spdy::SpdyRstStreamIR>(
        stream_id, spdy::ERROR_CODE_FLOW_CONTROL_ERROR));
    return;
  }

  const bool result = visitor_.OnBeginDataForStream(stream_id, length);
  if (!result) {
    fatal_visitor_callback_failure_ = true;
    decoder_.StopProcessing();
  }

  if (!iter->second.can_receive_body && length > 0) {
    EnqueueFrame(std::make_unique<spdy::SpdyRstStreamIR>(
        stream_id, spdy::ERROR_CODE_PROTOCOL_ERROR));
    return;
  }
}

void OgHttp2Session::OnStreamFrameData(spdy::SpdyStreamId stream_id,
                                       const char* data, size_t len) {
  // Count the data against flow control, even if the stream is unknown.
  MarkDataBuffered(stream_id, len);

  auto iter = stream_map_.find(stream_id);
  if (iter == stream_map_.end()) {
    return;
  }
  // Validate against the content-length if it exists.
  if (iter->second.remaining_content_length.has_value()) {
    if (len > *iter->second.remaining_content_length) {
      HandleContentLengthError(stream_id);
      iter->second.remaining_content_length.reset();
    } else {
      *iter->second.remaining_content_length -= len;
    }
  }
  if (streams_reset_.contains(stream_id)) {
    // If the stream was unknown due to a protocol error, the visitor was
    // informed in OnDataFrameHeader().
    return;
  }

  const bool result =
      visitor_.OnDataForStream(stream_id, absl::string_view(data, len));
  if (!result) {
    fatal_visitor_callback_failure_ = true;
    decoder_.StopProcessing();
  }
}

void OgHttp2Session::OnStreamEnd(spdy::SpdyStreamId stream_id) {
  auto iter = stream_map_.find(stream_id);
  if (iter != stream_map_.end()) {
    iter->second.half_closed_remote = true;
    if (streams_reset_.contains(stream_id)) {
      return;
    }

    // Validate against the content-length if it exists.
    if (iter->second.remaining_content_length.has_value() &&
        *iter->second.remaining_content_length != 0) {
      HandleContentLengthError(stream_id);
      return;
    }

    const bool result = visitor_.OnEndStream(stream_id);
    if (!result) {
      fatal_visitor_callback_failure_ = true;
      decoder_.StopProcessing();
    }
  }

  auto queued_frames_iter = queued_frames_.find(stream_id);
  const bool no_queued_frames = queued_frames_iter == queued_frames_.end() ||
                                queued_frames_iter->second == 0;
  if (iter != stream_map_.end() && iter->second.half_closed_local &&
      !IsServerSession() && no_queued_frames) {
    // From the client's perspective, the stream can be closed if it's already
    // half_closed_local.
    CloseStream(stream_id, Http2ErrorCode::HTTP2_NO_ERROR);
  }
}

void OgHttp2Session::OnStreamPadLength(spdy::SpdyStreamId stream_id,
                                       size_t value) {
  const size_t padding_length = 1 + value;
  const bool result = visitor_.OnDataPaddingLength(stream_id, padding_length);
  if (!result) {
    fatal_visitor_callback_failure_ = true;
    decoder_.StopProcessing();
  }
  connection_window_manager_.MarkWindowConsumed(padding_length);
  if (auto it = stream_map_.find(stream_id); it != stream_map_.end()) {
    it->second.window_manager.MarkWindowConsumed(padding_length);
  }
}

void OgHttp2Session::OnStreamPadding(spdy::SpdyStreamId /*stream_id*/, size_t
                                     /*len*/) {
  // Flow control was accounted for in OnStreamPadLength().
  // TODO(181586191): Pass padding to the visitor?
}

spdy::SpdyHeadersHandlerInterface* OgHttp2Session::OnHeaderFrameStart(
    spdy::SpdyStreamId stream_id) {
  auto it = stream_map_.find(stream_id);
  if (it != stream_map_.end() && !streams_reset_.contains(stream_id)) {
    headers_handler_.set_stream_id(stream_id);
    headers_handler_.set_header_type(
        NextHeaderType(it->second.received_header_type));
    return &headers_handler_;
  } else {
    return &noop_headers_handler_;
  }
}

void OgHttp2Session::OnHeaderFrameEnd(spdy::SpdyStreamId stream_id) {
  auto it = stream_map_.find(stream_id);
  if (it != stream_map_.end()) {
    if (headers_handler_.header_type() == HeaderType::RESPONSE &&
        !headers_handler_.status_header().empty() &&
        headers_handler_.status_header()[0] == '1') {
      // If response headers carried a 1xx response code, final response headers
      // should still be forthcoming.
      headers_handler_.set_header_type(HeaderType::RESPONSE_100);
    }
    it->second.received_header_type = headers_handler_.header_type();

    // Track the content-length if the headers indicate that a body can follow.
    it->second.can_receive_body =
        headers_handler_.CanReceiveBody() && !it->second.sent_head_method;
    if (it->second.can_receive_body) {
      it->second.remaining_content_length = headers_handler_.content_length();
    }

    headers_handler_.set_stream_id(0);
  }
}

void OgHttp2Session::OnRstStream(spdy::SpdyStreamId stream_id,
                                 spdy::SpdyErrorCode error_code) {
  auto iter = stream_map_.find(stream_id);
  if (iter != stream_map_.end()) {
    iter->second.half_closed_remote = true;
    AbandonData(iter->second);
  } else if (static_cast<Http2StreamId>(stream_id) >
             highest_processed_stream_id_) {
    // Receiving RST_STREAM before HEADERS is a connection error.
    LatchErrorAndNotify(Http2ErrorCode::PROTOCOL_ERROR,
                        ConnectionError::kWrongFrameSequence);
    return;
  }
  if (streams_reset_.contains(stream_id)) {
    return;
  }
  visitor_.OnRstStream(stream_id, TranslateErrorCode(error_code));
  // TODO(birenroy): Consider whether there are outbound frames queued for the
  // stream.
  CloseStream(stream_id, TranslateErrorCode(error_code));
}

void OgHttp2Session::OnSettings() {
  visitor_.OnSettingsStart();
  auto settings = std::make_unique<SpdySettingsIR>();
  settings->set_is_ack(true);
  EnqueueFrame(std::move(settings));
}

void OgHttp2Session::OnSetting(spdy::SpdySettingsId id, uint32_t value) {
  switch (id) {
    case HEADER_TABLE_SIZE:
      value = std::min(value, HpackCapacityBound(options_));
      if (value < framer_.GetHpackEncoder()->CurrentHeaderTableSizeSetting()) {
        // Safe to apply a smaller table capacity immediately.
        QUICHE_VLOG(2) << TracePerspectiveAsString(options_.perspective)
                       << " applying encoder table capacity " << value;
        framer_.GetHpackEncoder()->ApplyHeaderTableSizeSetting(value);
      } else {
        QUICHE_VLOG(2)
            << TracePerspectiveAsString(options_.perspective)
            << " NOT applying encoder table capacity until writing ack: "
            << value;
        encoder_header_table_capacity_when_acking_ = value;
      }
      break;
    case ENABLE_PUSH:
      if (value > 1u) {
        visitor_.OnInvalidFrame(
            0, Http2VisitorInterface::InvalidFrameError::kProtocol);
        // The specification says this is a connection-level protocol error.
        LatchErrorAndNotify(
            Http2ErrorCode::PROTOCOL_ERROR,
            Http2VisitorInterface::ConnectionError::kInvalidSetting);
        return;
      }
      // Aside from validation, this setting is ignored.
      break;
    case MAX_CONCURRENT_STREAMS:
      max_outbound_concurrent_streams_ = value;
      if (!IsServerSession()) {
        // We may now be able to start pending streams.
        StartPendingStreams();
      }
      break;
    case INITIAL_WINDOW_SIZE:
      if (value > spdy::kSpdyMaximumWindowSize) {
        visitor_.OnInvalidFrame(
            0, Http2VisitorInterface::InvalidFrameError::kFlowControl);
        // The specification says this is a connection-level flow control error.
        LatchErrorAndNotify(
            Http2ErrorCode::FLOW_CONTROL_ERROR,
            Http2VisitorInterface::ConnectionError::kFlowControlError);
        return;
      } else {
        UpdateStreamSendWindowSizes(value);
      }
      break;
    case MAX_FRAME_SIZE:
      if (value < kDefaultFramePayloadSizeLimit ||
          value > kMaximumFramePayloadSizeLimit) {
        visitor_.OnInvalidFrame(
            0, Http2VisitorInterface::InvalidFrameError::kProtocol);
        // The specification says this is a connection-level protocol error.
        LatchErrorAndNotify(
            Http2ErrorCode::PROTOCOL_ERROR,
            Http2VisitorInterface::ConnectionError::kInvalidSetting);
        return;
      }
      max_frame_payload_ = value;
      break;
    case ENABLE_CONNECT_PROTOCOL:
      if (value > 1u || (value == 0 && peer_enables_connect_protocol_)) {
        visitor_.OnInvalidFrame(
            0, Http2VisitorInterface::InvalidFrameError::kProtocol);
        LatchErrorAndNotify(
            Http2ErrorCode::PROTOCOL_ERROR,
            Http2VisitorInterface::ConnectionError::kInvalidSetting);
        return;
      }
      peer_enables_connect_protocol_ = (value == 1u);
      break;
    case kMetadataExtensionId:
      peer_supports_metadata_ = (value != 0);
      break;
    default:
      QUICHE_VLOG(1) << "Unimplemented SETTING id: " << id;
  }
  visitor_.OnSetting({id, value});
}

void OgHttp2Session::OnSettingsEnd() { visitor_.OnSettingsEnd(); }

void OgHttp2Session::OnSettingsAck() {
  if (!settings_ack_callbacks_.empty()) {
    SettingsAckCallback callback = std::move(settings_ack_callbacks_.front());
    settings_ack_callbacks_.pop_front();
    std::move(callback)();
  }

  visitor_.OnSettingsAck();
}

void OgHttp2Session::OnPing(spdy::SpdyPingId unique_id, bool is_ack) {
  visitor_.OnPing(unique_id, is_ack);
  if (options_.auto_ping_ack && !is_ack) {
    auto ping = std::make_unique<spdy::SpdyPingIR>(unique_id);
    ping->set_is_ack(true);
    EnqueueFrame(std::move(ping));
  }
}

void OgHttp2Session::OnGoAway(spdy::SpdyStreamId last_accepted_stream_id,
                              spdy::SpdyErrorCode error_code) {
  if (received_goaway_ &&
      last_accepted_stream_id >
          static_cast<spdy::SpdyStreamId>(received_goaway_stream_id_)) {
    // This GOAWAY has a higher `last_accepted_stream_id` than a previous
    // GOAWAY, a connection-level spec violation.
    const bool ok = visitor_.OnInvalidFrame(
        kConnectionStreamId,
        Http2VisitorInterface::InvalidFrameError::kProtocol);
    if (!ok) {
      fatal_visitor_callback_failure_ = true;
    }
    LatchErrorAndNotify(Http2ErrorCode::PROTOCOL_ERROR,
                        ConnectionError::kInvalidGoAwayLastStreamId);
    return;
  }

  received_goaway_ = true;
  received_goaway_stream_id_ = last_accepted_stream_id;
  const bool result = visitor_.OnGoAway(last_accepted_stream_id,
                                        TranslateErrorCode(error_code), "");
  if (!result) {
    fatal_visitor_callback_failure_ = true;
    decoder_.StopProcessing();
  }

  // Close the streams above `last_accepted_stream_id`. Only applies if the
  // session receives a GOAWAY as a client, as we do not support server push.
  if (last_accepted_stream_id == spdy::kMaxStreamId || IsServerSession()) {
    return;
  }
  std::vector<Http2StreamId> streams_to_close;
  for (const auto& [stream_id, stream_state] : stream_map_) {
    if (static_cast<spdy::SpdyStreamId>(stream_id) > last_accepted_stream_id) {
      streams_to_close.push_back(stream_id);
    }
  }
  for (Http2StreamId stream_id : streams_to_close) {
    CloseStream(stream_id, Http2ErrorCode::REFUSED_STREAM);
  }
}

bool OgHttp2Session::OnGoAwayFrameData(const char* /*goaway_data*/, size_t
                                       /*len*/) {
  // Opaque data is currently ignored.
  return true;
}

void OgHttp2Session::OnHeaders(spdy::SpdyStreamId stream_id,
                               size_t /*payload_length*/, bool /*has_priority*/,
                               int /*weight*/,
                               spdy::SpdyStreamId /*parent_stream_id*/,
                               bool /*exclusive*/, bool fin, bool /*end*/) {
  if (stream_id % 2 == 0) {
    // Server push is disabled; receiving push HEADERS is a connection error.
    LatchErrorAndNotify(Http2ErrorCode::PROTOCOL_ERROR,
                        ConnectionError::kInvalidNewStreamId);
    return;
  }
  headers_handler_.set_frame_contains_fin(fin);
  if (IsServerSession()) {
    const auto new_stream_id = static_cast<Http2StreamId>(stream_id);
    if (stream_map_.find(new_stream_id) != stream_map_.end() && fin) {
      // Not a new stream, must be trailers.
      return;
    }
    if (new_stream_id <= highest_processed_stream_id_) {
      // A new stream ID lower than the watermark is a connection error.
      LatchErrorAndNotify(Http2ErrorCode::PROTOCOL_ERROR,
                          ConnectionError::kInvalidNewStreamId);
      return;
    }

    if (stream_map_.size() >= max_inbound_concurrent_streams_) {
      // The new stream would exceed our advertised and acknowledged
      // MAX_CONCURRENT_STREAMS. For parity with nghttp2, treat this error as a
      // connection-level PROTOCOL_ERROR.
      bool ok = visitor_.OnInvalidFrame(
          stream_id, Http2VisitorInterface::InvalidFrameError::kProtocol);
      if (!ok) {
        fatal_visitor_callback_failure_ = true;
      }
      LatchErrorAndNotify(Http2ErrorCode::PROTOCOL_ERROR,
                          ConnectionError::kExceededMaxConcurrentStreams);
      return;
    }
    if (stream_map_.size() >= pending_max_inbound_concurrent_streams_) {
      // The new stream would exceed our advertised but unacked
      // MAX_CONCURRENT_STREAMS. Refuse the stream for parity with nghttp2.
      EnqueueFrame(std::make_unique<spdy::SpdyRstStreamIR>(
          stream_id, spdy::ERROR_CODE_REFUSED_STREAM));
      const bool ok = visitor_.OnInvalidFrame(
          stream_id, Http2VisitorInterface::InvalidFrameError::kRefusedStream);
      if (!ok) {
        fatal_visitor_callback_failure_ = true;
        LatchErrorAndNotify(Http2ErrorCode::REFUSED_STREAM,
                            ConnectionError::kExceededMaxConcurrentStreams);
      }
      return;
    }

    CreateStream(stream_id);
  }
}

void OgHttp2Session::OnWindowUpdate(spdy::SpdyStreamId stream_id,
                                    int delta_window_size) {
  constexpr int kMaxWindowValue = 2147483647;  // (1 << 31) - 1
  if (stream_id == 0) {
    if (delta_window_size == 0) {
      // A PROTOCOL_ERROR, according to RFC 9113 Section 6.9.
      LatchErrorAndNotify(Http2ErrorCode::PROTOCOL_ERROR,
                          ConnectionError::kFlowControlError);
      return;
    }
    if (connection_send_window_ > 0 &&
        delta_window_size > (kMaxWindowValue - connection_send_window_)) {
      // Window overflow is a FLOW_CONTROL_ERROR.
      LatchErrorAndNotify(Http2ErrorCode::FLOW_CONTROL_ERROR,
                          ConnectionError::kFlowControlError);
      return;
    }
    connection_send_window_ += delta_window_size;
  } else {
    if (delta_window_size == 0) {
      // A PROTOCOL_ERROR, according to RFC 9113 Section 6.9.
      EnqueueFrame(std::make_unique<spdy::SpdyRstStreamIR>(
          stream_id, spdy::ERROR_CODE_PROTOCOL_ERROR));
      return;
    }
    auto it = stream_map_.find(stream_id);
    if (it == stream_map_.end()) {
      QUICHE_VLOG(1) << "Stream " << stream_id << " not found!";
      if (static_cast<Http2StreamId>(stream_id) >
          highest_processed_stream_id_) {
        // Receiving WINDOW_UPDATE before HEADERS is a connection error.
        LatchErrorAndNotify(Http2ErrorCode::PROTOCOL_ERROR,
                            ConnectionError::kWrongFrameSequence);
      }
      // Do not inform the visitor of a WINDOW_UPDATE for a non-existent stream.
      return;
    } else {
      if (streams_reset_.contains(stream_id)) {
        return;
      }
      if (it->second.send_window > 0 &&
          delta_window_size > (kMaxWindowValue - it->second.send_window)) {
        // Window overflow is a FLOW_CONTROL_ERROR.
        EnqueueFrame(std::make_unique<spdy::SpdyRstStreamIR>(
            stream_id, spdy::ERROR_CODE_FLOW_CONTROL_ERROR));
        return;
      }
      const bool was_blocked = (it->second.send_window <= 0);
      it->second.send_window += delta_window_size;
      if (was_blocked && it->second.send_window > 0) {
        // The stream was blocked on flow control.
        QUICHE_VLOG(1) << "Marking stream " << stream_id << " ready to write.";
        write_scheduler_.MarkStreamReady(stream_id, false);
      }
    }
  }
  visitor_.OnWindowUpdate(stream_id, delta_window_size);
}

void OgHttp2Session::OnPushPromise(spdy::SpdyStreamId /*stream_id*/,
                                   spdy::SpdyStreamId /*promised_stream_id*/,
                                   bool /*end*/) {
  // Server push is disabled; PUSH_PROMISE is an invalid frame.
  LatchErrorAndNotify(Http2ErrorCode::PROTOCOL_ERROR,
                      ConnectionError::kInvalidPushPromise);
}

void OgHttp2Session::OnContinuation(spdy::SpdyStreamId /*stream_id*/,
                                    size_t /*payload_length*/, bool /*end*/) {}

void OgHttp2Session::OnAltSvc(spdy::SpdyStreamId /*stream_id*/,
                              absl::string_view /*origin*/,
                              const spdy::SpdyAltSvcWireFormat::
                                  AlternativeServiceVector& /*altsvc_vector*/) {
}

void OgHttp2Session::OnPriority(spdy::SpdyStreamId /*stream_id*/,
                                spdy::SpdyStreamId /*parent_stream_id*/,
                                int /*weight*/, bool /*exclusive*/) {}

void OgHttp2Session::OnPriorityUpdate(
    spdy::SpdyStreamId /*prioritized_stream_id*/,
    absl::string_view /*priority_field_value*/) {}

bool OgHttp2Session::OnUnknownFrame(spdy::SpdyStreamId /*stream_id*/,
                                    uint8_t /*frame_type*/) {
  return true;
}

void OgHttp2Session::OnUnknownFrameStart(spdy::SpdyStreamId stream_id,
                                         size_t length, uint8_t type,
                                         uint8_t flags) {
  process_metadata_ = false;
  if (streams_reset_.contains(stream_id)) {
    return;
  }
  if (type == kMetadataFrameType) {
    QUICHE_DCHECK_EQ(metadata_length_, 0u);
    visitor_.OnBeginMetadataForStream(stream_id, length);
    metadata_length_ = length;
    process_metadata_ = true;
    end_metadata_ = flags & kMetadataEndFlag;

    // Empty metadata payloads will not trigger OnUnknownFramePayload(), so
    // handle that possibility here.
    MaybeHandleMetadataEndForStream(stream_id);
  } else {
    QUICHE_DLOG(INFO) << "Received unexpected frame type "
                      << static_cast<int>(type);
  }
}

void OgHttp2Session::OnUnknownFramePayload(spdy::SpdyStreamId stream_id,
                                           absl::string_view payload) {
  if (!process_metadata_) {
    return;
  }
  if (streams_reset_.contains(stream_id)) {
    return;
  }
  if (metadata_length_ > 0) {
    QUICHE_DCHECK_LE(payload.size(), metadata_length_);
    const bool payload_success =
        visitor_.OnMetadataForStream(stream_id, payload);
    if (payload_success) {
      metadata_length_ -= payload.size();
      MaybeHandleMetadataEndForStream(stream_id);
    } else {
      fatal_visitor_callback_failure_ = true;
      decoder_.StopProcessing();
    }
  } else {
    QUICHE_DLOG(INFO) << "Unexpected metadata payload for stream " << stream_id;
  }
}

void OgHttp2Session::OnHeaderStatus(
    Http2StreamId stream_id, Http2VisitorInterface::OnHeaderResult result) {
  QUICHE_DCHECK_NE(result, Http2VisitorInterface::HEADER_OK);
  QUICHE_VLOG(1) << "OnHeaderStatus(stream_id=" << stream_id
                 << ", result=" << result << ")";
  const bool should_reset_stream =
      result == Http2VisitorInterface::HEADER_RST_STREAM ||
      result == Http2VisitorInterface::HEADER_FIELD_INVALID ||
      result == Http2VisitorInterface::HEADER_HTTP_MESSAGING;
  if (should_reset_stream) {
    const Http2ErrorCode error_code =
        (result == Http2VisitorInterface::HEADER_RST_STREAM)
            ? Http2ErrorCode::INTERNAL_ERROR
            : Http2ErrorCode::PROTOCOL_ERROR;
    const spdy::SpdyErrorCode spdy_error_code = TranslateErrorCode(error_code);
    const Http2VisitorInterface::InvalidFrameError frame_error =
        (result == Http2VisitorInterface::HEADER_RST_STREAM ||
         result == Http2VisitorInterface::HEADER_FIELD_INVALID)
            ? Http2VisitorInterface::InvalidFrameError::kHttpHeader
            : Http2VisitorInterface::InvalidFrameError::kHttpMessaging;
    auto it = streams_reset_.find(stream_id);
    if (it == streams_reset_.end()) {
      EnqueueFrame(
          std::make_unique<spdy::SpdyRstStreamIR>(stream_id, spdy_error_code));

      if (result == Http2VisitorInterface::HEADER_FIELD_INVALID ||
          result == Http2VisitorInterface::HEADER_HTTP_MESSAGING) {
        const bool ok = visitor_.OnInvalidFrame(stream_id, frame_error);
        if (!ok) {
          fatal_visitor_callback_failure_ = true;
          LatchErrorAndNotify(error_code, ConnectionError::kHeaderError);
        }
      }
    }
  } else if (result == Http2VisitorInterface::HEADER_CONNECTION_ERROR) {
    fatal_visitor_callback_failure_ = true;
    LatchErrorAndNotify(Http2ErrorCode::INTERNAL_ERROR,
                        ConnectionError::kHeaderError);
  } else if (result == Http2VisitorInterface::HEADER_COMPRESSION_ERROR) {
    LatchErrorAndNotify(Http2ErrorCode::COMPRESSION_ERROR,
                        ConnectionError::kHeaderError);
  }
}

void OgHttp2Session::MaybeSetupPreface(bool sending_outbound_settings) {
  if (!queued_preface_) {
    queued_preface_ = true;
    if (!IsServerSession()) {
      buffered_data_.Append(
          absl::string_view(spdy::kHttp2ConnectionHeaderPrefix,
                            spdy::kHttp2ConnectionHeaderPrefixSize));
    }
    if (!sending_outbound_settings) {
      QUICHE_DCHECK(frames_.empty());
      // First frame must be a non-ack SETTINGS.
      EnqueueFrame(PrepareSettingsFrame(GetInitialSettings()));
    }
  }
}

std::vector<Http2Setting> OgHttp2Session::GetInitialSettings() const {
  std::vector<Http2Setting> settings;
  if (!IsServerSession()) {
    // Disable server push. Note that server push from clients is already
    // disabled, so the server does not need to send this disabling setting.
    // TODO(diannahu): Consider applying server push disabling on SETTINGS ack.
    settings.push_back({Http2KnownSettingsId::ENABLE_PUSH, 0});
  }
  if (options_.max_header_list_bytes) {
    settings.push_back({Http2KnownSettingsId::MAX_HEADER_LIST_SIZE,
                        *options_.max_header_list_bytes});
  }
  if (options_.allow_extended_connect && IsServerSession()) {
    settings.push_back({Http2KnownSettingsId::ENABLE_CONNECT_PROTOCOL, 1u});
  }
  return setting
```