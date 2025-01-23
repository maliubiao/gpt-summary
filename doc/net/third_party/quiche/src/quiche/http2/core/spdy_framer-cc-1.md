Response:
My thinking process to summarize the functionality of the provided `spdy_framer.cc` code would go like this:

1. **Understand the Goal:** The core function of a "framer" is to take structured data (in this case, represented by `SpdyFrameIR` objects) and convert it into a serialized byte stream that adheres to the HTTP/2 or SPDY protocol specification. It also needs to handle the reverse process (not shown in this snippet).

2. **Identify Key Classes and Methods:**  I'd scan the code for central classes and their primary methods. The name `SpdyFramer` immediately stands out as the main actor. Within it, `SerializeFrame`, and individual `Serialize...` methods (like `SerializeData`, `SerializeHeaders`, etc.) are clearly the main actions.

3. **Analyze the `SerializeFrame` Method:** This seems to be the entry point. It takes a `SpdyFrameIR` and a `ZeroCopyOutputBuffer`. The use of a `FrameSerializationVisitor` pattern is evident. This suggests a dispatch mechanism based on the specific type of `SpdyFrameIR`.

4. **Examine the Visitors:**  The code defines two main visitors:
    * `FrameSerializationVisitor`:  Its primary job is to call the appropriate `SpdyFramer::Serialize...` method based on the type of frame being visited. It also manages the `SpdySerializedFrame` output.
    * `FlagsSerializationVisitor`: This visitor is specifically designed to extract the flags associated with a given `SpdyFrameIR`.

5. **Dive into Individual `Serialize...` Methods:**  I'd look at a few examples to understand the common patterns:
    * **Common Structure:** Most `Serialize...` methods follow a similar pattern:
        * Determine the necessary flags.
        * Calculate the frame size.
        * Create a `SpdyFrameBuilder`.
        * Call `BeginNewFrame` with the appropriate type, flags, and stream ID.
        * Write the frame-specific data fields using `builder.WriteUInt...` and `builder.WriteBytes`.
        * Use `QUICHE_DCHECK_EQ` to ensure the expected size is achieved.
    * **Frame-Specific Logic:** I'd notice the distinct logic for each frame type, handling things like padding, priority, header encoding (using `HpackEncoder`), etc.
    * **Helper Functions:** I'd observe the use of helper functions like `SerializeDataBuilderHelper`, `SerializeHeadersBuilderHelper`, etc., which encapsulate the logic for calculating flags and sizes.
    * **Continuation Frames:** The handling of `CONTINUATION` frames, especially within `SerializeHeaders` and `SerializePushPromise`, is an important detail.

6. **Look for Cross-Cutting Concerns:**
    * **Flags:** The consistent manipulation of `flags` across different frame types is a key aspect.
    * **Padding:** The handling of padding in `DATA`, `HEADERS`, and `PUSH_PROMISE` frames.
    * **HPACK Encoding:** The use of `HpackEncoder` for compressing headers.
    * **Error Handling (Implicit):** While not explicitly error handling, the `QUICHE_DCHECK_EQ` statements suggest a focus on correctness and detecting inconsistencies during serialization.

7. **Consider the `SpdyFrameIR` Hierarchy (Though Not Fully Shown):** I'd infer that `SpdyFrameIR` is an abstract base class, and there are concrete derived classes for each frame type (e.g., `SpdyDataIR`, `SpdyHeadersIR`). This is essential for the visitor pattern to work.

8. **Think About Usage (As a User of this Class):** A developer would likely create `SpdyFrameIR` objects, populate them with the necessary data, and then call `SpdyFramer::SerializeFrame` to get the serialized representation.

9. **Address the Specific Questions:** Now I would go back to the prompt's specific questions:
    * **Functionality:** Based on the above analysis, I'd summarize the core functionality as serializing `SpdyFrameIR` objects into byte streams.
    * **Relationship to JavaScript:**  I'd think about how this low-level C++ code relates to higher-level JavaScript. The connection is through the browser's network stack. JavaScript makes requests, and the browser uses code like this to format those requests into HTTP/2 frames for transmission. The example of `fetch()` is a good illustration.
    * **Logic and Assumptions:** I'd identify the key assumptions, such as the input `SpdyFrameIR` being well-formed. For input/output examples, I would choose a simple case like serializing a DATA frame.
    * **User Errors:** I'd think about common mistakes a *programmer* using this class might make, such as incorrectly setting flags or sizes in the `SpdyFrameIR` objects.
    * **User Steps to Reach This Code:** I'd trace back from a user action (like clicking a link) to how that triggers network requests and ultimately involves the framer.
    * **Part 2 Summary:** I'd reiterate the main function of serialization and the use of the visitor pattern.

By following these steps, I can systematically analyze the code and arrive at a comprehensive and accurate summary of its functionality, along with addressing the specific questions in the prompt. The key is to break down the code into manageable parts, understand the relationships between them, and then synthesize that understanding into a coherent explanation.
这是 `net/third_party/quiche/src/quiche/http2/core/spdy_framer.cc` 文件的第二部分，延续了第一部分的功能，主要负责将代表 HTTP/2 帧的内部数据结构 (`SpdyFrameIR`) 序列化成网络传输的字节流。

**归纳一下它的功能:**

这部分代码延续了 `SpdyFramer` 类的实现，主要负责将各种类型的 `SpdyFrameIR` 对象序列化为可以发送到网络上的字节流。 它使用了访问者模式 (`Visitor Pattern`) 来处理不同类型的帧，并提供了针对每种帧类型的序列化方法。

**更具体地说，这部分代码实现了以下功能:**

1. **定义帧标志的序列化访问器 (`FlagsSerializationVisitor`):**
   -  遍历 `SpdyFrameIR` 对象，提取并返回与该帧类型相关的标志位。
   -  例如，对于 `HEADERS` 帧，它会检查 `fin`, `padded`, `has_priority` 等属性，并设置相应的标志位。

2. **提供通用的帧序列化方法 (`SerializeFrame`):**
   -  接受一个 `SpdyFrameIR` 对象作为输入。
   -  创建一个 `FrameSerializationVisitor` 对象，并将 `SpdyFramer` 自身传递给访问器。
   -  调用 `frame.Visit(&visitor)`，根据 `frame` 的具体类型，访问器会调用 `SpdyFramer` 中对应的 `Serialize...` 方法。
   -  返回序列化后的 `SpdySerializedFrame` 对象。

3. **提供获取帧标志的方法 (`GetSerializedFlags`):**
   -  接受一个 `SpdyFrameIR` 对象作为输入。
   -  创建一个 `FlagsSerializationVisitor` 对象。
   -  调用 `frame.Visit(&visitor)`，让访问器提取标志位。
   -  返回提取出的标志位。

4. **实现各种 HTTP/2 帧类型的序列化方法 (`Serialize...`)：**
   -  **`SerializeData`:** 序列化 DATA 帧，包括数据和可选的填充。
   -  **`SerializeDataFrameHeaderWithPaddingLengthField`:** 序列化带有填充长度字段的 DATA 帧头部。
   -  **`SerializeRstStream`:** 序列化 RST_STREAM 帧，用于终止一个流。
   -  **`SerializeSettings`:** 序列化 SETTINGS 帧，用于协商连接级别的参数。
   -  **`SerializePing`:** 序列化 PING 帧，用于测量 RTT 或保持连接活跃。
   -  **`SerializeGoAway`:** 序列化 GOAWAY 帧，用于通知对端停止创建新的流。
   -  **`SerializeHeaders`:** 序列化 HEADERS 帧，用于发送 HTTP 头部。它涉及到 HPACK 压缩。
   -  **`SerializeWindowUpdate`:** 序列化 WINDOW_UPDATE 帧，用于控制流量。
   -  **`SerializePushPromise`:** 序列化 PUSH_PROMISE 帧，用于服务器主动推送资源。 它涉及到 HPACK 压缩。
   -  **`SerializeContinuation`:** 序列化 CONTINUATION 帧，用于分割过大的头部块。
   -  **`SerializeAltSvc`:** 序列化 ALTSVC 帧，用于宣告可用的备用服务。
   -  **`SerializePriority`:** 序列化 PRIORITY 帧，用于设置流的优先级。
   -  **`SerializePriorityUpdate`:** 序列化 PRIORITY_UPDATE 帧，用于更新现有流的优先级。
   -  **`SerializeAcceptCh`:** 序列化 ACCEPT_CH 帧，用于宣告服务器接受的客户端提示。
   -  **`SerializeUnknown`:** 序列化未知的帧类型。

5. **提供将帧序列化到 `ZeroCopyOutputBuffer` 的方法 (`SerializeFrame` 重载):**
   -  接受一个 `SpdyFrameIR` 对象和一个 `ZeroCopyOutputBuffer` 对象作为输入。
   -  创建一个 `FrameSerializationVisitorWithOutput` 对象，并将 `SpdyFramer` 和 `ZeroCopyOutputBuffer` 传递给它。
   -  调用 `frame.Visit(&visitor)`，访问器会将序列化后的数据写入 `ZeroCopyOutputBuffer`。
   -  返回写入的字节数。

6. **管理 HPACK 编码器 (`HpackEncoder`):**
   -  提供获取 HPACK 编码器实例的方法 (`GetHpackEncoder`)，用于压缩头部。
   -  提供更新 HPACK 头部表大小的方法 (`UpdateHeaderEncoderTableSize`)。
   -  提供获取当前头部编码器表大小的方法 (`header_encoder_table_size`)。

**与 JavaScript 功能的关系:**

这段 C++ 代码是 Chromium 网络栈的一部分，负责 HTTP/2 协议的底层实现。当 JavaScript 代码通过浏览器发起网络请求时，例如使用 `fetch()` API 或 `XMLHttpRequest` 对象，浏览器内部的网络栈会处理这些请求。

- **请求头部的序列化:** 当 JavaScript 发起一个 HTTP 请求时，浏览器会将请求头信息传递给 C++ 网络栈。`SpdyFramer::SerializeHeaders` 方法会被调用，使用 HPACK 编码器将头部压缩，并将其序列化为 HEADERS 帧发送出去。
   **举例说明:**  假设 JavaScript 代码执行以下操作：
   ```javascript
   fetch('https://example.com', {
     headers: {
       'Content-Type': 'application/json',
       'Authorization': 'Bearer mytoken'
     }
   });
   ```
   Chromium 网络栈会将 `Content-Type` 和 `Authorization` 这两个头部信息传递给 `SpdyFramer::SerializeHeaders`，最终序列化成 HEADERS 帧。

- **请求体的序列化:** 如果请求包含请求体 (例如 POST 请求)，`SpdyFramer::SerializeData` 方法会被调用，将请求体数据序列化为 DATA 帧。
   **举例说明:**  假设 JavaScript 代码执行以下操作：
   ```javascript
   fetch('https://example.com/api', {
     method: 'POST',
     body: JSON.stringify({ key: 'value' })
   });
   ```
   Chromium 网络栈会将 `JSON.stringify({ key: 'value' })` 的结果传递给 `SpdyFramer::SerializeData`，序列化成 DATA 帧。

- **服务器推送的头部序列化:** 当服务器使用 HTTP/2 的 Server Push 功能推送资源时，`SpdyFramer::SerializePushPromise` 方法会被调用，将推送资源的头部信息序列化为 PUSH_PROMISE 帧。
   **举例说明:**  如果服务器决定推送一个 CSS 文件，它会构造一个 PUSH_PROMISE 帧，其中包含了请求该 CSS 文件的 HEADERS 信息，并由 `SpdyFramer::SerializePushPromise` 进行序列化。

**逻辑推理、假设输入与输出:**

**假设输入:** 一个表示 HTTP HEADERS 帧的 `SpdyHeadersIR` 对象，包含以下信息：
- `stream_id`: 3
- `fin`: false
- `padded`: false
- `has_priority`: false
- `header_block`:  一个包含 `{"Content-Type": "text/html", "Custom-Header": "value"}` 的头部块。

**假设输出:** `SpdyFramer::SerializeFrame` 方法会返回一个 `SpdySerializedFrame` 对象，其中包含了序列化后的字节流，大致如下（字节流内容会因 HPACK 编码而异）：

```
00 00 0c  // Length: 12 bytes (假设 HPACK 编码后)
01        // Type: HEADERS (0x01)
04        // Flags: 0x04 (END_HEADERS)
00 00 00 03 // Stream ID: 3
... (HPACK 编码后的头部块) ...
```

**用户或编程常见的使用错误:**

1. **手动设置错误的标志位:**  程序员可能会错误地手动设置 `SpdyFrameIR` 对象的标志位，导致序列化后的帧标志不正确。
   **示例:** 程序员错误地将 `HEADERS` 帧的 `fin` 设置为 `true`，但实际上后续还有 CONTINUATION 帧要发送。

2. **计算错误的填充长度:** 如果启用了填充，程序员需要正确计算填充长度并设置 `padding_payload_len`。错误的填充长度会导致接收端解析错误。
   **示例:**  对于 DATA 帧，设置的 `padding_payload_len` 比实际填充的字节数多或少。

3. **在需要发送 CONTINUATION 帧时设置了 `END_HEADERS` 标志:** 对于较大的头部块，需要分割成多个 HEADERS 和 CONTINUATION 帧发送。如果在 HEADERS 帧或中间的 CONTINUATION 帧中错误地设置了 `END_HEADERS` 标志，接收端会认为头部已经结束，导致解析错误。

4. **忘记调用 HPACK 编码器:** 在序列化 HEADERS 和 PUSH_PROMISE 帧时，必须使用 HPACK 编码器对头部块进行压缩。忘记使用编码器会导致发送未压缩的头部，违反 HTTP/2 协议。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在 Chrome 浏览器中访问 `https://example.com/page`。以下是可能到达 `SpdyFramer::SerializeHeaders` 的步骤：

1. **用户在地址栏输入 URL 并按下回车键。**
2. **Chrome 浏览器解析 URL，确定协议为 HTTPS。**
3. **Chrome 的网络栈 (Cronet 或 Blink 的网络组件) 尝试与 `example.com` 的服务器建立 TCP 连接。**
4. **如果需要，进行 TLS 握手以建立安全连接。**
5. **在 TLS 握手期间或之后，如果客户端和服务器协商使用 HTTP/2 协议，则后续通信将使用 HTTP/2 帧。**
6. **浏览器构造一个表示 HTTP GET 请求的内部数据结构，包括请求方法、URL、头部信息等。**
7. **网络栈将 HTTP 请求的头部信息转换为 `SpdyHeadersIR` 对象。**
8. **`SpdyFramer::SerializeHeaders` 方法被调用，将 `SpdyHeadersIR` 对象序列化为可以发送的 HEADERS 帧。**
9. **序列化后的 HEADERS 帧被发送到服务器。**

**调试线索:**

如果在调试网络请求时遇到问题，可以从以下方面入手：

- **网络抓包:** 使用 Wireshark 或 Chrome 开发者工具的网络面板捕获网络数据包，查看发送的 HTTP/2 帧的内容，确认帧类型、标志位、长度等是否正确。
- **Chromium 内部日志:**  Chromium 提供了丰富的内部日志记录，可以查看与 HTTP/2 帧处理相关的日志信息，例如帧的序列化和反序列化过程。
- **断点调试:**  在 `SpdyFramer::SerializeHeaders` 或其他相关的序列化方法中设置断点，查看 `SpdyFrameIR` 对象的内容，以及序列化过程中的变量值，帮助定位问题。
- **对比预期输出:** 根据 HTTP/2 协议规范，手动计算预期生成的帧内容，与实际抓包到的内容进行对比，找出差异。

总而言之，这段代码是 Chromium 网络栈中至关重要的一部分，负责将高级的 HTTP/2 概念转化为底层的网络字节流，确保浏览器能够正确地与支持 HTTP/2 的服务器进行通信。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/core/spdy_framer.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
ERS_FLAG_END_HEADERS;
    if (headers.fin()) {
      flags_ |= CONTROL_FLAG_FIN;
    }
    if (headers.padded()) {
      flags_ |= HEADERS_FLAG_PADDED;
    }
    if (headers.has_priority()) {
      flags_ |= HEADERS_FLAG_PRIORITY;
    }
  }

  void VisitWindowUpdate(const SpdyWindowUpdateIR& /*window_update*/) override {
    flags_ = kNoFlags;
  }

  // TODO(diannahu): The END_PUSH_PROMISE flag is incorrect for PUSH_PROMISEs
  //     that require CONTINUATION frames.
  void VisitPushPromise(const SpdyPushPromiseIR& push_promise) override {
    flags_ = PUSH_PROMISE_FLAG_END_PUSH_PROMISE;
    if (push_promise.padded()) {
      flags_ |= PUSH_PROMISE_FLAG_PADDED;
    }
  }

  // TODO(diannahu): The END_HEADERS flag is incorrect for CONTINUATIONs that
  //     require CONTINUATION frames.
  void VisitContinuation(const SpdyContinuationIR& /*continuation*/) override {
    flags_ = HEADERS_FLAG_END_HEADERS;
  }

  void VisitAltSvc(const SpdyAltSvcIR& /*altsvc*/) override {
    flags_ = kNoFlags;
  }

  void VisitPriority(const SpdyPriorityIR& /*priority*/) override {
    flags_ = kNoFlags;
  }

  void VisitPriorityUpdate(
      const SpdyPriorityUpdateIR& /*priority_update*/) override {
    flags_ = kNoFlags;
  }

  void VisitAcceptCh(const SpdyAcceptChIR& /*accept_ch*/) override {
    flags_ = kNoFlags;
  }

  uint8_t flags() const { return flags_; }

 private:
  uint8_t flags_ = kNoFlags;
};

}  // namespace

SpdySerializedFrame SpdyFramer::SerializeFrame(const SpdyFrameIR& frame) {
  FrameSerializationVisitor visitor(this);
  frame.Visit(&visitor);
  return visitor.ReleaseSerializedFrame();
}

uint8_t SpdyFramer::GetSerializedFlags(const SpdyFrameIR& frame) {
  FlagsSerializationVisitor visitor;
  frame.Visit(&visitor);
  return visitor.flags();
}

bool SpdyFramer::SerializeData(const SpdyDataIR& data_ir,
                               ZeroCopyOutputBuffer* output) const {
  uint8_t flags = DATA_FLAG_NONE;
  int num_padding_fields = 0;
  size_t size_with_padding = 0;
  SerializeDataBuilderHelper(data_ir, &flags, &num_padding_fields,
                             &size_with_padding);
  SpdyFrameBuilder builder(size_with_padding, output);

  bool ok =
      builder.BeginNewFrame(SpdyFrameType::DATA, flags, data_ir.stream_id());

  if (data_ir.padded()) {
    ok = ok && builder.WriteUInt8(data_ir.padding_payload_len() & 0xff);
  }

  ok = ok && builder.WriteBytes(data_ir.data(), data_ir.data_len());
  if (data_ir.padding_payload_len() > 0) {
    std::string padding;
    padding = std::string(data_ir.padding_payload_len(), 0);
    ok = ok && builder.WriteBytes(padding.data(), padding.length());
  }
  QUICHE_DCHECK_EQ(size_with_padding, builder.length());
  return ok;
}

bool SpdyFramer::SerializeDataFrameHeaderWithPaddingLengthField(
    const SpdyDataIR& data_ir, ZeroCopyOutputBuffer* output) const {
  uint8_t flags = DATA_FLAG_NONE;
  size_t frame_size = 0;
  size_t num_padding_fields = 0;
  SerializeDataFrameHeaderWithPaddingLengthFieldBuilderHelper(
      data_ir, &flags, &frame_size, &num_padding_fields);

  SpdyFrameBuilder builder(frame_size, output);
  bool ok = true;
  ok = ok &&
       builder.BeginNewFrame(SpdyFrameType::DATA, flags, data_ir.stream_id(),
                             num_padding_fields + data_ir.data_len() +
                                 data_ir.padding_payload_len());
  if (data_ir.padded()) {
    ok = ok && builder.WriteUInt8(data_ir.padding_payload_len() & 0xff);
  }
  QUICHE_DCHECK_EQ(frame_size, builder.length());
  return ok;
}

bool SpdyFramer::SerializeRstStream(const SpdyRstStreamIR& rst_stream,
                                    ZeroCopyOutputBuffer* output) const {
  size_t expected_length = kRstStreamFrameSize;
  SpdyFrameBuilder builder(expected_length, output);
  bool ok = builder.BeginNewFrame(SpdyFrameType::RST_STREAM, 0,
                                  rst_stream.stream_id());
  ok = ok && builder.WriteUInt32(rst_stream.error_code());

  QUICHE_DCHECK_EQ(expected_length, builder.length());
  return ok;
}

bool SpdyFramer::SerializeSettings(const SpdySettingsIR& settings,
                                   ZeroCopyOutputBuffer* output) const {
  uint8_t flags = 0;
  // Size, in bytes, of this SETTINGS frame.
  size_t size = 0;
  const SettingsMap* values = &(settings.values());
  SerializeSettingsBuilderHelper(settings, &flags, values, &size);
  SpdyFrameBuilder builder(size, output);
  bool ok = builder.BeginNewFrame(SpdyFrameType::SETTINGS, flags, 0);

  // If this is an ACK, payload should be empty.
  if (settings.is_ack()) {
    return ok;
  }

  QUICHE_DCHECK_EQ(kSettingsFrameMinimumSize, builder.length());
  for (auto it = values->begin(); it != values->end(); ++it) {
    int setting_id = it->first;
    QUICHE_DCHECK_GE(setting_id, 0);
    ok = ok && builder.WriteUInt16(static_cast<SpdySettingsId>(setting_id)) &&
         builder.WriteUInt32(it->second);
  }
  QUICHE_DCHECK_EQ(size, builder.length());
  return ok;
}

bool SpdyFramer::SerializePing(const SpdyPingIR& ping,
                               ZeroCopyOutputBuffer* output) const {
  SpdyFrameBuilder builder(kPingFrameSize, output);
  uint8_t flags = 0;
  if (ping.is_ack()) {
    flags |= PING_FLAG_ACK;
  }
  bool ok = builder.BeginNewFrame(SpdyFrameType::PING, flags, 0);
  ok = ok && builder.WriteUInt64(ping.id());
  QUICHE_DCHECK_EQ(kPingFrameSize, builder.length());
  return ok;
}

bool SpdyFramer::SerializeGoAway(const SpdyGoAwayIR& goaway,
                                 ZeroCopyOutputBuffer* output) const {
  // Compute the output buffer size, take opaque data into account.
  size_t expected_length = kGoawayFrameMinimumSize;
  expected_length += goaway.description().size();
  SpdyFrameBuilder builder(expected_length, output);

  // Serialize the GOAWAY frame.
  bool ok = builder.BeginNewFrame(SpdyFrameType::GOAWAY, 0, 0);

  // GOAWAY frames specify the last good stream id.
  ok = ok && builder.WriteUInt32(goaway.last_good_stream_id()) &&
       // GOAWAY frames also specify the error status code.
       builder.WriteUInt32(goaway.error_code());

  // GOAWAY frames may also specify opaque data.
  if (!goaway.description().empty()) {
    ok = ok && builder.WriteBytes(goaway.description().data(),
                                  goaway.description().size());
  }

  QUICHE_DCHECK_EQ(expected_length, builder.length());
  return ok;
}

bool SpdyFramer::SerializeHeaders(const SpdyHeadersIR& headers,
                                  ZeroCopyOutputBuffer* output) {
  uint8_t flags = 0;
  // The size of this frame, including padding (if there is any) and
  // variable-length header block.
  size_t size = 0;
  std::string hpack_encoding;
  int weight = 0;
  size_t length_field = 0;
  SerializeHeadersBuilderHelper(headers, &flags, &size, &hpack_encoding,
                                &weight, &length_field);

  bool ok = true;
  SpdyFrameBuilder builder(size, output);
  ok = ok && builder.BeginNewFrame(SpdyFrameType::HEADERS, flags,
                                   headers.stream_id(), length_field);
  QUICHE_DCHECK_EQ(kHeadersFrameMinimumSize, builder.length());

  int padding_payload_len = 0;
  if (headers.padded()) {
    ok = ok && builder.WriteUInt8(headers.padding_payload_len());
    padding_payload_len = headers.padding_payload_len();
  }
  if (headers.has_priority()) {
    ok = ok &&
         builder.WriteUInt32(PackStreamDependencyValues(
             headers.exclusive(), headers.parent_stream_id())) &&
         // Per RFC 7540 section 6.3, serialized weight value is weight - 1.
         builder.WriteUInt8(weight - 1);
  }
  ok = ok && WritePayloadWithContinuation(
                 &builder, hpack_encoding, headers.stream_id(),
                 SpdyFrameType::HEADERS, padding_payload_len);

  if (debug_visitor_) {
    const size_t header_list_size =
        GetUncompressedSerializedLength(headers.header_block());
    debug_visitor_->OnSendCompressedFrame(headers.stream_id(),
                                          SpdyFrameType::HEADERS,
                                          header_list_size, builder.length());
  }

  return ok;
}

bool SpdyFramer::SerializeWindowUpdate(const SpdyWindowUpdateIR& window_update,
                                       ZeroCopyOutputBuffer* output) const {
  SpdyFrameBuilder builder(kWindowUpdateFrameSize, output);
  bool ok = builder.BeginNewFrame(SpdyFrameType::WINDOW_UPDATE, kNoFlags,
                                  window_update.stream_id());
  ok = ok && builder.WriteUInt32(window_update.delta());
  QUICHE_DCHECK_EQ(kWindowUpdateFrameSize, builder.length());
  return ok;
}

bool SpdyFramer::SerializePushPromise(const SpdyPushPromiseIR& push_promise,
                                      ZeroCopyOutputBuffer* output) {
  uint8_t flags = 0;
  size_t size = 0;
  std::string hpack_encoding;
  SerializePushPromiseBuilderHelper(push_promise, &flags, &hpack_encoding,
                                    &size);

  bool ok = true;
  SpdyFrameBuilder builder(size, output);
  size_t length =
      std::min(size, kHttp2MaxControlFrameSendSize) - kFrameHeaderSize;
  ok = builder.BeginNewFrame(SpdyFrameType::PUSH_PROMISE, flags,
                             push_promise.stream_id(), length);

  int padding_payload_len = 0;
  if (push_promise.padded()) {
    ok = ok && builder.WriteUInt8(push_promise.padding_payload_len()) &&
         builder.WriteUInt32(push_promise.promised_stream_id());
    QUICHE_DCHECK_EQ(kPushPromiseFrameMinimumSize + kPadLengthFieldSize,
                     builder.length());

    padding_payload_len = push_promise.padding_payload_len();
  } else {
    ok = ok && builder.WriteUInt32(push_promise.promised_stream_id());
    QUICHE_DCHECK_EQ(kPushPromiseFrameMinimumSize, builder.length());
  }

  ok = ok && WritePayloadWithContinuation(
                 &builder, hpack_encoding, push_promise.stream_id(),
                 SpdyFrameType::PUSH_PROMISE, padding_payload_len);

  if (debug_visitor_) {
    const size_t header_list_size =
        GetUncompressedSerializedLength(push_promise.header_block());
    debug_visitor_->OnSendCompressedFrame(push_promise.stream_id(),
                                          SpdyFrameType::PUSH_PROMISE,
                                          header_list_size, builder.length());
  }

  return ok;
}

bool SpdyFramer::SerializeContinuation(const SpdyContinuationIR& continuation,
                                       ZeroCopyOutputBuffer* output) const {
  const std::string& encoding = continuation.encoding();
  size_t frame_size = kContinuationFrameMinimumSize + encoding.size();
  SpdyFrameBuilder builder(frame_size, output);
  uint8_t flags = continuation.end_headers() ? HEADERS_FLAG_END_HEADERS : 0;
  bool ok = builder.BeginNewFrame(SpdyFrameType::CONTINUATION, flags,
                                  continuation.stream_id(),
                                  frame_size - kFrameHeaderSize);
  QUICHE_DCHECK_EQ(kFrameHeaderSize, builder.length());

  ok = ok && builder.WriteBytes(encoding.data(), encoding.size());
  return ok;
}

bool SpdyFramer::SerializeAltSvc(const SpdyAltSvcIR& altsvc_ir,
                                 ZeroCopyOutputBuffer* output) {
  std::string value;
  size_t size = 0;
  SerializeAltSvcBuilderHelper(altsvc_ir, &value, &size);
  SpdyFrameBuilder builder(size, output);
  bool ok = builder.BeginNewFrame(SpdyFrameType::ALTSVC, kNoFlags,
                                  altsvc_ir.stream_id()) &&
            builder.WriteUInt16(altsvc_ir.origin().length()) &&
            builder.WriteBytes(altsvc_ir.origin().data(),
                               altsvc_ir.origin().length()) &&
            builder.WriteBytes(value.data(), value.length());
  QUICHE_DCHECK_LT(kGetAltSvcFrameMinimumSize, builder.length());
  return ok;
}

bool SpdyFramer::SerializePriority(const SpdyPriorityIR& priority,
                                   ZeroCopyOutputBuffer* output) const {
  SpdyFrameBuilder builder(kPriorityFrameSize, output);
  bool ok = builder.BeginNewFrame(SpdyFrameType::PRIORITY, kNoFlags,
                                  priority.stream_id());
  ok = ok &&
       builder.WriteUInt32(PackStreamDependencyValues(
           priority.exclusive(), priority.parent_stream_id())) &&
       // Per RFC 7540 section 6.3, serialized weight value is actual value - 1.
       builder.WriteUInt8(priority.weight() - 1);
  QUICHE_DCHECK_EQ(kPriorityFrameSize, builder.length());
  return ok;
}

bool SpdyFramer::SerializePriorityUpdate(
    const SpdyPriorityUpdateIR& priority_update,
    ZeroCopyOutputBuffer* output) const {
  const size_t total_size = kPriorityUpdateFrameMinimumSize +
                            priority_update.priority_field_value().size();
  SpdyFrameBuilder builder(total_size, output);
  bool ok = builder.BeginNewFrame(SpdyFrameType::PRIORITY_UPDATE, kNoFlags,
                                  priority_update.stream_id());

  ok = ok && builder.WriteUInt32(priority_update.prioritized_stream_id());
  ok = ok && builder.WriteBytes(priority_update.priority_field_value().data(),
                                priority_update.priority_field_value().size());
  QUICHE_DCHECK_EQ(total_size, builder.length());
  return ok;
}

bool SpdyFramer::SerializeAcceptCh(const SpdyAcceptChIR& accept_ch,
                                   ZeroCopyOutputBuffer* output) const {
  const size_t total_size = accept_ch.size();
  SpdyFrameBuilder builder(total_size, output);
  bool ok = builder.BeginNewFrame(SpdyFrameType::ACCEPT_CH, kNoFlags,
                                  accept_ch.stream_id());

  for (const AcceptChOriginValuePair& entry : accept_ch.entries()) {
    ok = ok && builder.WriteUInt16(entry.origin.size());
    ok = ok && builder.WriteBytes(entry.origin.data(), entry.origin.size());
    ok = ok && builder.WriteUInt16(entry.value.size());
    ok = ok && builder.WriteBytes(entry.value.data(), entry.value.size());
  }

  QUICHE_DCHECK_EQ(total_size, builder.length());
  return ok;
}

bool SpdyFramer::SerializeUnknown(const SpdyUnknownIR& unknown,
                                  ZeroCopyOutputBuffer* output) const {
  const size_t total_size = kFrameHeaderSize + unknown.payload().size();
  SpdyFrameBuilder builder(total_size, output);
  bool ok = builder.BeginNewUncheckedFrame(
      unknown.type(), unknown.flags(), unknown.stream_id(), unknown.length());
  ok = ok &&
       builder.WriteBytes(unknown.payload().data(), unknown.payload().size());
  return ok;
}

namespace {

class FrameSerializationVisitorWithOutput : public SpdyFrameVisitor {
 public:
  explicit FrameSerializationVisitorWithOutput(SpdyFramer* framer,
                                               ZeroCopyOutputBuffer* output)
      : framer_(framer), output_(output), result_(false) {}
  ~FrameSerializationVisitorWithOutput() override = default;

  size_t Result() { return result_; }

  void VisitData(const SpdyDataIR& data) override {
    result_ = framer_->SerializeData(data, output_);
  }
  void VisitRstStream(const SpdyRstStreamIR& rst_stream) override {
    result_ = framer_->SerializeRstStream(rst_stream, output_);
  }
  void VisitSettings(const SpdySettingsIR& settings) override {
    result_ = framer_->SerializeSettings(settings, output_);
  }
  void VisitPing(const SpdyPingIR& ping) override {
    result_ = framer_->SerializePing(ping, output_);
  }
  void VisitGoAway(const SpdyGoAwayIR& goaway) override {
    result_ = framer_->SerializeGoAway(goaway, output_);
  }
  void VisitHeaders(const SpdyHeadersIR& headers) override {
    result_ = framer_->SerializeHeaders(headers, output_);
  }
  void VisitWindowUpdate(const SpdyWindowUpdateIR& window_update) override {
    result_ = framer_->SerializeWindowUpdate(window_update, output_);
  }
  void VisitPushPromise(const SpdyPushPromiseIR& push_promise) override {
    result_ = framer_->SerializePushPromise(push_promise, output_);
  }
  void VisitContinuation(const SpdyContinuationIR& continuation) override {
    result_ = framer_->SerializeContinuation(continuation, output_);
  }
  void VisitAltSvc(const SpdyAltSvcIR& altsvc) override {
    result_ = framer_->SerializeAltSvc(altsvc, output_);
  }
  void VisitPriority(const SpdyPriorityIR& priority) override {
    result_ = framer_->SerializePriority(priority, output_);
  }
  void VisitPriorityUpdate(
      const SpdyPriorityUpdateIR& priority_update) override {
    result_ = framer_->SerializePriorityUpdate(priority_update, output_);
  }
  void VisitAcceptCh(const SpdyAcceptChIR& accept_ch) override {
    result_ = framer_->SerializeAcceptCh(accept_ch, output_);
  }

  void VisitUnknown(const SpdyUnknownIR& unknown) override {
    result_ = framer_->SerializeUnknown(unknown, output_);
  }

 private:
  SpdyFramer* framer_;
  ZeroCopyOutputBuffer* output_;
  bool result_;
};

}  // namespace

size_t SpdyFramer::SerializeFrame(const SpdyFrameIR& frame,
                                  ZeroCopyOutputBuffer* output) {
  FrameSerializationVisitorWithOutput visitor(this, output);
  size_t free_bytes_before = output->BytesFree();
  frame.Visit(&visitor);
  return visitor.Result() ? free_bytes_before - output->BytesFree() : 0;
}

HpackEncoder* SpdyFramer::GetHpackEncoder() {
  if (hpack_encoder_ == nullptr) {
    hpack_encoder_ = std::make_unique<HpackEncoder>();
    if (!compression_enabled()) {
      hpack_encoder_->DisableCompression();
    }
  }
  return hpack_encoder_.get();
}

void SpdyFramer::UpdateHeaderEncoderTableSize(uint32_t value) {
  GetHpackEncoder()->ApplyHeaderTableSizeSetting(value);
}

size_t SpdyFramer::header_encoder_table_size() const {
  if (hpack_encoder_ == nullptr) {
    return kDefaultHeaderTableSizeSetting;
  } else {
    return hpack_encoder_->CurrentHeaderTableSizeSetting();
  }
}

}  // namespace spdy
```