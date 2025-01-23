Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

**1. Understanding the Goal:**

The core request is to analyze the `http_encoder.cc` file and describe its functionality, relation to JavaScript, provide examples, explain potential errors, and outline debugging steps.

**2. Initial Code Scan and Keyword Recognition:**

I'll start by quickly scanning the code, looking for keywords and patterns:

* `#include`:  Indicates dependencies and the overall purpose (encoding HTTP/3 frames).
* `namespace quic`:  Clearly identifies the code's place within the QUIC library.
* `HttpEncoder`: The central class.
* `Serialize...Frame`:  Functions with this naming convention are likely responsible for encoding different HTTP/3 frame types. This is a crucial observation.
* `HttpFrameType`: An enum (likely defined elsewhere) representing different HTTP/3 frame types like `DATA`, `HEADERS`, `SETTINGS`, etc.
* `QuicDataWriter`: A class used for writing data in a specific format (likely handling variable-length integers).
* `QuicByteCount`: A type for representing sizes, reinforcing the encoding aspect.
* `QUICHE_DCHECK`, `QUIC_DLOG`:  Debugging and assertion macros.
* `std::string`, `std::vector`, `std::pair`: Standard C++ data structures.
* `GetVarInt62Len`, `WriteVarInt62`:  Functions related to variable-length integer encoding (a key feature of HTTP/3).

**3. Deconstructing Functionality (Mapping Functions to Frame Types):**

The `Serialize...Frame` functions are the core of the encoder. I'll go through each one and identify the corresponding HTTP/3 frame type:

* `SerializeDataFrameHeader`: `HttpFrameType::DATA`
* `SerializeHeadersFrameHeader`: `HttpFrameType::HEADERS`
* `SerializeSettingsFrame`: `HttpFrameType::SETTINGS`
* `SerializeGoAwayFrame`: `HttpFrameType::GOAWAY`
* `SerializePriorityUpdateFrame`: `HttpFrameType::PRIORITY_UPDATE_REQUEST_STREAM`
* `SerializeAcceptChFrame`: `HttpFrameType::ACCEPT_CH`
* `SerializeOriginFrame`: `HttpFrameType::ORIGIN`
* `SerializeGreasingFrame`:  A special frame for testing and experimentation.
* `SerializeWebTransportStreamFrameHeader`: `HttpFrameType::WEBTRANSPORT_STREAM`
* `SerializeMetadataFrameHeader`: `HttpFrameType::METADATA`

This mapping provides a clear understanding of the encoder's scope. It handles the serialization of various HTTP/3 control and data frames.

**4. Identifying Key Operations:**

Within each `Serialize...Frame` function, the common operations are:

* **Calculating Payload Length:** Determining the size of the frame's data.
* **Calculating Total Length:**  Adding the header length (frame type and payload length) to the payload length.
* **Creating a Buffer/String:**  Allocating memory to hold the serialized frame.
* **Writing Frame Header:** Writing the frame type and payload length using `WriteFrameHeader` (or directly).
* **Writing Payload:**  Writing the frame-specific data using `QuicDataWriter`.

**5. Relating to JavaScript (and Web Browsers):**

Now, connect the low-level C++ encoding to the browser's behavior and JavaScript APIs:

* **Fetch API:** The most direct link. When a JavaScript application makes a `fetch` request, the browser needs to encode the HTTP request headers into a `HEADERS` frame. The response data will arrive in `DATA` frames.
* **WebSockets and WebTransport:**  The mention of `WEBTRANSPORT_STREAM` is a strong clue. These APIs use HTTP/3 as a transport, so this code is directly involved in sending data over these connections.
* **Settings Frames:**  Browsers and servers negotiate HTTP/3 settings using `SETTINGS` frames. This affects how the connection behaves.

**6. Crafting Examples (Hypothetical Input/Output):**

Create simple examples to illustrate the encoding process. Choose a few common frame types:

* **HEADERS:**  A simple request with a few headers.
* **SETTINGS:** Basic settings.
* **DATA:** A short data payload.

For each, define a plausible input structure (like the `SettingsFrame` struct) and the expected output (a hexadecimal representation of the serialized bytes). This demonstrates the encoding process in action.

**7. Identifying Potential User/Programming Errors:**

Think about how developers interacting with the QUIC stack *might* misuse it, or how the internal logic could fail:

* **Incorrect Payload Length Calculation:** A common off-by-one error or a misunderstanding of what constitutes the payload.
* **Mismatched Data:**  Trying to serialize data that doesn't conform to the expected frame structure.
* **Buffer Overflow (though less likely with `std::string` and `QuicDataWriter`):**  Trying to write more data than allocated.
* **Logic Errors in Frame Construction:** Forgetting to include a required field or encoding it incorrectly.

**8. Tracing User Actions and Debugging:**

Consider the steps a user takes in a browser that would lead to this code being executed:

1. User types a URL or clicks a link (initiating a navigation).
2. The browser resolves the domain and establishes a QUIC connection.
3. The browser needs to send an HTTP/3 request.
4. The `HttpEncoder` is used to serialize the request headers.
5. The server responds, and `HttpEncoder` (or a related decoder) is used for the response.

For debugging, think about the information a developer would need:

* **Network Logs:**  Seeing the actual bytes sent and received.
* **QUIC Internal Logs:**  The `QUIC_DLOG` statements in the code are clues.
* **Breakpoints:** Setting breakpoints in the `Serialize...Frame` functions.
* **Inspecting Variables:** Examining the values of payload lengths, frame data, etc.

**9. Structuring the Answer:**

Organize the information logically, following the prompt's structure:

* **Functionality:**  A high-level description and then a breakdown of each `Serialize...Frame` function.
* **Relationship to JavaScript:** Explain the connection through browser APIs.
* **Hypothetical Input/Output:** Provide clear examples.
* **User/Programming Errors:**  Describe common mistakes.
* **Debugging:** Outline the steps to reach this code and how to debug issues.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe focus too much on the low-level bit manipulation.
* **Correction:** Realize the importance of explaining the *purpose* of the encoding in the context of HTTP/3 and web browsers.
* **Refinement:** Make the JavaScript examples concrete by mentioning specific APIs like `fetch` and WebTransport. Ensure the hypothetical input/output examples are realistic and easy to understand. Emphasize the role of network logs in debugging.

By following this structured approach, I can systematically analyze the code and provide a comprehensive and accurate answer to the prompt.
这个文件 `net/third_party/quiche/src/quiche/quic/core/http/http_encoder.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，专注于 **将 HTTP/3 帧结构编码成二进制数据**。  它提供了一系列静态方法，用于将不同类型的 HTTP/3 帧（如 DATA, HEADERS, SETTINGS 等）序列化成可以通过网络发送的字节流。

**功能列举:**

1. **数据帧 (DATA Frame) 编码:**
   - `SerializeDataFrameHeader`:  仅序列化 DATA 帧的头部，包含帧类型和负载长度。
   - `GetDataFrameHeaderLength`: 计算 DATA 帧头部的长度。

2. **头部帧 (HEADERS Frame) 编码:**
   - `SerializeHeadersFrameHeader`: 序列化 HEADERS 帧的头部，包含帧类型和负载长度。

3. **设置帧 (SETTINGS Frame) 编码:**
   - `SerializeSettingsFrame`: 将 `SettingsFrame` 对象序列化成完整的 SETTINGS 帧，包括帧头部和设置参数。设置参数会按照键值对的键进行排序。

4. **GoAway 帧 (GOAWAY Frame) 编码:**
   - `SerializeGoAwayFrame`: 将 `GoAwayFrame` 对象序列化成完整的 GOAWAY 帧，用于通知对端停止创建新的流。

5. **优先级更新帧 (PRIORITY_UPDATE Frame) 编码:**
   - `SerializePriorityUpdateFrame`: 将 `PriorityUpdateFrame` 对象序列化成优先级更新帧，用于请求更新特定元素的优先级。

6. **Accept-CH 帧 (ACCEPT_CH Frame) 编码:**
   - `SerializeAcceptChFrame`: 将 `AcceptChFrame` 对象序列化成 ACCEPT_CH 帧，用于服务端向客户端声明支持的客户端提示 (Client Hints)。

7. **Origin 帧 (ORIGIN Frame) 编码:**
   - `SerializeOriginFrame`: 将 `OriginFrame` 对象序列化成 ORIGIN 帧，用于声明服务端支持的 Origin。

8. **Greasing 帧 (Greasing Frame) 编码:**
   - `SerializeGreasingFrame`: 生成一个“greasing”帧，用于测试和确保协议对未知帧类型的鲁棒性。这种帧的类型和内容是伪随机的，有助于发现实现中的假设或依赖。

9. **WebTransport 流帧头部 (WebTransport Stream Frame Header) 编码:**
   - `SerializeWebTransportStreamFrameHeader`: 序列化 WebTransport 流帧的头部，包含帧类型和会话 ID。

10. **元数据帧头部 (METADATA Frame Header) 编码:**
    - `SerializeMetadataFrameHeader`: 序列化 METADATA 帧的头部，包含帧类型和负载长度。

**与 JavaScript 功能的关系 (Fetch API 和 WebSocket API):**

这个文件直接参与了浏览器与服务器之间 HTTP/3 通信的底层实现，因此与 JavaScript 的 `fetch` API 和 WebSocket API 有着密切的关系。

* **Fetch API:** 当 JavaScript 代码使用 `fetch` 发起 HTTP 请求时，浏览器需要在底层将 HTTP 请求头（例如，请求方法、URL、请求头等）编码成 HTTP/3 的 HEADERS 帧。`HttpEncoder::SerializeHeadersFrameHeader` 方法就负责完成这个过程的一部分。同时，请求体的数据会被编码成 DATA 帧。
* **WebSocket API:** 虽然 WebSocket 最初基于 HTTP/1.1 升级而来，但在 QUIC 的背景下，WebSocket 可以直接运行在 QUIC 流之上。当使用基于 QUIC 的 WebSocket 时，`HttpEncoder` 也会参与消息的编码过程，特别是对于控制帧。
* **WebTransport API:**  `SerializeWebTransportStreamFrameHeader` 显式地表明了与 WebTransport 的联系。WebTransport 是一个允许客户端和服务器之间进行双向数据传输的 API，它可以运行在 HTTP/3 之上。这个方法用于编码 WebTransport 流的特定帧头。

**举例说明 (Fetch API):**

**假设输入 (JavaScript):**

```javascript
fetch('https://example.com/data', {
  method: 'GET',
  headers: {
    'X-Custom-Header': 'value'
  }
});
```

**逻辑推理和假设输出 (HttpEncoder 的部分工作):**

1. **Headers 构建:** 浏览器会将 `method: 'GET'` 和 `headers: {'X-Custom-Header': 'value'}` 等信息转换成 HTTP/3 的头部列表。
2. **Payload 长度计算:**  假设这个 GET 请求没有请求体，那么 HEADERS 帧的负载长度将基于编码后的头部列表的大小计算出来。
3. **`SerializeHeadersFrameHeader` 调用:** `HttpEncoder::SerializeHeadersFrameHeader` 方法会被调用，传入计算出的负载长度。
4. **假设输出 (十六进制表示):**  假设编码后的负载长度是 `0x0A` (十进制 10)，则输出可能类似于 `0x01 0x0A`。
   - `0x01` 代表 HEADERS 帧类型 (实际值可能不同，这里只是示例)。
   - `0x0A` 代表负载长度。

**用户或编程常见的使用错误举例说明:**

虽然 `HttpEncoder` 是 Chromium 内部使用的，开发者通常不会直接调用它，但理解其背后的逻辑有助于避免在更高层面的编程错误。

1. **错误地假设 HTTP/3 帧结构:**  开发者如果尝试手动构建 HTTP/3 帧，可能会错误地计算负载长度，或者使用错误的帧类型值。例如，错误地认为所有帧头部都是固定长度的。
2. **在不应该发送数据时发送数据:** 例如，在连接建立初期，可能需要先发送 SETTINGS 帧。错误的时间发送 DATA 帧可能会导致连接错误。
3. **忽略帧之间的依赖关系:**  某些帧的发送顺序和依赖关系是重要的。例如，在发送数据之前，通常需要先发送包含请求头的 HEADERS 帧。

**用户操作如何一步步到达这里 (调试线索):**

假设用户报告了某个网站加载缓慢或请求失败的问题，作为开发人员，可以按照以下步骤进行调试，最终可能会涉及到 `http_encoder.cc`:

1. **用户在 Chrome 浏览器中访问网站 `https://example.com`。**
2. **浏览器发起 QUIC 连接到服务器。** 这涉及到握手和协商过程。
3. **浏览器需要发送 HTTP/3 请求来获取网页资源。**
4. **Chrome 网络栈开始构建 HTTP/3 请求帧。**
   -  会根据请求头信息构建 HEADERS 帧。`HttpEncoder::SerializeHeadersFrameHeader` 会被调用来序列化 HEADERS 帧的头部。后续可能还会调用其他方法来序列化头部内容本身 (虽然 `http_encoder.cc` 中没有直接包含序列化头部内容的代码，但它负责帧头部的编码)。
   - 如果请求有 body，数据会被分割成 DATA 帧，并使用 `HttpEncoder::SerializeDataFrameHeader` 进行头部编码。
5. **构建好的帧数据被发送到网络。**
6. **如果在某个环节编码出错，例如计算的负载长度不正确，或者使用了错误的帧类型，服务器可能会拒绝连接或返回错误。**
7. **作为调试人员，可以使用 Chrome 的 `net-internals` 工具 (chrome://net-internals/#quic) 查看 QUIC 连接的详细信息，包括发送和接收的帧。**  如果发现发送的帧结构异常，就需要深入到 QUIC 代码中查找原因，这时就可能需要查看 `http_encoder.cc` 的代码来理解帧是如何被编码的。
8. **还可以使用抓包工具 (如 Wireshark) 捕获网络数据包，查看实际发送的二进制数据，与期望的 HTTP/3 帧结构进行对比。**

总而言之，`http_encoder.cc` 是 Chromium QUIC 实现中一个关键的低级别组件，负责将 HTTP/3 的逻辑结构转换为可以在网络上传输的二进制格式，是浏览器与服务器进行 HTTP/3 通信的基础。 尽管 JavaScript 开发者不会直接操作这个文件，但它支撑了 `fetch` 和 WebSocket 等重要的 Web API 的底层网络通信。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/http_encoder.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/http/http_encoder.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"

namespace quic {

namespace {

bool WriteFrameHeader(QuicByteCount length, HttpFrameType type,
                      QuicDataWriter* writer) {
  return writer->WriteVarInt62(static_cast<uint64_t>(type)) &&
         writer->WriteVarInt62(length);
}

QuicByteCount GetTotalLength(QuicByteCount payload_length, HttpFrameType type) {
  return QuicDataWriter::GetVarInt62Len(payload_length) +
         QuicDataWriter::GetVarInt62Len(static_cast<uint64_t>(type)) +
         payload_length;
}

}  // namespace

QuicByteCount HttpEncoder::GetDataFrameHeaderLength(
    QuicByteCount payload_length) {
  QUICHE_DCHECK_NE(0u, payload_length);
  return QuicDataWriter::GetVarInt62Len(payload_length) +
         QuicDataWriter::GetVarInt62Len(
             static_cast<uint64_t>(HttpFrameType::DATA));
}

quiche::QuicheBuffer HttpEncoder::SerializeDataFrameHeader(
    QuicByteCount payload_length, quiche::QuicheBufferAllocator* allocator) {
  QUICHE_DCHECK_NE(0u, payload_length);
  QuicByteCount header_length = GetDataFrameHeaderLength(payload_length);

  quiche::QuicheBuffer header(allocator, header_length);
  QuicDataWriter writer(header.size(), header.data());

  if (WriteFrameHeader(payload_length, HttpFrameType::DATA, &writer)) {
    return header;
  }
  QUIC_DLOG(ERROR)
      << "Http encoder failed when attempting to serialize data frame header.";
  return quiche::QuicheBuffer();
}

std::string HttpEncoder::SerializeHeadersFrameHeader(
    QuicByteCount payload_length) {
  QUICHE_DCHECK_NE(0u, payload_length);
  QuicByteCount header_length =
      QuicDataWriter::GetVarInt62Len(payload_length) +
      QuicDataWriter::GetVarInt62Len(
          static_cast<uint64_t>(HttpFrameType::HEADERS));

  std::string frame;
  frame.resize(header_length);
  QuicDataWriter writer(header_length, frame.data());

  if (WriteFrameHeader(payload_length, HttpFrameType::HEADERS, &writer)) {
    return frame;
  }
  QUIC_DLOG(ERROR)
      << "Http encoder failed when attempting to serialize headers "
         "frame header.";
  return {};
}

std::string HttpEncoder::SerializeSettingsFrame(const SettingsFrame& settings) {
  QuicByteCount payload_length = 0;
  std::vector<std::pair<uint64_t, uint64_t>> ordered_settings{
      settings.values.begin(), settings.values.end()};
  std::sort(ordered_settings.begin(), ordered_settings.end());
  // Calculate the payload length.
  for (const auto& p : ordered_settings) {
    payload_length += QuicDataWriter::GetVarInt62Len(p.first);
    payload_length += QuicDataWriter::GetVarInt62Len(p.second);
  }

  QuicByteCount total_length =
      GetTotalLength(payload_length, HttpFrameType::SETTINGS);

  std::string frame;
  frame.resize(total_length);
  QuicDataWriter writer(total_length, frame.data());

  if (!WriteFrameHeader(payload_length, HttpFrameType::SETTINGS, &writer)) {
    QUIC_DLOG(ERROR) << "Http encoder failed when attempting to serialize "
                        "settings frame header.";
    return {};
  }

  for (const auto& p : ordered_settings) {
    if (!writer.WriteVarInt62(p.first) || !writer.WriteVarInt62(p.second)) {
      QUIC_DLOG(ERROR) << "Http encoder failed when attempting to serialize "
                          "settings frame payload.";
      return {};
    }
  }

  return frame;
}

std::string HttpEncoder::SerializeGoAwayFrame(const GoAwayFrame& goaway) {
  QuicByteCount payload_length = QuicDataWriter::GetVarInt62Len(goaway.id);
  QuicByteCount total_length =
      GetTotalLength(payload_length, HttpFrameType::GOAWAY);

  std::string frame;
  frame.resize(total_length);
  QuicDataWriter writer(total_length, frame.data());

  if (WriteFrameHeader(payload_length, HttpFrameType::GOAWAY, &writer) &&
      writer.WriteVarInt62(goaway.id)) {
    return frame;
  }
  QUIC_DLOG(ERROR)
      << "Http encoder failed when attempting to serialize goaway frame.";
  return {};
}

std::string HttpEncoder::SerializePriorityUpdateFrame(
    const PriorityUpdateFrame& priority_update) {
  QuicByteCount payload_length =
      QuicDataWriter::GetVarInt62Len(priority_update.prioritized_element_id) +
      priority_update.priority_field_value.size();
  QuicByteCount total_length = GetTotalLength(
      payload_length, HttpFrameType::PRIORITY_UPDATE_REQUEST_STREAM);

  std::string frame;
  frame.resize(total_length);
  QuicDataWriter writer(total_length, frame.data());

  if (WriteFrameHeader(payload_length,
                       HttpFrameType::PRIORITY_UPDATE_REQUEST_STREAM,
                       &writer) &&
      writer.WriteVarInt62(priority_update.prioritized_element_id) &&
      writer.WriteBytes(priority_update.priority_field_value.data(),
                        priority_update.priority_field_value.size())) {
    return frame;
  }

  QUIC_DLOG(ERROR) << "Http encoder failed when attempting to serialize "
                      "PRIORITY_UPDATE frame.";
  return {};
}

std::string HttpEncoder::SerializeAcceptChFrame(
    const AcceptChFrame& accept_ch) {
  QuicByteCount payload_length = 0;
  for (const auto& entry : accept_ch.entries) {
    payload_length += QuicDataWriter::GetVarInt62Len(entry.origin.size());
    payload_length += entry.origin.size();
    payload_length += QuicDataWriter::GetVarInt62Len(entry.value.size());
    payload_length += entry.value.size();
  }

  QuicByteCount total_length =
      GetTotalLength(payload_length, HttpFrameType::ACCEPT_CH);

  std::string frame;
  frame.resize(total_length);
  QuicDataWriter writer(total_length, frame.data());

  if (!WriteFrameHeader(payload_length, HttpFrameType::ACCEPT_CH, &writer)) {
    QUIC_DLOG(ERROR)
        << "Http encoder failed to serialize ACCEPT_CH frame header.";
    return {};
  }

  for (const auto& entry : accept_ch.entries) {
    if (!writer.WriteStringPieceVarInt62(entry.origin) ||
        !writer.WriteStringPieceVarInt62(entry.value)) {
      QUIC_DLOG(ERROR)
          << "Http encoder failed to serialize ACCEPT_CH frame payload.";
      return {};
    }
  }

  return frame;
}

std::string HttpEncoder::SerializeOriginFrame(const OriginFrame& origin) {
  QuicByteCount payload_length = 0;
  for (const std::string& entry : origin.origins) {
    constexpr QuicByteCount kLengthFieldOverhead = 2;
    payload_length += kLengthFieldOverhead + entry.size();
  }

  QuicByteCount total_length =
      GetTotalLength(payload_length, HttpFrameType::ORIGIN);

  std::string frame;
  frame.resize(total_length);
  QuicDataWriter writer(total_length, frame.data());

  if (!WriteFrameHeader(payload_length, HttpFrameType::ORIGIN, &writer)) {
    QUIC_DLOG(ERROR) << "Http encoder failed to serialize ORIGIN frame header.";
    return {};
  }

  for (const std::string& entry : origin.origins) {
    if (!writer.WriteStringPiece16(entry)) {
      QUIC_DLOG(ERROR)
          << "Http encoder failed to serialize ACCEPT_CH frame payload.";
      return {};
    }
  }

  return frame;
}

std::string HttpEncoder::SerializeGreasingFrame() {
  uint64_t frame_type;
  QuicByteCount payload_length;
  std::string payload;
  if (!GetQuicFlag(quic_enable_http3_grease_randomness)) {
    frame_type = 0x40;
    payload_length = 1;
    payload = "a";
  } else {
    uint32_t result;
    QuicRandom::GetInstance()->RandBytes(&result, sizeof(result));
    frame_type = 0x1fULL * static_cast<uint64_t>(result) + 0x21ULL;

    // The payload length is random but within [0, 3];
    payload_length = result % 4;

    if (payload_length > 0) {
      payload.resize(payload_length);
      QuicRandom::GetInstance()->RandBytes(payload.data(), payload_length);
    }
  }
  QuicByteCount total_length = QuicDataWriter::GetVarInt62Len(frame_type) +
                               QuicDataWriter::GetVarInt62Len(payload_length) +
                               payload_length;

  std::string frame;
  frame.resize(total_length);
  QuicDataWriter writer(total_length, frame.data());

  bool success =
      writer.WriteVarInt62(frame_type) && writer.WriteVarInt62(payload_length);

  if (payload_length > 0) {
    success &= writer.WriteBytes(payload.data(), payload_length);
  }

  if (success) {
    return frame;
  }

  QUIC_DLOG(ERROR) << "Http encoder failed when attempting to serialize "
                      "greasing frame.";
  return {};
}

std::string HttpEncoder::SerializeWebTransportStreamFrameHeader(
    WebTransportSessionId session_id) {
  uint64_t stream_type =
      static_cast<uint64_t>(HttpFrameType::WEBTRANSPORT_STREAM);
  QuicByteCount header_length = QuicDataWriter::GetVarInt62Len(stream_type) +
                                QuicDataWriter::GetVarInt62Len(session_id);

  std::string frame;
  frame.resize(header_length);
  QuicDataWriter writer(header_length, frame.data());

  bool success =
      writer.WriteVarInt62(stream_type) && writer.WriteVarInt62(session_id);
  if (success && writer.remaining() == 0) {
    return frame;
  }

  QUIC_DLOG(ERROR) << "Http encoder failed when attempting to serialize "
                      "WEBTRANSPORT_STREAM frame header.";
  return {};
}

std::string HttpEncoder::SerializeMetadataFrameHeader(
    QuicByteCount payload_length) {
  QUICHE_DCHECK_NE(0u, payload_length);
  QuicByteCount header_length =
      QuicDataWriter::GetVarInt62Len(payload_length) +
      QuicDataWriter::GetVarInt62Len(
          static_cast<uint64_t>(HttpFrameType::METADATA));

  std::string frame;
  frame.resize(header_length);
  QuicDataWriter writer(header_length, frame.data());

  if (WriteFrameHeader(payload_length, HttpFrameType::METADATA, &writer)) {
    return frame;
  }
  QUIC_DLOG(ERROR)
      << "Http encoder failed when attempting to serialize METADATA "
         "frame header.";
  return {};
}

}  // namespace quic
```