Response:
The user wants to understand the functionality of the `spdy_framer.cc` file in Chromium's network stack. They are particularly interested in its relationship with JavaScript, logical reasoning with input/output examples, common usage errors, debugging context, and a summary of its functionality as the first part of a two-part explanation.

Here's a breakdown of how to approach this:

1. **Core Functionality:** Identify the main purpose of `spdy_framer.cc`. It's responsible for serializing Spdy frame data into a byte stream for network transmission.

2. **Relationship with JavaScript:**  Consider how the network stack interacts with the browser's JavaScript engine. While `spdy_framer.cc` doesn't directly execute JavaScript, it plays a role in how data is fetched and delivered to the JavaScript context.

3. **Logical Reasoning (Input/Output):**  Think about a specific frame type, like `HEADERS`. Illustrate how the input (a `SpdyHeadersIR` object) is transformed into output (a serialized byte stream).

4. **Common Usage Errors:** Focus on potential mistakes developers might make when using the Spdy framing mechanisms, particularly regarding frame construction and data integrity.

5. **User Operation and Debugging:** Trace a typical user interaction (e.g., loading a webpage) and how it leads to the execution of code in `spdy_framer.cc`. Explain how this information aids in debugging.

6. **Part 1 Summary:** Concisely summarize the identified functionalities.

**Mental Sandbox Simulation:**

* **Scenario 1: JavaScript `fetch()` request:** A JavaScript `fetch()` call initiates an HTTP/2 request. The browser needs to construct the necessary HTTP/2 frames. `spdy_framer.cc` will be involved in creating the `HEADERS` frame containing request headers.

* **Scenario 2:  Server push:** A server wants to push resources to the client. `spdy_framer.cc` will handle the serialization of `PUSH_PROMISE` and subsequent `HEADERS` and `DATA` frames for the pushed resource.

* **Error scenario:**  A developer might incorrectly set the padding length in a `DATA` frame, which could be detected by the receiver.

* **Debugging scenario:** When troubleshooting network issues, looking at the serialized frames can reveal problems with header compression, frame sizes, or flag settings.

By considering these scenarios, I can formulate the response.
好的，让我们来分析一下 `net/third_party/quiche/src/quiche/http2/core/spdy_framer.cc` 这个文件的功能。

**文件功能归纳:**

`spdy_framer.cc` 文件的主要功能是负责将 HTTP/2 协议中的各种帧 (frames)  **序列化 (serialization)** 成可以发送到网络上的字节流，以及提供创建这些帧序列的迭代器。  简单来说，它将程序内部表示的 HTTP/2 帧结构转换为网络传输所需的二进制格式。

**具体功能点:**

1. **帧的序列化:**  该文件包含了将各种类型的 Spdy 帧（例如 HEADERS, DATA, RST_STREAM, SETTINGS, PING, GOAWAY, WINDOW_UPDATE, PUSH_PROMISE, CONTINUATION, ALTSVC, PRIORITY, PRIORITY_UPDATE, ACCEPT_CH, UNKNOWN）序列化成字节流的具体实现。  每个 `Serialize...` 函数对应一个帧类型，负责根据帧的结构和数据填充 `SpdyFrameBuilder`，最终生成 `SpdySerializedFrame` 对象。

2. **帧构建辅助类:** 使用 `SpdyFrameBuilder` 类来简化帧的构建过程，它提供了写入不同类型数据的便捷方法 (例如 `WriteUInt8`, `WriteUInt32`, `WriteBytes`)。

3. **HPACK 集成:**  该文件与 HPACK 编码器 (`hpack::HpackEncoder`) 集成，用于压缩和解压缩 HTTP 头部字段。在序列化 HEADERS 和 PUSH_PROMISE 帧时，会调用 HPACK 编码器将头部块 (header block) 编码成字节流。

4. **分片处理 (CONTINUATION 帧):**  对于头部块过大的情况，该文件能够将 HEADERS 或 PUSH_PROMISE 帧的数据分片到多个 CONTINUATION 帧中进行发送，确保单个帧的大小不超过限制。

5. **帧迭代器:**  提供了 `SpdyFrameIterator` 及其子类 (`SpdyHeaderFrameIterator`, `SpdyPushPromiseFrameIterator`, `SpdyControlFrameIterator`)，用于将需要分片发送的帧（例如包含大型头部块的 HEADERS 或 PUSH_PROMISE 帧）分解成一个帧序列，每个序列元素对应一个可以发送的网络包。

6. **调试支持:**  通过 `SpdyFramerDebugVisitorInterface` 接口提供调试支持，允许在帧序列化时进行监控和记录，例如记录压缩前后的头部大小。

7. **辅助函数:**  包含一些辅助函数，例如 `PackStreamDependencyValues` 用于打包流依赖信息，`SerializeHeaderFrameFlags` 和 `SerializePushPromiseFrameFlags` 用于设置帧的标志位。

**与 JavaScript 的关系及举例:**

虽然 `spdy_framer.cc` 是 C++ 代码，但它在浏览器网络栈中扮演着关键角色，直接影响到 JavaScript 中网络请求的行为。

**举例说明:**

假设 JavaScript 代码发起一个 `fetch()` 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

当执行这个 `fetch()` 请求时，浏览器网络栈会进行以下操作，其中 `spdy_framer.cc` 会参与到帧的构建过程中：

1. **JavaScript 发起请求:** JavaScript 的 `fetch()` API 被调用。
2. **构建 HTTP 请求:**  浏览器内核会根据请求信息（URL, 方法, 头部等）构建一个 HTTP 请求。
3. **创建 HEADERS 帧:**  `spdy_framer.cc` 中的 `SerializeHeaders` 函数会被调用，根据 HTTP 请求的头部信息创建一个 `SpdyHeadersIR` 对象，并使用 HPACK 编码器将其头部块压缩，然后将 `SpdyHeadersIR` 对象序列化成一个或多个 HEADERS 帧（如果头部过大，可能还会生成 CONTINUATION 帧）。
    * **假设输入 (SpdyHeadersIR):**  包含请求方法 (GET), URL (/data), Host (example.com), User-Agent 等头部信息的 `SpdyHeadersIR` 对象。
    * **假设输出 (Serialized HEADERS frame):**  一个包含帧头和 HPACK 编码后的头部数据的字节流。
4. **发送网络数据:** 序列化后的帧数据通过网络发送到服务器。
5. **接收 HTTP 响应:** 服务器返回 HTTP 响应数据，网络栈会接收这些数据。
6. **解析 HTTP 响应帧:** 网络栈会解析接收到的 HTTP/2 帧，例如 HEADERS 帧（包含响应头部）和 DATA 帧（包含响应体）。
7. **传递响应到 JavaScript:**  解析后的响应头部和数据最终会传递回 JavaScript 的 `fetch()` API，触发 `.then()` 回调。

**用户或编程常见的使用错误及举例:**

虽然用户通常不直接操作 `spdy_framer.cc` 的代码，但在编程或者配置网络服务时，一些错误可能会间接导致与 `spdy_framer.cc` 相关的行为异常。

**举例说明:**

1. **不正确的头部信息:**  如果后端服务或代理配置不当，导致发送的 HTTP 头部信息不符合 HTTP/2 的规范（例如包含 HTTP/1.x 特有的头部），`spdy_framer.cc` 在序列化这些头部时可能会遇到问题，或者生成的帧可能不被对端正确解析。
    * **错误场景:** 后端服务错误地发送了 `Connection: keep-alive` 头部，而 HTTP/2 不使用该头部。
    * **可能的影响:**  连接可能被错误地关闭，导致请求失败。

2. **帧大小超出限制:**  如果程序尝试构建一个超过 HTTP/2 帧大小限制的帧（例如非常大的头部块，且未正确处理分片），`spdy_framer.cc` 在序列化时可能会报错或者生成不合法的帧。
    * **错误场景:**  尝试发送包含大量 Cookie 的请求，导致头部块过大。
    * **可能的影响:**  连接可能被关闭，或者请求被拒绝。

**用户操作如何一步步到达这里 (调试线索):**

作为调试线索，理解用户操作如何触发 `spdy_framer.cc` 的执行至关重要。

1. **用户在浏览器中输入 URL 并访问一个 HTTPS 网站。**
2. **浏览器发起连接:** 浏览器会尝试与服务器建立 TLS 连接。
3. **协议协商:** 在 TLS 握手过程中，通过 ALPN (Application-Layer Protocol Negotiation) 协商使用 HTTP/2 协议。
4. **发送 HTTP 请求:** 当需要发送 HTTP 请求时（例如加载网页资源），浏览器网络栈会构建 HTTP/2 帧。
5. **`spdy_framer.cc` 的调用:**  在构建帧的过程中，例如创建包含请求头部的 HEADERS 帧，会调用 `spdy_framer.cc` 中的 `SerializeHeaders` 函数。
6. **帧数据发送:** `spdy_framer.cc` 将 `SpdyHeadersIR` 对象序列化为字节流，并通过底层的网络 socket 发送出去。
7. **接收和发送其他帧:**  后续的数据传输、控制流管理等都会涉及到 `spdy_framer.cc` 对各种帧的序列化和反序列化 (尽管反序列化不在本文件中)。

**调试线索:**

* **网络抓包:** 使用 Wireshark 等工具抓取网络包，可以观察到由 `spdy_framer.cc` 生成的实际 HTTP/2 帧的二进制数据，从而分析帧的类型、标志位、头部内容等。
* **Chromium NetLog:** Chromium 提供了 NetLog 功能，可以记录网络栈的详细事件，包括 HTTP/2 帧的发送和接收，可以查看 `spdy_framer.cc` 在何时被调用以及序列化的帧内容。
* **代码断点:**  在 Chromium 源码中设置断点，可以跟踪 `spdy_framer.cc` 中帧序列化的过程，查看变量的值，了解帧是如何构建的。

**总结 Part 1 的功能:**

`net/third_party/quiche/src/quiche/http2/core/spdy_framer.cc` 的核心功能是 **将 HTTP/2 协议的各种帧结构转换为可以在网络上传输的二进制字节流**。它负责帧的序列化，集成了 HPACK 压缩，处理帧分片，并为上层网络栈提供创建帧序列的接口。虽然 JavaScript 不直接调用该文件，但其网络请求过程依赖于 `spdy_framer.cc` 生成符合 HTTP/2 协议的帧数据。理解该文件的功能对于调试 HTTP/2 相关的网络问题至关重要。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/core/spdy_framer.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/http2/core/spdy_framer.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/memory/memory.h"
#include "quiche/http2/core/spdy_alt_svc_wire_format.h"
#include "quiche/http2/core/spdy_frame_builder.h"
#include "quiche/http2/core/spdy_protocol.h"
#include "quiche/http2/core/zero_copy_output_buffer.h"
#include "quiche/http2/hpack/hpack_constants.h"
#include "quiche/http2/hpack/hpack_encoder.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace spdy {

namespace {

// Pack parent stream ID and exclusive flag into the format used by HTTP/2
// headers and priority frames.
uint32_t PackStreamDependencyValues(bool exclusive,
                                    SpdyStreamId parent_stream_id) {
  // Make sure the highest-order bit in the parent stream id is zeroed out.
  uint32_t parent = parent_stream_id & 0x7fffffff;
  // Set the one-bit exclusivity flag.
  uint32_t e_bit = exclusive ? 0x80000000 : 0;
  return parent | e_bit;
}

// Used to indicate no flags in a HTTP2 flags field.
const uint8_t kNoFlags = 0;

// Wire size of pad length field.
const size_t kPadLengthFieldSize = 1;

// The size of one parameter in SETTINGS frame.
const size_t kOneSettingParameterSize = 6;

size_t GetUncompressedSerializedLength(const quiche::HttpHeaderBlock& headers) {
  const size_t num_name_value_pairs_size = sizeof(uint32_t);
  const size_t length_of_name_size = num_name_value_pairs_size;
  const size_t length_of_value_size = num_name_value_pairs_size;

  size_t total_length = num_name_value_pairs_size;
  for (const auto& header : headers) {
    // We add space for the length of the name and the length of the value as
    // well as the length of the name and the length of the value.
    total_length += length_of_name_size + header.first.size() +
                    length_of_value_size + header.second.size();
  }
  return total_length;
}

// Serializes the flags octet for a given SpdyHeadersIR.
uint8_t SerializeHeaderFrameFlags(const SpdyHeadersIR& header_ir,
                                  const bool end_headers) {
  uint8_t flags = 0;
  if (header_ir.fin()) {
    flags |= CONTROL_FLAG_FIN;
  }
  if (end_headers) {
    flags |= HEADERS_FLAG_END_HEADERS;
  }
  if (header_ir.padded()) {
    flags |= HEADERS_FLAG_PADDED;
  }
  if (header_ir.has_priority()) {
    flags |= HEADERS_FLAG_PRIORITY;
  }
  return flags;
}

// Serializes the flags octet for a given SpdyPushPromiseIR.
uint8_t SerializePushPromiseFrameFlags(const SpdyPushPromiseIR& push_promise_ir,
                                       const bool end_headers) {
  uint8_t flags = 0;
  if (push_promise_ir.padded()) {
    flags = flags | PUSH_PROMISE_FLAG_PADDED;
  }
  if (end_headers) {
    flags |= PUSH_PROMISE_FLAG_END_PUSH_PROMISE;
  }
  return flags;
}

// Serializes a HEADERS frame from the given SpdyHeadersIR and encoded header
// block. Does not need or use the quiche::HttpHeaderBlock inside SpdyHeadersIR.
// Return false if the serialization fails. |encoding| should not be empty.
bool SerializeHeadersGivenEncoding(const SpdyHeadersIR& headers,
                                   const std::string& encoding,
                                   const bool end_headers,
                                   ZeroCopyOutputBuffer* output) {
  const size_t frame_size =
      GetHeaderFrameSizeSansBlock(headers) + encoding.size();
  SpdyFrameBuilder builder(frame_size, output);
  bool ret = builder.BeginNewFrame(
      SpdyFrameType::HEADERS, SerializeHeaderFrameFlags(headers, end_headers),
      headers.stream_id(), frame_size - kFrameHeaderSize);
  QUICHE_DCHECK_EQ(kFrameHeaderSize, builder.length());

  if (ret && headers.padded()) {
    ret &= builder.WriteUInt8(headers.padding_payload_len());
  }

  if (ret && headers.has_priority()) {
    int weight = ClampHttp2Weight(headers.weight());
    ret &= builder.WriteUInt32(PackStreamDependencyValues(
        headers.exclusive(), headers.parent_stream_id()));
    // Per RFC 7540 section 6.3, serialized weight value is actual value - 1.
    ret &= builder.WriteUInt8(weight - 1);
  }

  if (ret) {
    ret &= builder.WriteBytes(encoding.data(), encoding.size());
  }

  if (ret && headers.padding_payload_len() > 0) {
    std::string padding(headers.padding_payload_len(), 0);
    ret &= builder.WriteBytes(padding.data(), padding.length());
  }

  if (!ret) {
    QUICHE_DLOG(WARNING)
        << "Failed to build HEADERS. Not enough space in output";
  }
  return ret;
}

// Serializes a PUSH_PROMISE frame from the given SpdyPushPromiseIR and
// encoded header block. Does not need or use the quiche::HttpHeaderBlock inside
// SpdyPushPromiseIR.
bool SerializePushPromiseGivenEncoding(const SpdyPushPromiseIR& push_promise,
                                       const std::string& encoding,
                                       const bool end_headers,
                                       ZeroCopyOutputBuffer* output) {
  const size_t frame_size =
      GetPushPromiseFrameSizeSansBlock(push_promise) + encoding.size();
  SpdyFrameBuilder builder(frame_size, output);
  bool ok = builder.BeginNewFrame(
      SpdyFrameType::PUSH_PROMISE,
      SerializePushPromiseFrameFlags(push_promise, end_headers),
      push_promise.stream_id(), frame_size - kFrameHeaderSize);

  if (push_promise.padded()) {
    ok = ok && builder.WriteUInt8(push_promise.padding_payload_len());
  }
  ok = ok && builder.WriteUInt32(push_promise.promised_stream_id()) &&
       builder.WriteBytes(encoding.data(), encoding.size());
  if (ok && push_promise.padding_payload_len() > 0) {
    std::string padding(push_promise.padding_payload_len(), 0);
    ok = builder.WriteBytes(padding.data(), padding.length());
  }

  QUICHE_DLOG_IF(ERROR, !ok)
      << "Failed to write PUSH_PROMISE encoding, not enough "
      << "space in output";
  return ok;
}

bool WritePayloadWithContinuation(SpdyFrameBuilder* builder,
                                  const std::string& hpack_encoding,
                                  SpdyStreamId stream_id, SpdyFrameType type,
                                  int padding_payload_len) {
  uint8_t end_flag = 0;
  uint8_t flags = 0;
  if (type == SpdyFrameType::HEADERS) {
    end_flag = HEADERS_FLAG_END_HEADERS;
  } else if (type == SpdyFrameType::PUSH_PROMISE) {
    end_flag = PUSH_PROMISE_FLAG_END_PUSH_PROMISE;
  } else {
    QUICHE_DLOG(FATAL) << "CONTINUATION frames cannot be used with frame type "
                       << FrameTypeToString(type);
  }

  // Write all the padding payload and as much of the data payload as possible
  // into the initial frame.
  size_t bytes_remaining = 0;
  bytes_remaining = hpack_encoding.size() -
                    std::min(hpack_encoding.size(),
                             kHttp2MaxControlFrameSendSize - builder->length() -
                                 padding_payload_len);
  bool ret = builder->WriteBytes(&hpack_encoding[0],
                                 hpack_encoding.size() - bytes_remaining);
  if (padding_payload_len > 0) {
    std::string padding = std::string(padding_payload_len, 0);
    ret &= builder->WriteBytes(padding.data(), padding.length());
  }

  // Tack on CONTINUATION frames for the overflow.
  while (bytes_remaining > 0 && ret) {
    size_t bytes_to_write =
        std::min(bytes_remaining,
                 kHttp2MaxControlFrameSendSize - kContinuationFrameMinimumSize);
    // Write CONTINUATION frame prefix.
    if (bytes_remaining == bytes_to_write) {
      flags |= end_flag;
    }
    ret &= builder->BeginNewFrame(SpdyFrameType::CONTINUATION, flags, stream_id,
                                  bytes_to_write);
    // Write payload fragment.
    ret &= builder->WriteBytes(
        &hpack_encoding[hpack_encoding.size() - bytes_remaining],
        bytes_to_write);
    bytes_remaining -= bytes_to_write;
  }
  return ret;
}

void SerializeDataBuilderHelper(const SpdyDataIR& data_ir, uint8_t* flags,
                                int* num_padding_fields,
                                size_t* size_with_padding) {
  if (data_ir.fin()) {
    *flags = DATA_FLAG_FIN;
  }

  if (data_ir.padded()) {
    *flags = *flags | DATA_FLAG_PADDED;
    ++*num_padding_fields;
  }

  *size_with_padding = *num_padding_fields + data_ir.data_len() +
                       data_ir.padding_payload_len() + kDataFrameMinimumSize;
}

void SerializeDataFrameHeaderWithPaddingLengthFieldBuilderHelper(
    const SpdyDataIR& data_ir, uint8_t* flags, size_t* frame_size,
    size_t* num_padding_fields) {
  *flags = DATA_FLAG_NONE;
  if (data_ir.fin()) {
    *flags = DATA_FLAG_FIN;
  }

  *frame_size = kDataFrameMinimumSize;
  if (data_ir.padded()) {
    *flags = *flags | DATA_FLAG_PADDED;
    ++(*num_padding_fields);
    *frame_size = *frame_size + *num_padding_fields;
  }
}

void SerializeSettingsBuilderHelper(const SpdySettingsIR& settings,
                                    uint8_t* flags, const SettingsMap* values,
                                    size_t* size) {
  if (settings.is_ack()) {
    *flags = *flags | SETTINGS_FLAG_ACK;
  }
  *size =
      kSettingsFrameMinimumSize + (values->size() * kOneSettingParameterSize);
}

void SerializeAltSvcBuilderHelper(const SpdyAltSvcIR& altsvc_ir,
                                  std::string* value, size_t* size) {
  *size = kGetAltSvcFrameMinimumSize;
  *size = *size + altsvc_ir.origin().length();
  *value = SpdyAltSvcWireFormat::SerializeHeaderFieldValue(
      altsvc_ir.altsvc_vector());
  *size = *size + value->length();
}

}  // namespace

SpdyFramer::SpdyFramer(CompressionOption option)
    : debug_visitor_(nullptr), compression_option_(option) {
  static_assert(kHttp2MaxControlFrameSendSize <= kHttp2DefaultFrameSizeLimit,
                "Our send limit should be at most our receive limit.");
}

SpdyFramer::~SpdyFramer() = default;

void SpdyFramer::set_debug_visitor(
    SpdyFramerDebugVisitorInterface* debug_visitor) {
  debug_visitor_ = debug_visitor;
}

SpdyFramer::SpdyFrameIterator::SpdyFrameIterator(SpdyFramer* framer)
    : framer_(framer), is_first_frame_(true), has_next_frame_(true) {}

SpdyFramer::SpdyFrameIterator::~SpdyFrameIterator() = default;

size_t SpdyFramer::SpdyFrameIterator::NextFrame(ZeroCopyOutputBuffer* output) {
  const SpdyFrameIR* frame_ir = GetIR();
  if (!has_next_frame_ || frame_ir == nullptr) {
    QUICHE_BUG(spdy_bug_75_1)
        << "SpdyFramer::SpdyFrameIterator::NextFrame called without "
        << "a next frame.";
    return false;
  }

  const size_t size_without_block =
      is_first_frame_ ? GetFrameSizeSansBlock() : kContinuationFrameMinimumSize;
  std::string encoding =
      encoder_->Next(kHttp2MaxControlFrameSendSize - size_without_block);
  has_next_frame_ = encoder_->HasNext();

  if (framer_->debug_visitor_ != nullptr) {
    const auto& frame_ref =
        static_cast<const SpdyFrameWithHeaderBlockIR&>(*frame_ir);
    const size_t header_list_size =
        GetUncompressedSerializedLength(frame_ref.header_block());
    framer_->debug_visitor_->OnSendCompressedFrame(
        frame_ref.stream_id(),
        is_first_frame_ ? frame_ref.frame_type() : SpdyFrameType::CONTINUATION,
        header_list_size, size_without_block + encoding.size());
  }

  const size_t free_bytes_before = output->BytesFree();
  bool ok = false;
  if (is_first_frame_) {
    is_first_frame_ = false;
    ok = SerializeGivenEncoding(encoding, output);
  } else {
    SpdyContinuationIR continuation_ir(frame_ir->stream_id());
    continuation_ir.take_encoding(std::move(encoding));
    continuation_ir.set_end_headers(!has_next_frame_);
    ok = framer_->SerializeContinuation(continuation_ir, output);
  }
  return ok ? free_bytes_before - output->BytesFree() : 0;
}

bool SpdyFramer::SpdyFrameIterator::HasNextFrame() const {
  return has_next_frame_;
}

SpdyFramer::SpdyHeaderFrameIterator::SpdyHeaderFrameIterator(
    SpdyFramer* framer, std::unique_ptr<const SpdyHeadersIR> headers_ir)
    : SpdyFrameIterator(framer), headers_ir_(std::move(headers_ir)) {
  SetEncoder(headers_ir_.get());
}

SpdyFramer::SpdyHeaderFrameIterator::~SpdyHeaderFrameIterator() = default;

const SpdyFrameIR* SpdyFramer::SpdyHeaderFrameIterator::GetIR() const {
  return headers_ir_.get();
}

size_t SpdyFramer::SpdyHeaderFrameIterator::GetFrameSizeSansBlock() const {
  return GetHeaderFrameSizeSansBlock(*headers_ir_);
}

bool SpdyFramer::SpdyHeaderFrameIterator::SerializeGivenEncoding(
    const std::string& encoding, ZeroCopyOutputBuffer* output) const {
  return SerializeHeadersGivenEncoding(*headers_ir_, encoding,
                                       !has_next_frame(), output);
}

SpdyFramer::SpdyPushPromiseFrameIterator::SpdyPushPromiseFrameIterator(
    SpdyFramer* framer,
    std::unique_ptr<const SpdyPushPromiseIR> push_promise_ir)
    : SpdyFrameIterator(framer), push_promise_ir_(std::move(push_promise_ir)) {
  SetEncoder(push_promise_ir_.get());
}

SpdyFramer::SpdyPushPromiseFrameIterator::~SpdyPushPromiseFrameIterator() =
    default;

const SpdyFrameIR* SpdyFramer::SpdyPushPromiseFrameIterator::GetIR() const {
  return push_promise_ir_.get();
}

size_t SpdyFramer::SpdyPushPromiseFrameIterator::GetFrameSizeSansBlock() const {
  return GetPushPromiseFrameSizeSansBlock(*push_promise_ir_);
}

bool SpdyFramer::SpdyPushPromiseFrameIterator::SerializeGivenEncoding(
    const std::string& encoding, ZeroCopyOutputBuffer* output) const {
  return SerializePushPromiseGivenEncoding(*push_promise_ir_, encoding,
                                           !has_next_frame(), output);
}

SpdyFramer::SpdyControlFrameIterator::SpdyControlFrameIterator(
    SpdyFramer* framer, std::unique_ptr<const SpdyFrameIR> frame_ir)
    : framer_(framer), frame_ir_(std::move(frame_ir)) {}

SpdyFramer::SpdyControlFrameIterator::~SpdyControlFrameIterator() = default;

size_t SpdyFramer::SpdyControlFrameIterator::NextFrame(
    ZeroCopyOutputBuffer* output) {
  size_t size_written = framer_->SerializeFrame(*frame_ir_, output);
  has_next_frame_ = false;
  return size_written;
}

bool SpdyFramer::SpdyControlFrameIterator::HasNextFrame() const {
  return has_next_frame_;
}

const SpdyFrameIR* SpdyFramer::SpdyControlFrameIterator::GetIR() const {
  return frame_ir_.get();
}

std::unique_ptr<SpdyFrameSequence> SpdyFramer::CreateIterator(
    SpdyFramer* framer, std::unique_ptr<const SpdyFrameIR> frame_ir) {
  switch (frame_ir->frame_type()) {
    case SpdyFrameType::HEADERS: {
      return std::make_unique<SpdyHeaderFrameIterator>(
          framer, absl::WrapUnique(
                      static_cast<const SpdyHeadersIR*>(frame_ir.release())));
    }
    case SpdyFrameType::PUSH_PROMISE: {
      return std::make_unique<SpdyPushPromiseFrameIterator>(
          framer, absl::WrapUnique(static_cast<const SpdyPushPromiseIR*>(
                      frame_ir.release())));
    }
    case SpdyFrameType::DATA: {
      QUICHE_DVLOG(1) << "Serialize a stream end DATA frame for VTL";
      ABSL_FALLTHROUGH_INTENDED;
    }
    default: {
      return std::make_unique<SpdyControlFrameIterator>(framer,
                                                        std::move(frame_ir));
    }
  }
}

SpdySerializedFrame SpdyFramer::SerializeData(const SpdyDataIR& data_ir) {
  uint8_t flags = DATA_FLAG_NONE;
  int num_padding_fields = 0;
  size_t size_with_padding = 0;
  SerializeDataBuilderHelper(data_ir, &flags, &num_padding_fields,
                             &size_with_padding);

  SpdyFrameBuilder builder(size_with_padding);
  builder.BeginNewFrame(SpdyFrameType::DATA, flags, data_ir.stream_id());
  if (data_ir.padded()) {
    builder.WriteUInt8(data_ir.padding_payload_len() & 0xff);
  }
  builder.WriteBytes(data_ir.data(), data_ir.data_len());
  if (data_ir.padding_payload_len() > 0) {
    std::string padding(data_ir.padding_payload_len(), 0);
    builder.WriteBytes(padding.data(), padding.length());
  }
  QUICHE_DCHECK_EQ(size_with_padding, builder.length());
  return builder.take();
}

SpdySerializedFrame SpdyFramer::SerializeDataFrameHeaderWithPaddingLengthField(
    const SpdyDataIR& data_ir) {
  uint8_t flags = DATA_FLAG_NONE;
  size_t frame_size = 0;
  size_t num_padding_fields = 0;
  SerializeDataFrameHeaderWithPaddingLengthFieldBuilderHelper(
      data_ir, &flags, &frame_size, &num_padding_fields);

  SpdyFrameBuilder builder(frame_size);
  builder.BeginNewFrame(
      SpdyFrameType::DATA, flags, data_ir.stream_id(),
      num_padding_fields + data_ir.data_len() + data_ir.padding_payload_len());
  if (data_ir.padded()) {
    builder.WriteUInt8(data_ir.padding_payload_len() & 0xff);
  }
  QUICHE_DCHECK_EQ(frame_size, builder.length());
  return builder.take();
}

SpdySerializedFrame SpdyFramer::SerializeRstStream(
    const SpdyRstStreamIR& rst_stream) const {
  size_t expected_length = kRstStreamFrameSize;
  SpdyFrameBuilder builder(expected_length);

  builder.BeginNewFrame(SpdyFrameType::RST_STREAM, 0, rst_stream.stream_id());

  builder.WriteUInt32(rst_stream.error_code());

  QUICHE_DCHECK_EQ(expected_length, builder.length());
  return builder.take();
}

SpdySerializedFrame SpdyFramer::SerializeSettings(
    const SpdySettingsIR& settings) const {
  uint8_t flags = 0;
  // Size, in bytes, of this SETTINGS frame.
  size_t size = 0;
  const SettingsMap* values = &(settings.values());
  SerializeSettingsBuilderHelper(settings, &flags, values, &size);
  SpdyFrameBuilder builder(size);
  builder.BeginNewFrame(SpdyFrameType::SETTINGS, flags, 0);

  // If this is an ACK, payload should be empty.
  if (settings.is_ack()) {
    return builder.take();
  }

  QUICHE_DCHECK_EQ(kSettingsFrameMinimumSize, builder.length());
  for (auto it = values->begin(); it != values->end(); ++it) {
    int setting_id = it->first;
    QUICHE_DCHECK_GE(setting_id, 0);
    builder.WriteUInt16(static_cast<SpdySettingsId>(setting_id));
    builder.WriteUInt32(it->second);
  }
  QUICHE_DCHECK_EQ(size, builder.length());
  return builder.take();
}

SpdySerializedFrame SpdyFramer::SerializePing(const SpdyPingIR& ping) const {
  SpdyFrameBuilder builder(kPingFrameSize);
  uint8_t flags = 0;
  if (ping.is_ack()) {
    flags |= PING_FLAG_ACK;
  }
  builder.BeginNewFrame(SpdyFrameType::PING, flags, 0);
  builder.WriteUInt64(ping.id());
  QUICHE_DCHECK_EQ(kPingFrameSize, builder.length());
  return builder.take();
}

SpdySerializedFrame SpdyFramer::SerializeGoAway(
    const SpdyGoAwayIR& goaway) const {
  // Compute the output buffer size, take opaque data into account.
  size_t expected_length = kGoawayFrameMinimumSize;
  expected_length += goaway.description().size();
  SpdyFrameBuilder builder(expected_length);

  // Serialize the GOAWAY frame.
  builder.BeginNewFrame(SpdyFrameType::GOAWAY, 0, 0);

  // GOAWAY frames specify the last good stream id.
  builder.WriteUInt32(goaway.last_good_stream_id());

  // GOAWAY frames also specify the error code.
  builder.WriteUInt32(goaway.error_code());

  // GOAWAY frames may also specify opaque data.
  if (!goaway.description().empty()) {
    builder.WriteBytes(goaway.description().data(),
                       goaway.description().size());
  }

  QUICHE_DCHECK_EQ(expected_length, builder.length());
  return builder.take();
}

void SpdyFramer::SerializeHeadersBuilderHelper(const SpdyHeadersIR& headers,
                                               uint8_t* flags, size_t* size,
                                               std::string* hpack_encoding,
                                               int* weight,
                                               size_t* length_field) {
  if (headers.fin()) {
    *flags = *flags | CONTROL_FLAG_FIN;
  }
  // This will get overwritten if we overflow into a CONTINUATION frame.
  *flags = *flags | HEADERS_FLAG_END_HEADERS;
  if (headers.has_priority()) {
    *flags = *flags | HEADERS_FLAG_PRIORITY;
  }
  if (headers.padded()) {
    *flags = *flags | HEADERS_FLAG_PADDED;
  }

  *size = kHeadersFrameMinimumSize;

  if (headers.padded()) {
    *size = *size + kPadLengthFieldSize;
    *size = *size + headers.padding_payload_len();
  }

  if (headers.has_priority()) {
    *weight = ClampHttp2Weight(headers.weight());
    *size = *size + 5;
  }

  *hpack_encoding =
      GetHpackEncoder()->EncodeHeaderBlock(headers.header_block());
  *size = *size + hpack_encoding->size();
  if (*size > kHttp2MaxControlFrameSendSize) {
    *size = *size + GetNumberRequiredContinuationFrames(*size) *
                        kContinuationFrameMinimumSize;
    *flags = *flags & ~HEADERS_FLAG_END_HEADERS;
  }
  // Compute frame length field.
  if (headers.padded()) {
    *length_field = *length_field + kPadLengthFieldSize;
  }
  if (headers.has_priority()) {
    *length_field = *length_field + 4;  // Dependency field.
    *length_field = *length_field + 1;  // Weight field.
  }
  *length_field = *length_field + headers.padding_payload_len();
  *length_field = *length_field + hpack_encoding->size();
  // If the HEADERS frame with payload would exceed the max frame size, then
  // WritePayloadWithContinuation() will serialize CONTINUATION frames as
  // necessary.
  *length_field =
      std::min(*length_field, kHttp2MaxControlFrameSendSize - kFrameHeaderSize);
}

SpdySerializedFrame SpdyFramer::SerializeHeaders(const SpdyHeadersIR& headers) {
  uint8_t flags = 0;
  // The size of this frame, including padding (if there is any) and
  // variable-length header block.
  size_t size = 0;
  std::string hpack_encoding;
  int weight = 0;
  size_t length_field = 0;
  SerializeHeadersBuilderHelper(headers, &flags, &size, &hpack_encoding,
                                &weight, &length_field);

  SpdyFrameBuilder builder(size);
  builder.BeginNewFrame(SpdyFrameType::HEADERS, flags, headers.stream_id(),
                        length_field);

  QUICHE_DCHECK_EQ(kHeadersFrameMinimumSize, builder.length());

  int padding_payload_len = 0;
  if (headers.padded()) {
    builder.WriteUInt8(headers.padding_payload_len());
    padding_payload_len = headers.padding_payload_len();
  }
  if (headers.has_priority()) {
    builder.WriteUInt32(PackStreamDependencyValues(headers.exclusive(),
                                                   headers.parent_stream_id()));
    // Per RFC 7540 section 6.3, serialized weight value is actual value - 1.
    builder.WriteUInt8(weight - 1);
  }
  WritePayloadWithContinuation(&builder, hpack_encoding, headers.stream_id(),
                               SpdyFrameType::HEADERS, padding_payload_len);

  if (debug_visitor_) {
    const size_t header_list_size =
        GetUncompressedSerializedLength(headers.header_block());
    debug_visitor_->OnSendCompressedFrame(headers.stream_id(),
                                          SpdyFrameType::HEADERS,
                                          header_list_size, builder.length());
  }

  return builder.take();
}

SpdySerializedFrame SpdyFramer::SerializeWindowUpdate(
    const SpdyWindowUpdateIR& window_update) {
  SpdyFrameBuilder builder(kWindowUpdateFrameSize);
  builder.BeginNewFrame(SpdyFrameType::WINDOW_UPDATE, kNoFlags,
                        window_update.stream_id());
  builder.WriteUInt32(window_update.delta());
  QUICHE_DCHECK_EQ(kWindowUpdateFrameSize, builder.length());
  return builder.take();
}

void SpdyFramer::SerializePushPromiseBuilderHelper(
    const SpdyPushPromiseIR& push_promise, uint8_t* flags,
    std::string* hpack_encoding, size_t* size) {
  *flags = 0;
  // This will get overwritten if we overflow into a CONTINUATION frame.
  *flags = *flags | PUSH_PROMISE_FLAG_END_PUSH_PROMISE;
  // The size of this frame, including variable-length name-value block.
  *size = kPushPromiseFrameMinimumSize;

  if (push_promise.padded()) {
    *flags = *flags | PUSH_PROMISE_FLAG_PADDED;
    *size = *size + kPadLengthFieldSize;
    *size = *size + push_promise.padding_payload_len();
  }

  *hpack_encoding =
      GetHpackEncoder()->EncodeHeaderBlock(push_promise.header_block());
  *size = *size + hpack_encoding->size();
  if (*size > kHttp2MaxControlFrameSendSize) {
    *size = *size + GetNumberRequiredContinuationFrames(*size) *
                        kContinuationFrameMinimumSize;
    *flags = *flags & ~PUSH_PROMISE_FLAG_END_PUSH_PROMISE;
  }
}

SpdySerializedFrame SpdyFramer::SerializePushPromise(
    const SpdyPushPromiseIR& push_promise) {
  uint8_t flags = 0;
  size_t size = 0;
  std::string hpack_encoding;
  SerializePushPromiseBuilderHelper(push_promise, &flags, &hpack_encoding,
                                    &size);

  SpdyFrameBuilder builder(size);
  size_t length =
      std::min(size, kHttp2MaxControlFrameSendSize) - kFrameHeaderSize;
  builder.BeginNewFrame(SpdyFrameType::PUSH_PROMISE, flags,
                        push_promise.stream_id(), length);
  int padding_payload_len = 0;
  if (push_promise.padded()) {
    builder.WriteUInt8(push_promise.padding_payload_len());
    builder.WriteUInt32(push_promise.promised_stream_id());
    QUICHE_DCHECK_EQ(kPushPromiseFrameMinimumSize + kPadLengthFieldSize,
                     builder.length());

    padding_payload_len = push_promise.padding_payload_len();
  } else {
    builder.WriteUInt32(push_promise.promised_stream_id());
    QUICHE_DCHECK_EQ(kPushPromiseFrameMinimumSize, builder.length());
  }

  WritePayloadWithContinuation(
      &builder, hpack_encoding, push_promise.stream_id(),
      SpdyFrameType::PUSH_PROMISE, padding_payload_len);

  if (debug_visitor_) {
    const size_t header_list_size =
        GetUncompressedSerializedLength(push_promise.header_block());
    debug_visitor_->OnSendCompressedFrame(push_promise.stream_id(),
                                          SpdyFrameType::PUSH_PROMISE,
                                          header_list_size, builder.length());
  }

  return builder.take();
}

SpdySerializedFrame SpdyFramer::SerializeContinuation(
    const SpdyContinuationIR& continuation) const {
  const std::string& encoding = continuation.encoding();
  size_t frame_size = kContinuationFrameMinimumSize + encoding.size();
  SpdyFrameBuilder builder(frame_size);
  uint8_t flags = continuation.end_headers() ? HEADERS_FLAG_END_HEADERS : 0;
  builder.BeginNewFrame(SpdyFrameType::CONTINUATION, flags,
                        continuation.stream_id());
  QUICHE_DCHECK_EQ(kFrameHeaderSize, builder.length());

  builder.WriteBytes(encoding.data(), encoding.size());
  return builder.take();
}

SpdySerializedFrame SpdyFramer::SerializeAltSvc(const SpdyAltSvcIR& altsvc_ir) {
  std::string value;
  size_t size = 0;
  SerializeAltSvcBuilderHelper(altsvc_ir, &value, &size);
  SpdyFrameBuilder builder(size);
  builder.BeginNewFrame(SpdyFrameType::ALTSVC, kNoFlags, altsvc_ir.stream_id());

  builder.WriteUInt16(altsvc_ir.origin().length());
  builder.WriteBytes(altsvc_ir.origin().data(), altsvc_ir.origin().length());
  builder.WriteBytes(value.data(), value.length());
  QUICHE_DCHECK_LT(kGetAltSvcFrameMinimumSize, builder.length());
  return builder.take();
}

SpdySerializedFrame SpdyFramer::SerializePriority(
    const SpdyPriorityIR& priority) const {
  SpdyFrameBuilder builder(kPriorityFrameSize);
  builder.BeginNewFrame(SpdyFrameType::PRIORITY, kNoFlags,
                        priority.stream_id());

  builder.WriteUInt32(PackStreamDependencyValues(priority.exclusive(),
                                                 priority.parent_stream_id()));
  // Per RFC 7540 section 6.3, serialized weight value is actual value - 1.
  builder.WriteUInt8(priority.weight() - 1);
  QUICHE_DCHECK_EQ(kPriorityFrameSize, builder.length());
  return builder.take();
}

SpdySerializedFrame SpdyFramer::SerializePriorityUpdate(
    const SpdyPriorityUpdateIR& priority_update) const {
  const size_t total_size = kPriorityUpdateFrameMinimumSize +
                            priority_update.priority_field_value().size();
  SpdyFrameBuilder builder(total_size);
  builder.BeginNewFrame(SpdyFrameType::PRIORITY_UPDATE, kNoFlags,
                        priority_update.stream_id());

  builder.WriteUInt32(priority_update.prioritized_stream_id());
  builder.WriteBytes(priority_update.priority_field_value().data(),
                     priority_update.priority_field_value().size());
  QUICHE_DCHECK_EQ(total_size, builder.length());
  return builder.take();
}

SpdySerializedFrame SpdyFramer::SerializeAcceptCh(
    const SpdyAcceptChIR& accept_ch) const {
  const size_t total_size = accept_ch.size();
  SpdyFrameBuilder builder(total_size);
  builder.BeginNewFrame(SpdyFrameType::ACCEPT_CH, kNoFlags,
                        accept_ch.stream_id());

  for (const AcceptChOriginValuePair& entry : accept_ch.entries()) {
    builder.WriteUInt16(entry.origin.size());
    builder.WriteBytes(entry.origin.data(), entry.origin.size());
    builder.WriteUInt16(entry.value.size());
    builder.WriteBytes(entry.value.data(), entry.value.size());
  }

  QUICHE_DCHECK_EQ(total_size, builder.length());
  return builder.take();
}

SpdySerializedFrame SpdyFramer::SerializeUnknown(
    const SpdyUnknownIR& unknown) const {
  const size_t total_size = kFrameHeaderSize + unknown.payload().size();
  SpdyFrameBuilder builder(total_size);
  builder.BeginNewUncheckedFrame(unknown.type(), unknown.flags(),
                                 unknown.stream_id(), unknown.length());
  builder.WriteBytes(unknown.payload().data(), unknown.payload().size());
  return builder.take();
}

namespace {

class FrameSerializationVisitor : public SpdyFrameVisitor {
 public:
  explicit FrameSerializationVisitor(SpdyFramer* framer)
      : framer_(framer), frame_() {}
  ~FrameSerializationVisitor() override = default;

  SpdySerializedFrame ReleaseSerializedFrame() { return std::move(frame_); }

  void VisitData(const SpdyDataIR& data) override {
    frame_ = framer_->SerializeData(data);
  }
  void VisitRstStream(const SpdyRstStreamIR& rst_stream) override {
    frame_ = framer_->SerializeRstStream(rst_stream);
  }
  void VisitSettings(const SpdySettingsIR& settings) override {
    frame_ = framer_->SerializeSettings(settings);
  }
  void VisitPing(const SpdyPingIR& ping) override {
    frame_ = framer_->SerializePing(ping);
  }
  void VisitGoAway(const SpdyGoAwayIR& goaway) override {
    frame_ = framer_->SerializeGoAway(goaway);
  }
  void VisitHeaders(const SpdyHeadersIR& headers) override {
    frame_ = framer_->SerializeHeaders(headers);
  }
  void VisitWindowUpdate(const SpdyWindowUpdateIR& window_update) override {
    frame_ = framer_->SerializeWindowUpdate(window_update);
  }
  void VisitPushPromise(const SpdyPushPromiseIR& push_promise) override {
    frame_ = framer_->SerializePushPromise(push_promise);
  }
  void VisitContinuation(const SpdyContinuationIR& continuation) override {
    frame_ = framer_->SerializeContinuation(continuation);
  }
  void VisitAltSvc(const SpdyAltSvcIR& altsvc) override {
    frame_ = framer_->SerializeAltSvc(altsvc);
  }
  void VisitPriority(const SpdyPriorityIR& priority) override {
    frame_ = framer_->SerializePriority(priority);
  }
  void VisitPriorityUpdate(
      const SpdyPriorityUpdateIR& priority_update) override {
    frame_ = framer_->SerializePriorityUpdate(priority_update);
  }
  void VisitAcceptCh(const SpdyAcceptChIR& accept_ch) override {
    frame_ = framer_->SerializeAcceptCh(accept_ch);
  }
  void VisitUnknown(const SpdyUnknownIR& unknown) override {
    frame_ = framer_->SerializeUnknown(unknown);
  }

 private:
  SpdyFramer* framer_;
  SpdySerializedFrame frame_;
};

// TODO(diannahu): Use also in frame serialization.
class FlagsSerializationVisitor : public SpdyFrameVisitor {
 public:
  void VisitData(const SpdyDataIR& data) override {
    flags_ = DATA_FLAG_NONE;
    if (data.fin()) {
      flags_ |= DATA_FLAG_FIN;
    }
    if (data.padded()) {
      flags_ |= DATA_FLAG_PADDED;
    }
  }

  void VisitRstStream(const SpdyRstStreamIR& /*rst_stream*/) override {
    flags_ = kNoFlags;
  }

  void VisitSettings(const SpdySettingsIR& settings) override {
    flags_ = kNoFlags;
    if (settings.is_ack()) {
      flags_ |= SETTINGS_FLAG_ACK;
    }
  }

  void VisitPing(const SpdyPingIR& ping) override {
    flags_ = kNoFlags;
    if (ping.is_ack()) {
      flags_ |= PING_FLAG_ACK;
    }
  }

  void VisitGoAway(const SpdyGoAwayIR& /*goaway*/) override {
    flags_ = kNoFlags;
  }

  // TODO(diannahu): The END_HEADERS flag is incorrect for HEADERS that require
  //     CONTINUATION frames.
  void VisitHeaders(const SpdyHeadersIR& headers) override {
    flags_ = HEAD
"""


```