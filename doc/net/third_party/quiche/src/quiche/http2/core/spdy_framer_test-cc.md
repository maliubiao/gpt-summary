Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The user wants to understand the functionality of the provided C++ source code file, `spdy_framer_test.cc`. They are particularly interested in its relationship to JavaScript, logical reasoning with inputs/outputs, common usage errors, and debugging information. They also want a summary of the first part of the file (this specific snippet).

2. **Identify the File's Purpose:** The filename `spdy_framer_test.cc` and the included headers (`quiche/http2/core/spdy_framer.h`, `quiche/http2/core/spdy_protocol.h`, etc.) immediately suggest that this is a **unit test file** for the `SpdyFramer` class. The `SpdyFramer` is responsible for encoding and decoding SPDY/HTTP/2 frames. The `_test.cc` suffix is a standard convention for test files.

3. **Analyze the Includes:** The included headers reveal the core components being tested:
    * `spdy_framer.h`: The class under test.
    * Standard C++ libraries (`stdlib.h`, `<algorithm>`, etc.): Basic utilities.
    * `absl/strings/string_view.h`:  Efficient string handling.
    * `quiche/http2/core/...`:  Other HTTP/2 related classes like frame builders, decoders, and header handling.
    * `quiche/http2/hpack/hpack_encoder.h`:  HPACK encoding for headers.
    * `quiche/http2/test_tools/...`: Mocking and test utilities.
    * `quiche/common/...`: Common utilities.

4. **Examine Key Structures and Classes:**
    * **`MockDebugVisitor`:** A mock implementation of `SpdyFramerDebugVisitorInterface`. This suggests the code tests the debugging/logging aspects of the framer.
    * **`IsFrameUnionOf` Matcher:** A custom Google Test matcher. It appears to verify that different ways of serializing header frames produce the same output. This points to testing both incremental and non-incremental header serialization.
    * **`SpdyFramerPeer`:** A "friend" class (though implemented as a regular class here) providing access to internal methods of `SpdyFramer`. This is common in unit tests to test internal functionality that might not be directly exposed publicly. The methods `SerializeHeaders` and `SerializePushPromise` are crucial here, and the logic within them indicates testing different serialization paths.
    * **`TestSpdyVisitor`:** A concrete implementation of `SpdyFramerVisitorInterface` and `SpdyFramerDebugVisitorInterface`. This class simulates the role of a component that receives and processes the decoded frames from the `SpdyFramer`. It has counters and data members to track the different events and data it receives.
    * **`TestExtension`:** An implementation of `ExtensionVisitorInterface`. This indicates testing the framer's ability to handle non-standard frame types.
    * **`TestSpdyUnknownIR`:**  Inherits from `SpdyUnknownIR`, likely to test handling of unknown frame types.
    * **`SpdyFramerTest`:** The main test fixture using Google Test. It initializes the `SpdyFramer` and `Http2DecoderAdapter` (the deframer) and provides helper functions for comparing frames.

5. **Identify Key Functionality within the Snippet:**
    * **Header Serialization Testing:**  The `IsFrameUnionOf` matcher and the `SpdyFramerPeer` methods clearly focus on testing different ways of serializing header and push promise frames, ensuring consistency between older and newer (incremental) methods.
    * **Visitor Pattern Testing:**  The `TestSpdyVisitor` class demonstrates how the `SpdyFramer` interacts with its visitor. The various `On...` methods in `TestSpdyVisitor` correspond to the callbacks in the `SpdyFramerVisitorInterface`. The test setup involves creating a `SpdyFramer`, a `TestSpdyVisitor`, and feeding data through the framer, then verifying the state of the visitor.
    * **Error Handling Testing:** The `TestSpdyVisitor` tracks errors. The tests within the `SpdyFramerTest` class will likely assert on the `error_count_`.
    * **Extension Frame Testing:** The `TestExtension` class shows how the framer can be extended to handle custom frame types.

6. **Address Specific Parts of the Request:**

    * **Functionality:** Summarize the identified core functionalities (testing header serialization, visitor pattern, error handling, extension frames).
    * **Relationship to JavaScript:** Explain that this C++ code is part of the Chromium networking stack, which is used by the browser. While not directly interacting with JavaScript in this specific file, its functionality enables features that JavaScript developers use (like HTTP/2). Provide an example of a `fetch` request and how this C++ code would be involved in handling the HTTP/2 communication.
    * **Logical Reasoning (Input/Output):**  Provide a simple example of serializing a HEADERS frame with specific headers and then describe the expected output (the raw byte representation). Emphasize that the output format is defined by the HTTP/2 specification.
    * **Common Usage Errors:** Focus on the errors that the tests are designed to catch, such as oversized frames, invalid padding, and incorrect frame structure. Explain how these errors might arise from incorrect implementations or network issues.
    * **User Operations and Debugging:** Describe a typical user action (loading a webpage) and trace how it might lead to the execution of this code. Explain that developers would use debugging tools (like breakpoints) in this C++ code to understand network communication issues.
    * **Summary of Part 1:**  Condense the findings into a concise summary of the code's purpose.

7. **Structure the Answer:** Organize the information logically, using clear headings and bullet points to make it easy to read and understand. Address each part of the user's request.

8. **Review and Refine:** Read through the generated answer to ensure accuracy, clarity, and completeness. Make any necessary corrections or improvements. For example, ensure the JavaScript example is relevant and understandable. Double-check the input/output example for correctness.
这是对 Chromium 网络栈中 `net/third_party/quiche/src/quiche/http2/core/spdy_framer_test.cc` 文件第一部分的分析。

**文件功能归纳 (第 1 部分):**

该文件的主要功能是 **测试 `SpdyFramer` 类**。 `SpdyFramer` 负责 HTTP/2 协议中帧的序列化（编码）和反序列化（解码）。  具体来说，这部分代码涵盖了以下几个方面的测试：

1. **基础框架搭建:**  定义了测试所需的辅助类和结构，例如：
    * `MockDebugVisitor`:  用于模拟 `SpdyFramer` 的调试访问器，检查调试信息的输出。
    * `IsFrameUnionOf` matcher:  一个自定义的 Google Test matcher，用于比较通过不同方式序列化的帧是否一致（例如，整体序列化与增量序列化）。
    * `SpdyFramerPeer`:  一个友元类，用于访问 `SpdyFramer` 的内部方法，以便进行更细粒度的测试，特别是针对头部帧的序列化。
    * `TestSpdyVisitor`:  一个实现了 `SpdyFramerVisitorInterface` 的类，用于接收和处理 `SpdyFramer` 解码后的帧数据，并记录接收到的各种事件和数据。
    * `TestExtension`:  一个实现了 `ExtensionVisitorInterface` 的类，用于测试 `SpdyFramer` 处理未知或扩展帧的能力。
    * `TestSpdyUnknownIR`:  继承自 `SpdyUnknownIR`，用于测试处理未知帧的相关逻辑。
    * `SpdyFramerTest`:  主要的测试 fixture，用于组织和运行各种测试用例。

2. **头部帧 (HEADERS) 的序列化和反序列化测试:**
    * 使用 `SpdyFramerPeer` 的静态方法 `SerializeHeaders` 来测试 `SpdyFramer` 序列化头部帧的功能，并验证整体序列化和增量序列化的结果是否一致。
    * 使用 `TestSpdyVisitor` 模拟接收方，通过 `deframer_.ProcessInput` 来测试 `SpdyFramer` 反序列化头部帧的功能，并检查解析出的头部信息是否正确。

3. **流依赖 (Stream Dependency) 信息的序列化和反序列化测试:**  测试 `SpdyFramer` 是否能够正确处理头部帧中的流依赖信息（父流 ID，独占标志）。

4. **最大帧大小 (Max Frame Size) 的处理测试:**  测试 `SpdyFramer` 是否能够根据设置的最大帧大小正确处理接收到的帧，包括：
    * 接收小于等于最大帧大小的帧。
    * 接收大于最大帧大小的帧，并触发错误。
    * 设置更大的最大帧大小后，接收相应的帧。

5. **数据帧 (DATA) Padding 的处理测试:**  测试 `SpdyFramer` 对数据帧 Padding 的处理，包括：
    * 检测 Padding 长度超过帧剩余长度的情况，并触发错误。
    * 正确处理合法的 Padding。

**与 JavaScript 的功能关系:**

该 C++ 代码直接在 Chromium 的网络栈中运行，负责处理底层的 HTTP/2 协议帧。虽然 JavaScript 代码本身不直接调用这些 C++ 函数，但它依赖于这些底层功能来实现网络通信。

**举例说明:**

当 JavaScript 代码发起一个 HTTP/2 请求 (例如，使用 `fetch` API) 时，Chromium 浏览器会使用其网络栈来处理这个请求。 其中就包括 `SpdyFramer` 来将 JavaScript 请求转化为符合 HTTP/2 协议的帧进行发送，并将接收到的 HTTP/2 响应帧解析成 JavaScript 可以理解的数据。

例如，一个 JavaScript 的 `fetch` 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

在这个过程中，当浏览器需要发送请求头时，`SpdyFramer` 就会将这些请求头信息编码成一个 HTTP/2 HEADERS 帧。当服务器返回响应头时，`SpdyFramer` 又会将接收到的 HEADERS 帧解码成浏览器可以处理的格式，最终传递给 JavaScript 的 `response` 对象。

**逻辑推理 (假设输入与输出):**

假设输入是一个包含以下头部信息的 `SpdyHeadersIR` 对象：

```c++
SpdyHeadersIR headers(1);
headers.SetHeader(":method", "GET");
headers.SetHeader(":path", "/index.html");
headers.SetHeader("user-agent", "MyBrowser");
```

使用 `SpdyFramer` 序列化这个对象：

**假设输入:**  一个包含上述头部信息的 `SpdyHeadersIR` 对象，并且 `SpdyFramer` 启用了头部压缩。

**预期输出:**  一个 `SpdySerializedFrame` 对象，其内容是经过 HPACK 压缩后的 HEADERS 帧的二进制表示。  这个二进制表示会包含：

1. **帧头 (9 字节):**
   * `Length`:  指示 payload 的长度 (压缩后的头部块长度)。
   * `Type`:  `0x01` (HEADERS 帧类型)。
   * `Flags`:  可能包含 `0x04` (END_HEADERS) 如果没有后续的 CONTINUATION 帧。
   * `Stream Identifier`: `0x00000001` (流 ID 为 1)。

2. **帧 Payload:**
   * 经过 HPACK 压缩后的头部块的二进制数据。 这部分内容会根据 HPACK 编码规则进行编码，例如使用索引表示常见的头部字段，或者使用字面量表示。

**注意:**  具体的二进制输出会依赖于 HPACK 编码器的状态和具体的头部内容。

**用户或编程常见的使用错误:**

1. **尝试发送过大的帧:** 用户或编程者可能尝试构建一个 payload 长度超过 HTTP/2 协议允许的最大帧大小 (由 SETTINGS 帧协商) 的帧。 这会导致 `SpdyFramer` 拒绝发送或解码失败。
   * **例子:**  在构建一个 DATA 帧时，尝试写入超过 `SETTINGS_MAX_FRAME_SIZE` 限制的数据。

2. **错误地设置帧头信息:**  例如，设置了错误的帧类型、标志位或者流 ID。
   * **例子:**  在手动构建一个帧时，将帧类型设置为一个不存在的值。

3. **未能正确处理反序列化错误:**  接收方可能没有正确处理 `SpdyFramer` 返回的错误，导致程序行为异常。
   * **例子:**  接收到一个格式错误的帧，但程序没有检查 `deframer_.spdy_framer_error()`，导致后续处理使用了错误的数据。

4. **Padding 使用错误:**  在设置了 PADDED 标志的情况下，没有提供足够的 Padding 字节，或者 Padding 长度设置错误。
   * **例子:**  设置了 PADDED 标志，并将 Padding 长度设置为大于帧剩余长度的值。

**用户操作如何一步步到达这里 (调试线索):**

假设用户在浏览器中访问一个使用了 HTTP/2 协议的网站：

1. **用户在浏览器地址栏输入 URL 并回车。**
2. **浏览器解析 URL，并与服务器建立 TCP 连接。**
3. **浏览器和服务器进行 TLS 握手，建立安全连接。**
4. **浏览器和服务器进行 HTTP/2 协商 (通常在 TLS 的 ALPN 扩展中完成)。**
5. **如果协商成功，后续的 HTTP 通信将使用 HTTP/2 协议。**
6. **当浏览器需要请求资源 (例如 HTML 文件、CSS 文件、图片等) 时，它会构建 HTTP 请求。**
7. **Chromium 的网络栈会将这些 HTTP 请求转换为 HTTP/2 帧。  `SpdyFramer` 的序列化功能会被调用，将请求头信息编码成 HEADERS 帧，将请求体数据编码成 DATA 帧等。**
8. **这些帧通过底层的 socket 发送给服务器。**
9. **当服务器返回响应时，Chromium 的网络栈会接收到 HTTP/2 帧。**
10. **`SpdyFramer` 的反序列化功能会被调用，将接收到的帧解析成浏览器可以理解的数据。**
11. **例如，接收到的 HEADERS 帧会被解析出响应头信息，DATA 帧会被解析出响应体数据。**
12. **如果在这个过程中 `SpdyFramer` 遇到了格式错误的帧，或者帧的大小超出了限制，就会触发错误回调，例如 `OnError`。**

作为调试线索，开发者可能会：

* **设置断点:** 在 `SpdyFramer` 的序列化和反序列化方法中设置断点，查看帧的内容和处理流程。
* **查看日志:**  Chromium 的网络栈会输出详细的日志信息，包括发送和接收的帧内容，以及遇到的错误。开发者可以查看这些日志来定位问题。
* **使用网络抓包工具 (例如 Wireshark):**  抓取网络数据包，查看实际发送和接收的 HTTP/2 帧的二进制内容，与代码的预期进行对比。
* **检查 `TestSpdyVisitor` 的状态:**  在单元测试中，可以检查 `TestSpdyVisitor` 中记录的错误计数、接收到的帧类型和数据等，来判断 `SpdyFramer` 的行为是否符合预期。

希望以上分析对您有所帮助！ 接下来请提供后续的文件内容，以便进行后续部分的分析。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/core/spdy_framer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/http2/core/spdy_framer.h"

#include <stdlib.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <ios>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/macros.h"
#include "absl/strings/string_view.h"
#include "quiche/http2/core/array_output_buffer.h"
#include "quiche/http2/core/http2_frame_decoder_adapter.h"
#include "quiche/http2/core/recording_headers_handler.h"
#include "quiche/http2/core/spdy_alt_svc_wire_format.h"
#include "quiche/http2/core/spdy_bitmasks.h"
#include "quiche/http2/core/spdy_frame_builder.h"
#include "quiche/http2/core/spdy_headers_handler_interface.h"
#include "quiche/http2/core/spdy_protocol.h"
#include "quiche/http2/hpack/hpack_encoder.h"
#include "quiche/http2/test_tools/mock_spdy_framer_visitor.h"
#include "quiche/http2/test_tools/spdy_test_utils.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_text_utils.h"

using ::http2::Http2DecoderAdapter;
using ::testing::_;

namespace spdy {

namespace test {

namespace {

const int64_t kSize = 1024 * 1024;
char output_buffer[kSize] = "";

// frame_list_char is used to hold frames to be compared with output_buffer.
const int64_t buffer_size = 64 * 1024;
char frame_list_char[buffer_size] = "";
}  // namespace

class MockDebugVisitor : public SpdyFramerDebugVisitorInterface {
 public:
  MOCK_METHOD(void, OnSendCompressedFrame,
              (SpdyStreamId stream_id, SpdyFrameType type, size_t payload_len,
               size_t frame_len),
              (override));

  MOCK_METHOD(void, OnReceiveCompressedFrame,
              (SpdyStreamId stream_id, SpdyFrameType type, size_t frame_len),
              (override));
};

MATCHER_P(IsFrameUnionOf, frame_list, "") {
  size_t size_verified = 0;
  for (const auto& frame : *frame_list) {
    if (arg.size() < size_verified + frame.size()) {
      QUICHE_LOG(FATAL)
          << "Incremental header serialization should not lead to a "
          << "higher total frame length than non-incremental method.";
      return false;
    }
    if (memcmp(arg.data() + size_verified, frame.data(), frame.size())) {
      CompareCharArraysWithHexError(
          "Header serialization methods should be equivalent: ",
          reinterpret_cast<unsigned char*>(arg.data() + size_verified),
          frame.size(), reinterpret_cast<unsigned char*>(frame.data()),
          frame.size());
      return false;
    }
    size_verified += frame.size();
  }
  return size_verified == arg.size();
}

class SpdyFramerPeer {
 public:
  // TODO(dahollings): Remove these methods when deprecating non-incremental
  // header serialization path.
  static std::unique_ptr<SpdyHeadersIR> CloneSpdyHeadersIR(
      const SpdyHeadersIR& headers) {
    auto new_headers = std::make_unique<SpdyHeadersIR>(
        headers.stream_id(), headers.header_block().Clone());
    new_headers->set_fin(headers.fin());
    new_headers->set_has_priority(headers.has_priority());
    new_headers->set_weight(headers.weight());
    new_headers->set_parent_stream_id(headers.parent_stream_id());
    new_headers->set_exclusive(headers.exclusive());
    if (headers.padded()) {
      new_headers->set_padding_len(headers.padding_payload_len() + 1);
    }
    return new_headers;
  }

  static SpdySerializedFrame SerializeHeaders(SpdyFramer* framer,
                                              const SpdyHeadersIR& headers) {
    SpdySerializedFrame serialized_headers_old_version(
        framer->SerializeHeaders(headers));
    framer->hpack_encoder_.reset(nullptr);
    auto* saved_debug_visitor = framer->debug_visitor_;
    framer->debug_visitor_ = nullptr;

    std::vector<SpdySerializedFrame> frame_list;
    ArrayOutputBuffer frame_list_buffer(frame_list_char, buffer_size);
    SpdyFramer::SpdyHeaderFrameIterator it(framer, CloneSpdyHeadersIR(headers));
    while (it.HasNextFrame()) {
      size_t size_before = frame_list_buffer.Size();
      EXPECT_GT(it.NextFrame(&frame_list_buffer), 0u);
      frame_list.emplace_back(
          MakeSerializedFrame(frame_list_buffer.Begin() + size_before,
                              frame_list_buffer.Size() - size_before));
    }
    framer->debug_visitor_ = saved_debug_visitor;

    EXPECT_THAT(serialized_headers_old_version, IsFrameUnionOf(&frame_list));
    return serialized_headers_old_version;
  }

  static SpdySerializedFrame SerializeHeaders(SpdyFramer* framer,
                                              const SpdyHeadersIR& headers,
                                              ArrayOutputBuffer* output) {
    if (output == nullptr) {
      return SerializeHeaders(framer, headers);
    }
    output->Reset();
    EXPECT_TRUE(framer->SerializeHeaders(headers, output));
    SpdySerializedFrame serialized_headers_old_version =
        MakeSerializedFrame(output->Begin(), output->Size());
    framer->hpack_encoder_.reset(nullptr);
    auto* saved_debug_visitor = framer->debug_visitor_;
    framer->debug_visitor_ = nullptr;

    std::vector<SpdySerializedFrame> frame_list;
    ArrayOutputBuffer frame_list_buffer(frame_list_char, buffer_size);
    SpdyFramer::SpdyHeaderFrameIterator it(framer, CloneSpdyHeadersIR(headers));
    while (it.HasNextFrame()) {
      size_t size_before = frame_list_buffer.Size();
      EXPECT_GT(it.NextFrame(&frame_list_buffer), 0u);
      frame_list.emplace_back(
          MakeSerializedFrame(frame_list_buffer.Begin() + size_before,
                              frame_list_buffer.Size() - size_before));
    }
    framer->debug_visitor_ = saved_debug_visitor;

    EXPECT_THAT(serialized_headers_old_version, IsFrameUnionOf(&frame_list));
    return serialized_headers_old_version;
  }

  static std::unique_ptr<SpdyPushPromiseIR> CloneSpdyPushPromiseIR(
      const SpdyPushPromiseIR& push_promise) {
    auto new_push_promise = std::make_unique<SpdyPushPromiseIR>(
        push_promise.stream_id(), push_promise.promised_stream_id(),
        push_promise.header_block().Clone());
    new_push_promise->set_fin(push_promise.fin());
    if (push_promise.padded()) {
      new_push_promise->set_padding_len(push_promise.padding_payload_len() + 1);
    }
    return new_push_promise;
  }

  static SpdySerializedFrame SerializePushPromise(
      SpdyFramer* framer, const SpdyPushPromiseIR& push_promise) {
    SpdySerializedFrame serialized_headers_old_version =
        framer->SerializePushPromise(push_promise);
    framer->hpack_encoder_.reset(nullptr);
    auto* saved_debug_visitor = framer->debug_visitor_;
    framer->debug_visitor_ = nullptr;

    std::vector<SpdySerializedFrame> frame_list;
    ArrayOutputBuffer frame_list_buffer(frame_list_char, buffer_size);
    frame_list_buffer.Reset();
    SpdyFramer::SpdyPushPromiseFrameIterator it(
        framer, CloneSpdyPushPromiseIR(push_promise));
    while (it.HasNextFrame()) {
      size_t size_before = frame_list_buffer.Size();
      EXPECT_GT(it.NextFrame(&frame_list_buffer), 0u);
      frame_list.emplace_back(
          MakeSerializedFrame(frame_list_buffer.Begin() + size_before,
                              frame_list_buffer.Size() - size_before));
    }
    framer->debug_visitor_ = saved_debug_visitor;

    EXPECT_THAT(serialized_headers_old_version, IsFrameUnionOf(&frame_list));
    return serialized_headers_old_version;
  }

  static SpdySerializedFrame SerializePushPromise(
      SpdyFramer* framer, const SpdyPushPromiseIR& push_promise,
      ArrayOutputBuffer* output) {
    if (output == nullptr) {
      return SerializePushPromise(framer, push_promise);
    }
    output->Reset();
    EXPECT_TRUE(framer->SerializePushPromise(push_promise, output));
    SpdySerializedFrame serialized_headers_old_version =
        MakeSerializedFrame(output->Begin(), output->Size());
    framer->hpack_encoder_.reset(nullptr);
    auto* saved_debug_visitor = framer->debug_visitor_;
    framer->debug_visitor_ = nullptr;

    std::vector<SpdySerializedFrame> frame_list;
    ArrayOutputBuffer frame_list_buffer(frame_list_char, buffer_size);
    frame_list_buffer.Reset();
    SpdyFramer::SpdyPushPromiseFrameIterator it(
        framer, CloneSpdyPushPromiseIR(push_promise));
    while (it.HasNextFrame()) {
      size_t size_before = frame_list_buffer.Size();
      EXPECT_GT(it.NextFrame(&frame_list_buffer), 0u);
      frame_list.emplace_back(
          MakeSerializedFrame(frame_list_buffer.Begin() + size_before,
                              frame_list_buffer.Size() - size_before));
    }
    framer->debug_visitor_ = saved_debug_visitor;

    EXPECT_THAT(serialized_headers_old_version, IsFrameUnionOf(&frame_list));
    return serialized_headers_old_version;
  }
};

class TestSpdyVisitor : public SpdyFramerVisitorInterface,
                        public SpdyFramerDebugVisitorInterface {
 public:
  // This is larger than our max frame size because header blocks that
  // are too long can spill over into CONTINUATION frames.
  static constexpr size_t kDefaultHeaderBufferSize = 16 * 1024 * 1024;

  explicit TestSpdyVisitor(SpdyFramer::CompressionOption option)
      : framer_(option),
        error_count_(0),
        headers_frame_count_(0),
        push_promise_frame_count_(0),
        goaway_count_(0),
        setting_count_(0),
        settings_ack_sent_(0),
        settings_ack_received_(0),
        continuation_count_(0),
        altsvc_count_(0),
        priority_count_(0),
        unknown_frame_count_(0),
        on_unknown_frame_result_(false),
        last_window_update_stream_(0),
        last_window_update_delta_(0),
        last_push_promise_stream_(0),
        last_push_promise_promised_stream_(0),
        data_bytes_(0),
        fin_frame_count_(0),
        fin_flag_count_(0),
        end_of_stream_count_(0),
        control_frame_header_data_count_(0),
        zero_length_control_frame_header_data_count_(0),
        data_frame_count_(0),
        last_payload_len_(0),
        last_frame_len_(0),
        unknown_payload_len_(0),
        header_buffer_(new char[kDefaultHeaderBufferSize]),
        header_buffer_length_(0),
        header_buffer_size_(kDefaultHeaderBufferSize),
        header_stream_id_(static_cast<SpdyStreamId>(-1)),
        header_control_type_(SpdyFrameType::DATA),
        header_buffer_valid_(false) {}

  void OnError(Http2DecoderAdapter::SpdyFramerError error,
               std::string /*detailed_error*/) override {
    QUICHE_VLOG(1) << "SpdyFramer Error: "
                   << Http2DecoderAdapter::SpdyFramerErrorToString(error);
    ++error_count_;
  }

  void OnDataFrameHeader(SpdyStreamId stream_id, size_t length,
                         bool fin) override {
    QUICHE_VLOG(1) << "OnDataFrameHeader(" << stream_id << ", " << length
                   << ", " << fin << ")";
    ++data_frame_count_;
    header_stream_id_ = stream_id;
  }

  void OnStreamFrameData(SpdyStreamId stream_id, const char* data,
                         size_t len) override {
    QUICHE_VLOG(1) << "OnStreamFrameData(" << stream_id << ", data, " << len
                   << ", "
                   << ")   data:\n"
                   << quiche::QuicheTextUtils::HexDump(
                          absl::string_view(data, len));
    EXPECT_EQ(header_stream_id_, stream_id);

    data_bytes_ += len;
  }

  void OnStreamEnd(SpdyStreamId stream_id) override {
    QUICHE_VLOG(1) << "OnStreamEnd(" << stream_id << ")";
    EXPECT_EQ(header_stream_id_, stream_id);
    ++end_of_stream_count_;
  }

  void OnStreamPadLength(SpdyStreamId stream_id, size_t value) override {
    QUICHE_VLOG(1) << "OnStreamPadding(" << stream_id << ", " << value << ")\n";
    EXPECT_EQ(header_stream_id_, stream_id);
    // Count the padding length field byte against total data bytes.
    data_bytes_ += 1;
  }

  void OnStreamPadding(SpdyStreamId stream_id, size_t len) override {
    QUICHE_VLOG(1) << "OnStreamPadding(" << stream_id << ", " << len << ")\n";
    EXPECT_EQ(header_stream_id_, stream_id);
    data_bytes_ += len;
  }

  SpdyHeadersHandlerInterface* OnHeaderFrameStart(
      SpdyStreamId /*stream_id*/) override {
    if (headers_handler_ == nullptr) {
      headers_handler_ = std::make_unique<RecordingHeadersHandler>();
    }
    return headers_handler_.get();
  }

  void OnHeaderFrameEnd(SpdyStreamId /*stream_id*/) override {
    QUICHE_CHECK(headers_handler_ != nullptr);
    headers_ = headers_handler_->decoded_block().Clone();
    header_bytes_received_ = headers_handler_->uncompressed_header_bytes();
    headers_handler_.reset();
  }

  void OnRstStream(SpdyStreamId stream_id, SpdyErrorCode error_code) override {
    QUICHE_VLOG(1) << "OnRstStream(" << stream_id << ", " << error_code << ")";
    ++fin_frame_count_;
  }

  void OnSetting(SpdySettingsId id, uint32_t value) override {
    QUICHE_VLOG(1) << "OnSetting(" << id << ", " << std::hex << value << ")";
    ++setting_count_;
  }

  void OnSettingsAck() override {
    QUICHE_VLOG(1) << "OnSettingsAck";
    ++settings_ack_received_;
  }

  void OnSettingsEnd() override {
    QUICHE_VLOG(1) << "OnSettingsEnd";
    ++settings_ack_sent_;
  }

  void OnPing(SpdyPingId unique_id, bool is_ack) override {
    QUICHE_LOG(DFATAL) << "OnPing(" << unique_id << ", " << (is_ack ? 1 : 0)
                       << ")";
  }

  void OnGoAway(SpdyStreamId last_accepted_stream_id,
                SpdyErrorCode error_code) override {
    QUICHE_VLOG(1) << "OnGoAway(" << last_accepted_stream_id << ", "
                   << error_code << ")";
    ++goaway_count_;
  }

  void OnHeaders(SpdyStreamId stream_id, size_t payload_length,
                 bool has_priority, int weight, SpdyStreamId parent_stream_id,
                 bool exclusive, bool fin, bool end) override {
    QUICHE_VLOG(1) << "OnHeaders(" << stream_id << ", " << payload_length
                   << ", " << has_priority << ", " << weight << ", "
                   << parent_stream_id << ", " << exclusive << ", " << fin
                   << ", " << end << ")";
    ++headers_frame_count_;
    InitHeaderStreaming(SpdyFrameType::HEADERS, stream_id);
    if (fin) {
      ++fin_flag_count_;
    }
    header_has_priority_ = has_priority;
    header_parent_stream_id_ = parent_stream_id;
    header_exclusive_ = exclusive;
  }

  void OnWindowUpdate(SpdyStreamId stream_id, int delta_window_size) override {
    QUICHE_VLOG(1) << "OnWindowUpdate(" << stream_id << ", "
                   << delta_window_size << ")";
    last_window_update_stream_ = stream_id;
    last_window_update_delta_ = delta_window_size;
  }

  void OnPushPromise(SpdyStreamId stream_id, SpdyStreamId promised_stream_id,
                     bool end) override {
    QUICHE_VLOG(1) << "OnPushPromise(" << stream_id << ", "
                   << promised_stream_id << ", " << end << ")";
    ++push_promise_frame_count_;
    InitHeaderStreaming(SpdyFrameType::PUSH_PROMISE, stream_id);
    last_push_promise_stream_ = stream_id;
    last_push_promise_promised_stream_ = promised_stream_id;
  }

  void OnContinuation(SpdyStreamId stream_id, size_t payload_size,
                      bool end) override {
    QUICHE_VLOG(1) << "OnContinuation(" << stream_id << ", " << payload_size
                   << ", " << end << ")";
    ++continuation_count_;
  }

  void OnAltSvc(SpdyStreamId stream_id, absl::string_view origin,
                const SpdyAltSvcWireFormat::AlternativeServiceVector&
                    altsvc_vector) override {
    QUICHE_VLOG(1) << "OnAltSvc(" << stream_id << ", \"" << origin
                   << "\", altsvc_vector)";
    test_altsvc_ir_ = std::make_unique<SpdyAltSvcIR>(stream_id);
    if (origin.length() > 0) {
      test_altsvc_ir_->set_origin(std::string(origin));
    }
    for (const auto& altsvc : altsvc_vector) {
      test_altsvc_ir_->add_altsvc(altsvc);
    }
    ++altsvc_count_;
  }

  void OnPriority(SpdyStreamId stream_id, SpdyStreamId parent_stream_id,
                  int weight, bool exclusive) override {
    QUICHE_VLOG(1) << "OnPriority(" << stream_id << ", " << parent_stream_id
                   << ", " << weight << ", " << (exclusive ? 1 : 0) << ")";
    ++priority_count_;
  }

  void OnPriorityUpdate(SpdyStreamId prioritized_stream_id,
                        absl::string_view priority_field_value) override {
    QUICHE_VLOG(1) << "OnPriorityUpdate(" << prioritized_stream_id << ", "
                   << priority_field_value << ")";
  }

  bool OnUnknownFrame(SpdyStreamId stream_id, uint8_t frame_type) override {
    QUICHE_VLOG(1) << "OnUnknownFrame(" << stream_id << ", " << frame_type
                   << ")";
    return on_unknown_frame_result_;
  }

  void OnUnknownFrameStart(SpdyStreamId stream_id, size_t length, uint8_t type,
                           uint8_t flags) override {
    QUICHE_VLOG(1) << "OnUnknownFrameStart(" << stream_id << ", " << length
                   << ", " << static_cast<int>(type) << ", "
                   << static_cast<int>(flags) << ")";
    ++unknown_frame_count_;
  }

  void OnUnknownFramePayload(SpdyStreamId stream_id,
                             absl::string_view payload) override {
    QUICHE_VLOG(1) << "OnUnknownFramePayload(" << stream_id << ", " << payload
                   << ")";
    unknown_payload_len_ += payload.length();
  }

  void OnSendCompressedFrame(SpdyStreamId stream_id, SpdyFrameType type,
                             size_t payload_len, size_t frame_len) override {
    QUICHE_VLOG(1) << "OnSendCompressedFrame(" << stream_id << ", " << type
                   << ", " << payload_len << ", " << frame_len << ")";
    last_payload_len_ = payload_len;
    last_frame_len_ = frame_len;
  }

  void OnReceiveCompressedFrame(SpdyStreamId stream_id, SpdyFrameType type,
                                size_t frame_len) override {
    QUICHE_VLOG(1) << "OnReceiveCompressedFrame(" << stream_id << ", " << type
                   << ", " << frame_len << ")";
    last_frame_len_ = frame_len;
  }

  // Convenience function which runs a framer simulation with particular input.
  void SimulateInFramer(const unsigned char* input, size_t size) {
    deframer_.set_visitor(this);
    size_t input_remaining = size;
    const char* input_ptr = reinterpret_cast<const char*>(input);
    while (input_remaining > 0 && deframer_.spdy_framer_error() ==
                                      Http2DecoderAdapter::SPDY_NO_ERROR) {
      // To make the tests more interesting, we feed random (and small) chunks
      // into the framer.  This simulates getting strange-sized reads from
      // the socket.
      const size_t kMaxReadSize = 32;
      size_t bytes_read =
          (rand() % std::min(input_remaining, kMaxReadSize)) + 1;  // NOLINT
      size_t bytes_processed = deframer_.ProcessInput(input_ptr, bytes_read);
      input_remaining -= bytes_processed;
      input_ptr += bytes_processed;
    }
  }

  void InitHeaderStreaming(SpdyFrameType header_control_type,
                           SpdyStreamId stream_id) {
    if (!IsDefinedFrameType(SerializeFrameType(header_control_type))) {
      QUICHE_DLOG(FATAL) << "Attempted to init header streaming with "
                         << "invalid control frame type: "
                         << header_control_type;
    }
    memset(header_buffer_.get(), 0, header_buffer_size_);
    header_buffer_length_ = 0;
    header_stream_id_ = stream_id;
    header_control_type_ = header_control_type;
    header_buffer_valid_ = true;
  }

  void set_extension_visitor(ExtensionVisitorInterface* extension) {
    deframer_.set_extension_visitor(extension);
  }

  // Override the default buffer size (16K). Call before using the framer!
  void set_header_buffer_size(size_t header_buffer_size) {
    header_buffer_size_ = header_buffer_size;
    header_buffer_.reset(new char[header_buffer_size]);
  }

  SpdyFramer framer_;
  Http2DecoderAdapter deframer_;

  // Counters from the visitor callbacks.
  int error_count_;
  int headers_frame_count_;
  int push_promise_frame_count_;
  int goaway_count_;
  int setting_count_;
  int settings_ack_sent_;
  int settings_ack_received_;
  int continuation_count_;
  int altsvc_count_;
  int priority_count_;
  std::unique_ptr<SpdyAltSvcIR> test_altsvc_ir_;
  int unknown_frame_count_;
  bool on_unknown_frame_result_;
  SpdyStreamId last_window_update_stream_;
  int last_window_update_delta_;
  SpdyStreamId last_push_promise_stream_;
  SpdyStreamId last_push_promise_promised_stream_;
  int data_bytes_;
  int fin_frame_count_;      // The count of RST_STREAM type frames received.
  int fin_flag_count_;       // The count of frames with the FIN flag set.
  int end_of_stream_count_;  // The count of zero-length data frames.
  int control_frame_header_data_count_;  // The count of chunks received.
  // The count of zero-length control frame header data chunks received.
  int zero_length_control_frame_header_data_count_;
  int data_frame_count_;
  size_t last_payload_len_;
  size_t last_frame_len_;
  size_t unknown_payload_len_;

  // Header block streaming state:
  std::unique_ptr<char[]> header_buffer_;
  size_t header_buffer_length_;
  size_t header_buffer_size_;
  size_t header_bytes_received_;
  SpdyStreamId header_stream_id_;
  SpdyFrameType header_control_type_;
  bool header_buffer_valid_;
  std::unique_ptr<RecordingHeadersHandler> headers_handler_;
  quiche::HttpHeaderBlock headers_;
  bool header_has_priority_;
  SpdyStreamId header_parent_stream_id_;
  bool header_exclusive_;
};

class TestExtension : public ExtensionVisitorInterface {
 public:
  void OnSetting(SpdySettingsId id, uint32_t value) override {
    settings_received_.push_back({id, value});
  }

  // Called when non-standard frames are received.
  bool OnFrameHeader(SpdyStreamId stream_id, size_t length, uint8_t type,
                     uint8_t flags) override {
    stream_id_ = stream_id;
    length_ = length;
    type_ = type;
    flags_ = flags;
    return true;
  }

  // The payload for a single frame may be delivered as multiple calls to
  // OnFramePayload.
  void OnFramePayload(const char* data, size_t len) override {
    payload_.append(data, len);
  }

  std::vector<std::pair<SpdySettingsId, uint32_t>> settings_received_;
  SpdyStreamId stream_id_ = 0;
  size_t length_ = 0;
  uint8_t type_ = 0;
  uint8_t flags_ = 0;
  std::string payload_;
};

// Exposes SpdyUnknownIR::set_length() for testing purposes.
class TestSpdyUnknownIR : public SpdyUnknownIR {
 public:
  using SpdyUnknownIR::set_length;
  using SpdyUnknownIR::SpdyUnknownIR;
};

enum Output { USE, NOT_USE };

class SpdyFramerTest : public quiche::test::QuicheTestWithParam<Output> {
 public:
  SpdyFramerTest()
      : output_(output_buffer, kSize),
        framer_(SpdyFramer::ENABLE_COMPRESSION),
        deframer_(std::make_unique<Http2DecoderAdapter>()) {}

 protected:
  void SetUp() override {
    switch (GetParam()) {
      case USE:
        use_output_ = true;
        break;
      case NOT_USE:
        // TODO(yasong): remove this case after
        // gfe2_reloadable_flag_write_queue_zero_copy_buffer deprecates.
        use_output_ = false;
        break;
    }
  }

  void CompareFrame(const std::string& description,
                    const SpdySerializedFrame& actual_frame,
                    const unsigned char* expected, const int expected_len) {
    const unsigned char* actual =
        reinterpret_cast<const unsigned char*>(actual_frame.data());
    CompareCharArraysWithHexError(description, actual, actual_frame.size(),
                                  expected, expected_len);
  }

  bool use_output_ = false;
  ArrayOutputBuffer output_;
  SpdyFramer framer_;
  std::unique_ptr<Http2DecoderAdapter> deframer_;
};

INSTANTIATE_TEST_SUITE_P(SpdyFramerTests, SpdyFramerTest,
                         ::testing::Values(USE, NOT_USE));

// Test that we can encode and decode a quiche::HttpHeaderBlock in serialized
// form.
TEST_P(SpdyFramerTest, HeaderBlockInBuffer) {
  SpdyFramer framer(SpdyFramer::DISABLE_COMPRESSION);

  // Encode the header block into a Headers frame.
  SpdyHeadersIR headers(/* stream_id = */ 1);
  headers.SetHeader("alpha", "beta");
  headers.SetHeader("gamma", "charlie");
  headers.SetHeader("cookie", "key1=value1; key2=value2");
  SpdySerializedFrame frame(
      SpdyFramerPeer::SerializeHeaders(&framer, headers, &output_));

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(reinterpret_cast<unsigned char*>(frame.data()),
                           frame.size());

  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);
  EXPECT_EQ(headers.header_block(), visitor.headers_);
}

// Test that if there's not a full frame, we fail to parse it.
TEST_P(SpdyFramerTest, UndersizedHeaderBlockInBuffer) {
  SpdyFramer framer(SpdyFramer::DISABLE_COMPRESSION);

  // Encode the header block into a Headers frame.
  SpdyHeadersIR headers(/* stream_id = */ 1);
  headers.SetHeader("alpha", "beta");
  headers.SetHeader("gamma", "charlie");
  SpdySerializedFrame frame(
      SpdyFramerPeer::SerializeHeaders(&framer, headers, &output_));

  TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
  visitor.SimulateInFramer(reinterpret_cast<unsigned char*>(frame.data()),
                           frame.size() - 2);

  EXPECT_EQ(0, visitor.zero_length_control_frame_header_data_count_);
  EXPECT_THAT(visitor.headers_, testing::IsEmpty());
}

// Test that we can encode and decode stream dependency values in a header
// frame.
TEST_P(SpdyFramerTest, HeaderStreamDependencyValues) {
  SpdyFramer framer(SpdyFramer::DISABLE_COMPRESSION);

  const SpdyStreamId parent_stream_id_test_array[] = {0, 3};
  for (SpdyStreamId parent_stream_id : parent_stream_id_test_array) {
    const bool exclusive_test_array[] = {true, false};
    for (bool exclusive : exclusive_test_array) {
      SpdyHeadersIR headers(1);
      headers.set_has_priority(true);
      headers.set_parent_stream_id(parent_stream_id);
      headers.set_exclusive(exclusive);
      SpdySerializedFrame frame(
          SpdyFramerPeer::SerializeHeaders(&framer, headers, &output_));

      TestSpdyVisitor visitor(SpdyFramer::DISABLE_COMPRESSION);
      visitor.SimulateInFramer(reinterpret_cast<unsigned char*>(frame.data()),
                               frame.size());

      EXPECT_TRUE(visitor.header_has_priority_);
      EXPECT_EQ(parent_stream_id, visitor.header_parent_stream_id_);
      EXPECT_EQ(exclusive, visitor.header_exclusive_);
    }
  }
}

// Test that if we receive a frame with a payload length field at the default
// max size, we do not set an error in ProcessInput.
TEST_P(SpdyFramerTest, AcceptMaxFrameSizeSetting) {
  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  deframer_->set_visitor(&visitor);

  // DATA frame with maximum allowed payload length.
  unsigned char kH2FrameData[] = {
      0x00, 0x40, 0x00,        // Length: 2^14
      0x00,                    //   Type: DATA
      0x00,                    //  Flags: None
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x00, 0x00, 0x00,  // Junk payload
  };

  SpdySerializedFrame frame = MakeSerializedFrame(
      reinterpret_cast<char*>(kH2FrameData), sizeof(kH2FrameData));

  EXPECT_CALL(visitor, OnCommonHeader(1, 16384, 0x0, 0x0));
  EXPECT_CALL(visitor, OnDataFrameHeader(1, 1 << 14, false));
  EXPECT_CALL(visitor, OnStreamFrameData(1, _, 4));
  deframer_->ProcessInput(frame.data(), frame.size());
  EXPECT_FALSE(deframer_->HasError());
}

// Test that if we receive a frame with a payload length larger than the default
// max size, we set an error of SPDY_INVALID_CONTROL_FRAME_SIZE.
TEST_P(SpdyFramerTest, ExceedMaxFrameSizeSetting) {
  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  deframer_->set_visitor(&visitor);

  // DATA frame with too large payload length.
  unsigned char kH2FrameData[] = {
      0x00, 0x40, 0x01,        // Length: 2^14 + 1
      0x00,                    //   Type: DATA
      0x00,                    //  Flags: None
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x00, 0x00, 0x00,  // Junk payload
  };

  SpdySerializedFrame frame = MakeSerializedFrame(
      reinterpret_cast<char*>(kH2FrameData), sizeof(kH2FrameData));

  EXPECT_CALL(visitor, OnCommonHeader(1, 16385, 0x0, 0x0));
  EXPECT_CALL(visitor, OnError(Http2DecoderAdapter::SPDY_OVERSIZED_PAYLOAD, _));
  deframer_->ProcessInput(frame.data(), frame.size());
  EXPECT_TRUE(deframer_->HasError());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_OVERSIZED_PAYLOAD,
            deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

// Test that if we set a larger max frame size and then receive a frame with a
// payload length at that larger size, we do not set an error in ProcessInput.
TEST_P(SpdyFramerTest, AcceptLargerMaxFrameSizeSetting) {
  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  deframer_->set_visitor(&visitor);

  const size_t big_frame_size = (1 << 14) + 1;
  deframer_->SetMaxFrameSize(big_frame_size);

  // DATA frame with larger-than-default but acceptable payload length.
  unsigned char kH2FrameData[] = {
      0x00, 0x40, 0x01,        // Length: 2^14 + 1
      0x00,                    //   Type: DATA
      0x00,                    //  Flags: None
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x00, 0x00, 0x00, 0x00,  // Junk payload
  };

  SpdySerializedFrame frame = MakeSerializedFrame(
      reinterpret_cast<char*>(kH2FrameData), sizeof(kH2FrameData));

  EXPECT_CALL(visitor, OnCommonHeader(1, big_frame_size, 0x0, 0x0));
  EXPECT_CALL(visitor, OnDataFrameHeader(1, big_frame_size, false));
  EXPECT_CALL(visitor, OnStreamFrameData(1, _, 4));
  deframer_->ProcessInput(frame.data(), frame.size());
  EXPECT_FALSE(deframer_->HasError());
}

// Test that if we receive a DATA frame with padding length larger than the
// payload length, we set an error of SPDY_INVALID_PADDING
TEST_P(SpdyFramerTest, OversizedDataPaddingError) {
  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;
  deframer_->set_visitor(&visitor);

  // DATA frame with invalid padding length.
  // |kH2FrameData| has to be |unsigned char|, because Chromium on Windows uses
  // MSVC, where |char| is signed by default, which would not compile because of
  // the element exceeding 127.
  unsigned char kH2FrameData[] = {
      0x00, 0x00, 0x05,        // Length: 5
      0x00,                    //   Type: DATA
      0x09,                    //  Flags: END_STREAM|PADDED
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0xff,                    // PadLen: 255 trailing bytes (Too Long)
      0x00, 0x00, 0x00, 0x00,  // Padding
  };

  SpdySerializedFrame frame = MakeSerializedFrame(
      reinterpret_cast<char*>(kH2FrameData), sizeof(kH2FrameData));

  {
    testing::InSequence seq;
    EXPECT_CALL(visitor, OnCommonHeader(1, 5, 0x0, 0x9));
    EXPECT_CALL(visitor, OnDataFrameHeader(1, 5, 1));
    EXPECT_CALL(visitor, OnStreamPadding(1, 1));
    EXPECT_CALL(visitor, OnError(Http2DecoderAdapter::SPDY_INVALID_PADDING, _));
  }
  EXPECT_GT(frame.size(), deframer_->ProcessInput(frame.data(), frame.size()));
  EXPECT_TRUE(deframer_->HasError());
  EXPECT_EQ(Http2DecoderAdapter::SPDY_INVALID_PADDING,
            deframer_->spdy_framer_error())
      << Http2DecoderAdapter::SpdyFramerErrorToString(
             deframer_->spdy_framer_error());
}

// Test that if we receive a DATA frame with padding length not larger than the
// payload length, we do not set an error of SPDY_INVALID_PADDING
TEST_P(SpdyFramerTest, CorrectlySizedDataPaddingNoError) {
  testing::StrictMock<test::MockSpdyFramerVisitor> visitor;

  deframer_->set_visitor(&visitor);

  // DATA frame with valid Padding length
  char kH2FrameData[] = {
      0x00, 0x00, 0x05,        // Length: 5
      0x00,                    //   Type: DATA
      0x08,                    //  Flags: PADDED
      0x00, 0x00, 0x00, 0x01,  // Stream: 1
      0x04,                    // PadLen: 4 trailing bytes
      0x00, 0x00, 0x00, 0x00,  // Padding
  };

  SpdySerializedFrame frame =
      MakeSerializedFrame(kH2FrameData, sizeof(kH2FrameData));

  {
    testing::InSequence seq;
    EXPECT_CALL(visitor, OnCommonHeader(1, 5, 0x0, 0x8));
    EXPECT_CALL(visitor, OnDataFrameHeader(1, 5, false));
    EXPECT_CALL(visitor, OnStreamPadLength(1, 4));
    EXPECT_CALL(visitor, OnError(_, _)).Times(0);
    // Note that OnStreamFrameData(1, _, 1)) is never called
    // since there is no data, only padding
    EXPECT_CALL(visitor, OnStreamPa
```