Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Understanding the Request:**

The core request is to understand the functionality of the C++ file `decode_http2_structures_test.cc` within the Chromium networking stack. Specifically, the prompt asks for:

* A summary of its purpose.
* Its relationship to JavaScript.
* Logical reasoning with example inputs and outputs.
* Common usage errors.
* Steps to reach this code during debugging.

**2. Initial Code Scan and Keyword Identification:**

I started by scanning the code for keywords and structural elements:

* **Includes:** `decode_http2_structures.h`, `quiche/http2/http2_structures.h`, `quiche/http2/decoder/decode_buffer.h`,  `quiche/http2/decoder/decode_status.h`, `quiche/http2/http2_constants.h`, `quiche/http2/test_tools/...`, `quiche/common/platform/api/...`. These immediately suggest the file is about testing the *decoding* of HTTP/2 structures. The "test_tools" namespace confirms it's a test file.
* **Namespaces:** `http2::test`. Clearly within the HTTP/2 testing framework.
* **Test Classes:**  `FrameHeaderDecoderTest`, `PriorityFieldsDecoderTest`, `RstStreamFieldsDecoderTest`, etc. The names directly correspond to HTTP/2 frame header and field types.
* **`TEST_F` macros:**  Standard Google Test framework usage, indicating individual test cases.
* **`DecodeLeadingStructure` function:**  A crucial helper function for decoding and assertion.
* **`SerializeStructure` function:**  Another helper, for encoding structures into byte streams.
* **`Randomize` function:**  Indicates testing with randomly generated data.
* **Assertions (`EXPECT_EQ`, `ASSERT_LE`, `EXPECT_FALSE`, `EXPECT_TRUE`):**  Confirmation that the decoding process produces the expected results.
* **Literal data (e.g., `kData[]`):**  Specific byte sequences used for testing known cases.

**3. Deduction of Core Functionality:**

Based on the keywords and structure, the primary function is clear: **This file tests the correct decoding of various fixed-size HTTP/2 data structures.**  It takes raw byte sequences representing encoded HTTP/2 structures and uses the `DecodeHttp2Structures` logic (presumably defined in `decode_http2_structures.h`) to parse them. The tests verify that the decoded structure's fields match the expected values.

**4. Relationship to JavaScript:**

HTTP/2 is a network protocol used for web communication. JavaScript running in a browser uses this protocol (often transparently). Therefore, the decoding logic tested here is *fundamental* to how a browser (using Chromium's networking stack) interprets data received from a web server.

**Example:** When a JavaScript fetch request receives HTTP/2 headers, the underlying Chromium code uses logic similar to what's being tested here to parse those headers.

**5. Logical Reasoning with Examples:**

The `TEST_F` functions provide excellent examples. I picked a few representative ones to illustrate the process:

* **`FrameHeaderDecoderTest::DecodesLiteral`:**  Shows how a specific byte sequence is decoded into individual fields of the `Http2FrameHeader`. I provided the input bytes and the expected output fields.
* **`PriorityFieldsDecoderTest::DecodesLiteral`:** Similar to the above, but for `Http2PriorityFields`, highlighting bit manipulation (exclusive flag).
* **`GoAwayFieldsDecoderTest::DecodesLiteral`:**  Demonstrates decoding of `Http2GoAwayFields`, including handling of error codes and the reserved bit in the stream ID.

For each example, I identified the input (the `kData` array) and the expected output (the values asserted using `EXPECT_EQ`). I also explained the *meaning* of those bytes and the resulting field values.

**6. Common Usage Errors:**

This section required some thinking about how the *decoder* might be misused or encounter errors:

* **Insufficient Data:**  The decoder expects a certain number of bytes. Providing less would cause a problem.
* **Incorrect Data Format:**  Feeding arbitrary bytes that don't conform to the HTTP/2 structure format would lead to incorrect parsing.
* **Logic Errors in Decoder Implementation:**  Although the *test* file doesn't directly cause these, it's designed to *detect* them. A bug in `decode_http2_structures.h` could lead to incorrect decoding.

**7. Debugging Steps:**

This involves tracing how user actions in a browser might lead to this code being executed:

* **User types a URL and presses Enter:** This triggers a network request.
* **Browser establishes an HTTP/2 connection:** The browser and server negotiate to use HTTP/2.
* **Server sends HTTP/2 frames:** The server responds with data formatted according to HTTP/2.
* **Chromium's networking stack receives the data:** This is where the decoding logic comes in.
* **`DecodeHttp2Structures` is called:**  The core decoding functions are invoked to parse the incoming frames.
* **This test file simulates that process:**  The test cases mimic the server sending various HTTP/2 structures.

**8. Refinement and Organization:**

Finally, I organized the information into clear sections as requested by the prompt. I used headings and bullet points to improve readability. I also ensured that the language was precise and accurate in describing the technical details.

**Self-Correction/Refinement during the process:**

* Initially, I might have just said "it tests HTTP/2 decoding." I refined this to be more specific: "tests the correct decoding of *various fixed-size* HTTP/2 data structures."
* I considered just listing the test class names but realized explaining what each class represents (a specific HTTP/2 structure) would be more helpful.
*  For the JavaScript connection, I initially thought of just saying "browsers use HTTP/2."  I refined it to explain *how* JavaScript interacts (via `fetch`) and where the decoding happens (in the underlying network stack).
* I made sure the example inputs and outputs in the "Logical Reasoning" section were concrete and easy to understand.

By following these steps, I arrived at the comprehensive explanation provided in the initial prompt. The key was to systematically analyze the code, identify its purpose, connect it to the broader context of web browsing and HTTP/2, and provide concrete examples and scenarios.
这个C++源文件 `decode_http2_structures_test.cc` 的主要功能是：**测试 Chromium 网络栈中用于解码各种固定大小的 HTTP/2 数据结构的解码器是否正确工作。**

更具体地说，它包含了一系列单元测试，用于验证 `quiche/http2/decoder/decode_http2_structures.h` 中定义的解码逻辑对于不同的 HTTP/2 结构（如帧头、优先级字段、RST_STREAM 帧的字段等等）是否能够正确地将原始字节流解析为相应的结构体。

**以下是根据你的要求进行的详细说明：**

**1. 功能列举:**

* **测试 HTTP/2 结构体的解码:**  该文件是专门用来测试解码功能的，针对的是 `quiche/http2/http2_structures.h` 中定义的各种 HTTP/2 结构体。这些结构体定义了 HTTP/2 协议中不同帧类型的特定字段布局。
* **单元测试:**  它使用了 Google Test 框架 (`quiche/common/platform/api/quiche_test.h`) 来编写单元测试。每个 `TEST_F` 宏定义了一个独立的测试用例，针对特定的 HTTP/2 结构体进行解码测试。
* **正向测试 (Positive Testing):**  测试用例中通常会提供一些预期的字节序列，然后使用解码器进行解码，并断言解码后的结构体内容与预期一致。这验证了解码器在正常情况下的工作是否正确。
* **随机测试 (Randomized Testing):**  一些测试用例（通过 `TestDecodingRandomizedStructures` 函数实现）会生成随机的结构体数据，将其编码成字节流，然后再解码，以此来测试解码器在各种随机输入下的健壮性。
* **边界测试 (Implicit):**  虽然没有明确的边界测试用例，但通过提供特定的字节序列（例如，最大值、最小值等），也可以隐式地测试解码器在边界条件下的行为。
* **覆盖多种 HTTP/2 结构体:** 文件中包含了针对多种 HTTP/2 结构体的测试，例如 `Http2FrameHeader`, `Http2PriorityFields`, `Http2RstStreamFields`, `Http2SettingFields`, `Http2PushPromiseFields`, `Http2PingFields`, `Http2GoAwayFields`, `Http2WindowUpdateFields`, 和 `Http2AltSvcFields`。

**2. 与 JavaScript 功能的关系及举例说明:**

虽然这个 C++ 代码本身不是 JavaScript，但它在浏览器网络栈中扮演着至关重要的角色，直接影响着 JavaScript 发起的网络请求 (例如使用 `fetch` API 或 `XMLHttpRequest`) 的行为。

* **HTTP/2 协议的实现基础:** 当 JavaScript 发起一个网络请求，且浏览器与服务器之间协商使用 HTTP/2 协议时，浏览器会接收到服务器发送的 HTTP/2 帧。
* **解码是理解帧内容的关键:**  这些 HTTP/2 帧是以二进制格式编码的，而 `decode_http2_structures.h` 中定义的解码器（以及这个测试文件所测试的逻辑）负责将这些二进制数据解析成浏览器能够理解的结构化数据。
* **影响 JavaScript 可访问的信息:**  解码后的 HTTP/2 帧头、首部信息等会最终传递给浏览器的 JavaScript 环境，例如可以通过 `fetch` API 的 `Headers` 对象访问到解码后的 HTTP 首部。

**举例说明:**

假设 JavaScript 代码使用 `fetch` API 向服务器请求一个资源：

```javascript
fetch('https://example.com/data')
  .then(response => {
    console.log(response.headers.get('content-type'));
  });
```

在这个过程中，如果服务器使用 HTTP/2 协议响应，服务器会发送一个包含 HTTP 首部的 HEADERS 帧。  `decode_http2_structures_test.cc` 中测试的解码逻辑就负责解析这个 HEADERS 帧，提取出 `content-type` 等首部信息。  如果解码逻辑出现错误，那么 `response.headers.get('content-type')` 可能返回错误的值，或者导致网络请求失败。

**3. 逻辑推理及假设输入与输出:**

以 `FrameHeaderDecoderTest::DecodesLiteral` 中的一个测试用例为例：

**假设输入:**  一个包含 HEADERS 帧头的字节序列：

```
'\x00', '\x00', '\x05',          // Payload length: 5
'\x01',                          // Frame type: HEADERS
'\x08',                          // Flags: PADDED
'\x00', '\x00', '\x00', '\x01',  // Stream ID: 1
'\x04',                          // Padding length: 4
'\x00', '\x00', '\x00', '\x00'   // Padding bytes
```

**解码过程:**  `DecodeLeadingStructure` 函数会将这些字节传递给解码器。解码器会按照 HTTP/2 帧头的格式解析这些字节。

**预期输出 (解码后的 `Http2FrameHeader` 结构体内容):**

```
structure_.payload_length = 5u;
structure_.type = Http2FrameType::HEADERS;
structure_.flags = Http2FrameFlag::PADDED;
structure_.stream_id = 1u;
```

**逻辑推理:**  解码器根据 HTTP/2 协议的规范，将前 3 个字节解释为 Payload Length，第 4 个字节解释为 Frame Type，第 5 个字节解释为 Flags，接下来的 4 个字节解释为 Stream ID。

**4. 涉及用户或编程常见的使用错误及举例说明:**

这个测试文件本身是用来测试解码器实现的，所以直接的用户操作不会触发这里的错误。然而，它所测试的解码器可能会因为以下原因导致问题，这些问题最终可能会影响用户体验或开发者的编程：

* **服务器发送的 HTTP/2 帧格式错误:** 如果服务器实现有 bug，发送了不符合 HTTP/2 规范的帧，解码器可能会无法正确解析，导致连接错误或者数据丢失。
    * **例子:** 服务器发送的 HEADERS 帧，其 Payload Length 字段与实际的负载长度不符。解码器可能会读取超出实际数据范围的内存，或者提前结束解码，导致数据不完整。
* **网络传输错误导致帧数据损坏:** 虽然 HTTP/2 有错误检测机制，但在极端情况下，网络传输错误可能会导致接收到的帧数据被破坏。解码器可能会因为数据校验失败而拒绝处理，或者解析出错误的结果。
    * **例子:**  一个 PING 帧的 8 字节 opaque 数据在传输过程中发生 bit 翻转。解码器解析出的 opaque 数据与发送端不一致。
* **解码器实现本身的 Bug:**  `decode_http2_structures.h` 中的解码逻辑如果存在错误，即使服务器发送的是合法的帧，也可能导致解码失败或得到错误的结果。
    * **例子:** 解码器在处理设置帧 (SETTINGS frame) 时，对于某些特定的参数值没有按照规范进行处理。

**5. 用户操作是如何一步步的到达这里，作为调试线索:**

要调试与 HTTP/2 解码相关的问题，可以按照以下步骤逐步追踪：

1. **用户操作触发网络请求:**  用户在浏览器中输入 URL 并访问网页，或者 JavaScript 代码发起 `fetch` 或 `XMLHttpRequest` 请求。
2. **浏览器与服务器建立 HTTP/2 连接:**  在 TCP 连接建立之后，浏览器和服务器会进行协议协商，如果双方都支持 HTTP/2，则会升级到 HTTP/2 协议。
3. **服务器发送 HTTP/2 帧:**  服务器会根据请求发送各种 HTTP/2 帧，例如 HEADERS 帧 (包含响应头)，DATA 帧 (包含响应体)，SETTINGS 帧 (设置连接参数) 等。
4. **Chromium 网络栈接收数据:** 浏览器底层的网络栈 (即 Chromium 的网络模块) 会接收到服务器发送的二进制数据。
5. **HTTP/2 解码器介入:**  接收到的二进制数据会被传递给 HTTP/2 解码器进行解析。这个解码器使用了 `decode_http2_structures.h` 中定义的逻辑。
6. **`DecodeLeadingStructure` 或类似的函数被调用:**  在接收到完整的 HTTP/2 帧后，相应的解码函数 (例如 `DecodeFrameHeader`, `DecodePriorityFields` 等) 会被调用，这些函数内部会使用类似 `DecodeLeadingStructure` 中使用的 `DecodeBuffer` 来读取和解析数据。
7. **测试代码模拟了上述过程:**  `decode_http2_structures_test.cc` 中的测试用例通过构造不同的字节序列，模拟了服务器发送各种 HTTP/2 帧的情况，并验证了解码器的行为。

**调试线索:**

* **抓包分析:** 使用 Wireshark 等网络抓包工具可以查看浏览器和服务器之间传输的原始 HTTP/2 帧数据，这可以帮助判断服务器发送的帧是否符合规范。
* **Chromium 网络日志:** Chromium 提供了详细的网络日志功能 (可以通过 `chrome://net-export/` 生成)，可以记录 HTTP/2 连接的详细信息，包括发送和接收的帧数据，以及解码过程中的一些状态信息。
* **断点调试:** 如果怀疑解码器本身存在问题，可以在 `decode_http2_structures.cc` (实际的解码实现文件) 或相关的代码中设置断点，逐步跟踪解码过程，查看变量的值，分析解码逻辑是否正确。  `decode_http2_structures_test.cc` 中的测试用例也可以作为调试的起点，通过运行特定的测试用例来复现问题。

总而言之，`decode_http2_structures_test.cc` 是 Chromium 网络栈中一个非常重要的测试文件，它确保了 HTTP/2 协议的基础解码功能的正确性，这直接关系到浏览器与服务器之间的正常通信以及用户最终的网络体验。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/decoder/decode_http2_structures_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/http2/decoder/decode_http2_structures.h"

// Tests decoding all of the fixed size HTTP/2 structures (i.e. those defined
// in quiche/http2/http2_structures.h).

#include <stddef.h>

#include <string>

#include "absl/strings/string_view.h"
#include "quiche/http2/decoder/decode_buffer.h"
#include "quiche/http2/decoder/decode_status.h"
#include "quiche/http2/http2_constants.h"
#include "quiche/http2/test_tools/http2_frame_builder.h"
#include "quiche/http2/test_tools/http2_random.h"
#include "quiche/http2/test_tools/http2_structures_test_util.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace http2 {
namespace test {
namespace {

template <typename T, size_t N>
absl::string_view ToStringPiece(T (&data)[N]) {
  return absl::string_view(reinterpret_cast<const char*>(data), N * sizeof(T));
}

template <class S>
std::string SerializeStructure(const S& s) {
  Http2FrameBuilder fb;
  fb.Append(s);
  EXPECT_EQ(S::EncodedSize(), fb.size());
  return fb.buffer();
}

template <class S>
class StructureDecoderTest : public quiche::test::QuicheTest {
 protected:
  typedef S Structure;

  StructureDecoderTest() : random_(), random_decode_count_(100) {}

  // Set the fields of |*p| to random values.
  void Randomize(S* p) { ::http2::test::Randomize(p, &random_); }

  // Fully decodes the Structure at the start of data, and confirms it matches
  // *expected (if provided).
  void DecodeLeadingStructure(const S* expected, absl::string_view data) {
    ASSERT_LE(S::EncodedSize(), data.size());
    DecodeBuffer db(data);
    Randomize(&structure_);
    DoDecode(&structure_, &db);
    EXPECT_EQ(db.Offset(), S::EncodedSize());
    if (expected != nullptr) {
      EXPECT_EQ(structure_, *expected);
    }
  }

  template <size_t N>
  void DecodeLeadingStructure(const char (&data)[N]) {
    DecodeLeadingStructure(nullptr, absl::string_view(data, N));
  }

  // Encode the structure |in_s| into bytes, then decode the bytes
  // and validate that the decoder produced the same field values.
  void EncodeThenDecode(const S& in_s) {
    std::string bytes = SerializeStructure(in_s);
    EXPECT_EQ(S::EncodedSize(), bytes.size());
    DecodeLeadingStructure(&in_s, bytes);
  }

  // Generate
  void TestDecodingRandomizedStructures(size_t count) {
    for (size_t i = 0; i < count && !HasFailure(); ++i) {
      Structure input;
      Randomize(&input);
      EncodeThenDecode(input);
    }
  }

  void TestDecodingRandomizedStructures() {
    TestDecodingRandomizedStructures(random_decode_count_);
  }

  Http2Random random_;
  const size_t random_decode_count_;
  uint32_t decode_offset_ = 0;
  S structure_;
  size_t fast_decode_count_ = 0;
  size_t slow_decode_count_ = 0;
};

class FrameHeaderDecoderTest : public StructureDecoderTest<Http2FrameHeader> {};

TEST_F(FrameHeaderDecoderTest, DecodesLiteral) {
  {
    // Realistic input.
    const char kData[] = {
        '\x00', '\x00', '\x05',          // Payload length: 5
        '\x01',                          // Frame type: HEADERS
        '\x08',                          // Flags: PADDED
        '\x00', '\x00', '\x00', '\x01',  // Stream ID: 1
        '\x04',                          // Padding length: 4
        '\x00', '\x00', '\x00', '\x00',  // Padding bytes
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(5u, structure_.payload_length);
      EXPECT_EQ(Http2FrameType::HEADERS, structure_.type);
      EXPECT_EQ(Http2FrameFlag::PADDED, structure_.flags);
      EXPECT_EQ(1u, structure_.stream_id);
    }
  }
  {
    // Unlikely input.
    const char kData[] = {
        '\xff', '\xff', '\xff',          // Payload length: uint24 max
        '\xff',                          // Frame type: Unknown
        '\xff',                          // Flags: Unknown/All
        '\xff', '\xff', '\xff', '\xff',  // Stream ID: uint31 max, plus R-bit
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ((1u << 24) - 1, structure_.payload_length);
      EXPECT_EQ(static_cast<Http2FrameType>(255), structure_.type);
      EXPECT_EQ(255, structure_.flags);
      EXPECT_EQ(0x7FFFFFFFu, structure_.stream_id);
    }
  }
}

TEST_F(FrameHeaderDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures();
}

//------------------------------------------------------------------------------

class PriorityFieldsDecoderTest
    : public StructureDecoderTest<Http2PriorityFields> {};

TEST_F(PriorityFieldsDecoderTest, DecodesLiteral) {
  {
    const char kData[] = {
        '\x80', '\x00', '\x00', '\x05',  // Exclusive (yes) and Dependency (5)
        '\xff',                          // Weight: 256 (after adding 1)
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(5u, structure_.stream_dependency);
      EXPECT_EQ(256u, structure_.weight);
      EXPECT_EQ(true, structure_.is_exclusive);
    }
  }
  {
    const char kData[] = {
        '\x7f', '\xff',
        '\xff', '\xff',  // Exclusive (no) and Dependency (0x7fffffff)
        '\x00',          // Weight: 1 (after adding 1)
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(StreamIdMask(), structure_.stream_dependency);
      EXPECT_EQ(1u, structure_.weight);
      EXPECT_FALSE(structure_.is_exclusive);
    }
  }
}

TEST_F(PriorityFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures();
}

//------------------------------------------------------------------------------

class RstStreamFieldsDecoderTest
    : public StructureDecoderTest<Http2RstStreamFields> {};

TEST_F(RstStreamFieldsDecoderTest, DecodesLiteral) {
  {
    const char kData[] = {
        '\x00', '\x00', '\x00', '\x01',  // Error: PROTOCOL_ERROR
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_TRUE(structure_.IsSupportedErrorCode());
      EXPECT_EQ(Http2ErrorCode::PROTOCOL_ERROR, structure_.error_code);
    }
  }
  {
    const char kData[] = {
        '\xff', '\xff', '\xff',
        '\xff',  // Error: max uint32 (Unknown error code)
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_FALSE(structure_.IsSupportedErrorCode());
      EXPECT_EQ(static_cast<Http2ErrorCode>(0xffffffff), structure_.error_code);
    }
  }
}

TEST_F(RstStreamFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures();
}

//------------------------------------------------------------------------------

class SettingFieldsDecoderTest
    : public StructureDecoderTest<Http2SettingFields> {};

TEST_F(SettingFieldsDecoderTest, DecodesLiteral) {
  {
    const char kData[] = {
        '\x00', '\x01',                  // Setting: HEADER_TABLE_SIZE
        '\x00', '\x00', '\x40', '\x00',  // Value: 16K
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_TRUE(structure_.IsSupportedParameter());
      EXPECT_EQ(Http2SettingsParameter::HEADER_TABLE_SIZE,
                structure_.parameter);
      EXPECT_EQ(1u << 14, structure_.value);
    }
  }
  {
    const char kData[] = {
        '\x00', '\x00',                  // Setting: Unknown (0)
        '\xff', '\xff', '\xff', '\xff',  // Value: max uint32
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_FALSE(structure_.IsSupportedParameter());
      EXPECT_EQ(static_cast<Http2SettingsParameter>(0), structure_.parameter);
    }
  }
}

TEST_F(SettingFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures();
}

//------------------------------------------------------------------------------

class PushPromiseFieldsDecoderTest
    : public StructureDecoderTest<Http2PushPromiseFields> {};

TEST_F(PushPromiseFieldsDecoderTest, DecodesLiteral) {
  {
    const char kData[] = {
        '\x00', '\x01', '\x8a', '\x92',  // Promised Stream ID: 101010
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(101010u, structure_.promised_stream_id);
    }
  }
  {
    // Promised stream id has R-bit (reserved for future use) set, which
    // should be cleared by the decoder.
    const char kData[] = {
        '\xff', '\xff', '\xff',
        '\xff',  // Promised Stream ID: max uint31 and R-bit
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(StreamIdMask(), structure_.promised_stream_id);
    }
  }
}

TEST_F(PushPromiseFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures();
}

//------------------------------------------------------------------------------

class PingFieldsDecoderTest : public StructureDecoderTest<Http2PingFields> {};

TEST_F(PingFieldsDecoderTest, DecodesLiteral) {
  {
    // Each byte is different, so can detect if order changed.
    const char kData[] = {
        '\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07',
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(absl::string_view(kData, 8),
                ToStringPiece(structure_.opaque_bytes));
    }
  }
  {
    // All zeros, detect problems handling NULs.
    const char kData[] = {
        '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(absl::string_view(kData, 8),
                ToStringPiece(structure_.opaque_bytes));
    }
  }
  {
    const char kData[] = {
        '\xff', '\xff', '\xff', '\xff', '\xff', '\xff', '\xff', '\xff',
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(absl::string_view(kData, 8),
                ToStringPiece(structure_.opaque_bytes));
    }
  }
}

TEST_F(PingFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures();
}

//------------------------------------------------------------------------------

class GoAwayFieldsDecoderTest : public StructureDecoderTest<Http2GoAwayFields> {
};

TEST_F(GoAwayFieldsDecoderTest, DecodesLiteral) {
  {
    const char kData[] = {
        '\x00', '\x00', '\x00', '\x00',  // Last Stream ID: 0
        '\x00', '\x00', '\x00', '\x00',  // Error: NO_ERROR (0)
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(0u, structure_.last_stream_id);
      EXPECT_TRUE(structure_.IsSupportedErrorCode());
      EXPECT_EQ(Http2ErrorCode::HTTP2_NO_ERROR, structure_.error_code);
    }
  }
  {
    const char kData[] = {
        '\x00', '\x00', '\x00', '\x01',  // Last Stream ID: 1
        '\x00', '\x00', '\x00', '\x0d',  // Error: HTTP_1_1_REQUIRED
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(1u, structure_.last_stream_id);
      EXPECT_TRUE(structure_.IsSupportedErrorCode());
      EXPECT_EQ(Http2ErrorCode::HTTP_1_1_REQUIRED, structure_.error_code);
    }
  }
  {
    const char kData[] = {
        '\xff', '\xff',
        '\xff', '\xff',  // Last Stream ID: max uint31 and R-bit
        '\xff', '\xff',
        '\xff', '\xff',  // Error: max uint32 (Unknown error code)
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(StreamIdMask(), structure_.last_stream_id);  // No high-bit.
      EXPECT_FALSE(structure_.IsSupportedErrorCode());
      EXPECT_EQ(static_cast<Http2ErrorCode>(0xffffffff), structure_.error_code);
    }
  }
}

TEST_F(GoAwayFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures();
}

//------------------------------------------------------------------------------

class WindowUpdateFieldsDecoderTest
    : public StructureDecoderTest<Http2WindowUpdateFields> {};

TEST_F(WindowUpdateFieldsDecoderTest, DecodesLiteral) {
  {
    const char kData[] = {
        '\x00', '\x01', '\x00', '\x00',  // Window Size Increment: 2 ^ 16
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(1u << 16, structure_.window_size_increment);
    }
  }
  {
    // Increment must be non-zero, but we need to be able to decode the invalid
    // zero to detect it.
    const char kData[] = {
        '\x00', '\x00', '\x00', '\x00',  // Window Size Increment: 0
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(0u, structure_.window_size_increment);
    }
  }
  {
    // Increment has R-bit (reserved for future use) set, which
    // should be cleared by the decoder.
    // clang-format off
    const char kData[] = {
        // Window Size Increment: max uint31 and R-bit
        '\xff', '\xff', '\xff', '\xff',
    };
    // clang-format on
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(StreamIdMask(), structure_.window_size_increment);
    }
  }
}

TEST_F(WindowUpdateFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures();
}

//------------------------------------------------------------------------------

class AltSvcFieldsDecoderTest : public StructureDecoderTest<Http2AltSvcFields> {
};

TEST_F(AltSvcFieldsDecoderTest, DecodesLiteral) {
  {
    const char kData[] = {
        '\x00', '\x00',  // Origin Length: 0
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(0, structure_.origin_length);
    }
  }
  {
    const char kData[] = {
        '\x00', '\x14',  // Origin Length: 20
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(20, structure_.origin_length);
    }
  }
  {
    const char kData[] = {
        '\xff', '\xff',  // Origin Length: uint16 max
    };
    DecodeLeadingStructure(kData);
    if (!HasFailure()) {
      EXPECT_EQ(65535, structure_.origin_length);
    }
  }
}

TEST_F(AltSvcFieldsDecoderTest, DecodesRandomized) {
  TestDecodingRandomizedStructures();
}

}  // namespace
}  // namespace test
}  // namespace http2
```