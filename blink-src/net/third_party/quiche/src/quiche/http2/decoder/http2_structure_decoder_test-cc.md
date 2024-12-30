Response:
Let's break down the thought process for analyzing this C++ test file and generating the detailed response.

**1. Initial Understanding - What is the Goal?**

The first step is to understand the purpose of the file. The comments at the top clearly state: "Tests decoding all of the fixed size HTTP/2 structures... using Http2StructureDecoder..."  This tells us the core functionality being tested is the `Http2StructureDecoder`'s ability to handle the fixed-size components of HTTP/2 frames.

**2. Identifying Key Components:**

Next, I'd scan the code for important classes and functions. I'd immediately notice:

* `#include "quiche/http2/decoder/http2_structure_decoder.h"`: This is the class being tested.
* Various `#include "quiche/http2/http2_structures.h"` (implicitly): The "fixed size HTTP/2 structures" being decoded.
* `Http2StructureDecoderTest`: This is the main test fixture, a template class.
* `StartDecoding`, `ResumeDecoding`: These methods are central to the decoder's logic.
* `DecodeLeadingStructure`, `EncodeThenDecode`, `TestDecodingRandomizedStructures`: These are helper functions for structuring the tests.
* Individual test classes like `Http2FrameHeaderDecoderTest`, `Http2PriorityFieldsDecoderTest`, etc.: These indicate specific HTTP/2 structures being tested.
* `TEST_F`:  This is the Google Test macro for defining test cases.

**3. Deconstructing the Test Structure:**

The `Http2StructureDecoderTest` template is crucial. I'd analyze its methods:

* `StartDecoding`: How the decoding process begins. It checks if the entire structure is available at once.
* `ResumeDecoding`: How decoding continues when the structure is split across buffers.
* `DecodeLeadingStructure`:  A key function for performing the decoding and validation. It handles different ways the input buffer can be segmented.
* `EncodeThenDecode`:  A standard test pattern: encode, then decode, then compare.
* `TestDecodingRandomizedStructures`:  Tests robustness by feeding random data.

**4. Focusing on Functionality (Instruction 1):**

Based on the understanding of the test structure and the included headers, I would list the core functionalities:

* **Decoding Fixed-Size HTTP/2 Structures:**  This is the primary function. List examples like `Http2FrameHeader`, `Http2SettingsFields`, etc.
* **Handling Incomplete Data:** The `StartDecoding` and `ResumeDecoding` logic is specifically for testing how the decoder deals with data arriving in chunks.
* **Validation:** The tests use assertions (`EXPECT_EQ`, `ASSERT_TRUE`) to verify the correctness of the decoded data.
* **Randomized Testing:**  Ensuring robustness against various input patterns.

**5. Considering JavaScript Relationship (Instruction 2):**

This requires connecting the C++ HTTP/2 implementation to the browser's JavaScript environment. I would think about:

* **Network Requests:**  JavaScript's `fetch` API or `XMLHttpRequest` initiate network requests.
* **Browser's Internal Handling:**  The browser's network stack (where this C++ code resides) handles the underlying HTTP/2 protocol.
* **Data Representation:**  JavaScript deals with data in terms of strings, buffers, etc. The C++ code works with raw bytes.

This leads to the examples of a JavaScript `fetch` triggering the C++ decoder.

**6. Logical Reasoning - Input/Output (Instruction 3):**

For this, I would pick a specific test case, like `Http2FrameHeaderDecoderTest::DecodesLiteral`. I'd examine the `kData` arrays and the corresponding `EXPECT_EQ` assertions. This allows me to map the byte sequence to the decoded structure's fields.

**7. Common Usage Errors (Instruction 4):**

Here, I need to think from a *programmer's* perspective *using* this decoder (though it's primarily an internal Chromium component). Common errors when working with decoders include:

* **Insufficient Data:** Trying to decode when not enough bytes are available.
* **Incorrect Data Format:** Providing data that doesn't conform to the HTTP/2 structure definition.
* **State Management:** If the decoder had a more complex state machine (though this one seems relatively simple), incorrect state transitions could lead to errors.

**8. User Operations as Debugging Clues (Instruction 5):**

This involves tracing a user action down to the C++ code. I'd consider a typical web browsing scenario:

* **User Action:** Clicking a link, typing a URL, etc.
* **Browser Actions:**  DNS lookup, establishing a connection (potentially HTTP/2), sending a request.
* **Server Response:** The server sends HTTP/2 frames.
* **Decoding:** The `Http2StructureDecoder` comes into play when processing these frames.

This allows me to construct a step-by-step narrative of how a user action can lead to this specific code being executed.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe focus on the `RandomDecoderTest` base class.
* **Correction:** While important, the core logic is within `Http2StructureDecoderTest` and the specific structure tests. Focus on those first.
* **Initial thought:**  The JavaScript connection might be too abstract.
* **Refinement:** Provide concrete examples like `fetch` and the browser's network stack to make the connection clearer.
* **Initial thought:**  The "common usage errors" might be for end-users.
* **Correction:** The context is a C++ test file, so focus on errors a *developer* using this decoder might make.

By following these steps of understanding the purpose, identifying key elements, deconstructing the code, and then specifically addressing each instruction, I can generate a comprehensive and accurate explanation of the given C++ test file.
这个 C++ 文件 `http2_structure_decoder_test.cc` 是 Chromium 网络栈中 QUIC 协议库的一部分，专门用于测试 `Http2StructureDecoder` 类的功能。 `Http2StructureDecoder` 的作用是解码 HTTP/2 协议中固定大小的结构体。

**功能列举:**

1. **测试 HTTP/2 固定大小结构体的解码:**  该文件包含了多个测试用例，针对 `quiche/http2/http2_structures.h` 中定义的各种 HTTP/2 固定大小的结构体，例如 `Http2FrameHeader`, `Http2PriorityFields`, `Http2SettingsFields` 等。
2. **测试跨越输入缓冲区边界的结构体解码:** `Http2StructureDecoder` 的一个重要功能是处理结构体数据被分割在多个输入缓冲区的情况。测试用例会模拟这种情况，验证解码器是否能正确地将分散的数据拼接起来并解码。
3. **测试 `Start` 和 `Resume` 方法:**  `Http2StructureDecoder` 提供了 `Start` 和 `Resume` 方法用于分步解码。测试用例覆盖了这些方法的各种使用场景，包括一次性解码完成和需要多次 `Resume` 才能完成的情况。
4. **使用随机数据进行解码测试:**  为了提高测试的覆盖率和发现潜在的边界情况错误，该文件使用了随机数据生成器来创建各种各样的输入，并验证解码器是否能正确处理。
5. **验证解码结果的正确性:**  每个测试用例都会将解码后的结构体与预期值进行比较，确保解码结果的准确性。
6. **统计快速解码和慢速解码的次数:** 测试代码会记录 `Start` 方法一次性完成解码（快速解码）和需要 `Resume` 方法才能完成解码（慢速解码）的次数，用于分析解码器的性能和处理能力。

**与 JavaScript 功能的关系及举例说明:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的网络栈组件是浏览器与服务器进行 HTTP/2 通信的核心部分。当 JavaScript 发起网络请求时（例如使用 `fetch` API），底层的网络栈会使用这个解码器来解析服务器发送回来的 HTTP/2 数据。

**举例说明:**

假设一个 JavaScript 应用程序使用 `fetch` 发起一个 HTTP/2 GET 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

当服务器响应这个请求时，它会发送 HTTP/2 帧。浏览器接收到这些帧后，网络栈中的 `Http2StructureDecoder` 就会被用来解码这些帧的头部信息，例如：

* **`Http2FrameHeader`:** 解码帧的长度、类型、标志和流 ID。这对于确定如何处理后续的负载数据至关重要。
* **`Http2SettingsFields`:** 如果接收到 SETTINGS 帧，解码器会解析其中的设置参数，例如最大并发流数、头部表大小等。这些参数会影响浏览器的行为。
* **`Http2PriorityFields`:** 如果接收到 PRIORITY 帧，解码器会解析流的优先级信息，浏览器可能会根据这些信息来调整资源加载的顺序。

**逻辑推理、假设输入与输出:**

以 `Http2FrameHeaderDecoderTest::DecodesLiteral` 测试用例为例：

**假设输入:**

```
const char kData[] = {
    0x00, 0x00, 0x05,        // Payload length: 5
    0x01,                    // Frame type: HEADERS
    0x08,                    // Flags: PADDED
    0x00, 0x00, 0x00, 0x01,  // Stream ID: 1
    0x04,                    // Padding length: 4
    0x00, 0x00, 0x00, 0x00,  // Padding bytes
};
```

**逻辑推理:**

`Http2StructureDecoder` 会按照 `Http2FrameHeader` 的结构定义，从 `kData` 中读取相应的字节，并将其转换为结构体的字段值。

* 前 3 个字节 (0x00, 0x00, 0x05) 被解码为 `payload_length`，值为 5。
* 第 4 个字节 (0x01) 被解码为 `type`，对应 `Http2FrameType::HEADERS`。
* 第 5 个字节 (0x08) 被解码为 `flags`，对应 `Http2FrameFlag::PADDED`。
* 接下来的 4 个字节 (0x00, 0x00, 0x00, 0x01) 被解码为 `stream_id`，值为 1。

**预期输出 (解码后的 `Http2FrameHeader` 结构体):**

```
structure_->payload_length == 5u
structure_->type == Http2FrameType::HEADERS
structure_->flags == Http2FrameFlag::PADDED
structure_->stream_id == 1u
```

**用户或编程常见的使用错误举例说明:**

1. **提供的缓冲区数据不足:**  如果调用 `StartDecoding` 或 `ResumeDecoding` 时，提供的 `DecodeBuffer` 中包含的数据量小于当前待解码的结构体的大小，解码器会返回 `DecodeStatus::kDecodeInProgress`，表示解码尚未完成。

   **错误示例:**  假设要解码一个 `Http2FrameHeader` (9 字节)，但只提供了 5 字节的数据。

   ```c++
   Http2StructureDecoder decoder;
   Http2FrameHeader header;
   std::string incomplete_data = "\x00\x00\x05\x01\x08";
   DecodeBuffer buffer(incomplete_data);

   if (decoder.Start(&header, &buffer)) {
     // 错误：这里不应该进入，因为数据不足
   } else {
     // 正确：解码器返回 kDecodeInProgress
   }
   ```

2. **尝试解码非预期类型的帧负载:** 虽然 `Http2StructureDecoder` 专注于解码固定大小的结构体，但在实际应用中，它通常与其他的解码器（例如用于解码头部列表的 HPACK 解码器）配合使用。如果错误地将某种类型的帧负载（例如 HEADERS 帧的头部块）直接传递给 `Http2StructureDecoder`，会导致解码失败。

   **错误示例:**  假设尝试使用 `Http2SettingsFieldsDecoderTest` 来解码 HEADERS 帧的负载。

   ```c++
   Http2StructureDecoderTest<Http2SettingsFields> settings_decoder_test;
   std::string headers_payload = /* ... 头部块数据 ... */;
   // 错误：headers_payload 的格式不是 Http2SettingFields
   settings_decoder_test.DecodeLeadingStructure(nullptr, headers_payload);
   ```

**用户操作如何一步步到达这里，作为调试线索:**

假设用户在浏览器中访问一个使用 HTTP/2 协议的网站 `https://example.com`。以下是可能到达 `http2_structure_decoder_test.cc` 中测试代码覆盖的解码流程的步骤：

1. **用户在浏览器地址栏输入 `https://example.com` 并按下回车键。**
2. **浏览器发起连接请求。** 如果服务器支持 HTTP/2，浏览器和服务器会进行 ALPN 协商，选择使用 HTTP/2 协议。
3. **建立 HTTP/2 连接。**  TCP 连接建立后，会进行 HTTP/2 连接前言（connection preface）的交换。
4. **浏览器发送 HTTP/2 请求帧。**  例如，发送一个 HEADERS 帧来请求网页的 HTML 内容。
5. **服务器接收到请求并处理。**
6. **服务器构造 HTTP/2 响应帧。**  这可能包括 HEADERS 帧（包含响应头）和 DATA 帧（包含 HTML 内容）。
7. **服务器将响应帧发送回浏览器。**
8. **浏览器接收到 HTTP/2 帧的数据。** 这些数据可能以多个 TCP 包的形式到达，因此可能需要缓冲。
9. **网络栈的 HTTP/2 解码器开始工作。**  当接收到完整的或部分帧数据时，`Http2StructureDecoder` 会被用来解码帧头（`Http2FrameHeader`）。
10. **根据帧类型，可能会调用其他的解码器。** 例如，如果帧类型是 HEADERS，HPACK 解码器会被调用来解析头部列表。
11. **如果接收到 SETTINGS 帧，`Http2StructureDecoder` 会被用来解码 `Http2SettingFields`。** 浏览器会根据这些设置调整其行为。
12. **如果接收到 WINDOW_UPDATE 帧，`Http2StructureDecoder` 会被用来解码 `Http2WindowUpdateFields`。** 这用于流量控制。
13. **如果出现错误，服务器可能会发送 RST_STREAM 或 GOAWAY 帧，`Http2StructureDecoder` 会被用来解码 `Http2RstStreamFields` 或 `Http2GoAwayFields`。**

**作为调试线索:**

当在 Chromium 网络栈中调试 HTTP/2 相关问题时，`http2_structure_decoder_test.cc` 可以作为理解解码流程和验证解码器行为的参考。如果怀疑是帧头或某些固定大小结构体的解码出现问题，可以：

* **查看相关的测试用例:** 找到与怀疑出错的帧类型或结构体相关的测试用例，了解预期的输入和输出。
* **手动构造测试数据:**  根据测试用例中的数据格式，手动构造一些有问题的输入，并在本地运行相关的测试，看是否能复现问题。
* **在实际的网络请求中抓包:** 使用 Wireshark 等工具抓取网络数据包，查看实际接收到的 HTTP/2 帧的原始字节，并与测试用例中的数据进行对比，帮助定位问题。
* **使用 Chromium 的网络日志:** 启用 Chromium 的网络日志（`chrome://net-export/`），可以查看详细的 HTTP/2 事件，包括帧的发送和接收，以及解码过程中的信息。

总之，`http2_structure_decoder_test.cc` 是一个重要的测试文件，它确保了 Chromium 网络栈中 HTTP/2 固定大小结构体的解码功能的正确性和健壮性，对于理解和调试 HTTP/2 相关问题非常有帮助。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/decoder/http2_structure_decoder_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/http2/decoder/http2_structure_decoder.h"

// Tests decoding all of the fixed size HTTP/2 structures (i.e. those defined in
// quiche/http2/http2_structures.h) using Http2StructureDecoder, which
// handles buffering of structures split across input buffer boundaries, and in
// turn uses DoDecode when it has all of a structure in a contiguous buffer.

// NOTE: This tests the first pair of Start and Resume, which don't take
// a remaining_payload parameter. The other pair are well tested via the
// payload decoder tests, though...
// TODO(jamessynge): Create type parameterized tests for Http2StructureDecoder
// where the type is the type of structure, and with testing of both pairs of
// Start and Resume methods; note that it appears that the first pair will be
// used only for Http2FrameHeader, and the other pair only for structures in the
// frame payload.

#include <stddef.h>

#include <cstdint>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "quiche/http2/decoder/decode_buffer.h"
#include "quiche/http2/decoder/decode_status.h"
#include "quiche/http2/http2_constants.h"
#include "quiche/http2/test_tools/http2_frame_builder.h"
#include "quiche/http2/test_tools/http2_structures_test_util.h"
#include "quiche/http2/test_tools/random_decoder_test_base.h"
#include "quiche/http2/test_tools/verify_macros.h"
#include "quiche/common/platform/api/quiche_logging.h"

using ::testing::AssertionSuccess;

namespace http2 {
namespace test {
namespace {
const bool kMayReturnZeroOnFirst = false;

template <class S>
class Http2StructureDecoderTest : public RandomDecoderTest {
 protected:
  typedef S Structure;

  Http2StructureDecoderTest() {
    // IF the test adds more data after the encoded structure, stop as
    // soon as the structure is decoded.
    stop_decode_on_done_ = true;
  }

  DecodeStatus StartDecoding(DecodeBuffer* b) override {
    // Overwrite the current contents of |structure_|, into which we'll
    // decode the buffer, so that we can be confident that we really decoded
    // the structure every time.
    structure_ = std::make_unique<S>();
    uint32_t old_remaining = b->Remaining();
    if (structure_decoder_.Start(structure_.get(), b)) {
      EXPECT_EQ(old_remaining - S::EncodedSize(), b->Remaining());
      ++fast_decode_count_;
      return DecodeStatus::kDecodeDone;
    } else {
      EXPECT_LT(structure_decoder_.offset(), S::EncodedSize());
      EXPECT_EQ(0u, b->Remaining());
      EXPECT_EQ(old_remaining - structure_decoder_.offset(), b->Remaining());
      ++incomplete_start_count_;
      return DecodeStatus::kDecodeInProgress;
    }
  }

  DecodeStatus ResumeDecoding(DecodeBuffer* b) override {
    uint32_t old_offset = structure_decoder_.offset();
    EXPECT_LT(old_offset, S::EncodedSize());
    uint32_t avail = b->Remaining();
    if (structure_decoder_.Resume(structure_.get(), b)) {
      EXPECT_LE(S::EncodedSize(), old_offset + avail);
      EXPECT_EQ(b->Remaining(), avail - (S::EncodedSize() - old_offset));
      ++slow_decode_count_;
      return DecodeStatus::kDecodeDone;
    } else {
      EXPECT_LT(structure_decoder_.offset(), S::EncodedSize());
      EXPECT_EQ(0u, b->Remaining());
      EXPECT_GT(S::EncodedSize(), old_offset + avail);
      ++incomplete_resume_count_;
      return DecodeStatus::kDecodeInProgress;
    }
  }

  // Fully decodes the Structure at the start of data, and confirms it matches
  // *expected (if provided).
  AssertionResult DecodeLeadingStructure(const S* expected,
                                         absl::string_view data) {
    HTTP2_VERIFY_LE(S::EncodedSize(), data.size());
    DecodeBuffer original(data);

    // The validator is called after each of the several times that the input
    // DecodeBuffer is decoded, each with a different segmentation of the input.
    // Validate that structure_ matches the expected value, if provided.
    Validator validator;
    if (expected != nullptr) {
      validator = [expected, this](const DecodeBuffer& /*db*/,
                                   DecodeStatus /*status*/) -> AssertionResult {
        HTTP2_VERIFY_EQ(*expected, *structure_);
        return AssertionSuccess();
      };
    }

    // Before that, validate that decoding is done and that we've advanced
    // the cursor the expected amount.
    validator = ValidateDoneAndOffset(S::EncodedSize(), std::move(validator));

    // Decode several times, with several segmentations of the input buffer.
    fast_decode_count_ = 0;
    slow_decode_count_ = 0;
    incomplete_start_count_ = 0;
    incomplete_resume_count_ = 0;
    HTTP2_VERIFY_SUCCESS(DecodeAndValidateSeveralWays(
        &original, kMayReturnZeroOnFirst, validator));
    HTTP2_VERIFY_FALSE(HasFailure());
    HTTP2_VERIFY_EQ(S::EncodedSize(), structure_decoder_.offset());
    HTTP2_VERIFY_EQ(S::EncodedSize(), original.Offset());
    HTTP2_VERIFY_LT(0u, fast_decode_count_);
    HTTP2_VERIFY_LT(0u, slow_decode_count_);
    HTTP2_VERIFY_LT(0u, incomplete_start_count_);

    // If the structure is large enough so that SelectZeroOrOne will have
    // caused Resume to return false, check that occurred.
    if (S::EncodedSize() >= 2) {
      HTTP2_VERIFY_LE(0u, incomplete_resume_count_);
    } else {
      HTTP2_VERIFY_EQ(0u, incomplete_resume_count_);
    }
    if (expected != nullptr) {
      QUICHE_DVLOG(1) << "DecodeLeadingStructure expected: " << *expected;
      QUICHE_DVLOG(1) << "DecodeLeadingStructure   actual: " << *structure_;
      HTTP2_VERIFY_EQ(*expected, *structure_);
    }
    return AssertionSuccess();
  }

  template <size_t N>
  AssertionResult DecodeLeadingStructure(const char (&data)[N]) {
    return DecodeLeadingStructure(nullptr, absl::string_view(data, N));
  }

  template <size_t N>
  AssertionResult DecodeLeadingStructure(const unsigned char (&data)[N]) {
    return DecodeLeadingStructure(nullptr, ToStringPiece(data));
  }

  // Encode the structure |in_s| into bytes, then decode the bytes
  // and validate that the decoder produced the same field values.
  AssertionResult EncodeThenDecode(const S& in_s) {
    std::string bytes = SerializeStructure(in_s);
    HTTP2_VERIFY_EQ(S::EncodedSize(), bytes.size());
    return DecodeLeadingStructure(&in_s, bytes);
  }

  // Repeatedly fill a structure with random but valid contents, encode it, then
  // decode it, and finally validate that the decoded structure matches the
  // random input. Lather-rinse-and-repeat.
  AssertionResult TestDecodingRandomizedStructures(size_t count) {
    for (size_t i = 0; i < count; ++i) {
      Structure input;
      Randomize(&input, RandomPtr());
      HTTP2_VERIFY_SUCCESS(EncodeThenDecode(input));
    }
    return AssertionSuccess();
  }

  AssertionResult TestDecodingRandomizedStructures() {
    HTTP2_VERIFY_SUCCESS(TestDecodingRandomizedStructures(100));
    return AssertionSuccess();
  }

  uint32_t decode_offset_ = 0;
  std::unique_ptr<S> structure_;
  Http2StructureDecoder structure_decoder_;
  size_t fast_decode_count_ = 0;
  size_t slow_decode_count_ = 0;
  size_t incomplete_start_count_ = 0;
  size_t incomplete_resume_count_ = 0;
};

class Http2FrameHeaderDecoderTest
    : public Http2StructureDecoderTest<Http2FrameHeader> {};

TEST_F(Http2FrameHeaderDecoderTest, DecodesLiteral) {
  {
    // Realistic input.
    // clang-format off
    const char kData[] = {
        0x00, 0x00, 0x05,        // Payload length: 5
        0x01,                    // Frame type: HEADERS
        0x08,                    // Flags: PADDED
        0x00, 0x00, 0x00, 0x01,  // Stream ID: 1
        0x04,                    // Padding length: 4
        0x00, 0x00, 0x00, 0x00,  // Padding bytes
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(5u, structure_->payload_length);
    EXPECT_EQ(Http2FrameType::HEADERS, structure_->type);
    EXPECT_EQ(Http2FrameFlag::PADDED, structure_->flags);
    EXPECT_EQ(1u, structure_->stream_id);
  }
  {
    // Unlikely input.
    // clang-format off
    const unsigned char kData[] = {
        0xff, 0xff, 0xff,        // Payload length: uint24 max
        0xff,                    // Frame type: Unknown
        0xff,                    // Flags: Unknown/All
        0xff, 0xff, 0xff, 0xff,  // Stream ID: uint31 max, plus R-bit
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ((1u << 24) - 1u, structure_->payload_length);
    EXPECT_EQ(static_cast<Http2FrameType>(255), structure_->type);
    EXPECT_EQ(255, structure_->flags);
    EXPECT_EQ(0x7FFFFFFFu, structure_->stream_id);
  }
}

TEST_F(Http2FrameHeaderDecoderTest, DecodesRandomized) {
  EXPECT_TRUE(TestDecodingRandomizedStructures());
}

//------------------------------------------------------------------------------

class Http2PriorityFieldsDecoderTest
    : public Http2StructureDecoderTest<Http2PriorityFields> {};

TEST_F(Http2PriorityFieldsDecoderTest, DecodesLiteral) {
  {
    // clang-format off
    const unsigned char kData[] = {
        0x80, 0x00, 0x00, 0x05,  // Exclusive (yes) and Dependency (5)
        0xff,                    // Weight: 256 (after adding 1)
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(5u, structure_->stream_dependency);
    EXPECT_EQ(256u, structure_->weight);
    EXPECT_EQ(true, structure_->is_exclusive);
  }
  {
    // clang-format off
    const unsigned char kData[] = {
        0x7f, 0xff, 0xff, 0xff,  // Excl. (no) and Dependency (uint31 max)
        0x00,                    // Weight: 1 (after adding 1)
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(StreamIdMask(), structure_->stream_dependency);
    EXPECT_EQ(1u, structure_->weight);
    EXPECT_FALSE(structure_->is_exclusive);
  }
}

TEST_F(Http2PriorityFieldsDecoderTest, DecodesRandomized) {
  EXPECT_TRUE(TestDecodingRandomizedStructures());
}

//------------------------------------------------------------------------------

class Http2RstStreamFieldsDecoderTest
    : public Http2StructureDecoderTest<Http2RstStreamFields> {};

TEST_F(Http2RstStreamFieldsDecoderTest, DecodesLiteral) {
  {
    // clang-format off
    const char kData[] = {
        0x00, 0x00, 0x00, 0x01,  // Error: PROTOCOL_ERROR
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_TRUE(structure_->IsSupportedErrorCode());
    EXPECT_EQ(Http2ErrorCode::PROTOCOL_ERROR, structure_->error_code);
  }
  {
    // clang-format off
    const unsigned char kData[] = {
        0xff, 0xff, 0xff, 0xff,  // Error: max uint32 (Unknown error code)
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_FALSE(structure_->IsSupportedErrorCode());
    EXPECT_EQ(static_cast<Http2ErrorCode>(0xffffffff), structure_->error_code);
  }
}

TEST_F(Http2RstStreamFieldsDecoderTest, DecodesRandomized) {
  EXPECT_TRUE(TestDecodingRandomizedStructures());
}

//------------------------------------------------------------------------------

class Http2SettingFieldsDecoderTest
    : public Http2StructureDecoderTest<Http2SettingFields> {};

TEST_F(Http2SettingFieldsDecoderTest, DecodesLiteral) {
  {
    // clang-format off
    const char kData[] = {
        0x00, 0x01,              // Setting: HEADER_TABLE_SIZE
        0x00, 0x00, 0x40, 0x00,  // Value: 16K
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_TRUE(structure_->IsSupportedParameter());
    EXPECT_EQ(Http2SettingsParameter::HEADER_TABLE_SIZE, structure_->parameter);
    EXPECT_EQ(1u << 14, structure_->value);
  }
  {
    // clang-format off
    const unsigned char kData[] = {
        0x00, 0x00,              // Setting: Unknown (0)
        0xff, 0xff, 0xff, 0xff,  // Value: max uint32
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_FALSE(structure_->IsSupportedParameter());
    EXPECT_EQ(static_cast<Http2SettingsParameter>(0), structure_->parameter);
  }
}

TEST_F(Http2SettingFieldsDecoderTest, DecodesRandomized) {
  EXPECT_TRUE(TestDecodingRandomizedStructures());
}

//------------------------------------------------------------------------------

class Http2PushPromiseFieldsDecoderTest
    : public Http2StructureDecoderTest<Http2PushPromiseFields> {};

TEST_F(Http2PushPromiseFieldsDecoderTest, DecodesLiteral) {
  {
    // clang-format off
    const unsigned char kData[] = {
        0x00, 0x01, 0x8a, 0x92,  // Promised Stream ID: 101010
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(101010u, structure_->promised_stream_id);
  }
  {
    // Promised stream id has R-bit (reserved for future use) set, which
    // should be cleared by the decoder.
    // clang-format off
    const unsigned char kData[] = {
        // Promised Stream ID: max uint31 and R-bit
        0xff, 0xff, 0xff, 0xff,
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(StreamIdMask(), structure_->promised_stream_id);
  }
}

TEST_F(Http2PushPromiseFieldsDecoderTest, DecodesRandomized) {
  EXPECT_TRUE(TestDecodingRandomizedStructures());
}

//------------------------------------------------------------------------------

class Http2PingFieldsDecoderTest
    : public Http2StructureDecoderTest<Http2PingFields> {};

TEST_F(Http2PingFieldsDecoderTest, DecodesLiteral) {
  {
    // Each byte is different, so can detect if order changed.
    const char kData[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    };
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(ToStringPiece(kData), ToStringPiece(structure_->opaque_bytes));
  }
  {
    // All zeros, detect problems handling NULs.
    const char kData[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(ToStringPiece(kData), ToStringPiece(structure_->opaque_bytes));
  }
  {
    const unsigned char kData[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(ToStringPiece(kData), ToStringPiece(structure_->opaque_bytes));
  }
}

TEST_F(Http2PingFieldsDecoderTest, DecodesRandomized) {
  EXPECT_TRUE(TestDecodingRandomizedStructures());
}

//------------------------------------------------------------------------------

class Http2GoAwayFieldsDecoderTest
    : public Http2StructureDecoderTest<Http2GoAwayFields> {};

TEST_F(Http2GoAwayFieldsDecoderTest, DecodesLiteral) {
  {
    // clang-format off
    const char kData[] = {
        0x00, 0x00, 0x00, 0x00,  // Last Stream ID: 0
        0x00, 0x00, 0x00, 0x00,  // Error: NO_ERROR (0)
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(0u, structure_->last_stream_id);
    EXPECT_TRUE(structure_->IsSupportedErrorCode());
    EXPECT_EQ(Http2ErrorCode::HTTP2_NO_ERROR, structure_->error_code);
  }
  {
    // clang-format off
    const char kData[] = {
        0x00, 0x00, 0x00, 0x01,  // Last Stream ID: 1
        0x00, 0x00, 0x00, 0x0d,  // Error: HTTP_1_1_REQUIRED
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(1u, structure_->last_stream_id);
    EXPECT_TRUE(structure_->IsSupportedErrorCode());
    EXPECT_EQ(Http2ErrorCode::HTTP_1_1_REQUIRED, structure_->error_code);
  }
  {
    // clang-format off
    const unsigned char kData[] = {
        0xff, 0xff, 0xff, 0xff,  // Last Stream ID: max uint31 and R-bit
        0xff, 0xff, 0xff, 0xff,  // Error: max uint32 (Unknown error code)
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(StreamIdMask(), structure_->last_stream_id);  // No high-bit.
    EXPECT_FALSE(structure_->IsSupportedErrorCode());
    EXPECT_EQ(static_cast<Http2ErrorCode>(0xffffffff), structure_->error_code);
  }
}

TEST_F(Http2GoAwayFieldsDecoderTest, DecodesRandomized) {
  EXPECT_TRUE(TestDecodingRandomizedStructures());
}

//------------------------------------------------------------------------------

class Http2WindowUpdateFieldsDecoderTest
    : public Http2StructureDecoderTest<Http2WindowUpdateFields> {};

TEST_F(Http2WindowUpdateFieldsDecoderTest, DecodesLiteral) {
  {
    // clang-format off
    const char kData[] = {
        0x00, 0x01, 0x00, 0x00,  // Window Size Increment: 2 ^ 16
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(1u << 16, structure_->window_size_increment);
  }
  {
    // Increment must be non-zero, but we need to be able to decode the invalid
    // zero to detect it.
    // clang-format off
    const char kData[] = {
        0x00, 0x00, 0x00, 0x00,  // Window Size Increment: 0
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(0u, structure_->window_size_increment);
  }
  {
    // Increment has R-bit (reserved for future use) set, which
    // should be cleared by the decoder.
    // clang-format off
    const unsigned char kData[] = {
        // Window Size Increment: max uint31 and R-bit
        0xff, 0xff, 0xff, 0xff,
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(StreamIdMask(), structure_->window_size_increment);
  }
}

TEST_F(Http2WindowUpdateFieldsDecoderTest, DecodesRandomized) {
  EXPECT_TRUE(TestDecodingRandomizedStructures());
}

//------------------------------------------------------------------------------

class Http2AltSvcFieldsDecoderTest
    : public Http2StructureDecoderTest<Http2AltSvcFields> {};

TEST_F(Http2AltSvcFieldsDecoderTest, DecodesLiteral) {
  {
    // clang-format off
    const char kData[] = {
        0x00, 0x00,  // Origin Length: 0
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(0, structure_->origin_length);
  }
  {
    // clang-format off
    const char kData[] = {
        0x00, 0x14,  // Origin Length: 20
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(20, structure_->origin_length);
  }
  {
    // clang-format off
    const unsigned char kData[] = {
        0xff, 0xff,  // Origin Length: uint16 max
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(65535, structure_->origin_length);
  }
}

TEST_F(Http2AltSvcFieldsDecoderTest, DecodesRandomized) {
  EXPECT_TRUE(TestDecodingRandomizedStructures());
}

}  // namespace
}  // namespace test
}  // namespace http2

"""

```