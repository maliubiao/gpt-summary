Response: Let's break down the thought process for analyzing this C++ code and generating the explanation and JavaScript examples.

1. **Understand the Goal:** The request asks for a summary of the C++ code's functionality and, if related to JavaScript, to provide illustrative JavaScript examples.

2. **Initial Code Scan (Keywords and Structure):** Quickly skim the code, looking for key terms and the overall structure. I see:
    * `#include`: Standard C++ includes, suggesting basic input/output, memory management, and containers. Crucially, I spot includes related to Unicode and V8 internals: `"include/v8-isolate.h"`, `"src/strings/unicode-decoder.h"`, `"src/strings/unicode-inl.h"`. This immediately signals that the code is about Unicode handling within the V8 JavaScript engine.
    * `namespace v8 { namespace internal { namespace { ... } } }`:  Namespaces indicate this is part of the V8 engine's internal implementation. The anonymous namespace suggests helper functions for testing.
    * `void DecodeNormally(...)`, `void DecodeUtf16(...)`, `void DecodeIncrementally(...)`:  These function names strongly suggest different ways of decoding UTF-8 byte sequences into Unicode code points. The `Utf16` variant hints at handling surrogate pairs. "Incrementally" suggests processing the input in chunks.
    * `TEST(UnicodeTest, ...)`: This clearly indicates these are unit tests specifically for Unicode functionality. The test names (`Utf16BufferReuse`, `SurrogateOverrunsBuffer`, `IncrementalUTF8DecodingVsNonIncrementalUtf8Decoding`) give clues about what each test verifies.
    * `GC_INSIDE_NEW_STRING_FROM_UTF8_SUB_STRING(...)`: This macro and the `UnicodeWithGCTest` class point towards tests involving garbage collection and string creation from UTF-8 substrings.

3. **Deep Dive into Key Functions:** Focus on the decoding functions:
    * `DecodeNormally`:  Uses `unibrow::Utf8::ValueOf` in a loop. This seems like a straightforward, non-incremental decoding method.
    * `DecodeUtf16`:  This is more involved. It uses `Utf8Decoder`, gets the UTF-16 length, decodes to UTF-16, and *then* iterates through the UTF-16, combining surrogate pairs if necessary to get the final Unicode code points. This is crucial for understanding how V8 handles characters outside the Basic Multilingual Plane (BMP).
    * `DecodeIncrementally`: Uses `unibrow::Utf8::ValueOfIncremental`. The presence of `buffer` and `state` variables confirms that this function processes the UTF-8 byte stream piece by piece, maintaining internal state.

4. **Analyze the Tests:**  Examine the test cases:
    * `Utf16BufferReuse`:  The test data includes sequences where a multi-byte UTF-8 character is split across the end of one sequence and the beginning of another. This suggests testing how the decoder handles state and potential buffer overlaps.
    * `SurrogateOverrunsBuffer`: Tests a scenario where a surrogate pair might be split across buffer boundaries.
    * `IncrementalUTF8DecodingVsNonIncrementalUtf8Decoding`: This is a comprehensive test comparing the output of the incremental and non-incremental decoders against a set of expected Unicode code points for various valid and invalid UTF-8 sequences. The test cases cover correct UTF-8, boundary conditions, malformed sequences, lonely first bytes, incomplete sequences, impossible bytes, overlong sequences, and illegal code positions (like lone surrogates). This test is vital for verifying the correctness and robustness of V8's UTF-8 decoding.
    * `GC_INSIDE_NEW_STRING_FROM_UTF8_SUB_STRING`: These tests focus on how garbage collection interacts with the creation of new strings from UTF-8 substrings, testing both single-byte and multi-byte character scenarios.

5. **Connect to JavaScript:** Now, think about how these C++ functionalities relate to JavaScript:
    * **String Encoding:** JavaScript strings are internally represented as UTF-16. The C++ code directly deals with UTF-8 decoding *into* a representation that can be used by JavaScript strings.
    * **`charCodeAt()` and `codePointAt()`:**  These JavaScript methods provide access to the underlying Unicode values of characters in a string. `charCodeAt()` returns UTF-16 code units, while `codePointAt()` returns the full Unicode code point, handling surrogate pairs. The `DecodeUtf16` function mirrors the logic needed to implement `codePointAt()`.
    * **String Manipulation:** When you work with strings in JavaScript (e.g., slicing, concatenation), the engine needs to decode the underlying byte representation (often UTF-8 when the string originates from an external source or is created using escape sequences like `\u` or `\u{}`) into its internal UTF-16 format. The decoding functions in the C++ code are fundamental to these operations.
    * **Garbage Collection:** V8's garbage collector manages the memory used by JavaScript objects, including strings. The `GC_INSIDE_...` tests directly relate to ensuring that string creation and garbage collection work correctly together, especially for strings containing Unicode characters.
    * **Error Handling:** The tests with malformed UTF-8 sequences demonstrate how V8 handles invalid input, typically by replacing it with the Unicode replacement character (U+FFFD). This behavior is also observable in JavaScript.

6. **Construct the Explanation:**  Organize the findings into a clear and concise summary. Start with the main purpose (unit tests for Unicode functionality). Then, detail the different decoding methods and what aspects they test. Finally, explain the garbage collection related tests.

7. **Craft JavaScript Examples:** Create simple, illustrative JavaScript code snippets that demonstrate the concepts tested in the C++ code. Focus on:
    * Getting code points using `charCodeAt()` and `codePointAt()`.
    * Showing how surrogate pairs work.
    * Demonstrating the handling of invalid UTF-8 using `decodeURIComponent` and `encodeURIComponent`. (Initially, I might think of directly creating invalid UTF-8 in a JavaScript string, but that's not easily done. Simulating the *effects* of invalid UTF-8 through URL encoding/decoding is a more practical approach.)
    * Showing basic string manipulation with Unicode characters.

8. **Review and Refine:** Read through the explanation and examples to ensure accuracy, clarity, and conciseness. Make sure the connection between the C++ code and JavaScript functionality is explicit. For example, explicitly mention that `DecodeUtf16` is related to how `codePointAt()` works.

This structured approach, starting with a high-level overview and then drilling down into the details, allows for a comprehensive understanding of the code and its relevance to JavaScript. The key is to recognize the core concepts (UTF-8 decoding, UTF-16 representation, surrogate pairs, error handling, garbage collection) and how they manifest in both the C++ implementation and the JavaScript API.
这个C++源代码文件 `v8/test/unittests/strings/unicode-unittest.cc` 是 **V8 JavaScript 引擎** 的一部分，专门用于 **测试其处理 Unicode 字符串的功能是否正确**。

**具体来说，它的功能可以归纳为以下几点：**

1. **定义了多种 UTF-8 解码方式的测试函数：**
   - `DecodeNormally`:  一种标准的 UTF-8 解码方式。
   - `DecodeUtf16`:  一种先将 UTF-8 解码成 UTF-16，然后再转换成 Unicode 代码点的方式，这更贴近 JavaScript 内部处理字符串的方式。它特别处理了 UTF-16 代理对（surrogate pairs）。
   - `DecodeIncrementally`:  一种增量式的 UTF-8 解码方式，模拟分段接收 UTF-8 数据的情况。

2. **包含了大量的测试用例（TestCase）：** 这些测试用例覆盖了各种不同的 UTF-8 编码场景，包括：
   - **正确的 UTF-8 编码：** 验证解码器能否正确处理合法的 UTF-8 序列。
   - **边界情况：** 测试不同长度 UTF-8 序列的起始和结束。
   - **错误的 UTF-8 编码：**  测试解码器如何处理不合法的 UTF-8 序列，例如：
     - 意外的延续字节
     - 不完整的序列
     - 不可能的字节值
     - 过长的编码
     - 非法的代码点位置（例如单独的 UTF-16 代理对）
   - **非字符（Non-characters）：** 验证对 Unicode 标准中定义的非字符的处理。

3. **对比不同的解码结果：**  测试用例会使用不同的解码函数对同一组 UTF-8 字节进行解码，并比较结果是否一致，确保 V8 的各种 UTF-8 解码实现是正确的。

4. **测试 UTF-16 缓冲区的重用和溢出情况：** `Utf16BufferReuse` 和 `SurrogateOverrunsBuffer` 两个测试针对 `DecodeUtf16` 函数，检查在处理 UTF-16 转换时，缓冲区管理和代理对的处理是否正确。

5. **测试在垃圾回收期间创建 UTF-8 子字符串的情况：** `GC_INSIDE_NEW_STRING_FROM_UTF8_SUB_STRING` 宏定义了一系列测试，模拟在创建新的 UTF-8 子字符串时触发垃圾回收的情况，确保 V8 在这种复杂场景下也能正确处理字符串和内存。

**它与 JavaScript 的功能有密切关系：**

JavaScript 内部使用 UTF-16 编码来表示字符串。当 JavaScript 引擎（例如 V8）需要处理来自外部（例如网络请求、文件读取）的 UTF-8 数据时，就需要进行 UTF-8 到 UTF-16 的解码。

**JavaScript 例子说明：**

```javascript
// 假设我们有以下 UTF-8 编码的字节数据（表示 "你好"）
const utf8Bytes = [0xE4, 0xBD, 0xA0, 0xE5, 0xA5, 0xBD];

// 在 JavaScript 中，我们可以使用 TextDecoder API 将 UTF-8 字节解码为字符串
const decoder = new TextDecoder();
const decodedString = decoder.decode(new Uint8Array(utf8Bytes));
console.log(decodedString); // 输出: 你好

// 类似于 C++ 代码中的 DecodeNormally 或 DecodeUtf16 的功能

// JavaScript 中获取字符的 Unicode 代码点
console.log(decodedString.charCodeAt(0)); // 输出 "你" 的 UTF-16 编码: 20320
console.log(decodedString.codePointAt(0)); // 输出 "你" 的 Unicode 代码点: 20320

// 对于超出基本多文种平面 (BMP) 的字符，charCodeAt 会返回代理对
const emoji = "😀"; // UTF-8: F0 9F 98 80
console.log(emoji.charCodeAt(0)); // 返回高位代理: 55357
console.log(emoji.charCodeAt(1)); // 返回低位代理: 56832
console.log(emoji.codePointAt(0)); // 返回完整的 Unicode 代码点: 128512

// 这与 C++ 代码中 DecodeUtf16 处理代理对的逻辑相关

// JavaScript 如何处理无效的 UTF-8 数据
try {
  decodeURIComponent("%C0%AF"); // 这是一个无效的 UTF-8 序列
} catch (e) {
  console.error("解码失败:", e); // JavaScript 会抛出 URIError
}

// 类似于 C++ 代码中测试错误 UTF-8 编码的场景，JavaScript 也会有相应的错误处理机制。
```

**总结:**

`unicode-unittest.cc` 文件是 V8 引擎中至关重要的测试组件，它确保了 V8 能够正确可靠地处理各种 Unicode 编码，这直接影响了 JavaScript 中字符串操作的正确性，特别是涉及到非 ASCII 字符和国际化支持时。  它覆盖了 UTF-8 解码的各种细节和边界情况，保证了 V8 作为 JavaScript 引擎的健壮性。

Prompt: 
```
这是目录为v8/test/unittests/strings/unicode-unittest.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <vector>

#include "include/v8-isolate.h"
#include "src/base/vector.h"
#include "src/strings/unicode-decoder.h"
#include "src/strings/unicode-inl.h"
#include "test/unittests/heap/heap-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace v8 {
namespace internal {

namespace {

void DecodeNormally(const std::vector<uint8_t>& bytes,
                    std::vector<unibrow::uchar>* output) {
  size_t cursor = 0;
  while (cursor < bytes.size()) {
    output->push_back(
        unibrow::Utf8::ValueOf(bytes.data() + cursor, bytes.size(), &cursor));
  }
}

void DecodeUtf16(const std::vector<uint8_t>& bytes,
                 std::vector<unibrow::uchar>* output) {
  auto utf8_data = base::VectorOf(bytes);
  Utf8Decoder decoder(utf8_data);

  std::vector<uint16_t> utf16(decoder.utf16_length());
  decoder.Decode(utf16.data(), utf8_data);

  // Decode back into code points
  for (size_t i = 0; i < utf16.size(); i++) {
    uint16_t b = utf16[i];
    if (unibrow::Utf16::IsLeadSurrogate(b)) {
      output->push_back(unibrow::Utf16::CombineSurrogatePair(b, utf16[++i]));
    } else {
      output->push_back(b);
    }
  }
}

void DecodeIncrementally(const std::vector<uint8_t>& bytes,
                         std::vector<unibrow::uchar>* output) {
  unibrow::Utf8::Utf8IncrementalBuffer buffer = 0;
  unibrow::Utf8::State state = unibrow::Utf8::State::kAccept;
  const uint8_t* cursor = bytes.data();
  const uint8_t* end = bytes.data() + bytes.size();
  while (cursor < end) {
    unibrow::uchar result =
        unibrow::Utf8::ValueOfIncremental(&cursor, &state, &buffer);
    if (result != unibrow::Utf8::kIncomplete) {
      output->push_back(result);
    }
  }
  unibrow::uchar result = unibrow::Utf8::ValueOfIncrementalFinish(&state);
  if (result != unibrow::Utf8::kBufferEmpty) {
    output->push_back(result);
  }
}

}  // namespace

TEST(UnicodeTest, Utf16BufferReuse) {
  // Not enough continuation bytes before string ends.
  struct TestCase {
    std::vector<uint8_t> bytes;
    std::vector<unibrow::uchar> unicode_expected;
  };

  TestCase data[] = {
      {{0x00}, {0x0}},
      {{0xC2, 0x80}, {0x80}},
      {{0xE0, 0xA0, 0x80}, {0x800}},
      {{0xF0, 0x90, 0x80, 0x80}, {0x10000}},
      {{0xE0, 0xA0, 0x80}, {0x800}},
      {{0xC2, 0x80}, {0x80}},
      {{0x00}, {0x0}},
  };
  for (auto test : data) {
    // For figuring out which test fails:
    fprintf(stderr, "test: ");
    for (auto b : test.bytes) {
      fprintf(stderr, "%x ", b);
    }
    fprintf(stderr, "\n");

    std::vector<unibrow::uchar> output_utf16;
    DecodeUtf16(test.bytes, &output_utf16);

    CHECK_EQ(output_utf16.size(), test.unicode_expected.size());
    for (size_t i = 0; i < output_utf16.size(); ++i) {
      CHECK_EQ(output_utf16[i], test.unicode_expected[i]);
    }
  }
}

TEST(UnicodeTest, SurrogateOverrunsBuffer) {
  std::vector<unibrow::uchar> output_utf16;
  // Not enough continuation bytes before string ends.
  DecodeUtf16({0x00, 0xF0, 0x90, 0x80, 0x80, 0x00}, &output_utf16);
  CHECK_EQ(output_utf16[0], 0x00);
  CHECK_EQ(output_utf16[1], 0x10000);
  CHECK_EQ(output_utf16[0], 0x00);
}

TEST(UnicodeTest, IncrementalUTF8DecodingVsNonIncrementalUtf8Decoding) {
  // Unfortunately, V8 has two UTF-8 decoders. This test checks that they
  // produce the same result. This test was inspired by
  // https://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt .
  struct TestCase {
    std::vector<uint8_t> bytes;
    std::vector<unibrow::uchar> unicode_expected;
  };

  TestCase data[] = {
      // Correct UTF-8 text.
      {{0xCE, 0xBA, 0xE1, 0xBD, 0xB9, 0xCF, 0x83, 0xCE, 0xBC, 0xCE, 0xB5},
       {0x3BA, 0x1F79, 0x3C3, 0x3BC, 0x3B5}},

      // First possible sequence of a certain length:
      // 1 byte
      {{0x00}, {0x0}},
      // 2 bytes
      {{0xC2, 0x80}, {0x80}},
      // 3 bytes
      {{0xE0, 0xA0, 0x80}, {0x800}},
      // 4 bytes
      {{0xF0, 0x90, 0x80, 0x80}, {0x10000}},
      // 5 bytes (not supported)
      {{0xF8, 0x88, 0x80, 0x80, 0x80},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      // 6 bytes (not supported)
      {{0xFC, 0x84, 0x80, 0x80, 0x80, 0x80},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},

      // Last possible sequence of certain length:
      // 1 byte
      {{0x7F}, {0x7F}},
      // 2 bytes
      {{0xDF, 0xBF}, {0x7FF}},
      // 3 bytes
      {{0xEF, 0xBF, 0xBF}, {0xFFFF}},
      // 4 bytes (this sequence is not a valid code point)
      {{0xF7, 0xBF, 0xBF, 0xBF}, {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      // 5 bytes (not supported)
      {{0xFB, 0xBF, 0xBF, 0xBF, 0xBF},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      // 6 bytes (not supported)
      {{0xFD, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      // Other boundary conditions:
      {{0xED, 0x9F, 0xBF}, {0xD7FF}},
      {{0xEE, 0x80, 0x80}, {0xE000}},
      // U+fffd (invalid code point)
      {{0xEF, 0xBF, 0xBD}, {0xFFFD}},
      // U+10ffff (last valid code point)
      {{0xF4, 0x8F, 0xBF, 0xBF}, {0x10FFFF}},
      // First invalid (too large) code point
      {{0xF4, 0x90, 0x80, 0x80}, {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},

      // Malformed sequences:
      // Unexpected continuation bytes:
      // First continuation byte
      {{0x80}, {0xFFFD}},
      // Last continuation byte
      {{0xBF}, {0xFFFD}},
      // 2 continuation bytes
      {{0x80, 0xBF}, {0xFFFD, 0xFFFD}},
      // 3 continuation bytes
      {{0x80, 0xBF, 0x80}, {0xFFFD, 0xFFFD, 0xFFFD}},
      // 4 continuation bytes
      {{0x80, 0xBF, 0x80, 0xBF}, {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      // 5 continuation bytes
      {{0x80, 0xBF, 0x80, 0xBF, 0x80},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      // 6 continuation bytes
      {{0x80, 0xBF, 0x80, 0xBF, 0x80, 0xBF},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      // 7 continuation bytes
      {{0x80, 0xBF, 0x80, 0xBF, 0x80, 0xBF, 0xBF},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      // Sequence of all 64 possible continuation bytes
      {{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A,
        0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
        0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0,
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
        0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6,
        0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD,
        0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD,
        0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD,
        0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD,
        0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD,
        0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD,
        0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD,
        0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      // Using each possible continuation byte in a two-byte sequence:
      {{0xD0, 0x80, 0xD0, 0x81, 0xD0, 0x82, 0xD0, 0x83, 0xD0, 0x84, 0xD0, 0x85,
        0xD0, 0x86, 0xD0, 0x87, 0xD0, 0x88, 0xD0, 0x89, 0xD0, 0x8A, 0xD0, 0x8B,
        0xD0, 0x8C, 0xD0, 0x8D, 0xD0, 0x8E, 0xD0, 0x8F, 0xD0, 0x90, 0xD0, 0x91,
        0xD0, 0x92, 0xD0, 0x93, 0xD0, 0x94, 0xD0, 0x95, 0xD0, 0x96, 0xD0, 0x97,
        0xD0, 0x98, 0xD0, 0x99, 0xD0, 0x9A, 0xD0, 0x9B, 0xD0, 0x9C, 0xD0, 0x9D,
        0xD0, 0x9E, 0xD0, 0x9F, 0xD0, 0xA0, 0xD0, 0xA1, 0xD0, 0xA2, 0xD0, 0xA3,
        0xD0, 0xA4, 0xD0, 0xA5, 0xD0, 0xA6, 0xD0, 0xA7, 0xD0, 0xA8, 0xD0, 0xA9,
        0xD0, 0xAA, 0xD0, 0xAB, 0xD0, 0xAC, 0xD0, 0xAD, 0xD0, 0xAE, 0xD0, 0xAF,
        0xD0, 0xB0, 0xD0, 0xB1, 0xD0, 0xB2, 0xD0, 0xB3, 0xD0, 0xB4, 0xD0, 0xB5,
        0xD0, 0xB6, 0xD0, 0xB7, 0xD0, 0xB8, 0xD0, 0xB9, 0xD0, 0xBA, 0xD0, 0xBB,
        0xD0, 0xBC, 0xD0, 0xBD, 0xD0, 0xBE, 0xD0, 0xBF},
       {0x400, 0x401, 0x402, 0x403, 0x404, 0x405, 0x406, 0x407, 0x408, 0x409,
        0x40A, 0x40B, 0x40C, 0x40D, 0x40E, 0x40F, 0x410, 0x411, 0x412, 0x413,
        0x414, 0x415, 0x416, 0x417, 0x418, 0x419, 0x41A, 0x41B, 0x41C, 0x41D,
        0x41E, 0x41F, 0x420, 0x421, 0x422, 0x423, 0x424, 0x425, 0x426, 0x427,
        0x428, 0x429, 0x42A, 0x42B, 0x42C, 0x42D, 0x42E, 0x42F, 0x430, 0x431,
        0x432, 0x433, 0x434, 0x435, 0x436, 0x437, 0x438, 0x439, 0x43A, 0x43B,
        0x43C, 0x43D, 0x43E, 0x43F}},

      // Lonely first bytes:
      // All 32 first bytes of 32-byte sequences, each followed by a space
      // (generates 32 invalid char + space sequences.
      {{0xC0, 0x20, 0xC1, 0x20, 0xC2, 0x20, 0xC3, 0x20, 0xC4, 0x20, 0xC5,
        0x20, 0xC6, 0x20, 0xC7, 0x20, 0xC8, 0x20, 0xC9, 0x20, 0xCA, 0x20,
        0xCB, 0x20, 0xCC, 0x20, 0xCD, 0x20, 0xCE, 0x20, 0xCF, 0x20, 0xD0,
        0x20, 0xD1, 0x20, 0xD2, 0x20, 0xD3, 0x20, 0xD4, 0x20, 0xD5, 0x20,
        0xD6, 0x20, 0xD7, 0x20, 0xD8, 0x20, 0xD9, 0x20, 0xDA, 0x20, 0xDB,
        0x20, 0xDC, 0x20, 0xDD, 0x20, 0xDE, 0x20, 0xDF, 0x20},
       {0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20,
        0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20,
        0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20,
        0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20,
        0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20,
        0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20,
        0xFFFD, 0x20, 0xFFFD, 0x20}},
      // All 16 first bytes of 3-byte sequences, each followed by a space
      // (generates 16 invalid char + space sequences):
      {{0xE0, 0x20, 0xE1, 0x20, 0xE2, 0x20, 0xE3, 0x20, 0xE4, 0x20, 0xE5,
        0x20, 0xE6, 0x20, 0xE7, 0x20, 0xE8, 0x20, 0xE9, 0x20, 0xEA, 0x20,
        0xEB, 0x20, 0xEC, 0x20, 0xED, 0x20, 0xEE, 0x20, 0xEF, 0x20},
       {0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20,
        0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20,
        0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20,
        0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20}},
      // All 8 first bytes of 4-byte sequences, each followed by a space
      // (generates 8 invalid char + space sequences):
      {{0xF0, 0x20, 0xF1, 0x20, 0xF2, 0x20, 0xF3, 0x20, 0xF4, 0x20, 0xF5, 0x20,
        0xF6, 0x20, 0xF7, 0x20},
       {0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20,
        0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20}},
      // All 4 first bytes of 5-byte sequences (not supported), each followed by
      // a space (generates 4 invalid char + space sequences):
      {{0xF8, 0x20, 0xF9, 0x20, 0xFA, 0x20, 0xFB, 0x20},
       {0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20, 0xFFFD, 0x20}},
      // All 2 first bytes of 6-byte sequences (not supported), each followed by
      // a space (generates 2 invalid char + space sequences):
      {{0xFC, 0x20, 0xFD, 0x20}, {0xFFFD, 0x20, 0xFFFD, 0x20}},

      // Sequences with last continuation byte missing. Normally the whole
      // incomplete sequence generates a single invalid character (exceptions
      // explained below).

      // 2-byte sequences with last byte missing
      {{0xC0}, {0xFFFD}},
      {{0xDF}, {0xFFFD}},
      // 3-byte sequences with last byte missing.
      {{0xE8, 0x80}, {0xFFFD}},
      {{0xE0, 0xBF}, {0xFFFD}},
      {{0xEF, 0xBF}, {0xFFFD}},
      // Start of an overlong sequence. The first "maximal subpart" is the first
      // byte; it creates an invalid character. Each following byte generates an
      // invalid character too.
      {{0xE0, 0x80}, {0xFFFD, 0xFFFD}},
      // 4-byte sequences with last byte missing
      {{0xF1, 0x80, 0x80}, {0xFFFD}},
      {{0xF4, 0x8F, 0xBF}, {0xFFFD}},
      // Start of an overlong sequence. The first "maximal subpart" is the first
      // byte; it creates an invalid character. Each following byte generates an
      // invalid character too.
      {{0xF0, 0x80, 0x80}, {0xFFFD, 0xFFFD, 0xFFFD}},
      // 5-byte sequences (not supported) with last byte missing
      {{0xF8, 0x80, 0x80, 0x80}, {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xFB, 0xBF, 0xBF, 0xBF}, {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      // 6-byte sequences (not supported) with last byte missing
      {{0xFC, 0x80, 0x80, 0x80, 0x80},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xFD, 0xBF, 0xBF, 0xBF, 0xBF},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},

      // Concatenation of incomplete sequences: above incomplete sequences
      // concatenated.
      {{0xC0, 0xDF, 0xE8, 0x80, 0xE0, 0xBF, 0xEF, 0xBF, 0xE0, 0x80,
        0xF1, 0x80, 0x80, 0xF4, 0x8F, 0xBF, 0xF0, 0x80, 0x80, 0xF8,
        0x80, 0x80, 0x80, 0xFB, 0xBF, 0xBF, 0xBF, 0xFC, 0x80, 0x80,
        0x80, 0x80, 0xFD, 0xBF, 0xBF, 0xBF, 0xBF},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD,
        0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD,
        0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD,
        0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},

      // Incomplete sequence tests repeated with a space after the incomplete
      // sequence.

      // 2-byte sequences with last byte missing
      {{0xC0, 0x20}, {0xFFFD, 0x20}},
      {{0xDF, 0x20}, {0xFFFD, 0x20}},
      // 3-byte sequences with last byte missing
      {{0xE8, 0x80, 0x20}, {0xFFFD, 0x20}},
      {{0xE0, 0xBF, 0x20}, {0xFFFD, 0x20}},
      {{0xEF, 0xBF, 0x20}, {0xFFFD, 0x20}},
      // Start of overlong 3-byte sequence with last byte missing
      {{0xE0, 0x80, 0x20}, {0xFFFD, 0xFFFD, 0x20}},
      // 4-byte sequences with last byte missing
      {{0xF1, 0x80, 0x80, 0x20}, {0xFFFD, 0x20}},
      {{0xF4, 0x8F, 0xBF, 0x20}, {0xFFFD, 0x20}},
      // Start of overlong 4-byte sequence with last byte missing
      {{0xF0, 0x80, 0x80, 0x20}, {0xFFFD, 0xFFFD, 0xFFFD, 0x20}},
      // 5-byte sequences (not supported) with last byte missing
      {{0xF8, 0x80, 0x80, 0x80, 0x20}, {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0x20}},
      {{0xFB, 0xBF, 0xBF, 0xBF, 0x20}, {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0x20}},
      // 6-byte sequences (not supported) with last byte missing
      {{0xFC, 0x80, 0x80, 0x80, 0x80, 0x20},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0x20}},
      {{0xFD, 0xBF, 0xBF, 0xBF, 0xBF, 0x20},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0x20}},

      // Impossible bytes
      {{0xFE}, {0xFFFD}},
      {{0xFF}, {0xFFFD}},
      {{0xFE, 0xFE, 0xFF, 0xFF}, {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      // Lead-byte-like bytes which aren't valid lead bytes.
      {{0xC0}, {0xFFFD}},
      {{0xC0, 0xAA}, {0xFFFD, 0xFFFD}},
      {{0xC1}, {0xFFFD}},
      {{0xC1, 0xAA}, {0xFFFD, 0xFFFD}},
      {{0xF5}, {0xFFFD}},
      {{0xF5, 0xAA, 0xAA, 0xAA}, {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xF6}, {0xFFFD}},
      {{0xF6, 0xAA, 0xAA, 0xAA}, {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xF7}, {0xFFFD}},
      {{0xF7, 0xAA, 0xAA, 0xAA}, {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xF8}, {0xFFFD}},
      {{0xF8, 0xAA, 0xAA, 0xAA}, {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xF9}, {0xFFFD}},
      {{0xF9, 0xAA, 0xAA, 0xAA}, {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xFA}, {0xFFFD}},
      {{0xFA, 0xAA, 0xAA, 0xAA}, {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xFB}, {0xFFFD}},
      {{0xFB, 0xAA, 0xAA, 0xAA}, {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xFC}, {0xFFFD}},
      {{0xFC, 0xAA, 0xAA, 0xAA}, {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xFD}, {0xFFFD}},
      {{0xFD, 0xAA, 0xAA, 0xAA}, {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xFE}, {0xFFFD}},
      {{0xFE, 0xAA, 0xAA, 0xAA}, {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xFF}, {0xFFFD}},
      {{0xFF, 0xAA, 0xAA, 0xAA}, {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},

      // Overlong sequences:

      // Overlong encodings for "/"
      {{0xC0, 0xAF}, {0xFFFD, 0xFFFD}},
      {{0xE0, 0x80, 0xAF}, {0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xF0, 0x80, 0x80, 0xAF}, {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      // 5-byte sequence (not supported anyway)
      {{0xF8, 0x80, 0x80, 0x80, 0xAF},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      // 6-byte sequence (not supported anyway)
      {{0xFC, 0x80, 0x80, 0x80, 0x80, 0xAF},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},

      // Maximum overlong sequences
      {{0xC1, 0xBF}, {0xFFFD, 0xFFFD}},
      {{0xE0, 0x9F, 0xBF}, {0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xF0, 0x8F, 0xBF, 0xBF}, {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      // 5-byte sequence (not supported anyway)
      {{0xF8, 0x87, 0xBF, 0xBF, 0xBF},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      // 6-byte sequence (not supported anyway)
      {{0xFC, 0x83, 0xBF, 0xBF, 0xBF, 0xBF},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},

      // Overlong encodings for 0
      {{0xC0, 0x80}, {0xFFFD, 0xFFFD}},
      {{0xE0, 0x80, 0x80}, {0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xF0, 0x80, 0x80, 0x80}, {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      // 5-byte sequence (not supported anyway)
      {{0xF8, 0x80, 0x80, 0x80, 0x80},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      // 6-byte sequence (not supported anyway)
      {{0xFC, 0x80, 0x80, 0x80, 0x80, 0x80},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},

      // Illegal code positions:

      // Single UTF-16 surrogates
      {{0xED, 0xA0, 0x80}, {0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xED, 0xA0, 0x80}, {0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xED, 0xAD, 0xBF}, {0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xED, 0xAE, 0x80}, {0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xED, 0xAF, 0xBF}, {0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xED, 0xB0, 0x80}, {0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xED, 0xBE, 0x80}, {0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xED, 0xBF, 0xBF}, {0xFFFD, 0xFFFD, 0xFFFD}},

      // Paired surrogates
      {{0xED, 0xA0, 0x80, 0xED, 0xB0, 0x80},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xED, 0xA0, 0x80, 0xED, 0xBF, 0xBF},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xED, 0xAD, 0xBF, 0xED, 0xB0, 0x80},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xED, 0xAD, 0xBF, 0xED, 0xBF, 0xBF},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xED, 0xAE, 0x80, 0xED, 0xB0, 0x80},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xED, 0xAE, 0x80, 0xED, 0xBF, 0xBF},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xED, 0xAF, 0xBF, 0xED, 0xB0, 0x80},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},
      {{0xED, 0xAF, 0xBF, 0xED, 0xBF, 0xBF},
       {0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD}},

      // Surrogates with the last byte missing.
      {{0xED, 0xA0}, {0xFFFD, 0xFFFD}},
      {{0xED, 0xA0}, {0xFFFD, 0xFFFD}},
      {{0xED, 0xAD}, {0xFFFD, 0xFFFD}},
      {{0xED, 0xAE}, {0xFFFD, 0xFFFD}},
      {{0xED, 0xAF}, {0xFFFD, 0xFFFD}},
      {{0xED, 0xB0}, {0xFFFD, 0xFFFD}},
      {{0xED, 0xBE}, {0xFFFD, 0xFFFD}},
      {{0xED, 0xBF}, {0xFFFD, 0xFFFD}},

      // Other non-characters
      {{0xEF, 0xBF, 0xBE}, {0xFFFE}},
      {{0xEF, 0xBF, 0xBF}, {0xFFFF}},
      {{0xEF, 0xB7, 0x90, 0xEF, 0xB7, 0x91, 0xEF, 0xB7, 0x92, 0xEF, 0xB7, 0x93,
        0xEF, 0xB7, 0x94, 0xEF, 0xB7, 0x95, 0xEF, 0xB7, 0x96, 0xEF, 0xB7, 0x97,
        0xEF, 0xB7, 0x98, 0xEF, 0xB7, 0x99, 0xEF, 0xB7, 0x9A, 0xEF, 0xB7, 0x9B,
        0xEF, 0xB7, 0x9C, 0xEF, 0xB7, 0x9D, 0xEF, 0xB7, 0x9E, 0xEF, 0xB7, 0x9F,
        0xEF, 0xB7, 0xA0, 0xEF, 0xB7, 0xA1, 0xEF, 0xB7, 0xA2, 0xEF, 0xB7, 0xA3,
        0xEF, 0xB7, 0xA4, 0xEF, 0xB7, 0xA5, 0xEF, 0xB7, 0xA6, 0xEF, 0xB7, 0xA7,
        0xEF, 0xB7, 0xA8, 0xEF, 0xB7, 0xA9, 0xEF, 0xB7, 0xAA, 0xEF, 0xB7, 0xAB,
        0xEF, 0xB7, 0xAC, 0xEF, 0xB7, 0xAD, 0xEF, 0xB7, 0xAE, 0xEF, 0xB7, 0xAF},
       {0xFDD0, 0xFDD1, 0xFDD2, 0xFDD3, 0xFDD4, 0xFDD5, 0xFDD6, 0xFDD7,
        0xFDD8, 0xFDD9, 0xFDDA, 0xFDDB, 0xFDDC, 0xFDDD, 0xFDDE, 0xFDDF,
        0xFDE0, 0xFDE1, 0xFDE2, 0xFDE3, 0xFDE4, 0xFDE5, 0xFDE6, 0xFDE7,
        0xFDE8, 0xFDE9, 0xFDEA, 0xFDEB, 0xFDEC, 0xFDED, 0xFDEE, 0xFDEF}},
      {{0xF0, 0x9F, 0xBF, 0xBE, 0xF0, 0x9F, 0xBF, 0xBF, 0xF0, 0xAF, 0xBF,
        0xBE, 0xF0, 0xAF, 0xBF, 0xBF, 0xF0, 0xBF, 0xBF, 0xBE, 0xF0, 0xBF,
        0xBF, 0xBF, 0xF1, 0x8F, 0xBF, 0xBE, 0xF1, 0x8F, 0xBF, 0xBF, 0xF1,
        0x9F, 0xBF, 0xBE, 0xF1, 0x9F, 0xBF, 0xBF, 0xF1, 0xAF, 0xBF, 0xBE,
        0xF1, 0xAF, 0xBF, 0xBF, 0xF1, 0xBF, 0xBF, 0xBE, 0xF1, 0xBF, 0xBF,
        0xBF, 0xF2, 0x8F, 0xBF, 0xBE, 0xF2, 0x8F, 0xBF, 0xBF},
       {0x1FFFE, 0x1FFFF, 0x2FFFE, 0x2FFFF, 0x3FFFE, 0x3FFFF, 0x4FFFE, 0x4FFFF,
        0x5FFFE, 0x5FFFF, 0x6FFFE, 0x6FFFF, 0x7FFFE, 0x7FFFF, 0x8FFFE,
        0x8FFFF}},
  };

  for (auto test : data) {
    // For figuring out which test fails:
    fprintf(stderr, "test: ");
    for (auto b : test.bytes) {
      fprintf(stderr, "%x ", b);
    }
    fprintf(stderr, "\n");

    std::vector<unibrow::uchar> output_normal;
    DecodeNormally(test.bytes, &output_normal);

    CHECK_EQ(output_normal.size(), test.unicode_expected.size());
    for (size_t i = 0; i < output_normal.size(); ++i) {
      CHECK_EQ(output_normal[i], test.unicode_expected[i]);
    }

    std::vector<unibrow::uchar> output_incremental;
    DecodeIncrementally(test.bytes, &output_incremental);

    CHECK_EQ(output_incremental.size(), test.unicode_expected.size());
    for (size_t i = 0; i < output_incremental.size(); ++i) {
      CHECK_EQ(output_incremental[i], test.unicode_expected[i]);
    }

    std::vector<unibrow::uchar> output_utf16;
    DecodeUtf16(test.bytes, &output_utf16);

    CHECK_EQ(output_utf16.size(), test.unicode_expected.size());
    for (size_t i = 0; i < output_utf16.size(); ++i) {
      CHECK_EQ(output_utf16[i], test.unicode_expected[i]);
    }
  }
}

class UnicodeWithGCTest : public TestWithHeapInternals {};

#define GC_INSIDE_NEW_STRING_FROM_UTF8_SUB_STRING(NAME, STRING)               \
  TEST_F(UnicodeWithGCTest, GCInsideNewStringFromUtf8SubStringWith##NAME) {   \
    v8_flags.stress_concurrent_allocation =                                   \
        false; /* For SimulateFullSpace. */                                   \
    ManualGCScope manual_gc_scope(isolate());                                 \
    v8::HandleScope scope(reinterpret_cast<v8::Isolate*>(isolate()));         \
    Factory* factory = isolate()->factory();                                  \
    /* Length must be bigger than the buffer size of the Utf8Decoder. */      \
    const char* buf = STRING;                                                 \
    size_t len = strlen(buf);                                                 \
    Handle<String> main_string =                                              \
        factory                                                               \
            ->NewStringFromOneByte(v8::base::Vector<const uint8_t>(           \
                reinterpret_cast<const uint8_t*>(buf), len))                  \
            .ToHandleChecked();                                               \
    if (v8_flags.single_generation) {                                         \
      CHECK(!HeapLayout::InYoungGeneration(*main_string));                    \
      SimulateFullSpace(heap()->old_space());                                 \
    } else {                                                                  \
      CHECK(HeapLayout::InYoungGeneration(*main_string));                     \
      SimulateFullSpace(heap()->new_space());                                 \
    }                                                                         \
    /* Offset by two to check substring-ing. */                               \
    DirectHandle<String> s =                                                  \
        factory                                                               \
            ->NewStringFromUtf8SubString(Cast<SeqOneByteString>(main_string), \
                                         2, static_cast<int>(len - 2))        \
            .ToHandleChecked();                                               \
    DirectHandle<String> expected_string =                                    \
        factory                                                               \
            ->NewStringFromUtf8(                                              \
                v8::base::Vector<const char>(buf + 2, len - 2))               \
            .ToHandleChecked();                                               \
    CHECK(s->Equals(*expected_string));                                       \
  }

GC_INSIDE_NEW_STRING_FROM_UTF8_SUB_STRING(
    OneByte,
    "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
    "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
    "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
    "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
    "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
    "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
    "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
    "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
    "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ")
GC_INSIDE_NEW_STRING_FROM_UTF8_SUB_STRING(
    TwoByte,
    "QQ\xF0\x9F\x98\x8D\xF0\x9F\x98\x8D"
    "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
    "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
    "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
    "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
    "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
    "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
    "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
    "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
    "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
    "QQ\xF0\x9F\x98\x8D\xF0\x9F\x98\x8D")

#undef GC_INSIDE_NEW_STRING_FROM_UTF8_SUB_STRING

}  // namespace internal
}  // namespace v8

"""

```