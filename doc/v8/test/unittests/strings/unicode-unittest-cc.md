Response:
Let's break down the thought process for analyzing this C++ unittest file.

**1. Initial Scan and Purpose Identification:**

* **Keywords:**  Immediately, the keywords `TEST`, `UnicodeTest`, `Utf8`, `Utf16`, `Decode`, `Surrogate`, `Incremental`, `GC` stand out. This strongly suggests the file is about testing the correctness of Unicode encoding and decoding within V8, possibly with a focus on different decoding strategies and garbage collection interactions.
* **File Path:**  The path `v8/test/unittests/strings/unicode-unittest.cc` confirms this is a unit test file within the `strings` component of V8, specifically related to Unicode functionality. The `.cc` extension indicates C++ source code.

**2. Functionality Breakdown by Test Case:**

* **`Utf16BufferReuse`:** The name itself hints at testing how UTF-16 decoding handles buffer reuse scenarios. The `TestCase` struct and the `data` array strongly suggest a data-driven testing approach where various byte sequences are tested against expected Unicode code points. The comments like "Not enough continuation bytes before string ends" give further clues about the specific edge cases being targeted. The core function being tested here seems to be `DecodeUtf16`.

* **`SurrogateOverrunsBuffer`:** This name clearly points to testing scenarios where surrogate pairs might cross buffer boundaries or encounter unexpected ends. Again, `DecodeUtf16` is the likely function under scrutiny. The specific byte sequence `{0x00, 0xF0, 0x90, 0x80, 0x80, 0x00}` is a crucial input for understanding the test's intention. It looks like a valid 4-byte UTF-8 sequence embedded within null bytes.

* **`IncrementalUTF8DecodingVsNonIncrementalUtf8Decoding`:**  This is a more comprehensive test comparing two different UTF-8 decoding methods: incremental and non-incremental. The link to the "UTF-8-test.txt" further emphasizes the focus on thorough testing against a wide range of valid and invalid UTF-8 sequences. The `TestCase` struct and extensive `data` array reinforce the data-driven approach. The functions being tested are `DecodeNormally` (non-incremental) and `DecodeIncrementally`. The assertion that both methods should produce the same result is key. The various categories in the `data` array (Correct UTF-8, First/Last possible sequences, Malformed sequences, etc.) reveal the systematic approach to covering different UTF-8 encoding rules and error conditions.

* **`GCInsideNewStringFromUtf8SubStringWith...`:** The name and the `GC_INSIDE_NEW_STRING_FROM_UTF8_SUB_STRING` macro strongly indicate tests related to garbage collection happening during the creation of substrings from UTF-8 encoded strings. The test aims to ensure that garbage collection occurring at a specific point doesn't lead to errors. The macro itself defines two specific test cases, one with a simple ASCII string and another with a string containing multi-byte UTF-8 characters. The key functions here are related to string creation in V8's internal API, specifically `NewStringFromUtf8SubString`. The `SimulateFullSpace` call is a clear indication of simulating garbage collection.

**3. Identifying Relationships to JavaScript:**

* **String Encoding:** The core functionality of this unittest directly relates to how JavaScript engines handle strings internally. JavaScript strings are typically represented using UTF-16. The tests for UTF-8 to UTF-16 conversion are therefore very relevant to JavaScript's internal workings.
* **`charCodeAt()` and `codePointAt()`:** These JavaScript methods are the most obvious connection. They allow developers to access the underlying Unicode code points of a string, which is precisely what the C++ code is testing for correctness.
* **String Manipulation:**  JavaScript's string manipulation functions (e.g., `substring()`, `slice()`) are related to the `GCInsideNewStringFromUtf8SubString` tests. The ability to efficiently create substrings and the interaction with garbage collection are important for JavaScript performance.

**4. Code Logic Inference and Assumptions:**

* **Decoding Functions:** The `DecodeNormally`, `DecodeUtf16`, and `DecodeIncrementally` functions are clearly implementing different strategies for converting UTF-8 byte sequences to Unicode code points. The code within these functions reveals the logic of each approach (e.g., iterating through bytes, handling continuation bytes, dealing with surrogate pairs).
* **Error Handling:**  The presence of `0xFFFD` (the Unicode replacement character) in the expected output for many test cases indicates how the decoders handle invalid or malformed UTF-8 sequences. This is a standard practice in Unicode processing.
* **Garbage Collection Interaction:** The `GCInsideNewStringFromUtf8SubString` tests make the assumption that garbage collection might happen during string creation, especially when dealing with large strings or substrings. The tests aim to verify that V8's string handling is robust even under such conditions.

**5. Common Programming Errors:**

* **Incorrect UTF-8 Encoding:** The extensive tests for malformed UTF-8 sequences highlight a common error: generating or handling UTF-8 data incorrectly.
* **Off-by-One Errors:** When dealing with byte offsets and lengths in string processing, off-by-one errors are frequent. The substring tests implicitly touch on this.
* **Assuming ASCII:**  Developers sometimes assume all text is ASCII and fail to properly handle multi-byte UTF-8 characters, leading to incorrect display or processing.
* **Incorrect Surrogate Pair Handling:**  Working with UTF-16 and surrogate pairs can be tricky. The tests specifically targeting surrogate pairs highlight the importance of correct handling.

**Self-Correction/Refinement during the Thought Process:**

* **Initial thought:** Maybe the `Utf16BufferReuse` test is about memory efficiency.
* **Correction:**  While memory efficiency might be a *consequence*, the test cases focusing on partial byte sequences and expected outputs suggest the core focus is on the *correctness* of the decoding logic when faced with potentially incomplete input.
* **Initial thought:** The GC tests are just about preventing crashes.
* **Refinement:**  While preventing crashes is important, the tests also seem to verify the *correctness* of the resulting substring after a garbage collection cycle.

By following these steps, combining keyword analysis, test case examination, code inference, and considering the broader context of JavaScript and Unicode, we can arrive at a comprehensive understanding of the functionality of this V8 unittest file.
这个C++源代码文件 `v8/test/unittests/strings/unicode-unittest.cc` 是 V8 JavaScript 引擎的单元测试文件，专门用于测试 V8 中 Unicode 字符串处理的相关功能。

**主要功能列举:**

1. **UTF-8 解码测试:**  测试 V8 的 UTF-8 解码器是否能正确地将 UTF-8 字节序列解码为 Unicode 码点。
    * 包含了多种 UTF-8 编码的测试用例，包括：
        * 正确的 UTF-8 序列
        * 不同长度的 UTF-8 序列的边界情况（1字节到6字节，但实际上只支持到4字节）
        * 错误的 UTF-8 序列（例如，意外的延续字节、不完整的序列、过长编码、非法的码位）
        * 特殊的 Unicode 字符，如代理对。
    * 比较了两种 UTF-8 解码方式：
        * **非增量解码 (`DecodeNormally`)**: 一次性解码整个字节序列。
        * **增量解码 (`DecodeIncrementally`)**: 模拟逐步接收字节进行解码。
    * 验证了这两种解码方式对于相同的输入是否产生相同的 Unicode 码点序列。
    * 还测试了 UTF-8 到 UTF-16 的转换 (`DecodeUtf16`)。

2. **UTF-16 解码测试:** 测试 V8 的 UTF-16 解码器是否能正确处理 UTF-8 转换为 UTF-16 的过程，特别是代理对的处理和缓冲区边界情况。
    * `Utf16BufferReuse` 测试用例检查了在 UTF-8 转换到 UTF-16 的过程中，当 UTF-8 序列在字符串末尾不完整时，UTF-16 缓冲区的处理是否正确。
    * `SurrogateOverrunsBuffer` 测试用例检查了代理对是否会超出缓冲区边界。

3. **与垃圾回收 (GC) 的交互测试:**  测试在某些 Unicode 字符串操作过程中触发垃圾回收是否会导致问题。
    * `GCInsideNewStringFromUtf8SubStringWithOneByte` 和 `GCInsideNewStringFromUtf8SubStringWithTwoByte` 测试用例模拟了在从 UTF-8 子字符串创建新字符串时进行垃圾回收的情况。 这旨在确保在内存分配压力下，字符串操作的正确性。

**关于 `.tq` 后缀:**

如果 `v8/test/unittests/strings/unicode-unittest.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码** 文件。Torque 是一种 V8 内部使用的类型化的中间语言，用于编写 V8 的内置函数和运行时代码。由于当前文件以 `.cc` 结尾，所以它是 C++ 源代码。

**与 JavaScript 的功能关系及举例:**

这个单元测试直接关系到 JavaScript 中字符串的处理，特别是涉及到非 ASCII 字符的字符串。

**JavaScript 例子:**

```javascript
// 包含 Unicode 字符的字符串
const str = "你好，世界！🌍";

// 使用 charCodeAt 获取指定位置字符的 UTF-16 编码
console.log(str.charCodeAt(0)); // 输出 第一个字符 '你' 的 UTF-16 编码

// 使用 codePointAt 获取指定位置字符的 Unicode 码点
console.log(str.codePointAt(0)); // 输出 第一个字符 '你' 的 Unicode 码点

// 遍历字符串的 Unicode 码点
for (const char of str) {
  console.log(char, char.codePointAt(0));
}

// 测试包含不规范 UTF-8 数据的场景 (JavaScript 字符串内部通常是 UTF-16)
// 可以通过 TextDecoder API 来模拟解码 UTF-8
const utf8Bytes = new Uint8Array([0xC0, 0xAF]); // 一个不完整的 UTF-8 序列
const decoder = new TextDecoder();
try {
  console.log(decoder.decode(utf8Bytes));
} catch (e) {
  console.error("解码错误:", e); // JavaScript 会抛出错误
}
```

`v8/test/unittests/strings/unicode-unittest.cc` 中测试的解码器功能，正是 JavaScript 引擎在处理字符串时所使用的底层机制。例如，当 JavaScript 代码执行类似 `str.length`、`str[i]`、`str.charCodeAt(i)` 或使用正则表达式处理 Unicode 字符时，V8 引擎内部就需要依赖这些经过测试的 Unicode 处理功能。

**代码逻辑推理 (假设输入与输出):**

以 `IncrementalUTF8DecodingVsNonIncrementalUtf8Decoding` 测试组中的一个用例为例：

**假设输入 (bytes):** `{{0xE0, 0xA0, 0x80}}` (代表 UTF-8 编码的 U+0800 字符)

**代码逻辑:**

* `DecodeNormally` 函数会一次性读取这三个字节，识别出这是一个三字节的 UTF-8 序列，并将其解码为 Unicode 码点 `0x800`。
* `DecodeIncrementally` 函数会模拟逐步接收字节：
    * 接收 `0xE0`，识别出这是一个三字节序列的起始字节。
    * 接收 `0xA0`，检查是否是有效的延续字节。
    * 接收 `0x80`，检查是否是有效的延续字节。
    * 最终将这三个字节组合解码为 Unicode 码点 `0x800`。

**预期输出 (unicode_expected):** `{0x800}`

测试会断言 `DecodeNormally` 和 `DecodeIncrementally` 对于这个输入都得到相同的输出 `0x800`。

**用户常见的编程错误举例:**

1. **假设所有字符都是单字节:**
   ```javascript
   const str = "你好";
   for (let i = 0; i < str.length; i++) {
       console.log(str.charCodeAt(i)); // 可能会得到不期望的结果，因为 '你' 是多字节字符
   }
   ```
   应该使用 `codePointAt` 或迭代器来正确处理 Unicode 码点。

2. **不正确地处理 UTF-8 编码的数据:**
   假设用户从网络或文件中读取到 UTF-8 编码的字节流，并尝试将其直接作为单字节字符串处理，会导致乱码。
   ```javascript
   // 假设 data 是一个包含 UTF-8 编码 "你好" 的 Uint8Array
   const data = new Uint8Array([228, 189, 160, 229, 165, 189]);
   let str = "";
   for (let i = 0; i < data.length; i++) {
       str += String.fromCharCode(data[i]); // 错误的做法
   }
   console.log(str); // 输出乱码
   ```
   应该使用 `TextDecoder` 来正确解码 UTF-8 数据。

3. **在需要 Unicode 码点的地方使用 UTF-16 编码:**
   某些 API 或操作可能需要完整的 Unicode 码点（例如，处理 Emoji 或扩展字符），而 `charCodeAt` 只能提供 UTF-16 编码，对于超出 BMP 的字符会返回代理对的一部分。
   ```javascript
   const emoji = "😄"; // U+1F604
   console.log(emoji.charCodeAt(0)); // 输出代理对的第一个编码
   console.log(emoji.codePointAt(0)); // 输出正确的 Unicode 码点 128516
   ```

`v8/test/unittests/strings/unicode-unittest.cc` 中大量的测试用例覆盖了各种边界情况和错误场景，正是为了确保 V8 引擎能够正确可靠地处理 Unicode 字符串，从而避免用户在 JavaScript 编程中遇到这些常见的错误。

### 提示词
```
这是目录为v8/test/unittests/strings/unicode-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/strings/unicode-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
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
```