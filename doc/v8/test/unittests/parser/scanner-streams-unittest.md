Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

1. **Understand the Goal:** The request asks for the functionality of the C++ file `v8/test/unittests/parser/scanner-streams-unittest.cc`. The name itself gives a strong hint: it's a unit test for scanner streams. Specifically, it's testing different ways to feed character data to the V8 parser's scanner.

2. **Identify Key Components:** Scan the `#include` directives and the code structure to identify the core elements being tested.

    * **Headers:**
        * `src/base/strings.h`: Likely related to string manipulation utilities.
        * `src/heap/factory-inl.h`, `src/objects/objects-inl.h`: Indicate interaction with V8's object model, specifically string creation.
        * `src/parsing/scanner-character-streams.h`, `src/parsing/scanner.h`: The main targets! These are the scanner stream classes being tested.
        * `test/unittests/heap/heap-utils.h`, `test/unittests/test-utils.h`: Standard V8 testing utilities.
        * `testing/gtest/include/gtest/gtest.h`: The Google Test framework is used.

    * **Namespaces:** The `namespace { ... }` block suggests helper classes and functions specific to this test file.

    * **Test Fixture:** `using ScannerStreamsTest = v8::TestWithIsolate;` indicates the use of a test fixture that sets up an isolated V8 environment for each test.

    * **Helper Classes:**  The code defines several custom classes:
        * `ChunkSource`: This is crucial. It implements `v8::ScriptCompiler::ExternalSourceStream`, allowing the tests to feed data in chunks. This suggests testing how the scanner handles data coming in pieces.
        * `LockChecker`:  Seems to be a utility for ensuring proper locking/unlocking of resources, probably related to external string resources.
        * `TestExternalResource`, `TestExternalOneByteResource`: These likely represent external strings (two-byte and one-byte respectively) and are used to test how the scanner handles these types of strings.

    * **Helper Functions:**
        * `NewExternalTwoByteStringFromResource`: Creates a V8 string from an external two-byte resource, demonstrating interaction with V8's string creation.
        * `TestCharacterStream`, `TestCloneCharacterStream`, `TestCharacterStreams`, `TestChunkStreamAgainstReference`: These are test utility functions, encapsulating common testing patterns for different stream types.

    * **`TEST_F` Macros:** These are the actual unit tests, each focusing on a specific aspect of the scanner streams. The names of the tests provide valuable clues about what's being tested (e.g., `Utf8StreamAsciiOnly`, `Utf8StreamBOM`, `Utf8ChunkBoundaries`, `CharacterStreams`, `RelocatingCharacterStream`, `CloneCharacterStreams`).

3. **Infer Functionality from Test Names and Code:** Now, go through the individual tests and the helper classes to deduce the overall functionality.

    * **`ChunkSource`:** The constructors accept different input types (char**, char*, uint8_t*) and create "chunks" of data. The `GetMoreData` method simulates providing these chunks to the scanner. This clearly points to testing streamed input.

    * **`LockChecker` and `TestExternal*Resource`:** These classes together suggest testing scenarios involving external string resources and verifying correct locking behavior during scanning.

    * **`Utf8Stream*` tests:** These focus on testing how the scanner handles UTF-8 encoded input, including ASCII, multi-byte characters, Byte Order Marks (BOMs), and handling of split BOMs across chunks. The `AdvanceUntil` tests verify the ability to scan until a specific character is encountered.

    * **`CharacterStreams` test:**  This appears to be a more comprehensive test, covering various types of string input: external two-byte, external one-byte, and internal V8 strings (one-byte and two-byte), both in single and multi-chunk streaming scenarios. It also seems to test the `Seek` and `Back` methods of the stream.

    * **`Regress*` tests:** These are regression tests, meaning they were added to prevent bugs from recurring. The names (e.g., `Regress651333`, `Regress6377`, `Regress6836`) likely refer to specific bug reports. These tests often target edge cases or specific failure scenarios.

    * **`RelocatingCharacterStream`, `RelocatingUnbufferedCharacterStream` tests:** These tests are interesting. They involve triggering garbage collection (`InvokeMajorGC`) and checking if the scanner stream continues to work correctly even after the underlying string object has been moved in memory. This is a crucial test for V8's garbage collection behavior.

    * **`CloneCharacterStreams` test:**  This explicitly tests the `Clone()` method of the scanner stream, ensuring that cloned streams function independently and that resource locking is handled correctly during cloning.

4. **Address Specific Questions in the Prompt:** Now, address the individual points raised in the prompt:

    * **Functionality:** Summarize the main purpose – testing the `ScannerStream` class with different input sources and encodings.

    * **`.tq` Extension:** Explain that `.tq` signifies Torque code and confirm that this file is C++, not Torque.

    * **Relationship to JavaScript:** Connect the functionality to JavaScript by explaining that the scanner is a fundamental part of the JavaScript parsing process. Provide a simple JavaScript example of code that would be scanned.

    * **Code Logic Inference:** For tests like `Utf8StreamBOM`, describe the input (string with BOM) and the expected output (characters without the BOM). For tests involving chunking, explain how the input is split and how the scanner should process it.

    * **Common Programming Errors:** Relate the tests to potential errors, such as incorrect handling of UTF-8 encoding, BOMs, or issues with external string lifetimes.

    * **归纳功能 (Summarize Functionality):** Provide a concise summary of the file's purpose.

5. **Structure the Answer:** Organize the findings logically, using headings and bullet points for clarity. Start with a high-level summary and then delve into more specific details. Address each point of the prompt explicitly.

By following these steps, we can systematically analyze the C++ code and provide a comprehensive answer that addresses all aspects of the request. The key is to understand the purpose of the code through its structure, naming conventions, and the logic of the tests themselves.
好的，让我们来分析一下 `v8/test/unittests/parser/scanner-streams-unittest.cc` 这个文件。

**功能归纳**

`v8/test/unittests/parser/scanner-streams-unittest.cc` 文件的主要功能是**测试 V8 引擎中用于扫描源代码的各种字符流 (Scanner Streams) 的实现是否正确**。它涵盖了不同类型的输入源、字符编码和边界情况，以确保扫描器能够准确、高效地读取和处理源代码。

**具体功能点:**

1. **测试不同类型的输入源:**
   - **基于内存的字符串 (Internal Strings):** 测试从 V8 内部管理的字符串对象读取字符流。
   - **外部字符串 (External Strings):** 测试从外部提供的字符数据（例如，来自操作系统或外部库）读取字符流。这包括单字节 (ASCII) 和双字节 (UTF-16) 编码的外部字符串。
   - **流式输入 (Streamed Input):**  测试从 `v8::ScriptCompiler::ExternalSourceStream` 接口提供的流式数据读取字符流，允许以分块的方式提供输入。

2. **测试不同的字符编码:**
   - **UTF-8:** 重点测试对 UTF-8 编码的处理，包括：
     - 仅包含 ASCII 字符的 UTF-8 流。
     - 包含最大非代理字符的 UTF-8 流。
     - UTF-8 字节顺序标记 (BOM) 的处理（存在和缺失）。
     - BOM 被分割在多个数据块中的情况。
     - 跨越数据块边界的 UTF-8 字符。
     - 单字节数据块的情况。
     - 无效和过长的 UTF-8 序列的处理。
   - **One-Byte (ASCII):** 测试单字节编码的字符流。
   - **Two-Byte (UTF-16):** 测试双字节编码的字符流。

3. **测试字符流的核心操作:**
   - **Advance():** 逐个读取字符。
   - **AdvanceUntil():** 读取字符直到满足特定条件。
   - **Seek():** 将读取位置移动到指定偏移量。
   - **Back():** 将读取位置回退一个字符。
   - **Clone():** 克隆字符流，确保克隆后的流与原始流的行为一致。

4. **测试边界情况和错误处理:**
   - 处理输入结束。
   - 处理分割在数据块边界的字符。
   - 处理无效的 UTF-8 序列。
   - 回归测试，修复已知 bug (例如，`Regress651333`, `Regress6377`, `Regress6836`)。

5. **测试在垃圾回收 (GC) 期间的行为:**
   - 测试当底层字符串对象在 GC 过程中被移动时，字符流是否仍然能正常工作（`RelocatingCharacterStream`, `RelocatingUnbufferedCharacterStream`）。这对于确保 V8 的稳定性和内存管理至关重要。

**关于文件扩展名和 Torque:**

你提供的代码是 C++ 代码，以 `.cc` 结尾。如果 `v8/test/unittests/parser/scanner-streams-unittest.cc` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。Torque 是 V8 用来生成高效运行时代码的一种领域特定语言。但这个文件不是 Torque 文件。

**与 JavaScript 功能的关系以及 JavaScript 示例:**

`v8/test/unittests/parser/scanner-streams-unittest.cc` 中测试的 Scanner Streams 是 V8 引擎解析 JavaScript 代码的第一步。当 V8 执行 JavaScript 代码时，它首先需要将源代码转换成抽象语法树 (AST)。这个过程的开始阶段就是扫描 (Scanning)，也称为词法分析。

Scanner Streams 负责将输入的 JavaScript 源代码（通常是文本形式）分解成一个个的词法单元 (tokens)，例如关键字、标识符、运算符、字面量等。

**JavaScript 示例:**

考虑以下简单的 JavaScript 代码：

```javascript
function add(a, b) {
  return a + b;
}

let result = add(5, 3);
console.log(result);
```

当 V8 解析这段代码时，Scanner Streams 会将它分解成如下的词法单元（简化）：

- `function` (关键字)
- `add` (标识符)
- `(` (左括号)
- `a` (标识符)
- `,` (逗号)
- `b` (标识符)
- `)` (右括号)
- `{` (左花括号)
- `return` (关键字)
- `a` (标识符)
- `+` (运算符)
- `b` (标识符)
- `;` (分号)
- `}` (右花括号)
- `let` (关键字)
- `result` (标识符)
- `=` (运算符)
- `add` (标识符)
- `(` (左括号)
- `5` (数字字面量)
- `,` (逗号)
- `3` (数字字面量)
- `)` (右括号)
- `;` (分号)
- `console` (标识符)
- `. `(点运算符)
- `log` (标识符)
- `(` (左括号)
- `result` (标识符)
- `)` (右括号)
- `;` (分号)

Scanner Streams 需要能够正确地读取和识别这些词法单元，无论源代码是以何种方式提供（例如，作为字符串、外部文件流等）和使用何种编码（通常是 UTF-8）。

**代码逻辑推理 (假设输入与输出):**

让我们以 `TEST_F(ScannerStreamsTest, Utf8StreamBOM)` 为例：

**假设输入:**

一个包含 UTF-8 BOM 的字符串，例如：`"\xef\xbb\xbf" + "abc"` (BOM + "abc" 的 UTF-8 编码)。

**预期输出:**

Scanner Stream 应该跳过 BOM，并按顺序产生字符 'a', 'b', 'c'。 `stream->Advance()` 的调用应该依次返回 97 (字符 'a' 的 Unicode 值), 98 ('b'), 99 ('c')，最后返回 `v8::internal::Utf16CharacterStream::kEndOfInput` 表示输入结束。

**涉及用户常见的编程错误 (举例说明):**

1. **错误地处理字符编码:** 用户可能错误地假设输入总是 ASCII，而没有考虑到 UTF-8 等多字节编码。这会导致解析包含非 ASCII 字符的源代码时出现错误。

   **C++ 示例:**

   ```c++
   // 假设读取的是 ASCII，但实际是 UTF-8
   const char* utf8_string = "你好"; // UTF-8 编码
   for (int i = 0; utf8_string[i] != '\0'; ++i) {
       printf("%c\n", utf8_string[i]); // 可能会打印出乱码，因为 UTF-8 字符占多个字节
   }
   ```

2. **没有正确处理 BOM:**  用户的程序可能没有检测和跳过 UTF-8 BOM，导致将 BOM 的字节误认为是普通字符。

   **C++ 示例:**

   ```c++
   // 没有处理 BOM 的情况
   const char* utf8_with_bom = "\xef\xbb\xbfABC";
   // 错误地将 BOM 的字节也当作字符处理
   for (int i = 0; utf8_with_bom[i] != '\0'; ++i) {
       printf("%x ", static_cast<unsigned char>(utf8_with_bom[i]));
   }
   // 输出可能会包含 EF BB BF 等 BOM 的字节
   ```

3. **在处理流式输入时出现错误:** 用户可能没有正确地处理分块读取的数据，例如，在字符的字节序列被分割在不同的数据块中时，无法正确地拼接和解析字符。

   **假设情景:**  一个 UTF-8 编码的字符被分割在两个数据块中：第一个块包含字符的前几个字节，第二个块包含剩余的字节。如果扫描器没有正确处理这种情况，就会导致解析错误。

**总结 (第 1 部分的功能):**

`v8/test/unittests/parser/scanner-streams-unittest.cc` 的第 1 部分主要关注于测试 V8 引擎中用于扫描源代码的字符流的基本功能，特别是针对 UTF-8 编码和不同输入源的测试。它涵盖了字符的读取、定位、回退以及对 UTF-8 BOM 的处理。这些测试旨在确保扫描器能够准确地从各种来源读取和解码源代码字符，为后续的词法分析和语法分析奠定基础。

### 提示词
```
这是目录为v8/test/unittests/parser/scanner-streams-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/parser/scanner-streams-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/base/strings.h"
#include "src/heap/factory-inl.h"
#include "src/objects/objects-inl.h"
#include "src/parsing/scanner-character-streams.h"
#include "src/parsing/scanner.h"
#include "test/unittests/heap/heap-utils.h"
#include "test/unittests/test-utils.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {

using ScannerStreamsTest = v8::TestWithIsolate;
// Implement ExternalSourceStream based on const char**.
// This will take each string as one chunk. The last chunk must be empty.
class ChunkSource : public v8::ScriptCompiler::ExternalSourceStream {
 public:
  template <typename Char>
  explicit ChunkSource(const Char** chunks) : current_(0) {
    do {
      chunks_.push_back({reinterpret_cast<const uint8_t*>(*chunks),
                         (sizeof(Char) / sizeof(uint8_t)) *
                             std::char_traits<Char>::length(*chunks)});
      chunks++;
    } while (chunks_.back().len > 0);
  }
  explicit ChunkSource(const char* chunks) : current_(0) {
    do {
      chunks_.push_back(
          {reinterpret_cast<const uint8_t*>(chunks), strlen(chunks)});
      chunks += strlen(chunks) + 1;
    } while (chunks_.back().len > 0);
  }
  ChunkSource(const uint8_t* data, size_t char_size, size_t len,
              bool extra_chunky)
      : current_(0) {
    // If extra_chunky, we'll use increasingly large chunk sizes.  If not, we'll
    // have a single chunk of full length. Make sure that chunks are always
    // aligned to char-size though.
    size_t chunk_size = extra_chunky ? char_size : len;
    for (size_t i = 0; i < len; i += chunk_size, chunk_size += char_size) {
      chunks_.push_back({data + i, std::min(chunk_size, len - i)});
    }
    chunks_.push_back({nullptr, 0});
  }
  ~ChunkSource() override = default;
  size_t GetMoreData(const uint8_t** src) override {
    DCHECK_LT(current_, chunks_.size());
    Chunk& next = chunks_[current_++];
    uint8_t* chunk = new uint8_t[next.len];
    if (next.len > 0) {
      i::MemMove(chunk, next.ptr, next.len);
    }
    *src = chunk;
    return next.len;
  }

 private:
  struct Chunk {
    const uint8_t* ptr;
    size_t len;
  };
  std::vector<Chunk> chunks_;
  size_t current_;
};

// Checks that Lock() / Unlock() pairs are balanced. Not thread-safe.
class LockChecker {
 public:
  LockChecker() : lock_depth_(0) {}
  ~LockChecker() { CHECK_EQ(0, lock_depth_); }

  void Lock() const { lock_depth_++; }

  void Unlock() const {
    CHECK_GT(lock_depth_, 0);
    lock_depth_--;
  }

  bool IsLocked() const { return lock_depth_ > 0; }

  int LockDepth() const { return lock_depth_; }

 protected:
  mutable int lock_depth_;
};

class TestExternalResource : public v8::String::ExternalStringResource,
                             public LockChecker {
 public:
  explicit TestExternalResource(uint16_t* data, int length)
      : LockChecker(), data_(data), length_(static_cast<size_t>(length)) {}

  const uint16_t* data() const override {
    CHECK(IsLocked());
    return data_;
  }

  size_t length() const override { return length_; }

  bool IsCacheable() const override { return false; }
  void Lock() const override { LockChecker::Lock(); }
  void Unlock() const override { LockChecker::Unlock(); }

 private:
  uint16_t* data_;
  size_t length_;
};

class TestExternalOneByteResource
    : public v8::String::ExternalOneByteStringResource,
      public LockChecker {
 public:
  TestExternalOneByteResource(const char* data, size_t length)
      : data_(data), length_(length) {}

  const char* data() const override {
    CHECK(IsLocked());
    return data_;
  }
  size_t length() const override { return length_; }

  bool IsCacheable() const override { return false; }
  void Lock() const override { LockChecker::Lock(); }
  void Unlock() const override { LockChecker::Unlock(); }

 private:
  const char* data_;
  size_t length_;
};

// A test string with all lengths of utf-8 encodings.
const char unicode_utf8[] =
    "abc"               // 3x ascii
    "\xc3\xa4"          // a Umlaut, code point 228
    "\xe2\xa8\xa0"      // >> (math symbol), code point 10784
    "\xf0\x9f\x92\xa9"  // best character, code point 128169,
                        //     as utf-16 surrogates: 55357 56489
    "def";              // 3x ascii again.
const uint16_t unicode_ucs2[] = {97,    98,  99,  228, 10784, 55357,
                                 56489, 100, 101, 102, 0};

i::Handle<i::String> NewExternalTwoByteStringFromResource(
    i::Isolate* isolate, TestExternalResource* resource) {
  i::Factory* factory = isolate->factory();
  // String creation accesses the resource.
  resource->Lock();
  i::Handle<i::String> uc16_string(
      factory->NewExternalStringFromTwoByte(resource).ToHandleChecked());
  resource->Unlock();
  return uc16_string;
}

}  // anonymous namespace

TEST_F(ScannerStreamsTest, Utf8StreamAsciiOnly) {
  const char* chunks[] = {"abc", "def", "ghi", ""};
  ChunkSource chunk_source(chunks);
  std::unique_ptr<v8::internal::Utf16CharacterStream> stream(
      v8::internal::ScannerStream::For(
          &chunk_source, v8::ScriptCompiler::StreamedSource::UTF8));

  // Read the data without dying.
  v8::base::uc32 c;
  do {
    c = stream->Advance();
  } while (c != v8::internal::Utf16CharacterStream::kEndOfInput);
}

TEST_F(ScannerStreamsTest, Utf8StreamMaxNonSurrogateCharCode) {
  const char* chunks[] = {"\uffff\uffff", ""};
  ChunkSource chunk_source(chunks);
  std::unique_ptr<v8::internal::Utf16CharacterStream> stream(
      v8::internal::ScannerStream::For(
          &chunk_source, v8::ScriptCompiler::StreamedSource::UTF8));

  // Read the correct character.
  uint16_t max = unibrow::Utf16::kMaxNonSurrogateCharCode;
  CHECK_EQ(max, static_cast<uint32_t>(stream->Advance()));
  CHECK_EQ(max, static_cast<uint32_t>(stream->Advance()));
  CHECK_EQ(i::Utf16CharacterStream::kEndOfInput, stream->Advance());
}

TEST_F(ScannerStreamsTest, Utf8StreamBOM) {
  // Construct test string w/ UTF-8 BOM (byte order mark)
  char data[3 + arraysize(unicode_utf8)] = {"\xef\xbb\xbf"};
  strncpy(data + 3, unicode_utf8, arraysize(unicode_utf8));

  const char* chunks[] = {data, "\0"};
  ChunkSource chunk_source(chunks);
  std::unique_ptr<v8::internal::Utf16CharacterStream> stream(
      v8::internal::ScannerStream::For(
          &chunk_source, v8::ScriptCompiler::StreamedSource::UTF8));

  // Read the data without tripping over the BOM.
  for (size_t i = 0; unicode_ucs2[i]; i++) {
    CHECK_EQ(unicode_ucs2[i], stream->Advance());
  }
  CHECK_EQ(v8::internal::Utf16CharacterStream::kEndOfInput, stream->Advance());

  // Make sure seek works.
  stream->Seek(0);
  CHECK_EQ(unicode_ucs2[0], stream->Advance());

  stream->Seek(5);
  CHECK_EQ(unicode_ucs2[5], stream->Advance());

  // Try again, but make sure we have to seek 'backwards'.
  while (v8::internal::Utf16CharacterStream::kEndOfInput != stream->Advance()) {
    // Do nothing. We merely advance the stream to the end of its input.
  }
  stream->Seek(5);
  CHECK_EQ(unicode_ucs2[5], stream->Advance());
}

TEST_F(ScannerStreamsTest, Utf8SplitBOM) {
  // Construct chunks with a BOM split into two chunks.
  char partial_bom[] = "\xef\xbb";
  char data[1 + arraysize(unicode_utf8)] = {"\xbf"};
  strncpy(data + 1, unicode_utf8, arraysize(unicode_utf8));

  {
    const char* chunks[] = {partial_bom, data, "\0"};
    ChunkSource chunk_source(chunks);
    std::unique_ptr<v8::internal::Utf16CharacterStream> stream(
        v8::internal::ScannerStream::For(
            &chunk_source, v8::ScriptCompiler::StreamedSource::UTF8));

    // Read the data without tripping over the BOM.
    for (size_t i = 0; unicode_ucs2[i]; i++) {
      CHECK_EQ(unicode_ucs2[i], stream->Advance());
    }
  }

  // And now with single-byte BOM chunks.
  char bom_byte_1[] = "\xef";
  char bom_byte_2[] = "\xbb";
  {
    const char* chunks[] = {bom_byte_1, bom_byte_2, data, "\0"};
    ChunkSource chunk_source(chunks);
    std::unique_ptr<v8::internal::Utf16CharacterStream> stream(
        v8::internal::ScannerStream::For(
            &chunk_source, v8::ScriptCompiler::StreamedSource::UTF8));

    // Read the data without tripping over the BOM.
    for (size_t i = 0; unicode_ucs2[i]; i++) {
      CHECK_EQ(unicode_ucs2[i], stream->Advance());
    }
  }
}

TEST_F(ScannerStreamsTest, Utf8SplitMultiBOM) {
  // Construct chunks with a split BOM followed by another split BOM.
  const char* chunks[] = {"\xef\xbb", "\xbf\xef\xbb", "\xbf", ""};
  ChunkSource chunk_source(chunks);
  std::unique_ptr<i::Utf16CharacterStream> stream(
      v8::internal::ScannerStream::For(
          &chunk_source, v8::ScriptCompiler::StreamedSource::UTF8));

  // Read the data, ensuring we get exactly one of the two BOMs back.
  CHECK_EQ(0xFEFF, stream->Advance());
  CHECK_EQ(i::Utf16CharacterStream::kEndOfInput, stream->Advance());
}

TEST_F(ScannerStreamsTest, Utf8AdvanceUntil) {
  // Test utf-8 advancing until a certain char.

  const char line_term = '\n';
  const size_t kLen = arraysize(unicode_utf8);
  char data[kLen + 1];
  strncpy(data, unicode_utf8, kLen);
  data[kLen - 1] = line_term;
  data[kLen] = '\0';

  {
    const char* chunks[] = {data, "\0"};
    ChunkSource chunk_source(chunks);
    std::unique_ptr<v8::internal::Utf16CharacterStream> stream(
        v8::internal::ScannerStream::For(
            &chunk_source, v8::ScriptCompiler::StreamedSource::UTF8));

    int32_t res = stream->AdvanceUntil(
        [](int32_t c0_) { return unibrow::IsLineTerminator(c0_); });
    CHECK_EQ(line_term, res);
  }
}

TEST_F(ScannerStreamsTest, AdvanceMatchAdvanceUntil) {
  // Test if single advance and advanceUntil behave the same

  char data[] = {'a', 'b', '\n', 'c', '\0'};

  {
    const char* chunks[] = {data, "\0"};
    ChunkSource chunk_source_a(chunks);

    std::unique_ptr<v8::internal::Utf16CharacterStream> stream_advance(
        v8::internal::ScannerStream::For(
            &chunk_source_a, v8::ScriptCompiler::StreamedSource::UTF8));

    ChunkSource chunk_source_au(chunks);
    std::unique_ptr<v8::internal::Utf16CharacterStream> stream_advance_until(
        v8::internal::ScannerStream::For(
            &chunk_source_au, v8::ScriptCompiler::StreamedSource::UTF8));

    int32_t au_c0_ = stream_advance_until->AdvanceUntil(
        [](int32_t c0_) { return unibrow::IsLineTerminator(c0_); });

    int32_t a_c0_ = '0';
    while (!unibrow::IsLineTerminator(a_c0_)) {
      a_c0_ = stream_advance->Advance();
    }

    // Check both advances methods have the same output
    CHECK_EQ(a_c0_, au_c0_);

    // Check if both set the cursor to the correct position by advancing both
    // streams by one character.
    a_c0_ = stream_advance->Advance();
    au_c0_ = stream_advance_until->Advance();
    CHECK_EQ(a_c0_, au_c0_);
  }
}

TEST_F(ScannerStreamsTest, Utf8AdvanceUntilOverChunkBoundaries) {
  // Test utf-8 advancing until a certain char, crossing chunk boundaries.

  // Split the test string at each byte and pass it to the stream. This way,
  // we'll have a split at each possible boundary.
  size_t len = strlen(unicode_utf8);
  char buffer[arraysize(unicode_utf8) + 4];
  for (size_t i = 1; i < len; i++) {
    // Copy source string into buffer, splitting it at i.
    // Then add three chunks, 0..i-1, i..strlen-1, empty.
    memcpy(buffer, unicode_utf8, i);
    memcpy(buffer + i + 1, unicode_utf8 + i, len - i);
    buffer[i] = '\0';
    buffer[len + 1] = '\n';
    buffer[len + 2] = '\0';
    buffer[len + 3] = '\0';
    const char* chunks[] = {buffer, buffer + i + 1, buffer + len + 2};

    ChunkSource chunk_source(chunks);
    std::unique_ptr<v8::internal::Utf16CharacterStream> stream(
        v8::internal::ScannerStream::For(
            &chunk_source, v8::ScriptCompiler::StreamedSource::UTF8));

    int32_t res = stream->AdvanceUntil(
        [](int32_t c0_) { return unibrow::IsLineTerminator(c0_); });
    CHECK_EQ(buffer[len + 1], res);
  }
}

TEST_F(ScannerStreamsTest, Utf8ChunkBoundaries) {
  // Test utf-8 parsing at chunk boundaries.

  // Split the test string at each byte and pass it to the stream. This way,
  // we'll have a split at each possible boundary.
  size_t len = strlen(unicode_utf8);
  char buffer[arraysize(unicode_utf8) + 3];
  for (size_t i = 1; i < len; i++) {
    // Copy source string into buffer, splitting it at i.
    // Then add three chunks, 0..i-1, i..strlen-1, empty.
    memcpy(buffer, unicode_utf8, i);
    memcpy(buffer + i + 1, unicode_utf8 + i, len - i);
    buffer[i] = '\0';
    buffer[len + 1] = '\0';
    buffer[len + 2] = '\0';
    const char* chunks[] = {buffer, buffer + i + 1, buffer + len + 2};

    ChunkSource chunk_source(chunks);
    std::unique_ptr<v8::internal::Utf16CharacterStream> stream(
        v8::internal::ScannerStream::For(
            &chunk_source, v8::ScriptCompiler::StreamedSource::UTF8));

    for (size_t j = 0; unicode_ucs2[j]; j++) {
      CHECK_EQ(unicode_ucs2[j], stream->Advance());
    }
    CHECK_EQ(v8::internal::Utf16CharacterStream::kEndOfInput,
             stream->Advance());
  }
}

TEST_F(ScannerStreamsTest, Utf8SingleByteChunks) {
  // Have each byte as a single-byte chunk.
  size_t len = strlen(unicode_utf8);
  char buffer[arraysize(unicode_utf8) + 4];
  for (size_t i = 1; i < len - 1; i++) {
    // Copy source string into buffer, make a single-byte chunk at i.
    memcpy(buffer, unicode_utf8, i);
    memcpy(buffer + i + 3, unicode_utf8 + i + 1, len - i - 1);
    buffer[i] = '\0';
    buffer[i + 1] = unicode_utf8[i];
    buffer[i + 2] = '\0';
    buffer[len + 2] = '\0';
    buffer[len + 3] = '\0';
    const char* chunks[] = {buffer, buffer + i + 1, buffer + i + 3,
                            buffer + len + 3};

    ChunkSource chunk_source(chunks);
    std::unique_ptr<v8::internal::Utf16CharacterStream> stream(
        v8::internal::ScannerStream::For(
            &chunk_source, v8::ScriptCompiler::StreamedSource::UTF8));

    for (size_t j = 0; unicode_ucs2[j]; j++) {
      CHECK_EQ(unicode_ucs2[j], stream->Advance());
    }
    CHECK_EQ(v8::internal::Utf16CharacterStream::kEndOfInput,
             stream->Advance());
  }
}

#define CHECK_EQU(v1, v2) CHECK_EQ(static_cast<int>(v1), static_cast<int>(v2))

void TestCharacterStream(const char* reference, i::Utf16CharacterStream* stream,
                         unsigned length, unsigned start, unsigned end) {
  // Read streams one char at a time
  unsigned i;
  for (i = start; i < end; i++) {
    CHECK_EQU(i, stream->pos());
    CHECK_EQU(reference[i], stream->Advance());
  }
  CHECK_EQU(end, stream->pos());
  CHECK_EQU(i::Utf16CharacterStream::kEndOfInput, stream->Advance());
  CHECK_EQU(end + 1, stream->pos());
  stream->Back();

  // Pushback, re-read, pushback again.
  while (i > end / 4) {
    int32_t c0 = reference[i - 1];
    CHECK_EQU(i, stream->pos());
    stream->Back();
    i--;
    CHECK_EQU(i, stream->pos());
    int32_t c1 = stream->Advance();
    i++;
    CHECK_EQU(i, stream->pos());
    CHECK_EQ(c0, c1);
    stream->Back();
    i--;
    CHECK_EQU(i, stream->pos());
  }

  // Seek + read streams one char at a time.
  unsigned halfway = end / 2;
  stream->Seek(stream->pos() + halfway - i);
  for (i = halfway; i < end; i++) {
    CHECK_EQU(i, stream->pos());
    CHECK_EQU(reference[i], stream->Advance());
  }
  CHECK_EQU(i, stream->pos());
  CHECK(i::Scanner::IsInvalid(stream->Advance()));

  // Seek back, then seek beyond end of stream.
  stream->Seek(start);
  if (start < length) {
    CHECK_EQU(stream->Advance(), reference[start]);
  } else {
    CHECK(i::Scanner::IsInvalid(stream->Advance()));
  }
  stream->Seek(length + 5);
  CHECK(i::Scanner::IsInvalid(stream->Advance()));
}

void TestCloneCharacterStream(const char* reference,
                              i::Utf16CharacterStream* stream,
                              unsigned length) {
  // Test original stream through to the end.
  TestCharacterStream(reference, stream, length, 0, length);

  // Clone the stream after it completes.
  std::unique_ptr<i::Utf16CharacterStream> clone = stream->Clone();

  // Test that the clone through to the end.
  TestCharacterStream(reference, clone.get(), length, 0, length);

  // Rewind original stream to a third.
  stream->Seek(length / 3);

  // Rewind clone stream to two thirds.
  clone->Seek(2 * length / 3);

  // Test seeking clone didn't affect original stream.
  TestCharacterStream(reference, stream, length, length / 3, length);

  // Test seeking original stream didn't affect clone.
  TestCharacterStream(reference, clone.get(), length, 2 * length / 3, length);
}

#undef CHECK_EQU

void TestCharacterStreams(const char* one_byte_source, unsigned length,
                          unsigned start = 0, unsigned end = 0) {
  if (end == 0) end = length;

  i::Isolate* isolate =
      reinterpret_cast<i::Isolate*>(v8::Isolate::GetCurrent());
  i::Factory* factory = isolate->factory();

  // 2-byte external string
  std::unique_ptr<v8::base::uc16[]> uc16_buffer(new v8::base::uc16[length]);
  v8::base::Vector<const v8::base::uc16> two_byte_vector(
      uc16_buffer.get(), static_cast<int>(length));
  {
    for (unsigned i = 0; i < length; i++) {
      uc16_buffer[i] = static_cast<v8::base::uc16>(one_byte_source[i]);
    }
    TestExternalResource resource(uc16_buffer.get(), length);
    i::Handle<i::String> uc16_string(
        NewExternalTwoByteStringFromResource(isolate, &resource));
    std::unique_ptr<i::Utf16CharacterStream> uc16_stream(
        i::ScannerStream::For(isolate, uc16_string, start, end));
    TestCharacterStream(one_byte_source, uc16_stream.get(), length, start, end);

    // This avoids the GC from trying to free a stack allocated resource.
    if (IsExternalString(*uc16_string))
      i::Cast<i::ExternalTwoByteString>(uc16_string)
          ->SetResource(isolate, nullptr);
  }

  // 1-byte external string
  v8::base::Vector<const uint8_t> one_byte_vector =
      v8::base::OneByteVector(one_byte_source, static_cast<int>(length));
  i::Handle<i::String> one_byte_string =
      factory->NewStringFromOneByte(one_byte_vector).ToHandleChecked();
  {
    TestExternalOneByteResource one_byte_resource(one_byte_source, length);
    i::Handle<i::String> ext_one_byte_string(
        factory->NewExternalStringFromOneByte(&one_byte_resource)
            .ToHandleChecked());
    std::unique_ptr<i::Utf16CharacterStream> one_byte_stream(
        i::ScannerStream::For(isolate, ext_one_byte_string, start, end));
    TestCharacterStream(one_byte_source, one_byte_stream.get(), length, start,
                        end);
    // This avoids the GC from trying to free a stack allocated resource.
    if (IsExternalString(*ext_one_byte_string))
      i::Cast<i::ExternalOneByteString>(ext_one_byte_string)
          ->SetResource(isolate, nullptr);
  }

  // 1-byte generic i::String
  {
    std::unique_ptr<i::Utf16CharacterStream> string_stream(
        i::ScannerStream::For(isolate, one_byte_string, start, end));
    TestCharacterStream(one_byte_source, string_stream.get(), length, start,
                        end);
  }

  // 2-byte generic i::String
  {
    i::Handle<i::String> two_byte_string =
        factory->NewStringFromTwoByte(two_byte_vector).ToHandleChecked();
    std::unique_ptr<i::Utf16CharacterStream> two_byte_string_stream(
        i::ScannerStream::For(isolate, two_byte_string, start, end));
    TestCharacterStream(one_byte_source, two_byte_string_stream.get(), length,
                        start, end);
  }

  // Streaming has no notion of start/end, so let's skip streaming tests for
  // these cases.
  if (start != 0 || end != length) return;

  // 1-byte streaming stream, single + many chunks.
  {
    const uint8_t* data = one_byte_vector.begin();
    const uint8_t* data_end = one_byte_vector.end();

    ChunkSource single_chunk(data, 1, data_end - data, false);
    std::unique_ptr<i::Utf16CharacterStream> one_byte_streaming_stream(
        i::ScannerStream::For(&single_chunk,
                              v8::ScriptCompiler::StreamedSource::ONE_BYTE));
    TestCharacterStream(one_byte_source, one_byte_streaming_stream.get(),
                        length, start, end);

    ChunkSource many_chunks(data, 1, data_end - data, true);
    one_byte_streaming_stream.reset(i::ScannerStream::For(
        &many_chunks, v8::ScriptCompiler::StreamedSource::ONE_BYTE));
    TestCharacterStream(one_byte_source, one_byte_streaming_stream.get(),
                        length, start, end);
  }

  // UTF-8 streaming stream, single + many chunks.
  {
    const uint8_t* data = one_byte_vector.begin();
    const uint8_t* data_end = one_byte_vector.end();
    ChunkSource chunks(data, 1, data_end - data, false);
    std::unique_ptr<i::Utf16CharacterStream> utf8_streaming_stream(
        i::ScannerStream::For(&chunks,
                              v8::ScriptCompiler::StreamedSource::UTF8));
    TestCharacterStream(one_byte_source, utf8_streaming_stream.get(), length,
                        start, end);

    ChunkSource many_chunks(data, 1, data_end - data, true);
    utf8_streaming_stream.reset(i::ScannerStream::For(
        &many_chunks, v8::ScriptCompiler::StreamedSource::UTF8));
    TestCharacterStream(one_byte_source, utf8_streaming_stream.get(), length,
                        start, end);
  }

  // 2-byte streaming stream, single + many chunks.
  {
    const uint8_t* data =
        reinterpret_cast<const uint8_t*>(two_byte_vector.begin());
    const uint8_t* data_end =
        reinterpret_cast<const uint8_t*>(two_byte_vector.end());
    ChunkSource chunks(data, 2, data_end - data, false);
    std::unique_ptr<i::Utf16CharacterStream> two_byte_streaming_stream(
        i::ScannerStream::For(&chunks,
                              v8::ScriptCompiler::StreamedSource::TWO_BYTE));
    TestCharacterStream(one_byte_source, two_byte_streaming_stream.get(),
                        length, start, end);

    ChunkSource many_chunks(data, 2, data_end - data, true);
    two_byte_streaming_stream.reset(i::ScannerStream::For(
        &many_chunks, v8::ScriptCompiler::StreamedSource::TWO_BYTE));
    TestCharacterStream(one_byte_source, two_byte_streaming_stream.get(),
                        length, start, end);
  }
}

TEST_F(ScannerStreamsTest, CharacterStreams) {
  v8::HandleScope handles(isolate());
  v8::Local<v8::Context> context = v8::Context::New(isolate());
  v8::Context::Scope context_scope(context);

  TestCharacterStreams("abcdefghi", 9);
  TestCharacterStreams("abc\0\n\r\x7f", 7);
  TestCharacterStreams("\0", 1);
  TestCharacterStreams("", 0);

  // 4k large buffer.
  char buffer[4096 + 1];
  for (unsigned i = 0; i < arraysize(buffer); i++) {
    buffer[i] = static_cast<char>(i & 0x7F);
  }
  buffer[arraysize(buffer) - 1] = '\0';
  TestCharacterStreams(buffer, arraysize(buffer) - 1);
  TestCharacterStreams(buffer, arraysize(buffer) - 1, 576, 3298);
}

// Regression test for crbug.com/651333. Read invalid utf-8.
TEST_F(ScannerStreamsTest, Regress651333) {
  const uint8_t bytes[] =
      "A\xf1"
      "ad";  // Anad, with n == n-with-tilde.
  const uint16_t unicode[] = {65, 65533, 97, 100};

  // Run the test for all sub-strings 0..N of bytes, to make sure we hit the
  // error condition in and at chunk boundaries.
  for (size_t len = 0; len < arraysize(bytes); len++) {
    // Read len bytes from bytes, and compare against the expected unicode
    // characters. Expect kBadChar ( == Unicode replacement char == code point
    // 65533) instead of the incorrectly coded Latin1 char.
    ChunkSource chunks(bytes, 1, len, false);
    std::unique_ptr<i::Utf16CharacterStream> stream(i::ScannerStream::For(
        &chunks, v8::ScriptCompiler::StreamedSource::UTF8));
    for (size_t i = 0; i < len; i++) {
      CHECK_EQ(unicode[i], stream->Advance());
    }
    CHECK_EQ(i::Utf16CharacterStream::kEndOfInput, stream->Advance());
  }
}

void TestChunkStreamAgainstReference(
    const char* cases[],
    const std::vector<std::vector<uint16_t>>& unicode_expected) {
  for (size_t c = 0; c < unicode_expected.size(); ++c) {
    ChunkSource chunk_source(cases[c]);
    std::unique_ptr<i::Utf16CharacterStream> stream(i::ScannerStream::For(
        &chunk_source, v8::ScriptCompiler::StreamedSource::UTF8));
    for (size_t i = 0; i < unicode_expected[c].size(); i++) {
      CHECK_EQ(unicode_expected[c][i], stream->Advance());
    }
    CHECK_EQ(i::Utf16CharacterStream::kEndOfInput, stream->Advance());
    stream->Seek(0);
    for (size_t i = 0; i < unicode_expected[c].size(); i++) {
      CHECK_EQ(unicode_expected[c][i], stream->Advance());
    }
    CHECK_EQ(i::Utf16CharacterStream::kEndOfInput, stream->Advance());
  }
}

TEST_F(ScannerStreamsTest, Regress6377) {
  const char* cases[] = {
      "\xf0\x90\0"  // first chunk - start of 4-byte seq
      "\x80\x80"    // second chunk - end of 4-byte seq
      "a\0",        // and an 'a'

      "\xe0\xbf\0"  // first chunk - start of 3-byte seq
      "\xbf"        // second chunk - one-byte end of 3-byte seq
      "a\0",        // and an 'a'

      "\xc3\0"  // first chunk - start of 2-byte seq
      "\xbf"    // second chunk - end of 2-byte seq
      "a\0",    // and an 'a'

      "\xf0\x90\x80\0"  // first chunk - start of 4-byte seq
      "\x80"            // second chunk - one-byte end of 4-byte seq
      "a\xc3\0"         // and an 'a' + start of 2-byte seq
      "\xbf\0",         // third chunk - end of 2-byte seq
  };
  const std::vector<std::vector<uint16_t>> unicode_expected = {
      {0xD800, 0xDC00, 97},
      {0xFFF, 97},
      {0xFF, 97},
      {0xD800, 0xDC00, 97, 0xFF},
  };
  CHECK_EQ(unicode_expected.size(), arraysize(cases));
  TestChunkStreamAgainstReference(cases, unicode_expected);
}

TEST_F(ScannerStreamsTest, Regress6836) {
  const char* cases[] = {
      // 0xC2 is a lead byte, but there's no continuation. The bug occurs when
      // this happens near the chunk end.
      "X\xc2Y\0",
      // Last chunk ends with a 2-byte char lead.
      "X\xc2\0",
      // Last chunk ends with a 3-byte char lead and only one continuation
      // character.
      "X\xe0\xbf\0",
  };
  const std::vector<std::vector<uint16_t>> unicode_expected = {
      {0x58, 0xFFFD, 0x59},
      {0x58, 0xFFFD},
      {0x58, 0xFFFD},
  };
  CHECK_EQ(unicode_expected.size(), arraysize(cases));
  TestChunkStreamAgainstReference(cases, unicode_expected);
}

TEST_F(ScannerStreamsTest, TestOverlongAndInvalidSequences) {
  const char* cases[] = {
      // Overlong 2-byte sequence.
      "X\xc0\xbfY\0",
      // Another overlong 2-byte sequence.
      "X\xc1\xbfY\0",
      // Overlong 3-byte sequence.
      "X\xe0\x9f\xbfY\0",
      // Overlong 4-byte sequence.
      "X\xf0\x89\xbf\xbfY\0",
      // Invalid 3-byte sequence (reserved for surrogates).
      "X\xed\xa0\x80Y\0",
      // Invalid 4-bytes sequence (value out of range).
      "X\xf4\x90\x80\x80Y\0",
  };
  const std::vector<std::vector<uint16_t>> unicode_expected = {
      {0x58, 0xFFFD, 0xFFFD, 0x59},
      {0x58, 0xFFFD, 0xFFFD, 0x59},
      {0x58, 0xFFFD, 0xFFFD, 0xFFFD, 0x59},
      {0x58, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0x59},
      {0x58, 0xFFFD, 0xFFFD, 0xFFFD, 0x59},
      {0x58, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0x59},
  };
  CHECK_EQ(unicode_expected.size(), arraysize(cases));
  TestChunkStreamAgainstReference(cases, unicode_expected);
}

TEST_F(ScannerStreamsTest, RelocatingCharacterStream) {
  // This test relies on the invariant that GC will move objects.
  if (i::v8_flags.single_generation) return;
  i::v8_flags.manual_evacuation_candidates_selection = true;
  v8::internal::ManualGCScope manual_gc_scope(i_isolate());
  v8::HandleScope scope(isolate());

  const char* string = "abcd";
  int length = static_cast<int>(strlen(string));
  std::unique_ptr<v8::base::uc16[]> uc16_buffer(new v8::base::uc16[length]);
  for (int i = 0; i < length; i++) {
    uc16_buffer[i] = string[i];
  }
  v8::base::Vector<const v8::base::uc16> two_byte_vector(uc16_buffer.get(),
                                                         length);
  i::Handle<i::String> two_byte_string =
      i_isolate()
          ->factory()
          ->NewStringFromTwoByte(two_byte_vector, i::AllocationType::kYoung)
          .ToHandleChecked();
  std::unique_ptr<i::Utf16CharacterStream> two_byte_string_stream(
      i::ScannerStream::For(i_isolate(), two_byte_string, 0, length));
  CHECK_EQ('a', two_byte_string_stream->Advance());
  CHECK_EQ('b', two_byte_string_stream->Advance());
  CHECK_EQ(size_t{2}, two_byte_string_stream->pos());
  i::Tagged<i::String> raw = *two_byte_string;
  // We need to invoke GC without stack, otherwise no compaction is performed.
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      i_isolate()->heap());
  // 1st GC moves `two_byte_string` to old space and 2nd GC evacuates it within
  // old space.
  InvokeMajorGC();
  i::MemoryChunk::FromHeapObject(*two_byte_string)
      ->SetFlagNonExecutable(
          i::MemoryChunk::FORCE_EVACUATION_CANDIDATE_FOR_TESTING);
  InvokeMajorGC();
  // GC moved the string.
  CHECK_NE(raw, *two_byte_string);
  CHECK_EQ('c', two_byte_string_stream->Advance());
  CHECK_EQ('d', two_byte_string_stream->Advance());
}

TEST_F(ScannerStreamsTest, RelocatingUnbufferedCharacterStream) {
  // This test relies on the invariant that GC will move objects.
  if (i::v8_flags.single_generation) return;
  i::v8_flags.manual_evacuation_candidates_selection = true;
  v8::internal::ManualGCScope manual_gc_scope(i_isolate());
  v8::HandleScope scope(isolate());

  const char16_t* string = u"abc\u2603";
  int length = static_cast<int>(std::char_traits<char16_t>::length(string));
  std::unique_ptr<v8::base::uc16[]> uc16_buffer(new v8::base::uc16[length]);
  for (int i = 0; i < length; i++) {
    uc16_buffer[i] = string[i];
  }
  v8::base::Vector<const v8::base::uc16> two_byte_vector(uc16_buffer.get(),
                                                         length);
  i::Handle<i::String> two_byte_string =
      i_isolate()
          ->factory()
          ->NewStringFromTwoByte(two_byte_vector, i::AllocationType::kYoung)
          .ToHandleChecked();
  std::unique_ptr<i::Utf16CharacterStream> two_byte_string_stream(
      i::ScannerStream::For(i_isolate(), two_byte_string, 0, length));

  // Seek to offset 2 so that the buffer_pos_ is not zero initially.
  two_byte_string_stream->Seek(2);
  CHECK_EQ('c', two_byte_string_stream->Advance());
  CHECK_EQ(size_t{3}, two_byte_string_stream->pos());

  i::Tagged<i::String> raw = *two_byte_string;
  // We need to invoke GC without stack, otherwise no compaction is performed.
  i::DisableConservativeStackScanningScopeForTesting no_stack_scanning(
      i_isolate()->heap());
  // 1st GC moves `two_byte_string` to old space and 2nd GC evacuates it within
  // old space.
  InvokeMajorGC();
  i::MemoryChunk::FromHeapObject(*two_byte_string)
      ->SetFlagNonExecutable(
          i::MemoryChunk::FORCE_EVACUATION_CANDIDATE_FOR_TESTING);
  InvokeMajorGC();
  // GC moved the string and buffer was updated to the correct location.
  CHECK_NE(raw, *two_byte_string);

  // Check that we correctly moved based on buffer_pos_, not based on a position
  // of zero.
  CHECK_EQ(u'\u2603', two_byte_string_stream->Advance());
  CHECK_EQ(size_t{4}, two_byte_string_stream->pos());
}

TEST_F(ScannerStreamsTest, CloneCharacterStreams) {
  v8::HandleScope handles(isolate());
  v8::Local<v8::Context> context = v8::Context::New(isolate());
  v8::Context::Scope context_scope(context);

  i::Factory* factory = i_isolate()->factory();

  const char* one_byte_source = "abcdefghi";
  unsigned length = static_cast<unsigned>(strlen(one_byte_source));

  // Check that cloning a character stream does not update

  // 2-byte external string
  std::unique_ptr<v8::base::uc16[]> uc16_buffer(new v8::base::uc16[length]);
  v8::base::Vector<const v8::base::uc16> two_byte_vector(
      uc16_buffer.get(), static_cast<int>(length));
  {
    for (unsigned i = 0; i < length; i++) {
      uc16_buffer[i] = static_cast<v8::base::uc16>(one_byte_source[i]);
    }
    TestExternalResource resource(uc16_buffer.get(), length);
    i::Handle<i::String> uc16_string(
        NewExternalTwoByteStringFromResource(i_isolate(), &resource));
    std::unique_ptr<i::Utf16CharacterStream> uc16_stream(
        i::ScannerStream::For(i_isolate(), uc16_string, 0, length));

    CHECK(resource.IsLocked());
    CHECK_EQ(1, resource.LockDepth());
    std::unique_ptr<i::Utf16CharacterStream> cloned = uc16_stream->Clone();
    CHECK_EQ(2, resource.LockDepth());
    uc16_stream = std::move(cloned);
    CHECK_EQ(1, resource.LockDepth());

    TestCloneCharacterStream(one_
```