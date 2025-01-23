Response:
Let's break down the thought process for analyzing the C++ unittest file.

1. **Identify the Core Purpose:** The filename `streaming-decoder-unittest.cc` immediately suggests that this code tests the `StreamingDecoder` class, specifically in a unit testing context. The "streaming" part implies it deals with processing data in chunks or incrementally.

2. **Examine Includes:** The included headers provide crucial context:
    * `test/unittests/test-utils.h`:  Standard V8 unit testing utilities.
    * `src/objects/objects-inl.h`:  V8's object model (likely not directly relevant to the core streaming logic *being tested*, but part of the environment).
    * `src/wasm/module-decoder.h`: Suggests interaction with a more general WASM module decoding process.
    * `src/wasm/streaming-decoder.h`:  The main target of the tests.
    * `src/objects/descriptor-array.h`, `src/objects/dictionary.h`: Again, V8's internal object system, probably used in the larger context of WASM compilation but not the focus of these *specific* tests.
    * `test/common/wasm/wasm-macro-gen.h`:  Macros for generating WASM bytecode (essential for creating test inputs).

3. **Analyze the Test Structure:** The code defines:
    * `MockStreamingResult`:  A simple struct to capture the results of the streaming decoding process (number of sections, functions, errors, received bytes). This indicates that the tests will be inspecting the *outcomes* of the decoding.
    * `NoTracer`: A dummy class for tracing, likely used in the actual `StreamingDecoder` but not needed for these basic unit tests. This suggests the real decoder might have more complex debugging features.
    * `MockStreamingProcessor`:  A *crucial* component. This class *implements* the `StreamingProcessor` interface. This is a key pattern in testing asynchronous or event-driven systems: create a mock that observes and validates interactions. The mock here checks for the WASM magic number and version, counts sections and functions, and captures the received bytes.
    * `WasmStreamingDecoderTest`: The actual test fixture, inheriting from `::testing::Test`. This provides the test setup and helper methods.

4. **Understand the Test Helper Methods:**
    * `ExpectVerifies`: This method is the core positive test case. It iterates through all possible split points in the input data, creates a `StreamingDecoder` with the `MockStreamingProcessor`, feeds the data in two parts, finishes the stream, and then asserts that the `MockStreamingResult` matches the expected values (no error, correct section/function counts, all bytes received). This splitting is important to test the "streaming" aspect – handling data in chunks.
    * `ExpectFailure`:  Similar to `ExpectVerifies`, but asserts that an error occurred during decoding.

5. **Examine Individual Tests (Focus on Patterns):** The individual `TEST_F` macros reveal the specific scenarios being tested:
    * **Empty Stream:**  Handles the case of no input.
    * **Incomplete Module Header:** Checks for errors when the WASM magic number and version aren't fully provided.
    * **Magic and Version:** A basic success case with just the header.
    * **Bad Magic/Version:**  Tests error handling for incorrect header values.
    * **One/Two Long/Short/Empty Sections:** Tests parsing of different section structures.
    * **One/Two Functions:** Tests the code section and function parsing.
    * **Code Section Length Errors:**  Focuses on validating the length field of the code section.
    * **Number of Functions Errors:** Checks constraints on the number of functions declared.
    * **Two Code Sections:**  Tests the constraint that there should only be one code section.
    * **Unknown Section:**  Verifies handling of non-standard sections.
    * **Unknown Section Sandwich:** Checks error handling when an unknown section appears between code sections.
    * **Invalid Section Code:** Tests handling of completely invalid section identifiers.

6. **Relate to JavaScript (If Applicable):** The key connection to JavaScript is through the WebAssembly API. The C++ code is testing the *internal implementation* of how V8 handles streaming WASM compilation, but this directly relates to how a JavaScript developer would load and instantiate a WASM module asynchronously using `WebAssembly.instantiateStreaming()`.

7. **Identify Code Logic Reasoning and Assumptions:** The `MockStreamingProcessor` embodies the core logic being tested. The assumptions are based on the WASM specification – the expected magic number, version, section structure, and code section format. The tests explicitly check these assumptions.

8. **Consider Common Programming Errors:** The tests implicitly highlight potential errors:
    * **Incorrect WASM Header:** Providing wrong magic numbers or versions.
    * **Malformed Sections:**  Incorrect section IDs, lengths, or missing payload.
    * **Invalid Code Section Structure:**  Incorrect number of functions or function lengths.
    * **Unexpected Section Order:**  Like having multiple code sections.

9. **Structure the Answer:**  Organize the findings into logical categories as requested: functionality, Torque relevance, JavaScript relation, code logic reasoning (with examples), and common errors. Use the information gathered from the code analysis to populate each section. Be specific and provide concrete examples where possible.
这个 C++ 代码文件 `v8/test/unittests/wasm/streaming-decoder-unittest.cc` 是 V8 JavaScript 引擎中用于测试 WebAssembly **流式解码器 (Streaming Decoder)** 功能的单元测试。

以下是它的功能列表：

1. **测试流式解码器的正确性:**  该文件包含了多个测试用例，用于验证 `StreamingDecoder` 类在处理 WebAssembly 字节流时的正确性。流式解码器允许在下载 WebAssembly 模块的同时进行编译，从而提高加载速度。

2. **模拟流式输入:**  测试用例通过模拟接收 WebAssembly 字节流的不同部分（例如，模块头、不同的节、函数体等），来测试解码器在各种情况下的行为。

3. **验证模块头解析:**  测试用例会检查解码器是否正确解析了 WebAssembly 模块的魔数 (magic number) 和版本号。

4. **验证节 (Section) 的解析:**  测试用例会检查解码器是否能够正确识别和处理不同的 WebAssembly 节，例如类型节、导入节、函数节、代码节等（尽管在这个 Mock 的实现中，对具体的节内容并没有做深入的解析）。

5. **验证代码节 (Code Section) 的解析:**  测试用例会特别关注代码节的解析，包括函数数量和每个函数体的长度。

6. **错误处理测试:**  测试用例包含了各种预期的错误情况，例如：
    * 不完整的模块头
    * 错误的魔数或版本号
    * 节的长度不正确
    * 代码节的长度与实际内容不符
    * 函数的数量或长度不正确
    * 出现多个代码节
    * 遇到未知的节 ID

7. **使用 Mock 对象进行测试:**  该文件使用了 `MockStreamingProcessor` 类来模拟流式解码器的使用者，并捕获解码过程中的关键信息，例如处理的节数、函数数量、是否发生错误以及接收到的字节。这允许测试框架独立地验证解码器的行为，而无需实际的编译过程。

8. **测试分片接收:**  `ExpectVerifies` 和 `ExpectFailure` 方法通过将 WebAssembly 字节流分割成不同的片段，并分批发送给解码器，来模拟真实的流式接收场景。

**关于文件后缀 `.tq`:**

`v8/test/unittests/wasm/streaming-decoder-unittest.cc` 的文件后缀是 `.cc`，这表明它是一个 **C++ 源代码文件**。如果文件名以 `.tq` 结尾，那它才是一个 **V8 Torque 源代码文件**。Torque 是 V8 用于生成高效的内置函数的领域特定语言。

**与 JavaScript 的关系:**

`v8/test/unittests/wasm/streaming-decoder-unittest.cc` 测试的流式解码器是 V8 引擎加载和编译 WebAssembly 模块的关键组件。JavaScript 代码可以通过 `WebAssembly.instantiateStreaming()` 方法来触发流式解码过程。

**JavaScript 示例:**

```javascript
// 假设 serverResponse 是一个包含 WebAssembly 字节码的 Response 对象
fetch('my-module.wasm')
  .then(response => WebAssembly.instantiateStreaming(response))
  .then(result => {
    // result.instance 是 WebAssembly 模块的实例
    console.log("WebAssembly 模块加载成功", result.instance);
  })
  .catch(error => {
    console.error("加载 WebAssembly 模块失败", error);
  });
```

在这个例子中，`WebAssembly.instantiateStreaming(response)` 会指示浏览器使用流式解码器来处理从服务器接收到的 WebAssembly 字节流。`v8/test/unittests/wasm/streaming-decoder-unittest.cc` 中的测试就是为了确保 V8 的流式解码器能够正确处理各种合法的和非法的 WebAssembly 字节流，从而保证 `WebAssembly.instantiateStreaming()` 的正确性。

**代码逻辑推理 (假设输入与输出):**

考虑 `TEST_F(WasmStreamingDecoderTest, OneSection)` 这个测试用例：

**假设输入 (data):**

```c++
const uint8_t data[] = {
    U32_LE(kWasmMagic),    // 00 61 73 6d  (wasm)
    U32_LE(kWasmVersion),  // 01 00 00 00
    0x1,                   // Section ID (假设为某种自定义节)
    0x6,                   // Section Length
    0x0,                   // Payload
    0x0,
    0x0,
    0x0,
    0x0,
    0x0
};
```

**预期输出 (MockStreamingResult):**

* `ok()`: `true` (没有错误)
* `num_sections`: `1` (成功处理了一个节)
* `num_functions`: `0` (没有处理函数，因为不是代码节)
* `received_bytes`: 等于输入 `data` 的字节序列

**推理:**

1. `ExpectVerifies` 方法会遍历所有可能的分割点，模拟流式接收。
2. `MockStreamingProcessor` 的 `ProcessModuleHeader` 会验证魔数和版本号。
3. `MockStreamingProcessor` 的 `ProcessSection` 会被调用一次，因为有一个节（Section ID 为 0x1）。
4. `result_->num_sections` 会递增到 1。
5. 由于不是代码节，`ProcessCodeSectionHeader` 和 `ProcessFunctionBody` 不会被调用，所以 `result_->num_functions` 保持为 0。
6. `OnFinishedStream` 会被调用，`result_->received_bytes` 会存储接收到的所有字节。
7. 最终断言会验证 `result` 中的值是否与预期一致。

**用户常见的编程错误示例:**

1. **修改 WebAssembly 模块头时出错:**  用户可能不小心修改了 WebAssembly 文件的开头几个字节，导致魔数或版本号错误。

   **例如 (假设错误的魔数):**

   ```
   const uint8_t bad_header[] = {0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, ...};
   //                               ^^^^^^^^ 错误的魔数
   ```

   `WasmStreamingDecoderTest` 中的 `BadMagic` 测试用例就是为了检测这种情况。

2. **构造 WebAssembly 模块时节的长度计算错误:**  用户在手动构造 WebAssembly 模块时，可能会错误地计算节的长度，导致解码器在读取节内容时遇到问题。

   **例如 (假设节的长度少于实际内容):**

   ```
   const uint8_t incomplete_section[] = {
       WASM_MODULE_HEADER,
       0x01, // Section ID
       0x02, // Section Length (但实际有效载荷更长)
       0x00, 0x00, 0x00 // 实际应该有更多字节
   };
   ```

   `WasmStreamingDecoderTest` 中的 `OneSectionNotEnoughPayload1` 和 `OneSectionNotEnoughPayload2` 测试用例覆盖了这种错误。

3. **在流式加载过程中过早地假设模块已加载完成:**  虽然流式解码允许边下载边编译，但用户可能在 `Promise` resolve 之前就尝试访问模块的导出，导致错误。这虽然不是直接由解码器引起的错误，但流式加载的异步特性需要用户注意。

4. **服务器返回的 Content-Type 不正确:**  虽然与解码器本身无关，但如果服务器没有设置正确的 `Content-Type: application/wasm`，浏览器可能会拒绝进行流式编译。

总而言之，`v8/test/unittests/wasm/streaming-decoder-unittest.cc` 是一个至关重要的测试文件，它确保了 V8 引擎能够可靠地处理 WebAssembly 模块的流式加载，这对于 WebAssembly 的高效加载和执行至关重要。

### 提示词
```
这是目录为v8/test/unittests/wasm/streaming-decoder-unittest.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/unittests/wasm/streaming-decoder-unittest.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/unittests/test-utils.h"

#include "src/objects/objects-inl.h"

#include "src/wasm/module-decoder.h"
#include "src/wasm/streaming-decoder.h"

#include "src/objects/descriptor-array.h"
#include "src/objects/dictionary.h"
#include "test/common/wasm/wasm-macro-gen.h"

namespace v8 {
namespace internal {
namespace wasm {

struct MockStreamingResult {
  size_t num_sections = 0;
  size_t num_functions = 0;
  bool error;
  base::OwnedVector<const uint8_t> received_bytes;

  bool ok() const { return !error; }

  MockStreamingResult() = default;
};

class NoTracer {
 public:
  void Bytes(const uint8_t* start, uint32_t count) {}
  void Description(const char* desc) {}
};

class MockStreamingProcessor : public StreamingProcessor {
 public:
  explicit MockStreamingProcessor(MockStreamingResult* result)
      : result_(result) {}

  bool ProcessModuleHeader(base::Vector<const uint8_t> bytes) override {
    Decoder decoder(bytes.begin(), bytes.end());
    uint32_t magic_word = decoder.consume_u32("wasm magic", ITracer::NoTrace);
    if (decoder.failed() || magic_word != kWasmMagic) {
      result_->error = WasmError(0, "expected wasm magic");
      return false;
    }
    uint32_t magic_version =
        decoder.consume_u32("wasm version", ITracer::NoTrace);
    if (decoder.failed() || magic_version != kWasmVersion) {
      result_->error = WasmError(4, "expected wasm version");
      return false;
    }
    return true;
  }

  // Process all sections but the code section.
  bool ProcessSection(SectionCode section_code,
                      base::Vector<const uint8_t> bytes,
                      uint32_t offset) override {
    ++result_->num_sections;
    return true;
  }

  bool ProcessCodeSectionHeader(int num_functions, uint32_t offset,
                                std::shared_ptr<WireBytesStorage>,
                                int code_section_start,
                                int code_section_length) override {
    return true;
  }

  // Process a function body.
  bool ProcessFunctionBody(base::Vector<const uint8_t> bytes,
                           uint32_t offset) override {
    ++result_->num_functions;
    return true;
  }

  void OnFinishedChunk() override {}

  // Finish the processing of the stream.
  void OnFinishedStream(base::OwnedVector<const uint8_t> bytes,
                        bool after_error) override {
    result_->received_bytes = std::move(bytes);
    result_->error = after_error;
  }

  void OnAbort() override {}

  bool Deserialize(base::Vector<const uint8_t> module_bytes,
                   base::Vector<const uint8_t> wire_bytes) override {
    return false;
  }

 private:
  MockStreamingResult* const result_;
};

class WasmStreamingDecoderTest : public ::testing::Test {
 public:
  void ExpectVerifies(base::Vector<const uint8_t> data,
                      size_t expected_sections, size_t expected_functions) {
    for (int split = 0; split <= data.length(); ++split) {
      MockStreamingResult result;
      auto stream = StreamingDecoder::CreateAsyncStreamingDecoder(
          std::make_unique<MockStreamingProcessor>(&result));
      stream->OnBytesReceived(data.SubVector(0, split));
      stream->OnBytesReceived(data.SubVector(split, data.length()));
      stream->Finish();
      EXPECT_TRUE(result.ok());
      EXPECT_EQ(expected_sections, result.num_sections);
      EXPECT_EQ(expected_functions, result.num_functions);
      EXPECT_EQ(data, result.received_bytes.as_vector());
    }
  }

  void ExpectFailure(base::Vector<const uint8_t> data) {
    for (int split = 0; split <= data.length(); ++split) {
      MockStreamingResult result;
      auto stream = StreamingDecoder::CreateAsyncStreamingDecoder(
          std::make_unique<MockStreamingProcessor>(&result));
      stream->OnBytesReceived(data.SubVector(0, split));
      stream->OnBytesReceived(data.SubVector(split, data.length()));
      stream->Finish();
      EXPECT_FALSE(result.ok());
      EXPECT_TRUE(result.error);
    }
  }
};

TEST_F(WasmStreamingDecoderTest, EmptyStream) {
  MockStreamingResult result;
  auto stream = StreamingDecoder::CreateAsyncStreamingDecoder(
      std::make_unique<MockStreamingProcessor>(&result));
  stream->Finish();
  EXPECT_FALSE(result.ok());
}

TEST_F(WasmStreamingDecoderTest, IncompleteModuleHeader) {
  const uint8_t data[] = {U32_LE(kWasmMagic), U32_LE(kWasmVersion)};
  {
    MockStreamingResult result;
    auto stream = StreamingDecoder::CreateAsyncStreamingDecoder(
        std::make_unique<MockStreamingProcessor>(&result));
    stream->OnBytesReceived(base::VectorOf(data, 1));
    stream->Finish();
    EXPECT_FALSE(result.ok());
  }
  for (uint32_t length = 1; length < sizeof(data); ++length) {
    ExpectFailure(base::VectorOf(data, length));
  }
}

TEST_F(WasmStreamingDecoderTest, MagicAndVersion) {
  const uint8_t data[] = {U32_LE(kWasmMagic), U32_LE(kWasmVersion)};
  ExpectVerifies(base::ArrayVector(data), 0, 0);
}

TEST_F(WasmStreamingDecoderTest, BadMagic) {
  for (uint32_t x = 1; x; x <<= 1) {
    const uint8_t data[] = {U32_LE(kWasmMagic ^ x), U32_LE(kWasmVersion)};
    ExpectFailure(base::ArrayVector(data));
  }
}

TEST_F(WasmStreamingDecoderTest, BadVersion) {
  for (uint32_t x = 1; x; x <<= 1) {
    const uint8_t data[] = {U32_LE(kWasmMagic), U32_LE(kWasmVersion ^ x)};
    ExpectFailure(base::ArrayVector(data));
  }
}

TEST_F(WasmStreamingDecoderTest, OneSection) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      0x1,                   // Section ID
      0x6,                   // Section Length
      0x0,                   // Payload
      0x0,                   // 2
      0x0,                   // 3
      0x0,                   // 4
      0x0,                   // 5
      0x0                    // 6
  };
  ExpectVerifies(base::ArrayVector(data), 1, 0);
}

TEST_F(WasmStreamingDecoderTest, OneSection_b) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      0x1,                   // Section ID
      0x86,                  // Section Length = 6 (LEB)
      0x0,                   // --
      0x0,                   // Payload
      0x0,                   // 2
      0x0,                   // 3
      0x0,                   // 4
      0x0,                   // 5
      0x0                    // 6
  };
  ExpectVerifies(base::ArrayVector(data), 1, 0);
}

TEST_F(WasmStreamingDecoderTest, OneShortSection) {
  // Short section means that section length + payload is less than 5 bytes,
  // which is the maximum size of the length field.
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      0x1,                   // Section ID
      0x2,                   // Section Length
      0x0,                   // Payload
      0x0                    // 2
  };
  ExpectVerifies(base::ArrayVector(data), 1, 0);
}

TEST_F(WasmStreamingDecoderTest, OneShortSection_b) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      0x1,                   // Section ID
      0x82,                  // Section Length = 2 (LEB)
      0x80,                  // --
      0x0,                   // --
      0x0,                   // Payload
      0x0                    // 2
  };
  ExpectVerifies(base::ArrayVector(data), 1, 0);
}

TEST_F(WasmStreamingDecoderTest, OneEmptySection) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      0x1,                   // Section ID
      0x0                    // Section Length
  };
  ExpectVerifies(base::ArrayVector(data), 1, 0);
}

TEST_F(WasmStreamingDecoderTest, OneSectionNotEnoughPayload1) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      0x1,                   // Section ID
      0x6,                   // Section Length
      0x0,                   // Payload
      0x0,                   // 2
      0x0,                   // 3
      0x0,                   // 4
      0x0                    // 5
  };
  ExpectFailure(base::ArrayVector(data));
}

TEST_F(WasmStreamingDecoderTest, OneSectionNotEnoughPayload2) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      0x1,                   // Section ID
      0x6,                   // Section Length
      0x0                    // Payload
  };
  ExpectFailure(base::ArrayVector(data));
}

TEST_F(WasmStreamingDecoderTest, OneSectionInvalidLength) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      0x1,                   // Section ID
      0x80,                  // Section Length (invalid LEB)
      0x80,                  // --
      0x80,                  // --
      0x80,                  // --
      0x80,                  // --
  };
  ExpectFailure(base::ArrayVector(data));
}

TEST_F(WasmStreamingDecoderTest, TwoLongSections) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      0x1,                   // Section ID
      0x6,                   // Section Length
      0x0,                   // Payload
      0x0,                   // 2
      0x0,                   // 3
      0x0,                   // 4
      0x0,                   // 5
      0x0,                   // 6
      0x2,                   // Section ID
      0x7,                   // Section Length
      0x0,                   // Payload
      0x0,                   // 2
      0x0,                   // 3
      0x0,                   // 4
      0x0,                   // 5
      0x0,                   // 6
      0x0                    // 7
  };
  ExpectVerifies(base::ArrayVector(data), 2, 0);
}

TEST_F(WasmStreamingDecoderTest, TwoShortSections) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      0x1,                   // Section ID
      0x1,                   // Section Length
      0x0,                   // Payload
      0x2,                   // Section ID
      0x2,                   // Section Length
      0x0,                   // Payload
      0x0,                   // 2
  };
  ExpectVerifies(base::ArrayVector(data), 2, 0);
}

TEST_F(WasmStreamingDecoderTest, TwoSectionsShortLong) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      0x1,                   // Section ID
      0x1,                   // Section Length
      0x0,                   // Payload
      0x2,                   // Section ID
      0x7,                   // Section Length
      0x0,                   // Payload
      0x0,                   // 2
      0x0,                   // 3
      0x0,                   // 4
      0x0,                   // 5
      0x0,                   // 6
      0x0                    // 7
  };
  ExpectVerifies(base::ArrayVector(data), 2, 0);
}

TEST_F(WasmStreamingDecoderTest, TwoEmptySections) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      0x1,                   // Section ID
      0x0,                   // Section Length
      0x2,                   // Section ID
      0x0                    // Section Length
  };
  ExpectVerifies(base::ArrayVector(data), 2, 0);
}

TEST_F(WasmStreamingDecoderTest, OneFunction) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      kCodeSectionCode,      // Section ID
      0x8,                   // Section Length
      0x1,                   // Number of Functions
      0x6,                   // Function Length
      0x0,                   // Function
      0x0,                   // 2
      0x0,                   // 3
      0x0,                   // 4
      0x0,                   // 5
      0x0,                   // 6
  };
  ExpectVerifies(base::ArrayVector(data), 0, 1);
}

TEST_F(WasmStreamingDecoderTest, OneShortFunction) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      kCodeSectionCode,      // Section ID
      0x3,                   // Section Length
      0x1,                   // Number of Functions
      0x1,                   // Function Length
      0x0,                   // Function
  };
  ExpectVerifies(base::ArrayVector(data), 0, 1);
}

TEST_F(WasmStreamingDecoderTest, EmptyFunction) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      kCodeSectionCode,      // Section ID
      0x2,                   // Section Length
      0x1,                   // Number of Functions
      0x0,                   // Function Length  -- ERROR
  };
  ExpectFailure(base::ArrayVector(data));
}

TEST_F(WasmStreamingDecoderTest, TwoFunctions) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      kCodeSectionCode,      // Section ID
      0x10,                  // Section Length
      0x2,                   // Number of Functions
      0x6,                   // Function Length
      0x0,                   // Function
      0x0,                   // 2
      0x0,                   // 3
      0x0,                   // 4
      0x0,                   // 5
      0x0,                   // 6
      0x7,                   // Function Length
      0x0,                   // Function
      0x0,                   // 2
      0x0,                   // 3
      0x0,                   // 4
      0x0,                   // 5
      0x0,                   // 6
      0x0,                   // 7
  };
  ExpectVerifies(base::ArrayVector(data), 0, 2);
}

TEST_F(WasmStreamingDecoderTest, TwoFunctions_b) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      kCodeSectionCode,      // Section ID
      0xB,                   // Section Length
      0x2,                   // Number of Functions
      0x1,                   // Function Length
      0x0,                   // Function
      0x7,                   // Function Length
      0x0,                   // Function
      0x0,                   // 2
      0x0,                   // 3
      0x0,                   // 4
      0x0,                   // 5
      0x0,                   // 6
      0x0,                   // 7
  };
  ExpectVerifies(base::ArrayVector(data), 0, 2);
}

TEST_F(WasmStreamingDecoderTest, CodeSectionLengthZero) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      kCodeSectionCode,      // Section ID
      0x0,                   // Section Length
  };
  ExpectFailure(base::ArrayVector(data));
}

TEST_F(WasmStreamingDecoderTest, CodeSectionLengthTooHigh) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      kCodeSectionCode,      // Section ID
      0xD,                   // Section Length
      0x2,                   // Number of Functions
      0x7,                   // Function Length
      0x0,                   // Function
      0x0,                   // 2
      0x0,                   // 3
      0x0,                   // 4
      0x0,                   // 5
      0x0,                   // 6
      0x0,                   // 7
      0x1,                   // Function Length
      0x0,                   // Function
  };
  ExpectFailure(base::ArrayVector(data));
}

TEST_F(WasmStreamingDecoderTest, CodeSectionLengthTooHighZeroFunctions) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      kCodeSectionCode,      // Section ID
      0xD,                   // Section Length
      0x0,                   // Number of Functions
  };
  ExpectFailure(base::ArrayVector(data));
}

TEST_F(WasmStreamingDecoderTest, CodeSectionLengthTooLow) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      kCodeSectionCode,      // Section ID
      0x9,                   // Section Length
      0x2,                   // Number of Functions  <0>
      0x7,                   // Function Length      <1>
      0x0,                   // Function             <2>
      0x0,                   // 2                    <3>
      0x0,                   // 3                    <3>
      0x0,                   // 4                    <4>
      0x0,                   // 5                    <5>
      0x0,                   // 6                    <6>
      0x0,                   // 7                    <7>
      0x1,                   // Function Length      <8> -- ERROR
      0x0,                   // Function
  };
  ExpectFailure(base::ArrayVector(data));
}

TEST_F(WasmStreamingDecoderTest, CodeSectionLengthTooLowEndsInNumFunctions) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      kCodeSectionCode,      // Section ID
      0x1,                   // Section Length
      0x82,                  // Number of Functions  <0>
      0x80,                  // --                   <1> -- ERROR
      0x00,                  // --
      0x7,                   // Function Length
      0x0,                   // Function
      0x0,                   // 2
      0x0,                   // 3
      0x0,                   // 4
      0x0,                   // 5
      0x0,                   // 6
      0x0,                   // 7
      0x1,                   // Function Length
      0x0,                   // Function
  };
  ExpectFailure(base::ArrayVector(data));
}

TEST_F(WasmStreamingDecoderTest, CodeSectionLengthTooLowEndsInFunctionLength) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      kCodeSectionCode,      // Section ID
      0x5,                   // Section Length
      0x82,                  // Number of Functions  <0>
      0x80,                  // --                   <1>
      0x00,                  // --                   <2>
      0x87,                  // Function Length      <3>
      0x80,                  // --                   <4>
      0x00,                  // --                   <5> -- ERROR
      0x0,                   // Function
      0x0,                   // 2
      0x0,                   // 3
      0x0,                   // 4
      0x0,                   // 5
      0x0,                   // 6
      0x0,                   // 7
      0x1,                   // Function Length
      0x0,                   // Function
  };
  ExpectFailure(base::ArrayVector(data));
}

TEST_F(WasmStreamingDecoderTest, NumberOfFunctionsTooHigh) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      kCodeSectionCode,      // Section ID
      0xB,                   // Section Length
      0x4,                   // Number of Functions
      0x7,                   // Function Length
      0x0,                   // Function
      0x0,                   // 2
      0x0,                   // 3
      0x0,                   // 4
      0x0,                   // 5
      0x0,                   // 6
      0x0,                   // 7
      0x1,                   // Function Length
      0x0,                   // Function
  };
  ExpectFailure(base::ArrayVector(data));
}

TEST_F(WasmStreamingDecoderTest, NumberOfFunctionsTooLow) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      kCodeSectionCode,      // Section ID
      0x8,                   // Section Length
      0x2,                   // Number of Functions
      0x1,                   // Function Length
      0x0,                   // Function
      0x2,                   // Function Length
      0x0,                   // Function byte#0
      0x0,                   // Function byte#1   -- ERROR
      0x1,                   // Function Length
      0x0                    // Function
  };
  ExpectFailure(base::ArrayVector(data));
}

TEST_F(WasmStreamingDecoderTest, TwoCodeSections) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      kCodeSectionCode,      // Section ID
      0x3,                   // Section Length
      0x1,                   // Number of Functions
      0x1,                   // Function Length
      0x0,                   // Function
      kCodeSectionCode,      // Section ID      -- ERROR
      0x3,                   // Section Length
      0x1,                   // Number of Functions
      0x1,                   // Function Length
      0x0,                   // Function
  };
  ExpectFailure(base::ArrayVector(data));
}

TEST_F(WasmStreamingDecoderTest, UnknownSection) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      kCodeSectionCode,      // Section ID
      0x3,                   // Section Length
      0x1,                   // Number of Functions
      0x1,                   // Function Length
      0x0,                   // Function
      kUnknownSectionCode,   // Section ID
      0x3,                   // Section Length
      0x1,                   // Name Length
      0x1,                   // Name
      0x0,                   // Content
  };
  ExpectVerifies(base::ArrayVector(data), 1, 1);
}

TEST_F(WasmStreamingDecoderTest, UnknownSectionSandwich) {
  const uint8_t data[] = {
      U32_LE(kWasmMagic),    // --
      U32_LE(kWasmVersion),  // --
      kCodeSectionCode,      // Section ID
      0x3,                   // Section Length
      0x1,                   // Number of Functions
      0x1,                   // Function Length
      0x0,                   // Function
      kUnknownSectionCode,   // Section ID
      0x3,                   // Section Length
      0x1,                   // Name Length
      0x1,                   // Name
      0x0,                   // Content
      kCodeSectionCode,      // Section ID     -- ERROR
      0x3,                   // Section Length
      0x1,                   // Number of Functions
      0x1,                   // Function Length
      0x0,                   // Function
  };
  ExpectFailure(base::ArrayVector(data));
}

TEST_F(WasmStreamingDecoderTest, InvalidSectionCode) {
  uint8_t kInvalidSectionCode = 61;
  const uint8_t data[] = {WASM_MODULE_HEADER, SECTION(Invalid)};
  ExpectFailure(base::ArrayVector(data));
}

}  // namespace wasm
}  // namespace internal
}  // namespace v8
```