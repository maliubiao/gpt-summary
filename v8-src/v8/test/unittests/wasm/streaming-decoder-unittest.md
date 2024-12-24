Response: The user wants to understand the functionality of the C++ source code file `v8/test/unittests/wasm/streaming-decoder-unittest.cc`. This file's name strongly suggests it contains unit tests for a "streaming decoder" related to WebAssembly (Wasm).

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Subject:** The filename clearly points to unit tests for `StreamingDecoder`.

2. **Look for Test Fixtures:** The code defines a class `WasmStreamingDecoderTest` which inherits from `::testing::Test`. This is a strong indicator of a test fixture, containing multiple individual test cases.

3. **Examine Helper Structures and Classes:**
    * `MockStreamingResult`:  This structure appears to be used to collect data and status from the decoder during testing. Key fields like `num_sections`, `num_functions`, `error`, and `received_bytes` hint at what aspects of the decoder are being verified.
    * `NoTracer`:  This seems to be a no-op implementation for tracing, likely used to avoid logging overhead in tests.
    * `MockStreamingProcessor`: This class inherits from `StreamingProcessor`. It overrides several methods like `ProcessModuleHeader`, `ProcessSection`, `ProcessCodeSectionHeader`, `ProcessFunctionBody`, and `OnFinishedStream`. This suggests it's a mock implementation of the interface that the `StreamingDecoder` interacts with. The mock processor is designed to capture the actions of the decoder and check for expected behavior (like checking the magic number and version, counting sections and functions).

4. **Analyze the Test Methods:** The `TEST_F` macros define individual test cases within the `WasmStreamingDecoderTest` fixture. By examining the names of these tests, we can get a good sense of what aspects of the `StreamingDecoder` are being tested. Examples:
    * `EmptyStream`: Tests the decoder's behavior with no input.
    * `IncompleteModuleHeader`: Checks how the decoder handles an incomplete Wasm header.
    * `MagicAndVersion`: Verifies the decoder correctly processes the magic number and version.
    * `BadMagic`, `BadVersion`: Tests the decoder's error handling for incorrect magic numbers and versions.
    * Tests involving "Section": These tests focus on how the decoder handles different valid and invalid section structures (length, payload, multiple sections, empty sections).
    * Tests involving "Function": These tests specifically examine the decoder's behavior when processing the code section and function bodies (number of functions, function lengths, empty functions, invalid lengths).
    * `TwoCodeSections`, `UnknownSection`, `UnknownSectionSandwich`: These test more complex scenarios involving multiple code sections or unknown sections.
    * `InvalidSectionCode`: Checks error handling for invalid section codes.

5. **Identify Key Test Helper Functions:**
    * `ExpectVerifies`: This function takes Wasm bytecode as input, splits it at various points to simulate streaming, runs the decoder, and then asserts that the decoding was successful (`result.ok()`) and that the expected number of sections and functions were processed. It also verifies that the received bytes match the input.
    * `ExpectFailure`: Similar to `ExpectVerifies`, but it asserts that the decoding failed (`!result.ok()`).

6. **Synthesize the Functionality:** Based on the above analysis, we can infer the following:

    * The file contains unit tests for a `StreamingDecoder` in the V8 JavaScript engine's WebAssembly implementation.
    * The `StreamingDecoder` processes Wasm bytecode incrementally (as a stream).
    * The tests verify the decoder's ability to correctly parse the Wasm module header (magic number and version).
    * The tests check the decoder's handling of various valid and invalid Wasm section structures, including the code section and function bodies.
    * The tests also cover error handling scenarios, such as incomplete input, incorrect magic numbers/versions, invalid section lengths, and invalid section codes.
    * The tests use a mock processor (`MockStreamingProcessor`) to simulate the interaction between the decoder and its consumer. This allows for verifying the decoder's actions without needing a full Wasm compilation pipeline.
    * The tests use helper functions (`ExpectVerifies`, `ExpectFailure`) to simplify the process of setting up test cases and asserting expected outcomes.

7. **Refine the Summary:**  Finally, organize the identified functionalities into a clear and concise summary, using terms relevant to WebAssembly and streaming decoding. Emphasize the key aspects being tested.
这个C++源代码文件 `streaming-decoder-unittest.cc` 是 V8 JavaScript 引擎中 WebAssembly (Wasm) 模块的 **流式解码器 (Streaming Decoder)** 的单元测试文件。

它的主要功能是：

**测试 `StreamingDecoder` 类在各种场景下的行为，包括成功解码和失败解码。**

具体来说，它测试了以下方面：

1. **基本的流式解码流程:**  测试在逐步接收 WebAssembly 模块字节流时，解码器是否能够正确地解析模块头（魔数和版本号）、不同的 Section (例如，代码段) 以及函数体。

2. **正确的模块头解析:**  测试解码器是否能够正确识别和验证 WebAssembly 模块的魔数 (`kWasmMagic`) 和版本号 (`kWasmVersion`)。也测试了当魔数或版本号错误或不完整时的错误处理。

3. **Section 处理:**
    * **正常 Section:** 测试解码器是否能够正确处理各种类型的 Section，包括不同长度的 Section 和空 Section。
    * **代码 Section:**  特别关注代码 Section 的处理，包括函数数量、函数体长度以及函数体内容的解析。
    * **未知 Section:** 测试解码器是否能够处理未知的 Section。
    * **错误的 Section:** 测试解码器在遇到错误的 Section 长度、不完整的 Section 内容或无效的 Section ID 时的错误处理。

4. **函数体处理:**  测试解码器是否能够正确解析代码 Section 中的函数体，包括不同长度的函数体和空函数体 (虽然这被认为是错误情况)。

5. **错误处理:**  大量的测试用例专注于测试解码器在遇到各种错误情况时的处理，例如：
    * 不完整的模块头或 Section 数据。
    * 错误的魔数或版本号。
    * 无效的 Section 长度或内容。
    * 代码 Section 中函数数量或函数体长度不匹配。
    * 重复的代码 Section。

6. **分片接收数据 (Streaming):**  通过 `ExpectVerifies` 和 `ExpectFailure` 函数中的循环，模拟了分片接收 WebAssembly 模块字节流的过程，测试解码器在不同分片方式下的表现。

7. **使用 Mock 对象:**  使用了 `MockStreamingProcessor` 类作为 `StreamingDecoder` 的处理器接口的模拟实现。这个 Mock 对象用于验证解码器在不同阶段的回调行为，例如：
    * `ProcessModuleHeader`: 处理模块头。
    * `ProcessSection`: 处理非代码 Section。
    * `ProcessCodeSectionHeader`: 处理代码 Section 的头部信息。
    * `ProcessFunctionBody`: 处理函数体。
    * `OnFinishedStream`: 完成数据流处理。

**总而言之，`streaming-decoder-unittest.cc` 文件通过大量的单元测试用例，全面地验证了 V8 引擎中 WebAssembly 流式解码器的正确性和健壮性，确保它能够可靠地处理各种有效和无效的 WebAssembly 模块字节流。**

Prompt: ```这是目录为v8/test/unittests/wasm/streaming-decoder-unittest.cc的一个c++源代码文件， 请归纳一下它的功能

"""
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

"""
```