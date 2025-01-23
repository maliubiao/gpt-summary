Response:
Let's break down the thought process for analyzing the C++ test file.

1. **Identify the Core Purpose:** The file name `hpack_block_decoder_test.cc` immediately suggests it's a test file for something related to HPACK (HTTP/2 header compression) and block decoding. The `_test.cc` suffix is a common convention for test files in C++ projects.

2. **Scan the Includes:**  The included headers provide crucial context:
    * `quiche/http2/hpack/decoder/hpack_block_decoder.h`: This is the header file for the class being tested, `HpackBlockDecoder`.
    * Standard C++ headers (`<cstdint>`, `<sstream>`, `<string>`).
    * `absl/strings/string_view.h`:  Indicates string manipulation is involved.
    * `quiche/http2/decoder/decode_buffer.h`: Suggests the decoder processes some kind of buffer.
    * `quiche/http2/hpack/http2_hpack_constants.h`:  Likely contains constants related to HPACK.
    * Test-related headers (`quiche/http2/test_tools/...`, `quiche/common/platform/api/...`):  Confirms this is a test file and reveals the testing framework used (likely Google Test, based on `TEST_F`).

3. **Examine the Test Fixture:** The `HpackBlockDecoderTest` class inherits from `RandomDecoderTest`. This tells us:
    * The tests likely involve randomized inputs (due to the `RandomDecoderTest` base class).
    * There's a `collector_` of type `HpackBlockCollector` to capture the decoded output.
    * There's a `listener_` of type `HpackEntryDecoderVLoggingListener`, probably used for logging or observing the decoding process.
    * The object under test is `decoder_` of type `HpackBlockDecoder`.
    * Helper methods like `StartDecoding`, `ResumeDecoding`, and `DecodeAndValidateSeveralWays` are defined, suggesting a pattern for how the tests are structured.

4. **Analyze the Helper Methods:**
    * `StartDecoding` and `ResumeDecoding`: These methods seem to control the decoding process, taking a `DecodeBuffer` as input. The presence of `ResumeDecoding` implies that the decoding process might be incremental or can be paused and resumed.
    * `DecodeAndValidateSeveralWays`:  This is a key method. The name strongly suggests it runs the decoding process multiple times (likely with variations in input buffering or chunking) and then uses a `Validator` to check the results.
    * `DecodeHpackExampleAndValidateSeveralWays`: This method takes a string (likely representing a hex-encoded HPACK example) and decodes it. This points to testing against known, well-defined HPACK sequences.
    * `Rand8` and `Rand8String`:  These confirm the use of random data in the tests.

5. **Study the Individual Test Cases:**  The `TEST_F` macros define individual test cases. The names often correlate to sections of the HPACK specification (e.g., `SpecExample_C_2_1`). Inside each test:
    * **Look for the `do_check` lambda:** This lambda function typically contains the assertions that verify the correctness of the decoding. It usually uses the `collector_` to check the decoded headers.
    * **Examine the `hpack_example` string:**  This contains the hex-encoded HPACK data being tested.
    * **Understand the expected outcome:** The comments within the `hpack_example` strings and the assertions in `do_check` reveal the expected decoded header(s).

6. **Identify Key Testing Scenarios:**  The tests cover various aspects of HPACK decoding:
    * **Literal Headers (Indexed and Non-Indexed):** Tests like `SpecExample_C_2_1`, `SpecExample_C_2_2`, and `SpecExample_C_2_3` focus on decoding different types of literal headers.
    * **Indexed Headers:** `SpecExample_C_2_4` and `SpecExample_C_3_1` test decoding headers that are already present in the dynamic or static table.
    * **Dynamic Table Size Updates:**  The `Computed` test explicitly includes dynamic table size updates.
    * **Huffman Encoding:** The `Computed` test iterates through both Huffman and non-Huffman encoded values.
    * **Randomized Testing:** The `Computed` test heavily relies on random data generation and shuffling, ensuring robustness against various input combinations.

7. **Look for Javascript Connections (and lack thereof):**  While analyzing the code, specifically look for any interactions with web APIs, DOM manipulation, or asynchronous operations commonly found in JavaScript. In this case, the code is purely focused on the lower-level details of HPACK decoding, with no direct ties to JavaScript. The connection would be at a higher level where JavaScript might *use* the output of this decoder.

8. **Infer User Errors and Debugging:** Consider how a developer might misuse the decoder or encounter issues. The focus on buffer management (`DecodeBuffer`), the possibility of incremental decoding, and the handling of potentially invalid (but well-formed) HPACK data are all areas where errors could occur. The test setup itself (using a collector and validation) provides a debugging approach.

9. **Synthesize the Findings:** Finally, organize the observations into a clear and concise summary covering the file's functionality, its relation to JavaScript, logical reasoning (input/output), potential user errors, and debugging steps.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this test file directly tests network interactions.
* **Correction:** The includes and the class names suggest a focus on the HPACK *decoding* logic, not network I/O. Network interactions would be tested in other parts of the Chromium project.
* **Initial thought:** The randomized tests are just for fuzzing.
* **Refinement:** While they have elements of fuzzing, they are structured to cover various valid and some edge-case HPACK constructions, ensuring the decoder handles different encoding scenarios correctly. The `HpackBlockCollector` and the validation logic show a clear expectation of the decoded output.
* **Initial thought:** The comments in the `hpack_example` strings are just for human readability.
* **Refinement:** They actually provide valuable information about the expected decoding steps and the meaning of the byte sequence, aiding in understanding the test cases.

By following these steps and constantly refining understanding based on the code's structure and content, a comprehensive analysis of the test file can be achieved.
这个文件 `net/third_party/quiche/src/quiche/http2/hpack/decoder/hpack_block_decoder_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，专门用于测试 **HPACK 块解码器 (`HpackBlockDecoder`)** 的功能。HPACK (HTTP/2 Header Compression) 是一种压缩 HTTP 头部的方法，旨在减少头部的大小，从而提高网络传输效率。

**文件功能概览:**

该测试文件主要负责验证 `HpackBlockDecoder` 类是否能够正确地将 HPACK 编码的头部块解码回原始的头部键值对。它通过以下方式进行测试：

1. **提供多种 HPACK 编码的输入:** 包括来自 HTTP/2 规范的示例，以及通过程序生成的随机或特定结构的 HPACK 块。
2. **使用 `HpackBlockDecoder` 进行解码:**  将这些编码的输入提供给 `HpackBlockDecoder` 对象进行解码。
3. **验证解码结果:** 使用 `HpackBlockCollector` 收集解码后的头部信息，并与预期的结果进行比较。
4. **覆盖不同的 HPACK 编码方式:** 测试包括索引头部、字面头部（带索引和不带索引）、动态表大小更新等各种 HPACK 特性。
5. **进行随机化测试:**  利用 `RandomDecoderTest` 基类，生成随机的 HPACK 块并进行解码测试，增加测试的覆盖率和发现潜在问题的能力。

**与 Javascript 的关系 (无直接关系):**

这个 C++ 测试文件 **没有直接的 Javascript 功能**。它纯粹是 C++ 代码，用于测试网络栈的底层 HPACK 解码逻辑。

但是，HPACK 的解码功能最终会在浏览器或 Node.js 等环境中被 Javascript 使用。当浏览器接收到来自服务器的 HTTP/2 响应时，其网络栈会使用类似 `HpackBlockDecoder` 的组件来解码压缩的头部。解码后的头部信息会被传递给浏览器的渲染引擎或 Javascript 运行时环境，供 Javascript 代码访问和处理。

**举例说明:**

假设一个使用了 HTTP/2 的网站，服务器发送了一个压缩的响应头部块，其中包含以下 HPACK 编码的数据 (这是一个简化示例，实际编码会更复杂)：

```
82  // 代表索引头部，索引值为 2，对应 ":method: GET"
41 0f 7777772e6578616d706c652e636f6d  // 代表字面头部，索引名称 ":authority" (索引 1)，值为 "www.example.com"
```

1. **网络接收:** 浏览器的网络栈接收到这段数据。
2. **HPACK 解码:** `HpackBlockDecoder` (或类似的组件) 会被用来解码这段数据。
3. **解码结果:** 解码器会输出以下头部键值对：
   ```
   :method: GET
   :authority: www.example.com
   ```
4. **传递给 Javascript:** 这些解码后的头部信息会被传递给 Javascript 运行时环境。
5. **Javascript 使用:** Javascript 代码可以通过 `fetch` API 或其他网络请求相关的 API 访问这些头部信息，例如：
   ```javascript
   fetch('https://www.example.com')
     .then(response => {
       console.log(response.headers.get(':method')); // 输出 "GET"
       console.log(response.headers.get(':authority')); // 输出 "www.example.com"
     });
   ```

**逻辑推理 (假设输入与输出):**

**假设输入:** 一个包含单个字面头部的 HPACK 编码块：

```
40 0a 637573746f6d2d6b6579 0d 637573746f6d2d686561646572
```

* `40`:  表示带索引的字面头部 (Literal indexed)。
* `0a`:  名称长度为 10。
* `637573746f6d2d6b6579`:  名称 "custom-key" 的 ASCII 编码。
* `0d`:  值长度为 13。
* `637573746f6d2d686561646572`: 值 "custom-header" 的 ASCII 编码。

**预期输出:** 解码后的头部信息为：

```
custom-key: custom-header
```

**测试代码中的体现:** 可以看到 `SpecExample_C_2_1` 测试用例正是针对这种情况，它验证了 `HpackBlockDecoder` 能否正确解码并生成预期的头部。

**用户或编程常见的使用错误:**

虽然用户不会直接使用 `HpackBlockDecoder`，但在网络编程或 HTTP/2 协议实现中，可能会遇到与 HPACK 解码相关的错误：

1. **提供不完整的 HPACK 编码块:** 如果只提供了部分 HPACK 数据，解码器可能无法正确解析，导致错误或崩溃。
   * **例子:** 只提供了 `40 0a 637573746f6d2d6b6579`，缺少了值部分。
   * **测试代码中的预防:** 测试用例会提供完整的、有效的 HPACK 编码块。

2. **HPACK 动态表大小不匹配:**  HPACK 使用动态表来存储最近使用的头部，如果解码器和编码器的动态表大小配置不一致，可能导致解码错误。
   * **例子:** 编码器使用了较大的动态表，解码器使用了较小的动态表，导致索引错误。
   * **测试代码中的覆盖:**  测试用例包括了动态表大小更新的场景，以验证解码器对这些更新的处理。

3. **处理 Huffman 编码错误:** 如果 HPACK 头部值使用了 Huffman 编码，解码器需要正确处理。错误的 Huffman 编码会导致解码失败。
   * **例子:**  Huffman 编码的数据被损坏。
   * **测试代码中的覆盖:**  `Computed` 测试用例中会测试带有和不带有 Huffman 编码的头部。

**用户操作是如何一步步的到达这里，作为调试线索:**

作为一个最终用户，你不会直接操作到 `HpackBlockDecoder`。你的操作会触发浏览器的网络请求，而网络栈内部会处理 HPACK 解码。以下是一个可能的流程：

1. **用户在浏览器地址栏输入 URL 并回车，或者点击一个链接。**
2. **浏览器发起 HTTP/2 连接到服务器。**
3. **服务器发送 HTTP/2 响应，其中头部可能使用 HPACK 压缩。**
4. **浏览器网络栈接收到服务器的响应数据。**
5. **网络栈中的 HPACK 解码器 (`HpackBlockDecoder` 或类似的组件) 被调用，负责解压缩响应头部。**
6. **如果解码过程中出现问题，可能会触发错误处理逻辑，最终可能导致页面加载失败或者出现渲染问题。**

**作为调试线索:**

当需要调试与 HPACK 解码相关的问题时，以下线索可能有用：

* **抓包分析:** 使用 Wireshark 等工具抓取网络包，查看服务器发送的原始 HTTP/2 帧，特别是 HEADERS 帧，可以分析 HPACK 编码的数据是否正确。
* **浏览器开发者工具:** 现代浏览器通常提供查看请求和响应头部的功能，虽然显示的是解码后的结果，但可以帮助判断是否存在头部信息丢失或错误的情况。
* **QUIC/HTTP/2 日志:** Chromium 网络栈通常会有详细的日志输出，可以查看与 HPACK 解码相关的日志信息，例如解码器的状态、解码出的头部等。
* **断点调试:** 对于开发人员，可以在 `HpackBlockDecoder` 的代码中设置断点，逐步跟踪解码过程，分析解码状态和数据流。

总而言之，`hpack_block_decoder_test.cc` 是 Chromium 中一个重要的测试文件，它确保了 HPACK 解码器的正确性和可靠性，这对于高效的 HTTP/2 通信至关重要。虽然用户不会直接与之交互，但其功能直接影响着网页加载速度和性能。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/hpack/decoder/hpack_block_decoder_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "quiche/http2/hpack/decoder/hpack_block_decoder.h"

// Tests of HpackBlockDecoder.

#include <cstdint>
#include <sstream>
#include <string>

#include "absl/strings/string_view.h"
#include "quiche/http2/decoder/decode_buffer.h"
#include "quiche/http2/hpack/http2_hpack_constants.h"
#include "quiche/http2/test_tools/hpack_block_builder.h"
#include "quiche/http2/test_tools/hpack_block_collector.h"
#include "quiche/http2/test_tools/hpack_example.h"
#include "quiche/http2/test_tools/http2_random.h"
#include "quiche/http2/test_tools/random_decoder_test_base.h"
#include "quiche/common/platform/api/quiche_expect_bug.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace http2 {
namespace test {
namespace {

class HpackBlockDecoderTest : public RandomDecoderTest {
 protected:
  HpackBlockDecoderTest() : listener_(&collector_), decoder_(&listener_) {
    stop_decode_on_done_ = false;
    decoder_.Reset();
    // Make sure logging doesn't crash. Not examining the result.
    std::ostringstream strm;
    strm << decoder_;
  }

  DecodeStatus StartDecoding(DecodeBuffer* db) override {
    collector_.Clear();
    decoder_.Reset();
    return ResumeDecoding(db);
  }

  DecodeStatus ResumeDecoding(DecodeBuffer* db) override {
    DecodeStatus status = decoder_.Decode(db);

    // Make sure logging doesn't crash. Not examining the result.
    std::ostringstream strm;
    strm << decoder_;

    return status;
  }

  AssertionResult DecodeAndValidateSeveralWays(DecodeBuffer* db,
                                               const Validator& validator) {
    bool return_non_zero_on_first = false;
    return RandomDecoderTest::DecodeAndValidateSeveralWays(
        db, return_non_zero_on_first, validator);
  }

  AssertionResult DecodeAndValidateSeveralWays(const HpackBlockBuilder& hbb,
                                               const Validator& validator) {
    DecodeBuffer db(hbb.buffer());
    return DecodeAndValidateSeveralWays(&db, validator);
  }

  AssertionResult DecodeHpackExampleAndValidateSeveralWays(
      absl::string_view hpack_example, Validator validator) {
    std::string input = HpackExampleToStringOrDie(hpack_example);
    DecodeBuffer db(input);
    return DecodeAndValidateSeveralWays(&db, validator);
  }

  uint8_t Rand8() { return Random().Rand8(); }

  std::string Rand8String() { return Random().RandString(Rand8()); }

  HpackBlockCollector collector_;
  HpackEntryDecoderVLoggingListener listener_;
  HpackBlockDecoder decoder_;
};

// http://httpwg.org/specs/rfc7541.html#rfc.section.C.2.1
TEST_F(HpackBlockDecoderTest, SpecExample_C_2_1) {
  auto do_check = [this]() {
    return collector_.ValidateSoleLiteralNameValueHeader(
        HpackEntryType::kIndexedLiteralHeader, false, "custom-key", false,
        "custom-header");
  };
  const char hpack_example[] = R"(
      40                                      | == Literal indexed ==
      0a                                      |   Literal name (len = 10)
      6375 7374 6f6d 2d6b 6579                | custom-key
      0d                                      |   Literal value (len = 13)
      6375 7374 6f6d 2d68 6561 6465 72        | custom-header
                                              | -> custom-key:
                                              |   custom-header
      )";
  EXPECT_TRUE(DecodeHpackExampleAndValidateSeveralWays(
      hpack_example, ValidateDoneAndEmpty(do_check)));
  EXPECT_TRUE(do_check());
}

// http://httpwg.org/specs/rfc7541.html#rfc.section.C.2.2
TEST_F(HpackBlockDecoderTest, SpecExample_C_2_2) {
  auto do_check = [this]() {
    return collector_.ValidateSoleLiteralValueHeader(
        HpackEntryType::kUnindexedLiteralHeader, 4, false, "/sample/path");
  };
  const char hpack_example[] = R"(
      04                                      | == Literal not indexed ==
                                              |   Indexed name (idx = 4)
                                              |     :path
      0c                                      |   Literal value (len = 12)
      2f73 616d 706c 652f 7061 7468           | /sample/path
                                              | -> :path: /sample/path
      )";
  EXPECT_TRUE(DecodeHpackExampleAndValidateSeveralWays(
      hpack_example, ValidateDoneAndEmpty(do_check)));
  EXPECT_TRUE(do_check());
}

// http://httpwg.org/specs/rfc7541.html#rfc.section.C.2.3
TEST_F(HpackBlockDecoderTest, SpecExample_C_2_3) {
  auto do_check = [this]() {
    return collector_.ValidateSoleLiteralNameValueHeader(
        HpackEntryType::kNeverIndexedLiteralHeader, false, "password", false,
        "secret");
  };
  const char hpack_example[] = R"(
      10                                      | == Literal never indexed ==
      08                                      |   Literal name (len = 8)
      7061 7373 776f 7264                     | password
      06                                      |   Literal value (len = 6)
      7365 6372 6574                          | secret
                                              | -> password: secret
      )";
  EXPECT_TRUE(DecodeHpackExampleAndValidateSeveralWays(
      hpack_example, ValidateDoneAndEmpty(do_check)));
  EXPECT_TRUE(do_check());
}

// http://httpwg.org/specs/rfc7541.html#rfc.section.C.2.4
TEST_F(HpackBlockDecoderTest, SpecExample_C_2_4) {
  auto do_check = [this]() { return collector_.ValidateSoleIndexedHeader(2); };
  const char hpack_example[] = R"(
      82                                      | == Indexed - Add ==
                                              |   idx = 2
                                              | -> :method: GET
      )";
  EXPECT_TRUE(DecodeHpackExampleAndValidateSeveralWays(
      hpack_example, ValidateDoneAndEmpty(do_check)));
  EXPECT_TRUE(do_check());
}
// http://httpwg.org/specs/rfc7541.html#rfc.section.C.3.1
TEST_F(HpackBlockDecoderTest, SpecExample_C_3_1) {
  std::string example = R"(
      82                                      | == Indexed - Add ==
                                              |   idx = 2
                                              | -> :method: GET
      86                                      | == Indexed - Add ==
                                              |   idx = 6
                                              | -> :scheme: http
      84                                      | == Indexed - Add ==
                                              |   idx = 4
                                              | -> :path: /
      41                                      | == Literal indexed ==
                                              |   Indexed name (idx = 1)
                                              |     :authority
      0f                                      |   Literal value (len = 15)
      7777 772e 6578 616d 706c 652e 636f 6d   | www.example.com
                                              | -> :authority:
                                              |   www.example.com
      )";
  HpackBlockCollector expected;
  expected.ExpectIndexedHeader(2);
  expected.ExpectIndexedHeader(6);
  expected.ExpectIndexedHeader(4);
  expected.ExpectNameIndexAndLiteralValue(HpackEntryType::kIndexedLiteralHeader,
                                          1, false, "www.example.com");
  EXPECT_TRUE(DecodeHpackExampleAndValidateSeveralWays(
      example,
      ValidateDoneAndEmpty([&] { return collector_.VerifyEq(expected); })));
  EXPECT_TRUE(collector_.VerifyEq(expected));
}

// http://httpwg.org/specs/rfc7541.html#rfc.section.C.5.1
TEST_F(HpackBlockDecoderTest, SpecExample_C_5_1) {
  std::string example = R"(
      48                                      | == Literal indexed ==
                                              |   Indexed name (idx = 8)
                                              |     :status
      03                                      |   Literal value (len = 3)
      3330 32                                 | 302
                                              | -> :status: 302
      58                                      | == Literal indexed ==
                                              |   Indexed name (idx = 24)
                                              |     cache-control
      07                                      |   Literal value (len = 7)
      7072 6976 6174 65                       | private
                                              | -> cache-control: private
      61                                      | == Literal indexed ==
                                              |   Indexed name (idx = 33)
                                              |     date
      1d                                      |   Literal value (len = 29)
      4d6f 6e2c 2032 3120 4f63 7420 3230 3133 | Mon, 21 Oct 2013
      2032 303a 3133 3a32 3120 474d 54        |  20:13:21 GMT
                                              | -> date: Mon, 21 Oct 2013
                                              |   20:13:21 GMT
      6e                                      | == Literal indexed ==
                                              |   Indexed name (idx = 46)
                                              |     location
      17                                      |   Literal value (len = 23)
      6874 7470 733a 2f2f 7777 772e 6578 616d | https://www.exam
      706c 652e 636f 6d                       | ple.com
                                              | -> location:
                                              |   https://www.example.com
      )";
  HpackBlockCollector expected;
  expected.ExpectNameIndexAndLiteralValue(HpackEntryType::kIndexedLiteralHeader,
                                          8, false, "302");
  expected.ExpectNameIndexAndLiteralValue(HpackEntryType::kIndexedLiteralHeader,
                                          24, false, "private");
  expected.ExpectNameIndexAndLiteralValue(HpackEntryType::kIndexedLiteralHeader,
                                          33, false,
                                          "Mon, 21 Oct 2013 20:13:21 GMT");
  expected.ExpectNameIndexAndLiteralValue(HpackEntryType::kIndexedLiteralHeader,
                                          46, false, "https://www.example.com");
  EXPECT_TRUE(DecodeHpackExampleAndValidateSeveralWays(
      example,
      ValidateDoneAndEmpty([&] { return collector_.VerifyEq(expected); })));
  EXPECT_TRUE(collector_.VerifyEq(expected));
}

// Generate a bunch of HPACK block entries to expect, use those expectations
// to generate an HPACK block, then decode it and confirm it matches those
// expectations. Some of these are invalid (such as Indexed, with index=0),
// but well-formed, and the decoder doesn't check for validity, just
// well-formedness. That includes the validity of the strings not being checked,
// such as lower-case ascii for the names, and valid Huffman encodings.
TEST_F(HpackBlockDecoderTest, Computed) {
  HpackBlockCollector expected;
  expected.ExpectIndexedHeader(0);
  expected.ExpectIndexedHeader(1);
  expected.ExpectIndexedHeader(126);
  expected.ExpectIndexedHeader(127);
  expected.ExpectIndexedHeader(128);
  expected.ExpectDynamicTableSizeUpdate(0);
  expected.ExpectDynamicTableSizeUpdate(1);
  expected.ExpectDynamicTableSizeUpdate(14);
  expected.ExpectDynamicTableSizeUpdate(15);
  expected.ExpectDynamicTableSizeUpdate(30);
  expected.ExpectDynamicTableSizeUpdate(31);
  expected.ExpectDynamicTableSizeUpdate(4095);
  expected.ExpectDynamicTableSizeUpdate(4096);
  expected.ExpectDynamicTableSizeUpdate(8192);
  for (auto type : {HpackEntryType::kIndexedLiteralHeader,
                    HpackEntryType::kUnindexedLiteralHeader,
                    HpackEntryType::kNeverIndexedLiteralHeader}) {
    for (bool value_huffman : {false, true}) {
      // An entry with an index for the name. Ensure the name index
      // is not zero by adding one to the Rand8() result.
      expected.ExpectNameIndexAndLiteralValue(type, Rand8() + 1, value_huffman,
                                              Rand8String());
      // And two entries with literal names, one plain, one huffman encoded.
      expected.ExpectLiteralNameAndValue(type, false, Rand8String(),
                                         value_huffman, Rand8String());
      expected.ExpectLiteralNameAndValue(type, true, Rand8String(),
                                         value_huffman, Rand8String());
    }
  }
  // Shuffle the entries and serialize them to produce an HPACK block.
  expected.ShuffleEntries(RandomPtr());
  HpackBlockBuilder hbb;
  expected.AppendToHpackBlockBuilder(&hbb);

  EXPECT_TRUE(DecodeAndValidateSeveralWays(
      hbb,
      ValidateDoneAndEmpty([&] { return collector_.VerifyEq(expected); })));
  EXPECT_TRUE(collector_.VerifyEq(expected));
}

}  // namespace
}  // namespace test
}  // namespace http2
```