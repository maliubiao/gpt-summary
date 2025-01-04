Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The request asks for the functionality of the provided C++ code, its relation to JavaScript (if any), logical inferences with examples, potential user/programming errors, and debugging steps.

2. **Initial Scan and Identification of Key Components:**  A quick skim reveals:
    * `#include` directives:  These point to dependencies like `quiche/http2/decoder/decode_buffer.h`,  `quiche/http2/decoder/decode_status.h`, and testing utilities. This immediately suggests it's about testing HTTP/2 decoding.
    * `namespace http2::test`:  Confirms this is a test file within the HTTP/2 testing framework of the "quiche" library.
    * Class `RandomDecoderTestTest`:  This looks like the core of the testing logic, inheriting from `RandomDecoderTest`. The presence of `start_decoding_fn_`, `resume_decoding_fn_`, and counters suggests it's testing different phases of a decoding process.
    * `TEST_F` macros:  These are Google Test framework macros indicating individual test cases.
    * Functions like `StartDecoding`, `ResumeDecoding`, `StopDecodeOnDone`: These are virtual functions likely overridden from the base class `RandomDecoderTest`.
    * `DecodeSegments`, `DecodeAndValidateSeveralWays`: These look like helper functions provided by the base class for driving the decoding process in various ways.
    * `CorruptEnum` related tests: This seems to be a utility for intentionally corrupting enum values for testing robustness.

3. **Deconstruct the Functionality by Test Case:**  The most effective way to understand the functionality is to analyze each test case:

    * **`StopOnStartPartiallyDone`:**  Focuses on the scenario where `StartDecoding` decodes a small amount and returns `kDecodeDone`. This tests the immediate completion of the first decoding step.
    * **`StopOnResumePartiallyDone`:** Tests the scenario where `StartDecoding` returns `kDecodeInProgress`, and `ResumeDecoding` then decodes and returns `kDecodeDone`. This verifies stopping mid-process during a resume.
    * **`InProgressWhenEmpty`:**  Checks how the decoder behaves when it doesn't have enough data, returning `kDecodeInProgress`. This tests handling of incomplete data.
    * **`DoneExactlyAtEnd`:**  Focuses on the case where decoding completes exactly when all the input data is consumed.
    * **`DecodeSeveralWaysToEnd`:**  A more complex test that tries multiple ways to decode the entire input and validates the result. This aims to ensure consistent behavior across different decoding strategies.
    * **`DecodeTwoWaysAndStopEarly`:** Intentionally stops the decoding process early in one of the decoding attempts and checks for the expected failure/inconsistency. This tests early termination scenarios and validation.
    * **`DecodeThreeWaysAndError`:** Forces a decoding error during one of the attempts and verifies that the test framework catches it. This tests error handling.
    * **`ManyValues` (CorruptEnum):** Verifies that `CorruptEnum` can generate a wide range of values for a `DecodeStatus` enum. This checks the diversity of the corruption.
    * **`CorruptsOnlyEnum` (CorruptEnum):**  Confirms that `CorruptEnum` only modifies the target enum value and doesn't corrupt adjacent memory. This tests the safety and precision of the corruption mechanism.

4. **Identify the Core Purpose:**  Based on the test cases, the primary function of this file is to **thoroughly test the `RandomDecoderTest` base class.**  This base class seems designed to enable randomized testing of HTTP/2 decoders by allowing control over how much data is consumed and when decoding starts, resumes, or stops.

5. **Address the JavaScript Relationship:**  Think about how HTTP/2 concepts relate to JavaScript in a browser context. JavaScript in a browser doesn't directly interact with the *internal* decoding logic like this. However, it *uses* the results of this decoding when fetching resources. The key connection is: **This C++ code ensures the reliability of the underlying HTTP/2 decoding that JavaScript relies on for network communication.**

6. **Construct Logical Inferences and Examples:**  For each test case, create a simple "mental model" of the input and expected output. For example, in `StopOnStartPartiallyDone`, the input is the `kData`, and the expectation is that after the test, the `data_db_` offset is 1, indicating one byte was consumed.

7. **Consider User/Programming Errors:** Think about common mistakes when *using* a decoder or the `RandomDecoderTest` framework. Examples include providing insufficient data, incorrectly handling `DecodeStatus` return values, or not properly setting up the mock decoding functions.

8. **Trace User Operations for Debugging:** Imagine a user browsing a webpage. How does the browser end up using this decoding code? The path involves:
    * User enters a URL or clicks a link.
    * Browser initiates an HTTP/2 connection.
    * Server sends HTTP/2 frames.
    * Chromium's network stack (including this decoding code) processes those frames.
    * If a decoding error occurs (potentially uncovered by these tests), the browser might fail to load the page correctly.

9. **Structure the Answer:** Organize the findings into clear sections addressing each part of the original request: Functionality, JavaScript relation, logical inferences, user errors, and debugging steps. Use clear language and provide concrete examples.

10. **Review and Refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Are the examples easy to understand? Is the connection to JavaScript clear?  Are the debugging steps logical?

This structured approach, moving from high-level understanding to detailed analysis and then back to connecting the pieces, helps in comprehensively addressing the request. It also involves some iterative refinement as you uncover more details in the code.
这个 C++ 文件 `random_decoder_test_base_test.cc` 是 Chromium 网络栈中 QUIC 库的一部分，专门用于测试 `RandomDecoderTest` 基类。`RandomDecoderTest` 是一个用于随机化 HTTP/2 解码器行为的测试工具。

**功能列表:**

1. **测试 `RandomDecoderTest` 基类的行为:**  这个文件中的测试用例 (`TEST_F`) 验证了 `RandomDecoderTest` 基类的各种功能，例如：
    * **控制解码的开始和恢复:**  测试了在 `StartDecoding` 和 `ResumeDecoding` 函数中停止解码的能力。
    * **模拟部分完成的解码:**  测试了在解码过程中返回 `DecodeStatus::kDecodeDone` 或 `DecodeStatus::kDecodeInProgress` 的情况。
    * **处理解码完成:** 测试了在解码完成时 (`DecodeStatus::kDecodeDone`) 的行为。
    * **随机化解码过程:** 通过 `SelectRemaining()` 和 `SelectRandom()` 等方法模拟随机大小的数据块的解码。
    * **验证解码结果:** 使用 `DecodeAndValidateSeveralWays` 函数测试不同的解码方式是否产生一致的结果。
    * **模拟解码错误:** 测试了返回 `DecodeStatus::kDecodeError` 的情况。
    * **测试 `StopDecodeOnDone()` 的逻辑:** 验证了在解码完成时是否应该停止进一步解码的逻辑。

2. **提供 `RandomDecoderTestTest` 测试类:**  这个类继承自 `RandomDecoderTest` 并重写了一些虚函数，允许在测试中精确控制解码过程并进行断言。

3. **测试 `CorruptEnum` 函数:**  文件末尾的两个 `TEST` 用例测试了一个名为 `CorruptEnum` 的函数，该函数用于随机修改枚举类型的值，用于测试解码器对错误状态的鲁棒性。

**与 JavaScript 的关系:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的网络栈组件（HTTP/2 解码器）是浏览器与服务器通信的关键部分，而浏览器中运行的 JavaScript 代码会依赖于这种通信。

**举例说明:**

假设一个 JavaScript 应用通过 `fetch` API 发起一个 HTTP/2 请求。

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

在这个过程中，浏览器会：

1. **建立 HTTP/2 连接:** 与 `example.com` 服务器建立连接。
2. **发送请求:**  JavaScript 发起的请求会被编码成 HTTP/2 帧。
3. **接收响应:** 服务器返回的响应也是以 HTTP/2 帧的形式发送的。
4. **解码响应:** 浏览器内部的 HTTP/2 解码器（正是这个 C++ 文件所测试的组件）会解析接收到的 HTTP/2 帧，提取出响应头和响应体。
5. **传递数据给 JavaScript:**  解码后的响应体（例如 JSON 数据）会被传递给 JavaScript 代码，`response.json()` 方法会解析 JSON 数据。

**因此，`random_decoder_test_base_test.cc` 中测试的 HTTP/2 解码器的健壮性直接影响到 JavaScript 应用的网络功能是否正常。**  如果解码器存在缺陷，可能会导致 JavaScript 应用无法正确接收或解析服务器返回的数据。

**逻辑推理、假设输入与输出:**

以 `StopOnStartPartiallyDone` 测试用例为例：

* **假设输入:**  一个 `DecodeBuffer` `data_db_`，其内容为 `kData` (即 `0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07`)。
* **模拟行为:** `start_decoding_fn_` 被设置为只解码一个字节 (`db->DecodeUInt8()`) 并返回 `DecodeStatus::kDecodeDone`。
* **预期输出:**
    * `DecodeSegments` 函数返回 `DecodeStatus::kDecodeDone`。
    * `data_db_.Offset()` 的值为 `1`，表示解码器处理了一个字节。
    * `start_decoding_calls_` 为 `1`，`resume_decoding_calls_` 为 `0`，`stop_decode_on_done_calls_` 为 `1`。

**用户或编程常见的使用错误:**

1. **解码器实现不正确:**  如果实际的 HTTP/2 解码器代码在处理特定帧类型或数据边界时存在错误，这些错误可能在随机测试中被触发。例如，解码器可能没有正确处理帧长度字段，导致读取超出帧边界的数据。
    * **测试用例如何暴露:** `DecodeSegments` 和 `DecodeAndValidateSeveralWays` 可以通过模拟各种数据块大小和解码状态来发现这类错误。如果解码器在特定的数据分割方式下崩溃或产生错误的结果，测试就会失败。

2. **`RandomDecoderTest` 的使用不当:**  开发者可能在使用 `RandomDecoderTest` 基类编写测试时，没有正确设置 `start_decoding_fn_` 或 `resume_decoding_fn_`，导致测试没有覆盖到预期的解码路径。
    * **示例:**  开发者可能忘记在 `start_decoding_fn_` 中调用任何解码操作，导致测试始终在初始状态就返回 `kDecodeDone`，无法测试到后续的解码逻辑。

3. **对 `DecodeStatus` 的错误处理:**  解码器代码可能没有正确处理各种 `DecodeStatus` 返回值。例如，在接收到 `kDecodeInProgress` 时，解码器应该等待更多的数据，但如果错误地认为解码已完成，就会导致问题。
    * **测试用例如何暴露:**  `InProgressWhenEmpty` 测试用例专门测试了当解码器返回 `kDecodeInProgress` 但没有足够数据时的情况。如果解码器在这种情况下行为不正确，测试就会失败。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在使用 Chrome 浏览器浏览网页时遇到了网络问题，例如页面加载缓慢或部分内容无法加载。作为 Chromium 开发者，在调试这类问题时，可能会涉及到以下步骤，最终可能需要查看像 `random_decoder_test_base_test.cc` 这样的测试文件：

1. **用户报告问题:** 用户反馈某个网页在 Chrome 中加载异常。
2. **问题复现:** 开发者尝试在自己的环境中复现该问题，可能需要特定的网络环境或服务器配置。
3. **网络请求分析:** 使用 Chrome 的开发者工具 (Network 面板) 分析网络请求，查看请求头、响应头、状态码等信息，判断问题是否出在网络层。
4. **抓包分析:** 使用 Wireshark 等工具抓取网络包，检查 HTTP/2 连接的细节，例如帧类型、帧大小、帧内容等。
5. **定位到 HTTP/2 解码器:** 如果抓包分析显示接收到的 HTTP/2 帧存在异常，或者浏览器内部日志显示解码错误，那么问题可能出在 HTTP/2 解码器部分。
6. **查看解码器代码:** 开发者会查看 Chromium 中 HTTP/2 解码器的相关代码，尝试理解解码过程，查找潜在的错误点。
7. **运行相关测试:** 为了验证对解码器代码的理解或修复的正确性，开发者会运行相关的单元测试，例如 `random_decoder_test_base_test.cc` 中的测试用例。这些测试可以帮助开发者在隔离的环境下验证解码器的行为，确保其能够正确处理各种可能的输入和状态。
8. **修改代码和重新测试:** 如果测试失败，开发者会根据测试结果和代码分析，修改解码器代码，并重新运行测试，直到所有测试都通过。

**总结:**

`random_decoder_test_base_test.cc` 是一个重要的测试文件，用于验证 Chromium 中 HTTP/2 解码器框架的健壮性和正确性。它通过模拟各种随机的解码场景，帮助开发者发现潜在的 bug，确保浏览器能够可靠地处理 HTTP/2 网络通信，从而保证用户流畅的浏览体验。虽然它本身是 C++ 代码，但它所测试的功能直接影响到运行在浏览器中的 JavaScript 代码的网络功能。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/test_tools/random_decoder_test_base_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
#include "quiche/http2/test_tools/random_decoder_test_base.h"

#include <stddef.h>

#include <functional>
#include <ios>
#include <set>
#include <type_traits>

#include "quiche/http2/decoder/decode_buffer.h"
#include "quiche/http2/decoder/decode_status.h"
#include "quiche/http2/test_tools/http2_random.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_callbacks.h"

namespace http2 {
namespace test {
namespace {
const char kData[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
const bool kReturnNonZeroOnFirst = true;
const bool kMayReturnZeroOnFirst = false;

// Confirm the behavior of various parts of RandomDecoderTest.
class RandomDecoderTestTest : public RandomDecoderTest {
 public:
  RandomDecoderTestTest() : data_db_(kData) {
    QUICHE_CHECK_EQ(sizeof kData, 8u);
  }

 protected:
  typedef quiche::MultiUseCallback<DecodeStatus(DecodeBuffer* db)> DecodingFn;

  DecodeStatus StartDecoding(DecodeBuffer* db) override {
    ++start_decoding_calls_;
    if (start_decoding_fn_) {
      return start_decoding_fn_(db);
    }
    return DecodeStatus::kDecodeError;
  }

  DecodeStatus ResumeDecoding(DecodeBuffer* db) override {
    ++resume_decoding_calls_;
    if (resume_decoding_fn_) {
      return resume_decoding_fn_(db);
    }
    return DecodeStatus::kDecodeError;
  }

  bool StopDecodeOnDone() override {
    ++stop_decode_on_done_calls_;
    if (override_stop_decode_on_done_) {
      return sub_stop_decode_on_done_;
    }
    return RandomDecoderTest::StopDecodeOnDone();
  }

  size_t start_decoding_calls_ = 0;
  size_t resume_decoding_calls_ = 0;
  size_t stop_decode_on_done_calls_ = 0;

  DecodingFn start_decoding_fn_;
  DecodingFn resume_decoding_fn_;

  DecodeBuffer data_db_;

  bool sub_stop_decode_on_done_ = true;
  bool override_stop_decode_on_done_ = true;
};

// Decode a single byte on the StartDecoding call, then stop.
TEST_F(RandomDecoderTestTest, StopOnStartPartiallyDone) {
  start_decoding_fn_ = [this](DecodeBuffer* db) {
    EXPECT_EQ(1u, start_decoding_calls_);
    // Make sure the correct buffer is being used.
    EXPECT_EQ(kData, db->cursor());
    EXPECT_EQ(sizeof kData, db->Remaining());
    db->DecodeUInt8();
    return DecodeStatus::kDecodeDone;
  };

  EXPECT_EQ(DecodeStatus::kDecodeDone,
            DecodeSegments(&data_db_, SelectRemaining()));
  EXPECT_EQ(1u, data_db_.Offset());
  // StartDecoding should only be called once from each call to DecodeSegments.
  EXPECT_EQ(1u, start_decoding_calls_);
  EXPECT_EQ(0u, resume_decoding_calls_);
  EXPECT_EQ(1u, stop_decode_on_done_calls_);
}

// Stop decoding upon return from the first ResumeDecoding call.
TEST_F(RandomDecoderTestTest, StopOnResumePartiallyDone) {
  start_decoding_fn_ = [this](DecodeBuffer* db) {
    EXPECT_EQ(1u, start_decoding_calls_);
    db->DecodeUInt8();
    return DecodeStatus::kDecodeInProgress;
  };
  resume_decoding_fn_ = [this](DecodeBuffer* db) {
    EXPECT_EQ(1u, resume_decoding_calls_);
    // Make sure the correct buffer is being used.
    EXPECT_EQ(data_db_.cursor(), db->cursor());
    db->DecodeUInt16();
    return DecodeStatus::kDecodeDone;
  };

  // Check that the base class honors it's member variable stop_decode_on_done_.
  override_stop_decode_on_done_ = false;
  stop_decode_on_done_ = true;

  EXPECT_EQ(DecodeStatus::kDecodeDone,
            DecodeSegments(&data_db_, SelectRemaining()));
  EXPECT_EQ(3u, data_db_.Offset());
  EXPECT_EQ(1u, start_decoding_calls_);
  EXPECT_EQ(1u, resume_decoding_calls_);
  EXPECT_EQ(1u, stop_decode_on_done_calls_);
}

// Decode a random sized chunks, always reporting back kDecodeInProgress.
TEST_F(RandomDecoderTestTest, InProgressWhenEmpty) {
  start_decoding_fn_ = [this](DecodeBuffer* db) {
    EXPECT_EQ(1u, start_decoding_calls_);
    // Consume up to 2 bytes.
    if (db->HasData()) {
      db->DecodeUInt8();
      if (db->HasData()) {
        db->DecodeUInt8();
      }
    }
    return DecodeStatus::kDecodeInProgress;
  };
  resume_decoding_fn_ = [](DecodeBuffer* db) {
    // Consume all available bytes.
    if (db->HasData()) {
      db->AdvanceCursor(db->Remaining());
    }
    return DecodeStatus::kDecodeInProgress;
  };

  EXPECT_EQ(DecodeStatus::kDecodeInProgress,
            DecodeSegments(&data_db_, SelectRandom(kMayReturnZeroOnFirst)));
  EXPECT_TRUE(data_db_.Empty());
  EXPECT_EQ(1u, start_decoding_calls_);
  EXPECT_LE(1u, resume_decoding_calls_);
  EXPECT_EQ(0u, stop_decode_on_done_calls_);
}

TEST_F(RandomDecoderTestTest, DoneExactlyAtEnd) {
  start_decoding_fn_ = [this](DecodeBuffer* db) {
    EXPECT_EQ(1u, start_decoding_calls_);
    EXPECT_EQ(1u, db->Remaining());
    EXPECT_EQ(1u, db->FullSize());
    db->DecodeUInt8();
    return DecodeStatus::kDecodeInProgress;
  };
  resume_decoding_fn_ = [this](DecodeBuffer* db) {
    EXPECT_EQ(1u, db->Remaining());
    EXPECT_EQ(1u, db->FullSize());
    db->DecodeUInt8();
    if (data_db_.Remaining() == 1) {
      return DecodeStatus::kDecodeDone;
    }
    return DecodeStatus::kDecodeInProgress;
  };
  override_stop_decode_on_done_ = true;
  sub_stop_decode_on_done_ = true;

  EXPECT_EQ(DecodeStatus::kDecodeDone, DecodeSegments(&data_db_, SelectOne()));
  EXPECT_EQ(0u, data_db_.Remaining());
  EXPECT_EQ(1u, start_decoding_calls_);
  EXPECT_EQ((sizeof kData) - 1, resume_decoding_calls_);
  // Didn't need to call StopDecodeOnDone because we didn't finish early.
  EXPECT_EQ(0u, stop_decode_on_done_calls_);
}

TEST_F(RandomDecoderTestTest, DecodeSeveralWaysToEnd) {
  // Each call to StartDecoding or ResumeDecoding will consume all that is
  // available. When all the data has been consumed, returns kDecodeDone.
  size_t decoded_since_start = 0;
  auto shared_fn = [&decoded_since_start, this](DecodeBuffer* db) {
    decoded_since_start += db->Remaining();
    db->AdvanceCursor(db->Remaining());
    EXPECT_EQ(0u, db->Remaining());
    if (decoded_since_start == data_db_.FullSize()) {
      return DecodeStatus::kDecodeDone;
    }
    return DecodeStatus::kDecodeInProgress;
  };

  start_decoding_fn_ = [&decoded_since_start, shared_fn](DecodeBuffer* db) {
    decoded_since_start = 0;
    return shared_fn(db);
  };
  resume_decoding_fn_ = shared_fn;

  Validator validator = ValidateDoneAndEmpty();

  EXPECT_TRUE(DecodeAndValidateSeveralWays(&data_db_, kMayReturnZeroOnFirst,
                                           validator));

  // We should have reached the end.
  EXPECT_EQ(0u, data_db_.Remaining());

  // We currently have 4 ways of decoding; update this if that changes.
  EXPECT_EQ(4u, start_decoding_calls_);

  // Didn't need to call StopDecodeOnDone because we didn't finish early.
  EXPECT_EQ(0u, stop_decode_on_done_calls_);
}

TEST_F(RandomDecoderTestTest, DecodeTwoWaysAndStopEarly) {
  // On the second decode, return kDecodeDone before finishing.
  size_t decoded_since_start = 0;
  auto shared_fn = [&decoded_since_start, this](DecodeBuffer* db) {
    uint32_t amount = db->Remaining();
    if (start_decoding_calls_ == 2 && amount > 1) {
      amount = 1;
    }
    decoded_since_start += amount;
    db->AdvanceCursor(amount);
    if (decoded_since_start == data_db_.FullSize()) {
      return DecodeStatus::kDecodeDone;
    }
    if (decoded_since_start > 1 && start_decoding_calls_ == 2) {
      return DecodeStatus::kDecodeDone;
    }
    return DecodeStatus::kDecodeInProgress;
  };

  start_decoding_fn_ = [&decoded_since_start, shared_fn](DecodeBuffer* db) {
    decoded_since_start = 0;
    return shared_fn(db);
  };
  resume_decoding_fn_ = shared_fn;

  // We expect the first and second to succeed, but the second to end at a
  // different offset, which DecodeAndValidateSeveralWays should complain about.
  Validator validator = [this](const DecodeBuffer& /*input*/,
                               DecodeStatus status) -> AssertionResult {
    if (start_decoding_calls_ <= 2 && status != DecodeStatus::kDecodeDone) {
      return ::testing::AssertionFailure()
             << "Expected DecodeStatus::kDecodeDone, not " << status;
    }
    if (start_decoding_calls_ > 2) {
      return ::testing::AssertionFailure()
             << "How did we get to pass " << start_decoding_calls_;
    }
    return ::testing::AssertionSuccess();
  };

  EXPECT_FALSE(DecodeAndValidateSeveralWays(&data_db_, kMayReturnZeroOnFirst,
                                            validator));
  EXPECT_EQ(2u, start_decoding_calls_);
  EXPECT_EQ(1u, stop_decode_on_done_calls_);
}

TEST_F(RandomDecoderTestTest, DecodeThreeWaysAndError) {
  // Return kDecodeError from ResumeDecoding on the third decoding pass.
  size_t decoded_since_start = 0;
  auto shared_fn = [&decoded_since_start, this](DecodeBuffer* db) {
    if (start_decoding_calls_ == 3 && decoded_since_start > 0) {
      return DecodeStatus::kDecodeError;
    }
    uint32_t amount = db->Remaining();
    if (start_decoding_calls_ == 3 && amount > 1) {
      amount = 1;
    }
    decoded_since_start += amount;
    db->AdvanceCursor(amount);
    if (decoded_since_start == data_db_.FullSize()) {
      return DecodeStatus::kDecodeDone;
    }
    return DecodeStatus::kDecodeInProgress;
  };

  start_decoding_fn_ = [&decoded_since_start, shared_fn](DecodeBuffer* db) {
    decoded_since_start = 0;
    return shared_fn(db);
  };
  resume_decoding_fn_ = shared_fn;

  Validator validator = ValidateDoneAndEmpty();
  EXPECT_FALSE(DecodeAndValidateSeveralWays(&data_db_, kReturnNonZeroOnFirst,
                                            validator));
  EXPECT_EQ(3u, start_decoding_calls_);
  EXPECT_EQ(0u, stop_decode_on_done_calls_);
}

// CorruptEnum should produce lots of different values. On the assumption that
// the enum gets at least a byte of storage, we should be able to produce
// 256 distinct values.
TEST(CorruptEnumTest, ManyValues) {
  std::set<uint64_t> values;
  DecodeStatus status;
  QUICHE_LOG(INFO) << "sizeof status = " << sizeof status;
  Http2Random rng;
  for (int ndx = 0; ndx < 256; ++ndx) {
    CorruptEnum(&status, &rng);
    values.insert(static_cast<uint64_t>(status));
  }
}

// In practice the underlying type is an int, and currently that is 4 bytes.
typedef typename std::underlying_type<DecodeStatus>::type DecodeStatusUT;

struct CorruptEnumTestStruct {
  DecodeStatusUT filler1;
  DecodeStatus status;
  DecodeStatusUT filler2;
};

// CorruptEnum should only overwrite the enum, not any adjacent storage.
TEST(CorruptEnumTest, CorruptsOnlyEnum) {
  Http2Random rng;
  for (const DecodeStatusUT filler : {DecodeStatusUT(), ~DecodeStatusUT()}) {
    QUICHE_LOG(INFO) << "filler=0x" << std::hex << filler;
    CorruptEnumTestStruct s;
    s.filler1 = filler;
    s.filler2 = filler;
    for (int ndx = 0; ndx < 256; ++ndx) {
      CorruptEnum(&s.status, &rng);
      EXPECT_EQ(s.filler1, filler);
      EXPECT_EQ(s.filler2, filler);
    }
  }
}

}  // namespace
}  // namespace test
}  // namespace http2

"""

```