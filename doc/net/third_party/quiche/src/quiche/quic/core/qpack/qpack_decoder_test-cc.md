Response:
The user wants me to analyze a C++ source code file related to the QUIC protocol's QPACK implementation in Chromium. Specifically, it's the `qpack_decoder_test.cc` file.

Here's a breakdown of the requested information and my plan to address it:

1. **Functionality:** I need to understand what this test file is designed to do. The name `qpack_decoder_test.cc` strongly suggests it's for testing the `QpackDecoder` class. I will look for common testing patterns like setting up inputs, calling methods of the `QpackDecoder`, and asserting the expected outputs or behaviors.

2. **Relationship with Javascript:** I need to determine if the tested functionality interacts with Javascript. QPACK is a header compression mechanism for HTTP/3, which is used by web browsers (where Javascript runs). The connection is likely indirect – the QPACK decoder is implemented in C++, but it's used to process headers that are part of HTTP requests and responses initiated by Javascript in a browser. I need to identify scenarios where the decoding process directly impacts what Javascript sees or how it behaves.

3. **Logical Inference (Hypothetical Inputs and Outputs):**  I should find specific test cases within the file and analyze them. For each test, I'll identify the input data (typically a sequence of bytes representing encoded QPACK data) and the expected output (the decoded headers and any error conditions).

4. **Common Usage Errors:**  Test files often demonstrate how things can go wrong. I need to find test cases that explicitly check for error conditions, indicating potential pitfalls for developers implementing or using QPACK.

5. **User Journey (Debugging Clues):** I need to describe how a user's actions in a web browser could lead to the execution of this QPACK decoding code. This involves tracing the path from a user request to the network stack and the QPACK decoder.

6. **Summary of Functionality (Part 1):**  Finally, I need to summarize the functionality covered in the provided first part of the file.

**Mental Sandbox:**

* I'll start by looking for the `TEST_P` and `TEST` macros, as these define individual test cases.
* I'll examine the `EXPECT_CALL` macros to understand the expected interactions with mock objects (like `MockHeadersHandler`).
* I'll pay attention to how input data is created and fed to the decoder (`DecodeHeaderBlock`, `DecodeData`).
* For the Javascript relationship, I'll consider scenarios like fetching resources (images, scripts, etc.) where HTTP headers are crucial.
* For usage errors, I'll look for tests with `OnDecodingErrorDetected`.
* The user journey will involve explaining how a browser's network stack handles HTTP/3 requests and responses.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes
* 如果它与javascript的功能有关系，请做出对应的举例说明: Yes
* 如果做了逻辑推理，请给出假设输入与输出: Yes
* 如果涉及用户或者编程常见的使用错误，请举例说明: Yes
* 说明用户操作是如何一步步的到达这里，作为调试线索: Yes
* 这是第1部分，共2部分，请归纳一下它的功能: Yes

Confidence Score: 5/5 - I'm confident I can address all aspects of the request based on the provided code snippet and my understanding of testing practices and web technologies.

Strategizing complete. I will now proceed with generating the response.

这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/qpack/qpack_decoder_test.cc` 文件的第一部分，主要功能是**测试 QPACK 解码器 (`QpackDecoder`) 的各种功能和错误处理情况**。它通过编写单元测试用例，模拟不同的输入数据，并验证解码器的行为是否符合预期。

以下是根据代码内容归纳出的具体功能点：

**核心功能测试:**

* **基本解码流程:** 测试在没有错误的情况下，如何解码简单的头字段，包括空名称、空值、以及包含普通字符的名称和值。
* **处理多个头字段:** 测试解码器能否正确处理包含多个头字段的头块。
* **霍夫曼编码:** 测试解码器对使用霍夫曼编码的头字段名称和值的解码能力，包括正确解码和处理霍夫曼编码错误的情况 (例如，EOS 前缀不正确或过长)。
* **静态表:** 测试解码器使用静态表进行解码的能力，包括正确匹配静态表条目和处理超出静态表索引范围的情况。
* **动态表:** 这是测试的重点部分，涵盖了动态表的各种操作：
    * **添加条目:** 测试解码器如何处理编码器流发送的动态表更新指令，添加新的字面量条目和基于现有条目的条目。
    * **索引条目:** 测试解码器如何使用动态表中的条目进行解码，包括使用相对索引和后基准索引。
    * **调整容量:** 测试解码器如何响应编码器流发送的动态表容量更新指令，以及容量变化对现有条目的影响（驱逐）。
    * **动态表大小限制:** 测试解码器能否处理尝试设置超出最大允许容量的动态表。
* **头块前缀:** 测试解码器对头块前缀的解析，包括处理不完整的前缀和无效的编码插入计数值的情况。
* **包装的插入计数值:** 测试解码器处理插入计数值环绕的情况。

**错误处理测试:**

* **解码错误:**
    * **不完整的数据:**  测试解码器在遇到不完整的头块或头数据前缀时的错误处理。
    * **无效的前缀:** 测试解码器在遇到编码插入计数值过大时的错误处理。
    * **字符串字面量过长:** 测试解码器在遇到名称或值长度超过限制时的错误处理。
    * **霍夫曼解码错误:** 测试解码器在遇到无效的霍夫曼编码时的错误处理。
    * **静态表索引错误:** 测试解码器在尝试访问不存在的静态表条目时的错误处理。
    * **动态表索引错误:** 测试解码器在尝试访问不存在或已驱逐的动态表条目时的错误处理，包括使用相对索引和后基准索引。
    * **Base 值计算错误:** 测试解码器在计算 Base 值时发生错误（例如，负数）的错误处理。
    * **无效的编码插入计数值:** 测试解码器在遇到无法正确解码的插入计数值时的错误处理。
* **编码器流错误:**
    * **插入字面量错误:** 测试解码器在编码器流尝试插入过大字面量条目时的错误处理。
    * **无效的静态表条目:** 测试解码器在编码器流中收到无效的静态表索引时的错误处理。
    * **无效的动态表条目:** 测试解码器在编码器流中收到无效的动态表索引时的错误处理。
    * **重复无效条目:** 测试解码器在编码器流中收到重复的无效动态表索引时的错误处理。
    * **整数过大:** 测试解码器在编码器流中收到过大的整数时的错误处理。
    * **设置动态表容量错误:** 测试解码器在编码器流中收到设置无效动态表容量的指令时的错误处理。

**与 JavaScript 的关系 (推测):**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的 QPACK 解码器是 HTTP/3 协议栈的关键组成部分，而 HTTP/3 是现代 Web 浏览器与服务器通信的基础。  JavaScript 通过浏览器提供的 API (例如 `fetch`) 发起网络请求，这些请求的头部信息需要经过 QPACK 编码后在网络上传输，并在接收端由这个测试文件中验证的 `QpackDecoder` 进行解码。

**举例说明:**

假设 JavaScript 代码发起一个如下的 `fetch` 请求：

```javascript
fetch('https://example.com/data', {
  headers: {
    'Content-Type': 'application/json',
    'X-Custom-Header': 'some-value'
  }
});
```

1. **编码:** 浏览器会将这些头部信息 (`Content-Type: application/json`, `X-Custom-Header: some-value`) 使用 QPACK 编码成二进制数据。
2. **传输:** 编码后的数据通过 HTTP/3 连接发送到服务器。
3. **解码 (涉及本文件测试的代码):** 服务器接收到这些编码后的数据，并使用 QPACK 解码器（类似于这个测试文件中测试的 `QpackDecoder` 的实现）将其还原成原始的头部信息。
4. **服务器处理:** 服务器根据解码后的头部信息进行相应的处理。

**逻辑推理 (假设输入与输出):**

**假设输入:**  一个包含编码后的头字段的字节序列： `000023666f6f03626172`

**解码过程:**

1. **头块前缀:** `0000`  解码为 Required Insert Count = 0, Delta Base = 0。
2. **字面量头字段:** `23` 表示不带索引的字面量头字段，名称长度为 3 字节。
3. **名称:** `666f6f` 解码为字符串 "foo"。
4. **值长度:** `03` 表示值长度为 3 字节。
5. **值:** `626172` 解码为字符串 "bar"。

**预期输出:**  调用 `MockHeadersHandler` 的 `OnHeaderDecoded` 方法，参数为 `"foo"` 和 `"bar"`，然后调用 `OnDecodingCompleted` 表示解码完成。

**用户或编程常见的使用错误:**

* **配置错误的动态表大小:**  如果编码器和解码器配置的动态表最大容量不一致，可能会导致解码错误，例如尝试索引一个在解码器动态表中不存在的条目。
* **未处理编码器流错误:**  如果解码器没有正确处理编码器流发送的错误指令（例如，尝试添加过大的条目），可能导致状态不一致甚至崩溃。
* **不正确的头块边界:** 在流式处理头块数据时，如果开发者没有正确划分头块的边界，可能会导致解码器解析错误。例如，过早地调用 `EndDecoding`。
* **假设静态表内容固定不变:** 虽然 QPACK 有静态表，但在某些场景下，理解其内容和索引对于调试非常重要。 错误地假设静态表的内容或索引可能导致解码错误。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中输入 URL 或点击链接:** 触发浏览器发起 HTTP/3 请求。
2. **浏览器构建 HTTP 请求:**  包括生成请求头。
3. **QPACK 编码:** 浏览器的网络栈使用 QPACK 编码器对请求头进行编码。
4. **网络传输:** 编码后的数据通过 QUIC 连接发送到服务器。
5. **服务器接收数据:** 服务器的网络栈接收到包含 QPACK 编码头部的数据。
6. **QPACK 解码 (到达 `qpack_decoder_test.cc` 测试的代码):** 服务器的网络栈使用 QPACK 解码器 (类似于测试文件中的 `QpackDecoder`) 对接收到的头部进行解码。如果服务器的实现有问题，或者接收到的数据格式错误，就会触发类似 `qpack_decoder_test.cc` 中测试的错误场景。
7. **服务器处理请求:** 解码后的头部信息被传递给服务器应用程序进行处理。

**总结第一部分的功能:**

总而言之，`net/third_party/quiche/src/quiche/quic/core/qpack/qpack_decoder_test.cc` 的第一部分主要专注于 **全面测试 QPACK 解码器的核心解码功能和各种错误处理场景**，涵盖了字面量头字段、霍夫曼编码、静态表和动态表的操作。这些测试旨在确保解码器在各种输入情况下都能正确可靠地工作，并且能够妥善处理各种可能出现的错误情况，保证 HTTP/3 连接的稳定性和安全性。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/qpack/qpack_decoder_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/qpack/qpack_decoder.h"

#include <algorithm>
#include <memory>
#include <string>

#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/qpack/qpack_decoder_test_utils.h"
#include "quiche/quic/test_tools/qpack/qpack_test_utils.h"

using ::testing::_;
using ::testing::Eq;
using ::testing::Invoke;
using ::testing::Mock;
using ::testing::Sequence;
using ::testing::StrictMock;
using ::testing::Values;

namespace quic {
namespace test {
namespace {

// Header Acknowledgement decoder stream instruction with stream_id = 1.
const char* const kHeaderAcknowledgement = "\x81";

const uint64_t kMaximumDynamicTableCapacity = 1024;
const uint64_t kMaximumBlockedStreams = 1;

class QpackDecoderTest : public QuicTestWithParam<FragmentMode> {
 protected:
  QpackDecoderTest()
      : qpack_decoder_(kMaximumDynamicTableCapacity, kMaximumBlockedStreams,
                       &encoder_stream_error_delegate_),
        fragment_mode_(GetParam()) {
    qpack_decoder_.set_qpack_stream_sender_delegate(
        &decoder_stream_sender_delegate_);
  }

  ~QpackDecoderTest() override = default;

  void SetUp() override {
    // Destroy QpackProgressiveDecoder on error to test that it does not crash.
    // See https://crbug.com/1025209.
    ON_CALL(handler_, OnDecodingErrorDetected(_, _))
        .WillByDefault(Invoke([this](QuicErrorCode /* error_code */,
                                     absl::string_view /* error_message */) {
          progressive_decoder_.reset();
        }));
  }

  void DecodeEncoderStreamData(absl::string_view data) {
    qpack_decoder_.encoder_stream_receiver()->Decode(data);
  }

  std::unique_ptr<QpackProgressiveDecoder> CreateProgressiveDecoder(
      QuicStreamId stream_id) {
    return qpack_decoder_.CreateProgressiveDecoder(stream_id, &handler_);
  }

  void FlushDecoderStream() { qpack_decoder_.FlushDecoderStream(); }

  // Set up |progressive_decoder_|.
  void StartDecoding() {
    progressive_decoder_ = CreateProgressiveDecoder(/* stream_id = */ 1);
  }

  // Pass header block data to QpackProgressiveDecoder::Decode()
  // in fragments dictated by |fragment_mode_|.
  void DecodeData(absl::string_view data) {
    auto fragment_size_generator =
        FragmentModeToFragmentSizeGenerator(fragment_mode_);
    while (progressive_decoder_ && !data.empty()) {
      size_t fragment_size = std::min(fragment_size_generator(), data.size());
      progressive_decoder_->Decode(data.substr(0, fragment_size));
      data = data.substr(fragment_size);
    }
  }

  // Signal end of header block to QpackProgressiveDecoder.
  void EndDecoding() {
    if (progressive_decoder_) {
      progressive_decoder_->EndHeaderBlock();
    }
    // If no error was detected, |*progressive_decoder_| is kept alive so that
    // it can handle callbacks later in case of blocked decoding.
  }

  // Decode an entire header block.
  void DecodeHeaderBlock(absl::string_view data) {
    StartDecoding();
    DecodeData(data);
    EndDecoding();
  }

  StrictMock<MockEncoderStreamErrorDelegate> encoder_stream_error_delegate_;
  StrictMock<MockQpackStreamSenderDelegate> decoder_stream_sender_delegate_;
  StrictMock<MockHeadersHandler> handler_;

 private:
  QpackDecoder qpack_decoder_;
  const FragmentMode fragment_mode_;
  std::unique_ptr<QpackProgressiveDecoder> progressive_decoder_;
};

INSTANTIATE_TEST_SUITE_P(All, QpackDecoderTest,
                         Values(FragmentMode::kSingleChunk,
                                FragmentMode::kOctetByOctet));

TEST_P(QpackDecoderTest, NoPrefix) {
  EXPECT_CALL(handler_,
              OnDecodingErrorDetected(QUIC_QPACK_DECOMPRESSION_FAILED,
                                      Eq("Incomplete header data prefix.")));

  // Header Data Prefix is at least two bytes long.
  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("00", &input));
  DecodeHeaderBlock(input);
}

// Regression test for https://1025209: QpackProgressiveDecoder must not crash
// in Decode() if it is destroyed by handler_.OnDecodingErrorDetected().
TEST_P(QpackDecoderTest, InvalidPrefix) {
  StartDecoding();

  EXPECT_CALL(handler_,
              OnDecodingErrorDetected(QUIC_QPACK_DECOMPRESSION_FAILED,
                                      Eq("Encoded integer too large.")));

  // Encoded Required Insert Count in Header Data Prefix is too large.
  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("ffffffffffffffffffffffffffff", &input));
  DecodeData(input);
}

TEST_P(QpackDecoderTest, EmptyHeaderBlock) {
  EXPECT_CALL(handler_, OnDecodingCompleted());

  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("0000", &input));
  DecodeHeaderBlock(input);
}

TEST_P(QpackDecoderTest, LiteralEntryEmptyName) {
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq(""), Eq("foo")));
  EXPECT_CALL(handler_, OnDecodingCompleted());

  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("00002003666f6f", &input));
  DecodeHeaderBlock(input);
}

TEST_P(QpackDecoderTest, LiteralEntryEmptyValue) {
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq("foo"), Eq("")));
  EXPECT_CALL(handler_, OnDecodingCompleted());

  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("000023666f6f00", &input));
  DecodeHeaderBlock(input);
}

TEST_P(QpackDecoderTest, LiteralEntryEmptyNameAndValue) {
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq(""), Eq("")));
  EXPECT_CALL(handler_, OnDecodingCompleted());

  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("00002000", &input));
  DecodeHeaderBlock(input);
}

TEST_P(QpackDecoderTest, SimpleLiteralEntry) {
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq("foo"), Eq("bar")));
  EXPECT_CALL(handler_, OnDecodingCompleted());

  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("000023666f6f03626172", &input));
  DecodeHeaderBlock(input);
}

TEST_P(QpackDecoderTest, MultipleLiteralEntries) {
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq("foo"), Eq("bar")));
  std::string str(127, 'a');
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq("foobaar"), absl::string_view(str)));
  EXPECT_CALL(handler_, OnDecodingCompleted());

  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes(
      "0000"                // prefix
      "23666f6f03626172"    // foo: bar
      "2700666f6f62616172"  // 7 octet long header name, the smallest number
                            // that does not fit on a 3-bit prefix.
      "7f0061616161616161"  // 127 octet long header value, the smallest number
      "616161616161616161"  // that does not fit on a 7-bit prefix.
      "6161616161616161616161616161616161616161616161616161616161616161616161"
      "6161616161616161616161616161616161616161616161616161616161616161616161"
      "6161616161616161616161616161616161616161616161616161616161616161616161"
      "616161616161",
      &input));
  DecodeHeaderBlock(input);
}

// Name Length value is too large for varint decoder to decode.
TEST_P(QpackDecoderTest, NameLenTooLargeForVarintDecoder) {
  EXPECT_CALL(handler_,
              OnDecodingErrorDetected(QUIC_QPACK_DECOMPRESSION_FAILED,
                                      Eq("Encoded integer too large.")));

  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("000027ffffffffffffffffffff", &input));
  DecodeHeaderBlock(input);
}

// Name Length value can be decoded by varint decoder but exceeds 1 MB limit.
TEST_P(QpackDecoderTest, NameLenExceedsLimit) {
  EXPECT_CALL(handler_,
              OnDecodingErrorDetected(QUIC_QPACK_DECOMPRESSION_FAILED,
                                      Eq("String literal too long.")));

  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("000027ffff7f", &input));
  DecodeHeaderBlock(input);
}

// Value Length value is too large for varint decoder to decode.
TEST_P(QpackDecoderTest, ValueLenTooLargeForVarintDecoder) {
  EXPECT_CALL(handler_,
              OnDecodingErrorDetected(QUIC_QPACK_DECOMPRESSION_FAILED,
                                      Eq("Encoded integer too large.")));

  std::string input;
  ASSERT_TRUE(
      absl::HexStringToBytes("000023666f6f7fffffffffffffffffffff", &input));
  DecodeHeaderBlock(input);
}

// Value Length value can be decoded by varint decoder but exceeds 1 MB limit.
TEST_P(QpackDecoderTest, ValueLenExceedsLimit) {
  EXPECT_CALL(handler_,
              OnDecodingErrorDetected(QUIC_QPACK_DECOMPRESSION_FAILED,
                                      Eq("String literal too long.")));

  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("000023666f6f7fffff7f", &input));
  DecodeHeaderBlock(input);
}

TEST_P(QpackDecoderTest, LineFeedInValue) {
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq("foo"), Eq("ba\nr")));
  EXPECT_CALL(handler_, OnDecodingCompleted());

  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("000023666f6f0462610a72", &input));
  DecodeHeaderBlock(input);
}

TEST_P(QpackDecoderTest, IncompleteHeaderBlock) {
  EXPECT_CALL(handler_,
              OnDecodingErrorDetected(QUIC_QPACK_DECOMPRESSION_FAILED,
                                      Eq("Incomplete header block.")));

  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("00002366", &input));
  DecodeHeaderBlock(input);
}

TEST_P(QpackDecoderTest, HuffmanSimple) {
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq("custom-key"), Eq("custom-value")));
  EXPECT_CALL(handler_, OnDecodingCompleted());

  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes(
      "00002f0125a849e95ba97d7f8925a849e95bb8e8b4bf", &input));
  DecodeHeaderBlock(input);
}

TEST_P(QpackDecoderTest, AlternatingHuffmanNonHuffman) {
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq("custom-key"), Eq("custom-value")))
      .Times(4);
  EXPECT_CALL(handler_, OnDecodingCompleted());

  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes(
      "0000"                        // Prefix.
      "2f0125a849e95ba97d7f"        // Huffman-encoded name.
      "8925a849e95bb8e8b4bf"        // Huffman-encoded value.
      "2703637573746f6d2d6b6579"    // Non-Huffman encoded name.
      "0c637573746f6d2d76616c7565"  // Non-Huffman encoded value.
      "2f0125a849e95ba97d7f"        // Huffman-encoded name.
      "0c637573746f6d2d76616c7565"  // Non-Huffman encoded value.
      "2703637573746f6d2d6b6579"    // Non-Huffman encoded name.
      "8925a849e95bb8e8b4bf",       // Huffman-encoded value.
      &input));
  DecodeHeaderBlock(input);
}

TEST_P(QpackDecoderTest, HuffmanNameDoesNotHaveEOSPrefix) {
  EXPECT_CALL(handler_,
              OnDecodingErrorDetected(QUIC_QPACK_DECOMPRESSION_FAILED,
                                      Eq("Error in Huffman-encoded string.")));

  // 'y' ends in 0b0 on the most significant bit of the last byte.
  // The remaining 7 bits must be a prefix of EOS, which is all 1s.
  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes(
      "00002f0125a849e95ba97d7e8925a849e95bb8e8b4bf", &input));
  DecodeHeaderBlock(input);
}

TEST_P(QpackDecoderTest, HuffmanValueDoesNotHaveEOSPrefix) {
  EXPECT_CALL(handler_,
              OnDecodingErrorDetected(QUIC_QPACK_DECOMPRESSION_FAILED,
                                      Eq("Error in Huffman-encoded string.")));

  // 'e' ends in 0b101, taking up the 3 most significant bits of the last byte.
  // The remaining 5 bits must be a prefix of EOS, which is all 1s.
  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes(
      "00002f0125a849e95ba97d7f8925a849e95bb8e8b4be", &input));
  DecodeHeaderBlock(input);
}

TEST_P(QpackDecoderTest, HuffmanNameEOSPrefixTooLong) {
  EXPECT_CALL(handler_,
              OnDecodingErrorDetected(QUIC_QPACK_DECOMPRESSION_FAILED,
                                      Eq("Error in Huffman-encoded string.")));

  // The trailing EOS prefix must be at most 7 bits long.  Appending one octet
  // with value 0xff is invalid, even though 0b111111111111111 (15 bits) is a
  // prefix of EOS.
  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes(
      "00002f0225a849e95ba97d7fff8925a849e95bb8e8b4bf", &input));
  DecodeHeaderBlock(input);
}

TEST_P(QpackDecoderTest, HuffmanValueEOSPrefixTooLong) {
  EXPECT_CALL(handler_,
              OnDecodingErrorDetected(QUIC_QPACK_DECOMPRESSION_FAILED,
                                      Eq("Error in Huffman-encoded string.")));

  // The trailing EOS prefix must be at most 7 bits long.  Appending one octet
  // with value 0xff is invalid, even though 0b1111111111111 (13 bits) is a
  // prefix of EOS.
  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes(
      "00002f0125a849e95ba97d7f8a25a849e95bb8e8b4bfff", &input));
  DecodeHeaderBlock(input);
}

TEST_P(QpackDecoderTest, StaticTable) {
  // A header name that has multiple entries with different values.
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq(":method"), Eq("GET")));
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq(":method"), Eq("POST")));
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq(":method"), Eq("TRACE")));

  // A header name that has a single entry with non-empty value.
  EXPECT_CALL(handler_,
              OnHeaderDecoded(Eq("accept-encoding"), Eq("gzip, deflate, br")));
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq("accept-encoding"), Eq("compress")));
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq("accept-encoding"), Eq("")));

  // A header name that has a single entry with empty value.
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq("location"), Eq("")));
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq("location"), Eq("foo")));

  EXPECT_CALL(handler_, OnDecodingCompleted());

  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes(
      "0000d1dfccd45f108621e9aec2a11f5c8294e75f000554524143455f1000", &input));
  DecodeHeaderBlock(input);
}

TEST_P(QpackDecoderTest, TooHighStaticTableIndex) {
  // This is the last entry in the static table with index 98.
  EXPECT_CALL(handler_,
              OnHeaderDecoded(Eq("x-frame-options"), Eq("sameorigin")));

  // Addressing entry 99 should trigger an error.
  EXPECT_CALL(handler_,
              OnDecodingErrorDetected(QUIC_QPACK_DECOMPRESSION_FAILED,
                                      Eq("Static table entry not found.")));

  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("0000ff23ff24", &input));
  DecodeHeaderBlock(input);
}

TEST_P(QpackDecoderTest, DynamicTable) {
  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes(
      "3fe107"          // Set dynamic table capacity to 1024.
      "6294e703626172"  // Add literal entry with name "foo" and value "bar".
      "80035a5a5a"      // Add entry with name of dynamic table entry index 0
                        // (relative index) and value "ZZZ".
      "cf8294e7"        // Add entry with name of static table entry index 15
                        // and value "foo".
      "01",             // Duplicate entry with relative index 1.
      &input));
  DecodeEncoderStreamData(input);

  // Now there are four entries in the dynamic table.
  // Entry 0: "foo", "bar"
  // Entry 1: "foo", "ZZZ"
  // Entry 2: ":method", "foo"
  // Entry 3: "foo", "ZZZ"

  // Use a Sequence to test that mock methods are called in order.
  Sequence s;

  EXPECT_CALL(handler_, OnHeaderDecoded(Eq("foo"), Eq("bar"))).InSequence(s);
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq("foo"), Eq("ZZZ"))).InSequence(s);
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq(":method"), Eq("foo")))
      .InSequence(s);
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq("foo"), Eq("ZZZ"))).InSequence(s);
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq(":method"), Eq("ZZ"))).InSequence(s);
  EXPECT_CALL(handler_, OnDecodingCompleted()).InSequence(s);
  EXPECT_CALL(decoder_stream_sender_delegate_,
              WriteStreamData(Eq(kHeaderAcknowledgement)))
      .InSequence(s);

  ASSERT_TRUE(absl::HexStringToBytes(
      "0500"  // Required Insert Count 4 and Delta Base 0.
              // Base is 4 + 0 = 4.
      "83"    // Dynamic table entry with relative index 3, absolute index 0.
      "82"    // Dynamic table entry with relative index 2, absolute index 1.
      "81"    // Dynamic table entry with relative index 1, absolute index 2.
      "80"    // Dynamic table entry with relative index 0, absolute index 3.
      "41025a5a",  // Name of entry 1 (relative index) from dynamic table,
                   // with value "ZZ".
      &input));
  DecodeHeaderBlock(input);
  FlushDecoderStream();

  EXPECT_CALL(handler_, OnHeaderDecoded(Eq("foo"), Eq("bar"))).InSequence(s);
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq("foo"), Eq("ZZZ"))).InSequence(s);
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq(":method"), Eq("foo")))
      .InSequence(s);
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq("foo"), Eq("ZZZ"))).InSequence(s);
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq(":method"), Eq("ZZ"))).InSequence(s);
  EXPECT_CALL(handler_, OnDecodingCompleted()).InSequence(s);
  EXPECT_CALL(decoder_stream_sender_delegate_,
              WriteStreamData(Eq(kHeaderAcknowledgement)))
      .InSequence(s);

  ASSERT_TRUE(absl::HexStringToBytes(
      "0502"  // Required Insert Count 4 and Delta Base 2.
              // Base is 4 + 2 = 6.
      "85"    // Dynamic table entry with relative index 5, absolute index 0.
      "84"    // Dynamic table entry with relative index 4, absolute index 1.
      "83"    // Dynamic table entry with relative index 3, absolute index 2.
      "82"    // Dynamic table entry with relative index 2, absolute index 3.
      "43025a5a",  // Name of entry 3 (relative index) from dynamic table,
                   // with value "ZZ".
      &input));
  DecodeHeaderBlock(input);
  FlushDecoderStream();

  EXPECT_CALL(handler_, OnHeaderDecoded(Eq("foo"), Eq("bar"))).InSequence(s);
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq("foo"), Eq("ZZZ"))).InSequence(s);
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq(":method"), Eq("foo")))
      .InSequence(s);
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq("foo"), Eq("ZZZ"))).InSequence(s);
  EXPECT_CALL(handler_, OnHeaderDecoded(Eq(":method"), Eq("ZZ"))).InSequence(s);
  EXPECT_CALL(handler_, OnDecodingCompleted()).InSequence(s);
  EXPECT_CALL(decoder_stream_sender_delegate_,
              WriteStreamData(Eq(kHeaderAcknowledgement)))
      .InSequence(s);

  ASSERT_TRUE(absl::HexStringToBytes(
      "0582"  // Required Insert Count 4 and Delta Base 2 with sign bit set.
              // Base is 4 - 2 - 1 = 1.
      "80"    // Dynamic table entry with relative index 0, absolute index 0.
      "10"    // Dynamic table entry with post-base index 0, absolute index 1.
      "11"    // Dynamic table entry with post-base index 1, absolute index 2.
      "12"    // Dynamic table entry with post-base index 2, absolute index 3.
      "01025a5a",  // Name of entry 1 (post-base index) from dynamic table,
                   // with value "ZZ".
      &input));
  DecodeHeaderBlock(input);
  FlushDecoderStream();
}

TEST_P(QpackDecoderTest, DecreasingDynamicTableCapacityEvictsEntries) {
  std::string input;
  // Set dynamic table capacity to 1024.
  ASSERT_TRUE(absl::HexStringToBytes("3fe107", &input));
  DecodeEncoderStreamData(input);
  // Add literal entry with name "foo" and value "bar".
  ASSERT_TRUE(absl::HexStringToBytes("6294e703626172", &input));
  DecodeEncoderStreamData(input);

  EXPECT_CALL(handler_, OnHeaderDecoded(Eq("foo"), Eq("bar")));
  EXPECT_CALL(handler_, OnDecodingCompleted());
  EXPECT_CALL(decoder_stream_sender_delegate_,
              WriteStreamData(Eq(kHeaderAcknowledgement)));

  ASSERT_TRUE(absl::HexStringToBytes(
      "0200"  // Required Insert Count 1 and Delta Base 0.
              // Base is 1 + 0 = 1.
      "80",   // Dynamic table entry with relative index 0, absolute index 0.
      &input));
  DecodeHeaderBlock(input);

  // Change dynamic table capacity to 32 bytes, smaller than the entry.
  // This must cause the entry to be evicted.
  ASSERT_TRUE(absl::HexStringToBytes("3f01", &input));
  DecodeEncoderStreamData(input);

  EXPECT_CALL(handler_, OnDecodingErrorDetected(
                            QUIC_QPACK_DECOMPRESSION_FAILED,
                            Eq("Dynamic table entry already evicted.")));

  ASSERT_TRUE(absl::HexStringToBytes(
      "0200"  // Required Insert Count 1 and Delta Base 0.
              // Base is 1 + 0 = 1.
      "80",   // Dynamic table entry with relative index 0, absolute index 0.
      &input));
  DecodeHeaderBlock(input);
  FlushDecoderStream();
}

TEST_P(QpackDecoderTest, EncoderStreamErrorEntryTooLarge) {
  std::string input;
  EXPECT_CALL(
      encoder_stream_error_delegate_,
      OnEncoderStreamError(QUIC_QPACK_ENCODER_STREAM_ERROR_INSERTING_LITERAL,
                           Eq("Error inserting literal entry.")));

  // Set dynamic table capacity to 34.
  ASSERT_TRUE(absl::HexStringToBytes("3f03", &input));
  DecodeEncoderStreamData(input);
  // Add literal entry with name "foo" and value "bar", size is 32 + 3 + 3 = 38.
  ASSERT_TRUE(absl::HexStringToBytes("6294e703626172", &input));
  DecodeEncoderStreamData(input);
}

TEST_P(QpackDecoderTest, EncoderStreamErrorInvalidStaticTableEntry) {
  EXPECT_CALL(
      encoder_stream_error_delegate_,
      OnEncoderStreamError(QUIC_QPACK_ENCODER_STREAM_INVALID_STATIC_ENTRY,
                           Eq("Invalid static table entry.")));

  // Address invalid static table entry index 99.
  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("ff2400", &input));
  DecodeEncoderStreamData(input);
}

TEST_P(QpackDecoderTest, EncoderStreamErrorInvalidDynamicTableEntry) {
  EXPECT_CALL(encoder_stream_error_delegate_,
              OnEncoderStreamError(
                  QUIC_QPACK_ENCODER_STREAM_INSERTION_INVALID_RELATIVE_INDEX,
                  Eq("Invalid relative index.")));

  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes(
      "3fe107"          // Set dynamic table capacity to 1024.
      "6294e703626172"  // Add literal entry with name "foo" and value "bar".
      "8100",  // Address dynamic table entry with relative index 1.  Such
               // entry does not exist.  The most recently added and only
               // dynamic table entry has relative index 0.
      &input));
  DecodeEncoderStreamData(input);
}

TEST_P(QpackDecoderTest, EncoderStreamErrorDuplicateInvalidEntry) {
  EXPECT_CALL(encoder_stream_error_delegate_,
              OnEncoderStreamError(
                  QUIC_QPACK_ENCODER_STREAM_DUPLICATE_INVALID_RELATIVE_INDEX,
                  Eq("Invalid relative index.")));

  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes(
      "3fe107"          // Set dynamic table capacity to 1024.
      "6294e703626172"  // Add literal entry with name "foo" and value "bar".
      "01",  // Duplicate dynamic table entry with relative index 1.  Such
             // entry does not exist.  The most recently added and only
             // dynamic table entry has relative index 0.
      &input));
  DecodeEncoderStreamData(input);
}

TEST_P(QpackDecoderTest, EncoderStreamErrorTooLargeInteger) {
  EXPECT_CALL(encoder_stream_error_delegate_,
              OnEncoderStreamError(QUIC_QPACK_ENCODER_STREAM_INTEGER_TOO_LARGE,
                                   Eq("Encoded integer too large.")));

  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("3fffffffffffffffffffff", &input));
  DecodeEncoderStreamData(input);
}

TEST_P(QpackDecoderTest, InvalidDynamicEntryWhenBaseIsZero) {
  EXPECT_CALL(handler_, OnDecodingErrorDetected(QUIC_QPACK_DECOMPRESSION_FAILED,
                                                Eq("Invalid relative index.")));

  std::string input;
  // Set dynamic table capacity to 1024.
  ASSERT_TRUE(absl::HexStringToBytes("3fe107", &input));
  DecodeEncoderStreamData(input);
  // Add literal entry with name "foo" and value "bar".
  ASSERT_TRUE(absl::HexStringToBytes("6294e703626172", &input));
  DecodeEncoderStreamData(input);

  ASSERT_TRUE(absl::HexStringToBytes(
      "0280"  // Required Insert Count is 1.  Base 1 - 1 - 0 = 0 is explicitly
              // permitted by the spec.
      "80",   // However, addressing entry with relative index 0 would point to
              // absolute index -1, which is invalid.
      &input));
  DecodeHeaderBlock(input);
}

TEST_P(QpackDecoderTest, InvalidNegativeBase) {
  EXPECT_CALL(handler_, OnDecodingErrorDetected(QUIC_QPACK_DECOMPRESSION_FAILED,
                                                Eq("Error calculating Base.")));

  // Required Insert Count 1, Delta Base 1 with sign bit set, Base would
  // be 1 - 1 - 1 = -1, but it is not allowed to be negative.
  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("0281", &input));
  DecodeHeaderBlock(input);
}

TEST_P(QpackDecoderTest, InvalidDynamicEntryByRelativeIndex) {
  std::string input;
  // Set dynamic table capacity to 1024.
  ASSERT_TRUE(absl::HexStringToBytes("3fe107", &input));
  DecodeEncoderStreamData(input);
  // Add literal entry with name "foo" and value "bar".
  ASSERT_TRUE(absl::HexStringToBytes("6294e703626172", &input));
  DecodeEncoderStreamData(input);

  EXPECT_CALL(handler_, OnDecodingErrorDetected(QUIC_QPACK_DECOMPRESSION_FAILED,
                                                Eq("Invalid relative index.")));

  ASSERT_TRUE(absl::HexStringToBytes(
      "0200"  // Required Insert Count 1 and Delta Base 0.
              // Base is 1 + 0 = 1.
      "81",   // Indexed Header Field instruction addressing relative index 1.
              // This is absolute index -1, which is invalid.
      &input));
  DecodeHeaderBlock(input);

  EXPECT_CALL(handler_, OnDecodingErrorDetected(QUIC_QPACK_DECOMPRESSION_FAILED,
                                                Eq("Invalid relative index.")));

  ASSERT_TRUE(absl::HexStringToBytes(
      "0200"   // Required Insert Count 1 and Delta Base 0.
               // Base is 1 + 0 = 1.
      "4100",  // Literal Header Field with Name Reference instruction
               // addressing relative index 1.  This is absolute index -1,
               // which is invalid.
      &input));
  DecodeHeaderBlock(input);
}

TEST_P(QpackDecoderTest, EvictedDynamicTableEntry) {
  std::string input;
  // Update dynamic table capacity to 128.
  ASSERT_TRUE(absl::HexStringToBytes("3f61", &input));
  DecodeEncoderStreamData(input);

  // Add literal entry with name "foo" and value "bar", size 32 + 3 + 3 = 38.
  // This fits in the table three times.
  ASSERT_TRUE(absl::HexStringToBytes("6294e703626172", &input));
  DecodeEncoderStreamData(input);
  // Duplicate entry four times.  This evicts the first two instances.
  ASSERT_TRUE(absl::HexStringToBytes("00000000", &input));
  DecodeEncoderStreamData(input);

  EXPECT_CALL(handler_, OnDecodingErrorDetected(
                            QUIC_QPACK_DECOMPRESSION_FAILED,
                            Eq("Dynamic table entry already evicted.")));

  ASSERT_TRUE(absl::HexStringToBytes(
      "0500"  // Required Insert Count 4 and Delta Base 0.
              // Base is 4 + 0 = 4.
      "82",   // Indexed Header Field instruction addressing relative index 2.
              // This is absolute index 1. Such entry does not exist.
      &input));
  DecodeHeaderBlock(input);

  EXPECT_CALL(handler_, OnDecodingErrorDetected(
                            QUIC_QPACK_DECOMPRESSION_FAILED,
                            Eq("Dynamic table entry already evicted.")));

  ASSERT_TRUE(absl::HexStringToBytes(
      "0500"   // Required Insert Count 4 and Delta Base 0.
               // Base is 4 + 0 = 4.
      "4200",  // Literal Header Field with Name Reference instruction
               // addressing relative index 2.  This is absolute index 1. Such
               // entry does not exist.
      &input));
  DecodeHeaderBlock(input);

  EXPECT_CALL(handler_, OnDecodingErrorDetected(
                            QUIC_QPACK_DECOMPRESSION_FAILED,
                            Eq("Dynamic table entry already evicted.")));

  ASSERT_TRUE(absl::HexStringToBytes(
      "0380"  // Required Insert Count 2 and Delta Base 0 with sign bit set.
              // Base is 2 - 0 - 1 = 1
      "10",   // Indexed Header Field instruction addressing dynamic table
              // entry with post-base index 0, absolute index 1.  Such entry
              // does not exist.
      &input));
  DecodeHeaderBlock(input);

  EXPECT_CALL(handler_, OnDecodingErrorDetected(
                            QUIC_QPACK_DECOMPRESSION_FAILED,
                            Eq("Dynamic table entry already evicted.")));

  ASSERT_TRUE(absl::HexStringToBytes(
      "0380"   // Required Insert Count 2 and Delta Base 0 with sign bit set.
               // Base is 2 - 0 - 1 = 1
      "0000",  // Literal Header Field With Name Reference instruction
               // addressing dynamic table entry with post-base index 0,
               // absolute index 1.  Such entry does not exist.
      &input));
  DecodeHeaderBlock(input);
}

TEST_P(QpackDecoderTest, TableCapacityMustNotExceedMaximum) {
  EXPECT_CALL(
      encoder_stream_error_delegate_,
      OnEncoderStreamError(QUIC_QPACK_ENCODER_STREAM_SET_DYNAMIC_TABLE_CAPACITY,
                           Eq("Error updating dynamic table capacity.")));

  // Try to update dynamic table capacity to 2048, which exceeds the maximum.
  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("3fe10f", &input));
  DecodeEncoderStreamData(input);
}

TEST_P(QpackDecoderTest, SetDynamicTableCapacity) {
  // Update dynamic table capacity to 128, which does not exceed the maximum.
  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("3f61", &input));
  DecodeEncoderStreamData(input);
}

TEST_P(QpackDecoderTest, InvalidEncodedRequiredInsertCount) {
  // Maximum dynamic table capacity is 1024.
  // MaxEntries is 1024 / 32 = 32.
  // Required Insert Count is decoded modulo 2 * MaxEntries, that is, modulo 64.
  // A value of 1 cannot be encoded as 65 even though it has the same remainder.
  EXPECT_CALL(handler_, OnDecodingErrorDetected(
                            QUIC_QPACK_DECOMPRESSION_FAILED,
                            Eq("Error decoding Required Insert Count.")));
  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("4100", &input));
  DecodeHeaderBlock(input);
}

// Regression test for https://crbug.com/970218:  Decoder must stop processing
// after a Header Block Prefix with an invalid Encoded Required Insert Count.
TEST_P(QpackDecoderTest, DataAfterInvalidEncodedRequiredInsertCount) {
  EXPECT_CALL(handler_, OnDecodingErrorDetected(
                            QUIC_QPACK_DECOMPRESSION_FAILED,
                            Eq("Error decoding Required Insert Count.")));
  // Header Block Prefix followed by some extra data.
  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("410000", &input));
  DecodeHeaderBlock(input);
}

TEST_P(QpackDecoderTest, WrappedRequiredInsertCount) {
  std::string input;
  // Maximum dynamic table capacity is 1024.
  // MaxEntries is 1024 / 32 = 32.

  // Set dynamic table capacity to 1024.
  ASSERT_TRUE(absl::HexStringToBytes("3fe107", &input));
  DecodeEncoderStreamData(input);
  // Add literal entry with name "foo" and a 600 byte long value.  This will fit
  // in the dynamic table once but not twice.
  ASSERT_TRUE(
      absl::HexStringToBytes("6294e7"   // Name "foo".
                             "7fd903",  // Value length 600.
                             &input));
  DecodeEncoderStreamData(input);

  std::string header_value(600, 'Z');
  DecodeEncoderStreamData(header_value);

  // Duplicate most recent entry 200 times.
  DecodeEncoderStreamData(std::string(200, '\x00'));

  // Now there is only one entry in the dynamic table, with absolute index 200.

  EXPECT_CALL(handler_, OnHeaderDecoded(Eq("foo"), Eq(header_value)));
  EXPECT_CALL(handler_, OnDecodingCompleted());
  EXPECT_CALL(decoder_stream_sender_delegate_,
              WriteStreamData(Eq(kHeaderAcknowledgement)));

  // Send header block with Required Insert Count = 201.
  ASSERT_TRUE(absl::HexStringToBytes(
      "0a00"  // Encoded Required Insert Count 10, Required Insert Count 201,
              // Delta Base 0, Base 201.
      "80",   // Emit dynamic table entry with relative index 0.
      &input));
  DecodeHeaderBlock(input);
  FlushDecoderStream();
}

TEST_P(QpackDecoderTest, NonZeroRequiredInsertCountButNoDynamicEntries) {
  std::string input;
  // Set dynamic table capacity to 1024.
  ASSERT_TRUE(absl::HexStringToBytes("3fe107", &input));
  DecodeEncoderStreamData(input);
  // Add literal entry with name "foo" and value "bar".
  ASSERT_TRUE(absl::HexStringToBytes("6294e703626172", &input));
  DecodeEncoderStreamData(input);

  EXPECT_CALL(handler_, OnHeaderDecoded(Eq(":method"), Eq("GET")));
  EXPECT_CALL
```