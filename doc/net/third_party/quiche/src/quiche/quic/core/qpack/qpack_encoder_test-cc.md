Response:
The user wants a summary of the functionality of the C++ source code file `net/third_party/quiche/src/quiche/quic/core/qpack/qpack_encoder_test.cc`. I need to analyze the test cases defined in this file and deduce the functionalities of the `QpackEncoder` class being tested.

The test cases cover various scenarios:
- Basic encoding of header lists (empty, with empty name/value, simple cases).
- Encoding with static table referencing.
- Handling of decoder stream errors.
- Splitting of header values.
- Handling of insert count increments from the decoder.
- Dynamic table operations (insertion, referencing, capacity changes).
- Handling of blocked streams.
- Draining of the dynamic table.
- Scenarios where encoder stream writes are allowed and disallowed.

I should also look for connections to Javascript functionality and user/programming errors. Since this is a low-level network stack component, the direct connection to Javascript is likely through browser APIs like `fetch` or `XMLHttpRequest`, which use HTTP headers. Common errors might involve incorrect usage of these APIs leading to unexpected header values.
这是位于 Chromium 网络堆栈中 `net/third_party/quiche/src/quiche/quic/core/qpack/qpack_encoder_test.cc` 的源代码文件，它是一个单元测试文件，专门用于测试 `QpackEncoder` 类的功能。以下是该文件主要功能的归纳：

**主要功能:**

该文件通过编写一系列测试用例，来验证 `QpackEncoder` 类的正确性。`QpackEncoder` 的核心功能是将 HTTP 头部列表 (header list) 编码成 QPACK 格式的字节流，以便通过 QUIC 连接发送。这些测试用例覆盖了 `QpackEncoder` 的各种编码场景和行为，包括：

1. **基本编码:** 测试空头部列表、包含空名称或空值的头部、以及简单的键值对的编码。
2. **静态表引用:** 验证当头部可以引用 QPACK 静态表中的条目时，编码器是否能正确生成相应的编码。
3. **动态表操作:** 测试动态表的插入、引用和容量管理，包括：
    *   插入新的头部到动态表。
    *   引用动态表中的头部。
    *   动态调整动态表的大小。
    *   当动态表空间不足时，旧条目的 “排空”(draining) 机制。
4. **霍夫曼编码:**  测试启用和禁用霍夫曼编码时的头部编码。
5. **流阻塞:** 模拟和测试当解码器尚未确认动态表更新时，编码器如何处理流阻塞的情况。
6. **解码器流错误处理:**  测试当从解码器接收到错误指示时，编码器如何响应。
7. **插入计数器管理:**  验证编码器如何处理来自解码器的插入计数器增量 (Insert Count Increment) 指令，包括处理非法值和溢出情况。
8. **头部确认:** 测试编码器如何处理来自解码器的头部确认 (Header Acknowledgement) 指令。
9. **编码器流写入控制:**  测试当编码器流的缓冲区已满时，编码器是否会暂停写入动态表更新指令，并在缓冲区有空间后恢复写入。
10. **分段值编码:** 测试头部值包含空字符时，编码器如何处理分段编码。

**与 Javascript 的关系及举例说明:**

虽然这是一个 C++ 的测试文件，但它测试的 `QpackEncoder` 类直接影响着浏览器中 Javascript 发起的网络请求。

当 Javascript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起 HTTP/3 请求时，浏览器底层会使用 QUIC 协议和 QPACK 头部压缩。`QpackEncoder` 就负责将 Javascript 代码中设置的 HTTP 头部编码成符合 QPACK 规范的字节流，然后通过 QUIC 连接发送给服务器。

**举例说明:**

假设以下 Javascript 代码发起一个请求：

```javascript
fetch('https://example.com', {
  headers: {
    'Content-Type': 'application/json',
    'X-Custom-Header': 'my-value'
  }
});
```

当这个请求发送时，`QpackEncoder` 的功能就是将 `Content-Type: application/json` 和 `X-Custom-Header: my-value` 这两个头部编码成 QPACK 格式的字节。这个测试文件中的用例会覆盖编码器如何处理这些不同类型的头部，例如是否使用静态表、是否插入到动态表等等。

**逻辑推理、假设输入与输出:**

以下举例说明一个测试用例的逻辑推理、假设输入和输出：

**测试用例:** `TEST_P(QpackEncoderTest, Simple)`

**功能测试点:**  测试对简单键值对的头部进行编码。

**假设输入 (quiche::HttpHeaderBlock):**

```
{
  {"foo", "bar"}
}
```

**逻辑推理:**

1. 编码器需要判断 "foo" 和 "bar" 是否可以引用静态表或动态表。
2. 如果霍夫曼编码启用，则对 "foo" 和 "bar" 进行霍夫曼编码。
3. 生成相应的 QPACK 编码，指示这是一个新的头部，并包含编码后的名称和值。

**预期输出 (std::string):**

*   **如果霍夫曼编码启用:**  `00002a94e703626172` (十六进制字符串)
    *   `0000`:  前缀，指示该头部块没有依赖的指令。
    *   `2a`:  字面量头部，名字不引用表，名字长度为 3，最高位为 1 表示使用霍夫曼编码。
    *   `94e7`:  "foo" 的霍夫曼编码。
    *   `03`:  值的长度为 3。
    *   `626172`: "bar" 的 ASCII 编码。
*   **如果霍夫曼编码禁用:** `000023666f6f03626172` (十六进制字符串)
    *   `0000`:  前缀。
    *   `23`:  字面量头部，名字不引用表，名字长度为 3，最高位为 0 表示不使用霍夫曼编码。
    *   `666f6f`:  "foo" 的 ASCII 编码。
    *   `03`:  值的长度为 3。
    *   `626172`: "bar" 的 ASCII 编码。

**用户或编程常见的使用错误及举例说明:**

虽然 `QpackEncoder` 是一个底层组件，用户通常不会直接操作它，但与 HTTP 头部相关的错误最终可能会体现在 QPACK 的编码上。

**举例说明:**

1. **头部名称或值包含非法字符:**  虽然 HTTP 头部对字符有一些限制，但如果 Javascript 代码不小心设置了包含控制字符或其他非法字符的头部，`QpackEncoder` 在编码时可能会遇到问题或者产生不符合规范的输出。
2. **设置过大的头部值:**  如果 Javascript 代码尝试设置一个非常大的头部值，可能会导致编码后的 QPACK 数据过大，超出网络传输的限制。虽然 `QpackEncoder` 本身可能可以处理，但这会导致网络性能问题。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入 URL 或点击链接，发起 HTTP 请求。**
2. **Javascript 代码使用 `fetch` 或 `XMLHttpRequest` API 发起请求。**
3. **浏览器内核的网络栈开始处理该请求，确定使用 HTTP/3 协议。**
4. **在 HTTP/3 连接建立后，需要发送 HTTP 头部。**
5. **`QpackEncoder` 类被调用，将 HTTP 头部列表编码成 QPACK 格式的字节流。**
6. **如果编码过程中出现问题，或者需要验证编码的正确性，开发者可能会查看 `net/third_party/quiche/src/quiche/quic/core/qpack/qpack_encoder_test.cc` 这个测试文件，来了解 `QpackEncoder` 的预期行为和各种编码场景。**

例如，在调试网络请求时，如果怀疑头部压缩有问题，开发者可能会查看这个测试文件，找到类似的头部编码场景，然后对比实际抓包到的 QPACK 数据和测试用例的预期输出，来定位问题。

**第1部分功能归纳:**

总而言之，这个测试文件是用来确保 `QpackEncoder` 能够正确地将各种类型的 HTTP 头部列表编码成符合 QPACK 规范的字节流。它覆盖了编码器的核心功能，包括静态表和动态表的使用、霍夫曼编码、流阻塞处理以及错误处理等。通过这些测试用例，可以验证 `QpackEncoder` 在各种场景下的行为是否符合预期，保证了 Chromium 网络栈在 HTTP/3 协议下头部压缩功能的正确性。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/qpack/qpack_encoder_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "quiche/quic/core/qpack/qpack_encoder.h"

#include <limits>
#include <string>

#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/qpack/qpack_instruction_encoder.h"
#include "quiche/quic/core/qpack/value_splitting_header_list.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/qpack/qpack_encoder_peer.h"
#include "quiche/quic/test_tools/qpack/qpack_test_utils.h"

using ::testing::_;
using ::testing::Eq;
using ::testing::Return;
using ::testing::StrictMock;

namespace quic {
namespace test {
namespace {

// A number larger than kMaxBytesBufferedByStream in
// qpack_encoder_stream_sender.cc.  Returning this value from NumBytesBuffered()
// will instruct QpackEncoder not to generate any instructions for the encoder
// stream.
constexpr uint64_t kTooManyBytesBuffered = 1024 * 1024;

std::string PrintToString(const testing::TestParamInfo<HuffmanEncoding>& info) {
  switch (info.param) {
    case HuffmanEncoding::kEnabled:
      return "HuffmanEnabled";
    case HuffmanEncoding::kDisabled:
      return "HuffmanDisabled";
  }

  QUICHE_NOTREACHED();
  return "InvalidValue";
}

// Mock QpackEncoder::DecoderStreamErrorDelegate implementation.
class MockDecoderStreamErrorDelegate
    : public QpackEncoder::DecoderStreamErrorDelegate {
 public:
  ~MockDecoderStreamErrorDelegate() override = default;

  MOCK_METHOD(void, OnDecoderStreamError,
              (QuicErrorCode error_code, absl::string_view error_message),
              (override));
};

class QpackEncoderTest : public QuicTestWithParam<HuffmanEncoding> {
 protected:
  QpackEncoderTest()
      : huffman_encoding_(GetParam()),
        encoder_(&decoder_stream_error_delegate_, huffman_encoding_,
                 CookieCrumbling::kEnabled),
        encoder_stream_sent_byte_count_(0) {
    encoder_.set_qpack_stream_sender_delegate(&encoder_stream_sender_delegate_);
    encoder_.SetMaximumBlockedStreams(1);
  }

  ~QpackEncoderTest() override = default;

  bool HuffmanEnabled() const {
    return huffman_encoding_ == HuffmanEncoding::kEnabled;
  }

  std::string Encode(const quiche::HttpHeaderBlock& header_list) {
    return encoder_.EncodeHeaderList(/* stream_id = */ 1, header_list,
                                     &encoder_stream_sent_byte_count_);
  }

  const HuffmanEncoding huffman_encoding_;
  StrictMock<MockDecoderStreamErrorDelegate> decoder_stream_error_delegate_;
  StrictMock<MockQpackStreamSenderDelegate> encoder_stream_sender_delegate_;
  QpackEncoder encoder_;
  QuicByteCount encoder_stream_sent_byte_count_;
};

INSTANTIATE_TEST_SUITE_P(HuffmanEncoding, QpackEncoderTest,
                         ::testing::ValuesIn({HuffmanEncoding::kEnabled,
                                              HuffmanEncoding::kDisabled}),
                         PrintToString);

TEST_P(QpackEncoderTest, Empty) {
  EXPECT_CALL(encoder_stream_sender_delegate_, NumBytesBuffered())
      .WillRepeatedly(Return(0));
  quiche::HttpHeaderBlock header_list;
  std::string output = Encode(header_list);

  std::string expected_output;
  ASSERT_TRUE(absl::HexStringToBytes("0000", &expected_output));
  EXPECT_EQ(expected_output, output);
}

TEST_P(QpackEncoderTest, EmptyName) {
  EXPECT_CALL(encoder_stream_sender_delegate_, NumBytesBuffered())
      .WillRepeatedly(Return(0));
  quiche::HttpHeaderBlock header_list;
  header_list[""] = "foo";
  std::string output = Encode(header_list);

  std::string expected_output;
  if (HuffmanEnabled()) {
    ASSERT_TRUE(absl::HexStringToBytes("0000208294e7", &expected_output));
  } else {
    ASSERT_TRUE(absl::HexStringToBytes("00002003666f6f", &expected_output));
  }
  EXPECT_EQ(expected_output, output);
}

TEST_P(QpackEncoderTest, EmptyValue) {
  EXPECT_CALL(encoder_stream_sender_delegate_, NumBytesBuffered())
      .WillRepeatedly(Return(0));
  quiche::HttpHeaderBlock header_list;
  header_list["foo"] = "";
  std::string output = Encode(header_list);

  std::string expected_output;
  if (HuffmanEnabled()) {
    ASSERT_TRUE(absl::HexStringToBytes("00002a94e700", &expected_output));
  } else {
    ASSERT_TRUE(absl::HexStringToBytes("000023666f6f00", &expected_output));
  }
  EXPECT_EQ(expected_output, output);
}

TEST_P(QpackEncoderTest, EmptyNameAndValue) {
  EXPECT_CALL(encoder_stream_sender_delegate_, NumBytesBuffered())
      .WillRepeatedly(Return(0));
  quiche::HttpHeaderBlock header_list;
  header_list[""] = "";
  std::string output = Encode(header_list);

  std::string expected_output;
  ASSERT_TRUE(absl::HexStringToBytes("00002000", &expected_output));
  EXPECT_EQ(expected_output, output);
}

TEST_P(QpackEncoderTest, Simple) {
  EXPECT_CALL(encoder_stream_sender_delegate_, NumBytesBuffered())
      .WillRepeatedly(Return(0));
  quiche::HttpHeaderBlock header_list;
  header_list["foo"] = "bar";
  std::string output = Encode(header_list);

  std::string expected_output;
  if (HuffmanEnabled()) {
    ASSERT_TRUE(absl::HexStringToBytes("00002a94e703626172", &expected_output));
  } else {
    ASSERT_TRUE(
        absl::HexStringToBytes("000023666f6f03626172", &expected_output));
  }
  EXPECT_EQ(expected_output, output);
}

TEST_P(QpackEncoderTest, Multiple) {
  EXPECT_CALL(encoder_stream_sender_delegate_, NumBytesBuffered())
      .WillRepeatedly(Return(0));
  quiche::HttpHeaderBlock header_list;
  header_list["foo"] = "bar";
  // 'Z' would be Huffman encoded to 8 bits, so no Huffman encoding is used.
  header_list["ZZZZZZZ"] = std::string(127, 'Z');
  std::string output = Encode(header_list);

  std::string expected_output_hex;
  if (HuffmanEnabled()) {
    expected_output_hex =
        "0000"             // prefix
        "2a94e703626172";  // foo: bar
  } else {
    expected_output_hex =
        "0000"               // prefix
        "23666f6f03626172";  // foo: bar
  }
  expected_output_hex +=
      "27005a5a5a5a5a5a5a"  // 7 octet long header name, the smallest number
                            // that does not fit on a 3-bit prefix.
      "7f005a5a5a5a5a5a5a"  // 127 octet long header value, the smallest
      "5a5a5a5a5a5a5a5a5a"  // number that does not fit on a 7-bit prefix.
      "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
      "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
      "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
      "5a5a5a5a5a5a5a5a5a";
  std::string expected_output;
  ASSERT_TRUE(absl::HexStringToBytes(expected_output_hex, &expected_output));
  EXPECT_EQ(expected_output, output);
}

TEST_P(QpackEncoderTest, StaticTable) {
  EXPECT_CALL(encoder_stream_sender_delegate_, NumBytesBuffered())
      .WillRepeatedly(Return(0));
  {
    quiche::HttpHeaderBlock header_list;
    header_list[":method"] = "GET";
    header_list["accept-encoding"] = "gzip, deflate, br";
    header_list["location"] = "";

    std::string output = Encode(header_list);
    std::string expected_output;
    ASSERT_TRUE(absl::HexStringToBytes("0000d1dfcc", &expected_output));
    EXPECT_EQ(expected_output, output);
  }
  {
    quiche::HttpHeaderBlock header_list;
    header_list[":method"] = "POST";
    header_list["accept-encoding"] = "compress";
    header_list["location"] = "foo";

    std::string output = Encode(header_list);
    std::string expected_output;
    if (HuffmanEnabled()) {
      ASSERT_TRUE(absl::HexStringToBytes("0000d45f108621e9aec2a11f5c8294e7",
                                         &expected_output));
    } else {
      ASSERT_TRUE(absl::HexStringToBytes(
          "0000d45f1008636f6d70726573735c03666f6f", &expected_output));
    }
    EXPECT_EQ(expected_output, output);
  }
  {
    quiche::HttpHeaderBlock header_list;
    header_list[":method"] = "TRACE";
    header_list["accept-encoding"] = "";

    std::string output = Encode(header_list);
    std::string expected_output;
    ASSERT_TRUE(
        absl::HexStringToBytes("00005f000554524143455f1000", &expected_output));
    EXPECT_EQ(expected_output, output);
  }
}

TEST_P(QpackEncoderTest, DecoderStreamError) {
  EXPECT_CALL(decoder_stream_error_delegate_,
              OnDecoderStreamError(QUIC_QPACK_DECODER_STREAM_INTEGER_TOO_LARGE,
                                   Eq("Encoded integer too large.")));

  QpackEncoder encoder(&decoder_stream_error_delegate_, huffman_encoding_,
                       CookieCrumbling::kEnabled);
  encoder.set_qpack_stream_sender_delegate(&encoder_stream_sender_delegate_);
  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes("ffffffffffffffffffffff", &input));
  encoder.decoder_stream_receiver()->Decode(input);
}

TEST_P(QpackEncoderTest, SplitAlongNullCharacter) {
  EXPECT_CALL(encoder_stream_sender_delegate_, NumBytesBuffered())
      .WillRepeatedly(Return(0));
  quiche::HttpHeaderBlock header_list;
  header_list["foo"] = absl::string_view("bar\0bar\0baz", 11);
  std::string output = Encode(header_list);

  std::string expected_output;
  if (HuffmanEnabled()) {
    ASSERT_TRUE(
        absl::HexStringToBytes("0000"             // prefix
                               "2a94e703626172"   // foo: bar
                               "2a94e703626172"   // foo: bar
                               "2a94e70362617a",  // foo: baz
                               &expected_output));
  } else {
    ASSERT_TRUE(
        absl::HexStringToBytes("0000"               // prefix
                               "23666f6f03626172"   // foo: bar
                               "23666f6f03626172"   // foo: bar
                               "23666f6f0362617a",  // foo: bar
                               &expected_output));
  }
  EXPECT_EQ(expected_output, output);
}

TEST_P(QpackEncoderTest, ZeroInsertCountIncrement) {
  // Encoder receives insert count increment with forbidden value 0.
  EXPECT_CALL(
      decoder_stream_error_delegate_,
      OnDecoderStreamError(QUIC_QPACK_DECODER_STREAM_INVALID_ZERO_INCREMENT,
                           Eq("Invalid increment value 0.")));
  encoder_.OnInsertCountIncrement(0);
}

TEST_P(QpackEncoderTest, TooLargeInsertCountIncrement) {
  // Encoder receives insert count increment with value that increases Known
  // Received Count to a value (one) which is larger than the number of dynamic
  // table insertions sent (zero).
  EXPECT_CALL(
      decoder_stream_error_delegate_,
      OnDecoderStreamError(QUIC_QPACK_DECODER_STREAM_IMPOSSIBLE_INSERT_COUNT,
                           Eq("Increment value 1 raises known received count "
                              "to 1 exceeding inserted entry count 0")));
  encoder_.OnInsertCountIncrement(1);
}

// Regression test for https://crbug.com/1014372.
TEST_P(QpackEncoderTest, InsertCountIncrementOverflow) {
  QpackEncoderHeaderTable* header_table =
      QpackEncoderPeer::header_table(&encoder_);

  // Set dynamic table capacity large enough to hold one entry.
  header_table->SetMaximumDynamicTableCapacity(4096);
  header_table->SetDynamicTableCapacity(4096);
  // Insert one entry into the header table.
  header_table->InsertEntry("foo", "bar");

  // Receive Insert Count Increment instruction with increment value 1.
  encoder_.OnInsertCountIncrement(1);

  // Receive Insert Count Increment instruction that overflows the known
  // received count.  This must result in an error instead of a crash.
  EXPECT_CALL(decoder_stream_error_delegate_,
              OnDecoderStreamError(
                  QUIC_QPACK_DECODER_STREAM_INCREMENT_OVERFLOW,
                  Eq("Insert Count Increment instruction causes overflow.")));
  encoder_.OnInsertCountIncrement(std::numeric_limits<uint64_t>::max());
}

TEST_P(QpackEncoderTest, InvalidHeaderAcknowledgement) {
  // Encoder receives header acknowledgement for a stream on which no header
  // block with dynamic table entries was ever sent.
  EXPECT_CALL(
      decoder_stream_error_delegate_,
      OnDecoderStreamError(QUIC_QPACK_DECODER_STREAM_INCORRECT_ACKNOWLEDGEMENT,
                           Eq("Header Acknowledgement received for stream 0 "
                              "with no outstanding header blocks.")));
  encoder_.OnHeaderAcknowledgement(/* stream_id = */ 0);
}

TEST_P(QpackEncoderTest, DynamicTable) {
  EXPECT_CALL(encoder_stream_sender_delegate_, NumBytesBuffered())
      .WillRepeatedly(Return(0));
  encoder_.SetMaximumBlockedStreams(1);
  encoder_.SetMaximumDynamicTableCapacity(4096);
  encoder_.SetDynamicTableCapacity(4096);

  quiche::HttpHeaderBlock header_list;
  header_list["foo"] = "bar";
  header_list.AppendValueOrAddHeader("foo",
                                     "baz");  // name matches dynamic entry
  header_list["cookie"] = "baz";              // name matches static entry

  // Set Dynamic Table Capacity instruction.
  std::string set_dyanamic_table_capacity;
  ASSERT_TRUE(absl::HexStringToBytes("3fe11f", &set_dyanamic_table_capacity));
  // Insert three entries into the dynamic table.
  std::string insert_entries_hex;
  if (HuffmanEnabled()) {
    insert_entries_hex =
        "62"     // insert without name reference
        "94e7";  // Huffman-encoded literal name "foo"
  } else {
    insert_entries_hex =
        "43"       // insert without name reference
        "666f6f";  // literal name "foo"
  }
  insert_entries_hex +=
      "03626172"   // value "bar"
      "80"         // insert with name reference, dynamic index 0
      "0362617a"   // value "baz"
      "c5"         // insert with name reference, static index 5
      "0362617a";  // value "baz"
  std::string insert_entries;
  ASSERT_TRUE(absl::HexStringToBytes(insert_entries_hex, &insert_entries));
  EXPECT_CALL(encoder_stream_sender_delegate_,
              WriteStreamData(Eq(
                  absl::StrCat(set_dyanamic_table_capacity, insert_entries))));

  std::string expected_output;
  ASSERT_TRUE(absl::HexStringToBytes(
      "0400"     // prefix
      "828180",  // dynamic entries with relative index 0, 1, and 2
      &expected_output));
  EXPECT_EQ(expected_output, Encode(header_list));

  EXPECT_EQ(insert_entries.size(), encoder_stream_sent_byte_count_);
}

// There is no room in the dynamic table after inserting the first entry.
TEST_P(QpackEncoderTest, SmallDynamicTable) {
  EXPECT_CALL(encoder_stream_sender_delegate_, NumBytesBuffered())
      .WillRepeatedly(Return(0));
  encoder_.SetMaximumBlockedStreams(1);
  encoder_.SetMaximumDynamicTableCapacity(QpackEntry::Size("foo", "bar"));
  encoder_.SetDynamicTableCapacity(QpackEntry::Size("foo", "bar"));

  quiche::HttpHeaderBlock header_list;
  header_list["foo"] = "bar";
  header_list.AppendValueOrAddHeader("foo",
                                     "baz");  // name matches dynamic entry
  header_list["cookie"] = "baz";              // name matches static entry
  header_list["bar"] = "baz";                 // no match

  // Set Dynamic Table Capacity instruction.
  std::string set_dyanamic_table_capacity;
  ASSERT_TRUE(absl::HexStringToBytes("3f07", &set_dyanamic_table_capacity));
  // Insert one entry into the dynamic table.
  std::string insert_entry;
  if (HuffmanEnabled()) {
    ASSERT_TRUE(
        absl::HexStringToBytes("62"    // insert without name reference
                               "94e7"  // Huffman-encoded literal name "foo"
                               "03626172",  // value "bar"
                               &insert_entry));
  } else {
    ASSERT_TRUE(
        absl::HexStringToBytes("43"         // insert without name reference
                               "666f6f"     // literal name "foo"
                               "03626172",  // value "bar"
                               &insert_entry));
  }
  EXPECT_CALL(encoder_stream_sender_delegate_,
              WriteStreamData(
                  Eq(absl::StrCat(set_dyanamic_table_capacity, insert_entry))));

  std::string expected_output;
  ASSERT_TRUE(
      absl::HexStringToBytes("0200"       // prefix
                             "80"         // dynamic entry 0
                             "40"         // reference to dynamic entry 0 name
                             "0362617a"   // with literal value "baz"
                             "55"         // reference to static entry 5 name
                             "0362617a"   // with literal value "baz"
                             "23626172"   // literal name "bar"
                             "0362617a",  // with literal value "baz"
                             &expected_output));
  EXPECT_EQ(expected_output, Encode(header_list));

  EXPECT_EQ(insert_entry.size(), encoder_stream_sent_byte_count_);
}

TEST_P(QpackEncoderTest, BlockedStream) {
  EXPECT_CALL(encoder_stream_sender_delegate_, NumBytesBuffered())
      .WillRepeatedly(Return(0));
  encoder_.SetMaximumBlockedStreams(1);
  encoder_.SetMaximumDynamicTableCapacity(4096);
  encoder_.SetDynamicTableCapacity(4096);

  quiche::HttpHeaderBlock header_list1;
  header_list1["foo"] = "bar";

  // Set Dynamic Table Capacity instruction.
  std::string set_dyanamic_table_capacity;
  ASSERT_TRUE(absl::HexStringToBytes("3fe11f", &set_dyanamic_table_capacity));
  // Insert one entry into the dynamic table.
  std::string insert_entry1;
  if (HuffmanEnabled()) {
    ASSERT_TRUE(
        absl::HexStringToBytes("62"    // insert without name reference
                               "94e7"  // Huffman-encoded literal name "foo"
                               "03626172",  // value "bar"
                               &insert_entry1));
  } else {
    ASSERT_TRUE(
        absl::HexStringToBytes("43"         // insert without name reference
                               "666f6f"     // literal name "foo"
                               "03626172",  // value "bar"
                               &insert_entry1));
  }
  EXPECT_CALL(encoder_stream_sender_delegate_,
              WriteStreamData(Eq(
                  absl::StrCat(set_dyanamic_table_capacity, insert_entry1))));

  std::string expected_output;
  ASSERT_TRUE(
      absl::HexStringToBytes("0200"  // prefix
                             "80",   // dynamic entry 0
                             &expected_output));
  EXPECT_EQ(expected_output,
            encoder_.EncodeHeaderList(/* stream_id = */ 1, header_list1,
                                      &encoder_stream_sent_byte_count_));
  EXPECT_EQ(insert_entry1.size(), encoder_stream_sent_byte_count_);

  // Stream 1 is blocked.  Stream 2 is not allowed to block.
  quiche::HttpHeaderBlock header_list2;
  header_list2["foo"] = "bar";  // name and value match dynamic entry
  header_list2.AppendValueOrAddHeader("foo",
                                      "baz");  // name matches dynamic entry
  header_list2["cookie"] = "baz";              // name matches static entry
  header_list2["bar"] = "baz";                 // no match

  std::string entries;
  if (HuffmanEnabled()) {
    ASSERT_TRUE(
        absl::HexStringToBytes("0000"       // prefix
                               "2a94e7"     // literal name "foo"
                               "03626172"   // with literal value "bar"
                               "2a94e7"     // literal name "foo"
                               "0362617a"   // with literal value "baz"
                               "55"         // name of static entry 5
                               "0362617a"   // with literal value "baz"
                               "23626172"   // literal name "bar"
                               "0362617a",  // with literal value "baz"
                               &entries));
  } else {
    ASSERT_TRUE(
        absl::HexStringToBytes("0000"       // prefix
                               "23666f6f"   // literal name "foo"
                               "03626172"   // with literal value "bar"
                               "23666f6f"   // literal name "foo"
                               "0362617a"   // with literal value "baz"
                               "55"         // name of static entry 5
                               "0362617a"   // with literal value "baz"
                               "23626172"   // literal name "bar"
                               "0362617a",  // with literal value "baz"
                               &entries));
  }
  EXPECT_EQ(entries,
            encoder_.EncodeHeaderList(/* stream_id = */ 2, header_list2,
                                      &encoder_stream_sent_byte_count_));
  EXPECT_EQ(0u, encoder_stream_sent_byte_count_);

  // Peer acknowledges receipt of one dynamic table entry.
  // Stream 1 is no longer blocked.
  encoder_.OnInsertCountIncrement(1);

  // Insert three entries into the dynamic table.
  std::string insert_entries;
  ASSERT_TRUE(absl::HexStringToBytes(
      "80"         // insert with name reference, dynamic index 0
      "0362617a"   // value "baz"
      "c5"         // insert with name reference, static index 5
      "0362617a"   // value "baz"
      "43"         // insert without name reference
      "626172"     // name "bar"
      "0362617a",  // value "baz"
      &insert_entries));
  EXPECT_CALL(encoder_stream_sender_delegate_,
              WriteStreamData(Eq(insert_entries)));

  ASSERT_TRUE(
      absl::HexStringToBytes("0500"       // prefix
                             "83828180",  // dynamic entries
                             &expected_output));
  EXPECT_EQ(expected_output,
            encoder_.EncodeHeaderList(/* stream_id = */ 3, header_list2,
                                      &encoder_stream_sent_byte_count_));
  EXPECT_EQ(insert_entries.size(), encoder_stream_sent_byte_count_);

  // Stream 3 is blocked.  Stream 4 is not allowed to block, but it can
  // reference already acknowledged dynamic entry 0.
  std::string expected2;
  if (HuffmanEnabled()) {
    ASSERT_TRUE(
        absl::HexStringToBytes("0200"       // prefix
                               "80"         // dynamic entry 0
                               "2a94e7"     // literal name "foo"
                               "0362617a"   // with literal value "baz"
                               "55"         // name of static entry 5
                               "0362617a"   // with literal value "baz"
                               "23626172"   // literal name "bar"
                               "0362617a",  // with literal value "baz"
                               &expected2));
  } else {
    ASSERT_TRUE(
        absl::HexStringToBytes("0200"       // prefix
                               "80"         // dynamic entry 0
                               "23666f6f"   // literal name "foo"
                               "0362617a"   // with literal value "baz"
                               "55"         // name of static entry 5
                               "0362617a"   // with literal value "baz"
                               "23626172"   // literal name "bar"
                               "0362617a",  // with literal value "baz"
                               &expected2));
  }
  EXPECT_EQ(expected2,
            encoder_.EncodeHeaderList(/* stream_id = */ 4, header_list2,
                                      &encoder_stream_sent_byte_count_));
  EXPECT_EQ(0u, encoder_stream_sent_byte_count_);

  // Peer acknowledges receipt of two more dynamic table entries.
  // Stream 3 is still blocked.
  encoder_.OnInsertCountIncrement(2);

  // Stream 5 is not allowed to block, but it can reference already acknowledged
  // dynamic entries 0, 1, and 2.
  std::string expected3;
  ASSERT_TRUE(
      absl::HexStringToBytes("0400"       // prefix
                             "828180"     // dynamic entries
                             "23626172"   // literal name "bar"
                             "0362617a",  // with literal value "baz"
                             &expected3));
  EXPECT_EQ(expected3,
            encoder_.EncodeHeaderList(/* stream_id = */ 5, header_list2,
                                      &encoder_stream_sent_byte_count_));
  EXPECT_EQ(0u, encoder_stream_sent_byte_count_);

  // Peer acknowledges decoding header block on stream 3.
  // Stream 3 is not blocked any longer.
  encoder_.OnHeaderAcknowledgement(3);

  std::string expected4;
  ASSERT_TRUE(
      absl::HexStringToBytes("0500"       // prefix
                             "83828180",  // dynamic entries
                             &expected4));
  EXPECT_EQ(expected4,
            encoder_.EncodeHeaderList(/* stream_id = */ 6, header_list2,
                                      &encoder_stream_sent_byte_count_));
  EXPECT_EQ(0u, encoder_stream_sent_byte_count_);
}

TEST_P(QpackEncoderTest, Draining) {
  EXPECT_CALL(encoder_stream_sender_delegate_, NumBytesBuffered())
      .WillRepeatedly(Return(0));
  quiche::HttpHeaderBlock header_list1;
  header_list1["one"] = "foo";
  header_list1["two"] = "foo";
  header_list1["three"] = "foo";
  header_list1["four"] = "foo";
  header_list1["five"] = "foo";
  header_list1["six"] = "foo";
  header_list1["seven"] = "foo";
  header_list1["eight"] = "foo";
  header_list1["nine"] = "foo";
  header_list1["ten"] = "foo";

  // Make just enough room in the dynamic table for the header list plus the
  // first entry duplicated.  This will ensure that the oldest entries are
  // draining.
  uint64_t maximum_dynamic_table_capacity = 0;
  for (const auto& header_field : header_list1) {
    maximum_dynamic_table_capacity +=
        QpackEntry::Size(header_field.first, header_field.second);
  }
  maximum_dynamic_table_capacity += QpackEntry::Size("one", "foo");
  encoder_.SetMaximumDynamicTableCapacity(maximum_dynamic_table_capacity);
  encoder_.SetDynamicTableCapacity(maximum_dynamic_table_capacity);

  // Set Dynamic Table Capacity instruction and insert ten entries into the
  // dynamic table.
  EXPECT_CALL(encoder_stream_sender_delegate_, WriteStreamData(_));

  std::string expected_output;
  ASSERT_TRUE(
      absl::HexStringToBytes("0b00"                   // prefix
                             "89888786858483828180",  // dynamic entries
                             &expected_output));
  EXPECT_EQ(expected_output, Encode(header_list1));

  // Entry is identical to oldest one, which is draining.  It will be
  // duplicated and referenced.
  quiche::HttpHeaderBlock header_list2;
  header_list2["one"] = "foo";

  // Duplicate oldest entry.
  ASSERT_TRUE(absl::HexStringToBytes("09", &expected_output));
  EXPECT_CALL(encoder_stream_sender_delegate_,
              WriteStreamData(Eq(expected_output)));

  ASSERT_TRUE(
      absl::HexStringToBytes("0c00"  // prefix
                             "80",   // most recent dynamic table entry
                             &expected_output));
  EXPECT_EQ(expected_output, Encode(header_list2));

  quiche::HttpHeaderBlock header_list3;
  // Entry is identical to second oldest one, which is draining.  There is no
  // room to duplicate, it will be encoded with string literals.
  header_list3.AppendValueOrAddHeader("two", "foo");
  // Entry has name identical to second oldest one, which is draining.  There is
  // no room to insert new entry, it will be encoded with string literals.
  header_list3.AppendValueOrAddHeader("two", "bar");

  std::string entries =
      "0000"       // prefix
      "2374776f";  // literal name "two"
  if (HuffmanEnabled()) {
    entries += "8294e7";  // literal value "foo"
  } else {
    entries += "03666f6f";  // literal name "foo"
  }
  entries +=
      "2374776f"   // literal name "two"
      "03626172";  // literal value "bar"
  ASSERT_TRUE(absl::HexStringToBytes(entries, &expected_output));
  EXPECT_EQ(expected_output, Encode(header_list3));
}

TEST_P(QpackEncoderTest, DynamicTableCapacityLessThanMaximum) {
  encoder_.SetMaximumDynamicTableCapacity(1024);
  encoder_.SetDynamicTableCapacity(30);

  QpackEncoderHeaderTable* header_table =
      QpackEncoderPeer::header_table(&encoder_);

  EXPECT_EQ(1024u, header_table->maximum_dynamic_table_capacity());
  EXPECT_EQ(30u, header_table->dynamic_table_capacity());
}

TEST_P(QpackEncoderTest, EncoderStreamWritesDisallowedThenAllowed) {
  EXPECT_CALL(encoder_stream_sender_delegate_, NumBytesBuffered())
      .WillRepeatedly(Return(kTooManyBytesBuffered));
  encoder_.SetMaximumBlockedStreams(1);
  encoder_.SetMaximumDynamicTableCapacity(4096);
  encoder_.SetDynamicTableCapacity(4096);

  quiche::HttpHeaderBlock header_list1;
  header_list1["foo"] = "bar";
  header_list1.AppendValueOrAddHeader("foo", "baz");
  header_list1["cookie"] = "baz";  // name matches static entry

  // Encoder is not allowed to write on the encoder stream.
  // No Set Dynamic Table Capacity or Insert instructions are sent.
  // Headers are encoded as string literals.
  std::string entries;
  if (HuffmanEnabled()) {
    ASSERT_TRUE(
        absl::HexStringToBytes("0000"       // prefix
                               "2a94e7"     // literal name "foo"
                               "03626172"   // with literal value "bar"
                               "2a94e7"     // literal name "foo"
                               "0362617a"   // with literal value "baz"
                               "55"         // name of static entry 5
                               "0362617a",  // with literal value "baz"
                               &entries));
  } else {
    ASSERT_TRUE(
        absl::HexStringToBytes("0000"       // prefix
                               "23666f6f"   // literal name "foo"
                               "03626172"   // with literal value "bar"
                               "23666f6f"   // literal name "foo"
                               "0362617a"   // with literal value "baz"
                               "55"         // name of static entry 5
                               "0362617a",  // with literal value "baz"
                               &entries));
  }
  EXPECT_EQ(entries, Encode(header_list1));

  EXPECT_EQ(0u, encoder_stream_sent_byte_count_);

  // If number of bytes buffered by encoder stream goes under the threshold,
  // then QpackEncoder will resume emitting encoder stream instructions.
  ::testing::Mock::VerifyAndClearExpectations(&encoder_stream_sender_delegate_);
  EXPECT_CALL(encoder_stream_sender_delegate_, NumBytesBuffered())
      .WillRepeatedly(Return(0));

  quiche::HttpHeaderBlock header_list2;
  header_list2["foo"] = "bar";
  header_list2.AppendValueOrAddHeader("foo",
                                      "baz");  // name matches dynamic entry
  header_list2["cookie"] = "baz";              // name matches static entry

  // Set Dynamic Table Capacity instruction.
  std::string set_dyanamic_table_capacity;
  ASSERT_TRUE(absl::HexStringToBytes("3fe11f", &set_dyanamic_table_capacity));
  // Insert three entries into the dynamic table.
  std::string insert_entries_hex;
  if (HuffmanEnabled()) {
    insert_entries_hex =
        "62"     // insert without name reference
        "94e7";  // Huffman-encoded literal name "foo"
  } else {
    insert_entries_hex =
        "43"       // insert without name reference
        "666f6f";  // literal name "foo"
  }
  insert_entries_hex +=
      "03626172"   // value "bar"
      "80"         // insert with name reference, dynamic index 0
      "0362617a"   // value "baz"
      "c5"         // insert with name reference, static index 5
      "0362617a";  // value "baz"
  std::string insert_entries;
  ASSERT_TRUE(absl::HexStringToBytes(insert_entries_hex, &insert_entries));
  EXPECT_CALL(encoder_stream_sender_delegate_,
              WriteStreamData(Eq(
                  absl::StrCat(set_dyanamic_table_capacity, insert_entries))));

  std::string expected_output;
  ASSERT_TRUE(absl::HexStringToBytes(
      "0400"     // prefix
      "828180",  // dynamic entries with relative index 0, 1, and 2
      &expected_output));
  EXPECT_EQ(expected_output, Encode(header_list2));

  EXPECT_EQ(insert_entries.size(), encoder_stream_sent_byte_count_);
}

TEST_P(QpackEncoderTest, EncoderStreamWritesAllowedThenDisallowed) {
  EXPECT_CALL(encoder_stream_sender_delegate_, NumBytesBuffered())
      .WillRepeatedly(Return(0));
  encoder_.SetMaximumBlockedStreams(1);
  encoder_.SetMaximumDynamicTableCapacity(4096);
  encoder_.SetDynamicTableCapacity(4096);

  quiche::HttpHeaderBlock header_list1;
  header_list1["foo"] = "bar";
  header_list1.AppendValueOrAddHeader("foo",
                                      "baz");  // name matches dynamic entry
  header_list1["cookie"] = "baz";              // name matches static entry

  // Set Dynamic Table Capacity instruction.
  std::string set_dyanamic_table_capacity;
  ASSERT_TRUE(absl::HexStringToBytes("3fe11f", &set_dyanamic_table_capacity));
  // Insert three entries into the dynamic ta
```