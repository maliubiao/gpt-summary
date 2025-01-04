Response:
The user wants a summary of the functionality of the provided C++ code. They are particularly interested in:
1. The general purpose of the code.
2. Any relationship to JavaScript functionality (likely in a web browser context).
3. Logical deductions with example inputs and outputs.
4. Common user/programming errors related to the code.
5. How a user's actions might lead to this code being executed (debugging context).

This is the first part of a two-part request, so the current focus should be on summarizing the overall functionality of the code within this part.

**Plan:**
1. Identify the core class being tested: `HpackDecoderTest`.
2. Recognize that this is a unit test file for the `HpackDecoder` class.
3. Determine the main purpose of `HpackDecoder`: decoding HPACK encoded header blocks.
4. Note the use of a mock listener (`MockHpackDecoderListener`) to verify correct decoding behavior.
5. Summarize the key methods in `HpackDecoderTest` like `DecodeBlock` and the verification methods (`VerifyEntry`, `VerifyDynamicTableContents`).
6. Highlight the test cases which demonstrate decoding of various HPACK blocks, including examples from the RFC.
```
功能归纳：
```

这个C++源代码文件 `hpack_decoder_test.cc` 是 Chromium 网络栈中 QUIC 协议的 HPACK 解码器 (`HpackDecoder`) 的单元测试文件。它的主要功能是：

1. **测试 `HpackDecoder` 类的正确性**:  通过一系列的测试用例，验证 `HpackDecoder` 能够按照 HPACK 规范正确地解码 HPACK 编码的 HTTP/2 头部数据块。

2. **模拟 HPACK 解码过程**: 测试用例构造不同的 HPACK 编码数据，然后使用 `HpackDecoder` 进行解码，并断言解码的结果是否符合预期。

3. **验证解码后的头部信息**: 使用 `HpackDecoderListener` 接口监听解码事件，并捕获解码出的头部名称和值，然后与预期的头部信息进行比较。

4. **测试动态表操作**: 验证解码器在处理 HPACK 编码时，对动态表的更新和查找是否正确，包括添加新的头部、根据索引查找头部、以及在表大小限制下的头部驱逐行为。

5. **测试不同的 HPACK 特性**:  覆盖了 HPACK 规范中的各种编码方式，例如索引头部、字面头部（带索引或不带索引）、Huffman 编码等。

6. **模拟分片解码**:  通过 `fragment_the_hpack_block_` 变量控制是否将 HPACK 数据块分片解码，以测试解码器处理分片数据的能力。

7. **错误处理测试**:  虽然这段代码主要关注正确解码，但也包含了对错误处理的机制，例如当解码过程中发生错误时，会调用 `OnHeaderErrorDetected` 回调函数。

简而言之，这个文件是用来确保 `HpackDecoder` 能够可靠且正确地将 HPACK 编码的 HTTP/2 头部数据转换为可理解的头部键值对。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/hpack/decoder/hpack_decoder_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/http2/hpack/decoder/hpack_decoder.h"

// Tests of HpackDecoder.

#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "quiche/http2/decoder/decode_buffer.h"
#include "quiche/http2/hpack/decoder/hpack_decoder_listener.h"
#include "quiche/http2/hpack/decoder/hpack_decoder_state.h"
#include "quiche/http2/hpack/decoder/hpack_decoder_tables.h"
#include "quiche/http2/hpack/http2_hpack_constants.h"
#include "quiche/http2/http2_constants.h"
#include "quiche/http2/test_tools/hpack_block_builder.h"
#include "quiche/http2/test_tools/hpack_example.h"
#include "quiche/http2/test_tools/http2_random.h"
#include "quiche/http2/test_tools/random_util.h"
#include "quiche/http2/test_tools/verify_macros.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"

using ::testing::AssertionResult;
using ::testing::AssertionSuccess;
using ::testing::ElementsAreArray;
using ::testing::Eq;

namespace http2 {
namespace test {
class HpackDecoderStatePeer {
 public:
  static HpackDecoderTables* GetDecoderTables(HpackDecoderState* state) {
    return &state->decoder_tables_;
  }
  static void set_listener(HpackDecoderState* state,
                           HpackDecoderListener* listener) {
    state->listener_ = listener;
  }
};
class HpackDecoderPeer {
 public:
  static HpackDecoderState* GetDecoderState(HpackDecoder* decoder) {
    return &decoder->decoder_state_;
  }
  static HpackDecoderTables* GetDecoderTables(HpackDecoder* decoder) {
    return HpackDecoderStatePeer::GetDecoderTables(GetDecoderState(decoder));
  }
};

namespace {

typedef std::pair<std::string, std::string> HpackHeaderEntry;
typedef std::vector<HpackHeaderEntry> HpackHeaderEntries;

// TODO(jamessynge): Create a ...test_utils.h file with the mock listener
// and with VerifyDynamicTableContents.
class MockHpackDecoderListener : public HpackDecoderListener {
 public:
  MOCK_METHOD(void, OnHeaderListStart, (), (override));
  MOCK_METHOD(void, OnHeader, (absl::string_view name, absl::string_view value),
              (override));
  MOCK_METHOD(void, OnHeaderListEnd, (), (override));
  MOCK_METHOD(void, OnHeaderErrorDetected, (absl::string_view error_message),
              (override));
};

class HpackDecoderTest : public quiche::test::QuicheTestWithParam<bool>,
                         public HpackDecoderListener {
 protected:
  // Note that we initialize the random number generator with the same seed
  // for each individual test, therefore the order in which the tests are
  // executed does not effect the sequence produced by the RNG within any
  // one test.
  HpackDecoderTest() : decoder_(this, 4096) {
    fragment_the_hpack_block_ = GetParam();
  }
  ~HpackDecoderTest() override = default;

  void OnHeaderListStart() override {
    ASSERT_FALSE(saw_start_);
    ASSERT_FALSE(saw_end_);
    saw_start_ = true;
    header_entries_.clear();
  }

  // Called for each header name-value pair that is decoded, in the order they
  // appear in the HPACK block. Multiple values for a given key will be emitted
  // as multiple calls to OnHeader.
  void OnHeader(absl::string_view name, absl::string_view value) override {
    ASSERT_TRUE(saw_start_);
    ASSERT_FALSE(saw_end_);
    header_entries_.emplace_back(name, value);
  }

  // OnHeaderBlockEnd is called after successfully decoding an HPACK block. Will
  // only be called once per block, even if it extends into CONTINUATION frames.
  // A callback method which notifies when the parser finishes handling a
  // header block (i.e. the containing frame has the END_STREAM flag set).
  // Also indicates the total number of bytes in this block.
  void OnHeaderListEnd() override {
    ASSERT_TRUE(saw_start_);
    ASSERT_FALSE(saw_end_);
    ASSERT_TRUE(error_messages_.empty());
    saw_end_ = true;
  }

  // OnHeaderErrorDetected is called if an error is detected while decoding.
  // error_message may be used in a GOAWAY frame as the Opaque Data.
  void OnHeaderErrorDetected(absl::string_view error_message) override {
    ASSERT_TRUE(saw_start_);
    error_messages_.push_back(std::string(error_message));
    // No further callbacks should be made at this point, so replace 'this' as
    // the listener with mock_listener_, which is a strict mock, so will
    // generate an error for any calls.
    HpackDecoderStatePeer::set_listener(
        HpackDecoderPeer::GetDecoderState(&decoder_), &mock_listener_);
  }

  AssertionResult DecodeBlock(absl::string_view block) {
    QUICHE_VLOG(1) << "HpackDecoderTest::DecodeBlock";

    HTTP2_VERIFY_FALSE(decoder_.DetectError());
    HTTP2_VERIFY_TRUE(error_messages_.empty());
    HTTP2_VERIFY_FALSE(saw_start_);
    HTTP2_VERIFY_FALSE(saw_end_);
    header_entries_.clear();

    HTTP2_VERIFY_FALSE(decoder_.DetectError());
    HTTP2_VERIFY_TRUE(decoder_.StartDecodingBlock());
    HTTP2_VERIFY_FALSE(decoder_.DetectError());

    if (fragment_the_hpack_block_) {
      // See note in ctor regarding RNG.
      while (!block.empty()) {
        size_t fragment_size = random_.RandomSizeSkewedLow(block.size());
        DecodeBuffer db(block.substr(0, fragment_size));
        HTTP2_VERIFY_TRUE(decoder_.DecodeFragment(&db));
        HTTP2_VERIFY_EQ(0u, db.Remaining());
        block.remove_prefix(fragment_size);
      }
    } else {
      DecodeBuffer db(block);
      HTTP2_VERIFY_TRUE(decoder_.DecodeFragment(&db));
      HTTP2_VERIFY_EQ(0u, db.Remaining());
    }
    HTTP2_VERIFY_FALSE(decoder_.DetectError());

    HTTP2_VERIFY_TRUE(decoder_.EndDecodingBlock());
    if (saw_end_) {
      HTTP2_VERIFY_FALSE(decoder_.DetectError());
      HTTP2_VERIFY_TRUE(error_messages_.empty());
    } else {
      HTTP2_VERIFY_TRUE(decoder_.DetectError());
      HTTP2_VERIFY_FALSE(error_messages_.empty());
    }

    saw_start_ = saw_end_ = false;
    return AssertionSuccess();
  }

  const HpackDecoderTables& GetDecoderTables() {
    return *HpackDecoderPeer::GetDecoderTables(&decoder_);
  }
  const HpackStringPair* Lookup(size_t index) {
    return GetDecoderTables().Lookup(index);
  }
  size_t current_header_table_size() {
    return GetDecoderTables().current_header_table_size();
  }
  size_t header_table_size_limit() {
    return GetDecoderTables().header_table_size_limit();
  }
  void set_header_table_size_limit(size_t size) {
    HpackDecoderPeer::GetDecoderTables(&decoder_)->DynamicTableSizeUpdate(size);
  }

  // dynamic_index is one-based, because that is the way RFC 7541 shows it.
  AssertionResult VerifyEntry(size_t dynamic_index, const char* name,
                              const char* value) {
    const HpackStringPair* entry =
        Lookup(dynamic_index + kFirstDynamicTableIndex - 1);
    HTTP2_VERIFY_NE(entry, nullptr);
    HTTP2_VERIFY_EQ(entry->name, name);
    HTTP2_VERIFY_EQ(entry->value, value);
    return AssertionSuccess();
  }
  AssertionResult VerifyNoEntry(size_t dynamic_index) {
    const HpackStringPair* entry =
        Lookup(dynamic_index + kFirstDynamicTableIndex - 1);
    HTTP2_VERIFY_EQ(entry, nullptr);
    return AssertionSuccess();
  }
  AssertionResult VerifyDynamicTableContents(
      const std::vector<std::pair<const char*, const char*>>& entries) {
    size_t index = 1;
    for (const auto& entry : entries) {
      HTTP2_VERIFY_SUCCESS(VerifyEntry(index, entry.first, entry.second));
      ++index;
    }
    HTTP2_VERIFY_SUCCESS(VerifyNoEntry(index));
    return AssertionSuccess();
  }

  Http2Random random_;
  HpackDecoder decoder_;
  testing::StrictMock<MockHpackDecoderListener> mock_listener_;
  HpackHeaderEntries header_entries_;
  std::vector<std::string> error_messages_;
  bool fragment_the_hpack_block_;
  bool saw_start_ = false;
  bool saw_end_ = false;
};
INSTANTIATE_TEST_SUITE_P(AllWays, HpackDecoderTest, ::testing::Bool());

// Test based on RFC 7541, section C.3: Request Examples without Huffman Coding.
// This section shows several consecutive header lists, corresponding to HTTP
// requests, on the same connection.
// http://httpwg.org/specs/rfc7541.html#rfc.section.C.3
TEST_P(HpackDecoderTest, C3_RequestExamples) {
  // C.3.1 First Request
  std::string hpack_block = HpackExampleToStringOrDie(R"(
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
  )");
  EXPECT_TRUE(DecodeBlock(hpack_block));
  ASSERT_THAT(header_entries_,
              ElementsAreArray({
                  HpackHeaderEntry{":method", "GET"},
                  HpackHeaderEntry{":scheme", "http"},
                  HpackHeaderEntry{":path", "/"},
                  HpackHeaderEntry{":authority", "www.example.com"},
              }));

  // Dynamic Table (after decoding):
  //
  //   [  1] (s =  57) :authority: www.example.com
  //         Table size:  57
  ASSERT_TRUE(VerifyDynamicTableContents({{":authority", "www.example.com"}}));
  ASSERT_EQ(57u, current_header_table_size());

  // C.3.2 Second Request
  hpack_block = HpackExampleToStringOrDie(R"(
      82                                      | == Indexed - Add ==
                                              |   idx = 2
                                              | -> :method: GET
      86                                      | == Indexed - Add ==
                                              |   idx = 6
                                              | -> :scheme: http
      84                                      | == Indexed - Add ==
                                              |   idx = 4
                                              | -> :path: /
      be                                      | == Indexed - Add ==
                                              |   idx = 62
                                              | -> :authority:
                                              |   www.example.com
      58                                      | == Literal indexed ==
                                              |   Indexed name (idx = 24)
                                              |     cache-control
      08                                      |   Literal value (len = 8)
      6e6f 2d63 6163 6865                     | no-cache
                                              | -> cache-control: no-cache
  )");
  EXPECT_TRUE(DecodeBlock(hpack_block));
  ASSERT_THAT(header_entries_,
              ElementsAreArray({
                  HpackHeaderEntry{":method", "GET"},
                  HpackHeaderEntry{":scheme", "http"},
                  HpackHeaderEntry{":path", "/"},
                  HpackHeaderEntry{":authority", "www.example.com"},
                  HpackHeaderEntry{"cache-control", "no-cache"},
              }));

  // Dynamic Table (after decoding):
  //
  //   [  1] (s =  53) cache-control: no-cache
  //   [  2] (s =  57) :authority: www.example.com
  //         Table size: 110
  ASSERT_TRUE(VerifyDynamicTableContents(
      {{"cache-control", "no-cache"}, {":authority", "www.example.com"}}));
  ASSERT_EQ(110u, current_header_table_size());

  // C.3.2 Third Request
  hpack_block = HpackExampleToStringOrDie(R"(
      82                                      | == Indexed - Add ==
                                              |   idx = 2
                                              | -> :method: GET
      87                                      | == Indexed - Add ==
                                              |   idx = 7
                                              | -> :scheme: https
      85                                      | == Indexed - Add ==
                                              |   idx = 5
                                              | -> :path: /index.html
      bf                                      | == Indexed - Add ==
                                              |   idx = 63
                                              | -> :authority:
                                              |   www.example.com
      40                                      | == Literal indexed ==
      0a                                      |   Literal name (len = 10)
      6375 7374 6f6d 2d6b 6579                | custom-key
      0c                                      |   Literal value (len = 12)
      6375 7374 6f6d 2d76 616c 7565           | custom-value
                                              | -> custom-key:
                                              |   custom-value
  )");
  EXPECT_TRUE(DecodeBlock(hpack_block));
  ASSERT_THAT(header_entries_,
              ElementsAreArray({
                  HpackHeaderEntry{":method", "GET"},
                  HpackHeaderEntry{":scheme", "https"},
                  HpackHeaderEntry{":path", "/index.html"},
                  HpackHeaderEntry{":authority", "www.example.com"},
                  HpackHeaderEntry{"custom-key", "custom-value"},
              }));

  // Dynamic Table (after decoding):
  //
  //   [  1] (s =  54) custom-key: custom-value
  //   [  2] (s =  53) cache-control: no-cache
  //   [  3] (s =  57) :authority: www.example.com
  //         Table size: 164
  ASSERT_TRUE(VerifyDynamicTableContents({{"custom-key", "custom-value"},
                                          {"cache-control", "no-cache"},
                                          {":authority", "www.example.com"}}));
  ASSERT_EQ(164u, current_header_table_size());
}

// Test based on RFC 7541, section C.4 Request Examples with Huffman Coding.
// This section shows the same examples as the previous section but uses
// Huffman encoding for the literal values.
// http://httpwg.org/specs/rfc7541.html#rfc.section.C.4
TEST_P(HpackDecoderTest, C4_RequestExamplesWithHuffmanEncoding) {
  // C.4.1 First Request
  std::string hpack_block = HpackExampleToStringOrDie(R"(
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
      8c                                      |   Literal value (len = 12)
                                              |     Huffman encoded:
      f1e3 c2e5 f23a 6ba0 ab90 f4ff           | .....:k.....
                                              |     Decoded:
                                              | www.example.com
                                              | -> :authority:
                                              |   www.example.com
  )");
  EXPECT_TRUE(DecodeBlock(hpack_block));
  ASSERT_THAT(header_entries_,
              ElementsAreArray({
                  HpackHeaderEntry{":method", "GET"},
                  HpackHeaderEntry{":scheme", "http"},
                  HpackHeaderEntry{":path", "/"},
                  HpackHeaderEntry{":authority", "www.example.com"},
              }));

  // Dynamic Table (after decoding):
  //
  //   [  1] (s =  57) :authority: www.example.com
  //         Table size:  57
  ASSERT_TRUE(VerifyDynamicTableContents({{":authority", "www.example.com"}}));
  ASSERT_EQ(57u, current_header_table_size());

  // C.4.2 Second Request
  hpack_block = HpackExampleToStringOrDie(R"(
      82                                      | == Indexed - Add ==
                                              |   idx = 2
                                              | -> :method: GET
      86                                      | == Indexed - Add ==
                                              |   idx = 6
                                              | -> :scheme: http
      84                                      | == Indexed - Add ==
                                              |   idx = 4
                                              | -> :path: /
      be                                      | == Indexed - Add ==
                                              |   idx = 62
                                              | -> :authority:
                                              |   www.example.com
      58                                      | == Literal indexed ==
                                              |   Indexed name (idx = 24)
                                              |     cache-control
      86                                      |   Literal value (len = 6)
                                              |     Huffman encoded:
      a8eb 1064 9cbf                          | ...d..
                                              |     Decoded:
                                              | no-cache
                                              | -> cache-control: no-cache
  )");
  EXPECT_TRUE(DecodeBlock(hpack_block));
  ASSERT_THAT(header_entries_,
              ElementsAreArray({
                  HpackHeaderEntry{":method", "GET"},
                  HpackHeaderEntry{":scheme", "http"},
                  HpackHeaderEntry{":path", "/"},
                  HpackHeaderEntry{":authority", "www.example.com"},
                  HpackHeaderEntry{"cache-control", "no-cache"},
              }));

  // Dynamic Table (after decoding):
  //
  //   [  1] (s =  53) cache-control: no-cache
  //   [  2] (s =  57) :authority: www.example.com
  //         Table size: 110
  ASSERT_TRUE(VerifyDynamicTableContents(
      {{"cache-control", "no-cache"}, {":authority", "www.example.com"}}));
  ASSERT_EQ(110u, current_header_table_size());

  // C.4.2 Third Request
  hpack_block = HpackExampleToStringOrDie(R"(
    82                                      | == Indexed - Add ==
                                            |   idx = 2
                                            | -> :method: GET
    87                                      | == Indexed - Add ==
                                            |   idx = 7
                                            | -> :scheme: https
    85                                      | == Indexed - Add ==
                                            |   idx = 5
                                            | -> :path: /index.html
    bf                                      | == Indexed - Add ==
                                            |   idx = 63
                                            | -> :authority:
                                            |   www.example.com
    40                                      | == Literal indexed ==
    88                                      |   Literal name (len = 8)
                                            |     Huffman encoded:
    25a8 49e9 5ba9 7d7f                     | %.I.[.}.
                                            |     Decoded:
                                            | custom-key
    89                                      |   Literal value (len = 9)
                                            |     Huffman encoded:
    25a8 49e9 5bb8 e8b4 bf                  | %.I.[....
                                            |     Decoded:
                                            | custom-value
                                            | -> custom-key:
                                            |   custom-value
  )");
  EXPECT_TRUE(DecodeBlock(hpack_block));
  ASSERT_THAT(header_entries_,
              ElementsAreArray({
                  HpackHeaderEntry{":method", "GET"},
                  HpackHeaderEntry{":scheme", "https"},
                  HpackHeaderEntry{":path", "/index.html"},
                  HpackHeaderEntry{":authority", "www.example.com"},
                  HpackHeaderEntry{"custom-key", "custom-value"},
              }));

  // Dynamic Table (after decoding):
  //
  //   [  1] (s =  54) custom-key: custom-value
  //   [  2] (s =  53) cache-control: no-cache
  //   [  3] (s =  57) :authority: www.example.com
  //         Table size: 164
  ASSERT_TRUE(VerifyDynamicTableContents({{"custom-key", "custom-value"},
                                          {"cache-control", "no-cache"},
                                          {":authority", "www.example.com"}}));
  ASSERT_EQ(164u, current_header_table_size());
}

// Test based on RFC 7541, section C.5: Response Examples without Huffman
// Coding. This section shows several consecutive header lists, corresponding
// to HTTP responses, on the same connection. The HTTP/2 setting parameter
// SETTINGS_HEADER_TABLE_SIZE is set to the value of 256 octets, causing
// some evictions to occur.
// http://httpwg.org/specs/rfc7541.html#rfc.section.C.5
TEST_P(HpackDecoderTest, C5_ResponseExamples) {
  set_header_table_size_limit(256);

  // C.5.1 First Response
  //
  // Header list to encode:
  //
  //   :status: 302
  //   cache-control: private
  //   date: Mon, 21 Oct 2013 20:13:21 GMT
  //   location: https://www.example.com

  std::string hpack_block = HpackExampleToStringOrDie(R"(
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
  )");
  EXPECT_TRUE(DecodeBlock(hpack_block));
  ASSERT_THAT(header_entries_,
              ElementsAreArray({
                  HpackHeaderEntry{":status", "302"},
                  HpackHeaderEntry{"cache-control", "private"},
                  HpackHeaderEntry{"date", "Mon, 21 Oct 2013 20:13:21 GMT"},
                  HpackHeaderEntry{"location", "https://www.example.com"},
              }));

  // Dynamic Table (after decoding):
  //
  //   [  1] (s =  63) location: https://www.example.com
  //   [  2] (s =  65) date: Mon, 21 Oct 2013 20:13:21 GMT
  //   [  3] (s =  52) cache-control: private
  //   [  4] (s =  42) :status: 302
  //         Table size: 222
  ASSERT_TRUE(
      VerifyDynamicTableContents({{"location", "https://www.example.com"},
                                  {"date", "Mon, 21 Oct 2013 20:13:21 GMT"},
                                  {"cache-control", "private"},
                                  {":status", "302"}}));
  ASSERT_EQ(222u, current_header_table_size());

  // C.5.2 Second Response
  //
  // The (":status", "302") header field is evicted from the dynamic table to
  // free space to allow adding the (":status", "307") header field.
  //
  // Header list to encode:
  //
  //   :status: 307
  //   cache-control: private
  //   date: Mon, 21 Oct 2013 20:13:21 GMT
  //   location: https://www.example.com

  hpack_block = HpackExampleToStringOrDie(R"(
      48                                      | == Literal indexed ==
                                              |   Indexed name (idx = 8)
                                              |     :status
      03                                      |   Literal value (len = 3)
      3330 37                                 | 307
                                              | - evict: :status: 302
                                              | -> :status: 307
      c1                                      | == Indexed - Add ==
                                              |   idx = 65
                                              | -> cache-control: private
      c0                                      | == Indexed - Add ==
                                              |   idx = 64
                                              | -> date: Mon, 21 Oct 2013
                                              |   20:13:21 GMT
      bf                                      | == Indexed - Add ==
                                              |   idx = 63
                                              | -> location:
                                              |   https://www.example.com
  )");
  EXPECT_TRUE(DecodeBlock(hpack_block));
  ASSERT_THAT(header_entries_,
              ElementsAreArray({
                  HpackHeaderEntry{":status", "307"},
                  HpackHeaderEntry{"cache-control", "private"},
                  HpackHeaderEntry{"date", "Mon, 21 Oct 2013 20:13:21 GMT"},
                  HpackHeaderEntry{"location", "https://www.example.com"},
              }));

  // Dynamic Table (after decoding):
  //
  //   [  1] (s =  42) :status: 307
  //   [  2] (s =  63) location: https://www.example.com
  //   [  3] (s =  65) date: Mon, 21 Oct 2013 20:13:21 GMT
  //   [  4] (s =  52) cache-control: private
  //         Table size: 222

  ASSERT_TRUE(
      VerifyDynamicTableContents({{":status", "307"},
                                  {"location", "https://www.example.com"},
                                  {"date", "Mon, 21 Oct 2013 20:13:21 GMT"},
                                  {"cache-control", "private"}}));
  ASSERT_EQ(222u, current_header_table_size());

  // C.5.3 Third Response
  //
  // Several header fields are evicted from the dynamic table during the
  // processing of this header list.
  //
  // Header list to encode:
  //
  //   :status: 200
  //   cache-control: private
  //   date: Mon, 21 Oct 2013 20:13:22 GMT
  //   location: https://www.example.com
  //   content-encoding: gzip
  //   set-cookie: foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1
  hpack_block = HpackExampleToStringOrDie(R"(
      88                                      | == Indexed - Add ==
                                              |   idx = 8
                                              | -> :status: 200
      c1                                      | == Indexed - Add ==
                                              |   idx = 65
                                              | -> cache-control: private
      61                                      | == Literal indexed ==
                                              |   Indexed name (idx = 33)
                                              |     date
      1d                                      |   Literal value (len = 29)
      4d6f 6e2c 2032 3120 4f63 7420 3230 3133 | Mon, 21 Oct 2013
      2032 303a 3133 3a32 3220 474d 54        |  20:13:22 GMT
                                              | - evict: cache-control:
                                              |   private
                                              | -> date: Mon, 21 Oct 2013
                                              |   20:13:22 GMT
      c0                                      | == Indexed - Add ==
                                              |   idx = 64
                                              | -> location:
                                              |   https://www.example.com
      5a                                      | == Literal indexed ==
                                              |   Indexed name (idx = 26)
                                              |     content-encoding
      04                                      |   Literal value (len = 4)
      677a 6970                               | gzip
                                              | - evict: date: Mon, 21 Oct
                                              |    2013 20:13:21 GMT
                                              | -> content-encoding: gzip
      77                                      | == Literal indexed ==
                                              |   Indexed name (idx = 55)
                                              |     set-cookie
      38                                      |   Literal value (len = 56)
      666f 6f3d 4153 444a 4b48 514b 425a 584f | foo=ASDJKHQKBZXO
      5157 454f 5049 5541 5851 5745 4f49 553b | QWEOPIUAXQWEOIU;
      206d 6178 2d61 6765 3d33 3630 303b 2076 |  max-age=3600; v
      6572 7369 6f6e 3d31                     | ersion=1
                                              | - evict: location:
                                              |   https://www.example.com
                                              | - evict: :status: 307
                                              | -> set-cookie: foo=ASDJKHQ
                                              |   KBZXOQWEOPIUAXQWEOIU; ma
                                              |   x-age=3600; version=1
  )");
  EXPECT_TRUE(DecodeBlock(hpack_block));
  ASSERT_THAT(
      header_entries_,
      ElementsAreArray({
          HpackHeaderEntry{":status", "200"},
          HpackHeaderEntry{"cache-control", "private"},
          HpackHeaderEntry{"date", "Mon, 21 Oct 2013 20:13:22 GMT"},
          HpackHeaderEntry{"location", "https://www.example.com"},
          HpackHeaderEntry{"content-encoding", "gzip"},
          HpackHeaderEntry{
              "set-cookie",
              "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"},
      }));

  // Dynamic Table (after decoding):
  //
  //   [  1] (s =  98) set-cookie: foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU;
  //                    max-age=3600; version=1
  //   [  2] (s =  52) content-encoding: gzip
  //   [  3] (s =  65) date: Mon, 21 Oct 2013 20:13:22 GMT
  //         Table size: 215
  ASSERT_TRUE(VerifyDynamicTableContents(
      {{"set-cookie",
        "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"},
       {"content-encoding", "gzip"},
       {"date", "Mon, 21 Oct 2013 20:13:22 GMT"}}));
  ASSERT_EQ(215u, current_header_table_size());
}

// Test based on RFC 7541, section C.6: Response Examples with Huffman Coding.
// This section shows the same examples as the previous section but uses Huffman
// encoding for the literal values. The HTTP/2 setting parameter
// SETTINGS_HEADER_TABLE_SIZE is set to the value of 256 octets, causing some
// evictions to occur. The eviction mechanism uses the length of the decoded
// literal values, so the same evictions occur as in the previous section.
// http://httpwg.org/specs/rfc7541.html#rfc.section.C.6
TEST_P(HpackDecoderTest, C6_ResponseExamplesWithHuffmanEncoding) {
  set_header_table_size_limit(256);

  // C.5
"""


```