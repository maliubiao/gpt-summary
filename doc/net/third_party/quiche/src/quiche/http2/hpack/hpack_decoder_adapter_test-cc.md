Response:
The user wants a summary of the functionality of the C++ source code file `net/third_party/quiche/src/quiche/http2/hpack/hpack_decoder_adapter_test.cc`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The file name strongly suggests that it's a test file for `HpackDecoderAdapter`. The `#include` directives confirm this. The tests likely focus on verifying the correctness and robustness of the `HpackDecoderAdapter` class.

2. **Analyze Included Headers:**  The included headers provide clues about the functionalities being tested:
    * `quiche/http2/hpack/hpack_decoder_adapter.h`: This is the primary class being tested.
    * Various `decoder/` headers (`hpack_decoder.h`, `hpack_decoder_state.h`, `hpack_decoder_tables.h`): Indicate that the adapter interacts with the core HPACK decoding logic.
    * `hpack_constants.h`, `http2_hpack_constants.h`: Suggest testing against defined HPACK constants and rules.
    * `hpack_encoder.h`:  Indicates that encoding is sometimes used in the tests (e.g., for generating test inputs).
    * `quiche/http2/core/recording_headers_handler.h`: Implies that the tests check the output of the decoder by recording the decoded headers.
    * Test-related headers (`quiche/common/platform/api/quiche_test.h`): Confirm this is a unit test file.
    * Utility headers (`<string>`, `<vector>`, etc.): Standard C++ utilities used in the tests.

3. **Examine the Test Class Structure:** The `HpackDecoderAdapterTest` class inherits from `quiche::test::QuicheTestWithParam<bool>`. This means it's a parameterized test suite, with the boolean parameter likely controlling some aspect of the test setup (in this case, random splitting of input).

4. **Identify Helper Classes/Methods:**  Notice the `HpackDecoderStatePeer`, `HpackDecoderPeer`, and `HpackDecoderAdapterPeer` classes. These are friend classes or classes providing access to internal members for testing purposes. The `HpackEncoderPeer` suggests testing interactions with the encoder.

5. **Analyze Key Test Methods:** Look at the prominent methods within the test class:
    * `SetUp()`:  Initializes the test, including setting the parameter.
    * `HandleControlFrameHeadersStart()`, `HandleControlFrameHeadersData()`, `HandleControlFrameHeadersComplete()`: These mimic the lifecycle of processing HTTP/2 HEADERS frames and are central to testing the adapter's integration with the framing layer.
    * `DecodeHeaderBlock()`: A crucial method that encapsulates the process of feeding data to the decoder and checking the results. The parameter `check_decoded_size` hints at a test for header size accounting.
    * `EncodeAndDecodeDynamicTableSizeUpdates()`: Specifically tests dynamic table size updates.
    * `decoded_block()`: Accesses the recorded decoded headers.
    * `SizeOfHeaders()`: Calculates the size of headers, likely used for verifying decoded size.
    * `DecodeBlockExpectingSuccess()`: A convenience method for asserting successful decoding.
    * `expectEntry()`: Verifies specific entries in the decoder's dynamic table.
    * `MakeHeaderBlock()`: Creates test header blocks.

6. **Infer Functionality from Test Names:**  The names of the individual test cases (e.g., `ApplyHeaderTableSizeSetting`, `AddHeaderDataWithHandleControlFrameHeadersData`, `NameTooLong`, `IndexedHeaderStatic`) directly reveal the specific aspects of `HpackDecoderAdapter` being tested. Look for patterns like handling different HPACK encoding types (indexed, literal), error conditions (truncated input, invalid indexes), and dynamic table management.

7. **Connect to JavaScript (If Applicable):**  Think about how HPACK decoding relates to web browsers and JavaScript. Browsers use HPACK to decode HTTP/2 headers received from servers. JavaScript running in the browser interacts with these headers through APIs like `fetch` or `XMLHttpRequest`. The browser's network stack (which includes code like this) handles the low-level decoding.

8. **Consider User/Programming Errors:**  Think about what could go wrong when using an HPACK decoder. Common errors include: providing incomplete or corrupted encoded data, exceeding size limits, or incorrectly managing the decoder's state. The tests often simulate these scenarios.

9. **Relate to Debugging:** Imagine a scenario where a user reports an issue with HTTP/2 headers. How would a developer use this test file for debugging?  They might:
    * Run the existing tests to see if the core decoding logic is working correctly.
    * Create new test cases that reproduce the specific issue reported by the user.
    * Step through the `HpackDecoderAdapter` code while running the tests to understand the flow and identify the bug.

10. **Synthesize and Structure the Summary:** Organize the findings into logical sections: core functionality, relationship to JavaScript, example with assumptions, common usage errors, debugging context, and a final summary for part 1. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus only on the positive test cases.
* **Correction:** Realize that testing error conditions (like `NameTooLong`, `TruncatedIndex`) is equally important.
* **Initial thought:** Only list the test names.
* **Correction:** Explain the *purpose* of these tests and the underlying functionality they verify.
* **Initial thought:**  Assume a deep understanding of HPACK.
* **Correction:**  Provide a brief explanation of HPACK's role in HTTP/2 for broader understanding.
* **Initial thought:**  Omit the JavaScript connection because it's not directly used in the C++ code.
* **Correction:** Include the JavaScript connection to illustrate the relevance of this code to web development.
```cpp
// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/http2/hpack/hpack_decoder_adapter.h"

// Tests of HpackDecoderAdapter.

#include <stdint.h>

#include <cstddef>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/base/macros.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "quiche/http2/core/recording_headers_handler.h"
#include "quiche/http2/hpack/decoder/hpack_decoder.h"
#include "quiche/http2/hpack/decoder/hpack_decoder_state.h"
#include "quiche/http2/hpack/decoder/hpack_decoder_tables.h"
#include "quiche/http2/hpack/hpack_constants.h"
#include "quiche/http2/hpack/hpack_encoder.h"
#include "quiche/http2/hpack/hpack_output_stream.h"
#include "quiche/http2/hpack/http2_hpack_constants.h"
#include "quiche/http2/test_tools/hpack_block_builder.h"
#include "quiche/http2/test_tools/http2_random.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_text_utils.h"

using ::http2::HpackEntryType;
using ::http2::HpackStringPair;
using ::http2::test::HpackBlockBuilder;
using ::http2::test::HpackDecoderPeer;
using ::testing::ElementsAre;
using ::testing::Pair;

namespace http2 {
namespace test {

class HpackDecoderStatePeer {
 public:
  static HpackDecoderTables* GetDecoderTables(HpackDecoderState* state) {
    return &state->decoder_tables_;
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

}  // namespace test
}  // namespace http2

namespace spdy {
namespace test {

class HpackDecoderAdapterPeer {
 public:
  explicit HpackDecoderAdapterPeer(HpackDecoderAdapter* decoder)
      : decoder_(decoder) {}

  void HandleHeaderRepresentation(const std::string& name,
                                  const std::string& value) {
    decoder_->listener_adapter_.OnHeader(name, value);
  }

  http2::HpackDecoderTables* GetDecoderTables() {
    return http2::test::HpackDecoderPeer::GetDecoderTables(&decoder_->hpack_decoder_);
  }

  const HpackStringPair* GetTableEntry(uint32_t index) {
    return GetDecoderTables()->Lookup(index);
  }

  size_t current_header_table_size() {
    return GetDecoderTables()->current_header_table_size();
  }

  size_t header_table_size_limit() {
    return GetDecoderTables()->header_table_size_limit();
  }

  void set_header_table_size_limit(size_t size) {
    return GetDecoderTables()->DynamicTableSizeUpdate(size);
  }

 private:
  HpackDecoderAdapter* decoder_;
};

class HpackEncoderPeer {
 public:
  static void CookieToCrumbs(const HpackEncoder::Representation& cookie,
                             HpackEncoder::Representations* crumbs_out) {
    HpackEncoder::CookieToCrumbs(cookie, crumbs_out);
  }
};

namespace {

const bool kNoCheckDecodedSize = false;
const char* kCookieKey = "cookie";

class HpackDecoderAdapterTest : public quiche::test::QuicheTestWithParam<bool> {
 protected:
  HpackDecoderAdapterTest() : decoder_(), decoder_peer_(&decoder_) {}

  void SetUp() override { randomly_split_input_buffer_ = GetParam(); }

  void HandleControlFrameHeadersStart() {
    bytes_passed_in_ = 0;
    decoder_.HandleControlFrameHeadersStart(&handler_);
  }

  bool HandleControlFrameHeadersData(absl::string_view str) {
    QUICHE_VLOG(3) << "HandleControlFrameHeadersData:\n"
                   << quiche::QuicheTextUtils::HexDump(str);
    bytes_passed_in_ += str.size();
    return decoder_.HandleControlFrameHeadersData(str.data(), str.size());
  }

  bool HandleControlFrameHeadersComplete() {
    bool rc = decoder_.HandleControlFrameHeadersComplete();
    return rc;
  }

  bool DecodeHeaderBlock(absl::string_view str,
                         bool check_decoded_size = true) {
    // Don't call this again if HandleControlFrameHeadersData failed previously.
    EXPECT_FALSE(decode_has_failed_);
    HandleControlFrameHeadersStart();
    if (randomly_split_input_buffer_) {
      do {
        // Decode some fragment of the remaining bytes.
        size_t bytes = str.size();
        if (!str.empty()) {
          bytes = random_.Uniform(str.size()) + 1;
        }
        EXPECT_LE(bytes, str.size());
        if (!HandleControlFrameHeadersData(str.substr(0, bytes))) {
          decode_has_failed_ = true;
          return false;
        }
        str.remove_prefix(bytes);
      } while (!str.empty());
    } else if (!HandleControlFrameHeadersData(str)) {
      decode_has_failed_ = true;
      return false;
    }
    if (!HandleControlFrameHeadersComplete()) {
      decode_has_failed_ = true;
      return false;
    }
    EXPECT_EQ(handler_.compressed_header_bytes(), bytes_passed_in_);
    if (check_decoded_size) {
      EXPECT_EQ(handler_.uncompressed_header_bytes(),
                SizeOfHeaders(decoded_block()));
    }
    return true;
  }

  bool EncodeAndDecodeDynamicTableSizeUpdates(size_t first, size_t second) {
    HpackBlockBuilder hbb;
    hbb.AppendDynamicTableSizeUpdate(first);
    if (second != first) {
      hbb.AppendDynamicTableSizeUpdate(second);
    }
    return DecodeHeaderBlock(hbb.buffer());
  }

  const quiche::HttpHeaderBlock& decoded_block() const {
    return handler_.decoded_block();
  }

  static size_t SizeOfHeaders(const quiche::HttpHeaderBlock& headers) {
    size_t size = 0;
    for (const auto& kv : headers) {
      if (kv.first == kCookieKey) {
        HpackEncoder::Representations crumbs;
        HpackEncoderPeer::CookieToCrumbs(kv, &crumbs);
        for (const auto& crumb : crumbs) {
          size += crumb.first.size() + crumb.second.size();
        }
      } else {
        size += kv.first.size() + kv.second.size();
      }
    }
    return size;
  }

  const quiche::HttpHeaderBlock& DecodeBlockExpectingSuccess(
      absl::string_view str) {
    EXPECT_TRUE(DecodeHeaderBlock(str));
    return decoded_block();
  }

  void expectEntry(size_t index, size_t size, const std::string& name,
                   const std::string& value) {
    const HpackStringPair* entry = decoder_peer_.GetTableEntry(index);
    EXPECT_EQ(name, entry->name) << "index " << index;
    EXPECT_EQ(value, entry->value);
    EXPECT_EQ(size, entry->size());
  }

  quiche::HttpHeaderBlock MakeHeaderBlock(
      const std::vector<std::pair<std::string, std::string>>& headers) {
    quiche::HttpHeaderBlock result;
    for (const auto& kv : headers) {
      result.AppendValueOrAddHeader(kv.first, kv.second);
    }
    return result;
  }

  http2::test::Http2Random random_;
  HpackDecoderAdapter decoder_;
  test::HpackDecoderAdapterPeer decoder_peer_;
  RecordingHeadersHandler handler_;
  const quiche::HttpHeaderBlock dummy_block_;
  bool randomly_split_input_buffer_;
  bool decode_has_failed_ = false;
  size_t bytes_passed_in_;
};

INSTANTIATE_TEST_SUITE_P(NoHandler, HpackDecoderAdapterTest, ::testing::Bool());

INSTANTIATE_TEST_SUITE_P(WithHandler, HpackDecoderAdapterTest,
                         ::testing::Bool());

TEST_P(HpackDecoderAdapterTest, ApplyHeaderTableSizeSetting) {
  EXPECT_EQ(4096u, decoder_.GetCurrentHeaderTableSizeSetting());
  decoder_.ApplyHeaderTableSizeSetting(12 * 1024);
  EXPECT_EQ(12288u, decoder_.GetCurrentHeaderTableSizeSetting());
}

TEST_P(HpackDecoderAdapterTest,
       AddHeaderDataWithHandleControlFrameHeadersData) {
  // The hpack decode buffer size is limited in size. This test verifies that
  // adding encoded data under that limit is accepted, and data that exceeds the
  // limit is rejected.
  HandleControlFrameHeadersStart();
  const size_t kMaxBufferSizeBytes = 50;
  const std::string a_value = std::string(49, 'x');
  decoder_.set_max_decode_buffer_size_bytes(kMaxBufferSizeBytes);
  HpackBlockBuilder hbb;
  hbb.AppendLiteralNameAndValue(HpackEntryType::kNeverIndexedLiteralHeader,
                                false, "a", false, a_value);
  const std::string& s = hbb.buffer();
  EXPECT_GT(s.size(), kMaxBufferSizeBytes);

  // Any one in input buffer must not exceed kMaxBufferSizeBytes.
  EXPECT_TRUE(HandleControlFrameHeadersData(s.substr(0, s.size() / 2)));
  EXPECT_TRUE(HandleControlFrameHeadersData(s.substr(s.size() / 2)));

  EXPECT_FALSE(HandleControlFrameHeadersData(s));
  quiche::HttpHeaderBlock expected_block = MakeHeaderBlock({{"a", a_value}});
  EXPECT_EQ(expected_block, decoded_block());
}

TEST_P(HpackDecoderAdapterTest, NameTooLong) {
  // Verify that a name longer than the allowed size generates an error.
  const size_t kMaxBufferSizeBytes = 50;
  const std::string name = std::string(2 * kMaxBufferSizeBytes, 'x');
  const std::string value = "abc";

  decoder_.set_max_decode_buffer_size_bytes(kMaxBufferSizeBytes);

  HpackBlockBuilder hbb;
  hbb.AppendLiteralNameAndValue(HpackEntryType::kNeverIndexedLiteralHeader,
                                false, name, false, value);

  const size_t fragment_size = (3 * kMaxBufferSizeBytes) / 2;
  const std::string fragment = hbb.buffer().substr(0, fragment_size);

  HandleControlFrameHeadersStart();
  EXPECT_FALSE(HandleControlFrameHeadersData(fragment));
}

TEST_P(HpackDecoderAdapterTest, HeaderTooLongToBuffer) {
  // Verify that a header longer than the allowed size generates an error if
  // it isn't all in one input buffer.
  const std::string name = "some-key";
  const std::string value = "some-value";
  const size_t kMaxBufferSizeBytes = name.size() + value.size() - 2;
  decoder_.set_max_decode_buffer_size_bytes(kMaxBufferSizeBytes);

  HpackBlockBuilder hbb;
  hbb.AppendLiteralNameAndValue(HpackEntryType::kNeverIndexedLiteralHeader,
                                false, name, false, value);
  const size_t fragment_size = hbb.size() - 1;
  const std::string fragment = hbb.buffer().substr(0, fragment_size);

  HandleControlFrameHeadersStart();
  EXPECT_FALSE(HandleControlFrameHeadersData(fragment));
}

// Verify that a header block that exceeds the maximum length is rejected.
TEST_P(HpackDecoderAdapterTest, HeaderBlockTooLong) {
  const std::string name = "some-key";
  const std::string value = "some-value";
  const size_t kMaxBufferSizeBytes = 1024;

  HpackBlockBuilder hbb;
  hbb.AppendLiteralNameAndValue(HpackEntryType::kIndexedLiteralHeader, false,
                                name, false, value);
  while (hbb.size() < kMaxBufferSizeBytes) {
    hbb.AppendLiteralNameAndValue(HpackEntryType::kIndexedLiteralHeader, false,
                                  "", false, "");
  }
  // With no limit on the maximum header block size, the decoder handles the
  // entire block successfully.
  HandleControlFrameHeadersStart();
  EXPECT_TRUE(HandleControlFrameHeadersData(hbb.buffer()));
  EXPECT_TRUE(HandleControlFrameHeadersComplete());

  // When a total byte limit is imposed, the decoder bails before the end of the
  // block.
  decoder_.set_max_header_block_bytes(kMaxBufferSizeBytes);
  HandleControlFrameHeadersStart();
  EXPECT_FALSE(HandleControlFrameHeadersData(hbb.buffer()));
}

// Decode with incomplete data in buffer.
TEST_P(HpackDecoderAdapterTest, DecodeWithIncompleteData) {
  HandleControlFrameHeadersStart();

  // No need to wait for more data.
  EXPECT_TRUE(HandleControlFrameHeadersData("\x82\x85\x82"));
  std::vector<std::pair<std::string, std::string>> expected_headers = {
      {":method", "GET"}, {":path", "/index.html"}, {":method", "GET"}};

  quiche::HttpHeaderBlock expected_block1 = MakeHeaderBlock(expected_headers);
  EXPECT_EQ(expected_block1, decoded_block());

  // Full and partial headers, won't add partial to the headers.
  EXPECT_TRUE(
      HandleControlFrameHeadersData("\x40\x03goo"
                                    "\x03gar\xbe\x40\x04spam"));
  expected_headers.push_back({"goo", "gar"});
  expected_headers.push_back({"goo", "gar"});

  quiche::HttpHeaderBlock expected_block2 = MakeHeaderBlock(expected_headers);
  EXPECT_EQ(expected_block2, decoded_block());

  // Add the needed data.
  EXPECT_TRUE(HandleControlFrameHeadersData("\x04gggs"));

  EXPECT_TRUE(HandleControlFrameHeadersComplete());

  expected_headers.push_back({"spam", "gggs"});

  quiche::HttpHeaderBlock expected_block3 = MakeHeaderBlock(expected_headers);
  EXPECT_EQ(expected_block3, decoded_block());
}

TEST_P(HpackDecoderAdapterTest, HandleHeaderRepresentation) {
  // Make sure the decoder is properly initialized.
  HandleControlFrameHeadersStart();
  HandleControlFrameHeadersData("");

  // All cookie crumbs are joined.
  decoder_peer_.HandleHeaderRepresentation("cookie", " part 1");
  decoder_peer_.HandleHeaderRepresentation("cookie", "part 2 ");
  decoder_peer_.HandleHeaderRepresentation("cookie", "part3");

  // Already-delimited headers are passed through.
  decoder_peer_.HandleHeaderRepresentation("passed-through",
                                           std::string("foo\0baz", 7));

  // Other headers are joined on \0. Case matters.
  decoder_peer_.HandleHeaderRepresentation("joined", "joined");
  decoder_peer_.HandleHeaderRepresentation("joineD", "value 1");
  decoder_peer_.HandleHeaderRepresentation("joineD", "value 2");

  // Empty headers remain empty.
  decoder_peer_.HandleHeaderRepresentation("empty", "");

  // Joined empty headers work as expected.
  decoder_peer_.HandleHeaderRepresentation("empty-joined", "");
  decoder_peer_.HandleHeaderRepresentation("empty-joined", "foo");
  decoder_peer_.HandleHeaderRepresentation("empty-joined", "");
  decoder_peer_.HandleHeaderRepresentation("empty-joined", "");

  // Non-contiguous cookie crumb.
  decoder_peer_.HandleHeaderRepresentation("cookie", " fin!");

  // Finish and emit all headers.
  decoder_.HandleControlFrameHeadersComplete();

  // Resulting decoded headers are in the same order as the inputs.
  EXPECT_THAT(
      decoded_block(),
      ElementsAre(
          Pair("cookie", " part 1; part 2 ; part3;  fin!"),
          Pair("passed-through", absl::string_view("foo\0baz", 7)),
          Pair("joined", absl::string_view("joined\0value 1\0value 2", 22)),
          Pair("empty", ""),
          Pair("empty-joined", absl::string_view("\0foo\0\0", 6))));
}

// Decoding indexed static table field should work.
TEST_P(HpackDecoderAdapterTest, IndexedHeaderStatic) {
  // Reference static table entries #2 and #5.
  const quiche::HttpHeaderBlock& header_set1 =
      DecodeBlockExpectingSuccess("\x82\x85");
  quiche::HttpHeaderBlock expected_header_set1;
  expected_header_set1[":method"] = "GET";
  expected_header_set1[":path"] = "/index.html";
  EXPECT_EQ(expected_header_set1, header_set1);

  // Reference static table entry #2.
  const quiche::HttpHeaderBlock& header_set2 =
      DecodeBlockExpectingSuccess("\x82");
  quiche::HttpHeaderBlock expected_header_set2;
  expected_header_set2[":method"] = "GET";
  EXPECT_EQ(expected_header_set2, header_set2);
}

TEST_P(HpackDecoderAdapterTest, IndexedHeaderDynamic) {
  // First header block: add an entry to header table.
  const quiche::HttpHeaderBlock& header_set1 = DecodeBlockExpectingSuccess(
      "\x40\x03"
      "foo"
      "\x03"
      "bar");
  quiche::HttpHeaderBlock expected_header_set1;
  expected_header_set1["foo"] = "bar";
  EXPECT_EQ(expected_header_set1, header_set1);

  // Second header block: add another entry to header table.
  const quiche::HttpHeaderBlock& header_set2 = DecodeBlockExpectingSuccess(
      "\xbe\x40\x04"
      "spam"
      "\x04"
      "eggs");
  quiche::HttpHeaderBlock expected_header_set2;
  expected_header_set2["foo"] = "bar";
  expected_header_set2["spam"] = "eggs";
  EXPECT_EQ(expected_header_set2, header_set2);

  // Third header block: refer to most recently added entry.
  const quiche::HttpHeaderBlock& header_set3 =
      DecodeBlockExpectingSuccess("\xbe");
  quiche::HttpHeaderBlock expected_header_set3;
  expected_header_set3["spam"] = "eggs";
  EXPECT_EQ(expected_header_set3, header_set3);
}

// Test a too-large indexed header.
TEST_P(HpackDecoderAdapterTest, InvalidIndexedHeader) {
  // High-bit set, and a prefix of one more than the number of static entries.
  EXPECT_FALSE(DecodeHeaderBlock("\xbe"));
}

TEST_P(HpackDecoderAdapterTest, ContextUpdateMaximumSize) {
  EXPECT_EQ(kDefaultHeaderTableSizeSetting,
            decoder_peer_.header_table_size_limit());
  std::string input;
  {
    // Maximum-size update with size 126. Succeeds.
    HpackOutputStream output_stream;
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(126);

    input = output_stream.TakeString();
    EXPECT_TRUE(DecodeHeaderBlock(input));
    EXPECT_EQ(126u, decoder_peer_.header_table_size_limit());
  }
  {
    // Maximum-size update with kDefaultHeaderTableSizeSetting. Succeeds.
    HpackOutputStream output_stream;
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(kDefaultHeaderTableSizeSetting);

    input = output_stream.TakeString();
    EXPECT_TRUE(DecodeHeaderBlock(input));
    EXPECT_EQ(kDefaultHeaderTableSizeSetting,
              decoder_peer_.header_table_size_limit());
  }
  {
    // Maximum-size update with kDefaultHeaderTableSizeSetting + 1. Fails.
    HpackOutputStream output_stream;
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(kDefaultHeaderTableSizeSetting + 1);

    input = output_stream.TakeString();
    EXPECT_FALSE(DecodeHeaderBlock(input));
    EXPECT_EQ(kDefaultHeaderTableSizeSetting,
              decoder_peer_.header_table_size_limit());
  }
}

// Two HeaderTableSizeUpdates may appear at the beginning of the block
TEST_P(HpackDecoderAdapterTest, TwoTableSizeUpdates) {
  std::string input;
  {
    // Should accept two table size updates, update to second one
    HpackOutputStream output_stream;
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(0);
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(122);

    input = output_stream.TakeString();
    EXPECT_TRUE(DecodeHeaderBlock(input));
    EXPECT_EQ(122u, decoder_peer_.header_table_size_limit());
  }
}

// Three HeaderTableSizeUpdates should result in an error
TEST_P(HpackDecoderAdapterTest, ThreeTableSizeUpdatesError) {
  std::string input;
  {
    // Should reject three table size updates, update to second one
    HpackOutputStream output_stream;
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(5);
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(10);
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(15);

    input = output_stream.TakeString();

    EXPECT_FALSE(DecodeHeaderBlock(input));
    EXPECT_EQ(10u, decoder_peer_.header_table_size_limit());
  }
}

// HeaderTableSizeUpdates may only appear at the beginning of the block
// Any other updates should result in an error
TEST_P(HpackDecoderAdapterTest, TableSizeUpdateSecondError) {
  std::string input;
  {
    // Should reject a table size update appearing after a different entry
    // The table size should remain as the default
    HpackOutputStream output_stream;
    output_stream.AppendBytes("\x82\x85");
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(123);

    input = output_stream.TakeString();

    EXPECT_FALSE(DecodeHeaderBlock(input));
    EXPECT_EQ(kDefaultHeaderTableSizeSetting,
              decoder_peer_.header_table_size_limit());
  }
}

// HeaderTableSizeUpdates may only appear at the beginning of the block
// Any other updates should result in an error
TEST_P(HpackDecoderAdapterTest, TableSizeUpdateFirstThirdError) {
  std::string input;
  {
    // Should reject the second table size update
    // if a different entry appears after the first update
    // The table size should update to the first but not the second
    HpackOutputStream output_stream;
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(60);
    output_stream.AppendBytes("\x82\x85");
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(125);

    input = output_stream.TakeString();

    EXPECT_FALSE(DecodeHeaderBlock(input));
    EXPECT_EQ(60u, decoder_peer_.header_table_size_limit());
  }
}

// Decoding two valid encoded literal headers with no indexing should
// work.
TEST_P(HpackDecoderAdapterTest, LiteralHeaderNoIndexing) {
  // First header with indexed name, second header with string literal
  // name.
  const char input[] = "\x04\x0c/sample/path\x00\x06:path2\x0e/sample/path/2";
  const quiche::HttpHeaderBlock& header_set = DecodeBlockExpectingSuccess(
      absl::string_view(input, ABSL_ARRAYSIZE(input) - 1));

  quiche::HttpHeaderBlock expected_header_set;
  expected_header_set[":path"] = "/sample/path";
  expected_header_set[":path2"] = "/sample/path/2";
  EXPECT_EQ(expected_header_set, header_set);
}

// Decoding two valid encoded literal headers with incremental
// indexing and string literal names should work.
TEST_P(HpackDecoderAdapterTest, LiteralHeaderIncrementalIndexing) {
  const char input[] = "\x44\x0c/sample/path\x40\x06:path2\x0e/sample/path/2";
  const quiche::HttpHeaderBlock& header_set = DecodeBlockExpectingSuccess(
      absl::string_view(input, ABSL_ARRAYSIZE(input) - 1));

  quiche::HttpHeaderBlock expected_header_set;
  expected_header_set[":path"] = "/sample/path";
  expected_header_set[":path2"] = "/sample/path/2";
  EXPECT_EQ(expected_header_set, header_set);
}

TEST_P(HpackDecoderAdapterTest, LiteralHeaderWithIndexingInvalidNameIndex) {
  decoder_.ApplyHeaderTableSizeSetting(0);
  EXPECT_TRUE(EncodeAndDecodeDynamicTableSizeUpdates(0, 0));

  // Name is the last static index. Works.
  EXPECT_TRUE(DecodeHeaderBlock(absl::string_view("\x7d\x03ooo")));
  // Name is one beyond the last static index. Fails.
  EXPECT_FALSE(DecodeHeaderBlock(absl::string_view("\x7e\x03ooo")));
}

TEST_P(HpackDecoderAdapterTest, LiteralHeaderNoIndexingInvalidNameIndex) {
  // Name is the last static index. Works.
  EXPECT_TRUE(DecodeHeaderBlock(absl::string_view("\x0f\x2e\x03ooo")));
  // Name is one beyond the last static index. Fails.
  EXPECT_FALSE(DecodeHeaderBlock(absl::string_view("\x0f\x2f\x03ooo")));
}

TEST_P(HpackDecoderAdapterTest, LiteralHeaderNeverIndexedInvalidNameIndex) {
  // Name is the last static index. Works.
  EXPECT_TRUE(DecodeHeaderBlock(absl::string_view("\x1f\x2e\x03ooo")));
  // Name is one beyond the last static index. Fails.
  EXPECT_FALSE(DecodeHeaderBlock(absl::string_view("\x1f\x2f\x03ooo")));
}

TEST_P(HpackDecoderAdapterTest, TruncatedIndex) {
  // Indexed Header, varint for index requires multiple bytes,
  // but only one provided.
  EXPECT_FALSE(DecodeHeaderBlock("\xff"));
}

TEST_P(HpackDecoderAdapterTest, Trunc
### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/hpack/hpack_decoder_adapter_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/http2/hpack/hpack_decoder_adapter.h"

// Tests of HpackDecoderAdapter.

#include <stdint.h>

#include <cstddef>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/base/macros.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "quiche/http2/core/recording_headers_handler.h"
#include "quiche/http2/hpack/decoder/hpack_decoder.h"
#include "quiche/http2/hpack/decoder/hpack_decoder_state.h"
#include "quiche/http2/hpack/decoder/hpack_decoder_tables.h"
#include "quiche/http2/hpack/hpack_constants.h"
#include "quiche/http2/hpack/hpack_encoder.h"
#include "quiche/http2/hpack/hpack_output_stream.h"
#include "quiche/http2/hpack/http2_hpack_constants.h"
#include "quiche/http2/test_tools/hpack_block_builder.h"
#include "quiche/http2/test_tools/http2_random.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_text_utils.h"

using ::http2::HpackEntryType;
using ::http2::HpackStringPair;
using ::http2::test::HpackBlockBuilder;
using ::http2::test::HpackDecoderPeer;
using ::testing::ElementsAre;
using ::testing::Pair;

namespace http2 {
namespace test {

class HpackDecoderStatePeer {
 public:
  static HpackDecoderTables* GetDecoderTables(HpackDecoderState* state) {
    return &state->decoder_tables_;
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

}  // namespace test
}  // namespace http2

namespace spdy {
namespace test {

class HpackDecoderAdapterPeer {
 public:
  explicit HpackDecoderAdapterPeer(HpackDecoderAdapter* decoder)
      : decoder_(decoder) {}

  void HandleHeaderRepresentation(const std::string& name,
                                  const std::string& value) {
    decoder_->listener_adapter_.OnHeader(name, value);
  }

  http2::HpackDecoderTables* GetDecoderTables() {
    return HpackDecoderPeer::GetDecoderTables(&decoder_->hpack_decoder_);
  }

  const HpackStringPair* GetTableEntry(uint32_t index) {
    return GetDecoderTables()->Lookup(index);
  }

  size_t current_header_table_size() {
    return GetDecoderTables()->current_header_table_size();
  }

  size_t header_table_size_limit() {
    return GetDecoderTables()->header_table_size_limit();
  }

  void set_header_table_size_limit(size_t size) {
    return GetDecoderTables()->DynamicTableSizeUpdate(size);
  }

 private:
  HpackDecoderAdapter* decoder_;
};

class HpackEncoderPeer {
 public:
  static void CookieToCrumbs(const HpackEncoder::Representation& cookie,
                             HpackEncoder::Representations* crumbs_out) {
    HpackEncoder::CookieToCrumbs(cookie, crumbs_out);
  }
};

namespace {

const bool kNoCheckDecodedSize = false;
const char* kCookieKey = "cookie";

class HpackDecoderAdapterTest : public quiche::test::QuicheTestWithParam<bool> {
 protected:
  HpackDecoderAdapterTest() : decoder_(), decoder_peer_(&decoder_) {}

  void SetUp() override { randomly_split_input_buffer_ = GetParam(); }

  void HandleControlFrameHeadersStart() {
    bytes_passed_in_ = 0;
    decoder_.HandleControlFrameHeadersStart(&handler_);
  }

  bool HandleControlFrameHeadersData(absl::string_view str) {
    QUICHE_VLOG(3) << "HandleControlFrameHeadersData:\n"
                   << quiche::QuicheTextUtils::HexDump(str);
    bytes_passed_in_ += str.size();
    return decoder_.HandleControlFrameHeadersData(str.data(), str.size());
  }

  bool HandleControlFrameHeadersComplete() {
    bool rc = decoder_.HandleControlFrameHeadersComplete();
    return rc;
  }

  bool DecodeHeaderBlock(absl::string_view str,
                         bool check_decoded_size = true) {
    // Don't call this again if HandleControlFrameHeadersData failed previously.
    EXPECT_FALSE(decode_has_failed_);
    HandleControlFrameHeadersStart();
    if (randomly_split_input_buffer_) {
      do {
        // Decode some fragment of the remaining bytes.
        size_t bytes = str.size();
        if (!str.empty()) {
          bytes = random_.Uniform(str.size()) + 1;
        }
        EXPECT_LE(bytes, str.size());
        if (!HandleControlFrameHeadersData(str.substr(0, bytes))) {
          decode_has_failed_ = true;
          return false;
        }
        str.remove_prefix(bytes);
      } while (!str.empty());
    } else if (!HandleControlFrameHeadersData(str)) {
      decode_has_failed_ = true;
      return false;
    }
    if (!HandleControlFrameHeadersComplete()) {
      decode_has_failed_ = true;
      return false;
    }
    EXPECT_EQ(handler_.compressed_header_bytes(), bytes_passed_in_);
    if (check_decoded_size) {
      EXPECT_EQ(handler_.uncompressed_header_bytes(),
                SizeOfHeaders(decoded_block()));
    }
    return true;
  }

  bool EncodeAndDecodeDynamicTableSizeUpdates(size_t first, size_t second) {
    HpackBlockBuilder hbb;
    hbb.AppendDynamicTableSizeUpdate(first);
    if (second != first) {
      hbb.AppendDynamicTableSizeUpdate(second);
    }
    return DecodeHeaderBlock(hbb.buffer());
  }

  const quiche::HttpHeaderBlock& decoded_block() const {
    return handler_.decoded_block();
  }

  static size_t SizeOfHeaders(const quiche::HttpHeaderBlock& headers) {
    size_t size = 0;
    for (const auto& kv : headers) {
      if (kv.first == kCookieKey) {
        HpackEncoder::Representations crumbs;
        HpackEncoderPeer::CookieToCrumbs(kv, &crumbs);
        for (const auto& crumb : crumbs) {
          size += crumb.first.size() + crumb.second.size();
        }
      } else {
        size += kv.first.size() + kv.second.size();
      }
    }
    return size;
  }

  const quiche::HttpHeaderBlock& DecodeBlockExpectingSuccess(
      absl::string_view str) {
    EXPECT_TRUE(DecodeHeaderBlock(str));
    return decoded_block();
  }

  void expectEntry(size_t index, size_t size, const std::string& name,
                   const std::string& value) {
    const HpackStringPair* entry = decoder_peer_.GetTableEntry(index);
    EXPECT_EQ(name, entry->name) << "index " << index;
    EXPECT_EQ(value, entry->value);
    EXPECT_EQ(size, entry->size());
  }

  quiche::HttpHeaderBlock MakeHeaderBlock(
      const std::vector<std::pair<std::string, std::string>>& headers) {
    quiche::HttpHeaderBlock result;
    for (const auto& kv : headers) {
      result.AppendValueOrAddHeader(kv.first, kv.second);
    }
    return result;
  }

  http2::test::Http2Random random_;
  HpackDecoderAdapter decoder_;
  test::HpackDecoderAdapterPeer decoder_peer_;
  RecordingHeadersHandler handler_;
  const quiche::HttpHeaderBlock dummy_block_;
  bool randomly_split_input_buffer_;
  bool decode_has_failed_ = false;
  size_t bytes_passed_in_;
};

INSTANTIATE_TEST_SUITE_P(NoHandler, HpackDecoderAdapterTest, ::testing::Bool());

INSTANTIATE_TEST_SUITE_P(WithHandler, HpackDecoderAdapterTest,
                         ::testing::Bool());

TEST_P(HpackDecoderAdapterTest, ApplyHeaderTableSizeSetting) {
  EXPECT_EQ(4096u, decoder_.GetCurrentHeaderTableSizeSetting());
  decoder_.ApplyHeaderTableSizeSetting(12 * 1024);
  EXPECT_EQ(12288u, decoder_.GetCurrentHeaderTableSizeSetting());
}

TEST_P(HpackDecoderAdapterTest,
       AddHeaderDataWithHandleControlFrameHeadersData) {
  // The hpack decode buffer size is limited in size. This test verifies that
  // adding encoded data under that limit is accepted, and data that exceeds the
  // limit is rejected.
  HandleControlFrameHeadersStart();
  const size_t kMaxBufferSizeBytes = 50;
  const std::string a_value = std::string(49, 'x');
  decoder_.set_max_decode_buffer_size_bytes(kMaxBufferSizeBytes);
  HpackBlockBuilder hbb;
  hbb.AppendLiteralNameAndValue(HpackEntryType::kNeverIndexedLiteralHeader,
                                false, "a", false, a_value);
  const std::string& s = hbb.buffer();
  EXPECT_GT(s.size(), kMaxBufferSizeBytes);

  // Any one in input buffer must not exceed kMaxBufferSizeBytes.
  EXPECT_TRUE(HandleControlFrameHeadersData(s.substr(0, s.size() / 2)));
  EXPECT_TRUE(HandleControlFrameHeadersData(s.substr(s.size() / 2)));

  EXPECT_FALSE(HandleControlFrameHeadersData(s));
  quiche::HttpHeaderBlock expected_block = MakeHeaderBlock({{"a", a_value}});
  EXPECT_EQ(expected_block, decoded_block());
}

TEST_P(HpackDecoderAdapterTest, NameTooLong) {
  // Verify that a name longer than the allowed size generates an error.
  const size_t kMaxBufferSizeBytes = 50;
  const std::string name = std::string(2 * kMaxBufferSizeBytes, 'x');
  const std::string value = "abc";

  decoder_.set_max_decode_buffer_size_bytes(kMaxBufferSizeBytes);

  HpackBlockBuilder hbb;
  hbb.AppendLiteralNameAndValue(HpackEntryType::kNeverIndexedLiteralHeader,
                                false, name, false, value);

  const size_t fragment_size = (3 * kMaxBufferSizeBytes) / 2;
  const std::string fragment = hbb.buffer().substr(0, fragment_size);

  HandleControlFrameHeadersStart();
  EXPECT_FALSE(HandleControlFrameHeadersData(fragment));
}

TEST_P(HpackDecoderAdapterTest, HeaderTooLongToBuffer) {
  // Verify that a header longer than the allowed size generates an error if
  // it isn't all in one input buffer.
  const std::string name = "some-key";
  const std::string value = "some-value";
  const size_t kMaxBufferSizeBytes = name.size() + value.size() - 2;
  decoder_.set_max_decode_buffer_size_bytes(kMaxBufferSizeBytes);

  HpackBlockBuilder hbb;
  hbb.AppendLiteralNameAndValue(HpackEntryType::kNeverIndexedLiteralHeader,
                                false, name, false, value);
  const size_t fragment_size = hbb.size() - 1;
  const std::string fragment = hbb.buffer().substr(0, fragment_size);

  HandleControlFrameHeadersStart();
  EXPECT_FALSE(HandleControlFrameHeadersData(fragment));
}

// Verify that a header block that exceeds the maximum length is rejected.
TEST_P(HpackDecoderAdapterTest, HeaderBlockTooLong) {
  const std::string name = "some-key";
  const std::string value = "some-value";
  const size_t kMaxBufferSizeBytes = 1024;

  HpackBlockBuilder hbb;
  hbb.AppendLiteralNameAndValue(HpackEntryType::kIndexedLiteralHeader, false,
                                name, false, value);
  while (hbb.size() < kMaxBufferSizeBytes) {
    hbb.AppendLiteralNameAndValue(HpackEntryType::kIndexedLiteralHeader, false,
                                  "", false, "");
  }
  // With no limit on the maximum header block size, the decoder handles the
  // entire block successfully.
  HandleControlFrameHeadersStart();
  EXPECT_TRUE(HandleControlFrameHeadersData(hbb.buffer()));
  EXPECT_TRUE(HandleControlFrameHeadersComplete());

  // When a total byte limit is imposed, the decoder bails before the end of the
  // block.
  decoder_.set_max_header_block_bytes(kMaxBufferSizeBytes);
  HandleControlFrameHeadersStart();
  EXPECT_FALSE(HandleControlFrameHeadersData(hbb.buffer()));
}

// Decode with incomplete data in buffer.
TEST_P(HpackDecoderAdapterTest, DecodeWithIncompleteData) {
  HandleControlFrameHeadersStart();

  // No need to wait for more data.
  EXPECT_TRUE(HandleControlFrameHeadersData("\x82\x85\x82"));
  std::vector<std::pair<std::string, std::string>> expected_headers = {
      {":method", "GET"}, {":path", "/index.html"}, {":method", "GET"}};

  quiche::HttpHeaderBlock expected_block1 = MakeHeaderBlock(expected_headers);
  EXPECT_EQ(expected_block1, decoded_block());

  // Full and partial headers, won't add partial to the headers.
  EXPECT_TRUE(
      HandleControlFrameHeadersData("\x40\x03goo"
                                    "\x03gar\xbe\x40\x04spam"));
  expected_headers.push_back({"goo", "gar"});
  expected_headers.push_back({"goo", "gar"});

  quiche::HttpHeaderBlock expected_block2 = MakeHeaderBlock(expected_headers);
  EXPECT_EQ(expected_block2, decoded_block());

  // Add the needed data.
  EXPECT_TRUE(HandleControlFrameHeadersData("\x04gggs"));

  EXPECT_TRUE(HandleControlFrameHeadersComplete());

  expected_headers.push_back({"spam", "gggs"});

  quiche::HttpHeaderBlock expected_block3 = MakeHeaderBlock(expected_headers);
  EXPECT_EQ(expected_block3, decoded_block());
}

TEST_P(HpackDecoderAdapterTest, HandleHeaderRepresentation) {
  // Make sure the decoder is properly initialized.
  HandleControlFrameHeadersStart();
  HandleControlFrameHeadersData("");

  // All cookie crumbs are joined.
  decoder_peer_.HandleHeaderRepresentation("cookie", " part 1");
  decoder_peer_.HandleHeaderRepresentation("cookie", "part 2 ");
  decoder_peer_.HandleHeaderRepresentation("cookie", "part3");

  // Already-delimited headers are passed through.
  decoder_peer_.HandleHeaderRepresentation("passed-through",
                                           std::string("foo\0baz", 7));

  // Other headers are joined on \0. Case matters.
  decoder_peer_.HandleHeaderRepresentation("joined", "joined");
  decoder_peer_.HandleHeaderRepresentation("joineD", "value 1");
  decoder_peer_.HandleHeaderRepresentation("joineD", "value 2");

  // Empty headers remain empty.
  decoder_peer_.HandleHeaderRepresentation("empty", "");

  // Joined empty headers work as expected.
  decoder_peer_.HandleHeaderRepresentation("empty-joined", "");
  decoder_peer_.HandleHeaderRepresentation("empty-joined", "foo");
  decoder_peer_.HandleHeaderRepresentation("empty-joined", "");
  decoder_peer_.HandleHeaderRepresentation("empty-joined", "");

  // Non-contiguous cookie crumb.
  decoder_peer_.HandleHeaderRepresentation("cookie", " fin!");

  // Finish and emit all headers.
  decoder_.HandleControlFrameHeadersComplete();

  // Resulting decoded headers are in the same order as the inputs.
  EXPECT_THAT(
      decoded_block(),
      ElementsAre(
          Pair("cookie", " part 1; part 2 ; part3;  fin!"),
          Pair("passed-through", absl::string_view("foo\0baz", 7)),
          Pair("joined", absl::string_view("joined\0value 1\0value 2", 22)),
          Pair("empty", ""),
          Pair("empty-joined", absl::string_view("\0foo\0\0", 6))));
}

// Decoding indexed static table field should work.
TEST_P(HpackDecoderAdapterTest, IndexedHeaderStatic) {
  // Reference static table entries #2 and #5.
  const quiche::HttpHeaderBlock& header_set1 =
      DecodeBlockExpectingSuccess("\x82\x85");
  quiche::HttpHeaderBlock expected_header_set1;
  expected_header_set1[":method"] = "GET";
  expected_header_set1[":path"] = "/index.html";
  EXPECT_EQ(expected_header_set1, header_set1);

  // Reference static table entry #2.
  const quiche::HttpHeaderBlock& header_set2 =
      DecodeBlockExpectingSuccess("\x82");
  quiche::HttpHeaderBlock expected_header_set2;
  expected_header_set2[":method"] = "GET";
  EXPECT_EQ(expected_header_set2, header_set2);
}

TEST_P(HpackDecoderAdapterTest, IndexedHeaderDynamic) {
  // First header block: add an entry to header table.
  const quiche::HttpHeaderBlock& header_set1 = DecodeBlockExpectingSuccess(
      "\x40\x03"
      "foo"
      "\x03"
      "bar");
  quiche::HttpHeaderBlock expected_header_set1;
  expected_header_set1["foo"] = "bar";
  EXPECT_EQ(expected_header_set1, header_set1);

  // Second header block: add another entry to header table.
  const quiche::HttpHeaderBlock& header_set2 = DecodeBlockExpectingSuccess(
      "\xbe\x40\x04"
      "spam"
      "\x04"
      "eggs");
  quiche::HttpHeaderBlock expected_header_set2;
  expected_header_set2["foo"] = "bar";
  expected_header_set2["spam"] = "eggs";
  EXPECT_EQ(expected_header_set2, header_set2);

  // Third header block: refer to most recently added entry.
  const quiche::HttpHeaderBlock& header_set3 =
      DecodeBlockExpectingSuccess("\xbe");
  quiche::HttpHeaderBlock expected_header_set3;
  expected_header_set3["spam"] = "eggs";
  EXPECT_EQ(expected_header_set3, header_set3);
}

// Test a too-large indexed header.
TEST_P(HpackDecoderAdapterTest, InvalidIndexedHeader) {
  // High-bit set, and a prefix of one more than the number of static entries.
  EXPECT_FALSE(DecodeHeaderBlock("\xbe"));
}

TEST_P(HpackDecoderAdapterTest, ContextUpdateMaximumSize) {
  EXPECT_EQ(kDefaultHeaderTableSizeSetting,
            decoder_peer_.header_table_size_limit());
  std::string input;
  {
    // Maximum-size update with size 126. Succeeds.
    HpackOutputStream output_stream;
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(126);

    input = output_stream.TakeString();
    EXPECT_TRUE(DecodeHeaderBlock(input));
    EXPECT_EQ(126u, decoder_peer_.header_table_size_limit());
  }
  {
    // Maximum-size update with kDefaultHeaderTableSizeSetting. Succeeds.
    HpackOutputStream output_stream;
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(kDefaultHeaderTableSizeSetting);

    input = output_stream.TakeString();
    EXPECT_TRUE(DecodeHeaderBlock(input));
    EXPECT_EQ(kDefaultHeaderTableSizeSetting,
              decoder_peer_.header_table_size_limit());
  }
  {
    // Maximum-size update with kDefaultHeaderTableSizeSetting + 1. Fails.
    HpackOutputStream output_stream;
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(kDefaultHeaderTableSizeSetting + 1);

    input = output_stream.TakeString();
    EXPECT_FALSE(DecodeHeaderBlock(input));
    EXPECT_EQ(kDefaultHeaderTableSizeSetting,
              decoder_peer_.header_table_size_limit());
  }
}

// Two HeaderTableSizeUpdates may appear at the beginning of the block
TEST_P(HpackDecoderAdapterTest, TwoTableSizeUpdates) {
  std::string input;
  {
    // Should accept two table size updates, update to second one
    HpackOutputStream output_stream;
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(0);
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(122);

    input = output_stream.TakeString();
    EXPECT_TRUE(DecodeHeaderBlock(input));
    EXPECT_EQ(122u, decoder_peer_.header_table_size_limit());
  }
}

// Three HeaderTableSizeUpdates should result in an error
TEST_P(HpackDecoderAdapterTest, ThreeTableSizeUpdatesError) {
  std::string input;
  {
    // Should reject three table size updates, update to second one
    HpackOutputStream output_stream;
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(5);
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(10);
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(15);

    input = output_stream.TakeString();

    EXPECT_FALSE(DecodeHeaderBlock(input));
    EXPECT_EQ(10u, decoder_peer_.header_table_size_limit());
  }
}

// HeaderTableSizeUpdates may only appear at the beginning of the block
// Any other updates should result in an error
TEST_P(HpackDecoderAdapterTest, TableSizeUpdateSecondError) {
  std::string input;
  {
    // Should reject a table size update appearing after a different entry
    // The table size should remain as the default
    HpackOutputStream output_stream;
    output_stream.AppendBytes("\x82\x85");
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(123);

    input = output_stream.TakeString();

    EXPECT_FALSE(DecodeHeaderBlock(input));
    EXPECT_EQ(kDefaultHeaderTableSizeSetting,
              decoder_peer_.header_table_size_limit());
  }
}

// HeaderTableSizeUpdates may only appear at the beginning of the block
// Any other updates should result in an error
TEST_P(HpackDecoderAdapterTest, TableSizeUpdateFirstThirdError) {
  std::string input;
  {
    // Should reject the second table size update
    // if a different entry appears after the first update
    // The table size should update to the first but not the second
    HpackOutputStream output_stream;
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(60);
    output_stream.AppendBytes("\x82\x85");
    output_stream.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    output_stream.AppendUint32(125);

    input = output_stream.TakeString();

    EXPECT_FALSE(DecodeHeaderBlock(input));
    EXPECT_EQ(60u, decoder_peer_.header_table_size_limit());
  }
}

// Decoding two valid encoded literal headers with no indexing should
// work.
TEST_P(HpackDecoderAdapterTest, LiteralHeaderNoIndexing) {
  // First header with indexed name, second header with string literal
  // name.
  const char input[] = "\x04\x0c/sample/path\x00\x06:path2\x0e/sample/path/2";
  const quiche::HttpHeaderBlock& header_set = DecodeBlockExpectingSuccess(
      absl::string_view(input, ABSL_ARRAYSIZE(input) - 1));

  quiche::HttpHeaderBlock expected_header_set;
  expected_header_set[":path"] = "/sample/path";
  expected_header_set[":path2"] = "/sample/path/2";
  EXPECT_EQ(expected_header_set, header_set);
}

// Decoding two valid encoded literal headers with incremental
// indexing and string literal names should work.
TEST_P(HpackDecoderAdapterTest, LiteralHeaderIncrementalIndexing) {
  const char input[] = "\x44\x0c/sample/path\x40\x06:path2\x0e/sample/path/2";
  const quiche::HttpHeaderBlock& header_set = DecodeBlockExpectingSuccess(
      absl::string_view(input, ABSL_ARRAYSIZE(input) - 1));

  quiche::HttpHeaderBlock expected_header_set;
  expected_header_set[":path"] = "/sample/path";
  expected_header_set[":path2"] = "/sample/path/2";
  EXPECT_EQ(expected_header_set, header_set);
}

TEST_P(HpackDecoderAdapterTest, LiteralHeaderWithIndexingInvalidNameIndex) {
  decoder_.ApplyHeaderTableSizeSetting(0);
  EXPECT_TRUE(EncodeAndDecodeDynamicTableSizeUpdates(0, 0));

  // Name is the last static index. Works.
  EXPECT_TRUE(DecodeHeaderBlock(absl::string_view("\x7d\x03ooo")));
  // Name is one beyond the last static index. Fails.
  EXPECT_FALSE(DecodeHeaderBlock(absl::string_view("\x7e\x03ooo")));
}

TEST_P(HpackDecoderAdapterTest, LiteralHeaderNoIndexingInvalidNameIndex) {
  // Name is the last static index. Works.
  EXPECT_TRUE(DecodeHeaderBlock(absl::string_view("\x0f\x2e\x03ooo")));
  // Name is one beyond the last static index. Fails.
  EXPECT_FALSE(DecodeHeaderBlock(absl::string_view("\x0f\x2f\x03ooo")));
}

TEST_P(HpackDecoderAdapterTest, LiteralHeaderNeverIndexedInvalidNameIndex) {
  // Name is the last static index. Works.
  EXPECT_TRUE(DecodeHeaderBlock(absl::string_view("\x1f\x2e\x03ooo")));
  // Name is one beyond the last static index. Fails.
  EXPECT_FALSE(DecodeHeaderBlock(absl::string_view("\x1f\x2f\x03ooo")));
}

TEST_P(HpackDecoderAdapterTest, TruncatedIndex) {
  // Indexed Header, varint for index requires multiple bytes,
  // but only one provided.
  EXPECT_FALSE(DecodeHeaderBlock("\xff"));
}

TEST_P(HpackDecoderAdapterTest, TruncatedHuffmanLiteral) {
  // Literal value, Huffman encoded, but with the last byte missing (i.e.
  // drop the final ff shown below).
  //
  // 41                                      | == Literal indexed ==
  //                                         |   Indexed name (idx = 1)
  //                                         |     :authority
  // 8c                                      |   Literal value (len = 12)
  //                                         |     Huffman encoded:
  // f1e3 c2e5 f23a 6ba0 ab90 f4ff           | .....:k.....
  //                                         |     Decoded:
  //                                         | www.example.com
  //                                         | -> :authority: www.example.com

  std::string first;
  ASSERT_TRUE(absl::HexStringToBytes("418cf1e3c2e5f23a6ba0ab90f4ff", &first));
  EXPECT_TRUE(DecodeHeaderBlock(first));
  first.pop_back();
  EXPECT_FALSE(DecodeHeaderBlock(first));
}

TEST_P(HpackDecoderAdapterTest, HuffmanEOSError) {
  // Literal value, Huffman encoded, but with an additional ff byte at the end
  // of the string, i.e. an EOS that is longer than permitted.
  //
  // 41                                      | == Literal indexed ==
  //                                         |   Indexed name (idx = 1)
  //                                         |     :authority
  // 8d                                      |   Literal value (len = 13)
  //                                         |     Huffman encoded:
  // f1e3 c2e5 f23a 6ba0 ab90 f4ff           | .....:k.....
  //                                         |     Decoded:
  //                                         | www.example.com
  //                                         | -> :authority: www.example.com

  std::string first;
  ASSERT_TRUE(absl::HexStringToBytes("418cf1e3c2e5f23a6ba0ab90f4ff", &first));
  EXPECT_TRUE(DecodeHeaderBlock(first));
  ASSERT_TRUE(absl::HexStringToBytes("418df1e3c2e5f23a6ba0ab90f4ffff", &first));
  EXPECT_FALSE(DecodeHeaderBlock(first));
}

// Round-tripping the header set from RFC 7541 C.3.1 should work.
// http://httpwg.org/specs/rfc7541.html#rfc.section.C.3.1
TEST_P(HpackDecoderAdapterTest, BasicC31) {
  HpackEncoder encoder;

  quiche::HttpHeaderBlock expected_header_set;
  expected_header_set[":method"] = "GET";
  expected_header_set[":scheme"] = "http";
  expected_header_set[":path"] = "/";
  expected_header_set[":authority"] = "www.example.com";

  std::string encoded_header_set =
      encoder.EncodeHeaderBlock(expected_header_set);

  EXPECT_TRUE(DecodeHeaderBlock(encoded_header_set));
  EXPECT_EQ(expected_header_set, decoded_block());
}

// RFC 7541, Section C.4: Request Examples with Huffman Coding
// http://httpwg.org/specs/rfc7541.html#rfc.section.C.4
TEST_P(HpackDecoderAdapterTest, SectionC4RequestHuffmanExamples) {
  // TODO(jamessynge): Use http2/hpack/tools/hpack_example.h to parse the
  // example directly, instead of having it as a comment.
  //
  // 82                                      | == Indexed - Add ==
  //                                         |   idx = 2
  //                                         | -> :method: GET
  // 86                                      | == Indexed - Add ==
  //                                         |   idx = 6
  //                                         | -> :scheme: http
  // 84                                      | == Indexed - Add ==
  //                                         |   idx = 4
  //                                         | -> :path: /
  // 41                                      | == Literal indexed ==
  //                                         |   Indexed name (idx = 1)
  //                                         |     :authority
  // 8c                                      |   Literal value (len = 12)
  //                                         |     Huffman encoded:
  // f1e3 c2e5 f23a 6ba0 ab90 f4ff           | .....:k.....
  //                                         |     Decoded:
  //                                         | www.example.com
  //                                         | -> :authority: www.example.com
  std::string first;
  ASSERT_TRUE(
      absl::HexStringToBytes("828684418cf1e3c2e5f23a6ba0ab90f4ff", &first));
  const quiche::HttpHeaderBlock& first_header_set =
      DecodeBlockExpectingSuccess(first);

  EXPECT_THAT(first_header_set,
              ElementsAre(
                  // clang-format off
      Pair(":method", "GET"),
      Pair(":scheme", "http"),
      Pair(":path", "/"),
      Pair(":authority", "www.example.com")));
  // clang-format on

  expectEntry(62, 57, ":authority", "www.example.com");
  EXPECT_EQ(57u, decoder_peer_.current_header_table_size());

  // 82                                      | == Indexed - Add ==
  //                                         |   idx = 2
  //                                         | -> :method: GET
  // 86                                      | == Indexed - Add ==
  //                                         |   idx = 6
  //                                         | -> :scheme: http
  // 84                                      | == Indexed - Add ==
  //                                         |   idx = 4
  //                                         | -> :path: /
  // be                                      | == Indexed - Add ==
  //                                         |   idx = 62
  //                                         | -> :authority: www.example.com
  // 58                                      | == Literal indexed ==
  //                                         |   Indexed name (idx = 24)
  //                                         |     cache-control
  // 86                                      |   Literal value (len = 8)
  //                                         |     Huffman encoded:
  // a8eb 1064 9cbf                          | ...d..
  //                                         |     Decoded:
  //                                         | no-cache
  //                                         | -> cache-control: no-cache

  std::string second;
  ASSERT_TRUE(absl::HexStringToBytes("828684be5886a8eb10649cbf", &second));
  const quiche::HttpHeaderBlock& second_header_set =
      DecodeBlockExpectingSuccess(second);

  EXPECT_THAT(second_header_set,
              ElementsAre(
                  // clang-format off
      Pair(":method", "GET"),
      Pair(":scheme", "http"),
      Pair(":path", "/"),
      Pair(":authority", "www.example.com"),
      Pair("cache-control", "no-cache")));
  // clang-format on

  expectEntry(62, 53, "cache-control", "no-cache");
  expectEntry(63, 57, ":authority", "www.example.com");
  EXPECT_EQ(110u, decoder_peer_.current_header_table_size());

  // 82                                      | == Indexed - Add ==
  //                                         |   idx = 2
  //                                         | -> :method: GET
  // 87                                      | == Indexed - Add ==
  //                                         |   idx = 7
  //                                         | -> :scheme: https
  // 85                                      | == Indexed - Add ==
  //                                         |   idx = 5
  //                                         | -> :path: /index.html
  // bf                                      | == Indexed - Add ==
  //                                         |   idx = 63
  //                                         | -> :authority: www.example.com
  // 40                                      | == Literal indexed ==
  // 88                                      |   Literal name (len = 10)
  //                                         |     Huffman encoded:
  // 25a8 49e9 5ba9 7d7f                     | %.I.[.}.
  //                                         |     Decoded:
  //                                         | custom-key
  // 89                                      |   Literal value (len = 12)
  //                                         |     Huffman encoded:
  // 25a8 49e9 5bb8 e8b4 bf                  | %.I.[....
  //                                         |     Decoded:
  //                                         | custom-value
  //                                         | -> custom-key: custom-value
  std::string third;
  ASSERT_TRUE(absl::HexStringToBytes(
      "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf", &third));
  const quiche::HttpHeaderBlock& third_header_set =
      DecodeBlockExpectingSuccess(third);

  EXPECT_THAT(
      third_header_set,
      ElementsAre(
          // clang-format off
      Pair(":method", "GET"),
      Pair(":scheme", "https"),
      Pair(":path", "/index.html"),
      Pair(":authority", "www.example.com"),
      Pair("custom-key", "custom-value")));
  // clang-format on

  expectEntry(62, 54, "custom-key", "custom-value");
  expectEntry(63, 53, "cache-control", "no-cache");
  expectEntry(64, 57, ":authority", "www.example.com");
  EXPECT_EQ(164u, decoder_peer_.current_header_table_size());
}

// RFC 7541, Section C.6: Response Examples with Huffman Coding
// http://httpwg.org/specs/rfc7541.html#rfc.section.C.6
TEST_P(HpackDecoderAdapterTest, SectionC6ResponseHuffmanExamples) {
  // The example is based on a maximum dynamic table size of 256,
  // which allows for testing dynamic table evictions.
  decoder_peer_.set_header_table_size_limit(256);

  // 48                                      | == Literal indexed ==
  //                                         |   Indexed name (idx = 8)
  //                                         |     :status
  // 82                                      |   Literal value (len = 3)
  //                                         |     Huffman enco
```