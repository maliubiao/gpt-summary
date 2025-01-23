Response:
The user wants to understand the functionality of the `hpack_encoder_test.cc` file in the Chromium network stack. They are interested in its purpose, relationship with JavaScript, logical reasoning with input/output examples, common usage errors, and debugging information.

Here's a plan to address the user's request:

1. **Identify the core purpose:**  Recognize that it's a test file for the `HpackEncoder` class.
2. **List functionalities:** Extract the key test scenarios and the features of `HpackEncoder` being tested.
3. **JavaScript relation:** Analyze if HPACK encoding directly interacts with JavaScript and provide relevant examples if so, or explain the indirect relationship via the browser.
4. **Logical reasoning:** Select a few test cases and provide hypothetical inputs (HTTP headers) and their expected HPACK encoded outputs.
5. **Common usage errors:**  Think about how developers might misuse the `HpackEncoder` or related APIs, focusing on common pitfalls.
6. **User operation for debugging:**  Describe a scenario where a user action leads to the execution of this code and how a developer might use this test file for debugging.
这个文件 `net/third_party/quiche/src/quiche/http2/hpack/hpack_encoder_test.cc` 是 Chromium 网络栈中 QUIC 协议库的一部分，专门用于测试 `HpackEncoder` 类的功能。 `HpackEncoder` 的作用是将 HTTP/2 和 HTTP/3 的头部信息（headers）压缩成 HPACK 格式。

**该文件的主要功能包括：**

1. **单元测试 `HpackEncoder` 的各种编码场景：**
   - **索引头部 (Indexed Headers):** 测试对静态表和动态表中已存在头部进行索引编码的功能。
   - **字面头部 (Literal Headers):** 测试对新的头部名称或值进行字面值编码的功能，包括带索引和不带索引的情况。
   - **Huffman 编码：** 测试对头部名称和值进行 Huffman 压缩的功能。
   - **动态表操作：** 测试动态表的大小调整、头部条目的插入和删除（驱逐）等功能。
   - **Cookie 处理：** 测试 Cookie 头部的分解 (crumbling) 功能，将一个包含多个键值对的 Cookie 头部拆分成多个独立的头部。
   - **禁用压缩：** 测试在禁用 HPACK 压缩情况下的编码行为。
   - **多轮编码：** 测试在多次编码过程中，动态表状态的保持和更新。
   - **伪头部处理：** 测试对 HTTP/2 伪头部（如 `:path`, `:authority`）的编码顺序和方式。
   - **头部表大小更新：** 测试 `ApplyHeaderTableSizeSetting` 方法，用于更新 HPACK 动态表的最大尺寸。

2. **验证编码输出的正确性：**
   - 使用 `HpackOutputStream` 构建预期的 HPACK 编码结果。
   - 调用 `HpackEncoder` 的编码方法对给定的 HTTP 头部进行编码。
   - 比对实际编码输出和预期输出是否一致。

3. **验证头部监听器的行为：**
   - 设置 `HeaderListener`，用于在编码过程中接收被编码的头部信息。
   - 验证 `HeaderListener` 接收到的头部信息是否与原始头部信息一致。

**它与 JavaScript 的功能的关系：**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它所测试的 HPACK 编码功能与 JavaScript 在 Web 开发中有着密切的关系。

- **HTTP 请求和响应：** 当浏览器（其中包含 JavaScript 引擎）发起 HTTP/2 或 HTTP/3 请求时，浏览器会将 HTTP 头部信息传递给网络栈进行编码。`HpackEncoder` 就负责将这些头部信息压缩成 HPACK 格式，以便在网络上传输，从而减少数据量，提高性能。同样，当浏览器接收到 HTTP/2 或 HTTP/3 响应时，网络栈会将接收到的 HPACK 编码的头部信息解码成原始的 HTTP 头部，然后 JavaScript 才能访问这些头部信息。

**举例说明：**

假设 JavaScript 代码通过 `fetch` API 发起一个 HTTP/2 请求：

```javascript
fetch('https://example.com/data', {
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer mytoken'
  }
});
```

在这个过程中，Chromium 的网络栈会将 `Content-Type: application/json` 和 `Authorization: Bearer mytoken` 这两个头部信息传递给 `HpackEncoder` 进行编码。`hpack_encoder_test.cc` 中的测试用例会模拟各种场景，例如：

- **假设输入：**  `HttpHeaderBlock` 包含 `{"Content-Type", "application/json"}` 和 `{"Authorization", "Bearer mytoken"}`。
- **可能的输出（取决于动态表状态和编码策略）：**
    - 如果这两个头部是首次出现，可能会进行字面值编码，并可能添加到动态表中。
    - 如果 `Content-Type` 已经在静态表或动态表中，可能会使用索引编码。
    - Huffman 编码可能会应用于头部名称和值。

**逻辑推理的假设输入与输出：**

**场景 1： 索引静态表头部**

- **假设输入：** `HttpHeaderBlock` 包含 `{"method", "GET"}`。 `"method: GET"` 存在于 HPACK 静态表中。
- **预期输出：** HPACK 编码为表示静态表索引的字节序列（具体的字节取决于 "method: GET" 在静态表中的索引）。例如，可能是 `\x82` (假设 "method: GET" 的索引是 2，并且使用了最高位为 1 的索引表示)。

**场景 2： 字面值编码，添加至动态表**

- **假设输入：** `HttpHeaderBlock` 包含 `{"custom-header", "custom-value"}`。
- **预期输出：**  HPACK 编码会包含：
    - 表示字面值头部，并指示添加到动态表的字节。
    - 表示头部名称长度和内容的字节序列（可能使用 Huffman 编码）。
    - 表示头部值长度和内容的字节序列（可能使用 Huffman 编码）。
    - 例如，可能是 `\x40\x0dcustom-header\x0ccustom-value` （这只是一个示意，实际字节会更复杂）。

**涉及用户或者编程常见的使用错误：**

1. **不理解 HPACK 动态表的状态：** 开发者在测试或实现 HTTP/2/3 应用时，如果对 HPACK 动态表的工作方式不熟悉，可能会在编码和解码过程中产生误解，导致头部信息丢失或不一致。例如，发送方错误地假设接收方已经存在某个头部在动态表中，而实际情况并非如此。

2. **错误地处理 Cookie 头部：**  没有按照 HTTP/2 规范对 Cookie 头部进行分解，可能导致解码失败或者性能下降。`HpackEncoder` 的 Cookie crumbling 功能可以帮助避免这个问题。

3. **动态表大小设置不当：**  设置过小的动态表大小可能会导致频繁的头部驱逐，降低压缩效率。设置过大的动态表大小可能会占用过多内存。

4. **在需要逐帧发送头部的情况下，没有使用增量编码 API：**  `HpackEncoder` 提供了增量编码的 API，允许逐步编码头部信息。如果需要分块发送头部，但使用了非增量编码的方式，可能会导致问题。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在使用 Chrome 浏览器访问一个使用了 HTTP/2 或 HTTP/3 的网站时遇到了头部相关的错误，例如：

1. **用户在浏览器地址栏输入网址并访问。**
2. **浏览器向服务器发起 HTTP/2 或 HTTP/3 请求。**
3. **在发送请求前，浏览器会将 HTTP 头部传递给网络栈的 HPACK 编码器 (`HpackEncoder`) 进行压缩。**
4. **如果 `HpackEncoder` 在编码过程中出现 bug，可能会生成错误的 HPACK 编码。**
5. **服务器接收到错误的 HPACK 编码后，解码可能会失败，或者解码出错误的头部信息。**
6. **服务器根据错误的头部信息处理请求，可能会返回错误的结果。**
7. **开发者在调试时，可能会怀疑是 HPACK 编码的问题。**

**作为调试线索，开发者可以：**

- **查看 Chrome 的网络日志 (chrome://net-export/) 或使用 Wireshark 等工具抓包，分析发送的 HPACK 编码是否符合预期。**
- **如果怀疑 `HpackEncoder` 的行为，可以查阅 `hpack_encoder_test.cc` 中的测试用例，了解 `HpackEncoder` 在各种场景下的预期行为。**
- **可以尝试编写新的测试用例，模拟出现问题的场景，验证 `HpackEncoder` 是否存在 bug。**
- **通过单步调试 Chromium 源码，跟踪 `HpackEncoder` 的执行过程，查看动态表的状态变化和编码逻辑。**
- **查看 `hpack_encoder_test.cc` 中使用的 `ExpectIndex`, `ExpectIndexedLiteral` 等辅助函数，理解如何验证编码的正确性。**

总而言之，`hpack_encoder_test.cc` 是确保 Chromium 网络栈中 HPACK 编码功能正确性的关键组件，它通过大量的单元测试覆盖了各种编码场景，为开发者提供了理解和调试 HPACK 编码行为的重要参考。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/hpack/hpack_encoder_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/http2/hpack/hpack_encoder.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/http2/hpack/hpack_constants.h"
#include "quiche/http2/hpack/hpack_entry.h"
#include "quiche/http2/hpack/hpack_header_table.h"
#include "quiche/http2/hpack/hpack_output_stream.h"
#include "quiche/http2/hpack/hpack_static_table.h"
#include "quiche/http2/hpack/huffman/hpack_huffman_encoder.h"
#include "quiche/http2/test_tools/http2_random.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_simple_arena.h"

namespace spdy {

namespace test {

class HpackHeaderTablePeer {
 public:
  explicit HpackHeaderTablePeer(HpackHeaderTable* table) : table_(table) {}

  const HpackEntry* GetFirstStaticEntry() const {
    return &table_->static_entries_.front();
  }

  HpackHeaderTable::DynamicEntryTable* dynamic_entries() {
    return &table_->dynamic_entries_;
  }

 private:
  HpackHeaderTable* table_;
};

class HpackEncoderPeer {
 public:
  typedef HpackEncoder::Representation Representation;
  typedef HpackEncoder::Representations Representations;

  explicit HpackEncoderPeer(HpackEncoder* encoder) : encoder_(encoder) {}

  bool compression_enabled() const { return encoder_->enable_compression_; }
  HpackHeaderTable* table() { return &encoder_->header_table_; }
  HpackHeaderTablePeer table_peer() { return HpackHeaderTablePeer(table()); }
  void EmitString(absl::string_view str) { encoder_->EmitString(str); }
  void TakeString(std::string* out) {
    *out = encoder_->output_stream_.TakeString();
  }
  static void CookieToCrumbs(absl::string_view cookie,
                             std::vector<absl::string_view>* out) {
    Representations tmp;
    HpackEncoder::CookieToCrumbs(std::make_pair("", cookie), &tmp);

    out->clear();
    for (size_t i = 0; i != tmp.size(); ++i) {
      out->push_back(tmp[i].second);
    }
  }
  static void DecomposeRepresentation(absl::string_view value,
                                      std::vector<absl::string_view>* out) {
    Representations tmp;
    HpackEncoder::DecomposeRepresentation(std::make_pair("foobar", value),
                                          &tmp);

    out->clear();
    for (size_t i = 0; i != tmp.size(); ++i) {
      out->push_back(tmp[i].second);
    }
  }

  // TODO(dahollings): Remove or clean up these methods when deprecating
  // non-incremental encoding path.
  static std::string EncodeHeaderBlock(
      HpackEncoder* encoder, const quiche::HttpHeaderBlock& header_set) {
    return encoder->EncodeHeaderBlock(header_set);
  }

  static bool EncodeIncremental(HpackEncoder* encoder,
                                const quiche::HttpHeaderBlock& header_set,
                                std::string* output) {
    std::unique_ptr<HpackEncoder::ProgressiveEncoder> encoderator =
        encoder->EncodeHeaderSet(header_set);
    http2::test::Http2Random random;
    std::string output_buffer = encoderator->Next(random.UniformInRange(0, 16));
    while (encoderator->HasNext()) {
      std::string second_buffer =
          encoderator->Next(random.UniformInRange(0, 16));
      output_buffer.append(second_buffer);
    }
    *output = std::move(output_buffer);
    return true;
  }

  static bool EncodeRepresentations(HpackEncoder* encoder,
                                    const Representations& representations,
                                    std::string* output) {
    std::unique_ptr<HpackEncoder::ProgressiveEncoder> encoderator =
        encoder->EncodeRepresentations(representations);
    http2::test::Http2Random random;
    std::string output_buffer = encoderator->Next(random.UniformInRange(0, 16));
    while (encoderator->HasNext()) {
      std::string second_buffer =
          encoderator->Next(random.UniformInRange(0, 16));
      output_buffer.append(second_buffer);
    }
    *output = std::move(output_buffer);
    return true;
  }

 private:
  HpackEncoder* encoder_;
};

}  // namespace test

namespace {

using testing::ElementsAre;
using testing::Pair;

const size_t kStaticEntryIndex = 1;

enum EncodeStrategy {
  kDefault,
  kIncremental,
  kRepresentations,
};

class HpackEncoderTest
    : public quiche::test::QuicheTestWithParam<EncodeStrategy> {
 protected:
  typedef test::HpackEncoderPeer::Representations Representations;

  HpackEncoderTest()
      : peer_(&encoder_),
        static_(peer_.table_peer().GetFirstStaticEntry()),
        dynamic_table_insertions_(0),
        headers_storage_(1024 /* block size */),
        strategy_(GetParam()) {}

  void SetUp() override {
    // Populate dynamic entries into the table fixture. For simplicity each
    // entry has name.size() + value.size() == 10.
    key_1_ = peer_.table()->TryAddEntry("key1", "value1");
    key_1_index_ = dynamic_table_insertions_++;
    key_2_ = peer_.table()->TryAddEntry("key2", "value2");
    key_2_index_ = dynamic_table_insertions_++;
    cookie_a_ = peer_.table()->TryAddEntry("cookie", "a=bb");
    cookie_a_index_ = dynamic_table_insertions_++;
    cookie_c_ = peer_.table()->TryAddEntry("cookie", "c=dd");
    cookie_c_index_ = dynamic_table_insertions_++;

    // No further insertions may occur without evictions.
    peer_.table()->SetMaxSize(peer_.table()->size());
    QUICHE_CHECK_EQ(kInitialDynamicTableSize, peer_.table()->size());
  }

  void SaveHeaders(absl::string_view name, absl::string_view value) {
    absl::string_view n(headers_storage_.Memdup(name.data(), name.size()),
                        name.size());
    absl::string_view v(headers_storage_.Memdup(value.data(), value.size()),
                        value.size());
    headers_observed_.push_back(std::make_pair(n, v));
  }

  void ExpectIndex(size_t index) {
    expected_.AppendPrefix(kIndexedOpcode);
    expected_.AppendUint32(index);
  }
  void ExpectIndexedLiteral(size_t key_index, absl::string_view value) {
    expected_.AppendPrefix(kLiteralIncrementalIndexOpcode);
    expected_.AppendUint32(key_index);
    ExpectString(&expected_, value);
  }
  void ExpectIndexedLiteral(absl::string_view name, absl::string_view value) {
    expected_.AppendPrefix(kLiteralIncrementalIndexOpcode);
    expected_.AppendUint32(0);
    ExpectString(&expected_, name);
    ExpectString(&expected_, value);
  }
  void ExpectNonIndexedLiteral(absl::string_view name,
                               absl::string_view value) {
    expected_.AppendPrefix(kLiteralNoIndexOpcode);
    expected_.AppendUint32(0);
    ExpectString(&expected_, name);
    ExpectString(&expected_, value);
  }
  void ExpectNonIndexedLiteralWithNameIndex(size_t key_index,
                                            absl::string_view value) {
    expected_.AppendPrefix(kLiteralNoIndexOpcode);
    expected_.AppendUint32(key_index);
    ExpectString(&expected_, value);
  }
  void ExpectString(HpackOutputStream* stream, absl::string_view str) {
    size_t encoded_size =
        peer_.compression_enabled() ? http2::HuffmanSize(str) : str.size();
    if (encoded_size < str.size()) {
      expected_.AppendPrefix(kStringLiteralHuffmanEncoded);
      expected_.AppendUint32(encoded_size);
      http2::HuffmanEncode(str, encoded_size, stream->MutableString());
    } else {
      expected_.AppendPrefix(kStringLiteralIdentityEncoded);
      expected_.AppendUint32(str.size());
      expected_.AppendBytes(str);
    }
  }
  void ExpectHeaderTableSizeUpdate(uint32_t size) {
    expected_.AppendPrefix(kHeaderTableSizeUpdateOpcode);
    expected_.AppendUint32(size);
  }
  Representations MakeRepresentations(
      const quiche::HttpHeaderBlock& header_set) {
    Representations r;
    for (const auto& header : header_set) {
      r.push_back(header);
    }
    return r;
  }
  void CompareWithExpectedEncoding(const quiche::HttpHeaderBlock& header_set) {
    std::string actual_out;
    std::string expected_out = expected_.TakeString();
    switch (strategy_) {
      case kDefault:
        actual_out =
            test::HpackEncoderPeer::EncodeHeaderBlock(&encoder_, header_set);
        break;
      case kIncremental:
        EXPECT_TRUE(test::HpackEncoderPeer::EncodeIncremental(
            &encoder_, header_set, &actual_out));
        break;
      case kRepresentations:
        EXPECT_TRUE(test::HpackEncoderPeer::EncodeRepresentations(
            &encoder_, MakeRepresentations(header_set), &actual_out));
        break;
    }
    EXPECT_EQ(expected_out, actual_out);
  }
  void CompareWithExpectedEncoding(const Representations& representations) {
    std::string actual_out;
    std::string expected_out = expected_.TakeString();
    EXPECT_TRUE(test::HpackEncoderPeer::EncodeRepresentations(
        &encoder_, representations, &actual_out));
    EXPECT_EQ(expected_out, actual_out);
  }
  // Converts the index of a dynamic table entry to the HPACK index.
  // In these test, dynamic table entries are indexed sequentially, starting
  // with 0.  The HPACK indexing scheme is defined at
  // https://httpwg.org/specs/rfc7541.html#index.address.space.
  size_t DynamicIndexToWireIndex(size_t index) {
    return dynamic_table_insertions_ - index + kStaticTableSize;
  }

  HpackEncoder encoder_;
  test::HpackEncoderPeer peer_;

  // Calculated based on the names and values inserted in SetUp(), above.
  const size_t kInitialDynamicTableSize = 4 * (10 + 32);

  const HpackEntry* static_;
  const HpackEntry* key_1_;
  const HpackEntry* key_2_;
  const HpackEntry* cookie_a_;
  const HpackEntry* cookie_c_;
  size_t key_1_index_;
  size_t key_2_index_;
  size_t cookie_a_index_;
  size_t cookie_c_index_;
  size_t dynamic_table_insertions_;

  quiche::QuicheSimpleArena headers_storage_;
  std::vector<std::pair<absl::string_view, absl::string_view>>
      headers_observed_;

  HpackOutputStream expected_;
  const EncodeStrategy strategy_;
};

using HpackEncoderTestWithDefaultStrategy = HpackEncoderTest;

INSTANTIATE_TEST_SUITE_P(HpackEncoderTests, HpackEncoderTestWithDefaultStrategy,
                         ::testing::Values(kDefault));

TEST_P(HpackEncoderTestWithDefaultStrategy, EncodeRepresentations) {
  EXPECT_EQ(kInitialDynamicTableSize, encoder_.GetDynamicTableSize());
  encoder_.SetHeaderListener(
      [this](absl::string_view name, absl::string_view value) {
        this->SaveHeaders(name, value);
      });
  const std::vector<std::pair<absl::string_view, absl::string_view>>
      header_list = {{"cookie", "val1; val2;val3"},
                     {":path", "/home"},
                     {"accept", "text/html, text/plain,application/xml"},
                     {"cookie", "val4"},
                     {"withnul", absl::string_view("one\0two", 7)}};
  ExpectNonIndexedLiteralWithNameIndex(peer_.table()->GetByName(":path"),
                                       "/home");
  ExpectIndexedLiteral(peer_.table()->GetByName("cookie"), "val1");
  ExpectIndexedLiteral(peer_.table()->GetByName("cookie"), "val2");
  ExpectIndexedLiteral(peer_.table()->GetByName("cookie"), "val3");
  ExpectIndexedLiteral(peer_.table()->GetByName("accept"),
                       "text/html, text/plain,application/xml");
  ExpectIndexedLiteral(peer_.table()->GetByName("cookie"), "val4");
  ExpectIndexedLiteral("withnul", absl::string_view("one\0two", 7));

  CompareWithExpectedEncoding(header_list);
  EXPECT_THAT(
      headers_observed_,
      ElementsAre(Pair(":path", "/home"), Pair("cookie", "val1"),
                  Pair("cookie", "val2"), Pair("cookie", "val3"),
                  Pair("accept", "text/html, text/plain,application/xml"),
                  Pair("cookie", "val4"),
                  Pair("withnul", absl::string_view("one\0two", 7))));
  // Insertions and evictions have happened over the course of the test.
  EXPECT_GE(kInitialDynamicTableSize, encoder_.GetDynamicTableSize());
}

TEST_P(HpackEncoderTestWithDefaultStrategy, WithoutCookieCrumbling) {
  EXPECT_EQ(kInitialDynamicTableSize, encoder_.GetDynamicTableSize());
  encoder_.SetHeaderListener(
      [this](absl::string_view name, absl::string_view value) {
        this->SaveHeaders(name, value);
      });
  encoder_.DisableCookieCrumbling();

  const std::vector<std::pair<absl::string_view, absl::string_view>>
      header_list = {{"cookie", "val1; val2;val3"},
                     {":path", "/home"},
                     {"accept", "text/html, text/plain,application/xml"},
                     {"cookie", "val4"},
                     {"withnul", absl::string_view("one\0two", 7)}};
  ExpectNonIndexedLiteralWithNameIndex(peer_.table()->GetByName(":path"),
                                       "/home");
  ExpectIndexedLiteral(peer_.table()->GetByName("cookie"), "val1; val2;val3");
  ExpectIndexedLiteral(peer_.table()->GetByName("accept"),
                       "text/html, text/plain,application/xml");
  ExpectIndexedLiteral(peer_.table()->GetByName("cookie"), "val4");
  ExpectIndexedLiteral("withnul", absl::string_view("one\0two", 7));

  CompareWithExpectedEncoding(header_list);
  EXPECT_THAT(
      headers_observed_,
      ElementsAre(Pair(":path", "/home"), Pair("cookie", "val1; val2;val3"),
                  Pair("accept", "text/html, text/plain,application/xml"),
                  Pair("cookie", "val4"),
                  Pair("withnul", absl::string_view("one\0two", 7))));
  // Insertions and evictions have happened over the course of the test.
  EXPECT_GE(kInitialDynamicTableSize, encoder_.GetDynamicTableSize());
}

TEST_P(HpackEncoderTestWithDefaultStrategy, DynamicTableGrows) {
  EXPECT_EQ(kInitialDynamicTableSize, encoder_.GetDynamicTableSize());
  peer_.table()->SetMaxSize(4096);
  encoder_.SetHeaderListener(
      [this](absl::string_view name, absl::string_view value) {
        this->SaveHeaders(name, value);
      });
  const std::vector<std::pair<absl::string_view, absl::string_view>>
      header_list = {{"cookie", "val1; val2;val3"},
                     {":path", "/home"},
                     {"accept", "text/html, text/plain,application/xml"},
                     {"cookie", "val4"},
                     {"withnul", absl::string_view("one\0two", 7)}};
  std::string out;
  EXPECT_TRUE(test::HpackEncoderPeer::EncodeRepresentations(&encoder_,
                                                            header_list, &out));

  EXPECT_FALSE(out.empty());
  // Insertions have happened over the course of the test.
  EXPECT_GT(encoder_.GetDynamicTableSize(), kInitialDynamicTableSize);
}

INSTANTIATE_TEST_SUITE_P(HpackEncoderTests, HpackEncoderTest,
                         ::testing::Values(kDefault, kIncremental,
                                           kRepresentations));

TEST_P(HpackEncoderTest, SingleDynamicIndex) {
  encoder_.SetHeaderListener(
      [this](absl::string_view name, absl::string_view value) {
        this->SaveHeaders(name, value);
      });

  ExpectIndex(DynamicIndexToWireIndex(key_2_index_));

  quiche::HttpHeaderBlock headers;
  headers[key_2_->name()] = key_2_->value();
  CompareWithExpectedEncoding(headers);
  EXPECT_THAT(headers_observed_,
              ElementsAre(Pair(key_2_->name(), key_2_->value())));
}

TEST_P(HpackEncoderTest, SingleStaticIndex) {
  ExpectIndex(kStaticEntryIndex);

  quiche::HttpHeaderBlock headers;
  headers[static_->name()] = static_->value();
  CompareWithExpectedEncoding(headers);
}

TEST_P(HpackEncoderTest, SingleStaticIndexTooLarge) {
  peer_.table()->SetMaxSize(1);  // Also evicts all fixtures.
  ExpectIndex(kStaticEntryIndex);

  quiche::HttpHeaderBlock headers;
  headers[static_->name()] = static_->value();
  CompareWithExpectedEncoding(headers);

  EXPECT_EQ(0u, peer_.table_peer().dynamic_entries()->size());
}

TEST_P(HpackEncoderTest, SingleLiteralWithIndexName) {
  ExpectIndexedLiteral(DynamicIndexToWireIndex(key_2_index_), "value3");

  quiche::HttpHeaderBlock headers;
  headers[key_2_->name()] = "value3";
  CompareWithExpectedEncoding(headers);

  // A new entry was inserted and added to the reference set.
  HpackEntry* new_entry = peer_.table_peer().dynamic_entries()->front().get();
  EXPECT_EQ(new_entry->name(), key_2_->name());
  EXPECT_EQ(new_entry->value(), "value3");
}

TEST_P(HpackEncoderTest, SingleLiteralWithLiteralName) {
  ExpectIndexedLiteral("key3", "value3");

  quiche::HttpHeaderBlock headers;
  headers["key3"] = "value3";
  CompareWithExpectedEncoding(headers);

  HpackEntry* new_entry = peer_.table_peer().dynamic_entries()->front().get();
  EXPECT_EQ(new_entry->name(), "key3");
  EXPECT_EQ(new_entry->value(), "value3");
}

TEST_P(HpackEncoderTest, SingleLiteralTooLarge) {
  peer_.table()->SetMaxSize(1);  // Also evicts all fixtures.

  ExpectIndexedLiteral("key3", "value3");

  // A header overflowing the header table is still emitted.
  // The header table is empty.
  quiche::HttpHeaderBlock headers;
  headers["key3"] = "value3";
  CompareWithExpectedEncoding(headers);

  EXPECT_EQ(0u, peer_.table_peer().dynamic_entries()->size());
}

TEST_P(HpackEncoderTest, EmitThanEvict) {
  // |key_1_| is toggled and placed into the reference set,
  // and then immediately evicted by "key3".
  ExpectIndex(DynamicIndexToWireIndex(key_1_index_));
  ExpectIndexedLiteral("key3", "value3");

  quiche::HttpHeaderBlock headers;
  headers[key_1_->name()] = key_1_->value();
  headers["key3"] = "value3";
  CompareWithExpectedEncoding(headers);
}

TEST_P(HpackEncoderTest, CookieHeaderIsCrumbled) {
  ExpectIndex(DynamicIndexToWireIndex(cookie_a_index_));
  ExpectIndex(DynamicIndexToWireIndex(cookie_c_index_));
  ExpectIndexedLiteral(peer_.table()->GetByName("cookie"), "e=ff");

  quiche::HttpHeaderBlock headers;
  headers["cookie"] = "a=bb; c=dd; e=ff";
  CompareWithExpectedEncoding(headers);
}

TEST_P(HpackEncoderTest, CookieHeaderIsNotCrumbled) {
  encoder_.DisableCookieCrumbling();
  ExpectIndexedLiteral(peer_.table()->GetByName("cookie"), "a=bb; c=dd; e=ff");

  quiche::HttpHeaderBlock headers;
  headers["cookie"] = "a=bb; c=dd; e=ff";
  CompareWithExpectedEncoding(headers);
}

TEST_P(HpackEncoderTest, MultiValuedHeadersNotCrumbled) {
  ExpectIndexedLiteral("foo", "bar, baz");
  quiche::HttpHeaderBlock headers;
  headers["foo"] = "bar, baz";
  CompareWithExpectedEncoding(headers);
}

TEST_P(HpackEncoderTest, StringsDynamicallySelectHuffmanCoding) {
  // Compactable string. Uses Huffman coding.
  peer_.EmitString("feedbeef");
  expected_.AppendPrefix(kStringLiteralHuffmanEncoded);
  expected_.AppendUint32(6);
  expected_.AppendBytes("\x94\xA5\x92\x32\x96_");

  // Non-compactable. Uses identity coding.
  peer_.EmitString("@@@@@@");
  expected_.AppendPrefix(kStringLiteralIdentityEncoded);
  expected_.AppendUint32(6);
  expected_.AppendBytes("@@@@@@");

  std::string actual_out;
  std::string expected_out = expected_.TakeString();
  peer_.TakeString(&actual_out);
  EXPECT_EQ(expected_out, actual_out);
}

TEST_P(HpackEncoderTest, EncodingWithoutCompression) {
  encoder_.SetHeaderListener(
      [this](absl::string_view name, absl::string_view value) {
        this->SaveHeaders(name, value);
      });
  encoder_.DisableCompression();

  ExpectNonIndexedLiteral(":path", "/index.html");
  ExpectNonIndexedLiteral("cookie", "foo=bar");
  ExpectNonIndexedLiteral("cookie", "baz=bing");
  if (strategy_ == kRepresentations) {
    ExpectNonIndexedLiteral("hello", std::string("goodbye\0aloha", 13));
  } else {
    ExpectNonIndexedLiteral("hello", "goodbye");
    ExpectNonIndexedLiteral("hello", "aloha");
  }
  ExpectNonIndexedLiteral("multivalue", "value1, value2");

  quiche::HttpHeaderBlock headers;
  headers[":path"] = "/index.html";
  headers["cookie"] = "foo=bar; baz=bing";
  headers["hello"] = "goodbye";
  headers.AppendValueOrAddHeader("hello", "aloha");
  headers["multivalue"] = "value1, value2";

  CompareWithExpectedEncoding(headers);

  if (strategy_ == kRepresentations) {
    EXPECT_THAT(
        headers_observed_,
        ElementsAre(Pair(":path", "/index.html"), Pair("cookie", "foo=bar"),
                    Pair("cookie", "baz=bing"),
                    Pair("hello", absl::string_view("goodbye\0aloha", 13)),
                    Pair("multivalue", "value1, value2")));
  } else {
    EXPECT_THAT(
        headers_observed_,
        ElementsAre(Pair(":path", "/index.html"), Pair("cookie", "foo=bar"),
                    Pair("cookie", "baz=bing"), Pair("hello", "goodbye"),
                    Pair("hello", "aloha"),
                    Pair("multivalue", "value1, value2")));
  }
  EXPECT_EQ(kInitialDynamicTableSize, encoder_.GetDynamicTableSize());
}

TEST_P(HpackEncoderTest, MultipleEncodingPasses) {
  encoder_.SetHeaderListener(
      [this](absl::string_view name, absl::string_view value) {
        this->SaveHeaders(name, value);
      });

  // Pass 1.
  {
    quiche::HttpHeaderBlock headers;
    headers["key1"] = "value1";
    headers["cookie"] = "a=bb";

    ExpectIndex(DynamicIndexToWireIndex(key_1_index_));
    ExpectIndex(DynamicIndexToWireIndex(cookie_a_index_));
    CompareWithExpectedEncoding(headers);
  }
  // Header table is:
  // 65: key1: value1
  // 64: key2: value2
  // 63: cookie: a=bb
  // 62: cookie: c=dd
  // Pass 2.
  {
    quiche::HttpHeaderBlock headers;
    headers["key2"] = "value2";
    headers["cookie"] = "c=dd; e=ff";

    // "key2: value2"
    ExpectIndex(DynamicIndexToWireIndex(key_2_index_));
    // "cookie: c=dd"
    ExpectIndex(DynamicIndexToWireIndex(cookie_c_index_));
    // This cookie evicts |key1| from the dynamic table.
    ExpectIndexedLiteral(peer_.table()->GetByName("cookie"), "e=ff");
    dynamic_table_insertions_++;

    CompareWithExpectedEncoding(headers);
  }
  // Header table is:
  // 65: key2: value2
  // 64: cookie: a=bb
  // 63: cookie: c=dd
  // 62: cookie: e=ff
  // Pass 3.
  {
    quiche::HttpHeaderBlock headers;
    headers["key2"] = "value2";
    headers["cookie"] = "a=bb; b=cc; c=dd";

    // "key2: value2"
    EXPECT_EQ(65u, DynamicIndexToWireIndex(key_2_index_));
    ExpectIndex(DynamicIndexToWireIndex(key_2_index_));
    // "cookie: a=bb"
    EXPECT_EQ(64u, DynamicIndexToWireIndex(cookie_a_index_));
    ExpectIndex(DynamicIndexToWireIndex(cookie_a_index_));
    // This cookie evicts |key2| from the dynamic table.
    ExpectIndexedLiteral(peer_.table()->GetByName("cookie"), "b=cc");
    dynamic_table_insertions_++;
    // "cookie: c=dd"
    ExpectIndex(DynamicIndexToWireIndex(cookie_c_index_));

    CompareWithExpectedEncoding(headers);
  }

  // clang-format off
  EXPECT_THAT(headers_observed_,
              ElementsAre(Pair("key1", "value1"),
                          Pair("cookie", "a=bb"),
                          Pair("key2", "value2"),
                          Pair("cookie", "c=dd"),
                          Pair("cookie", "e=ff"),
                          Pair("key2", "value2"),
                          Pair("cookie", "a=bb"),
                          Pair("cookie", "b=cc"),
                          Pair("cookie", "c=dd")));
  // clang-format on
}

TEST_P(HpackEncoderTest, PseudoHeadersFirst) {
  quiche::HttpHeaderBlock headers;
  // A pseudo-header that should not be indexed.
  headers[":path"] = "/spam/eggs.html";
  // A pseudo-header to be indexed.
  headers[":authority"] = "www.example.com";
  // A regular header which precedes ":" alphabetically, should still be encoded
  // after pseudo-headers.
  headers["-foo"] = "bar";
  headers["foo"] = "bar";
  headers["cookie"] = "c=dd";

  // Headers are indexed in the order in which they were added.
  // This entry pushes "cookie: a=bb" back to 63.
  ExpectNonIndexedLiteralWithNameIndex(peer_.table()->GetByName(":path"),
                                       "/spam/eggs.html");
  ExpectIndexedLiteral(peer_.table()->GetByName(":authority"),
                       "www.example.com");
  ExpectIndexedLiteral("-foo", "bar");
  ExpectIndexedLiteral("foo", "bar");
  ExpectIndexedLiteral(peer_.table()->GetByName("cookie"), "c=dd");
  CompareWithExpectedEncoding(headers);
}

TEST_P(HpackEncoderTest, CookieToCrumbs) {
  test::HpackEncoderPeer peer(nullptr);
  std::vector<absl::string_view> out;

  // Leading and trailing whitespace is consumed. A space after ';' is consumed.
  // All other spaces remain. ';' at beginning and end of string produce empty
  // crumbs.
  // See section 8.1.3.4 "Compressing the Cookie Header Field" in the HTTP/2
  // specification at http://tools.ietf.org/html/draft-ietf-httpbis-http2-11
  peer.CookieToCrumbs(" foo=1;bar=2 ; bar=3;  bing=4; ", &out);
  EXPECT_THAT(out, ElementsAre("foo=1", "bar=2 ", "bar=3", " bing=4", ""));

  peer.CookieToCrumbs(";;foo = bar ;; ;baz =bing", &out);
  EXPECT_THAT(out, ElementsAre("", "", "foo = bar ", "", "", "baz =bing"));

  peer.CookieToCrumbs("baz=bing; foo=bar; baz=bing", &out);
  EXPECT_THAT(out, ElementsAre("baz=bing", "foo=bar", "baz=bing"));

  peer.CookieToCrumbs("baz=bing", &out);
  EXPECT_THAT(out, ElementsAre("baz=bing"));

  peer.CookieToCrumbs("", &out);
  EXPECT_THAT(out, ElementsAre(""));

  peer.CookieToCrumbs("foo;bar; baz;baz;bing;", &out);
  EXPECT_THAT(out, ElementsAre("foo", "bar", "baz", "baz", "bing", ""));

  peer.CookieToCrumbs(" \t foo=1;bar=2 ; bar=3;\t  ", &out);
  EXPECT_THAT(out, ElementsAre("foo=1", "bar=2 ", "bar=3", ""));

  peer.CookieToCrumbs(" \t foo=1;bar=2 ; bar=3 \t  ", &out);
  EXPECT_THAT(out, ElementsAre("foo=1", "bar=2 ", "bar=3"));
}

TEST_P(HpackEncoderTest, DecomposeRepresentation) {
  test::HpackEncoderPeer peer(nullptr);
  std::vector<absl::string_view> out;

  peer.DecomposeRepresentation("", &out);
  EXPECT_THAT(out, ElementsAre(""));

  peer.DecomposeRepresentation("foobar", &out);
  EXPECT_THAT(out, ElementsAre("foobar"));

  peer.DecomposeRepresentation(absl::string_view("foo\0bar", 7), &out);
  EXPECT_THAT(out, ElementsAre("foo", "bar"));

  peer.DecomposeRepresentation(absl::string_view("\0foo\0bar", 8), &out);
  EXPECT_THAT(out, ElementsAre("", "foo", "bar"));

  peer.DecomposeRepresentation(absl::string_view("foo\0bar\0", 8), &out);
  EXPECT_THAT(out, ElementsAre("foo", "bar", ""));

  peer.DecomposeRepresentation(absl::string_view("\0foo\0bar\0", 9), &out);
  EXPECT_THAT(out, ElementsAre("", "foo", "bar", ""));
}

// Test that encoded headers do not have \0-delimited multiple values, as this
// became disallowed in HTTP/2 draft-14.
TEST_P(HpackEncoderTest, CrumbleNullByteDelimitedValue) {
  if (strategy_ == kRepresentations) {
    // When HpackEncoder is asked to encode a list of Representations, the
    // caller must crumble null-delimited values.
    return;
  }
  quiche::HttpHeaderBlock headers;
  // A header field to be crumbled: "spam: foo\0bar".
  headers["spam"] = std::string("foo\0bar", 7);

  ExpectIndexedLiteral("spam", "foo");
  expected_.AppendPrefix(kLiteralIncrementalIndexOpcode);
  expected_.AppendUint32(62);
  expected_.AppendPrefix(kStringLiteralIdentityEncoded);
  expected_.AppendUint32(3);
  expected_.AppendBytes("bar");
  CompareWithExpectedEncoding(headers);
}

TEST_P(HpackEncoderTest, HeaderTableSizeUpdate) {
  encoder_.ApplyHeaderTableSizeSetting(1024);
  ExpectHeaderTableSizeUpdate(1024);
  ExpectIndexedLiteral("key3", "value3");

  quiche::HttpHeaderBlock headers;
  headers["key3"] = "value3";
  CompareWithExpectedEncoding(headers);

  HpackEntry* new_entry = peer_.table_peer().dynamic_entries()->front().get();
  EXPECT_EQ(new_entry->name(), "key3");
  EXPECT_EQ(new_entry->value(), "value3");
}

TEST_P(HpackEncoderTest, HeaderTableSizeUpdateWithMin) {
  const size_t starting_size = peer_.table()->settings_size_bound();
  encoder_.ApplyHeaderTableSizeSetting(starting_size - 2);
  encoder_.ApplyHeaderTableSizeSetting(starting_size - 1);
  // We must encode the low watermark, so the peer knows to evict entries
  // if necessary.
  ExpectHeaderTableSizeUpdate(starting_size - 2);
  ExpectHeaderTableSizeUpdate(starting_size - 1);
  ExpectIndexedLiteral("key3", "value3");

  quiche::HttpHeaderBlock headers;
  headers["key3"] = "value3";
  CompareWithExpectedEncoding(headers);

  HpackEntry* new_entry = peer_.table_peer().dynamic_entries()->front().get();
  EXPECT_EQ(new_entry->name(), "key3");
  EXPECT_EQ(new_entry->value(), "value3");
}

TEST_P(HpackEncoderTest, HeaderTableSizeUpdateWithExistingSize) {
  encoder_.ApplyHeaderTableSizeSetting(peer_.table()->settings_size_bound());
  // No encoded size update.
  ExpectIndexedLiteral("key3", "value3");

  quiche::HttpHeaderBlock headers;
  headers["key3"] = "value3";
  CompareWithExpectedEncoding(headers);

  HpackEntry* new_entry = peer_.table_peer().dynamic_entries()->front().get();
  EXPECT_EQ(new_entry->name(), "key3");
  EXPECT_EQ(new_entry->value(), "value3");
}

TEST_P(HpackEncoderTest, HeaderTableSizeUpdatesWithGreaterSize) {
  const size_t starting_size = peer_.table()->settings_size_bound();
  encoder_.ApplyHeaderTableSizeSetting(starting_size + 1);
  encoder_.ApplyHeaderTableSizeSetting(starting_size + 2);
  // Only a single size update to the final size.
  ExpectHeaderTableSizeUpdate(starting_size + 2);
  ExpectIndexedLiteral("key3", "value3");

  quiche::HttpHeaderBlock headers;
  headers["key3"] = "value3";
  CompareWithExpectedEncoding(headers);

  HpackEntry* new_entry = peer_.table_peer().dynamic_entries()->front().get();
  EXPECT_EQ(new_entry->name(), "key3");
  EXPECT_EQ(new_entry->value(), "value3");
}

}  // namespace

}  // namespace spdy
```