Response:
The user is asking for an analysis of a C++ source code file. I need to identify the file's purpose, its relationship to JavaScript (if any), illustrate its logic with examples, highlight common usage errors, and describe how a user might end up interacting with this code for debugging purposes.

**Plan:**

1. **Identify the core functionality:** The file `hpack_decoder_state_test.cc` suggests it's a test file for `hpack_decoder_state.h`. The "HPACK" part hints at HTTP/2 header compression.
2. **Explain HPACK decoding:**  Describe the role of `HpackDecoderState` in decoding HTTP/2 header blocks.
3. **JavaScript relationship:**  Consider how HTTP/2 and HPACK relate to web browsers and JavaScript's interaction with network requests.
4. **Logic examples:**  Use the test cases within the file to demonstrate the input and expected output of the decoder under different scenarios.
5. **Common errors:**  Analyze the test cases that focus on error conditions and explain what user actions or programming mistakes might lead to these errors.
6. **Debugging scenario:**  Describe a typical user interaction (e.g., a website loading slowly) that could lead a developer to investigate the HPACK decoding process.
这个文件 `hpack_decoder_state_test.cc` 是 Chromium 网络栈中 QUIC 协议库的一部分，它专门用于测试 **HPACK 解码器状态 (`HpackDecoderState`)** 的功能。HPACK (HTTP/2 Header Compression) 是一种用于压缩 HTTP/2 头部的方法，旨在减少网络传输的开销。

**主要功能:**

1. **单元测试:**  该文件包含了大量的单元测试用例，用于验证 `HpackDecoderState` 类的各种功能和边界情况。
2. **状态管理测试:** 它测试 HPACK 解码器的状态管理，例如解码过程中的不同状态转换，以及如何处理不同的 HPACK 编码。
3. **动态表测试:**  HPACK 使用一个动态表来存储最近使用的头部字段，以实现高效的压缩。该文件测试了动态表的添加、查找、删除和大小调整等操作。
4. **静态表测试:**  HPACK 还定义了一个静态表，包含了一些常见的头部字段。该文件可能间接测试了对静态表的使用。
5. **错误处理测试:** 测试解码器在遇到错误的 HPACK 编码时如何进行处理，例如无效的索引、错误的霍夫曼编码等。
6. **设置更新测试:** 测试对 HPACK 动态表大小的更新处理。

**与 JavaScript 的关系:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它所测试的功能直接影响着 web 浏览器（通常使用 JavaScript 编写 web 应用）的网络性能。

*   **浏览器中的 HTTP/2 支持:** 现代 web 浏览器广泛支持 HTTP/2 协议，其中包括 HPACK 头部压缩。当浏览器发起 HTTP/2 请求或接收 HTTP/2 响应时，会使用 HPACK 进行头部的编码和解码。
*   **JavaScript 发起的请求:** JavaScript 代码可以使用 `fetch` API 或 `XMLHttpRequest` 对象发起 HTTP 请求。如果服务器支持 HTTP/2，浏览器会自动使用 HTTP/2，并依赖底层的 C++ 代码（包括此处测试的 HPACK 解码器）来处理头部。
*   **性能影响:**  HPACK 的正确解码对于网页的加载速度至关重要。如果 HPACK 解码出现问题，可能会导致请求失败、头部信息丢失，或者性能下降。

**举例说明:**

假设一个 JavaScript 代码发起一个 HTTP/2 GET 请求：

```javascript
fetch('https://www.example.com/data')
  .then(response => {
    console.log(response.headers.get('content-type'));
    return response.json();
  })
  .then(data => console.log(data));
```

当浏览器接收到来自 `www.example.com` 服务器的响应时，服务器发送的 HTTP 响应头部可能使用 HPACK 进行了压缩。Chromium 的网络栈会使用 `HpackDecoderState` 来解码这些压缩的头部，例如 `content-type`。解码后的头部信息会被传递给 JavaScript，使得 `response.headers.get('content-type')` 可以正确获取到头部的值。

**逻辑推理 (假设输入与输出):**

假设输入是一个表示 HPACK 编码的字节序列，对应一个包含 `:status: 200` 和 `content-type: application/json` 两个头部的块。

*   **假设输入:**  `0x88 0x03 0x3a 0x73 0x74 0x61 0x74 0x75 0x73 0x03 0x32 0x30 0x30 0x40 0x0c 0x63 0x6f 0x6e 0x74 0x65 0x6e 0x74 0x2d 0x74 0x79 0x70 0x65 0x10 0x61 0x70 0x70 0x6c 0x69 0x63 0x61 0x74 0x69 0x6f 0x6e 0x2f 0x6a 0x73 0x6f 0x6e` (这是一个简化的假设，实际的 HPACK 编码会更复杂)
*   **预期输出 (通过 MockHpackDecoderListener 的回调):**
    1. `OnHeaderListStart()` 被调用。
    2. `OnHeader(":status", "200")` 被调用。
    3. `OnHeader("content-type", "application/json")` 被调用。
    4. `OnHeaderListEnd()` 被调用。

**用户或编程常见的使用错误 (以及如何触发测试中的错误):**

1. **动态表大小设置错误:**  HTTP/2 允许客户端和服务器协商 HPACK 动态表的大小。如果设置的值超过了允许的范围，或者尝试多次设置，就会触发错误。
    *   **测试用例:** `OptionalTableSizeChanges`, `RequiredTableSizeChangeBeforeHeader`, `InvalidRequiredSizeUpdate`, `InvalidOptionalSizeUpdate` 等测试了这些场景。
    *   **用户操作/编程错误:** 服务器配置了过大的 `SETTINGS_HEADER_TABLE_SIZE`，或者在发送头部块的过程中错误地发送了多个动态表大小更新。

2. **使用了无效的索引:** HPACK 使用索引来引用静态表或动态表中的头部字段。如果使用了超出范围的索引，解码器会报错。
    *   **测试用例:** `InvalidStaticIndex`, `InvalidDynamicIndex`, `InvalidNameIndex` 测试了这些情况。
    *   **用户操作/编程错误:** 编码器错误地生成了带有无效索引的 HPACK 块。

3. **霍夫曼解码错误:** HPACK 可以使用霍夫曼编码来进一步压缩头部字段的值。如果霍夫曼编码的数据不正确，解码器会报错。
    *   **测试用例:** `ErrorsSuppressCallbacks` 测试了 `OnHpackDecodeError(HpackDecodingError::kNameHuffmanError)` 的情况。
    *   **用户操作/编程错误:** 编码器在进行霍夫曼编码时引入了错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户访问网页:** 用户在浏览器中输入一个网址或点击一个链接，浏览器开始加载网页。
2. **浏览器发起 HTTP/2 连接:** 如果服务器支持 HTTP/2，浏览器会与服务器建立 HTTP/2 连接。
3. **接收到 HTTP/2 响应:** 服务器发送 HTTP 响应，其头部信息使用 HPACK 进行了压缩。
4. **Chromium 网络栈处理响应:** Chromium 的网络栈接收到这些压缩的头部数据。
5. **调用 HpackDecoderState 进行解码:** 网络栈会创建 `HpackDecoderState` 的实例，并逐步输入 HPACK 编码的字节序列。
6. **调试场景:**
    *   **网页加载缓慢或失败:** 用户发现网页加载很慢，或者某些资源加载失败。
    *   **开发者工具检查:** 开发者打开浏览器的开发者工具，查看 "Network" 标签，可能会发现某些请求的头部信息不正确，或者请求一直处于等待状态。
    *   **网络日志分析:**  网络工程师可能会捕获网络数据包，分析 HTTP/2 的帧，发现 HPACK 编码的头部数据存在异常。
    *   **断点调试 Chromium 源码:**  为了深入调查问题，开发人员可能会在 Chromium 的网络栈源码中设置断点，例如在 `HpackDecoderState::OnIndexedHeader` 或 `HpackDecoderState::OnLiteralNameAndValue` 等方法中，来观察 HPACK 解码的具体过程，查看解码状态和动态表的内容，从而定位问题是否出在 HPACK 解码环节。

总而言之，`hpack_decoder_state_test.cc` 文件是确保 Chromium 网络栈能够正确、高效地解码 HTTP/2 头部压缩的关键组成部分，它直接影响着用户的网络浏览体验。 当用户遇到与网页加载相关的性能问题时，开发者可能会通过分析网络数据包或调试浏览器源码来排查 HPACK 解码器是否存在问题。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/http2/hpack/decoder/hpack_decoder_state_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "quiche/http2/hpack/decoder/hpack_decoder_state.h"

// Tests of HpackDecoderState.

#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/http2/hpack/http2_hpack_constants.h"
#include "quiche/http2/http2_constants.h"
#include "quiche/http2/test_tools/verify_macros.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"

using ::testing::AssertionResult;
using ::testing::AssertionSuccess;
using ::testing::Eq;
using ::testing::Mock;
using ::testing::StrictMock;

namespace http2 {
namespace test {
class HpackDecoderStatePeer {
 public:
  static HpackDecoderTables* GetDecoderTables(HpackDecoderState* state) {
    return &state->decoder_tables_;
  }
};

namespace {

class MockHpackDecoderListener : public HpackDecoderListener {
 public:
  MOCK_METHOD(void, OnHeaderListStart, (), (override));
  MOCK_METHOD(void, OnHeader, (absl::string_view name, absl::string_view value),
              (override));
  MOCK_METHOD(void, OnHeaderListEnd, (), (override));
  MOCK_METHOD(void, OnHeaderErrorDetected, (absl::string_view error_message),
              (override));
};

enum StringBacking { UNBUFFERED, BUFFERED };

class HpackDecoderStateTest : public quiche::test::QuicheTest {
 protected:
  HpackDecoderStateTest() : decoder_state_(&listener_) {}

  HpackDecoderTables* GetDecoderTables() {
    return HpackDecoderStatePeer::GetDecoderTables(&decoder_state_);
  }

  const HpackStringPair* Lookup(size_t index) {
    return GetDecoderTables()->Lookup(index);
  }

  size_t current_header_table_size() {
    return GetDecoderTables()->current_header_table_size();
  }

  size_t header_table_size_limit() {
    return GetDecoderTables()->header_table_size_limit();
  }

  void set_header_table_size_limit(size_t size) {
    GetDecoderTables()->DynamicTableSizeUpdate(size);
  }

  void SetStringBuffer(absl::string_view s, StringBacking backing,
                       HpackDecoderStringBuffer* string_buffer) {
    string_buffer->OnStart(false, s.size());
    EXPECT_TRUE(string_buffer->OnData(s.data(), s.size()));
    EXPECT_TRUE(string_buffer->OnEnd());
    if (backing == BUFFERED) {
      string_buffer->BufferStringIfUnbuffered();
    }
  }

  void SetName(absl::string_view s, StringBacking backing) {
    SetStringBuffer(s, backing, &name_buffer_);
  }

  void SetValue(absl::string_view s, StringBacking backing) {
    SetStringBuffer(s, backing, &value_buffer_);
  }

  void SendStartAndVerifyCallback() {
    EXPECT_CALL(listener_, OnHeaderListStart());
    decoder_state_.OnHeaderBlockStart();
    Mock::VerifyAndClearExpectations(&listener_);
  }

  void SendSizeUpdate(size_t size) {
    decoder_state_.OnDynamicTableSizeUpdate(size);
    Mock::VerifyAndClearExpectations(&listener_);
  }

  void SendIndexAndVerifyCallback(size_t index,
                                  HpackEntryType /*expected_type*/,
                                  absl::string_view expected_name,
                                  absl::string_view expected_value) {
    EXPECT_CALL(listener_, OnHeader(Eq(expected_name), Eq(expected_value)));
    decoder_state_.OnIndexedHeader(index);
    Mock::VerifyAndClearExpectations(&listener_);
  }

  void SendValueAndVerifyCallback(size_t name_index, HpackEntryType entry_type,
                                  absl::string_view name,
                                  absl::string_view value,
                                  StringBacking value_backing) {
    SetValue(value, value_backing);
    EXPECT_CALL(listener_, OnHeader(Eq(name), Eq(value)));
    decoder_state_.OnNameIndexAndLiteralValue(entry_type, name_index,
                                              &value_buffer_);
    Mock::VerifyAndClearExpectations(&listener_);
  }

  void SendNameAndValueAndVerifyCallback(HpackEntryType entry_type,
                                         absl::string_view name,
                                         StringBacking name_backing,
                                         absl::string_view value,
                                         StringBacking value_backing) {
    SetName(name, name_backing);
    SetValue(value, value_backing);
    EXPECT_CALL(listener_, OnHeader(Eq(name), Eq(value)));
    decoder_state_.OnLiteralNameAndValue(entry_type, &name_buffer_,
                                         &value_buffer_);
    Mock::VerifyAndClearExpectations(&listener_);
  }

  void SendEndAndVerifyCallback() {
    EXPECT_CALL(listener_, OnHeaderListEnd());
    decoder_state_.OnHeaderBlockEnd();
    Mock::VerifyAndClearExpectations(&listener_);
  }

  // dynamic_index is one-based, because that is the way RFC 7541 shows it.
  AssertionResult VerifyEntry(size_t dynamic_index, absl::string_view name,
                              absl::string_view value) {
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
      const std::vector<std::pair<absl::string_view, absl::string_view>>&
          entries) {
    size_t index = 1;
    for (const auto& entry : entries) {
      HTTP2_VERIFY_SUCCESS(VerifyEntry(index, entry.first, entry.second));
      ++index;
    }
    HTTP2_VERIFY_SUCCESS(VerifyNoEntry(index));
    return AssertionSuccess();
  }

  StrictMock<MockHpackDecoderListener> listener_;
  HpackDecoderState decoder_state_;
  HpackDecoderStringBuffer name_buffer_, value_buffer_;
};

// Test based on RFC 7541, section C.3: Request Examples without Huffman Coding.
// This section shows several consecutive header lists, corresponding to HTTP
// requests, on the same connection.
TEST_F(HpackDecoderStateTest, C3_RequestExamples) {
  // C.3.1 First Request
  //
  // Header list to encode:
  //
  //   :method: GET
  //   :scheme: http
  //   :path: /
  //   :authority: www.example.com

  SendStartAndVerifyCallback();
  SendIndexAndVerifyCallback(2, HpackEntryType::kIndexedHeader, ":method",
                             "GET");
  SendIndexAndVerifyCallback(6, HpackEntryType::kIndexedHeader, ":scheme",
                             "http");
  SendIndexAndVerifyCallback(4, HpackEntryType::kIndexedHeader, ":path", "/");
  SendValueAndVerifyCallback(1, HpackEntryType::kIndexedLiteralHeader,
                             ":authority", "www.example.com", UNBUFFERED);
  SendEndAndVerifyCallback();

  // Dynamic Table (after decoding):
  //
  //   [  1] (s =  57) :authority: www.example.com
  //         Table size:  57

  ASSERT_TRUE(VerifyDynamicTableContents({{":authority", "www.example.com"}}));
  ASSERT_EQ(57u, current_header_table_size());

  // C.3.2 Second Request
  //
  // Header list to encode:
  //
  //   :method: GET
  //   :scheme: http
  //   :path: /
  //   :authority: www.example.com
  //   cache-control: no-cache

  SendStartAndVerifyCallback();
  SendIndexAndVerifyCallback(2, HpackEntryType::kIndexedHeader, ":method",
                             "GET");
  SendIndexAndVerifyCallback(6, HpackEntryType::kIndexedHeader, ":scheme",
                             "http");
  SendIndexAndVerifyCallback(4, HpackEntryType::kIndexedHeader, ":path", "/");
  SendIndexAndVerifyCallback(62, HpackEntryType::kIndexedHeader, ":authority",
                             "www.example.com");
  SendValueAndVerifyCallback(24, HpackEntryType::kIndexedLiteralHeader,
                             "cache-control", "no-cache", UNBUFFERED);
  SendEndAndVerifyCallback();

  // Dynamic Table (after decoding):
  //
  //   [  1] (s =  53) cache-control: no-cache
  //   [  2] (s =  57) :authority: www.example.com
  //         Table size: 110

  ASSERT_TRUE(VerifyDynamicTableContents(
      {{"cache-control", "no-cache"}, {":authority", "www.example.com"}}));
  ASSERT_EQ(110u, current_header_table_size());

  // C.3.3 Third Request
  //
  // Header list to encode:
  //
  //   :method: GET
  //   :scheme: https
  //   :path: /index.html
  //   :authority: www.example.com
  //   custom-key: custom-value

  SendStartAndVerifyCallback();
  SendIndexAndVerifyCallback(2, HpackEntryType::kIndexedHeader, ":method",
                             "GET");
  SendIndexAndVerifyCallback(7, HpackEntryType::kIndexedHeader, ":scheme",
                             "https");
  SendIndexAndVerifyCallback(5, HpackEntryType::kIndexedHeader, ":path",
                             "/index.html");
  SendIndexAndVerifyCallback(63, HpackEntryType::kIndexedHeader, ":authority",
                             "www.example.com");
  SendNameAndValueAndVerifyCallback(HpackEntryType::kIndexedLiteralHeader,
                                    "custom-key", UNBUFFERED, "custom-value",
                                    UNBUFFERED);
  SendEndAndVerifyCallback();

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
TEST_F(HpackDecoderStateTest, C5_ResponseExamples) {
  set_header_table_size_limit(256);

  // C.5.1 First Response
  //
  // Header list to encode:
  //
  //   :status: 302
  //   cache-control: private
  //   date: Mon, 21 Oct 2013 20:13:21 GMT
  //   location: https://www.example.com

  SendStartAndVerifyCallback();
  SendValueAndVerifyCallback(8, HpackEntryType::kIndexedLiteralHeader,
                             ":status", "302", BUFFERED);
  SendValueAndVerifyCallback(24, HpackEntryType::kIndexedLiteralHeader,
                             "cache-control", "private", UNBUFFERED);
  SendValueAndVerifyCallback(33, HpackEntryType::kIndexedLiteralHeader, "date",
                             "Mon, 21 Oct 2013 20:13:21 GMT", UNBUFFERED);
  SendValueAndVerifyCallback(46, HpackEntryType::kIndexedLiteralHeader,
                             "location", "https://www.example.com", UNBUFFERED);
  SendEndAndVerifyCallback();

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

  SendStartAndVerifyCallback();
  SendValueAndVerifyCallback(8, HpackEntryType::kIndexedLiteralHeader,
                             ":status", "307", BUFFERED);
  SendIndexAndVerifyCallback(65, HpackEntryType::kIndexedHeader,
                             "cache-control", "private");
  SendIndexAndVerifyCallback(64, HpackEntryType::kIndexedHeader, "date",
                             "Mon, 21 Oct 2013 20:13:21 GMT");
  SendIndexAndVerifyCallback(63, HpackEntryType::kIndexedHeader, "location",
                             "https://www.example.com");
  SendEndAndVerifyCallback();

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

  SendStartAndVerifyCallback();
  SendIndexAndVerifyCallback(8, HpackEntryType::kIndexedHeader, ":status",
                             "200");
  SendIndexAndVerifyCallback(65, HpackEntryType::kIndexedHeader,
                             "cache-control", "private");
  SendValueAndVerifyCallback(33, HpackEntryType::kIndexedLiteralHeader, "date",
                             "Mon, 21 Oct 2013 20:13:22 GMT", BUFFERED);
  SendIndexAndVerifyCallback(64, HpackEntryType::kIndexedHeader, "location",
                             "https://www.example.com");
  SendValueAndVerifyCallback(26, HpackEntryType::kIndexedLiteralHeader,
                             "content-encoding", "gzip", UNBUFFERED);
  SendValueAndVerifyCallback(
      55, HpackEntryType::kIndexedLiteralHeader, "set-cookie",
      "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1", BUFFERED);
  SendEndAndVerifyCallback();

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

// Confirm that the table size can be changed, but at most twice.
TEST_F(HpackDecoderStateTest, OptionalTableSizeChanges) {
  SendStartAndVerifyCallback();
  EXPECT_EQ(Http2SettingsInfo::DefaultHeaderTableSize(),
            header_table_size_limit());
  SendSizeUpdate(1024);
  EXPECT_EQ(1024u, header_table_size_limit());
  SendSizeUpdate(0);
  EXPECT_EQ(0u, header_table_size_limit());

  // Three updates aren't allowed.
  EXPECT_CALL(listener_, OnHeaderErrorDetected(
                             Eq("Dynamic table size update not allowed")));
  SendSizeUpdate(0);
}

// Confirm that required size updates are indeed required before headers.
TEST_F(HpackDecoderStateTest, RequiredTableSizeChangeBeforeHeader) {
  EXPECT_EQ(4096u, decoder_state_.GetCurrentHeaderTableSizeSetting());
  decoder_state_.ApplyHeaderTableSizeSetting(1024);
  decoder_state_.ApplyHeaderTableSizeSetting(2048);
  EXPECT_EQ(2048u, decoder_state_.GetCurrentHeaderTableSizeSetting());

  // First provide the required update, and an allowed second update.
  SendStartAndVerifyCallback();
  EXPECT_EQ(Http2SettingsInfo::DefaultHeaderTableSize(),
            header_table_size_limit());
  SendSizeUpdate(1024);
  EXPECT_EQ(1024u, header_table_size_limit());
  SendSizeUpdate(1500);
  EXPECT_EQ(1500u, header_table_size_limit());
  SendEndAndVerifyCallback();

  // Another HPACK block, but this time missing the required size update.
  decoder_state_.ApplyHeaderTableSizeSetting(1024);
  EXPECT_EQ(1024u, decoder_state_.GetCurrentHeaderTableSizeSetting());
  SendStartAndVerifyCallback();
  EXPECT_CALL(listener_,
              OnHeaderErrorDetected(Eq("Missing dynamic table size update")));
  decoder_state_.OnIndexedHeader(1);

  // Further decoded entries are ignored.
  decoder_state_.OnIndexedHeader(1);
  decoder_state_.OnDynamicTableSizeUpdate(1);
  SetValue("value", UNBUFFERED);
  decoder_state_.OnNameIndexAndLiteralValue(
      HpackEntryType::kIndexedLiteralHeader, 4, &value_buffer_);
  SetName("name", UNBUFFERED);
  decoder_state_.OnLiteralNameAndValue(HpackEntryType::kIndexedLiteralHeader,
                                       &name_buffer_, &value_buffer_);
  decoder_state_.OnHeaderBlockEnd();
  decoder_state_.OnHpackDecodeError(HpackDecodingError::kIndexVarintError);
}

// Confirm that required size updates are validated.
TEST_F(HpackDecoderStateTest, InvalidRequiredSizeUpdate) {
  // Require a size update, but provide one that isn't small enough.
  decoder_state_.ApplyHeaderTableSizeSetting(1024);
  SendStartAndVerifyCallback();
  EXPECT_EQ(Http2SettingsInfo::DefaultHeaderTableSize(),
            header_table_size_limit());
  EXPECT_CALL(
      listener_,
      OnHeaderErrorDetected(
          Eq("Initial dynamic table size update is above low water mark")));
  SendSizeUpdate(2048);
}

// Confirm that required size updates are indeed required before the end.
TEST_F(HpackDecoderStateTest, RequiredTableSizeChangeBeforeEnd) {
  decoder_state_.ApplyHeaderTableSizeSetting(1024);
  SendStartAndVerifyCallback();
  EXPECT_CALL(listener_,
              OnHeaderErrorDetected(Eq("Missing dynamic table size update")));
  decoder_state_.OnHeaderBlockEnd();
}

// Confirm that optional size updates are validated.
TEST_F(HpackDecoderStateTest, InvalidOptionalSizeUpdate) {
  // Require a size update, but provide one that isn't small enough.
  SendStartAndVerifyCallback();
  EXPECT_EQ(Http2SettingsInfo::DefaultHeaderTableSize(),
            header_table_size_limit());
  EXPECT_CALL(listener_,
              OnHeaderErrorDetected(Eq(
                  "Dynamic table size update is above acknowledged setting")));
  SendSizeUpdate(Http2SettingsInfo::DefaultHeaderTableSize() + 1);
}

TEST_F(HpackDecoderStateTest, InvalidStaticIndex) {
  SendStartAndVerifyCallback();
  EXPECT_CALL(listener_,
              OnHeaderErrorDetected(
                  Eq("Invalid index in indexed header field representation")));
  decoder_state_.OnIndexedHeader(0);
}

TEST_F(HpackDecoderStateTest, InvalidDynamicIndex) {
  SendStartAndVerifyCallback();
  EXPECT_CALL(listener_,
              OnHeaderErrorDetected(
                  Eq("Invalid index in indexed header field representation")));
  decoder_state_.OnIndexedHeader(kFirstDynamicTableIndex);
}

TEST_F(HpackDecoderStateTest, InvalidNameIndex) {
  SendStartAndVerifyCallback();
  EXPECT_CALL(listener_,
              OnHeaderErrorDetected(Eq("Invalid index in literal header field "
                                       "with indexed name representation")));
  SetValue("value", UNBUFFERED);
  decoder_state_.OnNameIndexAndLiteralValue(
      HpackEntryType::kIndexedLiteralHeader, kFirstDynamicTableIndex,
      &value_buffer_);
}

TEST_F(HpackDecoderStateTest, ErrorsSuppressCallbacks) {
  SendStartAndVerifyCallback();
  EXPECT_CALL(listener_,
              OnHeaderErrorDetected(Eq("Name Huffman encoding error")));
  decoder_state_.OnHpackDecodeError(HpackDecodingError::kNameHuffmanError);

  // Further decoded entries are ignored.
  decoder_state_.OnIndexedHeader(1);
  decoder_state_.OnDynamicTableSizeUpdate(1);
  SetValue("value", UNBUFFERED);
  decoder_state_.OnNameIndexAndLiteralValue(
      HpackEntryType::kIndexedLiteralHeader, 4, &value_buffer_);
  SetName("name", UNBUFFERED);
  decoder_state_.OnLiteralNameAndValue(HpackEntryType::kIndexedLiteralHeader,
                                       &name_buffer_, &value_buffer_);
  decoder_state_.OnHeaderBlockEnd();
  decoder_state_.OnHpackDecodeError(HpackDecodingError::kIndexVarintError);
}

}  // namespace
}  // namespace test
}  // namespace http2
```