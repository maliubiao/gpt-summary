Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The filename `qpack_header_table_test.cc` immediately suggests this file contains tests for the `QpackHeaderTable` class. The `#include "quiche/quic/core/qpack/qpack_header_table.h"` confirms this. The overall goal is to ensure the `QpackHeaderTable` functions correctly.

2. **Recognize the Testing Framework:** The presence of `#include "quiche/quic/platform/api/quic_test.h"` and `TEST_F`, `TYPED_TEST`, `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_THAT`, `FieldsAre`, `StrictMock`, `MOCK_METHOD` strongly indicates the use of Google Test (gtest) or a similar testing framework. This tells us the file structure will involve test fixtures and individual test cases.

3. **Understand the Class Under Test:** The `QpackHeaderTable` is likely responsible for managing a header table used in the QPACK (QPACK Header Compression) protocol. This protocol is used in HTTP/3 over QUIC. Key aspects of a header table would involve:
    * Storing header name-value pairs.
    * A dynamic part that can be modified.
    * Interaction with a static table of predefined headers.
    * Managing table capacity.
    * Eviction policies when the table is full.
    * Lookup functionality.

4. **Analyze the Test Structure:**
    * **Test Fixtures:** The `QpackHeaderTableTest` template class is a test fixture. It sets up common resources (`SetUp`), provides helper functions (e.g., `EntryFitsDynamicTableCapacity`, `InsertEntry`), and holds the `table_` object being tested. The `MyTypes` type alias and `TYPED_TEST_SUITE` indicate that these tests are run against both `QpackEncoderHeaderTable` and `QpackDecoderHeaderTable`. This makes sense as they likely share a base class or interface. Specialized test fixtures like `QpackEncoderHeaderTableTest` and `QpackDecoderHeaderTableTest` are used for tests specific to those derived classes.
    * **Individual Test Cases:**  Each `TYPED_TEST` or `TEST_F` defines a specific test scenario (e.g., `MaxEntries`, `SetDynamicTableCapacity`, `FindStaticHeaderField`).

5. **Examine Key Test Areas:**  Go through the test cases and identify the functionalities being tested. Look for patterns:
    * **Capacity Management:** Tests related to `MaxEntries`, `SetDynamicTableCapacity`, `EntryFitsDynamicTableCapacity`.
    * **Insertion and Lookup:** Tests involving `InsertEntry`, `FindHeaderField`, `FindHeaderName`, `LookupEntry`. Pay attention to the differences between static and dynamic entries.
    * **Eviction:** Tests named `EvictByInsertion`, `EvictByUpdateTableSize`, `EvictOldestOfIdentical`, `EvictOldestOfSameName`.
    * **Encoder-Specific:** Tests like `MaxInsertSizeWithoutEvictingGivenEntry`, `draining_index`.
    * **Decoder-Specific:** Tests involving observers (`RegisterObserver`, `UnregisterObserver`, `Cancel`).

6. **Infer Functionality from Tests:** Even without seeing the `QpackHeaderTable` implementation, we can infer its methods and their behavior from the tests. For instance, the `FindHeaderField` and `FindHeaderName` tests suggest that the table can search for entries based on both name and value, or just name. The eviction tests indicate that the table has a capacity and needs to remove older entries when full.

7. **Consider JavaScript Relevance:** Since the context mentions Chromium's network stack, and that's related to web browsers, think about where header compression plays a role. HTTP/3 and QPACK directly impact how browsers and servers communicate. Therefore, JavaScript running in a browser will indirectly benefit from a correctly implemented `QpackHeaderTable` through faster page load times due to efficient header compression.

8. **Construct Example Scenarios:** Based on the tests, create illustrative examples for assumptions, inputs, and outputs. Focus on the key operations like insertion, lookup, and eviction.

9. **Identify Potential User Errors:** Think about how a programmer using this component might make mistakes. For example, setting an invalid capacity, or not understanding the implications of table size limits.

10. **Trace User Operations:** Consider the user's interaction with a web browser that leads to the execution of this code. Start from the user typing a URL, and follow the steps down to the header compression logic.

11. **Review and Refine:**  Go back through your analysis, ensuring the explanations are clear, concise, and accurate based on the code provided. Check for any logical inconsistencies or missed points. For example, initially, I might have focused too much on the individual test cases without explicitly stating the overall purpose and the broader context of QPACK in HTTP/3. Refinement would involve adding those higher-level explanations. Also, double-check the interpretation of specific test assertions like `FieldsAre`.

This systematic approach allows for a comprehensive understanding of the test file's purpose, the functionality of the underlying class, and its relevance within the larger system. It also helps in generating relevant examples and identifying potential issues.
这个文件 `net/third_party/quiche/src/quiche/quic/core/qpack/qpack_header_table_test.cc` 是 Chromium 网络栈中 QUIC 协议的 QPACK (QPACK Header Compression) 组件的一部分，它包含了对 `QpackHeaderTable` 类的单元测试。

**它的主要功能是：**

1. **测试 `QpackHeaderTable` 类的各种功能：**
   - **动态表容量管理：** 测试设置最大动态表容量、设置动态表容量以及判断条目是否能放入动态表。
   - **条目插入：** 测试向动态表中插入新的头部字段（name-value 对）。
   - **条目查找：** 测试在静态表和动态表中查找头部字段，包括精确匹配（name 和 value 都匹配）和仅 name 匹配的情况。
   - **条目驱逐（Eviction）：** 测试在插入新条目或更新表容量时，旧条目如何被驱逐出动态表。测试了基于插入和基于更新表大小的驱逐策略，以及驱逐相同或相似条目的策略。
   - **观察者模式：**  测试 `QpackDecoderHeaderTable` 的观察者机制，允许其他组件在动态表插入条目达到特定数量时收到通知。
   - **最大插入大小计算：** 测试在不驱逐特定条目的情况下，可以插入的最大条目大小。
   - **Draining Index 计算：** 测试计算在 draining 期间可以访问的动态表条目的索引。

2. **针对 `QpackEncoderHeaderTable` 和 `QpackDecoderHeaderTable` 两个子类进行测试：**  虽然它们都继承自某个公共接口或基类，但编码器和解码器在头部表的使用上可能存在细微差别，因此需要分别测试。

**它与 JavaScript 的功能的关系：**

这个 C++ 文件本身不直接包含 JavaScript 代码。但是，它测试的网络栈组件 (`QpackHeaderTable`) 对 JavaScript 在浏览器中的行为有间接影响。

* **HTTP/3 性能优化：** QPACK 是 HTTP/3 协议中用于头部压缩的关键技术。当 JavaScript 代码发起 HTTP/3 请求时，浏览器底层会使用 QPACK 来压缩请求头和响应头。这个测试文件确保了 QPACK 头部表功能的正确性，从而保证了 HTTP/3 的高效运行。
* **更快的页面加载：** 正确的头部压缩可以显著减少网络传输的数据量，从而加速网页的加载速度。JavaScript 代码可以更快地获取到需要的数据和资源。
* **更低的延迟：** 减少数据传输也有助于降低网络延迟，提升用户体验。

**举例说明 JavaScript 的关系：**

假设一个 JavaScript 代码发起一个 HTTP/3 的 GET 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

当这个请求发送到服务器时，浏览器底层的 QUIC 协议会使用 `QpackEncoderHeaderTable` 来压缩请求头（例如 `Host`, `User-Agent`, `Accept` 等）。  服务器的 QUIC 实现会使用 `QpackDecoderHeaderTable` 来解压这些头部。  这个测试文件确保了编码器和解码器能够正确地进行这些操作，例如：

* **假设输入：**  JavaScript 发起的请求包含头部 `{'Content-Type': 'application/json', 'Accept-Language': 'en-US'}`。
* **`QpackEncoderHeaderTable` 的输出（压缩后的表示）：**  `QpackEncoderHeaderTableTest` 中的测试确保了这些头部能够被正确地索引和编码，例如可能将 `Content-Type: application/json`  在动态表中找到或者插入，并使用相应的索引来表示。
* **`QpackDecoderHeaderTable` 的输出（解压后的表示）：** `QpackDecoderHeaderTableTest` 中的测试确保了服务器能够正确地根据编码还原出原始的头部 `{'Content-Type': 'application/json', 'Accept-Language': 'en-US'}`。

**逻辑推理、假设输入与输出：**

考虑 `QpackEncoderHeaderTableTest.FindDynamicHeaderField` 测试：

* **假设输入：**
    1. 初始时动态表为空。
    2. 调用 `FindHeaderField("foo", "bar")`。
    3. 调用 `InsertEntry("foo", "bar")`。
    4. 再次调用 `FindHeaderField("foo", "bar")`。
    5. 调用 `FindHeaderField("foo", "baz")`。
    6. 调用 `FindHeaderName("foo")`。
    7. 调用 `InsertEntry("foo", "bar")`。
    8. 再次调用 `FindHeaderField("foo", "bar")`。
    9. 再次调用 `FindHeaderField("foo", "baz")`。
    10. 再次调用 `FindHeaderName("foo")`。

* **逻辑推理：**
    - 第一次查找时，动态表为空，应该找不到匹配项。
    - 插入后，动态表包含 `("foo", "bar")`。
    - 第二次查找时，应该找到精确匹配。
    - 第三次查找时，应该找到 name 匹配。
    - 第四次查找时，应该找到 name 匹配。
    - 再次插入相同条目后，动态表包含两个 `("foo", "bar")`，最新的条目索引更高。
    - 后续的查找会返回最新的匹配项。

* **预期输出：**
    1. `FindHeaderField("foo", "bar")` 返回 `(kNoMatch, _, _)`
    2. 插入后
    3. `FindHeaderField("foo", "bar")` 返回 `(kNameAndValue, kDynamicEntry, 0u)`
    4. `FindHeaderField("foo", "baz")` 返回 `(kName, kDynamicEntry, 0u)`
    5. `FindHeaderName("foo")` 返回 `(kName, kDynamicEntry, 0u)`
    6. 再次插入后
    7. `FindHeaderField("foo", "bar")` 返回 `(kNameAndValue, kDynamicEntry, 1u)`
    8. `FindHeaderField("foo", "baz")` 返回 `(kName, kDynamicEntry, 1u)`
    9. `FindHeaderName("foo")` 返回 `(kName, kDynamicEntry, 1u)`

**用户或编程常见的使用错误：**

1. **设置过小的动态表容量：**  用户或编程者可能将动态表的最大容量设置得过小，导致频繁的条目驱逐，降低了头部压缩的效率。
   * **错误示例：**  在配置 QUIC 连接参数时，将 QPACK 动态表的最大容量设置为一个很小的值，例如几百字节。
   * **后果：** 很多常用的头部字段无法被存储在动态表中，每次发送请求都需要重复发送完整的头部，增加了网络开销。

2. **没有考虑到头部字段的大小：**  用户在插入头部字段时，没有考虑到头部 name 和 value 的长度，导致插入失败或者触发不必要的驱逐。
   * **错误示例：**  尝试插入一个非常长的自定义头部字段，超过了当前动态表的剩余空间，导致插入失败或者驱逐了其他有用的条目。

3. **在解码器端错误地假设动态表的状态：**  在多路复用的 QUIC 连接中，不同的流可能共享同一个 QPACK 解码器状态。如果解码器端错误地假设某个头部字段一定存在于动态表中，可能会导致解码错误。
   * **错误示例：**  在处理接收到的 HTTP/3 帧时，解码器假设某个头部字段已经在动态表中（基于之前收到的指令），但实际上该条目已经被驱逐了。

**用户操作是如何一步步的到达这里，作为调试线索：**

作为一个开发者，如果需要调试与 QPACK 头部表相关的问题，可能会经历以下步骤：

1. **用户在浏览器中访问一个使用了 HTTP/3 的网站。**  这是触发 QUIC 和 QPACK 的起点。
2. **浏览器与服务器建立 QUIC 连接。** 在连接建立过程中，会协商 QPACK 的相关参数，例如动态表的最大容量。
3. **JavaScript 代码发起 HTTP 请求。**  例如，通过 `fetch` API 请求数据或资源。
4. **浏览器网络栈处理请求。**  在发送请求前，QUIC 层会使用 `QpackEncoderHeaderTable` 来压缩请求头。
5. **服务器接收到请求。** 服务器的 QUIC 实现使用 `QpackDecoderHeaderTable` 来解压请求头。
6. **如果出现问题，例如头部解压失败，或者性能异常。**  开发者可能会怀疑是 QPACK 头部表的问题。
7. **开始调试：**
   - **查看 Chromium 的网络日志：** 可以查看 QPACK 相关的帧和指令，了解动态表的变化。
   - **使用断点调试：**  在 `qpack_header_table_test.cc` 中相关的测试用例中设置断点，例如 `InsertEntry` 或 `FindHeaderField`，模拟用户场景，观察动态表的状态变化。
   - **检查 QPACK 编码和解码逻辑：**  查看 `QpackEncoderHeaderTable` 和 `QpackDecoderHeaderTable` 的实现代码，理解其内部机制。
   - **分析网络抓包：**  使用 Wireshark 等工具抓取网络包，分析 QPACK 头部压缩的具体过程。
   - **修改测试用例：**  如果发现现有测试用例没有覆盖到特定的场景，可以添加新的测试用例来验证假设。

通过以上步骤，开发者可以逐步定位问题，确定是否是 `QpackHeaderTable` 的实现存在 bug，或者配置不当导致的问题。 `qpack_header_table_test.cc` 文件本身就是调试过程中的一个重要参考，可以用来验证代码的正确性，并提供一些边界条件和使用场景的示例。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/qpack/qpack_header_table_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/qpack/qpack_header_table.h"

#include <memory>
#include <tuple>
#include <utility>

#include "absl/base/macros.h"
#include "absl/strings/string_view.h"
#include "quiche/http2/hpack/hpack_entry.h"
#include "quiche/quic/core/qpack/qpack_static_table.h"
#include "quiche/quic/platform/api/quic_test.h"

namespace quic {
namespace test {
namespace {

using ::testing::_;
using ::testing::FieldsAre;
using ::testing::Mock;
using ::testing::StrictMock;

constexpr uint64_t kMaximumDynamicTableCapacityForTesting = 1024 * 1024;
// Values for `is_static` argument.
constexpr bool kStaticEntry = true;
constexpr bool kDynamicEntry = false;

template <typename T>
class QpackHeaderTableTest : public QuicTest {
 protected:
  ~QpackHeaderTableTest() override = default;

  void SetUp() override {
    ASSERT_TRUE(table_.SetMaximumDynamicTableCapacity(
        kMaximumDynamicTableCapacityForTesting));
    ASSERT_TRUE(
        table_.SetDynamicTableCapacity(kMaximumDynamicTableCapacityForTesting));
  }

  bool EntryFitsDynamicTableCapacity(absl::string_view name,
                                     absl::string_view value) const {
    return table_.EntryFitsDynamicTableCapacity(name, value);
  }

  void InsertEntry(absl::string_view name, absl::string_view value) {
    table_.InsertEntry(name, value);
  }

  bool SetDynamicTableCapacity(uint64_t capacity) {
    return table_.SetDynamicTableCapacity(capacity);
  }

  uint64_t max_entries() const { return table_.max_entries(); }
  uint64_t inserted_entry_count() const {
    return table_.inserted_entry_count();
  }
  uint64_t dropped_entry_count() const { return table_.dropped_entry_count(); }

  T table_;
};

using MyTypes =
    ::testing::Types<QpackEncoderHeaderTable, QpackDecoderHeaderTable>;
TYPED_TEST_SUITE(QpackHeaderTableTest, MyTypes);

// MaxEntries is determined by maximum dynamic table capacity,
// which is set at construction time.
TYPED_TEST(QpackHeaderTableTest, MaxEntries) {
  TypeParam table1;
  table1.SetMaximumDynamicTableCapacity(1024);
  EXPECT_EQ(32u, table1.max_entries());

  TypeParam table2;
  table2.SetMaximumDynamicTableCapacity(500);
  EXPECT_EQ(15u, table2.max_entries());
}

TYPED_TEST(QpackHeaderTableTest, SetDynamicTableCapacity) {
  // Dynamic table capacity does not affect MaxEntries.
  EXPECT_TRUE(this->SetDynamicTableCapacity(1024));
  EXPECT_EQ(32u * 1024, this->max_entries());

  EXPECT_TRUE(this->SetDynamicTableCapacity(500));
  EXPECT_EQ(32u * 1024, this->max_entries());

  // Dynamic table capacity cannot exceed maximum dynamic table capacity.
  EXPECT_FALSE(this->SetDynamicTableCapacity(
      2 * kMaximumDynamicTableCapacityForTesting));
}

TYPED_TEST(QpackHeaderTableTest, EntryFitsDynamicTableCapacity) {
  EXPECT_TRUE(this->SetDynamicTableCapacity(39));

  EXPECT_TRUE(this->EntryFitsDynamicTableCapacity("foo", "bar"));
  EXPECT_TRUE(this->EntryFitsDynamicTableCapacity("foo", "bar2"));
  EXPECT_FALSE(this->EntryFitsDynamicTableCapacity("foo", "bar12"));
}

class QpackEncoderHeaderTableTest
    : public QpackHeaderTableTest<QpackEncoderHeaderTable> {
 protected:
  // Redefine MatchType with values identical to
  // QpackEncoderHeaderTable::MatchType for brevity.
  // (Using declarations cannot be used with enum class until C++20.)
  enum MatchType { kNameAndValue, kName, kNoMatch };

  ~QpackEncoderHeaderTableTest() override = default;

  std::tuple<MatchType, bool, uint64_t> FindHeaderField(
      absl::string_view name, absl::string_view value) const {
    QpackEncoderHeaderTable::MatchResult match_result =
        table_.FindHeaderField(name, value);

    return {static_cast<MatchType>(match_result.match_type),
            match_result.is_static, match_result.index};
  }

  std::tuple<MatchType, bool, uint64_t> FindHeaderName(
      absl::string_view name) const {
    QpackEncoderHeaderTable::MatchResult match_result =
        table_.FindHeaderName(name);

    return {static_cast<MatchType>(match_result.match_type),
            match_result.is_static, match_result.index};
  }

  uint64_t MaxInsertSizeWithoutEvictingGivenEntry(uint64_t index) const {
    return table_.MaxInsertSizeWithoutEvictingGivenEntry(index);
  }

  uint64_t draining_index(float draining_fraction) const {
    return table_.draining_index(draining_fraction);
  }
};

TEST_F(QpackEncoderHeaderTableTest, FindStaticHeaderField) {
  // A header name that has multiple entries with different values.
  EXPECT_THAT(FindHeaderField(":method", "GET"),
              FieldsAre(kNameAndValue, kStaticEntry, 17u));

  EXPECT_THAT(FindHeaderField(":method", "POST"),
              FieldsAre(kNameAndValue, kStaticEntry, 20u));

  // ":method: TRACE" does not exist in the static table.
  // Both following calls return the lowest index with key ":method".
  EXPECT_THAT(FindHeaderField(":method", "TRACE"),
              FieldsAre(kName, kStaticEntry, 15u));

  EXPECT_THAT(FindHeaderName(":method"), FieldsAre(kName, kStaticEntry, 15u));

  // A header name that has a single entry with non-empty value.
  EXPECT_THAT(FindHeaderField("accept-encoding", "gzip, deflate, br"),
              FieldsAre(kNameAndValue, kStaticEntry, 31u));

  EXPECT_THAT(FindHeaderField("accept-encoding", "compress"),
              FieldsAre(kName, kStaticEntry, 31u));

  EXPECT_THAT(FindHeaderField("accept-encoding", ""),
              FieldsAre(kName, kStaticEntry, 31u));

  EXPECT_THAT(FindHeaderName("accept-encoding"),
              FieldsAre(kName, kStaticEntry, 31u));

  // A header name that has a single entry with empty value.
  EXPECT_THAT(FindHeaderField("location", ""),
              FieldsAre(kNameAndValue, kStaticEntry, 12u));

  EXPECT_THAT(FindHeaderField("location", "foo"),
              FieldsAre(kName, kStaticEntry, 12u));

  EXPECT_THAT(FindHeaderName("location"), FieldsAre(kName, kStaticEntry, 12u));

  // No matching header name.
  EXPECT_THAT(FindHeaderField("foo", ""), FieldsAre(kNoMatch, _, _));
  EXPECT_THAT(FindHeaderField("foo", "bar"), FieldsAre(kNoMatch, _, _));
  EXPECT_THAT(FindHeaderName("foo"), FieldsAre(kNoMatch, _, _));
}

TEST_F(QpackEncoderHeaderTableTest, FindDynamicHeaderField) {
  // Dynamic table is initially entry.
  EXPECT_THAT(FindHeaderField("foo", "bar"), FieldsAre(kNoMatch, _, _));
  EXPECT_THAT(FindHeaderField("foo", "baz"), FieldsAre(kNoMatch, _, _));
  EXPECT_THAT(FindHeaderName("foo"), FieldsAre(kNoMatch, _, _));

  // Insert one entry.
  InsertEntry("foo", "bar");

  // Match name and value.
  EXPECT_THAT(FindHeaderField("foo", "bar"),
              FieldsAre(kNameAndValue, kDynamicEntry, 0u));

  // Match name only.
  EXPECT_THAT(FindHeaderField("foo", "baz"),
              FieldsAre(kName, kDynamicEntry, 0u));
  EXPECT_THAT(FindHeaderName("foo"), FieldsAre(kName, kDynamicEntry, 0u));

  // Insert an identical entry.  FindHeaderField() should return the index of
  // the most recently inserted matching entry.
  InsertEntry("foo", "bar");

  // Match name and value.
  EXPECT_THAT(FindHeaderField("foo", "bar"),
              FieldsAre(kNameAndValue, kDynamicEntry, 1u));

  // Match name only.
  EXPECT_THAT(FindHeaderField("foo", "baz"),
              FieldsAre(kName, kDynamicEntry, 1u));
  EXPECT_THAT(FindHeaderName("foo"), FieldsAre(kName, kDynamicEntry, 1u));
}

TEST_F(QpackEncoderHeaderTableTest, FindHeaderFieldPrefersStaticTable) {
  // Insert an entry to the dynamic table that exists in the static table.
  InsertEntry(":method", "GET");

  // FindHeaderField() prefers static table if both tables have name-and-value
  // match.
  EXPECT_THAT(FindHeaderField(":method", "GET"),
              FieldsAre(kNameAndValue, kStaticEntry, 17u));

  // FindHeaderField() prefers static table if both tables have name match but
  // no value match, and prefers the first entry with matching name.
  EXPECT_THAT(FindHeaderField(":method", "TRACE"),
              FieldsAre(kName, kStaticEntry, 15u));

  // FindHeaderName() prefers static table if both tables have a match, and
  // prefers the first entry with matching name.
  EXPECT_THAT(FindHeaderName(":method"), FieldsAre(kName, kStaticEntry, 15u));

  // Add new entry to the dynamic table.
  InsertEntry(":method", "TRACE");

  // FindHeaderField prefers name-and-value match in dynamic table over name
  // only match in static table.
  EXPECT_THAT(FindHeaderField(":method", "TRACE"),
              FieldsAre(kNameAndValue, kDynamicEntry, 1u));
}

TEST_F(QpackEncoderHeaderTableTest, EvictByInsertion) {
  EXPECT_TRUE(SetDynamicTableCapacity(40));

  // Entry size is 3 + 3 + 32 = 38.
  InsertEntry("foo", "bar");
  EXPECT_EQ(1u, inserted_entry_count());
  EXPECT_EQ(0u, dropped_entry_count());

  EXPECT_THAT(FindHeaderField("foo", "bar"),
              FieldsAre(kNameAndValue, kDynamicEntry, 0u));

  // Inserting second entry evicts the first one.
  InsertEntry("baz", "qux");
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(1u, dropped_entry_count());

  EXPECT_THAT(FindHeaderField("foo", "bar"), FieldsAre(kNoMatch, _, _));
  EXPECT_THAT(FindHeaderField("baz", "qux"),
              FieldsAre(kNameAndValue, kDynamicEntry, 1u));
}

TEST_F(QpackEncoderHeaderTableTest, EvictByUpdateTableSize) {
  // Entry size is 3 + 3 + 32 = 38.
  InsertEntry("foo", "bar");
  InsertEntry("baz", "qux");
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(0u, dropped_entry_count());

  EXPECT_THAT(FindHeaderField("foo", "bar"),
              FieldsAre(kNameAndValue, kDynamicEntry, 0u));
  EXPECT_THAT(FindHeaderField("baz", "qux"),
              FieldsAre(kNameAndValue, kDynamicEntry, 1u));

  EXPECT_TRUE(SetDynamicTableCapacity(40));
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(1u, dropped_entry_count());

  EXPECT_THAT(FindHeaderField("foo", "bar"), FieldsAre(kNoMatch, _, _));
  EXPECT_THAT(FindHeaderField("baz", "qux"),
              FieldsAre(kNameAndValue, kDynamicEntry, 1u));

  EXPECT_TRUE(SetDynamicTableCapacity(20));
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(2u, dropped_entry_count());

  EXPECT_THAT(FindHeaderField("foo", "bar"), FieldsAre(kNoMatch, _, _));
  EXPECT_THAT(FindHeaderField("baz", "qux"), FieldsAre(kNoMatch, _, _));
}

TEST_F(QpackEncoderHeaderTableTest, EvictOldestOfIdentical) {
  EXPECT_TRUE(SetDynamicTableCapacity(80));

  // Entry size is 3 + 3 + 32 = 38.
  // Insert same entry twice.
  InsertEntry("foo", "bar");
  InsertEntry("foo", "bar");
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(0u, dropped_entry_count());

  // Find most recently inserted entry.
  EXPECT_THAT(FindHeaderField("foo", "bar"),
              FieldsAre(kNameAndValue, kDynamicEntry, 1u));

  // Inserting third entry evicts the first one, not the second.
  InsertEntry("baz", "qux");
  EXPECT_EQ(3u, inserted_entry_count());
  EXPECT_EQ(1u, dropped_entry_count());

  EXPECT_THAT(FindHeaderField("foo", "bar"),
              FieldsAre(kNameAndValue, kDynamicEntry, 1u));
  EXPECT_THAT(FindHeaderField("baz", "qux"),
              FieldsAre(kNameAndValue, kDynamicEntry, 2u));
}

TEST_F(QpackEncoderHeaderTableTest, EvictOldestOfSameName) {
  EXPECT_TRUE(SetDynamicTableCapacity(80));

  // Entry size is 3 + 3 + 32 = 38.
  // Insert two entries with same name but different values.
  InsertEntry("foo", "bar");
  InsertEntry("foo", "baz");
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(0u, dropped_entry_count());

  // Find most recently inserted entry with matching name.
  EXPECT_THAT(FindHeaderField("foo", "foo"),
              FieldsAre(kName, kDynamicEntry, 1u));

  // Inserting third entry evicts the first one, not the second.
  InsertEntry("baz", "qux");
  EXPECT_EQ(3u, inserted_entry_count());
  EXPECT_EQ(1u, dropped_entry_count());

  EXPECT_THAT(FindHeaderField("foo", "foo"),
              FieldsAre(kName, kDynamicEntry, 1u));
  EXPECT_THAT(FindHeaderField("baz", "qux"),
              FieldsAre(kNameAndValue, kDynamicEntry, 2u));
}

// Returns the size of the largest entry that could be inserted into the
// dynamic table without evicting entry |index|.
TEST_F(QpackEncoderHeaderTableTest, MaxInsertSizeWithoutEvictingGivenEntry) {
  const uint64_t dynamic_table_capacity = 100;
  EXPECT_TRUE(SetDynamicTableCapacity(dynamic_table_capacity));

  // Empty table can take an entry up to its capacity.
  EXPECT_EQ(dynamic_table_capacity, MaxInsertSizeWithoutEvictingGivenEntry(0));

  const uint64_t entry_size1 = QpackEntry::Size("foo", "bar");
  InsertEntry("foo", "bar");
  EXPECT_EQ(dynamic_table_capacity - entry_size1,
            MaxInsertSizeWithoutEvictingGivenEntry(0));
  // Table can take an entry up to its capacity if all entries are allowed to be
  // evicted.
  EXPECT_EQ(dynamic_table_capacity, MaxInsertSizeWithoutEvictingGivenEntry(1));

  const uint64_t entry_size2 = QpackEntry::Size("baz", "foobar");
  InsertEntry("baz", "foobar");
  // Table can take an entry up to its capacity if all entries are allowed to be
  // evicted.
  EXPECT_EQ(dynamic_table_capacity, MaxInsertSizeWithoutEvictingGivenEntry(2));
  // Second entry must stay.
  EXPECT_EQ(dynamic_table_capacity - entry_size2,
            MaxInsertSizeWithoutEvictingGivenEntry(1));
  // First and second entry must stay.
  EXPECT_EQ(dynamic_table_capacity - entry_size2 - entry_size1,
            MaxInsertSizeWithoutEvictingGivenEntry(0));

  // Third entry evicts first one.
  const uint64_t entry_size3 = QpackEntry::Size("last", "entry");
  InsertEntry("last", "entry");
  EXPECT_EQ(1u, dropped_entry_count());
  // Table can take an entry up to its capacity if all entries are allowed to be
  // evicted.
  EXPECT_EQ(dynamic_table_capacity, MaxInsertSizeWithoutEvictingGivenEntry(3));
  // Third entry must stay.
  EXPECT_EQ(dynamic_table_capacity - entry_size3,
            MaxInsertSizeWithoutEvictingGivenEntry(2));
  // Second and third entry must stay.
  EXPECT_EQ(dynamic_table_capacity - entry_size3 - entry_size2,
            MaxInsertSizeWithoutEvictingGivenEntry(1));
}

TEST_F(QpackEncoderHeaderTableTest, DrainingIndex) {
  EXPECT_TRUE(SetDynamicTableCapacity(4 * QpackEntry::Size("foo", "bar")));

  // Empty table: no draining entry.
  EXPECT_EQ(0u, draining_index(0.0));
  EXPECT_EQ(0u, draining_index(1.0));

  // Table with one entry.
  InsertEntry("foo", "bar");
  // Any entry can be referenced if none of the table is draining.
  EXPECT_EQ(0u, draining_index(0.0));
  // No entry can be referenced if all of the table is draining.
  EXPECT_EQ(1u, draining_index(1.0));

  // Table with two entries is at half capacity.
  InsertEntry("foo", "bar");
  // Any entry can be referenced if at most half of the table is draining,
  // because current entries only take up half of total capacity.
  EXPECT_EQ(0u, draining_index(0.0));
  EXPECT_EQ(0u, draining_index(0.5));
  // No entry can be referenced if all of the table is draining.
  EXPECT_EQ(2u, draining_index(1.0));

  // Table with four entries is full.
  InsertEntry("foo", "bar");
  InsertEntry("foo", "bar");
  // Any entry can be referenced if none of the table is draining.
  EXPECT_EQ(0u, draining_index(0.0));
  // In a full table with identically sized entries, |draining_fraction| of all
  // entries are draining.
  EXPECT_EQ(2u, draining_index(0.5));
  // No entry can be referenced if all of the table is draining.
  EXPECT_EQ(4u, draining_index(1.0));
}

class MockObserver : public QpackDecoderHeaderTable::Observer {
 public:
  ~MockObserver() override = default;

  MOCK_METHOD(void, OnInsertCountReachedThreshold, (), (override));
  MOCK_METHOD(void, Cancel, (), (override));
};

class QpackDecoderHeaderTableTest
    : public QpackHeaderTableTest<QpackDecoderHeaderTable> {
 protected:
  ~QpackDecoderHeaderTableTest() override = default;

  void ExpectEntryAtIndex(bool is_static, uint64_t index,
                          absl::string_view expected_name,
                          absl::string_view expected_value) const {
    const auto* entry = table_.LookupEntry(is_static, index);
    ASSERT_TRUE(entry);
    EXPECT_EQ(expected_name, entry->name());
    EXPECT_EQ(expected_value, entry->value());
  }

  void ExpectNoEntryAtIndex(bool is_static, uint64_t index) const {
    EXPECT_FALSE(table_.LookupEntry(is_static, index));
  }

  void RegisterObserver(uint64_t required_insert_count,
                        QpackDecoderHeaderTable::Observer* observer) {
    table_.RegisterObserver(required_insert_count, observer);
  }

  void UnregisterObserver(uint64_t required_insert_count,
                          QpackDecoderHeaderTable::Observer* observer) {
    table_.UnregisterObserver(required_insert_count, observer);
  }
};

TEST_F(QpackDecoderHeaderTableTest, LookupStaticEntry) {
  ExpectEntryAtIndex(kStaticEntry, 0, ":authority", "");

  ExpectEntryAtIndex(kStaticEntry, 1, ":path", "/");

  // 98 is the last entry.
  ExpectEntryAtIndex(kStaticEntry, 98, "x-frame-options", "sameorigin");

  ASSERT_EQ(99u, QpackStaticTableVector().size());
  ExpectNoEntryAtIndex(kStaticEntry, 99);
}

TEST_F(QpackDecoderHeaderTableTest, InsertAndLookupDynamicEntry) {
  // Dynamic table is initially entry.
  ExpectNoEntryAtIndex(kDynamicEntry, 0);
  ExpectNoEntryAtIndex(kDynamicEntry, 1);
  ExpectNoEntryAtIndex(kDynamicEntry, 2);
  ExpectNoEntryAtIndex(kDynamicEntry, 3);

  // Insert one entry.
  InsertEntry("foo", "bar");

  ExpectEntryAtIndex(kDynamicEntry, 0, "foo", "bar");

  ExpectNoEntryAtIndex(kDynamicEntry, 1);
  ExpectNoEntryAtIndex(kDynamicEntry, 2);
  ExpectNoEntryAtIndex(kDynamicEntry, 3);

  // Insert a different entry.
  InsertEntry("baz", "bing");

  ExpectEntryAtIndex(kDynamicEntry, 0, "foo", "bar");

  ExpectEntryAtIndex(kDynamicEntry, 1, "baz", "bing");

  ExpectNoEntryAtIndex(kDynamicEntry, 2);
  ExpectNoEntryAtIndex(kDynamicEntry, 3);

  // Insert an entry identical to the most recently inserted one.
  InsertEntry("baz", "bing");

  ExpectEntryAtIndex(kDynamicEntry, 0, "foo", "bar");

  ExpectEntryAtIndex(kDynamicEntry, 1, "baz", "bing");

  ExpectEntryAtIndex(kDynamicEntry, 2, "baz", "bing");

  ExpectNoEntryAtIndex(kDynamicEntry, 3);
}

TEST_F(QpackDecoderHeaderTableTest, EvictByInsertion) {
  EXPECT_TRUE(SetDynamicTableCapacity(40));

  // Entry size is 3 + 3 + 32 = 38.
  InsertEntry("foo", "bar");
  EXPECT_EQ(1u, inserted_entry_count());
  EXPECT_EQ(0u, dropped_entry_count());

  ExpectEntryAtIndex(kDynamicEntry, 0u, "foo", "bar");

  // Inserting second entry evicts the first one.
  InsertEntry("baz", "qux");
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(1u, dropped_entry_count());

  ExpectNoEntryAtIndex(kDynamicEntry, 0u);
  ExpectEntryAtIndex(kDynamicEntry, 1u, "baz", "qux");
}

TEST_F(QpackDecoderHeaderTableTest, EvictByUpdateTableSize) {
  ExpectNoEntryAtIndex(kDynamicEntry, 0u);
  ExpectNoEntryAtIndex(kDynamicEntry, 1u);

  // Entry size is 3 + 3 + 32 = 38.
  InsertEntry("foo", "bar");
  InsertEntry("baz", "qux");
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(0u, dropped_entry_count());

  ExpectEntryAtIndex(kDynamicEntry, 0u, "foo", "bar");
  ExpectEntryAtIndex(kDynamicEntry, 1u, "baz", "qux");

  EXPECT_TRUE(SetDynamicTableCapacity(40));
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(1u, dropped_entry_count());

  ExpectNoEntryAtIndex(kDynamicEntry, 0u);
  ExpectEntryAtIndex(kDynamicEntry, 1u, "baz", "qux");

  EXPECT_TRUE(SetDynamicTableCapacity(20));
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(2u, dropped_entry_count());

  ExpectNoEntryAtIndex(kDynamicEntry, 0u);
  ExpectNoEntryAtIndex(kDynamicEntry, 1u);
}

TEST_F(QpackDecoderHeaderTableTest, EvictOldestOfIdentical) {
  EXPECT_TRUE(SetDynamicTableCapacity(80));

  // Entry size is 3 + 3 + 32 = 38.
  // Insert same entry twice.
  InsertEntry("foo", "bar");
  InsertEntry("foo", "bar");
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(0u, dropped_entry_count());

  ExpectEntryAtIndex(kDynamicEntry, 0u, "foo", "bar");
  ExpectEntryAtIndex(kDynamicEntry, 1u, "foo", "bar");
  ExpectNoEntryAtIndex(kDynamicEntry, 2u);

  // Inserting third entry evicts the first one, not the second.
  InsertEntry("baz", "qux");
  EXPECT_EQ(3u, inserted_entry_count());
  EXPECT_EQ(1u, dropped_entry_count());

  ExpectNoEntryAtIndex(kDynamicEntry, 0u);
  ExpectEntryAtIndex(kDynamicEntry, 1u, "foo", "bar");
  ExpectEntryAtIndex(kDynamicEntry, 2u, "baz", "qux");
}

TEST_F(QpackDecoderHeaderTableTest, EvictOldestOfSameName) {
  EXPECT_TRUE(SetDynamicTableCapacity(80));

  // Entry size is 3 + 3 + 32 = 38.
  // Insert two entries with same name but different values.
  InsertEntry("foo", "bar");
  InsertEntry("foo", "baz");
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(0u, dropped_entry_count());

  ExpectEntryAtIndex(kDynamicEntry, 0u, "foo", "bar");
  ExpectEntryAtIndex(kDynamicEntry, 1u, "foo", "baz");
  ExpectNoEntryAtIndex(kDynamicEntry, 2u);

  // Inserting third entry evicts the first one, not the second.
  InsertEntry("baz", "qux");
  EXPECT_EQ(3u, inserted_entry_count());
  EXPECT_EQ(1u, dropped_entry_count());

  ExpectNoEntryAtIndex(kDynamicEntry, 0u);
  ExpectEntryAtIndex(kDynamicEntry, 1u, "foo", "baz");
  ExpectEntryAtIndex(kDynamicEntry, 2u, "baz", "qux");
}

TEST_F(QpackDecoderHeaderTableTest, RegisterObserver) {
  StrictMock<MockObserver> observer1;
  RegisterObserver(1, &observer1);
  EXPECT_CALL(observer1, OnInsertCountReachedThreshold);
  InsertEntry("foo", "bar");
  EXPECT_EQ(1u, inserted_entry_count());
  Mock::VerifyAndClearExpectations(&observer1);

  // Registration order does not matter.
  StrictMock<MockObserver> observer2;
  StrictMock<MockObserver> observer3;
  RegisterObserver(3, &observer3);
  RegisterObserver(2, &observer2);

  EXPECT_CALL(observer2, OnInsertCountReachedThreshold);
  InsertEntry("foo", "bar");
  EXPECT_EQ(2u, inserted_entry_count());
  Mock::VerifyAndClearExpectations(&observer3);

  EXPECT_CALL(observer3, OnInsertCountReachedThreshold);
  InsertEntry("foo", "bar");
  EXPECT_EQ(3u, inserted_entry_count());
  Mock::VerifyAndClearExpectations(&observer2);

  // Multiple observers with identical |required_insert_count| should all be
  // notified.
  StrictMock<MockObserver> observer4;
  StrictMock<MockObserver> observer5;
  RegisterObserver(4, &observer4);
  RegisterObserver(4, &observer5);

  EXPECT_CALL(observer4, OnInsertCountReachedThreshold);
  EXPECT_CALL(observer5, OnInsertCountReachedThreshold);
  InsertEntry("foo", "bar");
  EXPECT_EQ(4u, inserted_entry_count());
  Mock::VerifyAndClearExpectations(&observer4);
  Mock::VerifyAndClearExpectations(&observer5);
}

TEST_F(QpackDecoderHeaderTableTest, UnregisterObserver) {
  StrictMock<MockObserver> observer1;
  StrictMock<MockObserver> observer2;
  StrictMock<MockObserver> observer3;
  StrictMock<MockObserver> observer4;
  RegisterObserver(1, &observer1);
  RegisterObserver(2, &observer2);
  RegisterObserver(2, &observer3);
  RegisterObserver(3, &observer4);

  UnregisterObserver(2, &observer3);

  EXPECT_CALL(observer1, OnInsertCountReachedThreshold);
  EXPECT_CALL(observer2, OnInsertCountReachedThreshold);
  EXPECT_CALL(observer4, OnInsertCountReachedThreshold);
  InsertEntry("foo", "bar");
  InsertEntry("foo", "bar");
  InsertEntry("foo", "bar");
  EXPECT_EQ(3u, inserted_entry_count());
}

TEST_F(QpackDecoderHeaderTableTest, Cancel) {
  StrictMock<MockObserver> observer;
  auto table = std::make_unique<QpackDecoderHeaderTable>();
  table->RegisterObserver(1, &observer);

  EXPECT_CALL(observer, Cancel);
  table.reset();
}

}  // namespace
}  // namespace test
}  // namespace quic
```