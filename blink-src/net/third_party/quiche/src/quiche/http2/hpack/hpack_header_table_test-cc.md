Response:
The user wants to understand the functionality of the C++ source code file `hpack_header_table_test.cc` in the Chromium network stack. They also want to know:
1. Its relationship with JavaScript, if any.
2. Examples of logical reasoning with hypothetical inputs and outputs.
3. Common user or programming errors related to this code.
4. How a user's actions might lead to this code being executed, as a debugging aid.

**Plan:**
1. **Analyze the code:** Identify the main functionalities being tested in `hpack_header_table_test.cc`. This involves understanding the `HpackHeaderTable` class and the test cases it contains.
2. **JavaScript Relationship:** Determine if the HPACK header table, which this test file covers, directly interacts with JavaScript in the Chromium browser.
3. **Logical Reasoning Examples:** Create hypothetical scenarios for some of the test cases, showing input and expected output.
4. **Common Errors:**  Infer potential usage errors based on the functionalities of the header table, particularly around size limits and entry management.
5. **User Journey:**  Describe a simplified user interaction that triggers HTTP/2 requests, leading to the usage of the HPACK header table.
这个C++源代码文件 `hpack_header_table_test.cc` 是 Chromium 网络栈中 QUIC 协议的 HTTP/2 HPACK 压缩算法中 **`HpackHeaderTable` 类的单元测试文件**。它的主要功能是：

1. **测试 `HpackHeaderTable` 类的各种功能是否正常工作。** 这包括：
    * **静态表初始化：** 验证静态表是否正确加载和索引。
    * **动态表条目插入和驱逐：** 测试向动态表添加新的头部字段，以及在表满时驱逐旧条目的机制。
    * **条目索引：** 验证通过名称和值查找条目的功能，包括静态表和动态表。
    * **设置大小：** 测试动态表的最大尺寸限制，以及修改这个限制是否会导致条目被驱逐。
    * **计算驱逐数量：** 验证在添加新条目或调整大小时需要驱逐的条目数量的计算是否正确。
    * **添加条目：** 测试添加条目的核心逻辑，包括正常添加和因空间不足导致的驱逐。
    * **处理过大的条目：** 验证当尝试添加一个比动态表最大尺寸还要大的条目时的行为。

2. **作为 `HpackHeaderTable` 类开发和调试的辅助工具。**  通过编写和运行这些测试，开发者可以确保 `HpackHeaderTable` 类的实现符合预期，并且在修改代码后不会引入新的错误。

**它与 JavaScript 的功能关系：**

虽然这个 C++ 文件本身不是 JavaScript 代码，但它所测试的 `HpackHeaderTable` 类在 Chromium 浏览器中扮演着关键角色，**间接地影响着 JavaScript 发起的网络请求的性能**。

* **HTTP/2 头部压缩：** HPACK 是一种用于压缩 HTTP/2 头部字段的算法。当 JavaScript 代码发起一个 HTTP/2 请求时（例如使用 `fetch` API 或 `XMLHttpRequest`），浏览器会使用 `HpackHeaderTable` 来压缩请求头部。
* **减小请求大小：** 通过维护一个包含常用头部字段的静态表和动态表，HPACK 可以用较小的索引值或差量编码来表示头部字段，从而减小请求的大小，提高网络传输效率。
* **提升页面加载速度：** 更小的请求意味着更快的数据传输，这直接有助于提升网页的加载速度，从而改善用户体验。

**举例说明：**

假设 JavaScript 代码发起以下 HTTP/2 请求：

```javascript
fetch('https://example.com/api/data', {
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer my_token',
    'Custom-Header': 'some_value'
  }
});
```

当这个请求发送到服务器之前，Chromium 浏览器中的 HPACK 编码器会使用 `HpackHeaderTable` 来压缩这些头部。

* **静态表匹配：**  `Content-Type` 可能会在静态表中找到，可以用一个较小的索引值表示。
* **动态表匹配：** 如果之前已经向同一个服务器发送过类似的请求，并且 `Authorization` 或 `Custom-Header` 已经被添加到动态表中，那么它们也可以用索引值表示。
* **新条目插入：**  如果 `Custom-Header` 是一个新的头部字段，它可能会被添加到动态表中，以便后续的请求可以利用它。

**假设输入与输出 (逻辑推理示例)：**

**场景 1：添加新条目到动态表**

* **假设输入：**
    * 动态表当前大小：500 字节
    * 动态表最大尺寸：1000 字节
    * 尝试添加的头部字段：`name: new_value`，大小为 100 字节（假设计算 `HpackEntry::Size()` 返回 100）
* **预期输出：**
    * 动态表大小变为 600 字节
    * `HpackHeaderTable::TryAddEntry()` 返回指向新添加条目的指针
    * `HpackHeaderTable::GetByNameAndValue("name", "new_value")` 返回新条目的索引

**场景 2：添加新条目导致驱逐**

* **假设输入：**
    * 动态表当前大小：950 字节
    * 动态表最大尺寸：1000 字节
    * 动态表中最早添加的条目：`old_name: old_value`，大小为 80 字节
    * 尝试添加的头部字段：`name: new_value`，大小为 100 字节
* **预期输出：**
    * 最早添加的条目 `old_name: old_value` 被驱逐
    * 动态表大小变为 970 字节 (950 - 80 + 100)
    * `HpackHeaderTable::TryAddEntry()` 返回指向新添加条目的指针
    * `HpackHeaderTable::GetByNameAndValue("name", "new_value")` 返回新条目的索引
    * `HpackHeaderTable::GetByNameAndValue("old_name", "old_value")` 返回 `kHpackEntryNotFound`

**用户或编程常见的使用错误举例说明：**

1. **动态表尺寸设置过小：**
   * **错误：**  如果程序将 `SETTINGS_HEADER_TABLE_SIZE` 设置得非常小，动态表可能无法有效地存储常用的头部字段，导致 HPACK 压缩效率降低，增加网络传输量。
   * **用户操作如何到达这里 (调试线索)：**  用户可能在某些网络配置中手动设置了较小的 HTTP/2 头部表尺寸，或者某些中间件或代理服务器可能会修改这个设置。在浏览器开发者工具的网络面板中，观察请求头部的压缩情况，如果发现头部字段没有被有效压缩，可能是动态表尺寸过小导致的。

2. **错误地假设头部字段会被持久化在动态表中：**
   * **错误：** 动态表是一个有限大小的缓存。开发者不应该假设添加的头部字段会一直存在。当动态表满时，旧的条目会被驱逐。
   * **用户操作如何到达这里 (调试线索)：**  用户可能在短时间内发送大量不同的 HTTP/2 请求，每个请求都包含一些新的自定义头部字段。如果动态表尺寸有限，一些较早添加的头部字段可能会被驱逐。在调试时，检查连续请求的头部，看是否需要重复发送相同的自定义头部，这可能表明之前的条目已被驱逐。

3. **忽略头部字段大小的影响：**
   * **错误：**  添加非常大的头部字段到动态表可能会迅速消耗其容量，导致频繁的驱逐，甚至可能因为单个头部字段过大而无法添加到动态表。
   * **用户操作如何到达这里 (调试线索)：** 用户可能在请求中包含了过大的 Cookie 或其他自定义头部字段。在调试时，检查请求头部的大小，如果发现某个头部字段非常大，需要考虑优化其大小或避免将其添加到动态表（通过发送时不指示插入）。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

假设用户正在浏览一个使用 HTTP/2 协议的网站：

1. **用户在浏览器地址栏输入网址并按下回车键。**
2. **浏览器解析 URL 并建立与服务器的 TCP 连接。**
3. **浏览器与服务器进行 TLS 握手，建立安全连接。**
4. **浏览器和服务器进行 HTTP/2 协商，确认使用 HTTP/2 协议。**
5. **浏览器发送 HTTP/2 请求到服务器，请求页面的 HTML 内容。**  在这个过程中，`HpackHeaderTable` 会被用来压缩请求头部，例如 `Host`、`User-Agent`、`Accept` 等。
6. **服务器响应请求，发送压缩后的 HTTP/2 头部和 HTML 内容。** 浏览器接收到响应后，会使用 `HpackHeaderTable` 的解码功能来解压缩头部。
7. **如果页面包含其他资源 (CSS, JavaScript, 图片等)，浏览器会重复步骤 5 和 6，发送额外的 HTTP/2 请求。**  在后续的请求中，如果某些头部字段在之前的请求中已经出现过并被添加到动态表中，HPACK 就可以用更高效的方式来表示这些头部。

**调试线索：**

* **网络性能问题：** 如果用户报告网页加载速度慢，可能是 HTTP/2 头部压缩效率不高导致的。可以检查浏览器开发者工具的网络面板，查看请求头部的大小和压缩情况。
* **头部字段丢失或不正确：**  虽然不太常见，但 HPACK 算法的错误实现可能导致头部字段在压缩或解压缩过程中丢失或损坏。这可能导致网站功能异常。可以通过抓包工具（如 Wireshark）查看原始的 HTTP/2 数据帧，分析头部字段是否正确传输。
* **特定头部字段的问题：** 如果某个特定的头部字段在不同请求中的行为不一致，可能是因为动态表的驱逐策略导致该字段有时在动态表中，有时不在，从而影响了压缩效果。

理解 `hpack_header_table_test.cc` 的功能有助于开发者理解 HPACK 算法的实现细节和工作原理，从而更好地排查和解决与 HTTP/2 头部压缩相关的性能和功能问题。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/http2/hpack/hpack_header_table_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/http2/hpack/hpack_header_table.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/http2/hpack/hpack_constants.h"
#include "quiche/http2/hpack/hpack_entry.h"
#include "quiche/http2/hpack/hpack_static_table.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace spdy {

using std::distance;

namespace test {

class HpackHeaderTablePeer {
 public:
  explicit HpackHeaderTablePeer(HpackHeaderTable* table) : table_(table) {}

  const HpackHeaderTable::DynamicEntryTable& dynamic_entries() {
    return table_->dynamic_entries_;
  }
  const HpackHeaderTable::StaticEntryTable& static_entries() {
    return table_->static_entries_;
  }
  const HpackEntry* GetFirstStaticEntry() {
    return &table_->static_entries_.front();
  }
  const HpackEntry* GetLastStaticEntry() {
    return &table_->static_entries_.back();
  }
  std::vector<HpackEntry*> EvictionSet(absl::string_view name,
                                       absl::string_view value) {
    HpackHeaderTable::DynamicEntryTable::iterator begin, end;
    table_->EvictionSet(name, value, &begin, &end);
    std::vector<HpackEntry*> result;
    for (; begin != end; ++begin) {
      result.push_back(begin->get());
    }
    return result;
  }
  size_t dynamic_table_insertions() {
    return table_->dynamic_table_insertions_;
  }
  size_t EvictionCountForEntry(absl::string_view name,
                               absl::string_view value) {
    return table_->EvictionCountForEntry(name, value);
  }
  size_t EvictionCountToReclaim(size_t reclaim_size) {
    return table_->EvictionCountToReclaim(reclaim_size);
  }
  void Evict(size_t count) { return table_->Evict(count); }

 private:
  HpackHeaderTable* table_;
};

}  // namespace test

namespace {

class HpackHeaderTableTest : public quiche::test::QuicheTest {
 protected:
  typedef std::vector<HpackEntry> HpackEntryVector;

  HpackHeaderTableTest() : table_(), peer_(&table_) {}

  // Returns an entry whose Size() is equal to the given one.
  static HpackEntry MakeEntryOfSize(uint32_t size) {
    EXPECT_GE(size, kHpackEntrySizeOverhead);
    std::string name((size - kHpackEntrySizeOverhead) / 2, 'n');
    std::string value(size - kHpackEntrySizeOverhead - name.size(), 'v');
    HpackEntry entry(name, value);
    EXPECT_EQ(size, entry.Size());
    return entry;
  }

  // Returns a vector of entries whose total size is equal to the given
  // one.
  static HpackEntryVector MakeEntriesOfTotalSize(uint32_t total_size) {
    EXPECT_GE(total_size, kHpackEntrySizeOverhead);
    uint32_t entry_size = kHpackEntrySizeOverhead;
    uint32_t remaining_size = total_size;
    HpackEntryVector entries;
    while (remaining_size > 0) {
      EXPECT_LE(entry_size, remaining_size);
      entries.push_back(MakeEntryOfSize(entry_size));
      remaining_size -= entry_size;
      entry_size = std::min(remaining_size, entry_size + 32);
    }
    return entries;
  }

  // Adds the given vector of entries to the given header table,
  // expecting no eviction to happen.
  void AddEntriesExpectNoEviction(const HpackEntryVector& entries) {
    for (auto it = entries.begin(); it != entries.end(); ++it) {
      HpackHeaderTable::DynamicEntryTable::iterator begin, end;

      table_.EvictionSet(it->name(), it->value(), &begin, &end);
      EXPECT_EQ(0, distance(begin, end));

      const HpackEntry* entry = table_.TryAddEntry(it->name(), it->value());
      EXPECT_NE(entry, static_cast<HpackEntry*>(nullptr));
    }
  }

  HpackHeaderTable table_;
  test::HpackHeaderTablePeer peer_;
};

TEST_F(HpackHeaderTableTest, StaticTableInitialization) {
  EXPECT_EQ(0u, table_.size());
  EXPECT_EQ(kDefaultHeaderTableSizeSetting, table_.max_size());
  EXPECT_EQ(kDefaultHeaderTableSizeSetting, table_.settings_size_bound());

  EXPECT_EQ(0u, peer_.dynamic_entries().size());
  EXPECT_EQ(0u, peer_.dynamic_table_insertions());

  // Static entries have been populated and inserted into the table & index.
  const HpackHeaderTable::StaticEntryTable& static_entries =
      peer_.static_entries();
  EXPECT_EQ(kStaticTableSize, static_entries.size());
  // HPACK indexing scheme is 1-based.
  size_t index = 1;
  for (const HpackEntry& entry : static_entries) {
    EXPECT_EQ(index, table_.GetByNameAndValue(entry.name(), entry.value()));
    index++;
  }
}

TEST_F(HpackHeaderTableTest, BasicDynamicEntryInsertionAndEviction) {
  EXPECT_EQ(kStaticTableSize, peer_.static_entries().size());

  const HpackEntry* first_static_entry = peer_.GetFirstStaticEntry();
  const HpackEntry* last_static_entry = peer_.GetLastStaticEntry();

  const HpackEntry* entry = table_.TryAddEntry("header-key", "Header Value");
  EXPECT_EQ("header-key", entry->name());
  EXPECT_EQ("Header Value", entry->value());

  // Table counts were updated appropriately.
  EXPECT_EQ(entry->Size(), table_.size());
  EXPECT_EQ(1u, peer_.dynamic_entries().size());
  EXPECT_EQ(kStaticTableSize, peer_.static_entries().size());

  EXPECT_EQ(62u, table_.GetByNameAndValue("header-key", "Header Value"));

  // Index of static entries does not change.
  EXPECT_EQ(first_static_entry, peer_.GetFirstStaticEntry());
  EXPECT_EQ(last_static_entry, peer_.GetLastStaticEntry());

  // Evict |entry|. Table counts are again updated appropriately.
  peer_.Evict(1);
  EXPECT_EQ(0u, table_.size());
  EXPECT_EQ(0u, peer_.dynamic_entries().size());
  EXPECT_EQ(kStaticTableSize, peer_.static_entries().size());

  // Index of static entries does not change.
  EXPECT_EQ(first_static_entry, peer_.GetFirstStaticEntry());
  EXPECT_EQ(last_static_entry, peer_.GetLastStaticEntry());
}

TEST_F(HpackHeaderTableTest, EntryIndexing) {
  const HpackEntry* first_static_entry = peer_.GetFirstStaticEntry();
  const HpackEntry* last_static_entry = peer_.GetLastStaticEntry();

  // Static entries are queryable by name & value.
  EXPECT_EQ(1u, table_.GetByName(first_static_entry->name()));
  EXPECT_EQ(1u, table_.GetByNameAndValue(first_static_entry->name(),
                                         first_static_entry->value()));

  // Create a mix of entries which duplicate names, and names & values of both
  // dynamic and static entries.
  table_.TryAddEntry(first_static_entry->name(), first_static_entry->value());
  table_.TryAddEntry(first_static_entry->name(), "Value Four");
  table_.TryAddEntry("key-1", "Value One");
  table_.TryAddEntry("key-2", "Value Three");
  table_.TryAddEntry("key-1", "Value Two");
  table_.TryAddEntry("key-2", "Value Three");
  table_.TryAddEntry("key-2", "Value Four");

  // The following entry is identical to the one at index 68.  The smaller index
  // is returned by GetByNameAndValue().
  EXPECT_EQ(1u, table_.GetByNameAndValue(first_static_entry->name(),
                                         first_static_entry->value()));
  EXPECT_EQ(67u,
            table_.GetByNameAndValue(first_static_entry->name(), "Value Four"));
  EXPECT_EQ(66u, table_.GetByNameAndValue("key-1", "Value One"));
  EXPECT_EQ(64u, table_.GetByNameAndValue("key-1", "Value Two"));
  // The following entry is identical to the one at index 65.  The smaller index
  // is returned by GetByNameAndValue().
  EXPECT_EQ(63u, table_.GetByNameAndValue("key-2", "Value Three"));
  EXPECT_EQ(62u, table_.GetByNameAndValue("key-2", "Value Four"));

  // Index of static entries does not change.
  EXPECT_EQ(first_static_entry, peer_.GetFirstStaticEntry());
  EXPECT_EQ(last_static_entry, peer_.GetLastStaticEntry());

  // Querying by name returns the most recently added matching entry.
  EXPECT_EQ(64u, table_.GetByName("key-1"));
  EXPECT_EQ(62u, table_.GetByName("key-2"));
  EXPECT_EQ(1u, table_.GetByName(first_static_entry->name()));
  EXPECT_EQ(kHpackEntryNotFound, table_.GetByName("not-present"));

  // Querying by name & value returns the lowest-index matching entry among
  // static entries, and the highest-index one among dynamic entries.
  EXPECT_EQ(66u, table_.GetByNameAndValue("key-1", "Value One"));
  EXPECT_EQ(64u, table_.GetByNameAndValue("key-1", "Value Two"));
  EXPECT_EQ(63u, table_.GetByNameAndValue("key-2", "Value Three"));
  EXPECT_EQ(62u, table_.GetByNameAndValue("key-2", "Value Four"));
  EXPECT_EQ(1u, table_.GetByNameAndValue(first_static_entry->name(),
                                         first_static_entry->value()));
  EXPECT_EQ(67u,
            table_.GetByNameAndValue(first_static_entry->name(), "Value Four"));
  EXPECT_EQ(kHpackEntryNotFound,
            table_.GetByNameAndValue("key-1", "Not Present"));
  EXPECT_EQ(kHpackEntryNotFound,
            table_.GetByNameAndValue("not-present", "Value One"));

  // Evict |entry1|. Queries for its name & value now return the static entry.
  // |entry2| remains queryable.
  peer_.Evict(1);
  EXPECT_EQ(1u, table_.GetByNameAndValue(first_static_entry->name(),
                                         first_static_entry->value()));
  EXPECT_EQ(67u,
            table_.GetByNameAndValue(first_static_entry->name(), "Value Four"));

  // Evict |entry2|. Queries by its name & value are not found.
  peer_.Evict(1);
  EXPECT_EQ(kHpackEntryNotFound,
            table_.GetByNameAndValue(first_static_entry->name(), "Value Four"));

  // Index of static entries does not change.
  EXPECT_EQ(first_static_entry, peer_.GetFirstStaticEntry());
  EXPECT_EQ(last_static_entry, peer_.GetLastStaticEntry());
}

TEST_F(HpackHeaderTableTest, SetSizes) {
  std::string key = "key", value = "value";
  const HpackEntry* entry1 = table_.TryAddEntry(key, value);
  const HpackEntry* entry2 = table_.TryAddEntry(key, value);
  const HpackEntry* entry3 = table_.TryAddEntry(key, value);

  // Set exactly large enough. No Evictions.
  size_t max_size = entry1->Size() + entry2->Size() + entry3->Size();
  table_.SetMaxSize(max_size);
  EXPECT_EQ(3u, peer_.dynamic_entries().size());

  // Set just too small. One eviction.
  max_size = entry1->Size() + entry2->Size() + entry3->Size() - 1;
  table_.SetMaxSize(max_size);
  EXPECT_EQ(2u, peer_.dynamic_entries().size());

  // Changing SETTINGS_HEADER_TABLE_SIZE.
  EXPECT_EQ(kDefaultHeaderTableSizeSetting, table_.settings_size_bound());
  // In production, the size passed to SetSettingsHeaderTableSize is never
  // larger than table_.settings_size_bound().
  table_.SetSettingsHeaderTableSize(kDefaultHeaderTableSizeSetting * 3 + 1);
  EXPECT_EQ(kDefaultHeaderTableSizeSetting * 3 + 1, table_.max_size());

  // SETTINGS_HEADER_TABLE_SIZE upper-bounds |table_.max_size()|,
  // and will force evictions.
  max_size = entry3->Size() - 1;
  table_.SetSettingsHeaderTableSize(max_size);
  EXPECT_EQ(max_size, table_.max_size());
  EXPECT_EQ(max_size, table_.settings_size_bound());
  EXPECT_EQ(0u, peer_.dynamic_entries().size());
}

TEST_F(HpackHeaderTableTest, EvictionCountForEntry) {
  std::string key = "key", value = "value";
  const HpackEntry* entry1 = table_.TryAddEntry(key, value);
  const HpackEntry* entry2 = table_.TryAddEntry(key, value);
  size_t entry3_size = HpackEntry::Size(key, value);

  // Just enough capacity for third entry.
  table_.SetMaxSize(entry1->Size() + entry2->Size() + entry3_size);
  EXPECT_EQ(0u, peer_.EvictionCountForEntry(key, value));
  EXPECT_EQ(1u, peer_.EvictionCountForEntry(key, value + "x"));

  // No extra capacity. Third entry would force evictions.
  table_.SetMaxSize(entry1->Size() + entry2->Size());
  EXPECT_EQ(1u, peer_.EvictionCountForEntry(key, value));
  EXPECT_EQ(2u, peer_.EvictionCountForEntry(key, value + "x"));
}

TEST_F(HpackHeaderTableTest, EvictionCountToReclaim) {
  std::string key = "key", value = "value";
  const HpackEntry* entry1 = table_.TryAddEntry(key, value);
  const HpackEntry* entry2 = table_.TryAddEntry(key, value);

  EXPECT_EQ(1u, peer_.EvictionCountToReclaim(1));
  EXPECT_EQ(1u, peer_.EvictionCountToReclaim(entry1->Size()));
  EXPECT_EQ(2u, peer_.EvictionCountToReclaim(entry1->Size() + 1));
  EXPECT_EQ(2u, peer_.EvictionCountToReclaim(entry1->Size() + entry2->Size()));
}

// Fill a header table with entries. Make sure the entries are in
// reverse order in the header table.
TEST_F(HpackHeaderTableTest, TryAddEntryBasic) {
  EXPECT_EQ(0u, table_.size());
  EXPECT_EQ(table_.settings_size_bound(), table_.max_size());

  HpackEntryVector entries = MakeEntriesOfTotalSize(table_.max_size());

  // Most of the checks are in AddEntriesExpectNoEviction().
  AddEntriesExpectNoEviction(entries);
  EXPECT_EQ(table_.max_size(), table_.size());
  EXPECT_EQ(table_.settings_size_bound(), table_.size());
}

// Fill a header table with entries, and then ramp the table's max
// size down to evict an entry one at a time. Make sure the eviction
// happens as expected.
TEST_F(HpackHeaderTableTest, SetMaxSize) {
  HpackEntryVector entries =
      MakeEntriesOfTotalSize(kDefaultHeaderTableSizeSetting / 2);
  AddEntriesExpectNoEviction(entries);

  for (auto it = entries.begin(); it != entries.end(); ++it) {
    size_t expected_count = distance(it, entries.end());
    EXPECT_EQ(expected_count, peer_.dynamic_entries().size());

    table_.SetMaxSize(table_.size() + 1);
    EXPECT_EQ(expected_count, peer_.dynamic_entries().size());

    table_.SetMaxSize(table_.size());
    EXPECT_EQ(expected_count, peer_.dynamic_entries().size());

    --expected_count;
    table_.SetMaxSize(table_.size() - 1);
    EXPECT_EQ(expected_count, peer_.dynamic_entries().size());
  }
  EXPECT_EQ(0u, table_.size());
}

// Fill a header table with entries, and then add an entry just big
// enough to cause eviction of all but one entry. Make sure the
// eviction happens as expected and the long entry is inserted into
// the table.
TEST_F(HpackHeaderTableTest, TryAddEntryEviction) {
  HpackEntryVector entries = MakeEntriesOfTotalSize(table_.max_size());
  AddEntriesExpectNoEviction(entries);

  // The first entry in the dynamic table.
  const HpackEntry* survivor_entry = peer_.dynamic_entries().front().get();

  HpackEntry long_entry =
      MakeEntryOfSize(table_.max_size() - survivor_entry->Size());

  // All dynamic entries but the first are to be evicted.
  EXPECT_EQ(peer_.dynamic_entries().size() - 1,
            peer_.EvictionSet(long_entry.name(), long_entry.value()).size());

  table_.TryAddEntry(long_entry.name(), long_entry.value());
  EXPECT_EQ(2u, peer_.dynamic_entries().size());
  EXPECT_EQ(63u, table_.GetByNameAndValue(survivor_entry->name(),
                                          survivor_entry->value()));
  EXPECT_EQ(62u,
            table_.GetByNameAndValue(long_entry.name(), long_entry.value()));
}

// Fill a header table with entries, and then add an entry bigger than
// the entire table. Make sure no entry remains in the table.
TEST_F(HpackHeaderTableTest, TryAddTooLargeEntry) {
  HpackEntryVector entries = MakeEntriesOfTotalSize(table_.max_size());
  AddEntriesExpectNoEviction(entries);

  const HpackEntry long_entry = MakeEntryOfSize(table_.max_size() + 1);

  // All entries are to be evicted.
  EXPECT_EQ(peer_.dynamic_entries().size(),
            peer_.EvictionSet(long_entry.name(), long_entry.value()).size());

  const HpackEntry* new_entry =
      table_.TryAddEntry(long_entry.name(), long_entry.value());
  EXPECT_EQ(new_entry, static_cast<HpackEntry*>(nullptr));
  EXPECT_EQ(0u, peer_.dynamic_entries().size());
}

}  // namespace

}  // namespace spdy

"""

```