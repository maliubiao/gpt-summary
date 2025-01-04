Response:
The user wants a summary of the functionality of the C++ source code file `net/third_party/quiche/src/quiche/balsa/balsa_headers_test.cc`. I need to analyze the code and identify the main purpose of the tests within this file. Specifically, I need to understand what aspects of the `BalsaHeaders` class are being tested.

The code includes tests for:
- Basic instantiation and assignment of iterators.
- Appending and replacing headers.
- Iterating through headers.
- Erasing headers using iterators.
- Setting the first line of the header.
- Removing headers by key or prefix.
- Removing specific values from headers.
- Appending to headers with comma and space.
- Functionality related to the `BalsaBuffer` class, including:
    - Memory management (block size, allocation).
    - Writing data in contiguous and non-contiguous blocks.
    - Copying and clearing buffers.
    - Accessing the first block.

The tests are focused on verifying the correct behavior of the `BalsaHeaders` and `BalsaBuffer` classes in various scenarios.

Regarding the user's specific requests:
- **Relationship with JavaScript:**  While this C++ code interacts with network protocols that might be used by JavaScript in web browsers, this specific test file doesn't directly involve JavaScript code or its execution.
- **Logical Reasoning (Input/Output):** Many of the tests have implicit input/output. For example, a test appending a header would have the initial state of the headers as input and the final state after appending as the output. I can provide a concrete example.
- **Common User/Programming Errors:** The tests implicitly cover potential errors in using the `BalsaHeaders` and `BalsaBuffer` classes, such as incorrect usage of iterators or memory management. I can provide an example of a potential usage error.
- **User Operations Leading to This Code:** This code is part of the Chromium network stack and would be executed during network communication. I can outline a generic user interaction that triggers network requests.
- **Functionality Summary (Part 1):** I need to summarize the functionality covered in the provided code snippet, focusing on the tests related to `BalsaHeaders` and `BalsaBuffer`.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/balsa/balsa_headers_test.cc` 文件的第一部分，它主要的功能是**测试 `quiche::BalsaHeaders` 和 `quiche::BalsaBuffer` 这两个 C++ 类的各种功能和边界情况**。

具体来说，这部分代码测试了以下方面：

**针对 `BalsaHeaders` 类:**

* **迭代器操作:**  测试了 `BalsaHeaders` 的迭代器（`const_header_lines_iterator`) 的基本操作，例如赋值 begin() 和 end()。
* **添加和替换 header:**
    * `ReplaceOrAppendHeader`: 测试了当 key 不存在时添加新的 header，以及当 key 存在时替换已有 header 的值。特别测试了替换为更长或更短的值，以及存在多个相同 key 的 header 时的替换行为。
    * `AppendHeader`: 测试了添加新的 header，并验证了使用迭代器遍历添加后的 headers 的顺序和内容。
* **删除 header:**
    * `erase`: 测试了使用迭代器删除 header 的功能。
    * `RemoveAllOfHeader`: 测试了通过匹配子字符串来删除 header 的功能 (注意：这里是子字符串匹配)。
    * `RemoveAllHeadersWithPrefix`: 测试了删除所有以特定前缀开头的 headers。
    * `RemoveValue`: 测试了从 header 中移除特定的值，包括处理包含多个值的 header (例如 "value1, value2") 的情况，以及值周围存在空格的情况。
* **设置首行 (first line):** 测试了 `SetRequestFirstlineFromStringPieces` 方法，用于设置 HTTP 请求的首行，并考虑了首行长度变化和是否已经存在首行的情况。
* **获取 header:**
    * `HasHeader`: 测试了检查是否存在特定 header 的功能。
    * `HasHeadersWithPrefix`: 测试了检查是否存在以特定前缀开头的 header 的功能。
    * `GetHeader`: 测试了获取特定 header 的值。
    * `GetAllOfHeader`: 测试了获取所有具有相同 key 的 header 的值。
    * `GetAllOfHeaderAsString`: 测试了获取所有具有相同 key 的 header 的值，并将它们连接成一个字符串。
    * `HeaderHasValue`: 测试了检查特定 header 是否包含某个值。
* **带有逗号和空格的添加:** `AppendToHeaderWithCommaAndSpace` 测试了向已存在的 header 添加值，并用逗号和空格分隔。

**针对 `BalsaBuffer` 类:**

* **内存管理:**
    * 测试了设置和获取 blocksize 的功能。
    * 测试了获取已使用的总字节数 (`GetTotalBytesUsed`) 和已分配的 buffer block 大小 (`GetTotalBufferBlockSize`)。
    * 测试了拷贝 buffer 内容 (`CopyFrom`)。
    * 测试了清空 buffer (`Clear`)，包括 buffer 中数据量大于 blocksize 的情况。
* **写入操作:**
    * `WriteToContiguousBuffer`: 测试了向连续的 buffer 中写入数据，包括写入小于 blocksize、大于 blocksize 以及多次写入的情况。
    * `Write`: 测试了向 buffer 中写入数据，并返回写入的 block 的索引。
* **访问:**
    * 测试了访问第一个 block 的起始和结束位置 (`StartOfFirstBlock`, `EndOfFirstBlock`) 以及可读字节数 (`GetReadableBytesOfFirstBlock`)，并处理了未初始化的情况。

**与 Javascript 的关系:**

这个 C++ 文件本身与 Javascript 没有直接的代码关系。但是，Chromium 是一个浏览器，其网络栈负责处理浏览器发出的网络请求和接收到的响应。

**举例说明:** 当一个 Javascript 代码发起一个 HTTP 请求 (例如使用 `fetch` API):

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

在这个过程中，Chromium 的网络栈会构建 HTTP 请求报文，其中包括 HTTP 请求头。`BalsaHeaders` 类就是用来管理这些 HTTP 请求头的。例如，Javascript 可能会设置一些自定义的请求头，这些头信息最终会被存储在 `BalsaHeaders` 对象中。

**假设输入与输出 (针对 `ReplaceOrAppendHeader`):**

**假设输入:**

```c++
BalsaHeaders header;
header.AppendHeader("key1", "value1");
header.AppendHeader("key2", "value2_old");
```

**操作:**

```c++
header.ReplaceOrAppendHeader("key2", "value2_new");
header.ReplaceOrAppendHeader("key3", "value3");
```

**预期输出 (遍历 header):**

* "key1": "value1"
* "key2": "value2_new"
* "key3": "value3"

**用户或编程常见的使用错误 (针对 `RemoveValue`):**

**错误示例:** 用户可能错误地认为 `RemoveValue` 会删除所有包含特定子字符串的值，而实际上它是进行**精确匹配**的。

```c++
BalsaHeaders headers;
headers.AppendHeader("My-Header", "value1, partial_value, value3");

// 用户错误地认为这会删除 "partial_value"
headers.RemoveValue("My-Header", "value");

// 实际上，只有当 header 中存在完全匹配 "value" 的值时才会被删除。
// 结果是 "My-Header" 的值仍然是 "value1, partial_value, value3"
```

**用户操作如何一步步到达这里 (调试线索):**

作为一个调试线索，以下是一个用户操作的流程，最终可能会触发对 `BalsaHeaders` 相关代码的执行：

1. **用户在浏览器地址栏输入网址或点击链接。**
2. **浏览器解析 URL，确定目标服务器。**
3. **浏览器构建 HTTP 请求。**  在这个阶段，Javascript 代码 (如果存在) 可能会通过 `fetch` 或 `XMLHttpRequest` API 添加或修改请求头。
4. **Chromium 网络栈使用 `BalsaHeaders` 类来存储和管理这些请求头信息。** 例如，设置 `Host`，`User-Agent`，`Accept` 等标准 header，或者用户自定义的 header。
5. **网络栈将请求头信息序列化并发送到服务器。**
6. **服务器返回 HTTP 响应，其中也包含响应头。**
7. **Chromium 网络栈使用 `BalsaHeaders` 类来解析和存储这些响应头信息。**
8. **Javascript 代码可以通过浏览器的 API (例如 `response.headers.get('Content-Type')`) 来访问这些响应头。**

在开发和测试 Chromium 的网络功能时，工程师会编写像 `balsa_headers_test.cc` 这样的测试文件来确保 `BalsaHeaders` 类的行为符合预期。如果在使用过程中出现与 HTTP 头相关的 bug，开发人员可能会通过分析网络请求和响应，并结合这些测试用例来定位问题。

**归纳一下它的功能 (第1部分):**

这部分代码的主要功能是**全面测试 `quiche::BalsaHeaders` 类和 `quiche::BalsaBuffer` 类的各项功能**，包括 header 的添加、替换、删除、迭代、首行设置，以及 buffer 的内存管理和写入操作。这些测试覆盖了正常情况和各种边界情况，旨在确保这两个类在处理 HTTP 报文头时的正确性和健壮性。同时也对 `BalsaBuffer` 类的基本内存管理和写入功能进行了测试。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/balsa/balsa_headers_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Note that several of the BalsaHeaders functions are
// tested in the balsa_frame_test as the BalsaFrame and
// BalsaHeaders classes are fairly related.

#include "quiche/balsa/balsa_headers.h"

#include <cstring>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/base/macros.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "quiche/balsa/balsa_enums.h"
#include "quiche/balsa/balsa_frame.h"
#include "quiche/balsa/simple_buffer.h"
#include "quiche/common/platform/api/quiche_expect_bug.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"

using absl::make_unique;
using testing::AnyOf;
using testing::Combine;
using testing::ElementsAre;
using testing::Eq;
using testing::StrEq;
using testing::ValuesIn;

namespace quiche {

namespace test {

class BalsaHeadersTestPeer {
 public:
  static void WriteFromFramer(BalsaHeaders* headers, const char* ptr,
                              size_t size) {
    headers->WriteFromFramer(ptr, size);
  }
};

namespace {

class BalsaBufferTest : public QuicheTest {
 public:
  void CreateBuffer(size_t blocksize) {
    buffer_ = std::make_unique<BalsaBuffer>(blocksize);
  }
  void CreateBuffer() { buffer_ = std::make_unique<BalsaBuffer>(); }
  static std::unique_ptr<BalsaBuffer> CreateUnmanagedBuffer(size_t blocksize) {
    return std::make_unique<BalsaBuffer>(blocksize);
  }
  absl::string_view Write(absl::string_view sp, size_t* block_buffer_idx) {
    if (sp.empty()) {
      return sp;
    }
    char* storage = buffer_->Reserve(sp.size(), block_buffer_idx);
    memcpy(storage, sp.data(), sp.size());
    return absl::string_view(storage, sp.size());
  }

 protected:
  std::unique_ptr<BalsaBuffer> buffer_;
};

using BufferBlock = BalsaBuffer::BufferBlock;

BufferBlock MakeBufferBlock(const std::string& s) {
  // Make the buffer twice the size needed to verify that CopyFrom copies our
  // buffer_size (as opposed to shrinking to fit or reusing an old buffer).
  BufferBlock block{make_unique<char[]>(s.size()), s.size() * 2, s.size()};
  std::memcpy(block.buffer.get(), s.data(), s.size());
  return block;
}

BalsaHeaders CreateHTTPHeaders(bool request, absl::string_view s) {
  BalsaHeaders headers;
  BalsaFrame framer;
  framer.set_is_request(request);
  framer.set_balsa_headers(&headers);
  QUICHE_CHECK_EQ(s.size(), framer.ProcessInput(s.data(), s.size()));
  QUICHE_CHECK(framer.MessageFullyRead());
  return headers;
}

class BufferBlockTest
    : public QuicheTestWithParam<std::tuple<const char*, const char*>> {};

TEST_P(BufferBlockTest, CopyFrom) {
  const std::string s1 = std::get<0>(GetParam());
  const std::string s2 = std::get<1>(GetParam());
  BufferBlock block;
  block.CopyFrom(MakeBufferBlock(s1));
  EXPECT_EQ(s1.size(), block.bytes_free);
  ASSERT_EQ(2 * s1.size(), block.buffer_size);
  EXPECT_EQ(0, memcmp(s1.data(), block.buffer.get(), s1.size()));
  block.CopyFrom(MakeBufferBlock(s2));
  EXPECT_EQ(s2.size(), block.bytes_free);
  ASSERT_EQ(2 * s2.size(), block.buffer_size);
  EXPECT_EQ(0, memcmp(s2.data(), block.buffer.get(), s2.size()));
}

const char* block_strings[] = {"short string", "longer than the other string"};
INSTANTIATE_TEST_SUITE_P(VariousSizes, BufferBlockTest,
                         Combine(ValuesIn(block_strings),
                                 ValuesIn(block_strings)));

TEST_F(BalsaBufferTest, BlocksizeSet) {
  CreateBuffer();
  EXPECT_EQ(BalsaBuffer::kDefaultBlocksize, buffer_->blocksize());
  CreateBuffer(1024);
  EXPECT_EQ(1024u, buffer_->blocksize());
}

TEST_F(BalsaBufferTest, GetMemorySize) {
  CreateBuffer(10);
  EXPECT_EQ(0u, buffer_->GetTotalBytesUsed());
  EXPECT_EQ(0u, buffer_->GetTotalBufferBlockSize());
  BalsaBuffer::Blocks::size_type index;
  buffer_->Reserve(1024, &index);
  EXPECT_EQ(10u + 1024u, buffer_->GetTotalBufferBlockSize());
  EXPECT_EQ(1024u, buffer_->GetTotalBytesUsed());
}

TEST_F(BalsaBufferTest, ManyWritesToContiguousBuffer) {
  CreateBuffer(0);
  // The test is that the process completes.  If it needs to do a resize on
  // every write, it will timeout or run out of memory.
  // ( 10 + 20 + 30 + ... + 1.2e6 bytes => ~1e11 bytes )
  std::string data = "0123456789";
  for (int i = 0; i < 120 * 1000; ++i) {
    buffer_->WriteToContiguousBuffer(data);
  }
}

TEST_F(BalsaBufferTest, CopyFrom) {
  CreateBuffer(10);
  std::unique_ptr<BalsaBuffer> ptr = CreateUnmanagedBuffer(1024);
  ASSERT_EQ(1024u, ptr->blocksize());
  EXPECT_EQ(0u, ptr->num_blocks());

  std::string data1 = "foobarbaz01";
  buffer_->WriteToContiguousBuffer(data1);
  buffer_->NoMoreWriteToContiguousBuffer();
  std::string data2 = "12345";
  Write(data2, nullptr);
  std::string data3 = "6789";
  Write(data3, nullptr);
  std::string data4 = "123456789012345";
  Write(data3, nullptr);

  ptr->CopyFrom(*buffer_);

  EXPECT_EQ(ptr->can_write_to_contiguous_buffer(),
            buffer_->can_write_to_contiguous_buffer());
  ASSERT_EQ(ptr->num_blocks(), buffer_->num_blocks());
  for (size_t i = 0; i < buffer_->num_blocks(); ++i) {
    ASSERT_EQ(ptr->bytes_used(i), buffer_->bytes_used(i));
    ASSERT_EQ(ptr->buffer_size(i), buffer_->buffer_size(i));
    EXPECT_EQ(0,
              memcmp(ptr->GetPtr(i), buffer_->GetPtr(i), ptr->bytes_used(i)));
  }
}

TEST_F(BalsaBufferTest, ClearWorks) {
  CreateBuffer(10);

  std::string data1 = "foobarbaz01";
  buffer_->WriteToContiguousBuffer(data1);
  buffer_->NoMoreWriteToContiguousBuffer();
  std::string data2 = "12345";
  Write(data2, nullptr);
  std::string data3 = "6789";
  Write(data3, nullptr);
  std::string data4 = "123456789012345";
  Write(data3, nullptr);

  buffer_->Clear();

  EXPECT_TRUE(buffer_->can_write_to_contiguous_buffer());
  EXPECT_EQ(10u, buffer_->blocksize());
  EXPECT_EQ(0u, buffer_->num_blocks());
}

TEST_F(BalsaBufferTest, ClearWorksWhenLargerThanBlocksize) {
  CreateBuffer(10);

  std::string data1 = "foobarbaz01lkjasdlkjasdlkjasd";
  buffer_->WriteToContiguousBuffer(data1);
  buffer_->NoMoreWriteToContiguousBuffer();
  std::string data2 = "12345";
  Write(data2, nullptr);
  std::string data3 = "6789";
  Write(data3, nullptr);
  std::string data4 = "123456789012345";
  Write(data3, nullptr);

  buffer_->Clear();

  EXPECT_TRUE(buffer_->can_write_to_contiguous_buffer());
  EXPECT_EQ(10u, buffer_->blocksize());
  EXPECT_EQ(0u, buffer_->num_blocks());
}

TEST_F(BalsaBufferTest, ContiguousWriteSmallerThanBlocksize) {
  CreateBuffer(1024);

  std::string data1 = "foo";
  buffer_->WriteToContiguousBuffer(data1);
  std::string composite = data1;
  const char* buf_ptr = buffer_->GetPtr(0);
  ASSERT_LE(composite.size(), buffer_->buffer_size(0));
  EXPECT_EQ(0, memcmp(composite.data(), buf_ptr, composite.size()));

  std::string data2 = "barbaz";
  buffer_->WriteToContiguousBuffer(data2);
  composite += data2;
  buf_ptr = buffer_->GetPtr(0);
  ASSERT_LE(composite.size(), buffer_->buffer_size(0));
  EXPECT_EQ(0, memcmp(composite.data(), buf_ptr, composite.size()));
}

TEST_F(BalsaBufferTest, SingleContiguousWriteLargerThanBlocksize) {
  CreateBuffer(10);

  std::string data1 = "abracadabrawords";
  buffer_->WriteToContiguousBuffer(data1);
  std::string composite = data1;
  const char* buf_ptr = buffer_->GetPtr(0);
  ASSERT_LE(data1.size(), buffer_->buffer_size(0));
  EXPECT_EQ(0, memcmp(composite.data(), buf_ptr, composite.size()))
      << composite << "\n"
      << absl::string_view(buf_ptr, buffer_->bytes_used(0));
}

TEST_F(BalsaBufferTest, ContiguousWriteLargerThanBlocksize) {
  CreateBuffer(10);

  std::string data1 = "123456789";
  buffer_->WriteToContiguousBuffer(data1);
  std::string composite = data1;
  ASSERT_LE(10u, buffer_->buffer_size(0));

  std::string data2 = "0123456789";
  buffer_->WriteToContiguousBuffer(data2);
  composite += data2;

  const char* buf_ptr = buffer_->GetPtr(0);
  ASSERT_LE(composite.size(), buffer_->buffer_size(0));
  EXPECT_EQ(0, memcmp(composite.data(), buf_ptr, composite.size()))
      << "composite: " << composite << "\n"
      << "   actual: " << absl::string_view(buf_ptr, buffer_->bytes_used(0));
}

TEST_F(BalsaBufferTest, TwoContiguousWritesLargerThanBlocksize) {
  CreateBuffer(5);

  std::string data1 = "123456";
  buffer_->WriteToContiguousBuffer(data1);
  std::string composite = data1;
  ASSERT_LE(composite.size(), buffer_->buffer_size(0));

  std::string data2 = "7890123";
  buffer_->WriteToContiguousBuffer(data2);
  composite += data2;

  const char* buf_ptr = buffer_->GetPtr(0);
  ASSERT_LE(composite.size(), buffer_->buffer_size(0));
  EXPECT_EQ(0, memcmp(composite.data(), buf_ptr, composite.size()))
      << "composite: " << composite << "\n"
      << "   actual: " << absl::string_view(buf_ptr, buffer_->bytes_used(0));
}

TEST_F(BalsaBufferTest, WriteSmallerThanBlocksize) {
  CreateBuffer(5);
  std::string data1 = "1234";
  size_t block_idx = 0;
  absl::string_view write_result = Write(data1, &block_idx);
  ASSERT_EQ(1u, block_idx);
  EXPECT_THAT(write_result, StrEq(data1));

  CreateBuffer(5);
  data1 = "1234";
  block_idx = 0;
  write_result = Write(data1, &block_idx);
  ASSERT_EQ(1u, block_idx);
  EXPECT_THAT(write_result, StrEq(data1));
}

TEST_F(BalsaBufferTest, TwoWritesSmallerThanBlocksizeThenAnotherWrite) {
  CreateBuffer(10);
  std::string data1 = "12345";
  size_t block_idx = 0;
  absl::string_view write_result = Write(data1, &block_idx);
  ASSERT_EQ(1u, block_idx);
  EXPECT_THAT(write_result, StrEq(data1));

  std::string data2 = "data2";
  block_idx = 0;
  write_result = Write(data2, &block_idx);
  ASSERT_EQ(1u, block_idx);
  EXPECT_THAT(write_result, StrEq(data2));

  std::string data3 = "data3";
  block_idx = 0;
  write_result = Write(data3, &block_idx);
  ASSERT_EQ(2u, block_idx);
  EXPECT_THAT(write_result, StrEq(data3));

  CreateBuffer(10);
  buffer_->NoMoreWriteToContiguousBuffer();
  data1 = "12345";
  block_idx = 0;
  write_result = Write(data1, &block_idx);
  ASSERT_EQ(0u, block_idx);
  EXPECT_THAT(write_result, StrEq(data1));

  data2 = "data2";
  block_idx = 0;
  write_result = Write(data2, &block_idx);
  ASSERT_EQ(0u, block_idx);
  EXPECT_THAT(write_result, StrEq(data2));

  data3 = "data3";
  block_idx = 0;
  write_result = Write(data3, &block_idx);
  ASSERT_EQ(1u, block_idx);
  EXPECT_THAT(write_result, StrEq(data3));
}

TEST_F(BalsaBufferTest, WriteLargerThanBlocksize) {
  CreateBuffer(5);
  std::string data1 = "123456789";
  size_t block_idx = 0;
  absl::string_view write_result = Write(data1, &block_idx);
  ASSERT_EQ(1u, block_idx);
  EXPECT_THAT(write_result, StrEq(data1));

  CreateBuffer(5);
  buffer_->NoMoreWriteToContiguousBuffer();
  data1 = "123456789";
  block_idx = 0;
  write_result = Write(data1, &block_idx);
  ASSERT_EQ(1u, block_idx);
  EXPECT_THAT(write_result, StrEq(data1));
}

TEST_F(BalsaBufferTest, ContiguousThenTwoSmallerThanBlocksize) {
  CreateBuffer(5);
  std::string data1 = "1234567890";
  buffer_->WriteToContiguousBuffer(data1);
  size_t block_idx = 0;
  std::string data2 = "1234";
  absl::string_view write_result = Write(data2, &block_idx);
  ASSERT_EQ(1u, block_idx);
  std::string data3 = "1234";
  write_result = Write(data3, &block_idx);
  ASSERT_EQ(2u, block_idx);
}

TEST_F(BalsaBufferTest, AccessFirstBlockUninitialized) {
  CreateBuffer(5);
  EXPECT_EQ(0u, buffer_->GetReadableBytesOfFirstBlock());
  EXPECT_QUICHE_BUG(buffer_->StartOfFirstBlock(),
                    "First block not allocated yet!");
  EXPECT_QUICHE_BUG(buffer_->EndOfFirstBlock(),
                    "First block not allocated yet!");
}

TEST_F(BalsaBufferTest, AccessFirstBlockInitialized) {
  CreateBuffer(5);
  std::string data1 = "1234567890";
  buffer_->WriteToContiguousBuffer(data1);
  const char* start = buffer_->StartOfFirstBlock();
  EXPECT_TRUE(start != nullptr);
  const char* end = buffer_->EndOfFirstBlock();
  EXPECT_TRUE(end != nullptr);
  EXPECT_EQ(data1.length(), static_cast<size_t>(end - start));
  EXPECT_EQ(data1.length(), buffer_->GetReadableBytesOfFirstBlock());
}

TEST(BalsaHeaders, CanAssignBeginToIterator) {
  {
    BalsaHeaders header;
    BalsaHeaders::const_header_lines_iterator chli = header.lines().begin();
    static_cast<void>(chli);
  }
  {
    const BalsaHeaders header;
    BalsaHeaders::const_header_lines_iterator chli = header.lines().begin();
    static_cast<void>(chli);
  }
}

TEST(BalsaHeaders, CanAssignEndToIterator) {
  {
    BalsaHeaders header;
    BalsaHeaders::const_header_lines_iterator chli = header.lines().end();
    static_cast<void>(chli);
  }
  {
    const BalsaHeaders header;
    BalsaHeaders::const_header_lines_iterator chli = header.lines().end();
    static_cast<void>(chli);
  }
}

TEST(BalsaHeaders, ReplaceOrAppendHeaderTestAppending) {
  BalsaHeaders header;
  std::string key_1 = "key_1";
  std::string value_1 = "value_1";
  header.ReplaceOrAppendHeader(key_1, value_1);

  BalsaHeaders::const_header_lines_iterator chli = header.lines().begin();
  ASSERT_EQ(absl::string_view("key_1"), chli->first);
  ASSERT_EQ(absl::string_view("value_1"), chli->second);
  ++chli;
  ASSERT_NE(header.lines().begin(), chli);
  ASSERT_EQ(header.lines().end(), chli);
}

TEST(BalsaHeaders, ReplaceOrAppendHeaderTestReplacing) {
  BalsaHeaders header;
  std::string key_1 = "key_1";
  std::string value_1 = "value_1";
  std::string key_2 = "key_2";
  header.ReplaceOrAppendHeader(key_1, value_1);
  header.ReplaceOrAppendHeader(key_2, value_1);
  std::string value_2 = "value_2_string";
  header.ReplaceOrAppendHeader(key_1, value_2);

  BalsaHeaders::const_header_lines_iterator chli = header.lines().begin();
  ASSERT_EQ(key_1, chli->first);
  ASSERT_EQ(value_2, chli->second);
  ++chli;
  ASSERT_EQ(key_2, chli->first);
  ASSERT_EQ(value_1, chli->second);
  ++chli;
  ASSERT_NE(header.lines().begin(), chli);
  ASSERT_EQ(header.lines().end(), chli);
}

TEST(BalsaHeaders, ReplaceOrAppendHeaderTestReplacingMultiple) {
  BalsaHeaders header;
  std::string key_1 = "key_1";
  std::string key_2 = "key_2";
  std::string value_1 = "val_1";
  std::string value_2 = "val_2";
  std::string value_3 =
      "value_3_is_longer_than_value_1_and_value_2_and_their_keys";
  // Set up header keys 1, 1, 2.  We will replace the value of key 1 with a long
  // enough string that it should be moved to the end.  This regression tests
  // that replacement works if we move the header to the end.
  header.AppendHeader(key_1, value_1);
  header.AppendHeader(key_1, value_2);
  header.AppendHeader(key_2, value_1);
  header.ReplaceOrAppendHeader(key_1, value_3);

  BalsaHeaders::const_header_lines_iterator chli = header.lines().begin();
  ASSERT_EQ(key_1, chli->first);
  ASSERT_EQ(value_3, chli->second);
  ++chli;
  ASSERT_EQ(key_2, chli->first);
  ASSERT_EQ(value_1, chli->second);
  ++chli;
  ASSERT_NE(header.lines().begin(), chli);
  ASSERT_EQ(header.lines().end(), chli);

  // Now test that replacement works with a shorter value, so that if we ever do
  // in-place replacement it's tested.
  header.ReplaceOrAppendHeader(key_1, value_1);
  chli = header.lines().begin();
  ASSERT_EQ(key_1, chli->first);
  ASSERT_EQ(value_1, chli->second);
  ++chli;
  ASSERT_EQ(key_2, chli->first);
  ASSERT_EQ(value_1, chli->second);
  ++chli;
  ASSERT_NE(header.lines().begin(), chli);
  ASSERT_EQ(header.lines().end(), chli);
}

TEST(BalsaHeaders, AppendHeaderAndIteratorTest1) {
  BalsaHeaders header;
  ASSERT_EQ(header.lines().begin(), header.lines().end());
  {
    std::string key_1 = "key_1";
    std::string value_1 = "value_1";
    header.AppendHeader(key_1, value_1);
    key_1 = "garbage";
    value_1 = "garbage";
  }

  ASSERT_NE(header.lines().begin(), header.lines().end());
  BalsaHeaders::const_header_lines_iterator chli = header.lines().begin();
  ASSERT_EQ(header.lines().begin(), chli);
  ASSERT_NE(header.lines().end(), chli);
  ASSERT_EQ(absl::string_view("key_1"), chli->first);
  ASSERT_EQ(absl::string_view("value_1"), chli->second);

  ++chli;
  ASSERT_NE(header.lines().begin(), chli);
  ASSERT_EQ(header.lines().end(), chli);
}

TEST(BalsaHeaders, AppendHeaderAndIteratorTest2) {
  BalsaHeaders header;
  ASSERT_EQ(header.lines().begin(), header.lines().end());
  {
    std::string key_1 = "key_1";
    std::string value_1 = "value_1";
    header.AppendHeader(key_1, value_1);
    key_1 = "garbage";
    value_1 = "garbage";
  }
  {
    std::string key_2 = "key_2";
    std::string value_2 = "value_2";
    header.AppendHeader(key_2, value_2);
    key_2 = "garbage";
    value_2 = "garbage";
  }

  ASSERT_NE(header.lines().begin(), header.lines().end());
  BalsaHeaders::const_header_lines_iterator chli = header.lines().begin();
  ASSERT_EQ(header.lines().begin(), chli);
  ASSERT_NE(header.lines().end(), chli);
  ASSERT_EQ(absl::string_view("key_1"), chli->first);
  ASSERT_EQ(absl::string_view("value_1"), chli->second);

  ++chli;
  ASSERT_NE(header.lines().begin(), chli);
  ASSERT_NE(header.lines().end(), chli);
  ASSERT_EQ(absl::string_view("key_2"), chli->first);
  ASSERT_EQ(absl::string_view("value_2"), chli->second);

  ++chli;
  ASSERT_NE(header.lines().begin(), chli);
  ASSERT_EQ(header.lines().end(), chli);
}

TEST(BalsaHeaders, AppendHeaderAndIteratorTest3) {
  BalsaHeaders header;
  ASSERT_EQ(header.lines().begin(), header.lines().end());
  {
    std::string key_1 = "key_1";
    std::string value_1 = "value_1";
    header.AppendHeader(key_1, value_1);
    key_1 = "garbage";
    value_1 = "garbage";
  }
  {
    std::string key_2 = "key_2";
    std::string value_2 = "value_2";
    header.AppendHeader(key_2, value_2);
    key_2 = "garbage";
    value_2 = "garbage";
  }
  {
    std::string key_3 = "key_3";
    std::string value_3 = "value_3";
    header.AppendHeader(key_3, value_3);
    key_3 = "garbage";
    value_3 = "garbage";
  }

  ASSERT_NE(header.lines().begin(), header.lines().end());
  BalsaHeaders::const_header_lines_iterator chli = header.lines().begin();
  ASSERT_EQ(header.lines().begin(), chli);
  ASSERT_NE(header.lines().end(), chli);
  ASSERT_EQ(absl::string_view("key_1"), chli->first);
  ASSERT_EQ(absl::string_view("value_1"), chli->second);

  ++chli;
  ASSERT_NE(header.lines().begin(), chli);
  ASSERT_NE(header.lines().end(), chli);
  ASSERT_EQ(absl::string_view("key_2"), chli->first);
  ASSERT_EQ(absl::string_view("value_2"), chli->second);

  ++chli;
  ASSERT_NE(header.lines().begin(), chli);
  ASSERT_NE(header.lines().end(), chli);
  ASSERT_EQ(absl::string_view("key_3"), chli->first);
  ASSERT_EQ(absl::string_view("value_3"), chli->second);

  ++chli;
  ASSERT_NE(header.lines().begin(), chli);
  ASSERT_EQ(header.lines().end(), chli);
}

TEST(BalsaHeaders, AppendHeaderAndTestEraseWithIterator) {
  BalsaHeaders header;
  ASSERT_EQ(header.lines().begin(), header.lines().end());
  {
    std::string key_1 = "key_1";
    std::string value_1 = "value_1";
    header.AppendHeader(key_1, value_1);
    key_1 = "garbage";
    value_1 = "garbage";
  }
  {
    std::string key_2 = "key_2";
    std::string value_2 = "value_2";
    header.AppendHeader(key_2, value_2);
    key_2 = "garbage";
    value_2 = "garbage";
  }
  {
    std::string key_3 = "key_3";
    std::string value_3 = "value_3";
    header.AppendHeader(key_3, value_3);
    key_3 = "garbage";
    value_3 = "garbage";
  }
  BalsaHeaders::const_header_lines_iterator chli = header.lines().begin();
  ++chli;  // should now point to key_2.
  ASSERT_EQ(absl::string_view("key_2"), chli->first);
  header.erase(chli);
  chli = header.lines().begin();

  ASSERT_NE(header.lines().begin(), header.lines().end());
  ASSERT_EQ(header.lines().begin(), chli);
  ASSERT_NE(header.lines().end(), chli);
  ASSERT_EQ(absl::string_view("key_1"), chli->first);
  ASSERT_EQ(absl::string_view("value_1"), chli->second);

  ++chli;
  ASSERT_NE(header.lines().begin(), chli);
  ASSERT_NE(header.lines().end(), chli);
  ASSERT_EQ(absl::string_view("key_3"), chli->first);
  ASSERT_EQ(absl::string_view("value_3"), chli->second);

  ++chli;
  ASSERT_NE(header.lines().begin(), chli);
  ASSERT_EQ(header.lines().end(), chli);
}

TEST(BalsaHeaders, TestSetFirstlineInAdditionalBuffer) {
  BalsaHeaders headers;
  headers.SetRequestFirstlineFromStringPieces("GET", "/", "HTTP/1.0");
  ASSERT_THAT(headers.first_line(), StrEq("GET / HTTP/1.0"));
}

TEST(BalsaHeaders, TestSetFirstlineInOriginalBufferAndIsShorterThanOriginal) {
  BalsaHeaders headers = CreateHTTPHeaders(true,
                                           "GET /foobar HTTP/1.0\r\n"
                                           "\r\n");
  ASSERT_THAT(headers.first_line(), StrEq("GET /foobar HTTP/1.0"));
  // Note that this SetRequestFirstlineFromStringPieces should replace the
  // original one in the -non- 'additional' buffer.
  headers.SetRequestFirstlineFromStringPieces("GET", "/", "HTTP/1.0");
  ASSERT_THAT(headers.first_line(), StrEq("GET / HTTP/1.0"));
}

TEST(BalsaHeaders, TestSetFirstlineInOriginalBufferAndIsLongerThanOriginal) {
  // Similar to above, but this time the new firstline is larger than
  // the original, yet it should still fit into the original -non-
  // 'additional' buffer as the first header-line has been erased.
  BalsaHeaders headers = CreateHTTPHeaders(true,
                                           "GET / HTTP/1.0\r\n"
                                           "some_key: some_value\r\n"
                                           "another_key: another_value\r\n"
                                           "\r\n");
  ASSERT_THAT(headers.first_line(), StrEq("GET / HTTP/1.0"));
  headers.erase(headers.lines().begin());
  // Note that this SetRequestFirstlineFromStringPieces should replace the
  // original one in the -non- 'additional' buffer.
  headers.SetRequestFirstlineFromStringPieces("GET", "/foobar", "HTTP/1.0");
  ASSERT_THAT(headers.first_line(), StrEq("GET /foobar HTTP/1.0"));
}

TEST(BalsaHeaders, TestSetFirstlineInAdditionalDataAndIsShorterThanOriginal) {
  BalsaHeaders headers;
  headers.SetRequestFirstlineFromStringPieces("GET", "/foobar", "HTTP/1.0");
  ASSERT_THAT(headers.first_line(), StrEq("GET /foobar HTTP/1.0"));
  headers.SetRequestFirstlineFromStringPieces("GET", "/", "HTTP/1.0");
  ASSERT_THAT(headers.first_line(), StrEq("GET / HTTP/1.0"));
}

TEST(BalsaHeaders, TestSetFirstlineInAdditionalDataAndIsLongerThanOriginal) {
  BalsaHeaders headers;
  headers.SetRequestFirstlineFromStringPieces("GET", "/", "HTTP/1.0");
  ASSERT_THAT(headers.first_line(), StrEq("GET / HTTP/1.0"));
  headers.SetRequestFirstlineFromStringPieces("GET", "/foobar", "HTTP/1.0");
  ASSERT_THAT(headers.first_line(), StrEq("GET /foobar HTTP/1.0"));
}

TEST(BalsaHeaders, TestDeletingSubstring) {
  BalsaHeaders headers;
  headers.SetRequestFirstlineFromStringPieces("GET", "/", "HTTP/1.0");
  headers.AppendHeader("key1", "value1");
  headers.AppendHeader("key2", "value2");
  headers.AppendHeader("key", "value");
  headers.AppendHeader("unrelated", "value");

  // RemoveAllOfHeader should not delete key1 or key2 given a substring.
  headers.RemoveAllOfHeader("key");
  EXPECT_TRUE(headers.HasHeader("key1"));
  EXPECT_TRUE(headers.HasHeader("key2"));
  EXPECT_TRUE(headers.HasHeader("unrelated"));
  EXPECT_FALSE(headers.HasHeader("key"));
  EXPECT_TRUE(headers.HasHeadersWithPrefix("key"));
  EXPECT_TRUE(headers.HasHeadersWithPrefix("KeY"));
  EXPECT_TRUE(headers.HasHeadersWithPrefix("UNREL"));
  EXPECT_FALSE(headers.HasHeadersWithPrefix("key3"));

  EXPECT_FALSE(headers.GetHeader("key1").empty());
  EXPECT_FALSE(headers.GetHeader("KEY1").empty());
  EXPECT_FALSE(headers.GetHeader("key2").empty());
  EXPECT_FALSE(headers.GetHeader("unrelated").empty());
  EXPECT_TRUE(headers.GetHeader("key").empty());

  // Add key back in.
  headers.AppendHeader("key", "");
  EXPECT_TRUE(headers.HasHeader("key"));
  EXPECT_TRUE(headers.HasHeadersWithPrefix("key"));
  EXPECT_TRUE(headers.GetHeader("key").empty());

  // RemoveAllHeadersWithPrefix should delete everything starting with key.
  headers.RemoveAllHeadersWithPrefix("key");
  EXPECT_FALSE(headers.HasHeader("key1"));
  EXPECT_FALSE(headers.HasHeader("key2"));
  EXPECT_TRUE(headers.HasHeader("unrelated"));
  EXPECT_FALSE(headers.HasHeader("key"));
  EXPECT_FALSE(headers.HasHeadersWithPrefix("key"));
  EXPECT_FALSE(headers.HasHeadersWithPrefix("key1"));
  EXPECT_FALSE(headers.HasHeadersWithPrefix("key2"));
  EXPECT_FALSE(headers.HasHeadersWithPrefix("kEy"));
  EXPECT_TRUE(headers.HasHeadersWithPrefix("unrelated"));

  EXPECT_TRUE(headers.GetHeader("key1").empty());
  EXPECT_TRUE(headers.GetHeader("key2").empty());
  EXPECT_FALSE(headers.GetHeader("unrelated").empty());
  EXPECT_TRUE(headers.GetHeader("key").empty());
}

TEST(BalsaHeaders, TestRemovingValues) {
  // Remove entire line from headers, twice. Ensures working line-skipping.
  // Skip consideration of a line whose key is larger than our search key.
  // Skip consideration of a line whose key is smaller than our search key.
  // Skip consideration of a line that is already marked for skipping.
  // Skip consideration of a line whose value is too small.
  // Skip consideration of a line whose key is correct in length but doesn't
  // match.
  {
    BalsaHeaders headers;
    headers.SetRequestFirstlineFromStringPieces("GET", "/", "HTTP/1.0");
    headers.AppendHeader("hi", "hello");
    headers.AppendHeader("key1", "val1");
    headers.AppendHeader("key1", "value2");
    headers.AppendHeader("key1", "value3");
    headers.AppendHeader("key2", "value4");
    headers.AppendHeader("unrelated", "value");

    EXPECT_EQ(0u, headers.RemoveValue("key1", ""));
    EXPECT_EQ(1u, headers.RemoveValue("key1", "value2"));

    std::string key1_vals = headers.GetAllOfHeaderAsString("key1");
    EXPECT_THAT(key1_vals, StrEq("val1,value3"));

    EXPECT_TRUE(headers.HeaderHasValue("key1", "val1"));
    EXPECT_TRUE(headers.HeaderHasValue("key1", "value3"));
    EXPECT_EQ("value4", headers.GetHeader("key2"));
    EXPECT_EQ("hello", headers.GetHeader("hi"));
    EXPECT_EQ("value", headers.GetHeader("unrelated"));
    EXPECT_FALSE(headers.HeaderHasValue("key1", "value2"));

    EXPECT_EQ(1u, headers.RemoveValue("key1", "value3"));

    key1_vals = headers.GetAllOfHeaderAsString("key1");
    EXPECT_THAT(key1_vals, StrEq("val1"));

    EXPECT_TRUE(headers.HeaderHasValue("key1", "val1"));
    EXPECT_EQ("value4", headers.GetHeader("key2"));
    EXPECT_EQ("hello", headers.GetHeader("hi"));
    EXPECT_EQ("value", headers.GetHeader("unrelated"));
    EXPECT_FALSE(headers.HeaderHasValue("key1", "value3"));
    EXPECT_FALSE(headers.HeaderHasValue("key1", "value2"));
  }

  // Remove/keep values with surrounding spaces.
  // Remove values from in between others in multi-value line.
  // Remove entire multi-value line.
  // Keep value in between removed values in multi-value line.
  // Keep trailing value that is too small to be matched after removing a match.
  // Keep value containing matched value (partial but not complete match).
  // Keep an empty header.
  {
    BalsaHeaders headers;
    headers.SetRequestFirstlineFromStringPieces("GET", "/", "HTTP/1.0");
    headers.AppendHeader("key1", "value1");
    headers.AppendHeader("key1", "value2, value3,value2");
    headers.AppendHeader("key1", "value4 ,value2,value5,val6");
    headers.AppendHeader("key1", "value2,  value2   , value2");
    headers.AppendHeader("key1", "  value2  ,   value2   ");
    headers.AppendHeader("key1", " value2 a");
    headers.AppendHeader("key1", "");
    headers.AppendHeader("key1", ",  ,,");
    headers.AppendHeader("unrelated", "value");

    EXPECT_EQ(8u, headers.RemoveValue("key1", "value2"));

    std::string key1_vals = headers.GetAllOfHeaderAsString("key1");
    EXPECT_THAT(key1_vals,
                StrEq("value1,value3,value4 ,value5,val6,value2 a,,,  ,,"));

    EXPECT_EQ("value", headers.GetHeader("unrelated"));
    EXPECT_TRUE(headers.HeaderHasValue("key1", "value1"));
    EXPECT_TRUE(headers.HeaderHasValue("key1", "value3"));
    EXPECT_TRUE(headers.HeaderHasValue("key1", "value4"));
    EXPECT_TRUE(headers.HeaderHasValue("key1", "value5"));
    EXPECT_TRUE(headers.HeaderHasValue("key1", "val6"));
    EXPECT_FALSE(headers.HeaderHasValue("key1", "value2"));
  }

  {
    const absl::string_view key("key");
    const absl::string_view value1("foo\0bar", 7);
    const absl::string_view value2("value2");
    const std::string value = absl::StrCat(value1, ",", value2);

    {
      BalsaHeaders headers;
      headers.AppendHeader(key, value);

      EXPECT_TRUE(headers.HeaderHasValue(key, value1));
      EXPECT_TRUE(headers.HeaderHasValue(key, value2));
      EXPECT_EQ(value, headers.GetAllOfHeaderAsString(key));

      EXPECT_EQ(1u, headers.RemoveValue(key, value2));

      EXPECT_TRUE(headers.HeaderHasValue(key, value1));
      EXPECT_FALSE(headers.HeaderHasValue(key, value2));
      EXPECT_EQ(value1, headers.GetAllOfHeaderAsString(key));
    }

    {
      BalsaHeaders headers;
      headers.AppendHeader(key, value1);
      headers.AppendHeader(key, value2);

      EXPECT_TRUE(headers.HeaderHasValue(key, value1));
      EXPECT_TRUE(headers.HeaderHasValue(key, value2));
      EXPECT_EQ(value, headers.GetAllOfHeaderAsString(key));

      EXPECT_EQ(1u, headers.RemoveValue(key, value2));

      EXPECT_TRUE(headers.HeaderHasValue(key, value1));
      EXPECT_FALSE(headers.HeaderHasValue(key, value2));
      EXPECT_EQ(value1, headers.GetAllOfHeaderAsString(key));
    }
  }
}

TEST(BalsaHeaders, ZeroAppendToHeaderWithCommaAndSpace) {
  // Create an initial header with zero 'X-Forwarded-For' headers.
  BalsaHeaders headers = CreateHTTPHeaders(true,
                                           "GET / HTTP/1.0\r\n"
                                           "\r\n");

  // Use AppendToHeaderWithCommaAndSpace to add 4 new 'X-Forwarded-For' headers.
  // Appending these headers should preserve the order in which they are added.
  // i.e. 1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4
  headers.AppendToHeaderWithCommaAndSpace("X-Forwarded-For", "1.1.1.1");
  headers.AppendToHeaderWithCommaAndSpace("X-Forwarded-For", "2.2.2.2");
  headers.AppendToHeaderWithCommaAndSpace("X-Forwarded-For", "3.3.3.3");
  headers.AppendToHeaderWithCommaAndSpace("X-Forwarded-For", "4.4.4.4");

  // Fetch the 'X-Forwarded-For' headers and compare them to the expected order.
  EXPECT_THAT(headers.GetAllOfHeader("X-Forwarded-For"),
              ElementsAre("1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4"));
}

TEST(BalsaHeaders, SingleAppendToHeaderWithCommaAndSpace) {
  // Create an initial header with one 'X-Forwarded-For' header.
  BalsaHeaders headers = CreateHTTPHeaders(true,
                                           "GET / HTTP/1.0\r\n"
                                           "X-Forwarded-For: 1.1.1.1\r\n"
                                           "\r\n");

  // Use AppendToHeaderWithCommaAndSpace to add 4 new 'X-Forwarded-For' headers.
  // Appending these headers should preserve the order in which they are added.
  // i.e. 1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4, 5.5.5.5
  headers.AppendToHeaderWithCommaAndSpace("X-Forwarded-For", "2.2.2.2");
  headers.AppendToHeaderWithCommaAndSpace("X-Forwarded-For", "3.3.3.3");
  headers.AppendToHeaderWithCommaAndSpace("X-Forwarded-For", "4.4.4.4");
  headers.AppendToHeaderWithCommaAndSpace("X-Forwarded-For", "5.5.5.5");

  // Fetch the 'X-Forwarded-For' headers and compare them to the expected order.
  EXPECT_THAT(headers.GetAllOfHeader("X-Forwarded-For"),
              ElementsAre("1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4, 5.5.5.5"));
}

TEST(BalsaHeaders, MultipleAppendToHeaderWithCommaAndSpace) {
  // Create an initial header with two 'X-Forwarded-For' headers.
  BalsaHeaders headers = CreateHTTPHeaders(true,
                                           "GET / HTTP/1.0\r\n"
                                           "X-Forwarded-For: 1.1.1.1\r\n"
                                           "X-Forwarded-For: 2.2.2.2\r\n"
                                           "\r\n");

  // Use AppendToHeaderWithCommaAndSpace to add 4 new 'X-Forwarded-For' headers.
  // Appending these headers should preserve the order in which they are added.
  // i.e. 1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4, 5.5.5.5, 6.6.6.6
  headers.AppendToHeaderWithCommaAndSpace("X-Forwarded-For", "3.3.3.3");
  headers.AppendToHeaderWithCommaAndSpace("X-Forwarded-For", "4.4.4.4");
  headers.AppendToHeaderWithCommaAndSpace("X-Forwarded-For", "5.5.5.5");
  headers.AppendToHeaderWithCommaAndSpace("X-Forwarded-For", "6.6.6.6");

  // Fetch the 'X-Forwarded-For' headers and compare them to the expected order
"""


```