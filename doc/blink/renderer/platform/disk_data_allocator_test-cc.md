Response: My thinking process to answer the request about `disk_data_allocator_test.cc` went through these stages:

1. **Understand the Core Question:** The main goal is to understand what this test file does, its relevance to web technologies (JavaScript, HTML, CSS), and potential user/programming errors it helps uncover.

2. **Initial Code Scan (Keywords and Structure):** I quickly scanned the code for key terms and structure. I saw:
    * `#include` statements, particularly the ones mentioning `disk_data_allocator.h`, `gtest`, and `features.h`. This immediately told me it's a C++ test file for a disk data allocator.
    * `TEST_F` macros, indicating Google Test framework usage. Each `TEST_F` likely tests a specific functionality.
    * Names like `ReserveChunk`, `ReadWrite`, `Discard`, `FreeChunksMerging`, `ProvideFile`, `WriteWithLimitedCapacity`. These strongly suggest the features being tested.
    * The use of `InMemoryDataAllocator` initially puzzled me. I realized it's probably a mock or simplified implementation for testing purposes, not directly interacting with the actual disk in most tests. This is a common testing strategy.
    * The presence of `base::RandBytesAsString` and `memcmp` indicates testing of data integrity.

3. **Deconstruct Individual Tests:** I went through each `TEST_F` block and tried to understand its specific purpose:
    * **`ReserveChunk`:** Tests basic reservation and releasing of memory chunks.
    * **`ReadWrite`:** Verifies that data written to an allocated chunk can be read back correctly.
    * **`ReadWriteDiscardMultiple`:** Tests writing and reading multiple chunks, ensuring data integrity and proper discarding.
    * **`WriteEventuallyFail`:** Checks the behavior when the allocator runs out of space.
    * **`CanReuseFreedChunk`:**  Verifies that freed chunks can be reallocated.
    * **`ExactThenWorstFit`:** Explores the allocator's strategy for finding available chunks (exact fit first, then potentially worst fit).
    * **`FreeChunksMerging`:** Focuses on how the allocator merges adjacent free chunks to manage memory efficiently.
    * **`ProvideInvalidFile`/`ProvideValidFile`:** Tests the allocator's ability to work with actual disk files. This is important for real-world usage.
    * **`WriteWithLimitedCapacity`:**  Examines the allocator's behavior when a maximum disk capacity is enforced (likely through a feature flag).

4. **Identify Core Functionality:** From the individual tests, I pieced together the core responsibilities of the `DiskDataAllocator`:
    * Allocating and reserving chunks of memory (either in-memory for testing or on disk).
    * Writing data to allocated chunks.
    * Reading data from allocated chunks.
    * Discarding (freeing) allocated chunks.
    * Managing free chunks, including merging them.
    * Handling limited disk capacity.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):** This was the trickiest part. I had to think about *where* in the browser's rendering engine persistent data storage is needed:
    * **Caching:** Browsers cache resources (images, scripts, stylesheets) to speed up subsequent page loads. This is a prime candidate for using a disk data allocator.
    * **`localStorage`/`sessionStorage`:** These web APIs allow JavaScript to store data persistently. The underlying implementation likely involves a disk data allocator.
    * **IndexedDB:** A more powerful client-side database API. It certainly needs a robust disk storage mechanism.
    * **Service Workers:**  Can cache network requests and responses, requiring disk storage.
    * **Compiled Code/Bytecode Cache:**  The browser might cache compiled JavaScript or CSS to improve performance.

    I then tried to create concrete examples linking the allocator's actions to these web technologies. For instance, when a browser caches an image, the `DiskDataAllocator` would be used to reserve space on disk and write the image data.

6. **Logical Reasoning and Assumptions:** I looked for tests that involved a clear sequence of actions and predictable outcomes. The `FreeChunksMerging` test is a good example. I constructed a simple scenario with allocations and discards to illustrate the merging logic, specifying the expected state of the free chunks.

7. **Identify Potential User/Programming Errors:**  I considered common mistakes developers might make when dealing with persistent storage:
    * **Exceeding storage limits:** The `WriteEventuallyFail` and `WriteWithLimitedCapacity` tests directly relate to this.
    * **Data corruption:** The read/write tests and the use of `memcmp` are designed to catch this.
    * **Memory leaks (not explicitly tested here, but related to discarding):**  While not directly shown, the `Discard` tests ensure the allocator can reuse space, which helps prevent unbounded growth.
    * **Incorrectly handling file operations:** The `ProvideInvalidFile` and `ProvideValidFile` tests highlight the importance of providing a valid file handle.

8. **Structure the Answer:** I organized the information logically, starting with the core functionality, then connecting it to web technologies, providing examples, illustrating logical reasoning, and finally discussing potential errors. I used clear headings and bullet points to make the information easily digestible.

9. **Refine and Elaborate:** I reviewed my initial draft and added more detail and explanation where needed. For instance, I clarified the purpose of the `InMemoryDataAllocator` and provided more specific examples for the web technology connections.

By following these steps, I could comprehensively address the prompt and provide a detailed and informative answer. The key was to move from the low-level code details to the high-level implications for web developers and users.
这个C++源代码文件 `disk_data_allocator_test.cc` 是 Chromium Blink 渲染引擎的一部分，专门用于测试 `DiskDataAllocator` 类的功能。 `DiskDataAllocator` 的作用是在磁盘上分配和管理数据，例如用于缓存资源或者持久化某些状态。

**主要功能:**

该测试文件通过一系列单元测试来验证 `DiskDataAllocator` 的以下核心功能：

1. **分配内存块 (Chunk Allocation):**
   - 测试 `TryReserveChunk()` 方法，用于预留指定大小的磁盘空间块。
   - 验证预留的块的起始偏移量是否正确。
   - 测试当没有足够空间时，预留操作是否会失败。

2. **写入数据 (Data Writing):**
   - 测试 `Write()` 方法，将数据写入到预留的磁盘空间块中。
   - 验证写入的数据大小是否与预期一致。
   - 测试当磁盘空间不足时，写入操作是否会失败。

3. **读取数据 (Data Reading):**
   - 测试 `Read()` 方法，从已分配的磁盘空间块中读取数据。
   - 验证读取的数据与写入的数据是否一致。

4. **释放内存块 (Chunk Discarding):**
   - 测试 `Discard()` 方法，释放已分配的磁盘空间块，使其可以被重新使用。
   - 验证释放后，该空间可以被再次分配。

5. **空闲块管理 (Free Chunk Management):**
   - 测试当释放相邻的内存块时，它们是否能够合并成一个更大的空闲块。
   - 验证空闲块的大小和位置是否正确。
   - 测试分配器如何选择合适的空闲块来满足新的分配请求 (例如，精确匹配或最差匹配)。

6. **与文件系统交互 (File System Interaction):**
   - 测试 `ProvideTemporaryFile()` 方法，用于为分配器提供一个临时文件来存储数据。
   - 验证分配器在提供了有效文件后才能进行写入操作。
   - 测试使用实际文件进行读写操作。

7. **容量限制 (Capacity Limits):**
   - 测试在设置了最大磁盘容量的情况下，分配器是否能够正确处理空间不足的情况。

**与 JavaScript, HTML, CSS 的关系:**

`DiskDataAllocator` 并不直接暴露给 JavaScript, HTML 或 CSS，但它在 Blink 渲染引擎的底层发挥着重要作用，支持着与这些技术相关的关键功能：

* **HTTP 缓存 (HTTP Cache):** 浏览器会缓存从网络上下载的资源，例如图片、脚本、样式表等，以提高页面加载速度。 `DiskDataAllocator` 可以用来管理这些缓存数据在磁盘上的存储。
    * **举例:** 当浏览器下载一个 CSS 文件时，Blink 引擎可以使用 `DiskDataAllocator` 在磁盘上分配一块空间，并将 CSS 文件的内容写入其中。下次访问相同网页时，如果缓存有效，浏览器可以直接从磁盘读取 CSS 文件，而无需再次下载。

* **Service Worker 缓存:** Service Worker 可以拦截网络请求并提供缓存的响应。 `DiskDataAllocator` 可以用来存储 Service Worker 缓存的数据。
    * **举例:** 一个 Service Worker 可以缓存页面中使用的 JavaScript 文件。 当用户离线或网络较差时，Service Worker 可以从磁盘读取缓存的 JavaScript 文件并返回，确保应用的基本功能可用。

* **IndexedDB 存储:** IndexedDB 是一个浏览器提供的客户端数据库，允许 JavaScript 存储大量的结构化数据。 底层实现可能会使用类似 `DiskDataAllocator` 的机制来管理数据在磁盘上的存储。
    * **举例:** 一个在线笔记应用可以使用 IndexedDB 存储用户的笔记内容。  `DiskDataAllocator` 负责在后台管理这些笔记数据在磁盘上的分配和存储。

* **编译后的代码缓存:**  为了提高性能，浏览器可能会缓存编译后的 JavaScript 代码或者 CSS 样式。 `DiskDataAllocator` 可以用来存储这些编译后的代码。
    * **举例:**  V8 JavaScript 引擎可以将 JavaScript 代码编译成机器码并缓存起来。 `DiskDataAllocator` 可以用来管理这些编译后的代码在磁盘上的存储，下次加载相同脚本时可以直接使用缓存的版本。

**逻辑推理和假设输入/输出:**

**测试用例: `TEST_F(DiskDataAllocatorTest, ReserveChunk)`**

* **假设输入:**
    * 调用 `TryReserveChunk(100)`  (请求分配 100 字节)
    * 调用 `TryReserveChunk(100)`  (再次请求分配 100 字节)
    * 调用 `Discard()` 释放第二次分配的块
    * 调用 `TryReserveChunk(100)`  (再次请求分配 100 字节)
    * 调用 `TryReserveChunk(300)`  (请求分配 300 字节，但不持有结果)
    * 调用 `TryReserveChunk(100)`  (再次请求分配 100 字节)

* **预期输出:**
    * 第一次分配的块起始偏移量为 0。
    * 第二次分配的块起始偏移量为 100。
    * 第三次分配的块（在第二次释放后）起始偏移量为 100 (重用了之前释放的空间)。
    * 第四次分配的块起始偏移量为 200 (因为之前 300 字节的块由于没有持有而被释放，或者分配器找到了合适的空间)。

**测试用例: `TEST_F(DiskDataAllocatorTest, FreeChunksMerging)`**

* **假设输入:**
    * 分配 4 个大小为 100 字节的块 (编号为 0, 1, 2, 3)。
    * 依次释放块 0, 1, 2, 3。

* **预期输出:**
    * 释放块 0 后，存在一个 100 字节的空闲块。
    * 释放块 1 后，与之前的空闲块合并，存在一个 200 字节的空闲块。
    * 释放块 2 后，与之前的空闲块合并，存在一个 300 字节的空闲块。
    * 释放块 3 后，与之前的空闲块合并，存在一个 400 字节的空闲块。

**用户或编程常见的使用错误:**

虽然用户通常不会直接操作 `DiskDataAllocator`，但开发者在使用依赖于它的 Blink 功能时可能会遇到一些问题，而这些测试可以帮助避免这些问题：

1. **超出磁盘配额:** 如果尝试缓存或存储的数据超过了浏览器或操作系统分配的磁盘配额，`DiskDataAllocator` 可能会返回失败，导致功能异常。
   * **例子:**  一个离线应用尝试缓存大量图片，但用户的可用磁盘空间不足。 这可能会导致缓存失败，应用无法正常离线运行。

2. **数据损坏:**  如果写入或读取数据的过程中发生错误，可能会导致缓存数据损坏。 `ReadWrite` 测试可以帮助确保数据的完整性。
   * **例子:**  如果在写入缓存数据的过程中突然断电，可能会导致部分数据写入失败，下次读取时会得到损坏的数据。

3. **内存泄漏 (在 `DiskDataAllocator` 的上下文中指磁盘空间未释放):**  如果分配了磁盘空间但忘记释放，最终会导致磁盘空间耗尽。 `Discard` 相关的测试确保了空间可以被正确回收。
   * **例子:**  一个 Service Worker 缓存了大量的资源，但没有正确地清理过期的缓存，导致占用的磁盘空间不断增加。

4. **并发问题 (虽然测试中未直接体现):** 在多线程环境下使用 `DiskDataAllocator` 时，如果没有适当的同步机制，可能会导致数据竞争和状态不一致。 尽管此测试文件是单线程的，但在实际使用中，需要考虑线程安全。

总而言之， `disk_data_allocator_test.cc` 通过全面的测试用例，确保了 `DiskDataAllocator` 能够可靠地管理磁盘上的数据，这对于 Blink 渲染引擎的性能和功能至关重要，并间接地影响着 Web 开发者和用户的体验。

Prompt: 
```
这是目录为blink/renderer/platform/disk_data_allocator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/disk_data_allocator.h"

#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/files/file.h"
#include "base/files/file_util.h"
#include "base/rand_util.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/platform/disk_data_allocator_test_utils.h"
#include "third_party/blink/renderer/platform/disk_data_metadata.h"

using ThreadPoolExecutionMode =
    base::test::TaskEnvironment::ThreadPoolExecutionMode;

namespace blink {

class DiskDataAllocatorTest : public ::testing::Test {
 public:
  explicit DiskDataAllocatorTest(
      ThreadPoolExecutionMode thread_pool_execution_mode =
          ThreadPoolExecutionMode::DEFAULT)
      : task_environment_(base::test::TaskEnvironment::TimeSource::MOCK_TIME,
                          thread_pool_execution_mode) {}

  static std::vector<std::unique_ptr<DiskDataMetadata>>
  Allocate(InMemoryDataAllocator* allocator, size_t size, size_t count) {
    std::string random_data = base::RandBytesAsString(size);

    std::vector<std::unique_ptr<DiskDataMetadata>> all_metadata;
    for (size_t i = 0; i < count; i++) {
      auto reserved_chunk = allocator->TryReserveChunk(random_data.size());
      auto metadata = allocator->Write(std::move(reserved_chunk),
                                       base::as_byte_span(random_data));
      EXPECT_TRUE(metadata);
      EXPECT_EQ(metadata->start_offset(), static_cast<int64_t>(i * size));
      all_metadata.push_back(std::move(metadata));
    }
    return all_metadata;
  }

 protected:
  void SetUp() override {
    // On some platforms, initialization takes time, though it happens when
    // base::ThreadTicks is used. To prevent flakiness depending on test
    // execution ordering, force initialization.
    if (base::ThreadTicks::IsSupported())
      base::ThreadTicks::WaitUntilInitialized();
  }

  base::test::TaskEnvironment task_environment_;
};

TEST_F(DiskDataAllocatorTest, ReserveChunk) {
  InMemoryDataAllocator allocator;

  auto reserved_chunk_1 = allocator.TryReserveChunk(100);
  auto metadata_1 = reserved_chunk_1->Take();
  EXPECT_EQ(0, metadata_1->start_offset());

  auto reserved_chunk_2 = allocator.TryReserveChunk(100);
  auto metadata_2 = reserved_chunk_2->Take();
  EXPECT_EQ(100, metadata_2->start_offset());

  // Reserved chunk can be released via |Discard()|
  allocator.Discard(std::move(metadata_2));
  // Second chunk is reused.
  auto reserved_chunk_3 = allocator.TryReserveChunk(100);
  auto metadata_3 = reserved_chunk_3->Take();
  EXPECT_EQ(100, metadata_3->start_offset());

  // If a ReservedChunk is destructed with DiskDataMetadata, the chunk is
  // released automatically.
  auto reserved_chunk_4 = allocator.TryReserveChunk(300);
  reserved_chunk_4 = nullptr;
  auto reserved_chunk_5 = allocator.TryReserveChunk(100);
  auto metadata_5 = reserved_chunk_5->Take();
  EXPECT_EQ(200, metadata_5->start_offset());
}

TEST_F(DiskDataAllocatorTest, ReadWrite) {
  InMemoryDataAllocator allocator;

  constexpr size_t kSize = 1000;
  std::string random_data = base::RandBytesAsString(kSize);
  auto reserved_chunk = allocator.TryReserveChunk(kSize);
  ASSERT_TRUE(reserved_chunk);
  auto metadata = allocator.Write(std::move(reserved_chunk),
                                  base::as_byte_span(random_data));
  EXPECT_TRUE(metadata);
  EXPECT_EQ(kSize, metadata->size());

  auto read_data = std::vector<char>(kSize);
  allocator.Read(*metadata, base::as_writable_bytes(base::span(read_data)));

  EXPECT_EQ(0, memcmp(&read_data[0], random_data.c_str(), kSize));
}

TEST_F(DiskDataAllocatorTest, ReadWriteDiscardMultiple) {
  InMemoryDataAllocator allocator;

  std::vector<std::pair<std::unique_ptr<DiskDataMetadata>, std::string>>
      data_written;

  for (int i = 0; i < 10; i++) {
    int size = base::RandInt(100, 1000);
    auto data = base::RandBytesAsString(size);
    auto reserved_chunk = allocator.TryReserveChunk(size);
    ASSERT_TRUE(reserved_chunk);
    auto metadata =
        allocator.Write(std::move(reserved_chunk), base::as_byte_span(data));
    EXPECT_TRUE(metadata);
    data_written.emplace_back(std::move(metadata), data);
  }

  base::RandomShuffle(data_written.begin(), data_written.end());

  for (const auto& p : data_written) {
    size_t size = p.first->size();
    auto read_data = std::vector<char>(size);
    allocator.Read(*p.first, base::as_writable_bytes(base::span(read_data)));

    EXPECT_EQ(0, memcmp(&read_data[0], &p.second[0], size));
  }

  base::RandomShuffle(data_written.begin(), data_written.end());

  for (auto& p : data_written) {
    auto metadata = std::move(p.first);
    allocator.Discard(std::move(metadata));
  }
}

TEST_F(DiskDataAllocatorTest, WriteEventuallyFail) {
  InMemoryDataAllocator allocator;

  constexpr size_t kSize = 1 << 18;
  std::string random_data = base::RandBytesAsString(kSize);

  static_assert(4 * kSize == InMemoryDataAllocator::kMaxSize, "");
  for (int i = 0; i < 4; i++) {
    auto reserved_chunk = allocator.TryReserveChunk(random_data.size());
    ASSERT_TRUE(reserved_chunk);
    auto metadata = allocator.Write(std::move(reserved_chunk),
                                    base::as_byte_span(random_data));
    EXPECT_TRUE(metadata);
  }
  auto reserved_chunk = allocator.TryReserveChunk(random_data.size());
  ASSERT_TRUE(reserved_chunk);
  auto metadata = allocator.Write(std::move(reserved_chunk),
                                  base::as_byte_span(random_data));
  EXPECT_FALSE(metadata);
  EXPECT_FALSE(allocator.may_write());
}

TEST_F(DiskDataAllocatorTest, CanReuseFreedChunk) {
  InMemoryDataAllocator allocator;

  constexpr size_t kSize = 1 << 10;
  std::vector<std::unique_ptr<DiskDataMetadata>> all_metadata;

  for (int i = 0; i < 10; i++) {
    std::string random_data = base::RandBytesAsString(kSize);
    auto reserved_chunk = allocator.TryReserveChunk(random_data.size());
    ASSERT_TRUE(reserved_chunk);
    auto metadata = allocator.Write(std::move(reserved_chunk),
                                    base::as_byte_span(random_data));
    EXPECT_TRUE(metadata);
    all_metadata.push_back(std::move(metadata));
  }

  auto metadata = std::move(all_metadata[4]);
  ASSERT_TRUE(metadata);
  int64_t start_offset = metadata->start_offset();
  allocator.Discard(std::move(metadata));

  std::string random_data = base::RandBytesAsString(kSize);
  auto reserved_chunk = allocator.TryReserveChunk(random_data.size());
  ASSERT_TRUE(reserved_chunk);
  auto new_metadata = allocator.Write(std::move(reserved_chunk),
                                      base::as_byte_span(random_data));
  EXPECT_TRUE(new_metadata);
  EXPECT_EQ(new_metadata->start_offset(), start_offset);
}

TEST_F(DiskDataAllocatorTest, ExactThenWorstFit) {
  InMemoryDataAllocator allocator;

  int count = 10;
  size_t size_increment = 1000;
  std::vector<std::unique_ptr<DiskDataMetadata>> all_metadata;

  size_t size = 10000;
  // Allocate a bunch of random-sized
  for (int i = 0; i < count; i++) {
    std::string random_data = base::RandBytesAsString(size);
    auto reserved_chunk = allocator.TryReserveChunk(random_data.size());
    ASSERT_TRUE(reserved_chunk);
    auto metadata = allocator.Write(std::move(reserved_chunk),
                                    base::as_byte_span(random_data));
    EXPECT_TRUE(metadata);
    all_metadata.push_back(std::move(metadata));
    size += size_increment;
  }

  auto& hole_metadata = all_metadata[4];
  size_t hole_size = hole_metadata->size();
  int64_t hole_offset = hole_metadata->start_offset();
  allocator.Discard(std::move(hole_metadata));

  auto& larger_hole_metadata = all_metadata[9];
  int64_t larger_hole_offset = larger_hole_metadata->start_offset();
  allocator.Discard(std::move(larger_hole_metadata));

  std::string random_data = base::RandBytesAsString(hole_size);
  auto reserved_chunk = allocator.TryReserveChunk(random_data.size());
  ASSERT_TRUE(reserved_chunk);
  auto metadata = allocator.Write(std::move(reserved_chunk),
                                  base::as_byte_span(random_data));
  EXPECT_TRUE(metadata);
  // Exact fit.
  EXPECT_EQ(metadata->start_offset(), hole_offset);
  allocator.Discard(std::move(metadata));

  // -1 to check that this is not best fit.
  random_data = base::RandBytesAsString(hole_size - 1);
  reserved_chunk = allocator.TryReserveChunk(random_data.size());
  ASSERT_TRUE(reserved_chunk);
  metadata = allocator.Write(std::move(reserved_chunk),
                             base::as_byte_span(random_data));
  EXPECT_TRUE(metadata);
  EXPECT_EQ(metadata->start_offset(), larger_hole_offset);
}

TEST_F(DiskDataAllocatorTest, FreeChunksMerging) {
  constexpr size_t kSize = 100;

  auto allocator = std::make_unique<InMemoryDataAllocator>();
  auto chunks = Allocate(allocator.get(), kSize, 4);
  EXPECT_EQ(static_cast<int64_t>(4 * kSize), allocator->disk_footprint());
  EXPECT_EQ(0u, allocator->free_chunks_size());

  // Layout is (indices in |chunks|):
  // | 0 | 1 | 2 | 3 |
  // Discarding a higher index after a lower one triggers merging on the left.

  // Merge left.
  allocator->Discard(std::move(chunks[0]));
  EXPECT_EQ(1u, allocator->FreeChunks().size());
  allocator->Discard(std::move(chunks[1]));
  EXPECT_EQ(1u, allocator->FreeChunks().size());
  EXPECT_EQ(2 * kSize, allocator->FreeChunks().begin()->second);
  allocator->Discard(std::move(chunks[2]));
  EXPECT_EQ(1u, allocator->FreeChunks().size());
  EXPECT_EQ(3 * kSize, allocator->FreeChunks().begin()->second);
  EXPECT_EQ(3 * kSize, allocator->free_chunks_size());
  allocator->Discard(std::move(chunks[3]));
  EXPECT_EQ(1u, allocator->FreeChunks().size());
  EXPECT_EQ(4 * kSize, allocator->FreeChunks().begin()->second);
  EXPECT_EQ(static_cast<int64_t>(4 * kSize), allocator->disk_footprint());

  allocator = std::make_unique<InMemoryDataAllocator>();
  chunks = Allocate(allocator.get(), kSize, 4);

  // Merge right.
  allocator->Discard(std::move(chunks[3]));
  EXPECT_EQ(1u, allocator->FreeChunks().size());
  allocator->Discard(std::move(chunks[2]));
  EXPECT_EQ(1u, allocator->FreeChunks().size());
  EXPECT_EQ(2 * kSize, allocator->FreeChunks().begin()->second);
  allocator->Discard(std::move(chunks[0]));
  EXPECT_EQ(2u, allocator->FreeChunks().size());
  EXPECT_EQ(3 * kSize, allocator->free_chunks_size());
  // Multiple merges: left, then right.
  allocator->Discard(std::move(chunks[1]));
  EXPECT_EQ(1u, allocator->FreeChunks().size());

  allocator = std::make_unique<InMemoryDataAllocator>();
  chunks = Allocate(allocator.get(), kSize, 4);

  // Left then right merging.
  allocator->Discard(std::move(chunks[0]));
  allocator->Discard(std::move(chunks[2]));
  EXPECT_EQ(2u, allocator->FreeChunks().size());
  allocator->Discard(std::move(chunks[1]));
  EXPECT_EQ(1u, allocator->FreeChunks().size());
}

TEST_F(DiskDataAllocatorTest, ProvideInvalidFile) {
  DiskDataAllocator allocator;
  EXPECT_FALSE(allocator.may_write());
  allocator.ProvideTemporaryFile(base::File());
  EXPECT_FALSE(allocator.may_write());
}

TEST_F(DiskDataAllocatorTest, ProvideValidFile) {
  base::FilePath path;
  if (!base::CreateTemporaryFile(&path))
    GTEST_SKIP() << "Cannot create temporary file.";

  int flags = base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_READ |
              base::File::FLAG_WRITE | base::File::FLAG_DELETE_ON_CLOSE;
  auto file = base::File(base::FilePath(path), flags);
  if (!file.IsValid())
    GTEST_SKIP() << "Cannot create temporary file.";

  DiskDataAllocator allocator;
  EXPECT_FALSE(allocator.may_write());
  allocator.ProvideTemporaryFile(std::move(file));
  EXPECT_TRUE(allocator.may_write());

  // Test read/write with a real file.
  constexpr size_t kSize = 1000;
  std::string random_data = base::RandBytesAsString(kSize);
  auto reserved_chunk = allocator.TryReserveChunk(random_data.size());
  ASSERT_TRUE(reserved_chunk);
  auto metadata = allocator.Write(std::move(reserved_chunk),
                                  base::as_byte_span(random_data));
  if (!metadata) {
    GTEST_SKIP() << "Disk full?";
  }

  EXPECT_EQ(kSize, metadata->size());

  auto read_data = std::vector<char>(kSize);
  allocator.Read(*metadata, base::as_writable_bytes(base::span(read_data)));

  EXPECT_EQ(0, memcmp(&read_data[0], random_data.c_str(), kSize));
}

TEST_F(DiskDataAllocatorTest, WriteWithLimitedCapacity) {
  base::test::ScopedFeatureList features;
  const std::vector<base::test::FeatureRefAndParams> enabled_features = {
      {features::kCompressParkableStrings, {{"max_disk_capacity_mb", "1"}}}};
  features.InitWithFeaturesAndParameters(enabled_features, {});

  InMemoryDataAllocator allocator;

  constexpr size_t kMB = 1024 * 1024;

  {
    // If we use max capacity, another reservation should not be possible.
    auto reserved_chunk = allocator.TryReserveChunk(kMB);
    ASSERT_TRUE(reserved_chunk);
    auto reserved_chunk_failed = allocator.TryReserveChunk(1);
    ASSERT_FALSE(reserved_chunk_failed);
    // |reserved_chunk| will be released after this line.
  }

  // Tested condition:
  // | 1 (1MB - 1000) | free (500) | 3 (100) | free (400) |
  std::string random_data_1 = base::RandBytesAsString(kMB - 1000);
  auto reserved_chunk = allocator.TryReserveChunk(random_data_1.size());
  ASSERT_TRUE(reserved_chunk);
  auto metadata_1 = allocator.Write(std::move(reserved_chunk),
                                    base::as_byte_span(random_data_1));
  EXPECT_TRUE(metadata_1);

  std::string random_data_2 = base::RandBytesAsString(500);
  reserved_chunk = allocator.TryReserveChunk(random_data_2.size());
  ASSERT_TRUE(reserved_chunk);
  auto metadata_2 = allocator.Write(std::move(reserved_chunk),
                                    base::as_byte_span(random_data_2));
  EXPECT_TRUE(metadata_2);

  std::string random_data_3 = base::RandBytesAsString(100);
  reserved_chunk = allocator.TryReserveChunk(random_data_3.size());
  ASSERT_TRUE(reserved_chunk);
  auto metadata_3 = allocator.Write(std::move(reserved_chunk),
                                    base::as_byte_span(random_data_3));
  EXPECT_TRUE(metadata_3);

  allocator.Discard(std::move(metadata_2));

  // Second slot should be available.
  reserved_chunk = allocator.TryReserveChunk(450);
  ASSERT_TRUE(reserved_chunk);

  // Second slot is reserved. Now we should not find available slot.
  std::string random_data_4 = base::RandBytesAsString(450);
  auto reserved_chunk_2 = allocator.TryReserveChunk(random_data_4.size());
  ASSERT_FALSE(reserved_chunk_2);
}

}  // namespace blink

"""

```