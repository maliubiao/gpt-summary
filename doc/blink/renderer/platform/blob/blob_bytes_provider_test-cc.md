Response:
Let's break down the thought process for analyzing the provided C++ test file.

1. **Identify the Core Subject:** The filename `blob_bytes_provider_test.cc` immediately tells us the central class being tested is `BlobBytesProvider`.

2. **Understand the Purpose of a Test File:** Test files in software development are designed to verify the functionality of specific code units (like classes or functions). They do this by setting up scenarios, calling the code being tested, and then asserting that the actual outcome matches the expected outcome.

3. **Scan the Includes:** The `#include` directives reveal the dependencies and give clues about what `BlobBytesProvider` interacts with. Key includes are:
    * `<memory>`, `<utility>`: Standard C++ utilities for memory management.
    * `"base/containers/...`", `"base/files/...`", `"base/functional/...`", `"base/ranges/...`", `"base/run_loop.h"`, `"base/test/task_environment.h"`, `"base/time/time.h"`: These are all from Chromium's "base" library, indicating that `BlobBytesProvider` likely interacts with files, memory, threading/async operations, and time.
    * `"testing/gtest/include/gtest/gtest.h"`:  This confirms it's a unit test file using the Google Test framework.
    * `"third_party/blink/public/platform/platform.h"` and `"third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"`: These point to Blink-specific platform abstractions and testing utilities, indicating it's part of the rendering engine.

4. **Analyze the Test Fixture:** The `BlobBytesProviderTest` class, inheriting from `testing::Test`, sets up the testing environment.
    * `SetUp()`:  Initializes test data (`test_bytes1_`, `test_data1_`, etc.) which suggests `BlobBytesProvider` deals with byte arrays or data buffers. The `Platform::SetMainThreadTaskRunnerForTesting()` indicates involvement with Blink's threading model.
    * `TearDown()`: Cleans up resources, particularly running the `task_environment_` to process any pending asynchronous tasks.
    * `CreateProvider()`: A helper function to instantiate `BlobBytesProvider` instances, which is a common pattern in testing.
    * Member variables (`test_data1_`, `test_bytes1_`, etc.): Store the sample data used in the tests.

5. **Examine the Individual Test Cases (using `TEST_F`):**  Each `TEST_F` function focuses on testing a specific aspect of `BlobBytesProvider`.
    * `Consolidation`: Tests how the provider combines smaller data chunks into larger ones. The `kMaxConsolidatedItemSizeInBytes` constant is important here.
    * `RequestAsReply`: Tests retrieving the entire blob data as a contiguous memory block. The use of `base::BindOnce` suggests asynchronous operations or callbacks.
    * `RequestAsFile`: This is more complex. The `RequestAsFile` nested class and `INSTANTIATE_TEST_SUITE_P` with the `file_tests` array indicate thorough testing of writing blob data to files at various offsets and sizes. The temporary file creation using `base::CreateTemporaryFile` is crucial.
    * `RequestAsStream`:  Tests sending the blob data through a Mojo data pipe, which is a common inter-process communication mechanism in Chromium. The `mojo::ScopedDataPipeProducerHandle` and `mojo::ScopedDataPipeConsumerHandle` are key Mojo concepts. The watcher pattern confirms asynchronous streaming.

6. **Connect to Web Technologies (JavaScript, HTML, CSS):**  Based on the functionality observed in the tests, start drawing connections:
    * **Blobs in JavaScript:**  Immediately, the term "Blob" links directly to the JavaScript `Blob` API. This API allows web pages to handle raw binary data.
    * **File API:** The `RequestAsFile` tests strongly suggest interaction with the browser's File API, where JavaScript can create `File` objects (which are specialized Blobs).
    * **Downloading Files:**  The ability to write blob data to files is directly related to the functionality of downloading files from the web.
    * **Sending Data:** The `RequestAsStream` test using Mojo points to how blob data might be efficiently sent between different parts of the Chromium browser process (e.g., from the renderer to the browser process for download handling or network requests).
    * **HTML `<input type="file">`:**  When a user selects a file using `<input type="file">`, the browser often represents this file internally as a Blob.

7. **Infer Logic and Assumptions:**
    * **Consolidation Logic:** The assumption is that `BlobBytesProvider` has logic to efficiently store and manage blob data, avoiding excessive small allocations by consolidating smaller chunks.
    * **File Writing Logic:**  The `RequestAsFile` tests imply logic to correctly copy data from the internal representation of the blob to a file on disk, handling offsets and sizes.
    * **Streaming Logic:** The `RequestAsStream` test suggests logic to pipe the blob data through a Mojo data pipe in a non-blocking manner.

8. **Identify Potential Usage Errors:**  Think about how developers using the related APIs (even indirectly) might make mistakes:
    * **Incorrect Offset/Size:**  Providing invalid offsets or sizes to `RequestAsFile` could lead to data corruption or crashes.
    * **Writing to Read-Only Files:** Attempting to write blob data to a file opened only for reading will fail.
    * **Resource Leaks (less direct in this test):** While not directly tested here, improper management of `BlobBytesProvider` or related resources could lead to memory leaks.

9. **Structure the Output:** Organize the findings into clear categories: functionality, relationship to web technologies, logic/assumptions, and usage errors, as requested by the prompt. Provide concrete examples where possible.

This systematic approach, starting from the code itself and then expanding to its context within the browser and web technologies, allows for a comprehensive understanding of the test file's purpose and implications.这是名为 `blob_bytes_provider_test.cc` 的 Chromium Blink 引擎源代码文件，它位于 `blink/renderer/platform/blob` 目录下。从文件名和目录结构可以推断，这个文件是用于测试 `BlobBytesProvider` 类的。

以下是该文件的功能详细说明：

**主要功能:**

1. **测试 `BlobBytesProvider` 类的功能:**  这个文件包含了多个单元测试，用于验证 `BlobBytesProvider` 类的各种方法和功能是否按预期工作。`BlobBytesProvider` 的作用是提供对 Blob (Binary Large Object) 数据的字节级访问，它可能管理着 Blob 数据在内存或文件中的存储。

**具体测试的功能点:**

* **数据合并 (Consolidation):**  测试 `AppendData` 方法是否能有效地将多个小的数据块合并成一个更大的数据块，以提高存储和访问效率。它测试了合并后数据块的数量和大小，以及数据内容的正确性。
* **以回复形式请求数据 (RequestAsReply):** 测试 `RequestAsReply` 方法，该方法可能将 Blob 的全部数据以 `Vector<uint8_t>` 的形式同步返回。测试用例验证了返回数据的完整性和正确性。
* **以文件形式请求数据 (RequestAsFile):**  这是一个比较重要的测试集，它测试了 `RequestAsFile` 方法将 Blob 的一部分或全部数据写入到指定文件的能力。测试了以下场景：
    * 从空文件开始写入。
    * 从非零偏移量开始写入文件。
    * 向已存在的文件写入数据。
    * 测试了各种不同的偏移量和大小组合，确保写入的文件内容与 Blob 的相应部分一致。
    * 测试了提供无效文件句柄或不可写文件句柄时的行为。
* **以流形式请求数据 (RequestAsStream):** 测试 `RequestAsStream` 方法，该方法将 Blob 的数据通过 Mojo DataPipe 发送出去，实现异步的数据传输。测试用例验证了通过管道接收到的数据与 Blob 的原始数据是否一致。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`BlobBytesProvider` 是 Blink 渲染引擎内部的组件，它直接服务于 Web API 中的 Blob 对象。 JavaScript 可以创建和操作 Blob 对象，而 `BlobBytesProvider` 则负责在底层管理这些 Blob 对象的数据。

* **JavaScript `Blob` 对象:** 当 JavaScript 代码创建一个 `Blob` 对象时，Blink 引擎内部可能会使用 `BlobBytesProvider` 来存储和管理该 Blob 的数据。例如：

  ```javascript
  const blob = new Blob(['<p>Hello, world!</p>'], { type: 'text/html' });
  ```

  在这个例子中，`BlobBytesProvider` 可能会被用来存储包含 HTML 内容的字节流。

* **HTML `<input type="file">` 元素:** 当用户通过 `<input type="file">` 元素选择文件时，浏览器会创建一个 `File` 对象，它是 `Blob` 的子类。`BlobBytesProvider` 可能负责读取和管理这些文件的内容。

* **CSS `url()` 函数引用 Blob:**  CSS 中可以使用 `url()` 函数引用 Blob 对象作为图像或其他资源。例如：

  ```css
  .my-image {
    background-image: url(blob:http://example.com/d0f8b8d0-4b1c-4f0a-a9d1-b3b7e5c0a1b2);
  }
  ```

  在这个例子中，浏览器需要从指定的 Blob URL 获取数据来渲染背景图像。`BlobBytesProvider` 负责提供这些 Blob 的字节数据。

* **`FileReader` API:** JavaScript 的 `FileReader` API 可以用来读取 Blob 的内容。  `BlobBytesProvider` 在底层为 `FileReader` 提供数据源。例如：

  ```javascript
  const reader = new FileReader();
  reader.onload = function() {
    console.log(reader.result); // Blob 的内容
  };
  reader.readAsText(blob);
  ```

**逻辑推理及假设输入与输出:**

**测试用例: `Consolidation`**

* **假设输入:**  连续调用 `AppendData` 方法，分别传入字符串 "abc", "def", "ps1", "ps2"，以及一个大小超过 `kMaxConsolidatedItemSizeInBytes` 的数据块。
* **预期输出:**  `data->data_` 应该包含两个 `RawData` 对象。第一个 `RawData` 对象的大小为 12，内容为 "abcdefps1ps2"。第二个 `RawData` 对象的大小为 `kMaxConsolidatedItemSizeInBytes`。

**测试用例: `RequestAsFile`, `AtStartOfEmptyFile`**

* **假设输入:** `FileTestData` 参数为 `{0, 192}` (请求偏移量 0，大小 192 字节)。Blob 数据由 `test_data1_`, `test_data2_`, `test_data3_` 组成，总大小为 128 + 64 + 32 = 224 字节。目标文件为空。
* **预期输出:**  创建的临时文件的大小为 192 字节，文件的前 192 字节内容与 `combined_bytes_` 的前 192 字节内容一致。

**测试用例: `RequestAsStream`**

* **假设输入:** Blob 数据由 `test_data1_`, `test_data2_`, `test_data3_` 组成。
* **预期输出:** 通过 Mojo DataPipe 接收到的 `received_data` 与 `combined_bytes_` 完全一致。

**用户或编程常见的使用错误举例:**

* **`RequestAsFile` 中提供不可写的文件:** 用户可能会错误地使用只读模式打开文件，然后尝试使用 `RequestAsFile` 写入数据。测试用例 `RequestAsFile_UnwritableFile` 就模拟了这种情况，预期结果是写入操作失败，`last_modified` 回调参数为 `false`，且文件大小保持为 0。

* **`RequestAsFile` 中提供无效的文件句柄:** 如果传递给 `RequestAsFile` 的 `base::File` 对象是无效的（例如，未打开），测试用例 `RequestAsFile_InvaldFile` 验证了这种情况，预期结果是 `last_modified` 回调参数为 `false`。

* **在 JavaScript 中错误地处理 Blob 的异步操作:** 虽然这个测试文件主要关注 C++ 层面，但在 JavaScript 中，开发者可能会忘记 Blob 的读取操作是异步的，导致在数据加载完成前就尝试访问数据。例如，在 `FileReader.onload` 事件触发前就尝试使用 `reader.result`。

* **在 JavaScript 中创建过大的 Blob 导致内存问题:**  虽然 `BlobBytesProvider` 旨在高效管理 Blob 数据，但如果 JavaScript 代码创建了非常大的 Blob，仍然可能导致内存消耗过高，尤其是在资源受限的环境中。

总而言之，`blob_bytes_provider_test.cc` 是一个关键的测试文件，用于确保 Blink 引擎中 Blob 数据管理的核心组件 `BlobBytesProvider` 的稳定性和正确性，这直接关系到 Web 平台上 Blob 相关功能的正常运行。

### 提示词
```
这是目录为blink/renderer/platform/blob/blob_bytes_provider_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/blob/blob_bytes_provider.h"

#include <memory>
#include <utility>

#include "base/containers/heap_array.h"
#include "base/containers/span.h"
#include "base/files/file.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/ranges/algorithm.h"
#include "base/run_loop.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/scheduler/test/renderer_scheduler_test_support.h"

namespace blink {

class BlobBytesProviderTest : public testing::Test {
 public:
  void SetUp() override {
    Platform::SetMainThreadTaskRunnerForTesting();

    test_bytes1_.resize(128);
    for (wtf_size_t i = 0; i < test_bytes1_.size(); ++i)
      test_bytes1_[i] = i % 191;
    test_data1_ = RawData::Create();
    test_data1_->MutableData()->AppendVector(test_bytes1_);
    test_bytes2_.resize(64);
    for (wtf_size_t i = 0; i < test_bytes2_.size(); ++i)
      test_bytes2_[i] = i;
    test_data2_ = RawData::Create();
    test_data2_->MutableData()->AppendVector(test_bytes2_);
    test_bytes3_.resize(32);
    for (wtf_size_t i = 0; i < test_bytes3_.size(); ++i)
      test_bytes3_[i] = (i + 10) % 137;
    test_data3_ = RawData::Create();
    test_data3_->MutableData()->AppendVector(test_bytes3_);

    combined_bytes_.AppendVector(test_bytes1_);
    combined_bytes_.AppendVector(test_bytes2_);
    combined_bytes_.AppendVector(test_bytes3_);
  }

  void TearDown() override {
    task_environment_.RunUntilIdle();
    Platform::UnsetMainThreadTaskRunnerForTesting();
  }

  std::unique_ptr<BlobBytesProvider> CreateProvider(
      scoped_refptr<RawData> data = nullptr) {
    auto result = std::make_unique<BlobBytesProvider>();
    if (data)
      result->AppendData(std::move(data));
    return result;
  }

 protected:
  base::test::TaskEnvironment task_environment_;

  scoped_refptr<RawData> test_data1_;
  Vector<uint8_t> test_bytes1_;
  scoped_refptr<RawData> test_data2_;
  Vector<uint8_t> test_bytes2_;
  scoped_refptr<RawData> test_data3_;
  Vector<uint8_t> test_bytes3_;
  Vector<uint8_t> combined_bytes_;
};

TEST_F(BlobBytesProviderTest, Consolidation) {
  auto data = CreateProvider();
  DCHECK_CALLED_ON_VALID_SEQUENCE(data->sequence_checker_);

  data->AppendData(base::span_from_cstring("abc"));
  data->AppendData(base::span_from_cstring("def"));
  data->AppendData(base::span_from_cstring("ps1"));
  data->AppendData(base::span_from_cstring("ps2"));

  EXPECT_EQ(1u, data->data_.size());
  EXPECT_EQ(12u, data->data_[0]->size());
  EXPECT_EQ(0, memcmp(data->data_[0]->data(), "abcdefps1ps2", 12));

  auto large_data = base::HeapArray<char>::WithSize(
      BlobBytesProvider::kMaxConsolidatedItemSizeInBytes);
  data->AppendData(large_data);

  EXPECT_EQ(2u, data->data_.size());
  EXPECT_EQ(12u, data->data_[0]->size());
  EXPECT_EQ(BlobBytesProvider::kMaxConsolidatedItemSizeInBytes,
            data->data_[1]->size());
}

TEST_F(BlobBytesProviderTest, RequestAsReply) {
  auto provider = CreateProvider(test_data1_);
  Vector<uint8_t> received_bytes;
  provider->RequestAsReply(
      base::BindOnce([](Vector<uint8_t>* bytes_out,
                        const Vector<uint8_t>& bytes) { *bytes_out = bytes; },
                     &received_bytes));
  EXPECT_EQ(test_bytes1_, received_bytes);

  received_bytes.clear();
  provider = CreateProvider();
  provider->AppendData(test_data1_);
  provider->AppendData(test_data2_);
  provider->AppendData(test_data3_);
  provider->RequestAsReply(
      base::BindOnce([](Vector<uint8_t>* bytes_out,
                        const Vector<uint8_t>& bytes) { *bytes_out = bytes; },
                     &received_bytes));
  EXPECT_EQ(combined_bytes_, received_bytes);
}

namespace {

struct FileTestData {
  uint32_t offset;
  uint32_t size;
};

void PrintTo(const FileTestData& test, std::ostream* os) {
  *os << "offset: " << test.offset << ", size: " << test.size;
}

class RequestAsFile : public BlobBytesProviderTest,
                      public testing::WithParamInterface<FileTestData> {
 public:
  void SetUp() override {
    BlobBytesProviderTest::SetUp();
    test_provider_ = CreateProvider();
    test_provider_->AppendData(test_data1_);
    test_provider_->AppendData(test_data2_);
    test_provider_->AppendData(test_data3_);

    auto combined_bytes_span =
        base::span(combined_bytes_).subspan(GetParam().offset, GetParam().size);
    sliced_data_.AppendRange(combined_bytes_span.begin(),
                             combined_bytes_span.end());
  }

  base::File DoRequestAsFile(uint64_t source_offset,
                             uint64_t source_length,
                             uint64_t file_offset) {
    base::FilePath path;
    base::CreateTemporaryFile(&path);
    std::optional<base::Time> received_modified;
    test_provider_->RequestAsFile(
        source_offset, source_length,
        base::File(path, base::File::FLAG_OPEN | base::File::FLAG_WRITE),
        file_offset,
        base::BindOnce(
            [](std::optional<base::Time>* received_modified,
               std::optional<base::Time> modified) {
              *received_modified = modified;
            },
            &received_modified));
    base::File file(path, base::File::FLAG_OPEN | base::File::FLAG_READ |
                              base::File::FLAG_DELETE_ON_CLOSE);
    base::File::Info info;
    EXPECT_TRUE(file.GetInfo(&info));
    EXPECT_EQ(info.last_modified, received_modified);
    return file;
  }

 protected:
  std::unique_ptr<BlobBytesProvider> test_provider_;
  Vector<uint8_t> sliced_data_;
};

TEST_P(RequestAsFile, AtStartOfEmptyFile) {
  FileTestData test = GetParam();
  base::File file = DoRequestAsFile(test.offset, test.size, 0);

  base::File::Info info;
  EXPECT_TRUE(file.GetInfo(&info));
  EXPECT_EQ(static_cast<int64_t>(test.size), info.size);

  Vector<uint8_t> read_data(test.size);
  EXPECT_TRUE(file.ReadAndCheck(0, read_data));
  EXPECT_EQ(sliced_data_, read_data);
}

TEST_P(RequestAsFile, OffsetInEmptyFile) {
  FileTestData test = GetParam();
  int file_offset = 32;
  sliced_data_.InsertVector(0, Vector<uint8_t>(file_offset));

  base::File file = DoRequestAsFile(test.offset, test.size, file_offset);

  base::File::Info info;
  EXPECT_TRUE(file.GetInfo(&info));
  if (test.size == 0) {
    EXPECT_EQ(0, info.size);
  } else {
    EXPECT_EQ(static_cast<int64_t>(test.size) + 32, info.size);

    Vector<uint8_t> read_data(sliced_data_.size());
    EXPECT_TRUE(file.ReadAndCheck(0, read_data));
    EXPECT_EQ(sliced_data_, read_data);
  }
}

TEST_P(RequestAsFile, OffsetInNonEmptyFile) {
  FileTestData test = GetParam();
  size_t file_offset = 23;

  Vector<uint8_t> expected_data(1024, 42);

  base::FilePath path;
  base::CreateTemporaryFile(&path);
  {
    base::File file(path, base::File::FLAG_OPEN | base::File::FLAG_WRITE);
    EXPECT_TRUE(file.WriteAtCurrentPosAndCheck(expected_data));
  }

  base::span(expected_data).subspan(file_offset).copy_prefix_from(sliced_data_);

  test_provider_->RequestAsFile(
      test.offset, test.size,
      base::File(path, base::File::FLAG_OPEN | base::File::FLAG_WRITE),
      file_offset, base::BindOnce([](std::optional<base::Time> last_modified) {
        EXPECT_TRUE(last_modified);
      }));

  base::File file(path, base::File::FLAG_OPEN | base::File::FLAG_READ |
                            base::File::FLAG_DELETE_ON_CLOSE);
  base::File::Info info;
  EXPECT_TRUE(file.GetInfo(&info));
  EXPECT_EQ(static_cast<int64_t>(expected_data.size()), info.size);

  Vector<uint8_t> read_data(expected_data.size());
  EXPECT_TRUE(file.ReadAndCheck(0, read_data));
  EXPECT_EQ(expected_data, read_data);
}

const FileTestData file_tests[] = {
    {0, 128 + 64 + 32},  // The full amount of data.
    {0, 128 + 64},       // First two chunks.
    {10, 13},            // Just a subset of the first chunk.
    {10, 128},           // Parts of both the first and second chunk.
    {128, 64},           // The entire second chunk.
    {0, 0},              // Zero bytes from the beginning.
    {130, 10},           // Just a subset of the second chunk.
    {140, 0},            // Zero bytes from the middle of the second chunk.
    {10, 128 + 64},      // Parts of all three chunks.
};

INSTANTIATE_TEST_SUITE_P(BlobBytesProviderTest,
                         RequestAsFile,
                         testing::ValuesIn(file_tests));

TEST_F(BlobBytesProviderTest, RequestAsFile_MultipleChunks) {
  auto provider = CreateProvider();
  provider->AppendData(test_data1_);
  provider->AppendData(test_data2_);
  provider->AppendData(test_data3_);

  base::FilePath path;
  base::CreateTemporaryFile(&path);

  Vector<uint8_t> expected_data;
  for (size_t i = 0; i < combined_bytes_.size(); i += 16) {
    provider->RequestAsFile(
        i, 16, base::File(path, base::File::FLAG_OPEN | base::File::FLAG_WRITE),
        combined_bytes_.size() - i - 16,
        base::BindOnce([](std::optional<base::Time> last_modified) {
          EXPECT_TRUE(last_modified);
        }));
    auto combined_bytes_chunk = base::span(combined_bytes_).subspan(i, 16u);
    expected_data.insert(0, combined_bytes_chunk.data(),
                         combined_bytes_chunk.size());
  }

  base::File file(path, base::File::FLAG_OPEN | base::File::FLAG_READ |
                            base::File::FLAG_DELETE_ON_CLOSE);
  base::File::Info info;
  EXPECT_TRUE(file.GetInfo(&info));
  EXPECT_EQ(static_cast<int64_t>(combined_bytes_.size()), info.size);

  Vector<uint8_t> read_data(expected_data.size());
  EXPECT_TRUE(file.ReadAndCheck(0, read_data));
  EXPECT_EQ(expected_data, read_data);
}

TEST_F(BlobBytesProviderTest, RequestAsFile_InvaldFile) {
  auto provider = CreateProvider(test_data1_);

  provider->RequestAsFile(
      0, 16, base::File(), 0,
      base::BindOnce([](std::optional<base::Time> last_modified) {
        EXPECT_FALSE(last_modified);
      }));
}

TEST_F(BlobBytesProviderTest, RequestAsFile_UnwritableFile) {
  auto provider = CreateProvider(test_data1_);

  base::FilePath path;
  base::CreateTemporaryFile(&path);
  provider->RequestAsFile(
      0, 16, base::File(path, base::File::FLAG_OPEN | base::File::FLAG_READ), 0,
      base::BindOnce([](std::optional<base::Time> last_modified) {
        EXPECT_FALSE(last_modified);
      }));

  base::File file(path, base::File::FLAG_OPEN | base::File::FLAG_READ |
                            base::File::FLAG_DELETE_ON_CLOSE);
  base::File::Info info;
  EXPECT_TRUE(file.GetInfo(&info));
  EXPECT_EQ(0, info.size);
}

TEST_F(BlobBytesProviderTest, RequestAsStream) {
  auto provider = CreateProvider();
  provider->AppendData(test_data1_);
  provider->AppendData(test_data2_);
  provider->AppendData(test_data3_);

  mojo::ScopedDataPipeProducerHandle producer_handle;
  mojo::ScopedDataPipeConsumerHandle consumer_handle;
  ASSERT_EQ(mojo::CreateDataPipe(7, producer_handle, consumer_handle),
            MOJO_RESULT_OK);
  provider->RequestAsStream(std::move(producer_handle));

  Vector<uint8_t> received_data;
  base::RunLoop loop;
  mojo::SimpleWatcher watcher(
      FROM_HERE, mojo::SimpleWatcher::ArmingPolicy::AUTOMATIC,
      blink::scheduler::GetSequencedTaskRunnerForTesting());
  watcher.Watch(
      consumer_handle.get(), MOJO_HANDLE_SIGNAL_READABLE,
      MOJO_WATCH_CONDITION_SATISFIED,
      base::BindRepeating(
          [](mojo::DataPipeConsumerHandle pipe,
             base::RepeatingClosure quit_closure, Vector<uint8_t>* bytes_out,
             MojoResult result, const mojo::HandleSignalsState& state) {
            if (result == MOJO_RESULT_CANCELLED ||
                result == MOJO_RESULT_FAILED_PRECONDITION) {
              quit_closure.Run();
              return;
            }

            size_t num_bytes = 0;
            MojoResult query_result = pipe.ReadData(
                MOJO_READ_DATA_FLAG_QUERY, base::span<uint8_t>(), num_bytes);
            if (query_result == MOJO_RESULT_SHOULD_WAIT)
              return;
            EXPECT_EQ(MOJO_RESULT_OK, query_result);

            Vector<uint8_t> bytes(num_bytes);
            EXPECT_EQ(
                MOJO_RESULT_OK,
                pipe.ReadData(MOJO_READ_DATA_FLAG_ALL_OR_NONE,
                              base::as_writable_byte_span(bytes), num_bytes));
            bytes_out->AppendVector(bytes);
          },
          consumer_handle.get(), loop.QuitClosure(), &received_data));
  loop.Run();

  EXPECT_EQ(combined_bytes_, received_data);
}

}  // namespace

}  // namespace blink
```