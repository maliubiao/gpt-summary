Response:
Let's break down the thought process for analyzing the C++ test file and generating the explanation.

1. **Understand the Goal:** The request is to understand the functionality of `shared_buffer_test.cc`, explain its relation to web technologies, and point out potential user errors. This means focusing on what the *tests* are doing, not just the implementation details of `SharedBuffer` itself.

2. **Identify the Core Subject:** The filename and the `#include` directives (`shared_buffer.h`) immediately point to the `SharedBuffer` class as the central object of the tests. The `SegmentedBufferTest` also appears, suggesting a related but potentially separate concept.

3. **Analyze Each Test Case Individually:** This is the most crucial step. Go through each `TEST` function and figure out its purpose.

    * **`SegmentedBufferTest, TakeData`:** This test creates a `SegmentedBuffer`, appends string data, and then calls `TakeData()`. The assertions check if the `TakeData()` method correctly returns the appended data as a vector of character vectors. This suggests `SegmentedBuffer` is used to store data in chunks.

    * **`SharedBufferTest, getAsBytes`:** This test creates a `SharedBuffer`, appends string data, and then uses `GetBytes()` to retrieve the entire buffer as a single byte array. The assertion checks if the retrieved data matches the concatenated input strings. This indicates `SharedBuffer` can provide a contiguous view of its data.

    * **`SharedBufferTest, getPartAsBytes`:** Similar to the previous test, but it focuses on retrieving different *portions* of the `SharedBuffer` using `GetBytes()`. The loop iterates through different sizes to verify partial retrieval. This further confirms the ability to access parts of the buffer.

    * **`SharedBufferTest, getAsBytesLargeSegments`:** This test uses larger data segments (4096 bytes) to test the `GetBytes()` method. The assertions check if the retrieved data is correctly ordered and contains the expected characters. This likely tests how `SharedBuffer` handles larger amounts of data and segmentation.

    * **`SharedBufferTest, copy`:** This test creates a `SharedBuffer`, appends data multiple times, and then uses `CopyAs<Vector<char>>()` to create a copy. It verifies that the copy has the correct size and content. This highlights the ability to create a complete, independent copy of the buffer's data.

    * **`SharedBufferTest, constructorWithFlatData`:** This test creates a `SharedBuffer` directly from a flat `Vector<char>` and verifies that the internal representation remains flat (a single segment). This explores a specific constructor behavior.

    * **`SharedBufferTest, FlatData`:** This test checks the `FlatData` utility, which provides a flat view of the `SharedBuffer`'s data. It verifies that the size and content of the `FlatData` match the original buffer, even when the `SharedBuffer` has multiple segments. This is likely an optimization for accessing data in a contiguous manner.

    * **`SharedBufferTest, GetIteratorAt`:** This test focuses on the `GetIteratorAt()` method, which allows accessing data at a specific offset within the buffer. It checks various offsets, including within and between segments, and verifies the returned iterators and their content. This confirms the ability to access data at arbitrary positions.

    * **`SharedBufferIteratorTest, Empty`:** This test checks the behavior of iterators on an empty `SharedBuffer`. It verifies that the begin and end iterators are equal.

    * **`SharedBufferIteratorTest, SingleSegment`:** This test checks the iterator behavior on a `SharedBuffer` with a single segment. It iterates through the buffer and verifies the content.

4. **Identify Relationships to Web Technologies (JavaScript, HTML, CSS):** Now, connect the functionality of `SharedBuffer` (as demonstrated by the tests) to concepts in web development.

    * **JavaScript `ArrayBuffer` and `SharedArrayBuffer`:** The core concept of a raw byte buffer is directly analogous. `SharedBuffer` likely serves a similar purpose within the Blink rendering engine.

    * **HTML File Handling (e.g., `<input type="file">`, `FileReader`):** When a user uploads a file, the browser needs to store the file's contents. `SharedBuffer` is a good candidate for holding this raw data.

    * **Network Requests (e.g., `fetch` API):**  When the browser downloads resources, the raw bytes of the response need to be stored. `SharedBuffer` can be used here.

    * **Canvas API:** The Canvas API allows manipulation of raw pixel data. `SharedBuffer` could be used to store and access this data.

    * **CSS Font Data:**  Font files are binary data. `SharedBuffer` could be used to load and manage font data.

5. **Infer Logic and Provide Examples:**  Based on the test cases, create simple hypothetical scenarios. For example, if `Append` adds data, then appending "A" and then "B" should result in a buffer containing "AB". This demonstrates the sequential nature of appending.

6. **Identify Potential Usage Errors:** Think about common mistakes developers make when dealing with buffers and memory.

    * **Out-of-bounds access:** Trying to read or write beyond the allocated size of the buffer.
    * **Incorrect size calculation:**  Providing the wrong size when creating or accessing the buffer.
    * **Memory leaks (though `scoped_refptr` mitigates this in the C++ code):**  Not properly releasing the buffer's memory when it's no longer needed (less relevant due to the use of smart pointers in the test code, but a general buffer usage concern).
    * **Type mismatches:** Interpreting the buffer's contents as the wrong data type.

7. **Structure the Explanation:** Organize the findings into clear sections: Functionality, Relationship to Web Technologies, Logical Inference, and Common Usage Errors. Use bullet points and clear language.

8. **Refine and Review:** Read through the explanation to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might just say "stores data," but refining it to "efficiently stores and manages raw byte sequences" is more precise. Also, double-check that the examples are relevant and easy to understand.

By following these steps, we can effectively analyze the C++ test file and generate a comprehensive and informative explanation that addresses all aspects of the request.
这个C++源代码文件 `shared_buffer_test.cc` 是 Chromium Blink 引擎的一部分，它的主要功能是 **测试 `blink::SharedBuffer` 类的各种功能和特性**。 `SharedBuffer` 在 Blink 中用于表示共享的、不可变的字节序列，通常用于存储从网络加载的资源（如图片、脚本、样式表等）的内容。

以下是该测试文件涵盖的主要功能点，并说明了它们与 JavaScript、HTML、CSS 的关系，以及可能的逻辑推理和常见使用错误：

**1. `SegmentedBufferTest::TakeData()`**

*   **功能:** 测试 `blink::SegmentedBuffer` 类的 `TakeData()` 方法。 `SegmentedBuffer` 是 `SharedBuffer` 内部使用的辅助类，用于在内存中分段存储数据。`TakeData()` 方法将 `SegmentedBuffer` 中存储的数据移动到一个 `Vector<Vector<char>>` 中。
*   **与 Web 技术的关系:**  `SegmentedBuffer` 的存在是为了高效地管理可能来自不同来源或以不同大小块到达的数据。这与浏览器处理网络请求时逐步接收数据的情形有关。
*   **逻辑推理:**
    *   **假设输入:**  向 `SegmentedBuffer` 依次添加字符串 "Hello"、"World"、"Goodbye"。
    *   **预期输出:** `TakeData()` 返回的 `Vector<Vector<char>>` 包含三个内部 `Vector<char>`，分别存储 "Hello"、"World" 和 "Goodbye"。
*   **常见使用错误:**  由于 `TakeData()` 会移动数据，在调用之后尝试访问原始 `SegmentedBuffer` 的内容会导致未定义的行为。

**2. `SharedBufferTest::getAsBytes()`**

*   **功能:** 测试 `SharedBuffer` 的 `GetBytes()` 方法，该方法尝试将整个 buffer 的内容复制到一个预先分配好的 `uint8_t` 数组中。
*   **与 Web 技术的关系:**  当需要以连续的字节数组形式访问资源内容时（例如，传递给解码器、计算哈希值等），会使用此方法。这与 JavaScript 中 `ArrayBuffer` 的概念类似。
*   **逻辑推理:**
    *   **假设输入:** 创建一个 `SharedBuffer`，依次添加 "Hello"、"World" 和 "Goodbye"。
    *   **预期输出:** 调用 `GetBytes()` 后，目标 `uint8_t` 数组包含 "HelloWorldGoodbye" 的字节表示。
*   **常见使用错误:**
    *   **目标缓冲区太小:** 如果传递给 `GetBytes()` 的缓冲区大小小于 `SharedBuffer` 的实际大小，会导致数据截断或写入越界。
    *   **未初始化目标缓冲区:** 虽然测试代码使用了 `Uninit()`，但在实际使用中，如果目标缓冲区未初始化，可能会包含垃圾数据。

**3. `SharedBufferTest::getPartAsBytes()`**

*   **功能:**  测试 `GetBytes()` 方法获取 `SharedBuffer` 部分内容的能力。
*   **与 Web 技术的关系:**  在某些情况下，只需要处理资源内容的一部分，例如读取文件头信息或处理流式数据。
*   **逻辑推理:**
    *   **假设输入:**  创建一个包含 "HelloWorldGoodbye" 的 `SharedBuffer`。
    *   **预期输出:**  分别调用 `GetBytes()` 并指定不同大小的目标缓冲区（如 17, 7, 3），会得到 "HelloWorldGoodbye"、"HelloWo" 和 "Hel"。
*   **常见使用错误:**  指定的读取大小超过了 `SharedBuffer` 的剩余大小，会导致读取失败或未定义的行为。

**4. `SharedBufferTest::getAsBytesLargeSegments()`**

*   **功能:** 测试 `GetBytes()` 处理包含较大段的 `SharedBuffer` 的能力。
*   **与 Web 技术的关系:**  确保 `SharedBuffer` 能高效处理大型资源，例如大型图片或音视频文件。
*   **逻辑推理:**
    *   **假设输入:** 创建一个 `SharedBuffer`，包含三个大小为 4096 字节的段，分别填充 'a'、'b' 和 'c'。
    *   **预期输出:**  调用 `GetBytes()` 后，目标缓冲区的前 4096 字节为 'a'，接下来的 4096 字节为 'b'，最后 4096 字节为 'c'。

**5. `SharedBufferTest::copy()`**

*   **功能:** 测试 `SharedBuffer` 的 `CopyAs<Vector<char>>()` 方法，该方法创建一个包含 `SharedBuffer` 完整内容的新 `Vector<char>`。
*   **与 Web 技术的关系:**  在需要对资源内容进行修改但不希望影响原始 `SharedBuffer` 时，会使用拷贝。
*   **逻辑推理:**
    *   **假设输入:**  创建一个包含重复数据的 `SharedBuffer`。
    *   **预期输出:** `CopyAs<Vector<char>>()` 返回的 `Vector<char>` 包含与原始 `SharedBuffer` 相同的内容和大小。
*   **常见使用错误:**  没有意识到 `CopyAs` 会创建新的内存分配，在处理非常大的 buffer 时可能会导致内存消耗增加。

**6. `SharedBufferTest::constructorWithFlatData()`**

*   **功能:** 测试使用 `base::span` 直接从现有的 `Vector<char>` 创建 `SharedBuffer` 的构造函数。
*   **与 Web 技术的关系:**  当已经拥有内存中的数据并且需要将其包装成 `SharedBuffer` 时使用。
*   **逻辑推理:**
    *   **假设输入:**  一个包含 "FooBarBaz" 的 `Vector<char>`。
    *   **预期输出:**  使用此 `Vector<char>` 创建的 `SharedBuffer` 内部只有一个段，并且该段的内容与原始 `Vector<char>` 相同。

**7. `SharedBufferTest::FlatData()`**

*   **功能:** 测试 `SharedBuffer` 的 `DeprecatedFlatData` 结构，它提供了一个指向 `SharedBuffer` 底层数据的只读指针。
*   **与 Web 技术的关系:**  在需要直接访问 `SharedBuffer` 的连续内存块时（例如，传递给某些底层 API），可以使用此结构。
*   **逻辑推理:**
    *   **假设输入:**  一个包含多个段的 `SharedBuffer`。
    *   **预期输出:** `DeprecatedFlatData` 结构指向的数据与 `SharedBuffer` 的内容一致，并且大小相同。对于由单个连续内存块创建的 `SharedBuffer`，`FlatData` 不会进行额外的拷贝。

**8. `SharedBufferTest::GetIteratorAt()`**

*   **功能:** 测试 `SharedBuffer` 的 `GetIteratorAt()` 方法，该方法返回一个指向指定偏移量处的迭代器。
*   **与 Web 技术的关系:**  允许在 `SharedBuffer` 中进行随机访问，例如从特定位置开始读取数据。
*   **逻辑推理:**
    *   **假设输入:**  一个包含多个段的 `SharedBuffer`。
    *   **预期输出:**  调用 `GetIteratorAt()` 并传入不同的偏移量，会返回指向该偏移量对应数据段的迭代器。
*   **常见使用错误:**  传入的偏移量超出 `SharedBuffer` 的大小，会导致返回 `cend()` 迭代器，表示访问越界。

**9. `SharedBufferIteratorTest::Empty()` 和 `SharedBufferIteratorTest::SingleSegment()`**

*   **功能:** 测试 `SharedBuffer` 迭代器的行为，包括空 buffer 和只有一个段的 buffer 的情况。
*   **与 Web 技术的关系:**  迭代器用于遍历 `SharedBuffer` 的内容，例如逐段处理数据。
*   **逻辑推理:**
    *   **对于空 buffer:** `begin()` 和 `end()` 迭代器相等。
    *   **对于单段 buffer:** 迭代器可以正确地指向唯一的段，并且遍历结束后会到达 `end()`。

**与 JavaScript, HTML, CSS 的关系举例:**

*   **JavaScript:** 当 JavaScript 通过 `fetch` API 获取网络资源时，返回的 `Response` 对象可能包含一个 `body` 属性，该属性是一个 `ReadableStream`。  Blink 内部可能会使用 `SharedBuffer` 来存储接收到的数据块。  JavaScript 最终可以通过 `response.arrayBuffer()` 或 `response.blob()` 将这些数据转换为 `ArrayBuffer` 或 `Blob` 对象。
*   **HTML:**  `<img src="...">` 加载图片时，浏览器会下载图片数据并存储在内存中。 `SharedBuffer` 可以用来存储这些图片数据。 JavaScript 可以通过 Canvas API 访问图片的像素数据，这可能涉及到从 `SharedBuffer` 中读取数据。
*   **CSS:**  `@font-face` 规则加载字体文件时，浏览器会下载字体文件数据。 `SharedBuffer` 可以用来存储字体文件的数据。渲染引擎需要解析这些数据以渲染文本。

**总结:**

`shared_buffer_test.cc` 通过一系列单元测试，全面地验证了 `blink::SharedBuffer` 类的功能，包括创建、追加数据、获取数据、拷贝以及迭代等操作。 这些功能是 Blink 引擎高效处理网络资源和实现网页渲染的基础。理解这些测试用例有助于理解 `SharedBuffer` 的设计和使用场景。

Prompt: 
```
这是目录为blink/renderer/platform/wtf/shared_buffer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"

#include <algorithm>
#include <cstdlib>
#include <memory>

#include "base/containers/heap_array.h"
#include "base/memory/scoped_refptr.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

TEST(SegmentedBufferTest, TakeData) {
  char test_data0[] = "Hello";
  char test_data1[] = "World";
  char test_data2[] = "Goodbye";

  SegmentedBuffer buffer;
  buffer.Append(test_data0, strlen(test_data0));
  buffer.Append(test_data1, strlen(test_data1));
  buffer.Append(test_data2, strlen(test_data2));
  Vector<Vector<char>> data = std::move(buffer).TakeData();
  ASSERT_EQ(3U, data.size());
  EXPECT_EQ(data[0], base::make_span(test_data0, strlen(test_data0)));
  EXPECT_EQ(data[1], base::make_span(test_data1, strlen(test_data1)));
  EXPECT_EQ(data[2], base::make_span(test_data2, strlen(test_data2)));
}

TEST(SharedBufferTest, getAsBytes) {
  char test_data0[] = "Hello";
  char test_data1[] = "World";
  char test_data2[] = "Goodbye";

  scoped_refptr<SharedBuffer> shared_buffer =
      SharedBuffer::Create(test_data0, strlen(test_data0));
  shared_buffer->Append(test_data1, strlen(test_data1));
  shared_buffer->Append(test_data2, strlen(test_data2));

  const size_t size = shared_buffer->size();
  auto data = base::HeapArray<uint8_t>::Uninit(size);
  ASSERT_TRUE(shared_buffer->GetBytes(data));

  EXPECT_EQ(base::byte_span_from_cstring("HelloWorldGoodbye"), data.as_span());
}

TEST(SharedBufferTest, getPartAsBytes) {
  char test_data0[] = "Hello";
  char test_data1[] = "World";
  char test_data2[] = "Goodbye";

  scoped_refptr<SharedBuffer> shared_buffer =
      SharedBuffer::Create(test_data0, strlen(test_data0));
  shared_buffer->Append(test_data1, strlen(test_data1));
  shared_buffer->Append(test_data2, strlen(test_data2));

  struct TestData {
    size_t size;
    const char* expected;
  } test_data[] = {
      {17, "HelloWorldGoodbye"}, {7, "HelloWo"}, {3, "Hel"},
  };
  for (TestData& test : test_data) {
    auto data = base::HeapArray<uint8_t>::Uninit(test.size);
    ASSERT_TRUE(shared_buffer->GetBytes(data));
    EXPECT_EQ(std::string_view(test.expected, test.size),
              base::as_string_view(data));
  }
}

TEST(SharedBufferTest, getAsBytesLargeSegments) {
  Vector<char> vector0(0x4000);
  for (size_t i = 0; i < vector0.size(); ++i)
    vector0[i] = 'a';
  Vector<char> vector1(0x4000);
  for (size_t i = 0; i < vector1.size(); ++i)
    vector1[i] = 'b';
  Vector<char> vector2(0x4000);
  for (size_t i = 0; i < vector2.size(); ++i)
    vector2[i] = 'c';

  scoped_refptr<SharedBuffer> shared_buffer =
      SharedBuffer::Create(std::move(vector0));
  shared_buffer->Append(vector1);
  shared_buffer->Append(vector2);

  const size_t size = shared_buffer->size();
  auto data = base::HeapArray<uint8_t>::Uninit(size);
  ASSERT_TRUE(shared_buffer->GetBytes(data));

  ASSERT_EQ(0x4000U + 0x4000U + 0x4000U, size);
  int position = 0;
  for (int i = 0; i < 0x4000; ++i) {
    EXPECT_EQ('a', data[position]);
    ++position;
  }
  for (int i = 0; i < 0x4000; ++i) {
    EXPECT_EQ('b', data[position]);
    ++position;
  }
  for (int i = 0; i < 0x4000; ++i) {
    EXPECT_EQ('c', data[position]);
    ++position;
  }
}

TEST(SharedBufferTest, copy) {
  Vector<char> test_data(10000);
  std::generate(test_data.begin(), test_data.end(), &std::rand);

  size_t length = test_data.size();
  scoped_refptr<SharedBuffer> shared_buffer =
      SharedBuffer::Create(test_data.data(), length);
  shared_buffer->Append(test_data.data(), length);
  shared_buffer->Append(test_data.data(), length);
  shared_buffer->Append(test_data.data(), length);
  // sharedBuffer must contain data more than segmentSize (= 0x1000) to check
  // copy().
  ASSERT_EQ(length * 4, shared_buffer->size());

  Vector<char> clone = shared_buffer->CopyAs<Vector<char>>();
  ASSERT_EQ(length * 4, clone.size());
  const Vector<char> contiguous = shared_buffer->CopyAs<Vector<char>>();
  ASSERT_EQ(contiguous.size(), shared_buffer->size());
  ASSERT_EQ(0, memcmp(clone.data(), contiguous.data(), clone.size()));

  clone.AppendVector(test_data);
  ASSERT_EQ(length * 5, clone.size());
}

TEST(SharedBufferTest, constructorWithFlatData) {
  Vector<char> data;

  while (data.size() < 10000ul) {
    data.Append("FooBarBaz", 9ul);
    auto shared_buffer = SharedBuffer::Create(base::span(data));

    Vector<Vector<char>> segments;
    for (const auto& span : *shared_buffer) {
      segments.emplace_back();
      segments.back().AppendSpan(span);
    }

    // Shared buffers constructed from flat data should stay flat.
    ASSERT_EQ(segments.size(), 1ul);
    ASSERT_EQ(segments.front().size(), data.size());
    EXPECT_EQ(memcmp(segments.front().data(), data.data(), data.size()), 0);
  }
}

TEST(SharedBufferTest, FlatData) {
  auto check_flat_data = [](scoped_refptr<const SharedBuffer> shared_buffer) {
    const SegmentedBuffer::DeprecatedFlatData flat_buffer(shared_buffer.get());

    EXPECT_EQ(shared_buffer->size(), flat_buffer.size());
    size_t offset = 0;
    for (const auto& span : *shared_buffer) {
      EXPECT_EQ(span, base::span(flat_buffer).subspan(offset, span.size()));
      offset += span.size();

      // If the SharedBuffer is not segmented, FlatData doesn't copy any data.
      EXPECT_EQ(span.size() == flat_buffer.size(),
                span.data() == flat_buffer.data());
    }
  };

  scoped_refptr<SharedBuffer> shared_buffer = SharedBuffer::Create();

  // Add enough data to hit a couple of segments.
  while (shared_buffer->size() < 10000) {
    check_flat_data(shared_buffer);
    shared_buffer->Append("FooBarBaz", 9u);
  }
}

TEST(SharedBufferTest, GetIteratorAt) {
  Vector<char> data(300);
  std::generate(data.begin(), data.end(), &std::rand);
  auto buffer = SharedBuffer::Create();
  const size_t first_segment_size = 127;
  const size_t second_segment_size = data.size() - first_segment_size;
  buffer->Append(data.data(), first_segment_size);
  buffer->Append(data.data() + first_segment_size, second_segment_size);

  const auto it0 = buffer->GetIteratorAt(static_cast<size_t>(0));
  EXPECT_EQ(it0, buffer->cbegin());
  ASSERT_NE(it0, buffer->cend());
  ASSERT_EQ(it0->size(), 127u);
  EXPECT_EQ(0, memcmp(it0->data(), data.data(), it0->size()));

  const auto it1 = buffer->GetIteratorAt(static_cast<size_t>(1));
  EXPECT_NE(it1, buffer->cbegin());
  ASSERT_NE(it1, buffer->cend());
  ASSERT_EQ(it1->size(), 126u);
  EXPECT_EQ(0, memcmp(it1->data(), data.data() + 1, it1->size()));

  const auto it126 = buffer->GetIteratorAt(static_cast<size_t>(126));
  EXPECT_NE(it126, buffer->cbegin());
  ASSERT_NE(it126, buffer->cend());
  ASSERT_EQ(it126->size(), 1u);
  EXPECT_EQ(0, memcmp(it126->data(), data.data() + 126, it126->size()));

  const auto it127 = buffer->GetIteratorAt(static_cast<size_t>(127));
  EXPECT_NE(it127, buffer->cbegin());
  ASSERT_NE(it127, buffer->cend());
  ASSERT_EQ(it127->size(), second_segment_size);
  EXPECT_EQ(0, memcmp(it127->data(), data.data() + 127, it127->size()));

  const auto it128 = buffer->GetIteratorAt(static_cast<size_t>(128));
  EXPECT_NE(it128, buffer->cbegin());
  ASSERT_NE(it128, buffer->cend());
  ASSERT_EQ(it128->size(), second_segment_size - 1);
  EXPECT_EQ(0, memcmp(it128->data(), data.data() + 128, it128->size()));

  const auto it299 = buffer->GetIteratorAt(static_cast<size_t>(299));
  EXPECT_NE(it299, buffer->cbegin());
  ASSERT_NE(it299, buffer->cend());
  ASSERT_EQ(it299->size(), 1u);
  EXPECT_EQ(0, memcmp(it299->data(), data.data() + 299, it299->size()));

  // All of the iterators above are different each other.
  const SharedBuffer::Iterator iters[] = {
      it0, it1, it126, it127, it128, it299,
  };
  for (size_t i = 0; i < std::size(iters); ++i) {
    for (size_t j = 0; j < std::size(iters); ++j) {
      EXPECT_EQ(i == j, iters[i] == iters[j]);
    }
  }

  auto it = it0;
  ++it;
  EXPECT_EQ(it, it127);

  it = it1;
  ++it;
  EXPECT_EQ(it, it127);

  it = it126;
  ++it;
  EXPECT_EQ(it, it127);

  it = it127;
  ++it;
  EXPECT_EQ(it, buffer->cend());

  it = it128;
  ++it;
  EXPECT_EQ(it, buffer->cend());

  const auto it300 = buffer->GetIteratorAt(static_cast<size_t>(300));
  EXPECT_EQ(it300, buffer->cend());

  const auto it301 = buffer->GetIteratorAt(static_cast<size_t>(301));
  EXPECT_EQ(it301, buffer->cend());
}

TEST(SharedBufferIteratorTest, Empty) {
  auto buffer = SharedBuffer::Create();

  EXPECT_EQ(buffer->begin(), buffer->end());
  EXPECT_EQ(buffer->cbegin(), buffer->cend());
  EXPECT_EQ(buffer->GetIteratorAt(static_cast<size_t>(0)), buffer->end());
  EXPECT_EQ(buffer->GetIteratorAt(static_cast<size_t>(1)), buffer->end());
}

TEST(SharedBufferIteratorTest, SingleSegment) {
  auto buffer = SharedBuffer::Create("hello", static_cast<size_t>(5));

  EXPECT_EQ(buffer->begin(), buffer->cbegin());
  EXPECT_EQ(buffer->end(), buffer->cend());

  auto it = buffer->cbegin();
  ASSERT_NE(it, buffer->cend());

  EXPECT_EQ(String(base::as_bytes(*it)), "hello");

  ++it;

  EXPECT_EQ(it, buffer->cend());

  it = buffer->GetIteratorAt(static_cast<size_t>(0));
  EXPECT_EQ(String(base::as_bytes(*it)), "hello");

  it = buffer->GetIteratorAt(static_cast<size_t>(1));
  EXPECT_EQ(String(base::as_bytes(*it)), "ello");
  it = buffer->GetIteratorAt(static_cast<size_t>(4));
  EXPECT_EQ(String(base::as_bytes(*it)), "o");
  EXPECT_EQ(buffer->GetIteratorAt(static_cast<size_t>(5)), buffer->cend());
}

}  // namespace blink

"""

```