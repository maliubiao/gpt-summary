Response:
Let's break down the thought process for analyzing the C++ unit test file `chunked_upload_data_stream_unittest.cc`.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `ChunkedUploadDataStream` class being tested. Unit tests are designed to verify specific behaviors and edge cases of a particular unit of code. Therefore, examining the test cases is the most direct way to understand the class's purpose.

**2. Initial Scan and Identification of Key Components:**

* **File Name:**  `chunked_upload_data_stream_unittest.cc` immediately tells us this is a test file for `ChunkedUploadDataStream`.
* **Includes:**  The included headers (`chunked_upload_data_stream.h`, `io_buffer.h`, `net_errors.h`, etc.) give hints about the class's dependencies and related concepts. We see things like "upload," "data stream," "IO buffer," and "network errors."
* **Test Fixture/Suite:** The `TEST()` macros indicate individual test cases within the `ChunkedUploadDataStreamTest` test suite. This helps organize the different aspects being tested.
* **Helper Functions:** The `ReadSync` function is a utility for simplifying synchronous reading from the stream. This points towards the core operation of the class: reading data.
* **Core Assertions:** The tests heavily use `ASSERT_THAT` and `EXPECT_EQ` (from Google Test) to verify expected outcomes. This is where the actual checks of the class's behavior happen.

**3. Analyzing Individual Test Cases (Iterative Process):**

For each test case, the thought process involves:

* **Test Name:**  The test name is often a good starting point. `AppendOnce`, `AppendOnceBeforeRead`, `MultipleAppends`, etc., clearly indicate what aspect of the class is being tested.
* **Setup:** Look for the creation of a `ChunkedUploadDataStream` object. Pay attention to how it's initialized (e.g., `stream(0)`). The `Init()` method is also crucial for understanding setup.
* **Actions:**  Identify the key actions being performed on the `ChunkedUploadDataStream` object. These usually involve:
    * `AppendData()`: Adding data to the stream. Note the `is_eof` flag.
    * `Read()`: Reading data from the stream.
    * `CreateWriter()`: Getting a writer object.
    * `Init()`:  Initializing or re-initializing the stream.
* **Assertions:** Examine the `ASSERT_THAT` and `EXPECT_EQ` statements. These verify:
    * The return value of `Init()` (should be `IsOk()`).
    * Stream properties like `IsInMemory()`, `size()`, `position()`, `IsEOF()`.
    * The data read from the stream using `ReadSync` or the callback.
* **Logical Inference (within a test):**  Understand the sequence of actions and how they are expected to affect the state of the stream. For example, in `AppendOnce`, the read should pend until data is appended.
* **Identifying Potential Issues:** Consider what could go wrong. For example, what happens if you try to read before appending data? What if you append after the stream is considered "ended"?

**4. Connecting to JavaScript (If Applicable):**

* **Identify the Core Functionality:** The `ChunkedUploadDataStream` is about sending data in chunks, a common technique in web requests.
* **Think about Web APIs:** JavaScript has APIs for making network requests, such as `fetch` and `XMLHttpRequest`.
* **Map Concepts:**  Relate the C++ concepts to their JavaScript counterparts. For example:
    * `ChunkedUploadDataStream` ->  The underlying mechanism that `fetch` or `XMLHttpRequest` might use for chunked uploads. The developer using JavaScript doesn't directly interact with this.
    * `AppendData()` ->  Conceptually similar to providing data to be sent in a request body.
    * `Read()` -> The browser internally reads from this stream to send the data over the network.
    * `is_eof` -> The signal that the upload is complete. This maps to the completion of the request in JavaScript.
* **Illustrative Examples:** Create simple JavaScript code snippets that demonstrate scenarios where chunked uploading might be used, even if the underlying `ChunkedUploadDataStream` is hidden.

**5. Identifying User/Programming Errors:**

* **Look for Potential Misuse:** Consider how a developer might incorrectly use the `ChunkedUploadDataStream` or related concepts.
* **Relate to Test Cases:** Some test cases implicitly highlight potential errors (e.g., appending data after marking the stream as finished).
* **Think about the API Contract:**  What are the expected preconditions and postconditions for the methods?  Violating these can lead to errors.

**6. Tracing User Actions (Debugging):**

* **Start with a User Action:**  Think of a user interaction in a web browser that would trigger a network request involving uploading data (e.g., uploading a large file).
* **Follow the Request:**  Imagine the steps the browser takes:
    * User initiates the upload.
    * JavaScript code (if any) prepares the data.
    * The browser's network stack takes over.
    * The `ChunkedUploadDataStream` (or a similar mechanism) might be used to handle the upload, especially for large files.
* **Identify Key Components:**  Recognize the involvement of JavaScript, browser network internals, and potentially server-side code.
* **Connect to the Test File:**  Understand that these unit tests are verifying the correct behavior of *one component* in this larger process. A bug in `ChunkedUploadDataStream` could manifest as an upload failure observed by the user.

**Self-Correction/Refinement During the Process:**

* **Initial Assumption Check:**  Are my initial assumptions about the class's purpose correct?  Do the test cases support this?
* **Clarification of Concepts:**  Do I fully understand terms like "chunked upload" and "data stream"? If not, I'd need to research those.
* **Refining JavaScript Examples:** Are my JavaScript examples clear and accurate in illustrating the connection (even if indirect)?
* **Improving Error Scenarios:** Are the user error examples realistic and helpful?

By following this structured approach, analyzing the test cases systematically, and relating the C++ code to higher-level concepts and user actions, a comprehensive understanding of the `ChunkedUploadDataStream` and its testing can be achieved.
这个文件 `net/base/chunked_upload_data_stream_unittest.cc` 是 Chromium 网络栈中 `ChunkedUploadDataStream` 类的单元测试文件。它的主要功能是 **验证 `ChunkedUploadDataStream` 类的正确性**。

以下是该文件功能的详细列表：

**核心功能验证:**

1. **追加数据 (Appending Data):**
   - 测试在读取之前、读取期间和读取之后追加数据到流的能力。
   - 验证可以多次追加数据。
   - 验证追加空数据。
   - 测试在 `Init` 方法调用之前和之后追加数据。

2. **读取数据 (Reading Data):**
   - 测试同步读取数据的功能 (`ReadSync` 辅助函数）。
   - 验证读取的数据与追加的数据是否一致。
   - 测试读取不同大小的数据块。
   - 测试在有未完成读取操作时追加数据的行为。
   - 验证当所有数据都读取完毕后，`IsEOF()` 返回 `true`。

3. **初始化 (Initialization):**
   - 测试 `Init` 方法的调用成功与否。
   - 验证初始化后流的状态（`IsInMemory()`, `size()`, `position()`, `IsEOF()`）。
   - 测试在追加数据之前和之后进行初始化。

4. **重置/重初始化 (Rewinding/Re-initialization):**
   - 测试在数据流完成后重新初始化流，并能够重新读取数据。
   - 测试在有未完成读取操作时重新初始化流的行为，验证未完成的读取操作被取消。

5. **空上传 (Empty Upload):**
   - 测试上传空数据的情况。
   - 测试在初始化之前就标记上传结束的情况。

6. **编写器 (Writer):**
   - 测试通过 `CreateWriter()` 方法创建的 `ChunkedUploadDataStream::Writer` 类的功能。
   - 验证在 `Init` 方法调用前后使用 Writer 追加数据。
   - 测试在数据流被销毁后使用 Writer 的行为。

**与其他 JavaScript 功能的关系：**

`ChunkedUploadDataStream` 类是网络栈内部实现细节，JavaScript 代码通常不会直接操作它。但是，它与 JavaScript 中发起网络请求的功能密切相关，尤其是在处理需要上传大量数据的场景下。

**举例说明:**

假设一个 JavaScript 网页需要上传一个大型文件，例如通过 `<input type="file">` 元素选择的文件。当使用 `fetch` API 或 `XMLHttpRequest` 对象发起 POST 请求时，浏览器可能会在底层使用类似 `ChunkedUploadDataStream` 的机制来实现分块上传。

```javascript
// JavaScript 示例 (使用 fetch API 上传文件)
const fileInput = document.getElementById('fileInput');
const file = fileInput.files[0];

fetch('/upload', {
  method: 'POST',
  body: file, // 浏览器可能会在底层将文件数据分块
})
.then(response => {
  // 处理上传成功
})
.catch(error => {
  // 处理上传失败
});
```

在这个例子中，虽然 JavaScript 代码直接将 `File` 对象作为 `fetch` 的 `body`，但浏览器内部的网络栈可能会使用类似 `ChunkedUploadDataStream` 的类来将文件数据分割成多个小块，并逐个发送到服务器。这样做的好处是可以避免一次性加载整个大文件到内存中，提高效率并降低内存占用。

**逻辑推理 (假设输入与输出):**

以下是一些测试用例的逻辑推理：

**测试用例: `AppendOnce`**

* **假设输入:**
    * 初始化一个空的 `ChunkedUploadDataStream`。
    * 尝试读取数据（预期返回 `ERR_IO_PENDING`）。
    * 追加字符串 "0123456789"，并标记为结束。
* **预期输出:**
    * 之前的读取操作完成，读取到 "0123456789"。
    * `position()` 为 10。
    * `IsEOF()` 返回 `true`。

**测试用例: `MultipleAppendsBetweenReads`**

* **假设输入:**
    * 初始化一个空的 `ChunkedUploadDataStream`。
    * 循环 10 次：
        * 追加一个字符。
        * 读取一个字符。
* **预期输出:**
    * 每次读取操作成功读取到对应的字符。
    * 循环结束后，`position()` 为 10。
    * `IsEOF()` 返回 `true`。

**常见的使用错误 (用户或编程):**

1. **在未调用 `Init` 方法前尝试读取或追加数据:**  虽然代码中似乎允许这样做（在某些测试用例中可以看到），但通常推荐先初始化流。未初始化的状态可能导致不可预测的行为。

2. **在流已标记为结束后继续追加数据:**  `AppendData` 方法的第二个参数 `is_eof` 用于标记流的结束。如果在设置为 `true` 后继续追加数据，可能会导致数据丢失或服务端处理错误。测试用例 `ChunkedUploadDataStreamWriter` 演示了在流被删除后尝试追加数据的情况，这属于编程错误。

3. **忘记处理异步读取的回调:** 当 `Read` 方法返回 `ERR_IO_PENDING` 时，表示数据尚未准备好，需要等待回调通知。如果忘记设置或处理回调，程序可能会一直等待。

**用户操作如何一步步到达这里 (调试线索):**

假设用户在浏览器中执行以下操作：

1. **用户在一个网页上点击了一个“上传文件”按钮。**
2. **用户选择了一个非常大的文件进行上传。**
3. **网页的 JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起了一个 POST 请求，并将文件对象作为请求体。**

**调试线索:**

当浏览器处理这个上传请求时，可能会遇到以下情况，从而触发对 `ChunkedUploadDataStream` 相关代码的调试：

1. **性能问题:** 如果上传速度很慢，开发者可能会想了解数据是如何分块、传输的。`ChunkedUploadDataStream` 负责管理数据的分块，是性能瓶颈的潜在位置。

2. **上传失败或中断:** 如果上传过程中出现错误，例如网络连接不稳定，开发者可能需要查看网络栈的日志，了解数据流的状态，以及是否正确处理了错误。

3. **服务端接收数据不完整或顺序错误:** 如果服务端接收到的数据有问题，可能是客户端分块上传的逻辑有误，需要检查 `ChunkedUploadDataStream` 的实现是否正确。

4. **内存占用过高:**  如果上传大文件导致浏览器内存占用过高，可能需要检查是否有效地使用了流式上传，`ChunkedUploadDataStream` 的实现会影响内存使用情况。

**总结:**

`net/base/chunked_upload_data_stream_unittest.cc` 是一个至关重要的测试文件，它确保了 `ChunkedUploadDataStream` 类的可靠性，而这个类是 Chromium 网络栈处理大文件上传等场景的关键组件。理解这个文件可以帮助开发者深入了解网络请求的底层实现，并有助于排查与文件上传相关的网络问题。

### 提示词
```
这是目录为net/base/chunked_upload_data_stream_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/base/chunked_upload_data_stream.h"

#include <memory>
#include <string>

#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/base/upload_data_stream.h"
#include "net/log/net_log_with_source.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {

namespace {

constexpr char kTestData[] = "0123456789";
constexpr size_t kTestDataSize = std::size(kTestData) - 1;
constexpr size_t kTestBufferSize = 1 << 14;  // 16KB.

}  // namespace

// Reads data once from the upload data stream, and returns the data as string.
// Expects the read to succeed synchronously.
std::string ReadSync(UploadDataStream* stream, int buffer_size) {
  auto buf = base::MakeRefCounted<IOBufferWithSize>(buffer_size);
  int result = stream->Read(buf.get(),
                            buffer_size,
                            TestCompletionCallback().callback());
  EXPECT_GE(result, 0);
  return std::string(buf->data(), result);
}

// Check the case data is added after the first read attempt.
TEST(ChunkedUploadDataStreamTest, AppendOnce) {
  ChunkedUploadDataStream stream(0);

  ASSERT_THAT(
      stream.Init(TestCompletionCallback().callback(), NetLogWithSource()),
      IsOk());
  EXPECT_FALSE(stream.IsInMemory());
  EXPECT_EQ(0u, stream.size());  // Content-Length is 0 for chunked data.
  EXPECT_EQ(0u, stream.position());
  EXPECT_FALSE(stream.IsEOF());

  TestCompletionCallback callback;
  auto buf = base::MakeRefCounted<IOBufferWithSize>(kTestBufferSize);
  int result = stream.Read(buf.get(), kTestBufferSize, callback.callback());
  ASSERT_THAT(result, IsError(ERR_IO_PENDING));

  stream.AppendData(base::byte_span_from_cstring(kTestData), true);
  int read = callback.WaitForResult();
  ASSERT_GE(read, 0);
  EXPECT_EQ(kTestData, std::string(buf->data(), read));
  EXPECT_EQ(0u, stream.size());  // Content-Length is 0 for chunked data.
  EXPECT_EQ(kTestDataSize, stream.position());
  EXPECT_TRUE(stream.IsEOF());
}

TEST(ChunkedUploadDataStreamTest, AppendOnceBeforeRead) {
  ChunkedUploadDataStream stream(0);

  ASSERT_THAT(
      stream.Init(TestCompletionCallback().callback(), NetLogWithSource()),
      IsOk());
  EXPECT_FALSE(stream.IsInMemory());
  EXPECT_EQ(0u, stream.size());  // Content-Length is 0 for chunked data.
  EXPECT_EQ(0u, stream.position());
  EXPECT_FALSE(stream.IsEOF());

  stream.AppendData(base::byte_span_from_cstring(kTestData), true);
  EXPECT_EQ(0u, stream.size());  // Content-Length is 0 for chunked data.
  EXPECT_EQ(0u, stream.position());
  EXPECT_FALSE(stream.IsEOF());

  std::string data = ReadSync(&stream, kTestBufferSize);
  EXPECT_EQ(kTestData, data);
  EXPECT_EQ(0u, stream.size());  // Content-Length is 0 for chunked data.
  EXPECT_EQ(kTestDataSize, stream.position());
  EXPECT_TRUE(stream.IsEOF());
}

TEST(ChunkedUploadDataStreamTest, AppendOnceBeforeInit) {
  ChunkedUploadDataStream stream(0);

  stream.AppendData(base::byte_span_from_cstring(kTestData), true);
  ASSERT_THAT(
      stream.Init(TestCompletionCallback().callback(), NetLogWithSource()),
      IsOk());
  EXPECT_FALSE(stream.IsInMemory());
  EXPECT_EQ(0u, stream.size());  // Content-Length is 0 for chunked data.
  EXPECT_EQ(0u, stream.position());
  EXPECT_FALSE(stream.IsEOF());

  std::string data = ReadSync(&stream, kTestBufferSize);
  EXPECT_EQ(kTestData, data);
  EXPECT_EQ(0u, stream.size());  // Content-Length is 0 for chunked data.
  EXPECT_EQ(kTestDataSize, stream.position());
  EXPECT_TRUE(stream.IsEOF());
}

TEST(ChunkedUploadDataStreamTest, MultipleAppends) {
  ChunkedUploadDataStream stream(0);

  ASSERT_THAT(
      stream.Init(TestCompletionCallback().callback(), NetLogWithSource()),
      IsOk());
  EXPECT_FALSE(stream.IsInMemory());
  EXPECT_EQ(0u, stream.size());
  EXPECT_EQ(0u, stream.position());
  EXPECT_FALSE(stream.IsEOF());

  TestCompletionCallback callback;
  auto buf = base::MakeRefCounted<IOBufferWithSize>(kTestBufferSize);
  for (size_t i = 0; i < kTestDataSize; ++i) {
    EXPECT_EQ(0u, stream.size());  // Content-Length is 0 for chunked data.
    EXPECT_EQ(i, stream.position());
    ASSERT_FALSE(stream.IsEOF());
    int bytes_read = stream.Read(buf.get(),
                                 kTestBufferSize,
                                 callback.callback());
    ASSERT_THAT(bytes_read, IsError(ERR_IO_PENDING));
    stream.AppendData(base::byte_span_from_cstring(kTestData).subspan(i, 1u),
                      i == kTestDataSize - 1);
    ASSERT_EQ(1, callback.WaitForResult());
    EXPECT_EQ(kTestData[i], buf->data()[0]);
  }

  EXPECT_EQ(0u, stream.size());  // Content-Length is 0 for chunked data.
  EXPECT_EQ(kTestDataSize, stream.position());
  ASSERT_TRUE(stream.IsEOF());
}

TEST(ChunkedUploadDataStreamTest, MultipleAppendsBetweenReads) {
  ChunkedUploadDataStream stream(0);

  ASSERT_THAT(
      stream.Init(TestCompletionCallback().callback(), NetLogWithSource()),
      IsOk());
  EXPECT_FALSE(stream.IsInMemory());
  EXPECT_EQ(0u, stream.size());  // Content-Length is 0 for chunked data.
  EXPECT_EQ(0u, stream.position());
  EXPECT_FALSE(stream.IsEOF());

  auto buf = base::MakeRefCounted<IOBufferWithSize>(kTestBufferSize);
  for (size_t i = 0; i < kTestDataSize; ++i) {
    EXPECT_EQ(i, stream.position());
    ASSERT_FALSE(stream.IsEOF());
    stream.AppendData(base::byte_span_from_cstring(kTestData).subspan(i, 1u),
                      i == kTestDataSize - 1);
    int bytes_read = stream.Read(buf.get(),
                                 kTestBufferSize,
                                 TestCompletionCallback().callback());
    ASSERT_EQ(1, bytes_read);
    EXPECT_EQ(kTestData[i], buf->data()[0]);
  }

  EXPECT_EQ(kTestDataSize, stream.position());
  ASSERT_TRUE(stream.IsEOF());
}

// Checks that multiple reads can be merged.
TEST(ChunkedUploadDataStreamTest, MultipleAppendsBeforeInit) {
  ChunkedUploadDataStream stream(0);
  stream.AppendData(base::byte_span_from_cstring(kTestData).first(1u), false);
  stream.AppendData(base::byte_span_from_cstring(kTestData).subspan(1u, 1u),
                    false);
  stream.AppendData(base::byte_span_from_cstring(kTestData).subspan(2u), true);

  ASSERT_THAT(
      stream.Init(TestCompletionCallback().callback(), NetLogWithSource()),
      IsOk());
  EXPECT_FALSE(stream.IsInMemory());
  EXPECT_EQ(0u, stream.size());  // Content-Length is 0 for chunked data.
  EXPECT_EQ(0u, stream.position());
  EXPECT_FALSE(stream.IsEOF());

  std::string data = ReadSync(&stream, kTestBufferSize);
  EXPECT_EQ(kTestData, data);
  EXPECT_EQ(kTestDataSize, stream.position());
  ASSERT_TRUE(stream.IsEOF());
}

TEST(ChunkedUploadDataStreamTest, MultipleReads) {
  // Use a read size different from the write size to test bounds checking.
  const size_t kReadSize = kTestDataSize + 3;

  ChunkedUploadDataStream stream(0);
  stream.AppendData(base::byte_span_from_cstring(kTestData), false);
  stream.AppendData(base::byte_span_from_cstring(kTestData), false);
  stream.AppendData(base::byte_span_from_cstring(kTestData), false);
  stream.AppendData(base::byte_span_from_cstring(kTestData), true);

  ASSERT_THAT(
      stream.Init(TestCompletionCallback().callback(), NetLogWithSource()),
      IsOk());
  EXPECT_FALSE(stream.IsInMemory());
  EXPECT_EQ(0u, stream.size());  // Content-Length is 0 for chunked data.
  EXPECT_EQ(0u, stream.position());
  EXPECT_FALSE(stream.IsEOF());

  std::string data = ReadSync(&stream, kReadSize);
  EXPECT_EQ("0123456789012", data);
  EXPECT_EQ(kReadSize, stream.position());
  EXPECT_FALSE(stream.IsEOF());

  data = ReadSync(&stream, kReadSize);
  EXPECT_EQ("3456789012345", data);
  EXPECT_EQ(2 * kReadSize, stream.position());
  EXPECT_FALSE(stream.IsEOF());

  data = ReadSync(&stream, kReadSize);
  EXPECT_EQ("6789012345678", data);
  EXPECT_EQ(3 * kReadSize, stream.position());
  EXPECT_FALSE(stream.IsEOF());

  data = ReadSync(&stream, kReadSize);
  EXPECT_EQ("9", data);
  EXPECT_EQ(4 * kTestDataSize, stream.position());
  EXPECT_TRUE(stream.IsEOF());
}

TEST(ChunkedUploadDataStreamTest, EmptyUpload) {
  ChunkedUploadDataStream stream(0);

  ASSERT_THAT(
      stream.Init(TestCompletionCallback().callback(), NetLogWithSource()),
      IsOk());
  EXPECT_FALSE(stream.IsInMemory());
  EXPECT_EQ(0u, stream.size());  // Content-Length is 0 for chunked data.
  EXPECT_EQ(0u, stream.position());
  EXPECT_FALSE(stream.IsEOF());

  TestCompletionCallback callback;
  auto buf = base::MakeRefCounted<IOBufferWithSize>(kTestBufferSize);
  int result = stream.Read(buf.get(), kTestBufferSize, callback.callback());
  ASSERT_THAT(result, IsError(ERR_IO_PENDING));

  stream.AppendData({}, true);
  int read = callback.WaitForResult();
  EXPECT_EQ(0, read);
  EXPECT_EQ(0u, stream.position());
  EXPECT_TRUE(stream.IsEOF());
}

TEST(ChunkedUploadDataStreamTest, EmptyUploadEndedBeforeInit) {
  ChunkedUploadDataStream stream(0);
  stream.AppendData({}, true);

  ASSERT_THAT(
      stream.Init(TestCompletionCallback().callback(), NetLogWithSource()),
      IsOk());
  EXPECT_FALSE(stream.IsInMemory());
  EXPECT_EQ(0u, stream.size());  // Content-Length is 0 for chunked data.
  EXPECT_EQ(0u, stream.position());
  EXPECT_FALSE(stream.IsEOF());

  std::string data = ReadSync(&stream, kTestBufferSize);
  ASSERT_EQ("", data);
  EXPECT_EQ(0u, stream.position());
  EXPECT_TRUE(stream.IsEOF());
}

TEST(ChunkedUploadDataStreamTest, RewindAfterComplete) {
  ChunkedUploadDataStream stream(0);
  stream.AppendData(base::byte_span_from_cstring(kTestData).first(1u), false);
  stream.AppendData(base::byte_span_from_cstring(kTestData).subspan(1u), true);

  ASSERT_THAT(
      stream.Init(TestCompletionCallback().callback(), NetLogWithSource()),
      IsOk());
  EXPECT_FALSE(stream.IsInMemory());
  EXPECT_EQ(0u, stream.size());  // Content-Length is 0 for chunked data.
  EXPECT_EQ(0u, stream.position());
  EXPECT_FALSE(stream.IsEOF());

  std::string data = ReadSync(&stream, kTestBufferSize);
  EXPECT_EQ(kTestData, data);
  EXPECT_EQ(kTestDataSize, stream.position());
  ASSERT_TRUE(stream.IsEOF());

  // Rewind stream and repeat.
  ASSERT_THAT(
      stream.Init(TestCompletionCallback().callback(), NetLogWithSource()),
      IsOk());
  EXPECT_FALSE(stream.IsInMemory());
  EXPECT_EQ(0u, stream.size());  // Content-Length is 0 for chunked data.
  EXPECT_EQ(0u, stream.position());
  EXPECT_FALSE(stream.IsEOF());

  data = ReadSync(&stream, kTestBufferSize);
  EXPECT_EQ(kTestData, data);
  EXPECT_EQ(kTestDataSize, stream.position());
  ASSERT_TRUE(stream.IsEOF());
}

TEST(ChunkedUploadDataStreamTest, RewindWhileReading) {
  ChunkedUploadDataStream stream(0);

  ASSERT_THAT(
      stream.Init(TestCompletionCallback().callback(), NetLogWithSource()),
      IsOk());
  EXPECT_FALSE(stream.IsInMemory());
  EXPECT_EQ(0u, stream.size());  // Content-Length is 0 for chunked data.
  EXPECT_EQ(0u, stream.position());
  EXPECT_FALSE(stream.IsEOF());

  TestCompletionCallback callback;
  auto buf = base::MakeRefCounted<IOBufferWithSize>(kTestBufferSize);
  int result = stream.Read(buf.get(), kTestBufferSize, callback.callback());
  ASSERT_THAT(result, IsError(ERR_IO_PENDING));

  ASSERT_THAT(
      stream.Init(TestCompletionCallback().callback(), NetLogWithSource()),
      IsOk());
  EXPECT_FALSE(stream.IsInMemory());
  EXPECT_EQ(0u, stream.size());  // Content-Length is 0 for chunked data.
  EXPECT_EQ(0u, stream.position());
  EXPECT_FALSE(stream.IsEOF());

  // Adding data now should not result in calling the original read callback,
  // since the stream was re-initialized for reuse, which cancels all pending
  // reads.
  stream.AppendData(base::byte_span_from_cstring(kTestData), true);
  EXPECT_FALSE(callback.have_result());

  std::string data = ReadSync(&stream, kTestBufferSize);
  EXPECT_EQ(kTestData, data);
  EXPECT_EQ(kTestDataSize, stream.position());
  ASSERT_TRUE(stream.IsEOF());
  EXPECT_FALSE(callback.have_result());
}

// Check the behavior of ChunkedUploadDataStream::Writer.
TEST(ChunkedUploadDataStreamTest, ChunkedUploadDataStreamWriter) {
  auto stream = std::make_unique<ChunkedUploadDataStream>(0);
  std::unique_ptr<ChunkedUploadDataStream::Writer> writer(
      stream->CreateWriter());

  // Write before Init.
  ASSERT_TRUE(writer->AppendData(
      base::byte_span_from_cstring(kTestData).first(1u), false));
  ASSERT_THAT(
      stream->Init(TestCompletionCallback().callback(), NetLogWithSource()),
      IsOk());

  // Write after Init.
  ASSERT_TRUE(writer->AppendData(
      base::byte_span_from_cstring(kTestData).subspan(1u), false));

  TestCompletionCallback callback;
  std::string data = ReadSync(stream.get(), kTestBufferSize);
  EXPECT_EQ(kTestData, data);

  // Writing data should gracefully fail if the stream is deleted while still
  // appending data to it.
  stream.reset();
  EXPECT_FALSE(
      writer->AppendData(base::byte_span_from_cstring(kTestData), true));
}

}  // namespace net
```