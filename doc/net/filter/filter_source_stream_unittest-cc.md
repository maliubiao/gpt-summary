Response:
Let's break down the thought process to analyze the provided C++ code and answer the prompt's questions.

**1. Initial Understanding: The Core Purpose**

The first step is to quickly scan the code and identify its main goal. Keywords like `unittest`, `FilterSourceStream`, `MockSourceStream`, `Read`, `FilterData`, and the presence of `TEST_P` macros strongly suggest this is a unit test file for a class named `FilterSourceStream`. The "net" namespace hints it's related to networking functionality within Chromium.

**2. Deconstructing the Code: Key Components and Their Roles**

Next, I'd examine the different parts of the code:

* **Includes:**  These give clues about dependencies and the types of operations involved. `base/functional/bind.h`, `net/base/io_buffer.h`, `testing/gtest/include/gtest/gtest.h` are standard for Chromium testing. `net/filter/filter_source_stream.h` and `net/filter/mock_source_stream.h` are the key subject and a test double, respectively.

* **Helper Classes:**  The `TestFilterSourceStreamBase` and its derived classes (`NeedsAllInputFilterSourceStream`, `MultiplySourceStream`, `PassThroughFilterSourceStream`, `ThrottleSourceStream`, `NoOutputSourceStream`, `ErrorFilterSourceStream`) are crucial. I'd note their purpose based on their names and the logic within their `FilterData` methods.

    * `TestFilterSourceStreamBase`:  Provides a basic framework and a buffer.
    * `NeedsAllInputFilterSourceStream`:  Only outputs data when all input is received.
    * `MultiplySourceStream`: Repeats input.
    * `PassThroughFilterSourceStream`: Passes input unchanged.
    * `ThrottleSourceStream`: Outputs one byte at a time.
    * `NoOutputSourceStream`: Consumes input but produces no output.
    * `ErrorFilterSourceStream`:  Always returns an error.

* **Test Fixture:** The `FilterSourceStreamTest` class sets up the testing environment and provides the `CompleteReadIfAsync` helper function. The `INSTANTIATE_TEST_SUITE_P` indicates parameterized testing for synchronous and asynchronous operations.

* **Test Cases (using `TEST_P`):**  Each `TEST_P` function focuses on testing a specific scenario or behavior of the `FilterSourceStream`. The names of the tests are descriptive (e.g., `FilterDataReturnNoBytesExceptLast`, `FilterDataReturnError`).

* **Mocking:** The use of `MockSourceStream` is significant. It allows for controlled simulation of the upstream data source with specific read results (data, EOF, errors).

**3. Analyzing Functionality and Relationships**

With the components identified, I would analyze how they interact:

* **The `FilterSourceStream` Concept:**  The core idea is a stream that processes data from an upstream source before passing it to a downstream consumer. The `FilterData` method is the key to this processing.

* **Upstream and Downstream:** The `MockSourceStream` acts as the upstream, providing simulated data. The `Read` method of the `FilterSourceStream` is used by the downstream consumer (the test code) to receive filtered data.

* **Filtering Logic:** The different derived classes demonstrate various filtering operations.

* **Asynchronous Operations:** The parameterized testing with `MockSourceStream::ASYNC` highlights the support for asynchronous reads, a common pattern in network programming.

**4. Addressing the Prompt's Questions (Iterative Refinement):**

Now, I'd systematically answer each part of the prompt:

* **功能 (Functionality):**  Based on the analysis above, I'd summarize the core functionality: unit testing for `FilterSourceStream`, demonstrating different filtering behaviors, and verifying handling of synchronous and asynchronous data flow.

* **与 JavaScript 的关系 (Relationship with JavaScript):** This requires some inference. Network stacks are used by web browsers, which execute JavaScript. Features like `fetch` API or `XMLHttpRequest` in JavaScript rely on the underlying network stack. I'd make the connection that a `FilterSourceStream` could be involved in processing responses received by JavaScript, potentially for things like decompression or data transformation. I'd emphasize that this specific file is C++ and doesn't directly *contain* JavaScript code, but it supports features used by JavaScript.

* **逻辑推理 (Logical Reasoning):** For each test case, I'd analyze the setup (the `MockSourceStream`'s read results) and the expected outcome. I'd pick a few representative examples, like `FilterDataReturnNoBytesExceptLast` (showing how the stream buffers data until EOF) or `FilterDataReturnError` (demonstrating error propagation). For each, I'd explicitly state the input (simulated upstream data) and the expected output (the data received by the test code).

* **用户或编程常见的使用错误 (Common User/Programming Errors):** I'd think about how developers might misuse or misunderstand the `FilterSourceStream`. Not handling errors correctly, providing insufficient output buffer space, or misconfiguring the filter chain are likely candidates. I'd illustrate with concrete C++ examples.

* **用户操作如何到达这里 (How User Operations Reach Here):** This requires tracing back the network request flow in a browser. I'd consider a simple scenario like a user visiting a website. I'd outline the steps from typing the URL, DNS lookup, establishing a connection, sending the request, receiving the response, and then highlight where a `FilterSourceStream` might be involved (e.g., processing the compressed response body). This helps establish the real-world context of the unit test.

**5. Review and Refinement:**

Finally, I'd review my answers for clarity, accuracy, and completeness. I'd ensure the examples are easy to understand and directly relate to the code being analyzed. I might rephrase sentences for better flow and ensure all parts of the prompt are adequately addressed. For instance, initially, I might have focused too much on the technical details of the C++ code and needed to explicitly connect it to user-facing scenarios and JavaScript interactions.

This iterative process of understanding, deconstructing, analyzing, and refining allows for a comprehensive and accurate response to the prompt.
这个 C++ 文件 `filter_source_stream_unittest.cc` 是 Chromium 网络栈中 `net/filter` 目录下 `FilterSourceStream` 类的单元测试代码。它的主要功能是**测试 `FilterSourceStream` 及其子类的各种行为和功能**。

**以下是该文件的功能分解：**

1. **定义了多个 `FilterSourceStream` 的测试子类：**
   - `TestFilterSourceStreamBase`:  作为一个基础测试类，提供了一些公共的辅助方法。
   - `NeedsAllInputFilterSourceStream`:  只有在接收到所有预期的输入数据后才输出数据。
   - `MultiplySourceStream`: 将每个输入的字节重复指定的次数。
   - `PassThroughFilterSourceStream`:  将输入数据不做任何修改地传递出去。
   - `ThrottleSourceStream`:  每次只输出一个字节的数据。
   - `NoOutputSourceStream`:  消耗所有输入数据但不产生任何输出。
   - `ErrorFilterSourceStream`:  在 `FilterData` 方法中返回错误代码。

2. **使用 `MockSourceStream` 模拟上游数据源：**
   - `MockSourceStream` 是一个用于测试的模拟类，允许预先设定上游数据源的读取结果（数据、EOF、错误等）。这使得可以精确地控制输入，以便测试 `FilterSourceStream` 的行为。

3. **编写了多个单元测试用例（使用 `TEST_P`）：**
   - 这些测试用例覆盖了 `FilterSourceStream` 及其子类的不同场景，例如：
     - 当 `FilterData` 返回 0 字节时（除了最后一次）：测试 `FilterSourceStream` 如何处理需要等待更多输入的过滤器。
     - 当上游返回 EOF 时 `FilterData` 返回 0 字节。
     - 当 `FilterData` 不输出任何数据时。
     - 当 `FilterData` 返回数据时。
     - 当 `FilterData` 返回比输入更多的数据时。
     - 当输出缓冲区空间不足时。
     - 当 `FilterData` 返回错误时。
     - 测试过滤器链（多个 `FilterSourceStream` 串联）。
     - 测试输出缓冲区空间限制导致多次调用 `FilterData` 的情况。
     - 测试 `ThrottleSourceStream` 每次只输出一个字节的情况。

4. **使用了 Google Test 框架 (`testing/gtest/include/gtest/gtest.h`)：**
   - 使用 `TEST_P` 定义参数化测试，允许使用不同的 `MockSourceStream::Mode`（同步或异步）运行相同的测试逻辑，以验证在不同模式下的行为。
   - 使用 `EXPECT_EQ`、`ASSERT_GT` 等断言来验证测试结果是否符合预期。

**与 JavaScript 的功能关系：**

`FilterSourceStream` 本身是用 C++ 实现的，与 JavaScript 没有直接的代码关系。但是，它作为 Chromium 网络栈的一部分，在处理网络请求和响应时扮演着重要的角色。当 JavaScript 代码（例如使用 `fetch` API 或 `XMLHttpRequest`）发起网络请求并接收到响应时，`FilterSourceStream` 的子类可能会被用来处理响应的数据流，例如：

* **解码压缩内容 (Content Decoding):**  如果服务器返回的是经过 gzip 或 brotli 压缩的内容，可能会有 `FilterSourceStream` 的子类负责解压缩数据，然后再将解压后的数据传递给 JavaScript。
* **数据转换 (Data Transformation):** 在某些情况下，可能需要对接收到的数据进行转换或过滤，然后才能提供给 JavaScript。例如，处理分块传输编码 (Chunked Transfer Encoding) 的数据。

**举例说明:**

假设一个 JavaScript 代码使用 `fetch` API 请求一个经过 gzip 压缩的 JSON 文件：

```javascript
fetch('https://example.com/data.json.gz')
  .then(response => response.json())
  .then(data => console.log(data));
```

在这个过程中，当浏览器接收到服务器返回的 gzip 压缩数据流时，Chromium 的网络栈可能会使用一个类似 `GzipSourceStream`（虽然这个例子中没有直接定义，但原理类似）的 `FilterSourceStream` 子类来解压缩数据。`GzipSourceStream` 会读取压缩的数据块，解压缩它们，并将解压后的数据传递给后续的处理步骤，最终 `response.json()` 才能正确地解析 JSON 数据并提供给 JavaScript。

**逻辑推理的假设输入与输出：**

**示例 1: 测试 `MultiplySourceStream`**

* **假设输入（上游 `MockSourceStream` 提供的数据）:** 字符串 "AB"
* **`MultiplySourceStream` 的 `multiplier_` 设置为:** 3
* **预期输出（`Read` 方法返回的数据）:** 字符串 "AAABBB"

**示例 2: 测试 `NeedsAllInputFilterSourceStream`**

* **假设输入（上游 `MockSourceStream` 分两次提供数据）:** 第一次 "He"，第二次 "llo"
* **`NeedsAllInputFilterSourceStream` 的 `expected_input_bytes_` 设置为:** 5
* **预期输出（在接收到 "Hello" 之后 `Read` 方法返回的数据）:** 字符串 "Hello"

**涉及用户或编程常见的使用错误：**

1. **输出缓冲区太小：**  用户（通常是调用网络栈的更高层代码）提供的输出缓冲区太小，无法容纳 `FilterSourceStream` 处理后的数据。例如，调用 `Read` 方法时提供的 `output_buffer_size` 小于过滤器实际要输出的数据量。这会导致 `Read` 方法多次返回读取了部分数据，调用者需要循环调用 `Read` 直到所有数据都被读取。如果调用者没有正确处理这种情况，可能会丢失数据或导致程序错误。

   ```c++
   // 错误示例：输出缓冲区太小
   scoped_refptr<IOBufferWithSize> output_buffer =
       base::MakeRefCounted<IOBufferWithSize>(1); // 极小的缓冲区
   int rv = stream.Read(output_buffer.get(), output_buffer->size(), callback.callback());
   // 如果 stream 返回的数据大于 1，则只读取了一部分
   ```

2. **没有处理 `ERR_IO_PENDING`：**  在异步模式下，`Read` 方法可能会返回 `ERR_IO_PENDING`，表示操作正在进行中，需要等待回调完成。如果调用者没有正确处理这个返回值，就无法获取到最终的数据。

   ```c++
   // 错误示例：没有处理异步情况
   int rv = stream.Read(output_buffer.get(), output_buffer->size(), callback.callback());
   // 如果 rv == ERR_IO_PENDING，应该等待回调，而不是直接使用 output_buffer 的内容
   ```

3. **错误地假设数据一次性返回：**  `FilterSourceStream` 可能会分多次返回数据，即使上游一次性提供了所有数据。例如，`ThrottleSourceStream` 每次只返回一个字节。调用者不能假设一次 `Read` 调用就能获取到所有期望的数据。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在 Chrome 浏览器中访问一个使用了 gzip 压缩的网页 `https://example.com/compressed_page.html`。以下是可能到达 `FilterSourceStream` 的步骤：

1. **用户在地址栏输入 URL 并按下回车。**
2. **浏览器解析 URL 并进行 DNS 查询，获取服务器 IP 地址。**
3. **浏览器与服务器建立 TCP 连接 (可能包括 TLS 握手)。**
4. **浏览器向服务器发送 HTTP 请求，请求 `compressed_page.html`。请求头中可能包含 `Accept-Encoding: gzip`，告知服务器浏览器支持 gzip 压缩。**
5. **服务器返回 HTTP 响应，响应头中包含 `Content-Encoding: gzip`，表示响应体是 gzip 压缩的。**
6. **Chromium 网络栈接收到响应头，识别出内容是 gzip 压缩的。**
7. **网络栈创建一个 `GzipSourceStream` (或类似的子类) 来处理响应体的数据流。这个 `GzipSourceStream` 会将上游（负责接收网络数据的模块）提供的压缩数据解压缩。**
8. **当上层的网络模块或渲染引擎需要访问网页内容时，它会调用 `GzipSourceStream` 的 `Read` 方法来读取解压缩后的数据。**
9. **`GzipSourceStream` 内部会调用其上游的 `Read` 方法获取压缩数据，然后进行解压缩，并将解压后的数据写入到 `Read` 方法提供的输出缓冲区中。**

**作为调试线索：**

如果在加载这个网页时出现问题，例如页面显示乱码或加载失败，开发者可以使用调试工具（如 Chrome 的开发者工具）来检查网络请求的详细信息。

* **查看请求头和响应头：**  确认请求头中是否包含了正确的 `Accept-Encoding`，响应头中是否包含了 `Content-Encoding: gzip`。
* **查看响应体：**  查看原始的压缩响应体数据，以及经过 `GzipSourceStream` 处理后的解压缩数据，可以帮助判断是压缩过程还是解压缩过程出现了问题。
* **断点调试：**  如果怀疑 `FilterSourceStream` 的实现有问题，开发者可以在 `filter_source_stream_unittest.cc` 中找到相关的测试用例，或者在 `FilterSourceStream` 及其子类的代码中设置断点，逐步跟踪数据的处理过程，查看中间状态和变量的值，以定位问题所在。

总而言之，`filter_source_stream_unittest.cc` 这个文件是确保 `FilterSourceStream` 及其各种实现能够正确可靠地处理网络数据流的关键组成部分，它通过模拟不同的场景和数据输入，来验证代码的正确性。 理解这些测试用例有助于理解 `FilterSourceStream` 的工作原理，并在遇到相关问题时提供调试思路。

### 提示词
```
这是目录为net/filter/filter_source_stream_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include <algorithm>
#include <string>

#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/numerics/safe_conversions.h"
#include "base/types/expected.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/filter/filter_source_stream.h"
#include "net/filter/mock_source_stream.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

const size_t kDefaultBufferSize = 4096;
const size_t kSmallBufferSize = 1;

class TestFilterSourceStreamBase : public FilterSourceStream {
 public:
  explicit TestFilterSourceStreamBase(std::unique_ptr<SourceStream> upstream)
      : FilterSourceStream(SourceStream::TYPE_NONE, std::move(upstream)) {}

  TestFilterSourceStreamBase(const TestFilterSourceStreamBase&) = delete;
  TestFilterSourceStreamBase& operator=(const TestFilterSourceStreamBase&) =
      delete;

  ~TestFilterSourceStreamBase() override { DCHECK(buffer_.empty()); }
  std::string GetTypeAsString() const override { return type_string_; }

  void set_type_string(const std::string& type_string) {
    type_string_ = type_string;
  }

 protected:
  // Writes contents of |buffer_| to |output_buffer| and returns the number of
  // bytes written or an error code. Additionally removes consumed data from
  // |buffer_|.
  size_t WriteBufferToOutput(IOBuffer* output_buffer,
                             size_t output_buffer_size) {
    size_t bytes_to_filter = std::min(buffer_.length(), output_buffer_size);
    memcpy(output_buffer->data(), buffer_.data(), bytes_to_filter);
    buffer_.erase(0, bytes_to_filter);
    return bytes_to_filter;
  }

  // Buffer used by subclasses to hold data that is yet to be passed to the
  // caller.
  std::string buffer_;

 private:
  std::string type_string_;
};

// A FilterSourceStream that needs all input data before it can return non-zero
// bytes read.
class NeedsAllInputFilterSourceStream : public TestFilterSourceStreamBase {
 public:
  NeedsAllInputFilterSourceStream(std::unique_ptr<SourceStream> upstream,
                                  size_t expected_input_bytes)
      : TestFilterSourceStreamBase(std::move(upstream)),
        expected_input_bytes_(expected_input_bytes) {}

  NeedsAllInputFilterSourceStream(const NeedsAllInputFilterSourceStream&) =
      delete;
  NeedsAllInputFilterSourceStream& operator=(
      const NeedsAllInputFilterSourceStream&) = delete;

  base::expected<size_t, Error> FilterData(IOBuffer* output_buffer,
                                           size_t output_buffer_size,
                                           IOBuffer* input_buffer,
                                           size_t input_buffer_size,
                                           size_t* consumed_bytes,
                                           bool upstream_eof_reached) override {
    buffer_.append(input_buffer->data(), input_buffer_size);
    EXPECT_GE(expected_input_bytes_, input_buffer_size);
    expected_input_bytes_ -= input_buffer_size;
    *consumed_bytes = input_buffer_size;
    if (!upstream_eof_reached) {
      // Keep returning 0 bytes read until all input has been consumed.
      return 0;
    }
    EXPECT_EQ(0u, expected_input_bytes_);
    return WriteBufferToOutput(output_buffer, output_buffer_size);
  }

 private:
  // Expected remaining bytes to be received from |upstream|.
  size_t expected_input_bytes_;
};

// A FilterSourceStream that repeat every input byte by |multiplier| amount of
// times.
class MultiplySourceStream : public TestFilterSourceStreamBase {
 public:
  MultiplySourceStream(std::unique_ptr<SourceStream> upstream, int multiplier)
      : TestFilterSourceStreamBase(std::move(upstream)),
        multiplier_(multiplier) {}

  MultiplySourceStream(const MultiplySourceStream&) = delete;
  MultiplySourceStream& operator=(const MultiplySourceStream&) = delete;

  base::expected<size_t, Error> FilterData(
      IOBuffer* output_buffer,
      size_t output_buffer_size,
      IOBuffer* input_buffer,
      size_t input_buffer_size,
      size_t* consumed_bytes,
      bool /*upstream_eof_reached*/) override {
    for (size_t i = 0; i < input_buffer_size; i++) {
      for (int j = 0; j < multiplier_; j++)
        buffer_.append(input_buffer->data() + i, 1);
    }
    *consumed_bytes = input_buffer_size;
    return WriteBufferToOutput(output_buffer, output_buffer_size);
  }

 private:
  int multiplier_;
};

// A FilterSourceStream passes through data unchanged to consumer.
class PassThroughFilterSourceStream : public TestFilterSourceStreamBase {
 public:
  explicit PassThroughFilterSourceStream(std::unique_ptr<SourceStream> upstream)
      : TestFilterSourceStreamBase(std::move(upstream)) {}

  PassThroughFilterSourceStream(const PassThroughFilterSourceStream&) = delete;
  PassThroughFilterSourceStream& operator=(
      const PassThroughFilterSourceStream&) = delete;

  base::expected<size_t, Error> FilterData(
      IOBuffer* output_buffer,
      size_t output_buffer_size,
      IOBuffer* input_buffer,
      size_t input_buffer_size,
      size_t* consumed_bytes,
      bool /*upstream_eof_reached*/) override {
    buffer_.append(input_buffer->data(), input_buffer_size);
    *consumed_bytes = input_buffer_size;
    return WriteBufferToOutput(output_buffer, output_buffer_size);
  }
};

// A FilterSourceStream passes throttle input data such that it returns them to
// caller only one bytes at a time.
class ThrottleSourceStream : public TestFilterSourceStreamBase {
 public:
  explicit ThrottleSourceStream(std::unique_ptr<SourceStream> upstream)
      : TestFilterSourceStreamBase(std::move(upstream)) {}

  ThrottleSourceStream(const ThrottleSourceStream&) = delete;
  ThrottleSourceStream& operator=(const ThrottleSourceStream&) = delete;

  base::expected<size_t, Error> FilterData(
      IOBuffer* output_buffer,
      size_t output_buffer_size,
      IOBuffer* input_buffer,
      size_t input_buffer_size,
      size_t* consumed_bytes,
      bool /*upstream_eof_reached*/) override {
    buffer_.append(input_buffer->data(), input_buffer_size);
    *consumed_bytes = input_buffer_size;
    size_t bytes_to_read = std::min(size_t{1}, buffer_.size());
    memcpy(output_buffer->data(), buffer_.data(), bytes_to_read);
    buffer_.erase(0, bytes_to_read);
    return bytes_to_read;
  }
};

// A FilterSourceStream that consumes all input data but return no output.
class NoOutputSourceStream : public TestFilterSourceStreamBase {
 public:
  NoOutputSourceStream(std::unique_ptr<SourceStream> upstream,
                       size_t expected_input_size)
      : TestFilterSourceStreamBase(std::move(upstream)),
        expected_input_size_(expected_input_size) {}

  NoOutputSourceStream(const NoOutputSourceStream&) = delete;
  NoOutputSourceStream& operator=(const NoOutputSourceStream&) = delete;

  base::expected<size_t, Error> FilterData(
      IOBuffer* output_buffer,
      size_t output_buffer_size,
      IOBuffer* input_buffer,
      size_t input_buffer_size,
      size_t* consumed_bytes,
      bool /*upstream_eof_reached*/) override {
    EXPECT_GE(expected_input_size_, input_buffer_size);
    expected_input_size_ -= input_buffer_size;
    *consumed_bytes = input_buffer_size;
    consumed_all_input_ = (expected_input_size_ == 0);
    return 0;
  }

  bool consumed_all_input() const { return consumed_all_input_; }

 private:
  // Expected remaining bytes to be received from |upstream|.
  size_t expected_input_size_;
  bool consumed_all_input_ = false;
};

// A FilterSourceStream return an error code in FilterData().
class ErrorFilterSourceStream : public FilterSourceStream {
 public:
  explicit ErrorFilterSourceStream(std::unique_ptr<SourceStream> upstream)
      : FilterSourceStream(SourceStream::TYPE_NONE, std::move(upstream)) {}

  ErrorFilterSourceStream(const ErrorFilterSourceStream&) = delete;
  ErrorFilterSourceStream& operator=(const ErrorFilterSourceStream&) = delete;

  base::expected<size_t, Error> FilterData(
      IOBuffer* output_buffer,
      size_t output_buffer_size,
      IOBuffer* input_buffer,
      size_t input_buffer_size,
      size_t* consumed_bytes,
      bool /*upstream_eof_reached*/) override {
    return base::unexpected(ERR_CONTENT_DECODING_FAILED);
  }
  std::string GetTypeAsString() const override { return ""; }
};

}  // namespace

class FilterSourceStreamTest
    : public ::testing::TestWithParam<MockSourceStream::Mode> {
 protected:
  // If MockSourceStream::Mode is ASYNC, completes |num_reads| from
  // |mock_stream| and wait for |callback| to complete. If Mode is not ASYNC,
  // does nothing and returns |previous_result|.
  int CompleteReadIfAsync(int previous_result,
                          TestCompletionCallback* callback,
                          MockSourceStream* mock_stream,
                          size_t num_reads) {
    if (GetParam() == MockSourceStream::ASYNC) {
      EXPECT_EQ(ERR_IO_PENDING, previous_result);
      while (num_reads > 0) {
        mock_stream->CompleteNextRead();
        num_reads--;
      }
      return callback->WaitForResult();
    }
    return previous_result;
  }
};

INSTANTIATE_TEST_SUITE_P(FilterSourceStreamTests,
                         FilterSourceStreamTest,
                         ::testing::Values(MockSourceStream::SYNC,
                                           MockSourceStream::ASYNC));

// Tests that a FilterSourceStream subclass (NeedsAllInputFilterSourceStream)
// can return 0 bytes for FilterData()s when it has not consumed EOF from the
// upstream. In this case, FilterSourceStream should continue reading from
// upstream to complete filtering.
TEST_P(FilterSourceStreamTest, FilterDataReturnNoBytesExceptLast) {
  auto source = std::make_unique<MockSourceStream>();
  std::string input("hello, world!");
  size_t read_size = 2;
  size_t num_reads = 0;
  // Add a sequence of small reads.
  for (size_t offset = 0; offset < input.length(); offset += read_size) {
    source->AddReadResult(input.data() + offset,
                          std::min(read_size, input.length() - offset), OK,
                          GetParam());
    num_reads++;
  }
  source->AddReadResult(input.data(), 0, OK, GetParam());  // EOF
  num_reads++;

  MockSourceStream* mock_stream = source.get();
  NeedsAllInputFilterSourceStream stream(std::move(source), input.length());
  scoped_refptr<IOBufferWithSize> output_buffer =
      base::MakeRefCounted<IOBufferWithSize>(kDefaultBufferSize);
  TestCompletionCallback callback;
  std::string actual_output;
  while (true) {
    int rv = stream.Read(output_buffer.get(), output_buffer->size(),
                         callback.callback());
    if (rv == ERR_IO_PENDING)
      rv = CompleteReadIfAsync(rv, &callback, mock_stream, num_reads);
    if (rv == OK)
      break;
    ASSERT_GT(rv, OK);
    actual_output.append(output_buffer->data(), rv);
  }
  EXPECT_EQ(input, actual_output);
}

// Tests that FilterData() returns 0 byte read because the upstream gives an
// EOF.
TEST_P(FilterSourceStreamTest, FilterDataReturnNoByte) {
  auto source = std::make_unique<MockSourceStream>();
  std::string input;
  source->AddReadResult(input.data(), 0, OK, GetParam());
  MockSourceStream* mock_stream = source.get();
  PassThroughFilterSourceStream stream(std::move(source));
  scoped_refptr<IOBufferWithSize> output_buffer =
      base::MakeRefCounted<IOBufferWithSize>(kDefaultBufferSize);
  TestCompletionCallback callback;
  int rv = stream.Read(output_buffer.get(), output_buffer->size(),
                       callback.callback());
  rv = CompleteReadIfAsync(rv, &callback, mock_stream, 1);
  EXPECT_EQ(OK, rv);
}

// Tests that FilterData() returns 0 byte filtered even though the upstream
// produces data.
TEST_P(FilterSourceStreamTest, FilterDataOutputNoData) {
  auto source = std::make_unique<MockSourceStream>();
  std::string input = "hello, world!";
  size_t read_size = 2;
  size_t num_reads = 0;
  // Add a sequence of small reads.
  for (size_t offset = 0; offset < input.length(); offset += read_size) {
    source->AddReadResult(input.data() + offset,
                          std::min(read_size, input.length() - offset), OK,
                          GetParam());
    num_reads++;
  }
  // Add a 0 byte read to signal EOF.
  source->AddReadResult(input.data() + input.length(), 0, OK, GetParam());
  num_reads++;
  MockSourceStream* mock_stream = source.get();
  NoOutputSourceStream stream(std::move(source), input.length());
  scoped_refptr<IOBufferWithSize> output_buffer =
      base::MakeRefCounted<IOBufferWithSize>(kDefaultBufferSize);
  TestCompletionCallback callback;
  int rv = stream.Read(output_buffer.get(), output_buffer->size(),
                       callback.callback());
  rv = CompleteReadIfAsync(rv, &callback, mock_stream, num_reads);
  EXPECT_EQ(OK, rv);
  EXPECT_TRUE(stream.consumed_all_input());
}

// Tests that FilterData() returns non-zero bytes because the upstream
// returns data.
TEST_P(FilterSourceStreamTest, FilterDataReturnData) {
  auto source = std::make_unique<MockSourceStream>();
  std::string input = "hello, world!";
  size_t read_size = 2;
  // Add a sequence of small reads.
  for (size_t offset = 0; offset < input.length(); offset += read_size) {
    source->AddReadResult(input.data() + offset,
                          std::min(read_size, input.length() - offset), OK,
                          GetParam());
  }
  // Add a 0 byte read to signal EOF.
  source->AddReadResult(input.data() + input.length(), 0, OK, GetParam());
  MockSourceStream* mock_stream = source.get();
  PassThroughFilterSourceStream stream(std::move(source));
  scoped_refptr<IOBufferWithSize> output_buffer =
      base::MakeRefCounted<IOBufferWithSize>(kDefaultBufferSize);
  TestCompletionCallback callback;
  std::string actual_output;
  while (true) {
    int rv = stream.Read(output_buffer.get(), output_buffer->size(),
                         callback.callback());
    rv = CompleteReadIfAsync(rv, &callback, mock_stream, /*num_reads=*/1);
    if (rv == OK)
      break;
    ASSERT_GE(static_cast<int>(read_size), rv);
    ASSERT_GT(rv, OK);
    actual_output.append(output_buffer->data(), rv);
  }
  EXPECT_EQ(input, actual_output);
}

// Tests that FilterData() returns more data than what it consumed.
TEST_P(FilterSourceStreamTest, FilterDataReturnMoreData) {
  auto source = std::make_unique<MockSourceStream>();
  std::string input = "hello, world!";
  size_t read_size = 2;
  // Add a sequence of small reads.
  for (size_t offset = 0; offset < input.length(); offset += read_size) {
    source->AddReadResult(input.data() + offset,
                          std::min(read_size, input.length() - offset), OK,
                          GetParam());
  }
  // Add a 0 byte read to signal EOF.
  source->AddReadResult(input.data() + input.length(), 0, OK, GetParam());
  MockSourceStream* mock_stream = source.get();
  int multiplier = 2;
  MultiplySourceStream stream(std::move(source), multiplier);
  scoped_refptr<IOBufferWithSize> output_buffer =
      base::MakeRefCounted<IOBufferWithSize>(kDefaultBufferSize);
  TestCompletionCallback callback;
  std::string actual_output;
  while (true) {
    int rv = stream.Read(output_buffer.get(), output_buffer->size(),
                         callback.callback());
    rv = CompleteReadIfAsync(rv, &callback, mock_stream, /*num_reads=*/1);
    if (rv == OK)
      break;
    ASSERT_GE(static_cast<int>(read_size) * multiplier, rv);
    ASSERT_GT(rv, OK);
    actual_output.append(output_buffer->data(), rv);
  }
  EXPECT_EQ("hheelllloo,,  wwoorrlldd!!", actual_output);
}

// Tests that FilterData() returns non-zero bytes and output buffer size is
// smaller than the number of bytes read from the upstream.
TEST_P(FilterSourceStreamTest, FilterDataOutputSpace) {
  auto source = std::make_unique<MockSourceStream>();
  std::string input = "hello, world!";
  size_t read_size = 2;
  // Add a sequence of small reads.
  for (size_t offset = 0; offset < input.length(); offset += read_size) {
    source->AddReadResult(input.data() + offset,
                          std::min(read_size, input.length() - offset), OK,
                          GetParam());
  }
  // Add a 0 byte read to signal EOF.
  source->AddReadResult(input.data() + input.length(), 0, OK, GetParam());
  // Use an extremely small buffer size, so FilterData will need more output
  // space.
  scoped_refptr<IOBufferWithSize> output_buffer =
      base::MakeRefCounted<IOBufferWithSize>(kSmallBufferSize);
  MockSourceStream* mock_stream = source.get();
  PassThroughFilterSourceStream stream(std::move(source));
  TestCompletionCallback callback;
  std::string actual_output;
  while (true) {
    int rv = stream.Read(output_buffer.get(), output_buffer->size(),
                         callback.callback());
    if (rv == ERR_IO_PENDING)
      rv = CompleteReadIfAsync(rv, &callback, mock_stream, /*num_reads=*/1);
    if (rv == OK)
      break;
    ASSERT_GT(rv, OK);
    ASSERT_GE(kSmallBufferSize, static_cast<size_t>(rv));
    actual_output.append(output_buffer->data(), rv);
  }
  EXPECT_EQ(input, actual_output);
}

// Tests that FilterData() returns an error code, which is then surfaced as
// the result of calling Read().
TEST_P(FilterSourceStreamTest, FilterDataReturnError) {
  auto source = std::make_unique<MockSourceStream>();
  std::string input;
  source->AddReadResult(input.data(), 0, OK, GetParam());
  scoped_refptr<IOBufferWithSize> output_buffer =
      base::MakeRefCounted<IOBufferWithSize>(kDefaultBufferSize);
  MockSourceStream* mock_stream = source.get();
  ErrorFilterSourceStream stream(std::move(source));
  TestCompletionCallback callback;
  int rv = stream.Read(output_buffer.get(), output_buffer->size(),
                       callback.callback());
  rv = CompleteReadIfAsync(rv, &callback, mock_stream, /*num_reads=*/1);
  EXPECT_EQ(ERR_CONTENT_DECODING_FAILED, rv);
  // Reading from |stream| again should return the same error.
  rv = stream.Read(output_buffer.get(), output_buffer->size(),
                   callback.callback());
  EXPECT_EQ(ERR_CONTENT_DECODING_FAILED, rv);
}

TEST_P(FilterSourceStreamTest, FilterChaining) {
  auto source = std::make_unique<MockSourceStream>();
  std::string input = "hello, world!";
  source->AddReadResult(input.data(), input.length(), OK, GetParam());
  source->AddReadResult(input.data(), 0, OK, GetParam());  // EOF

  MockSourceStream* mock_stream = source.get();
  auto pass_through_source =
      std::make_unique<PassThroughFilterSourceStream>(std::move(source));
  pass_through_source->set_type_string("FIRST_PASS_THROUGH");
  auto needs_all_input_source =
      std::make_unique<NeedsAllInputFilterSourceStream>(
          std::move(pass_through_source), input.length());
  needs_all_input_source->set_type_string("NEEDS_ALL");
  auto second_pass_through_source =
      std::make_unique<PassThroughFilterSourceStream>(
          std::move(needs_all_input_source));
  second_pass_through_source->set_type_string("SECOND_PASS_THROUGH");
  scoped_refptr<IOBufferWithSize> output_buffer =
      base::MakeRefCounted<IOBufferWithSize>(kDefaultBufferSize);

  TestCompletionCallback callback;
  std::string actual_output;
  while (true) {
    int rv = second_pass_through_source->Read(
        output_buffer.get(), output_buffer->size(), callback.callback());
    if (rv == ERR_IO_PENDING)
      rv = CompleteReadIfAsync(rv, &callback, mock_stream, /*num_reads=*/2);
    if (rv == OK)
      break;
    ASSERT_GT(rv, OK);
    actual_output.append(output_buffer->data(), rv);
  }
  EXPECT_EQ(input, actual_output);
  // Type string (from left to right) should be the order of data flow.
  EXPECT_EQ("FIRST_PASS_THROUGH,NEEDS_ALL,SECOND_PASS_THROUGH",
            second_pass_through_source->Description());
}

// Tests that FilterData() returns multiple times for a single MockStream
// read, because there is not enough output space.
TEST_P(FilterSourceStreamTest, OutputSpaceForOneRead) {
  auto source = std::make_unique<MockSourceStream>();
  std::string input = "hello, world!";
  source->AddReadResult(input.data(), input.length(), OK, GetParam());
  // Add a 0 byte read to signal EOF.
  source->AddReadResult(input.data() + input.length(), 0, OK, GetParam());
  // Use an extremely small buffer size (1 byte), so FilterData will need more
  // output space.
  scoped_refptr<IOBufferWithSize> output_buffer =
      base::MakeRefCounted<IOBufferWithSize>(kSmallBufferSize);
  MockSourceStream* mock_stream = source.get();
  PassThroughFilterSourceStream stream(std::move(source));
  TestCompletionCallback callback;
  std::string actual_output;
  while (true) {
    int rv = stream.Read(output_buffer.get(), output_buffer->size(),
                         callback.callback());
    if (rv == ERR_IO_PENDING)
      rv = CompleteReadIfAsync(rv, &callback, mock_stream, /*num_reads=*/1);
    if (rv == OK)
      break;
    ASSERT_GT(rv, OK);
    ASSERT_GE(kSmallBufferSize, static_cast<size_t>(rv));
    actual_output.append(output_buffer->data(), rv);
  }
  EXPECT_EQ(input, actual_output);
}

// Tests that FilterData() returns multiple times for a single MockStream
// read, because the filter returns one byte at a time.
TEST_P(FilterSourceStreamTest, ThrottleSourceStream) {
  auto source = std::make_unique<MockSourceStream>();
  std::string input = "hello, world!";
  source->AddReadResult(input.data(), input.length(), OK, GetParam());
  // Add a 0 byte read to signal EOF.
  source->AddReadResult(input.data() + input.length(), 0, OK, GetParam());
  scoped_refptr<IOBufferWithSize> output_buffer =
      base::MakeRefCounted<IOBufferWithSize>(kDefaultBufferSize);
  MockSourceStream* mock_stream = source.get();
  ThrottleSourceStream stream(std::move(source));
  TestCompletionCallback callback;
  std::string actual_output;
  while (true) {
    int rv = stream.Read(output_buffer.get(), output_buffer->size(),
                         callback.callback());
    if (rv == ERR_IO_PENDING)
      rv = CompleteReadIfAsync(rv, &callback, mock_stream, /*num_reads=*/1);
    if (rv == OK)
      break;
    ASSERT_GT(rv, OK);
    // ThrottleSourceStream returns 1 byte at a time.
    ASSERT_GE(1u, static_cast<size_t>(rv));
    actual_output.append(output_buffer->data(), rv);
  }
  EXPECT_EQ(input, actual_output);
}

}  // namespace net
```