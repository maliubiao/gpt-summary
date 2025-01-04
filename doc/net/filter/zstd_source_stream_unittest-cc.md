Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Understand the Goal:** The core request is to understand the purpose of `zstd_source_stream_unittest.cc` and its relationship to other concepts like JavaScript, debugging, and error handling. It's a unit test, so the primary function is to verify the behavior of some code, specifically `ZstdSourceStream`.

2. **Identify the Core Class Under Test:** The filename itself, `zstd_source_stream_unittest.cc`, strongly suggests that the class being tested is `ZstdSourceStream`. The `#include "net/filter/zstd_source_stream.h"` confirms this.

3. **Determine the Purpose of the Tested Class:** The name "ZstdSourceStream" hints at a stream that handles Zstandard (zstd) compression/decompression. The `net/filter` directory suggests it's part of the networking stack, likely involved in handling compressed data during network transfers.

4. **Analyze the Test Structure:** Unit tests in C++ often follow a structure involving:
    * **Setup (`SetUp()`):** Initializing test fixtures and data.
    * **Test Cases (`TEST_F()`):** Individual tests focusing on specific functionalities.
    * **Assertions (`EXPECT_EQ`, `ASSERT_TRUE`, `memcmp`):** Verifying the expected behavior.
    * **Helper Functions (`ReadStream`, `ReadStreamUntilDone`):** Simplifying common test operations.
    * **Mocking (`MockSourceStream`):** Simulating dependencies to isolate the unit under test.

5. **Examine `SetUp()`:**
    * It loads data from files (`google.txt`, `google.zst`, `google.szst`, `test.dict`). This indicates the tests will involve comparing decompressed data against original data and potentially using dictionaries.
    * It creates a `MockSourceStream` and a `ZstdSourceStream`. This tells us `ZstdSourceStream` likely takes another `SourceStream` as input (likely the source of the compressed data).

6. **Analyze Helper Functions:**
    * `ReadStream`: This is the primary way to interact with the `ZstdSourceStream` in the tests. It takes a callback, which is standard for asynchronous operations in Chromium's networking stack.
    * `ReadStreamUntilDone`:  A convenience function for reading the entire stream until it's exhausted.

7. **Deconstruct Individual Test Cases (`TEST_F()`):**  Go through each test case and understand what it's verifying:
    * `EmptyStream`: Handles the case where the input stream is empty.
    * `DecodeZstdOneBlockSync`: Basic synchronous decompression of a single zstd block.
    * `IgnoreExtraDataInOneRead`/`IgnoreExtraDataInDifferentRead`: Tests handling of extraneous data after the compressed data.
    * `DecodeZstdTwoBlockSync`:  Handles decompression when the compressed data is split into multiple reads.
    * `DecodeZstdOneBlockAsync`: Tests asynchronous decompression.
    * `DecodeTwoConcatenatedFrames`: Verifies handling of multiple compressed frames in a single stream.
    * `WithDictionary`: Tests decompression using a zstd dictionary.
    * `WindowSizeTooBig`: Checks error handling when the compressed data specifies a window size larger than supported.

8. **Identify Connections to JavaScript (if any):**  Carefully consider where zstd decompression might be relevant in a browser context and how it relates to JavaScript.
    * **Network Requests:** Compressed content (like Brotli, gzip, zstd) can be served by web servers. The browser (written in C++) needs to decompress this before the JavaScript can use it.
    * **`Content-Encoding` Header:** This HTTP header indicates the compression used.
    * **`fetch()` API:**  JavaScript's `fetch()` API is the primary way to make network requests. The browser handles the decompression transparently.

9. **Consider Logic and Input/Output:** For each test case, think about the input to the `MockSourceStream` and the expected output from the `ZstdSourceStream`. This involves understanding the test data (`google.txt`, `google.zst`, etc.).

10. **Think About User/Programming Errors:** What mistakes could developers or users make related to zstd decompression?
    * Providing incorrect compressed data.
    * Not handling errors during decompression.
    * Expecting decompression when the server doesn't send compressed data.
    * Problems with dictionary usage.

11. **Trace User Operations to the Code:** How would a user action lead to this code being executed?  Focus on the networking aspects.
    * User types a URL.
    * Browser makes a request.
    * Server responds with compressed content (indicated by `Content-Encoding: zstd`).
    * The networking stack in Chromium (including `ZstdSourceStream`) is used to decompress the response.

12. **Structure the Answer:** Organize the findings logically, addressing each part of the prompt:
    * Functionality of the file.
    * Relationship to JavaScript (with examples).
    * Logic and input/output (for specific tests).
    * Common errors.
    * User operation tracing.

13. **Refine and Elaborate:** Ensure the explanation is clear, concise, and provides sufficient detail. Use the information gathered from analyzing the code to support each point. For instance, mentioning `MockSourceStream` is crucial for explaining how the tests work. Highlighting the role of `Content-Encoding` connects the C++ code to web standards and JavaScript's `fetch` API.

By following these steps, you can systematically analyze the C++ unittest file and generate a comprehensive and accurate response to the prompt. The key is to understand the context (unit testing, networking stack), the specific class being tested, and how it interacts with other components and higher-level concepts like JavaScript.这个文件 `net/filter/zstd_source_stream_unittest.cc` 是 Chromium 网络栈的一部分，它是一个**单元测试文件**，专门用于测试 `ZstdSourceStream` 类的功能。 `ZstdSourceStream`  很可能是一个用于**解压缩 zstd 格式数据**的流处理类。

让我们详细列举一下它的功能：

**1. 测试 ZstdSourceStream 的核心解压缩功能:**

*   **基本解压缩:** 测试 `ZstdSourceStream` 能否正确地将 zstd 压缩的数据解压缩回原始数据。
*   **同步和异步读取:** 测试在同步和异步读取场景下，`ZstdSourceStream` 的解压缩功能是否正常工作。
*   **处理单个和多个数据块:** 测试当压缩数据以单个或多个数据块到达时，`ZstdSourceStream` 是否能正确处理。
*   **处理连接的压缩帧:** 测试 `ZstdSourceStream` 是否能够正确处理连续的多个 zstd 压缩帧。
*   **使用字典进行解压缩:** 测试 `ZstdSourceStream` 是否支持使用预定义的字典进行解压缩。

**2. 测试错误处理机制:**

*   **忽略额外的尾部数据:** 测试当压缩数据后跟随有额外的非压缩数据时，`ZstdSourceStream` 是否能够正确地忽略这些数据。
*   **处理过大的窗口大小:** 测试当接收到的 zstd 数据指定了一个过大的窗口大小时，`ZstdSourceStream` 是否能正确地检测并返回错误。

**3. 性能和指标收集 (通过 `base::HistogramTester`):**

*   **记录解压缩状态:**  测试代码中使用了 `base::HistogramTester` 来记录 zstd 解压缩的状态 (例如，成功、遇到错误等)，这表明 `ZstdSourceStream` 可能会收集这些指标用于性能分析或错误监控。

**与 JavaScript 的功能关系:**

`ZstdSourceStream` 本身是用 C++ 编写的，JavaScript 代码不能直接调用它。但是，它在浏览器网络栈中扮演着关键角色，直接影响到 JavaScript 通过网络获取资源时的性能和功能。

**举例说明:**

假设一个网站使用 zstd 压缩来传输其资源（例如，JavaScript 文件、CSS 文件、文本文件）。

1. **用户发起请求:** 当用户在浏览器中访问该网站时，浏览器会向服务器发送 HTTP 请求。
2. **服务器响应:** 服务器返回一个 HTTP 响应，其中 `Content-Encoding`  HTTP 头的值设置为 `zstd`，表明响应体是用 zstd 压缩的。
3. **浏览器接收响应:** 浏览器网络栈接收到压缩的响应数据。
4. **Zstd 解压缩:**  `ZstdSourceStream`  就会被调用来解压缩响应体中的 zstd 数据。
5. **JavaScript 可用:** 解压缩后的数据被传递给浏览器的其他组件，最终，如果是 JavaScript 文件，它会被 JavaScript 引擎解析和执行。

**假设输入与输出 (逻辑推理):**

**测试用例: `DecodeZstdOneBlockSync`**

*   **假设输入 (MockSourceStream 提供的数据):**  `encoded_buffer()`  (包含 "google.zst" 文件内容的 zstd 压缩数据)
*   **预期输出 (ReadStream 返回的数据):**
    *   `bytes_read`:  等于  `source_data_len()` (解压缩后的 "google.txt" 文件的长度)
    *   `out_data()`:  包含 "google.txt" 文件的内容

**测试用例: `WindowSizeTooBig`**

*   **假设输入 (MockSourceStream 提供的数据):** `kNineMegWindowZstd` (一段人为构造的、指定了过大窗口大小的 zstd 数据)
*   **预期输出 (ReadStream 返回的数据):** `net::ERR_ZSTD_WINDOW_SIZE_TOO_BIG` (表示遇到了窗口大小过大的错误)

**用户或编程常见的使用错误 (涉及 `ZstdSourceStream` 相关的场景):**

1. **服务器配置错误:** 服务器错误地配置了 `Content-Encoding: zstd`，但实际发送的是未压缩的数据或者使用其他压缩算法的数据。这会导致 `ZstdSourceStream` 解压失败。
    *   **错误现象:** 浏览器可能无法正常加载网页资源，控制台可能会报解码错误。
    *   **调试线索:** 检查网络请求的响应头，确认 `Content-Encoding` 是否正确。查看 `ZstdSourceStream` 的错误日志或指标。

2. **中间代理或缓存问题:**  中间代理或缓存可能错误地修改了响应的 `Content-Encoding` 头，或者缓存了压缩不一致的数据。
    *   **错误现象:**  间歇性出现解压错误，某些用户或在特定网络环境下出现问题。
    *   **调试线索:**  禁用缓存进行测试，检查中间代理的配置。

3. **手动构造错误的 Zstd 数据:** 如果开发者在某些场景下需要手动处理 zstd 数据，可能会构造出不符合 zstd 规范的数据。
    *   **错误现象:**  `ZstdSourceStream` 解压时会报错。
    *   **调试线索:**  使用 zstd 官方工具或库验证手动构造的数据的有效性。

4. **忘记包含字典 (在需要字典的情况下):** 如果服务器使用了基于字典的 zstd 压缩 (例如，使用了 Shared Brotli 字典机制，但底层使用了 zstd)，而客户端没有提供正确的字典。
    *   **错误现象:**  解压失败。
    *   **调试线索:** 检查服务器是否使用了字典压缩，客户端是否正确获取并传递了字典。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入一个 URL 并回车，或者点击一个链接。**
2. **浏览器解析 URL，并向目标服务器发起 HTTP 请求。**
3. **服务器处理请求，并决定使用 zstd 压缩响应体。** 服务器设置 HTTP 响应头的 `Content-Encoding: zstd` 并发送压缩后的数据。
4. **浏览器的网络栈接收到 HTTP 响应。**
5. **网络栈检查 `Content-Encoding` 头，发现是 `zstd`。**
6. **网络栈创建或获取一个 `ZstdSourceStream` 实例。**
7. **压缩的响应数据被传递给 `ZstdSourceStream` 进行解压缩。**  `ZstdSourceStream` 会读取输入流的数据，并尝试使用 zstd 算法进行解压。
8. **如果解压缩成功，解压后的数据会被传递给浏览器的其他组件 (例如，渲染引擎、JavaScript 引擎)。**
9. **如果解压缩失败 (例如，数据损坏、窗口大小过大)，`ZstdSourceStream` 会返回错误，网络栈会处理该错误，并可能向用户显示错误页面或阻止资源加载。**

在调试与 zstd 压缩相关的问题时，可以关注以下几个方面：

*   **网络请求和响应头:**  确认 `Content-Encoding` 是否为 `zstd`，以及其他相关的头部信息。
*   **错误日志:**  查看浏览器的控制台或 Chromium 的内部日志，可能会有关于 zstd 解压错误的详细信息。
*   **抓包分析:** 使用网络抓包工具 (如 Wireshark) 查看网络传输的原始数据，确认数据是否真的被 zstd 压缩。
*   **禁用压缩:** 在浏览器开发者工具中，可以尝试禁用 zstd 压缩来排除是否是压缩本身导致的问题。

总而言之，`net/filter/zstd_source_stream_unittest.cc`  是 Chromium 网络栈中一个非常重要的单元测试文件，它保证了 `ZstdSourceStream` 类的正确性和稳定性，从而确保浏览器能够正确地处理 zstd 压缩的网页内容，提升用户的浏览体验。

Prompt: 
```
这是目录为net/filter/zstd_source_stream_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/filter/zstd_source_stream.h"

#include <utility>

#include "base/files/file_util.h"
#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "base/path_service.h"
#include "base/run_loop.h"
#include "base/test/metrics/histogram_tester.h"
#include "net/base/io_buffer.h"
#include "net/base/test_completion_callback.h"
#include "net/filter/mock_source_stream.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

namespace net {

namespace {

const size_t kDefaultBufferSize = 4096;
const size_t kLargeBufferSize = 7168;

// Get the path of data directory.
base::FilePath GetTestDataDir() {
  base::FilePath data_dir;
  base::PathService::Get(base::DIR_SRC_TEST_DATA_ROOT, &data_dir);
  data_dir = data_dir.AppendASCII("net");
  data_dir = data_dir.AppendASCII("data");
  data_dir = data_dir.AppendASCII("filter_unittests");
  return data_dir;
}

}  // namespace

class ZstdSourceStreamTest : public PlatformTest {
 protected:
  void SetUp() override {
    PlatformTest::SetUp();

    // Get the path of data directory.
    base::FilePath data_dir = GetTestDataDir();

    // Read data from the original file into buffer.
    base::FilePath file_path;
    file_path = data_dir.AppendASCII("google.txt");
    ASSERT_TRUE(base::ReadFileToString(file_path, &source_data_));
    ASSERT_GE(kDefaultBufferSize, source_data_.size());

    // Read data from the encoded file into buffer.
    base::FilePath encoded_file_path;
    encoded_file_path = data_dir.AppendASCII("google.zst");
    ASSERT_TRUE(base::ReadFileToString(encoded_file_path, &encoded_buffer_));
    ASSERT_GE(kDefaultBufferSize, encoded_buffer_.size());

    auto source = std::make_unique<MockSourceStream>();
    source->set_expect_all_input_consumed(false);
    source_ = source.get();
    zstd_stream_ = CreateZstdSourceStream(std::move(source));

    out_buffer_ = base::MakeRefCounted<IOBufferWithSize>(kDefaultBufferSize);
  }

  int ReadStream(net::CompletionOnceCallback callback) {
    return zstd_stream_->Read(out_buffer(), out_buffer_size(),
                              std::move(callback));
  }

  std::string ReadStreamUntilDone() {
    std::string actual_output;
    while (true) {
      TestCompletionCallback callback;
      int bytes_read = ReadStream(callback.callback());
      if (bytes_read <= OK) {
        break;
      }
      actual_output.append(out_data(), bytes_read);
    }
    return actual_output;
  }

  IOBuffer* out_buffer() { return out_buffer_.get(); }
  char* out_data() { return out_buffer_->data(); }
  size_t out_buffer_size() { return out_buffer_->size(); }

  std::string source_data() { return source_data_; }
  size_t source_data_len() { return source_data_.length(); }

  char* encoded_buffer() { return &encoded_buffer_[0]; }
  size_t encoded_buffer_len() { return encoded_buffer_.length(); }

  MockSourceStream* source() { return source_; }
  SourceStream* zstd_stream() { return zstd_stream_.get(); }

  void ResetStream() {
    source_ = nullptr;
    zstd_stream_ = nullptr;
  }

 private:
  std::unique_ptr<SourceStream> zstd_stream_;
  raw_ptr<MockSourceStream> source_;
  scoped_refptr<IOBufferWithSize> out_buffer_;

  std::string source_data_;
  std::string encoded_buffer_;
};

TEST_F(ZstdSourceStreamTest, EmptyStream) {
  source()->AddReadResult(nullptr, 0, OK, MockSourceStream::SYNC);
  TestCompletionCallback callback;
  int result = ReadStream(callback.callback());
  EXPECT_EQ(OK, result);
  EXPECT_EQ("ZSTD", zstd_stream()->Description());
}

// Basic scenario: decoding zstd data with big enough buffer
TEST_F(ZstdSourceStreamTest, DecodeZstdOneBlockSync) {
  base::HistogramTester histograms;

  source()->AddReadResult(encoded_buffer(), encoded_buffer_len(), OK,
                          MockSourceStream::SYNC);

  TestCompletionCallback callback;
  int bytes_read = ReadStream(callback.callback());
  EXPECT_EQ(static_cast<int>(source_data_len()), bytes_read);
  EXPECT_EQ(0, memcmp(out_data(), source_data().c_str(), source_data_len()));

  // Resetting streams is needed to call the destructor of ZstdSourceStream,
  // where the histograms are recorded.
  ResetStream();

  histograms.ExpectTotalCount("Net.ZstdFilter.Status", 1);
  histograms.ExpectUniqueSample(
      "Net.ZstdFilter.Status",
      static_cast<int>(ZstdDecodingStatus::kEndOfFrame), 1);
}

TEST_F(ZstdSourceStreamTest, IgnoreExtraDataInOneRead) {
  std::string response_with_extra_data(encoded_buffer(), encoded_buffer_len());
  response_with_extra_data.append(100, 'x');
  source()->AddReadResult(response_with_extra_data.data(),
                          response_with_extra_data.length(), OK,
                          MockSourceStream::SYNC);
  // Add an EOF.
  source()->AddReadResult(nullptr, 0, OK, MockSourceStream::SYNC);

  std::string actual_output = ReadStreamUntilDone();

  EXPECT_EQ(source_data_len(), actual_output.size());
  EXPECT_EQ(source_data(), actual_output);
}

TEST_F(ZstdSourceStreamTest, IgnoreExtraDataInDifferentRead) {
  std::string extra_data;
  extra_data.append(100, 'x');
  source()->AddReadResult(encoded_buffer(), encoded_buffer_len(), OK,
                          MockSourceStream::SYNC);
  source()->AddReadResult(extra_data.c_str(), extra_data.length(), OK,
                          MockSourceStream::SYNC);
  // Add an EOF.
  source()->AddReadResult(extra_data.c_str(), 0, OK, MockSourceStream::SYNC);

  std::string actual_output = ReadStreamUntilDone();

  EXPECT_EQ(source_data_len(), actual_output.size());
  EXPECT_EQ(source_data(), actual_output);
}

TEST_F(ZstdSourceStreamTest, DecodeZstdTwoBlockSync) {
  source()->AddReadResult(encoded_buffer(), 10, OK, MockSourceStream::SYNC);
  source()->AddReadResult(encoded_buffer() + 10, encoded_buffer_len() - 10, OK,
                          MockSourceStream::SYNC);
  TestCompletionCallback callback;
  int bytes_read = ReadStream(callback.callback());
  EXPECT_EQ(static_cast<int>(source_data_len()), bytes_read);
  EXPECT_EQ(0, memcmp(out_data(), source_data().c_str(), source_data_len()));
}

TEST_F(ZstdSourceStreamTest, DecodeZstdOneBlockAsync) {
  source()->AddReadResult(encoded_buffer(), encoded_buffer_len(), OK,
                          MockSourceStream::ASYNC);
  // Add an EOF.
  source()->AddReadResult(nullptr, 0, OK, MockSourceStream::ASYNC);

  scoped_refptr<IOBuffer> buffer =
      base::MakeRefCounted<IOBufferWithSize>(source_data_len());

  std::string actual_output;
  int bytes_read = 0;
  do {
    TestCompletionCallback callback;
    bytes_read = ReadStream(callback.callback());
    if (bytes_read == ERR_IO_PENDING) {
      source()->CompleteNextRead();
      bytes_read = callback.WaitForResult();
    }
    EXPECT_GE(static_cast<int>(kDefaultBufferSize), bytes_read);
    EXPECT_GE(bytes_read, 0);
    if (bytes_read > 0) {
      actual_output.append(out_data(), bytes_read);
    }
  } while (bytes_read > 0);
  EXPECT_EQ(source_data_len(), actual_output.size());
  EXPECT_EQ(source_data(), actual_output);
}

TEST_F(ZstdSourceStreamTest, DecodeTwoConcatenatedFrames) {
  std::string encoded_buffer;
  std::string source_data;

  base::FilePath data_dir = GetTestDataDir();

  // Read data from the original file into buffer.
  base::FilePath file_path;
  file_path = data_dir.AppendASCII("google.txt");
  ASSERT_TRUE(base::ReadFileToString(file_path, &source_data));
  source_data.append(source_data);
  ASSERT_GE(kLargeBufferSize, source_data.size());

  // Read data from the encoded file into buffer.
  base::FilePath encoded_file_path;
  encoded_file_path = data_dir.AppendASCII("google.zst");
  ASSERT_TRUE(base::ReadFileToString(encoded_file_path, &encoded_buffer));

  // Concatenate two encoded buffers.
  encoded_buffer.append(encoded_buffer);
  ASSERT_GE(kLargeBufferSize, encoded_buffer.size());

  scoped_refptr<IOBufferWithSize> out_buffer =
      base::MakeRefCounted<IOBufferWithSize>(kLargeBufferSize);

  // Decompress content.
  auto source = std::make_unique<MockSourceStream>();
  source->AddReadResult(encoded_buffer.c_str(), encoded_buffer.size(), OK,
                        MockSourceStream::SYNC);
  source->AddReadResult(nullptr, 0, OK, MockSourceStream::SYNC);
  source->set_expect_all_input_consumed(false);

  std::unique_ptr<SourceStream> zstd_stream =
      CreateZstdSourceStream(std::move(source));

  std::string actual_output;
  while (true) {
    TestCompletionCallback callback;
    int bytes_read = zstd_stream->Read(out_buffer.get(), kLargeBufferSize,
                                       callback.callback());
    if (bytes_read <= OK) {
      break;
    }
    actual_output.append(out_buffer->data(), bytes_read);
  }

  EXPECT_EQ(source_data.length(), actual_output.size());
  EXPECT_EQ(source_data, actual_output);
}

TEST_F(ZstdSourceStreamTest, WithDictionary) {
  std::string encoded_buffer;
  std::string dictionary_data;

  base::FilePath data_dir = GetTestDataDir();
  // Read data from the encoded file into buffer.
  base::FilePath encoded_file_path;
  encoded_file_path = data_dir.AppendASCII("google.szst");
  ASSERT_TRUE(base::ReadFileToString(encoded_file_path, &encoded_buffer));

  // Read data from the dictionary file into buffer.
  base::FilePath dictionary_file_path;
  dictionary_file_path = data_dir.AppendASCII("test.dict");
  ASSERT_TRUE(base::ReadFileToString(dictionary_file_path, &dictionary_data));

  scoped_refptr<net::IOBuffer> dictionary_buffer =
      base::MakeRefCounted<net::StringIOBuffer>(dictionary_data);

  scoped_refptr<IOBufferWithSize> out_buffer =
      base::MakeRefCounted<IOBufferWithSize>(kDefaultBufferSize);

  auto source = std::make_unique<MockSourceStream>();
  source->AddReadResult(encoded_buffer.c_str(), encoded_buffer.size(), OK,
                        MockSourceStream::SYNC);

  std::unique_ptr<SourceStream> zstd_stream =
      CreateZstdSourceStreamWithDictionary(std::move(source), dictionary_buffer,
                                           dictionary_data.size());

  TestCompletionCallback callback;
  int bytes_read = zstd_stream->Read(out_buffer.get(), kDefaultBufferSize,
                                     callback.callback());

  EXPECT_EQ(static_cast<int>(source_data_len()), bytes_read);
  EXPECT_EQ(
      0, memcmp(out_buffer->data(), source_data().c_str(), source_data_len()));
}

TEST_F(ZstdSourceStreamTest, WindowSizeTooBig) {
  base::HistogramTester histograms;

  constexpr uint8_t kNineMegWindowZstd[] = {
      0x28, 0xb5, 0x2f, 0xfd, 0xa4, 0x00, 0x00, 0x90, 0x00, 0x4c, 0x00, 0x00,
      0x08, 0x00, 0x01, 0x00, 0xfc, 0xff, 0x39, 0x10, 0x02, 0x02, 0x00, 0x10,
      0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
      0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
      0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
      0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
      0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
      0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
      0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
      0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
      0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
      0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
      0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
      0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
      0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
      0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
      0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
      0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
      0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
      0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
      0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
      0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
      0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
      0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
      0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x10,
      0x00, 0x03, 0x00, 0x10, 0x00, 0x6e, 0x70, 0x97, 0x34};
  out_data()[0] = 'e';

  source()->AddReadResult(reinterpret_cast<const char*>(kNineMegWindowZstd),
                          sizeof(kNineMegWindowZstd), OK,
                          MockSourceStream::SYNC);

  TestCompletionCallback callback;
  int bytes_read = ReadStream(callback.callback());
  EXPECT_EQ(net::ERR_ZSTD_WINDOW_SIZE_TOO_BIG, bytes_read);
  EXPECT_EQ(0, memcmp(out_data(), "e", 1));

  // Resetting streams is needed to call the destructor of ZstdSourceStream,
  // where the histograms are recorded.
  ResetStream();

  histograms.ExpectTotalCount("Net.ZstdFilter.Status", 1);
  histograms.ExpectUniqueSample(
      "Net.ZstdFilter.Status",
      static_cast<int>(ZstdDecodingStatus::kDecodingError), 1);
}

}  // namespace net

"""

```