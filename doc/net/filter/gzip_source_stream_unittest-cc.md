Response:
My thinking process to answer the request went through these stages:

1. **Understand the Core Task:** The main goal is to analyze the C++ unit test file `gzip_source_stream_unittest.cc` and explain its purpose, relationship to JavaScript, logic, potential errors, and debugging context.

2. **Identify the Tested Class:**  The file name itself, `gzip_source_stream_unittest.cc`, strongly suggests the primary class under test is `GzipSourceStream`. Further examination of the `#include` statements confirms this, as `net/filter/gzip_source_stream.h` would define this class.

3. **Determine the Functionality of `GzipSourceStream`:** The name and the presence of zlib headers (`third_party/zlib/zlib.h`) strongly indicate that `GzipSourceStream` deals with gzip and potentially deflate compression/decompression within the network stack. The use of `SourceStream` in the name and included files suggests it's a part of a larger streaming data processing pipeline.

4. **Analyze the Unit Tests:**  The `TEST_P` macros point to parameterized tests, driven by the `GzipTestParam` struct. This struct defines variations in buffer size, read mode (synchronous/asynchronous), and read result type (one byte at a time or all at once). This highlights the focus on testing different I/O scenarios.

5. **Break Down Individual Tests:** I reviewed each test case (`EmptyStream`, `DeflateOneBlock`, `GzipOneBloc`, etc.) to understand the specific scenarios being tested:
    * **`EmptyStream`:**  Tests handling of an empty input stream.
    * **`DeflateOneBlock`/`GzipOneBloc`:** Tests basic decompression of single blocks of deflate/gzip data.
    * **`DeflateTwoReads`:** Tests handling of data arriving in multiple chunks.
    * **`IgnoreDataAfterEof`:** Checks if extraneous data after the compressed stream is ignored.
    * **`MissingZlibHeader`/`CorruptGzipHeader`:** Tests error handling for malformed compressed data.
    * **`GzipCorrectness`/`GzipCorrectnessWithoutFooter`:** Validates decompression against known good gzip data, including the case of a missing footer.
    * **`DeflateWithAdler32`/`DeflateWithBadAdler32`/`DeflateWithoutHeaderWithAdler32`/`DeflateWithoutHeaderWithBadAdler32`:** Focuses on deflate specifics, including header presence and Adler-32 checksum verification.

6. **Infer Functionality Based on Tests:** By observing the test cases, I could solidify the understanding of `GzipSourceStream`'s capabilities:
    * Decompression of gzip and deflate streams.
    * Handling of synchronous and asynchronous I/O.
    * Tolerance of data arriving in chunks.
    * Error handling for corrupted or incomplete data.
    * Support for different deflate formats (with/without headers and checksums).

7. **Address JavaScript Relationship:** I considered how gzip/deflate is used in web contexts. The primary connection is in content encoding (e.g., `Content-Encoding: gzip`). Browsers (which have JavaScript engines) need to decompress these responses. Therefore, `GzipSourceStream` (or similar components in other browsers) is *essential* for correctly displaying web content.

8. **Construct Logical Reasoning Examples:**  For each test case, I formulated a hypothetical input (simulated by `source()->AddReadResult()`) and the expected output (what `ReadStream()` should produce). This demonstrates the function's behavior under different conditions.

9. **Identify Common Usage Errors:**  I thought about how developers or network components might misuse decompression:
    * Providing the wrong content encoding.
    * Sending corrupted or truncated compressed data.
    * Not handling decompression errors gracefully.

10. **Outline Debugging Steps:** I focused on how a developer might arrive at this code during debugging:
    * Observing a "Content Encoding Error" in the browser.
    * Investigating network requests and responses.
    * Stepping through the network stack code.
    * Setting breakpoints in `GzipSourceStream` and related classes.

11. **Structure the Answer:** I organized the information into the requested categories: functionality, JavaScript relationship, logical reasoning, usage errors, and debugging. I used clear language and examples to illustrate the concepts.

12. **Refine and Review:** I reread the answer to ensure accuracy, completeness, and clarity, making minor edits for better flow and wording. For example, I ensured that the JavaScript explanation specifically mentioned `Content-Encoding`. I also double-checked that my hypothetical inputs and outputs aligned with the test scenarios.

By following this structured approach, I could effectively analyze the C++ code and provide a comprehensive and informative answer to the user's request.
这个C++源代码文件 `gzip_source_stream_unittest.cc` 是 Chromium 网络栈的一部分，它的主要功能是**测试 `GzipSourceStream` 类的正确性**。`GzipSourceStream` 类的作用是**在网络数据流中透明地解压缩 gzip 或 deflate 编码的数据**。

更具体地说，这个单元测试文件做了以下事情：

1. **创建和配置 `GzipSourceStream` 对象：**  测试用例会创建 `GzipSourceStream` 的实例，并将其与一个 `MockSourceStream` 对象关联起来。`MockSourceStream` 用于模拟底层数据源的行为，例如返回压缩数据。

2. **模拟不同的输入场景：**  通过 `MockSourceStream::AddReadResult` 方法，测试用例可以模拟底层数据源返回不同大小和内容的压缩数据块，以及模拟同步和异步读取操作。

3. **测试解压缩功能：**  测试用例调用 `GzipSourceStream::Read` 方法从流中读取解压缩后的数据，并将读取到的数据与预期的数据进行比较。

4. **测试不同的压缩格式：**  测试用例会分别测试 `GzipSourceStream` 处理 gzip 和 deflate 两种压缩格式的能力。

5. **测试错误处理：**  测试用例会模拟各种错误情况，例如：
    * 空流
    * 不完整的压缩数据
    * 损坏的 gzip 头或校验和
    * 数据流末尾有多余的数据

6. **验证输出结果：**  使用 `EXPECT_EQ` 等 Google Test 宏来断言 `GzipSourceStream` 的行为是否符合预期，例如读取到的字节数、解压缩后的数据内容以及是否返回了正确的错误码。

**与 JavaScript 的关系：**

`GzipSourceStream` 的功能直接关系到 JavaScript 在浏览器环境中的运行。当浏览器通过 HTTP(S) 请求资源时，服务器可能会使用 gzip 或 deflate 压缩响应内容，并通过 `Content-Encoding` 头部告知浏览器。浏览器接收到压缩后的数据后，需要进行解压缩才能让 JavaScript 代码使用。

`GzipSourceStream` (或类似功能的模块) 就是在浏览器网络栈中负责解压缩这些压缩数据的关键组件。JavaScript 代码通常不需要直接与 `GzipSourceStream` 交互，解压缩过程是透明的。

**举例说明：**

假设一个网站的服务器配置为使用 gzip 压缩文本资源（例如 JavaScript 文件、CSS 文件、HTML 文件）。

1. **用户在浏览器中访问该网站。**
2. **浏览器发送 HTTP 请求到服务器请求一个 JavaScript 文件。**
3. **服务器返回包含 gzip 压缩的 JavaScript 文件内容，并在 HTTP 响应头中设置 `Content-Encoding: gzip`。**
4. **浏览器接收到响应后，网络栈中的组件（例如 `GzipSourceStream`）会根据 `Content-Encoding` 头识别出数据是经过 gzip 压缩的。**
5. **`GzipSourceStream` 会读取压缩后的数据流，并进行解压缩。**
6. **解压缩后的原始 JavaScript 代码会被传递给 JavaScript 引擎进行解析和执行。**
7. **JavaScript 代码在浏览器中运行。**

**逻辑推理 - 假设输入与输出：**

**测试用例：`DeflateOneBlock`**

* **假设输入 (模拟 `MockSourceStream` 返回的数据):** 一段经过 deflate 压缩的字节流，其解压后对应于 `source_data_` 的内容。结尾是一个表示流结束的空数据块。
* **预期输出 ( `ReadStream` 函数的返回值和 `actual_output` 的内容):**
    * 返回值：等于 `source_data_len_`，表示成功读取了 `source_data_len_` 个字节。
    * `actual_output` 的内容：与 `source_data_` 的内容完全相同，表示成功解压缩。

**测试用例：`CorruptGzipHeader`**

* **假设输入 (模拟 `MockSourceStream` 返回的数据):** 一段 gzip 压缩的字节流，但是其头部（前几个字节）被故意修改为无效的值。
* **预期输出 ( `ReadStream` 函数的返回值):** 返回 `ERR_CONTENT_DECODING_FAILED` 错误码，表示解压缩失败，因为 gzip 头部损坏。

**用户或编程常见的使用错误：**

1. **服务器配置错误，声明了错误的 `Content-Encoding`。** 例如，服务器实际返回的是未压缩的数据，但却设置了 `Content-Encoding: gzip`。在这种情况下，浏览器会尝试使用 `GzipSourceStream` 解压缩，但会因为数据格式不正确而失败，导致页面加载错误。

2. **网络传输过程中数据损坏。** 尽管这种情况比较少见，但如果 gzip 压缩的数据在网络传输过程中发生损坏，例如部分字节丢失或被修改，`GzipSourceStream` 在尝试解压缩时可能会遇到错误，导致 `ERR_CONTENT_DECODING_FAILED`。

3. **开发者在自定义网络请求中错误地使用了压缩。** 如果开发者手动创建网络请求并尝试发送或接收压缩数据，但没有正确地设置 `Content-Encoding` 或没有使用正确的压缩算法，可能会导致解压缩失败。

**用户操作如何一步步到达这里，作为调试线索：**

假设用户在浏览某个网页时遇到了以下情况：

1. **用户在浏览器中输入网址并回车，或者点击了一个链接。**
2. **浏览器发送 HTTP 请求到服务器获取网页资源（HTML、CSS、JavaScript 等）。**
3. **服务器返回的某个响应（例如一个 JavaScript 文件）设置了 `Content-Encoding: gzip`。**
4. **浏览器接收到压缩后的数据。**
5. **Chromium 的网络栈会创建一个 `GzipSourceStream` 对象来处理这个压缩流。**
6. **在解压缩过程中，`GzipSourceStream` 遇到了问题，例如压缩数据损坏或者格式不正确。**
7. **`GzipSourceStream::Read` 方法返回一个错误码，例如 `ERR_CONTENT_DECODING_FAILED`。**
8. **浏览器可能会显示一个错误页面，提示用户内容解码失败。**

**作为调试线索，开发者可能会：**

* **查看浏览器的开发者工具 (Network 标签页):**  检查响应头中的 `Content-Encoding` 是否正确，以及响应的大小和状态码。
* **使用 `chrome://net-internals/#events`:** 查看更底层的网络事件，包括数据接收和解压缩过程中的错误信息。
* **如果怀疑是服务器配置问题，会检查服务器的压缩配置。**
* **如果怀疑是网络传输问题，可能会尝试重新加载页面或者使用不同的网络环境。**
* **如果怀疑是 Chromium 的解压缩代码存在 bug，可能会尝试查看 `gzip_source_stream_unittest.cc` 相关的测试用例，了解 `GzipSourceStream` 的预期行为和测试覆盖范围，或者甚至单步调试 `GzipSourceStream` 的代码来定位问题。**  开发者可能会设置断点在 `GzipSourceStream::Read` 函数中，或者在 zlib 相关的调用中，来观察解压缩过程中的数据和状态。

总而言之，`gzip_source_stream_unittest.cc` 是一个至关重要的单元测试文件，它确保了 Chromium 网络栈能够正确地处理 gzip 和 deflate 压缩的数据，这对于用户浏览网页的正常体验至关重要。

### 提示词
```
这是目录为net/filter/gzip_source_stream_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include <string>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "net/base/io_buffer.h"
#include "net/base/test_completion_callback.h"
#include "net/filter/filter_source_stream_test_util.h"
#include "net/filter/gzip_source_stream.h"
#include "net/filter/mock_source_stream.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/zlib/zlib.h"

namespace net {

namespace {

const int kBigBufferSize = 4096;
const int kSmallBufferSize = 1;

enum class ReadResultType {
  // Each call to AddReadResult is a separate read from the lower layer
  // SourceStream.
  EVERYTHING_AT_ONCE,
  // Whenever AddReadResult is called, each byte is actually a separate read
  // result.
  ONE_BYTE_AT_A_TIME,
};

// How many bytes to leave unused at the end of |source_data_|. This margin is
// present so that tests that need to append data after the zlib EOF do not run
// out of room in the output buffer.
const size_t kEOFMargin = 64;

struct GzipTestParam {
  GzipTestParam(int buf_size,
                MockSourceStream::Mode read_mode,
                ReadResultType read_result_type)
      : buffer_size(buf_size),
        mode(read_mode),
        read_result_type(read_result_type) {}

  const int buffer_size;
  const MockSourceStream::Mode mode;
  const ReadResultType read_result_type;
};

}  // namespace

class GzipSourceStreamTest : public ::testing::TestWithParam<GzipTestParam> {
 protected:
  GzipSourceStreamTest() : output_buffer_size_(GetParam().buffer_size) {}

  // Helpful function to initialize the test fixture.|type| specifies which type
  // of GzipSourceStream to create. It must be one of TYPE_GZIP and
  // TYPE_DEFLATE.
  void Init(SourceStream::SourceType type) {
    EXPECT_TRUE(SourceStream::TYPE_GZIP == type ||
                SourceStream::TYPE_DEFLATE == type);
    source_data_len_ = kBigBufferSize - kEOFMargin;

    for (size_t i = 0; i < source_data_len_; i++)
      source_data_[i] = i % 256;

    encoded_data_len_ = kBigBufferSize;
    CompressGzip(source_data_, source_data_len_, encoded_data_,
                 &encoded_data_len_, type != SourceStream::TYPE_DEFLATE);

    output_buffer_ =
        base::MakeRefCounted<IOBufferWithSize>(output_buffer_size_);
    auto source = std::make_unique<MockSourceStream>();
    if (GetParam().read_result_type == ReadResultType::ONE_BYTE_AT_A_TIME)
      source->set_read_one_byte_at_a_time(true);
    source_ = source.get();
    stream_ = GzipSourceStream::Create(std::move(source), type);
  }

  // If MockSourceStream::Mode is ASYNC, completes reads from |mock_stream|
  // until there's no pending read, and then returns |callback|'s result, once
  // it's invoked. If Mode is not ASYNC, does nothing and returns
  // |previous_result|.
  int CompleteReadsIfAsync(int previous_result,
                           TestCompletionCallback* callback,
                           MockSourceStream* mock_stream) {
    if (GetParam().mode == MockSourceStream::ASYNC) {
      EXPECT_EQ(ERR_IO_PENDING, previous_result);
      while (mock_stream->awaiting_completion())
        mock_stream->CompleteNextRead();
      return callback->WaitForResult();
    }
    return previous_result;
  }

  char* source_data() { return source_data_; }
  size_t source_data_len() { return source_data_len_; }

  char* encoded_data() { return encoded_data_; }
  size_t encoded_data_len() { return encoded_data_len_; }

  IOBuffer* output_buffer() { return output_buffer_.get(); }
  char* output_data() { return output_buffer_->data(); }
  size_t output_buffer_size() { return output_buffer_size_; }

  MockSourceStream* source() { return source_; }
  GzipSourceStream* stream() { return stream_.get(); }

  // Reads from |stream_| until an error occurs or the EOF is reached.
  // When an error occurs, returns the net error code. When an EOF is reached,
  // returns the number of bytes read and appends data read to |output|.
  int ReadStream(std::string* output) {
    int bytes_read = 0;
    while (true) {
      TestCompletionCallback callback;
      int rv = stream_->Read(output_buffer(), output_buffer_size(),
                             callback.callback());
      if (rv == ERR_IO_PENDING)
        rv = CompleteReadsIfAsync(rv, &callback, source());
      if (rv == OK)
        break;
      if (rv < OK)
        return rv;
      EXPECT_GT(rv, OK);
      bytes_read += rv;
      output->append(output_data(), rv);
    }
    return bytes_read;
  }

 private:
  char source_data_[kBigBufferSize];
  size_t source_data_len_;

  char encoded_data_[kBigBufferSize];
  size_t encoded_data_len_;

  scoped_refptr<IOBuffer> output_buffer_;
  const int output_buffer_size_;

  raw_ptr<MockSourceStream, DanglingUntriaged> source_;
  std::unique_ptr<GzipSourceStream> stream_;
};

INSTANTIATE_TEST_SUITE_P(
    GzipSourceStreamTests,
    GzipSourceStreamTest,
    ::testing::Values(GzipTestParam(kBigBufferSize,
                                    MockSourceStream::SYNC,
                                    ReadResultType::EVERYTHING_AT_ONCE),
                      GzipTestParam(kSmallBufferSize,
                                    MockSourceStream::SYNC,
                                    ReadResultType::EVERYTHING_AT_ONCE),
                      GzipTestParam(kBigBufferSize,
                                    MockSourceStream::ASYNC,
                                    ReadResultType::EVERYTHING_AT_ONCE),
                      GzipTestParam(kSmallBufferSize,
                                    MockSourceStream::ASYNC,
                                    ReadResultType::EVERYTHING_AT_ONCE),
                      GzipTestParam(kBigBufferSize,
                                    MockSourceStream::SYNC,
                                    ReadResultType::ONE_BYTE_AT_A_TIME),
                      GzipTestParam(kSmallBufferSize,
                                    MockSourceStream::SYNC,
                                    ReadResultType::ONE_BYTE_AT_A_TIME),
                      GzipTestParam(kBigBufferSize,
                                    MockSourceStream::ASYNC,
                                    ReadResultType::ONE_BYTE_AT_A_TIME),
                      GzipTestParam(kSmallBufferSize,
                                    MockSourceStream::ASYNC,
                                    ReadResultType::ONE_BYTE_AT_A_TIME)));

TEST_P(GzipSourceStreamTest, EmptyStream) {
  Init(SourceStream::TYPE_DEFLATE);
  source()->AddReadResult(nullptr, 0, OK, GetParam().mode);
  TestCompletionCallback callback;
  std::string actual_output;
  int result = ReadStream(&actual_output);
  EXPECT_EQ(OK, result);
  EXPECT_EQ("DEFLATE", stream()->Description());
}

TEST_P(GzipSourceStreamTest, DeflateOneBlock) {
  Init(SourceStream::TYPE_DEFLATE);
  source()->AddReadResult(encoded_data(), encoded_data_len(), OK,
                          GetParam().mode);
  source()->AddReadResult(nullptr, 0, OK, GetParam().mode);
  std::string actual_output;
  int rv = ReadStream(&actual_output);
  EXPECT_EQ(static_cast<int>(source_data_len()), rv);
  EXPECT_EQ(std::string(source_data(), source_data_len()), actual_output);
  EXPECT_EQ("DEFLATE", stream()->Description());
}

TEST_P(GzipSourceStreamTest, GzipOneBloc) {
  Init(SourceStream::TYPE_GZIP);
  source()->AddReadResult(encoded_data(), encoded_data_len(), OK,
                          GetParam().mode);
  source()->AddReadResult(nullptr, 0, OK, GetParam().mode);
  std::string actual_output;
  int rv = ReadStream(&actual_output);
  EXPECT_EQ(static_cast<int>(source_data_len()), rv);
  EXPECT_EQ(std::string(source_data(), source_data_len()), actual_output);
  EXPECT_EQ("GZIP", stream()->Description());
}

TEST_P(GzipSourceStreamTest, DeflateTwoReads) {
  Init(SourceStream::TYPE_DEFLATE);
  source()->AddReadResult(encoded_data(), 10, OK, GetParam().mode);
  source()->AddReadResult(encoded_data() + 10, encoded_data_len() - 10, OK,
                          GetParam().mode);
  source()->AddReadResult(nullptr, 0, OK, GetParam().mode);
  std::string actual_output;
  int rv = ReadStream(&actual_output);
  EXPECT_EQ(static_cast<int>(source_data_len()), rv);
  EXPECT_EQ(std::string(source_data(), source_data_len()), actual_output);
  EXPECT_EQ("DEFLATE", stream()->Description());
}

// Check that any extra bytes after the end of the gzipped data are silently
// ignored.
TEST_P(GzipSourceStreamTest, IgnoreDataAfterEof) {
  Init(SourceStream::TYPE_DEFLATE);
  const char kExtraData[] = "Hello, World!";
  std::string encoded_data_with_trailing_data(encoded_data(),
                                              encoded_data_len());
  encoded_data_with_trailing_data.append(kExtraData, sizeof(kExtraData));
  source()->AddReadResult(encoded_data_with_trailing_data.c_str(),
                          encoded_data_with_trailing_data.length(), OK,
                          GetParam().mode);
  source()->AddReadResult(nullptr, 0, OK, GetParam().mode);
  // Compressed and uncompressed data get returned as separate Read() results,
  // so this test has to call Read twice.
  std::string actual_output;
  int rv = ReadStream(&actual_output);
  std::string expected_output(source_data(), source_data_len());
  EXPECT_EQ(static_cast<int>(expected_output.size()), rv);
  EXPECT_EQ(expected_output, actual_output);
  EXPECT_EQ("DEFLATE", stream()->Description());
}

TEST_P(GzipSourceStreamTest, MissingZlibHeader) {
  Init(SourceStream::TYPE_DEFLATE);
  const size_t kZlibHeaderLen = 2;
  source()->AddReadResult(encoded_data() + kZlibHeaderLen,
                          encoded_data_len() - kZlibHeaderLen, OK,
                          GetParam().mode);
  source()->AddReadResult(nullptr, 0, OK, GetParam().mode);
  std::string actual_output;
  int rv = ReadStream(&actual_output);
  EXPECT_EQ(static_cast<int>(source_data_len()), rv);
  EXPECT_EQ(std::string(source_data(), source_data_len()), actual_output);
  EXPECT_EQ("DEFLATE", stream()->Description());
}

TEST_P(GzipSourceStreamTest, CorruptGzipHeader) {
  Init(SourceStream::TYPE_GZIP);
  encoded_data()[1] = 0;
  int read_len = encoded_data_len();
  // Needed to a avoid a DCHECK that all reads were consumed.
  if (GetParam().read_result_type == ReadResultType::ONE_BYTE_AT_A_TIME)
    read_len = 2;
  source()->AddReadResult(encoded_data(), read_len, OK, GetParam().mode);
  std::string actual_output;
  int rv = ReadStream(&actual_output);
  EXPECT_EQ(ERR_CONTENT_DECODING_FAILED, rv);
  EXPECT_EQ("GZIP", stream()->Description());
}

// This test checks that the gzip stream source works correctly on 'golden' data
// as produced by gzip(1).
TEST_P(GzipSourceStreamTest, GzipCorrectness) {
  Init(SourceStream::TYPE_GZIP);
  const char kDecompressedData[] = "Hello, World!";
  const unsigned char kGzipData[] = {
      // From:
      //   echo -n 'Hello, World!' | gzip | xxd -i | sed -e 's/^/  /'
      // The footer is the last 8 bytes.
      0x1f, 0x8b, 0x08, 0x00, 0x2b, 0x02, 0x84, 0x55, 0x00, 0x03, 0xf3,
      0x48, 0xcd, 0xc9, 0xc9, 0xd7, 0x51, 0x08, 0xcf, 0x2f, 0xca, 0x49,
      0x51, 0x04, 0x00, 0xd0, 0xc3, 0x4a, 0xec, 0x0d, 0x00, 0x00, 0x00};
  source()->AddReadResult(reinterpret_cast<const char*>(kGzipData),
                          sizeof(kGzipData), OK, GetParam().mode);
  source()->AddReadResult(nullptr, 0, OK, GetParam().mode);
  std::string actual_output;
  int rv = ReadStream(&actual_output);
  EXPECT_EQ(static_cast<int>(strlen(kDecompressedData)), rv);
  EXPECT_EQ(kDecompressedData, actual_output);
  EXPECT_EQ("GZIP", stream()->Description());
}

// Same as GzipCorrectness except that last 8 bytes are removed to test that the
// implementation can handle missing footer.
TEST_P(GzipSourceStreamTest, GzipCorrectnessWithoutFooter) {
  Init(SourceStream::TYPE_GZIP);
  const char kDecompressedData[] = "Hello, World!";
  const unsigned char kGzipData[] = {
      // From:
      //   echo -n 'Hello, World!' | gzip | xxd -i | sed -e 's/^/  /'
      // with the 8 footer bytes removed.
      0x1f, 0x8b, 0x08, 0x00, 0x2b, 0x02, 0x84, 0x55, 0x00,
      0x03, 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0xd7, 0x51, 0x08,
      0xcf, 0x2f, 0xca, 0x49, 0x51, 0x04, 0x00};
  source()->AddReadResult(reinterpret_cast<const char*>(kGzipData),
                          sizeof(kGzipData), OK, GetParam().mode);
  source()->AddReadResult(nullptr, 0, OK, GetParam().mode);
  std::string actual_output;
  int rv = ReadStream(&actual_output);
  EXPECT_EQ(static_cast<int>(strlen(kDecompressedData)), rv);
  EXPECT_EQ(kDecompressedData, actual_output);
  EXPECT_EQ("GZIP", stream()->Description());
}

// Test with the same compressed data as the above tests, but uses deflate with
// header and checksum. Tests the Z_STREAM_END case in
// STATE_SNIFFING_DEFLATE_HEADER.
TEST_P(GzipSourceStreamTest, DeflateWithAdler32) {
  Init(SourceStream::TYPE_DEFLATE);
  const char kDecompressedData[] = "Hello, World!";
  const unsigned char kGzipData[] = {0x78, 0x01, 0xf3, 0x48, 0xcd, 0xc9, 0xc9,
                                     0xd7, 0x51, 0x08, 0xcf, 0x2f, 0xca, 0x49,
                                     0x51, 0x04, 0x00, 0x1f, 0x9e, 0x04, 0x6a};
  source()->AddReadResult(reinterpret_cast<const char*>(kGzipData),
                          sizeof(kGzipData), OK, GetParam().mode);
  source()->AddReadResult(nullptr, 0, OK, GetParam().mode);
  std::string actual_output;
  int rv = ReadStream(&actual_output);
  EXPECT_EQ(static_cast<int>(strlen(kDecompressedData)), rv);
  EXPECT_EQ(kDecompressedData, actual_output);
  EXPECT_EQ("DEFLATE", stream()->Description());
}

TEST_P(GzipSourceStreamTest, DeflateWithBadAdler32) {
  Init(SourceStream::TYPE_DEFLATE);
  const unsigned char kGzipData[] = {0x78, 0x01, 0xf3, 0x48, 0xcd, 0xc9, 0xc9,
                                     0xd7, 0x51, 0x08, 0xcf, 0x2f, 0xca, 0x49,
                                     0x51, 0x04, 0x00, 0xFF, 0xFF, 0xFF, 0xFF};
  source()->AddReadResult(reinterpret_cast<const char*>(kGzipData),
                          sizeof(kGzipData), OK, GetParam().mode);
  std::string actual_output;
  int rv = ReadStream(&actual_output);
  EXPECT_EQ(ERR_CONTENT_DECODING_FAILED, rv);
  EXPECT_EQ("DEFLATE", stream()->Description());
}

TEST_P(GzipSourceStreamTest, DeflateWithoutHeaderWithAdler32) {
  Init(SourceStream::TYPE_DEFLATE);
  const char kDecompressedData[] = "Hello, World!";
  const unsigned char kGzipData[] = {0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0xd7, 0x51,
                                     0x08, 0xcf, 0x2f, 0xca, 0x49, 0x51, 0x04,
                                     0x00, 0x1f, 0x9e, 0x04, 0x6a};
  source()->AddReadResult(reinterpret_cast<const char*>(kGzipData),
                          sizeof(kGzipData), OK, GetParam().mode);
  source()->AddReadResult(nullptr, 0, OK, GetParam().mode);
  std::string actual_output;
  int rv = ReadStream(&actual_output);
  EXPECT_EQ(static_cast<int>(strlen(kDecompressedData)), rv);
  EXPECT_EQ(kDecompressedData, actual_output);
  EXPECT_EQ("DEFLATE", stream()->Description());
}

TEST_P(GzipSourceStreamTest, DeflateWithoutHeaderWithBadAdler32) {
  Init(SourceStream::TYPE_DEFLATE);
  const unsigned char kGzipData[] = {0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0xd7, 0x51,
                                     0x08, 0xcf, 0x2f, 0xca, 0x49, 0x51, 0x04,
                                     0x00, 0xFF, 0xFF, 0xFF, 0xFF};
  source()->AddReadResult(reinterpret_cast<const char*>(kGzipData),
                          sizeof(kGzipData), OK, GetParam().mode);
  std::string actual_output;
  int rv = ReadStream(&actual_output);
  EXPECT_EQ(ERR_CONTENT_DECODING_FAILED, rv);
  EXPECT_EQ("DEFLATE", stream()->Description());
}

}  // namespace net
```